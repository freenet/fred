package freenet.node.updater;

import java.io.File;
import java.io.IOException;

import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchResult;
import freenet.client.async.BinaryBlobWriter;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientGetCallback;
import freenet.client.async.ClientGetter;
import freenet.keys.FreenetURI;
import freenet.node.NodeClientCore;
import freenet.node.RequestClient;
import freenet.node.RequestClientBuilder;
import freenet.node.RequestStarter;
import freenet.support.Logger;
import freenet.support.io.FileBucket;
import freenet.support.io.FileUtil;

/** Fetches the old freenet-ext.jar and freenet-stable-latest.jar. In other
 * words it fetches the transitional versions.
 * @author toad
 */
class LegacyJarFetcher implements ClientGetCallback {
	
	final FreenetURI uri;
	final File tempFile;
	final File saveTo;
	final FileBucket blobBucket;
	final FetchContext ctx;
	final ClientGetter cg;
	final ClientContext context;
	private boolean fetched;
	private boolean failed;
	final LegacyFetchCallback cb;
	interface LegacyFetchCallback {
		public void onSuccess();
		public void onFailure(FetchException e, LegacyJarFetcher fetcher);
	}

	// Single client for both fetches.
	static final RequestClient client = new RequestClientBuilder().build();

	public LegacyJarFetcher(FreenetURI uri, File saveTo, NodeClientCore core, LegacyFetchCallback cb) {
		this.uri = uri;
		this.saveTo = saveTo;
		this.context = core.clientContext;
		this.cb = cb;
		ctx = core.makeClient((short) 1, false).getFetchContext();
		ctx.allowSplitfiles = true;
		ctx.dontEnterImplicitArchives = false;
		ctx.maxNonSplitfileRetries = -1;
		ctx.maxSplitfileBlockRetries = -1;
		blobBucket = new FileBucket(saveTo, false, false, false, false);
		if(blobBucket.size() > 0) {
			fetched = true;
			cg = null;
			tempFile = null;
		} else {
			// Write to temp file then rename.
			// We do not want to rename unless we are sure we've finished the fetch.
			File tmp;
			try {
				tmp = File.createTempFile(saveTo.getName(), NodeUpdateManager.TEMP_BLOB_SUFFIX, saveTo.getParentFile());
				tmp.deleteOnExit(); // To be used sparingly, as it leaks, but safe enough here as it should only happen twice during a normal run.
			} catch (IOException e) {
				Logger.error(this, "Cannot create temp file so cannot fetch legacy jar "+uri+" : UOM from old versions will not work!");
				cg = null;
				fetched = false;
				tempFile = null;
				return;
			}
			tempFile = tmp;
			cg = new ClientGetter(this,  
					uri, ctx, RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
					null, new BinaryBlobWriter(new FileBucket(tempFile, false, false, false, false)));
			fetched = false;
		}
	}

	public void start() {
		boolean f;
		synchronized(this) {
			f = fetched;
		}
		if(f)
			cb.onSuccess();
		else {
			try {
				cg.start(context);
			} catch (FetchException e) {
				synchronized(this) {
					failed = true;
				}
				cb.onFailure(e, this);
			}
		}
	}

	public void stop() {
		synchronized(this) {
			if(fetched) return;
		}
		cg.cancel(context);
	}

	public long getBlobSize() {
		if(failed || !fetched) {
			Logger.error(this, "Asking for blob size but failed="+failed+" fetched="+fetched);
			return -1;
		}
		return blobBucket.size();
	}
	
	public File getBlobFile() {
		if(failed || !fetched) {
			Logger.error(this, "Asking for blob but failed="+failed+" fetched="+fetched);
			return null;
		}
		return saveTo;
	}

	/** Have we fetched the key?
	 * @return True only if we have the blob. */
	public synchronized boolean fetched() {
		return fetched;
	}
	
	public synchronized boolean failed() {
		return failed;
	}

	@Override
	public void onSuccess(FetchResult result, ClientGetter state) {
		result.asBucket().free();
		if(!FileUtil.renameTo(tempFile, saveTo)) {
			Logger.error(this, "Fetched file but unable to rename temp file "+tempFile+" to "+saveTo+" : UOM FROM OLD NODES WILL NOT WORK!");
		} else {
			synchronized(this) {
				fetched = true;
			}
			cb.onSuccess();
		}
	}

	@Override
	public void onFailure(FetchException e, ClientGetter state) {
		synchronized(this) {
			failed = true;
		}
		tempFile.delete();
		cb.onFailure(e, this);
	}

    @Override
    public void onResume(ClientContext context) {
        // Do nothing. Not persistent.
    }

    @Override
    public RequestClient getRequestClient() {
        return client;
    }

}
