/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.async;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.MalformedURLException;
import java.util.List;

import freenet.client.ArchiveContext;
import freenet.client.ClientMetadata;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.FetchResult;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.crypt.HashResult;
import freenet.keys.FreenetURI;
import freenet.keys.USK;
import freenet.node.PrioRunnable;
import freenet.node.RequestClient;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.api.Bucket;
import freenet.support.compress.Compressor;
import freenet.support.compress.DecompressorThreadManager;
import freenet.support.io.Closer;
import freenet.support.io.InsufficientDiskSpaceException;
import freenet.support.Logger.LogLevel;
import freenet.support.io.NativeThread;

/**
 * Poll a USK, and when a new slot is found, fetch it.
 */
public class USKRetriever extends BaseClientGetter implements USKCallback {
	private static final long serialVersionUID = 5913500655676487409L;

	/** Context for fetching data */
	final FetchContext ctx;
	final USKRetrieverCallback cb;
	final USK origUSK;
	// In wierd
	/** The USKCallback that is actually subscribed. This is used when we may
	 * be going through a USKSparseProxyCallback. */
	private USKCallback proxy;
	/** Alternatively, we may be driving a USKFetcher directly. This happens when
	 * the client subscribes with a custom FetchContext. */
	private USKFetcher fetcher;

        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	public USKRetriever(FetchContext fctx, short prio,
			final RequestClient client, USKRetrieverCallback cb, USK origUSK) {
		super(prio, client);
		if(client.persistent()) throw new UnsupportedOperationException("USKRetriever cannot be persistent");
		this.ctx = fctx;
		this.cb = cb;
		this.origUSK = origUSK;
		this.proxy = this;
	}

	@Override
	public void onFoundEdition(long l, USK key, ClientContext context, boolean metadata, short codec, byte[] data, boolean newKnownGood, boolean newSlotToo) {
		if(l < 0) {
			Logger.error(this, "Found negative edition: "+l+" for "+key+" !!!");
			return;
		}
		if(l < origUSK.suggestedEdition) {
			Logger.warning(this, "Found edition prior to that specified by the client: "+l+" < "+origUSK.suggestedEdition);
			return;
		}
		if(logMINOR) Logger.minor(this, "Found edition "+l+" for "+this+" - fetching...");
		// Create a SingleFileFetcher for the key (as an SSK).
		// Put the edition number into its context object.
		// Put ourself as callback.
		// Fetch it. If it fails, ignore it, if it succeeds, return the data with the edition # to the client.
		FreenetURI uri = key.getSSK(l).getURI();
		try {
			SingleFileFetcher getter =
				(SingleFileFetcher) SingleFileFetcher.create(this, this, uri, ctx, new ArchiveContext(ctx.maxTempLength, ctx.maxArchiveLevels),
						ctx.maxNonSplitfileRetries, 0, true, l, true, false, context, realTimeFlag, false);
			getter.schedule(context);
		} catch (MalformedURLException e) {
			Logger.error(this, "Impossible: "+e, e);
		} catch (FetchException e) {
			Logger.error(this, "Could not start fetcher for "+uri+" : "+e, e);
		}
	}

	@Override
	public void onSuccess(StreamGenerator streamGenerator, ClientMetadata clientMetadata, List<? extends Compressor> decompressors, final ClientGetState state, ClientContext context) {
		if(logMINOR)
			Logger.minor(this, "Success on "+this+" from "+state+" : length "+streamGenerator.size()+"mime type "+clientMetadata.getMIMEType());
		DecompressorThreadManager decompressorManager = null;
		OutputStream output = null;
		Bucket finalResult = null;
		long maxLen = Math.max(ctx.maxTempLength, ctx.maxOutputLength);
		try {
			finalResult = context.getBucketFactory(persistent()).makeBucket(maxLen);
		} catch (InsufficientDiskSpaceException e) {
            onFailure(new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE), state, context);
            return;
		} catch (IOException e) {
			Logger.error(this, "Caught "+e, e);
			onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, e), state, context);
			return;
		} catch(Throwable t) {
			Logger.error(this, "Caught "+t, t);
			onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, t), state, context);
			return;
		}

		PipedInputStream pipeIn = null;
		PipedOutputStream pipeOut = null;
		try {
			output = finalResult.getOutputStream();
			// Decompress
			if(decompressors != null) {
				if(logMINOR) Logger.minor(this, "Decompressing...");
				pipeIn = new PipedInputStream();
				pipeOut = new PipedOutputStream(pipeIn);
				decompressorManager = new DecompressorThreadManager(pipeIn, decompressors, maxLen);
				pipeIn = decompressorManager.execute();
				ClientGetWorkerThread worker = new ClientGetWorkerThread(new BufferedInputStream(pipeIn), output, null, null, ctx.getSchemeHostAndPort(), null, false, null, null, null, context.linkFilterExceptionProvider);
				worker.start();
				streamGenerator.writeTo(pipeOut, context);
				worker.waitFinished();
				// If this throws, we want the whole request to fail.
				pipeOut.close(); pipeOut = null;
			} else {
					streamGenerator.writeTo(output, context);
					// If this throws, we want the whole request to fail.
					output.close(); output = null;
			}
		} catch(IOException e) {
			Logger.error(this, "Caught "+e, e);
			onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, e), state, context);
		} catch (Throwable t) {
			Logger.error(this, "Caught "+t, t);
			onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, t), state, context);
			return;
		} finally {
			Closer.close(output);
			Closer.close(pipeOut);
		}

		final FetchResult result = new FetchResult(clientMetadata, finalResult);
		context.uskManager.updateKnownGood(origUSK, state.getToken(), context);
		context.mainExecutor.execute(new PrioRunnable() {

			@Override
			public void run() {
				cb.onFound(origUSK, state.getToken(), result);
			}

			@Override
			public int getPriority() {
				return NativeThread.NORM_PRIORITY;
			}

		});

	}

	@Override
	public void onFailure(FetchException e, ClientGetState state, ClientContext context) {
		switch(e.mode) {
		case NOT_ENOUGH_PATH_COMPONENTS:
		case PERMANENT_REDIRECT:
			context.uskManager.updateKnownGood(origUSK, state.getToken(), context);
			return;
		}
		Logger.warning(this, "Found edition "+state.getToken()+" but failed to fetch edition: "+e, e);
	}

	@Override
	public void onBlockSetFinished(ClientGetState state, ClientContext context) {
		// Ignore
	}

	/**
	 * Get the original USK URI which was passed when creating the retriever - not the latest known URI!
	 */
	public USK getOriginalUSK() {
		return origUSK;
	}

	/**
	 * Get the original USK URI which was passed when creating the retriever - not the latest known URI!
	 */
	@Override
	public FreenetURI getURI() {
		// FIXME: Toad: Why did getURI() return null? Does it break anything that I made it return the URI?
		return origUSK.getURI();
	}

	@Override
	public boolean isFinished() {
		return false;
	}

	@Override
	protected void innerNotifyClients(ClientContext context) {
		// Ignore for now
	}

	@Override
	public void onTransition(ClientGetState oldState, ClientGetState newState, ClientContext context) {
		// Ignore
	}

	@Override
	public void onExpectedMIME(ClientMetadata meta, ClientContext context) {
		// Ignore
	}

	@Override
	public void onExpectedSize(long size, ClientContext context) {
		// Ignore
	}

	@Override
	public void onFinalizedMetadata() {
		// Ignore
	}

	@Override
	public short getPollingPriorityNormal() {
		return cb.getPollingPriorityNormal();
	}

	@Override
	public short getPollingPriorityProgress() {
		return cb.getPollingPriorityProgress();
	}

	@Override
	public void cancel(ClientContext context) {
		super.cancel();
	}

	@Override
	protected void innerToNetwork(ClientContext context) {
		// Ignore
	}

	@Override
	public void onExpectedTopSize(long size, long compressed, int blocksReq, int blocksTotal, ClientContext context) {
		// Ignore
	}

	@Override
	public void onSplitfileCompatibilityMode(CompatibilityMode min, CompatibilityMode max, byte[] splitfileKey, boolean compressed, boolean bottomLayer, boolean definitiveAnyway, ClientContext context) {
		// Ignore
	}

	@Override
	public void onHashes(HashResult[] hashes, ClientContext context) {
		// Ignore
	}

	/** Called when we subscribe() in USKManager, if we don't directly subscribe
	 * the USKRetriever. Usually this happens when we put a proxy between them,
	 * e.g. USKProxyCompletionCallback, which hides updates for efficiency.
	 * @param cb The callback that is actually USKManager.subscribe()'ed.
	 */
	synchronized void setProxy(USKCallback cb) {
		proxy = cb;
	}

	synchronized USKCallback getProxy() {
		return proxy;
	}

	synchronized void setFetcher(USKFetcher f) {
		fetcher = f;
	}

	synchronized USKFetcher getFetcher() {
		return fetcher;
	}

	public void unsubscribe(USKManager manager) {
		USKFetcher f;
		USKCallback p;
		synchronized(this) {
			f = fetcher;
			p = proxy;
		}
		if(f != null)
			f.cancel(manager.getContext());
		if(p != null)
			manager.unsubscribe(origUSK, p);
	}

	/** Only works if setFetcher() has been called, i.e. if this was created
	 * through USKManager.subscribeContentCustom().
	 * FIXME this is a special case hack,
	 * For a generic solution see https://bugs.freenetproject.org/view.php?id=4984
	 * @param time The new cooldown time. At least 30 minutes or we throw.
	 * @param tries The new number of tries after each cooldown. Greater than 0
	 * and less than 3 or we throw.
	 */
	public void changeUSKPollParameters(long time, int tries, ClientContext context) {
		USKFetcher f;
		synchronized(this) {
			f = fetcher;
		}
		if(f == null) throw new IllegalStateException();
		f.changeUSKPollParameters(time, tries, context);
	}

    @Override
    public void innerOnResume(ClientContext context) {
        Logger.error(this, "Cannot be persistent");
        // Do nothing. Cannot be persistent.
    }

    @Override
    protected ClientBaseCallback getCallback() {
        // Not persistent.
        return null;
    }
}
