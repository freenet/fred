package freenet.node.updater;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.FetchResult;
import freenet.client.async.BinaryBlobWriter;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientGetCallback;
import freenet.client.async.ClientGetter;
import freenet.client.async.PersistenceDisabledException;
import freenet.l10n.NodeL10n;
import freenet.node.NodeClientCore;
import freenet.node.RequestClient;
import freenet.node.RequestStarter;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.MediaType;
import freenet.support.api.Bucket;
import freenet.support.api.RandomAccessBucket;
import freenet.support.api.RandomAccessBuffer;
import freenet.support.io.ArrayBucket;
import freenet.support.io.BucketTools;
import freenet.support.io.ByteArrayRandomAccessBuffer;
import freenet.support.io.FileBucket;
import freenet.support.io.FileUtil;
import freenet.support.io.FileRandomAccessBuffer;

/**
 * Fetches the revocation key. Each time it starts, it will try to fetch it until it has 3 DNFs. If it ever finds it, it will
 * be immediately fed to the NodeUpdateManager.
 */
public class RevocationChecker implements ClientGetCallback, RequestClient {

	public final static int REVOCATION_DNF_MIN = 3;
	
	private boolean logMINOR;

	private NodeUpdateManager manager;
	private NodeClientCore core;
	private int revocationDNFCounter;
	private FetchContext ctxRevocation;
	private ClientGetter revocationGetter;
	private boolean wasAggressive;
	/** Last time at which we got 3 DNFs on the revocation key */
	private long lastSucceeded;
	// Kept separately from NodeUpdateManager.hasBeenBlown because there are local problems that can blow the key.
	private volatile boolean blown;
	
	private File blobFile;
	/** The original binary blob bucket. */
	private ArrayBucket blobBucket;

	public RevocationChecker(NodeUpdateManager manager, File blobFile) {
		this.manager = manager;
		core = manager.node.clientCore;
		this.revocationDNFCounter = 0;
		this.blobFile = blobFile;
		this.logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		ctxRevocation = core.makeClient((short)0, false).getFetchContext();
		// Do not allow redirects etc.
		// If we allow redirects then it will take too long to download the revocation.
		// Anyone inserting it should be aware of this fact! 
		// You must insert with no content type, and be less than the size limit, and less than the block size after compression!
		// If it doesn't fit, we'll still tell the user, but the message may not be easily readable.
		ctxRevocation.allowSplitfiles = false;
		ctxRevocation.maxArchiveLevels = 0;
		ctxRevocation.followRedirects = false;
		// big enough ?
		ctxRevocation.maxOutputLength = NodeUpdateManager.MAX_REVOCATION_KEY_LENGTH;
		ctxRevocation.maxTempLength = NodeUpdateManager.MAX_REVOCATION_KEY_TEMP_LENGTH;
		ctxRevocation.maxSplitfileBlockRetries = -1; // if we find content, try forever to get it; not used because of the above size limits.
		ctxRevocation.maxNonSplitfileRetries = 0; // but return quickly normally
	}
	
	public int getRevocationDNFCounter() {
		return revocationDNFCounter;
	}

	public void start(boolean aggressive) {
		start(aggressive, true);
		if(blobFile.exists()) {
			ArrayBucket bucket = new ArrayBucket();
			try {
				BucketTools.copy(new FileBucket(blobFile, true, false, false, true), bucket);
				// Allow to free if bogus.
				manager.uom.processRevocationBlob(bucket, "disk", true);
			} catch (IOException e) {
				Logger.error(this, "Failed to read old revocation blob: "+e, e);
				System.err.println("We may have downloaded an old revocation blob before restarting but it cannot be read: "+e);
				e.printStackTrace();
			}
		}
	}
	
	/** Start a fetch.
	 * @param aggressive If set to true, then we have just fetched an update, and therefore can increase the priority of the
	 * fetch to maximum.
	 * @return True if the checker was already running and the counter was not reset.
	 * */
	public boolean start(boolean aggressive, boolean reset) {
		
		if(manager.isBlown()) {
			Logger.error(this, "Not starting revocation checker: key already blown!");
			return false;
		}
		boolean wasRunning = false;
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		ClientGetter cg = null;
		try {
			ClientGetter toCancel = null;
			synchronized(this) {
				if(aggressive && !wasAggressive) {
					// Ignore old one.
					toCancel = revocationGetter;
					if(logMINOR) Logger.minor(this, "Ignoring old request, because was low priority");
					revocationGetter = null;
					if(toCancel != null) wasRunning = true;
				}
				wasAggressive = aggressive;
				if(revocationGetter != null && 
						!(revocationGetter.isCancelled() || revocationGetter.isFinished()))  {
					if(logMINOR) Logger.minor(this, "Not queueing another revocation fetcher yet, old one still running");
					reset = false;
					wasRunning = false;
				} else {
					if(reset) {
						if(logMINOR) Logger.minor(this, "Resetting DNF count from "+revocationDNFCounter, new Exception("debug"));
						revocationDNFCounter = 0;
					} else {
						if(logMINOR) Logger.minor(this, "Revocation count "+revocationDNFCounter);
					}
					if(logMINOR) Logger.minor(this, "fetcher="+revocationGetter);
					if(revocationGetter != null && logMINOR) Logger.minor(this, "revocation fetcher: cancelled="+revocationGetter.isCancelled()+", finished="+revocationGetter.isFinished());
					// Client startup may not have completed yet.
					manager.node.clientCore.getPersistentTempDir().mkdirs();
					cg = revocationGetter = new ClientGetter(this, 
							manager.getRevocationURI(), ctxRevocation, 
							aggressive ? RequestStarter.MAXIMUM_PRIORITY_CLASS : RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, 
							null, new BinaryBlobWriter(new ArrayBucket()), null);
					if(logMINOR) Logger.minor(this, "Queued another revocation fetcher (count="+revocationDNFCounter+")");
				}
			}
			if(toCancel != null)
				toCancel.cancel(core.clientContext);
			if(cg != null) {
				core.clientContext.start(cg);
				if(logMINOR) Logger.minor(this, "Started revocation fetcher");
			}
			return wasRunning;
		} catch (FetchException e) {
			if(e.mode == FetchExceptionMode.RECENTLY_FAILED) {
				Logger.error(this, "Cannot start revocation fetcher because recently failed");
			} else {
				Logger.error(this, "Cannot start fetch for the auto-update revocation key: "+e, e);
				manager.blow("Cannot start fetch for the auto-update revocation key: "+e, true);
			}
			synchronized(this) {
				if(revocationGetter == cg) {
					revocationGetter = null;
				}
			}
			return false;
		} catch (PersistenceDisabledException e) {
			// Impossible
			return false;
		}
	}

	long lastSucceeded() {
		return lastSucceeded;
	}
	
	long lastSucceededDelta() {
		if(lastSucceeded <= 0) return -1;
		return System.currentTimeMillis() - lastSucceeded;
	}
	
	/** Called when the revocation URI changes. */
	public void onChangeRevocationURI() {
		kill();
		start(wasAggressive);
	}

	@Override
	public void onSuccess(FetchResult result, ClientGetter state) {
		onSuccess(result, state.getBlobBucket());
	}
	
	void onSuccess(FetchResult result, Bucket blob) {
		// The key has been blown !
		// FIXME: maybe we need a bigger warning message.
		blown = true;
		moveBlob(blob);
		String msg = null;
		try {
			byte[] buf = result.asByteArray();
			msg = new String(buf, MediaType.getCharsetRobustOrUTF(result.getMimeType()));
		} catch (Throwable t) {
			try {
				msg = "Failed to extract result when key blown: "+t;
				Logger.error(this, msg, t);
				System.err.println(msg);
				t.printStackTrace();
			} catch (Throwable t1) {
				msg = "Internal error after retreiving revocation key";
			}
		}
		manager.blow(msg, false); // Real one, even if we can't extract the message.
	}
	
	public boolean hasBlown() {
		return blown;
	}

	private void moveBlob(Bucket tmpBlob) {
		if(tmpBlob == null) {
			Logger.error(this, "No temporary binary blob file moving it: may not be able to propagate revocation, bug???");
			return;
		}
		if(tmpBlob instanceof ArrayBucket) {
			synchronized(this) {
				if(tmpBlob == blobBucket) return;
				blobBucket = (ArrayBucket) tmpBlob;
			}
		} else {
			try {
				ArrayBucket buf = new ArrayBucket(BucketTools.toByteArray(tmpBlob));
				synchronized(this) {
					blobBucket = buf;
				}
			} catch (IOException e) {
				System.err.println("Unable to copy data from revocation bucket!");
				System.err.println("This should not happen and indicates there may be a problem with the auto-update checker.");
				// Don't blow(), as that's already happened.
				return;
			}
			if(tmpBlob instanceof FileBucket) {
				File f = ((FileBucket)tmpBlob).getFile();
				synchronized(this) {
					if(f == blobFile) return;
					if(f.equals(blobFile)) return;
					if(FileUtil.getCanonicalFile(f).equals(FileUtil.getCanonicalFile(blobFile))) return;
				}
			}
			System.out.println("Unexpected blob file in revocation checker: "+tmpBlob);
		}
		FileBucket fb = new FileBucket(blobFile, false, false, false, false);
		try {
			BucketTools.copy(tmpBlob, fb);
		} catch (IOException e) {
			System.err.println("Got revocation but cannot write it to disk: "+e);
			System.err.println("This means the auto-update system is blown but we can't tell other nodes about it!");
			e.printStackTrace();
		}
	}

	@Override
	public void onFailure(FetchException e, ClientGetter state) {
		onFailure(e, state.getBlobBucket());
	}
	
	void onFailure(FetchException e, Bucket blob) {
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		if(logMINOR) Logger.minor(this, "Revocation fetch failed: "+e);
		FetchExceptionMode errorCode = e.getMode();
		boolean completed = false;
		long now = System.currentTimeMillis();
		if(errorCode == FetchExceptionMode.CANCELLED) {
			return; // cancelled by us above, or killed; either way irrelevant and doesn't need to be restarted
		}
		if(e.isFatal()) {
			if(!e.isDefinitelyFatal()) {
				// INTERNAL_ERROR could be related to the key but isn't necessarily.
				// FIXME somebody should look at these two strings and de-uglify them!
				// They should never be seen but they should be idiot-proof if they ever are.
				// FIXME split into two parts? Fetch manually should be a second part?
				String message = l10n("revocationFetchFailedMaybeInternalError", new String[] { "detail", "key" }, new String[] { e.toUserFriendlyString(), manager.getRevocationURI().toASCIIString() });
				System.err.println(message);
				e.printStackTrace();
				manager.blow(message, true);
				return;
			}
			// Really fatal, i.e. something was inserted but can't be decoded.
			// FIXME somebody should look at these two strings and de-uglify them!
			// They should never be seen but they should be idiot-proof if they ever are.
			String message = l10n("revocationFetchFailedFatally", new String[] { "detail", "key" }, new String[] { e.toUserFriendlyString(), manager.getRevocationURI().toASCIIString() });			
			manager.blow(message, false);
			moveBlob(blob);
			return;
		}
		if(e.newURI != null) {
			manager.blow("Revocation URI redirecting to "+e.newURI+" - maybe you set the revocation URI to the update URI?", false);
		}
		synchronized(this) {
			if(errorCode == FetchExceptionMode.DATA_NOT_FOUND){
				revocationDNFCounter++;
				if(logMINOR) Logger.minor(this, "Incremented DNF counter to "+revocationDNFCounter);
			}
			if(revocationDNFCounter >= 3) {
				lastSucceeded = now;
				completed = true;
				revocationDNFCounter = 0;
			}
			revocationGetter = null;
		}
		if(completed)
			manager.noRevocationFound();
		else {
			if(errorCode == FetchExceptionMode.RECENTLY_FAILED) {
				// Try again in 1 second.
				// This ensures we don't constantly start them, fail them, and start them again.
				this.manager.node.ticker.queueTimedJob(new Runnable() {

					@Override
					public void run() {
						start(wasAggressive, false);
					}

				}, SECONDS.toMillis(1));
			} else {
				start(wasAggressive, false);
			}
		}
	}
	
	private String l10n(String key, String[] pattern, String[] value) {
		return NodeL10n.getBase().getString("RevocationChecker." + key,
				pattern, value);
	}

	public void kill() {
		if(revocationGetter != null)
			revocationGetter.cancel(core.clientContext);
	}

	public long getBlobSize() {
		return blobFile.length();
	}

	public RandomAccessBucket getBlobBucket() {
		if(!manager.isBlown()) return null;
		synchronized(this) {
			if(blobBucket != null)
				return blobBucket;
		}
		File f = getBlobFile();
		if(f == null) return null;
		return new FileBucket(f, true, false, false, false);
	}
	
	public RandomAccessBuffer getBlobBuffer() {
		if(!manager.isBlown()) return null;
		synchronized(this) {
			if(blobBucket != null) {
			    try {
			        ByteArrayRandomAccessBuffer t = new ByteArrayRandomAccessBuffer(blobBucket.toByteArray());
			        t.setReadOnly();
			        return t;
			    } catch (IOException e) {
			        Logger.error(this, "Impossible: "+e, e);
			        return null;
			    }
			}
		}
		File f = getBlobFile();
		if(f == null) return null;
		try {
			return new FileRandomAccessBuffer(f, true);
		} catch(FileNotFoundException e) {
			Logger.error(this, "We do not have the blob file for the revocation even though we have successfully downloaded it!", e);
			return null;
		} catch (IOException e) {
            Logger.error(this, "Error reading downloaded revocation blob file: "+e, e);
            return null;
		}
	}
	
	/** Get the binary blob, if we have fetched it. */
	private File getBlobFile() {
		if(blobFile.exists()) return blobFile;
		return null;
	}

	@Override
	public boolean persistent() {
		return false;
	}

	@Override
	public boolean realTimeFlag() {
		return false;
	}

    @Override
    public void onResume(ClientContext context) {
        // Do nothing. Not persistent.
    }

    @Override
    public RequestClient getRequestClient() {
        return this;
    }

}
