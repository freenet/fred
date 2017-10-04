/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.fcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.FetchResult;
import freenet.client.InsertContext;
import freenet.client.async.BinaryBlob;
import freenet.client.async.BinaryBlobWriter;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientGetCallback;
import freenet.client.async.ClientGetter;
import freenet.client.async.ClientRequester;
import freenet.client.async.CompatibilityAnalyser;
import freenet.client.async.PersistenceDisabledException;
import freenet.client.async.PersistentClientCallback;
import freenet.client.async.PersistentJob;
import freenet.client.events.ClientEvent;
import freenet.client.events.ClientEventListener;
import freenet.client.events.EnterFiniteCooldownEvent;
import freenet.client.events.ExpectedFileSizeEvent;
import freenet.client.events.ExpectedHashesEvent;
import freenet.client.events.ExpectedMIMEEvent;
import freenet.client.events.SendingToNetworkEvent;
import freenet.client.events.SplitfileCompatibilityModeEvent;
import freenet.client.events.SplitfileProgressEvent;
import freenet.clients.fcp.RequestIdentifier.RequestType;
import freenet.crypt.ChecksumChecker;
import freenet.crypt.ChecksumFailedException;
import freenet.crypt.HashResult;
import freenet.keys.FreenetURI;
import freenet.node.NodeClientCore;
import freenet.support.CurrentTimeUTC;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;
import freenet.support.io.ArrayBucketFactory;
import freenet.support.io.BucketTools;
import freenet.support.io.FileBucket;
import freenet.support.io.NativeThread;
import freenet.support.io.NullBucket;
import freenet.support.io.ResumeFailedException;
import freenet.support.io.StorageFormatException;

/**
 * A simple client fetch. This can of course fetch arbitrarily large
 * files, including splitfiles, redirects, etc.
 */
public class ClientGet extends ClientRequest implements ClientGetCallback, ClientEventListener, PersistentClientCallback {

    private static final long serialVersionUID = 1L;
    /** Fetch context. Never passed in: always created new by the ClientGet. Therefore, we
	 * can safely delete it in requestWasRemoved(). */
	private final FetchContext fctx;
	private final ClientGetter getter;
	private final ReturnType returnType;
	private final File targetFile;
	/** Bucket returned when the request was completed, if returnType == RETURN_TYPE_DIRECT. */
	private Bucket returnBucketDirect;
	private final boolean binaryBlob;
	private final String extensionCheck;
	private final Bucket initialMetadata;

	// Verbosity bitmasks
	private static final int VERBOSITY_SPLITFILE_PROGRESS = 1;
	private static final int VERBOSITY_SENT_TO_NETWORK = 2;
	private static final int VERBOSITY_COMPATIBILITY_MODE = 4;
	private static final int VERBOSITY_EXPECTED_HASHES = 8;
	private static final int VERBOSITY_EXPECTED_TYPE = 32;
	private static final int VERBOSITY_EXPECTED_SIZE = 64;
	private static final int VERBOSITY_ENTER_FINITE_COOLDOWN = 128;

	// Stuff waiting for reconnection
	/** Did the request succeed? Valid if finished. */
	private boolean succeeded;
	/** Length of the found data. Will be updated from ClientGetter in onResume() but we persist 
	 * it anyway. */
	private long foundDataLength = -1;
	/** MIME type of the found data. Will be updated from ClientGetter in onResume() but we persist 
     * it anyway. */
	private String foundDataMimeType;
	/** Details of request failure. */
	private GetFailedMessage getFailedMessage;
	/** Last progress message. Not persistent, ClientGetter will update on onResume(). */
	private transient SimpleProgressMessage progressPending;
	/** Have we received a SendingToNetworkEvent? */
	private boolean sentToNetwork;
	/** Current compatibility mode. This is updated over time as the request progresses, and can be
	 * used e.g. to reinsert the file. This is NOT transient, as the ClientGetter does not retain 
	 * this information. */
	private CompatibilityAnalyser compatMode;
	/** Expected hashes of the final data. Will be updated from ClientGetter in onResume() but we 
	 * persist it anyway.  */
	private ExpectedHashes expectedHashes;

	private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
    private static Map<Short, ReturnType> returnTypeByCode = new HashMap<Short, ReturnType>();
    
	public enum ReturnType {
	    DIRECT((short)0),
	    NONE((short)1),
	    DISK((short)2),
	    CHUNKED((short)3);
	    
	    final short code;
	    
	    ReturnType(short code) {
	        if(returnTypeByCode.containsKey(code)) throw new Error("Duplicate");
	        returnTypeByCode.put(code, this);
	        this.code = code;
	    }
	    
	    public static ReturnType getByCode(short x) {
	        ReturnType u = returnTypeByCode.get(x);
	        if(u == null) throw new IllegalArgumentException();
	        return u;
	    }
	    
	}

	/**
	 * Create one for a global-queued request not made by FCP.
	 * @throws IdentifierCollisionException
	 * @throws NotAllowedException
	 * @throws IOException
	 */
	public ClientGet(PersistentRequestClient globalClient, FreenetURI uri, boolean dsOnly, boolean ignoreDS,
			boolean filterData, int maxSplitfileRetries, int maxNonSplitfileRetries,
			long maxOutputLength, ReturnType returnType, boolean persistRebootOnly, String identifier, int verbosity,
			short prioClass, File returnFilename, boolean writeToClientCache, boolean realTimeFlag, boolean binaryBlob, NodeClientCore core) throws IdentifierCollisionException, NotAllowedException, IOException {
		super(uri, identifier, verbosity, null, globalClient,
				prioClass,
				(persistRebootOnly ? Persistence.REBOOT : Persistence.FOREVER), realTimeFlag, null, true);

		fctx = core.clientContext.getDefaultPersistentFetchContext();
		fctx.eventProducer.addEventListener(this);
		fctx.localRequestOnly = dsOnly;
		fctx.ignoreStore = ignoreDS;
		fctx.maxNonSplitfileRetries = maxNonSplitfileRetries;
		fctx.maxSplitfileBlockRetries = maxSplitfileRetries;
		fctx.filterData = filterData;
		fctx.maxOutputLength = maxOutputLength;
		fctx.maxTempLength = maxOutputLength;
		fctx.canWriteClientCache = writeToClientCache;
		compatMode = new CompatibilityAnalyser();
		// FIXME fctx.ignoreUSKDatehints = ignoreUSKDatehints;
		Bucket ret = null;
		this.returnType = returnType;
		this.binaryBlob = binaryBlob;
		String extensionCheck = null;
		if(returnType == ReturnType.DISK) {
			this.targetFile = returnFilename;
			if(!(core.allowDownloadTo(returnFilename)))
				throw new NotAllowedException();
			if(targetFile.exists()) {
			    if(targetFile.length() == 0) {
			        // FIXME get rid
			        // Dirty hack for migration
			        // Ignore zero length file as we probably created it.
			        targetFile.delete();
                    Logger.error(this, "Target file already exists but is zero length, deleting...");
			    }
			    if(targetFile.exists())
			        throw new IOException("Target filename exists already: "+targetFile);
			}
			ret = new FileBucket(returnFilename, false, true, false, false);
			if(filterData) {
				String name = returnFilename.getName();
				int idx = name.lastIndexOf('.');
				if(idx != -1) {
					idx++;
					if(idx != name.length())
						extensionCheck = name.substring(idx);
				}
			}
		} else if(returnType == ReturnType.NONE) {
			targetFile = null;
			ret = new NullBucket();
		} else {
		    targetFile = null;
		    ret = null; // Let the ClientGetter allocate the Bucket later on.
		}
		this.extensionCheck = extensionCheck;
		this.initialMetadata = null;
		getter = makeGetter(core, ret);
	}

	public ClientGet(FCPConnectionHandler handler, ClientGetMessage message, 
	        NodeClientCore core) throws IdentifierCollisionException, MessageInvalidException {
		super(message.uri, message.identifier, message.verbosity, handler,
				message.priorityClass, message.persistence, message.realTimeFlag, message.clientToken, message.global);
		// Create a Fetcher directly in order to get more fine-grained control,
		// since the client may override a few context elements.
		fctx = core.clientContext.getDefaultPersistentFetchContext();
		fctx.eventProducer.addEventListener(this);
		// ignoreDS
		fctx.localRequestOnly = message.dsOnly;
		fctx.ignoreStore = message.ignoreDS;
		fctx.maxNonSplitfileRetries = message.maxRetries;
		fctx.maxSplitfileBlockRetries = message.maxRetries;
		// FIXME do something with verbosity !!
		// Has already been checked
		fctx.maxOutputLength = message.maxSize;
		fctx.maxTempLength = message.maxTempSize;
		fctx.canWriteClientCache = message.writeToClientCache;
		fctx.filterData = message.filterData;
		fctx.ignoreUSKDatehints = message.ignoreUSKDatehints;
		compatMode = new CompatibilityAnalyser();

		if(message.allowedMIMETypes != null) {
			fctx.allowedMIMETypes = new HashSet<String>();
			for(String mime : message.allowedMIMETypes)
				fctx.allowedMIMETypes.add(mime);
		}

		this.returnType = message.returnType;
		this.binaryBlob = message.binaryBlob;
		Bucket ret = null;
		String extensionCheck = null;
		if(returnType == ReturnType.DISK) {
			this.targetFile = message.diskFile;
			if(!core.allowDownloadTo(targetFile))
				throw new MessageInvalidException(ProtocolErrorMessage.ACCESS_DENIED, "Not allowed to download to "+targetFile, identifier, global);
			else if(!(handler.allowDDAFrom(targetFile, true)))
				throw new MessageInvalidException(ProtocolErrorMessage.DIRECT_DISK_ACCESS_DENIED, "Not allowed to download to " + targetFile + ". You might need to do a " + TestDDARequestMessage.NAME + " first.", identifier, global);
			ret = new FileBucket(targetFile, false, true, false, false);
			if(fctx.filterData) {
				String name = targetFile.getName();
				int idx = name.lastIndexOf('.');
				if(idx != -1) {
					idx++;
					if(idx != name.length())
						extensionCheck = name.substring(idx);
				}
			}
		} else if(returnType == ReturnType.NONE) {
			targetFile = null;
			ret = new NullBucket();
        } else {
            targetFile = null;
            ret = null; // Let the ClientGetter allocate the Bucket later on.
		}
		this.extensionCheck = extensionCheck;
		initialMetadata = message.getInitialMetadata();
        try {
            getter = makeGetter(core, ret);
        } catch (IOException e) {
            Logger.error(this, "Cannot create bucket for temporary storage: "+e, e);
            // This is *not* a FetchException since we don't register it: it's a protocol error.
            throw new MessageInvalidException(ProtocolErrorMessage.INTERNAL_ERROR,
                    "Cannot create bucket for temporary storage (out of disk space?): " + e, identifier, global);
        }
	}

    private ClientGetter makeGetter(Bucket ret) throws IOException {
        return makeGetter(null, ret);
    }

    private ClientGetter makeGetter(NodeClientCore core, Bucket ret) throws IOException {
        if (binaryBlob && ret == null) {
            ret = core.clientContext.getBucketFactory(persistence == Persistence.FOREVER).makeBucket(fctx.maxOutputLength);
        }

	    return new ClientGetter(this,
                uri, fctx, priorityClass,
                binaryBlob ? new NullBucket() : ret, binaryBlob ? new BinaryBlobWriter(ret) : null, false, initialMetadata, extensionCheck);
	}
	
	protected ClientGet() {
	    // For serialization.
	    fctx = null;
	    getter = null;
	    returnType = null;
	    targetFile = null;
	    binaryBlob = false;
	    extensionCheck = null;
	    initialMetadata = null;
	}

	/**
	 * Must be called just after construction, but within a transaction.
	 * @throws IdentifierCollisionException If the identifier is already in use.
	 */
	@Override
	void register(boolean noTags) throws IdentifierCollisionException {
		if(client != null)
			assert(this.persistence == client.persistence);
		if(persistence != Persistence.CONNECTION)
			client.register(this);
			if(persistence != Persistence.CONNECTION && !noTags) {
				FCPMessage msg = persistentTagMessage();
				client.queueClientRequestMessage(msg, 0);
			}
	}

	@Override
	public void start(ClientContext context) {
		try {
			synchronized(this) {
				if(finished) return;
			}
			getter.start(context);
			if(persistence != Persistence.CONNECTION && !finished) {
				FCPMessage msg = persistentTagMessage();
				client.queueClientRequestMessage(msg, 0);
			}
			synchronized(this) {
				started = true;
			}
			if(client != null) {
				RequestStatusCache cache = client.getRequestStatusCache();
				if(cache != null) {
					cache.updateStarted(identifier, true);
				}
			}
		} catch (FetchException e) {
			synchronized(this) {
				started = true;
			} // before the failure handler
			onFailure(e, null);
		} catch (Throwable t) {
			synchronized(this) {
				started = true;
			}
			onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR, t), null);
		}
	}

	@Override
	public void onLostConnection(ClientContext context) {
		if(persistence == Persistence.CONNECTION)
			cancel(context);
		// Otherwise ignore
	}

	@Override
	public void onSuccess(FetchResult result, ClientGetter state) {
		Logger.minor(this, "Succeeded: "+identifier);
		Bucket data = binaryBlob ? state.getBlobBucket() : result.asBucket();
		synchronized(this) {
			if(succeeded) {
				Logger.error(this, "onSuccess called twice for "+this+" ("+identifier+ ')');
				return; // We might be called twice; ignore it if so.
			}
			started = true;
			if(!binaryBlob)
				this.foundDataMimeType = result.getMimeType();
			else
				this.foundDataMimeType = BinaryBlob.MIME_TYPE;

			// completionTime is set here rather than in finish() for two reasons:
			// 1. It must be set inside the lock.
			// 2. It must be set before AllData is sent so it is consistent.
            completionTime = System.currentTimeMillis();
			progressPending = null;
			this.foundDataLength = data.size();
			this.succeeded = true;
			finished = true;
			if(returnType == ReturnType.DIRECT)
			    returnBucketDirect = data;
		}
		trySendDataFoundOrGetFailed(null, null);
		trySendAllDataMessage(null, null);
		finish();
		if(client != null)
			client.notifySuccess(this);
	}

    public void setSuccessForMigration(long completionTime, Bucket data) throws ResumeFailedException {
        synchronized(this) {
            succeeded = true;
            started = true;
            finished = true;
            this.completionTime = completionTime;
            if(returnType == ReturnType.NONE) {
                // OK.
            } else if(returnType == ReturnType.DISK) {
                if(!(targetFile.exists() && targetFile.length() == foundDataLength))
                    throw new ResumeFailedException("Success but target file doesn't exist or isn't valid");
            } else if(returnType == ReturnType.DIRECT) {
                returnBucketDirect = data;
                if(returnBucketDirect.size() != foundDataLength)
                    throw new ResumeFailedException("Success but temporary data bucket doesn't exist or isn't valid");
            }
        }
    }

	private void trySendDataFoundOrGetFailed(FCPConnectionOutputHandler handler, String listRequestIdentifier) {
		FCPMessage msg;

		// Don't need to lock. succeeded is only ever set, never unset.
		// and succeeded and getFailedMessage are both atomic.
		if(succeeded) {
			// FIXME: Duplicate of AllDataMessage
			// FIXME: CompletionTime is set on finish() : we need to give it current time here
			msg = new DataFoundMessage(foundDataLength, foundDataMimeType, identifier, global, startupTime, completionTime != 0 ? completionTime : System.currentTimeMillis());
		} else {
			msg = getFailedMessage;
		}

		if(handler == null && persistence == Persistence.CONNECTION)
			handler = origHandler.outputHandler;
		if(handler != null)
			handler.queue(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier));
		else
			client.queueClientRequestMessage(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier), 0);
	}
	
	private synchronized AllDataMessage getAllDataMessage() {
	    if(returnType != ReturnType.DIRECT)
	        return null;
	    AllDataMessage msg = new AllDataMessage(returnBucketDirect, identifier, global, startupTime, 
	            completionTime, foundDataMimeType);
        if(persistence == Persistence.CONNECTION)
            msg.setFreeOnSent();
        return msg;
	}

	private void trySendAllDataMessage(FCPConnectionOutputHandler handler, String listRequestIdentifier) {
	    if(persistence == Persistence.CONNECTION) {
	        if(handler == null)
	            handler = origHandler.outputHandler;
	    }
	    if(handler != null) {
	        FCPMessage allData = FCPMessage.withListRequestIdentifier(getAllDataMessage(), listRequestIdentifier);
	        if(allData != null)
	            handler.queue(allData);
	    }
	}

	private void queueProgressMessageInner(FCPMessage msg, FCPConnectionOutputHandler handler, int verbosityMask) {
	    if(persistence == Persistence.CONNECTION && handler == null)
	        handler = origHandler.outputHandler;
	    if(handler != null)
	        handler.queue(msg);
	    else
	        client.queueClientRequestMessage(msg, verbosityMask);
    }

    @Override
	public void sendPendingMessages(FCPConnectionOutputHandler handler, String listRequestIdentifier, boolean includeData, boolean onlyData) {
		if(!onlyData) {
			FCPMessage msg = persistentTagMessage();
			handler.queue(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier));
			if(progressPending != null) {
				handler.queue(FCPMessage.withListRequestIdentifier(progressPending, listRequestIdentifier));
			}
			if(sentToNetwork)
				handler.queue(FCPMessage.withListRequestIdentifier(new SendingToNetworkMessage(identifier, global), listRequestIdentifier));
			if(finished)
				trySendDataFoundOrGetFailed(handler, listRequestIdentifier);
		} else if(returnType != ReturnType.DIRECT) {
		    ProtocolErrorMessage msg = new ProtocolErrorMessage(ProtocolErrorMessage.WRONG_RETURN_TYPE, false, "No AllData", identifier, global);
		    handler.queue(msg);
		    return;
		}

		if(includeData) {
		    trySendAllDataMessage(handler, listRequestIdentifier);
		}
		
		CompatibilityMode cmsg;
		ExpectedHashes expectedHashes;
		ExpectedMIME mimeMsg = null;
		ExpectedDataLength lengthMsg = null;
		synchronized(this) {
		    cmsg = new CompatibilityMode(identifier, global, compatMode);
		    expectedHashes = this.expectedHashes;
		    if(foundDataMimeType != null)
		        mimeMsg = new ExpectedMIME(identifier, global, foundDataMimeType);
		    if(foundDataLength > 0)
		        lengthMsg = new ExpectedDataLength(identifier, global, foundDataLength);
		}
		handler.queue(FCPMessage.withListRequestIdentifier(cmsg, listRequestIdentifier));

		if(expectedHashes != null) {
			handler.queue(FCPMessage.withListRequestIdentifier(expectedHashes, listRequestIdentifier));
		}

		if (mimeMsg != null) {
			handler.queue(FCPMessage.withListRequestIdentifier(mimeMsg, listRequestIdentifier));
		}
		if (lengthMsg != null) {
			handler.queue(FCPMessage.withListRequestIdentifier(lengthMsg, listRequestIdentifier));
		}
	}

	private FCPMessage persistentTagMessage() {
		return new PersistentGet(identifier, uri, verbosity, priorityClass, returnType, persistence, targetFile, clientToken, client.isGlobalQueue, started, fctx.maxNonSplitfileRetries, binaryBlob, fctx.maxOutputLength, isRealTime());
	}
	
	// FIXME code duplication: ClientGet ClientPut ClientPutDir
	// FIXME maybe move to ClientRequest as final protected?
	private boolean isRealTime() {
		// FIXME: remove debug code
		if (lowLevelClient == null) {
			// This can happen but only due to data corruption - old databases on which various bugs have resulted in it getting deleted, and also possibly failed deletions.
			Logger.error(this, "lowLevelClient == null", new Exception("error"));
			return false;
		}
		return lowLevelClient.realTimeFlag();
	}

	@Override
	public void onFailure(FetchException e, ClientGetter state) {
		if(finished) return;
		synchronized(this) {
		    if(e.expectedSize != 0)
		        this.foundDataLength = e.expectedSize;
		    if(e.getExpectedMimeType() != null)
		        this.foundDataMimeType = e.getExpectedMimeType();
			succeeded = false;
			getFailedMessage = new GetFailedMessage(e, identifier, global);
			finished = true;
			started = true;
			completionTime = System.currentTimeMillis();
		}
		if(logMINOR)
			Logger.minor(this, "Caught "+e, e);
		trySendDataFoundOrGetFailed(null, null);
		// We do not want the data to be removed on failure, because the request
		// may be restarted, and the bucket persists on the getter, even if we get rid of it here.
		//freeData(container);
		finish();
		if(client != null)
			client.notifyFailure(this);
	}

	@Override
	public void requestWasRemoved(ClientContext context) {
		// if request is still running, send a GetFailed with code=cancelled
		if( !finished ) {
			synchronized(this) {
				succeeded = false;
				finished = true;
				FetchException cancelled = new FetchException(FetchExceptionMode.CANCELLED);
				getFailedMessage = new GetFailedMessage(cancelled, identifier, global);
			}
			trySendDataFoundOrGetFailed(null, null);
		}
		// notify client that request was removed
		FCPMessage msg = new PersistentRequestRemovedMessage(getIdentifier(), global);
		if(persistence != Persistence.CONNECTION) {
		client.queueClientRequestMessage(msg, 0);
		}

		freeData();

		super.requestWasRemoved(context);
	}

	@Override
	public void receive(ClientEvent ce, ClientContext context) {
	    if(logMINOR) Logger.minor(this, "Receiving "+ce+" on "+this);
	    final FCPMessage progress;
		final int verbosityMask;
		if(ce instanceof SplitfileProgressEvent) {
			verbosityMask = ClientGet.VERBOSITY_SPLITFILE_PROGRESS;
			synchronized(this) {
			    progress = progressPending = 
			        new SimpleProgressMessage(identifier, global, (SplitfileProgressEvent)ce);
			}
			if(client != null) {
			    RequestStatusCache cache = client.getRequestStatusCache();
			    if(cache != null) {
			        cache.updateStatus(identifier, (progressPending).getEvent());
			    }
			}
            if((verbosity & verbosityMask) == 0)
                return;
		} else if(ce instanceof SendingToNetworkEvent) {
			verbosityMask = ClientGet.VERBOSITY_SENT_TO_NETWORK;
			synchronized(this) {
			    sentToNetwork = true;
			}
			if((verbosity & verbosityMask) == 0)
				return;
			progress = new SendingToNetworkMessage(identifier, global);
		} else if(ce instanceof SplitfileCompatibilityModeEvent) {
		    handleCompatibilityMode((SplitfileCompatibilityModeEvent)ce, context);
		    return;
		} else if(ce instanceof ExpectedHashesEvent) {
            ExpectedHashesEvent event = (ExpectedHashesEvent)ce;
		    synchronized(this) {
		        if(expectedHashes != null) {
		            Logger.error(this, "Got a new ExpectedHashes", new Exception("debug"));
		            return;
		        } else {
		            progress = this.expectedHashes = new ExpectedHashes(event, identifier, global);
		        }
		    }
			verbosityMask = ClientGet.VERBOSITY_EXPECTED_HASHES;
			if((verbosity & verbosityMask) == 0)
				return;
		} else if(ce instanceof ExpectedMIMEEvent) {
            ExpectedMIMEEvent event = (ExpectedMIMEEvent)ce;
		    synchronized(this) {
		        foundDataMimeType = event.expectedMIMEType;
		    }
		    if(client != null) {
		        RequestStatusCache cache = client.getRequestStatusCache();
		        if(cache != null) {
		            cache.updateExpectedMIME(identifier, foundDataMimeType);
		        }
		    }
			verbosityMask = VERBOSITY_EXPECTED_TYPE;
            progress = new ExpectedMIME(identifier, global, event.expectedMIMEType);
			if((verbosity & verbosityMask) == 0)
				return;
		} else if(ce instanceof ExpectedFileSizeEvent) {
            ExpectedFileSizeEvent event = (ExpectedFileSizeEvent)ce;
		    synchronized(this) {
		        foundDataLength = event.expectedSize;
		    }
		    if(client != null) {
		        RequestStatusCache cache = client.getRequestStatusCache();
		        if(cache != null) {
		            cache.updateExpectedDataLength(identifier, foundDataLength);
		        }
		    }
			verbosityMask = VERBOSITY_EXPECTED_SIZE;
			if((verbosity & verbosityMask) == 0)
				return;
			progress = new ExpectedDataLength(identifier, global, event.expectedSize);
		} else if(ce instanceof EnterFiniteCooldownEvent) {
			verbosityMask = VERBOSITY_ENTER_FINITE_COOLDOWN;
			if((verbosity & verbosityMask) == 0)
				return;
			EnterFiniteCooldownEvent event = (EnterFiniteCooldownEvent)ce;
			progress = new EnterFiniteCooldown(identifier, global, event.wakeupTime);
		} else {
		    Logger.error(this, "Unknown event "+ce);
		    return; // Don't know what to do with event
		}
		queueProgressMessageInner(progress, null, verbosityMask);
	}
	
	private void handleCompatibilityMode(final SplitfileCompatibilityModeEvent ce, ClientContext context) {
	    if(persistence == Persistence.FOREVER && context.jobRunner.hasLoaded()) {
	        try {
	            context.jobRunner.queue(new PersistentJob() {
	                
	                @Override
	                public boolean run(ClientContext context) {
	                    innerHandleCompatibilityMode(ce);
	                    return false;
	                }
	                
	            }, NativeThread.HIGH_PRIORITY);
	        } catch (PersistenceDisabledException e) {
	            // Not much we can do
	        }
	    } else {
	        innerHandleCompatibilityMode(ce);
	    }
	}

	private void innerHandleCompatibilityMode(SplitfileCompatibilityModeEvent ce) {
	    compatMode.merge(ce.minCompatibilityMode, ce.maxCompatibilityMode, ce.splitfileCryptoKey, ce.dontCompress, ce.bottomLayer);
	    if(client != null) {
	        RequestStatusCache cache = client.getRequestStatusCache();
	        if(cache != null) {
	            cache.updateDetectedCompatModes(identifier, compatMode.getModes(), compatMode.getCryptoKey(), compatMode.dontCompress());
	        }
	    }
	    if((verbosity & VERBOSITY_COMPATIBILITY_MODE) != 0)
	        queueProgressMessageInner(new CompatibilityMode(identifier, global, compatMode), null, VERBOSITY_COMPATIBILITY_MODE);
    }

    @Override
	protected ClientRequester getClientRequest() {
		return getter;
	}

	@Override
	protected void freeData() {
	    // We don't remove the data if written to a file.
		Bucket data;
		synchronized(this) {
			data = returnBucketDirect;
			returnBucketDirect = null;
		}
		if(data != null) {
			data.free();
		}
		if(initialMetadata != null)
		    initialMetadata.free();
	}

	@Override
	public boolean hasSucceeded() {
		return succeeded;
	}

	public boolean isDirect() {
		return this.returnType == ReturnType.DIRECT;
	}

	public boolean isToDisk() {
		return this.returnType == ReturnType.DISK;
	}

	public FreenetURI getURI() {
		return uri;
	}

	public long getDataSize() {
		if(foundDataLength > 0)
			return foundDataLength;
		return -1;
	}

	public String getMIMEType() {
		if(foundDataMimeType != null)
			return foundDataMimeType;
		return null;
	}

	public File getDestFilename() {
		return targetFile;
	}

	@Override
	public double getSuccessFraction() {
		if(progressPending != null) {
			return progressPending.getFraction();
		} else
			return -1;
	}

	@Override
	public double getTotalBlocks() {
		if(progressPending != null) {
			return progressPending.getTotalBlocks();
		} else
			return 1;
	}

	@Override
	public double getMinBlocks() {
		if(progressPending != null) {
			return progressPending.getMinBlocks();
		} else
			return 1;
	}

	@Override
	public double getFailedBlocks() {
		if(progressPending != null) {
			return progressPending.getFailedBlocks();
		} else
			return 0;
	}

	@Override
	public double getFatalyFailedBlocks() {
		if(progressPending != null) {
			return progressPending.getFatalyFailedBlocks();
		} else
			return 0;
	}

	@Override
	public double getFetchedBlocks() {
		if(progressPending != null) {
			return progressPending.getFetchedBlocks();
		} else
			return 0;
	}
	
	public InsertContext.CompatibilityMode[] getCompatibilityMode() {
	    return compatMode.getModes();
	}
	
	public boolean getDontCompress() {
		return compatMode.dontCompress();
	}
	
	public byte[] getOverriddenSplitfileCryptoKey() {
	    return compatMode.getCryptoKey();
	}

	@Override
	public String getFailureReason(boolean longDescription) {
		if(getFailedMessage == null)
			return null;
		String s = getFailedMessage.getShortFailedMessage();
		if(longDescription && getFailedMessage.extraDescription != null)
			s += ": "+getFailedMessage.extraDescription;
		return s;
	}
	
	GetFailedMessage getFailureMessage() {
		if(getFailedMessage == null) return null;
		return getFailedMessage;
	}
	
	public FetchExceptionMode getFailureReasonCode() {
		if(getFailedMessage == null)
			return null;
		return getFailedMessage.code;
		
	}

	@Override
	public boolean isTotalFinalized() {
		if(finished && succeeded) return true;
		if(progressPending == null) return false;
		else {
			return progressPending.isTotalFinalized();
		}
	}

	/**
	 * Returns the {@link Bucket} that contains the downloaded data.
	 *
	 * @return The data in a {@link Bucket}, or <code>null</code> if this
	 *         isn&rsquo;t applicable
	 */
	public Bucket getBucket() {
	    return makeBucket(true);
	}
	
	private Bucket makeBucket(boolean readOnly) {
	    if(returnType == ReturnType.DIRECT) {
	        synchronized(this) {
	            return returnBucketDirect;
	        }
	    } else if(returnType == ReturnType.DISK) {
	        return new FileBucket(targetFile, readOnly, false, false, false);
	    } else {
	        return null;
	    }
	}

	@Override
	public boolean canRestart() {
		if(!finished) {
			Logger.minor(this, "Cannot restart because not finished for "+identifier);
			return false;
		}
		if(succeeded) {
			Logger.minor(this, "Cannot restart because succeeded for "+identifier);
			return false;
		}
		return getter.canRestart();
	}

	@Override
	public boolean restart(ClientContext context, final boolean disableFilterData) {
		if(!canRestart()) return false;
		FreenetURI redirect = null;
		synchronized(this) {
			finished = false;
			if(persistence == Persistence.FOREVER && getFailedMessage != null) {
				if(getFailedMessage.redirectURI != null) {
					redirect =
						getFailedMessage.redirectURI;
				}
			} else if(getFailedMessage != null)
				redirect = getFailedMessage.redirectURI;
			this.getFailedMessage = null;
			this.progressPending = null;
			compatMode = new CompatibilityAnalyser();
			expectedHashes = null;
			started = false;
			if(disableFilterData)
				fctx.filterData = false;
		}
		if(client != null) {
			RequestStatusCache cache = client.getRequestStatusCache();
			if(cache != null) {
				cache.updateStarted(identifier, redirect);
			}
		}
		try {
			if(getter.restart(redirect, fctx.filterData, context)) {
				synchronized(this) {
					if(redirect != null) {
						this.uri = redirect;
					}
					started = true;
				}
			}
			if(client != null) {
				RequestStatusCache cache = client.getRequestStatusCache();
				if(cache != null) {
					cache.updateStarted(identifier, true);
				}
			}
			return true;
		} catch (FetchException e) {
			onFailure(e, null);
			return false;
		}
	}

	public synchronized boolean hasPermRedirect() {
		return getFailedMessage != null && getFailedMessage.redirectURI != null;
	}

	public boolean filterData() {
		return fctx.filterData;
	}

	@Override
	synchronized RequestStatus getStatus() {
		boolean totalFinalized = false;
		int total = 0, min = 0, fetched = 0, fatal = 0, failed = 0;
		// See ClientRequester.getLatestSuccess() for why this defaults to current time.
		Date latestSuccess = CurrentTimeUTC.get();
		Date latestFailure = null;
		
		if(progressPending != null) {
			totalFinalized = progressPending.isTotalFinalized();
			// FIXME why are these doubles???
			total = (int) progressPending.getTotalBlocks();
			min = (int) progressPending.getMinBlocks();
			fetched = (int) progressPending.getFetchedBlocks();
			latestSuccess = progressPending.getLatestSuccess();
			fatal = (int) progressPending.getFatalyFailedBlocks();
			failed = (int) progressPending.getFailedBlocks();
			latestFailure = progressPending.getLatestFailure();
		}
		if(finished && succeeded) totalFinalized = true;
		FetchExceptionMode failureCode = null;
		String failureReasonShort = null;
		String failureReasonLong = null;
		if(getFailedMessage != null) {
			failureCode = getFailedMessage.code;
			failureReasonShort = getFailedMessage.getShortFailedMessage();
			failureReasonShort = getFailedMessage.getLongFailedMessage();
		}
		String mimeType = foundDataMimeType;
		long dataSize = foundDataLength;
		File target = getDestFilename();
		if(target != null)
			target = new File(target.getPath());
		
		Bucket shadow = (finished && succeeded) ? getBucket() : null;
		if(shadow != null) {
		    if(dataSize != shadow.size()) {
		        Logger.error(this, "Size of downloaded data has changed: "+dataSize+" -> "+shadow.size()+" on "+shadow);
		        shadow = null;
		    } else {
		        shadow = shadow.createShadow();
		    }
		}
		
		boolean filterData;
		boolean overriddenDataType;
		filterData = fctx.filterData;
		overriddenDataType = fctx.overrideMIME != null || fctx.charset != null;
		
        return new DownloadRequestStatus(
            identifier, persistence, started, finished, succeeded, total, min, fetched,
            latestSuccess, fatal, failed, latestFailure, totalFinalized, priorityClass, failureCode,
            mimeType, dataSize, target, getCompatibilityMode(),  getOverriddenSplitfileCryptoKey(),
            getURI(), failureReasonShort, failureReasonLong, overriddenDataType, shadow, filterData,
            getDontCompress());
	}

	private static final long CLIENT_DETAIL_MAGIC = 0x67145b675d2e22f4L;
	private static final int CLIENT_DETAIL_VERSION = 1;

    @Override
    public void getClientDetail(DataOutputStream dos, ChecksumChecker checker) throws IOException {
        if(persistence != Persistence.FOREVER) return;
        super.getClientDetail(dos, checker);
        dos.writeLong(CLIENT_DETAIL_MAGIC);
        dos.writeInt(CLIENT_DETAIL_VERSION);
        dos.writeUTF(uri.toString());
        // Basic details needed for restarting the request.
        dos.writeShort(returnType.code);
        if(returnType == ReturnType.DISK) {
            dos.writeUTF(targetFile.toString());
        }
        dos.writeBoolean(binaryBlob);
        DataOutputStream innerDOS = 
            new DataOutputStream(checker.checksumWriterWithLength(dos, new ArrayBucketFactory()));        
        try {
            fctx.writeTo(innerDOS);
        } finally {
            innerDOS.close();
        }
        if(extensionCheck != null) {
            dos.writeBoolean(true);
            dos.writeUTF(extensionCheck);
        } else {
            dos.writeBoolean(false);
        }
        if(initialMetadata != null) {
            dos.writeBoolean(true);
            initialMetadata.storeTo(innerDOS);
        } else {
            dos.writeBoolean(false);
        }
        synchronized(this) {
            if(finished) {
                dos.writeBoolean(succeeded);
                writeTransientProgressFields(dos);
                if(succeeded) {
                    if(returnType == ReturnType.DIRECT) {
                        innerDOS = 
                            new DataOutputStream(checker.checksumWriterWithLength(dos, new ArrayBucketFactory()));
                        try {
                            returnBucketDirect.storeTo(innerDOS);
                        } finally {
                            innerDOS.close();
                        }
                    }
                } else {
                    innerDOS = 
                        new DataOutputStream(checker.checksumWriterWithLength(dos, new ArrayBucketFactory()));
                    try {
                        getFailedMessage.writeTo(innerDOS);
                    } finally {
                        innerDOS.close();
                    }
                }
                return;
            }
        }
        // Not finished, or was recently not finished.
        // Don't hold lock while calling getter.
        // If it's just finished we get a race and restart. That's okay.
        innerDOS = 
            new DataOutputStream(checker.checksumWriterWithLength(dos, new ArrayBucketFactory()));
        try {
            if(getter.writeTrivialProgress(innerDOS)) {
                writeTransientProgressFields(innerDOS);
            }
        } finally {
            innerDOS.close();
        }
    }
    
    public static ClientRequest restartFrom(DataInputStream dis, RequestIdentifier reqID, 
            ClientContext context, ChecksumChecker checker) throws StorageFormatException, IOException, ResumeFailedException {
        return new ClientGet(dis, reqID, context, checker);
    }
    
    private ClientGet(DataInputStream dis, RequestIdentifier reqID, ClientContext context, ChecksumChecker checker) 
    throws IOException, StorageFormatException, ResumeFailedException {
        super(dis, reqID, context);
        ClientGetter getter = null;
        long magic = dis.readLong();
        if(magic != CLIENT_DETAIL_MAGIC) 
            throw new StorageFormatException("Bad magic for request");
        int version = dis.readInt();
        if(version != CLIENT_DETAIL_VERSION)
            throw new StorageFormatException("Bad version "+version);
        String s = dis.readUTF();
        try {
            uri = new FreenetURI(s);
        } catch (MalformedURLException e) {
            throw new StorageFormatException("Bad URI");
        }
        short r = dis.readShort();
        try {
            returnType = ReturnType.getByCode(r);
        } catch (IllegalArgumentException e) {
            throw new StorageFormatException("Bad return type "+r);
        }
        if(returnType == ReturnType.DISK) {
            targetFile = new File(dis.readUTF());
        } else {
            targetFile = null;
        }
        binaryBlob = dis.readBoolean();
        FetchContext fctx = null;
        try {
            DataInputStream innerDIS =
                new DataInputStream(checker.checksumReaderWithLength(dis, context.tempBucketFactory, 65536));
            try {
                fctx = new FetchContext(innerDIS);
            } catch (IOException e) {
                Logger.error(this, "Unable to read fetch settings, will use default settings: "+e, e);
            } finally {
                innerDIS.close();
            }
        } catch (ChecksumFailedException e) {
            Logger.error(this, "Unable to read fetch settings, will use default settings");
        }
        if(fctx == null) {
            fctx = context.getDefaultPersistentFetchContext();
        }
        this.fctx = fctx;
        fctx.eventProducer.addEventListener(this);
        if(dis.readBoolean())
            extensionCheck = dis.readUTF();
        else
            extensionCheck = null;
        if(dis.readBoolean()) {
            initialMetadata = BucketTools.restoreFrom(dis, context.persistentFG, context.persistentFileTracker, context.getPersistentMasterSecret());
            // No way to recover if we don't have the initialMetadata.
        } else {
            initialMetadata = null;
        }
        if(finished) {
            succeeded = dis.readBoolean();
            readTransientProgressFields(dis);
            if(succeeded) {
                if(returnType == ReturnType.DIRECT) {
                    try {
                        DataInputStream innerDIS =
                            new DataInputStream(checker.checksumReaderWithLength(dis, context.tempBucketFactory, 65536));
                        try {
                            returnBucketDirect = BucketTools.restoreFrom(innerDIS, context.persistentFG, context.persistentFileTracker, context.getPersistentMasterSecret());
                        } catch (IOException e) {
                            Logger.error(this, "Failed to restore completed download-to-temp-space request, restarting instead");
                            returnBucketDirect = null;
                            succeeded = false;
                            finished = false;
                        } finally {
                            innerDIS.close();
                        }
                    } catch (ChecksumFailedException e) {
                        Logger.error(this, "Failed to restore completed download-to-temp-space request, restarting instead");
                        returnBucketDirect = null;
                        succeeded = false;
                        finished = false;
                    } catch (StorageFormatException e) {
                        Logger.error(this, "Failed to restore completed download-to-temp-space request, restarting instead");
                        returnBucketDirect = null;
                        succeeded = false;
                        finished = false;
                    }
                }
            } else {
                try {
                    DataInputStream innerDIS =
                        new DataInputStream(checker.checksumReaderWithLength(dis, context.tempBucketFactory, 65536));
                    try {
                        getFailedMessage = new GetFailedMessage(innerDIS, reqID, foundDataLength, foundDataMimeType);
                        started = true;
                    } catch (IOException e) {
                        Logger.error(this, "Unable to restore reason for failure, restarting request : "+e, e);
                        finished = false;
                        getFailedMessage = null;
                    } finally {
                        innerDIS.close();
                    }
                } catch (ChecksumFailedException e) {
                    Logger.error(this, "Unable to restore reason for failure, restarting request");
                    finished = false;
                    getFailedMessage = null;
                }
            }
        } else {
            getter = makeGetter(makeBucket(false));
            try {
                DataInputStream innerDIS =
                    new DataInputStream(checker.checksumReaderWithLength(dis, context.tempBucketFactory, 65536));
                try {
                    if(getter.resumeFromTrivialProgress(innerDIS, context)) {
                        readTransientProgressFields(innerDIS);
                    }
                } catch (IOException e) {
                    Logger.error(this, "Unable to restore splitfile, restarting: "+e);
                } finally {
                    innerDIS.close();
                }
            } catch (ChecksumFailedException e) {
                Logger.error(this, "Unable to restore splitfile, restarting (checksum failed)");
            }
        }
        if(compatMode == null)
            compatMode = new CompatibilityAnalyser();
        if(getter == null) getter = makeGetter(makeBucket(false));
        this.getter = getter;
    }

    private void readTransientProgressFields(DataInputStream dis) throws IOException, StorageFormatException {
        foundDataLength = dis.readLong();
        if(dis.readBoolean())
            foundDataMimeType = dis.readUTF();
        else
            foundDataMimeType = null;
        compatMode = new CompatibilityAnalyser(dis);
        HashResult[] hashes = HashResult.readHashes(dis);
        if(hashes == null || hashes.length == 0) {
            expectedHashes = null;
        } else {
            expectedHashes = new ExpectedHashes(hashes, identifier, global);
        }
    }
    
    private synchronized void writeTransientProgressFields(DataOutputStream dos) throws IOException {
        dos.writeLong(foundDataLength);
        if(foundDataMimeType != null) {
            dos.writeBoolean(true);
            dos.writeUTF(foundDataMimeType);
        } else {
            dos.writeBoolean(false);
        }
        compatMode.writeTo(dos);
        HashResult.write(expectedHashes == null ? null : expectedHashes.hashes, dos);
    }

    @Override
    protected void innerResume(ClientContext context) throws ResumeFailedException {
        if(returnBucketDirect != null) returnBucketDirect.onResume(context);
        if(initialMetadata != null) initialMetadata.onResume(context);
        // We might already have these if we've just restored.
        if(foundDataLength <= 0)
            this.foundDataLength = getter.expectedSize();
        if(foundDataMimeType == null)
            this.foundDataMimeType = getter.expectedMIME();
    }

    @Override
    RequestType getType() {
        return RequestType.GET;
    }

    @Override
    public boolean fullyResumed() {
        return getter != null && getter.resumedFetcher();
    }

}
