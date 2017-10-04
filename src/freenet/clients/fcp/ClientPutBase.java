package freenet.clients.fcp;

import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;

import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.async.BaseClientPutter;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientPutCallback;
import freenet.client.events.ClientEvent;
import freenet.client.events.ClientEventListener;
import freenet.client.events.FinishedCompressionEvent;
import freenet.client.events.ExpectedHashesEvent;
import freenet.client.events.SplitfileProgressEvent;
import freenet.client.events.StartedCompressionEvent;
import freenet.clients.fcp.ClientRequest.Persistence;
import freenet.keys.FreenetURI;
import freenet.keys.InsertableClientSSK;
import freenet.node.NodeClientCore;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;

/**
 * Base class for ClientPut and ClientPutDir.
 * Any code which can be shared between the two goes here.
 */
public abstract class ClientPutBase extends ClientRequest implements ClientPutCallback, ClientEventListener {

    private static final long serialVersionUID = 1L;
    /** Created new for each ClientPutBase, so we have to delete it in requestWasRemoved() */
	final InsertContext ctx;

	// Verbosity bitmasks
	private static final int VERBOSITY_SPLITFILE_PROGRESS = 1;
	
	private static final int VERBOSITY_EXPECTED_HASHES = 8; // same as ClientGet
	private static final int VERBOSITY_PUT_FETCHABLE = 256;
	private static final int VERBOSITY_COMPRESSION_START_END = 512;

	// Stuff waiting for reconnection
	/** Has the request succeeded? */
	protected boolean succeeded;
	/** If the request failed, how did it fail? PutFailedMessage is the most
	 * convenient way to store this (InsertException has a stack trace!).
	 */
	protected PutFailedMessage putFailedMessage;
	/** URI generated for the insert. */
	protected FreenetURI generatedURI;
	// This could be a SimpleProgress, or it could be started/finished compression.
	// Not that important, so not saved on persistence.
	// Probably saving it would conflict with later changes (full persistence at
	// ClientPutter level).
	protected transient FCPMessage progressMessage;
	
	protected final FreenetURI publicURI;
	
	/** Metadata returned instead of URI */
	private Bucket generatedMetadata;

	public final static String SALT = "Salt";
	public final static String FILE_HASH = "FileHash";

	private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
	private static Map<Integer, UploadFrom> uploadFromByCode = new HashMap<Integer, UploadFrom>();
	
	public enum UploadFrom { // Codes must be constant at least for migration
	    DIRECT(0),
	    DISK(1),
	    REDIRECT(2);
	    
	    final int code;
	    
	    UploadFrom(int code) {
	        if(uploadFromByCode.containsKey(code)) throw new Error("Duplicate");
	        uploadFromByCode.put(code, this);
	        this.code = code;
	    }
	    
	    public static UploadFrom getByCode(int x) {
	        UploadFrom u = uploadFromByCode.get(x);
	        if(u == null) throw new IllegalArgumentException();
	        return u;
	    }
	    
	}
	
	public ClientPutBase(FreenetURI uri, String identifier, int verbosity,
			FCPConnectionHandler handler, short priorityClass, Persistence persistence, String clientToken, boolean global,
			boolean getCHKOnly, boolean dontCompress, boolean localRequestOnly, int maxRetries, boolean earlyEncode, boolean canWriteClientCache, boolean forkOnCacheable, String compressorDescriptor, int extraInsertsSingleBlock, int extraInsertsSplitfileHeader, boolean realTimeFlag, InsertContext.CompatibilityMode compatibilityMode, boolean ignoreUSKDatehints, FCPServer server) throws MalformedURLException {
		super(uri, identifier, verbosity, handler, priorityClass, persistence, realTimeFlag, clientToken, global);
		ctx = server.core.clientContext.getDefaultPersistentInsertContext();
        ctx.getCHKOnly = getCHKOnly;
		ctx.dontCompress = dontCompress;
		ctx.eventProducer.addEventListener(this);
		ctx.maxInsertRetries = maxRetries;
		ctx.canWriteClientCache = canWriteClientCache;
		ctx.compressorDescriptor = compressorDescriptor;
		ctx.forkOnCacheable = forkOnCacheable;
		ctx.extraInsertsSingleBlock = extraInsertsSingleBlock;
		ctx.extraInsertsSplitfileHeaderBlock = extraInsertsSplitfileHeader;
		ctx.setCompatibilityMode(compatibilityMode);
		ctx.localRequestOnly = localRequestOnly;
		ctx.earlyEncode = earlyEncode;
		ctx.ignoreUSKDatehints = ignoreUSKDatehints;
		publicURI = this.uri.deriveRequestURIFromInsertURI();
	}
	
	protected ClientPutBase() {
	    // For serialization.
	    ctx = null;
	    publicURI = null;
	}

	static FreenetURI checkEmptySSK(FreenetURI uri, String filename, ClientContext context) {
		if("SSK".equals(uri.getKeyType()) && uri.getDocName() == null && uri.getRoutingKey() == null) {
			if(filename == null || filename.equals("")) filename = "key";
			// SSK@ = use a random SSK.
	    	InsertableClientSSK key = InsertableClientSSK.createRandom(context.random, "");
	    	return key.getInsertURI().setDocName(filename);
		} else {
			return uri;
		}
	}

	public ClientPutBase(FreenetURI uri, String identifier, int verbosity,
			FCPConnectionHandler handler, PersistentRequestClient client, short priorityClass, Persistence persistence, String clientToken,
			boolean global, boolean getCHKOnly, boolean dontCompress, int maxRetries, boolean earlyEncode, boolean canWriteClientCache, boolean forkOnCacheable, boolean localRequestOnly, int extraInsertsSingleBlock, int extraInsertsSplitfileHeader, boolean realTimeFlag, String compressorDescriptor, InsertContext.CompatibilityMode compatMode, boolean ignoreUSKDatehints, NodeClientCore core) throws MalformedURLException {
		super(uri, identifier, verbosity, handler, client, priorityClass, persistence, realTimeFlag, clientToken, global);
		ctx = core.clientContext.getDefaultPersistentInsertContext();
        ctx.getCHKOnly = getCHKOnly;
		ctx.dontCompress = dontCompress;
		ctx.eventProducer.addEventListener(this);
		ctx.maxInsertRetries = maxRetries;
		ctx.canWriteClientCache = canWriteClientCache;
		ctx.compressorDescriptor = compressorDescriptor;
		ctx.forkOnCacheable = forkOnCacheable;
		ctx.extraInsertsSingleBlock = extraInsertsSingleBlock;
		ctx.extraInsertsSplitfileHeaderBlock = extraInsertsSplitfileHeader;
		ctx.localRequestOnly = localRequestOnly;
		ctx.setCompatibilityMode(compatMode);
		ctx.ignoreUSKDatehints = ignoreUSKDatehints;
		ctx.earlyEncode = earlyEncode;
		publicURI = this.uri.deriveRequestURIFromInsertURI();
	}

	@Override
	public void onLostConnection(ClientContext context) {
		if(persistence == Persistence.CONNECTION)
			cancel(context);
		// otherwise ignore
	}

	@Override
	public void onSuccess(BaseClientPutter state) {
		synchronized(this) {
			// Including this helps with certain bugs...
			//progressMessage = null;
		    started = true; // FIXME remove, used by resuming
			succeeded = true;
			finished = true;
			completionTime = System.currentTimeMillis();
			if(generatedURI == null)
				Logger.error(this, "No generated URI in onSuccess() for "+this+" from "+state);
		}
    if (persistence == Persistence.CONNECTION) {
      freeData();
    }
		finish();
		trySendFinalMessage(null, null);
		if(client != null)
			client.notifySuccess(this);
	}

	@Override
	public void onFailure(InsertException e, BaseClientPutter state) {
		if(finished) return;
		synchronized(this) {
		    started = true; // FIXME remove, used by resuming
			finished = true;
			completionTime = System.currentTimeMillis();
			putFailedMessage = new PutFailedMessage(e, identifier, global);
		}
    if (persistence == Persistence.CONNECTION) {
      freeData();
    }
		finish();
		trySendFinalMessage(null, null);
		if(client != null)
			client.notifyFailure(this);
	}

	@Override
	public void onGeneratedURI(FreenetURI uri, BaseClientPutter state) {
		synchronized(this) {
			if(generatedURI != null) {
				if(!uri.equals(generatedURI))
					Logger.error(this, "onGeneratedURI("+uri+ ',' +state+") but already set generatedURI to "+generatedURI);
				else
					if(logMINOR) Logger.minor(this, "onGeneratedURI() twice with same value: "+generatedURI+" -> "+uri);
			} else {
				generatedURI = uri;
			}
		}
		trySendGeneratedURIMessage(null, null);
		if(client != null) {
			RequestStatusCache cache = client.getRequestStatusCache();
			if(cache != null) {
				cache.gotFinalURI(identifier, uri);
			}
		}
	}
	
	public FreenetURI getGeneratedURI() {
		return generatedURI;
	}
	
	@Override
	public void onGeneratedMetadata(Bucket metadata, BaseClientPutter state) {
		boolean delete = false;
		synchronized(this) {
			if(generatedURI != null)
				Logger.error(this, "Got generated metadata but already have URI on "+this+" from "+state);
			if(generatedMetadata != null) {
				Logger.error(this, "Already got generated metadata from "+state+" on "+this);
				delete = true;
			} else {
				generatedMetadata = metadata;
			}
		}
		if(delete) {
			metadata.free();
		} else {
			trySendGeneratedMetadataMessage(metadata, null, null);
		}
	}
	
	@Override
	public void requestWasRemoved(ClientContext context) {
		// if request is still running, send a PutFailed with code=cancelled
		if( !finished ) {
			synchronized(this) {
				finished = true;
				InsertException cancelled = new InsertException(InsertExceptionMode.CANCELLED);
				putFailedMessage = new PutFailedMessage(cancelled, identifier, global);
			}
			trySendFinalMessage(null, null);
		}
		// notify client that request was removed
		FCPMessage msg = new PersistentRequestRemovedMessage(getIdentifier(), global);
		if(persistence == Persistence.CONNECTION)
			origHandler.outputHandler.queue(msg);
		else
		client.queueClientRequestMessage(msg, 0);

		freeData();
		Bucket meta;
		synchronized(this) {
			meta = generatedMetadata;
			generatedMetadata = null;
		}
		// FIXME combine the synchronized blocks, null out even if non-persistent.
		if(meta != null) {
			meta.free();
		}
		if(persistence == Persistence.FOREVER) {
			synchronized(this) {
				putFailedMessage = null;
				generatedURI = null;
				progressMessage = null;
			}
		}
		super.requestWasRemoved(context);
	}

	@Override
	public void receive(final ClientEvent ce, ClientContext context) {
		if(finished) return;
		if(logMINOR) Logger.minor(this, "Receiving event "+ce+" on "+this);
		if(ce instanceof SplitfileProgressEvent) {
			if((verbosity & VERBOSITY_SPLITFILE_PROGRESS) == VERBOSITY_SPLITFILE_PROGRESS) {
				SimpleProgressMessage progress = 
					new SimpleProgressMessage(identifier, global, (SplitfileProgressEvent)ce);
				trySendProgressMessage(progress, VERBOSITY_SPLITFILE_PROGRESS, null);
			}
			if(client != null) {
				RequestStatusCache cache = client.getRequestStatusCache();
				if(cache != null) {
					cache.updateStatus(identifier, (SplitfileProgressEvent)ce);
				}
			}
		} else if(ce instanceof StartedCompressionEvent) {
			if((verbosity & VERBOSITY_COMPRESSION_START_END) == VERBOSITY_COMPRESSION_START_END) {
				StartedCompressionMessage msg =
					new StartedCompressionMessage(identifier, global, ((StartedCompressionEvent)ce).codec);
				trySendProgressMessage(msg, VERBOSITY_COMPRESSION_START_END, null);
				onStartCompressing();
			}
		} else if(ce instanceof FinishedCompressionEvent) {
			if((verbosity & VERBOSITY_COMPRESSION_START_END) == VERBOSITY_COMPRESSION_START_END) {
				FinishedCompressionMessage msg = 
					new FinishedCompressionMessage(identifier, global, (FinishedCompressionEvent)ce);
				trySendProgressMessage(msg, VERBOSITY_COMPRESSION_START_END, null);
				onStopCompressing();
			}
		} else if(ce instanceof ExpectedHashesEvent) {
			if((verbosity & VERBOSITY_EXPECTED_HASHES) == VERBOSITY_EXPECTED_HASHES) {
				ExpectedHashes msg =
					new ExpectedHashes((ExpectedHashesEvent)ce, identifier, global);
				trySendProgressMessage(msg, VERBOSITY_EXPECTED_HASHES, null);
				//FIXME: onHashesComputed();
			}
		}
	}

	protected abstract void onStopCompressing();

	protected abstract void onStartCompressing();

	@Override
	public void onFetchable(BaseClientPutter putter) {
		if(finished) return;
		if((verbosity & VERBOSITY_PUT_FETCHABLE) == VERBOSITY_PUT_FETCHABLE) {
			FreenetURI temp;
			synchronized (this) {
				temp = generatedURI;
			}
			PutFetchableMessage msg =
				new PutFetchableMessage(identifier, global, temp);
			trySendProgressMessage(msg, VERBOSITY_PUT_FETCHABLE, null);
		}
	}

	private void trySendFinalMessage(FCPConnectionOutputHandler handler, String listRequestIdentifier) {

		FCPMessage msg;
		synchronized (this) {
			if(succeeded) {
				msg = new PutSuccessfulMessage(identifier, global, generatedURI, startupTime, completionTime);
			} else {
				msg = putFailedMessage;
			}
		}

		if(msg == null) {
			Logger.error(this, "Trying to send null message on "+this, new Exception("error"));
		} else {
			if(persistence == Persistence.CONNECTION && handler == null)
				handler = origHandler.outputHandler;
			if(handler != null)
				handler.queue(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier));
			else
				client.queueClientRequestMessage(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier), 0);
		}
	}

	private void trySendGeneratedURIMessage(FCPConnectionOutputHandler handler, String listRequestIdentifier) {
		FCPMessage msg;
		synchronized(this) {
			msg = new URIGeneratedMessage(generatedURI, identifier, isGlobalQueue());
		}
		if(persistence == Persistence.CONNECTION && handler == null)
			handler = origHandler.outputHandler;
		if(handler != null)
			handler.queue(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier));
		else
			client.queueClientRequestMessage(msg, 0);
	}

	/**
	 * @param metadata Activated by caller.
	 * @param handler
	 * @param listRequestIdentifier
	 */
	private void trySendGeneratedMetadataMessage(Bucket metadata, FCPConnectionOutputHandler handler, String listRequestIdentifier) {
		FCPMessage msg = FCPMessage.withListRequestIdentifier(new GeneratedMetadataMessage(identifier, global, metadata), listRequestIdentifier);
		if(persistence == Persistence.CONNECTION && handler == null)
			handler = origHandler.outputHandler;
		if(handler != null)
			handler.queue(msg);
		else
			client.queueClientRequestMessage(msg, 0);
	}

	/**
	 * @param msg
	 * @param verbosity
	 * @param handler
	 * @param container Either container or context is required for a persistent request.
	 */
	private void trySendProgressMessage(final FCPMessage msg, final int verbosity, FCPConnectionOutputHandler handler) {
	    synchronized(this) {
	        if(persistence != Persistence.CONNECTION)
	            progressMessage = msg;
	    }
		if(persistence == Persistence.CONNECTION && handler == null)
			handler = origHandler.outputHandler;
		if(handler != null)
			handler.queue(msg);
		else
			client.queueClientRequestMessage(msg, verbosity);
	}

	protected abstract FCPMessage persistentTagMessage();

	@Override
	public void sendPendingMessages(FCPConnectionOutputHandler handler, String listRequestIdentifier, boolean includeData, boolean onlyData) {
		FCPMessage msg = FCPMessage.withListRequestIdentifier(persistentTagMessage(), listRequestIdentifier);
		handler.queue(msg);

		boolean generated = false;
		boolean fin = false;
		Bucket meta;
		synchronized (this) {
			generated = generatedURI != null;
			msg = FCPMessage.withListRequestIdentifier(progressMessage, listRequestIdentifier);
			fin = finished;
			meta = generatedMetadata;
		}
		if(generated)
			trySendGeneratedURIMessage(handler, listRequestIdentifier);
		if(meta != null)
			trySendGeneratedMetadataMessage(meta, handler, listRequestIdentifier);
		if(msg != null)
			handler.queue(msg);
		if(fin)
			trySendFinalMessage(handler, listRequestIdentifier);
	}

	protected abstract String getTypeName();

	@Override
	public synchronized double getSuccessFraction() {
		if(progressMessage != null) {
			if(progressMessage instanceof SimpleProgressMessage)
				return ((SimpleProgressMessage)progressMessage).getFraction();
			else return 0;
		} else
			return -1;
	}


	@Override
	public synchronized double getTotalBlocks() {
		if(progressMessage != null) {
			if(progressMessage instanceof SimpleProgressMessage)
				return ((SimpleProgressMessage)progressMessage).getTotalBlocks();
			else return 0;
		} else
			return -1;
	}

	@Override
	public synchronized double getMinBlocks() {
		if(progressMessage != null) {
			if(progressMessage instanceof SimpleProgressMessage)
				return ((SimpleProgressMessage)progressMessage).getMinBlocks();
			else return 0;
		} else
			return -1;
	}

	@Override
	public synchronized double getFailedBlocks() {
		if(progressMessage != null) {
			if(progressMessage instanceof SimpleProgressMessage)
				return ((SimpleProgressMessage)progressMessage).getFailedBlocks();
			else return 0;
		} else
			return -1;
	}

	@Override
	public synchronized double getFatalyFailedBlocks() {
		if(progressMessage != null) {
			if(progressMessage instanceof SimpleProgressMessage)
				return ((SimpleProgressMessage)progressMessage).getFatalyFailedBlocks();
			else return 0;
		} else
			return -1;
	}

	@Override
	public synchronized double getFetchedBlocks() {
		if(progressMessage != null) {
			if(progressMessage instanceof SimpleProgressMessage)
				return ((SimpleProgressMessage)progressMessage).getFetchedBlocks();
			else return 0;
		} else
			return -1;
	}

	@Override
	public synchronized boolean isTotalFinalized() {
		if(!(progressMessage instanceof SimpleProgressMessage)) return false;
		else {
			return ((SimpleProgressMessage)progressMessage).isTotalFinalized();
		}
	}

	@Override
	public synchronized String getFailureReason(boolean longDescription) {
		if(putFailedMessage == null)
			return null;
		String s = putFailedMessage.shortCodeDescription;
		if(longDescription && putFailedMessage.extraDescription != null)
			s += ": "+putFailedMessage.extraDescription;
		return s;
	}

	public PutFailedMessage getFailureMessage() {
		if(putFailedMessage == null)
			return null;
		return putFailedMessage;
	}
	
	public synchronized void setVarsRestart() {
	    finished = false;
	    this.putFailedMessage = null;
	    this.progressMessage = null;
	    started = false;
	}

}
