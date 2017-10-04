/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.fcp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Date;

import freenet.client.ClientMetadata;
import freenet.client.DefaultMIMETypes;
import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.Metadata;
import freenet.client.Metadata.DocumentType;
import freenet.client.MetadataUnresolvedException;
import freenet.client.async.BinaryBlob;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientPutter;
import freenet.clients.fcp.RequestIdentifier.RequestType;
import freenet.crypt.SHA256;
import freenet.keys.FreenetURI;
import freenet.node.NodeClientCore;
import freenet.support.Base64;
import freenet.support.CurrentTimeUTC;
import freenet.support.IllegalBase64Exception;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;
import freenet.support.api.RandomAccessBucket;
import freenet.support.io.Closer;
import freenet.support.io.ResumeFailedException;

public class ClientPut extends ClientPutBase {

    private static final long serialVersionUID = 1L;
    ClientPutter putter;
	private final UploadFrom uploadFrom;
	/** Original filename if from disk, otherwise null. Purely for PersistentPut. */
	private final File origFilename;
	/** If uploadFrom==UPLOAD_FROM_REDIRECT, this is the target of the redirect */
	private final FreenetURI targetURI;
	private RandomAccessBucket data;
	private final ClientMetadata clientMetadata;
	/** We store the size of inserted data before freeing it */
	private long finishedSize;
	/** Filename if the file has one */
	private final String targetFilename;
	/** If true, we are inserting a binary blob: No metadata, no URI is generated. */
	private final boolean binaryBlob;
	private transient boolean compressing;
	private boolean compressed;

        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
	/**
	 * Fproxy
	 * Creates a new persistent insert.
	 * @param uri
	 *            The URI to insert data to
	 * @param identifier
	 *            The identifier of the insert
	 * @param verbosity
	 *            The verbosity bitmask
	 * @param priorityClass
	 *            The priority for this insert
	 * @param persistence
	 *            The persistence type of this insert
	 * @param clientToken
	 *            The client token of this insert
	 * @param getCHKOnly
	 *            Whether only the resulting CHK is requested
	 * @param dontCompress
	 *            Whether the file should not be compressed
	 * @param maxRetries
	 *            The maximum number of retries
	 * @param uploadFromType
	 *            Where the file is uploaded from
	 * @param origFilename
	 *            The original filename
	 * @param contentType
	 *            The content type of the data
	 * @param data
	 *            The data (may be <code>null</code> if
	 *            <code>uploadFromType</code> is UPLOAD_FROM_REDIRECT)
	 * @param redirectTarget
	 *            The URI to redirect to (if <code>uploadFromType</code> is
	 *            UPLOAD_FROM_REDIRECT)
	 * @param handler
	 *            The FCP connection handler
	 * @param global
	 *            Whether this insert appears on the global queue
	 * 
	 * @throws IdentifierCollisionException
	 * @throws NotAllowedException 
	 * @throws MetadataUnresolvedException 
	 * @throws IOException 
	 * @throws InsertException 
	 */
	public ClientPut(PersistentRequestClient globalClient, FreenetURI uri, String identifier, int verbosity, 
			short priorityClass, Persistence persistence, String clientToken,
			boolean getCHKOnly, boolean dontCompress, int maxRetries, UploadFrom uploadFromType, File origFilename,
			String contentType, RandomAccessBucket data, FreenetURI redirectTarget, String targetFilename, boolean earlyEncode, boolean canWriteClientCache, boolean forkOnCacheable, int extraInsertsSingleBlock, int extraInsertsSplitfileHeaderBlock, boolean realTimeFlag, InsertContext.CompatibilityMode compatMode, byte[] overrideSplitfileKey, boolean binaryBlob, NodeClientCore core) throws IdentifierCollisionException, NotAllowedException, MetadataUnresolvedException, IOException {
		super(uri = checkEmptySSK(uri, targetFilename, core.clientContext), identifier, verbosity, null, globalClient, priorityClass, persistence, null, true, getCHKOnly, dontCompress, maxRetries, earlyEncode, canWriteClientCache, forkOnCacheable, false, extraInsertsSingleBlock, extraInsertsSplitfileHeaderBlock, realTimeFlag, null, compatMode, false/*XXX ignoreUSKDatehints*/, core);
		if(uploadFromType == UploadFrom.DISK) {
			if(!core.allowUploadFrom(origFilename))
				throw new NotAllowedException();
			if(!(origFilename.exists() && origFilename.canRead()))
				throw new FileNotFoundException();
		}

		this.binaryBlob = binaryBlob;
		if(binaryBlob) contentType = null;
		this.targetFilename = targetFilename;
		this.uploadFrom = uploadFromType;
		this.origFilename = origFilename;
		// Now go through the fields one at a time
		String mimeType = contentType;
		this.clientToken = clientToken;
		RandomAccessBucket tempData = data;
		ClientMetadata cm = new ClientMetadata(mimeType);
		boolean isMetadata = false;
		if(logMINOR) Logger.minor(this, "data = "+tempData+", uploadFrom = "+uploadFrom);
		if(uploadFrom == UploadFrom.REDIRECT) {
			this.targetURI = redirectTarget;
			Metadata m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, targetURI, cm);
			tempData = m.toBucket(core.clientContext.getBucketFactory(isPersistentForever()));
			isMetadata = true;
		} else
			targetURI = null;

		this.data = tempData;
		this.clientMetadata = cm;

		putter = new ClientPutter(this, data, this.uri, cm,
				ctx, priorityClass,
				isMetadata,
				this.uri.getDocName() == null ? targetFilename : null, binaryBlob, overrideSplitfileKey, -1);
	}
	
	public ClientPut(FCPConnectionHandler handler, ClientPutMessage message, FCPServer server) throws IdentifierCollisionException, MessageInvalidException, IOException {
		super(checkEmptySSK(message.uri, message.targetFilename, server.core.clientContext), message.identifier, message.verbosity,
				handler, message.priorityClass, message.persistence, message.clientToken,
				message.global, message.getCHKOnly, message.dontCompress, message.localRequestOnly, message.maxRetries, message.earlyEncode, message.canWriteClientCache, message.forkOnCacheable, message.compressorDescriptor, message.extraInsertsSingleBlock, message.extraInsertsSplitfileHeaderBlock, message.realTimeFlag, message.compatibilityMode, message.ignoreUSKDatehints, server);
		String salt = null;
		byte[] saltedHash = null;
		binaryBlob = message.binaryBlob;
		
		if(message.uploadFromType == UploadFrom.DISK) {
			if(!handler.server.core.allowUploadFrom(message.origFilename))
				throw new MessageInvalidException(ProtocolErrorMessage.ACCESS_DENIED, "Not allowed to upload from "+message.origFilename, identifier, global);

			if(message.fileHash != null) {
				try {
					salt = handler.connectionIdentifier + '-' + message.identifier + '-';
					saltedHash = Base64.decodeStandard(message.fileHash);
				} catch (IllegalBase64Exception e) {
					try {
						saltedHash = Base64.decode(message.fileHash);
					} catch (IllegalBase64Exception e1) {
						throw new MessageInvalidException(ProtocolErrorMessage.INVALID_FIELD, "Can't base64 decode " + ClientPutBase.FILE_HASH, identifier, global);
					}
				}
			} else if(!handler.allowDDAFrom(message.origFilename, false))
				throw new MessageInvalidException(ProtocolErrorMessage.DIRECT_DISK_ACCESS_DENIED, "Not allowed to upload from "+message.origFilename+". Have you done a testDDA previously ?", identifier, global);		
		}
			
		this.targetFilename = message.targetFilename;
		this.uploadFrom = message.uploadFromType;
		this.origFilename = message.origFilename;
		// Now go through the fields one at a time
		String mimeType = message.contentType;
		if(binaryBlob) {
			if(mimeType != null && !mimeType.equals(BinaryBlob.MIME_TYPE)) {
				throw new MessageInvalidException(ProtocolErrorMessage.INVALID_FIELD, "No MIME type allowed when inserting a binary blob", identifier, global);
			}
		}
		if(mimeType == null && origFilename != null) {
			mimeType = DefaultMIMETypes.guessMIMEType(origFilename.getName(), true);
		}
		if ((mimeType == null) && (targetFilename != null)) {
			mimeType = DefaultMIMETypes.guessMIMEType(targetFilename, true);
		}
		if(mimeType != null && mimeType.equals("")) mimeType = null;
		if(mimeType != null && !DefaultMIMETypes.isPlausibleMIMEType(mimeType)) {
			throw new MessageInvalidException(ProtocolErrorMessage.BAD_MIME_TYPE, "Bad MIME type in Metadata.ContentType", identifier, global);
		}
		
		clientToken = message.clientToken;
		RandomAccessBucket tempData = message.getRandomAccessBucket();
		ClientMetadata cm = new ClientMetadata(mimeType);
		boolean isMetadata = false;
		if(logMINOR) Logger.minor(this, "data = "+tempData+", uploadFrom = "+uploadFrom);
		if(uploadFrom == UploadFrom.REDIRECT) {
			this.targetURI = message.redirectTarget;
			Metadata m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, targetURI, cm);
			try {
	            tempData = m.toBucket(server.core.clientContext.getBucketFactory(isPersistentForever()));
			} catch (MetadataUnresolvedException e) {
				// Impossible
				Logger.error(this, "Impossible: "+e, e);
				this.data = null;
				clientMetadata = cm;
				putter = null;
				// This is *not* an InsertException since we don't register it: it's a protocol error.
				throw new MessageInvalidException(ProtocolErrorMessage.INTERNAL_ERROR, "Impossible: metadata unresolved: "+e, identifier, global);
			}
			isMetadata = true;
		} else
			targetURI = null;
		this.data = tempData;
		this.clientMetadata = cm;
		
		// Check the hash : allow it to be null for backward compatibility and if testDDA is allowed
		if(salt != null) {
			MessageDigest md = SHA256.getMessageDigest();
			byte[] foundHash;
			try {
				md.update(salt.getBytes("UTF-8"));
			} catch (UnsupportedEncodingException e) {
				throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
			}
			InputStream is = null;
			try {
				is = data.getInputStream();
				SHA256.hash(is, md);
			} catch (IOException e) {
				SHA256.returnMessageDigest(md);
				Logger.error(this, "Got IOE: " + e.getMessage(), e);
				throw new MessageInvalidException(ProtocolErrorMessage.COULD_NOT_READ_FILE,
						"Unable to access file: " + e, identifier, global);
			} finally {
				Closer.close(is);
			}
			foundHash = md.digest();
			SHA256.returnMessageDigest(md);

			if(logMINOR) Logger.minor(this, "FileHash result : we found " + Base64.encode(foundHash) + " and were given " + Base64.encode(saltedHash) + '.');

			if(!Arrays.equals(saltedHash, foundHash))
				throw new MessageInvalidException(ProtocolErrorMessage.DIRECT_DISK_ACCESS_DENIED, "The hash doesn't match! (salt used : \""+salt+"\")", identifier, global);
		}
		
		if(logMINOR) Logger.minor(this, "data = "+data+", uploadFrom = "+uploadFrom);
		putter = new ClientPutter(this, data, this.uri, cm, 
				ctx, priorityClass, 
				isMetadata,
				this.uri.getDocName() == null ? targetFilename : null, binaryBlob, message.overrideSplitfileCryptoKey, message.metadataThreshold);
	}
	
	protected ClientPut() {
	    // For serialization.
	    uploadFrom = null;
	    origFilename = null;
	    targetURI = null;
	    clientMetadata = null;
	    finishedSize = 0;
	    targetFilename = null;
	    binaryBlob = false;
	}
	
	@Override
	void register(boolean noTags) throws IdentifierCollisionException {
		if(persistence != Persistence.CONNECTION)
			client.register(this);
		if(persistence != Persistence.CONNECTION && !noTags) {
			FCPMessage msg = persistentTagMessage();
			client.queueClientRequestMessage(msg, 0);
		}
	}
	
	@Override
	public void start(ClientContext context) {
		if(logMINOR)
			Logger.minor(this, "Starting "+this+" : "+identifier);
		synchronized(this) {
			if(finished) return;
		}
		try {
			putter.start(false, context);
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
		} catch (InsertException e) {
			synchronized(this) {
				started = true;
			}
			onFailure(e, null);
		} catch (Throwable t) {
			synchronized(this) {
				started = true;
			}
			onFailure(new InsertException(InsertExceptionMode.INTERNAL_ERROR, t, null), null);
		}
	}

	@Override
	protected void freeData() {
		Bucket d;
		synchronized(this) {
			d = data;
			data = null;
			if(d == null) return;
			finishedSize = d.size();
		}
		d.free();
	}
	
	@Override
	protected freenet.client.async.ClientRequester getClientRequest() {
		return putter;
	}

	@Override
	protected FCPMessage persistentTagMessage() {
		if (putter == null)
			Logger.error(this, "putter == null", new Exception("error"));
		// FIXME end
		return new PersistentPut(identifier, publicURI, uri, verbosity, priorityClass, uploadFrom, targetURI, 
				persistence, origFilename, clientMetadata.getMIMEType(), client.isGlobalQueue,
				getDataSize(), clientToken, started, ctx.maxInsertRetries, targetFilename, binaryBlob, this.ctx.getCompatibilityMode(), this.ctx.dontCompress, this.ctx.compressorDescriptor, isRealTime(), putter != null ? putter.getSplitfileCryptoKey() : null);
	}

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
	protected String getTypeName() {
		return "PUT";
	}

	@Override
	public boolean hasSucceeded() {
		return succeeded;
	}

	public FreenetURI getFinalURI() {
		return generatedURI;
	}

	public boolean isDirect() {
		return uploadFrom == UploadFrom.DIRECT;
	}

	public File getOrigFilename() {
		if(uploadFrom != UploadFrom.DISK)
			return null;
		return origFilename;
	}

	public long getDataSize() {
		if(data == null)
			return finishedSize;
		else {
			return data.size();
		}
	}

	public String getMIMEType() {
		return clientMetadata.getMIMEType();
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
		return putter.canRestart();
	}

	@Override
	public boolean restart(ClientContext context, final boolean disableFilterData) {
		if(!canRestart()) return false;
		setVarsRestart();
		try {
			if(client != null) {
				RequestStatusCache cache = client.getRequestStatusCache();
				if(cache != null) {
					cache.updateStarted(identifier, false);
				}
			}
			if(putter.restart(context)) {
				synchronized(this) {
					generatedURI = null;
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
		} catch (InsertException e) {
			onFailure(e, null);
			return false;
		}
	}
	
	@Override
	public void setVarsRestart() {
		super.setVarsRestart();
		if(client != null) {
			RequestStatusCache cache = client.getRequestStatusCache();
			if(cache != null) {
				cache.updateCompressionStatus(identifier, isCompressing());
			}
		}
	}
	
	@Override
	public void requestWasRemoved(ClientContext context) {
		if(persistence == Persistence.FOREVER) {
			putter = null;
		}
		super.requestWasRemoved(context);
	}
	
	public enum COMPRESS_STATE {
		/** Waiting for a slot on the compression scheduler */
		WAITING,
		/** Compressing the data */
		COMPRESSING,
		/** Inserting the data */
		WORKING
	}
	
	/** Probably not meaningful for ClientPutDir's */
	public COMPRESS_STATE isCompressing() {
		if(ctx.dontCompress) return COMPRESS_STATE.WORKING;
		synchronized(this) {
			if(!compressed) return COMPRESS_STATE.WAITING; // An insert starts at compressing
			// The progress message persists... so we need to know whether we have
			// started compressing *SINCE RESTART*.
			if(compressing) return COMPRESS_STATE.COMPRESSING;
			return COMPRESS_STATE.WORKING;
		}
	}

	@Override
	protected void onStartCompressing() {
		synchronized(this) {
		    if(compressed) return;
			compressing = true;
		}
		if(client != null) {
			RequestStatusCache cache = client.getRequestStatusCache();
			if(cache != null) {
				cache.updateCompressionStatus(identifier, COMPRESS_STATE.COMPRESSING);
			}
		}
	}

	@Override
	protected void onStopCompressing() {
		synchronized(this) {
		    if(compressed) return; // Race condition possible
			compressing = false;
			compressed = true;
		}
		if(client != null) {
			RequestStatusCache cache = client.getRequestStatusCache();
			if(cache != null) {
				cache.updateCompressionStatus(identifier, COMPRESS_STATE.WORKING);
			}
		}
	}

	@Override
	RequestStatus getStatus() {
		FreenetURI finalURI = getFinalURI();
		InsertExceptionMode failureCode = null;
		String failureReasonShort = null;
		String failureReasonLong = null;
		if(putFailedMessage != null) {
			failureCode = putFailedMessage.code;
			failureReasonShort = putFailedMessage.getShortFailedMessage();
			failureReasonShort = putFailedMessage.getLongFailedMessage();
		}
		String mimeType = null;
		if(persistence == Persistence.FOREVER) {
			mimeType = clientMetadata.getMIMEType();
		}
		File fnam = getOrigFilename();
		if(fnam != null) fnam = new File(fnam.getPath());
		
		int total=0, min=0, fetched=0, fatal=0, failed=0;
		// See ClientRequester.getLatestSuccess() for why this defaults to current time.
		Date latestSuccess = CurrentTimeUTC.get();
		Date latestFailure = null;
		boolean totalFinalized = false;
		
		if(progressMessage != null) {
			if(progressMessage instanceof SimpleProgressMessage) {
				SimpleProgressMessage msg = (SimpleProgressMessage)progressMessage;
				total = (int) msg.getTotalBlocks();
				min = (int) msg.getMinBlocks();
				fetched = (int) msg.getFetchedBlocks();
				latestSuccess = msg.getLatestSuccess();
				fatal = (int) msg.getFatalyFailedBlocks();
				failed = (int) msg.getFailedBlocks();
				latestFailure = msg.getLatestFailure();
				totalFinalized = msg.isTotalFinalized();
			}
		}
		
        return new UploadFileRequestStatus(
            identifier, persistence, started, finished, succeeded, total, min, fetched,
            latestSuccess, fatal, failed, latestFailure, totalFinalized, priorityClass, finalURI,
            uri, failureCode, failureReasonShort, failureReasonLong, getDataSize(), mimeType,
            fnam, isCompressing());
	}
	
	@Override
	public void innerResume(ClientContext context) throws ResumeFailedException {
	    if(data != null)
	        data.onResume(context);
	}

    @Override
    RequestType getType() {
        return RequestType.PUT;
    }

    @Override
    public boolean fullyResumed() {
        // FIXME we might need this in future.
        return false;
    }

}
