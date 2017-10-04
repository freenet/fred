/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.fcp;

import java.io.File;
import java.io.FileNotFoundException;
import java.net.MalformedURLException;
import java.util.Date;
import java.util.HashMap;

import freenet.client.DefaultMIMETypes;
import freenet.client.FetchException;
import freenet.client.FetchResult;
import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.async.BaseClientPutter;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientGetter;
import freenet.client.async.ClientRequester;
import freenet.client.async.ContainerInserter;
import freenet.client.async.DefaultManifestPutter;
import freenet.client.async.ManifestPutter;
import freenet.client.async.TooManyFilesInsertException;
import freenet.clients.fcp.RequestIdentifier.RequestType;
import freenet.keys.FreenetURI;
import freenet.node.NodeClientCore;
import freenet.support.CurrentTimeUTC;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.ManifestElement;
import freenet.support.io.FileBucket;
import freenet.support.io.ResumeFailedException;

public class ClientPutDir extends ClientPutBase {

    private static final long serialVersionUID = 1L;
    private HashMap<String, Object> manifestElements;
	private ManifestPutter putter;
	private final String defaultName;
	private final long totalSize;
	private final int numberOfFiles;
	private final boolean wasDiskPut;
	
	private static volatile boolean logMINOR;
	private final byte[] overrideSplitfileCryptoKey;
	
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	public ClientPutDir(FCPConnectionHandler handler, ClientPutDirMessage message, 
			HashMap<String, Object> manifestElements, boolean wasDiskPut, FCPServer server) throws IdentifierCollisionException, MalformedURLException, TooManyFilesInsertException {
		super(checkEmptySSK(message.uri, message.targetFilename != null ? message.targetFilename : "site", server.core.clientContext), message.identifier, message.verbosity,
				handler, message.priorityClass, message.persistence, message.clientToken,
				message.global, message.getCHKOnly, message.dontCompress, message.localRequestOnly, message.maxRetries, message.earlyEncode, message.canWriteClientCache, message.forkOnCacheable, message.compressorDescriptor, message.extraInsertsSingleBlock, message.extraInsertsSplitfileHeaderBlock, message.realTimeFlag, message.compatibilityMode, message.ignoreUSKDatehints, server);
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		this.wasDiskPut = wasDiskPut;
		this.overrideSplitfileCryptoKey = message.overrideSplitfileCryptoKey;
		
		// objectOnNew is called once, objectOnUpdate is never called, yet manifestElements get blanked anyway!
		
		this.manifestElements = new HashMap<String,Object>();
		this.manifestElements.putAll(manifestElements);
		
//		this.manifestElements = manifestElements;
		
//		this.manifestElements = new HashMap<String, Object>();
//		this.manifestElements.putAll(manifestElements);
		this.defaultName = message.defaultName;
		makePutter(server.core.clientContext);
		if(putter != null) {
			numberOfFiles = putter.countFiles();
			totalSize = putter.totalSize();
		} else {
			numberOfFiles = -1;
			totalSize = -1;
		}
		if(logMINOR) Logger.minor(this, "Putting dir "+identifier+" : "+priorityClass);
	}

	/**
	 * Fproxy
	*	Puts a disk dir
	 * @throws TooManyFilesInsertException 
	 * @throws InsertException 
	*/
	public ClientPutDir(PersistentRequestClient client, FreenetURI uri, String identifier, int verbosity, short priorityClass, Persistence persistence, String clientToken, boolean getCHKOnly, boolean dontCompress, int maxRetries, File dir, String defaultName, boolean allowUnreadableFiles, boolean includeHiddenFiles, boolean global, boolean earlyEncode, boolean canWriteClientCache, boolean forkOnCacheable, int extraInsertsSingleBlock, int extraInsertsSplitfileHeaderBlock, boolean realTimeFlag, byte[] overrideSplitfileCryptoKey, NodeClientCore core) throws FileNotFoundException, IdentifierCollisionException, MalformedURLException, TooManyFilesInsertException {
		super(checkEmptySSK(uri, "site", core.clientContext), identifier, verbosity , null, client, priorityClass, persistence, clientToken, global, getCHKOnly, dontCompress, maxRetries, earlyEncode, canWriteClientCache, forkOnCacheable, false, extraInsertsSingleBlock, extraInsertsSplitfileHeaderBlock, realTimeFlag, null, InsertContext.CompatibilityMode.COMPAT_DEFAULT, false/*XXX ignoreUSKDatehints*/, core);
		wasDiskPut = true;
		this.overrideSplitfileCryptoKey = overrideSplitfileCryptoKey;
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		this.manifestElements = makeDiskDirManifest(dir, "", allowUnreadableFiles, includeHiddenFiles);
		this.defaultName = defaultName;
		makePutter(core.clientContext);
		if(putter != null) {
			numberOfFiles = putter.countFiles();
			totalSize = putter.totalSize();
		} else {
			numberOfFiles = -1;
			totalSize = -1;
		}
		if(logMINOR) Logger.minor(this, "Putting dir "+identifier+" : "+priorityClass);
	}

	public ClientPutDir(PersistentRequestClient client, FreenetURI uri, String identifier, int verbosity, short priorityClass, Persistence persistence, String clientToken, boolean getCHKOnly, boolean dontCompress, int maxRetries, HashMap<String, Object> elements, String defaultName, boolean global, boolean earlyEncode, boolean canWriteClientCache, boolean forkOnCacheable, int extraInsertsSingleBlock, int extraInsertsSplitfileHeaderBlock, boolean realTimeFlag, byte[] overrideSplitfileCryptoKey, NodeClientCore core) throws IdentifierCollisionException, MalformedURLException, TooManyFilesInsertException {
		super(checkEmptySSK(uri, "site", core.clientContext), identifier, verbosity , null, client, priorityClass, persistence, clientToken, global, getCHKOnly, dontCompress, maxRetries, earlyEncode, canWriteClientCache, forkOnCacheable, false, extraInsertsSingleBlock, extraInsertsSplitfileHeaderBlock, realTimeFlag, null, InsertContext.CompatibilityMode.COMPAT_DEFAULT, false/*XXX ignoreUSKDatehints*/, core);
		wasDiskPut = false;
		this.overrideSplitfileCryptoKey = overrideSplitfileCryptoKey;
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		this.manifestElements = elements;
		this.defaultName = defaultName;
		makePutter(core.clientContext);
		if(putter != null) {
			numberOfFiles = putter.countFiles();
			totalSize = putter.totalSize();
		} else {
			numberOfFiles = -1;
			totalSize = -1;
		}
		if(logMINOR) Logger.minor(this, "Putting data from custom buckets "+identifier+" : "+priorityClass);
	}
	
	protected ClientPutDir() {
	    // For serialization.
	    defaultName = null;
	    totalSize = 0;
	    numberOfFiles = 0;
	    wasDiskPut = false;
	    overrideSplitfileCryptoKey = null;
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
	
	private HashMap<String, Object> makeDiskDirManifest(File dir, String prefix, boolean allowUnreadableFiles, boolean includeHiddenFiles) throws FileNotFoundException {

		HashMap<String, Object> map = new HashMap<String, Object>();
		File[] files = dir.listFiles();
		
		if(files == null)
			throw new IllegalArgumentException("No such directory");

		for (File f : files) {
			
    		if(f.isHidden() && !includeHiddenFiles) continue;

			if (f.exists() && f.canRead()) {
				if(f.isFile()) {
					FileBucket bucket = new FileBucket(f, true, false, false, false);
					if(logMINOR)
						Logger.minor(this, "Add file : " + f.getAbsolutePath());
					
					map.put(f.getName(), new ManifestElement(f.getName(), prefix + f.getName(), bucket, DefaultMIMETypes.guessMIMEType(f.getName(), true), f.length()));
				} else if(f.isDirectory()) {
					if(logMINOR)
						Logger.minor(this, "Add dir : " + f.getAbsolutePath());
					
					map.put(f.getName(), makeDiskDirManifest(f, prefix + f.getName() + "/", allowUnreadableFiles, includeHiddenFiles));
				} else {
					if(!allowUnreadableFiles)
						throw new FileNotFoundException("Not a file and not a directory : " + f);
				}
			} else if (!allowUnreadableFiles)
				throw new FileNotFoundException("The file does not exist or is unreadable : " + f);
			
		}

		return map;
	}
	
	private void makePutter(ClientContext context) throws TooManyFilesInsertException {
	    putter = new DefaultManifestPutter(this,
	            manifestElements, priorityClass, uri, defaultName, ctx,
	            overrideSplitfileCryptoKey, context);
	}

	@Override
	public void start(ClientContext context) {
		if(finished) return;
		if(started) return;
		try {
			if(putter != null)
				putter.start(context);

			started = true;
			if(client != null) {
				RequestStatusCache cache = client.getRequestStatusCache();
				if(cache != null) {
					cache.updateStarted(identifier, true);
				}
			}
			if(logMINOR) Logger.minor(this, "Started "+putter+" for "+this+" persistence="+persistence);
			if(persistence != Persistence.CONNECTION && !finished) {
				FCPMessage msg = persistentTagMessage();
				client.queueClientRequestMessage(msg, 0);
			}
		} catch (InsertException e) {
			started = true;
			onFailure(e, null);
		}
	}
	
	@Override
	public void onLostConnection(ClientContext context) {
		if(persistence == Persistence.CONNECTION)
			cancel(context);
		// otherwise ignore
	}
	
	@Override
	protected void freeData() {
		if(logMINOR) Logger.minor(this, "freeData() on "+this+" persistence type = "+persistence);
		synchronized(this) {
			if(manifestElements == null) {
				if(logMINOR)
					Logger.minor(this, "manifestElements = "+manifestElements, new Exception("error"));
				return;
			}
		}
		if(logMINOR) Logger.minor(this, "freeData() more on "+this+" persistence type = "+persistence);
		// We have to commit everything, so activating everything here doesn't cost us much memory...?
		freeData(manifestElements);
		manifestElements = null;
	}
	
	@SuppressWarnings("unchecked")
	private void freeData(HashMap<String, Object> manifestElements) {
		if(logMINOR) Logger.minor(this, "freeData() inner on "+this+" persistence type = "+persistence+" size = "+manifestElements.size());
		for(Object o: manifestElements.values()) {
			if(o instanceof HashMap) {
				freeData((HashMap<String, Object>) o);
			} else {
				ManifestElement e = (ManifestElement) o;
				if(logMINOR) Logger.minor(this, "Freeing "+e);
				e.freeData();
			}
		}
	}

	@Override
	protected ClientRequester getClientRequest() {
		return putter;
	}

	@Override
	protected FCPMessage persistentTagMessage() {
		// FIXME: remove debug code
		if (lowLevelClient == null)
			Logger.error(this, "lowLevelClient == null", new Exception("error"));
		if (putter == null)
			Logger.error(this, "putter == null", new Exception("error"));
		// FIXME end
		return new PersistentPutDir(identifier, publicURI, uri, verbosity, priorityClass,
				persistence, global, defaultName, manifestElements, clientToken, started, ctx.maxInsertRetries, ctx.dontCompress, ctx.compressorDescriptor, wasDiskPut, isRealTime(), putter != null ? putter.getSplitfileCryptoKey() : null, this.ctx.getCompatibilityMode());
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
		return "PUTDIR";
	}

	@Override
	public boolean hasSucceeded() {
		return succeeded;
	}

	public FreenetURI getFinalURI() {
		return generatedURI;
	}

	public int getNumberOfFiles() {
		return numberOfFiles;
	}

	public long getTotalDataSize() {
		return totalSize;
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
		return true;
	}

	@Override
	public boolean restart(ClientContext context, final boolean disableFilterData) {
		if(!canRestart()) return false;
		setVarsRestart();
		if(client != null) {
			RequestStatusCache cache = client.getRequestStatusCache();
			if(cache != null) {
				cache.updateStarted(identifier, false);
			}
		}
		try {
			makePutter(context);
		} catch (TooManyFilesInsertException e) {
			this.onFailure(new InsertException(e), null);
		}
		start(context);
		return true;
	}

	public void onFailure() {}

	public void onSuccess() {}

	@Override
	public void onSuccess(BaseClientPutter state) {
		super.onSuccess(state);
	}
	
	@Override
	public void onFailure(InsertException e, BaseClientPutter state) {
		super.onFailure(e, state);
	}

	@Override
	public void requestWasRemoved(ClientContext context) {
		if(persistence == Persistence.FOREVER) {
			putter = null;
		}
		super.requestWasRemoved(context);
	}

	@Override
	protected void onStartCompressing() {
		// Ignore
	}

	@Override
	protected void onStopCompressing() {
		// Ignore
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
		
		return new UploadDirRequestStatus(
		    identifier, persistence, started, finished, succeeded, total, min, fetched,
		    latestSuccess, fatal, failed, latestFailure, totalFinalized, priorityClass, finalURI,
		    uri, failureCode, failureReasonShort, failureReasonLong, totalSize, numberOfFiles);
	}
	
	@Override
	public void innerResume(ClientContext context) throws ResumeFailedException {
	    ContainerInserter.resumeMetadata(manifestElements, context);
	}

    @Override
    RequestType getType() {
        return RequestType.PUTDIR;
    }

    @Override
    public boolean fullyResumed() {
        return false;
    }

}
