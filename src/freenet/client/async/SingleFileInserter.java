package freenet.client.async;

import java.io.IOException;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.util.HashMap;

import freenet.client.ClientMetadata;
import freenet.client.InsertBlock;
import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.Metadata;
import freenet.client.MetadataUnresolvedException;
import freenet.client.ArchiveManager.ARCHIVE_TYPE;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.client.Metadata.DocumentType;
import freenet.client.events.FinishedCompressionEvent;
import freenet.client.events.ExpectedHashesEvent;
import freenet.client.events.StartedCompressionEvent;
import freenet.crypt.HashResult;
import freenet.crypt.HashType;
import freenet.crypt.MultiHashOutputStream;
import freenet.keys.BaseClientKey;
import freenet.keys.CHKBlock;
import freenet.keys.FreenetURI;
import freenet.keys.SSKBlock;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;
import freenet.support.api.LockableRandomAccessBuffer;
import freenet.support.api.RandomAccessBucket;
import freenet.support.compress.Compressor.COMPRESSOR_TYPE;
import freenet.support.io.BucketTools;
import freenet.support.io.NotPersistentBucket;
import freenet.support.io.NullOutputStream;
import freenet.support.io.ResumeFailedException;

/**
 * Attempt to insert a file. May include metadata.
 * 
 * This stage:
 * Attempt to compress the file. Off-thread if it will take a while.
 * Then hand it off to some combination of SingleBlockInserters and SplitFileInserters, possibly 
 * under the supervision of its own handler class SplitHandler.
 * 
 * WARNING: Changing non-transient members on classes that are Serializable can result in 
 * losing uploads.
 */
class SingleFileInserter implements ClientPutState, Serializable {

    private static final long serialVersionUID = 1L;
    private static volatile boolean logMINOR;
	private static volatile boolean logDEBUG;
	
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
				logDEBUG = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
	final BaseClientPutter parent;
	InsertBlock block;
	final InsertContext ctx;
	final boolean metadata;
	final PutCompletionCallback cb;
	final ARCHIVE_TYPE archiveType;
	/** If true, we are not the top level request, and should not
	 * update our parent to point to us as current put-stage. */
	private final boolean reportMetadataOnly;
	public final Object token;
	private final boolean freeData; // this is being set, but never read ???
	private final String targetFilename;
	private final boolean persistent;
	private boolean started;
	private boolean cancelled;
	private final boolean forSplitfile;
	private final long origDataLength;
	private final long origCompressedDataLength;
	private HashResult[] origHashes;
	/** If true, use random crypto keys for CHKs. */
	private final byte[] forceCryptoKey;
	private final byte cryptoAlgorithm;
	private final boolean realTimeFlag;
	/** When positive, means we will return metadata rather than a URI, once the
	 * metadata is under this length. If it is too short it is still possible to
	 * return a URI, but we won't return both. */
	private final long metadataThreshold;
	
	// A persistent hashCode is helpful in debugging, and also means we can put
	// these objects into sets etc when we need to.
	
	private final int hashCode;
	
	@Override
	public int hashCode() {
		return hashCode;
	}

	/**
	 * @param parent
	 * @param cb
	 * @param block
	 * @param metadata
	 * @param ctx
	 * @param getCHKOnly
	 * @param reportMetadataOnly If true, don't insert the metadata, just report it.
	 * @param insertAsArchiveManifest If true, insert the metadata as an archive manifest.
	 * @param freeData If true, free the data when possible.
	 * @param targetFilename 
	 * @param earlyEncode If true, try to get a URI as quickly as possible.
	 * @param metadataThreshold 
	 * @throws InsertException
	 */
	SingleFileInserter(BaseClientPutter parent, PutCompletionCallback cb, InsertBlock block, 
			boolean metadata, InsertContext ctx, boolean realTimeFlag,
			boolean reportMetadataOnly, Object token, ARCHIVE_TYPE archiveType,
			boolean freeData, String targetFilename, boolean forSplitfile, boolean persistent, long origDataLength, long origCompressedDataLength, HashResult[] origHashes, byte cryptoAlgorithm, byte[] forceCryptoKey, long metadataThreshold) {
		hashCode = super.hashCode();
		this.reportMetadataOnly = reportMetadataOnly;
		this.token = token;
		this.parent = parent;
		this.block = block;
		this.ctx = ctx;
		this.realTimeFlag = realTimeFlag;
		this.metadata = metadata;
		this.cb = cb;
		this.archiveType = archiveType;
		this.freeData = freeData;
		this.targetFilename = targetFilename;
		this.persistent = persistent;
		this.forSplitfile = forSplitfile;
		this.origCompressedDataLength = origCompressedDataLength;
		this.origDataLength = origDataLength;
		this.origHashes = origHashes;
		this.forceCryptoKey = forceCryptoKey;
		this.cryptoAlgorithm = cryptoAlgorithm;
		this.metadataThreshold = metadataThreshold;
		if(logMINOR) Logger.minor(this, "Created "+this+" persistent="+persistent+" freeData="+freeData);
	}
	
	public void start(ClientContext context) throws InsertException {
		tryCompress(context);
	}

	void onCompressed(CompressionOutput output, ClientContext context) {
	    synchronized(this) {
	        if(started) {
	            Logger.error(this, "Already started, not starting again", new Exception("error"));
	            return;
	        }
	        if(cancelled) {
	            Logger.error(this, "Already cancelled, not starting");
	            return;
	        }
	    }
		try {
			onCompressedInner(output, context);
		} catch (InsertException e) {
			cb.onFailure(e, SingleFileInserter.this, context);
        } catch (Throwable t) {
            Logger.error(this, "Caught in OffThreadCompressor: "+t, t);
            System.err.println("Caught in OffThreadCompressor: "+t);
            t.printStackTrace();
            // Try to fail gracefully
			cb.onFailure(new InsertException(InsertExceptionMode.INTERNAL_ERROR, t, null), SingleFileInserter.this, context);
		}
	}
	
	void onCompressedInner(CompressionOutput output, ClientContext context) throws InsertException {
		HashResult[] hashes = output.hashes;
		long origSize = block.getData().size();
		byte[] hashThisLayerOnly = null;
		if(hashes != null && metadata) {
			hashThisLayerOnly = HashResult.get(hashes, HashType.SHA256);
			hashes = null; // Inherit origHashes
		}
		if(hashes != null) {
			if(logDEBUG) {
				Logger.debug(this, "Computed hashes for "+this+" for "+block.desiredURI+" size "+origSize);
				for(HashResult res : hashes) {
					Logger.debug(this, res.type.name()+" : "+res.hashAsHex());
				}
			}
			HashResult[] clientHashes = hashes;
			if(persistent) clientHashes = HashResult.copy(hashes);
			ctx.eventProducer.produceEvent(new ExpectedHashesEvent(clientHashes), context);
			
			// So it is passed on.
			origHashes = hashes;
		} else {
			hashes = origHashes; // Inherit so it goes all the way to the top.
		}
		RandomAccessBucket bestCompressedData = output.data;
		long bestCompressedDataSize = bestCompressedData.size();
		RandomAccessBucket data = bestCompressedData;
		COMPRESSOR_TYPE bestCodec = output.bestCodec;
		
		boolean shouldFreeData = freeData;
		if(bestCodec != null) {
			if(logMINOR) Logger.minor(this, "The best compression algorithm is "+bestCodec+ " we have gained"+ (100-(bestCompressedDataSize*100/origSize)) +"% ! ("+origSize+'/'+bestCompressedDataSize+')');
			shouldFreeData = true; // must be freed regardless of whether the original data was to be freed
			if(freeData) {
				block.getData().free();
			}
			block.nullData();
		} else {
			data = block.getData();
			bestCompressedDataSize = origSize;
		}

		int blockSize;
		int oneBlockCompressedSize;
		
		boolean isCHK = false;
		String type = block.desiredURI.getKeyType();
		boolean isUSK = false;
		if(type.equals("SSK") || type.equals("KSK") || (isUSK = type.equals("USK"))) {
			blockSize = SSKBlock.DATA_LENGTH;
			oneBlockCompressedSize = SSKBlock.MAX_COMPRESSED_DATA_LENGTH;
		} else if(type.equals("CHK")) {
			blockSize = CHKBlock.DATA_LENGTH;
			oneBlockCompressedSize = CHKBlock.MAX_COMPRESSED_DATA_LENGTH;
			isCHK = true;
		} else {
			throw new InsertException(InsertExceptionMode.INVALID_URI, "Unknown key type: "+type, null);
		}
		
		// Compressed data ; now insert it
		// We do NOT need to switch threads here: the actual compression is done by InsertCompressor on the RealCompressor thread,
		// which then switches either to the database thread or to a new executable to run this method.
		
		if(parent == cb) {
			short codecID = bestCodec == null ? -1 : bestCodec.metadataID;
			ctx.eventProducer.produceEvent(new FinishedCompressionEvent(codecID, origSize, bestCompressedDataSize), context);
			if(logMINOR) Logger.minor(this, "Compressed "+origSize+" to "+data.size()+" on "+this+" data = "+data);
		}
		
		// Insert it...
		short codecNumber = bestCodec == null ? -1 : bestCodec.metadataID;
		long compressedDataSize = data.size();
		boolean fitsInOneBlockAsIs = bestCodec == null ? compressedDataSize <= blockSize : compressedDataSize <= oneBlockCompressedSize;
		boolean fitsInOneCHK = bestCodec == null ? compressedDataSize <= CHKBlock.DATA_LENGTH : compressedDataSize <= CHKBlock.MAX_COMPRESSED_DATA_LENGTH;

		if((fitsInOneBlockAsIs || fitsInOneCHK) && origSize > Integer.MAX_VALUE)
			throw new InsertException(InsertExceptionMode.INTERNAL_ERROR, "2GB+ should not encode to one block!", null);

		boolean noMetadata = ((block.clientMetadata == null) || block.clientMetadata.isTrivial()) && targetFilename == null;
		if((noMetadata || metadata) && archiveType == null) {
			if(fitsInOneBlockAsIs) {
				if(persistent && (data instanceof NotPersistentBucket))
					data = fixNotPersistent(data, context);
				// Just insert it
				ClientPutState bi =
					createInserter(parent, data, codecNumber, ctx, cb, metadata, (int)origSize, -1, true, context, shouldFreeData, forSplitfile);
				if(logMINOR)
					Logger.minor(this, "Inserting without metadata: "+bi+" for "+this);
				cb.onTransition(this, bi, context);
				if(ctx.earlyEncode && bi instanceof SingleBlockInserter && isCHK)
					((SingleBlockInserter)bi).getBlock(context);
				bi.schedule(context);
				if(!isUSK)
					cb.onBlockSetFinished(this, context);
				synchronized(this) {
				    started = true;
				}
				if(persistent) {
					block.nullData();
					block = null;
				}
				return;
			}
		}
		if (fitsInOneCHK) {
			// Insert single block, then insert pointer to it
			if(persistent && (data instanceof NotPersistentBucket)) {
				data = fixNotPersistent(data, context);
			}
			if(reportMetadataOnly) {
				SingleBlockInserter dataPutter = new SingleBlockInserter(parent, data, codecNumber, FreenetURI.EMPTY_CHK_URI, ctx, realTimeFlag, cb, metadata, (int)origSize, -1, true, true, token, context, persistent, shouldFreeData, forSplitfile ? ctx.extraInsertsSplitfileHeaderBlock : ctx.extraInsertsSingleBlock, cryptoAlgorithm, forceCryptoKey);
				if(logMINOR)
					Logger.minor(this, "Inserting with metadata: "+dataPutter+" for "+this);
				Metadata meta = makeMetadata(archiveType, dataPutter.getURI(context), hashes);
				cb.onMetadata(meta, this, context);
				cb.onTransition(this, dataPutter, context);
				dataPutter.schedule(context);
				if(!isUSK)
					cb.onBlockSetFinished(this, context);
				synchronized(this) {
					// Don't delete them because they are being passed on.
					origHashes = null;
				}
			} else {
				MultiPutCompletionCallback mcb = 
					new MultiPutCompletionCallback(cb, parent, token, persistent, false, ctx.earlyEncode);
				SingleBlockInserter dataPutter = new SingleBlockInserter(parent, data, codecNumber, FreenetURI.EMPTY_CHK_URI, ctx, realTimeFlag, mcb, metadata, (int)origSize, -1, true, false, token, context, persistent, shouldFreeData, forSplitfile ? ctx.extraInsertsSplitfileHeaderBlock : ctx.extraInsertsSingleBlock, cryptoAlgorithm, forceCryptoKey);
				if(logMINOR)
					Logger.minor(this, "Inserting data: "+dataPutter+" for "+this);
				Metadata meta = makeMetadata(archiveType, dataPutter.getURI(context), hashes);
				RandomAccessBucket metadataBucket;
				try {
					metadataBucket = meta.toBucket(context.getBucketFactory(persistent));
				} catch (IOException e) {
					Logger.error(this, "Caught "+e, e);
					throw new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null);
				} catch (MetadataUnresolvedException e) {
					// Impossible, we're not inserting a manifest.
					Logger.error(this, "Caught "+e, e);
					throw new InsertException(InsertExceptionMode.INTERNAL_ERROR, "Got MetadataUnresolvedException in SingleFileInserter: "+e.toString(), null);
				}
				ClientPutState metaPutter = createInserter(parent, metadataBucket, (short) -1, ctx, mcb, true, (int)origSize, -1, true, context, true, false);
				if(logMINOR)
					Logger.minor(this, "Inserting metadata: "+metaPutter+" for "+this);
				mcb.addURIGenerator(metaPutter);
				mcb.add(dataPutter);
				cb.onTransition(this, mcb, context);
				Logger.minor(this, ""+mcb+" : data "+dataPutter+" meta "+metaPutter);
				mcb.arm(context);
				dataPutter.schedule(context);
				if(ctx.earlyEncode && metaPutter instanceof SingleBlockInserter)
					((SingleBlockInserter)metaPutter).getBlock(context);
				metaPutter.schedule(context);
				if(!isUSK)
					cb.onBlockSetFinished(this, context);
				// Deleting origHashes is fine, we are done with them.
			}
			synchronized(this) {
			    started = true;
			}
			if(persistent) {
				block.nullData();
				block = null;
			}
			return;
		}
		// Otherwise the file is too big to fit into one block
		// We therefore must make a splitfile
		// Job of SplitHandler: when the splitinserter has the metadata,
		// insert it. Then when the splitinserter has finished, and the
		// metadata insert has finished too, tell the master callback.
		LockableRandomAccessBuffer dataRAF;
        try {
            dataRAF = data.toRandomAccessBuffer();
        } catch (IOException e) {
            throw new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null);
        }
		if(reportMetadataOnly) {
			SplitFileInserter sfi = new SplitFileInserter(persistent, parent, cb, 
			        dataRAF, shouldFreeData, ctx, context, origSize, bestCodec, 
			        block.clientMetadata, metadata, archiveType, cryptoAlgorithm, forceCryptoKey,
			        hashThisLayerOnly, hashes, ctx.dontCompress, parent.getMinSuccessFetchBlocks(),
			        parent.getTotalBlocks(), origDataLength, origCompressedDataLength, 
			        realTimeFlag, token);
			if(logMINOR)
				Logger.minor(this, "Inserting as splitfile: "+sfi+" for "+this);
			cb.onTransition(this, sfi, context);
			sfi.schedule(context);
			block.nullData();
			block.nullMetadata();
			synchronized(this) {
				// Don't delete them because they are being passed on.
				origHashes = null;
			}
		} else {
			CompatibilityMode cmode = ctx.getCompatibilityMode();
			boolean allowSizes = (cmode == CompatibilityMode.COMPAT_CURRENT || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal());
			if(metadata) allowSizes = false;
			SplitHandler sh = new SplitHandler(origSize, compressedDataSize, allowSizes);
			SplitFileInserter sfi = new SplitFileInserter(persistent, parent, sh, 
			        dataRAF, shouldFreeData, ctx, context, origSize, bestCodec, 
			        block.clientMetadata, metadata, archiveType, cryptoAlgorithm, forceCryptoKey,
			        hashThisLayerOnly, hashes, ctx.dontCompress, parent.getMinSuccessFetchBlocks(),
			        parent.getTotalBlocks(), origDataLength, origCompressedDataLength, 
			        realTimeFlag, token);
			sh.sfi = sfi;
			if(logMINOR)
				Logger.minor(this, "Inserting as splitfile: "+sfi+" for "+sh+" for "+this);
			cb.onTransition(this, sh, context);
			sfi.schedule(context);
			synchronized(this) {
			    started = true;
			}
			// SplitHandler will need this.origHashes.
		}
	}
	
	private RandomAccessBucket fixNotPersistent(RandomAccessBucket data, ClientContext context) throws InsertException {
		boolean skip = false;
		try {
			if(!skip) {
			if(logMINOR) Logger.minor(this, "Copying data from "+data+" length "+data.size());
			RandomAccessBucket newData = context.persistentBucketFactory.makeBucket(data.size());
			BucketTools.copy(data, newData);
			data.free();
			data = newData;
			}
		} catch (IOException e) {
			Logger.error(this, "Caught "+e+" while copying non-persistent data", e);
			throw new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null);
		}
		// Note that SegmentedBCB *does* support splitting, so we don't need to do anything to the data
		// if it doesn't fit in a single block.
		return data;
	}

	private void tryCompress(ClientContext context) throws InsertException {
		// First, determine how small it needs to be
	    RandomAccessBucket origData = block.getData();
	    RandomAccessBucket data = origData;
		int blockSize;
		int oneBlockCompressedSize;
		boolean dontCompress = ctx.dontCompress;
		
		long origSize = data.size();
		String type = block.desiredURI.getKeyType().toUpperCase();
		if(type.equals("SSK") || type.equals("KSK") || type.equals("USK")) {
			blockSize = SSKBlock.DATA_LENGTH;
			oneBlockCompressedSize = SSKBlock.MAX_COMPRESSED_DATA_LENGTH;
		} else if(type.equals("CHK")) {
			blockSize = CHKBlock.DATA_LENGTH;
			oneBlockCompressedSize = CHKBlock.MAX_COMPRESSED_DATA_LENGTH;
		} else {
			throw new InsertException(InsertExceptionMode.INVALID_URI, "Unknown key type: "+type, null);
		}
		
		// We always want SHA256, even for small files.
		long wantHashes = 0;
		CompatibilityMode cmode = ctx.getCompatibilityMode();
		boolean atLeast1254 = (cmode == CompatibilityMode.COMPAT_CURRENT || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal());
		if(atLeast1254) {
			// We verify this. We want it for *all* files.
			wantHashes |= HashType.SHA256.bitmask;
			// FIXME: If the user requests it, calculate the others for small files.
			// FIXME maybe the thresholds should be configurable.
			if(data.size() >= 1024*1024 && !metadata) {
				// SHA1 is common and MD5 is cheap.
				wantHashes |= HashType.SHA1.bitmask;
				wantHashes |= HashType.MD5.bitmask;
			}
			if(data.size() >= 4*1024*1024 && !metadata) {
				// Useful for cross-network, and cheap.
				wantHashes |= HashType.ED2K.bitmask;
				// Very widely supported for cross-network.
				wantHashes |= HashType.TTH.bitmask;
				// For completeness.
				wantHashes |= HashType.SHA512.bitmask;
			}
		}
		boolean tryCompress = (origSize > blockSize) && (!ctx.dontCompress) && (!dontCompress);
		if(tryCompress) {
			InsertCompressor.start(context, this, origData, oneBlockCompressedSize, context.getBucketFactory(persistent), persistent, wantHashes, !atLeast1254);
		} else {
			if(logMINOR) Logger.minor(this, "Not compressing "+origData+" size = "+origSize+" block size = "+blockSize);
			HashResult[] hashes = null;
			if(wantHashes != 0) {
				// Need to get the hashes anyway
				NullOutputStream nos = new NullOutputStream();
				MultiHashOutputStream hasher = new MultiHashOutputStream(nos, wantHashes);
				try {
					BucketTools.copyTo(data, hasher, data.size());
				} catch (IOException e) {
					throw new InsertException(InsertExceptionMode.BUCKET_ERROR, "I/O error generating hashes", e, null);
				}
				hashes = hasher.getResults();
			}
			final CompressionOutput output = new CompressionOutput(data, null, hashes);
			context.getJobRunner(persistent).queueNormalOrDrop(new PersistentJob() {

                @Override
                public boolean run(ClientContext context) {
                    onCompressed(output, context);
                    return true;
                }
			    
			});
		}
	}
	
	private Metadata makeMetadata(ARCHIVE_TYPE archiveType, FreenetURI uri, HashResult[] hashes) {
		Metadata meta = null;
		boolean allowTopBlocks = origDataLength != 0;
		int req = 0;
		int total = 0;
		long data = 0;
		long compressed = 0;
		boolean topDontCompress = false;
		CompatibilityMode topCompatibilityMode = CompatibilityMode.COMPAT_UNKNOWN;
		if(allowTopBlocks) {
			req = parent.getMinSuccessFetchBlocks();
			total = parent.totalBlocks;
			topDontCompress = ctx.dontCompress;
			topCompatibilityMode = ctx.getCompatibilityMode();
			data = origDataLength;
			compressed = origCompressedDataLength;
		}
		if(archiveType != null)
			meta = new Metadata(DocumentType.ARCHIVE_MANIFEST, archiveType, null, uri, block.clientMetadata, data, compressed, req, total, topDontCompress, topCompatibilityMode, hashes);
		else // redirect
			meta = new Metadata(DocumentType.SIMPLE_REDIRECT, archiveType, null, uri, block.clientMetadata, data, compressed, req, total, topDontCompress, topCompatibilityMode, hashes);
		if(targetFilename != null) {
			HashMap<String, Object> hm = new HashMap<String, Object>();
			hm.put(targetFilename, meta);
			meta = Metadata.mkRedirectionManifestWithMetadata(hm);
		}
		return meta;
	}

	/**
	 * Create an inserter, either for a USK or a single block.
	 * @param forSplitfile Whether this insert is above a splitfile. This
	 * affects whether we do multiple inserts of the same block. */
	private ClientPutState createInserter(BaseClientPutter parent, Bucket data, short compressionCodec, 
			InsertContext ctx, PutCompletionCallback cb, boolean isMetadata, int sourceLength, int token, 
			boolean addToParent, ClientContext context, boolean freeData, boolean forSplitfile) throws InsertException {
		
		FreenetURI uri = block.desiredURI;
		uri.checkInsertURI(); // will throw an exception if needed
		
		if(uri.getKeyType().equals("USK")) {
			try {
				return new USKInserter(parent, data, compressionCodec, uri, ctx, cb, isMetadata, sourceLength, token, 
					addToParent, this.token, context, freeData, persistent, realTimeFlag, forSplitfile ? ctx.extraInsertsSplitfileHeaderBlock : ctx.extraInsertsSingleBlock, cryptoAlgorithm, forceCryptoKey);
			} catch (MalformedURLException e) {
				throw new InsertException(InsertExceptionMode.INVALID_URI, e, null);
			}
		} else {
			SingleBlockInserter sbi = 
				new SingleBlockInserter(parent, data, compressionCodec, uri, ctx, realTimeFlag, cb, isMetadata, sourceLength, token, 
						addToParent, false, this.token, context, persistent, freeData, forSplitfile ? ctx.extraInsertsSplitfileHeaderBlock : ctx.extraInsertsSingleBlock, cryptoAlgorithm, forceCryptoKey);
			// pass uri to SBI
			block.nullURI();
			return sbi;
		}
		
	}
	
	/**
	 * When we get the metadata, start inserting it to our target key.
	 * When we have inserted both the metadata and the splitfile,
	 * call the master callback.
	 */
	public class SplitHandler implements PutCompletionCallback, ClientPutState, Serializable {

        private static final long serialVersionUID = 1L;
        ClientPutState sfi;
		ClientPutState metadataPutter;
		boolean finished;
		boolean splitInsertSuccess;
		boolean metaInsertSuccess;
		boolean splitInsertSetBlocks;
		boolean metaInsertSetBlocks;
		boolean metaInsertStarted;
		boolean metaFetchable;
		final boolean persistent;
		final long origDataLength;
		final long origCompressedDataLength;
		private transient boolean resumed;
		
		// A persistent hashCode is helpful in debugging, and also means we can put
		// these objects into sets etc when we need to.
		
		private final int hashCode;
		
		@Override
		public int hashCode() {
			return hashCode;
		}

		/**
		 * zero arg c'tor for db4o on jamvm
		 */
		@SuppressWarnings("unused")
		private SplitHandler() {
			persistent = false;
			origDataLength = 0;
			origCompressedDataLength = 0;
			hashCode = 0;
		}

		public SplitHandler(long origDataLength, long origCompressedDataLength, boolean allowSizes) {
			// Default constructor
			this.persistent = SingleFileInserter.this.persistent;
			this.hashCode = super.hashCode();
			this.origDataLength = allowSizes ? origDataLength : 0;
			this.origCompressedDataLength = allowSizes ? origCompressedDataLength : 0;
		}

		@Override
		public synchronized void onTransition(ClientPutState oldState, ClientPutState newState, ClientContext context) {
			if(persistent) { // FIXME debug-point
				if(logMINOR) Logger.minor(this, "Transition: "+oldState+" -> "+newState);
			}
			if(oldState == sfi)
				sfi = newState;
			if(oldState == metadataPutter)
				metadataPutter = newState;
		}
		
		@Override
		public void onSuccess(ClientPutState state, ClientContext context) {
			if(logMINOR) Logger.minor(this, "onSuccess("+state+") for "+this);
			boolean lateStart = false;
			synchronized(this) {
				if(finished){
					return;
				}
				if(state == sfi) {
					if(logMINOR) Logger.minor(this, "Splitfile insert succeeded for "+this+" : "+state);
					splitInsertSuccess = true;
					if(!metaInsertSuccess && !metaInsertStarted) {
						lateStart = true;
						// Cannot remove yet because not created metadata inserter yet.
					} else {
						sfi = null;
						if(logMINOR) Logger.minor(this, "Metadata already started for "+this+" : success="+metaInsertSuccess+" started="+metaInsertStarted);
					}
				} else if(state == metadataPutter) {
					if(logMINOR) Logger.minor(this, "Metadata insert succeeded for "+this+" : "+state);
					metaInsertSuccess = true;
					metadataPutter = null;
				} else {
					Logger.error(this, "Unknown: "+state+" for "+this, new Exception("debug"));
				}
				if(splitInsertSuccess && metaInsertSuccess) {
					if(logMINOR) Logger.minor(this, "Both succeeded for "+this);
					finished = true;
					if(freeData)
						block.free();
					else {
						block.nullData();
					}
				}
			}
			if(lateStart) {
				if(startMetadata(context)) {
					synchronized(this) {
						sfi = null;
					}
				}
			}
			if(finished) {
				cb.onSuccess(this, context);
			}
		}

		@Override
		public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
			boolean toFail = true;
			synchronized(this) {
				if(logMINOR)
					Logger.minor(this, "onFailure(): "+e+" on "+state+" on "+this+" sfi = "+sfi+" metadataPutter = "+metadataPutter);
				if(state == sfi) {
					sfi = null;
				} else if(state == metadataPutter) {
					metadataPutter = null;
				} else {
					Logger.error(this, "onFailure() on unknown state "+state+" on "+this, new Exception("debug"));
				}
				if(finished){
					toFail = false; // Already failed
				}
			}
			// fail() will cancel the other one, so we don't need to.
			// When it does, it will come back here, and we won't call fail(), because fail() has already set finished = true.
			if(toFail)
			fail(e, context);
		}

		@Override
		public void onMetadata(Metadata meta, ClientPutState state, ClientContext context) {
			InsertException e = null;
			if(logMINOR) Logger.minor(this, "Got metadata for "+this+" from "+state);
			synchronized(this) {
				if(finished) return;
				if(reportMetadataOnly) {
					if(state != sfi) {
						Logger.error(this, "Got metadata from unknown object "+state+" when expecting to report metadata");
						return;
					}
					metaInsertSuccess = true;
				} else if(state == metadataPutter) {
					Logger.error(this, "Got metadata for metadata");
					e = new InsertException(InsertExceptionMode.INTERNAL_ERROR, "Did not expect to get metadata for metadata inserter", null);
				} else if(state != sfi) {
					Logger.error(this, "Got metadata from unknown state "+state+" sfi="+sfi+" metadataPutter="+metadataPutter+" on "+this+" persistent="+persistent, new Exception("debug"));
					e = new InsertException(InsertExceptionMode.INTERNAL_ERROR, "Got metadata from unknown state", null);
				} else {
					// Already started metadata putter ? (in which case we've got the metadata twice)
					if(metadataPutter != null) return;
					if(metaInsertSuccess) return;
				}
			}
			if(reportMetadataOnly) {
				cb.onMetadata(meta, this, context);
				return;
			}
			if(e != null) {
				onFailure(e, state, context);
				return;
			}
			
			byte[] metaBytes;
			try {
				metaBytes = meta.writeToByteArray();
			} catch (MetadataUnresolvedException e1) {
				Logger.error(this, "Impossible: "+e1, e1);
				fail((InsertException)new InsertException(InsertExceptionMode.INTERNAL_ERROR, "MetadataUnresolvedException in SingleFileInserter.SplitHandler: "+e1, null).initCause(e1), context);
				return;
			}
			
			String metaPutterTargetFilename = targetFilename;
			
			if(targetFilename != null) {
				
				if(metaBytes.length <= Short.MAX_VALUE) {
					HashMap<String, Object> hm = new HashMap<String, Object>();
					hm.put(targetFilename, meta);
					meta = Metadata.mkRedirectionManifestWithMetadata(hm);
					metaPutterTargetFilename = null;
					try {
						metaBytes = meta.writeToByteArray();
					} catch (MetadataUnresolvedException e1) {
						Logger.error(this, "Impossible (2): "+e1, e1);
						fail((InsertException)new InsertException(InsertExceptionMode.INTERNAL_ERROR, "MetadataUnresolvedException in SingleFileInserter.SplitHandler(2): "+e1, null).initCause(e1), context);
						return;
					}
				}
			}
			
			RandomAccessBucket metadataBucket;
			try {
				metadataBucket = BucketTools.makeImmutableBucket(context.getBucketFactory(persistent), metaBytes);
			} catch (IOException e1) {
				InsertException ex = new InsertException(InsertExceptionMode.BUCKET_ERROR, e1, null);
				fail(ex, context);
				return;
			}
			ClientMetadata m = meta.getClientMetadata();
			CompatibilityMode cmode = ctx.getCompatibilityMode();
			if(!(cmode == CompatibilityMode.COMPAT_CURRENT || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal()))
				m = null;
			if(metadataThreshold > 0 && metaBytes.length < metadataThreshold) {
				// FIXME what to do about m ???
				// I.e. do the other layers of metadata already include the content type?
				// It's probably already included in the splitfile, but need to check that, and test it.
				synchronized(this) {
					metaInsertSuccess = true;
				}
				cb.onMetadata(metadataBucket, state, context);
				return;
			}
			InsertBlock newBlock = new InsertBlock(metadataBucket, m, block.desiredURI);
			synchronized(this) {
			    // Only the bottom layer in a multi-level splitfile pyramid has randomised keys. The rest are unpredictable anyway, and this ensures we only need to supply one key when reinserting.
			    metadataPutter = new SingleFileInserter(parent, this, newBlock, true, ctx, realTimeFlag, false, token, archiveType, true, metaPutterTargetFilename, true, persistent, origDataLength, origCompressedDataLength, origHashes, cryptoAlgorithm, forceCryptoKey, metadataThreshold);
			    if(origHashes != null) {
			        // It gets passed on, and the last one deletes it.
			        SingleFileInserter.this.origHashes = null;
			    }
			    // If EarlyEncode, then start the metadata insert ASAP, to get the key.
			    // Otherwise, wait until the data is fetchable (to improve persistence).
			    if(logMINOR)
			        Logger.minor(this, "Created metadata putter for "+this+" : "+metadataPutter+" bucket "+metadataBucket+" size "+metadataBucket.size());
			    if(!(ctx.earlyEncode || splitInsertSuccess)) return;
			}
			if(logMINOR) Logger.minor(this, "Putting metadata on "+metadataPutter+" from "+sfi+" ("+((SplitFileInserter)sfi).getLength()+ ')');
			if(!startMetadata(context)) {
				Logger.error(this, "onMetadata() yet unable to start metadata due to not having all URIs?!?!");
				fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR, "onMetadata() yet unable to start metadata due to not having all URIs", null), context);
				return;
			}
			synchronized(this) {
				if(splitInsertSuccess && sfi != null) {
					sfi = null;
				}
			}
				
		}

		private void fail(InsertException e, ClientContext context) {
			if(logMINOR) Logger.minor(this, "Failing: "+e, e);
			ClientPutState oldSFI = null;
			ClientPutState oldMetadataPutter = null;
			synchronized(this) {
				if(finished){
					return;
				}
				finished = true;
				oldSFI = sfi;
				oldMetadataPutter = metadataPutter;
			}
			if(oldSFI != null)
				oldSFI.cancel(context);
			if(oldMetadataPutter != null)
				oldMetadataPutter.cancel(context);
			synchronized(this) {
				if(freeData)
					block.free();
				else {
					block.nullData();
				}
			}
			cb.onFailure(e, this, context);
		}

		@Override
		public BaseClientPutter getParent() {
			return parent;
		}

		@Override
		public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
			if(persistent) // FIXME debug-point
				if(logMINOR) Logger.minor(this, "onEncode() for "+this+" : "+state+" : "+key);
			synchronized(this) {
				if(state != metadataPutter) {
					if(logMINOR) Logger.minor(this, "ignored onEncode() for "+this+" : "+state);
					return;
				}
			}
			cb.onEncode(key, this, context);
		}

		@Override
		public void cancel(ClientContext context) {
			if(logMINOR) Logger.minor(this, "Cancelling "+this);
			ClientPutState oldSFI = null;
			ClientPutState oldMetadataPutter = null;
			synchronized(this) {
				oldSFI = sfi;
				oldMetadataPutter = metadataPutter;
			}
			if(oldSFI != null)
				oldSFI.cancel(context);
			if(oldMetadataPutter != null)
				oldMetadataPutter.cancel(context);
			
			// FIXME in the other cases, fail() and onSuccess(), we only free when
			// we set finished. But we haven't set finished here. Can we rely on 
			// the callback and not do anything here? Note that it is in fact safe
			// to double-free, it's not safe to not free.
			if(freeData) {
				block.free();
			} else {
				block.nullData();
			}
		}

		@Override
		public void onBlockSetFinished(ClientPutState state, ClientContext context) {
			synchronized(this) {
				if(state == sfi)
					splitInsertSetBlocks = true;
				else if (state == metadataPutter)
					metaInsertSetBlocks = true;
				else
					if(logMINOR) Logger.minor(this, "Unrecognised: "+state+" in onBlockSetFinished()");
				if(!(splitInsertSetBlocks && metaInsertSetBlocks)) 
					return;
			}
			cb.onBlockSetFinished(this, context);
		}

		@Override
		public void schedule(ClientContext context) throws InsertException {
			sfi.schedule(context);
		}

		@Override
		public Object getToken() {
			return token;
		}

		@Override
		public void onFetchable(ClientPutState state) {

			if(persistent) // FIXME debug-point
				if(logMINOR) Logger.minor(this, "onFetchable on "+this);
			
			if(logMINOR) Logger.minor(this, "onFetchable("+state+ ')');
			
			boolean meta;
			
			synchronized(this) {
				meta = (state == metadataPutter);
				if(meta) {
					if(!metaInsertStarted) {
						Logger.error(this, "Metadata insert not started yet got onFetchable for it: "+state+" on "+this);
					}
					if(logMINOR) Logger.minor(this, "Metadata fetchable"+(metaFetchable?"":" already"));
					if(metaFetchable) return;
					metaFetchable = true;
				} else {
					if(state != sfi) {
						Logger.error(this, "onFetchable for unknown state "+state);
						return;
					}
					if(logMINOR) Logger.minor(this, "Data fetchable");
					if(metaInsertStarted) return;
				}
			}
			
			if(meta) {
				cb.onFetchable(this);
			}
		}
		
		/**
		 * Start fetching metadata.
		 * @param container
		 * @param context
		 * @return True unless we don't have all URI's and so can't remove sfi.
		 */
		private boolean startMetadata(ClientContext context) {
			if(persistent) // FIXME debug-point
				if(logMINOR) Logger.minor(this, "startMetadata() on "+this);
			try {
				ClientPutState putter;
				synchronized(this) {
					if(metaInsertStarted) return true;
					putter = metadataPutter;
					if(putter == null) {
						if(logMINOR) Logger.minor(this, "Cannot start metadata yet: no metadataPutter");
					} else
						metaInsertStarted = true;
				}
				if(putter != null) {
					if(logMINOR) Logger.minor(this, "Starting metadata inserter: "+putter+" for "+this);
					putter.schedule(context);
					if(logMINOR) Logger.minor(this, "Started metadata inserter: "+putter+" for "+this);
					return true;
				} else {
					return false;
				}
			} catch (InsertException e1) {
				Logger.error(this, "Failing "+this+" : "+e1, e1);
				fail(e1, context);
				return true;
			}
		}
		
		@Override
		public void onMetadata(Bucket meta, ClientPutState state, ClientContext context) {
			if(logMINOR) Logger.minor(this, "Got metadata bucket for "+this+" from "+state);
			boolean freeIt = false;
			synchronized(this) {
				if(finished) return;
				if(state == metadataPutter) {
					// Okay, return it.
				} else if(state == sfi) {
					if(metadataPutter != null) {
						Logger.error(this, "Got metadata from "+sfi+" even though already started inserting metadata on the next layer on "+this+" !!");
						freeIt = true;
					} else {
						// Okay, return it.
						metaInsertSuccess = true; // Not going to start it now, so effectively it has succeeded.
					}
				} else if(reportMetadataOnly) {
					if(state != sfi) {
						Logger.error(this, "Got metadata from unknown object "+state+" when expecting to report metadata");
						return;
					}
					metaInsertSuccess = true;
				} else {
					Logger.error(this, "Got metadata from unknown object "+state);
					freeIt = true;
				}
			}
			if(freeIt) {
				meta.free();
				return;
			}
			cb.onMetadata(meta, this, context);
		}

        @Override
        public void onResume(ClientContext context) throws InsertException, ResumeFailedException {
            synchronized(this) {
                if(resumed) return;
                resumed = true;
            }
            if(sfi != null)
                sfi.onResume(context);
            if(metadataPutter != null)
                metadataPutter.onResume(context);
            if(sfi != null)
                sfi.schedule(context);
            if(metadataPutter != null) {
                if(ctx.earlyEncode || sfi == null || metaInsertStarted)
                    metadataPutter.schedule(context);
            }
        }

        @Override
        public void onShutdown(ClientContext context) {
            ClientPutState splitfileInserter;
            ClientPutState metadataInserter;
            synchronized(this) {
                splitfileInserter = sfi;
                metadataInserter = metadataPutter;
            }
            if(splitfileInserter != null)
                splitfileInserter.onShutdown(context);
            if(metadataInserter != null)
                metadataInserter.onShutdown(context);
        }
		
	}

	@Override
	public BaseClientPutter getParent() {
		return parent;
	}

	@Override
	public void cancel(ClientContext context) {
		if(logMINOR) Logger.minor(this, "Cancel "+this);
		synchronized(this) {
			if(cancelled) return;
			cancelled = true;
		}
		if(freeData) {
			block.free();
		}
		// Must call onFailure so get removeFrom()'ed
		cb.onFailure(new InsertException(InsertExceptionMode.CANCELLED), this, context);
	}

	@Override
	public void schedule(ClientContext context) throws InsertException {
		start(context);
	}

	@Override
	public Object getToken() {
		return token;
	}

	public void onStartCompression(COMPRESSOR_TYPE ctype, ClientContext context) {
		if(parent == cb) {
			if(ctx == null) throw new NullPointerException();
			if(ctx.eventProducer == null) throw new NullPointerException();
			ctx.eventProducer.produceEvent(new StartedCompressionEvent(ctype), context);
		}
	}
	
	synchronized boolean cancelled() {
		return cancelled;
	}
	
	synchronized boolean started() {
		return started;
	}
	
	private transient boolean resumed = false;

    @Override
    public final void onResume(ClientContext context) throws InsertException, ResumeFailedException {
        synchronized(this) {
            if(resumed) return;
            resumed = true;
        }
        if(block != null && block.getData() != null)
            block.getData().onResume(context);
        if(cb != null && cb != parent)
            cb.onResume(context);
        synchronized(this) {
            if(started || cancelled) return;
        }
        tryCompress(context);
    }

    @Override
    public void onShutdown(ClientContext context) {
        // Ignore.
    }

}
