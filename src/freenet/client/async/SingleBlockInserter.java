/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.async;

import java.io.IOException;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.util.Arrays;

import freenet.client.FailureCodeTracker;
import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.keys.CHKEncodeException;
import freenet.keys.ClientCHKBlock;
import freenet.keys.ClientKey;
import freenet.keys.ClientKeyBlock;
import freenet.keys.ClientSSK;
import freenet.keys.ClientSSKBlock;
import freenet.keys.FreenetURI;
import freenet.keys.InsertableClientSSK;
import freenet.keys.KeyBlock;
import freenet.keys.KeyDecodeException;
import freenet.keys.KeyEncodeException;
import freenet.keys.KeyVerifyException;
import freenet.keys.SSKBlock;
import freenet.keys.SSKEncodeException;
import freenet.node.KeysFetchingLocally;
import freenet.node.LowLevelPutException;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.RequestClient;
import freenet.node.RequestScheduler;
import freenet.node.SendableInsert;
import freenet.node.SendableRequestItem;
import freenet.node.SendableRequestItemKey;
import freenet.node.SendableRequestSender;
import freenet.store.KeyCollisionException;
import freenet.support.Fields;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;
import freenet.support.compress.InvalidCompressionCodecException;
import freenet.support.io.BucketTools;
import freenet.support.io.ResumeFailedException;

/**
 * Insert a single block.
 * 
 * WARNING: Changing non-transient members on classes that are Serializable can result in 
 * restarting downloads or losing uploads.
 */
public class SingleBlockInserter extends SendableInsert implements ClientPutState, Serializable {

    private static final long serialVersionUID = 1L;
    private static volatile boolean logMINOR;
	private static volatile boolean logDEBUG;
	
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
				logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}
	
	private Bucket sourceData;
	final short compressionCodec;
	final FreenetURI uri; // uses essentially no RAM in the common case of a CHK because we use FreenetURI.EMPTY_CHK_URI
	private ClientKey resultingKey;
	final PutCompletionCallback cb;
	final BaseClientPutter parent;
	final InsertContext ctx;
	private int retries;
	private final FailureCodeTracker errors;
	private boolean finished;
	private final boolean dontSendEncoded;
	final int token; // for e.g. splitfiles
	private final Object tokenObject;
	final boolean isMetadata;
	final int sourceLength;
	private int consecutiveRNFs;
	private boolean isSSK;
	private boolean freeData;
	private int completedInserts;
	final int extraInserts;
	final byte[] cryptoKey;
	final byte cryptoAlgorithm;

	/**
	 * Create a SingleBlockInserter.
	 * @param parent The parent. Must be activated.
	 * @param data
	 * @param compressionCodec The compression codec.
	 * @param uri
	 * @param ctx
	 * @param realTimeFlag
	 * @param cb
	 * @param isMetadata
	 * @param sourceLength The length of the original, uncompressed data.
	 * @param token
	 * @param addToParent
	 * @param dontSendEncoded
	 * @param tokenObject
	 * @param context
	 * @param persistent
	 * @param freeData
	 * @param extraInserts
	 * @param cryptoAlgorithm
	 * @param cryptoKey
	 */
	public SingleBlockInserter(BaseClientPutter parent, Bucket data, short compressionCodec, FreenetURI uri, InsertContext ctx, boolean realTimeFlag, PutCompletionCallback cb, boolean isMetadata, int sourceLength, int token, boolean addToParent, boolean dontSendEncoded, Object tokenObject, ClientContext context, boolean persistent, boolean freeData, int extraInserts, byte cryptoAlgorithm, byte[] cryptoKey) {
		super(persistent, realTimeFlag);
		this.consecutiveRNFs = 0;
		this.tokenObject = tokenObject;
		this.token = token;
		this.parent = parent;
		this.dontSendEncoded = dontSendEncoded;
		this.retries = 0;
		this.finished = false;
		this.ctx = ctx;
		this.freeData = freeData;
		errors = new FailureCodeTracker(true);
		this.cb = cb;
		this.uri = uri;
		this.compressionCodec = compressionCodec;
		this.sourceData = data;
		if(sourceData == null) throw new NullPointerException();
		this.isMetadata = isMetadata;
		this.sourceLength = sourceLength;
		isSSK = uri.getKeyType().toUpperCase().equals("SSK");
		if(addToParent) {
			parent.addMustSucceedBlocks(1);
			parent.notifyClients(context);
		}
		this.extraInserts = extraInserts;
		this.cryptoAlgorithm = cryptoAlgorithm;
		this.cryptoKey = cryptoKey;
	}

	protected ClientKeyBlock innerEncode() throws InsertException {
		CompatibilityMode cmode = ctx.getCompatibilityMode();
		boolean pre1254 = !(cmode == CompatibilityMode.COMPAT_CURRENT || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal());
		try {
			return innerEncode(uri, sourceData, isMetadata, compressionCodec, sourceLength, ctx.compressorDescriptor, pre1254, cryptoAlgorithm, cryptoKey);
		} catch (KeyEncodeException e) {
			Logger.error(SingleBlockInserter.class, "Caught "+e, e);
			throw new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null);
		} catch (MalformedURLException e) {
			throw new InsertException(InsertExceptionMode.INVALID_URI, e, null);
		} catch (IOException e) {
			Logger.error(SingleBlockInserter.class, "Caught "+e+" encoding data "+sourceData, e);
			throw new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null);
		} catch (InvalidCompressionCodecException e) {
			throw new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null);
		}
			
	}
	
	protected static ClientKeyBlock innerEncode(FreenetURI uri, Bucket sourceData, boolean isMetadata, short compressionCodec, int sourceLength, String compressorDescriptor, boolean pre1254, byte cryptoAlgorithm, byte[] cryptoKey) throws InsertException, CHKEncodeException, IOException, SSKEncodeException, MalformedURLException, InvalidCompressionCodecException {
		String uriType = uri.getKeyType();
		if(uriType.equals("CHK")) {
			return ClientCHKBlock.encode(sourceData, isMetadata, compressionCodec == -1, compressionCodec, sourceLength, compressorDescriptor, pre1254, cryptoKey, cryptoAlgorithm);
		} else if(uriType.equals("SSK") || uriType.equals("KSK")) {
			InsertableClientSSK ik = InsertableClientSSK.create(uri);
			return ik.encode(sourceData, isMetadata, compressionCodec == -1, compressionCodec, sourceLength, compressorDescriptor, pre1254);
		} else {
			throw new InsertException(InsertExceptionMode.INVALID_URI, "Unknown keytype "+uriType, null);
		}
	}

	protected void onEncode(final ClientKey key, final ClientContext context) {
		synchronized(this) {
			if(finished) return;
			if(resultingKey != null) return;
			resultingKey = key;
		}
		if(!persistent) {
			context.mainExecutor.execute(new Runnable() {
				
				@Override
				public void run() {
					cb.onEncode(key, SingleBlockInserter.this, context);
				}
			}, "Got URI");
		} else {
		    context.jobRunner.queueNormalOrDrop(new PersistentJob() { 
		        // Will be reported on restart in innerOnResume() if necessary.
		        
                @Override
                public boolean run(ClientContext context) {
                    cb.onEncode(key, SingleBlockInserter.this, context);
                    return false;
                }
		        
		    });
		}
	}
	
	protected ClientKeyBlock encode(ClientContext context) throws InsertException {
		ClientKeyBlock block;
		boolean shouldSend;
		synchronized(this) {
			if(finished) return null;
			if(sourceData == null) {
				Logger.error(this, "Source data is null on "+this+" but not finished!");
				return null;
			}
			block = innerEncode();
			shouldSend = (resultingKey == null);
			resultingKey = block.getClientKey();
		}
		if(logMINOR)
			Logger.minor(this, "Encoded "+resultingKey.getURI()+" for "+this+" shouldSend="+shouldSend+" dontSendEncoded="+dontSendEncoded);
		if(shouldSend && !dontSendEncoded)
			cb.onEncode(block.getClientKey(), this, context);
		return block;
	}
	
	@Override
	public short getPriorityClass() {
		return parent.getPriorityClass(); // Not much point deactivating
	}

	@Override
	public void onFailure(LowLevelPutException e, SendableRequestItem keyNum, ClientContext context) {
		synchronized(this) {
			if(finished) return;
		}
		if(parent.isCancelled()) {
			fail(new InsertException(InsertExceptionMode.CANCELLED), context);
			return;
		}
		if(logMINOR) Logger.minor(this, "onFailure() on "+e+" for "+this);
		
		switch(e.code) {
		case LowLevelPutException.COLLISION:
			fail(new InsertException(InsertExceptionMode.COLLISION), context);
			return;
		case LowLevelPutException.INTERNAL_ERROR:
			fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR), context);
			return;
		case LowLevelPutException.REJECTED_OVERLOAD:
			errors.inc(InsertExceptionMode.REJECTED_OVERLOAD);
			break;
		case LowLevelPutException.ROUTE_NOT_FOUND:
			errors.inc(InsertExceptionMode.ROUTE_NOT_FOUND);
			break;
		case LowLevelPutException.ROUTE_REALLY_NOT_FOUND:
			errors.inc(InsertExceptionMode.ROUTE_REALLY_NOT_FOUND);
			break;
		default:
			Logger.error(this, "Unknown LowLevelPutException code: "+e.code);
			errors.inc(InsertExceptionMode.INTERNAL_ERROR);
		}
		if(e.code == LowLevelPutException.ROUTE_NOT_FOUND || e.code == LowLevelPutException.ROUTE_REALLY_NOT_FOUND) {
			consecutiveRNFs++;
			if(logMINOR) Logger.minor(this, "Consecutive RNFs: "+consecutiveRNFs+" / "+ctx.consecutiveRNFsCountAsSuccess);
			// Use >= so that extra inserts see this as a success.
			if(consecutiveRNFs >= ctx.consecutiveRNFsCountAsSuccess) {
				if(logMINOR) Logger.minor(this, "Consecutive RNFs: "+consecutiveRNFs+" - counting as success");
				onSuccess(keyNum, getKeyNoEncode(), context);
				return;
			}
		} else
			consecutiveRNFs = 0;
		if(logMINOR) Logger.minor(this, "Failed: "+e);
		retries++;
		if((retries > ctx.maxInsertRetries) && (ctx.maxInsertRetries != -1)) {
			fail(InsertException.construct(persistent ? errors.clone() : errors), context);
			return;
		}
		clearWakeupTime(context);
	}

	private void fail(InsertException e, ClientContext context) {
		fail(e, false, context);
	}
	
	private void fail(InsertException e, boolean forceFatal, ClientContext context) {
		synchronized(this) {
			if(finished) return;
			finished = true;
		}
		if(e.isFatal() || forceFatal)
			parent.fatallyFailedBlock(context);
		else
			parent.failedBlock(context);
		unregister(context, getPriorityClass());
		if(freeData) {
			sourceData.free();
			sourceData = null;
		}
		cb.onFailure(e, this, context);
	}

	public ClientKeyBlock getBlock(ClientContext context) {
		try {
			synchronized (this) {
				if(finished) return null;
			}
			return encode(context);
		} catch (InsertException e) {
			cb.onFailure(e, this, context);
			return null;
		} catch (Throwable t) {
			Logger.error(this, "Caught "+t, t);
			cb.onFailure(new InsertException(InsertExceptionMode.INTERNAL_ERROR, t, null), this, context);
			return null;
		}
	}

	@Override
	public void schedule(ClientContext context) throws InsertException {
		synchronized(this) {
			if(finished) {
				if(logMINOR)
					Logger.minor(this, "Finished already: "+this);
				return;
			}
		}
		if(ctx.getCHKOnly || ctx.earlyEncode) {
			tryEncode(context);
		}
		if(ctx.getCHKOnly) { 
			onSuccess(null, getKeyNoEncode(), context);
		} else {
			getScheduler(context).registerInsert(this);
		}
	}

	@Override
	public boolean isSSK() {
		return isSSK;
	}

	public FreenetURI getURI(ClientContext context) {
		synchronized(this) {
			if(resultingKey != null) {
				return resultingKey.getURI();
			}
		}
		getBlock(context);
		synchronized(this) {
			// FIXME not really necessary? resultingKey is never dropped, only set.
		    return resultingKey.getURI();
		}
	}

	public synchronized FreenetURI getURINoEncode() {
		return resultingKey == null ? null : resultingKey.getURI();
	}
	
	public synchronized ClientKey getKeyNoEncode() {
	    return resultingKey;
	}

	@Override
	public void onSuccess(SendableRequestItem keyNum, ClientKey key, ClientContext context) {
	    onEncode(key, context);
		if(logMINOR) Logger.minor(this, "Succeeded ("+this+"): "+token);
		if(parent.isCancelled()) {
			fail(new InsertException(InsertExceptionMode.CANCELLED), context);
			return;
		}
		boolean shouldSendKey = false;
		synchronized(this) {
			if(extraInserts > 0 && !ctx.getCHKOnly) {
				if(++completedInserts <= extraInserts) {
					if(logMINOR) Logger.minor(this, "Completed inserts "+completedInserts+" of extra inserts "+extraInserts+" on "+this);
					return; // Let it repeat until we've done enough inserts. It hasn't been unregistered yet.
				}
			}
			if(finished) {
				// Normal with persistence.
				Logger.normal(this, "Block already completed: "+this);
				return;
			}
			finished = true;
			if(resultingKey == null) {
			    shouldSendKey = true;
			    resultingKey = key;
			} else {
			    if(!resultingKey.equals(key))
			        Logger.error(this, "Different key: "+resultingKey+" -> "+key+" for "+this);
			}
		}
		if(freeData) {
			sourceData.free();
			sourceData = null;
		}
		parent.completedBlock(false, context);
		unregister(context, getPriorityClass());
		if(logMINOR) Logger.minor(this, "Calling onSuccess for "+cb);
		if(shouldSendKey)
		    cb.onEncode(key, this, context); // In case of race conditions etc, especially for LocalRequestOnly.
		cb.onSuccess(this, context);
	}

	@Override
	public BaseClientPutter getParent() {
		return parent;
	}

	@Override
	public void cancel(ClientContext context) {
		synchronized(this) {
			if(finished) return;
			finished = true;
		}
		if(freeData) {
			sourceData.free();
			sourceData = null;
		}
		super.unregister(context, getPriorityClass());
		cb.onFailure(new InsertException(InsertExceptionMode.CANCELLED), this, context);
	}

	@Override
	public synchronized boolean isEmpty() {
		return finished;
	}
	
	@Override
	public synchronized boolean isCancelled() {
		return finished;
	}

	static class MySendableRequestSender implements SendableRequestSender {

		final String compressorDescriptor;
		// Only use when sure it is available!
		final SingleBlockInserter orig;

		MySendableRequestSender(String compress, SingleBlockInserter orig) {
			compressorDescriptor = compress;
			this.orig = orig;
		}

		@Override
		public boolean send(NodeClientCore core, RequestScheduler sched, final ClientContext context, final ChosenBlock req) {
			// Ignore keyNum, key, since we're only sending one block.
			ClientKeyBlock encodedBlock;
			KeyBlock b;
			final ClientKey key;
			ClientKey k = null;
			if(SingleBlockInserter.logMINOR) Logger.minor(this, "Starting request");
			BlockItem block = (BlockItem) req.token;
			try {
				try {
					encodedBlock = innerEncode(block.uri, block.copyBucket, block.isMetadata, block.compressionCodec, block.sourceLength, compressorDescriptor, block.pre1254, block.cryptoAlgorithm, block.cryptoKey);
					b = encodedBlock.getBlock();
				} catch (CHKEncodeException e) {
					throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, e.toString() + ":" + e.getMessage(), e);
				} catch (SSKEncodeException e) {
					throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, e.toString() + ":" + e.getMessage(), e);
				} catch (MalformedURLException e) {
					throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, e.toString() + ":" + e.getMessage(), e);
				} catch (InsertException e) {
					throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, e.toString() + ":" + e.getMessage(), e);
				} catch (IOException e) {
					throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, e.toString() + ":" + e.getMessage(), e);
				} catch (InvalidCompressionCodecException e) {
					throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, e.toString() + ":" + e.getMessage(), e);
				}
				if (b==null) {
					Logger.error(this, "Asked to send empty block", new Exception("error"));
					return false;
				}
				key = encodedBlock.getClientKey();
				k = key;
				context.getJobRunner(block.persistent).queueNormalOrDrop(new PersistentJob() {
				    
				    @Override
				    public boolean run(ClientContext context) {
				        orig.onEncode(key, context);
				        return true;
				    }
				    
				});
				if(req.localRequestOnly)
					try {
						core.node.store(b, false, req.canWriteClientCache, true, false);
					} catch (KeyCollisionException e) {
						LowLevelPutException failed = new LowLevelPutException(LowLevelPutException.COLLISION);
						KeyBlock collided = core.node.fetch(k.getNodeKey(), true, req.canWriteClientCache, false, false, null);
						if(collided == null) {
							Logger.error(this, "Collided but no key?!");
							// Could be a race condition.
							try {
								core.node.store(b, false, req.canWriteClientCache, true, false);
							} catch (KeyCollisionException e2) {
								Logger.error(this, "Collided but no key and still collided!");
								throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, "Collided, can't find block, but still collides!", e);
							}
						}
						
						failed.setCollidedBlock(collided);
						throw failed;
					}
				else
					core.realPut(b, req.canWriteClientCache, req.forkOnCacheable, Node.PREFER_INSERT_DEFAULT, Node.IGNORE_LOW_BACKOFF_DEFAULT, req.realTimeFlag);
			} catch (LowLevelPutException e) {
				if(logMINOR) Logger.minor(this, "Caught "+e, e);
				if(e.code == LowLevelPutException.COLLISION) {
					// Collision
					try {
						ClientSSKBlock collided = ClientSSKBlock.construct(((SSKBlock)e.getCollidedBlock()), (ClientSSK)k);
						byte[] data = collided.memoryDecode(true);
						byte[] inserting = BucketTools.toByteArray(block.copyBucket);
						if(collided.isMetadata() == block.isMetadata && collided.getCompressionCodec() == block.compressionCodec && Arrays.equals(data, inserting)) {
							if(SingleBlockInserter.logMINOR) Logger.minor(this, "Collided with identical data");
							req.onInsertSuccess(k, context);
							return true;
						} else {
							if(SingleBlockInserter.logMINOR) Logger.minor(this, "Apparently real collision: collided.isMetadata="+collided.isMetadata()+" block.isMetadata="+block.isMetadata+
									" collided.codec="+collided.getCompressionCodec()+" block.codec="+block.compressionCodec+
									" collided.datalength="+data.length+" block.datalength="+inserting.length+" H(collided)="+Fields.hashCode(data)+" H(inserting)="+Fields.hashCode(inserting));
						}
					} catch (KeyVerifyException e1) {
						Logger.error(this, "Caught "+e1+" when checking collision!", e1);
					} catch (KeyDecodeException e1) {
						Logger.error(this, "Caught "+e1+" when checking collision!", e1);
					} catch (IOException e1) {
						Logger.error(this, "Caught "+e1+" when checking collision!", e1);
					}
				}
				req.onFailure(e, context);
				if(SingleBlockInserter.logMINOR) Logger.minor(this, "Request failed for "+e);
				return true;
			} finally {
				block.copyBucket.free();
			}
			if(SingleBlockInserter.logMINOR) Logger.minor(this, "Request succeeded");
			req.onInsertSuccess(k, context);
			return true;
		}

		@Override
		public boolean sendIsBlocking() {
			return true;
		}
	}

	
	@Override
	public SendableRequestSender getSender() {
		String compress;
		compress = ctx.compressorDescriptor;
		return new MySendableRequestSender(compress, this);
	}

	@Override
	public RequestClient getClient() {
		return parent.getClient();
	}

	@Override
	public ClientRequester getClientRequest() {
		return parent;
	}

	@Override
	public Object getToken() {
		return tokenObject;
	}

	/** Attempt to encode the block, if necessary */
	public void tryEncode(ClientContext context) {
		synchronized(this) {
			if(resultingKey != null) return;
			if(finished) return;
		}
		try {
			encode(context);
		} catch (InsertException e) {
			fail(e, context);
		} catch (Throwable t) {
			Logger.error(this, "Caught "+t, t);
			// Don't requeue on BackgroundBlockEncoder.
			// Not necessary to do so (we'll ask again when we need it), and it'll probably just break again.
		}
	}

	@Override
	public synchronized long countSendableKeys() {
		if(finished)
			return 0;
		else
			return 1;
	}

	@Override
	public synchronized long countAllKeys() {
		return countSendableKeys();
	}

	@Override
	public SendableRequestItem chooseKey(KeysFetchingLocally ignored, ClientContext context) {
		try {
			BlockItemKey key;
			synchronized(this) {
				if(finished) return null;
				key = new BlockItemKey(this, hashCode());
				if(ignored.hasInsert(key))
				    return null;
				return getBlockItem(key, context);
			}
		} catch (InsertException e) {
			fail(e, context);
			return null;
		}
	}
	
	@Override
	public long getWakeupTime(ClientContext context, long now) {
	    KeysFetchingLocally keysFetching = getScheduler(context).fetchingKeys();
	    synchronized(this) {
	        if(finished) return -1;
            BlockItemKey key = new BlockItemKey(this, hashCode());
            if(keysFetching.hasInsert(key))
                return Long.MAX_VALUE;
            return 0;
	    }
	}

	private BlockItem getBlockItem(BlockItemKey key, ClientContext context) throws InsertException {
		try {
			synchronized(this) {
				if(finished) return null;
			}
			if(persistent) {
				if(sourceData == null) {
					Logger.error(this, "getBlockItem(): sourceData = null", new Exception("error"));
					fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR), context);
					return null;
				}
			}
			Bucket data = sourceData.createShadow();
			FreenetURI u = uri;
			if(u.getKeyType().equals("CHK")) u = FreenetURI.EMPTY_CHK_URI;
			if(data == null) {
				data = context.tempBucketFactory.makeBucket(sourceData.size());
				BucketTools.copy(sourceData, data);
			}
			CompatibilityMode cmode = ctx.getCompatibilityMode();
			boolean pre1254 = !(cmode == CompatibilityMode.COMPAT_CURRENT || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal());
			return new BlockItem(key, data, isMetadata, compressionCodec, sourceLength, u, persistent, pre1254, cryptoAlgorithm, cryptoKey);
		} catch (IOException e) {
			throw new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null);
		}
	}
	
	/** Everything needed to check whether we are already running a request */
	private static class BlockItemKey implements SendableRequestItemKey {
		private final int hashCode;
		/** STRICTLY for purposes of equals() !!! */
		private final SingleBlockInserter parent;
		
		BlockItemKey(SingleBlockInserter parent, int hashCode) {
			this.parent = parent;
			this.hashCode = hashCode;
		}
		
		@Override
		public int hashCode() {
			return hashCode;
		}
		
		@Override
		public boolean equals(Object o) {
			if(o instanceof BlockItemKey) {
				if(((BlockItemKey)o).parent == parent) return true;
			}
			return false;
		}
		
	}

	/** Everything needed to actually run a request, without access to the SingleBlockInserter (this is
	 * why we copy the Bucket). */
	private static class BlockItem implements SendableRequestItem {
		
		public final boolean pre1254;
		private final Bucket copyBucket;
		final BlockItemKey key;
		private final FreenetURI uri;
		private final boolean persistent;
		private final boolean isMetadata;
		private final short compressionCodec;
		private final int sourceLength;
		public byte cryptoAlgorithm;
		public byte[] cryptoKey;
		
		BlockItem(BlockItemKey key, Bucket bucket, boolean meta, short codec, int srclen, FreenetURI u, boolean persistent, boolean pre1254, byte cryptoAlgorithm, byte[] cryptoKey) {
			this.key = key;
			this.copyBucket = bucket;
			this.pre1254 = pre1254;
			this.uri = u;
			this.isMetadata = meta;
			this.compressionCodec = codec;
			this.sourceLength = srclen;
			this.persistent = persistent;
			this.cryptoAlgorithm = cryptoAlgorithm;
			this.cryptoKey = cryptoKey;
		}
		
		@Override
		public void dump() {
			copyBucket.free();
		}

		@Override
		public SendableRequestItemKey getKey() {
			return key;
		}
		
	}
	
	@Override
	public boolean canWriteClientCache() {
		boolean retval = ctx.canWriteClientCache;
		return retval;
	}
	
	@Override
	public boolean localRequestOnly() {
		boolean retval = ctx.localRequestOnly;
		return retval;
	}
	
	@Override
	public boolean forkOnCacheable() {
		boolean retval = ctx.forkOnCacheable;
		return retval;
	}
	
	@Override
	public void onEncode(SendableRequestItem token, ClientKey key, ClientContext context) {
		onEncode(key, context);
	}

    @Override
    public void innerOnResume(ClientContext context) throws InsertException, ResumeFailedException {
        sourceData.onResume(context);
        if(cb != parent) cb.onResume(context);
        if(resultingKey != null)
            cb.onEncode(resultingKey, SingleBlockInserter.this, context);
        this.schedule(context);
    }

    @Override
    public void onShutdown(ClientContext context) {
        // Ignore.
    }

}
