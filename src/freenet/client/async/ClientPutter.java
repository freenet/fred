/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.async;

import java.io.IOException;

import freenet.client.ClientMetadata;
import freenet.client.InsertBlock;
import freenet.client.InsertContext;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.Metadata;
import freenet.client.events.SendingToNetworkEvent;
import freenet.client.events.SplitfileProgressEvent;
import freenet.crypt.ChecksumChecker;
import freenet.keys.BaseClientKey;
import freenet.keys.FreenetURI;
import freenet.keys.Key;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;
import freenet.support.api.RandomAccessBucket;
import freenet.support.io.ResumeFailedException;

/** A high level insert. */
public class ClientPutter extends BaseClientPutter implements PutCompletionCallback {

    private static final long serialVersionUID = 1L;
    /** Callback for when the insert completes. */
	final ClientPutCallback client;
	/** The data to insert. */
	final RandomAccessBucket data;
	/** The URI to insert it to. Can be CHK@. */
	final FreenetURI targetURI;
	/** The ClientMetadata i.e. the MIME type and any other client-visible metadata. */
	final ClientMetadata cm;
	/** Config settings for this insert - what kind of splitfile to use if needed etc. */
	final InsertContext ctx;
	/** Target filename. If specified, we create manifest metadata so that the file can be accessed at
	 * [ final key ] / [ target filename ]. */
	final String targetFilename;
	/** The current state of the insert. */
	private ClientPutState currentState;
	/** Whether the insert has finished. */
	private boolean finished;
	/** Are we inserting metadata? */
	private final boolean isMetadata;
	private boolean startedStarting;
	/** Are we inserting a binary blob? */
	private final boolean binaryBlob;
	/** The final URI for the data. */
	private FreenetURI uri;
	private final byte[] overrideSplitfileCrypto;
	/** Random or overriden splitfile cryptokey. Valid after start(). */
	private byte[] cryptoKey;
	/** When positive, means we will return metadata rather than a URI, once the
	 * metadata is under this length. If it is too short it is still possible to
	 * return a URI, but we won't return both. */
	private final long metadataThreshold;
	private boolean gotFinalMetadata;

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
	 * zero arg c'tor for db4o on jamvm
	 */
	@SuppressWarnings("unused")
	private ClientPutter() {
		targetURI = null;
		targetFilename = null;
		overrideSplitfileCrypto = null;
		isMetadata = false;
		data = null;
		ctx = null;
		cm = null;
		client = null;
		binaryBlob = false;
		metadataThreshold = 0;
	}

	/**
	 * @param client The object to call back when we complete, or don't.
	 * @param data The data to insert. This will be freed when the insert has completed, whether 
	 * it succeeds or not, so wrap it in a @link freenet.support.io.NoFreeBucket if you don't want 
	 * it to be freed.
	 * @param targetURI
	 * @param cm
	 * @param ctx
	 * @param priorityClass
	 * @param isMetadata
	 * @param targetFilename If set, create a one-file manifest containing this filename pointing to this file.
	 * @param binaryBlob
	 * @param overrideSplitfileCrypto
	 * @param metadataThreshold
	 */
	public ClientPutter(ClientPutCallback client, RandomAccessBucket data, FreenetURI targetURI, ClientMetadata cm, InsertContext ctx,
			short priorityClass,
			boolean isMetadata, String targetFilename, boolean binaryBlob, byte[] overrideSplitfileCrypto,
			long metadataThreshold) {
		super(priorityClass, client);
		this.cm = cm;
		this.isMetadata = isMetadata;
		this.client = client;
		this.data = data;
		this.targetURI = targetURI;
		this.ctx = ctx;
		this.finished = false;
		this.cancelled = false;
		this.targetFilename = targetFilename;
		this.binaryBlob = binaryBlob;
		this.overrideSplitfileCrypto = overrideSplitfileCrypto;
		this.metadataThreshold = metadataThreshold;
	}

	/** Start the insert.
	 * @param earlyEncode If true, try to find the final URI as quickly as possible, and insert the upper
	 * layers as soon as we can, rather than waiting for the lower layers. The default behaviour is safer,
	 * because an attacker can usually only identify the datastream once he has the top block, or once you
	 * have announced the key.
	 * @param context Contains some useful transient fields such as the schedulers.
	 * @throws InsertException If the insert cannot be started for some reason.
	 */
	public void start(ClientContext context) throws InsertException {
		start(false, context);
	}

	/** Start the insert.
	 * @param restart If true, restart the insert even though it has completed before.
	 * @param context Contains some useful transient fields such as the schedulers.
	 * @throws InsertException If the insert cannot be started for some reason.
	 */
	public boolean start(boolean restart, ClientContext context) throws InsertException {
		if(logMINOR)
			Logger.minor(this, "Starting "+this+" for "+targetURI);
		byte cryptoAlgorithm;
		CompatibilityMode mode = ctx.getCompatibilityMode();
		if(!(mode == CompatibilityMode.COMPAT_CURRENT || mode.ordinal() >= CompatibilityMode.COMPAT_1416.ordinal()))
			cryptoAlgorithm = Key.ALGO_AES_PCFB_256_SHA256;
		else
			cryptoAlgorithm = Key.ALGO_AES_CTR_256_SHA256;
		try {
			this.targetURI.checkInsertURI();
			// If the top level key is an SSK, all CHK blocks and particularly splitfiles below it should have
			// randomised keys. This substantially improves security by making it impossible to identify blocks
			// even if you know the content. In the user interface, we will offer the option of inserting as a
			// random SSK to take advantage of this.
			boolean randomiseSplitfileKeys = randomiseSplitfileKeys(targetURI, ctx);

			if(data == null)
				throw new InsertException(InsertExceptionMode.BUCKET_ERROR, "No data to insert", null);

			boolean cancel = false;
			synchronized(this) {
				if(restart) {
					clearCountersOnRestart();
					if(currentState != null && !finished) {
						if(logMINOR) Logger.minor(this, "Can't restart, not finished and currentState != null : "+currentState);
						return false;
					}
					if(finished)
					    startedStarting = false;
					finished = false;
				}
				if(startedStarting) {
					if(logMINOR) Logger.minor(this, "Can't "+(restart?"restart":"start")+" : startedStarting = true");
					return false;
				}
				startedStarting = true;
				if(currentState != null) {
					if(logMINOR) Logger.minor(this, "Can't "+(restart?"restart":"start")+" : currentState != null : "+currentState);
					return false;
				}
				cancel = this.cancelled;
				cryptoKey = null;
				if(overrideSplitfileCrypto != null) {
					cryptoKey = overrideSplitfileCrypto;
					if (cryptoKey.length != 32)
						throw new InsertException(InsertExceptionMode.INVALID_URI, "overrideSplitfileCryptoKey must be of length 32", null);
				} else if(randomiseSplitfileKeys) {
					cryptoKey = new byte[32];
					context.random.nextBytes(cryptoKey);
				}
				if(!cancel) {
					if(!binaryBlob) {
						ClientMetadata meta = cm;
						if(meta != null) meta = persistent() ? meta.clone() : meta;
						currentState =
							new SingleFileInserter(this, this, new InsertBlock(data, meta, targetURI), isMetadata, ctx, realTimeFlag,
                                    false, null, null, false, targetFilename, false, persistent(), 0, 0, null, cryptoAlgorithm, cryptoKey, metadataThreshold);
					} else
						currentState =
							new BinaryBlobInserter(data, this, getClient(), false, priorityClass, ctx, context);
				}
			}
			if(cancel) {
				onFailure(new InsertException(InsertExceptionMode.CANCELLED), null, context);
				return false;
			}
			synchronized(this) {
				cancel = cancelled;
			}
			if(cancel) {
				onFailure(new InsertException(InsertExceptionMode.CANCELLED), null, context);
				return false;
			}
			if(logMINOR)
				Logger.minor(this, "Starting insert: "+currentState);
			if(currentState instanceof SingleFileInserter)
				((SingleFileInserter)currentState).start(context);
			else
				currentState.schedule(context);
			synchronized(this) {
				cancel = cancelled;
			}
			if(cancel) {
				onFailure(new InsertException(InsertExceptionMode.CANCELLED), null, context);
				return false;
			}
		} catch (InsertException e) {
			Logger.error(this, "Failed to start insert: "+e, e);
			synchronized(this) {
				finished = true;
				currentState = null;
			}
			// notify the client that the insert could not even be started
			if (this.client!=null) {
				this.client.onFailure(e, this);
			}
		} catch (IOException e) {
			Logger.error(this, "Failed to start insert: "+e, e);
			synchronized(this) {
				finished = true;
				currentState = null;
			}
			// notify the client that the insert could not even be started
			if (this.client!=null) {
				this.client.onFailure(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null), this);
			}
		} catch (BinaryBlobFormatException e) {
			Logger.error(this, "Failed to start insert: "+e, e);
			synchronized(this) {
				finished = true;
				currentState = null;
			}
			// notify the client that the insert could not even be started
			if (this.client!=null) {
				this.client.onFailure(new InsertException(InsertExceptionMode.BINARY_BLOB_FORMAT_ERROR, e, null), this);
			}
		}
		if(logMINOR)
			Logger.minor(this, "Started "+this);
		return true;
	}

	public static boolean randomiseSplitfileKeys(FreenetURI targetURI, InsertContext ctx) {
		// If the top level key is an SSK, all CHK blocks and particularly splitfiles below it should have
		// randomised keys. This substantially improves security by making it impossible to identify blocks
		// even if you know the content. In the user interface, we will offer the option of inserting as a
		// random SSK to take advantage of this.
		boolean randomiseSplitfileKeys = targetURI.isSSK() || targetURI.isKSK() || targetURI.isUSK();
		if(randomiseSplitfileKeys) {
			CompatibilityMode cmode = ctx.getCompatibilityMode();
			if(!(cmode == CompatibilityMode.COMPAT_CURRENT || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal()))
				randomiseSplitfileKeys = false;
		}
		return randomiseSplitfileKeys;
	}

	/** Called when the insert succeeds. */
	@Override
	public void onSuccess(ClientPutState state, ClientContext context) {
		synchronized(this) {
			finished = true;
			currentState = null;
		}
		if(super.failedBlocks > 0 || super.fatallyFailedBlocks > 0 || super.successfulBlocks < super.totalBlocks) {
			// USK auxiliary inserts are allowed to fail.
			// If only generating the key, splitfile may not have reported the blocks as inserted.
			if (!uri.isUSK() && !ctx.getCHKOnly)
				Logger.error(this, "Failed blocks: "+failedBlocks+", Fatally failed blocks: "+fatallyFailedBlocks+
						", Successful blocks: "+successfulBlocks+", Total blocks: "+totalBlocks+" but success?! on "+this+" from "+state,
						new Exception("debug"));
		}
		client.onSuccess(this);
	}

	/** Called when the insert fails. */
	@Override
	public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
		if(logMINOR) Logger.minor(this, "onFailure() for "+this+" : "+state+" : "+e, e);
		synchronized(this) {
			finished = true;
			currentState = null;
		}
		client.onFailure(e, this);
	}

	/** Called when we know the final URI of the insert. */
	@Override
	public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
		FreenetURI u;
		synchronized(this) {
		    u = key.getURI(); 
			if(gotFinalMetadata) {
				Logger.error(this, "Generated URI *and* sent final metadata??? on "+this+" from "+state);
			}
			if(targetFilename != null)
				u = u.pushMetaString(targetFilename);
			if(this.uri != null) {
			    if(!this.uri.equals(u)) {
			        Logger.error(this, "onEncode() called twice with different URIs: "+this.uri+" -> "+u+" for "+this, new Exception("error"));
			    }
			    return;
			}
            this.uri = u;
		}
		client.onGeneratedURI(u, this);
	}
	
	/** Called when metadataThreshold was specified and metadata is being returned
	 * instead of a URI. */
	public void onMetadata(Bucket finalMetadata, ClientPutState state, ClientContext context) {
		boolean freeIt = false;
		synchronized(this) {
			if(uri != null) {
				Logger.error(this, "Generated URI *and* sent final metadata??? on "+this+" from "+state);
			}
			if(gotFinalMetadata) {
				Logger.error(this, "onMetadata called twice - already sent metadata to client for "+this);
				freeIt = true;
			} else {
				gotFinalMetadata = true;
			}
		}
		if(freeIt) {
			finalMetadata.free();
			return;
		}
		client.onGeneratedMetadata(finalMetadata, this);
	}

	/** Cancel the insert. Will call onFailure() if it is not already cancelled, so the callback will
	 * normally be called. */
	@Override
	public void cancel(ClientContext context) {
		if(logMINOR)
			Logger.minor(this, "Cancelling "+this, new Exception("debug"));
		ClientPutState oldState = null;
		synchronized(this) {
			if(cancelled) return;
			if(finished) return;
			super.cancel();
			oldState = currentState;
		}
		if(oldState != null) oldState.cancel(context);
		onFailure(new InsertException(InsertExceptionMode.CANCELLED), null, context);
	}

	/** Has the insert completed already? */
	@Override
	public synchronized boolean isFinished() {
		return finished || cancelled;
	}
	
	/**
	 * @return The data {@link Bucket} which is used by this ClientPutter.
	 */
	public Bucket getData() {
		return data;
	}
	
	/**
	 * Get the target URI with which this insert was started.
	 */
	public FreenetURI getTargetURI() {
		return targetURI;
	}

	/** Get the final URI to the inserted data */
	@Override
	public FreenetURI getURI() {
		return uri;
	}

	/**
	 * Get used splitfile cryptokey. Valid only after start().
	 */
	public byte[] getSplitfileCryptoKey() {
		return cryptoKey;
	}

	/** Called when a ClientPutState transitions to a new state. If this is the current state, then we update
	 * it, but it might also be a subsidiary state, in which case we ignore it. */
	@Override
	public void onTransition(ClientPutState oldState, ClientPutState newState, ClientContext context) {
		if(newState == null) throw new NullPointerException();

		synchronized (this) {
			if (currentState == oldState) {
				currentState = newState;
				return;
			}
		}
		if(persistent())
		    context.jobRunner.setCheckpointASAP();
		Logger.normal(this, "onTransition: cur=" + currentState + ", old=" + oldState + ", new=" + newState);
	}

	/** Called when we have generated metadata for the insert. This should not happen, because we should
	 * insert the metadata! */
	@Override
	public void onMetadata(Metadata m, ClientPutState state, ClientContext context) {
		Logger.error(this, "Got metadata on "+this+" from "+state+" (this means the metadata won't be inserted)");
	}

	/** The number of blocks that will be needed to fetch the data. We put this in the top block metadata. */
	protected int minSuccessFetchBlocks;
	
	@Override
	public int getMinSuccessFetchBlocks() {
		return minSuccessFetchBlocks;
	}
	
	@Override
	public void addBlock() {
		synchronized(this) {
			minSuccessFetchBlocks++;
		}
		super.addBlock();
	}
	
	@Override
	public void addBlocks(int num) {
		synchronized(this) {
			minSuccessFetchBlocks+=num;
		}
		super.addBlocks(num);
	}
	
	/** Add one or more blocks to the number of requires blocks, and don't notify the clients. */
	@Override
	public void addMustSucceedBlocks(int blocks) {
		synchronized(this) {
			minSuccessFetchBlocks += blocks;
		}
		super.addMustSucceedBlocks(blocks);
	}

	/** Add one or more blocks to the number of requires blocks, and don't notify the clients. 
	 * These blocks are added to the minSuccessFetchBlocks for the insert, but not to the counter for what
	 * the requestor must fetch. */
	@Override
	public void addRedundantBlocksInsert(int blocks) {
		super.addMustSucceedBlocks(blocks);
	}
	
	@Override
	protected void clearCountersOnRestart() {
		minSuccessFetchBlocks = 0;
		super.clearCountersOnRestart();
	}

	@Override
	protected void innerNotifyClients(ClientContext context) {
	    SplitfileProgressEvent e;
	    synchronized(this) {
	        e = new SplitfileProgressEvent(
	            this.totalBlocks,
	            this.successfulBlocks,
	            this.latestSuccess,
	            this.failedBlocks,
	            this.fatallyFailedBlocks,
	            this.latestFailure,
	            this.minSuccessBlocks,
	            this.minSuccessFetchBlocks,
	            this.blockSetFinalized);
	    }
		ctx.eventProducer.produceEvent(e, context);
	}

	/** Notify listening clients that an insert has been sent to the network. */
	@Override
	protected void innerToNetwork(ClientContext context) {
		ctx.eventProducer.produceEvent(new SendingToNetworkEvent(), context);
	}

	/** Called when we know exactly how many blocks will be needed. */
	@Override
	public void onBlockSetFinished(ClientPutState state, ClientContext context) {
		if(logMINOR)
			Logger.minor(this, "Set finished", new Exception("debug"));
		blockSetFinalized(context);
	}

	/** Called (sometimes) when enough of the data has been inserted that the file can now be fetched. Not
	 * very useful unless earlyEncode was enabled. */
	@Override
	public void onFetchable(ClientPutState state) {
		client.onFetchable(this);
	}

	/** Can we restart the insert? */
	public boolean canRestart() {
		if(currentState != null && !finished) {
			Logger.minor(this, "Cannot restart because not finished for "+uri);
			return false;
		}
		if(data == null) return false;
		return true;
	}

	/** Restart the insert.
	 * @return True if the insert restarted successfully.
	 * @throws InsertException If the insert could not be restarted for some reason.
	 * */
	public boolean restart(ClientContext context) throws InsertException {
		return start(true, context);
	}

	@Override
	public void onTransition(ClientGetState oldState, ClientGetState newState, ClientContext context) {
		// Ignore, at the moment
	    // This exists here because e.g. USKInserter does requests as well as inserts.
	    // FIXME I'm not sure that's a good enough reason though! Get rid ...
	}

	@Override
	public void dump() {
		System.out.println("URI: "+uri);
		System.out.println("Client: "+client);
		System.out.println("Finished: "+finished);
		System.out.println("Data: "+data);
	}
	
    public byte[] getClientDetail(ChecksumChecker checker) throws IOException {
        if(client instanceof PersistentClientCallback) {
            return getClientDetail((PersistentClientCallback)client, checker);
        } else
            return new byte[0];
    }

    @Override
    public void innerOnResume(ClientContext context) throws ResumeFailedException {
        super.innerOnResume(context);
        if(currentState != null) {
            try {
                currentState.onResume(context);
            } catch (InsertException e) {
                this.onFailure(e, null, context);
                return;
            }
        }
        if(data != null)
            data.onResume(context);
        notifyClients(context);
    }

    @Override
    protected ClientBaseCallback getCallback() {
        return client;
    }
    
    @Override
    public void onShutdown(ClientContext context) {
        ClientPutState state;
        synchronized(this) {
            state = currentState;
        }
        if(state != null)
            state.onShutdown(context);
    }
}
