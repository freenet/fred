/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import static java.util.concurrent.TimeUnit.SECONDS;

import freenet.crypt.DSAPublicKey;
import freenet.crypt.SHA256;
import freenet.io.comm.AsyncMessageCallback;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.Message;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.PeerContext;
import freenet.io.comm.SlowAsyncMessageFilterCallback;
import freenet.keys.NodeSSK;
import freenet.keys.SSKBlock;
import freenet.keys.SSKVerifyException;
import freenet.support.Logger;
import freenet.support.ShortBuffer;
import freenet.support.io.NativeThread;

/**
 * SSKs require separate logic for inserts and requests, for various reasons:
 * - SSKs can collide.
 * - SSKs have only 1kB of data, so we can pack it into the DataReply, and we don't need to
 *   wait for a long data-transfer timeout.
 * - SSKs have pubkeys, which don't always need to be sent.
 */
public class SSKInsertSender extends BaseSender implements PrioRunnable, AnyInsertSender, ByteCounter {

    // Constants
    static final long ACCEPTED_TIMEOUT = SECONDS.toMillis(10);

    // Basics
    final NodeSSK myKey;
    final long origUID;
    final InsertTag origTag;
    /** SSK's pubkey */
    final DSAPublicKey pubKey;
    /** SSK's pubkey's hash */
    final byte[] pubKeyHash;
    /** Data (we know at start of insert) - can change if we get a collision */
    byte[] data;
    /** Headers (we know at start of insert) - can change if we get a collision */
    byte[] headers;
    final boolean fromStore;
    final long startTime;
    private boolean hasCollided;
    private boolean hasRecentlyCollided;
    private SSKBlock block;
    private static boolean logMINOR;
    private static boolean logDEBUG;
    static {
    	Logger.registerClass(SSKInsertSender.class);
    }
    private final boolean forkOnCacheable;
    private final boolean preferInsert;
    private final boolean ignoreLowBackoff;
    private final boolean realTimeFlag;
    private InsertTag forkedRequestTag;
    
    private int status = -1;
    /** Still running */
    static final int NOT_FINISHED = -1;
    /** Successful insert */
    static final int SUCCESS = 0;
    /** Route not found */
    static final int ROUTE_NOT_FOUND = 1;
    /** Internal error */
    static final int INTERNAL_ERROR = 3;
    /** Timed out waiting for response */
    static final int TIMED_OUT = 4;
    /** Locally Generated a RejectedOverload */
    static final int GENERATED_REJECTED_OVERLOAD = 5;
    /** Could not get off the node at all! */
    static final int ROUTE_REALLY_NOT_FOUND = 6;
    
    SSKInsertSender(SSKBlock block, long uid, InsertTag tag, short htl, PeerNode source, Node node, boolean fromStore, boolean forkOnCacheable, boolean preferInsert, boolean ignoreLowBackoff, boolean realTimeFlag) {
    	super(block.getKey(), realTimeFlag, source, node, htl, uid);
    	this.fromStore = fromStore;
    	this.origUID = uid;
    	this.origTag = tag;
    	myKey = block.getKey();
    	data = block.getRawData();
    	headers = block.getRawHeaders();
    	pubKey = myKey.getPubKey();
    	if(pubKey == null)
    		throw new IllegalArgumentException("Must have pubkey to insert data!!");
    	// pubKey.fingerprint() is not the same as hash(pubKey.asBytes())). FIXME it should be!
    	byte[] pubKeyAsBytes = pubKey.asBytes();
    	pubKeyHash = SHA256.digest(pubKeyAsBytes);
    	this.block = block;
    	startTime = System.currentTimeMillis();
    	this.forkOnCacheable = forkOnCacheable;
    	this.preferInsert = preferInsert;
    	this.ignoreLowBackoff = ignoreLowBackoff;
    	this.realTimeFlag = realTimeFlag;
    }

    void start() {
    	node.executor.execute(this, "SSKInsertSender for UID "+uid+" on "+node.getDarknetPortNumber()+" at "+System.currentTimeMillis());
    }
    
	@Override
	public void run() {
	    freenet.support.Logger.OSThread.logPID(this);
        origTag.startedSender();
        try {
            routeRequests();
        } catch (Throwable t) {
            Logger.error(this, "Caught "+t, t);
            if(status == NOT_FINISHED)
            	finish(INTERNAL_ERROR, null);
        } finally {
        	if(logMINOR) Logger.minor(this, "Finishing "+this);
            if(status == NOT_FINISHED)
            	finish(INTERNAL_ERROR, null);
            origTag.finishedSender();
        	if(forkedRequestTag != null)
        		forkedRequestTag.finishedSender();
        }
	}

	static final int MAX_HIGH_HTL_FAILURES = 5;
	
    protected void routeRequests() {
        PeerNode next = null;
        // While in no-cache mode, we don't decrement HTL on a RejectedLoop or similar, but we only allow a limited number of such failures before RNFing.
        int highHTLFailureCount = 0;
        boolean starting = true;
        while(true) {
            /*
             * If we haven't routed to any node yet, decrement according to the source.
             * If we have, decrement according to the node which just failed.
             * Because:
             * 1) If we always decrement according to source then we can be at max or min HTL
             * for a long time while we visit *every* peer node. This is BAD!
             * 2) The node which just failed can be seen as the requestor for our purposes.
             */
            // Decrement at this point so we can DNF immediately on reaching HTL 0.
            boolean canWriteStorePrev = node.canWriteDatastoreInsert(htl);
            if((!starting) && (!canWriteStorePrev)) {
            	// We always decrement on starting a sender.
            	// However, after that, if our HTL is above the no-cache threshold,
            	// we do not want to decrement the HTL for trivial rejections (e.g. RejectedLoop),
            	// because we would end up caching data too close to the originator.
            	// So allow 5 failures and then RNF.
            	if(highHTLFailureCount++ >= MAX_HIGH_HTL_FAILURES) {
            		if(logMINOR) Logger.minor(this, "Too many failures at non-cacheable HTL");
                    finish(ROUTE_NOT_FOUND, null);
                    return;
            	}
            	if(logMINOR) Logger.minor(this, "Allowing failure "+highHTLFailureCount+" htl is still "+htl);
            } else {
                htl = node.decrementHTL(hasForwarded ? next : source, htl);
                if(logMINOR) Logger.minor(this, "Decremented HTL to "+htl);
            }
            starting = false;
            if(htl <= 0) {
                // Send an InsertReply back
        		if(!hasForwarded)
        			origTag.setNotRoutedOnwards();
                finish(SUCCESS, null);
                return;
            }
            
        	if(origTag.shouldStop()) {
        		finish(SUCCESS, null);
        		return;
        	}
        	
            if( node.canWriteDatastoreInsert(htl) && (!canWriteStorePrev) && forkOnCacheable && forkedRequestTag == null) {
            	// FORK! We are now cacheable, and it is quite possible that we have already gone over the ideal sink nodes,
            	// in which case if we don't fork we will miss them, and greatly reduce the insert's reachability.
            	// So we fork: Create a new UID so we can go over the previous hops again if they happen to be good places to store the data.
            	
            	// Existing transfers will keep their existing UIDs, since they copied the UID in the constructor.
            	// Both local and remote inserts can be forked here: If it has reached this HTL, it means it's already been routed to some nodes.
            	
            	uid = node.clientCore.makeUID();
            	forkedRequestTag = new InsertTag(true, InsertTag.START.REMOTE, source, realTimeFlag, uid, node);
            	forkedRequestTag.reassignToSelf();
            	forkedRequestTag.startedSender();
            	forkedRequestTag.unlockHandler();
				forkedRequestTag.setAccepted();
            	Logger.normal(this, "FORKING SSK INSERT "+origUID+" to "+uid);
            	nodesRoutedTo.clear();
            	node.tracker.lockUID(forkedRequestTag);
            }
            
            // Route it
            next = node.peers.closerPeer(forkedRequestTag == null ? source : null, nodesRoutedTo, target, true, node.isAdvancedModeEnabled(), -1, null,
			        null, htl, ignoreLowBackoff ? Node.LOW_BACKOFF : 0, source == null, realTimeFlag, newLoadManagement);
            
            if(next == null) {
                // Backtrack
        		if(!hasForwarded)
        			origTag.setNotRoutedOnwards();
                finish(ROUTE_NOT_FOUND, null);
                return;
            }
            
            InsertTag thisTag = forkedRequestTag;
            if(forkedRequestTag == null) thisTag = origTag;
            
            innerRouteRequests(next, thisTag);
            return;
        }            
    }
    
    private void handleNoPubkeyAccepted(PeerNode next, InsertTag thisTag) {
    	// FIXME implementing two stage timeout would likely involve forking at this point.
    	// The problem is the peer has now got everything it needs to run the insert!
    	
		// Try to propagate back to source
		Logger.error(this, "Timeout waiting for FNPSSKPubKeyAccepted on "+next);
		next.localRejectedOverload("Timeout2", realTimeFlag);
		// This is a local timeout, they should send it immediately.
		forwardRejectedOverload();
		next.fatalTimeout(thisTag, false);
	}

	private MessageFilter makeSearchFilter(PeerNode next,
			int searchTimeout) {
        /** What are we waiting for now??:
         * - FNPRouteNotFound - couldn't exhaust HTL, but send us the 
         *   data anyway please
         * - FNPInsertReply - used up all HTL, yay
         * - FNPRejectOverload - propagating an overload error :(
         * - FNPDataFound - target already has the data, and the data is
         *   an SVK/SSK/KSK, therefore could be different to what we are
         *   inserting.
         * - FNPDataInsertRejected - the insert was invalid
         */
        
        MessageFilter mfInsertReply = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPInsertReply);
        MessageFilter mfRejectedOverload = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPRejectedOverload);
        MessageFilter mfRouteNotFound = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPRouteNotFound);
        MessageFilter mfDataInsertRejected = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPDataInsertRejected);
        MessageFilter mfSSKDataFoundHeaders = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPSSKDataFoundHeaders);
        
        return mfRouteNotFound.or(mfInsertReply.or(mfRejectedOverload.or(mfDataInsertRejected.or(mfSSKDataFoundHeaders))));
	}

	private DO handleMessage(Message msg, PeerNode next, InsertTag thisTag) {
		if (msg.getSpec() == DMT.FNPRejectedOverload) {
			if(handleRejectedOverload(msg, next, thisTag)) return DO.NEXT_PEER;
			else return DO.WAIT;
		}

		if (msg.getSpec() == DMT.FNPRouteNotFound) {
			handleRouteNotFound(msg, next, thisTag);
			// Finished as far as this node is concerned
			return DO.NEXT_PEER;
		}

		if (msg.getSpec() == DMT.FNPDataInsertRejected) {
			handleDataInsertRejected(msg, next, thisTag);
			return DO.NEXT_PEER; // What else can we do?
		}
		
		if(msg.getSpec() == DMT.FNPSSKDataFoundHeaders) {
			return handleSSKDataFoundHeaders(msg, next, thisTag);
		}
		
		if (msg.getSpec() != DMT.FNPInsertReply) {
			Logger.error(this, "Unknown reply: " + msg);
			finish(INTERNAL_ERROR, next);
			return DO.FINISHED;
		}
				
		// Our task is complete
		next.successNotOverload(realTimeFlag);
		finish(SUCCESS, next);
		return DO.FINISHED;

    }

    private enum DO {
    	FINISHED,
    	WAIT,
    	NEXT_PEER
    }

	private static final long TIMEOUT_AFTER_ACCEPTEDREJECTED_TIMEOUT = SECONDS.toMillis(60);

	@Override
	protected void handleAcceptedRejectedTimeout(final PeerNode next, final UIDTag tag) {
		// It could still be running. So the timeout is fatal to the node.
		// This is a WARNING not an ERROR because it's possible that the problem is we simply haven't been able to send the message yet, because we don't use sendSync().
		// FIXME use a callback to rule this out and log an ERROR.
		Logger.warning(this, "Timeout awaiting Accepted/Rejected "+this+" to "+next);
		// Use the right UID here, in case we fork.
		final long uid = tag.uid;
		tag.handlingTimeout(next);
		// The node didn't accept the request. So we don't need to send them the data.
		// However, we do need to wait a bit longer to try to postpone the fatalTimeout().
		// Somewhat intricate logic to try to avoid fatalTimeout() if at all possible.
		MessageFilter mf = makeAcceptedRejectedFilter(next, TIMEOUT_AFTER_ACCEPTEDREJECTED_TIMEOUT, tag);
		try {
			node.usm.addAsyncFilter(mf, new SlowAsyncMessageFilterCallback() {

				@Override
				public void onMatched(Message m) {
					if(m.getSpec() == DMT.FNPRejectedLoop ||
							m.getSpec() == DMT.FNPRejectedOverload) {
						// Ok.
						next.noLongerRoutingTo(tag, false);
					} else {
						assert(m.getSpec() == DMT.FNPSSKAccepted);
						if(logMINOR)
							Logger.minor(this, "Accepted after timeout on "+SSKInsertSender.this+" - will not send DataInsert, waiting for RejectedTimeout");
						if(logMINOR) Logger.minor(this, "Forked timed out insert but not going to send DataInsert on "+SSKInsertSender.this+" to "+next);
						// We are not going to send the DataInsert.
						// We have moved on, and we don't want inserts to fork unnecessarily.
						// However, we need to send a DataInsertRejected, or two-stage timeout will happen.
						try {
							next.sendAsync(DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_TIMEOUT_WAITING_FOR_ACCEPTED), new AsyncMessageCallback() {

								@Override
								public void sent() {
									// Ignore.
									if(logDEBUG) Logger.debug(this, "DataInsertRejected sent after accepted timeout on "+SSKInsertSender.this);
								}

								@Override
								public void acknowledged() {
									if(logDEBUG) Logger.debug(this, "DataInsertRejected acknowledged after accepted timeout on "+SSKInsertSender.this);
									next.noLongerRoutingTo(tag, false);
								}

								@Override
								public void disconnected() {
									if(logDEBUG) Logger.debug(this, "DataInsertRejected peer disconnected after accepted timeout on "+SSKInsertSender.this);
									next.noLongerRoutingTo(tag, false);
								}

								@Override
								public void fatalError() {
									if(logDEBUG) Logger.debug(this, "DataInsertRejected fatal error after accepted timeout on "+SSKInsertSender.this);
									next.noLongerRoutingTo(tag, false);
								}
								
							}, SSKInsertSender.this);
						} catch (NotConnectedException e) {
							next.noLongerRoutingTo(tag, false);
						}
					}
				}

				@Override
				public boolean shouldTimeout() {
					return false;
				}

				@Override
				public void onTimeout() {
					Logger.error(this, "Fatal: No Accepted/Rejected for "+SSKInsertSender.this);
					next.fatalTimeout(tag, false);
				}

				@Override
				public void onDisconnect(PeerContext ctx) {
					next.noLongerRoutingTo(tag, false);
				}

				@Override
				public void onRestarted(PeerContext ctx) {
					next.noLongerRoutingTo(tag, false);
				}

				@Override
				public int getPriority() {
					return NativeThread.NORM_PRIORITY;
				}
				
			}, this);
		} catch (DisconnectedException e) {
			next.noLongerRoutingTo(tag, false);
		}
	}

    /** @return True if fatal and we should try another node, false if just relayed so 
     * we should wait for more responses. */
    private boolean handleRejectedOverload(Message msg, PeerNode next, InsertTag thisTag) {
		// Probably non-fatal, if so, we have time left, can try next one
		if (msg.getBoolean(DMT.IS_LOCAL)) {
			next.localRejectedOverload("ForwardRejectedOverload4", realTimeFlag);
			if(logMINOR) Logger.minor(this,
					"Local RejectedOverload, moving on to next peer");
			// Give up on this one, try another
        	next.noLongerRoutingTo(thisTag, false);
			return true;
		} else {
			forwardRejectedOverload();
		}
		return false; // Wait for any further response
	}

	private void handleRouteNotFound(Message msg, PeerNode next, InsertTag thisTag) {
		if(logMINOR) Logger.minor(this, "Rejected: RNF");
		short newHtl = msg.getShort(DMT.HTL);
		if(newHtl < 0) newHtl = 0;
		if (htl > newHtl)
			htl = newHtl;
		next.successNotOverload(realTimeFlag);
    	next.noLongerRoutingTo(thisTag, false);
	}

	private void handleDataInsertRejected(Message msg, PeerNode next, InsertTag thisTag) {
		next.successNotOverload(realTimeFlag);
		short reason = msg.getShort(DMT.DATA_INSERT_REJECTED_REASON);
		if(logMINOR) Logger.minor(this, "DataInsertRejected: " + reason);
		if (reason == DMT.DATA_INSERT_REJECTED_VERIFY_FAILED) {
			if (fromStore) {
				// That's odd...
				Logger.error(this,"Verify failed on next node "
						+ next + " for DataInsert but we were sending from the store!");
			}
		}
		Logger.error(this, "SSK insert rejected! Reason="
				+ DMT.getDataInsertRejectedReason(reason));
    	next.noLongerRoutingTo(thisTag, false);
	}

	/** @return True if we got new data and are propagating it. False if something failed
     * and we need to try the next node. */
	private DO handleSSKDataFoundHeaders(Message msg, PeerNode next, InsertTag thisTag) {
		
		/**
		 * Data was already on node, and was NOT equal to what we sent. COLLISION!
		 * 
		 * We can either accept the old data or the new data.
		 * OLD DATA:
		 * - KSK-based stuff is usable. Well, somewhat; a node could spoof KSKs on
		 * receiving an insert, (if it knows them in advance), but it cannot just 
		 * start inserts to overwrite old SSKs.
		 * - You cannot "update" an SSK.
		 * NEW DATA:
		 * - KSK-based stuff not usable. (Some people think this is a good idea!).
		 * - Illusion of updatability. (VERY BAD IMHO, because it's not really
		 * updatable... FIXME implement TUKs; would determine latest version based
		 * on version number, and propagate on request with a certain probability or
		 * according to time. However there are good arguments to do updating at a
		 * higher level (e.g. key bottleneck argument), and TUKs should probably be 
		 * distinct from SSKs.
		 * 
		 * For now, accept the "old" i.e. preexisting data.
		 */
		Logger.normal(this, "Got collision on "+myKey+" ("+uid+") sending to "+next.getPeer());
		
		headers = ((ShortBuffer) msg.getObject(DMT.BLOCK_HEADERS)).getData();
		// Wait for the data
		MessageFilter mfData = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(SSKInsertHandler.DATA_INSERT_TIMEOUT).setType(DMT.FNPSSKDataFoundData);
		Message dataMessage;
		try {
			dataMessage = node.usm.waitFor(mfData, this);
		} catch (DisconnectedException e) {
			if(logMINOR)
				Logger.minor(this, "Disconnected: "+next+" getting datareply for "+this);
			next.noLongerRoutingTo(thisTag, false);
			return DO.NEXT_PEER;
		}
		if(dataMessage == null) {
			Logger.error(this, "Got headers but not data for datareply for insert from "+this);
			next.noLongerRoutingTo(thisTag, false);
			return DO.NEXT_PEER;
		}
		// collided, overwrite data with remote data
		try {
			data = ((ShortBuffer) dataMessage.getObject(DMT.DATA)).getData();
			block = new SSKBlock(data, headers, block.getKey(), false);
			
			synchronized(this) {
				hasRecentlyCollided = true;
				hasCollided = true;
				notifyAll();
			}
			
			// The node will now propagate the new data. There is no need to move to the next node yet.
			return DO.WAIT;
		} catch (SSKVerifyException e) {
			Logger.error(this, "Invalid SSK from remote on collusion: " + this + ":" +block);
			finish(INTERNAL_ERROR, next);
			return DO.FINISHED;
		}
	}

	@Override
	protected MessageFilter makeAcceptedRejectedFilter(PeerNode next,
			long acceptedTimeout, UIDTag tag) {
		// Use the right UID here, in case we fork.
		final long uid = tag.uid;
        /*
         * Because messages may be re-ordered, it is
         * entirely possible that we get a non-local RejectedOverload,
         * followed by an Accepted. So we must loop here.
         */
        
        MessageFilter mfAccepted = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(acceptedTimeout).setType(DMT.FNPSSKAccepted);
        MessageFilter mfRejectedLoop = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(acceptedTimeout).setType(DMT.FNPRejectedLoop);
        MessageFilter mfRejectedOverload = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(acceptedTimeout).setType(DMT.FNPRejectedOverload);
        return mfAccepted.or(mfRejectedLoop.or(mfRejectedOverload));
	}

	private boolean hasForwardedRejectedOverload;
    
    synchronized boolean receivedRejectedOverload() {
    	return hasForwardedRejectedOverload;
    }
    
    /** Forward RejectedOverload to the request originator.
     * DO NOT CALL if have a *local* RejectedOverload.
     */
    @Override
    protected synchronized void forwardRejectedOverload() {
    	if(hasForwardedRejectedOverload) return;
    	hasForwardedRejectedOverload = true;
   		notifyAll();
	}
    
    private void finish(int code, PeerNode next) {
    	if(logMINOR) Logger.minor(this, "Finished: "+getStatusString(code)+" on "+this+" from "+(next == null ? "(null)" : next.shortToString()), new Exception("debug"));
    	
    	if(next != null) {
    		if(origTag != null) next.noLongerRoutingTo(origTag, false);
    		if(forkedRequestTag != null) next.noLongerRoutingTo(forkedRequestTag, false);
    	}
    	
    	synchronized(this) {
    		if(status != NOT_FINISHED && status != TIMED_OUT)
    			throw new IllegalStateException("finish() called with "+code+" when was already "+status);
    		
    		if((code == ROUTE_NOT_FOUND) && !hasForwarded)
    			code = ROUTE_REALLY_NOT_FOUND;
    		
    		if(status != TIMED_OUT) {
    			status = code;
    			notifyAll();
    		}
        }

        if(code == SUCCESS && next != null)
        	next.onSuccess(true, true);
        
        if(logMINOR) Logger.minor(this, "Set status code: "+getStatusString());
        // Nothing to wait for, no downstream transfers, just exit.
    }

    @Override
    public synchronized int getStatus() {
        return status;
    }
    
    @Override
    public synchronized short getHTL() {
        return htl;
    }

    @Override
    public synchronized String getStatusString() {
    	return getStatusString(status);
    }
    
    /**
     * @return The current status as a string
     */
    public static String getStatusString(int status) {
        if(status == SUCCESS)
            return "SUCCESS";
        if(status == ROUTE_NOT_FOUND)
            return "ROUTE NOT FOUND";
        if(status == NOT_FINISHED)
            return "NOT FINISHED";
        if(status == INTERNAL_ERROR)
        	return "INTERNAL ERROR";
        if(status == TIMED_OUT)
        	return "TIMED OUT";
        if(status == GENERATED_REJECTED_OVERLOAD)
        	return "GENERATED REJECTED OVERLOAD";
        if(status == ROUTE_REALLY_NOT_FOUND)
        	return "ROUTE REALLY NOT FOUND";
        return "UNKNOWN STATUS CODE: "+status;
    }

	@Override
	public boolean sentRequest() {
		return hasForwarded;
	}
	
	public synchronized boolean hasRecentlyCollided() {
		boolean status = hasRecentlyCollided;
		hasRecentlyCollided = false;
		return status;
	}
	
	public boolean hasCollided() {
		return hasCollided;
	}
	
	public byte[] getPubkeyHash() {
		return headers;
	}

	public byte[] getHeaders() {
		return headers;
	}
	
	public byte[] getData() {
		return data;
	}

	public SSKBlock getBlock() {
		return block;
	}

	@Override
	public long getUID() {
		return uid;
	}

	private final Object totalBytesSync = new Object();
	private int totalBytesSent;
	
	@Override
	public void sentBytes(int x) {
		synchronized(totalBytesSync) {
			totalBytesSent += x;
		}
		node.nodeStats.insertSentBytes(true, x);
	}
	
	public int getTotalSentBytes() {
		synchronized(totalBytesSync) {
			return totalBytesSent;
		}
	}
	
	private int totalBytesReceived;
	
	@Override
	public void receivedBytes(int x) {
		synchronized(totalBytesSync) {
			totalBytesReceived += x;
		}
		node.nodeStats.insertReceivedBytes(true, x);
	}
	
	public int getTotalReceivedBytes() {
		synchronized(totalBytesSync) {
			return totalBytesReceived;
		}
	}

	@Override
	public void sentPayload(int x) {
		node.sentPayload(x);
		node.nodeStats.insertSentBytes(true, -x);
	}

	@Override
	public int getPriority() {
		return NativeThread.HIGH_PRIORITY;
	}

	@Override
	public String toString() {
		return "SSKInsertSender:" + myKey+":"+uid;
	}

	public PeerNode[] getRoutedTo() {
		return this.nodesRoutedTo.toArray(new PeerNode[nodesRoutedTo.size()]);
	}

	@Override
	protected Message createDataRequest() {
        Message request = DMT.createFNPSSKInsertRequestNew(uid, htl, myKey);
        if(forkOnCacheable != Node.FORK_ON_CACHEABLE_DEFAULT) {
        	request.addSubMessage(DMT.createFNPSubInsertForkControl(forkOnCacheable));
        }
        if(ignoreLowBackoff != Node.IGNORE_LOW_BACKOFF_DEFAULT) {
        	request.addSubMessage(DMT.createFNPSubInsertIgnoreLowBackoff(ignoreLowBackoff));
        }
        if(preferInsert != Node.PREFER_INSERT_DEFAULT) {
        	request.addSubMessage(DMT.createFNPSubInsertPreferInsert(preferInsert));
        }
    	request.addSubMessage(DMT.createFNPRealTimeFlag(realTimeFlag));
        return request;
	}

	@Override
	protected long getAcceptedTimeout() {
		return ACCEPTED_TIMEOUT;
	}

	@Override
	protected void timedOutWhileWaiting() {
		htl -= (short)Math.max(0, hopsForFatalTimeoutWaitingForPeer());
		if(htl < 0) htl = 0;
        // Backtrack, i.e. RNF.
		if(!hasForwarded)
			origTag.setNotRoutedOnwards();
        finish(ROUTE_NOT_FOUND, null);
	}
	
	private boolean needPubKey;
	
	protected boolean isAccepted(Message msg) {
		if(msg.getSpec() == DMT.FNPSSKAccepted) {
			needPubKey = msg.getBoolean(DMT.NEED_PUB_KEY);
			return true;
		} else return false;
	}

	@Override
	protected void onAccepted(PeerNode next) {
        if(logMINOR) Logger.minor(this, "Got Accepted on "+this);
        
        InsertTag thisTag = forkedRequestTag;
        if(forkedRequestTag == null) thisTag = origTag;
        
        // Send the headers and data
        
        Message headersMsg = DMT.createFNPSSKInsertRequestHeaders(uid, headers, realTimeFlag);
        Message dataMsg = DMT.createFNPSSKInsertRequestData(uid, data, realTimeFlag);
        
        try {
			next.sendAsync(headersMsg, null, this);
			next.sendSync(dataMsg, this, realTimeFlag);
			sentPayload(data.length);
		} catch (NotConnectedException e1) {
			if(logMINOR) Logger.minor(this, "Not connected to "+next);
			next.noLongerRoutingTo(thisTag, false);
			routeRequests();
			return;
		} catch (SyncSendWaitedTooLongException e) {
			Logger.error(this, "Waited too long to send "+dataMsg+" to "+next+" on "+this);
			next.noLongerRoutingTo(thisTag, false);
			routeRequests();
			return;
		}
        
        // Do we need to send them the pubkey?
        
		if(needPubKey) {
        	Message pkMsg = DMT.createFNPSSKPubKey(uid, pubKey, realTimeFlag);
        	try {
        		next.sendSync(pkMsg, this, realTimeFlag);
        	} catch (NotConnectedException e) {
        		if(logMINOR) Logger.minor(this, "Node disconnected while sending pubkey: "+next);
				next.noLongerRoutingTo(thisTag, false);
				routeRequests();
				return;
        	} catch (SyncSendWaitedTooLongException e) {
        		Logger.warning(this, "Took too long to send pubkey to "+next+" on "+this);
				next.noLongerRoutingTo(thisTag, false);
				routeRequests();
				return;
			}
        	
        	// Wait for the SSKPubKeyAccepted
        	
        	// FIXME doubled the timeout because handling it properly would involve forking.
        	MessageFilter mf1 = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(ACCEPTED_TIMEOUT*2).setType(DMT.FNPSSKPubKeyAccepted);
        	
        	Message newAck;
			try {
				newAck = node.usm.waitFor(mf1, this);
			} catch (DisconnectedException e) {
				if(logMINOR) Logger.minor(this, "Disconnected from "+next);
				next.noLongerRoutingTo(thisTag, false);
				routeRequests();
				return;
			}
        	
        	if(newAck == null) {
        		handleNoPubkeyAccepted(next, thisTag);
				// Try another peer
    			routeRequests();
    			return;
        	}
        }
        
        // We have sent them the pubkey, and the data.
        // Wait for the response.
        
		MessageFilter mf = makeSearchFilter(next, calculateTimeout(htl));
        
        while (true) {
        	Message msg;
			try {
				msg = node.usm.waitFor(mf, this);
			} catch (DisconnectedException e) {
				Logger.normal(this, "Disconnected from " + next
						+ " while waiting for InsertReply on " + this);
				next.noLongerRoutingTo(thisTag, false);
				break;
			}

			if (msg == null) {
				
				// First timeout.
				Logger.warning(this, "Timeout waiting for reply after Accepted in "+this+" from "+next);
				next.localRejectedOverload("AfterInsertAcceptedTimeout", realTimeFlag);
				forwardRejectedOverload();
				finish(TIMED_OUT, next);
				
				// Wait for second timeout.
				while(true) {
					
					try {
						msg = node.usm.waitFor(mf, this);
					} catch (DisconnectedException e) {
						Logger.normal(this, "Disconnected from " + next
								+ " while waiting for InsertReply on " + this);
						next.noLongerRoutingTo(thisTag, false);
						return;
					}
					
					if(msg == null) {
						// Second timeout.
						Logger.error(this, "Fatal timeout waiting for reply after Accepted on "+this+" from "+next);
						next.fatalTimeout(thisTag, false);
						return;
					}
					
					DO action = handleMessage(msg, next, thisTag);
					
					if(action == DO.FINISHED)
						return;
					else if(action == DO.NEXT_PEER) {
						next.noLongerRoutingTo(thisTag, false);
						return; // Don't try others
					}
					// else if(action == DO.WAIT) continue;
					
				}
			}
			
			DO action = handleMessage(msg, next, thisTag);
			
			if(action == DO.FINISHED)
				return;
			else if(action == DO.NEXT_PEER)
				break;
			// else if(action == DO.WAIT) continue;
        }
		routeRequests();
	}

	@Override
	protected boolean isInsert() {
		return true;
	}
	
	@Override
	protected PeerNode sourceForRouting() {
		if(forkedRequestTag != null) return null;
		return source;
	}

	@Override
	protected long ignoreLowBackoff() {
		return ignoreLowBackoff ? Node.LOW_BACKOFF : 0;
	}

}
