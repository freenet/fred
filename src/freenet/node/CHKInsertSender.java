/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.util.ArrayList;
import java.util.List;

import freenet.io.comm.AsyncMessageCallback;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.Message;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.PeerContext;
import freenet.io.comm.SlowAsyncMessageFilterCallback;
import freenet.io.xfer.AbortedException;
import freenet.io.xfer.BlockTransmitter;
import freenet.io.xfer.BlockTransmitter.BlockTransmitterCompletion;
import freenet.io.xfer.PartiallyReceivedBlock;
import freenet.keys.CHKBlock;
import freenet.keys.CHKVerifyException;
import freenet.keys.NodeCHK;
import freenet.support.Logger;
import freenet.support.io.NativeThread;

public final class CHKInsertSender extends BaseSender implements PrioRunnable, AnyInsertSender, ByteCounter {
	
	private class BackgroundTransfer implements PrioRunnable, SlowAsyncMessageFilterCallback {
		private final long uid;
		/** Node we are waiting for response from */
		final PeerNode pn;
		/** We may be sending data to that node */
		BlockTransmitter bt;
		/** Have we received notice of the downstream success
		 * or failure of dependant transfers from that node?
		 * Includes timing out. */
		boolean receivedCompletionNotice;
		/** Set when we fatally timeout, or when we get a completion other than a timeout. */
		boolean finishedWaiting;

		/** Was the notification of successful transfer? */
		boolean completionSucceeded;
		
		/** Have we completed the immediate transfer? */
		boolean completedTransfer;
		/** Did it succeed? */
		//boolean transferSucceeded;
		
		/** Do we have the InsertReply, RNF or similar completion? If not,
		 * there is no point starting to wait for a timeout. */
		boolean gotInsertReply;
		/** Have we started the first wait? We start waiting when we have 
		 * completed the transfer AND received an InsertReply, RNF or similar. */
		private boolean startedWait;
		/** Has the background transfer been terminated due to not receiving
		 * an InsertReply, or due to disconnection etc? */
		private boolean killed;
		
		private final InsertTag thisTag;
		
		BackgroundTransfer(final PeerNode pn, PartiallyReceivedBlock prb, InsertTag thisTag) {
			this.pn = pn;
			this.uid = CHKInsertSender.this.uid;
			this.thisTag = thisTag;
			bt = new BlockTransmitter(node.usm, node.getTicker(), pn, uid, prb, CHKInsertSender.this, BlockTransmitter.NEVER_CASCADE, 
					new BlockTransmitterCompletion() {

				@Override
				public void blockTransferFinished(boolean success) {
					if(logMINOR) Logger.minor(this, "Transfer completed: "+success+" for "+this);
					BackgroundTransfer.this.completedTransfer(success);
					// Double-check that the node is still connected. Pointless to wait otherwise.
					if (pn.isConnected() && success) {
						synchronized(backgroundTransfers) {
							if(!gotInsertReply) return;
							if(startedWait) return;
							startedWait = true;
						}
						startWait();
					} else {
						BackgroundTransfer.this.receivedNotice(false, false, false);
						pn.localRejectedOverload("TransferFailedInsert", realTimeFlag);
					}
				}
				
			}, realTimeFlag, node.nodeStats);
		}
		
		/** Start waiting for an acknowledgement or timeout. Caller must ensure
		 * that the transfer has succeeded and we have received an RNF, InsertReply
		 * or other valid completion. The timeout is relative to that, since up
		 * to that point we could still be routing. */
		private void startWait() {
			if(logMINOR) Logger.minor(this, "Waiting for completion notification from "+this);
			//synch-version: this.receivedNotice(waitForReceivedNotification(this));
			//Add ourselves as a listener for the longterm completion message of this transfer, then gracefully exit.
			try {
				node.usm.addAsyncFilter(getNotificationMessageFilter(false), BackgroundTransfer.this, null);
			} catch (DisconnectedException e) {
				// Normal
				if(logMINOR)
					Logger.minor(this, "Disconnected while adding filter");
				BackgroundTransfer.this.completedTransfer(false);
				BackgroundTransfer.this.receivedNotice(false, false, true);
			}
		}
		
		void start() {
			node.executor.execute(this, "CHKInsert-BackgroundTransfer for "+uid+" to "+pn.getPeer());
		}
		
		@Override
		public void run() {
			freenet.support.Logger.OSThread.logPID(this);
			try {
				this.realRun();
			} catch (Throwable t) {
				this.completedTransfer(false);
				this.receivedNotice(false, false, true);
				Logger.error(this, "Caught "+t, t);
			}
		}
		
		private void realRun() {
			bt.sendAsync();
			// REDFLAG: Load limiting:
			// No confirmation that it has finished, and it won't finish immediately on the transfer finishing.
			// So don't try to thisTag.removeRoutingTo(next), just assume it keeps running until the whole insert finishes.
		}
		
		private void completedTransfer(boolean success) {
			synchronized(backgroundTransfers) {
				//transferSucceeded = success; //FIXME Don't used
				completedTransfer = true;
				backgroundTransfers.notifyAll();
			}
			if(!success) {
				setTransferTimedOut();
			}
		}
		
		/** @param timeout Whether this completion is the result of a timeout.
		 * @return True if we should wait again, false if we have already received a notice or timed out. */
		private boolean receivedNotice(boolean success, boolean timeout, boolean kill) {
			if(logMINOR) Logger.minor(this, "Received notice: "+success+(timeout ? " (timeout)" : "")+" on "+this);
			boolean noUnlockPeer = false;
			boolean gotFatalTimeout = false;
			synchronized(backgroundTransfers) {
				if(finishedWaiting) {
					if(!(killed || kill))
						Logger.error(this, "Finished waiting already yet receivedNotice("+success+","+timeout+","+kill+")", new Exception("error"));
					return false;
				}
				if(killed) {
					// Do nothing. But do unlock.
				} else if(kill) {
					killed = true;
					finishedWaiting = true;
					receivedCompletionNotice = true;
					completionSucceeded = false;
				} else {
					if (receivedCompletionNotice) {
						// Two stage timeout.
						if(logMINOR) Logger.minor(this, "receivedNotice("+success+"), already had receivedNotice("+completionSucceeded+")");
						if(timeout) {
							// Fatal timeout.
							finishedWaiting = true;
							gotFatalTimeout = true;
						}
					} else {
						// Normal completion.
						completionSucceeded = success;
						receivedCompletionNotice = true;
						if(!timeout) // Any completion mode other than a timeout immediately sets finishedWaiting, because we won't wait any longer.
							finishedWaiting = true;
						else {
							// First timeout but not had second timeout yet.
							// Unlock downstream (below), but will wait here for the peer to fatally timeout.
							// UIDTag will automatically reassign to self when the time comes if we call handlingTimeout() here, and will avoid unnecessarily logging errors.
							// LOCKING: Note that it is safe to call the tag within the lock since we always take the UIDTag lock last.
							thisTag.handlingTimeout(pn);
							noUnlockPeer = true;
						}
					}
				}
				if(!noUnlockPeer)
					startedWait = true; // Prevent further wait's.
			}
			if((!gotFatalTimeout) && (!success)) {
				setTransferTimedOut();
			}
			if(!noUnlockPeer)
				// Downstream (away from originator), we need to stay locked on the peer until the fatal timeout / the delayed notice.
				// Upstream (towards originator), of course, we can unlockHandler() as soon as all the transfers are finished.
				// LOCKING: Do this outside the lock as pn can do heavy stuff in response (new load management).
				pn.noLongerRoutingTo(thisTag, false);
			synchronized(backgroundTransfers) {
				// Avoid "Unlocked handler but still routing to yet not reassigned".
				if(!gotFatalTimeout) {
					backgroundTransfers.notifyAll();
				}
			}
			if(timeout && gotFatalTimeout) {
				Logger.error(this, "Second timeout waiting for final ack from "+pn+" on "+this);
				pn.fatalTimeout(thisTag, false);
				return false;
			}
			return true;
		}
		
		@Override
		public void onMatched(Message m) {
			pn.successNotOverload(realTimeFlag);
			PeerNode pn = (PeerNode) m.getSource();
			// pn cannot be null, because the filters will prevent garbage collection of the nodes
			
			if(this.pn.equals(pn)) {
				boolean anyTimedOut = m.getBoolean(DMT.ANY_TIMED_OUT);
				if(anyTimedOut) {
					CHKInsertSender.this.setTransferTimedOut();
				}
				receivedNotice(!anyTimedOut, false, false);
			} else {
				Logger.error(this, "received completion notice for wrong node: "+pn+" != "+this.pn);
			}			
		}
		
		@Override
		public boolean shouldTimeout() {
			//AFIACS, this will still let the filter timeout, but not call onMatched() twice.
			return finishedWaiting;
		}
		
		private MessageFilter getNotificationMessageFilter(boolean longTimeoutAnyway) {
			return MessageFilter.create().setField(DMT.UID, uid).setType(DMT.FNPInsertTransfersCompleted).setSource(pn).setTimeout(longTimeoutAnyway ? TRANSFER_COMPLETION_ACK_TIMEOUT_BULK : transferCompletionTimeout);
		}

		@Override
		public void onTimeout() {
			/* FIXME: Cascading timeout...
			   if this times out, we don't have any time to report to the node of origin the timeout notification (anyTimedOut?).
			 */
			// NORMAL priority because it is normally caused by a transfer taking too long downstream, and that doesn't usually indicate a bug.
			Logger.normal(this, "Timed out waiting for a final ack from: "+pn+" on "+this, new Exception("debug"));
			if(receivedNotice(false, true, false)) {
				pn.localRejectedOverload("InsertTimeoutNoFinalAck", realTimeFlag);
				// First timeout. Wait for second timeout.
				try {
					node.usm.addAsyncFilter(getNotificationMessageFilter(true), this, CHKInsertSender.this);
				} catch (DisconnectedException e) {
					// Normal
					if(logMINOR)
						Logger.minor(this, "Disconnected while adding filter after first timeout");
					pn.noLongerRoutingTo(thisTag, false);
				}
			}
		}

		@Override
		public void onDisconnect(PeerContext ctx) {
			Logger.normal(this, "Disconnected "+ctx+" for "+this);
			receivedNotice(true, false, true); // as far as we know
			pn.noLongerRoutingTo(thisTag, false);
		}

		@Override
		public void onRestarted(PeerContext ctx) {
			Logger.normal(this, "Restarted "+ctx+" for "+this);
			receivedNotice(true, false, true);
			pn.noLongerRoutingTo(thisTag, false);
		}

		@Override
		public int getPriority() {
			return NativeThread.HIGH_PRIORITY;
		}
		
		@Override
		public String toString() {
			return super.toString()+":"+uid+":"+pn;
		}

		/** Called when we have received an InsertReply, RouteNotFound or other
		 * successful or quasi-successful completion to routing. */
		public void onCompleted() {
			synchronized(backgroundTransfers) {
				if(finishedWaiting) return;
				if(gotInsertReply) return;
				gotInsertReply = true;
				if(!completedTransfer) return;
				if(startedWait) return;
				startedWait = true;
			}
			startWait();
		}

		/** Called when we get a failure, e.g. DataInsertRejected. */
		public void kill() {
			Logger.normal(this, "Killed "+this);
			receivedNotice(false, false, true); // as far as we know
			pn.noLongerRoutingTo(thisTag, false);
		}
	}

	CHKInsertSender(NodeCHK myKey, long uid, InsertTag tag, byte[] headers, short htl,
			PeerNode source, Node node, PartiallyReceivedBlock prb, boolean fromStore,
			boolean forkOnCacheable, boolean preferInsert, boolean ignoreLowBackoff, boolean realTimeFlag) {
		super(myKey, realTimeFlag, source, node, htl, uid);
        this.origUID = uid;
        this.origTag = tag;
        this.headers = headers;
        this.prb = prb;
        this.fromStore = fromStore;
        this.startTime = System.currentTimeMillis();
        this.backgroundTransfers = new ArrayList<BackgroundTransfer>();
        this.forkOnCacheable = forkOnCacheable;
        this.preferInsert = preferInsert;
        this.ignoreLowBackoff = ignoreLowBackoff;
        if(realTimeFlag) {
        	transferCompletionTimeout = TRANSFER_COMPLETION_ACK_TIMEOUT_REALTIME;
        } else {
        	transferCompletionTimeout = TRANSFER_COMPLETION_ACK_TIMEOUT_BULK;
        }
    }

	void start() {
		node.executor.execute(this, "CHKInsertSender for UID "+uid+" on "+node.getDarknetPortNumber()+" at "+System.currentTimeMillis());
	}

	static boolean logMINOR;
	static boolean logDEBUG;
	
	static {
		Logger.registerClass(CHKInsertSender.class);
	}
	
    // Constants
    static final long ACCEPTED_TIMEOUT = SECONDS.toMillis(10);
    static final long TRANSFER_COMPLETION_ACK_TIMEOUT_REALTIME = MINUTES.toMillis(1);
    static final long TRANSFER_COMPLETION_ACK_TIMEOUT_BULK = MINUTES.toMillis(5);

    final long transferCompletionTimeout;
    
    // Basics
    final long origUID;
    final InsertTag origTag;
    private InsertTag forkedRequestTag;
    final byte[] headers; // received BEFORE creation => we handle Accepted elsewhere
    final PartiallyReceivedBlock prb;
    final boolean fromStore;
    private boolean receiveFailed;
    final long startTime;
    private final boolean forkOnCacheable;
    private final boolean preferInsert;
    private final boolean ignoreLowBackoff;

    
    /** List of nodes we are waiting for either a transfer completion
     * notice or a transfer completion from. Also used as a sync object for waiting for transfer completion. */
    private List<BackgroundTransfer> backgroundTransfers;
    
    /** Have all transfers completed and all nodes reported completion status? */
    private boolean allTransfersCompleted;
    
    /** Has a transfer timed out, either directly or downstream? */
    private volatile boolean transferTimedOut;
    
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
    /** Receive failed. Not used internally; only used by CHKInsertHandler. */
    static final int RECEIVE_FAILED = 7;
    
    @Override
	public String toString() {
        return super.toString()+" for "+uid;
    }
    
    @Override
    public void run() {
	    freenet.support.Logger.OSThread.logPID(this);
    	origTag.startedSender();
        try {
            routeRequests();
        } catch (Throwable t) {
            Logger.error(this, "Caught "+t, t);
        } finally {
        	// Always check: we ALWAYS set status, even if receiveFailed.
            int myStatus;
            synchronized (this) {
				myStatus = status;
			}
            if(myStatus == NOT_FINISHED)
            	finish(INTERNAL_ERROR, null);
            origTag.finishedSender();
        	if(forkedRequestTag != null)
        		forkedRequestTag.finishedSender();
        }
    }
    
	static final int MAX_HIGH_HTL_FAILURES = 5;
	
	@Override
    protected void routeRequests() {
        
        PeerNode next = null;
        // While in no-cache mode, we don't decrement HTL on a RejectedLoop or similar, but we only allow a limited number of such failures before RNFing.
        int highHTLFailureCount = 0;
        boolean starting = true;
        while(true) {
        	if(failIfReceiveFailed(null, null)) return; // don't need to set status as killed by CHKInsertHandler
            
        	if(origTag.shouldStop()) {
        		finish(SUCCESS, null);
        		return;
        	}
        	
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
            boolean successNow = false;
            boolean noRequest = false;
            synchronized (this) {
            	if(htl <= 0) {
            		successNow = true;
            		// Send an InsertReply back
            		noRequest = !hasForwarded;
            	}
            }
            if(successNow) {
        		if(noRequest)
        			origTag.setNotRoutedOnwards();
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
				forkedRequestTag = new InsertTag(false, InsertTag.START.REMOTE, source, realTimeFlag, uid, node);
				forkedRequestTag.reassignToSelf();
				forkedRequestTag.startedSender();
				forkedRequestTag.unlockHandler();
				forkedRequestTag.setAccepted();
            	Logger.normal(this, "FORKING CHK INSERT "+origUID+" to "+uid);
            	nodesRoutedTo.clear();
            	node.tracker.lockUID(forkedRequestTag);
            }
            
            // Route it
            // Can backtrack, so only route to nodes closer than we are to target.
            next = node.peers.closerPeer(forkedRequestTag == null ? source : null, nodesRoutedTo, target, true, node.isAdvancedModeEnabled(), -1, null,
			        null, htl, ignoreLowBackoff ? Node.LOW_BACKOFF : 0, source == null, realTimeFlag, newLoadManagement);
			
            if(next == null) {
                // Backtrack
        		if(!hasForwarded)
        			origTag.setNotRoutedOnwards();
                finish(ROUTE_NOT_FOUND, null);
                return;
            }
			
            if(logMINOR) Logger.minor(this, "Routing insert to "+next);
            nodesRoutedTo.add(next);
            
            InsertTag thisTag = forkedRequestTag;
            if(forkedRequestTag == null) thisTag = origTag;
            
			if(failIfReceiveFailed(thisTag, next)) {
				// Need to tell the peer that the DataInsert is not forthcoming.
				// DataInsertRejected is overridden to work both ways.
				try {
					next.sendAsync(DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_RECEIVE_FAILED), null, this);
				} catch (NotConnectedException e) {
					// Ignore
				}
				return;
			}
			
			innerRouteRequests(next, thisTag);
			return;
		}
	}

    private void handleRejectedTimeout(Message msg, PeerNode next) {
    	// Some severe lag problem.
    	// However it is not fatal because we can be confident now that even if the DataInsert
    	// is delivered late, it will not be acted on. I.e. we are certain how many requests
    	// are running, which is what fatal timeouts are designed to deal with.
		Logger.warning(this, "Node timed out waiting for our DataInsert (" + msg + " from " + next
				+ ") after Accepted in insert - treating as fatal timeout");
		// Terminal overload
		// Try to propagate back to source
		next.localRejectedOverload("AfterInsertAcceptedRejectedTimeout", realTimeFlag);
		
		// We have always started the transfer by the time this is called, so we do NOT need to removeRoutingTo().
		finish(TIMED_OUT, next);
	}

	/** @return True if fatal i.e. we should try another node. */
	private boolean handleRejectedOverload(Message msg, PeerNode next) {
		// Probably non-fatal, if so, we have time left, can try next one
		if (msg.getBoolean(DMT.IS_LOCAL)) {
			next.localRejectedOverload("ForwardRejectedOverload6", realTimeFlag);
			if(logMINOR) Logger.minor(this,
					"Local RejectedOverload, moving on to next peer");
			// Give up on this one, try another
			return true;
		} else {
			forwardRejectedOverload();
		}
		return false; // Wait for any further response
	}

	private void handleRNF(Message msg, PeerNode next) {
		if(logMINOR) Logger.minor(this, "Rejected: RNF");
		short newHtl = msg.getShort(DMT.HTL);
		if(newHtl < 0) newHtl = 0;
		synchronized (this) {
			if (htl > newHtl)
				htl = newHtl;						
		}
		// Finished as far as this node is concerned - except for the data transfer, which will continue until it finishes.
		next.successNotOverload(realTimeFlag);
	}

	private void handleDataInsertRejected(Message msg, PeerNode next) {
		next.successNotOverload(realTimeFlag);
		short reason = msg
				.getShort(DMT.DATA_INSERT_REJECTED_REASON);
		if(logMINOR) Logger.minor(this, "DataInsertRejected: " + reason);
		if (reason == DMT.DATA_INSERT_REJECTED_VERIFY_FAILED) {
			if (fromStore) {
				// That's odd...
				Logger.error(this,"Verify failed on next node "
						+ next + " for DataInsert but we were sending from the store!");
			} else {
				try {
					if (!prb.allReceived())
						Logger.error(this,
								"Did not receive all packets but next node says invalid anyway!");
					else {
						// Check the data
						new CHKBlock(prb.getBlock(), headers,
								(NodeCHK) key);
						Logger.error(this,
								"Verify failed on " + next
								+ " but data was valid!");
					}
				} catch (CHKVerifyException e) {
					Logger.normal(this,
									"Verify failed because data was invalid");
				} catch (AbortedException e) {
					onReceiveFailed();
				}
			}
		} else if (reason == DMT.DATA_INSERT_REJECTED_RECEIVE_FAILED) {
			boolean recvFailed;
			synchronized(backgroundTransfers) {
				recvFailed = receiveFailed;
			}
			if (recvFailed) {
				if(logMINOR) Logger.minor(this, "Failed to receive data, so failed to send data");
			} else {
				try {
					if (prb.allReceived()) {
						// Probably caused by transient connectivity problems.
						// Only fatal timeouts warrant ERROR's because they indicate something seriously wrong that didn't result in a disconnection, and because they cause disconnections.
						Logger.warning(this, "Received all data but send failed to " + next);
					} else {
						if (prb.isAborted()) {
							Logger.normal(this, "Send failed: aborted: " + prb.getAbortReason() + ": " + prb.getAbortDescription());
						} else
							Logger.normal(this, "Send failed; have not yet received all data but not aborted: " + next);
					}
				} catch (AbortedException e) {
					onReceiveFailed();
				}
			}
		}
		Logger.error(this, "DataInsert rejected! Reason="
				+ DMT.getDataInsertRejectedReason(reason));
	}

	@Override
	protected MessageFilter makeAcceptedRejectedFilter(PeerNode next, long acceptedTimeout, UIDTag tag) {
		// Use the right UID here, in case we fork on cacheable.
		final long uid = tag.uid;
        MessageFilter mfAccepted = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(acceptedTimeout).setType(DMT.FNPAccepted);
        MessageFilter mfRejectedLoop = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(acceptedTimeout).setType(DMT.FNPRejectedLoop);
        MessageFilter mfRejectedOverload = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(acceptedTimeout).setType(DMT.FNPRejectedOverload);
        
        // mfRejectedOverload must be the last thing in the or
        // So its or pointer remains null
        // Otherwise we need to recreate it below
        mfRejectedOverload.clearOr();
        return mfAccepted.or(mfRejectedLoop.or(mfRejectedOverload));
	}

	private static final long TIMEOUT_AFTER_ACCEPTEDREJECTED_TIMEOUT = MINUTES.toMillis(1);

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
						assert(m.getSpec() == DMT.FNPAccepted);
						if(logMINOR)
							Logger.minor(this, "Accepted after timeout on "+CHKInsertSender.this+" - will not send DataInsert, waiting for RejectedTimeout");
						// We are not going to send the DataInsert.
						// We have moved on, and we don't want inserts to fork unnecessarily.
						// However, we need to send a DataInsertRejected, or two-stage timeout will happen.
						try {
							next.sendAsync(DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_TIMEOUT_WAITING_FOR_ACCEPTED), new AsyncMessageCallback() {

								@Override
								public void sent() {
									// Ignore.
									if(logDEBUG) Logger.debug(this, "DataInsertRejected sent after accepted timeout on "+CHKInsertSender.this);
								}

								@Override
								public void acknowledged() {
									if(logDEBUG) Logger.debug(this, "DataInsertRejected acknowledged after accepted timeout on "+CHKInsertSender.this);
									next.noLongerRoutingTo(tag, false);
								}

								@Override
								public void disconnected() {
									if(logDEBUG) Logger.debug(this, "DataInsertRejected peer disconnected after accepted timeout on "+CHKInsertSender.this);
									next.noLongerRoutingTo(tag, false);
								}

								@Override
								public void fatalError() {
									if(logDEBUG) Logger.debug(this, "DataInsertRejected fatal error after accepted timeout on "+CHKInsertSender.this);
									next.noLongerRoutingTo(tag, false);
								}
								
							}, CHKInsertSender.this);
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
					Logger.error(this, "Fatal: No Accepted/Rejected for "+CHKInsertSender.this);
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

	private BackgroundTransfer startBackgroundTransfer(PeerNode node, PartiallyReceivedBlock prb, InsertTag tag) {
		BackgroundTransfer ac = new BackgroundTransfer(node, prb, tag);
		synchronized(backgroundTransfers) {
			backgroundTransfers.add(ac);
			backgroundTransfers.notifyAll();
		}
		ac.start();
		return ac;
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
	
	private void setTransferTimedOut() {
		synchronized(this) {
			if(!transferTimedOut) {
				transferTimedOut = true;
				notifyAll();
			}
		}
	}
    
    /**
     * Finish the insert process. Will set status, wait for underlings to complete, and report success
     * if appropriate.
     * @param code The status code to set. 
     * @param next The node we successfully inserted to.
     */
    private void finish(int code, PeerNode next) {
    	if(logMINOR) Logger.minor(this, "Finished: "+code+" on "+this, new Exception("debug"));
     
    	// If there is an InsertReply, it always happens before the transfer completion notice.
    	// So we do NOT need to removeRoutingTo().
    	
        synchronized(this) {
        	if(allTransfersCompleted) return; // Already called. Doesn't prevent race condition resulting in the next bit running but that's not really a problem.
        	if((code == ROUTE_NOT_FOUND) && !hasForwarded)
        		code = ROUTE_REALLY_NOT_FOUND;

        	if(status != NOT_FINISHED) {
        		if(status == RECEIVE_FAILED) {
        			if(code == SUCCESS)
        				Logger.error(this, "Request succeeded despite receive failed?! on "+this);
        		} else if(status != TIMED_OUT)
        			throw new IllegalStateException("finish() called with "+code+" when was already "+status);
        	} else {
                status = code;
        	}
        	
        	notifyAll();
        	if(logMINOR) Logger.minor(this, "Set status code: "+getStatusString()+" on "+uid);
        }
		
        boolean failedRecv = false; // receiveFailed is protected by backgroundTransfers but status by this
        // Now wait for transfers, or for downstream transfer notifications.
        // Note that even the data receive may not have completed by this point.
        boolean mustWait = false;
		synchronized(backgroundTransfers) {
			if (backgroundTransfers.isEmpty()) {
				if(logMINOR) Logger.minor(this, "No background transfers");
				failedRecv = receiveFailed;
			} else {
				mustWait = true;
			}
		}
		if(mustWait) { 
			waitForBackgroundTransferCompletions();
			synchronized(backgroundTransfers) {
				failedRecv = receiveFailed;
			}
		}
        
		synchronized(this) {
			// waitForBackgroundTransferCompletions() may have already set it.
			if(!allTransfersCompleted) {
				if(failedRecv)
					status = RECEIVE_FAILED;
				allTransfersCompleted = true;
				notifyAll();
			}
		}
        	
        if(status == SUCCESS && next != null)
        	next.onSuccess(true, false);
        
        if(logMINOR) Logger.minor(this, "Returning from finish()");
    }

    @Override
    public synchronized int getStatus() {
        return status;
    }
    
    @Override
    public synchronized short getHTL() {
        return htl;
    }
    
    public boolean failIfReceiveFailed(InsertTag tag, PeerNode next) {
    	synchronized(backgroundTransfers) {
    		if(!receiveFailed) return false;
    	}
    	if(logMINOR) Logger.minor(this, "Failing because receive failed on "+this);
    	if(tag != null && next != null) {
   			next.noLongerRoutingTo(tag, false);
    	}
    	return true;
    }

    /**
     * Called by CHKInsertHandler to notify that the receive has
     * failed.
     */
    public void onReceiveFailed() {
    	if(logMINOR) Logger.minor(this, "Receive failed on "+this);
    	synchronized(backgroundTransfers) {
    		receiveFailed = true;
    		backgroundTransfers.notifyAll();
    		// Locking is safe as UIDTag always taken last.
    		for(BackgroundTransfer t : backgroundTransfers)
    			t.thisTag.handlingTimeout(t.pn);
    	}
    	// Set status immediately.
    	// The code (e.g. waitForStatus()) relies on a status eventually being set,
    	// so we may as well set it here. The alternative is to set it in realRun()
    	// when we notice that receiveFailed = true.
    	synchronized(this) {
    		status = RECEIVE_FAILED;
    		allTransfersCompleted = true;
    		notifyAll();
    	}
    	// Do not call finish(), that can only be called on the main thread and it will block.
    }

    /**
     * @return The current status as a string
     */
    @Override
    public synchronized String getStatusString() {
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
	public synchronized boolean sentRequest() {
		return hasForwarded;
	}
		
		private void waitForBackgroundTransferCompletions() {
			try {
				freenet.support.Logger.OSThread.logPID(this);
				if(logMINOR) Logger.minor(this, "Waiting for background transfer completions: "+this);
				
				// We must presently be at such a stage that no more background transfers will be added.
				
				BackgroundTransfer[] transfers;
				synchronized(backgroundTransfers) {
					transfers = new BackgroundTransfer[backgroundTransfers.size()];
					transfers = backgroundTransfers.toArray(transfers);
				}
				
				// Wait for the outgoing transfers to complete.
				if(!waitForBackgroundTransfers(transfers)) {
					setTransferTimedOut();
					return;
				}
			} finally {
				synchronized(CHKInsertSender.this) {
					allTransfersCompleted = true;
					CHKInsertSender.this.notifyAll();
				}
			}
		}

		/**
		 * Block until all transfers have reached a final-terminal state (success/failure). On success this means that a
		 * successful 'received-notification' has been received.
		 * @return True if all background transfers were successful.
		 */
		private boolean waitForBackgroundTransfers(BackgroundTransfer[] transfers) {
			long start = System.currentTimeMillis();
			// Generous deadline so we catch bugs more obviously
			long deadline = start + transferCompletionTimeout * 3;
			// MAYBE all done
			while(true) {
				if(System.currentTimeMillis() > deadline) {
					// NORMAL priority because it is normally caused by a transfer taking too long downstream, and that doesn't usually indicate a bug.
					Logger.normal(this, "Timed out waiting for background transfers! Probably caused by async filter not getting a timeout notification! DEBUG ME!");
					return false;
				}
				//If we want to be sure to exit as-soon-as the transfers are done, then we must hold the lock while we check.
				synchronized(backgroundTransfers) {
					if(receiveFailed) return false;
					
					boolean noneRouteable = true;
					boolean completedTransfers = true;
					boolean completedNotifications = true;
					boolean someFailed = false;
					for(BackgroundTransfer transfer: transfers) {
						if(!transfer.pn.isRoutable()) {
							if(logMINOR)
								Logger.minor(this, "Ignoring transfer to "+transfer.pn+" for "+this+" as not routable");
							continue;
						}
						noneRouteable = false;
						if(!transfer.completedTransfer) {
							if(logMINOR)
								Logger.minor(this, "Waiting for transfer completion to "+transfer.pn+" : "+transfer);
							//must wait
							completedTransfers = false;
							break;
						}
						if (!transfer.receivedCompletionNotice) {
							if(logMINOR)
								Logger.minor(this, "Waiting for completion notice from "+transfer.pn+" : "+transfer);
							//must wait
							completedNotifications = false;
							break;
						}
						if (!transfer.completionSucceeded)
							someFailed = true;
					}
					if(noneRouteable) return false;
					if(completedTransfers && completedNotifications) return !someFailed;
					
					if(logMINOR) Logger.minor(this, "Waiting: transfer completion=" + completedTransfers + " notification="+completedNotifications); 
					try {
						backgroundTransfers.wait(SECONDS.toMillis(100));
					} catch (InterruptedException e) {
						// Ignore
					}
				}				
			}
		}


	public synchronized boolean completed() {
		return allTransfersCompleted;
	}

	/** Block until status has been set to something other than NOT_FINISHED */
	public synchronized void waitForStatus() {
		while(status == NOT_FINISHED) {
			try {
				CHKInsertSender.this.wait(SECONDS.toMillis(100));
			} catch (InterruptedException e) {
				// Ignore
			}
		}
	}

	public boolean anyTransfersFailed() {
		return transferTimedOut;
	}

	public byte[] getPubkeyHash() {
		return headers;
	}

	public byte[] getHeaders() {
		return headers;
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
		node.nodeStats.insertSentBytes(false, x);
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
		node.nodeStats.insertReceivedBytes(false, x);
	}
	
	public int getTotalReceivedBytes() {
		synchronized(totalBytesSync) {
			return totalBytesReceived;
		}
	}

	@Override
	public void sentPayload(int x) {
		node.sentPayload(x);
		node.nodeStats.insertSentBytes(false, -x);
	}

	public boolean failedReceive() {
		return receiveFailed;
	}

	public boolean startedSendingData() {
		synchronized(backgroundTransfers) {
			return !backgroundTransfers.isEmpty();
		}
	}

	@Override
	public int getPriority() {
		return NativeThread.HIGH_PRIORITY;
	}

	public PeerNode[] getRoutedTo() {
		return this.nodesRoutedTo.toArray(new PeerNode[nodesRoutedTo.size()]);
	}

	@Override
	protected Message createDataRequest() {
        Message req;
        
        req = DMT.createFNPInsertRequest(uid, htl, key);
        if(forkOnCacheable != Node.FORK_ON_CACHEABLE_DEFAULT) {
        	req.addSubMessage(DMT.createFNPSubInsertForkControl(forkOnCacheable));
        }
        if(ignoreLowBackoff != Node.IGNORE_LOW_BACKOFF_DEFAULT) {
        	req.addSubMessage(DMT.createFNPSubInsertIgnoreLowBackoff(ignoreLowBackoff));
        }
        if(preferInsert != Node.PREFER_INSERT_DEFAULT) {
        	req.addSubMessage(DMT.createFNPSubInsertPreferInsert(preferInsert));
        }
    	req.addSubMessage(DMT.createFNPRealTimeFlag(realTimeFlag));
        
    	return req;
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

	@Override
	protected void onAccepted(PeerNode next) {
        // Send them the data.
        // Which might be the new data resulting from a collision...

        Message dataInsert;
        dataInsert = DMT.createFNPDataInsert(uid, headers);
        /** What are we waiting for now??:
         * - FNPRouteNotFound - couldn't exhaust HTL, but send us the 
         *   data anyway please
         * - FNPInsertReply - used up all HTL, yay
         * - FNPRejectOverload - propagating an overload error :(
         * - FNPRejectTimeout - we took too long to send the DataInsert
         * - FNPDataInsertRejected - the insert was invalid
         */
        
        int searchTimeout = calculateTimeout(htl);
        MessageFilter mfInsertReply = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPInsertReply);
        MessageFilter mfRejectedOverload = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPRejectedOverload);
        MessageFilter mfRouteNotFound = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPRouteNotFound);
        MessageFilter mfDataInsertRejected = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPDataInsertRejected);
        MessageFilter mfTimeout = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPRejectedTimeout);
        
        MessageFilter mf = mfInsertReply.or(mfRouteNotFound.or(mfDataInsertRejected.or(mfTimeout.or(mfRejectedOverload))));

        InsertTag thisTag = forkedRequestTag;
        if(forkedRequestTag == null) thisTag = origTag;
        
        if(logMINOR) Logger.minor(this, "Sending DataInsert");
        try {
			next.sendSync(dataInsert, this, realTimeFlag);
		} catch (NotConnectedException e1) {
			if(logMINOR) Logger.minor(this, "Not connected sending DataInsert: "+next+" for "+uid);
			next.noLongerRoutingTo(thisTag, false);
			routeRequests();
			return;
		} catch (SyncSendWaitedTooLongException e) {
			Logger.error(this, "Unable to send "+dataInsert+" to "+next+" in a reasonable time");
			// Other side will fail. No need to do anything.
			next.noLongerRoutingTo(thisTag, false);
			routeRequests();
			return;
		}

		if(logMINOR) Logger.minor(this, "Sending data");
		final BackgroundTransfer transfer = 
			startBackgroundTransfer(next, prb, thisTag);
		
		// Once the transfer has started, we only unlock the tag after the transfer completes (successfully or not).
		
        while (true) {

        	Message msg;
        	
			if(failIfReceiveFailed(thisTag, next)) {
				// The transfer has started, it will be cancelled.
				transfer.onCompleted();
				return;
			}
			
			try {
				msg = node.usm.waitFor(mf, this);
			} catch (DisconnectedException e) {
				Logger.normal(this, "Disconnected from " + next
						+ " while waiting for InsertReply on " + this);
				transfer.onDisconnect(next);
				break;
			}
			if(failIfReceiveFailed(thisTag, next)) {
				// The transfer has started, it will be cancelled.
				transfer.onCompleted();
				return;
			}
			
			if (msg == null) {
				
				Logger.warning(this, "Timeout on insert "+this+" to "+next);
				
				// First timeout.
				// Could be caused by the next node, or could be caused downstream.
				next.localRejectedOverload("AfterInsertAcceptedTimeout2", realTimeFlag);
				forwardRejectedOverload();

				synchronized(this) {
					status = TIMED_OUT;
					notifyAll();
				}
				
				// Wait for the second timeout off-thread.
				// FIXME wait asynchronously.
				
				final InsertTag tag = thisTag;
				final PeerNode waitingFor = next;
				final short htl = this.htl;
				
				Runnable r = new Runnable() {

					@Override
					public void run() {
						// We do not need to unlock the tag here.
						// That will happen in the BackgroundTransfer, which has already started.
						
						// FIXME factor out
				        int searchTimeout = calculateTimeout(htl);
		                MessageFilter mfInsertReply = MessageFilter.create().setSource(waitingFor).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPInsertReply);
		                MessageFilter mfRejectedOverload = MessageFilter.create().setSource(waitingFor).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPRejectedOverload);
		                MessageFilter mfRouteNotFound = MessageFilter.create().setSource(waitingFor).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPRouteNotFound);
		                MessageFilter mfDataInsertRejected = MessageFilter.create().setSource(waitingFor).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPDataInsertRejected);
		                MessageFilter mfTimeout = MessageFilter.create().setSource(waitingFor).setField(DMT.UID, uid).setTimeout(searchTimeout).setType(DMT.FNPRejectedTimeout);
		                
		                MessageFilter mf = mfInsertReply.or(mfRouteNotFound.or(mfDataInsertRejected.or(mfTimeout.or(mfRejectedOverload))));

			            while (true) {
			            	
			            	Message msg;

			    			if(failIfReceiveFailed(tag, waitingFor)) {
			    				transfer.onCompleted();
			    				return;
			    			}
							
							try {
								msg = node.usm.waitFor(mf, CHKInsertSender.this);
							} catch (DisconnectedException e) {
								Logger.normal(this, "Disconnected from " + waitingFor
										+ " while waiting for InsertReply on " + CHKInsertSender.this);
								transfer.onDisconnect(waitingFor);
								return;
							}
							
			    			if(failIfReceiveFailed(tag, waitingFor)) {
			    				transfer.onCompleted();
			    				return;
			    			}
							
							if(msg == null) {
								// Second timeout.
								// Definitely caused by the next node, fatal.
								Logger.error(this, "Got second (local) timeout on "+CHKInsertSender.this+" from "+waitingFor);
			    				transfer.onCompleted();
								waitingFor.fatalTimeout();
								return;
							}
							
							if (msg.getSpec() == DMT.FNPRejectedTimeout) {
								// Next node timed out awaiting our DataInsert.
								// But we already sent it, so something is wrong. :(
								handleRejectedTimeout(msg, waitingFor);
								transfer.kill();
								return;
							}

							if (msg.getSpec() == DMT.FNPRejectedOverload) {
								if(handleRejectedOverload(msg, waitingFor)) {
									// Already set the status, and handle... will have unlocked the next node, so no need to call finished().
									transfer.onCompleted();
									return; // Don't try another node.
								}
								else continue;
							}

							if (msg.getSpec() == DMT.FNPRouteNotFound) {
								transfer.onCompleted();
								return; // Don't try another node.
							}
							
							if (msg.getSpec() == DMT.FNPDataInsertRejected) {
								handleDataInsertRejected(msg, waitingFor);
								transfer.kill();
								return; // Don't try another node.
							}
							
							if (msg.getSpec() != DMT.FNPInsertReply) {
								Logger.error(this, "Unknown reply: " + msg);
								transfer.onCompleted();
								return;
							} else {
								// Our task is complete, one node (quite deep), has accepted the insert.
								// The request will not be routed to any other nodes, this is where the data *should* be.
								// We will removeRoutingTo() after the node has sent the transfer completion notice, which never happens before the InsertReply.
								transfer.onCompleted();
								return;
							}
			            }
					}
					
				};
				
				// Wait for the timeout off-thread.
				node.executor.execute(r);
				// Meanwhile, finish() to update allTransfersCompleted and hence allow the CHKInsertHandler to send the message downstream.
				// We have already set the status code, this is necessary in order to avoid race conditions.
				// However since it is set to TIMED_OUT, we are allowed to set it again.
				finish(TIMED_OUT, next);
				return;
			}

			if (msg.getSpec() == DMT.FNPRejectedTimeout) {
				// Next node timed out awaiting our DataInsert.
				// But we already sent it, so something is wrong. :(
				transfer.kill();
				handleRejectedTimeout(msg, next);
				return;
			}

			if (msg.getSpec() == DMT.FNPRejectedOverload) {
				if(handleRejectedOverload(msg, next)) {
					// We have had an Accepted. This happens on a timeout downstream.
					// They will complete it (finish()), so we need to wait for a transfer completion.
					// FIXME it might be less confusing and therefore less likely to cause problems
					// if we had a different message sent post-accept???
					transfer.onCompleted();
					break;
				}
				else continue;
			}

			if (msg.getSpec() == DMT.FNPRouteNotFound) {
				//RNF means that the HTL was not exhausted, but that the data will still be stored.
				handleRNF(msg, next);
				transfer.onCompleted();
				break;
			}

			//Can occur after reception of the entire chk block
			if (msg.getSpec() == DMT.FNPDataInsertRejected) {
				handleDataInsertRejected(msg, next);
				transfer.kill();
				break;
			}
			
			if (msg.getSpec() != DMT.FNPInsertReply) {
				Logger.error(this, "Unknown reply: " + msg);
				transfer.onCompleted();
				finish(INTERNAL_ERROR, next);
				return;
			} else {
				transfer.onCompleted();
				// Our task is complete, one node (quite deep), has accepted the insert.
				// The request will not be routed to any other nodes, this is where the data *should* be.
				// We will removeRoutingTo() after the node has sent the transfer completion notice, which never happens before the InsertReply.
				finish(SUCCESS, next);
				return;
			}
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
