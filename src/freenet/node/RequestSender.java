/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.util.ArrayList;

import freenet.crypt.CryptFormatException;
import freenet.crypt.DSAPublicKey;
import freenet.io.comm.AsyncMessageCallback;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.Message;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.PeerContext;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.io.comm.RetrievalException;
import freenet.io.comm.SlowAsyncMessageFilterCallback;
import freenet.io.xfer.BlockReceiver;
import freenet.io.xfer.BlockReceiver.BlockReceiverCompletion;
import freenet.io.xfer.BlockReceiver.BlockReceiverTimeoutHandler;
import freenet.io.xfer.PartiallyReceivedBlock;
import freenet.keys.CHKBlock;
import freenet.keys.Key;
import freenet.keys.KeyVerifyException;
import freenet.keys.NodeCHK;
import freenet.keys.NodeSSK;
import freenet.keys.SSKBlock;
import freenet.keys.SSKVerifyException;
import freenet.node.FailureTable.BlockOffer;
import freenet.node.FailureTable.OfferList;
import freenet.node.OpennetManager.ConnectionType;
import freenet.node.OpennetManager.WaitedTooLongForOpennetNoderefException;
import freenet.store.KeyCollisionException;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.ShortBuffer;
import freenet.support.SimpleFieldSet;
import freenet.support.TimeUtil;
import freenet.support.io.NativeThread;
import freenet.support.math.MedianMeanRunningAverage;

/**
 * @author amphibian
 * 
 * Sends a request out onto the network, and deals with the 
 * consequences. Other half of the request functionality is provided
 * by RequestHandler.
 * 
 * Must put self onto node's list of senders on creation, and remove
 * self from it on destruction. Must put self onto node's list of
 * transferring senders when starts transferring, and remove from it
 * when finishes transferring.
 */
public final class RequestSender extends BaseSender implements PrioRunnable {

    // Constants
    static final long ACCEPTED_TIMEOUT = SECONDS.toMillis(10);
    // After a get offered key fails, wait this long for two stage timeout. Probably we will
    // have disconnected by then.
    static final long GET_OFFER_LONG_TIMEOUT = SECONDS.toMillis(60);
    final long getOfferedTimeout;
    /** Wait up to this long to get a path folding reply */
    static final long OPENNET_TIMEOUT = MINUTES.toMillis(2);
    /** One in this many successful requests is randomly reinserted.
     * This is probably a good idea anyway but with the split store it's essential. */
    static final int RANDOM_REINSERT_INTERVAL = 200;
    
    // Basics
    final RequestTag origTag;
    private PartiallyReceivedBlock prb;
    private byte[] finalHeaders;
    private byte[] finalSskData;
    private DSAPublicKey pubKey;
    private SSKBlock block;
    private PeerNode transferringFrom;
    private boolean reassignedToSelfDueToMultipleTimeouts;
    private final boolean canWriteClientCache;
    private final boolean canWriteDatastore;
    
    /** If true, only try to fetch the key from nodes which have offered it */
    private boolean tryOffersOnly;
    
	private final ArrayList<RequestSenderListener> listeners=new ArrayList<RequestSenderListener>();
	
    // Terminal status
    // Always set finished AFTER setting the reason flag

    private int status = -1;
    static final int NOT_FINISHED = -1;
    static final int SUCCESS = 0;
    static final int ROUTE_NOT_FOUND = 1;
    static final int DATA_NOT_FOUND = 3;
    static final int TRANSFER_FAILED = 4;
    static final int VERIFY_FAILURE = 5;
    static final int TIMED_OUT = 6;
    static final int GENERATED_REJECTED_OVERLOAD = 7;
    static final int INTERNAL_ERROR = 8;
    static final int RECENTLY_FAILED = 9;
    static final int GET_OFFER_VERIFY_FAILURE = 10;
    static final int GET_OFFER_TRANSFER_FAILED = 11;
    private PeerNode successFrom;
    
    static String getStatusString(int status) {
    	switch(status) {
    	case NOT_FINISHED:
    		return "NOT FINISHED";
    	case SUCCESS:
    		return "SUCCESS";
    	case ROUTE_NOT_FOUND:
    		return "ROUTE NOT FOUND";
    	case DATA_NOT_FOUND:
    		return "DATA NOT FOUND";
    	case TRANSFER_FAILED:
    		return "TRANSFER FAILED";
    	case GET_OFFER_TRANSFER_FAILED:
    		return "GET OFFER TRANSFER FAILED";
    	case VERIFY_FAILURE:
    		return "VERIFY FAILURE";
    	case GET_OFFER_VERIFY_FAILURE:
    		return "GET OFFER VERIFY FAILURE";
    	case TIMED_OUT:
    		return "TIMED OUT";
    	case GENERATED_REJECTED_OVERLOAD:
    		return "GENERATED REJECTED OVERLOAD";
    	case INTERNAL_ERROR:
    		return "INTERNAL ERROR";
    	case RECENTLY_FAILED:
    		return "RECENTLY FAILED";
    	default:
    		return "UNKNOWN STATUS CODE: "+status;
    	}
    }
    
    String getStatusString() {
    	return getStatusString(getStatus());
    }
    
    private static volatile boolean logMINOR;
    static {
	Logger.registerLogThresholdCallback(new LogThresholdCallback(){
		@Override
		public void shouldUpdate(){
			logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		}
	});
    }
    
    @Override
	public String toString() {
        return super.toString()+" for "+uid;
    }

    /**
     * RequestSender constructor.
     * @param key The key to request. Its public key should have been looked up
     * already; RequestSender will not look it up.
     * @param realTimeFlag If enabled,  
     */
    public RequestSender(Key key, DSAPublicKey pubKey, short htl, long uid, RequestTag tag, Node n,
            PeerNode source, boolean offersOnly, boolean canWriteClientCache, boolean canWriteDatastore, boolean realTimeFlag) {
    	super(key, realTimeFlag, source, n, htl, uid);
    	if(realTimeFlag) {
    		getOfferedTimeout = BlockReceiver.RECEIPT_TIMEOUT_REALTIME;
    	} else {
    		getOfferedTimeout = BlockReceiver.RECEIPT_TIMEOUT_BULK;
    	}
        this.pubKey = pubKey;
        this.origTag = tag;
        this.tryOffersOnly = offersOnly;
        this.canWriteClientCache = canWriteClientCache;
        this.canWriteDatastore = canWriteDatastore;
    }

    public void start() {
    	node.executor.execute(this, "RequestSender for UID "+uid+" on "+node.getDarknetPortNumber());
    }
    
    @Override
    public void run() {
    	node.getTicker().queueTimedJob(new Runnable() {
    		
    		@Override
    		public void run() {
    			// Because we can reroute, and we apply the same timeout for each peer,
    			// it is possible for us to exceed the timeout. In which case the downstream
				// node will get impatient. So we need to reassign to self when this happens,
				// so that we don't ourselves get blamed.
				
    			boolean fromOfferedKey;
    			
				synchronized(RequestSender.this) {
					if(status != NOT_FINISHED) return;
					if(transferringFrom != null) return;
					reassignedToSelfDueToMultipleTimeouts = true;
					fromOfferedKey = (routeAttempts == 0);
				}
				
				// We are still routing, yet we have exceeded the per-peer timeout, probably due to routing to multiple nodes e.g. RNFs and accepted timeouts.
				Logger.normal(this, "Reassigning to self on timeout: "+RequestSender.this);
				
				reassignToSelfOnTimeout(fromOfferedKey);
			}
    		
    	}, incomingSearchTimeout);
        try {
        	realRun();
        } catch (Throwable t) {
            Logger.error(this, "Caught "+t, t);
            finish(INTERNAL_ERROR, null, false);
        } finally {
        	// LOCKING: Normally receivingAsync is set by this thread, so there is no need to synchronize.
        	// If it is set by another thread it will only be after it was set by this thread.
        	if(status == NOT_FINISHED && !receivingAsync) {
        		Logger.error(this, "Not finished: "+this);
        		finish(INTERNAL_ERROR, null, false);
        	}
        	if(logMINOR) Logger.minor(this, "Leaving RequestSender.run() for "+uid);
        }
    }

	static final int MAX_HIGH_HTL_FAILURES = 5;
	
    private void realRun() {
	    freenet.support.Logger.OSThread.logPID(this);
        if(isSSK && (pubKey == null)) {
        	pubKey = ((NodeSSK)key).getPubKey();
        }
        
        // First ask any nodes that have offered the data
        
        final OfferList offers = node.failureTable.getOffers(key);
        
        if(offers != null)
        	tryOffers(offers, null, null);
        else
        	startRequests();
    }
    
    private void startRequests() {
        if(tryOffersOnly) {
        	if(logMINOR) Logger.minor(this, "Tried all offers, not doing a regular request for key");
        	finish(DATA_NOT_FOUND, null, true); // FIXME need a different error code?
        	return;
        }
        
		routeAttempts=0;
		starting = true;
        // While in no-cache mode, we don't decrement HTL on a RejectedLoop or similar, but we only allow a limited number of such failures before RNFing.
		highHTLFailureCount = 0;
        routeRequests();
	}

    private boolean starting;
    private int highHTLFailureCount = 0;
    private boolean killedByRecentlyFailed = false;
    
    /** Route requests. Method is responsible for its own completion, e.g. finish
     * or chaining to MainLoopCallback, i.e. the caller isn't going to do more 
     * stuff relevant to the request afterwards. */
    protected void routeRequests() {
    	
    	if(logMINOR) Logger.minor(this, "Routing requests on "+this, new Exception("debug"));
    	
    	PeerNode next = null;
    	
        while(true) {
            boolean canWriteStorePrev = node.canWriteDatastoreInsert(htl);
            if(dontDecrementHTLThisTime) {
            	// NLM needs us to reroute.
            	dontDecrementHTLThisTime = false;
            } else {
            	// FIXME SECURITY/NETWORK: Should we never decrement on the originator?
            	// It would buy us another hop of no-cache, making it significantly
            	// harder to trace after the fact; however it would make local 
            	// requests fractionally easier to detect by peers.
            	// IMHO local requests are so easy for peers to detect anyway that
            	// it's probably worth it.
            	// Currently the worst case is we don't cache on the originator
            	// and we don't cache on the first peer we route to. If we get
            	// RejectedOverload's etc we won't cache on them either, up to 5;
            	// but lets assume that one of them accepts, and routes onward;
            	// the *second* hop out (with the originator being 0) WILL cache.
            	// Note also that changing this will have a performance impact.
            	if((!starting) && (!canWriteStorePrev)) {
            		// We always decrement on starting a sender.
            		// However, after that, if our HTL is above the no-cache threshold,
            		// we do not want to decrement the HTL for trivial rejections (e.g. RejectedLoop),
            		// because we would end up caching data too close to the originator.
            		// So allow 5 failures and then RNF.
            		if(highHTLFailureCount++ >= MAX_HIGH_HTL_FAILURES) {
            			if(logMINOR) Logger.minor(this, "Too many failures at non-cacheable HTL");
            			finish(ROUTE_NOT_FOUND, null, false);
            			return;
            		}
            		if(logMINOR) Logger.minor(this, "Allowing failure "+highHTLFailureCount+" htl is still "+htl);
            	} else {
            		/*
            		 * If we haven't routed to any node yet, decrement according to the source.
            		 * If we have, decrement according to the node which just failed.
            		 * Because:
            		 * 1) If we always decrement according to source then we can be at max or min HTL
            		 * for a long time while we visit *every* peer node. This is BAD!
            		 * 2) The node which just failed can be seen as the requestor for our purposes.
            		 */
            		// Decrement at this point so we can DNF immediately on reaching HTL 0.
            		htl = node.decrementHTL((hasForwarded ? next : source), htl);
            		if(logMINOR) Logger.minor(this, "Decremented HTL to "+htl);
            	}
            }
            starting = false;

            if(logMINOR) Logger.minor(this, "htl="+htl);
            if(htl <= 0) {
            	// This used to be RNF, I dunno why
				//???: finish(GENERATED_REJECTED_OVERLOAD, null);
                node.failureTable.onFinalFailure(key, null, htl, origHTL, FailureTable.RECENTLY_FAILED_TIME, FailureTable.REJECT_TIME, source);
                finish(DATA_NOT_FOUND, null, false);
                return;
            }
            
            // If we are unable to reply in a reasonable time, and we haven't started a 
            // transfer, we should not route further. There are other cases e.g. we 
            // reassign to self (due to external timeout) while waiting for the data, then
            // get a transfer without timing out on the node. In that case we will get the
            // data, but just for ourselves.
            boolean failed;
            synchronized(this) {
            	failed = reassignedToSelfDueToMultipleTimeouts;
            	if(!failed) routeAttempts++;
            }
            if(failed) {
            	finish(TIMED_OUT, null, false);
            	return;
            }
            
        	if(origTag.shouldStop()) {
        		finish(ROUTE_NOT_FOUND, null, false);
        		return;
        	}
        	
            RecentlyFailedReturn r = new RecentlyFailedReturn();
            
            long now = System.currentTimeMillis();
            
            // Route it
            next = node.peers.closerPeer(source, nodesRoutedTo, target, true, node.isAdvancedModeEnabled(), -1, null,
			        2.0, key, htl, 0, source == null, realTimeFlag, r, false, now, newLoadManagement);
            
            long recentlyFailed = r.recentlyFailed();
            if(recentlyFailed > now) {
            	synchronized(this) {
            		recentlyFailedTimeLeft = (int)Math.min(Integer.MAX_VALUE, recentlyFailed - now);
            	}
            	finish(RECENTLY_FAILED, null, false);
                node.failureTable.onFinalFailure(key, null, htl, origHTL, -1, -1, source);
            	return;
            } else {
            	boolean rfAnyway = false;
            	synchronized(this) {
            		rfAnyway = killedByRecentlyFailed;
            	}
            	if(rfAnyway) {
            		// We got a RecentlyFailed so we have to send one.
            		// But we set a timeout of 0 because we're not generating one based on where we've routed the key to.
            		// Returning the time we were passed minus some value will give the next node an inaccurate high timeout.
            		// Rerouting (even assuming we change FNPRecentlyFailed to include a hop count) would also cause problems because nothing would be quenched until we have visited every node on the network.
            		// That leaves forwarding a RecentlyFailed which won't create further RecentlyFailed's.
            		// However the peer will still avoid sending us the same key for 10 minutes due to per-node failure tables. This is fine, we probably don't have it anyway!
            		synchronized(this) {
            			recentlyFailedTimeLeft = 0;
            		}
                	finish(RECENTLY_FAILED, null, false);
                    node.failureTable.onFinalFailure(key, null, htl, origHTL, -1, -1, source);
                	return;
            	}
            }
            
            if(next == null) {
				if (logMINOR && rejectOverloads>0)
					Logger.minor(this, "no more peers, but overloads ("+rejectOverloads+"/"+routeAttempts+" overloaded)");
                // Backtrack
                finish(ROUTE_NOT_FOUND, null, false);
                node.failureTable.onFinalFailure(key, null, htl, origHTL, -1, -1, source);
                return;
            }
            
            innerRouteRequests(next, origTag);
            // Will either chain back to routeRequests(), or call onAccepted().
           	return;
        }
	}

	private synchronized long timeSinceSentForTimeout() {
    	int time = timeSinceSent();
    	if(time > FailureTable.REJECT_TIME) {
    		if(time < searchTimeout + SECONDS.toMillis(10)) return FailureTable.REJECT_TIME;
    		Logger.error(this, "Very long time since sent: "+time+" ("+TimeUtil.formatTime(time, 2, true)+")");
    		return FailureTable.REJECT_TIME;
    	}
    	return time;
    }
    
    private class MainLoopCallback implements SlowAsyncMessageFilterCallback {
    	
    	// Needs to be a separate class so it can check whether the main loop has moved on to another peer.
    	// If it has
    	
    	private final PeerNode waitingFor;
    	private final boolean noReroute;
    	private final long deadline;
		public byte[] sskData;
		public byte[] headers;
		final long searchTimeout;

		public MainLoopCallback(PeerNode source, boolean noReroute, long searchTimeout) {
			waitingFor = source;
			this.noReroute = noReroute;
			this.searchTimeout = searchTimeout;
			deadline = System.currentTimeMillis() + searchTimeout;
		}

		@Override
		public void onMatched(Message msg) {
			
			assert(waitingFor == msg.getSource());
			
        	DO action = handleMessage(msg, noReroute, waitingFor, this);
        	
        	if(action == DO.FINISHED)
        		return;
        	else if(action == DO.NEXT_PEER) {
        		if(!noReroute) {
        			// Try another peer
        			routeRequests();
        		}
        	} else /*if(action == DO.WAIT)*/ {
        		// Try again.
        		schedule();
        	}
		}
		
		public void schedule() {
        	long now = System.currentTimeMillis();
        	int timeout = (int)(Math.min(Integer.MAX_VALUE, deadline - now));
        	if(timeout >= 0) {
        		MessageFilter mf = createMessageFilter(timeout, waitingFor);
        		try {
        			node.usm.addAsyncFilter(mf, this, RequestSender.this);
        		} catch (DisconnectedException e) {
        			onDisconnect(lastNode);
        		}
        	} else {
        		onTimeout();
        	}
		}

		@Override
		public boolean shouldTimeout() {
			if(noReroute) return false;
			return false;
		}

		@Override
		public void onTimeout() {
			// This is probably a downstream timeout.
			// It's not a serious problem until we have a second (fatal) timeout.
			Logger.warning(this, "Timed out after waiting "+searchTimeout+" on "+uid+" from "+waitingFor+" ("+gotMessages+" messages; last="+lastMessage+") for "+uid+" noReroute="+noReroute);
			if(noReroute) {
				waitingFor.localRejectedOverload("FatalTimeoutForked", realTimeFlag);
			} else {
				// Fatal timeout
				waitingFor.localRejectedOverload("FatalTimeout", realTimeFlag);
				forwardRejectedOverload();
				node.failureTable.onFinalFailure(key, waitingFor, htl, origHTL, FailureTable.RECENTLY_FAILED_TIME, FailureTable.REJECT_TIME, source);
				finish(TIMED_OUT, waitingFor, false);
			}
    		
			// Wait for second timeout.
    		// FIXME make this async.
    		long deadline = System.currentTimeMillis() + searchTimeout;
			while(true) {
				
				Message msg;
				try {
		        	int timeout = (int)(Math.min(Integer.MAX_VALUE, deadline - System.currentTimeMillis()));
					msg = node.usm.waitFor(createMessageFilter(timeout, waitingFor), RequestSender.this);
				} catch (DisconnectedException e) {
					Logger.normal(this, "Disconnected from " + waitingFor
							+ " while waiting for reply on " + this);
					waitingFor.noLongerRoutingTo(origTag, false);
					return;
				}
				
				if(msg == null) {
					// Second timeout.
					Logger.error(this, "Fatal timeout waiting for reply after Accepted on "+this+" from "+waitingFor);
					waitingFor.fatalTimeout(origTag, false);
					return;
				}
				
				DO action = handleMessage(msg, noReroute, waitingFor, this);
				
				if(action == DO.FINISHED)
					return;
				else if(action == DO.NEXT_PEER) {
					waitingFor.noLongerRoutingTo(origTag, false);
					return; // Don't try others
				}
				// else if(action == DO.WAIT) continue;
			}
		}

		@Override
		public void onDisconnect(PeerContext ctx) {
			Logger.normal(this, "Disconnected from "+waitingFor+" while waiting for data on "+uid);
			waitingFor.noLongerRoutingTo(origTag, false);
			if(noReroute) return;
			// Try another peer.
			routeRequests();
		}

		@Override
		public void onRestarted(PeerContext ctx) {
			onDisconnect(ctx);
		}

		@Override
		public int getPriority() {
			return NativeThread.NORM_PRIORITY;
		}
		
		@Override
		public String toString() {
			return super.toString()+":"+waitingFor+":"+noReroute+":"+RequestSender.this;
		}
    	
    };
    
    enum OFFER_STATUS {
    	FETCHING, // Fetching asynchronously or already fetched.
    	TWO_STAGE_TIMEOUT, // Waiting asynchronously for two stage timeout; remove the offer, but don't unlock the tag.
    	FATAL, // Fatal error, fail the whole request.
    	TRY_ANOTHER, // Delete the offer and move on.
    	KEEP // Keep the offer and move on.
    }
    
	/** Tries offers. If we succeed or fatally fail, end the request. If an offer is being
	 * transferred asynchronously, set the receivingAsync flag and return. Otherwise we 
	 * have run out of offers without succeeding, so chain to startRequests(). 
	 * @param pn If this and status are non-null, we have just tried an offer, and these
	 * two contain its status. This should be handled before we try to do any more. */
    private void tryOffers(final OfferList offers, PeerNode pn, OFFER_STATUS status) {
        while(true) {
        	if(pn == null) {
        		// Fetches valid offers, then expired ones. Expired offers don't count towards failures,
        		// but they're still worth trying.
        		BlockOffer offer = offers.getFirstOffer();
        		if(offer == null) {
        			if(logMINOR) Logger.minor(this, "No more offers");
        			startRequests();
        			return;
        		}
        		pn = offer.getPeerNode();
        		status = tryOffer(offer, pn, offers);
        	}
			switch(status) {
			case FATAL:
				offers.deleteLastOffer();
				pn.noLongerRoutingTo(origTag, true);
				return;
			case TWO_STAGE_TIMEOUT:
				offers.deleteLastOffer();
				break;
			case FETCHING:
				return;
			case KEEP:
				offers.keepLastOffer();
				pn.noLongerRoutingTo(origTag, true);
				break;
			case TRY_ANOTHER:
				offers.deleteLastOffer();
				pn.noLongerRoutingTo(origTag, true);
				break;
			}
			pn = null;
			status = null;
        }
    }

    private OFFER_STATUS tryOffer(final BlockOffer offer, final PeerNode pn, final OfferList offers) {
    	if(pn == null) return OFFER_STATUS.TRY_ANOTHER;
    	if(pn.getBootID() != offer.bootID) return OFFER_STATUS.TRY_ANOTHER;
    	origTag.addRoutedTo(pn, true);
    	Message msg = DMT.createFNPGetOfferedKey(key, offer.authenticator, pubKey == null, uid);
    	msg.addSubMessage(DMT.createFNPRealTimeFlag(realTimeFlag));
    	try {
    		pn.sendSync(msg, this, realTimeFlag);
		} catch (NotConnectedException e2) {
			if(logMINOR)
				Logger.minor(this, "Disconnected: "+pn+" getting offer for "+key);
    		return OFFER_STATUS.TRY_ANOTHER;
		} catch (SyncSendWaitedTooLongException e) {
			if(logMINOR)
				Logger.minor(this, "Took too long sending offer get to "+pn+" for "+key);
    		return OFFER_STATUS.TRY_ANOTHER;
		}
    	// Wait asynchronously for a response.
		synchronized(this) {
			receivingAsync = true;
		}
		try {
			node.usm.addAsyncFilter(getOfferedKeyReplyFilter(pn, getOfferedTimeout), new SlowAsyncMessageFilterCallback() {
				
				@Override
				public void onMatched(Message m) {
					OFFER_STATUS status =
						isSSK ? handleSSKOfferReply(m, pn, offer) :
							handleCHKOfferReply(m, pn, offer, offers);
					tryOffers(offers, pn, status);
				}
				
				@Override
				public boolean shouldTimeout() {
					return false;
				}
				
				@Override
				public void onTimeout() {
					Logger.warning(this, "Timeout awaiting reply to offer request on "+this+" to "+pn);
					// Two stage timeout.
					OFFER_STATUS status = handleOfferTimeout(offer, pn, offers);
					tryOffers(offers, pn, status);
				}
				
				@Override
				public void onDisconnect(PeerContext ctx) {
					if(logMINOR)
						Logger.minor(this, "Disconnected: "+pn+" getting offer for "+key);
					tryOffers(offers, pn, OFFER_STATUS.TRY_ANOTHER);
				}
				
				@Override
				public void onRestarted(PeerContext ctx) {
					if(logMINOR)
						Logger.minor(this, "Disconnected: "+pn+" getting offer for "+key);
					tryOffers(offers, pn, OFFER_STATUS.TRY_ANOTHER);
				}
				
				@Override
				public int getPriority() {
					return NativeThread.HIGH_PRIORITY;
				}
				
			}, this);
			return OFFER_STATUS.FETCHING;
		} catch (DisconnectedException e) {
			if(logMINOR)
				Logger.minor(this, "Disconnected: "+pn+" getting offer for "+key);
			return OFFER_STATUS.TRY_ANOTHER;
		}
	}

	private MessageFilter getOfferedKeyReplyFilter(final PeerNode pn, long timeout) {
    	MessageFilter mfRO = MessageFilter.create().setSource(pn).setField(DMT.UID, uid).setTimeout(timeout).setType(DMT.FNPRejectedOverload);
    	MessageFilter mfGetInvalid = MessageFilter.create().setSource(pn).setField(DMT.UID, uid).setTimeout(timeout).setType(DMT.FNPGetOfferedKeyInvalid);
    	if(isSSK) {
    		MessageFilter mfAltDF = MessageFilter.create().setSource(pn).setField(DMT.UID, uid).setTimeout(timeout).setType(DMT.FNPSSKDataFoundHeaders);
    		return mfAltDF.or(mfRO.or(mfGetInvalid));
    	} else {
    		MessageFilter mfDF = MessageFilter.create().setSource(pn).setField(DMT.UID, uid).setTimeout(timeout).setType(DMT.FNPCHKDataFound);
    		return mfDF.or(mfRO.or(mfGetInvalid));
    	}
	}

	private OFFER_STATUS handleOfferTimeout(final BlockOffer offer, final PeerNode pn,
			OfferList offers) {
		try {
			node.usm.addAsyncFilter(getOfferedKeyReplyFilter(pn, GET_OFFER_LONG_TIMEOUT), new SlowAsyncMessageFilterCallback() {
				
				@Override
				public void onMatched(Message m) {
					OFFER_STATUS status = 
						isSSK ? handleSSKOfferReply(m, pn, offer) :
							handleCHKOfferReply(m, pn, offer, null);
						if(status != OFFER_STATUS.FETCHING)
							pn.noLongerRoutingTo(origTag, true);
						// If FETCHING, the block transfer will unlock it.
						if(logMINOR) Logger.minor(this, "Forked get offered key due to two stage timeout completed with status "+status+" from message "+m+" for "+RequestSender.this+" to "+pn);
				}
				
				@Override
				public boolean shouldTimeout() {
					return false;
				}
				
				@Override
				public void onTimeout() {
					Logger.error(this, "Fatal timeout getting offered key from "+pn+" for "+RequestSender.this);
					pn.fatalTimeout(origTag, true);
				}
				
				@Override
				public void onDisconnect(PeerContext ctx) {
					// Ok.
					pn.noLongerRoutingTo(origTag, true);
				}
				
				@Override
				public void onRestarted(PeerContext ctx) {
					// Ok.
					pn.noLongerRoutingTo(origTag, true);
				}
				
				@Override
				public int getPriority() {
					return NativeThread.HIGH_PRIORITY;
				}
				
			}, this);
			return OFFER_STATUS.TWO_STAGE_TIMEOUT;
		} catch (DisconnectedException e) {
			// Okay.
			if(logMINOR)
				Logger.minor(this, "Disconnected (2): "+pn+" getting offer for "+key);
    		return OFFER_STATUS.TRY_ANOTHER;
		}
	}

	private OFFER_STATUS handleSSKOfferReply(Message reply, PeerNode pn,
			BlockOffer offer) {
    	if(reply.getSpec() == DMT.FNPRejectedOverload) {
			// Non-fatal, keep it.
			if(logMINOR)
				Logger.minor(this, "Node "+pn+" rejected FNPGetOfferedKey for "+key+" (expired="+offer.isExpired());
			return OFFER_STATUS.KEEP;
		} else if(reply.getSpec() == DMT.FNPGetOfferedKeyInvalid) {
			// Fatal, delete it.
			if(logMINOR)
				Logger.minor(this, "Node "+pn+" rejected FNPGetOfferedKey as invalid with reason "+reply.getShort(DMT.REASON));
			return OFFER_STATUS.TRY_ANOTHER;
		} else if(reply.getSpec() == DMT.FNPSSKDataFoundHeaders) {
			byte[] headers = ((ShortBuffer) reply.getObject(DMT.BLOCK_HEADERS)).getData();
			// Wait for the data
			MessageFilter mfData = MessageFilter.create().setSource(pn).setField(DMT.UID, uid).setTimeout(getOfferedTimeout).setType(DMT.FNPSSKDataFoundData);
			Message dataMessage;
			try {
				dataMessage = node.usm.waitFor(mfData, this);
			} catch (DisconnectedException e) {
				if(logMINOR)
					Logger.minor(this, "Disconnected: "+pn+" getting data for offer for "+key);
				return OFFER_STATUS.TRY_ANOTHER;
			}
			if(dataMessage == null) {
				Logger.error(this, "Got headers but not data from "+pn+" for offer for "+key+" on "+this);
				return OFFER_STATUS.TRY_ANOTHER;
			}
			byte[] sskData = ((ShortBuffer) dataMessage.getObject(DMT.DATA)).getData();
			if(pubKey == null) {
				MessageFilter mfPK = MessageFilter.create().setSource(pn).setField(DMT.UID, uid).setTimeout(getOfferedTimeout).setType(DMT.FNPSSKPubKey);
				Message pk;
				try {
					pk = node.usm.waitFor(mfPK, this);
				} catch (DisconnectedException e) {
					if(logMINOR)
						Logger.minor(this, "Disconnected: "+pn+" getting pubkey for offer for "+key);
					return OFFER_STATUS.TRY_ANOTHER;
				}
				if(pk == null) {
					Logger.error(this, "Got data but not pubkey from "+pn+" for offer for "+key+" on "+this);
					return OFFER_STATUS.TRY_ANOTHER;
				}
				try {
					pubKey = DSAPublicKey.create(((ShortBuffer)pk.getObject(DMT.PUBKEY_AS_BYTES)).getData());
				} catch (CryptFormatException e) {
					Logger.error(this, "Bogus pubkey from "+pn+" for offer for "+key+" : "+e, e);
					return OFFER_STATUS.TRY_ANOTHER;
				}
				
				try {
					((NodeSSK)key).setPubKey(pubKey);
				} catch (SSKVerifyException e) {
					Logger.error(this, "Bogus SSK data from "+pn+" for offer for "+key+" : "+e, e);
					return OFFER_STATUS.TRY_ANOTHER;
				}
			}
			
			if(finishSSKFromGetOffer(pn, headers, sskData)) {
				if(logMINOR) Logger.minor(this, "Successfully fetched SSK from offer from "+pn+" for "+key);
				return OFFER_STATUS.FETCHING;
			} else {
				return OFFER_STATUS.TRY_ANOTHER;
			}
		} else {
			// Impossible???
			Logger.error(this, "Unexpected reply to get offered key: "+reply);
			return OFFER_STATUS.TRY_ANOTHER;
		}
	}

	/** @return True if we successfully received the offer or failed fatally, or we started
	 * to receive a block transfer asynchronously (in which case receivingAsync will be set,
	 * and if it fails the whole request will fail). False if we should try the next offer 
	 * and/or normal fetches.
	 * @param offers The list of offered keys. Only used if we complete asynchronously.
	 * Null indicates this is a fork due to two stage timeout. 
	 * */
	private OFFER_STATUS handleCHKOfferReply(Message reply, final PeerNode pn, final BlockOffer offer, final OfferList offers) {
		if(reply.getSpec() == DMT.FNPRejectedOverload) {
			// Non-fatal, keep it.
			if(logMINOR)
				Logger.minor(this, "Node "+pn+" rejected FNPGetOfferedKey for "+key+" (expired="+offer.isExpired());
			return OFFER_STATUS.KEEP;
		} else if(reply.getSpec() == DMT.FNPGetOfferedKeyInvalid) {
			// Fatal, delete it.
			if(logMINOR)
				Logger.minor(this, "Node "+pn+" rejected FNPGetOfferedKey as invalid with reason "+reply.getShort(DMT.REASON));
			return OFFER_STATUS.TRY_ANOTHER;
		} else if(reply.getSpec() == DMT.FNPCHKDataFound) {
			finalHeaders = ((ShortBuffer)reply.getObject(DMT.BLOCK_HEADERS)).getData();
			// Receive the data
			
        	// FIXME: Validate headers
        	
			origTag.senderTransferBegins((NodeCHK)key, this);
        	
        	try {
        		
        		prb = new PartiallyReceivedBlock(Node.PACKETS_IN_BLOCK, Node.PACKET_SIZE);
        		
        		// FIXME kill the transfer if off-thread (two stage timeout, offers == null) and it's already completed successfully?
        		// FIXME we are also plotting to get rid of transfer cancels so maybe not?
        		synchronized(this) {
        			transferringFrom = pn;
        			notifyAll();
        		}
        		fireCHKTransferBegins();
				
        		BlockReceiver br = new BlockReceiver(node.usm, pn, uid, prb, this, node.getTicker(), true, realTimeFlag, myTimeoutHandler, true);
        		
       			if(logMINOR) Logger.minor(this, "Receiving data (for offer reply)");
       			receivingAsync = true;
       			br.receive(new BlockReceiverCompletion() {
       				
					@Override
					public void blockReceived(byte[] data) {
        				synchronized(RequestSender.this) {
        					transferringFrom = null;
        				}
        				origTag.senderTransferEnds((NodeCHK)key, RequestSender.this);
                		try {
	                		// Received data
	               			pn.transferSuccess(realTimeFlag);
	                		if(logMINOR) Logger.minor(this, "Received data from offer reply");
                			verifyAndCommit(finalHeaders, data);
	                		finish(SUCCESS, pn, true);
	                		node.nodeStats.successfulBlockReceive(realTimeFlag, source == null);
                		} catch (KeyVerifyException e1) {
                			Logger.normal(this, "Got data but verify failed: "+e1, e1);
                			if(offers != null) {
                				finish(GET_OFFER_VERIFY_FAILURE, pn, true);
                				offers.deleteLastOffer();
                			}
                		} catch (Throwable t) {
                			Logger.error(this, "Failed on "+this, t);
                			if(offers != null) {
                				finish(INTERNAL_ERROR, pn, true);
                			}
                		} finally {
                			// This is only necessary here because we don't always call finish().
                			pn.noLongerRoutingTo(origTag, true);
                		}
					}

					@Override
					public void blockReceiveFailed(
							RetrievalException e) {
        				synchronized(RequestSender.this) {
        					transferringFrom = null;
        				}
        				origTag.senderTransferEnds((NodeCHK)key, RequestSender.this);
						try {
							if (e.getReason()==RetrievalException.SENDER_DISCONNECTED)
								Logger.normal(this, "Transfer failed (disconnect): "+e, e);
							else
								// A certain number of these are normal, it's better to track them through statistics than call attention to them in the logs.
								Logger.normal(this, "Transfer for offer failed ("+e.getReason()+"/"+RetrievalException.getErrString(e.getReason())+"): "+e+" from "+pn, e);
							if(offers != null) {
								finish(GET_OFFER_TRANSFER_FAILED, pn, true);
							}
							// Backoff here anyway - the node really ought to have it!
							pn.transferFailed("RequestSenderGetOfferedTransferFailed", realTimeFlag);
							if(offers != null) {
								offers.deleteLastOffer();
							}
		    				if(!prb.abortedLocally())
		    					node.nodeStats.failedBlockReceive(false, false, realTimeFlag, source == null);
                		} catch (Throwable t) {
                			Logger.error(this, "Failed on "+this, t);
                			if(offers != null) {
                				finish(INTERNAL_ERROR, pn, true);
                			}
                		} finally {
                			// This is only necessary here because we don't always call finish().
                			pn.noLongerRoutingTo(origTag, true);
                		}
					}
        				
        		});
        		return OFFER_STATUS.FETCHING;
        	} finally {
        		origTag.senderTransferEnds((NodeCHK)key, this);
        	}
		} else {
			// Impossible.
			Logger.error(this, "Unexpected reply to get offered key: "+reply);
			return OFFER_STATUS.TRY_ANOTHER;
		}
	}

	@Override
	protected MessageFilter makeAcceptedRejectedFilter(PeerNode next,
			long acceptedTimeout, UIDTag tag) {
		assert(tag == origTag);
		/**
		 * What are we waiting for?
		 * FNPAccepted - continue
		 * FNPRejectedLoop - go to another node
		 * FNPRejectedOverload - propagate back to source, go to another node if local
		 */
		
		MessageFilter mfAccepted = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(acceptedTimeout).setType(DMT.FNPAccepted);
		MessageFilter mfRejectedLoop = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(acceptedTimeout).setType(DMT.FNPRejectedLoop);
		MessageFilter mfRejectedOverload = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(acceptedTimeout).setType(DMT.FNPRejectedOverload);
		
		// mfRejectedOverload must be the last thing in the or
		// So its or pointer remains null
		// Otherwise we need to recreate it below
		return mfAccepted.or(mfRejectedLoop.or(mfRejectedOverload));
	}

	private MessageFilter createMessageFilter(int timeout, PeerNode next) {
		MessageFilter mfDNF = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(timeout).setType(DMT.FNPDataNotFound);
		MessageFilter mfRF = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(timeout).setType(DMT.FNPRecentlyFailed);
		MessageFilter mfRouteNotFound = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(timeout).setType(DMT.FNPRouteNotFound);
		MessageFilter mfRejectedOverload = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(timeout).setType(DMT.FNPRejectedOverload);
		
		MessageFilter mf = mfDNF.or(mfRF.or(mfRouteNotFound.or(mfRejectedOverload)));
		if(!isSSK) {
			MessageFilter mfRealDFCHK = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(timeout).setType(DMT.FNPCHKDataFound);
			mf = mfRealDFCHK.or(mf);
		} else {
			MessageFilter mfPubKey = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(timeout).setType(DMT.FNPSSKPubKey);
			MessageFilter mfDFSSKHeaders = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(timeout).setType(DMT.FNPSSKDataFoundHeaders);
			MessageFilter mfDFSSKData = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(timeout).setType(DMT.FNPSSKDataFoundData);
			mf = mfPubKey.or(mfDFSSKHeaders.or(mfDFSSKData.or(mf)));
		}
		return mf;
	}

	private DO handleMessage(Message msg, boolean wasFork, PeerNode source, MainLoopCallback waiter) {
		//For debugging purposes, remember the number of responses AFTER the insert, and the last message type we received.
		gotMessages++;
		lastMessage=msg.getSpec().getName();
		if(logMINOR) Logger.minor(this, "Handling message "+msg+" on "+this);
    	
    	if(msg.getSpec() == DMT.FNPDataNotFound) {
    		handleDataNotFound(msg, wasFork, source);
    		return DO.FINISHED;
    	}
    	
    	if(msg.getSpec() == DMT.FNPRecentlyFailed) {
    		handleRecentlyFailed(msg, wasFork, source);
    		// We will resolve finish() in routeRequests(), after recomputing.
    		return DO.NEXT_PEER;
    	}
    	
    	if(msg.getSpec() == DMT.FNPRouteNotFound) {
    		handleRouteNotFound(msg, source);
    		return DO.NEXT_PEER;
    	}
    	
    	if(msg.getSpec() == DMT.FNPRejectedOverload) {
    		if(handleRejectedOverload(msg, wasFork, source)) return DO.WAIT;
    		else return DO.FINISHED;
    	}

    	if((!isSSK) && msg.getSpec() == DMT.FNPCHKDataFound) {
    		handleCHKDataFound(msg, wasFork, source, waiter);
    		return DO.FINISHED;
    	}
    	
    	if(isSSK && msg.getSpec() == DMT.FNPSSKPubKey) {
    		
    		if(!handleSSKPubKey(msg, source)) return DO.NEXT_PEER;
			if(waiter.sskData != null && waiter.headers != null) {
				finishSSK(source, wasFork, waiter.headers, waiter.sskData);
				return DO.FINISHED;
			}
			return DO.WAIT;
    	}
    	            	
    	if(isSSK && msg.getSpec() == DMT.FNPSSKDataFoundData) {
    		
    		if(logMINOR) Logger.minor(this, "Got data on "+uid);
    		
        	waiter.sskData = ((ShortBuffer)msg.getObject(DMT.DATA)).getData();
        	
        	if(pubKey != null && waiter.headers != null) {
        		finishSSK(source, wasFork, waiter.headers, waiter.sskData);
        		return DO.FINISHED;
        	}
        	return DO.WAIT;

    	}
    	
    	if(isSSK && msg.getSpec() == DMT.FNPSSKDataFoundHeaders) {
    		
    		if(logMINOR) Logger.minor(this, "Got headers on "+uid);
    		
        	waiter.headers = ((ShortBuffer)msg.getObject(DMT.BLOCK_HEADERS)).getData();
    		
        	if(pubKey != null && waiter.sskData != null) {
        		finishSSK(source, wasFork, waiter.headers, waiter.sskData);
        		return DO.FINISHED;
        	}
        	return DO.WAIT;

    	}
    	
   		Logger.error(this, "Unexpected message: "+msg);
   		int t = timeSinceSent();
   		node.failureTable.onFailed(key, source, htl, t, t);
   		source.noLongerRoutingTo(origTag, false);
   		return DO.NEXT_PEER;
    	
	}
    
    /** @return True unless the pubkey is broken and we should try another node */
    private boolean handleSSKPubKey(Message msg, PeerNode next) {
		if(logMINOR) Logger.minor(this, "Got pubkey on "+uid);
		byte[] pubkeyAsBytes = ((ShortBuffer)msg.getObject(DMT.PUBKEY_AS_BYTES)).getData();
		try {
			if(pubKey == null)
				pubKey = DSAPublicKey.create(pubkeyAsBytes);
			((NodeSSK)key).setPubKey(pubKey);
			return true;
		} catch (SSKVerifyException e) {
			pubKey = null;
			Logger.error(this, "Invalid pubkey from "+source+" on "+uid+" ("+e.getMessage()+ ')', e);
			int t = timeSinceSent();
    		node.failureTable.onFailed(key, next, htl, t, t);
    		next.noLongerRoutingTo(origTag, false);
			return false; // try next node
		} catch (CryptFormatException e) {
			Logger.error(this, "Invalid pubkey from "+source+" on "+uid+" ("+e+ ')');
			int t = timeSinceSent();
    		node.failureTable.onFailed(key, next, htl, t, t);
    		next.noLongerRoutingTo(origTag, false);
			return false; // try next node
		}
	}

	private void handleCHKDataFound(Message msg, final boolean wasFork, final PeerNode next, final MainLoopCallback waiter) {
    	// Found data
    	
    	// First get headers
    	
    	waiter.headers = ((ShortBuffer)msg.getObject(DMT.BLOCK_HEADERS)).getData();
    	
    	// FIXME: Validate headers
    	
    	if(!wasFork)
    		origTag.senderTransferBegins((NodeCHK)key, this);
    	
    	final PartiallyReceivedBlock prb = new PartiallyReceivedBlock(Node.PACKETS_IN_BLOCK, Node.PACKET_SIZE);
    	
    	boolean failNow = false;
    	
    	synchronized(this) {
        	finalHeaders = waiter.headers;
    		if(this.status == SUCCESS || this.prb != null && transferringFrom != null)
    			failNow = true;
    		if((!wasFork) && (this.prb == null || !this.prb.allReceivedAndNotAborted())) 
    			this.prb = prb;
    		notifyAll();
    	}
    	if(!wasFork)
    		// Don't fire transfer begins on a fork since we have not set headers or prb.
    		// If we find the data we will offer it to the requester.
    		fireCHKTransferBegins();
    	
    	final long tStart = System.currentTimeMillis();
    	final BlockReceiver br = new BlockReceiver(node.usm, next, uid, prb, this, node.getTicker(), true, realTimeFlag, myTimeoutHandler, true);
    	
    	if(failNow) {
    		if(logMINOR) Logger.minor(this, "Terminating forked transfer on "+this+" from "+next);
    		prb.abort(RetrievalException.CANCELLED_BY_RECEIVER, "Cancelling fork", true);
    		br.receive(new BlockReceiverCompletion() {

				@Override
				public void blockReceived(byte[] buf) {
    				if(!wasFork)
    					origTag.senderTransferEnds((NodeCHK)key, RequestSender.this);
					next.noLongerRoutingTo(origTag, false);
				}

				@Override
				public void blockReceiveFailed(RetrievalException e) {
    				if(!wasFork)
    					origTag.senderTransferEnds((NodeCHK)key, RequestSender.this);
					next.noLongerRoutingTo(origTag, false);
				}
    			
    		});
    		return;
    	}
    	
    	if(logMINOR) Logger.minor(this, "Receiving data");
    	if(!wasFork) {
    		synchronized(this) {
    			transferringFrom = next;
    		}
    	} else
        	if(logMINOR) Logger.minor(this, "Receiving data from fork");
    	
    	receivingAsync = true;
    	br.receive(new BlockReceiverCompletion() {
    		
    		@Override
    		public void blockReceived(byte[] data) {
    			try {
    				long tEnd = System.currentTimeMillis();
    				transferTime = tEnd - tStart;
    				boolean haveSetPRB = false;
    				synchronized(RequestSender.this) {
    					transferringFrom = null;
    					if(RequestSender.this.prb == null || !RequestSender.this.prb.allReceivedAndNotAborted()) {
    						RequestSender.this.prb = prb;
    						haveSetPRB = true;
    					}
    				}
    				if(!wasFork)
    					origTag.senderTransferEnds((NodeCHK)key, RequestSender.this);
   					next.transferSuccess(realTimeFlag);
    				next.successNotOverload(realTimeFlag);
   					node.nodeStats.successfulBlockReceive(realTimeFlag, source == null);
    				if(logMINOR) Logger.minor(this, "Received data");
    				// Received data
    				try {
    					verifyAndCommit(waiter.headers, data);
    					if(logMINOR) Logger.minor(this, "Written to store");
    				} catch (KeyVerifyException e1) {
    					Logger.normal(this, "Got data but verify failed: "+e1, e1);
    					node.failureTable.onFinalFailure(key, next, htl, origHTL, FailureTable.RECENTLY_FAILED_TIME, FailureTable.REJECT_TIME, source);
    					if(!wasFork)
    						finish(VERIFY_FAILURE, next, false);
    					else
    						next.noLongerRoutingTo(origTag, false);
    					return;
    				}
    				if(haveSetPRB) // It was a fork, so we didn't immediately send the data.
    					fireCHKTransferBegins();
    				finish(SUCCESS, next, false);
    			} catch (Throwable t) {
        			Logger.error(this, "Failed on "+this, t);
        			if(!wasFork)
        				finish(INTERNAL_ERROR, next, true);
    			} finally {
    				if(wasFork)
    					next.noLongerRoutingTo(origTag, false);
    			}
    		}
    		
    		@Override
    		public void blockReceiveFailed(
    				RetrievalException e) {
    			try {
    				synchronized(RequestSender.this) {
    					transferringFrom = null;
    				}
    				origTag.senderTransferEnds((NodeCHK)key, RequestSender.this);
    				if (e.getReason()==RetrievalException.SENDER_DISCONNECTED)
    					Logger.normal(this, "Transfer failed (disconnect): "+e, e);
    				else
    					// A certain number of these are normal, it's better to track them through statistics than call attention to them in the logs.
    					Logger.normal(this, "Transfer failed ("+e.getReason()+"/"+RetrievalException.getErrString(e.getReason())+"): "+e+" from "+next, e);
    				if(RequestSender.this.source == null)
    					Logger.normal(this, "Local transfer failed: "+e.getReason()+" : "+RetrievalException.getErrString(e.getReason())+"): "+e+" from "+next, e);
    				// We do an ordinary backoff in all cases.
    				if(!prb.abortedLocally())
    					next.localRejectedOverload("TransferFailedRequest"+e.getReason(), realTimeFlag);
    				node.failureTable.onFinalFailure(key, next, htl, origHTL, FailureTable.RECENTLY_FAILED_TIME, FailureTable.REJECT_TIME, source);
    				if(!wasFork)
    					finish(TRANSFER_FAILED, next, false);
    				int reason = e.getReason();
    				boolean timeout = (!br.senderAborted()) &&
    				(reason == RetrievalException.SENDER_DIED || reason == RetrievalException.RECEIVER_DIED || reason == RetrievalException.TIMED_OUT
    						|| reason == RetrievalException.UNABLE_TO_SEND_BLOCK_WITHIN_TIMEOUT);
    				// But we only do a transfer backoff (which is separate, and starts at a higher threshold) if we timed out.
    				if(timeout) {
    					// Looks like a timeout. Backoff.
    					if(logMINOR) Logger.minor(this, "Timeout transferring data : "+e, e);
    					next.transferFailed(e.getErrString(), realTimeFlag);
    				} else {
    					// Quick failure (in that we didn't have to timeout). Don't backoff.
    					// Treat as a DNF.
    					node.failureTable.onFinalFailure(key, next, htl, origHTL, FailureTable.RECENTLY_FAILED_TIME, FailureTable.REJECT_TIME, source);
    				}
    				if(!prb.abortedLocally())
    					node.nodeStats.failedBlockReceive(true, timeout, realTimeFlag, source == null);
    			} catch (Throwable t) {
        			Logger.error(this, "Failed on "+this, t);
        			if(!wasFork)
        				finish(INTERNAL_ERROR, next, true);
    			} finally {
    				if(wasFork)
    					next.noLongerRoutingTo(origTag, false);
    			}
    		}
    		
    	});
	}

	/** @param next 
	 * @return True to continue waiting for this node, false to move on to another. */
	private boolean handleRejectedOverload(Message msg, boolean wasFork, PeerNode next) {
		
		// Non-fatal - probably still have time left
		forwardRejectedOverload();
		rejectOverloads++;
		if (msg.getBoolean(DMT.IS_LOCAL)) {
			//NB: IS_LOCAL means it's terminal. not(IS_LOCAL) implies that the rejection message was forwarded from a downstream node.
			//"Local" from our peers perspective, this has nothing to do with local requests (source==null)
			long t = timeSinceSentForTimeout();
    		node.failureTable.onFailed(key, next, htl, t, t);
			next.localRejectedOverload("ForwardRejectedOverload2", realTimeFlag);
			// Node in trouble suddenly??
			Logger.normal(this, "Local RejectedOverload after Accepted, moving on to next peer");
			// Local RejectedOverload, after already having Accepted.
			// This indicates either:
			// a) The node no longer has the resources to handle the request, even though it did initially.
			// b) The node has a severe internal error.
			// c) The node knows we will timeout fatally if it doesn't send something.
			// In all 3 cases, it is possible that the request is continuing downstream.
			// So this is fatal. Treat similarly to a DNF.
			// FIXME use a different message for termination after accepted.
			next.noLongerRoutingTo(origTag, false);
			node.failureTable.onFinalFailure(key, next, htl, origHTL, FailureTable.RECENTLY_FAILED_TIME, FailureTable.REJECT_TIME, source);
			if(!wasFork)
				finish(TIMED_OUT, next, false);
			return false;
		}
		//so long as the node does not send a (IS_LOCAL) message. Interestingly messages can often timeout having only received this message.
		return true;
	}

	private void handleRouteNotFound(Message msg, PeerNode next) {
		// Backtrack within available hops
		short newHtl = msg.getShort(DMT.HTL);
		if(newHtl < 0) newHtl = 0;
		if(newHtl < htl) htl = newHtl;
		next.successNotOverload(realTimeFlag);
		int t = timeSinceSent();
		node.failureTable.onFailed(key, next, htl, t, t);
		next.noLongerRoutingTo(origTag, false);
	}

	private void handleDataNotFound(Message msg, boolean wasFork, PeerNode next) {
		next.successNotOverload(realTimeFlag);
		node.failureTable.onFinalFailure(key, next, htl, origHTL, FailureTable.RECENTLY_FAILED_TIME, FailureTable.REJECT_TIME, source);
		if(!wasFork)
			finish(DATA_NOT_FOUND, next, false);
		else
			next.noLongerRoutingTo(origTag, false);
	}

	private void handleRecentlyFailed(Message msg, boolean wasFork, PeerNode next) {
		next.successNotOverload(realTimeFlag);
		/*
		 * Must set a correct recentlyFailedTimeLeft before calling this finish(), because it will be
		 * passed to the handler.
		 * 
		 * It is *VITAL* that the TIME_LEFT we pass on is not larger than it should be.
		 * It is somewhat less important that it is not too much smaller than it should be.
		 * 
		 * Why? Because:
		 * 1) We have to use FNPRecentlyFailed to create failure table entries. Because otherwise,
		 * the failure table is of little value: A request is routed through a node, which gets a DNF,
		 * and adds a failure table entry. Other requests then go through that node via other paths.
		 * They are rejected with FNPRecentlyFailed - not with DataNotFound. If this does not create
		 * failure table entries, more requests will be pointlessly routed through that chain.
		 * 
		 * 2) If we use a fixed timeout on receiving FNPRecentlyFailed, they can be self-seeding. 
		 * What this means is A sends a request to B, which DNFs. This creates a failure table entry 
		 * which lasts for 10 minutes. 5 minutes later, A sends another request to B, which is killed
		 * with FNPRecentlyFailed because of the failure table entry. B's failure table lasts for 
		 * another 5 minutes, but A's lasts for the full 10 minutes i.e. until 5 minutes after B's. 
		 * After B's failure table entry has expired, but before A's expires, B sends a request to A. 
		 * A replies with FNPRecentlyFailed. Repeat ad infinitum: A reinforces B's blocks, and B 
		 * reinforces A's blocks!
		 * 
		 * 3) This can still happen even if we check where the request is coming from. A loop could 
		 * very easily form: A - B - C - A. A requests from B, DNFs (assume the request comes in from 
		 * outside, there are more nodes. C requests from A, sets up a block. B's block expires, C's 
		 * is still active. A requests from B which requests from C ... and it goes round again.
		 * 
		 * 4) It is exactly the same if we specify a timeout, unless the timeout can be guaranteed to 
		 * not increase the expiry time.
		 */
		
		// First take the original TIME_LEFT. This will start at 10 minutes if we get rejected in
		// the same millisecond as the failure table block was added.
		int timeLeft = msg.getInt(DMT.TIME_LEFT);
		int origTimeLeft = timeLeft;
		
		if(timeLeft <= 0) {
			if(timeLeft == 0) {
				if(logMINOR) Logger.minor(this, "RecentlyFailed: timeout already consumed on "+this);
			} else {
				Logger.error(this, "Impossible: timeLeft="+timeLeft);
			}
			origTimeLeft = 0;
			timeLeft = 0;
		}
		
		// This is in theory relative to when the request was received by the node. Lets make it relative
		// to a known event before that: the time when we sent the request.
		
		long timeSinceSent = Math.max(0, timeSinceSent());
		timeLeft -= timeSinceSent;
		
		// Subtract 1% for good measure / to compensate for dodgy clocks
		timeLeft -= origTimeLeft / 100;
		
		if(timeLeft < 0) timeLeft = 0;
		
		// We don't store the recently failed time because we will either generate our own, based on which
		// peers we have routed the key to (including the timeout we got here, which we DO store in the 
		// FTE), or we will send a RecentlyFailed with timeout 0, which won't cause RF's on the downstream
		// peer. The point is, forwarding it as-is is inaccurate: it creates a timeout which is not 
		// justified. More info in routeRequests().
		
		synchronized(this) {
			killedByRecentlyFailed = true;
		}
		
		// Kill the request, regardless of whether there is timeout left.
		// If there is, we will avoid sending requests for the specified period.
		node.failureTable.onFinalFailure(key, next, htl, origHTL, timeLeft, FailureTable.REJECT_TIME, source);
		next.noLongerRoutingTo(origTag, false);
	}

	/**
     * Finish fetching an SSK. We must have received the data, the headers and the pubkey by this point.
     * @param next The node we received the data from.
	 * @param wasFork 
     */
	private void finishSSK(PeerNode next, boolean wasFork, byte[] headers, byte[] sskData) {
    	try {
			block = new SSKBlock(sskData, headers, (NodeSSK)key, false);
			node.storeShallow(block, canWriteClientCache, canWriteDatastore, false);
			if(node.random.nextInt(RANDOM_REINSERT_INTERVAL) == 0)
				node.queueRandomReinsert(block);
			synchronized(this) {
				finalHeaders = headers;
				finalSskData = sskData;
			}
			finish(SUCCESS, next, false);
		} catch (SSKVerifyException e) {
			Logger.error(this, "Failed to verify: "+e+" from "+next, e);
			if(!wasFork)
				finish(VERIFY_FAILURE, next, false);
			else
				next.noLongerRoutingTo(origTag, false);
			return;
		} catch (KeyCollisionException e) {
			Logger.normal(this, "Collision on "+this);
			block = node.fetch((NodeSSK)key, false, canWriteClientCache, canWriteClientCache, canWriteDatastore, false, null);
			if(block != null) {
				headers = block.getRawHeaders();
				sskData = block.getRawData();
			}
			synchronized(this) {
				if(finalHeaders == null || finalSskData == null) {
					finalHeaders = headers;
					finalSskData = sskData;
				}
			}
			finish(SUCCESS, next, false);
		}
	}

    /**
     * Finish fetching an SSK. We must have received the data, the headers and the pubkey by this point.
     * @param next The node we received the data from.
     * @return True if the request has completed. False if we need to look elsewhere.
     */
	private boolean finishSSKFromGetOffer(PeerNode next, byte[] headers, byte[] sskData) {
    	try {
			block = new SSKBlock(sskData, headers, (NodeSSK)key, false);
			synchronized(this) {
				finalHeaders = headers;
				finalSskData = sskData;
			}
			node.storeShallow(block, canWriteClientCache, canWriteDatastore, tryOffersOnly);
			if(node.random.nextInt(RANDOM_REINSERT_INTERVAL) == 0)
				node.queueRandomReinsert(block);
			finish(SUCCESS, next, true);
			return true;
		} catch (SSKVerifyException e) {
			Logger.error(this, "Failed to verify (from get offer): "+e+" from "+next, e);
			return false;
		} catch (KeyCollisionException e) {
			Logger.normal(this, "Collision (from get offer) on "+this);
			finish(SUCCESS, next, true);
			return false;
		}
	}

	protected Message createDataRequest() {
		Message req;
    	if(!isSSK)
    		req = DMT.createFNPCHKDataRequest(uid, htl, (NodeCHK)key);
    	else// if(key instanceof NodeSSK)
    		req = DMT.createFNPSSKDataRequest(uid, htl, (NodeSSK)key, pubKey == null);
    	req.addSubMessage(DMT.createFNPRealTimeFlag(realTimeFlag));
    	return req;
	}

	private void verifyAndCommit(byte[] headers, byte[] data) throws KeyVerifyException {
    	if(!isSSK) {
    		CHKBlock block = new CHKBlock(data, headers, (NodeCHK)key);
    		synchronized(this) {
    			finalHeaders = headers;
    		}
    		if(logMINOR) Logger.minor(this, "Verified");
    		// Cache only in the cache, not the store. The reason for this is that
    		// requests don't go to the full distance, and therefore pollute the 
    		// store; simulations it is best to only include data from requests
    		// which go all the way i.e. inserts.
    		node.storeShallow(block, canWriteClientCache, canWriteDatastore, tryOffersOnly);
			if(node.random.nextInt(RANDOM_REINSERT_INTERVAL) == 0)
				node.queueRandomReinsert(block);
    	} else /*if (key instanceof NodeSSK)*/ {
    		synchronized(this) {
    			finalHeaders = headers;
    			finalSskData = data;
    		}
    		try {
    			SSKBlock block = new SSKBlock(data, headers, (NodeSSK)key, false);
        		if(logMINOR) Logger.minor(this, "Verified SSK");
				node.storeShallow(block, canWriteClientCache, canWriteDatastore, tryOffersOnly);
			} catch (KeyCollisionException e) {
				Logger.normal(this, "Collision on "+this);
			}
    	}
	}

	private volatile boolean hasForwardedRejectedOverload;
    
    /** Forward RejectedOverload to the request originator */
    protected void forwardRejectedOverload() {
		synchronized (this) {
			if(hasForwardedRejectedOverload) return;
			hasForwardedRejectedOverload = true;
			notifyAll();
		}
		fireReceivedRejectOverload();
	}
    
    public PartiallyReceivedBlock getPRB() {
        return prb;
    }

    public boolean transferStarted() {
        return prb != null;
    }

    // these are bit-masks
    static final short WAIT_REJECTED_OVERLOAD = 1;
    static final short WAIT_TRANSFERRING_DATA = 2;
    static final short WAIT_FINISHED = 4;
    
    static final short WAIT_ALL = 
    	WAIT_REJECTED_OVERLOAD | WAIT_TRANSFERRING_DATA | WAIT_FINISHED;
    
    /**
     * Wait until either the transfer has started, we receive a 
     * RejectedOverload, or we get a terminal status code.
     * Must not return until we are finished - cannot timeout, because the caller will unlock
     * the UID!
     * @param mask Bitmask indicating what NOT to wait for i.e. the situation when this function
     * exited last time (see WAIT_ constants above). Bits can also be set true even though they
     * were not valid, to indicate that the caller doesn't care about that bit.
     * If zero, function will throw an IllegalArgumentException.
     * @return Bitmask indicating present situation. Can be fed back to this function,
     * if nonzero.
     */
    public synchronized short waitUntilStatusChange(short mask) {
    	if(mask == WAIT_ALL) throw new IllegalArgumentException("Cannot ignore all!");
    	while(true) {
    	long now = System.currentTimeMillis();
    	long deadline = now + (realTimeFlag ? MINUTES.toMillis(5) : MINUTES.toMillis(21));
        while(true) {
        	short current = mask; // If any bits are set already, we ignore those states.
        	
       		if(hasForwardedRejectedOverload)
       			current |= WAIT_REJECTED_OVERLOAD;
        	
       		if(prb != null)
       			current |= WAIT_TRANSFERRING_DATA;
        	
        	if(status != NOT_FINISHED || sentAbortDownstreamTransfers)
        		current |= WAIT_FINISHED;
        	
        	if(current != mask) return current;
			
            try {
            	if(now >= deadline) {
            		Logger.error(this, "Waited more than 5 minutes for status change on " + this + " current = " + current + " and there was no change.");
            		break;
            	}
            	
            	if(logMINOR) Logger.minor(this, "Waiting for status change on "+this+" current is "+current+" status is "+status);
                wait(deadline - now);
                now = System.currentTimeMillis(); // Is used in the next iteration so needed even without the logging
                
                if(now >= deadline) {
                    Logger.error(this, "Waited more than 5 minutes for status change on " + this + " current = " + current + ", maybe nobody called notify()");
                    // Normally we would break; here, but we give the function a change to succeed
                    // in the next iteration and break in the above if(now >= deadline) if it
                    // did not succeed. This makes the function work if notify() is not called.
                }
            } catch (InterruptedException e) {
                // Ignore
            }
        }
    	}
    }
    
	private static MedianMeanRunningAverage avgTimeTaken = new MedianMeanRunningAverage();
	
	private static MedianMeanRunningAverage avgTimeTakenTransfer = new MedianMeanRunningAverage();
	
	private long transferTime;
	
	/** Complete the request. Note that if the request was forked (which unfortunately is
	 * possible because of timeouts awaiting Accepted/Rejected), it is *possible* that 
	 * there are other forks still running; UIDTag will wait for them. Hence a fork that 
	 * fails should NOT call this method, however a fork that succeeds SHOULD call it. 
	 * @param code The completion code.
	 * @param next The node being routed to.
	 * @param fromOfferedKey Whether this was the result of fetching an offered key.
	 */
    private void finish(int code, PeerNode next, boolean fromOfferedKey) {
    	if(logMINOR) Logger.minor(this, "finish("+code+ ") on "+this+" from "+next);
        
    	boolean doOpennet;
    	
        synchronized(this) {
        	if(status != NOT_FINISHED) {
        		if(logMINOR) Logger.minor(this, "Status already set to "+status+" - returning on "+this+" would be setting "+code+" from "+next);
            	if(next != null) next.noLongerRoutingTo(origTag, fromOfferedKey);
        		return;
        	}
            doOpennet = code == SUCCESS && !(fromOfferedKey || isSSK);
       		if(doOpennet)
       			origTag.waitingForOpennet(next); // Call this first so we don't unlock.
       		if(next != null) next.noLongerRoutingTo(origTag, fromOfferedKey);
       		// After calling both, THEN tell handler.
            status = code;
            if(status == SUCCESS)
            	successFrom = next;
            notifyAll();
        }
        
    	boolean shouldUnlock = doOpennet && next != null;
        
        if(status == SUCCESS) {
        	if((!isSSK) && transferTime > 0 && logMINOR) {
        		long timeTaken = System.currentTimeMillis() - startTime;
        		synchronized(avgTimeTaken) {
       				avgTimeTaken.report(timeTaken);
           			avgTimeTakenTransfer.report(transferTime);
       				if(logMINOR) Logger.minor(this, "Successful CHK request took "+timeTaken+" average "+avgTimeTaken);
           			if(logMINOR) Logger.minor(this, "Successful CHK request transfer "+transferTime+" average "+avgTimeTakenTransfer);
           			if(logMINOR) Logger.minor(this, "Search phase: median "+(avgTimeTaken.currentValue() - avgTimeTakenTransfer.currentValue())+"ms, mean "+(avgTimeTaken.meanValue() - avgTimeTakenTransfer.meanValue())+"ms");
        		}
        	}
        	if(next != null) {
        		next.onSuccess(false, isSSK);
        	}
        	// FIXME should this be called when fromOfferedKey??
       		node.nodeStats.requestCompleted(true, source != null, isSSK);
        	
       		fireRequestSenderFinished(code, fromOfferedKey);
       		
       		if(doOpennet) {
       			if(finishOpennet(next))
       				shouldUnlock = false;
       		}
        } else {
        	node.nodeStats.requestCompleted(false, source != null, isSSK);
			fireRequestSenderFinished(code, fromOfferedKey);
		}
        
    	if(shouldUnlock) next.noLongerRoutingTo(origTag, fromOfferedKey);
		
		synchronized(this) {
			opennetFinished = true;
			notifyAll();
		}
		
    }
    
    AsyncMessageCallback finishOpennetOnAck(final PeerNode next) {
    	
    	return new AsyncMessageCallback() {

			private boolean completed;
			
			@Override
			public void sent() {
				// Ignore
			}

			@Override
			public void acknowledged() {
				synchronized(this) {
					if(completed) return;
					completed = true;
				}
				origTag.finishedWaitingForOpennet(next);
			}

			@Override
			public void disconnected() {
				synchronized(this) {
					if(completed) return;
					completed = true;
				}
				origTag.finishedWaitingForOpennet(next);
			}

			@Override
			public void fatalError() {
				synchronized(this) {
					if(completed) return;
					completed = true;
				}
				origTag.finishedWaitingForOpennet(next);
			}
			
		};
    }

	/** Acknowledge the opennet path folding attempt without sending a reference. Once
	 * the send completes (asynchronously), unlock everything. */
	void ackOpennet(final PeerNode next) {
		Message msg = DMT.createFNPOpennetCompletedAck(uid);
		// We probably should set opennetFinished after the send completes.
		try {
			next.sendAsync(msg, finishOpennetOnAck(next), this);
		} catch (NotConnectedException e) {
			// Ignore.
		}
	}

	/**
     * Do path folding, maybe.
     * Wait for either a CompletedAck or a ConnectDestination.
     * If the former, exit.
     * If we want a connection, reply with a ConnectReply, otherwise send a ConnectRejected and exit.
     * Add the peer.
     * @return True only if there was a fatal timeout and the caller should not unlock.
     */
    private boolean finishOpennet(PeerNode next) {
    	
    	OpennetManager om;
    	
    	try {
   			byte[] noderef = OpennetManager.waitForOpennetNoderef(false, next, uid, this, node);
        	
        	if(noderef == null) {
        		ackOpennet(next);
        		return false;
        	}
        	
    		om = node.getOpennet();
    		
    		if(om == null) {
        		ackOpennet(next);
        		return false;
    		}
    		
        	SimpleFieldSet ref = OpennetManager.validateNoderef(noderef, 0, noderef.length, next, false);
        	
        	if(ref == null) {
        		ackOpennet(next);
        		return false;
        	}
        	
            if(!node.canWriteDatastoreRequest(origHTL)) {
                // Do not path fold at all at high HTL.
                ackOpennet(next);
                return false;
            }
        	
			if(node.addNewOpennetNode(ref, ConnectionType.PATH_FOLDING) == null) {
				if(logMINOR) Logger.minor(this, "Don't want noderef on "+this);
				// If we don't want it let somebody else have it
				synchronized(this) {
					opennetNoderef = noderef;
				}
				// RequestHandler will send a noderef back up, eventually, and will unlockHandler() after that point.
				assert(source != null);
				if(origTag.shouldStop()) {
					// Can't pass it on.
					origTag.finishedWaitingForOpennet(next);
				}
				return false;
			} else {
				// opennetNoderef = null i.e. we want the noderef so we won't pass it further down.
				Logger.normal(this, "Added opennet noderef in "+this+" from "+next);
			}
			
	    	// We want the node: send our reference
    		om.sendOpennetRef(true, uid, next, om.crypto.myCompressedFullRef(), this);
			origTag.finishedWaitingForOpennet(next);

		} catch (FSParseException e) {
			Logger.error(this, "Could not parse opennet noderef for "+this+" from "+next, e);
    		ackOpennet(next);
			return false;
		} catch (PeerParseException e) {
			Logger.error(this, "Could not parse opennet noderef for "+this+" from "+next, e);
    		ackOpennet(next);
			return false;
		} catch (ReferenceSignatureVerificationException e) {
			Logger.error(this, "Bad signature on opennet noderef for "+this+" from "+next+" : "+e, e);
    		ackOpennet(next);
			return false;
		} catch (NotConnectedException e) {
			// Hmmm... let the LRU deal with it
			if(logMINOR)
				Logger.minor(this, "Not connected sending ConnectReply on "+this+" to "+next);
			origTag.finishedWaitingForOpennet(next);
    	} catch (WaitedTooLongForOpennetNoderefException e) {
    		Logger.error(this, "RequestSender timed out waiting for noderef from "+next+" for "+this);
    		// Not an error since it can be caused downstream.
    		origTag.timedOutToHandlerButContinued(); // Since we will tell downstream that we are finished.
    		Logger.warning(this, "RequestSender timed out waiting for noderef from "+next+" for "+this);
			synchronized(this) {
				opennetTimedOut = true;
				opennetFinished = true;
				notifyAll();
			}
			// We need to wait.
			try {
				OpennetManager.waitForOpennetNoderef(false, next, uid, this, node);
			} catch (WaitedTooLongForOpennetNoderefException e1) {
	    		Logger.error(this, "RequestSender FATAL TIMEOUT out waiting for noderef from "+next+" for "+this);
				// Fatal timeout. Urgh.
				next.fatalTimeout(origTag, false);
	    		ackOpennet(next);
	    		return true;
			}
    		ackOpennet(next);
		} finally {
    		synchronized(this) {
    			opennetFinished = true;
    			notifyAll();
    		}
    	}
		return false;
	}

    // Opennet stuff
    
    /** Have we finished all opennet-related activities? */
    private boolean opennetFinished;
    
    /** Did we timeout waiting for opennet noderef? */
    private boolean opennetTimedOut;
    
    /** Opennet noderef from next node */
    private byte[] opennetNoderef;
    
    public byte[] waitForOpennetNoderef() throws WaitedTooLongForOpennetNoderefException {
    	synchronized(this) {
    		long startTime = System.currentTimeMillis();
    		while(true) {
    			if(opennetFinished) {
    				if(opennetTimedOut)
    					throw new WaitedTooLongForOpennetNoderefException();
    				if(logMINOR)
    					Logger.minor(this, "Grabbing opennet noderef on "+this, new Exception("debug"));
    				// Only one RequestHandler may take the noderef
    				byte[] ref = opennetNoderef;
    				opennetNoderef = null;
    				return ref;
    			}
    			try {
    				int waitTime = (int) Math.min(Integer.MAX_VALUE, OPENNET_TIMEOUT + startTime - System.currentTimeMillis());
    				if(waitTime > 0) {
    					wait(waitTime);
    					continue;
    				}
				} catch (InterruptedException e) {
					// Ignore
					continue;
				}
				if(logMINOR) Logger.minor(this, "Took too long waiting for opennet ref on "+this);
				return null;
    		}
    	}
    }

    public synchronized PeerNode successFrom() {
    	return successFrom;
    }
    
	public synchronized byte[] getHeaders() {
        return finalHeaders;
    }

    public int getStatus() {
        return status;
    }

    public short getHTL() {
        return htl;
    }
    
    final synchronized byte[] getSSKData() {
    	return finalSskData;
    }
    
    public SSKBlock getSSKBlock() {
    	return block;
    }

	private final Object totalBytesSync = new Object();
	private int totalBytesSent;
	
	@Override
	public void sentBytes(int x) {
		synchronized(totalBytesSync) {
			totalBytesSent += x;
		}
		if(logMINOR) Logger.minor(this, "Sent bytes: "+x+" for "+this+" isSSK="+isSSK, new Exception("debug"));
		node.nodeStats.requestSentBytes(isSSK, x);
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
		node.nodeStats.requestReceivedBytes(isSSK, x);
	}
	
	public int getTotalReceivedBytes() {
		synchronized(totalBytesSync) {
			return totalBytesReceived;
		}
	}
	
	synchronized boolean hasForwarded() {
		return hasForwarded;
	}

	@Override
	public void sentPayload(int x) {
		node.sentPayload(x);
		node.nodeStats.requestSentBytes(isSSK, -x);
	}
	
	private int recentlyFailedTimeLeft;

	synchronized int getRecentlyFailedTimeLeft() {
		return recentlyFailedTimeLeft;
	}
	
	public boolean isLocalRequestSearch() {
		return (source==null);
	}
	
	public void addListener(RequestSenderListener l) {
		// Only call here if we've already called for the other listeners.
		// Therefore the callbacks will only be called once.
		boolean reject=false;
		boolean transfer=false;
		boolean sentFinished;
		boolean sentTransferCancel = false;
		boolean sentFinishedFromOfferedKey = false;
		int status;
		// LOCKING: We add the new listener. We check each notification.
		// If it has already been sent when we add the new listener, we need to send it here.
		// Otherwise we don't, it will be called by the thread processing that event, even if it's already happened.
		synchronized (listeners) {
			sentTransferCancel = sentAbortDownstreamTransfers;
			if(!sentTransferCancel) {
				listeners.add(l);
				if(logMINOR) Logger.minor(this, "Added listener "+l+" to "+this);
			}
			reject = sentReceivedRejectOverload;
			transfer = sentCHKTransferBegins;
			sentFinished = sentRequestSenderFinished;
			sentFinishedFromOfferedKey = completedFromOfferedKey;
		}
		transfer=transfer && transferStarted();
		if (reject)
			l.onReceivedRejectOverload();
		if (transfer)
			l.onCHKTransferBegins();
		if(sentTransferCancel)
			l.onAbortDownstreamTransfers(abortDownstreamTransfersReason, abortDownstreamTransfersDesc);
		if(sentFinished) {
			// At the time when we added the listener, we had sent the status to the others.
			// Therefore, we need to send it to this one too.
			synchronized(this) {
				status = this.status;
			}
			if (status!=NOT_FINISHED)
				l.onRequestSenderFinished(status, sentFinishedFromOfferedKey, this);
			else
				Logger.error(this, "sentFinished is true but status is still NOT_FINISHED?!?! on "+this, new Exception("error"));
		}
	}
	
	private boolean sentReceivedRejectOverload;
	
	private void fireReceivedRejectOverload() {
		synchronized (listeners) {
			if(sentReceivedRejectOverload) return;
			sentReceivedRejectOverload = true;
			for (RequestSenderListener l : listeners) {
				try {
					l.onReceivedRejectOverload();
				} catch (Throwable t) {
					Logger.error(this, "Caught: "+t, t);
				}
			}
		}
	}
	
	private boolean sentCHKTransferBegins;
	
	private void fireCHKTransferBegins() {
		synchronized (listeners) {
			if(sentCHKTransferBegins) return;
			sentCHKTransferBegins = true;
			for (RequestSenderListener l : listeners) {
				try {
					l.onCHKTransferBegins();
				} catch (Throwable t) {
					Logger.error(this, "Caught: "+t, t);
				}
			}
		}
	}
	
	private boolean sentRequestSenderFinished;
	private boolean completedFromOfferedKey;
	
	private void fireRequestSenderFinished(int status, boolean fromOfferedKey) {
		origTag.setRequestSenderFinished(status);
		synchronized (listeners) {
			if(sentRequestSenderFinished) {
				Logger.error(this, "Request sender finished twice: "+status+", "+fromOfferedKey+" on "+this);
				return;
			}
			sentRequestSenderFinished = true;
			completedFromOfferedKey = fromOfferedKey;
			if(logMINOR) Logger.minor(this, "Notifying "+listeners.size()+" listeners of status "+status);
			for (RequestSenderListener l : listeners) {
				try {
					l.onRequestSenderFinished(status, fromOfferedKey, this);
				} catch (Throwable t) {
					Logger.error(this, "Caught: "+t, t);
				}
			}
		}
	}

	private boolean sentAbortDownstreamTransfers;
	private int abortDownstreamTransfersReason;
	private String abortDownstreamTransfersDesc;
	private boolean receivingAsync;
	
	private void reassignToSelfOnTimeout(boolean fromOfferedKey) {
		RequestSenderListener[] list;
		synchronized(listeners) {
			if(sentCHKTransferBegins) {
				Logger.error(this, "Transfer started, not dumping listeners when reassigning to self on timeout (race condition?) on "+this);
				return;
			}
			list = listeners.toArray(new RequestSenderListener[listeners.size()]);
			listeners.clear();
		}
		for(RequestSenderListener l : list) {
			l.onRequestSenderFinished(TIMED_OUT, fromOfferedKey, this);
		}
		origTag.timedOutToHandlerButContinued();
	}
	
	@Override
	public int getPriority() {
		return NativeThread.HIGH_PRIORITY;
	}

	public PeerNode transferringFrom() {
		return transferringFrom;
	}

	public synchronized boolean abortedDownstreamTransfers() {
		return sentAbortDownstreamTransfers;
	}

	public long fetchTimeout() {
		return incomingSearchTimeout;
	}

	BlockReceiverTimeoutHandler myTimeoutHandler = new BlockReceiverTimeoutHandler() {

		/** The data receive has failed. A block timed out. The PRB will be cancelled as
		 * soon as we return, and that will cause the source node to consider the request
		 * finished. Meantime we don't know whether the upstream node has finished or not.
		 * So we reassign the request to ourself, and then wait for the second timeout. */
		@Override
		public void onFirstTimeout() {
			origTag.timedOutToHandlerButContinued();
		}

		/** The timeout appears to have been caused by the node we are directly connected
		 * to. So we need to disconnect the node, or take other fairly strong sanctions,
		 * to avoid load management problems. */
		@Override
		public void onFatalTimeout(PeerContext receivingFrom) {
			Logger.error(this, "Fatal timeout receiving requested block on "+this+" from "+receivingFrom);
			((PeerNode)receivingFrom).fatalTimeout();
		}
		
	};
	
	// FIXME this should not be necessary, we should be able to ask our listeners.
	// However at the moment NodeClientCore's realGetCHK and realGetSSK (the blocking fetches)
	// do not register a RequestSenderListener. Eventually they will be replaced with something that does.
	
	// Also we should consider whether a local RequestSenderListener added *after* the request starts should
	// impact on the decision or whether that leaks too much information. It's probably safe
	// given the amount leaked anyway! (Note that if we start the request locally we will want
	// to finish it even if incoming RequestHandler's are coalesced with it and they fail their 
	// onward transfers).
	
	private boolean transferCoalesced;

	public synchronized void setTransferCoalesced() {
		transferCoalesced = true;
	}

	public synchronized boolean isTransferCoalesced() {
		return transferCoalesced;
	}
	
	private int searchTimeout;
	
	@Override
	protected void onAccepted(PeerNode next) {
		onAccepted(next, false, htl);
	}
	
	/** If we handled a timeout, and forked, we need to know the original HTL. */
	protected void onAccepted(PeerNode next, boolean forked, short htl) {
		MainLoopCallback cb;
        synchronized(this) {
        	receivingAsync = true;
        	searchTimeout = calculateTimeout(htl);
            cb = new MainLoopCallback(next, forked, searchTimeout);
        }
        cb.schedule();
	}

	protected long getAcceptedTimeout() {
		return ACCEPTED_TIMEOUT;
	}

	@Override
	protected void timedOutWhileWaiting(double load) {
		htl -= (short)Math.max(0, hopsForFatalTimeoutWaitingForPeer());
		if(htl < 0) htl = 0;
		// Timeouts while waiting for a slot are relatively normal.
		// That is, in an ideal world they wouldn't happen.
		// They happen when the network is very small, or when there is a capacity bottleneck.
		// They are best considered statistically, see the stats page.
		// Individual timeouts are therefore not very interesting...
		if(logMINOR) {
			if(source != null)
				Logger.minor(this, "Timed out while waiting for a slot on "+this);
			else
				Logger.minor(this, "Local request timed out while waiting for a slot on "+this);
		}
    	finish(ROUTE_NOT_FOUND, null, false);
        node.failureTable.onFinalFailure(key, null, htl, origHTL, -1, -1, source);
	}

	@Override
	protected boolean isInsert() {
		return false;
	}

	@Override
	protected void handleAcceptedRejectedTimeout(final PeerNode next,
			final UIDTag origTag) {
		
		final short htl = this.htl;
		origTag.handlingTimeout(next);

		long timeout = MINUTES.toMillis(1);

		MessageFilter mf = makeAcceptedRejectedFilter(next, timeout, origTag);
		try {
			node.usm.addAsyncFilter(mf, new SlowAsyncMessageFilterCallback() {

				@Override
				public void onMatched(Message m) {
					if(m.getSpec() == DMT.FNPRejectedLoop ||
							m.getSpec() == DMT.FNPRejectedOverload) {
						// Ok.
						next.noLongerRoutingTo(origTag, false);
					} else {
						// Accepted. May as well wait for the data, if any.
						onAccepted(next, true, htl);
					}
				}
				
				@Override
				public boolean shouldTimeout() {
					return false;
				}

				@Override
				public void onTimeout() {
					Logger.error(this, "Fatal timeout waiting for Accepted/Rejected from "+next+" on "+RequestSender.this);
					next.fatalTimeout(origTag, false);
				}

				@Override
				public void onDisconnect(PeerContext ctx) {
					next.noLongerRoutingTo(origTag, false);
				}

				@Override
				public void onRestarted(PeerContext ctx) {
					next.noLongerRoutingTo(origTag, false);
				}

				@Override
				public int getPriority() {
					return NativeThread.NORM_PRIORITY;
				}
				
			}, this);
		} catch (DisconnectedException e) {
			next.noLongerRoutingTo(origTag, false);
		}
	}

}
