package freenet.node;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.lang.ref.WeakReference;
import java.util.HashSet;

import freenet.support.Logger;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger.LogLevel;

/**
 * Base class for tags representing a running request. These store enough information
 * to detect whether they are finished; if they are still in the list, this normally
 * represents a bug.
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public abstract class UIDTag {
	
    private static volatile boolean logMINOR;
    
    static {
    	Logger.registerLogThresholdCallback(new LogThresholdCallback(){
    		@Override
    		public void shouldUpdate(){
    			logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
    		}
    	});
    }
    
	final long createdTime;
	final boolean wasLocal;
	private final WeakReference<PeerNode> sourceRef;
	final boolean realTimeFlag;
	protected final RequestTracker tracker;
	protected boolean accepted;
	protected boolean sourceRestarted;
	private boolean slowDown;
	
	/** Nodes we have routed to at some point */
	private HashSet<PeerNode> routedTo = null;
	/** Nodes we are currently talking to i.e. which have not yet removed our UID from the
	 * list of active requests. */
	private HashSet<PeerNode> currentlyRoutingTo = null;
	/** Node we are currently doing an offered-key-fetch from */
	private HashSet<PeerNode> fetchingOfferedKeyFrom = null;
	/** We are waiting for two stage timeouts from these nodes. If the handler is unlocked
	 * and there are still nodes in the above two, we will log an error; but if those nodes
	 * are here too, we will reassignTagToSelf and not log an error. */
	private HashSet<PeerNode> handlingTimeouts = null;
	protected boolean notRoutedOnwards;
	final long uid;
	
	protected boolean unlockedHandler;
	protected boolean noRecordUnlock;
	private boolean hasUnlocked;
	
	private boolean waitingForSlot;
	
	UIDTag(PeerNode source, boolean realTimeFlag, long uid, Node node) {
		createdTime = System.currentTimeMillis();
		this.sourceRef = source == null ? null : source.myRef;
		wasLocal = source == null;
		this.realTimeFlag = realTimeFlag;
		this.tracker = node.tracker;
		this.uid = uid;
		if(logMINOR)
			Logger.minor(this, "Created "+this);
		if(wasLocal) accepted = true; // FIXME remove, but it's always true at the moment.
	}

	public abstract void logStillPresent(Long uid);

	long age() {
		return System.currentTimeMillis() - createdTime;
	}
	
	/** Notify that we are routing to, or fetching an offered key from, a 
	 * specific node. This should be called before we send the actual request
	 * message, to avoid us thinking we have more outgoing capacity than we
	 * actually have on a specific peer.
	 * @param peer The peer we are routing to.
	 * @param offeredKey If true, we are fetching an offered key, if false we
	 * are routing a normal request. Fetching an offered key is quite distinct,
	 * notably it has much shorter timeouts.
	 * @return True if we were already routing to (or fetching an offered key 
	 * from, depending on offeredKey) the peer.
	 */
	public synchronized boolean addRoutedTo(PeerNode peer, boolean offeredKey) {
		if(logMINOR)
			Logger.minor(this, "Routing to "+peer+" on "+this+(offeredKey ? " (offered)" : ""), new Exception("debug"));
		if(routedTo == null) routedTo = new HashSet<PeerNode>();
		routedTo.add(peer);
		if(offeredKey) {
			if(fetchingOfferedKeyFrom == null) fetchingOfferedKeyFrom = new HashSet<PeerNode>();
			return fetchingOfferedKeyFrom.add(peer);
		} else {
			if(currentlyRoutingTo == null) currentlyRoutingTo = new HashSet<PeerNode>();
			return currentlyRoutingTo.add(peer);
		}
	}

	public synchronized boolean hasRoutedTo(PeerNode peer) {
		if(routedTo == null) return false;
		return routedTo.contains(peer);
	}

	public synchronized boolean currentlyRoutingTo(PeerNode peer) {
		if(currentlyRoutingTo == null) return false;
		return currentlyRoutingTo.contains(peer);
	}
	
	// Note that these don't actually get removed until the request is finished, unless there is a disconnection or similar. But that
	// is generally not a problem as they complete quickly and successfully mostly.
	// The alternative would be to remove when the transfer is finished, but that does not
	// guarantee the UID has been freed; we can only safely (for load management purposes)
	// remove once we have an acknowledgement which is sent after the UID is removed.
	
	public synchronized boolean currentlyFetchingOfferedKeyFrom(PeerNode peer) {
		if(fetchingOfferedKeyFrom == null) return false;
		return fetchingOfferedKeyFrom.contains(peer);
	}

	/** Notify that we are no longer fetching an offered key from a specific 
	 * node. Must be called only when we are sure the next node doesn't think
	 * we are routing to it any more. See removeRoutingTo() explanation for more
	 * detail. When we are not routing to any nodes, and not fetching from, and
	 * the handler has also been unlocked, the UID is unlocked.
	 * @param next The node we are no longer fetching an offered key from.
	 */
	public void removeFetchingOfferedKeyFrom(PeerNode next) {
		boolean noRecordUnlock;
		synchronized(this) {
			if(fetchingOfferedKeyFrom == null) return;
			fetchingOfferedKeyFrom.remove(next);
			if(handlingTimeouts != null) {
				handlingTimeouts.remove(next);
			}
			if(!mustUnlock()) return;
			noRecordUnlock = this.noRecordUnlock;
		}
		if(logMINOR) Logger.minor(this, "Unlocking "+this);
		innerUnlock(noRecordUnlock);
	}
	
	/** Notify that we are no longer routing to a specific node. When we are
	 * not routing to (or fetching offered keys from) any nodes, and the handler
	 * side has also been unlocked, the whole tag is unlocked (note that this 
	 * is only relevant to incoming requests; outgoing requests only care about
	 * what we are routing to). We should not call this method until we are 
	 * reasonably sure that the node in question no longer thinks we are 
	 * routing to it. Whereas we unlock the handler as soon as possible, 
	 * without waiting for acknowledgement of our completion notice. Be 
	 * cautious (late) in what you send, and generous (early) in what 
	 * you accept! This avoids problems with the previous node thinking we've
	 * finished when we haven't, or us thinking the next node has finished when
	 * it hasn't.
	 * @param next The node we are no longer routing to.
	 */
	public void removeRoutingTo(PeerNode next) {
		if(logMINOR)
			Logger.minor(this, "No longer routing to "+next+" on "+this, new Exception("debug"));
		boolean noRecordUnlock;
		synchronized(this) {
			if(currentlyRoutingTo == null) return;
			if(!currentlyRoutingTo.remove(next)) {
				Logger.warning(this, "Removing wrong node or removing twice? on "+this+" : "+next, new Exception("debug"));
			}
			if(handlingTimeouts != null) {
				handlingTimeouts.remove(next);
			}
			if(!mustUnlock()) return;
			noRecordUnlock = this.noRecordUnlock;
		}
		if(logMINOR) Logger.minor(this, "Unlocking "+this);
		innerUnlock(noRecordUnlock);
	}
	
	protected void innerUnlock(boolean noRecordUnlock) {
		tracker.unlockUID(this, false, noRecordUnlock);
	}

	public void postUnlock() {
		PeerNode[] peers;
		synchronized(this) {
			if(routedTo != null)
				peers = routedTo.toArray(new PeerNode[routedTo.size()]);
			else
				peers = null;
		}
		if(peers != null)
			for(PeerNode p : peers)
				p.postUnlock(this);
	}

	/** Add up the expected transfers in.
	 * @param ignoreLocalVsRemote If true, pretend that the request is remote even if it's local.
	 */
	public abstract int expectedTransfersIn(boolean ignoreLocalVsRemote);
	
	/** Add up the expected transfers out.
	 * @param ignoreLocalVsRemote If true, pretend that the request is remote even if it's local.
	 * @param outwardTransfersPerInsert Expected number of outward transfers for an insert.
	 * @param forAccept If true, we are deciding whether to accept a request.
	 * If false, we are deciding whether to SEND a request. We need to be more
	 * careful for the latter than the former, to avoid unnecessary rejections 
	 * and mandatory backoffs.
	 */
	public abstract int expectedTransfersOut(boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept);
	
	public synchronized void setNotRoutedOnwards() {
		this.notRoutedOnwards = true;
	}

	private boolean reassigned;
	
	/** Get the effective source node (e.g. for load management). This is null if the tag 
	 * was reassigned to us. */
	public synchronized PeerNode getSource() {
		if(reassigned) return null;
		if(wasLocal) return null;
		return sourceRef.get();
	}

	/** Reassign the tag to us rather than its original sender. */
	public synchronized void reassignToSelf() {
		if(wasLocal) return;
		reassigned = true;
	}
	
	/** Was the request originated locally? This returns the original answer: It is not
	 * affected by reassigning to self. */
	public boolean wasLocal() {
		return wasLocal;
	}
	
	/** Is the request local now? I.e. was it either originated locally or reassigned to
	 * self? */
	public boolean isLocal() {
		if(wasLocal) return true;
		synchronized(this) {
			return reassigned;
		}
	}

	public abstract boolean isSSK();

	public abstract boolean isInsert();

	public abstract boolean isOfferReply();
	
	/** Caller must call innerUnlock(noRecordUnlock) immediately if this returns true. 
	 * Hence derived versions should call mustUnlock() only after they have checked their
	 * own unlock blockers. */
	protected synchronized boolean mustUnlock() {
		if(hasUnlocked) return false;
		if(!unlockedHandler) return false;
		if(currentlyRoutingTo != null && !currentlyRoutingTo.isEmpty()) {
			if(!(reassigned || wasLocal || sourceRestarted || timedOutButContinued)) {
				boolean expected = false;
				if(handlingTimeouts != null) {
					expected = true;
					for(PeerNode pn : currentlyRoutingTo) {
						if(handlingTimeouts.contains(pn)) {
							if(logMINOR) Logger.debug(this, "Still waiting for "+pn.shortToString()+" but expected because handling timeout in unlockHandler - will reassign to self to resolve timeouts");
							break;
						}
						expected = false;
					}
				}
				if(!expected) {
					if(handlingTimeouts != null)
						Logger.normal(this, "Unlocked handler but still routing to "+currentlyRoutingTo+" - expected because have timed out so a fork might have succeeded and we might be waiting for the original");
					else
						Logger.error(this, "Unlocked handler but still routing to "+currentlyRoutingTo+" yet not reassigned on "+this, new Exception("debug"));
				} else
					reassignToSelf();
			}
			return false;
		}
		if(fetchingOfferedKeyFrom != null && !fetchingOfferedKeyFrom.isEmpty()) {
			if(!(reassigned || wasLocal)) {
				boolean expected = false;
				if(handlingTimeouts != null) {
					expected = true;
					for(PeerNode pn : fetchingOfferedKeyFrom) {
						if(handlingTimeouts.contains(pn)) {
							if(logMINOR) Logger.debug(this, "Still waiting for "+pn.shortToString()+" but expected because handling timeout in unlockHandler - will reassign to self to resolve timeouts");
							break;
						}
						expected = false;
					}
				}
				if(!expected)
					// Fork succeeds can't happen for fetch-offered-keys.
					Logger.error(this, "Unlocked handler but still fetching offered keys from "+fetchingOfferedKeyFrom+" yet not reassigned on "+this, new Exception("debug"));
				else
					reassignToSelf();
			}
			return false;
		}
		Logger.normal(this, "Unlocking "+this, new Exception("debug"));
		hasUnlocked = true;
		return true;
	}
	
	/** Unlock the handler. That is, the incoming request has finished. This 
	 * method should be called before the acknowledgement that the request has
	 * finished is sent downstream. Therefore, we will never be waiting for an
	 * acknowledgement from downstream in order to release the slot it is using,
	 * during which time it might think we are rejecting wrongly.
	 * 
	 * Once both the incoming and outgoing requests are unlocked, the whole tag
	 * is unlocked.
	 */
	public void unlockHandler(boolean noRecord) {
		boolean canUnlock;
		synchronized(this) {
			if(unlockedHandler) return;
			noRecordUnlock = noRecord;
			unlockedHandler = true;
			canUnlock = mustUnlock();
		}
		if(canUnlock)
			innerUnlock(noRecordUnlock);
		else {
			Logger.normal(this, "Cannot unlock yet in unlockHandler, still sending requests");
		}
	}

	public void unlockHandler() {
		unlockHandler(false);
	}

	// LOCKING: Synchronized because of access to currentlyRoutingTo i.e. to avoid ConcurrentModificationException.
	// UIDTag lock is always taken last anyway so this is safe.
	// Also it is only used in logging anyway.
	@Override
	public synchronized String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append(super.toString());
		sb.append(":");
		sb.append(uid);
		if(unlockedHandler)
			sb.append(" (unlocked handler)");
		if(hasUnlocked)
			sb.append(" (unlocked)");
		if(noRecordUnlock)
			sb.append(" (don't record unlock)");
		if(currentlyRoutingTo != null && !currentlyRoutingTo.isEmpty()) {
			sb.append(" (routing to ");
			for(PeerNode pn : currentlyRoutingTo) {
				sb.append(pn.shortToString());
				sb.append(",");
			}
			sb.setLength(sb.length()-1);
			sb.append(")");
		}
		if(fetchingOfferedKeyFrom != null)
			sb.append(" (fetch offered keys from ").append(fetchingOfferedKeyFrom.size()).append(")");
		if(sourceRestarted)
			sb.append(" (source restarted)");
		if(timedOutButContinued)
			sb.append(" (timed out but continued)");
		return sb.toString();
	}

	/** Mark a peer as handling a timeout. Hence if when the handler is unlocked, this 
	 * peer is still marked as routing to (or fetching offered keys from), rather than 
	 * logging an error, we will reassign this tag to self, to wait for the fatal timeout.
	 * @param next
	 */
	public synchronized void handlingTimeout(PeerNode next) {
		if(handlingTimeouts == null)
			handlingTimeouts = new HashSet<PeerNode>();
		handlingTimeouts.add(next);
	}

	private long loggedStillPresent;
	private static final long LOGGED_STILL_PRESENT_INTERVAL = SECONDS.toMillis(60);

	public void maybeLogStillPresent(long now, Long uid) {
		if(now - createdTime > RequestTracker.TIMEOUT) {
			synchronized(this) {
				if(now - loggedStillPresent < LOGGED_STILL_PRESENT_INTERVAL) return;
				loggedStillPresent = now;
			}
			logStillPresent(uid);
		}
	}

	public synchronized void setAccepted() {
		accepted = true;
	}
	
	private boolean timedOutButContinued;

	/** Set when we are going to tell downstream that the request has timed out,
	 * but can't terminate it yet. We will terminate the request if we have to
	 * reroute it, and we count it towards the peer's limit, but we don't stop
	 * messages to the request source. */
	public synchronized void timedOutToHandlerButContinued() {
		timedOutButContinued = true;
	}
	
	/** The handler disconnected or restarted. */
	public synchronized void onRestartOrDisconnectSource() {
		sourceRestarted = true;
	}
	
	// The third option is reassignToSelf(). We only use that when we actually
	// want the data, and mean to continue. In that case, none of the next three
	// are appropriate.
	
	/** Should we deduct this request from the source's limit, instead of 
	 * counting it towards it? A normal request is counted towards it. A hidden
	 * request is deducted from it. This is used when the source has restarted
	 * but also in some other cases. */
	public synchronized boolean countAsSourceRestarted() {
		return sourceRestarted || timedOutButContinued;
	}
	
	/** Should we send messages to the source? */
	public synchronized boolean hasSourceReallyRestarted() {
		return sourceRestarted;
	}
	
	/** Should we stop the request as soon as is convenient? Normally this 
	 * happens when the source is restarted or disconnected. */
	public synchronized boolean shouldStop() {
		return sourceRestarted || timedOutButContinued;
	}

	public synchronized boolean isSource(PeerNode pn) {
		if(reassigned) return false;
		if(wasLocal) return false;
		if(sourceRef == null) return false;
		return sourceRef == pn.myRef;
	}
	
	public synchronized void setWaitingForSlot() {
		// FIXME use a counter on Node.
		// We'd need to ensure it ALWAYS gets unset when some wierd
		// error happens.
		if(waitingForSlot) return;
		waitingForSlot = true;
	}
	
	public synchronized void clearWaitingForSlot() {
		// FIXME use a counter on Node.
		// We'd need to ensure it ALWAYS gets unset when some wierd
		// error happens.
		// Probably we can do this just by calling clearWaitingForSlot() when unlocking???
		if(!waitingForSlot) return;
		waitingForSlot = false;
	}
	
	public synchronized boolean isWaitingForSlot() {
		return waitingForSlot;
	}

	/** Set a flag indicating the originator should slow down. Only used at the shouldRejectRequest stage. */
	synchronized void slowDown() {
		slowDown = true;
	}

	/** Query the slow-down flag. Should be checked after shouldRejectRequest. */
	synchronized boolean shouldSlowDown() {
		return slowDown;
	}
}
