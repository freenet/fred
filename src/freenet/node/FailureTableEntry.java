package freenet.node;

import static java.util.concurrent.TimeUnit.HOURS;

import java.lang.ref.WeakReference;
import java.util.Arrays;
import java.util.HashSet;

import freenet.keys.Key;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;

/** Tracks recent requests for a specific key. If we have recently routed to a specific 
 * node, and failed, we should not route to it again, unless it is at a higher HTL. 
 * Different failures cause different timeouts. Similarly we track the nodes that have
 * requested the key, because for both sets of nodes, when we find the data we offer them
 * it; this greatly improves latency and efficiency for polling-based tools. For nodes
 * we have routed to, we keep up to HTL separate entries; for nodes we have received 
 * requests from, we keep only one entry.
 * 
 * SECURITY: All this could be a security risk if not regularly cleared - which it is,
 * of course: We forget about either kind of node after a fixed period, in 
 * cleanupRequested(), which the FailureTable calls regularly. Against a near-omnipotent 
 * attacker able to compromise nodes at will of course it is still a security risk to 
 * track anything but we have bigger problems at that level.
 * @author toad
 */
class FailureTableEntry implements TimedOutNodesList {
	
	/** The key */
	final Key key; // FIXME should this be stored compressed somehow e.g. just the routing key?
	/** Time of creation of this entry */
	long creationTime;
	/** Time we last received a request for the key */
	long receivedTime;
	/** Time we last received a DNF after sending a request for a key */
	long sentTime;
	/** WeakReference's to PeerNodeUnlocked's who have requested the key */
	WeakReference<? extends PeerNodeUnlocked>[] requestorNodes;
	/** Times at which they requested it */
	long[] requestorTimes;
	/** Boot ID when they requested it. We don't send it to restarted nodes, as a 
	 * (weak, but useful if combined with other measures) protection against seizure. */
	long[] requestorBootIDs;
	short[] requestorHTLs;
	
	// FIXME Note that just because a node is in this list doesn't mean it DNFed or RFed.
	// We include *ALL* nodes we routed to here!
	/** WeakReference's to PeerNodeUnlocked's we have requested it from */
	WeakReference<? extends PeerNodeUnlocked>[] requestedNodes;
	/** Their locations when we requested it. This may be needed in the future to
	 * determine whether to let a request through that we would otherwise have
	 * failed with RecentlyFailed, because the node we would route it to is closer
	 * to the target than any we've routed to in the past. */
	double[] requestedLocs;
	long[] requestedBootIDs;
	long[] requestedTimes;
	/** Timeouts for each node for purposes of RecentlyFailed. We accept what
	 * they say, subject to an upper limit, because we MUST NOT suppress too
	 * many requests, as that could lead to a self-sustaining key blocking. */
	long[] requestedTimeoutsRF;
	/** Timeouts for each node for purposes of per-node failure tables. We use
	 * our own estimates, based on time elapsed, for most failure modes; a fixed
	 * period for DNF and RecentlyFailed. */
	long[] requestedTimeoutsFT;
	
	short[] requestedTimeoutHTLs;
	
	private static volatile boolean logMINOR;
	
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
	/** We remember that a node has asked us for a key for up to an hour; after that, we won't offer the key, and
	 * if we receive an offer from that node, we will reject it */
	static final long MAX_TIME_BETWEEN_REQUEST_AND_OFFER = HOURS.toMillis(1);

        public static final long[] EMPTY_LONG_ARRAY = new long[0];
        public static final short[] EMPTY_SHORT_ARRAY = new short[0];
        public static final double[] EMPTY_DOUBLE_ARRAY = new double[0];
        @SuppressWarnings("unchecked")
        public static final WeakReference<? extends PeerNodeUnlocked>[] EMPTY_WEAK_REFERENCE =
            (WeakReference<? extends PeerNodeUnlocked>[])new WeakReference<?>[0];
        
	FailureTableEntry(Key key) {
		this.key = key.archivalCopy();
		long now = System.currentTimeMillis();
		creationTime = now;
		receivedTime = -1;
		sentTime = -1;
		requestorNodes = EMPTY_WEAK_REFERENCE;
		requestorTimes = EMPTY_LONG_ARRAY;
		requestorBootIDs = EMPTY_LONG_ARRAY;
		requestorHTLs = EMPTY_SHORT_ARRAY;
		requestedNodes = EMPTY_WEAK_REFERENCE;
		requestedLocs = EMPTY_DOUBLE_ARRAY;
		requestedBootIDs = EMPTY_LONG_ARRAY;
		requestedTimes = EMPTY_LONG_ARRAY;
		requestedTimeoutsRF = EMPTY_LONG_ARRAY;
		requestedTimeoutsFT = EMPTY_LONG_ARRAY;
		requestedTimeoutHTLs = EMPTY_SHORT_ARRAY;
	}
	
	/** A request failed to a specific peer.
	 * @param routedTo The peer we routed to.
	 * @param rfTimeout The time until we can route to the node again, for purposes of RecentlyFailed.
	 * @param ftTimeout The time until we can route to the node again, for purposes of per-node failure tables.
	 * @param now The current time.
	 * @param htl The HTL of the request. Note that timeouts only apply to the same HTL.
	 */
	public synchronized void failedTo(PeerNodeUnlocked routedTo, long rfTimeout, long ftTimeout, long now, short htl) {
		if(logMINOR) {
			Logger.minor(this, "Failed sending request to "+routedTo.shortToString()+" : timeout "+rfTimeout+" / "+ftTimeout);
		}
		int idx = addRequestedFrom(routedTo, htl, now);
		if(rfTimeout > 0) {
			long curTimeoutTime = requestedTimeoutsRF[idx];
			long newTimeoutTime = now + rfTimeout;
			if(newTimeoutTime > curTimeoutTime) {
				requestedTimeoutsRF[idx] = newTimeoutTime;
				requestedTimeoutHTLs[idx] = htl;
			}
		}
		if(ftTimeout > 0) {
			long curTimeoutTime = requestedTimeoutsFT[idx];
			long newTimeoutTime = now +  ftTimeout;
			if(newTimeoutTime > curTimeoutTime) {
				requestedTimeoutsFT[idx] = newTimeoutTime;
				requestedTimeoutHTLs[idx] = htl;
			}
		}
	}

	// These are rather low level, in an attempt to absolutely minimize memory usage...
	// The two methods have almost identical code/logic.
	// Dunno if there's a more elegant way of dealing with this which doesn't significantly increase
	// per entry byte cost.
	// Note also this will generate some churn...
	
	synchronized int addRequestor(PeerNodeUnlocked requestor, long now, short origHTL) {
		if(logMINOR) Logger.minor(this, "Adding requestors: "+requestor+" at "+now);
		receivedTime = now;
		boolean includedAlready = false;
		int nulls = 0;
		int ret = -1;
		for(int i=0;i<requestorNodes.length;i++) {
			PeerNodeUnlocked got = requestorNodes[i] == null ? null : requestorNodes[i].get();
			// No longer subscribed if they have rebooted, or expired
			if(got == requestor) {
				// Update existing entry
				includedAlready = true;
				requestorTimes[i] = now;
				requestorBootIDs[i] = requestor.getBootID();
				requestorHTLs[i] = origHTL;
				ret = i;
				break;
			} else if(got != null && 
					(got.getBootID() != requestorBootIDs[i] || now - requestorTimes[i] > MAX_TIME_BETWEEN_REQUEST_AND_OFFER)) {
				requestorNodes[i] = null;
				got = null;
			}
			if(got == null)
				nulls++;
		}
		if(nulls == 0 && includedAlready) return ret;
		int notIncluded = includedAlready ? 0 : 1;
		// Because weak, these can become null; doesn't matter, but we want to minimise memory usage
		if(nulls == 1 && !includedAlready) {
			// Nice special case
			for(int i=0;i<requestorNodes.length;i++) {
				if(requestorNodes[i] == null || requestorNodes[i].get() == null) {
					requestorNodes[i] = requestor.getWeakRef();
					requestorTimes[i] = now;
					requestorBootIDs[i] = requestor.getBootID();
					requestorHTLs[i] = origHTL;
					return i;
				}
			}
		}
        @SuppressWarnings("unchecked")
		WeakReference<? extends PeerNodeUnlocked>[] newRequestorNodes =
		    (WeakReference<? extends PeerNodeUnlocked>[])
		    new WeakReference<?>[requestorNodes.length+notIncluded-nulls];
		long[] newRequestorTimes = new long[requestorNodes.length+notIncluded-nulls];
		long[] newRequestorBootIDs = new long[requestorNodes.length+notIncluded-nulls];
		short[] newRequestorHTLs = new short[requestorNodes.length+notIncluded-nulls];
		int toIndex = 0;
		
		for(int i=0;i<requestorNodes.length;i++) {
			WeakReference<? extends PeerNodeUnlocked> ref = requestorNodes[i];
			PeerNodeUnlocked pn = ref == null ? null : ref.get();
			if(pn == null) continue;
			if(pn == requestor) ret = toIndex;
			newRequestorNodes[toIndex] = requestorNodes[i];
			newRequestorTimes[toIndex] = requestorTimes[i];
			newRequestorBootIDs[toIndex] = requestorBootIDs[i];
			newRequestorHTLs[toIndex] = requestorHTLs[i];
			toIndex++;
		}
		
		if(!includedAlready) {
			newRequestorNodes[toIndex] = requestor.getWeakRef();
			newRequestorTimes[toIndex] = now;
			newRequestorBootIDs[toIndex] = requestor.getBootID();
			newRequestorHTLs[toIndex] = origHTL;
			ret = toIndex;
			toIndex++;
		}
		
		for(int i=toIndex;i<newRequestorNodes.length;i++) newRequestorNodes[i] = null;
		if(toIndex > newRequestorNodes.length + 2) {
			newRequestorNodes = Arrays.copyOf(newRequestorNodes, toIndex);
			newRequestorTimes = Arrays.copyOf(newRequestorTimes, toIndex);
			newRequestorBootIDs = Arrays.copyOf(newRequestorBootIDs, toIndex);
			newRequestorHTLs = Arrays.copyOf(newRequestorHTLs, toIndex);
		}
		requestorNodes = newRequestorNodes;
		requestorTimes = newRequestorTimes;
		requestorBootIDs = newRequestorBootIDs;
		requestorHTLs = newRequestorHTLs;
		
		return ret;
	}

	/** Add a requested from entry to the node. If there already is one reuse it but only
	 * if the HTL matches. Return the index so we can update timeouts etc.
	 * @param requestedFrom The node we have routed the request to.
	 * @param htl The HTL at which the request was sent.
	 * @param now The current time.
	 * @return The index of the new or old entry.
	 */
	private synchronized int addRequestedFrom(PeerNodeUnlocked requestedFrom, short htl, long now) {
		if(logMINOR) Logger.minor(this, "Adding requested from: "+requestedFrom+" at "+now);
		sentTime = now;
		boolean includedAlready = false;
		int nulls = 0;
		int ret = -1;
		for(int i=0;i<requestedNodes.length;i++) {
			PeerNodeUnlocked got = requestedNodes[i] == null ? null : requestedNodes[i].get();
			if(got == requestedFrom && (requestedTimeoutsRF[i] == -1 || requestedTimeoutsFT[i] == -1 || requestedTimeoutHTLs[i] == htl)) {
				includedAlready = true;
				requestedLocs[i] = requestedFrom.getLocation();
				requestedBootIDs[i] = requestedFrom.getBootID();
				requestedTimes[i] = now;
				ret = i;
			} else if(got != null && 
					(got.getBootID() != requestedBootIDs[i] || now - requestedTimes[i] > MAX_TIME_BETWEEN_REQUEST_AND_OFFER)) {
				requestedNodes[i] = null;
				got = null;
			}
			if(got == null)
				nulls++;
		}
		if(includedAlready && nulls == 0) return ret;
		int notIncluded = includedAlready ? 0 : 1;
		// Because weak, these can become null; doesn't matter, but we want to minimise memory usage
		if(nulls == 1 && !includedAlready) {
			// Nice special case
			for(int i=0;i<requestedNodes.length;i++) {
				if(requestedNodes[i] == null || requestedNodes[i].get() == null) {
					requestedNodes[i] = requestedFrom.getWeakRef();
					requestedLocs[i] = requestedFrom.getLocation();
					requestedBootIDs[i] = requestedFrom.getBootID();
					requestedTimes[i] = now;
					requestedTimeoutsRF[i] = -1;
					requestedTimeoutsFT[i] = -1;
					requestedTimeoutHTLs[i] = (short) -1;
					return i;
				}
			}
		}
		@SuppressWarnings("unchecked")
		WeakReference<? extends PeerNodeUnlocked>[] newRequestedNodes =
		    (WeakReference<? extends PeerNodeUnlocked>[])
		    new WeakReference<?>[requestedNodes.length+notIncluded-nulls];
		double[] newRequestedLocs = new double[requestedNodes.length+notIncluded-nulls];
		long[] newRequestedBootIDs = new long[requestedNodes.length+notIncluded-nulls];
		long[] newRequestedTimes = new long[requestedNodes.length+notIncluded-nulls];
		long[] newRequestedTimeoutsFT = new long[requestedNodes.length+notIncluded-nulls];
		long[] newRequestedTimeoutsRF = new long[requestedNodes.length+notIncluded-nulls];
		short[] newRequestedTimeoutHTLs = new short[requestedNodes.length+notIncluded-nulls];

		int toIndex = 0;
		for(int i=0;i<requestedNodes.length;i++) {
			WeakReference<? extends PeerNodeUnlocked> ref = requestedNodes[i];
			PeerNodeUnlocked pn = ref == null ? null : ref.get();
			if(pn == null) continue;
			if(pn == requestedFrom) ret = toIndex;
			newRequestedNodes[toIndex] = requestedNodes[i];
			newRequestedTimes[toIndex] = requestedTimes[i];
			newRequestedBootIDs[toIndex] = requestedBootIDs[i];
			newRequestedLocs[toIndex] = requestedLocs[i];
			newRequestedTimeoutsFT[toIndex] = requestedTimeoutsFT[i];
			newRequestedTimeoutsRF[toIndex] = requestedTimeoutsRF[i];
			newRequestedTimeoutHTLs[toIndex] = requestedTimeoutHTLs[i];
			toIndex++;
		}
		
		if(!includedAlready) {
			ret = toIndex;
			newRequestedNodes[toIndex] = requestedFrom.getWeakRef();
			newRequestedTimes[toIndex] = now;
			newRequestedBootIDs[toIndex] = requestedFrom.getBootID();
			newRequestedLocs[toIndex] = requestedFrom.getLocation();
			newRequestedTimeoutsFT[toIndex] = -1;
			newRequestedTimeoutsRF[toIndex] = -1;
			newRequestedTimeoutHTLs[toIndex] = (short) -1;
			ret = toIndex;
			toIndex++;
		}
		
		for(int i=toIndex;i<newRequestedNodes.length;i++) newRequestedNodes[i] = null;
		if(toIndex > newRequestedNodes.length + 2) {
			newRequestedNodes = Arrays.copyOf(newRequestedNodes, toIndex);
			newRequestedLocs = Arrays.copyOf(newRequestedLocs, toIndex);
			newRequestedBootIDs = Arrays.copyOf(newRequestedBootIDs, toIndex);
			newRequestedTimes = Arrays.copyOf(newRequestedTimes, toIndex);
			newRequestedTimeoutsRF = Arrays.copyOf(newRequestedTimeoutsRF, toIndex);
			newRequestedTimeoutsFT = Arrays.copyOf(newRequestedTimeoutsFT, toIndex);
			newRequestedTimeoutHTLs = Arrays.copyOf(newRequestedTimeoutHTLs, toIndex);
		}
		requestedNodes = newRequestedNodes;
		requestedLocs = newRequestedLocs;
		requestedBootIDs = newRequestedBootIDs;
		requestedTimes = newRequestedTimes;
		requestedTimeoutsRF = newRequestedTimeoutsRF;
		requestedTimeoutsFT = newRequestedTimeoutsFT;
		requestedTimeoutHTLs = newRequestedTimeoutHTLs;
		
		return ret;
	}

	/** Offer this key to all the nodes that have requested it, and all the nodes it has been requested from.
	 * Called after a) the data has been stored, and b) this entry has been removed from the FT */
	public void offer() {
		HashSet<PeerNodeUnlocked> set = new HashSet<PeerNodeUnlocked>();
		final boolean logMINOR = FailureTableEntry.logMINOR;
		if(logMINOR) Logger.minor(this, "Sending offers to nodes which requested the key from us: ("+requestorNodes.length+") for "+key);
		synchronized(this) {
			for(int i=0;i<requestorNodes.length;i++) {
				WeakReference<? extends PeerNodeUnlocked> ref = requestorNodes[i];
				if(ref == null) continue;
				PeerNodeUnlocked pn = ref.get();
				if(pn == null) continue;
				if(pn.getBootID() != requestorBootIDs[i]) continue;
				if(!set.add(pn)) {
					Logger.error(this, "Node is in requestorNodes twice: "+pn);
				}
			}
			if(logMINOR) Logger.minor(this, "Sending offers to nodes which we sent the key to: ("+requestedNodes.length+") for "+key);
			for(int i=0;i<requestedNodes.length;i++) {
				WeakReference<? extends PeerNodeUnlocked> ref = requestedNodes[i];
				if(ref == null) continue;
				PeerNodeUnlocked pn = ref.get();
				if(pn == null) continue;
				if(pn.getBootID() != requestedBootIDs[i]) continue;
				if(!set.add(pn)) continue;
			}
		}
		// Do the offers outside the lock. 
		// We do not need to hold it, offer() doesn't do anything that affects us.
		for(PeerNodeUnlocked pn : set) {
			if(logMINOR) Logger.minor(this, "Offering to "+pn);
			pn.offer(key);
		}
	}

	/**
	 * Has any node asked for this key?
	 */
	public synchronized boolean othersWant() {
		boolean anyValid = false;
		for(int i=0;i<requestorNodes.length;i++) {
			WeakReference<? extends PeerNodeUnlocked> ref = requestorNodes[i];
			if(ref == null) continue;
			PeerNodeUnlocked pn = ref.get();
			if(pn == null) {
				requestorNodes[i] = null;
				continue;
			}
			long bootID = pn.getBootID();
			if(bootID != requestorBootIDs[i]) {
				requestorNodes[i] = null;
				continue;
			}
			anyValid = true;
		}
		if(!anyValid) {
			requestorNodes = EMPTY_WEAK_REFERENCE;
			requestorTimes = requestorBootIDs = EMPTY_LONG_ARRAY;
			requestorHTLs = EMPTY_SHORT_ARRAY;
		}
		return anyValid;
	}

	/**
	 * Has this peer asked us for the key?
	 */
	public synchronized boolean askedByPeer(PeerNodeUnlocked peer, long now) {
		boolean anyValid = false;
		boolean ret = false;
		for(int i=0;i<requestorNodes.length;i++) {
			WeakReference<? extends PeerNodeUnlocked> ref = requestorNodes[i];
			if(ref == null) continue;
			PeerNodeUnlocked pn = ref.get();
			if(pn == null) {
				requestorNodes[i] = null;
				continue;
			}
			long bootID = pn.getBootID();
			if(bootID != requestorBootIDs[i]) {
				requestorNodes[i] = null;
				continue;
			}
			if(now - requestorTimes[i] < MAX_TIME_BETWEEN_REQUEST_AND_OFFER) {
				if(pn == peer) ret = true;
				anyValid = true;
			} 
		}
		if(!anyValid) {
			requestorNodes = EMPTY_WEAK_REFERENCE;
			requestorTimes = requestorBootIDs = EMPTY_LONG_ARRAY;
			requestorHTLs = EMPTY_SHORT_ARRAY;
		}
		return ret;
	}

	/**
	 * Have we asked this peer for the key?
	 */
	public synchronized boolean askedFromPeer(PeerNodeUnlocked peer, long now) {
		boolean anyValid = false;
		boolean ret = false;
		for(int i=0;i<requestedNodes.length;i++) {
			WeakReference<? extends PeerNodeUnlocked> ref = requestedNodes[i];
			if(ref == null) continue;
			PeerNodeUnlocked pn = ref.get();
			if(pn == null) {
				requestedNodes[i] = null;
				continue;
			}
			long bootID = pn.getBootID();
			if(bootID != requestedBootIDs[i]) {
				requestedNodes[i] = null;
				continue;
			}
			anyValid = true;
			if(now - requestedTimes[i] < MAX_TIME_BETWEEN_REQUEST_AND_OFFER) {
				if(pn == peer) ret = true;
				anyValid = true;
			}
		}
		if(!anyValid) {
			requestedNodes = EMPTY_WEAK_REFERENCE;
			requestedTimes = requestedBootIDs = requestedTimeoutsRF = requestedTimeoutsFT = EMPTY_LONG_ARRAY;
			requestedTimeoutHTLs =EMPTY_SHORT_ARRAY;
		}
		return ret;
	}

	public synchronized boolean isEmpty() {
		if(requestedNodes.length > 0) return false;
		if(requestorNodes.length > 0) return false;
		return true;
	}

	/** Get the timeout time for the given peer, taking HTL into account.
	 * If there was a timeout at HTL 1, and we are now sending a request at
	 * HTL 2, we ignore the timeout. */
	@Override
	public synchronized long getTimeoutTime(PeerNode peer, short htl, long now, boolean forPerNodeFailureTables) {
		long timeout = -1;
		for(int i=0;i<requestedNodes.length;i++) {
			WeakReference<? extends PeerNodeUnlocked> ref = requestedNodes[i];
			if(ref != null && ref.get() == peer) {
				if(requestedTimeoutHTLs[i] >= htl) {
					long thisTimeout = forPerNodeFailureTables ? requestedTimeoutsFT[i] : requestedTimeoutsRF[i];
					if(thisTimeout > timeout && thisTimeout > now)
						timeout = thisTimeout;
				}
			}
		}
		return timeout;
	}
	
	public synchronized boolean cleanup() {
		long now = System.currentTimeMillis(); // don't pass in as a pass over the whole FT may take a while. get it in the method.
		
		boolean empty = cleanupRequestor(now);
		empty &= cleanupRequested(now);
		return empty;
	}

	private boolean cleanupRequestor(long now) {
		boolean empty = true;
		int x = 0;
		for(int i=0;i<requestorNodes.length;i++) {
			WeakReference<? extends PeerNodeUnlocked> ref = requestorNodes[i];
			if(ref == null) continue;
			PeerNodeUnlocked pn = ref.get();
			if(pn == null) continue;
			long bootID = pn.getBootID();
			if(bootID != requestorBootIDs[i]) continue;
			if(!pn.isConnected()) continue;
			if(now - requestorTimes[i] > MAX_TIME_BETWEEN_REQUEST_AND_OFFER) continue;
			empty = false;
			requestorNodes[x] = requestorNodes[i];
			requestorTimes[x] = requestorTimes[i];
			requestorBootIDs[x] = requestorBootIDs[i];
			requestorHTLs[x] = requestorHTLs[i];
			x++;
		}
		if(x < requestorNodes.length) {
			requestorNodes = Arrays.copyOf(requestorNodes, x);
			requestorTimes = Arrays.copyOf(requestorTimes, x);
			requestorBootIDs = Arrays.copyOf(requestorBootIDs, x);
			requestorHTLs = Arrays.copyOf(requestorHTLs, x);
		}
		
		return empty;
	}
	
	private boolean cleanupRequested(long now) {
		boolean empty = true;
		int x = 0;
		for(int i=0;i<requestedNodes.length;i++) {
			WeakReference<? extends PeerNodeUnlocked> ref = requestedNodes[i];
			if(ref == null) continue;
			PeerNodeUnlocked pn = ref.get();
			if(pn == null) continue;
			long bootID = pn.getBootID();
			if(bootID != requestedBootIDs[i]) continue;
			if(!pn.isConnected()) continue;
			if(now - requestedTimes[i] > MAX_TIME_BETWEEN_REQUEST_AND_OFFER) continue;
			empty = false;
			requestedNodes[x] = requestedNodes[i];
			requestedTimes[x] = requestedTimes[i];
			requestedBootIDs[x] = requestedBootIDs[i];
			requestedLocs[x] = requestedLocs[i];
			if(now < requestedTimeoutsRF[x] || now < requestedTimeoutsFT[x]) { 
				requestedTimeoutsRF[x] = requestedTimeoutsRF[i];
				requestedTimeoutsFT[x] = requestedTimeoutsFT[i];
				requestedTimeoutHTLs[x] = requestedTimeoutHTLs[i];
			} else {
				requestedTimeoutsRF[x] = -1;
				requestedTimeoutsFT[x] = -1;
				requestedTimeoutHTLs[x] = (short)-1;
			}
			x++;
		}
		if(x < requestedNodes.length) {
			requestedNodes = Arrays.copyOf(requestedNodes, x);
			requestedTimes = Arrays.copyOf(requestedTimes, x);
			requestedBootIDs = Arrays.copyOf(requestedBootIDs, x);
			requestedLocs = Arrays.copyOf(requestedLocs, x);
			requestedTimeoutsRF = Arrays.copyOf(requestedTimeoutsRF, x);
			requestedTimeoutsFT = Arrays.copyOf(requestedTimeoutsFT, x);
			requestedTimeoutHTLs = Arrays.copyOf(requestedTimeoutHTLs, x);
		}
		return empty;
	}

	public synchronized short minRequestorHTL(short htl) {
		long now = System.currentTimeMillis();
		boolean anyValid = false;
		for(int i=0;i<requestorNodes.length;i++) {
			WeakReference<? extends PeerNodeUnlocked> ref = requestorNodes[i];
			if(ref == null) continue;
			PeerNodeUnlocked pn = ref.get();
			if(pn == null) {
				requestorNodes[i] = null;
				continue;
			}
			long bootID = pn.getBootID();
			if(bootID != requestorBootIDs[i]) {
				requestorNodes[i] = null;
				continue;
			}
			if(now - requestorTimes[i] < MAX_TIME_BETWEEN_REQUEST_AND_OFFER) {
				if(requestorHTLs[i] < htl) htl = requestorHTLs[i];
			}
			anyValid = true;
		}
		if(!anyValid) {
			requestorNodes = EMPTY_WEAK_REFERENCE;
			requestorTimes = requestorBootIDs = EMPTY_LONG_ARRAY;
			requestorHTLs = EMPTY_SHORT_ARRAY;
		}
		return htl;
	}

}
