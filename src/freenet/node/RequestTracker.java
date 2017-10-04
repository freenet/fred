package freenet.node;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import freenet.keys.NodeCHK;
import freenet.support.Logger;
import freenet.support.Ticker;

public class RequestTracker {
	
	private static volatile boolean logMINOR;
	private static volatile boolean logDEBUG;

	static {
		Logger.registerClass(RequestTracker.class);
	}
	
	// The runningLocal* are secondary. That is, we take the lock on the
	// corresponding running* when accessing runningLocal*. Local requests
	// have a tag in *both*.
	
	private final HashMap<Long,RequestTag> runningCHKGetUIDsBulk;
	private final HashMap<Long,RequestTag> runningLocalCHKGetUIDsBulk;
	private final HashMap<Long,RequestTag> runningSSKGetUIDsBulk;
	private final HashMap<Long,RequestTag> runningLocalSSKGetUIDsBulk;
	private final HashMap<Long,InsertTag> runningCHKPutUIDsBulk;
	private final HashMap<Long,InsertTag> runningLocalCHKPutUIDsBulk;
	private final HashMap<Long,InsertTag> runningSSKPutUIDsBulk;
	private final HashMap<Long,InsertTag> runningLocalSSKPutUIDsBulk;
	private final HashMap<Long,OfferReplyTag> runningCHKOfferReplyUIDsBulk;
	private final HashMap<Long,OfferReplyTag> runningSSKOfferReplyUIDsBulk;

	private final HashMap<Long,RequestTag> runningCHKGetUIDsRT;
	private final HashMap<Long,RequestTag> runningLocalCHKGetUIDsRT;
	private final HashMap<Long,RequestTag> runningSSKGetUIDsRT;
	private final HashMap<Long,RequestTag> runningLocalSSKGetUIDsRT;
	private final HashMap<Long,InsertTag> runningCHKPutUIDsRT;
	private final HashMap<Long,InsertTag> runningLocalCHKPutUIDsRT;
	private final HashMap<Long,InsertTag> runningSSKPutUIDsRT;
	private final HashMap<Long,InsertTag> runningLocalSSKPutUIDsRT;
	private final HashMap<Long,OfferReplyTag> runningCHKOfferReplyUIDsRT;
	private final HashMap<Long,OfferReplyTag> runningSSKOfferReplyUIDsRT;
	
	private final PeerManager peers;
	private final Ticker ticker;

	/** RequestSender's currently transferring, by key */
	private final HashMap<NodeCHK, RequestSender> transferringRequestSendersRT;
	private final HashMap<NodeCHK, RequestSender> transferringRequestSendersBulk;
	/** UIDs of RequestHandler's currently transferring */
	private final HashSet<Long> transferringRequestHandlers;
	
	RequestTracker(PeerManager peers, Ticker ticker) {
		this.peers = peers;
		this.ticker = ticker;
		runningCHKGetUIDsRT = new HashMap<Long,RequestTag>();
		runningLocalCHKGetUIDsRT = new HashMap<Long,RequestTag>();
		runningSSKGetUIDsRT = new HashMap<Long,RequestTag>();
		runningLocalSSKGetUIDsRT = new HashMap<Long,RequestTag>();
		runningCHKPutUIDsRT = new HashMap<Long,InsertTag>();
		runningLocalCHKPutUIDsRT = new HashMap<Long,InsertTag>();
		runningSSKPutUIDsRT = new HashMap<Long,InsertTag>();
		runningLocalSSKPutUIDsRT = new HashMap<Long,InsertTag>();
		runningCHKOfferReplyUIDsRT = new HashMap<Long,OfferReplyTag>();
		runningSSKOfferReplyUIDsRT = new HashMap<Long,OfferReplyTag>();

		runningCHKGetUIDsBulk = new HashMap<Long,RequestTag>();
		runningLocalCHKGetUIDsBulk = new HashMap<Long,RequestTag>();
		runningSSKGetUIDsBulk = new HashMap<Long,RequestTag>();
		runningLocalSSKGetUIDsBulk = new HashMap<Long,RequestTag>();
		runningCHKPutUIDsBulk = new HashMap<Long,InsertTag>();
		runningLocalCHKPutUIDsBulk = new HashMap<Long,InsertTag>();
		runningSSKPutUIDsBulk = new HashMap<Long,InsertTag>();
		runningLocalSSKPutUIDsBulk = new HashMap<Long,InsertTag>();
		runningCHKOfferReplyUIDsBulk = new HashMap<Long,OfferReplyTag>();
		runningSSKOfferReplyUIDsBulk = new HashMap<Long,OfferReplyTag>();
		
		transferringRequestSendersRT = new HashMap<NodeCHK, RequestSender>();
		transferringRequestSendersBulk = new HashMap<NodeCHK, RequestSender>();
		transferringRequestHandlers = new HashSet<Long>();
	}

	public boolean lockUID(UIDTag tag) {
		return lockUID(tag.uid, tag.isSSK(), tag.isInsert(), tag.isOfferReply(), tag.wasLocal(), tag.realTimeFlag, tag);
	}

	public boolean lockUID(long uid, boolean ssk, boolean insert, boolean offerReply, boolean local, boolean realTimeFlag, UIDTag tag) {
		// If these are switched around, we must remember to remove from both.
		if(offerReply) {
			// local irrelevant for OfferReplyTag's.
			HashMap<Long,OfferReplyTag> map = getOfferTracker(ssk, realTimeFlag);
			return innerLock(map, null, (OfferReplyTag)tag, uid, ssk, insert, offerReply, false);
		} else if(insert) {
			HashMap<Long,InsertTag> overallMap = getInsertTracker(ssk, false, realTimeFlag);
			HashMap<Long,InsertTag> localMap = local ? getInsertTracker(ssk, local, realTimeFlag) : null;
			return innerLock(overallMap, localMap, (InsertTag)tag, uid, ssk, insert, offerReply, local);
		} else {
			HashMap<Long,RequestTag> overallMap = getRequestTracker(ssk,false, realTimeFlag);
			HashMap<Long,RequestTag> localMap = local ? getRequestTracker(ssk,local, realTimeFlag) : null;
			return innerLock(overallMap, localMap, (RequestTag)tag, uid, ssk, insert, offerReply, local);
		}
	}

	private<T extends UIDTag> boolean innerLock(HashMap<Long, T> overallMap, HashMap<Long, T> localMap, T tag, Long uid, boolean ssk, boolean insert, boolean offerReply, boolean local) {
		synchronized(overallMap) {
			if(logMINOR) Logger.minor(this, "Locking "+uid+" ssk="+ssk+" insert="+insert+" offerReply="+offerReply+" local="+local+" size="+overallMap.size(), new Exception("debug"));
			T oldTag = overallMap.get(uid);
			if(oldTag != null) {
				if(oldTag == tag) {
					Logger.error(this, "Tag already registered: "+tag, new Exception("debug"));
				} else {
					return false;
				}
			}
			overallMap.put(uid, tag);
			if(logMINOR) Logger.minor(this, "Locked "+uid+" ssk="+ssk+" insert="+insert+" offerReply="+offerReply+" local="+local+" size="+overallMap.size());
			if(local) {
				if(logMINOR) Logger.minor(this, "Locking (local) "+uid+" ssk="+ssk+" insert="+insert+" offerReply="+offerReply+" local="+local+" size="+localMap.size(), new Exception("debug"));
				oldTag = localMap.get(uid);
				if(oldTag != null) {
					if(oldTag == tag) {
						Logger.error(this, "Tag already registered (local): "+tag, new Exception("debug"));
					} else {
						// Violates the invariant that local requests are always registered on the main (non-local) map too.
						Logger.error(this, "Different tag already registered (local) EVEN THOUGH NOT ON MAIN MAP: "+tag, new Exception("debug"));
						overallMap.remove(uid);
						return false;
					}
				}
				localMap.put(uid, tag);
				if(logMINOR) Logger.minor(this, "Locked (local) "+uid+" ssk="+ssk+" insert="+insert+" offerReply="+offerReply+" local="+local+" size="+localMap.size());
			}
		}
		return true;
	}

	/** Only used by UIDTag. */
	void unlockUID(UIDTag tag, boolean canFail, boolean noRecord) {
		unlockUID(tag.uid, tag.isSSK(), tag.isInsert(), canFail, tag.isOfferReply(), tag.wasLocal(), tag.realTimeFlag, tag, noRecord);
	}

	protected void unlockUID(long uid, boolean ssk, boolean insert, boolean canFail, boolean offerReply, boolean local, boolean realTimeFlag, UIDTag tag, boolean noRecord) {
		if(!noRecord)
			completed(uid);

		if(offerReply) {
			HashMap<Long,OfferReplyTag> map = getOfferTracker(ssk, realTimeFlag);
			innerUnlock(map, null, (OfferReplyTag)tag, uid, ssk, insert, offerReply, false, canFail);
		} else if(insert) {
			HashMap<Long,InsertTag> overallMap = getInsertTracker(ssk, false, realTimeFlag);
			HashMap<Long,InsertTag> localMap = local ? getInsertTracker(ssk,local, realTimeFlag) : null;
			innerUnlock(overallMap, localMap, (InsertTag)tag, uid, ssk, insert, offerReply, local, canFail);
		} else {
			HashMap<Long,RequestTag> overallMap = getRequestTracker(ssk, false, realTimeFlag);
			HashMap<Long,RequestTag> localMap = local ? getRequestTracker(ssk,local, realTimeFlag) : null;
			innerUnlock(overallMap, localMap, (RequestTag)tag, uid, ssk, insert, offerReply, local, canFail);
		}
	}

	/**
	 * Do the actual unlock.
	 * @param <T> The type of the tag.
	 * @param overallMap The overall map for this group of requests. LOCKING:
	 * We use the overallMap as lock for both.
	 * @param localMap The local map if any. We check on overallMap and then
	 * remove from both.
	 * @param tag The tag to remove.
	 * @param uid The UID of the tag.
	 * @param ssk Whether it is an SSK.
	 * @param insert Whether it is an insert.
	 * @param offerReply Whether it is an offer reply.
	 * @param local Whether it is local. If it is local we use both maps. If
	 * it is not we expect the latter to be null.
	 * @param canFail
	 */
	private<T extends UIDTag> void innerUnlock(HashMap<Long, T> overallMap, HashMap<Long, T> localMap, T tag, Long uid, boolean ssk, boolean insert, boolean offerReply, boolean local, boolean canFail) {
		synchronized(overallMap) {
			if(logMINOR) Logger.minor(this, "Unlocking "+uid+" ssk="+ssk+" insert="+insert+" offerReply="+offerReply+" local="+local+" size="+overallMap.size(), new Exception("debug"));
			if(overallMap.get(uid) != tag) {
				if(canFail) {
					if(logMINOR) Logger.minor(this, "Can fail and did fail: removing "+tag+" got "+overallMap.get(uid)+" for "+uid);
				} else {
					Logger.error(this, "Removing "+tag+" for "+uid+" returned "+overallMap.get(uid));
				}
			} else
				overallMap.remove(uid);
			if(logMINOR) Logger.minor(this, "Unlocked "+uid+" ssk="+ssk+" insert="+insert+" offerReply="+offerReply+" local="+local+" size="+overallMap.size());
			if(local) {
				if(localMap.get(uid) != tag) {
					if(canFail) {
						if(logMINOR) Logger.minor(this, "Can fail and did fail (local): removing "+tag+" got "+localMap.get(uid)+" for "+uid);
					} else {
						Logger.error(this, "Removing "+tag+" for "+uid+" returned (local) "+localMap.get(uid));
					}
				} else
					localMap.remove(uid);
				if(logMINOR) Logger.minor(this, "Unlocked (local) "+uid+" ssk="+ssk+" insert="+insert+" offerReply="+offerReply+" local="+local+" size="+localMap.size());
				
			} else {
				assert(localMap == null);
			}
		}
	}

	public static class CountedRequests {
		private int total;
		private int expectedTransfersOut;
		private int expectedTransfersIn;
		public int total() {
			return total;
		}
		public int expectedTransfersOut() {
			return expectedTransfersOut;
		}
		public int expectedTransfersIn() {
			return expectedTransfersIn;
		}
	}

	/** Count all requests running globally which match particular parameters.
	 * @param local If true, only include requests which originated locally.
	 * @param ssk If true, count SSK requests, if false, count CHK requests.
	 * @param insert If true, count inserts, otherwise count requests.
	 * @param offer If true, count offer replies (takes precedence over insert).
	 * @param realTimeFlag If true, count real-time requests, if false, count bulk requests. 
	 * @param transfersPerInsert Assume that any insert will cause this many outgoing transfers. 
	 * This is not predictable, so we use an average.
	 * @param ignoreLocalVsRemote If true, pretend that the request is remote even if it's local 
	 * (that is, count imaginary onward transfers etc depending on the request type).
	 * @param counter Transfer counts for all requests will be added to this counter object.
	 * @param counterSourceRestarted Transfer counts for requests whose source restarted (and so 
	 * are counted as local) will be added to this counter object. */
	public void countRequests(boolean local, boolean ssk, boolean insert, boolean offer, boolean realTimeFlag, int transfersPerInsert, boolean ignoreLocalVsRemote, CountedRequests counter, CountedRequests counterSourceRestarted) {
		HashMap<Long, ? extends UIDTag> map = getTracker(local, ssk, insert, offer, realTimeFlag);
		// Map is locked by the non-local version, although we're counting from the local version.
		HashMap<Long, ? extends UIDTag> mapLock = map;
		if(local)
			mapLock = getTracker(false, ssk, insert, offer, realTimeFlag);
		synchronized(mapLock) {
			int count = 0;
			int transfersOut = 0;
			int transfersIn = 0;
			int countSR = 0;
			int transfersOutSR = 0;
			int transfersInSR = 0;
			for(Map.Entry<Long, ? extends UIDTag> entry : map.entrySet()) {
				UIDTag tag = entry.getValue();
				// The overall running* map can include local. But the local map can't include non-local.
				if((!local) && tag.wasLocal) continue;
				int out = tag.expectedTransfersOut(ignoreLocalVsRemote, transfersPerInsert, true);
				int in = tag.expectedTransfersIn(ignoreLocalVsRemote);
				count++;
				transfersOut += out;
				transfersIn += in;
				if(counterSourceRestarted != null && tag.countAsSourceRestarted()) {
					countSR++;
					transfersOutSR += out;
					transfersInSR += in;
				}
				if(logDEBUG) Logger.debug(this, "UID "+entry.getKey()+" : out "+transfersOut+" in "+transfersIn);
			}
			counter.total += count;
			counter.expectedTransfersIn += transfersIn;
			counter.expectedTransfersOut += transfersOut;
			if(counterSourceRestarted != null) {
				counterSourceRestarted.total += countSR;
				counterSourceRestarted.expectedTransfersIn += transfersInSR;
				counterSourceRestarted.expectedTransfersOut += transfersOutSR;
			}
		}
	}

	/**
	 * Count requests routed to a peer, or accepted from a peer, that match the specified criteria.
	 * PERFORMANCE: There is a map for all requests of a given type (local, ssk, etc). However this
	 * is not divided up by node. FIXME ideally we would countRequests for all PeerNode's
	 * simultaneously when we need data on more than one. FIXME it would be even better if we could
	 * just store the status on the PeerNode's, but the memory usage might be an issue and 
	 * synchronization would likely be problematic.
	 * @param source The peer the requests were accepted from or routed to.
	 * @param requestsToNode If true, count requests sent to the node and currently 
	 * running. If false, count requests originated by the node.
	 * @param local If true, only include requests which originated locally. 
	 * @param ssk If true, count SSK requests, if false, count CHK requests. 
	 * @param insert If true, count inserts, otherwise count requests.
	 * @param offer If true, count offer replies (takes precedence over insert).
	 * @param realTimeFlag If true, count real-time requests, if false, count bulk requests.
	 * @param transfersPerInsert Assume that any insert will cause this many outgoing transfers. 
	 * This is not predictable, so we use an average.
	 * @param ignoreLocalVsRemote If true, pretend that the request is remote even if it's local 
	 * (that is, count imaginary onward transfers etc depending on the request type).
	 * @param counter Transfer counts for all requests will be added to this counter object.
	 * @param counterSR Transfer counts for requests whose source restarted (and so 
	 * are counted as local) will be added to this counter object. */
	public void countRequests(PeerNode source, boolean requestsToNode, boolean local, boolean ssk, boolean insert, boolean offer, boolean realTimeFlag, int transfersPerInsert, boolean ignoreLocalVsRemote, CountedRequests counter, CountedRequests counterSR) {
		HashMap<Long, ? extends UIDTag> map = getTracker(local, ssk, insert, offer, realTimeFlag);
		// Map is locked by the non-local version, although we're counting from the local version.
		HashMap<Long, ? extends UIDTag> mapLock = map;
		if(local)
			mapLock = getTracker(false, ssk, insert, offer, realTimeFlag);
		synchronized(mapLock) {
			int count = 0;
			int transfersOut = 0;
			int transfersIn = 0;
			int countSR = 0;
			int transfersOutSR = 0;
			int transfersInSR = 0;
			if(!requestsToNode) {
				// If a request is adopted by us as a result of a timeout, it can be in the
				// remote map despite having source == null. However, if a request is in the
				// local map it will always have source == null.
				if(source != null && local) return;
				for(Map.Entry<Long, ? extends UIDTag> entry : map.entrySet()) {
					UIDTag tag = entry.getValue();
					// The overall running* map can include local. But the local map can't include non-local.
					if((!local) && tag.wasLocal) continue;
					if(tag.getSource() == source) {
						int out = tag.expectedTransfersOut(ignoreLocalVsRemote, transfersPerInsert, true);
						int in = tag.expectedTransfersIn(ignoreLocalVsRemote);
						count++;
						transfersOut += out;
						transfersIn += in;
						if(counterSR != null && tag.countAsSourceRestarted()) {
							countSR++;
							transfersOutSR += out;
							transfersInSR += in;
						}
						if(logMINOR) Logger.minor(this, "Counting "+tag+" from "+entry.getKey()+" from "+source+" count now "+count+" out now "+transfersOut+" in now "+transfersIn);
					} else if(logDEBUG) Logger.debug(this, "Not counting "+entry.getKey());
				}
				if(logMINOR) Logger.minor(this, "Returning count: "+count+" in: "+transfersIn+" out: "+transfersOut);
				counter.total += count;
				counter.expectedTransfersIn += transfersIn;
				counter.expectedTransfersOut += transfersOut;
				if(counterSR != null) {
					counterSR.total += countSR;
					counterSR.expectedTransfersIn += transfersInSR;
					counterSR.expectedTransfersOut += transfersOutSR;
				}
			} else {
				// hasSourceRestarted is irrelevant for requests *to* a node.
				// FIXME improve efficiency!
				for(Map.Entry<Long, ? extends UIDTag> entry : map.entrySet()) {
					UIDTag tag = entry.getValue();
					// The overall running* map can include local. But the local map can't include non-local.
					if((!local) && tag.wasLocal) continue;
					// Ordinary requests can be routed to an offered key.
					// So we *DO NOT* care whether it's an ordinary routed relayed request or a GetOfferedKey, if we are counting outgoing requests.
					if(tag.currentlyFetchingOfferedKeyFrom(source)) {
						if(logMINOR) Logger.minor(this, "Counting "+tag+" to "+entry.getKey());
						transfersOut += tag.expectedTransfersOut(ignoreLocalVsRemote, transfersPerInsert, false);
						transfersIn += tag.expectedTransfersIn(ignoreLocalVsRemote);
						count++;
					} else if(tag.currentlyRoutingTo(source)) {
						if(logMINOR) Logger.minor(this, "Counting "+tag+" to "+entry.getKey());
						transfersOut += tag.expectedTransfersOut(ignoreLocalVsRemote, transfersPerInsert, false);
						transfersIn += tag.expectedTransfersIn(ignoreLocalVsRemote);
						count++;
					} else if(logDEBUG) Logger.debug(this, "Not counting "+entry.getKey());
				}
				if(logMINOR) Logger.minor(this, "Counted for "+(local?"local":"remote")+" "+(ssk?"ssk":"chk")+" "+(insert?"insert":"request")+" "+(offer?"offer":"")+" : "+count+" of "+map.size()+" for "+source);
				counter.total += count;
				counter.expectedTransfersIn += transfersIn;
				counter.expectedTransfersOut += transfersOut;
			}
		}
	}
	
	/**
	 * Count all requests, by the peer which originated the request.
	 * @param source The peer the requests were accepted from or routed to.
	 * @param local If true, only include requests which originated locally. 
	 * @param ssk If true, count SSK requests, if false, count CHK requests. 
	 * @param insert If true, count inserts, otherwise count requests.
	 * @param offer If true, count offer replies (takes precedence over insert).
	 * @param realTimeFlag If true, count real-time requests, if false, count bulk requests.
	 * @param transfersPerInsert Assume that any insert will cause this many outgoing transfers. 
	 * This is not predictable, so we use an average.
	 * @param ignoreLocalVsRemote If true, pretend that the request is remote even if it's local 
	 * (that is, count imaginary onward transfers etc depending on the request type).
	 * @param counterMap Map from PeerNode to CountedRequests counters. We will use "null" for 
	 * various cases: local requests, requested that have been adopted because their originator
	 * restarted, requests where the originator PeerNode has been removed from the routing table
	 * etc. */
	public void countAllRequestsByIncomingPeer(boolean requestsToNode, boolean local, boolean ssk, boolean insert, boolean offer, boolean realTimeFlag, int transfersPerInsert, boolean ignoreLocalVsRemote, Map<PeerNode, CountedRequests> counterMap) {
		HashMap<Long, ? extends UIDTag> map = getTracker(local, ssk, insert, offer, realTimeFlag);
		// Map is locked by the non-local version, although we're counting from the local version.
		HashMap<Long, ? extends UIDTag> mapLock = map;
		if(local)
			mapLock = getTracker(false, ssk, insert, offer, realTimeFlag);
		synchronized(mapLock) {
			if(!requestsToNode) {
				// If a request is adopted by us as a result of a timeout, it can be in the
				// remote map despite having source == null. However, if a request is in the
				// local map it will always have source == null.
				for(Map.Entry<Long, ? extends UIDTag> entry : map.entrySet()) {
					UIDTag tag = entry.getValue();
					// The overall running* map can include local. But the local map can't include non-local.
					if((!local) && tag.wasLocal) continue;
					PeerNode source = tag.getSource(); // Can be null in various cases
					CountedRequests counter = counterMap.get(source);
					if(counter == null) {
						counter = new CountedRequests();
						counterMap.put(source, counter);
					}
					int out = tag.expectedTransfersOut(ignoreLocalVsRemote, transfersPerInsert, true);
					int in = tag.expectedTransfersIn(ignoreLocalVsRemote);
					counter.total++;
					counter.expectedTransfersIn += in;
					counter.expectedTransfersOut += out;
				}
			}
		}
	}
	
	public class WaitingForSlots {
		int local;
		int remote;
	}
	
	/**
	 * @return [0] is the number of local requests waiting for slots, [1] is the
	 * number of remote requests waiting for slots.
	 */
	public WaitingForSlots countRequestsWaitingForSlots() {
		WaitingForSlots slots = new WaitingForSlots();
		countRequestsWaitingForSlots(runningSSKGetUIDsRT, slots);
		countRequestsWaitingForSlots(runningCHKGetUIDsRT, slots);
		countRequestsWaitingForSlots(runningSSKPutUIDsRT, slots);
		countRequestsWaitingForSlots(runningCHKPutUIDsRT, slots);
		countRequestsWaitingForSlots(runningSSKOfferReplyUIDsRT, slots);
		countRequestsWaitingForSlots(runningCHKOfferReplyUIDsRT, slots);
		countRequestsWaitingForSlots(runningSSKGetUIDsBulk, slots);
		countRequestsWaitingForSlots(runningCHKGetUIDsBulk, slots);
		countRequestsWaitingForSlots(runningSSKPutUIDsBulk, slots);
		countRequestsWaitingForSlots(runningCHKPutUIDsBulk, slots);
		return slots;
	}
	
	private void countRequestsWaitingForSlots(HashMap<Long, ? extends UIDTag> runningUIDs, WaitingForSlots slots) {
		// FIXME use a counter, but that means make sure it always removes it when something bad happens.
		
		synchronized(runningUIDs) {
			for(UIDTag tag : runningUIDs.values()) {
				if(!tag.isWaitingForSlot()) continue;
				if(tag.isLocal())
					slots.local++;
				else
					slots.remote++;
			}
		}
	}

	void reassignTagToSelf(UIDTag tag) {
		// The tag remains remote, but we flag it as adopted.
		tag.reassignToSelf();
	}

	private HashMap<Long, ? extends UIDTag> getTracker(boolean local, boolean ssk,
			boolean insert, boolean offer, boolean realTimeFlag) {
		if(offer)
			return getOfferTracker(ssk, realTimeFlag);
		else if(insert)
			return getInsertTracker(ssk, local, realTimeFlag);
		else
			return getRequestTracker(ssk, local, realTimeFlag);
	}


	private HashMap<Long, RequestTag> getRequestTracker(boolean ssk, boolean local, boolean realTimeFlag) {
		if(realTimeFlag) {
			if(ssk) {
				return local ? runningLocalSSKGetUIDsRT : runningSSKGetUIDsRT;
			} else {
				return local ? runningLocalCHKGetUIDsRT : runningCHKGetUIDsRT;
			}
		} else {
			if(ssk) {
				return local ? runningLocalSSKGetUIDsBulk : runningSSKGetUIDsBulk;
			} else {
				return local ? runningLocalCHKGetUIDsBulk : runningCHKGetUIDsBulk;
			}
		}
	}

	private HashMap<Long, InsertTag> getInsertTracker(boolean ssk, boolean local, boolean realTimeFlag) {
		if(realTimeFlag) {
			if(ssk) {
				return local ? runningLocalSSKPutUIDsRT : runningSSKPutUIDsRT;
			} else {
				return local ? runningLocalCHKPutUIDsRT : runningCHKPutUIDsRT;
			}
		} else {
			if(ssk) {
				return local ? runningLocalSSKPutUIDsBulk : runningSSKPutUIDsBulk;
			} else {
				return local ? runningLocalCHKPutUIDsBulk : runningCHKPutUIDsBulk;
			}
		}
	}

	private HashMap<Long, OfferReplyTag> getOfferTracker(boolean ssk, boolean realTimeFlag) {
		if(realTimeFlag)
			return ssk ? runningSSKOfferReplyUIDsRT : runningCHKOfferReplyUIDsRT;
		else
			return ssk ? runningSSKOfferReplyUIDsBulk : runningCHKOfferReplyUIDsBulk;
	}

	// Must include bulk inserts so fairly long.
	// 21 minutes is enough for a fatal timeout.
	static final long TIMEOUT = MINUTES.toMillis(21);

	void startDeadUIDChecker() {
		ticker.queueTimedJob(deadUIDChecker, TIMEOUT);
	}

	private Runnable deadUIDChecker = new Runnable() {
		@Override
		public void run() {
			try {
				checkUIDs(runningSSKGetUIDsRT);
				checkUIDs(runningCHKGetUIDsRT);
				checkUIDs(runningSSKPutUIDsRT);
				checkUIDs(runningCHKPutUIDsRT);
				checkUIDs(runningSSKOfferReplyUIDsRT);
				checkUIDs(runningCHKOfferReplyUIDsRT);
				checkUIDs(runningSSKGetUIDsBulk);
				checkUIDs(runningCHKGetUIDsBulk);
				checkUIDs(runningSSKPutUIDsBulk);
				checkUIDs(runningCHKPutUIDsBulk);
				checkUIDs(runningSSKOfferReplyUIDsBulk);
				checkUIDs(runningCHKOfferReplyUIDsBulk);
			} finally {
				ticker.queueTimedJob(this, SECONDS.toMillis(60));
			}
		}

		private void checkUIDs(HashMap<Long, ? extends UIDTag> map) {
			Long[] uids;
			UIDTag[] tags;
			synchronized(map) {
				uids = map.keySet().toArray(new Long[map.size()]);
				tags = map.values().toArray(new UIDTag[map.size()]);
			}
			long now = System.currentTimeMillis();
			for(int i=0;i<uids.length;i++) {
				tags[i].maybeLogStillPresent(now, uids[i]);
			}
		}
	};
	

	public void onRestartOrDisconnect(PeerNode pn) {
		onRestartOrDisconnect(pn, runningSSKGetUIDsRT);
		onRestartOrDisconnect(pn, runningCHKGetUIDsRT);
		onRestartOrDisconnect(pn, runningSSKPutUIDsRT);
		onRestartOrDisconnect(pn, runningCHKPutUIDsRT);
		onRestartOrDisconnect(pn, runningSSKOfferReplyUIDsRT);
		onRestartOrDisconnect(pn, runningCHKOfferReplyUIDsRT);
		onRestartOrDisconnect(pn, runningSSKGetUIDsBulk);
		onRestartOrDisconnect(pn, runningCHKGetUIDsBulk);
		onRestartOrDisconnect(pn, runningSSKPutUIDsBulk);
		onRestartOrDisconnect(pn, runningCHKPutUIDsBulk);
		onRestartOrDisconnect(pn, runningSSKOfferReplyUIDsBulk);
		onRestartOrDisconnect(pn, runningCHKOfferReplyUIDsBulk);
	}

	private void onRestartOrDisconnect(PeerNode pn,
			HashMap<Long, ? extends UIDTag> uids) {
		synchronized(uids) {
			for(UIDTag tag : uids.values()) {
				if(tag.isSource(pn))
					tag.onRestartOrDisconnectSource();
			}
		}
	}
	
	public int getNumSSKRequests() {
		int total = 0;
		// running* include all requests, local and remote.
		synchronized(runningSSKGetUIDsBulk) {
			total += runningSSKGetUIDsBulk.size();
		}
		synchronized(runningSSKGetUIDsRT) {
			total += runningSSKGetUIDsRT.size();
		}
		return total;
	}

	public int getNumCHKRequests() {
		int total = 0;
		synchronized(runningCHKGetUIDsBulk) {
			total += runningCHKGetUIDsBulk.size();
		}
		synchronized(runningCHKGetUIDsRT) {
			total += runningCHKGetUIDsRT.size();
		}
		return total;
	}

	public int getNumSSKInserts() {
		int total = 0;
		synchronized(runningSSKPutUIDsBulk) {
			total += runningSSKPutUIDsBulk.size();
		}
		synchronized(runningSSKPutUIDsRT) {
			total += runningSSKPutUIDsRT.size();
		}
		return total;
	}

	public int getNumCHKInserts() {
		int total = 0;
		synchronized(runningCHKPutUIDsBulk) {
			total += runningCHKPutUIDsBulk.size();
		}
		synchronized(runningCHKPutUIDsRT) {
			total += runningCHKPutUIDsRT.size();
		}
		return total;
	}

	public int getNumLocalSSKRequests() {
		int total = 0;
		synchronized(runningSSKGetUIDsBulk) {
			total += runningLocalSSKGetUIDsBulk.size();
		}
		synchronized(runningSSKGetUIDsRT) {
			total += runningLocalSSKGetUIDsRT.size();
		}
		return total;
	}

	public int getNumLocalCHKRequests() {
		int total = 0;
		synchronized(runningCHKGetUIDsBulk) {
			total += runningLocalCHKGetUIDsBulk.size();
		}
		synchronized(runningCHKGetUIDsRT) {
			total += runningLocalCHKGetUIDsRT.size();
		}
		return total;
	}

	public int getNumRemoteCHKRequests() {
		int total = 0;
		synchronized(runningCHKGetUIDsBulk) {
			total += runningCHKGetUIDsBulk.size();
			total -= runningLocalCHKGetUIDsBulk.size();
		}
		synchronized(runningCHKGetUIDsRT) {
			total += runningCHKGetUIDsRT.size();
			total -= runningLocalCHKGetUIDsRT.size();
		}
		return total;
	}

	public int getNumRemoteSSKRequests() {
		int total = 0;
		synchronized(runningSSKGetUIDsBulk) {
			total += runningSSKGetUIDsBulk.size();
			total -= runningLocalSSKGetUIDsBulk.size();
		}
		synchronized(runningSSKGetUIDsRT) {
			total += runningSSKGetUIDsRT.size();
			total -= runningLocalSSKGetUIDsRT.size();
		}
		return total;
	}

	public int getNumLocalCHKInserts() {
		int total = 0;
		synchronized(runningCHKPutUIDsBulk) {
			total += runningLocalCHKPutUIDsBulk.size();
		}
		synchronized(runningCHKPutUIDsRT) {
			total += runningLocalCHKPutUIDsRT.size();
		}
		return total;
	}

	public int getNumLocalSSKInserts() {
		int total = 0;
		synchronized(runningSSKPutUIDsBulk) {
			total += runningLocalSSKPutUIDsBulk.size();
		}
		synchronized(runningSSKPutUIDsRT) {
			total += runningLocalSSKPutUIDsRT.size();
		}
		return total;
	}

	public int getNumRemoteCHKInserts() {
		int total = 0;
		synchronized(runningCHKPutUIDsBulk) {
			total += runningCHKPutUIDsBulk.size() - runningLocalCHKPutUIDsBulk.size();
		}
		synchronized(runningCHKPutUIDsRT) {
			total += runningCHKPutUIDsRT.size() - runningLocalCHKPutUIDsRT.size();
		}
		return total;
	}

	public int getNumRemoteSSKInserts() {
		int total = 0;
		synchronized(runningSSKPutUIDsRT) {
			total += runningSSKPutUIDsRT.size() - runningLocalSSKPutUIDsRT.size();
		}
		synchronized(runningSSKPutUIDsBulk) {
			total += runningSSKPutUIDsBulk.size() - runningLocalSSKPutUIDsBulk.size();
		}
		return total;
	}

	public int getNumSSKOfferReplies() {
		int total = 0;
		synchronized(runningSSKOfferReplyUIDsRT) {
			total += runningSSKOfferReplyUIDsRT.size();
		}
		synchronized(runningSSKOfferReplyUIDsBulk) {
			total += runningSSKOfferReplyUIDsBulk.size();
		}
		return total;
	}

	public int getNumCHKOfferReplies() {
		int total = 0;
		synchronized(runningCHKOfferReplyUIDsRT) {
			total += runningCHKOfferReplyUIDsRT.size();
		}
		synchronized(runningCHKOfferReplyUIDsBulk) {
			total += runningCHKOfferReplyUIDsBulk.size();
		}
		return total;
	}

	public int getNumSSKOfferReplies(boolean realTimeFlag) {
		return realTimeFlag ? runningSSKOfferReplyUIDsRT.size() : runningSSKOfferReplyUIDsBulk.size();
	}

	public int getNumCHKOfferReplies(boolean realTimeFlag) {
		return realTimeFlag ? runningCHKOfferReplyUIDsRT.size() : runningCHKOfferReplyUIDsBulk.size();
	}

	public void addRunningUIDs(List<Long> list) {
		addRunningUIDs(runningSSKGetUIDsRT, list);
		addRunningUIDs(runningCHKGetUIDsRT, list);
		addRunningUIDs(runningSSKPutUIDsRT, list);
		addRunningUIDs(runningCHKPutUIDsRT, list);
		addRunningUIDs(runningSSKOfferReplyUIDsRT, list);
		addRunningUIDs(runningCHKOfferReplyUIDsRT, list);
		addRunningUIDs(runningSSKGetUIDsBulk, list);
		addRunningUIDs(runningCHKGetUIDsBulk, list);
		addRunningUIDs(runningSSKPutUIDsBulk, list);
		addRunningUIDs(runningCHKPutUIDsBulk, list);
		addRunningUIDs(runningSSKOfferReplyUIDsBulk, list);
		addRunningUIDs(runningCHKOfferReplyUIDsBulk, list);
	}
	
	private void addRunningUIDs(HashMap<Long, ? extends UIDTag> runningUIDs, List<Long> list) {
		synchronized(runningUIDs) {
			list.addAll(runningUIDs.keySet());
		}
	}

	public int getTotalRunningUIDsAlt() {
		return this.runningCHKGetUIDsRT.size() + this.runningCHKPutUIDsRT.size() + this.runningSSKGetUIDsRT.size() +
		this.runningSSKPutUIDsRT.size() + this.runningSSKOfferReplyUIDsRT.size() + this.runningCHKOfferReplyUIDsRT.size() +
		this.runningCHKGetUIDsBulk.size() + this.runningCHKPutUIDsBulk.size() + this.runningSSKGetUIDsBulk.size() +
		this.runningSSKPutUIDsBulk.size() + this.runningSSKOfferReplyUIDsBulk.size() + this.runningCHKOfferReplyUIDsBulk.size();
	}

	private ArrayList<Long> completedBuffer = new ArrayList<Long>();

	// Every this many slots, we tell all the PeerMessageQueue's to remove the old Items for the ID's in question.
	// This prevents memory DoS amongst other things.
	static final int COMPLETED_THRESHOLD = 128;

	/**
	 * A request completed (regardless of success).
	 */
	void completed(long id) {
		Long[] list;
		synchronized (completedBuffer) {
			completedBuffer.add(id);
			if(completedBuffer.size() < COMPLETED_THRESHOLD) return;
			list = completedBuffer.toArray(new Long[completedBuffer.size()]);
			completedBuffer.clear();
		}
		for(PeerNode pn : peers.myPeers()) {
			if(!pn.isRoutingCompatible()) continue;
			pn.removeUIDsFromMessageQueues(list);
		}
	}

	public RequestSender getTransferringRequestSenderByKey(NodeCHK key, boolean realTimeFlag) {
		HashMap<NodeCHK, RequestSender> transferringRequestSenders =
			realTimeFlag ? transferringRequestSendersRT : transferringRequestSendersBulk;
		synchronized(transferringRequestSenders) {
			return transferringRequestSenders.get(key);
		}
	}
	
	/**
	 * Add a transferring RequestSender to our HashMap.
	 * Should only be called by UIDTag.
	 */
	public void addTransferringSender(NodeCHK key, RequestSender sender) {
		HashMap<NodeCHK, RequestSender> transferringRequestSenders =
			sender.realTimeFlag ? transferringRequestSendersRT : transferringRequestSendersBulk;
		synchronized(transferringRequestSenders) {
			transferringRequestSenders.put(key, sender);
		}
	}

	/** Should only be called by RequestTag. */
	void addTransferringRequestHandler(long id) {
		synchronized(transferringRequestHandlers) {
			transferringRequestHandlers.add(id);
		}
	}

	/** Should only be called by RequestTag. */
	void removeTransferringRequestHandler(long id) {
		synchronized(transferringRequestHandlers) {
			transferringRequestHandlers.remove(id);
		}
	}

	/**
	 * Remove a sender from the set of currently transferring senders.
	 */
	public void removeTransferringSender(NodeCHK key, RequestSender sender) {
		HashMap<NodeCHK, RequestSender> transferringRequestSenders =
			sender.realTimeFlag ? transferringRequestSendersRT : transferringRequestSendersBulk;
		synchronized(transferringRequestSenders) {
//			RequestSender rs = (RequestSender) transferringRequestSenders.remove(key);
//			if(rs != sender) {
//				Logger.error(this, "Removed "+rs+" should be "+sender+" for "+key+" in removeTransferringSender");
//			}

			// Since there is no request coalescing, we only remove it if it matches,
			// and don't complain if it doesn't.
			if(transferringRequestSenders.get(key) == sender)
				transferringRequestSenders.remove(key);
		}
	}

	public int getNumTransferringRequestSenders() {
		int total = 0;
		synchronized(transferringRequestSendersRT) {
			total += transferringRequestSendersRT.size();
		}
		synchronized(transferringRequestSendersBulk) {
			total += transferringRequestSendersBulk.size();
		}
		return total;
	}

	public int getNumTransferringRequestHandlers() {
		synchronized(transferringRequestHandlers) {
			return transferringRequestHandlers.size();
		}
	}


}
