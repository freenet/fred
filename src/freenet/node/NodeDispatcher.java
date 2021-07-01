/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.concurrent.ArrayBlockingQueue;

import freenet.crypt.HMAC;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.Dispatcher;
import freenet.io.comm.Message;
import freenet.io.comm.MessageType;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.Peer;
import freenet.keys.Key;
import freenet.keys.KeyBlock;
import freenet.keys.NodeCHK;
import freenet.keys.NodeSSK;
import freenet.node.NodeStats.Accept;
import freenet.node.NodeStats.AcceptStatus;
import freenet.node.NodeStats.PeerLoadStats;
import freenet.node.NodeStats.RejectReason;
import freenet.node.probe.Probe;
import freenet.store.BlockMetadata;
import freenet.support.Fields;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.ShortBuffer;
import freenet.support.io.NativeThread;

/**
 * @author amphibian
 * 
 * Dispatcher for unmatched FNP messages.
 * 
 * What can we get?
 * 
 * SwapRequests
 * 
 * DataRequests
 * 
 * InsertRequests
 * 
 * Probably a few others; those are the important bits.
 * 
 * Requests:
 * - Loop detection only works when the request is actually running. We do
 * NOT remember what UID's we have routed in the past. Hence there is no
 * possibility of an attacker probing for old UID's. Also, even in the rare-ish
 * case where a request forks because an Accepted is delayed, this isn't a
 * big problem: Since we moved on, we're not waiting for it, there will be
 * no timeout/snarl-up beyond what has already happened. 
 * - We should parse the message completely before checking the UID, 
 * overload, and passing it to the handler. Invalid requests should never
 * be accepted. However, because of inserts, we cannot guarantee that we
 * never check the UID before we know the request is fully routable.  
 */
public class NodeDispatcher implements Dispatcher, Runnable {

	private static volatile boolean logMINOR;
	private static volatile boolean logDEBUG;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
				logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}

	final Node node;
	final RequestTracker tracker;
	private NodeStats nodeStats;
	private NodeDispatcherCallback callback;
	final Probe probe;
	
	private static final long STALE_CONTEXT=20000;
	private static final long STALE_CONTEXT_CHECK=20000;

	NodeDispatcher(Node node) {
		this.node = node;
		this.tracker = node.tracker;
		this.nodeStats = node.nodeStats;
		node.getTicker().queueTimedJob(this, STALE_CONTEXT_CHECK);
		this.probe = new Probe(node);
	}

	ByteCounter pingCounter = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			node.nodeStats.pingCounterReceived(x);
		}

		@Override
		public void sentBytes(int x) {
			node.nodeStats.pingCounterSent(x);
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}
		
	};
	
	public interface NodeDispatcherCallback {
		public void snoop(Message m, Node n);
	}
	
	@Override
	public boolean handleMessage(Message m) {
		PeerNode source = (PeerNode)m.getSource();
		if(source == null) {
			// Node has been disconnected and garbage collected already! Ouch.
			return true;
		}
		if(logMINOR) Logger.minor(this, "Dispatching "+m+" from "+source);
		if(callback != null) {
			try {
				callback.snoop(m, node);
			} catch (Throwable t) {
				Logger.error(this, "Callback threw "+t, t);
			}
		}
		MessageType spec = m.getSpec();
		if(spec == DMT.FNPPing) {
			// Send an FNPPong
			Message reply = DMT.createFNPPong(m.getInt(DMT.PING_SEQNO));
			try {
				source.sendAsync(reply, null, pingCounter); // nothing we can do if can't contact source
			} catch (NotConnectedException e) {
				if(logMINOR) Logger.minor(this, "Lost connection replying to "+m);
			}
			return true;
		} else if(spec == DMT.FNPDetectedIPAddress) {
			Peer p = (Peer) m.getObject(DMT.EXTERNAL_ADDRESS);
			source.setRemoteDetectedPeer(p);
			node.ipDetector.redetectAddress();
			return true;
		} else if(spec == DMT.FNPTime) {
			return handleTime(m, source);
		} else if(spec == DMT.FNPUptime) {
			return handleUptime(m, source);
		} else if(spec == DMT.FNPVisibility && source instanceof DarknetPeerNode) {
			((DarknetPeerNode)source).handleVisibility(m);
			return true;
		} else if(spec == DMT.FNPVoid) {
			return true;
		} else if(spec == DMT.FNPDisconnect) {
			handleDisconnect(m, source);
			return true;
		} else if(spec == DMT.nodeToNodeMessage) {
			node.receivedNodeToNodeMessage(m, source);
			return true;
		} else if(spec == DMT.UOMAnnouncement && source.isRealConnection()) {
			return node.nodeUpdater.uom.handleAnnounce(m, source);
		} else if(spec == DMT.UOMRequestRevocation && source.isRealConnection()) {
			return node.nodeUpdater.uom.handleRequestRevocation(m, source);
		} else if(spec == DMT.UOMSendingRevocation && source.isRealConnection()) {
			return node.nodeUpdater.uom.handleSendingRevocation(m, source);
		} else if(spec == DMT.UOMRequestMainJar && node.nodeUpdater.isEnabled() && source.isRealConnection()) {
			node.nodeUpdater.uom.handleRequestJar(m, source);
			return true;
		} else if(spec == DMT.UOMSendingMainJar && node.nodeUpdater.isEnabled() && source.isRealConnection()) {
			return node.nodeUpdater.uom.handleSendingMain(m, source);
		} else if(spec == DMT.UOMFetchDependency && node.nodeUpdater.isEnabled() && source.isRealConnection()) {
			node.nodeUpdater.uom.handleFetchDependency(m, source);
			return true;
		} else if(spec == DMT.FNPOpennetAnnounceRequest) {
			return handleAnnounceRequest(m, source);
		} else if(spec == DMT.FNPRoutingStatus) {
			if(source instanceof DarknetPeerNode) {
				boolean value = m.getBoolean(DMT.ROUTING_ENABLED);
				if(logMINOR)
					Logger.minor(this, "The peer ("+source+") asked us to set routing="+value);
				((DarknetPeerNode)source).setRoutingStatus(value, false);
			}
			// We claim it in any case
			return true;
		} else if(source.isRealConnection() && spec == DMT.FNPLocChangeNotificationNew) {
			double newLoc = m.getDouble(DMT.LOCATION);
			ShortBuffer buffer = ((ShortBuffer) m.getObject(DMT.PEER_LOCATIONS));
			double[] locs = Fields.bytesToDoubles(buffer.getData());
			
			/**
			 * Do *NOT* remove the sanity check below! 
			 * @see http://archives.freenetproject.org/message/20080718.144240.359e16d3.en.html
			 */
			if((OpennetManager.MAX_PEERS_FOR_SCALING < locs.length) && (source.isOpennet())) {
				if(locs.length > OpennetManager.PANIC_MAX_PEERS) {
					// This can't happen by accident
					Logger.error(this, "We received "+locs.length+ " locations from "+source.toString()+"! That should *NOT* happen! Possible attack!");
					source.forceDisconnect();
					return true;
				} else {
					// A few extra can happen by accident. Just use the first 20.
					Logger.normal(this, "Too many locations from "+source.toString()+" : "+locs.length+" could be an accident, using the first "+OpennetManager.MAX_PEERS_FOR_SCALING);
					locs = Arrays.copyOf(locs, OpennetManager.MAX_PEERS_FOR_SCALING);
				}
			}
			// We are on darknet and we trust our peers OR we are on opennet
			// and the amount of locations sent to us seems reasonable
			source.updateLocation(newLoc, locs);
			
			return true;
		} else if(spec == DMT.FNPPeerLoadStatusByte || spec == DMT.FNPPeerLoadStatusShort || spec == DMT.FNPPeerLoadStatusInt) {
			// Must be handled before doing the routable check!
			// We may not have received the Location yet, etc.
			return handlePeerLoadStatus(m, source);
		}
		
		if(!source.isRoutable()) {
			if(logDEBUG) Logger.debug(this, "Not routable");

			if(spec == DMT.FNPCHKDataRequest) {
				rejectRequest(m, node.nodeStats.chkRequestCtr);
			} else if(spec == DMT.FNPSSKDataRequest) {
				rejectRequest(m, node.nodeStats.sskRequestCtr);
			} else if(spec == DMT.FNPInsertRequest) {
				rejectRequest(m, node.nodeStats.chkInsertCtr);
			} else if(spec == DMT.FNPSSKInsertRequest) {
				rejectRequest(m, node.nodeStats.sskInsertCtr);
			} else if(spec == DMT.FNPSSKInsertRequestNew) {
				rejectRequest(m, node.nodeStats.sskInsertCtr);
			} else if(spec == DMT.FNPGetOfferedKey) {
				rejectRequest(m, node.failureTable.senderCounter);
			} else {
				return false;
			}
			return true;
		}

		if(spec == DMT.FNPSwapRequest) {
			return node.lm.handleSwapRequest(m, source);
		} else if(spec == DMT.FNPSwapReply) {
			return node.lm.handleSwapReply(m, source);
		} else if(spec == DMT.FNPSwapRejected) {
			return node.lm.handleSwapRejected(m, source);
		} else if(spec == DMT.FNPSwapCommit) {
			return node.lm.handleSwapCommit(m, source);
		} else if(spec == DMT.FNPSwapComplete) {
			return node.lm.handleSwapComplete(m, source);
		} else if(spec == DMT.FNPCHKDataRequest) {
			handleDataRequest(m, source, false);
			return true;
		} else if(spec == DMT.FNPSSKDataRequest) {
			handleDataRequest(m, source, true);
			return true;
		} else if(spec == DMT.FNPInsertRequest) {
			handleInsertRequest(m, source, false);
			return true;
		} else if(spec == DMT.FNPSSKInsertRequest) {
			handleInsertRequest(m, source, true);
			return true;
		} else if(spec == DMT.FNPSSKInsertRequestNew) {
			handleInsertRequest(m, source, true);
			return true;
		} else if(spec == DMT.FNPRoutedPing) {
			return handleRouted(m, source);
		} else if(spec == DMT.FNPRoutedPong) {
			return handleRoutedReply(m);
		} else if(spec == DMT.FNPRoutedRejected) {
			return handleRoutedRejected(m);
		} else if(spec == DMT.FNPOfferKey) {
			return handleOfferKey(m, source);
		} else if(spec == DMT.FNPGetOfferedKey) {
			return handleGetOfferedKey(m, source);
		} else if(spec == DMT.FNPGetYourFullNoderef && source instanceof DarknetPeerNode) {
			((DarknetPeerNode)source).sendFullNoderef();
			return true;
		} else if(spec == DMT.FNPMyFullNoderef && source instanceof DarknetPeerNode) {
			((DarknetPeerNode)source).handleFullNoderef(m);
			return true;
		} else if(spec == DMT.ProbeRequest) {
			//Response is handled by callbacks within probe.
			probe.request(m, source);
			return true;
		}
		return false;
	}

	private void rejectRequest(Message m, ByteCounter ctr) {
		long uid = m.getLong(DMT.UID);
		Message msg = DMT.createFNPRejectedOverload(uid, true, false, false);
		// Send the load status anyway, hopefully this is a temporary problem.
		msg.setNeedsLoadBulk();
		msg.setNeedsLoadRT();
		try {
			m.getSource().sendAsync(msg, null, ctr);
		} catch (NotConnectedException e) {
			// Ignore
		}
	}

	private boolean handlePeerLoadStatus(Message m, PeerNode source) {
		PeerLoadStats stat = node.nodeStats.parseLoadStats(source, m);
		source.reportLoadStatus(stat);
		return true;
	}

	private boolean handleUptime(Message m, PeerNode source) {
		byte uptime = m.getByte(DMT.UPTIME_PERCENT_48H);
		source.setUptime(uptime);
		return true;
	}

	private boolean handleOfferKey(Message m, PeerNode source) {
		Key key = (Key) m.getObject(DMT.KEY);
		byte[] authenticator = ((ShortBuffer) m.getObject(DMT.OFFER_AUTHENTICATOR)).getData();
		node.failureTable.onOffer(key, source, authenticator);
		return true;
	}

	private boolean handleGetOfferedKey(Message m, PeerNode source) {
		Key key = (Key) m.getObject(DMT.KEY);
		byte[] authenticator = ((ShortBuffer) m.getObject(DMT.OFFER_AUTHENTICATOR)).getData();
		long uid = m.getLong(DMT.UID);
		if(!HMAC.verifyWithSHA256(node.failureTable.offerAuthenticatorKey, key.getFullKey(), authenticator)) {
			Logger.error(this, "Invalid offer request from "+source+" : authenticator did not verify");
			try {
				source.sendAsync(DMT.createFNPGetOfferedKeyInvalid(uid, DMT.GET_OFFERED_KEY_REJECTED_BAD_AUTHENTICATOR), null, node.failureTable.senderCounter);
			} catch (NotConnectedException e) {
				// Too bad.
			}
			return true;
		}
		if(logMINOR) Logger.minor(this, "Valid GetOfferedKey for "+key+" from "+source);
		
		// Do we want it? We can RejectOverload if we don't have the bandwidth...
		boolean isSSK = key instanceof NodeSSK;
        boolean realTimeFlag = DMT.getRealTimeFlag(m);
		OfferReplyTag tag = new OfferReplyTag(isSSK, source, realTimeFlag, uid, node);
		
		if(!tracker.lockUID(uid, isSSK, false, true, false, realTimeFlag, tag)) {
			if(logMINOR) Logger.minor(this, "Could not lock ID "+uid+" -> rejecting (already running)");
			Message rejected = DMT.createFNPRejectedLoop(uid);
			try {
				source.sendAsync(rejected, null, node.failureTable.senderCounter);
			} catch (NotConnectedException e) {
				Logger.normal(this, "Rejecting request from "+source.getPeer()+": "+e);
			}
			return true;
		} else {
			if(logMINOR) Logger.minor(this, "Locked "+uid);
		}
		boolean needPubKey;
		try {
		needPubKey = m.getBoolean(DMT.NEED_PUB_KEY);
		AcceptStatus status = 
			nodeStats.shouldRejectRequest(true, false, isSSK, false, true, source, false, false, realTimeFlag, tag);
		if(status != null && !status.accept()) {
		    RejectReason reject = (RejectReason) status;
			Logger.normal(this, "Rejecting FNPGetOfferedKey from "+source+" for "+key+" : "+reject);
			Message rejected = DMT.createFNPRejectedOverload(uid, true, true, realTimeFlag);
			if(reject.soft)
				rejected.addSubMessage(DMT.createFNPRejectIsSoft());
			try {
				source.sendAsync(rejected, null, node.failureTable.senderCounter);
			} catch (NotConnectedException e) {
				Logger.normal(this, "Rejecting (overload) data request from "+source.getPeer()+": "+e);
			}
			tag.unlockHandler(reject.soft);
			return true;
		}
		
        if(status != null && status.slowDown()) {
            Message rejected = DMT.createFNPRejectedOverload(uid, false, true, realTimeFlag);
            try {
                source.sendAsync(rejected, null, node.failureTable.senderCounter);
            } catch (NotConnectedException e) {
                // Ignore
            }
        }
        
		} catch (Error e) {
			tag.unlockHandler();
			throw e;
		} catch (RuntimeException e) {
			tag.unlockHandler();
			throw e;
		} // Otherwise, sendOfferedKey is responsible for unlocking. 
		
		// Accept it.
		

		
		try {
			node.failureTable.sendOfferedKey(key, isSSK, needPubKey, uid, source, tag,realTimeFlag);
		} catch (NotConnectedException e) {
			// Too bad.
		}
		return true;
	}

	private void handleDisconnect(final Message m, final PeerNode source) {
		// Wait for 1 second to ensure that the ack gets sent first.
		node.getTicker().queueTimedJob(new Runnable() {
			@Override
			public void run() {
				finishDisconnect(m, source);
			}
		}, 1000);
	}
	
	private void finishDisconnect(final Message m, final PeerNode source) {
		source.disconnected(true, true);
		// If true, remove from active routing table, likely to be down for a while.
		// Otherwise just dump all current connection state and keep trying to connect.
		boolean remove = m.getBoolean(DMT.REMOVE);
		if(remove) {
			node.peers.disconnectAndRemove(source, false, false, false);
			if(source instanceof DarknetPeerNode)
				// FIXME remove, dirty logs.
				// FIXME add a useralert?
				System.out.println("Disconnecting permanently from your friend \""+((DarknetPeerNode)source).getName()+"\" because they asked us to remove them.");
		}
		// If true, purge all references to this node. Otherwise, we can keep the node
		// around in secondary tables etc in order to more easily reconnect later. 
		// (Mostly used on opennet)
		boolean purge = m.getBoolean(DMT.PURGE);
		if(purge) {
			OpennetManager om = node.getOpennet();
			if(om != null && source instanceof OpennetPeerNode)
				om.purgeOldOpennetPeer((OpennetPeerNode)source);
		}
		// Process parting message
		int type = m.getInt(DMT.NODE_TO_NODE_MESSAGE_TYPE);
		ShortBuffer messageData = (ShortBuffer) m.getObject(DMT.NODE_TO_NODE_MESSAGE_DATA);
		if(messageData.getLength() == 0) return;
		node.receivedNodeToNodeMessage(source, type, messageData, true);
	}

	private boolean handleTime(Message m, PeerNode source) {
		long delta = m.getLong(DMT.TIME) - System.currentTimeMillis();
		source.setTimeDelta(delta);
		return true;
	}

	// We need to check the datastore before deciding whether to accept a request.
	// This can block - in bad cases, for a long time.
	// So we need to run it on a separate thread.
	
	private final PrioRunnable queueRunner = new PrioRunnable() {

		@Override
		public void run() {
			while(true) {
				try {
					Message msg = requestQueue.take();
					boolean isSSK = msg.getSpec() == DMT.FNPSSKDataRequest;
					innerHandleDataRequest(msg, (PeerNode)msg.getSource(), isSSK);
				} catch (InterruptedException e) {
					// Ignore
				}
			}
		}

		@Override
		public int getPriority() {
			// Slightly less than the actual requests themselves because accepting requests increases load.
			return NativeThread.HIGH_PRIORITY-1;
		}
		
	};
	
	private final ArrayBlockingQueue<Message> requestQueue = new ArrayBlockingQueue<Message>(100);
	
	private void handleDataRequest(Message m, PeerNode source, boolean isSSK) {
		// FIXME check probablyInStore and if not, we can handle it inline.
		// This and DatastoreChecker require that method be implemented...
		// For now just handle everything on the thread...
		if(!requestQueue.offer(m)) {
			rejectRequest(m, isSSK ? node.nodeStats.sskRequestCtr : node.nodeStats.chkRequestCtr);
		}
	}
	
	/**
	 * Handle an incoming FNPDataRequest. We should parse it and determine 
	 * whether it is valid before we accept it.
	 */
	private void innerHandleDataRequest(Message m, PeerNode source, boolean isSSK) {
		if(!source.isConnected()) {
			if(logMINOR) Logger.minor(this, "Handling request off thread, source disconnected: "+source+" for "+m);
			return;
		}
		if(!source.isRoutable()) {
			if(logMINOR) Logger.minor(this, "Handling request off thread, source no longer routable: "+source+" for "+m);
			rejectRequest(m, isSSK ? node.nodeStats.sskRequestCtr : node.nodeStats.chkRequestCtr);
			return;
		}
		long id = m.getLong(DMT.UID);
		ByteCounter ctr = isSSK ? node.nodeStats.sskRequestCtr : node.nodeStats.chkRequestCtr;
        short htl = m.getShort(DMT.HTL);
		if(htl <= 0) htl = 1;
        Key key = (Key) m.getObject(DMT.FREENET_ROUTING_KEY);
        boolean realTimeFlag = DMT.getRealTimeFlag(m);
        final RequestTag tag = new RequestTag(isSSK, RequestTag.START.REMOTE, source, realTimeFlag, id, node);
		if(!tracker.lockUID(id, isSSK, false, false, false, realTimeFlag, tag)) {
			if(logMINOR) Logger.minor(this, "Could not lock ID "+id+" -> rejecting (already running)");
			Message rejected = DMT.createFNPRejectedLoop(id);
			try {
				source.sendAsync(rejected, null, ctr);
			} catch (NotConnectedException e) {
				Logger.normal(this, "Rejecting request from "+source.getPeer()+": "+e);
			}
			node.failureTable.onFinalFailure(key, null, htl, htl, -1, -1, source);
			return;
		} else {
			if(logMINOR) Logger.minor(this, "Locked "+id);
		}
		
		// There are at least 2 threads that call this function.
		// DO NOT reuse the meta object, unless on a per-thread basis.
		// Object allocation is pretty cheap in modern Java anyway...
		// If we do reuse it, call reset().
		BlockMetadata meta = new BlockMetadata();
		KeyBlock block = node.fetch(key, false, false, false, false, meta);
		if(block != null)
			tag.setNotRoutedOnwards();
		
		AcceptStatus status = nodeStats.shouldRejectRequest(!isSSK, false, isSSK, false, false, source, block != null, false, realTimeFlag, tag);
		if(status != null && !status.accept()) {
		    RejectReason rejectReason = (RejectReason) status;
			// can accept 1 CHK request every so often, but not with SSKs because they aren't throttled so won't sort out bwlimitDelayTime, which was the whole reason for accepting them when overloaded...
			Logger.normal(this, "Rejecting "+(isSSK ? "SSK" : "CHK")+" request from "+source.getPeer()+" preemptively because "+rejectReason);
			Message rejected = DMT.createFNPRejectedOverload(id, true, true, realTimeFlag);
			if(rejectReason.soft)
				rejected.addSubMessage(DMT.createFNPRejectIsSoft());
			try {
				source.sendAsync(rejected, null, ctr);
			} catch (NotConnectedException e) {
				Logger.normal(this, "Rejecting (overload) data request from "+source.getPeer()+": "+e);
			}
			tag.setRejected();
			tag.unlockHandler(rejectReason.soft);
			// Do not tell failure table.
			// Otherwise an attacker can flood us with requests very cheaply and purge our
			// failure table even though we didn't accept any of them.
			return;
		}
        if(status != null && status.slowDown()) {
            Message rejected = DMT.createFNPRejectedOverload(id, false, true, realTimeFlag);
            try {
                source.sendAsync(rejected, null, node.failureTable.senderCounter);
            } catch (NotConnectedException e) {
                // Ignore
            }
        }
		nodeStats.reportIncomingRequestLocation(key.toNormalizedDouble());
		//if(!node.lockUID(id)) return false;
		boolean needsPubKey = false;
		if(key instanceof NodeSSK)
			needsPubKey = m.getBoolean(DMT.NEED_PUB_KEY);
		RequestHandler rh = new RequestHandler(source, id, node, htl, key, tag, block, realTimeFlag, needsPubKey);
		rh.receivedBytes(m.receivedByteCount());
		node.executor.execute(rh, "RequestHandler for UID "+id+" on "+node.getDarknetPortNumber());
	}

	/**
	 * Handle an incoming insert. We should parse it and determine whether it
	 * is valid before we accept it. However in the case of inserts it *IS* 
	 * possible for the request sender to cause it to fail later during the 
	 * receive of the data or the DataInsert.
	 * @param m The incoming message.
	 * @param source The node that sent the message.
	 * @param isSSK True if it is an SSK insert, false if it is a CHK insert.
	 */
	private void handleInsertRequest(Message m, PeerNode source, boolean isSSK) {
		ByteCounter ctr = isSSK ? node.nodeStats.sskInsertCtr : node.nodeStats.chkInsertCtr;
		long id = m.getLong(DMT.UID);
        boolean realTimeFlag = DMT.getRealTimeFlag(m);
		InsertTag tag = new InsertTag(isSSK, InsertTag.START.REMOTE, source, realTimeFlag, id, node);
		if(!tracker.lockUID(id, isSSK, true, false, false, realTimeFlag, tag)) {
			if(logMINOR) Logger.minor(this, "Could not lock ID "+id+" -> rejecting (already running)");
			Message rejected = DMT.createFNPRejectedLoop(id);
			try {
				source.sendAsync(rejected, null, ctr);
			} catch (NotConnectedException e) {
				Logger.normal(this, "Rejecting insert request from "+source.getPeer()+": "+e);
			}
			return;
		}
		boolean preferInsert = Node.PREFER_INSERT_DEFAULT;
		boolean ignoreLowBackoff = Node.IGNORE_LOW_BACKOFF_DEFAULT;
		boolean forkOnCacheable = Node.FORK_ON_CACHEABLE_DEFAULT;
		Message forkControl = m.getSubMessage(DMT.FNPSubInsertForkControl);
		if(forkControl != null)
			forkOnCacheable = forkControl.getBoolean(DMT.ENABLE_INSERT_FORK_WHEN_CACHEABLE);
		Message lowBackoff = m.getSubMessage(DMT.FNPSubInsertIgnoreLowBackoff);
		if(lowBackoff != null)
			ignoreLowBackoff = lowBackoff.getBoolean(DMT.IGNORE_LOW_BACKOFF);
		Message preference = m.getSubMessage(DMT.FNPSubInsertPreferInsert);
		if(preference != null)
			preferInsert = preference.getBoolean(DMT.PREFER_INSERT);
		// SSKs don't fix bwlimitDelayTime so shouldn't be accepted when overloaded.
		AcceptStatus status = nodeStats.shouldRejectRequest(!isSSK, true, isSSK, false, false, source, false, preferInsert, realTimeFlag, tag);
		if(status != null && !status.accept()) {
		    RejectReason rejectReason = (RejectReason) status;
			Logger.normal(this, "Rejecting insert from "+source.getPeer()+" preemptively because "+rejectReason);
			Message rejected = DMT.createFNPRejectedOverload(id, true, true, realTimeFlag);
			if(rejectReason.soft)
				rejected.addSubMessage(DMT.createFNPRejectIsSoft());
			try {
				source.sendAsync(rejected, null, ctr);
			} catch (NotConnectedException e) {
				Logger.normal(this, "Rejecting (overload) insert request from "+source.getPeer()+": "+e);
			}
			tag.unlockHandler(rejectReason.soft);
			return;
		}
        if(status != null && status.slowDown()) {
            Message rejected = DMT.createFNPRejectedOverload(id, false, true, realTimeFlag);
            try {
                source.sendAsync(rejected, null, node.failureTable.senderCounter);
            } catch (NotConnectedException e) {
                // Ignore
            }
        }
		long now = System.currentTimeMillis();
		if(m.getSpec().equals(DMT.FNPSSKInsertRequest)) {
			NodeSSK key = (NodeSSK) m.getObject(DMT.FREENET_ROUTING_KEY);
	        byte[] data = ((ShortBuffer) m.getObject(DMT.DATA)).getData();
	        byte[] headers = ((ShortBuffer) m.getObject(DMT.BLOCK_HEADERS)).getData();
	        short htl = m.getShort(DMT.HTL);
			if(htl <= 0) htl = 1;
			SSKInsertHandler rh = new SSKInsertHandler(key, data, headers, htl, source, id, node, now, tag, node.canWriteDatastoreInsert(htl), forkOnCacheable, preferInsert, ignoreLowBackoff, realTimeFlag);
	        rh.receivedBytes(m.receivedByteCount());
			node.executor.execute(rh, "SSKInsertHandler for "+id+" on "+node.getDarknetPortNumber());
		} else if(m.getSpec().equals(DMT.FNPSSKInsertRequestNew)) {
			NodeSSK key = (NodeSSK) m.getObject(DMT.FREENET_ROUTING_KEY);
			short htl = m.getShort(DMT.HTL);
			if(htl <= 0) htl = 1;
			SSKInsertHandler rh = new SSKInsertHandler(key, null, null, htl, source, id, node, now, tag, node.canWriteDatastoreInsert(htl), forkOnCacheable, preferInsert, ignoreLowBackoff, realTimeFlag);
	        rh.receivedBytes(m.receivedByteCount());
			node.executor.execute(rh, "SSKInsertHandler for "+id+" on "+node.getDarknetPortNumber());
		} else {
	        NodeCHK key = (NodeCHK) m.getObject(DMT.FREENET_ROUTING_KEY);
	        short htl = m.getShort(DMT.HTL);
			if(htl <= 0) htl = 1;
			CHKInsertHandler rh = new CHKInsertHandler(key, htl, source, id, node, now, tag, forkOnCacheable, preferInsert, ignoreLowBackoff, realTimeFlag);
	        rh.receivedBytes(m.receivedByteCount());
			node.executor.execute(rh, "CHKInsertHandler for "+id+" on "+node.getDarknetPortNumber());
		}
		if(logMINOR) Logger.minor(this, "Started InsertHandler for "+id);
	}
	
	private boolean handleAnnounceRequest(Message m, PeerNode source) {
		long uid = m.getLong(DMT.UID);
		double target = m.getDouble(DMT.TARGET_LOCATION); // FIXME validate
		short htl = (short) Math.min(m.getShort(DMT.HTL), node.maxHTL());
		long xferUID = m.getLong(DMT.TRANSFER_UID);
		int noderefLength = m.getInt(DMT.NODEREF_LENGTH);
		int paddedLength = m.getInt(DMT.PADDED_LENGTH);

		// Only accept a valid message. See comments at top of NodeDispatcher, but it's a good idea anyway.
		if(target < 0.0 || target >= 1.0 || htl <= 0 || 
				paddedLength < 0 || paddedLength > OpennetManager.MAX_OPENNET_NODEREF_LENGTH ||
				noderefLength > paddedLength) {
			Message msg = DMT.createFNPRejectedOverload(uid, true, false, false);
			try {
				source.sendAsync(msg, null, node.nodeStats.announceByteCounter);
			} catch (NotConnectedException e) {
				// OK
			}
			if(logMINOR) Logger.minor(this, "Got bogus announcement message from "+source);
			return true;
		}
		
		OpennetManager om = node.getOpennet();
		if(om == null || !source.canAcceptAnnouncements()) {
			if(om != null && source instanceof SeedClientPeerNode)
				om.seedTracker.rejectedAnnounce((SeedClientPeerNode)source);
			Message msg = DMT.createFNPOpennetDisabled(uid);
			try {
				source.sendAsync(msg, null, node.nodeStats.announceByteCounter);
			} catch (NotConnectedException e) {
				// OK
			}
			if(logMINOR) Logger.minor(this, "Rejected announcement (opennet or announcement disabled) from "+source);
			return true;
		}
		boolean success = false;
		try {
			// UIDs for announcements are separate from those for requests.
			// So we don't need to, and should not, ask Node.
			NodeStats.AnnouncementDecision shouldAcceptAnnouncement = node.nodeStats.shouldAcceptAnnouncement(uid);
			if (!(NodeStats.AnnouncementDecision.ACCEPT == shouldAcceptAnnouncement)) {
				if (om != null && source instanceof SeedClientPeerNode)
					om.seedTracker.rejectedAnnounce((SeedClientPeerNode)source);
				Message msg = null;
				if (NodeStats.AnnouncementDecision.OVERLOAD == shouldAcceptAnnouncement) {
					msg = DMT.createFNPRejectedOverload(uid, true, false, false);
					if (logMINOR)
						Logger.minor(this,
							     "Rejected announcement (overall overload) from "
							     + source);
				} else if (NodeStats.AnnouncementDecision.LOOP == shouldAcceptAnnouncement) {
					msg = DMT.createFNPRejectedLoop(uid);
					if (logMINOR)
						Logger.minor(this,
							     "Rejected announcement (loop) from "+
							     source);
				} else {
					throw new Error("This shouldn't happen. Please report");
				}

				try {
					source.sendAsync(msg, null, node.nodeStats.announceByteCounter);
				} catch (NotConnectedException e) {
					// OK
				}
				return true;
			}
			if(!source.shouldAcceptAnnounce(uid)) {
				if(om != null && source instanceof SeedClientPeerNode)
					om.seedTracker.rejectedAnnounce((SeedClientPeerNode)source);
				node.nodeStats.endAnnouncement(uid);
				Message msg = DMT.createFNPRejectedOverload(uid, true, false, false);
				try {
					source.sendAsync(msg, null, node.nodeStats.announceByteCounter);
				} catch (NotConnectedException e) {
					// OK
				}
				if(logMINOR) Logger.minor(this, "Rejected announcement (peer limit) from "+source);
				return true;
			}
			if(om != null && source instanceof SeedClientPeerNode) {
				if(!om.seedTracker.acceptAnnounce((SeedClientPeerNode)source, node.fastWeakRandom)) {
					node.nodeStats.endAnnouncement(uid);
					Message msg = DMT.createFNPRejectedOverload(uid, true, false, false);
					try {
						source.sendAsync(msg, null, node.nodeStats.announceByteCounter);
					} catch (NotConnectedException e) {
						// OK
					}
					if(logMINOR) Logger.minor(this, "Rejected announcement (seednode limit) from "+source);
					return true;
				}
			}
			if(source instanceof SeedClientPeerNode) {
				short maxHTL = node.maxHTL();
				if(htl < maxHTL-1) {
					Logger.error(this, "Announcement from seed client not at max HTL: "+htl+" for "+source);
					htl = maxHTL;
				}
			}
			AnnouncementCallback cb = null;
			if(logMINOR) {
				final String origin = source.toString()+" (htl "+htl+")";
				// Log the progress of the announcement.
				// This is similar to Announcer's logging.
				cb = new AnnouncementCallback() {
					private int totalAdded;
					private int totalNotWanted;
					private boolean acceptedSomewhere;
					@Override
					public synchronized void acceptedSomewhere() {
						acceptedSomewhere = true;
					}
					@Override
					public void addedNode(PeerNode pn) {
						synchronized(this) {
							totalAdded++;
						}
						Logger.minor(this, "Announcement from "+origin+" added node "+pn+(pn instanceof SeedClientPeerNode ? " (seed server added the peer directly)" : ""));
						return;
					}
					@Override
					public void bogusNoderef(String reason) {
						Logger.minor(this, "Announcement from "+origin+" got bogus noderef: "+reason, new Exception("debug"));
					}
					@Override
					public void completed() {
						synchronized(this) {
							Logger.minor(this, "Announcement from "+origin+" completed");
						}
						int shallow=node.maxHTL()-(totalAdded+totalNotWanted);
						if(acceptedSomewhere)
							Logger.minor(this, "Announcement from "+origin+" completed ("+totalAdded+" added, "+totalNotWanted+" not wanted, "+shallow+" shallow)");
						else
							Logger.minor(this, "Announcement from "+origin+" not accepted anywhere.");
					}

					@Override
					public void nodeFailed(PeerNode pn, String reason) {
						Logger.minor(this, "Announcement from "+origin+" failed: "+reason);
					}
					@Override
					public void noMoreNodes() {
						Logger.minor(this, "Announcement from "+origin+" ran out of nodes (route not found)");
					}
					@Override
					public void nodeNotWanted() {
						synchronized(this) {
							totalNotWanted++;
						}
						Logger.minor(this, "Announcement from "+origin+" returned node not wanted for a total of "+totalNotWanted+" from this announcement)");
					}
					@Override
					public void nodeNotAdded() {
						Logger.minor(this, "Announcement from "+origin+" : node not wanted (maybe already have it, opennet just turned off, etc)");
					}
					@Override
					public void relayedNoderef() {
						synchronized(this) {
							totalAdded++;
							Logger.minor(this, "Announcement from "+origin+" accepted by a downstream node, relaying noderef for a total of "+totalAdded+" from this announcement)");
						}
					}
				};
			}
			AnnounceSender sender = new AnnounceSender(target, htl, uid, source, om, node, xferUID, noderefLength, paddedLength, cb);
			node.executor.execute(sender, "Announcement sender for "+uid);
			success = true;
			if(logMINOR) Logger.minor(this, "Accepted announcement from "+source);
			return true;
		} finally {
			if(!success)
				source.completedAnnounce(uid);
		}
	}

	final Hashtable<Long, RoutedContext> routedContexts = new Hashtable<Long, RoutedContext>();

	static class RoutedContext {
		long createdTime;
		long accessTime;
		PeerNode source;
		final HashSet<PeerNode> routedTo;
		Message msg;
		short lastHtl;
		final byte[] identity;

		RoutedContext(Message msg, PeerNode source, byte[] identity) {
			createdTime = accessTime = System.currentTimeMillis();
			this.source = source;
			routedTo = new HashSet<PeerNode>();
			this.msg = msg;
			lastHtl = msg.getShort(DMT.HTL);
			this.identity = identity;
		}

		void addSent(PeerNode n) {
			routedTo.add(n);
		}
	}
	
	/**
	 * Cleanup any old/stale routing contexts and reschedule execution.
	 */
	@Override
	public void run() {
		long now=System.currentTimeMillis();
		synchronized (routedContexts) {
			Iterator<RoutedContext> i = routedContexts.values().iterator();
			while (i.hasNext()) {
				RoutedContext rc = i.next();
				if (now-rc.createdTime > STALE_CONTEXT) {
					i.remove();
				}
			}
		}
		node.getTicker().queueTimedJob(this, STALE_CONTEXT_CHECK);
	}

	/**
	 * Handle an FNPRoutedRejected message.
	 */
	private boolean handleRoutedRejected(Message m) {
		if(!node.enableRoutedPing()) return true;
		long id = m.getLong(DMT.UID);
		Long lid = Long.valueOf(id);
		RoutedContext rc = routedContexts.get(lid);
		if(rc == null) {
			// Gah
			Logger.error(this, "Unrecognized FNPRoutedRejected");
			return false; // locally originated??
		}
		short htl = rc.lastHtl;
		if(rc.source != null)
			htl = rc.source.decrementHTL(htl);
		short ohtl = m.getShort(DMT.HTL);
		if(ohtl < htl) htl = ohtl;
		if(htl == 0) {
			// Equivalent to DNF.
			// Relay.
			if(rc.source != null) {
				try {
					rc.source.sendAsync(DMT.createFNPRoutedRejected(id, (short)0), null, nodeStats.routedMessageCtr);
				} catch (NotConnectedException e) {
					// Ouch.
					Logger.error(this, "Unable to relay probe DNF: peer disconnected: "+rc.source);
				}
			}
		} else {
			// Try routing to the next node
			forward(rc.msg, id, rc.source, htl, rc.msg.getDouble(DMT.TARGET_LOCATION), rc, rc.identity);
		}
		return true;
	}

	/**
	 * Handle a routed-to-a-specific-node message.
	 * @param m
	 * @return False if we want the message put back on the queue.
	 */
	boolean handleRouted(Message m, PeerNode source) {
		if(!node.enableRoutedPing()) return true;
		if(logMINOR) Logger.minor(this, "handleRouted("+m+ ')');

		long id = m.getLong(DMT.UID);
		Long lid = Long.valueOf(id);
		short htl = m.getShort(DMT.HTL);
		byte[] identity = ((ShortBuffer) m.getObject(DMT.NODE_IDENTITY)).getData();
		if(source != null) htl = source.decrementHTL(htl);
		RoutedContext ctx;
		ctx = routedContexts.get(lid);
		if(ctx != null) {
			try {
				source.sendAsync(DMT.createFNPRoutedRejected(id, htl), null, nodeStats.routedMessageCtr);
			} catch (NotConnectedException e) {
				if(logMINOR) Logger.minor(this, "Lost connection rejecting "+m);
			}
			return true;
		}
		ctx = new RoutedContext(m, source, identity);
		synchronized (routedContexts) {
			routedContexts.put(lid, ctx);
		}
		// source == null => originated locally, keep full htl
		double target = m.getDouble(DMT.TARGET_LOCATION);
		if(logMINOR) Logger.minor(this, "id "+id+" from "+source+" htl "+htl+" target "+target);
		if(Math.abs(node.lm.getLocation() - target) <= Double.MIN_VALUE) {
			if(logMINOR) Logger.minor(this, "Dispatching "+m.getSpec()+" on "+node.getDarknetPortNumber());
			// Handle locally
			// Message type specific processing
			dispatchRoutedMessage(m, source, id);
			return true;
		} else if(htl == 0) {
			Message reject = DMT.createFNPRoutedRejected(id, (short)0);
			if(source != null) try {
				source.sendAsync(reject, null, nodeStats.routedMessageCtr);
			} catch (NotConnectedException e) {
				if(logMINOR) Logger.minor(this, "Lost connection rejecting "+m);
			}
			return true;
		} else {
			return forward(m, id, source, htl, target, ctx, identity);
		}
	}

	boolean handleRoutedReply(Message m) {
		if(!node.enableRoutedPing()) return true;
		long id = m.getLong(DMT.UID);
		if(logMINOR) Logger.minor(this, "Got reply: "+m);
		Long lid = Long.valueOf(id);
		RoutedContext ctx = routedContexts.get(lid);
		if(ctx == null) {
			Logger.error(this, "Unrecognized routed reply: "+m);
			return false;
		}
		PeerNode pn = ctx.source;
		if(pn == null) return false;
		try {
			pn.sendAsync(m.cloneAndDropSubMessages(), null, nodeStats.routedMessageCtr);
		} catch (NotConnectedException e) {
			if(logMINOR) Logger.minor(this, "Lost connection forwarding "+m+" to "+pn);
		}
		return true;
	}

	private boolean forward(Message m, long id, PeerNode pn, short htl, double target, RoutedContext ctx, byte[] targetIdentity) {
		if(logMINOR) Logger.minor(this, "Should forward");
		// Forward
		m = preForward(m, htl);
		while(true) {
			PeerNode next = node.peers.getByPubKeyHash(targetIdentity);
			if(next != null && !next.isConnected()) {
				Logger.error(this, "Found target but disconnected!: "+next);
				next = null;
			}
			if(next == null)
			next = node.peers.closerPeer(pn, ctx.routedTo, target, true, node.isAdvancedModeEnabled(), -1, null,
				        null, htl, 0, pn == null, false, false);
			if(logMINOR) Logger.minor(this, "Next: "+next+" message: "+m);
			if(next != null) {
				// next is connected, or at least has been => next.getPeer() CANNOT be null.
				if(logMINOR) Logger.minor(this, "Forwarding "+m.getSpec()+" to "+next.getPeer().getPort());
				ctx.addSent(next);
				try {
					next.sendAsync(m, null, nodeStats.routedMessageCtr);
				} catch (NotConnectedException e) {
					continue;
				}
			} else {
				if(logMINOR) Logger.minor(this, "Reached dead end for "+m.getSpec()+" on "+node.getDarknetPortNumber());
				// Reached a dead end...
				Message reject = DMT.createFNPRoutedRejected(id, htl);
				if(pn != null) try {
					pn.sendAsync(reject, null, nodeStats.routedMessageCtr);
				} catch (NotConnectedException e) {
					Logger.error(this, "Cannot send reject message back to source "+pn);
					return true;
				}
			}
			return true;
		}
	}

	/**
	 * Prepare a routed-to-node message for forwarding.
	 */
	private Message preForward(Message m, short newHTL) {
		m = m.cloneAndDropSubMessages();
		m.set(DMT.HTL, newHTL); // update htl
		if(m.getSpec() == DMT.FNPRoutedPing) {
			int x = m.getInt(DMT.COUNTER);
			x++;
			m.set(DMT.COUNTER, x);
		}
		return m;
	}

	/**
	 * Deal with a routed-to-node message that landed on this node.
	 * This is where message-type-specific code executes. 
	 * @param m
	 * @return
	 */
	private boolean dispatchRoutedMessage(Message m, PeerNode src, long id) {
		if(m.getSpec() == DMT.FNPRoutedPing) {
			if(logMINOR) Logger.minor(this, "RoutedPing reached other side! ("+id+")");
			int x = m.getInt(DMT.COUNTER);
			Message reply = DMT.createFNPRoutedPong(id, x);
			if(logMINOR) Logger.minor(this, "Replying - counter = "+x+" for "+id);
			try {
				src.sendAsync(reply, null, nodeStats.routedMessageCtr);
			} catch (NotConnectedException e) {
				if(logMINOR) Logger.minor(this, "Lost connection replying to "+m+" in dispatchRoutedMessage");
			}
			return true;
		}
		return false;
	}

	void start(NodeStats stats) {
		this.nodeStats = stats;
		node.executor.execute(queueRunner);
	}

	public static String peersUIDsToString(long[] peerUIDs, double[] peerLocs) {
		StringBuilder sb = new StringBuilder(peerUIDs.length*23+peerLocs.length*26);
		int min=Math.min(peerUIDs.length, peerLocs.length);
		for(int i=0;i<min;i++) {
			double loc = peerLocs[i];
			long uid = peerUIDs[i];
			sb.append(loc);
			sb.append('=');
			sb.append(uid);
			if(i != min-1)
				sb.append('|');
		}
		if(peerUIDs.length > min) {
			for(int i=min;i<peerUIDs.length;i++) {
				sb.append("|U:");
				sb.append(peerUIDs[i]);
			}
		} else if(peerLocs.length > min) {
			for(int i=min;i<peerLocs.length;i++) {
				sb.append("|L:");
				sb.append(peerLocs[i]);
			}
		}
		return sb.toString();
	}
	
	public void setHook(NodeDispatcherCallback cb) {
		this.callback = cb;
	}
}
