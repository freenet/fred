/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.Message;
import freenet.io.comm.NotConnectedException;
import freenet.io.xfer.BlockTransmitter;
import freenet.io.xfer.BlockTransmitter.BlockTransmitterCompletion;
import freenet.io.xfer.PartiallyReceivedBlock;
import freenet.keys.CHKBlock;
import freenet.keys.Key;
import freenet.keys.KeyBlock;
import freenet.keys.NodeCHK;
import freenet.keys.NodeSSK;
import freenet.keys.SSKBlock;
import freenet.support.LRUMap;
import freenet.support.ListUtils;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.SerialExecutor;
import freenet.support.Logger.LogLevel;
import freenet.support.io.NativeThread;

// FIXME it is ESSENTIAL that we delete the ULPR data on requestors etc once we have found the key.
// Otherwise it will be much too easy to trace a request if an attacker busts the node afterwards.
// We can use an HMAC or something to authenticate offers.

// LOCKING: Always take the FailureTable lock first if you need both. Take the FailureTableEntry 
// lock only on cheap internal operations.

/**
 * Tracks recently DNFed keys, where they were routed to, what the location was at the time, who requested them.
 * Implements Ultra-Lightweight Persistent Requests: Refuse requests for a key for 10 minutes after it's DNFed 
 * (UNLESS we find a better route for the request), and when it is found, offer it to those who've asked for it
 * in the last hour.
 * LOCKING: Do not lock PeerNode before FailureTable/FailureTableEntry.
 * @author toad
 */
public class FailureTable {
	
	private static volatile boolean logMINOR;
	//private static volatile boolean logDEBUG;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
				//logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}

	/** FailureTableEntry's by key. Note that we push an entry only when sentTime changes. */
	private final LRUMap<Key,FailureTableEntry> entriesByKey;
	/** BlockOfferList by key. Synchronized on self, as it doesn't interact with the main FT. */
	private final LRUMap<Key,BlockOfferList> blockOfferListByKey;
	private final Node node;
	
	/** Maximum number of keys to track */
	static final int MAX_ENTRIES = 20*1000;
	/** Maximum number of offers to track */
	static final int MAX_OFFERS = 10*1000;
	/** Terminate a request if there was a DNF on the same key less than 10 minutes ago.
	 * Maximum time for any FailureTable i.e. for this period after a DNF, we will avoid the node that 
	 * DNFed. */
	static final long REJECT_TIME = MINUTES.toMillis(10);
	/** Maximum time for a RecentlyFailed. I.e. until this period expires, we take a request into account
	 * when deciding whether we have recently failed to this peer. If we get a DNF, we use this figure.
	 * If we get a RF, we use what it tells us, which can be less than this. Most other failures use
	 * shorter periods. */
	static final long RECENTLY_FAILED_TIME = MINUTES.toMillis(30);
	/** After 1 hour we forget about an entry completely */
	static final long MAX_LIFETIME = MINUTES.toMillis(60);
	/** Offers expire after 10 minutes */
	static final long OFFER_EXPIRY_TIME = MINUTES.toMillis(10);
	/** HMAC key for the offer authenticator */
	final byte[] offerAuthenticatorKey;
	/** Clean up old data every 10 minutes to save memory and improve privacy */
	static final long CLEANUP_PERIOD = MINUTES.toMillis(10);

	FailureTable(Node node) {
		entriesByKey = LRUMap.createSafeMap();
		blockOfferListByKey = LRUMap.createSafeMap();
		this.node = node;
		offerAuthenticatorKey = new byte[32];
		node.random.nextBytes(offerAuthenticatorKey);
		offerExecutor = new SerialExecutor(NativeThread.HIGH_PRIORITY);
		node.ticker.queueTimedJob(new FailureTableCleaner(), CLEANUP_PERIOD);
	}
	
	public void start() {
		offerExecutor.start(node.executor, "FailureTable offers executor for "+node.getDarknetPortNumber());
	}
	
	/**
	 * Called when we route to a node and it fails for some reason, but we continue the request.
	 * Normally the timeout will be the time it took to route to that node and wait for its 
	 * response / timeout waiting for its response.
	 * @param key
	 * @param routedTo
	 * @param htl
	 * @param rfTimeout
	 * @param ftTimeout
	 */
	public void onFailed(Key key, PeerNode routedTo, short htl, long rfTimeout, long ftTimeout) {
		if(ftTimeout < 0 || ftTimeout > REJECT_TIME) {
			Logger.error(this, "Bogus timeout "+ftTimeout, new Exception("error"));
			ftTimeout = Math.max(Math.min(REJECT_TIME, ftTimeout), 0);
		}
		if(rfTimeout < 0 || rfTimeout > RECENTLY_FAILED_TIME) {
			if(rfTimeout > 0)
				Logger.error(this, "Bogus timeout "+rfTimeout, new Exception("error"));
			rfTimeout = Math.max(Math.min(RECENTLY_FAILED_TIME, rfTimeout), 0);
		}
		if(!(node.enableULPRDataPropagation || node.enablePerNodeFailureTables)) return;
		long now = System.currentTimeMillis();
		FailureTableEntry entry;
		synchronized(this) {
			entry = entriesByKey.get(key);
			if(entry == null)
				entry = new FailureTableEntry(key);
			entriesByKey.push(key, entry);
			// LOCKING: Taking PeerNode then FT/FTE will deadlock.
			// However this should not happen.
			// We have to do this inside the lock to prevent race condition with the cleaner causing us to get dropped because isEmpty() before updating.
			entry.failedTo(routedTo, rfTimeout, ftTimeout, now, htl);

			trimEntries();
		}
	}
	
	/** When a request finishes with a failure, record who generated the failure
	 * so we don't route to them next time, and also who originated it so we can
	 * send the data back to them if we find them.
	 * ORDERING: You should generally call this *before* calling finish() to 
	 * avoid problems.
	 * LOCKING: NEVER synchronize on PeerNode before calling any FailureTable method.
	 */
	public void onFinalFailure(Key key, PeerNode routedTo, short htl, short origHTL, long rfTimeout, long ftTimeout, PeerNode requestor) {
		if(ftTimeout < -1 || ftTimeout > REJECT_TIME) {
			// -1 is a valid no-op.
			Logger.error(this, "Bogus timeout "+ftTimeout, new Exception("error"));
			ftTimeout = Math.max(Math.min(REJECT_TIME, ftTimeout), 0);
		}
		if(rfTimeout < 0 || rfTimeout > RECENTLY_FAILED_TIME) {
			if(rfTimeout > 0)
				Logger.error(this, "Bogus timeout "+rfTimeout, new Exception("error"));
			rfTimeout = Math.max(Math.min(RECENTLY_FAILED_TIME, rfTimeout), 0);
		}
		if(!(node.enableULPRDataPropagation || node.enablePerNodeFailureTables)) return;
		long now = System.currentTimeMillis();
		FailureTableEntry entry;
		synchronized(this) {
			entry = entriesByKey.get(key);
			if(entry == null)
				entry = new FailureTableEntry(key);
			entriesByKey.push(key, entry);

			// LOCKING: Taking PeerNode then FT/FTE will deadlock.
			// However this should not happen.
			// We have to do this inside the lock to prevent race condition with the cleaner causing us to get dropped because isEmpty() before updating.
			
			if(routedTo != null)
				entry.failedTo(routedTo, rfTimeout, ftTimeout, now, htl);
			if(requestor != null)
				entry.addRequestor(requestor, now, origHTL);

			trimEntries();
		}
	}

	private synchronized void trimEntries() {
		while(entriesByKey.size() > MAX_ENTRIES) {
			entriesByKey.popKey();
		}
	}

	// LOCKING: Synchronized on FailureTable because we need to remove self in deleteOffer(). 
	private final class BlockOfferList {
		private BlockOffer[] offers;
		final FailureTableEntry entry;
		
		BlockOfferList(FailureTableEntry entry, BlockOffer offer) {
			this.entry = entry;
			this.offers = new BlockOffer[] { offer };
		}

		public long expires() {
			synchronized(blockOfferListByKey) {
				long last = 0;
				for(BlockOffer offer: offers) {
					if(offer.offeredTime > last) last = offer.offeredTime;
				}
				return last + OFFER_EXPIRY_TIME;
			}
		}

		public boolean isEmpty(long now) {
			synchronized(blockOfferListByKey) {
				for(BlockOffer offer: offers) {
					if(!offer.isExpired(now)) return false;
				}
				return true;
			}
		}

		public void deleteOffer(BlockOffer offer) {
			if(logMINOR) Logger.minor(this, "Deleting "+offer+" from "+this);
			synchronized(blockOfferListByKey) {
				int idx = -1;
				final int offerLength = offers.length;
				for(int i=0;i<offerLength;i++) {
					if(offers[i] == offer) idx = i;
				}
				if(idx < 0) return;
				BlockOffer[] newOffers = new BlockOffer[offerLength - 1];
				if(idx > 0)
					System.arraycopy(offers, 0, newOffers, 0, idx);
				if(idx < newOffers.length)
					System.arraycopy(offers, idx + 1, newOffers, idx, offers.length - idx - 1);
				offers = newOffers;
				if(offers.length > 1) return;
				blockOfferListByKey.removeKey(entry.key);
			}
			node.clientCore.dequeueOfferedKey(entry.key);
		}

		public void addOffer(BlockOffer offer) {
			synchronized(blockOfferListByKey) {
				offers = Arrays.copyOf(offers, offers.length+1);
				offers[offers.length-1] = offer;
			}
		}
		
		@Override
		public String toString() {
			return super.toString()+"("+offers.length+")";
		}
	}
	
	static final class BlockOffer {
		final long offeredTime;
		/** Either offered by or offered to this node */
		final WeakReference<PeerNode> nodeRef;
		/** Authenticator */
		final byte[] authenticator;
		/** Boot ID when the offer was made */
		final long bootID;
		
		BlockOffer(PeerNode pn, long now, byte[] authenticator, long bootID) {
			this.nodeRef = pn.myRef;
			this.offeredTime = now;
			this.authenticator = authenticator;
			this.bootID = bootID;
		}

		public PeerNode getPeerNode() {
			return nodeRef.get();
		}

		public boolean isExpired(long now) {
			return nodeRef.get() == null || now > (offeredTime + OFFER_EXPIRY_TIME);
		}

		public boolean isExpired() {
			return isExpired(System.currentTimeMillis());
		}
	}
	
	/**
	 * Called when a data block is found (after it has been stored; there is a good chance of its being available in the
	 * near future). If there are nodes waiting for it, we will offer it to them. Removes the list of 
	 * nodes that offered the key too (but this is a separate operation).
	 * LOCKING: Never call when locked PeerNode, and try to avoid other locks as
	 * they might cause a deadlock. Schedule off-thread if necessary.
	 */
	public void onFound(KeyBlock block) {
		if(logMINOR) Logger.minor(this, "Found "+block.getKey());
		if(!(node.enableULPRDataPropagation || node.enablePerNodeFailureTables)) {
			if(logMINOR) Logger.minor(this, "Ignoring onFound because enable ULPR = "+node.enableULPRDataPropagation+" and enable failure tables = "+node.enablePerNodeFailureTables);
			return;
		}
		Key key = block.getKey();
		if(key == null) throw new NullPointerException();
		FailureTableEntry entry;
		synchronized(blockOfferListByKey) {
			blockOfferListByKey.removeKey(key);
		}
		synchronized(this) {
			entry = entriesByKey.get(key);
			if(entry == null) {
				if(logMINOR) Logger.minor(this, "Key not found in entriesByKey");
				return; // Nobody cares
			}
			entriesByKey.removeKey(key);
		}
		if(logMINOR) Logger.minor(this, "Offering key");
		if(!node.enableULPRDataPropagation) return;
		entry.offer();
	}
	
	/** Run onOffer() on a separate thread since it can block for disk I/O, and we don't want to cause 
	 * transfer timeouts etc because of slow disk. */
	private final SerialExecutor offerExecutor;
	
	/**
	 * Called when we get an offer for a key. If this is an SSK, we will only accept it if we have previously asked for it.
	 * If it is a CHK, we will accept it if we want it.
	 * @param key The key we are being offered.
	 * @param peer The node offering it.
	 * @param authenticator 
	 */
	void onOffer(final Key key, final PeerNode peer, final byte[] authenticator) {
		if(!node.enableULPRDataPropagation) return;
		if(logMINOR)
			Logger.minor(this, "Offered key "+key+" by peer "+peer);
		FailureTableEntry entry;
		synchronized(this) {
			entry = entriesByKey.get(key);
			if(entry == null) {
				if(logMINOR) Logger.minor(this, "We didn't ask for the key");
				return; // we haven't asked for it
			}
		}
		offerExecutor.execute(new Runnable() {
			@Override
			public void run() {
				innerOnOffer(key, peer, authenticator);
			}
		}, "onOffer()");
	}

	/**
	 * This method runs on the SerialExecutor. Therefore, any blocking network I/O needs to be scheduled
	 * on a separate thread. However, blocking disk I/O *should happen on this thread*. We deliberately
	 * serialise it, as high latencies can otherwise result.
	 */
	protected void innerOnOffer(Key key, PeerNode peer, byte[] authenticator) {
		if(logMINOR) Logger.minor(this, "Inner on offer for "+key+" from "+peer+" on "+node.getDarknetPortNumber());
		if(key.getRoutingKey() == null) throw new NullPointerException();
		//NB: node.hasKey() executes a datastore fetch
		// If we have the key in the datastore (store or cache), we don't want it.
		// If we have the key in the client cache, we might want it for other nodes,
		// although hopefully the client layer was tripped when we got it.
		if(node.hasKey(key, false, true)) {
			Logger.minor(this, "Already have key");
			return;
		}
		
		// Re-check after potentially long disk I/O.
		FailureTableEntry entry;
		long now = System.currentTimeMillis();
		synchronized(this) {
			entry = entriesByKey.get(key);
			if(entry == null) {
				if(logMINOR) Logger.minor(this, "We didn't ask for the key");
				return; // we haven't asked for it
			}
		}

		/*
		 * Accept (subject to later checks) if we asked for it.
		 * Should we accept it if we were asked for it? This is "bidirectional propagation".
		 * It's good because it makes the whole structure much more reliable; it's bad because
		 * it's not entirely under our control - we didn't choose to route it to the node, the node
		 * routed it to us. Now it's found it before we did...
		 * 
		 * Attacks:
		 * - Frost spamming etc: Is it easier to offer data to our peers rather than inserting it? Will
		 * it result in it being propagated further? The peer node would then do the request, rather than
		 * this node doing an insert. Is that beneficial?
		 * 
		 * Not relevant with CHKs anyway.
		 * 
		 * On the plus side, propagation to nodes that have asked is worthwhile because reduced polling 
		 * cost enables more secure messaging systems e.g. outbox polling...
		 * - Social engineering: If a key is unpopular, you can put a different copy of it on different 
		 * nodes. You can then use this to trace the requestor - identify that he is or isn't on the target. 
		 * You can't do this with a regular insert because it will often go several nodes even at htl 0. 
		 * With subscriptions, you might be able to bypass this - but only if you know no other nodes in the
		 * neighbourhood are subscribed. Easier with SSKs; with CHKs you have only binary information of 
		 * whether the person got the key (with social engineering). Hard to exploit on darknet; if you're 
		 * that close to the suspect there are easier ways to get at them e.g. correlation attacks.
		 * 
		 * Conclusion: We should accept the request if:
		 * - We asked for it from that node. (Note that a node might both have asked us and been asked).
		 * - That node asked for it, and it's a CHK.
		 */
		
		boolean weAsked = entry.askedFromPeer(peer, now);
		boolean heAsked = entry.askedByPeer(peer, now);
		if(!(weAsked || heAsked)) {
			if(logMINOR) Logger.minor(this, "Not propagating key: weAsked="+weAsked+" heAsked="+heAsked);
			if(entry.isEmpty()) {
				synchronized(this) {
					entriesByKey.removeKey(key);
				}
			}
			return;
		}
		if(entry.isEmpty()) {
			synchronized(this) {
				entriesByKey.removeKey(key);
			}
		}
		
		// Valid offer.
		
		// Add to offers list
		
		synchronized(blockOfferListByKey) {			
			if(logMINOR) Logger.minor(this, "Valid offer");
			BlockOfferList bl = blockOfferListByKey.get(key);
			BlockOffer offer = new BlockOffer(peer, now, authenticator, peer.getBootID());
			if(bl == null) {
				bl = new BlockOfferList(entry, offer);
			} else {
				bl.addOffer(offer);
			}
			blockOfferListByKey.push(key, bl);
			trimOffersList(now);
		}
		
		// Accept the offer.
		// Either a peer wants it, in which case we want it for them,
		// or we want it, or we have requested it in the past, in which case
		// we will probably want it in the future.
		// FIXME: Not safe to queue offered keys as realtime????
		// For the same reason that priorities are not safe?
		// But do it at low priorities?
		// Offers mostly happen for SSKs anyway ... reconsider?
		node.clientCore.queueOfferedKey(key, false);
	}

	private void trimOffersList(long now) {
		synchronized(blockOfferListByKey) {
			while(true) {
				if(blockOfferListByKey.isEmpty()) return;
				BlockOfferList bl = blockOfferListByKey.peekValue();
				if(bl.isEmpty(now) || bl.expires() < now || blockOfferListByKey.size() > MAX_OFFERS) {
					if(logMINOR) Logger.minor(this, "Removing block offer list "+bl+" list size now "+blockOfferListByKey.size());
					blockOfferListByKey.popKey();
				} else {
					return;
				}
			}
		}
	}

	/**
	 * We offered a key, a node has responded to the offer. Note that this runs on the incoming
	 * packets thread so should allocate a new thread if it does anything heavy. Note also that
	 * it is responsible for unlocking the UID.
	 * @param key The key to send.
	 * @param isSSK Whether it is an SSK.
	 * @param uid The UID.
	 * @param source The node that asked for the key.
	 * @throws NotConnectedException If the sender ceases to be connected.
	 */
	public void sendOfferedKey(final Key key, final boolean isSSK, final boolean needPubKey, final long uid, final PeerNode source, final OfferReplyTag tag, final boolean realTimeFlag) throws NotConnectedException {
		this.offerExecutor.execute(new Runnable() {
			@Override
			public void run() {
				try {
					innerSendOfferedKey(key, isSSK, needPubKey, uid, source, tag, realTimeFlag);
				} catch (NotConnectedException e) {
					tag.unlockHandler();
					// Too bad.
				} catch (Throwable t) {
					tag.unlockHandler();
					Logger.error(this, "Caught "+t+" sending offered key", t);
				}
			}
		}, "sendOfferedKey");
	}

	/**
	 * This method runs on the SerialExecutor. Therefore, any blocking network I/O needs to be scheduled
	 * on a separate thread. However, blocking disk I/O *should happen on this thread*. We deliberately
	 * serialise it, as high latencies can otherwise result.
	 */
	protected void innerSendOfferedKey(Key key, final boolean isSSK, boolean needPubKey, final long uid, final PeerNode source, final OfferReplyTag tag, final boolean realTimeFlag) throws NotConnectedException {
		if(isSSK) {
			SSKBlock block = node.fetch((NodeSSK)key, false, false, false, false, true, null);
			if(block == null) {
				// Don't have the key
				source.sendAsync(DMT.createFNPGetOfferedKeyInvalid(uid, DMT.GET_OFFERED_KEY_REJECTED_NO_KEY), null, senderCounter);
				tag.unlockHandler();
				return;
			}
			
			final Message data = DMT.createFNPSSKDataFoundData(uid, block.getRawData(), realTimeFlag);
			Message headers = DMT.createFNPSSKDataFoundHeaders(uid, block.getRawHeaders(), realTimeFlag);
			final int dataLength = block.getRawData().length;
			
			source.sendAsync(headers, null, senderCounter);
			
			node.executor.execute(new PrioRunnable() {

				@Override
				public int getPriority() {
					return NativeThread.HIGH_PRIORITY;
				}

				@Override
				public void run() {
					try {
						source.sendSync(data, senderCounter, realTimeFlag);
						senderCounter.sentPayload(dataLength);
					} catch (NotConnectedException e) {
						// :(
					} catch (SyncSendWaitedTooLongException e) {
						// Impossible
					} finally {
						tag.unlockHandler();
					}
				}
				
			}, "Send offered SSK");
			
			if(needPubKey) {
				Message pk = DMT.createFNPSSKPubKey(uid, block.getPubKey(), realTimeFlag);
				source.sendAsync(pk, null, senderCounter);
			}
		} else {
			CHKBlock block = node.fetch((NodeCHK)key, false, false, false, false, true, null);
			if(block == null) {
				// Don't have the key
				source.sendAsync(DMT.createFNPGetOfferedKeyInvalid(uid, DMT.GET_OFFERED_KEY_REJECTED_NO_KEY), null, senderCounter);
				tag.unlockHandler();
				return;
			}
			Message df = DMT.createFNPCHKDataFound(uid, block.getRawHeaders());
			source.sendAsync(df, null, senderCounter);
        	PartiallyReceivedBlock prb =
        		new PartiallyReceivedBlock(Node.PACKETS_IN_BLOCK, Node.PACKET_SIZE, block.getRawData());
        	final BlockTransmitter bt =
        		new BlockTransmitter(node.usm, node.getTicker(), source, uid, prb, senderCounter, BlockTransmitter.NEVER_CASCADE,
        				new BlockTransmitterCompletion() {

					@Override
					public void blockTransferFinished(boolean success) {
						tag.unlockHandler();
					}
					
				}, realTimeFlag, node.nodeStats);
        	node.executor.execute(new PrioRunnable() {

				@Override
				public int getPriority() {
					return NativeThread.HIGH_PRIORITY;
				}

				@Override
				public void run() {
					bt.sendAsync();
				}
        		
        	}, "CHK offer sender");
		}
	}

	public final OfferedKeysByteCounter senderCounter = new OfferedKeysByteCounter();
	
	class OfferedKeysByteCounter implements ByteCounter {

		@Override
		public void receivedBytes(int x) {
			node.nodeStats.offeredKeysSenderReceivedBytes(x);
		}

		@Override
		public void sentBytes(int x) {
			node.nodeStats.offeredKeysSenderSentBytes(x);
		}

		@Override
		public void sentPayload(int x) {
			node.sentPayload(x);
			node.nodeStats.offeredKeysSenderSentBytes(-x);
		}
		
	}
	
	class OfferList {

		OfferList(BlockOfferList offerList) {
			this.offerList = offerList;
			recentOffers = new ArrayList<BlockOffer>();
			expiredOffers = new ArrayList<BlockOffer>();
			long now = System.currentTimeMillis();
			for(BlockOffer offer: offerList.offers) {
				if(!offer.isExpired(now))
					recentOffers.add(offer);
				else
					expiredOffers.add(offer);
			}
			if(logMINOR)
				Logger.minor(this, "Offers: "+recentOffers.size()+" recent "+expiredOffers.size()+" expired");
		}
		
		private final BlockOfferList offerList;
		
		private final List<BlockOffer> recentOffers;
		private final List<BlockOffer> expiredOffers;
		
		/** The last offer we returned */
		private BlockOffer lastOffer;
		
		public BlockOffer getFirstOffer() {
			if(lastOffer != null) {
				throw new IllegalStateException("Last offer not dealt with");
			}
			if(!recentOffers.isEmpty()) {
				return lastOffer = ListUtils.removeRandomBySwapLastSimple(node.random, recentOffers);
			}
			if(!expiredOffers.isEmpty()) {
				return lastOffer = ListUtils.removeRandomBySwapLastSimple(node.random, expiredOffers);
			}
			// No more offers.
			return null;
		}
		
		/**
		 * Delete the last offer - we have used it, successfully or not.
		 */
		public void deleteLastOffer() {
			offerList.deleteOffer(lastOffer);
			lastOffer = null;
		}

		/**
		 * Keep the last offer - we weren't able to use it e.g. because of RejectedOverload.
		 * Maybe it will be useful again in the future.
		 */
		public void keepLastOffer() {
			lastOffer = null;
		}
		
	}
	
	/** Have we had any offers for the key?
	 * @param key The key to check.
	 * @return True if there are any offers, false otherwise.
	 */
	public boolean hadAnyOffers(Key key) {
		synchronized(blockOfferListByKey) {
			return blockOfferListByKey.get(key) != null;
		}
	}

	public OfferList getOffers(Key key) {
		if(!node.enableULPRDataPropagation) return null;
		BlockOfferList bl;
		synchronized(blockOfferListByKey) {
			bl = blockOfferListByKey.get(key);
			if(bl == null) return null;
		}
		return new OfferList(bl);
	}

	/** Called when a node disconnects */
	public void onDisconnect() {
		if(!(node.enableULPRDataPropagation || node.enablePerNodeFailureTables)) return;
		// FIXME do something (off thread if expensive)
	}

	public TimedOutNodesList getTimedOutNodesList(Key key) {
		if(!node.enablePerNodeFailureTables) return null;
		synchronized(this) {
			return entriesByKey.get(key);
		}
	}
	
	public class FailureTableCleaner implements Runnable {

		@Override
		public void run() {
			try {
				realRun();
			} catch (Throwable t) {
				Logger.error(this, "FailureTableCleaner caught "+t, t);
			} finally {
				node.ticker.queueTimedJob(this, CLEANUP_PERIOD);
			}
		}

		private void realRun() {
			if(logMINOR) Logger.minor(this, "Starting FailureTable cleanup");
			long startTime = System.currentTimeMillis();
			FailureTableEntry[] entries;
			synchronized(FailureTable.this) {
				entries = new FailureTableEntry[entriesByKey.size()];
				entriesByKey.valuesToArray(entries);
			}
			for(FailureTableEntry entry: entries) {
				if(entry.cleanup()) {
					synchronized(FailureTable.this) {
						synchronized(entry) {
						if(entry.isEmpty()) {
							if(logMINOR) Logger.minor(this, "Removing entry for "+entry.key);
							entriesByKey.removeKey(entry.key);
						}
						}
					}
				}
			}
			long endTime = System.currentTimeMillis();
			if(logMINOR) Logger.minor(this, "Finished FailureTable cleanup took "+(endTime-startTime)+"ms");
		}
	}

	public boolean peersWantKey(Key key) {
		FailureTableEntry entry;
		synchronized(this) {
			entry = entriesByKey.get(key);
			if(entry == null) return false; // Nobody cares
		}
		return entry.othersWant();
	}
        
        /** @return The lowest HTL at which any peer has requested this key recently */
	public short minOfferedHTL(Key key, short htl) {
		FailureTableEntry entry;
		synchronized(this) {
			entry = entriesByKey.get(key);
			if(entry == null) return htl;
		}
		return entry.minRequestorHTL(htl);
	}
}
