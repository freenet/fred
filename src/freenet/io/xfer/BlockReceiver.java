/*
 * Dijjer - A Peer to Peer HTTP Cache
 * Copyright (C) 2004,2005 Change.Tv, Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package freenet.io.xfer;

import static java.util.concurrent.TimeUnit.SECONDS;

import freenet.io.comm.AsyncMessageFilterCallback;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.Message;
import freenet.io.comm.MessageCore;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.PeerContext;
import freenet.io.comm.RetrievalException;
import freenet.io.comm.SlowAsyncMessageFilterCallback;
import freenet.node.PeerNode;
import freenet.node.SyncSendWaitedTooLongException;
import freenet.support.BitArray;
import freenet.support.Buffer;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.Ticker;
import freenet.support.TimeUtil;
import freenet.support.io.NativeThread;
import freenet.support.math.MedianMeanRunningAverage;

/**
 * IMPORTANT: The receiver can cancel the incoming transfer. This may or may not, 
 * depending on the caller, result in the PRB being cancelled, and thus propagate back to
 * the originator.
 * 
 * This allows for a weak DoS, in that a node can start a request and then cancel it, 
 * having wasted a certain amount of upstream bandwidth on transferring data, especially
 * if upstream has lots of bandwidth and the attacker has limited bandwidth in the victim
 * -> attacker direction. However this behaviour can be detected fairly easily.
 * 
 * If we allow receiver cancels and don't propagate, a more serious DoS is possible. If we
 * don't allow receiver cancels, we have to get rid of turtles, and massively tighten up
 * transfer timeouts.
 * 
 * However, if we do that, we have to consider that a node might be able to connect, max
 * out the bandwidth with transfers, and then disconnect, avoiding the need to spend
 * bandwidth on receiving all the data; and then reconnect, after it's confident that the
 * transfers to it will have been cancelled. Or not reconnect at all, on opennet - just 
 * use a different identity. Downstream bandwidth is very cheap for small-scale attackers,
 * but if this is a usable force multiplier it could still be a good DoS if we went that
 * way.
 * 
 * But if we did get rid of receiver cancels, it *would* mean we could get rid of a lot of
 * code - e.g. the ReceiverAbortHandler, which in some cases (e.g RequestHandler) is 
 * complex and involves complex security tradeoffs. It would also make transfers 
 * significantly more reliable.
 * 
 * @author ian
 */
public class BlockReceiver implements AsyncMessageFilterCallback {

	private static volatile boolean logMINOR;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	public interface BlockReceiverTimeoutHandler {
		
		/** After a block times out, we call this callback. Once it returns, we cancel the
		 * PRB and wait for a cancel message or the second timeout. Hence, if the problem
		 * is on the node sending the data, we will get the first timeout then the second
		 * (fatal) timeout. But if the problem is upstream, we will only get the first
		 * timeout. 
		 * 
		 * Simple requests will need to implement this and transfer ownership of
		 * the request to this node, because the source node will end the request as soon
		 * as it sees the transfer cancel resulting from the PRB being cancelled; 
		 * assigning the UID to ourselves keeps it consistent, and thus avoids severe load
		 * management problems (resulting in e.g. constantly sending requests to a node 
		 * which are then rejected because we think we have capacity when we don't). */
		void onFirstTimeout();
		
		/** After the first timeout, we wait for either a cancel message (sendAborted 
		 * here), or the second timeout. If we get the second timeout, the problem was
		 * caused by the node we are receiving the data from, rather than upstream. In
		 * which case, we may need to take severe action against the node responsible, 
		 * because we do not know whether or not it thinks the transfer is still running.
		 * If it is still running and yet we cancel it, we will think that there is 
		 * capacity for more requests on the node when there isn't, resulting in load 
		 * management problems as above. */
		void onFatalTimeout(PeerContext source);
	}

	/*
	 * RECEIPT_TIMEOUT must be less than 60 seconds because BlockTransmitter times out after not
	 * hearing from us in 60 seconds. Without contact from the transmitter, we will try sending
	 * at most MAX_CONSECUTIVE_MISSING_PACKET_REPORTS every RECEIPT_TIMEOUT to recover.
	 */
	public final long RECEIPT_TIMEOUT;
	public static final long RECEIPT_TIMEOUT_REALTIME = SECONDS.toMillis(10);
	public static final long RECEIPT_TIMEOUT_BULK = SECONDS.toMillis(30);
	// TODO: This should be proportional to the calculated round-trip-time, not a constant
	public final long MAX_ROUND_TRIP_TIME;
	public static final int MAX_CONSECUTIVE_MISSING_PACKET_REPORTS = 4;
	public static final int MAX_SEND_INTERVAL = 500;
	public static final long CLEANUP_TIMEOUT = SECONDS.toMillis(5);
	// After 15 seconds, the receive is overdue and will cause backoff.
	public static final long TOO_LONG_TIMEOUT = SECONDS.toMillis(15);
	/** sendAborted is not sent at the realtime/bulk priority. Most of the two
	 * stage timeout stuff uses 60 seconds, it's a good number. */
	public static final long ACK_TRANSFER_FAILED_TIMEOUT = SECONDS.toMillis(60);
	PartiallyReceivedBlock _prb;
	PeerContext _sender;
	long _uid;
	MessageCore _usm;
	ByteCounter _ctr;
	Ticker _ticker;
	boolean sentAborted;
	private MessageFilter discardFilter;
	private long discardEndTime;
	private boolean senderAborted;
	private final boolean _realTime;
//	private final boolean _doTooLong;
	private final BlockReceiverTimeoutHandler _timeoutHandler;
	private final boolean completeAfterAckedAllReceived;

	/**
	 * @param usm
	 * @param sender
	 * @param uid
	 * @param prb
	 * @param ctr
	 * @param ticker
	 * @param realTime
	 * @param timeoutHandler
	 * @param completeAfterAckedAllReceived If true, we need to call completion
	 * only after we have received an ack to the allReceived message. Generally,
	 * handlers want to complete early (=false), so the slot is freed up and can 
	 * be reused by the other side; senders want to complete late, so they don't 
	 * end up reusing the slot before the handler has completed (=true).
	 */
	public BlockReceiver(MessageCore usm, PeerContext sender, long uid, PartiallyReceivedBlock prb, ByteCounter ctr, Ticker ticker, boolean realTime, BlockReceiverTimeoutHandler timeoutHandler, boolean completeAfterAckedAllReceived) {
		BlockReceiverTimeoutHandler nullTimeoutHandler = new BlockReceiverTimeoutHandler() {

			@Override
			public void onFirstTimeout() {
				// Do nothing
			}

			@Override
			public void onFatalTimeout(PeerContext source) {
				// Do nothing
			}

		};
		_timeoutHandler = timeoutHandler == null ? nullTimeoutHandler : timeoutHandler;
		_sender = sender;
		_prb = prb;
		_uid = uid;
		_usm = usm;
		_ctr = ctr;
		_ticker = ticker;
		_realTime = realTime;
		this.completeAfterAckedAllReceived = completeAfterAckedAllReceived;
		RECEIPT_TIMEOUT = _realTime ? RECEIPT_TIMEOUT_REALTIME : RECEIPT_TIMEOUT_BULK;
		MAX_ROUND_TRIP_TIME = RECEIPT_TIMEOUT;
//		_doTooLong = doTooLong;
	}

	private void sendAborted(int reason, String desc) throws NotConnectedException {
		synchronized(this) {
			if(sentAborted) return;
			sentAborted = true;
		}
		_usm.send(_sender, DMT.createSendAborted(_uid, reason, desc), _ctr);
	}
	
	public interface BlockReceiverCompletion {

		public void blockReceived(byte[] buf);

		public void blockReceiveFailed(RetrievalException e);

	}
	
	private BlockReceiverCompletion callback;
	
	private long startTime;
	
	// If false, don't check for duplicate messages from the sender.
	// Turn off if e.g. we know that the PRB is already partially received when we start the transfer.
	// This prevents malicious or broken nodes from trickling transfers forever by sending the same packets over and over.
	static final boolean CHECK_DUPES = true;
	
	private boolean gotAllSent;
	
	private AsyncMessageFilterCallback notificationWaiter = new SlowAsyncMessageFilterCallback() {

		@Override
		public void onMatched(Message m1) {
            if(logMINOR)
            	Logger.minor(this, "Received "+m1);
            if ((m1 != null) && m1.getSpec().equals(DMT.sendAborted)) {
				String desc=m1.getString(DMT.DESCRIPTION);
				if (desc.indexOf("Upstream")<0)
					desc="Upstream transmit error: "+desc;
				_prb.abort(m1.getInt(DMT.REASON), desc, false);
				synchronized(BlockReceiver.this) {
					senderAborted = true;
				}
				complete(m1.getInt(DMT.REASON), desc);
				return;
			}
            boolean truncateTimeout = false;
			if ((m1 != null) && (m1.getSpec().equals(DMT.packetTransmit))) {
				// packetTransmit received
				int packetNo = m1.getInt(DMT.PACKET_NO);
				BitArray sent = (BitArray) m1.getObject(DMT.SENT);
				Buffer data = (Buffer) m1.getObject(DMT.DATA);
				int missing = 0;
				try {
					synchronized(BlockReceiver.this) {
						if(completed) return;
					}
					if(CHECK_DUPES && _prb.isReceived(packetNo)) {
						// Transmitter sent the same packet twice?!?!?
						Logger.error(this, "Already received the packet - DoS??? on "+this+" uid "+_uid+" from "+_sender);
						// Does not extend timeouts.
						truncateTimeout = true;
					} else {
						_prb.addPacket(packetNo, data);
						if(logMINOR) {
							synchronized(BlockReceiver.this) {
								long interval = System.currentTimeMillis() - timeStartedWaiting;
								Logger.minor(this, "Packet interval: "+interval+" = "+TimeUtil.formatTime(interval, 2, true)+" from "+_sender);
							}
						}
						// Check that we have what the sender thinks we have
						for (int x = 0; x < sent.getSize(); x++) {
							if (sent.bitAt(x) && !_prb.isReceived(x)) {
								missing++;
							}
						}
						if(logMINOR && missing != 0) 
							Logger.minor(this, "Packets which the sender says it has sent but we have not received: "+missing);
					}
				} catch (AbortedException e) {
					// We didn't cause it?!
					Logger.error(this, "Caught in receive - probably a bug as receive sets it: "+e, e);
					complete(RetrievalException.UNKNOWN, "Aborted?");
					return;
				}
			} else if (m1 != null && m1.getSpec().equals(DMT.allSent)) {
				synchronized(BlockReceiver.this) {
					if(completed) return;
					if(gotAllSent)
						// Multiple allSent's don't extend the timeouts.
						truncateTimeout = true;
					gotAllSent = true;
				}
			}
			try {
				if(_prb.allReceived()) {
					try {
						Message m = DMT.createAllReceived(_uid);
						if(completeAfterAckedAllReceived) {
							try {
								// FIXME layer violation
								// FIXME make asynchronous
								((PeerNode)_sender).sendSync(m, _ctr, _realTime);
							} catch (SyncSendWaitedTooLongException e) {
								// Complete anyway.
							}
						} else {
							_usm.send(_sender, m, _ctr);
						}
						discardEndTime=System.currentTimeMillis()+CLEANUP_TIMEOUT;
						discardFilter=relevantMessages(CLEANUP_TIMEOUT);
						maybeResetDiscardFilter();
					} catch (NotConnectedException e1) {
						// Ignore, we've got it.
						if(logMINOR) Logger.minor(this, "Got data but can't send allReceived to "+_sender+" as is disconnected");
					}
					long endTime = System.currentTimeMillis();
					long transferTime = (endTime - startTime);
					if(logMINOR) {
						synchronized(avgTimeTaken) {
							avgTimeTaken.report(transferTime);
							Logger.minor(this, "Block transfer took "+transferTime+"ms - average is "+avgTimeTaken);
						}
					}
					complete(_prb.getBlock());
					return;
				}
			} catch (AbortedException e1) {
				// We didn't cause it?!
				Logger.error(this, "Caught in receive - probably a bug as receive sets it: "+e1, e1);
				complete(RetrievalException.UNKNOWN, "Aborted?");
				return;
			}
			try {
				// Even if timeout <= 0, we still add the filter, because we want to receive any messages that are already buffered before we timeout.
				waitNotification(truncateTimeout);
			} catch (DisconnectedException e) {
				onDisconnect(null);
				return;
			}
		}
		
		@Override
		public boolean shouldTimeout() {
			return completed;
		}
		
		@Override
		public void onTimeout() {
			synchronized(this) {
				if(completed) return;
			}
			try {
				if(_prb.allReceived()) return;
				_prb.abort(RetrievalException.SENDER_DIED, "Sender unresponsive to resend requests", false);
				complete(RetrievalException.SENDER_DIED,
						"Sender unresponsive to resend requests");
				
				_timeoutHandler.onFirstTimeout();
				// If upstream caused the problem, then sender will itself timeout
				// and will tell us. So wait for a timeout.
				// It is important for load management that the two sides agree on the number of transfers happening.
				// Therefore we need to not complete until the other side has acknowledged that the transfer has been cancelled.
				MessageFilter mfSendAborted = MessageFilter.create().setTimeout(ACK_TRANSFER_FAILED_TIMEOUT).setType(DMT.sendAborted).setField(DMT.UID, _uid).setSource(_sender);
				try {
					_usm.addAsyncFilter(mfSendAborted, new SlowAsyncMessageFilterCallback() {

						@Override
						public void onMatched(Message m) {
							// Ok.
							if(logMINOR) Logger.minor(this, "Transfer cancel acknowledged");
						}

						@Override
						public boolean shouldTimeout() {
							return false;
						}

						@Override
						public void onTimeout() {
							Logger.error(this, "Other side did not acknowlege transfer failure on "+BlockReceiver.this);
							_timeoutHandler.onFatalTimeout(_sender);
						}

						@Override
						public void onDisconnect(PeerContext ctx) {
							// Ok.
						}

						@Override
						public void onRestarted(PeerContext ctx) {
							// Ok.
						}

						@Override
						public int getPriority() {
							return NativeThread.NORM_PRIORITY;
						}
						
					}, _ctr);
				} catch (DisconnectedException e) {
					// Ignore
				}
				
				return;
			} catch (AbortedException e) {
				// We didn't cause it?!
				Logger.error(this, "Caught in receive - probably a bug as receive sets it: "+e, e);
				complete(RetrievalException.UNKNOWN, "Aborted?");
				return;
			}
		}
		
		@Override
		public void onDisconnect(PeerContext ctx) {
			complete(RetrievalException.SENDER_DISCONNECTED, RetrievalException.getErrString(RetrievalException.SENDER_DISCONNECTED));
		}
		
		@Override
		public void onRestarted(PeerContext ctx) {
			complete(RetrievalException.SENDER_DISCONNECTED, RetrievalException.getErrString(RetrievalException.SENDER_DISCONNECTED));
		}

		@Override
		public int getPriority() {
			return NativeThread.NORM_PRIORITY;
		}
		
	};
	
	private boolean completed;
	
	private void complete(int reason, String description) {
		synchronized(this) {
			if(completed) {
				if(logMINOR) Logger.minor(this, "Already completed");
				return;
			}
			completed = true;
		}
		if(logMINOR)
			Logger.minor(this, "Transfer failed: ("+(_realTime?"realtime":"bulk")+") "+reason+" : "+description+" on "+_uid+" from "+_sender);
		_prb.removeListener(myListener);
		byte[] block = _prb.abort(reason, description, false);
		if(block == null) {
			// Expected behaviour.
			// Send the abort whether we have received one or not.
			// If we are cancelling due to failing to turtle, we need to tell the sender
			// this otherwise he will keep sending, wasting a lot of bandwidth on packets
			// that we will ignore. If we are cancelling because the sender has told us 
			// to, we need to acknowledge that.
			try {
				sendAborted(_prb._abortReason, _prb._abortDescription);
			} catch (NotConnectedException e) {
				// Ignore at this point.
			}
			callback.blockReceiveFailed(new RetrievalException(reason, description));
		} else {
			Logger.error(this, "Succeeded in complete("+reason+","+description+") on "+this, new Exception("error"));
			callback.blockReceived(block);
		}
		decRunningBlockReceives();
	}

	private void complete(byte[] ret) {
		synchronized(this) {
			if(completed) {
				if(logMINOR) Logger.minor(this, "Already completed");
				return;
			}
			completed = true;
		}
		_prb.removeListener(myListener);
		callback.blockReceived(ret);
		decRunningBlockReceives();
	}

	private long timeStartedWaiting = -1;
	
	private void waitNotification(boolean truncateTimeout) throws DisconnectedException {
		long timeout;
		long now = System.currentTimeMillis();
		synchronized(this) {
			if(truncateTimeout) {
				timeout = (int)Math.min(timeStartedWaiting + RECEIPT_TIMEOUT - now, RECEIPT_TIMEOUT);
			} else {
				timeStartedWaiting = now;
				timeout = RECEIPT_TIMEOUT;
			}
		}
		_usm.addAsyncFilter(relevantMessages(timeout), notificationWaiter, _ctr);
	}

	private MessageFilter relevantMessages(long timeout) {
		MessageFilter mfPacketTransmit = MessageFilter.create().setTimeout(timeout).setType(DMT.packetTransmit).setField(DMT.UID, _uid).setSource(_sender);
		MessageFilter mfAllSent = MessageFilter.create().setTimeout(timeout).setType(DMT.allSent).setField(DMT.UID, _uid).setSource(_sender);
		MessageFilter mfSendAborted = MessageFilter.create().setTimeout(timeout).setType(DMT.sendAborted).setField(DMT.UID, _uid).setSource(_sender);
		return mfPacketTransmit.or(mfAllSent.or(mfSendAborted));
	}

	PartiallyReceivedBlock.PacketReceivedListener myListener;
	
	public void receive(BlockReceiverCompletion callback) {
		startTime = System.currentTimeMillis();
		this.callback = callback;
		synchronized(_prb) {
			try {
				_prb.addListener(myListener = new PartiallyReceivedBlock.PacketReceivedListener() {;

					@Override
					public void packetReceived(int packetNo) {
						// Ignore
					}

					@Override
					public void receiveAborted(int reason, String description) {
						complete(reason, description);
					}
				});
			} catch (AbortedException e) {
				try {
					callback.blockReceived(_prb.getBlock());
					return;
				} catch (AbortedException e1) {
					e = e1;
				}
				callback.blockReceiveFailed(new RetrievalException(_prb._abortReason, _prb._abortDescription));
				return;
			}
		}
		incRunningBlockReceives();
		try {
			waitNotification(false);
		} catch (DisconnectedException e) {
			RetrievalException retrievalException = new RetrievalException(RetrievalException.SENDER_DISCONNECTED);
			_prb.abort(retrievalException.getReason(), retrievalException.toString(), true /* kind of, it shouldn't count towards the stats anyway */);
			callback.blockReceiveFailed(retrievalException);
			decRunningBlockReceives();
		} catch(RuntimeException e) {
			decRunningBlockReceives();
			throw e;
		} catch (Error e) {
			decRunningBlockReceives();
			throw e;
		}
	}
	
	private static MedianMeanRunningAverage avgTimeTaken = new MedianMeanRunningAverage();
	
	private void maybeResetDiscardFilter() {
		long timeleft=discardEndTime-System.currentTimeMillis();
		if (timeleft>0) {
			try {
				discardFilter.setTimeout((int)timeleft);
				_usm.addAsyncFilter(discardFilter, this, _ctr);
			} catch (DisconnectedException e) {
				//ignore
			}
		}
	}
	
	/**
	 * Used to discard leftover messages, usually just packetTransmit and allSent.
	 * allSent, is quite common, as the receive() routine usually quits immeadiately on receiving all packets.
	 * packetTransmit is less common, when receive() requested what it thought was a missing packet, only reordered.
	 */
	@Override
	public void onMatched(Message m) {
		if (logMINOR)
			Logger.minor(this, "discarding message post-receive: "+m);
		maybeResetDiscardFilter();												   
	}
	
	@Override
	public boolean shouldTimeout() {
		return false;
	}
	
	@Override
	public void onTimeout() {
		//ignore
	}

	@Override
	public void onDisconnect(PeerContext ctx) {
		// Ignore
	}

	@Override
	public void onRestarted(PeerContext ctx) {
		// Ignore
	}

	public synchronized boolean senderAborted() {
		return senderAborted;
	}
	
	static int runningBlockReceives = 0;
	
	private void incRunningBlockReceives() {
		if(logMINOR) Logger.minor(this, "Starting block receive "+_uid);
		synchronized(BlockReceiver.class) {
			runningBlockReceives++;
			if(logMINOR) Logger.minor(BlockTransmitter.class, "Started a block receive, running: "+runningBlockReceives);
		}
	}
	
	private void decRunningBlockReceives() {
		if(logMINOR) Logger.minor(this, "Stopping block receive "+_uid);
		synchronized(BlockReceiver.class) {
			runningBlockReceives--;
			if(logMINOR) Logger.minor(BlockTransmitter.class, "Finished a block receive, running: "+runningBlockReceives);
		}
	}

	public synchronized static int getRunningReceives() {
		return runningBlockReceives;
	}
	
	@Override
	public String toString() {
		return super.toString()+":"+_uid+":"+_sender.shortToString();
	}
	
}
