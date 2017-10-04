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

import java.util.HashSet;
import java.util.Deque;

import freenet.io.comm.AsyncMessageCallback;
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
import freenet.node.MessageItem;
import freenet.io.comm.SlowAsyncMessageFilterCallback;
import freenet.node.PrioRunnable;
import freenet.support.BitArray;
import freenet.support.Executor;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Ticker;
import freenet.support.TimeUtil;
import freenet.support.Logger.LogLevel;
import freenet.support.io.NativeThread;
import freenet.support.math.MedianMeanRunningAverage;

/**
 * @author ian
 *
 * Given a PartiallyReceivedBlock retransmit to another node (to be received by BlockReceiver).
 * Since a PRB can be concurrently transmitted to many peers NOWHERE in this class is prb.abort() to be called.
 * 
 * SECURITY: We must keep sending the data even if the inter-block interval becomes too
 * large for the receiver to be able to accept the data. Otherwise a malicious node can
 * use much more bandwidth on our input and upstream nodes than he expends himself, simply
 * by doing lots of requests and only accepting a few bytes per second worth of packets. 
 * Obviously if such situations arise naturally they should be handled via load limiting -
 * either the originator itself with an accurate bandwidth limit, or the packets-in-flight
 * limit.
 */
public class BlockTransmitter {

	private static volatile boolean logMINOR;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	public static final int SEND_TIMEOUT = 60000;
	
	final MessageCore _usm;
	final PeerContext _destination;
	private boolean _sentSendAborted;
	final long _uid;
	private final boolean realTime;
	final PartiallyReceivedBlock _prb;
	private Deque<Integer> _unsent;
	private BlockSenderJob _senderThread = new BlockSenderJob();
	private BitArray _sentPackets;
	private long timeAllSent = -1;
	final ByteCounter _ctr;
	final int PACKET_SIZE;
	private final ReceiverAbortHandler abortHandler;
	private HashSet<MessageItem> itemsPending = new HashSet<MessageItem>();
	
	private final Ticker _ticker;
	private final Executor _executor;
	private final BlockTransmitterCompletion _callback;
	
	public interface BlockTimeCallback {
		public void blockTime(long interval, boolean realtime);
	}
	
	private final BlockTimeCallback blockTimeCallback;

	/** Have we received a completion acknowledgement from the other side - either a 
	 * sendAborted or allReceived? */
	private boolean _receivedSendCompletion;
	/** Was it an allReceived? */
	private boolean _receivedSendSuccess;
	/** Have we completed i.e. called the callback? */
	private boolean _completed;
	/** Have we failed e.g. due to PRB abort, disconnection? */
	private boolean _failed;
	
	static int runningBlockTransmits = 0;
	
	class BlockSenderJob implements PrioRunnable {
		
		private boolean running = false;
		
		@Override
		public void run() {
			synchronized(this) {
				if(running) return;
				running = true;
			}
			try {
				while(true) {
					int packetNo = -1;
					BitArray copy;
					synchronized(_senderThread) {
						if(_failed || _receivedSendCompletion || _completed) return;
						if(_unsent.size() == 0) {
							// Wait for PRB callback to tell us we have more packets.
							return;
						}
						else {
							packetNo = _unsent.removeFirst();
							if(_sentPackets.bitAt(packetNo)) {
								Logger.error(this, "Already sent packet in run(): "+packetNo+" for "+this+" unsent is "+_unsent+" sent is "+_sentPackets, new Exception("error"));
								continue;
							}
						}
						copy = _sentPackets.copy();
						_sentPackets.setBit(packetNo, true);
					}
					if(!innerRun(packetNo, copy)) return;
				}
			} finally {
				synchronized(this) {
					running = false;
				}
			}
		}
		
		public void schedule() {
			if(_failed || _receivedSendCompletion || _completed) {
				if(logMINOR) Logger.minor(this, "Not scheduling for "+_uid+" to "+_destination+" :"+
						(_failed ? "(failed) " : "") + (_receivedSendCompletion ? "(receivedSendCompletion) " : "") + (_completed ? "(completed) " : ""));
				return;
			}
			_executor.execute(this, "BlockTransmitter block sender for "+_uid+" to "+_destination);
		}

		/** @return True . */
		private boolean innerRun(int packetNo, BitArray copied) {
			try {
				Message msg = DMT.createPacketTransmit(_uid, packetNo, copied, _prb.getPacket(packetNo), realTime);
				MyAsyncMessageCallback cb = new MyAsyncMessageCallback();
				MessageItem item;
				// Everything is throttled.
				item = _destination.sendAsync(msg, cb, _ctr);
				synchronized(itemsPending) {
					itemsPending.add(item);
				}
			} catch (NotConnectedException e) {
				onDisconnect();
				return false;
			} catch (AbortedException e) {
				Logger.normal(this, "Terminating send due to abort: "+e);
				// The PRB callback will deal with this.
				return false;
			}
			boolean success = false;
			boolean complete = false;
			synchronized (_senderThread) {
				if(_unsent.size() == 0 && getNumSent() == _prb._packets) {
					//No unsent packets, no unreceived packets
					sendAllSentNotification();
					if(maybeAllSent()) {
						if(maybeComplete()) {
							complete = true;
							success = _receivedSendSuccess;
						} else return false;
					} else {
						return false;
					}
				}
			}
			if(complete) {
				callCallback(success);
				return false; // No more blocks to send.
			}
			return true; // More blocks to send.
		}

		@Override
		public int getPriority() {
			return NativeThread.HIGH_PRIORITY;
		}
		
	}
	
	public BlockTransmitter(MessageCore usm, Ticker ticker, PeerContext destination, long uid, PartiallyReceivedBlock source, ByteCounter ctr, ReceiverAbortHandler abortHandler, BlockTransmitterCompletion callback, boolean realTime, BlockTimeCallback blockTimes) {
		this.realTime = realTime;
		_ticker = ticker;
		_executor = _ticker.getExecutor();
		_callback = callback;
		this.abortHandler = abortHandler;
		_usm = usm;
		_destination = destination;
		_uid = uid;
		_prb = source;
		_ctr = ctr;
		if(_ctr == null) throw new NullPointerException();
		PACKET_SIZE = DMT.packetTransmitSize(_prb._packetSize, _prb._packets);
		try {
			_sentPackets = new BitArray(_prb.getNumPackets());
		} catch (AbortedException e) {
			Logger.error(this, "Aborted during setup");
			// Will throw on running
		}
		this.blockTimeCallback = blockTimes;
		if(logMINOR) Logger.minor(this, "Starting block transmit for "+uid+" to "+destination.shortToString()+" realtime="+realTime);
	}

	private Runnable timeoutJob;
	
	public void scheduleTimeoutAfterBlockSends() {
		synchronized(_senderThread) {
			if(_receivedSendCompletion) return;
			if(timeoutJob != null) return;
			if(logMINOR) Logger.minor(this, "Scheduling timeout on "+this);
			timeoutJob = new PrioRunnable() {
				
				@Override
				public void run() {
					String timeString;
					String abortReason;
					Future fail;
					synchronized(_senderThread) {
						if(_completed) return;
						boolean hadSendCompletion = _receivedSendCompletion;
						if(!_receivedSendCompletion) {
							_receivedSendCompletion = true;
							_receivedSendSuccess = false;
						}
						//SEND_TIMEOUT (one minute) after all packets have been transmitted, terminate the send.
						if(_failed) {
							// Already failed, we were just waiting for the acknowledgement sendAborted.
							if(!hadSendCompletion) {
								Logger.warning(this, "Terminating send after failure on "+this);
								abortReason = "Already failed and no acknowledgement";
							} else {
								// Waiting for transfers maybe???
								if(logMINOR) Logger.minor(this, "Trying to terminate send after timeout");
								abortReason = "Already failed";
							}
						} else {
							timeString=TimeUtil.formatTime((System.currentTimeMillis() - timeAllSent), 2, true);
							Logger.warning(this, "Terminating send "+_uid+" to "+_destination+" from "+_destination.getSocketHandler()+" as we haven't heard from receiver in "+timeString+ '.');
							abortReason = "Haven't heard from you (receiver) in "+timeString;
						}
						fail = maybeFail(RetrievalException.RECEIVER_DIED, abortReason);
					}
					fail.execute();
				}
				
				@Override
				public int getPriority() {
					return NativeThread.NORM_PRIORITY;
				}
				
			};
			_ticker.queueTimedJob(timeoutJob, "Timeout for "+this, SEND_TIMEOUT, false, false);
		}
	}

	/** LOCKING: Must be called with _senderThread held. 
	 * @return True if everything has been sent and we are now just waiting for an
	 * acknowledgement or timeout from the other side. */
	public boolean maybeAllSent() {
		if(blockSendsPending == 0 && _unsent.size() == 0 && getNumSent() == _prb._packets) {
			timeAllSent = System.currentTimeMillis();
			if(logMINOR)
				Logger.minor(this, "Sent all blocks, none unsent on "+this);
			_senderThread.notifyAll();
			return true;
		}
		if(blockSendsPending == 0 && _failed) {
			timeAllSent = System.currentTimeMillis();
			if(logMINOR)
				Logger.minor(this, "Sent blocks and failed on "+this);
			return true;
		}
		if(logMINOR) Logger.minor(this, "maybeAllSent: block sends pending = "+blockSendsPending+" unsent = "+_unsent.size()+" sent = "+getNumSent()+" on "+this);
		return false;
	}

	/** Complete? maybeAllSent() must have already returned true. This method checks 
	 * _sendCompleted and then uses _completed to complete only once. LOCKING: Must be 
	 * called with _senderThread held. 
	 * Caller must call the callback then call cleanup() outside the lock if this returns true. */
	public boolean maybeComplete() {
		if(!_receivedSendCompletion) {
			if(logMINOR) Logger.minor(this, "maybeComplete() not completing because send not completed on "+this);
			// All the block sends have completed, wait for the other side to acknowledge or timeout.
			scheduleTimeoutAfterBlockSends();
			return false;
		}
		if(_completed) {
			if(logMINOR) Logger.minor(this, "maybeComplete() already completed on "+this);
			return false;
		}
		if(logMINOR) Logger.minor(this, "maybeComplete() completing on "+this);
		_completed = true;
		decRunningBlockTransmits();
		return true;
	}
	
	interface Future {
		void execute();
	}
	
	private final Future nullFuture = new Future() {

		@Override
		public void execute() {
			// Do nothing.
		}
		
	};
	
	/** Only fail once. Called on a drastic failure e.g. disconnection. Unless we are sure
	 * that we don't need to (e.g. on disconnection), the caller must call prepareSendAborted
	 * afterwards, and if that returns true, send the sendAborted via innerSendAborted.
	 * LOCKING: Must be called inside the _senderThread lock.
	 * @return A Future which the caller must execute() outside the lock. */
	public Future maybeFail(final int reason, final String description) {
		if(_completed) {
			if(logMINOR) Logger.minor(this, "maybeFail() already completed on "+this);
			return nullFuture;
		}
		_failed = true;
		if(!_receivedSendCompletion) {
			// Don't actually timeout until after we have an acknowledgement of the transfer cancel.
			// This is important for keeping track of how many transfers are actually running, which will be important for load management later on.
			// The caller will immediately call prepareSendAbort() then innerSendAborted().
			if(logMINOR) Logger.minor(this, "maybeFail() waiting for acknowledgement on "+this);
			if(_sentSendAborted) {
				scheduleTimeoutAfterBlockSends();
				return nullFuture; // Do nothing, waiting for timeout.
			} else {
				_sentSendAborted = true;
				// Send the aborted, then wait.
				return new Future() {

					@Override
					public void execute() {
						try {
							innerSendAborted(reason, description);
							scheduleTimeoutAfterBlockSends();
						} catch (NotConnectedException e) {
							onDisconnect();
						}
					}
					
				};
			}
		}
		if(blockSendsPending != 0) {
			if(logMINOR) Logger.minor(this, "maybeFail() waiting for "+blockSendsPending+" block sends on "+this);
			if(_sentSendAborted)
				return nullFuture; // Wait for blockSendsPending to reach 0
			else {
				_sentSendAborted = true;
				// They have sent us a cancel, but we still need to send them an ack or they will do a fatal timeout.
				return new Future() {

					@Override
					public void execute() {
						try {
							innerSendAborted(reason, description);
						} catch (NotConnectedException e) {
							onDisconnect();
						}
					}
				
				};
			}
		}
		if(logMINOR) Logger.minor(this, "maybeFail() completing on "+this);
		_completed = true;
		decRunningBlockTransmits();
		final boolean sendAborted = _sentSendAborted;
		_sentSendAborted = true;
		return new Future() {

			@Override
			public void execute() {
				if(!sendAborted) {
					try {
						innerSendAborted(reason, description);
					} catch (NotConnectedException e) {
						onDisconnect();
					}
				}
				callCallback(false);
			}
			
		};
	}
	
	/** Abort the send, and then send the sendAborted message. Don't do anything if the
	 * send has already been aborted. */
	public void abortSend(int reason, String desc) throws NotConnectedException {
		if(logMINOR) Logger.minor(this, "Aborting send on "+this);
		Future fail;
		synchronized(_senderThread) {
			_failed = true;
			fail = maybeFail(reason, desc);
		}
		fail.execute();
		cancelItemsPending();
	}
	
	public void innerSendAborted(int reason, String desc) throws NotConnectedException {
		_usm.send(_destination, DMT.createSendAborted(_uid, reason, desc), _ctr);
	}
	
	private void sendAllSentNotification() {
		try {
			_usm.send(_destination, DMT.createAllSent(_uid), _ctr);
		} catch (NotConnectedException e) {
			Logger.normal(this, "disconnected for allSent()");
		}
	}
	
	public interface ReceiverAbortHandler {
		
		/** @return True to cancel the PRB and thus cascade the cancel to the downstream
		 * transfer, false otherwise. */
		public boolean onAbort();
		
	}
	
	public static final ReceiverAbortHandler ALWAYS_CASCADE = new ReceiverAbortHandler() {

		@Override
		public boolean onAbort() {
			return true;
		}
		
	};
	
	public static final ReceiverAbortHandler NEVER_CASCADE = new ReceiverAbortHandler() {

		@Override
		public boolean onAbort() {
			return false;
		}
		
	};
	
	public interface BlockTransmitterCompletion {
		
		public void blockTransferFinished(boolean success);
		
	}
	
	private PartiallyReceivedBlock.PacketReceivedListener myListener = null;

	private AsyncMessageFilterCallback cbAllReceived = new SlowAsyncMessageFilterCallback() {

		@Override
		public void onMatched(Message m) {
			if(logMINOR) {
				long endTime = System.currentTimeMillis();
				long transferTime = (endTime - startTime);
				synchronized(avgTimeTaken) {
					avgTimeTaken.report(transferTime);
					Logger.minor(this, "Block send took "+transferTime+" : "+avgTimeTaken+" on "+BlockTransmitter.this);
				}
			}
			synchronized(_senderThread) {
				_receivedSendCompletion = true;
				_receivedSendSuccess = true;
				if(!maybeAllSent()) return;
				if(!maybeComplete()) return;
			}
			callCallback(true);
		}

		@Override
		public boolean shouldTimeout() {
			synchronized(_senderThread) {
				// We are waiting for the send completion, which is set on timeout as well as on receiving a message.
				// In some corner cases we might want to get the allReceived after setting _failed, so don't timeout on _failed.
				// We do want to timeout on _completed because that means everything is finished - it is only set in maybeComplete() and maybeFail().
				if(_receivedSendCompletion || _completed) return true; 
			}
			return false;
		}

		@Override
		public void onTimeout() {
			// Do nothing
		}

		@Override
		public void onDisconnect(PeerContext ctx) {
			BlockTransmitter.this.onDisconnect();
		}

		@Override
		public void onRestarted(PeerContext ctx) {
			BlockTransmitter.this.onDisconnect();
		}

		@Override
		public int getPriority() {
			return NativeThread.NORM_PRIORITY;
		}
		
	};
	
	private AsyncMessageFilterCallback cbSendAborted = new SlowAsyncMessageFilterCallback() {

		@Override
		public void onMatched(Message msg) {
			if((!_prb.isAborted()) && abortHandler.onAbort())
				_prb.abort(RetrievalException.CANCELLED_BY_RECEIVER, "Cascading cancel from receiver", true);
			Future fail;
			synchronized(_senderThread) {
				_receivedSendCompletion = true;
				_receivedSendSuccess = false;
				fail = maybeFail(msg.getInt(DMT.REASON), msg.getString(DMT.DESCRIPTION));
				if(logMINOR) Logger.minor(this, "Transfer got sendAborted on "+BlockTransmitter.this);
			}
			fail.execute();
			cancelItemsPending();
		}

		@Override
		public boolean shouldTimeout() {
			synchronized(_senderThread) {
				// We are waiting for the send completion, which is set on timeout as well as on receiving a message.
				// We don't want to timeout on _failed because we can set _failed, send sendAborted, and then wait for the acknowledging sendAborted.
				// We do want to timeout on _completed because that means everything is finished - it is only set in maybeComplete() and maybeFail().
				if(_receivedSendCompletion || _completed) return true; 
			}
			return false;
		}

		@Override
		public void onTimeout() {
			// Do nothing
		}

		@Override
		public void onDisconnect(PeerContext ctx) {
			BlockTransmitter.this.onDisconnect();
		}

		@Override
		public void onRestarted(PeerContext ctx) {
			BlockTransmitter.this.onDisconnect();
		}

		@Override
		public int getPriority() {
			return NativeThread.NORM_PRIORITY;
		}
		
	};
	
	private void onDisconnect() {
		Logger.normal(this, "Terminating send "+_uid+" to "+_destination+" from "+_destination.getSocketHandler()+" because node disconnected while waiting");
		//They disconnected, can't send an abort to them then can we?
		Future fail;
		synchronized(_senderThread) {
			_receivedSendCompletion = true; // effectively
			blockSendsPending = 0; // effectively
			_sentSendAborted = true; // effectively
			fail = maybeFail(RetrievalException.SENDER_DISCONNECTED, "Sender disconnected");
		}
		fail.execute();
		// Sometimes disconnect doesn't clear the message queue.
		// Since we are cancelling the transfer, we need to unqueue the messages.
		cancelItemsPending();
	}
	
	private void onAborted(int reason, String description) {
		if(logMINOR) Logger.minor(this, "Aborting on "+this);
		Future fail;
		synchronized(_senderThread) {
			timeAllSent = -1;
			_failed = true;
			_senderThread.notifyAll();
			fail = maybeFail(reason, description);
		}
		fail.execute();
		cancelItemsPending();
	}

	private long startTime;
	
	/** Send the data, off-thread. */
	public void sendAsync() {
		startTime = System.currentTimeMillis();
		
		if(logMINOR) Logger.minor(this, "Starting async send on "+this);
		incRunningBlockTransmits();
		
		try {
			synchronized(_prb) {
				_unsent = _prb.addListener(myListener = new PartiallyReceivedBlock.PacketReceivedListener() {;

					@Override
					public void packetReceived(int packetNo) {
						synchronized(_senderThread) {
							if(logMINOR) Logger.minor(this, "Got packet "+packetNo+" for "+_uid+" to "+_destination);
							if(_unsent.contains(packetNo)) {
								Logger.error(this, "Already in unsent: "+packetNo+" for "+this+" unsent is "+_unsent, new Exception("error"));
								return;
							}
							if(_sentPackets.bitAt(packetNo)) {
								Logger.error(this, "Already sent packet in packetReceived: "+packetNo+" for "+this+" unsent is "+_unsent+" sent is "+_sentPackets, new Exception("error"));
								return;
							}
							_unsent.addLast(packetNo);
							timeAllSent = -1;
							_senderThread.schedule();
						}
					}

					@Override
					public void receiveAborted(int reason, String description) {
						onAborted(reason, description);
					}
				});
			}
			_senderThread.schedule();

			MessageFilter mfAllReceived = MessageFilter.create().setType(DMT.allReceived).setField(DMT.UID, _uid).setSource(_destination).setNoTimeout();
			MessageFilter mfSendAborted = MessageFilter.create().setType(DMT.sendAborted).setField(DMT.UID, _uid).setSource(_destination).setNoTimeout();
			
			try {
				_usm.addAsyncFilter(mfAllReceived, cbAllReceived, _ctr);
				_usm.addAsyncFilter(mfSendAborted, cbSendAborted, _ctr);
			} catch (DisconnectedException e) {
				onDisconnect();
			}
			
		} catch (AbortedException e) {
			onAborted(_prb._abortReason, _prb._abortDescription);
		}
	}
	
	private void cancelItemsPending() {
		MessageItem[] items;
		synchronized(itemsPending) {
			items = itemsPending.toArray(new MessageItem[itemsPending.size()]);
			itemsPending.clear();
		}
		for(MessageItem item : items) {
			if(!_destination.unqueueMessage(item)) {
				// Race condition, can happen
				if(logMINOR) Logger.minor(this, "Message not queued ?!?!?!? on "+this+" : "+item);
			}
		}
	}

	long timeLastBlockSendCompleted = -1;
	
	private static synchronized void incRunningBlockTransmits() {
		runningBlockTransmits++;
		if(logMINOR) Logger.minor(BlockTransmitter.class, "Started a block transmit, running: "+runningBlockTransmits);
	}

	private static synchronized void decRunningBlockTransmits() {
		runningBlockTransmits--;
		if(logMINOR) Logger.minor(BlockTransmitter.class, "Finished a block transmit, running: "+runningBlockTransmits);
	}

	private void cleanup() {
		// FIXME remove filters
		// shouldTimeout() should deal with them adequately, maybe we don't need to explicitly remove them.
		if (myListener!=null)
			_prb.removeListener(myListener);
	}

	private class MyAsyncMessageCallback implements AsyncMessageCallback {

		
		MyAsyncMessageCallback() {
			synchronized(_senderThread) {
				blockSendsPending++;
			}
		}
		
		private boolean completed = false;
		
		@Override
		public void sent() {
			if(logMINOR) Logger.minor(this, "Sent block on "+BlockTransmitter.this);
			// Wait for acknowledged
		}

		@Override
		public void acknowledged() {
			complete(false);
		}

		@Override
		public void disconnected() {
			// FIXME kill transfer
			complete(true);
		}

		@Override
		public void fatalError() {
			// FIXME kill transfer
			complete(true);
		}
		
		private void complete(boolean failed) {
			if(logMINOR) Logger.minor(this, "Completed send on a block for "+BlockTransmitter.this);
			boolean success = false;
			long now = System.currentTimeMillis();
			boolean callCallback = false;
			long delta = -1;
			synchronized(_senderThread) {
				if(completed) return;
				completed = true;
				if(lastSentPacket > 0) {
					delta = now - lastSentPacket;
					long threshold = (realTime ? BlockReceiver.RECEIPT_TIMEOUT_REALTIME : BlockReceiver.RECEIPT_TIMEOUT_BULK);
					if(delta > threshold)
						Logger.warning(this, "Time between packets on "+BlockTransmitter.this+" : "+TimeUtil.formatTime(delta, 2, true)+" ( "+delta+"ms) realtime="+realTime);
					else if(delta > threshold / 5)
						Logger.normal(this, "Time between packets on "+BlockTransmitter.this+" : "+TimeUtil.formatTime(delta, 2, true)+" ( "+delta+"ms) realtime="+realTime);
					else if(logMINOR) 
						Logger.minor(this, "Time between packets on "+BlockTransmitter.this+" : "+TimeUtil.formatTime(delta, 2, true)+" ( "+delta+"ms) realtime="+realTime);
				}
				lastSentPacket = now;
				blockSendsPending--;
				if(logMINOR) Logger.minor(this, "Pending: "+blockSendsPending);
				if(maybeAllSent()) {
					if(maybeComplete()) {
						callCallback = true;
						success = _receivedSendSuccess;
					}
				}
			}
			if(!failed)
				// Everything is throttled, but payload is not reported.
				_ctr.sentPayload(PACKET_SIZE);
			if(callCallback) {
				callCallback(success);
			}
			if(delta > 0 && blockTimeCallback != null) {
				blockTimeCallback.blockTime(delta, realTime);
			}
		}

	};
	
	private int blockSendsPending = 0;
	
	private long lastSentPacket = -1;
	
	private static MedianMeanRunningAverage avgTimeTaken = new MedianMeanRunningAverage();
	
	/** LOCKING: Must be called with _senderThread held. */
	private int getNumSent() {
		int ret = 0;
		for (int x=0; x<_sentPackets.getSize(); x++) {
			if (_sentPackets.bitAt(x)) {
				ret++;
			}
		}
		return ret;
	}
	
	public void callCallback(final boolean success) {
		if(_callback != null) {
			_executor.execute(new Runnable() {

				@Override
				public void run() {
					try {
						_callback.blockTransferFinished(success);
					} finally {
						cleanup();
					}
				}
				
			}, "BlockTransmitter completion callback for "+this);
		} else {
			cleanup();
		}
	}

	public PeerContext getDestination() {
		return _destination;
	}
	
	@Override
	public String toString() {
		return "BlockTransmitter for "+_uid+" to "+_destination.shortToString();
	}

	public synchronized static int getRunningSends() {
		return runningBlockTransmits;
	}
}
