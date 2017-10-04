/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.io.xfer;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import freenet.io.comm.AsyncMessageCallback;
import freenet.io.comm.AsyncMessageFilterCallback;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.Message;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.PeerContext;
import freenet.node.PrioRunnable;
import freenet.support.BitArray;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.io.NativeThread;

/**
 * Bulk data transfer (not block). Bulk transfer is designed for files which may be much bigger than a 
 * key block, and where we have the whole file at the outset. Do not persist across node restarts.
 * 
 * Used by update over mandatory, sending a file to our peers attached to an N2NTM etc.
 * @author toad
 */
public class BulkTransmitter {
	
	public interface AllSentCallback {

		void allSent();

	}

	/** If no packets sent in this period, and no completion acknowledgement / cancellation, assume failure. */
	static final long TIMEOUT = MINUTES.toMillis(5);
	/** Time to hang around listening for the last FNPBulkReceivedAll message */
	static final long FINAL_ACK_TIMEOUT = SECONDS.toMillis(10);
	final AllSentCallback allSentCallback;
	/** Available blocks */
	final PartiallyReceivedBulk prb;
	/** Peer who we are sending the data to */
	final PeerContext peer;
	/** Transfer UID for messages */
	final long uid;
	/** Blocks we have but haven't sent yet. 0 = block sent or not present, 1 = block present but not sent */
	final BitArray blocksNotSentButPresent;
	private boolean cancelled;
	/** Not persistent over reboots */
	final long peerBootID;
	private boolean sentCancel;
	private boolean finished;
	/** Not expecting a response? */
	final boolean noWait;
	private long finishTime=-1;
	private String cancelReason;
	private final ByteCounter ctr;
	private final boolean realTime;
	
	private static long transfersCompleted;
	private static long transfersSucceeded;

        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
	public BulkTransmitter(PartiallyReceivedBulk prb, PeerContext peer, long uid, boolean noWait, ByteCounter ctr, boolean realTime) throws DisconnectedException {
		this(prb, peer, uid, noWait, ctr, realTime, null);
	}
	
	/**
	 * Create a bulk data transmitter.
	 * @param prb The PartiallyReceivedBulk containing the file we want to send, or the part of it that we have so far.
	 * @param peer The peer we want to send it to.
	 * @param uid The unique identifier for this data transfer
	 * @param noWait If true, don't wait for an FNPBulkReceivedAll, return as soon as we've sent everything.
	 * @throws DisconnectedException If the peer we are trying to send to becomes disconnected.
	 */
	public BulkTransmitter(PartiallyReceivedBulk prb, PeerContext peer, long uid, boolean noWait, ByteCounter ctr, boolean realTime, AllSentCallback cb) throws DisconnectedException {
		this.prb = prb;
		this.peer = peer;
		this.uid = uid;
		this.noWait = noWait;
		this.ctr = ctr;
		this.realTime = realTime;
		this.allSentCallback = cb;
		if(ctr == null) throw new NullPointerException();
		peerBootID = peer.getBootID();
		// Need to sync on prb while doing both operations, to avoid race condition.
		// Specifically, we must not get calls to blockReceived() until blocksNotSentButPresent
		// has been set, AND it must be accurate, so there must not be an unlocked period
		// between cloning and adding.
		synchronized(prb) {
			// We can just clone it.
			blocksNotSentButPresent = prb.cloneBlocksReceived();
			prb.add(this);
		}
		try {
			prb.usm.addAsyncFilter(MessageFilter.create().setNoTimeout().setSource(peer).setType(DMT.FNPBulkReceiveAborted).setField(DMT.UID, uid),
					new AsyncMessageFilterCallback() {
						@Override
						public void onMatched(Message m) {
							cancel("Other side sent FNPBulkReceiveAborted");
						}
						@Override
						public boolean shouldTimeout() {
							synchronized(BulkTransmitter.this) {
								if(cancelled || finished) return true;
							}
							if(BulkTransmitter.this.prb.isAborted()) return true;
							return false;
						}
						@Override
						public void onTimeout() {
							// Ignore
						}
						@Override
						public void onDisconnect(PeerContext ctx) {
							// Ignore
						}
						@Override
						public void onRestarted(PeerContext ctx) {
							// Ignore
						}
			}, ctr);
			prb.usm.addAsyncFilter(MessageFilter.create().setNoTimeout().setSource(peer).setType(DMT.FNPBulkReceivedAll).setField(DMT.UID, uid),
					new AsyncMessageFilterCallback() {
						@Override
						public void onMatched(Message m) {
							// send() will terminate, so must call setAllQueued().
							setAllQueued();
							completed();
						}
						@Override
						public boolean shouldTimeout() {
							synchronized(BulkTransmitter.this) {
								   if (cancelled) return true;
								   if (finished)  return (System.currentTimeMillis()-finishTime > FINAL_ACK_TIMEOUT);
							}
							if(BulkTransmitter.this.prb.isAborted()) return true;
							return false;
						}
						@Override
						public void onTimeout() {
							// Ignore
						}
						@Override
						public void onDisconnect(PeerContext ctx) {
							// Ignore
						}
						@Override
						public void onRestarted(PeerContext ctx) {
							// Ignore
						}
			}, ctr);
		} catch (DisconnectedException e) {
			cancel("Disconnected");
			throw e;
		}
	}

	/**
	 * Received a block. Set the relevant bit to 1 to indicate that we have the block but haven't sent
	 * it yet. **Only called by PartiallyReceivedBulk.**
	 * @param block The block number that has been received.
	 */
	synchronized void blockReceived(int block) {
		blocksNotSentButPresent.setBit(block, true);
		notifyAll();
	}

	/**
	 * Called when the PRB is aborted.
	 */
	public void onAborted() {
		sendAbortedMessage();
		synchronized(this) {
			notifyAll();
		}
	}
	
	private void sendAbortedMessage() {
		synchronized(this) {
			if(sentCancel) return;
			sentCancel = true;
		}
		try {
			peer.sendAsync(DMT.createFNPBulkSendAborted(uid), null, ctr);
		} catch (NotConnectedException e) {
			// Cool
		}
	}

	public void cancel(String reason) {
		if(logMINOR)
			Logger.minor(this, "Cancelling "+this);
		sendAbortedMessage();
		synchronized(this) {
			if(cancelled || finished) return;
			cancelled = true;
			cancelReason = reason;
			notifyAll();
		}
		prb.remove(this);
		synchronized(BulkTransmitter.class) {
			transfersCompleted++;
		}
		// Call AllSentCallback if necessary.
		// If there are packets still waiting, it will be called after they are sent or failed.
		setAllQueued();
	}

	/** Like cancel(), but without the negative overtones: The client says it's got everything,
	 * we believe them (even if we haven't sent everything; maybe they had a partial). */
	public void completed() {
		synchronized(this) {
			if(cancelled || finished) return;
			finished = true;
			finishTime = System.currentTimeMillis();
			notifyAll();
		}
		prb.remove(this);
		synchronized(BulkTransmitter.class) {
			transfersCompleted++;
			transfersSucceeded++;
		}
		if(logMINOR) Logger.minor(this, "Completed transfer successfully "+this);
	}
	
	/**
	 * Send the file.
	 * @return True if the file was successfully sent. False otherwise.
	 * @throws DisconnectedException 
	 */
	public boolean send() throws DisconnectedException {
		long lastSentPacket = System.currentTimeMillis();
outer:	while(true) {
			int max = Math.min(Integer.MAX_VALUE, prb.blocks);
			max = Math.min(max, peer.getThrottleWindowSize());
			// FIXME Need to introduce the global limiter of [code]max[/code] for memory management instead of hard-code for each, no? 
			max = Math.min(max, 100); 
			if(max < 1) max = 1;
			
			if(prb.isAborted()) {
				if(logMINOR)
					Logger.minor(this, "Aborted "+this);
				return false;
			}
			int blockNo;
			if(peer.getBootID() != peerBootID) {
				synchronized(this) {
					cancelled = true;
					notifyAll();
				}
				prb.remove(BulkTransmitter.this);
				if(logMINOR)
					Logger.minor(this, "Failed to send "+uid+": peer restarted: "+peer);
				throw new DisconnectedException();
			}
			synchronized(this) {
				if(finished) return true;
				if(cancelled) return false;
				blockNo = blocksNotSentButPresent.firstOne();
			}
			if(blockNo < 0) {
				setAllQueued();
				if(noWait && prb.hasWholeFile()) {
					completed();
					return true;
				}
				synchronized(this) {
					// Wait for all packets to complete
					while(true) {
						if(failedPacket) {
							cancel("Packet send failed");
							return false;
						}
						if(logMINOR)
							Logger.minor(this, "Waiting for packets: remaining: "+inFlightPackets);
						if(inFlightPackets == 0) break;
						try {
							wait();
							if(failedPacket) {
								cancel("Packet send failed");
								return false;
							}
							if(inFlightPackets == 0) break;
							continue outer; // Might be a packet...
						} catch (InterruptedException e) {
							// Ignore
						}
					}
					
					// Wait for a packet to come in, BulkReceivedAll or BulkReceiveAborted
					try {
						wait(SECONDS.toMillis(60));
					} catch (InterruptedException e) {
						// No problem
						continue;
					}
				}
				long end = System.currentTimeMillis();
				if(end - lastSentPacket > TIMEOUT) {
					Logger.error(this, "Send timed out on "+this);
					cancel("Timeout awaiting BulkReceivedAll");
					return false;
				}
				continue;
			}
			// Send a packet
			byte[] buf = prb.getBlockData(blockNo);
			if(buf == null) {
				if(logMINOR)
					Logger.minor(this, "Block "+blockNo+" is null, presumably the send is cancelled: "+this);
				// Already cancelled, quit
				return false;
			}
			
			// Congestion control and bandwidth limiting
			try {
				if(logMINOR) Logger.minor(this, "Sending packet "+blockNo);
				Message msg = DMT.createFNPBulkPacketSend(uid, blockNo, buf);
				UnsentPacketTag tag = new UnsentPacketTag();
				peer.sendAsync(msg, tag, ctr);
				synchronized(this) {
					while(inFlightPackets >= max && !failedPacket)
						try {
							wait(1000);
						} catch (InterruptedException e) {
							// Ignore
						}
				}
				synchronized(this) {
					blocksNotSentButPresent.setBit(blockNo, false);
				}
				lastSentPacket = System.currentTimeMillis();
			} catch (NotConnectedException e) {
				cancel("Disconnected");
				if(logMINOR)
					Logger.minor(this, "Cancelled: not connected "+this);
				throw new DisconnectedException();
			}
		}
	}
	
	private void setAllQueued() {
		if(allSentCallback != null) {
			boolean callAllSent = false;
			boolean anyFailed = false;
			synchronized(this) {
				allQueued = true;
				if(unsentPackets == 0 && !calledAllSent) {
					if(logMINOR) Logger.minor(this, "Calling all sent callback on "+this);
					callAllSent = true;
					calledAllSent = true;
					anyFailed = failedPacket;
				} else if(!calledAllSent) {
					if(logMINOR) Logger.minor(this, "Still waiting for "+unsentPackets);
				}
			}
			if(callAllSent) {
				callAllSentCallbackInner();
			}
		}
	}
	
	private void callAllSentCallbackInner() {
		prb.usm.getExecutor().execute(new PrioRunnable() {

			@Override
			public void run() {
				allSentCallback.allSent();
			}

			@Override
			public int getPriority() {
				return NativeThread.HIGH_PRIORITY;
			}
			
		});
	}
	private int inFlightPackets = 0;
	private int unsentPackets = 0;
	private boolean failedPacket = false;
	private boolean allQueued = false;
	private boolean calledAllSent = false;
	
	private class UnsentPacketTag implements AsyncMessageCallback {

		private boolean finished;
		private boolean sent;
		
		private UnsentPacketTag() {
			synchronized(BulkTransmitter.this) {
				inFlightPackets++;
				unsentPackets++;
			}
		}
		
		@Override
		public void acknowledged() {
			complete(false);
		}

		private void complete(boolean failed) {
			synchronized(this) {
				if(finished) return;
				finished = true;
				notifyAll();
			}
			if(!failed)
				ctr.sentPayload(prb.blockSize);
			synchronized(BulkTransmitter.this) {
				if(failed) {
					failedPacket = true;
					BulkTransmitter.this.notifyAll();
					if(logMINOR) Logger.minor(this, "Packet failed for "+BulkTransmitter.this);
				} else {
					inFlightPackets--;
					BulkTransmitter.this.notifyAll();
					if(logMINOR) Logger.minor(this, "Packet sent "+BulkTransmitter.this+" remaining in flight: "+inFlightPackets);
				}
			}
			sent(true);
		}

		@Override
		public void disconnected() {
			complete(true);
		}

		@Override
		public void fatalError() {
			complete(true);
		}

		@Override
		public void sent() {
			sent(false);
		}
		
		public void sent(boolean ignoreFinished) {
			if(allSentCallback == null) return;
			synchronized(this) {
				if(finished && !ignoreFinished) return;
				if(sent) return;
				sent = true;
				notifyAll();
			}
			final boolean anyFailed;
			synchronized(BulkTransmitter.this) {
				unsentPackets--;
				if(unsentPackets > 0) return;
				if(!allQueued) return;
				if(calledAllSent) return;
				calledAllSent = true;
				anyFailed = failedPacket;
			}
			if(logMINOR) Logger.minor(this, "Calling all sent callback on "+this);
			callAllSentCallbackInner();
		}
		
	}
	
	@Override
	public String toString() {
		return "BulkTransmitter:"+uid+":"+peer.shortToString();
	}
	
	public String getCancelReason() {
		return cancelReason;
	}
	
	public static synchronized long[] transferSuccess() {
		return new long[] { transfersCompleted, transfersSucceeded };
	}
}
