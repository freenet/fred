/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import freenet.crypt.BlockCipher;
import freenet.crypt.HMAC;
import freenet.crypt.PCFBMode;
import freenet.io.comm.DMT;
import freenet.io.comm.Message;
import freenet.io.comm.Peer.LocalAddressException;
import freenet.io.xfer.PacketThrottle;
import freenet.node.NewPacketFormatKeyContext.AddedAcks;
import freenet.support.Fields;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.SparseBitmap;

import static java.util.concurrent.TimeUnit.MINUTES;

public class NewPacketFormat implements PacketFormat {

	private static final int HMAC_LENGTH = 10;
	// FIXME Use a more efficient structure - int[] or maybe just a big byte[].
	// FIXME increase this significantly to let it ride over network interruptions.
	private static final int NUM_SEQNUMS_TO_WATCH_FOR = 1024;
	// FIXME This should be globally allocated according to available memory etc. For links with
	// high bandwidth and high latency, and lots of memory, a much bigger buffer would be helpful.
	private static final int MAX_RECEIVE_BUFFER_SIZE = 256 * 1024;
	private static final int MSG_WINDOW_SIZE = 65536;
	private static final int NUM_MESSAGE_IDS = 268435456;
	static final long NUM_SEQNUMS = 2147483648l;
	private static final long MAX_MSGID_BLOCK_TIME = MINUTES.toMillis(10);
	private static final int MAX_ACKS = 500;
	static boolean DO_KEEPALIVES = true;

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

	private final BasePeerNode pn;

	/** The actual buffer of outgoing messages that have not yet been acked.
	 * LOCKING: Protected by sendBufferLock. */
	private final List<Map<Integer, MessageWrapper>> startedByPrio;
	/** The next message ID for outgoing messages.
	 * LOCKING: Protected by (this). */
	private int nextMessageID;
	/** The first message id that hasn't been acked by the receiver.
	 * LOCKING: Protected by (this). */
	private int messageWindowPtrAcked;
	/** All messages that have been acked (we remove those which are out of window to
	 * limit space usage).
	 * LOCKING: Protected by (this). */
	private final SparseBitmap ackedMessages = new SparseBitmap();

	private final HashMap<Integer, PartiallyReceivedBuffer> receiveBuffers = new HashMap<>();
	private final HashMap<Integer, SparseBitmap> receiveMaps = new HashMap<>();
	/** The first message id that hasn't been fully received */
	private int messageWindowPtrReceived;
	private final SparseBitmap receivedMessages= new SparseBitmap();

	/** How much of our receive buffer have we used? Equal to how much is used of the
	 * sender's send buffer. The receive buffer is actually implemented in receiveBuffers.
	 * LOCKING: Protected by receiveBufferSizeLock. */
	private int receiveBufferUsed = 0;
	/** How much of the other side's buffer have we used? Or alternatively, how much space
	 * have we used in our send buffer, namely startedByPrio? 
	 * LOCKING: Protected by sendBufferLock */
	private int sendBufferUsed = 0;
	/** Lock protecting buffer usage counters, and the buffer itself (startedByPrio). 
	 * MUST BE TAKEN LAST. 
	 * Justification: The outgoing buffer and the buffer usage should be protected by 
	 * the same lock, for consistency. The buffer usage and the connection status must
	 * be protected by the same lock, so we don't send packets when we are disconnected 
	 * and get race conditions in onDisconnect(). The incoming buffer estimate could be
	 * separated in theory. */
	private final Object sendBufferLock = new Object();
	/** Lock protecting the size of the receive buffer. */
	private final Object receiveBufferSizeLock = new Object();
	
	private long timeLastSentPacket;
	private long timeLastSentPayload;

	NewPacketFormat(BasePeerNode pn, int ourInitialMsgID, int theirInitialMsgID) {
		this.pn = pn;

		startedByPrio = new ArrayList<>(DMT.NUM_PRIORITIES);
		for(int i = 0; i < DMT.NUM_PRIORITIES; i++) {
			startedByPrio.add(new HashMap<Integer, MessageWrapper>());
		}

		// Make sure the numbers are within the ranges we want
		ourInitialMsgID = (ourInitialMsgID & 0x7FFFFFFF) % NUM_MESSAGE_IDS;
		theirInitialMsgID = (theirInitialMsgID & 0x7FFFFFFF) % NUM_MESSAGE_IDS;

		nextMessageID = ourInitialMsgID;
		messageWindowPtrAcked = ourInitialMsgID;
		messageWindowPtrReceived = theirInitialMsgID;
	}

	@Override
	public boolean handleReceivedPacket(byte[] buf, int offset, int length) {
		NPFPacket packet = null;
		SessionKey s = null;
		for(int i = 0; i < 3; i++) {
			if(i == 0) {
				s = pn.getCurrentKeyTracker();
			} else if (i == 1) {
				s = pn.getPreviousKeyTracker();
			} else {
				s = pn.getUnverifiedKeyTracker();
			}
			if(s == null) continue;
			packet = tryDecipherPacket(buf, offset, length, s);
			if(packet != null) {
				if(logDEBUG) Logger.debug(this, "Decrypted packet with tracker " + i);
				break;
			}
		}
		if(packet == null) {
			if(logMINOR) Logger.minor(this, "Could not decrypt received packet");
			return false;
		}

		pn.receivedPacket(false, true);
		pn.verified(s);
		pn.maybeRekey();
		pn.reportIncomingBytes(length);

		List<byte[]> finished = handleDecryptedPacket(packet, s);
		if(logMINOR && !finished.isEmpty()) 
			Logger.minor(this, "Decoded messages: "+finished.size());
		DecodingMessageGroup group = pn.startProcessingDecryptedMessages(finished.size());
		for(byte[] buffer : finished) {
			group.processDecryptedMessage(buffer, 0, buffer.length, 0);
		}
		group.complete();

		return true;
	}

	List<byte[]> handleDecryptedPacket(NPFPacket packet, SessionKey sessionKey) {
		List<byte[]> fullyReceived = new LinkedList<>();

		NewPacketFormatKeyContext keyContext = sessionKey.packetContext;
		for(int ack : packet.getAcks()) {
			keyContext.ack(ack, pn, sessionKey);
		}
		
		boolean dontAck = false;
		boolean wakeUp = false;
		if(packet.getError() || (packet.getFragments().size() == 0)) {
			if(logMINOR) Logger.minor(this, "Not acking because " + (packet.getError() ? "error" : "no fragments"));
			dontAck = true;
		}
		List<byte[]> l = packet.getLossyMessages();
		if(l != null && !l.isEmpty())
		{
		    ArrayList<Message> lossyMessages = new ArrayList<>(l.size());
			for(byte[] buf : l) {
				// FIXME factor out parsing once we are sure these are not bogus.
				// For now we have to be careful.
				Message msg = Message.decodeMessageLax(buf, pn, 0);
				if(msg == null) {
					lossyMessages.clear();
					break;
				}
				if(!msg.getSpec().isLossyPacketMessage()) {
					lossyMessages.clear();
					break;
				}
				lossyMessages.add(msg);
			}
			// Handle them *before* the rest.
			if(logMINOR && lossyMessages.size() > 0) Logger.minor(this, "Successfully parsed "+lossyMessages.size()+" lossy packet messages");
			for(Message msg : lossyMessages)
				pn.handleMessage(msg);
		}
		for(MessageFragment fragment : packet.getFragments()) {
			if(messageWindowPtrReceived + MSG_WINDOW_SIZE > NUM_MESSAGE_IDS) {
				int upperBound = (messageWindowPtrReceived + MSG_WINDOW_SIZE) % NUM_MESSAGE_IDS;
				if((fragment.messageID > upperBound) && (fragment.messageID < messageWindowPtrReceived)) {
					if(logMINOR) Logger.minor(this, "Received message "+fragment.messageID+" outside window, acking");
					continue;
				}
			} else {
				int upperBound = messageWindowPtrReceived + MSG_WINDOW_SIZE;
				if(!((fragment.messageID >= messageWindowPtrReceived) && (fragment.messageID < upperBound))) {
					if(logMINOR) Logger.minor(this, "Received message "+fragment.messageID+" outside window, acking");
					continue;
				}
			}
			synchronized(receivedMessages) {
				if(receivedMessages.contains(fragment.messageID, fragment.messageID)) continue;
			}

			PartiallyReceivedBuffer recvBuffer = receiveBuffers.get(fragment.messageID);
			SparseBitmap recvMap = receiveMaps.get(fragment.messageID);
			if(recvBuffer == null) {
				if(logMINOR) Logger.minor(this, "Message id " + fragment.messageID + ": Creating buffer");

				recvBuffer = new PartiallyReceivedBuffer(this);
				if(fragment.firstFragment) {
					if(!recvBuffer.setMessageLength(fragment.messageLength)) {
						dontAck = true;
						continue;
					}
				} else {
					synchronized(receiveBufferSizeLock) {
						if((receiveBufferUsed + fragment.fragmentLength) > MAX_RECEIVE_BUFFER_SIZE) {
							if(logMINOR) Logger.minor(this, "Could not create buffer, would excede max size");
							dontAck = true;
							continue;
						}
					}
				}

				recvMap = new SparseBitmap();
				receiveBuffers.put(fragment.messageID, recvBuffer);
				receiveMaps.put(fragment.messageID, recvMap);
			} else {
				if(fragment.firstFragment) {
					if(!recvBuffer.setMessageLength(fragment.messageLength)) {
						dontAck = true;
						continue;
					}
				}
			}

			if(!recvBuffer.add(fragment.fragmentData, fragment.fragmentOffset)) {
				dontAck = true;
				continue;
			}
			if(fragment.fragmentLength == 0) {
				Logger.warning(this, "Received fragment of length 0");
				continue;
			}
			recvMap.add(fragment.fragmentOffset, fragment.fragmentOffset + fragment.fragmentLength - 1);
			if((recvBuffer.messageLength != -1) && recvMap.contains(0, recvBuffer.messageLength - 1)) {
				receiveBuffers.remove(fragment.messageID);
				receiveMaps.remove(fragment.messageID);

				synchronized(receivedMessages) {
					if(receivedMessages.contains(fragment.messageID, fragment.messageID)) continue;
					receivedMessages.add(fragment.messageID, fragment.messageID);

					int oldWindow = messageWindowPtrReceived;
					while(receivedMessages.contains(messageWindowPtrReceived, messageWindowPtrReceived)) {
						messageWindowPtrReceived++;
						if(messageWindowPtrReceived == NUM_MESSAGE_IDS) messageWindowPtrReceived = 0;
					}

					if(messageWindowPtrReceived < oldWindow) {
						receivedMessages.remove(oldWindow, NUM_MESSAGE_IDS - 1);
						receivedMessages.remove(0, messageWindowPtrReceived);
					} else {
						receivedMessages.remove(oldWindow, messageWindowPtrReceived);
					}
				}

				synchronized(sendBufferLock) {
					receiveBufferUsed -= recvBuffer.messageLength;
					if(logDEBUG) Logger.debug(this, "Removed " + recvBuffer.messageLength + " from buffer. Total is now " + receiveBufferUsed);
				}

				fullyReceived.add(recvBuffer.buffer);
				
				if(logMINOR) Logger.minor(this, "Message id " + fragment.messageID + ": Completed");
			} else {
				if(logDEBUG) Logger.debug(this, "Message id " + fragment.messageID + ": " + recvMap);
			}
		}

		if(!dontAck) {
			int seqno = packet.getSequenceNumber();
			int acksQueued = keyContext.queueAck(seqno);
			boolean addedAck = acksQueued >= 0;
			if(acksQueued > MAX_ACKS)
				wakeUp = true;
			if(addedAck) {
				if(!wakeUp) {
					synchronized(sendBufferLock) {
						if(receiveBufferUsed > MAX_RECEIVE_BUFFER_SIZE / 2)
							wakeUp = true;
					}
				}
				if(wakeUp)
					pn.wakeUpSender();
			}
		}


		return fullyReceived;
	}

	private NPFPacket tryDecipherPacket(byte[] buf, int offset, int length, SessionKey sessionKey) {
		NewPacketFormatKeyContext keyContext = sessionKey.packetContext;
		// Create the watchlist if the key has changed
		if(keyContext.seqNumWatchList == null) {
			if(logMINOR) Logger.minor(this, "Creating watchlist starting at " + keyContext.watchListOffset);
			
			keyContext.seqNumWatchList = new byte[NUM_SEQNUMS_TO_WATCH_FOR][4];

			int seqNum = keyContext.watchListOffset;
			for(int i = 0; i < keyContext.seqNumWatchList.length; i++) {
				keyContext.seqNumWatchList[i] = NewPacketFormat.encryptSequenceNumber(seqNum++, sessionKey);
				if(seqNum < 0) seqNum = 0;
			}
		}

		// Move the watchlist if needed
		int highestReceivedSeqNum;
		synchronized(this) {
			highestReceivedSeqNum = keyContext.highestReceivedSeqNum;
		}
		// The entry for the highest received sequence number is kept in the middle of the list
		int oldHighestReceived = (int) ((0l + keyContext.watchListOffset + (keyContext.seqNumWatchList.length / 2)) % NUM_SEQNUMS);
		if(seqNumGreaterThan(highestReceivedSeqNum, oldHighestReceived, 31)) {
			int moveBy;
			if(highestReceivedSeqNum > oldHighestReceived) {
				moveBy = highestReceivedSeqNum - oldHighestReceived;
			} else {
				moveBy = ((int) (NUM_SEQNUMS - oldHighestReceived)) + highestReceivedSeqNum;
			}

			if(moveBy > keyContext.seqNumWatchList.length) {
				Logger.warning(this, "Moving watchlist pointer by " + moveBy);
			} else if(moveBy < 0) {
				Logger.warning(this, "Tried moving watchlist pointer by " + moveBy);
				moveBy = 0;
			} else {
				if(logDEBUG) Logger.debug(this, "Moving watchlist pointer by " + moveBy);
			}

			int seqNum = (int) ((0l + keyContext.watchListOffset + keyContext.seqNumWatchList.length) % NUM_SEQNUMS);
			for(int i = keyContext.watchListPointer; i < (keyContext.watchListPointer + moveBy); i++) {
				keyContext.seqNumWatchList[i % keyContext.seqNumWatchList.length] = encryptSequenceNumber(seqNum++, sessionKey);
				if(seqNum < 0) seqNum = 0;
			}

			keyContext.watchListPointer = (keyContext.watchListPointer + moveBy) % keyContext.seqNumWatchList.length;
			keyContext.watchListOffset = (int) ((0l + keyContext.watchListOffset + moveBy) % NUM_SEQNUMS);
		}

		for(int i = 0; i < keyContext.seqNumWatchList.length; i++) {
			int index = (keyContext.watchListPointer + i) % keyContext.seqNumWatchList.length;
			if (!Fields.byteArrayEqual(
						buf, keyContext.seqNumWatchList[index],
						offset + HMAC_LENGTH, 0,
						keyContext.seqNumWatchList[index].length))
				continue;
			
			int sequenceNumber = (int) ((0l + keyContext.watchListOffset + i) % NUM_SEQNUMS);
			if(logDEBUG) Logger.debug(this, "Received packet matches sequence number " + sequenceNumber);
			NPFPacket p = decipherFromSeqnum(buf, offset, length, sessionKey, sequenceNumber);
			if(p != null) {
				if(logMINOR) Logger.minor(this, "Received packet " + p.getSequenceNumber()+" on "+sessionKey);
				return p;
			}
		}

		return null;
	}

	/** Must NOT modify buf contents. */
	private NPFPacket decipherFromSeqnum(byte[] buf, int offset, int length, SessionKey sessionKey, int sequenceNumber) {
		BlockCipher ivCipher = sessionKey.ivCipher;

		byte[] IV = new byte[ivCipher.getBlockSize() / 8];
		System.arraycopy(sessionKey.ivNonce, 0, IV, 0, IV.length);
		IV[IV.length - 4] = (byte) (sequenceNumber >>> 24);
		IV[IV.length - 3] = (byte) (sequenceNumber >>> 16);
		IV[IV.length - 2] = (byte) (sequenceNumber >>> 8);
		IV[IV.length - 1] = (byte) (sequenceNumber);

		ivCipher.encipher(IV, IV);

		byte[] payload = Arrays.copyOfRange(buf, offset + HMAC_LENGTH, offset + length);
		byte[] hash = Arrays.copyOfRange(buf, offset, offset + HMAC_LENGTH);
		byte[] localHash = Arrays.copyOf(HMAC.macWithSHA256(sessionKey.hmacKey, payload), HMAC_LENGTH);
		if (!MessageDigest.isEqual(hash, localHash)) {
			if (logMINOR) {
				Logger.minor(this, "Failed to validate the HMAC using TrackerID="+sessionKey.trackerID);
			}

			return null;
		}

		PCFBMode payloadCipher = PCFBMode.create(sessionKey.incommingCipher, IV);
		payloadCipher.blockDecipher(payload, 0, payload.length);

		NPFPacket p = NPFPacket.create(payload, pn);

		NewPacketFormatKeyContext keyContext = sessionKey.packetContext;
		synchronized(this) {
			if(seqNumGreaterThan(sequenceNumber, keyContext.highestReceivedSeqNum, 31)) {
				keyContext.highestReceivedSeqNum = sequenceNumber;
			}
		}

		return p;
	}

	private boolean seqNumGreaterThan(long i1, long i2, int serialBits) {
		//halfValue is half the window of possible numbers, so this returns true if the distance from
		//i2->i1 is smaller than i1->i2. See RFC1982 for details and limitations.

		long halfValue = (long) Math.pow(2, serialBits - 1);
		return (((i1 < i2) && ((i2 - i1) > halfValue)) || ((i1 > i2) && (i1 - i2 < halfValue)));
	}

	static byte[] encryptSequenceNumber(int seqNum, SessionKey sessionKey) {
		byte[] seqNumBytes = new byte[4];
		seqNumBytes[0] = (byte) (seqNum >>> 24);
		seqNumBytes[1] = (byte) (seqNum >>> 16);
		seqNumBytes[2] = (byte) (seqNum >>> 8);
		seqNumBytes[3] = (byte) (seqNum);

		BlockCipher ivCipher = sessionKey.ivCipher;

		byte[] IV = new byte[ivCipher.getBlockSize() / 8];
		System.arraycopy(sessionKey.ivNonce, 0, IV, 0, IV.length);
		System.arraycopy(seqNumBytes, 0, IV, IV.length - seqNumBytes.length, seqNumBytes.length);
		ivCipher.encipher(IV, IV);

		PCFBMode cipher = PCFBMode.create(sessionKey.incommingCipher, IV);
		cipher.blockEncipher(seqNumBytes, 0, seqNumBytes.length);

		return seqNumBytes;
	}

	@Override
	public boolean maybeSendPacket(boolean ackOnly)
	throws BlockedTooLongException {
		SessionKey sessionKey = pn.getPreviousKeyTracker();
		if(sessionKey != null) {
			// Try to sent an ack-only packet.
			if(maybeSendPacket(true, sessionKey)) return true;
		}
		sessionKey = pn.getUnverifiedKeyTracker();
		if(sessionKey != null) {
			// Try to sent an ack-only packet.
			if(maybeSendPacket(true, sessionKey)) return true;
		}
		sessionKey = pn.getCurrentKeyTracker();
		if(sessionKey == null) {
			Logger.warning(this, "No key for encrypting hash");
			return false;
		}
		return maybeSendPacket(ackOnly, sessionKey);
	}
	
	boolean maybeSendPacket(boolean ackOnly, SessionKey sessionKey)
	throws BlockedTooLongException {
		int maxPacketSize = pn.getMaxPacketSize();
		NewPacketFormatKeyContext keyContext = sessionKey.packetContext;

		NPFPacket packet = createPacket(maxPacketSize - HMAC_LENGTH, pn.getMessageQueue(), sessionKey, ackOnly);
		if(packet == null) return false;

		int paddedLen = packet.getLength() + HMAC_LENGTH;
		if(pn.shouldPadDataPackets()) {
			int packetLength = paddedLen;
			if(logDEBUG) Logger.debug(this, "Pre-padding length: " + packetLength);

			if(packetLength < 64) {
				paddedLen = 64 + pn.paddingGen().nextInt(32);
			} else {
				paddedLen = ((packetLength + 63) / 64) * 64;
				if(paddedLen < maxPacketSize) {
					paddedLen += pn.paddingGen().nextInt(Math.min(64, maxPacketSize - paddedLen));
				} else if((packetLength <= maxPacketSize) && (paddedLen > maxPacketSize)) {
					paddedLen = maxPacketSize;
				}
			}
		}

		byte[] data = new byte[paddedLen];
		packet.toBytes(data, HMAC_LENGTH, pn.paddingGen());

		BlockCipher ivCipher = sessionKey.ivCipher;

		byte[] IV = new byte[ivCipher.getBlockSize() / 8];
		System.arraycopy(sessionKey.ivNonce, 0, IV, 0, IV.length);
		System.arraycopy(data, HMAC_LENGTH, IV, IV.length - 4, 4);

		ivCipher.encipher(IV, IV);

		PCFBMode payloadCipher = PCFBMode.create(sessionKey.outgoingCipher, IV);
		payloadCipher.blockEncipher(data, HMAC_LENGTH, paddedLen - HMAC_LENGTH);

		//Add hash
		byte[] text = new byte[paddedLen - HMAC_LENGTH];
		System.arraycopy(data, HMAC_LENGTH, text, 0, text.length);

		byte[] hash = HMAC.macWithSHA256(sessionKey.hmacKey, text);

		System.arraycopy(hash, 0, data, 0, HMAC_LENGTH);

		try {
			if(logMINOR) {
				String fragments = null;
				for(MessageFragment frag : packet.getFragments()) {
					if(fragments == null) fragments = String.valueOf(frag.messageID);
					else fragments = fragments + ", " + frag.messageID;
					fragments += " ("+frag.fragmentOffset+"->"+(frag.fragmentOffset+frag.fragmentLength-1)+")";
				}

				Logger.minor(this, "Sending packet " + packet.getSequenceNumber() + " ("
				                + data.length + " bytes) with fragments " + fragments + " and "
				                + packet.getAcks().size() + " acks on "+this);
			}
			pn.sendEncryptedPacket(data);
		} catch (LocalAddressException e) {
			Logger.error(this, "Caught exception while sending packet", e);
			return false;
		}
		
		packet.onSent(data.length, pn);

		if(packet.getFragments().size() > 0) {
			keyContext.sent(packet.getSequenceNumber());
		}

		long now = System.currentTimeMillis();
		pn.sentPacket();
		pn.reportOutgoingBytes(data.length);
		if(pn.shouldThrottle()) {
			pn.sentThrottledBytes(data.length);
		}
		if(packet.getFragments().size() == 0) {
			pn.onNotificationOnlyPacketSent(data.length);
		}
		
		synchronized(this) {
			if(timeLastSentPacket < now) timeLastSentPacket = now;
			if(packet.getFragments().size() > 0) {
				if(timeLastSentPayload < now) timeLastSentPayload = now;
			}
		}

		return true;
	}

	NPFPacket createPacket(int maxPacketSize, PeerMessageQueue messageQueue, SessionKey sessionKey, boolean ackOnly) throws BlockedTooLongException {
		
		checkForLostPackets();
		
		NPFPacket packet = new NPFPacket();
		SentPacket sentPacket = new SentPacket(this);
		
		boolean mustSend = false;
		long now = System.currentTimeMillis();
		
		NewPacketFormatKeyContext keyContext = sessionKey.packetContext;
		
		AddedAcks moved = keyContext.addAcks(packet, maxPacketSize, now);
		if(moved != null && moved.anyUrgentAcks) {
			if(logDEBUG) Logger.debug(this, "Must send because urgent acks");
			mustSend = true;
		}
		
		int numAcks = packet.countAcks();
		
		if(numAcks > MAX_ACKS) {
			mustSend = true;
		}
		
		if(numAcks > 0) {
			if(logDEBUG) Logger.debug(this, "Added acks for "+this+" for "+pn.shortToString());
		}
		
		byte[] haveAddedStatsBulk = null;
		byte[] haveAddedStatsRT = null;
		
		if(!ackOnly) {
			
			boolean addedFragments = false;
			
			while(true) {
				
				boolean addStatsBulk = false;
				boolean addStatsRT = false;
				
				synchronized(sendBufferLock) {
					// Always finish what we have started before considering sending more packets.
					// Anything beyond this is beyond the scope of NPF and is PeerMessageQueue's job.
addOldLoop:			for(Map<Integer, MessageWrapper> started : startedByPrio) {
						//Try to finish messages that have been started
						Iterator<MessageWrapper> it = started.values().iterator();
						while(it.hasNext() && packet.getLength() < maxPacketSize) {
							MessageWrapper wrapper = it.next();
							while(packet.getLength() < maxPacketSize) {
								MessageFragment frag = wrapper.getMessageFragment(maxPacketSize - packet.getLength());
								if(frag == null) break;
								mustSend = true;
								addedFragments = true;
								packet.addMessageFragment(frag);
								sentPacket.addFragment(frag);
								if(wrapper.allSent()) {
									if((haveAddedStatsBulk == null) && wrapper.getItem().sendLoadBulk) {
										addStatsBulk = true;
										// Add the lossy message outside the lock.
										break addOldLoop;
									}
									if((haveAddedStatsRT == null) && wrapper.getItem().sendLoadRT) {
										addStatsRT = true;
										// Add the lossy message outside the lock.
										break addOldLoop;
									}
								}
							}
						}
					}
				}
				
				if(!(addStatsBulk || addStatsRT)) break;
				
				if(addStatsBulk) {
					MessageItem item = pn.makeLoadStats();
					if(item != null) {
						byte[] buf = item.getData();
						haveAddedStatsBulk = buf;
						// FIXME if this fails, drop some messages.
						packet.addLossyMessage(buf, maxPacketSize);
					}
				}
				
				if(addStatsRT) {
					MessageItem item = pn.makeLoadStats();
					if(item != null) {
						byte[] buf = item.getData();
						haveAddedStatsRT = buf;
						// FIXME if this fails, drop some messages.
						packet.addLossyMessage(buf, maxPacketSize);
					}
				}
			}
			
			if(addedFragments) {
				if(logDEBUG) Logger.debug(this, "Added fragments for "+this+" (must send)");
			}
			
		}
		
		if((!mustSend) && packet.getLength() >= (maxPacketSize * 4 / 5)) {
			if(logDEBUG) Logger.debug(this, "Must send because packet is big on acks alone");
			// Lots of acks to send, send a packet.
			mustSend = true;
		}
		
		if((!ackOnly) && (!mustSend)) {
			if(messageQueue.mustSendNow(now) || messageQueue.mustSendSize(packet.getLength(), maxPacketSize)) {
				if(logDEBUG) Logger.debug(this, "Must send because of message queue");
				mustSend = true;
			}
		}
		
		if((!mustSend) && numAcks > 0) {
			int maxSendBufferSize = maxSendBufferSize();
			synchronized(sendBufferLock) {
				if(sendBufferUsed > maxSendBufferSize / 2) {
					if(logDEBUG) Logger.debug(this, "Must send because other side buffer size is "+sendBufferUsed);
					mustSend = true;
				}
			}

		}
		
		boolean checkedCanSend = false;
		boolean cantSend = false;
		
		boolean mustSendKeepalive = false;
		
		if(DO_KEEPALIVES) {
			synchronized(this) {
				if(!mustSend) {
					if(now - timeLastSentPacket > Node.KEEPALIVE_INTERVAL)
						mustSend = true;
				}
				if((!ackOnly) && now - timeLastSentPayload > Node.KEEPALIVE_INTERVAL && 
						packet.getFragments().isEmpty())
					mustSendKeepalive = true;
			}
		}
		
		if(mustSendKeepalive) {
			if(!checkedCanSend)
				cantSend = !canSend(sessionKey);
			checkedCanSend = true;
			if(!cantSend) {
				mustSend = true;
			}
		}
		
		if(!mustSend) {
			if(moved != null) {
				moved.abort();
			}
			return null;
		}
		
		boolean sendStatsBulk = false, sendStatsRT = false;
		
		if(!ackOnly) {
			
			sendStatsBulk = pn.grabSendLoadStatsASAP(false);
			sendStatsRT = pn.grabSendLoadStatsASAP(true);
			
			if(sendStatsBulk || sendStatsRT) {
				if(!checkedCanSend)
					cantSend = !canSend(sessionKey);
				checkedCanSend = true;
				if(cantSend) {
					if(sendStatsBulk)
						pn.setSendLoadStatsASAP(false);
					if(sendStatsRT)
						pn.setSendLoadStatsASAP(true);
				} else {
					mustSend = true;
				}
			}
		}
		
		if(ackOnly && numAcks == 0) return null;
		
		if((!ackOnly) && (!cantSend)) {
			
			if(sendStatsBulk) {
				MessageItem item = pn.makeLoadStats();
				if(item != null) {
					if(haveAddedStatsBulk != null) {
						packet.removeLossyMessage(haveAddedStatsBulk);
					}
					messageQueue.pushfrontPrioritizedMessageItem(item);
					haveAddedStatsBulk = item.buf;
				}
			}
			
			if(sendStatsRT) {
				MessageItem item = pn.makeLoadStats();
				if(item != null) {
					if(haveAddedStatsRT != null) {
						packet.removeLossyMessage(haveAddedStatsRT);
					}
					messageQueue.pushfrontPrioritizedMessageItem(item);
					haveAddedStatsRT = item.buf;
				}
			}
			
			fragments:
				for(int i = 0; i < startedByPrio.size(); i++) {

					prio:
					while(true) {
						
						boolean addStatsBulk = false;
						boolean addStatsRT = false;
						
						//Add messages from the message queue
						while ((packet.getLength() + 10) < maxPacketSize) { //Fragment header is max 9 bytes, allow min 1 byte data
							
							if(!checkedCanSend) {
								// Check in advance to avoid reordering message items.
								cantSend = !canSend(sessionKey);
							}
							checkedCanSend = false;
							if(cantSend) break;
							boolean wasGeneratedPing = false;
							
							MessageItem item = messageQueue.grabQueuedMessageItem(i);
							if(item == null) {
								if(mustSendKeepalive && packet.noFragments()) {
									// Create a ping for keepalive purposes.
									// It will be acked, this ensures both sides don't timeout.
									Message msg;
									synchronized(this) {
										msg = DMT.createFNPPing(pingCounter++);
									}
									item = new MessageItem(msg, null, null);
									item.setDeadline(now + PacketSender.MAX_COALESCING_DELAY);
									wasGeneratedPing = true;
									// Should we report this on the PeerNode's stats? We'd need to run a job off-thread, so probably not worth it.
								} else {
									break prio;
								}
							}
							
							int messageID = getMessageID();
							if(messageID == -1) {
								// CONCURRENCY: This will fail sometimes if we send messages to the same peer from different threads.
								// This doesn't happen at the moment because we use a single PacketSender for all ports and all peers.
								// We might in future split it across multiple threads but it'd be best to keep the same peer on the same thread.
								Logger.error(this, "No availiable message ID, requeuing and sending packet (we already checked didn't we???)");
								if(!wasGeneratedPing) {
									messageQueue.pushfrontPrioritizedMessageItem(item);
									// No point adding to queue if it's just a ping:
									//  We will try again next time.
									//  But odds are the connection is broken and the other side isn't responding...
								}
								break fragments;
							}
							
							if(logDEBUG) Logger.debug(this, "Allocated "+messageID+" for "+item+" for "+this);
							
							MessageWrapper wrapper = new MessageWrapper(item, messageID);
							MessageFragment frag = wrapper.getMessageFragment(maxPacketSize - packet.getLength());
							if(frag == null) {
								messageQueue.pushfrontPrioritizedMessageItem(item);
								break prio;
							}
							packet.addMessageFragment(frag);
							sentPacket.addFragment(frag);
							
							//Priority of the one we grabbed might be higher than i
							Map<Integer, MessageWrapper> queue = startedByPrio.get(item.getPriority());
							synchronized(sendBufferLock) {
								// CONCURRENCY: This could go over the limit if we allow createPacket() for the same node on two threads in parallel. That's probably a bad idea anyway.
								sendBufferUsed += item.buf.length;
								if(logDEBUG) Logger.debug(this, "Added " + item.buf.length + " to remote buffer. Total is now " + sendBufferUsed + " for "+pn.shortToString());
								queue.put(messageID, wrapper);
							}
							
							if(wrapper.allSent()) {
								if((haveAddedStatsBulk == null) && wrapper.getItem().sendLoadBulk) {
									addStatsBulk = true;
									break;
								}
								if((haveAddedStatsRT == null) && wrapper.getItem().sendLoadRT) {
									addStatsRT = true;
									break;
								}
							}

						}
						
						if(!(addStatsBulk || addStatsRT)) break;
						
						if(addStatsBulk) {
							MessageItem item = pn.makeLoadStats();
							if(item != null) {
								byte[] buf = item.getData();
								haveAddedStatsBulk = item.buf;
								// FIXME if this fails, drop some messages.
								packet.addLossyMessage(buf, maxPacketSize);
							}
						}
						
						if(addStatsRT) {
							MessageItem item = pn.makeLoadStats();
							if(item != null) {
								byte[] buf = item.getData();
								haveAddedStatsRT = item.buf;
								// FIXME if this fails, drop some messages.
								packet.addLossyMessage(buf, maxPacketSize);
							}
						}
						
						if(cantSend) break;
					}						
				}
		
		}

		if(packet.getLength() == 5) return null;

		int seqNum = keyContext.allocateSequenceNumber(pn);
		if(seqNum == -1) return null;
		packet.setSequenceNumber(seqNum);
		
		if(logDEBUG && ackOnly) {
			Logger.debug(this, "Sending ack-only packet length "+packet.getLength()+" for "+this);
		} else if(logDEBUG && !ackOnly) {
			Logger.debug(this, "Sending packet length "+packet.getLength()+" for "+this);
		}

		if(packet.getFragments().size() > 0) {
			keyContext.sent(sentPacket, seqNum);
		}

		return packet;
	}
	
	private int pingCounter;

	/**
	 * Maximum message size in bytes.
	 */
	public static final int MAX_MESSAGE_SIZE = 4096;
	
	private int maxSendBufferSize() {
		return MAX_RECEIVE_BUFFER_SIZE;
	}

	@Override
	public long timeCheckForLostPackets() {
		long timeCheck = Long.MAX_VALUE;
		double averageRTT = averageRTT();
		SessionKey key = pn.getCurrentKeyTracker();
		if(key != null)
			timeCheck = Math.min(timeCheck, ((key.packetContext)).timeCheckForLostPackets(averageRTT));
		key = pn.getPreviousKeyTracker();
		if(key != null)
			timeCheck = Math.min(timeCheck, ((key.packetContext)).timeCheckForLostPackets(averageRTT));
		key = pn.getUnverifiedKeyTracker();
		if(key != null)
			timeCheck = Math.min(timeCheck, ((key.packetContext)).timeCheckForLostPackets(averageRTT));
		return timeCheck;
	}
	
	private long timeCheckForAcks() {
		long timeCheck = Long.MAX_VALUE;
		SessionKey key = pn.getCurrentKeyTracker();
		if(key != null)
			timeCheck = Math.min(timeCheck, (key.packetContext).timeCheckForAcks());
		key = pn.getPreviousKeyTracker();
		if(key != null)
			timeCheck = Math.min(timeCheck, (key.packetContext).timeCheckForAcks());
		key = pn.getUnverifiedKeyTracker();
		if(key != null)
			timeCheck = Math.min(timeCheck, (key.packetContext).timeCheckForAcks());
		return timeCheck;
	}

	@Override
	public void checkForLostPackets() {
		if(pn == null) return;
		double averageRTT = averageRTT();
		long curTime = System.currentTimeMillis();
		SessionKey key = pn.getCurrentKeyTracker();
		if(key != null)
			((key.packetContext)).checkForLostPackets(averageRTT, curTime, pn);
		key = pn.getPreviousKeyTracker();
		if(key != null)
			((key.packetContext)).checkForLostPackets(averageRTT, curTime, pn);
		key = pn.getUnverifiedKeyTracker();
		if(key != null)
			((key.packetContext)).checkForLostPackets(averageRTT, curTime, pn);
	}

	@Override
	public List<MessageItem> onDisconnect() {
		int messageSize = 0;
		final List<MessageItem> items = new ArrayList<>();
		// LOCKING: No packet may be sent while connected = false.
		// So we guarantee that no more packets are sent by setting this here.
		synchronized(sendBufferLock) {
			for(Map<Integer, MessageWrapper> queue : startedByPrio) {
				for(MessageWrapper wrapper : queue.values()) {
					items.add(wrapper.getItem());
					messageSize += wrapper.getLength();
				}
				queue.clear();
			}
			sendBufferUsed -= messageSize;
			// This is just a check for logging/debugging purposes.
			if(sendBufferUsed != 0) {
				Logger.warning(this, "Possible leak in transport code: Buffer size not empty after disconnecting on "+this+" for "+pn+" after removing "+messageSize+" total was "+sendBufferUsed);
				sendBufferUsed = 0;
			}
		}
		return items;
	}
	
	/** When do we need to send a packet?
	 * @return 0 if there is anything already in flight. The time that the oldest ack was
	 * queued at plus the lesser of half the RTT or 100ms if there are acks queued. 
	 * Otherwise Long.MAX_VALUE to indicate that we need to get messages from the queue. */
	@Override
	public long timeNextUrgent(boolean canSend, long now) {
		long ret = Long.MAX_VALUE;
		if(canSend) {
			// Is there anything in flight?
			// Packets in flight limit applies even if there is stuff to resend.
			synchronized(sendBufferLock) {
				for(Map<Integer, MessageWrapper> started : startedByPrio) {
					for(MessageWrapper wrapper : started.values()) {
						if(wrapper.allSent()) continue;
						// We do not reset the deadline when we resend.
						// The RTO computation logic should ensure that we don't use horrible amounts of bandwidth for retransmission.
						long d = wrapper.getItem().getDeadline();
						if(d > 0)
							ret = Math.min(ret, d);
						else
							Logger.error(this, "Started sending message "+wrapper.getItem()+" but deadline is "+d);
					}
				}
			}
		}
		// Check for acks.
		ret = Math.min(ret, timeCheckForAcks());
		
		if(ret > now) {
		    // Always wake up after half an RTT, check whether stuff is lost or needs ack'ing.
		    ret = Math.min(ret, now + Math.min(100, (long)averageRTT()/2));
		    
		    if(canSend && DO_KEEPALIVES) {
		        synchronized(this) {
		            ret = Math.min(ret, timeLastSentPayload + Node.KEEPALIVE_INTERVAL);
		        }
		    }
		}

		return ret;
	}
	
	@Override
	public long timeSendAcks() {
		return timeCheckForAcks();
	}
	
	@Override
	public boolean canSend(SessionKey tracker) {
		
		boolean canAllocateID;
		
		synchronized(this) {
			// Check whether we can allocate a message number.
			canAllocateID = 
				!seqNumGreaterThan(nextMessageID, (messageWindowPtrAcked + MSG_WINDOW_SIZE) % NUM_MESSAGE_IDS, 28);
		}
		
		if(canAllocateID) {
			// Check whether we need to rekey.
			if(tracker == null) return false;
			NewPacketFormatKeyContext keyContext = tracker.packetContext;
			if(!keyContext.canAllocateSeqNum()) {
				// We can't allocate more sequence numbers because we haven't rekeyed yet
				pn.startRekeying();
				Logger.error(this, "Can't send because we would block on "+this);
				return false;
			}
		}
		
		if(canAllocateID) {
			int bufferUsage;
			synchronized(sendBufferLock) {
				bufferUsage = sendBufferUsed;
			}
			int maxSendBufferSize = maxSendBufferSize();
			if((bufferUsage + MAX_MESSAGE_SIZE) > maxSendBufferSize) {
				if(logDEBUG) Logger.debug(this, "Cannot send: Would exceed remote buffer size. Remote at " + bufferUsage+" max is "+maxSendBufferSize+" on "+this);
				return false;
			}

		}
		
		if(tracker != null && pn != null) {
			PacketThrottle throttle = pn.getThrottle();
			if(throttle == null) {
				// Ignore
			} else {
				int maxPackets = (int)Math.min(Integer.MAX_VALUE, pn.getThrottle().getWindowSize());
				// Impose a minimum so that we don't lose the ability to send anything.
				if(maxPackets < 1) maxPackets = 1;
				NewPacketFormatKeyContext packets = tracker.packetContext;
				if(maxPackets <= packets.countSentPackets()) {
					// FIXME some packets will be visible from the outside yet only contain acks.
					// SECURITY/INVISIBILITY: They won't count here, this is bad.
					// However, counting packets in flight, rather than bytes of messages, is the right solution:
					// 1. It's closer to what TCP does.
					// 2. It avoids needing to have an excessively high minimum window size.
					// 3. It allows us to start work on any message even if it's big, while still having reasonably accurate congestion control.
					// This prevents us from getting into a situation where we never use up the full window but can never send big messages either.
					// 4. It's closer to what we used to do (only limit big packets), which seemed to work mostly.
					// 5. It avoids some complicated headaches with PeerMessageQueue. E.g. we need to avoid requeueing.
					// 6. In spite of the issue with acks, it's probably more "invisible" on the whole, in that the number of packets is visible,
					// whereas messages are supposed to not be visible.
					// Arguably we should count bytes rather than packets.
					if(logDEBUG) Logger.debug(this, "Cannot send because "+packets.countSentPackets()+" in flight of limit "+maxPackets+" on "+this);
					return false;
				}
			}
		}
		
		if(!canAllocateID) {
			synchronized(sendBufferLock) {
				for(Map<Integer, MessageWrapper> started : startedByPrio) {
					for(MessageWrapper wrapper : started.values()) {
						if(!wrapper.allSent()) return true;
					}
				}
			}
		}
		
		if(logDEBUG && !canAllocateID) Logger.debug(this, "Cannot send because cannot allocate ID on "+this);
		return canAllocateID;
	}

	private long blockedSince = -1;
	private int getMessageID() throws BlockedTooLongException {
		int messageID;
		synchronized(this) {
			if(seqNumGreaterThan(nextMessageID, (messageWindowPtrAcked + MSG_WINDOW_SIZE) % NUM_MESSAGE_IDS, 28)) {
				if(blockedSince == -1) {
					blockedSince = System.currentTimeMillis();
				} else if(System.currentTimeMillis() - blockedSince > MAX_MSGID_BLOCK_TIME) {
					throw new BlockedTooLongException(System.currentTimeMillis() - blockedSince);
				}
				return -1;
			}
			blockedSince = -1;
			messageID = nextMessageID++;
			if(nextMessageID == NUM_MESSAGE_IDS) nextMessageID = 0;
		}
		return messageID;
	}

	private double averageRTT() {
		if(pn != null) {
			return pn.averagePingTimeCorrected();
		}
		return PeerNode.MIN_RTO;
	}

	static class SentPacket {
		final NewPacketFormat npf;
		final List<MessageWrapper> messages = new ArrayList<>();
		final List<int[]> ranges = new ArrayList<>();
		long sentTime;

		SentPacket(NewPacketFormat npf) {
			this.npf = npf;
		}

		void addFragment(MessageFragment frag) {
			messages.add(frag.wrapper);
			ranges.add(new int[] { frag.fragmentOffset, frag.fragmentOffset + frag.fragmentLength - 1 });
		}

		public long acked(SessionKey key) {
			Iterator<MessageWrapper> msgIt = messages.iterator();
			Iterator<int[]> rangeIt = ranges.iterator();

			while(msgIt.hasNext()) {
				MessageWrapper wrapper = msgIt.next();
				int[] range = rangeIt.next();
				
				if(logDEBUG)
					Logger.debug(this, "Acknowledging "+range[0]+" to "+range[1]+" on "+wrapper.getMessageID());

				if(wrapper.ack(range[0], range[1], npf.pn)) {
					Map<Integer, MessageWrapper> started = npf.startedByPrio.get(wrapper.getPriority());
					MessageWrapper removed = null;
					synchronized(npf.sendBufferLock) {
						removed = started.remove(wrapper.getMessageID());
						if(removed != null) {
							int size = wrapper.getLength();
							npf.sendBufferUsed -= size;
							if(logDEBUG) Logger.debug(this, "Removed " + size + " from remote buffer. Total is now " + npf.sendBufferUsed);
						}
					}
					if(removed == null && logMINOR) {
						// ack() can return true more than once, it just only calls the callbacks once.
						Logger.minor(this, "Completed message "+wrapper.getMessageID()+" but it is not in the map from "+wrapper);
					}

					if(removed != null) {
						if(logDEBUG) Logger.debug(this, "Completed message "+wrapper.getMessageID()+" from "+wrapper);

						boolean couldSend = npf.canSend(key);
						int id = wrapper.getMessageID();
						synchronized(npf) {
							npf.ackedMessages.add(id, id);

							int oldWindow = npf.messageWindowPtrAcked;
							while(npf.ackedMessages.contains(npf.messageWindowPtrAcked, npf.messageWindowPtrAcked)) {
								npf.messageWindowPtrAcked++;
								if(npf.messageWindowPtrAcked == NUM_MESSAGE_IDS) npf.messageWindowPtrAcked = 0;
							}

							if(npf.messageWindowPtrAcked < oldWindow) {
								npf.ackedMessages.remove(oldWindow, NUM_MESSAGE_IDS - 1);
								npf.ackedMessages.remove(0, npf.messageWindowPtrAcked);
							} else {
								npf.ackedMessages.remove(oldWindow, npf.messageWindowPtrAcked);
							}
						}
						if(!couldSend && npf.canSend(key)) {
							//We aren't blocked anymore, notify packet sender
							npf.pn.wakeUpSender();
						}
					}
				}
			}

			return System.currentTimeMillis() - sentTime;
		}

		public void lost() {
			Iterator<MessageWrapper> msgIt = messages.iterator();
			Iterator<int[]> rangeIt = ranges.iterator();

			while(msgIt.hasNext()) {
				MessageWrapper wrapper = msgIt.next();
				int[] range = rangeIt.next();

				wrapper.lost(range[0], range[1]);
			}
		}

		public void sent() {
			sentTime = System.currentTimeMillis();
		}

		long getSentTime() {
			return sentTime;
		}
	}

	private static class PartiallyReceivedBuffer {
		private int messageLength;
		private byte[] buffer;
		private final NewPacketFormat npf;

		private PartiallyReceivedBuffer(NewPacketFormat npf) {
			messageLength = -1;
			buffer = new byte[0];
			this.npf = npf;
		}

		private boolean add(byte[] data, int dataOffset) {
			if(buffer.length < (dataOffset + data.length)) {
				if(!resize(dataOffset + data.length)) return false;
			}

			System.arraycopy(data, 0, buffer, dataOffset, data.length);
			return true;
		}

		private boolean setMessageLength(int messageLength) {
			if(this.messageLength != -1 && this.messageLength != messageLength) {
				Logger.warning(this, "Message length has already been set to a different length");
			}

			this.messageLength = messageLength;

			if(buffer.length > messageLength) {
				Logger.warning(this, "Buffer is larger than set message length! (" + buffer.length + ">" + messageLength + ")");
			}

			return resize(messageLength);
		}

		private boolean resize(int length) {
			if(logDEBUG) Logger.debug(this, "Resizing from " + buffer.length + " to " + length);

			synchronized(npf.receiveBufferSizeLock) {
				if((npf.receiveBufferUsed + (length - buffer.length)) > MAX_RECEIVE_BUFFER_SIZE) {
					if(logMINOR) Logger.minor(this, "Could not resize buffer, would excede max size");
					return false;
				}

				npf.receiveBufferUsed += (length - buffer.length);
				if(logDEBUG) Logger.debug(this, "Added " + (length - buffer.length) + " to buffer. Total is now " + npf.receiveBufferUsed);
			}

			buffer = Arrays.copyOf(buffer, length);

			return true;
		}
	}
	
	@Override
	public String toString() {
		if(pn != null) return super.toString() +" for "+pn.shortToString();
		else return super.toString();
	}

	@Override
	public boolean fullPacketQueued(int maxPacketSize) {
		return pn.getMessageQueue().mustSendSize(HMAC_LENGTH /* FIXME estimate headers */, maxPacketSize);
	}
}
