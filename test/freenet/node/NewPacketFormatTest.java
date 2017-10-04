/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import junit.framework.TestCase;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import freenet.crypt.BlockCipher;
import freenet.crypt.ciphers.Rijndael;
import freenet.io.comm.DMT;
import freenet.io.comm.FreenetInetAddress;
import freenet.io.comm.Message;
import freenet.io.comm.Peer;
import freenet.support.MutableBoolean;

public class NewPacketFormatTest extends TestCase {
	@Override
	public void setUp() {
		// Because we don't call maybeSendPacket, the packet sent times are not updated,
		// so lets turn off the keepalives.
		NewPacketFormat.DO_KEEPALIVES = false;
	}
	
	public void testEmptyCreation() throws BlockedTooLongException {
		NewPacketFormat npf = new NewPacketFormat(null, 0, 0);
		PeerMessageQueue pmq = new PeerMessageQueue();
		SessionKey s = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);

		NPFPacket p = npf.createPacket(1400, pmq, s, false);
		if(p != null) fail("Created packet from nothing");
	}

	public void testAckOnlyCreation() throws BlockedTooLongException, InterruptedException {
		BasePeerNode pn = new NullBasePeerNode();
		NewPacketFormat npf = new NewPacketFormat(pn, 0, 0);
		PeerMessageQueue pmq = new PeerMessageQueue();
		SessionKey s = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);

		NPFPacket p = null;

		//Packet that should be acked
		p = new NPFPacket();
		p.addMessageFragment(new MessageFragment(true, false, true, 0, 8, 8, 0, new byte[] {(byte) 0x01,
		                (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD,
		                (byte) 0xEF }, null));
		assertEquals(1, npf.handleDecryptedPacket(p, s).size());

		Thread.sleep(NewPacketFormatKeyContext.MAX_ACK_DELAY*2);
		p = npf.createPacket(1400, pmq, s, false);
		assertEquals(1, p.getAcks().size());
	}

	public void testLostLastAck() throws BlockedTooLongException, InterruptedException {
		NullBasePeerNode senderNode = new NullBasePeerNode();
		NewPacketFormat sender = new NewPacketFormat(senderNode, 0, 0);
		PeerMessageQueue senderQueue = new PeerMessageQueue();
		NullBasePeerNode receiverNode = new NullBasePeerNode();
		NewPacketFormat receiver = new NewPacketFormat(receiverNode, 0, 0);
		PeerMessageQueue receiverQueue = new PeerMessageQueue();
		SessionKey senderKey = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);
		senderNode.currentKey = senderKey;
		SessionKey receiverKey = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);

		senderQueue.queueAndEstimateSize(new MessageItem(new byte[1024], null, false, null, (short) 0, false, false), 1024);

		NPFPacket fragment1 = sender.createPacket(512, senderQueue, senderKey, false);
		assertEquals(1, fragment1.getFragments().size());
		receiver.handleDecryptedPacket(fragment1, receiverKey);

		NPFPacket fragment2 = sender.createPacket(512, senderQueue, senderKey, false);
		assertEquals(1, fragment2.getFragments().size());
		receiver.handleDecryptedPacket(fragment2, receiverKey);

		Thread.sleep(NewPacketFormatKeyContext.MAX_ACK_DELAY*2);
		NPFPacket ack1 = receiver.createPacket(512, receiverQueue, receiverKey, false);
		assertEquals(2, ack1.getAcks().size());
		assertEquals(0, (int)ack1.getAcks().first());
		assertEquals(1, (int)ack1.getAcks().last());
		sender.handleDecryptedPacket(ack1, senderKey);

		NPFPacket fragment3 = sender.createPacket(512, senderQueue, senderKey, false);
		assertEquals(1, fragment3.getFragments().size());
		receiver.handleDecryptedPacket(fragment3, receiverKey);
		Thread.sleep(NewPacketFormatKeyContext.MAX_ACK_DELAY*2);
		receiver.createPacket(512, senderQueue, receiverKey, false); //Sent, but lost

		try {
			Thread.sleep(2000); //RTT is 250ms by default since there is no PeerNode to track it
		} catch (InterruptedException e) { fail(); }

		NPFPacket resend1 = sender.createPacket(512, senderQueue, senderKey, false);
		if(resend1 == null) fail("No packet to resend");
		assertEquals(0, receiver.handleDecryptedPacket(resend1, receiverKey).size());

		//Make sure an ack is sent
		Thread.sleep(NewPacketFormatKeyContext.MAX_ACK_DELAY*2);
		NPFPacket ack2 = receiver.createPacket(512, receiverQueue, receiverKey, false);
		assertNotNull(ack2);
		assertEquals(1, ack2.getAcks().size());
		assertEquals(0, ack2.getFragments().size());
	}

	public void testOutOfOrderDelivery() throws BlockedTooLongException {
		NullBasePeerNode senderNode = new NullBasePeerNode();
		NewPacketFormat sender = new NewPacketFormat(senderNode, 0, 0);
		PeerMessageQueue senderQueue = new PeerMessageQueue();
		NullBasePeerNode receiverNode = new NullBasePeerNode();
		NewPacketFormat receiver = new NewPacketFormat(receiverNode, 0, 0);
		SessionKey senderKey = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);
		SessionKey receiverKey = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);

		senderQueue.queueAndEstimateSize(new MessageItem(new byte[1024], null, false, null, (short) 0, false, false), 1024);

		NPFPacket fragment1 = sender.createPacket(512, senderQueue, senderKey, false);
		assertEquals(1, fragment1.getFragments().size());

		NPFPacket fragment2 = sender.createPacket(512, senderQueue, senderKey, false);
		assertEquals(1, fragment2.getFragments().size());

		NPFPacket fragment3 = sender.createPacket(512, senderQueue, senderKey, false);
		assertEquals(1, fragment3.getFragments().size());

		receiver.handleDecryptedPacket(fragment1, receiverKey);
		receiver.handleDecryptedPacket(fragment3, receiverKey);
		assertEquals(1, receiver.handleDecryptedPacket(fragment2, receiverKey).size());
	}

	public void testReceiveUnknownMessageLength() throws BlockedTooLongException {
		NullBasePeerNode senderNode = new NullBasePeerNode();
		NewPacketFormat sender = new NewPacketFormat(senderNode, 0, 0);
		PeerMessageQueue senderQueue = new PeerMessageQueue();
		NullBasePeerNode receiverNode = new NullBasePeerNode();
		NewPacketFormat receiver = new NewPacketFormat(receiverNode, 0, 0);
		SessionKey senderKey = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);
		SessionKey receiverKey = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);

		senderQueue.queueAndEstimateSize(new MessageItem(new byte[1024], null, false, null, (short) 0, false, false), 1024);

		NPFPacket fragment1 = sender.createPacket(512, senderQueue, senderKey, false);
		assertEquals(1, fragment1.getFragments().size());
		NPFPacket fragment2 = sender.createPacket(512, senderQueue, senderKey, false);
		assertEquals(1, fragment2.getFragments().size());
		NPFPacket fragment3 = sender.createPacket(512, senderQueue, senderKey, false);
		assertEquals(1, fragment3.getFragments().size());

		receiver.handleDecryptedPacket(fragment3, receiverKey);
		receiver.handleDecryptedPacket(fragment2, receiverKey);
		assertEquals(1, receiver.handleDecryptedPacket(fragment1, receiverKey).size());
	}

	public void testResendAlreadyCompleted() throws BlockedTooLongException, InterruptedException {
		NullBasePeerNode senderNode = new NullBasePeerNode();
		NewPacketFormat sender = new NewPacketFormat(senderNode, 0, 0);
		PeerMessageQueue senderQueue = new PeerMessageQueue();
		NullBasePeerNode receiverNode = new NullBasePeerNode();
		NewPacketFormat receiver = new NewPacketFormat(receiverNode, 0, 0);
		SessionKey senderKey = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);
		SessionKey receiverKey = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);

		senderQueue.queueAndEstimateSize(new MessageItem(new byte[128], null, false, null, (short) 0, false, false), 1024);

		Thread.sleep(PacketSender.MAX_COALESCING_DELAY*2);
		NPFPacket packet1 = sender.createPacket(512, senderQueue, senderKey, false);
		assertEquals(1, receiver.handleDecryptedPacket(packet1, receiverKey).size());

		//Receiving the same packet twice should work
		assertEquals(0, receiver.handleDecryptedPacket(packet1, receiverKey).size());

		//Same message, new sequence number ie. resend
		assertEquals(0, receiver.handleDecryptedPacket(packet1, receiverKey).size());
	}
	
	// Test sending it when the peer wants it to be sent. This is as a real message, *not* as a lossy message.
	public void testLoadStatsSendWhenPeerWants() throws BlockedTooLongException, InterruptedException {
		final Message loadMessage = DMT.createFNPVoid();
		final MutableBoolean gotMessage = new MutableBoolean();
		final SessionKey senderKey = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);
		NullBasePeerNode senderNode = new NullBasePeerNode() {
			
			boolean shouldSend = true;
			
			@Override
			public MessageItem makeLoadStats() {
				return new MessageItem(loadMessage, null, null, (short)0);
			}

			@Override
			public synchronized boolean grabSendLoadStatsASAP(boolean realtime) {
				boolean ret = shouldSend;
				shouldSend = false;
				return ret;
			}

			@Override
			public synchronized void setSendLoadStatsASAP(boolean realtime) {
				shouldSend = true;
			}
			
			@Override
			public SessionKey getCurrentKeyTracker() {
				return senderKey;
			}

		};
		NewPacketFormat sender = new NewPacketFormat(senderNode, 0, 0);
		PeerMessageQueue senderQueue = new PeerMessageQueue();
		NullBasePeerNode receiverNode = new NullBasePeerNode() {
			
			@Override
			public void handleMessage(Message msg) {
				assert(msg.getSpec().equals(DMT.FNPVoid));
				synchronized(gotMessage) {
					gotMessage.value = true;
				}
			}
			
			@Override
			public void processDecryptedMessage(byte[] data, int offset, int length, int overhead) {
				Message m = Message.decodeMessageFromPacket(data, offset, length, this, overhead);
				if(m != null) {
					handleMessage(m);
				}
			}
			
		};
		NewPacketFormat receiver = new NewPacketFormat(receiverNode, 0, 0);
		SessionKey receiverKey = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);

		senderQueue.queueAndEstimateSize(new MessageItem(new byte[128], null, false, null, (short) 0, false, false), 1024);

		Thread.sleep(PacketSender.MAX_COALESCING_DELAY*2);
		NPFPacket packet1 = sender.createPacket(512, senderQueue, senderKey, false);
		assert(packet1.getLossyMessages().size() == 0);
		assert(packet1.getFragments().size() == 2);
		synchronized(gotMessage) {
			assert(!gotMessage.value);
		}
		List<byte[]> finished = receiver.handleDecryptedPacket(packet1, receiverKey);
		assertEquals(2, finished.size());
		DecodingMessageGroup decoder = receiverNode.startProcessingDecryptedMessages(finished.size());
		for(byte[] buffer : finished) {
			decoder.processDecryptedMessage(buffer, 0, buffer.length, 0);
		}
		decoder.complete();
		
		synchronized(gotMessage) {
			assert(gotMessage.value);
		}
	}
	
	// Test sending it as a per-packet lossy message.
	public void testLoadStatsLowLevel() throws BlockedTooLongException, InterruptedException {
		final byte[] loadMessage = 
			new byte[] { (byte)0xFF, (byte)0xEE, (byte)0xDD, (byte)0xCC, (byte)0xBB, (byte)0xAA};
		final SessionKey senderKey = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);
		NullBasePeerNode senderNode = new NullBasePeerNode() {
			
			@Override
			public MessageItem makeLoadStats() {
				return new MessageItem(loadMessage, null, false, null, (short) 0, false, false);
			}

			@Override
			public SessionKey getCurrentKeyTracker() {
				return senderKey;
			}

		};
		NewPacketFormat sender = new NewPacketFormat(senderNode, 0, 0);
		PeerMessageQueue senderQueue = new PeerMessageQueue();
		
		senderQueue.queueAndEstimateSize(new MessageItem(new byte[128], null, false, null, (short) 0, false, true), 1024);

		Thread.sleep(PacketSender.MAX_COALESCING_DELAY*2);
		NPFPacket packet1 = sender.createPacket(512, senderQueue, senderKey, false);
		assertTrue(packet1 != null);
		assertEquals(1, packet1.getFragments().size());
		assertEquals(1, packet1.getLossyMessages().size());
		NPFPacketTest.checkEquals(loadMessage, packet1.getLossyMessages().get(0));
		// Don't decode the packet because it's not a real message.
	}
	
	// Test sending load message as a per-packet lossy message, including message decoding.
	public void testLoadStatsHighLevel() throws BlockedTooLongException, InterruptedException {
		final Message loadMessage = DMT.createFNPVoid();
		final MutableBoolean gotMessage = new MutableBoolean();
		NullBasePeerNode senderNode = new NullBasePeerNode() {
			
			@Override
			public MessageItem makeLoadStats() {
				return new MessageItem(loadMessage, null, null, (short)0);
			}

			@Override
			public void handleMessage(Message msg) {
				assert(msg.getSpec().equals(DMT.FNPVoid));
				synchronized(gotMessage) {
					gotMessage.value = true;
				}
			}

		};
		NewPacketFormat sender = new NewPacketFormat(senderNode, 0, 0);
		PeerMessageQueue senderQueue = new PeerMessageQueue();
		NullBasePeerNode receiverNode = new NullBasePeerNode() {
			
			@Override
			public void handleMessage(Message msg) {
				assert(msg.getSpec().equals(DMT.FNPVoid));
				synchronized(gotMessage) {
					gotMessage.value = true;
				}
			}
			
		};
		NewPacketFormat receiver = new NewPacketFormat(receiverNode, 0, 0);
		SessionKey senderKey = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);
		SessionKey receiverKey = new SessionKey(null, null, null, null, null, null, null, null, new NewPacketFormatKeyContext(0, 0), 1);

		senderQueue.queueAndEstimateSize(new MessageItem(new byte[128], null, false, null, (short) 0, false, true), 1024);

		Thread.sleep(PacketSender.MAX_COALESCING_DELAY*2);
		NPFPacket packet1 = sender.createPacket(512, senderQueue, senderKey, false);
		assertEquals(1, packet1.getFragments().size());
		assertEquals(1, packet1.getLossyMessages().size());
		synchronized(gotMessage) {
			assert(!gotMessage.value);
		}
		assertEquals(1, receiver.handleDecryptedPacket(packet1, receiverKey).size());
		synchronized(gotMessage) {
			assert(gotMessage.value);
		}
	}
	
	/* This checks the output of the sequence number encryption function to
	 * make sure it doesn't change accidentally. */
	public void testSequenceNumberEncryption() {
		BlockCipher ivCipher = new Rijndael();
		ivCipher.initialize(new byte[] {
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
		});

		byte[] ivNonce = new byte[16];

		BlockCipher incommingCipher = new Rijndael();
		incommingCipher.initialize(new byte[] {
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00
		});

		SessionKey sessionKey = new SessionKey(null, null, null, incommingCipher, null, ivCipher, ivNonce, null, null, -1);

		byte[] encrypted = NewPacketFormat.encryptSequenceNumber(0, sessionKey);

		/* This result has not been checked, but it was the output when
		 * this test was added and we are (in this test) only
		 * interested in making sure the output doesn't change. */
		byte[] correct = new byte[] {(byte) 0xF7, (byte) 0x95, (byte) 0xBD, (byte) 0x4A};

		assertTrue(Arrays.equals(correct, encrypted));
	}

	public void testEncryption()
			throws BlockedTooLongException, UnknownHostException, InterruptedException {
		Random random = new Random(120116);
		NullBasePeerNode senderNode = new NullBasePeerNode();
		NullBasePeerNode receiverNode = new NullBasePeerNode();
		byte[] outgoingKey = new byte[32];
		random.nextBytes(outgoingKey);
		BlockCipher outgoingCipher = new Rijndael();
		outgoingCipher.initialize(outgoingKey);
		byte[] incomingKey = new byte[32];
		random.nextBytes(incomingKey);
		BlockCipher incomingCipher = new Rijndael();
		incomingCipher.initialize(incomingKey);
		BlockCipher ivCipher = new Rijndael();
		byte[] ivKey = new byte[32];
		random.nextBytes(ivKey);
		ivCipher.initialize(ivKey);
		byte[] ivNonce = new byte[16];
		random.nextBytes(ivNonce);
		byte[] hmacKey = new byte[32];
		random.nextBytes(hmacKey);
		int senderStartSeq = 1000;
		int receiverStartSeq = 2000;

		NewPacketFormatKeyContext senderContext =
				new NewPacketFormatKeyContext(senderStartSeq, receiverStartSeq);

		NewPacketFormatKeyContext receiverContext =
				new NewPacketFormatKeyContext(receiverStartSeq, senderStartSeq);

		SessionKey senderSessionKey = new SessionKey(null, outgoingCipher, outgoingKey,
							     incomingCipher, incomingKey, ivCipher,
							     ivNonce, hmacKey, senderContext, 0);

		SessionKey receiverSessionKey = new SessionKey(null, incomingCipher, incomingKey,
							       outgoingCipher, outgoingKey,
							       ivCipher, ivNonce, hmacKey,
							       receiverContext, 0);

		senderNode.currentKey = senderSessionKey;
		receiverNode.currentKey = receiverSessionKey;

		NewPacketFormat
				senderNPF =
				new NewPacketFormat(senderNode, senderStartSeq, receiverStartSeq);
		NewPacketFormat
				receiverNPF =
				new NewPacketFormat(receiverNode, receiverStartSeq, senderStartSeq);

		PeerMessageQueue senderQueue = new PeerMessageQueue();

		byte[] message = new byte[1024];
		random.nextBytes(message);
		byte[] copyOfMessage = Arrays.copyOf(message, message.length);

		senderQueue.queueAndEstimateSize(
				new MessageItem(message, null, false, null, (short) 0, false,
						false), 1024);

		senderNode.messageQueue = senderQueue;
		Thread.sleep(PacketSender.MAX_COALESCING_DELAY * 2);
		senderNPF.maybeSendPacket(false, senderSessionKey);

		FreenetInetAddress LOCALHOST = new FreenetInetAddress("127.0.0.1");
		Peer PEER = new Peer(LOCALHOST, 1234);

		byte[] data = senderNode.sentEncryptedPacket;

		receiverNode.decryptedMessages = new ArrayList<byte[]>();
		receiverNPF.handleReceivedPacket(data, 0, data.length);

		assertEquals(1, receiverNode.decryptedMessages.size());
		assertTrue(Arrays.equals(message, copyOfMessage));
		assertTrue(Arrays.equals(message, receiverNode.decryptedMessages.get(0)));
	}
}
