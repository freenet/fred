package freenet.node;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Random;

import freenet.io.comm.AsyncMessageCallback;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.Message;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.Peer;
import freenet.io.comm.PeerContext;
import freenet.io.comm.SocketHandler;
import freenet.io.comm.Peer.LocalAddressException;
import freenet.io.xfer.PacketThrottle;

/** Tests can override this to record specific events e.g. rekey */
public class NullBasePeerNode implements BasePeerNode {

	@Override
	public Peer getPeer() {
		return null;
	}

	@Override
	public void forceDisconnect() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isConnected() {
		return true;
	}

	@Override
	public boolean isRoutable() {
		return false;
	}

	@Override
	public int getVersionNumber() {
		throw new UnsupportedOperationException();
	}

	@Override
	public MessageItem sendAsync(Message msg, AsyncMessageCallback cb,
			ByteCounter ctr) throws NotConnectedException {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getBootID() {
		return 0;
	}

	@Override
	public PacketThrottle getThrottle() {
		return null;
	}

	@Override
	public SocketHandler getSocketHandler() {
		return null;
	}

	@Override
	public OutgoingPacketMangler getOutgoingMangler() {
		return null;
	}

	@Override
	public WeakReference<? extends PeerContext> getWeakRef() {
		return new WeakReference<NullBasePeerNode>(this);
	}

	@Override
	public String shortToString() {
		return toString();
	}

	@Override
	public void transferFailed(String reason, boolean realTime) {
		// Awww
	}

	@Override
	public boolean unqueueMessage(MessageItem item) {
		throw new UnsupportedOperationException();
	}
	
	SessionKey currentKey;
	SessionKey previousKey;
	SessionKey unverifiedKey;

	@Override
	public SessionKey getCurrentKeyTracker() {
		return currentKey;
	}

	@Override
	public SessionKey getPreviousKeyTracker() {
		return previousKey;
	}

	@Override
	public SessionKey getUnverifiedKeyTracker() {
		return unverifiedKey;
	}

	@Override
	public void receivedPacket(boolean dontLog, boolean dataPacket) {
		// Do nothing by default
	}

	@Override
	public void verified(SessionKey s) {
	    if (decryptedMessages == null)
	        throw new UnsupportedOperationException(); // Not expecting messages.
	}

	@Override
	public void startRekeying() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void maybeRekey() {
		// Do nothing
	}

	@Override
	public void reportIncomingBytes(int length) {
		// Ignore
	}

	@Override
	public void reportOutgoingBytes(int length) {
		// Ignore
	}

	protected ArrayList<byte[]> decryptedMessages;

	protected void processDecryptedMessage(byte[] data, int offset, int length,
			int overhead) {
	    if (decryptedMessages == null) {
	        throw new UnsupportedOperationException();
	    } else {
	        decryptedMessages.add(java.util.Arrays.copyOfRange(data, offset, offset+length));
	    }
	}

	@Override
	public void reportPing(long rt) {
		// Ignore
	}

	@Override
	public double averagePingTime() {
		return 250;
	}

	@Override
	public void wakeUpSender() {
		// Do nothing
	}

	@Override
	public int getMaxPacketSize() {
		return 1280;
	}

	public PeerMessageQueue messageQueue;

	@Override
	public PeerMessageQueue getMessageQueue() {
		return messageQueue;
	}

	@Override
	public boolean shouldPadDataPackets() {
		return false;
	}

	byte[] sentEncryptedPacket;

	@Override
	public void sendEncryptedPacket(byte[] data) throws LocalAddressException {
	    sentEncryptedPacket = data;
	}

	@Override
	public void sentPacket() {
		// Do nothing
	}

	@Override
	public boolean shouldThrottle() {
		return false;
	}

	@Override
	public void sentThrottledBytes(int length) {
		// Do nothing
	}

	@Override
	public void onNotificationOnlyPacketSent(int length) {
		// Do nothing
	}

	@Override
	public void resentBytes(int bytesToResend) {
		// Ignore
	}

	@Override
	public Random paddingGen() {
		return null;
	}

	@Override
	public void handleMessage(Message msg) {
		throw new UnsupportedOperationException();
	}

	@Override
	public MessageItem makeLoadStats() {
		// Don't send load stats.
		return null;
	}

	@Override
	public boolean grabSendLoadStatsASAP(boolean realtime) {
		return false;
	}

	@Override
	public void setSendLoadStatsASAP(boolean realtime) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void reportThrottledPacketSendTime(long time, boolean realTime) {
		// Ignore.
	}

	@Override
	public DecodingMessageGroup startProcessingDecryptedMessages(int count) {
		return new DecodingMessageGroup() {

			@Override
			public void processDecryptedMessage(byte[] data, int offset,
					int length, int overhead) {
				NullBasePeerNode.this.processDecryptedMessage(data, offset, length, overhead);
			}

			@Override
			public void complete() {
				// Do nothing.
			}
			
		};
	}

	@Override
	public double averagePingTimeCorrected() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void backoffOnResend() {
		// Ignore
	}

	@Override
	public void receivedAck(long currentTimeMillis) {
		// Ignore
	}

	@Override
	public int getThrottleWindowSize() {
		// Arbitrary.
		return 10;
	}
}
