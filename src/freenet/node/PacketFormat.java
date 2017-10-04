package freenet.node;

import java.util.List;

public interface PacketFormat {

	boolean handleReceivedPacket(byte[] buf, int offset, int length);

	/**
	 * Maybe send something. A SINGLE PACKET. Don't send everything at once, for two reasons:
	 * <ol>
	 * <li>It is possible for a node to have a very long backlog.</li>
	 * <li>Sometimes sending a packet can take a long time.</li>
	 * <li>In the near future PacketSender will be responsible for output bandwidth throttling. So it makes sense to
	 * send a single packet and round-robin.</li>
	 * </ol>
	 * @param ackOnly 
	 */
	boolean maybeSendPacket(boolean ackOnly) throws BlockedTooLongException;

	/**
	 * Called when the peer has been disconnected.
	 * THE CALLER SHOULD STOP USING THE PACKET FORMAT OBJECT AFTER CALLING THIS FUNCTION!
	 */
	List<MessageItem> onDisconnect();

	/**
	 * Returns {@code false} if the packet format can't send new messages because it must wait for some internal event.
	 * For example, if a packet sequence number can not be allocated this method should return {@code false}, but if
	 * nothing can be sent because there is no (external) data to send it should not.
	 * Note that this only applies to packets being created from messages on the @see PeerMessageQueue.
	 * Note also that there may already be messages in flight, but it may return false in that
	 * case, so you need to check timeNextUrgent() as well.
	 * @return {@code false} if the packet format can't send packets
	 */
	boolean canSend(SessionKey key);

	/**
	 * @return The time at which the packet format will want to send an ack, finish sending a message,
	 * retransmit a packet, or similar. Long.MAX_VALUE if not supported or if there is nothing to ack 
	 * and nothing in flight. 
	 * @param canSend If false, canSend() has returned false. Some transports will
	 * want to send a packet anyway e.g. an ack, a resend in some cases. */
	long timeNextUrgent(boolean canSend, long now);
	
	/**
	 * @return The time at which the packet format will want to send an ack. Resends
	 * etc don't count, only acks. The reason acks are special is they are needed
	 * for the other side to recognise that their packets have been received and
	 * thus avoid retransmission.
	 */
	long timeSendAcks();
	
	/** Is there enough data queued to justify sending a packet immediately? Ideally
	 * this should take into account transport level headers. */
	boolean fullPacketQueued(int maxPacketSize);

	void checkForLostPackets();

	long timeCheckForLostPackets();

}
