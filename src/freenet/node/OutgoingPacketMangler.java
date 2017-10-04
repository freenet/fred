/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import freenet.io.AddressTracker.Status;
import freenet.io.comm.FreenetInetAddress;
import freenet.io.comm.Peer;
import freenet.io.comm.PeerContext;
import freenet.io.comm.SocketHandler;

/**
 * Low-level interface for sending packets.
 * A UDP-based transport will have to implement both this and IncomingPacketFilter, usually
 * on the same class. 
 * @see freenet.io.comm.IncomingPacketFilter
 * @see freenet.node.FNPPacketMangler
 */
public interface OutgoingPacketMangler {

	/**
	 * Send a handshake, if possible, to the node.
	 * @param pn
	 */
	public void sendHandshake(PeerNode pn, boolean notRegistered);

	/**
	 * Is a peer disconnected?
	 */
	public boolean isDisconnected(PeerContext context);
	
	/**
	 * List of supported negotiation types in preference order (best last)
	 */
	public int[] supportedNegTypes();
	
	/**
	 * The SocketHandler we are connected to.
	 */
	public SocketHandler getSocketHandler();

	/**
	 * Get our addresses, as peers.
	 */
	public Peer[] getPrimaryIPAddress();

	/**
	 * Get our compressed noderef
	 */
	public byte[] getCompressedNoderef();
	
	/**
	 * Always allow local addresses?
	 */
	public boolean alwaysAllowLocalAddresses();

	/**
	 * Port forwarding status.
	 * @return A status code from AddressTracker. FIXME make this more generic when we need to.
	 */
	public Status getConnectivityStatus();

	/**
	 * Is there any reason not to allow this connection? E.g. limits on the number of nodes on
	 * a specific IP address?
	 */
	public boolean allowConnection(PeerNode node, FreenetInetAddress addr);

	/**
	 * If the lower level code detects the port forwarding is broken, it will call this method.
	 */
	public void setPortForwardingBroken();
}
