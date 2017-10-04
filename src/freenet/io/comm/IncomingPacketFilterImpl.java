/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.io.comm;

import java.util.concurrent.atomic.AtomicLong;

import freenet.crypt.EntropySource;
import freenet.node.FNPPacketMangler;
import freenet.node.Node;
import freenet.node.NodeCrypto;
import freenet.node.PeerNode;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;

public class IncomingPacketFilterImpl implements IncomingPacketFilter {

	private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, IncomingPacketFilterImpl.class);
			}
		});
	}

	private FNPPacketMangler mangler;
	private NodeCrypto crypto;
	private Node node;
	private final EntropySource fnpTimingSource;

	public IncomingPacketFilterImpl(FNPPacketMangler mangler, Node node, NodeCrypto crypto) {
		this.mangler = mangler;
		this.node = node;
		this.crypto = crypto;
		fnpTimingSource = new EntropySource();
	}

	@Override
	public boolean isDisconnected(PeerContext context) {
		if(context == null) return false;
		return !context.isConnected();
	}
	
	private static final AtomicLong successfullyDecodedPackets = new AtomicLong();
	private static final AtomicLong failedDecodePackets = new AtomicLong();
	
	public static long[] getDecodedPackets() {
		if(!logMINOR) return null;
		long decoded = successfullyDecodedPackets.get();
		long failed = failedDecodePackets.get();
		return new long[] { decoded, decoded+failed };
	}

	@Override
	public DECODED process(byte[] buf, int offset, int length, Peer peer, long now) {
		if(logMINOR) Logger.minor(this, "Packet length "+length+" from "+peer);
		node.random.acceptTimerEntropy(fnpTimingSource, 0.25);
		PeerNode opn = node.peers.getByPeer(peer, mangler);

		if(opn != null) {
			if(opn.handleReceivedPacket(buf, offset, length)) {
				if(logMINOR) successfullyDecodedPackets.incrementAndGet();
				return DECODED.DECODED;
			}
		} else {
			Logger.normal(this, "Got packet from unknown address");
		}
		DECODED decoded = mangler.process(buf, offset, length, peer, opn);
		if(decoded == DECODED.DECODED) {
			if(logMINOR) successfullyDecodedPackets.incrementAndGet();
		} else if(decoded == DECODED.NOT_DECODED) {
			
			for(PeerNode pn : crypto.getPeerNodes()) {
				if(pn == opn) continue;
				if(pn.handleReceivedPacket(buf, offset, length)) {
					if(logMINOR) successfullyDecodedPackets.incrementAndGet();
					return DECODED.DECODED;
				}
			}
			
			if(logMINOR) failedDecodePackets.incrementAndGet();
		}
		return decoded;
	}

}
