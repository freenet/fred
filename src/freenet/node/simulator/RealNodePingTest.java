/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node.simulator;

import freenet.crypt.RandomSource;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.node.FSParseException;
import freenet.node.Node;
import freenet.node.NodeInitException;
import freenet.node.NodeStarter;
import freenet.node.PeerNode;
import freenet.node.DarknetPeerNode.FRIEND_TRUST;
import freenet.node.DarknetPeerNode.FRIEND_VISIBILITY;
import freenet.node.PeerTooOldException;
import freenet.support.Executor;
import freenet.support.Logger;
import freenet.support.PooledExecutor;
import freenet.support.Logger.LogLevel;
import freenet.support.LoggerHook.InvalidThresholdException;

/**
 * @author amphibian
 * 
 * When the code is invoked via this class, it:
 * - Creates two nodes.
 * - Connects them to each other
 * - Sends pings from the first node to the second node.
 * - Prints on the logger when packets are sent, when they are
 *   received, (by both sides), and their sequence numbers.
 */
public class RealNodePingTest {
	
	public static final int DARKNET_PORT1 = RealNodeBusyNetworkTest.DARKNET_PORT_END;
	public static final int DARKNET_PORT2 = RealNodeBusyNetworkTest.DARKNET_PORT_END+1;
	public static final int DARKNET_PORT_END = DARKNET_PORT2+1;
	
	static final FRIEND_TRUST trust = FRIEND_TRUST.LOW;
	static final FRIEND_VISIBILITY visibility = FRIEND_VISIBILITY.NO;

    public static void main(String[] args) throws FSParseException, PeerParseException, InterruptedException, ReferenceSignatureVerificationException, NodeInitException, InvalidThresholdException, PeerTooOldException {
        RandomSource random = NodeStarter.globalTestInit("pingtest", false, LogLevel.ERROR, "", true);
        // Create 2 nodes
        Executor executor = new PooledExecutor();
        Node node1 = NodeStarter.createTestNode(DARKNET_PORT1, 0, "pingtest", true, Node.DEFAULT_MAX_HTL, 0, random, executor, 1000, 65536, true, false, false, false, false, false, true, 0, false, false, true, false, null);
        Node node2 = NodeStarter.createTestNode(DARKNET_PORT2, 0, "pingtest", true, Node.DEFAULT_MAX_HTL, 0, random, executor, 1000, 65536, true, false, false, false, false, false, true, 0, false, false, true, false, null);
        // Connect
        node1.connect(node2, trust, visibility);
        node2.connect(node1, trust, visibility);
        // No swapping
        node1.start();
        node2.start();
        // Ping
        PeerNode pn = node1.getPeerNodes()[0];
        int pingID = 0;
        Thread.sleep(20000);
        //node1.usm.setDropProbability(4);
        while(true) {
            Logger.error(RealNodePingTest.class, "Sending PING "+pingID);
            boolean success;
            try {
                success = pn.ping(pingID);
            } catch (NotConnectedException e1) {
                Logger.error(RealNodePingTest.class, "Not connected");
                continue;
            }
            if(success)
                Logger.error(RealNodePingTest.class, "PING "+pingID+" successful");
            else
                Logger.error(RealNodePingTest.class, "PING FAILED: "+pingID);
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                // Shouldn't happen
            }
            pingID++;
        }
    }
}
