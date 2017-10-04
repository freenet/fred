/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node.simulator;

import static java.util.concurrent.TimeUnit.DAYS;

import java.io.File;
import java.io.UnsupportedEncodingException;

import freenet.client.HighLevelSimpleClient;
import freenet.crypt.DummyRandomSource;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.keys.CHKBlock;
import freenet.keys.CHKDecodeException;
import freenet.keys.CHKEncodeException;
import freenet.keys.CHKVerifyException;
import freenet.keys.ClientCHK;
import freenet.keys.ClientCHKBlock;
import freenet.node.FSParseException;
import freenet.node.Node;
import freenet.node.NodeInitException;
import freenet.node.NodeStarter;
import freenet.node.RequestStarter;
import freenet.support.Executor;
import freenet.support.Fields;
import freenet.support.HexUtil;
import freenet.support.Logger;
import freenet.support.PooledExecutor;
import freenet.support.Logger.LogLevel;
import freenet.support.LoggerHook.InvalidThresholdException;
import freenet.support.compress.InvalidCompressionCodecException;
import freenet.support.compress.Compressor.COMPRESSOR_TYPE;
import freenet.support.io.FileUtil;

/**
 * Test a busy, bandwidth limited network. Hopefully this should reveal any serious problems with
 * load limiting and block transfer.
 * @author toad
 */
public class RealNodeBusyNetworkTest extends RealNodeRoutingTest {

    static final int NUMBER_OF_NODES = 25;
    static final int DEGREE = 5;
    static final short MAX_HTL = (short)8;
    static final int INSERT_KEYS = 50;
    static final boolean START_WITH_IDEAL_LOCATIONS = true;
    static final boolean FORCE_NEIGHBOUR_CONNECTIONS = true;
    static final boolean ENABLE_SWAPPING = false;
    static final boolean ENABLE_ULPRS = false;
    static final boolean ENABLE_PER_NODE_FAILURE_TABLES = false;
    static final boolean ENABLE_SWAP_QUEUEING = false;
    static final boolean ENABLE_PACKET_COALESCING = true;
    static final boolean ENABLE_FOAF = true;
    static final boolean FORK_ON_CACHEABLE = false;
    static final boolean REAL_TIME_FLAG = false;

    static final int TARGET_SUCCESSES = 20;
    //static final int NUMBER_OF_NODES = 50;
    //static final short MAX_HTL = 10;

    static final int DARKNET_PORT_BASE = 5008;
    static final int DARKNET_PORT_END = DARKNET_PORT_BASE + NUMBER_OF_NODES;

    public static void main(String[] args) throws FSParseException, PeerParseException, CHKEncodeException, InvalidThresholdException, NodeInitException, ReferenceSignatureVerificationException, InterruptedException, UnsupportedEncodingException, CHKVerifyException, CHKDecodeException, InvalidCompressionCodecException {
        String name = "realNodeRequestInsertTest";
        File wd = new File(name);
        if(!FileUtil.removeAll(wd)) {
        	System.err.println("Mass delete failed, test may not be accurate.");
        	System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
        }
        wd.mkdir();
        //NOTE: globalTestInit returns in ignored random source
        //NodeStarter.globalTestInit(name, false, LogLevel.ERROR, "freenet.node.Location:normal,freenet.node.simulator.RealNode:minor,freenet.node.Insert:MINOR,freenet.node.Request:MINOR,freenet.node.Node:MINOR");
        //NodeStarter.globalTestInit(name, false, LogLevel.ERROR, "freenet.node.Location:MINOR,freenet.io.comm:MINOR,freenet.node.NodeDispatcher:MINOR,freenet.node.simulator:MINOR,freenet.node.PeerManager:MINOR,freenet.node.RequestSender:MINOR");
        //NodeStarter.globalTestInit(name, false, LogLevel.ERROR, "freenet.node.FNP:MINOR,freenet.node.Packet:MINOR,freenet.io.comm:MINOR,freenet.node.PeerNode:MINOR,freenet.node.DarknetPeerNode:MINOR");
        NodeStarter.globalTestInit(name, false, LogLevel.ERROR, "", true);
        System.out.println("Busy network test (inserts/retrieves in quantity/stress test)");
        System.out.println();
        DummyRandomSource random = new DummyRandomSource();
        //DiffieHellman.init(random);
        Node[] nodes = new Node[NUMBER_OF_NODES];
        Logger.normal(RealNodeRoutingTest.class, "Creating nodes...");
        Executor executor = new PooledExecutor();
        for(int i=0;i<NUMBER_OF_NODES;i++) {
            nodes[i] =
            	NodeStarter.createTestNode(DARKNET_PORT_BASE+i, 0, name, false, MAX_HTL, 20 /* 5% */, random, executor, 500*NUMBER_OF_NODES, (CHKBlock.DATA_LENGTH+CHKBlock.TOTAL_HEADERS_LENGTH)*100, true, ENABLE_SWAPPING, false, ENABLE_ULPRS, ENABLE_PER_NODE_FAILURE_TABLES, ENABLE_SWAP_QUEUEING, ENABLE_PACKET_COALESCING, 8000, ENABLE_FOAF, false, true, false, null);
            Logger.normal(RealNodeRoutingTest.class, "Created node "+i);
        }

        // Now link them up
        makeKleinbergNetwork(nodes, START_WITH_IDEAL_LOCATIONS, DEGREE, FORCE_NEIGHBOUR_CONNECTIONS, random);

        Logger.normal(RealNodeRoutingTest.class, "Added random links");

        for(int i=0;i<NUMBER_OF_NODES;i++) {
            nodes[i].start();
            System.err.println("Started node "+i+"/"+nodes.length);
        }

        waitForAllConnected(nodes);

        waitForPingAverage(0.95, nodes, random, MAX_PINGS, 1000);

        System.out.println();
        System.out.println("Ping average > 95%, lets do some inserts/requests");
        System.out.println();

        HighLevelSimpleClient[] clients = new HighLevelSimpleClient[nodes.length];
        for(int i=0;i<clients.length;i++) {
        	clients[i] = nodes[i].clientCore.makeClient(RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, false);
        }

        // Insert 100 keys into random nodes

        ClientCHK[] keys = new ClientCHK[INSERT_KEYS];

        String baseString = System.currentTimeMillis() + " ";
        for(int i=0;i<INSERT_KEYS;i++) {
        	System.err.println("Inserting "+i+" of "+INSERT_KEYS);
            int node1 = random.nextInt(NUMBER_OF_NODES);
            Node randomNode = nodes[node1];
            String dataString = baseString + i;
            byte[] data = dataString.getBytes("UTF-8");
            ClientCHKBlock b;
            b = ClientCHKBlock.encode(data, false, false, (short)-1, 0, COMPRESSOR_TYPE.DEFAULT_COMPRESSORDESCRIPTOR, false);
            CHKBlock block = b.getBlock();
            ClientCHK chk = b.getClientKey();
            byte[] encData = block.getData();
            byte[] encHeaders = block.getHeaders();
            ClientCHKBlock newBlock = new ClientCHKBlock(encData, encHeaders, chk, true);
            keys[i] = chk;
            Logger.minor(RealNodeRequestInsertTest.class, "Decoded: "+new String(newBlock.memoryDecode(), "UTF-8"));
            Logger.normal(RealNodeRequestInsertTest.class,"CHK: "+chk.getURI());
            Logger.minor(RealNodeRequestInsertTest.class,"Headers: "+HexUtil.bytesToHex(block.getHeaders()));
            // Insert it.
			try {
				randomNode.clientCore.realPut(block, false, FORK_ON_CACHEABLE, false, false, REAL_TIME_FLAG);
				Logger.error(RealNodeRequestInsertTest.class, "Inserted to "+node1);
				Logger.minor(RealNodeRequestInsertTest.class, "Data: "+Fields.hashCode(encData)+", Headers: "+Fields.hashCode(encHeaders));
			} catch (freenet.node.LowLevelPutException putEx) {
				Logger.error(RealNodeRequestInsertTest.class, "Insert failed: "+ putEx);
				System.err.println("Insert failed: "+ putEx);
				System.exit(EXIT_INSERT_FAILED);
			}
        }

        // Now queue requests for each key on every node.
        for(int i=0;i<INSERT_KEYS;i++) {
        	ClientCHK key = keys[i];
        	System.err.println("Queueing requests for "+i+" of "+INSERT_KEYS);
        	for(int j=0;j<nodes.length;j++) {
        		clients[j].prefetch(key.getURI(), DAYS.toMillis(1), 32768, null);
        	}
        	long totalRunningRequests = 0;
        	for(int j=0;j<nodes.length;j++) {
        		totalRunningRequests += nodes[j].clientCore.countQueuedRequests();
        	}
        	System.err.println("Running requests: "+totalRunningRequests);
        }

        // Now wait until finished. How???

        while(true) {
        	long totalRunningRequests = 0;
        	for(int i=0;i<nodes.length;i++) {
        		totalRunningRequests += nodes[i].clientCore.countQueuedRequests();
        	}
        	System.err.println("Running requests: "+totalRunningRequests);
        	if(totalRunningRequests == 0) break;
        	Thread.sleep(1000);
        }
        System.exit(0);
    }
}
