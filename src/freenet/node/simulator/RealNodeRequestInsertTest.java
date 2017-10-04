/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node.simulator;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

import freenet.crypt.DummyRandomSource;
import freenet.crypt.RandomSource;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.keys.CHKEncodeException;
import freenet.keys.ClientCHKBlock;
import freenet.keys.ClientKSK;
import freenet.keys.ClientKey;
import freenet.keys.ClientKeyBlock;
import freenet.keys.FreenetURI;
import freenet.keys.InsertableClientSSK;
import freenet.keys.KeyDecodeException;
import freenet.keys.SSKEncodeException;
import freenet.node.FSParseException;
import freenet.node.LowLevelGetException;
import freenet.node.Node;
import freenet.node.NodeInitException;
import freenet.node.NodeStarter;
import freenet.support.Executor;
import freenet.support.Logger;
import freenet.support.PooledExecutor;
import freenet.support.Logger.LogLevel;
import freenet.support.LoggerHook.InvalidThresholdException;
import freenet.support.compress.Compressor.COMPRESSOR_TYPE;
import freenet.support.compress.InvalidCompressionCodecException;
import freenet.support.io.ArrayBucket;
import freenet.support.io.FileUtil;
import freenet.support.math.RunningAverage;
import freenet.support.math.SimpleRunningAverage;

/**
 * @author amphibian
 */
public class RealNodeRequestInsertTest extends RealNodeRoutingTest {

    static final int NUMBER_OF_NODES = 100;
    static final int DEGREE = 10;
    static final short MAX_HTL = (short)5;
    static final boolean START_WITH_IDEAL_LOCATIONS = true;
    static final boolean FORCE_NEIGHBOUR_CONNECTIONS = true;
    static final boolean ENABLE_SWAPPING = false;
    static final boolean ENABLE_ULPRS = false;
    static final boolean ENABLE_PER_NODE_FAILURE_TABLES = false;
    static final boolean ENABLE_SWAP_QUEUEING = false;
    static final boolean ENABLE_PACKET_COALESCING = true;
    static final boolean ENABLE_FOAF = true;
    static final boolean FORK_ON_CACHEABLE = false;
    static final boolean DISABLE_PROBABILISTIC_HTLS = true;
    // Set to true to cache everything. This depends on security level.
    static final boolean USE_SLASHDOT_CACHE = false;
    static final boolean REAL_TIME_FLAG = false;
    
    static final int TARGET_SUCCESSES = 20;
    //static final int NUMBER_OF_NODES = 50;
    //static final short MAX_HTL = 10;

    // FIXME: HACK: High bwlimit makes the "other" requests not affect the test requests.
    // Real solution is to get rid of the "other" requests!!
    static final int BWLIMIT = 1000*1024;
    
    //public static final int DARKNET_PORT_BASE = RealNodePingTest.DARKNET_PORT2+1;
    public static final int DARKNET_PORT_BASE = 10000;
    public static final int DARKNET_PORT_END = DARKNET_PORT_BASE + NUMBER_OF_NODES;
    
	public static void main(String[] args) throws FSParseException, PeerParseException, CHKEncodeException, InvalidThresholdException, NodeInitException, ReferenceSignatureVerificationException, InterruptedException {
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
        System.out.println("Insert/retrieve test");
        System.out.println();
        DummyRandomSource random = new DummyRandomSource(3142);
        DummyRandomSource topologyRandom = new DummyRandomSource(3143);
        //DiffieHellman.init(random);
        Node[] nodes = new Node[NUMBER_OF_NODES];
        Logger.normal(RealNodeRoutingTest.class, "Creating nodes...");
        Executor executor = new PooledExecutor();
        for(int i=0;i<NUMBER_OF_NODES;i++) {
            nodes[i] = 
            	NodeStarter.createTestNode(DARKNET_PORT_BASE+i, 0, name, DISABLE_PROBABILISTIC_HTLS, MAX_HTL, 20 /* 5% */, random, executor, 500*NUMBER_OF_NODES, 256*1024, true, ENABLE_SWAPPING, false, ENABLE_ULPRS, ENABLE_PER_NODE_FAILURE_TABLES, ENABLE_SWAP_QUEUEING, ENABLE_PACKET_COALESCING, BWLIMIT, ENABLE_FOAF, false, true, USE_SLASHDOT_CACHE, null);
            Logger.normal(RealNodeRoutingTest.class, "Created node "+i);
        }
        
        // Now link them up
        makeKleinbergNetwork(nodes, START_WITH_IDEAL_LOCATIONS, DEGREE, FORCE_NEIGHBOUR_CONNECTIONS, topologyRandom);

        Logger.normal(RealNodeRoutingTest.class, "Added random links");
        
        for(int i=0;i<NUMBER_OF_NODES;i++) {
            nodes[i].start();
            System.err.println("Started node "+i+"/"+nodes.length);
        }
        
        waitForAllConnected(nodes);
        
        waitForPingAverage(0.5, nodes, new DummyRandomSource(3143), MAX_PINGS, 1000);
        
        random = new DummyRandomSource(3144);
        
        System.out.println();
        System.out.println("Ping average > 95%, lets do some inserts/requests");
        System.out.println();
        
        RealNodeRequestInsertTest tester = new RealNodeRequestInsertTest(nodes, random, TARGET_SUCCESSES);
        
        while(true) {
            try {
    			waitForAllConnected(nodes);
    			int status = tester.insertRequestTest();
    			if(status == -1) continue;
    			System.exit(status);
            } catch (Throwable t) {
                Logger.error(RealNodeRequestInsertTest.class, "Caught "+t, t);
            }
        }
    }

    public RealNodeRequestInsertTest(Node[] nodes, DummyRandomSource random, int targetSuccesses) {
    	this.nodes = nodes;
    	this.random = random;
    	this.targetSuccesses = targetSuccesses;
	}

    private final Node[] nodes;
    private final RandomSource random;
    private int requestNumber = 0;
    private RunningAverage requestsAvg = new SimpleRunningAverage(100, 0.0);
    private String baseString = System.currentTimeMillis() + " ";
	private int insertAttempts = 0;
	private int fetchSuccesses = 0;
	private final int targetSuccesses;

	/**
	 * @param nodes
	 * @param random
	 * @return -1 to continue or an exit code (0 or positive for an error).
	 * @throws CHKEncodeException
	 * @throws InvalidCompressionCodecException
	 * @throws SSKEncodeException
	 * @throws IOException
	 * @throws KeyDecodeException
	 */
	int insertRequestTest() throws CHKEncodeException, InvalidCompressionCodecException, SSKEncodeException, IOException, KeyDecodeException {
		
        requestNumber++;
        try {
            Thread.sleep(100);
        } catch (InterruptedException e1) {
        }
        String dataString = baseString + requestNumber;
        // Pick random node to insert to
        int node1 = random.nextInt(NUMBER_OF_NODES);
        Node randomNode = nodes[node1];
        //Logger.error(RealNodeRequestInsertTest.class,"Inserting: \""+dataString+"\" to "+node1);
        
        //boolean isSSK = requestNumber % 2 == 1;
        boolean isSSK = true;
        
        FreenetURI testKey;
        ClientKey insertKey;
        ClientKey fetchKey;
        ClientKeyBlock block;
        
    	byte[] buf = dataString.getBytes("UTF-8");
        if(isSSK) {
        	testKey = new FreenetURI("KSK", dataString);
        	
        	insertKey = InsertableClientSSK.create(testKey);
        	fetchKey = ClientKSK.create(testKey);
        	
        	block = ((InsertableClientSSK)insertKey).encode(new ArrayBucket(buf), false, false, (short)-1, buf.length, COMPRESSOR_TYPE.DEFAULT_COMPRESSORDESCRIPTOR, false);
        } else {
        	block = ClientCHKBlock.encode(buf, false, false, (short)-1, buf.length, COMPRESSOR_TYPE.DEFAULT_COMPRESSORDESCRIPTOR, false);
        	insertKey = fetchKey = block.getClientKey();
        	testKey = insertKey.getURI();
        }
        
        System.err.println();
        System.err.println("Created random test key "+testKey+" = "+fetchKey.getNodeKey(false));
        System.err.println();
        
        byte[] data = dataString.getBytes("UTF-8");
        Logger.minor(RealNodeRequestInsertTest.class, "Decoded: "+new String(block.memoryDecode(), "UTF-8"));
        Logger.normal(RealNodeRequestInsertTest.class,"Insert Key: "+insertKey.getURI());
        Logger.normal(RealNodeRequestInsertTest.class,"Fetch Key: "+fetchKey.getURI());
		try {
			insertAttempts++;
			randomNode.clientCore.realPut(block.getBlock(), false, FORK_ON_CACHEABLE, false, false, REAL_TIME_FLAG);
			Logger.error(RealNodeRequestInsertTest.class, "Inserted to "+node1);
		} catch (freenet.node.LowLevelPutException putEx) {
			Logger.error(RealNodeRequestInsertTest.class, "Insert failed: "+ putEx);
			System.err.println("Insert failed: "+ putEx);
			return EXIT_INSERT_FAILED;
		}
        // Pick random node to request from
        int node2;
        do {
            node2 = random.nextInt(NUMBER_OF_NODES);
        } while(node2 == node1);
        Node fetchNode = nodes[node2];
        try {
        	block = fetchNode.clientCore.realGetKey(fetchKey, false, false, false, REAL_TIME_FLAG);
        } catch (LowLevelGetException e) {
        	block = null;
        }
        if(block == null) {
			int percentSuccess=100*fetchSuccesses/insertAttempts;
            Logger.error(RealNodeRequestInsertTest.class, "Fetch #"+requestNumber+" FAILED ("+percentSuccess+"%); from "+node2);
            System.err.println("Fetch #"+requestNumber+" FAILED ("+percentSuccess+"%); from "+node2);
            requestsAvg.report(0.0);
        } else {
            byte[] results = block.memoryDecode();
            requestsAvg.report(1.0);
            if(Arrays.equals(results, data)) {
				fetchSuccesses++;
				int percentSuccess=100*fetchSuccesses/insertAttempts;
                Logger.error(RealNodeRequestInsertTest.class, "Fetch #"+requestNumber+" from node "+node2+" succeeded ("+percentSuccess+"%): "+new String(results));
                System.err.println("Fetch #"+requestNumber+" succeeded ("+percentSuccess+"%): \""+new String(results)+'\"');
                if(fetchSuccesses == targetSuccesses) {
                	System.err.println("Succeeded, "+targetSuccesses+" successful fetches");
                	return 0;
                }
            } else {
                Logger.error(RealNodeRequestInsertTest.class, "Returned invalid data!: "+new String(results));
                System.err.println("Returned invalid data!: "+new String(results));
                return EXIT_BAD_DATA;
            }
        }
        StringBuilder load = new StringBuilder("Running UIDs for nodes: ");
        int totalRunningUIDsAlt = 0;
        List<Long> runningUIDsList = new ArrayList<Long>();
        for(int i=0;i<nodes.length;i++) {
        	load.append(i);
        	load.append(':');
        	nodes[i].tracker.addRunningUIDs(runningUIDsList);
        	int runningUIDsAlt = nodes[i].tracker.getTotalRunningUIDsAlt();
        	totalRunningUIDsAlt += runningUIDsAlt;
        	load.append(totalRunningUIDsAlt);
        	if(i != nodes.length-1)
        		load.append(' ');
        }
        System.err.println(load.toString());
        if(totalRunningUIDsAlt != 0)
        	System.err.println("Still running UIDs (alt): "+totalRunningUIDsAlt);
        if(!runningUIDsList.isEmpty()) {
        	System.err.println("List of running UIDs: "+Arrays.toString(runningUIDsList.toArray()));
        }
        return -1;
	}
}
