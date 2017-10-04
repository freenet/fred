package freenet.node.simulator;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;

import freenet.client.ClientMetadata;
import freenet.client.FetchException;
import freenet.client.HighLevelSimpleClient;
import freenet.client.InsertBlock;
import freenet.client.InsertException;
import freenet.crypt.RandomSource;
import freenet.keys.FreenetURI;
import freenet.node.Node;
import freenet.node.NodeInitException;
import freenet.node.NodeStarter;
import freenet.support.Executor;
import freenet.support.Logger;
import freenet.support.PooledExecutor;
import freenet.support.TimeUtil;
import freenet.support.Logger.LogLevel;
import freenet.support.LoggerHook.InvalidThresholdException;
import freenet.support.api.RandomAccessBucket;
import freenet.support.io.FileUtil;

public class BootstrapPushPullTest {

	public static int TEST_SIZE = 1024*1024;
	
	public static int EXIT_NO_SEEDNODES = 257;
	public static int EXIT_FAILED_TARGET = 258;
	public static int EXIT_INSERT_FAILED = 259;
	public static int EXIT_FETCH_FAILED = 260;
	public static int EXIT_THREW_SOMETHING = 261;
	
	public static int DARKNET_PORT1 = 5002;
	public static int OPENNET_PORT1 = 5003;
	public static int DARKNET_PORT2 = 5004;
	public static int OPENNET_PORT2 = 5005;
	
	public static void main(String[] args) throws InvalidThresholdException, IOException, NodeInitException, InterruptedException {
		Node node = null;
		Node secondNode = null;
		try {
		String ipOverride = null;
		if(args.length > 0)
			ipOverride = args[0];
        File dir = new File("bootstrap-push-pull-test");
        FileUtil.removeAll(dir);
        RandomSource random = NodeStarter.globalTestInit(dir.getPath(), false, LogLevel.NORMAL, ""/*"freenet.node:MINOR,freenet.client:MINOR"*/, false);
        File seednodes = new File("seednodes.fref");
        if(!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
        	System.err.println("Unable to read seednodes.fref, it doesn't exist, or is empty");
        	System.exit(EXIT_NO_SEEDNODES);
        }
        File innerDir = new File(dir, Integer.toString(DARKNET_PORT1));
        innerDir.mkdir();
        FileInputStream fis = new FileInputStream(seednodes);
        FileUtil.writeTo(fis, new File(innerDir, "seednodes.fref"));
        fis.close();
        // Create one node
        Executor executor = new PooledExecutor();
        node = NodeStarter.createTestNode(DARKNET_PORT1, OPENNET_PORT1, dir.getPath(), false, Node.DEFAULT_MAX_HTL, 0, random, executor, 1000, 5*1024*1024, true, true, true, true, true, true, true, 12*1024, false, true, false, false, ipOverride);
        //NodeCrypto.DISABLE_GROUP_STRIP = true;
    	//Logger.setupStdoutLogging(LogLevel.MINOR, "freenet:NORMAL,freenet.node.NodeDispatcher:MINOR,freenet.node.FNPPacketMangler:MINOR");
    	Logger.getChain().setThreshold(LogLevel.ERROR); // kill logging
    	// Start it
        node.start();
		if (!TestUtil.waitForNodes(node)) {
			node.park();
			System.exit(EXIT_FAILED_TARGET);
		}
        System.err.println("Creating test data: "+TEST_SIZE+" bytes.");
        RandomAccessBucket data = node.clientCore.tempBucketFactory.makeBucket(TEST_SIZE);
        OutputStream os = data.getOutputStream();
		try {
        byte[] buf = new byte[4096];
        for(long written = 0; written < TEST_SIZE;) {
        	node.fastWeakRandom.nextBytes(buf);
        	int toWrite = (int) Math.min(TEST_SIZE - written, buf.length);
        	os.write(buf, 0, toWrite);
        	written += toWrite;
        }
		} finally {
        os.close();
		}
        System.err.println("Inserting test data.");
        HighLevelSimpleClient client = node.clientCore.makeClient((short)0, false);
        InsertBlock block = new InsertBlock(data, new ClientMetadata(), FreenetURI.EMPTY_CHK_URI);
        long startInsertTime = System.currentTimeMillis();
        FreenetURI uri;
        try {
			uri = client.insert(block, false, null);
		} catch (InsertException e) {
			System.err.println("INSERT FAILED: "+e);
			e.printStackTrace();
			System.exit(EXIT_INSERT_FAILED);
			return;
		}
        long endInsertTime = System.currentTimeMillis();
        System.err.println("RESULT: Insert took "+(endInsertTime-startInsertTime)+"ms ("+TimeUtil.formatTime(endInsertTime-startInsertTime)+") to "+uri+" .");
        node.park();
		
        // Bootstrap a second node.
        File secondInnerDir = new File(dir, Integer.toString(DARKNET_PORT2));
        secondInnerDir.mkdir();
        fis = new FileInputStream(seednodes);
        FileUtil.writeTo(fis, new File(secondInnerDir, "seednodes.fref"));
        fis.close();
        executor = new PooledExecutor();
        secondNode = NodeStarter.createTestNode(DARKNET_PORT2, OPENNET_PORT2, dir.getPath(), false, Node.DEFAULT_MAX_HTL, 0, random, executor, 1000, 5*1024*1024, true, true, true, true, true, true, true, 12*1024, false, true, false, false, ipOverride);        
        secondNode.start();
		if (!TestUtil.waitForNodes(secondNode)) {
			secondNode.park();
			System.exit(EXIT_FAILED_TARGET);
		}
        
        // Fetch the data
        long startFetchTime = System.currentTimeMillis();
        client = secondNode.clientCore.makeClient((short)0, false);
        try {
			client.fetch(uri);
		} catch (FetchException e) {
			System.err.println("FETCH FAILED: "+e);
			e.printStackTrace();
			System.exit(EXIT_FETCH_FAILED);
			return;
		}
		long endFetchTime = System.currentTimeMillis();
		System.err.println("RESULT: Fetch took "+(endFetchTime-startFetchTime)+"ms ("+TimeUtil.formatTime(endFetchTime-startFetchTime)+") of "+uri+" .");
		secondNode.park();
		System.exit(0);
	    } catch (Throwable t) {
	    	System.err.println("CAUGHT: "+t);
	    	t.printStackTrace();
	    	try {
	    		if(node != null)
	    			node.park();
	    	} catch (Throwable t1) {}
	    	try {
	    		if(secondNode != null)
	    			secondNode.park();
	    	} catch (Throwable t1) {}

	    	System.exit(EXIT_THREW_SOMETHING);
	    }
	}
}
