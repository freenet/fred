package freenet.node.simulator;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import freenet.crypt.RandomSource;
import freenet.node.Node;
import freenet.node.NodeInitException;
import freenet.node.NodeStarter;
import freenet.support.Executor;
import freenet.support.Logger;
import freenet.support.PooledExecutor;
import freenet.support.TimeUtil;
import freenet.support.Logger.LogLevel;
import freenet.support.LoggerHook.InvalidThresholdException;
import freenet.support.io.FileUtil;

public class BootstrapSeedTest {

	public static int EXIT_NO_SEEDNODES = 257;
	public static int EXIT_FAILED_TARGET = 258;
	public static int EXIT_THREW_SOMETHING = 259;
	
	public static int DARKNET_PORT = 5006;
	public static int OPENNET_PORT = 5007;
	
	/**
	 * @param args
	 * @throws InvalidThresholdException 
	 * @throws NodeInitException 
	 * @throws InterruptedException 
	 * @throws IOException 
	 */
	public static void main(String[] args) throws InvalidThresholdException, NodeInitException, InterruptedException, IOException {
		Node node = null;
		try {
		String ipOverride = null;
		if(args.length > 0)
			ipOverride = args[0];
        File dir = new File("bootstrap-test");
        FileUtil.removeAll(dir);
        RandomSource random = NodeStarter.globalTestInit(dir.getPath(), false, LogLevel.ERROR, "", false);
        File seednodes = new File("seednodes.fref");
        if(!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
        	System.err.println("Unable to read seednodes.fref, it doesn't exist, or is empty");
        	System.exit(EXIT_NO_SEEDNODES);
        }
        File innerDir = new File(dir, Integer.toString(DARKNET_PORT));
        innerDir.mkdir();
        FileInputStream fis = new FileInputStream(seednodes);
        FileUtil.writeTo(fis, new File(innerDir, "seednodes.fref"));
        fis.close();
        // Create one node
        Executor executor = new PooledExecutor();
        node = NodeStarter.createTestNode(DARKNET_PORT, OPENNET_PORT, "bootstrap-test", false, Node.DEFAULT_MAX_HTL, 0, random, executor, 1000, 5*1024*1024, true, true, true, true, true, true, true, 12*1024, false, true, false, false, ipOverride);
        //NodeCrypto.DISABLE_GROUP_STRIP = true;
    	//Logger.setupStdoutLogging(LogLevel.MINOR, "freenet:NORMAL,freenet.node.NodeDispatcher:MINOR,freenet.node.FNPPacketMangler:MINOR");
    	Logger.getChain().setThreshold(LogLevel.ERROR); // kill logging
    	long startTime = System.currentTimeMillis();
    	// Start it
        node.start();
        // Wait until we have 10 connected nodes...
        int seconds = 0;
		int targetPeers = node.getOpennet().getAnnouncementThreshold();
        while(seconds < 600) {
        	Thread.sleep(1000);
        	int seeds = node.peers.countSeednodes();
        	int seedConns = node.peers.getConnectedSeedServerPeersVector(null).size();
        	int opennetPeers = node.peers.countValidPeers();
        	int opennetConns = node.peers.countConnectedOpennetPeers();
        	System.err.println(""+seconds+" : seeds: "+seeds+", connected: "+seedConns
        			+" opennet: peers: "+opennetPeers+", connected: "+opennetConns);
        	seconds++;
        	if(opennetConns >= targetPeers) {
        		long timeTaken = System.currentTimeMillis()-startTime;
        		System.out.println("Completed bootstrap ("+targetPeers+" peers) in "+timeTaken+"ms ("+TimeUtil.formatTime(timeTaken)+")");
        		node.park();
        		System.exit(0);
        	}
        }
        System.err.println("Failed to reach target peers count "+targetPeers+" in 5 minutes.");
		node.park();
        System.exit(EXIT_FAILED_TARGET);
	    } catch (Throwable t) {
	    	System.err.println("CAUGHT: "+t);
	    	t.printStackTrace();
	    	try {
	    		if(node != null)
	    			node.park();
	    	} catch (Throwable t1) {}
	    	System.exit(EXIT_THREW_SOMETHING);
	    }
	}

}
