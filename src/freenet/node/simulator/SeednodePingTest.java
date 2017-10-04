/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node.simulator;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import freenet.crypt.RandomSource;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.node.Announcer;
import freenet.node.FSParseException;
import freenet.node.Node;
import freenet.node.NodeFile;
import freenet.node.NodeInitException;
import freenet.node.NodeStarter;
import freenet.node.OpennetDisabledException;
import freenet.node.SeedServerPeerNode;
import freenet.node.SeedServerTestPeerNode;
import freenet.node.SeedServerTestPeerNode.FATE;
import freenet.support.Executor;
import freenet.support.Logger;
import freenet.support.PooledExecutor;
import freenet.support.SimpleFieldSet;
import freenet.support.TimeUtil;
import freenet.support.Logger.LogLevel;
import freenet.support.LoggerHook.InvalidThresholdException;

/**
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class SeednodePingTest extends RealNodeTest {

	static File STATUS_DIR = new File("/var/www/freenet/tests/seednodes/status/");
	static final long COUNT_SUCCESSES_PERIOD = DAYS.toMillis(7);

	static final int DARKNET_PORT = RealNodeULPRTest.DARKNET_PORT_END;
	static final int OPENNET_PORT = DARKNET_PORT+1;

    public static void main(String[] args) throws FSParseException, IOException, OpennetDisabledException, PeerParseException, InterruptedException, ReferenceSignatureVerificationException, NodeInitException, InvalidThresholdException {
    	Node node = null;
    	try {
    	if(args.length == 1)
    		STATUS_DIR = new File(args[0]);
        RandomSource random = NodeStarter.globalTestInit("seednode-pingtest", false, LogLevel.ERROR, "", false);
        // Create one node
        Executor executor = new PooledExecutor();
	node = NodeStarter.createTestNode(DARKNET_PORT, OPENNET_PORT, "seednode-pingtest", false, Node.DEFAULT_MAX_HTL, 0, random, executor, 1000, 5*1024*1024, true, false, false, false, false, false, false, 0, false, false, false, false, null);
	// Connect & ping
	List<SeedServerTestPeerNode> seedNodes = new ArrayList<SeedServerTestPeerNode>();
	List<SimpleFieldSet> seedNodesAsSFS = Announcer.readSeednodes(new File("/tmp/", NodeFile.Seednodes.getFilename()));
	int numberOfNodesInTheFile = 0;
	for(SimpleFieldSet sfs : seedNodesAsSFS) {
		numberOfNodesInTheFile++;
		SeedServerTestPeerNode seednode = node.createNewSeedServerTestPeerNode(sfs);
		try {
			node.connectToSeednode(seednode);
			seedNodes.add(seednode);
		} catch (Exception fse) {
			System.err.println("ERROR adding "+seednode.toString()+ " "+fse.getMessage());
		}
	}
	// Start it
        node.start();
	//Logger.setupStdoutLogging(LogLevel.MINOR, "freenet:NORMAL,freenet.node.NodeDispatcher:MINOR,freenet.node.FNPPacketMangler:MINOR");
	Logger.getChain().setThreshold(LogLevel.ERROR); // kill logging
	Thread.sleep(SECONDS.toMillis(2));
	if(seedNodes.size() != numberOfNodesInTheFile)
		    System.out.println("ERROR ADDING SOME OF THE SEEDNODES!!");
	System.out.println("Let some time for the "+ seedNodes.size() +" nodes to connect...");
	Thread.sleep(SECONDS.toMillis(8));

	int pingID = 0;
	long deadline = System.currentTimeMillis() + MINUTES.toMillis(2);
	while(System.currentTimeMillis() < deadline) {
		int countConnectedSeednodes = 0;
		for(SeedServerPeerNode seednode : node.peers.getConnectedSeedServerPeersVector(null)) {
			try {
				double pingTime = seednode.averagePingTime();
				int uptime = seednode.getUptime();
				long timeDelta = seednode.getClockDelta();
				if(seednode.isRealConnection())
					continue;
				countConnectedSeednodes++;
				boolean ping = seednode.ping(pingID++);
				if(ping)
					System.out.println(seednode.getIdentityString()+
						" uptime="+uptime+
						" ping="+ping+
						" pingTime="+pingTime+
						" uptime="+seednode.getUptime()+
						" timeDelta="+TimeUtil.formatTime(timeDelta));
				// sanity check
				if(seednode.isRoutable())
					System.out.println(seednode + " is routable!");
			} catch (NotConnectedException e) {
				System.out.println(seednode.getIdentityString() + " is not connected "+seednode.getHandshakeCount());
			}
		}
		Map<FATE, Integer> totals = new EnumMap<FATE, Integer>(SeedServerTestPeerNode.FATE.class);
		for(SeedServerTestPeerNode seednode : seedNodes) {
			FATE fate = seednode.getFate();
			Integer x = totals.get(fate);
			if(x == null)
				totals.put(fate, 1);
			else
				totals.put(fate, x+1);
			System.out.println(seednode.getIdentityString() + " : "+fate+ " : "+seednode.getPeerNodeStatusString());
		}
		System.out.println("TOTALS:");
		for (Entry<FATE, Integer> fateEntry : totals.entrySet()) {
			System.out.println(fateEntry.getKey() + " : " + fateEntry.getValue());
		}
		System.out.println("################## ("+node.peers.countConnectedPeers()+") "+countConnectedSeednodes+'/'+node.peers.countSeednodes());
		Thread.sleep(SECONDS.toMillis(5));
	}
	Map<FATE, Integer> totals = new EnumMap<FATE, Integer>(SeedServerTestPeerNode.FATE.class);
	for(SeedServerTestPeerNode seednode : seedNodes) {
		FATE fate = seednode.getFate();
		Integer x = totals.get(fate);
		if(x == null)
			totals.put(fate, 1);
		else
			totals.put(fate, x+1);
		System.out.println(seednode.getIdentityString() + " : "+fate+ " : "+seednode.getPeerNodeStatusString());
	}
	System.out.println("RESULT:TOTALS:");
	for(FATE fate : totals.keySet()) {
		System.out.println("RESULT:"+fate + " : "+totals.get(fate));
	}
    System.out.println("Completed seednodes scan.");
    // Record statuses.
    System.out.println("FINAL STATUS:");
    long writeTime = System.currentTimeMillis();
    for(SeedServerTestPeerNode peer : seedNodes) {
    	String status = writeTime+" : "+peer.getIdentityString()+" : "+peer.getFate();
    	System.out.println(status);
    	File logFile = new File(STATUS_DIR, peer.getIdentityString());
    	FileOutputStream fos = new FileOutputStream(logFile, true);
    	OutputStreamWriter osw = new OutputStreamWriter(fos, "UTF-8");
    	osw.write(status+"\n");
    	osw.close();
    	FileInputStream fis = new FileInputStream(logFile);
    	InputStreamReader isr = new InputStreamReader(fis, "UTF-8");
    	BufferedReader br = new BufferedReader(isr);
    	String line;
    	int successes = 0;
    	int failures = 0;
    	long lastSuccess = 0;
    	long firstSample = 0;
    	long countSince = writeTime - COUNT_SUCCESSES_PERIOD;
    	do {
    		line = br.readLine();
    		if(line == null) break;
    		String[] results = line.split(" : ");
    		if(results.length != 3) {
    			System.err.println("Unable to parse line in "+logFile+" : wrong number of fields : "+results.length+" : "+line);
    			continue;
    		}
    		long time = Long.parseLong(results[0]);
    		FATE fate = FATE.valueOf(results[2]);
    		if(firstSample == 0) firstSample = time;
    		if(fate == FATE.CONNECTED_SUCCESS) {
    			if(time >= countSince)
    				successes++;
    			lastSuccess = time;
    		} else {
    			if(time >= countSince)
    				failures++;
    		}
    	} while(line != null);
    	br.close();
    	if(firstSample < countSince && successes == 0)
    		System.err.println("RESULT:"+peer.getIdentityString()+" NOT CONNECTED IN LAST WEEK! LAST CONNECTED: "+(lastSuccess > 0 ? TimeUtil.formatTime(writeTime - lastSuccess) : "NEVER"));
    	System.out.println(peer.getIdentityString()+" : last success "+(lastSuccess > 0 ? TimeUtil.formatTime(writeTime - lastSuccess) : "NEVER")+" failures in last week: "+failures+" successes in last week: "+successes);
    }
    node.park();
    System.exit(0);
    } catch (Throwable t) {
    	System.err.println("CAUGHT: "+t);
    	t.printStackTrace();
    	try {
    		if(node != null)
    		node.park();
    	} catch (Throwable t1) {}
    	System.exit(1);
    }
    }
}
