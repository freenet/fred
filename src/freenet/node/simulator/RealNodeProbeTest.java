/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node.simulator;

import freenet.config.SubConfig;
import freenet.crypt.DummyRandomSource;
import freenet.node.Node;
import freenet.node.NodeStarter;
import freenet.node.probe.Error;
import freenet.node.probe.Listener;
import freenet.node.probe.Probe;
import freenet.node.probe.Type;
import freenet.support.Executor;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.PooledExecutor;
import freenet.support.io.FileUtil;

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.InputStreamReader;
import java.text.NumberFormat;

/**
 * Create a mesh of nodes and let them sort out their locations.
 *
 * Then present a user interface to run different types of probes from random nodes.
 */
public class RealNodeProbeTest extends RealNodeRoutingTest {

	static final int NUMBER_OF_NODES = 100;
	static final int DEGREE = 10;
	static final short MAX_HTL = (short) 5;
	static final boolean START_WITH_IDEAL_LOCATIONS = true;
	static final boolean FORCE_NEIGHBOUR_CONNECTIONS = true;
	static final boolean ENABLE_SWAPPING = false;
	static final boolean ENABLE_SWAP_QUEUEING = false;
	static final boolean ENABLE_FOAF = true;
	private static final boolean DO_INSERT_TEST = true;
	static final int MAX_PINGS = 2000;
	static final int OUTPUT_BANDWIDTH_LIMIT = 0; // Can be useful to set this for some tests.

	public static int DARKNET_PORT_BASE = RealNodeRoutingTest.DARKNET_PORT_END;
	public static final int DARKNET_PORT_END = DARKNET_PORT_BASE + NUMBER_OF_NODES;

	public static void main(String[] args) throws Exception {
		System.out.println("Probe test using real nodes:");
		System.out.println();
		String dir = "realNodeProbeTest";
		File wd = new File(dir);
		if(!FileUtil.removeAll(wd)) {
			System.err.println("Mass delete failed, test may not be accurate.");
			System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
		}
		if (!wd.mkdir()) {
			System.err.println("Unabled to create test directory \"" + dir + "\".");
			return;
		}
		NodeStarter.globalTestInit(dir, false, LogLevel.ERROR, "", true);
		// Make the network reproducible so we can easily compare different routing options by specifying a seed.
		DummyRandomSource random = new DummyRandomSource(3142);
		Node[] nodes = new Node[NUMBER_OF_NODES];
		Logger.normal(RealNodeProbeTest.class, "Creating nodes...");
		Executor executor = new PooledExecutor();
		for(int i = 0; i < NUMBER_OF_NODES; i++) {
			System.err.println("Creating node " + i);
			nodes[i] = NodeStarter.createTestNode(DARKNET_PORT_BASE + i, 0, dir, true, MAX_HTL, 0 /* no dropped packets */, random, executor, 500 * NUMBER_OF_NODES, 256*1024, true, ENABLE_SWAPPING, false, false, false, ENABLE_SWAP_QUEUEING, true, OUTPUT_BANDWIDTH_LIMIT, ENABLE_FOAF, false, true, false, null, i == 0);
			Logger.normal(RealNodeProbeTest.class, "Created node " + i);
		}
		Logger.normal(RealNodeProbeTest.class, "Created " + NUMBER_OF_NODES + " nodes");
		// Now link them up
		makeKleinbergNetwork(nodes, START_WITH_IDEAL_LOCATIONS, DEGREE, FORCE_NEIGHBOUR_CONNECTIONS, random);

		Logger.normal(RealNodeProbeTest.class, "Added random links");

		for(int i = 0; i < NUMBER_OF_NODES; i++) {
			System.err.println("Starting node " + i);
			nodes[i].start();
		}

        System.out.println();
        System.out.println("Ping average > 95%, lets do some inserts/requests");
        System.out.println();
        
        if(DO_INSERT_TEST) {
        	
            waitForPingAverage(0.5, nodes, new DummyRandomSource(3143), MAX_PINGS, 1000);
            
            RealNodeRequestInsertTest tester = new RealNodeRequestInsertTest(nodes, random, 10);
            
            waitForAllConnected(nodes);
            
            while(true) {
            	try {
            		waitForAllConnected(nodes);
            		int status = tester.insertRequestTest();
            		if(status == -1) continue;
            		System.out.println("Insert test completed with status "+status);
            		break;
            	} catch (Throwable t) {
            		Logger.error(RealNodeRequestInsertTest.class, "Caught "+t, t);
            	}
            }
        }

		final NumberFormat nf = NumberFormat.getInstance();
		Listener print = new Listener() {
			@Override
			public void onError(Error error, Byte code, boolean local) {
				System.out.print("Probe error: " + error.name());
				if (local) System.out.print(" (local)");
				System.out.println(code == null ? "" : " (" + code + ")");
			}

			@Override
			public void onRefused() {
				System.out.println("Probe refused.");
			}

			@Override
			public void onOutputBandwidth(float outputBandwidth) {
				System.out.println("Probe got bandwidth limit " + nf.format(outputBandwidth) +
					" KiB per second.");
			}

			@Override
			public void onBuild(int build) {
				System.out.println("Probe got build " + build + ".");
			}

			@Override
			public void onIdentifier(long identifier, byte uptimePercentage) {
				System.out.println("Probe got identifier " + identifier + " with uptime percentage " + uptimePercentage + ".");
			}

			@Override
			public void onLinkLengths(float[] linkLengths) {
				System.out.print("Probe got link lengths: { ");
				for (Float length : linkLengths) System.out.print(length + " ");
				System.out.println("}.");
			}

			@Override
			public void onLocation(float location) {
				System.out.println("Probe got location " + location + ".");
			}

			@Override
			public void onStoreSize(float storeSize) {
				System.out.println("Probe got store size " + nf.format(storeSize) + " GiB.");
			}

			@Override
			public void onUptime(float uptimePercentage) {
				System.out.print("Probe got uptime " + nf.format(uptimePercentage) + "%.");
			}

			@Override
			public void onRejectStats(byte[] stats) {
				System.out.println("Probe got reject stats:");
				System.out.println("CHK request: "+stats[0]);
				System.out.println("SSK request: "+stats[1]);
				System.out.println("CHK insert: "+stats[2]);
				System.out.println("SSK insert: "+stats[3]);
			}

			@Override
			public void onOverallBulkOutputCapacity(
					byte bandwidthClassForCapacityUsage, float outputBulkCapacityUsed) {
				System.out.println("Probe got output capacity "+nf.format(outputBulkCapacityUsed)+
						"% (bandwidth class "+bandwidthClassForCapacityUsage+")");
			}
		};

		final Type types[] = {
			Type.BANDWIDTH,
			Type.BUILD,
			Type.IDENTIFIER,
			Type.LINK_LENGTHS,
			Type.LOCATION,
			Type.STORE_SIZE,
			Type.UPTIME_48H,
			Type.UPTIME_7D,
			Type.REJECT_STATS,
			Type.OVERALL_BULK_OUTPUT_CAPACITY_USAGE
		};

		int index = 0;
		byte htl = Probe.MAX_HTL;
		BufferedReader r;
		Console console = System.console();
		if(console != null)
			r = new BufferedReader(console.reader());
		else
			r = new BufferedReader(new InputStreamReader(System.in)); // Use the system locale here.
		while (true) {
			System.err.println("Sending probes from node " + index + " with HTL " + htl + ".");
			System.err.println("0) BANDWIDTH");
			System.err.println("1) BUILD");
			System.err.println("2) IDENTIFIER");
			System.err.println("3) LINK_LENGTHS");
			System.err.println("4) LOCATION");
			System.err.println("5) STORE_SIZE");
			System.err.println("6) UPTIME 48-hour");
			System.err.println("7) UPTIME 7-day");
			System.err.println("8) REJECT_STATS");
			System.err.println("9) OVERALL_BULK_OUTPUT_CAPACITY_USAGE");
			System.err.println("10) Pick another node");
			System.err.println("11) Pick another HTL");
			System.err.println("12) Pick current node's refusals");
			
			System.err.println("Anything else to exit.");
			System.err.println("Select: ");
			try {
				int selection = Integer.parseInt(r.readLine());
				if (selection == types.length) {
					System.err.print("Enter new node index ([0-" + (NUMBER_OF_NODES - 1) + "]):");
					index = Integer.valueOf(r.readLine());
				}
				else if (selection == types.length+1) {
					System.err.print("Enter new HTL: ");
					htl = Byte.valueOf(r.readLine());
				} else if (selection == types.length+2) {
					SubConfig nodeConfig = nodes[index].config.get("node");
					String[] options = { "probeBandwidth", "probeBuild", "probeIdentifier", "probeLinkLengths", "probeLinkLengths", "probeUptime" };
					for (String option : options) {
						System.err.print(option + ": ");
						nodeConfig.set(option, Boolean.valueOf(r.readLine()));
					}
				} else nodes[index].startProbe(htl, random.nextLong(), types[selection], print);
			} catch (Exception e) {
				//If a non-number is entered or one outside the bounds.
				System.out.print(e.toString());
				e.printStackTrace();
				//Return isn't enough to exit: the nodes are still in the background.
				System.exit(0);
			}
		}
	}
}
