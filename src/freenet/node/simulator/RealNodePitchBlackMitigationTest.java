/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node.simulator;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.File;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.stream.Collectors;

import freenet.crypt.DummyRandomSource;
import freenet.crypt.RandomSource;
import freenet.node.LocationManager;
import freenet.node.Node;
import freenet.node.NodeStarter;
import freenet.node.PeerNode;
import freenet.support.Executor;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.PooledExecutor;
import freenet.support.io.FileUtil;
import freenet.support.math.BootstrappingDecayingRunningAverage;
import freenet.support.math.RunningAverage;
import freenet.support.math.SimpleRunningAverage;

/**
 * @author amphibian
 *
 * Create a mesh of nodes and let them sort out their locations.
 *
 * Then run some node-to-node searches.
 */
public class RealNodePitchBlackMitigationTest extends RealNodeTest {

	static final int NUMBER_OF_NODES = 100;
	static final int DEGREE = 10;
	static final short MAX_HTL = (short) 10;
	static final boolean START_WITH_IDEAL_LOCATIONS = true;
	static final boolean FORCE_NEIGHBOUR_CONNECTIONS = true;
	static final int MIN_PINGS = 420;
	static final int MAX_PINGS = 840;
	static final boolean ENABLE_SWAPPING = true;
	static final boolean ENABLE_SWAP_QUEUEING = true;
	static final boolean ENABLE_FOAF = true;
	static final boolean ACTIVE_PITCH_BLACK_ATTACK = false;
	static final boolean INITIAL_PITCH_BLACK_ATTACK = true;
	public static final long PITCH_BLACK_MITIGATION_STARTUP_DELAY = MINUTES.toMillis(1);
	public static final long PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY = MINUTES.toMillis(30);
	public static final int PINGS_PER_ITERATION = 10;

	public static int DARKNET_PORT_BASE = RealNodeRequestInsertTest.DARKNET_PORT_END;
	public static final int DARKNET_PORT_END = DARKNET_PORT_BASE + NUMBER_OF_NODES;
	public static final double PITCH_BLACK_ATTACK_JITTER = 0.001;
	public static final double PITCH_BLACK_ATTACK_MEAN_LOCATION = 0.5;
	public static final int BETWEEN_PING_SLEEP_TIME = 500000;

	public static void main(String[] args) throws Exception {
		System.out.println("Routing test using real nodes:");
		System.out.println();
		String dir = "realNodeRequestInsertTest";
		File wd = new File(dir);
		if (!FileUtil.removeAll(wd)) {
			System.err.println("Mass delete failed, test may not be accurate.");
			System.exit(EXIT_CANNOT_DELETE_OLD_DATA);
		}
		wd.mkdir();
		//NOTE: globalTestInit returns in ignored random source
		NodeStarter.globalTestInit(dir, false, LogLevel.ERROR, "", true);
		// Make the network reproducible so we can easily compare different routing options by specifying a seed.
		DummyRandomSource random = new DummyRandomSource(3142);
		//DiffieHellman.init(random);
		Node[] nodes = new Node[NUMBER_OF_NODES];
		Logger.normal(RealNodePitchBlackMitigationTest.class, "Creating nodes...");
		Executor executor = new PooledExecutor();
		for (int i = 0; i < NUMBER_OF_NODES; i++) {
			System.err.println("Creating node " + i);
			nodes[i] = NodeStarter.createTestNode(
					DARKNET_PORT_BASE + i,
					0,
					dir,
					true,
					MAX_HTL,
					0 /* no dropped packets */,
					random,
					executor,
					500 * NUMBER_OF_NODES,
					4000000, // 30 CHKs to avoid stray failures through overwriting
					true,
					ENABLE_SWAPPING,
					false,
					false,
					false,
					ENABLE_SWAP_QUEUEING,
					true,
					0,
					ENABLE_FOAF,
					false,
					true,
					false,
					null);
			Logger.normal(RealNodePitchBlackMitigationTest.class, "Created node " + i);
		}
		Logger.normal(RealNodePitchBlackMitigationTest.class, "Created " + NUMBER_OF_NODES + " nodes");
		// Now link them up
		makeKleinbergNetwork(
				nodes,
				START_WITH_IDEAL_LOCATIONS,
				DEGREE,
				FORCE_NEIGHBOUR_CONNECTIONS,
				random);

		Logger.normal(RealNodePitchBlackMitigationTest.class, "Added random links");

		// force a disrupted network
		if (INITIAL_PITCH_BLACK_ATTACK) {
			for (int i = 0; i < NUMBER_OF_NODES; i++) {
				Node nodeToAttack = nodes[i];
				attackSpecificNode(
						PITCH_BLACK_ATTACK_MEAN_LOCATION,
						PITCH_BLACK_ATTACK_JITTER,
						nodeToAttack,
						i);
			}
		}

		// enable warning logging to see pitch black defense lo
		Logger.globalSetThreshold(LogLevel.WARNING);

		// set the time to yesterday to have pitch black information
		nodes[0].lm.setClockForTesting(Clock.offset(Clock.systemDefaultZone(), Duration.ofDays(-1)));
		// shift forward one day per 5 minutes
		Runnable dayIncrementingJob = new Runnable() {
			@Override
			public void run() {
				nodes[0].ticker.queueTimedJob(
						this,
						PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY);
				nodes[0].lm.setClockForTesting(Clock.offset(
						nodes[0].lm.getClockForTesting(),
						Duration.ofDays(1)));
			}
		};
		nodes[0].ticker.queueTimedJob(
				dayIncrementingJob,
				PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY);

		// start the nodes and adjust mitigation times
		nodes[0].lm.PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY = PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY;
		nodes[0].lm.PITCH_BLACK_MITIGATION_STARTUP_DELAY = PITCH_BLACK_MITIGATION_STARTUP_DELAY;
		for (int i = 0; i < NUMBER_OF_NODES; i++) {
			System.err.println("Starting node " + i);
			nodes[i].start(false);
		}

		waitForAllConnected(nodes);

		// Make the choice of nodes to ping to and from deterministic too.
		// There is timing noise because of all the nodes, but the network
		// and the choice of nodes to start and finish are deterministic, so
		// the overall result should be more or less deterministic.
		waitForPingAverage(0.98, nodes, new DummyRandomSource(3143), MAX_PINGS, BETWEEN_PING_SLEEP_TIME);
		System.exit(0);
	}

	public static void attackSpecificNode(
			double pitchBlackAttackMeanLocation,
			double pitchBlackAttackJitter,
			Node nodeToAttack,
			int indexOfNode) {
		double pitchBlackFakeLocation = pitchBlackAttackMeanLocation
				+ (nodeToAttack.fastWeakRandom.nextDouble() * pitchBlackAttackJitter);
		System.err.println("Pitch-Black-Attack on node "
				+ indexOfNode
				+ " using mean "
				+ pitchBlackAttackMeanLocation
				+ " with jitter "
				+ pitchBlackAttackJitter
				+ ": "
				+ pitchBlackFakeLocation);
		nodeToAttack.setLocation(pitchBlackFakeLocation);
		System.err.println("New location of node " + indexOfNode + ": " + nodeToAttack.getLocation());
	}

	static void waitForPingAverage(
			double accuracy,
			Node[] nodes,
			RandomSource random,
			int maxTests,
			int sleepTime) throws InterruptedException {
		int totalHopsTaken = 0;
		int cycleNumber = 0;
		int lastSwaps = 0;
		int lastNoSwaps = 0;
		int failures = 0;
		int successes = 0;
		RunningAverage avg = new SimpleRunningAverage(100, 0.0);
		RunningAverage avg2 = new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 100, null);
		int pings = 0;
		for (int total = 0; total < maxTests; total++) {
			cycleNumber++;
			if (ACTIVE_PITCH_BLACK_ATTACK) {
				for (int i = 0; i < NUMBER_OF_NODES; i++) {
					Node nodeToAttack = nodes[i];
					// attack 2% of the nodes per round
					if (nodeToAttack.fastWeakRandom.nextFloat() < 0.98) {
						continue;
					}
					attackSpecificNode(
							PITCH_BLACK_ATTACK_MEAN_LOCATION,
							PITCH_BLACK_ATTACK_JITTER,
							nodeToAttack,
							i);
				}
		}
			try {
				Thread.sleep(sleepTime);
			} catch (InterruptedException e) {
				// Ignore
			}
			for (int i = 0; i < nodes.length; i++) {
				System.err.println("Cycle " + cycleNumber + " node " + i + ": " + nodes[i].getLocation() + " degree: " + nodes[i].getPeerNodes().length + " locs: " + Arrays
						.stream(nodes[i].getPeerNodes()).map(PeerNode::getLocation).collect(Collectors.summarizingDouble(d -> d)));
			}
			int newSwaps = LocationManager.swaps;
			int totalStarted = LocationManager.startedSwaps;
			int noSwaps = LocationManager.noSwaps;
			System.err.println("Swaps: " + (newSwaps - lastSwaps));
			System.err.println("\nTotal swaps: Started*2: "
					+ totalStarted * 2
					+ ", succeeded: "
					+ newSwaps
					+ ", last minute failures: "
					+ noSwaps
					+
					", ratio "
					+ (double) noSwaps / (double) newSwaps
					+ ", early failures: "
					+ ((totalStarted * 2) - (noSwaps + newSwaps)));
			System.err.println("This cycle ratio: " + ((double) (noSwaps - lastNoSwaps)) / ((double) (
					newSwaps
							- lastSwaps)));
			lastNoSwaps = noSwaps;
			System.err.println("Swaps rejected (already locked): "
					+ LocationManager.swapsRejectedAlreadyLocked);
			System.err.println("Swaps rejected (nowhere to go): "
					+ LocationManager.swapsRejectedNowhereToGo);
			System.err.println("Swaps rejected (rate limit): " + LocationManager.swapsRejectedRateLimit);
			System.err.println("Swaps rejected (recognized ID):"
					+ LocationManager.swapsRejectedRecognizedID);
			System.err.println("Swaps failed:" + LocationManager.noSwaps);
			System.err.println("Swaps succeeded:" + LocationManager.swaps);

			double totalSwapInterval = 0.0;
			double totalSwapTime = 0.0;
			for (int i = 0; i < nodes.length; i++) {
				totalSwapInterval += nodes[i].lm.getSendSwapInterval();
				totalSwapTime += nodes[i].lm.getAverageSwapTime();
			}
			System.err.println("Average swap time: " + (totalSwapTime / nodes.length));
			System.err.println("Average swap sender interval: " + (totalSwapInterval / nodes.length));

			waitForAllConnected(nodes);

			lastSwaps = newSwaps;
			// Do some (routed) test-pings
			for (int i = 0; i < PINGS_PER_ITERATION; i++) {
				try {
					Thread.sleep(sleepTime);
				} catch (InterruptedException e1) {
				}
				try {
					Node randomNode = nodes[random.nextInt(nodes.length)];
					Node randomNode2 = randomNode;
					while (randomNode2 == randomNode) {
						randomNode2 = nodes[random.nextInt(nodes.length)];
					}
					double loc2 = randomNode2.getLocation();
					Logger.normal(
							RealNodePitchBlackMitigationTest.class,
							"Pinging " + randomNode2.getDarknetPortNumber() + " @ " + loc2 + " from " + randomNode
									.getDarknetPortNumber() + " @ " + randomNode.getLocation());

					int hopsTaken = randomNode.routedPing(loc2, randomNode2.getDarknetPubKeyHash());
					pings++;
					if (hopsTaken < 0) {
						failures++;
						avg.report(0.0);
						avg2.report(0.0);
						double ratio = (double) successes / ((double) (failures + successes));
						System.err.println("Routed ping "
								+ pings
								+ " FAILED from "
								+ randomNode.getDarknetPortNumber()
								+ " to "
								+ randomNode2.getDarknetPortNumber()
								+ " (long:"
								+ ratio
								+ ", short:"
								+ avg.currentValue()
								+ ", vague:"
								+ avg2.currentValue()
								+ ')');
					} else {
						totalHopsTaken += hopsTaken;
						successes++;
						avg.report(1.0);
						avg2.report(1.0);
						double ratio = (double) successes / ((double) (failures + successes));
						System.err.println("Routed ping "
								+ pings
								+ " success: "
								+ hopsTaken
								+ ' '
								+ randomNode.getDarknetPortNumber()
								+ " to "
								+ randomNode2.getDarknetPortNumber()
								+ " (long:"
								+ ratio
								+ ", short:"
								+ avg.currentValue()
								+ ", vague:"
								+ avg2.currentValue()
								+ ')');
					}
				} catch (Throwable t) {
					Logger.error(RealNodePitchBlackMitigationTest.class, "Caught " + t, t);
				}
			}
			System.err.println("Average path length for successful requests: "
					+ ((double) totalHopsTaken) / successes);
			if (pings > MAX_PINGS || pings > MIN_PINGS && avg.currentValue() > accuracy && ((double) successes / ((double) (failures
					+ successes)) > accuracy)) {
				System.err.println();
				System.err.println("Reached " + (accuracy * 100) + "% accuracy.");
				System.err.println();
				System.err.println("Network size: " + nodes.length);
				System.err.println("Maximum HTL: " + MAX_HTL);
				System.err.println("Average path length for successful requests: "
						+ totalHopsTaken / successes);
				System.err.println("Total started swaps: " + LocationManager.startedSwaps);
				System.err.println("Total rejected swaps (already locked): "
						+ LocationManager.swapsRejectedAlreadyLocked);
				System.err.println("Total swaps rejected (nowhere to go): "
						+ LocationManager.swapsRejectedNowhereToGo);
				System.err.println("Total swaps rejected (rate limit): "
						+ LocationManager.swapsRejectedRateLimit);
				System.err.println("Total swaps rejected (recognized ID):"
						+ LocationManager.swapsRejectedRecognizedID);
				System.err.println("Total swaps failed:" + LocationManager.noSwaps);
				System.err.println("Total swaps succeeded:" + LocationManager.swaps);
				return;
			}
		}
		System.exit(EXIT_PING_TARGET_NOT_REACHED);
	}
}
