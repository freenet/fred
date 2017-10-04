package freenet.node.simulator;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TimeZone;
import java.util.TreeMap;

import freenet.client.ClientMetadata;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.HighLevelSimpleClient;
import freenet.client.InsertBlock;
import freenet.client.InsertException;
import freenet.client.async.ClientContext;
import freenet.client.events.ClientEvent;
import freenet.client.events.ClientEventListener;
import freenet.crypt.RandomSource;
import freenet.keys.FreenetURI;
import freenet.node.Node;
import freenet.node.NodeStarter;
import freenet.node.Version;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.PooledExecutor;
import freenet.support.api.RandomAccessBucket;
import freenet.support.io.FileUtil;

/**
 * Push / Pull test over long period of time
 * 
 * <p>
 * This class push a series of keys in the format of
 * <code>KSK@&lt;unique identifier&gt;-DATE-n</code>. It will then try to pull them after (2^n - 1)
 * days.
 * <p>
 * The result is recorded as a CSV file in the format of:
 * 
 * <pre>
 * 	DATE, VERSION, SEED-TIME-1, PUSH-TIME-#0, ... , PUSH-TIME-#N, SEED-TIME-2, PULL-TIME-#0, ... , PULL-TIME-#N
 * </pre>
 * 
 * @author sdiz
 */
public class LongTermPushPullTest extends LongTermTest {
	private static final int TEST_SIZE = 64 * 1024;

	private static final int EXIT_NO_SEEDNODES = 257;
	private static final int EXIT_FAILED_TARGET = 258;
	private static final int EXIT_THREW_SOMETHING = 261;

	private static final int DARKNET_PORT1 = 5010;
	private static final int OPENNET_PORT1 = 5011;
	private static final int DARKNET_PORT2 = 5012;
	private static final int OPENNET_PORT2 = 5013;

	private static final int MAX_N = 8;

	public static void main(String[] args) {
		if (args.length < 0 || args.length > 2) {
			System.err.println("Usage: java freenet.node.simulator.LongTermPushPullTest <unique identifier>");
			System.exit(1);
		}
		String uid = args[0];
		
		if(args.length == 2 && (args[1].equalsIgnoreCase("--dump") || args[1].equalsIgnoreCase("-dump") || args[1].equalsIgnoreCase("dump"))) {
			try {
				dumpStats(uid);
			} catch (IOException e) {
				System.err.println("IO ERROR: "+e);
				e.printStackTrace();
				System.exit(1);
			} catch (ParseException e) {
				System.err.println("PARSE ERROR: "+e);
				e.printStackTrace();
				System.exit(2);
			}
			System.exit(0);
		}

		List<String> csvLine = new ArrayList<String>(3 + 2 * MAX_N);
		System.out.println("DATE:" + dateFormat.format(today.getTime()));
		csvLine.add(dateFormat.format(today.getTime()));

		System.out.println("Version:" + Version.buildNumber());
		csvLine.add(String.valueOf(Version.buildNumber()));

		int exitCode = 0;
		Node node = null;
		Node node2 = null;
		try {
			final File dir = new File("longterm-push-pull-test-" + uid);
			FileUtil.removeAll(dir);
			RandomSource random = NodeStarter.globalTestInit(dir.getPath(), false, LogLevel.ERROR, "", false);
			File seednodes = new File("seednodes.fref");
			if (!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
				System.err.println("Unable to read seednodes.fref, it doesn't exist, or is empty");
				System.exit(EXIT_NO_SEEDNODES);
			}

			final File innerDir = new File(dir, Integer.toString(DARKNET_PORT1));
			innerDir.mkdir();
			FileInputStream fis = new FileInputStream(seednodes);
			FileUtil.writeTo(fis, new File(innerDir, "seednodes.fref"));
			fis.close();

			// Create one node
			node = NodeStarter.createTestNode(DARKNET_PORT1, OPENNET_PORT1, dir.getPath(), false, Node.DEFAULT_MAX_HTL,
			        0, random, new PooledExecutor(), 1000, 4 * 1024 * 1024, true, true, true, true, true, true, true,
			        12 * 1024, true, true, false, false, null);
			Logger.getChain().setThreshold(LogLevel.ERROR);

			// Start it
			node.start();
			long t1 = System.currentTimeMillis();
			if (!TestUtil.waitForNodes(node)) {
				exitCode = EXIT_FAILED_TARGET;
				return;
			}
				
			long t2 = System.currentTimeMillis();
			System.out.println("SEED-TIME:" + (t2 - t1));
			csvLine.add(String.valueOf(t2 - t1));

			// PUSH N+1 BLOCKS
			for (int i = 0; i <= MAX_N; i++) {
			    RandomAccessBucket data = randomData(node);
				HighLevelSimpleClient client = node.clientCore.makeClient((short) 0, false);
				FreenetURI uri = new FreenetURI("KSK@" + uid + "-" + dateFormat.format(today.getTime()) + "-" + i);
				System.out.println("PUSHING " + uri);
				client.addEventHook(new ClientEventListener() {

					@Override
					public void receive(ClientEvent ce, ClientContext context) {
						System.out.println(ce.getDescription());
					}
					
				});

				try {
					InsertBlock block = new InsertBlock(data, new ClientMetadata(), uri);
					t1 = System.currentTimeMillis();
					client.insert(block, false, null);
					t2 = System.currentTimeMillis();

					System.out.println("PUSH-TIME-" + i + ":" + (t2 - t1));
					csvLine.add(String.valueOf(t2 - t1));
				} catch (InsertException e) {
					e.printStackTrace();
					csvLine.add("N/A");
				}

				data.free();
			}

			node.park();

			// Node 2
			File innerDir2 = new File(dir, Integer.toString(DARKNET_PORT2));
			innerDir2.mkdir();
			fis = new FileInputStream(seednodes);
			FileUtil.writeTo(fis, new File(innerDir2, "seednodes.fref"));
			fis.close();
			node2 = NodeStarter.createTestNode(DARKNET_PORT2, OPENNET_PORT2, dir.getPath(), false,
			        Node.DEFAULT_MAX_HTL, 0, random, new PooledExecutor(), 1000, 5 * 1024 * 1024, true, true, true,
			        true, true, true, true, 12 * 1024, false, true, false, false, null);
			node2.start();

			t1 = System.currentTimeMillis();
			if (!TestUtil.waitForNodes(node2)) {
				exitCode = EXIT_FAILED_TARGET;
				return;
			}
			t2 = System.currentTimeMillis();
			System.out.println("SEED-TIME:" + (t2 - t1));
			csvLine.add(String.valueOf(t2 - t1));

			// PULL N+1 BLOCKS
			for (int i = 0; i <= MAX_N; i++) {
				HighLevelSimpleClient client = node2.clientCore.makeClient((short) 0, false);
				Calendar targetDate = (Calendar) today.clone();
				targetDate.add(Calendar.DAY_OF_MONTH, -((1 << i) - 1));

				FreenetURI uri = new FreenetURI("KSK@" + uid + "-" + dateFormat.format(targetDate.getTime()) + "-" + i);
				System.out.println("PULLING " + uri);

				try {
					t1 = System.currentTimeMillis();
					client.fetch(uri);
					t2 = System.currentTimeMillis();

					System.out.println("PULL-TIME-" + i + ":" + (t2 - t1));
					csvLine.add(String.valueOf(t2 - t1));
				} catch (FetchException e) {
					if (e.getMode() != FetchExceptionMode.ALL_DATA_NOT_FOUND
					        && e.getMode() != FetchExceptionMode.DATA_NOT_FOUND)
						e.printStackTrace();
					csvLine.add(FetchException.getShortMessage(e.getMode()));
				}
			}
		} catch (Throwable t) {
			t.printStackTrace();
			exitCode = EXIT_THREW_SOMETHING;
		} finally {
			try {
				if (node != null)
					node.park();
			} catch (Throwable t1) {
			}
			try {
				if (node2 != null)
					node2.park();
			} catch (Throwable t1) {
			}

			File file = new File(uid + ".csv");
			writeToStatusLog(file, csvLine);
			System.exit(exitCode);
		}
	}

	private static void dumpStats(String uid) throws IOException, ParseException {
		File file = new File(uid + ".csv");
		FileInputStream fis = new FileInputStream(file);
		BufferedReader br = new BufferedReader(new InputStreamReader(fis, ENCODING));
		String line = null;
		Calendar prevDate = null;
		TreeMap<GregorianCalendar,DumpElement> map = new TreeMap<GregorianCalendar,DumpElement>();
		while((line = br.readLine()) != null) {
			DumpElement element;
			//System.out.println("LINE: "+line);
			String[] split = line.split(",");
			Date date = dateFormat.parse(split[0]);
			GregorianCalendar calendar = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
			calendar.setTime(date);
			System.out.println("Date: "+dateFormat.format(calendar.getTime()));
			if(prevDate != null) {
				long now = calendar.getTimeInMillis();
				long prev = prevDate.getTimeInMillis();
				long dist = DAYS.convert(now - prev, MILLISECONDS);
				if(dist != 1) System.out.println(""+dist+" days since last report");
			}
			prevDate = calendar;
			int version = Integer.parseInt(split[1]);
			if(split.length > 2) {
				int[] pushTimes = new int[MAX_N+1];
				String[] pushFailures = new String[MAX_N+1];
				for(int i=0;i<=MAX_N;i++) {
					String s = split[3+i];
					try {
						pushTimes[i] = Integer.parseInt(s);
					} catch (NumberFormatException e) {
						pushFailures[i] = s;
					}
				}
				if(split.length > 3 + MAX_N+1) {
					int[] pullTimes = new int[MAX_N+1];
					String[] pullFailures = new String[MAX_N+1];
					for(int i=0;i<=MAX_N;i++) {
						String s = split[3+MAX_N+2+i];
						try {
							pullTimes[i] = Integer.parseInt(s);
						} catch (NumberFormatException e) {
							pullFailures[i] = s;
						}
					}
					element = new DumpElement(calendar, version, pushTimes, pushFailures, pullTimes, pullFailures);
				} else {
					element = new DumpElement(calendar, version, pushTimes, pushFailures);
				}
			} else {
				element = new DumpElement(calendar, version);
			}
			calendar.set(Calendar.MILLISECOND, 0);
			calendar.set(Calendar.SECOND, 0);
			calendar.set(Calendar.MINUTE, 0);
			calendar.set(Calendar.HOUR_OF_DAY, 0);
			map.put(calendar, element);
		}
		fis.close();
		for(int i=0;i<=MAX_N;i++) {
			int delta = ((1<<i)-1);
			System.out.println("Checking delta: "+delta+" days");
			int failures = 0;
			int successes = 0;
			long successTime = 0;
			int noMatch = 0;
			int insertFailure = 0;
			Map<String,Integer> failureModes = new HashMap<String,Integer>();
			for(Entry<GregorianCalendar,DumpElement> entry : map.entrySet()) {
				GregorianCalendar date = entry.getKey();
				DumpElement element = entry.getValue();
				if(element.pullTimes != null) {
					date = (GregorianCalendar) date.clone();
					date.add(Calendar.DAY_OF_MONTH, -delta);
					System.out.println("Checking "+date.getTime()+" for "+element.date.getTime()+" delta "+delta);
					DumpElement inserted = map.get(date);
					if(inserted == null) {
						System.out.println("No match");
						noMatch++;
						continue;
					}
					if(inserted.pushTimes == null || inserted.pushTimes[i] == 0) {
						System.out.println("Insert failure");
						if(element.pullTimes[i] != 0) {
							System.err.println("Fetched it anyway??!?!?: time "+element.pullTimes[i]);
						}
						insertFailure++;
					}
					if(element.pullTimes[i] == 0) {
						String failureMode = element.pullFailures[i];
						Integer count = failureModes.get(failureMode);
						if(count == null)
							failureModes.put(failureMode, 1);
						else
							failureModes.put(failureMode, count+1);
						failures++;
					} else {
						successes++;
						successTime += element.pullTimes[i];
					}
				}
			}
			System.out.println("Successes: "+successes);
			if(successes != 0) System.out.println("Average success time "+(successTime / successes));
			System.out.println("Failures: "+failures);
			for(Map.Entry<String,Integer> entry : failureModes.entrySet())
				System.out.println(entry.getKey()+" : "+entry.getValue());
			System.out.println("No match: "+noMatch);
			System.out.println("Insert failure: "+insertFailure);
			double psuccess = (successes*1.0 / (1.0*(successes + failures)));
			System.out.println("Success rate for "+delta+" days: "+psuccess+" ("+(successes+failures)+" samples)");
			if(delta != 0) {
				double halfLifeEstimate = -1*Math.log(2)/(Math.log(psuccess)/delta);
				System.out.println("Half-life estimate: "+halfLifeEstimate+" days");
			}
			System.out.println();
		}
	}
	
	static class DumpElement {
		public DumpElement(GregorianCalendar date, int version) {
			this.date = date;
			this.version = version;
			this.seedTime = -1;
			this.pushTimes = null;
			this.pushFailures = null;
			this.pullTimes = null;
			this.pullFailures = null;
		}
		public DumpElement(GregorianCalendar date, int version, int[] pushTimes, String[] pushFailures) {
			this.date = date;
			this.version = version;
			this.seedTime = -1;
			this.pushTimes = pushTimes;
			this.pushFailures = pushFailures;
			this.pullTimes = null;
			this.pullFailures = null;
		}
		public DumpElement(GregorianCalendar date, int version, int[] pushTimes, String[] pushFailures, int[] pullTimes, String[] pullFailures) {
			this.date = date;
			this.version = version;
			this.seedTime = -1;
			this.pushTimes = pushTimes;
			this.pushFailures = pushFailures;
			this.pullTimes = pullTimes;
			this.pullFailures = pullFailures;
		}
		final GregorianCalendar date;
		final int version;
		final long seedTime;
		final int[] pushTimes; // 0 = failure, look up in pushFailures
		final String[] pushFailures;
		final int[] pullTimes;
		final String[] pullFailures;
	}
	

	private static RandomAccessBucket randomData(Node node) throws IOException {
	    RandomAccessBucket data = node.clientCore.tempBucketFactory.makeBucket(TEST_SIZE);
		OutputStream os = data.getOutputStream();
		try {
		byte[] buf = new byte[4096];
		for (long written = 0; written < TEST_SIZE;) {
			node.fastWeakRandom.nextBytes(buf);
			int toWrite = (int) Math.min(TEST_SIZE - written, buf.length);
			os.write(buf, 0, toWrite);
			written += toWrite;
		}
		} finally {
		os.close();
		}
		return data;
	}
}
