package freenet.node.simulator;

import static java.util.concurrent.TimeUnit.HOURS;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;

import freenet.client.ClientMetadata;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.FetchWaiter;
import freenet.client.HighLevelSimpleClient;
import freenet.client.InsertBlock;
import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.crypt.RandomSource;
import freenet.keys.FreenetURI;
import freenet.node.Node;
import freenet.node.NodeStarter;
import freenet.node.RequestClient;
import freenet.node.RequestClientBuilder;
import freenet.node.Version;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.PooledExecutor;
import freenet.support.api.RandomAccessBucket;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;

/** 
 * Insert 32x single blocks. Pull them individually, with 0 retries, after 2^n-1 
 * days, for n in 0...8.
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class LongTermManySingleBlocksTest extends LongTermTest {
	
	public static class InsertBatch {

		private final HighLevelSimpleClient client;
		private int runningInserts;
		private ArrayList<BatchInsert> inserts = new ArrayList<BatchInsert>();
		
		public InsertBatch(HighLevelSimpleClient client) {
			this.client = client;
			// TODO Auto-generated constructor stub
		}

		public void startInsert(InsertBlock block) {
			BatchInsert bi = new BatchInsert(block);
			synchronized(this) {
				inserts.add(bi);
			}
			bi.start();
		}
		
		class BatchInsert implements Runnable {

			private final InsertBlock block;
			//private boolean finished = false;
			//private boolean started = false;
			private long insertTime;
			private InsertException failed;
			private FreenetURI uri;
			
			public BatchInsert(InsertBlock block) {
				this.block = block;
			}

			public void start() {
				Thread t = new Thread(this);
				t.setDaemon(true);
				t.start();
			}

			@Override
			public void run() {
				synchronized(InsertBatch.this) {
					runningInserts++;
					//started = true;
					System.out.println("Starting insert: running "+runningInserts);
				}
				long t1 = 0, t2 = 0;
				FreenetURI thisURI = null;
				InsertException f = null;
				try {
					t1 = System.currentTimeMillis();
					thisURI = client.insert(block, false, null);
					t2 = System.currentTimeMillis();
				} catch (InsertException e) {
					f = e;
				} finally {
					synchronized(InsertBatch.this) {
						runningInserts--;
						System.out.println("Completed insert: running "+runningInserts);
						//finished = true;
						if(thisURI != null) {
							uri = thisURI;
							insertTime = t2 - t1;
						} else {
							if(f != null)
								failed = f;
							else
								f = new InsertException(InsertExceptionMode.INTERNAL_ERROR);
						}
							
						InsertBatch.this.notifyAll();
					}
				}
			}
			
		}

		public synchronized void waitUntilFinished() {
			while(true) {
				if(runningInserts == 0) return;
				try {
					wait();
				} catch (InterruptedException e) {
					// Ignore
				}
			}
		}

		public synchronized FreenetURI[] getURIs() {
			FreenetURI[] uris = new FreenetURI[inserts.size()];
			for(int i=0;i<uris.length;i++)
				uris[i] = inserts.get(i).uri;
			return uris;
		}

		public synchronized long[] getTimes() {
			long[] times = new long[inserts.size()];
			for(int i=0;i<times.length;i++)
				times[i] = inserts.get(i).insertTime;
			return times;
		}

		public InsertException[] getErrors() {
			InsertException[] errors = new InsertException[inserts.size()];
			for(int i=0;i<errors.length;i++)
				errors[i] = inserts.get(i).failed;
			return errors;
		}

	}

	private static final int TEST_SIZE = 32 * 1024;

	private static final int DARKNET_PORT1 = 9010;
	private static final int OPENNET_PORT1 = 9011;
	
	private static final int MAX_N = 8;
	
	private static final int INSERTED_BLOCKS = 32;

	public static void main(String[] args) {
		if (args.length < 1 || args.length > 2) {
			System.err.println("Usage: java freenet.node.simulator.LongTermPushPullTest <unique identifier>");
			System.exit(1);
		}
		String uid = args[0];
		
		List<String> csvLine = new ArrayList<String>();
		System.out.println("DATE:" + dateFormat.format(today.getTime()));
		csvLine.add(dateFormat.format(today.getTime()));

		System.out.println("Version:" + Version.buildNumber());
		csvLine.add(String.valueOf(Version.buildNumber()));

		int exitCode = 0;
		Node node = null;
		Node node2 = null;
		FileInputStream fis = null;
		File file = new File("many-single-blocks-test-"+uid + ".csv");
		long t1, t2;
		
		try {
			
			// INSERT STUFF
			
			final File dir = new File("longterm-mhk-test-" + uid);
			FileUtil.removeAll(dir);
			RandomSource random = NodeStarter.globalTestInit(dir.getPath(), false, LogLevel.ERROR, "", false);
			File seednodes = new File("seednodes.fref");
			if (!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
				System.err.println("Unable to read seednodes.fref, it doesn't exist, or is empty");
				System.exit(EXIT_NO_SEEDNODES);
			}

			final File innerDir = new File(dir, Integer.toString(DARKNET_PORT1));
			innerDir.mkdir();
			fis = new FileInputStream(seednodes);
			FileUtil.writeTo(fis, new File(innerDir, "seednodes.fref"));
			fis.close();

			// Create one node
			node = NodeStarter.createTestNode(DARKNET_PORT1, OPENNET_PORT1, dir.getPath(), false, Node.DEFAULT_MAX_HTL,
			        0, random, new PooledExecutor(), 1000, 4 * 1024 * 1024, true, true, true, true, true, true, true,
			        12 * 1024, true, true, false, false, null);
			Logger.getChain().setThreshold(LogLevel.ERROR);

			// Start it
			node.start();
			t1 = System.currentTimeMillis();
			if (!TestUtil.waitForNodes(node)) {
				exitCode = EXIT_FAILED_TARGET;
				return;
			}
				
			t2 = System.currentTimeMillis();
			System.out.println("SEED-TIME:" + (t2 - t1));
			csvLine.add(String.valueOf(t2 - t1));

			HighLevelSimpleClient client = node.clientCore.makeClient((short) 0, false);

			int successes = 0;
			
			long startInsertsTime = System.currentTimeMillis();
			
			InsertBatch batch = new InsertBatch(client);
			
			// Inserts are sloooooow so do them in parallel.
			
			for(int i=0;i<INSERTED_BLOCKS;i++) {
				
				System.err.println("Inserting block "+i);
				
				RandomAccessBucket single = randomData(node);
				
				InsertBlock block = new InsertBlock(single, new ClientMetadata(), FreenetURI.EMPTY_CHK_URI);
				
				batch.startInsert(block);
				
			}
			
			batch.waitUntilFinished();
			FreenetURI[] uris = batch.getURIs();
			long[] times = batch.getTimes();
			InsertException[] errors = batch.getErrors();
			
			for(int i=0;i<INSERTED_BLOCKS;i++) {
				if(uris[i] != null) {
					csvLine.add(String.valueOf(times[i]));
					csvLine.add(uris[i].toASCIIString());
					System.out.println("Pushed block "+i+" : "+uris[i]+" in "+times[i]);
					successes++;
				} else {
					csvLine.add(InsertException.getShortMessage(errors[i].getMode()));
					csvLine.add("N/A");
					System.out.println("Failed to push block "+i+" : "+errors[i]);
				}
			}
			
			long endInsertsTime = System.currentTimeMillis();
			
			System.err.println("Succeeded inserts: "+successes+" of "+INSERTED_BLOCKS+" in "+(endInsertsTime-startInsertsTime)+"ms");
			
			FetchContext fctx = client.getFetchContext();
			fctx.maxNonSplitfileRetries = 0;
			fctx.maxSplitfileBlockRetries = 0;
			RequestClient requestContext = new RequestClientBuilder().build();

			// PARSE FILE AND FETCH OLD STUFF IF APPROPRIATE
			
			FreenetURI[] mhkURIs = new FreenetURI[3];
			fis = new FileInputStream(file);
			BufferedReader br = new BufferedReader(new InputStreamReader(fis, ENCODING));
			String line = null;
			GregorianCalendar target = (GregorianCalendar) today.clone();
			target.set(Calendar.HOUR_OF_DAY, 0);
			target.set(Calendar.MINUTE, 0);
			target.set(Calendar.MILLISECOND, 0);
			target.set(Calendar.SECOND, 0);
			GregorianCalendar[] targets = new GregorianCalendar[MAX_N+1];
			for(int i=0;i<targets.length;i++) {
				targets[i] = ((GregorianCalendar)target.clone());
				targets[i].add(Calendar.DAY_OF_MONTH, -((1<<i)-1));
				targets[i].getTime();
			}
			int[] totalFetchesByDelta = new int[MAX_N+1];
			int[] totalSuccessfulFetchesByDelta = new int[MAX_N+1];
			long[] totalFetchTimeByDelta = new long[MAX_N+1];
			
loopOverLines:
			while((line = br.readLine()) != null) {
				
				for(int i=0;i<mhkURIs.length;i++) mhkURIs[i] = null;
				//System.out.println("LINE: "+line);
				String[] split = line.split("!");
				Date date = dateFormat.parse(split[0]);
				GregorianCalendar calendar = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
				calendar.setTime(date);
				System.out.println("Date: "+dateFormat.format(calendar.getTime()));
				calendar.set(Calendar.HOUR_OF_DAY, 0);
				calendar.set(Calendar.MINUTE, 0);
				calendar.set(Calendar.MILLISECOND, 0);
				calendar.set(Calendar.SECOND, 0);
				calendar.getTime();
				FreenetURI[] insertedURIs = new FreenetURI[INSERTED_BLOCKS];
				int[] insertTimes = new int[INSERTED_BLOCKS];
				if(split.length < 3) continue;
				int seedTime = Integer.parseInt(split[2]);
				System.out.println("Seed time: "+seedTime);
				if(split.length < 4) continue;
				
				int token = 3;
				
				if(split.length < token + INSERTED_BLOCKS * 2) continue;
			
				for(int i=0;i<INSERTED_BLOCKS;i++) {
					try {
						insertTimes[i] = Integer.parseInt(split[token]);
					} catch (NumberFormatException e) {
						insertTimes[i] = -1;
					}
					token++;
					try {
						insertedURIs[i] = new FreenetURI(split[token]);
					} catch (MalformedURLException e) {
						insertedURIs[i] = null;
					}
					token++;
					System.out.println("Key insert "+i+" : "+insertedURIs[i]+" in "+insertTimes[i]);
				}
				for(int i=0;i<targets.length;i++) {
					if(Math.abs(targets[i].getTimeInMillis() - calendar.getTimeInMillis()) < HOURS.toMillis(12)) {
						System.out.println("Found row for target date "+((1<<i)-1)+" days ago.");
						System.out.println("Version: "+split[1]);
						csvLine.add(Integer.toString(i));
						int pulled = 0;
						int inserted = 0;
						for(int j=0;j<INSERTED_BLOCKS;j++) {
							if(insertedURIs[j] == null) {
								csvLine.add("INSERT FAILED");
								continue;
							}
							inserted++;
							try {
								t1 = System.currentTimeMillis();
								FetchWaiter fw = new FetchWaiter(requestContext);
								client.fetch(insertedURIs[j], 32768, fw, fctx);
								fw.waitForCompletion();
								t2 = System.currentTimeMillis();
								
								System.out.println("PULL-TIME FOR BLOCK "+j+": " + (t2 - t1));
								csvLine.add(String.valueOf(t2 - t1));
								pulled++;
							} catch (FetchException e) {
								if (e.getMode() != FetchExceptionMode.ALL_DATA_NOT_FOUND
										&& e.getMode() != FetchExceptionMode.DATA_NOT_FOUND)
									e.printStackTrace();
								csvLine.add(FetchException.getShortMessage(e.getMode()));
								System.err.println("FAILED PULL FOR BLOCK "+j+": "+e);
							}
						}
						System.out.println("Pulled "+pulled+" blocks of "+inserted+" from "+((1<<i)-1)+" days ago.");
					}
				}
				
				while(split.length > token + INSERTED_BLOCKS) {
					int delta;
					try {
						delta = Integer.parseInt(split[token]);
					} catch (NumberFormatException e) {
						System.err.println("Unable to parse token "+token+" = \""+token+"\"");
						System.err.println("This is supposed to be a delta");
						System.err.println("Skipping the rest of the line for date "+dateFormat.format(calendar.getTime()));
						continue loopOverLines;
					}
					System.out.println("Delta: "+((1<<delta)-1)+" days");
					token++;
					int totalFetchTime = 0;
					int totalSuccesses = 0;
					int totalFetches = 0;
					for(int i=0;i<INSERTED_BLOCKS;i++) {
						if(split[token].equals(""))
							continue;
						int mhkFetchTime = -1;
						totalFetches++;
						try {
							mhkFetchTime = Integer.parseInt(split[token]);
							System.out.println("Fetched block #"+i+" on "+date+" in "+mhkFetchTime+"ms");
							totalSuccesses++;
							totalFetchTime += mhkFetchTime;
						} catch (NumberFormatException e) {
							System.out.println("Failed block #"+i+" on "+date+" : "+split[token]);
						}
						token++;
					}
					totalFetchesByDelta[delta] += totalFetches;
					totalSuccessfulFetchesByDelta[delta] += totalSuccesses;
					totalFetchTimeByDelta[delta] += totalFetchTime;
					System.err.println("Succeeded: "+totalSuccesses+" of "+totalFetches+" average "+((double)totalFetchTime)/((double)totalSuccesses)+"ms for delta "+delta+" on "+dateFormat.format(date));
				}
			}
			
			System.out.println();
			System.out.println();
			
			for(int i=0;i<MAX_N+1;i++) {
				System.out.println("DELTA: "+i+" days: Total fetches: "+totalFetchesByDelta[i]+" total successes "+totalSuccessfulFetchesByDelta[i]+" = "+((totalSuccessfulFetchesByDelta[i]*100.0)/totalFetchesByDelta[i])+"% in "+(totalFetchTimeByDelta[i]*1.0)/totalSuccessfulFetchesByDelta[i]+"ms");
			}
			
			fis.close();
			fis = null;
			
		} catch (Throwable t) {
			t.printStackTrace();
			exitCode = EXIT_THREW_SOMETHING;
		} finally {
			try {
				if (node != null)
					node.park();
			} catch (Throwable tt) {
			}
			try {
				if (node2 != null)
					node2.park();
			} catch (Throwable tt) {
			}
			Closer.close(fis);
			writeToStatusLog(file, csvLine);

			System.out.println("Exiting with status "+exitCode);
			System.exit(exitCode);
		}
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
