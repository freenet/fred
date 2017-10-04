package freenet.client.async;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Random;

import freenet.support.math.MersenneTwister;

import freenet.keys.Key;
import freenet.keys.KeyBlock;
import freenet.keys.NodeSSK;
import freenet.node.LowLevelGetException;
import freenet.node.Node;
import freenet.node.PrioRunnable;
import freenet.node.RequestStarter;
import freenet.node.SendableGet;
import freenet.support.Executor;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.io.NativeThread;

/**
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class DatastoreChecker implements PrioRunnable {

    /** True to start the DatastoreChecker thread lazily (mostly for simulations). */
    private final boolean lazy;
    /** True if lazy is true and the datastore checker thread is running */
    private boolean running;
    private final Executor executor;
    private final String threadName;
    
	// Setting these to 1, 3 kills 1/3rd of datastore checks.
	// 2, 5 gives 40% etc.
	// In normal operation KILL_BLOCKS should be 0 !!!!
	static final int KILL_BLOCKS = 0;
	static final int RESET_COUNTER = 100;
	
	private static volatile boolean logMINOR;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {

			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	private static class QueueItem {
		/** Request which we will call finishRegister() for when we have
		 *  checked the keys lists. Deactivated (if persistent). */
		final SendableGet getter;
        /** Arrays of keys to check. */
        Key[] keys;
        final BlockSet blockSet;
		QueueItem(Key[] keys, SendableGet getter, BlockSet blockSet) {
			this.getter = getter;
            this.keys = keys;
            this.blockSet = blockSet;
		}

		@Override
		public boolean equals(Object o) {
		    // Hack to make queue.remove() work, see removeRequest() below.
			if(!(o instanceof QueueItem)) return false; // equals() should not throw ClassCastException
			return this.getter == ((QueueItem)o).getter;
		}

		@Override
		public int hashCode() {
			if (getter == null) {
				return 0;
			}
			return getter.hashCode();
		}
	}

	/** List of requests to check the datastore for. */
	private final ArrayDeque<QueueItem>[] queue;

	private ClientContext context;
	private final Node node;

	public synchronized void setContext(ClientContext context) {
		this.context = context;
	}

	@SuppressWarnings("unchecked")
    public DatastoreChecker(Node node, boolean lazyStart, Executor executor, String threadName) {
		this.node = node;
		this.lazy = lazyStart;
		this.executor = executor;
		this.threadName = threadName;
		int priorities = RequestStarter.NUMBER_OF_PRIORITY_CLASSES;
		queue = (ArrayDeque<QueueItem>[])new ArrayDeque<?>[priorities];
		for(int i=0;i<priorities;i++)
			queue[i] = new ArrayDeque<QueueItem>();
	}

	public void queueRequest(SendableGet getter, BlockSet blocks) {
		Key[] checkKeys = getter.listKeys();
		short prio = getter.getPriorityClass();
		if(logMINOR) Logger.minor(this, "Queueing transient request "+getter+" priority "+prio+" keys "+checkKeys.length);
		// FIXME check using store.probablyInStore
		ArrayList<Key> finalKeysToCheck = new ArrayList<Key>(checkKeys.length);
		synchronized(this) {
			for(Key key : checkKeys) {
				finalKeysToCheck.add(key);
			}
			QueueItem queueItem = new QueueItem(
					finalKeysToCheck.toArray(new Key[finalKeysToCheck.size()]),
					getter, blocks);
			if(logMINOR && queue[prio].contains(queueItem)) {
				Logger.error(this, "Transient request "+getter+" is already queued!");
				return;
			}
			queue[prio].add(queueItem);
			wakeUp();
		}
	}

	@Override
	public void run() {
		while(true) {
			try {
				if(realRun()) return; // Lazy termination.
			} catch (Throwable t) {
				Logger.error(this, "Caught "+t+" in datastore checker thread", t);
			}
		}
	}

	/** Process a single job, waiting if necessary.
	 * @return True if lazy=true and there are no jobs to run.
	 */
	private boolean realRun() {
		Random random;
		if(KILL_BLOCKS != 0)
			random = new MersenneTwister();
		else
			random = null;
		Key[] keys = null;
		SendableGet getter = null;
		ClientRequestScheduler sched = null;
		BlockSet blocks = null;
		boolean waited = false;
		synchronized(this) {
			while(true) {
				for(short prio = 0;prio<queue.length;prio++) {
				    QueueItem trans;
					if((trans = queue[prio].pollFirst()) != null) {
						keys = trans.keys;
						getter = trans.getter;
						// sched assigned out of loop
						blocks = trans.blockSet;
						if(logMINOR)
							Logger.minor(this, "Checking transient request "+getter+" prio "+prio+" of "+queue[prio].size());
						break;
					}
				}
				if(keys != null)
					break;
				if(logMINOR) Logger.minor(this, "Waiting for more transient requests");
				if(lazy) {
				    running = false;
				    return true;
				}
				waited = true;
				try {
					// Wait for anything.
					wait(SECONDS.toMillis(100));
				} catch (InterruptedException e) {
					// Ok
				}
			}
		}
		sched = getter.getScheduler(context);
		boolean anyValid = false;
		for(Key key : keys) {
			if(random != null) {
				if(random.nextInt(RESET_COUNTER) < KILL_BLOCKS) {
					anyValid = true;
					continue;
				}
			}
			KeyBlock block;
			if(blocks != null)
				block = blocks.get(key);
			else
				block = node.fetch(key, true, true, false, false, null);
			if(block != null) {
				if(logMINOR) Logger.minor(this, "Found key");
				if(key instanceof NodeSSK)
					sched.tripPendingKey(block);
				else // CHK
					sched.tripPendingKey(block);
			} else {
				anyValid = true;
			}
//			synchronized(this) {
//				keysToCheck[priority].remove(key);
//			}
		}
		if(logMINOR) Logger.minor(this, "Checked "+keys.length+" keys");
		if(getter.persistent()) {
			final SendableGet get = getter;
			final ClientRequestScheduler scheduler = sched;
			final boolean valid = anyValid;
			try {
				context.jobRunner.queue(new PersistentJob() {

					@Override
					public boolean run(ClientContext context) {
						try {
							scheduler.finishRegister(new SendableGet[] { get }, true, valid);
						} catch (Throwable t) {
							Logger.error(this, "Failed to register "+get+": "+t, t);
							try {
								get.onFailure(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR, "Internal error: "+t, t), null, context);
							} catch (Throwable t1) {
								Logger.error(this, "Failed to fail: "+t, t);
							}
						}
						return false;
					}
					
					@Override
					public String toString() {
						return "DatastoreCheckerFinishRegister";
					}

				}, NativeThread.NORM_PRIORITY);
			} catch (PersistenceDisabledException e) {
				// Impossible
			}
		} else {
			sched.finishRegister(new SendableGet[] { getter }, false, anyValid);
		}
		return false;
	}

	synchronized void wakeUp() {
	    if(lazy) {
	        if(!running) {
	            start();
	            return;
	        }
	    }
		notifyAll();
	}

	public synchronized void start() {
	    if(lazy) {
	        if(isEmpty()) return;
	        if(running) return;
	    }
	    running = true;
            executor.execute(this, threadName);
	}

	private synchronized boolean isEmpty() {
	    for(ArrayDeque<QueueItem> q : queue) {
	        if(!q.isEmpty()) return false;
	    }
	    return true;
    }

        @Override
	public int getPriority() {
		return NativeThread.NORM_PRIORITY;
	}

	public void removeRequest(SendableGet request, boolean persistent, short prio) {
		if(logMINOR) Logger.minor(this, "Removing request prio="+prio+" persistent="+persistent);
		QueueItem requestMatcher = new QueueItem(null, request, null);
		synchronized(this) {
		    if(!queue[prio].remove(requestMatcher)) return;
		}
		if(logMINOR) Logger.minor(this, "Removed transient request");
	}

}
