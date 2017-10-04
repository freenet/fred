package freenet.client.async;

import java.lang.ref.WeakReference;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;

import freenet.client.FetchContext;
import freenet.crypt.RandomSource;
import freenet.keys.ClientKey;
import freenet.keys.Key;
import freenet.node.BaseSendableGet;
import freenet.node.KeysFetchingLocally;
import freenet.node.Node;
import freenet.node.RequestClient;
import freenet.node.RequestScheduler;
import freenet.node.RequestStarter;
import freenet.node.SendableGet;
import freenet.node.SendableInsert;
import freenet.node.SendableRequest;
import freenet.node.SendableRequestItem;
import freenet.node.SendableRequestItemKey;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.RandomGrabArray;
import freenet.support.RandomGrabArrayWithObject;
import freenet.support.RemoveRandom.RemoveRandomReturn;
import freenet.support.RemoveRandomParent;
import freenet.support.SectoredRandomGrabArray;
import freenet.support.SectoredRandomGrabArraySimple;
import freenet.support.TimeUtil;

/** The global request queue. Both transient and persistent requests are kept on this in-RAM 
 * structure, which supports choosing a request to run. See KeyListenerTracker for the code
 * that matches up a fetched block with whoever was waiting for it, which needs to be separate for
 * various reasons. This class is not persistent. 
 * 
 * COOLDOWN TRACKER AND WAKEUP TIMES: Each node in the tree (priority, client, request) keeps a 
 * "wakeup time". This indicates that until the time given there is no point checking the requests
 * below that node. This happens either because all the keys are being fetched (in which case the
 * wakeup time is Long.MAX_VALUE) or because a key has been fetched repeatedly and has entered 
 * a cooldown period, meaning it will be fetchable in 30 minutes.
 * 
 * LOCKING: Consequently we need to lock the entire tree whenever we access either the tree or the
 * cooldown tracker (which really should be part of the tree, TODO!): When a request completes, we
 * start at the request itself and go up the tree until we stop updating the wakeup times. However
 * when we choose a request to send, we start at the top and go down (and update the cooldown times
 * when backtracking back up the tree if we don't find anything).
 * 
 * **We lock on ClientRequestSelector** when using the tree, including the cooldown times.
 * 
 * REDFLAG LOCKING: Actually in the completion case we could find the top and then lock the whole 
 * tree, and then update the cooldowns; and/or we could avoid updating the cooldowns during request 
 * selection, e.g. by making sure that each structure always does a bottom-up update when something
 * changes, although that would not help with locking...
 * 
 * FIXME: More seriously, we should really combine the cooldown tracker and the RGAs. The RGAs and 
 * SRGAs should contain their own wakeup times. This could significantly simplify the code. 
 * CooldownTracker is left over from the DB4O era.
 */
public class ClientRequestSelector implements KeysFetchingLocally {
	
	final boolean isInsertScheduler;
	final boolean isSSKScheduler;
	final boolean isRTScheduler;
	
	final ClientRequestScheduler sched;
	
	// Root: SRGA of SRGAs (for a priority), descend by RequestClient.
	// Layer 1: SRGA of RGAs (for a RequestClient), descend by ClientRequestSchedulerGroup.
	// Layer 2: RGAs (for a ClientRequestSchedulerGroup), contain SendableRequest's.
	// Layer 3: SendableRequest's.
	
	static class ClientRequestRGANode extends SectoredRandomGrabArraySimple<RequestClient,ClientRequestSchedulerGroup> {

        public ClientRequestRGANode(RequestClient object, RemoveRandomParent parent,
                ClientRequestSelector root) {
            super(object, parent, root);
        }
	    
	}
	
	static class RequestClientRGANode extends SectoredRandomGrabArray<RequestClient,ClientRequestRGANode> {

        public RequestClientRGANode(RemoveRandomParent parent, ClientRequestSelector root) {
            super(parent, root);
        }
	    
	}
	
	/**
     * The base of the tree.
     */
    protected RequestClientRGANode[] priorities;
    
    protected final Deque<BaseSendableGet>recentSuccesses;
    
    ClientRequestSelector(boolean isInsertScheduler, boolean isSSKScheduler, boolean isRTScheduler, ClientRequestScheduler sched) {
		this.sched = sched;
		this.isInsertScheduler = isInsertScheduler;
		this.isSSKScheduler = isSSKScheduler;
		this.isRTScheduler = isRTScheduler;
		if(!isInsertScheduler) {
			keysFetching = new HashSet<Key>();
			transientRequestsWaitingForKeysFetching = new HashMap<Key, WeakReference<BaseSendableGet>[]>();
			runningInserts = null;
			recentSuccesses = new ArrayDeque<BaseSendableGet>();
		} else {
			keysFetching = null;
			runningInserts = new HashSet<SendableRequestItemKey>();
			recentSuccesses = null;
		}
		priorities = new RequestClientRGANode[RequestStarter.NUMBER_OF_PRIORITY_CLASSES];
	}
	
	private static volatile boolean logMINOR;
	
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
	/**
	 * All Key's we are currently fetching. 
	 * Locally originated requests only, avoids some complications with HTL, 
	 * and also has the benefit that we can see stuff that's been scheduled on a SenderThread
	 * but that thread hasn't started yet. FIXME: Both issues can be avoided: first we'd get 
	 * rid of the SenderThread and start the requests directly and asynchronously, secondly
	 * we'd move this to node but only track keys we are fetching at max HTL.
	 * LOCKING: Always lock this LAST.
	 */
	private transient HashSet<Key> keysFetching;
	
	private transient HashMap<Key, WeakReference<BaseSendableGet>[]> transientRequestsWaitingForKeysFetching;
	
	private transient final HashSet<SendableRequestItemKey> runningInserts;
	
	/** Choose a priority to start requests from.
	 * @return The priority chosen or the time at which a priority will have requests to send.
	 * LOCKING: Synchronized because we may create new priorities. Both the cooldown queue and the 
	 * RGA hierarchy, rooted at the priorities, use ClientRequestSelector lock. */
	private synchronized long choosePriority(int fuzz, RandomSource random, ClientContext context, long now){
	    RequestClientRGANode result = null;
		
		long wakeupTime = Long.MAX_VALUE;
		
		short iteration = 0, priority;
		// we loop to ensure we try every possibilities ( n + 1)
		//
		// PRIO will do 0,1,2,3,4,5,6,0
		// TWEAKED will do rand%6,0,1,2,3,4,5,6
		while(iteration++ < RequestStarter.NUMBER_OF_PRIORITY_CLASSES + 1){
			priority = fuzz<0 ? tweakedPrioritySelector[random.nextInt(tweakedPrioritySelector.length)] : prioritySelector[Math.abs(fuzz % prioritySelector.length)];
			result = priorities[priority];
			if(result != null) {
			    long cooldownTime = result.getWakeupTime(context, now);
			    if(cooldownTime > 0) {
			        if(cooldownTime < wakeupTime) wakeupTime = cooldownTime;
			        if(logMINOR) {
			            if(cooldownTime == Long.MAX_VALUE)
			                Logger.minor(this, "Priority "+priority+" is waiting until a request finishes or is empty");
			            else
			                Logger.minor(this, "Priority "+priority+" is in cooldown for another "+(cooldownTime - now)+" "+TimeUtil.formatTime(cooldownTime - now));
			        }
			        result = null;
				}
			}
			if(priority > RequestStarter.MINIMUM_FETCHABLE_PRIORITY_CLASS) {
				fuzz++;
				continue; // Don't return because first round may be higher with soft scheduling
			}
			if(((result != null) && (!result.isEmpty()))) {
				if(logMINOR) Logger.minor(this, "using priority : "+priority);
				return priority;
			}
			
			if(logMINOR) Logger.minor(this, "Priority "+priority+" is null (fuzz = "+fuzz+ ')');
			fuzz++;
		}
		
		//FIXME: implement NONE
		return wakeupTime;
	}
	
	/** Choose a request to run and create the ChosenBlock for it. A request chosen by 
	 * chooseRequestInner() may not be runnable (it may return null if the request is already 
	 * running), so we may need to try repeatedly. FIXME this is only necessary because many 
	 * classes only update their cooldown status when choosing a block to send, e.g. 
	 * SplitFileInserter. */
	ChosenBlock chooseRequest(int fuzz, RandomSource random, OfferedKeysList offeredKeys, RequestStarter starter, boolean realTime, ClientContext context) {
		long now = System.currentTimeMillis();
		for(int i=0;i<5;i++) {
			SelectorReturn r = chooseRequestInner(fuzz, random, offeredKeys, starter, realTime, context, now);
                        SendableRequest req = r.req;
			if(req == null) {
			    if(r.wakeupTime != Long.MAX_VALUE && r.wakeupTime > now) {
			        // Wake up later.
			        sched.clientContext.ticker.queueTimedJob(new Runnable() {
			            
			            @Override
			            public void run() {
			                sched.wakeStarter();
			            }
			            
			        }, r.wakeupTime - now);
			    }
			    continue;
			}
			if(isInsertScheduler && req instanceof SendableGet) {
				IllegalStateException e = new IllegalStateException("removeFirstInner returned a SendableGet on an insert scheduler!!");
				req.internalError(e, sched, req.persistent());
				throw e;
			}
			ChosenBlock block = maybeMakeChosenRequest(req, context, now);
			if(block != null) return block;
		}
		return null;
	}
	
	public ChosenBlock maybeMakeChosenRequest(SendableRequest req, ClientContext context, long now) {
		if(req == null) return null;
		if(req.isCancelled()) {
			if(logMINOR) Logger.minor(this, "Request is cancelled: "+req);
			return null;
		}
		if(req.getWakeupTime(context, now) != 0) {
		    // Race condition. We don't need to add a wake-up job. FIXME this shouldn't happen 
		    // because we only consider local requests of the same type?! Add logging and debug!
			if(logMINOR) Logger.minor(this, "Request is in cooldown: "+req);
			return null;
		}
		SendableRequestItem token = req.chooseKey(this, context);
		if(token == null) {
			if(logMINOR) Logger.minor(this, "Choose key returned null: "+req);
			return null;
		} else {
			Key key;
			ClientKey ckey;
			if(isInsertScheduler) {
				key = null;
				ckey = null;
			} else {
				key = ((BaseSendableGet)req).getNodeKey(token);
				if(req instanceof SendableGet)
					ckey = ((SendableGet)req).getKey(token);
				else
					ckey = null;
			}
			ChosenBlock ret;
			if(key != null && key.getRoutingKey() == null)
				throw new NullPointerException();
			boolean localRequestOnly;
			boolean ignoreStore;
			boolean canWriteClientCache;
			boolean forkOnCacheable;
			boolean realTimeFlag;
			if(req instanceof SendableGet) {
				SendableGet sg = (SendableGet) req;
				FetchContext ctx = sg.getContext();
				localRequestOnly = ctx.localRequestOnly;
				ignoreStore = ctx.ignoreStore;
				canWriteClientCache = ctx.canWriteClientCache;
				realTimeFlag = sg.realTimeFlag();
				forkOnCacheable = false;
			} else {
				localRequestOnly = false;
				if(req instanceof SendableInsert) {
					canWriteClientCache = ((SendableInsert)req).canWriteClientCache();
					forkOnCacheable = ((SendableInsert)req).forkOnCacheable();
					localRequestOnly = ((SendableInsert)req).localRequestOnly();
					realTimeFlag = ((SendableInsert)req).realTimeFlag();
				} else {
					canWriteClientCache = false;
					forkOnCacheable = Node.FORK_ON_CACHEABLE_DEFAULT;
					localRequestOnly = false;
					realTimeFlag = false;
				}
				ignoreStore = false;
			}
			ret = new ChosenBlockImpl(req, token, key, ckey, localRequestOnly, ignoreStore, canWriteClientCache, forkOnCacheable, realTimeFlag, sched, req.persistent());
			if(logMINOR) Logger.minor(this, "Created "+ret+" for "+req);
			return ret;
		}
	}

	public class SelectorReturn {
		public final SendableRequest req;
		public final long wakeupTime;
		SelectorReturn(SendableRequest req) {
			this.req = req;
			this.wakeupTime = -1;
		}
		SelectorReturn(long wakeupTime) {
			this.wakeupTime = wakeupTime;
			this.req = null;
		}
	}
	
	/** Choose a request to run. Does not check whether the SendableRequest is actually runnable at 
	 * the moment. The cooldown mechanism on the RGAs and SRGAs should ensure that it is usable 
	 * most of the time.
	 * @return Either a chosen request or the time at which we should try again if all priorities 
	 * are waiting for requests to finish / cooldown periods to expire. */
	SelectorReturn chooseRequestInner(int fuzz, RandomSource random, OfferedKeysList offeredKeys, RequestStarter starter, boolean realTime, ClientContext context, long now) {
		// Priorities start at 0
		if(logMINOR) Logger.minor(this, "removeFirst()");
		boolean tryOfferedKeys = offeredKeys != null && random.nextBoolean();
		if(tryOfferedKeys) {
			if(offeredKeys.getWakeupTime(context, now) == 0)
				return new SelectorReturn(offeredKeys);
		}
		long l = choosePriority(fuzz, random, context, now);
		if(l > Integer.MAX_VALUE) {
			if(logMINOR) Logger.minor(this, "No priority available for the next "+TimeUtil.formatTime(l - now));
			return new SelectorReturn(l);
		}
		int choosenPriorityClass = (int)l;
		if(choosenPriorityClass == -1) {
			if(!tryOfferedKeys) {
				if(offeredKeys != null && offeredKeys.getWakeupTime(context, now) == 0)
					return new SelectorReturn(offeredKeys);
			}
			if(logMINOR)
				Logger.minor(this, "Nothing to do");
			// No requests queued at all.
			return new SelectorReturn(Long.MAX_VALUE);
		}
		long wakeupTime = Long.MAX_VALUE;
outer:	for(;choosenPriorityClass <= RequestStarter.MINIMUM_FETCHABLE_PRIORITY_CLASS;choosenPriorityClass++) {
			if(logMINOR) Logger.minor(this, "Using priority "+choosenPriorityClass);
			RequestClientRGANode chosenTracker = priorities[choosenPriorityClass];
			if(chosenTracker == null) {
				if(logMINOR) Logger.minor(this, "No requests to run: chosen priority empty");
				continue; // Try next priority
			}
			while(true) {
			    long cooldownTime = chosenTracker.getWakeupTime(context, now);
			    if(cooldownTime > 0) {
			        if(cooldownTime < wakeupTime) wakeupTime = cooldownTime;
			        Logger.normal(this, "Priority "+choosenPriorityClass+" is in cooldown for another "+(cooldownTime - now)+" "+TimeUtil.formatTime(cooldownTime - now));
			        continue outer;
				}
				
				if(logMINOR)
					Logger.minor(this, "Got priority tracker "+chosenTracker);
				RemoveRandomReturn val;
				synchronized(this) {
				    // We must hold the overall lock, just as in addToGrabArrays.
				    // This is important for keeping the cooldown tracker consistent amongst other 
				    // things: We can get a race condition between thread A reading the tree, 
				    // finding nothing and setCachedWakeup(), and thread B waking up a request, 
				    // resulting in the request not being accessible.
				    val = chosenTracker.removeRandom(starter, context, now);
				}
				SendableRequest req;
				if(val == null) {
					Logger.normal(this, "Priority "+choosenPriorityClass+" returned null - nothing to schedule, should remove priority");
					continue outer;
				} else if(val.item == null) {
					if(val.wakeupTime == -1)
						Logger.normal(this, "Priority "+choosenPriorityClass+" returned cooldown time of -1 - nothing to schedule, should remove priority");
					else {
						Logger.normal(this, "Priority "+choosenPriorityClass+" returned cooldown time of "+(val.wakeupTime - now)+" = "+TimeUtil.formatTime(val.wakeupTime - now));
						if(val.wakeupTime > 0 && val.wakeupTime < wakeupTime)
							wakeupTime = val.wakeupTime;
					}
					continue outer;
				} else {
					req = (SendableRequest) val.item;
				}
				if(req.getPriorityClass() != choosenPriorityClass) {
					// Reinsert it : shouldn't happen if we are calling reregisterAll,
					// maybe we should ask people to report that error if seen
					Logger.normal(this, "In wrong priority class: "+req+" (req.prio="+req.getPriorityClass()+" but chosen="+choosenPriorityClass+ ')');
					// Remove it.
					ClientRequestRGANode clientGrabber = chosenTracker.getGrabber(req.getClient());
					if(clientGrabber != null) {
						RandomGrabArray baseRGA = clientGrabber.getGrabber(req.getSchedulerGroup());
						if(baseRGA != null) {
							// Must synchronize to avoid nasty race conditions with cooldown.
							synchronized(this) {
								baseRGA.remove(req, context);
							}
						} else {
							// Okay, it's been removed already. Cool.
						}
					} else {
						Logger.error(this, "Could not find client grabber for client "+req.getClient()+" from "+chosenTracker);
					}
					innerRegister(req, context);
					continue;
				}
				
				// Check recentSuccesses
				/** Choose a recently succeeded request.
				 * 50% chance of using a recently succeeded request, if there is one.
				 * We keep a list of recently succeeded BaseSendableGet's, because transient 
				 * requests are chosen individually. */
				if(!isInsertScheduler) {
					BaseSendableGet altReq = null;
					synchronized(recentSuccesses) {
						if(!recentSuccesses.isEmpty()) {
							if(random.nextBoolean()) {
								altReq = recentSuccesses.poll();
							}
						}
					}
					if(altReq != null && (altReq.isCancelled())) {
						if(logMINOR)
							Logger.minor(this, "Ignoring cancelled recently succeeded item "+altReq);
						altReq = null;
					}
					if(altReq != null && (l = altReq.getWakeupTime(context, now)) != 0) {
						if(logMINOR) {
							Logger.minor(this, "Ignoring recently succeeded item, cooldown time = "+l+((l > 0) ? " ("+TimeUtil.formatTime(l - now)+")" : ""));
							altReq = null;
						}
					}
					if (altReq != null && altReq != req) {
						int prio = altReq.getPriorityClass();
						if(prio <= choosenPriorityClass) {
							// Use the recent one instead
							if(logMINOR)
								Logger.minor(this, "Recently succeeded (transient) req "+altReq+" (prio="+altReq.getPriorityClass()+") is better than "+req+" (prio="+req.getPriorityClass()+"), using that");
							// Don't need to reregister, because removeRandom doesn't actually remove!
							req = altReq;
						} else {
							// Don't use the recent one
							if(logMINOR)
								Logger.minor(this, "Chosen req "+req+" is better, reregistering recently succeeded "+altReq);
							synchronized(recentSuccesses) {
								recentSuccesses.add(altReq);
							}
						}
					}
				}
				
				// Now we have chosen a request.
				if(logMINOR) Logger.minor(this, "removeFirst() returning "+req+" (prio "+
						req.getPriorityClass()+", client "+req.getClient()+", client-req "+req.getClientRequest()+ ')');
				if(logMINOR) Logger.minor(this, "removeFirst() returning "+req+" of "+req.getClientRequest());
				assert(req.realTimeFlag() == realTime);
				return new SelectorReturn(req);
				
			}
		}
		if(logMINOR) Logger.minor(this, "No requests to run");
		return new SelectorReturn(wakeupTime);
	}
	
	private static final short[] tweakedPrioritySelector = { 
		RequestStarter.MAXIMUM_PRIORITY_CLASS,
		RequestStarter.MAXIMUM_PRIORITY_CLASS,
		RequestStarter.MAXIMUM_PRIORITY_CLASS,
		RequestStarter.MAXIMUM_PRIORITY_CLASS,
		RequestStarter.MAXIMUM_PRIORITY_CLASS,
		RequestStarter.MAXIMUM_PRIORITY_CLASS,
		RequestStarter.MAXIMUM_PRIORITY_CLASS,
		
		RequestStarter.INTERACTIVE_PRIORITY_CLASS,
		RequestStarter.INTERACTIVE_PRIORITY_CLASS,
		RequestStarter.INTERACTIVE_PRIORITY_CLASS,
		RequestStarter.INTERACTIVE_PRIORITY_CLASS,
		RequestStarter.INTERACTIVE_PRIORITY_CLASS,
		RequestStarter.INTERACTIVE_PRIORITY_CLASS,
		
		RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
		RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
		RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, 
		RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, 
		RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
		
		RequestStarter.UPDATE_PRIORITY_CLASS,
		RequestStarter.UPDATE_PRIORITY_CLASS, 
		RequestStarter.UPDATE_PRIORITY_CLASS, 
		RequestStarter.UPDATE_PRIORITY_CLASS,
		
		RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS, 
		RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS, 
		RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS,
		
		RequestStarter.PREFETCH_PRIORITY_CLASS, 
		RequestStarter.PREFETCH_PRIORITY_CLASS
	};
	private static final short[] prioritySelector = {
		RequestStarter.MAXIMUM_PRIORITY_CLASS,
		RequestStarter.INTERACTIVE_PRIORITY_CLASS,
		RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, 
		RequestStarter.UPDATE_PRIORITY_CLASS,
		RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS,
		RequestStarter.PREFETCH_PRIORITY_CLASS
	};

	/**
	 * @return True unless the key was already present.
	 */
	public boolean addToFetching(Key key) {
		synchronized(keysFetching) {
			boolean retval = keysFetching.add(key);
			if(!retval) {
				Logger.normal(this, "Already in keysFetching: "+key);
			} else {
				if(logMINOR)
					Logger.minor(this, "Added to keysFetching: "+key);
			}
			return retval;
		}
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public boolean hasKey(Key key, BaseSendableGet getterWaiting) {
		if(keysFetching == null) {
			throw new NullPointerException();
		}
		synchronized(keysFetching) {
			boolean ret = keysFetching.contains(key);
			if(!ret) return ret;
			// It is being fetched. Add the BaseSendableGet to the wait list so it gets woken up when the request finishes.
			if(getterWaiting != null) {
			    WeakReference<BaseSendableGet>[] waiting = transientRequestsWaitingForKeysFetching.get(key);
			    if(waiting == null) {
			        transientRequestsWaitingForKeysFetching.put(key, (WeakReference<BaseSendableGet>[])new WeakReference<?>[] { new WeakReference<BaseSendableGet>(getterWaiting) });
			    } else {
			        for(WeakReference<BaseSendableGet> ref : waiting) {
			            if(ref.get() == getterWaiting) return true;
			        }
			        WeakReference<BaseSendableGet>[] newWaiting = Arrays.copyOf(waiting, waiting.length+1);
			        newWaiting[waiting.length] = new WeakReference<BaseSendableGet>(getterWaiting);
			        transientRequestsWaitingForKeysFetching.put(key, newWaiting);
			    }
			}
			return true;
		}
	}

	/** LOCKING: Caller should hold as few locks as possible */ 
	public void removeFetchingKey(final Key key) {
		WeakReference<BaseSendableGet>[] transientWaiting;
		if(logMINOR)
			Logger.minor(this, "Removing from keysFetching: "+key);
		if(key != null) {
			synchronized(keysFetching) {
				keysFetching.remove(key);
				transientWaiting = this.transientRequestsWaitingForKeysFetching.remove(key);
			}
			if(transientWaiting != null) {
				if(transientWaiting != null) {
					for(WeakReference<BaseSendableGet> ref : transientWaiting) {
						BaseSendableGet get = ref.get();
						if(get == null) continue;
						get.clearWakeupTime(sched.getContext());
					}
				}
			}
		}
	}

	@Override
	public boolean hasInsert(SendableRequestItemKey token) {
		synchronized(runningInserts) {
			return runningInserts.contains(token);
		}
	}

	public boolean addRunningInsert(SendableRequestItemKey token) {
		synchronized(runningInserts) {
			boolean retval = runningInserts.add(token);
			if(!retval) {
			    // This shouldn't happen often, because the chooseBlock()'s should check for it...
				Logger.error(this, "Already in runningInserts: "+token);
			} else {
				if(logMINOR)
					Logger.minor(this, "Added to runningInserts: "+token);
			}
			return retval;
		}
	}
	
	public void removeRunningInsert(SendableRequestItemKey token) {
		if(logMINOR)
			Logger.minor(this, "Removing from runningInserts: "+token);
		synchronized(runningInserts) {
			runningInserts.remove(token);
		}
	}

	@Override
	public long checkRecentlyFailed(Key key, boolean realTime) {
		Node node = sched.getNode();
		return node.clientCore.checkRecentlyFailed(key, realTime);
	}
	
	   /** Add a request (or insert) to the request selection tree.
     * @param priorityClass The priority of the request.
     * @param client Label object indicating which larger group of requests this request belongs to
     * (e.g. the global queue, or an FCP client), and whether it is persistent.
     * @param cr The high-level request that this single block request is part of. E.g. a fetch for 
     * a single key may download many blocks in a splitfile; an insert for a large freesite is 
     * considered a single @see ClientRequester.
     * @param req A single SendableRequest object which is one or more low-level requests. E.g. it 
     * can be an insert of a single block, or it can be a request or insert for a single segment 
     * within a splitfile. 
     * @param container The database handle, if the request is persistent, in which case this will
     * be a ClientRequestSchedulerCore. If so, this method must be called on the database thread.
     * @param context The client context object, which contains links to all the important objects
     * that are not persisted in the database, e.g. executors, temporary filename generator, etc.
     */
    void addToGrabArray(short priorityClass, RequestClient client, ClientRequestSchedulerGroup cr, SendableRequest req, ClientContext context) {
        if((priorityClass > RequestStarter.PAUSED_PRIORITY_CLASS) || (priorityClass < RequestStarter.MAXIMUM_PRIORITY_CLASS))
            throw new IllegalStateException("Invalid priority: "+priorityClass+" - range is "+RequestStarter.MAXIMUM_PRIORITY_CLASS+" (most important) to "+RequestStarter.PAUSED_PRIORITY_CLASS+" (least important)");
        // Client
        synchronized(this) {
            ClientRequestRGANode requestGrabber = makeSRGAForClient(priorityClass, client, context);
            requestGrabber.add(cr, req, context);
        }
        sched.wakeStarter();
    }

    private ClientRequestRGANode makeSRGAForClient(short priorityClass,
            RequestClient client, ClientContext context) {
        RequestClientRGANode clientGrabber = priorities[priorityClass];
        if(clientGrabber == null) {
            clientGrabber = new RequestClientRGANode(null, this);
            priorities[priorityClass] = clientGrabber;
            if(logMINOR) Logger.minor(this, "Registering client tracker for priority "+priorityClass+" : "+clientGrabber);
        }
        // Request
        ClientRequestRGANode requestGrabber = clientGrabber.getGrabber(client);
        if(requestGrabber == null) {
            requestGrabber = new ClientRequestRGANode(client, clientGrabber, this);
            if(logMINOR)
                Logger.minor(this, "Creating new grabber: "+requestGrabber+" for "+client+" from "+clientGrabber+" : prio="+priorityClass);
            clientGrabber.addGrabber(client, requestGrabber, context);
            clientGrabber.clearWakeupTime(context);
        }
        return requestGrabber;
    }

    public void reregisterAll(ClientRequester request, ClientContext context, short oldPrio) {
        RequestClient client = request.getClient();
        short newPrio = request.getPriorityClass();
        if(newPrio == oldPrio) {
            Logger.error(this, "Changing priority from "+oldPrio+" to "+newPrio+" for "+request);
            return;
        }
        ClientRequestSchedulerGroup group = request.getSchedulerGroup();
        synchronized(this) {
            // First by priority
            RequestClientRGANode clientGrabber = priorities[oldPrio];
            if(clientGrabber == null) {
                // Normal as most of the schedulers aren't relevant to any given insert/request.
                if(logMINOR) Logger.minor(this, "Changing priority but request not running "+request, new Exception("debug"));
                return;
            }
            // Then by RequestClient
            ClientRequestRGANode requestGrabber = clientGrabber.getGrabber(client);
            if(requestGrabber == null) {
                if(logMINOR) Logger.minor(this, "Changing priority but request not running "+request, new Exception("debug"));
                return;
            }
            RandomGrabArrayWithObject<ClientRequestSchedulerGroup> rga = requestGrabber.getGrabber(group);
            if(rga == null) {
                if(logMINOR) Logger.minor(this, "Changing priority but request not running "+request, new Exception("debug"));
                return;
            }
            requestGrabber.maybeRemove(rga, context);
            requestGrabber = makeSRGAForClient(newPrio, client, context);
            if(requestGrabber.getGrabber(group) != null) {
                Logger.error(this, "RGA already exists for "+request+" : "+requestGrabber.getGrabber(group)+
                        " but want to insert "+rga, new Exception("error"));
                requestGrabber.maybeRemove(rga, context);
            }
            requestGrabber.addGrabber(group, rga, context);
        }
    }

    public synchronized long countQueuedRequests(ClientContext context) {
        long total = 0;
        for(int i=0;i<priorities.length;i++) {
            RequestClientRGANode prio = priorities[i];
            if(prio == null || prio.isEmpty())
                System.out.println("Priority "+i+" : empty");
            else {
                System.out.println("Priority "+i+" : "+prio.size());
                    System.out.println("Clients: "+prio.size()+" for "+prio);
                    for(int k=0;k<prio.size();k++) {
                        RequestClient client = prio.getClient(k);
                        System.out.println("Client "+k+" : "+client);
                        ClientRequestRGANode requestGrabber = prio.getGrabber(client);
                        System.out.println("SRGA for client: "+requestGrabber);
                        for(int l=0;l<requestGrabber.size();l++) {
                            ClientRequestSchedulerGroup cr = requestGrabber.getClient(l);
                            System.out.println("Request "+l+" : "+cr);
                            RandomGrabArray rga = requestGrabber.getGrabber(cr);
                            System.out.println("Queued SendableRequests: "+rga.size()+" on "+rga);
                            long sendable = 0;
                            long all = 0;
                            for(int m=0;m<rga.size();m++) {
                                SendableRequest req = (SendableRequest) rga.get(m);
                                if(req == null) continue;
                                sendable += req.countSendableKeys();
                                all += req.countAllKeys();
                            }
                            System.out.println("Sendable keys: "+sendable+" all keys "+all+" diff "+(all-sendable));
                            total += all;
                        }
                    }
            }
        }
        return total;
    }   
    
    /**
     * @param req
     * @param container
     */
    void innerRegister(SendableRequest req, ClientContext context) {
        if(isInsertScheduler && req instanceof BaseSendableGet)
            throw new IllegalArgumentException("Adding a SendableGet to an insert scheduler!!");
        if((!isInsertScheduler) && req instanceof SendableInsert)
            throw new IllegalArgumentException("Adding a SendableInsert to a request scheduler!!");
        if(isInsertScheduler != req.isInsert())
            throw new IllegalArgumentException("Request isInsert="+req.isInsert()+" but my isInsertScheduler="+isInsertScheduler+"!!");
        short prio = req.getPriorityClass();
        if(logMINOR) Logger.minor(this, "Still registering "+req+" at prio "+prio+" for "+req.getClientRequest()+" ssk="+this.isSSKScheduler+" insert="+this.isInsertScheduler);
        addToGrabArray(prio, req.getClient(), req.getSchedulerGroup(), req, context);
        if(logMINOR) Logger.minor(this, "Registered "+req+" on prioclass="+prio);
    }
    
    public void succeeded(BaseSendableGet succeeded) {
        // Do nothing.
        // FIXME: Keep a list of recently succeeded ClientRequester's.
        if(isInsertScheduler) return;
        if(succeeded.isCancelled()) return;
        // Don't bother with getCooldownTime at this point.
            if(logMINOR)
                Logger.minor(this, "Recording successful fetch from "+succeeded);
        synchronized(recentSuccesses) {
            while(recentSuccesses.size() >= 8)
                recentSuccesses.pollFirst();
            recentSuccesses.add(succeeded);
        }
    }
    
    public void wakeUp(ClientContext context) {
        // Break out of locks. Can be called within RGAs etc!
        context.mainExecutor.execute(new Runnable() {

            @Override
            public void run() {
                sched.wakeStarter();
            }
            
        });
    }

}
