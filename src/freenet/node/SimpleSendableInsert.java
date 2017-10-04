/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import freenet.client.InsertException;
import freenet.client.async.ChosenBlock;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientRequestScheduler;
import freenet.client.async.ClientRequestSchedulerGroup;
import freenet.client.async.ClientRequester;
import freenet.keys.CHKBlock;
import freenet.keys.ClientKey;
import freenet.keys.KeyBlock;
import freenet.keys.SSKBlock;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;

/**
 * Simple SendableInsert implementation. No feedback, no retries, just insert the
 * block. Not designed for use by the client layer (and not persistent). Used by the node layer 
 * for the 1 in every 200 successful requests which starts an insert.
 */
public class SimpleSendableInsert extends SendableInsert {

    private static final long serialVersionUID = 1L;
    public final KeyBlock block;
	public final short prioClass;
	private boolean finished;
	public final RequestClient client;
	public final ClientRequestScheduler scheduler;
	      
        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	public SimpleSendableInsert(NodeClientCore core, KeyBlock block, short prioClass) {
		super(false, false);
		this.block = block;
		this.prioClass = prioClass;
		this.client = core.node.nonPersistentClientBulk;
		if(block instanceof CHKBlock)
			scheduler = core.requestStarters.chkPutSchedulerBulk;
		else if(block instanceof SSKBlock)
			scheduler = core.requestStarters.sskPutSchedulerBulk;
		else
			throw new IllegalArgumentException("Don't know what to do with "+block);
		if(!scheduler.isInsertScheduler())
			throw new IllegalStateException("Scheduler "+scheduler+" is not an insert scheduler!");
	}
	
	public SimpleSendableInsert(KeyBlock block, short prioClass, RequestClient client, ClientRequestScheduler scheduler) {
		super(false, false);
		this.block = block;
		this.prioClass = prioClass;
		this.client = client;
		this.scheduler = scheduler;
	}
	
	@Override
	public void onSuccess(SendableRequestItem keyNum, ClientKey key, ClientContext context) {
		// Yay!
		if(logMINOR)
			Logger.minor(this, "Finished insert of "+block);
	}

	@Override
	public void onFailure(LowLevelPutException e, SendableRequestItem keyNum, ClientContext context) {
		if(logMINOR)
			Logger.minor(this, "Failed insert of "+block+": "+e);
	}

	@Override
	public short getPriorityClass() {
		return prioClass;
	}

	@Override
	public SendableRequestSender getSender() {
		return new SendableRequestSender() {

			@Override
			public boolean send(NodeClientCore core, RequestScheduler sched, ClientContext context, ChosenBlock req) {
				// Ignore keyNum, key, since this is a single block
				try {
					if(logMINOR) Logger.minor(this, "Starting request: "+this);
					// FIXME bulk flag
					core.realPut(block, req.canWriteClientCache, Node.FORK_ON_CACHEABLE_DEFAULT, Node.PREFER_INSERT_DEFAULT, Node.IGNORE_LOW_BACKOFF_DEFAULT, false);
				} catch (LowLevelPutException e) {
					onFailure(e, req.token, context);
					if(logMINOR) Logger.minor(this, "Request failed: "+this+" for "+e);
					return true;
				} finally {
					finished = true;
				}
				if(logMINOR) Logger.minor(this, "Request succeeded: "+this);
				onSuccess(req.token, null, context);
                sched.removeRunningInsert(SimpleSendableInsert.this, req.token.getKey());
				return true;
			}

			@Override
			public boolean sendIsBlocking() {
				return true;
			}
		};
	}

	@Override
	public RequestClient getClient() {
		return client;
	}

	@Override
	public ClientRequester getClientRequest() {
		return null;
	}

	@Override
    public ClientRequestSchedulerGroup getSchedulerGroup() {
	    return null;
	}

	@Override
	public boolean isCancelled() {
		return finished;
	}
	
	@Override
	public boolean isEmpty() {
		return finished;
	}

	public void schedule() {
		finished = false; // can reschedule
		scheduler.registerInsert(this);
	}

	public void cancel(ClientContext context) {
		synchronized(this) {
			if(finished) return;
			finished = true;
		}
		super.unregister(context, prioClass);
	}

	@Override
	public synchronized long countAllKeys() {
		if(finished) return 0;
		return 1;
	}

	@Override
	public synchronized long countSendableKeys() {
		if(finished) return 0;
		return 1;
	}
	
	// FIXME share with SingleBlockInserter???
	private static class MySendableRequestItem implements SendableRequestItem, SendableRequestItemKey {
	    
	    final SimpleSendableInsert parent;

        public MySendableRequestItem(SimpleSendableInsert parent) {
            this.parent = parent;
        }

        @Override
        public void dump() {
            // Ignore.
        }

        @Override
        public SendableRequestItemKey getKey() {
            return this;
        }
        
        @Override
        public boolean equals(Object o) {
            if(o instanceof MySendableRequestItem) {
                return ((MySendableRequestItem)o).parent == parent;
            } else return false;
        }
        
        @Override
        public int hashCode() {
            return parent.hashCode();
        }
	    
	}

	@Override
	public synchronized SendableRequestItem chooseKey(KeysFetchingLocally keys, ClientContext context) {
	    MySendableRequestItem mine = new MySendableRequestItem(this);
		if(keys.hasInsert(mine))
			return null;
		if(finished) return null;
		else
			return mine;
	}
	
	@Override
	public synchronized long getWakeupTime(ClientContext context, long now) {
	    if(isEmpty()) return -1;
	    if(scheduler.fetchingKeys().hasInsert(new MySendableRequestItem(this)))
	        return Long.MAX_VALUE;
	    return 0;
	}

	@Override
	public boolean isSSK() {
		return block instanceof SSKBlock;
	}

	@Override
	public boolean canWriteClientCache() {
		return false;
	}

	@Override
	public boolean forkOnCacheable() {
		return Node.FORK_ON_CACHEABLE_DEFAULT;
	}

	@Override
	public void onEncode(SendableRequestItem token, ClientKey key, ClientContext context) {
		// Ignore.
	}

	@Override
	public boolean localRequestOnly() {
		return false;
	}

    @Override
    protected void innerOnResume(ClientContext context) throws InsertException {
        // Do nothing.
    }

}
