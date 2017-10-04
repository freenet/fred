package freenet.client.async;

import freenet.keys.ClientKey;
import freenet.keys.Key;
import freenet.node.LowLevelGetException;
import freenet.node.LowLevelPutException;
import freenet.node.RequestScheduler;
import freenet.node.SendableGet;
import freenet.node.SendableInsert;
import freenet.node.SendableRequest;
import freenet.node.SendableRequestItem;
import freenet.node.SendableRequestSender;
import freenet.support.Logger;

/**
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 *
 */
public class ChosenBlockImpl extends ChosenBlock {
    
    private static volatile boolean logMINOR;
    private static volatile boolean logDEBUG;
    static {
        Logger.registerClass(ChosenBlockImpl.class);
    }

	public final SendableRequest request;
	public final RequestScheduler sched;
	public final boolean persistent;

	public ChosenBlockImpl(SendableRequest req, SendableRequestItem token, Key key, ClientKey ckey, 
			boolean localRequestOnly, boolean ignoreStore, boolean canWriteClientCache, boolean forkOnCacheable, boolean realTimeFlag, RequestScheduler sched, boolean persistent) {
		super(token, key, ckey, localRequestOnly, ignoreStore, canWriteClientCache, forkOnCacheable, realTimeFlag);
		this.request = req;
		this.sched = sched;
		this.persistent = persistent;
		if(logDEBUG) Logger.minor(this, "Created "+this+" for "+(persistent?"persistent":"transient")+" block "+token+" for key "+key, new Exception("debug")); 
	}

	@Override
	public boolean isCancelled() {
		return request.isCancelled();
	}

	@Override
	public boolean isPersistent() {
		return persistent;
	}

	@Override
	public void onFailure(final LowLevelPutException e, ClientContext context) {
	    context.getJobRunner(persistent).queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                try {
                    ((SendableInsert) request).onFailure(e, token, context);
                } finally {
                    sched.removeRunningInsert((SendableInsert)(request), token.getKey());
                    // Something might be waiting for a request to complete (e.g. if we have two requests for the same key), 
                    // so wake the starter thread.
                }
                sched.wakeStarter();
                return false;
            }
	        
	    });
	}

	@Override
	public void onInsertSuccess(final ClientKey key, ClientContext context) {
        context.getJobRunner(persistent).queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                try {
                    ((SendableInsert) request).onSuccess(token, key, context);
                } finally {
                    sched.removeRunningInsert((SendableInsert)(request), token.getKey());
                }
                // Something might be waiting for a request to complete (e.g. if we have two requests for the same key), 
                // so wake the starter thread.
                sched.wakeStarter();
                return false;
            }
            
        });
	}

	@Override
	public void onFailure(final LowLevelGetException e, ClientContext context) {
        context.getJobRunner(persistent).queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                try {
                    ((SendableGet) request).onFailure(e, token, context);
                } finally {
                    sched.removeFetchingKey(key);
                }
                // Something might be waiting for a request to complete (e.g. if we have two requests for the same key), 
                // so wake the starter thread.
                sched.wakeStarter();
                return false;
            }

        });
	}

	@Override
	public void onFetchSuccess(ClientContext context) {
	    context.getJobRunner(persistent).queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                try {
                    sched.succeeded((SendableGet)request, false);
                } finally {
                    sched.removeFetchingKey(key);
                }
                // Something might be waiting for a request to complete (e.g. if we have two requests for the same key), 
                // so wake the starter thread.
                sched.wakeStarter();
                return false;
            }
	        
	    });
	}
	
	@Override
	public short getPriority() {
		return request.getPriorityClass();
	}

	@Override
	public SendableRequestSender getSender() {
		return request.getSender();
	}
	
}
