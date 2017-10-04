/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientGetState;
import freenet.client.async.ClientRequestScheduler;
import freenet.client.async.ClientRequester;
import freenet.client.async.PersistentJob;
import freenet.client.async.SimpleSingleFileFetcher;
import freenet.client.async.WantsCooldownCallback;
import freenet.keys.ClientKey;
import freenet.keys.Key;
import freenet.support.Logger;
import freenet.support.io.NativeThread;

/**
 * A low-level key fetch which can be sent immediately. @see SendableRequest
 * 
 * WARNING: Changing non-transient members on classes that are Serializable can result in 
 * restarting downloads or losing uploads. (Some children of this class are actually stored)
 */
public abstract class SendableGet extends BaseSendableGet {

    private static final long serialVersionUID = 1L;
    /** Parent BaseClientGetter. Required for schedulers. */
	public final ClientRequester parent;
	
	/** Get a numbered key to fetch. */
	public abstract ClientKey getKey(SendableRequestItem token);
	
	@Override
	public Key getNodeKey(SendableRequestItem token) {
		ClientKey key = getKey(token);
		if(key == null) return null;
		return key.getNodeKey(true);
	}
	
	/**
	 * What keys are we interested in? For purposes of checking the datastore.
	 * This is in SendableGet, *not* KeyListener, in order to deal with it in
	 * smaller chunks.
	 */
	public abstract Key[] listKeys();

	/** Get the fetch context (settings) object. */
	public abstract FetchContext getContext();
	
	/** Called when/if the low-level request fails. */
	public abstract void onFailure(LowLevelGetException e, SendableRequestItem token, ClientContext context);
	
	// Implementation

	public SendableGet(ClientRequester parent, boolean realTimeFlag) {
		super(parent.persistent(), realTimeFlag);
		this.parent = parent;
	}
	
	static final SendableGetRequestSender sender = new SendableGetRequestSender();
	
	@Override
	public SendableRequestSender getSender() {
		return sender;
	}
	
	@Override
	public ClientRequestScheduler getScheduler(ClientContext context) {
		if(isSSK())
			return context.getSskFetchScheduler(realTimeFlag);
		else
			return context.getChkFetchScheduler(realTimeFlag);
	}

	/**
	 * Get the time at which the key specified by the given token will wake up from the 
	 * cooldown queue.
	 * @param token
	 * @return
	 */
	public abstract long getCooldownWakeup(SendableRequestItem token);
	
	/**
	 * An internal error occurred, effecting this SendableGet, independantly of any ChosenBlock's.
	 */
	@Override
	public void internalError(final Throwable t, final RequestScheduler sched, boolean persistent) {
		Logger.error(this, "Internal error on "+this+" : "+t, t);
		sched.callFailure(this, new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR, t.getMessage(), t), NativeThread.MAX_PRIORITY, persistent);
	}

	@Override
	public final boolean isInsert() {
		return false;
	}

	@Override
	public void unregister(ClientContext context, short oldPrio) {
		super.unregister(context, oldPrio);
		ClientRequestScheduler scheduler = getScheduler(context);
		context.checker.removeRequest(this, persistent, oldPrio == -1 ? getPriorityClass() : oldPrio);
	}
	
	public static FetchException translateException(LowLevelGetException e) {
	    switch(e.code) {
	    case LowLevelGetException.DATA_NOT_FOUND:
	    case LowLevelGetException.DATA_NOT_FOUND_IN_STORE:
	        return new FetchException(FetchExceptionMode.DATA_NOT_FOUND);
	    case LowLevelGetException.RECENTLY_FAILED:
	        return new FetchException(FetchExceptionMode.RECENTLY_FAILED);
	    case LowLevelGetException.DECODE_FAILED:
	        return new FetchException(FetchExceptionMode.BLOCK_DECODE_ERROR);
	    case LowLevelGetException.INTERNAL_ERROR:
	        return new FetchException(FetchExceptionMode.INTERNAL_ERROR);
	    case LowLevelGetException.REJECTED_OVERLOAD:
	        return new FetchException(FetchExceptionMode.REJECTED_OVERLOAD);
	    case LowLevelGetException.ROUTE_NOT_FOUND:
	        return new FetchException(FetchExceptionMode.ROUTE_NOT_FOUND);
	    case LowLevelGetException.TRANSFER_FAILED:
	        return new FetchException(FetchExceptionMode.TRANSFER_FAILED);
	    case LowLevelGetException.VERIFY_FAILED:
	        return new FetchException(FetchExceptionMode.BLOCK_DECODE_ERROR);
	    case LowLevelGetException.CANCELLED:
	        return new FetchException(FetchExceptionMode.CANCELLED);
	    default:
	        Logger.error(SimpleSingleFileFetcher.class, "Unknown LowLevelGetException code: "+e.code);
	        return new FetchException(FetchExceptionMode.INTERNAL_ERROR, "Unknown error code: "+e.code);
	    }
	}
	
    @Override
    public boolean reduceWakeupTime(final long wakeupTime, ClientContext context) {
        boolean ret = super.reduceWakeupTime(wakeupTime, context);
        if(this.parent instanceof WantsCooldownCallback) {
            context.getJobRunner(persistent).queueNormalOrDrop(new PersistentJob() {

                @Override
                public boolean run(ClientContext context) {
                    ((WantsCooldownCallback)parent).enterCooldown(getClientGetState(), wakeupTime, context);
                    return false;
                }
                
            });
        }
        return ret;
    }
    
    @Override
    public void clearWakeupTime(ClientContext context) {
        super.clearWakeupTime(context);
        if(this.parent instanceof WantsCooldownCallback) {
            context.getJobRunner(persistent).queueNormalOrDrop(new PersistentJob() {

                @Override
                public boolean run(ClientContext context) {
                    ((WantsCooldownCallback)parent).clearCooldown(getClientGetState());
                    return false;
                }
                
            });
        }
    }

    protected abstract ClientGetState getClientGetState();

}
