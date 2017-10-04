/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import freenet.client.InsertException;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientRequestScheduler;
import freenet.keys.ClientKey;
import freenet.support.Logger;
import freenet.support.io.NativeThread;
import freenet.support.io.ResumeFailedException;

/**
 * Callback interface for a low level insert, which is immediately sendable. These
 * should be registered on the ClientRequestScheduler when we want to send them. It will
 * then, when it is time to send, create a thread, send the request, and call the 
 * callback below.
 */
public abstract class SendableInsert extends SendableRequest {

    private static final long serialVersionUID = 1L;

	public SendableInsert(boolean persistent, boolean realTimeFlag) {
		super(persistent, realTimeFlag);
	}
	
	/** Called when we successfully insert the data */
	public abstract void onSuccess(SendableRequestItem keyNum, ClientKey key, ClientContext context);
	
	/** Called when we don't! */
	public abstract void onFailure(LowLevelPutException e, SendableRequestItem keyNum, ClientContext context);

	@Override
	public void internalError(Throwable t, RequestScheduler sched, boolean persistent) {
		Logger.error(this, "Internal error on "+this+" : "+t, t);
		sched.callFailure(this, new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, t.getMessage(), t), NativeThread.MAX_PRIORITY, persistent);
	}

	@Override
	public final boolean isInsert() {
		return true;
	}
	
	@Override
	public ClientRequestScheduler getScheduler(ClientContext context) {
		if(isSSK())
			return context.getSskInsertScheduler(realTimeFlag);
		else
			return context.getChkInsertScheduler(realTimeFlag);
	}

	public abstract boolean canWriteClientCache();
	
	public abstract boolean localRequestOnly();

	public abstract boolean forkOnCacheable();

	/** Encoded a key */
	public abstract void onEncode(SendableRequestItem token, ClientKey key, ClientContext context);
	
	public abstract boolean isEmpty();
	
	@Override
	public long getWakeupTime(ClientContext context, long now) {
		if(isEmpty()) return -1;
		return 0;
	}
	
	private transient boolean resumed = false;
	
	public final void onResume(ClientContext context) throws InsertException, ResumeFailedException {
	    synchronized(this) {
	        if(resumed) return;
	        resumed = true;
	    }
	    innerOnResume(context);
	}
	
	protected abstract void innerOnResume(ClientContext context) throws InsertException, ResumeFailedException;

}
