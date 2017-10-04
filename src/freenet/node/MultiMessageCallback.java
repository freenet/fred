package freenet.node;

import freenet.io.comm.AsyncMessageCallback;

/** Groups a set of message sends together so that we get a single sent(boolean)
 * callback after all the messages have been sent, and then later a finished(boolean).
 * None of the callbacks will be called until after you call arm(). Typical usage:
 * <pre>Message m1 = ...;
 * Message m2 = ...;
 * PeerNode pn = ...;
 * MultiMessageCallback mcb = new MultiMessageCallback() {
 *   protected void finish(boolean success) {
 *     // Messages have finished.
 *   }
 *   protected void sent(boolean success) {
 *     // Messages have been sent.
 *   }
 * }
 * pn.sendAsync(m1, mcb.make(), ctr);
 * pn.sendAsync(m2, mcb.make(), ctr);
 * mcb.arm();</pre> */
public abstract class MultiMessageCallback {
	
    /** Number of messages that have not yet completed */
	private int waiting;
	/** Number of messages that have not yet been sent */
	private int waitingForSend;
	
	/** True if arm() has been called. finish(boolean) and sent(boolean) will 
	 * only be called after arming the callback. */
	private boolean armed;
	
	/** True if some messages have failed to send (e.g. disconnected). */
	private boolean someFailed;
	
	/** This is called when all messages have been acked, or failed */
	abstract void finish();
	
	/** This is called when all messages have been sent (but not acked) or failed to send */
	abstract void sent();

	/** Add another message. You should call arm() after you have added all messages. */
	public AsyncMessageCallback make() {
		synchronized(this) {
		    assert(!armed);
			AsyncMessageCallback cb = new AsyncMessageCallback() {

				private boolean finished;
				private boolean sent;
				
				@Override
				public void sent() {
					boolean success;
					synchronized(MultiMessageCallback.this) {
						if(finished || sent) return;
						sent = true;
						waitingForSend--;
						if(waitingForSend > 0) return;
                        if(!armed) return;
						success = !someFailed;
					}
					MultiMessageCallback.this.sent();
				}

				@Override
				public void acknowledged() {
					complete(true);
				}

				@Override
				public void disconnected() {
					complete(false);
				}

				@Override
				public void fatalError() {
					complete(false);
				}
				
				private void complete(boolean success) {
					boolean callSent = false;
					synchronized(MultiMessageCallback.this) {
						if(finished) return;
						if(!sent) {
							sent = true;
							waitingForSend--;
							if(waitingForSend == 0)
								callSent = true;
						}
						if(!success) someFailed = true;
						finished = true;
						waiting--;
						if(!finished()) return;
						if(someFailed) success = false;
					}
					if(callSent)
						MultiMessageCallback.this.sent();
					finish();
				}
				
			};
			waiting++;
			waitingForSend++;
			return cb;
		}
	}

	/** Enable the callback. The callbacks sent(boolean) and finish(boolean)
	 * will only be called after this method has been called, so you should 
	 * use this to indicate that you won't add any more messages. */
	public void arm() {
		boolean success;
		boolean callSent = false;
		boolean complete = false;
		synchronized(this) {
			armed = true;
			complete = waiting == 0;
			if(waitingForSend == 0) callSent = true;
			success = !someFailed;
		}
		if(callSent) sent();
		if(complete) finish();
	}
	
	/** @return True if the callbacck has finished (and is armed) */
	protected final synchronized boolean finished() {
		return armed && waiting == 0;
	}

}
