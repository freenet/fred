package freenet.client.async;

import freenet.keys.ClientKey;
import freenet.keys.Key;
import freenet.node.LowLevelGetException;
import freenet.node.LowLevelPutException;
import freenet.node.NodeClientCore;
import freenet.node.RequestScheduler;
import freenet.node.SendableRequestItem;
import freenet.node.SendableRequestSender;

/**
 * A single selected request, including everything needed to execute it. Most important functions 
 * are the callbacks, which run off-thread, call the upstream callbacks on the SendableGet etc, and
 * remove the fetching keys from the KeysFetchingLocally.
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public abstract class ChosenBlock {

	/** The token indicating the key within the request to be fetched/inserted.
	 * Meaning is entirely defined by the request. */
	public transient final SendableRequestItem token;
	/** The key to be fetched, null if not a BaseSendableGet */
	public transient final Key key;
	/** The client-layer key to be fetched, null if not a SendableGet */
	public transient final ClientKey ckey;
	public transient final boolean localRequestOnly;
	public transient final boolean ignoreStore;
	public transient final boolean canWriteClientCache;
	public transient final boolean forkOnCacheable;
	public transient final boolean realTimeFlag;

	public ChosenBlock(SendableRequestItem token, Key key, ClientKey ckey, boolean localRequestOnly, boolean ignoreStore, boolean canWriteClientCache, boolean forkOnCacheable, boolean realTimeFlag) {
		this.token = token;
		if(token == null) throw new NullPointerException();
		this.key = key;
		this.ckey = ckey;
		this.localRequestOnly = localRequestOnly;
		this.ignoreStore = ignoreStore;
		this.canWriteClientCache = canWriteClientCache;
		this.forkOnCacheable = forkOnCacheable;
		this.realTimeFlag = realTimeFlag;
	}

	public abstract boolean isPersistent();

	public abstract boolean isCancelled();

	public abstract void onFailure(LowLevelPutException e, ClientContext context);

	public abstract void onInsertSuccess(ClientKey key, ClientContext context);

	public abstract void onFailure(LowLevelGetException e, ClientContext context);

	/**
	 * The actual data delivery goes through CRS.tripPendingKey(). This is just a notification
	 * for book-keeping purposes. We call the scheduler to tell it that the request succeeded,
	 * so that it can be rescheduled soon for more requests.
	 * @param context Might be useful.
	 */
	public abstract void onFetchSuccess(ClientContext context);

	public abstract short getPriority();
	
	private boolean sendIsBlocking;

	public boolean send(NodeClientCore core, RequestScheduler sched) {
		ClientContext context = sched.getContext();
		SendableRequestSender sender = getSender();
		sendIsBlocking = sender.sendIsBlocking();
		return sender.send(core, sched, context, this);
	}
	
	public abstract SendableRequestSender getSender();
	
	public void onDumped() {
		token.dump();
	}
	
	/** Call this after send() */
	public boolean sendIsBlocking() {
		return sendIsBlocking;
	}
}
