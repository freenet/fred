/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.async;

import java.util.ArrayList;
import java.util.HashSet;

import freenet.crypt.RandomSource;
import freenet.keys.Key;
import freenet.node.BaseSendableGet;
import freenet.node.KeysFetchingLocally;
import freenet.node.LowLevelGetException;
import freenet.node.NodeClientCore;
import freenet.node.RequestClient;
import freenet.node.RequestCompletionListener;
import freenet.node.RequestScheduler;
import freenet.node.SendableRequestItem;
import freenet.node.SendableRequestItemKey;
import freenet.node.SendableRequestSender;
import freenet.support.ListUtils;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;

/**
 * All the keys at a given priority which we have received key offers from other nodes for.
 * 
 * This list needs to be kept up to date when:
 * - A request is removed.
 * - A request's priority changes.
 * - A key is found.
 * - A node disconnects or restarts (through the BlockOffer objects on the FailureTable).
 * 
 * And of course, when an offer is received, we need to add an element.
 * 
 * @author toad
 *
 */
@SuppressWarnings("serial") // We don't serialize this.
public class OfferedKeysList extends BaseSendableGet implements RequestClient {

	private final HashSet<Key> keys;
	private final ArrayList<Key> keysList; // O(1) remove random element the way we use it, see chooseKey().
	private static volatile boolean logMINOR;
	private static volatile boolean logDEBUG;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
				logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}
	private final RandomSource random;
	private final short priorityClass;
	private final boolean isSSK;
	
	OfferedKeysList(RandomSource random, short priorityClass, boolean isSSK, boolean realTimeFlag) {
		super(false, realTimeFlag);
		this.keys = new HashSet<Key>();
		this.keysList = new ArrayList<Key>();
		this.random = random;
		this.priorityClass = priorityClass;
		this.isSSK = isSSK;
	}
	
	/** Called when a key is found, when it no longer belongs to this list etc. */
	public synchronized void remove(Key key) {
		assert(keysList.size() == keys.size());
		if(keys.remove(key)) {
			ListUtils.removeBySwapLast(keysList, key);
			if(logMINOR) Logger.minor(this, "Found "+key+" , removing it "+" for "+this+" size now "+keysList.size());
		}
		assert(keysList.size() == keys.size());
	}
	
	public synchronized boolean isEmpty() {
		return keys.isEmpty();
	}

	@Override
	public long countAllKeys() {
		// Not supported.
		throw new UnsupportedOperationException();
	}

	@Override
	public long countSendableKeys() {
		// Not supported.
		throw new UnsupportedOperationException();
	}

	private static class MySendableRequestItem implements SendableRequestItem, SendableRequestItemKey {
		final Key key;
		MySendableRequestItem(Key key) {
			this.key = key;
		}
		@Override
		public void dump() {
			// Ignore, we will be GC'ed
		}
		@Override
		public SendableRequestItemKey getKey() {
			return this;
		}
	}
	
	@Override
	public synchronized SendableRequestItem chooseKey(KeysFetchingLocally fetching, ClientContext context) {
		assert(keysList.size() == keys.size());
		if(keys.size() == 1) {
			// Shortcut the common case
			Key k = keysList.get(0);
			if(fetching.hasKey(k, null)) return null;
			// Ignore RecentlyFailed because an offered key overrides it.
			keys.remove(k);
			keysList.remove(0);
			keysList.trimToSize();
			return new MySendableRequestItem(k);
		}
		for(int i=0;i<10;i++) {
			// Pick a random key
			if(keysList.isEmpty()) return null;
			int ptr = random.nextInt(keysList.size());
			// Avoid shuffling penalty by swapping the chosen element with the end.
			Key k = keysList.get(ptr);
			if(fetching.hasKey(k, null)) continue;
			// Ignore RecentlyFailed because an offered key overrides it.
			ListUtils.removeBySwapLast(keysList, ptr);
			keys.remove(k);
			assert(keysList.size() == keys.size());
			return new MySendableRequestItem(k);
		}
		return null;
	}

	@Override
	public RequestClient getClient() {
		return this;
	}

	@Override
	public ClientRequester getClientRequest() {
		// FIXME is this safe?
		return null;
	}

	@Override
	public short getPriorityClass() {
		return priorityClass;
	}

	@Override
	public void internalError(Throwable t, RequestScheduler sched, boolean persistent) {
		Logger.error(this, "Internal error: "+t, t);
	}
	
	@Override
	public SendableRequestSender getSender() {
		return new SendableRequestSender() {

			@Override
			public boolean send(NodeClientCore core, final RequestScheduler sched, ClientContext context, ChosenBlock req) {
				final Key key = ((MySendableRequestItem) req.token).key;
				// Have to cache it in order to propagate it; FIXME
				// Don't let a node force us to start a real request for a specific key.
				// We check the datastore, take up offers if any (on a short timeout), and then quit if we still haven't fetched the data.
				// Obviously this may have a marginal impact on load but it should only be marginal.
				core.asyncGet(key, true, new RequestCompletionListener() {

					@Override
					public void onSucceeded() {
                        // We don't use ChosenBlockImpl so have to remove the keys from the fetching set ourselves.
						sched.removeFetchingKey(key);
						sched.wakeStarter();
					}

					@Override
					public void onFailed(LowLevelGetException e) {
					    // We don't use ChosenBlockImpl so have to remove the keys from the fetching set ourselves.
						sched.removeFetchingKey(key);
						// Something might be waiting for a request to complete (e.g. if we have two requests for the same key), 
						// so wake the starter thread.
						sched.wakeStarter();
					}

				}, true, false, realTimeFlag, false, false);
				// FIXME reconsider canWriteClientCache=false parameter.
				return true;
			}

			@Override
			public boolean sendIsBlocking() {
				return false;
			}
			
		};
	}

	@Override
	public boolean isCancelled() {
		return false;
	}

	public synchronized void queueKey(Key key) {
		assert(keysList.size() == keys.size());
		if(keys.add(key)) {
			keysList.add(key);
			if(logMINOR) Logger.minor(this, "Queued key "+key+" on "+this);
		}
		assert(keysList.size() == keys.size());
	}

	@Override
	public Key getNodeKey(SendableRequestItem token) {
		return ((MySendableRequestItem) token).key;
	}

	@Override
	public boolean isSSK() {
		return isSSK;
	}

	@Override
	public boolean isInsert() {
		return false;
	}

	@Override
	public ClientRequestScheduler getScheduler(ClientContext context) {
		if(isSSK)
			return context.getSskFetchScheduler(realTimeFlag);
		else
			return context.getChkFetchScheduler(realTimeFlag);
	}

	@Override
	public boolean preRegister(ClientContext context, boolean toNetwork) {
		// Ignore
		return false;
	}

	@Override
	public long getWakeupTime(ClientContext context, long now) {
		if(isEmpty()) {
		    return Long.MAX_VALUE;
		}
		return 0;
	}

}
