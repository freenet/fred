/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.async;

import static java.lang.String.format;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import freenet.crypt.RandomSource;
import freenet.crypt.SHA256;
import freenet.keys.Key;
import freenet.keys.KeyBlock;
import freenet.keys.NodeSSK;
import freenet.node.SendableGet;
import freenet.node.SendableRequest;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;

/**
 * <p>Tracks exactly which keys we are listening for. This is 
 * decoupled from actually requesting them because we want to pick up the data even if we didn't 
 * request it - some nearby node requested it, it got inserted through this node, it was offered 
 * via ULPRs some time after we requested it etc.</p>
 * 
 * <p>The queue of requests to run, and the algorithm to choose which to start, is in
 * @see ClientRequestSchedulerSelector .</p>
 * 
 * PERSISTENCE: This class is NOT serialized, it is recreated on every startup, and downloads are
 * re-registered with this class (for KeyListeners) and downloads and uploads are re-registered 
 * with the ClientRequestSelector.
 * @author toad
 */
class KeyListenerTracker implements KeySalter {
	
	private static volatile boolean logMINOR;
	
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
	/** Minimum number of retries at which we start to hold it against a request.
	 * See the comments on fixRetryCount; we don't want many untried requests to prevent
	 * us from trying requests which have only been tried once (e.g. USK checkers), from 
	 * other clients (and we DO want retries to take precedence over client round robin IF 
	 * the request has been tried many times already). */
	private static final int MIN_RETRY_COUNT = 3;

	final boolean isInsertScheduler;
	final boolean isSSKScheduler;
	final boolean isRTScheduler;
	
	protected final ClientRequestScheduler sched;
	/** Transient even for persistent scheduler. There is one for each of transient, persistent. */
	private final ArrayList<KeyListener> keyListeners;

	final boolean persistent;
	
	public boolean persistent() {
	    return persistent;
	}
	
	protected KeyListenerTracker(boolean forInserts, boolean forSSKs, boolean forRT, RandomSource random, ClientRequestScheduler sched, byte[] globalSalt, boolean persistent) {
		this.isInsertScheduler = forInserts;
		this.isSSKScheduler = forSSKs;
		this.isRTScheduler = forRT;
		this.sched = sched;
		keyListeners = new ArrayList<KeyListener>();
		if(globalSalt == null) {
		    globalSalt = new byte[32];
		    random.nextBytes(globalSalt);
		}
		this.globalSalt = globalSalt;
		this.persistent = persistent;
	}
	
	/**
	 * Mangle the retry count.
	 * Below a certain number of attempts, we don't prefer one request to another just because
	 * it's been tried more times. The reason for this is to prevent floods of low-retry-count
	 * requests from starving other clients' requests which need to be retried. The other
	 * solution would be to sort by client before retry count, but that would be excessive 
	 * IMHO; we DO want to avoid rerequesting keys we've tried many times before.
	 */
	protected static int fixRetryCount(int retryCount) {
		return Math.max(0, retryCount-MIN_RETRY_COUNT);
	}

	public void addPendingKeys(KeyListener listener) {
		if(listener == null) throw new NullPointerException();
		synchronized (this) {
			// We have to register before checking the disk, so it may well get registered twice.
			if(keyListeners.contains(listener))
				return;
			keyListeners.add(listener);
		}
		if (logMINOR)
			Logger.minor(this, "Added pending keys to "+this+" : size now "+keyListeners.size()+" : "+listener);
	}
	
	public boolean removePendingKeys(KeyListener listener) {
		boolean ret;
		synchronized (this) {
			ret = keyListeners.remove(listener);
		}
		listener.onRemove();
		if (logMINOR)
			Logger.minor(this, "Removed pending keys from "+this+" : size now "+keyListeners.size()+" : "+listener, new Exception("debug"));
		return ret;
	}
	
	public boolean removePendingKeys(HasKeyListener hasListener) {
		ArrayList<KeyListener> matches = new ArrayList<KeyListener>();
		synchronized (this) {
			for (KeyListener listener : keyListeners) {
				HasKeyListener hkl;
				try {
					hkl = listener.getHasKeyListener();
				} catch (Throwable t) {
					Logger.error(this, format("Error in getHasKeyListener callback for %s", listener), t);
					continue;
				}
				if (hkl == hasListener) {
					matches.add(listener);
				}
			}
		}
		if (matches.isEmpty()) {
			return false;
		}
		for (KeyListener listener : matches) {
			try {
				removePendingKeys(listener);
			} catch (Throwable t) {
				Logger.error(this, format("Error while removing %s", listener), t);
			}
		}
		return true;
	}
	
	public short getKeyPrio(Key key, short priority) {
		assert(key instanceof NodeSSK == isSSKScheduler);
		byte[] saltedKey = saltKey(key);
		List<KeyListener> matches = probablyWantKey(key, saltedKey);
		if (matches.isEmpty()) {
			return priority;
		}
		for (KeyListener listener : matches) {
			short prio;
			try {
				prio = listener.definitelyWantKey(key);
			} catch (Throwable t) {
				Logger.error(this, format("Error in definitelyWantKey callback for %s", listener), t);
				continue;
			}
			if(prio == -1) continue;
			if(prio < priority) priority = prio;
		}
		return priority;
	}
	
	public synchronized long countWaitingKeys() {
		long count = 0;
		for (KeyListener listener : keyListeners) {
			try {
				count += listener.countKeys();
			} catch (Throwable t) {
				Logger.error(this, format("Error in countKeys callback for %s", listener), t);
			}
		}
		return count;
	}
	
	public boolean anyWantKey(Key key) {
		assert(key instanceof NodeSSK == isSSKScheduler);
		byte[] saltedKey = saltKey(key);
		List<KeyListener> matches = probablyWantKey(key, saltedKey);
		if (!matches.isEmpty()) {
			for (KeyListener listener : matches) {
				try {
					if (listener.definitelyWantKey(key) >= 0) {
						return true;
					}
				} catch (Throwable t) {
					Logger.error(this, format("Error in definitelyWantKey callback for %s", listener), t);
				}
			}
		}
		return false;
	}
	
	public synchronized boolean anyProbablyWantKey(Key key) {
		assert(key instanceof NodeSSK == isSSKScheduler);
		byte[] saltedKey = saltKey(key);
		for (KeyListener listener : keyListeners) {
			try {
				if (listener.probablyWantKey(key, saltedKey)) {
					return true;
				}
			} catch (Throwable t) {
				Logger.error(this, format("Error in probablyWantKey callback for %s", listener), t);
			}
		}
		return false;
	}
	
	public boolean tripPendingKey(Key key, KeyBlock block, ClientContext context) {
		if((key instanceof NodeSSK) != isSSKScheduler) {
			Logger.error(this, "Key "+key+" on scheduler ssk="+isSSKScheduler, new Exception("debug"));
			return false;
		}
		assert(key instanceof NodeSSK == isSSKScheduler);
		byte[] saltedKey = saltKey(key);
		List<KeyListener> matches = probablyWantKey(key, saltedKey);
		boolean ret = false;
		for (KeyListener listener : matches) {
			try {
				if (listener.handleBlock(key, saltedKey, block, context)) {
					ret = true;
				}
			} catch (Throwable t) {
				Logger.error(this, format("Error in handleBlock callback for %s", listener), t);
			}
			if (listener.isEmpty()) {
				try {
					removePendingKeys(listener);
				} catch (Throwable t) {
					Logger.error(this, format("Error while removing %s", listener), t);
				}
			}
		}
		return ret;
	}
	
	public SendableGet[] requestsForKey(Key key) {
		ArrayList<SendableGet> list = new ArrayList<SendableGet>();
		assert(key instanceof NodeSSK == isSSKScheduler);
		byte[] saltedKey = saltKey(key);
		List<KeyListener> matches = probablyWantKey(key, saltedKey);
		for (KeyListener listener : matches) {
			SendableGet[] reqs;
			try {
				reqs = listener.getRequestsForKey(key);
			} catch (Throwable t) {
				Logger.error(this, format("Error in getRequestsForKey callback for %s", listener), t);
				continue;
			}
			if (reqs == null) {
				continue;
			}
			for (SendableGet req : reqs) {
				list.add(req);
			}
		}
		if (list.isEmpty()) {
			return null;
		}
		return list.toArray(new SendableGet[list.size()]);
	}
	
	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append(super.toString());
		sb.append(':');
		if(isInsertScheduler)
			sb.append("insert:");
		if(isSSKScheduler)
			sb.append("SSK");
		else
			sb.append("CHK");
		return sb.toString();
	}

	public byte[] globalSalt;
	
	public byte[] saltKey(Key key) {
		MessageDigest md = SHA256.getMessageDigest();
		md.update(key.getRoutingKey());
		md.update(globalSalt);
		byte[] ret = md.digest();
		SHA256.returnMessageDigest(md);
		return ret;
	}
	
	protected void hintGlobalSalt(byte[] globalSalt2) {
		if(globalSalt == null)
			globalSalt = globalSalt2;
	}

	/**
	 * Returns all KeyListeners that return true on probablyWantKey(key, saltedKey)
	 */
	private List<KeyListener> probablyWantKey(Key key, byte[] saltedKey) {
		ArrayList<KeyListener> matches = new ArrayList<KeyListener>();
		synchronized (this) {
			for (KeyListener listener : keyListeners) {
				try {
					if (!listener.probablyWantKey(key, saltedKey)) {
						continue;
					}
				} catch (Throwable t) {
					Logger.error(this, format("Error in probablyWantKey callback for %s", listener), t);
					continue;
				}
				matches.add(listener);
			}
		}
		return matches;
	}
}
