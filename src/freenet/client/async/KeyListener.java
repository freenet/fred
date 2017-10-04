package freenet.client.async;

import freenet.keys.Key;
import freenet.keys.KeyBlock;
import freenet.node.SendableGet;

/**
 * Transient object created on startup for persistent requests (or at creation
 * time for non-persistent requests), to monitor the stream of successfully
 * fetched keys. If a key appears interesting, we schedule a job on the database
 * thread to double-check and process the data if we still want it.
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 * 
 * saltedKey is the routing key from the key, salted globally (concat a global
 * salt value and then SHA) in order to save some cycles. Implementations that
 * use two internal bloom filters may need to have an additional local salt, as
 * in SplitFileFetcherKeyListener.
 */
public interface KeyListener {
	
	/**
	 * Fast guess at whether we want a key or not. Usually implemented by a 
	 * bloom filter.
	 * LOCKING: Should avoid external locking if possible. Will be called
	 * within the CRSBase lock.
	 * @return True if we probably want the key. False if we definitely don't
	 * want it.
	 */
	public boolean probablyWantKey(Key key, byte[] saltedKey);
	
	/**
	 * Do we want the key? This is called by the ULPR code, because fetching the
	 * key will involve significant work. tripPendingKey() on the other hand
	 * will go straight to handleBlock().
	 * @return -1 if we don't want the key, otherwise the priority of the request
	 * interested in the key.
	 */
	public short definitelyWantKey(Key key);

	/**
	 * Find the requests related to a specific key, used in retrying after cooldown.
	 * Caller should call probablyWantKey() first.
	 */
	public SendableGet[] getRequestsForKey(Key key);
	
	/**
	 * Handle the found data, if we really want it.
	 */
	public boolean handleBlock(Key key, byte[] saltedKey, KeyBlock found, ClientContext context);
	
	/**
	 * Is this related to a persistent request?
	 */
	boolean persistent();

	/**
	 * Priority of the associated request.
	 * LOCKING: Should avoid external locking if possible. Will be called
	 * within the CRSBase lock.
	 */
	short getPriorityClass();

	public long countKeys();

	/**
	 * @return The parent HasKeyListener. This does mean it will be pinned in
	 * RAM, but it can be deactivated so it's not a big deal.
	 * LOCKING: Should avoid external locking if possible. Will be called
	 * within the CRSBase lock.
	 */
	public HasKeyListener getHasKeyListener();

	/**
	 * Deactivate the request once it has been removed.
	 */
	public void onRemove();
	
	/**
	 * Has the request finished? If every key has been found, or enough keys have
	 * been found, return true so that the caller can remove it from the list.
	 */
	public boolean isEmpty();

	public boolean isSSK();

}
