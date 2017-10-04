/**
 * Public Key Store (with LRU memory cache)
 */
package freenet.node;

import java.io.IOException;

import freenet.crypt.DSAPublicKey;
import freenet.store.BlockMetadata;
import freenet.store.GetPubkey;
import freenet.store.PubkeyStore;
import freenet.support.ByteArrayWrapper;
import freenet.support.HexUtil;
import freenet.support.LRUMap;
import freenet.support.Logger;

public class NodeGetPubkey implements GetPubkey {
	private static volatile boolean logMINOR;

	static {
		Logger.registerClass(NodeGetPubkey.class);
	}
	
	// Debugging stuff
	private static final boolean USE_RAM_PUBKEYS_CACHE = true;
	private static final int MAX_MEMORY_CACHED_PUBKEYS = 1000;
	
	private final LRUMap<ByteArrayWrapper, DSAPublicKey> cachedPubKeys;

	private PubkeyStore pubKeyDatastore;
	private PubkeyStore pubKeyDatacache;
	private PubkeyStore pubKeyClientcache;
	private PubkeyStore pubKeySlashdotcache;
	
	private final Node node;
	
	NodeGetPubkey(Node node) {
		cachedPubKeys = LRUMap.createSafeMap(ByteArrayWrapper.FAST_COMPARATOR);
		this.node = node;
	}

	void setDataStore(PubkeyStore pubKeyDatastore, PubkeyStore pubKeyDatacache) {
		this.pubKeyDatastore = pubKeyDatastore;
		this.pubKeyDatacache = pubKeyDatacache;
	}

	/* (non-Javadoc)
	 * @see freenet.node.GetPubkey#getKey(byte[], boolean, boolean, freenet.store.BlockMetadata)
	 */
	@Override
	public DSAPublicKey getKey(byte[] hash, boolean canReadClientCache, boolean forULPR, BlockMetadata meta) {
		boolean ignoreOldBlocks = !node.getWriteLocalToDatastore();
		if(canReadClientCache) ignoreOldBlocks = false;
		ByteArrayWrapper w = new ByteArrayWrapper(hash);
		if (logMINOR)
			Logger.minor(this, "Getting pubkey: " + HexUtil.bytesToHex(hash));

		if (USE_RAM_PUBKEYS_CACHE) {
			synchronized (cachedPubKeys) {
				DSAPublicKey key = cachedPubKeys.get(w);
				if (key != null) {
					cachedPubKeys.push(w, key);
					if (logMINOR)
						Logger.minor(this, "Got " + HexUtil.bytesToHex(hash) + " from in-memory cache");
					return key;
				}
			}
		}
		try {
			DSAPublicKey key = null;
			if(pubKeyClientcache != null && canReadClientCache)
				key = pubKeyClientcache.fetch(hash, false, false, meta);
			if(node.oldPKClientCache != null && canReadClientCache && key == null) {
				PubkeyStore pks = node.oldPKClientCache;
				if(pks != null) key = pks.fetch(hash, false, false, meta);
				if(key != null && logMINOR)
					Logger.minor(this, "Got "+HexUtil.bytesToHex(hash)+" from old client cache");
			}
			// We can *read* from the datastore even if nearby, but we cannot promote in that case.
			if(key == null) {
				key = pubKeyDatastore.fetch(hash, false, ignoreOldBlocks, meta);
				if(key != null && logMINOR)
					Logger.minor(this, "Got "+HexUtil.bytesToHex(hash)+" from store");
			}
			if(key == null) {
				PubkeyStore pks = node.oldPK;
				if(pks != null) key = pks.fetch(hash, false, ignoreOldBlocks, meta);
				if(key != null && logMINOR)
					Logger.minor(this, "Got "+HexUtil.bytesToHex(hash)+" from old store");
			}
			if (key == null) {
				key = pubKeyDatacache.fetch(hash, false, ignoreOldBlocks, meta);
				if(key != null && logMINOR)
					Logger.minor(this, "Got "+HexUtil.bytesToHex(hash)+" from cache");
			}
			if(key == null) {
				PubkeyStore pks = node.oldPKCache;
				if(pks != null) key = pks.fetch(hash, false, ignoreOldBlocks, meta);
				if(key != null && logMINOR)
					Logger.minor(this, "Got "+HexUtil.bytesToHex(hash)+" from old cache");
			}
			if(key == null && pubKeySlashdotcache != null && forULPR) {
				key = pubKeySlashdotcache.fetch(hash, false, ignoreOldBlocks, meta);
				if (logMINOR)
					Logger.minor(this, "Got " + HexUtil.bytesToHex(hash) + " from slashdot cache");
			}
			if (key != null) {
				// Just put into the in-memory cache
				cacheKey(hash, key, false, false, false, false, false);
			}
			return key;
		} catch (IOException e) {
			// FIXME deal with disk full, access perms etc; tell user about it.
			Logger.error(this, "Error accessing pubkey store: " + e, e);
			return null;
		}
	}

	/* (non-Javadoc)
	 * @see freenet.node.GetPubkey#cacheKey(byte[], freenet.crypt.DSAPublicKey, boolean, boolean, boolean, boolean, boolean)
	 */
	@Override
	public void cacheKey(byte[] hash, DSAPublicKey key, boolean deep, boolean canWriteClientCache, boolean canWriteDatastore, boolean forULPR, boolean writeLocalToDatastore) {
		if (logMINOR)
			Logger.minor(this, "Cache key: " + HexUtil.bytesToHex(hash) + " : " + key);
		ByteArrayWrapper w = new ByteArrayWrapper(hash);
		synchronized (cachedPubKeys) {
			DSAPublicKey key2 = cachedPubKeys.get(w);
			if ((key2 != null) && !key2.equals(key))
				throw new IllegalArgumentException("Wrong hash?? Already have different key with same hash!");
			cachedPubKeys.push(w, key);
			while (cachedPubKeys.size() > MAX_MEMORY_CACHED_PUBKEYS)
				cachedPubKeys.popKey();
		}
		try {
			if (canWriteClientCache && !(canWriteDatastore || writeLocalToDatastore)) {
				if(pubKeyClientcache != null) {
					pubKeyClientcache.put(key, false);
				}
			}
			if (forULPR && !(canWriteDatastore || writeLocalToDatastore)) {
				if(pubKeySlashdotcache!= null) {
					pubKeySlashdotcache.put(key, false);
				}
			}
			// Cannot write to the store or cache if request started nearby.
			if(!(canWriteDatastore || writeLocalToDatastore)) return;
			if (deep) {
				pubKeyDatastore.put(key, !canWriteDatastore);
			}
			pubKeyDatacache.put(key, !canWriteDatastore);
		} catch (IOException e) {
			// FIXME deal with disk full, access perms etc; tell user about it.
			Logger.error(this, "Error accessing pubkey store: " + e, e);
		}
	}

	public void setLocalDataStore(PubkeyStore pubKeyClientcache) {
		this.pubKeyClientcache = pubKeyClientcache;
	}
	
	public void setLocalSlashdotcache(PubkeyStore pubKeySlashdotcache) {
		this.pubKeySlashdotcache = pubKeySlashdotcache;
	}
}
