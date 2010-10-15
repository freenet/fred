/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.store;

import java.io.IOException;

import com.sleepycat.je.DatabaseException;

import freenet.crypt.DSAPublicKey;
import freenet.keys.KeyVerifyException;

import freenet.support.math.LinearRateEstimate;

/**
 * @author toad
 */
public abstract class StoreCallback<T extends StorableBlock> {
	
	/** Length of a data block. Fixed for lifetime of the store. */
	public abstract int dataLength();
	
	/** Length of a header block. Fixed for the lifetime of the store. */
	public abstract int headerLength();
	
	/** Length of a routing key. Routing key is what we use to search for a block. Also fixed. */
	public abstract int routingKeyLength();
	
	/** Whether we should create a .keys file to keep full keys in in order to reconstruct. */
	public abstract boolean storeFullKeys();
	
	/** Whether we need the key in order to reconstruct a block. */
	public abstract boolean constructNeedsKey();
	
	/** Length of a full key. Full keys are stored in the .keys file. Also fixed. */
	public abstract int fullKeyLength();
	
	/** Can the same key be valid for two different StorableBlocks? */
	public abstract boolean collisionPossible();
	
	protected FreenetStore<T> store;


	
	/** Called once when first connecting to a FreenetStore. Package-local. */
	public void setStore(FreenetStore<T> store) {
		this.store = store;
	}
	
	public FreenetStore<T> getStore() {
		return store;
	}
	
	// Reconstruction
	
	/** Construct a StorableBlock from the data, headers, and optionally routing key or full key.
	 * IMPORTANT: Using the full key or routing key is OPTIONAL, and if we don't use them, WE DON'T
	 * CHECK THEM EITHER! Caller MUST check that the key is the one expected.
	 * @throws KeyVerifyException */
	public abstract T construct(byte[] data, byte[] headers, byte[] routingKey, byte[] fullKey, boolean canReadClientCache, boolean canReadSlashdotCache, BlockMetadata meta, DSAPublicKey knownPubKey)
	        throws KeyVerifyException;
	
	public void setMaxKeys(long maxStoreKeys, boolean shrinkNow) throws DatabaseException, IOException {
		store.setMaxKeys(maxStoreKeys, shrinkNow);
	}
    
    public long getMaxKeys() {
    	return store.getMaxKeys();
    }
	
	public long hits() {
		return store.hits();
	}
	
	public long misses() {
		return store.misses();
	}
	
	public long writes() {
		return store.writes();
	}

	public static final int RATE_ESTIMATE_UPDATE_INTERVAL = 3000;    // milliseconds between samples
	public static final int RATE_ESTIMATE_HISTORY_DURATION = 60000;  // duration over which the rate estimate is performed (in milliseconds)
	private final LinearRateEstimate accessRateEstimate = new LinearRateEstimate(RATE_ESTIMATE_HISTORY_DURATION, RATE_ESTIMATE_UPDATE_INTERVAL);
	private final LinearRateEstimate writeRateEstimate = new LinearRateEstimate(RATE_ESTIMATE_HISTORY_DURATION, RATE_ESTIMATE_UPDATE_INTERVAL);

	public void updateRateEstimates() {
		accessRateEstimate.report(hits()+misses());
		writeRateEstimate.report(writes());
	}

	public double accessRate() {
		return accessRateEstimate.currentValue();
	}

	public double writeRate() {
		return writeRateEstimate.currentValue();
	}

	public long keyCount() {
		return store.keyCount();
	}
	
	public long getBloomFalsePositive() {
		return store.getBloomFalsePositive();
	}

	/** Generate a routing key from a full key */
	public abstract byte[] routingKeyFromFullKey(byte[] keyBuf);
}
