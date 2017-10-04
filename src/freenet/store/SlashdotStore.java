package freenet.store;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import freenet.keys.KeyVerifyException;
import freenet.node.stats.StoreAccessStats;
import freenet.node.useralerts.UserAlertManager;
import freenet.support.ByteArrayWrapper;
import freenet.support.LRUMap;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Ticker;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;
import freenet.support.io.TempBucketFactory;

/** Short-term cache. Used to cache all blocks retrieved in the last 30 minutes (on low 
 * security levels), or just to cache data fetched through ULPRs (on higher security levels).
 * - Strict LRU.
 * - Size limit.
 * - Strictly enforced time limit.
 * - Blocks are encrypted, and kept in temp files.
 * 
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class SlashdotStore<T extends StorableBlock> implements FreenetStore<T> {

	private static volatile boolean logDEBUG;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}
	
	private class DiskBlock {
		Bucket data;
		long lastAccessed;
	}
	
	private final TempBucketFactory bf;
	
	private long maxLifetime;
	
	private final long purgePeriod;
	
	// PURGING OLD DATA:
	// Every X period? I don't think it matters if we're a few minutes out, and it's probably easiest that way...
	
	private final Ticker ticker;
	
	private final LRUMap<ByteArrayWrapper, DiskBlock> blocksByRoutingKey;
	
	private final StoreCallback<T> callback;
	
	private int maxKeys;
	
	private long hits;
	private long misses;
	private long writes;
	
	private final int headerSize;
	private final int dataSize;
	private final int fullKeySize;
	
	public SlashdotStore(StoreCallback<T> callback, int maxKeys, long maxLifetime, long purgePeriod, Ticker ticker, TempBucketFactory tbf) {
		this.callback = callback;
		this.blocksByRoutingKey = LRUMap.createSafeMap(ByteArrayWrapper.FAST_COMPARATOR);
		this.maxKeys = maxKeys;
		this.bf = tbf;
		this.ticker = ticker;
		this.maxLifetime = maxLifetime;
		this.purgePeriod = purgePeriod;
		callback.setStore(this);
		this.headerSize = callback.headerLength();
		this.dataSize = callback.dataLength();
		this.fullKeySize = callback.fullKeyLength();
		Runnable purgeOldData = new Runnable() {

			@Override
			public void run() {
				try {
					purgeOldData();
				} finally {
					SlashdotStore.this.ticker.queueTimedJob(this, SlashdotStore.this.purgePeriod);
				}
			}

		};
		ticker.queueTimedJob(purgeOldData, maxLifetime + purgePeriod);
	}
	
	/**
	 * @param meta IGNORED!
	 */
	@Override
	public T fetch(byte[] routingKey, byte[] fullKey, boolean dontPromote, boolean canReadClientCache, boolean canReadSlashdotCache, boolean ignoreOldBlocks, BlockMetadata meta) throws IOException {
		ByteArrayWrapper key = new ByteArrayWrapper(routingKey);
		DiskBlock block;
		long timeAccessed;
		synchronized(this) {
			block = blocksByRoutingKey.get(key);
			if(block == null) {
				misses++;
				return null;
			}
			timeAccessed = block.lastAccessed;
		}
		byte[] fk = new byte[fullKeySize];
		byte[] header = new byte[headerSize];
		byte[] data = new byte[dataSize];
		InputStream in = block.data.getInputStream();
		try {
			DataInputStream dis = new DataInputStream(in);
			dis.readFully(fk);
			dis.readFully(header);
			dis.readFully(data);
		} finally {
			in.close();
		}
		try {
			T ret =
				callback.construct(data, header, fk, canReadClientCache, canReadSlashdotCache, null, null);
			synchronized(this) {
				hits++;
				if(!dontPromote) {
					block.lastAccessed = System.currentTimeMillis();
					blocksByRoutingKey.push(key, block);
				}
			}
			if(logDEBUG) Logger.debug(this, "Block was last accessed "+(System.currentTimeMillis() - timeAccessed)+"ms ago");
			return ret;
		} catch (KeyVerifyException e) {
			block.data.free();
			synchronized(this) {
				blocksByRoutingKey.removeKey(key);
				misses++;
			}
			return null;
		}
	}

	@Override
	public long getBloomFalsePositive() {
		return -1;
	}

	@Override
	public long getMaxKeys() {
		return maxKeys;
	}

	@Override
	public long hits() {
		return hits;
	}

	@Override
	public long keyCount() {
		return blocksByRoutingKey.size();
	}

	@Override
	public long misses() {
		return misses;
	}

	@Override
	public boolean probablyInStore(byte[] routingKey) {
		ByteArrayWrapper key = new ByteArrayWrapper(routingKey);
		return blocksByRoutingKey.containsKey(key);
	}

	/**
	 * @param isOldBlock Ignored, we don't distinguish between stuff that should be cached and
	 * stuff that shouldn't be cached; really it's all in the latter category anyway here!
	 */
	@Override
	public void put(T block, byte[] data, byte[] header, boolean overwrite, boolean isOldBlock) throws IOException, KeyCollisionException {
		byte[] routingkey = block.getRoutingKey();
		byte[] fullKey = block.getFullKey();
		
		Bucket bucket = bf.makeBucket(fullKeySize + dataSize + headerSize);
		OutputStream os = bucket.getOutputStream();
		try {
		os.write(fullKey);
		os.write(header);
		os.write(data);
		} finally {
		os.close();
		}
		
		DiskBlock stored = new DiskBlock();
		stored.data = bucket;
		purgeOldData(new ByteArrayWrapper(routingkey), stored);
	}

	@Override
	public void setMaxKeys(long maxStoreKeys, boolean shrinkNow) throws IOException {
		if(maxStoreKeys > Integer.MAX_VALUE) throw new IllegalArgumentException();
		this.maxKeys = (int) maxStoreKeys;
		if(shrinkNow) {
			purgeOldData();
		} else {
			ticker.queueTimedJob(new Runnable() {

				@Override
				public void run() {
					purgeOldData();
					// Don't re-schedule
				}
				
			}, 0);
		}
	}

	@Override
	public long writes() {
		return writes;
	}

	protected void purgeOldData() {
		purgeOldData(null, null);
	}
	
	protected void purgeOldData(ByteArrayWrapper key, DiskBlock addFirst) {
		List<DiskBlock> blocks = null;
		DiskBlock oldBlock;
		synchronized(this) {
			long now = System.currentTimeMillis();
			if(addFirst != null) {
				addFirst.lastAccessed = now;
				oldBlock = blocksByRoutingKey.push(key, addFirst);
				if(oldBlock != null) {
	                if(blocks == null) blocks = new ArrayList<DiskBlock>();
	                blocks.add(oldBlock);
				}
				writes++;
			}
			while(true) {
				if(blocksByRoutingKey.isEmpty()) break;
				DiskBlock block = blocksByRoutingKey.peekValue();
				if(now - block.lastAccessed < maxLifetime && blocksByRoutingKey.size() < maxKeys) break;
				if(blocks == null) blocks = new ArrayList<DiskBlock>();
				blocks.add(block);
				blocksByRoutingKey.popValue();
			}
		}
		if(blocks == null) return;
		for(DiskBlock block : blocks) {
			block.data.free();
		}
	}

	public synchronized Long getLifetime() {
		return maxLifetime;
	}

	public synchronized void setLifetime(Long val) {
		maxLifetime = val;
	}
	
	@Override
	public StoreAccessStats getSessionAccessStats() {
		return new StoreAccessStats() {

			@Override
			public long hits() {
				return hits;
			}

			@Override
			public long misses() {
				return misses;
			}

			@Override
			public long falsePos() {
				return 0;
			}

			@Override
			public long writes() {
				return writes;
			}
			
		};
	}

	@Override
	public StoreAccessStats getTotalAccessStats() {
		return null;
	}

	@Override
	public boolean start(Ticker ticker, boolean longStart) throws IOException {
		return false;
	}

	@Override
	public void setUserAlertManager(UserAlertManager userAlertManager) {
		// Do nothing
	}

	@Override
	public FreenetStore<T> getUnderlyingStore() {
		return this;
	}

	@Override
	public void close() {
		// Do nothing
	}
}
