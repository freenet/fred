package freenet.store.caching;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import freenet.crypt.DSAGroup;
import freenet.crypt.DSAPrivateKey;
import freenet.crypt.DSAPublicKey;
import freenet.crypt.DummyRandomSource;
import freenet.crypt.Global;
import freenet.crypt.RandomSource;
import freenet.crypt.SHA256;
import freenet.keys.CHKBlock;
import freenet.keys.CHKDecodeException;
import freenet.keys.CHKEncodeException;
import freenet.keys.CHKVerifyException;
import freenet.keys.ClientCHK;
import freenet.keys.ClientCHKBlock;
import freenet.keys.ClientSSK;
import freenet.keys.ClientSSKBlock;
import freenet.keys.InsertableClientSSK;
import freenet.keys.Key;
import freenet.keys.KeyDecodeException;
import freenet.keys.NodeSSK;
import freenet.keys.SSKBlock;
import freenet.keys.SSKEncodeException;
import freenet.keys.SSKVerifyException;
import freenet.node.SemiOrderedShutdownHook;
import freenet.store.CHKStore;
import freenet.store.GetPubkey;
import freenet.store.KeyCollisionException;
import freenet.store.PubkeyStore;
import freenet.store.RAMFreenetStore;
import freenet.store.SSKStore;
import freenet.store.SimpleGetPubkey;
import freenet.store.WriteBlockableFreenetStore;
import freenet.store.saltedhash.ResizablePersistentIntBuffer;
import freenet.store.saltedhash.SaltedHashFreenetStore;
import freenet.support.Fields;
import freenet.support.PooledExecutor;
import freenet.support.SimpleReadOnlyArrayBucket;
import freenet.support.Ticker;
import freenet.support.TrivialTicker;
import freenet.support.api.Bucket;
import freenet.support.compress.Compressor;
import freenet.support.compress.InvalidCompressionCodecException;
import freenet.support.io.ArrayBucketFactory;
import freenet.support.io.BucketTools;
import freenet.support.io.FileUtil;

/**
 * CachingFreenetStoreTest Test for CachingFreenetStore
 *
 * @author Simon Vocella <voxsim@gmail.com>
 *
 *         FIXME lots of repeated code, factor out.
 */
public class CachingFreenetStoreTest {
	
	private static final File TEMP_DIR = new File("tmp-CachingFreenetStoreTest");

	private Random weakPRNG = new Random(12340);
	private PooledExecutor exec = new PooledExecutor();
	private Ticker ticker = new TrivialTicker(exec);
	private long cachingFreenetStoreMaxSize = Fields.parseLong("1M");
	private long cachingFreenetStorePeriod = Fields.parseLong("300k");

	@BeforeClass
	public static void setupClass() {
		FileUtil.removeAll(TEMP_DIR);

		if(! TEMP_DIR.mkdir()) {
			throw new IllegalStateException("Could not create temporary directory for store tests");
		}
	}

	@Before
	public void setUpTest() {
		ResizablePersistentIntBuffer.setPersistenceTime(-1);
		exec.start();
	}

	@AfterClass
	public static void cleanup() {
		FileUtil.removeAll(TEMP_DIR);
	}

	private File getStorePath(String testname) {
		File storePath = new File(TEMP_DIR, "CachingFreenetStoreTest_" + testname);
		FileUtil.removeAll(storePath);
		if( ! storePath.mkdirs() ) {
			throw new IllegalStateException("Could not create temporary test store path: " + storePath);
		}
		return storePath;
	}

	/* Simple test with CHK for CachingFreenetStore */
	@Test
 	public void testSimpleCHK() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		CHKStore store = new CHKStore();
		File f = getStorePath("testSimpleCHK");
		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "testCachingFreenetStoreCHK",
				store, weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(cachingFreenetStoreMaxSize,
					cachingFreenetStorePeriod, ticker);
			try (CachingFreenetStore<CHKBlock> cachingStore = new CachingFreenetStore<CHKBlock>(store, saltStore, tracker)) {
				cachingStore.start(null, true);

				for (int i = 0; i < 5; i++) {
					String test = "test" + i;
					ClientCHKBlock block = encodeBlockCHK(test);
					store.put(block.getBlock(), false);

					ClientCHK key = block.getClientKey();
					// Check that it's in the cache, *not* the underlying store.
					assertEquals(null, saltStore.fetch(key.getRoutingKey(), key.getNodeCHK().getFullKey(), false, false, false, false, null));
					CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
					String data = decodeBlockCHK(verify, key);
					assertEquals(test, data);
				}
			}
		}
	}

	/*
	 * Check that if the size limit is 0 (and therefore presumably if it is smaller
	 * than the key being cached), we will pass through immediately.
	 */
	@Test
 	public void testZeroSize() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {

		File f = getStorePath("testZeroSize");
		CHKStore store = new CHKStore();
		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "testCachingFreenetStoreCHK",
				store, weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(0, cachingFreenetStorePeriod, ticker);
			try (CachingFreenetStore<CHKBlock> cachingStore = new CachingFreenetStore<CHKBlock>(store, saltStore, tracker)) {
				cachingStore.start(null, true);

				for (int i = 0; i < 5; i++) {
					String test = "test" + i;
					ClientCHKBlock block = encodeBlockCHK(test);
					store.put(block.getBlock(), false);

					ClientCHK key = block.getClientKey();
					// It should pass straight through.
					assertNotNull( saltStore.fetch(key.getRoutingKey(), key.getNodeCHK().getFullKey(), false, false, false, false, null));
					CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
					String data = decodeBlockCHK(verify, key);
					assertEquals(test, data);
				}
			}
		}
	}

	class WaitableCachingFreenetStoreTracker extends CachingFreenetStoreTracker {
		/* Don't reuse (this), avoid changing locking behaviour of parent class */
		private final Object sync = new Object();

		public WaitableCachingFreenetStoreTracker(long cachingFreenetStoreMaxSize, long cachingFreenetStorePeriod,
				Ticker ticker) {
			super(cachingFreenetStoreMaxSize, cachingFreenetStorePeriod, ticker);
		}

		@Override
		void pushAllCachingStores() {
			super.pushAllCachingStores();
			synchronized (sync) {
				sync.notifyAll();
			}
		}

		public void waitForZero() throws InterruptedException {
			synchronized (sync) {
				while (getSizeOfCache() > 0)
					sync.wait();
			}
		}
	}

	/*
	 * Check that if we are going over the maximum size, the caching store will call
	 * pushAll and all blocks is in the *undelying* store and the size is 0
	 */
	@Test
 	public void testOverMaximumSize()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException, InterruptedException {
		File f = getStorePath("testOverMaximumSize");

		String test = "test0";
		ClientCHKBlock block = encodeBlockCHK(test);
		byte[] data = block.getBlock().getRawData();
		byte[] header = block.getBlock().getRawHeaders();
		byte[] routingKey = block.getBlock().getRoutingKey();
		long sizeBlock = data.length + header.length + block.getBlock().getFullKey().length + routingKey.length;
		int howManyBlocks = ((int) (cachingFreenetStoreMaxSize / sizeBlock)) + 1;

		CHKStore store = new CHKStore();

		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "testCachingFreenetStoreCHK",
				store, weakPRNG, howManyBlocks * 5, false, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			WaitableCachingFreenetStoreTracker tracker = new WaitableCachingFreenetStoreTracker(cachingFreenetStoreMaxSize,
					cachingFreenetStorePeriod, ticker);
			try (CachingFreenetStore<CHKBlock> cachingStore = new CachingFreenetStore<CHKBlock>(store, saltStore, tracker)) {
				cachingStore.start(null, true);
				List<ClientCHKBlock> chkBlocks = new ArrayList<ClientCHKBlock>();
				List<String> tests = new ArrayList<String>();

				store.put(block.getBlock(), false);
				chkBlocks.add(block);
				tests.add(test);

				for (int i = 1; i < howManyBlocks; i++) {
					test = "test" + i;
					tests.add(test);

					block = encodeBlockCHK(test);
					store.put(block.getBlock(), false);
					chkBlocks.add(block);
				}

				tracker.waitForZero();

				boolean atLeastOneKey = false;
				for (int i = 0; i < howManyBlocks; i++) {
					test = tests.get(i);
					block = chkBlocks.get(i);
					ClientCHK key = block.getClientKey();

					CHKBlock verifyInStore = saltStore.fetch(key.getRoutingKey(), key.getNodeCHK().getFullKey(), false, false,
							false, false, null);
					// Since SaltedHashFreenetStore is loosy, it might have been replaced in a
					// collision
					if (verifyInStore == null) {
						continue;
					}
					// If its in the Store, it should be obtainable through the Cache
					CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
					String receivedData = decodeBlockCHK(verify, key);
					assertEquals(test, receivedData);

					atLeastOneKey = true;
				}

				assertTrue("At least one key should have matched", atLeastOneKey);
			}
		}
	}

	@Test
 	public void testCollisionsOverMaximumSize()
			throws IOException, SSKEncodeException, InvalidCompressionCodecException, InterruptedException {
		PubkeyStore pk = new PubkeyStore();
		new RAMFreenetStore<DSAPublicKey>(pk, 10);
		GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
		SSKStore store = new SSKStore(pubkeyCache);
		int sskBlockSize = store.getTotalBlockSize();

		// Create a cache with size limit of 1.5 SSK's.
		File f = getStorePath("testCollisionsOverMaximumSize");
		try (SaltedHashFreenetStore<SSKBlock> saltStore = SaltedHashFreenetStore.construct(f, "testCachingFreenetStoreSSK",
				store, weakPRNG, 20, true, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			WaitableCachingFreenetStoreTracker tracker = new WaitableCachingFreenetStoreTracker((sskBlockSize * 3) / 2,
					cachingFreenetStorePeriod, ticker);
			try (CachingFreenetStore<SSKBlock> cachingStore = new CachingFreenetStore<SSKBlock>(store, saltStore, tracker)) {
				cachingStore.start(null, true);
				RandomSource random = new DummyRandomSource(12345);

				final int CRYPTO_KEY_LENGTH = 32;
				byte[] ckey = new byte[CRYPTO_KEY_LENGTH];
				random.nextBytes(ckey);
				DSAGroup g = Global.DSAgroupBigA;
				DSAPrivateKey privKey = new DSAPrivateKey(g, random);
				DSAPublicKey pubKey = new DSAPublicKey(g, privKey);
				byte[] pkHash = SHA256.digest(pubKey.asBytes());
				String docName = "myDOC";
				InsertableClientSSK ik = new InsertableClientSSK(docName, pkHash, pubKey, privKey, ckey,
						Key.ALGO_AES_PCFB_256_SHA256);

				// Write one key to the store.

				String test = "test";
				SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(test.getBytes("UTF-8"));
				ClientSSKBlock block = ik.encode(bucket, false, false, (short) -1, bucket.size(), random,
						Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
				SSKBlock sskBlock = (SSKBlock) block.getBlock();
				pubkeyCache.cacheKey(sskBlock.getKey().getPubKeyHash(), sskBlock.getPubKey(), false, false, false, false,
						false);
				try {
					store.put(sskBlock, false, false);
				} catch (KeyCollisionException e1) {
					fail();
				}

				assertEquals(sskBlockSize, tracker.getSizeOfCache());

				// Write a colliding key.
				test = "test1";
				bucket = new SimpleReadOnlyArrayBucket(test.getBytes("UTF-8"));
				block = ik.encode(bucket, false, false, (short) -1, bucket.size(), random,
						Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
				sskBlock = (SSKBlock) block.getBlock();
				try {
					store.put(sskBlock, false, false);
					fail();
				} catch (KeyCollisionException e) {
					// Expected.
				}
				try {
					store.put(sskBlock, true, false);
				} catch (KeyCollisionException e) {
					fail();
				}

				// Size is still one key.
				assertEquals(sskBlockSize, tracker.getSizeOfCache());

				// Write a second key, should trigger write to disk.
				DSAPrivateKey privKey2 = new DSAPrivateKey(g, random);
				DSAPublicKey pubKey2 = new DSAPublicKey(g, privKey2);
				byte[] pkHash2 = SHA256.digest(pubKey2.asBytes());
				InsertableClientSSK ik2 = new InsertableClientSSK(docName, pkHash2, pubKey2, privKey2, ckey,
						Key.ALGO_AES_PCFB_256_SHA256);
				block = ik2.encode(bucket, false, false, (short) -1, bucket.size(), random,
						Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
				SSKBlock sskBlock2 = (SSKBlock) block.getBlock();
				pubkeyCache.cacheKey(sskBlock2.getKey().getPubKeyHash(), sskBlock2.getPubKey(), false, false, false, false,
						false);

				try {
					store.put(sskBlock2, false, false);
				} catch (KeyCollisionException e) {
					fail();
				}

				// Wait for it to write to disk.
				tracker.waitForZero();

				assertTrue(store.fetch(sskBlock.getKey(), false, false, false, false, null).equals(sskBlock));
				assertTrue(store.fetch(sskBlock2.getKey(), false, false, false, false, null).equals(sskBlock2));
			}
		}
	}

	@Test
 	public void testSimpleManualWrite()
			throws IOException, SSKEncodeException, InvalidCompressionCodecException, InterruptedException {

		PubkeyStore pk = new PubkeyStore();
		new RAMFreenetStore<DSAPublicKey>(pk, 10);
		GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
		SSKStore store = new SSKStore(pubkeyCache);
		int sskBlockSize = store.getTotalBlockSize();

		File f = getStorePath("testSimpleManualWrite");
		try (SaltedHashFreenetStore<SSKBlock> saltStore = SaltedHashFreenetStore.construct(f, "testCachingFreenetStoreSSK",
				store, weakPRNG, 20, true, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker((sskBlockSize * 3), cachingFreenetStorePeriod,
					ticker);
			try (CachingFreenetStore<SSKBlock> cachingStore = new CachingFreenetStore<SSKBlock>(store, saltStore, tracker)) {
				cachingStore.start(null, true);
				RandomSource random = new DummyRandomSource(12345);

				final int CRYPTO_KEY_LENGTH = 32;
				byte[] ckey = new byte[CRYPTO_KEY_LENGTH];
				random.nextBytes(ckey);
				DSAGroup g = Global.DSAgroupBigA;
				DSAPrivateKey privKey = new DSAPrivateKey(g, random);
				DSAPublicKey pubKey = new DSAPublicKey(g, privKey);
				byte[] pkHash = SHA256.digest(pubKey.asBytes());
				String docName = "myDOC";
				InsertableClientSSK ik = new InsertableClientSSK(docName, pkHash, pubKey, privKey, ckey,
						Key.ALGO_AES_PCFB_256_SHA256);

				// Nothing to write.
				assertTrue(tracker.getSizeOfCache() == 0);
				assert (cachingStore.pushLeastRecentlyBlock() == -1);

				// Write one key to the store.

				String test = "test";
				SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(test.getBytes("UTF-8"));
				ClientSSKBlock block = ik.encode(bucket, false, false, (short) -1, bucket.size(), random,
						Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
				SSKBlock sskBlock = (SSKBlock) block.getBlock();
				pubkeyCache.cacheKey(sskBlock.getKey().getPubKeyHash(), sskBlock.getPubKey(), false, false, false, false,
						false);
				try {
					store.put(sskBlock, false, false);
				} catch (KeyCollisionException e1) {
					fail();
				}

				// Write.
				assertEquals(tracker.getSizeOfCache(), sskBlockSize);
				assertEquals(cachingStore.pushLeastRecentlyBlock(), sskBlockSize);

				// Nothing to write.
				assertEquals(cachingStore.pushLeastRecentlyBlock(), -1);
			}
		}
	}

	/**
	 * pushLeastRecentlyBlock() with collisions: Lock { Grab a block for key K. (Do
	 * not remove it) } Write the block. Lock { Detected a different block for key
	 * K. Return 0 rather than removing it. }
	 */
	@Test
 	public void testManualWriteCollision() throws IOException, SSKEncodeException, InvalidCompressionCodecException,
			InterruptedException, ExecutionException {

		PubkeyStore pk = new PubkeyStore();
		RAMFreenetStore<DSAPublicKey> ramFreenetStore = new RAMFreenetStore<DSAPublicKey>(pk, 10);
		pk.setStore(ramFreenetStore);

		GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
		SSKStore store = new SSKStore(pubkeyCache);
		int sskBlockSize = store.getTotalBlockSize();

		File f = getStorePath("testManualWriteCollision");
		try (SaltedHashFreenetStore<SSKBlock> saltStore = SaltedHashFreenetStore.construct(f, "testCachingFreenetStoreSSK",
				store, weakPRNG, 20, true, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			// Don't let the write complete until we say so...
			WriteBlockableFreenetStore<SSKBlock> delayStore = new WriteBlockableFreenetStore<SSKBlock>(saltStore, true);
			CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker((sskBlockSize * 3), cachingFreenetStorePeriod,
					ticker);
			try (final CachingFreenetStore<SSKBlock> cachingStore = new CachingFreenetStore<SSKBlock>(store, delayStore,
					tracker)) {
				cachingStore.start(null, true);
				RandomSource random = new DummyRandomSource(12345);

				final int CRYPTO_KEY_LENGTH = 32;
				byte[] ckey = new byte[CRYPTO_KEY_LENGTH];
				random.nextBytes(ckey);
				DSAGroup g = Global.DSAgroupBigA;
				DSAPrivateKey privKey = new DSAPrivateKey(g, random);
				DSAPublicKey pubKey = new DSAPublicKey(g, privKey);
				byte[] pkHash = SHA256.digest(pubKey.asBytes());
				String docName = "myDOC";
				InsertableClientSSK ik = new InsertableClientSSK(docName, pkHash, pubKey, privKey, ckey,
						Key.ALGO_AES_PCFB_256_SHA256);

				// Nothing to write.
				assertTrue(tracker.getSizeOfCache() == 0);
				assertEquals(cachingStore.pushLeastRecentlyBlock(), -1);

				// Write one key to the cache. It will not be written through to disk.
				String test = "test";
				SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(test.getBytes("UTF-8"));
				ClientSSKBlock block = ik.encode(bucket, false, false, (short) -1, bucket.size(), random,
						Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
				SSKBlock sskBlock = (SSKBlock) block.getBlock();
				pubkeyCache.cacheKey(sskBlock.getKey().getPubKeyHash(), sskBlock.getPubKey(), false, false, false, false,
						false);
				try {
					store.put(sskBlock, false, false);
				} catch (KeyCollisionException e1) {
					fail();
				}

				FutureTask<Long> future = new FutureTask<Long>(new Callable<Long>() {

					@Override
					public Long call() throws Exception {
						return cachingStore.pushLeastRecentlyBlock();
					}

				});
				Executors.newCachedThreadPool().execute(future);

				delayStore.waitForSomeBlocked();

				// Write colliding key. Should cause the write above to return 0: After it
				// unlocks, it will see
				// there is a new, different block for that key, and therefore it cannot remove
				// the block, and
				// thus must return 0.
				test = "test1";
				bucket = new SimpleReadOnlyArrayBucket(test.getBytes("UTF-8"));
				block = ik.encode(bucket, false, false, (short) -1, bucket.size(), random,
						Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
				SSKBlock sskBlock2 = (SSKBlock) block.getBlock();
				try {
					store.put(sskBlock2, false, false);
					fail();
				} catch (KeyCollisionException e) {
					// Expected.
				}
				try {
					store.put(sskBlock2, true, false);
				} catch (KeyCollisionException e) {
					fail();
				}

				// Size is still one key.
				assertTrue(tracker.getSizeOfCache() == sskBlockSize);

				// Now let the write through.
				delayStore.setBlocked(false);

				assertEquals(future.get().longValue(), 0L);
				NodeSSK key = sskBlock.getKey();
				assertTrue(
						saltStore.fetch(key.getRoutingKey(), key.getFullKey(), false, false, false, false, null).equals(sskBlock));
				assertTrue(store.fetch(key, false, false, false, false, null).equals(sskBlock2));

				// Still needs writing.
				assertEquals(cachingStore.pushLeastRecentlyBlock(), sskBlockSize);
				assertTrue(store.fetch(key, false, false, false, false, null).equals(sskBlock2));
			}
		}
	}

	/* Simple test with SSK for CachingFreenetStore */
	@Test
 	public void testSimpleSSK() throws IOException, KeyCollisionException, SSKVerifyException, KeyDecodeException,
			SSKEncodeException, InvalidCompressionCodecException {

		final int keys = 5;
		PubkeyStore pk = new PubkeyStore();
		RAMFreenetStore<DSAPublicKey> ramFreenetStore = new RAMFreenetStore<DSAPublicKey>(pk, keys);
		pk.setStore(ramFreenetStore);

		GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
		SSKStore store = new SSKStore(pubkeyCache);
		File f = getStorePath("testSimpleSSK");
		try (SaltedHashFreenetStore<SSKBlock> saltStore = SaltedHashFreenetStore.construct(f, "testCachingFreenetStoreSSK",
				store, weakPRNG, 20, true, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(cachingFreenetStoreMaxSize,
					cachingFreenetStorePeriod, ticker);
			try (CachingFreenetStore<SSKBlock> cachingStore = new CachingFreenetStore<SSKBlock>(store, saltStore, tracker)) {
				cachingStore.start(null, true);
				RandomSource random = new DummyRandomSource(12345);

				for (int i = 0; i < 5; i++) {
					String test = "test" + i;
					ClientSSKBlock block = encodeBlockSSK(test, random);
					SSKBlock sskBlock = (SSKBlock) block.getBlock();
					store.put(sskBlock, false, false);

					ClientSSK key = block.getClientKey();
					NodeSSK ssk = (NodeSSK) key.getNodeKey();
					pubkeyCache.cacheKey(ssk.getPubKeyHash(), ssk.getPubKey(), false, false, false, false, false);
					// Check that it's in the cache, *not* the underlying store.
					assertNull(saltStore.fetch(ssk.getRoutingKey(), ssk.getFullKey(), false, false, false, false, null));
					SSKBlock verify = store.fetch(ssk, false, false, false, false, null);
					String data = decodeBlockSSK(verify, key);
					assertEquals(test, data);
				}
			}
		}
	}

	/* Test to re-open after close */
	@Test
 	public void testOnCloseCHK() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {

		CHKStore store = new CHKStore();
		File f = getStorePath("testOnCloseCHK");
		List<String> tests = new ArrayList<String>();
		List<ClientCHKBlock> chkBlocks = new ArrayList<ClientCHKBlock>();
		CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(cachingFreenetStoreMaxSize,
				cachingFreenetStorePeriod, ticker);

		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f,
				"testCachingFreenetStoreOnClose", store, weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true, ticker,
				null)) {
			try (CachingFreenetStore<CHKBlock> cachingStore = new CachingFreenetStore<CHKBlock>(store, saltStore, tracker)) {
				cachingStore.start(null, true);

				// Insert Keys
				for (int i = 0; i < 5; i++) {
					String test = "test" + i;
					ClientCHKBlock block = encodeBlockCHK(test);
					store.put(block.getBlock(), false);
					tests.add(test);
					chkBlocks.add(block);

					// Check that it's in the cache, *not* the underlying store.
					assertNull(saltStore.fetch(block.getKey().getRoutingKey(), block.getKey().getFullKey(), false, false, false,
							false, null));
				}
			}
		}

		store = new CHKStore();
		try (SaltedHashFreenetStore<CHKBlock> saltStore2 = SaltedHashFreenetStore.construct(f,
				"testCachingFreenetStoreOnClose", store, weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true, ticker,
				null)) {
			try (CachingFreenetStore<CHKBlock> cachingStore = new CachingFreenetStore<CHKBlock>(store, saltStore2, tracker)) {
				cachingStore.start(null, true);

				boolean atLeastOneKey = false;
				for (int i = 0; i < 5; i++) {
					ClientCHKBlock block = chkBlocks.get(i);
					ClientCHK key = block.getClientKey();
					CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
					// Key might not be present because of collisions in store
					if (verify == null) {
						continue;
					}
					String data = decodeBlockCHK(verify, key);
					String test = tests.get(i);
					assertEquals(test, data);

					// Check its really in the underlying store
					assertNotNull(saltStore2.fetch(block.getKey().getRoutingKey(), block.getKey().getFullKey(), false, false,
							false, false, null));

					atLeastOneKey = true;
				}
				assertTrue("Atl least one Key should have been present in the store", atLeastOneKey);
			}
		}
	}

	/* Test whether stuff gets written to disk after the caching period expires */
	@Test
 	public void testTimeExpireCHK()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException, InterruptedException {
		File f = getStorePath("testTimeExpireCHK");
		long delay = 100;

		CHKStore store = new CHKStore();
		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f,
				"testCachingFreenetStoreTimeExpire", store, weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true,
				ticker, null)) {
			WaitableCachingFreenetStoreTracker tracker = new WaitableCachingFreenetStoreTracker(cachingFreenetStoreMaxSize,
					delay, ticker);
			try (CachingFreenetStore<CHKBlock> cachingStore = new CachingFreenetStore<CHKBlock>(store, saltStore, tracker)) {
				cachingStore.start(null, true);

				List<ClientCHKBlock> chkBlocks = new ArrayList<ClientCHKBlock>();
				List<String> tests = new ArrayList<String>();

				// Put five chk blocks
				for (int i = 0; i < 5; i++) {
					String test = "test" + i;
					tests.add(test);

					ClientCHKBlock block = encodeBlockCHK(test);
					chkBlocks.add(block);

					store.put(block.getBlock(), false);
					// Check that it's in the cache, *not* the underlying store.
					assertEquals(saltStore.fetch(block.getKey().getRoutingKey(), block.getKey().getFullKey(), false, false, false,
							false, null), null);
				}

				tracker.waitForZero();

				boolean atLeastOneKey = false;
				for (int i = 0; i < 5; i++) {
					String test = tests.get(i);
					ClientCHKBlock block = chkBlocks.get(i);
					ClientCHK key = block.getClientKey();
					CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
					// Key might not be present because of collisions in store
					if (verify == null) {
						continue;
					}
					String data = decodeBlockCHK(verify, key);
					assertEquals(test, data);
					// Check that it's in the underlying store now.
					assertNotNull(saltStore.fetch(block.getKey().getRoutingKey(), block.getKey().getFullKey(), false, false,
							false, false, null));

					atLeastOneKey = true;
				}
				assertTrue("Atl least one Key should have been present in the store", atLeastOneKey);
			}
		}
	}

	private String decodeBlockCHK(CHKBlock verify, ClientCHK key)
			throws CHKVerifyException, CHKDecodeException, IOException {
		ClientCHKBlock cb = new ClientCHKBlock(verify, key);
		Bucket output = cb.decode(new ArrayBucketFactory(), 32768, false);
		byte[] buf = BucketTools.toByteArray(output);
		return new String(buf, "UTF-8");
	}

	private ClientCHKBlock encodeBlockCHK(String test) throws CHKEncodeException, IOException {
		byte[] data = test.getBytes("UTF-8");
		SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data);
		return ClientCHKBlock.encode(bucket, false, false, (short) -1, bucket.size(),
				Compressor.DEFAULT_COMPRESSORDESCRIPTOR, null, (byte) 0);
	}

	/* Test with SSK to re-open after close */
	@Test
 	public void testOnCloseSSK() throws IOException, SSKEncodeException, InvalidCompressionCodecException,
			KeyCollisionException, SSKVerifyException, KeyDecodeException {
		File f = getStorePath("testOnCloseSSK");

		final int keys = 5;
		PubkeyStore pk = new PubkeyStore();
		RAMFreenetStore<DSAPublicKey> ramFreenetStore = new RAMFreenetStore<DSAPublicKey>(pk, keys);
		pk.setStore(ramFreenetStore);
		GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
		SSKStore store = new SSKStore(pubkeyCache);

		List<ClientSSKBlock> sskBlocks = new ArrayList<ClientSSKBlock>();
		List<String> tests = new ArrayList<String>();
		CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(cachingFreenetStoreMaxSize,
				cachingFreenetStorePeriod, ticker);

		try (SaltedHashFreenetStore<SSKBlock> saltStore = SaltedHashFreenetStore.construct(f,
				"testCachingFreenetStoreOnCloseSSK", store, weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true,
				ticker, null)) {
			try (CachingFreenetStore<SSKBlock> cachingStore = new CachingFreenetStore<SSKBlock>(store, saltStore, tracker)) {
				cachingStore.start(null, true);
				RandomSource random = new DummyRandomSource(12345);

				for (int i = 0; i < 5; i++) {
					String test = "test" + i;
					ClientSSKBlock block = encodeBlockSSK(test, random);
					SSKBlock sskBlock = (SSKBlock) block.getBlock();
					store.put(sskBlock, false, false);
					pubkeyCache.cacheKey(sskBlock.getKey().getPubKeyHash(), sskBlock.getKey().getPubKey(), false, false, false,
							false, false);
					tests.add(test);
					sskBlocks.add(block);
				}
			}
		}

		try (SaltedHashFreenetStore<SSKBlock> saltStore2 = SaltedHashFreenetStore.construct(f,
				"testCachingFreenetStoreOnCloseSSK", store, weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true,
				ticker, null)) {
			try (CachingFreenetStore<SSKBlock> cachingStore = new CachingFreenetStore<SSKBlock>(store, saltStore2, tracker)) {
				cachingStore.start(null, true);

				boolean atLeastOneKey = false;
				for (int i = 0; i < 5; i++) {
					String test = tests.remove(0); // get the first element
					ClientSSKBlock block = sskBlocks.remove(0); // get the first element
					ClientSSK key = block.getClientKey();
					NodeSSK ssk = (NodeSSK) key.getNodeKey();
					SSKBlock verify = store.fetch(ssk, false, false, false, false, null);
					// Key might not be present, because of collisions in the store
					if (verify == null) {
						continue;
					}
					String data = decodeBlockSSK(verify, key);
					assertEquals(test, data);
					// Check that it's in the underlying store now.
					assertNotNull(saltStore2.fetch(block.getKey().getRoutingKey(), block.getKey().getFullKey(), false, false,
							false, false, null));

					atLeastOneKey = true;
				}
				assertTrue("At least on key should have been present", atLeastOneKey);
			}
		}
	}

	/*
	 * Test with SSK whether stuff gets written to disk after the caching period
	 * expires
	 */
	@Test
 	public void testTimeExpireSSK() throws IOException, SSKEncodeException, InvalidCompressionCodecException,
			KeyCollisionException, SSKVerifyException, KeyDecodeException, InterruptedException {
		File f = getStorePath("testTimeExpireSSK");

		final int keys = 5;
		PubkeyStore pk = new PubkeyStore();
		RAMFreenetStore<DSAPublicKey> ramFreenetStore = new RAMFreenetStore<DSAPublicKey>(pk, keys);
		pk.setStore(ramFreenetStore);
		GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
		SSKStore store = new SSKStore(pubkeyCache);

		try (SaltedHashFreenetStore<SSKBlock> saltStore = SaltedHashFreenetStore.construct(f,
				"testCachingFreenetStoreOnCloseSSK", store, weakPRNG, 10, true, SemiOrderedShutdownHook.get(), true, true,
				ticker, null)) {
			WaitableCachingFreenetStoreTracker tracker = new WaitableCachingFreenetStoreTracker(cachingFreenetStoreMaxSize,
					100, ticker);
			try (CachingFreenetStore<SSKBlock> cachingStore = new CachingFreenetStore<SSKBlock>(store, saltStore, tracker)) {
				cachingStore.start(null, true);
				RandomSource random = new DummyRandomSource(12345);

				List<ClientSSKBlock> sskBlocks = new ArrayList<ClientSSKBlock>();
				List<String> tests = new ArrayList<String>();

				for (int i = 0; i < 5; i++) {
					String test = "test" + i;
					ClientSSKBlock block = encodeBlockSSK(test, random);
					SSKBlock sskBlock = (SSKBlock) block.getBlock();
					store.put(sskBlock, false, false);
					pubkeyCache.cacheKey(sskBlock.getKey().getPubKeyHash(), sskBlock.getKey().getPubKey(), false, false, false,
							false, false);
					tests.add(test);
					sskBlocks.add(block);
				}

				tracker.waitForZero();

				boolean atLeastOneKey = false;
				for (int i = 0; i < 5; i++) {
					String test = tests.get(i);
					ClientSSKBlock block = sskBlocks.get(i);
					ClientSSK key = block.getClientKey();
					NodeSSK ssk = (NodeSSK) key.getNodeKey();
					SSKBlock verify = store.fetch(ssk, false, false, false, false, null);
					if (verify == null) {
						continue;
					}
					String data = decodeBlockSSK(verify, key);
					assertEquals(test, data);
					// Check that it's in the underlying store now.
					assertNotNull(saltStore.fetch(block.getKey().getRoutingKey(), block.getKey().getFullKey(), false, false,
							false, false, null));

					atLeastOneKey = true;
				}
				assertTrue("At least one key should have been present", atLeastOneKey);
			}
		}
	}

	@Test
 	public void testOnCollisionsSSK_useSlotFilter() throws IOException, SSKEncodeException, InvalidCompressionCodecException,
			SSKVerifyException, KeyDecodeException, KeyCollisionException {
		// With slot filters turned on, it should be cached, it should compare it, and
		// still not throw if it's the same block.
		checkOnCollisionsSSK(true);
	}

	@Test
 	public void testOnCollisionsSSK_dontUseSlotFilter() throws IOException, SSKEncodeException, InvalidCompressionCodecException,
			SSKVerifyException, KeyDecodeException, KeyCollisionException {
		// With slot filters turned off, it goes straight to disk, because
		// probablyInStore() always returns true.
		checkOnCollisionsSSK(false);
	}

	/* Test collisions on SSK */
	private void checkOnCollisionsSSK(boolean useSlotFilter) throws IOException, SSKEncodeException,
			InvalidCompressionCodecException, SSKVerifyException, KeyDecodeException, KeyCollisionException {

		FileUtil.removeAll(TEMP_DIR);

		final int keys = 5;
		PubkeyStore pk = new PubkeyStore();
		RAMFreenetStore<DSAPublicKey> ramFreenetStore = new RAMFreenetStore<DSAPublicKey>(pk, keys);
		pk.setStore(ramFreenetStore);
		GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
		SSKStore store = new SSKStore(pubkeyCache);
		File f = getStorePath("checkOnCollisionsSSK");

		try (SaltedHashFreenetStore<SSKBlock> saltStore = SaltedHashFreenetStore.construct(f,
				"testCachingFreenetStoreOnCloseSSK", store, weakPRNG, 10, useSlotFilter, SemiOrderedShutdownHook.get(), true,
				true, ticker, null)) {
			CachingFreenetStoreTracker tracker = new CachingFreenetStoreTracker(cachingFreenetStoreMaxSize,
					cachingFreenetStorePeriod, ticker);
			try (CachingFreenetStore<SSKBlock> cachingStore = new CachingFreenetStore<SSKBlock>(store, saltStore, tracker)) {
				cachingStore.start(null, true);
				RandomSource random = new DummyRandomSource(12345);

				final int CRYPTO_KEY_LENGTH = 32;
				byte[] ckey = new byte[CRYPTO_KEY_LENGTH];
				random.nextBytes(ckey);
				DSAGroup g = Global.DSAgroupBigA;
				DSAPrivateKey privKey = new DSAPrivateKey(g, random);
				DSAPublicKey pubKey = new DSAPublicKey(g, privKey);
				byte[] pkHash = SHA256.digest(pubKey.asBytes());
				String docName = "myDOC";
				InsertableClientSSK ik = new InsertableClientSSK(docName, pkHash, pubKey, privKey, ckey,
						Key.ALGO_AES_PCFB_256_SHA256);

				String test = "test";
				SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(test.getBytes("UTF-8"));
				ClientSSKBlock block = ik.encode(bucket, false, false, (short) -1, bucket.size(), random,
						Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
				SSKBlock sskBlock = (SSKBlock) block.getBlock();
				store.put(sskBlock, false, false);

				// If the block is the same then there should not be a collision
				try {
					store.put(sskBlock, false, false);
					assertTrue(true);
				} catch (KeyCollisionException e) {
					fail();
				}

				String test1 = "test1";
				SimpleReadOnlyArrayBucket bucket1 = new SimpleReadOnlyArrayBucket(test1.getBytes("UTF-8"));
				ClientSSKBlock block1 = ik.encode(bucket1, false, false, (short) -1, bucket1.size(), random,
						Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
				SSKBlock sskBlock1 = (SSKBlock) block1.getBlock();

				// if it's different (e.g. different content, same key), there should be a KCE
				// thrown
				try {
					store.put(sskBlock1, false, false);
					fail();
				} catch (KeyCollisionException e) {
					assertTrue(true);
				}

				// if overwrite is set, then no collision should be thrown
				try {
					store.put(sskBlock1, true, false);
					assertTrue(true);
				} catch (KeyCollisionException e) {
					fail();
				}

				ClientSSK key = block1.getClientKey();
				pubkeyCache.cacheKey(sskBlock.getKey().getPubKeyHash(), sskBlock.getKey().getPubKey(), false, false, false,
						false, false);
				NodeSSK ssk = (NodeSSK) key.getNodeKey();
				SSKBlock verify = store.fetch(ssk, false, false, false, false, null);
				String data = decodeBlockSSK(verify, key);
				assertEquals(test1, data);

				if (useSlotFilter) {
					// Check that it's in the cache
					assertNull(saltStore.fetch(block.getKey().getRoutingKey(), block.getKey().getFullKey(), false, false, false,
							false, null));
				} else {
					// Check that it's in the underlying store now.
					assertNotNull(saltStore.fetch(block.getKey().getRoutingKey(), block.getKey().getFullKey(), false, false,
							false, false, null));
				}
			}
		}
	}

	private String decodeBlockSSK(SSKBlock verify, ClientSSK key)
			throws SSKVerifyException, KeyDecodeException, IOException {
		ClientSSKBlock cb = ClientSSKBlock.construct(verify, key);
		Bucket output = cb.decode(new ArrayBucketFactory(), 32768, false);
		byte[] buf = BucketTools.toByteArray(output);
		return new String(buf, "UTF-8");
	}

	private ClientSSKBlock encodeBlockSSK(String test, RandomSource random)
			throws IOException, SSKEncodeException, InvalidCompressionCodecException {
		byte[] data = test.getBytes("UTF-8");
		SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data);
		InsertableClientSSK ik = InsertableClientSSK.createRandom(random, test);
		return ik.encode(bucket, false, false, (short) -1, bucket.size(), random, Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
	}
}
