package freenet.store;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import freenet.crypt.DummyRandomSource;
import freenet.crypt.RandomSource;
import freenet.keys.CHKBlock;
import freenet.keys.CHKDecodeException;
import freenet.keys.CHKEncodeException;
import freenet.keys.CHKVerifyException;
import freenet.keys.ClientCHK;
import freenet.keys.ClientCHKBlock;
import freenet.keys.Key;
import freenet.node.SemiOrderedShutdownHook;
import freenet.store.saltedhash.ResizablePersistentIntBuffer;
import freenet.store.saltedhash.SaltedHashFreenetStore;
import freenet.support.PooledExecutor;
import freenet.support.SimpleReadOnlyArrayBucket;
import freenet.support.Ticker;
import freenet.support.TrivialTicker;
import freenet.support.api.Bucket;
import freenet.support.compress.Compressor;
import freenet.support.io.ArrayBucketFactory;
import freenet.support.io.BucketTools;
import freenet.support.io.FileUtil;

/** Test migration from a RAMFreenetStore to a SaltedHashFreenetStore */
public class RAMSaltMigrationTest {
	
	private static final File TEMP_DIR = new File("tmp-RAMSaltMigrationTest");

	private RandomSource strongPRNG = new DummyRandomSource(43210);
	private Random weakPRNG = new Random(12340);
	private PooledExecutor exec = new PooledExecutor();
	private Ticker ticker = new TrivialTicker(exec);

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


	/**
	 * Insert Standard testing data
	 * @param keycount Number of keys to insert
	 * @param store Store to put data to
	 * @param dummyValueInserted The inserted values will be added to this list
	 * @param blocksInserted The inserted Blocks will be added to this list
	 * @return number of collisions during the insert
	 * @throws CHKEncodeException
	 * @throws IOException
	 */
	private int insertStandardTestBlocksIntoStore(int keycount, CHKStore store, List<String> dummyValueInsertedList, List<ClientCHKBlock> blockInsertedList)
			throws CHKEncodeException, IOException {
		
		int collisions = 0;
		for (int i = 0; i < keycount; i++) {
			String dummyValueInserted = "test" + i;
			ClientCHKBlock blockInserted = encodeBlock(dummyValueInserted, true);
			store.put(blockInserted.getBlock(), true);

			dummyValueInsertedList.add(dummyValueInserted);
			blockInsertedList.add(blockInserted);
			
			// Did we have a collision during the put and the actual size did not increase?
			if (store.keyCount() + collisions == i) {
				collisions++;
			}
		}
		return collisions;
	}

	/**
	 * Probe all inserted keys and see what is actually there, after collisions might
	 * have happend during insert or resize
	 * 
	 * @param store to check for keys
	 * @param dummyValueInsertedList to check for in store
	 * @param blockInsertedList to check for in store
	 * @param dummyValueActuallyStoredList found values will be added to this list
	 * @param blockActuallyStoredList found blocks will be added to this list
	 * @throws IOException
	 */
	private void probeStoreBlocks(CHKStore store, List<String> dummyValueInsertedList, List<ClientCHKBlock> blockInsertedList, List<String> dummyValueActuallyStoredList, List<ClientCHKBlock> blockActuallyStoredList)
			throws IOException {
		for (int i = 0; i < dummyValueInsertedList.size(); i++) {

			CHKBlock verify = store.fetch(blockInsertedList.get(i).getClientKey().getNodeCHK(), false, false, null);
			if (verify != null) {
				dummyValueActuallyStoredList.add(dummyValueInsertedList.get(i));
				blockActuallyStoredList.add(blockInsertedList.get(i));
			}
		}
		assertTrue("Inserts failed, not a single key stored", dummyValueActuallyStoredList.size() > 0);
	}

	/**
	 * Checks if the store contains the given blocks and values
	 * @param store to check
	 * @param dummyValueActuallyStoredList of values expected
	 * @param blockActuallyStoredList of blocks expecte
	 * @param expectAll true, if all keys must be in the store, or at least one will be sufficient to succeed
	 * @throws CHKVerifyException
	 * @throws CHKDecodeException
	 * @throws IOException
	 */
	private void checkStandardTestBlocks(CHKStore store, List<String> dummyValueActuallyStoredList, List<ClientCHKBlock> blockActuallyStoredList, boolean expectAll)
			throws CHKVerifyException, CHKDecodeException, IOException {

		int numberOfHits = 0;
		for (int i = 0; i < blockActuallyStoredList.size(); i++) {

			String value = dummyValueActuallyStoredList.get(i);
			ClientCHK key = blockActuallyStoredList.get(i).getClientKey();
			CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);

			if (expectAll) {
				assertNotNull("Expect all keys to be in store. Not found: " + value, verify);
			} else if (verify == null) {
				continue;
			}

			String decodedValue = decodeBlock(verify, key);
			assertEquals(value, decodedValue);
			numberOfHits++;
		}
		
		assertTrue("Not all keys in store were a hit", numberOfHits > 0);
	}

	@Test
	public void testRAMStore_newFormat() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		checkRAMStore(true);
	}

	@Test
	public void testRAMStore_oldFormat() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		checkRAMStore(false);
	}

	private void checkRAMStore(boolean newFormat)
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		CHKStore store = new CHKStore();
		RAMFreenetStore<CHKBlock> ramFreenetStore = new RAMFreenetStore<CHKBlock>(store, 10);
		store.setStore(ramFreenetStore);

		// Encode a block
		String test = "test";
		ClientCHKBlock block = encodeBlock(test, newFormat);
		store.put(block.getBlock(), false);

		ClientCHK key = block.getClientKey();

		CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
		String data = decodeBlock(verify, key);
		assertEquals(test, data);
	}

	@Test
	public void testRAMStoreOldBlocks() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		CHKStore store = new CHKStore();
		RAMFreenetStore<CHKBlock> ramFreenetStore = new RAMFreenetStore<CHKBlock>(store, 10);
		store.setStore(ramFreenetStore);

		// Encode a block
		String test = "test";
		ClientCHKBlock block = encodeBlock(test, false);
		store.put(block.getBlock(), true);

		ClientCHK key = block.getClientKey();

		CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
		String data = decodeBlock(verify, key);
		assertEquals(test, data);

		// ignoreOldBlocks works.
		assertEquals(null, store.fetch(key.getNodeCHK(), false, true, null));

		// Put it with oldBlock = false should unset the flag.
		store.put(block.getBlock(), false);

		verify = store.fetch(key.getNodeCHK(), false, true, null);
		data = decodeBlock(verify, key);
		assertEquals(test, data);
	}

	@Test
	public void testSaltedStore_oldFormat()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		checkSaltedStore(false, "testSaltedStore_oldFormat");
	}

	@Test
	public void testSaltedStore_newFormat()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		checkSaltedStore(true, "testSaltedStore_newFormat");
	}

	public void checkSaltedStore(boolean newFormat, String testName)
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		CHKStore store = new CHKStore();

		File f = getStorePath(testName);
		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG,
				10, false, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			saltStore.start(null, true);

			for (int i = 0; i < 5; i++) {

				// Encode a block
				String test = "test" + i;
				ClientCHKBlock block = encodeBlock(test, newFormat);
				store.put(block.getBlock(), false);

				ClientCHK key = block.getClientKey();

				CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
				String data = decodeBlock(verify, key);
				assertEquals(test, data);
			}
		}
	}

	private void innerTestSaltedStoreWithClose(int persistenceTime, int delay, String testName)
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		ResizablePersistentIntBuffer.setPersistenceTime(persistenceTime);

		int keycount = 5;

		CHKStore store = new CHKStore();
		File f = getStorePath(testName);
		List<String> dummyValueActuallyStoredList = new ArrayList<String>(keycount);
		List<ClientCHKBlock> blockActuallyStoredList = new ArrayList<ClientCHKBlock>(keycount);
		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG,
				10, false, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			saltStore.start(null, true);

			List<String> dummyValueInsertedList = new ArrayList<String>(keycount);
			List<ClientCHKBlock> blockInsertedList = new ArrayList<ClientCHKBlock>(keycount);
			int collisions = insertStandardTestBlocksIntoStore(keycount, store, dummyValueInsertedList, blockInsertedList);

			probeStoreBlocks(store, dummyValueInsertedList, blockInsertedList, dummyValueActuallyStoredList, blockActuallyStoredList);
			assertEquals("The number of inserts minus the number of collissions should be the same as the number of keys in the store. Collisions " + collisions, dummyValueInsertedList.size() - collisions, blockActuallyStoredList.size());
		}

		store = new CHKStore();
		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG,
				10, false, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			checkStandardTestBlocks(store, dummyValueActuallyStoredList, blockActuallyStoredList, true);
		}
	}

	private void checkBlocks(CHKStore store, boolean write, boolean expectFailure)
			throws CHKEncodeException, IOException, CHKVerifyException, CHKDecodeException {

		for (int i = 0; i < 5; i++) {

			// Encode a block
			String test = "test" + i;
			// Use new format for every other block to ensure they are mixed in the same
			// store.
			ClientCHKBlock block = encodeBlock(test, (i & 1) == 1);
			if (write)
				store.put(block.getBlock(), false);

			ClientCHK key = block.getClientKey();

			CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
			if (expectFailure)
				assertEquals(null, verify);
			else {
				String data = decodeBlock(verify, key);
				assertEquals(test, data);
			}
		}
	}

	private void innerTestSaltedStoreSlotFilterWithAbort(int persistenceTime, int delay, boolean expectFailure,
			boolean forceValidEmpty, String testName) throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		ResizablePersistentIntBuffer.setPersistenceTime(persistenceTime);

		File f = getStorePath(testName);

		CHKStore store = new CHKStore();
		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG,
				10, true, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			saltStore.start(ticker, true);

			// Make sure it's clear.
			checkBlocks(store, false, true);

			checkBlocks(store, true, false);

			try {
				Thread.sleep(delay);
			} catch (InterruptedException e) {
			}
	
		}

		store = new CHKStore();
		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG,
				10, true, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			saltStore.start(ticker, true);
			if (forceValidEmpty)
				saltStore.forceValidEmpty();

			checkBlocks(store, false, expectFailure);
		}
	}

	@Test
	public void testSaltedStoreWithClose_writeImmediately()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		// Write straight through should work.
		innerTestSaltedStoreWithClose(-1, 0, "testSaltedStoreWithClose_writeImmediately");
	}

	@Test
	public void testSaltedStoreWithClose_writeOnShotdown()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		// Write on shutdown should work.
		innerTestSaltedStoreWithClose(0, 0, "testSaltedStoreWithClose_writeOnShotdown");
	}

	@Test
	public void testSaltedStoreWithClose_waitLongerThanPersistenceTime()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		// Shorter interval than delay should work.
		innerTestSaltedStoreWithClose(1000, 2000, "testSaltedStoreWithClose_waitLongerThanPersistenceTime");
	}

	@Test
	public void testSaltedStoreWithClose_noWaitWithPersincenceTime_relayOnClose()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		// Longer interval than delay should work (write on shutdown).
		innerTestSaltedStoreWithClose(5000, 0, "testSaltedStoreWithClose_noWaitWithPersincenceTime_relayOnClose");
	}

	public void innerTestSaltedStoreSlotFilterWithAbort_writeImmediately()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		// Write straight through should work even with abort.
		innerTestSaltedStoreSlotFilterWithAbort(-1, 0, false, false, "innerTestSaltedStoreSlotFilterWithAbort_writeImmediately");
	}

	public void innerTestSaltedStoreSlotFilterWithAbort_waitLongerThanPersistenceTime()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		// Shorter interval than delay should work.
		innerTestSaltedStoreSlotFilterWithAbort(1000, 2000, false, false, "innerTestSaltedStoreSlotFilterWithAbort_waitLongerThanPersistenceTime");
	}

	public void innerTestSaltedStoreSlotFilterWithAbort_noWaitWithPersincenceTime_slotsUnknown()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		// Even this should work, because the slots still say unknown.
		innerTestSaltedStoreSlotFilterWithAbort(5000, 0, false, false, "innerTestSaltedStoreSlotFilterWithAbort_noWaitWithPersincenceTime_slotsUnknown");
	}

	public void innerTestSaltedStoreSlotFilterWithAbort_noWaitWithPersincenceTime_forceKownEmpty_fails()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		// However if we set the unknown slots to known empty, it should fail.
		innerTestSaltedStoreSlotFilterWithAbort(5000, 0, true, true, "innerTestSaltedStoreSlotFilterWithAbort_noWaitWithPersincenceTime_forceKownEmpty_fails");
	}

	public void innerTestSaltedStoreSlotFilterWithAbort_writeImmediately_forceKownEmptz()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		// But if we do the same thing while giving it enough time to write, it should
		// work.
		innerTestSaltedStoreSlotFilterWithAbort(-1, 0, false, true, "innerTestSaltedStoreSlotFilterWithAbort_writeImmediately_forceKownEmptz");
	}

	@Test
	public void testSaltedStoreWithClose_withPersincenceTimeAndLongerWait_forceKownEmpty()
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		// But if we do the same thing while giving it enough time to write, it should
		// work.
		innerTestSaltedStoreSlotFilterWithAbort(1000, 2000, false, true, "testSaltedStoreWithClose_withPersincenceTimeAndLongerWait_forceKownEmpty");
	}

	@Test
	public void testSaltedStoreOldBlock_noSlotFilters_bloomZero()
			throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
		checkSaltedStoreOldBlocks(5, 10, 0, false, "testSaltedStoreOldBlock_noSlotFilters_bloomZero");
	}

	@Test
	public void testSaltedStoreOldBlock_noSlotFilters_bloom50()
			throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
		checkSaltedStoreOldBlocks(5, 10, 50, false, "testSaltedStoreOldBlock_noSlotFilters_bloom50");
	}

	@Test
	public void testSaltedStoreOldBlock_withSlotFilters_bloomZero()
			throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
		checkSaltedStoreOldBlocks(5, 10, 0, true, "testSaltedStoreOldBlock_withSlotFilters_bloomZero");
	}

	public void checkSaltedStoreOldBlocks(int keycount, int size, int bloomSize, boolean useSlotFilter, String testName)
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		int delay = 1000;
		ResizablePersistentIntBuffer.setPersistenceTime(delay);

		CHKStore store = new CHKStore();

		File f = getStorePath(testName);
		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG,
				size, useSlotFilter, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			
			saltStore.start(null, true);

			List<String> dummyValueInsertedList = new ArrayList<String>(keycount);
			List<ClientCHKBlock> blockInsertedList = new ArrayList<ClientCHKBlock>(keycount);
			int collisions = insertStandardTestBlocksIntoStore(keycount, store, dummyValueInsertedList, blockInsertedList);

			List<String> dummyValueActuallyStoredList = new ArrayList<String>(keycount);
			List<ClientCHKBlock> blockActuallyStoredList = new ArrayList<ClientCHKBlock>(keycount);
			probeStoreBlocks(store, dummyValueInsertedList, blockInsertedList, dummyValueActuallyStoredList, blockActuallyStoredList);
			assertEquals("The number of inserts minus the number of collissions should be the same as the number of keys in the store. Collisions " + collisions, dummyValueInsertedList.size() - collisions, blockActuallyStoredList.size());
			
			for (int i = 0; i < dummyValueActuallyStoredList.size(); i++) {

				String value = dummyValueActuallyStoredList.get(i);
				ClientCHKBlock block = blockActuallyStoredList.get(i);

				ClientCHK key = block.getClientKey();

				CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
				String decodedValue = decodeBlock(verify, key);
				assertEquals(value, decodedValue);

				// ignoreOldBlocks works.
				assertEquals(null, store.fetch(key.getNodeCHK(), false, true, null));

				// Put it with oldBlock = false should unset the flag.
				store.put(block.getBlock(), false);

				verify = store.fetch(key.getNodeCHK(), false, true, null);
				decodedValue = decodeBlock(verify, key);
				assertEquals(decodedValue, decodedValue);
			}
		}
	}

	@Test
	public void testSaltedStoreResize_noUseSlotFilter_writeImmediately_noAbort_openNewSize()
			throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
		checkSaltedStoreResize(5, 10, 20, false, -1, false, true, "testSaltedStoreResize_noUseSlotFilter_writeImmediately_noAbort_openNewSize");
	}

	@Test
	public void testSaltedStoreResize_useSlotFilter_writeImmediately_noAbort_openNewSize()
			throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
		checkSaltedStoreResize(5, 10, 20, true, -1, false, true, "testSaltedStoreResize_useSlotFilter_writeImmediately_noAbort_openNewSize");
	}

	@Test
	public void testSaltedStoreResize_useSlotFilter_1h_noAbort_openNewSize()
			throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
		// Will write to disk on shutdown.
		checkSaltedStoreResize(5, 10, 20, true, 60000, false, true, "testSaltedStoreResize_useSlotFilter_1h_noAbort_openNewSize");
	}

	@Test
	public void testSaltedStoreResize_useSlotFilter_1h_noAbort_noOpenNewSize()
			throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
		// Using the old size causes it to resize on startup back to the old size. This
		// needs testing too, and revealed some odd bugs.
		checkSaltedStoreResize(5, 10, 20, true, 60000, false, false, "testSaltedStoreResize_useSlotFilter_1h_noAbort_noOpenNewSize");
	}

	@Test
	public void testSaltedStoreResize_useSlotFilter_1h_abort_openNewSize()
			throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
		// It will force to disk after resizing, so should still work even with a long
		// write time.
		checkSaltedStoreResize(5, 10, 20, true, 60000, true, true, "testSaltedStoreResize_useSlotFilter_1h_abort_openNewSize");
	}

	@Test
	public void testSaltedStoreResize_useSlotFilter_1h_abort_noOpenNewSize()
			throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
		checkSaltedStoreResize(5, 10, 20, true, 60000, true, false, "testSaltedStoreResize_useSlotFilter_1h_abort_noOpenNewSize");
	}

	public void checkSaltedStoreResize(int keycount, int size, int newSize, boolean useSlotFilter, int persistenceTime,
			boolean abort, boolean openNewSize, String testName)
			throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		File f = getStorePath(testName);

		ResizablePersistentIntBuffer.setPersistenceTime(persistenceTime);

		CHKStore store = new CHKStore();
		SaltedHashFreenetStore.NO_CLEANER_SLEEP = true;
		List<String> dummyValueActuallyStoredList = new ArrayList<String>(keycount);
		List<ClientCHKBlock> blockActuallyStoredList = new ArrayList<ClientCHKBlock>(keycount);
		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG,
				size, useSlotFilter, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			saltStore.start(ticker, true);

			List<String> dummyValueInsertedList = new ArrayList<String>(keycount);
			List<ClientCHKBlock> blockInsertedList = new ArrayList<ClientCHKBlock>(keycount);
			int collisions = insertStandardTestBlocksIntoStore(keycount, store, dummyValueInsertedList, blockInsertedList);
			
			saltStore.setMaxKeys(newSize, true);

			probeStoreBlocks(store, dummyValueInsertedList, blockInsertedList, dummyValueActuallyStoredList, blockActuallyStoredList);
			assertEquals("The number of inserts minus the number of collissions should be the same as the number of keys in the store. Collisions " + collisions, dummyValueInsertedList.size() - collisions, blockActuallyStoredList.size());

			saltStore.close(abort);
		}

		store = new CHKStore();
		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG,
				openNewSize ? newSize : size, useSlotFilter, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			saltStore.start(ticker, true);

			// If we did open the new size we expect all previously matched keys to be present.
			// If we opend the old size, it causes a resize again, which might create new collisions and keys might be lost again.
			boolean expectAll = openNewSize;

			checkStandardTestBlocks(store, dummyValueActuallyStoredList, blockActuallyStoredList, expectAll);
		}
	}

	@Test
	public void testMigrate() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		CHKStore store = new CHKStore();
		RAMFreenetStore<CHKBlock> ramStore = new RAMFreenetStore<CHKBlock>(store, 10);
		store.setStore(ramStore);

		// Encode a block
		String test = "test";
		ClientCHKBlock block = encodeBlock(test, true);
		store.put(block.getBlock(), false);

		ClientCHK key = block.getClientKey();

		CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
		String data = decodeBlock(verify, key);
		assertEquals(test, data);

		CHKStore newStore = new CHKStore();
		File f = getStorePath("testMigrate");
		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", newStore,
				weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true, ticker, null)) {
			saltStore.start(null, true);

			ramStore.migrateTo(newStore, false);

			CHKBlock newVerify = store.fetch(key.getNodeCHK(), false, false, null);
			String newData = decodeBlock(newVerify, key);
			assertEquals(test, newData);
		}
	}

	@Test
	public void testMigrateKeyed() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		CHKStore store = new CHKStore();
		RAMFreenetStore<CHKBlock> ramStore = new RAMFreenetStore<CHKBlock>(store, 10);
		store.setStore(ramStore);

		// Encode a block
		String test = "test";
		ClientCHKBlock block = encodeBlock(test, true);
		store.put(block.getBlock(), false);

		ClientCHK key = block.getClientKey();

		CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
		String data = decodeBlock(verify, key);
		assertEquals(test, data);

		byte[] storeKey = new byte[32];
		strongPRNG.nextBytes(storeKey);

		CHKStore newStore = new CHKStore();
		File f = getStorePath("testMigrateKeyed");
		try (SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", newStore,
				weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true, ticker, storeKey)) {
			saltStore.start(null, true);

			ramStore.migrateTo(newStore, false);

			CHKBlock newVerify = store.fetch(key.getNodeCHK(), false, false, null);
			String newData = decodeBlock(newVerify, key);
			assertEquals(test, newData);
		}
	}

	private String decodeBlock(CHKBlock verify, ClientCHK key)
			throws CHKVerifyException, CHKDecodeException, IOException {
		ClientCHKBlock cb = new ClientCHKBlock(verify, key);
		Bucket output = cb.decode(new ArrayBucketFactory(), 32768, false);
		byte[] buf = BucketTools.toByteArray(output);
		return new String(buf, "UTF-8");
	}

	private ClientCHKBlock encodeBlock(String test, boolean newFormat) throws CHKEncodeException, IOException {
		byte[] data = test.getBytes("UTF-8");
		SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data);
		return ClientCHKBlock.encode(bucket, false, false, (short) -1, bucket.size(),
				Compressor.DEFAULT_COMPRESSORDESCRIPTOR, null,
				newFormat ? Key.ALGO_AES_CTR_256_SHA256 : Key.ALGO_AES_PCFB_256_SHA256);
	}

}
