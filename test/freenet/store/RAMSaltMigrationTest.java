package freenet.store;

import java.io.File;
import java.io.IOException;
import java.util.Random;

import junit.framework.TestCase;

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
public class RAMSaltMigrationTest extends TestCase {

	private RandomSource strongPRNG = new DummyRandomSource(43210);
	private Random weakPRNG = new Random(12340);
	private PooledExecutor exec = new PooledExecutor();
	private Ticker ticker = new TrivialTicker(exec);
	private File tempDir;

	@Override
	protected void setUp() throws java.lang.Exception {
		tempDir = new File("tmp-slashdotstoretest");
		tempDir.mkdir();
		exec.start();
		ResizablePersistentIntBuffer.setPersistenceTime(-1);
	}

	@Override
	protected void tearDown() {
		FileUtil.removeAll(tempDir);
	}

	public void testRAMStore() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		checkRAMStore(true);
		checkRAMStore(false);
	}
	
	private void checkRAMStore(boolean newFormat) throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		CHKStore store = new CHKStore();
		new RAMFreenetStore<CHKBlock>(store, 10);

		// Encode a block
		String test = "test";
		ClientCHKBlock block = encodeBlock(test, newFormat);
		store.put(block.getBlock(), false);

		ClientCHK key = block.getClientKey();

		CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
		String data = decodeBlock(verify, key);
		assertEquals(test, data);
	}

	public void testRAMStoreOldBlocks() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		CHKStore store = new CHKStore();
		new RAMFreenetStore<CHKBlock>(store, 10);

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

	public void testSaltedStore() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		checkSaltedStore(false);
		checkSaltedStore(true);
	}
	
	public void checkSaltedStore(boolean newFormat) throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		File f = new File(tempDir, "saltstore");
		FileUtil.removeAll(f);

		CHKStore store = new CHKStore();
		SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true, null);
		saltStore.start(null, true);

		for(int i=0;i<5;i++) {
			
			// Encode a block
			String test = "test" + i;
			ClientCHKBlock block = encodeBlock(test, newFormat);
			store.put(block.getBlock(), false);
			
			ClientCHK key = block.getClientKey();
			
			CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
			String data = decodeBlock(verify, key);
			assertEquals(test, data);
		}
		
		saltStore.close();
	}
	
	private void innerTestSaltedStoreWithClose(int persistenceTime, int delay) throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		ResizablePersistentIntBuffer.setPersistenceTime(persistenceTime);
		
		File f = new File(tempDir, "saltstore");
		FileUtil.removeAll(f);

		CHKStore store = new CHKStore();
		SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true, null);
		saltStore.start(null, true);

		checkBlocks(store, true, false);
		
		saltStore.close();
		
		if(delay != 0)
			try {
				Thread.sleep(delay);
			} catch (InterruptedException e) {
				// Ignore
			}
		
		saltStore = SaltedHashFreenetStore.construct(new File(tempDir, "saltstore"), "teststore", store, weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true, null);
		
		checkBlocks(store, false, false);

		saltStore.close();
	}

	private void checkBlocks(CHKStore store,
			boolean write, boolean expectFailure) throws CHKEncodeException, IOException, CHKVerifyException, CHKDecodeException {
		
		for(int i=0;i<5;i++) {
			
			// Encode a block
			String test = "test" + i;
			// Use new format for every other block to ensure they are mixed in the same store.
			ClientCHKBlock block = encodeBlock(test, (i & 1) == 1);
			if(write)
				store.put(block.getBlock(), false);
			
			ClientCHK key = block.getClientKey();
			
			CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
			if(expectFailure)
				assertEquals(null, verify);
			else {
				String data = decodeBlock(verify, key);
				assertEquals(test, data);
			}
		}
	}

	private void innerTestSaltedStoreSlotFilterWithAbort(int persistenceTime, int delay, boolean expectFailure, boolean forceValidEmpty) throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		ResizablePersistentIntBuffer.setPersistenceTime(persistenceTime);
		
		File f = new File(tempDir, "saltstore");
		FileUtil.removeAll(f);

		CHKStore store = new CHKStore();
		SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG, 10, true, SemiOrderedShutdownHook.get(), true, true, null);
		saltStore.start(ticker, true);
		
		// Make sure it's clear.
		checkBlocks(store, false, true);

		checkBlocks(store, true, false);
		
		if(delay != 0)
			try {
				Thread.sleep(delay);
			} catch (InterruptedException e) {
				// Ignore
			}
		
		saltStore.close(true);
		
		store = new CHKStore();
		saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG, 10, true, SemiOrderedShutdownHook.get(), true, true, null);
		saltStore.start(ticker, true);
		if(forceValidEmpty)
			saltStore.forceValidEmpty();
		
		checkBlocks(store, false, expectFailure);

		saltStore.close();
	}

	public void testSaltedStoreWithClose() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		// Write straight through should work.
		innerTestSaltedStoreWithClose(-1, 0);
		// Write on shutdown should work.
		innerTestSaltedStoreWithClose(0, 0);
		// Shorter interval than delay should work.
		innerTestSaltedStoreWithClose(1000, 2000);
		// Longer interval than delay should work (write on shutdown).
		innerTestSaltedStoreWithClose(5000, 0);
		// Write straight through should work even with abort.
		innerTestSaltedStoreSlotFilterWithAbort(-1, 0, false, false);
		// Write straight through should work 
		innerTestSaltedStoreSlotFilterWithAbort(1000, 2000, false, false);
		// Even this should work, because the slots still say unknown.
		innerTestSaltedStoreSlotFilterWithAbort(5000, 0, false, false);
		// However if we set the unknown slots to known empty, it should fail.
		innerTestSaltedStoreSlotFilterWithAbort(5000, 0, true, true);
		// But if we do the same thing while giving it enough time to write, it should work.
		innerTestSaltedStoreSlotFilterWithAbort(-1, 0, false, true);
		innerTestSaltedStoreSlotFilterWithAbort(1000, 2000, false, true);
		
	}

	public void testSaltedStoreOldBlock() throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
		checkSaltedStoreOldBlocks(5, 10, 0, false);
		checkSaltedStoreOldBlocks(5, 10, 50, false);
		checkSaltedStoreOldBlocks(5, 10, 0, true);
	}
	
	public void checkSaltedStoreOldBlocks(int keycount, int size, int bloomSize, boolean useSlotFilter) throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		CHKStore store = new CHKStore();
		SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(new File(tempDir, "saltstore-"+keycount+"-"+size+"-"+bloomSize+"-"+useSlotFilter), "teststore", store, weakPRNG, size, useSlotFilter, SemiOrderedShutdownHook.get(), true, true, null);
		saltStore.start(null, true);
		
		ClientCHK[] keys = new ClientCHK[keycount];
		String[] test = new String[keycount];
		ClientCHKBlock[] block = new ClientCHKBlock[keycount];

		for(int i=0;i<keycount;i++) {
			
			// Encode a block
			test[i] = "test" + i;
			block[i] = encodeBlock(test[i], true);
			store.put(block[i].getBlock(), true);
			
			keys[i] = block[i].getClientKey();
		}
		
		for(int i=0;i<keycount;i++) {
			
			ClientCHK key = keys[i];
			
			CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
			String data = decodeBlock(verify, key);
			assertEquals(test[i], data);
			
			// ignoreOldBlocks works.
			assertEquals(null, store.fetch(key.getNodeCHK(), false, true, null));
			
			// Put it with oldBlock = false should unset the flag.
			store.put(block[i].getBlock(), false);
			
			verify = store.fetch(key.getNodeCHK(), false, true, null);
			data = decodeBlock(verify, key);
			assertEquals(test[i], data);
		}
		
		saltStore.close();
	}
	
	public void testSaltedStoreResize() throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
		checkSaltedStoreResize(5, 10, 20, false, -1, false, true);
		checkSaltedStoreResize(5, 10, 20, true, -1, false, true);
		// Will write to disk on shutdown.
		checkSaltedStoreResize(5, 10, 20, true, 60*60*1000, false, true);
		// Using the old size causes it to resize on startup back to the old size. This needs testing too, and revealed some odd bugs.
		checkSaltedStoreResize(5, 10, 20, true, 60*60*1000, false, false);
		// It will force to disk after resizing, so should still work even with a long write time.
		checkSaltedStoreResize(5, 10, 20, true, 60*60*1000, true, true);
		checkSaltedStoreResize(5, 10, 20, true, 60*60*1000, true, false);
	}
	
	public void checkSaltedStoreResize(int keycount, int size, int newSize, boolean useSlotFilter, int persistenceTime, boolean abort, boolean openNewSize) throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		
		File f = new File(tempDir, "saltstore-"+keycount+"-"+size+"-"+useSlotFilter);
		FileUtil.removeAll(f);
		
		ResizablePersistentIntBuffer.setPersistenceTime(persistenceTime);
		
		CHKStore store = new CHKStore();
		SaltedHashFreenetStore.NO_CLEANER_SLEEP = true;
		SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG, size, useSlotFilter, SemiOrderedShutdownHook.get(), true, true, null);
		saltStore.start(ticker, true);
		
		ClientCHK[] keys = new ClientCHK[keycount];
		String[] test = new String[keycount];
		ClientCHKBlock[] block = new ClientCHKBlock[keycount];

		for(int i=0;i<keycount;i++) {
			
			// Encode a block
			test[i] = "test" + i;
			block[i] = encodeBlock(test[i], true);
			store.put(block[i].getBlock(), true);
			
			keys[i] = block[i].getClientKey();
		}
		
		saltStore.setMaxKeys(newSize, true);
		
		for(int i=0;i<keycount;i++) {
			
			ClientCHK key = keys[i];
			
			CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
			assert(verify != null);
			String data = decodeBlock(verify, key);
			assertEquals(test[i], data);
		}
		
		saltStore.close(abort);

		store = new CHKStore();
		saltStore = SaltedHashFreenetStore.construct(f, "teststore", store, weakPRNG, openNewSize ? newSize : size, useSlotFilter, SemiOrderedShutdownHook.get(), true, true, null);
		saltStore.start(ticker, true);
		
		for(int i=0;i<keycount;i++) {
			
			ClientCHK key = keys[i];
			
			CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
			assert(verify != null);
			String data = decodeBlock(verify, key);
			assertEquals(test[i], data);
		}
		
		saltStore.close();
	}

	public void testMigrate() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		CHKStore store = new CHKStore();
		RAMFreenetStore<CHKBlock> ramStore = new RAMFreenetStore<CHKBlock>(store, 10);

		// Encode a block
		String test = "test";
		ClientCHKBlock block = encodeBlock(test, true);
		store.put(block.getBlock(), false);

		ClientCHK key = block.getClientKey();

		CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
		String data = decodeBlock(verify, key);
		assertEquals(test, data);

		CHKStore newStore = new CHKStore();
		SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(new File(tempDir, "saltstore"), "teststore", newStore, weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true, null);
		saltStore.start(null, true);

		ramStore.migrateTo(newStore, false);

		CHKBlock newVerify = store.fetch(key.getNodeCHK(), false, false, null);
		String newData = decodeBlock(newVerify, key);
		assertEquals(test, newData);
		saltStore.close();
	}

	public void testMigrateKeyed() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		CHKStore store = new CHKStore();
		RAMFreenetStore<CHKBlock> ramStore = new RAMFreenetStore<CHKBlock>(store, 10);

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
		SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(new File(tempDir, "saltstore"), "teststore", newStore, weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true, storeKey);
		saltStore.start(null, true);

		ramStore.migrateTo(newStore, false);

		CHKBlock newVerify = store.fetch(key.getNodeCHK(), false, false, null);
		String newData = decodeBlock(newVerify, key);
		assertEquals(test, newData);
		saltStore.close();
	}

	private String decodeBlock(CHKBlock verify, ClientCHK key) throws CHKVerifyException, CHKDecodeException, IOException {
		ClientCHKBlock cb = new ClientCHKBlock(verify, key);
		Bucket output = cb.decode(new ArrayBucketFactory(), 32768, false);
		byte[] buf = BucketTools.toByteArray(output);
		return new String(buf, "UTF-8");
	}
	
	private ClientCHKBlock encodeBlock(String test, boolean newFormat) throws CHKEncodeException, IOException {
		byte[] data = test.getBytes("UTF-8");
		SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data);
		return ClientCHKBlock.encode(bucket, false, false, (short)-1, bucket.size(), Compressor.DEFAULT_COMPRESSORDESCRIPTOR, false, null, newFormat ? Key.ALGO_AES_CTR_256_SHA256 : Key.ALGO_AES_PCFB_256_SHA256);
	}

}
