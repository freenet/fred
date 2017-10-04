package freenet.store.saltedhash;

import java.io.File;
import java.io.IOException;
import java.util.Random;

import junit.framework.TestCase;
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
 * SaltedHashFreenetStoreTest
 * Test for SaltedHashFreenetStore
 * 
 * @author Simon Vocella <voxsim@gmail.com>
 * 
 */
public class SaltedHashFreenetStoreTest extends TestCase {

	private Random weakPRNG = new Random(12340);
	private PooledExecutor exec = new PooledExecutor();
	private Ticker ticker = new TrivialTicker(exec);
	private File tempDir;
	
	@Override
	protected void setUp() throws java.lang.Exception {
		tempDir = new File("tmp-saltedHashfreenetstoretest");
		tempDir.mkdir();
		exec.start();
		ResizablePersistentIntBuffer.setPersistenceTime(-1);
	}

	@Override
	protected void tearDown() {
		FileUtil.removeAll(tempDir);
	}
	
	/* Simple test with CHK for SaltedHashFreenetStore without slotFilter */
	public void testSimpleCHK() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
		File f = new File(tempDir, "saltstore");
		FileUtil.removeAll(f);

		CHKStore store = new CHKStore();
		SaltedHashFreenetStore<CHKBlock> saltStore = SaltedHashFreenetStore.construct(f, "testSaltedHashFreenetStoreCHK", store, weakPRNG, 10, false, SemiOrderedShutdownHook.get(), true, true, null);
		saltStore.start(null, true);

		for(int i=0;i<5;i++) {
			String test = "test" + i;
			ClientCHKBlock block = encodeBlockCHK(test);
			store.put(block.getBlock(), false);
			ClientCHK key = block.getClientKey();
			CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
			String data = decodeBlockCHK(verify, key);
			assertEquals(test, data);
		}
		
		saltStore.close();
	}
	
	/* Simple test with SSK for SaltedHashFreenetStore without slotFilter */
	public void testSimpleSSK() throws IOException, KeyCollisionException, SSKVerifyException, KeyDecodeException, SSKEncodeException, InvalidCompressionCodecException {
		File f = new File(tempDir, "saltstore");
		FileUtil.removeAll(f);

		final int keys = 5;
		PubkeyStore pk = new PubkeyStore();
		new RAMFreenetStore<DSAPublicKey>(pk, keys);
		GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
		SSKStore store = new SSKStore(pubkeyCache);
		SaltedHashFreenetStore<SSKBlock> saltStore = SaltedHashFreenetStore.construct(f, "testSaltedHashFreenetStoreSSK", store, weakPRNG, 20, false, SemiOrderedShutdownHook.get(), true, true, null);
		saltStore.start(null, true);
		RandomSource random = new DummyRandomSource(12345);

		for(int i=0;i<5;i++) {
			String test = "test" + i;
			ClientSSKBlock block = encodeBlockSSK(test, random);
			SSKBlock sskBlock = (SSKBlock) block.getBlock();
			store.put(sskBlock, false, false);
			ClientSSK key = block.getClientKey();
			NodeSSK ssk = (NodeSSK) key.getNodeKey();
			pubkeyCache.cacheKey(ssk.getPubKeyHash(), ssk.getPubKey(), false, false, false, false, false);
			SSKBlock verify = store.fetch(ssk, false, false, false, false, null);
			String data = decodeBlockSSK(verify, key);
			assertEquals(test, data);
		}
		
		saltStore.close();
	}

	private String decodeBlockCHK(CHKBlock verify, ClientCHK key) throws CHKVerifyException, CHKDecodeException, IOException {
		ClientCHKBlock cb = new ClientCHKBlock(verify, key);
		Bucket output = cb.decode(new ArrayBucketFactory(), 32768, false);
		byte[] buf = BucketTools.toByteArray(output);
		return new String(buf, "UTF-8");
	}

	private ClientCHKBlock encodeBlockCHK(String test) throws CHKEncodeException, IOException {
		byte[] data = test.getBytes("UTF-8");
		SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data);
		return ClientCHKBlock.encode(bucket, false, false, (short)-1, bucket.size(), Compressor.DEFAULT_COMPRESSORDESCRIPTOR, false, null, (byte)0);
	}
	
	public void testOnCollisionsSSK() throws IOException, SSKEncodeException, InvalidCompressionCodecException, SSKVerifyException, KeyDecodeException, KeyCollisionException {
		// With slot filters turned off, it goes straight to disk, because probablyInStore() always returns true.
		checkOnCollisionsSSK(false);
		// With slot filters turned on, it should be cached, it should compare it, and still not throw if it's the same block.
		checkOnCollisionsSSK(true);
	}
	
	/* Test collisions on SSK */
	private void checkOnCollisionsSSK(boolean useSlotFilter) throws IOException, SSKEncodeException, InvalidCompressionCodecException, SSKVerifyException, KeyDecodeException, KeyCollisionException {
		File f = new File(tempDir, "saltstore");
		FileUtil.removeAll(f);

		final int keys = 5;
		PubkeyStore pk = new PubkeyStore();
		new RAMFreenetStore<DSAPublicKey>(pk, keys);
		GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
		SSKStore store = new SSKStore(pubkeyCache);
		SaltedHashFreenetStore<SSKBlock> saltStore = SaltedHashFreenetStore.construct(f, "testSaltedHashFreenetStoreOnCloseSSK", store, weakPRNG, 10, true, SemiOrderedShutdownHook.get(), true, true, null);
		saltStore.start(null, true);
		RandomSource random = new DummyRandomSource(12345);
		
		final int CRYPTO_KEY_LENGTH = 32;
		byte[] ckey = new byte[CRYPTO_KEY_LENGTH];
		random.nextBytes(ckey);
		DSAGroup g = Global.DSAgroupBigA;
		DSAPrivateKey privKey = new DSAPrivateKey(g, random);
		DSAPublicKey pubKey = new DSAPublicKey(g, privKey);
		byte[] pkHash = SHA256.digest(pubKey.asBytes());
		String docName = "myDOC";
		InsertableClientSSK ik = new InsertableClientSSK(docName, pkHash, pubKey, privKey, ckey, Key.ALGO_AES_PCFB_256_SHA256);
		
		String test = "test";
		SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(test.getBytes("UTF-8"));
		ClientSSKBlock block = ik.encode(bucket, false, false, (short)-1, bucket.size(), Compressor.DEFAULT_COMPRESSORDESCRIPTOR, false);
		SSKBlock sskBlock = (SSKBlock) block.getBlock();
		store.put(sskBlock, false, false);
		
		//If the block is the same then there should not be a collision
		try {
			store.put(sskBlock, false, false);
			assertTrue(true);
		} catch (KeyCollisionException e) {
			fail();
			
		}
		
		String test1 = "test1";
		SimpleReadOnlyArrayBucket bucket1 = new SimpleReadOnlyArrayBucket(test1.getBytes("UTF-8"));
		ClientSSKBlock block1 = ik.encode(bucket1, false, false, (short)-1, bucket1.size(), Compressor.DEFAULT_COMPRESSORDESCRIPTOR, false);
		SSKBlock sskBlock1 = (SSKBlock) block1.getBlock();
		
		//if it's different (e.g. different content, same key), there should be a KCE thrown
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
		pubkeyCache.cacheKey(sskBlock.getKey().getPubKeyHash(), sskBlock.getKey().getPubKey(), false, false, false, false, false);
		// Check that it's in the cache, *not* the underlying store.
		NodeSSK ssk = (NodeSSK) key.getNodeKey();
		SSKBlock verify = store.fetch(ssk, false, false, false, false, null);
		String data = decodeBlockSSK(verify, key);
		assertEquals(test1, data);
		
		saltStore.close();
	}
	
	private String decodeBlockSSK(SSKBlock verify, ClientSSK key) throws SSKVerifyException, KeyDecodeException, IOException {
		ClientSSKBlock cb = ClientSSKBlock.construct(verify, key);
		Bucket output = cb.decode(new ArrayBucketFactory(), 32768, false);
		byte[] buf = BucketTools.toByteArray(output);
		return new String(buf, "UTF-8");
	}

	private ClientSSKBlock encodeBlockSSK(String test, RandomSource random) throws IOException, SSKEncodeException, InvalidCompressionCodecException {
		byte[] data = test.getBytes("UTF-8");
		SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data);
		InsertableClientSSK ik = InsertableClientSSK.createRandom(random, test);
		return ik.encode(bucket, false, false, (short)-1, bucket.size(), Compressor.DEFAULT_COMPRESSORDESCRIPTOR, false);
	}
}
