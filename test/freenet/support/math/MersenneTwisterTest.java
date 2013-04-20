package freenet.support.math;

import freenet.support.Fields;
import freenet.support.TestProperty;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import junit.framework.*;

public class MersenneTwisterTest extends TestCase {

	// Should be sufficient for testing MT
	private static final int SEED_SIZE = 624;
	private static final int[] INT_SEED = new int[SEED_SIZE];
	private static final byte[] BYTE_SEED;

	static {
		ByteBuffer bb = ByteBuffer.allocate(INT_SEED.length*4);
		for(int i=0; i<INT_SEED.length; i++){
			INT_SEED[i] = i;
			bb.putInt(i);
		}
		BYTE_SEED = bb.array();
	}

	private static final int[] INPUT_1 = new int[] {
		123456789, 123456789, 123456789, 123456789
	};
	private static final byte[] OUTPUT_1 = new byte[] {
	 (byte)0x15, (byte)0xCD, (byte)0x5B, (byte)0x7,
	 (byte)0x15, (byte)0xCD, (byte)0x5B, (byte)0x7,
	 (byte)0x15, (byte)0xCD, (byte)0x5B, (byte)0x7,
	 (byte)0x15, (byte)0xCD, (byte)0x5B, (byte)0x7
	};

	private static final byte[] EXPECTED_OUTPUT_MT_INT = new byte[] {
	 (byte)0x9a, (byte)0x6, (byte)0xab, (byte)0x8c, (byte)0x2b, (byte)0xf3,
	 (byte)0x3d, (byte)0x7f, (byte)0x6, (byte)0x4, (byte)0x5b, (byte)0x20ac,
	 (byte)0x46, (byte)0xdd, (byte)0xdf, (byte)0x47, (byte)0x28, (byte)0xc0,
	 (byte)0xb7, (byte)0x74
	 };

	private static final byte[] EXPECTED_OUTPUT_MT_LONG = new byte[] {
	 (byte)0x4f, (byte)0x75, (byte)0xda, (byte)0x52, (byte)0xe2, (byte)0x40,
	 (byte)0xf0, (byte)0x1, (byte)0x8a, (byte)0x69, (byte)0xf6, (byte)0xcb,
	 (byte)0x1a, (byte)0xe3, (byte)0x1, (byte)0xb6, (byte)0x21, (byte)0x1f,
	 (byte)0x73, (byte)0xec
	 };
	private static final byte[] EXPECTED_OUTPUT_MT_INTS = new byte[] {
	 (byte)0x1C, (byte)0x58, (byte)0xB0, (byte)0x47, (byte)0x92,
	 (byte)0xC7, (byte)0xBE, (byte)0xC4, (byte)0x25, (byte)0x64,
	 (byte)0x31, (byte)0x27, (byte)0x12, (byte)0x14, (byte)0xDB,
	 (byte)0xF, (byte)0x61, (byte)0xA6, (byte)0x73, (byte)0x32
	 };
	private static final byte[] EXPECTED_OUTPUT_MT_BYTES = new byte[] {
	 (byte)0x5C, (byte)0x6, (byte)0xAD, (byte)0x71, (byte)0x56,
	 (byte)0xDB, (byte)0xBE, (byte)0x69, (byte)0x87, (byte)0xDF,
	 (byte)0xC4, (byte)0x3B, (byte)0xCB, (byte)0x71, (byte)0x73,
	 (byte)0xF1, (byte)0x9B, (byte)0xED, (byte)0x9, (byte)0x2D,
	 };


	public void testBytesToInts() {
		// Test the consistency in order to avoid the freenet-ext #24 fiasco
		int[] output = Fields.bytesToInts(OUTPUT_1, 0, OUTPUT_1.length);

		assertEquals(INPUT_1.length, output.length);
		for(int i=0; i<INPUT_1.length; i++)
			assertEquals(INPUT_1[i], output[i]);
	}

	public void testConsistencySeedFromInts() throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		MersenneTwister mt = new MersenneTwister(INT_SEED);
		byte[] bytes = new byte[SEED_SIZE];

		mt.nextBytes(bytes);
		md.update(bytes);

		assertEquals(new String(EXPECTED_OUTPUT_MT_INTS, "UTF-8"), new String(md.digest(), "UTF-8"));
	}

	public void testConsistencySeedFromBytes() throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		MersenneTwister mt = new MersenneTwister(BYTE_SEED);
		byte[] bytes = new byte[SEED_SIZE];

		mt.nextBytes(bytes);
		md.update(bytes);

		assertEquals(new String(EXPECTED_OUTPUT_MT_BYTES, "UTF-8"), new String(md.digest(), "UTF-8"));
	}

	public void testConsistencySeedFromInteger() throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		MersenneTwister mt = new MersenneTwister(Integer.MAX_VALUE);
		byte[] bytes = new byte[SEED_SIZE];

		mt.nextBytes(bytes);
		md.update(bytes);

		assertEquals(new String(EXPECTED_OUTPUT_MT_INT, "UTF-8"), new String(md.digest(), "UTF-8"));
	}

	public void testConsistencySeedFromLong() throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		MersenneTwister mt = new MersenneTwister(Long.MAX_VALUE);
		byte[] bytes = new byte[SEED_SIZE];

		mt.nextBytes(bytes);
		md.update(bytes);

		assertEquals(new String(EXPECTED_OUTPUT_MT_LONG, "UTF-8"), new String(md.digest(), "UTF-8"));
	}
	
	/**
	 * This is a regression test which exposes a flaw in the default java 
	 * implementation in java.util.Random which is inherited by {@link MersenneTwister}
	 * class. It generates a 24 bytes using one instance of {@link MersenneTwister}, 
	 * while using the second one try to generate the same sequence step by step 
	 * by requesting 1, 2, or 3 bytes in a loop. The Oracle implementation loses 
	 * some bytes when called with buffers of length not divisible by 4. If this is 
	 * the case the output of the two instances of the {@link MersenneTwister} class
	 * will be different.  
	 */
	public void testNextBytesMethod() throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MersenneTwister mt1 = new MersenneTwister(INT_SEED);
		MersenneTwister mt2 = new MersenneTwister(INT_SEED);
		byte buff[] = new byte[24];
		mt1.nextBytes(buff);
		int m = 0;
		for (int i = 0; i < 4; i++) {
			for (int j = 1; j <= 3; j++) {
				byte buff2[] = new byte[j];
				mt2.nextBytes(buff2);
				for (int k = 0; k < j; k++) {
					Assert.assertEquals(buff[m++], buff2[k]);
				}
			}
		}
	}
	
	/**
	 * Compare the new implementation of nextBytes() method with the Oracle's 
	 * overriden implementation. 
	 * 
	 */
	public void testBenchmarkNextBytesMethod() {
		if(!TestProperty.BENCHMARK) 
			return;
		final int NO_REPETITIONS = 2000000;
		
		/** an object containing the new implementation */
		MersenneTwister mt1 = new MersenneTwister();
		/** an object containing Oracle's implementation */
		MersenneTwister mt2 = new MersenneTwister() {
			public void nextBytes(byte[] bytes) {
				for (int i = 0; i < bytes.length; )
					for (int rnd = nextInt(), n = Math.min(bytes.length - i, 4);
							n-- > 0; rnd >>= 8)	
						bytes[i++] = (byte)rnd;
			}
		};
		/** Scenario 1: call the method only with numbers divisible by 4  */
		byte b1[] = new byte[4];
		byte b2[] = new byte[64];
		long t1 = System.currentTimeMillis();
		for (int i = 0; i < NO_REPETITIONS; i++) {
			if (i % 2 == 0) {
				mt1.nextBytes(b1);
			} else {
				mt1.nextBytes(b2);
			}
		}
		long t2 = System.currentTimeMillis();
		long diff1 = t2 - t1;
		t2 = System.currentTimeMillis();
		for (int i = 0; i < NO_REPETITIONS; i++) {
			if (i % 2 == 0) {
				mt2.nextBytes(b1);
			} else {
				mt2.nextBytes(b2);
			}
		}
		t2 = System.currentTimeMillis();
		long diff2 = t2 - t1;
		System.out.println("SCENARIO 1: Oracle's code = " + diff2 + "; Our version = " + diff1);
		
		/** Scenario 2: call the method only with numbers not divisible by 4  */
		b1 = new byte[1];
		b2 = new byte[2];
		byte b3[] = new byte[3];
		t1 = System.currentTimeMillis();
		for (int i = 0; i < NO_REPETITIONS; i++) {
			if (i % 3 == 0) {
				mt1.nextBytes(b1);
			} if (i % 3 == 1) {
				mt1.nextBytes(b2);
			} else {
				mt1.nextBytes(b3);
			}
		}
		t2 = System.currentTimeMillis();
		diff1 = t2 - t1;
		t2 = System.currentTimeMillis();
		for (int i = 0; i < NO_REPETITIONS; i++) {
			if (i % 3 == 0) {
				mt2.nextBytes(b1);
			} if (i % 3 == 1) {
				mt2.nextBytes(b2);
			} else {
				mt2.nextBytes(b3);
			}
		}
		t2 = System.currentTimeMillis();
		diff2 = t2 - t1;
		System.out.println("SCENARIO 2: Oracle's code = " + diff2 + "; Our version = " + diff1);
	}
	
}
