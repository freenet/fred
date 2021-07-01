/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;

import net.i2p.util.NativeBigInteger;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import junit.framework.TestCase;

public class HashTest {
	static private byte[] helloWorld = "hello world".getBytes(Charset.forName("UTF-8"));
	static private byte[] nullArray = null;
	static private final HashType[] types = {HashType.MD5, HashType.ED2K, HashType.SHA1, 
	    HashType.TTH, HashType.SHA256, HashType.SHA384, HashType.SHA512};
	static private final String[] trueHashes = {
		"5eb63bbbe01eeed093cb22bb8f5acdc3",
		"aa010fbc1d14c795d86ef98c95479d17",
		"2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
		"ca1158e471d147bb714a6b1b8a537ff756f7abe1b63dc11d",
		"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		"fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3"
		+ "e417cb71ce646efd0819dd8c088de1bd",
		"309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f"
		+ "989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
	};
	static private final String[] falseHashes = {
		"aa010fbc1d14c795d86ef98c95479d17",
		"5eb63bbbe01eeed093cb22bb8f5acdc3",
		"309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee",
		"2aae6c35c94fcfb415dbe95f408b9ce91ee846edb63dc11d",
		"ca1158e471d147bb714a6b1b8a537ff756f7abe1b63dc11d9088f7ace2efcde9",
		"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9e417cb71ce646efd0819dd8c08"
		+ "8de1bd",
		"fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c08"
		+ "8de1bdd830e81f605dcf7dc5542e93ae9cd76f"
	};
	
	@Test
	// This also tests addBytes(byte[]...) and getHash()
	public void testGetHashByteArrayArray() {
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			byte[] abcResult = hash.genHash(helloWorld);
			byte[] expectedABCResult = Hex.decode(trueHashes[i]);
			assertArrayEquals("HashType: "+types[i].name(), abcResult, expectedABCResult);
		}
	}

	@Test
	// This also tests addBytes(byte[]...) and getHash()
	public void testGetHashByteArrayArrayReset() {
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			byte[] abcResult = hash.genHash(helloWorld);
			byte[] abcResult2 = hash.genHash(helloWorld);
			assertArrayEquals("HashType: "+types[i].name(), abcResult, abcResult2);
		}
	}


	@Test
	// This also tests addBytes(byte[]...) and getHash()
	public void testGetHashByteArrayArraySameAsMessageDigest() {
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			MessageDigest md = types[i].get();
			byte[] mdResult = md.digest(helloWorld);
			byte[] hashResult = hash.genHash(helloWorld);
			assertArrayEquals("HashType: "+types[i].name(), mdResult, hashResult);
		}
	}

	@Test
	// This also tests addBytes(byte[]...) and getHash()
	public void testGetHashByteArrayArrayNullInput() {
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			
			boolean throwNull = false;
			try{
				hash.genHash(nullArray);
			}catch(NullPointerException e){
				throwNull = true;
			}
			assertTrue("HashType: "+types[i].name(), throwNull);
		}
	}

	@Test
	// This also tests addBytes(byte[]...)
	public void testGetHashByteArrayArrayNullMatrixElementInput() {
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			boolean throwNulls = false;
			byte[][] nullMatrix = {helloWorld, null};
			try{
				hash.genHash(nullMatrix);
			}catch(NullPointerException e){
				throwNulls = true;
			}
			assertTrue("HashType: "+types[i].name(), throwNulls);
		}
	}

	@Test
	// tests getHashResult() as well
	public void testGetHashResultHashResultByteArray() {
		for(int i = 0; i < types.length; i++){
			HashResult hash2 = new HashResult(types[i], Hex.decode(trueHashes[i]));
			Hash hash = new Hash(types[i]);
			HashResult hash1 = hash.genHashResult(helloWorld);
			assertTrue("HashType: "+types[i].name(), Hash.verify(hash1, hash2));
		}
	}

	@Test
	public void testGetHashHex(){
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			hash.addBytes(helloWorld);
			String hexHash = hash.genHexHash();
			assertEquals("HashType: "+types[i].name(), trueHashes[i], hexHash);
		}
	}

	@Test
	public void testGetNativeBigIntegerHashByteArrayArray(){
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			NativeBigInteger abcVector = new NativeBigInteger(1, Hex.decode(trueHashes[i]));
			NativeBigInteger result = hash.genNativeBigIntegerHash(helloWorld);
			assertEquals("HashType: "+types[i].name(), abcVector, result);
		}	
	}

	@Test
	public void testAddByteByte(){
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);

			for (int j = 0; j < helloWorld.length; j++){
				hash.addByte(helloWorld[j]);
			}
			assertArrayEquals("HashType: "+types[i].name(), 
			        Hex.decode(trueHashes[i]), hash.genHash());	
		}
	}

	@Test
	@SuppressWarnings("null")
	public void testAddByteByteNullInput(){
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			boolean throwNull = false;
			Byte nullByte = null;
			try{
				hash.addByte(nullByte);
			}catch(NullPointerException e){
				throwNull = true;
			}
			assertTrue("HashType: "+types[i].name(), throwNull);
		}
	}

	@Test
	public void testAddBytesByteBuffer(){
		for(int i = 0; i < types.length; i++){
			ByteBuffer byteBuffer = ByteBuffer.wrap(helloWorld);
			Hash hash = new Hash(types[i]); 
			hash.addBytes(byteBuffer);
			assertArrayEquals("HashType: "+types[i].name(), 
			        Hex.decode(trueHashes[i]), hash.genHash());
		}
	}

	@Test
	public void testAddBytesByteBufferNullInput(){
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]); 
			boolean throwNull = false;
			ByteBuffer nullBuffer = null;
			try{
				hash.addBytes(nullBuffer);
			}catch(NullPointerException e){
				throwNull = true;
			}
			assertTrue("HashType: "+types[i].name(), throwNull);
		}
	}

	@Test
	public void testAddByteByteArrayIntInt(){
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			hash.addBytes(helloWorld, 0, helloWorld.length/2);
			hash.addBytes(helloWorld, helloWorld.length/2, helloWorld.length-helloWorld.length/2);
			assertArrayEquals("HashType: "+types[i].name(), 
			        Hex.decode(trueHashes[i]), hash.genHash());	
		}
	}

	@Test
	public void testAddByteByteArrayIntIntNullInput(){
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			boolean throwNull = false;
			byte[] nullArray = null;
			try{
				hash.addBytes(nullArray, 0, helloWorld.length);
			}catch(IllegalArgumentException e){
				throwNull = true;
			}
			assertTrue("HashType: "+types[i].name(), throwNull);
		}
	}

	@Test
	public void testAddByteByteArrayIntIntOffsetOutOfBounds(){
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			boolean throwOutOfBounds = false;
			try{
				hash.addBytes(helloWorld, -3, helloWorld.length-3);
			}catch(ArrayIndexOutOfBoundsException e){
				throwOutOfBounds = true;
			}
			assertTrue("HashType: "+types[i].name(), throwOutOfBounds);
		}
	}

	@Test
	public void testAddByteByteArrayIntIntLengthOutOfBounds(){
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			boolean throwOutOfBounds = false;
			try{
				hash.addBytes(helloWorld, 0, helloWorld.length+3);
			}catch(IllegalArgumentException e){
				throwOutOfBounds = true;
			}
			assertTrue("HashType: "+types[i].name(), throwOutOfBounds);
		}
	}

	@Test
	public void testVerifyByteArrayByteArray() {
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			assertTrue("HashType: "+types[i].name(), 
			        hash.verify(Hex.decode(trueHashes[i]), helloWorld));
		}
	}

	@Test
	public void testVerifyByteArrayByteArrayFalse() {
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			assertFalse("HashType: "+types[i].name(), 
			        hash.verify(Hex.decode(falseHashes[i]), helloWorld));
		}
	}

	@Test
	public void testVerifyByteArrayByteArrayWrongSizeMac() {
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			
			assertFalse("HashType: "+types[i].name(), hash.verify(helloWorld, helloWorld));
		}
	}

	@Test
	public void testVerifyByteArrayByteArrayNullInputPos1() {
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			boolean throwResult = false;
			try{
				hash.verify(nullArray, helloWorld);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue("HashType: "+types[i].name(), throwResult);
		}
	}

	@Test
	public void testVerifyByteArrayByteArrayNullInputPos2() {
		for(int i = 0; i < types.length; i++){
			Hash hash = new Hash(types[i]);
			boolean throwResult = false;
			try{
				hash.verify(helloWorld, nullArray);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue("HashType: "+types[i].name(), throwResult);
		}
	}

	@Test
	public void testVerifyHashResultByteArray() {
		for(int i = 0; i < types.length; i++){
			byte[] hash1 = helloWorld;
			HashResult hashResult = new HashResult(types[i], Hex.decode(trueHashes[i]));

			assertTrue("HashType: "+types[i].name(), Hash.verify(hashResult, hash1));
		}
	}

	@Test
	public void testVerifyHashResultByteArrayFalse() {
		for(int i = 0; i < types.length; i++){
			byte[] hash1 = helloWorld;
			HashResult hashResult = new HashResult(types[i], Hex.decode(falseHashes[i]));

			assertFalse("HashType: "+types[i].name(), Hash.verify(hashResult, hash1));
		}
	}

	@Test
	public void testVerifyHashResultByteArrayWrongSizeMac() {
		for(int i = 0; i < types.length; i++){
			byte[] hash1 = helloWorld;
			HashResult hashResult = new HashResult(types[i], hash1, true);

			assertFalse("HashType: "+types[i].name(), Hash.verify(hashResult, hash1));
		}
	}

	@Test
	public void testVerifyHashResultByteArrayNullInputPos1() {
		for(int i = 0; i < types.length; i++){
			byte[] hashResult = Hex.decode(trueHashes[i]);
			boolean throwResult = false;
			HashResult nullResult = null;
			try{
				Hash.verify(nullResult, hashResult);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue("HashType: "+types[i].name(), throwResult);
		}
	}

	@Test
	public void testVerifyHashResultByteArrayNullInputPos2() {
		for(int i = 0; i < types.length; i++){
			HashResult hash1 = new HashResult(types[i], Hex.decode(trueHashes[i]));
			boolean throwResult = false;
			try{
				Hash.verify(hash1, nullArray);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue("HashType: "+types[i].name(), throwResult);
		}
	}

	@Test
	public void testVerifyHashResultHashResult() {
		for(int i = 0; i < types.length; i++){
			HashResult hash = new HashResult(types[i], Hex.decode(trueHashes[i]));

			assertTrue("HashType: "+types[i].name(), Hash.verify(hash, hash));
		}
	}

	@Test
	public void testVerifyHashResultHashResultFalse() {
		for(int i = 0; i < types.length; i++){
			HashResult hash1 = new HashResult(types[i], Hex.decode(trueHashes[i]));
			HashResult hash2 = new HashResult(types[i], Hex.decode(falseHashes[i]));

			assertFalse("HashType: "+types[i].name(), Hash.verify(hash1, hash2));
		}
	}

	@Test
	public void testVerifyHashResultHashResultNullInputPos1() {
		for(int i = 0; i < types.length; i++){
			HashResult hash = new HashResult(types[i], Hex.decode(trueHashes[i]));
			boolean throwResult = false;
			HashResult nullResult = null;
			try{
				Hash.verify(nullResult, hash);
			}catch(NullPointerException e){
				throwResult = true;
			}
			assertTrue("HashType: "+types[i].name(), throwResult);
		}
	}

	@Test
	public void testVerifyHashResultHashResultNullInputPos2() {
		for(int i = 0; i < types.length; i++){
			HashResult hash = new HashResult(types[i], Hex.decode(trueHashes[i]));
			HashResult nullResult = null;

			assertFalse("HashType: "+types[i].name(), Hash.verify(hash, nullResult));
		}
	}
}
