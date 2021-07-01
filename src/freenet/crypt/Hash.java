/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import java.nio.ByteBuffer;
import java.security.MessageDigest;

import net.i2p.util.NativeBigInteger;
import freenet.support.HexUtil;

/**
 * The Hash class will generate the hash value of a given set of bytes and also verify that
 * a hash matches a given set of bytes. The addBytes methods can be used to pass data into 
 * a buffer that will be used to generate a hash. Once a hash is generated, the buffer is 
 * cleared or reset. 
 * @author unixninja92
 * Suggested HashType to use: SHA256
 */
public final class Hash{
	private final HashType type;
	private MessageDigest digest;
	
	/**
	 * Creates an instance of Hash using the specified hashing algorithm.
	 * @param type The hashing algorithm to use. 
	 */
	public Hash(HashType type){
		this.type = type;
		digest = type.get();
	}
	
	/**
	 * Generates the hash of all the bytes in the buffer added with the
	 * addBytes methods. The buffer is then cleared after the hash has been
	 * generated.
	 * @return The generated hash of all the bytes added since last reset.
	 */
	public final byte[] genHash(){
		byte[] result = digest.digest();
		if(type == HashType.ED2K){
			//ED2K does not reset after generating a digest. Work around this issue
			digest.reset();
		}else if(type == HashType.TTH){
			//TTH's .reset method is broken or isn't implemented. Work around this bug
			digest = type.get();
		}
		return result;
	}
	
	/**
	 * Generates the hash of only the specified bytes. The buffer is cleared before 
	 * processing the input to ensure that no extra data is included. Once the hash
	 * has been generated, the buffer is cleared again. 
	 * @param input The bytes to hash
	 * @return The generated hash of the data
	 */
	public final byte[] genHash(byte[]... input) {
		digest.reset();
		addBytes(input);
		return genHash();
	}
	
	/**
	 * Generates the HashResult of all the bytes in the buffer added with the
	 * addBytes methods. The buffer is then cleared after the hash has been
	 * generated.
	 * @return The generated hash as a HashResult of all the bytes added 
	 * since last reset.
	 */
	public final HashResult genHashResult() {
		return new HashResult(type, genHash());
	}
	
	/**
	 * Generates the hash as a HashResult string of only the specified bytes. 
	 * The buffer is cleared before processing the input to ensure that no 
	 * extra data is included. Once the hash has been generated, the buffer 
	 * is cleared again. 
	 * @param input The bytes to hash
	 * @return The generated hash as a HashResult of the data
	 */
	public final HashResult genHashResult(byte[]... input){
		digest.reset();
		addBytes(input);
		return genHashResult();
	}
	
	/**
	 * Generates the hash as a hex string of all the bytes in the buffer added 
	 * with the addBytes methods. The buffer is then cleared after the hash 
	 * has been generated.
	 * @return The generated hash as a hex string of all the bytes added since 
	 * last reset.
	 */
	public final String genHexHash() {
		return HexUtil.bytesToHex(genHash());
	}
	
	/**
	 * Generates the hash as a NativeBigInteger of all the bytes in the buffer 
	 * added with the addBytes methods. The buffer is then cleared after the hash 
	 * has been generated.
	 * @return The generated hash as a NativeBigInteger of all the bytes added 
	 * since last reset.
	 */
	public final NativeBigInteger genNativeBigIntegerHash(){
		return new NativeBigInteger(1, genHash());
	}
	
	/**
	 * Generates the hash as a NativeBigInteger string of only the specified 
	 * bytes. The buffer is cleared before processing the input to ensure that 
	 * no extra data is included. Once the hash has been generated, the buffer 
	 * is cleared again. 
	 * @param input The bytes to hash
	 * @return The generated hash as a NativeBigInteger of the data
	 */
	public final NativeBigInteger genNativeBigIntegerHash(byte[]... data){
		digest.reset();
		addBytes(data);
		return genNativeBigIntegerHash();
	}
	
	/**
	 * Adds the specified byte to the buffer of bytes to be hashed. 
	 * @param input Byte to be added to hash
	 */
	public final void addByte(byte input){
		digest.update(input);
	}

	/**
	 * Adds the specified byte arrays to the buffer of bytes to be hashed. 
	 * @param input The byte[]s to add
	 */
	public final void addBytes(byte[]... input){
		for(byte[] b: input){
			digest.update(b);
		}
	}

	/**
	 * Adds the remaining bytes from a  ByteBuffer to the buffer of bytes 
	 * to be hashed. The bytes read from the ByteBuffer will be from 
	 * input.position() to input.remaining(). Upon return, the ByteBuffer's
	 * .position() will be equal to .remaining() and .remaining() will 
	 * stay unchanged. 
	 * @param input The ByteBuffer to be hashed
	 */
	public final void addBytes(ByteBuffer input){
		digest.update(input);
	}
	
	/**
	 * Adds the specified portion of the byte[] passed in to the buffer 
	 * of bytes to be hashed.
	 * @param input The array containing bytes to be hashed
	 * @param offset Where the first byte to hash is
	 * @param len How many bytes after the offset to add to hash.
	 */
	public final void addBytes(byte[] input, int offset, int len){
		digest.update(input, offset, len);
	}
	
	/**
	 * Generates the hash of the byte arrays provided and checks to see if that hash
	 * is the same as the one passed in. The buffer is cleared before processing the 
	 * input to ensure that no extra data is included. Once the hash has been 
	 * generated, the buffer is cleared again. 
	 * @param hash The hash to be verified
	 * @param data The data to be hashed
	 * @return Returns true if the generated hash matches the passed in hash. 
	 * Otherwise returns false.
	 */
	public final boolean verify(byte[] hash, byte[]... data){
		return MessageDigest.isEqual(hash, genHash(data));
	}
	
	/**
	 * Checks to see if the HashResults passed in are equivalent. Does a simple byte
	 * compare and type compare.
	 * @param hash1 The first hash to be compared
	 * @param hash2 The second hash to be compared
	 * @return Returns true if the hashes are the same. Otherwise returns false. 
	 */
	public final static boolean verify(HashResult hash1, HashResult hash2){
		return hash1.equals(hash2);
	}	
	
	/**
	 * Checks to see if the provided HashResult is equivalt to the HashResult
	 * generated from the given byte array.
	 * @param hash The HashResult to verify
	 * @param input The data to check against the HashResult
	 * @return Returns true if HashResult matches the generated HashResult of the data.
	 */
	public final static boolean verify(HashResult hash, byte[]... input){
		HashType type = hash.type;
		Hash h = new Hash(type);
		return verify(hash, new HashResult(type, h.genHash(input)));
	}
	
}
