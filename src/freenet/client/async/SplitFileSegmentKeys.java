package freenet.client.async;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Arrays;

import freenet.keys.ClientCHK;
import freenet.keys.NodeCHK;
import freenet.support.Logger;
import freenet.support.Fields;

/** Contains the keys for a splitfile segment, in an efficient compressed form. These are 
 * not changed, so the object never needs to be stored once created; this is good as it is
 * fairly large. SplitFileFetcherSegment keeps the data on which keys have been used 
 * separately and passes it in.
 * 
 * We will auto-upgrade SplitFileFetcherSegment's to use SplitFileSegmentKeys in the caller.
 * 
 * @author toad
 */
public class SplitFileSegmentKeys implements Cloneable, Serializable {
	
    private static final long serialVersionUID = 1L;
    public final int dataBlocks;
	public final int checkBlocks;
	/** Modern splitfiles have a common decrypt key */
	public final byte[] commonDecryptKey;
	/** Modern splitfiles have common extra bytes */
	public final byte[] commonExtraBytes;
	/** Routing keys. */
	public final byte[] routingKeys;
	/** Individual per-block decryption keys. Only on older splitfiles. */
	public final byte[] decryptKeys;
	/** Individual per-block extra bytes. */
	public final byte[] extraBytesForKeys;
	
	static final int EXTRA_BYTES_LENGTH = ClientCHK.EXTRA_LENGTH;

	// Bare constructor for Metadata. It will read the actual keys later.
	public SplitFileSegmentKeys(int blocksPerSegment, int checkBlocksPerSegment, byte[] splitfileSingleCryptoKey, byte splitfileSingleCryptoAlgorithm) {
		this.dataBlocks = blocksPerSegment;
		this.checkBlocks = checkBlocksPerSegment;
		routingKeys = new byte[NodeCHK.KEY_LENGTH * (dataBlocks + checkBlocks)];
		if(splitfileSingleCryptoKey != null) {
			commonDecryptKey = splitfileSingleCryptoKey;
			commonExtraBytes = ClientCHK.getExtra(splitfileSingleCryptoAlgorithm, (short)-1, false);
			decryptKeys = null;
			extraBytesForKeys = null;
		} else {
			commonDecryptKey = null;
			commonExtraBytes = null;
			decryptKeys = new byte[ClientCHK.CRYPTO_KEY_LENGTH * (dataBlocks + checkBlocks)];
			extraBytesForKeys = new byte[EXTRA_BYTES_LENGTH * (dataBlocks + checkBlocks)];
		}
	}
	
	protected SplitFileSegmentKeys() {
        // For serialization.
	    dataBlocks = 0;
	    checkBlocks = 0;
	    commonDecryptKey = null;
	    commonExtraBytes = null;
	    routingKeys = null;
	    decryptKeys = null;
	    extraBytesForKeys = null;
	}

	public int getBlockNumber(ClientCHK key, boolean[] ignoreSlots) {
		byte[] rkey = key.getRoutingKey();
		byte[] ckey = null;
		byte[] extra = null;
		int x = 0;
		for(int i=0;i<(dataBlocks + checkBlocks);i++) {
			int oldX = x;
			x += NodeCHK.KEY_LENGTH;
			if(ignoreSlots != null && ignoreSlots[i]) {
				continue;
			}
			if(!Fields.byteArrayEqual(routingKeys, rkey, oldX, 0, NodeCHK.KEY_LENGTH))
				continue;
			if(ckey == null) ckey = key.getCryptoKey();
			assert(ClientCHK.CRYPTO_KEY_LENGTH == NodeCHK.KEY_LENGTH);
			// FIXME USE THE RIGHT CONSTANT, DONT ASSUME THE TWO LENGTHS ARE THE SAME
			if(commonDecryptKey != null) {
				if(!Arrays.equals(commonDecryptKey, ckey)) continue;
			} else {
				if(!Fields.byteArrayEqual(decryptKeys,ckey,oldX,0,NodeCHK.KEY_LENGTH))
					continue;
			}
			if(extra == null) extra = key.getExtra();
			if(commonExtraBytes != null) {
				if(!Arrays.equals(commonExtraBytes, extra)) continue;
			} else {
				if(!Fields.byteArrayEqual(extraBytesForKeys, extra, i * EXTRA_BYTES_LENGTH, 0, EXTRA_BYTES_LENGTH))
					continue;
			}
			return i;
		}
		return -1;
	}
	
	public int getBlockNumber(NodeCHK key, boolean[] ignoreSlots) {
		byte[] rkey = key.getRoutingKey();
		int x = 0;
		for(int i=0;i<(dataBlocks + checkBlocks);i++) {
			int oldX = x;
			x += NodeCHK.KEY_LENGTH;
			if(ignoreSlots != null && ignoreSlots[i]) {
				continue;
			}
			if(!Fields.byteArrayEqual(routingKeys, rkey, oldX, 0, NodeCHK.KEY_LENGTH))
				continue;
			return i;
		}
		return -1;
	}
	
	public int[] getBlockNumbers(NodeCHK key, boolean[] ignoreSlots) {
		ArrayList<Integer> results = null;
		byte[] rkey = key.getRoutingKey();
		int x = 0;
		for(int i=0;i<(dataBlocks + checkBlocks);i++) {
			int oldX = x;
			x += NodeCHK.KEY_LENGTH;
			if(ignoreSlots != null && ignoreSlots[i]) {
				continue;
			}
			if(!Fields.byteArrayEqual(routingKeys, rkey, oldX, 0, NodeCHK.KEY_LENGTH))
				continue;
			if(results == null) results = new ArrayList<Integer>();
			results.add(i);
		}
		if(results == null) return new int[0];
		int[] ret = new int[results.size()];
		for(int i=0;i<ret.length;i++) ret[i] = results.get(i);
		return ret;
	}
	
	public NodeCHK getNodeKey(int x, boolean[] ignoreSlots) {
		if(ignoreSlots != null) {
			if(ignoreSlots[x]) return null;
		}
		return getNodeKey(x);
	}
	
	public ClientCHK getKey(int x, boolean[] ignoreSlots, boolean copy) {
		if(ignoreSlots != null) {
			if(ignoreSlots[x]) return null;
		}
		return getKey(x, copy);
	}

	private ClientCHK getKey(int x, boolean copy) {
		byte[] routingKey = new byte[32];
		System.arraycopy(routingKeys, x * NodeCHK.KEY_LENGTH, routingKey, 0, NodeCHK.KEY_LENGTH);
		byte[] decryptKey;
		if(commonDecryptKey != null) {
			if(copy) {
				decryptKey = commonDecryptKey.clone();
			} else {
				decryptKey = commonDecryptKey;
			}
		} else {
			int offset = x * ClientCHK.CRYPTO_KEY_LENGTH;
			decryptKey = Arrays.copyOfRange(decryptKeys, offset, offset + ClientCHK.CRYPTO_KEY_LENGTH);
		}
		byte[] extra;
		if(commonExtraBytes != null) {
			if(copy) {
				extra = commonExtraBytes.clone();
			} else {
				extra = commonExtraBytes;
			}
		} else {
			int offset = x * EXTRA_BYTES_LENGTH;
			extra = Arrays.copyOfRange(extraBytesForKeys, offset, offset + EXTRA_BYTES_LENGTH);
		}
		try {
			return new ClientCHK(routingKey, decryptKey, extra);
		} catch (MalformedURLException e) {
			Logger.error(this, "Impossible: "+e);
			throw new IllegalStateException(e);
		}
	}

	private NodeCHK getNodeKey(int x) {
		int xr = x * NodeCHK.KEY_LENGTH;
		byte[] routingKey = Arrays.copyOfRange(routingKeys, xr, xr + NodeCHK.KEY_LENGTH);
		byte[] extra;
		if(commonExtraBytes != null) {
			extra = commonExtraBytes;
		} else {
			int xe = x * EXTRA_BYTES_LENGTH;
			extra = Arrays.copyOfRange(extraBytesForKeys, xe, xe + EXTRA_BYTES_LENGTH);
		}
		
		byte cryptoAlgorithm = ClientCHK.getCryptoAlgorithmFromExtra(extra);
		
		return new NodeCHK(routingKey, cryptoAlgorithm);
	}

	public void readKeys(DataInputStream dis, boolean check) throws IOException {
		int count = check ? checkBlocks : dataBlocks;
		int offset = check ? dataBlocks : 0;
		if(commonDecryptKey != null) {
			int rkOffset = offset * NodeCHK.KEY_LENGTH;
			for(int i=0;i<count;i++) {
				dis.readFully(routingKeys, rkOffset, NodeCHK.KEY_LENGTH);
				rkOffset += NodeCHK.KEY_LENGTH;
			}
		} else {
			int rkOffset = offset * NodeCHK.KEY_LENGTH;
			int extraOffset = offset * EXTRA_BYTES_LENGTH;
			assert(NodeCHK.KEY_LENGTH == ClientCHK.CRYPTO_KEY_LENGTH);
			for(int i=0;i<count;i++) {
				ClientCHK key = ClientCHK.readRawBinaryKey(dis);
				byte[] r = key.getRoutingKey();
				System.arraycopy(r, 0, routingKeys, rkOffset, NodeCHK.KEY_LENGTH);
				byte[] c = key.getCryptoKey();
				System.arraycopy(c, 0, decryptKeys, rkOffset, NodeCHK.KEY_LENGTH);
				rkOffset += NodeCHK.KEY_LENGTH;
				byte[] e = key.getExtra();
				System.arraycopy(e, 0, extraBytesForKeys, extraOffset, EXTRA_BYTES_LENGTH);
				extraOffset += EXTRA_BYTES_LENGTH;
			}
		}
	}

	public void writeKeys(DataOutputStream dos, boolean check) throws IOException {
		int count = check ? checkBlocks : dataBlocks;
		int offset = check ? dataBlocks : 0;
		if(commonDecryptKey != null) {
			int rkOffset = offset * NodeCHK.KEY_LENGTH;
			for(int i=0;i<count;i++) {
				dos.write(routingKeys, rkOffset, NodeCHK.KEY_LENGTH);
				rkOffset += NodeCHK.KEY_LENGTH;
			}
		} else {
			int rkOffset = offset * NodeCHK.KEY_LENGTH;
			int extraOffset = offset * EXTRA_BYTES_LENGTH;
			assert(NodeCHK.KEY_LENGTH == ClientCHK.CRYPTO_KEY_LENGTH);
			for(int i=0;i<count;i++) {
				dos.write(extraBytesForKeys, extraOffset, EXTRA_BYTES_LENGTH);
				extraOffset += EXTRA_BYTES_LENGTH;
				dos.write(routingKeys, rkOffset, NodeCHK.KEY_LENGTH);
				dos.write(decryptKeys, rkOffset, NodeCHK.KEY_LENGTH);
				rkOffset += NodeCHK.KEY_LENGTH;
			}
		}
	}
	
    public static int storedKeysLength(int dataBlocks, int checkBlocks, boolean commonDecryptKey) {
        // FIXME URGENT Implement a unit test for storedKeysLength() vs writeKeys() vs readKeys().
        int blocks = dataBlocks + checkBlocks;
        if(commonDecryptKey) {
            return blocks * NodeCHK.KEY_LENGTH;
        } else {
            return blocks * (EXTRA_BYTES_LENGTH + NodeCHK.KEY_LENGTH*2);
        }
    }

	public int getDataBlocks() {
		return dataBlocks;
	}

	public int getCheckBlocks() {
		return checkBlocks;
	}

	public void setKey(int i, ClientCHK key) {
		byte[] r = key.getRoutingKey();
		System.arraycopy(r, 0, routingKeys, i * NodeCHK.KEY_LENGTH, NodeCHK.KEY_LENGTH);
		if(decryptKeys != null) {
			byte[] c = key.getCryptoKey();
			System.arraycopy(c, 0, decryptKeys, i * ClientCHK.CRYPTO_KEY_LENGTH, ClientCHK.CRYPTO_KEY_LENGTH);
		}
		if(extraBytesForKeys != null) {
			byte[] e = key.getExtra();
			System.arraycopy(e, 0, extraBytesForKeys, i * EXTRA_BYTES_LENGTH, EXTRA_BYTES_LENGTH);
		}
	}

	public NodeCHK[] listNodeKeys(boolean[] foundKeys) {
		ArrayList<NodeCHK> list = new ArrayList<NodeCHK>();
		for(int i=0;i<dataBlocks+checkBlocks;i++) {
			NodeCHK k = getNodeKey(i, foundKeys);
			if(k == null) continue;
			list.add(k);
		}
		return list.toArray(new NodeCHK[list.size()]);
	}
	
	@Override
	public SplitFileSegmentKeys clone() {
		try {
			return (SplitFileSegmentKeys) super.clone();
		} catch (CloneNotSupportedException e) {
			throw new Error("Yes it is!");
		}
	}

	// Not often used, not very efficient, but overriding equals() requires overriding hashCode().
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + checkBlocks;
        result = prime * result + Arrays.hashCode(commonDecryptKey);
        result = prime * result + Arrays.hashCode(commonExtraBytes);
        result = prime * result + dataBlocks;
        result = prime * result + Arrays.hashCode(decryptKeys);
        result = prime * result + Arrays.hashCode(extraBytesForKeys);
        result = prime * result + Arrays.hashCode(routingKeys);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        SplitFileSegmentKeys other = (SplitFileSegmentKeys) obj;
        if (checkBlocks != other.checkBlocks)
            return false;
        if (!Arrays.equals(commonDecryptKey, other.commonDecryptKey))
            return false;
        if (!Arrays.equals(commonExtraBytes, other.commonExtraBytes))
            return false;
        if (dataBlocks != other.dataBlocks)
            return false;
        if (!Arrays.equals(decryptKeys, other.decryptKeys))
            return false;
        if (!Arrays.equals(extraBytesForKeys, other.extraBytesForKeys))
            return false;
        if (!Arrays.equals(routingKeys, other.routingKeys))
            return false;
        return true;
    }

    public int totalKeys() {
        return checkBlocks + dataBlocks;
    }

}
