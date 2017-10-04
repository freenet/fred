package freenet.store;

import java.io.IOException;

import freenet.crypt.CryptFormatException;
import freenet.crypt.DSAPublicKey;
import freenet.keys.KeyVerifyException;
import freenet.keys.PubkeyVerifyException;
import freenet.support.Logger;

public class PubkeyStore extends StoreCallback<DSAPublicKey> {

	@Override
	public boolean collisionPossible() {
		return false;
	}

	@Override
	public DSAPublicKey construct(byte[] data, byte[] headers,
			byte[] fullKey, boolean canReadClientCache, boolean canReadSlashdotCache, BlockMetadata meta, DSAPublicKey ignored) throws KeyVerifyException {
		if(data == null) throw new PubkeyVerifyException("Need data to construct pubkey");
		try {
			return DSAPublicKey.create(data);
		} catch (CryptFormatException e) {
			throw new PubkeyVerifyException(e);
		}
	}

	public DSAPublicKey fetch(byte[] hash, boolean dontPromote, boolean ignoreOldBlocks, BlockMetadata meta) throws IOException {
		return store.fetch(hash, null, dontPromote, false, false, ignoreOldBlocks, meta);
	}
	
	final private static byte[] empty = new byte[0];
	
	public void put(DSAPublicKey key, boolean isOldBlock) throws IOException {
		try {
			store.put(key, key.asPaddedBytes(), empty, false, isOldBlock);
		} catch (KeyCollisionException e) {
			Logger.error(this, "Impossible for PubkeyStore: "+e, e);
		}
	}
	
	@Override
	public int dataLength() {
		return DSAPublicKey.PADDED_SIZE;
	}

	@Override
	public int fullKeyLength() {
		return DSAPublicKey.HASH_LENGTH;
	}

	@Override
	public int headerLength() {
		return 0;
	}

	@Override
	public int routingKeyLength() {
		return DSAPublicKey.HASH_LENGTH;
	}

	@Override
	public boolean storeFullKeys() {
		return false;
	}

	@Override
	public boolean constructNeedsKey() {
		return false;
	}

	@Override
	public byte[] routingKeyFromFullKey(byte[] keyBuf) {
		return keyBuf;
	}
}
