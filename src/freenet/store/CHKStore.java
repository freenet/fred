package freenet.store;

import java.io.IOException;

import freenet.crypt.DSAPublicKey;
import freenet.keys.CHKBlock;
import freenet.keys.CHKVerifyException;
import freenet.keys.KeyVerifyException;
import freenet.keys.NodeCHK;
import freenet.support.Logger;

public class CHKStore extends StoreCallback<CHKBlock> {

	@Override
	public boolean collisionPossible() {
		return false;
	}

	@Override
	public CHKBlock construct(byte[] data, byte[] headers,
			byte[] fullKey, boolean canReadClientCache, boolean canReadSlashdotCache, BlockMetadata meta, DSAPublicKey ignored) throws KeyVerifyException {
		if(data == null || headers == null) throw new CHKVerifyException("Need either data and headers");
		return CHKBlock.construct(data, headers, NodeCHK.cryptoAlgorithmFromFullKey(fullKey));
	}

	public CHKBlock fetch(NodeCHK chk, boolean dontPromote, boolean ignoreOldBlocks, BlockMetadata meta) throws IOException {
		// FIXME optimize: change API so we can just pass in the crypto algorithm rather than having to construct the full key???
		return store.fetch(chk.getRoutingKey(), chk.getFullKey(), dontPromote, false, false, ignoreOldBlocks, meta);
	}
	
	public void put(CHKBlock b, boolean isOldBlock) throws IOException {
		try {
			store.put(b, b.getRawData(), b.getRawHeaders(), false, isOldBlock);
		} catch (KeyCollisionException e) {
			Logger.error(this, "Impossible for CHKStore: "+e, e);
		}
	}
	
	@Override
	public int dataLength() {
		return CHKBlock.DATA_LENGTH;
	}

	@Override
	public int fullKeyLength() {
		return NodeCHK.FULL_KEY_LENGTH;
	}
	@Override
	public int headerLength() {
		return CHKBlock.TOTAL_HEADERS_LENGTH;
	}

	@Override
	public int routingKeyLength() {
		return NodeCHK.KEY_LENGTH;
	}

	@Override
	public boolean storeFullKeys() {
		// Worth the extra two file descriptors, because if we have the keys we can do lazy 
		// reconstruction i.e. don't construct each block, just transcode from the .keys file
		// straight into the database.
		return true;
	}

	@Override
	public boolean constructNeedsKey() {
		return false;
	}

	@Override
	public byte[] routingKeyFromFullKey(byte[] keyBuf) {
		return NodeCHK.routingKeyFromFullKey(keyBuf);
	}

}
