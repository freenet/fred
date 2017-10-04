package freenet.store;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import freenet.crypt.DSAGroup;
import freenet.crypt.DSAPrivateKey;
import freenet.crypt.DSAPublicKey;
import freenet.crypt.Global;
import freenet.support.ByteArrayWrapper;
import freenet.support.math.MersenneTwister;
import junit.framework.TestCase;

public class PubkeyStoreTest extends TestCase {
	
	public void testSimple() throws IOException {
		final int keys = 10;
		PubkeyStore pk = new PubkeyStore();
		new RAMFreenetStore<DSAPublicKey>(pk, keys);
		DSAGroup group = Global.DSAgroupBigA;
		Random random = new MersenneTwister(1010101);
		HashMap<ByteArrayWrapper, DSAPublicKey> map = new HashMap<ByteArrayWrapper, DSAPublicKey>();
		for(int i=0;i<keys;i++) {
			DSAPrivateKey privKey = new DSAPrivateKey(group, random);
			DSAPublicKey key = new DSAPublicKey(group, privKey);
			byte[] hash = key.asBytesHash();
			ByteArrayWrapper w = new ByteArrayWrapper(hash);
			map.put(w, key.cloneKey());
			pk.put(key, false);
			assertTrue(pk.fetch(hash, false, false, null).equals(key));
		}
		int x = 0;
		for(Map.Entry<ByteArrayWrapper, DSAPublicKey> entry : map.entrySet()) {
			x++;
			assertTrue(pk.fetch(entry.getKey().get(), false, false, null).equals(entry.getValue()));
		}
		assert(x == keys);
	}

}
