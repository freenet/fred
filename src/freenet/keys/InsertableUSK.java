/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.keys;

import java.net.MalformedURLException;

import freenet.crypt.DSAGroup;
import freenet.crypt.DSAPrivateKey;
import freenet.crypt.DSAPublicKey;
import freenet.crypt.Global;
import freenet.support.Logger;

/**
 * An insertable USK.
 * 
 * Changes from an ordinary USK:
 * - It has a private key
 * - getURI() doesn't include ,extra
 * - constructor from URI doesn't need or want ,extra
 * - It has a getUSK() method which gets the public USK
 */
public class InsertableUSK extends USK {
	
    private static final long serialVersionUID = 1L;
    public final DSAPrivateKey privKey;
	
	public static InsertableUSK createInsertable(FreenetURI uri) throws MalformedURLException {
		if(!uri.getKeyType().equalsIgnoreCase("USK"))
			throw new MalformedURLException();
		InsertableClientSSK ssk =
			InsertableClientSSK.create(uri.setKeyType("SSK"));
		return new InsertableUSK(ssk.docName, ssk.pubKeyHash, ssk.cryptoKey, ssk.privKey, uri.getSuggestedEdition(), ssk.cryptoAlgorithm);
	}
	
	InsertableUSK(String docName, byte[] pubKeyHash, byte[] cryptoKey, DSAPrivateKey key, long suggestedEdition, byte cryptoAlgorithm) throws MalformedURLException {
		super(pubKeyHash, cryptoKey, docName, suggestedEdition, cryptoAlgorithm);
		if(cryptoKey.length != ClientSSK.CRYPTO_KEY_LENGTH)
			throw new MalformedURLException("Decryption key wrong length: "+cryptoKey.length+" should be "+ClientSSK.CRYPTO_KEY_LENGTH);
		this.privKey = key;
	}

	public USK getUSK() {
		return new USK(pubKeyHash, cryptoKey, siteName, suggestedEdition, cryptoAlgorithm);
	}

	public InsertableClientSSK getInsertableSSK(long ver) {
		return getInsertableSSK(siteName + SEPARATOR + ver);
	}
	
	public InsertableClientSSK getInsertableSSK(String string) {
		try {
			return new InsertableClientSSK(string, pubKeyHash, 
					new DSAPublicKey(getCryptoGroup(), privKey), privKey, cryptoKey, cryptoAlgorithm);
		} catch (MalformedURLException e) {
			Logger.error(this, "Caught "+e+" should not be possible in USK.getSSK", e);
			throw new Error(e);
		}
	}

	public InsertableUSK privCopy(long edition) {
		if(edition == suggestedEdition) return this;
		try {
			return new InsertableUSK(siteName, pubKeyHash, cryptoKey, privKey, edition, cryptoAlgorithm);
		} catch (MalformedURLException e) {
			throw new Error(e);
		}
	}

	public final DSAGroup getCryptoGroup() {
		return Global.DSAgroupBigA;
	}
}
