package freenet.crypt;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.lang.reflect.Constructor;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;

import freenet.support.Logger;
import freenet.support.io.Closer;

public class JceLoader {
	static public final Provider BouncyCastle;
	static public final Provider NSS; // optional, may be null
	static public final Provider SUN; // optional, may be null
	static public final Provider SunJCE; // optional, may be null
	static private boolean checkUse(String prop)
	{
		return checkUse(prop, "true");
	}
	static private boolean checkUse(String prop, String def)
	{
		return "true".equalsIgnoreCase(System.getProperty("freenet.jce."+prop, def));
	}
	static {
		Provider p;
		// NSS is preferred over BC, add it first
		p = null;
		if (checkUse("use.NSS","false")) {
			try {
				p = (new NSSLoader()).load(checkUse("prefer.NSS"));
				try{
				    KeyGenerator kgen = KeyGenerator.getInstance("AES", "SunPKCS11-NSS");
				    kgen.init(256);
				} catch (GeneralSecurityException e) {
				    final String msg = "Error with SunPKCS11-NSS. "
				            + "Unlimited policy file not installed.";
				    Logger.warning(NSSLoader.class, msg, e);
				    System.out.println(msg);
				}
			} catch(Throwable e) {
				// FIXME what about Windows/MacOSX/etc?
				final String msg = "Unable to load SunPKCS11-NSScrypto provider. "
				        + "This is NOT fatal error, Freenet will work, but some performance "
				        + "degradation possible. Consider installing libnss3 package.";
				Logger.warning(NSSLoader.class, msg, e);
			}
		}
		NSS = p;
		p = null;
		if (checkUse("use.BC.I.know.what.I.am.doing")) {
			try {
				p = (new BouncyCastleLoader()).load();
			} catch(Throwable e) {
				final String msg = "SERIOUS PROBLEM: Unable to load or use BouncyCastle provider.";
				System.err.println(msg);
				e.printStackTrace();
				Logger.error(JceLoader.class, msg, e);
			}
		}
		BouncyCastle = p;
		// optional
		if (checkUse("use.SunJCE")) {
		    try{
		        KeyGenerator kgen = KeyGenerator.getInstance("AES", "SunJCE");
		        kgen.init(256);
		    }
		    catch(Throwable e) {
		        Logger.warning(NSSLoader.class, "Error with SunJCE. Unlimited policy file not installed.", e);
		    }
		    SunJCE = Security.getProvider("SunJCE");
		}
		else SunJCE = null;

		SUN = checkUse("use.SUN") ? Security.getProvider("SUN") : null;
	}
	static private class BouncyCastleLoader {
		private BouncyCastleLoader() {}
		private Provider load() throws Throwable {
			Provider p = Security.getProvider("BC");
			if (p == null) {
				try {
					Class<?> c = 
					        Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
					p = (Provider)c.newInstance();
					Security.addProvider(p);
				} catch(Throwable e) {
					throw e;
				}
				Logger.debug(BouncyCastleLoader.class, "Loaded BouncyCastle provider: " + p);
			} else {
				Logger.debug(BouncyCastleLoader.class, "Found BouncyCastle provider: " + p);
			}
			try {
				// We don't want totally unusable provider
				KeyAgreement.getInstance("ECDH", p);
				Signature.getInstance("SHA256withECDSA", p);
			} catch(Throwable e) {
				throw new Error("Cannot use required algorithm from BouncyCaste provider", e);
			}
			return p;
		}
	}
	static private class NSSLoader {
		private NSSLoader() {}
		private Provider load(boolean atfirst) throws Throwable {
			Provider nssProvider = null;
			for(Provider p: java.security.Security.getProviders()) {
				if (p.getName().matches("^SunPKCS11-(?i)NSS.*$")) {
					nssProvider = p;
					break;
				}
			}
			if(nssProvider == null) {
				File nssFile = File.createTempFile("nss",".cfg");
				nssFile.deleteOnExit();
				OutputStream os = null;
				try {
					// More robust than PrintWriter(file), which can hang on out of disk space.
					os = new FileOutputStream(nssFile);
					OutputStreamWriter osw = new OutputStreamWriter(os, "ISO-8859-1");
					BufferedWriter bw = new BufferedWriter(osw);
					bw.write("name=NSScrypto\n");
					bw.write("nssDbMode=noDb\n");
					bw.write("attributes=compatibility\n");
					bw.close();
					os = null;
				} finally {
					Closer.close(os);
				}
				Class<?> c = Class.forName("sun.security.pkcs11.SunPKCS11");
				Constructor<?> constructor = c.getConstructor(String.class);
				nssProvider = (Provider)constructor.newInstance(nssFile.getPath());
				if (atfirst)
					Security.insertProviderAt(nssProvider, 1);
				else
					Security.addProvider(nssProvider);
				Logger.debug(NSSLoader.class, "Loaded NSS provider " + nssProvider);
			} else {
				Logger.debug(NSSLoader.class, "Found NSS provider " + nssProvider);
			}
			return nssProvider;
		}
	}
	static public void main(String[] args) {
		dumpLoaded();
	}
	
	static public void dumpLoaded() {
		System.out.println("BouncyCastle: "+BouncyCastle);
		System.out.println("SunPKCS11-NSS: "+NSS);
		System.out.println("SUN: "+SUN);
		System.out.println("SunJCE: "+SunJCE);
	}
}
