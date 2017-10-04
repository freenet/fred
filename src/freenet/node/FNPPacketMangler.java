/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;

import freenet.crypt.BlockCipher;
import freenet.crypt.ECDH;
import freenet.crypt.ECDHLightContext;
import freenet.crypt.ECDSA;
import freenet.crypt.ECDSA.Curves;
import freenet.crypt.HMAC;
import freenet.crypt.KeyAgreementSchemeContext;
import freenet.crypt.PCFBMode;
import freenet.crypt.SHA256;
import freenet.crypt.UnsupportedCipherException;
import freenet.crypt.Util;
import freenet.crypt.ciphers.Rijndael;
import freenet.io.AddressTracker;
import freenet.io.AddressTracker.Status;
import freenet.io.comm.FreenetInetAddress;
import freenet.io.comm.IncomingPacketFilter.DECODED;
import freenet.io.comm.PacketSocketHandler;
import freenet.io.comm.Peer;
import freenet.io.comm.Peer.LocalAddressException;
import freenet.io.comm.PeerContext;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.io.comm.SocketHandler;
import freenet.node.OpennetManager.ConnectionType;
import freenet.support.ByteArrayWrapper;
import freenet.support.Fields;
import freenet.support.HexUtil;
import freenet.support.LRUMap;
import freenet.support.Logger;
import freenet.support.SerialExecutor;
import freenet.support.SimpleFieldSet;
import freenet.support.TimeUtil;
import freenet.support.io.FileUtil;
import freenet.support.io.InetAddressComparator;
import freenet.support.io.NativeThread;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * @author amphibian
 *
 * Handles connection setup and more complex packet decoding (cases where we don't immediately know
 * which peer sent the packet). Connection setup uses JFKi, but with an outer obfuscation layer
 * keyed on the "identity" of both the peer and this node.
 * 
 * @see freenet.io.comm.IncomingPacketFilter
 * @see NewPacketFormat
 */
public class FNPPacketMangler implements OutgoingPacketMangler {
    static { Logger.registerClass(FNPPacketMangler.class); }
	private static volatile boolean logMINOR;
	private static volatile boolean logDEBUG;

	private final Node node;
	private final NodeCrypto crypto;
	private final PacketSocketHandler sock;
	/**
	 * Objects cached during JFK message exchange: JFK(3,4) with authenticator as key
	 * The messages are cached in hashmaps because the message retrieval from the cache
	 * can be performed in constant time( given the key)
	 */
	private final HashMap<ByteArrayWrapper, byte[]> authenticatorCache;
	/** The following is used in the HMAC calculation of JFK message3 and message4 */
	private static final byte[] JFK_PREFIX_INITIATOR, JFK_PREFIX_RESPONDER;
	static {
		byte[] I,R;
		try {
			I = "I".getBytes("UTF-8");
			R = "R".getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		}

		JFK_PREFIX_INITIATOR = I;
		JFK_PREFIX_RESPONDER = R;
	}

	/* How often shall we generate a new exponential and add it to the FIFO? */
	public final static int DH_GENERATION_INTERVAL = 30000; // 30sec
	/* How big is the FIFO? */
	public final static int DH_CONTEXT_BUFFER_SIZE = 20;
	/*
	* The FIFO itself
	* Get a lock on dhContextFIFO before touching it!
	*/
	private final LinkedList<ECDHLightContext> ecdhContextFIFO = new LinkedList<ECDHLightContext>();
	private ECDHLightContext ecdhContextToBePrunned;
	private static final ECDH.Curves ecdhCurveToUse = ECDH.Curves.P256;
	private long jfkECDHLastGenerationTimestamp = 0;

	private static final int HASH_LENGTH = SHA256.getDigestLength();
	/** The size of the key used to authenticate the hmac */
	private static final int TRANSIENT_KEY_SIZE = HASH_LENGTH;
	/** The key used to authenticate the hmac */
	private final byte[] transientKey = new byte[TRANSIENT_KEY_SIZE];
	public static final long TRANSIENT_KEY_REKEYING_MIN_INTERVAL = MINUTES.toMillis(30);
	/** The rekeying interval for the session key (keytrackers) */
	public static final long SESSION_KEY_REKEYING_INTERVAL = MINUTES.toMillis(60);
	/** The max amount of time we will accept to use the current tracker when it should have been replaced */
	public static final long MAX_SESSION_KEY_REKEYING_DELAY = MINUTES.toMillis(5);
	/** The amount of data sent before we ask for a rekey */
	public static final int AMOUNT_OF_BYTES_ALLOWED_BEFORE_WE_REKEY = 1024 * 1024 * 1024;
	/** The Runnable in charge of rekeying on a regular basis */
	private final Runnable transientKeyRekeyer = new Runnable() {
		@Override
		public void run() {
			maybeResetTransientKey();
		}
	};

        private long lastConnectivityStatusUpdate;
        private Status lastConnectivityStatus;


	public FNPPacketMangler(Node node, NodeCrypto crypt, PacketSocketHandler sock) {
		this.node = node;
		this.crypto = crypt;
		this.sock = sock;
		authenticatorCache = new HashMap<ByteArrayWrapper, byte[]>();
	}

	/**
	 * Start up the FNPPacketMangler. By the time this is called, all objects will have been constructed,
	 * but not all will have been started yet.
	 */
	public void start() {
		// Run it directly so that the transient key is set.
		maybeResetTransientKey();
		// Fill the DH FIFO on-thread
		for(int i=0;i<DH_CONTEXT_BUFFER_SIZE;i++) {
			_fillJFKECDHFIFO();
		}
		this.authHandlingThread.start(node.executor, "FNP incoming auth packet handler thread");
	}

	/**
	 * Decrypt and authenticate packet.
	 * Then feed it to USM.checkFilters.
	 * Packets generated should have a PeerNode on them.
	 * Note that the buffer can be modified by this method.
	 */
	public DECODED process(byte[] buf, int offset, int length, Peer peer, PeerNode opn) {

		if(opn != null && opn.getOutgoingMangler() != this) {
			Logger.error(this, "Apparently contacted by "+opn+") on "+this, new Exception("error"));
			opn = null;
		}
		boolean wantAnonAuth = crypto.wantAnonAuth();

		if(opn != null) {
			if(logMINOR) Logger.minor(this, "Trying exact match");
			if(length > Node.SYMMETRIC_KEY_LENGTH /* iv */ + HASH_LENGTH + 2 && !node.isStopping()) {
				// Might be an auth packet
				if(tryProcessAuth(buf, offset, length, opn, peer, false)) {
					return DECODED.DECODED;
				}
				// Might be a reply to us sending an anon auth packet.
				// I.e. we are not the seednode, they are.
				if(tryProcessAuthAnonReply(buf, offset, length, opn, peer)) {
					return DECODED.DECODED;
				}
			}
		}
		PeerNode[] peers = crypto.getPeerNodes();
		if(node.isStopping()) return DECODED.SHUTTING_DOWN;
		// Disconnected node connecting on a new IP address?
		if(length > Node.SYMMETRIC_KEY_LENGTH /* iv */ + HASH_LENGTH + 2) {
			for(PeerNode pn: peers) {
				if(pn == opn) continue;
				if(logDEBUG)
					Logger.debug(this, "Trying auth with "+pn);
				if(tryProcessAuth(buf, offset, length, pn, peer,false)) {
					return DECODED.DECODED;
				}
				if(pn.handshakeUnknownInitiator()) {
					// Might be a reply to us sending an anon auth packet.
					// I.e. we are not the seednode, they are.
					if(tryProcessAuthAnonReply(buf, offset, length, pn, peer)) {
						return DECODED.DECODED;
					}
				}
			}
		}
		
		boolean wantAnonAuthChangeIP = wantAnonAuth && crypto.wantAnonAuthChangeIP();
		
		if(wantAnonAuth && wantAnonAuthChangeIP) {
			if(checkAnonAuthChangeIP(opn, buf, offset, length, peer)) return DECODED.DECODED;
		}

		boolean didntTryOldOpennetPeers;
		OpennetManager opennet = node.getOpennet();
		if(opennet != null) {
			// Try old opennet connections.
			if(opennet.wantPeer(null, false, true, true, ConnectionType.RECONNECT)) {
				// We want a peer.
				// Try old connections.
				for(PeerNode oldPeer: opennet.getOldPeers()) {
					if(tryProcessAuth(buf, offset, length, oldPeer, peer, true)) return DECODED.DECODED;
				}
				didntTryOldOpennetPeers = false;
			} else
				didntTryOldOpennetPeers = true;
		} else
			didntTryOldOpennetPeers = false;
		if(wantAnonAuth) {
			if(tryProcessAuthAnon(buf, offset, length, peer))
				return DECODED.DECODED;
		}
		
		if(wantAnonAuth && !wantAnonAuthChangeIP) {
			if(checkAnonAuthChangeIP(opn, buf, offset, length, peer)) {
				// This can happen when a node is upgraded from a SeedClientPeerNode to an OpennetPeerNode.
				//Logger.error(this, "Last resort match anon-auth against all anon setup peernodes succeeded - this should not happen! (It can happen if they change address)");
				return DECODED.DECODED;
			}
		}

                // Don't log too much if we are a seednode
                if(logMINOR && crypto.isOpennet && wantAnonAuth) {
                	if(!didntTryOldOpennetPeers)
                		Logger.minor(this,"Unmatchable packet from "+peer);
                } else
                    Logger.normal(this,"Unmatchable packet from "+peer);
                
                if(!didntTryOldOpennetPeers)
                	return DECODED.NOT_DECODED;
                else
                	return DECODED.DIDNT_WANT_OPENNET;
	}
	
	private boolean checkAnonAuthChangeIP(PeerNode opn, byte[] buf, int offset, int length, Peer peer) {
		PeerNode[] anonPeers = crypto.getAnonSetupPeerNodes();
		if(length > Node.SYMMETRIC_KEY_LENGTH /* iv */ + HASH_LENGTH + 3) {
			for(PeerNode pn: anonPeers) {
				if(pn == opn) continue;
				if(tryProcessAuthAnonReply(buf, offset, length, pn, peer)) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Is this a negotiation packet? If so, process it.
	 * @param buf The buffer to read bytes from
	 * @param offset The offset at which to start reading
	 * @param length The number of bytes to read
	 * @param pn The PeerNode we think is responsible
	 * @param peer The Peer to send a reply to
	 * @return True if we handled a negotiation packet, false otherwise.
	 */
	private boolean tryProcessAuth(byte[] buf, int offset, int length, PeerNode pn, Peer peer, boolean oldOpennetPeer) {
		BlockCipher authKey = pn.incomingSetupCipher;
		if(logDEBUG) Logger.debug(this, "Decrypt key: "+HexUtil.bytesToHex(pn.incomingSetupKey)+" for "+peer+" : "+pn+" in tryProcessAuth");
		// Does the packet match IV E( H(data) data ) ?
		int ivLength = PCFBMode.lengthIV(authKey);
		int digestLength = HASH_LENGTH;
		if(length < digestLength + ivLength + 4) {
			if(logMINOR) {
				if(buf.length < length) {
					if(logDEBUG) Logger.debug(this, "The packet is smaller than the decrypted size: it's probably the wrong tracker ("+buf.length+'<'+length+')');
				} else {
					Logger.minor(this, "Too short: "+length+" should be at least "+(digestLength + ivLength + 4));
				}
			}
			return false;
		}
		// IV at the beginning
		PCFBMode pcfb = PCFBMode.create(authKey, buf, offset);
		// Then the hash, then the data
		// => Data starts at ivLength + digestLength
		// Decrypt the hash
		byte[] hash = Arrays.copyOfRange(buf, offset+ivLength, offset+ivLength+digestLength);
		pcfb.blockDecipher(hash, 0, hash.length);

		int dataStart = ivLength + digestLength + offset+2;

		int byte1 = ((pcfb.decipher(buf[dataStart-2])) & 0xff);
		int byte2 = ((pcfb.decipher(buf[dataStart-1])) & 0xff);
		int dataLength = (byte1 << 8) + byte2;
		if(logDEBUG) Logger.debug(this, "Data length: "+dataLength+" (1 = "+byte1+" 2 = "+byte2+ ')');
		if(dataLength > length - (ivLength+hash.length+2)) {
			if(logDEBUG) Logger.debug(this, "Invalid data length "+dataLength+" ("+(length - (ivLength+hash.length+2))+") in tryProcessAuth");
			return false;
		}
		// Decrypt the data
		byte[] payload = Arrays.copyOfRange(buf, dataStart, dataStart+dataLength);
		pcfb.blockDecipher(payload, 0, payload.length);

		byte[] realHash = SHA256.digest(payload);

		if(MessageDigest.isEqual(realHash, hash)) {
			// Got one
			processDecryptedAuth(payload, pn, peer, oldOpennetPeer);
			pn.reportIncomingBytes(length);
			return true;
		} else {
			if(logDEBUG) Logger.debug(this, "Incorrect hash in tryProcessAuth for "+peer+" (length="+dataLength+"): \nreal hash="+HexUtil.bytesToHex(realHash)+"\n bad hash="+HexUtil.bytesToHex(hash));
			return false;
		}
	}

	/**
	 * Might be an anonymous-initiator negotiation packet (i.e.
	 * we are the responder).
	 * Anonymous initiator is used for seednode connections,
	 * and will in future be used for other things for example
	 * one-side-only invites, password based invites etc.
	 * @param buf The buffer to read bytes from
	 * @param offset The offset at which to start reading
	 * @param length The number of bytes to read
	 * @param peer The Peer to send a reply to
	 * @return True if we handled a negotiation packet, false otherwise.
	 */
	private boolean tryProcessAuthAnon(byte[] buf, int offset, int length, Peer peer) {
		BlockCipher authKey = crypto.getAnonSetupCipher();
		// Does the packet match IV E( H(data) data ) ?
		int ivLength = PCFBMode.lengthIV(authKey);
		int digestLength = HASH_LENGTH;
		if(length < digestLength + ivLength + 5) {
			if(logMINOR) Logger.minor(this, "Too short: "+length+" should be at least "+(digestLength + ivLength + 5));
			return false;
		}
		// IV at the beginning
		PCFBMode pcfb = PCFBMode.create(authKey, buf, offset);
		// Then the hash, then the data
		// => Data starts at ivLength + digestLength
		// Decrypt the hash
		byte[] hash = Arrays.copyOfRange(buf, offset+ivLength, offset+ivLength+digestLength);
		pcfb.blockDecipher(hash, 0, hash.length);

		int dataStart = ivLength + digestLength + offset+2;

		int byte1 = ((pcfb.decipher(buf[dataStart-2])) & 0xff);
		int byte2 = ((pcfb.decipher(buf[dataStart-1])) & 0xff);
		int dataLength = (byte1 << 8) + byte2;
		if(logMINOR) Logger.minor(this, "Data length: "+dataLength+" (1 = "+byte1+" 2 = "+byte2+ ')');
		if(dataLength > length - (ivLength+hash.length+2)) {
			if(logMINOR) Logger.minor(this, "Invalid data length "+dataLength+" ("+(length - (ivLength+hash.length+2))+") in tryProcessAuthAnon");
			return false;
		}
		// Decrypt the data
		byte[] payload = Arrays.copyOfRange(buf, dataStart, dataStart+dataLength);
		pcfb.blockDecipher(payload, 0, payload.length);

		byte[] realHash = SHA256.digest(payload);

		if(MessageDigest.isEqual(realHash, hash)) {
			// Got one
			processDecryptedAuthAnon(payload, peer);
			return true;
		} else {
			if(logMINOR) Logger.minor(this, "Incorrect hash in tryProcessAuthAnon for "+peer+" (length="+dataLength+"): \nreal hash="+HexUtil.bytesToHex(realHash)+"\n bad hash="+HexUtil.bytesToHex(hash));
			return false;
		}
	}

	/**
	 * Might be a reply to an anonymous-initiator negotiation
	 * packet (i.e. we are the initiator).
	 * Anonymous initiator is used for seednode connections,
	 * and will in future be used for other things for example
	 * one-side-only invites, password based invites etc.
	 * @param buf The buffer to read bytes from
	 * @param offset The offset at which to start reading
	 * @param length The number of bytes to read
	 * @param pn The PeerNode we think is responsible
	 * @param peer The Peer to send a reply to
	 * @return True if we handled a negotiation packet, false otherwise.
	 */
	private boolean tryProcessAuthAnonReply(byte[] buf, int offset, int length, PeerNode pn, Peer peer) {
		BlockCipher authKey = pn.anonymousInitiatorSetupCipher;
		// Does the packet match IV E( H(data) data ) ?
		int ivLength = PCFBMode.lengthIV(authKey);
		int digestLength = HASH_LENGTH;
		if(length < digestLength + ivLength + 5) {
			if(logDEBUG) Logger.debug(this, "Too short: "+length+" should be at least "+(digestLength + ivLength + 5));
			return false;
		}
		// IV at the beginning
		PCFBMode pcfb = PCFBMode.create(authKey, buf, offset);
		// Then the hash, then the data
		// => Data starts at ivLength + digestLength
		// Decrypt the hash
		byte[] hash = Arrays.copyOfRange(buf, offset+ivLength, offset+ivLength+digestLength);
		pcfb.blockDecipher(hash, 0, hash.length);

		int dataStart = ivLength + digestLength + offset+2;

		int byte1 = ((pcfb.decipher(buf[dataStart-2])) & 0xff);
		int byte2 = ((pcfb.decipher(buf[dataStart-1])) & 0xff);
		int dataLength = (byte1 << 8) + byte2;
		if(logDEBUG) Logger.minor(this, "Data length: "+dataLength+" (1 = "+byte1+" 2 = "+byte2+ ')');
		if(dataLength > length - (ivLength+hash.length+2)) {
			if(logDEBUG) Logger.debug(this, "Invalid data length "+dataLength+" ("+(length - (ivLength+hash.length+2))+") in tryProcessAuth");
			return false;
		}
		// Decrypt the data
		byte[] payload = Arrays.copyOfRange(buf, dataStart, dataStart+dataLength);
		pcfb.blockDecipher(payload, 0, payload.length);

		byte[] realHash = SHA256.digest(payload);

		if(MessageDigest.isEqual(realHash, hash)) {
			// Got one
			processDecryptedAuthAnonReply(payload, peer, pn);
			return true;
		} else {
			if(logDEBUG) Logger.debug(this, "Incorrect hash in tryProcessAuth for "+peer+" (length="+dataLength+"): \nreal hash="+HexUtil.bytesToHex(realHash)+"\n bad hash="+HexUtil.bytesToHex(hash));
			return false;
		}
	}

	// Anonymous-initiator setup types
	/** Connect to a node hoping it will act as a seednode for us */
	static final byte SETUP_OPENNET_SEEDNODE = 1;

	/**
	 * Process an anonymous-initiator connection setup packet. For a normal setup
	 * (@see processDecryptedAuth()), we know the node that is trying to contact us.
	 * But in this case, we don't know the node yet, and we are doing a
	 * special-purpose connection setup. At the moment the only type supported is
	 * for a new node connecting to a seednode in order to announce. In future,
	 * nodes may support other anonymous-initiator connection types such as when a
	 * node (which is certain of its connectivity) issues one-time invites which
	 * allow a new node to connect to it.
	 * @param payload The decrypted payload of the packet.
	 * @param replyTo The address the packet came in from.
	 */
	private void processDecryptedAuthAnon(final byte[] payload, final Peer replyTo) {
		if(logMINOR) Logger.minor(this, "Processing decrypted auth packet from "+replyTo+" length "+payload.length);

		/** Protocol version. Should be 1. */
		final int version = payload[0];
		/** Negotiation type. Common to anonymous-initiator auth and normal setup.
		 *   2 = JFK.
		 *   3 = JFK, reuse PacketTracker
		 * Other types might indicate other DH variants, or even non-DH-based
		 * algorithms such as password based key setup. */
		final int negType = payload[1];
		/** Packet phase. */
		final int packetType = payload[2];
		/** Setup type. This is specific to anonymous-initiator setup, and specifies the
		 * purpose of the connection. At the moment it is SETUP_OPENNET_SEEDNODE to indicate
		 * we are connecting to a seednode (which doesn't know us). Invites might require
		 * a different setupType. */
		final int setupType = payload[3];

		if(logMINOR) Logger.minor(this, "Received anonymous auth packet (phase="+packetType+", v="+version+", nt="+negType+", setup type="+setupType+") from "+replyTo+"");

		if(version != 1) {
			Logger.error(this, "Decrypted auth packet but invalid version: "+version);
			return;
		}
		if(!(negType == 10)) {
			if(negType > 10)
				Logger.error(this, "Unknown neg type: "+negType);
			else
				Logger.warning(this, "Received a setup packet with unsupported obsolete neg type: "+negType);
			return;
		}

		// Known setup types
		if(setupType != SETUP_OPENNET_SEEDNODE) {
			Logger.error(this, "Unknown setup type "+negType);
			return;
		}

		// We are the RESPONDER.
		// Therefore, we can only get packets of phase 1 and 3 here.

		if(packetType == 0 || packetType == 2) {
			this.authHandlingThread.execute(new Runnable() {

				@Override
				public void run() {
					if(packetType == 0) {
						// Phase 1
						processJFKMessage1(payload,4,null,replyTo, true, setupType, negType);
					} else if(packetType == 2) {
						// Phase 3
						processJFKMessage3(payload, 4, null, replyTo, false, true, setupType, negType);
					}
				}
				
			});
		} else {
			Logger.error(this, "Invalid phase "+packetType+" for anonymous-initiator (we are the responder) from "+replyTo);
		}
		
	}

	private void processDecryptedAuthAnonReply(final byte[] payload, final Peer replyTo, final PeerNode pn) {
		if(logMINOR) Logger.minor(this, "Processing decrypted auth packet from "+replyTo+" for "+pn+" length "+payload.length);

		/** Protocol version. Should be 1. */
		final int version = payload[0];
		/** Negotiation type.
		 *   2 = JFK.
		 *   3 = JFK, reuse PacketTracker
		 * Other types might indicate other DH variants, or even non-DH-based
		 * algorithms such as password based key setup. */
		final int negType = payload[1];
		/** Packet phase. */
		final int packetType = payload[2];
		/** Setup type. See above. */
		final int setupType = payload[3];

		if(logMINOR) Logger.minor(this, "Received anonymous auth packet (phase="+packetType+", v="+version+", nt="+negType+", setup type="+setupType+") from "+replyTo+"");

		if(version != 1) {
			Logger.error(this, "Decrypted auth packet but invalid version: "+version);
			return;
		}
		if(!(negType == 10)) {
			if(negType > 10)
				Logger.error(this, "Unknown neg type: "+negType);
			else
				Logger.warning(this, "Received a setup packet with unsupported obsolete neg type: "+negType);
			return;
		}

		// Known setup types
		if(setupType != SETUP_OPENNET_SEEDNODE) {
			Logger.error(this, "Unknown setup type "+negType);
			return;
		}

		// We are the INITIATOR.
		// Therefore, we can only get packets of phase 2 and 4 here.

		if(packetType == 1 || packetType == 3) {
			authHandlingThread.execute(new Runnable() {
				
				@Override
				public void run() {
					if(packetType == 1) {
						// Phase 2
						processJFKMessage2(payload, 4, pn, replyTo, true, setupType, negType);
					} else if(packetType == 3) {
						// Phase 4
						processJFKMessage4(payload, 4, pn, replyTo, false, negType);
					}
				}
				
			});
		} else {
			Logger.error(this, "Invalid phase "+packetType+" for anonymous-initiator (we are the initiator) from "+replyTo);
		}
		
	}
	
	private final SerialExecutor authHandlingThread = new SerialExecutor(NativeThread.HIGH_PRIORITY, 1000);

	/**
	 * Process a decrypted, authenticated auth packet.
	 * @param payload The packet payload, after it has been decrypted.
	 */
	private void processDecryptedAuth(final byte[] payload, final PeerNode pn, final Peer replyTo, final boolean oldOpennetPeer) {
		if(logMINOR) Logger.minor(this, "Processing decrypted auth packet from "+replyTo+" for "+pn);
		if(pn.isDisabled()) {
			if(logMINOR) Logger.minor(this, "Won't connect to a disabled peer ("+pn+ ')');
			return;  // We don't connect to disabled peers
		}

		final int negType = payload[1];
		final int packetType = payload[2];
		final int version = payload[0];

		if(logMINOR) {
			long now = System.currentTimeMillis();
			long last = pn.lastSentPacketTime();
			String delta = "never";
			if (last>0) {
				delta = TimeUtil.formatTime(now-last, 2, true)+" ago";
			}
			Logger.minor(this, "Received auth packet for "+pn.getPeer()+" (phase="+packetType+", v="+version+", nt="+negType+") (last packet sent "+delta+") from "+replyTo+"");
		}

		/* Format:
		 * 1 byte - version number (1)
		 * 1 byte - negotiation type (0 = simple DH, will not be supported when implement JFKi || 1 = StS)
		 * 1 byte - packet type (0-3)
		 */
		if(version != 1) {
			Logger.error(this, "Decrypted auth packet but invalid version: "+version);
			return;
		}

		if(negType >= 0 && negType < 10) {
			// negType 0 through 5 no longer supported, used old FNP.
			Logger.warning(this, "Old neg type "+negType+" not supported");
			return;
		} else if (negType == 10) {
			// negType == 10 => Changes the method of ack encoding (from single-ack to cummulative range acks)
		    // negType == 9 => Lots of changes:
		    //      Security fixes:
		    //      - send Ni' (a hash of Ni) in JFK1 to prevent a potential CPU DoS		    
		    //      Improvements:
		    //      - use ECDSA with P256 instead of DSA2048
		    //      - use a 128bit nonce instead of a 64bit one
		    //      - use the hash of the pubkey as an identity instead of just random (forgeable) data
		    // negType == 8 => use ECDH with P256 instead of DH1024
			// negType == 7 => same as 6, but determine the initial sequence number by hashing the identity
			// instead of negotiating it
			/*
			 * We implement Just Fast Keying key management protocol with active identity protection
			 * for the initiator and no identity protection for the responder
			 * M1:
			 * This is a straightforward DiffieHellman exponential.
			 * The Initiator Nonce serves two purposes;it allows the initiator to use the same
			 * exponentials during different sessions while ensuring that the resulting session
			 * key will be different,can be used to differentiate between parallel sessions
			 * M2:
			 * Responder replies with a signed copy of his own exponential, a random nonce and
			 * an authenticator which provides sufficient defense against forgeries,replays
			 * We slightly deviate JFK here;we do not send any public key information as specified in the JFK docs
			 * M3:
			 * Initiator echoes the data sent by the responder including the authenticator.
			 * This helps the responder verify the authenticity of the returned data.
			 * M4:
			 * Encrypted message of the signature on both nonces, both exponentials using the same keys as in the previous message
			 */
			if(packetType<0 || packetType>3) {
				Logger.error(this,"Unknown PacketType" + packetType + "from" + replyTo + "from" +pn);
				return ;
			} else authHandlingThread.execute(new Runnable() {

				@Override
				public void run() {
					if(packetType==0) {
						/*
						 * Initiator- This is a straightforward DiffieHellman exponential.
						 * The Initiator Nonce serves two purposes;it allows the initiator to use the same
						 * exponentials during different sessions while ensuring that the resulting
						 * session key will be different,can be used to differentiate between
						 * parallel sessions
						 */
						processJFKMessage1(payload,3,pn,replyTo,false,-1,negType);

					} else if(packetType==1) {
						/*
						 * Responder replies with a signed copy of his own exponential, a random
						 * nonce and an authenticator calculated from a transient hash key private
						 * to the responder.
						 */
						processJFKMessage2(payload,3,pn,replyTo,false,-1,negType);
					} else if(packetType==2) {
						/*
						 * Initiator echoes the data sent by the responder.These messages are
						 * cached by the Responder.Receiving a duplicate message simply causes
						 * the responder to Re-transmit the corresponding message4
						 */
						processJFKMessage3(payload, 3, pn, replyTo, oldOpennetPeer, false, -1, negType);
					} else if(packetType==3) {
						/*
						 * Encrypted message of the signature on both nonces, both exponentials
						 * using the same keys as in the previous message.
						 * The signature is non-message recovering
						 */
						processJFKMessage4(payload, 3, pn, replyTo, oldOpennetPeer, negType);
					}
				}
			});
		} else {
			Logger.error(this, "Decrypted auth packet but unknown negotiation type "+negType+" from "+replyTo+" possibly from "+pn);
			return;
		}
	}

	/*
	 * Initiator Method:Message1
	 * Process Message1
	 * Receive the Initiator nonce and DiffieHellman Exponential
	 * @param The packet phase number
	 * @param The peerNode we are talking to. CAN BE NULL if anonymous initiator, since we are the responder.
	 * @param The peer to which we need to send the packet
	 * @param unknownInitiator If true, we (the responder) don't know the
	 * initiator, and should check for fields which would be skipped in a
	 * normal setup where both sides know the other (indicated with * below).
	 * @param setupType The type of unknown-initiator setup.
	 *
	 * format :
	 * Ni'
	 * g^i
	 * *IDr'
	 *
	 * See http://www.wisdom.weizmann.ac.il/~reingold/publications/jfk-tissec.pdf
	 * Just Fast Keying: Key Agreement In A Hostile Internet
	 * Aiello, Bellovin, Blaze, Canetti, Ioannidis, Keromytis, Reingold.
	 * ACM Transactions on Information and System Security, Vol 7 No 2, May 2004, Pages 1-30.
	 *
	 */
	private void processJFKMessage1(byte[] payload,int offset,PeerNode pn,Peer replyTo, boolean unknownInitiator, int setupType, int negType)
	{
		long t1=System.currentTimeMillis();
		int modulusLength = getModulusLength();
		// Pre negtype 9 we were sending Ni as opposed to Ni'
		int nonceSizeHashed = HASH_LENGTH;
		if(logMINOR) Logger.minor(this, "Got a JFK(1) message, processing it - "+pn);
		// FIXME: follow the spec and send IDr' ?
		if(payload.length < nonceSizeHashed + modulusLength + 3 + (unknownInitiator ? NodeCrypto.IDENTITY_LENGTH : 0)) {
			Logger.error(this, "Packet too short from "+pn+": "+payload.length+" after decryption in JFK(1), should be "+(nonceSizeHashed + modulusLength));
			return;
		}
		// get Ni'
		byte[] nonceInitiator = new byte[nonceSizeHashed];
		System.arraycopy(payload, offset, nonceInitiator, 0, nonceSizeHashed);
		offset += nonceSizeHashed;

		// get g^i
		byte[] hisExponential = Arrays.copyOfRange(payload, offset, offset + modulusLength);
		if(unknownInitiator) {
			// Check IDr'
			offset += modulusLength;
			byte[] expectedIdentityHash = Arrays.copyOfRange(payload, offset, offset + NodeCrypto.IDENTITY_LENGTH);
			if(!MessageDigest.isEqual(expectedIdentityHash, crypto.identityHash)) {
				Logger.error(this, "Invalid unknown-initiator JFK(1), IDr' is "+HexUtil.bytesToHex(expectedIdentityHash)+" should be "+HexUtil.bytesToHex(crypto.identityHash));
				return;
			}
		}
		
		if(throttleRekey(pn, replyTo)) return;
		   

		    try {
		    	sendJFKMessage2(nonceInitiator, hisExponential, pn, replyTo, unknownInitiator, setupType, negType);
		    } catch (NoContextsException e) {
		    	handleNoContextsException(NoContextsException.CONTEXT.REPLYING);
		    	return;
		    }

		long t2=System.currentTimeMillis();
		if((t2-t1)>500) {
			Logger.error(this,"Message1 timeout error:Processing packet for "+pn);
		}
	}
	
	private long lastLoggedNoContexts = -1;
	private static long LOG_NO_CONTEXTS_INTERVAL = MINUTES.toMillis(1);

	private void handleNoContextsException(NoContextsException.CONTEXT context) {
		if(node.getUptime() < SECONDS.toMillis(30)) {
			Logger.warning(this, "No contexts available, unable to handle or send packet ("+context+") on "+this);
			return;
		}
		// Log it immediately.
		Logger.warning(this, "No contexts available "+context+" - running out of entropy or severe CPU usage problems?");
		// More loudly periodically.
		long now = System.currentTimeMillis();
		synchronized(this) {
			if(now < lastLoggedNoContexts + LOG_NO_CONTEXTS_INTERVAL)
				return;
			lastLoggedNoContexts = now;
		}
		logLoudErrorNoContexts();
	}

	private void logLoudErrorNoContexts() {
		// If this is happening regularly post-startup then it's unlikely that reading the disk will help.
		// FIXME localise this, give a useralert etc.
		// RNG exhaustion shouldn't happen for Windows users at all, and may not happen on Linux depending on the JVM version, so lets leave it for now.
		System.err.println("FREENET IS HAVING PROBLEMS CONNECTING: Either your CPU is overloaded or it is having trouble reading from the random number generator");
		System.err.println("If the problem is CPU usage, please shut down whatever applications are hogging the CPU.");
		if(FileUtil.detectedOS.isUnix) {
			File f = new File("/dev/hwrng");
			if(f.exists())
				System.err.println("Installing \"rngd\" might help (e.g. apt-get install rng-tools).");
			System.err.println("The best solution is to install a hardware random number generator, or use turbid or similar software to take random data from an unconnected sound card.");
			System.err.println("The quick workaround is to add \"wrapper.java.additional.4=-Djava.security.egd=file:///dev/urandom\" to your wrapper.conf.");
		}
	}

	private final LRUMap<InetAddress, Long> throttleRekeysByIP = LRUMap.createSafeMap(InetAddressComparator.COMPARATOR);

	private static final int REKEY_BY_IP_TABLE_SIZE = 1024;

	private boolean throttleRekey(PeerNode pn, Peer replyTo) {
		if(pn != null) {
			return pn.throttleRekey();
		}
		long now = System.currentTimeMillis();
		InetAddress addr = replyTo.getAddress();
		synchronized(throttleRekeysByIP) {
			Long l = throttleRekeysByIP.get(addr);
			if(l == null || l != null && now > l)
				throttleRekeysByIP.push(addr, now);
			while(throttleRekeysByIP.size() > REKEY_BY_IP_TABLE_SIZE || 
					((!throttleRekeysByIP.isEmpty()) && throttleRekeysByIP.peekValue() < now - PeerNode.THROTTLE_REKEY))
				throttleRekeysByIP.popKey();
			if(l != null && now - l < PeerNode.THROTTLE_REKEY) {
				Logger.error(this, "Two JFK(1)'s initiated by same IP within "+PeerNode.THROTTLE_REKEY+"ms");
				return true;
			}
		}
		return false;
	}

	private static final int MAX_NONCES_PER_PEER = 10;

	/*
	 * format:
	 * Ni',g^i
	 * We send IDr' only if unknownInitiator is set.
	 * @param pn The node to encrypt the message to. Cannot be null, because we are the initiator and we
	 * know the responder in all cases.
	 * @param replyTo The peer to send the actual packet to.
	 */
	private void sendJFKMessage1(PeerNode pn, Peer replyTo, boolean unknownInitiator, int setupType, int negType) throws NoContextsException {
		if(logMINOR) Logger.minor(this, "Sending a JFK(1) message to "+replyTo+" for "+pn.getPeer());
		final long now = System.currentTimeMillis();
		int modulusLength = getModulusLength();
        // Pre negtype 9 we were sending Ni as opposed to Ni'
        int nonceSize = getNonceSize();
		
		KeyAgreementSchemeContext ctx = pn.getKeyAgreementSchemeContext();
            if((ctx == null) || !(ctx instanceof ECDHLightContext) || ((pn.jfkContextLifetime + DH_GENERATION_INTERVAL*DH_CONTEXT_BUFFER_SIZE) < now)) {
                pn.jfkContextLifetime = now;
                pn.setKeyAgreementSchemeContext(ctx = getECDHLightContext());
            }
		
		int offset = 0;
		byte[] nonce = new byte[nonceSize];
		byte[] myExponential = ctx.getPublicKeyNetworkFormat();
		node.random.nextBytes(nonce);

		synchronized (pn.jfkNoncesSent) {
			pn.jfkNoncesSent.add(nonce);
			if(pn.jfkNoncesSent.size() > MAX_NONCES_PER_PEER)
				pn.jfkNoncesSent.removeFirst();
		}

		int nonceSizeHashed = HASH_LENGTH;
		byte[] message1 = new byte[nonceSizeHashed+modulusLength+(unknownInitiator ? NodeCrypto.IDENTITY_LENGTH : 0)];

		System.arraycopy(SHA256.digest(nonce), 0, message1, offset, nonceSizeHashed);
		offset += nonceSizeHashed;
		System.arraycopy(myExponential, 0, message1, offset, modulusLength);

		if(unknownInitiator) {
			offset += modulusLength;
			System.arraycopy(pn.identityHash, 0, message1, offset, pn.identityHash.length);
			sendAnonAuthPacket(1,negType,0,setupType,message1,pn,replyTo,pn.anonymousInitiatorSetupCipher);
		} else {
			sendAuthPacket(1,negType,0,message1,pn,replyTo);
		}
		long t2=System.currentTimeMillis();
		if((t2-now)>500) {
			Logger.error(this,"Message1 timeout error:Sending packet for "+pn.getPeer());
		}
	}

	/*
	 * format:
	 * Ni',Nr,g^r
	 * Signature[g^r,grpInfo(r)]
	 * Hashed JFKAuthenticator : HMAC{Hkr}[g^r, g^i, Nr, Ni', IPi]
	 *
	 * NB: we don't send IDr nor groupinfo as we know them: even if the responder doesn't know the initiator,
	 * the initiator ALWAYS knows the responder.
	 * @param pn The node to encrypt the message for. CAN BE NULL if anonymous-initiator.
	 * @param replyTo The peer to send the packet to.
	 */
	private void sendJFKMessage2(byte[] nonceInitator, byte[] hisExponential, PeerNode pn, Peer replyTo, boolean unknownInitiator, int setupType, int negType) throws NoContextsException {
		if(logMINOR) Logger.minor(this, "Sending a JFK(2) message to "+pn);
		int modulusLength = getModulusLength();
		int nonceSize = getNonceSize();
		// g^r
		// Neg type 8 and later use ECDH for generating the keys.
		KeyAgreementSchemeContext ctx = getECDHLightContext();
		
		// Nr
		byte[] myNonce = new byte[nonceSize];
		node.random.nextBytes(myNonce);
		byte[] myExponential = ctx.getPublicKeyNetworkFormat();
		// Neg type 9 and later use ECDSA signature.
		byte[] sig = ctx.ecdsaSig;
	    if(sig.length != getSignatureLength())
	        throw new IllegalStateException("This shouldn't happen: please report! We are attempting to send "+sig.length+" bytes of signature in JFK2! "+pn.getPeer());
	    byte[] authenticator = HMAC.macWithSHA256(getTransientKey(),assembleJFKAuthenticator(myExponential, hisExponential, myNonce, nonceInitator, replyTo.getAddress().getAddress()));
		if(logDEBUG) Logger.debug(this, "We are using the following HMAC : " + HexUtil.bytesToHex(authenticator));
        if(logDEBUG) Logger.debug(this, "We have Ni' : " + HexUtil.bytesToHex(nonceInitator));
		byte[] message2 = new byte[nonceInitator.length + nonceSize+modulusLength+
		                           sig.length+
		                           HASH_LENGTH];

		int offset = 0;
		System.arraycopy(nonceInitator, 0, message2, offset, nonceInitator.length);
		offset += nonceInitator.length;
		System.arraycopy(myNonce, 0, message2, offset, myNonce.length);
		offset += myNonce.length;
		System.arraycopy(myExponential, 0, message2, offset, modulusLength);
		offset += modulusLength;

	    System.arraycopy(sig, 0, message2, offset, sig.length);
	    offset += sig.length;
		
		System.arraycopy(authenticator, 0, message2, offset, HASH_LENGTH);

		if(unknownInitiator) {
			sendAnonAuthPacket(1,negType,1,setupType,message2,pn,replyTo,crypto.anonSetupCipher);
		} else {
			sendAuthPacket(1,negType,1,message2,pn,replyTo);
		}
	}

	/*
	 * Assemble what will be the jfk-Authenticator :
	 * computed over the Responder exponentials and the Nonces and
	 * used by the responder to verify that the round-trip has been done
	 *
	 */
	private byte[] assembleJFKAuthenticator(byte[] gR, byte[] gI, byte[] nR, byte[] nI, byte[] address) {
		byte[] authData=new byte[gR.length + gI.length + nR.length + nI.length + address.length];
		int offset = 0;

		System.arraycopy(gR, 0, authData, offset ,gR.length);
		offset += gR.length;
		System.arraycopy(gI, 0, authData, offset, gI.length);
		offset += gI.length;
		System.arraycopy(nR, 0,authData, offset, nR.length);
		offset += nR.length;
		System.arraycopy(nI, 0,authData, offset, nI.length);
		offset += nI.length;
		System.arraycopy(address, 0, authData, offset, address.length);

		return authData;
	}

	/*
	 * Initiator Method:Message2
	 * @see{sendJFKMessage2} for packet format details.
	 * Note that this packet is exactly the same for known initiator as for unknown initiator.
	 *
	 * @param payload The buffer containing the decrypted auth packet.
	 * @param inputOffset The offset in the buffer at which the packet starts.
	 * @param replyTo The peer to which we need to send the packet
	 * @param pn The peerNode we are talking to. Cannot be null as we are the initiator.
	 */
	private void processJFKMessage2(byte[] payload,int inputOffset,PeerNode pn,Peer replyTo, boolean unknownInitiator, int setupType, int negType)
	{
		long t1=System.currentTimeMillis();
		int modulusLength = getModulusLength();
		// Pre negtype 9 we were sending Ni as opposed to Ni'
		int nonceSize = getNonceSize();
		int nonceSizeHashed = HASH_LENGTH;
		
		if(logMINOR) Logger.minor(this, "Got a JFK(2) message, processing it - "+pn.getPeer());
		// FIXME: follow the spec and send IDr' ?
		int expectedLength = nonceSizeHashed + nonceSize + modulusLength + HASH_LENGTH*2;
		if(payload.length < expectedLength + 3) {
			Logger.error(this, "Packet too short from "+pn.getPeer()+": "+payload.length+" after decryption in JFK(2), should be "+(expectedLength + 3));
			return;
		}

		byte[] nonceInitiator = new byte[nonceSizeHashed];
		System.arraycopy(payload, inputOffset, nonceInitiator, 0, nonceSizeHashed);
		inputOffset += nonceSizeHashed;
		byte[] nonceResponder = new byte[nonceSize];
		System.arraycopy(payload, inputOffset, nonceResponder, 0, nonceSize);
		inputOffset += nonceSize;

		byte[] hisExponential = Arrays.copyOfRange(payload, inputOffset, inputOffset+modulusLength);
		inputOffset += modulusLength;

		int sigLength = getSignatureLength();
		byte[] sig = new byte[sigLength];
		System.arraycopy(payload, inputOffset, sig, 0, sigLength);
		inputOffset += sigLength;

		byte[] authenticator = Arrays.copyOfRange(payload, inputOffset, inputOffset + HASH_LENGTH);
		inputOffset += HASH_LENGTH;

		// Check try to find the authenticator in the cache.
		// If authenticator is already present, indicates duplicate/replayed message2
		// Now simply transmit the corresponding message3
		Object message3 = null;
		synchronized (authenticatorCache) {
			message3 = authenticatorCache.get(new ByteArrayWrapper(authenticator));
		}
		if(message3 != null) {
			Logger.normal(this, "We replayed a message from the cache (shouldn't happen often) - "+pn.getPeer());
			sendAuthPacket(1, negType, 3, (byte[]) message3, pn, replyTo);
			return;
		}

		// sanity check
		byte[] myNi = null;
		synchronized (pn.jfkNoncesSent) {
			for(byte[] buf : pn.jfkNoncesSent) {
				if(MessageDigest.isEqual(nonceInitiator, SHA256.digest(buf)))
					myNi = buf;
			}
		}
		// We don't except such a message;
		if(myNi == null) {
			if(shouldLogErrorInHandshake(t1)) {
				Logger.normal(this, "We received an unexpected JFK(2) message from "+pn.getPeer()+" (time since added: "+pn.timeSinceAddedOrRestarted()+" time last receive:"+pn.lastReceivedPacketTime()+')');
			}
			return;
		}

		    // Verify the ECDSA signature ; We are assuming that it's the curve we expect
		    if(!ECDSA.verify(Curves.P256, pn.peerECDSAPubKey, sig, hisExponential)) {
	              if(pn.peerECDSAPubKeyHash == null) {
	            	  // FIXME remove when remove DSA support.
	            	  // Caused by nodes running broken early versions of negType9.
	            	  Logger.error(this, "Peer attempting negType "+negType+" with ECDSA but no ECDSA key known: "+pn.userToString());
	            	  return;
	              }
		    	  Logger.error(this, "The ECDSA signature verification has failed in JFK(2)!! "+pn.getPeer());
	              if(logDEBUG) Logger.debug(this, "Expected signature on "+HexUtil.bytesToHex(hisExponential)+
	            		  " with "+HexUtil.bytesToHex(pn.peerECDSAPubKeyHash)+
	            		  " signature "+HexUtil.bytesToHex(sig));
	              return;
		    }


		// At this point we know it's from the peer, so we can report a packet received.
		pn.receivedPacket(true, false);

		sendJFKMessage3(negType, myNi, nonceResponder, hisExponential, authenticator, pn, replyTo, unknownInitiator, setupType);

		long t2=System.currentTimeMillis();
		if((t2-t1)>500) {
			Logger.error(this,"Message2 timeout error:Processing packet for "+pn.getPeer());
		}
	}

	/*
	 * Initiator Method:Message3
	 * Process Message3
	 * Send the Initiator nonce,Responder nonce and DiffieHellman Exponential of the responder
	 * and initiator in the clear.(unVerifiedData)
	 * Send the authenticator which allows the responder to verify that a roundtrip occured
	 * Compute the signature of the unVerifiedData and encrypt it using a shared key
	 * which is derived from DHExponentials and the nonces; add a HMAC to protect it
	 *
	 * Format:
	 * Ni, Nr, g^i, g^r
	 * Authenticator - HMAC{Hkr}[g^r, g^i, Nr, Ni', IPi]
	 * HMAC{Ka}(cyphertext)
	 * IV + E{KE}[S{i}[Ni',Nr,g^i,g^r,idR, bootID, znoderefI], bootID, znoderefI*]
	 *
	 * * Noderef is sent whether or not unknownInitiator is true, however if it is, it will
	 * be a *full* noderef, otherwise it will exclude the pubkey etc.
	 *
	 * @param payload The buffer containing the decrypted auth packet.
	 * @param replyTo The peer to which we need to send the packet.
	 * @param pn The PeerNode we are talking to. CAN BE NULL in the case of anonymous initiator since we are the
	 * responder.
	 * @return byte Message3
	 */
	private void processJFKMessage3(byte[] payload, int inputOffset, PeerNode pn,Peer replyTo, boolean oldOpennetPeer, boolean unknownInitiator, int setupType, int negType)
	{
		final long t1 = System.currentTimeMillis();
		int modulusLength = getModulusLength();
		int nonceSize = getNonceSize();
		if(logMINOR) Logger.minor(this, "Got a JFK(3) message, processing it - "+pn);

		BlockCipher c = null;
		try { c = new Rijndael(256, 256); } catch (UnsupportedCipherException e) { throw new RuntimeException(e); }

		final int expectedLength =
			nonceSize*2 + // Ni, Nr
			modulusLength*2 + // g^i, g^r
			HASH_LENGTH + // authenticator
			HASH_LENGTH + // HMAC of the cyphertext
			(c.getBlockSize() >> 3) + // IV
			HASH_LENGTH + // it's at least a signature
			8 +	      // a bootid
			8 + // packet tracker ID
			1;	      // znoderefI* is at least 1 byte long

		if(payload.length < expectedLength + 3) {
			Logger.error(this, "Packet too short from "+pn+": "+payload.length+" after decryption in JFK(3), should be "+(expectedLength + 3));
			return;
		}

		// Ni
		byte[] nonceInitiator = new byte[nonceSize];
		System.arraycopy(payload, inputOffset, nonceInitiator, 0, nonceSize);
		inputOffset += nonceSize;
		if(logDEBUG) Logger.debug(this, "We are receiving Ni : " + HexUtil.bytesToHex(nonceInitiator));
		// Before negtype 9 we didn't hash it!
		byte[] nonceInitiatorHashed = SHA256.digest(nonceInitiator);
		    
		// Nr
		byte[] nonceResponder = new byte[nonceSize];
		System.arraycopy(payload, inputOffset, nonceResponder, 0, nonceSize);
		inputOffset += nonceSize;
		// g^i
		byte[] initiatorExponential = Arrays.copyOfRange(payload, inputOffset, inputOffset+modulusLength);
		inputOffset += modulusLength;
		// g^r
		byte[] responderExponential = Arrays.copyOfRange(payload, inputOffset, inputOffset+modulusLength);
		inputOffset += modulusLength;

		byte[] authenticator = Arrays.copyOfRange(payload, inputOffset, inputOffset+HASH_LENGTH);
		inputOffset += HASH_LENGTH;

		// We *WANT* to check the hmac before we do the lookup on the hashmap
		// @see https://bugs.freenetproject.org/view.php?id=1604
		if(!HMAC.verifyWithSHA256(getTransientKey(), assembleJFKAuthenticator(responderExponential, initiatorExponential, nonceResponder, nonceInitiatorHashed, replyTo.getAddress().getAddress()) , authenticator)) {
			if(shouldLogErrorInHandshake(t1)) {
			    if(logDEBUG) Logger.debug(this, "We received the following HMAC : " + HexUtil.bytesToHex(authenticator));
			    if(logDEBUG) Logger.debug(this, "We have Ni' : " + HexUtil.bytesToHex(nonceInitiatorHashed));
				Logger.normal(this, "The HMAC doesn't match; let's discard the packet (either we rekeyed or we are victim of forgery) - JFK3 - "+pn);
			}
			return;
		}
		// Check try to find the authenticator in the cache.
		// If authenticator is already present, indicates duplicate/replayed message3
		// Now simply transmit the corresponding message4
		Object message4 = null;
		synchronized (authenticatorCache) {
			message4 = authenticatorCache.get(new ByteArrayWrapper(authenticator));
		}
		if(message4 != null) {
			Logger.normal(this, "We replayed a message from the cache (shouldn't happen often) - "+pn);
			// We are replaying a JFK(4).
			// Therefore if it is anon-initiator it is encrypted with our setup key.
			if(unknownInitiator) {
				sendAnonAuthPacket(1,negType,3,setupType, (byte[]) message4, null, replyTo, crypto.anonSetupCipher);
			} else {
				sendAuthPacket(1, negType, 3, (byte[]) message4, pn, replyTo);
			}
			return;
		} else {
			if(logDEBUG) Logger.debug(this, "No message4 found for "+HexUtil.bytesToHex(authenticator)+" responderExponential "+Fields.hashCode(responderExponential)+" initiatorExponential "+Fields.hashCode(initiatorExponential)+" nonceResponder "+Fields.hashCode(nonceResponder)+" nonceInitiator "+Fields.hashCode(nonceInitiatorHashed)+" address "+HexUtil.bytesToHex(replyTo.getAddress().getAddress()));
		}

		byte[] hmac = Arrays.copyOfRange(payload, inputOffset, inputOffset+HASH_LENGTH);
		inputOffset += HASH_LENGTH;

		byte[] computedExponential;

            ECPublicKey initiatorKey = ECDH.getPublicKey(initiatorExponential, ecdhCurveToUse);
            ECPublicKey responderKey = ECDH.getPublicKey(responderExponential, ecdhCurveToUse);
            ECDHLightContext ctx = findECDHContextByPubKey(responderKey);
            if (ctx == null) {
                Logger.error(this, "WTF? the HMAC verified but we don't know about that exponential! SHOULDN'T HAPPEN! - JFK3 - "+pn);
                // Possible this is a replay or severely delayed? We don't keep
                // every exponential we ever use.
                return;
            }
            computedExponential = ctx.getHMACKey(initiatorKey);

		if(logDEBUG) Logger.debug(this, "The shared Master secret is : "+HexUtil.bytesToHex(computedExponential) +" for " + pn);
		
		/* 0 is the outgoing key for the initiator, 7 for the responder */
		byte[] outgoingKey = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "7");
		byte[] incommingKey = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "0");
		byte[] Ke = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "1");
		byte[] Ka = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "2");

		byte[] hmacKey = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "3");
		byte[] ivKey = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "4");
		byte[] ivNonce = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "5");

		/* Bytes  1-4:  Initial sequence number for the initiator
		 * Bytes  5-8:  Initial sequence number for the responder
		 * Bytes  9-12: Initial message id for the initiator
		 * Bytes 13-16: Initial message id for the responder
		 * Note that we are the responder */
		byte[] sharedData = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "6");
		Arrays.fill(computedExponential, (byte)0);
		int theirInitialSeqNum = ((sharedData[0] & 0xFF) << 24)
				| ((sharedData[1] & 0xFF) << 16)
				| ((sharedData[2] & 0xFF) << 8)
				| (sharedData[3] & 0xFF);
		int ourInitialSeqNum = ((sharedData[4] & 0xFF) << 24)
				| ((sharedData[5] & 0xFF) << 16)
				| ((sharedData[6] & 0xFF) << 8)
				| (sharedData[7] & 0xFF);
		int theirInitialMsgID, ourInitialMsgID;

			theirInitialMsgID =
				unknownInitiator ? getInitialMessageID(crypto.myIdentity) :
					getInitialMessageID(pn.identity, crypto.myIdentity);
			ourInitialMsgID =
				unknownInitiator ? getInitialMessageID(crypto.myIdentity) :
					getInitialMessageID(crypto.myIdentity, pn.identity);

		if(logMINOR)
			Logger.minor(this, "Their initial message ID: "+theirInitialMsgID+" ours "+ourInitialMsgID);

		c.initialize(Ke);
		int ivLength = PCFBMode.lengthIV(c);
		int decypheredPayloadOffset = 0;
		// We compute the HMAC of ("I"+cyphertext) : the cyphertext includes the IV!
		byte[] decypheredPayload = Arrays.copyOf(JFK_PREFIX_INITIATOR, JFK_PREFIX_INITIATOR.length + payload.length - inputOffset);
		decypheredPayloadOffset += JFK_PREFIX_INITIATOR.length;
		System.arraycopy(payload, inputOffset, decypheredPayload, decypheredPayloadOffset, decypheredPayload.length-decypheredPayloadOffset);
		if(!HMAC.verifyWithSHA256(Ka, decypheredPayload, hmac)) {
			Logger.error(this, "The inner-HMAC doesn't match; let's discard the packet JFK(3) - "+pn);
			return;
		}

		final PCFBMode pk = PCFBMode.create(c, decypheredPayload, decypheredPayloadOffset);
		// Get the IV
		decypheredPayloadOffset += ivLength;
		// Decrypt the payload
		pk.blockDecipher(decypheredPayload, decypheredPayloadOffset, decypheredPayload.length-decypheredPayloadOffset);
		/*
		 * DecipheredData Format:
		 * Signature
		 * Node Data (starting with BootID)
		 */
		int sigLength = getSignatureLength();
		byte[] sig = new byte[sigLength];
		System.arraycopy(decypheredPayload, decypheredPayloadOffset, sig, 0, sigLength);
		decypheredPayloadOffset += sigLength;
		byte[] data = new byte[decypheredPayload.length - decypheredPayloadOffset];
		System.arraycopy(decypheredPayload, decypheredPayloadOffset, data, 0, decypheredPayload.length - decypheredPayloadOffset);
		int ptr = 0;
		long trackerID;
		trackerID = Fields.bytesToLong(data, ptr);
		if(trackerID < 0) trackerID = -1;
		ptr += 8;
		long bootID = Fields.bytesToLong(data, ptr);
		ptr += 8;
		byte[] hisRef = Arrays.copyOfRange(data, ptr, data.length);

		// construct the peernode
		if(unknownInitiator) {
			pn = getPeerNodeFromUnknownInitiator(hisRef, setupType, pn, replyTo);
		}
		if(pn == null) {
			if(unknownInitiator) {
				// Reject
				Logger.normal(this, "Rejecting... unable to construct PeerNode");
			} else {
				Logger.error(this, "PeerNode is null and unknownInitiator is false!");
			}
			return;
		}

		// verify the signature
		byte[] toVerify = assembleDHParams(nonceInitiatorHashed, nonceResponder, initiatorExponential, responderExponential, crypto.getIdentity(), data);
		    if(!ECDSA.verify(Curves.P256, pn.peerECDSAPubKey, sig, toVerify)) {
	              Logger.error(this, "The ECDSA signature verification has failed!! JFK(3) - "+pn.getPeer());
	                return;
		    }


		// At this point we know it's from the peer, so we can report a packet received.
		pn.receivedPacket(true, false);

		BlockCipher outgoingCipher = null;
		BlockCipher incommingCipher = null;
		BlockCipher ivCipher = null;
		try {
			outgoingCipher = new Rijndael(256, 256);
			incommingCipher = new Rijndael(256, 256);
			ivCipher = new Rijndael(256, 256);
		} catch (UnsupportedCipherException e) {
			throw new RuntimeException(e);
		}
		outgoingCipher.initialize(outgoingKey);
		incommingCipher.initialize(incommingKey);
		ivCipher.initialize(ivKey);

		// Promote if necessary
		boolean dontWant = false;
		if(oldOpennetPeer && pn instanceof OpennetPeerNode /* true */) {
			OpennetManager opennet = node.getOpennet();
			OpennetPeerNode opn = (OpennetPeerNode) pn;
			if(opennet == null) {
				Logger.normal(this, "Dumping incoming old-opennet peer as opennet just turned off: "+pn+".");
				return;
			}
			/* When an old-opennet-peer connects, add it at the top of the LRU, so that it isn't
			 * immediately dropped when there is no droppable peer to drop. If it was dropped
			 * from the bottom of the LRU list, we would not have added it to the LRU; so it was
			 * somewhere in the middle. */
			if(!opennet.wantPeer(opn, false, false, true, ConnectionType.RECONNECT)) {
				Logger.normal(this, "No longer want peer "+pn+" - dumping it after connecting");
				dontWant = true;
				opennet.purgeOldOpennetPeer(opn);
			}
			// wantPeer will call node.peers.addPeer(), we don't have to.
		}
		if((!dontWant) && !crypto.allowConnection(pn, replyTo.getFreenetAddress())) {
			if(pn instanceof DarknetPeerNode) {
				Logger.error(this, "Dropping peer "+pn+" because don't want connection due to others on the same IP address!");
				System.out.println("Disconnecting permanently from your friend \""+((DarknetPeerNode)pn).getName()+"\" because other peers are using the same IP address!");
			}
			Logger.normal(this, "Rejecting connection because already have something with the same IP");
			dontWant = true;
		}

		long newTrackerID = pn.completedHandshake(
				bootID, hisRef, 0, hisRef.length, outgoingCipher, outgoingKey, incommingCipher,
				incommingKey, replyTo, true, negType, trackerID, false, false, hmacKey, ivCipher,
				ivNonce, ourInitialSeqNum, theirInitialSeqNum, ourInitialMsgID, theirInitialMsgID);
		
		if(newTrackerID > 0) {

			// Send reply
			sendJFKMessage4(negType, nonceInitiatorHashed, nonceResponder,initiatorExponential, responderExponential,
					c, Ka, authenticator, hisRef, pn, replyTo, unknownInitiator, setupType, newTrackerID, newTrackerID == trackerID);

			if(dontWant) {
				node.peers.disconnectAndRemove(pn, true, true, true); // Let it connect then tell it to remove it.
			} else {
				pn.maybeSendInitialMessages();
			}
		} else {
			Logger.error(this, "Handshake failure! with "+pn.getPeer());
			// Don't send the JFK(4). We have not successfully connected.
		}

		if (logMINOR) Logger.minor(this, "Seed client connected with negtype " + negType);

		final long t2=System.currentTimeMillis();
		if((t2-t1)>500) {
			Logger.error(this,"Message3 Processing packet for "+pn.getPeer()+" took "+TimeUtil.formatTime(t2-t1, 3, true));
		}
	}

	private PeerNode getPeerNodeFromUnknownInitiator(byte[] hisRef, int setupType, PeerNode pn, Peer from) {
		if(setupType == SETUP_OPENNET_SEEDNODE) {
			OpennetManager om = node.getOpennet();
			if(om == null) {
				Logger.error(this, "Opennet disabled, ignoring seednode connect attempt");
				// FIXME Send some sort of explicit rejection message.
				return null;
			}
			SimpleFieldSet ref = OpennetManager.validateNoderef(hisRef, null, true);
			if(ref == null) {
				Logger.error(this, "Invalid noderef");
				// FIXME Send some sort of explicit rejection message.
				return null;
			}
			PeerNode seed;
			try {
				seed = new SeedClientPeerNode(ref, node, crypto);
				// Don't tell tracker yet as we don't have the address yet.
			} catch (FSParseException e) {
				Logger.error(this, "Invalid seed client noderef: "+e+" from "+from, e);
				return null;
			} catch (PeerParseException e) {
				Logger.error(this, "Invalid seed client noderef: "+e+" from "+from, e);
				return null;
			} catch (ReferenceSignatureVerificationException e) {
				Logger.error(this, "Invalid seed client noderef: "+e+" from "+from, e);
				return null;
			} catch (PeerTooOldException e) {
                Logger.error(this, "Invalid seed client noderef: "+e+" from "+from, e);
                return null;
            }
			if(seed.equals(pn)) {
				Logger.normal(this, "Already connected to seednode");
				return pn;
			}
			node.peers.addPeer(seed);
			return seed;
		} else {
			Logger.error(this, "Unknown setup type");
			return null;
		}
	}

	/*
	 * Responder Method:Message4
	 * Process Message4
	 *
	 * Format:
	 * HMAC{Ka}[cyphertext]
	 * IV + E{Ke}[S{R}[Ni', Nr, g^i, g^r, IDi, bootID, znoderefR, znoderefI], bootID, znoderefR]
	 *
	 * @param payload The decrypted auth packet.
	 * @param pn The PeerNode we are talking to. Cannot be null as we are the initiator.
	 * @param replyTo The Peer we are replying to.
	 */
	private boolean processJFKMessage4(byte[] payload, int inputOffset, PeerNode pn, Peer replyTo, boolean oldOpennetPeer, int negType) {
		final long t1 = System.currentTimeMillis();
		int modulusLength = getModulusLength();
		int signLength = getSignatureLength();
		if(logMINOR) Logger.minor(this, "Got a JFK(4) message, processing it - "+pn.getPeer());
		if(pn.jfkMyRef == null) {
			String error = "Got a JFK(4) message but no pn.jfkMyRef for "+pn;
			if(node.getUptime() < SECONDS.toMillis(60)) {
				Logger.minor(this, error);
			} else {
				Logger.error(this, error);
			}
		}
		BlockCipher c = null;
		try { c = new Rijndael(256, 256); } catch (UnsupportedCipherException e) { throw new RuntimeException(e); }

		final int expectedLength =
			HASH_LENGTH + // HMAC of the cyphertext
			(c.getBlockSize() >> 3) + // IV
			signLength + // the signature
			9 + // ID of packet tracker, plus boolean byte
			8+ // bootID
			1; // znoderefR

		if(payload.length - inputOffset < expectedLength + 3) {
			Logger.error(this, "Packet too short from "+pn.getPeer()+": "+payload.length+" after decryption in JFK(4), should be "+(expectedLength + 3));
			return false;
		}
		byte[] jfkBuffer = pn.getJFKBuffer();
		if(jfkBuffer == null) {
			Logger.normal(this, "We have already handled this message... might be a replay or a bug - "+pn);
			return false;
		}

		byte[] hmac = Arrays.copyOfRange(payload, inputOffset, inputOffset+HASH_LENGTH);
		inputOffset += HASH_LENGTH;

		c.initialize(pn.jfkKe);
		int ivLength = PCFBMode.lengthIV(c);
		int decypheredPayloadOffset = 0;
		// We compute the HMAC of ("R"+cyphertext) : the cyphertext includes the IV!
		byte[] decypheredPayload = Arrays.copyOf(JFK_PREFIX_RESPONDER, JFK_PREFIX_RESPONDER.length + payload.length - inputOffset);
		decypheredPayloadOffset += JFK_PREFIX_RESPONDER.length;
		System.arraycopy(payload, inputOffset, decypheredPayload, decypheredPayloadOffset, payload.length-inputOffset);
		if(!HMAC.verifyWithSHA256(pn.jfkKa, decypheredPayload, hmac)) {
			Logger.normal(this, "The digest-HMAC doesn't match; let's discard the packet - "+pn.getPeer());
			return false;
		}

		// Try to find the HMAC in the cache:
		// If it is already present it indicates duplicate/replayed message4 and we can discard
		// If it's not, we can add it with a timestamp
		byte[] message4Timestamp = null;
		synchronized (authenticatorCache) {
			ByteArrayWrapper hmacBAW = new ByteArrayWrapper(hmac);
			message4Timestamp = authenticatorCache.get(hmacBAW);
			if(message4Timestamp == null) { // normal behaviour
				authenticatorCache.put(hmacBAW, Fields.longToBytes(t1));
			}
		}
		if(message4Timestamp != null) {
			Logger.normal(this, "We got a replayed message4 (first handled at "+TimeUtil.formatTime(t1-Fields.bytesToLong(message4Timestamp))+") from - "+pn);
			return true;
		}

		// Get the IV
		final PCFBMode pk = PCFBMode.create(c, decypheredPayload, decypheredPayloadOffset);
		decypheredPayloadOffset += ivLength;
		// Decrypt the payload
		pk.blockDecipher(decypheredPayload, decypheredPayloadOffset, decypheredPayload.length - decypheredPayloadOffset);
		/*
		 * DecipheredData Format:
		 * Signature-r,s
		 * bootID, znoderef
		 */
        byte[] sig = new byte[signLength];
        System.arraycopy(decypheredPayload, decypheredPayloadOffset, sig, 0, signLength);
        decypheredPayloadOffset += signLength;
		byte[] data = new byte[decypheredPayload.length - decypheredPayloadOffset];
		System.arraycopy(decypheredPayload, decypheredPayloadOffset, data, 0, decypheredPayload.length - decypheredPayloadOffset);
		int ptr = 0;
		long trackerID;
		boolean reusedTracker;
		trackerID = Fields.bytesToLong(data, ptr);
		ptr += 8;
		reusedTracker = data[ptr++] != 0;
		long bootID = Fields.bytesToLong(data, ptr);
		ptr += 8;
		byte[] hisRef = Arrays.copyOfRange(data, ptr, data.length);

		// verify the signature
		int dataLen = hisRef.length + 8 + 9;
		int nonceSize = getNonceSize();
		int nonceSizeHashed = HASH_LENGTH;
		byte[] identity = crypto.getIdentity();
		byte[] locallyGeneratedText = new byte[nonceSizeHashed + nonceSize + modulusLength * 2 + identity.length + dataLen + pn.jfkMyRef.length];
		int bufferOffset = nonceSizeHashed + nonceSize + modulusLength*2;
		System.arraycopy(jfkBuffer, 0, locallyGeneratedText, 0, bufferOffset);
		System.arraycopy(identity, 0, locallyGeneratedText, bufferOffset, identity.length);
		bufferOffset += identity.length;
		// bootID
		System.arraycopy(data, 0, locallyGeneratedText, bufferOffset, dataLen);
		bufferOffset += dataLen;
		System.arraycopy(pn.jfkMyRef, 0, locallyGeneratedText, bufferOffset, pn.jfkMyRef.length);
	        if(!ECDSA.verify(Curves.P256, pn.peerECDSAPubKey, sig, locallyGeneratedText)) {
	            Logger.error(this, "The ECDSA signature verification has failed!! JFK(4) - "+pn.getPeer()+" length "+locallyGeneratedText.length+" hisRef "+hisRef.length+" hash "+Fields.hashCode(hisRef)+" myRef "+pn.jfkMyRef.length+" hash "+Fields.hashCode(pn.jfkMyRef)+" boot ID "+bootID);
	            return true;
	        }


		// Received a packet
		pn.receivedPacket(true, false);

		// Promote if necessary
		boolean dontWant = false;
		if(oldOpennetPeer && pn instanceof OpennetPeerNode /* true */) {
		    OpennetPeerNode opn = (OpennetPeerNode) pn;
			OpennetManager opennet = node.getOpennet();
			if(opennet == null) {
				Logger.normal(this, "Dumping incoming old-opennet peer as opennet just turned off: "+pn+".");
				return true;
			}
			/* When an old-opennet-peer connects, add it at the top of the LRU, so that it isn't
			 * immediately dropped when there is no droppable peer to drop. If it was dropped
			 * from the bottom of the LRU list, we would not have added it to the LRU; so it was
			 * somewhere in the middle. */
			if(!opennet.wantPeer(opn, false, false, true, ConnectionType.RECONNECT)) {
				Logger.normal(this, "No longer want peer "+pn+" - dumping it after connecting");
				dontWant = true;
				opennet.purgeOldOpennetPeer(opn);
			}
			// wantPeer will call node.peers.addPeer(), we don't have to.
		}
		if((!dontWant) && !crypto.allowConnection(pn, replyTo.getFreenetAddress())) {
			Logger.normal(this, "Rejecting connection because already have something with the same IP");
			dontWant = true;
		}

		// We change the key
		BlockCipher ivCipher = null;
		BlockCipher outgoingCipher = null;
		BlockCipher incommingCipher = null;
		try {
			ivCipher = new Rijndael(256, 256);
			outgoingCipher = new Rijndael(256, 256);
			incommingCipher = new Rijndael(256, 256);
		} catch (UnsupportedCipherException e) {
			throw new RuntimeException(e);
		}

		outgoingCipher.initialize(pn.outgoingKey);
		incommingCipher.initialize(pn.incommingKey);
		ivCipher.initialize(pn.ivKey);

		long newTrackerID = pn.completedHandshake(
				bootID, hisRef, 0, hisRef.length, outgoingCipher, pn.outgoingKey, incommingCipher,
				pn.incommingKey, replyTo, false, negType, trackerID, true, reusedTracker, pn.hmacKey,
				ivCipher, pn.ivNonce, pn.ourInitialSeqNum, pn.theirInitialSeqNum, pn.ourInitialMsgID,
				pn.theirInitialMsgID);
		if(newTrackerID >= 0) {
			if(dontWant) {
				node.peers.disconnectAndRemove(pn, true, true, true);
			} else {
				pn.maybeSendInitialMessages();
			}
		} else {
			Logger.error(this, "Handshake failed!");
		}

		// cleanup
		// FIXME: maybe we should copy zeros/garbage into it before leaving it to the GC
		pn.setJFKBuffer(null);
		pn.jfkKa = null;
		pn.jfkKe = null;
		pn.outgoingKey = null;
		pn.incommingKey = null;
		pn.hmacKey = null;
		pn.ivKey = null;
		pn.ivNonce = null;
		pn.ourInitialSeqNum = 0;
		pn.theirInitialSeqNum = 0;
		pn.ourInitialMsgID = 0;
		pn.theirInitialMsgID = 0;
		// We want to clear it here so that new handshake requests
		// will be sent with a different DH pair
		pn.setKeyAgreementSchemeContext(null);
		synchronized (pn.jfkNoncesSent) {
			// FIXME TRUE MULTI-HOMING: winner-takes-all, kill all other connection attempts since we can't deal with multiple active connections
			// Also avoids leaking
			pn.jfkNoncesSent.clear();
		}

		final long t2=System.currentTimeMillis();
		if((t2-t1)>500)
			Logger.error(this,"Message4 timeout error:Processing packet from "+pn.getPeer());
		return true;
	}

	/*
	 * Format:
	 * Ni, Nr, g^i, g^r
	 * Authenticator - HMAC{Hkr}[g^r, g^i, Nr, Ni', IPi]
	 * HMAC{Ka}(cyphertext)
	 * IV + E{KE}[S{i}[Ni',Nr,g^i,g^r,idR, bootID, znoderefI], bootID, znoderefI]
	 *
	 * @param pn The PeerNode to encrypt the message for. Cannot be null as we are the initiator.
	 * @param replyTo The Peer to send the packet to.
	 */

	private void sendJFKMessage3(final int negType, byte[] nonceInitiator, byte[] nonceResponder, byte[] hisExponential, byte[] authenticator, final PeerNode pn, final Peer replyTo, final boolean unknownInitiator, final int setupType)
	{
		if(logMINOR) Logger.minor(this, "Sending a JFK(3) message to "+pn.getPeer());
		int modulusLength = getModulusLength();
		int signLength = getSignatureLength();
		int nonceSize = getNonceSize();
        // Pre negtype 9 we were sending Ni as opposed to Ni'
        byte[] nonceInitiatorHashed = SHA256.digest(nonceInitiator);
        
		long t1=System.currentTimeMillis();
		BlockCipher c = null;
		try { c = new Rijndael(256, 256); } catch (UnsupportedCipherException e) { throw new RuntimeException(e); }
		KeyAgreementSchemeContext ctx = pn.getKeyAgreementSchemeContext();
		if(ctx == null) return;
		byte[] ourExponential = ctx.getPublicKeyNetworkFormat();
		pn.jfkMyRef = unknownInitiator ? crypto.myCompressedHeavySetupRef() : crypto.myCompressedSetupRef();
		byte[] data = new byte[8 + 8 + pn.jfkMyRef.length];
		int ptr = 0;
		long trackerID;
		trackerID = pn.getReusableTrackerID();
		System.arraycopy(Fields.longToBytes(trackerID), 0, data, ptr, 8);
		ptr += 8;
		if(logMINOR) Logger.minor(this, "Sending tracker ID "+trackerID+" in JFK(3)");
		System.arraycopy(Fields.longToBytes(pn.getOutgoingBootID()), 0, data, ptr, 8);
		ptr += 8;
		System.arraycopy(pn.jfkMyRef, 0, data, ptr, pn.jfkMyRef.length);
		final byte[] message3 = new byte[nonceSize*2 + // nI, nR
		                           modulusLength*2 + // g^i, g^r
		                           HASH_LENGTH + // authenticator
		                           HASH_LENGTH + // HMAC(cyphertext)
		                           (c.getBlockSize() >> 3) + // IV
		                           signLength + // Signature
		                           data.length]; // The bootid+noderef
		int offset = 0;
		// Ni
		System.arraycopy(nonceInitiator, 0, message3, offset, nonceSize);
		offset += nonceSize;
		if(logDEBUG) Logger.debug(this, "We are sending Ni : " + HexUtil.bytesToHex(nonceInitiator));
		// Nr
		System.arraycopy(nonceResponder, 0, message3, offset, nonceSize);
		offset += nonceSize;
		// g^i
		System.arraycopy(ourExponential, 0,message3, offset, ourExponential.length);
		offset += ourExponential.length;
		// g^r
		System.arraycopy(hisExponential, 0,message3, offset, hisExponential.length);
		offset += hisExponential.length;

		// Authenticator
		System.arraycopy(authenticator, 0, message3, offset, HASH_LENGTH);
		offset += HASH_LENGTH;
		/*
		 * Digital Signature of the message with the private key belonging to the initiator/responder
		 * It is assumed to be non-message recovering
		 */
		// save parameters so that we can verify message4
		byte[] toSign = assembleDHParams(nonceInitiatorHashed, nonceResponder, ourExponential, hisExponential, pn.getPubKeyHash(), data);
		pn.setJFKBuffer(toSign);
		byte[] sig = crypto.ecdsaSign(toSign);

		byte[] computedExponential=((ECDHLightContext)ctx).getHMACKey(ECDH.getPublicKey(hisExponential, ecdhCurveToUse));

		if(logDEBUG) Logger.debug(this, "The shared Master secret is : "+HexUtil.bytesToHex(computedExponential)+ " for " + pn);
		/* 0 is the outgoing key for the initiator, 7 for the responder */
		pn.outgoingKey = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "0");
		pn.incommingKey = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "7");
		pn.jfkKe = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "1");
		pn.jfkKa = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "2");

		pn.hmacKey = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "3");
		pn.ivKey = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "4");
		pn.ivNonce = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "5");

		/* Bytes  1-4:  Initial sequence number for the initiator
		 * Bytes  5-8:  Initial sequence number for the responder
		 * Bytes  9-12: Initial message id for the initiator
		 * Bytes 13-16: Initial message id for the responder
		 * Note that we are the initiator */
		byte[] sharedData = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "6");
	    Arrays.fill(computedExponential, (byte)0);
		pn.ourInitialSeqNum = ((sharedData[0] & 0xFF) << 24)
				| ((sharedData[1] & 0xFF) << 16)
				| ((sharedData[2] & 0xFF) << 8)
				| (sharedData[3] & 0xFF);
		pn.theirInitialSeqNum = ((sharedData[4] & 0xFF) << 24)
				| ((sharedData[5] & 0xFF) << 16)
				| ((sharedData[6] & 0xFF) << 8)
				| (sharedData[7] & 0xFF);

			pn.theirInitialMsgID =
				unknownInitiator ? getInitialMessageID(pn.identity) :
					getInitialMessageID(pn.identity, crypto.myIdentity);
			pn.ourInitialMsgID =
				unknownInitiator ? getInitialMessageID(pn.identity) :
					getInitialMessageID(crypto.myIdentity, pn.identity);

		if(logMINOR)
			Logger.minor(this, "Their initial message ID: "+pn.theirInitialMsgID+" ours "+pn.ourInitialMsgID);


		c.initialize(pn.jfkKe);
		int ivLength = PCFBMode.lengthIV(c);
		byte[] iv = new byte[ivLength];
		node.random.nextBytes(iv);
		PCFBMode pcfb = PCFBMode.create(c, iv);
		int cleartextOffset = 0;
		byte[] cleartext = new byte[JFK_PREFIX_INITIATOR.length + ivLength + sig.length + data.length];
		System.arraycopy(JFK_PREFIX_INITIATOR, 0, cleartext, cleartextOffset, JFK_PREFIX_INITIATOR.length);
		cleartextOffset += JFK_PREFIX_INITIATOR.length;
		System.arraycopy(iv, 0, cleartext, cleartextOffset, ivLength);
		cleartextOffset += ivLength;
		System.arraycopy(sig, 0, cleartext, cleartextOffset, sig.length);
		cleartextOffset += sig.length;
		System.arraycopy(data, 0, cleartext, cleartextOffset, data.length);
		cleartextOffset += data.length;

		int cleartextToEncypherOffset = JFK_PREFIX_INITIATOR.length + ivLength;
		pcfb.blockEncipher(cleartext, cleartextToEncypherOffset, cleartext.length-cleartextToEncypherOffset);

		// We compute the HMAC of (prefix + cyphertext) Includes the IV!
		byte[] hmac = HMAC.macWithSHA256(pn.jfkKa, cleartext);

		// copy stuffs back to the message
		System.arraycopy(hmac, 0, message3, offset, HASH_LENGTH);
		offset += HASH_LENGTH;
		System.arraycopy(iv, 0, message3, offset, ivLength);
		offset += ivLength;
		System.arraycopy(cleartext, cleartextToEncypherOffset, message3, offset, cleartext.length-cleartextToEncypherOffset);

		// cache the message
		synchronized (authenticatorCache) {
			if(!maybeResetTransientKey())
				authenticatorCache.put(new ByteArrayWrapper(authenticator),message3);
		}
		final long timeSent = System.currentTimeMillis();
		if(unknownInitiator) {
			sendAnonAuthPacket(1, negType, 2, setupType, message3, pn, replyTo, pn.anonymousInitiatorSetupCipher);
		} else {
			sendAuthPacket(1, negType, 2, message3, pn, replyTo);
		}

		/* Re-send the packet after 5sec if we don't get any reply */
		node.getTicker().queueTimedJob(new Runnable() {
			@Override
			public void run() {
				if(pn.timeLastConnectionCompleted() < timeSent) {
					if(logMINOR) Logger.minor(this, "Resending JFK(3) to "+pn+" for "+node.getDarknetPortNumber());
					if(unknownInitiator) {
						sendAnonAuthPacket(1, negType, 2, setupType, message3, pn, replyTo, pn.anonymousInitiatorSetupCipher);
					} else {
						sendAuthPacket(1, negType, 2, message3, pn, replyTo);
					}
				}
			}
		}, SECONDS.toMillis(5));
		long t2=System.currentTimeMillis();
		if((t2-t1)>MILLISECONDS.toMillis(500))
			Logger.error(this,"Message3 timeout error:Sending packet for "+pn.getPeer());
	}

	private int getInitialMessageID(byte[] identity) {
		MessageDigest md = SHA256.getMessageDigest();
		md.update(identity);
		// Similar to JFK keygen, should be safe enough.
		try {
			md.update("INITIAL0".getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new Error(e);
		}
		byte[] hashed = md.digest();
		SHA256.returnMessageDigest(md);
		return Fields.bytesToInt(hashed, 0);
	}

	private int getInitialMessageID(byte[] identity, byte[] otherIdentity) {
		MessageDigest md = SHA256.getMessageDigest();
		md.update(identity);
		md.update(otherIdentity);
		// Similar to JFK keygen, should be safe enough.
		try {
			md.update("INITIAL1".getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new Error(e);
		}
		byte[] hashed = md.digest();
		SHA256.returnMessageDigest(md);
		return Fields.bytesToInt(hashed, 0);
	}

	/*
	 * Format:
	 * HMAC{Ka}(cyphertext)
	 * IV, E{Ke}[S{R}[Ni',Nr,g^i,g^r,idI, bootID, znoderefR, znoderefI],bootID,znoderefR]
	 *
	 * @param replyTo The Peer we are replying to.
	 * @param pn The PeerNode to encrypt the auth packet to. Cannot be null, because even in anonymous initiator,
	 * we will have created one before calling this method.
	 */
	private void sendJFKMessage4(int negType, byte[] nonceInitiatorHashed, byte[] nonceResponder, byte[] initiatorExponential, byte[] responderExponential, BlockCipher c, byte[] Ka, byte[] authenticator, byte[] hisRef, PeerNode pn, Peer replyTo, boolean unknownInitiator, int setupType, long newTrackerID, boolean sameAsOldTrackerID)
	{
		if(logMINOR)
			Logger.minor(this, "Sending a JFK(4) message to "+pn.getPeer());
		long t1=System.currentTimeMillis();

		byte[] myRef = crypto.myCompressedSetupRef();
		byte[] data = new byte[9 + 8 + myRef.length + hisRef.length];
		int ptr = 0;
		System.arraycopy(Fields.longToBytes(newTrackerID), 0, data, ptr, 8);
		ptr += 8;
		data[ptr++] = (byte) (sameAsOldTrackerID ? 1 : 0);

		System.arraycopy(Fields.longToBytes(pn.getOutgoingBootID()), 0, data, ptr, 8);
		ptr += 8;
		System.arraycopy(myRef, 0, data, ptr, myRef.length);
		ptr += myRef.length;
		System.arraycopy(hisRef, 0, data, ptr, hisRef.length);

		byte[] params = assembleDHParams(nonceInitiatorHashed, nonceResponder, initiatorExponential, responderExponential, pn.getPubKeyHash(), data);
		if(logMINOR)
			Logger.minor(this, "Message length "+params.length+" myRef: "+myRef.length+" hash "+Fields.hashCode(myRef)+" hisRef: "+hisRef.length+" hash "+Fields.hashCode(hisRef)+" boot ID "+node.bootID);
		byte[] sig = crypto.ecdsaSign(params);

		int ivLength = PCFBMode.lengthIV(c);
		byte[] iv=new byte[ivLength];
		node.random.nextBytes(iv);
		PCFBMode pk=PCFBMode.create(c, iv);
		// Don't include the last bit
		int dataLength = data.length - hisRef.length;
		byte[] cyphertext = new byte[JFK_PREFIX_RESPONDER.length + ivLength + sig.length + dataLength];
		int cleartextOffset = 0;
		System.arraycopy(JFK_PREFIX_RESPONDER, 0, cyphertext, cleartextOffset, JFK_PREFIX_RESPONDER.length);
		cleartextOffset += JFK_PREFIX_RESPONDER.length;
		System.arraycopy(iv, 0, cyphertext, cleartextOffset, ivLength);
		cleartextOffset += ivLength;
		System.arraycopy(sig, 0, cyphertext, cleartextOffset, sig.length);
		cleartextOffset += sig.length;
		System.arraycopy(data, 0, cyphertext, cleartextOffset, dataLength);
		cleartextOffset += dataLength;
		// Now encrypt the cleartext[Signature]
		int cleartextToEncypherOffset = JFK_PREFIX_RESPONDER.length + ivLength;
		pk.blockEncipher(cyphertext, cleartextToEncypherOffset, cyphertext.length - cleartextToEncypherOffset);

		// We compute the HMAC of (prefix + iv + signature)
		byte[] hmac = HMAC.macWithSHA256(Ka, cyphertext);

		// Message4 = hmac + IV + encryptedSignature
		byte[] message4 = new byte[HASH_LENGTH + ivLength + (cyphertext.length - cleartextToEncypherOffset)];
		int offset = 0;
		System.arraycopy(hmac, 0, message4, offset, HASH_LENGTH);
		offset += HASH_LENGTH;
		System.arraycopy(iv, 0, message4, offset, ivLength);
		offset += ivLength;
		System.arraycopy(cyphertext, cleartextToEncypherOffset, message4, offset, cyphertext.length - cleartextToEncypherOffset);

		// cache the message
		synchronized (authenticatorCache) {
			if(!maybeResetTransientKey())
				authenticatorCache.put(new ByteArrayWrapper(authenticator), message4);
			if(logDEBUG) Logger.debug(this, "Storing JFK(4) for "+HexUtil.bytesToHex(authenticator));
		}

		if(unknownInitiator) {
			sendAnonAuthPacket(1, negType, 3, setupType, message4, pn, replyTo, crypto.anonSetupCipher);
		} else {
			sendAuthPacket(1, negType, 3, message4, pn, replyTo);
		}
		long t2=System.currentTimeMillis();
		if((t2-t1)>500)
			Logger.error(this,"Message4 timeout error:Sending packet for "+pn.getPeer());
	}

	/**
	 * Send an auth packet.
	 */
	private void sendAuthPacket(int version, int negType, int phase, byte[] data, PeerNode pn, Peer replyTo) {
		if(pn == null) throw new IllegalArgumentException("pn shouldn't be null here!");
		byte[] output = new byte[data.length+3];
		output[0] = (byte) version;
		output[1] = (byte) negType;
		output[2] = (byte) phase;
		System.arraycopy(data, 0, output, 3, data.length);
		if(logMINOR) {
			long now = System.currentTimeMillis();
			String delta = "never";
			long last = pn.lastSentPacketTime();
			delta = TimeUtil.formatTime(now - last, 2, true) + " ago";
			Logger.minor(this, "Sending auth packet for "+ String.valueOf(pn.getPeer())+" (phase="+phase+", ver="+version+", nt="+negType+") (last packet sent "+delta+") to "+replyTo+" data.length="+data.length+" to "+replyTo);
		}
		sendAuthPacket(output, pn.outgoingSetupCipher, pn, replyTo, false);
	}

	/**
	 * @param version
	 * @param negType
	 * @param phase
	 * @param setupType
	 * @param data
	 * @param pn May be null. If not null, used for details such as anti-firewall hacks.
	 * @param replyTo
	 * @param cipher
	 */
	private void sendAnonAuthPacket(int version, int negType, int phase, int setupType, byte[] data, PeerNode pn, Peer replyTo, BlockCipher cipher) {
		byte[] output = new byte[data.length+4];
		output[0] = (byte) version;
		output[1] = (byte) negType;
		output[2] = (byte) phase;
		output[3] = (byte) setupType;
		System.arraycopy(data, 0, output, 4, data.length);
		if(logMINOR) Logger.minor(this, "Sending anon auth packet (phase="+phase+", ver="+version+", nt="+negType+", setup="+setupType+") data.length="+data.length);
		sendAuthPacket(output, cipher, pn, replyTo, true);
	}

	/**
	 * Send an auth packet (we have constructed the payload, now hash it, pad it, encrypt it).
	 */
	private void sendAuthPacket(byte[] output, BlockCipher cipher, PeerNode pn, Peer replyTo, boolean anonAuth) {
		int length = output.length;
		if(length > sock.getMaxPacketSize()) {
			throw new IllegalStateException("Cannot send auth packet: too long: "+length);
		}
		byte[] iv = new byte[PCFBMode.lengthIV(cipher)];
		node.random.nextBytes(iv);
		byte[] hash = SHA256.digest(output);
		if(logDEBUG) Logger.debug(this, "Data hash: "+HexUtil.bytesToHex(hash));
		int prePaddingLength = iv.length + hash.length + 2 /* length */ + output.length;
		int maxPacketSize = sock.getMaxPacketSize();
		int paddingLength;
		if(prePaddingLength < maxPacketSize) {
			paddingLength = node.fastWeakRandom.nextInt(Math.min(100, maxPacketSize - prePaddingLength));
		} else {
			paddingLength = 0; // Avoid oversize packets if at all possible, the MTU is an estimate and may be wrong, and fragmented packets are often dropped by firewalls.
			// Tell the devs, this shouldn't happen.
			Logger.error(this, "Warning: sending oversize auth packet (anonAuth="+anonAuth+") of "+prePaddingLength+" bytes!");
		}
		if(paddingLength < 0) paddingLength = 0;
		byte[] data = new byte[prePaddingLength + paddingLength];
		PCFBMode pcfb = PCFBMode.create(cipher, iv);
		System.arraycopy(iv, 0, data, 0, iv.length);
		pcfb.blockEncipher(hash, 0, hash.length);
		System.arraycopy(hash, 0, data, iv.length, hash.length);
		if(logMINOR) Logger.minor(this, "Payload length: "+length+" padded length "+data.length);
		data[hash.length+iv.length] = (byte) pcfb.encipher((byte)(length>>8));
		data[hash.length+iv.length+1] = (byte) pcfb.encipher((byte)length);
		pcfb.blockEncipher(output, 0, output.length);
		System.arraycopy(output, 0, data, hash.length+iv.length+2, output.length);

		Util.randomBytes(node.fastWeakRandom, data, hash.length+iv.length+2+output.length, paddingLength);
		try {
			sendPacket(data, replyTo, pn);
			node.nodeStats.reportAuthBytes(data.length + sock.getHeadersLength(replyTo));
		} catch (LocalAddressException e) {
			Logger.warning(this, "Tried to send auth packet to local address: "+replyTo+" for "+pn+" - maybe you should set allowLocalAddresses for this peer??");
		}
	}

	private void sendPacket(byte[] data, Peer replyTo, PeerNode pn) throws LocalAddressException {
		if(pn != null) {
			if(pn.isIgnoreSource()) {
				Peer p = pn.getPeer();
				if(p != null) replyTo = p;
			}
		}
		sock.sendPacket(data, replyTo, pn == null ? crypto.config.alwaysAllowLocalAddresses() : pn.allowLocalAddresses());
		if(pn != null)
			pn.reportOutgoingBytes(data.length);
		if(PeerNode.shouldThrottle(replyTo, node)) {
			node.outputThrottle.forceGrab(data.length);
		}
	}

	/**
	 * Should we log an error for an event that could easily be
	 * caused by a handshake across a restart boundary?
	 */
	private boolean shouldLogErrorInHandshake(long now) {
		if(now - node.startupTime < Node.HANDSHAKE_TIMEOUT*2)
			return false;
		return true;
	}

	/* (non-Javadoc)
	 * @see freenet.node.OutgoingPacketMangler#sendHandshake(freenet.node.PeerNode)
	 */
	@Override
	public void sendHandshake(PeerNode pn, boolean notRegistered) {
		int negType = pn.selectNegType(this);
		if(negType == -1) {
			// Pick a random negType from what I do support
			int[] negTypes = supportedNegTypes();
			negType = negTypes[node.random.nextInt(negTypes.length)];
			Logger.normal(this, "Cannot send handshake to "+pn+" because no common negTypes, choosing random negType of "+negType);
		}
		if(logMINOR) Logger.minor(this, "Possibly sending handshake to "+pn+" negotiation type "+negType);

		Peer peer = pn.getHandshakeIP();
		if(peer == null) {
			pn.couldNotSendHandshake(notRegistered);
			return;
		}
		Peer oldPeer = peer;
		peer = peer.dropHostName();
		if(peer == null) {
			Logger.error(this, "No address for peer "+oldPeer+" so cannot send handshake");
			pn.couldNotSendHandshake(notRegistered);
			return;
		}
		try {
			sendJFKMessage1(pn, peer, pn.handshakeUnknownInitiator(), pn.handshakeSetupType(), negType);
		} catch (NoContextsException e) {
			handleNoContextsException(NoContextsException.CONTEXT.SENDING);
			return;
		}
		if(logMINOR)
			Logger.minor(this, "Sending handshake to "+peer+" for "+pn);
		pn.sentHandshake(notRegistered);
	}

	/* (non-Javadoc)
	 * @see freenet.node.OutgoingPacketMangler#isDisconnected(freenet.io.comm.PeerContext)
	 */
	@Override
	public boolean isDisconnected(PeerContext context) {
		if(context == null) return false;
		return !context.isConnected();
	}

	@Override
	public int[] supportedNegTypes() {
		return new int[] { 10 };
	}

	@Override
	public SocketHandler getSocketHandler() {
		return sock;
	}

	@Override
	public Peer[] getPrimaryIPAddress() {
		return crypto.detector.getPrimaryPeers();
	}

	@Override
	public byte[] getCompressedNoderef() {
		return crypto.myCompressedFullRef();
	}

	@Override
	public boolean alwaysAllowLocalAddresses() {
		return crypto.config.alwaysAllowLocalAddresses();
	}


	private ECDHLightContext _genECDHLightContext() {
        final ECDHLightContext ctx = new ECDHLightContext(ecdhCurveToUse);
        ctx.setECDSASignature(crypto.ecdsaSign(ctx.getPublicKeyNetworkFormat()));
        if(logDEBUG) Logger.debug(this, "ECDSA Signature: "+HexUtil.bytesToHex(ctx.ecdsaSig)+" for "+HexUtil.bytesToHex(ctx.getPublicKeyNetworkFormat()));
        return ctx;
    }

    private void _fillJFKECDHFIFOOffThread() {
        // do it off-thread
        node.executor.execute(new PrioRunnable() {
            @Override
            public void run() {
                _fillJFKECDHFIFO();
            }
            @Override
            public int getPriority() {
                return NativeThread.MIN_PRIORITY;
            }
        }, "ECDH exponential signing");
    }
    
	private void _fillJFKECDHFIFO() {
        synchronized (ecdhContextFIFO) {
            int size = ecdhContextFIFO.size();
            if((size > 0) && (size + 1 > DH_CONTEXT_BUFFER_SIZE)) {
                ECDHLightContext result = null;
                long oldestSeen = Long.MAX_VALUE;

                for (ECDHLightContext tmp: ecdhContextFIFO) {
                    if(tmp.lifetime < oldestSeen) {
                        oldestSeen = tmp.lifetime;
                        result = tmp;
                    }
                }
                ecdhContextFIFO.remove(ecdhContextToBePrunned = result);
            }

            ecdhContextFIFO.addLast(_genECDHLightContext());
        }
    }
	
    /**
     * Change the ECDH key on a regular basis but at most once every 30sec
     *
     * @return {@link ECDHLightContext}
     * @throws NoContextsException 
     */
    private ECDHLightContext getECDHLightContext() throws NoContextsException {
        final long now = System.currentTimeMillis();
        ECDHLightContext result = null;

        synchronized (ecdhContextFIFO) {
            result = ecdhContextFIFO.pollFirst();
            
            // Shall we replace one element of the queue ?
            if((jfkECDHLastGenerationTimestamp + DH_GENERATION_INTERVAL) < now) {
                jfkECDHLastGenerationTimestamp = now;
                _fillJFKECDHFIFOOffThread();
            }
            
            // Don't generate on-thread as it might block.
            if(result == null)
                throw new NoContextsException();

            ecdhContextFIFO.addLast(result);
        }

        if(logMINOR) Logger.minor(this, "getECDHLightContext() is serving "+result.hashCode());
        return result;
    }
    
    @SuppressWarnings("serial")
	private static class NoContextsException extends Exception {
    	
    	private enum CONTEXT {
    		SENDING,
    		REPLYING
    	}
    }

	 /**
     * Used in processJFK[3|4]
     * That's O^(n) ... but we have only a few elements and
     * we call it only once a round-trip has been done
     *
     * @param exponential
     * @return the corresponding ECDHLightContext with the right exponent
     */
    private ECDHLightContext findECDHContextByPubKey(ECPublicKey exponential) {
        synchronized (ecdhContextFIFO) {
            for (ECDHLightContext result : ecdhContextFIFO) {
                if(exponential.equals(result.getPublicKey())) {
                    return result;
                }
            }

            if((ecdhContextToBePrunned != null) && ((ecdhContextToBePrunned.getPublicKey()).equals(exponential)))
                return ecdhContextToBePrunned;
        }
        return null;
    }

	/*
	 * Prepare DH parameters of message2 for them to be signed (useful in message3 to check the sig)
	 */
	private byte[] assembleDHParams(byte[] nonceInitiator,byte[] nonceResponder,byte[] initiatorExponential, byte[] responderExponential, byte[] id, byte[] sa) {
		byte[] result = new byte[nonceInitiator.length + nonceResponder.length + initiatorExponential.length + responderExponential.length + id.length + sa.length];
		int offset = 0;

		System.arraycopy(nonceInitiator, 0,result,offset,nonceInitiator.length);
		offset += nonceInitiator.length;
		System.arraycopy(nonceResponder,0 ,result,offset,nonceResponder.length);
		offset += nonceResponder.length;
		System.arraycopy(initiatorExponential, 0, result,offset, initiatorExponential.length);
		offset += initiatorExponential.length;
		System.arraycopy(responderExponential, 0, result, offset, responderExponential.length);
		offset += responderExponential.length;
		System.arraycopy(id, 0, result , offset,id.length);
		offset += id.length;
		System.arraycopy(sa, 0, result , offset,sa.length);

		return result;
	}

	private byte[] getTransientKey() {
		synchronized (authenticatorCache) {
			return transientKey;
		}
	}

	// FIXME this is our Key Derivation Function for JFK.
	// FIXME we should move it to freenet/crypt/
	private byte[] computeJFKSharedKey(byte[] exponential, byte[] nI, byte[] nR, String what) {
		assert("0".equals(what) || "1".equals(what) || "2".equals(what) || "3".equals(what)
				|| "4".equals(what) || "5".equals(what) || "6".equals(what) || "7".equals(what));
		byte[] number = null;
		try {
			number = what.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		}

		byte[] toHash = new byte[nI.length + nR.length + number.length];
		int offset = 0;
		System.arraycopy(nI, 0, toHash, offset, nI.length);
		offset += nI.length;
		System.arraycopy(nR, 0, toHash, offset, nR.length);
		offset += nR.length;
		System.arraycopy(number, 0, toHash, offset, number.length);

		return HMAC.macWithSHA256(exponential, toHash);
	}

	private long timeLastReset = -1;

	/**
	 * How big can the authenticator cache get before we flush it ?
	 * n * 40 bytes (32 for the authenticator and 8 for the timestamp)
	 *
	 * We push to it until we reach the cap where we rekey or we reach the PFS interval
	 */
	private int getAuthenticatorCacheSize() {
		if(crypto.isOpennet && node.wantAnonAuth(true)) // seednodes
			return 5000; // 200kB
		else
			return 250; // 10kB
	}
	
	/**
	 * Change the transient key used by JFK.
	 *
	 * It will determine the PFS interval, hence we call it at least once every 30mins.
	 *
	 * @return True if we reset the transient key and therefore the authenticator cache.
	 */
	private boolean maybeResetTransientKey() {
		long now = System.currentTimeMillis();
		boolean isCacheTooBig = true;
		int authenticatorCacheSize = 0;
		int AUTHENTICATOR_CACHE_SIZE = getAuthenticatorCacheSize();
		synchronized (authenticatorCache) {
			authenticatorCacheSize = authenticatorCache.size();
			if(authenticatorCacheSize < AUTHENTICATOR_CACHE_SIZE) {
				isCacheTooBig = false;
				if(now - timeLastReset < TRANSIENT_KEY_REKEYING_MIN_INTERVAL)
					return false;
			}
			timeLastReset = now;

			node.random.nextBytes(transientKey);

			// reset the authenticator cache
			authenticatorCache.clear();
		}
		node.getTicker().queueTimedJob(transientKeyRekeyer, "JFKmaybeResetTransientKey"+now, TRANSIENT_KEY_REKEYING_MIN_INTERVAL, false, false);
		Logger.normal(this, "JFK's TransientKey has been changed and the message cache flushed because "+(isCacheTooBig ? ("the cache is oversized ("+authenticatorCacheSize+')') : "it's time to rekey")+ " on " + this);
		return true;
	}

	@Override
	public Status getConnectivityStatus() {
		long now = System.currentTimeMillis();
		if (now - lastConnectivityStatusUpdate < MINUTES.toMillis(3))
			return lastConnectivityStatus;

		Status value;
		if (crypto.config.alwaysHandshakeAggressively())
			value = AddressTracker.Status.DEFINITELY_NATED;
		else
			value = sock.getDetectedConnectivityStatus();

		lastConnectivityStatusUpdate = now;

		return lastConnectivityStatus = value;
	}

	@Override
	public boolean allowConnection(PeerNode pn, FreenetInetAddress addr) {
		return crypto.allowConnection(pn, addr);
	}

	@Override
	public void setPortForwardingBroken() {
		crypto.setPortForwardingBroken();
	}
	
	/** @returns the modulus length in bytes for a given negType */
	private int getModulusLength() {
	        return ecdhCurveToUse.modulusSize;
	}
	
	private int getSignatureLength() {
	       return ECDSA.Curves.P256.maxSigSize;
	}
	
	private int getNonceSize() {
		return 16;
	}
}
