package freenet.node;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.lang.ref.WeakReference;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import freenet.client.FetchResult;
import freenet.client.async.USKRetriever;
import freenet.client.async.USKRetrieverCallback;
import freenet.crypt.BlockCipher;
import freenet.crypt.DSA;
import freenet.crypt.DSAGroup;
import freenet.crypt.DSAPublicKey;
import freenet.crypt.DSASignature;
import freenet.crypt.ECDSA;
import freenet.crypt.ECDSA.Curves;
import freenet.crypt.Global;
import freenet.crypt.HMAC;
import freenet.crypt.KeyAgreementSchemeContext;
import freenet.crypt.SHA256;
import freenet.crypt.UnsupportedCipherException;
import freenet.crypt.ciphers.Rijndael;
import freenet.io.AddressTracker;
import freenet.io.comm.AsyncMessageCallback;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.FreenetInetAddress;
import freenet.io.comm.Message;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.Peer;
import freenet.io.comm.Peer.LocalAddressException;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.io.comm.SocketHandler;
import freenet.io.xfer.PacketThrottle;
import freenet.keys.ClientSSK;
import freenet.keys.FreenetURI;
import freenet.keys.Key;
import freenet.keys.USK;
import freenet.node.NodeStats.PeerLoadStats;
import freenet.node.NodeStats.RequestType;
import freenet.node.NodeStats.RunningRequestsSnapshot;
import freenet.node.OpennetManager.ConnectionType;
import freenet.node.PeerManager.PeerStatusChangeListener;
import freenet.support.Base64;
import freenet.support.BooleanLastTrueTracker;
import freenet.support.Fields;
import freenet.support.HexUtil;
import freenet.support.IllegalBase64Exception;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.SimpleFieldSet;
import freenet.support.TimeUtil;
import freenet.support.WeakHashSet;
import freenet.support.math.MersenneTwister;
import freenet.support.math.RunningAverage;
import freenet.support.math.SimpleRunningAverage;
import freenet.support.math.TimeDecayingRunningAverage;
import freenet.support.transport.ip.HostnameSyntaxException;
import freenet.support.transport.ip.IPUtil;

/**
 * @author amphibian
 *
 * Represents a peer we are connected to. One of the major issues
 * is that we can rekey, or a node can go down and come back up
 * while we are connected to it, and we want to reinitialize the
 * packet numbers when this happens. Hence we separate a lot of
 * code into SessionKey, which handles all communications to and
 * from this peer over the duration of a single key.
 * 
 * LOCKING: Can hold PeerManager and then lock PeerNode. Cannot hold
 * PeerNode and then lock PeerManager.
 */
public abstract class PeerNode implements USKRetrieverCallback, BasePeerNode, PeerNodeUnlocked {

	private String lastGoodVersion;
	/**
	 * True if this peer has a build number older than our last-known-good build number.
	 * Note that even if this is true, the node can still be 'connected'.
	 */
	protected boolean unroutableOlderVersion;
	/**
	 * True if this peer reports that our build number is before their last-known-good build number.
	 * Note that even if this is true, the node can still be 'connected'.
	 */
	protected boolean unroutableNewerVersion;
	protected boolean disableRouting;
	protected boolean disableRoutingHasBeenSetLocally;
	protected boolean disableRoutingHasBeenSetRemotely;
	/*
	* Buffer of Ni,Nr,g^i,g^r,ID
	*/
	private byte[] jfkBuffer;
	//TODO: sync ?

	protected byte[] jfkKa;
	protected byte[] incommingKey;
	protected byte[] jfkKe;
	protected byte[] outgoingKey;
	protected byte[] jfkMyRef;
	protected byte[] hmacKey;
	protected byte[] ivKey;
	protected byte[] ivNonce;
	protected int ourInitialSeqNum;
	protected int theirInitialSeqNum;
	protected int ourInitialMsgID;
	protected int theirInitialMsgID;
	// The following is used only if we are the initiator

	protected long jfkContextLifetime = 0;
	/** My low-level address for SocketManager purposes */
	private Peer detectedPeer;
	/** My OutgoingPacketMangler i.e. the object which encrypts packets sent to this node */
	private final OutgoingPacketMangler outgoingMangler;
	/** Advertised addresses */
	protected List<Peer> nominalPeer;
	/** The PeerNode's report of our IP address */
	private Peer remoteDetectedPeer;
	/** Is this a testnet node? */
	public final boolean testnetEnabled;
	/** Packets sent/received on the current preferred key */
	private SessionKey currentTracker;
	/** Previous key - has a separate packet number space */
	private SessionKey previousTracker;
	/** When did we last rekey (promote the unverified tracker to new) ? */
	private long timeLastRekeyed;
	/** How much data did we send with the current tracker ? */
	private long totalBytesExchangedWithCurrentTracker = 0;
	/** Are we rekeying ? */
	private boolean isRekeying = false;
	/** Unverified tracker - will be promoted to currentTracker if
	* we receive packets on it
	*/
	private SessionKey unverifiedTracker;
	/** When did we last send a packet? */
	private long timeLastSentPacket;
	/** When did we last receive a packet? */
	private long timeLastReceivedPacket;
	/** When did we last receive a non-auth packet? */
	private long timeLastReceivedDataPacket;
	/** When did we last receive an ack? */
	private long timeLastReceivedAck;
	/** When was isRoutingCompatible() last true? */
	private long timeLastRoutable;
	/** Time added or restarted (reset on startup unlike peerAddedTime) */
	private long timeAddedOrRestarted;
	
	private long countSelectionsSinceConnected = 0;
	// 5mins; yes it's alchemy!
	public static final long SELECTION_SAMPLING_PERIOD = MINUTES.toMillis(5);
	// 30%; yes it's alchemy too! and probably *way* too high to serve any purpose
	public static final int SELECTION_PERCENTAGE_WARNING = 30;
	// Minimum number of routable peers to have for the selection code to have any effect
	public static final int SELECTION_MIN_PEERS = 5;
	// Should be good enough provided we don't get selected more than 10 times per/sec
	// Lower the following value if you want to spare memory... or better switch from a TreeSet to a bit field.
	public static final int SELECTION_MAX_SAMPLES = (int) (10 * SECONDS.convert(SELECTION_SAMPLING_PERIOD, MILLISECONDS));

	/** Is the peer connected? If currentTracker == null then we have no way to send packets 
	 * (though we may be able to receive them on the other trackers), and are disconnected. So we
	 * MUST set isConnected to false when currentTracker = null, but the other way around isn't
	 * always true. LOCKING: Locks itself, safe to read atomically, however we should take (this) 
	 * when setting it. */
	private final BooleanLastTrueTracker isConnected;
	
	// FIXME use a BooleanLastTrueTracker. Be careful as isRoutable() depends on more than this flag!
	private boolean isRoutable;

	/** Used by maybeOnConnect */
	private boolean wasDisconnected = true;
	
	/** Were we removed from the routing table? 
	 * Used as a cache to avoid accessing PeerManager if not needed. */
	private boolean removed;
	
	/**
	* ARK fetcher.
	*/
	private USKRetriever arkFetcher;
	/** My ARK SSK public key; edition is the next one, not the current one,
	* so this is what we want to fetch. */
	private USK myARK;
	/** Number of handshake attempts since last successful connection or ARK fetch */
	private int handshakeCount;
	/** After this many failed handshakes, we start the ARK fetcher. */
	private static final int MAX_HANDSHAKE_COUNT = 2;
	final PeerLocation location;
	/** Node identity; for now a block of data, in future a
	* public key (FIXME). Cannot be changed.
	*/
	final byte[] identity;
	final String identityAsBase64String;
	/** Hash of node identity. Used in setup key. */
	final byte[] identityHash;
	/** Hash of hash of node identity. Used in setup key. */
	final byte[] identityHashHash;
	/** Semi-unique ID used to help in mapping the network (see the code that uses it). Note this is for diagnostic
	* purposes only and should be removed along with the code that uses it eventually - FIXME */
	final long swapIdentifier;
	/** Negotiation types supported */
	int[] negTypes;
	/** Integer hash of node identity. Used as hashCode(). */
	final int hashCode;
	/** The Node we serve */
	final Node node;
	/** The PeerManager we serve */
	final PeerManager peers;
	/** MessageItem's to send ASAP.
	 * LOCKING: Lock on self, always take that lock last. Sometimes used inside PeerNode.this lock. */
	private final PeerMessageQueue messageQueue;
	/** When did we last receive a SwapRequest? */
	private long timeLastReceivedSwapRequest;
	/** Average interval between SwapRequest's */
	private final RunningAverage swapRequestsInterval;
	/** When did we last receive a probe request? */
	private long timeLastReceivedProbeRequest;
	/** Average interval between probe requests */
	private final RunningAverage probeRequestsInterval;
	/** Should we decrement HTL when it is at the maximum?
	* This decision is made once per node to prevent giving
	* away information that can make correlation attacks much
	* easier.
	*/
	final boolean decrementHTLAtMaximum;
	/** Should we decrement HTL when it is at the minimum (1)? */
	final boolean decrementHTLAtMinimum;

	/** Time at which we should send the next handshake request */
	protected long sendHandshakeTime;
	/** Time after which we log message requeues while rate limiting */
	private long nextMessageRequeueLogTime;
	/** Interval between rate limited message requeue logs (in milliseconds) */
	private static final long messageRequeueLogRateLimitInterval = 1000;
	/** Number of messages to be requeued after which we rate limit logging of such */
	private static final int messageRequeueLogRateLimitThreshold = 15;
	/** Version of the node */
	private String version;
	/** Total input */
	private long totalInputSinceStartup;
	/** Total output */
	private long totalOutputSinceStartup;
	/** Peer node crypto group; changing this means new noderef */
	final DSAGroup peerCryptoGroup;

	/** Peer node public key; changing this means new noderef */
	final DSAPublicKey peerPubKey;
	// FIXME when negType 9 is mandatory, make peerECDSAPubKey final and remove getter, synchronization and complexity in parseECDSA().
	private ECPublicKey peerECDSAPubKey;
	private byte[] peerECDSAPubKeyHash;
	final byte[] pubKeyHash;
	final byte[] pubKeyHashHash;
	private boolean isSignatureVerificationSuccessfull;
	/** Incoming setup key. Used to decrypt incoming auth packets.
	* Specifically: K_node XOR H(setupKey).
	*/
	final byte[] incomingSetupKey;
	/** Outgoing setup key. Used to encrypt outgoing auth packets.
	* Specifically: setupKey XOR H(K_node).
	*/
	final byte[] outgoingSetupKey;
	/** Incoming setup cipher (see above) */
	final BlockCipher incomingSetupCipher;
	/** Outgoing setup cipher (see above) */
	final BlockCipher outgoingSetupCipher;
	/** Anonymous-connect cipher. This is used in link setup if
	 * we are trying to get a connection to this node even though
	 * it doesn't know us, e.g. as a seednode. */
	final BlockCipher anonymousInitiatorSetupCipher;
	/** The context object for the currently running negotiation. */
	private KeyAgreementSchemeContext ctx;
	/** The other side's boot ID. This is a random number generated
	* at startup. LOCKING: It is far too dangerous to hold the main (this) lock while accessing 
	* bootID given that we ask for it in the messaging code and so on. This is essentially a "the 
	* other side restarted" flag, so there isn't really a consistency issue with the rest of 
	* PeerNode. So it's okay to effectively use a separate lock for it. */
	private final AtomicLong bootID;
	/** Our boot ID. This is set to a random number on startup, and then reset whenever
	 * we dump the in-flight messages and call disconnected() on their clients, i.e.
	 * whenever we call disconnected(true, ...) */
	private long myBootID;
	/** myBootID at the time of the last successful completed handshake. */
	private long myLastSuccessfulBootID;

	/** If true, this means last time we tried, we got a bogus noderef */
	private boolean bogusNoderef;
	/** The time at which we last completed a connection setup. */
	private long connectedTime;
	/** The status of this peer node in terms of Node.PEER_NODE_STATUS_* */
	private int peerNodeStatus = PeerManager.PEER_NODE_STATUS_DISCONNECTED;

	static final long CHECK_FOR_SWAPPED_TRACKERS_INTERVAL = FNPPacketMangler.SESSION_KEY_REKEYING_INTERVAL / 30;

	static final byte[] TEST_AS_BYTES;
	static {
		try {
			TEST_AS_BYTES = "test".getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		}
	}

	/** Holds a String-Long pair that shows which message types (as name) have been send to this peer. */
	private final Hashtable<String, Long> localNodeSentMessageTypes = new Hashtable<String, Long>();
	/** Holds a String-Long pair that shows which message types (as name) have been received by this peer. */
	private final Hashtable<String, Long> localNodeReceivedMessageTypes = new Hashtable<String, Long>();

	/** Hold collected IP addresses for handshake attempts, populated by DNSRequestor */
	private Peer[] handshakeIPs;
	/** The last time we attempted to update handshakeIPs */
	private long lastAttemptedHandshakeIPUpdateTime;
	/** True if we have never connected to this peer since it was added to this node */
	protected boolean neverConnected;
	/** When this peer was added to this node.
	 * This is used differently by opennet and darknet nodes.
	 * Darknet nodes clear it after connecting but persist it across restarts, and clear it on restart unless the peer has never connected, or if it is more than 30 days ago.
	 * Opennet nodes clear it after the post-connect grace period elapses, and don't persist it across restarts.
	 */
	protected long peerAddedTime = 1;
	/** Average proportion of requests which are rejected or timed out */
	private TimeDecayingRunningAverage pRejected;
	/** Total low-level input bytes */
	private long totalBytesIn;
	/** Total low-level output bytes */
	private long totalBytesOut;
	/** Times had routable connection when checked */
	private long hadRoutableConnectionCount;
	/** Times checked for routable connection */
	private long routableConnectionCheckCount;
	/** Delta between our clock and his clock (positive = his clock is fast, negative = our clock is fast) */
	private long clockDelta;
	/** Percentage uptime of this node, 0 if they haven't said */
	private byte uptime;

	/** If the clock delta is more than this constant, we don't talk to the node. Reason: It may not be up to date,
	* it will have difficulty resolving date-based content etc. */
	private static final long MAX_CLOCK_DELTA = DAYS.toMillis(1);
	/** 1 hour after the node is disconnected, if it is still disconnected and hasn't connected in that time,
	 * clear the message queue */
	private static final long CLEAR_MESSAGE_QUEUE_AFTER = HOURS.toMillis(1);
	/** A WeakReference to this object. Can be taken whenever a node object needs to refer to this object for a
	 * long time, but without preventing it from being GC'ed. */
	final WeakReference<PeerNode> myRef;
	/** The node is being disconnected, but it may take a while. */
	private boolean disconnecting;
	/** When did we last disconnect? Not Disconnected because a discrete event */
	long timeLastDisconnect;
	/** Previous time of disconnection */
	long timePrevDisconnect;
	/** Acknowledging mode */
	private boolean useCumulativeAcks;

	// Burst-only mode
	/** True if we are currently sending this peer a burst of handshake requests */
	private boolean isBursting;
	/** Number of handshake attempts (while in ListenOnly mode) since the beginning of this burst */
	private int listeningHandshakeBurstCount;
	/** Total number of handshake attempts (while in ListenOnly mode) to be in this burst */
	private int listeningHandshakeBurstSize;

	/** The set of the listeners that needs to be notified when status changes. It uses WeakReference, so there is no need to deregister*/
	private Set<PeerManager.PeerStatusChangeListener> listeners=Collections.synchronizedSet(new WeakHashSet<PeerStatusChangeListener>());

	// NodeCrypto for the relevant node reference for this peer's type (Darknet or Opennet at this time))
	protected final NodeCrypto crypto;

	/**
	 * Some alchemy we use in PeerNode.shouldBeExcludedFromPeerList()
	 */
	public static final long BLACK_MAGIC_BACKOFF_PRUNING_TIME = MINUTES.toMillis(5);
	public static final double BLACK_MAGIC_BACKOFF_PRUNING_PERCENTAGE = 0.9;

	/**
	 * For FNP link setup:
	 *  The initiator has to ensure that nonces send back by the
	 *  responder in message2 match what was chosen in message 1
	 */
	protected final LinkedList<byte[]> jfkNoncesSent = new LinkedList<byte[]>();
	private static volatile boolean logMINOR;
	private static volatile boolean logDEBUG;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
				logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}

	private PacketFormat packetFormat;
	MersenneTwister paddingGen;
	
	protected SimpleFieldSet fullFieldSet;

	/**
	 * If this returns true, we will generate the identity from the pubkey.
	 * Only set this if you don't want to send an identity, e.g. for anonymous
	 * initiator crypto where we need a small noderef and we don't use the
	 * identity anyway because we don't auto-reconnect.
	 */
	protected abstract boolean generateIdentityFromPubkey();

	protected boolean ignoreLastGoodVersion() {
		return false;
	}

	/**
	* Create a PeerNode from a SimpleFieldSet containing a
	* node reference for one. This must contain the following
	* fields:
	* - identity
	* - version
	* - location
	* - physical.udp
	* - setupKey
	* Do not add self to PeerManager.
	* @param fs The SimpleFieldSet to parse
	* @param node2 The running Node we are part of.
	*/
	public PeerNode(SimpleFieldSet fs, Node node2, NodeCrypto crypto, PeerManager peers, boolean fromLocal, boolean fromAnonymousInitiator, OutgoingPacketMangler mangler, boolean isOpennet) throws FSParseException, PeerParseException, ReferenceSignatureVerificationException {
	    removed = true;
		boolean noSig = false;
		if(fromLocal || fromAnonymousInitiator) noSig = true;
		myRef = new WeakReference<PeerNode>(this);
		this.checkStatusAfterBackoff = new PeerNodeBackoffStatusChecker(myRef);
		if(mangler == null) throw new NullPointerException();
		this.outgoingMangler = mangler;
		this.node = node2;
		this.crypto = crypto;
		assert(crypto.isOpennet == (isOpennet() || isSeed()));
		this.peers = peers;
		this.backedOffPercent = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
		this.backedOffPercentRT = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
		this.backedOffPercentBulk = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
		this.myBootID = node2.bootID;
		this.bootID = new AtomicLong();
		version = fs.get("version");
		Version.seenVersion(version);
		try {
			simpleVersion = Version.getArbitraryBuildNumber(version);
		} catch (VersionParseException e2) {
			throw new FSParseException("Invalid version "+version+" : "+e2);
		}
		String locationString = fs.get("location");

		location = new PeerLocation(locationString);
		
		disableRouting = disableRoutingHasBeenSetLocally = false;
		disableRoutingHasBeenSetRemotely = false; // Assume so

		lastGoodVersion = fs.get("lastGoodVersion");
		updateVersionRoutablity();

		testnetEnabled = fs.getBoolean("testnet", false);
		if(testnetEnabled) {
			String err = "Ignoring incompatible testnet node " + detectedPeer;
			Logger.error(this, err);
			throw new PeerParseException(err);
		}

		negTypes = fs.getIntArray("auth.negTypes");
		if(negTypes == null || negTypes.length == 0) {
			if(fromAnonymousInitiator)
				negTypes = mangler.supportedNegTypes(false); // Assume compatible. Anonymous initiator = short-lived, and we already connected so we know we are.
			else
				throw new FSParseException("No negTypes!");
		}

		if(fs.getBoolean("opennet", false) != isOpennet)
			throw new FSParseException("Trying to parse a darknet peer as opennet or an opennet peer as darknet isOpennet="+isOpennet+" boolean = "+fs.getBoolean("opennet", false)+" string = \""+fs.get("opennet")+"\"");

		/* Read the DSA key material for the peer */
		try {
			SimpleFieldSet sfs = fs.subset("dsaGroup");
			if(sfs == null) {
			    this.peerCryptoGroup = Global.DSAgroupBigA;
				fs.put("dsaGroup", this.peerCryptoGroup.asFieldSet());
			} else
			    this.peerCryptoGroup = DSAGroup.create(sfs);

			sfs = fs.subset("dsaPubKey");
			if(sfs == null || peerCryptoGroup == null)
				throw new FSParseException("No dsaPubKey - very old reference?");
			else {
				this.peerPubKey = DSAPublicKey.create(sfs, peerCryptoGroup);
				pubKeyHash = SHA256.digest(peerPubKey.asBytes());
				pubKeyHashHash = SHA256.digest(pubKeyHash);
			}
			
			parseECDSA(fs, fromAnonymousInitiator, true);
			if(noSig || verifyReferenceSignature(fs)) {
				this.isSignatureVerificationSuccessfull = true;
			}
		} catch(IllegalBase64Exception e) {
			Logger.error(this, "Caught " + e, e);
			throw new FSParseException(e);
		}

		// Identifier

		if(!generateIdentityFromPubkey()) {
			String identityString = fs.get("identity");
			if(identityString == null)
				throw new PeerParseException("No identity!");
			try {
				identity = Base64.decode(identityString);
			} catch(NumberFormatException e) {
				throw new FSParseException(e);
			} catch(IllegalBase64Exception e) {
				throw new FSParseException(e);
			}
		} else {
			identity = pubKeyHash;
		}

		if(identity == null)
			throw new FSParseException("No identity");
		identityAsBase64String = Base64.encode(identity);
		identityHash = SHA256.digest(identity);
		identityHashHash = SHA256.digest(identityHash);
		swapIdentifier = Fields.bytesToLong(identityHashHash);
		hashCode = Fields.hashCode(pubKeyHash);

		// Setup incoming and outgoing setup ciphers
		byte[] nodeKey = crypto.identityHash;
		byte[] nodeKeyHash = crypto.identityHashHash;

		int digestLength = SHA256.getDigestLength();
		incomingSetupKey = new byte[digestLength];
		for(int i = 0; i < incomingSetupKey.length; i++)
			incomingSetupKey[i] = (byte) (nodeKey[i] ^ identityHashHash[i]);
		outgoingSetupKey = new byte[digestLength];
		for(int i = 0; i < outgoingSetupKey.length; i++)
			outgoingSetupKey[i] = (byte) (nodeKeyHash[i] ^ identityHash[i]);
		if(logMINOR)
			Logger.minor(this, "Keys:\nIdentity:  " + HexUtil.bytesToHex(crypto.myIdentity) +
				"\nThisIdent: " + HexUtil.bytesToHex(identity) +
				"\nNode:      " + HexUtil.bytesToHex(nodeKey) +
				"\nNode hash: " + HexUtil.bytesToHex(nodeKeyHash) +
				"\nThis:      " + HexUtil.bytesToHex(identityHash) +
				"\nThis hash: " + HexUtil.bytesToHex(identityHashHash) +
				"\nFor:       " + getPeer());

		try {
			incomingSetupCipher = new Rijndael(256, 256);
			incomingSetupCipher.initialize(incomingSetupKey);
			outgoingSetupCipher = new Rijndael(256, 256);
			outgoingSetupCipher.initialize(outgoingSetupKey);
			anonymousInitiatorSetupCipher = new Rijndael(256, 256);
			anonymousInitiatorSetupCipher.initialize(identityHash);
		} catch(UnsupportedCipherException e1) {
			Logger.error(this, "Caught: " + e1);
			throw new Error(e1);
		}

		nominalPeer = new ArrayList<Peer>();
		try {
			String physical[] = fs.getAll("physical.udp");
			if(physical == null) {
				// Leave it empty
			} else {
				for(String phys: physical) {
					Peer p;
					try {
						p = new Peer(phys, true, true);
					} catch(HostnameSyntaxException e) {
						if(fromLocal)
							Logger.error(this, "Invalid hostname or IP Address syntax error while parsing peer reference in local peers list: " + phys);
						System.err.println("Invalid hostname or IP Address syntax error while parsing peer reference: " + phys);
						continue;
					} catch (PeerParseException e) {
						if(fromLocal)
							Logger.error(this, "Invalid hostname or IP Address syntax error while parsing peer reference in local peers list: " + phys);
						System.err.println("Invalid hostname or IP Address syntax error while parsing peer reference: " + phys);
						continue;
					} catch (UnknownHostException e) {
						if(fromLocal)
							Logger.error(this, "Invalid hostname or IP Address syntax error while parsing peer reference in local peers list: " + phys);
						System.err.println("Invalid hostname or IP Address syntax error while parsing peer reference: " + phys);
						continue;
					}
					if(!nominalPeer.contains(p))
						nominalPeer.add(p);
				}
			}
		} catch(Exception e1) {
			throw new FSParseException(e1);
		}
		if(nominalPeer.isEmpty()) {
			Logger.normal(this, "No IP addresses found for identity '" + identityAsBase64String + "', possibly at location '" + location + ": " + userToString());
			detectedPeer = null;
		} else {
			detectedPeer = nominalPeer.get(0);
		}
		updateShortToString();

		// Don't create trackers until we have a key
		currentTracker = null;
		previousTracker = null;

		timeLastSentPacket = -1;
		timeLastReceivedPacket = -1;
		timeLastReceivedSwapRequest = -1;
		timeLastRoutable = -1;
		timeAddedOrRestarted = System.currentTimeMillis();

		swapRequestsInterval = new SimpleRunningAverage(50, Node.MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS);
		probeRequestsInterval = new SimpleRunningAverage(50, Node.MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS);

		messageQueue = new PeerMessageQueue();

		decrementHTLAtMaximum = node.random.nextFloat() < Node.DECREMENT_AT_MAX_PROB;
		decrementHTLAtMinimum = node.random.nextFloat() < Node.DECREMENT_AT_MIN_PROB;

		pingNumber = node.random.nextLong();

		// A SimpleRunningAverage would be a bad choice because it would cause oscillations.
		// So go for a filter.
		pingAverage =
			// Short average otherwise we will reject for a *REALLY* long time after any spike.
			new TimeDecayingRunningAverage(1, SECONDS.toMillis(30), 0, NodePinger.CRAZY_MAX_PING_TIME, node);

		// TDRA for probability of rejection
		pRejected =
			new TimeDecayingRunningAverage(0, MINUTES.toMillis(4), 0.0, 1.0, node);

		// ARK stuff.

		parseARK(fs, true, false);

		// Now for the metadata.
		// The metadata sub-fieldset contains data about the node which is not part of the node reference.
		// It belongs to this node, not to the node being described.
		// Therefore, if we are parsing a remotely supplied ref, ignore it.

		long now = System.currentTimeMillis();
		if(fromLocal) {

			SimpleFieldSet metadata = fs.subset("metadata");

			if(metadata != null) {
				
				location.setPeerLocations(fs.getAll("peersLocation"));
				
				// Don't be tolerant of nonexistant domains; this should be an IP address.
				Peer p;
				try {
					String detectedUDPString = metadata.get("detected.udp");
					p = null;
					if(detectedUDPString != null)
						p = new Peer(detectedUDPString, false);
				} catch(UnknownHostException e) {
					p = null;
					Logger.error(this, "detected.udp = " + metadata.get("detected.udp") + " - " + e, e);
				} catch(PeerParseException e) {
					p = null;
					Logger.error(this, "detected.udp = " + metadata.get("detected.udp") + " - " + e, e);
				}
				if(p != null)
					detectedPeer = p;
				updateShortToString();
				timeLastReceivedPacket = metadata.getLong("timeLastReceivedPacket", -1);
				long timeLastConnected = metadata.getLong("timeLastConnected", -1);
				timeLastRoutable = metadata.getLong("timeLastRoutable", -1);
				if(timeLastConnected < 1 && timeLastReceivedPacket > 1)
					timeLastConnected = timeLastReceivedPacket;
				isConnected = new BooleanLastTrueTracker(timeLastConnected);
				if(timeLastRoutable < 1 && timeLastReceivedPacket > 1)
					timeLastRoutable = timeLastReceivedPacket;
				peerAddedTime = metadata.getLong("peerAddedTime",
						0 // missing peerAddedTime is normal: Not only do exported refs not include it, opennet peers don't either.
						);
				neverConnected = metadata.getBoolean("neverConnected", false);
				maybeClearPeerAddedTimeOnRestart(now);
				hadRoutableConnectionCount = metadata.getLong("hadRoutableConnectionCount", 0);
				routableConnectionCheckCount = metadata.getLong("routableConnectionCheckCount", 0);
			} else {
				isConnected = new BooleanLastTrueTracker();
			}
		} else {
			isConnected = new BooleanLastTrueTracker();
			neverConnected = true;
			peerAddedTime = now;
		}
		// populate handshakeIPs so handshakes can start ASAP
		lastAttemptedHandshakeIPUpdateTime = 0;
		maybeUpdateHandshakeIPs(true);

		listeningHandshakeBurstCount = 0;
		listeningHandshakeBurstSize = Node.MIN_BURSTING_HANDSHAKE_BURST_SIZE
			+ node.random.nextInt(Node.RANDOMIZED_BURSTING_HANDSHAKE_BURST_SIZE);

		if(isBurstOnly()) {
			Logger.minor(this, "First BurstOnly mode handshake in "+(sendHandshakeTime - now)+"ms for "+shortToString()+" (count: "+listeningHandshakeBurstCount+", size: "+listeningHandshakeBurstSize+ ')');
		}

		if(fromLocal)
			innerCalcNextHandshake(false, false, now); // Let them connect so we can recognise we are NATed

		else
			sendHandshakeTime = now;  // Be sure we're ready to handshake right away

		totalInputSinceStartup = fs.getLong("totalInput", 0);
		totalOutputSinceStartup = fs.getLong("totalOutput", 0);

		byte buffer[] = new byte[16];
		node.random.nextBytes(buffer);
		paddingGen = new MersenneTwister(buffer);
		
		if(fromLocal) {
			SimpleFieldSet f = fs.subset("full");
			if(fullFieldSet == null && f != null)
				fullFieldSet = f;
		}
		
	// status may have changed from PEER_NODE_STATUS_DISCONNECTED to PEER_NODE_STATUS_NEVER_CONNECTED
	}

	/** @return True if there is a new ECDSA key */
	private synchronized boolean parseECDSA(SimpleFieldSet fs, boolean fromAnonymousInitiator, boolean startup) throws FSParseException {
	    // FIXME When negType9 is mandatory, make the fields final and move back into PeerNode.
		SimpleFieldSet sfs = fs.subset("ecdsa.P256");
		if(sfs == null) {
			// ECDSA is not sent on connect, for example.
			// This is fine, don't change the existing reference.
			return false;
		} else {
            byte[] pub;
			try {
				pub = Base64.decode(sfs.get("pub"));
			} catch (IllegalBase64Exception e) {
				Logger.error(this, "Caught " + e + " parsing ECC pubkey", e);
				throw new FSParseException(e);
			}
            if (pub.length > ECDSA.Curves.P256.modulusSize)
                throw new FSParseException("ecdsa.P256.pub is not the right size!");
            ECPublicKey key = ECDSA.getPublicKey(pub, ECDSA.Curves.P256);
            if(key == null)
                throw new FSParseException("ecdsa.P256.pub is invalid!");
            if(peerECDSAPubKey == null) {
                this.peerECDSAPubKey = key;
                peerECDSAPubKeyHash = SHA256.digest(peerECDSAPubKey.getEncoded());
                if(!startup) {
                    Logger.normal(this, "Peer now has an ECDSA key, upgraded to negType 9+: "+userToString());
                    if(isDarknet()) node.peers.writePeersDarknetUrgent();
                }
                return true;
            } else if(!key.equals(peerECDSAPubKey)) {
            	Logger.error(this, "Tried to change ECDSA key on "+userToString()+" - did neighbour try to downgrade? Rejecting...");
            	throw new FSParseException("Changing ECDSA key not allowed!");
            } else {
            	return false;
            }
		}
	}

	abstract boolean dontKeepFullFieldSet();

	protected abstract void maybeClearPeerAddedTimeOnRestart(long now);

	private boolean parseARK(SimpleFieldSet fs, boolean onStartup, boolean forDiffNodeRef) {
		USK ark = null;
		long arkNo = 0;
		try {
			String arkPubKey = fs.get("ark.pubURI");
			arkNo = fs.getLong("ark.number", -1);
			if(arkPubKey == null && arkNo <= -1) {
				// ark.pubURI and ark.number are always optional as a pair
				return false;
			} else if(arkPubKey != null && arkNo > -1) {
				if(onStartup) arkNo++;
				// this is the number of the ref we are parsing.
				// we want the number of the next edition.
				// on startup we want to fetch the old edition in case there's been a corruption.
				FreenetURI uri = new FreenetURI(arkPubKey);
				ClientSSK ssk = new ClientSSK(uri);
				ark = new USK(ssk, arkNo);
			} else if(forDiffNodeRef && arkPubKey == null && myARK != null && arkNo > -1) {
				// get the ARK URI from the previous ARK and the edition from the SFS
				ark = myARK.copy(arkNo);
			} else if(forDiffNodeRef && arkPubKey != null && myARK != null && arkNo <= -1) {
				// the SFS must contain an edition if it contains a arkPubKey
				Logger.error(this, "Got a differential node reference from " + this + " with an arkPubKey but no ARK edition");
				return false;
			} else return false;
		} catch(MalformedURLException e) {
			Logger.error(this, "Couldn't parse ARK info for " + this + ": " + e, e);
		} catch(NumberFormatException e) {
			Logger.error(this, "Couldn't parse ARK info for " + this + ": " + e, e);
		}

		synchronized(this) {
			if(ark != null) {
				if((myARK == null) || ((myARK != ark) && !myARK.equals(ark))) {
					myARK = ark;
					return true;
				}
			}
		}
		return false;
	}

	/**
	* Get my low-level address. This is the address that packets have been received from from this node.
	*
	* Normally this is the address that packets have been received from from this node.
	* However, if ignoreSourcePort is set, we will search for a similar address with a different port
	* number in the node reference.
	*/
	@Override
	public synchronized Peer getPeer() {
		return detectedPeer;
	}

	/**
	* Returns an array with the advertised addresses and the detected one
	*/
	protected synchronized Peer[] getHandshakeIPs() {
		return handshakeIPs;
	}

	private String handshakeIPsToString() {
		Peer[] localHandshakeIPs;
		synchronized(this) {
			localHandshakeIPs = handshakeIPs;
		}
		if(localHandshakeIPs == null)
			return "null";
		StringBuilder toOutputString = new StringBuilder(1024);
		toOutputString.append("[ ");
		if (localHandshakeIPs.length != 0) {
			for(Peer localHandshakeIP: localHandshakeIPs) {
				if(localHandshakeIP == null) {
					toOutputString.append("null, ");
					continue;
				}
				toOutputString.append('\'');
				// Actually do the DNS request for the member Peer of localHandshakeIPs
				toOutputString.append(localHandshakeIP.getAddress(false));
				toOutputString.append('\'');
				toOutputString.append(", ");
			}
			// assert(toOutputString.length() >= 2) -- always true as localHandshakeIPs.length != 0
			// remove last ", "
			toOutputString.deleteCharAt(toOutputString.length()-1);
			toOutputString.deleteCharAt(toOutputString.length()-1);
		}
		toOutputString.append(" ]");
		return toOutputString.toString();
	}

	/**
	* Do the maybeUpdateHandshakeIPs DNS requests, but only if ignoreHostnames is false
	* This method should only be called by maybeUpdateHandshakeIPs.
	* Also removes dupes post-lookup.
	*/
	private Peer[] updateHandshakeIPs(Peer[] localHandshakeIPs, boolean ignoreHostnames) {
		for(Peer localHandshakeIP: localHandshakeIPs) {
			if(ignoreHostnames) {
				// Don't do a DNS request on the first cycle through PeerNodes by DNSRequest
				// upon startup (I suspect the following won't do anything, but just in case)
				if(logMINOR)
					Logger.debug(this, "updateHandshakeIPs: calling getAddress(false) on Peer '" + localHandshakeIP + "' for " + shortToString() + " (" + ignoreHostnames + ')');
				localHandshakeIP.getAddress(false);
			} else {
				// Actually do the DNS request for the member Peer of localHandshakeIPs
				if(logMINOR)
					Logger.debug(this, "updateHandshakeIPs: calling getHandshakeAddress() on Peer '" + localHandshakeIP + "' for " + shortToString() + " (" + ignoreHostnames + ')');
				localHandshakeIP.getHandshakeAddress();
			}
		}
		// De-dupe
		HashSet<Peer> ret = new HashSet<Peer>();
		for(Peer localHandshakeIP: localHandshakeIPs)
			ret.add(localHandshakeIP);
		return ret.toArray(new Peer[ret.size()]);
	}

	/**
	* Do occasional DNS requests, but ignoreHostnames should be true
	* on PeerNode construction
	*/
	public void maybeUpdateHandshakeIPs(boolean ignoreHostnames) {
		long now = System.currentTimeMillis();
		Peer localDetectedPeer = null;
		synchronized(this) {
			localDetectedPeer = detectedPeer;
			if((now - lastAttemptedHandshakeIPUpdateTime) < MINUTES.toMillis(5)) {
				//Logger.minor(this, "Looked up recently (localDetectedPeer = "+localDetectedPeer + " : "+((localDetectedPeer == null) ? "" : localDetectedPeer.getAddress(false).toString()));
				return;
			}
			// We want to come back right away for DNS requesting if this is our first time through
			if(!ignoreHostnames)
				lastAttemptedHandshakeIPUpdateTime = now;
		}
		if(logMINOR)
			Logger.minor(this, "Updating handshake IPs for peer '" + shortToString() + "' (" + ignoreHostnames + ')');
		Peer[] myNominalPeer;

		// Don't synchronize while doing lookups which may take a long time!
		synchronized(this) {
			myNominalPeer = nominalPeer.toArray(new Peer[nominalPeer.size()]);
		}

		Peer[] localHandshakeIPs;
		if(myNominalPeer.length == 0) {
			if(localDetectedPeer == null) {
				synchronized(this) {
					handshakeIPs = null;
				}
				if(logMINOR)
					Logger.minor(this, "1: maybeUpdateHandshakeIPs got a result of: " + handshakeIPsToString());
				return;
			}
			localHandshakeIPs = new Peer[]{localDetectedPeer};
			localHandshakeIPs = updateHandshakeIPs(localHandshakeIPs, ignoreHostnames);
			synchronized(this) {
				handshakeIPs = localHandshakeIPs;
			}
			if(logMINOR)
				Logger.minor(this, "2: maybeUpdateHandshakeIPs got a result of: " + handshakeIPsToString());
			return;
		}

		// Hack for two nodes on the same IP that can't talk over inet for routing reasons
		FreenetInetAddress localhost = node.fLocalhostAddress;
		Peer[] nodePeers = outgoingMangler.getPrimaryIPAddress();

		List<Peer> localPeers = null;
		synchronized(this) {
			localPeers = new ArrayList<Peer>(nominalPeer);
		}

		boolean addedLocalhost = false;
		Peer detectedDuplicate = null;
		for(Peer p: myNominalPeer) {
			if(p == null)
				continue;
			if(localDetectedPeer != null) {
				if((p != localDetectedPeer) && p.equals(localDetectedPeer)) {
					// Equal but not the same object; need to update the copy.
					detectedDuplicate = p;
				}
			}
			FreenetInetAddress addr = p.getFreenetAddress();
			if(addr.equals(localhost)) {
				if(addedLocalhost)
					continue;
				addedLocalhost = true;
			}
			for(Peer nodePeer: nodePeers) {
				// REDFLAG - Two lines so we can see which variable is null when it NPEs
				FreenetInetAddress myAddr = nodePeer.getFreenetAddress();
				if(myAddr.equals(addr)) {
					if(!addedLocalhost)
						localPeers.add(new Peer(localhost, p.getPort()));
					addedLocalhost = true;
				}
			}
			if(localPeers.contains(p))
				continue;
			localPeers.add(p);
		}

		localHandshakeIPs = localPeers.toArray(new Peer[localPeers.size()]);
		localHandshakeIPs = updateHandshakeIPs(localHandshakeIPs, ignoreHostnames);
		synchronized(this) {
			handshakeIPs = localHandshakeIPs;
			if((detectedDuplicate != null) && detectedDuplicate.equals(localDetectedPeer))
				localDetectedPeer = detectedPeer = detectedDuplicate;
			updateShortToString();
		}
		if(logMINOR) {
			if(localDetectedPeer != null)
				Logger.minor(this, "3: detectedPeer = " + localDetectedPeer + " (" + localDetectedPeer.getAddress(false) + ')');
			Logger.minor(this, "3: maybeUpdateHandshakeIPs got a result of: " + handshakeIPsToString());
		}
	}

	/**
	* Returns this peer's current keyspace location, or -1 if it is unknown.
	*/
	public double getLocation() {
		return location.getLocation();
	}

	public boolean shouldBeExcludedFromPeerList() {
		long now = System.currentTimeMillis();
		synchronized(this) {
			if(BLACK_MAGIC_BACKOFF_PRUNING_PERCENTAGE < backedOffPercent.currentValue())
				return true;
			else if(BLACK_MAGIC_BACKOFF_PRUNING_TIME + now < getRoutingBackedOffUntilMax())
				return true;
			else
				return false;
		}
	}

	public double[] getPeersLocation() {
		return location.getPeerLocations();
	}

	public long getLocSetTime() {
		return location.getLocationSetTime();
	}

	/**
	* Returns a unique node identifier (usefull to compare two peernodes).
	*/
	public int getIdentityHash() {
		return hashCode;
	}

	/**
	 * Returns true if the last-known build number for this peer is to old to allow traffic to be routed to it.
	 * This does not give any indication as to the connection status of the peer.
	 */
	public synchronized boolean isUnroutableOlderVersion() {
		return unroutableOlderVersion;
	}

	/**
	 * Returns true if this (or another) peer has reported to us that our build number is too old for data to be routed
	 * to us. In turn, we will not route data to them either. Does not strictly indicate that the peer is connected.
	 */
	public synchronized boolean isUnroutableNewerVersion() {
		return unroutableNewerVersion;
	}

	/**
	* Returns true if requests can be routed through this peer. True if the peer's location is known, presently
	* connected, and routing-compatible. That is, ignoring backoff, the peer's location is known, build number
	* is compatible, and routing has not been explicitly disabled.
	*
	* Note possible deadlocks! PeerManager calls this, we call
	* PeerManager in e.g. verified.
	*/
	@Override
	public boolean isRoutable() {
		if((!isConnected()) || (!isRoutingCompatible())) return false;
		return location.isValidLocation();
	}
	
	synchronized boolean isInMandatoryBackoff(long now, boolean realTime) {
		long mandatoryBackoffUntil = realTime ? mandatoryBackoffUntilRT : mandatoryBackoffUntilBulk;
		if((mandatoryBackoffUntil > -1 && now < mandatoryBackoffUntil)) {
			if(logMINOR) Logger.minor(this, "In mandatory backoff");
			return true;
		}
		return false;
	}
	
	/**
	 * Returns true if (apart from actually knowing the peer's location), it is presumed that this peer could route requests.
	 * True if this peer's build number is not 'too-old' or 'too-new', actively connected, and not marked as explicity disabled.
	 * Does not reflect any 'backoff' logic.
	 */
	public boolean isRoutingCompatible() {
		long now = System.currentTimeMillis(); // no System.currentTimeMillis in synchronized
		synchronized(this) {
			if(isRoutable && !disableRouting) {
				timeLastRoutable = now;
				return true;
			}
			if(logMINOR) Logger.minor(this, "Not routing compatible");
			return false;
		}
	}

	@Override
	public boolean isConnected() {
		return isConnected.isTrue();
	}

	/**
	* Send a message, off-thread, to this node.
	* @param msg The message to be sent.
	* @param cb The callback to be called when the packet has been sent, or null.
	* @param ctr A callback to tell how many bytes were used to send this message.
	*/
	@Override
	public MessageItem sendAsync(Message msg, AsyncMessageCallback cb, ByteCounter ctr) throws NotConnectedException {
		if(ctr == null)
			Logger.error(this, "ByteCounter null, so bandwidth usage cannot be logged. Refusing to send.", new Exception("debug"));
		if(logMINOR)
			Logger.minor(this, "Sending async: " + msg + " : " + cb + " on " + this+" for "+node.getDarknetPortNumber()+" priority "+msg.getPriority());
		if(!isConnected()) {
			if(cb != null)
				cb.disconnected();
			throw new NotConnectedException();
		}
		if(msg.getSource() != null) {
			Logger.error(this, "Messages should NOT be relayed as-is, they should always be re-created to clear any sub-messages etc, see comments in Message.java!: "+msg, new Exception("error"));
		}
		addToLocalNodeSentMessagesToStatistic(msg);
		MessageItem item = new MessageItem(msg, cb == null ? null : new AsyncMessageCallback[]{cb}, ctr);
		long now = System.currentTimeMillis();
		reportBackoffStatus(now);
		int maxSize = getMaxPacketSize();
		int x = messageQueue.queueAndEstimateSize(item, maxSize);
		if(x > maxSize || !node.enablePacketCoalescing) {
			// If there is a packet's worth to send, wake up the packetsender.
			wakeUpSender();
		}
		// Otherwise we do not need to wake up the PacketSender
		// It will wake up before the maximum coalescing delay (100ms) because
		// it wakes up every 100ms *anyway*.
		return item;
	}
	
	@Override
	public void wakeUpSender() {
		if(logMINOR) Logger.minor(this, "Waking up PacketSender");
		node.ps.wakeUp();
	}

	@Override
	public boolean unqueueMessage(MessageItem message) {
		if(logMINOR) Logger.minor(this, "Unqueueing message on "+this+" : "+message);
		return messageQueue.removeMessage(message);
	}

	public long getMessageQueueLengthBytes() {
		return messageQueue.getMessageQueueLengthBytes();
	}

	/**
	 * Returns the number of milliseconds that it is estimated to take to transmit the currently queued packets.
	 */
	public long getProbableSendQueueTime() {
		double bandwidth = (getThrottle().getBandwidth()+1.0);
		if(shouldThrottle())
			bandwidth = Math.min(bandwidth, node.getOutputBandwidthLimit() / 2);
		long length = getMessageQueueLengthBytes();
		return (long)(1000.0*length/bandwidth);
	}

	/**
	* @return The last time we received a packet.
	*/
	public synchronized long lastReceivedPacketTime() {
		return timeLastReceivedPacket;
	}

	public synchronized long lastReceivedDataPacketTime() {
		return timeLastReceivedDataPacket;
	}
	
	public synchronized long lastReceivedAckTime() {
		return timeLastReceivedAck;
	}

	public long timeLastConnected(long now) {
		return isConnected.getTimeLastTrue(now);
	}

	public synchronized long timeLastRoutable() {
		return timeLastRoutable;
	}

	@Override
	public void maybeRekey() {
		long now = System.currentTimeMillis();
		boolean shouldDisconnect = false;
		boolean shouldReturn = false;
		boolean shouldRekey = false;
		long timeWhenRekeyingShouldOccur = 0;

		synchronized (this) {
			timeWhenRekeyingShouldOccur = timeLastRekeyed + FNPPacketMangler.SESSION_KEY_REKEYING_INTERVAL;
			shouldDisconnect = (timeWhenRekeyingShouldOccur + FNPPacketMangler.MAX_SESSION_KEY_REKEYING_DELAY < now) && isRekeying;
			shouldReturn = isRekeying || !isConnected();
			shouldRekey = (timeWhenRekeyingShouldOccur < now);
			if((!shouldRekey) && totalBytesExchangedWithCurrentTracker > FNPPacketMangler.AMOUNT_OF_BYTES_ALLOWED_BEFORE_WE_REKEY) {
				shouldRekey = true;
				timeWhenRekeyingShouldOccur = now;
			}
		}

		if(shouldDisconnect) {
			String time = TimeUtil.formatTime(FNPPacketMangler.MAX_SESSION_KEY_REKEYING_DELAY);
			System.err.println("The peer (" + this + ") has been asked to rekey " + time + " ago... force disconnect.");
			Logger.error(this, "The peer (" + this + ") has been asked to rekey " + time + " ago... force disconnect.");
			forceDisconnect();
		} else if (shouldReturn || hasLiveHandshake(now)) {
			return;
		} else if(shouldRekey) {
			startRekeying();
		}
	}

	@Override
	public void startRekeying() {
		long now = System.currentTimeMillis();
		synchronized(this) {
			if(isRekeying) return;
			isRekeying = true;
			sendHandshakeTime = now; // Immediately
			ctx = null;
		}
		Logger.normal(this, "We are asking for the key to be renewed (" + this.detectedPeer + ')');
	}

	/**
	* @return The time this PeerNode was added to the node (persistent across restarts).
	*/
	public synchronized long getPeerAddedTime() {
		return peerAddedTime;
	}

	/**
	* @return The time elapsed since this PeerNode was added to the node, or the node started up.
	*/
	public synchronized long timeSinceAddedOrRestarted() {
		return System.currentTimeMillis() - timeAddedOrRestarted;
	}
	
	/**
	* Disconnected e.g. due to not receiving a packet for ages.
	* @param dumpMessageQueue If true, clear the messages-to-send queue, and
	* change the bootID so even if we reconnect the other side will know that
	* a disconnect happened. If false, don't clear the messages yet. They 
	* will be cleared after an hour if the peer is disconnected at that point.
	* @param dumpTrackers If true, dump the SessionKey's (i.e. dump the
	* cryptographic data so we don't understand any packets they send us).
	* <br>
	* Possible arguments:<ul>
	* <li>true, true => dump everything, immediate disconnect</li>
	* <li>true, false => dump messages but keep trackers so we can 
	* acknowledge messages on their end for a while.</li>
	* <li>false, false => tell the rest of the node that we have 
	* disconnected but do not immediately drop messages, continue to 
	* respond to their messages.</li>
	* <li>false, true => dump crypto but keep messages. DOES NOT MAKE 
	* SENSE!!! DO NOT USE!!! </ul>
	* @return True if the node was connected, false if it was not.
	*/
	public boolean disconnected(boolean dumpMessageQueue, boolean dumpTrackers) {
		assert(!((!dumpMessageQueue) && dumpTrackers)); // Invalid combination!
		final long now = System.currentTimeMillis();
		if(isRealConnection())
			Logger.normal(this, "Disconnected " + this, new Exception("debug"));
		else if(logMINOR)
			Logger.minor(this, "Disconnected "+this, new Exception("debug"));
		node.usm.onDisconnect(this);
		if(dumpMessageQueue)
			node.tracker.onRestartOrDisconnect(this);
		node.failureTable.onDisconnect(this);
		node.peers.disconnected(this);
		node.nodeUpdater.disconnected(this);
		boolean ret;
		SessionKey cur, prev, unv;
		MessageItem[] messagesTellDisconnected = null;
		List<MessageItem> moreMessagesTellDisconnected = null;
		PacketFormat oldPacketFormat = null;
		synchronized(this) {
			disconnecting = false;
			// Force renegotiation.
			ret = isConnected.set(false, now);
			isRoutable = false;
			isRekeying = false;
			// Prevent sending packets to the node until that happens.
			cur = currentTracker;
			prev = previousTracker;
			unv = unverifiedTracker;
			if(dumpTrackers) {
				currentTracker = null;
				previousTracker = null;
				unverifiedTracker = null;
			}
			// Else DO NOT clear trackers, because hopefully it's a temporary connectivity glitch.
			sendHandshakeTime = now;
			countFailedRevocationTransfers = 0;
			timePrevDisconnect = timeLastDisconnect;
			timeLastDisconnect = now;
			if(dumpMessageQueue) {
				// Reset the boot ID so that we get different trackers next time.
				myBootID = node.fastWeakRandom.nextLong();
				messagesTellDisconnected = grabQueuedMessageItems();
				oldPacketFormat = packetFormat;
				packetFormat = null;
			}
		}
		if(oldPacketFormat != null) {
			moreMessagesTellDisconnected = oldPacketFormat.onDisconnect();
		}
		if(messagesTellDisconnected != null) {
			if(logMINOR)
				Logger.minor(this, "Messages to dump: "+messagesTellDisconnected.length);
			for(MessageItem mi : messagesTellDisconnected) {
				mi.onDisconnect();
			}
		}
		if(moreMessagesTellDisconnected != null) {
			if(logMINOR)
				Logger.minor(this, "Messages to dump: "+moreMessagesTellDisconnected.size());
			for(MessageItem mi : moreMessagesTellDisconnected) {
				mi.onDisconnect();
			}
		}
		if(cur != null) cur.disconnected();
		if(prev != null) prev.disconnected();
		if(unv != null) unv.disconnected();
		if(_lastThrottle != null)
			_lastThrottle.maybeDisconnected();
		node.lm.lostOrRestartedNode(this);
		if(peers.havePeer(this))
			setPeerNodeStatus(now);
		if(!dumpMessageQueue) {
			// Wait for a while and then drop the messages if we haven't
			// reconnected.
			node.getTicker().queueTimedJob(new Runnable() {
				@Override
				public void run() {
					if((!PeerNode.this.isConnected()) &&
							timeLastDisconnect == now) {
						PacketFormat oldPacketFormat = null;
						synchronized(this) {
							if(isConnected()) return;
							// Reset the boot ID so that we get different trackers next time.
							myBootID = node.fastWeakRandom.nextLong();
							oldPacketFormat = packetFormat;
							packetFormat = null;
						}
						MessageItem[] messagesTellDisconnected = grabQueuedMessageItems();
						if(messagesTellDisconnected != null) {
							for(MessageItem mi : messagesTellDisconnected) {
								mi.onDisconnect();
							}
						}
						if(oldPacketFormat != null) {
							List<MessageItem> moreMessagesTellDisconnected = 
								oldPacketFormat.onDisconnect();
							if(moreMessagesTellDisconnected != null) {
								if(logMINOR)
									Logger.minor(this, "Messages to dump: "+moreMessagesTellDisconnected.size());
								for(MessageItem mi : moreMessagesTellDisconnected) {
									mi.onDisconnect();
								}
							}
						}
					}

				}
			}, CLEAR_MESSAGE_QUEUE_AFTER);
		}
		// Tell opennet manager even if this is darknet, because we may need more opennet peers now.
		OpennetManager om = node.getOpennet();
		if(om != null)
			om.onDisconnect(this);
		outputLoadTrackerRealTime.failSlotWaiters(true);
		outputLoadTrackerBulk.failSlotWaiters(true);
		loadSenderRealTime.onDisconnect();
		loadSenderBulk.onDisconnect();
		return ret;
	}

	@Override
	public void forceDisconnect() {
		Logger.error(this, "Forcing disconnect on " + this, new Exception("debug"));
		disconnected(true, true); // always dump trackers, maybe dump messages
	}

	/**
	* Grab all queued Message's.
	* @return Null if no messages are queued, or an array of
	* Message's.
	*/
	public MessageItem[] grabQueuedMessageItems() {
		return messageQueue.grabQueuedMessageItems();
	}

	public void requeueMessageItems(MessageItem[] messages, int offset, int length, boolean dontLog) {
		requeueMessageItems(messages, offset, length, dontLog, "");
	}

	public void requeueMessageItems(MessageItem[] messages, int offset, int length, boolean dontLog, String reason) {
		// Will usually indicate serious problems
		if(!dontLog) {
			long now = System.currentTimeMillis();
			String rateLimitWrapper = "";
			boolean rateLimitLogging = false;
			if(messages.length > messageRequeueLogRateLimitThreshold) {
				rateLimitWrapper = " (log message rate limited)";
				if(nextMessageRequeueLogTime <= now) {
					nextMessageRequeueLogTime = now + messageRequeueLogRateLimitInterval;
				} else {
					rateLimitLogging = true;
				}
			}
			if(!rateLimitLogging) {
				String reasonWrapper = "";
				if(0 < reason.length()) {
					reasonWrapper = " because of '" + reason + '\'';
				}
				Logger.normal(this, "Requeueing " + messages.length + " messages" + reasonWrapper + " on " + this + rateLimitWrapper);
			}
		}
		synchronized(messageQueue) {
			for(int i = offset+length-1; i >= offset; i--)
				if(messages[i] != null)
					messageQueue.pushfrontPrioritizedMessageItem(messages[i]);
		}
	}

	/**
	* @return The time at which we must send a packet, even if
	* it means it will only contains ack requests etc., or
	* Long.MAX_VALUE if we have no pending ack request/acks/etc.
	* Note that if this is less than now, it may not be entirely
	* accurate i.e. we definitely must send a packet, but don't
	* rely on it to tell you exactly how overdue we are.
	*/
	public long getNextUrgentTime(long now) {
		long t = Long.MAX_VALUE;
		SessionKey cur;
		SessionKey prev;
		PacketFormat pf;
		synchronized(this) {
			if(!isConnected()) return Long.MAX_VALUE;
			cur = currentTracker;
			prev = previousTracker;
			pf = packetFormat;
			if(cur == null && prev == null) return Long.MAX_VALUE;
		}
		if(pf != null) {
			boolean canSend = cur != null && pf.canSend(cur);
			if(canSend) { // New messages are only sent on cur.
				long l = messageQueue.getNextUrgentTime(t, 0); // Need an accurate value even if in the past.
				if(t >= now && l < now && logMINOR)
					Logger.minor(this, "Next urgent time from message queue less than now");
				else if(logDEBUG)
					Logger.debug(this, "Next urgent time is "+(l-now)+"ms on "+this);
				t = l;
			}
			long l = pf.timeNextUrgent(canSend);
			if(l < now && logMINOR)
				Logger.minor(this, "Next urgent time from packet format less than now on "+this);
			t = Math.min(t, l);
		}
		return t;
	}

	/**
	* @return The time at which we last sent a packet.
	*/
	public long lastSentPacketTime() {
		return timeLastSentPacket;
	}

	/**
	* @return True, if we are disconnected and it has been a
	* sufficient time period since we last sent a handshake
	* attempt.
	*/
	public boolean shouldSendHandshake() {
		long now = System.currentTimeMillis();
		boolean tempShouldSendHandshake = false;
		boolean disconnected;
		synchronized(this) {
			if(disconnecting) return false;
			disconnected = !isConnected();
			tempShouldSendHandshake = ((now > sendHandshakeTime) && (handshakeIPs != null) && (isRekeying || disconnected));
		}
		if(logMINOR) Logger.minor(this, "shouldSendHandshake(): initial = "+tempShouldSendHandshake);
		if(tempShouldSendHandshake && (hasLiveHandshake(now)))
			tempShouldSendHandshake = false;
		if(tempShouldSendHandshake) {
			if(disconnected && isBurstOnly()) {
				synchronized(this) {
					isBursting = true;
				}
			    setPeerNodeStatus(System.currentTimeMillis());
			} else
				return true;
		}
		if(logMINOR) Logger.minor(this, "shouldSendHandshake(): final = "+tempShouldSendHandshake);
		return tempShouldSendHandshake;
	}
	
	public long timeSendHandshake(long now) {
		if(hasLiveHandshake(now)) return Long.MAX_VALUE;
		synchronized(this) {
			if(disconnecting) return Long.MAX_VALUE;
			if(handshakeIPs == null) return Long.MAX_VALUE;
			if(!(isRekeying || !isConnected())) return Long.MAX_VALUE;
			return sendHandshakeTime;
		}
	}

	/**
	* Does the node have a live handshake in progress?
	* @param now The current time.
	*/
	public boolean hasLiveHandshake(long now) {
		KeyAgreementSchemeContext c = null;
		synchronized(this) {
			c = ctx;
		}
		if(c != null && logDEBUG)
			Logger.minor(this, "Last used (handshake): " + (now - c.lastUsedTime()));
		return !((c == null) || (now - c.lastUsedTime() > Node.HANDSHAKE_TIMEOUT));
	}
	boolean firstHandshake = true;

	/**
	 * Set sendHandshakeTime, and return whether to fetch the ARK.
	 */
	protected boolean innerCalcNextHandshake(boolean successfulHandshakeSend, boolean dontFetchARK, long now) {
		if((!isConnected()) && isBurstOnly())
			return calcNextHandshakeBurstOnly(now);
		synchronized(this) {
			long delay;
			if(unroutableOlderVersion || unroutableNewerVersion || disableRouting) {
				// Let them know we're here, but have no hope of routing general data to them.
				delay = Node.MIN_TIME_BETWEEN_VERSION_SENDS + node.random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_VERSION_SENDS);
			} else if(invalidVersion() && !firstHandshake) {
				delay = Node.MIN_TIME_BETWEEN_VERSION_PROBES + node.random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_VERSION_PROBES);
			} else {
				delay = Node.MIN_TIME_BETWEEN_HANDSHAKE_SENDS + node.random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_HANDSHAKE_SENDS);
			}
			// FIXME proper multi-homing support!
			delay /= (handshakeIPs == null ? 1 : handshakeIPs.length);
			if(delay < 3000) delay = 3000;
			sendHandshakeTime = now + delay;
			if(logMINOR) Logger.minor(this, "Next handshake in "+delay+" on "+this);

			if(successfulHandshakeSend)
				firstHandshake = false;
			handshakeCount++;
			return handshakeCount == MAX_HANDSHAKE_COUNT;
		}
	}

	private synchronized boolean calcNextHandshakeBurstOnly(long now) {
		boolean fetchARKFlag = false;
		listeningHandshakeBurstCount++;
		if(isBurstOnly()) {
			if(listeningHandshakeBurstCount >= listeningHandshakeBurstSize) {
				listeningHandshakeBurstCount = 0;
				fetchARKFlag = true;
			}
		}
		long delay;
		if(listeningHandshakeBurstCount == 0) {  // 0 only if we just reset it above
			delay = Node.MIN_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS
				+ node.random.nextInt(Node.RANDOMIZED_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS);
			listeningHandshakeBurstSize = Node.MIN_BURSTING_HANDSHAKE_BURST_SIZE
					+ node.random.nextInt(Node.RANDOMIZED_BURSTING_HANDSHAKE_BURST_SIZE);
			isBursting = false;
		} else {
			delay = Node.MIN_TIME_BETWEEN_HANDSHAKE_SENDS
				+ node.random.nextInt((int) Node.RANDOMIZED_TIME_BETWEEN_HANDSHAKE_SENDS);
		}
		// FIXME proper multi-homing support!
		delay /= (handshakeIPs == null ? 1 : handshakeIPs.length);
		if(delay < 3000) delay = 3000;

		sendHandshakeTime = now + delay;
		if(logMINOR) Logger.minor(this, "Next BurstOnly mode handshake in "+(sendHandshakeTime - now)+"ms for "+shortToString()+" (count: "+listeningHandshakeBurstCount+", size: "+listeningHandshakeBurstSize+ ") on "+this, new Exception("double-called debug"));
		return fetchARKFlag;
	}

	protected void calcNextHandshake(boolean successfulHandshakeSend, boolean dontFetchARK, boolean notRegistered) {
		long now = System.currentTimeMillis();
		boolean fetchARKFlag = false;
		fetchARKFlag = innerCalcNextHandshake(successfulHandshakeSend, dontFetchARK, now);
		if(!notRegistered)
			setPeerNodeStatus(now);  // Because of isBursting being set above and it can't hurt others
		// Don't fetch ARKs for peers we have verified (through handshake) to be incompatible with us
		if(fetchARKFlag && !dontFetchARK) {
			long arkFetcherStartTime1 = System.currentTimeMillis();
			startARKFetcher();
			long arkFetcherStartTime2 = System.currentTimeMillis();
			if((arkFetcherStartTime2 - arkFetcherStartTime1) > 500)
				Logger.normal(this, "arkFetcherStartTime2 is more than half a second after arkFetcherStartTime1 (" + (arkFetcherStartTime2 - arkFetcherStartTime1) + ") working on " + shortToString());
		}
	}

	/** If the outgoingMangler allows bursting, we still don't want to burst *all the time*, because it may be mistaken
	 * in its detection of a port forward. So from time to time we will aggressively handshake anyway. This flag is set
	 * once every UPDATE_BURST_NOW_PERIOD. */
	private boolean burstNow;
	private long timeSetBurstNow;
	static final long UPDATE_BURST_NOW_PERIOD = MINUTES.toMillis(5);
	/** Burst only 19 in 20 times if definitely port forwarded. Save entropy by writing this as 20 not 0.95. */
	static final int P_BURST_IF_DEFINITELY_FORWARDED = 20;

	public boolean isBurstOnly() {
		AddressTracker.Status status = outgoingMangler.getConnectivityStatus();
		if(status == AddressTracker.Status.DONT_KNOW) return false;
		if(status == AddressTracker.Status.DEFINITELY_NATED || status == AddressTracker.Status.MAYBE_NATED) return false;

		// For now. FIXME try it with a lower probability when we're sure that the packet-deltas mechanisms works.
		if(status == AddressTracker.Status.MAYBE_PORT_FORWARDED) return false;
		long now = System.currentTimeMillis();
		if(now - timeSetBurstNow > UPDATE_BURST_NOW_PERIOD) {
			burstNow = (node.random.nextInt(P_BURST_IF_DEFINITELY_FORWARDED) == 0);
			timeSetBurstNow = now;
		}
		return burstNow;
	}

	/**
	* Call this method when a handshake request has been
	* sent.
	*/
	public void sentHandshake(boolean notRegistered) {
		if(logMINOR)
			Logger.minor(this, "sentHandshake(): " + this);
		calcNextHandshake(true, false, notRegistered);
	}

	/**
	* Call this method when a handshake request could not be sent (i.e. no IP address available)
	* sent.
	*/
	public void couldNotSendHandshake(boolean notRegistered) {
		if(logMINOR)
			Logger.minor(this, "couldNotSendHandshake(): " + this);
		calcNextHandshake(false, false, notRegistered);
	}

	/**
	* @return The maximum time between received packets.
	*/
	public long maxTimeBetweenReceivedPackets() {
		return Node.MAX_PEER_INACTIVITY;
	}

	/**
	* @return The maximum time between received packets.
	*/
	public long maxTimeBetweenReceivedAcks() {
		return Node.MAX_PEER_INACTIVITY;
	}

	/**
	* Low-level ping this node.
	* @return True if we received a reply inside 2000ms.
	* (If we have heavy packet loss, it can take that long to resend).
	*/
	public boolean ping(int pingID) throws NotConnectedException {
		Message ping = DMT.createFNPPing(pingID);
		node.usm.send(this, ping, node.dispatcher.pingCounter);
		Message msg;
		try {
			msg = node.usm.waitFor(MessageFilter.create().setTimeout(2000).setType(DMT.FNPPong).setField(DMT.PING_SEQNO, pingID), null);
		} catch(DisconnectedException e) {
			throw new NotConnectedException("Disconnected while waiting for pong");
		}
		return msg != null;
	}

	/**
	* Decrement the HTL (or not), in accordance with our
	* probabilistic HTL rules. Whether to decrement is determined once for
	* each connection, rather than for every request, because if we don't
	* we would get a predictable fraction of requests with each HTL - this
	* pattern could give away a lot of information close to the originator.
	* Although it's debatable whether it's worth worrying about given all
	* the other information they have if close by ...
	* @param htl The old HTL.
	* @return The new HTL.
	*/
	public short decrementHTL(short htl) {
		short max = node.maxHTL();
		if(htl > max)
			htl = max;
		if(htl <= 0)
			return 0;
		if(htl == max) {
			if(decrementHTLAtMaximum || node.disableProbabilisticHTLs)
				htl--;
			return htl;
		}
		if(htl == 1) {
			if(decrementHTLAtMinimum || node.disableProbabilisticHTLs)
				htl--;
			return htl;
		}
		htl--;
		return htl;
	}

	/**
	* Enqueue a message to be sent to this node and wait up to a minute for it to be transmitted
	* and acknowledged.
	*/
	public void sendSync(Message req, ByteCounter ctr, boolean realTime) throws NotConnectedException, SyncSendWaitedTooLongException {
		SyncMessageCallback cb = new SyncMessageCallback();
		MessageItem item = sendAsync(req, cb, ctr);
		cb.waitForSend(MINUTES.toMillis(1));
		if (!cb.done) {
			Logger.warning(this, "Waited too long for a blocking send for " + req + " to " + PeerNode.this, new Exception("error"));
			this.localRejectedOverload("SendSyncTimeout", realTime);
			// Try to unqueue it, since it presumably won't be of any use now.
			if(!messageQueue.removeMessage(item)) {
				cb.waitForSend(SECONDS.toMillis(10));
				if(!cb.done) {
					Logger.error(this, "Waited too long for blocking send and then could not unqueue for "+req+" to "+PeerNode.this, new Exception("error"));
					// Can't cancel yet can't send, something seriously wrong.
					// Treat as fatal timeout as probably their fault.
					// FIXME: We have already waited more than the no-messages timeout, but should we wait that period again???
					fatalTimeout();
					// Then throw the error.
				} else {
					return;
				}
			}
			throw new SyncSendWaitedTooLongException();
		}
	}

	private class SyncMessageCallback implements AsyncMessageCallback {

		private boolean done = false;
		private boolean disconnected = false;
		private boolean sent = false;

		public synchronized void waitForSend(long maxWaitInterval) throws NotConnectedException {
			long now = System.currentTimeMillis();
			long end = now + maxWaitInterval;
			while((now = System.currentTimeMillis()) < end) {
				if(done) {
					if(disconnected)
						throw new NotConnectedException();
					return;
				}
				int waitTime = (int) (Math.min(end - now, Integer.MAX_VALUE));
				try {
					wait(waitTime);
				} catch(InterruptedException e) {
				// Ignore
				}
			}
		}

		@Override
		public void acknowledged() {
			synchronized(this) {
				if(!done) {
					if (!sent) {
						// Can happen due to lag.
						Logger.normal(this, "Acknowledged but not sent?! on " + this + " for " + PeerNode.this+" - lag ???");
					}
				} else
					return;
				done = true;
				notifyAll();
			}
		}

		@Override
		public void disconnected() {
			synchronized(this) {
				done = true;
				disconnected = true;
				notifyAll();
			}
		}

		@Override
		public void fatalError() {
			synchronized(this) {
				done = true;
				notifyAll();
			}
		}

		@Override
		public void sent() {
			// It might have been lost, we wait until it is acked.
			synchronized(this) {
				sent = true;
			}
		}
	}

	/**
	 * Determines the degree of the peer via the locations of its peers it provides.
	 * @return The number of peers this peer reports having, or 0 if this peer does not provide that information.
	 */
	public int getDegree() {
		return location.getDegree();
	}

	public void updateLocation(double newLoc, double[] newLocs) {
		boolean anythingChanged = location.updateLocation(newLoc, newLocs);
		node.peers.updatePMUserAlert();
		if(anythingChanged)
			// Not urgent. This makes up the majority of the total writes.
			// Writing it on shutdown is sufficient.
			node.peers.writePeers(isOpennet());
		synchronized(this) {
		    if(!isConnected()) return; // Race condition.
	        setPeerNodeStatus(System.currentTimeMillis());
		}
	}

	/**
	* Should we reject a swap request?
	*/
	public boolean shouldRejectSwapRequest() {
		long now = System.currentTimeMillis();
		synchronized(this) {
			if(timeLastReceivedSwapRequest > 0) {
				long timeSinceLastTime = now - timeLastReceivedSwapRequest;
				swapRequestsInterval.report(timeSinceLastTime);
				double averageInterval = swapRequestsInterval.currentValue();
				if(averageInterval >= Node.MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS) {
					timeLastReceivedSwapRequest = now;
					return false;
				} else return true;
			}
			timeLastReceivedSwapRequest = now;
		}
		return false;
	}

	/**
	* Should we reject a swap request?
	*/
	public boolean shouldRejectProbeRequest() {
		long now = System.currentTimeMillis();
		synchronized(this) {
			if(timeLastReceivedProbeRequest > 0) {
				long timeSinceLastTime = now - timeLastReceivedProbeRequest;
				probeRequestsInterval.report(timeSinceLastTime);
				double averageInterval = probeRequestsInterval.currentValue();
				if(averageInterval >= Node.MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS) {
					timeLastReceivedProbeRequest = now;
					return false;
				} else return true;
			}
			timeLastReceivedProbeRequest = now;
		}
		return false;
	}

	/**
	* IP on the other side appears to have changed...
	* @param newPeer The new address of the peer.
	*/
	public void changedIP(Peer newPeer) {
		setDetectedPeer(newPeer);
	}

	private void setDetectedPeer(Peer newPeer) {
		// Also, we need to call .equals() to propagate any DNS lookups that have been done if the two have the same domain.
		Peer p = newPeer;
		newPeer = newPeer.dropHostName();
		if(newPeer == null) {
			Logger.error(this, "Impossible: No address for detected peer! "+p+" on "+this);
			return;
		}
		synchronized(this) {
			Peer oldPeer = detectedPeer;
			if((newPeer != null) && ((oldPeer == null) || !oldPeer.equals(newPeer))) {
				this.detectedPeer = newPeer;
				updateShortToString();
				// IP has changed, it is worth looking up the DNS address again.
				this.lastAttemptedHandshakeIPUpdateTime = 0;
				if(!isConnected())
					return;
			} else
				return;
		}
		getThrottle().maybeDisconnected();
		sendIPAddressMessage();
	}

	/**
	* @return The current primary SessionKey, or null if we
	* don't have one.
	*/
	@Override
	public synchronized SessionKey getCurrentKeyTracker() {
		return currentTracker;
	}

	/**
	* @return The previous primary SessionKey, or null if we
	* don't have one.
	*/
	@Override
	public synchronized SessionKey getPreviousKeyTracker() {
		return previousTracker;
	}

	/**
	* @return The unverified SessionKey, if any, or null if we
	* don't have one. The caller MUST call verified(KT) if a
	* decrypt succeeds with this KT.
	*/
	@Override
	public synchronized SessionKey getUnverifiedKeyTracker() {
		return unverifiedTracker;
	}

	private String shortToString;
	private void updateShortToString() {
		shortToString = super.toString() + '@' + detectedPeer + '@' + HexUtil.bytesToHex(pubKeyHash);
	}

	/**
	* @return short version of toString()
	* *** Note that this is not synchronized! It is used by logging in code paths that
	* will deadlock if it is synchronized! ***
	*/
	@Override
	public String shortToString() {
		return shortToString;
	}

	@Override
	public String toString() {
		// FIXME?
		return shortToString()+'@'+Integer.toHexString(super.hashCode());
	}

	/**
	* Update timeLastReceivedPacket
	* @throws NotConnectedException
	* @param dontLog If true, don't log an error or throw an exception if we are not connected. This
	* can be used in handshaking when the connection hasn't been verified yet.
	* @param dataPacket If this is a real packet, as opposed to a handshake packet.
	*/
	@Override
	public void receivedPacket(boolean dontLog, boolean dataPacket) {
		synchronized(this) {
			if((!isConnected()) && (!dontLog)) {
				// Don't log if we are disconnecting, because receiving packets during disconnecting is normal.
				// That includes receiving packets after we have technically disconnected already.
				// A race condition involving forceCancelDisconnecting causing a mistaken log message anyway
				// is conceivable, but unlikely...
				if((unverifiedTracker == null) && (currentTracker == null) && !disconnecting)
					Logger.error(this, "Received packet while disconnected!: " + this, new Exception("error"));
				else
					if(logMINOR)
						Logger.minor(this, "Received packet while disconnected on " + this + " - recently disconnected() ?");
			} else {
				if(logMINOR) Logger.minor(this, "Received packet on "+this);
			}
		}
		long now = System.currentTimeMillis();
		synchronized(this) {
			timeLastReceivedPacket = now;
			if(dataPacket)
				timeLastReceivedDataPacket = now;
		}
	}
	
	@Override
	public synchronized void receivedAck(long now) {
		if(timeLastReceivedAck < now)
			timeLastReceivedAck = now;
	}

	/**
	* Update timeLastSentPacket
	*/
	@Override
	public void sentPacket() {
		timeLastSentPacket = System.currentTimeMillis();
	}

	public synchronized KeyAgreementSchemeContext getKeyAgreementSchemeContext() {
		return ctx;
	}

	public synchronized void setKeyAgreementSchemeContext(KeyAgreementSchemeContext ctx2) {
		this.ctx = ctx2;
		if(logMINOR)
			Logger.minor(this, "setKeyAgreementSchemeContext(" + ctx2 + ") on " + this);
	}

	/**
	* Called when we have completed a handshake, and have a new session key.
	* Creates a new tracker and demotes the old one. Deletes the old one if
	* the bootID isn't recognized, since if the node has restarted we cannot
	* recover old messages. In more detail:
	* <ul>
	* <li>Process the new noderef (check if it's valid, pick up any new information etc).</li>
	* <li>Handle version conflicts (if the node is too old, or we are too old, we mark it as
	* non-routable, but some messages will still be exchanged e.g. Update Over Mandatory stuff).</li>
	* <li>Deal with key trackers (if we just got message 4, the new key tracker becomes current;
	* if we just got message 3, it's possible that our message 4 will be lost in transit, so we
	* make the new tracker unverified. It will be promoted to current if we get a packet on it..
	* if the node has restarted, we dump the old key trackers, otherwise current becomes previous).</li>
	* <li>Complete the connection process: update the node's status, send initial messages, update
	* the last-received-packet timestamp, etc.</li>
	* @param thisBootID The boot ID of the peer we have just connected to.
	* This is simply a random number regenerated on every startup of the node.
	* We use it to determine whether the node has restarted since we last saw
	* it.
	* @param data Byte array from which to read the new noderef.
	* @param offset Offset to start reading at.
	* @param length Number of bytes to read.
	* @param encKey The new session key.
	* @param replyTo The IP the handshake came in on.
	* @param trackerID The tracker ID proposed by the other side. If -1, create a new tracker. If any
	* other value, check whether we have it, and if we do, return that, otherwise return the ID of the
	* new tracker.
	* @param isJFK4 If true, we are processing a JFK(4) and must respect the tracker ID chosen by the
	* responder. If false, we are processing a JFK(3) and we can either reuse the suggested tracker ID,
	* which the other side is able to reuse, or we can create a new tracker ID.
	* @param jfk4SameAsOld If true, the responder chose to use the tracker ID that we provided. If
	* we don't have it now the connection fails.
	* @return The ID of the new PacketTracker. If this is different to the passed-in trackerID, then
	* it's a new tracker. -1 to indicate failure.
	*/
	public long completedHandshake(long thisBootID, byte[] data, int offset, int length, BlockCipher outgoingCipher, byte[] outgoingKey, BlockCipher incommingCipher, byte[] incommingKey, Peer replyTo, boolean unverified, int negType, long trackerID, boolean isJFK4, boolean jfk4SameAsOld, byte[] hmacKey, BlockCipher ivCipher, byte[] ivNonce, int ourInitialSeqNum, int theirInitialSeqNum, int ourInitialMsgID, int theirInitialMsgID) {
		long now = System.currentTimeMillis();
		if(logMINOR) Logger.minor(this, "Tracker ID "+trackerID+" isJFK4="+isJFK4+" jfk4SameAsOld="+jfk4SameAsOld);
		if(trackerID < 0) trackerID = Math.abs(node.random.nextLong());

		// Update sendHandshakeTime; don't send another handshake for a while.
		// If unverified, "a while" determines the timeout; if not, it's just good practice to avoid a race below.
		if(!(isSeed() && this instanceof SeedServerPeerNode))
                    calcNextHandshake(true, true, false);
		stopARKFetcher();
		try {
			// First, the new noderef
			processNewNoderef(data, offset, length);
		} catch(FSParseException e1) {
			synchronized(this) {
				bogusNoderef = true;
				// Disconnect, something broke
				isConnected.set(false, now);
			}
			Logger.error(this, "Failed to parse new noderef for " + this + ": " + e1, e1);
			node.peers.disconnected(this);
			return -1;
		}
		boolean routable = true;
		boolean newer = false;
		boolean older = false;
		if(isSeed()) {
                        routable = false;
                        if(logMINOR) Logger.minor(this, "Not routing traffic to " + this + " it's for announcement.");
                } else if(bogusNoderef) {
			Logger.normal(this, "Not routing traffic to " + this + " - bogus noderef");
			routable = false;
			//FIXME: It looks like bogusNoderef will just be set to false a few lines later...
		} else if(reverseInvalidVersion()) {
			Logger.normal(this, "Not routing traffic to " + this + " - reverse invalid version " + Version.getVersionString() + " for peer's lastGoodversion: " + getLastGoodVersion());
			newer = true;
		} else
			newer = false;
		if(forwardInvalidVersion()) {
			Logger.normal(this, "Not routing traffic to " + this + " - invalid version " + getVersion());
			older = true;
			routable = false;
		} else if(Math.abs(clockDelta) > MAX_CLOCK_DELTA) {
			Logger.normal(this, "Not routing traffic to " + this + " - clock problems");
			routable = false;
		} else
			older = false;
		changedIP(replyTo);
		boolean bootIDChanged = false;
		boolean wasARekey = false;
		SessionKey oldPrev = null;
		SessionKey oldCur = null;
		SessionKey newTracker;
		MessageItem[] messagesTellDisconnected = null;
		PacketFormat oldPacketFormat = null;
		synchronized(this) {
			disconnecting = false;
			// FIXME this shouldn't happen, does it?
			if(currentTracker != null) {
				if(Arrays.equals(outgoingKey, currentTracker.outgoingKey)
						&& Arrays.equals(incommingKey, currentTracker.incommingKey)) {
					Logger.error(this, "completedHandshake() with identical key to current, maybe replayed JFK(4)?");
					return -1;
				}
			}
			if(previousTracker != null) {
				if(Arrays.equals(outgoingKey, previousTracker.outgoingKey)
						&& Arrays.equals(incommingKey, previousTracker.incommingKey)) {
					Logger.error(this, "completedHandshake() with identical key to previous, maybe replayed JFK(4)?");
					return -1;
				}
			}
			if(unverifiedTracker != null) {
				if(Arrays.equals(outgoingKey, unverifiedTracker.outgoingKey)
						&& Arrays.equals(incommingKey, unverifiedTracker.incommingKey)) {
					Logger.error(this, "completedHandshake() with identical key to unverified, maybe replayed JFK(4)?");
					return -1;
				}
			}
			handshakeCount = 0;
			bogusNoderef = false;
			// Don't reset the uptime if we rekey
			if(!isConnected()) {
				connectedTime = now;
				countSelectionsSinceConnected = 0;
				sentInitialMessages = false;
			} else
				wasARekey = true;
			disableRouting = disableRoutingHasBeenSetLocally || disableRoutingHasBeenSetRemotely;
			isRoutable = routable;
			unroutableNewerVersion = newer;
			unroutableOlderVersion = older;
			boolean notReusingTracker = false;
			long oldBootID;
			oldBootID = bootID.getAndSet(thisBootID);
			bootIDChanged = oldBootID != thisBootID;
			if(myLastSuccessfulBootID != this.myBootID) {
				// If our own boot ID changed, because we forcibly disconnected, 
				// we need to use a new tracker. This is equivalent to us having restarted,
				// from the point of view of the other side, but since we haven't we need
				// to track it here.
				bootIDChanged = true;
				myLastSuccessfulBootID = myBootID;
			}
			if(bootIDChanged && wasARekey) {
				// This can happen if the other side thought we disconnected but we didn't think they did.
				Logger.normal(this, "Changed boot ID while rekeying! from " + oldBootID + " to " + thisBootID + " for " + getPeer());
				wasARekey = false;
				connectedTime = now;
				countSelectionsSinceConnected = 0;
				sentInitialMessages = false;
			} else if(bootIDChanged && logMINOR)
				Logger.minor(this, "Changed boot ID from " + oldBootID + " to " + thisBootID + " for " + getPeer());
			if(bootIDChanged) {
				oldPrev = previousTracker;
				oldCur = currentTracker;
				previousTracker = null;
				currentTracker = null;
				// Messages do not persist across restarts.
				// Generally they would be incomprehensible, anything that isn't should be sent as
				// connection initial messages by maybeOnConnect().
				messagesTellDisconnected = grabQueuedMessageItems();
				this.offeredMainJarVersion = 0;
				oldPacketFormat = packetFormat;
				packetFormat = null;
			} else {
				// else it's a rekey
			}
			newTracker = new SessionKey(this, outgoingCipher, outgoingKey, incommingCipher, incommingKey, ivCipher, ivNonce, hmacKey, new NewPacketFormatKeyContext(ourInitialSeqNum, theirInitialSeqNum), trackerID);
			if(logMINOR) Logger.minor(this, "New key tracker in completedHandshake: "+newTracker+" for "+shortToString()+" neg type "+negType);
			if(unverified) {
				if(unverifiedTracker != null) {
					// Keep the old unverified tracker if possible.
					if(previousTracker == null)
						previousTracker = unverifiedTracker;
				}
				unverifiedTracker = newTracker;
			} else {
				oldPrev = previousTracker;
				previousTracker = currentTracker;
				currentTracker = newTracker;
				// Keep the old unverified tracker.
				// In case of a race condition (two setups between A and B complete at the same time),
				// we might want to keep the unverified tracker rather than the previous tracker.
				neverConnected = false;
				maybeClearPeerAddedTimeOnConnect();
			}
			isConnected.set(currentTracker != null, now);
			ctx = null;
			isRekeying = false;
			timeLastRekeyed = now - (unverified ? 0 : FNPPacketMangler.MAX_SESSION_KEY_REKEYING_DELAY / 2);
			totalBytesExchangedWithCurrentTracker = 0;
			// This has happened in the past, and caused problems, check for it.
			if(currentTracker != null && previousTracker != null &&
					Arrays.equals(currentTracker.outgoingKey, previousTracker.outgoingKey) &&
					Arrays.equals(currentTracker.incommingKey, previousTracker.incommingKey))
				Logger.error(this, "currentTracker key equals previousTracker key: cur "+currentTracker+" prev "+previousTracker);
			if(previousTracker != null && unverifiedTracker != null &&
					Arrays.equals(previousTracker.outgoingKey, unverifiedTracker.outgoingKey) &&
					Arrays.equals(previousTracker.incommingKey, unverifiedTracker.incommingKey))
				Logger.error(this, "previousTracker key equals unverifiedTracker key: prev "+previousTracker+" unv "+unverifiedTracker);
			timeLastSentPacket = now;
			if(packetFormat == null) {
				packetFormat = new NewPacketFormat(this, ourInitialMsgID, theirInitialMsgID);
			}
			// Completed setup counts as received data packet, for purposes of avoiding spurious disconnections.
			timeLastReceivedPacket = now;
			timeLastReceivedDataPacket = now;
			timeLastReceivedAck = now;
		}
		if(messagesTellDisconnected != null) {
			for(MessageItem item: messagesTellDisconnected) {
				item.onDisconnect();
			}
		}

		if(bootIDChanged) {
			node.lm.lostOrRestartedNode(this);
			node.usm.onRestart(this);
			node.tracker.onRestartOrDisconnect(this);
		}
		if(oldPrev != null) oldPrev.disconnected();
		if(oldCur != null) oldCur.disconnected();
		if(oldPacketFormat != null) {
			List<MessageItem> tellDisconnect = oldPacketFormat.onDisconnect();
			if(tellDisconnect != null)
				for(MessageItem item : tellDisconnect) {
					item.onDisconnect();
				}
		}
		PacketThrottle throttle;
		synchronized(this) {
			throttle = _lastThrottle;
		}
		if(throttle != null) throttle.maybeDisconnected();
		Logger.normal(this, "Completed handshake with " + this + " on " + replyTo + " - current: " + currentTracker +
			" old: " + previousTracker + " unverified: " + unverifiedTracker + " bootID: " + thisBootID + (bootIDChanged ? "(changed) " : "") + " for " + shortToString());

		setPeerNodeStatus(now);

		if(newer || older || !isConnected())
			node.peers.disconnected(this);
		else if(!wasARekey) {
			node.peers.addConnectedPeer(this);
			maybeOnConnect();
		}
		
		crypto.maybeBootConnection(this, replyTo.getFreenetAddress());

		return trackerID;
	}

	protected abstract void maybeClearPeerAddedTimeOnConnect();

	@Override
	public long getBootID() {
		return bootID.get();
	}
	private final Object arkFetcherSync = new Object();

	void startARKFetcher() {
		// FIXME any way to reduce locking here?
		if(!node.enableARKs) return;
		synchronized(arkFetcherSync) {
			if(myARK == null) {
				Logger.minor(this, "No ARK for " + this + " !!!!");
				return;
			}
			if(arkFetcher == null) {
				Logger.minor(this, "Starting ARK fetcher for " + this + " : " + myARK);
				arkFetcher = node.clientCore.uskManager.subscribeContent(myARK, this, true, node.arkFetcherContext, RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, node.nonPersistentClientRT);
			}
		}
	}

	protected void stopARKFetcher() {
		if(!node.enableARKs) return;
		Logger.minor(this, "Stopping ARK fetcher for " + this + " : " + myARK);
		// FIXME any way to reduce locking here?
		USKRetriever ret;
		synchronized(arkFetcherSync) {
			if(arkFetcher == null) {
				if(logMINOR) Logger.minor(this, "ARK fetcher not running for "+this);
				return;
			}
			ret = arkFetcher;
			arkFetcher = null;
		}
		final USKRetriever unsub = ret;
		node.executor.execute(new Runnable() {

			@Override
			public void run() {
				node.clientCore.uskManager.unsubscribeContent(myARK, unsub, true);
			}
			
		});
	}


	// Both at IMMEDIATE_SPLITFILE_PRIORITY_CLASS because we want to compete with FMS, not
	// wipe it out!

	@Override
	public short getPollingPriorityNormal() {
		return RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
	}

	@Override
	public short getPollingPriorityProgress() {
		return RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
	}

	boolean sentInitialMessages;

	void maybeSendInitialMessages() {
		synchronized(this) {
			if(sentInitialMessages)
				return;
			if(currentTracker != null)
				sentInitialMessages = true;
			else
				return;
		}

		sendInitialMessages();
	}

	/**
	* Send any high level messages that need to be sent on connect.
	*/
	protected void sendInitialMessages() {
		loadSender(true).setSendASAP();
		loadSender(false).setSendASAP();
		Message locMsg = DMT.createFNPLocChangeNotificationNew(node.lm.getLocation(), node.peers.getPeerLocationDoubles(true));
		Message ipMsg = DMT.createFNPDetectedIPAddress(detectedPeer);
		Message timeMsg = DMT.createFNPTime(System.currentTimeMillis());
		Message dRoutingMsg = DMT.createRoutingStatus(!disableRoutingHasBeenSetLocally);
		Message uptimeMsg = DMT.createFNPUptime((byte)(int)(100*node.uptime.getUptime()));

		try {
			if(isRealConnection())
				sendAsync(locMsg, null, node.nodeStats.initialMessagesCtr);
			sendAsync(ipMsg, null, node.nodeStats.initialMessagesCtr);
			sendAsync(timeMsg, null, node.nodeStats.initialMessagesCtr);
			sendAsync(dRoutingMsg, null, node.nodeStats.initialMessagesCtr);
			sendAsync(uptimeMsg, null, node.nodeStats.initialMessagesCtr);
		} catch(NotConnectedException e) {
			Logger.error(this, "Completed handshake with " + getPeer() + " but disconnected (" + isConnected + ':' + currentTracker + "!!!: " + e, e);
		}

		if(isRealConnection())
			node.nodeUpdater.maybeSendUOMAnnounce(this);
		sendConnectedDiffNoderef();
	}

	private void sendIPAddressMessage() {
		Message ipMsg = DMT.createFNPDetectedIPAddress(detectedPeer);
		try {
			sendAsync(ipMsg, null, node.nodeStats.changedIPCtr);
		} catch(NotConnectedException e) {
			Logger.normal(this, "Sending IP change message to " + this + " but disconnected: " + e, e);
		}
	}

	/**
	* Called when a packet is successfully decrypted on a given
	* SessionKey for this node. Will promote the unverifiedTracker
	* if necessary.
	*/
	@Override
	public void verified(SessionKey tracker) {
		long now = System.currentTimeMillis();
		SessionKey completelyDeprecatedTracker;
		synchronized(this) {
			if(tracker == unverifiedTracker) {
				if(logMINOR)
					Logger.minor(this, "Promoting unverified tracker " + tracker + " for " + getPeer());
				completelyDeprecatedTracker = previousTracker;
				previousTracker = currentTracker;
				currentTracker = unverifiedTracker;
				unverifiedTracker = null;
				isConnected.set(true, now);
				neverConnected = false;
				maybeClearPeerAddedTimeOnConnect();
				ctx = null;
			} else
				return;
		}
		maybeSendInitialMessages();
		setPeerNodeStatus(now);
		node.peers.addConnectedPeer(this);
		maybeOnConnect();
		if(completelyDeprecatedTracker != null) {
			completelyDeprecatedTracker.disconnected();
		}
	}

	private synchronized boolean invalidVersion() {
		return bogusNoderef || forwardInvalidVersion() || reverseInvalidVersion();
	}

	private synchronized boolean forwardInvalidVersion() {
		return !Version.checkGoodVersion(version);
	}

	private synchronized boolean reverseInvalidVersion() {
		if(ignoreLastGoodVersion()) return false;
		return !Version.checkArbitraryGoodVersion(Version.getVersionString(), lastGoodVersion);
	}

	/**
	 * The same as isUnroutableOlderVersion, but not synchronized.
	 */
	public boolean publicInvalidVersion() {
		return unroutableOlderVersion;
	}

	/**
	 * The same as inUnroutableNewerVersion.
	 */
	public synchronized boolean publicReverseInvalidVersion() {
		return unroutableNewerVersion;
	}

	public synchronized boolean dontRoute() {
		return disableRouting;
	}

	/**
	* Process a differential node reference
	* The identity must not change, or we throw.
	*/
	public void processDiffNoderef(SimpleFieldSet fs) throws FSParseException {
		processNewNoderef(fs, false, true, false);
	}

	/**
	* Process a new nodereference, in compressed form.
	* The identity must not change, or we throw.
	*/
	private void processNewNoderef(byte[] data, int offset, int length) throws FSParseException {
		SimpleFieldSet fs = compressedNoderefToFieldSet(data, offset, length);
		processNewNoderef(fs, false, false, false);
	}

	static SimpleFieldSet compressedNoderefToFieldSet(byte[] data, int offset, int length) throws FSParseException {
		if(length <= 5)
			throw new FSParseException("Too short");
		// Lookup table for groups.
		DSAGroup group = null;
		int firstByte = data[offset];
		offset++;
		length--;
		if((firstByte & 0x2) == 2) {
			int groupIndex = (data[offset] & 0xff);
			offset++;
			length--;
			group = Global.getGroup(groupIndex);
			if(group == null) throw new FSParseException("Unknown group number "+groupIndex);
			if(logMINOR)
				Logger.minor(PeerNode.class, "DSAGroup set to "+group.fingerprintToString()+ " using the group-index "+groupIndex);
		}
		// Is it compressed?
		if((firstByte & 1) == 1) {
			try {
				// Gzipped
				Inflater i = new Inflater();
				i.setInput(data, offset, length);
				// We shouldn't ever need a 4096 bytes long ref!
				byte[] output = new byte[4096];
				length = i.inflate(output, 0, output.length);
				// Finished
				data = output;
				offset = 0;
				if(logMINOR)
					Logger.minor(PeerNode.class, "We have decompressed a "+length+" bytes big reference.");
			} catch(DataFormatException e) {
				throw new FSParseException("Invalid compressed data");
			}
		}
		if(logMINOR)
			Logger.minor(PeerNode.class, "Reference: " + HexUtil.bytesToHex(data, offset, length) + '(' + length + ')');

		// Now decode it
		ByteArrayInputStream bais = new ByteArrayInputStream(data, offset, length);
		InputStreamReader isr;
		try {
			isr = new InputStreamReader(bais, "UTF-8");
		} catch(UnsupportedEncodingException e1) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e1, e1);
		}
		BufferedReader br = new BufferedReader(isr);
		try {
			SimpleFieldSet fs = new SimpleFieldSet(br, false, true);
			if(group != null) {
				SimpleFieldSet sfs = new SimpleFieldSet(true);
				sfs.put("dsaGroup", group.asFieldSet());
				fs.putAllOverwrite(sfs);
			}
			return fs;
		} catch(IOException e) {
			throw (FSParseException)new FSParseException("Impossible: " + e).initCause(e);
		}
	}

	/**
	* Process a new nodereference, as a SimpleFieldSet.
	*/
	protected void processNewNoderef(SimpleFieldSet fs, boolean forARK, boolean forDiffNodeRef, boolean forFullNodeRef) throws FSParseException {
		if(logMINOR)
			Logger.minor(this, "Parsing: \n" + fs);
		boolean changedAnything = innerProcessNewNoderef(fs, forARK, forDiffNodeRef, forFullNodeRef) || forARK;
		if(changedAnything && !isSeed())
			node.peers.writePeers(isOpennet());
		// FIXME should this be urgent if IPs change? Dunno.
	}

	/**
	* The synchronized part of processNewNoderef
	* @throws FSParseException
	*/
	protected synchronized boolean innerProcessNewNoderef(SimpleFieldSet fs, boolean forARK, boolean forDiffNodeRef, boolean forFullNodeRef) throws FSParseException {
		
		boolean shouldUpdatePeerCounts = false;
		
		if(forFullNodeRef) {
		    // Check the signature.
			try {
				if(!verifyReferenceSignature(fs))
	                throw new FSParseException("Invalid signature");
			} catch (ReferenceSignatureVerificationException e) {
                throw new FSParseException("Invalid signature");
            }
		}
		
		// Anything may be omitted for a differential node reference
		boolean changedAnything = false;
		if(!forDiffNodeRef && (false != fs.getBoolean("testnet", false))) {
			String err = "Preventing connection to node " + detectedPeer +" - testnet is enabled!";
			Logger.error(this, err);
			throw new FSParseException(err);
		}
		String s = fs.get("opennet");
		if(s == null && forFullNodeRef)
			throw new FSParseException("No opennet ref");
		else if(s != null) {
			try {
				boolean b = Fields.stringToBool(s);
				if(b != (isOpennet() || isSeed()))
					throw new FSParseException("Changed opennet status?!?!?!? expected="+isOpennet()+" but got "+b+" ("+s+") on "+this);
			} catch (NumberFormatException e) {
				throw new FSParseException("Cannot parse opennet=\""+s+"\"", e);
			}
		}
		if(!generateIdentityFromPubkey()) {
			String identityString = fs.get("identity");
			if(identityString == null && forFullNodeRef)
				throw new FSParseException("No identity!");
			else if(identityString != null) {
				try {
					byte[] id = Base64.decode(identityString);
					if(!Arrays.equals(id, identity))
						throw new FSParseException("Changing the identity");
				} catch(NumberFormatException e) {
					throw new FSParseException(e);
				} catch(IllegalBase64Exception e) {
					throw new FSParseException(e);
				}
			}
		}
		
		SimpleFieldSet sfs = fs.subset("dsaGroup");
		if(sfs != null) {
			DSAGroup cmp;
			try {
				cmp = DSAGroup.create(sfs);
			} catch (IllegalBase64Exception e) {
				throw new FSParseException(e);
			}
			if(!cmp.equals(this.peerCryptoGroup))
				throw new FSParseException("Changed DSA group?!");
		}

		sfs = fs.subset("dsaPubKey");
		if(sfs != null) {
			DSAPublicKey key;
			key = DSAPublicKey.create(sfs, peerCryptoGroup);
			if(!key.equals(this.peerPubKey))
				throw new FSParseException("Changed pubkey?!");
		}

		String newVersion = fs.get("version");
		if(newVersion == null) {
			// Version may be ommitted for an ARK.
			if(!forARK && !forDiffNodeRef)
				throw new FSParseException("No version");
		} else {
			if(!newVersion.equals(version))
				changedAnything = true;
			version = newVersion;
			if(version != null) {
				try {
					simpleVersion = Version.getArbitraryBuildNumber(version);
				} catch (VersionParseException e) {
					Logger.error(this, "Bad version: " + version + " : " + e, e);
				}
			}
			Version.seenVersion(newVersion);
		}
		String newLastGoodVersion = fs.get("lastGoodVersion");
		if(newLastGoodVersion != null) {
			// Can be null if anon auth or if forDiffNodeRef.
			lastGoodVersion = newLastGoodVersion;
		} else if(forFullNodeRef)
			throw new FSParseException("No lastGoodVersion");

		updateVersionRoutablity();

		String locationString = fs.get("location");
		if(locationString != null) {
			double newLoc = Location.getLocation(locationString);
			if (!Location.isValid(newLoc)) {
				if(logMINOR)
					Logger.minor(this, "Invalid or null location, waiting for FNPLocChangeNotification: locationString=" + locationString);
			} else {
				double oldLoc = location.setLocation(newLoc);
				if(!Location.equals(oldLoc, newLoc)) {
					if(!Location.isValid(oldLoc))
						shouldUpdatePeerCounts = true;
					changedAnything = true;
				}
			}
		}
		try {
			String physical[] = fs.getAll("physical.udp");
			if(physical != null) {
				List<Peer> oldNominalPeer = nominalPeer;

				nominalPeer = new ArrayList<Peer>(physical.length);

				Peer[] oldPeers = oldNominalPeer.toArray(new Peer[oldNominalPeer.size()]);

				for(String phys: physical) {
					Peer p;
					try {
						p = new Peer(phys, true, true);
					} catch(HostnameSyntaxException e) {
						Logger.error(this, "Invalid hostname or IP Address syntax error while parsing new peer reference: " + phys);
						continue;
					} catch (PeerParseException e) {
						Logger.error(this, "Invalid hostname or IP Address syntax error while parsing new peer reference: " + phys);
						continue;
					} catch (UnknownHostException e) {
						// Should be impossible???
						Logger.error(this, "Invalid hostname or IP Address syntax error while parsing new peer reference: " + phys);
						continue;
					}
					if(!nominalPeer.contains(p)) {
						if(oldNominalPeer.contains(p)) {
							// Do nothing
							// .contains() will .equals() on each, and equals() will propagate the looked-up IP if necessary.
							// This is obviously O(n^2), but it doesn't matter, there will be very few peers.
						}
						nominalPeer.add(p);
					}
				}
				// XXX should we trigger changedAnything on *any* change, or on just *addition* of new addresses
				if(!Arrays.equals(oldPeers, nominalPeer.toArray(new Peer[nominalPeer.size()]))) {
					changedAnything = true;
					if(logMINOR) Logger.minor(this, "Got new physical.udp for "+this+" : "+Arrays.toString(nominalPeer.toArray()));
					// Look up the DNS names if any ASAP
					lastAttemptedHandshakeIPUpdateTime = 0;
					// Clear nonces to prevent leak. Will kill any in-progress connect attempts, but that is okay because
					// either we got an ARK which changed our peers list, or we just connected.
					jfkNoncesSent.clear();
				}

			} else if(forARK || forFullNodeRef) {
				// Connection setup doesn't include a physical.udp.
				// Differential noderefs only include it on the first one after connect.
				Logger.error(this, "ARK noderef has no physical.udp for "+this+" : forDiffNodeRef="+forDiffNodeRef+" forARK="+forARK);
				if(forFullNodeRef)
					throw new FSParseException("ARK noderef has no physical.udp");
			}
		} catch(Exception e1) {
			Logger.error(this, "Caught "+e1, e1);
			throw new FSParseException(e1);
		}

		if(logMINOR)
			Logger.minor(this, "Parsed successfully; changedAnything = " + changedAnything);

		int[] newNegTypes = fs.getIntArray("auth.negTypes");

		boolean refHadNegTypes = false;

		if(newNegTypes == null || newNegTypes.length == 0) {
			newNegTypes = new int[]{0};
		} else {
			refHadNegTypes = true;
		}
		if(!forDiffNodeRef || refHadNegTypes) {
			if(!Arrays.equals(negTypes, newNegTypes)) {
				changedAnything = true;
				negTypes = newNegTypes;
			}
		}
		changedAnything |= parseECDSA(fs, false, false);

		if(parseARK(fs, false, forDiffNodeRef))
			changedAnything = true;
		if(shouldUpdatePeerCounts) {
			node.executor.execute(new Runnable() {

				@Override
				public void run() {
					node.peers.updatePMUserAlert();
				}
				
			});

		}
		return changedAnything;
	}

	/**
	 * Get a PeerNodeStatus for this node.
	 * @param noHeavy If true, avoid any expensive operations e.g. the message count hashtables.
	 */
	public abstract PeerNodeStatus getStatus(boolean noHeavy);

	public String getTMCIPeerInfo() {
		long now = System.currentTimeMillis();
		int idle = -1;
		synchronized(this) {
			idle = (int) ((now - timeLastReceivedPacket) / 1000);
		}
		if((getPeerNodeStatus() == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED) && (getPeerAddedTime() > 1))
			idle = (int) ((now - getPeerAddedTime()) / 1000);
		return String.valueOf(getPeer()) + '\t' + getIdentityString() + '\t' + getLocation() + '\t' + getPeerNodeStatusString() + '\t' + idle;
	}

	public synchronized String getVersion() {
		return version;
	}

	private synchronized String getLastGoodVersion() {
		return lastGoodVersion;
	}

	private int simpleVersion;

	public int getSimpleVersion() {
		return simpleVersion;
	}

	/**
	* Write the peer's noderef to disk
	*/
	public void write(Writer w) throws IOException {
		SimpleFieldSet fs = exportFieldSet();
		SimpleFieldSet meta = exportMetadataFieldSet(System.currentTimeMillis());
		if(!meta.isEmpty())
			fs.put("metadata", meta);
		fs.writeTo(w);
	}

	/**
	 * (both metadata + normal fieldset but atomically)
	 */
	public synchronized SimpleFieldSet exportDiskFieldSet() {
		SimpleFieldSet fs = exportFieldSet();
		SimpleFieldSet meta = exportMetadataFieldSet(System.currentTimeMillis());
		if(!meta.isEmpty())
			fs.put("metadata", meta);
		if(fullFieldSet != null)
			fs.put("full", fullFieldSet);
		return fs;
	}

	/**
	* Export metadata about the node as a SimpleFieldSet
	*/
	public synchronized SimpleFieldSet exportMetadataFieldSet(long now) {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		if(detectedPeer != null)
			fs.putSingle("detected.udp", detectedPeer.toStringPrefNumeric());
		if(lastReceivedPacketTime() > 0)
			fs.put("timeLastReceivedPacket", timeLastReceivedPacket);
		if(lastReceivedAckTime() > 0)
			fs.put("timeLastReceivedAck", timeLastReceivedAck);
		long timeLastConnected = isConnected.getTimeLastTrue(now);
		if(timeLastConnected > 0)
			fs.put("timeLastConnected", timeLastConnected);
		if(timeLastRoutable() > 0)
			fs.put("timeLastRoutable", timeLastRoutable);
		if(getPeerAddedTime() > 0 && shouldExportPeerAddedTime())
			fs.put("peerAddedTime", peerAddedTime);
		if(neverConnected)
			fs.putSingle("neverConnected", "true");
		if(hadRoutableConnectionCount > 0)
			fs.put("hadRoutableConnectionCount", hadRoutableConnectionCount);
		if(routableConnectionCheckCount > 0)
			fs.put("routableConnectionCheckCount", routableConnectionCheckCount);
		double[] peerLocs = getPeersLocation();
		if(peerLocs != null)
			fs.put("peersLocation", peerLocs);
		return fs;
	}

	// Opennet peers don't persist or export the peer added time.
	protected abstract boolean shouldExportPeerAddedTime();

	/**
	* Export volatile data about the node as a SimpleFieldSet
	*/
	public SimpleFieldSet exportVolatileFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		long now = System.currentTimeMillis();
		synchronized(this) {
			fs.put("averagePingTime", averagePingTime());
			long idle = now - lastReceivedPacketTime();
			if(idle > SECONDS.toMillis(60) && -1 != lastReceivedPacketTime())

				fs.put("idle", idle);
			if(peerAddedTime > 1)
				fs.put("peerAddedTime", peerAddedTime);
			fs.putSingle("lastRoutingBackoffReasonRT", lastRoutingBackoffReasonRT);
			fs.putSingle("lastRoutingBackoffReasonBulk", lastRoutingBackoffReasonBulk);
			fs.put("routingBackoffPercent", backedOffPercent.currentValue() * 100);
			fs.put("routingBackoffRT", Math.max(Math.max(routingBackedOffUntilRT, transferBackedOffUntilRT) - now, 0));
			fs.put("routingBackoffBulk", Math.max(Math.max(routingBackedOffUntilBulk, transferBackedOffUntilBulk) - now, 0));
			fs.put("routingBackoffLengthRT", routingBackoffLengthRT);
			fs.put("routingBackoffLengthBulk", routingBackoffLengthBulk);
			fs.put("overloadProbability", getPRejected() * 100);
			fs.put("percentTimeRoutableConnection", getPercentTimeRoutableConnection() * 100);
		}
		fs.putSingle("status", getPeerNodeStatusString());
		return fs;
	}

	/**
	* Export the peer's noderef as a SimpleFieldSet
	*/
	public synchronized SimpleFieldSet exportFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		if(getLastGoodVersion() != null)
			fs.putSingle("lastGoodVersion", lastGoodVersion);
		for(int i = 0; i < nominalPeer.size(); i++)
			fs.putAppend("physical.udp", nominalPeer.get(i).toString());
		fs.put("auth.negTypes", negTypes);
		fs.putSingle("identity", getIdentityString());
		fs.put("location", getLocation());
		fs.put("testnet", testnetEnabled);
		fs.putSingle("version", version);
		if(peerCryptoGroup != null)
			fs.put("dsaGroup", peerCryptoGroup.asFieldSet());
		if(peerPubKey != null)
			fs.put("dsaPubKey", peerPubKey.asFieldSet());
		if(peerECDSAPubKey != null) {
		    fs.put("ecdsa", ECDSA.Curves.P256.getSFS(peerECDSAPubKey));
		}
		if(myARK != null) {
			// Decrement it because we keep the number we would like to fetch, not the last one fetched.
			fs.put("ark.number", myARK.suggestedEdition - 1);
			fs.putSingle("ark.pubURI", myARK.getBaseSSK().toString(false, false));
		}
		fs.put("opennet", isOpennet());
		fs.put("seed", isSeed());
		fs.put("totalInput", (getTotalInputSinceStartup()+getTotalInputBytes()));
		fs.put("totalOutput", (getTotalOutputSinceStartup()+getTotalOutputBytes()));
		return fs;
	}

	public abstract boolean isDarknet();

	public abstract boolean isOpennet();

	public abstract boolean isSeed();

	/**
	* @return The time at which we last connected (or reconnected).
	*/
	public synchronized long timeLastConnectionCompleted() {
		return connectedTime;
	}

	@Override
	public boolean equals(Object o) {
		if(o == this)
			return true;
		if(o instanceof PeerNode) {
			PeerNode pn = (PeerNode) o;
			return Arrays.equals(pn.pubKeyHash, pubKeyHash);
		} else
			return false;
	}

	@Override
	public final int hashCode() {
		return hashCode;
	}

	public boolean isRoutingBackedOff(long ignoreBackoffUnder, boolean realTime) {
		long now = System.currentTimeMillis();
		double pingTime;
		synchronized(this) {
			long routingBackedOffUntil = realTime ? routingBackedOffUntilRT : routingBackedOffUntilBulk;
			if(now < routingBackedOffUntil) {
				if(routingBackedOffUntil - now >= ignoreBackoffUnder) return true;
			}
			long transferBackedOffUntil = realTime ? transferBackedOffUntilRT : transferBackedOffUntilBulk;
			if(now < transferBackedOffUntil) {
				if(transferBackedOffUntil - now >= ignoreBackoffUnder) return true;
			}
			if(isInMandatoryBackoff(now, realTime)) return true;
			pingTime = averagePingTime();
		}
		if(pingTime > maxPeerPingTime()) return true;
		return false;
	}
	
	public boolean isRoutingBackedOff(boolean realTime) {
		long now = System.currentTimeMillis();
		double pingTime;
		synchronized(this) {
			long routingBackedOffUntil = realTime ? routingBackedOffUntilRT : routingBackedOffUntilBulk;
			long transferBackedOffUntil = realTime ? transferBackedOffUntilRT : transferBackedOffUntilBulk;
			if(now < routingBackedOffUntil || now < transferBackedOffUntil) return true;
			pingTime = averagePingTime();
		}
		if(pingTime > maxPeerPingTime()) return true;
		return false;
	}
	
	public boolean isRoutingBackedOffEither() {
		long now = System.currentTimeMillis();
		double pingTime;
		synchronized(this) {
			long routingBackedOffUntil = Math.max(routingBackedOffUntilRT, routingBackedOffUntilBulk);
			long transferBackedOffUntil = Math.max(transferBackedOffUntilRT, transferBackedOffUntilBulk);
			if(now < routingBackedOffUntil || now < transferBackedOffUntil) return true;
			pingTime = averagePingTime();
		}
		if(pingTime > maxPeerPingTime()) return true;
		return false;
	}
	
	long routingBackedOffUntilRT = -1;
	long routingBackedOffUntilBulk = -1;
	/** Initial nominal routing backoff length */
	static final int INITIAL_ROUTING_BACKOFF_LENGTH = (int) SECONDS.toMillis(1);
	/** How much to multiply by during fast routing backoff */

	static final int BACKOFF_MULTIPLIER = 2;
	/** Maximum upper limit to routing backoff slow or fast */
	static final int MAX_ROUTING_BACKOFF_LENGTH = (int) HOURS.toMillis(3);
	/** Current nominal routing backoff length */

	// Transfer Backoff

	long transferBackedOffUntilRT = -1;
	long transferBackedOffUntilBulk = -1;
	static final int INITIAL_TRANSFER_BACKOFF_LENGTH = (int) SECONDS.toMillis(30); // 60 seconds, but it starts at twice this.
	static final int TRANSFER_BACKOFF_MULTIPLIER = 2;
	static final int MAX_TRANSFER_BACKOFF_LENGTH = (int) HOURS.toMillis(3);

	int transferBackoffLengthRT = INITIAL_TRANSFER_BACKOFF_LENGTH;
	int transferBackoffLengthBulk = INITIAL_TRANSFER_BACKOFF_LENGTH;

	int routingBackoffLengthRT = INITIAL_ROUTING_BACKOFF_LENGTH;
	int routingBackoffLengthBulk = INITIAL_ROUTING_BACKOFF_LENGTH;
	/** Last backoff reason */
	String lastRoutingBackoffReasonRT;
	String lastRoutingBackoffReasonBulk;
	/** Previous backoff reason (used by setPeerNodeStatus)*/
	String previousRoutingBackoffReasonRT;
	String previousRoutingBackoffReasonBulk;
	/* percent of time this peer is backed off */
	public final RunningAverage backedOffPercent;
	public final RunningAverage backedOffPercentRT;
	public final RunningAverage backedOffPercentBulk;
	/* time of last sample */
	private long lastSampleTime = Long.MAX_VALUE;
	
	// Separate, mandatory backoff mechanism for when nodes are consistently sending unexpected soft rejects.
	// E.g. when load management predicts GUARANTEED and yet we are rejected.
	// This can happens when the peer's view of how many of our requests are running is different to our view.
	// But there has not been a timeout, so we haven't called fatalTimeout() and reconnected.
	
	// FIXME 3 different kinds of backoff? Can we get rid of some???
	
	long mandatoryBackoffUntilRT = -1;
	int mandatoryBackoffLengthRT = INITIAL_MANDATORY_BACKOFF_LENGTH;
	long mandatoryBackoffUntilBulk = -1;
	int mandatoryBackoffLengthBulk = INITIAL_MANDATORY_BACKOFF_LENGTH;
	static final int INITIAL_MANDATORY_BACKOFF_LENGTH = (int) SECONDS.toMillis(1);
	static final int MANDATORY_BACKOFF_MULTIPLIER = 2;
	static final int MAX_MANDATORY_BACKOFF_LENGTH = (int) MINUTES.toMillis(5);

	/** When load management predicts that a peer will definitely accept the request, both
	 * before it was sent and after we got the rejected, we go into mandatory backoff. */
	public void enterMandatoryBackoff(String reason, boolean realTime) {
		long now = System.currentTimeMillis();
		synchronized(this) {
			long mandatoryBackoffUntil = realTime ? mandatoryBackoffUntilRT : mandatoryBackoffUntilBulk;
			int mandatoryBackoffLength = realTime ? mandatoryBackoffLengthRT : mandatoryBackoffLengthBulk;
			if(mandatoryBackoffUntil > -1 && mandatoryBackoffUntil > now) return;
			Logger.error(this, "Entering mandatory backoff for "+this + (realTime ? " (realtime)" : " (bulk)"));
			mandatoryBackoffUntil = now + (mandatoryBackoffLength/2) + node.fastWeakRandom.nextInt((int) (mandatoryBackoffLength/2));
			mandatoryBackoffLength *= MANDATORY_BACKOFF_MULTIPLIER;
			node.nodeStats.reportMandatoryBackoff(reason, mandatoryBackoffUntil - now, realTime);
			if(realTime) {
				mandatoryBackoffLengthRT = mandatoryBackoffLength;
				mandatoryBackoffUntilRT = mandatoryBackoffUntil;
			} else {
				mandatoryBackoffLengthBulk = mandatoryBackoffLength;
				mandatoryBackoffUntilBulk = mandatoryBackoffUntil;
			}
			setLastBackoffReason(reason, realTime);
		}
		if(realTime)
			outputLoadTrackerRealTime.failSlotWaiters(true);
		else
			outputLoadTrackerBulk.failSlotWaiters(true);
	}
	
	/** Called when a request is accepted. We don't wait for completion, unlike 
	 * successNotOverload(). */
	public synchronized void resetMandatoryBackoff(boolean realTime) {
		if(realTime)
			mandatoryBackoffLengthRT = INITIAL_MANDATORY_BACKOFF_LENGTH;
		else
			mandatoryBackoffLengthBulk = INITIAL_MANDATORY_BACKOFF_LENGTH;
	}
	
	/**
	 * Track the percentage of time a peer spends backed off
	 */
	private void reportBackoffStatus(long now) {
		synchronized(this) {
			if(now > lastSampleTime) { // don't report twice in the same millisecond
				double report = 0.0;
				if(now > routingBackedOffUntilRT) { // not backed off
					if(lastSampleTime > routingBackedOffUntilRT) { // last sample after last backoff
						backedOffPercentRT.report(0.0);
						report = 0.0;
					}else {
						if(routingBackedOffUntilRT > 0) {
							report = (double) (routingBackedOffUntilRT - lastSampleTime) / (double) (now - lastSampleTime);
							backedOffPercentRT.report(report);
						}
					}
				} else {
					report = 0.0;
					backedOffPercentRT.report(1.0);
				}
				
				if(now > routingBackedOffUntilBulk) { // not backed off
					if(lastSampleTime > routingBackedOffUntilBulk) { // last sample after last backoff
						report = 0.0;
						backedOffPercentBulk.report(0.0);
					}else {
						if(routingBackedOffUntilBulk > 0) {
							double myReport = (double) (routingBackedOffUntilBulk - lastSampleTime) / (double) (now - lastSampleTime);
							backedOffPercentBulk.report(myReport);
							if(report > myReport) report = myReport;
						}
					}
				} else {
					backedOffPercentBulk.report(1.0);
				}
				backedOffPercent.report(report);
			}
			lastSampleTime = now;
		}
	}

	/**
	 * Got a local RejectedOverload.
	 * Back off this node for a while.
	 */
	public void localRejectedOverload(String reason, boolean realTime) {
		assert reason.indexOf(' ') == -1;
		pRejected.report(1.0);
		if(logMINOR)
			Logger.minor(this, "Local rejected overload (" + reason + ") on " + this + " : pRejected=" + pRejected.currentValue());
		long now = System.currentTimeMillis();
		Peer peer = getPeer();
		reportBackoffStatus(now);
		// We need it because of nested locking on getStatus()
		synchronized(this) {
			// Don't back off any further if we are already backed off
			long routingBackedOffUntil = realTime ? routingBackedOffUntilRT : routingBackedOffUntilBulk;
			int routingBackoffLength = realTime ? routingBackoffLengthRT : routingBackoffLengthBulk;
			if(now > routingBackedOffUntil) {
				routingBackoffLength = routingBackoffLength * BACKOFF_MULTIPLIER;
				if(routingBackoffLength > MAX_ROUTING_BACKOFF_LENGTH)
					routingBackoffLength = MAX_ROUTING_BACKOFF_LENGTH;
				int x = node.random.nextInt((int) routingBackoffLength);
				routingBackedOffUntil = now + x;
				node.nodeStats.reportRoutingBackoff(reason, x, realTime);
				if(logMINOR) {
					String reasonWrapper = "";
					if(0 < reason.length())
						reasonWrapper = " because of '" + reason + '\'';
					Logger.minor(this, "Backing off" + reasonWrapper + ": routingBackoffLength=" + routingBackoffLength + ", until " + x + "ms on " + peer);
				}
				if(realTime) {
					routingBackedOffUntilRT = routingBackedOffUntil;
					routingBackoffLengthRT = routingBackoffLength;
				} else {
					routingBackedOffUntilBulk = routingBackedOffUntil;
					routingBackoffLengthBulk = routingBackoffLength;
				}
			} else {
				if(logMINOR)
					Logger.minor(this, "Ignoring localRejectedOverload: " + (routingBackedOffUntil - now) + "ms remaining on routing backoff on " + peer);
				return;
			}
			setLastBackoffReason(reason, realTime);
		}
		setPeerNodeStatus(now);
		if(realTime)
			outputLoadTrackerRealTime.failSlotWaiters(true);
		else
			outputLoadTrackerBulk.failSlotWaiters(true);
	}

	/**
	 * Didn't get RejectedOverload.
	 * Reset routing backoff.
	 */
	public void successNotOverload(boolean realTime) {
		pRejected.report(0.0);
		if(logMINOR)
			Logger.minor(this, "Success not overload on " + this + " : pRejected=" + pRejected.currentValue());
		Peer peer = getPeer();
		long now = System.currentTimeMillis();
		reportBackoffStatus(now);
		synchronized(this) {
			// Don't un-backoff if still backed off
			long until;
			if(now > (until = realTime ? routingBackedOffUntilRT : routingBackedOffUntilBulk)) {
				if(realTime)
					routingBackoffLengthRT = INITIAL_ROUTING_BACKOFF_LENGTH;
				else
					routingBackoffLengthBulk = INITIAL_ROUTING_BACKOFF_LENGTH;
				if(logMINOR)
					Logger.minor(this, "Resetting routing backoff on " + peer);
			} else {
				if(logMINOR)
					Logger.minor(this, "Ignoring successNotOverload: " + (until - now) + "ms remaining on routing backoff on " + peer);
				return;
			}
		}
		setPeerNodeStatus(now);
	}

	/**
	 * A transfer failed.
	 * Back off this node for a while.
	 */
	@Override
	public void transferFailed(String reason, boolean realTime) {
		assert reason.indexOf(' ') == -1;
		pRejected.report(1.0);
		if(logMINOR)
			Logger.minor(this, "Transfer failed (" + reason + ") on " + this + " : pRejected=" + pRejected.currentValue());
		long now = System.currentTimeMillis();
		Peer peer = getPeer();
		reportBackoffStatus(now);
		// We need it because of nested locking on getStatus()
		synchronized(this) {
			// Don't back off any further if we are already backed off
			long transferBackedOffUntil = realTime ? transferBackedOffUntilRT : transferBackedOffUntilBulk;
			int transferBackoffLength = realTime ? transferBackoffLengthRT : transferBackoffLengthBulk;
			if(now > transferBackedOffUntil) {
				transferBackoffLength = transferBackoffLength * TRANSFER_BACKOFF_MULTIPLIER;
				if(transferBackoffLength > MAX_TRANSFER_BACKOFF_LENGTH)
					transferBackoffLength = MAX_TRANSFER_BACKOFF_LENGTH;
				int x = node.random.nextInt((int) transferBackoffLength);
				transferBackedOffUntil = now + x;
				node.nodeStats.reportTransferBackoff(reason, x, realTime);
				if(logMINOR) {
					String reasonWrapper = "";
					if(0 < reason.length())
						reasonWrapper = " because of '" + reason + '\'';
					Logger.minor(this, "Backing off (transfer)" + reasonWrapper + ": transferBackoffLength=" + transferBackoffLength + ", until " + x + "ms on " + peer);
				}
				if(realTime) {
					transferBackedOffUntilRT = transferBackedOffUntil;
					transferBackoffLengthRT = transferBackoffLength;
				} else {
					transferBackedOffUntilBulk = transferBackedOffUntil;
					transferBackoffLengthBulk = transferBackoffLength;
				}
			} else {
				if(logMINOR)
					Logger.minor(this, "Ignoring transfer failure: " + (transferBackedOffUntil - now) + "ms remaining on transfer backoff on " + peer);
				return;
			}
			setLastBackoffReason(reason, realTime);
		}
		if(realTime)
			outputLoadTrackerRealTime.failSlotWaiters(true);
		else
			outputLoadTrackerBulk.failSlotWaiters(true);
		setPeerNodeStatus(now);
	}

	/**
	 * A transfer succeeded.
	 * Reset backoff.
	 */
	public void transferSuccess(boolean realTime) {
		pRejected.report(0.0);
		if(logMINOR)
			Logger.minor(this, "Transfer success on " + this + " : pRejected=" + pRejected.currentValue());
		Peer peer = getPeer();
		long now = System.currentTimeMillis();
		reportBackoffStatus(now);
		synchronized(this) {
			// Don't un-backoff if still backed off
			long until;
			if(now > (until = realTime ? transferBackedOffUntilRT : transferBackedOffUntilBulk)) {
				if(realTime)
					transferBackoffLengthRT = INITIAL_TRANSFER_BACKOFF_LENGTH;
				else
					transferBackoffLengthBulk = INITIAL_TRANSFER_BACKOFF_LENGTH;
				if(logMINOR)
					Logger.minor(this, "Resetting transfer backoff on " + peer);
			} else {
				if(logMINOR)
					Logger.minor(this, "Ignoring transfer success: " + (until - now) + "ms remaining on transfer backoff on " + peer);
				return;
			}
		}
		setPeerNodeStatus(now);
	}


	Object pingSync = new Object();
	// Relatively few as we only get one every 200ms*#nodes
	// We want to get reasonably early feedback if it's dropping all of them...

	final static int MAX_PINGS = 5;
	long pingNumber;
	private final RunningAverage pingAverage;

	/**
	 * @return The probability of a request sent to this peer being rejected (locally)
	 * due to overload, or timing out after being accepted.
	 */
	public double getPRejected() {
		return pRejected.currentValue();
	}

	@Override
	public double averagePingTime() {
		return pingAverage.currentValue();
	}
	
	private boolean reportedRTT;
	private double SRTT = 1000;
	private double RTTVAR = 0;
	private double RTO = 1000;
	
	/** Calculated as per RFC 2988 */
	@Override
	public synchronized double averagePingTimeCorrected() {
		return RTO; 
	}

	@Override
	public void reportThrottledPacketSendTime(long timeDiff, boolean realTime) {
		// FIXME do we need this?
		if(logMINOR)
			Logger.minor(this, "Reporting throttled packet send time: " + timeDiff + " to " + getPeer()+" ("+(realTime?"realtime":"bulk")+")");
	}

	public void setRemoteDetectedPeer(Peer p) {
		this.remoteDetectedPeer = p;
	}

	public Peer getRemoteDetectedPeer() {
		return remoteDetectedPeer;
	}

	public synchronized long getRoutingBackoffLength(boolean realTime) {
		return realTime ? routingBackoffLengthRT : routingBackoffLengthBulk;
	}

	public synchronized long getRoutingBackedOffUntil(boolean realTime) {
		return Math.max(realTime ? mandatoryBackoffUntilRT : mandatoryBackoffUntilBulk,
				Math.max(                               
						realTime ? routingBackedOffUntilRT : routingBackedOffUntilBulk, 
								realTime ? transferBackedOffUntilRT : transferBackedOffUntilBulk));
	}
	
	public synchronized long getRoutingBackedOffUntilMax() {
		return Math.max(Math.max(mandatoryBackoffUntilRT, mandatoryBackoffUntilBulk),
				Math.max(
						Math.max(routingBackedOffUntilRT, routingBackedOffUntilBulk),
						Math.max(transferBackedOffUntilRT, transferBackedOffUntilBulk)));
	}
	
	public synchronized long getRoutingBackedOffUntilRT() {
		return Math.max(routingBackedOffUntilRT, transferBackedOffUntilRT);
	}
	
	public synchronized long getRoutingBackedOffUntilBulk() {
		return Math.max(routingBackedOffUntilBulk, transferBackedOffUntilBulk);
	}

	public synchronized String getLastBackoffReason(boolean realTime) {
		return realTime ? lastRoutingBackoffReasonRT : lastRoutingBackoffReasonBulk;
	}

	public synchronized String getPreviousBackoffReason(boolean realTime) {
		return realTime ? previousRoutingBackoffReasonRT : previousRoutingBackoffReasonBulk;
	}

	public synchronized void setLastBackoffReason(String s, boolean realTime) {
		if(realTime)
			lastRoutingBackoffReasonRT = s;
		else
			lastRoutingBackoffReasonBulk = s;
	}

	public void addToLocalNodeSentMessagesToStatistic(Message m) {
		String messageSpecName;
		Long count;

		messageSpecName = m.getSpec().getName();
		// Synchronize to make increments atomic.
		synchronized(localNodeSentMessageTypes) {
			count = localNodeSentMessageTypes.get(messageSpecName);
			if(count == null)
				count = 1L;
			else
				count = count.longValue() + 1;
			localNodeSentMessageTypes.put(messageSpecName, count);
		}
	}

	public void addToLocalNodeReceivedMessagesFromStatistic(Message m) {
		String messageSpecName;
		Long count;

		messageSpecName = m.getSpec().getName();
		// Synchronize to make increments atomic.
		synchronized(localNodeReceivedMessageTypes) {
			count = localNodeReceivedMessageTypes.get(messageSpecName);
			if(count == null)
				count = 1L;
			else
				count = count.longValue() + 1;
			localNodeReceivedMessageTypes.put(messageSpecName, count);
		}
	}

	public Hashtable<String,Long> getLocalNodeSentMessagesToStatistic() {
		// Must be synchronized *during the copy*
		synchronized (localNodeSentMessageTypes) {
			return new Hashtable<String,Long>(localNodeSentMessageTypes);
		}
	}

	public Hashtable<String,Long> getLocalNodeReceivedMessagesFromStatistic() {
		// Must be synchronized *during the copy*
		synchronized (localNodeReceivedMessageTypes) {
			return new Hashtable<String,Long>(localNodeReceivedMessageTypes);
		}
	}

	synchronized USK getARK() {
		return myARK;
	}

	public void gotARK(SimpleFieldSet fs, long fetchedEdition) {
		try {
			synchronized(this) {
				handshakeCount = 0;
				// edition +1 because we store the ARK edition that we want to fetch.
				if(myARK.suggestedEdition < fetchedEdition + 1)
					myARK = myARK.copy(fetchedEdition + 1);
			}
			processNewNoderef(fs, true, false, false);
		} catch(FSParseException e) {
			Logger.error(this, "Invalid ARK update: " + e, e);
			// This is ok as ARKs are limited to 4K anyway.
			Logger.error(this, "Data was: \n" + fs.toString());
			synchronized(this) {
				handshakeCount = PeerNode.MAX_HANDSHAKE_COUNT;
			}
		}
	}

	public synchronized int getPeerNodeStatus() {
		return peerNodeStatus;
	}

	public String getPeerNodeStatusString() {
		int status = getPeerNodeStatus();
		return getPeerNodeStatusString(status);
	}

	public static String getPeerNodeStatusString(int status) {
		if(status == PeerManager.PEER_NODE_STATUS_CONNECTED)
			return "CONNECTED";
		if(status == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF)
			return "BACKED OFF";
		if(status == PeerManager.PEER_NODE_STATUS_TOO_NEW)
			return "TOO NEW";
		if(status == PeerManager.PEER_NODE_STATUS_TOO_OLD)
			return "TOO OLD";
		if(status == PeerManager.PEER_NODE_STATUS_DISCONNECTED)
			return "DISCONNECTED";
		if(status == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED)
			return "NEVER CONNECTED";
		if(status == PeerManager.PEER_NODE_STATUS_DISABLED)
			return "DISABLED";
		if(status == PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM)
			return "CLOCK PROBLEM";
		if(status == PeerManager.PEER_NODE_STATUS_CONN_ERROR)
			return "CONNECTION ERROR";
		if(status == PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED)
			return "ROUTING DISABLED";
		if(status == PeerManager.PEER_NODE_STATUS_LISTEN_ONLY)
			return "LISTEN ONLY";
		if(status == PeerManager.PEER_NODE_STATUS_LISTENING)
			return "LISTENING";
		if(status == PeerManager.PEER_NODE_STATUS_BURSTING)
			return "BURSTING";
		if(status == PeerManager.PEER_NODE_STATUS_DISCONNECTING)
			return "DISCONNECTING";
		if(status == PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS)
			return "NO LOAD STATS";
		return "UNKNOWN STATUS";
	}

	public String getPeerNodeStatusCSSClassName() {
		int status = getPeerNodeStatus();
		return getPeerNodeStatusCSSClassName(status);
	}

	public static String getPeerNodeStatusCSSClassName(int status) {
		if(status == PeerManager.PEER_NODE_STATUS_CONNECTED)
			return "peer_connected";
		else if(status == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF)
			return "peer_backed_off";
		else if(status == PeerManager.PEER_NODE_STATUS_TOO_NEW)
			return "peer_too_new";
		else if(status == PeerManager.PEER_NODE_STATUS_TOO_OLD)
			return "peer_too_old";
		else if(status == PeerManager.PEER_NODE_STATUS_DISCONNECTED)
			return "peer_disconnected";
		else if(status == PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED)
			return "peer_never_connected";
		else if(status == PeerManager.PEER_NODE_STATUS_DISABLED)
			return "peer_disabled";
		else if(status == PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED)
			return "peer_routing_disabled";
		else if(status == PeerManager.PEER_NODE_STATUS_BURSTING)
			return "peer_bursting";
		else if(status == PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM)
			return "peer_clock_problem";
		else if(status == PeerManager.PEER_NODE_STATUS_LISTENING)
			return "peer_listening";
		else if(status == PeerManager.PEER_NODE_STATUS_LISTEN_ONLY)
			return "peer_listen_only";
		else if(status == PeerManager.PEER_NODE_STATUS_DISCONNECTING)
			return "peer_disconnecting";
		else if(status == PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS)
			return "peer_no_load_stats";
		else
			return "peer_unknown_status";
	}

	/** Calculate the current status. Does not update peerNodeStatus itself, nor does it update
	 * the various listeners and trackers interested in peer statuses; see 
	 * setPeerNodeStatus(long, boolean) for that. Override this method to implement special peer
	 * statuses that are specific to your PeerNode implementation (e.g. DarknetPeerNode).
	 * You should generally call this method and then adjust the return value in special cases.
	 * Note that this method updates the backoff statistics. */
	protected synchronized int calculatePeerNodeStatus(long now, long routingBackedOffUntilRT, long localRoutingBackedOffUntilBulk, boolean overPingTime, boolean noLoadStats) {
		if(disconnecting)
			return PeerManager.PEER_NODE_STATUS_DISCONNECTING;
		int peerNodeStatus; // Caller's responsibility to update this.peerNodeStatus.
		boolean isConnected = isConnected();
		if(isRoutable()) {  // Function use also updates timeLastConnected and timeLastRoutable
			if(noLoadStats)
				peerNodeStatus = PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS;
			else {
				peerNodeStatus = PeerManager.PEER_NODE_STATUS_CONNECTED;
				if(overPingTime && (lastRoutingBackoffReasonRT == null || now >= routingBackedOffUntilRT)) {
					lastRoutingBackoffReasonRT = "TooHighPing";
				}
				if(now < routingBackedOffUntilRT || overPingTime || isInMandatoryBackoff(now, true)) {
					peerNodeStatus = PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF;
					if(!lastRoutingBackoffReasonRT.equals(previousRoutingBackoffReasonRT) || (previousRoutingBackoffReasonRT == null)) {
						if(previousRoutingBackoffReasonRT != null) {
							peers.removePeerNodeRoutingBackoffReason(previousRoutingBackoffReasonRT, this, true);
						}
						peers.addPeerNodeRoutingBackoffReason(lastRoutingBackoffReasonRT, this, true);
						previousRoutingBackoffReasonRT = lastRoutingBackoffReasonRT;
					}
				} else {
					if(previousRoutingBackoffReasonRT != null) {
						peers.removePeerNodeRoutingBackoffReason(previousRoutingBackoffReasonRT, this, true);
						previousRoutingBackoffReasonRT = null;
					}
				}
				if(overPingTime && (lastRoutingBackoffReasonBulk == null || now >= routingBackedOffUntilBulk)) {
					lastRoutingBackoffReasonBulk = "TooHighPing";
				}
				
				if(now < routingBackedOffUntilBulk || overPingTime || isInMandatoryBackoff(now, false)) {
					peerNodeStatus = PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF;
					if(!lastRoutingBackoffReasonBulk.equals(previousRoutingBackoffReasonBulk) || (previousRoutingBackoffReasonBulk == null)) {
						if(previousRoutingBackoffReasonBulk != null) {
							peers.removePeerNodeRoutingBackoffReason(previousRoutingBackoffReasonBulk, this, false);
						}
						peers.addPeerNodeRoutingBackoffReason(lastRoutingBackoffReasonBulk, this, false);
						previousRoutingBackoffReasonBulk = lastRoutingBackoffReasonBulk;
					}
				} else {
					if(previousRoutingBackoffReasonBulk != null) {
						peers.removePeerNodeRoutingBackoffReason(previousRoutingBackoffReasonBulk, this, false);
						previousRoutingBackoffReasonBulk = null;
					}
				}
			}
		} else if(isConnected && bogusNoderef)
			peerNodeStatus = PeerManager.PEER_NODE_STATUS_CONN_ERROR;
		else if(isConnected && unroutableNewerVersion)
			peerNodeStatus = PeerManager.PEER_NODE_STATUS_TOO_NEW;
		else if(isConnected && unroutableOlderVersion)
			peerNodeStatus = PeerManager.PEER_NODE_STATUS_TOO_OLD;
		else if(isConnected && disableRouting)
			peerNodeStatus = PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED;
		else if(isConnected && Math.abs(clockDelta) > MAX_CLOCK_DELTA)
			peerNodeStatus = PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM;
		else if(neverConnected)
			peerNodeStatus = PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED;
		else if(isBursting)
			return PeerManager.PEER_NODE_STATUS_BURSTING;
		else
			peerNodeStatus = PeerManager.PEER_NODE_STATUS_DISCONNECTED;
		if(!removed) {
		    if(!isConnected && (previousRoutingBackoffReasonRT != null)) {
		        peers.removePeerNodeRoutingBackoffReason(previousRoutingBackoffReasonRT, this, true);
		        previousRoutingBackoffReasonRT = null;
		    }
		    if(!isConnected && (previousRoutingBackoffReasonBulk != null)) {
		        peers.removePeerNodeRoutingBackoffReason(previousRoutingBackoffReasonBulk, this, false);
		        previousRoutingBackoffReasonBulk = null;
		    }
		}
		return peerNodeStatus;
	}

	public int setPeerNodeStatus(long now) {
		return setPeerNodeStatus(now, false);
	}

	/* Calls calculatePeerNodeStatus() to calculate the current status, and then updates everyone
	 * who needs to know. In particular the PeerStatusTracker but also load management stuff and
	 * UI listeners. Should not be overridden in general. 
	 * @param now The current time.
	 * @param noLog If true don't complain if a peer status e.g. isn't in the tracker. */
	public final int setPeerNodeStatus(long now, boolean noLog) {
		long localRoutingBackedOffUntilRT = getRoutingBackedOffUntil(true);
		long localRoutingBackedOffUntilBulk = getRoutingBackedOffUntil(true);
		int oldPeerNodeStatus;
		long threshold = maxPeerPingTime();
		boolean noLoadStats = noLoadStats();
		synchronized(this) {
			oldPeerNodeStatus = peerNodeStatus;
			peerNodeStatus = calculatePeerNodeStatus(now, localRoutingBackedOffUntilRT, localRoutingBackedOffUntilBulk, averagePingTime() > threshold, noLoadStats);

			if(peerNodeStatus != oldPeerNodeStatus && recordStatus() && !removed) {
				peers.changePeerNodeStatus(this, oldPeerNodeStatus, peerNodeStatus, noLog);
			}

		}
		if(logMINOR) Logger.minor(this, "Peer node status now "+peerNodeStatus+" was "+oldPeerNodeStatus);
		if(peerNodeStatus!=oldPeerNodeStatus){
			if(oldPeerNodeStatus == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF) {
				outputLoadTrackerRealTime.maybeNotifySlotWaiter();
				outputLoadTrackerBulk.maybeNotifySlotWaiter();
			}
			notifyPeerNodeStatusChangeListeners();
		}
		if(peerNodeStatus == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF) {
			long delta = Math.max(localRoutingBackedOffUntilRT, localRoutingBackedOffUntilBulk) - now + 1;
			if(delta > 0)
				node.ticker.queueTimedJob(checkStatusAfterBackoff, "Update status for "+this, delta, true, true);
		}
		return peerNodeStatus;
	}
	
	/** @return True if either bulk or realtime has not yet received a valid peer load 
	 * stats message. If so, we will not be able to route requests to the node under new 
	 * load management. */
	private boolean noLoadStats() {
		if(node.enableNewLoadManagement(false) || node.enableNewLoadManagement(true)) {
			if(outputLoadTrackerRealTime.getLastIncomingLoadStats() == null) {
				if(isRoutable())
					Logger.normal(this, "No realtime load stats on "+this);
				return true;
			}
			if(outputLoadTrackerBulk.getLastIncomingLoadStats() == null) {
				if(isRoutable())
					Logger.normal(this, "No bulk load stats on "+this);
				return true;
			}
		}
		return false;
	}
	
	private final Runnable checkStatusAfterBackoff;

	public abstract boolean recordStatus();

	public String getIdentityString() {
		return identityAsBase64String;
	}

	public boolean isFetchingARK() {
		return arkFetcher != null;
	}

	public synchronized int getHandshakeCount() {
		return handshakeCount;
	}

	/**
	 * Queries the Version class to determine if this peers advertised build-number is either too-old or
	 * to new for the routing of requests.
	 */
	synchronized void updateVersionRoutablity() {
			unroutableOlderVersion = forwardInvalidVersion();
			unroutableNewerVersion = reverseInvalidVersion();
	}

	/**
	 * Will return true if routing to this node is either explictly disabled, or disabled due to
	 * noted incompatiblity in build-version numbers.
	 * Logically: "not(isRoutable())", but will return false even if disconnected (meaning routing is not disabled).
	 */
	public synchronized boolean noLongerRoutable() {
		if(unroutableNewerVersion || unroutableOlderVersion || disableRouting)
			return true;
		return false;
	}

	final void invalidate(long now) {
		synchronized(this) {
			isRoutable = false;
		}
		Logger.normal(this, "Invalidated " + this);
		setPeerNodeStatus(System.currentTimeMillis());
	}

	public void maybeOnConnect() {
		if(wasDisconnected && isConnected()) {
			synchronized(this) {
				wasDisconnected = false;
			}
			onConnect();
		} else if(!isConnected()) {
			synchronized(this) {
				wasDisconnected = true;
			}
		}
	}

	/**
	 * A method to be called once at the beginning of every time isConnected() is true
	 */
	protected void onConnect() {
		synchronized(this) {
			uomCount = 0;
			lastSentUOM = -1;
			sendingUOMMainJar = false;
			sendingUOMLegacyExtJar = false;
		}
		OpennetManager om = node.getOpennet();
		if(om != null) {
		    // OpennetManager must be notified of a new connection even if it is a darknet peer.
		    om.onConnectedPeer(this);
		}
	}

	@Override
	public void onFound(USK origUSK, long edition, FetchResult result) {
		if(isConnected() || myARK.suggestedEdition > edition) {
			result.asBucket().free();
			return;
		}

		byte[] data;
		try {
			data = result.asByteArray();
		} catch(IOException e) {
			Logger.error(this, "I/O error reading fetched ARK: " + e, e);
			result.asBucket().free();
			return;
		}

		String ref;
		try {
			ref = new String(data, "UTF-8");
		} catch(UnsupportedEncodingException e) {
			result.asBucket().free();
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		}

		SimpleFieldSet fs;
		try {
			fs = new SimpleFieldSet(ref, false, true, false);
			if(logMINOR)
				Logger.minor(this, "Got ARK for " + this);
			gotARK(fs, edition);
		} catch(IOException e) {
			// Corrupt ref.
			Logger.error(this, "Corrupt ARK reference? Fetched " + myARK.copy(edition) + " got while parsing: " + e + " from:\n" + ref, e);
		}
		result.asBucket().free();

	}

	public synchronized boolean noContactDetails() {
		return handshakeIPs == null || handshakeIPs.length == 0;
	}

	public synchronized void reportIncomingBytes(int length) {
		totalBytesIn += length;
		totalBytesExchangedWithCurrentTracker += length;
	}

	public synchronized void reportOutgoingBytes(int length) {
		totalBytesOut += length;
		totalBytesExchangedWithCurrentTracker += length;
	}

	public synchronized long getTotalInputBytes() {
		return totalBytesIn;
	}

	public synchronized long getTotalOutputBytes() {
		return totalBytesOut;
	}

	public synchronized long getTotalInputSinceStartup() {
		return totalInputSinceStartup;
	}

	public synchronized long getTotalOutputSinceStartup() {
		return totalOutputSinceStartup;
	}

	public boolean isSignatureVerificationSuccessfull() {
		return isSignatureVerificationSuccessfull;
	}

	public void checkRoutableConnectionStatus() {
		synchronized(this) {
			if(isRoutable())
				hadRoutableConnectionCount += 1;
			routableConnectionCheckCount += 1;
			// prevent the average from moving too slowly by capping the checkcount to 200000,
			// which, at 7 seconds between counts, works out to about 2 weeks.  This also prevents
			// knowing how long we've had a particular peer long term.
			if(routableConnectionCheckCount >= 200000) {
				// divide both sides by the same amount to keep the same ratio
				hadRoutableConnectionCount = hadRoutableConnectionCount / 2;
				routableConnectionCheckCount = routableConnectionCheckCount / 2;
			}
		}
	}

	public synchronized double getPercentTimeRoutableConnection() {
		if(hadRoutableConnectionCount == 0)
			return 0.0;
		return ((double) hadRoutableConnectionCount) / routableConnectionCheckCount;
	}

	@Override
	public int getVersionNumber() {
		return Version.getArbitraryBuildNumber(getVersion(), -1);
	}

	private final PacketThrottle _lastThrottle = new PacketThrottle(Node.PACKET_SIZE);

	@Override
	public PacketThrottle getThrottle() {
		return _lastThrottle;
	}

	/**
	 * Select the most appropriate negType, taking the user's preference into account
	 * order matters
	 *
	 * @param mangler
	 * @return -1 if no common negType has been found
	 */
	public int selectNegType(OutgoingPacketMangler mangler) {
		int[] hisNegTypes;
		int[] myNegTypes = mangler.supportedNegTypes(false);
		boolean supportECDSA;
		synchronized(this) {
			hisNegTypes = negTypes;
			supportECDSA = this.peerECDSAPubKey != null; // FIXME REMOVE
		}
		int bestNegType = -1;
		for(int negType: myNegTypes) {
			if(negType >= 9 && !supportECDSA)
				continue; // FIXME REMOVE
			for(int hisNegType: hisNegTypes) {
				if(hisNegType == negType) {
					bestNegType = negType;
					break;
				}
			}
		}
		return bestNegType;
	}

	public String userToString() {
		return String.valueOf(getPeer());
	}

	public void setTimeDelta(long delta) {
		synchronized(this) {
			clockDelta = delta;
			if(Math.abs(clockDelta) > MAX_CLOCK_DELTA)
				isRoutable = false;
		}
		setPeerNodeStatus(System.currentTimeMillis());
	}

	public long getClockDelta() {
		return clockDelta;
	}

	/** Offer a key to this node */
	public void offer(Key key) {
		byte[] keyBytes = key.getFullKey();
		// FIXME maybe the authenticator should be shorter than 32 bytes to save memory?
		byte[] authenticator = HMAC.macWithSHA256(node.failureTable.offerAuthenticatorKey, keyBytes, 32);
		Message msg = DMT.createFNPOfferKey(key, authenticator);
		try {
			sendAsync(msg, null, node.nodeStats.sendOffersCtr);
		} catch(NotConnectedException e) {
		// Ignore
		}
	}

	@Override
	public OutgoingPacketMangler getOutgoingMangler() {
		return outgoingMangler;
	}

	@Override
	public SocketHandler getSocketHandler() {
		return outgoingMangler.getSocketHandler();
	}

	/** Is this peer disabled? I.e. has the user explicitly disabled it? */
	public boolean isDisabled() {
		return false;
	}

	/** Is this peer allowed local addresses? If false, we will never connect to this peer via
	 * a local address even if it advertises them.
	 */
	public boolean allowLocalAddresses() {
		return this.outgoingMangler.alwaysAllowLocalAddresses();
	}

	/** Is this peer set to ignore source address? If so, we will always reply to the peer's official
	 * address, even if we get packets from somewhere else. @see DarknetPeerNode.isIgnoreSourcePort().
	 */
	public boolean isIgnoreSource() {
		return false;
	}

	/**
	 * Create a DarknetPeerNode or an OpennetPeerNode as appropriate
	 */
	public static PeerNode create(SimpleFieldSet fs, Node node2, NodeCrypto crypto, OpennetManager opennet, PeerManager manager, OutgoingPacketMangler mangler) throws FSParseException, PeerParseException, ReferenceSignatureVerificationException {
		if(crypto.isOpennet)
			return new OpennetPeerNode(fs, node2, crypto, opennet, manager, true, mangler);
		else
			return new DarknetPeerNode(fs, node2, crypto, manager, true, mangler, null, null);
	}
	
	public byte[] getPubKeyHash() {
		return pubKeyHash;
	}

	public byte[] getPubKeyHashHash() {
		return pubKeyHashHash;
	}

	public boolean neverConnected() {
		return neverConnected;
	}

	/** Called when a request or insert succeeds. Used by opennet. */
	public abstract void onSuccess(boolean insert, boolean ssk);

	/** Called when a delayed disconnect is occurring. Tell the node that it is being 
	 * disconnected, but that the process may take a while. After this point, requests
	 * will not be accepted from the peer nor routed to it. 
	 * @param dumpMessageQueue If true, immediately dump the message queue, since we are
	 * closing the connection due to some low level trouble e.g. not acknowledging. 
	 * We will continue to try to send anything already in flight, and it is possible to
	 * send more messages after this point, for instance the message telling it we are
	 * disconnecting, but see above - no requests will be routed across this connection. 
	 * @return True if we have already started disconnecting, false otherwise. */
	public boolean notifyDisconnecting(boolean dumpMessageQueue) {
		MessageItem[] messagesTellDisconnected = null;
		synchronized(this) {
			if(disconnecting) return true;
			disconnecting = true;
			jfkNoncesSent.clear();
			if(dumpMessageQueue) {
				// Reset the boot ID so that we get different trackers next time.
				myBootID = node.fastWeakRandom.nextLong();
				messagesTellDisconnected = grabQueuedMessageItems();
			}
		}
		setPeerNodeStatus(System.currentTimeMillis());
		if(messagesTellDisconnected != null) {
			if(logMINOR)
				Logger.minor(this, "Messages to dump: "+messagesTellDisconnected.length);
			for(MessageItem mi : messagesTellDisconnected) {
				mi.onDisconnect();
			}
		}
		return false;
	}

	/** Called to cancel a delayed disconnect. Always succeeds even if the node was not being
	 * disconnected. */
	public void onAdded() {
		synchronized(this) {
			removed = false;
			disconnecting = false;
		}
		setPeerNodeStatus(System.currentTimeMillis(), true);
	}

	/** Called when the peer is removed from the PeerManager */
	public void onRemove() {
		synchronized(this) {
			removed = true;
		}
		node.getTicker().removeQueuedJob(checkStatusAfterBackoff);
		disconnected(true, true);
		stopARKFetcher();
	}
	
	/** @return True if we have been removed from the peers list. */
	synchronized boolean cachedRemoved() {
		return removed;
	}

	public synchronized boolean isDisconnecting() {
		return disconnecting;
	}

	protected byte[] getJFKBuffer() {
		return jfkBuffer;
	}

	protected void setJFKBuffer(byte[] bufferJFK) {
		this.jfkBuffer = bufferJFK;
	}

	public int getSigParamsByteLength() {
		int bitLen = this.peerCryptoGroup.getQ().bitLength();
		int byteLen = (bitLen + 7) / 8;
		return byteLen;
	}

	static final int MAX_SIMULTANEOUS_ANNOUNCEMENTS = 1;
	static final int MAX_ANNOUNCE_DELAY = 1000;
	private long timeLastAcceptedAnnouncement;
	private long[] runningAnnounceUIDs = new long[0];

	public synchronized boolean shouldAcceptAnnounce(long uid) {
		long now = System.currentTimeMillis();
		if(runningAnnounceUIDs.length < MAX_SIMULTANEOUS_ANNOUNCEMENTS &&
				now - timeLastAcceptedAnnouncement > MAX_ANNOUNCE_DELAY) {
			long[] newList = new long[runningAnnounceUIDs.length + 1];
			if(runningAnnounceUIDs.length > 0)
				System.arraycopy(runningAnnounceUIDs, 0, newList, 0, runningAnnounceUIDs.length);
			newList[runningAnnounceUIDs.length] = uid;
			timeLastAcceptedAnnouncement = now;
			return true;
		} else {
			return false;
		}
	}

	public synchronized boolean completedAnnounce(long uid) {
		final int runningAnnounceUIDsLength = runningAnnounceUIDs.length;
		if(runningAnnounceUIDsLength < 1) return false;
		long[] newList = new long[runningAnnounceUIDsLength - 1];
		int x = 0;
		for(int i=0;i<runningAnnounceUIDs.length;i++) {
			if(i == runningAnnounceUIDs.length) return false;
			long l = runningAnnounceUIDs[i];
			if(l == uid) continue;
			newList[x++] = l;
		}
		runningAnnounceUIDs = newList;
		if(x < runningAnnounceUIDs.length) {
			assert(false); // Callers prevent duplicated UIDs.
			runningAnnounceUIDs = Arrays.copyOf(runningAnnounceUIDs, x);
		}
		return true;
	}

	public synchronized long timeLastDisconnect() {
		return timeLastDisconnect;
	}

	/** Does this peernode want to be returned by for example PeerManager.getByPeer() ?
	 * False = seednode etc, never going to be routable. */
	public abstract boolean isRealConnection();

	/** Can we accept announcements from this node? */
	public boolean canAcceptAnnouncements() {
		return isOpennet() || node.passOpennetRefsThroughDarknet();
	}

	public boolean handshakeUnknownInitiator() {
		return false;
	}

	public int handshakeSetupType() {
		return -1;
	}

	@Override
	public WeakReference<PeerNode> getWeakRef() {
		return myRef;
	}

	/**
	 * Get a single address to send a handshake to.
	 * The current code doesn't work well with multiple simulataneous handshakes.
	 * Alternates between valid values.
	 * (FIXME!)
	 */
	public Peer getHandshakeIP() {
		Peer[] localHandshakeIPs;
		if(!shouldSendHandshake()) {
			if(logMINOR) Logger.minor(this, "Not sending handshake to "+getPeer()+" because pn.shouldSendHandshake() returned false");
			return null;
		}
		long firstTime = System.currentTimeMillis();
		localHandshakeIPs = getHandshakeIPs();
		long secondTime = System.currentTimeMillis();
		if((secondTime - firstTime) > 1000)
			Logger.error(this, "getHandshakeIPs() took more than a second to execute ("+(secondTime - firstTime)+") working on "+userToString());
		if(localHandshakeIPs.length == 0) {
			long thirdTime = System.currentTimeMillis();
			if((thirdTime - secondTime) > 1000)
				Logger.error(this, "couldNotSendHandshake() (after getHandshakeIPs()) took more than a second to execute ("+(thirdTime - secondTime)+") working on "+userToString());
			return null;
		}
		long loopTime1 = System.currentTimeMillis();
		List<Peer> validIPs = new ArrayList<Peer>(localHandshakeIPs.length);
		boolean allowLocalAddresses = allowLocalAddresses();
		for(Peer peer: localHandshakeIPs) {
			FreenetInetAddress addr = peer.getFreenetAddress();
			if(peer.getAddress(false) == null) {
				if(logMINOR) Logger.minor(this, "Not sending handshake to "+peer+" for "+getPeer()+" because the DNS lookup failed or it's a currently unsupported IPv6 address");
				continue;
			}
			if(!peer.isRealInternetAddress(false, false, allowLocalAddresses)) {
				if(logMINOR) Logger.minor(this, "Not sending handshake to "+peer+" for "+getPeer()+" because it's not a real Internet address and metadata.allowLocalAddresses is not true");
				continue;
			}
			if(!isConnected()) {
				// If we are connected, we are rekeying.
				// We have separate code to boot out connections.
				if(!outgoingMangler.allowConnection(this, addr)) {
					if(logMINOR)
						Logger.minor(this, "Not sending handshake packet to "+peer+" for "+this);
					continue;
				}
			}
			validIPs.add(peer);
		}
		Peer ret;
		if(validIPs.isEmpty()) {
			ret = null;
		} else if(validIPs.size() == 1) {
			ret = validIPs.get(0);
		} else {
			// Don't need to synchronize for this value as we're only called from one thread anyway.
			handshakeIPAlternator %= validIPs.size();
			ret = validIPs.get(handshakeIPAlternator);
			handshakeIPAlternator++;
		}
		long loopTime2 = System.currentTimeMillis();
		if((loopTime2 - loopTime1) > 1000)
			Logger.normal(this, "loopTime2 is more than a second after loopTime1 ("+(loopTime2 - loopTime1)+") working on "+userToString());
		return ret;
	}

	private int handshakeIPAlternator;

	public void sendNodeToNodeMessage(SimpleFieldSet fs, int n2nType, boolean includeSentTime, long now, boolean queueOnNotConnected) {
		fs.putOverwrite("n2nType", Integer.toString(n2nType));
		if(includeSentTime) {
			fs.put("sentTime", now);
		}
		try {
			Message n2nm;
			n2nm = DMT.createNodeToNodeMessage(
					n2nType, fs.toString().getBytes("UTF-8"));
			try {
				sendAsync(n2nm, null, node.nodeStats.nodeToNodeCounter);
			} catch (NotConnectedException e) {
				if(includeSentTime) {
					fs.removeValue("sentTime");
				}
				if(isDarknet() && queueOnNotConnected) {
					queueN2NM(fs);
				}
			}
		} catch (UnsupportedEncodingException e) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		}
	}

	/**
	 * A method to queue an N2NM in a extra peer data file, only implemented by DarknetPeerNode
	 */
	public void queueN2NM(SimpleFieldSet fs) {
		// Do nothing in the default impl
	}

	/**
	 * Return the relevant local node reference related to this peer's type
	 */
	protected SimpleFieldSet getLocalNoderef() {
		return crypto.exportPublicFieldSet();
	}

	/**
	 * A method to be called after completing a handshake to send the
	 * newly connected peer, as a differential node reference, the
	 * parts of our node reference not needed for handshake.
	 * Should only be called by completedHandshake() after we're happy
	 * with the connection
	 * 
	 * FIXME this should be sent when our noderef changes.
	 */
	protected void sendConnectedDiffNoderef() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		SimpleFieldSet nfs = getLocalNoderef();
		if(null == nfs) return;
		String s;
		s = nfs.get("ark.pubURI");
		if(null != s) {
			fs.putOverwrite("ark.pubURI", s);
		}
		s = nfs.get("ark.number");
		if(null != s) {
			fs.putOverwrite("ark.number", s);
		}
		if(isDarknet() && null != (s = nfs.get("myName"))) {
			fs.putOverwrite("myName", s);
		}
		String[] physicalUDPEntries = nfs.getAll("physical.udp");
		if(physicalUDPEntries != null) {
			fs.putOverwrite("physical.udp", physicalUDPEntries);
		}
		// FIXME remove when make peerECDSA* final.
		fs.putOverwrite("ecdsa.P256.pub", nfs.get("ecdsa.P256.pub"));
		if(!fs.isEmpty()) {
			if(logMINOR) Logger.minor(this, "fs is '" + fs.toString() + "'");
			sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_DIFFNODEREF, false, 0, false);
		} else {
			if(logMINOR) Logger.minor(this, "fs is empty");
		}
	}

	@Override
	public boolean shouldThrottle() {
		return shouldThrottle(getPeer(), node);
	}

	public static boolean shouldThrottle(Peer peer, Node node) {
		if(node.throttleLocalData) return true;
		if(peer == null) return true; // presumably
		InetAddress addr = peer.getAddress(false);
		if(addr == null) return true; // presumably
		return IPUtil.isValidAddress(addr, false);
	}

	static final long MAX_RTO = SECONDS.toMillis(60);
	static final long MIN_RTO = SECONDS.toMillis(1);
	private int consecutiveRTOBackoffs;

	// Clock generally has 20ms granularity or better, right?
	// FIXME determine the clock granularity.
	private static final int CLOCK_GRANULARITY = 20;
	
	@Override
	public void reportPing(long t) {
		this.pingAverage.report(t);
		synchronized(this) {
			consecutiveRTOBackoffs = 0;
			// Update RTT according to RFC 2988.
			if(!reportedRTT) {
				double oldRTO = RTO;
				// Initialize
				SRTT = t;
				RTTVAR = t / 2;
				RTO = SRTT + Math.max(CLOCK_GRANULARITY, RTTVAR * 4);
				// RFC 2988 specifies a 1 second minimum RTT, mostly due to legacy issues,
				// but given that Freenet is mostly used on very slow upstream links, it 
				// probably makes sense for us too for now, to avoid excessive retransmits.
				// FIXME !!!
				if(RTO < MIN_RTO)
					RTO = MIN_RTO;
				if(RTO > MAX_RTO)
					RTO = MAX_RTO;
				reportedRTT = true;
				if(logMINOR) Logger.minor(this, "Received first packet on "+shortToString()+" setting RTO to "+RTO);
				if(oldRTO > RTO) {
					// We have backed off
					if(logMINOR) Logger.minor(this, "Received first packet after backing off on resend. RTO is "+RTO+" but was "+oldRTO);
					// FIXME: do something???
				}
			} else {
				// Update
				RTTVAR = 0.75 * RTTVAR + 0.25 * Math.abs(SRTT - t);
				SRTT = 0.875 * SRTT + 0.125 * t;
				RTO = SRTT + Math.max(CLOCK_GRANULARITY, RTTVAR * 4);
				// RFC 2988 specifies a 1 second minimum RTT, mostly due to legacy issues,
				// but given that Freenet is mostly used on very slow upstream links, it 
				// probably makes sense for us too for now, to avoid excessive retransmits.
				// FIXME !!!
				if(RTO < MIN_RTO)
					RTO = MIN_RTO;
				if(RTO > MAX_RTO)
					RTO = MAX_RTO;
			}
			if(logMINOR) Logger.minor(this, "Reported ping "+t+" avg is now "+pingAverage.currentValue()+" RTO is "+RTO+" SRTT is "+SRTT+" RTTVAR is "+RTTVAR+" for "+shortToString());
		}
	}
	
	/**
	 * RFC 2988:
	 *    Note that a TCP implementation MAY clear SRTT and RTTVAR after
	 *    backing off the timer multiple times as it is likely that the
	 *    current SRTT and RTTVAR are bogus in this situation.  Once SRTT and
	 *    RTTVAR are cleared they should be initialized with the next RTT
	 *    sample taken per (2.2) rather than using (2.3).
	 */
	static final int MAX_CONSECUTIVE_RTO_BACKOFFS = 5;
	
	@Override
	public synchronized void backoffOnResend() {
		if(RTO >= MAX_RTO) {
			Logger.error(this, "Major packet loss on "+this+" - RTO is already at limit and still losing packets!");
		}
		RTO = RTO * 2;
		if(RTO > MAX_RTO)
			RTO = MAX_RTO;
		consecutiveRTOBackoffs++;
		if(consecutiveRTOBackoffs > MAX_CONSECUTIVE_RTO_BACKOFFS) {
			Logger.warning(this, "Resetting RTO for "+this+" after "+consecutiveRTOBackoffs+" consecutive backoffs due to packet loss");
			consecutiveRTOBackoffs = 0;
			reportedRTT = false;
		}
		if(logMINOR) Logger.minor(this, "Backed off on resend, RTO is now "+RTO+" for "+shortToString()+" consecutive RTO backoffs is "+consecutiveRTOBackoffs);
	}

	private long resendBytesSent;

	public final ByteCounter resendByteCounter = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			// Ignore
		}

		@Override
		public void sentBytes(int x) {
			synchronized(PeerNode.this) {
				resendBytesSent += x;
			}
			node.nodeStats.resendByteCounter.sentBytes(x);
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}

	};

	public long getResendBytesSent() {
		return resendBytesSent;
	}

	/**
	 * Should this peer be disconnected and removed immediately?
	 */
	public boolean shouldDisconnectAndRemoveNow() {
		return false;
	}

	public void setUptime(byte uptime2) {
		this.uptime = uptime2;
	}

	public short getUptime() {
		return (short) (uptime & 0xFF);
	}

	public void incrementNumberOfSelections(long time) {
		// TODO: reimplement with a bit field to spare memory
		synchronized(this) {
			countSelectionsSinceConnected++;
		}
	}

	/**
	 * @return The rate at which this peer has been selected since it connected.
	 */
	public synchronized double selectionRate() {
		long timeSinceConnected = System.currentTimeMillis() - this.connectedTime;
		// Avoid bias due to short uptime.
		if(timeSinceConnected < SECONDS.toMillis(10)) return 0.0;
		return countSelectionsSinceConnected / (double) timeSinceConnected;
	}

	private volatile long offeredMainJarVersion;

	public void setMainJarOfferedVersion(long mainJarVersion) {
		offeredMainJarVersion = mainJarVersion;
	}

	public long getMainJarOfferedVersion() {
		return offeredMainJarVersion;
	}

	/**
	 * Maybe send something. A SINGLE PACKET.
	 * Don't send everything at once, for two reasons:
	 * 1. It is possible for a node to have a very long backlog.
	 * 2. Sometimes sending a packet can take a long time.
	 * 3. In the near future PacketSender will be responsible for output bandwidth
	 * throttling.
	 * So it makes sense to send a single packet and round-robin.
	 * @param now
	 * @param ackOnly
	 * @throws BlockedTooLongException
	 */
	public boolean maybeSendPacket(long now, boolean ackOnly) throws BlockedTooLongException {
		PacketFormat pf;
		synchronized(this) {
			if(packetFormat == null) return false;
			pf = packetFormat;
		}
		return pf.maybeSendPacket(now, ackOnly);
	}

	/**
	 * @return The ID of a reusable PacketTracker if there is one, otherwise -1.
	 */
	public long getReusableTrackerID() {
		SessionKey cur;
		synchronized(this) {
			cur = currentTracker;
		}
		if(cur == null) {
			if(logMINOR) Logger.minor(this, "getReusableTrackerID(): cur = null on "+this);
			return -1;
		}
		if(logMINOR) Logger.minor(this, "getReusableTrackerID(): "+cur.trackerID+" on "+this);
		return cur.trackerID;
	}

	private long lastFailedRevocationTransfer;
	/** Reset on disconnection */
	private int countFailedRevocationTransfers;

	public void failedRevocationTransfer() {
		// Something odd happened, possibly a disconnect, maybe looking up the DNS names will help?
		lastAttemptedHandshakeIPUpdateTime = System.currentTimeMillis();
		countFailedRevocationTransfers++;
	}

	public int countFailedRevocationTransfers() {
		return countFailedRevocationTransfers;
	}

	/** Registers a listener that will be notified when status changes. Only the WeakReference of it is stored, so there is no need for deregistering
	 * @param listener - The listener to be registered*/
	public void registerPeerNodeStatusChangeListener(PeerManager.PeerStatusChangeListener listener){
		listeners.add(listener);
	}

	/** Notifies the listeners that status has been changed*/
	private void notifyPeerNodeStatusChangeListeners(){
		synchronized (listeners) {
			for(PeerManager.PeerStatusChangeListener l:listeners){
				l.onPeerStatusChange();
			}
		}
	}


	public boolean isLowUptime() {
		return getUptime() < Node.MIN_UPTIME_STORE_KEY;
	}

	public void setAddedReason(ConnectionType connectionType) {
		// Do nothing.
	}

	public synchronized ConnectionType getAddedReason() {
		return null;
	}
	
	private final Object routedToLock = new Object();
	
	final LoadSender loadSenderRealTime = new LoadSender(true);
	final LoadSender loadSenderBulk = new LoadSender(false);
	
	class LoadSender {
	
		LoadSender(boolean realTimeFlag) {
			this.realTimeFlag = realTimeFlag;
		}
		
		public void onDisconnect() {
			this.lastSentAllocationInput = 0;
			this.lastSentAllocationOutput = 0;
			this.timeLastSentAllocationNotice = -1;
			this.lastFullStats = null;
		}

		private int lastSentAllocationInput;
		private int lastSentAllocationOutput;
		private int lastSentMaxOutputTransfers = Integer.MAX_VALUE;
		private int lastSentMaxOutputTransfersPeerLimit = Integer.MAX_VALUE;
		private long timeLastSentAllocationNotice;
		private long countAllocationNotices;
		private PeerLoadStats lastFullStats;
		private final boolean realTimeFlag;
		private boolean sendASAP;
		
		public void onSetPeerAllocation(boolean input, int thisAllocation, int transfersPerInsert) {
			
			boolean mustSend = false;
			// FIXME review constants, how often are allocations actually sent?
			long now = System.currentTimeMillis();
			synchronized(this) {
				int last = input ? lastSentAllocationInput : lastSentAllocationOutput;
				if(now - timeLastSentAllocationNotice > 5000) {
					if(logMINOR) Logger.minor(this, "Last sent allocation "+TimeUtil.formatTime(now - timeLastSentAllocationNotice));
					mustSend = true;
				} else {
					if(thisAllocation > last * 1.05) {
						if(logMINOR) Logger.minor(this, "Last allocation was "+last+" this is "+thisAllocation);
						mustSend = true;
					} else if(thisAllocation < last * 0.9) { 
						if(logMINOR) Logger.minor(this, "Last allocation was "+last+" this is "+thisAllocation);
						mustSend = true;
					}
				}
				if(!mustSend) return;
				sendASAP = true;
			}
			if(!mustSend) return;
		}
		
		public void onSetMaxOutputTransfers(int maxOutputTransfers) {
			synchronized(this) {
				if(maxOutputTransfers == lastSentMaxOutputTransfers) return;
				if(lastSentMaxOutputTransfers == Integer.MAX_VALUE || lastSentMaxOutputTransfers == 0) {
					sendASAP = true;
				} else if(maxOutputTransfers > lastSentMaxOutputTransfers * 1.05 || maxOutputTransfers < lastSentMaxOutputTransfers * 0.9) {
					sendASAP = true;
				}
			}
		}
		
		public void onSetMaxOutputTransfersPeerLimit(int maxOutputTransfersPeerLimit) {
			synchronized(this) {
				if(maxOutputTransfersPeerLimit == lastSentMaxOutputTransfersPeerLimit) return;
				if(lastSentMaxOutputTransfersPeerLimit == Integer.MAX_VALUE || lastSentMaxOutputTransfersPeerLimit == 0) {
					sendASAP = true;
				} else if(maxOutputTransfersPeerLimit > lastSentMaxOutputTransfersPeerLimit * 1.05 || maxOutputTransfersPeerLimit < lastSentMaxOutputTransfersPeerLimit * 0.9) {
					sendASAP = true;
				}
			}
		}
		
		Message makeLoadStats(long now, int transfersPerInsert, boolean noRemember) {
			PeerLoadStats stats = node.nodeStats.createPeerLoadStats(PeerNode.this, transfersPerInsert, realTimeFlag);
			synchronized(this) {
				lastSentAllocationInput = (int) stats.inputBandwidthPeerLimit;
				lastSentAllocationOutput = (int) stats.outputBandwidthPeerLimit;
				lastSentMaxOutputTransfers = stats.maxTransfersOut;
				if(!noRemember) {
					if(lastFullStats != null && lastFullStats.equals(stats)) return null;
					lastFullStats = stats;
				}
				timeLastSentAllocationNotice = now;
				countAllocationNotices++;
				if(logMINOR) Logger.minor(this, "Sending allocation notice to "+this+" allocation is "+lastSentAllocationInput+" input "+lastSentAllocationOutput+" output.");
			}
			Message msg = DMT.createFNPPeerLoadStatus(stats);
			return msg;
		}

		public synchronized boolean grabSendASAP() {
			boolean send = sendASAP;
			sendASAP = false;
			return send;
		}

		public synchronized void setSendASAP() {
			sendASAP = true;
		}

	}
	
	void removeUIDsFromMessageQueues(Long[] list) {
		this.messageQueue.removeUIDsFromMessageQueues(list);
	}

	public void onSetMaxOutputTransfers(boolean realTime, int maxOutputTransfers) {
		(realTime ? loadSenderRealTime : loadSenderBulk).onSetMaxOutputTransfers(maxOutputTransfers);
	}
	
	public void onSetMaxOutputTransfersPeerLimit(boolean realTime, int maxOutputTransfers) {
		(realTime ? loadSenderRealTime : loadSenderBulk).onSetMaxOutputTransfersPeerLimit(maxOutputTransfers);
	}
	
	public void onSetPeerAllocation(boolean input, int thisAllocation, int transfersPerInsert, int maxOutputTransfers, boolean realTime) {
		(realTime ? loadSenderRealTime : loadSenderBulk).onSetPeerAllocation(input, thisAllocation, transfersPerInsert);
	}

	public class IncomingLoadSummaryStats {
		public IncomingLoadSummaryStats(int totalRequests,
				double outputBandwidthPeerLimit,
				double inputBandwidthPeerLimit,
				double outputBandwidthTotalLimit,
				double inputBandwidthTotalLimit,
				double usedOutput,
				double usedInput,
				double othersUsedOutput,
				double othersUsedInput) {
			runningRequestsTotal = totalRequests;
			peerCapacityOutputBytes = (int)outputBandwidthPeerLimit;
			peerCapacityInputBytes = (int)inputBandwidthPeerLimit;
			totalCapacityOutputBytes = (int)outputBandwidthTotalLimit;
			totalCapacityInputBytes = (int)inputBandwidthTotalLimit;
			usedCapacityOutputBytes = (int) usedOutput;
			usedCapacityInputBytes = (int) usedInput;
			othersUsedCapacityOutputBytes = (int) othersUsedOutput;
			othersUsedCapacityInputBytes = (int) othersUsedInput;
		}
		
		public final int runningRequestsTotal;
		public final int peerCapacityOutputBytes;
		public final int peerCapacityInputBytes;
		public final int totalCapacityOutputBytes;
		public final int totalCapacityInputBytes;
		public final int usedCapacityOutputBytes;
		public final int usedCapacityInputBytes;
		public final int othersUsedCapacityOutputBytes;
		public final int othersUsedCapacityInputBytes;
	}
	
	enum RequestLikelyAcceptedState {
		GUARANTEED, // guaranteed to be accepted, under the per-peer guaranteed limit
		LIKELY, // likely to be accepted even though above the per-peer guaranteed limit, as overall is below the overall lower limit
		UNLIKELY, // not likely to be accepted; peer is over the per-peer guaranteed limit, and global is over the overall lower limit
		UNKNOWN // no data but accepting anyway
	}
	
	// FIXME add LOW_CAPACITY/BROKEN. Set this when the published capacity is way below the median.
	// FIXME will need to calculate the median first!
	
	OutputLoadTracker outputLoadTrackerRealTime = new OutputLoadTracker(true);
	OutputLoadTracker outputLoadTrackerBulk = new OutputLoadTracker(false);
	
	public OutputLoadTracker outputLoadTracker(boolean realTime) {
		return realTime ? outputLoadTrackerRealTime : outputLoadTrackerBulk;
	}

	public void reportLoadStatus(PeerLoadStats stat) {
		outputLoadTracker(stat.realTime).reportLoadStatus(stat);
		node.executor.execute(checkStatusAfterBackoff);
	}
	
	public static class SlotWaiter {
		
		final PeerNode source;
		private final HashSet<PeerNode> waitingFor;
		private PeerNode acceptedBy;
		private RequestLikelyAcceptedState acceptedState;
		final UIDTag tag;
		final boolean offeredKey;
		final RequestType requestType;
		private boolean failed;
		private SlotWaiterFailedException fe;
		final boolean realTime;
		
		// FIXME the counter is a quick hack to ensure that the original ordering is preserved
		// even after failures (transfer failures, backoffs).
		// The real solution, which would likely result in simpler code as well as saving 
		// a thread, is to make the wait loop in RequestSender asynchronous i.e. to not
		// block at all there, but process the waiters in order in a callback when we get
		// such a failure.
		
		final long counter;
		static private long waiterCounter;
		
		SlotWaiter(UIDTag tag, RequestType type, boolean offeredKey, boolean realTime, PeerNode source) {
			this.tag = tag;
			this.requestType = type;
			this.offeredKey = offeredKey;
			this.waitingFor = new HashSet<PeerNode>();
			this.realTime = realTime;
			this.source = source;
			synchronized(SlotWaiter.class) {
				counter = waiterCounter++;
			}
		}
		
		/**
		 * Add another node to wait for.
		 * @return True unless queueing the slot was impossible due to a problem with the PeerNode.
		 * So we return true when there is a successful queueing, and we also return true when there is
		 * a race condition and the waiter has already completed.
		 */
		public boolean addWaitingFor(PeerNode peer) {
			boolean cantQueue = (!peer.isRoutable()) || peer.isInMandatoryBackoff(System.currentTimeMillis(), realTime);
			synchronized(this) {
				if(acceptedBy != null) {
					if(logMINOR) Logger.minor(this, "Not adding "+peer.shortToString+" because already matched on "+this);
					return true;
				}
				if(failed) {
					if(logMINOR) Logger.minor(this, "Not adding "+peer.shortToString+" because already failed on "+this);
					return true;
				}
				if(waitingFor.contains(peer)) return true;
				// Race condition if contains() && cantQueue (i.e. it was accepted then it became backed off), but probably not serious.
				if(cantQueue) return false;
				waitingFor.add(peer);
				tag.setWaitingForSlot();
			}
			if(!peer.outputLoadTracker(realTime).queueSlotWaiter(this)) {
				synchronized(this) {
					waitingFor.remove(peer);
					if(acceptedBy != null || failed) return true;
				}
				return false;
			} else return true;
		}
		
		/** First part of wake-up callback. If this returns null, we have already woken up,
		 * but if it returns a PeerNode[], the SlotWaiter has been woken up, and the caller
		 * **must** call unregister() with the returned data.
		 * @param peer The peer waking up the SlotWaiter.
		 * @param state The accept state we are waking up with.
		 * @return Null if already woken up or not waiting for this peer, otherwise an
		 * array of all the PeerNode's the slot was registered on, which *must* be passed
		 * to unregister() as soon as the caller has unlocked everything that reasonably
		 * can be unlocked. */
		synchronized PeerNode[] innerOnWaited(PeerNode peer, RequestLikelyAcceptedState state) {
			if(logMINOR) Logger.minor(this, "Waking slot waiter "+this+" on "+peer);
			if(acceptedBy != null) {
				if(logMINOR) Logger.minor(this, "Already accepted on "+this);
				if(acceptedBy != peer) {
					if(offeredKey)
						tag.removeFetchingOfferedKeyFrom(peer);
					else
						tag.removeRoutingTo(peer);
				}
				return null;
			}
			if(!waitingFor.contains(peer)) {
				if(logMINOR) Logger.minor(this, "Not waiting for peer "+peer+" on "+this);
				if(acceptedBy != peer) {
					if(offeredKey)
						tag.removeFetchingOfferedKeyFrom(peer);
					else
						tag.removeRoutingTo(peer);
				}
				return null;
			}
			acceptedBy = peer;
			acceptedState = state;
			if(!tag.addRoutedTo(peer, offeredKey)) {
				Logger.normal(this, "onWaited for "+this+" added on "+tag+" but already added - race condition?");
			}
			notifyAll();
			// Because we are no longer in the slot queue we must remove it.
			// If we want to wait for it again it must be re-queued.
			PeerNode[] toUnreg = waitingFor.toArray(new PeerNode[waitingFor.size()]);
			waitingFor.clear();
			tag.clearWaitingForSlot();
			return toUnreg;
		}
		
		/** Caller should not hold locks while calling this.
		 * @param exclude Only set this if you have already removed the slot waiter. */
		void unregister(PeerNode exclude, PeerNode[] all) {
			if(all == null) return;
			for(PeerNode p : all)
				if(p != exclude) p.outputLoadTracker(realTime).unqueueSlotWaiter(this);
		}
		
		/** Some sort of failure.
		 * @param reallyFailed If true, we can't route to the node, or should reconsider 
		 * routing to it, due to e.g. backoff or disconnection. If false, this is 
		 * something like the node is now regarded as low capacity so we should consider
		 * other nodes, but still allow this one.
		 */
		void onFailed(PeerNode peer, boolean reallyFailed) {
			if(logMINOR) Logger.minor(this, "onFailed() on "+this+" reallyFailed="+reallyFailed);
			synchronized(this) {
				if(acceptedBy != null) {
					if(logMINOR) Logger.minor(this, "Already matched on "+this);
					return;
				}
				// Always wake up.
				// Whether it's a backoff or a disconnect, we probably want to add another peer.
				// FIXME get rid of parameter.
				failed = true;
				fe = new SlotWaiterFailedException(peer, reallyFailed);
				tag.clearWaitingForSlot();
				notifyAll();
			}
		}
		
		public HashSet<PeerNode> waitingForList() {
			synchronized(this) {
				return new HashSet<PeerNode>(waitingFor);
			}
		}
		
		/** Wait for any of the PeerNode's we have queued on to accept (locally
		 * i.e. to allocate a local slot to) this request.
		 * @param maxWait The time to wait for. Can be 0, but if it is 0, this
		 * is a "peek", i.e. if we return null, the queued slots remain live.
		 * Whereas if maxWait is not 0, we will unregister when we timeout.
		 * @param timeOutIsFatal If true, if we timeout, count it for each node
		 * involved as a fatal timeout.
		 * @return A matched node, or null.
		 * @throws SlotWaiterFailedException If a peer actually failed.
		 */
		public PeerNode waitForAny(long maxWait, boolean timeOutIsFatal) throws SlotWaiterFailedException {
			// If waitingFor is non-empty after this function returns, we can
			// be accepted when we shouldn't be accepted. So always ensure that
			// the state is clean when returning, by clearing waitingFor and
			// calling unregister().
			PeerNode[] all;
			PeerNode ret = null;
			boolean grabbed = false;
			SlotWaiterFailedException f = null;
			synchronized(this) {
				if(shouldGrab()) {
					if(logMINOR) Logger.minor(this, "Already matched on "+this);
					ret = grab();
					grabbed = true;
				}
				if(fe != null) {
					f = fe;
					fe = null;
					grabbed = true;
				}
				all = waitingFor.toArray(new PeerNode[waitingFor.size()]);
				if(ret != null)
					waitingFor.clear();
				if(grabbed || all.length == 0)
					tag.clearWaitingForSlot();
			}
			if(grabbed) {
				unregister(ret, all);
				if(f != null && ret == null) throw f;
				return ret;
			}
			// grab() above will have set failed = false if necessary.
			// acceptedBy = null because ret = null, and it won't change after that because waitingFor is empty.
			if(all.length == 0) {
				if(logMINOR) Logger.minor(this, "None to wait for on "+this);
				return null;
			}
			// Double-check before blocking, prevent race condition.
			long now = System.currentTimeMillis();
			boolean anyValid = false;
			for(PeerNode p : all) {
				if((!p.isRoutable()) || p.isInMandatoryBackoff(now, realTime)) {
					if(logMINOR) Logger.minor(this, "Peer is not valid in waitForAny(): "+p);
					continue;
				}
				anyValid = true;
				RequestLikelyAcceptedState accept = p.outputLoadTracker(realTime).tryRouteTo(tag, RequestLikelyAcceptedState.LIKELY, offeredKey);
				if(accept != null) {
					if(logMINOR) Logger.minor(this, "tryRouteTo() pre-wait check returned "+accept);
					PeerNode[] unreg;
					PeerNode other = null;
					synchronized(this) {
						if(logMINOR) Logger.minor(this, "tryRouteTo() succeeded to "+p+" on "+this+" with "+accept+" - checking whether we have already accepted.");
						unreg = innerOnWaited(p, accept);
						if(unreg == null) {
							// Recover from race condition.
							if(shouldGrab()) other = grab();
						}
						if(other == null) {
							if(logMINOR) Logger.minor(this, "Trying the original tryRouteTo() on "+this);
							// Having set the acceptedBy etc, clear it now.
							acceptedBy = null;
							failed = false;
							fe = null;
						}						
						tag.clearWaitingForSlot();
					}
					unregister(null, unreg);
					if(other != null) {
						Logger.normal(this, "Race condition: tryRouteTo() succeeded on "+p.shortToString()+" but already matched on "+other.shortToString()+" on "+this);
						tag.removeRoutingTo(p);
						return other;
					}
					p.outputLoadTracker(realTime).reportAllocated(isLocal());
					// p != null so in this one instance we're going to ignore fe.
					return p;
				}
			}
			if(maxWait == 0) return null;
			// Don't need to clear waiting here because we are still waiting.
			if(!anyValid) {
				synchronized(this) {
					if(fe != null) {
						f = fe;
						fe = null;
					}
					if(shouldGrab()) ret = grab();
					all = waitingFor.toArray(new PeerNode[waitingFor.size()]);
					waitingFor.clear();
					failed = false;
					acceptedBy = null;
				}
				if(logMINOR) Logger.minor(this, "None valid to wait for on "+this);
				unregister(ret, all);
				if(f != null && ret == null) throw f;
				tag.clearWaitingForSlot();
				return ret;
			}
			synchronized(this) {
				if(logMINOR) Logger.minor(this, "Waiting for any node to wake up "+this+" : "+Arrays.toString(waitingFor.toArray())+" (for up to "+maxWait+"ms)");
				long waitStart = System.currentTimeMillis();
				long deadline = waitStart + maxWait;
				boolean timedOut = false;
				while(acceptedBy == null && (!waitingFor.isEmpty()) && !failed) {
					try {
						if(maxWait == Long.MAX_VALUE)
							wait();
						else {
							int wait = (int)Math.min(Integer.MAX_VALUE, deadline - System.currentTimeMillis());
							if(wait > 0) wait(wait);
							if(logMINOR) Logger.minor(this, "Maximum wait time exceeded on "+this);
							if(shouldGrab()) {
								// Race condition resulting in stalling
								// All we have to do is break.
								break;
							} else {
								// Bigger problem.
								// No external entity called us, so waitingFor have not been unregistered.
								timedOut = true;
								all = waitingFor.toArray(new PeerNode[waitingFor.size()]);
								waitingFor.clear();
								break;
								// Now no callers will succeed.
								// But we still need to unregister the waitingFor's or they will stick around until they are matched, and then, if we are unlucky, will lock a slot on the RequestTag forever and thus cause a catastrophic stall of the whole peer.
							}
						}
					} catch (InterruptedException e) {
						// Ignore
					}
				}
				if(!timedOut) {
					long waitEnd = System.currentTimeMillis();
					if(waitEnd - waitStart > (realTime ? 6000 : 60000)) {
						Logger.warning(this, "Waited "+(waitEnd - waitStart)+"ms for "+this);
					} else if(waitEnd - waitStart > (realTime ? 1000 : 10000)) {
						Logger.normal(this, "Waited "+(waitEnd - waitStart)+"ms for "+this);
					} else {
						if(logMINOR) Logger.minor(this, "Waited "+(waitEnd - waitStart)+"ms for "+this);
					}
				}
				if(logMINOR) Logger.minor(this, "Returning after waiting: accepted by "+acceptedBy+" waiting for "+waitingFor.size()+" failed "+failed+" on "+this);
				ret = acceptedBy;
				acceptedBy = null; // Allow for it to wait again if necessary
				all = waitingFor.toArray(new PeerNode[waitingFor.size()]);
				waitingFor.clear();
				failed = false;
				fe = null;
				tag.clearWaitingForSlot();
			}
			if(timeOutIsFatal && all != null) {
				for(PeerNode pn : all) {
					pn.outputLoadTracker(realTime).reportFatalTimeoutInWait(isLocal());
				}
			}
			unregister(ret, all);
			return ret;
		}
		
		final boolean isLocal() {
			return source == null;
		}
		
		private boolean shouldGrab() {
			return acceptedBy != null || waitingFor.isEmpty() || failed;
		}

		private synchronized PeerNode grab() {
			if(logMINOR) Logger.minor(this, "Returning in first check: accepted by "+acceptedBy+" waiting for "+waitingFor.size()+" failed "+failed+" accepted state "+acceptedState);
			failed = false;
			PeerNode got = acceptedBy;
			acceptedBy = null; // Allow for it to wait again if necessary
			return got;
		}

		public synchronized RequestLikelyAcceptedState getAcceptedState() {
			return acceptedState;
		}
		
		@Override
		public String toString() {
			return super.toString()+":"+counter+":"+requestType+":"+realTime;
		}
		
		public synchronized int waitingForCount() {
			return waitingFor.size();
		}

	}
	
	@SuppressWarnings("serial")
	static class SlotWaiterFailedException extends Exception {
		final PeerNode pn;
		final boolean fatal;
		SlotWaiterFailedException(PeerNode p, boolean f) {
			this.pn = p;
			this.fatal = f;
			// FIXME OPTIMISATION: arrange for empty stack trace
		}
	}
	
	static class SlotWaiterList {
		
		private final LinkedHashMap<PeerNode, TreeMap<Long, SlotWaiter>> lru =
			new LinkedHashMap<PeerNode, TreeMap<Long, SlotWaiter>>();

		public synchronized void put(SlotWaiter waiter) {
			PeerNode source = waiter.source;
			TreeMap<Long, SlotWaiter> map = lru.get(source);
			if(map == null) {
				lru.put(source, map = new TreeMap<Long, SlotWaiter>());
			}
			map.put(waiter.counter, waiter);
		}

		public synchronized void remove(SlotWaiter waiter) {
			PeerNode source = waiter.source;
			TreeMap<Long, SlotWaiter> map = lru.get(source);
			if(map == null) {
				if(logMINOR) Logger.minor(this, "SlotWaiter "+waiter+" was not queued");
				return;
			}
			map.remove(waiter.counter);
			if(map.isEmpty())
				lru.remove(source);
		}

		public synchronized boolean isEmpty() {
			return lru.isEmpty();
		}

		public synchronized SlotWaiter removeFirst() {
			if(lru.isEmpty()) return null;
			// FIXME better to use LRUMap?
			// Would need to update it to use Iterator and other modern APIs in values(), and creating two objects here isn't THAT expensive on modern VMs...
			PeerNode source = lru.keySet().iterator().next();
			TreeMap<Long, SlotWaiter> map = lru.get(source);
			Long key = map.firstKey();
			SlotWaiter ret = map.get(key);
			map.remove(key);
			lru.remove(source);
			if(!map.isEmpty())
				lru.put(source, map);
			return ret;
		}

		public synchronized ArrayList<SlotWaiter> values() {
			ArrayList<SlotWaiter> list = new ArrayList<SlotWaiter>();
			for(TreeMap<Long, SlotWaiter> map : lru.values()) {
				list.addAll(map.values());
			}
			return list;
		}
		
		public String toString() {
			return super.toString()+":peers="+lru.size();
		}
		
	}
	

	/** cached RequestType.values(). Never modify or pass this array to outside code! */
	private static final RequestType[] RequestType_values = RequestType.values();

	/** Uses the information we receive on the load on the target node to determine whether
	 * we can route to it and when we can route to it.
	 */
	class OutputLoadTracker {
		
		final boolean realTime;
		
		private PeerLoadStats lastIncomingLoadStats;
		
		private boolean dontSendUnlessGuaranteed;
		
		// These only count remote timeouts.
		// Strictly local and remote should be the same in new load management, but
		// local often produces more load than can be handled by our peers.
		// Fair sharing in SlotWaiterList ensures that this doesn't cause excessive
		// timeouts for others, but we want the stats that determine their RecentlyFailed
		// times to be based on remote requests only. Also, local requests by definition
		// do not cause downstream problems.
		private long totalFatalTimeouts;
		private long totalAllocated;
		
		public void reportLoadStatus(PeerLoadStats stat) {
			if(logMINOR) Logger.minor(this, "Got load status : "+stat);
			synchronized(routedToLock) {
				lastIncomingLoadStats = stat;
			}
			maybeNotifySlotWaiter();
		}
		
		synchronized /* lock only used for counter */ void reportFatalTimeoutInWait(boolean local) {
			if(!local)
				totalFatalTimeouts++;
			node.nodeStats.reportFatalTimeoutInWait(local);
		}

		synchronized /* lock only used for counter */ void reportAllocated(boolean local) {
			if(!local)
				totalAllocated++;
			node.nodeStats.reportAllocatedSlot(local);
		}
		
		public synchronized double proportionTimingOutFatallyInWait() {
			if(totalFatalTimeouts == 1 && totalAllocated == 0) return 0.5; // Limit impact if the first one is rejected.
			return (double)totalFatalTimeouts / ((double)(totalFatalTimeouts + totalAllocated));
		}

		public PeerLoadStats getLastIncomingLoadStats() {
			synchronized(routedToLock) {
				return lastIncomingLoadStats;
			}
		}
		
		OutputLoadTracker(boolean realTime) {
			this.realTime = realTime;
		}
		
		public IncomingLoadSummaryStats getIncomingLoadStats() {
			PeerLoadStats loadStats;
			synchronized(routedToLock) {
				if(lastIncomingLoadStats == null) return null;
				loadStats = lastIncomingLoadStats;
			}
			RunningRequestsSnapshot runningRequests = node.nodeStats.getRunningRequestsTo(PeerNode.this, loadStats.averageTransfersOutPerInsert, realTime);
			RunningRequestsSnapshot otherRunningRequests = loadStats.getOtherRunningRequests();
			boolean ignoreLocalVsRemoteBandwidthLiability = node.nodeStats.ignoreLocalVsRemoteBandwidthLiability();
			return new IncomingLoadSummaryStats(runningRequests.totalRequests(), 
					loadStats.outputBandwidthPeerLimit, loadStats.inputBandwidthPeerLimit,
					loadStats.outputBandwidthUpperLimit, loadStats.inputBandwidthUpperLimit,
					runningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, false),
					runningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, true),
					otherRunningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, false),
					otherRunningRequests.calculate(ignoreLocalVsRemoteBandwidthLiability, true));
		}
		
		/** Can we route the tag to this peer? If so (including if we are accepting because
		 * we don't have any load stats), and we haven't already, addRoutedTo() and return 
		 * the accepted state. Otherwise return null. */
		public RequestLikelyAcceptedState tryRouteTo(UIDTag tag,
				RequestLikelyAcceptedState worstAcceptable, boolean offeredKey) {
			PeerLoadStats loadStats;
			boolean ignoreLocalVsRemote = node.nodeStats.ignoreLocalVsRemoteBandwidthLiability();
			if(!isRoutable()) return null;
			if(isInMandatoryBackoff(System.currentTimeMillis(), realTime)) return null;
			synchronized(routedToLock) {
				loadStats = lastIncomingLoadStats;
				if(loadStats == null) {
					Logger.error(this, "Accepting because no load stats from "+PeerNode.this.shortToString()+" ("+PeerNode.this.getVersionNumber()+")");
					if(tag.addRoutedTo(PeerNode.this, offeredKey)) {
						// FIXME maybe wait a bit, check the other side's version first???
						return RequestLikelyAcceptedState.UNKNOWN;
					} else return null;
				}
				if(dontSendUnlessGuaranteed)
					worstAcceptable = RequestLikelyAcceptedState.GUARANTEED;
				// Requests already running to this node
				RunningRequestsSnapshot runningRequests = node.nodeStats.getRunningRequestsTo(PeerNode.this, loadStats.averageTransfersOutPerInsert, realTime);
				runningRequests.log(PeerNode.this);
				// Requests running from its other peers
				RunningRequestsSnapshot otherRunningRequests = loadStats.getOtherRunningRequests();
				RequestLikelyAcceptedState acceptState = getRequestLikelyAcceptedState(runningRequests, otherRunningRequests, ignoreLocalVsRemote, loadStats);
				if(logMINOR) Logger.minor(this, "Predicted acceptance state for request: "+acceptState+" must beat "+worstAcceptable);
				if(acceptState.ordinal() > worstAcceptable.ordinal()) return null;
				if(tag.addRoutedTo(PeerNode.this, offeredKey))
					return acceptState;
				else {
					if(logMINOR) Logger.minor(this, "Already routed to peer");
					return null;
				}
			}
		}
		
		// FIXME on capacity changing so that we should add another node???
		// FIXME on backoff so that we should add another node???
		
		private final EnumMap<RequestType,SlotWaiterList> slotWaiters = new EnumMap<RequestType,SlotWaiterList>(RequestType.class);
		
		boolean queueSlotWaiter(SlotWaiter waiter) {
			if(!isRoutable()) {
				if(logMINOR) Logger.minor(this, "Not routable, so not queueing");
				return false;
			}
			if(isInMandatoryBackoff(System.currentTimeMillis(), realTime)) {
				if(logMINOR) Logger.minor(this, "In mandatory backoff, so not queueing");
				return false;
			}
			boolean noLoadStats = false;
			PeerNode[] all = null;
			boolean queued = false;
			synchronized(routedToLock) {
				noLoadStats = (this.lastIncomingLoadStats == null);
				if(!noLoadStats) {
					SlotWaiterList list = makeSlotWaiters(waiter.requestType);
					list.put(waiter);
					if(logMINOR) Logger.minor(this, "Queued slot "+waiter+" waiter for "+waiter.requestType+" on "+list+" on "+this+" for "+PeerNode.this);
					queued = true;
				} else {
					if(logMINOR) Logger.minor(this, "Not waiting for "+this+" as no load stats");
					all = waiter.innerOnWaited(PeerNode.this, RequestLikelyAcceptedState.UNKNOWN);
				}
			}
			if(all != null) {
				reportAllocated(waiter.isLocal());
				waiter.unregister(null, all);
			} else if(queued) {
				if((!isRoutable()) || (isInMandatoryBackoff(System.currentTimeMillis(), realTime))) {
					// Has lost connection etc since start of the method.
					if(logMINOR) Logger.minor(this, "Queued but not routable or in mandatory backoff, failing");
					waiter.onFailed(PeerNode.this, true);
					return false;
				}
			}
			return true;
		}
		
		private SlotWaiterList makeSlotWaiters(RequestType requestType) {
			SlotWaiterList slots = slotWaiters.get(requestType);
			if(slots == null) {
				slots = new SlotWaiterList();
				slotWaiters.put(requestType, slots);
			}
			return slots;
		}
		
		void unqueueSlotWaiter(SlotWaiter waiter) {
			synchronized(routedToLock) {
				SlotWaiterList map = slotWaiters.get(waiter.requestType);
				if(map == null) return;
				map.remove(waiter);
			}
		}
		
		private void failSlotWaiters(boolean reallyFailed) {
			for(RequestType type : RequestType_values) {
				SlotWaiterList slots; 
				synchronized(routedToLock) {
					slots = slotWaiters.get(type);
					if(slots == null) continue;
					slotWaiters.remove(type);
				}
				for(SlotWaiter w : slots.values())
					w.onFailed(PeerNode.this, reallyFailed);
			}
		}
		
		private int slotWaiterTypeCounter = 0;

		private void maybeNotifySlotWaiter() {
			if(!isRoutable()) return;
			boolean ignoreLocalVsRemote = node.nodeStats.ignoreLocalVsRemoteBandwidthLiability();
			if(logMINOR) Logger.minor(this, "Maybe waking up slot waiters for "+this+" realtime="+realTime+" for "+PeerNode.this.shortToString());
			while(true) {
				boolean foundNone = true;
				int typeNum;
				PeerLoadStats loadStats;
				synchronized(routedToLock) {
					loadStats = lastIncomingLoadStats;
					if(slotWaiters.isEmpty()) {
						if(logMINOR) Logger.minor(this, "No slot waiters for "+this);
						return;
					}
					typeNum = slotWaiterTypeCounter;
				}
				typeNum++;
				if(typeNum == RequestType_values.length)
					typeNum = 0;
				for(int i=0;i<RequestType_values.length;i++) {
					SlotWaiterList list;
					RequestType type = RequestType_values[typeNum];
					if(logMINOR) Logger.minor(this, "Checking slot waiter list for "+type);
					SlotWaiter slot;
					RequestLikelyAcceptedState acceptState;
					PeerNode[] peersForSuccessfulSlot;
					synchronized(routedToLock) {
						list = slotWaiters.get(type);
						if(list == null) {
							if(logMINOR) Logger.minor(this, "No list");
							typeNum++;
							if(typeNum == RequestType_values.length)
								typeNum = 0;
							continue;
						}
						if(list.isEmpty()) {
							if(logMINOR) Logger.minor(this, "List empty");
							typeNum++;
							if(typeNum == RequestType_values.length)
								typeNum = 0;
							continue;
						}
						if(logMINOR) Logger.minor(this, "Checking slot waiters for "+type);
						foundNone = false;
						// Requests already running to this node
						RunningRequestsSnapshot runningRequests = node.nodeStats.getRunningRequestsTo(PeerNode.this, loadStats.averageTransfersOutPerInsert, realTime);
						runningRequests.log(PeerNode.this);
						// Requests running from its other peers
						RunningRequestsSnapshot otherRunningRequests = loadStats.getOtherRunningRequests();
						acceptState = getRequestLikelyAcceptedState(runningRequests, otherRunningRequests, ignoreLocalVsRemote, loadStats);
						if(acceptState == null || acceptState == RequestLikelyAcceptedState.UNLIKELY) {
							if(logMINOR) Logger.minor(this, "Accept state is "+acceptState+" - not waking up - type is "+type);
							return;
						}
						if(dontSendUnlessGuaranteed && acceptState != RequestLikelyAcceptedState.GUARANTEED) {
							if(logMINOR) Logger.minor(this, "Not accepting until guaranteed for "+PeerNode.this+" realtime="+realTime);
							return;
						}
						if(list.isEmpty()) continue;
						slot = list.removeFirst();
						if(logMINOR) Logger.minor(this, "Accept state is "+acceptState+" for "+slot+" - waking up on "+this);
						peersForSuccessfulSlot = slot.innerOnWaited(PeerNode.this, acceptState);
						if(peersForSuccessfulSlot == null) continue;
						reportAllocated(slot.isLocal());
						slotWaiterTypeCounter = typeNum;
					}
					slot.unregister(PeerNode.this, peersForSuccessfulSlot);
					if(logMINOR) Logger.minor(this, "Accept state is "+acceptState+" for "+slot+" - waking up");
					typeNum++;
					if(typeNum == RequestType_values.length)
						typeNum = 0;
				}
				if(foundNone) {
					return;
				}
			}
		}
		
		/** LOCKING: Call inside routedToLock 
		 * @param otherRunningRequests 
		 * @param runningRequests 
		 * @param byteCountersInput 
		 * @param byteCountersOutput */
		private RequestLikelyAcceptedState getRequestLikelyAcceptedState(RunningRequestsSnapshot runningRequests, RunningRequestsSnapshot otherRunningRequests, boolean ignoreLocalVsRemote, PeerLoadStats stats) {
			RequestLikelyAcceptedState outputState = getRequestLikelyAcceptedStateBandwidth(false, runningRequests, otherRunningRequests, ignoreLocalVsRemote, stats);
			RequestLikelyAcceptedState inputState = getRequestLikelyAcceptedStateBandwidth(true, runningRequests, otherRunningRequests, ignoreLocalVsRemote, stats);
			RequestLikelyAcceptedState transfersState = getRequestLikelyAcceptedStateTransfers(runningRequests, otherRunningRequests, ignoreLocalVsRemote, stats);
			RequestLikelyAcceptedState ret = inputState;
			
			if(outputState.ordinal() > ret.ordinal())
				ret = outputState;
			if(transfersState.ordinal() > ret.ordinal())
				ret = transfersState;
			return ret;
		}
		
		private RequestLikelyAcceptedState getRequestLikelyAcceptedStateBandwidth(
				boolean input,
				RunningRequestsSnapshot runningRequests,
				RunningRequestsSnapshot otherRunningRequests, boolean ignoreLocalVsRemote, 
				PeerLoadStats stats) {
			double ourUsage = runningRequests.calculate(ignoreLocalVsRemote, input);
			if(logMINOR) Logger.minor(this, "Our usage is "+ourUsage+" peer limit is "+stats.peerLimit(input)+" lower limit is "+stats.lowerLimit(input)+" realtime "+realTime+" input "+input);
			if(ourUsage < stats.peerLimit(input))
				return RequestLikelyAcceptedState.GUARANTEED;
			otherRunningRequests.log(PeerNode.this);
			double theirUsage = otherRunningRequests.calculate(ignoreLocalVsRemote, input);
			if(logMINOR) Logger.minor(this, "Their usage is "+theirUsage);
			if(ourUsage + theirUsage < stats.lowerLimit(input))
				return RequestLikelyAcceptedState.LIKELY;
			else
				return RequestLikelyAcceptedState.UNLIKELY;
		}

		private RequestLikelyAcceptedState getRequestLikelyAcceptedStateTransfers(
				RunningRequestsSnapshot runningRequests,
				RunningRequestsSnapshot otherRunningRequests, boolean ignoreLocalVsRemote, 
				PeerLoadStats stats) {
			
			int ourUsage = runningRequests.totalOutTransfers();
			int maxTransfersOutPeerLimit = Math.min(stats.maxTransfersOutPeerLimit, stats.maxTransfersOut);
			if(logMINOR) Logger.minor(this, "Our usage is "+ourUsage+" peer limit is "+maxTransfersOutPeerLimit
					+" lower limit is "+stats.maxTransfersOutLowerLimit+" realtime "+realTime);
			if(ourUsage < maxTransfersOutPeerLimit)
				return RequestLikelyAcceptedState.GUARANTEED;
			otherRunningRequests.log(PeerNode.this);
			int theirUsage = otherRunningRequests.totalOutTransfers();
			if(logMINOR) Logger.minor(this, "Their usage is "+theirUsage);
			if(ourUsage + theirUsage < stats.maxTransfersOutLowerLimit)
				return RequestLikelyAcceptedState.LIKELY;
			else
				return RequestLikelyAcceptedState.UNLIKELY;
		}

		public void setDontSendUnlessGuaranteed() {
			synchronized(routedToLock) {
				if(!dontSendUnlessGuaranteed) {
					Logger.error(this, "Setting don't-send-unless-guaranteed for "+PeerNode.this+" realtime="+realTime);
					dontSendUnlessGuaranteed = true;
				}
			}
		}

		public void clearDontSendUnlessGuaranteed() {
			synchronized(routedToLock) {
				if(dontSendUnlessGuaranteed) {
					Logger.error(this, "Clearing don't-send-unless-guaranteed for "+PeerNode.this+" realtime="+realTime);
					dontSendUnlessGuaranteed = false;
				}
			}
		}
	
	}
	
	public void noLongerRoutingTo(UIDTag tag, boolean offeredKey) {
		if(offeredKey && !(tag instanceof RequestTag))
			throw new IllegalArgumentException("Only requests can have offeredKey=true");
		synchronized(routedToLock) {
			if(offeredKey)
				tag.removeFetchingOfferedKeyFrom(this);
			else
				tag.removeRoutingTo(this);
		}
		if(logMINOR) Logger.minor(this, "No longer routing "+tag+" to "+this);
		outputLoadTracker(tag.realTimeFlag).maybeNotifySlotWaiter();
	}
	
	public void postUnlock(UIDTag tag) {
		outputLoadTracker(tag.realTimeFlag).maybeNotifySlotWaiter();
	}
	
	static SlotWaiter createSlotWaiter(UIDTag tag, RequestType type, boolean offeredKey, boolean realTime, PeerNode source) {
		return new SlotWaiter(tag, type, offeredKey, realTime, source);
	}

	public IncomingLoadSummaryStats getIncomingLoadStats(boolean realTime) {
		return outputLoadTracker(realTime).getIncomingLoadStats();
	}

	public LoadSender loadSender(boolean realtime) {
		return realtime ? loadSenderRealTime : loadSenderBulk;
	}
	
	/** A fatal timeout occurred, and we don't know whether the peer is still running the
	 * request we passed in for us. If it is, we cannot reuse that slot. So we need to
	 * query it periodically until it is no longer running it. If we cannot send the query
	 * or if we don't get a response, we disconnect via fatalTimeout() (with no arguments).
	 * @param tag The request which we routed to this peer. It may or may not still be
	 * running.
	 */
	public void fatalTimeout(UIDTag tag, boolean offeredKey) {
		// FIXME implement! For now we just disconnect (no-op).
		// A proper implementation requires new messages.
		noLongerRoutingTo(tag, offeredKey);
		fatalTimeout();
	}
	
	/** After a fatal timeout - that is, a timeout that we reasonably believe originated
	 * on the node rather than downstream - we do not know whether or not the node thinks
	 * the request is still running. Hence load management will get really confused and 
	 * likely start to send requests over and over, which are repeatedly rejected.
	 * 
	 * So we have some alternatives: 
	 * 1) Lock the slot forever (or at least until the node reconnects). So every time a
	 * node times out, it loses a slot, and gradually it becomes completely catatonic.
	 * 2) Wait forever for an acknowledgement of the timeout. This may be worth 
	 * investigating. One problem with this is that the slot would still count towards our
	 * overall load management, which is surely a bad thing, although we could make it 
	 * only count towards this node. Also, if it doesn't arrive in a reasonable time maybe
	 * there has been a severe problem e.g. out of memory, bug etc; in that case, waiting
	 * forever may not be sensible.
	 * 3) Disconnect the node. This makes perfect sense for opennet. For darknet it's a 
	 * bit more problematic.
	 * 4) Turn off routing to the node, possibly for a limited period. This would need to
	 * include the effects of disconnection. It might open up some cheapish local DoS's.
	 * 
	 * For all nodes, at present, we disconnect. For darknet nodes, we log an error, and 
	 * allow them to reconnect. */
	public abstract void fatalTimeout();
	
	public abstract boolean shallWeRouteAccordingToOurPeersLocation();
	
	@Override
	public PeerMessageQueue getMessageQueue() {
		return messageQueue;
	}

	public boolean handleReceivedPacket(byte[] buf, int offset, int length, long now, Peer replyTo) {
		PacketFormat pf;
		synchronized(this) {
			pf = packetFormat;
			if(pf == null) return false;
		}
		return pf.handleReceivedPacket(buf, offset, length, now, replyTo);
	}

	public void checkForLostPackets() {
		PacketFormat pf;
		synchronized(this) {
			pf = packetFormat;
			if(pf == null) return;
		}
		pf.checkForLostPackets();
	}

	public long timeCheckForLostPackets() {
		PacketFormat pf;
		synchronized(this) {
			pf = packetFormat;
			if(pf == null) return Long.MAX_VALUE;
		}
		return pf.timeCheckForLostPackets();
	}
	
	public void setAcknowledgeType(int negType) {
		useCumulativeAcks = (negType >= 10);
	}
	
	@Override
	public boolean isUseCumulativeAcksSet() {
		return useCumulativeAcks;
	}

	/** Only called for new format connections, for which we don't care about PacketTracker */
	public void dumpTracker(SessionKey brokenKey) {
		long now = System.currentTimeMillis();
		synchronized(this) {
			if(currentTracker == brokenKey) {
				currentTracker = null;
				isConnected.set(false, now);
			} else if(previousTracker == brokenKey)
				previousTracker = null;
			else if(unverifiedTracker == brokenKey)
				unverifiedTracker = null;
		}
		// Update connected vs not connected status.
		isConnected();
		setPeerNodeStatus(System.currentTimeMillis());
	}
	
	@Override
	public void handleMessage(Message m) {
		node.usm.checkFilters(m, crypto.socket);
	}

	@Override
	public void sendEncryptedPacket(byte[] data) throws LocalAddressException {
		crypto.socket.sendPacket(data, getPeer(), allowLocalAddresses());
	}
	
	@Override
	public int getMaxPacketSize() {
		return crypto.socket.getMaxPacketSize();
	}
	
	@Override
	public boolean shouldPadDataPackets() {
		return crypto.config.paddDataPackets();
	}
	
	@Override
	public void sentThrottledBytes(int count) {
		node.outputThrottle.forceGrab(count);
	}
	
	@Override
	public void onNotificationOnlyPacketSent(int length) {
		node.nodeStats.reportNotificationOnlyPacketSent(length);
	}
	
	@Override
	public void resentBytes(int length) {
		resendByteCounter.sentBytes(length);
	}
	
	// FIXME move this to PacketFormat eventually.
	@Override
	public Random paddingGen() {
		return paddingGen;
	}

	public synchronized boolean matchesPeerAndPort(Peer peer) {
		if(detectedPeer != null && detectedPeer.laxEquals(peer)) return true;
		if(nominalPeer != null) { // FIXME condition necessary???
			for(Peer p : nominalPeer) {
				if(p != null && p.laxEquals(peer)) return true;
			}
		}
		return false;
	}

	/** Does this PeerNode match the given IP address? 
	 * @param strict If true, only match if the IP is actually in use. If false,
	 * also match from nominal IP addresses and domain names etc. */
	public synchronized boolean matchesIP(FreenetInetAddress addr, boolean strict) {
		if(detectedPeer != null) {
			FreenetInetAddress a = detectedPeer.getFreenetAddress();
			if(a != null) {
				if(strict ? a.equals(addr) : a.laxEquals(addr))
					return true;
			}
		}
		if((!strict) && nominalPeer != null) {
			for(Peer p : nominalPeer) {
				if(p == null) continue;
				FreenetInetAddress a = p.getFreenetAddress();
				if(a == null) continue;
				if(a.laxEquals(addr)) return true;
			}
		}
		return false;
	}
	
	@Override
	public MessageItem makeLoadStats(boolean realtime, boolean boostPriority, boolean noRemember) {
	    // FIXME re-enable when try NLM again.
	    return null;
//		Message msg = loadSender(realtime).makeLoadStats(System.currentTimeMillis(), node.nodeStats.outwardTransfersPerInsert(), noRemember);
//		if(msg == null) return null;
//		return new MessageItem(msg, null, node.nodeStats.allocationNoticesCounter, boostPriority ? DMT.PRIORITY_NOW : (short)-1);
	}

	@Override
	public boolean grabSendLoadStatsASAP(boolean realtime) {
		return loadSender(realtime).grabSendASAP();
	}

	@Override
	public void setSendLoadStatsASAP(boolean realtime) {
		loadSender(realtime).setSendASAP();
	}
	
	@Override
	public DecodingMessageGroup startProcessingDecryptedMessages(int size) {
		return new MyDecodingMessageGroup(size);
	}
	
	class MyDecodingMessageGroup implements DecodingMessageGroup {

		private final ArrayList<Message> messages;
		private final ArrayList<Message> messagesWantSomething;
		
		public MyDecodingMessageGroup(int size) {
			messages = new ArrayList<Message>(size);
			messagesWantSomething = new ArrayList<Message>(size);
		}

		@Override
		public void processDecryptedMessage(byte[] data, int offset,
				int length, int overhead) {
			Message m = node.usm.decodeSingleMessage(data, offset, length, PeerNode.this, overhead);
			if(m == null) {
				if(logMINOR) Logger.minor(this, "Message not decoded from "+PeerNode.this+" ("+PeerNode.this.getVersionNumber()+")");
				return;
			}
			if(DMT.isPeerLoadStatusMessage(m)) {
				handleMessage(m);
				return;
			}
			if(DMT.isLoadLimitedRequest(m)) {
				messagesWantSomething.add(m);
			} else {
				messages.add(m);
			}
		}

		@Override
		public void complete() {
			for(Message msg : messages) {
				handleMessage(msg);
			}
			for(Message msg : messagesWantSomething) {
				handleMessage(msg);
			}
		}
		
	}
	
	public boolean isLowCapacity(boolean isRealtime) {
		PeerLoadStats stats = outputLoadTracker(isRealtime).getLastIncomingLoadStats();
		if(stats == null) return false;
		NodePinger pinger = node.nodeStats.nodePinger;
		if(pinger == null) return false; // FIXME possible?
		if(pinger.capacityThreshold(isRealtime, true) > stats.peerLimit(true)) return true;
		if(pinger.capacityThreshold(isRealtime, false) > stats.peerLimit(false)) return true;
		return false;
	}

	public void reportRoutedTo(double target, boolean isLocal, boolean realTime, PeerNode prev, Set<PeerNode> routedTo) {
		double distance = Location.distance(target, getLocation());
		
		double myLoc = node.getLocation();
		double prevLoc;
		if(prev != null)
			prevLoc = prev.getLocation();
		else
			prevLoc = -1.0;
		
		double[] peersLocation = getPeersLocation();
		if((peersLocation != null) && (shallWeRouteAccordingToOurPeersLocation())) {
			for(double l : peersLocation) {
				boolean ignoreLoc = false; // Because we've already been there
				if(Math.abs(l - myLoc) < Double.MIN_VALUE * 2 ||
						Math.abs(l - prevLoc) < Double.MIN_VALUE * 2)
					ignoreLoc = true;
				else {
					for(PeerNode cmpPN : routedTo)
						if(Math.abs(l - cmpPN.getLocation()) < Double.MIN_VALUE * 2) {
							ignoreLoc = true;
							break;
						}
				}
				if(ignoreLoc) continue;
				double newDiff = Location.distance(l, target);
				if(newDiff < distance) {
					distance = newDiff;
				}
			}
			if(logMINOR)
				Logger.minor(this, "The peer "+this+" has published his peer's locations and the closest we have found to the target is "+distance+" away.");
		}
		
		node.nodeStats.routingMissDistanceOverall.report(distance);
		(isLocal ? node.nodeStats.routingMissDistanceLocal : node.nodeStats.routingMissDistanceRemote).report(distance);
		(realTime ? node.nodeStats.routingMissDistanceRT : node.nodeStats.routingMissDistanceBulk).report(distance);
		node.peers.incrementSelectionSamples(System.currentTimeMillis(), this);
	}

	private long maxPeerPingTime() {
		if(node == null)
			return NodeStats.DEFAULT_MAX_PING_TIME * 2;
		NodeStats stats = node.nodeStats;
		if(node.nodeStats == null)
			return NodeStats.DEFAULT_MAX_PING_TIME * 2;
		else
			return stats.maxPeerPingTime();
	}
	
	/** Whether we are sending the main jar to this peer */
	protected boolean sendingUOMMainJar;
	/** Whether we are sending the ext jar (legacy) to this peer */
	protected boolean sendingUOMLegacyExtJar;
	/** The number of UOM transfers in progress to this peer.
	 * Note that there are mechanisms in UOM to limit this. */
	private int uomCount;
	/** The time when we last had UOM transfers in progress to this peer,
	 * if uomCount == 0. */
	private long lastSentUOM;
	// FIXME consider limiting the individual dependencies. 
	// Not clear whether that would actually improve protection against DoS, given that transfer failures happen naturally anyway.
	
	/** Start sending a UOM jar to this peer.
	 * @return True unless it was already sending, in which case the caller
	 * should reject it. */
	public synchronized boolean sendingUOMJar(boolean isExt) {
		if(isExt) {
			if(sendingUOMLegacyExtJar) return false;
			sendingUOMLegacyExtJar = true;
		} else {
			if(sendingUOMMainJar) return false;
			sendingUOMMainJar = true;
		}
		return true;
	}
	
	public synchronized void finishedSendingUOMJar(boolean isExt) {
		if(isExt) {
			sendingUOMLegacyExtJar = false;
			if(!(sendingUOMMainJar || uomCount > 0))
				lastSentUOM = System.currentTimeMillis();
		} else {
			sendingUOMMainJar = false;
			if(!(sendingUOMLegacyExtJar || uomCount > 0))
				lastSentUOM = System.currentTimeMillis();
		}
	}
	
	protected synchronized long timeSinceSentUOM() {
		if(sendingUOMMainJar || sendingUOMLegacyExtJar) return 0;
		if(uomCount > 0) return 0;
		if(lastSentUOM <= 0) return Long.MAX_VALUE;
		return System.currentTimeMillis() - lastSentUOM;
	}
	
	public synchronized void incrementUOMSends() {
		uomCount++;
	}
	
	public synchronized void decrementUOMSends() {
		uomCount--;
		if(uomCount == 0 && (!sendingUOMMainJar) && (!sendingUOMLegacyExtJar))
			lastSentUOM = System.currentTimeMillis();
	}

	/** Get the boot ID for purposes of the other node. This is set to a random number on
	 * startup, but also whenever we disconnected(true,...) i.e. whenever we dump the 
	 * message queues and PacketFormat's. */
	public synchronized long getOutgoingBootID() {
		return this.myBootID;
	}

	private long lastIncomingRekey;
	
	static final long THROTTLE_REKEY = 1000;
	
	public synchronized boolean throttleRekey() {
		long now = System.currentTimeMillis();
		if(now - lastIncomingRekey < THROTTLE_REKEY) {
			Logger.error(this, "Two rekeys initiated by other side within "+THROTTLE_REKEY+"ms");
			return true;
		}
		lastIncomingRekey = now;
		return false;
	}

	public boolean fullPacketQueued() {
		PacketFormat pf;
		synchronized(this) {
			pf = packetFormat;
			if(pf == null) return false;
		}
		return pf.fullPacketQueued(getMaxPacketSize());
	}

	public long timeSendAcks() {
		PacketFormat pf;
		synchronized(this) {
			pf = packetFormat;
			if(pf == null) return Long.MAX_VALUE;
		}
		return pf.timeSendAcks();
	}
	
	/** Calculate the maximum number of outgoing transfers to this peer that we
	 * will accept in requests and inserts. */
	public int calculateMaxTransfersOut(int timeout, double nonOverheadFraction) {
		// First get usable bandwidth.
		double bandwidth = (getThrottle().getBandwidth()+1.0);
		if(shouldThrottle())
			bandwidth = Math.min(bandwidth, node.getOutputBandwidthLimit() / 2);
		bandwidth *= nonOverheadFraction;
		// Transfers are divided into packets. Packets are 1KB. There are 1-2
		// of these for SSKs and 32 of them for CHKs, but that's irrelevant here.
		// We are only concerned here with the time that a transfer will have to
		// wait after sending a packet for it to have an opportunity to send 
		// another one. Or equivalently the delay between starting and sending 
		// the first packet.
		double packetsPerSecond = bandwidth / 1024.0;
		return (int)Math.max(1, Math.min(packetsPerSecond * timeout, Integer.MAX_VALUE));
	}

	public synchronized boolean hasFullNoderef() {
		return fullFieldSet != null;
	}
	
	public synchronized SimpleFieldSet getFullNoderef() {
		return fullFieldSet;
	}

	private int consecutiveGuaranteedRejectsRT = 0;
	private int consecutiveGuaranteedRejectsBulk = 0;

	private static final int CONSECUTIVE_REJECTS_MANDATORY_BACKOFF = 5;

	/** After 5 consecutive GUARANTEED soft rejections, we enter mandatory backoff.
	 * The reason why we don't immediately enter mandatory backoff is as follows:
	 * PROBLEM: Requests could have completed between the time when the request 
	 * was rejected and now.
	 * SOLUTION A: Tracking all possible requests which completed since the 
	 * request was sent. CON: This would be rather complex, and I'm not sure
	 * how well it would work when there are many requests in flight; would it
	 * even be possible without stopping sending requests after some arbitrary
	 * threshold? We might need a time element, and would probably need parameters...
	 * SOLUTION B: Enforcing a hard peer limit on both sides, as opposed to 
	 * accepting a request if the *current* usage, without the new request, is 
	 * over the limit. CON: This would break fairness between request types.
	 * 
	 * Of course, the problem with just using a counter is it may need to be 
	 * changed frequently ... FIXME create a better solution!
	 *
	 * Fortunately, this is pretty rare. It happens when e.g. we send an SSK,
	 * then we send a CHK, the messages are reordered and the CHK is accepted,
	 * and then the SSK is rejected. Both were GUARANTEED because if they 
	 * are accepted in order, thanks to the mechanism referred to in solution B,
	 * they will both be accepted.
	 */
	public void rejectedGuaranteed(boolean realTimeFlag) {
		synchronized(this) {
			if(realTimeFlag) {
				consecutiveGuaranteedRejectsRT++;
				if(consecutiveGuaranteedRejectsRT != CONSECUTIVE_REJECTS_MANDATORY_BACKOFF) {
					return;
				}
				consecutiveGuaranteedRejectsRT = 0;
			} else {
				consecutiveGuaranteedRejectsBulk++;
				if(consecutiveGuaranteedRejectsBulk != CONSECUTIVE_REJECTS_MANDATORY_BACKOFF) {
					return;
				}
				consecutiveGuaranteedRejectsBulk = 0;
			}
		}
		enterMandatoryBackoff("Mandatory:RejectedGUARANTEED", realTimeFlag);
	}

	/** Accepting a request, even if it was not GUARANTEED, resets the counters
	 * for consecutive guaranteed rejections. @see rejectedGuaranteed(boolean realTimeFlag).
	 */
	public void acceptedAny(boolean realTimeFlag) {
		synchronized(this) {
			if(realTimeFlag) {
				consecutiveGuaranteedRejectsRT = 0;
			} else {
				consecutiveGuaranteedRejectsBulk = 0;
			}
		}
	}
	
	/** @return The largest throttle window size of any of our throttles.
	 * This is just for guesstimating how many blocks we can have in flight. */
	@Override
	public int getThrottleWindowSize() {
		PacketThrottle throttle = getThrottle();
		if(throttle != null) return (int)(Math.min(throttle.getWindowSize(), Integer.MAX_VALUE));
		else return Integer.MAX_VALUE;
	}
	
	private boolean verifyReferenceSignature(SimpleFieldSet fs) throws ReferenceSignatureVerificationException {
	    // Assume we failed at validating
	    boolean failed = true;
	    String signature = fs.get("sig");
        String signatureP256 = fs.get("sigP256");
            try {
                // If we have:
                // - the new P256 signature AND the P256 pubkey
                // OR
                // - the old DSA signature the pubkey and the groups
                // THEN
                // verify the signatures
                fs.removeValue("sig");
                byte[] toVerifyDSA = fs.toOrderedString().getBytes("UTF-8");
                fs.removeValue("sigP256");
                byte[] toVerifyECDSA = fs.toOrderedString().getBytes("UTF-8");
                

                boolean isECDSAsigPresent = (signatureP256 != null && peerECDSAPubKey != null);
                boolean isDSAsigPresent = (signature != null && peerPubKey != null);
                boolean verifyECDSA = false; // assume it failed.
                boolean verifyDSA  = false; //assume it failed.
                
                // Is there a new ECDSA sig?
                if(isECDSAsigPresent) {
                        fs.putSingle("sigP256", signatureP256);
                        verifyECDSA = ECDSA.verify(Curves.P256, peerECDSAPubKey, Base64.decode(signatureP256), toVerifyECDSA);                       
                }
                
                // Is there an old DSA sig?
                if(isDSAsigPresent) {
                    fs.putSingle("sig", signature);
                    verifyDSA = DSA.verify(peerPubKey, new DSASignature(signature), new BigInteger(1, SHA256.digest(toVerifyDSA)), false);
                }

                // If there is no signature, FAIL
                // If there is an ECDSA signature, and it doesn't verify, FAIL
                // If there is a DSA signature, and it doesn't verify, FAIL
                boolean hasNoSignature = (!isECDSAsigPresent && !isDSAsigPresent);
                boolean isECDSAsigInvalid = (isECDSAsigPresent && !verifyECDSA);
                boolean isDSAsigInvalid = (isDSAsigPresent && !verifyDSA);
                failed = hasNoSignature || isECDSAsigInvalid || isDSAsigInvalid;
                if(failed) {
                    String errCause = "";
                    if(hasNoSignature)
                        errCause += " (No signature)";
                    if(peerCryptoGroup == null)
                        errCause += " (No peer crypto group)";
                    if(peerPubKey == null && peerECDSAPubKey == null)
                        errCause += " (No peer public key)";
                    if(isECDSAsigInvalid)
                        errCause += " (ECDSA signature is invalid)";
                    if(isDSAsigInvalid)
                        errCause += " (DSA signature is invalid)";
                    if(failed)
                        errCause += " (VERIFICATION FAILED)";
                    Logger.error(this, "The integrity of the reference has been compromised!" + errCause + " fs was\n" + fs.toOrderedString());
                    this.isSignatureVerificationSuccessfull = false;
                    throw new ReferenceSignatureVerificationException("The integrity of the reference has been compromised!" + errCause);
                } else {
                    this.isSignatureVerificationSuccessfull = true;
                    if(!dontKeepFullFieldSet())
                        this.fullFieldSet = fs;
                }
            } catch(NumberFormatException e) {
                Logger.error(this, "Invalid reference: " + e, e);
                throw new ReferenceSignatureVerificationException("The node reference you added is invalid: It does not have a valid DSA signature.");
            } catch(IllegalBase64Exception e) {
                Logger.error(this, "Invalid reference: " + e, e);
                throw new ReferenceSignatureVerificationException("The node reference you added is invalid: It does not have a valid ECDSA signature.");
            } catch(UnsupportedEncodingException e) {
                throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
            }
        return !failed;
	}
	
	protected byte[] getIdentity() {
	    return identity;
	}
	
	protected byte[] getIdentity(int negType) {
	    if(negType > 8)
	        return peerECDSAPubKeyHash;
	    else
	        return identity;
	}

	synchronized ECPublicKey peerECDSAPubKey() {
		// FIXME when negType 9 is mandatory, make peerECDSAPubKey final and remove this getter.
		return peerECDSAPubKey;
	}

	synchronized byte[] peerECDSAPubKeyHash() {
		// FIXME when negType 9 is mandatory, make peerECDSAPubKey final and remove this getter.
		return peerECDSAPubKeyHash;
	}
}
