/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.Enumeration;
import java.util.Map;

import freenet.crypt.Util;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.FreenetInetAddress;
import freenet.io.comm.Message;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.Peer;
import freenet.io.comm.PeerContext;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.io.comm.RetrievalException;
import freenet.io.comm.SlowAsyncMessageFilterCallback;
import freenet.io.xfer.BulkReceiver;
import freenet.io.xfer.BulkTransmitter;
import freenet.io.xfer.BulkTransmitter.AllSentCallback;
import freenet.io.xfer.PartiallyReceivedBulk;
import freenet.node.OpennetPeerNode.NOT_DROP_REASON;
import freenet.support.Fields;
import freenet.support.HTMLNode;
import freenet.support.LRUQueue;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.SimpleFieldSet;
import freenet.support.TimeSortedHashtable;
import freenet.support.io.ByteArrayRandomAccessBuffer;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import freenet.support.io.NativeThread;
import freenet.support.transport.ip.HostnameSyntaxException;
import freenet.support.transport.ip.IPUtil;

/**
 * Central location for all things opennet.
 * In particular:
 * - Opennet crypto
 * - LRU connections
 * 
 * Both here and in OpennetPeerNode there are lots of dubious heuristics to avoid excessive 
 * connection churn.
 * @author toad
 */
public class OpennetManager {

	final Node node;
	final NodeCrypto crypto;
	final Announcer announcer;
	final SeedAnnounceTracker seedTracker = new SeedAnnounceTracker();

	/* The routing table is split into "buckets" by distance, each of which has a separate LRU 
	 * list. For now there are only 2 buckets; the PETS paper suggested many buckets, but this 
	 * would have larger overhead, more dependence on the network size, and it is not clear that 
	 * it is necessary at the moment.
	 * 
	 * The measured global link length distribution showed a good (1/d) length distribution below 
	 * 0.01 (but nowhere near enough nodes) and a flat distribution above 0.01. Hence the choice of
	 * LONG_DISTANCE as 0.01. It appeared that there were very few short links (~ 15% less than 
	 * 0.01 distance) and a lot of random long links, which is the opposite of what we need for
	 * good routing, so requests would mostly bounce around randomly on the long links.
	 * 
	 * LONG_PROPORTION is chosen as 30% for two reasons: (a) It is close to the Kleinberg optimum 
	 * (around 20%), and (b) it ensures that nodes with 10 connections still have 3 long links, so 
	 * long links cannot form chains and the routing still scales if the short routing is broken.
	 * 
	 * See USK@ZLwcSLwqpM1527Tw1YmnSiXgzITU0neHQ11Cyl0iLmk,f6FLo3TvsEijIcJq-X3BTjjtm0ErVZwAPO7AUd9V7lY,AQACAAE/fix-link-length/7/
	 * (FIXME move to wiki or other permanent storage)
	 */
	/** Peers with more than this distance are considered "long links". */
	static final double LONG_DISTANCE = 0.01;
	/** This proportion of the routing table consists of "long links". */
	static final double LONG_PROPORTION = 0.3;
	/** The proportion of the routing table which consists of "short links". */
	public static final double SHORT_PROPORTION = 1.0 - LONG_PROPORTION;
	
    enum LinkLengthClass {
        /** Shorter than LONG_DISTANCE */
        SHORT {
            @Override
            public int getTargetPeers(int target) {
                int longPeers = (int) (target * LONG_PROPORTION);
                return target - longPeers;
            }
        },
        /** Longer than LONG_DISTANCE */
        LONG {
            @Override
            public int getTargetPeers(int target) {
                int longPeers = (int) (target * LONG_PROPORTION);
                return longPeers;
            }
        };
        /** Get the target number of peers for this class, given the overall target number of peers */
        public abstract int getTargetPeers(int target);
    }
    
    /** Peers LRUs by LinkLengthClass. PeerNodes are promoted within their LRU when they 
     * successfully fetch a key. Normally we take the bottom peer, but if that isn't eligible 
     * to be dropped, we iterate up the list. */
    private final EnumMap<LinkLengthClass, LRUQueue<OpennetPeerNode>> peersLRUByDistance;
	
	/** Old peers. Opennet peers which we dropped but would still like to talk to
	 * if we have no other option. */
	private final LRUQueue<OpennetPeerNode> oldPeers;
	/** Maximum number of old peers */
	static final int MAX_OLD_PEERS = 25;
	/** Time at which last dropped a peer due to an incoming connection of each type. */
	private final EnumMap<ConnectionType,Long> timeLastDropped;
	// These only count stuff where we actually have a node to add.
	private final EnumMap<ConnectionType,Long> connectionAttempts;
	private final EnumMap<ConnectionType,Long> connectionAttemptsAdded;
	private final EnumMap<ConnectionType,Long> connectionAttemptsAddedPlentySpace;
	private final EnumMap<ConnectionType,Long> connectionAttemptsRejectedByPerTypeEnforcement;
	private final EnumMap<ConnectionType,Long> connectionAttemptsRejectedNoPeersDroppable;
	/** Number of successful CHK requests since last added a node. All values are incremented on a 
	 * successful request, but when we add a node, we reset the value for that type of node. */
	private final EnumMap<ConnectionType,Long> successCount;

	/** Only drop a connection after at least this many successful requests.
	 * This is per connection type. */
	// FIXME should be a function of # opennet peers? max # opennet peers? ...
	public static final int MIN_SUCCESS_BETWEEN_DROP_CONNS = 10;
	/** Chance of resetting path folding (for plausible deniability) is 1 in this number. */
	public static final int RESET_PATH_FOLDING_PROB = 20;
	/** Don't re-add a node until it's been up and disconnected for at least this long */
	public static final long DONT_READD_TIME = MINUTES.toMillis(1);
	/** Don't drop a node until it's at least this old, if it's connected. */
	public static final long DROP_MIN_AGE = MINUTES.toMillis(5);
	/** Don't drop a node until it's at least this old, if it's not connected (if it has connected once then DROP_DISCONNECT_DELAY applies, but only once an hour as below). Must be less than DROP_MIN_AGE.
	 * Relatively generous because noderef transfers e.g. for announcement can be slow (Note
	 * that announcements actually wait for previous transfers!). */
	public static final long DROP_MIN_AGE_DISCONNECTED = MINUTES.toMillis(5);
	/** Don't drop a node until this long after startup */
	public static final long DROP_STARTUP_DELAY = MINUTES.toMillis(2);
	/** Don't drop a node until this long after losing connection to it.
	 * This should be long enough to cover a typical reboot, but not so long as to result in a lot
	 * of disconnected nodes in the Strangers list. Also it should probably not be longer than DROP_MIN_AGE! */
	public static final long DROP_DISCONNECT_DELAY = MINUTES.toMillis(5);
	/** But if it has disconnected more than once in this period, allow it to be dropped anyway */
	public static final long DROP_DISCONNECT_DELAY_COOLDOWN = MINUTES.toMillis(60);
	/** Every DROP_CONNECTED_TIME, we may drop a peer even though it is connected.
	 * This is per connection type, we should consider whether to reduce it further. */
	public static final long DROP_CONNECTED_TIME = MINUTES.toMillis(5);
	/** Minimum time between offers, if we have maximum peers. Less than the above limits,
	 * since an offer may not be accepted. */
	public static final long MIN_TIME_BETWEEN_OFFERS = SECONDS.toMillis(30);

	private static volatile boolean logMINOR;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	/** How big to pad opennet noderefs to? If they are bigger than this then we won't send them. */
	public static final int PADDED_NODEREF_SIZE = 3072;
	/** Allow for future expansion. However at any given time all noderefs should be PADDED_NODEREF_SIZE */
	public static final int MAX_OPENNET_NODEREF_LENGTH = 32768;

	/** Enable scaling of peers with bandwidth? */
	public static final boolean ENABLE_PEERS_PER_KB_OUTPUT = true;
	/** Constant for scaling peers: we multiply bandwidth in kB/sec by this
	 * and then take the square root. 12 gives 11 at 10K, 15 at 20K, 19 at
	 * 30K, 26 at 60K, 34 at 100K, 40 at 140K, 100 at 2500K.
	 * 212 at 30mbit/s (the mean upload in Japan in 2014) and
	 * 363 at 88mbit/s (the mean upload in Hong Kong in 2014).*/
	public static final double SCALING_CONSTANT = 12.0;
	/**
	 * Minimum number of peers. Do not reduce this: As a rough estimate, because the vast majority
	 * of requests complete in 5 hops, this gives just one binary decision per hop on average.
	 */
	public static final int MIN_PEERS_FOR_SCALING = 10;
	/** The maximum possible distance between two nodes in the wrapping [0,1) location space. */
	public static final double MAX_DISTANCE = 0.5;
	/** The fraction of nodes which are only a short distance away. */
	public static final double SHORT_NODES_FRACTION = LONG_DISTANCE / MAX_DISTANCE;
	/** The estimated average number of nodes which are active at any given time. */
	public static final int LAST_NETWORK_SIZE_ESTIMATE = 5000;
	/** The estimated number of nodes which are a short distance away. */
	public static final int AVAILABLE_SHORT_DISTANCE_NODES =
		(int) (LAST_NETWORK_SIZE_ESTIMATE * SHORT_NODES_FRACTION);
	/**
	 * Maximum number of peers.
	 *
	 * This is limited by the expected availability of nodes with short links to a given location.
	 * Above that number of peers, fast nodes will not be able to find enough peers with short
	 * links.
	 *
	 * @see freenet.node.OpennetManager.LinkLengthClass
	 */
	public static final int MAX_PEERS_FOR_SCALING =
		(int) (AVAILABLE_SHORT_DISTANCE_NODES / SHORT_PROPORTION);
	/** Maximum number of peers for purposes of FOAF attack/sanity check */
	public static final int PANIC_MAX_PEERS = MAX_PEERS_FOR_SCALING + 10;
	/** Stop trying to reconnect to an old-opennet-peer after a month. */
	public static final long MAX_TIME_ON_OLD_OPENNET_PEERS = DAYS.toMillis(31);

	// This is only relevant while the connection is in the grace period.
	// Null means none of the above e.g. not in grace period.
	public enum ConnectionType {
		PATH_FOLDING,
		ANNOUNCE,
		RECONNECT
	}

	private final long creationTime;
	
	private boolean stopping;

	public OpennetManager(Node node, NodeCryptoConfig opennetConfig, long startupTime, boolean enableAnnouncement) throws NodeInitException {
		this.creationTime = System.currentTimeMillis();
		this.node = node;
		crypto =
			new NodeCrypto(node, true, opennetConfig, startupTime, node.enableARKs);

		timeLastDropped = new EnumMap<ConnectionType,Long>(ConnectionType.class);
		connectionAttempts = new EnumMap<ConnectionType,Long>(ConnectionType.class);
		connectionAttemptsAdded = new EnumMap<ConnectionType,Long>(ConnectionType.class);
		connectionAttemptsAddedPlentySpace = new EnumMap<ConnectionType,Long>(ConnectionType.class);
		connectionAttemptsRejectedByPerTypeEnforcement = new EnumMap<ConnectionType,Long>(ConnectionType.class);
		connectionAttemptsRejectedNoPeersDroppable = new EnumMap<ConnectionType,Long>(ConnectionType.class);
		successCount = new EnumMap<ConnectionType,Long>(ConnectionType.class);
		for(ConnectionType c : ConnectionType.values()) {
			timeLastDropped.put(c, 0L);
			connectionAttempts.put(c, 0L);
			connectionAttemptsAdded.put(c, 0L);
			connectionAttemptsAddedPlentySpace.put(c, 0L);
			connectionAttemptsRejectedByPerTypeEnforcement.put(c, 0L);
			connectionAttemptsRejectedNoPeersDroppable.put(c, 0L);
			successCount.put(c, 0L);
		}

		File nodeFile = node.nodeDir().file("opennet-"+crypto.portNumber);
		File backupNodeFile = node.nodeDir().file("opennet-"+crypto.portNumber+".bak");

		// Keep opennet crypto details in a separate file
		try {
			readFile(nodeFile);
		} catch (IOException e) {
			try {
				readFile(backupNodeFile);
			} catch (IOException e1) {
				crypto.initCrypto();
			}
		}
		peersLRUByDistance = new EnumMap<LinkLengthClass, LRUQueue<OpennetPeerNode>>(LinkLengthClass.class);
		for(LinkLengthClass l : LinkLengthClass.values())
		    peersLRUByDistance.put(l, new LRUQueue<OpennetPeerNode>());
		oldPeers = new LRUQueue<OpennetPeerNode>();
		announcer = (enableAnnouncement ? new Announcer(this) : null);
	}

	public void writeFile() {
		File nodeFile = node.nodeDir().file("opennet-"+crypto.portNumber);
		File backupNodeFile = node.nodeDir().file("opennet-"+crypto.portNumber+".bak");
		writeFile(nodeFile, backupNodeFile);
	}

	private void writeFile(File orig, File backup) {
		SimpleFieldSet fs = crypto.exportPrivateFieldSet();

		if(orig.exists()) backup.delete();

		FileOutputStream fos = null;
		OutputStreamWriter osr = null;
		BufferedWriter bw = null;
		try {
			fos = new FileOutputStream(backup);
			osr = new OutputStreamWriter(fos, "UTF-8");
			bw = new BufferedWriter(osr);
			fs.writeTo(bw);

			bw.close();
			FileUtil.renameTo(backup, orig);
		} catch (IOException e) {
			Closer.close(bw);
			Closer.close(osr);
			Closer.close(fos);
		}
	}

	private void readFile(File filename) throws IOException {
		// REDFLAG: Any way to share this code with Node and NodePeer?
		FileInputStream fis = new FileInputStream(filename);
		InputStreamReader isr = new InputStreamReader(fis, "UTF-8");
		BufferedReader br = new BufferedReader(isr);
		SimpleFieldSet fs = new SimpleFieldSet(br, false, true);
		br.close();
		// Read contents
		String[] udp = fs.getAll("physical.udp");
		if((udp != null) && (udp.length > 0)) {
			for(String u: udp) {
				// Just keep the first one with the correct port number.
				Peer p;
				try {
					p = new Peer(u, false, true);
				} catch (HostnameSyntaxException e) {
					Logger.error(this, "Invalid hostname or IP Address syntax error while loading opennet peer node reference: "+u);
					System.err.println("Invalid hostname or IP Address syntax error while loading opennet peer node reference: "+u);
					continue;
				} catch (PeerParseException e) {
					throw (IOException)new IOException().initCause(e);
				}
				if(p.getPort() == crypto.portNumber) {
					// DNSRequester doesn't deal with our own node
					node.ipDetector.setOldIPAddress(p.getFreenetAddress());
					break;
				}
			}
		}

		crypto.readCrypto(fs);
	}

	public void start() {
		synchronized(this) {
			stopping = false;
		}
		// Do this outside the constructor, since the constructor is called by the Node constructor, and callbacks may make assumptions about data structures being ready.
		node.peers.tryReadPeers(node.nodeDir().file("openpeers-"+crypto.portNumber).toString(), crypto, this, true, false);
		OpennetPeerNode[] nodes = node.peers.getOpennetPeers();
		Arrays.sort(nodes, new Comparator<OpennetPeerNode>() {
			@Override
			public int compare(OpennetPeerNode pn1, OpennetPeerNode pn2) {
				if(pn1 == pn2) return 0;
				long lastSuccess1 = pn1.timeLastSuccess();
				long lastSuccess2 = pn2.timeLastSuccess();

				if(lastSuccess1 > lastSuccess2) return 1;
				if(lastSuccess2 > lastSuccess1) return -1;

				boolean neverConnected1 = pn1.neverConnected();
				boolean neverConnected2 = pn2.neverConnected();
				if(neverConnected1 && (!neverConnected2))
					return -1;
				if((!neverConnected1) && neverConnected2)
					return 1;
				// a-b not opposite sign to b-a possible in a corner case (a=0 b=Integer.MIN_VALUE).
				if(pn1.hashCode > pn2.hashCode) return 1;
				else if(pn1.hashCode < pn2.hashCode) return -1;
				Logger.error(this, "Two OpennetPeerNodes with the same hashcode: "+pn1+" vs "+pn2);
				return Fields.compareObjectID(pn1, pn2);
			}
		});
		for(OpennetPeerNode opn: nodes) {
		    // Drop any peers which don't have a location yet. That means we haven't connected to 
		    // them yet, and we need the location to decide which LRU to put them in ...
		    // This should only be a problem with old nodes; we will include the location in new 
		    // path folding noderefs...
		    if(Location.isValid(opn.getLocation()))
		        lruQueue(opn).push(opn);
		    else
		        node.peers.disconnectAndRemove(opn, false, false, false);
		}
		if(logMINOR) {
			Logger.minor(this, "My full compressed ref: "+crypto.myCompressedFullRef().length);
			Logger.minor(this, "My full setup ref: "+crypto.myCompressedSetupRef().length);
			Logger.minor(this, "My heavy setup ref: "+crypto.myCompressedHeavySetupRef().length);
		}
		dropAllExcessPeers();
		writeFile();
		// Read old peers
		node.peers.tryReadPeers(node.nodeDir().file("openpeers-old-"+crypto.portNumber).toString(), crypto, this, true, true);
		crypto.start();
		if(announcer!= null)
			announcer.start();
	}

	/**
	 * Called when opennet is disabled
	 */
	public void stop(boolean purge) {
		synchronized(this) {
			stopping = true;
		}
		if(announcer != null)
			announcer.stop();
		crypto.stop();
		if(purge)
			node.peers.removeOpennetPeers();
		crypto.socket.getAddressTracker().setPresumedInnocent();
	}
	
	synchronized boolean stopping() {
		return stopping;
	}
	
	private LRUQueue<OpennetPeerNode> lruQueue(LinkLengthClass distance) {
	    return peersLRUByDistance.get(distance);
	}
	
    private LRUQueue<OpennetPeerNode> lruQueue(OpennetPeerNode pn) {
        return lruQueue(pn.linkLengthClass());
    }
    
	public boolean alreadyHaveOpennetNode(SimpleFieldSet fs) {
		try {
			// FIXME OPT can we do this cheaper?
			// Maybe just parse the pubkey, and then compare it with the existing peers?
			OpennetPeerNode pn = new OpennetPeerNode(fs, node, crypto, this, node.peers, false, crypto.packetMangler);
			if(lruQueue(pn).contains(pn)) {
				if(logMINOR) Logger.minor(this, "Not adding "+pn.userToString()+" to opennet list as already there");
				return true;
			}
			// Don't check for self. That should be passed through too.
			return false;
		} catch (Throwable t) {
			// Don't break the code flow in the caller which is normally a request.
			Logger.error(this, "Caught "+t+" parsing opennet node from fieldset", t);
			return false;
		}
	}

	public OpennetPeerNode addNewOpennetNode(SimpleFieldSet fs, ConnectionType connectionType, boolean allowExisting) throws FSParseException, PeerParseException, ReferenceSignatureVerificationException {
		try {
		OpennetPeerNode pn = new OpennetPeerNode(fs, node, crypto, this, node.peers, false, crypto.packetMangler);
		if(Arrays.equals(pn.getPubKeyHash(), crypto.pubKeyHash)) {
			if(logMINOR) Logger.minor(this, "Not adding self as opennet peer");
			return null; // Equal to myself
		}
		LinkLengthClass distance = pn.linkLengthClass();
		LRUQueue<OpennetPeerNode> peersLRU = lruQueue(distance);
		if(peersLRU.contains(pn)) {
			if(logMINOR) Logger.minor(this, "Not adding "+pn.userToString()+" to opennet list as already there");
			if(allowExisting) {
				// However, we can reconnect.
				return (OpennetPeerNode) peersLRU.get(pn);
			} else {
				return null;
			}
		}
		if(pn.isUnroutableOlderVersion() && node.nodeUpdater != null && node.nodeUpdater.dontAllowUOM()) {
			// We can't send the UOM to it, so we should not accept it.
			// Plus, some versions around 1320 had big problems with being connected both as a seednode and as an opennet peer.
			return null;
		}
		if(wantPeer(pn, true, false, false, connectionType, distance)) return pn;
		else return null;
		// Start at bottom. Node must prove itself.
		} catch (Throwable t) {
			// Don't break the code flow in the caller which is normally a request.
			Logger.error(this, "Caught "+t+" adding opennet node from fieldset", t);
			return null;
		}

	}

	/** When did we last offer our noderef to some other node? */
	private long timeLastOffered;

	void forceAddPeer(OpennetPeerNode nodeToAddNow, boolean addAtLRU) {
	    LinkLengthClass distance = nodeToAddNow.linkLengthClass();
        LRUQueue<OpennetPeerNode> peersLRU = lruQueue(distance);
		synchronized(this) {
			if(addAtLRU)
				peersLRU.pushLeast(nodeToAddNow);
			else
				peersLRU.push(nodeToAddNow);
			oldPeers.remove(nodeToAddNow);
		}
		dropExcessPeers(distance);
	}

	public boolean wantPeer(OpennetPeerNode nodeToAddNow, boolean addAtLRU, boolean justChecking, boolean oldOpennetPeer, ConnectionType connectionType) {
	    if(nodeToAddNow != null) {
	        if(!Location.isValid(nodeToAddNow.getLocation())) {
	            Logger.error(this, "Added opennet node reference must include a valid location", new Exception("error"));
	            return false;
	        }
            // We have received a node reference, so we know whether it is long or short.
	        LinkLengthClass distance = nodeToAddNow.linkLengthClass();
	        return wantPeer(nodeToAddNow, addAtLRU, justChecking, oldOpennetPeer, connectionType, distance);
	    } else {
	        // Initiate path folding if we want a long link *or* a short link.
	        // FIXME ideally we'd like to indicate whether we want long links or short links.
	        return wantPeer(nodeToAddNow, addAtLRU, justChecking, oldOpennetPeer, connectionType, LinkLengthClass.SHORT)
	             || wantPeer(nodeToAddNow, addAtLRU, justChecking, oldOpennetPeer, connectionType, LinkLengthClass.LONG);
	    }
	}
	
	/**
	 * Trim the peers list and possibly add a new node. Note that if we are not adding a new node,
	 * we will only return true every MIN_TIME_BETWEEN_OFFERS, to prevent problems caused by many
	 * pending offers being accepted simultaneously.
	 * @param nodeToAddNow Node to add. Can be null, which means the caller needs to know whether
	 * we have space for another node, without actually adding one. This happens e.g. when we are
	 * the data source and are trying to decide whether to send our noderef downstream for path
	 * folding. 
	 * @param addAtLRU If there is a node to add, add it at the bottom rather than the top. Normally
	 * we set this on new path folded nodes so that they will be replaced if during the trial period,
	 * plus the time it takes to get a new path folding offer, they don't have a successful request.
	 * @param justChecking If true, we want to know whether there is space for a node to be added
	 * RIGHT NOW. If false, the normal behaviour applies: if nodeToAddNow is passed in, we decide
	 * whether to add that node, if it's null, we decide whether to send an offer subject to the
	 * inter-offer time.
	 * @param oldOpennetPeer If true, we are trying to add an old-opennet-peer which has reconnected.
	 * There is a throttle, we accept no more than one old-opennet-peer every 30 seconds. On receiving
	 * a packet, we call once to decide whether to try to parse it against the old-opennet-peers, and
	 * then again to decide whether it is worth keeping; in the latter case if we decide not, the
	 * old-opennet-peer will be told to disconnect and go away, but normally we don't reach that point
	 * because of the first check.
	 * @param isLong True if the peer to add is distant. False otherwise.
	 * @return True if the node was added / should be added.
	 */
	public boolean wantPeer(OpennetPeerNode nodeToAddNow, boolean addAtLRU, boolean justChecking, boolean oldOpennetPeer, ConnectionType connectionType, LinkLengthClass distance) {
	    LRUQueue<OpennetPeerNode> peersLRU = lruQueue(distance);
		boolean notMany = false;
		boolean noDisconnect;
		long now = System.currentTimeMillis();
		if(logMINOR) Logger.minor(this, "wantPeer("+(nodeToAddNow != null) + "," +addAtLRU+","+justChecking+","+oldOpennetPeer+","+connectionType+","+distance+")");
		boolean outdated = nodeToAddNow == null ? false : nodeToAddNow.isUnroutableOlderVersion();
		if(outdated && logMINOR) Logger.minor(this, "Peer is outdated: "+nodeToAddNow.getVersionNumber()+" for "+connectionType);
		if(outdated) {
			if(tooManyOutdatedPeers()) {
				if(logMINOR) Logger.minor(this, "Rejecting TOO OLD peer from "+connectionType+" (too many already): "+nodeToAddNow);
				return false;
			}
		}
		if(nodeToAddNow != null && crypto.config.oneConnectionPerAddress()) {
			boolean okay = false;
			boolean any = false;
			Peer[] handshakeIPs = nodeToAddNow.getHandshakeIPs();
			if(handshakeIPs != null) {
				for(Peer p : handshakeIPs) {
					if(p == null) continue;
					FreenetInetAddress addr = p.getFreenetAddress();
					if(addr == null) continue;
					InetAddress a = addr.getAddress(false);
					if(a == null) continue;
					if(a.isAnyLocalAddress() || a.isLinkLocalAddress() || IPUtil.isSiteLocalAddress(a)) continue;
					any = true;
					if(crypto.allowConnection(nodeToAddNow, addr))
						okay = true;
					else {
						// if NodeCrypto reject *any* address, reject peer
						okay = false;
						break;
					}
				}
			} else {
				Logger.error(this, "Peer does not have any IP addresses???");
			}
			if(any && !okay) {
				Logger.normal(this, "Rejecting peer as we are already connected to a peer with the same IP address");
				return false;
			}
		}
		int maxPeers = getNumberOfConnectedPeersToAim(distance);
		if(logMINOR) Logger.minor(this, "Peers target: "+maxPeers);
		synchronized(this) {
			if(nodeToAddNow != null &&
					peersLRU.contains(nodeToAddNow)) {
				if(logMINOR)
					Logger.minor(this, "Opennet peer already present in LRU: "+nodeToAddNow);
				return true;
			}
			if(nodeToAddNow != null)
				connectionAttempts.put(connectionType, connectionAttempts.get(connectionType)+1);
			if(getSize(distance) < maxPeers || outdated) {
				if(nodeToAddNow != null) {
					if(logMINOR) Logger.minor(this, "Added opennet peer "+nodeToAddNow+" as opennet peers list not full");
					if(addAtLRU)
						peersLRU.pushLeast(nodeToAddNow);
					else
						peersLRU.push(nodeToAddNow);
					oldPeers.remove(nodeToAddNow);
					connectionAttemptsAddedPlentySpace.put(connectionType, connectionAttemptsAddedPlentySpace.get(connectionType)+1);
				} else {
					if(logMINOR) Logger.minor(this, "Want peer because not enough opennet nodes");
				}
				if(nodeToAddNow == null && !justChecking)
					timeLastOffered = System.currentTimeMillis();
				notMany = true;
				// Don't check timeLastAddedOldOpennetPeer, since we want it anyway. But do update it.
			}
			// Old opennet peers should only replace free slots / disconnected droppable nodes.
			// We can make offers regardless of timeLastOffered provided they are disconnected droppable peers.
			// And we only allow a connection to be dropped every 10 successful fetches.
			noDisconnect = successCount.get(connectionType) < MIN_SUCCESS_BETWEEN_DROP_CONNS || oldOpennetPeer || (nodeToAddNow == null && now - timeLastOffered <= MIN_TIME_BETWEEN_OFFERS) || now - timeLastDropped.get(connectionType) < DROP_CONNECTED_TIME;
		}
		if(nodeToAddNow != null)
			nodeToAddNow.setAddedReason(connectionType);
		if(notMany) {
			if(nodeToAddNow != null) {
				node.peers.addPeer(nodeToAddNow, true); // Add to peers outside the OM lock
			}
			return true;
		}
		boolean canAdd = true;
		ArrayList<OpennetPeerNode> dropList = new ArrayList<OpennetPeerNode>();
		maxPeers = getNumberOfConnectedPeersToAim(distance);
		synchronized(this) {
			int size = getSize(distance);
			if(size == maxPeers && nodeToAddNow == null) {
				// Allow an offer to be predicated on throwing out a connected node,
				// provided that we meet the other criteria e.g. time since last added,
				// node isn't too new.
				OpennetPeerNode toDrop = peerToDrop(noDisconnect, false, nodeToAddNow != null, connectionType, maxPeers, distance, peersLRU);
				if(toDrop == null) {
					if(logMINOR)
						Logger.minor(this, "No more peers to drop (in first bit), still "+peersLRU.size()+" peers, cannot accept peer"+(nodeToAddNow == null ? "" : nodeToAddNow.toString()));
					canAdd = false;
					if(nodeToAddNow != null)
						connectionAttemptsRejectedNoPeersDroppable.put(connectionType, connectionAttemptsRejectedNoPeersDroppable.get(connectionType)+1);
				} else {
					// Only check per-type limits if we are throwing out connected peers.
					// This is important for bootstrapping, given the low announcement limit.
					if(toDrop.isConnected() && enforcePerTypeGracePeriodLimits(maxPeers, connectionType, nodeToAddNow != null, peersLRU)) {
						if(nodeToAddNow != null)
							connectionAttemptsRejectedByPerTypeEnforcement.put(connectionType, connectionAttemptsRejectedByPerTypeEnforcement.get(connectionType)+1);
						return false;
					}
				}
			} else while(canAdd && (size = getSize(distance)) > maxPeers - ((nodeToAddNow == null || outdated) ? 0 : 1)) {
				OpennetPeerNode toDrop;
				// can drop peers which are over the limit
				toDrop = peerToDrop(noDisconnect, false, nodeToAddNow != null, connectionType, maxPeers, distance, peersLRU);
				if(toDrop == null) {
					if(logMINOR)
						Logger.minor(this, "No more peers to drop, still "+peersLRU.size()+" peers, cannot accept peer"+(nodeToAddNow == null ? "" : nodeToAddNow.toString()));
					canAdd = false;
					if(nodeToAddNow != null)
						connectionAttemptsRejectedNoPeersDroppable.put(connectionType, connectionAttemptsRejectedNoPeersDroppable.get(connectionType)+1);
					break;
				}
				// Only check per-type limits if we are throwing out connected peers.
				// This is important for bootstrapping, given the low announcement limit.
				if(toDrop.isConnected() && enforcePerTypeGracePeriodLimits(maxPeers, connectionType, nodeToAddNow != null, peersLRU)) {
					if(nodeToAddNow != null)
						connectionAttemptsRejectedByPerTypeEnforcement.put(connectionType, connectionAttemptsRejectedByPerTypeEnforcement.get(connectionType)+1);
					return false;
				}
				if(nodeToAddNow != null || size > maxPeers) {
					if(logMINOR)
						Logger.minor(this, "Drop opennet peer: "+toDrop+" (connected="+toDrop.isConnected()+") of "+peersLRU.size()+":"+getSize(distance));
					peersLRU.remove(toDrop);
					dropList.add(toDrop);
				}
			}
			if(canAdd && !justChecking) {
				if(nodeToAddNow != null) {
					successCount.put(connectionType, 0L);
					if(addAtLRU)
						peersLRU.pushLeast(nodeToAddNow);
					else
						peersLRU.push(nodeToAddNow);
					if(logMINOR) Logger.minor(this, "Added opennet peer "+nodeToAddNow+" after clearing "+dropList.size()+" items - now have "+peersLRU.size()+" opennet peers");
					oldPeers.remove(nodeToAddNow);
					if(!dropList.isEmpty()) {
						if(logMINOR) Logger.minor(this, "Dropped opennet peer: "+dropList.get(0));
						timeLastDropped.put(connectionType, now);
					}
					connectionAttemptsAdded.put(connectionType, connectionAttemptsAdded.get(connectionType)+1);
				} else {
					// Do not update timeLastDropped, anything dropped was over the limit so doesn't count (because nodeToAddNow == null).
					if(!justChecking) {
						timeLastOffered = now;
						if(logMINOR)
							Logger.minor(this, "Sending offer");
					}
				}
			}
		}
		if(nodeToAddNow != null && canAdd && !node.peers.addPeer(nodeToAddNow, true)) {
			if(logMINOR)
				Logger.minor(this, "Already in global peers list: "+nodeToAddNow+" when adding opennet node");
			// Just because it's in the global peers list doesn't mean its in the LRU, it may be an old-opennet-peers reconnection.
			// In which case we add it to the global peers list *before* adding it here.
		}
		for(OpennetPeerNode pn : dropList) {
			if(logMINOR) Logger.minor(this, "Dropping LRU opennet peer: "+pn);
			pn.setAddedReason(null);
			node.peers.disconnectAndRemove(pn, true, true, true);
		}
		return canAdd;
	}
	
	private int maxOutdatedPeers() {
		return Math.max(5, getNumberOfConnectedPeersToAimIncludingDarknet() / 4);
	}
	
	private boolean tooManyOutdatedPeers() {
	    // This does not check whether they are short or long as it is irrelevant for outdated peers.
		int maxTooOldPeers = maxOutdatedPeers();
		int count = 0;
		OpennetPeerNode[] peers = node.peers.getOpennetPeers();
		for(OpennetPeerNode pn : peers) {
			if(pn.isUnroutableOlderVersion()) {
				count++;
				if(count >= maxTooOldPeers)
					return true;
			}
		}
		return false;
	}

	private synchronized boolean enforcePerTypeGracePeriodLimits(int maxPeers, ConnectionType type, boolean addingPeer, LRUQueue<OpennetPeerNode> peersLRU) {
		if(type == null) {
			if(logMINOR) Logger.minor(this, "No type set, not enforcing per type limits");
		}

		// We do NOT want to have all our peers in grace periods!
		// For opennet to work, we need LRU. For LRU to work it needs a choice.
		// If everything is in a grace period, then we have no choice - we replace the one node that comes out of its grace period as soon as it does.
		// So first calculate an overall limit on the number of peers in grace periods.

		// Heuristic: Half rounded down.
		int maxGracePeriodPeers = maxPeers / 2;

		int announceMax;
		int reconnectMax;
		int pathFoldingMax;
		// Same total global number of slots as 1242/1243.
		announceMax = reconnectMax = (maxGracePeriodPeers / 5) + 1;
		pathFoldingMax = maxGracePeriodPeers - announceMax - reconnectMax;
		if(pathFoldingMax < 2) return false;
		if(logMINOR) Logger.minor(this, "Per type grace period limits: total peers: "+maxPeers+" announce "+announceMax+" reconnect "+reconnectMax+" path folding "+pathFoldingMax);
		int myLimit;
		if(type == ConnectionType.PATH_FOLDING)
			myLimit = pathFoldingMax;
		else if(type == ConnectionType.ANNOUNCE)
			myLimit = announceMax;
		else
			myLimit = reconnectMax;
		int count = 0;
		OpennetPeerNode[] peers = peersLRU.toArray(new OpennetPeerNode[peersLRU.size()]);
		for(OpennetPeerNode pn : peers) {
			if(pn.getAddedReason() != type) continue;
			if(!pn.isConnected()) continue;
			if(pn.isDroppable(false)) continue;
			if(++count >= myLimit) {
				if(logMINOR) Logger.minor(this, "Per type grace period limit rejected peer of type "+type+" count is "+count+" limit is "+myLimit);
				return true;
			}
		}
		if(logMINOR) Logger.minor(this, "Per type grace period limit allowed connection of type "+type+" count is "+count+" limit is "+myLimit+" addingPeer="+addingPeer);
		return false;
	}
	
	void dropAllExcessPeers() {
        for(LinkLengthClass l : LinkLengthClass.values()) dropExcessPeers(l);
	}

	void dropExcessPeers(LinkLengthClass distance) {
	    LRUQueue<OpennetPeerNode> peersLRU = lruQueue(distance);
		int maxPeers = getNumberOfConnectedPeersToAim(distance);
		while(peersLRU.size() > maxPeers) {
			if(logMINOR)
	            Logger.minor(this, "Dropping opennet peers: currently "+peersLRU.size()+" of "+maxPeers+" for "+distance+" distance links");
            OpennetPeerNode toDrop;
			toDrop = peerToDrop(false, false, false, null, maxPeers, distance, peersLRU);
			if(toDrop == null) toDrop = peerToDrop(false, true, false, null, maxPeers, distance, peersLRU);
			if(toDrop == null) return;
			synchronized(this) {
				peersLRU.remove(toDrop);
			}
			if(logMINOR)
				Logger.minor(this, "Dropping "+toDrop);
			node.peers.disconnectAndRemove(toDrop, true, true, true);
		}
	}

	// A TOO OLD peer does not count towards the limit, even if it is not connected.
	// It can however be dumped if it doesn't connect in a reasonable time, and if
	// it upgrades, it may not have the usual grace period.
	
	/**
	 * How many opennet peers do we have?
	 * Connected but out of date nodes don't count towards the connection limit. Let them connect for
	 * long enough to auto-update. They will be disconnected eventually, and then removed:
	 * @see OpennetPeerNode#shouldDisconnectAndRemoveNow()
	 */
	synchronized public int getSize(LinkLengthClass distance) {
		int x = 0;
		for (Enumeration<OpennetPeerNode> e = lruQueue(distance).elements(); e.hasMoreElements();) {
			OpennetPeerNode pn = e.nextElement();
			if(!pn.isUnroutableOlderVersion()) x++;
		}
		return x;
	}

	private OpennetPeerNode peerToDrop(boolean noDisconnect, boolean force, boolean addingNode, ConnectionType connectionType, int maxPeers, LinkLengthClass distance, LRUQueue<OpennetPeerNode> peersLRU) {
		if(getSize(distance) < maxPeers) {
			// Don't drop any peers
			if(logMINOR) Logger.minor(this, "peerToDrop(): Not dropping any peer (force="+force+" addingNode="+addingNode+") because don't need to");
			return null;
		}
		synchronized(this) {
			EnumMap<NOT_DROP_REASON, Integer> map = null;
			if(addingNode) map = new EnumMap<NOT_DROP_REASON, Integer>(NOT_DROP_REASON.class);
			// Do we want it?
			OpennetPeerNode[] peers = peersLRU.toArrayOrdered(new OpennetPeerNode[peersLRU.size()]);
			for(OpennetPeerNode pn: peers) {
				if(pn == null) continue;
				boolean tooOld = pn.isUnroutableOlderVersion();
				if(pn.isConnected() && tooOld) {
					// Doesn't count towards the opennet peers limit, so no point dropping it.
					continue;
				}
				NOT_DROP_REASON reason = pn.isDroppableWithReason(false);
				if(map != null) {
					Integer x = map.get(reason);
					if(x == null)
						map.put(reason, 1);
					else
						map.put(reason, x+1);
				}
				// Over the limit does not force us to drop TOO OLD peers since they don't count towards the limit.
				if((reason != NOT_DROP_REASON.DROPPABLE) && ((!force) || tooOld)) {
					continue;
				}
				// LOCKING: Always take the OpennetManager lock first
				if(!pn.isConnected()) {
					if(logMINOR)
						Logger.minor(this, "Possibly dropping opennet peer "+pn+" as is disconnected (reason="+reason+" force="+force+" tooOld="+tooOld);
					pn.setWasDropped();
					return pn;
				}
			}
			if(noDisconnect) {
				if(addingNode && logMINOR) {
					Logger.minor(this, "Not disconnecting");
					if(map != null)
						for(Map.Entry<NOT_DROP_REASON, Integer> entry : map.entrySet()) {
							Logger.minor(this, ""+entry.getKey()+" : "+entry.getValue());
						}
				}
				return null;
			}
			if(map != null) map.clear();
			for(OpennetPeerNode pn: peers) {
				if(pn == null) continue;
				boolean tooOld = pn.isUnroutableOlderVersion();
				if(pn.isConnected() && tooOld) {
					// Doesn't count anyway.
					continue;
				}
				NOT_DROP_REASON reason = pn.isDroppableWithReason(false);
				if(map != null) {
					Integer x = map.get(reason);
					if(x == null)
						map.put(reason, 1);
					else
						map.put(reason, x+1);
				}
				// Over the limit does not force us to drop TOO OLD peers since they don't count towards the limit.
				if((reason != NOT_DROP_REASON.DROPPABLE) && ((!force) || tooOld)) {
					continue;
				}
				if(logMINOR)
					Logger.minor(this, "Possibly dropping opennet peer "+pn+" "+
							((connectionType == null) ? "" : ((System.currentTimeMillis() - timeLastDropped.get(connectionType))+" ms since last dropped peer of type "+connectionType)));
				pn.setWasDropped();
				return pn;
			}
			if(addingNode && logMINOR) {
				Logger.minor(this, "Nothing to drop");
				if(map != null)
					for(Map.Entry<NOT_DROP_REASON, Integer> entry : map.entrySet()) {
						Logger.minor(this, ""+entry.getKey()+" : "+entry.getValue());
					}
			}
		}
		return null;
	}

	public void onSuccess(OpennetPeerNode pn) {
	    LinkLengthClass distance = pn.linkLengthClass();
	    LRUQueue<OpennetPeerNode> peersLRU = lruQueue(distance);
		synchronized(this) {
			for(ConnectionType type : ConnectionType.values())
				successCount.put(type, successCount.get(type)+1);
			if(peersLRU.contains(pn)) {
				peersLRU.push(pn);
				if(logMINOR) Logger.minor(this, "Opennet peer "+pn+" promoted to top of LRU because of successful request");
				return;
			} else {
				if(logMINOR) Logger.minor(this, "Success on opennet peer which isn't in the LRU!: "+pn, new Exception("debug"));
				// Re-add it: nasty race condition when we have few peers
			}
		}
		if(!wantPeer(pn, false, false, false, ConnectionType.RECONNECT, distance)) // Start at top as it just succeeded
			node.peers.disconnectAndRemove(pn, true, false, true);
	}

	public void onRemove(OpennetPeerNode pn) {
		long now = System.currentTimeMillis();
        LRUQueue<OpennetPeerNode> peersLRU = lruQueue(pn);
		synchronized (this) {
			peersLRU.remove(pn);
			if(pn.isDroppable(true) && !pn.grabWasDropped()) {
				if(logMINOR) Logger.minor(this, "onRemove() for "+pn);
				if(pn.timeLastConnected(now) > 0) {
					// Don't even add it if it never connected.
					oldPeers.push(pn);
					while (oldPeers.size() > MAX_OLD_PEERS)
						oldPeers.pop();
				}
			}
		}
	}

	synchronized OpennetPeerNode[] getOldPeers() {
		return oldPeers.toArrayOrdered(new OpennetPeerNode[oldPeers.size()]);
	}

	synchronized OpennetPeerNode[] getUnsortedOldPeers() {
		return oldPeers.toArray(new OpennetPeerNode[oldPeers.size()]);
	}

	/**
	 * Add an old opennet node - a node which might try to reconnect, and which we should accept
	 * if we are desperate.
	 * @param pn The node to add to the old opennet nodes LRU.
	 */
	synchronized void addOldOpennetNode(OpennetPeerNode pn) {
		oldPeers.push(pn);
	}

	final String getOldPeersFilename() {
		return node.nodeDir().file("openpeers-old-"+crypto.portNumber).toString();
	}

	synchronized int countOldOpennetPeers() {
		return oldPeers.size();
	}

	OpennetPeerNode randomOldOpennetNode() {
		OpennetPeerNode[] nodes = getUnsortedOldPeers();
		if(nodes.length == 0) return null;
		return nodes[node.random.nextInt(nodes.length)];
	}

	public synchronized void purgeOldOpennetPeer(OpennetPeerNode source) {
		oldPeers.remove(source);
	}

	public int getNumberOfConnectedPeersToAimIncludingDarknet() {
		int max = node.getMaxOpennetPeers();
		if(ENABLE_PEERS_PER_KB_OUTPUT) {
			int obwLimit = node.getOutputBandwidthLimit();
			int targetPeers = (int)Math.round(Math.min(MAX_PEERS_FOR_SCALING, Math.sqrt(obwLimit * SCALING_CONSTANT / 1000.0)));
			if(targetPeers < MIN_PEERS_FOR_SCALING)
				targetPeers = MIN_PEERS_FOR_SCALING;
			if(max > targetPeers) max = targetPeers; // Allow user to reduce it.
		}
		return max;
	}

	/** Get the target number of opennet peers. Do not call while holding locks. */
	public int getNumberOfConnectedPeersToAim(LinkLengthClass distance) {
	    if(distance == null) throw new IllegalArgumentException();
	    int target = getNumberOfConnectedPeersToAim();
	    return distance.getTargetPeers(target);
	}
	
	public int getNumberOfConnectedPeersToAim() {
		int max = getNumberOfConnectedPeersToAimIncludingDarknet();
		return max - node.peers.countConnectedDarknetPeers();
	}

	public void sendOpennetRef(boolean isReply, long uid, PeerNode peer, byte[] noderef, ByteCounter ctr) throws NotConnectedException {
		sendOpennetRef(isReply, uid, peer, noderef, ctr, null);
	}
	
	/**
	 * Send our opennet noderef to a node.
	 * @param isReply If true, send an FNPOpennetConnectReply, else send an FNPOpennetConnectDestination.
	 * @param uid The unique ID of the request chain involved.
	 * @param peer The node to send the noderef to. Not necessarily an OpennetPeerNode, as path 
	 * folding and possibly announcement can pass through darknet.
	 * @param cs The full compressed noderef to send.
	 * @throws NotConnectedException If the peer becomes disconnected while we are trying to send the noderef.
	 */
	public boolean sendOpennetRef(boolean isReply, long uid, PeerNode peer, byte[] noderef, ByteCounter ctr, AllSentCallback cb) throws NotConnectedException {
		byte[] padded = new byte[paddedSize(noderef.length)];
		if(noderef.length > padded.length) {
			Logger.error(this, "Noderef too big: "+noderef.length+" bytes");
			return false;
		}
		System.arraycopy(noderef, 0, padded, 0, noderef.length);
		Util.randomBytes(node.fastWeakRandom, padded, noderef.length, padded.length-noderef.length);
		long xferUID = node.random.nextLong();
		Message msg2 = isReply ? DMT.createFNPOpennetConnectReplyNew(uid, xferUID, noderef.length, padded.length) :
			DMT.createFNPOpennetConnectDestinationNew(uid, xferUID, noderef.length, padded.length);
		peer.sendAsync(msg2, null, ctr);
		return innerSendOpennetRef(xferUID, padded, peer, ctr, cb);
	}

	/**
	 * Just the actual transfer.
	 * @param xferUID The transfer UID
	 * @param padded The length of the data to transfer.
	 * @param peer The peer to send it to.
	 * @param cb 
	 * @throws NotConnectedException If the peer is not connected, or we lose the connection to the peer,
	 * or it restarts.
	 */
	private boolean innerSendOpennetRef(long xferUID, byte[] padded, PeerNode peer, ByteCounter ctr, AllSentCallback cb) throws NotConnectedException {
		ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(padded);
		raf.setReadOnly();
		PartiallyReceivedBulk prb =
			new PartiallyReceivedBulk(node.usm, padded.length, Node.PACKET_SIZE, raf, true);
		try {
			BulkTransmitter bt =
				new BulkTransmitter(prb, peer, xferUID, true, ctr, true, cb);
			return bt.send();
		} catch (DisconnectedException e) {
			throw new NotConnectedException(e);
		}
	}

	public long startSendAnnouncementRequest(long uid, PeerNode peer, byte[] noderef, ByteCounter ctr,
			double target, short htl) throws NotConnectedException {
		long xferUID = node.random.nextLong();
		Message msg = DMT.createFNPOpennetAnnounceRequest(uid, xferUID, noderef.length,
				paddedSize(noderef.length), target, htl);
		peer.sendAsync(msg, null, ctr);
		return xferUID;
	}

	public void finishSentAnnouncementRequest(PeerNode peer, byte[] noderef, ByteCounter ctr,
			long xferUID) throws NotConnectedException {
		byte[] padded = new byte[paddedSize(noderef.length)];
		System.arraycopy(noderef, 0, padded, 0, noderef.length);
		Util.randomBytes(node.fastWeakRandom, padded, noderef.length, padded.length-noderef.length);
		innerSendOpennetRef(xferUID, padded, peer, ctr, null);
	}

	private int paddedSize(int length) {
		if(length < PADDED_NODEREF_SIZE) return PADDED_NODEREF_SIZE;
		Logger.normal(this, "Large noderef: "+length);
		if(length > MAX_OPENNET_NODEREF_LENGTH)
			throw new IllegalArgumentException("Too big noderef: "+length+" limit is "+MAX_OPENNET_NODEREF_LENGTH);
		return ((length >>> 10) + ((length & 1023) == 0 ? 0 : 1)) << 10;
	}

	public void sendAnnouncementReply(long uid, PeerNode peer, byte[] noderef, ByteCounter ctr)
	throws NotConnectedException {
		byte[] padded = new byte[PADDED_NODEREF_SIZE];
		if(noderef.length > padded.length) {
			Logger.error(this, "Noderef too big: "+noderef.length+" bytes");
			return;
		}
		System.arraycopy(noderef, 0, padded, 0, noderef.length);
		long xferUID = node.random.nextLong();
		Message msg = DMT.createFNPOpennetAnnounceReply(uid, xferUID, noderef.length,
				padded.length);
		peer.sendAsync(msg, null, ctr);
		innerSendOpennetRef(xferUID, padded, peer, ctr, null);
	}

	interface NoderefCallback {
		/** Got a noderef. */
		void gotNoderef(byte[] noderef);
		/** Timed out waiting for a noderef. */
		void timedOut();
		/** Got an ack - didn't timeout but there won't be a noderef. 
		 * @param timedOutMessage */
		void acked(boolean timedOutMessage);
	}
	
	private static class SyncNoderefCallback implements NoderefCallback {

		byte[] returned;
		boolean finished;
		boolean timedOut;
		
		@Override
		public synchronized void timedOut() {
			timedOut = true;
			finished = true;
			notifyAll();
		}
		
		@Override
		public void acked(boolean timedOutMessage) {
			gotNoderef(null);
		}
		
		@Override
		public synchronized void gotNoderef(byte[] noderef) {
			returned = noderef;
			finished = true;
			notifyAll();
		}
		
		public synchronized byte[] waitForResult() throws WaitedTooLongForOpennetNoderefException {
			while(!finished)
				try {
					wait();
				} catch (InterruptedException e) {
					// Ignore
				}
			if(timedOut) throw new WaitedTooLongForOpennetNoderefException();
			return returned;
		}
		
	}
	
	@SuppressWarnings("serial")
	static class WaitedTooLongForOpennetNoderefException extends Exception {
		
	}
	
	/**
	 * Wait for an opennet noderef.
	 * @param isReply If true, wait for an FNPOpennetConnectReply[New], if false wait for an FNPOpennetConnectDestination[New].
	 * @param uid The UID of the parent request.
	 * @return An opennet noderef.
	 */
	public static byte[] waitForOpennetNoderef(boolean isReply, PeerNode source, long uid, ByteCounter ctr, Node node) throws WaitedTooLongForOpennetNoderefException {
		SyncNoderefCallback cb = new SyncNoderefCallback();
		if(logMINOR) Logger.minor(OpennetManager.class, "Waiting for opennet noderef on "+uid+" from "+source+" reply="+isReply);
		waitForOpennetNoderef(isReply, source, uid, ctr, cb, node);
		return cb.waitForResult();
	}
	
	public static void waitForOpennetNoderef(final boolean isReply, final PeerNode source, final long uid, final ByteCounter ctr, final NoderefCallback callback, final Node node) {
		// FIXME remove back compat code
		MessageFilter mf =
			MessageFilter.create().setSource(source).setField(DMT.UID, uid).
			setTimeout(RequestSender.OPENNET_TIMEOUT).
			setType(isReply ? DMT.FNPOpennetConnectReplyNew : DMT.FNPOpennetConnectDestinationNew);
		// Also waiting for an ack
		MessageFilter mfAck =
			MessageFilter.create().setSource(source).setField(DMT.UID, uid).
			setTimeout(RequestSender.OPENNET_TIMEOUT).setType(DMT.FNPOpennetCompletedAck);
		// Also waiting for an upstream timed out.
		MessageFilter mfAckTimeout =
			MessageFilter.create().setSource(source).setField(DMT.UID, uid).
			setTimeout(RequestSender.OPENNET_TIMEOUT).setType(DMT.FNPOpennetCompletedTimeout);
		
		mf = mfAck.or(mfAckTimeout.or(mf));
		try {
			node.usm.addAsyncFilter(mf, new SlowAsyncMessageFilterCallback() {
				
				boolean completed;

				@Override
				public void onMatched(Message msg) {
					if (msg.getSpec() == DMT.FNPOpennetCompletedAck || 
							msg.getSpec() == DMT.FNPOpennetCompletedTimeout) {
						synchronized(this) {
							if(completed) return;
							completed = true;
						}
						callback.acked(msg.getSpec() == DMT.FNPOpennetCompletedTimeout);
					} else {
						// Noderef bulk transfer
						long xferUID = msg.getLong(DMT.TRANSFER_UID);
						int paddedLength = msg.getInt(DMT.PADDED_LENGTH);
						int realLength = msg.getInt(DMT.NODEREF_LENGTH);
						complete(innerWaitForOpennetNoderef(xferUID, paddedLength, realLength, source, isReply, uid, false, ctr, node));
					}
				}

				@Override
				public boolean shouldTimeout() {
					return false;
				}

				@Override
				public void onTimeout() {
					synchronized(this) {
						if(completed) return;
						completed = true;
					}
					callback.timedOut();
				}

				@Override
				public void onDisconnect(PeerContext ctx) {
					complete(null);
				}

				@Override
				public void onRestarted(PeerContext ctx) {
					complete(null);
				}

				@Override
				public int getPriority() {
					return NativeThread.NORM_PRIORITY;
				}
				
				private void complete(byte[] buf) {
					synchronized(this) {
						if(completed) return;
						completed = true;
					}
					callback.gotNoderef(buf);
				}
				
			}, ctr);
		} catch (DisconnectedException e) {
			callback.gotNoderef(null);
		}
	}

	static byte[] innerWaitForOpennetNoderef(long xferUID, int paddedLength, int realLength, PeerNode source, boolean isReply, long uid, boolean sendReject, ByteCounter ctr, Node node) {
		byte[] buf = new byte[paddedLength];
		ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(buf);
		PartiallyReceivedBulk prb = new PartiallyReceivedBulk(node.usm, buf.length, Node.PACKET_SIZE, raf, false);
		BulkReceiver br = new BulkReceiver(prb, source, xferUID, ctr);
		if (logMINOR) {
			Logger.minor(OpennetManager.class, "Receiving noderef (reply="+isReply+") as bulk transfer for request uid "+uid+" with transfer "+xferUID+" from "+source);
		}
		if (!br.receive()) {
			if (source.isConnected()) {
				String msg = "Failed to receive noderef bulk transfer : "
					+RetrievalException.getErrString(prb.getAbortReason())+" : "
					+prb.getAbortDescription()+" from "+source;
				if (prb.getAbortReason() != RetrievalException.SENDER_DISCONNECTED) {
					Logger.warning(OpennetManager.class, msg);
				} else {
					Logger.normal(OpennetManager.class, msg);
				}
				if (sendReject) rejectRef(uid, source, DMT.NODEREF_REJECTED_TRANSFER_FAILED, ctr);
			}
			return null;
		}
		byte[] noderef = Arrays.copyOf(buf, realLength);
		return noderef;
	}

	public static void rejectRef(long uid, PeerNode source, int reason, ByteCounter ctr) {
		Message msg = DMT.createFNPOpennetNoderefRejected(uid, reason);
		try {
			source.sendAsync(msg, null, ctr);
		} catch (NotConnectedException e) {
			// Ignore
		}
	}

	public static SimpleFieldSet validateNoderef(byte[] noderef, int offset, int length, PeerNode from, boolean forceOpennetEnabled) {
    	SimpleFieldSet ref;
		try {
			ref = PeerNode.compressedNoderefToFieldSet(noderef, 0, noderef.length);
		} catch (FSParseException e) {
			Logger.error(OpennetManager.class, "Invalid noderef: "+e, e);
			return null;
		}
		if(forceOpennetEnabled)
			ref.put("opennet", true);

		if(!OpennetPeerNode.validateRef(ref)) {
			Logger.error(OpennetManager.class, "Could not parse opennet noderef from "+from);
			return null;
		}

		if (ref != null) {
			String identity = ref.get("identity");
			if (identity != null) // N2N_MESSAGE_TYPE_DIFFNODEREF don't have identity
				registerKnownIdentity(identity);
		}
		return ref;
	}

	/** Do an announcement !!
	 * @param target The location to announce to. In 0.7 we don't try to prevent nodes from choosing their
	 * announcement location, because it is easy for them to get the location they want later on anyway,
	 * and we can do a much more effective announcement this way. */
	public void announce(double target, AnnouncementCallback cb) {
		AnnounceSender sender = new AnnounceSender(target, this, node, cb, null);
		node.executor.execute(sender, "Announcement to "+target);
	}

	public long getCreationTime() {
		return creationTime;
	}


	private static final long MAX_AGE = DAYS.toMillis(7);
	private static final TimeSortedHashtable<String> knownIds = new TimeSortedHashtable<String>();

	private static void registerKnownIdentity(String d) {
		if (logMINOR)
			Logger.minor(OpennetManager.class, "Known Id: " + d);
		long now = System.currentTimeMillis();

		synchronized (knownIds) {
			if(logMINOR) Logger.minor(OpennetManager.class, "Adding Id " + d + " knownIds size " + knownIds.size());
			knownIds.push(d, now);
			if(logMINOR) Logger.minor(OpennetManager.class, "Added Id " + d + " knownIds size " + knownIds.size());
			knownIds.removeBefore(now - MAX_AGE);
			if(logMINOR) Logger.minor(OpennetManager.class, "Added and pruned location " + d + " knownIds size " + knownIds.size());
		}
		if(logMINOR) Logger.minor(OpennetManager.class, "Estimated opennet size(session): " + knownIds.size());
	}
    //Return the estimated network size based on locations seen after timestamp or for the whole session if -1
	public int getNetworkSizeEstimate(long timestamp) {
		return knownIds.countValuesAfter(timestamp);
	}

	public int getAnnouncementThreshold() {
		return announcer.getAnnouncementThreshold();
	}

	/** Notification that a peer was disconnected. Query the Announcer,
	 * it may need to rerun. */
	public void onDisconnect(PeerNode node2) {
		if(announcer != null)
			announcer.maybeSendAnnouncementOffThread();
	}

	public void drawOpennetStatsBox(HTMLNode box) {
		HTMLNode table = box.addChild("table", "border", "0");
		HTMLNode row = table.addChild("tr");

		row.addChild("th");
		for(ConnectionType type : ConnectionType.values()) {
			row.addChild("th", type.name());
		}

		row = table.addChild("tr");
		row.addChild("td", "Connection attempts");
		for(ConnectionType type : ConnectionType.values()) {
			row.addChild("td", Long.toString(connectionAttempts.get(type)));
		}

		row = table.addChild("tr");
		row.addChild("td", "Connections accepted");
		for(ConnectionType type : ConnectionType.values()) {
			row.addChild("td", Long.toString(connectionAttemptsAdded.get(type)));
		}

		row = table.addChild("tr");
		row.addChild("td", "Accepted (free slots)");
		for(ConnectionType type : ConnectionType.values()) {
			row.addChild("td", Long.toString(connectionAttemptsAddedPlentySpace.get(type)));
		}

		row = table.addChild("tr");
		row.addChild("td", "Rejected (per-type grace periods)");
		for(ConnectionType type : ConnectionType.values()) {
			row.addChild("td", Long.toString(connectionAttemptsRejectedByPerTypeEnforcement.get(type)));
		}

		row = table.addChild("tr");
		row.addChild("td", "Rejected (no droppable peers)");
		for(ConnectionType type : ConnectionType.values()) {
			row.addChild("td", Long.toString(connectionAttemptsRejectedNoPeersDroppable.get(type)));
		}

	}

	public boolean waitingForUpdater() {
		return announcer.isWaitingForUpdater();
	}
	
	public void reannounce() {
		announcer.reannounce();
	}

	public void drawSeedStatsBox(HTMLNode content) {
		seedTracker.drawSeedStats(content);
	}

	/** Called when a connection completes. If it's an opennet peer, we may need to drop a peer
	 * to make space. If it's a darknet peer, the connection limit for opennet peers may have
	 * decreased so again we may need to drop a peer. */
    public void onConnectedPeer(PeerNode pn) {
        if(pn instanceof OpennetPeerNode) {
            dropExcessPeers(((OpennetPeerNode)pn).linkLengthClass());
        } else {
            // The peer count target may have decreased, so we may need to drop an opennet peer.
            dropAllExcessPeers();
        }
    }

}
