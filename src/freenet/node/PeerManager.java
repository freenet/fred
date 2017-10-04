/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import freenet.io.comm.AsyncMessageCallback;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.FreenetInetAddress;
import freenet.io.comm.Message;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.Peer;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.keys.Key;
import freenet.l10n.NodeL10n;
import freenet.node.DarknetPeerNode.FRIEND_TRUST;
import freenet.node.DarknetPeerNode.FRIEND_VISIBILITY;
import freenet.node.useralerts.AbstractUserAlert;
import freenet.node.useralerts.DroppedOldPeersUserAlert;
import freenet.node.useralerts.PeerManagerUserAlert;
import freenet.node.useralerts.SimpleUserAlert;
import freenet.node.useralerts.UserAlert;
import freenet.support.ByteArrayWrapper;
import freenet.support.HTMLNode;
import freenet.support.Logger;
import freenet.support.ShortBuffer;
import freenet.support.SimpleFieldSet;
import freenet.support.TimeUtil;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import freenet.support.io.NativeThread;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * @author amphibian
 * 
 * Maintains:
 * - A list of peers we want to connect to.
 * - A list of peers we are actually connected to.
 * - Each peer's Location.
 */
public class PeerManager {

        private static volatile boolean logMINOR;
        static {
            Logger.registerClass(PeerManager.class);
        }
	/** Our Node */
	final Node node;
	/** All the peers we want to connect to */
	private PeerNode[] myPeers;
	/** All the peers we are actually connected to */
	private PeerNode[] connectedPeers;
	private String darkFilename;
        private String openFilename;
        private String oldOpennetPeersFilename;
        // FIXME MEMORY use a hash. Not hashCode() though.
        // FIXME Strip metadata, except for peer locations.
        private String darknetPeersStringCache = null;
        private String opennetPeersStringCache = null;
        private String oldOpennetPeersStringCache = null;
        private PeerManagerUserAlert ua;	// Peers stuff
	/** age of oldest never connected peer (milliseconds) */
	private long oldestNeverConnectedDarknetPeerAge;
	/** Next time to update oldestNeverConnectedPeerAge */
	private long nextOldestNeverConnectedDarknetPeerAgeUpdateTime = -1;
	/** oldestNeverConnectedPeerAge update interval (milliseconds) */
	private static final long oldestNeverConnectedPeerAgeUpdateInterval = 5000;
	/** Next time to log the PeerNode status summary */
	private long nextPeerNodeStatusLogTime = -1;
	/** PeerNode status summary log interval (milliseconds) */
	private static final long peerNodeStatusLogInterval = 5000;
	/** Statuses for all PeerNode's */
	private final PeerStatusTracker<Integer> allPeersStatuses;
	/** Statuses for darknet PeerNode's */
	private final PeerStatusTracker<Integer> darknetPeersStatuses;
	/** PeerNode routing backoff reasons, by reason (realtime) */
	private final PeerStatusTracker<String> peerNodeRoutingBackoffReasonsRT;
	/** PeerNode routing backoff reasons, by reason (bulk) */
	private final PeerStatusTracker<String> peerNodeRoutingBackoffReasonsBulk;
	/** Next time to update routableConnectionStats */
	private long nextRoutableConnectionStatsUpdateTime = -1;
	/** routableConnectionStats update interval (milliseconds) */
	private static final long routableConnectionStatsUpdateInterval = SECONDS.toMillis(7);

	/** Should update the peer-file ? */
	private volatile boolean shouldWritePeersDarknet = false;
	private volatile boolean shouldWritePeersOpennet = false;
	private static final long MIN_WRITEPEERS_DELAY = MINUTES.toMillis(5); // Urgent stuff calls write*PeersUrgent.
	private final Runnable writePeersRunnable = new Runnable() {

		@Override
		public void run() {
			try {
				writePeersNow(false);
			} finally {
				node.getTicker().queueTimedJob(writePeersRunnable, MIN_WRITEPEERS_DELAY);
			}
		}
	};
	
	protected void writePeersNow(boolean rotateBackups) {
		writePeersDarknetNow(rotateBackups);
		writePeersOpennetNow(rotateBackups);
	}

	private void writePeersDarknetNow(boolean rotateBackups) {
		if(shouldWritePeersDarknet) {
			shouldWritePeersDarknet = false;
			writePeersInnerDarknet(rotateBackups);
		}
	}

	private void writePeersOpennetNow(boolean rotateBackups) {
		if(shouldWritePeersOpennet) {
			shouldWritePeersOpennet = false;
			writePeersInnerOpennet(rotateBackups);
		}
	}

	public static final int PEER_NODE_STATUS_CONNECTED = 1;
	public static final int PEER_NODE_STATUS_ROUTING_BACKED_OFF = 2;
	public static final int PEER_NODE_STATUS_TOO_NEW = 3;
	public static final int PEER_NODE_STATUS_TOO_OLD = 4;
	public static final int PEER_NODE_STATUS_DISCONNECTED = 5;
	public static final int PEER_NODE_STATUS_NEVER_CONNECTED = 6;
	public static final int PEER_NODE_STATUS_DISABLED = 7;
	public static final int PEER_NODE_STATUS_BURSTING = 8;
	public static final int PEER_NODE_STATUS_LISTENING = 9;
	public static final int PEER_NODE_STATUS_LISTEN_ONLY = 10;
	public static final int PEER_NODE_STATUS_CLOCK_PROBLEM = 11;
	public static final int PEER_NODE_STATUS_CONN_ERROR = 12;
	public static final int PEER_NODE_STATUS_DISCONNECTING = 13;
	public static final int PEER_NODE_STATUS_ROUTING_DISABLED = 14;
	public static final int PEER_NODE_STATUS_NO_LOAD_STATS = 15;
	
	/** The list of listeners that needs to be notified when peers' statuses changed.
	 * FIXME use this for PeerManagerUserAlert.
	 * FIXME don't register with each PeerNode separately, just provide an
	 * interface for listening for all of them. (Possibly excluding 
	 * status changes on seed servers and seed clients). 
	 * */
	private List<PeerStatusChangeListener> listeners=new CopyOnWriteArrayList<PeerStatusChangeListener>();

	/**
	 * Create a PeerManager by reading a list of peers from
	 * a file.
	 * @param node
	 * @param shutdownHook
	 */
	public PeerManager(Node node, SemiOrderedShutdownHook shutdownHook) {
		Logger.normal(this, "Creating PeerManager");
		peerNodeRoutingBackoffReasonsRT = new PeerStatusTracker<String>();
		peerNodeRoutingBackoffReasonsBulk = new PeerStatusTracker<String>();
		allPeersStatuses = new PeerStatusTracker<Integer>();
		darknetPeersStatuses = new PeerStatusTracker<Integer>();
		System.out.println("Creating PeerManager");
		myPeers = new PeerNode[0];
		connectedPeers = new PeerNode[0];
		this.node = node;
		shutdownHook.addEarlyJob(new Thread() {
			public void run() {
				// Ensure we're not waiting 5mins here
				writePeersDarknet();
				writePeersOpennet();
				writePeersNow(false);
			}
		});
	}

	/**
	 * Attempt to read a file full of noderefs. Try the file as named first, then the .bak if it is empty or
	 * otherwise doesn't work. WARNING: Only call this AFTER the Node constructor has completed! Methods may 
	 * be called on Node!
	 * @param filename The filename to read from. If this doesn't work, we try the .bak file.
	 * @param crypto The cryptographic identity which these nodes are connected to.
	 * @param opennet The opennet manager for the nodes. Only needed (for constructing the nodes) if isOpennet.
	 * @param isOpennet Whether the file contains opennet peers.
	 * @param oldOpennetPeers If true, don't add the nodes to the routing table, pass them to the opennet
	 * manager as "old peers" i.e. inactive nodes which may try to reconnect.
	 */
	void tryReadPeers(String filename, NodeCrypto crypto, OpennetManager opennet, boolean isOpennet, boolean oldOpennetPeers) {
		synchronized(writePeersSync) {
			if(!oldOpennetPeers)
				if(isOpennet)
					openFilename = filename;
				else
					darkFilename = filename;
		}
		int maxBackups = isOpennet ? BACKUPS_OPENNET : BACKUPS_DARKNET;
		for(int i=0;i<=maxBackups;i++) {
			File peersFile = this.getBackupFilename(filename, i);
			// Try to read the node list from disk
			if(peersFile.exists())
				if(readPeers(peersFile, crypto, opennet, oldOpennetPeers)) {
					String msg;
					if(oldOpennetPeers)
						msg = "Read " + opennet.countOldOpennetPeers() + " old-opennet-peers from " + peersFile;
					else if(isOpennet)
						msg = "Read " + getOpennetPeers().length + " opennet peers from " + peersFile;
					else
						msg = "Read " + getDarknetPeers().length + " darknet peers from " + peersFile;
					Logger.normal(this, msg);
					System.out.println(msg);
					return;
				}
		}
		if(!isOpennet)
			System.out.println("No darknet peers file found.");
		// The other cases are less important.
	}

	private boolean readPeers(File peersFile, NodeCrypto crypto, OpennetManager opennet, boolean oldOpennetPeers) {
		boolean someBroken = false;
		boolean gotSome = false;
		FileInputStream fis;
		try {
			fis = new FileInputStream(peersFile);
		} catch(FileNotFoundException e4) {
			Logger.normal(this, "Peers file not found: " + peersFile);
			return false;
		}
		InputStreamReader ris;
		try {
			ris = new InputStreamReader(fis, "UTF-8");
		} catch(UnsupportedEncodingException e4) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e4, e4);
		}
		BufferedReader br = new BufferedReader(ris);
		File brokenPeersFile = new File(peersFile.getPath() + ".broken");
		DroppedOldPeersUserAlert droppedOldPeers = new DroppedOldPeersUserAlert(brokenPeersFile);
		try { // FIXME: no better way?
			while(true) {
				// Read a single NodePeer
				SimpleFieldSet fs;
				fs = new SimpleFieldSet(br, false, true);
				try {
					PeerNode pn = PeerNode.create(fs, node, crypto, opennet);
					if(oldOpennetPeers) {
					    if(!(pn instanceof OpennetPeerNode))
					        Logger.error(this, "Darknet node in old opennet peers?!: "+pn);
					    else
					        opennet.addOldOpennetNode((OpennetPeerNode)pn);
					} else
						addPeer(pn, true, false);
					gotSome = true;
				} catch(FSParseException e2) {
					Logger.error(this, "Could not parse peer: " + e2 + '\n' + fs.toString(), e2);
					System.err.println("Cannot parse a friend from the peers file: "+e2);
					someBroken = true;
					continue;
				} catch(PeerParseException e2) {
					Logger.error(this, "Could not parse peer: " + e2 + '\n' + fs.toString(), e2);
					System.err.println("Cannot parse a friend from the peers file: "+e2);
					someBroken = true;
					continue;
				} catch(ReferenceSignatureVerificationException e2) {
					Logger.error(this, "Could not parse peer: " + e2 + '\n' + fs.toString(), e2);
					System.err.println("Cannot parse a friend from the peers file: "+e2);
					someBroken = true;
					continue;
				} catch (RuntimeException e2) {
					Logger.error(this, "Could not parse peer: " + e2 + '\n' + fs.toString(), e2);
					System.err.println("Cannot parse a friend from the peers file: "+e2);
					someBroken = true;
					continue;
					// FIXME tell the user???
				} catch (PeerTooOldException e) {
				    if(crypto.isOpennet) {
				        // Ignore.
				        Logger.error(this, "Dropping too-old opennet peer");
				    } else {
				        // A lot more noisy!
				        droppedOldPeers.add(e, fs.get("myName"));
				    }
                    someBroken = true;
                    continue;
                }
			}
		} catch(EOFException e) {
			// End of file, fine
		} catch(IOException e1) {
			Logger.error(this, "Could not read peers file: " + e1, e1);
		}
		try {
			br.close();
		} catch(IOException e3) {
			Logger.error(this, "Ignoring " + e3 + " caught reading " + peersFile, e3);
		}
		if(someBroken) {
			try {
				brokenPeersFile.delete();
				FileOutputStream fos = new FileOutputStream(brokenPeersFile);
				fis = new FileInputStream(peersFile);
				FileUtil.copy(fis, fos, -1);
				fos.close();
				fis.close();
				System.err.println("Broken peers file copied to " + brokenPeersFile);
			} catch (IOException e) {
				System.err.println("Unable to copy broken peers file.");
			}
		}
		if(!droppedOldPeers.isEmpty()) {
		    try {
		        node.clientCore.alerts.register(droppedOldPeers);
		        Logger.error(this, droppedOldPeers.getText());
		    } catch (Throwable t) {
		        // Startup MUST complete, don't let client layer problems kill it.
		        Logger.error(this, "Caught error telling user about dropped peers", t);
		    }
		}
		return !someBroken;
	}

    public boolean addPeer(PeerNode pn) {
		return addPeer(pn, false, false);
	}

	/**
	 * Add a peer.
	 * @param pn The node to add to the routing table.
	 * @param ignoreOpennet If true, don't check for opennet peers. If false, check for opennet peers and if so,
	 * if opennet is enabled auto-add them to the opennet LRU, otherwise fail.
	 * @param reactivate If true, re-enable the peer if it is in state DISCONNECTING before re-adding it.
	 * @return True if the node was successfully added. False if it was already present, or if we tried to add
	 * an opennet peer when opennet was disabled.
	 */
	boolean addPeer(PeerNode pn, boolean ignoreOpennet, boolean reactivate) {
		assert (pn != null);
		if(reactivate)
			pn.forceCancelDisconnecting();
		synchronized(this) {
			for(PeerNode myPeer: myPeers) {
				if(myPeer.equals(pn)) {
					if(logMINOR)
						Logger.minor(this, "Can't add peer " + pn + " because already have " + myPeer, new Exception("debug"));
					return false;
				}
			}
			myPeers = Arrays.copyOf(myPeers, myPeers.length + 1);
			myPeers[myPeers.length - 1] = pn;
			Logger.normal(this, "Added " + pn);
		}
		if(pn.recordStatus())
			addPeerNodeStatus(pn.getPeerNodeStatus(), pn, false);
		pn.setPeerNodeStatus(System.currentTimeMillis());
		if((!ignoreOpennet) && pn instanceof OpennetPeerNode) {
			OpennetManager opennet = node.getOpennet();
			if(opennet != null)
				opennet.forceAddPeer((OpennetPeerNode)pn, true);
			else {
				Logger.error(this, "Adding opennet peer when no opennet enabled!!!: " + pn + " - removing...");
				removePeer(pn);
				return false;
			}
		}
		notifyPeerStatusChangeListeners();
		if(!pn.isSeed()) {
			// LOCKING: addPeer() can be called inside PM lock, so must do this on a separate thread.
			node.executor.execute(new Runnable() {
				
				@Override
				public void run() {
					updatePMUserAlert();
				}
				
			});
		}
		return true;
	}

	synchronized boolean havePeer(PeerNode pn) {
		for(PeerNode myPeer: myPeers) {
			if(myPeer == pn)
				return true;
		}
		return false;
	}

	/** Remove a PeerNode. LOCKING: Caller should not hold locks on any PeerNode. */
	private boolean removePeer(PeerNode pn) {
		if(logMINOR)
			Logger.minor(this, "Removing " + pn);
		boolean isInPeers = false;
		synchronized(this) {
			for(PeerNode myPeer: myPeers) {
				if(myPeer == pn)
					isInPeers = true;
			}
			if(pn instanceof DarknetPeerNode)
				((DarknetPeerNode) pn).removeExtraPeerDataDir();
			if(isInPeers) {
				int peerNodeStatus = pn.getPeerNodeStatus();
				if(pn.recordStatus())
					removePeerNodeStatus(peerNodeStatus, pn, !isInPeers);
				String peerNodePreviousRoutingBackoffReason = pn.getPreviousBackoffReason(true);
				if(peerNodePreviousRoutingBackoffReason != null)
					removePeerNodeRoutingBackoffReason(peerNodePreviousRoutingBackoffReason, pn, true);
				peerNodePreviousRoutingBackoffReason = pn.getPreviousBackoffReason(false);
				if(peerNodePreviousRoutingBackoffReason != null)
					removePeerNodeRoutingBackoffReason(peerNodePreviousRoutingBackoffReason, pn, false);

				// removing from connectedPeers
				ArrayList<PeerNode> a = new ArrayList<PeerNode>();
				for(PeerNode mp : myPeers) {
					if((mp != pn) && mp.isConnected() && mp.isRealConnection())
						a.add(mp);
				}

				PeerNode[] newConnectedPeers = new PeerNode[a.size()];
				newConnectedPeers = a.toArray(newConnectedPeers);
				connectedPeers = newConnectedPeers;

				// removing from myPeers
				PeerNode[] newMyPeers = new PeerNode[myPeers.length - 1];
				int positionInNewArray = 0;
				for(PeerNode mp : myPeers) {
					if(mp != pn) {
						newMyPeers[positionInNewArray] = mp;
						positionInNewArray++;
					}
				}
				myPeers = newMyPeers;

				Logger.normal(this, "Removed " + pn);
			}
		}
		pn.onRemove();
		if(isInPeers && !pn.isSeed())
			updatePMUserAlert();
		notifyPeerStatusChangeListeners();
		updatePMUserAlert();
		return true;
	}

	public boolean removeAllPeers() {
		Logger.normal(this, "removeAllPeers!");
		PeerNode[] oldPeers;
		synchronized(this) {
			oldPeers = myPeers;
			myPeers = new PeerNode[0];
			connectedPeers = new PeerNode[0];
		}
		for(PeerNode oldPeer: oldPeers)
			oldPeer.onRemove();
		notifyPeerStatusChangeListeners();
		return true;
	}

	public boolean disconnected(PeerNode pn) {
		synchronized(this) {
			boolean isInPeers = false;
			for(PeerNode connectedPeer: connectedPeers) {
				if(connectedPeer == pn)
					isInPeers = true;
			}
			if(!isInPeers)
				return false;
			// removing from connectedPeers
			ArrayList<PeerNode> a = new ArrayList<PeerNode>();
			for(PeerNode mp : myPeers) {
				if((mp != pn) && mp.isRoutable())
					a.add(mp);
			}
			PeerNode[] newConnectedPeers = new PeerNode[a.size()];
			newConnectedPeers = a.toArray(newConnectedPeers);
			connectedPeers = newConnectedPeers;
		}
                if(!pn.isSeed())
                    updatePMUserAlert();
		node.lm.announceLocChange();
		return true;
	}
	long timeFirstAnyConnections = 0;

	public long getTimeFirstAnyConnections() {
		return timeFirstAnyConnections;
	}

	public void addConnectedPeer(PeerNode pn) {
		if(!pn.isRealConnection()) {
			if(logMINOR)
				Logger.minor(this, "Not a real connection: " + pn);
			return;
		}
		if(!pn.isConnected()) {
			if(logMINOR)
				Logger.minor(this, "Not connected: " + pn);
			return;
		}
		long now = System.currentTimeMillis();
		synchronized(this) {
			if(timeFirstAnyConnections == 0)
				timeFirstAnyConnections = now;
			for(PeerNode connectedPeer: connectedPeers) {
				if(connectedPeer == pn) {
					if(logMINOR)
						Logger.minor(this, "Already connected: " + pn);
					return;
				}
			}
			boolean inMyPeers = false;
			for(PeerNode mp: myPeers) {
				if(mp == pn) {
					inMyPeers = true;
					break;
				}
			}
			if(!inMyPeers) {
				Logger.error(this, "Connecting to " + pn + " but not in peers!");
				// FIXME LOCKING calling inside PM lock - safe???
				addPeer(pn);
			}
			if(logMINOR)
				Logger.minor(this, "Connecting: " + pn);
			connectedPeers = Arrays.copyOf(connectedPeers, connectedPeers.length + 1);
			connectedPeers[connectedPeers.length - 1] = pn;
			if(logMINOR)
				Logger.minor(this, "Connected peers: " + connectedPeers.length);
		}
		if(!pn.isSeed())
                    updatePMUserAlert();
		node.lm.announceLocChange();
	}
//    NodePeer route(double targetLocation, RoutingContext ctx) {
//        double minDist = 1.1;
//        NodePeer best = null;
//        for(NodePeer p: connectedPeers) {
//            if(ctx.alreadyRoutedTo(p)) continue;
//            double loc = p.getLocation().getValue();
//            double dist = Math.abs(loc - targetLocation);
//            if(dist < minDist) {
//                minDist = dist;
//                best = p;
//            }
//        }
//        return best;
//    }
//    
//    NodePeer route(Location target, RoutingContext ctx) {
//        return route(target.getValue(), ctx);
//    }
//
	/**
	 * Find the node with the given Peer address. Used by FNPPacketMangler to try to 
	 * quickly identify a peer by the address of the packet. Includes 
	 * non-isRealConnection()'s since they can also be connected.
	 */
	public PeerNode getByPeer(Peer peer) {
		PeerNode[] peerList = myPeers();
		for(PeerNode pn : peerList) {
			if(pn.isDisabled()) continue;
			if(pn.matchesPeerAndPort(peer))
				return pn;
		}
		// Try a match by IP address if we can't match exactly by IP:port.
		FreenetInetAddress addr = peer.getFreenetAddress();
		for(PeerNode pn : peerList) {
			if(pn.isDisabled()) continue;
			if(pn.matchesIP(addr, false))
				return pn;
		}
		return null;
	}
	
	/**
	 * Find the node with the given Peer address, or IP address. Checks the outgoing
	 * packet mangler as well.
	 * @param peer
	 * @param mangler
	 * @return
	 */
	public PeerNode getByPeer(Peer peer, FNPPacketMangler mangler) {
		PeerNode[] peerList = myPeers();
		for(PeerNode pn : peerList) {
			if(pn.isDisabled()) continue;
			if(pn.matchesPeerAndPort(peer) && pn.getOutgoingMangler() == mangler)
				return pn;
		}
		// Try a match by IP address if we can't match exactly by IP:port.
		FreenetInetAddress addr = peer.getFreenetAddress();
		for(PeerNode pn : peerList) {
			if(pn.isDisabled()) continue;
			if(pn.matchesIP(addr, false) && pn.getOutgoingMangler() == mangler)
				return pn;
		}
		return null;
	}

	/**
	 * Find nodes with a given IP address.
	 */
	public ArrayList<PeerNode> getAllConnectedByAddress(FreenetInetAddress a, boolean strict) {
		ArrayList<PeerNode> found = null;
		
		PeerNode[] peerList = myPeers();
		// Try a match by IP address if we can't match exactly by IP:port.
		for(PeerNode pn : peerList) {
			if(!pn.isConnected()) continue;
			if(!pn.isRoutable()) continue;
			if(pn.matchesIP(a, strict)) {
				if(found == null) found = new ArrayList<PeerNode>();
				found.add(pn);
			}
		}
		return found;
	}

	/**
	 * Connect to a node provided the fieldset representing it.
	 * @throws PeerTooOldException 
	 */
	public void connect(SimpleFieldSet noderef, FRIEND_TRUST trust, FRIEND_VISIBILITY visibility) throws FSParseException, PeerParseException, ReferenceSignatureVerificationException, PeerTooOldException {
		PeerNode pn = node.createNewDarknetNode(noderef, trust, visibility);
		PeerNode[] peerList = myPeers();
		for(PeerNode mp: peerList) {
			if(Arrays.equals(mp.peerECDSAPubKeyHash, pn.peerECDSAPubKeyHash))
				return;
		}
		addPeer(pn);
	}
	
	public void disconnectAndRemove(final PeerNode pn, boolean sendDisconnectMessage, final boolean waitForAck, boolean purge) {
		disconnect(pn, sendDisconnectMessage, waitForAck, purge, false, true, Node.MAX_PEER_INACTIVITY);
	}

	/**
	 * Disconnect from a specified node
	 * @param sendDisconnectMessage If false, don't send the FNPDisconnected message.
	 * @param waitForAck If false, don't wait for the ack for the FNPDisconnected message.
	 * @param purge If true, set the purge flag on the disconnect, causing the other peer
	 * to purge this node from e.g. its old opennet peers list.
	 * @param dumpMessagesNow If true, dump queued messages immediately, before the 
	 * disconnect completes.
	 * @param remove If true, remove the node from the routing table and tell the peer to do so.
	 */
	public void disconnect(final PeerNode pn, boolean sendDisconnectMessage, final boolean waitForAck, boolean purge, boolean dumpMessagesNow, final boolean remove, long timeout) {
		if(logMINOR)
			Logger.minor(this, "Disconnecting " + pn.shortToString(), new Exception("debug"));
		synchronized(this) {
			if(!havePeer(pn))
				return;
		}
		if(pn.notifyDisconnecting(dumpMessagesNow)) {
			if(logMINOR)
				Logger.minor(this, "Already disconnecting "+pn.shortToString());
			return;
		}
		if(sendDisconnectMessage) {
			Message msg = DMT.createFNPDisconnect(remove, purge, -1, new ShortBuffer(new byte[0]));
			try {
				pn.sendAsync(msg, new AsyncMessageCallback() {

					boolean done = false;

					@Override
					public void acknowledged() {
						done();
					}

					@Override
					public void disconnected() {
						done();
					}

					@Override
					public void fatalError() {
						done();
					}

					@Override
					public void sent() {
						if(!waitForAck)
							done();
					}

					void done() {
						synchronized(this) {
							if(done)
								return;
							done = true;
						}
						if(remove) {
							if(removePeer(pn) && !pn.isSeed())
								writePeersUrgent(pn.isOpennet());
						}
					}
				}, ctrDisconn);
			} catch(NotConnectedException e) {
				if(remove) {
					if(pn.isDisconnecting() && removePeer(pn) && !pn.isSeed())
						writePeersUrgent(pn.isOpennet());
				}
				return;
			}
			if(!pn.isSeed()) {
				node.getTicker().queueTimedJob(new Runnable() {
					
					@Override
					public void run() {
						if(pn.isDisconnecting()) {
							if(remove) {
								if(removePeer(pn)) {
									if(!pn.isSeed()) {
										writePeersUrgent(pn.isOpennet());
									}
								}
							}
							pn.disconnected(true, true);
						}
					}
				}, timeout);
			}
		} else {
			if(remove) {
				if(removePeer(pn) && !pn.isSeed())
					writePeersUrgent(pn.isOpennet());
			}
		}
	}
	final ByteCounter ctrDisconn = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			node.nodeStats.disconnBytesReceived(x);
		}

		@Override
		public void sentBytes(int x) {
			node.nodeStats.disconnBytesSent(x);
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}
	};

	/**
	 * @return An array of the current locations (as doubles) of all
	 * our connected peers or double[0] if Node.shallWePublishOurPeersLocation() is false
	 */
	public double[] getPeerLocationDoubles(boolean pruneBackedOffPeers) {
		double[] locs;
		if(!node.shallWePublishOurPeersLocation())
			return new double[0];
		PeerNode[] conns = connectedPeers();
		locs = new double[conns.length];
		int x = 0;
		for(PeerNode conn: conns) {
			if(conn.isRoutable()) {
				if(!pruneBackedOffPeers || !conn.shouldBeExcludedFromPeerList()) {
					locs[x++] = conn.getLocation();
				}
			}
		}
		// Wipe out any information contained in the order
		java.util.Arrays.sort(locs, 0, x);
		if(x != locs.length)
			return Arrays.copyOf(locs, x);
		else
			return locs;
	}

	/**
	 * @return A random routable connected peer.
	 * FIXME: should this take performance into account?
	 * DO NOT remove the "synchronized". See below for why.
	 */
	public synchronized PeerNode getRandomPeer(PeerNode exclude) {
		if(connectedPeers.length == 0)
			return null;
		for(int i = 0; i < 5; i++) {
			PeerNode pn = connectedPeers[node.random.nextInt(connectedPeers.length)];
			if(pn == exclude)
				continue;
			if(pn.isRoutable())
				return pn;
		}
		// None of them worked
		// Move the un-connected ones out
		// This is safe as they will add themselves when they
		// reconnect, and they can't do it yet as we are synchronized.
		ArrayList<PeerNode> v = new ArrayList<PeerNode>(connectedPeers.length);
		for(PeerNode pn : myPeers) {
			if(pn == exclude)
				continue;
			if(pn.isRoutable())
				v.add(pn);
			else
				if(logMINOR)
					Logger.minor(this, "Excluding " + pn + " because is disconnected");
		}
		int lengthWithoutExcluded = v.size();
		if((exclude != null) && exclude.isRoutable())
			v.add(exclude);
		PeerNode[] newConnectedPeers = new PeerNode[v.size()];
		newConnectedPeers = v.toArray(newConnectedPeers);
		if(logMINOR)
			Logger.minor(this, "Connected peers (in getRandomPeer): " + newConnectedPeers.length + " was " + connectedPeers.length);
		connectedPeers = newConnectedPeers;
		if(lengthWithoutExcluded == 0)
			return null;
		return connectedPeers[node.random.nextInt(lengthWithoutExcluded)];
	}

	public void localBroadcast(Message msg, boolean ignoreRoutability, 
	        boolean onlyRealConnections, ByteCounter ctr) {
	    localBroadcast(msg, ignoreRoutability, onlyRealConnections, ctr, 
	            Integer.MIN_VALUE, Integer.MAX_VALUE);
	}
	
	/**
	 * Asynchronously send this message to every connected peer.
	 * @param maxVersion Only send the message if the version >= maxVersion.
	 * @param minVersion Only send the message if the version <= minVersion.
	 */
	public void localBroadcast(Message msg, boolean ignoreRoutability, 
	        boolean onlyRealConnections, ByteCounter ctr, int minVersion, int maxVersion) {
		// myPeers not connectedPeers as connectedPeers only contains
		// ROUTABLE peers, and we may want to send to non-routable peers
		PeerNode[] peers = myPeers();
		for(PeerNode peer: peers) {
			if(ignoreRoutability) {
				if(!peer.isConnected())
					continue;
			} else
				if(!peer.isRoutable())
					continue;
			if(onlyRealConnections && !peer.isRealConnection())
				continue;
			int version = peer.getVersionNumber();
			if(version < minVersion) continue;
			if(version > maxVersion) continue;
			try {
				peer.sendAsync(msg, null, ctr);
			} catch(NotConnectedException e) {
				// Ignore
			}
		}
	}

	/**
	 * Asynchronously send a differential node reference to every isConnected() peer.
	 */
	public void locallyBroadcastDiffNodeRef(SimpleFieldSet fs, boolean toDarknetOnly, boolean toOpennetOnly) {
		// myPeers not connectedPeers as connectedPeers only contains
		// ROUTABLE peers and we want to also send to non-routable peers
		PeerNode[] peers = myPeers();
		for(PeerNode peer: peers) {
			if(!peer.isConnected())
				continue;
			if(toDarknetOnly && !peer.isDarknet())
				continue;
			if(toOpennetOnly && !peer.isOpennet())
				continue;
			peer.sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_DIFFNODEREF, false, 0, false);
		}
	}

	public PeerNode getRandomPeer() {
		return getRandomPeer(null);
	}

	public PeerNode closerPeer(PeerNode pn, Set<PeerNode> routedTo, double loc, boolean ignoreSelf, boolean calculateMisrouting,
	        int minVersion, List<Double> addUnpickedLocsTo, Key key, short outgoingHTL, long ignoreBackoffUnder, boolean isLocal, boolean realTime, boolean excludeMandatoryBackoff) {
		return closerPeer(pn, routedTo, loc, ignoreSelf, calculateMisrouting, minVersion, addUnpickedLocsTo, 2.0, key, outgoingHTL, ignoreBackoffUnder, isLocal, realTime, null, false, System.currentTimeMillis(), excludeMandatoryBackoff);
	}

	/**
	 * Find the peer, if any, which is closer to the target location than we are, and is not included in the provided set.
	 * If ignoreSelf==false, and we are closer to the target than any peers, this function returns null.
	 * This function returns two values, the closest such peer which is backed off, and the same which is not backed off.
	 * It is possible for either to be null independent of the other, 'closest' is the closer of the two in either case, and
	 * will not be null if any of the other two return values is not null. LOCKING: This will briefly take
	 * various locks, try to avoid calling it with lots of locks held.
	 * @param addUnpickedLocsTo Add all locations we didn't choose which we could have routed to to 
	 * this array. Remove the location of the peer we pick from it.
	 * @param maxDistance If a node is further away from the target than this distance, ignore it.
	 * @param key The original key, if we have it, and if we want to consult with the FailureTable
	 * to avoid routing to nodes which have recently failed for the same key.
	 * @param isLocal We don't just check pn == null because in some cases pn can be null here: If an insert is forked, for
	 * a remote requests, we can route back to the originator, so we set pn to null. Whereas for stats we want to know 
	 * accurately whether this was originated remotely.
	 * @param recentlyFailed If non-null, we should check for recently failed: If we have routed to, and got
	 * a failed response from, and are still connected to and within the timeout for, our top two routing choices,
	 * *and* the same is true of at least 3 nodes, we fill in this object and return null. This will cause a
	 * RecentlyFailed message to be returned to the originator, allowing them to retry in a little while. Note that the
	 * scheduler is not clever enough to retry immediately when that timeout elapses, and even if it was, it probably
	 * wouldn't be a good idea due to introducing a round-trip-to-request-originator; FIXME consider this.
	 */
	public PeerNode closerPeer(PeerNode pn, Set<PeerNode> routedTo, double target, boolean ignoreSelf,
	        boolean calculateMisrouting, int minVersion, List<Double> addUnpickedLocsTo, double maxDistance, Key key, short outgoingHTL, long ignoreBackoffUnder, boolean isLocal, boolean realTime,
	        RecentlyFailedReturn recentlyFailed, boolean ignoreTimeout, long now, boolean newLoadManagement) {
		
		int countWaiting = 0;
		long soonestTimeoutWakeup = Long.MAX_VALUE;
		
		PeerNode[] peers = connectedPeers();
		if(!node.enablePerNodeFailureTables)
			key = null;
		if(logMINOR)
			Logger.minor(this, "Choosing closest peer: connectedPeers=" + peers.length+" key "+key);
		
		double myLoc = node.getLocation();
		
		double maxDiff = Double.MAX_VALUE;
		if(!ignoreSelf)
			maxDiff = Location.distance(myLoc, target);
		
		double prevLoc = -1.0;
		if(pn != null) prevLoc = pn.getLocation();

		/**
		 * Routing order:
		 * - Non-timed-out non-backed-off peers, in order of closeness to the target.
		 * - Timed-out, non-backed-off peers, least recently timed out first.
		 * - Non-timed-out backed-off peers, in order of closeness to the target.
		 * - Timed out, backed-off peers, least recently timed out first.
		 * - 
		 */
		double closestDistance = Double.MAX_VALUE;
		// If closestDistance is FOAF, this is the real distance.
		// Reset every time closestDistance is.
		double closestRealDistance = Double.MAX_VALUE;

		PeerNode closestBackedOff = null;
		double closestBackedOffDistance = Double.MAX_VALUE;
		double closestRealBackedOffDistance = Double.MAX_VALUE;

		PeerNode closestNotBackedOff = null;
		double closestNotBackedOffDistance = Double.MAX_VALUE;
		double closestRealNotBackedOffDistance = Double.MAX_VALUE;

		PeerNode leastRecentlyTimedOut = null;
		long timeLeastRecentlyTimedOut = Long.MAX_VALUE;
		double leastRecentlyTimedOutDistance = Double.MAX_VALUE;

		PeerNode leastRecentlyTimedOutBackedOff = null;
		long timeLeastRecentlyTimedOutBackedOff = Long.MAX_VALUE;
		double leastRecentlyTimedOutBackedOffDistance = Double.MAX_VALUE;
		
		TimedOutNodesList entry = null;

		if(key != null)
			entry = node.failureTable.getTimedOutNodesList(key);
		
		double[] selectionRates = new double[peers.length];
		double totalSelectionRate = 0.0;
		for(int i=0;i<peers.length;i++) {
			selectionRates[i] = peers[i].selectionRate();
			totalSelectionRate += selectionRates[i];
		}
		boolean enableFOAFMitigationHack = (peers.length >= PeerNode.SELECTION_MIN_PEERS) && (totalSelectionRate > 0.0);

		// Locations not to consider for routing: our own location, and locations already routed to
		Set<Double> excludeLocations = new HashSet<Double>();
		excludeLocations.add(myLoc);
		excludeLocations.add(prevLoc);
		for (PeerNode routedToNode : routedTo) {
			excludeLocations.add(routedToNode.getLocation());
		}

		for(int i = 0; i < peers.length; i++) {
			PeerNode p = peers[i];
			if(routedTo.contains(p)) {
				if(logMINOR)
					Logger.minor(this, "Skipping (already routed to): " + p.getPeer());
				continue;
			}
			if(p == pn) {
				if(logMINOR)
					Logger.minor(this, "Skipping (req came from): " + p.getPeer());
				continue;
			}
			if(!p.isRoutable()) {
				if(logMINOR)
					Logger.minor(this, "Skipping (not connected): " + p.getPeer());
				continue;
			}
			if(p.isDisconnecting()) {
				if(logMINOR)
					Logger.minor(this, "Skipping (disconnecting): "+p.getPeer());
				continue;
			}
			if(newLoadManagement && p.outputLoadTracker(realTime).getLastIncomingLoadStats() == null) {
				if(logMINOR)
					Logger.minor(this, "Skipping (no load stats): "+p.getPeer());
				continue;
			}
			if(minVersion > 0 && Version.getArbitraryBuildNumber(p.getVersion(), -1) < minVersion) {
				if(logMINOR)
					Logger.minor(this, "Skipping old version: " + p.getPeer());
				continue;
			}
			if(enableFOAFMitigationHack) {
				double selectionRate = selectionRates[i];
				double selectionSamplesPercentage = selectionRate / totalSelectionRate;
				if(PeerNode.SELECTION_PERCENTAGE_WARNING < selectionSamplesPercentage) {
					if(logMINOR)
						Logger.minor(this, "Skipping over-selectionned peer(" + selectionSamplesPercentage + "%): " + p.getPeer());
					continue;
				}
			}
			if(newLoadManagement && p.isInMandatoryBackoff(now, realTime)) {
				if(logMINOR) Logger.minor(this, "Skipping (mandatory backoff): "+p.getPeer());
				continue;
			}
			
			/** For RecentlyFailed i.e. request quenching */
			long timeoutRF = -1;
			/** For per-node failure tables i.e. routing */
			long timeoutFT = -1;
			if(entry != null && !ignoreTimeout) {
				timeoutFT = entry.getTimeoutTime(p, outgoingHTL, now, true);
				timeoutRF = entry.getTimeoutTime(p, outgoingHTL, now, false);
				if(timeoutRF > now) {
					soonestTimeoutWakeup = Math.min(soonestTimeoutWakeup, timeoutRF);
					countWaiting++;
				}
			}
			boolean timedOut = timeoutFT > now;
			//To help avoid odd race conditions, get the location only once and use it for all calculations.
			double loc = p.getLocation();
			boolean direct = true;
			double realDiff = Location.distance(loc, target);
			double diff = realDiff;
			
			if (p.shallWeRouteAccordingToOurPeersLocation(outgoingHTL)) {
				double l = p.getClosestPeerLocation(target, excludeLocations);
				if (!Double.isNaN(l)) {
					double newDiff = Location.distance(l, target);
					if(newDiff < diff) {
						loc = l;
						diff = newDiff;
						direct = false;
					}
				}
				if(logMINOR)
					Logger.minor(this, "The peer "+p+" has published his peer's locations and the closest we have found to the target is "+diff+" away.");
			}
			
			if(diff > maxDistance)
				continue;
			if((!ignoreSelf) && (diff > maxDiff)) {
				if(logMINOR)
					Logger.minor(this, "Ignoring, further than self >maxDiff=" + maxDiff);
				continue;
			}
			if(logMINOR)
				Logger.minor(this, "p.loc=" + loc + ", target=" + target + ", d=" + Location.distance(loc, target) + " usedD=" + diff + " timedOut=" + timedOut + " for " + p.getPeer());
			boolean chosen = false;
			if(diff < closestDistance || (Math.abs(diff - closestDistance) < Double.MIN_VALUE*2 && (direct || realDiff < closestRealDistance))) {
				closestDistance = diff;
				chosen = true;
				closestRealDistance = realDiff;
				if(logMINOR)
					Logger.minor(this, "New best: " + diff + " (" + loc + " for " + p.getPeer());
			}
			boolean backedOff = p.isRoutingBackedOff(ignoreBackoffUnder, realTime);
			if(backedOff && (diff < closestBackedOffDistance || (Math.abs(diff - closestBackedOffDistance) < Double.MIN_VALUE*2 && (direct || realDiff < closestRealBackedOffDistance))) && !timedOut) {
				closestBackedOffDistance = diff;
				closestBackedOff = p;
				chosen = true;
				closestRealBackedOffDistance = realDiff;
				if(logMINOR)
					Logger.minor(this, "New best-backed-off: " + diff + " (" + loc + " for " + p.getPeer());
			}
			if(!backedOff && (diff < closestNotBackedOffDistance || (Math.abs(diff - closestNotBackedOffDistance) < Double.MIN_VALUE*2 && (direct || realDiff < closestRealNotBackedOffDistance))) && !timedOut) {
				closestNotBackedOffDistance = diff;
				closestNotBackedOff = p;
				chosen = true;
				closestRealNotBackedOffDistance = realDiff;
				if(logMINOR)
					Logger.minor(this, "New best-not-backed-off: " + diff + " (" + loc + " for " + p.getPeer());
			}
			if(timedOut)
				if(!backedOff) {
					if(timeoutFT < timeLeastRecentlyTimedOut) {
						timeLeastRecentlyTimedOut = timeoutFT;
						leastRecentlyTimedOut = p;
						leastRecentlyTimedOutDistance = diff;
					}
				} else
					if(timeoutFT < timeLeastRecentlyTimedOutBackedOff) {
						timeLeastRecentlyTimedOutBackedOff = timeoutFT;
						leastRecentlyTimedOutBackedOff = p;
						leastRecentlyTimedOutBackedOffDistance = diff;
					}
			if(addUnpickedLocsTo != null && !chosen) {
				Double d = new Double(loc);
				// Here we can directly compare double's because they aren't processed in any way, and are finite and (probably) nonzero.
				if(!addUnpickedLocsTo.contains(d))
					addUnpickedLocsTo.add(d);
			}
		}

		PeerNode best = closestNotBackedOff;
		double bestDistance = closestNotBackedOffDistance;
		
		/**
		 * Various things are "advisory" i.e. they are taken into account but do not cause a request not to be routed at all:
		 * - Backoff: A node is backed off for a period after it rejects a request; 
		 * this is randomised and increases exponentially if no requests are accepted; 
		 * a longer period is imposed for timeouts after a request has been accepted 
		 * and transfer failures.
		 * - Recent failures: After various kinds of failures we impose a timeout, 
		 * until when we will try to avoid sending the same key to that node. This is 
		 * part of per-node failure tables.
		 * Combining these:
		 * - If there are nodes which are both not backed off and not timed out, we 
		 * route to whichever of those nodes is closest to the target location. If we 
		 * are still here, all nodes are either backed off or timed out.
		 * - If there are nodes which are timed out but not backed off, choose the node
		 * whose timeout expires soonest. Hence if a single key is requested 
		 * continually, we round-robin between nodes. If we still don't have a winner,
		 * we know all nodes are backed off.
		 * - If there are nodes which are backed off but not timed out, choose the node
		 * which is closest to the target but is not backed off. If we still don't have
		 * a winner, all nodes are backed off AND timed out.
		 * - Choose the backed off node whose timeout expires soonest.
		 */
		if(best == null) {
			if(leastRecentlyTimedOut != null) {
				// FIXME downgrade to DEBUG
				best = leastRecentlyTimedOut;
				bestDistance = leastRecentlyTimedOutDistance;
				if(logMINOR)
					Logger.minor(this, "Using least recently failed in-timeout-period peer for key: " + best.shortToString() + " for " + key);
			} else if(closestBackedOff != null) {
				best = closestBackedOff;
				bestDistance = closestBackedOffDistance;
				if(logMINOR)
					Logger.minor(this, "Using best backed-off peer for key: " + best.shortToString());
			} else if(leastRecentlyTimedOutBackedOff != null) {
				best = leastRecentlyTimedOutBackedOff;
				bestDistance = leastRecentlyTimedOutBackedOffDistance;
				if(logMINOR)
					Logger.minor(this, "Using least recently failed in-timeout-period backed-off peer for key: " + best.shortToString() + " for " + key);
			}
		}
		
		if(recentlyFailed != null && logMINOR)
			Logger.minor(this, "Count waiting: "+countWaiting);
		if(recentlyFailed != null && countWaiting >= 3 && 
				node.enableULPRDataPropagation /* dangerous to do RecentlyFailed if we won't track/propagate offers */) {
			// Recently failed is possible.
			// Route twice, each time ignoring timeout.
			// If both return a node which is in timeout, we should do RecentlyFailed.
			PeerNode first = closerPeer(pn, routedTo, target, ignoreSelf, false, minVersion, null, maxDistance, key, outgoingHTL, ignoreBackoffUnder, isLocal, realTime, null, true, now, newLoadManagement);
			if(first != null) {
				long firstTime;
				long secondTime;
				if((firstTime = entry.getTimeoutTime(first, outgoingHTL, now, false)) > now) {
					if(logMINOR) Logger.minor(this, "First choice is past now");
					HashSet<PeerNode> newRoutedTo = new HashSet<PeerNode>(routedTo);
					newRoutedTo.add(first);
					PeerNode second = closerPeer(pn, newRoutedTo, target, ignoreSelf, false, minVersion, null, maxDistance, key, outgoingHTL, ignoreBackoffUnder, isLocal, realTime, null, true, now, newLoadManagement);
					if(second != null) {
						if((secondTime = entry.getTimeoutTime(first, outgoingHTL, now, false)) > now) {
							if(logMINOR) Logger.minor(this, "Second choice is past now");
							// Recently failed!
							// Return the time at which this will change.
							// This is the sooner of the two top nodes' timeouts.
							// We also take into account the sooner of any timed out node, IF there are exactly 3 nodes waiting.
							long until = Math.min(secondTime, firstTime);
							if(countWaiting == 3) {
								// Count the others as well if there are only 3.
								// If there are more than that they won't matter.
								until = Math.min(until, soonestTimeoutWakeup);
								if(logMINOR) Logger.minor(this, "Recently failed: "+(int)Math.min(Integer.MAX_VALUE, (soonestTimeoutWakeup - now))+"ms");
							}
							
							long check;
							if(best == closestNotBackedOff)
								// We are routing to the perfect node, so no node coming out of backoff/FailureTable will make any difference; don't check.
								check = Long.MAX_VALUE;
							else
								// A node waking up from backoff or FailureTable might well change the decision, which limits the length of a RecentlyFailed.
								check = checkBackoffsForRecentlyFailed(peers, best, target, bestDistance, myLoc, prevLoc, now, entry, outgoingHTL);
							if(check < until) {
								if(logMINOR) Logger.minor(this, "Reducing RecentlyFailed from "+(until-now)+"ms to "+(check-now)+"ms because of check for peers to wakeup");
								until = check;
							}
							if(until > now + MIN_DELTA) {
								if(until > now + FailureTable.RECENTLY_FAILED_TIME) {
									Logger.error(this, "Wakeup time is too long: "+TimeUtil.formatTime(until-now));
									until = now + FailureTable.RECENTLY_FAILED_TIME;
								}
								if(!node.failureTable.hadAnyOffers(key)) {
									recentlyFailed.fail(until);
									return null;
								} else {
									if(logMINOR) Logger.minor(this, "Have an offer for the key so not sending RecentlyFailed");
								}
							} else {
								// Waking up too soon. Don't RecentlyFailed.
								if(logMINOR) Logger.minor(this, "Not sending RecentlyFailed because will wake up in "+(check-now)+"ms");
							}
						}
					} else {
						if(logMINOR) Logger.minor(this, "Second choice is not in timeout (for recentlyfailed): "+second);
					}
				} else {
					if(logMINOR) Logger.minor(this, "First choice is not in timeout (for recentlyfailed): "+first);
				}
			}
		}

		// DO NOT PUT A ELSE HERE: we need to re-check the value!
		if(best != null) {
			//racy... getLocation() could have changed
			if(calculateMisrouting) {
				int numberOfConnected = getPeerNodeStatusSize(PEER_NODE_STATUS_CONNECTED, false);
				int numberOfRoutingBackedOff = getPeerNodeStatusSize(PEER_NODE_STATUS_ROUTING_BACKED_OFF, false);
				if(numberOfRoutingBackedOff + numberOfConnected > 0)
					node.nodeStats.backedOffPercent.report((double) numberOfRoutingBackedOff / (double) (numberOfRoutingBackedOff + numberOfConnected));
			}
			//racy... getLocation() could have changed
			if(addUnpickedLocsTo != null)
				//Add the location which we did not pick, if it exists.
				if(closestNotBackedOff != null && closestBackedOff != null)
					addUnpickedLocsTo.add(new Double(closestBackedOff.getLocation()));
					
		}
		
		return best;
	}

	static final int MIN_DELTA = 2000;
	
	/** Check whether the routing situation will change soon because of a node coming out of backoff or of
	 * a FailureTable timeout.
	 * 
	 * If we have routed to a backed off node, or a node due to a failure-table timeout, there is a good
	 * chance that the ideal node will change shortly.
	 * 
	 * @return The time at which there will be a different best location to route to for this key, or
	 * Long.MAX_VALUE if we cannot predict a better peer after any amount of time.
	 */
	private long checkBackoffsForRecentlyFailed(PeerNode[] peers, PeerNode best, double target, double bestDistance, double myLoc, double prevLoc, long now, TimedOutNodesList entry, short outgoingHTL) {
		long overallWakeup = Long.MAX_VALUE;

		Set<Double> excludeLocations = new HashSet<Double>();
		excludeLocations.add(myLoc);
		excludeLocations.add(prevLoc);

		for(PeerNode p : peers) {
			if(p == best) continue;
			if(!p.isRoutable()) continue;
			
			// Is it further from the target than what we've chosen?
			// It probably is, but if there is backoff or failure tables involved it might not be.
			
			double loc = p.getLocation();
			double realDiff = Location.distance(loc, target);
			double diff = realDiff;
			
			if (p.shallWeRouteAccordingToOurPeersLocation(outgoingHTL)) {
				double l = p.getClosestPeerLocation(target, excludeLocations);
				if (!Double.isNaN(l)) {
					double newDiff = Location.distance(l, target);
					if(newDiff < diff) {
						loc = l;
						diff = newDiff;
					}
				}
				if(logMINOR)
					Logger.minor(this, "The peer "+p+" has published his peer's locations and the closest we have found to the target is "+diff+" away.");
			}
			
			if(diff >= bestDistance) continue;
			
			// The peer is of interest.
			// It will be relevant to routing at max(wakeup from backoff, failure table timeout, recentlyfailed timeout).
			
			long wakeup = 0;
			
			long timeoutFT = entry.getTimeoutTime(p, outgoingHTL, now, true);
			long timeoutRF = entry.getTimeoutTime(p, outgoingHTL, now, false);
			
			if(timeoutFT > now)
				wakeup = Math.max(wakeup, timeoutFT);
			if(timeoutRF > now)
				wakeup = Math.max(wakeup, timeoutRF);
			
			long bulkBackoff = p.getRoutingBackedOffUntilBulk();
			long rtBackoff = p.getRoutingBackedOffUntilRT();
			
			// Whichever backoff is sooner, but ignore if not backed off.
			
			if(bulkBackoff > now && rtBackoff <= now)
				wakeup = Math.max(wakeup, bulkBackoff);
			else if(bulkBackoff <= now && rtBackoff > now)
				wakeup = Math.max(wakeup, rtBackoff);
			else if(bulkBackoff > now && rtBackoff > now)
				wakeup = Math.max(wakeup, Math.min(bulkBackoff, rtBackoff));
			if(wakeup > now) {
				if(logMINOR) Logger.minor(this, "Peer "+p+" will wake up from backoff, failure table and recentlyfailed in "+(wakeup-now)+"ms");
				overallWakeup = Math.min(overallWakeup, wakeup);
			} else {
				// Race condition??? Just come out of backoff and we used the other one?
				// Don't take it into account.
				if(logMINOR) Logger.minor(this, "Better node in check backoffs for RecentlyFailed??? "+p);
			}
		}
		return overallWakeup;
	}

	/**
	 * @return Some status information
	 */
	public String getStatus() {
		StringBuilder sb = new StringBuilder();
		PeerNode[] peers = myPeers();
		String[] status = new String[peers.length];
		for(int i = 0; i < peers.length; i++) {
			PeerNode pn = peers[i];
			status[i] = pn.getStatus(true).toString();
		}
		Arrays.sort(status);
		for(String s: status) {
			sb.append(s);
			sb.append('\n');
		}
		return sb.toString();
	}

	/**
	 * @return TMCI peer list
	 */
	public String getTMCIPeerList() {
		StringBuilder sb = new StringBuilder();
		PeerNode[] peers = myPeers();
		String[] peerList = new String[peers.length];
		for(int i = 0; i < peers.length; i++) {
			PeerNode pn = peers[i];
			peerList[i] = pn.getTMCIPeerInfo();
		}
		Arrays.sort(peerList);
		for(String p: peerList) {
			sb.append(p);
			sb.append('\n');
		}
		return sb.toString();
	}

	private final Object writePeersSync = new Object();
	private final Object writePeerFileSync = new Object();
	
	void writePeers(boolean opennet) {
		if(opennet)
			writePeersOpennet();
		else
			writePeersDarknet();
	}

	void writePeersUrgent(boolean opennet) {
		if(opennet)
			writePeersOpennetUrgent();
		else
			writePeersDarknetUrgent();
	}
	
	void writePeersOpennetUrgent() {
		node.executor.execute(new PrioRunnable() {

			@Override
			public void run() {
				writePeersOpennetNow(true);
			}

			@Override
			public int getPriority() {
				return NativeThread.HIGH_PRIORITY;
			}
			
		});
	}

	void writePeersDarknetUrgent() {
		node.executor.execute(new PrioRunnable() {

			@Override
			public void run() {
				writePeersDarknetNow(true);
			}

			@Override
			public int getPriority() {
				return NativeThread.HIGH_PRIORITY;
			}
			
		});
	}

	void writePeersDarknet() {
		shouldWritePeersDarknet = true;
	}
	
	void writePeersOpennet() {
		shouldWritePeersOpennet = true;
	}
	
	protected String getDarknetPeersString() {
		StringBuilder sb = new StringBuilder();
		PeerNode[] peers = myPeers();
		for(PeerNode pn : peers) {
			if(pn instanceof DarknetPeerNode)
				sb.append(pn.exportDiskFieldSet().toOrderedString());
		}
		
		return sb.toString();
	}
	
	protected String getOpennetPeersString() {
		StringBuilder sb = new StringBuilder();
		PeerNode[] peers = myPeers();
		for(PeerNode pn : peers) {
			if(pn instanceof OpennetPeerNode)
				sb.append(pn.exportDiskFieldSet().toOrderedString());
		}
		
		return sb.toString();
	}
	
	protected String getOldOpennetPeersString(OpennetManager om) {
		StringBuilder sb = new StringBuilder();
		for(PeerNode pn : om.getOldPeers()) {
			if(pn instanceof OpennetPeerNode)
				sb.append(pn.exportDiskFieldSet().toOrderedString());
		}
		
		return sb.toString();
	}
	
	private static final int BACKUPS_OPENNET = 1;
	private static final int BACKUPS_DARKNET = 10;
	
	private void writePeersInnerDarknet(boolean rotateBackups) {
        String newDarknetPeersString = null;
		synchronized(writePeersSync) {
			if(darkFilename != null)
				newDarknetPeersString = getDarknetPeersString();
		}
		synchronized(writePeerFileSync) {
			if(newDarknetPeersString != null && !newDarknetPeersString.equals(darknetPeersStringCache))
				writePeersInner(darkFilename, darknetPeersStringCache = newDarknetPeersString, BACKUPS_DARKNET, rotateBackups);
		}
	}

	private void writePeersInnerOpennet(boolean rotateBackups) {
        String newOpennetPeersString = null;
        String newOldOpennetPeersString = null;
		synchronized(writePeersSync) {
			OpennetManager om = node.getOpennet();
			if(om != null) {
				if(openFilename != null)
					newOpennetPeersString = getOpennetPeersString();
				oldOpennetPeersFilename = om.getOldPeersFilename();
				newOldOpennetPeersString = getOldOpennetPeersString(om);
			}
		}
		synchronized(writePeerFileSync) {
			if(newOpennetPeersString != null && !newOpennetPeersString.equals(opennetPeersStringCache)) {
				writePeersInner(openFilename, opennetPeersStringCache = newOpennetPeersString, BACKUPS_OPENNET, rotateBackups);
			}
			if(newOldOpennetPeersString != null && !newOldOpennetPeersString.equals(oldOpennetPeersStringCache)) {
				writePeersInner(oldOpennetPeersFilename, oldOpennetPeersStringCache = newOldOpennetPeersString, BACKUPS_OPENNET, rotateBackups);
			}
		}
	}
	
	/**
	 * Write the peers file to disk
	 * @param rotateBackups If true, rotate backups. If false, just clobber the latest file.
	 */
	private void writePeersInner(String filename, String sb, int maxBackups, boolean rotateBackups) {
		assert(maxBackups >= 1);
		synchronized(writePeerFileSync) {
			FileOutputStream fos = null;
			File f;
			File full = new File(filename).getAbsoluteFile();
			try {
				f = File.createTempFile(full.getName()+".", ".tmp", full.getParentFile());
			} catch (IOException e2) {
				Logger.error(this, "Cannot write peers to disk: Cannot create temp file - " + e2, e2);
				Closer.close(fos);
				return;
			}
			try {
				fos = new FileOutputStream(f);
			} catch(FileNotFoundException e2) {
				Logger.error(this, "Cannot write peers to disk: Cannot create " + f + " - " + e2, e2);
				Closer.close(fos);
				f.delete();
				return;
			}
			OutputStreamWriter w = null;
			try {
				w = new OutputStreamWriter(fos, "UTF-8");
			} catch(UnsupportedEncodingException e2) {
				Closer.close(w);
				f.delete();
				throw new Error("Impossible: JVM doesn't support UTF-8: " + e2, e2);
			}
			try {
				w.write(sb);
				w.flush();
				fos.getFD().sync();
				w.close();
				w = null;
				
				if(rotateBackups) {
					File prevFile = null;
					for(int i=maxBackups;i>=0;i--) {
						File thisFile = getBackupFilename(filename, i);
						if(prevFile == null) {
							thisFile.delete();
						} else {
							if(thisFile.exists()) {
								FileUtil.renameTo(thisFile, prevFile);
							}
						}
						prevFile = thisFile;
					}
					FileUtil.renameTo(f, prevFile);
				} else {
					FileUtil.renameTo(f, getBackupFilename(filename, 0));
				}
			} catch(IOException e) {
				try {
					fos.close();
				} catch(IOException e1) {
					Logger.error(this, "Cannot close peers file: " + e, e);
				}
				Logger.error(this, "Cannot write file: " + e, e);
				f.delete();
				return; // don't overwrite old file!
			} finally {
				Closer.close(w);
				Closer.close(fos);
				f.delete();
			}
		}
	}

	private File getBackupFilename(String filename, int i) {
		if(i == 0) return new File(filename);
		if(i == 1) return new File(filename+".bak");
		return new File(filename+".bak."+i);
	}

	/**
	 * Update the numbers needed by our PeerManagerUserAlert on the UAM.
	 * Also run the node's onConnectedPeers() method if applicable.
	 * LOCKING: Do not call inside PeerNode lock.
	 */
	public void updatePMUserAlert() {
		if(ua == null)
			return;
		int peers, darknetPeers, opennetPeers;
		synchronized(this) {
			darknetPeers = this.getDarknetPeers().length;
			opennetPeers = this.getOpennetPeers().length;
			peers = darknetPeers + opennetPeers; // Seednodes don't count.
		}
		OpennetManager om = node.getOpennet();

		boolean opennetDefinitelyPortForwarded;
		boolean opennetEnabled;
		boolean opennetAssumeNAT;
		if(om != null) {
			opennetEnabled = true;
			opennetDefinitelyPortForwarded = om.crypto.definitelyPortForwarded();
			opennetAssumeNAT = om.crypto.config.alwaysHandshakeAggressively();
		} else {
			opennetEnabled = false;
			opennetDefinitelyPortForwarded = false;
			opennetAssumeNAT = false;
		}
		boolean darknetDefinitelyPortForwarded = node.darknetDefinitelyPortForwarded();
		boolean darknetAssumeNAT = node.darknetCrypto.config.alwaysHandshakeAggressively();
		synchronized(ua) {
			ua.opennetDefinitelyPortForwarded = opennetDefinitelyPortForwarded;
			ua.darknetDefinitelyPortForwarded = darknetDefinitelyPortForwarded;
			ua.opennetAssumeNAT = opennetAssumeNAT;
			ua.darknetAssumeNAT = darknetAssumeNAT;
			ua.darknetConns = getPeerNodeStatusSize(PEER_NODE_STATUS_CONNECTED, true) +
				getPeerNodeStatusSize(PEER_NODE_STATUS_ROUTING_BACKED_OFF, true);
			ua.conns = getPeerNodeStatusSize(PEER_NODE_STATUS_CONNECTED, false) +
				getPeerNodeStatusSize(PEER_NODE_STATUS_ROUTING_BACKED_OFF, false);
			ua.darknetPeers = darknetPeers;
			ua.disconnDarknetPeers = darknetPeers - ua.darknetConns;
			ua.peers = peers;
			ua.neverConn = getPeerNodeStatusSize(PEER_NODE_STATUS_NEVER_CONNECTED, true);
			ua.clockProblem = getPeerNodeStatusSize(PEER_NODE_STATUS_CLOCK_PROBLEM, false);
			ua.connError = getPeerNodeStatusSize(PEER_NODE_STATUS_CONN_ERROR, true);
			ua.isOpennetEnabled = opennetEnabled;
			ua.tooNewPeersDarknet = getPeerNodeStatusSize(PEER_NODE_STATUS_TOO_NEW, true);
			ua.tooNewPeersTotal = getPeerNodeStatusSize(PEER_NODE_STATUS_TOO_NEW, false);
		}
		if(anyConnectedPeers())
			node.onConnectedPeer();
	}

	public boolean anyConnectedPeers() {
		PeerNode[] conns = connectedPeers();
		for(PeerNode conn: conns) {
			if(conn.isRoutable())
				return true;
		}
		return false;
	}
	
	public boolean anyDarknetPeers() {
		PeerNode[] conns = connectedPeers();
		for(PeerNode p : conns)
			if(p.isDarknet())
				return true;
		return false;
	}

	/**
	 * Ask each PeerNode to read in it's extra peer data
	 */
	public void readExtraPeerData() {
		DarknetPeerNode[] peers = getDarknetPeers();
		for(DarknetPeerNode peer: peers) {
			try {
				peer.readExtraPeerData();
			} catch(Exception e) {
				Logger.error(this, "Got exception while reading extra peer data", e);
			}
		}
		String msg = "Extra peer data reading and processing completed";
		Logger.normal(this, msg);
		System.out.println(msg);
	}

	public void start() {
		ua = new PeerManagerUserAlert(node.nodeStats, node.nodeUpdater);
		updatePMUserAlert();
		node.clientCore.alerts.register(ua);
		node.getTicker().queueTimedJob(writePeersRunnable, 0);
	}

	public int countNonBackedOffPeers(boolean realTime) {
		PeerNode[] peers = connectedPeers();
		// even if myPeers peers are connected they won't be routed to
		int countNoBackoff = 0;
		for(PeerNode peer: peers) {
			if(peer.isRoutable())
				if(!peer.isRoutingBackedOff(realTime))
					countNoBackoff++;
		}
		return countNoBackoff;
	}
	// Stats stuff
	/**
	 * Update oldestNeverConnectedPeerAge if the timer has expired
	 */
	public void maybeUpdateOldestNeverConnectedDarknetPeerAge(long now) {
		PeerNode[] peerList;
		synchronized(this) {
			if(now <= nextOldestNeverConnectedDarknetPeerAgeUpdateTime)
				return;
			nextOldestNeverConnectedDarknetPeerAgeUpdateTime = now + oldestNeverConnectedPeerAgeUpdateInterval;
			peerList = myPeers;
		}
		oldestNeverConnectedDarknetPeerAge = 0;
		for(PeerNode pn: peerList) {
			if(!pn.isDarknet()) continue;
			if(pn.getPeerNodeStatus() == PEER_NODE_STATUS_NEVER_CONNECTED)
				if((now - pn.getPeerAddedTime()) > oldestNeverConnectedDarknetPeerAge)
					oldestNeverConnectedDarknetPeerAge = now - pn.getPeerAddedTime();
		}
		if(oldestNeverConnectedDarknetPeerAge > 0 && logMINOR)
			Logger.minor(this, "Oldest never connected peer is " + oldestNeverConnectedDarknetPeerAge + "ms old");
		nextOldestNeverConnectedDarknetPeerAgeUpdateTime = now + oldestNeverConnectedPeerAgeUpdateInterval;
	}

	public long getOldestNeverConnectedDarknetPeerAge() {
		return oldestNeverConnectedDarknetPeerAge;
	}

	/**
	 * Log the current PeerNode status summary if the timer has expired
	 */
	public void maybeLogPeerNodeStatusSummary(long now) {
		if(now > nextPeerNodeStatusLogTime) {
			if((now - nextPeerNodeStatusLogTime) > SECONDS.toMillis(10) && nextPeerNodeStatusLogTime > 0)
				Logger.error(this, "maybeLogPeerNodeStatusSummary() not called for more than 10 seconds (" + (now - nextPeerNodeStatusLogTime) + ").  PacketSender getting bogged down or something?");

			int numberOfConnected = 0;
			int numberOfRoutingBackedOff = 0;
			int numberOfTooNew = 0;
			int numberOfTooOld = 0;
			int numberOfDisconnected = 0;
			int numberOfNeverConnected = 0;
			int numberOfDisabled = 0;
			int numberOfListenOnly = 0;
			int numberOfListening = 0;
			int numberOfBursting = 0;
			int numberOfClockProblem = 0;
			int numberOfConnError = 0;
			int numberOfDisconnecting = 0;
			int numberOfRoutingDisabled = 0;
			int numberOfNoLoadStats = 0;

			PeerNode[] peers = this.myPeers();
			
			for(PeerNode peer: peers) {
				if(peer == null) {
					Logger.error(this, "getPeerNodeStatuses(true) == null!");
					continue;
				}
				int status = peer.getPeerNodeStatus();
				switch(status) {
					case PEER_NODE_STATUS_CONNECTED:
						numberOfConnected++;
						break;
					case PEER_NODE_STATUS_ROUTING_BACKED_OFF:
						numberOfRoutingBackedOff++;
						break;
					case PEER_NODE_STATUS_TOO_NEW:
						numberOfTooNew++;
						break;
					case PEER_NODE_STATUS_TOO_OLD:
						numberOfTooOld++;
						break;
					case PEER_NODE_STATUS_DISCONNECTED:
						numberOfDisconnected++;
						break;
					case PEER_NODE_STATUS_NEVER_CONNECTED:
						numberOfNeverConnected++;
						break;
					case PEER_NODE_STATUS_DISABLED:
						numberOfDisabled++;
						break;
					case PEER_NODE_STATUS_LISTEN_ONLY:
						numberOfListenOnly++;
						break;
					case PEER_NODE_STATUS_LISTENING:
						numberOfListening++;
						break;
					case PEER_NODE_STATUS_BURSTING:
						numberOfBursting++;
						break;
					case PEER_NODE_STATUS_CLOCK_PROBLEM:
						numberOfClockProblem++;
						break;
					case PEER_NODE_STATUS_CONN_ERROR:
						numberOfConnError++;
						break;
					case PEER_NODE_STATUS_DISCONNECTING:
						numberOfDisconnecting++;
						break;
					case PEER_NODE_STATUS_ROUTING_DISABLED:
						numberOfRoutingDisabled++;
						break;
					case PEER_NODE_STATUS_NO_LOAD_STATS:
						numberOfNoLoadStats++;
						break;
					default:
						Logger.error(this, "Unknown peer status value : " + status);
						break;
				}
			}
			Logger.normal(this, "Connected: " + numberOfConnected + "  Routing Backed Off: " + numberOfRoutingBackedOff + "  Too New: " + numberOfTooNew + "  Too Old: " + numberOfTooOld + "  Disconnected: " + numberOfDisconnected + "  Never Connected: " + numberOfNeverConnected + "  Disabled: " + numberOfDisabled + "  Bursting: " + numberOfBursting + "  Listening: " + numberOfListening + "  Listen Only: " + numberOfListenOnly + "  Clock Problem: " + numberOfClockProblem + "  Connection Problem: " + numberOfConnError + "  Disconnecting: " + numberOfDisconnecting+" No load stats: "+numberOfNoLoadStats);
			nextPeerNodeStatusLogTime = now + peerNodeStatusLogInterval;
		}
	}
	
	public void changePeerNodeStatus(PeerNode peerNode, int oldPeerNodeStatus,
			int peerNodeStatus, boolean noLog) {
		Integer newStatus = Integer.valueOf(peerNodeStatus);
		Integer oldStatus = Integer.valueOf(oldPeerNodeStatus);
		this.allPeersStatuses.changePeerNodeStatus(peerNode, oldStatus, newStatus, noLog);
		if(!peerNode.isOpennet())
			this.darknetPeersStatuses.changePeerNodeStatus(peerNode, oldStatus, newStatus, noLog);
		node.executor.execute(new Runnable() {

			@Override
			public void run() {
				updatePMUserAlert();
			}
			
		});
	}

	/**
	 * Add a PeerNode status to the map. Used internally when a peer is added.
	 */
	private void addPeerNodeStatus(int pnStatus, PeerNode peerNode, boolean noLog) {
		Integer peerNodeStatus = Integer.valueOf(pnStatus);
		this.allPeersStatuses.addStatus(peerNodeStatus, peerNode, noLog);
		if(!peerNode.isOpennet())
			this.darknetPeersStatuses.addStatus(peerNodeStatus, peerNode, noLog);
	}

	/**
	 * How many PeerNodes have a particular status?
	 * @param darknet If true, only count darknet nodes, if false, count all nodes.
	 */
	public int getPeerNodeStatusSize(int pnStatus, boolean darknet) {
		if(darknet)
			return darknetPeersStatuses.statusSize(pnStatus);
		else
			return allPeersStatuses.statusSize(pnStatus);
	}

	/**
	 * Remove a PeerNode status from the map. Used internally when a peer is removed.
	 * @param isInPeers If true, complain if the node is not in the peers list; if false, complain if it is.
	 */
	private void removePeerNodeStatus(int pnStatus, PeerNode peerNode, boolean noLog) {
		Integer peerNodeStatus = Integer.valueOf(pnStatus);
		this.allPeersStatuses.removeStatus(peerNodeStatus, peerNode, noLog);
		if(!peerNode.isOpennet())
			this.darknetPeersStatuses.removeStatus(peerNodeStatus, peerNode, noLog);
	}

	/**
	 * Add a PeerNode routing backoff reason to the map
	 */
	public void addPeerNodeRoutingBackoffReason(String peerNodeRoutingBackoffReason, PeerNode peerNode, boolean realTime) {
		if(peerNodeRoutingBackoffReason == null) {
			Logger.error(this, "Impossible backoff reason null on "+peerNode+" realtime="+realTime, new Exception("error"));
			return;
		}
		PeerStatusTracker<String> peerNodeRoutingBackoffReasons =
			realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
		peerNodeRoutingBackoffReasons.addStatus(peerNodeRoutingBackoffReason, peerNode, false);
	}

	/**
	 * What are the currently tracked PeerNode routing backoff reasons?
	 */
	public String[] getPeerNodeRoutingBackoffReasons(boolean realTime) {
		ArrayList<String> list = new ArrayList<String>();
		PeerStatusTracker<String> peerNodeRoutingBackoffReasons =
			realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
		peerNodeRoutingBackoffReasons.addStatusList(list);
		return list.toArray(new String[list.size()]);
	}

	/**
	 * How many PeerNodes have a particular routing backoff reason?
	 */
	public int getPeerNodeRoutingBackoffReasonSize(String peerNodeRoutingBackoffReason, boolean realTime) {
		PeerStatusTracker<String> peerNodeRoutingBackoffReasons =
			realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
		return peerNodeRoutingBackoffReasons.statusSize(peerNodeRoutingBackoffReason);
	}

	/**
	 * Remove a PeerNode routing backoff reason from the map
	 */
	public void removePeerNodeRoutingBackoffReason(String peerNodeRoutingBackoffReason, PeerNode peerNode, boolean realTime) {
		PeerStatusTracker<String> peerNodeRoutingBackoffReasons =
			realTime ? peerNodeRoutingBackoffReasonsRT : peerNodeRoutingBackoffReasonsBulk;
		peerNodeRoutingBackoffReasons.removeStatus(peerNodeRoutingBackoffReason, peerNode, false);
	}

	public PeerNodeStatus[] getPeerNodeStatuses(boolean noHeavy) {
		PeerNode[] peers = myPeers();
		PeerNodeStatus[] _peerNodeStatuses = new PeerNodeStatus[peers.length];
		for(int peerIndex = 0, peerCount = peers.length; peerIndex < peerCount; peerIndex++) {
			_peerNodeStatuses[peerIndex] = peers[peerIndex].getStatus(noHeavy);
		}
		return _peerNodeStatuses;
	}

	public DarknetPeerNodeStatus[] getDarknetPeerNodeStatuses(boolean noHeavy) {
		DarknetPeerNode[] peers = getDarknetPeers();
		DarknetPeerNodeStatus[] _peerNodeStatuses = new DarknetPeerNodeStatus[peers.length];
		for(int peerIndex = 0, peerCount = peers.length; peerIndex < peerCount; peerIndex++) {
			_peerNodeStatuses[peerIndex] = (DarknetPeerNodeStatus) peers[peerIndex].getStatus(noHeavy);
		}
		return _peerNodeStatuses;
	}

	public OpennetPeerNodeStatus[] getOpennetPeerNodeStatuses(boolean noHeavy) {
		OpennetPeerNode[] peers = getOpennetPeers();
		OpennetPeerNodeStatus[] _peerNodeStatuses = new OpennetPeerNodeStatus[peers.length];
		for(int peerIndex = 0, peerCount = peers.length; peerIndex < peerCount; peerIndex++) {
			_peerNodeStatuses[peerIndex] = (OpennetPeerNodeStatus) peers[peerIndex].getStatus(noHeavy);
		}
		return _peerNodeStatuses;
	}

	/**
	 * Update hadRoutableConnectionCount/routableConnectionCheckCount on peers if the timer has expired
	 */
	public void maybeUpdatePeerNodeRoutableConnectionStats(long now) {
		PeerNode[] peerList;
		synchronized(this) {
			if(now <= nextRoutableConnectionStatsUpdateTime)
				return;
			nextRoutableConnectionStatsUpdateTime = now + routableConnectionStatsUpdateInterval;
			peerList = myPeers;
		}
		if(-1 != nextRoutableConnectionStatsUpdateTime) {
			for(PeerNode pn: peerList) {
				pn.checkRoutableConnectionStatus();
			}
		}
	}

	/**
	 * Get the darknet peers list.
	 * FIXME: optimise
	 */
	public DarknetPeerNode[] getDarknetPeers() {
		PeerNode[] peers = myPeers();
		// FIXME optimise! Maybe maintain as a separate list?
		ArrayList<PeerNode> v = new ArrayList<PeerNode>(peers.length);
		for(PeerNode peer: peers) {
			if(peer instanceof DarknetPeerNode)
				v.add(peer);
		}
		return v.toArray(new DarknetPeerNode[v.size()]);
	}

	/** Get the currently connected seednodes.
	 * @param exclude Set of peer public keys to exclude.
	 */
	public List<SeedServerPeerNode> getConnectedSeedServerPeersVector(HashSet<ByteArrayWrapper> exclude) {
		PeerNode[] peers = myPeers();
		// FIXME optimise! Maybe maintain as a separate list?
		ArrayList<SeedServerPeerNode> v = new ArrayList<SeedServerPeerNode>(peers.length);
		for(PeerNode p : peers) {
			if(p instanceof SeedServerPeerNode) {
				SeedServerPeerNode sspn = (SeedServerPeerNode) p;
				if(exclude != null && exclude.contains(new ByteArrayWrapper(sspn.getPubKeyHash()))) {
					if(logMINOR)
						Logger.minor(this, "Not including in getConnectedSeedServerPeersVector() as in exclude set: " + sspn.userToString());
					continue;
				}
				if(!sspn.isConnected()) {
					if(logMINOR)
						Logger.minor(this, "Not including in getConnectedSeedServerPeersVector() as disconnected: " + sspn.userToString());
					continue;
				}
				v.add(sspn);
			}
		}
		return v;
	}

	public List<SeedServerPeerNode> getSeedServerPeersVector() {
		PeerNode[] peers = myPeers();
		// FIXME optimise! Maybe maintain as a separate list?
		List<SeedServerPeerNode> v = new ArrayList<SeedServerPeerNode>(peers.length);
		for(PeerNode peer : peers) {
			if(peer instanceof SeedServerPeerNode)
				v.add((SeedServerPeerNode)peer);
		}
		return v;
	}

	/**
	 * Get the opennet peers list.
	 */
	public OpennetPeerNode[] getOpennetPeers() {
		PeerNode[] peers = myPeers();
		// FIXME optimise! Maybe maintain as a separate list?
		ArrayList<PeerNode> v = new ArrayList<PeerNode>(peers.length);
		for(PeerNode peer: peers) {
			if(peer instanceof OpennetPeerNode)
				v.add(peer);
		}
		return v.toArray(new OpennetPeerNode[v.size()]);
	}
	
	public PeerNode[] getOpennetAndSeedServerPeers() {
		PeerNode[] peers = myPeers();
		// FIXME optimise! Maybe maintain as a separate list?
		ArrayList<PeerNode> v = new ArrayList<PeerNode>(peers.length);
		for(PeerNode peer: peers) {
			if(peer instanceof OpennetPeerNode)
				v.add(peer);
			else if(peer instanceof SeedServerPeerNode)
				v.add(peer);
		}
		return v.toArray(new PeerNode[v.size()]);
	}

	public boolean anyConnectedPeerHasAddress(FreenetInetAddress addr, PeerNode pn) {
		PeerNode[] peers = myPeers();
		for(PeerNode p : peers) {
			if(p == pn)
				continue;
			if(!p.isConnected())
				continue;
			if(!p.isRealConnection())
				continue; // Ignore non-searchable peers i.e. bootstrapping peers
			// If getPeer() is null then presumably !isConnected().
			if(p.isDarknet() && !pn.isDarknet()) {
				// Darknet is only affected by other darknet peers.
				// Opennet peers with the same IP will NOT cause darknet peers to be dropped, even if one connection per IP is set for darknet, and even if it isn't set for opennet.
				// (Which would be a perverse configuration anyway!)
				// FIXME likewise, FOAFs should not boot darknet connections.
				continue;
			}
			if(p.getPeer().getFreenetAddress().equals(addr))
				return true;
		}
		return false;
	}

	public void removeOpennetPeers() {
		synchronized(this) {
			ArrayList<PeerNode> keep = new ArrayList<PeerNode>();
			ArrayList<PeerNode> conn = new ArrayList<PeerNode>();
			for(PeerNode pn : myPeers) {
				if(pn instanceof OpennetPeerNode)
					continue;
				keep.add(pn);
				if(pn.isConnected())
					conn.add(pn);
			}
			myPeers = keep.toArray(new PeerNode[keep.size()]);
			connectedPeers = keep.toArray(new PeerNode[conn.size()]);
		}
		updatePMUserAlert();
		notifyPeerStatusChangeListeners();
	}

	public PeerNode containsPeer(PeerNode pn) {
		PeerNode[] peers = pn.isOpennet() ? getOpennetAndSeedServerPeers() : getDarknetPeers();

		for(PeerNode peer: peers)
			if(Arrays.equals(pn.getPubKeyHash(), peer.getPubKeyHash()))
				return peer;

		return null;
	}

	public int countConnectedDarknetPeers() {
		int count = 0;
		PeerNode[] peers = myPeers();
		for(PeerNode peer: peers) {
			if(peer == null)
				continue;
			if(!(peer instanceof DarknetPeerNode))
				continue;
			if(peer.isOpennet())
				continue;
			if(!peer.isRoutable())
				continue;
			count++;
		}
		if(logMINOR) Logger.minor(this, "countConnectedDarknetPeers() returning "+count);
		return count;
	}

	public int countConnectedPeers() {
		int count = 0;
		PeerNode[] peers = myPeers();
		for(PeerNode peer: peers) {
			if(peer == null)
				continue;
			if(!peer.isRoutable())
				continue;
			count++;
		}
		return count;
	}

	public int countAlmostConnectedDarknetPeers() {
		int count = 0;
		PeerNode[] peers = myPeers();
		for(PeerNode peer: peers) {
			if(peer == null)
				continue;
			if(!(peer instanceof DarknetPeerNode))
				continue;
			if(peer.isOpennet())
				continue;
			if(!peer.isConnected())
				continue;
			count++;
		}
		return count;
	}

	public int countCompatibleDarknetPeers() {
		int count = 0;
		PeerNode[] peers = myPeers();
		for(PeerNode peer: peers) {
			if(peer == null)
				continue;
			if(!(peer instanceof DarknetPeerNode))
				continue;
			if(peer.isOpennet())
				continue;
			if(!peer.isConnected())
				continue;
			if(!peer.isRoutingCompatible())
				continue;
			count++;
		}
		return count;
	}

	public int countCompatibleRealPeers() {
		int count = 0;
		PeerNode[] peers = myPeers();
		for(PeerNode peer: peers) {
			if(peer == null)
				continue;
			if(!peer.isRealConnection())
				continue;
			if(!peer.isConnected())
				continue;
			if(!peer.isRoutingCompatible())
				continue;
			count++;
		}
		return count;
	}

	public int countConnectedOpennetPeers() {
		int count = 0;
		PeerNode[] peers = connectedPeers();
		for(PeerNode peer: peers) {
			if(peer == null)
				continue;
			if(!(peer instanceof OpennetPeerNode))
				continue;
			if(!peer.isRoutable())
				continue;
			count++;
		}
		return count;
	}

	/**
	 * How many peers do we have that actually may connect? Don't include seednodes, disabled nodes, etc.
	 */
	public int countValidPeers() {
		PeerNode[] peers = myPeers();
		int count = 0;
		for(PeerNode peer: peers) {
			if(!peer.isRealConnection())
				continue;
			if(peer.isDisabled())
				continue;
			count++;
		}
		return count;
	}
	
	/**
	 * How many peers do we have that actually may connect? Don't include seednodes, disabled nodes, etc.
	 */
	public int countConnectiblePeers() {
		PeerNode[] peers = myPeers();
		int count = 0;
		for(PeerNode peer: peers) {
			if(peer.isDisabled())
				continue;
			if(peer instanceof DarknetPeerNode) {
				if(((DarknetPeerNode)peer).isListenOnly())
					continue;
			}
			count++;
		}
		return count;
	}
	
	public int countSeednodes() {
		int count = 0;
		for(PeerNode peer : myPeers()) {
			if(peer instanceof SeedServerPeerNode || 
					peer instanceof SeedClientPeerNode)
				count++;
		}
		return count;
	}
	
	public int countBackedOffPeers(boolean realTime) {
		PeerNode[] peers = myPeers();
		int count = 0;
		for(PeerNode peer : peers) {
			if(!peer.isRealConnection())
				continue;
			if(peer.isDisabled())
				continue;
			if(peer.isRoutingBackedOff(realTime))
				count++;
		}
		return count;
	}

	public PeerNode getByPubKeyHash(byte[] pkHash) {
		PeerNode[] peers = myPeers();
		for(PeerNode peer : peers) {
			if(Arrays.equals(peer.peerECDSAPubKeyHash, pkHash))
				return peer;
		}
		return null;
	}
	
	void incrementSelectionSamples(PeerNode pn) {
		// TODO: reimplement with a bit field to spare memory
		pn.incrementNumberOfSelections();
	}
	
	/** Notifies the listeners about status change*/
	private void notifyPeerStatusChangeListeners(){
		for(PeerStatusChangeListener l:listeners){
			l.onPeerStatusChange();
			for(PeerNode pn:myPeers()){
				pn.registerPeerNodeStatusChangeListener(l);
			}
		}
	}
	
	/** Registers a listener to be notified when peers' statuses changes
	 * @param listener - the listener to be registered*/
	public void addPeerStatusChangeListener(PeerStatusChangeListener listener){
		listeners.add(listener);
		for(PeerNode pn:myPeers()){
			pn.registerPeerNodeStatusChangeListener(listener);
		}
	}
	
	/** Removes a listener
	 * @param listener - The listener to be removed*/
	public void removePeerStatusChangeListener(PeerStatusChangeListener listener){
		listeners.remove(listener);
	}
	
	/** A listener interface that can be used to be notified about peer status change events*/
	public static interface PeerStatusChangeListener{
		/** Peers status have changed*/
		public void onPeerStatusChange();
	}
	
	/** Get a non-copied snapshot of the peers list. NOTE: LOW LEVEL:
	 * Should be up to date (but not guaranteed when exit lock), DO NOT
	 * MODIFY THE RETURNED DATA! Package-local - stuff outside node/ 
	 * should use the copying getters (which are a little more expensive). */
	synchronized PeerNode[] myPeers() {
		return myPeers;
	}
	
	/** Get the last snapshot of the connected peers list. NOTE: This is
	 * not as reliable as using the copying getters (or even using myPeers()
	 * and then checking each peer). But it is fast.
	 * 
	 * FIXME: Check all callers. Should they use myPeers and check for 
	 * connectedness, and/or should they use a copying method? I'm not sure
	 * how reliable updating of connectedPeers is ...
	 */
	synchronized PeerNode[] connectedPeers() {
		return connectedPeers;
	}

	/** Count the number of PeerNode's with a given status (right now, not 
	 * based on a snapshot). Note you should not call this if holding lots 
	 * of locks! */
	public int countByStatus(int status) {
		int count = 0;
		PeerNode[] peers = myPeers();
		for(PeerNode peer : peers) {
			if(peer.getPeerNodeStatus() == status)
				count++;
		}
		return count;
	}

	// We can't trust our strangers, so need a consensus.
	public static final int OUTDATED_MIN_TOO_NEW_TOTAL = 5;
	// We can trust our friends, so only 1 is needed.
	public static final int OUTDATED_MIN_TOO_NEW_DARKNET = 1;
	public static final int OUTDATED_MAX_CONNS = 5;
	
	public boolean isOutdated() {
		
		int tooNewDarknet = getPeerNodeStatusSize(PEER_NODE_STATUS_TOO_NEW, true);
		
		if(tooNewDarknet >= OUTDATED_MIN_TOO_NEW_DARKNET)
			return true;
		
		int tooNewOpennet = getPeerNodeStatusSize(PEER_NODE_STATUS_TOO_NEW, false);
		
		// FIXME arbitrary constants.
		// We cannot count on the version announcements.
		// Until we actually get a validated update jar it's all potentially bogus.
		
		int connections = getPeerNodeStatusSize(PEER_NODE_STATUS_CONNECTED, false) +
			getPeerNodeStatusSize(PEER_NODE_STATUS_ROUTING_BACKED_OFF, false);
		
		if(tooNewOpennet >= OUTDATED_MIN_TOO_NEW_TOTAL) {
			return connections < OUTDATED_MAX_CONNS;
		} else return false;
	}
	
}
