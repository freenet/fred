package freenet.node;

import static java.util.concurrent.TimeUnit.DAYS;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

import freenet.client.DefaultMIMETypes;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.FreenetInetAddress;
import freenet.io.comm.Message;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.Peer;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.io.comm.RetrievalException;
import freenet.io.xfer.BulkReceiver;
import freenet.io.xfer.BulkTransmitter;
import freenet.io.xfer.PartiallyReceivedBulk;
import freenet.keys.FreenetURI;
import freenet.l10n.NodeL10n;
import freenet.node.useralerts.AbstractUserAlert;
import freenet.node.useralerts.BookmarkFeedUserAlert;
import freenet.node.useralerts.DownloadFeedUserAlert;
import freenet.node.useralerts.N2NTMUserAlert;
import freenet.node.useralerts.UserAlert;
import freenet.support.Base64;
import freenet.support.HTMLNode;
import freenet.support.IllegalBase64Exception;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.SimpleFieldSet;
import freenet.support.SizeUtil;
import freenet.support.api.HTTPUploadedFile;
import freenet.support.api.RandomAccessBuffer;
import freenet.support.io.BucketTools;
import freenet.support.io.ByteArrayRandomAccessBuffer;
import freenet.support.io.FileUtil;
import freenet.support.io.FileRandomAccessBuffer;

public class DarknetPeerNode extends PeerNode {

	/** Name of this node */
	String myName;

	/** True if this peer is not to be connected with */
	private boolean isDisabled;

	/** True if we don't send handshake requests to this peer, but will connect if we receive one */
	private boolean isListenOnly;

	/** True if we send handshake requests to this peer in infrequent bursts */
	private boolean isBurstOnly;

	/** True if we want to ignore the source port of the node's sent packets.
	 * This is normally set when dealing with an Evil Corporate Firewall which rewrites the port on outgoing
	 * packets but does not redirect incoming packets destined to the rewritten port.
	 * What it does is this: If we have an address with the same IP but a different port, to the detectedPeer,
	 * we use that instead. */
	private boolean ignoreSourcePort;

	/** True if we want to allow LAN/localhost addresses. */
	private boolean allowLocalAddresses;

	/** Extra peer data file numbers */
	private LinkedHashSet<Integer> extraPeerDataFileNumbers;

	/** Private comment on the peer for /friends/ page */
	private String privateDarknetComment;

	/** Private comment on the peer for /friends/ page's extra peer data file number */
	private int privateDarknetCommentFileNumber;

	/** Queued-to-send N2NM extra peer data file numbers */
	private LinkedHashSet<Integer> queuedToSendN2NMExtraPeerDataFileNumbers;

	private FRIEND_TRUST trustLevel;

	private FRIEND_VISIBILITY ourVisibility;
	private FRIEND_VISIBILITY theirVisibility;

	private static boolean logMINOR;

	public enum FRIEND_TRUST {
		LOW,
		NORMAL,
		HIGH;

		private static final FRIEND_TRUST[] valuesBackwards;
		static {
			final FRIEND_TRUST[] values = values();
			valuesBackwards = new FRIEND_TRUST[values.length];
			for(int i=0;i<values.length;i++)
				valuesBackwards[i] = values[values.length-i-1];
		}

		public static FRIEND_TRUST[] valuesBackwards() {
			return valuesBackwards.clone();
		}

		public boolean isDefaultValue() {
			return equals(FRIEND_TRUST.NORMAL);
		}

	}

	public enum FRIEND_VISIBILITY {
		YES((short)0), // Visible
		NAME_ONLY((short)1), // Only the name is visible, but other friends can ask for a connection
		NO((short)2); // Not visible to our other friends at all

		/** The codes are persistent and used to communicate between nodes, so they must not change.
		 * Which is why we are not using ordinal(). */
		final short code;

		FRIEND_VISIBILITY(short code) {
			this.code = code;
		}

		public boolean isStricterThan(FRIEND_VISIBILITY theirVisibility) {
			if(theirVisibility == null) return true;
			// Higher number = more strict.
			return theirVisibility.code < code;
		}

		public static FRIEND_VISIBILITY getByCode(short code) {
			for(FRIEND_VISIBILITY f : values()) {
				if(f.code == code) return f;
			}
			return null;
		}

		public boolean isDefaultValue() {
			return equals(FRIEND_VISIBILITY.YES);
		}
	}

	/**
	 * Create a darknet PeerNode from a SimpleFieldSet
	 * @param fs The SimpleFieldSet to parse
	 * @param node2 The running Node we are part of.
	 * @param trust If this is a new node, we will use this parameter to set the initial trust level.
	 */
	public DarknetPeerNode(SimpleFieldSet fs, Node node2, NodeCrypto crypto, PeerManager peers, boolean fromLocal, OutgoingPacketMangler mangler, FRIEND_TRUST trust, FRIEND_VISIBILITY visibility2) throws FSParseException, PeerParseException, ReferenceSignatureVerificationException {
		super(fs, node2, crypto, peers, fromLocal, false, mangler, false);

		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);

		String name = fs.get("myName");
		if(name == null) throw new FSParseException("No name");
		myName = name;

		if(fromLocal) {
			SimpleFieldSet metadata = fs.subset("metadata");

			isDisabled = metadata.getBoolean("isDisabled", false);
			isListenOnly = metadata.getBoolean("isListenOnly", false);
			isBurstOnly = metadata.getBoolean("isBurstOnly", false);
			disableRouting = disableRoutingHasBeenSetLocally = metadata.getBoolean("disableRoutingHasBeenSetLocally", false);
			ignoreSourcePort = metadata.getBoolean("ignoreSourcePort", false);
			allowLocalAddresses = metadata.getBoolean("allowLocalAddresses", false);
			String s = metadata.get("trustLevel");
			if(s != null) {
				trustLevel = FRIEND_TRUST.valueOf(s);
			} else {
				trustLevel = node.securityLevels.getDefaultFriendTrust();
				System.err.println("Assuming friend ("+name+") trust is opposite of friend seclevel: "+trustLevel);
			}
			s = metadata.get("ourVisibility");
			if(s != null) {
				ourVisibility = FRIEND_VISIBILITY.valueOf(s);
			} else {
				System.err.println("Assuming friend ("+name+") wants to be invisible");
				node.createVisibilityAlert();
				ourVisibility = FRIEND_VISIBILITY.NO;
			}
			s = metadata.get("theirVisibility");
			if(s != null) {
				theirVisibility = FRIEND_VISIBILITY.valueOf(s);
			} else {
				theirVisibility = FRIEND_VISIBILITY.NO;
			}
		} else {
			if(trust == null) throw new IllegalArgumentException();
			trustLevel = trust;
			ourVisibility = visibility2;
		}

		// Setup the private darknet comment note
		privateDarknetComment = "";
		privateDarknetCommentFileNumber = -1;

		// Setup the extraPeerDataFileNumbers
		extraPeerDataFileNumbers = new LinkedHashSet<Integer>();

		// Setup the queuedToSendN2NMExtraPeerDataFileNumbers
		queuedToSendN2NMExtraPeerDataFileNumbers = new LinkedHashSet<Integer>();

	}

	/**
	 *
	 * Normally this is the address that packets have been received from from this node.
	 * However, if ignoreSourcePort is set, we will search for a similar address with a different port
	 * number in the node reference.
	 */
	@Override
	public synchronized Peer getPeer(){
		Peer detectedPeer = super.getPeer();
		if(ignoreSourcePort) {
			FreenetInetAddress addr = detectedPeer == null ? null : detectedPeer.getFreenetAddress();
			int port = detectedPeer == null ? -1 : detectedPeer.getPort();
			if(nominalPeer == null) return detectedPeer;
			for(Peer p : nominalPeer) {
				if(p.getPort() != port && p.getFreenetAddress().equals(addr)) {
					return p;
				}
			}
		}
		return detectedPeer;
	}

	/**
	 * @return True, if we are disconnected and it has been a
	 * sufficient time period since we last sent a handshake
	 * attempt.
	 */
	@Override
	public boolean shouldSendHandshake() {
		synchronized(this) {
			if(isDisabled) return false;
			if(isListenOnly) return false;
			if(!super.shouldSendHandshake()) return false;
		}
		return true;
	}

	@Override
	protected synchronized boolean innerProcessNewNoderef(SimpleFieldSet fs, boolean forARK, boolean forDiffNodeRef, boolean forFullNodeRef) throws FSParseException {
		boolean changedAnything = super.innerProcessNewNoderef(fs, forARK, forDiffNodeRef, forFullNodeRef);
		String name = fs.get("myName");
		if(name == null && forFullNodeRef) throw new FSParseException("No name in full noderef");
		if(name != null && !name.equals(myName)) {
			changedAnything = true;
			myName = name;
		}
		return changedAnything;
	}

	@Override
	public synchronized SimpleFieldSet exportFieldSet() {
		SimpleFieldSet fs = super.exportFieldSet();
		fs.putSingle("myName", getName());
		return fs;
	}

	@Override
	public synchronized SimpleFieldSet exportMetadataFieldSet(long now) {
		SimpleFieldSet fs = super.exportMetadataFieldSet(now);
		if(isDisabled)
			fs.putSingle("isDisabled", "true");
		if(isListenOnly)
			fs.putSingle("isListenOnly", "true");
		if(isBurstOnly)
			fs.putSingle("isBurstOnly", "true");
		if(ignoreSourcePort)
			fs.putSingle("ignoreSourcePort", "true");
		if(allowLocalAddresses)
			fs.putSingle("allowLocalAddresses", "true");
		if(disableRoutingHasBeenSetLocally)
			fs.putSingle("disableRoutingHasBeenSetLocally", "true");
		fs.putSingle("trustLevel", trustLevel.name());
		fs.putSingle("ourVisibility", ourVisibility.name());
		if(theirVisibility != null)
			fs.putSingle("theirVisibility", theirVisibility.name());

		return fs;
	}

	public synchronized String getName() {
		return myName;
	}

	@Override
	protected synchronized int calculatePeerNodeStatus(long now, long backedOffUntilRT, long backedOffUntilBulk, boolean overPingThreshold, boolean noLoadStats) {
		if(isDisabled) {
			return PeerManager.PEER_NODE_STATUS_DISABLED;
		}
		int status = super.calculatePeerNodeStatus(now, backedOffUntilRT, backedOffUntilBulk, overPingThreshold, noLoadStats);
		if(status == PeerManager.PEER_NODE_STATUS_CONNECTED ||
				status == PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM ||
				status == PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF ||
				status == PeerManager.PEER_NODE_STATUS_CONN_ERROR ||
				status == PeerManager.PEER_NODE_STATUS_TOO_NEW ||
				status == PeerManager.PEER_NODE_STATUS_TOO_OLD ||
				status == PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED ||
				status == PeerManager.PEER_NODE_STATUS_DISCONNECTING ||
				status == PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS)
			return status;
		if(isListenOnly)
			return PeerManager.PEER_NODE_STATUS_LISTEN_ONLY;
		if(isBurstOnly)
			return PeerManager.PEER_NODE_STATUS_LISTENING;
		return status;
	}

	public void enablePeer() {
		synchronized(this) {
			isDisabled = false;
		}
		setPeerNodeStatus(System.currentTimeMillis());
		node.peers.writePeersDarknetUrgent();
	}

	public void disablePeer() {
		synchronized(this) {
			isDisabled = true;
		}
		if(isConnected()) {
			forceDisconnect();
		}
		stopARKFetcher();
		setPeerNodeStatus(System.currentTimeMillis());
		node.peers.writePeersDarknetUrgent();
	}

	@Override
	public synchronized boolean isDisabled() {
		return isDisabled;
	}

	public void setListenOnly(boolean setting) {
		synchronized(this) {
			isListenOnly = setting;
		}
		if(setting && isBurstOnly()) {
			setBurstOnly(false);
		}
		if(setting) {
			stopARKFetcher();
		}
		setPeerNodeStatus(System.currentTimeMillis());
		node.peers.writePeersDarknetUrgent();
	}

	public synchronized boolean isListenOnly() {
		return isListenOnly;
	}

	public void setBurstOnly(boolean setting) {
		synchronized(this) {
			isBurstOnly = setting;
		}
		if(setting && isListenOnly()) {
			setListenOnly(false);
		}
		long now = System.currentTimeMillis();
		if(!setting) {
			synchronized(this) {
				sendHandshakeTime = now;  // don't keep any long handshake delays we might have had under BurstOnly
			}
		}
		setPeerNodeStatus(now);
		node.peers.writePeersDarknetUrgent();
	}

	public void setIgnoreSourcePort(boolean setting) {
		synchronized(this) {
			ignoreSourcePort = setting;
		}
	}

	/**
	 * Change the routing status of a peer
	 *
	 * @param shouldRoute
	 * @param localRequest (true everywhere but in NodeDispatcher)
	 */
	public void setRoutingStatus(boolean shouldRoute, boolean localRequest) {
		synchronized(this) {
			if(localRequest)
				disableRoutingHasBeenSetLocally = !shouldRoute;
			else
				disableRoutingHasBeenSetRemotely = !shouldRoute;

			disableRouting = disableRoutingHasBeenSetLocally || disableRoutingHasBeenSetRemotely;
		}

		if(localRequest) {
			Message msg = DMT.createRoutingStatus(shouldRoute);
			try {
				sendAsync(msg, null, node.nodeStats.setRoutingStatusCtr);
			} catch(NotConnectedException e) {
			// ok
			}
		}
		setPeerNodeStatus(System.currentTimeMillis());
		node.peers.writePeersDarknetUrgent();

	}

	@Override
	public boolean isIgnoreSource() {
		return ignoreSourcePort;
	}

	@Override
	public boolean isBurstOnly() {
		synchronized(this) {
			if(isBurstOnly) return true;
		}
		return super.isBurstOnly();
	}

	@Override
	public boolean allowLocalAddresses() {
		synchronized(this) {
			if(allowLocalAddresses) return true;
		}
		return super.allowLocalAddresses();
	}

	public void setAllowLocalAddresses(boolean setting) {
		synchronized(this) {
			allowLocalAddresses = setting;
		}
		node.peers.writePeersDarknetUrgent();
	}

	public boolean readExtraPeerData() {
		String extraPeerDataDirPath = node.getExtraPeerDataDir();
		File extraPeerDataPeerDir = new File(extraPeerDataDirPath+File.separator+getIdentityString());
	 	if(!extraPeerDataPeerDir.exists()) {
	 		return false;
	 	}
	 	if(!extraPeerDataPeerDir.isDirectory()) {
	   		Logger.error(this, "Extra peer data directory for peer not a directory: "+extraPeerDataPeerDir.getPath());
	 		return false;
	 	}
	 	File[] extraPeerDataFiles = extraPeerDataPeerDir.listFiles();
	 	if(extraPeerDataFiles == null) {
	 		return false;
	 	}
		boolean gotError = false;
		boolean readResult = false;
		for (File extraPeerDataFile : extraPeerDataFiles) {
			Integer fileNumber;
			try {
				fileNumber = Integer.valueOf(extraPeerDataFile.getName());
			} catch (NumberFormatException e) {
				gotError = true;
				continue;
			}
			synchronized(extraPeerDataFileNumbers) {
				extraPeerDataFileNumbers.add(fileNumber);
			}
			readResult = readExtraPeerDataFile(extraPeerDataFile, fileNumber.intValue());
			if(!readResult) {
				gotError = true;
			}
		}
		return !gotError;
	}

	public boolean rereadExtraPeerDataFile(int fileNumber) {
		if(logMINOR)
			Logger.minor(this, "Rereading peer data file "+fileNumber+" for "+shortToString());
		String extraPeerDataDirPath = node.getExtraPeerDataDir();
		File extraPeerDataPeerDir = new File(extraPeerDataDirPath+File.separator+getIdentityString());
		if(!extraPeerDataPeerDir.exists()) {
			Logger.error(this, "Extra peer data directory for peer does not exist: "+extraPeerDataPeerDir.getPath());
			return false;
		}
		if(!extraPeerDataPeerDir.isDirectory()) {
			Logger.error(this, "Extra peer data directory for peer not a directory: "+extraPeerDataPeerDir.getPath());
			return false;
		}
		File extraPeerDataFile = new File(extraPeerDataDirPath+File.separator+getIdentityString()+File.separator+fileNumber);
		if(!extraPeerDataFile.exists()) {
			Logger.error(this, "Extra peer data file for peer does not exist: "+extraPeerDataFile.getPath());
			return false;
		}
		return readExtraPeerDataFile(extraPeerDataFile, fileNumber);
	}

	public boolean readExtraPeerDataFile(File extraPeerDataFile, int fileNumber) {
		if(logMINOR) Logger.minor(this, "Reading "+extraPeerDataFile+" : "+fileNumber+" for "+shortToString());
		boolean gotError = false;
	 	if(!extraPeerDataFile.exists()) {
	 		if(logMINOR)
	 			Logger.minor(this, "Does not exist");
	 		return false;
	 	}
		Logger.normal(this, "extraPeerDataFile: "+extraPeerDataFile.getPath());
		FileInputStream fis;
		try {
			fis = new FileInputStream(extraPeerDataFile);
		} catch (FileNotFoundException e1) {
			Logger.normal(this, "Extra peer data file not found: "+extraPeerDataFile.getPath());
			return false;
		}
		InputStreamReader isr;
		try {
			isr = new InputStreamReader(fis, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		}
		BufferedReader br = new BufferedReader(isr);
		SimpleFieldSet fs = null;
		try {
			// Read in the single SimpleFieldSet
			fs = new SimpleFieldSet(br, false, true);
		} catch (EOFException e3) {
			// End of file, fine
		} catch (IOException e4) {
			Logger.error(this, "Could not read extra peer data file: "+e4, e4);
		} finally {
			try {
				br.close();
			} catch (IOException e5) {
				Logger.error(this, "Ignoring "+e5+" caught reading "+extraPeerDataFile.getPath(), e5);
			}
		}
		if(fs == null) {
			Logger.normal(this, "Deleting corrupt (too short?) file: "+extraPeerDataFile);
			deleteExtraPeerDataFile(fileNumber);
			return true;
		}
		boolean parseResult = false;
		try {
			parseResult = parseExtraPeerData(fs, extraPeerDataFile, fileNumber);
			if(!parseResult) {
				gotError = true;
			}
		} catch (FSParseException e2) {
			Logger.error(this, "Could not parse extra peer data: "+e2+ '\n' +fs.toString(),e2);
			gotError = true;
		}
		return !gotError;
	}

	private boolean parseExtraPeerData(SimpleFieldSet fs, File extraPeerDataFile, int fileNumber) throws FSParseException {
		String extraPeerDataTypeString = fs.get("extraPeerDataType");
		int extraPeerDataType = -1;
		try {
			extraPeerDataType = Integer.parseInt(extraPeerDataTypeString);
		} catch (NumberFormatException e) {
			Logger.error(this, "NumberFormatException parsing extraPeerDataType ("+extraPeerDataTypeString+") in file "+extraPeerDataFile.getPath());
			return false;
		}
		if(extraPeerDataType == Node.EXTRA_PEER_DATA_TYPE_N2NTM) {
			node.handleNodeToNodeTextMessageSimpleFieldSet(fs, this, fileNumber);
			return true;
		} else if(extraPeerDataType == Node.EXTRA_PEER_DATA_TYPE_PEER_NOTE) {
			String peerNoteTypeString = fs.get("peerNoteType");
			int peerNoteType = -1;
			try {
				peerNoteType = Integer.parseInt(peerNoteTypeString);
			} catch (NumberFormatException e) {
				Logger.error(this, "NumberFormatException parsing peerNoteType ("+peerNoteTypeString+") in file "+extraPeerDataFile.getPath());
				return false;
			}
			if(peerNoteType == Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT) {
				synchronized(this) {
				  	try {
						privateDarknetComment = Base64.decodeUTF8(fs.get("privateDarknetComment"));
					} catch (IllegalBase64Exception e) {
						Logger.error(this, "Bad Base64 encoding when decoding a private darknet comment SimpleFieldSet", e);
						return false;
					}
					privateDarknetCommentFileNumber = fileNumber;
				}
				return true;
			}
			Logger.error(this, "Read unknown peer note type '"+peerNoteType+"' from file "+extraPeerDataFile.getPath());
			return false;
		} else if(extraPeerDataType == Node.EXTRA_PEER_DATA_TYPE_QUEUED_TO_SEND_N2NM) {
			boolean sendSuccess = false;
			int type = fs.getInt("n2nType");
			if(isConnected()) {
				Message n2nm;
				if(fs.get("extraPeerDataType") != null) {
					fs.removeValue("extraPeerDataType");
				}
				if(fs.get("senderFileNumber") != null) {
					fs.removeValue("senderFileNumber");
				}
				fs.putOverwrite("senderFileNumber", String.valueOf(fileNumber));
				if(fs.get("sentTime") != null) {
					fs.removeValue("sentTime");
				}
				fs.putOverwrite("sentTime", Long.toString(System.currentTimeMillis()));

				try {
					n2nm = DMT.createNodeToNodeMessage(type, fs.toString().getBytes("UTF-8"));
				} catch (UnsupportedEncodingException e) {
					Logger.error(this, "UnsupportedEncodingException processing extraPeerDataType ("+extraPeerDataTypeString+") in file "+extraPeerDataFile.getPath(), e);
					throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
				}

				try {
					synchronized(queuedToSendN2NMExtraPeerDataFileNumbers) {
						node.usm.send(this, n2nm, null);
						Logger.normal(this, "Sent queued ("+fileNumber+") N2NM to '"+getName()+"': "+n2nm);
						sendSuccess = true;
						queuedToSendN2NMExtraPeerDataFileNumbers.remove(fileNumber);
					}
					deleteExtraPeerDataFile(fileNumber);
				} catch (NotConnectedException e) {
					sendSuccess = false;  // redundant, but clear
				}
			}
			if(!sendSuccess) {
				synchronized(queuedToSendN2NMExtraPeerDataFileNumbers) {
					fs.putOverwrite("extraPeerDataType", Integer.toString(extraPeerDataType));
					fs.removeValue("sentTime");
					queuedToSendN2NMExtraPeerDataFileNumbers.add(Integer.valueOf(fileNumber));
				}
			}
			return true;
		}
		else if(extraPeerDataType == Node.EXTRA_PEER_DATA_TYPE_BOOKMARK) {
			Logger.normal(this, "Read friend bookmark" + fs.toString());
			handleFproxyBookmarkFeed(fs, fileNumber);
			return true;
		}
		else if(extraPeerDataType == Node.EXTRA_PEER_DATA_TYPE_DOWNLOAD) {
			Logger.normal(this, "Read friend download" + fs.toString());
			handleFproxyDownloadFeed(fs, fileNumber);
			return true;
		}
		Logger.error(this, "Read unknown extra peer data type '"+extraPeerDataType+"' from file "+extraPeerDataFile.getPath());
		return false;
	}

	public int writeNewExtraPeerDataFile(SimpleFieldSet fs, int extraPeerDataType) {
		String extraPeerDataDirPath = node.getExtraPeerDataDir();
		if(extraPeerDataType > 0)
			fs.putOverwrite("extraPeerDataType", Integer.toString(extraPeerDataType));
		File extraPeerDataPeerDir = new File(extraPeerDataDirPath+File.separator+getIdentityString());
	 	if(!extraPeerDataPeerDir.exists()) {
	 		if(!extraPeerDataPeerDir.mkdir()) {
		   		Logger.error(this, "Extra peer data directory for peer could not be created: "+extraPeerDataPeerDir.getPath());
		 		return -1;
		 	}
	 	}
	 	if(!extraPeerDataPeerDir.isDirectory()) {
	   		Logger.error(this, "Extra peer data directory for peer not a directory: "+extraPeerDataPeerDir.getPath());
	 		return -1;
	 	}
		Integer[] localFileNumbers;
		int nextFileNumber = 0;
		synchronized(extraPeerDataFileNumbers) {
			// Find the first free slot
			localFileNumbers = extraPeerDataFileNumbers.toArray(new Integer[extraPeerDataFileNumbers.size()]);
			Arrays.sort(localFileNumbers);
			for (int localFileNumber : localFileNumbers) {
				if(localFileNumber > nextFileNumber) {
					break;
				}
				nextFileNumber = localFileNumber + 1;
			}
			extraPeerDataFileNumbers.add(nextFileNumber);
		}
		FileOutputStream fos;
		File extraPeerDataFile = new File(extraPeerDataPeerDir.getPath()+File.separator+nextFileNumber);
	 	if(extraPeerDataFile.exists()) {
   			Logger.error(this, "Extra peer data file already exists: "+extraPeerDataFile.getPath());
		 	return -1;
	 	}
		String f = extraPeerDataFile.getPath();
		try {
			fos = new FileOutputStream(f);
		} catch (FileNotFoundException e2) {
			Logger.error(this, "Cannot write extra peer data file to disk: Cannot create "
					+ f + " - " + e2, e2);
			return -1;
		}
		OutputStreamWriter w;
		try {
			w = new OutputStreamWriter(fos, "UTF-8");
		} catch (UnsupportedEncodingException e2) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e2, e2);
		}
		BufferedWriter bw = new BufferedWriter(w);
		try {
			fs.writeTo(bw);
			bw.close();
		} catch (IOException e) {
			try {
				fos.close();
			} catch (IOException e1) {
				Logger.error(this, "Cannot close extra peer data file: "+e, e);
			}
			Logger.error(this, "Cannot write file: " + e, e);
			return -1;
		}
		return nextFileNumber;
	}

	public void deleteExtraPeerDataFile(int fileNumber) {
		String extraPeerDataDirPath = node.getExtraPeerDataDir();
		File extraPeerDataPeerDir = new File(extraPeerDataDirPath, getIdentityString());
	 	if(!extraPeerDataPeerDir.exists()) {
	   		Logger.error(this, "Extra peer data directory for peer does not exist: "+extraPeerDataPeerDir.getPath());
	 		return;
	 	}
	 	if(!extraPeerDataPeerDir.isDirectory()) {
	   		Logger.error(this, "Extra peer data directory for peer not a directory: "+extraPeerDataPeerDir.getPath());
	 		return;
	 	}
		File extraPeerDataFile = new File(extraPeerDataPeerDir, Integer.toString(fileNumber));
	 	if(!extraPeerDataFile.exists()) {
	   		Logger.error(this, "Extra peer data file for peer does not exist: "+extraPeerDataFile.getPath());
	 		return;
	 	}
		synchronized(extraPeerDataFileNumbers) {
			extraPeerDataFileNumbers.remove(fileNumber);
		}
		if(!extraPeerDataFile.delete()) {
			if(extraPeerDataFile.exists()) {
				Logger.error(this, "Cannot delete file "+extraPeerDataFile+" after sending message to "+getPeer()+" - it may be resent on resting the node");
			} else {
				Logger.normal(this, "File does not exist when deleting: "+extraPeerDataFile+" after sending message to "+getPeer());
			}
		}
	}

	public void removeExtraPeerDataDir() {
		String extraPeerDataDirPath = node.getExtraPeerDataDir();
		File extraPeerDataPeerDir = new File(extraPeerDataDirPath+File.separator+getIdentityString());
	 	if(!extraPeerDataPeerDir.exists()) {
			Logger.error(this, "Extra peer data directory for peer does not exist: "+extraPeerDataPeerDir.getPath());
			return;
	 	}
	 	if(!extraPeerDataPeerDir.isDirectory()) {
	   		Logger.error(this, "Extra peer data directory for peer not a directory: "+extraPeerDataPeerDir.getPath());
	 		return;
	 	}
		Integer[] localFileNumbers;
		synchronized(extraPeerDataFileNumbers) {
			localFileNumbers = extraPeerDataFileNumbers.toArray(new Integer[extraPeerDataFileNumbers.size()]);
		}
		for (Integer localFileNumber : localFileNumbers) {
			deleteExtraPeerDataFile(localFileNumber.intValue());
		}
		extraPeerDataPeerDir.delete();
	}

	public boolean rewriteExtraPeerDataFile(SimpleFieldSet fs, int extraPeerDataType, int fileNumber) {
		String extraPeerDataDirPath = node.getExtraPeerDataDir();
		if(extraPeerDataType > 0)
			fs.putOverwrite("extraPeerDataType", Integer.toString(extraPeerDataType));
		File extraPeerDataPeerDir = new File(extraPeerDataDirPath+File.separator+getIdentityString());
	 	if(!extraPeerDataPeerDir.exists()) {
	   		Logger.error(this, "Extra peer data directory for peer does not exist: "+extraPeerDataPeerDir.getPath());
	 		return false;
	 	}
	 	if(!extraPeerDataPeerDir.isDirectory()) {
	   		Logger.error(this, "Extra peer data directory for peer not a directory: "+extraPeerDataPeerDir.getPath());
	 		return false;
	 	}
		File extraPeerDataFile = new File(extraPeerDataDirPath+File.separator+getIdentityString()+File.separator+fileNumber);
	 	if(!extraPeerDataFile.exists()) {
	   		Logger.error(this, "Extra peer data file for peer does not exist: "+extraPeerDataFile.getPath());
	 		return false;
	 	}
		String f = extraPeerDataFile.getPath();
		FileOutputStream fos;
		try {
			fos = new FileOutputStream(f);
		} catch (FileNotFoundException e2) {
			Logger.error(this, "Cannot write extra peer data file to disk: Cannot open "
					+ f + " - " + e2, e2);
			return false;
		}
		OutputStreamWriter w;
		try {
			w = new OutputStreamWriter(fos, "UTF-8");
		} catch (UnsupportedEncodingException e2) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e2, e2);
		}
		BufferedWriter bw = new BufferedWriter(w);
		try {
			fs.writeTo(bw);
			bw.close();
		} catch (IOException e) {
			try {
				fos.close();
			} catch (IOException e1) {
				Logger.error(this, "Cannot close extra peer data file: "+e, e);
			}
			Logger.error(this, "Cannot write file: " + e, e);
			return false;
		}
		return true;
	}

	public synchronized String getPrivateDarknetCommentNote() {
		return privateDarknetComment;
	}

	public synchronized void setPrivateDarknetCommentNote(String comment) {
		int localFileNumber;
		privateDarknetComment = comment;
		localFileNumber = privateDarknetCommentFileNumber;
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.put("peerNoteType", Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT);
		fs.putSingle("privateDarknetComment", Base64.encodeUTF8(comment));
		if(localFileNumber == -1) {
			localFileNumber = writeNewExtraPeerDataFile(fs, Node.EXTRA_PEER_DATA_TYPE_PEER_NOTE);
			privateDarknetCommentFileNumber = localFileNumber;
		} else {
			rewriteExtraPeerDataFile(fs, Node.EXTRA_PEER_DATA_TYPE_PEER_NOTE, localFileNumber);
		}
	}

	@Override
	public void queueN2NM(SimpleFieldSet fs) {
		int fileNumber = writeNewExtraPeerDataFile( fs, Node.EXTRA_PEER_DATA_TYPE_QUEUED_TO_SEND_N2NM);
		synchronized(queuedToSendN2NMExtraPeerDataFileNumbers) {
			queuedToSendN2NMExtraPeerDataFileNumbers.add(fileNumber);
		}
	}

	public void sendQueuedN2NMs() {
		if(logMINOR)
			Logger.minor(this, "Sending queued N2NMs for "+shortToString());
		Integer[] localFileNumbers;
		synchronized(queuedToSendN2NMExtraPeerDataFileNumbers) {
			localFileNumbers = queuedToSendN2NMExtraPeerDataFileNumbers.toArray(new Integer[queuedToSendN2NMExtraPeerDataFileNumbers.size()]);
		}
		Arrays.sort(localFileNumbers);
		for (Integer localFileNumber : localFileNumbers) {
			rereadExtraPeerDataFile(localFileNumber.intValue());
		}
	}

	@Override
	void startARKFetcher() {
		synchronized(this) {
			if(isListenOnly) {
				Logger.minor(this, "Not starting ark fetcher for "+this+" as it's in listen-only mode.");
				return;
			}
		}
		super.startARKFetcher();
	}

	@Override
	public String getTMCIPeerInfo() {
		return getName()+'\t'+super.getTMCIPeerInfo();
	}

	/**
	 * A method to be called once at the beginning of every time isConnected() is true
	 */
	@Override
	protected void onConnect() {
		super.onConnect();
		sendQueuedN2NMs();
	}

	// File transfer offers
	// FIXME this should probably be somewhere else, along with the N2NM stuff... but where?
	// FIXME this should be persistent across node restarts

	/** Files I have offered to this peer */
	private final HashMap<Long, FileOffer> myFileOffersByUID = new HashMap<Long, FileOffer>();
	/** Files this peer has offered to me */
	private final HashMap<Long, FileOffer> hisFileOffersByUID = new HashMap<Long, FileOffer>();

	private void storeOffers() {
		// FIXME do something
	}

	// FIXME refactor this. We want to be able to send file transfers from code that isn't related to fproxy.
	// FIXME and it should be able to talk to plugins on other nodes etc etc.
	// FIXME there are already type fields etc, so this shouldn't be too difficult? But it's not really supported at the moment.
	// FIXME See also e.g. fcp/SendTextMessage.
	class FileOffer {
		final long uid;
		final String filename;
		final String mimeType;
		final String comment;
		/** Only valid if amIOffering == false. Set when start receiving. */
		private File destination;
		private RandomAccessBuffer data;
		final long size;
		/** Who is offering it? True = I am offering it, False = I am being offered it */
		final boolean amIOffering;
		private PartiallyReceivedBulk prb;
		private BulkTransmitter transmitter;
		private BulkReceiver receiver;
		/** True if the offer has either been accepted or rejected */
		private boolean acceptedOrRejected;

		FileOffer(long uid, RandomAccessBuffer data, String filename, String mimeType, String comment) throws IOException {
			this.uid = uid;
			this.data = data;
			this.filename = filename;
			this.mimeType = mimeType;
			this.comment = comment;
			size = data.size();
			amIOffering = true;
		}

		public FileOffer(SimpleFieldSet fs, boolean amIOffering) throws FSParseException {
			uid = fs.getLong("uid");
			size = fs.getLong("size");
			mimeType = fs.get("metadata.contentType");
			filename = FileUtil.sanitize(fs.get("filename"), mimeType);
			destination = null;
			String s = fs.get("comment");
			if(s != null) {
				try {
					s = Base64.decodeUTF8(s);
				} catch (IllegalBase64Exception e) {
					// Maybe it wasn't encoded? FIXME remove
					Logger.error(this, "Bad Base64 encoding when decoding a private darknet comment SimpleFieldSet", e);
				}
			}
			comment = s;
			this.amIOffering = amIOffering;
		}

		public void toFieldSet(SimpleFieldSet fs) {
			fs.put("uid", uid);
			fs.putSingle("filename", filename);
			fs.putSingle("metadata.contentType", mimeType);
			fs.putSingle("comment", Base64.encodeUTF8(comment));
			fs.put("size", size);
		}

		public void accept() {
			acceptedOrRejected = true;
			final String baseFilename = "direct-"+FileUtil.sanitize(getName())+"-"+filename;
			final File dest = node.clientCore.downloadsDir().file(baseFilename+".part");
			destination = node.clientCore.downloadsDir().file(baseFilename);
			try {
				data = new FileRandomAccessBuffer(dest, size, false);
			} catch (IOException e) {
				// Impossible
				throw new Error("Impossible: FileNotFoundException opening with RAF with rw! "+e, e);
			}
			prb = new PartiallyReceivedBulk(node.usm, size, Node.PACKET_SIZE, data, false);
			receiver = new BulkReceiver(prb, DarknetPeerNode.this, uid, null);
			// FIXME make this persistent
			node.executor.execute(new Runnable() {
				@Override
				public void run() {
					if(logMINOR)
						Logger.minor(this, "Received file");
					try {
						if(!receiver.receive()) {
							String err = "Failed to receive "+this;
							Logger.error(this, err);
							System.err.println(err);
							onReceiveFailure();
						} else {
							data.close();
							if(!dest.renameTo(node.clientCore.downloadsDir().file(baseFilename))){
								Logger.error(this, "Failed to rename "+dest.getName()+" to remove .part suffix.");
							}
							onReceiveSuccess();
						}
					} catch (Throwable t) {
						Logger.error(this, "Caught "+t+" receiving file", t);
						onReceiveFailure();
					} finally {
						remove();
					}
					if(logMINOR)
						Logger.minor(this, "Received file");
				}
			}, "Receiver for bulk transfer "+uid+":"+filename);
			sendFileOfferAccepted(uid);
		}

		protected void remove() {
			Long l = uid;
			synchronized(DarknetPeerNode.this) {
				myFileOffersByUID.remove(l);
				hisFileOffersByUID.remove(l);
			}
			data.close();
		}

		public void send() throws DisconnectedException {
			prb = new PartiallyReceivedBulk(node.usm, size, Node.PACKET_SIZE, data, true);
			transmitter = new BulkTransmitter(prb, DarknetPeerNode.this, uid, false, node.nodeStats.nodeToNodeCounter, false);
			if(logMINOR)
				Logger.minor(this, "Sending "+uid);
			node.executor.execute(new Runnable() {
				@Override
				public void run() {
					if(logMINOR)
						Logger.minor(this, "Sending file");
					try {
						if(!transmitter.send()) {
							String err = "Failed to send "+uid+" for "+FileOffer.this;
							Logger.error(this, err);
							System.err.println(err);
						}
					} catch (Throwable t) {
						Logger.error(this, "Caught "+t+" sending file", t);
						remove();
					}
					if(logMINOR)
						Logger.minor(this, "Sent file");
				}

			}, "Sender for bulk transfer "+uid+":"+filename);
		}

		public void reject() {
			acceptedOrRejected = true;
			sendFileOfferRejected(uid);
		}

		public void onRejected() {
			transmitter.cancel("FileOffer: Offer rejected");
			// FIXME prb's can't be shared, right? Well they aren't here...
			prb.abort(RetrievalException.CANCELLED_BY_RECEIVER, "Cancelled by receiver");
		}

		protected void onReceiveFailure() {
			UserAlert alert = new AbstractUserAlert() {
				@Override
				public String dismissButtonText() {
					return NodeL10n.getBase().getString("UserAlert.hide");
				}
				@Override
				public HTMLNode getHTMLText() {
					HTMLNode div = new HTMLNode("div");

					div.addChild("p", l10n("failedReceiveHeader", new String[] { "filename", "node" },
							new String[] { filename, getName() }));

					// Descriptive table
					describeFile(div);

					return div;
				}

				@Override
				public short getPriorityClass() {
					return UserAlert.MINOR;
				}

				@Override
				public String getText() {
					StringBuilder sb = new StringBuilder();
					sb.append(l10n("failedReceiveHeader", new String[] { "filename", "node" },
							new String[] { filename, getName() }));
					sb.append('\n');
					sb.append(l10n("fileLabel"));
					sb.append(' ');
					sb.append(filename);
					sb.append('\n');
					sb.append(l10n("sizeLabel"));
					sb.append(' ');
					sb.append(SizeUtil.formatSize(size));
					sb.append('\n');
					sb.append(l10n("mimeLabel"));
					sb.append(' ');
					sb.append(mimeType);
					sb.append('\n');
					sb.append(l10n("senderLabel"));
					sb.append(' ');
					sb.append(getName());
					sb.append('\n');
					if(comment != null && comment.length() > 0) {
						sb.append(l10n("commentLabel"));
						sb.append(' ');
						sb.append(comment);
					}
					return sb.toString();
				}

				@Override
				public String getTitle() {
					return l10n("failedReceiveTitle");
				}

				@Override
				public boolean isValid() {
					return true;
				}

				@Override
				public void isValid(boolean validity) {
					// Ignore
				}

				@Override
				public void onDismiss() {
					// Ignore
				}

				@Override
				public boolean shouldUnregisterOnDismiss() {
					return true;
				}

				@Override
				public boolean userCanDismiss() {
					return true;
				}

				@Override
				public String getShortText() {
					return l10n("failedReceiveShort", new String[] { "filename", "node" }, new String[] { filename, getName() });
				}

			};
			node.clientCore.alerts.register(alert);
		}

		private void onReceiveSuccess() {
			UserAlert alert = new AbstractUserAlert() {
				@Override
				public String dismissButtonText() {
					return NodeL10n.getBase().getString("UserAlert.hide");
				}
				@Override
				public HTMLNode getHTMLText() {
					HTMLNode div = new HTMLNode("div");

					// FIXME localise!!!

					div.addChild("p", l10n("succeededReceiveHeader", new String[] { "filename", "node" },
							new String[] { filename, getName() }));

					// Descriptive table
					describeFile(div);

					return div;
				}

				@Override
				public short getPriorityClass() {
					return UserAlert.MINOR;
				}

				@Override
				public String getText() {
					String header = l10n("succeededReceiveHeader", new String[] { "filename", "node" },
							new String[] { filename, getName() });

					return describeFileText(header);
				}

				@Override
				public String getTitle() {
					return l10n("succeededReceiveTitle");
				}

				@Override
				public boolean isValid() {
					return true;
				}

				@Override
				public void isValid(boolean validity) {
					// Ignore
				}

				@Override
				public void onDismiss() {
					// Ignore
				}

				@Override
				public boolean shouldUnregisterOnDismiss() {
					return true;
				}

				@Override
				public boolean userCanDismiss() {
					return true;
				}
				@Override
				public String getShortText() {
					return l10n("succeededReceiveShort", new String[] { "filename", "node" }, new String[] { filename, getName() });
				}

			};
			node.clientCore.alerts.register(alert);
		}

		/** Ask the user whether (s)he wants to download a file from a direct peer */
		public UserAlert askUserUserAlert() {
			return new AbstractUserAlert() {
				@Override
				public String dismissButtonText() {
					return null; // Cannot hide, but can reject
				}
				@Override
				public HTMLNode getHTMLText() {
					HTMLNode div = new HTMLNode("div");

					div.addChild("p", l10n("offeredFileHeader", "name", getName()));

					// Descriptive table
					describeFile(div);

					// Accept/reject form

					// Hopefully we will have a container when this function is called!
					HTMLNode form = node.clientCore.getToadletContainer().addFormChild(div, "/friends/", "f2fFileOfferAcceptForm");

					// FIXME node_ is inefficient
					form.addChild("input", new String[] { "type", "name" },
							new String[] { "hidden", "node_"+DarknetPeerNode.this.hashCode() });

					form.addChild("input", new String[] { "type", "name", "value" },
							new String[] { "hidden", "id", Long.toString(uid) });

					form.addChild("input", new String[] { "type", "name", "value" },
							new String[] { "submit", "acceptTransfer", l10n("acceptTransferButton") });

					form.addChild("input", new String[] { "type", "name", "value" },
							new String[] { "submit", "rejectTransfer", l10n("rejectTransferButton") });

					return div;
				}
				@Override
				public short getPriorityClass() {
					return UserAlert.MINOR;
				}
				@Override
				public String getText() {
					String header = l10n("offeredFileHeader", "name", getName());
					return describeFileText(header);
				}

				@Override
				public String getTitle() {
					return l10n("askUserTitle");
				}

				@Override
				public boolean isValid() {
					if(acceptedOrRejected) {
						node.clientCore.alerts.unregister(this);
						return false;
					}
					return true;
				}
				@Override
				public void isValid(boolean validity) {
					// Ignore
				}
				@Override
				public void onDismiss() {
					// Ignore
				}
				@Override
				public boolean shouldUnregisterOnDismiss() {
					return false;
				}

				@Override
				public boolean userCanDismiss() {
					return false; // should accept or reject
				}
				@Override
				public String getShortText() {
					return l10n("offeredFileShort", new String[] { "filename", "node" }, new String[] { filename, getName() });
				}
			};

		}
		protected void addComment(HTMLNode node) {
			String[] lines = comment.split("\n");
			for (int i = 0, c = lines.length; i < c; i++) {
				node.addChild("#", lines[i]);
				if(i != lines.length - 1)
					node.addChild("br");
			}
		}

		private String l10n(String key) {
			return NodeL10n.getBase().getString("FileOffer."+key);
		}
		private String l10n(String key, String pattern, String value) {
			return NodeL10n.getBase().getString("FileOffer."+key, pattern, value);
		}
		private String l10n(String key, String[] pattern, String[] value) {
			return NodeL10n.getBase().getString("FileOffer."+key, pattern, value);
		}

		private String describeFileText(String header) {
			StringBuilder sb = new StringBuilder();
			sb.append(header);
			sb.append('\n');
			sb.append(l10n("fileLabel"));
			sb.append(' ');
			sb.append(filename);
			sb.append('\n');
			sb.append(l10n("sizeLabel"));
			sb.append(' ');
			sb.append(SizeUtil.formatSize(size));
			sb.append('\n');
			sb.append(l10n("mimeLabel"));
			sb.append(' ');
			sb.append(mimeType);
			sb.append('\n');
			sb.append(l10n("senderLabel"));
			sb.append(' ');
			sb.append(userToString());
			sb.append('\n');
			if(comment != null && comment.length() > 0) {
				sb.append(l10n("commentLabel"));
				sb.append(' ');
				sb.append(comment);
			}
			return sb.toString();
		}

		private void describeFile(HTMLNode div) {
			HTMLNode table = div.addChild("table", "border", "0");
			HTMLNode row = table.addChild("tr");
			row.addChild("td").addChild("#", l10n("fileLabel"));
			row.addChild("td").addChild("#", filename);
			if(destination != null) {
				row = table.addChild("tr");
				row.addChild("td").addChild("#", l10n("fileSavedToLabel"));
				row.addChild("td").addChild("#", destination.getPath());
			}
			row = table.addChild("tr");
			row.addChild("td").addChild("#", l10n("sizeLabel"));
			row.addChild("td").addChild("#", SizeUtil.formatSize(size));
			row = table.addChild("tr");
			row.addChild("td").addChild("#", l10n("mimeLabel"));
			row.addChild("td").addChild("#", mimeType);
			row = table.addChild("tr");
			row.addChild("td").addChild("#", l10n("senderLabel"));
			row.addChild("td").addChild("#", getName());
			row = table.addChild("tr");
			if(comment != null && comment.length() > 0) {
				row.addChild("td").addChild("#", l10n("commentLabel"));
				addComment(row.addChild("td"));
			}
		}
	}

	public int sendBookmarkFeed(FreenetURI uri, String name, String description, boolean hasAnActiveLink) {
		long now = System.currentTimeMillis();
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.putSingle("URI", uri.toString());
		fs.putSingle("Name", name);
		fs.put("composedTime", now);
		fs.put("hasAnActivelink", hasAnActiveLink);
		if(description != null)
			fs.putSingle("Description", Base64.encodeUTF8(description));
		fs.put("type", Node.N2N_TEXT_MESSAGE_TYPE_BOOKMARK);
		sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_FPROXY, true, now, true);
		setPeerNodeStatus(System.currentTimeMillis());
		return getPeerNodeStatus();
	}

	public int sendDownloadFeed(FreenetURI URI, String description) {
		long now = System.currentTimeMillis();
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.putSingle("URI", URI.toString());
		fs.put("composedTime", now);
		if(description != null) {
			fs.putSingle("Description", Base64.encodeUTF8(description));
		}
		fs.put("type", Node.N2N_TEXT_MESSAGE_TYPE_DOWNLOAD);
		sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_FPROXY, true, now, true);
		setPeerNodeStatus(System.currentTimeMillis());
		return getPeerNodeStatus();
	}

	public int sendTextFeed(String message) {
		long now = System.currentTimeMillis();
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.put("type", Node.N2N_TEXT_MESSAGE_TYPE_USERALERT);
		fs.putSingle("text", Base64.encodeUTF8(message));
		fs.put("composedTime", now);
		sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_FPROXY, true, now, true);
		this.setPeerNodeStatus(System.currentTimeMillis());
		return getPeerNodeStatus();
	}

	public int sendFileOfferAccepted(long uid) {
		long now = System.currentTimeMillis();
		storeOffers();

		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.put("type", Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_ACCEPTED);
		fs.put("uid", uid);
		if(logMINOR)
			Logger.minor(this, "Sending node to node message (file offer accepted):\n"+fs);


		sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_FPROXY, true, now, true);
		setPeerNodeStatus(System.currentTimeMillis());
		return getPeerNodeStatus();
	}

	public int sendFileOfferRejected(long uid) {
		long now = System.currentTimeMillis();
		storeOffers();

		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.put("type", Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_REJECTED);
		fs.put("uid", uid);
		if(logMINOR)
			Logger.minor(this, "Sending node to node message (file offer rejected):\n"+fs);

		sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_FPROXY, true, now, true);
		setPeerNodeStatus(System.currentTimeMillis());
		return getPeerNodeStatus();
	}

	private int sendFileOffer(String fnam, String mime, String message, RandomAccessBuffer data) throws IOException {
		long uid = node.random.nextLong();
		long now = System.currentTimeMillis();
		FileOffer fo = new FileOffer(uid, data, fnam, mime, message);
		synchronized(this) {
			myFileOffersByUID.put(uid, fo);
		}
		storeOffers();
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fo.toFieldSet(fs);
		if(logMINOR)
			Logger.minor(this, "Sending node to node message (file offer):\n"+fs);

		fs.put("type", Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER);
		sendNodeToNodeMessage(fs, Node.N2N_MESSAGE_TYPE_FPROXY, true, now, true);
		setPeerNodeStatus(System.currentTimeMillis());
		return getPeerNodeStatus();
	}

	public int sendFileOffer(File file, String message) throws IOException {
		String fnam = file.getName();
		String mime = DefaultMIMETypes.guessMIMEType(fnam, false);
		RandomAccessBuffer data = new FileRandomAccessBuffer(file, true);
		return sendFileOffer(fnam, mime, message, data);
	}

	public int sendFileOffer(HTTPUploadedFile file, String message) throws IOException {
		String fnam = file.getFilename();
		String mime = file.getContentType();
		RandomAccessBuffer data = new ByteArrayRandomAccessBuffer(BucketTools.toByteArray(file.getData()));
		return sendFileOffer(fnam, mime, message, data);
	}

	public void handleFproxyN2NTM(SimpleFieldSet fs, int fileNumber) {
		String text = null;
		long composedTime = fs.getLong("composedTime", -1);
		long sentTime = fs.getLong("sentTime", -1);
		long receivedTime = fs.getLong("receivedTime", -1);
	  	try {
			text = Base64.decodeUTF8(fs.get("text"));
		} catch (IllegalBase64Exception e) {
			Logger.error(this, "Bad Base64 encoding when decoding a N2NTM SimpleFieldSet", e);
			return;
		}
		N2NTMUserAlert userAlert = new N2NTMUserAlert(this, text, fileNumber, composedTime, sentTime, receivedTime);
		node.clientCore.alerts.register(userAlert);
	}

	public void handleFproxyFileOffer(SimpleFieldSet fs, int fileNumber) {
		final FileOffer offer;
		try {
			offer = new FileOffer(fs, false);
		} catch (FSParseException e) {
			Logger.error(this, "Could not parse offer: "+e+" on "+this+" :\n"+fs, e);
			return;
		}
		Long u = offer.uid;
		synchronized (this) {
			if (hisFileOffersByUID.containsKey(u))
				return; // Ignore re-advertisement
			hisFileOffersByUID.put(u, offer);
		}

		// Don't persist for now - FIXME
		this.deleteExtraPeerDataFile(fileNumber);

		UserAlert alert = offer.askUserUserAlert();

		node.clientCore.alerts.register(alert);
	}

	public void acceptTransfer(long id) {
		if(logMINOR)
			Logger.minor(this, "Accepting transfer "+id+" on "+this);
		FileOffer fo;
		synchronized(this) {
			fo = hisFileOffersByUID.get(id);
		}
		if(fo == null) {
			Logger.error(this, "Cannot accept transfer "+id+" - does not exist");
			return;
		}
		fo.accept();
	}

	public void rejectTransfer(long id) {
		FileOffer fo;
		synchronized(this) {
			fo = hisFileOffersByUID.remove(id);
		}
		if(fo == null) {
			Logger.error(this, "Cannot accept transfer "+id+" - does not exist");
			return;
		}
		fo.reject();
	}

	public void handleFproxyFileOfferAccepted(SimpleFieldSet fs, int fileNumber) {
		// Don't persist for now - FIXME
		this.deleteExtraPeerDataFile(fileNumber);

		long uid;
		try {
			uid = fs.getLong("uid");
		} catch (FSParseException e) {
			Logger.error(this, "Could not parse offer accepted: "+e+" on "+this+" :\n"+fs, e);
			return;
		}
		if(logMINOR)
			Logger.minor(this, "Offer accepted for "+uid);
		FileOffer fo;
		synchronized(this) {
			fo = (myFileOffersByUID.get(uid));
		}
		if(fo == null) {
			Logger.error(this, "No such offer: "+uid);
			try {
				sendAsync(DMT.createFNPBulkSendAborted(uid), null, node.nodeStats.nodeToNodeCounter);
			} catch (NotConnectedException e) {
				// Fine by me!
			}
			return;
		}
		try {
			fo.send();
		} catch (DisconnectedException e) {
			Logger.error(this, "Cannot send because node disconnected: "+e+" for "+uid+":"+fo.filename, e);
		}
	}

	public void handleFproxyFileOfferRejected(SimpleFieldSet fs, int fileNumber) {
		// Don't persist for now - FIXME
		this.deleteExtraPeerDataFile(fileNumber);

		long uid;
		try {
			uid = fs.getLong("uid");
		} catch (FSParseException e) {
			Logger.error(this, "Could not parse offer rejected: "+e+" on "+this+" :\n"+fs, e);
			return;
		}

		FileOffer fo;
		synchronized(this) {
			fo = myFileOffersByUID.remove(uid);
		}
		fo.onRejected();
	}

	public void handleFproxyBookmarkFeed(SimpleFieldSet fs, int fileNumber) {
		String name = fs.get("Name");
		String description = null;
		FreenetURI uri = null;
		boolean hasAnActiveLink = fs.getBoolean("hasAnActivelink", false);
		long composedTime = fs.getLong("composedTime", -1);
		long sentTime = fs.getLong("sentTime", -1);
		long receivedTime = fs.getLong("receivedTime", -1);
		try {
			String s = fs.get("Description");
			if(s != null)
				description = Base64.decodeUTF8(s);
			uri = new FreenetURI(fs.get("URI"));
		} catch (MalformedURLException e) {
			Logger.error(this, "Malformed URI in N2NTM Bookmark Feed message");
			return;
		} catch (IllegalBase64Exception e) {
			Logger.error(this, "Bad Base64 encoding when decoding a N2NTM SimpleFieldSet", e);
			return;
		}
		BookmarkFeedUserAlert userAlert = new BookmarkFeedUserAlert(this, name, description, hasAnActiveLink, fileNumber, uri, composedTime, sentTime, receivedTime);
		node.clientCore.alerts.register(userAlert);
	}

	public void handleFproxyDownloadFeed(SimpleFieldSet fs, int fileNumber) {
		FreenetURI uri = null;
		String description = null;
		long composedTime = fs.getLong("composedTime", -1);
		long sentTime = fs.getLong("sentTime", -1);
		long receivedTime = fs.getLong("receivedTime", -1);
		try {
			String s = fs.get("Description");
			if(s != null)
				description = Base64.decodeUTF8(s);
			uri = new FreenetURI(fs.get("URI"));
		} catch (MalformedURLException e) {
			Logger.error(this, "Malformed URI in N2NTM File Feed message");
			return;
		} catch (IllegalBase64Exception e) {
			Logger.error(this, "Bad Base64 encoding when decoding a N2NTM SimpleFieldSet", e);
			return;
		}
		DownloadFeedUserAlert userAlert = new DownloadFeedUserAlert(this, description, fileNumber, uri, composedTime, sentTime, receivedTime);
		node.clientCore.alerts.register(userAlert);
	}

	@Override
	public String userToString() {
		return ""+getPeer()+" : "+getName();
	}

	@Override
	public PeerNodeStatus getStatus(boolean noHeavy) {
		return new DarknetPeerNodeStatus(this, noHeavy);
	}

	@Override
	public boolean isDarknet() {
		return true;
	}

	@Override
	public boolean isOpennet() {
		return false;
	}

	@Override
	public boolean isSeed() {
		return false;
	}

	@Override
	public void onSuccess(boolean insert, boolean ssk) {
		// Ignore it
	}

	@Override
	public void onRemove() {
		// Do nothing
		// FIXME is there anything we should do?
	}

	@Override
	public boolean isRealConnection() {
		return true;
	}

	@Override
	public boolean recordStatus() {
		return true;
	}

	@Override
	protected boolean generateIdentityFromPubkey() {
		return false;
	}

	@Override
	public boolean equals(Object o) {
		if(o == this) return true;
		// Only equal to seednode of its own type.
		if(o instanceof DarknetPeerNode) {
			return super.equals(o);
		} else return false;
	}

	@Override
	public final boolean shouldDisconnectAndRemoveNow() {
		return false;
	}

	@Override
	/** Darknet peers clear peerAddedTime on connecting. */
	protected void maybeClearPeerAddedTimeOnConnect() {
		peerAddedTime = 0;  // don't store anymore
	}

	@Override
	/** Darknet nodes *do* export the peer added time. However it gets
	 * cleared on connecting: It is only kept for never-connected peers
	 * so we can see that we haven't had a connection in a long time and
	 * offer to get rid of them. */
	protected boolean shouldExportPeerAddedTime() {
		return true;
	}

	@Override
	protected void maybeClearPeerAddedTimeOnRestart(long now) {
		if((now - peerAddedTime) > DAYS.toMillis(30))
			peerAddedTime = 0;
		if(!neverConnected)
			peerAddedTime = 0;
	}

	// FIXME find a better solution???
	@Override
	public void fatalTimeout() {
		if(node.isStopping()) return;
		Logger.error(this, "Disconnecting from darknet node "+this+" because of fatal timeout", new Exception("error"));
		System.err.println("Your friend node \""+getName()+"\" ("+getPeer()+" version "+getVersion()+") is having severe problems. We have disconnected to try to limit the effect on us. It will reconnect soon.");
		// FIXME post a useralert
		// Disconnect.
		forceDisconnect();
	}

	public synchronized FRIEND_TRUST getTrustLevel() {
		return trustLevel;
	}

	@Override
	public boolean shallWeRouteAccordingToOurPeersLocation() {
		if(!node.shallWeRouteAccordingToOurPeersLocation()) return false; // Globally disabled
		if(trustLevel == FRIEND_TRUST.LOW) return false;
		return true;
	}

	public void setTrustLevel(FRIEND_TRUST trust) {
		synchronized(this) {
			trustLevel = trust;
		}
		node.peers.writePeersDarknetUrgent();
	}

	/** FIXME This should be the worse of our visibility for the peer and that which the peer has told us.
	 * I.e. visibility is reciprocal. */
	public synchronized FRIEND_VISIBILITY getVisibility() {
		// ourVisibility can't be null.
		if(ourVisibility.isStricterThan(theirVisibility)) return ourVisibility;
		return theirVisibility;
	}

	public synchronized FRIEND_VISIBILITY getOurVisibility() {
		return ourVisibility;
	}

	public void setVisibility(FRIEND_VISIBILITY visibility) {
		synchronized(this) {
			if(ourVisibility == visibility) return;
			ourVisibility = visibility;
		}
		node.peers.writePeersDarknetUrgent();
		try {
			sendVisibility();
		} catch (NotConnectedException e) {
			Logger.normal(this, "Disconnected while sending visibility update");
		}
	}

	private void sendVisibility() throws NotConnectedException {
		sendAsync(DMT.createFNPVisibility(getOurVisibility().code), null, node.nodeStats.initialMessagesCtr);
	}

	public void handleVisibility(Message m) {
		FRIEND_VISIBILITY v = FRIEND_VISIBILITY.getByCode(m.getShort(DMT.FRIEND_VISIBILITY));
		if(v == null) {
			Logger.error(this, "Bogus visibility setting from peer "+this+" : code "+m.getShort(DMT.FRIEND_VISIBILITY));
			v = FRIEND_VISIBILITY.NO;
		}
		synchronized(this) {
			if(theirVisibility == v) return;
			theirVisibility = v;
		}
		node.peers.writePeersDarknet();
	}

	public synchronized FRIEND_VISIBILITY getTheirVisibility() {
		if(theirVisibility == null) return FRIEND_VISIBILITY.NO;
		return theirVisibility;
	}

	@Override
	boolean dontKeepFullFieldSet() {
		return false;
	}

	private boolean sendingFullNoderef;

	public void sendFullNoderef() {
		synchronized(this) {
			if(sendingFullNoderef) return; // DoS????
			sendingFullNoderef = true;
		}
		try {
			SimpleFieldSet myFullNoderef = node.exportDarknetPublicFieldSet();
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DeflaterOutputStream dos = new DeflaterOutputStream(baos);
			try {
				myFullNoderef.writeTo(dos);
				dos.close();
			} catch (IOException e) {
				Logger.error(this, "Impossible: Caught error while writing compressed noderef: "+e, e);
				synchronized(this) {
					sendingFullNoderef = false;
				}
				return;
			}
			byte[] data = baos.toByteArray();
			long uid = node.fastWeakRandom.nextLong();
			RandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(data);
			PartiallyReceivedBulk prb = new PartiallyReceivedBulk(node.usm, data.length, Node.PACKET_SIZE, raf, true);
			try {
				sendAsync(DMT.createFNPMyFullNoderef(uid, data.length), null, node.nodeStats.foafCounter);
			} catch (NotConnectedException e1) {
				// Ignore
				synchronized(this) {
					sendingFullNoderef = false;
				}
				return;
			}
			final BulkTransmitter bt;
			try {
				bt = new BulkTransmitter(prb, this, uid, false, node.nodeStats.foafCounter, false);
			} catch (DisconnectedException e) {
				synchronized(this) {
					sendingFullNoderef = false;
				}
				return;
			}
			node.executor.execute(new Runnable() {

				@Override
				public void run() {
					try {
						bt.send();
					} catch (DisconnectedException e) {
						// :|
					} finally {
						synchronized(DarknetPeerNode.this) {
							sendingFullNoderef = false;
						}
					}
				}

			});
		} catch (RuntimeException e) {
			synchronized(this) {
				sendingFullNoderef = false;
			}
			throw e;
		} catch (Error e) {
			synchronized(this) {
				sendingFullNoderef = false;
			}
			throw e;
		}
	}

	private boolean receivingFullNoderef;

	public void handleFullNoderef(Message m) {
		if(this.dontKeepFullFieldSet()) return;
		long uid = m.getLong(DMT.UID);
		int length = m.getInt(DMT.NODEREF_LENGTH);
		if(length > 8 * 1024) {
			// Way too long!
			return;
		}
		synchronized(this) {
			if(receivingFullNoderef) return; // DoS????
			receivingFullNoderef = true;
		}
		try {
			final byte[] data = new byte[length];
			RandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(data);
			PartiallyReceivedBulk prb = new PartiallyReceivedBulk(node.usm, length, Node.PACKET_SIZE, raf, false);
			final BulkReceiver br = new BulkReceiver(prb, this, uid, node.nodeStats.foafCounter);
			node.executor.execute(new Runnable() {

				@Override
				public void run() {
					try {
						if(br.receive()) {
							ByteArrayInputStream bais = new ByteArrayInputStream(data);
							InflaterInputStream dis = new InflaterInputStream(bais);
							SimpleFieldSet fs;
							try {
								fs = new SimpleFieldSet(new BufferedReader(new InputStreamReader(dis, "UTF-8")), false, false);
							} catch (UnsupportedEncodingException e) {
								synchronized(DarknetPeerNode.this) {
									receivingFullNoderef = false;
								}
								Logger.error(this, "Impossible: "+e, e);
								e.printStackTrace();
								return;
							} catch (IOException e) {
								synchronized(DarknetPeerNode.this) {
									receivingFullNoderef = false;
								}
								Logger.error(this, "Impossible: "+e, e);
								return;
							}
							try {
								processNewNoderef(fs, false, false, true);
							} catch (FSParseException e) {
								Logger.error(this, "Peer "+DarknetPeerNode.this+" sent bogus full noderef: "+e, e);
								synchronized(DarknetPeerNode.this) {
									receivingFullNoderef = false;
								}
								return;
							}
							synchronized(DarknetPeerNode.this) {
								fullFieldSet = fs;
							}
							node.peers.writePeersDarknet();
						} else {
							Logger.error(this, "Failed to receive noderef from "+DarknetPeerNode.this);
						}
					} finally {
						synchronized(DarknetPeerNode.this) {
							receivingFullNoderef = false;
						}
					}
				}
			});
		} catch (RuntimeException e) {
			synchronized(this) {
				receivingFullNoderef = false;
			}
			throw e;
		} catch (Error e) {
			synchronized(this) {
				receivingFullNoderef = false;
			}
			throw e;
		}
	}

	@Override
	protected void sendInitialMessages() {
		super.sendInitialMessages();
		try {
			sendVisibility();
		} catch(NotConnectedException e) {
			Logger.error(this, "Completed handshake with " + getPeer() + " but disconnected: "+e, e);
		}
		if(!dontKeepFullFieldSet()) {
			try {
				sendAsync(DMT.createFNPGetYourFullNoderef(), null, node.nodeStats.foafCounter);
			} catch (NotConnectedException e) {
				// Ignore
			}
		}
	}
}
