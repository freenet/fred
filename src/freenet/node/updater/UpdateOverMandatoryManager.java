/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node.updater;

import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.WeakHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.FetchResult;
import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.async.BaseClientPutter;
import freenet.client.async.BinaryBlob;
import freenet.client.async.BinaryBlobFormatException;
import freenet.client.async.BinaryBlobWriter;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientGetCallback;
import freenet.client.async.ClientGetter;
import freenet.client.async.ClientPutCallback;
import freenet.client.async.ClientPutter;
import freenet.client.async.PersistenceDisabledException;
import freenet.client.async.SimpleBlockSet;
import freenet.io.comm.AsyncMessageCallback;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.Message;
import freenet.io.comm.NotConnectedException;
import freenet.io.xfer.BulkReceiver;
import freenet.io.xfer.BulkTransmitter;
import freenet.io.xfer.PartiallyReceivedBulk;
import freenet.keys.FreenetURI;
import freenet.l10n.NodeL10n;
import freenet.node.Node;
import freenet.node.PeerNode;
import freenet.node.RequestClient;
import freenet.node.RequestStarter;
import freenet.node.Version;
import freenet.node.useralerts.AbstractUserAlert;
import freenet.node.useralerts.UserAlert;
import freenet.support.HTMLNode;
import freenet.support.HexUtil;
import freenet.support.Logger;
import freenet.support.ShortBuffer;
import freenet.support.SizeUtil;
import freenet.support.TimeUtil;
import freenet.support.WeakHashSet;
import freenet.support.api.Bucket;
import freenet.support.api.RandomAccessBucket;
import freenet.support.api.RandomAccessBuffer;
import freenet.support.io.ArrayBucket;
import freenet.support.io.ByteArrayRandomAccessBuffer;
import freenet.support.io.Closer;
import freenet.support.io.FileBucket;
import freenet.support.io.FileUtil;
import freenet.support.io.FileRandomAccessBuffer;

/**
 * Co-ordinates update over mandatory. Update over mandatory = updating from your peers, even
 * though they may be so much newer than you that you can't route requests through them.
 * NodeDispatcher feeds UOMAnnouncement's received from peers to this class, and it decides what to
 * do about them.
 * @author toad
 */
public class UpdateOverMandatoryManager implements RequestClient {

	private static volatile boolean logMINOR;

	static {
		Logger.registerClass(UpdateOverMandatoryManager.class);
	}

	final NodeUpdateManager updateManager;
	/** Set of PeerNode's which say (or said before they disconnected) 
	 * the key has been revoked */
	private final HashSet<PeerNode> nodesSayKeyRevoked;
	/** Set of PeerNode's which say the key has been revoked but failed
	 * to transfer the revocation key. */
	private final HashSet<PeerNode> nodesSayKeyRevokedFailedTransfer;
	/** Set of PeerNode's which say the key has been revoked and are transferring the revocation certificate. */
	private final HashSet<PeerNode> nodesSayKeyRevokedTransferring;
	/** PeerNode's which have offered the main jar which we are not fetching it from right now */
	private final HashSet<PeerNode> nodesOfferedMainJar;
	/** PeerNode's which have offered the ext jar which we are not fetching it from right now */
	private final HashSet<PeerNode> nodesAskedSendMainJar;
	/** PeerNode's sending us the main jar */
	private final HashSet<PeerNode> nodesSendingMainJar;
	/** PeerNode's that we've successfully fetched a jar from */
	private final HashSet<PeerNode> nodesSentMainJar;
	/** All PeerNode's that offered the main jar, regardless of what happened after that. */
	private final HashSet<PeerNode> allNodesOfferedMainJar;
	// 2 for reliability, no more as gets very slow/wasteful
	static final int MAX_NODES_SENDING_JAR = 2;
	/** Maximum time between asking for the main jar and it starting to transfer */
	static final long REQUEST_MAIN_JAR_TIMEOUT = SECONDS.toMillis(60);
	//** Grace time before we use UoM to update */
	public static final long GRACE_TIME = HOURS.toMillis(3);
	private UserAlert alert;
	private static final Pattern mainBuildNumberPattern = Pattern.compile("^main(?:-jar)?-(\\d+)\\.fblob$");
	private static final Pattern mainTempBuildNumberPattern = Pattern.compile("^main(?:-jar)?-(\\d+-)?(\\d+)\\.fblob\\.tmp*$");
	private static final Pattern revocationTempBuildNumberPattern = Pattern.compile("^revocation(?:-jar)?-(\\d+-)?(\\d+)\\.fblob\\.tmp*$");
	/** If we fetched the main jar locally, there is a 1 in RANDOM_INSERT_BLOB chance of inserting it.
	 * We always insert it if we downloaded it via UOM. We always reinsert revocations. */
    protected static final int RANDOM_INSERT_BLOB = 10;
	private boolean fetchingUOM;
	
	private final HashMap<ShortBuffer, File> dependencies;
	
	private final WeakHashMap<PeerNode, Integer> peersFetchingDependencies;
	
	private final HashMap<ShortBuffer, UOMDependencyFetcher> dependencyFetchers;

	public UpdateOverMandatoryManager(NodeUpdateManager manager) {
		this.updateManager = manager;
		nodesSayKeyRevoked = new HashSet<PeerNode>();
		nodesSayKeyRevokedFailedTransfer = new HashSet<PeerNode>();
		nodesSayKeyRevokedTransferring = new HashSet<PeerNode>();
		nodesOfferedMainJar = new HashSet<PeerNode>();
		nodesSentMainJar = new HashSet<PeerNode>();
		nodesAskedSendMainJar = new HashSet<PeerNode>();
		nodesSendingMainJar = new HashSet<PeerNode>();
		allNodesOfferedMainJar = new HashSet<PeerNode>();
		dependencies = new HashMap<ShortBuffer, File>();
		peersFetchingDependencies = new WeakHashMap<PeerNode, Integer>();
		dependencyFetchers = new HashMap<ShortBuffer, UOMDependencyFetcher>();
	}

	/** 
	 * Handle a UOMAnnouncement message. A node has sent us a message offering us use of its update
	 * over mandatory facilities in some way.
	 * @param m The message to handle. Either a UOMAnnounce or a UOMAnnouncement.
	 * @param source The PeerNode which sent the message.
	 * @return True unless we don't want the message (in this case, always true).
	 */
	public boolean handleAnnounce(Message m, final PeerNode source) {
		
		String mainJarKey = m.getString(DMT.MAIN_JAR_KEY);
		String revocationKey = m.getString(DMT.REVOCATION_KEY);
		boolean haveRevocationKey = m.getBoolean(DMT.HAVE_REVOCATION_KEY);
		long mainJarVersion = m.getLong(DMT.MAIN_JAR_VERSION);
		long revocationKeyLastTried = m.getLong(DMT.REVOCATION_KEY_TIME_LAST_TRIED);
		int revocationKeyDNFs = m.getInt(DMT.REVOCATION_KEY_DNF_COUNT);
		long revocationKeyFileLength = m.getLong(DMT.REVOCATION_KEY_FILE_LENGTH);
		long mainJarFileLength = m.getLong(DMT.MAIN_JAR_FILE_LENGTH);
		int pingTime = m.getInt(DMT.PING_TIME);
		int delayTime = m.getInt(DMT.BWLIMIT_DELAY_TIME);

		// Log it

		if(logMINOR) {
			Logger.minor(this, "Update Over Mandatory offer from node " + source.getPeer() + " : " + source.userToString() + ":");
			Logger.minor(this, "Main jar key: " + mainJarKey + " version=" + mainJarVersion + " length=" + mainJarFileLength);
			Logger.minor(this, "Revocation key: " + revocationKey + " found=" + haveRevocationKey + " length=" + revocationKeyFileLength + " last had 3 DNFs " + revocationKeyLastTried + " ms ago, " + revocationKeyDNFs + " DNFs so far");
			Logger.minor(this, "Load stats: " + pingTime + "ms ping, " + delayTime + "ms bwlimit delay time");
		}

		// Now the core logic

		// First off, if a node says it has the revocation key, and its key is the same as ours,
		// we should 1) suspend any auto-updates and tell the user, 2) try to download it, and 
		// 3) if the download fails, move the notification; if the download succeeds, process it

		if(haveRevocationKey) {

			if(updateManager.isBlown())
				return true; // We already know

			// First, is the key the same as ours?
			try {
				FreenetURI revocationURI = new FreenetURI(revocationKey);
				if(revocationURI.equals(updateManager.getRevocationURI())) {

					// Uh oh...

					// Have to do this first to avoid race condition
					synchronized(this) {
						// If already transferring, don't start another transfer.
						if(nodesSayKeyRevokedTransferring.contains(source)) return true;
						// If waiting for SendingRevocation, don't start another transfer.
						if(nodesSayKeyRevoked.contains(source)) return true;
						nodesSayKeyRevoked.add(source);
					}

					// Disable the update
					updateManager.peerClaimsKeyBlown();

					// Tell the user
					alertUser();

					System.err.println("Your peer " + source.userToString() +
							" (build #" + source.getSimpleVersion() + ") says that the auto-update key is blown!");
					System.err.println("Attempting to fetch it...");

					tryFetchRevocation(source);
					
				} else {
					// Should probably also be a useralert?
					Logger.normal(this, "Node " + source + " sent us a UOM claiming that the auto-update key was blown, but it used a different key to us: \nour key=" + updateManager.getRevocationURI() + "\nhis key=" + revocationURI);
				}
			} catch(MalformedURLException e) {
				// Should maybe be a useralert?
				Logger.error(this, "Node " + source + " sent us a UOMAnnouncement claiming that the auto-update key was blown, but it had an invalid revocation URI: " + revocationKey + " : " + e, e);
				System.err.println("Node " + source.userToString() + " sent us a UOMAnnouncement claiming that the revocation key was blown, but it had an invalid revocation URI: " + revocationKey + " : " + e);
			} catch(NotConnectedException e) {
				System.err.println("Node " + source + " says that the auto-update key was blown, but has now gone offline! Something bad may be happening!");
				Logger.error(this, "Node " + source + " says that the auto-update key was blown, but has now gone offline! Something bad may be happening!");
				synchronized(UpdateOverMandatoryManager.this) {
					nodesSayKeyRevoked.remove(source);
					// Might be valid, but no way to tell except if other peers tell us.
					// And there's a good chance it isn't.
				}
				maybeNotRevoked();
			}

		}
		
		tellFetchers(source);
		
		if(updateManager.isBlown())
			return true; // We already know

		if(!updateManager.isEnabled())
			return true; // Don't care if not enabled, except for the revocation URI

		long now = System.currentTimeMillis();
		
		handleMainJarOffer(now, mainJarFileLength, mainJarVersion, source, mainJarKey);
		
		return true;
	}

	private void tellFetchers(PeerNode source) {
		HashSet<UOMDependencyFetcher> fetchList;
		synchronized(dependencyFetchers) {
			fetchList = new HashSet<UOMDependencyFetcher>(dependencyFetchers.values());
		}
		for(UOMDependencyFetcher f : fetchList) {
		    if(source.isDarknet()) f.peerMaybeFreeSlots(source);
			f.start();
		}
	}

	private void tryFetchRevocation(final PeerNode source) throws NotConnectedException {
		// Try to transfer it.

		Message msg = DMT.createUOMRequestRevocation(updateManager.node.random.nextLong());
		source.sendAsync(msg, new AsyncMessageCallback() {

			@Override
			public void acknowledged() {
				// Ok
			}

			@Override
			public void disconnected() {
				// :(
				System.err.println("Failed to send request for revocation key to " + source.userToString() + 
						" (build #" + source.getSimpleVersion() + ") because it disconnected!");
				source.failedRevocationTransfer();
				synchronized(UpdateOverMandatoryManager.this) {
					nodesSayKeyRevokedFailedTransfer.add(source);
				}
			}

			@Override
			public void fatalError() {
				// Not good!
				System.err.println("Failed to send request for revocation key to " + source.userToString() + " because of a fatal error.");
			}

			@Override
			public void sent() {
				// Cool
			}
		}, updateManager.ctr);
		
		updateManager.node.getTicker().queueTimedJob(new Runnable() {

			@Override
			public void run() {
				if(updateManager.isBlown()) return;
				synchronized(UpdateOverMandatoryManager.this) {
					if(nodesSayKeyRevokedFailedTransfer.contains(source)) return;
					if(nodesSayKeyRevokedTransferring.contains(source)) return;
					nodesSayKeyRevoked.remove(source);
				}
				System.err.println("Peer "+source+" (build #" + source.getSimpleVersion() + ") said that the auto-update key had been blown, but did not transfer the revocation certificate. The most likely explanation is that the key has not been blown (the node is buggy or malicious), so we are ignoring this.");
				maybeNotRevoked();
			}

		}, SECONDS.toMillis(60));

	// The reply message will start the transfer. It includes the revocation URI
	// so we can tell if anything wierd is happening.

	}

	private void handleMainJarOffer(long now, long mainJarFileLength, long mainJarVersion, PeerNode source, String jarKey) {
		
		long started = updateManager.getStartedFetchingNextMainJarTimestamp();
		long whenToTakeOverTheNormalUpdater;
		if(started > 0)
			whenToTakeOverTheNormalUpdater = started + GRACE_TIME;
		else
			whenToTakeOverTheNormalUpdater = System.currentTimeMillis() + GRACE_TIME;
		boolean isOutdated = updateManager.node.isOudated();
		// if the new build is self-mandatory or if the "normal" updater has been trying to update for more than one hour
		Logger.normal(this, "We received a valid UOMAnnouncement (main) : (isOutdated=" + isOutdated + " version=" + mainJarVersion + " whenToTakeOverTheNormalUpdater=" + TimeUtil.formatTime(whenToTakeOverTheNormalUpdater - now) + ") file length " + mainJarFileLength + " updateManager version " + updateManager.newMainJarVersion());
		if(mainJarVersion > Version.buildNumber() && mainJarFileLength > 0 &&
			mainJarVersion > updateManager.newMainJarVersion()) {
			source.setMainJarOfferedVersion(mainJarVersion);
			// Offer is valid.
			if(logMINOR)
				Logger.minor(this, "Offer is valid");
			if((isOutdated) || whenToTakeOverTheNormalUpdater < now) {
				// Take up the offer, subject to limits on number of simultaneous downloads.
				// If we have fetches running already, then sendUOMRequestMainJar() will add the offer to nodesOfferedMainJar,
				// so that if all our fetches fail, we can fetch from this node.
				if(!isOutdated) {
					String howLong = TimeUtil.formatTime(now - started);
					Logger.error(this, "The update process seems to have been stuck for " + howLong + "; let's switch to UoM! SHOULD NOT HAPPEN! (1)");
					System.out.println("The update process seems to have been stuck for " + howLong + "; let's switch to UoM! SHOULD NOT HAPPEN! (1)");
				} else if(logMINOR)
					Logger.minor(this, "Fetching via UOM as our build is deprecated");
				// Fetch it
				try {
					FreenetURI mainJarURI = new FreenetURI(jarKey).setSuggestedEdition(mainJarVersion);
					if(mainJarURI.equals(updateManager.getURI().setSuggestedEdition(mainJarVersion)))
						sendUOMRequest(source, true);
					else
					    // FIXME don't log if it's the transitional version.
						System.err.println("Node " + source.userToString() + " offered us a new main jar (version " + mainJarVersion + ") but his key was different to ours:\n" +
							"our key: " + updateManager.getURI() + "\nhis key:" + mainJarURI);
				} catch(MalformedURLException e) {
					// Should maybe be a useralert?
					Logger.error(this, "Node " + source + " sent us a UOMAnnouncement claiming to have a new ext jar, but it had an invalid URI: " + jarKey + " : " + e, e);
					System.err.println("Node " + source.userToString() + " sent us a UOMAnnouncement claiming to have a new ext jar, but it had an invalid URI: " + jarKey + " : " + e);
				}
				synchronized(this) {
					allNodesOfferedMainJar.add(source);
				}
			} else {
				// Don't take up the offer. Add to nodesOfferedMainJar, so that we know where to fetch it from when we need it.
				synchronized(this) {
					nodesOfferedMainJar.add(source);
					allNodesOfferedMainJar.add(source);
				}
				updateManager.node.getTicker().queueTimedJob(new Runnable() {

					@Override
					public void run() {
						if(updateManager.isBlown())
							return;
						if(!updateManager.isEnabled())
							return;
						if(updateManager.hasNewMainJar())
							return;
						if(!updateManager.node.isOudated()) {
							Logger.error(this, "The update process seems to have been stuck for too long; let's switch to UoM! SHOULD NOT HAPPEN! (2) (ext)");
							System.out.println("The update process seems to have been stuck for too long; let's switch to UoM! SHOULD NOT HAPPEN! (2) (ext)");
						}
						maybeRequestMainJar();
					}
				}, whenToTakeOverTheNormalUpdater - now);
			}
		} else {
			// We may want the dependencies.
			// These may be similar even if his url is different, so add unconditionally.
			synchronized(this) {
				allNodesOfferedMainJar.add(source);
			}
		}
		startSomeDependencyFetchers();
	}

	private void sendUOMRequest(final PeerNode source, boolean addOnFail) {
		final String name = "Main";
		String lname = "main";
		if(logMINOR)
			Logger.minor(this, "sendUOMRequest"+name+"(" + source + "," + addOnFail + ")");
		if(!source.isConnected() || source.isSeed()) {
                    if(logMINOR) Logger.minor(this, "Not sending UOM "+lname+" request to "+source+" (disconnected or seednode)");
                    return;
                }
		final HashSet<PeerNode> sendingJar = nodesSendingMainJar;
		final HashSet<PeerNode> askedSendJar = nodesAskedSendMainJar;
		boolean wasFetchingUOM = false;
		synchronized(this) {
			long offeredVersion = source.getMainJarOfferedVersion();
			long updateVersion = updateManager.newMainJarVersion();
			if(offeredVersion < updateVersion) {
				if(offeredVersion <= 0)
					Logger.error(this, "Not sending UOM "+lname+" request to " + source + " because it hasn't offered anything!");
				else
					if(logMINOR)
						Logger.minor(this, "Not sending UOM "+lname+" request to " + source + " because we already have its offered version " + offeredVersion);
				return;
			}
			int curVersion = updateManager.getMainVersion();
			if(curVersion >= offeredVersion) {
				if(logMINOR)
					Logger.minor(this, "Not fetching from " + source + " because current "+lname+" jar version " + curVersion + " is more recent than " + offeredVersion);
				return;
			}
			if(askedSendJar.contains(source)) {
				if(logMINOR)
					Logger.minor(this, "Recently asked node " + source + " ("+lname+") so not re-asking yet.");
				return;
			}
			if(addOnFail && askedSendJar.size() + sendingJar.size() >= MAX_NODES_SENDING_JAR) {
				HashSet<PeerNode> offeredJar = nodesOfferedMainJar;
				if(offeredJar.add(source))
					System.err.println("Offered "+lname+" jar by " + source.userToString() + " (already fetching from " + sendingJar.size() + "), but will use this offer if our current fetches fail).");
				return;
			} else {
				if(sendingJar.contains(source)) {
					if(logMINOR)
						Logger.minor(this, "Not fetching "+lname+" jar from " + source.userToString() + " because already fetching from that node");
					return;
				}
				sendingJar.add(source);
			}
			wasFetchingUOM = fetchingUOM;
			fetchingUOM = true;
		}
		if(!wasFetchingUOM)
			this.updateManager.onStartFetchingUOM();

		Message msg = 
			DMT.createUOMRequestMainJar(updateManager.node.random.nextLong());

		try {
			System.err.println("Fetching "+lname+" jar from " + source.userToString());
			source.sendAsync(msg, new AsyncMessageCallback() {

				@Override
				public void acknowledged() {
					// Cool! Wait for the actual transfer.
				}

				@Override
				public void disconnected() {
					Logger.normal(this, "Disconnected from " + source.userToString() + " after sending UOMRequestMainJar");
					synchronized(UpdateOverMandatoryManager.this) {
						sendingJar.remove(source);
					}
					maybeRequestMainJar();
				}

				@Override
				public void fatalError() {
					Logger.normal(this, "Fatal error from " + source.userToString() + " after sending UOMRequestMainJar");
					synchronized(UpdateOverMandatoryManager.this) {
						askedSendJar.remove(source);
					}
					maybeRequestMainJar();
				}

				@Override
				public void sent() {
					// Timeout...
					updateManager.node.ticker.queueTimedJob(new Runnable() {

						@Override
						public void run() {
							synchronized(UpdateOverMandatoryManager.this) {
								// free up a slot
								if(!askedSendJar.remove(source))
									return;
							}
							maybeRequestMainJar();
						}
					}, REQUEST_MAIN_JAR_TIMEOUT);
				}
			}, updateManager.ctr);
		} catch(NotConnectedException e) {
			synchronized(this) {
				askedSendJar.remove(source);
			}
			maybeRequestMainJar();
		}
	}

	protected void maybeRequestMainJar() {
		PeerNode[] offers;
		synchronized(this) {
			if(nodesAskedSendMainJar.size() + nodesSendingMainJar.size() >= MAX_NODES_SENDING_JAR)
				return;
			if(nodesOfferedMainJar.isEmpty())
				return;
			offers = nodesOfferedMainJar.toArray(new PeerNode[nodesOfferedMainJar.size()]);
		}
		for(PeerNode offer: offers) {
			if(!offer.isConnected())
				continue;
			synchronized(this) {
				if(nodesAskedSendMainJar.size() + nodesSendingMainJar.size() >= MAX_NODES_SENDING_JAR)
					return;
				if(nodesSendingMainJar.contains(offer))
					continue;
				if(nodesAskedSendMainJar.contains(offer))
					continue;
			}
			sendUOMRequest(offer, false);
		}
	}

	private void alertUser() {
		synchronized(this) {
			if(alert != null)
				return;
			alert = new PeersSayKeyBlownAlert();
		}
		updateManager.node.clientCore.alerts.register(alert);
	}

	private class PeersSayKeyBlownAlert extends AbstractUserAlert {

		public PeersSayKeyBlownAlert() {
			super(false, null, null, null, null, UserAlert.WARNING, true, null, false, null);
		}

		@Override
		public HTMLNode getHTMLText() {
			HTMLNode div = new HTMLNode("div");

			div.addChild("p").addChild("#", l10n("intro"));

			PeerNode[][] nodes = getNodesSayBlown();
			PeerNode[] nodesSayBlownConnected = nodes[0];
			PeerNode[] nodesSayBlownDisconnected = nodes[1];
			PeerNode[] nodesSayBlownFailedTransfer = nodes[2];

			if(nodesSayBlownConnected.length > 0)
				div.addChild("p").addChild("#", l10n("fetching"));
			else
				div.addChild("p").addChild("#", l10n("failedFetch"));

			if(nodesSayBlownConnected.length > 0) {
				div.addChild("p").addChild("#", l10n("connectedSayBlownLabel"));
				HTMLNode list = div.addChild("ul");
				for(PeerNode pn: nodesSayBlownConnected) {
					list.addChild("li", pn.userToString() + " (" + pn.getPeer() + ")");
				}
			}

			if(nodesSayBlownDisconnected.length > 0) {
				div.addChild("p").addChild("#", l10n("disconnectedSayBlownLabel"));
				HTMLNode list = div.addChild("ul");
				for(PeerNode pn: nodesSayBlownDisconnected) {
					list.addChild("li", pn.userToString() + " (" + pn.getPeer() + ")");
				}
			}

			if(nodesSayBlownFailedTransfer.length > 0) {
				div.addChild("p").addChild("#", l10n("failedTransferSayBlownLabel"));
				HTMLNode list = div.addChild("ul");
				for(PeerNode pn: nodesSayBlownFailedTransfer) {
					list.addChild("li", pn.userToString() + " (" + pn.getPeer() + ")");
				}
			}

			return div;
		}

		private String l10n(String key) {
			return NodeL10n.getBase().getString("PeersSayKeyBlownAlert." + key);
		}

		private String l10n(String key, String pattern, String value) {
			return NodeL10n.getBase().getString("PeersSayKeyBlownAlert." + key, pattern, value);
		}

		@Override
		public String getText() {
			StringBuilder sb = new StringBuilder();
			sb.append(l10n("intro")).append("\n\n");
			PeerNode[][] nodes = getNodesSayBlown();
			PeerNode[] nodesSayBlownConnected = nodes[0];
			PeerNode[] nodesSayBlownDisconnected = nodes[1];
			PeerNode[] nodesSayBlownFailedTransfer = nodes[2];

			if(nodesSayBlownConnected.length > 0)
				sb.append(l10n("fetching")).append("\n\n");
			else
				sb.append(l10n("failedFetch")).append("\n\n");

			if(nodesSayBlownConnected.length > 0) {
				sb.append(l10n("connectedSayBlownLabel")).append("\n\n");
				for(PeerNode pn: nodesSayBlownConnected) {
					sb.append(pn.userToString() + " (" + pn.getPeer() + ")").append("\n");
				}
				sb.append("\n");
			}

			if(nodesSayBlownDisconnected.length > 0) {
				sb.append(l10n("disconnectedSayBlownLabel"));

				for(PeerNode pn: nodesSayBlownDisconnected) {
					sb.append(pn.userToString() + " (" + pn.getPeer() + ")").append("\n");
				}
				sb.append("\n");
			}

			if(nodesSayBlownFailedTransfer.length > 0) {
				sb.append(l10n("failedTransferSayBlownLabel"));

				for(PeerNode pn: nodesSayBlownFailedTransfer) {
					sb.append(pn.userToString() + " (" + pn.getPeer() + ")").append('\n');
				}
				sb.append("\n");
			}

			return sb.toString();
		}

		@Override
		public String getTitle() {
			return l10n("titleWithCount", "count", Integer.toString(nodesSayKeyRevoked.size()));
		}

		@Override
		public void isValid(boolean validity) {
			// Do nothing
		}

		@Override
		public boolean isValid() {
			if(updateManager.isBlown()) return false;
			return mightBeRevoked();
		}
		
		@Override
		public String getShortText() {
			return l10n("short");
		}
	}

	public PeerNode[][] getNodesSayBlown() {
		List<PeerNode> nodesConnectedSayRevoked = new ArrayList<PeerNode>();
		List<PeerNode> nodesDisconnectedSayRevoked = new ArrayList<PeerNode>();
		List<PeerNode> nodesFailedSayRevoked = new ArrayList<PeerNode>();
		synchronized(this) {
			PeerNode[] nodesSayRevoked = nodesSayKeyRevoked.toArray(new PeerNode[nodesSayKeyRevoked.size()]);
			for(PeerNode pn: nodesSayRevoked) {
				if(nodesSayKeyRevokedFailedTransfer.contains(pn))
					nodesFailedSayRevoked.add(pn);
				else
					nodesConnectedSayRevoked.add(pn);
			}
		}
		for(int i = 0; i < nodesConnectedSayRevoked.size(); i++) {
			PeerNode pn = nodesConnectedSayRevoked.get(i);
			if(!pn.isConnected()) {
				nodesDisconnectedSayRevoked.add(pn);
				nodesConnectedSayRevoked.remove(i);
				i--;
				continue;
			}
		}
		return new PeerNode[][]{
				nodesConnectedSayRevoked.toArray(new PeerNode[nodesConnectedSayRevoked.size()]),
				nodesDisconnectedSayRevoked.toArray(new PeerNode[nodesDisconnectedSayRevoked.size()]),
				nodesFailedSayRevoked.toArray(new PeerNode[nodesFailedSayRevoked.size()]),
			};
	}

	/**
	 * A peer node requests us to send the binary blob of the revocation key.
	 * @param m The message requesting the transfer.
	 * @param source The node requesting the transfer.
	 * @return True if we handled the message (i.e. always).
	 */
	public boolean handleRequestRevocation(Message m, final PeerNode source) {
		// Do we have the data?

		final RandomAccessBuffer data = updateManager.revocationChecker.getBlobBuffer();

		if(data == null) {
			Logger.normal(this, "Peer " + source + " asked us for the blob file for the revocation key but we don't have it!");
			// Probably a race condition on reconnect, hopefully we'll be asked again
			return true;
		}

		final long uid = m.getLong(DMT.UID);

		final PartiallyReceivedBulk prb;
		long length;
		length = data.size();
		prb = new PartiallyReceivedBulk(updateManager.node.getUSM(), length,
		        Node.PACKET_SIZE, data, true);

		final BulkTransmitter bt;
		try {
			bt = new BulkTransmitter(prb, source, uid, false, updateManager.ctr, true);
		} catch(DisconnectedException e) {
			Logger.error(this, "Peer " + source + " asked us for the blob file for the revocation key, then disconnected: " + e, e);
			data.close();
			return true;
		}

		final Runnable r = new Runnable() {

			@Override
			public void run() {
				try {
					if(!bt.send())
						Logger.error(this, "Failed to send revocation key blob to " + source.userToString() + " : " + bt.getCancelReason());
					else
						Logger.normal(this, "Sent revocation key blob to " + source.userToString());
				} catch (DisconnectedException e) {
					// Not much we can do here either.
					Logger.warning(this, "Failed to send revocation key blob (disconnected) to " + source.userToString() + " : " + bt.getCancelReason());
				} finally {
					data.close();
				}
			}
		};

		Message msg = DMT.createUOMSendingRevocation(uid, length, updateManager.getRevocationURI().toString());

		try {
			source.sendAsync(msg, new AsyncMessageCallback() {

				@Override
				public void acknowledged() {
					if(logMINOR)
						Logger.minor(this, "Sending data...");
					// Send the data
					updateManager.node.executor.execute(r, "Revocation key send for " + uid + " to " + source.userToString());
				}

				@Override
				public void disconnected() {
					// Argh
					Logger.error(this, "Peer " + source + " asked us for the blob file for the revocation key, then disconnected when we tried to send the UOMSendingRevocation");
				}

				@Override
				public void fatalError() {
					// Argh
					Logger.error(this, "Peer " + source + " asked us for the blob file for the revocation key, then got a fatal error when we tried to send the UOMSendingRevocation");
				}

				@Override
				public void sent() {
					if(logMINOR)
						Logger.minor(this, "Message sent, data soon");
				}

				@Override
				public String toString() {
					return super.toString() + "(" + uid + ":" + source.getPeer() + ")";
				}
			}, updateManager.ctr);
		} catch(NotConnectedException e) {
			Logger.error(this, "Peer " + source + " asked us for the blob file for the revocation key, then disconnected when we tried to send the UOMSendingRevocation: " + e, e);
			return true;
		}

		return true;
	}

	public boolean handleSendingRevocation(Message m, final PeerNode source) {
		final long uid = m.getLong(DMT.UID);
		final long length = m.getLong(DMT.FILE_LENGTH);
		String key = m.getString(DMT.REVOCATION_KEY);
		
		FreenetURI revocationURI;
		try {
			revocationURI = new FreenetURI(key);
		} catch(MalformedURLException e) {
			Logger.error(this, "Failed receiving recovation because URI not parsable: " + e + " for " + key, e);
			System.err.println("Failed receiving recovation because URI not parsable: " + e + " for " + key);
			e.printStackTrace();
			synchronized(this) {
				// Wierd case of a failed transfer
				// This is definitely not valid, don't add to nodesSayKeyRevokedFailedTransfer.
				nodesSayKeyRevoked.remove(source);
				nodesSayKeyRevokedTransferring.remove(source);
			}
			cancelSend(source, uid);
			maybeNotRevoked();
			return true;
		}

		if(!revocationURI.equals(updateManager.getRevocationURI())) {
			System.err.println("Node sending us a revocation certificate from the wrong URI:\n" +
				"Node: " + source.userToString() + "\n" +
				"Our   URI: " + updateManager.getRevocationURI() + "\n" +
				"Their URI: " + revocationURI);
			synchronized(this) {
				// Wierd case of a failed transfer
				nodesSayKeyRevoked.remove(source);
				// This is definitely not valid, don't add to nodesSayKeyRevokedFailedTransfer.
				nodesSayKeyRevokedTransferring.remove(source);
			}
			cancelSend(source, uid);
			maybeNotRevoked();
			return true;
		}
		
		if(updateManager.isBlown()) {
			if(logMINOR)
				Logger.minor(this, "Already blown, so not receiving from " + source + "(" + uid + ")");
			cancelSend(source, uid);
			return true;
		}

		if(length > NodeUpdateManager.MAX_REVOCATION_KEY_BLOB_LENGTH) {
			System.err.println("Node " + source.userToString() + " offered us a revocation certificate " + SizeUtil.formatSize(length) + " long. This is unacceptably long so we have refused the transfer. No real revocation cert would be this big.");
			Logger.error(this, "Node " + source.userToString() + " offered us a revocation certificate " + SizeUtil.formatSize(length) + " long. This is unacceptably long so we have refused the transfer. No real revocation cert would be this big.");
			synchronized(UpdateOverMandatoryManager.this) {
				nodesSayKeyRevoked.remove(source);
				nodesSayKeyRevokedTransferring.remove(source);
			}
			cancelSend(source, uid);
			maybeNotRevoked();
			return true;
		}
		
		if(length <= 0) {
			System.err.println("Revocation key is zero bytes from "+source+" - ignoring as this is almost certainly a bug or an attack, it is definitely not valid.");
			synchronized(UpdateOverMandatoryManager.this) {
				nodesSayKeyRevoked.remove(source);
				// This is almost certainly not valid, don't add to nodesSayKeyRevokedFailedTransfer.
				nodesSayKeyRevokedTransferring.remove(source);
			}
			cancelSend(source, uid);
			maybeNotRevoked();
			return true;
		}
		
		System.err.println("Transferring auto-updater revocation certificate length "+length+" from "+source);

		// Okay, we can receive it

		final File temp;

		try {
			temp = File.createTempFile("revocation-", ".fblob.tmp", updateManager.node.clientCore.getPersistentTempDir());
			temp.deleteOnExit();
		} catch(IOException e) {
			System.err.println("Cannot save revocation certificate to disk and therefore cannot fetch it from our peer!: " + e);
			e.printStackTrace();
			updateManager.blow("Cannot fetch the revocation certificate from our peer because we cannot write it to disk: " + e, true);
			cancelSend(source, uid);
			return true;
		}

		FileRandomAccessBuffer raf;
		try {
			raf = new FileRandomAccessBuffer(temp, length, false);
		} catch(FileNotFoundException e) {
			Logger.error(this, "Peer " + source + " asked us for the blob file for the revocation key, we have downloaded it but don't have the file even though we did have it when we checked!: " + e, e);
			updateManager.blow("Internal error after fetching the revocation certificate from our peer, maybe out of disk space, file disappeared "+temp+" : " + e, true);
			return true;
        } catch(IOException e) {
            Logger.error(this, "Peer " + source + " asked us for the blob file for the revocation key, we have downloaded it but now can't read the file due to a disk I/O error: " + e, e);
            updateManager.blow("Internal error after fetching the revocation certificate from our peer, maybe out of disk space or other disk I/O error, file disappeared "+temp+" : " + e, true);
            return true;
		}
		
		// It isn't starting, it's transferring.
		synchronized(this) {
			nodesSayKeyRevokedTransferring.add(source);
			nodesSayKeyRevoked.remove(source);
		}
		
		PartiallyReceivedBulk prb = new PartiallyReceivedBulk(updateManager.node.getUSM(), length,
			Node.PACKET_SIZE, raf, false);

		final BulkReceiver br = new BulkReceiver(prb, source, uid, updateManager.ctr);

		updateManager.node.executor.execute(new Runnable() {

			@Override
			public void run() {
				try {
				if(br.receive())
					// Success!
					processRevocationBlob(temp, source);
				else {
					Logger.error(this, "Failed to transfer revocation certificate from " + source);
					System.err.println("Failed to transfer revocation certificate from " + source);
					source.failedRevocationTransfer();
					int count = source.countFailedRevocationTransfers();
					boolean retry = count < 3;
					synchronized(UpdateOverMandatoryManager.this) {
						nodesSayKeyRevokedFailedTransfer.add(source);
						nodesSayKeyRevokedTransferring.remove(source);
						if(retry) {
							if(nodesSayKeyRevoked.contains(source))
								retry = false;
							else
								nodesSayKeyRevoked.add(source);
						}
					}
					maybeNotRevoked();
					if(retry) tryFetchRevocation(source);
				}
				} catch (Throwable t) {
					Logger.error(this, "Caught error while transferring revocation certificate from "+source+" : "+t, t);
					System.err.println("Peer "+source+" said that the revocation key has been blown, but we got an internal error while transferring it:");
					t.printStackTrace();
					updateManager.blow("Internal error while fetching the revocation certificate from our peer "+source+" : "+t, true);
					synchronized(UpdateOverMandatoryManager.this) {
						nodesSayKeyRevokedTransferring.remove(source);
					}
				}
			}
		}, "Revocation key receive for " + uid + " from " + source.userToString());

		return true;
	}

	protected void maybeNotRevoked() {
		synchronized(this) {
			if(!updateManager.peersSayBlown()) return;
			if(mightBeRevoked()) return;
			updateManager.notPeerClaimsKeyBlown();
		}
	}

	private boolean mightBeRevoked() {
		PeerNode[] started;
		PeerNode[] transferring;
		synchronized(this) {
			started = nodesSayKeyRevoked.toArray(new PeerNode[nodesSayKeyRevoked.size()]);
			transferring = nodesSayKeyRevokedTransferring.toArray(new PeerNode[nodesSayKeyRevokedTransferring.size()]);
		}
		// If a peer is not connected, ignore it.
		// If a peer has already tried 3 times to send the revocation cert, ignore it,
		// because it is probably evil.
		for(PeerNode peer : started) {
			if(!peer.isConnected()) continue;
			if(peer.countFailedRevocationTransfers() > 3) continue;
			return true;
		}
		for(PeerNode peer : transferring) {
			if(!peer.isConnected()) continue;
			if(peer.countFailedRevocationTransfers() > 3) continue;
			return true;
		}
		return false;
	}

	void processRevocationBlob(final File temp, PeerNode source) {
		processRevocationBlob(new FileBucket(temp, true, false, false, true), source.userToString(), false);
	}
	
	/**
	 * Process a binary blob for a revocation certificate (the revocation key).
	 * @param temp The file it was written to.
	 */
	void processRevocationBlob(final Bucket temp, final String source, final boolean fromDisk) {

		SimpleBlockSet blocks = new SimpleBlockSet();

		DataInputStream dis = null;
		try {
			dis = new DataInputStream(temp.getInputStream());
			BinaryBlob.readBinaryBlob(dis, blocks, true);
		} catch(FileNotFoundException e) {
			Logger.error(this, "Somebody deleted " + temp + " ? We lost the revocation certificate from " + source + "!");
			System.err.println("Somebody deleted " + temp + " ? We lost the revocation certificate from " + source + "!");
			if(!fromDisk)
				updateManager.blow("Somebody deleted " + temp + " ? We lost the revocation certificate from " + source + "!", true);
			return;
		} catch (EOFException e) {
			Logger.error(this, "Peer " + source + " sent us an invalid revocation certificate! (data too short, might be truncated): " + e + " (data in " + temp + ")", e);
			System.err.println("Peer " + source + " sent us an invalid revocation certificate! (data too short, might be truncated): " + e + " (data in " + temp + ")");
			// Probably malicious, might just be buggy, either way, it's not blown
			e.printStackTrace();
			// FIXME file will be kept until exit for debugging purposes
			return;
		} catch(BinaryBlobFormatException e) {
			Logger.error(this, "Peer " + source + " sent us an invalid revocation certificate!: " + e + " (data in " + temp + ")", e);
			System.err.println("Peer " + source + " sent us an invalid revocation certificate!: " + e + " (data in " + temp + ")");
			// Probably malicious, might just be buggy, either way, it's not blown
			e.printStackTrace();
			// FIXME file will be kept until exit for debugging purposes
			return;
		} catch(IOException e) {
			Logger.error(this, "Could not read revocation cert from temp file " + temp + " from node " + source + " ! : "+e, e);
			System.err.println("Could not read revocation cert from temp file " + temp + " from node " + source + " ! : "+e);
			e.printStackTrace();
			if(!fromDisk)
				updateManager.blow("Could not read revocation cert from temp file " + temp + " from node " + source + " ! : "+e, true);
			// FIXME will be kept until exit for debugging purposes
			return;
		} finally {
			if(dis != null)
				try {
					dis.close();
				} catch(IOException e) {
					// Ignore
				}
		}

		// Fetch our revocation key from the datastore plus the binary blob

		FetchContext seedContext = updateManager.node.clientCore.makeClient((short) 0, false).getFetchContext();
		FetchContext tempContext = new FetchContext(seedContext, FetchContext.IDENTICAL_MASK, true, blocks);
		// If it is too big, we get a TOO_BIG. This is fatal so we will blow, which is the right thing as it means the top block is valid.
		tempContext.maxOutputLength = NodeUpdateManager.MAX_REVOCATION_KEY_LENGTH;
		tempContext.maxTempLength = NodeUpdateManager.MAX_REVOCATION_KEY_TEMP_LENGTH;
		tempContext.localRequestOnly = true;

		final ArrayBucket cleanedBlob = new ArrayBucket();

		ClientGetCallback myCallback = new ClientGetCallback() {

			@Override
			public void onFailure(FetchException e, ClientGetter state) {
				if(e.mode == FetchExceptionMode.CANCELLED) {
					// Eh?
					Logger.error(this, "Cancelled fetch from store/blob of revocation certificate from " + source);
					System.err.println("Cancelled fetch from store/blob of revocation certificate from " + source + " to " + temp + " - please report to developers");
				// Probably best to keep files around for now.
				} else if(e.isFatal()) {
					// Blown: somebody inserted a revocation message, but it was corrupt as inserted
					// However it had valid signatures etc.

					System.err.println("Got revocation certificate from " + source + " (fatal error i.e. someone with the key inserted bad data) : "+e);
					// Blow the update, and propagate the revocation certificate.
					updateManager.revocationChecker.onFailure(e, cleanedBlob);
					// Don't delete it if it's from disk, as it's already in the right place.
					if(!fromDisk)
						temp.free();

					insertBlob(updateManager.revocationChecker.getBlobBucket(), "revocation", RequestStarter.INTERACTIVE_PRIORITY_CLASS);
				} else {
					String message = "Failed to fetch revocation certificate from blob from " +
						source + " : "+e+
						(fromDisk ? " : did you change the revocation key?" : 
							" : this is almost certainly bogus i.e. the auto-update is fine but the node is broken.");
					Logger.error(this, message);
					System.err.println(message);
					// This is almost certainly bogus.
					// Delete it, even if it's fromDisk.
					temp.free();
					cleanedBlob.free();
				}
			}

			@Override
			public void onSuccess(FetchResult result, ClientGetter state) {
				System.err.println("Got revocation certificate from " + source);
				updateManager.revocationChecker.onSuccess(result, cleanedBlob);
				if(!fromDisk)
					temp.free();
				insertBlob(updateManager.revocationChecker.getBlobBucket(), "revocation", RequestStarter.INTERACTIVE_PRIORITY_CLASS);
			}
			
            @Override
            public void onResume(ClientContext context) {
                // Not persistent.
            }
            
            @Override
            public RequestClient getRequestClient() {
                return UpdateOverMandatoryManager.this;
            }
		};

		ClientGetter cg = new ClientGetter(myCallback,
			updateManager.getRevocationURI(), tempContext, (short) 0, null, new BinaryBlobWriter(cleanedBlob), null);

		try {
			updateManager.node.clientCore.clientContext.start(cg);
		} catch(FetchException e1) {
			System.err.println("Failed to decode UOM blob: " + e1);
			e1.printStackTrace();
			myCallback.onFailure(e1, cg);
		} catch (PersistenceDisabledException e) {
			// Impossible
		}

	}

	protected void insertBlob(final RandomAccessBucket bucket, final String type, short priority) {
		ClientPutCallback callback = new ClientPutCallback() {

			@Override
			public void onFailure(InsertException e, BaseClientPutter state) {
				Logger.error(this, "Failed to insert "+type+" binary blob: " + e, e);
			}
			
			@Override
			public void onFetchable(BaseClientPutter state) {
				// Ignore
			}
			
			@Override
			public void onGeneratedURI(FreenetURI uri, BaseClientPutter state) {
				// Ignore
			}
			
			@Override
			public void onSuccess(BaseClientPutter state) {
				// All done. Cool.
				Logger.normal(this, "Inserted "+type+" binary blob");
			}

			@Override
			public void onGeneratedMetadata(Bucket metadata,
					BaseClientPutter state) {
				Logger.error(this, "Got onGeneratedMetadata inserting blob from "+state, new Exception("error"));
				metadata.free();
			}

            @Override
            public void onResume(ClientContext context) {
                // Not persistent.
            }
            
            @Override
            public RequestClient getRequestClient() {
                return UpdateOverMandatoryManager.this;
            }

		};
		// We are inserting a binary blob so we don't need to worry about CompatibilityMode etc.
		InsertContext ctx = updateManager.node.clientCore.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, false).getInsertContext(true);
		ClientPutter putter = new ClientPutter(callback, bucket,
			FreenetURI.EMPTY_CHK_URI, null, ctx,
			priority, false, null, true, null, -1);
		try {
			updateManager.node.clientCore.clientContext.start(putter);
		} catch(InsertException e1) {
			Logger.error(this, "Failed to start insert of "+type+" binary blob: " + e1, e1);
		} catch (PersistenceDisabledException e) {
			// Impossible
		}
	}

	private void cancelSend(PeerNode source, long uid) {
		Message msg = DMT.createFNPBulkReceiveAborted(uid);
		try {
			source.sendAsync(msg, null, updateManager.ctr);
		} catch(NotConnectedException e1) {
			// Ignore
		}
	}

	public void killAlert() {
		updateManager.node.clientCore.alerts.unregister(alert);
	}

	public void handleRequestJar(Message m, final PeerNode source) {
		final String name = "main";
		
		Message msg;
		final BulkTransmitter bt;
		final FileRandomAccessBuffer raf;

		if (source.isOpennet() && updateManager.dontAllowUOM()) {
			Logger.normal(this, "Peer " + source
					+ " asked us for the blob file for " + name
					+ "; We are a seenode, so we ignore it!");
			return;
		}
		// Do we have the data?

		File data;
		int version;
		FreenetURI uri;
		if (source.getVersionNumber() < NodeUpdateManager.TRANSITION_VERSION) {
		    data = updateManager.getTransitionMainBlob();
		    version = NodeUpdateManager.TRANSITION_VERSION;
		    uri = NodeUpdateManager.transitionMainJarURIAsUSK;
		} else {
		    data = updateManager.getCurrentVersionBlobFile();
		    version = Version.buildNumber();
            uri = updateManager.getURI();
		}
		
		if(data == null) {
			Logger.normal(this, "Peer " + source + " asked us for the blob file for the "+name+" jar but we don't have it!");
			// Probably a race condition on reconnect, hopefully we'll be asked again
			return;
		}

		final long uid = m.getLong(DMT.UID);

		if(!source.sendingUOMJar(false)) {
			Logger.error(this, "Peer "+source+" asked for UOM main jar twice");
			return;
		}
		
		try {
			
			try {
				raf = new FileRandomAccessBuffer(data, true);
			} catch(FileNotFoundException e) {
				Logger.error(this, "Peer " + source + " asked us for the blob file for the "+name+" jar, we have downloaded it but don't have the file even though we did have it when we checked!: " + e, e);
				return;
            } catch(IOException e) {
                Logger.error(this, "Peer " + source + " asked us for the blob file for the "+name+" jar, we have downloaded it but can't read the file due to a disk I/O error: " + e, e);
                return;
			}
			
			final PartiallyReceivedBulk prb;
			long length;
			length = raf.size();
			prb = new PartiallyReceivedBulk(updateManager.node.getUSM(), length,
			        Node.PACKET_SIZE, raf, true);
			
			try {
				bt = new BulkTransmitter(prb, source, uid, false, updateManager.ctr, true);
			} catch(DisconnectedException e) {
				Logger.error(this, "Peer " + source + " asked us for the blob file for the "+name+" jar, then disconnected: " + e, e);
				raf.close();
				return;
			}
			
			msg =
				DMT.createUOMSendingMainJar(uid, length, uri.toString(), version);
			
		} catch (RuntimeException e) {
			source.finishedSendingUOMJar(false);
			throw e;
		} catch (Error e) {
			source.finishedSendingUOMJar(false);
			throw e;
		}
		
		final Runnable r = new Runnable() {

			@Override
			public void run() {
				try {
					if(!bt.send())
						Logger.error(this, "Failed to send "+name+" jar blob to " + source.userToString() + " : " + bt.getCancelReason());
					else
						Logger.normal(this, "Sent "+name+" jar blob to " + source.userToString());
					raf.close();
				} catch (DisconnectedException e) {
					// Not much we can do.
				} finally {
					source.finishedSendingUOMJar(false);
					raf.close();
				}
			}
		};

		try {
			source.sendAsync(msg, new AsyncMessageCallback() {

				@Override
				public void acknowledged() {
					if(logMINOR)
						Logger.minor(this, "Sending data...");
					// Send the data

					updateManager.node.executor.execute(r, name+" jar send for " + uid + " to " + source.userToString());
				}

				@Override
				public void disconnected() {
					// Argh
					Logger.error(this, "Peer " + source + " asked us for the blob file for the "+name+" jar, then disconnected when we tried to send the UOMSendingMainJar");
					source.finishedSendingUOMJar(false);
				}

				@Override
				public void fatalError() {
					// Argh
					Logger.error(this, "Peer " + source + " asked us for the blob file for the "+name+" jar, then got a fatal error when we tried to send the UOMSendingMainJar");
					source.finishedSendingUOMJar(false);
				}

				@Override
				public void sent() {
					if(logMINOR)
						Logger.minor(this, "Message sent, data soon");
				}

				@Override
				public String toString() {
					return super.toString() + "(" + uid + ":" + source.getPeer() + ")";
				}
			}, updateManager.ctr);
		} catch(NotConnectedException e) {
			Logger.error(this, "Peer " + source + " asked us for the blob file for the "+name+" jar, then disconnected when we tried to send the UOMSendingMainJar: " + e, e);
			return;
		} catch (RuntimeException e) {
			source.finishedSendingUOMJar(false);
			throw e;
		} catch (Error e) {
			source.finishedSendingUOMJar(false);
			throw e;
		}

	}
	
	public boolean handleSendingMain(Message m, final PeerNode source) {
		final long uid = m.getLong(DMT.UID);
		final long length = m.getLong(DMT.FILE_LENGTH);
		String key = m.getString(DMT.MAIN_JAR_KEY);
		final int version = m.getInt(DMT.MAIN_JAR_VERSION);
		final FreenetURI jarURI;
		try {
			jarURI = new FreenetURI(key).setSuggestedEdition(version);
		} catch(MalformedURLException e) {
			Logger.error(this, "Failed receiving main jar " + version + " because URI not parsable: " + e + " for " + key, e);
			System.err.println("Failed receiving main jar " + version + " because URI not parsable: " + e + " for " + key);
			e.printStackTrace();
			cancelSend(source, uid);
			synchronized(this) {
				this.nodesAskedSendMainJar.remove(source);
			}
			return true;
		}

		if(!jarURI.equals(updateManager.getURI().setSuggestedEdition(version))) {
			System.err.println("Node sending us a main jar update (" + version + ") from the wrong URI:\n" +
				"Node: " + source.userToString() + "\n" +
				"Our   URI: " + updateManager.getURI() + "\n" +
				"Their URI: " + jarURI);
			cancelSend(source, uid);
			synchronized(this) {
				this.nodesAskedSendMainJar.remove(source);
			}
			return true;
		}

		if(updateManager.isBlown()) {
			if(logMINOR)
				Logger.minor(this, "Key blown, so not receiving main jar from " + source + "(" + uid + ")");
			cancelSend(source, uid);
			synchronized(this) {
				this.nodesAskedSendMainJar.remove(source);
			}
			return true;
		}

		if(length > NodeUpdateManager.MAX_MAIN_JAR_LENGTH) {
			System.err.println("Node " + source.userToString() + " offered us a main jar (" + version + ") " + SizeUtil.formatSize(length) + " long. This is unacceptably long so we have refused the transfer.");
			Logger.error(this, "Node " + source.userToString() + " offered us a main jar (" + version + ") " + SizeUtil.formatSize(length) + " long. This is unacceptably long so we have refused the transfer.");
			// If the transfer fails, we don't try again.
			cancelSend(source, uid);
			synchronized(this) {
				this.nodesAskedSendMainJar.remove(source);
			}
			return true;
		}

		// Okay, we can receive it
		System.out.println("Receiving main jar "+version+" from "+source.userToString());

		final File temp;

		try {
			temp = File.createTempFile("main-", ".fblob.tmp", updateManager.node.clientCore.getPersistentTempDir());
			temp.deleteOnExit();
		} catch(IOException e) {
			System.err.println("Cannot save new main jar to disk and therefore cannot fetch it from our peer!: " + e);
			e.printStackTrace();
			cancelSend(source, uid);
			synchronized(this) {
				this.nodesAskedSendMainJar.remove(source);
			}
			return true;
		}

		FileRandomAccessBuffer raf;
		try {
			raf = new FileRandomAccessBuffer(temp, length, false);
		} catch(IOException e) {
			Logger.error(this, "Peer " + source + " sending us a main jar binary blob, but we " +
					((e instanceof FileNotFoundException) ? "lost the temp file " : "cannot read the temp file ") + temp + " : " + e, e);
			synchronized(this) {
				this.nodesAskedSendMainJar.remove(source);
			}
			return true;
		}

		PartiallyReceivedBulk prb = new PartiallyReceivedBulk(updateManager.node.getUSM(), length,
			Node.PACKET_SIZE, raf, false);

		final BulkReceiver br = new BulkReceiver(prb, source, uid, updateManager.ctr);

		updateManager.node.executor.execute(new Runnable() {

			@Override
			public void run() {
				boolean success = false;
				try {
					synchronized(UpdateOverMandatoryManager.class) {
						nodesAskedSendMainJar.remove(source);
						nodesSendingMainJar.add(source);
					}
					success = br.receive();
					if(success)
						// Success!
						processMainJarBlob(temp, source, version, jarURI);
					else {
						Logger.error(this, "Failed to transfer main jar " + version + " from " + source);
						System.err.println("Failed to transfer main jar " + version + " from " + source);
						temp.delete();
					}
				} finally {
					synchronized(UpdateOverMandatoryManager.class) {
						nodesSendingMainJar.remove(source);
						if(success)
							nodesSentMainJar.add(source);
					}
				}
			}
		}, "Main jar (" + version + ") receive for " + uid + " from " + source.userToString());

		return true;
	}

	protected void processMainJarBlob(final File temp, final PeerNode source, final int version, FreenetURI uri) {
		SimpleBlockSet blocks = new SimpleBlockSet();
		final String toString = source == null ? "(local)" : source.userToString();

		DataInputStream dis = null;
		try {
			dis = new DataInputStream(new BufferedInputStream(new FileInputStream(temp)));
			BinaryBlob.readBinaryBlob(dis, blocks, true);
		} catch(FileNotFoundException e) {
			Logger.error(this, "Somebody deleted " + temp + " ? We lost the main jar (" + version + ") from " + toString + "!");
			System.err.println("Somebody deleted " + temp + " ? We lost the main jar (" + version + ") from " + toString + "!");
			return;
		} catch(IOException e) {
			Logger.error(this, "Could not read main jar (" + version + ") from temp file " + temp + " from node " + toString + " !");
			System.err.println("Could not read main jar (" + version + ") from temp file " + temp + " from node " + toString + " !");
			// FIXME will be kept until exit for debugging purposes
			return;
		} catch(BinaryBlobFormatException e) {
			Logger.error(this, "Peer " + toString + " sent us an invalid main jar (" + version + ")!: " + e, e);
			System.err.println("Peer " + toString + " sent us an invalid main jar (" + version + ")!: " + e);
			e.printStackTrace();
			// FIXME will be kept until exit for debugging purposes
			return;
		} finally {
			if(dis != null)
				try {
					dis.close();
				} catch(IOException e) {
					// Ignore
				}
		}

		// Fetch the jar from the datastore plus the binary blob

		FetchContext seedContext = updateManager.node.clientCore.makeClient((short) 0, false).getFetchContext();
		FetchContext tempContext = new FetchContext(seedContext, FetchContext.IDENTICAL_MASK, true, blocks);
		tempContext.localRequestOnly = true;

		File f;
		FileBucket b = null;
		try {
			f = File.createTempFile("main-", ".fblob.tmp", updateManager.node.clientCore.getPersistentTempDir());
			f.deleteOnExit();
			b = new FileBucket(f, false, false, true, true);
		} catch(IOException e) {
			Logger.error(this, "Cannot share main jar from " + toString + " with our peers because cannot write the cleaned version to disk: " + e, e);
			System.err.println("Cannot share main jar from " + toString + " with our peers because cannot write the cleaned version to disk: " + e);
			e.printStackTrace();
			b = null;
			f = null;
		}
		final FileBucket cleanedBlob = b;
		final File cleanedBlobFile = f;

		ClientGetCallback myCallback = new ClientGetCallback() {

			@Override
			public void onFailure(FetchException e, ClientGetter state) {
				if(e.mode == FetchExceptionMode.CANCELLED) {
					// Eh?
					Logger.error(this, "Cancelled fetch from store/blob of main jar (" + version + ") from " + toString);
					System.err.println("Cancelled fetch from store/blob of main jar (" + version + ") from " + toString + " to " + temp + " - please report to developers");
				// Probably best to keep files around for now.
				} else if(e.newURI != null) {
					temp.delete();
					Logger.error(this, "URI changed fetching main jar "+version+" from "+toString);
					System.out.println("URI changed fetching main jar "+version+" from "+toString);
				} else if(e.isFatal()) {
					// Bogus as inserted. Ignore.
					temp.delete();
					Logger.error(this, "Failed to fetch main jar " + version + " from " + toString + " : fatal error (update was probably inserted badly): " + e, e);
					System.err.println("Failed to fetch main jar " + version + " from " + toString + " : fatal error (update was probably inserted badly): " + e);
				} else {
					Logger.error(this, "Failed to fetch main jar " + version + " from blob from " + toString);
					System.err.println("Failed to fetch main jar " + version + " from blob from " + toString);
				}
			}

			@Override
			public void onSuccess(FetchResult result, ClientGetter state) {
				System.err.println("Got main jar version " + version + " from " + toString);
				if(result.size() == 0) {
					System.err.println("Ignoring because 0 bytes long");
					return;
				}

				NodeUpdater mainUpdater = updateManager.getMainUpdater();
				if(mainUpdater == null) {
					System.err.println("Not updating because updater is disabled!");
					return;
				}
				mainUpdater.onSuccess(result, cleanedBlobFile, version);
				temp.delete();
				
				maybeInsertMainJar(mainUpdater, source, version);
			}

            @Override
            public void onResume(ClientContext context) {
                // Not persistent.
            }
            
            @Override
            public RequestClient getRequestClient() {
                return UpdateOverMandatoryManager.this;
            }

		};

		ClientGetter cg = new ClientGetter(myCallback,
			uri, tempContext, (short) 0, null, new BinaryBlobWriter(cleanedBlob), null);

		try {
			updateManager.node.clientCore.clientContext.start(cg);
		} catch(FetchException e1) {
			myCallback.onFailure(e1, cg);
		} catch (PersistenceDisabledException e) {
			// Impossible
		}

	}

	/** Maybe insert the main jar blob. If so, compute the appropriate priority. */
	protected void maybeInsertMainJar(NodeUpdater mainUpdater, PeerNode source, int version) {
	    short priority = RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS;
	    if(source != null) {
	        // We got it from another node.
	        priority = RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
	    } else if(updateManager.node.lastVersion > 0 && 
	            updateManager.node.lastVersion != version) {
	        // We just restarted after updating.
	        priority = RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS;
	    } else if(updateManager.node.fastWeakRandom.nextInt(RANDOM_INSERT_BLOB) != 0) {
	        // 1 in RANDOM_INSERT_BLOB chance of inserting anyway at bulk priority.
	        return;
	    }
        insertBlob(mainUpdater.getBlobBucket(version), "main jar", priority);
    }

    protected boolean removeOldTempFiles() {
		File oldTempFilesPeerDir = updateManager.node.clientCore.getPersistentTempDir();
		if(!oldTempFilesPeerDir.exists())
			return false;
		if(!oldTempFilesPeerDir.isDirectory()) {
			Logger.error(this, "Persistent temporary files location is not a directory: " + oldTempFilesPeerDir.getPath());
			return false;
		}

		boolean gotError = false;
		File[] oldTempFiles = oldTempFilesPeerDir.listFiles(new FileFilter() {

			private final int lastGoodMainBuildNumber = Version.lastGoodBuild();

			@Override
			public boolean accept(File file) {
				String fileName = file.getName();

				if(fileName.startsWith("revocation-") && fileName.endsWith(".fblob.tmp"))
					return true;

				String buildNumberStr;
				int buildNumber;
				Matcher mainBuildNumberMatcher = mainBuildNumberPattern.matcher(fileName);
				Matcher mainTempBuildNumberMatcher = mainTempBuildNumberPattern.matcher(fileName);
				Matcher revocationTempBuildNumberMatcher = revocationTempBuildNumberPattern.matcher(fileName);

				if(mainBuildNumberMatcher.matches()) {
					try {
					buildNumberStr = mainBuildNumberMatcher.group(1);
					buildNumber = Integer.parseInt(buildNumberStr);
					if(buildNumber < lastGoodMainBuildNumber)
						return true;
					} catch (NumberFormatException e) {
						Logger.error(this, "Wierd file in persistent temp: "+fileName);
						return false;
					}
				} else if(mainTempBuildNumberMatcher.matches() || revocationTempBuildNumberMatcher.matches()) {
					// Temporary file, can be deleted
					return true;
				}

				return false;
			}
		});

		for(File fileToDelete : oldTempFiles) {
			String fileToDeleteName = fileToDelete.getName();
			if(!fileToDelete.delete()) {
				if(fileToDelete.exists())
					Logger.error(this, "Cannot delete temporary persistent file " + fileToDeleteName + " even though it exists: must be TOO persistent :)");
				else
					Logger.normal(this, "Temporary persistent file does not exist when deleting: " + fileToDeleteName);
				gotError = true;
			}
		}

		return !gotError;
	}

	@Override
	public boolean persistent() {
		return false;
	}

	public void disconnected(PeerNode pn) {
		synchronized(this) {
			nodesSayKeyRevoked.remove(pn);
			nodesSayKeyRevokedFailedTransfer.remove(pn);
			nodesSayKeyRevokedTransferring.remove(pn);
			nodesOfferedMainJar.remove(pn);
			allNodesOfferedMainJar.remove(pn);
			nodesSentMainJar.remove(pn);
			nodesAskedSendMainJar.remove(pn);
			nodesSendingMainJar.remove(pn);
		}
		maybeNotRevoked();
	}

	public boolean fetchingFromTwo() {
		synchronized(this) {
			return (this.nodesSendingMainJar.size()) >= 2;
		}
	}

	@Override
	public boolean realTimeFlag() {
		return false;
	}

	public boolean isFetchingMain() {
		synchronized(this) {
			return nodesSendingMainJar.size() > 0;
		}
	}

	public void addDependency(byte[] expectedHash, File filename) {
		if(logMINOR) Logger.minor(this, "Add dependency: "+filename+" for "+HexUtil.bytesToHex(expectedHash));
		synchronized(dependencies) {
			dependencies.put(new ShortBuffer(expectedHash), filename);
		}
	}
	
	static final int MAX_TRANSFERS_PER_PEER = 2;

	public void handleFetchDependency(Message m, final PeerNode source) {
		File data;
		final ShortBuffer buf = (ShortBuffer)m.getObject(DMT.EXPECTED_HASH);
		long length = m.getLong(DMT.FILE_LENGTH);
		long uid = m.getLong(DMT.UID);
		synchronized(dependencies) {
			data = dependencies.get(buf);
		}
		boolean fail = !incrementDependencies(source);
		FileRandomAccessBuffer raf;
		final BulkTransmitter bt;
		
		try {
			if(data != null)
				raf = new FileRandomAccessBuffer(data, true);
			else {
				Logger.error(this, "Dependency with hash "+HexUtil.bytesToHex(buf.getData())+" not found!");
				fail = true;
				raf = null;
			}
		} catch(IOException e) {
			Logger.error(this, "Peer " + source + " asked us for the dependency with hash "+HexUtil.bytesToHex(buf.getData())+" jar, we have downloaded it but " +
			        (e instanceof FileNotFoundException ? "don't have the file" : "can't read the file")+
			        " even though we did have it when we checked!: " + e, e);
			raf = null;
			fail = true;
		}
		
		PartiallyReceivedBulk prb;
		if(raf != null) {
		    long thisLength = raf.size();
		    prb = new PartiallyReceivedBulk(updateManager.node.getUSM(), thisLength,
		            Node.PACKET_SIZE, raf, true);
		    if(length != thisLength) {
		        fail = true;
		    }
		} else {
		    prb = new PartiallyReceivedBulk(updateManager.node.getUSM(), 0,
		            Node.PACKET_SIZE, new ByteArrayRandomAccessBuffer(new byte[0]), true);
		    fail = true;
		}
		
		try {
			bt = new BulkTransmitter(prb, source, uid, false, updateManager.ctr, true);
		} catch(DisconnectedException e) {
			Logger.error(this, "Peer " + source + " asked us for the dependency with hash "+HexUtil.bytesToHex(buf.getData())+" jar then disconnected", e);
			raf.close();
			decrementDependencies(source);
			return;
		}
		
		if(fail) {
			cancelSend(source, uid);
			decrementDependencies(source);
		} else {
			final FileRandomAccessBuffer r = raf;
			updateManager.node.executor.execute(new Runnable() {
				
				@Override
				public void run() {
					source.incrementUOMSends();
					try {
						bt.send();
					} catch (DisconnectedException e) {
						Logger.normal(this, "Disconnected while sending dependency with hash "+HexUtil.bytesToHex(buf.getData())+" to "+source);
					} finally {
						source.decrementUOMSends();
						decrementDependencies(source);
						r.close();
					}
				}
				
			});
		}
	}
	
	private void decrementDependencies(PeerNode source) {
		synchronized(peersFetchingDependencies) {
			Integer x = peersFetchingDependencies.get(source);
			if(x == null) {
				Logger.error(this, "Inconsistent dependency counting? Should not be null for "+source);
			} else if(x == 1) {
				peersFetchingDependencies.remove(source);
			} else if(x <= 0) {
				Logger.error(this, "Inconsistent dependency counting? Counter is "+x+" for "+source);
				peersFetchingDependencies.remove(source);
			} else {
				peersFetchingDependencies.put(source, x-1);
			}
		}
	}

	/** @return False if we cannot accept any more transfers from this node. 
	 * True to accept the transfer. */
	private boolean incrementDependencies(PeerNode source) {
		synchronized(peersFetchingDependencies) {
			Integer x = peersFetchingDependencies.get(source);
			if(x == null) x = 0;
			x++;
			if(x > MAX_TRANSFERS_PER_PEER) {
				Logger.normal(this, "Too many dependency transfers for peer "+source+" - rejecting");
				return false;
			}
			else peersFetchingDependencies.put(source, x);
			return true;
		}
	}

	boolean fetchingUOM() {
		return fetchingUOM;
	}
	
	public interface UOMDependencyFetcherCallback {
		void onSuccess();
	}

	/** Try to fetch a dependency by hash.
	 * @param expectedHash The hash of the expected file. Will be checked.
	 * @param size The length of the expected file.
	 * @param saveTo The file will be overwritten only if the download is
	 * successful and the hash is correct.
	 * @param uomDependencyFetchCallback Callback to call when done.
	 */
	public UOMDependencyFetcher fetchDependency(byte[] expectedHash, long size, File saveTo, 
	        boolean executable, UOMDependencyFetcherCallback cb) {
		final UOMDependencyFetcher f = new UOMDependencyFetcher(expectedHash, size, saveTo, executable, cb);
		synchronized(this) {
			dependencyFetchers.put(f.expectedHashBuffer, f);
		}
		this.updateManager.node.executor.execute(new Runnable() {

			@Override
			public void run() {
				f.start();
			}
			
		});
		f.start();
		return f;
	}
	
	protected void startSomeDependencyFetchers() {
		UOMDependencyFetcher[] fetchers;
		synchronized(this) {
			fetchers = dependencyFetchers.values().toArray(new UOMDependencyFetcher[dependencyFetchers.size()]);
		}
		for(UOMDependencyFetcher f : fetchers) {
			f.start();
		}
	}
	
	/** A download succeeded from a peer. Reconsider all the other downloads
	 * that failed from it. E.g. when we have one darknet connection and a
	 * transfer fails due to a transfer glitch. */
	protected void peerMaybeFreeAllSlots(PeerNode fetchFrom) {
		UOMDependencyFetcher[] fetchers;
		synchronized(this) {
			fetchers = dependencyFetchers.values().toArray(new UOMDependencyFetcher[dependencyFetchers.size()]);
		}
		for(UOMDependencyFetcher f : fetchers) {
			f.peerMaybeFreeSlots(fetchFrom);
		}
	}

	class UOMDependencyFetcher {
		
		final byte[] expectedHash;
		final ShortBuffer expectedHashBuffer;
		final long size;
		final File saveTo;
		final boolean executable;
		private boolean completed;
		private final UOMDependencyFetcherCallback cb;
		private final WeakHashSet<PeerNode> peersFailed;
		private final HashSet<PeerNode> peersFetching;
		
		private UOMDependencyFetcher(byte[] expectedHash, long size, File saveTo, boolean executable, UOMDependencyFetcherCallback callback) {
			this.expectedHash = expectedHash;
			expectedHashBuffer = new ShortBuffer(expectedHash);
			this.size = size;
			this.executable = executable;
			this.saveTo = saveTo;
			cb = callback;
			peersFailed = new WeakHashSet<PeerNode>();
			peersFetching = new HashSet<PeerNode>();
		}
		
		/** If a transfer has failed from this peer, retry it. */
		private void peerMaybeFreeSlots(PeerNode fetchFrom) {
			synchronized(this) {
				if(!peersFailed.remove(fetchFrom)) return;
				if(completed) return;
			}
			start();
		}

		private boolean maybeFetch() {
			boolean tryEverything = false;
			PeerNode chosen = null;
			while(true) {
				synchronized(this) {
					if(peersFetching.size() >= MAX_NODES_SENDING_JAR) {
						if(logMINOR) Logger.minor(this, "Already fetching jar from 2 peers "+peersFetching);
						return false;
					}
					if(completed) return false;
				}
				HashSet<PeerNode> uomPeers;
				synchronized(UpdateOverMandatoryManager.this) {
					uomPeers = new HashSet<PeerNode>(nodesSentMainJar);
				}
				chosen = chooseRandomPeer(uomPeers);
				if(chosen != null) break;
				synchronized(UpdateOverMandatoryManager.this) {
					uomPeers = new HashSet<PeerNode>(nodesSendingMainJar);
				}
				chosen = chooseRandomPeer(uomPeers);
				if(chosen != null) break;
				synchronized(UpdateOverMandatoryManager.this) {
					uomPeers = new HashSet<PeerNode>(allNodesOfferedMainJar);
				}
				chosen = chooseRandomPeer(uomPeers);
				if(chosen != null) break;
				if(tryEverything) {
					Logger.minor(this, "Could not find a peer to send request to for "+saveTo);
					return false;
				}
				synchronized(this) {
					if(peersFailed.size() != 0) {
						System.out.println("UOM trying peers which have failed downloads for "+saveTo.getName()+" because nowhere else to go ...");
						peersFailed.clear();
						tryEverything = true;
					}
				}
				if(!tryEverything) {
					Logger.minor(this, "Could not find a peer to send request to for "+saveTo);
					return false;
				}
			}
			if(chosen == null) return false;
			
			final PeerNode fetchFrom = chosen;
			updateManager.node.executor.execute(new Runnable() {

				@Override
				public void run() {
					boolean failed = false;
					File tmp = null;
					FileRandomAccessBuffer raf = null;
					try {
						System.out.println("Fetching "+saveTo+" from "+fetchFrom);
						long uid = updateManager.node.fastWeakRandom.nextLong();
						fetchFrom.sendAsync(DMT.createUOMFetchDependency(uid, expectedHash, size), null, updateManager.ctr);
						tmp = FileUtil.createTempFile(saveTo.getName(), NodeUpdateManager.TEMP_FILE_SUFFIX, saveTo.getParentFile());
						raf = new FileRandomAccessBuffer(tmp, size, false);
						PartiallyReceivedBulk prb = 
							new PartiallyReceivedBulk(updateManager.node.getUSM(), size,
								Node.PACKET_SIZE, raf, false);
						BulkReceiver br = new BulkReceiver(prb, fetchFrom, uid, updateManager.ctr);
						failed = !br.receive();
						raf.close();
						raf = null;
						if(!failed) {
							// Check the hash.
							if(MainJarDependenciesChecker.validFile(tmp, expectedHash, size, executable)) {
								if(FileUtil.renameTo(tmp, saveTo)) {
									synchronized(UOMDependencyFetcher.this) {
										if(completed) return;
										completed = true;
									}
									synchronized(UpdateOverMandatoryManager.this) {
										dependencyFetchers.remove(expectedHashBuffer);
									}
									cb.onSuccess();
								} else {
									synchronized(UOMDependencyFetcher.this) {
										if(completed) return;
									}
									failed = true;
									System.err.println("Update failing: Saved dependency to "+tmp+" for "+saveTo+" but cannot rename it! Permissions problems?");
								}
								peerMaybeFreeAllSlots(fetchFrom);
							} else {
								synchronized(UOMDependencyFetcher.this) {
									if(completed) return;
								}
								failed = true;
								System.err.println("Update failing: Downloaded file "+saveTo+" from "+fetchFrom+" but file does not match expected hash.");
								// Wrong length -> transfer would have failed.
							}
						} else {
							System.out.println("Download failed: "+saveTo+" from "+fetchFrom);
							failed = true;
						}
					} catch (NotConnectedException e) {
						// Not counting this as a failure.
						System.out.println("Disconnected while downloading "+saveTo+" from "+fetchFrom);
					} catch (IOException e) {
						// This isn't their fault either.
						// User might be able to understand and fix this.
						System.out.println("IOException while downloading "+saveTo+" from "+fetchFrom+" : "+e);
						Logger.error(this, "IOException while downloading "+saveTo+" from "+fetchFrom+" : "+e, e);
					} catch (RuntimeException e) {
						Logger.error(this, "Caught fetching "+saveTo+" from "+fetchFrom +" : "+e, e);
						System.err.println("Fetch failed due to internal error (bug or severe local problem?): "+e);
						e.printStackTrace();
					} catch (Error e) {
						Logger.error(this, "Caught fetching "+saveTo+" from "+fetchFrom +" : "+e, e);
						System.err.println("Fetch failed due to internal error (bug or severe local problem?): "+e);
						e.printStackTrace();
					} finally {
						boolean connected = fetchFrom.isConnected();
						boolean addFailed = failed && connected;
						synchronized(UOMDependencyFetcher.this) {
							if(addFailed)
								peersFailed.add(fetchFrom);
							peersFetching.remove(fetchFrom);
						}
						Closer.close(raf);
						if(tmp != null) 
							tmp.delete();
						if(failed) {
							start();
							if(fetchFrom.isConnected() && fetchFrom.isDarknet()) {
							    // Darknet peers only: Try again in an hour.
							    // On opennet we'll just keep announcing until we succeed.
							    updateManager.node.getTicker().queueTimedJob(new Runnable() {

                                    @Override
                                    public void run() {
                                        peerMaybeFreeSlots(fetchFrom);
                                    }
							        
							    }, TimeUnit.HOURS.toMillis(1));
							}
						}
					}
				}
				
			});
			return true;
		}
		
		private synchronized PeerNode chooseRandomPeer(HashSet<PeerNode> uomPeers) {
			if(completed) return null;
			if(peersFetching.size() >= MAX_NODES_SENDING_JAR) {
				if(logMINOR) Logger.minor(this, "Already fetching jar from 2 peers "+peersFetching);
				return null;
			}
			if(logMINOR) Logger.minor(this, "Trying to choose peer from "+uomPeers.size());
			ArrayList<PeerNode> notTried = null;
			for(PeerNode pn : uomPeers) {
				if(peersFetching.contains(pn)) {
					if(logMINOR) Logger.minor(this, "Already fetching from "+pn);
					continue;
				}
				if(peersFailed.contains(pn)) {
					if(logMINOR) Logger.minor(this, "Peer already failed for "+saveTo+" : "+pn);
					continue;
				}
				if(!pn.isConnected()) {
					if(logMINOR) Logger.minor(this, "Peer not connected: "+pn);
					continue;
				}
				if(notTried == null) notTried = new ArrayList<PeerNode>();
				notTried.add(pn);
			}
			if(notTried == null) {
				if(logMINOR) Logger.minor(this, "No peers to ask for "+saveTo);
				return null;
			}
			PeerNode fetchFrom = notTried.get(updateManager.node.fastWeakRandom.nextInt(notTried.size()));
			peersFetching.add(fetchFrom);
			return fetchFrom;
		}

		void start() {
			while(maybeFetch());
		}

		public void cancel() {
			synchronized(this) {
				completed = true;
			}
			synchronized(UpdateOverMandatoryManager.this) {
				dependencyFetchers.remove(expectedHashBuffer);
			}
		}
		
	}

}
