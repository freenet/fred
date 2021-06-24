package freenet.clients.http;

import java.io.File;
import java.io.IOException;
import java.lang.management.*;
import java.net.URI;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.*;

import freenet.client.HighLevelSimpleClient;
import freenet.client.async.PersistenceDisabledException;
import freenet.clients.fcp.DownloadRequestStatus;
import freenet.clients.fcp.FCPServer;
import freenet.clients.fcp.RequestStatus;
import freenet.clients.fcp.UploadDirRequestStatus;
import freenet.clients.fcp.UploadFileRequestStatus;
import freenet.config.SubConfig;
import freenet.io.xfer.BlockReceiver;
import freenet.io.xfer.BlockTransmitter;
import freenet.l10n.BaseL10n;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.NodeStarter;
import freenet.node.NodeStats;
import freenet.node.OpennetManager;
import freenet.node.PeerManager;
import freenet.node.PeerNodeStatus;
import freenet.node.RequestTracker;
import freenet.node.Version;
import freenet.node.diagnostics.*;
import freenet.node.diagnostics.threads.*;
import freenet.node.stats.DataStoreInstanceType;
import freenet.node.stats.DataStoreStats;
import freenet.node.stats.StatsNotAvailableException;
import freenet.node.stats.StoreAccessStats;
import freenet.pluginmanager.PluginInfoWrapper;
import freenet.pluginmanager.PluginManager;
import freenet.support.BandwidthStatsContainer;
import freenet.support.SizeUtil;
import freenet.support.api.HTTPRequest;

public class DiagnosticToadlet extends Toadlet {

	private final Node node;
	private final NodeClientCore core;
	private final NodeStats stats;
	private final PeerManager peers;
	private final NumberFormat thousandPoint = NumberFormat.getInstance();
	private final FCPServer fcp;
	//private final DecimalFormat fix1p1 = new DecimalFormat("0.0");
	//private final DecimalFormat fix1p2 = new DecimalFormat("0.00");
	private final DecimalFormat fix1p4 = new DecimalFormat("0.0000");
	//private final DecimalFormat fix1p6sci = new DecimalFormat("0.######E0");
	private final DecimalFormat fix3p1pct = new DecimalFormat("##0.0%");
	//private final DecimalFormat fix3p1US = new DecimalFormat("##0.0", new DecimalFormatSymbols(Locale.US));
	//private final DecimalFormat fix3pctUS = new DecimalFormat("##0%", new DecimalFormatSymbols(Locale.US));
	//private final DecimalFormat fix6p6 = new DecimalFormat("#####0.0#####");
	public static final String TOADLET_URL = "/diagnostic/";
	private final BaseL10n baseL10n;

	protected DiagnosticToadlet(Node n, NodeClientCore core, FCPServer fcp, HighLevelSimpleClient client) {
		super(client);
		this.node = n;
		this.core = core;
		this.fcp = fcp;
		stats = node.nodeStats;
		peers = node.peers;
		/* copied from NodeL10n constructor. */
		baseL10n = new BaseL10n("freenet/l10n/", "freenet.l10n.${lang}.properties", new File(".").getPath()+File.separator+"freenet.l10n.${lang}.override.properties", BaseL10n.LANGUAGE.ENGLISH);
	}

	public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {
        if(!ctx.checkFullAccess(this))
            return;

		node.clientCore.bandwidthStatsPutter.updateData(node);

		final SubConfig nodeConfig = node.config.get("node");

		StringBuilder textBuilder = new StringBuilder();

		// Synchronize to avoid problems with DecimalFormat.
		synchronized(this) {
		// drawNodeVersionBox
		textBuilder.append("Freenet Version:\n");
		textBuilder.append(baseL10n.getString("WelcomeToadlet.version", new String[] { "fullVersion", "build", "rev" },
				new String[] { Version.publicVersion(), Integer.toString(Version.buildNumber()), Version.cvsRevision() })).append("\n");
		textBuilder.append(baseL10n.getString("WelcomeToadlet.extVersion", new String[] { "build", "rev" },
				new String[] { Integer.toString(NodeStarter.extBuildNumber), NodeStarter.extRevisionNumber }));
		textBuilder.append("\n");

		// drawNodeVersionBox
		textBuilder.append("System Information:\n");
		Runtime rt = Runtime.getRuntime();
		long freeMemory = rt.freeMemory();
		long totalMemory = rt.totalMemory();
		long maxMemory = rt.maxMemory();
		long usedJavaMem = totalMemory - freeMemory;
		long allocatedJavaMem = totalMemory;
		long maxJavaMem = maxMemory;
		int availableCpus = rt.availableProcessors();
		int threadCount = stats.getActiveThreadCount();
			textBuilder.append(l10n("usedMemory", "memory", SizeUtil.formatSize(usedJavaMem, true))).append("\n");
			textBuilder.append(l10n("allocMemory", "memory", SizeUtil.formatSize(allocatedJavaMem, true))).append("\n");
			textBuilder.append(l10n("maxMemory", "memory", SizeUtil.formatSize(maxJavaMem, true))).append("\n");
			textBuilder.append(l10n("threads", new String[] { "running", "max" },
				new String[] { thousandPoint.format(threadCount), Integer.toString(stats.getThreadLimit()) })).append("\n");
			textBuilder.append(l10n("cpus", "count", Integer.toString(availableCpus))).append("\n");
			textBuilder.append(l10n("javaVersion", "version", System.getProperty("java.version"))).append("\n");
			textBuilder.append(l10n("jvmVendor", "vendor", System.getProperty("java.vendor"))).append("\n");
			textBuilder.append(l10n("jvmName", "name", System.getProperty("java.vm.name"))).append("\n");
			textBuilder.append(l10n("jvmVersion", "version", System.getProperty("java.vm.version"))).append("\n");
		textBuilder.append(l10n("osName", "name", System.getProperty("os.name"))).append("\n");
		textBuilder.append(l10n("osVersion", "version", System.getProperty("os.version"))).append("\n");
		textBuilder.append(l10n("osArch", "arch", System.getProperty("os.arch"))).append("\n");
		textBuilder.append("\n");

		// drawStoreSizeBox
		textBuilder.append("Store Size:\n");
		Map<DataStoreInstanceType, DataStoreStats> storeStats = node.getDataStoreStats();
		for (Map.Entry<DataStoreInstanceType, DataStoreStats> entry : storeStats.entrySet()) {
			DataStoreInstanceType instance = entry.getKey();
			DataStoreStats stats = entry.getValue();
			StoreAccessStats sessionAccess = stats.getSessionAccessStats();
			StoreAccessStats totalAccess;
			try {
				totalAccess = stats.getTotalAccessStats();
			} catch (StatsNotAvailableException e) {
				totalAccess = null;
			}
			textBuilder.append(l10n(instance.store.name())).append(": (").append(l10n(instance.key.name())).append(")\n");
			textBuilder.append("  ").append(l10n("keys")).append(": ").append(thousandPoint.format(stats.keys())).append("\n");
			textBuilder.append("  ").append(l10n("capacity")).append(": ").append(thousandPoint.format(stats.capacity())).append("\n");
			textBuilder.append("  ").append(l10n("datasize")).append(": ").append(SizeUtil.formatSize(stats.dataSize())).append("\n");
			textBuilder.append("  ").append(l10n("utilization")).append(": ").append(fix3p1pct.format(stats.utilization())).append("\n");
			textBuilder.append("  ").append(l10n("readRequests")).append(": ").append(thousandPoint.format(sessionAccess.readRequests()) +
					(totalAccess == null ? "" : (" ("+thousandPoint.format(totalAccess.readRequests())+")"))).append("\n");
			textBuilder.append("  ").append(l10n("successfulReads")).append(": ").append(thousandPoint.format(sessionAccess.successfulReads()) +
					(totalAccess == null ? "" : (" ("+thousandPoint.format(totalAccess.successfulReads())+")"))).append("\n");
			try {
				textBuilder.append(fix1p4.format(sessionAccess.successRate())).append("%");
				if(totalAccess != null) {
					try {
						textBuilder.append(" (").append(fix1p4.format(totalAccess.successRate())).append("%)");
					} catch (StatsNotAvailableException e) {
						// Ignore
					}
				}
				textBuilder.append("\n");
			} catch (StatsNotAvailableException e) {
			}
		}
		textBuilder.append("\n");

		// drawActivity
		textBuilder.append("Activity:\n");
		RequestTracker tracker = node.tracker;
		int numLocalCHKInserts = tracker.getNumLocalCHKInserts();
		int numRemoteCHKInserts = tracker.getNumRemoteCHKInserts();
		int numLocalSSKInserts = tracker.getNumLocalSSKInserts();
		int numRemoteSSKInserts = tracker.getNumRemoteSSKInserts();
		int numLocalCHKRequests = tracker.getNumLocalCHKRequests();
		int numRemoteCHKRequests = tracker.getNumRemoteCHKRequests();
		int numLocalSSKRequests = tracker.getNumLocalSSKRequests();
		int numRemoteSSKRequests = tracker.getNumRemoteSSKRequests();
		int numTransferringRequests = tracker.getNumTransferringRequestSenders();
		int numTransferringRequestHandlers = tracker.getNumTransferringRequestHandlers();
		int numCHKOfferReplys = tracker.getNumCHKOfferReplies();
		int numSSKOfferReplys = tracker.getNumSSKOfferReplies();
		int numCHKRequests = numLocalCHKRequests + numRemoteCHKRequests;
		int numSSKRequests = numLocalSSKRequests + numRemoteSSKRequests;
		int numCHKInserts = numLocalCHKInserts + numRemoteCHKInserts;
		int numSSKInserts = numLocalSSKInserts + numRemoteSSKInserts;
		if ((numTransferringRequests == 0) &&
				(numCHKRequests == 0) && (numSSKRequests == 0) &&
				(numCHKInserts == 0) && (numSSKInserts == 0) &&
				(numTransferringRequestHandlers == 0) && 
				(numCHKOfferReplys == 0) && (numSSKOfferReplys == 0)) {
			textBuilder.append(l10n("noRequests")).append("\n");
		} else {
			if (numCHKInserts > 0 || numSSKInserts > 0) {
				textBuilder.append(l10n("activityInserts",
						new String[] { "CHKhandlers", "SSKhandlers", "local" } ,
						new String[] { Integer.toString(numCHKInserts), Integer.toString(numSSKInserts), Integer.toString(numLocalCHKInserts)+"/" + Integer.toString(numLocalSSKInserts)})
						+ "\n");
			}
			if (numCHKRequests > 0 || numSSKRequests > 0) {
				textBuilder.append(l10n("activityRequests",
						new String[] { "CHKhandlers", "SSKhandlers", "local" } ,
						new String[] { Integer.toString(numCHKRequests), Integer.toString(numSSKRequests), Integer.toString(numLocalCHKRequests)+"/" + Integer.toString(numLocalSSKRequests)})
						+ "\n");
			}
			if (numTransferringRequests > 0 || numTransferringRequestHandlers > 0) {
				textBuilder.append(l10n("transferringRequests",
						new String[] { "senders", "receivers", "turtles" }, new String[] { Integer.toString(numTransferringRequests), Integer.toString(numTransferringRequestHandlers), "0"})
						+ "\n");
			}
			if (numCHKOfferReplys > 0 || numSSKOfferReplys > 0) {
				textBuilder.append(l10n("offerReplys",
						new String[] { "chk", "ssk" }, new String[] { Integer.toString(numCHKOfferReplys), Integer.toString(numSSKOfferReplys) })
						+ "\n");
			}
			textBuilder.append(l10n("runningBlockTransfers",
					new String[] { "sends", "receives" }, new String[] { Integer.toString(BlockTransmitter.getRunningSends()), Integer.toString(BlockReceiver.getRunningReceives()) })
					+ "\n");
		}
		textBuilder.append("\n");

		// drawPeerStatsBox
		textBuilder.append("Peer Statistics:\n");
		PeerNodeStatus[] peerNodeStatuses = peers.getPeerNodeStatuses(true);
		Arrays.sort(peerNodeStatuses, new Comparator<PeerNodeStatus>() {
			@Override
			public int compare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
				int statusDifference = firstNode.getStatusValue() - secondNode.getStatusValue();
				if (statusDifference != 0) {
					return statusDifference;
				}
				return 0;
			}
		});
		int numberOfConnected = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONNECTED);
		int numberOfRoutingBackedOff = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF);
		int numberOfTooNew = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_NEW);
		int numberOfTooOld = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_OLD);
		int numberOfDisconnected = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISCONNECTED);
		int numberOfNeverConnected = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED);
		int numberOfDisabled = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISABLED);
		int numberOfBursting = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_BURSTING);
		int numberOfListening = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTENING);
		int numberOfListenOnly = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTEN_ONLY);
		int numberOfSeedServers = getCountSeedServers(peerNodeStatuses);
		int numberOfSeedClients = getCountSeedClients(peerNodeStatuses);
		int numberOfRoutingDisabled = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_ROUTING_DISABLED);
		int numberOfClockProblem = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CLOCK_PROBLEM);
		int numberOfConnError = getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONN_ERROR);
		int numberOfDisconnecting = PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISCONNECTING);
		int numberOfNoLoadStats = PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_NO_LOAD_STATS);
		if (numberOfConnected > 0)
			textBuilder.append(l10nDark("connectedShort")).append(": ").append(numberOfConnected).append("\n");
		if (numberOfRoutingBackedOff > 0)
			textBuilder.append(l10nDark("backedOffShort")).append(": ").append(numberOfRoutingBackedOff).append("\n");
		if (numberOfTooNew > 0)
			textBuilder.append(l10nDark("tooNewShort")).append(": ").append(numberOfTooNew).append("\n");
		if (numberOfTooOld > 0)
			textBuilder.append(l10nDark("tooOldShort")).append(": ").append(numberOfTooOld).append("\n");
		if (numberOfDisconnected > 0)
			textBuilder.append(l10nDark("notConnectedShort")).append(": ").append(numberOfDisconnected).append("\n");
		if (numberOfNeverConnected > 0)
			textBuilder.append(l10nDark("neverConnectedShort")).append(": ").append(numberOfNeverConnected).append("\n");
		if (numberOfDisabled > 0)
			textBuilder.append(l10nDark("disabledShort")).append(": ").append(numberOfDisabled).append("\n");
		if (numberOfBursting > 0)
			textBuilder.append(l10nDark("burstingShort")).append(": ").append(numberOfBursting).append("\n");
		if (numberOfListening > 0)
			textBuilder.append(l10nDark("listeningShort")).append(": ").append(numberOfListening).append("\n");
		if (numberOfListenOnly > 0)
			textBuilder.append(l10nDark("listenOnlyShort")).append(": ").append(numberOfListenOnly).append("\n");
		if (numberOfClockProblem > 0)
			textBuilder.append(l10nDark("clockProblemShort")).append(": ").append(numberOfClockProblem).append("\n");
		if (numberOfConnError > 0)
			textBuilder.append(l10nDark("connErrorShort")).append(": ").append(numberOfConnError).append("\n");
		if (numberOfDisconnecting > 0)
			textBuilder.append(l10nDark("disconnectingShort")).append(": ").append(numberOfDisconnecting).append("\n");
		if (numberOfSeedServers > 0)
			textBuilder.append(l10nDark("seedServersShort")).append(": ").append(numberOfSeedServers).append("\n");
		if (numberOfSeedClients > 0)
			textBuilder.append(l10nDark("seedClientsShort")).append(": ").append(numberOfSeedClients).append("\n");
		if (numberOfRoutingDisabled > 0)
			textBuilder.append(l10nDark("routingDisabledShort")).append(": ").append(numberOfRoutingDisabled).append("\n");
		if (numberOfNoLoadStats > 0)
			textBuilder.append(l10nDark("noLoadStatsShort")).append(": ").append(numberOfNoLoadStats).append("\n");
		OpennetManager om = node.getOpennet();
		if(om != null) {
			textBuilder.append(l10n("maxTotalPeers")+": "+om.getNumberOfConnectedPeersToAimIncludingDarknet()).append("\n");
			textBuilder.append(l10n("maxOpennetPeers")+": "+om.getNumberOfConnectedPeersToAim()).append("\n");
		}
		textBuilder.append("\n");

		// drawBandwidth
		textBuilder.append("Bandwidth:\n");
		long[] total = node.collector.getTotalIO();
		if(total[0] == 0 || total[1] == 0)
			textBuilder.append("bandwidth error\n");
		else  {
			final long now = System.currentTimeMillis();
			final long nodeUptimeSeconds = (now - node.startupTime) / 1000;
			long total_output_rate = (total[0]) / nodeUptimeSeconds;
			long total_input_rate = (total[1]) / nodeUptimeSeconds;
			long totalPayload = node.getTotalPayloadSent();
			long total_payload_rate = totalPayload / nodeUptimeSeconds;
			if(node.clientCore == null) throw new NullPointerException();
			BandwidthStatsContainer stats = node.clientCore.bandwidthStatsPutter.getLatestBWData();
			if(stats == null) throw new NullPointerException();
			long overall_total_out = stats.totalBytesOut;
			long overall_total_in = stats.totalBytesIn;
			int percent = (int) (100 * totalPayload / total[0]);
			long[] rate = node.nodeStats.getNodeIOStats();
			long delta = (rate[5] - rate[2]) / 1000;
			if(delta > 0) {
				long output_rate = (rate[3] - rate[0]) / delta;
				long input_rate = (rate[4] - rate[1]) / delta;
				int outputBandwidthLimit = nodeConfig.getInt("outputBandwidthLimit");
				int inputBandwidthLimit = nodeConfig.getInt("inputBandwidthLimit");
				if(inputBandwidthLimit == -1) {
					inputBandwidthLimit = outputBandwidthLimit * 4;
				}
				textBuilder.append(l10n("inputRate", new String[] { "rate", "max" }, new String[] { SizeUtil.formatSize(input_rate, true), SizeUtil.formatSize(inputBandwidthLimit, true) })).append("\n");
				textBuilder.append(l10n("outputRate", new String[] { "rate", "max" }, new String[] { SizeUtil.formatSize(output_rate, true), SizeUtil.formatSize(outputBandwidthLimit, true) })).append("\n");
			}
			textBuilder.append(l10n("totalInputSession", new String[] { "total", "rate" }, new String[] { SizeUtil.formatSize(total[1], true), SizeUtil.formatSize(total_input_rate, true) })).append("\n");
			textBuilder.append(l10n("totalOutputSession", new String[] { "total", "rate" }, new String[] { SizeUtil.formatSize(total[0], true), SizeUtil.formatSize(total_output_rate, true) } )).append("\n");
			textBuilder.append(l10n("payloadOutput", new String[] { "total", "rate", "percent" }, new String[] { SizeUtil.formatSize(totalPayload, true), SizeUtil.formatSize(total_payload_rate, true), Integer.toString(percent) } )).append("\n");
			textBuilder.append(l10n("totalInput", new String[] { "total" }, new String[] { SizeUtil.formatSize(overall_total_in, true) })).append("\n");
			textBuilder.append(l10n("totalOutput", new String[] { "total" }, new String[] { SizeUtil.formatSize(overall_total_out, true) } )).append("\n");
			long totalBytesSentCHKRequests = node.nodeStats.getCHKRequestTotalBytesSent();
			long totalBytesSentSSKRequests = node.nodeStats.getSSKRequestTotalBytesSent();
			long totalBytesSentCHKInserts = node.nodeStats.getCHKInsertTotalBytesSent();
			long totalBytesSentSSKInserts = node.nodeStats.getSSKInsertTotalBytesSent();
			long totalBytesSentOfferedKeys = node.nodeStats.getOfferedKeysTotalBytesSent();
			long totalBytesSendOffers = node.nodeStats.getOffersSentBytesSent();
			long totalBytesSentSwapOutput = node.nodeStats.getSwappingTotalBytesSent();
			long totalBytesSentAuth = node.nodeStats.getTotalAuthBytesSent();
			long totalBytesSentAckOnly = node.nodeStats.getNotificationOnlyPacketsSentBytes();
			long totalBytesSentResends = node.nodeStats.getResendBytesSent();
			long totalBytesSentUOM = node.nodeStats.getUOMBytesSent();
			long totalBytesSentAnnounce = node.nodeStats.getAnnounceBytesSent();
			long totalBytesSentAnnouncePayload = node.nodeStats.getAnnounceBytesPayloadSent();
			long totalBytesSentRoutingStatus = node.nodeStats.getRoutingStatusBytes();
			long totalBytesSentNetworkColoring = node.nodeStats.getNetworkColoringSentBytes();
			long totalBytesSentPing = node.nodeStats.getPingSentBytes();
			long totalBytesSentProbeRequest = node.nodeStats.getProbeRequestSentBytes();
			long totalBytesSentRouted = node.nodeStats.getRoutedMessageSentBytes();
			long totalBytesSentDisconn = node.nodeStats.getDisconnBytesSent();
			long totalBytesSentInitial = node.nodeStats.getInitialMessagesBytesSent();
			long totalBytesSentChangedIP = node.nodeStats.getChangedIPBytesSent();
			long totalBytesSentNodeToNode = node.nodeStats.getNodeToNodeBytesSent();
			long totalBytesSentAllocationNotices = node.nodeStats.getAllocationNoticesBytesSent();
			long totalBytesSentFOAF = node.nodeStats.getFOAFBytesSent();
			long totalBytesSentRemaining = total[0] - 
				(totalPayload + totalBytesSentCHKRequests + totalBytesSentSSKRequests +
				totalBytesSentCHKInserts + totalBytesSentSSKInserts +
				totalBytesSentOfferedKeys + totalBytesSendOffers + totalBytesSentSwapOutput + 
				totalBytesSentAuth + totalBytesSentAckOnly + totalBytesSentResends +
				totalBytesSentUOM + totalBytesSentAnnounce + 
				totalBytesSentRoutingStatus + totalBytesSentNetworkColoring + totalBytesSentPing +
				totalBytesSentProbeRequest + totalBytesSentRouted + totalBytesSentDisconn + 
				totalBytesSentInitial + totalBytesSentChangedIP + totalBytesSentNodeToNode + totalBytesSentAllocationNotices + totalBytesSentFOAF);
			textBuilder.append(l10n("requestOutput", new String[] { "chk", "ssk" }, new String[] { SizeUtil.formatSize(totalBytesSentCHKRequests, true), SizeUtil.formatSize(totalBytesSentSSKRequests, true) })).append("\n");
			textBuilder.append(l10n("insertOutput", new String[] { "chk", "ssk" }, new String[] { SizeUtil.formatSize(totalBytesSentCHKInserts, true), SizeUtil.formatSize(totalBytesSentSSKInserts, true) })).append("\n");
			textBuilder.append(l10n("offeredKeyOutput", new String[] { "total", "offered" }, new String[] { SizeUtil.formatSize(totalBytesSentOfferedKeys, true), SizeUtil.formatSize(totalBytesSendOffers, true) })).append("\n");
			textBuilder.append(l10n("swapOutput", "total", SizeUtil.formatSize(totalBytesSentSwapOutput, true))).append("\n");
			textBuilder.append(l10n("authBytes", "total", SizeUtil.formatSize(totalBytesSentAuth, true))).append("\n");
			textBuilder.append(l10n("ackOnlyBytes", "total", SizeUtil.formatSize(totalBytesSentAckOnly, true))).append("\n");
			textBuilder.append(l10n("resendBytes", new String[] { "total", "percent" }, new String[] { SizeUtil.formatSize(totalBytesSentResends, true), Long.toString((100 * totalBytesSentResends) / Math.max(1, total[0])) } )).append("\n");
			textBuilder.append(l10n("uomBytes", "total",  SizeUtil.formatSize(totalBytesSentUOM, true))).append("\n");
			textBuilder.append(l10n("announceBytes", new String[] { "total", "payload" }, new String[] { SizeUtil.formatSize(totalBytesSentAnnounce, true), SizeUtil.formatSize(totalBytesSentAnnouncePayload, true) })).append("\n");
			textBuilder.append(l10n("adminBytes", new String[] { "routingStatus", "disconn", "initial", "changedIP" }, new String[] { SizeUtil.formatSize(totalBytesSentRoutingStatus, true), SizeUtil.formatSize(totalBytesSentDisconn, true), SizeUtil.formatSize(totalBytesSentInitial, true), SizeUtil.formatSize(totalBytesSentChangedIP, true) })).append("\n");
			textBuilder.append(l10n("debuggingBytes", new String[] { "netColoring", "ping", "probe", "routed" }, new String[] { SizeUtil.formatSize(totalBytesSentNetworkColoring, true), SizeUtil.formatSize(totalBytesSentPing, true), SizeUtil.formatSize(totalBytesSentProbeRequest, true), SizeUtil.formatSize(totalBytesSentRouted, true) } )).append("\n");
			textBuilder.append(l10n("nodeToNodeBytes", "total", SizeUtil.formatSize(totalBytesSentNodeToNode, true))).append("\n");
			textBuilder.append(l10n("loadAllocationNoticesBytes", "total", SizeUtil.formatSize(totalBytesSentAllocationNotices, true))).append("\n");
			textBuilder.append(l10n("foafBytes", "total", SizeUtil.formatSize(totalBytesSentFOAF, true))).append("\n");
			textBuilder.append(l10n("unaccountedBytes", new String[] { "total", "percent" },
					new String[] { SizeUtil.formatSize(totalBytesSentRemaining, true), Integer.toString((int)(totalBytesSentRemaining*100 / total[0])) })).append("\n");
			double sentOverheadPerSecond = node.nodeStats.getSentOverheadPerSecond();
			textBuilder.append(l10n("totalOverhead", new String[] { "rate", "percent" },
					new String[] { SizeUtil.formatSize((long)sentOverheadPerSecond), Integer.toString((int)((100 * sentOverheadPerSecond) / total_output_rate)) })).append("\n");
		}
		textBuilder.append("\n");

		// showStartingPlugins
		textBuilder.append("Plugins:\n");
		PluginManager pm = node.pluginManager;
		if (!pm.getPlugins().isEmpty()) {
			textBuilder.append(baseL10n.getString("PluginToadlet.pluginListTitle")).append("\n");
			for(PluginInfoWrapper pi: pm.getPlugins()) {
				long ver = pi.getPluginLongVersion();
				if (ver != -1)
					textBuilder.append(pi.getFilename()).append(" (").append(pi.getPluginClassName()).append(") - " ).append(pi.getPluginVersion()+ " ("+ver+")").append(" ").append(pi.getThreadName()).append("\n");
				else
					textBuilder.append(pi.getFilename()).append(" (").append(pi.getPluginClassName()).append(") - ").append(pi.getPluginVersion()).append(" ").append(pi.getThreadName()).append("\n");
			}
		}
		textBuilder.append("\n");

		// handleGetInner
		textBuilder.append("Queue:\n");
		try {
			RequestStatus[] reqs = fcp.getGlobalRequests();
			if(reqs.length < 1)
				textBuilder.append(baseL10n.getString("QueueToadlet.globalQueueIsEmpty")).append("\n");
			else {
				long totalQueuedDownload = 0;
				long totalQueuedUpload = 0;
				for(RequestStatus req: reqs) {
					if(req instanceof DownloadRequestStatus) {
						totalQueuedDownload++;
					} else if(req instanceof UploadFileRequestStatus) {
						totalQueuedUpload++;
					} else if(req instanceof UploadDirRequestStatus) {
						totalQueuedUpload++;
					}
				}
				textBuilder.append("Downloads Queued: ").append(totalQueuedDownload).append(" (").append(totalQueuedDownload).append(")\n");
				textBuilder.append("Uploads Queued: ").append(totalQueuedUpload).append(" (").append(totalQueuedUpload).append(")\n");
			}
		} catch (PersistenceDisabledException e) {
			textBuilder.append("DatabaseDisabledException\n");
		}
		textBuilder.append("\n");

		// drawThreadPriorityStatsBox
		if (node.isNodeDiagnosticsEnabled()) {
			textBuilder.append(threadsStats());
			textBuilder.append("\n");
		}
		}

		this.writeTextReply(ctx, 200, "OK", textBuilder.toString());
	}

	/**
	 * Retrieves ThreadDiagnostics (through NodeDiagnostics) to display
	 * thread information (id, name, group, % cpu, etc).
	 * @return Thread information in tab separated format.
	 */
	private StringBuilder threadsStats() {
		StringBuilder sb = new StringBuilder();

		ThreadDiagnostics threadDiagnostics = node
			.getNodeDiagnostics()
			.getThreadDiagnostics();

		NodeThreadSnapshot threadSnapshot = threadDiagnostics.getThreadSnapshot();

		double wallTime = TimeUnit.MILLISECONDS.toNanos(
			threadSnapshot.getInterval()
		);

		List<NodeThreadInfo> threads = threadSnapshot.getThreads();
		threads.sort(Comparator.comparing(NodeThreadInfo::getCpuTime).reversed());

		sb.append(String.format("Threads (%d):%n", threads.size()));

		// ID, Name, Priority, Group (system, main), Status, % CPU
		sb.append(
			String.format(
				"%5s %-60s %5s %10s %-20s %-5s%n",
				"ID",
				"Name",
				"Prio.",
				"Group",
				"Status",
				"% CPU"
			)
		);

		for (NodeThreadInfo thread : threads) {
			String line = String.format(
				"%5s %-60s %5s %10s %-20s %.2f%n",
				thread.getId(),
				thread.getName().substring(0, Math.min(60, thread.getName().length())),
				thread.getPrio(),
				thread.getGroupName().substring(0, Math.min(10, thread.getGroupName().length())),
				thread.getState(),
				thread.getCpuTime() / wallTime * 100
			);
			sb.append(line);
		}

		return sb;
	}

	private int getPeerStatusCount(PeerNodeStatus[] peerNodeStatuses, int status) {
		int count = 0;
		for (PeerNodeStatus peerNodeStatus: peerNodeStatuses) {
			if(!peerNodeStatus.recordStatus())
				continue;
			if (peerNodeStatus.getStatusValue() == status) {
				count++;
			}
		}
		return count;
	}
	
	private int getCountSeedServers(PeerNodeStatus[] peerNodeStatuses) {
		int count = 0;
		for (PeerNodeStatus peerNodeStatus: peerNodeStatuses) {
			if(peerNodeStatus.isSeedServer()) count++;
		}
		return count;
	}

	private int getCountSeedClients(PeerNodeStatus[] peerNodeStatuses) {
		int count = 0;
		for (PeerNodeStatus peerNodeStatus: peerNodeStatuses) {
			if(peerNodeStatus.isSeedClient()) count++;
		}
		return count;
	}

	private String l10n(String key) {
		return baseL10n.getString("StatisticsToadlet."+key);
	}

	private String l10nDark(String key) {
		return baseL10n.getString("DarknetConnectionsToadlet."+key);
	}

	private String l10n(String key, String pattern, String value) {
		return baseL10n.getString("StatisticsToadlet."+key, new String[] { pattern }, new String[] { value });
	}

	private String l10n(String key, String[] patterns, String[] values) {
		return baseL10n.getString("StatisticsToadlet."+key, patterns, values);
	}

	@Override
	public String path() {
		return TOADLET_URL;
	}
}
