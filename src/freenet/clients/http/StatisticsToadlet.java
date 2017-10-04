package freenet.clients.http;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.IOException;
import java.net.URI;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.NumberFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import freenet.client.async.ClientRequester;
import freenet.client.HighLevelSimpleClient;
import freenet.config.SubConfig;
import freenet.crypt.ciphers.Rijndael;
import freenet.io.comm.IncomingPacketFilterImpl;
import freenet.io.xfer.BlockReceiver;
import freenet.io.xfer.BlockTransmitter;
import freenet.l10n.NodeL10n;
import freenet.keys.FreenetURI;
import freenet.node.Location;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.NodeStarter;
import freenet.node.NodeStats;
import freenet.node.OpennetManager;
import freenet.node.PeerManager;
import freenet.node.PeerNodeStatus;
import freenet.node.RequestClient;
import freenet.node.RequestStarterGroup;
import freenet.node.RequestTracker;
import freenet.node.Version;
import freenet.node.stats.DataStoreInstanceType;
import freenet.node.stats.DataStoreStats;
import freenet.node.stats.StatsNotAvailableException;
import freenet.node.stats.StoreAccessStats;
import freenet.support.BandwidthStatsContainer;
import freenet.support.HTMLNode;
import freenet.support.SizeUtil;
import freenet.support.TimeUtil;
import freenet.support.api.HTTPRequest;
import freenet.support.io.NativeThread;

public class StatisticsToadlet extends Toadlet {

	static final NumberFormat thousandPoint = NumberFormat.getInstance();

	private static class STMessageCount {
		public String messageName;
		public int messageCount;

		STMessageCount( String messageName, int messageCount ) {
			this.messageName = messageName;
			this.messageCount = messageCount;
		}
	}

	private final Node node;
	private final NodeClientCore core;
	private final NodeStats stats;
	private final PeerManager peers;
	private final DecimalFormat fix1p1 = new DecimalFormat("0.0");
	private final DecimalFormat fix1p2 = new DecimalFormat("0.00");
	private final DecimalFormat fix1p4 = new DecimalFormat("0.0000");
	private final DecimalFormat fix1p6sci = new DecimalFormat("0.######E0");
	private final DecimalFormat fix3p1pct = new DecimalFormat("##0.0%");
	private final DecimalFormat fix3p1US = new DecimalFormat("##0.0", new DecimalFormatSymbols(Locale.US));
	private final DecimalFormat fix3pctUS = new DecimalFormat("##0%", new DecimalFormatSymbols(Locale.US));
	private final DecimalFormat fix6p6 = new DecimalFormat("#####0.0#####");

	protected StatisticsToadlet(Node n, NodeClientCore core, HighLevelSimpleClient client) {
		super(client);
		this.node = n;
		this.core = core;
		stats = node.nodeStats;
		peers = node.peers;
	}

	/**
	 * Counts the peers in <code>peerNodes</code> that have the specified
	 * status.
	 * @param peerNodeStatuses The peer nodes' statuses
	 * @param status The status to count
	 * @return The number of peers that have the specified status.
	 */
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

	public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {
        if(!ctx.checkFullAccess(this))
            return;
        
		final SubConfig nodeConfig = node.config.get("node");
		
		final String requestPath = request.getPath().substring(path().length());

		if (requestPath.length() > 0) {
			if(requestPath.equals("requesters.html") || requestPath.equals("/requesters.html")) {
				showRequesters(ctx);
				return;
			}
		}

		node.clientCore.bandwidthStatsPutter.updateData(node);

		HTMLNode pageNode;
		
		// Synchronize to avoid problems with DecimalFormat.
		synchronized(this) {
		
		/* gather connection statistics */
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

		PageNode page = ctx.getPageMaker().getPageNode(l10n("fullTitle"), ctx);
		boolean advancedMode = ctx.isAdvancedModeEnabled();
		pageNode = page.outer;
		HTMLNode contentNode = page.content;

		// FIXME! We need some nice images
		final long now = System.currentTimeMillis();
		double myLocation = node.getLocation();
		final long nodeUptimeSeconds = (now - node.startupTime) / 1000;

		if(ctx.isAllowedFullAccess())
			contentNode.addChild(ctx.getAlertManager().createSummary());

		double swaps = node.getSwaps();
		double noSwaps = node.getNoSwaps();

		HTMLNode overviewTable = contentNode.addChild("table", "class", "column");

		HTMLNode overviewTableRow = overviewTable.addChild("tr");
		HTMLNode nextTableCell = overviewTableRow.addChild("td", "class", "first");

		// node version information box
		HTMLNode versionInfobox = nextTableCell.addChild("div", "class", "infobox");
		
		drawNodeVersionBox(versionInfobox);
		
		// jvm stats box
		HTMLNode jvmStatsInfobox = nextTableCell.addChild("div", "class", "infobox");
		
		drawJVMStatsBox(jvmStatsInfobox, advancedMode);
		
		// Statistic gathering box
		HTMLNode statGatheringContent = ctx.getPageMaker().getInfobox("#", l10n("statisticGatheringTitle"), nextTableCell, "statistics-generating", true);
		// Generate a Thread-Dump
		if(node.isUsingWrapper()){
			HTMLNode threadDumpForm = ctx.addFormChild(statGatheringContent, "/", "threadDumpForm");
			threadDumpForm.addChild("input", new String[] { "type", "name", "value" }, new String[] { "submit", "getThreadDump", l10n("threadDumpButton")});
		}
		// Get logs
		HTMLNode logsList = statGatheringContent.addChild("ul");
		if(nodeConfig.config.get("logger").getBoolean("enabled"))
			logsList.addChild("li").addChild("a", new String[]{ "href", "target"}, new String[]{ "/?latestlog", "_blank"}, l10n("getLogs"));
		logsList.addChild("li").addChild("a", "href", TranslationToadlet.TOADLET_URL+"?getOverrideTranlationFile").addChild("#", NodeL10n.getBase().getString("TranslationToadlet.downloadTranslationsFile"));
		logsList.addChild("li").addChild("a", "href", DiagnosticToadlet.TOADLET_URL).addChild("#", NodeL10n.getBase().getString("FProxyToadlet.diagnostic"));
		
		if(advancedMode) {
			// store size box
			//HTMLNode storeSizeInfobox = nextTableCell.addChild("div", "class", "infobox");
             HTMLNode storeSizeInfobox = contentNode.addChild("div","class", "infobox");
			
			drawStoreSizeBox(storeSizeInfobox, nodeUptimeSeconds);
           
			
			if(numberOfConnected + numberOfRoutingBackedOff > 0) {
				
				HTMLNode loadStatsInfobox = nextTableCell.addChild("div", "class", "infobox");
				
				drawLoadBalancingBox(loadStatsInfobox, false);
				
				loadStatsInfobox = nextTableCell.addChild("div", "class", "infobox");
				
				drawLoadBalancingBox(loadStatsInfobox, true);
				
				HTMLNode newLoadManagementBox = nextTableCell.addChild("div", "class", "infobox");
				drawNewLoadManagementBox(newLoadManagementBox);
								
				// Psuccess box
				HTMLNode successRateBox = nextTableCell.addChild("div", "class", "infobox");
				successRateBox.addChild("div", "class", "infobox-header", l10n("successRate"));
				HTMLNode successRateContent = successRateBox.addChild("div", "class", "infobox-content");
				stats.fillSuccessRateBox(successRateContent);
				
				HTMLNode timeDetailBox = nextTableCell.addChild("div", "class", "infobox");
				timeDetailBox.addChild("div", "class", "infobox-header", l10n("chkDetailTiming"));
				HTMLNode timingsContent = timeDetailBox.addChild("div", "class", "infobox-content");
				stats.fillDetailedTimingsBox(timingsContent);
				
				HTMLNode byHTLBox = nextTableCell.addChild("div", "class", "infobox");
				byHTLBox.addChild("div", "class", "infobox-header", l10n("successByHTLBulk"));
				HTMLNode byHTLContent = byHTLBox.addChild("div", "class", "infobox-content");
				stats.fillRemoteRequestHTLsBox(byHTLContent, false);
				
				byHTLBox = nextTableCell.addChild("div", "class", "infobox");
				byHTLBox.addChild("div", "class", "infobox-header", l10n("successByHTLRT"));
				byHTLContent = byHTLBox.addChild("div", "class", "infobox-content");
				stats.fillRemoteRequestHTLsBox(byHTLContent, true);
			}
		}

		if(advancedMode || numberOfConnected + numberOfRoutingBackedOff > 0) {

			// Activity box
			nextTableCell = overviewTableRow.addChild("td", "class", "last");
			HTMLNode activityInfobox = nextTableCell.addChild("div", "class", "infobox");
			
			drawActivityBox(activityInfobox, advancedMode);

			/* node status overview box */
			if(advancedMode) {
				HTMLNode overviewInfobox = nextTableCell.addChild("div", "class", "infobox");
				drawOverviewBox(overviewInfobox, nodeUptimeSeconds, node.clientCore.bandwidthStatsPutter.getLatestUptimeData().totalUptime, now, swaps, noSwaps);
			}

			// Peer statistics box
			HTMLNode peerStatsInfobox = nextTableCell.addChild("div", "class", "infobox");
			
			drawPeerStatsBox(peerStatsInfobox, advancedMode, numberOfConnected, numberOfRoutingBackedOff,
					numberOfTooNew, numberOfTooOld, numberOfDisconnected, numberOfNeverConnected, numberOfDisabled, 
					numberOfBursting, numberOfListening, numberOfListenOnly, numberOfSeedServers, numberOfSeedClients,
					numberOfRoutingDisabled, numberOfClockProblem, numberOfConnError, numberOfDisconnecting, numberOfNoLoadStats, node);

			// Bandwidth box
			HTMLNode bandwidthInfobox = nextTableCell.addChild("div", "class", "infobox");
			
			drawBandwidthBox(bandwidthInfobox, nodeUptimeSeconds, advancedMode);
		}

		if(advancedMode) {

			// Peer routing backoff reason box
			HTMLNode backoffReasonInfobox = nextTableCell.addChild("div", "class", "infobox");
			backoffReasonInfobox.addChild("div", "class", "infobox-header", "Peer Backoff");
			HTMLNode backoffReasonContent = backoffReasonInfobox.addChild("div", "class", "infobox-content");

			HTMLNode curBackoffReasonInfobox = backoffReasonContent.addChild("div", "class", "infobox");
			curBackoffReasonInfobox.addChild("div", "class", "infobox-header", "Current backoff reasons (bulk)");
			HTMLNode curBackoffReasonContent = curBackoffReasonInfobox.addChild("div", "class", "infobox-content");

			String [] routingBackoffReasons = peers.getPeerNodeRoutingBackoffReasons(false);
			if(routingBackoffReasons.length == 0) {
				curBackoffReasonContent.addChild("#", l10n("notBackedOff"));
			} else {
				HTMLNode reasonList = curBackoffReasonContent.addChild("ul");
				for(String routingBackoffReason: routingBackoffReasons) {
					int reasonCount = peers.getPeerNodeRoutingBackoffReasonSize(routingBackoffReason, false);
					if(reasonCount > 0) {
						reasonList.addChild("li", routingBackoffReason + '\u00a0' + reasonCount);
					}
				}
			}

			curBackoffReasonInfobox = backoffReasonContent.addChild("div", "class", "infobox");
			curBackoffReasonInfobox.addChild("div", "class", "infobox-header", "Current backoff reasons (realtime)");
			curBackoffReasonContent = curBackoffReasonInfobox.addChild("div", "class", "infobox-content");

			routingBackoffReasons = peers.getPeerNodeRoutingBackoffReasons(true);
			if(routingBackoffReasons.length == 0) {
				curBackoffReasonContent.addChild("#", l10n("notBackedOff"));
			} else {
				HTMLNode reasonList = curBackoffReasonContent.addChild("ul");
				for(String routingBackoffReason: routingBackoffReasons) {
					int reasonCount = peers.getPeerNodeRoutingBackoffReasonSize(routingBackoffReason, true);
					if(reasonCount > 0) {
						reasonList.addChild("li", routingBackoffReason + '\u00a0' + reasonCount);
					}
				}
			}

			// Per backoff-type count and avg backoff lengths

			// Mandatory backoff - bulk
			HTMLNode mandatoryBackoffStatisticsTableBulk = backoffReasonInfobox.addChild("table", "border", "0");
			HTMLNode row = mandatoryBackoffStatisticsTableBulk.addChild("tr");
			row.addChild("th", l10n("mandatoryBackoffReason") + " (bulk)");
			row.addChild("th", l10n("count"));
			row.addChild("th", l10n("avgTime"));
			row.addChild("th", l10n("totalTime"));

			for(NodeStats.TimedStats entry : stats.getMandatoryBackoffStatistics(false)) {
				row = mandatoryBackoffStatisticsTableBulk.addChild("tr");
				row.addChild("td", entry.keyStr);
				row.addChild("td", Long.toString(entry.count));
				row.addChild("td", TimeUtil.formatTime(entry.avgTime, 2, true));
				row.addChild("td", TimeUtil.formatTime(entry.totalTime, 2, true));
			}

			// Mandatory backoff - realtime
			HTMLNode mandatoryBackoffStatisticsTableRT = backoffReasonInfobox.addChild("table", "border", "0");
			row = mandatoryBackoffStatisticsTableRT.addChild("tr");
			row.addChild("th", l10n("mandatoryBackoffReason") + " (realtime)");
			row.addChild("th", l10n("count"));
			row.addChild("th", l10n("avgTime"));
			row.addChild("th", l10n("totalTime"));

			for(NodeStats.TimedStats entry : stats.getMandatoryBackoffStatistics(true)) {
				row = mandatoryBackoffStatisticsTableRT.addChild("tr");
				row.addChild("td", entry.keyStr);
				row.addChild("td", Long.toString(entry.count));
				row.addChild("td", TimeUtil.formatTime(entry.avgTime, 2, true));
				row.addChild("td", TimeUtil.formatTime(entry.totalTime, 2, true));
			}

			// Routing Backoff bulk
			HTMLNode routingBackoffStatisticsTableBulk = backoffReasonInfobox.addChild("table", "border", "0");
			row = routingBackoffStatisticsTableBulk.addChild("tr");
			row.addChild("th", l10n("routingBackoffReason") + " (bulk)");
			row.addChild("th", l10n("count"));
			row.addChild("th", l10n("avgTime"));
			row.addChild("th", l10n("totalTime"));

			for(NodeStats.TimedStats entry : stats.getRoutingBackoffStatistics(false)) {
				row = routingBackoffStatisticsTableBulk.addChild("tr");
				row.addChild("td", entry.keyStr);
				row.addChild("td", Long.toString(entry.count));
				row.addChild("td", TimeUtil.formatTime(entry.avgTime, 2, true));
				row.addChild("td", TimeUtil.formatTime(entry.totalTime, 2, true));
			}

			// Routing Backoff realtime
			HTMLNode routingBackoffStatisticsTableRT = backoffReasonInfobox.addChild("table", "border", "0");
			row = routingBackoffStatisticsTableRT.addChild("tr");
			row.addChild("th", l10n("routingBackoffReason") + " (realtime)");
			row.addChild("th", l10n("count"));
			row.addChild("th", l10n("avgTime"));
			row.addChild("th", l10n("totalTime"));

			for(NodeStats.TimedStats entry : stats.getRoutingBackoffStatistics(true)) {
				row = routingBackoffStatisticsTableRT.addChild("tr");
				row.addChild("td", entry.keyStr);
				row.addChild("td", Long.toString(entry.count));
				row.addChild("td", TimeUtil.formatTime(entry.avgTime, 2, true));
				row.addChild("td", TimeUtil.formatTime(entry.totalTime, 2, true));
			}

			// Transfer Backoff bulk
			HTMLNode transferBackoffStatisticsTableBulk = backoffReasonInfobox.addChild("table", "border", "0");
			row = transferBackoffStatisticsTableBulk.addChild("tr");
			row.addChild("th", l10n("transferBackoffReason") + " (bulk)");
			row.addChild("th", l10n("count"));
			row.addChild("th", l10n("avgTime"));
			row.addChild("th", l10n("totalTime"));

			for(NodeStats.TimedStats entry : stats.getTransferBackoffStatistics(false)) {
				row = transferBackoffStatisticsTableBulk.addChild("tr");
				row.addChild("td", entry.keyStr);
				row.addChild("td", Long.toString(entry.count));
				row.addChild("td", TimeUtil.formatTime(entry.avgTime, 2, true));
				row.addChild("td", TimeUtil.formatTime(entry.totalTime, 2, true));
			}
			// Transfer Backoff realtime
			HTMLNode transferBackoffStatisticsTableRT = backoffReasonInfobox.addChild("table", "border", "0");
			row = transferBackoffStatisticsTableRT.addChild("tr");
			row.addChild("th", l10n("transferBackoffReason") + " (realtime)");
			row.addChild("th", l10n("count"));
			row.addChild("th", l10n("avgTime"));
			row.addChild("th", l10n("totalTime"));

			for(NodeStats.TimedStats entry : stats.getTransferBackoffStatistics(true)) {
				row = transferBackoffStatisticsTableRT.addChild("tr");
				row.addChild("td", entry.keyStr);
				row.addChild("td", Long.toString(entry.count));
				row.addChild("td", TimeUtil.formatTime(entry.avgTime, 2, true));
				row.addChild("td", TimeUtil.formatTime(entry.totalTime, 2, true));
			}

			//Swap statistics box
			HTMLNode locationSwapInfobox = nextTableCell.addChild("div", "class", "infobox");
			drawSwapStatsBox(locationSwapInfobox, myLocation, nodeUptimeSeconds, swaps, noSwaps);

			// unclaimedFIFOMessageCounts box
			HTMLNode unclaimedFIFOMessageCountsInfobox = nextTableCell.addChild("div", "class", "infobox");
			drawUnclaimedFIFOMessageCountsBox(unclaimedFIFOMessageCountsInfobox);

						
			HTMLNode threadsPriorityInfobox = nextTableCell.addChild("div", "class", "infobox");
			drawThreadPriorityStatsBox(threadsPriorityInfobox);
			
			nextTableCell = overviewTableRow.addChild("td");

			// thread usage box
			HTMLNode threadUsageInfobox = nextTableCell.addChild("div", "class", "infobox");
			threadUsageInfobox.addChild("div", "class", "infobox-header", "Thread usage");
			HTMLNode threadUsageContent = threadUsageInfobox.addChild("div", "class", "infobox-content");
			HTMLNode threadUsageList = threadUsageContent.addChild("ul");
			getThreadNames(threadUsageList);
			
			// rejection reasons box
			drawRejectReasonsBox(nextTableCell, false);
			drawRejectReasonsBox(nextTableCell, true);
			
			OpennetManager om = node.getOpennet();
			if(om != null) {
				// opennet stats box
				drawOpennetStatsBox(nextTableCell.addChild("div", "class", "infobox"), om);
				
				if(node.isSeednode())
					drawSeedStatsBox(nextTableCell.addChild("div", "class", "infobox"), om);
			}

			// peer distribution box
			overviewTableRow = overviewTable.addChild("tr");
			nextTableCell = overviewTableRow.addChild("td", "class", "first");
			HTMLNode peerCircleInfobox = nextTableCell.addChild("div", "class", "infobox");
			peerCircleInfobox.addChild("div", "class", "infobox-header", "Peer\u00a0Location\u00a0Distribution (w/pReject)");
			HTMLNode peerCircleTable = peerCircleInfobox.addChild("div", "class", "infobox-content").addChild("table");
			addPeerCircle(peerCircleTable, peerNodeStatuses, myLocation);
			nextTableCell = overviewTableRow.addChild("td");

			// node distribution box
			HTMLNode nodeCircleInfobox = nextTableCell.addChild("div", "class", "infobox");
			nodeCircleInfobox.addChild("div", "class", "infobox-header", "Node\u00a0Location\u00a0Distribution (w/Swap\u00a0Age)");
			HTMLNode nodeCircleTable = nodeCircleInfobox.addChild("div", "class", "infobox-content").addChild("table");
			addNodeCircle(nodeCircleTable, myLocation);
			
			
			overviewTableRow = overviewTable.addChild("tr");
			nextTableCell = overviewTableRow.addChild("td", "class", "first");
			// specialisation box
			int[] incomingRequestCountArray = new int[1];
			int[] incomingRequestLocation = stats.getIncomingRequestLocation(incomingRequestCountArray);
			int incomingRequestsCount = incomingRequestCountArray[0];
			
			if(incomingRequestsCount > 0) {
				HTMLNode nodeSpecialisationInfobox = nextTableCell.addChild("div", "class", "infobox");
				nodeSpecialisationInfobox.addChild("div", "class", "infobox-header", "Incoming\u00a0Request\u00a0Distribution");
				HTMLNode nodeSpecialisationTable = nodeSpecialisationInfobox.addChild("div", "class", "infobox-content").addChild("table");
				addSpecialisation(nodeSpecialisationTable, myLocation, incomingRequestLocation);
			}
			
			nextTableCell = overviewTableRow.addChild("td");
			int[] outgoingLocalRequestCountArray = new int[1];
			int[] outgoingLocalRequestLocation = stats.getOutgoingLocalRequestLocation(outgoingLocalRequestCountArray);
			int outgoingLocalRequestsCount = outgoingLocalRequestCountArray[0];
			int[] outgoingRequestCountArray = new int[1];
			int[] outgoingRequestLocation = stats.getOutgoingRequestLocation(outgoingRequestCountArray);
			int outgoingRequestsCount = outgoingRequestCountArray[0];
			
			if(outgoingLocalRequestsCount > 0 && outgoingRequestsCount > 0) {
				HTMLNode nodeSpecialisationInfobox = nextTableCell.addChild("div", "class", "infobox");
				nodeSpecialisationInfobox.addChild("div", "class", "infobox-header", "Outgoing\u00a0Request\u00a0Distribution");
				HTMLNode nodeSpecialisationTable = nodeSpecialisationInfobox.addChild("div", "class", "infobox-content").addChild("table");
				addCombinedSpecialisation(nodeSpecialisationTable, myLocation, outgoingLocalRequestLocation, outgoingRequestLocation);
			}

			overviewTableRow = overviewTable.addChild("tr");
			nextTableCell = overviewTableRow.addChild("td", "class", "first");

			// success rate per location
			int[] locationSuccessRatesArray = stats.chkSuccessRatesByLocation.getPercentageArray(1000);
			HTMLNode nodeSpecialisationInfobox = nextTableCell.addChild("div", "class", "infobox");
			nodeSpecialisationInfobox.addChild("div", "class", "infobox-header", "Local\u00a0CHK\u00a0Success\u00a0Rates\u00a0By\u00a0Location");
			HTMLNode nodeSpecialisationTable = nodeSpecialisationInfobox.addChild("div", "class", "infobox-content").addChild("table");
			addSpecialisation(nodeSpecialisationTable, myLocation, locationSuccessRatesArray);
			nextTableCell = overviewTableRow.addChild("td");
			
			// FOAF link-length distribution box
			HTMLNode foafLinkInfobox = nextTableCell.addChild("div", "class", "infobox");
			foafLinkInfobox.addChild("div", "class", "infobox-header", "FOAF\u00a0Link-Length\u00a0Distribution");
			HTMLNode foafLinkTable = foafLinkInfobox.addChild("div", "class", "infobox-content").addChild("table");
			addFOAFLinkLengthHistogram(foafLinkTable, peerNodeStatuses);
		}
		
		}

		this.writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	}

	private void showRequesters(ToadletContext ctx) throws ToadletContextClosedException, IOException {
		PageNode page = ctx.getPageMaker().getPageNode(l10n("fullTitle"), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;

		drawClientRequestersBox(contentNode);
		writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	}

	private void drawLoadBalancingBox(HTMLNode loadStatsInfobox, boolean realTime) {
		// Load balancing box
		// Include overall window, and RTTs for each
		
		loadStatsInfobox.addChild("div", "class", "infobox-header", "Load limiting "+(realTime ? "RealTime" : "Bulk"));
		HTMLNode loadStatsContent = loadStatsInfobox.addChild("div", "class", "infobox-content");
		RequestStarterGroup starters = core.requestStarters;
		double window = starters.getWindow(realTime);
		double realWindow = starters.getRealWindow(realTime);
		HTMLNode loadStatsList = loadStatsContent.addChild("ul");
		loadStatsList.addChild("li", l10n("globalWindow")+": "+window);
		loadStatsList.addChild("li", l10n("realGlobalWindow")+": "+realWindow);
		loadStatsList.addChild("li", starters.statsPageLine(false, false, realTime));
		loadStatsList.addChild("li", starters.statsPageLine(true, false, realTime));
		loadStatsList.addChild("li", starters.statsPageLine(false, true, realTime));
		loadStatsList.addChild("li", starters.statsPageLine(true, true, realTime));
		loadStatsList.addChild("li", starters.diagnosticThrottlesLine(false));
		loadStatsList.addChild("li", starters.diagnosticThrottlesLine(true));
	}
	
	private void drawNewLoadManagementBox(HTMLNode infobox) {
		infobox.addChild("div", "class", "infobox-header", l10n("newLoadManagementTitle"));
		HTMLNode content = infobox.addChild("div", "class", "infobox-content");
		node.nodeStats.drawNewLoadManagementDelayTimes(content);
	}

	private void drawRejectReasonsBox(HTMLNode nextTableCell, boolean local) {
		HTMLNode rejectReasonsTable = new HTMLNode("table");
		NodeStats stats = node.nodeStats;
		boolean success = local ? stats.getLocalRejectReasonsTable(rejectReasonsTable) :
			stats.getRejectReasonsTable(rejectReasonsTable);
		if(!success)
			return;
		HTMLNode rejectReasonsInfobox = nextTableCell.addChild("div", "class", "infobox");
		rejectReasonsInfobox.addChild("div", "class", "infobox-header", (local ? "Local " : "")+"Preemptive Rejection Reasons");
		rejectReasonsInfobox.addChild("div", "class", "infobox-content").addChild(rejectReasonsTable);
	}

	private void drawNodeVersionBox(HTMLNode versionInfobox) {
		
		versionInfobox.addChild("div", "class", "infobox-header", l10n("versionTitle"));
		HTMLNode versionInfoboxContent = versionInfobox.addChild("div", "class", "infobox-content");
		HTMLNode versionInfoboxList = versionInfoboxContent.addChild("ul");
		versionInfoboxList.addChild("li", NodeL10n.getBase().getString("WelcomeToadlet.version", new String[] { "fullVersion", "build", "rev" },
				new String[] { Version.publicVersion(), Integer.toString(Version.buildNumber()), Version.cvsRevision() }));
		versionInfoboxList.addChild("li", NodeL10n.getBase().getString("WelcomeToadlet.extVersion", new String[] { "build", "rev" },
				new String[] { Integer.toString(NodeStarter.extBuildNumber), NodeStarter.extRevisionNumber }));

		node.getNodeUpdater().addChangelogLinks(Version.buildNumber(), versionInfobox);
	}

	private void drawJVMStatsBox(HTMLNode jvmStatsInfobox, boolean advancedModeEnabled) {
		
		jvmStatsInfobox.addChild("div", "class", "infobox-header", l10n("jvmInfoTitle"));
		HTMLNode jvmStatsInfoboxContent = jvmStatsInfobox.addChild("div", "class", "infobox-content");
		HTMLNode jvmStatsList = jvmStatsInfoboxContent.addChild("ul");

		Runtime rt = Runtime.getRuntime();
		long freeMemory = rt.freeMemory();
		long totalMemory = rt.totalMemory();
		long maxMemory = rt.maxMemory();

		long usedJavaMem = totalMemory - freeMemory;
		long allocatedJavaMem = totalMemory;
		long maxJavaMem = maxMemory;
		int availableCpus = rt.availableProcessors();

		int threadCount = stats.getActiveThreadCount();

		jvmStatsList.addChild("li", l10n("usedMemory", "memory", SizeUtil.formatSize(usedJavaMem, true)));
		jvmStatsList.addChild("li", l10n("allocMemory", "memory", SizeUtil.formatSize(allocatedJavaMem, true)));
		jvmStatsList.addChild("li", l10n("maxMemory", "memory", SizeUtil.formatSize(maxJavaMem, true)));
		jvmStatsList.addChild("li", l10n("threads", new String[] { "running", "max" },
				new String[] { thousandPoint.format(threadCount), Integer.toString(stats.getThreadLimit()) }));
		jvmStatsList.addChild("li", l10n("cpus", "count", Integer.toString(availableCpus)));
		jvmStatsList.addChild("li", l10n("javaVersion", "version", System.getProperty("java.version")));
		jvmStatsList.addChild("li", l10n("jvmVendor", "vendor", System.getProperty("java.vendor")));
		jvmStatsList.addChild("li", l10n("jvmName", "name", System.getProperty("java.vm.name")));
		jvmStatsList.addChild("li", l10n("jvmVersion", "version", System.getProperty("java.vm.version")));
		jvmStatsList.addChild("li", l10n("osName", "name", System.getProperty("os.name")));
		jvmStatsList.addChild("li", l10n("osVersion", "version", System.getProperty("os.version")));
		jvmStatsList.addChild("li", l10n("osArch", "arch", System.getProperty("os.arch")));
		if(advancedModeEnabled) {
			if(Rijndael.AesCtrProvider == null)
				jvmStatsList.addChild("li", l10n("cryptoUsingBuiltin"));
			else
				jvmStatsList.addChild("li", l10n("cryptoUsingJCA", "provider", Rijndael.getProviderName()));
		}
	}
	
	private void drawThreadPriorityStatsBox(HTMLNode node) {
		
		node.addChild("div", "class", "infobox-header", l10n("threadsByPriority"));
		HTMLNode threadsInfoboxContent = node.addChild("div", "class", "infobox-content");
		int[] activeThreadsByPriority = stats.getActiveThreadsByPriority();
		int[] waitingThreadsByPriority = stats.getWaitingThreadsByPriority();
		
		HTMLNode threadsByPriorityTable = threadsInfoboxContent.addChild("table", "border", "0");
		HTMLNode row = threadsByPriorityTable.addChild("tr");

		row.addChild("th", l10n("priority"));
		row.addChild("th", l10n("running"));
		row.addChild("th", l10n("waiting"));
		
		for(int i=0; i<activeThreadsByPriority.length; i++) {
			row = threadsByPriorityTable.addChild("tr");
			row.addChild("td", String.valueOf(i+1));
			row.addChild("td", String.valueOf(activeThreadsByPriority[i]));
			row.addChild("td", String.valueOf(waitingThreadsByPriority[i]));
		}
	}

	private void drawOpennetStatsBox(HTMLNode box, OpennetManager om) {
		box.addChild("div", "class", "infobox-header", l10n("opennetStats"));
		HTMLNode opennetStatsContent = box.addChild("div", "class", "infobox-content");
		om.drawOpennetStatsBox(opennetStatsContent);
	}
	
	private void drawSeedStatsBox(HTMLNode box, OpennetManager om) {
		box.addChild("div", "class", "infobox-header", l10n("seedStats"));
		HTMLNode opennetStatsContent = box.addChild("div", "class", "infobox-content");
		om.drawSeedStatsBox(opennetStatsContent);
	}

	private void drawClientRequestersBox(HTMLNode box) {
		box.addChild("div", "class", "infobox-header", l10n("clientRequesterObjects"));
		HTMLNode masterContent = box.addChild("div", "class", "infobox-content");
		HTMLNode table = masterContent.addChild("table");
		HTMLNode row = table.addChild("tr");
		row.addChild("th", "RequestClient");
		row.addChild("th", l10n("clientRequesters.class"));
		row.addChild("th", l10n("clientRequesters.age"));
		row.addChild("th", l10n("clientRequesters.priorityClass"));
		row.addChild("th", l10n("clientRequesters.realtimeFlag"));
		row.addChild("th", l10n("clientRequesters.uri"));
		NumberFormat nf = NumberFormat.getInstance();
		nf.setMaximumFractionDigits(0);
		nf.setMinimumIntegerDigits(2);
		ClientRequester[] requests = ClientRequester.getAll();
		Arrays.sort(requests, new Comparator<ClientRequester>() {
				@Override
				public int compare(ClientRequester a, ClientRequester b) {
					return -Long.signum(a.creationTime - b.creationTime);
				}
			});
		long now = System.currentTimeMillis();
		for(ClientRequester request : requests) {
			if(request.isFinished() || request.isCancelled())
				continue;
			row = table.addChild("tr");
			RequestClient client = request.getClient();
			row.addChild("td", client.toString());
			try {
				String s = request.toString();
				if(s.indexOf(':') > s.indexOf('@')) {
					s = s.substring(0, s.indexOf(':'));
				}
				row.addChild("td", s);
			} catch (Throwable t) {
				// FIXME shouldn't happen...
				row.addChild("td", "ERROR: "+request.getClass().toString());
			}
			long diff = now - request.creationTime;
			StringBuilder sb = new StringBuilder();
			sb.append(TimeUtil.formatTime(diff, 2));
			row.addChild("td", sb.toString());
			row.addChild("td", Short.toString(request.getPriorityClass()));
			row.addChild("td", client==null ? "?" : Boolean.toString(client.realTimeFlag()));
			FreenetURI uri = request.getURI(); // getURI() sometimes returns null, eg for ClientPutters
			row.addChild("td", uri == null ? "null" : uri.toString());
		}
	}

	private void drawStoreSizeBox(HTMLNode storeSizeInfobox, long nodeUptimeSeconds) {
		storeSizeInfobox.addChild("div", "class", "infobox-header", l10n("datastore"));
		HTMLNode storeSizeInfoboxContent = storeSizeInfobox.addChild("div", "class", "infobox-content");

		HTMLNode scrollDiv = storeSizeInfoboxContent.addChild("div", "style", "overflow:scr");

		HTMLNode storeSizeTable = scrollDiv.addChild("table", "border", "0");
		HTMLNode row = storeSizeTable.addChild("tr");

		//FIXME - Non-breaking space? "Stat-name"?
		row.addChild("th", "");

		row.addChild("th", l10n("keys"));
		row.addChild("th", l10n("capacity"));
		row.addChild("th", l10n("datasize"));
		row.addChild("th", l10n("utilization"));
		row.addChild("th", l10n("readRequests"));
		row.addChild("th", l10n("successfulReads"));
		row.addChild("th", l10n("successRate"));
		row.addChild("th", l10n("writes"));
		row.addChild("th", l10n("accessRate"));
		row.addChild("th", l10n("writeRate"));
		row.addChild("th", l10n("falsePos"));
		row.addChild("th", l10n("avgLocation"));
		row.addChild("th", l10n("avgSuccessLoc"));
		row.addChild("th", l10n("furthestSuccess"));
		row.addChild("th", l10n("avgDist"));
		row.addChild("th", l10n("distanceStats"));


		Map<DataStoreInstanceType, DataStoreStats> storeStats = node.getDataStoreStats();
		for (Map.Entry<DataStoreInstanceType, DataStoreStats> entry : storeStats.entrySet()) {
			DataStoreInstanceType instance = entry.getKey();
			DataStoreStats stats = entry.getValue();
			
			StoreAccessStats sessionAccess = stats.getSessionAccessStats();
			StoreAccessStats totalAccess;
			long totalUptimeSeconds = 0;
			try {
				totalAccess = stats.getTotalAccessStats();
				// FIXME this is not necessarily the same as the datastore's uptime if we've switched.
				// Ideally we'd track uptime there too.
				totalUptimeSeconds = 
					node.clientCore.bandwidthStatsPutter.getLatestUptimeData().totalUptime;
			} catch (StatsNotAvailableException e) {
				totalAccess = null;
			}
			
			row = storeSizeTable.addChild("tr");
			row.addChild("th", l10n(instance.store.name()) + "\n" + " (" + l10n(instance.key.name()) + ")");

			row.addChild("td", thousandPoint.format(stats.keys()));
			row.addChild("td", thousandPoint.format(stats.capacity()));
			row.addChild("td", SizeUtil.formatSize(stats.dataSize()));
			row.addChild("td", fix3p1pct.format(stats.utilization()));
			row.addChild("td", thousandPoint.format(sessionAccess.readRequests()) +
					(totalAccess == null ? "" : (" ("+thousandPoint.format(totalAccess.readRequests())+")")));
			row.addChild("td", thousandPoint.format(sessionAccess.successfulReads()) +
					(totalAccess == null ? "" : (" ("+thousandPoint.format(totalAccess.successfulReads())+")")));
			try {
				String rate = fix1p4.format(sessionAccess.successRate()) + "%";
				if(totalAccess != null) {
					try {
						rate += " (" + fix1p4.format(totalAccess.successRate()) + "%)";
					} catch (StatsNotAvailableException e) {
						// Ignore
					}
				}
				row.addChild("td", rate);
			} catch (StatsNotAvailableException e) {
				row.addChild("td", "N/A");
			}
			row.addChild("td", thousandPoint.format(sessionAccess.writes()) +
					(totalAccess == null ? "" : (" ("+thousandPoint.format(totalAccess.writes())+")")));
			String access = fix1p2.format(sessionAccess.accessRate(nodeUptimeSeconds)) + " /s";
			if(totalAccess != null)
				access += " (" + fix1p2.format(totalAccess.accessRate(totalUptimeSeconds)) + " /s)";
			row.addChild("td", access);
			access = fix1p2.format(sessionAccess.writeRate(nodeUptimeSeconds)) + " /s";
			if(totalAccess != null)
				access += " (" + fix1p2.format(totalAccess.writeRate(totalUptimeSeconds)) + " /s)";
			row.addChild("td", access);
			row.addChild("td", thousandPoint.format(sessionAccess.falsePos()) +
					(totalAccess == null ? "" : (" ("+thousandPoint.format(totalAccess.falsePos())+")")));
			try {
				row.addChild("td", fix1p4.format(stats.avgLocation()));
			} catch (StatsNotAvailableException e) {
				row.addChild("td", "N/A");
			}

			try {
				row.addChild("td", fix1p4.format(stats.avgSuccess()));
			} catch (StatsNotAvailableException e) {
				row.addChild("td", "N/A");
			}

			try {
				row.addChild("td", fix1p4.format(stats.furthestSuccess()));
			} catch (StatsNotAvailableException e) {
				row.addChild("td", "N/A");
			}

			try {
				row.addChild("td", fix1p4.format(stats.avgDist()));
			} catch (StatsNotAvailableException e) {
				row.addChild("td", "N/A");
			}

			try {
				row.addChild("td", fix3p1pct.format(stats.distanceStats()));
			} catch (StatsNotAvailableException e) {
				row.addChild("td", "N/A");
			}
		}

	}

	private void drawUnclaimedFIFOMessageCountsBox(HTMLNode unclaimedFIFOMessageCountsInfobox) {
		
		unclaimedFIFOMessageCountsInfobox.addChild("div", "class", "infobox-header", "unclaimedFIFO Message Counts");
		HTMLNode unclaimedFIFOMessageCountsInfoboxContent = unclaimedFIFOMessageCountsInfobox.addChild("div", "class", "infobox-content");
		HTMLNode unclaimedFIFOMessageCountsList = unclaimedFIFOMessageCountsInfoboxContent.addChild("ul");
		Map<String, Integer> unclaimedFIFOMessageCountsMap = node.getUSM().getUnclaimedFIFOMessageCounts();
		STMessageCount[] unclaimedFIFOMessageCountsArray = new STMessageCount[unclaimedFIFOMessageCountsMap.size()];
		int i = 0;
		int totalCount = 0;
		for (Map.Entry<String, Integer> e : unclaimedFIFOMessageCountsMap.entrySet()) {
			String messageName = e.getKey();
			int messageCount = e.getValue();
			totalCount = totalCount + messageCount;
			unclaimedFIFOMessageCountsArray[i++] = new STMessageCount( messageName, messageCount );
		}
		Arrays.sort(unclaimedFIFOMessageCountsArray, new Comparator<STMessageCount>() {
			@Override
			public int compare(STMessageCount firstCount, STMessageCount secondCount) {
				return secondCount.messageCount - firstCount.messageCount;  // sort in descending order
			}
		});
		for (STMessageCount messageCountItem: unclaimedFIFOMessageCountsArray) {
			int thisMessageCount = messageCountItem.messageCount;
			double thisMessagePercentOfTotal = ((double) thisMessageCount) / ((double) totalCount);
			unclaimedFIFOMessageCountsList.addChild("li", "" + messageCountItem.messageName + ":\u00a0" + thisMessageCount + "\u00a0(" + fix3p1pct.format(thisMessagePercentOfTotal) + ')');
		}
		unclaimedFIFOMessageCountsList.addChild("li", "Unclaimed Messages Considered:\u00a0" + totalCount);
		
	}

	private void drawSwapStatsBox(HTMLNode locationSwapInfobox, double location, long nodeUptimeSeconds, double swaps, double noSwaps) {
		
		locationSwapInfobox.addChild("div", "class", "infobox-header", "Location swaps");
		int startedSwaps = node.getStartedSwaps();
		int swapsRejectedAlreadyLocked = node.getSwapsRejectedAlreadyLocked();
		int swapsRejectedNowhereToGo = node.getSwapsRejectedNowhereToGo();
		int swapsRejectedRateLimit = node.getSwapsRejectedRateLimit();
		int swapsRejectedRecognizedID = node.getSwapsRejectedRecognizedID();
		double locChangeSession = node.getLocationChangeSession();
		int averageSwapTime = node.getAverageOutgoingSwapTime();
		long sendSwapInterval = node.getSendSwapInterval();

		HTMLNode locationSwapInfoboxContent = locationSwapInfobox.addChild("div", "class", "infobox-content");
		HTMLNode locationSwapList = locationSwapInfoboxContent.addChild("ul");
		locationSwapList.addChild("li", "location:\u00a0" + location);
		if (swaps > 0.0) {
			locationSwapList.addChild("li", "locChangeSession:\u00a0" + fix1p6sci.format(locChangeSession));
			locationSwapList.addChild("li", "locChangePerSwap:\u00a0" + fix1p6sci.format(locChangeSession/swaps));
		}
		if ((swaps > 0.0) && (nodeUptimeSeconds >= 60)) {
			locationSwapList.addChild("li", "locChangePerMinute:\u00a0" + fix1p6sci.format(locChangeSession/(nodeUptimeSeconds/60.0)));
		}
		if ((swaps > 0.0) && (nodeUptimeSeconds >= 60)) {
			locationSwapList.addChild("li", "swapsPerMinute:\u00a0" + fix1p6sci.format(swaps/(nodeUptimeSeconds/60.0)));
		}
		if ((noSwaps > 0.0) && (nodeUptimeSeconds >= 60)) {
			locationSwapList.addChild("li", "noSwapsPerMinute:\u00a0" + fix1p6sci.format(noSwaps/(nodeUptimeSeconds/60.0)));
		}
		if ((swaps > 0.0) && (noSwaps > 0.0)) {
			locationSwapList.addChild("li", "swapsPerNoSwaps:\u00a0" + fix1p6sci.format(swaps/noSwaps));
		}
		if (swaps > 0.0) {
			locationSwapList.addChild("li", "swaps:\u00a0" + (int)swaps);
		}
		if (noSwaps > 0.0) {
			locationSwapList.addChild("li", "noSwaps:\u00a0" + (int)noSwaps);
		}
		if (startedSwaps > 0) {
			locationSwapList.addChild("li", "startedSwaps:\u00a0" + startedSwaps);
		}
		if (swapsRejectedAlreadyLocked > 0) {
			locationSwapList.addChild("li", "swapsRejectedAlreadyLocked:\u00a0" + swapsRejectedAlreadyLocked);
		}
		if (swapsRejectedNowhereToGo > 0) {
			locationSwapList.addChild("li", "swapsRejectedNowhereToGo:\u00a0" + swapsRejectedNowhereToGo);
		}
		if (swapsRejectedRateLimit > 0) {
			locationSwapList.addChild("li", "swapsRejectedRateLimit:\u00a0" + swapsRejectedRateLimit);
		}
		if (swapsRejectedRecognizedID > 0) {
			locationSwapList.addChild("li", "swapsRejectedRecognizedID:\u00a0" + swapsRejectedRecognizedID);
		}
		locationSwapList.addChild("li", "averageSwapTime:\u00a0" + TimeUtil.formatTime(averageSwapTime, 2, true));
		locationSwapList.addChild("li", "sendSwapInterval:\u00a0" + TimeUtil.formatTime(sendSwapInterval, 2, true));
	}

	protected static void drawPeerStatsBox(HTMLNode peerStatsInfobox, boolean advancedModeEnabled, int numberOfConnected, 
			int numberOfRoutingBackedOff, int numberOfTooNew, int numberOfTooOld, int numberOfDisconnected, 
			int numberOfNeverConnected, int numberOfDisabled, int numberOfBursting, int numberOfListening, 
			int numberOfListenOnly, int numberOfSeedServers, int numberOfSeedClients, int numberOfRoutingDisabled, 
			int numberOfClockProblem, int numberOfConnError, int numberOfDisconnecting, int numberOfNoLoadStats, Node node) {
		
		peerStatsInfobox.addChild("div", "class", "infobox-header", l10n("peerStatsTitle"));
		HTMLNode peerStatsContent = peerStatsInfobox.addChild("div", "class", "infobox-content");
		HTMLNode peerStatsList = peerStatsContent.addChild("ul");
		if (numberOfConnected > 0) {
			HTMLNode peerStatsConnectedListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsConnectedListItem.addChild("span", new String[] { "class", "title", "style" }, 
					new String[] { "peer_connected", l10nDark("connected"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("connectedShort"));
			peerStatsConnectedListItem.addChild("span", ":\u00a0" + numberOfConnected);
		}
		if (numberOfRoutingBackedOff > 0) {
			HTMLNode peerStatsRoutingBackedOffListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsRoutingBackedOffListItem.addChild("span", new String[] { "class", "title", "style" }, 
					new String[] { "peer_backed_off", l10nDark(advancedModeEnabled ? "backedOff" : "busy"), 
					"border-bottom: 1px dotted; cursor: help;" }, l10nDark((advancedModeEnabled ? "backedOff" : "busy")+"Short"));
			peerStatsRoutingBackedOffListItem.addChild("span", ":\u00a0" + numberOfRoutingBackedOff);
		}
		if (numberOfTooNew > 0) {
			HTMLNode peerStatsTooNewListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsTooNewListItem.addChild("span", new String[] { "class", "title", "style" }, 
					new String[] { "peer_too_new", l10nDark("tooNew"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("tooNewShort"));
			peerStatsTooNewListItem.addChild("span", ":\u00a0" + numberOfTooNew);
		}
		if (numberOfTooOld > 0) {
			HTMLNode peerStatsTooOldListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsTooOldListItem.addChild("span", new String[] { "class", "title", "style" }, 
					new String[] { "peer_too_old", l10nDark("tooOld"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("tooOldShort"));
			peerStatsTooOldListItem.addChild("span", ":\u00a0" + numberOfTooOld);
		}
		if (numberOfDisconnected > 0) {
			HTMLNode peerStatsDisconnectedListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsDisconnectedListItem.addChild("span", new String[] { "class", "title", "style" }, 
					new String[] { "peer_disconnected", l10nDark("notConnected"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("notConnectedShort"));
			peerStatsDisconnectedListItem.addChild("span", ":\u00a0" + numberOfDisconnected);
		}
		if (numberOfNeverConnected > 0) {
			HTMLNode peerStatsNeverConnectedListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsNeverConnectedListItem.addChild("span", new String[] { "class", "title", "style" },
					new String[] { "peer_never_connected", l10nDark("neverConnected"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("neverConnectedShort"));
			peerStatsNeverConnectedListItem.addChild("span", ":\u00a0" + numberOfNeverConnected);
		}
		if (numberOfDisabled > 0) {
			HTMLNode peerStatsDisabledListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsDisabledListItem.addChild("span", new String[] { "class", "title", "style" }, 
					new String[] { "peer_disabled", l10nDark("disabled"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("disabledShort"));
			peerStatsDisabledListItem.addChild("span", ":\u00a0" + numberOfDisabled);
		}
		if (numberOfBursting > 0) {
			HTMLNode peerStatsBurstingListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsBurstingListItem.addChild("span", new String[] { "class", "title", "style" }, 
					new String[] { "peer_bursting", l10nDark("bursting"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("burstingShort"));
			peerStatsBurstingListItem.addChild("span", ":\u00a0" + numberOfBursting);
		}
		if (numberOfListening > 0) {
			HTMLNode peerStatsListeningListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsListeningListItem.addChild("span", new String[] { "class", "title", "style" }, 
					new String[] { "peer_listening", l10nDark("listening"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("listeningShort"));
			peerStatsListeningListItem.addChild("span", ":\u00a0" + numberOfListening);
		}
		if (numberOfListenOnly > 0) {
			HTMLNode peerStatsListenOnlyListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsListenOnlyListItem.addChild("span", new String[] { "class", "title", "style" }, 
					new String[] { "peer_listen_only", l10nDark("listenOnly"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("listenOnlyShort"));
			peerStatsListenOnlyListItem.addChild("span", ":\u00a0" + numberOfListenOnly);
		}
		if (numberOfClockProblem > 0) {
			HTMLNode peerStatsRoutingDisabledListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsRoutingDisabledListItem.addChild("span", new String[] { "class", "title", "style" }, new String[] { "peer_clock_problem", l10nDark("clockProblem"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("clockProblemShort"));
			peerStatsRoutingDisabledListItem.addChild("span", ":\u00a0" + numberOfClockProblem);
		}
		if (numberOfConnError > 0) {
			HTMLNode peerStatsRoutingDisabledListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsRoutingDisabledListItem.addChild("span", new String[] { "class", "title", "style" }, new String[] { "peer_routing_disabled", l10nDark("connError"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("connErrorShort"));
			peerStatsRoutingDisabledListItem.addChild("span", ":\u00a0" + numberOfClockProblem);
		}
		if (numberOfDisconnecting > 0) {
			HTMLNode peerStatsListenOnlyListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsListenOnlyListItem.addChild("span", new String[] { "class", "title", "style" }, new String[] { "peer_disconnecting", l10nDark("disconnecting"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("disconnectingShort"));
			peerStatsListenOnlyListItem.addChild("span", ":\u00a0" + numberOfDisconnecting);
		}
		if (numberOfSeedServers > 0) {
			HTMLNode peerStatsSeedServersListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsSeedServersListItem.addChild("span", new String[] { "class", "title", "style" },
					new String[] { "peer_listening" /* FIXME */, l10nDark("seedServers"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("seedServersShort"));
			peerStatsSeedServersListItem.addChild("span", ":\u00a0" + numberOfSeedServers);
		}
		if (numberOfSeedClients > 0) {
			HTMLNode peerStatsSeedClientsListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsSeedClientsListItem.addChild("span", new String[] { "class", "title", "style" },
					new String[] { "peer_listening" /* FIXME */, l10nDark("seedClients"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("seedClientsShort"));
			peerStatsSeedClientsListItem.addChild("span", ":\u00a0" + numberOfSeedClients);
		}
		if (numberOfRoutingDisabled > 0) {
			HTMLNode peerStatsRoutingDisabledListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsRoutingDisabledListItem.addChild("span", new String[] { "class", "title", "style" }, new String[] { "peer_routing_disabled", l10nDark("routingDisabled"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("routingDisabledShort"));
			peerStatsRoutingDisabledListItem.addChild("span", ":\u00a0" + numberOfRoutingDisabled);
		}
		if (numberOfNoLoadStats > 0) {
			HTMLNode peerStatsNoLoadStatsListItem = peerStatsList.addChild("li").addChild("span");
			peerStatsNoLoadStatsListItem.addChild("span", new String[] { "class", "title", "style" }, new String[] { "peer_no_load_stats", l10nDark("noLoadStats"), "border-bottom: 1px dotted; cursor: help;" }, l10nDark("noLoadStatsShort"));
			peerStatsNoLoadStatsListItem.addChild("span", ":\u00a0" + numberOfNoLoadStats);
		}
		OpennetManager om = node.getOpennet();
		if(om != null) {
			peerStatsList.addChild("li", l10n("maxTotalPeers")+": "+om.getNumberOfConnectedPeersToAimIncludingDarknet());
			peerStatsList.addChild("li", l10n("maxOpennetPeers")+": "+om.getNumberOfConnectedPeersToAim());
		}
	}

	private static String l10n(String key) {
		return NodeL10n.getBase().getString("StatisticsToadlet."+key);
	}
	
	private static String l10nDark(String key) {
		return NodeL10n.getBase().getString("DarknetConnectionsToadlet."+key);
	}

	private static String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("StatisticsToadlet."+key, new String[] { pattern }, new String[] { value });
	}
	
	private static String l10n(String key, String[] patterns, String[] values) {
		return NodeL10n.getBase().getString("StatisticsToadlet."+key, patterns, values);
	}
	
	private void drawActivityBox(HTMLNode activityInfobox, boolean advancedModeEnabled) {
		
		activityInfobox.addChild("div", "class", "infobox-header", l10nDark("activityTitle"));
		HTMLNode activityInfoboxContent = activityInfobox.addChild("div", "class", "infobox-content");
		
		HTMLNode activityList = drawActivity(activityInfoboxContent, node);
		
		int numARKFetchers = node.getNumARKFetchers();

		if (advancedModeEnabled && activityList != null) {
			if (numARKFetchers > 0)
				activityList.addChild("li", "ARK\u00a0Fetch\u00a0Requests:\u00a0" + numARKFetchers);
			activityList.addChild("li", "BackgroundFetcherByUSKSize:\u00a0" + node.clientCore.uskManager.getBackgroundFetcherByUSKSize());
			activityList.addChild("li", "temporaryBackgroundFetchersLRUSize:\u00a0" + node.clientCore.uskManager.getTemporaryBackgroundFetchersLRU());
			activityList.addChild("li", "outputBandwidthLiabilityUsage:\u00a0" + this.fix3p1pct.format(node.nodeStats.getBandwidthLiabilityUsage()));
		}
		
	}
	
	static void drawBandwidth(HTMLNode activityList, Node node, long nodeUptimeSeconds, boolean isAdvancedModeEnabled) {
		long[] total = node.collector.getTotalIO();
		if(total[0] == 0 || total[1] == 0)
			return;
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
			SubConfig nodeConfig = node.config.get("node");
			int outputBandwidthLimit = nodeConfig.getInt("outputBandwidthLimit");
			int inputBandwidthLimit = nodeConfig.getInt("inputBandwidthLimit");
			if(inputBandwidthLimit == -1) {
				inputBandwidthLimit = outputBandwidthLimit * 4;
			}
			activityList.addChild("li", l10n("inputRate", new String[] { "rate", "max" }, new String[] { SizeUtil.formatSize(input_rate, true), SizeUtil.formatSize(inputBandwidthLimit, true) }));
			activityList.addChild("li", l10n("outputRate", new String[] { "rate", "max" }, new String[] { SizeUtil.formatSize(output_rate, true), SizeUtil.formatSize(outputBandwidthLimit, true) }));
		}
		activityList.addChild("li", l10n("totalInputSession", new String[] { "total", "rate" }, new String[] { SizeUtil.formatSize(total[1], true), SizeUtil.formatSize(total_input_rate, true) }));
		activityList.addChild("li", l10n("totalOutputSession", new String[] { "total", "rate" }, new String[] { SizeUtil.formatSize(total[0], true), SizeUtil.formatSize(total_output_rate, true) } ));
		activityList.addChild("li", l10n("payloadOutput", new String[] { "total", "rate", "percent" }, new String[] { SizeUtil.formatSize(totalPayload, true), SizeUtil.formatSize(total_payload_rate, true), Integer.toString(percent) } ));
		activityList.addChild("li", l10n("totalInput", new String[] { "total" }, new String[] { SizeUtil.formatSize(overall_total_in, true) }));
		activityList.addChild("li", l10n("totalOutput", new String[] { "total" }, new String[] { SizeUtil.formatSize(overall_total_out, true) } ));
		if(isAdvancedModeEnabled) {
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
			activityList.addChild("li", l10n("requestOutput", new String[] { "chk", "ssk" }, new String[] { SizeUtil.formatSize(totalBytesSentCHKRequests, true), SizeUtil.formatSize(totalBytesSentSSKRequests, true) }));
			activityList.addChild("li", l10n("insertOutput", new String[] { "chk", "ssk" }, new String[] { SizeUtil.formatSize(totalBytesSentCHKInserts, true), SizeUtil.formatSize(totalBytesSentSSKInserts, true) }));
			activityList.addChild("li", l10n("offeredKeyOutput", new String[] { "total", "offered" }, new String[] { SizeUtil.formatSize(totalBytesSentOfferedKeys, true), SizeUtil.formatSize(totalBytesSendOffers, true) }));
			activityList.addChild("li", l10n("swapOutput", "total", SizeUtil.formatSize(totalBytesSentSwapOutput, true)));
			activityList.addChild("li", l10n("authBytes", "total", SizeUtil.formatSize(totalBytesSentAuth, true)));
			activityList.addChild("li", l10n("ackOnlyBytes", "total", SizeUtil.formatSize(totalBytesSentAckOnly, true)));
			activityList.addChild("li", l10n("resendBytes", new String[] { "total", "percent" }, new String[] { SizeUtil.formatSize(totalBytesSentResends, true), Long.toString((100 * totalBytesSentResends) / Math.max(1, total[0])) } ));
			activityList.addChild("li", l10n("uomBytes", "total",  SizeUtil.formatSize(totalBytesSentUOM, true)));
			activityList.addChild("li", l10n("announceBytes", new String[] { "total", "payload" }, new String[] { SizeUtil.formatSize(totalBytesSentAnnounce, true), SizeUtil.formatSize(totalBytesSentAnnouncePayload, true) }));
			activityList.addChild("li", l10n("adminBytes", new String[] { "routingStatus", "disconn", "initial", "changedIP" }, new String[] { SizeUtil.formatSize(totalBytesSentRoutingStatus, true), SizeUtil.formatSize(totalBytesSentDisconn, true), SizeUtil.formatSize(totalBytesSentInitial, true), SizeUtil.formatSize(totalBytesSentChangedIP, true) }));
			activityList.addChild("li", l10n("debuggingBytes", new String[] { "netColoring", "ping", "probe", "routed" }, new String[] { SizeUtil.formatSize(totalBytesSentNetworkColoring, true), SizeUtil.formatSize(totalBytesSentPing, true), SizeUtil.formatSize(totalBytesSentProbeRequest, true), SizeUtil.formatSize(totalBytesSentRouted, true) } ));
			activityList.addChild("li", l10n("nodeToNodeBytes", "total", SizeUtil.formatSize(totalBytesSentNodeToNode, true)));
			activityList.addChild("li", l10n("loadAllocationNoticesBytes", "total", SizeUtil.formatSize(totalBytesSentAllocationNotices, true)));
			activityList.addChild("li", l10n("foafBytes", "total", SizeUtil.formatSize(totalBytesSentFOAF, true)));
			activityList.addChild("li", l10n("unaccountedBytes", new String[] { "total", "percent" },
					new String[] { SizeUtil.formatSize(totalBytesSentRemaining, true), Integer.toString((int)(totalBytesSentRemaining*100 / total[0])) }));
			double sentOverheadPerSecond = node.nodeStats.getSentOverheadPerSecond();
			activityList.addChild("li", l10n("totalOverhead", new String[] { "rate", "percent" }, 
					new String[] { SizeUtil.formatSize((long)sentOverheadPerSecond), Integer.toString((int)((100 * sentOverheadPerSecond) / total_output_rate)) }));
		}
	}

	static HTMLNode drawActivity(HTMLNode activityInfoboxContent, Node node) {
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
			activityInfoboxContent.addChild("#", l10n("noRequests"));
			
			return null;
		} else {
			HTMLNode activityList = activityInfoboxContent.addChild("ul");
			if (numCHKInserts > 0 || numSSKInserts > 0) {
				activityList.addChild("li", NodeL10n.getBase().getString("StatisticsToadlet.activityInserts", 
						new String[] { "CHKhandlers", "SSKhandlers", "local" } , 
						new String[] { Integer.toString(numCHKInserts), Integer.toString(numSSKInserts), Integer.toString(numLocalCHKInserts)+"/" + Integer.toString(numLocalSSKInserts)}));
			}
			if (numCHKRequests > 0 || numSSKRequests > 0) {
				activityList.addChild("li", NodeL10n.getBase().getString("StatisticsToadlet.activityRequests", 
						new String[] { "CHKhandlers", "SSKhandlers", "local" } , 
						new String[] { Integer.toString(numCHKRequests), Integer.toString(numSSKRequests), Integer.toString(numLocalCHKRequests)+"/" + Integer.toString(numLocalSSKRequests)}));
			}
			if (numTransferringRequests > 0 || numTransferringRequestHandlers > 0) {
				activityList.addChild("li", NodeL10n.getBase().getString("StatisticsToadlet.transferringRequests", 
						new String[] { "senders", "receivers", "turtles" }, new String[] { Integer.toString(numTransferringRequests), Integer.toString(numTransferringRequestHandlers), "0"}));
			}
			if (numCHKOfferReplys > 0 || numSSKOfferReplys > 0) {
				activityList.addChild("li", NodeL10n.getBase().getString("StatisticsToadlet.offerReplys", 
						new String[] { "chk", "ssk" }, new String[] { Integer.toString(numCHKOfferReplys), Integer.toString(numSSKOfferReplys) }));
			}
			activityList.addChild("li", NodeL10n.getBase().getString("StatisticsToadlet.runningBlockTransfers", 
					new String[] { "sends", "receives" }, new String[] { Integer.toString(BlockTransmitter.getRunningSends()), Integer.toString(BlockReceiver.getRunningReceives()) }));
			return activityList;
		}
	}

	private void drawOverviewBox(HTMLNode overviewInfobox, long nodeUptimeSeconds, long nodeUptimeTotal, long now, double swaps, double noSwaps) {
		
		overviewInfobox.addChild("div", "class", "infobox-header", "Node status overview");
		HTMLNode overviewInfoboxContent = overviewInfobox.addChild("div", "class", "infobox-content");
		HTMLNode overviewList = overviewInfoboxContent.addChild("ul");
		/* node status values */
		int bwlimitDelayTime = (int) stats.getBwlimitDelayTime();
		int bwlimitDelayTimeBulk = (int) stats.getBwlimitDelayTimeBulk();
		int bwlimitDelayTimeRT = (int) stats.getBwlimitDelayTimeRT();
		int nodeAveragePingTime = (int) stats.getNodeAveragePingTime();
		double numberOfRemotePeerLocationsSeenInSwaps = node.getNumberOfRemotePeerLocationsSeenInSwaps();

		// Darknet
		int darknetSizeEstimateSession = stats.getDarknetSizeEstimate(-1);
		int darknetSizeEstimate24h = 0;
		int darknetSizeEstimate48h = 0;
		if(nodeUptimeSeconds > HOURS.toSeconds(24)) {
			darknetSizeEstimate24h = stats.getDarknetSizeEstimate(now - HOURS.toMillis(24));
		}
		if(nodeUptimeSeconds > HOURS.toSeconds(48)) {
			darknetSizeEstimate48h = stats.getDarknetSizeEstimate(now - HOURS.toMillis(48));
		}
		// Opennet
		int opennetSizeEstimateSession = stats.getOpennetSizeEstimate(-1);
		int opennetSizeEstimate24h = 0;
		int opennetSizeEstimate48h = 0;
		if (nodeUptimeSeconds > HOURS.toSeconds(24)) {
			opennetSizeEstimate24h = stats.getOpennetSizeEstimate(now - HOURS.toMillis(24));
		}
		if (nodeUptimeSeconds > HOURS.toSeconds(48)) {
			opennetSizeEstimate48h = stats.getOpennetSizeEstimate(now - HOURS.toMillis(48));
		}
		
		double routingMissDistanceLocal =  stats.routingMissDistanceLocal.currentValue();
		double routingMissDistanceRemote =  stats.routingMissDistanceRemote.currentValue();
		double routingMissDistanceOverall =  stats.routingMissDistanceOverall.currentValue();
		double routingMissDistanceBulk =  stats.routingMissDistanceBulk.currentValue();
		double routingMissDistanceRT =  stats.routingMissDistanceRT.currentValue();
		double backedOffPercent =  stats.backedOffPercent.currentValue();
		overviewList.addChild("li", "bwlimitDelayTime:\u00a0" + bwlimitDelayTime + "ms");
		overviewList.addChild("li", "bwlimitDelayTimeBulk:\u00a0" + bwlimitDelayTimeBulk + "ms");
		overviewList.addChild("li", "bwlimitDelayTimeRT:\u00a0" + bwlimitDelayTimeRT + "ms");
		overviewList.addChild("li", "nodeAveragePingTime:\u00a0" + nodeAveragePingTime + "ms");
		overviewList.addChild("li", "darknetSizeEstimateSession:\u00a0" + darknetSizeEstimateSession + "\u00a0nodes");
		if(nodeUptimeSeconds > DAYS.toSeconds(1)) {
			overviewList.addChild("li", "darknetSizeEstimate24h:\u00a0" + darknetSizeEstimate24h + "\u00a0nodes");
		}
		if(nodeUptimeSeconds > DAYS.toSeconds(2)) {
			overviewList.addChild("li", "darknetSizeEstimate48h:\u00a0" + darknetSizeEstimate48h + "\u00a0nodes");
		}
		overviewList.addChild("li", "opennetSizeEstimateSession:\u00a0" + opennetSizeEstimateSession + "\u00a0nodes");
		if (nodeUptimeSeconds > DAYS.toSeconds(1)) {
			overviewList.addChild("li", "opennetSizeEstimate24h:\u00a0" + opennetSizeEstimate24h + "\u00a0nodes");
		}
		if (nodeUptimeSeconds > DAYS.toSeconds(2)) {
			overviewList.addChild("li", "opennetSizeEstimate48h:\u00a0" + opennetSizeEstimate48h + "\u00a0nodes");
		}
		if ((numberOfRemotePeerLocationsSeenInSwaps > 0.0) && ((swaps > 0.0) || (noSwaps > 0.0))) {
			overviewList.addChild("li", "avrConnPeersPerNode:\u00a0" + fix6p6.format(numberOfRemotePeerLocationsSeenInSwaps/(swaps+noSwaps)) + "\u00a0peers");
		}
		overviewList.addChild("li", "nodeUptimeSession:\u00a0" + TimeUtil.formatTime(MILLISECONDS.convert(nodeUptimeSeconds, SECONDS)));
		overviewList.addChild("li", "nodeUptimeTotal:\u00a0" + TimeUtil.formatTime(nodeUptimeTotal));
		overviewList.addChild("li", "routingMissDistanceLocal:\u00a0" + fix1p4.format(routingMissDistanceLocal));
		overviewList.addChild("li", "routingMissDistanceRemote:\u00a0" + fix1p4.format(routingMissDistanceRemote));
		overviewList.addChild("li", "routingMissDistanceOverall:\u00a0" + fix1p4.format(routingMissDistanceOverall));
		overviewList.addChild("li", "routingMissDistanceBulk:\u00a0" + fix1p4.format(routingMissDistanceBulk));
		overviewList.addChild("li", "routingMissDistanceRT:\u00a0" + fix1p4.format(routingMissDistanceRT));
		overviewList.addChild("li", "backedOffPercent:\u00a0" + fix3p1pct.format(backedOffPercent));
		overviewList.addChild("li", "pInstantReject:\u00a0" + fix3p1pct.format(stats.pRejectIncomingInstantly()));
		overviewList.addChild("li", "pInstantRejectRequestBulk:\u00a0" + fix3p1pct.format(stats.pRejectIncomingInstantlyCHKRequestBulk())+" (CHK) "+fix3p1pct.format(stats.pRejectIncomingInstantlySSKRequestBulk())+" (SSK)");
		overviewList.addChild("li", "pInstantRejectInsertBulk:\u00a0" + fix3p1pct.format(stats.pRejectIncomingInstantlyCHKInsertBulk())+" (CHK) "+fix3p1pct.format(stats.pRejectIncomingInstantlySSKInsertBulk())+" (SSK)");
		overviewList.addChild("li", "pInstantRejectRequestRT:\u00a0" + fix3p1pct.format(stats.pRejectIncomingInstantlyCHKRequestRT())+" (CHK) "+fix3p1pct.format(stats.pRejectIncomingInstantlySSKRequestRT())+" (SSK)");
		overviewList.addChild("li", "pInstantRejectInsertRT:\u00a0" + fix3p1pct.format(stats.pRejectIncomingInstantlyCHKInsertRT())+" (CHK) "+fix3p1pct.format(stats.pRejectIncomingInstantlySSKInsertRT())+" (SSK)");
		overviewList.addChild("li", "unclaimedFIFOSize:\u00a0" + node.getUnclaimedFIFOSize());
		overviewList.addChild("li", "RAMBucketPoolSize:\u00a0" + SizeUtil.formatSize(core.tempBucketFactory.getRamUsed())+ " / "+ SizeUtil.formatSize(core.tempBucketFactory.getMaxRamUsed()));
		overviewList.addChild("li", "uptimeAverage:\u00a0" + fix3p1pct.format(node.uptime.getUptime()));
		
		long[] decoded = IncomingPacketFilterImpl.getDecodedPackets();
		if(decoded != null) {
			overviewList.addChild("li", "packetsDecoded:\u00a0"+fix3p1pct.format(((double)decoded[0])/((double)decoded[1]))+"\u00a0("+decoded[1]+")");
		}
		
	}

	private void drawBandwidthBox(HTMLNode bandwidthInfobox, long nodeUptimeSeconds, boolean isAdvancedModeEnabled) {
		
		bandwidthInfobox.addChild("div", "class", "infobox-header", l10n("bandwidthTitle"));
		HTMLNode bandwidthInfoboxContent = bandwidthInfobox.addChild("div", "class", "infobox-content");
		HTMLNode bandwidthList = bandwidthInfoboxContent.addChild("ul");
		drawBandwidth(bandwidthList, node, nodeUptimeSeconds, isAdvancedModeEnabled);
		
	}

	// FIXME this should probably be moved to nodestats so it can be used by FCP??? would have to make ThreadBunch public :<
	private void getThreadNames(HTMLNode threadUsageList) {
		Thread[] threads = stats.getThreads();

		LinkedHashMap<String, ThreadBunch> map = new LinkedHashMap<String, ThreadBunch>();
		int totalCount = 0;
		for(Thread thread: threads) {
			if(thread == null) break;
			String name = NativeThread.normalizeName(thread.getName());
			ThreadBunch bunch = map.get(name);
			if(bunch != null) {
				bunch.count++;
			} else {
				map.put(name, new ThreadBunch(name, 1));
			}
			totalCount++;
		}
		ThreadBunch[] bunches = map.values().toArray(new ThreadBunch[map.size()]);
		Arrays.sort(bunches, new Comparator<ThreadBunch>() {
			@Override
			public int compare(ThreadBunch b0, ThreadBunch b1) {
				if(b0.count > b1.count) return -1;
				if(b0.count < b1.count) return 1;
				return b0.name.compareTo(b1.name);
			}

		});
		double thisThreadPercentOfTotal;
		for(ThreadBunch bunch: bunches) {
			thisThreadPercentOfTotal = ((double) bunch.count) / ((double) totalCount);
			threadUsageList.addChild("li", "" + bunch.name + ":\u00a0" + Integer.toString(bunch.count) + "\u00a0(" + fix3p1pct.format(thisThreadPercentOfTotal) + ')');
		}
	}

	private static class ThreadBunch {
		public ThreadBunch(String name2, int i) {
			this.name = name2;
			this.count = i;
		}
		String name;
		int count;
	}

	private final static int PEER_CIRCLE_RADIUS = 100;
	private final static int PEER_CIRCLE_INNER_RADIUS = 60;
	private final static int PEER_CIRCLE_ADDITIONAL_FREE_SPACE = 10;
	private final static long MAX_CIRCLE_AGE_THRESHOLD = HOURS.toMillis(24);
	private final static int HISTOGRAM_LENGTH = 10;
	
	private int simpleHistogramDivisor(int[] a) {
		int max = 1;
		for (int i = 0; i < a.length; i++) {
			if (a[i] > max) max = a[i];
		}
		return max;
	}
	
	private int combinedHistogramDivisor(int[] a, int[] b) {
		int max = 1;
		for (int i = 0; i < a.length; i++) {
			if (a[i] + b[i] > max) max = a[i] + b[i];
		}
		return max;
	}

	private void addNodeCircle (HTMLNode circleTable, double myLocation) {
		int[] histogram = new int[HISTOGRAM_LENGTH];
		for (int i = 0; i < HISTOGRAM_LENGTH; i++) {
			histogram[i] = 0;
		}
		HTMLNode nodeCircleTableRow = circleTable.addChild("tr");
		HTMLNode nodeHistogramLegendTableRow = circleTable.addChild("tr");
		HTMLNode nodeHistogramGraphTableRow = circleTable.addChild("tr");
		HTMLNode nodeCircleTableCell = nodeCircleTableRow.addChild("td", new String[] { "class", "colspan" }, new String[] {"first", "10"});
		HTMLNode nodeHistogramLegendCell;
		HTMLNode nodeHistogramGraphCell;
		HTMLNode nodeCircleInfoboxContent = nodeCircleTableCell.addChild("div", new String[] { "style", "class" }, new String[] {"position: relative; height: " + ((PEER_CIRCLE_RADIUS + PEER_CIRCLE_ADDITIONAL_FREE_SPACE) * 2) + "px; width: " + ((PEER_CIRCLE_RADIUS + PEER_CIRCLE_ADDITIONAL_FREE_SPACE) * 2) + "px", "peercircle" });
		nodeCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0, false, 1.0),	 "mark" }, "|");
		nodeCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.125, false, 1.0), "mark" }, "+");
		nodeCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.25, false, 1.0),  "mark" }, "--");
		nodeCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.375, false, 1.0), "mark" }, "+");
		nodeCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.5, false, 1.0),   "mark" }, "|");
		nodeCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.625, false, 1.0), "mark" }, "+");
		nodeCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.75, false, 1.0),  "mark" }, "--");
		nodeCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.875, false, 1.0), "mark" }, "+");
		nodeCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { "position: absolute; top: " + PEER_CIRCLE_RADIUS + "px; left: " + (PEER_CIRCLE_RADIUS + PEER_CIRCLE_ADDITIONAL_FREE_SPACE) + "px", "mark" }, "+");
		final Object[] knownLocsCopy = stats.getKnownLocations(-1);
		final Double[] locations = (Double[])knownLocsCopy[0];
		final Long[] timestamps = (Long[])knownLocsCopy[1];
		Double location;
		Long locationTime;
		double strength = 1.0;
		long now = System.currentTimeMillis();
		long age = 1;
		int histogramIndex;
		for(int i=0; i<locations.length; i++){
			location = locations[i];
			locationTime = timestamps[i];
			age = now - locationTime.longValue();
			if( age > MAX_CIRCLE_AGE_THRESHOLD ) {
				age = MAX_CIRCLE_AGE_THRESHOLD;
			}
			strength = 1 - ((double) age / MAX_CIRCLE_AGE_THRESHOLD );
			histogramIndex = (int) (Math.floor(location.doubleValue() * HISTOGRAM_LENGTH));
			histogram[histogramIndex]++;
			
			nodeCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(location.doubleValue(), false, strength), "connected" }, "x");
		}
		nodeCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(myLocation, true, 1.0), "me" }, "x");
		//
		int histogramDiv = simpleHistogramDivisor(histogram); // Prevent division by 0 on empty histograms.
		double histogramPercent;
		for (int i = 0; i < HISTOGRAM_LENGTH; i++) {
			nodeHistogramLegendCell = nodeHistogramLegendTableRow.addChild("td");
			nodeHistogramGraphCell = nodeHistogramGraphTableRow.addChild("td", "style", "height: 100px;");
			nodeHistogramLegendCell.addChild("div", "class", "histogramLabel").addChild("#", fix1p1.format(((double) i) / HISTOGRAM_LENGTH ));
			histogramPercent = (double)histogram[i] / histogramDiv;
			
			// Don't use HTMLNode here to speed things up
			nodeHistogramGraphCell.addChild("%", "<div class=\"histogramConnected\" style=\"height: " + fix3pctUS.format(histogramPercent) + "; width: 100%;\">\u00a0</div>");
		}
	}
	
	private void addSpecialisation(HTMLNode table, double peerLocation, int[] incomingRequestLocation) {
		HTMLNode nodeHistogramLegendTableRow = table.addChild("tr");
		HTMLNode nodeHistogramGraphTableRow = table.addChild("tr");
		int myIndex = (int)(peerLocation * incomingRequestLocation.length);
		int histogramDiv = simpleHistogramDivisor(incomingRequestLocation);
		for (int i = 0; i<incomingRequestLocation.length; i++) {
			HTMLNode nodeHistogramLegendCell = nodeHistogramLegendTableRow.addChild("td");
			HTMLNode nodeHistogramGraphCell = nodeHistogramGraphTableRow.addChild("td", "style", "height: 100px;");
			HTMLNode nodeHistogramGraphCell2 = nodeHistogramLegendCell.addChild("div", "class", "histogramLabel");
			if(i == myIndex)
				 nodeHistogramGraphCell2 = nodeHistogramGraphCell2.addChild("span", "class", "me");
			nodeHistogramGraphCell2.addChild("#", fix1p1.format(((double) i) / incomingRequestLocation.length ));
			nodeHistogramGraphCell.addChild("div", new String[] { "class", "style" }, new String[] { "histogramConnected", "height: " + fix3pctUS.format(((double)incomingRequestLocation[i]) / histogramDiv) + "; width: 100%;" }, "\u00a0");
		}
	}
	
	private void addCombinedSpecialisation(HTMLNode table, double peerLocation, int[] locallyOriginatingRequests, int[] remotelyOriginatingRequests) {
		assert(locallyOriginatingRequests.length == remotelyOriginatingRequests.length);
		HTMLNode nodeHistogramLegendTableRow = table.addChild("tr");
		HTMLNode nodeHistogramGraphTableRow = table.addChild("tr");
		int myIndex = (int)(peerLocation * locallyOriginatingRequests.length);
		int histogramDiv = combinedHistogramDivisor(locallyOriginatingRequests, remotelyOriginatingRequests);
		for (int i = 0; i<locallyOriginatingRequests.length; i++) {
			HTMLNode nodeHistogramLegendCell = nodeHistogramLegendTableRow.addChild("td");
			HTMLNode nodeHistogramGraphCell = nodeHistogramGraphTableRow.addChild("td", "style", "height: 100px;");
			HTMLNode nodeHistogramGraphCell2 = nodeHistogramLegendCell.addChild("div", "class", "histogramLabel");
			if(i == myIndex)
				 nodeHistogramGraphCell2 = nodeHistogramGraphCell2.addChild("span", "class", "me");
			nodeHistogramGraphCell2.addChild("#", fix1p1.format(((double) i) / locallyOriginatingRequests.length ));
			nodeHistogramGraphCell.addChild("div",
				new String[] { "class", "style" },
				new String[] { "histogramConnected", "height: " +
					fix3pctUS.format(((double)locallyOriginatingRequests[i]) / histogramDiv) +
					"; width: 100%;" },
				"\u00a0");
			nodeHistogramGraphCell.addChild("div",
				new String[] { "class", "style" },
				new String[] { "histogramDisconnected", "height: " +
					fix3pctUS.format(((double)remotelyOriginatingRequests[i]) / histogramDiv) +
					"; width: 100%;" },
				"\u00a0");
		}
	}

	private void addFOAFLinkLengthHistogram(HTMLNode circleTable, PeerNodeStatus[] peerNodeStatuses) {
		int[] peersLinkHistogram = new int[HISTOGRAM_LENGTH];
		
		HTMLNode peerHistogramLegendTableRow = circleTable.addChild("tr");
		HTMLNode peerHistogramGraphTableRow = circleTable.addChild("tr");
		HTMLNode peerHistogramLegendCell;
		HTMLNode peerHistogramGraphCell;

		int peersLinkCount = 0;
		for (PeerNodeStatus pns : peerNodeStatuses) {
			if (!pns.isSearchable()) continue;
			if (!pns.isRoutable()) continue;

			double peerLoc = pns.getLocation();
			if (!Location.isValid(peerLoc)) continue;

			double[] foafLocs = pns.getPeersLocation();
			if (foafLocs == null) continue;
			
			for (double foafLoc : foafLocs) {
				if (!Location.isValid(foafLoc)) continue;
				
				int idx = (int)Math.floor(Location.distance(peerLoc, foafLoc) * HISTOGRAM_LENGTH / 0.5);
				peersLinkHistogram[idx]++;
				peersLinkCount++;
			}
		}
		
		double cumulativeFraction = 0;
		for (int i = 0; i < HISTOGRAM_LENGTH; i++) {
			peerHistogramLegendCell = peerHistogramLegendTableRow.addChild("td");
			peerHistogramGraphCell = peerHistogramGraphTableRow.addChild("td", "style", "height: 100px;");
			peerHistogramLegendCell.addChild("div", "class", "histogramLabel").addChild("#", fix1p2.format(((double)i) / HISTOGRAM_LENGTH * 0.5));
			if (peersLinkCount == 0) continue;

			double histogramFraction = ((double)peersLinkHistogram[i]) / peersLinkCount;
			peerHistogramGraphCell.addChild("div", new String[] { "class", "style" }, new String[] { "histogramConnected", "height: " + fix3pctUS.format(histogramFraction) + "; width: 100%;" }, "\u00a0");
			peerHistogramGraphCell.addChild("div", new String[] { "class", "style" }, new String[] { "histogramDisconnected", "height: " + fix3pctUS.format(cumulativeFraction) + "; width: 100%;" }, "\u00a0");
			cumulativeFraction += histogramFraction;
		}
	}

	private void addPeerCircle (HTMLNode circleTable, PeerNodeStatus[] peerNodeStatuses, double myLocation) {
		int[] histogramConnected = new int[HISTOGRAM_LENGTH];
		int[] histogramDisconnected = new int[HISTOGRAM_LENGTH];
		for (int i = 0; i < HISTOGRAM_LENGTH; i++) {
			histogramConnected[i] = 0;
			histogramDisconnected[i] = 0;
		}
		HTMLNode peerCircleTableRow = circleTable.addChild("tr");
		HTMLNode peerHistogramLegendTableRow = circleTable.addChild("tr");
		HTMLNode peerHistogramGraphTableRow = circleTable.addChild("tr");
		HTMLNode peerCircleTableCell = peerCircleTableRow.addChild("td", new String[] { "class", "colspan" }, new String[] {"first", "10"});
		HTMLNode peerHistogramLegendCell;
		HTMLNode peerHistogramGraphCell;
		HTMLNode peerCircleInfoboxContent = peerCircleTableCell.addChild("div", new String[] { "style", "class" }, new String[] {"position: relative; height: " + ((PEER_CIRCLE_RADIUS + PEER_CIRCLE_ADDITIONAL_FREE_SPACE) * 2) + "px; width: " + ((PEER_CIRCLE_RADIUS + PEER_CIRCLE_ADDITIONAL_FREE_SPACE) * 2) + "px", "peercircle" });
		peerCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0, false, 1.0),	 "mark" }, "|");
		peerCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.125, false, 1.0), "mark" }, "+");
		peerCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.25, false, 1.0),  "mark" }, "--");
		peerCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.375, false, 1.0), "mark" }, "+");
		peerCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.5, false, 1.0),   "mark" }, "|");
		peerCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.625, false, 1.0), "mark" }, "+");
		peerCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.75, false, 1.0),  "mark" }, "--");
		peerCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(0.875, false, 1.0), "mark" }, "+");
		peerCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { "position: absolute; top: " + PEER_CIRCLE_RADIUS + "px; left: " + (PEER_CIRCLE_RADIUS + PEER_CIRCLE_ADDITIONAL_FREE_SPACE) + "px", "mark" }, "+");

		PeerNodeStatus peerNodeStatus;
		double peerLocation;
		int histogramIndex;
		int peerCount = peerNodeStatuses.length;
		for (int peerIndex = 0; peerIndex < peerCount; peerIndex++) {
			peerNodeStatus = peerNodeStatuses[peerIndex];
			peerLocation = peerNodeStatus.getLocation();
			if(!peerNodeStatus.isSearchable()) continue;
			if (!Location.isValid(peerLocation)) continue;
			double[] foafLocations=peerNodeStatus.getPeersLocation();
			if (foafLocations!=null && peerNodeStatus.isRoutable()) {
				for (double foafLocation : foafLocations) {
					//one grey dot for each "Friend-of-a-friend"
					peerCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(foafLocation, false, 0.9), "disconnected" }, ".");
				}
			}
			histogramIndex = (int)(peerLocation * HISTOGRAM_LENGTH);
			histogramIndex %= HISTOGRAM_LENGTH; // Map (unlikely) location 1.0 to 0.0
			if (peerNodeStatus.isConnected()) {
				histogramConnected[histogramIndex]++;
			} else {
				histogramDisconnected[histogramIndex]++;
			}
			peerCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(peerLocation, false, (1.0 - peerNodeStatus.getPReject())), ((peerNodeStatus.isConnected())?"connected":"disconnected") }, ((peerNodeStatus.isOpennet())?"o":"x"));
		}
		peerCircleInfoboxContent.addChild("span", new String[] { "style", "class" }, new String[] { generatePeerCircleStyleString(myLocation, true, 1.0), "me" }, "x");
		//
		int histogramDiv = combinedHistogramDivisor(histogramConnected, histogramDisconnected);
		double histogramPercent;
		for (int i = 0; i < HISTOGRAM_LENGTH; i++) {
			peerHistogramLegendCell = peerHistogramLegendTableRow.addChild("td");
			peerHistogramGraphCell = peerHistogramGraphTableRow.addChild("td", "style", "height: 100px;");
			peerHistogramLegendCell.addChild("div", "class", "histogramLabel").addChild("#", fix1p1.format(((double) i) / HISTOGRAM_LENGTH));
			//
			histogramPercent = ((double) histogramConnected[ i ] ) / histogramDiv;
			peerHistogramGraphCell.addChild("div", new String[] { "class", "style" }, new String[] { "histogramConnected", "height: " + fix3pctUS.format(histogramPercent) + "; width: 100%;" }, "\u00a0");
			//
			histogramPercent = ((double) histogramDisconnected[ i ] ) / histogramDiv;
			peerHistogramGraphCell.addChild("div", new String[] { "class", "style" }, new String[] { "histogramDisconnected", "height: " + fix3pctUS.format(histogramPercent) + "; width: 100%;" }, "\u00a0");
		}
	}

	private String generatePeerCircleStyleString (double peerLocation, boolean offsetMe, double strength) {
		peerLocation *= Math.PI * 2;
		//
		int offset = 0;
		if( offsetMe ) {
			// Make our own peer stand out from the crowd better so we can see it easier
			offset = -10;
		} else {
			offset = (int) (PEER_CIRCLE_INNER_RADIUS * (1.0 - strength));
		}
		double x = PEER_CIRCLE_ADDITIONAL_FREE_SPACE + PEER_CIRCLE_RADIUS + Math.sin(peerLocation) * (PEER_CIRCLE_RADIUS - offset);
		double y = PEER_CIRCLE_RADIUS - Math.cos(peerLocation) * (PEER_CIRCLE_RADIUS - offset);  // no PEER_CIRCLE_ADDITIONAL_FREE_SPACE for y-disposition
		//
		return "position: absolute; top: " + fix3p1US.format(y) + "px; left: " + fix3p1US.format(x) + "px";
	}

	@Override
	public String path() {
		return "/stats/";
	}
}
