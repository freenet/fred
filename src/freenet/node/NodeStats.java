package freenet.node;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;

import freenet.config.InvalidConfigValueException;
import freenet.config.NodeNeedRestartException;
import freenet.config.SubConfig;
import freenet.crypt.RandomSource;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.Message;
import freenet.io.xfer.BlockTransmitter.BlockTimeCallback;
import freenet.io.xfer.BulkTransmitter;
import freenet.l10n.NodeL10n;
import freenet.node.RequestTracker.CountedRequests;
import freenet.node.RequestTracker.WaitingForSlots;
import freenet.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import freenet.node.stats.StatsNotAvailableException;
import freenet.node.stats.StoreLocationStats;
import freenet.store.StoreCallback;
import freenet.support.HTMLNode;
import freenet.support.Histogram2;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.SimpleFieldSet;
import freenet.support.StringCounter;
import freenet.support.TimeUtil;
import freenet.support.TokenBucket;
import freenet.support.api.BooleanCallback;
import freenet.support.api.IntCallback;
import freenet.support.api.LongCallback;
import freenet.support.math.BootstrappingDecayingRunningAverage;
import freenet.support.math.DecayingKeyspaceAverage;
import freenet.support.math.RunningAverage;
import freenet.support.math.TimeDecayingRunningAverage;
import freenet.support.math.TrivialRunningAverage;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

/** Node (as opposed to NodeClientCore) level statistics. Includes shouldRejectRequest(), but not limited
 * to stuff required to implement that. */
public class NodeStats implements Persistable, BlockTimeCallback {

	public static enum RequestType {
		CHK_REQUEST,
		SSK_REQUEST,
		CHK_INSERT,
		SSK_INSERT,
		CHK_OFFER_FETCH,
		SSK_OFFER_FETCH;
	}

	/** Histogram for request locations. */
	private static class RequestsByLocation {
		private final int[] bins;
		private int count = 0;

		/** Constructs a request location histogram with the given number of bins. */
		RequestsByLocation(int numBins) {
			bins = new int[numBins];
		}

		/** Update the request counts with a request for the given location. */
		final void report(final double loc) {
			assert(loc >= 0 && loc < 1.0);
			final int bin = (int)Math.floor(loc * bins.length);
			synchronized (this) {
				bins[bin]++;
			}
		}

		/** Get the request count bins. The total request count is placed at position zero of the
		  * given array. */
		final int[] getCounts(final int[] total) {
			final int[] ret = new int[bins.length];
			synchronized (this) {
				System.arraycopy(bins, 0, ret, 0, bins.length);
				total[0] = count;
			}
			return ret;
		}
	}

	/** Sub-max ping time. If ping is greater than this, we reject some requests. */
	public static final long DEFAULT_SUB_MAX_PING_TIME = MILLISECONDS.toMillis(700);
	/** Maximum overall average ping time. If ping is greater than this,
	 * we reject all requests. */
	public static final long DEFAULT_MAX_PING_TIME = MILLISECONDS.toMillis(1500);
	/** Maximum throttled packet delay. If the throttled packet delay is greater
	 * than this, reject all packets. */
	public static final long MAX_THROTTLE_DELAY_RT = SECONDS.toMillis(2);
	public static final long MAX_THROTTLE_DELAY_BULK = SECONDS.toMillis(10);
	/** If the throttled packet delay is less than this, reject no packets; if it's
	 * between the two, reject some packets. */
	public static final long SUB_MAX_THROTTLE_DELAY_RT = SECONDS.toMillis(1);
	public static final long SUB_MAX_THROTTLE_DELAY_BULK = SECONDS.toMillis(5);
	/** How high can bwlimitDelayTime be before we alert (in milliseconds)*/
	public static final long MAX_BWLIMIT_DELAY_TIME_ALERT_THRESHOLD = MAX_THROTTLE_DELAY_BULK;
	/** How high can nodeAveragePingTime be before we alert (in milliseconds)*/
	public static final long MAX_NODE_AVERAGE_PING_TIME_ALERT_THRESHOLD = DEFAULT_MAX_PING_TIME;
	/** How long we're over the bwlimitDelayTime threshold before we alert (in milliseconds)*/
	public static final long MAX_BWLIMIT_DELAY_TIME_ALERT_DELAY = MINUTES.toMillis(10);
	/** How long we're over the nodeAveragePingTime threshold before we alert (in milliseconds)*/
	public static final long MAX_NODE_AVERAGE_PING_TIME_ALERT_DELAY = MINUTES.toMillis(10);
	/** Accept one request every 10 seconds regardless, to ensure we update the
	 * block send time.
	 */
	public static final long MAX_INTERREQUEST_TIME = SECONDS.toMillis(10);

	/** Locations of incoming requests */
	private final RequestsByLocation incomingRequests = new RequestsByLocation(10);
	/** Locations of outgoing requests */
	private final RequestsByLocation outgoingLocalRequests = new RequestsByLocation(10);
	private final RequestsByLocation outgoingRequests = new RequestsByLocation(10);

	private volatile long subMaxPingTime;
	private volatile long maxPingTime;

	final Node node;
	private MemoryChecker myMemoryChecker;
	public final PeerManager peers;

	final RandomSource hardRandom;

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

	/** first time bwlimitDelay was over PeerManagerUserAlert threshold */
	private long firstBwlimitDelayTimeThresholdBreak ;
	/** first time nodeAveragePing was over PeerManagerUserAlert threshold */
	private long firstNodeAveragePingTimeThresholdBreak;
	/** bwlimitDelay PeerManagerUserAlert should happen if true */
	public boolean bwlimitDelayAlertRelevant;
	/** nodeAveragePing PeerManagerUserAlert should happen if true */
	public boolean nodeAveragePingAlertRelevant;
	/** Average proportion of requests rejected immediately due to overload */
	public final BootstrappingDecayingRunningAverage pInstantRejectIncomingOverall;
	public final BootstrappingDecayingRunningAverage pInstantRejectIncomingCHKRequestRT;
	public final BootstrappingDecayingRunningAverage pInstantRejectIncomingSSKRequestRT;
	public final BootstrappingDecayingRunningAverage pInstantRejectIncomingCHKInsertRT;
	public final BootstrappingDecayingRunningAverage pInstantRejectIncomingSSKInsertRT;
	public final BootstrappingDecayingRunningAverage pInstantRejectIncomingCHKRequestBulk;
	public final BootstrappingDecayingRunningAverage pInstantRejectIncomingSSKRequestBulk;
	public final BootstrappingDecayingRunningAverage pInstantRejectIncomingCHKInsertBulk;
	public final BootstrappingDecayingRunningAverage pInstantRejectIncomingSSKInsertBulk;
	private boolean ignoreLocalVsRemoteBandwidthLiability;

	/** Average delay caused by throttling for sending a packet */
	private final RunningAverage throttledPacketSendAverage;
	private final RunningAverage throttledPacketSendAverageRT;
	private final RunningAverage throttledPacketSendAverageBulk;

	// Bytes used by each different type of local/remote chk/ssk request/insert
	final TimeDecayingRunningAverage remoteChkFetchBytesSentAverage;
	final TimeDecayingRunningAverage remoteSskFetchBytesSentAverage;
	final TimeDecayingRunningAverage remoteChkInsertBytesSentAverage;
	final TimeDecayingRunningAverage remoteSskInsertBytesSentAverage;
	final TimeDecayingRunningAverage remoteChkFetchBytesReceivedAverage;
	final TimeDecayingRunningAverage remoteSskFetchBytesReceivedAverage;
	final TimeDecayingRunningAverage remoteChkInsertBytesReceivedAverage;
	final TimeDecayingRunningAverage remoteSskInsertBytesReceivedAverage;
	final TimeDecayingRunningAverage localChkFetchBytesSentAverage;
	final TimeDecayingRunningAverage localSskFetchBytesSentAverage;
	final TimeDecayingRunningAverage localChkInsertBytesSentAverage;
	final TimeDecayingRunningAverage localSskInsertBytesSentAverage;
	final TimeDecayingRunningAverage localChkFetchBytesReceivedAverage;
	final TimeDecayingRunningAverage localSskFetchBytesReceivedAverage;
	final TimeDecayingRunningAverage localChkInsertBytesReceivedAverage;
	final TimeDecayingRunningAverage localSskInsertBytesReceivedAverage;

	// Bytes used by successful chk/ssk request/insert.
	// Note: These are used to determine whether to accept a request,
	// hence they should be roughly representative of incoming - NOT LOCAL -
	// requests. Therefore, while we DO report local successful requests,
	// we only report the portion which will be consistent with a remote
	// request. If there is both a Handler and a Sender, it's a remote
	// request, report both. If there is only a Sender, report only the
	// received bytes (for a request). Etc.

	// Note that these are always reported in the Handler or the NodeClientCore
	// call taking its place.
	final TimeDecayingRunningAverage successfulChkFetchBytesSentAverage;
	final TimeDecayingRunningAverage successfulSskFetchBytesSentAverage;
	final TimeDecayingRunningAverage successfulChkInsertBytesSentAverage;
	final TimeDecayingRunningAverage successfulSskInsertBytesSentAverage;
	final TimeDecayingRunningAverage successfulChkOfferReplyBytesSentAverage;
	final TimeDecayingRunningAverage successfulSskOfferReplyBytesSentAverage;
	final TimeDecayingRunningAverage successfulChkFetchBytesReceivedAverage;
	final TimeDecayingRunningAverage successfulSskFetchBytesReceivedAverage;
	final TimeDecayingRunningAverage successfulChkInsertBytesReceivedAverage;
	final TimeDecayingRunningAverage successfulSskInsertBytesReceivedAverage;
	final TimeDecayingRunningAverage successfulChkOfferReplyBytesReceivedAverage;
	final TimeDecayingRunningAverage successfulSskOfferReplyBytesReceivedAverage;

	final TrivialRunningAverage globalFetchPSuccess;
	final TrivialRunningAverage chkLocalFetchPSuccess;
	final TrivialRunningAverage chkRemoteFetchPSuccess;
	final TrivialRunningAverage sskLocalFetchPSuccess;
	final TrivialRunningAverage sskRemoteFetchPSuccess;
	final TrivialRunningAverage blockTransferPSuccessRT;
	final TrivialRunningAverage blockTransferPSuccessBulk;
	final TrivialRunningAverage blockTransferPSuccessLocal;
	final TrivialRunningAverage blockTransferFailTimeout;

	final TrivialRunningAverage successfulLocalCHKFetchTimeAverageRT;
	final TrivialRunningAverage unsuccessfulLocalCHKFetchTimeAverageRT;
	final TrivialRunningAverage localCHKFetchTimeAverageRT;
	final TrivialRunningAverage successfulLocalCHKFetchTimeAverageBulk;
	final TrivialRunningAverage unsuccessfulLocalCHKFetchTimeAverageBulk;
	final TrivialRunningAverage localCHKFetchTimeAverageBulk;

	final TrivialRunningAverage successfulLocalSSKFetchTimeAverageRT;
	final TrivialRunningAverage unsuccessfulLocalSSKFetchTimeAverageRT;
	final TrivialRunningAverage localSSKFetchTimeAverageRT;
	final TrivialRunningAverage successfulLocalSSKFetchTimeAverageBulk;
	final TrivialRunningAverage unsuccessfulLocalSSKFetchTimeAverageBulk;
	final TrivialRunningAverage localSSKFetchTimeAverageBulk;

	final public Histogram2 chkSuccessRatesByLocation;

	private long previous_input_stat;
	private long previous_output_stat;
	private long previous_io_stat_time;
	private long last_input_stat;
	private long last_output_stat;
	private long last_io_stat_time;
	private final Object ioStatSync = new Object();
	/** Next time to update the node I/O stats */
	private long nextNodeIOStatsUpdateTime = -1;
	/** Node I/O stats update interval (milliseconds) */
	private static final long nodeIOStatsUpdateInterval = 2000;

	// various metrics
	public final RunningAverage routingMissDistanceLocal;
	public final RunningAverage routingMissDistanceRemote;
	public final RunningAverage routingMissDistanceOverall;
	public final RunningAverage routingMissDistanceBulk;
	public final RunningAverage routingMissDistanceRT;
	public final RunningAverage backedOffPercent;
	public final DecayingKeyspaceAverage avgCacheCHKLocation;
	public final DecayingKeyspaceAverage avgSlashdotCacheCHKLocation;
	//public final DecayingKeyspaceAverage avgSlashdotCacheLocation;
	public final DecayingKeyspaceAverage avgStoreCHKLocation;
	//public final DecayingKeyspaceAverage avgStoreLocation;
	public final DecayingKeyspaceAverage avgStoreCHKSuccess;

	// FIXME: does furthest{Store,Cache}Success need to be synchronized?
	public double furthestCacheCHKSuccess=0.0;
	public double furthestClientCacheCHKSuccess=0.0;
	public double furthestSlashdotCacheCHKSuccess=0.0;
	public double furthestStoreCHKSuccess=0.0;
	public double furthestStoreSSKSuccess=0.0;
	public double furthestCacheSSKSuccess=0.0;
	public double furthestClientCacheSSKSuccess=0.0;
	public double furthestSlashdotCacheSSKSuccess=0.0;
	protected final Persister persister;

	protected final DecayingKeyspaceAverage avgRequestLocation;

	// ThreadCounting stuffs
	public final ThreadGroup rootThreadGroup;
	private int threadLimit;

	final NodePinger nodePinger;

	final StringCounter preemptiveRejectReasons;
	final StringCounter localPreemptiveRejectReasons;

	// Enable this if you run into hard to debug OOMs.
	// Disabled to prevent long pauses every 30 seconds.
	private int aggressiveGCModificator = -1 /*250*/;

	// Peers stats
	/** Next time to update PeerManagerUserAlert stats */
	private long nextPeerManagerUserAlertStatsUpdateTime = -1;
	/** PeerManagerUserAlert stats update interval (milliseconds) */
	private static final long peerManagerUserAlertStatsUpdateInterval = 1000;  // 1 second

	// Backoff stats
	final Hashtable<String, TrivialRunningAverage> avgMandatoryBackoffTimesRT;
	final Hashtable<String, TrivialRunningAverage> avgMandatoryBackoffTimesBulk;
	final Hashtable<String, TrivialRunningAverage> avgRoutingBackoffTimesRT;
	final Hashtable<String, TrivialRunningAverage> avgRoutingBackoffTimesBulk;
	final Hashtable<String, TrivialRunningAverage> avgTransferBackoffTimesRT;
	final Hashtable<String, TrivialRunningAverage> avgTransferBackoffTimesBulk;

	// Database stats
	final Hashtable<String, TrivialRunningAverage> avgDatabaseJobExecutionTimes;
	public final DecayingKeyspaceAverage avgClientCacheCHKLocation;
	public final DecayingKeyspaceAverage avgCacheCHKSuccess;
	public final DecayingKeyspaceAverage avgSlashdotCacheCHKSucess;
	public final DecayingKeyspaceAverage avgClientCacheCHKSuccess;

	public final DecayingKeyspaceAverage avgStoreSSKLocation;
	public final DecayingKeyspaceAverage avgCacheSSKLocation;
	public final DecayingKeyspaceAverage avgSlashdotCacheSSKLocation;
	public final DecayingKeyspaceAverage avgClientCacheSSKLocation;

	public final DecayingKeyspaceAverage avgCacheSSKSuccess;
	public final DecayingKeyspaceAverage avgSlashdotCacheSSKSuccess;
	public final DecayingKeyspaceAverage avgClientCacheSSKSuccess;
	public final DecayingKeyspaceAverage avgStoreSSKSuccess;
	
	private volatile boolean enableNewLoadManagementRT;
	private volatile boolean enableNewLoadManagementBulk;

	NodeStats(Node node, int sortOrder, SubConfig statsConfig) throws NodeInitException {
		this.node = node;
		this.peers = node.peers;
		this.hardRandom = node.random;
		this.routingMissDistanceLocal = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
		this.routingMissDistanceRemote = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
		this.routingMissDistanceOverall = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
		this.routingMissDistanceBulk = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
		this.routingMissDistanceRT = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
		this.backedOffPercent = new TimeDecayingRunningAverage(0.0, 180000, 0.0, 1.0, node);
		preemptiveRejectReasons = new StringCounter();
		localPreemptiveRejectReasons = new StringCounter();
		pInstantRejectIncomingOverall = new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
		pInstantRejectIncomingCHKRequestRT = new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
		pInstantRejectIncomingSSKRequestRT = new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
		pInstantRejectIncomingCHKInsertRT = new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
		pInstantRejectIncomingSSKInsertRT = new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
		pInstantRejectIncomingCHKRequestBulk = new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
		pInstantRejectIncomingSSKRequestBulk = new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
		pInstantRejectIncomingCHKInsertBulk = new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
		pInstantRejectIncomingSSKInsertBulk = new BootstrappingDecayingRunningAverage(0.0, 0.0, 1.0, 1000, null);
		REJECT_STATS_AVERAGERS = new RunningAverage[] {
					pInstantRejectIncomingCHKRequestBulk,
					pInstantRejectIncomingSSKRequestBulk,
					pInstantRejectIncomingCHKInsertBulk,
					pInstantRejectIncomingSSKInsertBulk
		};
		noisyRejectStats = new byte[4];
		ThreadGroup tg = Thread.currentThread().getThreadGroup();
		while(tg.getParent() != null) tg = tg.getParent();
		this.rootThreadGroup = tg;
		throttledPacketSendAverage =
			new BootstrappingDecayingRunningAverage(0, 0, Long.MAX_VALUE, 100, null);
		throttledPacketSendAverageRT =
			new BootstrappingDecayingRunningAverage(0, 0, Long.MAX_VALUE, 100, null);
		throttledPacketSendAverageBulk =
			new BootstrappingDecayingRunningAverage(0, 0, Long.MAX_VALUE, 100, null);
		nodePinger = new NodePinger(node);

		previous_input_stat = 0;
		previous_output_stat = 0;
		previous_io_stat_time = 1;
		last_input_stat = 0;
		last_output_stat = 0;
		last_io_stat_time = 3;

		int defaultThreadLimit;
		long memoryLimit = NodeStarter.getMemoryLimitMB();
		
		System.out.println("Memory is "+memoryLimit+"MB");
		if(memoryLimit > 0 && memoryLimit < 100) {
			defaultThreadLimit = 200;
			System.out.println("Severe memory pressure, setting 200 thread limit. Freenet may not work well!");
		} else if(memoryLimit > 0 && memoryLimit < 128) {
			defaultThreadLimit = 300;
			System.out.println("Moderate memory pressure, setting 300 thread limit. Increase your memory limit in wrapper.conf if possible.");
		} else if(memoryLimit > 0 && memoryLimit < 192) {
			defaultThreadLimit = 400;
			System.out.println("Setting 400 thread limit due to <=192MB memory limit. This should be enough but more memory is better.");
		} else {
			System.out.println("Setting standard 500 thread limit. This should be enough for most nodes but more memory is usually a good thing.");
			defaultThreadLimit = 500;
		}
		statsConfig.register("threadLimit", defaultThreadLimit, sortOrder++, true, true, "NodeStat.threadLimit", "NodeStat.threadLimitLong",
				new IntCallback() {
					@Override
					public Integer get() {
						return threadLimit;
					}
					@Override
					public void set(Integer val) throws InvalidConfigValueException {
						if (get().equals(val))
					        return;
						if(val < 100)
							throw new InvalidConfigValueException(l10n("valueTooLow"));
						threadLimit = val;
					}
		},false);
		
		threadLimit = statsConfig.getInt("threadLimit");

		// Yes it could be in seconds insteed of multiples of 0.12, but we don't want people to play with it :)
		statsConfig.register("aggressiveGC", aggressiveGCModificator, sortOrder++, true, false, "NodeStat.aggressiveGC", "NodeStat.aggressiveGCLong",
				new IntCallback() {
					@Override
					public Integer get() {
						return aggressiveGCModificator;
					}
					@Override
					public void set(Integer val) throws InvalidConfigValueException {
						if (get().equals(val))
					        return;
						Logger.normal(this, "Changing aggressiveGCModificator to "+val);
						aggressiveGCModificator = val;
					}
		},false);
		aggressiveGCModificator = statsConfig.getInt("aggressiveGC");

		myMemoryChecker = new MemoryChecker(node.getTicker(), aggressiveGCModificator);
		statsConfig.register("memoryChecker", true, sortOrder++, true, false, "NodeStat.memCheck", "NodeStat.memCheckLong",
				new BooleanCallback(){
					@Override
					public Boolean get() {
						return myMemoryChecker.isRunning();
					}

					@Override
					public void set(Boolean val) throws InvalidConfigValueException {
						if (get().equals(val))
					        return;

						if(val)
							myMemoryChecker.start();
						else
							myMemoryChecker.terminate();
					}
		});
		if(statsConfig.getBoolean("memoryChecker"))
			myMemoryChecker.start();

		statsConfig.register("ignoreLocalVsRemoteBandwidthLiability", false, sortOrder++, true, false, "NodeStat.ignoreLocalVsRemoteBandwidthLiability", "NodeStat.ignoreLocalVsRemoteBandwidthLiabilityLong", new BooleanCallback() {

			@Override
			public Boolean get() {
				synchronized(NodeStats.this) {
					return ignoreLocalVsRemoteBandwidthLiability;
				}
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException {
				synchronized(NodeStats.this) {
					ignoreLocalVsRemoteBandwidthLiability = val;
				}
			}
		});
		ignoreLocalVsRemoteBandwidthLiability = statsConfig.getBoolean("ignoreLocalVsRemoteBandwidthLiability");

		statsConfig.register("maxPingTime", DEFAULT_MAX_PING_TIME, sortOrder++, true, true, "NodeStat.maxPingTime", "NodeStat.maxPingTimeLong", new LongCallback() {

			@Override
			public Long get() {
				return maxPingTime;
			}

			@Override
			public void set(Long val) throws InvalidConfigValueException, NodeNeedRestartException {
				maxPingTime = val;
			}

		}, false);
		maxPingTime = statsConfig.getLong("maxPingTime");

		statsConfig.register("subMaxPingTime", DEFAULT_SUB_MAX_PING_TIME, sortOrder++, true, true, "NodeStat.subMaxPingTime", "NodeStat.subMaxPingTimeLong", new LongCallback() {

			@Override
			public Long get() {
				return subMaxPingTime;
			}

			@Override
			public void set(Long val) throws InvalidConfigValueException, NodeNeedRestartException {
				subMaxPingTime = val;
			}

		}, false);
		subMaxPingTime = statsConfig.getLong("subMaxPingTime");

		// This is a *network* level setting, because it affects the rate at which we initiate local
		// requests, which could be seen by distant nodes.

		node.securityLevels.addNetworkThreatLevelListener(new SecurityLevelListener<NETWORK_THREAT_LEVEL>() {

			@Override
			public void onChange(NETWORK_THREAT_LEVEL oldLevel, NETWORK_THREAT_LEVEL newLevel) {
				if(newLevel == NETWORK_THREAT_LEVEL.MAXIMUM)
					ignoreLocalVsRemoteBandwidthLiability = true;
				if(oldLevel == NETWORK_THREAT_LEVEL.MAXIMUM)
					ignoreLocalVsRemoteBandwidthLiability = false;
				// Otherwise leave it as it was. It defaults to false.
			}

		});
		
		statsConfig.register("enableNewLoadManagementRT", false, sortOrder++, true, false, "Node.enableNewLoadManagementRT", "Node.enableNewLoadManagementRTLong", new BooleanCallback() {

			@Override
			public Boolean get() {
				return enableNewLoadManagementRT;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException,
					NodeNeedRestartException {
				enableNewLoadManagementRT = val;
			}
			
		});
		enableNewLoadManagementRT = statsConfig.getBoolean("enableNewLoadManagementRT");
		statsConfig.register("enableNewLoadManagementBulk", false, sortOrder++, true, false, "Node.enableNewLoadManagementBulk", "Node.enableNewLoadManagementBulkLong", new BooleanCallback() {

			@Override
			public Boolean get() {
				return enableNewLoadManagementBulk;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException,
					NodeNeedRestartException {
				enableNewLoadManagementBulk = val;
			}
			
		});
		enableNewLoadManagementBulk = statsConfig.getBoolean("enableNewLoadManagementBulk");
		
        if(node.lastVersion <= 1455 && (enableNewLoadManagementRT || enableNewLoadManagementBulk)) {
            // FIXME remove
            enableNewLoadManagementRT = false;
            enableNewLoadManagementBulk = false;
            System.err.println("Turning off NLM when upgrading from pre-1455. The load stats messages aren't being sent at the moment so it won't work anyway.");
            statsConfig.config.store();
        }

		persister = new ConfigurablePersister(this, statsConfig, "nodeThrottleFile", "node-throttle.dat", sortOrder++, true, false,
				"NodeStat.statsPersister", "NodeStat.statsPersisterLong", node.ticker, node.getRunDir());

		SimpleFieldSet throttleFS = persister.read();
		if(logMINOR) Logger.minor(this, "Read throttleFS:\n"+throttleFS);

		// Guesstimates. Hopefully well over the reality.
		localChkFetchBytesSentAverage = new TimeDecayingRunningAverage(500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("LocalChkFetchBytesSentAverage"), node);
		localSskFetchBytesSentAverage = new TimeDecayingRunningAverage(500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("LocalSskFetchBytesSentAverage"), node);
		localChkInsertBytesSentAverage = new TimeDecayingRunningAverage(32768, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("LocalChkInsertBytesSentAverage"), node);
		localSskInsertBytesSentAverage = new TimeDecayingRunningAverage(2048, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("LocalSskInsertBytesSentAverage"), node);
		localChkFetchBytesReceivedAverage = new TimeDecayingRunningAverage(32768+2048/*path folding*/, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("LocalChkFetchBytesReceivedAverage"), node);
		localSskFetchBytesReceivedAverage = new TimeDecayingRunningAverage(2048, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("LocalSskFetchBytesReceivedAverage"), node);
		localChkInsertBytesReceivedAverage = new TimeDecayingRunningAverage(1024, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("LocalChkInsertBytesReceivedAverage"), node);
		localSskInsertBytesReceivedAverage = new TimeDecayingRunningAverage(500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("LocalChkInsertBytesReceivedAverage"), node);

		remoteChkFetchBytesSentAverage = new TimeDecayingRunningAverage(32768+1024+500+2048/*path folding*/, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("RemoteChkFetchBytesSentAverage"), node);
		remoteSskFetchBytesSentAverage = new TimeDecayingRunningAverage(1024+1024+500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("RemoteSskFetchBytesSentAverage"), node);
		remoteChkInsertBytesSentAverage = new TimeDecayingRunningAverage(32768+32768+1024, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("RemoteChkInsertBytesSentAverage"), node);
		remoteSskInsertBytesSentAverage = new TimeDecayingRunningAverage(1024+1024+500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("RemoteSskInsertBytesSentAverage"), node);
		remoteChkFetchBytesReceivedAverage = new TimeDecayingRunningAverage(32768+1024+500+2048/*path folding*/, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("RemoteChkFetchBytesReceivedAverage"), node);
		remoteSskFetchBytesReceivedAverage = new TimeDecayingRunningAverage(2048+500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("RemoteSskFetchBytesReceivedAverage"), node);
		remoteChkInsertBytesReceivedAverage = new TimeDecayingRunningAverage(32768+1024+500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("RemoteChkInsertBytesReceivedAverage"), node);
		remoteSskInsertBytesReceivedAverage = new TimeDecayingRunningAverage(1024+1024+500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("RemoteSskInsertBytesReceivedAverage"), node);

		successfulChkFetchBytesSentAverage = new TimeDecayingRunningAverage(32768+1024+500+2048/*path folding*/, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("SuccessfulChkFetchBytesSentAverage"), node);
		successfulSskFetchBytesSentAverage = new TimeDecayingRunningAverage(1024+1024+500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("SuccessfulSskFetchBytesSentAverage"), node);
		successfulChkInsertBytesSentAverage = new TimeDecayingRunningAverage(32768+32768+1024, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("SuccessfulChkInsertBytesSentAverage"), node);
		successfulSskInsertBytesSentAverage = new TimeDecayingRunningAverage(1024+1024+500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("SuccessfulSskInsertBytesSentAverage"), node);
		successfulChkOfferReplyBytesSentAverage = new TimeDecayingRunningAverage(32768+500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("successfulChkOfferReplyBytesSentAverage"), node);
		successfulSskOfferReplyBytesSentAverage = new TimeDecayingRunningAverage(3072, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("successfulSskOfferReplyBytesSentAverage"), node);
		successfulChkFetchBytesReceivedAverage = new TimeDecayingRunningAverage(32768+1024+500+2048/*path folding*/, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("SuccessfulChkFetchBytesReceivedAverage"), node);
		successfulSskFetchBytesReceivedAverage = new TimeDecayingRunningAverage(2048+500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("SuccessfulSskFetchBytesReceivedAverage"), node);
		successfulChkInsertBytesReceivedAverage = new TimeDecayingRunningAverage(32768+1024+500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("SuccessfulChkInsertBytesReceivedAverage"), node);
		successfulSskInsertBytesReceivedAverage = new TimeDecayingRunningAverage(1024+1024+500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("SuccessfulSskInsertBytesReceivedAverage"), node);
		successfulChkOfferReplyBytesReceivedAverage = new TimeDecayingRunningAverage(32768+500, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("successfulChkOfferReplyBytesReceivedAverage"), node);
		successfulSskOfferReplyBytesReceivedAverage = new TimeDecayingRunningAverage(3072, 180000, 0.0, 200*1024, throttleFS == null ? null : throttleFS.subset("successfulSskOfferReplyBytesReceivedAverage"), node);

		globalFetchPSuccess = new TrivialRunningAverage();
		chkLocalFetchPSuccess = new TrivialRunningAverage();
		chkRemoteFetchPSuccess = new TrivialRunningAverage();
		sskLocalFetchPSuccess = new TrivialRunningAverage();
		sskRemoteFetchPSuccess = new TrivialRunningAverage();
		blockTransferPSuccessRT = new TrivialRunningAverage();
		blockTransferPSuccessBulk = new TrivialRunningAverage();
		blockTransferPSuccessLocal = new TrivialRunningAverage();
		blockTransferFailTimeout = new TrivialRunningAverage();

		successfulLocalCHKFetchTimeAverageRT = new TrivialRunningAverage();
		unsuccessfulLocalCHKFetchTimeAverageRT = new TrivialRunningAverage();
		localCHKFetchTimeAverageRT = new TrivialRunningAverage();
		successfulLocalCHKFetchTimeAverageBulk = new TrivialRunningAverage();
		unsuccessfulLocalCHKFetchTimeAverageBulk = new TrivialRunningAverage();
		localCHKFetchTimeAverageBulk = new TrivialRunningAverage();

		successfulLocalSSKFetchTimeAverageRT = new TrivialRunningAverage();
		unsuccessfulLocalSSKFetchTimeAverageRT = new TrivialRunningAverage();
		localSSKFetchTimeAverageRT = new TrivialRunningAverage();
		successfulLocalSSKFetchTimeAverageBulk = new TrivialRunningAverage();
		unsuccessfulLocalSSKFetchTimeAverageBulk = new TrivialRunningAverage();
		localSSKFetchTimeAverageBulk = new TrivialRunningAverage();

		chkSuccessRatesByLocation = new Histogram2(10, 1.0);

		double nodeLoc=node.lm.getLocation();
		this.avgCacheCHKLocation   = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageCacheCHKLocation"));
		this.avgStoreCHKLocation   = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageStoreCHKLocation"));
		this.avgSlashdotCacheCHKLocation = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageSlashdotCacheCHKLocation"));
		this.avgClientCacheCHKLocation = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageClientCacheCHKLocation"));

		this.avgCacheCHKSuccess    = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageCacheCHKSuccessLocation"));
		this.avgSlashdotCacheCHKSucess =  new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageSlashdotCacheCHKSuccessLocation"));
		this.avgClientCacheCHKSuccess    = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageClientCacheCHKSuccessLocation"));
		this.avgStoreCHKSuccess    = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageStoreCHKSuccessLocation"));
		this.avgRequestLocation = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageRequestLocation"));

		this.avgCacheSSKLocation   = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageCacheSSKLocation"));
		this.avgStoreSSKLocation   = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageStoreSSKLocation"));
		this.avgSlashdotCacheSSKLocation = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageSlashdotCacheSSKLocation"));
		this.avgClientCacheSSKLocation = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageClientCacheSSKLocation"));

		this.avgCacheSSKSuccess    = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageCacheSSKSuccessLocation"));
		this.avgSlashdotCacheSSKSuccess =  new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageSlashdotCacheSSKSuccessLocation"));
		this.avgClientCacheSSKSuccess    = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageClientCacheSSKSuccessLocation"));
		this.avgStoreSSKSuccess    = new DecayingKeyspaceAverage(nodeLoc, 10000, throttleFS == null ? null : throttleFS.subset("AverageStoreSSKSuccessLocation"));

		hourlyStatsRT = new HourlyStats(node);
		hourlyStatsBulk = new HourlyStats(node);

		avgMandatoryBackoffTimesRT = new Hashtable<String, TrivialRunningAverage>();
		avgMandatoryBackoffTimesBulk = new Hashtable<String, TrivialRunningAverage>();
		avgRoutingBackoffTimesRT = new Hashtable<String, TrivialRunningAverage>();
		avgRoutingBackoffTimesBulk = new Hashtable<String, TrivialRunningAverage>();
		avgTransferBackoffTimesRT = new Hashtable<String, TrivialRunningAverage>();
		avgTransferBackoffTimesBulk = new Hashtable<String, TrivialRunningAverage>();

		avgDatabaseJobExecutionTimes = new Hashtable<String, TrivialRunningAverage>();
		
		if(!NodeStarter.isTestingVM()) {
			// Normal mode
			minReportsNoisyRejectStats = 200;
			rejectStatsUpdateInterval = MINUTES.toMillis(10);
			rejectStatsFuzz = 10.0;
		} else {
			// Stuff we only do in testing VMs
			minReportsNoisyRejectStats = 1;
			rejectStatsUpdateInterval = SECONDS.toMillis(10);
			rejectStatsFuzz = -1.0;
		}
		statsConfig.finishedInitialization();
	}

	protected String l10n(String key) {
		return NodeL10n.getBase().getString("NodeStats."+key);
	}

	protected String l10n(String key, String[] patterns, String[] values) {
		return NodeL10n.getBase().getString("NodeStats."+key, patterns, values);
	}

	public void start() throws NodeInitException {
		node.executor.execute(new Runnable() {
			@Override
			public void run() {
				nodePinger.start();
			}
		}, "Starting NodePinger");
		persister.start();
		noisyRejectStatsUpdater.run();
	}

	/** Every 60 seconds, check whether we need to adjust the bandwidth delay time because of idleness.
	 * (If no packets have been sent, the throttledPacketSendAverage should decrease; if it doesn't, it may go high,
	 * and then no requests will be accepted, and it will stay high forever. */
	static final long CHECK_THROTTLE_TIME = SECONDS.toMillis(60);
	/** Absolute limit of 4MB queued to any given peer. FIXME make this configurable.
	 * Note that for many MessageItem's, the actual memory usage will be significantly more than this figure. */
	private static final long MAX_PEER_QUEUE_BYTES = 4 * 1024 * 1024;
	/** Don't accept requests if it'll take more than 1 minutes to send the current message queue.
	 * On the assumption that most of the message queue is block transfer data.
	 * Note that this only applies to data on the queue before calling shouldRejectRequest(): we
	 * do *not* attempt to include any estimate of how much the request will add to it. This is
	 * important because if we did, the AIMD may not have reached sufficient speed to transfer it
	 * in 60 seconds yet, because it hasn't had enough data in transit to need to increase its speed.
	 * 
	 * Interaction with output bandwidth liability: This must be slightly larger than the
	 * output bandwidth liability time limit (combined for both types).
	 * 
	 * A fast peer can have slightly more than half our output limit queued in requests to run. 
	 * If they all complete, they will take half the time limit. If they are all served from the 
	 * store, this will be shown on the queue time. But the queue time is estimated based on 
	 * using at most half the limit, so the time will be slightly over the overall limit. */
	
	// FIXME increase to 4 minutes when bulk/realtime flag merged!

	private static final long MAX_PEER_QUEUE_TIME = MINUTES.toMillis(2);

	private long lastAcceptedRequest = -1;

	static final double DEFAULT_OVERHEAD = 0.7;
	static final long DEFAULT_ONLY_PERIOD = MINUTES.toMillis(1);
	static final long DEFAULT_TRANSITION_PERIOD = MINUTES.toMillis(4);
	/** Relatively high minimum overhead. A low overhead estimate becomes a self-fulfilling
	 * prophecy, and it takes a long time to shake it off as the averages gradually increase.
	 * If we accept no requests then everything is overhead! Whereas with a high minimum
	 * overhead the worst case is that more stuff succeeds than expected and we have a few
	 * timeouts (because output bandwidth liability was assuming a lower overhead than
	 * actually happens) - but this should be very rare. */
	static final double MIN_NON_OVERHEAD = 0.5;
	
	// FIXME slowdown
//	/** Proportion of the thread limit we can use without triggering slow-down messages */
//	private static final double SOFT_REJECT_MAX_THREAD_USAGE = 0.9;
//	/** Proportion of the various bandwidth limits we can use without triggering slow-down messages */
//	private static final double SOFT_REJECT_MAX_BANDWIDTH_USAGE = 1.0;
	
	/** All requests must be able to complete in this many seconds given the bandwidth
	 * available, even if they all succeed. Bulk requests. */
	static final int BANDWIDTH_LIABILITY_LIMIT_SECONDS_BULK = 120; //FIXME slowdown (int)(120 / SOFT_REJECT_MAX_BANDWIDTH_USAGE);
	/** All requests must be able to complete in this many seconds given the bandwidth
	 * available, even if they all succeed. Realtime requests - separate from bulk 
	 * requests, given higher priority but expected to be bursty and lower capacity. */
	static final int BANDWIDTH_LIABILITY_LIMIT_SECONDS_REALTIME = 60; //FIXME slowdown (int)(60 / SOFT_REJECT_MAX_BANDWIDTH_USAGE);
	
	/** Stats to send to a single peer so it can determine whether we are likely to reject 
	 * a request. Includes the various limits, but also, the expected transfers
	 * from requests already accepted from other peers (but NOT from this peer).
	 * Note that requests which are sourceRestarted() or reassignToSelf() are
	 * included in "from other peers", as are local requests. */
	public class PeerLoadStats {
		
		public final PeerNode peer;
		/** These do not include those from the peer */
		public final int expectedTransfersOutCHK;
		public final int expectedTransfersInCHK;
		public final int expectedTransfersOutSSK;
		public final int expectedTransfersInSSK;
		public final double outputBandwidthLowerLimit;
		public final double outputBandwidthUpperLimit;
		public final double outputBandwidthPeerLimit;
		public final double inputBandwidthLowerLimit;
		public final double inputBandwidthUpperLimit;
		public final double inputBandwidthPeerLimit;
		public final int totalRequests;
		public final int averageTransfersOutPerInsert;
		public final boolean realTime;
		/** Maximum transfers out - hard limit based on congestion control. */
		public final int maxTransfersOut;
		/** Maximum transfers out - per-peer limit. If total is over the lower limit, we will be accepted
		 * as long as we are below this limit. */
		public final int maxTransfersOutPeerLimit;
		/** Maximum transfers out - lower overall limit. If total is over this limit, we will be accepted
		 * as long as the per-peer usage is above the peer limit. */
		public final int maxTransfersOutLowerLimit;
		/** Maximum transfers out - upper overall limit. Nothing is accepted above this limit. */
		public final int maxTransfersOutUpperLimit;
		
		@Override
		public boolean equals(Object o) {
			if(!(o instanceof PeerLoadStats)) return false;
			PeerLoadStats s = (PeerLoadStats)o;
			if(s.peer != peer) return false;
			if(s.expectedTransfersOutCHK != expectedTransfersOutCHK) return false;
			if(s.expectedTransfersInCHK != expectedTransfersInCHK) return false;
			if(s.expectedTransfersOutSSK != expectedTransfersOutSSK) return false;
			if(s.expectedTransfersInSSK != expectedTransfersInSSK) return false;
			if(s.totalRequests != totalRequests) return false;
			if(s.averageTransfersOutPerInsert != averageTransfersOutPerInsert) return false;
			if(s.outputBandwidthLowerLimit != outputBandwidthLowerLimit) return false;
			if(s.outputBandwidthUpperLimit != outputBandwidthUpperLimit) return false;
			if(s.outputBandwidthPeerLimit != outputBandwidthPeerLimit) return false;
			if(s.inputBandwidthLowerLimit != inputBandwidthLowerLimit) return false;
			if(s.inputBandwidthUpperLimit != inputBandwidthUpperLimit) return false;
			if(s.inputBandwidthPeerLimit != inputBandwidthPeerLimit) return false;
			if(s.maxTransfersOut != maxTransfersOut) return false;
			if(s.maxTransfersOutPeerLimit != maxTransfersOutPeerLimit) return false;
			if(s.maxTransfersOutLowerLimit != maxTransfersOutLowerLimit) return false;
			if(s.maxTransfersOutUpperLimit != maxTransfersOutUpperLimit) return false;
			return true;
		}
		
		@Override
		public int hashCode() {
			return peer.hashCode();
		}
		
		@Override
		public String toString() {
			return peer.toString()+":output:{lower="+outputBandwidthLowerLimit+",upper="+outputBandwidthUpperLimit+",this="+outputBandwidthPeerLimit+"},input:lower="+inputBandwidthLowerLimit+",upper="+inputBandwidthUpperLimit+",peer="+inputBandwidthPeerLimit+"},requests:"+
				"in:"+expectedTransfersInCHK+"chk/"+expectedTransfersInSSK+"ssk:out:"+
				expectedTransfersOutCHK+"chk/"+expectedTransfersOutSSK+"ssk transfers="+maxTransfersOut+"/"+maxTransfersOutPeerLimit+"/"+maxTransfersOutLowerLimit+"/"+maxTransfersOutUpperLimit;
		}
		
		public PeerLoadStats(PeerNode peer, int transfersPerInsert, boolean realTimeFlag) {
			this.peer = peer;
			this.realTime = realTimeFlag;
			long now = System.currentTimeMillis();
			
			double nonOverheadFraction = getNonOverheadFraction(now);
			
			int limit = getLimitSeconds(realTimeFlag);
			
			boolean ignoreLocalVsRemote = ignoreLocalVsRemoteBandwidthLiability();
			
			RunningRequestsSnapshot runningLocal = new RunningRequestsSnapshot(node.tracker, peer, false, ignoreLocalVsRemote, transfersPerInsert, realTimeFlag);
			
			int peers = node.peers.countConnectedPeers();
			
			// Peer limits are adjusted to deduct any requests already allocated by sourceRestarted() requests.
			// I.e. requests which were sent before the peer restarted, which it doesn't know about or failed for when the bootID changed.
			// We try to complete these quickly, but they can stick around for a while sometimes.
			
			// This implies that the sourceRestarted() requests are not counted when checking whether the peer is over the limit.
			
			outputBandwidthUpperLimit = getOutputBandwidthUpperLimit(limit, nonOverheadFraction);
			outputBandwidthLowerLimit = getLowerLimit(outputBandwidthUpperLimit);
			
			inputBandwidthUpperLimit = getInputBandwidthUpperLimit(limit);
			inputBandwidthLowerLimit = getLowerLimit(inputBandwidthUpperLimit);
			
			maxTransfersOutUpperLimit = getMaxTransfersUpperLimit(realTimeFlag, nonOverheadFraction);
			maxTransfersOutLowerLimit = (int)Math.max(1,getLowerLimit(maxTransfersOutUpperLimit));
			maxTransfersOutPeerLimit = (int)Math.max(1,getPeerLimit(peer, maxTransfersOutUpperLimit - maxTransfersOutLowerLimit, peers, runningLocal.expectedTransfersOutCHKSR + runningLocal.expectedTransfersOutSSKSR));
			maxTransfersOut = calculateMaxTransfersOut(peer, realTime, nonOverheadFraction, maxTransfersOutUpperLimit);
			
			outputBandwidthPeerLimit = getPeerLimit(peer, outputBandwidthUpperLimit - outputBandwidthLowerLimit, peers, runningLocal.calculateSR(false));
			inputBandwidthPeerLimit = getPeerLimit(peer, inputBandwidthUpperLimit - inputBandwidthLowerLimit, peers, runningLocal.calculateSR(true));
			
			this.averageTransfersOutPerInsert = transfersPerInsert;
			
			RunningRequestsSnapshot runningGlobal = new RunningRequestsSnapshot(node.tracker, ignoreLocalVsRemote, transfersPerInsert, realTimeFlag);
			expectedTransfersInCHK = runningGlobal.expectedTransfersInCHK - runningLocal.expectedTransfersInCHK;
			expectedTransfersInSSK = runningGlobal.expectedTransfersInSSK - runningLocal.expectedTransfersInSSK;
			expectedTransfersOutCHK = runningGlobal.expectedTransfersOutCHK - runningLocal.expectedTransfersOutCHK;
			expectedTransfersOutSSK = runningGlobal.expectedTransfersOutSSK - runningLocal.expectedTransfersOutSSK;
			totalRequests = runningGlobal.totalRequests - runningLocal.totalRequests;
		}

		public PeerLoadStats(PeerNode source, Message m) {
			peer = source;
			if(m.getSpec() == DMT.FNPPeerLoadStatusInt) {
				expectedTransfersInCHK = m.getInt(DMT.OTHER_TRANSFERS_IN_CHK);
				expectedTransfersInSSK = m.getInt(DMT.OTHER_TRANSFERS_IN_SSK);
				expectedTransfersOutCHK = m.getInt(DMT.OTHER_TRANSFERS_OUT_CHK);
				expectedTransfersOutSSK = m.getInt(DMT.OTHER_TRANSFERS_OUT_SSK);
				averageTransfersOutPerInsert = m.getInt(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT);
				maxTransfersOut = m.getInt(DMT.MAX_TRANSFERS_OUT);
				maxTransfersOutUpperLimit = m.getInt(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT);
				maxTransfersOutLowerLimit = m.getInt(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT);
				maxTransfersOutPeerLimit = m.getInt(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT);
			} else if(m.getSpec() == DMT.FNPPeerLoadStatusShort) {
				expectedTransfersInCHK = m.getShort(DMT.OTHER_TRANSFERS_IN_CHK) & 0xFFFF;
				expectedTransfersInSSK = m.getShort(DMT.OTHER_TRANSFERS_IN_SSK) & 0xFFFF;
				expectedTransfersOutCHK = m.getShort(DMT.OTHER_TRANSFERS_OUT_CHK) & 0xFFFF;
				expectedTransfersOutSSK = m.getShort(DMT.OTHER_TRANSFERS_OUT_SSK) & 0xFFFF;
				averageTransfersOutPerInsert = m.getShort(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT) & 0xFFFF;
				maxTransfersOut = m.getShort(DMT.MAX_TRANSFERS_OUT) & 0xFFFF;
				maxTransfersOutUpperLimit = m.getShort(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT) & 0xFFFF;
				maxTransfersOutLowerLimit = m.getShort(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT) & 0xFFFF;
				maxTransfersOutPeerLimit = m.getShort(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT) & 0xFFFF;
			} else if(m.getSpec() == DMT.FNPPeerLoadStatusByte) {
				expectedTransfersInCHK = m.getByte(DMT.OTHER_TRANSFERS_IN_CHK) & 0xFF;
				expectedTransfersInSSK = m.getByte(DMT.OTHER_TRANSFERS_IN_SSK) & 0xFF;
				expectedTransfersOutCHK = m.getByte(DMT.OTHER_TRANSFERS_OUT_CHK) & 0xFF;
				expectedTransfersOutSSK = m.getByte(DMT.OTHER_TRANSFERS_OUT_SSK) & 0xFF;
				averageTransfersOutPerInsert = m.getByte(DMT.AVERAGE_TRANSFERS_OUT_PER_INSERT) & 0xFF;
				maxTransfersOut = m.getByte(DMT.MAX_TRANSFERS_OUT) & 0xFF;
				maxTransfersOutUpperLimit = m.getByte(DMT.MAX_TRANSFERS_OUT_UPPER_LIMIT) & 0xFF;
				maxTransfersOutLowerLimit = m.getByte(DMT.MAX_TRANSFERS_OUT_LOWER_LIMIT) & 0xFF;
				maxTransfersOutPeerLimit = m.getByte(DMT.MAX_TRANSFERS_OUT_PEER_LIMIT) & 0xFF;
			} else throw new IllegalArgumentException();
			outputBandwidthLowerLimit = m.getInt(DMT.OUTPUT_BANDWIDTH_LOWER_LIMIT);
			outputBandwidthUpperLimit = m.getInt(DMT.OUTPUT_BANDWIDTH_UPPER_LIMIT);
			outputBandwidthPeerLimit = m.getInt(DMT.OUTPUT_BANDWIDTH_PEER_LIMIT);
			inputBandwidthLowerLimit = m.getInt(DMT.INPUT_BANDWIDTH_LOWER_LIMIT);
			inputBandwidthUpperLimit = m.getInt(DMT.INPUT_BANDWIDTH_UPPER_LIMIT);
			inputBandwidthPeerLimit = m.getInt(DMT.INPUT_BANDWIDTH_PEER_LIMIT);
			totalRequests = -1;
			realTime = m.getBoolean(DMT.REAL_TIME_FLAG);
		}

		public RunningRequestsSnapshot getOtherRunningRequests() {
			return new RunningRequestsSnapshot(this);
		}
		
		public double peerLimit(boolean input) {
			if(input)
				return inputBandwidthPeerLimit;
			else
				return outputBandwidthPeerLimit;
		}

		public double lowerLimit(boolean input) {
			if(input)
				return inputBandwidthLowerLimit;
			else
				return outputBandwidthLowerLimit;
		}
		
	}
	
	class RunningRequestsSnapshot {
		
		final int expectedTransfersOutCHK;
		final int expectedTransfersInCHK;
		final int expectedTransfersOutSSK;
		final int expectedTransfersInSSK;
		final int totalRequests;
		final int expectedTransfersOutCHKSR;
		final int expectedTransfersInCHKSR;
		final int expectedTransfersOutSSKSR;
		final int expectedTransfersInSSKSR;
		final int totalRequestsSR;
		final int averageTransfersPerInsert;
		final boolean realTimeFlag;
		
		/** Create a snapshot of all requests running. Because this isn't for any particular peer, 
		 * it includes all requests, even those which are SourceRestarted.
		 * @param tracker The RequestTracker for the Node.
		 * @param ignoreLocalVsRemote If true, pretend that the request is remote even if it's local 
		 * (that is, count imaginary onward transfers etc depending on the request type). 
		 * @param transfersPerInsert Assume that any insert will cause this many outgoing transfers. 
		 * This is not predictable, so we use an average.
		 * @param realTimeFlag If true, count real-time requests, if false, count bulk requests. */
		RunningRequestsSnapshot(RequestTracker tracker, boolean ignoreLocalVsRemote, int transfersPerInsert, boolean realTimeFlag) {
			this.averageTransfersPerInsert = transfersPerInsert;
			this.realTimeFlag = realTimeFlag;
			CountedRequests countCHK = new CountedRequests();
			CountedRequests countSSK = new CountedRequests();
			CountedRequests countCHKSR = new CountedRequests();
			CountedRequests countSSKSR = new CountedRequests();
			tracker.countRequests(true, false, false, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countCHK, countCHKSR);
			tracker.countRequests(true, true, false, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countSSK, countSSKSR);
			tracker.countRequests(true, false, true, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countCHK, countCHKSR);
			tracker.countRequests(true, true, true, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countSSK, countSSKSR);
			tracker.countRequests(false, false, false, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countCHK, countCHKSR);
			tracker.countRequests(false, true, false, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countSSK, countSSKSR);
			tracker.countRequests(false, false, true, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countCHK, countCHKSR);
			tracker.countRequests(false, true, true, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countSSK, countSSKSR);
			tracker.countRequests(false, false, false, true, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countCHK, countCHKSR);
			tracker.countRequests(false, true, false, true, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countSSK, countSSKSR);
			this.expectedTransfersInCHK = countCHK.expectedTransfersIn();
			this.expectedTransfersInSSK = countSSK.expectedTransfersIn();
			this.expectedTransfersOutCHK = countCHK.expectedTransfersOut();
			this.expectedTransfersOutSSK = countSSK.expectedTransfersOut();
			this.totalRequests = countCHK.total() + countSSK.total();
			this.expectedTransfersInCHKSR = countCHKSR.expectedTransfersIn();
			this.expectedTransfersInSSKSR = countSSKSR.expectedTransfersIn();
			this.expectedTransfersOutCHKSR = countCHKSR.expectedTransfersOut();
			this.expectedTransfersOutSSKSR = countSSKSR.expectedTransfersOut();
			this.totalRequestsSR = countCHKSR.total() + countSSKSR.total();
		}
		
		/**
		 * Create a snapshot of either the requests from a node, or the requests 
		 * routed to a node. If we are counting requests from a node, we also fill
		 * in the *SR counters with the counts for requests which have sourceRestarted()
		 * i.e. the requests where the peer has reconnected after a timeout but the 
		 * requests are still running. These are only counted in the *SR totals,
		 * they are not in the basic totals. The caller will reduce the limits
		 * according to the *SR totals, and only consider the non-SR requests when
		 * deciding whether the peer is over the limit. The updated limits are 
		 * sent to the downstream node so that it can send the right number of requests.
		 * @param node We need this to count the requests.
		 * @param source The peer we are interested in.
		 * @param requestsToNode If true, count requests sent to the node and currently
		 * running. If false, count requests originated by the node.
		 */
		RunningRequestsSnapshot(RequestTracker tracker, PeerNode source, boolean requestsToNode, boolean ignoreLocalVsRemote, int transfersPerInsert, boolean realTimeFlag) {
			this.averageTransfersPerInsert = transfersPerInsert;
			this.realTimeFlag = realTimeFlag;
			// We are calculating what part of their resources we use. Therefore, we have
			// to see it from their point of view - meaning all the requests are remote.
			if(requestsToNode) ignoreLocalVsRemote = true;
			CountedRequests countCHK = new CountedRequests();
			CountedRequests countSSK = new CountedRequests();
			CountedRequests countCHKSR = null;
			CountedRequests countSSKSR = null;
			if(!requestsToNode) {
				// No point counting if it's requests to the node.
				// Restarted only matters for requests from a node.
				countCHKSR = new CountedRequests();
				countSSKSR = new CountedRequests();
			}
			tracker.countRequests(source, requestsToNode, true, false, false, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countCHK, countCHKSR);
			tracker.countRequests(source, requestsToNode, true, true, false, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countSSK, countSSKSR);
			tracker.countRequests(source, requestsToNode, true, false, true, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countCHK, countCHKSR);
			tracker.countRequests(source, requestsToNode, true, true, true, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countSSK, countSSKSR);
			tracker.countRequests(source, requestsToNode, false, false, false, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countCHK, countCHKSR);
			tracker.countRequests(source, requestsToNode, false, true, false, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countSSK, countSSKSR);
			tracker.countRequests(source, requestsToNode, false, false, true, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countCHK, countCHKSR);
			tracker.countRequests(source, requestsToNode, false, true, true, false, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countSSK, countSSKSR);
			tracker.countRequests(source, requestsToNode, false, false, false, true, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countCHK, countCHKSR);
			tracker.countRequests(source, requestsToNode, false, true, false, true, realTimeFlag, transfersPerInsert, ignoreLocalVsRemote, countSSK, countSSKSR);
			if(!requestsToNode) {
				this.expectedTransfersInCHKSR = countCHKSR.expectedTransfersIn();
				this.expectedTransfersInSSKSR = countSSKSR.expectedTransfersIn();
				this.expectedTransfersOutCHKSR = countCHKSR.expectedTransfersOut();
				this.expectedTransfersOutSSKSR = countSSKSR.expectedTransfersOut();
				this.totalRequestsSR = countCHKSR.total() + countSSKSR.total();
				this.expectedTransfersInCHK = countCHK.expectedTransfersIn() - expectedTransfersInCHKSR;
				this.expectedTransfersInSSK = countSSK.expectedTransfersIn() - expectedTransfersInSSKSR;
				this.expectedTransfersOutCHK = countCHK.expectedTransfersOut() - expectedTransfersOutCHKSR;
				this.expectedTransfersOutSSK = countSSK.expectedTransfersOut() - expectedTransfersOutSSKSR;
				this.totalRequests = (countCHK.total() + countSSK.total()) - totalRequestsSR;
			} else {
				this.expectedTransfersInCHK = countCHK.expectedTransfersIn();
				this.expectedTransfersInSSK = countSSK.expectedTransfersIn();
				this.expectedTransfersOutCHK = countCHK.expectedTransfersOut();
				this.expectedTransfersOutSSK = countSSK.expectedTransfersOut();
				this.totalRequests = countCHK.total() + countSSK.total();
				this.expectedTransfersInCHKSR = 0;
				this.expectedTransfersInSSKSR = 0;
				this.expectedTransfersOutCHKSR = 0;
				this.expectedTransfersOutSSKSR = 0;
				this.totalRequestsSR = 0;
			}
		}

		public RunningRequestsSnapshot(PeerLoadStats stats) {
			this.realTimeFlag = stats.realTime;
			// Assume they are all remote.
			this.expectedTransfersInCHK = stats.expectedTransfersInCHK;
			this.expectedTransfersInSSK = stats.expectedTransfersInSSK;
			this.expectedTransfersOutCHK = stats.expectedTransfersOutCHK;
			this.expectedTransfersOutSSK = stats.expectedTransfersOutSSK;
			this.totalRequests = stats.totalRequests;
			this.averageTransfersPerInsert = stats.averageTransfersOutPerInsert;
			this.expectedTransfersInCHKSR = 0;
			this.expectedTransfersInSSKSR = 0;
			this.expectedTransfersOutCHKSR = 0;
			this.expectedTransfersOutSSKSR = 0;
			this.totalRequestsSR = 0;
		}
		
		/** For calculating minima only */
		private RunningRequestsSnapshot(int averageTransfersPerInsert) {
			realTimeFlag = false;
			expectedTransfersInCHK = 1;
			expectedTransfersInSSK = 1;
			expectedTransfersOutCHK = 1;
			expectedTransfersOutSSK = 1;
			totalRequests = 1; // Yes this is inconsistent, but it's used for a different calculation.
			this.averageTransfersPerInsert = averageTransfersPerInsert;
			this.expectedTransfersInCHKSR = 0;
			this.expectedTransfersInSSKSR = 0;
			this.expectedTransfersOutCHKSR = 0;
			this.expectedTransfersOutSSKSR = 0;
			this.totalRequestsSR = 0;
		}

		public void log() {
			log(null);
		}
		
		public void log(PeerNode source) {
			String message = 
				"Running (adjusted): CHK in: "+expectedTransfersInCHK+" out: "+expectedTransfersOutCHK+
					" SSK in: "+expectedTransfersInSSK+" out: "+expectedTransfersOutSSK
					+" total="+totalRequests+(source == null ? "" : (" for "+source)) + (realTimeFlag ? " (realtime)" : " (bulk)");
			if(expectedTransfersInCHK < 0 || expectedTransfersOutCHK < 0 ||
					expectedTransfersInSSK < 0 || expectedTransfersOutSSK < 0)
				Logger.error(this, message);
			else
				if(logMINOR) Logger.minor(this, message);
		}

		public double calculate(boolean input) {
			
			if(input)
				return this.expectedTransfersInCHK * (32768+256) +
					this.expectedTransfersInSSK * (2048+256) +
					this.expectedTransfersOutCHK * TRANSFER_OUT_IN_OVERHEAD +
					this.expectedTransfersOutSSK * TRANSFER_OUT_IN_OVERHEAD;
			else
				return this.expectedTransfersOutCHK * (32768+256) +
					this.expectedTransfersOutSSK * (2048+256) +
					expectedTransfersInCHK * TRANSFER_IN_OUT_OVERHEAD +
					expectedTransfersInSSK * TRANSFER_IN_OUT_OVERHEAD;
		}

		public double calculateSR(boolean input) {
			
			if(input)
				return this.expectedTransfersInCHKSR * (32768+256) +
					this.expectedTransfersInSSKSR * (2048+256) +
					this.expectedTransfersOutCHKSR * TRANSFER_OUT_IN_OVERHEAD +
					this.expectedTransfersOutSSKSR * TRANSFER_OUT_IN_OVERHEAD;
			else
				return this.expectedTransfersOutCHKSR * (32768+256) +
					this.expectedTransfersOutSSKSR * (2048+256) +
					expectedTransfersInCHKSR * TRANSFER_IN_OUT_OVERHEAD +
					expectedTransfersInSSKSR * TRANSFER_IN_OUT_OVERHEAD;
		}

		/**
		 * @return The number of requests running or -1 if not known (remote doesn't tell us).
		 */
		public int totalRequests() {
			return totalRequests;
		}

		public int totalOutTransfers() {
			return expectedTransfersOutCHK + expectedTransfersOutSSK;
		}

		public double calculateMinimum(boolean input, int averageTransfersPerInsert) {
			return new RunningRequestsSnapshot(averageTransfersPerInsert).calculate(input);
		}

	}
	
	// Look plausible from my node-throttle.dat stats as of 01/11/2010.
	/** Output bytes required for an inbound transfer. Includes e.g. sending the request
	 * in the first place. */
	static final int TRANSFER_IN_OUT_OVERHEAD = 256;
	/** Input bytes required for an outbound transfer. Includes e.g. sending the insert
	 * etc. */
	static final int TRANSFER_OUT_IN_OVERHEAD = 256;
	
	static class RejectReason {
		public final String name;
		/** If true, rejected because of preemptive bandwidth limiting, i.e. "soft", at least somewhat predictable, can be retried.
		 * If false, hard rejection, should backoff and not retry. */
		public final boolean soft;
		RejectReason(String n, boolean s) {
			name = n;
			soft = s;
		}
		@Override
		public String toString() {
			return (soft ? "SOFT" : "HARD") + ":" + name;
		}
	}
	
	private final Object serializeShouldRejectRequest = new Object();
	
	/** Should a request be accepted by this node, based on its local capacity?
	 * This includes thread limits and ping times, but more importantly, 
	 * mechanisms based on predicting worst case bandwidth usage for all running
	 * requests, and fairly sharing that capacity between peers. Currently there
	 * is no mechanism for fairness between request types, this should be
	 * implemented on the sender side, and is with new load management. New load
	 * management has caused various changes here but that's probably sorted out
	 * now, i.e. changes involved in new load management will probably be mainly
	 * in PeerNode and RequestSender now.
	 * @param canAcceptAnyway Periodically we ignore the ping time and accept a
	 * request anyway. This is because the ping time partly depends on whether
	 * we have accepted any requests... FIXME this should be reconsidered.
	 * @param isInsert Whether this is an insert.
	 * @param isSSK Whether this is a request/insert for an SSK.
	 * @param isLocal Is this request originated locally? This can affect our
	 * estimate of likely bandwidth usage. Whether it should be used is unclear,
	 * since an attacker can observe bandwidth usage. It is configurable.
	 * @param isOfferReply Is this request actually a GetOfferedKey? This is a
	 * non-relayed fetch of a block which we recently offered via ULPRs.
	 * @param source The node that sent us this request. This should be null
	 * on local requests and non-null on remote requests, but in some parts of
	 * the code that doesn't always hold. It *should* hold here, but that needs
	 * more checking before we can remove isLocal.
	 * @param hasInStore If this is a request, do we have the block in the 
	 * datastore already? This affects whether we accept it, which gives a 
	 * significant performance gain. Arguably there is a security issue, 
	 * although timing attacks are pretty easy anyway, and making requests go
	 * further may give attackers more samples...
	 * @param preferInsert If true, prefer inserts to requests (slightly). There
	 * is a flag for this on inserts. The idea is that when inserts are 
	 * misrouted this causes long-term problems because the data is stored in 
	 * the wrong place. New load management should avoid the need for this.
	 * @param realTimeFlag Is this a realtime request (low latency, low capacity)
	 * or a bulk request (high latency, high capacity)? They are accounted for 
	 * separately.
	 * @return The reason for rejecting it, or null to accept it.
	 */
	public RejectReason shouldRejectRequest(boolean canAcceptAnyway, boolean isInsert, boolean isSSK, boolean isLocal, boolean isOfferReply, PeerNode source, boolean hasInStore, boolean preferInsert, boolean realTimeFlag, UIDTag tag) {
		// Serialise shouldRejectRequest.
		// It's not always called on the same thread, and things could be problematic if they interfere with each other.
		synchronized(serializeShouldRejectRequest) {
		if(logMINOR) dumpByteCostAverages();

		if(source != null) {
			if(source.isDisconnecting())
				return new RejectReason("disconnecting", false);
		}
		
		int threadCount = getActiveThreadCount();
		if(threadLimit < threadCount) {
			rejected(">threadLimit", isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);
			return new RejectReason(">threadLimit ("+threadCount+'/'+threadLimit+')', false);
		}
		// FIXME slowdown
//		if(threadLimit < threadCount * SOFT_REJECT_MAX_THREAD_USAGE)
//			slowDown(">softThreadLimit", isLocal, isInsert, isSSK, isOfferReply, realTimeFlag, tag);

		long now = System.currentTimeMillis();
		
		double nonOverheadFraction = getNonOverheadFraction(now);
		
		// If no recent reports, no packets have been sent; correct the average downwards.
		double pingTime;
		pingTime = nodePinger.averagePingTime();
		synchronized(this) {
			// Round trip time
			if(pingTime > maxPingTime) {
				if((now - lastAcceptedRequest > MAX_INTERREQUEST_TIME) && canAcceptAnyway) {
					if(logMINOR) Logger.minor(this, "Accepting request anyway (take one every 10 secs to keep bwlimitDelayTime updated)");
				} else {
					rejected(">MAX_PING_TIME", isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);
					return new RejectReason(">MAX_PING_TIME ("+TimeUtil.formatTime((long)pingTime, 2, true)+ ')', false);
				}
			} else if(pingTime > subMaxPingTime) {
				double x = ((pingTime - subMaxPingTime)) / (maxPingTime - subMaxPingTime);
				if(randomLessThan(x, preferInsert)) {
					rejected(">SUB_MAX_PING_TIME", isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);
					return new RejectReason(">SUB_MAX_PING_TIME ("+TimeUtil.formatTime((long)pingTime, 2, true)+ ')', false);
				}
				// FIXME use slowDown as well as or instead of random here?
			}

		}

		// Pre-emptive rejection based on avoiding timeouts, with fair sharing
		// between peers. We calculate the node's capacity for requests and then
		// decide whether we will exceed it, or whether a particular peer will
		// exceed its slice of it. Peers are guaranteed a proportion of the
		// total ("peer limit"), but can opportunistically use a bit more, 
		// provided the total is less than the "lower limit". The overall usage
		// should not go over the "upper limit".
		
		// This should normally account for the bulk of request rejections.
		
		int transfersPerInsert = outwardTransfersPerInsert();
		
		/** Requests running, globally */
		RunningRequestsSnapshot requestsSnapshot = new RunningRequestsSnapshot(node.tracker, ignoreLocalVsRemoteBandwidthLiability, transfersPerInsert, realTimeFlag);
		
		// Don't need to decrement because it won't be counted until setAccepted() below.

		if(logMINOR)
			requestsSnapshot.log();
		
		long limit = getLimitSeconds(realTimeFlag);
		
		// Allow a bit more if the data is in the store and can therefore be served immediately.
		// This should improve performance.
		if(hasInStore) {
			limit += 10;
			if(logMINOR) Logger.minor(this, "Maybe accepting extra request due to it being in datastore (limit now "+limit+"s)...");
		}
		
		int peers = node.peers.countConnectedPeers();
		
		// These limits are by transfers.
		// We limit the total number of transfers running in parallel to ensure
		// that they don't get starved: The number of seconds a transfer has to
		// wait (for all the others) before it can send needs to be reasonable.
		
		// Whereas the bandwidth-based limit is by bytes, on the principle that
		// it must be possible to complete all transfers within a reasonable time.
		
		/** Requests running for this specific peer (local counts as a peer).
		 * Note that this separately counts requests which have sourceRestarted,
		 * which are not included in the count, and are decremented from the peer limit
		 * before it is used and sent to the peer. This ensures that the peer
		 * doesn't use more than it should after a restart. */
		RunningRequestsSnapshot peerRequestsSnapshot = new RunningRequestsSnapshot(node.tracker, source, false, ignoreLocalVsRemoteBandwidthLiability, transfersPerInsert, realTimeFlag);
		if(logMINOR)
			peerRequestsSnapshot.log(source);
		
		int maxTransfersOutUpperLimit = getMaxTransfersUpperLimit(realTimeFlag, nonOverheadFraction);
		int maxTransfersOutLowerLimit = (int)Math.max(1,getLowerLimit(maxTransfersOutUpperLimit));
		int maxTransfersOutPeerLimit = (int)Math.max(1,getPeerLimit(source, maxTransfersOutUpperLimit - maxTransfersOutLowerLimit, peers, (peerRequestsSnapshot.expectedTransfersOutCHKSR + peerRequestsSnapshot.expectedTransfersOutSSKSR)));
		/** Per-peer limit based on current state of the connection. */
		int maxOutputTransfers = this.calculateMaxTransfersOut(source, realTimeFlag, nonOverheadFraction, maxTransfersOutUpperLimit);
		
		// Check bandwidth-based limits, with fair sharing.
		
		String ret = checkBandwidthLiability(getOutputBandwidthUpperLimit(limit, nonOverheadFraction), requestsSnapshot, peerRequestsSnapshot, false,
				source, isLocal, isSSK, isInsert, isOfferReply, realTimeFlag, maxOutputTransfers, maxTransfersOutPeerLimit);
		if(ret != null) {
			return new RejectReason(ret, true);
		}
		
		ret = checkBandwidthLiability(getInputBandwidthUpperLimit(limit), requestsSnapshot, peerRequestsSnapshot, true,
				source, isLocal, isSSK, isInsert, isOfferReply, realTimeFlag, maxOutputTransfers, maxTransfersOutPeerLimit);
		if(ret != null) {
			return new RejectReason(ret, true);
		}
		
		// Check transfer-based limits, with fair sharing.
		
		ret = checkMaxOutputTransfers(maxOutputTransfers, maxTransfersOutUpperLimit, maxTransfersOutLowerLimit, maxTransfersOutPeerLimit,
				requestsSnapshot, peerRequestsSnapshot, isLocal, realTimeFlag, isInsert, isSSK, isOfferReply);
		if(ret != null) {
			return new RejectReason(ret, true);
		}
		
		// Message queues - when the link level has far more queued than it
		// can transmit in a reasonable time, don't accept requests.
		if(source != null) {
			if(source.getMessageQueueLengthBytes() > MAX_PEER_QUEUE_BYTES) {
				rejected(">MAX_PEER_QUEUE_BYTES", isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);
				return new RejectReason("Too many message bytes queued for peer", false);
				// FIXME slowDown?
			}
			if(source.getProbableSendQueueTime() > MAX_PEER_QUEUE_TIME) {
				rejected(">MAX_PEER_QUEUE_TIME", isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);
				return new RejectReason("Peer's queue will take too long to transfer", false);
				// FIXME slowDown?
			}
		}
		
		synchronized(this) {
			if(logMINOR) Logger.minor(this, "Accepting request? (isSSK="+isSSK+")");
			lastAcceptedRequest = now;
		}
		
		accepted(isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);

		if(tag != null) tag.setAccepted();
		
		// Accept
		return null;
		}
	}
	
//	private void slowDown(String reason, boolean isLocal, boolean isInsert,
//			boolean isSSK, boolean isOfferReply, boolean realTimeFlag,
//			UIDTag tag) {
//		if(isLocal || isOfferReply) return;
//		if(logMINOR) Logger.minor(this, "Slow down: "+reason+" insert="+isInsert+" SSK="+isSSK+" realTimeFlag="+realTimeFlag);
//		tag.slowDown();
//	}

	private int getLimitSeconds(boolean realTimeFlag) {
		return realTimeFlag ? BANDWIDTH_LIABILITY_LIMIT_SECONDS_REALTIME : BANDWIDTH_LIABILITY_LIMIT_SECONDS_BULK;
	}

	public int calculateMaxTransfersOut(PeerNode peer, boolean realTime,
			double nonOverheadFraction, int maxTransfersOutUpperLimit) {
		if(peer == null) return Integer.MAX_VALUE;
		else return Math.min(maxTransfersOutUpperLimit, peer.calculateMaxTransfersOut(getAcceptableBlockTime(realTime), nonOverheadFraction));
	}

	private int getAcceptableBlockTime(boolean realTime) {
		return realTime ? 2 : 15;
	}

	static final double ONE_PEER_MAX_PEERS_EQUIVALENT = 2.0;
	
	public double getLowerLimit(double upperLimit) {
		// Bandwidth scheduling is now unfair, based on deadlines.
		// Therefore we can allocate a large chunk of our capacity to a single peer.
		return upperLimit / 2;
	}

	public int outwardTransfersPerInsert() {
		// FIXME compute an average
		return 1;
	}

	private double getInputBandwidthUpperLimit(long limit) {
		return node.getInputBandwidthLimit() * limit;
	}

	private double getNonOverheadFraction(long now) {
		
		long[] total = node.collector.getTotalIO();
		long totalSent = total[0];
		long totalOverhead = getSentOverhead();
		long uptime = node.getUptime();
		
		/** The fraction of output bytes which are used for requests */
		// FIXME consider using a shorter average
		// FIXME what happens when the bwlimit changes?
		
		double totalCouldSend = Math.max(totalSent,
				(((node.getOutputBandwidthLimit() * uptime))/1000.0));
		double nonOverheadFraction = (totalCouldSend - totalOverhead) / totalCouldSend;
		long timeFirstAnyConnections = peers.timeFirstAnyConnections;
		if(timeFirstAnyConnections > 0) {
			long time = now - timeFirstAnyConnections;
			if(time < DEFAULT_ONLY_PERIOD) {
				nonOverheadFraction = DEFAULT_OVERHEAD;
				if(logMINOR) Logger.minor(this, "Adjusted non-overhead fraction: "+nonOverheadFraction);
			} else if(time < DEFAULT_ONLY_PERIOD + DEFAULT_TRANSITION_PERIOD) {
				time -= DEFAULT_ONLY_PERIOD;
				nonOverheadFraction = (time * nonOverheadFraction + 
					(DEFAULT_TRANSITION_PERIOD - time) * DEFAULT_OVERHEAD) / DEFAULT_TRANSITION_PERIOD;
				if(logMINOR) Logger.minor(this, "Adjusted non-overhead fraction: "+nonOverheadFraction);
			}
		}
		if(nonOverheadFraction < MIN_NON_OVERHEAD) {
			// If there's been an auto-update, we may have used a vast amount of bandwidth for it.
			// Also, if things have broken, our overhead might be above our bandwidth limit,
			// especially on a slow node.
			
			// So impose a minimum of 20% of the bandwidth limit.
			// This will ensure we don't get stuck in any situation where all our bandwidth is overhead,
			// and we don't accept any requests because of that, so it remains that way...
			Logger.warning(this, "Non-overhead fraction is "+nonOverheadFraction+" - assuming this is self-inflicted and using default");
			nonOverheadFraction = MIN_NON_OVERHEAD;
		}
		if(nonOverheadFraction > 1.0) {
			Logger.error(this, "Non-overhead fraction is >1.0!!!");
			return 1.0;
		}
		return nonOverheadFraction;
	}

	private double getOutputBandwidthUpperLimit(long limit, double nonOverheadFraction) {
		double outputAvailablePerSecond = node.getOutputBandwidthLimit() * nonOverheadFraction;
		return outputAvailablePerSecond * limit;
	}
	
	private int getMaxTransfersUpperLimit(boolean realTime, double nonOverheadFraction) {
		// FIXME refactor with getOutputBandwidthUpperLimit so we can avoid calling it twice.
		double outputAvailablePerSecond = node.getOutputBandwidthLimit() * nonOverheadFraction;
		
		return (int)Math.max(1, (getAcceptableBlockTime(realTime) * outputAvailablePerSecond) / 1024.0);
	}

	/** Should the request be rejected due to bandwidth liability? Enforces fair
	 * sharing between peers, while allowing peers to opportunistically use a bit
	 * more than their fair share as long as the total is below the lower limit.
	 * Used for both bandwidth-based limiting and transfer-count-based limiting.
	 * 
	 * @param bandwidthAvailableOutputUpperLimit The overall upper limit, already calculated.
	 * @param requestsSnapshot The requests running.
	 * @param peerRequestsSnapshot The requests running to this one peer.
	 * @param input True if this is input bandwidth, false if it is output bandwidth.
	 * @param source The source of the request.
	 * @param isLocal True if the request is local.
	 * @param isSSK True if it is an SSK request.
	 * @param isInsert True if it is an insert.
	 * @param isOfferReply True if it is a GetOfferedKey.
	 * @param realTimeFlag True if this is a real-time request, false if it is a bulk
	 * request.
	 * @return A string explaining why, or null if we can accept the request.
	 */
	private String checkBandwidthLiability(double bandwidthAvailableOutputUpperLimit,
			RunningRequestsSnapshot requestsSnapshot, RunningRequestsSnapshot peerRequestsSnapshot, boolean input,
			PeerNode source, boolean isLocal, boolean isSSK, boolean isInsert, boolean isOfferReply, boolean realTimeFlag, int maxOutputTransfers, int maxOutputTransfersPeerLimit) {
		String name = input ? "Input" : "Output";
		int peers = node.peers.countConnectedPeers();
		
		double bandwidthAvailableOutputLowerLimit = getLowerLimit(bandwidthAvailableOutputUpperLimit);
		
		double bandwidthLiabilityOutput = requestsSnapshot.calculate(input);
		
		// Calculate the peer limit so the peer gets notified, even if we are going to ignore it.
		
		double thisAllocation = getPeerLimit(source, bandwidthAvailableOutputUpperLimit - bandwidthAvailableOutputLowerLimit, peers, peerRequestsSnapshot.calculateSR(input));
		
		if(SEND_LOAD_STATS_NOTICES && source != null) {
			// FIXME tell local as well somehow?
			if(!input) {
				source.onSetMaxOutputTransfers(realTimeFlag, maxOutputTransfers);
				source.onSetMaxOutputTransfersPeerLimit(realTimeFlag, maxOutputTransfersPeerLimit);
			}
			source.onSetPeerAllocation(input, (int)thisAllocation, realTimeFlag);
		}
		
		// Ignore the upper limit.
		// Because we reassignToSelf() in various tricky timeout conditions, it is possible to exceed it.
		// Even if we do we still need to allow the guaranteed allocation for each peer.
		// Except when we do that, we have to offer it via ULPRs afterwards ...
		// Yes but the GetOfferedKey's are subject to load management, so no problem.
		if(bandwidthLiabilityOutput > bandwidthAvailableOutputUpperLimit) {
			Logger.warning(this, "Above upper limit. Not rejecting as this can occasionally happen due to reassigns: upper limit "+bandwidthAvailableOutputUpperLimit+" usage is "+bandwidthLiabilityOutput);
		}
		
		if(bandwidthLiabilityOutput > bandwidthAvailableOutputLowerLimit) {
			
			// Bandwidth is scarce (we are over the lower limit i.e. more than half our capacity is used).
			// Share available bandwidth fairly between peers.
			
			if(logMINOR)
				Logger.minor(this, "Allocation ("+name+") for "+source+" is "+thisAllocation+" total usage is "+bandwidthLiabilityOutput+" of lower limit"+bandwidthAvailableOutputLowerLimit+" upper limit is "+bandwidthAvailableOutputUpperLimit+" for "+name);
			
			double peerUsedBytes = getPeerBandwidthLiability(peerRequestsSnapshot, input);
			if(peerUsedBytes > thisAllocation) {
				rejected(name+" bandwidth liability: fairness between peers", isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);
				return name+" bandwidth liability: fairness between peers (peer "+source+" used "+peerUsedBytes+" allowed "+thisAllocation+")";
			// FIXME slowdown
//			} else {
//				double slowDownLimit = thisAllocation * SOFT_REJECT_MAX_BANDWIDTH_USAGE;
//				// Allow any node to use one request of each type. They'll just have to get backed off if necessary.
//				slowDownLimit = Math.max(slowDownLimit, requestsSnapshot.calculateMinimum(input, ignoreLocalVsRemoteBandwidthLiability, transfersPerInsert));
//				if(peerUsedBytes > slowDownLimit) {
//					// Sender should slow down if we are using more than 80% of our fair share of capacity.
//					slowDown(name+" bandwidth liability: fairness between peers", isLocal, isInsert, isSSK, isOfferReply, realTimeFlag, tag);
//				}
			}
			
		} else {
			
			// Plenty of bandwidth available, allow one peer to use up to the lower limit (about half the total).
			
			// slowDown() is unnecessary, we do NOT want to keep the total below the lower limit.
			
			if(logMINOR)
				Logger.minor(this, "Total usage is "+bandwidthLiabilityOutput+" below lower limit "+bandwidthAvailableOutputLowerLimit+" for "+name);
		}
		return null;
	}
	
	private String checkMaxOutputTransfers(int maxOutputTransfers,
			int maxTransfersOutUpperLimit, int maxTransfersOutLowerLimit,
			int maxTransfersOutPeerLimit,
			RunningRequestsSnapshot requestsSnapshot,
			RunningRequestsSnapshot peerRequestsSnapshot, boolean isLocal, boolean realTime,
			boolean isInsert, boolean isSSK, boolean isOfferReply) {
		if(logMINOR) Logger.minor(this, "Max transfers: congestion control limit "+maxOutputTransfers+
				" upper "+maxTransfersOutUpperLimit+" lower "+maxTransfersOutLowerLimit+" peer "+maxTransfersOutPeerLimit+" "+(realTime ? "(rt)" : "(bulk)"));
		int peerOutTransfers = peerRequestsSnapshot.totalOutTransfers();
		int totalOutTransfers = requestsSnapshot.totalOutTransfers();
		if(peerOutTransfers > maxOutputTransfers && !isLocal) {
			// Can't handle that many transfers with current bandwidth.
			rejected("TooManyTransfers: Congestion control", isLocal, isInsert, isSSK, isOfferReply, realTime);
			return "TooManyTransfers: Congestion control";
		}
		if(totalOutTransfers <= maxTransfersOutLowerLimit) {
			// If the total is below the lower limit, then fine, go for it.
			// Do not send slow-down's, we have plenty of spare bandwidth.
			return null;
		}
		if(peerOutTransfers <= maxTransfersOutPeerLimit) {
			// The total is above the lower limit, but the per-peer is below the peer limit.
			// It is within its guaranteed space, so we accept it.
			// FIXME slowdown
//			if(peerOutTransfers > Math.max(1, maxTransfersOutPeerLimit * SOFT_REJECT_MAX_BANDWIDTH_USAGE))
//				// Send slow-down's if we are using more than 80% of our peer limit.
//				slowDown("TooManyTransfers: Fair sharing between peers", isLocal, isInsert, isSSK, isOfferReply, realTime, tag);
			return null;
		}
		rejected("TooManyTransfers: Fair sharing between peers", isLocal, isInsert, isSSK, isOfferReply, realTime);
		return "TooManyTransfers: Fair sharing between peers";
	}



	static final boolean SEND_LOAD_STATS_NOTICES = true;
	
	/**
	 * @param source The peer.
	 * @param totalGuaranteedBandwidth The difference between the upper and lower overall
	 * bandwidth limits. If the total usage is less than the lower limit, we do not 
	 * enforce fairness. Any node may therefore optimistically try to use up to the lower
	 * limit. However, the node is only guaranteed its fair share, which is defined as its
	 * fraction of the part of the total that is above the lower limit.
	 * @param dontTellPeer
	 * @param peers
	 * @param sourceRestarted 
	 * @return
	 */
	private double getPeerLimit(PeerNode source, double totalGuaranteedBandwidth, int peers, double sourceRestarted) {
		
		double thisAllocation;
		double totalAllocation = totalGuaranteedBandwidth;
		// FIXME: MAKE CONFIGURABLE AND SECLEVEL DEPENDANT!
		double localAllocation = totalAllocation * 0.5;
		if (source == null)
		    thisAllocation = localAllocation;
		else {
		    totalAllocation -= localAllocation;
		    thisAllocation = totalAllocation / peers;
		}
		
		if(logMINOR && sourceRestarted != 0)
			Logger.minor(this, "Allocation is "+thisAllocation+" source restarted is "+sourceRestarted);
		return thisAllocation - sourceRestarted;
		
	}

	/** Calculate the worst-case bytes used by a specific peer. This will be
	 * compared to its peer limit, and if it is higher, the request may be 
	 * rejected.
	 * @param requestsSnapshot Snapshot of requests running from the peer.
	 * @param input If true, calculate input bytes, if false, calculate output bytes.
	 * @return
	 */
	private double getPeerBandwidthLiability(RunningRequestsSnapshot requestsSnapshot, boolean input) {
		
		return requestsSnapshot.calculate(input);
	}

	/** @return True if we should reject the request.
	 * @param x The threshold. We should reject the request unless a random number is greater than this threshold.
	 * @param preferInsert If true, we allow 3 chances to pass the threshold.
	 */
	private boolean randomLessThan(double x, boolean preferInsert) {
		if(preferInsert) {
			// Three chances.
			for(int i=0;i<3;i++)
				if(hardRandom.nextDouble() >= x) return false;
			return true;
		} else {
			// One chance
		}
		return hardRandom.nextDouble() < x;
	}

	private void rejected(String reason, boolean isLocal, boolean isInsert, boolean isSSK, boolean isOfferReply, boolean isRealTime) {
		reason += " "+(isRealTime?" (rt)":" (bulk)");
		if(logMINOR) Logger.minor(this, "Rejecting (local="+isLocal+") isSSK="+isSSK+" isInsert="+isInsert+" : "+reason);
		if(!isLocal) preemptiveRejectReasons.inc(reason);
		else this.localPreemptiveRejectReasons.inc(reason);
		if(!isLocal && !isOfferReply) {
			this.pInstantRejectIncomingOverall.report(1.0);
			getRejectedTracker(isRealTime, isSSK, isInsert).report(1.0);
		}
	}
	
	private void accepted(boolean isLocal, boolean isInsert, boolean isSSK,
			boolean isOfferReply, boolean realTimeFlag) {
		if(!isLocal && !isOfferReply) {
			pInstantRejectIncomingOverall.report(0.0);
			getRejectedTracker(realTimeFlag, isSSK, isInsert).report(0.0);
		}
	}

	private BootstrappingDecayingRunningAverage getRejectedTracker(
			boolean isRealTime, boolean isSSK, boolean isInsert) {
		if(isRealTime) {
			if(isSSK) {
				return isInsert ? pInstantRejectIncomingSSKInsertRT : pInstantRejectIncomingSSKRequestRT;
			} else {
				return isInsert ? pInstantRejectIncomingCHKInsertRT : pInstantRejectIncomingCHKRequestRT;
			}
		} else {
			if(isSSK) {
				return isInsert ? pInstantRejectIncomingSSKInsertBulk : pInstantRejectIncomingSSKRequestBulk;
			} else {
				return isInsert ? pInstantRejectIncomingCHKInsertBulk : pInstantRejectIncomingCHKRequestBulk;
			}
		}
	}

	private RunningAverage getThrottle(boolean isLocal, boolean isInsert, boolean isSSK, boolean isSent) {
		if(isLocal) {
			if(isInsert) {
				if(isSSK) {
					return isSent ? this.localSskInsertBytesSentAverage : this.localSskInsertBytesReceivedAverage;
				} else {
					return isSent ? this.localChkInsertBytesSentAverage : this.localChkInsertBytesReceivedAverage;
				}
			} else {
				if(isSSK) {
					return isSent ? this.localSskFetchBytesSentAverage : this.localSskFetchBytesReceivedAverage;
				} else {
					return isSent ? this.localChkFetchBytesSentAverage : this.localChkFetchBytesReceivedAverage;
				}
			}
		} else {
			if(isInsert) {
				if(isSSK) {
					return isSent ? this.remoteSskInsertBytesSentAverage : this.remoteSskInsertBytesReceivedAverage;
				} else {
					return isSent ? this.remoteChkInsertBytesSentAverage : this.remoteChkInsertBytesReceivedAverage;
				}
			} else {
				if(isSSK) {
					return isSent ? this.remoteSskFetchBytesSentAverage : this.remoteSskFetchBytesReceivedAverage;
				} else {
					return isSent ? this.remoteChkFetchBytesSentAverage : this.remoteChkFetchBytesReceivedAverage;
				}
			}
		}
	}

	private void dumpByteCostAverages() {
		Logger.minor(this, "Byte cost averages: REMOTE:"+
				" CHK insert "+remoteChkInsertBytesSentAverage.currentValue()+ '/' +remoteChkInsertBytesReceivedAverage.currentValue()+
				" SSK insert "+remoteSskInsertBytesSentAverage.currentValue()+ '/' +remoteSskInsertBytesReceivedAverage.currentValue()+
				" CHK fetch "+remoteChkFetchBytesSentAverage.currentValue()+ '/' +remoteChkFetchBytesReceivedAverage.currentValue()+
				" SSK fetch "+remoteSskFetchBytesSentAverage.currentValue()+ '/' +remoteSskFetchBytesReceivedAverage.currentValue());
		Logger.minor(this, "Byte cost averages: LOCAL:"+
				" CHK insert "+localChkInsertBytesSentAverage.currentValue()+ '/' +localChkInsertBytesReceivedAverage.currentValue()+
				" SSK insert "+localSskInsertBytesSentAverage.currentValue()+ '/' +localSskInsertBytesReceivedAverage.currentValue()+
				" CHK fetch "+localChkFetchBytesSentAverage.currentValue()+ '/' +localChkFetchBytesReceivedAverage.currentValue()+
				" SSK fetch "+localSskFetchBytesSentAverage.currentValue()+ '/' +localSskFetchBytesReceivedAverage.currentValue());
		Logger.minor(this, "Byte cost averages: SUCCESSFUL:"+
				" CHK insert "+successfulChkInsertBytesSentAverage.currentValue()+ '/' +successfulChkInsertBytesReceivedAverage.currentValue()+
				" SSK insert "+successfulSskInsertBytesSentAverage.currentValue()+ '/' +successfulSskInsertBytesReceivedAverage.currentValue()+
				" CHK fetch "+successfulChkFetchBytesSentAverage.currentValue()+ '/' +successfulChkFetchBytesReceivedAverage.currentValue()+
				" SSK fetch "+successfulSskFetchBytesSentAverage.currentValue()+ '/' +successfulSskFetchBytesReceivedAverage.currentValue()+
				" CHK offer reply "+successfulChkOfferReplyBytesSentAverage.currentValue()+ '/' +successfulChkOfferReplyBytesReceivedAverage.currentValue()+
				" SSK offer reply "+successfulSskOfferReplyBytesSentAverage.currentValue()+ '/' +successfulSskOfferReplyBytesReceivedAverage.currentValue());

	}

	public double getBwlimitDelayTimeRT() {
		return throttledPacketSendAverageRT.currentValue();
	}

	public double getBwlimitDelayTimeBulk() {
		return throttledPacketSendAverageBulk.currentValue();
	}

	public double getBwlimitDelayTime() {
		return throttledPacketSendAverage.currentValue();
	}

	public double getNodeAveragePingTime() {
		return nodePinger.averagePingTime();
	}

	public int getOpennetSizeEstimate(long timestamp) {
		if (node.opennet == null)
			return 0;
		return node.opennet.getNetworkSizeEstimate(timestamp);
	}
	public int getDarknetSizeEstimate(long timestamp) {
		return node.lm.getNetworkSizeEstimate( timestamp );
	}

	public Object[] getKnownLocations(long timestamp) {
		return node.lm.getKnownLocations( timestamp );
	}

	public double pRejectIncomingInstantly() {
		return pInstantRejectIncomingOverall.currentValue();
	}

	public double pRejectIncomingInstantlyCHKRequestRT() {
		return pInstantRejectIncomingCHKRequestRT.currentValue();
	}

	public double pRejectIncomingInstantlyCHKInsertRT() {
		return pInstantRejectIncomingCHKInsertRT.currentValue();
	}

	public double pRejectIncomingInstantlySSKRequestRT() {
		return pInstantRejectIncomingSSKRequestRT.currentValue();
	}

	public double pRejectIncomingInstantlySSKInsertRT() {
		return pInstantRejectIncomingSSKInsertRT.currentValue();
	}

	public double pRejectIncomingInstantlyCHKRequestBulk() {
		return pInstantRejectIncomingCHKRequestBulk.currentValue();
	}

	public double pRejectIncomingInstantlyCHKInsertBulk() {
		return pInstantRejectIncomingCHKInsertBulk.currentValue();
	}

	public double pRejectIncomingInstantlySSKRequestBulk() {
		return pInstantRejectIncomingSSKRequestBulk.currentValue();
	}

	public double pRejectIncomingInstantlySSKInsertBulk() {
		return pInstantRejectIncomingSSKInsertBulk.currentValue();
	}

	/**
	 * Update peerManagerUserAlertStats if the timer has expired.
	 * Only called from PacketSender so doesn't need sync.
	 */
	public void maybeUpdatePeerManagerUserAlertStats(long now) {
		if(now > nextPeerManagerUserAlertStatsUpdateTime) {
			if(getBwlimitDelayTime() > MAX_BWLIMIT_DELAY_TIME_ALERT_THRESHOLD) {
				if(firstBwlimitDelayTimeThresholdBreak == 0) {
					firstBwlimitDelayTimeThresholdBreak = now;
				}
			} else {
				firstBwlimitDelayTimeThresholdBreak = 0;
			}
			if((firstBwlimitDelayTimeThresholdBreak != 0) && ((now - firstBwlimitDelayTimeThresholdBreak) >= MAX_BWLIMIT_DELAY_TIME_ALERT_DELAY)) {
				bwlimitDelayAlertRelevant = true;
			} else {
				bwlimitDelayAlertRelevant = false;
			}
			if(getNodeAveragePingTime() > 2*maxPingTime) {
				if(firstNodeAveragePingTimeThresholdBreak == 0) {
					firstNodeAveragePingTimeThresholdBreak = now;
				}
			} else {
				firstNodeAveragePingTimeThresholdBreak = 0;
			}
			if((firstNodeAveragePingTimeThresholdBreak != 0) && ((now - firstNodeAveragePingTimeThresholdBreak) >= MAX_NODE_AVERAGE_PING_TIME_ALERT_DELAY)) {
				nodeAveragePingAlertRelevant = true;
			} else {
				nodeAveragePingAlertRelevant = false;
			}
			if(logDEBUG) Logger.debug(this, "mUPMUAS: "+now+": "+getBwlimitDelayTime()+" >? "+MAX_BWLIMIT_DELAY_TIME_ALERT_THRESHOLD+" since "+firstBwlimitDelayTimeThresholdBreak+" ("+bwlimitDelayAlertRelevant+") "+getNodeAveragePingTime()+" >? "+MAX_NODE_AVERAGE_PING_TIME_ALERT_THRESHOLD+" since "+firstNodeAveragePingTimeThresholdBreak+" ("+nodeAveragePingAlertRelevant+ ')');
			nextPeerManagerUserAlertStatsUpdateTime = now + peerManagerUserAlertStatsUpdateInterval;
		}
	}

	@Override
	public SimpleFieldSet persistThrottlesToFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.put("RemoteChkFetchBytesSentAverage", remoteChkFetchBytesSentAverage.exportFieldSet(true));
		fs.put("RemoteSskFetchBytesSentAverage", remoteSskFetchBytesSentAverage.exportFieldSet(true));
		fs.put("RemoteChkInsertBytesSentAverage", remoteChkInsertBytesSentAverage.exportFieldSet(true));
		fs.put("RemoteSskInsertBytesSentAverage", remoteSskInsertBytesSentAverage.exportFieldSet(true));
		fs.put("RemoteChkFetchBytesReceivedAverage", remoteChkFetchBytesReceivedAverage.exportFieldSet(true));
		fs.put("RemoteSskFetchBytesReceivedAverage", remoteSskFetchBytesReceivedAverage.exportFieldSet(true));
		fs.put("RemoteChkInsertBytesReceivedAverage", remoteChkInsertBytesReceivedAverage.exportFieldSet(true));
		fs.put("RemoteSskInsertBytesReceivedAverage", remoteSskInsertBytesReceivedAverage.exportFieldSet(true));
		fs.put("LocalChkFetchBytesSentAverage", localChkFetchBytesSentAverage.exportFieldSet(true));
		fs.put("LocalSskFetchBytesSentAverage", localSskFetchBytesSentAverage.exportFieldSet(true));
		fs.put("LocalChkInsertBytesSentAverage", localChkInsertBytesSentAverage.exportFieldSet(true));
		fs.put("LocalSskInsertBytesSentAverage", localSskInsertBytesSentAverage.exportFieldSet(true));
		fs.put("LocalChkFetchBytesReceivedAverage", localChkFetchBytesReceivedAverage.exportFieldSet(true));
		fs.put("LocalSskFetchBytesReceivedAverage", localSskFetchBytesReceivedAverage.exportFieldSet(true));
		fs.put("LocalChkInsertBytesReceivedAverage", localChkInsertBytesReceivedAverage.exportFieldSet(true));
		fs.put("LocalSskInsertBytesReceivedAverage", localSskInsertBytesReceivedAverage.exportFieldSet(true));
		fs.put("SuccessfulChkFetchBytesSentAverage", successfulChkFetchBytesSentAverage.exportFieldSet(true));
		fs.put("SuccessfulSskFetchBytesSentAverage", successfulSskFetchBytesSentAverage.exportFieldSet(true));
		fs.put("SuccessfulChkInsertBytesSentAverage", successfulChkInsertBytesSentAverage.exportFieldSet(true));
		fs.put("SuccessfulSskInsertBytesSentAverage", successfulSskInsertBytesSentAverage.exportFieldSet(true));
		fs.put("SuccessfulChkOfferReplyBytesSentAverage", successfulChkOfferReplyBytesSentAverage.exportFieldSet(true));
		fs.put("SuccessfulSskOfferReplyBytesSentAverage", successfulSskOfferReplyBytesSentAverage.exportFieldSet(true));
		fs.put("SuccessfulChkFetchBytesReceivedAverage", successfulChkFetchBytesReceivedAverage.exportFieldSet(true));
		fs.put("SuccessfulSskFetchBytesReceivedAverage", successfulSskFetchBytesReceivedAverage.exportFieldSet(true));
		fs.put("SuccessfulChkInsertBytesReceivedAverage", successfulChkInsertBytesReceivedAverage.exportFieldSet(true));
		fs.put("SuccessfulSskInsertBytesReceivedAverage", successfulSskInsertBytesReceivedAverage.exportFieldSet(true));
		fs.put("SuccessfulChkOfferReplyBytesReceivedAverage", successfulChkOfferReplyBytesReceivedAverage.exportFieldSet(true));
		fs.put("SuccessfulSskOfferReplyBytesReceivedAverage", successfulSskOfferReplyBytesReceivedAverage.exportFieldSet(true));

		//These are not really part of the 'throttling' data, but are also running averages which should be persisted
		fs.put("AverageCacheCHKLocation", avgCacheCHKLocation.exportFieldSet(true));
		fs.put("AverageStoreCHKLocation", avgStoreCHKLocation.exportFieldSet(true));
		fs.put("AverageSlashdotCacheCHKLocation",avgSlashdotCacheCHKLocation.exportFieldSet(true));
		fs.put("AverageClientCacheCHKLocation",avgClientCacheCHKLocation.exportFieldSet(true));

		fs.put("AverageCacheCHKSuccessLocation", avgCacheCHKSuccess.exportFieldSet(true));
		fs.put("AverageSlashdotCacheCHKSuccessLocation", avgSlashdotCacheCHKSucess.exportFieldSet(true));
		fs.put("AverageClientCacheCHKSuccessLocation", avgClientCacheCHKSuccess.exportFieldSet(true));
		fs.put("AverageStoreCHKSuccessLocation", avgStoreCHKSuccess.exportFieldSet(true));

		fs.put("AverageCacheSSKLocation", avgCacheSSKLocation.exportFieldSet(true));
		fs.put("AverageStoreSSKLocation", avgStoreSSKLocation.exportFieldSet(true));
		fs.put("AverageSlashdotCacheSSKLocation",avgSlashdotCacheSSKLocation.exportFieldSet(true));
		fs.put("AverageClientCacheSSKLocation",avgClientCacheSSKLocation.exportFieldSet(true));

		fs.put("AverageCacheSSKSuccessLocation", avgCacheSSKSuccess.exportFieldSet(true));
		fs.put("AverageSlashdotCacheSSKSuccessLocation", avgSlashdotCacheSSKSuccess.exportFieldSet(true));
		fs.put("AverageClientCacheSSKSuccessLocation", avgClientCacheSSKSuccess.exportFieldSet(true));
		fs.put("AverageStoreSSKSuccessLocation", avgStoreSSKSuccess.exportFieldSet(true));

		fs.put("AverageRequestLocation", avgRequestLocation.exportFieldSet(true));

		return fs;
	}

	/**
	 * Update the node-wide bandwidth I/O stats if the timer has expired
	 */
	public void maybeUpdateNodeIOStats(long now) {
		if(now > nextNodeIOStatsUpdateTime) {
			long[] io_stats = node.collector.getTotalIO();
			long outdiff;
			long indiff;
			synchronized(ioStatSync) {
				previous_output_stat = last_output_stat;
				previous_input_stat = last_input_stat;
				previous_io_stat_time = last_io_stat_time;
				last_output_stat = io_stats[ 0 ];
				last_input_stat = io_stats[ 1 ];
				last_io_stat_time = now;
				outdiff = last_output_stat - previous_output_stat;
				indiff = last_input_stat - previous_input_stat;
			}
			if(logMINOR)
				Logger.minor(this, "Last 2 seconds: input: "+indiff+" output: "+outdiff);
			nextNodeIOStatsUpdateTime = now + nodeIOStatsUpdateInterval;
		}
	}

	public long[] getNodeIOStats() {
		long[] result = new long[6];
		synchronized(ioStatSync) {
			result[ 0 ] = previous_output_stat;
			result[ 1 ] = previous_input_stat;
			result[ 2 ] = previous_io_stat_time;
			result[ 3 ] = last_output_stat;
			result[ 4 ] = last_input_stat;
			result[ 5 ] = last_io_stat_time;
		}
		return result;
	}

	public void waitUntilNotOverloaded() {
		while(threadLimit < getActiveThreadCount()){
			try{
				Thread.sleep(5000);
			} catch (InterruptedException e) {}
		}
	}

	public int getActiveThreadCount() {
		return rootThreadGroup.activeCount() - node.executor.getWaitingThreadsCount();
	}

	public int[] getActiveThreadsByPriority() {
		return node.executor.runningThreads();
	}

	public int[] getWaitingThreadsByPriority() {
		return node.executor.waitingThreads();
	}

	public int getThreadLimit() {
		return threadLimit;
	}

	/**
	 * Gets a copy of the thread list. The result might contain null values:
	 * The end of the list is marked by a null entry in the array.
	 */
	public Thread[] getThreads() {
		int count = 0;
		Thread[] threads;
		while(true) {
			count = Math.max(rootThreadGroup.activeCount(), count);
			threads = new Thread[count*2+50];
			rootThreadGroup.enumerate(threads);
			if(threads[threads.length-1] == null) break;
		}

		return threads;
	}

	public SimpleFieldSet exportVolatileFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		long now = System.currentTimeMillis();
		fs.put("isUsingWrapper", node.isUsingWrapper());
		long nodeUptimeSeconds = 0;
		synchronized(this) {
			fs.put("startupTime", node.startupTime);
			nodeUptimeSeconds = (now - node.startupTime) / 1000;
			if (nodeUptimeSeconds == 0) nodeUptimeSeconds = 1;	// prevent division by zero
			fs.put("uptimeSeconds", nodeUptimeSeconds);
		}
		fs.put("averagePingTime", getNodeAveragePingTime());
		fs.put("bwlimitDelayTime", getBwlimitDelayTime());
		fs.put("bwlimitDelayTimeRT", getBwlimitDelayTimeRT());
		fs.put("bwlimitDelayTimeBulk", getBwlimitDelayTimeBulk());

		// Network Size
		fs.put("opennetSizeEstimateSession", getOpennetSizeEstimate(-1));
		fs.put("networkSizeEstimateSession", getDarknetSizeEstimate(-1));
		for (int t = 1 ; t < 7; t++) {
			int hour = t * 24;
			long limit = now - DAYS.toMillis(t);

			fs.put("opennetSizeEstimate"+hour+"hourRecent", getOpennetSizeEstimate(limit));
			fs.put("networkSizeEstimate"+hour+"hourRecent", getDarknetSizeEstimate(limit));
		}
		fs.put("routingMissDistanceLocal", routingMissDistanceLocal.currentValue());
		fs.put("routingMissDistanceRemote", routingMissDistanceRemote.currentValue());
		fs.put("routingMissDistanceOverall", routingMissDistanceOverall.currentValue());
		fs.put("routingMissDistanceBulk", routingMissDistanceBulk.currentValue());
		fs.put("routingMissDistanceRT", routingMissDistanceRT.currentValue());
		
		fs.put("backedOffPercent", backedOffPercent.currentValue());
		fs.put("pInstantReject", pRejectIncomingInstantly());
		fs.put("unclaimedFIFOSize", node.usm.getUnclaimedFIFOSize());
		fs.put("RAMBucketPoolSize", node.clientCore.tempBucketFactory.getRamUsed());

		/* gather connection statistics */
		PeerNodeStatus[] peerNodeStatuses = peers.getPeerNodeStatuses(true);
		int numberOfSeedServers = 0;
		int numberOfSeedClients = 0;

		for (PeerNodeStatus peerNodeStatus: peerNodeStatuses) {
			if (peerNodeStatus.isSeedServer())
				numberOfSeedServers++;
			if (peerNodeStatus.isSeedClient())
				numberOfSeedClients++;
		}

		int numberOfConnected = PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_CONNECTED);
		int numberOfRoutingBackedOff = PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF);
		int numberOfTooNew = PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_NEW);
		int numberOfTooOld = PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_TOO_OLD);
		int numberOfDisconnected = PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISCONNECTED);
		int numberOfNeverConnected = PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_NEVER_CONNECTED);
		int numberOfDisabled = PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_DISABLED);
		int numberOfBursting = PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_BURSTING);
		int numberOfListening = PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTENING);
		int numberOfListenOnly = PeerNodeStatus.getPeerStatusCount(peerNodeStatuses, PeerManager.PEER_NODE_STATUS_LISTEN_ONLY);

		int numberOfSimpleConnected = numberOfConnected + numberOfRoutingBackedOff;
		int numberOfNotConnected = numberOfTooNew + numberOfTooOld + numberOfDisconnected + numberOfNeverConnected + numberOfDisabled + numberOfBursting + numberOfListening + numberOfListenOnly;

		fs.put("numberOfSeedServers", numberOfSeedServers);
		fs.put("numberOfSeedClients", numberOfSeedClients);
		fs.put("numberOfConnected", numberOfConnected);
		fs.put("numberOfRoutingBackedOff", numberOfRoutingBackedOff);
		fs.put("numberOfTooNew", numberOfTooNew);
		fs.put("numberOfTooOld", numberOfTooOld);
		fs.put("numberOfDisconnected", numberOfDisconnected);
		fs.put("numberOfNeverConnected", numberOfNeverConnected);
		fs.put("numberOfDisabled", numberOfDisabled);
		fs.put("numberOfBursting", numberOfBursting);
		fs.put("numberOfListening", numberOfListening);
		fs.put("numberOfListenOnly", numberOfListenOnly);

		fs.put("numberOfSimpleConnected", numberOfSimpleConnected);
		fs.put("numberOfNotConnected", numberOfNotConnected);

		fs.put("numberOfTransferringRequestSenders", node.tracker.getNumTransferringRequestSenders());
		fs.put("numberOfARKFetchers", node.getNumARKFetchers());
		fs.put("bandwidthLiabilityUsageOutputBulk", node.nodeStats.getBandwidthLiabilityUsage());
		
		RequestTracker tracker = node.tracker;

		fs.put("numberOfLocalCHKInserts", tracker.getNumLocalCHKInserts());
		fs.put("numberOfRemoteCHKInserts", tracker.getNumRemoteCHKInserts());
		fs.put("numberOfLocalSSKInserts", tracker.getNumLocalSSKInserts());
		fs.put("numberOfRemoteSSKInserts", tracker.getNumRemoteSSKInserts());
		fs.put("numberOfLocalCHKRequests", tracker.getNumLocalCHKRequests());
		fs.put("numberOfRemoteCHKRequests", tracker.getNumRemoteCHKRequests());
		fs.put("numberOfLocalSSKRequests", tracker.getNumLocalSSKRequests());
		fs.put("numberOfRemoteSSKRequests", tracker.getNumRemoteSSKRequests());
		fs.put("numberOfTransferringRequestHandlers", node.tracker.getNumTransferringRequestHandlers());
		fs.put("numberOfCHKOfferReplys", tracker.getNumCHKOfferReplies());
		fs.put("numberOfSSKOfferReplys", tracker.getNumSSKOfferReplies());

		fs.put("delayTimeLocalRT", nlmDelayRTLocal.currentValue());
		fs.put("delayTimeRemoteRT", nlmDelayRTRemote.currentValue());
		fs.put("delayTimeLocalBulk", nlmDelayBulkLocal.currentValue());
		fs.put("delayTimeRemoteBulk", nlmDelayBulkRemote.currentValue());
		synchronized(slotTimeoutsSync) {
		    // timeoutFractions = fatalTimeouts/(fatalTimeouts+allocatedSlot)
		    fs.put("fatalTimeoutsLocal",fatalTimeoutsInWaitLocal);
		    fs.put("fatalTimeoutsRemote",fatalTimeoutsInWaitRemote);
		    fs.put("allocatedSlotLocal",allocatedSlotLocal);
		    fs.put("allocatedSlotRemote",allocatedSlotRemote);
		}

		WaitingForSlots waitingSlots = tracker.countRequestsWaitingForSlots();
		fs.put("RequestsWaitingSlotsLocal", waitingSlots.local);
		fs.put("RequestsWaitingSlotsRemote", waitingSlots.remote);

		fs.put("successfulLocalCHKFetchTimeBulk", successfulLocalCHKFetchTimeAverageBulk.currentValue());
		fs.put("successfulLocalCHKFetchTimeRT", successfulLocalCHKFetchTimeAverageRT.currentValue());
		fs.put("unsuccessfulLocalCHKFetchTimeBulk", unsuccessfulLocalCHKFetchTimeAverageBulk.currentValue());
		fs.put("unsuccessfulLocalCHKFetchTimeRT", unsuccessfulLocalCHKFetchTimeAverageRT.currentValue());

		fs.put("successfulLocalSSKFetchTimeBulk", successfulLocalSSKFetchTimeAverageBulk.currentValue());
		fs.put("successfulLocalSSKFetchTimeRT", successfulLocalSSKFetchTimeAverageRT.currentValue());
		fs.put("unsuccessfulLocalSSKFetchTimeBulk", unsuccessfulLocalSSKFetchTimeAverageBulk.currentValue());
		fs.put("unsuccessfulLocalSSKFetchTimeRT", unsuccessfulLocalSSKFetchTimeAverageRT.currentValue());

		long[] total = node.collector.getTotalIO();
		long total_output_rate = (total[0]) / nodeUptimeSeconds;
		long total_input_rate = (total[1]) / nodeUptimeSeconds;
		long totalPayloadOutput = node.getTotalPayloadSent();
		long total_payload_output_rate = totalPayloadOutput / nodeUptimeSeconds;
		int total_payload_output_percent = (total[0]==0)?-1:(int) (100 * totalPayloadOutput / total[0]);
		fs.put("totalOutputBytes", total[0]);
		fs.put("totalOutputRate", total_output_rate);
		fs.put("totalPayloadOutputBytes", totalPayloadOutput);
		fs.put("totalPayloadOutputRate", total_payload_output_rate);
		fs.put("totalPayloadOutputPercent", total_payload_output_percent);
		fs.put("totalInputBytes", total[1]);
		fs.put("totalInputRate", total_input_rate);

		long[] rate = getNodeIOStats();
		long deltaMS = (rate[5] - rate[2]);
		double recent_output_rate = deltaMS==0?0:(1000.0 * (rate[3] - rate[0]) / deltaMS);
		double recent_input_rate = deltaMS==0?0:(1000.0 * (rate[4] - rate[1]) / deltaMS);
		fs.put("recentOutputRate", recent_output_rate);
		fs.put("recentInputRate", recent_input_rate);

		fs.put("ackOnlyBytes", getNotificationOnlyPacketsSentBytes());
		fs.put("resentBytes", getResendBytesSent());
		fs.put("updaterOutputBytes", getUOMBytesSent());
		fs.put("announcePayloadBytes", getAnnounceBytesPayloadSent());
		fs.put("announceSentBytes", getAnnounceBytesSent());

		String [] routingBackoffReasons = peers.getPeerNodeRoutingBackoffReasons(true);
		if(routingBackoffReasons.length != 0) {
			for(String routingBackoffReason: routingBackoffReasons) {
				fs.put("numberWithRoutingBackoffReasonsRT." + routingBackoffReason, peers.getPeerNodeRoutingBackoffReasonSize(routingBackoffReason, true));
			}
		}

		routingBackoffReasons = peers.getPeerNodeRoutingBackoffReasons(false);
		if(routingBackoffReasons.length != 0) {
			for(String routingBackoffReason: routingBackoffReasons) {
				fs.put("numberWithRoutingBackoffReasonsBulk." + routingBackoffReason, peers.getPeerNodeRoutingBackoffReasonSize(routingBackoffReason, false));
			}
		}

		double swaps = node.getSwaps();
		double noSwaps = node.getNoSwaps();
		double numberOfRemotePeerLocationsSeenInSwaps = node.getNumberOfRemotePeerLocationsSeenInSwaps();
		fs.put("numberOfRemotePeerLocationsSeenInSwaps", numberOfRemotePeerLocationsSeenInSwaps);
		double avgConnectedPeersPerNode = 0.0;
		if ((numberOfRemotePeerLocationsSeenInSwaps > 0.0) && ((swaps > 0.0) || (noSwaps > 0.0))) {
			avgConnectedPeersPerNode = numberOfRemotePeerLocationsSeenInSwaps/(swaps+noSwaps);
		}
		fs.put("avgConnectedPeersPerNode", avgConnectedPeersPerNode);

		int startedSwaps = node.getStartedSwaps();
		int swapsRejectedAlreadyLocked = node.getSwapsRejectedAlreadyLocked();
		int swapsRejectedNowhereToGo = node.getSwapsRejectedNowhereToGo();
		int swapsRejectedRateLimit = node.getSwapsRejectedRateLimit();
		int swapsRejectedRecognizedID = node.getSwapsRejectedRecognizedID();
		double locationChangePerSession = node.getLocationChangeSession();
		double locationChangePerSwap = 0.0;
		double locationChangePerMinute = 0.0;
		double swapsPerMinute = 0.0;
		double noSwapsPerMinute = 0.0;
		double swapsPerNoSwaps = 0.0;
		if (swaps > 0) {
			locationChangePerSwap = locationChangePerSession/swaps;
		}
		if ((swaps > 0.0) && (nodeUptimeSeconds >= 60)) {
			locationChangePerMinute = locationChangePerSession/(nodeUptimeSeconds/60.0);
		}
		if ((swaps > 0.0) && (nodeUptimeSeconds >= 60)) {
			swapsPerMinute = swaps/(nodeUptimeSeconds/60.0);
		}
		if ((noSwaps > 0.0) && (nodeUptimeSeconds >= 60)) {
			noSwapsPerMinute = noSwaps/(nodeUptimeSeconds/60.0);
		}
		if ((swaps > 0.0) && (noSwaps > 0.0)) {
			swapsPerNoSwaps = swaps/noSwaps;
		}
		fs.put("locationChangePerSession", locationChangePerSession);
		fs.put("locationChangePerSwap", locationChangePerSwap);
		fs.put("locationChangePerMinute", locationChangePerMinute);
		fs.put("swapsPerMinute", swapsPerMinute);
		fs.put("noSwapsPerMinute", noSwapsPerMinute);
		fs.put("swapsPerNoSwaps", swapsPerNoSwaps);
		fs.put("swaps", swaps);
		fs.put("noSwaps", noSwaps);
		fs.put("startedSwaps", startedSwaps);
		fs.put("swapsRejectedAlreadyLocked", swapsRejectedAlreadyLocked);
		fs.put("swapsRejectedNowhereToGo", swapsRejectedNowhereToGo);
		fs.put("swapsRejectedRateLimit", swapsRejectedRateLimit);
		fs.put("swapsRejectedRecognizedID", swapsRejectedRecognizedID);
		long fix32kb = 32 * 1024;
		long cachedKeys = node.getChkDatacache().keyCount();
		long cachedSize = cachedKeys * fix32kb;
		long storeKeys = node.getChkDatastore().keyCount();
		long storeSize = storeKeys * fix32kb;
		long overallKeys = cachedKeys + storeKeys;
		long overallSize = cachedSize + storeSize;

		long maxOverallKeys = node.getMaxTotalKeys();
		long maxOverallSize = maxOverallKeys * fix32kb;

		double percentOverallKeysOfMax = (double)(overallKeys*100)/(double)maxOverallKeys;

		long cachedStoreHits = node.getChkDatacache().hits();
		long cachedStoreMisses = node.getChkDatacache().misses();
		long cachedStoreWrites = node.getChkDatacache().writes();
		long cacheAccesses = cachedStoreHits + cachedStoreMisses;
		long cachedStoreFalsePositives = node.getChkDatacache().getBloomFalsePositive();
		double percentCachedStoreHitsOfAccesses = (double)(cachedStoreHits*100) / (double)cacheAccesses;
		long storeHits = node.getChkDatastore().hits();
		long storeMisses = node.getChkDatastore().misses();
		long storeWrites = node.getChkDatastore().writes();
		long storeFalsePositives = node.getChkDatastore().getBloomFalsePositive();
		long storeAccesses = storeHits + storeMisses;
		double percentStoreHitsOfAccesses = (double)(storeHits*100) / (double)storeAccesses;
		long overallAccesses = storeAccesses + cacheAccesses;
		double avgStoreAccessRate = (double)overallAccesses/(double)nodeUptimeSeconds;

		fs.put("cachedKeys", cachedKeys);
		fs.put("cachedSize", cachedSize);
		fs.put("storeKeys", storeKeys);
		fs.put("storeSize", storeSize);
		fs.put("overallKeys", overallKeys);
		fs.put("overallSize", overallSize);
		fs.put("maxOverallKeys", maxOverallKeys);
		fs.put("maxOverallSize", maxOverallSize);
		fs.put("percentOverallKeysOfMax", percentOverallKeysOfMax);
		fs.put("cachedStoreHits", cachedStoreHits);
		fs.put("cachedStoreMisses", cachedStoreMisses);
		fs.put("cachedStoreWrites", cachedStoreWrites);
		fs.put("cacheAccesses", cacheAccesses);
		fs.put("cachedStoreFalsePositives", cachedStoreFalsePositives);
		fs.put("percentCachedStoreHitsOfAccesses", percentCachedStoreHitsOfAccesses);
		fs.put("storeHits", storeHits);
		fs.put("storeMisses", storeMisses);
		fs.put("storeAccesses", storeAccesses);
		fs.put("storeWrites", storeWrites);
		fs.put("storeFalsePositives", storeFalsePositives);
		fs.put("percentStoreHitsOfAccesses", percentStoreHitsOfAccesses);
		fs.put("overallAccesses", overallAccesses);
		fs.put("avgStoreAccessRate", avgStoreAccessRate);

		Runtime rt = Runtime.getRuntime();
		float freeMemory = rt.freeMemory();
		float totalMemory = rt.totalMemory();
		float maxMemory = rt.maxMemory();

		long usedJavaMem = (long)(totalMemory - freeMemory);
		long allocatedJavaMem = (long)totalMemory;
		long maxJavaMem = (long)maxMemory;
		int availableCpus = rt.availableProcessors();

		fs.put("freeJavaMemory", (long)freeMemory);
		fs.put("usedJavaMemory", usedJavaMem);
		fs.put("allocatedJavaMemory", allocatedJavaMem);
		fs.put("maximumJavaMemory", maxJavaMem);
		fs.put("availableCPUs", availableCpus);
		fs.put("runningThreadCount", getActiveThreadCount());

		fs.put("globalFetchPSuccess", globalFetchPSuccess.currentValue());
		fs.put("globalFetchCount", globalFetchPSuccess.countReports());
		fs.put("chkLocalFetchPSuccess", chkLocalFetchPSuccess.currentValue());
		fs.put("chkLocalFetchCount", chkLocalFetchPSuccess.countReports());
		fs.put("chkRemoteFetchPSuccess", chkRemoteFetchPSuccess.currentValue());
		fs.put("chkRemoteFetchCount", chkRemoteFetchPSuccess.countReports());
		fs.put("sskLocalFetchPSuccess", sskLocalFetchPSuccess.currentValue());
		fs.put("sskLocalFetchCount", sskLocalFetchPSuccess.countReports());
		fs.put("sskRemoteFetchPSuccess", sskRemoteFetchPSuccess.currentValue());
		fs.put("sskRemoteFetchCount", sskRemoteFetchPSuccess.countReports());
		fs.put("blockTransferPSuccessRT", blockTransferPSuccessRT.currentValue());
		fs.put("blockTransferCountRT", blockTransferPSuccessRT.countReports());
		fs.put("blockTransferPSuccessBulk", blockTransferPSuccessBulk.currentValue());
		fs.put("blockTransferCountBulk", blockTransferPSuccessBulk.countReports());
		fs.put("blockTransferFailTimeout", blockTransferFailTimeout.currentValue());

		return fs;
	}

	public boolean isTestnetEnabled() {
		return Node.isTestnetEnabled();
	}

	public boolean getRejectReasonsTable(HTMLNode table) {
		return preemptiveRejectReasons.toTableRows(table) > 0;
	}

	public boolean getLocalRejectReasonsTable(HTMLNode table) {
		return localPreemptiveRejectReasons.toTableRows(table) > 0;
	}

	public synchronized void requestCompleted(boolean succeeded, boolean isRemote, boolean isSSK) {
		globalFetchPSuccess.report(succeeded ? 1.0 : 0.0);
		if(isSSK) {
			if (isRemote) {
				sskRemoteFetchPSuccess.report(succeeded ? 1.0 : 0.0);
			} else {
				sskLocalFetchPSuccess.report(succeeded ? 1.0 : 0.0);
			}
		} else {
			if (isRemote) {
				chkRemoteFetchPSuccess.report(succeeded ? 1.0 : 0.0);
			} else {
				chkLocalFetchPSuccess.report(succeeded ? 1.0 : 0.0);
			}
		}
	}

	private final DecimalFormat fix3p3pct = new DecimalFormat("##0.000%");
	private final NumberFormat thousandPoint = NumberFormat.getInstance();

	public void fillSuccessRateBox(HTMLNode parent) {
		HTMLNode list = parent.addChild("table", "border", "0");
		final RunningAverage[] averages = new RunningAverage[] {
				globalFetchPSuccess,
				chkLocalFetchPSuccess,
				chkRemoteFetchPSuccess,
				sskLocalFetchPSuccess,
				sskRemoteFetchPSuccess,
				blockTransferPSuccessBulk,
				blockTransferPSuccessRT,
				blockTransferPSuccessLocal,
				blockTransferFailTimeout
		};
		final String[] names = new String[] {
				l10n("allRequests"),
				l10n("localCHKs"),
				l10n("remoteCHKs"),
				l10n("localSSKs"),
				l10n("remoteSSKs"),
				l10n("blockTransfersBulk"),
				l10n("blockTransfersRT"),
				l10n("blockTransfersLocal"),
				l10n("transfersTimedOut")
		};
		HTMLNode row = list.addChild("tr");
		row.addChild("th", l10n("group"));
		row.addChild("th", l10n("pSuccess"));
		row.addChild("th", l10n("count"));

		for(int i=0;i<averages.length;i++) {
			row = list.addChild("tr");
			row.addChild("td", names[i]);
			if (averages[i].countReports()==0) {
				row.addChild("td", "-");
				row.addChild("td", "0");
			} else {
				row.addChild("td", fix3p3pct.format(averages[i].currentValue()));
				row.addChild("td", thousandPoint.format(averages[i].countReports()));
			}
		}

		row = list.addChild("tr");
		long[] bulkSuccess = BulkTransmitter.transferSuccess();
		row = list.addChild("tr");
		row.addChild("td", l10n("bulkSends"));
		row.addChild("td", fix3p3pct.format(((double)bulkSuccess[1])/((double)bulkSuccess[0])));
		row.addChild("td", Long.toString(bulkSuccess[0]));
	}

	/* Total bytes sent by requests and inserts, excluding payload */
	private long chkRequestSentBytes;
	private long chkRequestRcvdBytes;
	private long sskRequestSentBytes;
	private long sskRequestRcvdBytes;
	private long chkInsertSentBytes;
	private long chkInsertRcvdBytes;
	private long sskInsertSentBytes;
	private long sskInsertRcvdBytes;

	public synchronized void requestSentBytes(boolean ssk, int x) {
		if(ssk)
			sskRequestSentBytes += x;
		else
			chkRequestSentBytes += x;
	}

	public synchronized void requestReceivedBytes(boolean ssk, int x) {
		if(ssk)
			sskRequestRcvdBytes += x;
		else
			chkRequestRcvdBytes += x;
	}

	public synchronized void insertSentBytes(boolean ssk, int x) {
		if(logDEBUG)
			Logger.debug(this, "insertSentBytes("+ssk+", "+x+")");
		if(ssk)
			sskInsertSentBytes += x;
		else
			chkInsertSentBytes += x;
	}

	public synchronized void insertReceivedBytes(boolean ssk, int x) {
		if(ssk)
			sskInsertRcvdBytes += x;
		else
			chkInsertRcvdBytes += x;
	}

	public synchronized long getCHKRequestTotalBytesSent() {
		return chkRequestSentBytes;
	}

	public synchronized long getSSKRequestTotalBytesSent() {
		return sskRequestSentBytes;
	}

	public synchronized long getCHKInsertTotalBytesSent() {
		return chkInsertSentBytes;
	}

	public synchronized long getSSKInsertTotalBytesSent() {
		return sskInsertSentBytes;
	}

	private long offeredKeysSenderRcvdBytes;
	private long offeredKeysSenderSentBytes;

	public synchronized void offeredKeysSenderReceivedBytes(int x) {
		offeredKeysSenderRcvdBytes += x;
	}

	/**
	 * @return The number of bytes sent in replying to FNPGetOfferedKey's.
	 */
	public synchronized void offeredKeysSenderSentBytes(int x) {
		offeredKeysSenderSentBytes += x;
	}

	public long getOfferedKeysTotalBytesReceived() {
		return offeredKeysSenderRcvdBytes;
	}

	public long getOfferedKeysTotalBytesSent() {
		return offeredKeysSenderSentBytes;
	}

	private long offerKeysRcvdBytes;
	private long offerKeysSentBytes;

	ByteCounter sendOffersCtr = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			synchronized(NodeStats.this) {
				offerKeysRcvdBytes += x;
			}
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				offerKeysSentBytes += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}

	};

	public synchronized long getOffersSentBytesSent() {
		return offerKeysSentBytes;
	}

	private long swappingRcvdBytes;
	private long swappingSentBytes;

	public synchronized void swappingReceivedBytes(int x) {
		swappingRcvdBytes += x;
	}

	public synchronized void swappingSentBytes(int x) {
		swappingSentBytes += x;
	}

	public synchronized long getSwappingTotalBytesReceived() {
		return swappingRcvdBytes;
	}

	public synchronized long getSwappingTotalBytesSent() {
		return swappingSentBytes;
	}

	private long totalAuthBytesSent;

	public synchronized void reportAuthBytes(int x) {
		totalAuthBytesSent += x;
	}

	public synchronized long getTotalAuthBytesSent() {
		return totalAuthBytesSent;
	}

	private long resendBytesSent;

	public final ByteCounter resendByteCounter = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			// Ignore
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				resendBytesSent += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			Logger.error(this, "Payload sent in resendByteCounter????", new Exception("error"));
		}

	};

	public synchronized long getResendBytesSent() {
		return resendBytesSent;
	}

	private long uomBytesSent;

	public synchronized void reportUOMBytesSent(int x) {
		uomBytesSent += x;
	}

	public synchronized long getUOMBytesSent() {
		return uomBytesSent;
	}

	// Opennet-related bytes - *not* including bytes sent on requests, those are accounted towards
	// the requests' totals.

	private long announceBytesSent;
	private long announceBytesPayload;

	public final ByteCounter announceByteCounter = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			// Ignore
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				announceBytesSent += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			synchronized(NodeStats.this) {
				announceBytesPayload += x;
			}
		}

	};

	public synchronized long getAnnounceBytesSent() {
		return announceBytesSent;
	}

	public synchronized long getAnnounceBytesPayloadSent() {
		return announceBytesPayload;
	}

	private long routingStatusBytesSent;

	ByteCounter setRoutingStatusCtr = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			// Impossible?
			Logger.error(this, "Routing status sender received bytes: "+x+" - isn't that impossible?");
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				routingStatusBytesSent += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}

	};

	public synchronized long getRoutingStatusBytes() {
		return routingStatusBytesSent;
	}

	private long networkColoringReceivedBytesCounter;
	private long networkColoringSentBytesCounter;

	public synchronized void networkColoringReceivedBytes(int x) {
		networkColoringReceivedBytesCounter += x;
	}

	public synchronized void networkColoringSentBytes(int x) {
		networkColoringSentBytesCounter += x;
	}

	public synchronized long getNetworkColoringSentBytes() {
		return networkColoringSentBytesCounter;
	}

	private long pingBytesReceived;
	private long pingBytesSent;

	public synchronized void pingCounterReceived(int x) {
		pingBytesReceived += x;
	}

	public synchronized void pingCounterSent(int x) {
		pingBytesSent += x;
	}

	public synchronized long getPingSentBytes() {
		return pingBytesSent;
	}

	public ByteCounter sskRequestCtr = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			synchronized(NodeStats.this) {
				sskRequestRcvdBytes += x;
			}
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				sskRequestSentBytes += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}

	};

	public ByteCounter chkRequestCtr = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			synchronized(NodeStats.this) {
				chkRequestRcvdBytes += x;
			}
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				chkRequestSentBytes += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}

	};

	public ByteCounter sskInsertCtr = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			synchronized(NodeStats.this) {
				sskInsertRcvdBytes += x;
			}
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				sskInsertSentBytes += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}

	};

	public ByteCounter chkInsertCtr = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			synchronized(NodeStats.this) {
				chkInsertRcvdBytes += x;
			}
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				chkInsertSentBytes += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}

	};

	private long probeRequestSentBytes;
	private long probeRequestRcvdBytes;

	public ByteCounter probeRequestCtr = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			synchronized(NodeStats.this) {
				probeRequestRcvdBytes += x;
			}
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				probeRequestSentBytes += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}

	};

	public synchronized long getProbeRequestSentBytes() {
		return probeRequestSentBytes;
	}

	private long routedMessageBytesRcvd;
	private long routedMessageBytesSent;

	public ByteCounter routedMessageCtr = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			synchronized(NodeStats.this) {
				routedMessageBytesRcvd += x;
			}
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				routedMessageBytesSent += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}

	};

	public synchronized long getRoutedMessageSentBytes() {
		return routedMessageBytesSent;
	}

	private long disconnBytesReceived;
	private long disconnBytesSent;

	void disconnBytesReceived(int x) {
		this.disconnBytesReceived += x;
	}

	void disconnBytesSent(int x) {
		this.disconnBytesSent += x;
	}

	public long getDisconnBytesSent() {
		return disconnBytesSent;
	}

	private long initialMessagesBytesReceived;
	private long initialMessagesBytesSent;

	ByteCounter initialMessagesCtr = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			synchronized(NodeStats.this) {
				initialMessagesBytesReceived += x;
			}
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				initialMessagesBytesSent += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}

	};

	public synchronized long getInitialMessagesBytesSent() {
		return initialMessagesBytesSent;
	}

	private long changedIPBytesReceived;
	private long changedIPBytesSent;

	ByteCounter changedIPCtr = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			synchronized(NodeStats.this) {
				changedIPBytesReceived += x;
			}
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				changedIPBytesSent += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}

	};

	public long getChangedIPBytesSent() {
		return changedIPBytesSent;
	}

	private long nodeToNodeRcvdBytes;
	private long nodeToNodeSentBytes;

	final ByteCounter nodeToNodeCounter = new ByteCounter() {

		@Override
		public void receivedBytes(int x) {
			synchronized(NodeStats.this) {
				nodeToNodeRcvdBytes += x;
			}
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				nodeToNodeSentBytes += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}

	};

	public long getNodeToNodeBytesSent() {
		return nodeToNodeSentBytes;
	}
	
	private long allocationNoticesCounterBytesReceived;
	private long allocationNoticesCounterBytesSent;
	
	final ByteCounter allocationNoticesCounter = new ByteCounter() {
		
		@Override
		public void receivedBytes(int x) {
			synchronized(NodeStats.this) {
				allocationNoticesCounterBytesReceived += x;
			}
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				allocationNoticesCounterBytesSent += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}
		
	};
	
	public long getAllocationNoticesBytesSent() {
		return allocationNoticesCounterBytesSent;
	}

	private long foafCounterBytesReceived;
	private long foafCounterBytesSent;
	
	final ByteCounter foafCounter = new ByteCounter() {
		
		@Override
		public void receivedBytes(int x) {
			synchronized(NodeStats.this) {
				foafCounterBytesReceived += x;
			}
		}

		@Override
		public void sentBytes(int x) {
			synchronized(NodeStats.this) {
				foafCounterBytesSent += x;
			}
		}

		@Override
		public void sentPayload(int x) {
			// Ignore
		}
		
	};
	
	public long getFOAFBytesSent() {
		return foafCounterBytesSent;
	}

	
	

	private long notificationOnlySentBytes;

	synchronized void reportNotificationOnlyPacketSent(int packetSize) {
		notificationOnlySentBytes += packetSize;
	}

	public long getNotificationOnlyPacketsSentBytes() {
		return notificationOnlySentBytes;
	}

	public synchronized long getSentOverhead() {
		return offerKeysSentBytes // offers we have sent
		+ swappingSentBytes // swapping
		+ totalAuthBytesSent // connection setup
		+ resendBytesSent // resends - FIXME might be dependant on requests?
		+ uomBytesSent // update over mandatory
		+ announceBytesSent // announcements, including payload
		+ routingStatusBytesSent // routing status
		+ networkColoringSentBytesCounter // network coloring
		+ pingBytesSent // ping bytes
		+ probeRequestSentBytes // probe requests
		+ routedMessageBytesSent // routed test messages
		+ disconnBytesSent // disconnection related bytes
		+ initialMessagesBytesSent // initial messages
		+ changedIPBytesSent // changed IP
		+ nodeToNodeSentBytes // n2n messages
		+ notificationOnlySentBytes; // ack-only packets
	}

	/**
	 * The average number of bytes sent per second for things other than requests, inserts,
	 * and offer replies.
	 */
	public double getSentOverheadPerSecond() {
		long uptime = node.getUptime();
		// actually we’d want to convert uptime to seconds here but this is results in better accuracy.
		return getSentOverhead() * SECONDS.toMillis(1) / uptime;
	}

	public synchronized void successfulBlockReceive(boolean realTimeFlag, boolean isLocal) {
		RunningAverage blockTransferPSuccess = realTimeFlag ? blockTransferPSuccessRT : blockTransferPSuccessBulk;
		blockTransferPSuccess.report(1.0);
		if(isLocal)
			blockTransferPSuccessLocal.report(1.0);
		if(logMINOR) Logger.minor(this, "Successful receives: "+blockTransferPSuccess.currentValue()+" count="+blockTransferPSuccess.countReports()+" realtime="+realTimeFlag);
	}

	public synchronized void failedBlockReceive(boolean normalFetch, boolean timeout, boolean realTimeFlag, boolean isLocal) {
		if(normalFetch) {
			blockTransferFailTimeout.report(timeout ? 1.0 : 0.0);
		}
		RunningAverage blockTransferPSuccess = realTimeFlag ? blockTransferPSuccessRT : blockTransferPSuccessBulk;
		blockTransferPSuccess.report(0.0);
		if(isLocal)
			blockTransferPSuccessLocal.report(0.0);
		if(logMINOR) Logger.minor(this, "Successful receives: "+blockTransferPSuccess.currentValue()+" count="+blockTransferPSuccess.countReports()+" realtime="+realTimeFlag);
	}

	public void reportIncomingRequestLocation(double loc) {
		incomingRequests.report(loc);
	}

	public int[] getIncomingRequestLocation(int[] retval) {
		return incomingRequests.getCounts(retval);
	}

	public void reportOutgoingLocalRequestLocation(double loc) {
		outgoingLocalRequests.report(loc);
	}

	public int[] getOutgoingLocalRequestLocation(int[] retval) {
		return outgoingLocalRequests.getCounts(retval);
	}

	public void reportOutgoingRequestLocation(double loc) {
		outgoingRequests.report(loc);
	}

	public int[] getOutgoingRequestLocation(int[] retval) {
		return outgoingRequests.getCounts(retval);
	}

	public void reportCHKOutcome(long rtt, boolean successful, double location, boolean isRealtime) {
		if (successful) {
			(isRealtime ? successfulLocalCHKFetchTimeAverageRT : successfulLocalCHKFetchTimeAverageBulk).report(rtt);
			chkSuccessRatesByLocation.report(location, 1.0);
		} else {
			(isRealtime ? unsuccessfulLocalCHKFetchTimeAverageRT : unsuccessfulLocalCHKFetchTimeAverageBulk).report(rtt);
			chkSuccessRatesByLocation.report(location, 0.0);
		}
		(isRealtime ? localCHKFetchTimeAverageRT : localCHKFetchTimeAverageBulk).report(rtt);
	}

	public void reportSSKOutcome(long rtt, boolean successful, boolean isRealtime) {
		if (successful) {
			(isRealtime ? successfulLocalSSKFetchTimeAverageRT : successfulLocalSSKFetchTimeAverageBulk).report(rtt);
		} else {
			(isRealtime ? unsuccessfulLocalSSKFetchTimeAverageRT : unsuccessfulLocalSSKFetchTimeAverageBulk).report(rtt);
		}
		(isRealtime ? localSSKFetchTimeAverageRT : localSSKFetchTimeAverageBulk).report(rtt);
	}

	public void fillDetailedTimingsBox(HTMLNode html) {
		HTMLNode table = html.addChild("table");
		HTMLNode row = table.addChild("tr");
		row.addChild("td");
		row.addChild("td", "colspan", "2", "CHK");
		row.addChild("td", "colspan", "2", "SSK");
		row = table.addChild("tr");
		row.addChild("td", l10n("successfulHeader"));
		row.addChild("td", TimeUtil.formatTime((long)successfulLocalCHKFetchTimeAverageBulk.currentValue(), 2, true));
		row.addChild("td", TimeUtil.formatTime((long)successfulLocalCHKFetchTimeAverageRT.currentValue(), 2, true));
		row.addChild("td", TimeUtil.formatTime((long)successfulLocalSSKFetchTimeAverageBulk.currentValue(), 2, true));
		row.addChild("td", TimeUtil.formatTime((long)successfulLocalSSKFetchTimeAverageRT.currentValue(), 2, true));
		row = table.addChild("tr");
		row.addChild("td", l10n("unsuccessfulHeader"));
		row.addChild("td", TimeUtil.formatTime((long)unsuccessfulLocalCHKFetchTimeAverageBulk.currentValue(), 2, true));
		row.addChild("td", TimeUtil.formatTime((long)unsuccessfulLocalCHKFetchTimeAverageRT.currentValue(), 2, true));
		row.addChild("td", TimeUtil.formatTime((long)unsuccessfulLocalSSKFetchTimeAverageBulk.currentValue(), 2, true));
		row.addChild("td", TimeUtil.formatTime((long)unsuccessfulLocalSSKFetchTimeAverageRT.currentValue(), 2, true));
		row = table.addChild("tr");
		row.addChild("td", l10n("averageHeader"));
		row.addChild("td", TimeUtil.formatTime((long)localCHKFetchTimeAverageBulk.currentValue(), 2, true));
		row.addChild("td", TimeUtil.formatTime((long)localCHKFetchTimeAverageRT.currentValue(), 2, true));
		row.addChild("td", TimeUtil.formatTime((long)localSSKFetchTimeAverageBulk.currentValue(), 2, true));
		row.addChild("td", TimeUtil.formatTime((long)localSSKFetchTimeAverageRT.currentValue(), 2, true));
	}

	private HourlyStats hourlyStatsRT;
	private HourlyStats hourlyStatsBulk;

	void remoteRequest(boolean ssk, boolean success, boolean local, short htl, double location, boolean realTime, boolean fromOfferedKey) {
		if(logMINOR) Logger.minor(this, "Remote request: sucess="+success+" htl="+htl+" locally answered="+local+" location of key="+location+" from offered key = "+fromOfferedKey);
		if(!fromOfferedKey) {
			if(realTime)
				hourlyStatsRT.remoteRequest(ssk, success, local, htl, location);
			else
				hourlyStatsBulk.remoteRequest(ssk, success, local, htl, location);
		}
	}

	public void fillRemoteRequestHTLsBox(HTMLNode html, boolean realTime) {
		if(realTime)
			hourlyStatsRT.fillRemoteRequestHTLsBox(html);
		else
			hourlyStatsBulk.fillRemoteRequestHTLsBox(html);
	}

	private String sanitizeDBJobType(String jobType) {
		int typeBeginIndex = jobType.lastIndexOf('.'); // Only use the actual class name, exclude the packages
		int typeEndIndex = jobType.indexOf('@');

		if(typeBeginIndex < 0)
			typeBeginIndex = jobType.lastIndexOf(':'); // Strip "DBJobWrapper:" prefix

		if(typeBeginIndex < 0)
			typeBeginIndex = 0;
		else
			++typeBeginIndex;

		if(typeEndIndex < 0)
			typeEndIndex = jobType.length();

		return jobType.substring(typeBeginIndex, typeEndIndex);
	}

	public void reportDatabaseJob(String jobType, long executionTimeMiliSeconds) {
		jobType = sanitizeDBJobType(jobType);

		TrivialRunningAverage avg;

		synchronized(avgDatabaseJobExecutionTimes) {
			avg = avgDatabaseJobExecutionTimes.get(jobType);

			if(avg == null) {
				avg = new TrivialRunningAverage();
				avgDatabaseJobExecutionTimes.put(jobType, avg);
			}
		}

		avg.report(executionTimeMiliSeconds);
	}

	public void reportMandatoryBackoff(String backoffType, long backoffTimeMilliSeconds, boolean realtime) {
		TrivialRunningAverage avg;
		if(realtime) {
			synchronized (avgMandatoryBackoffTimesRT) {
				avg = avgMandatoryBackoffTimesRT.get(backoffType);

				if (avg == null) {
					avg = new TrivialRunningAverage();
					avgMandatoryBackoffTimesRT.put(backoffType, avg);
				}
			}
		} else {
			synchronized (avgMandatoryBackoffTimesBulk) {
				avg = avgMandatoryBackoffTimesBulk.get(backoffType);

				if (avg == null) {
					avg = new TrivialRunningAverage();
					avgMandatoryBackoffTimesBulk.put(backoffType, avg);
				}
			}
		}
		avg.report(backoffTimeMilliSeconds);
	}

	public void reportRoutingBackoff(String backoffType, long backoffTimeMilliSeconds, boolean realtime) {
		TrivialRunningAverage avg;

		if(realtime) {
			synchronized (avgRoutingBackoffTimesRT) {
				avg = avgRoutingBackoffTimesRT.get(backoffType);

				if (avg == null) {
					avg = new TrivialRunningAverage();
					avgRoutingBackoffTimesRT.put(backoffType, avg);
				}
			}
		} else {
			synchronized (avgRoutingBackoffTimesBulk) {
				avg = avgRoutingBackoffTimesBulk.get(backoffType);

				if (avg == null) {
					avg = new TrivialRunningAverage();
					avgRoutingBackoffTimesBulk.put(backoffType, avg);
				}
			}
		}

		avg.report(backoffTimeMilliSeconds);
	}

	public void reportTransferBackoff(String backoffType, long backoffTimeMilliSeconds, boolean realtime) {
		TrivialRunningAverage avg;

		if (realtime) {
			synchronized (avgTransferBackoffTimesRT) {
				avg = avgTransferBackoffTimesRT.get(backoffType);

				if (avg == null) {
					avg = new TrivialRunningAverage();
					avgTransferBackoffTimesRT.put(backoffType, avg);
				}
			}
		} else {
			synchronized (avgTransferBackoffTimesBulk) {
				avg = avgTransferBackoffTimesBulk.get(backoffType);

				if (avg == null) {
					avg = new TrivialRunningAverage();
					avgTransferBackoffTimesBulk.put(backoffType, avg);
				}
			}
		}
		avg.report(backoffTimeMilliSeconds);
	}

	/**
	 * View of stats for CHK Store
	 *
	 * @return stats for CHK Store
	 */
	public StoreLocationStats chkStoreStats() {
		return new StoreLocationStats() {
			@Override
			public double avgLocation() {
				return avgStoreCHKLocation.currentValue();
			}

			@Override
			public double avgSuccess() {
				return avgStoreCHKSuccess.currentValue();
			}

			@Override
			public double furthestSuccess() throws StatsNotAvailableException {
				return furthestStoreCHKSuccess;
			}

			@Override
			public double avgDist() throws StatsNotAvailableException {
				return Location.distance(node.lm.getLocation(), avgLocation());
			}

			@Override
			public double distanceStats() throws StatsNotAvailableException {
				return cappedDistance(avgStoreCHKLocation, node.getChkDatastore());
			}
		};
	}

	/**
	 * View of stats for CHK Cache
	 *
	 * @return CHK cache stats
	 */
	public StoreLocationStats chkCacheStats() {
		return new StoreLocationStats() {
			@Override
			public double avgLocation() {
				return avgCacheCHKLocation.currentValue();
			}

			@Override
			public double avgSuccess() {
				return avgCacheCHKSuccess.currentValue();
			}

			@Override
			public double furthestSuccess() throws StatsNotAvailableException {
				return furthestCacheCHKSuccess;
			}

			@Override
			public double avgDist() throws StatsNotAvailableException {
				return Location.distance(node.lm.getLocation(), avgLocation());
			}

			@Override
			public double distanceStats() throws StatsNotAvailableException {
				return cappedDistance(avgCacheCHKLocation, node.getChkDatacache());
			}
		};
	}

	/**
	 * View of stats for CHK SlashdotCache
	 *
	 * @return CHK Slashdotcache stats
	 */
	public StoreLocationStats chkSlashDotCacheStats() {
		return new StoreLocationStats() {
			@Override
			public double avgLocation() {
				return avgSlashdotCacheCHKLocation.currentValue();
			}

			@Override
			public double avgSuccess() {
				return avgSlashdotCacheCHKSucess.currentValue();
			}

			@Override
			public double furthestSuccess() throws StatsNotAvailableException {
				return furthestSlashdotCacheCHKSuccess;
			}

			@Override
			public double avgDist() throws StatsNotAvailableException {
				return Location.distance(node.lm.getLocation(), avgLocation());
			}

			@Override
			public double distanceStats() throws StatsNotAvailableException {
				return cappedDistance(avgSlashdotCacheCHKLocation, node.getChkSlashdotCache());
			}
		};
	}

		/**
	 * View of stats for CHK ClientCache
	 *
	 * @return CHK ClientCache stats
	 */
	public StoreLocationStats chkClientCacheStats() {
		return new StoreLocationStats() {
			@Override
			public double avgLocation() {
				return avgClientCacheCHKLocation.currentValue();
			}

			@Override
			public double avgSuccess() {
				return avgClientCacheCHKSuccess.currentValue();
			}

			@Override
			public double furthestSuccess() throws StatsNotAvailableException {
				return furthestClientCacheCHKSuccess;
			}

			@Override
			public double avgDist() throws StatsNotAvailableException {
				return Location.distance(node.lm.getLocation(), avgLocation());
			}

			@Override
			public double distanceStats() throws StatsNotAvailableException {
				return cappedDistance(avgClientCacheCHKLocation, node.getChkClientCache());
			}
		};
	}

	/**
	 * View of stats for SSK Store
	 *
	 * @return stats for SSK Store
	 */
	public StoreLocationStats sskStoreStats() {
		return new StoreLocationStats() {
			@Override
			public double avgLocation() {
				return avgStoreSSKLocation.currentValue();
			}

			@Override
			public double avgSuccess() {
				return avgStoreSSKSuccess.currentValue();
			}

			@Override
			public double furthestSuccess() throws StatsNotAvailableException {
				return furthestStoreSSKSuccess;
			}

			@Override
			public double avgDist() throws StatsNotAvailableException {
				return Location.distance(node.lm.getLocation(), avgLocation());
			}

			@Override
			public double distanceStats() throws StatsNotAvailableException {
				return cappedDistance(avgStoreSSKLocation, node.getSskDatastore());
			}
		};
	}

	/**
	 * View of stats for SSK Cache
	 *
	 * @return SSK cache stats
	 */
	public StoreLocationStats sskCacheStats() {
		return new StoreLocationStats() {
			@Override
			public double avgLocation() {
				return avgCacheSSKLocation.currentValue();
			}

			@Override
			public double avgSuccess() {
				return avgCacheSSKSuccess.currentValue();
			}

			@Override
			public double furthestSuccess() throws StatsNotAvailableException {
				return furthestCacheSSKSuccess;
			}

			@Override
			public double avgDist() throws StatsNotAvailableException {
				return Location.distance(node.lm.getLocation(), avgLocation());
			}

			@Override
			public double distanceStats() throws StatsNotAvailableException {
				return cappedDistance(avgCacheSSKLocation, node.getSskDatacache());
			}
		};
	}

	/**
	 * View of stats for SSK SlashdotCache
	 *
	 * @return SSK Slashdotcache stats
	 */
	public StoreLocationStats sskSlashDotCacheStats() {
		return new StoreLocationStats() {
			@Override
			public double avgLocation() {
				return avgSlashdotCacheSSKLocation.currentValue();
			}

			@Override
			public double avgSuccess() {
				return avgSlashdotCacheSSKSuccess.currentValue();
			}

			@Override
			public double furthestSuccess() throws StatsNotAvailableException {
				return furthestSlashdotCacheSSKSuccess;
			}

			@Override
			public double avgDist() throws StatsNotAvailableException {
				return Location.distance(node.lm.getLocation(), avgLocation());
			}

			@Override
			public double distanceStats() throws StatsNotAvailableException {
				return cappedDistance(avgSlashdotCacheSSKLocation, node.getSskSlashdotCache());
			}
		};
	}

		/**
	 * View of stats for SSK ClientCache
	 *
	 * @return SSK ClientCache stats
	 */
	public StoreLocationStats sskClientCacheStats() {
		return new StoreLocationStats() {
			@Override
			public double avgLocation() {
				return avgClientCacheSSKLocation.currentValue();
			}

			@Override
			public double avgSuccess() {
				return avgClientCacheSSKSuccess.currentValue();
			}

			@Override
			public double furthestSuccess() throws StatsNotAvailableException {
				return furthestClientCacheSSKSuccess;
			}

			@Override
			public double avgDist() throws StatsNotAvailableException {
				return Location.distance(node.lm.getLocation(), avgLocation());
			}

			@Override
			public double distanceStats() throws StatsNotAvailableException {
				return cappedDistance(avgClientCacheSSKLocation, node.getSskClientCache());
			}
		};
	}


	private double cappedDistance(DecayingKeyspaceAverage avgLocation, StoreCallback<?> store) {
		double cachePercent = 1.0 * avgLocation.countReports() / store.keyCount();
		//Cap the reported value at 100%, as the decaying average does not account beyond that anyway.
		if (cachePercent > 1.0) {
			cachePercent = 1.0;
		}
		return cachePercent;
	}


	public static class TimedStats implements Comparable<TimedStats> {
		public final String keyStr;
		public final long count;
		public final long avgTime;
		public final long totalTime;

		public TimedStats(String myKeyStr, long myCount, long myAvgTime, long myTotalTime) {
			keyStr = myKeyStr;
			count = myCount;
			avgTime = myAvgTime;
			totalTime = myTotalTime;
		}

		@Override
		public int compareTo(TimedStats o) {
			if(totalTime < o.totalTime)
				return 1;
			else if(totalTime == o.totalTime)
				return 0;
			else
				return -1;
		}
	}

	public TimedStats[] getMandatoryBackoffStatistics(boolean realtime) {

		if (realtime) {
			TimedStats[] entries = new TimedStats[avgMandatoryBackoffTimesRT.size()];
			int i = 0;

			synchronized (avgMandatoryBackoffTimesRT) {
				for (Map.Entry<String, TrivialRunningAverage> entry : avgMandatoryBackoffTimesRT.entrySet()) {
					TrivialRunningAverage avg = entry.getValue();
					entries[i++] = new TimedStats(entry.getKey(), avg.countReports(), (long) avg.currentValue(), (long) avg.totalValue());
				}
			}

			Arrays.sort(entries);
			return entries;
		} else {
			TimedStats[] entries = new TimedStats[avgMandatoryBackoffTimesBulk.size()];
			int i = 0;

			synchronized (avgMandatoryBackoffTimesBulk) {
				for (Map.Entry<String, TrivialRunningAverage> entry : avgMandatoryBackoffTimesBulk.entrySet()) {
					TrivialRunningAverage avg = entry.getValue();
					entries[i++] = new TimedStats(entry.getKey(), avg.countReports(), (long) avg.currentValue(), (long) avg.totalValue());
				}
			}

			Arrays.sort(entries);
			return entries;
		}
	}

	public TimedStats[] getRoutingBackoffStatistics(boolean realtime) {
		if (realtime) {
			TimedStats[] entries = new TimedStats[avgRoutingBackoffTimesRT.size()];
			int i = 0;

			synchronized (avgRoutingBackoffTimesRT) {
				for (Map.Entry<String, TrivialRunningAverage> entry : avgRoutingBackoffTimesRT.entrySet()) {
					TrivialRunningAverage avg = entry.getValue();
					entries[i++] = new TimedStats(entry.getKey(), avg.countReports(), (long) avg.currentValue(), (long) avg.totalValue());
				}
			}

			Arrays.sort(entries);
			return entries;
		} else {
			TimedStats[] entries = new TimedStats[avgRoutingBackoffTimesBulk.size()];
			int i = 0;

			synchronized (avgRoutingBackoffTimesBulk) {
				for (Map.Entry<String, TrivialRunningAverage> entry : avgRoutingBackoffTimesBulk.entrySet()) {
					TrivialRunningAverage avg = entry.getValue();
					entries[i++] = new TimedStats(entry.getKey(), avg.countReports(), (long) avg.currentValue(), (long) avg.totalValue());
				}
			}

			Arrays.sort(entries);
			return entries;
		}
	}

	public TimedStats[] getTransferBackoffStatistics(boolean realtime) {
		if (realtime) {
			TimedStats[] entries = new TimedStats[avgTransferBackoffTimesRT.size()];
			int i = 0;

			synchronized (avgTransferBackoffTimesRT) {
				for (Map.Entry<String, TrivialRunningAverage> entry : avgTransferBackoffTimesRT.entrySet()) {
					TrivialRunningAverage avg = entry.getValue();
					entries[i++] = new TimedStats(entry.getKey(), avg.countReports(), (long) avg.currentValue(), (long) avg.totalValue());
				}
			}

			Arrays.sort(entries);
			return entries;
		} else {
			TimedStats[] entries = new TimedStats[avgTransferBackoffTimesBulk.size()];
			int i = 0;

			synchronized (avgTransferBackoffTimesBulk) {
				for (Map.Entry<String, TrivialRunningAverage> entry : avgTransferBackoffTimesBulk.entrySet()) {
					TrivialRunningAverage avg = entry.getValue();
					entries[i++] = new TimedStats(entry.getKey(), avg.countReports(), (long) avg.currentValue(), (long) avg.totalValue());
				}
			}

			Arrays.sort(entries);
			return entries;
		}
	}

	public TimedStats[] getDatabaseJobExecutionStatistics() {
		TimedStats[] entries = new TimedStats[avgDatabaseJobExecutionTimes.size()];
		int i = 0;

		synchronized(avgDatabaseJobExecutionTimes) {
			for(Map.Entry<String, TrivialRunningAverage> entry : avgDatabaseJobExecutionTimes.entrySet()) {
				TrivialRunningAverage avg = entry.getValue();
				entries[i++] = new TimedStats(entry.getKey(), avg.countReports(), (long) avg.currentValue(), (long) avg.totalValue());
			}
		}

		Arrays.sort(entries);
		return entries;
	}

	public PeerLoadStats createPeerLoadStats(PeerNode peer, int transfersPerInsert, boolean realTimeFlag) {
		return new PeerLoadStats(peer, transfersPerInsert, realTimeFlag);
	}

	public PeerLoadStats parseLoadStats(PeerNode source, Message m) {
		return new PeerLoadStats(source, m);
	}

	public RunningRequestsSnapshot getRunningRequestsTo(PeerNode peerNode, boolean realTimeFlag) {
		return new RunningRequestsSnapshot(node.tracker, peerNode, true, false, outwardTransfersPerInsert(), realTimeFlag);
	}
	
	public boolean ignoreLocalVsRemoteBandwidthLiability() {
		return ignoreLocalVsRemoteBandwidthLiability;
	}
	
	private int totalAnnouncements;
	private int totalAnnounceForwards;
	
	public void reportAnnounceForwarded(int forwardedRefs, PeerNode source) {
		synchronized(this) {
			totalAnnouncements++;
			totalAnnounceForwards += forwardedRefs;
			if(logMINOR) Logger.minor(this, "Announcements: "+totalAnnouncements+" average "+((totalAnnounceForwards*1.0)/totalAnnouncements));
			// FIXME add to stats page
		}
		OpennetManager om = node.getOpennet();
		if(om != null && source instanceof SeedClientPeerNode)
			om.seedTracker.completedAnnounce((SeedClientPeerNode)source, forwardedRefs);
	}
	
	public synchronized int getTransfersPerAnnounce() {
		if(totalAnnouncements == 0) return 1;
		return (int)Math.max(1, Math.ceil((totalAnnounceForwards*1.0)/totalAnnouncements));
	}

	private final HashSet<Long> runningAnnouncements = new HashSet<Long>();

	// FIXME make configurable, more sophisticated.
	
	/** To prevent thread overflow */
	private final static int MAX_ANNOUNCEMENTS = 100;

	enum AnnouncementDecision {
		ACCEPT,
		OVERLOAD,
		LOOP
	}
	public AnnouncementDecision shouldAcceptAnnouncement(long uid) {
		int outputPerSecond = node.getOutputBandwidthLimit() / 2; // FIXME: Take overhead into account??? Be careful, it may include announcements and that would cause problems!
		int inputPerSecond = node.getInputBandwidthLimit() / 2;
		int limit = Math.min(inputPerSecond, outputPerSecond);
		synchronized(this) {
			int transfersPerAnnouncement = getTransfersPerAnnounce();
			int running = runningAnnouncements.size();
			if(running >= MAX_ANNOUNCEMENTS) {
				if(logMINOR) Logger.minor(this, "Too many announcements running: "+running);
				return AnnouncementDecision.OVERLOAD;
			}
			// Liability-style limiting as well.
			int perTransfer = OpennetManager.PADDED_NODEREF_SIZE;
			// Must all complete in 30 seconds. That is the timeout for one block.
			int bandwidthIn30Secs = limit * 30;
			if(perTransfer * transfersPerAnnouncement * running > bandwidthIn30Secs) {
				if(logMINOR) Logger.minor(this, "Can't complete "+running+" announcements in 30 secs");
				return AnnouncementDecision.OVERLOAD;
			}
			boolean ret = runningAnnouncements.add(uid);
			if(logMINOR) {
				if(ret) Logger.minor(this, "Accepting announcement "+uid);
				else Logger.minor(this, "Rejecting (loop) announcement "+uid);
			}
			return (ret ? AnnouncementDecision.ACCEPT : AnnouncementDecision.LOOP);
		}
	}
	
	public synchronized void endAnnouncement(long uid) {
		runningAnnouncements.remove(uid);
	}

	@Override
	public void blockTime(long interval, boolean realtime) {
		throttledPacketSendAverage.report(interval);
		if(realtime)
			throttledPacketSendAverageRT.report(interval);
		else
			throttledPacketSendAverageBulk.report(interval);
	}
	
	/** If a peer is over this threshold it is considered to be backed off. */
	public synchronized long maxPeerPingTime() {
		return 2 * maxPingTime;
	}
	
	private RunningAverage nlmDelayRTLocal = new TrivialRunningAverage();
	private RunningAverage nlmDelayRTRemote = new TrivialRunningAverage();
	private RunningAverage nlmDelayBulkLocal = new TrivialRunningAverage();
	private RunningAverage nlmDelayBulkRemote = new TrivialRunningAverage();

	public void reportNLMDelay(long waitTime, boolean realTime, boolean local) {
		if(realTime) {
			if(local)
				nlmDelayRTLocal.report(waitTime);
			else
				nlmDelayRTRemote.report(waitTime);
		} else {
			if(local)
				nlmDelayBulkLocal.report(waitTime);
			else
				nlmDelayBulkRemote.report(waitTime);
		}
		if(logMINOR) Logger.minor(this, "Delay times: realtime: local="+nlmDelayRTLocal.currentValue()+" remote = "+nlmDelayRTRemote.currentValue()+
				" bulk: local="+nlmDelayBulkLocal.currentValue()+" remote="+nlmDelayBulkRemote.currentValue());
	}

	public void drawNewLoadManagementDelayTimes(HTMLNode content) {
		WaitingForSlots waitingSlots = node.tracker.countRequestsWaitingForSlots();
		content.addChild("p").addChild("#", l10n("slotsWaiting", new String[] { "local", "remote" }, new String[] { Integer.toString(waitingSlots.local), Integer.toString(waitingSlots.remote) }));
		HTMLNode table = content.addChild("table", "border", "0");
		HTMLNode header = table.addChild("tr");
		header.addChild("th", l10n("delayTimes"));
		header.addChild("th", l10n("localHeader"));
		header.addChild("th", l10n("remoteHeader"));
		HTMLNode row = table.addChild("tr");
		row.addChild("th", l10n("realTimeHeader"));
		row.addChild("td", TimeUtil.formatTime((int)nlmDelayRTLocal.currentValue(), 2, true));
		row.addChild("td", TimeUtil.formatTime((int)nlmDelayRTRemote.currentValue(), 2, true));
		row = table.addChild("tr");
		row.addChild("th", l10n("bulkHeader"));
		row.addChild("td", TimeUtil.formatTime((int)nlmDelayBulkLocal.currentValue(), 2, true));
		row.addChild("td", TimeUtil.formatTime((int)nlmDelayBulkRemote.currentValue(), 2, true));
		
		synchronized(slotTimeoutsSync) {
			if(fatalTimeoutsInWaitLocal + fatalTimeoutsInWaitRemote + 
					allocatedSlotLocal + allocatedSlotRemote > 0) {
				content.addChild("b", l10n("timeoutFractions"));
				table = content.addChild("table", "border", "0");
				header = table.addChild("tr");
				header.addChild("th", l10n("localHeader"));
				header.addChild("th", l10n("remoteHeader"));
				row = table.addChild("tr");
				row.addChild("td", this.fix3p3pct.format(((double)fatalTimeoutsInWaitLocal)/((double)(fatalTimeoutsInWaitLocal + allocatedSlotLocal))));
				row.addChild("td", this.fix3p3pct.format(((double)fatalTimeoutsInWaitRemote)/((double)(fatalTimeoutsInWaitRemote + allocatedSlotRemote))));
			}
		}
	}

	private Object slotTimeoutsSync = new Object();
	private long fatalTimeoutsInWaitLocal;
	private long fatalTimeoutsInWaitRemote;
	private long allocatedSlotLocal;
	private long allocatedSlotRemote;
	
	public void reportFatalTimeoutInWait(boolean local) {
		synchronized(slotTimeoutsSync) {
			if(local)
				fatalTimeoutsInWaitLocal++;
			else
				fatalTimeoutsInWaitRemote++;
		}
	}

	public void reportAllocatedSlot(boolean local) {
		synchronized(slotTimeoutsSync) {
			if(local)
				allocatedSlotLocal++;
			else
				allocatedSlotRemote++;
		}
	}
	
	
	public boolean enableNewLoadManagement(boolean realTimeFlag) {
		return realTimeFlag ? enableNewLoadManagementRT : enableNewLoadManagementBulk;
	}
	
	final RunningAverage[] REJECT_STATS_AVERAGERS;
	
	private final Runnable noisyRejectStatsUpdater = new Runnable() {

		@Override
		public void run() {
			// SECURITY/TRIVIAL PERFORMANCE TRADEOFF: I don't think we want to run this lazily.
			// If we run it lazily, an attacker could trigger it, given that it's triggered rarely
			// in normal operation. FIXME long term we probably want to get rid of this from the
			// production network, and just surveil a few "special" nodes which volunteer to have
			// heavier stats inserted regularly.
			try {
				synchronized(noisyRejectStats) { // Only used for accessing the bytes.
					for(int i=0;i<REJECT_STATS_AVERAGERS.length;i++) {
						byte result;
						RunningAverage r = REJECT_STATS_AVERAGERS[i];
						if(r.countReports() < minReportsNoisyRejectStats) {
							// Do not return data until there are at least 200 results.
							result = -1;
						} else {
							double noisy = r.currentValue() * 100.0;
							if(rejectStatsFuzz > 0)
								noisy = randomNoise(noisy, rejectStatsFuzz);
							if(noisy < 0) result = 0;
							if(noisy > 100) result = 100;
							else result = (byte)noisy;
						}
						noisyRejectStats[i] = result;
					}
				}
			} finally {
				node.ticker.queueTimedJob(this, rejectStatsUpdateInterval);
			}
		}
		
	};
	
	/** How many reports to require before returning a value for reject stats */
	private final int minReportsNoisyRejectStats;
	/** How often to update the reject stats */
	private final long rejectStatsUpdateInterval;
	/** If positive, the level of fuzz (size of 1 standard deviation for gauss in percent) to use */
	private final double rejectStatsFuzz;
	
	private final byte[] noisyRejectStats;

	/**
	 * @return Array of 4 bytes, with the percentage rejections for (bulk only): CHK request, 
	 * SSK request, CHK insert, SSK insert. Negative value = insufficient data. Positive value = 
	 * percentage rejected. PRECAUTIONS: We update this statistic every 10 minutes. We don't 
	 * return a value unless we have at least 200 samples. We add Gaussian noise. 
	 * FIXME SECURITY We should remove this eventually. */
	public byte[] getNoisyRejectStats() {
		synchronized(noisyRejectStats) {
			return Arrays.copyOf(noisyRejectStats, noisyRejectStats.length);
		}
	}

	/**
	 * Applies multiplicative Gaussian noise of mean 1.0 and the specified sigma to the input value.
	 * @param input Value to apply noise to.
	 * @param sigma Proportion change at one standard deviation.
	 * @return Value +/- Gaussian percentage.
	 */
	public final double randomNoise(final double input, final double sigma) {
		double multiplier = (node.random.nextGaussian() * sigma) + 1.0;

		/*
		 * Cap noise to [0.5, 1.5]. Such amounts are very rare (5 sigma at 10%) and serve only to throw off the
		 * statistics by including crazy things like negative values or impossibly huge limits.
		 */
		if (multiplier < 0.5) multiplier = 0.5;
		else if (multiplier > 1.5) multiplier = 1.5;

		return input * multiplier;
	}
	
	public final double getBandwidthLiabilityUsage() {
		long now = System.currentTimeMillis();
		long limit = getLimitSeconds(false);
		int transfersPerInsert = outwardTransfersPerInsert();
		RunningRequestsSnapshot requestsSnapshot = new RunningRequestsSnapshot(node.tracker, ignoreLocalVsRemoteBandwidthLiability, transfersPerInsert, false);
		double usedBytes = requestsSnapshot.calculate(false);
		double nonOverheadFraction = getNonOverheadFraction(now);
		double upperLimit = getOutputBandwidthUpperLimit(limit, nonOverheadFraction);
		return usedBytes / upperLimit;
	}

}
