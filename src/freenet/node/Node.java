/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
/* Freenet 0.7 node. */
package freenet.node;

import static freenet.node.stats.DataStoreKeyType.CHK;
import static freenet.node.stats.DataStoreKeyType.PUB_KEY;
import static freenet.node.stats.DataStoreKeyType.SSK;
import static freenet.node.stats.DataStoreType.CACHE;
import static freenet.node.stats.DataStoreType.CLIENT;
import static freenet.node.stats.DataStoreType.SLASHDOT;
import static freenet.node.stats.DataStoreType.STORE;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.Random;
import java.util.Set;

import freenet.config.*;
import freenet.node.diagnostics.*;
import freenet.node.useralerts.*;
import org.tanukisoftware.wrapper.WrapperManager;

import freenet.client.FetchContext;
import freenet.clients.fcp.FCPMessage;
import freenet.clients.fcp.FeedMessage;
import freenet.clients.http.SecurityLevelsToadlet;
import freenet.clients.http.SimpleToadletServer;
import freenet.crypt.DSAPublicKey;
import freenet.crypt.ECDH;
import freenet.crypt.MasterSecret;
import freenet.crypt.PersistentRandomSource;
import freenet.crypt.RandomSource;
import freenet.crypt.Yarrow;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.FreenetInetAddress;
import freenet.io.comm.IOStatisticCollector;
import freenet.io.comm.Message;
import freenet.io.comm.MessageCore;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.Peer;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.io.comm.TrafficClass;
import freenet.io.comm.UdpSocketHandler;
import freenet.io.xfer.PartiallyReceivedBlock;
import freenet.keys.CHKBlock;
import freenet.keys.CHKVerifyException;
import freenet.keys.ClientCHK;
import freenet.keys.ClientCHKBlock;
import freenet.keys.ClientKey;
import freenet.keys.ClientKeyBlock;
import freenet.keys.ClientSSK;
import freenet.keys.ClientSSKBlock;
import freenet.keys.Key;
import freenet.keys.KeyBlock;
import freenet.keys.KeyVerifyException;
import freenet.keys.NodeCHK;
import freenet.keys.NodeSSK;
import freenet.keys.SSKBlock;
import freenet.keys.SSKVerifyException;
import freenet.l10n.BaseL10n;
import freenet.l10n.NodeL10n;
import freenet.node.DarknetPeerNode.FRIEND_TRUST;
import freenet.node.DarknetPeerNode.FRIEND_VISIBILITY;
import freenet.node.NodeDispatcher.NodeDispatcherCallback;
import freenet.node.OpennetManager.ConnectionType;
import freenet.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import freenet.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import freenet.node.probe.Listener;
import freenet.node.probe.Type;
import freenet.node.stats.DataStoreInstanceType;
import freenet.node.stats.DataStoreStats;
import freenet.node.stats.NotAvailNodeStoreStats;
import freenet.node.stats.StoreCallbackStats;
import freenet.node.updater.NodeUpdateManager;
import freenet.pluginmanager.ForwardPort;
import freenet.pluginmanager.PluginDownLoaderOfficialHTTPS;
import freenet.pluginmanager.PluginManager;
import freenet.store.BlockMetadata;
import freenet.store.CHKStore;
import freenet.store.FreenetStore;
import freenet.store.KeyCollisionException;
import freenet.store.NullFreenetStore;
import freenet.store.PubkeyStore;
import freenet.store.RAMFreenetStore;
import freenet.store.SSKStore;
import freenet.store.SlashdotStore;
import freenet.store.StorableBlock;
import freenet.store.StoreCallback;
import freenet.store.caching.CachingFreenetStore;
import freenet.store.caching.CachingFreenetStoreTracker;
import freenet.store.saltedhash.ResizablePersistentIntBuffer;
import freenet.store.saltedhash.SaltedHashFreenetStore;
import freenet.support.Executor;
import freenet.support.Fields;
import freenet.support.HTMLNode;
import freenet.support.HexUtil;
import freenet.support.JVMVersion;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.PooledExecutor;
import freenet.support.PrioritizedTicker;
import freenet.support.ShortBuffer;
import freenet.support.SimpleFieldSet;
import freenet.support.Ticker;
import freenet.support.TokenBucket;
import freenet.support.api.BooleanCallback;
import freenet.support.api.IntCallback;
import freenet.support.api.LongCallback;
import freenet.support.api.ShortCallback;
import freenet.support.api.StringCallback;
import freenet.support.io.ArrayBucketFactory;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import freenet.support.io.NativeThread;
import freenet.support.math.MersenneTwister;
import freenet.support.transport.ip.HostnameSyntaxException;

/**
 * @author amphibian
 */
public class Node implements TimeSkewDetectorCallback {

	public class MigrateOldStoreData implements Runnable {

		private final boolean clientCache;

		public MigrateOldStoreData(boolean clientCache) {
			this.clientCache = clientCache;
			if(clientCache) {
				oldCHKClientCache = chkClientcache;
				oldPKClientCache = pubKeyClientcache;
				oldSSKClientCache = sskClientcache;
			} else {
				oldCHK = chkDatastore;
				oldPK = pubKeyDatastore;
				oldSSK = sskDatastore;
				oldCHKCache = chkDatastore;
				oldPKCache = pubKeyDatastore;
				oldSSKCache = sskDatastore;
			}
		}

		@Override
		public void run() {
			System.err.println("Migrating old "+(clientCache ? "client cache" : "datastore"));
			if(clientCache) {
				migrateOldStore(oldCHKClientCache, chkClientcache, true);
				StoreCallback<? extends StorableBlock> old;
				synchronized(Node.this) {
					old = oldCHKClientCache;
					oldCHKClientCache = null;
				}
				closeOldStore(old);
				migrateOldStore(oldPKClientCache, pubKeyClientcache, true);
				synchronized(Node.this) {
					old = oldPKClientCache;
					oldPKClientCache = null;
				}
				closeOldStore(old);
				migrateOldStore(oldSSKClientCache, sskClientcache, true);
				synchronized(Node.this) {
					old = oldSSKClientCache;
					oldSSKClientCache = null;
				}
				closeOldStore(old);
			} else {
				migrateOldStore(oldCHK, chkDatastore, false);
				oldCHK = null;
				migrateOldStore(oldPK, pubKeyDatastore, false);
				oldPK = null;
				migrateOldStore(oldSSK, sskDatastore, false);
				oldSSK = null;
				migrateOldStore(oldCHKCache, chkDatacache, false);
				oldCHKCache = null;
				migrateOldStore(oldPKCache, pubKeyDatacache, false);
				oldPKCache = null;
				migrateOldStore(oldSSKCache, sskDatacache, false);
				oldSSKCache = null;
			}
			System.err.println("Finished migrating old "+(clientCache ? "client cache" : "datastore"));
		}

	}

	volatile CHKStore oldCHK;
	volatile PubkeyStore oldPK;
	volatile SSKStore oldSSK;

	volatile CHKStore oldCHKCache;
	volatile PubkeyStore oldPKCache;
	volatile SSKStore oldSSKCache;

	volatile CHKStore oldCHKClientCache;
	volatile PubkeyStore oldPKClientCache;
	volatile SSKStore oldSSKClientCache;

	private <T extends StorableBlock> void migrateOldStore(StoreCallback<T> old, StoreCallback<T> newStore, boolean canReadClientCache) {
		FreenetStore<T> store = old.getStore();
		if(store instanceof RAMFreenetStore) {
			RAMFreenetStore<T> ramstore = (RAMFreenetStore<T>)store;
			try {
				ramstore.migrateTo(newStore, canReadClientCache);
			} catch (IOException e) {
				Logger.error(this, "Caught migrating old store: "+e, e);
			}
			ramstore.clear();
		} else if(store instanceof SaltedHashFreenetStore) {
			Logger.error(this, "Migrating from from a saltedhashstore not fully supported yet: will not keep old keys");
		}
	}


	public <T extends StorableBlock> void closeOldStore(StoreCallback<T> old) {
		FreenetStore<T> store = old.getStore();
		if(store instanceof SaltedHashFreenetStore) {
			SaltedHashFreenetStore<T> saltstore = (SaltedHashFreenetStore<T>) store;
			saltstore.close();
			saltstore.destruct();
		}
	}


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
	private static MeaningfulNodeNameUserAlert nodeNameUserAlert;
	private static TimeSkewDetectedUserAlert timeSkewDetectedUserAlert;

	public class NodeNameCallback extends StringCallback  {
		NodeNameCallback() {
		}
		@Override
		public String get() {
			String name;
			synchronized(this) {
				name = myName;
			}
			if(name.startsWith("Node id|")|| name.equals("MyFirstFreenetNode") || name.startsWith("Freenet node with no name #")){
				clientCore.alerts.register(nodeNameUserAlert);
			}else{
				clientCore.alerts.unregister(nodeNameUserAlert);
			}
			return name;
		}

		@Override
		public void set(String val) throws InvalidConfigValueException {
			if(get().equals(val)) return;
			else if(val.length() > 128)
				throw new InvalidConfigValueException("The given node name is too long ("+val+')');
			else if("".equals(val))
				val = "~none~";
			synchronized(this) {
				myName = val;
			}
			// We'll broadcast the new name to our connected darknet peers via a differential node reference
			SimpleFieldSet fs = new SimpleFieldSet(true);
			fs.putSingle("myName", myName);
			peers.locallyBroadcastDiffNodeRef(fs, true, false);
			// We call the callback once again to ensure MeaningfulNodeNameUserAlert
			// has been unregistered ... see #1595
			get();
		}
	}

	private class StoreTypeCallback extends StringCallback implements EnumerableOptionCallback {

		@Override
		public String get() {
			synchronized(Node.this) {
				return storeType;
			}
		}

		@Override
		public void set(String val) throws InvalidConfigValueException, NodeNeedRestartException {
			boolean found = false;
			for (String p : getPossibleValues()) {
				if (p.equals(val)) {
					found = true;
					break;
				}
			}
			if (!found)
				throw new InvalidConfigValueException("Invalid store type");

			String type;
			synchronized(Node.this) {
				type = storeType;
			}
			if(type.equals("ram")) {
				synchronized(this) { // Serialise this part.
					makeStore(val);
				}
			} else {
				synchronized(Node.this) {
					storeType = val;
				}
				throw new NodeNeedRestartException("Store type cannot be changed on the fly");
			}
		}

		@Override
		public String[] getPossibleValues() {
			return new String[] { "salt-hash", "ram" };
		}
	}

	private class ClientCacheTypeCallback extends StringCallback implements EnumerableOptionCallback {

		@Override
		public String get() {
			synchronized(Node.this) {
				return clientCacheType;
			}
		}

		@Override
		public void set(String val) throws InvalidConfigValueException, NodeNeedRestartException {
			boolean found = false;
			for (String p : getPossibleValues()) {
				if (p.equals(val)) {
					found = true;
					break;
				}
			}
			if (!found)
				throw new InvalidConfigValueException("Invalid store type");

			synchronized(this) { // Serialise this part.
				String suffix = getStoreSuffix();
				if (val.equals("salt-hash")) {
					byte[] key;
                    try {
                        synchronized(Node.this) {
                            if(keys == null) throw new MasterKeysWrongPasswordException();
                            key = keys.clientCacheMasterKey;
                            clientCacheType = val;
                        }
                    } catch (MasterKeysWrongPasswordException e1) {
                        setClientCacheAwaitingPassword();
                        throw new InvalidConfigValueException("You must enter the password");
					}
					try {
						initSaltHashClientCacheFS(suffix, true, key);
					} catch (NodeInitException e) {
						Logger.error(this, "Unable to create new store", e);
						System.err.println("Unable to create new store: "+e);
						e.printStackTrace();
						// FIXME l10n both on the NodeInitException and the wrapper message
						throw new InvalidConfigValueException("Unable to create new store: "+e);
					}
				} else if(val.equals("ram")) {
					initRAMClientCacheFS();
				} else /*if(val.equals("none")) */{
					initNoClientCacheFS();
				}
				
				synchronized(Node.this) {
					clientCacheType = val;
				}
			}
		}

		@Override
		public String[] getPossibleValues() {
			return new String[] { "salt-hash", "ram", "none" };
		}
	}

	private static class L10nCallback extends StringCallback implements EnumerableOptionCallback {
		@Override
		public String get() {
			return NodeL10n.getBase().getSelectedLanguage().fullName;
		}

		@Override
		public void set(String val) throws InvalidConfigValueException {
			if(val == null || get().equalsIgnoreCase(val)) return;
			try {
				NodeL10n.getBase().setLanguage(BaseL10n.LANGUAGE.mapToLanguage(val));
			} catch (MissingResourceException e) {
				throw new InvalidConfigValueException(e.getLocalizedMessage());
			}
			PluginManager.setLanguage(NodeL10n.getBase().getSelectedLanguage());
		}

		@Override
		public String[] getPossibleValues() {
			return BaseL10n.LANGUAGE.valuesWithFullNames();
		}
	}

	/** Encryption key for client.dat.crypt or client.dat.bak.crypt */
	private DatabaseKey databaseKey;
	
	/** Encryption keys, if loaded, null if waiting for a password. We must be able to write them, 
	 * and they're all used elsewhere anyway, so there's no point trying not to keep them in memory. */
	private MasterKeys keys;

	/** Stats */
	public final NodeStats nodeStats;

	/** Config object for the whole node. */
	public final PersistentConfig config;

	// Static stuff related to logger

	/** Directory to log to */
	static File logDir;
	/** Maximum size of gzipped logfiles */
	static long maxLogSize;
	/** Log config handler */
	public static LoggingConfigHandler logConfigHandler;

	public static final int PACKETS_IN_BLOCK = 32;
	public static final int PACKET_SIZE = 1024;
	public static final double DECREMENT_AT_MIN_PROB = 0.25;
	public static final double DECREMENT_AT_MAX_PROB = 0.5;
	// Send keepalives every 7-14 seconds. Will be acked and if necessary resent.
	// Old behaviour was keepalives every 14-28. Even that was adequate for a 30 second
	// timeout. Most nodes don't need to send keepalives because they are constantly busy,
	// this is only an issue for disabled darknet connections, very quiet private networks
	// etc.
	public static final long KEEPALIVE_INTERVAL = SECONDS.toMillis(7);
	// If no activity for 30 seconds, node is dead
	// 35 seconds allows plenty of time for resends etc even if above is 14 sec as it is on older nodes.
	public static final long MAX_PEER_INACTIVITY = SECONDS.toMillis(35);
	/** Time after which a handshake is assumed to have failed. */
	public static final int HANDSHAKE_TIMEOUT = (int) MILLISECONDS.toMillis(4800); // Keep the below within the 30 second assumed timeout.
	// Inter-handshake time must be at least 2x handshake timeout
	public static final int MIN_TIME_BETWEEN_HANDSHAKE_SENDS = HANDSHAKE_TIMEOUT*2; // 10-20 secs
	public static final int RANDOMIZED_TIME_BETWEEN_HANDSHAKE_SENDS = HANDSHAKE_TIMEOUT*2; // avoid overlap when the two handshakes are at the same time
	public static final int MIN_TIME_BETWEEN_VERSION_PROBES = HANDSHAKE_TIMEOUT*4;
	public static final int RANDOMIZED_TIME_BETWEEN_VERSION_PROBES = HANDSHAKE_TIMEOUT*2; // 20-30 secs
	public static final int MIN_TIME_BETWEEN_VERSION_SENDS = HANDSHAKE_TIMEOUT*4;
	public static final int RANDOMIZED_TIME_BETWEEN_VERSION_SENDS = HANDSHAKE_TIMEOUT*2; // 20-30 secs
	public static final int MIN_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS = HANDSHAKE_TIMEOUT*24; // 2-5 minutes
	public static final int RANDOMIZED_TIME_BETWEEN_BURSTING_HANDSHAKE_BURSTS = HANDSHAKE_TIMEOUT*36;
	public static final int MIN_BURSTING_HANDSHAKE_BURST_SIZE = 1; // 1-4 handshake sends per burst
	public static final int RANDOMIZED_BURSTING_HANDSHAKE_BURST_SIZE = 3;
	// If we don't receive any packets at all in this period, from any node, tell the user
	public static final long ALARM_TIME = MINUTES.toMillis(1);

	static final long MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS = MILLISECONDS.toMillis(900);
	static final long MIN_INTERVAL_BETWEEN_INCOMING_PROBE_REQUESTS = MILLISECONDS.toMillis(1000);
	public static final int SYMMETRIC_KEY_LENGTH = 32; // 256 bits - note that this isn't used everywhere to determine it

	/** Datastore directory */
	private final ProgramDirectory storeDir;

	/** Datastore properties */
	private String storeType;
	private boolean storeUseSlotFilters;
	private boolean storeSaltHashResizeOnStart;
	
	/** Minimum total datastore size */
	static final long MIN_STORE_SIZE = 32 * 1024 * 1024;
	/** Default datastore size (must be at least MIN_STORE_SIZE) */
	static final long DEFAULT_STORE_SIZE = 32 * 1024 * 1024;
	/** Minimum client cache size */
	static final long MIN_CLIENT_CACHE_SIZE = 0;
	/** Default client cache size (must be at least MIN_CLIENT_CACHE_SIZE) */
	static final long DEFAULT_CLIENT_CACHE_SIZE = 10 * 1024 * 1024;
	/** Minimum slashdot cache size */
	static final long MIN_SLASHDOT_CACHE_SIZE = 0;
	/** Default slashdot cache size (must be at least MIN_SLASHDOT_CACHE_SIZE) */
	static final long DEFAULT_SLASHDOT_CACHE_SIZE = 10 * 1024 * 1024;

	/** The number of bytes per key total in all the different datastores. All the datastores
	 * are always the same size in number of keys. */
	public static final int sizePerKey = CHKBlock.DATA_LENGTH + CHKBlock.TOTAL_HEADERS_LENGTH +
		DSAPublicKey.PADDED_SIZE + SSKBlock.DATA_LENGTH + SSKBlock.TOTAL_HEADERS_LENGTH;

	/** The maximum number of keys stored in each of the datastores, cache and store combined. */
	private long maxTotalKeys;
	long maxCacheKeys;
	long maxStoreKeys;
	/** The maximum size of the datastore. Kept to avoid rounding turning 5G into 5368698672 */
	private long maxTotalDatastoreSize;
	/** If true, store shrinks occur immediately even if they are over 10% of the store size. If false,
	 * we just set the storeSize and do an offline shrink on the next startup. Online shrinks do not
	 * preserve the most recently used data so are not recommended. */
	private boolean storeForceBigShrinks;

	private final SemiOrderedShutdownHook shutdownHook;
	/** The CHK datastore. Long term storage; data should only be inserted here if
	 * this node is the closest location on the chain so far, and it is on an
	 * insert (because inserts will always reach the most specialized node; if we
	 * allow requests to store here, then we get pollution by inserts for keys not
	 * close to our specialization). These conclusions derived from Oskar's simulations. */
	private CHKStore chkDatastore;
	/** The SSK datastore. See description for chkDatastore. */
	private SSKStore sskDatastore;
	/** The store of DSAPublicKeys (by hash). See description for chkDatastore. */
	private PubkeyStore pubKeyDatastore;

	/** Client cache store type */
	private String clientCacheType;
	/** Client cache could not be opened so is a RAMFS until the correct password is entered */
	private boolean clientCacheAwaitingPassword;
	private boolean databaseAwaitingPassword;
	/** Client cache maximum cached keys for each type */
	long maxClientCacheKeys;
	/** Maximum size of the client cache. Kept to avoid rounding problems. */
	private long maxTotalClientCacheSize;

	/** The CHK datacache. Short term cache which stores everything that passes
	 * through this node. */
	private CHKStore chkDatacache;
	/** The SSK datacache. Short term cache which stores everything that passes
	 * through this node. */
	private SSKStore sskDatacache;
	/** The public key datacache (by hash). Short term cache which stores
	 * everything that passes through this node. */
	private PubkeyStore pubKeyDatacache;

	/** The CHK client cache. Caches local requests only. */
	private CHKStore chkClientcache;
	/** The SSK client cache. Caches local requests only. */
	private SSKStore sskClientcache;
	/** The pubkey client cache. Caches local requests only. */
	private PubkeyStore pubKeyClientcache;

	// These only cache keys for 30 minutes.

	// FIXME make the first two configurable
	private long maxSlashdotCacheSize;
	private int maxSlashdotCacheKeys;
	static final long PURGE_INTERVAL = SECONDS.toMillis(60);

	private CHKStore chkSlashdotcache;
	private SlashdotStore<CHKBlock> chkSlashdotcacheStore;
	private SSKStore sskSlashdotcache;
	private SlashdotStore<SSKBlock> sskSlashdotcacheStore;
	private PubkeyStore pubKeySlashdotcache;
	private SlashdotStore<DSAPublicKey> pubKeySlashdotcacheStore;

	/** If false, only ULPRs will use the slashdot cache. If true, everything does. */
	private boolean useSlashdotCache;
	/** If true, we write stuff to the datastore even though we shouldn't because the HTL is
	 * too high. However it is flagged as old so it won't be included in the Bloom filter for
	 * sharing purposes. */
	private boolean writeLocalToDatastore;

	final NodeGetPubkey getPubKey;

	/** FetchContext for ARKs */
	public final FetchContext arkFetcherContext;

	/** IP detector */
	public final NodeIPDetector ipDetector;
	/** For debugging/testing, set this to true to stop the
	 * probabilistic decrement at the edges of the HTLs. */
	boolean disableProbabilisticHTLs;

	public final RequestTracker tracker;
	
	/** Semi-unique ID for swap requests. Used to identify us so that the
	 * topology can be reconstructed. */
	public long swapIdentifier;
	private String myName;
	public final LocationManager lm;
	/** My peers */
	public final PeerManager peers;
	/** Node-reference directory (node identity, peers, etc) */
	final ProgramDirectory nodeDir;
	/** Config directory (l10n overrides, etc) */
	final ProgramDirectory cfgDir;
	/** User data directory (bookmarks, download lists, etc) */
	final ProgramDirectory userDir;
	/** Run-time state directory (bootID, PRNG seed, etc) */
	final ProgramDirectory runDir;
	/** Plugin directory */
	final ProgramDirectory pluginDir;

	/** File to write crypto master keys into, possibly passworded */
	final File masterKeysFile;
	/** Directory to put extra peer data into */
	final File extraPeerDataDir;
	private volatile boolean hasPanicked;
	/** Strong RNG */
	public final RandomSource random;
	/** JCA-compliant strong RNG. WARNING: DO NOT CALL THIS ON THE MAIN NETWORK
	 * HANDLING THREADS! In some configurations it can block, potentially 
	 * forever, on nextBytes()! */
	public final SecureRandom secureRandom;
	/** Weak but fast RNG */
	public final Random fastWeakRandom;
	/** The object which handles incoming messages and allows us to wait for them */
	final MessageCore usm;

	// Darknet stuff

	NodeCrypto darknetCrypto;
	// Back compat
	private boolean showFriendsVisibilityAlert;

	// Opennet stuff

	private final NodeCryptoConfig opennetCryptoConfig;
	OpennetManager opennet;
	private volatile boolean isAllowedToConnectToSeednodes;
	private int maxOpennetPeers;
	private boolean acceptSeedConnections;
	private boolean passOpennetRefsThroughDarknet;

	// General stuff

	public final Executor executor;
	public final PacketSender ps;
	public final PrioritizedTicker ticker;
	final DNSRequester dnsr;
	final NodeDispatcher dispatcher;
	public final UptimeEstimator uptime;
	public final TokenBucket outputThrottle;
	public boolean throttleLocalData;
	private int outputBandwidthLimit;
	private int inputBandwidthLimit;
	private long amountOfDataToCheckCompressionRatio;
	private int minimumCompressionPercentage;
	private int maxTimeForSingleCompressor;
	private boolean connectionSpeedDetection;
	boolean inputLimitDefault;
	final boolean enableARKs;
	final boolean enablePerNodeFailureTables;
	final boolean enableULPRDataPropagation;
	final boolean enableSwapping;
	private volatile boolean publishOurPeersLocation;
	private volatile boolean routeAccordingToOurPeersLocation;
	boolean enableSwapQueueing;
	boolean enablePacketCoalescing;
	public static final short DEFAULT_MAX_HTL = (short)18;
	private short maxHTL;
	private boolean skipWrapperWarning;
	private int maxPacketSize;
	/** Should inserts ignore low backoff times by default? */
	public static final boolean IGNORE_LOW_BACKOFF_DEFAULT = false;
	/** Definition of "low backoff times" for above. */
	public static final long LOW_BACKOFF = SECONDS.toMillis(30);
	/** Should inserts be fairly blatently prioritised on accept by default? */
	public static final boolean PREFER_INSERT_DEFAULT = false;
	/** Should inserts fork when the HTL reaches cacheability? */
	public static final boolean FORK_ON_CACHEABLE_DEFAULT = true;
	public final IOStatisticCollector collector;
	/** Type identifier for fproxy node to node messages, as sent on DMT.nodeToNodeMessage's */
	public static final int N2N_MESSAGE_TYPE_FPROXY = 1;
	/** Type identifier for differential node reference messages, as sent on DMT.nodeToNodeMessage's */
	public static final int N2N_MESSAGE_TYPE_DIFFNODEREF = 2;
	/** Identifier within fproxy messages for simple, short text messages to be displayed on the homepage as useralerts */
	public static final int N2N_TEXT_MESSAGE_TYPE_USERALERT = 1;
	/** Identifier within fproxy messages for an offer to transfer a file */
	public static final int N2N_TEXT_MESSAGE_TYPE_FILE_OFFER = 2;
	/** Identifier within fproxy messages for accepting an offer to transfer a file */
	public static final int N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_ACCEPTED = 3;
	/** Identifier within fproxy messages for rejecting an offer to transfer a file */
	public static final int N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_REJECTED = 4;
	/** Identified within friend feed for the recommendation of a bookmark */
	public static final int N2N_TEXT_MESSAGE_TYPE_BOOKMARK = 5;
	/** Identified within friend feed for the recommendation of a file */
	public static final int N2N_TEXT_MESSAGE_TYPE_DOWNLOAD = 6;
	public static final int EXTRA_PEER_DATA_TYPE_N2NTM = 1;
	public static final int EXTRA_PEER_DATA_TYPE_PEER_NOTE = 2;
	public static final int EXTRA_PEER_DATA_TYPE_QUEUED_TO_SEND_N2NM = 3;
	public static final int EXTRA_PEER_DATA_TYPE_BOOKMARK = 4;
	public static final int EXTRA_PEER_DATA_TYPE_DOWNLOAD = 5;
	public static final int PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT = 1;

	/** The bootID of the last time the node booted up. Or -1 if we don't know due to
	 * permissions problems, or we suspect that the node has been booted and not
	 * written the file e.g. if we can't write it. So if we want to compare data
	 * gathered in the last session and only recorded to disk on a clean shutdown
	 * to data we have now, we just include the lastBootID. */
	public final long lastBootID;
	public final long bootID;
	public final long startupTime;

	private SimpleToadletServer toadlets;

	public final NodeClientCore clientCore;

	// ULPRs, RecentlyFailed, per node failure tables, are all managed by FailureTable.
	final FailureTable failureTable;

	// The version we were before we restarted.
	public int lastVersion;

	/** NodeUpdater **/
	public final NodeUpdateManager nodeUpdater;

	public final SecurityLevels securityLevels;

	/** Diagnostics */
	private final DefaultNodeDiagnostics nodeDiagnostics;

	// Things that's needed to keep track of
	public final PluginManager pluginManager;

	// Helpers
	public final InetAddress localhostAddress;
	public final FreenetInetAddress fLocalhostAddress;

	// The node starter
	private static NodeStarter nodeStarter;

	// The watchdog will be silenced until it's true
	private boolean hasStarted;
	private boolean isStopping = false;

	/**
	 * Minimum uptime for us to consider a node an acceptable place to store a key. We store a key
	 * to the datastore only if it's from an insert, and we are a sink, but when calculating whether
	 * we are a sink we ignore nodes which have less uptime (percentage) than this parameter.
	 */
	static final int MIN_UPTIME_STORE_KEY = 40;

	private volatile boolean isPRNGReady = false;

	private boolean storePreallocate;
	
	private boolean enableRoutedPing;

	private boolean enableNodeDiagnostics;

	private boolean peersOffersDismissed;

	/**
	 * Minimum bandwidth limit in bytes considered usable: 10 KiB. If there is an attempt to set a limit below this -
	 * excluding the reserved -1 for input bandwidth - the callback will throw. See the callbacks for
	 * outputBandwidthLimit and inputBandwidthLimit. 10 KiB are equivalent to 50 GiB traffic per month.
	 */
	private static final int minimumBandwidth = 10 * 1024;

	/** Quality of Service mark we will use for all outgoing packets (opennet/darknet) */
	private TrafficClass trafficClass;
	public TrafficClass getTrafficClass() {
		return trafficClass;
	}

	/*
	 * Gets minimum bandwidth in bytes considered usable.
	 *
	 * @see #minimumBandwidth
	 */
	public static int getMinimumBandwidth() {
		return minimumBandwidth;
	}

	/**
	 * Dispatches a probe request with the specified settings
	 * @see freenet.node.probe.Probe#start(byte, long, Type, Listener)
	 */
	public void startProbe(final byte htl, final long uid, final Type type, final Listener listener) {
		dispatcher.probe.start(htl, uid, type, listener);
	}

	/**
	 * Read all storable settings (identity etc) from the node file.
	 * @param filename The name of the file to read from.
	 * @throws IOException throw when I/O error occur
	 */
	private void readNodeFile(String filename) throws IOException {
		// REDFLAG: Any way to share this code with NodePeer?
		FileInputStream fis = new FileInputStream(filename);
		InputStreamReader isr = new InputStreamReader(fis, "UTF-8");
		BufferedReader br = new BufferedReader(isr);
		SimpleFieldSet fs = new SimpleFieldSet(br, false, true);
		br.close();
		// Read contents
		String[] udp = fs.getAll("physical.udp");
		if((udp != null) && (udp.length > 0)) {
			for(String udpAddr : udp) {
				// Just keep the first one with the correct port number.
				Peer p;
				try {
					p = new Peer(udpAddr, false, true);
				} catch (HostnameSyntaxException e) {
					Logger.error(this, "Invalid hostname or IP Address syntax error while parsing our darknet node reference: "+udpAddr);
					System.err.println("Invalid hostname or IP Address syntax error while parsing our darknet node reference: "+udpAddr);
					continue;
				} catch (PeerParseException e) {
					throw (IOException)new IOException().initCause(e);
				}
				if(p.getPort() == getDarknetPortNumber()) {
					// DNSRequester doesn't deal with our own node
					ipDetector.setOldIPAddress(p.getFreenetAddress());
					break;
				}
			}
		}

		darknetCrypto.readCrypto(fs);

		swapIdentifier = Fields.bytesToLong(darknetCrypto.identityHashHash);
		String loc = fs.get("location");
		double locD = Location.getLocation(loc);
		if (locD == -1.0)
			throw new IOException("Invalid location: " + loc);
		lm.setLocation(locD);
		myName = fs.get("myName");
		if(myName == null) {
			myName = newName();
		}

		String verString = fs.get("version");
		if(verString == null) {
			Logger.error(this, "No version!");
			System.err.println("No version!");
		} else {
			lastVersion = Version.getArbitraryBuildNumber(verString, -1);
		}
	}

	public void makeStore(String val) throws InvalidConfigValueException {
		String suffix = getStoreSuffix();
		if (val.equals("salt-hash")) {
			try {
				initSaltHashFS(suffix, true, null);
			} catch (NodeInitException e) {
				Logger.error(this, "Unable to create new store", e);
				System.err.println("Unable to create new store: "+e);
				e.printStackTrace();
				// FIXME l10n both on the NodeInitException and the wrapper message
				throw new InvalidConfigValueException("Unable to create new store: "+e);
			}
		} else {
			initRAMFS();
		}

		synchronized(Node.this) {
			storeType = val;
		}
	}


	private String newName() {
		return "Freenet node with no name #"+random.nextLong();
	}

	private final Object writeNodeFileSync = new Object();

	public void writeNodeFile() {
		synchronized(writeNodeFileSync) {
			writeNodeFile(nodeDir.file("node-"+getDarknetPortNumber()), nodeDir.file("node-"+getDarknetPortNumber()+".bak"));
		}
	}

	public void writeOpennetFile() {
		OpennetManager om = opennet;
		if(om != null) om.writeFile();
	}

	private void writeNodeFile(File orig, File backup) {
		SimpleFieldSet fs = darknetCrypto.exportPrivateFieldSet();

		if(orig.exists()) backup.delete();

		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(backup);
			fs.writeTo(fos);
			fos.close();
			fos = null;
			FileUtil.renameTo(backup, orig);
		} catch (IOException ioe) {
			Logger.error(this, "IOE :"+ioe.getMessage(), ioe);
			return;
		} finally {
			Closer.close(fos);
		}
	}

	private void initNodeFileSettings() {
		Logger.normal(this, "Creating new node file from scratch");
		// Don't need to set getDarknetPortNumber()
		// FIXME use a real IP!
		darknetCrypto.initCrypto();
		swapIdentifier = Fields.bytesToLong(darknetCrypto.identityHashHash);
		myName = newName();
	}

	/**
	 * Read the config file from the arguments.
	 * Then create a node.
	 * Anything that needs static init should ideally be in here.
	 * @param args
	 */
	public static void main(String[] args) throws IOException {
		NodeStarter.main(args);
	}

	public boolean isUsingWrapper(){
		if(nodeStarter!=null && WrapperManager.isControlledByNativeWrapper())
			return true;
		else
			return false;
	}

	public NodeStarter getNodeStarter(){
		return nodeStarter;
	}

	/**
	 * Create a Node from a Config object.
	 * @param config The Config object for this node.
	 * @param r The random number generator for this node. Passed in because we may want
	 * to use a non-secure RNG for e.g. one-JVM live-code simulations. Should be a Yarrow in
	 * a production node. Yarrow will be used if that parameter is null
	 * @param weakRandom The fast random number generator the node will use. If null a MT
	 * instance will be used, seeded from the secure PRNG.
	 * @param lc logging config Handler
	 * @param ns NodeStarter
	 * @param executor Executor
	 * @throws NodeInitException If the node initialization fails.
	 */
	 Node(PersistentConfig config, RandomSource r, RandomSource weakRandom, LoggingConfigHandler lc, NodeStarter ns, Executor executor) throws NodeInitException {
		this.shutdownHook = SemiOrderedShutdownHook.get();
		// Easy stuff
		String tmp = "Initializing Node using Freenet Build #"+Version.buildNumber()+" r"+Version.cvsRevision()+" and freenet-ext Build #"+NodeStarter.extBuildNumber+" r"+NodeStarter.extRevisionNumber+" with "+System.getProperty("java.vendor")+" JVM version "+System.getProperty("java.version")+" running on "+System.getProperty("os.arch")+' '+System.getProperty("os.name")+' '+System.getProperty("os.version");
		fixCertsFiles();
		Logger.normal(this, tmp);
		System.out.println(tmp);
		collector = new IOStatisticCollector();
		this.executor = executor;
		nodeStarter=ns;
		if(logConfigHandler != lc)
			logConfigHandler=lc;
		getPubKey = new NodeGetPubkey(this);
		startupTime = System.currentTimeMillis();
		SimpleFieldSet oldConfig = config.getSimpleFieldSet();
		// Setup node-specific configuration
		final SubConfig nodeConfig = config.createSubConfig("node");
		final SubConfig installConfig = config.createSubConfig("node.install");

		int sortOrder = 0;

		// Directory for node-related files other than store
		this.userDir = setupProgramDir(installConfig, "userDir", ".",
		  "Node.userDir", "Node.userDirLong", nodeConfig);
		this.cfgDir = setupProgramDir(installConfig, "cfgDir", getUserDir().toString(),
		  "Node.cfgDir", "Node.cfgDirLong", nodeConfig);
		this.nodeDir = setupProgramDir(installConfig, "nodeDir", getUserDir().toString(),
		  "Node.nodeDir", "Node.nodeDirLong", nodeConfig);
		this.runDir = setupProgramDir(installConfig, "runDir", getUserDir().toString(),
		  "Node.runDir", "Node.runDirLong", nodeConfig);
		this.pluginDir = setupProgramDir(installConfig, "pluginDir",  userDir().file("plugins").toString(),
		  "Node.pluginDir", "Node.pluginDirLong", nodeConfig);

		// l10n stuffs
		nodeConfig.register("l10n", Locale.getDefault().getLanguage().toLowerCase(), sortOrder++, false, true,
				"Node.l10nLanguage",
				"Node.l10nLanguageLong",
				new L10nCallback());

		try {
			new NodeL10n(BaseL10n.LANGUAGE.mapToLanguage(nodeConfig.getString("l10n")), getCfgDir());
		} catch (MissingResourceException e) {
			try {
				new NodeL10n(BaseL10n.LANGUAGE.mapToLanguage(nodeConfig.getOption("l10n").getDefault()), getCfgDir());
			} catch (MissingResourceException e1) {
				new NodeL10n(BaseL10n.LANGUAGE.mapToLanguage(BaseL10n.LANGUAGE.getDefault().shortCode), getCfgDir());
			}
		}

		// FProxy config needs to be here too
		SubConfig fproxyConfig = config.createSubConfig("fproxy");
		try {
			toadlets = new SimpleToadletServer(fproxyConfig, new ArrayBucketFactory(), executor, this);
			fproxyConfig.finishedInitialization();
			toadlets.start();
		} catch (IOException e4) {
			Logger.error(this, "Could not start web interface: "+e4, e4);
			System.err.println("Could not start web interface: "+e4);
			e4.printStackTrace();
			throw new NodeInitException(NodeInitException.EXIT_COULD_NOT_START_FPROXY, "Could not start FProxy: "+e4);
		} catch (InvalidConfigValueException e4) {
			System.err.println("Invalid config value, cannot start web interface: "+e4);
			e4.printStackTrace();
			throw new NodeInitException(NodeInitException.EXIT_COULD_NOT_START_FPROXY, "Could not start FProxy: "+e4);
		}
		
		final NativeThread entropyGatheringThread = new NativeThread(new Runnable() {
			
			long tLastAdded = -1;

			private void recurse(File f) {
				if(isPRNGReady)
					return;
				extendTimeouts();
				File[] subDirs = f.listFiles(new FileFilter() {

					@Override
					public boolean accept(File pathname) {
						return pathname.exists() && pathname.canRead() && pathname.isDirectory();
					}
				});


				// @see http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=5086412
				if(subDirs != null)
					for(File currentDir : subDirs)
						recurse(currentDir);
			}

			@Override
			public void run() {
				try {
					// Delay entropy generation helper hack if enough entropy available
					Thread.sleep(100);
				} catch (InterruptedException e) {
				}
				if(isPRNGReady)
					return;
				System.out.println("Not enough entropy available.");
				System.out.println("Trying to gather entropy (randomness) by reading the disk...");
				if(File.separatorChar == '/') {
					if(new File("/dev/hwrng").exists())
						System.out.println("/dev/hwrng exists - have you installed rng-tools?");
					else
						System.out.println("You should consider installing a better random number generator e.g. haveged.");
				}
				extendTimeouts();
				for(File root : File.listRoots()) {
					if(isPRNGReady)
						return;
					recurse(root);
				}
			}
			
			/** This is ridiculous, but for some users it can take more than an hour, and timing out sucks
			 * a few bytes and then times out again. :( */
			static final int EXTEND_BY = 60*60*1000;
			
			private void extendTimeouts() {
				long now = System.currentTimeMillis();
				if(now - tLastAdded < EXTEND_BY/2) return;
				long target = tLastAdded + EXTEND_BY;
				while(target < now)
					target += EXTEND_BY;
				long extend = target - now;
				assert(extend < Integer.MAX_VALUE);
				assert(extend > 0);
				WrapperManager.signalStarting((int)extend);
				tLastAdded = now;
			}

		}, "Entropy Gathering Thread", NativeThread.MIN_PRIORITY, true);

		// Setup RNG if needed : DO NOT USE IT BEFORE THAT POINT!
		if (r == null) {
			// Preload required freenet.crypt.Util and freenet.crypt.Rijndael classes (selftest can delay Yarrow startup and trigger false lack-of-enthropy message)
			freenet.crypt.Util.mdProviders.size();
			freenet.crypt.ciphers.Rijndael.getProviderName();

			File seed = userDir.file("prng.seed");
			FileUtil.setOwnerRW(seed);
			entropyGatheringThread.start();
			// Can block.
			this.random = new Yarrow(seed);
			// http://bugs.sun.com/view_bug.do;jsessionid=ff625daf459fdffffffffcd54f1c775299e0?bug_id=4705093
			// This might block on /dev/random while doing new SecureRandom(). Once it's created, it won't block.
			ECDH.blockingInit();
		} else {
			this.random = r;
			// if it's not null it's because we are running in the simulator
		}
		// This can block too.
		this.secureRandom = NodeStarter.getGlobalSecureRandom();
		isPRNGReady = true;
		toadlets.getStartupToadlet().setIsPRNGReady();
		if(weakRandom == null) {
			byte buffer[] = new byte[16];
			random.nextBytes(buffer);
			this.fastWeakRandom = new MersenneTwister(buffer);
		}else
			this.fastWeakRandom = weakRandom;

		nodeNameUserAlert = new MeaningfulNodeNameUserAlert(this);
		this.config = config;
		lm = new LocationManager(random, this);

		try {
			localhostAddress = InetAddress.getByName("127.0.0.1");
		} catch (UnknownHostException e3) {
			// Does not do a reverse lookup, so this is impossible
			throw new Error(e3);
		}
		fLocalhostAddress = new FreenetInetAddress(localhostAddress);

		this.securityLevels = new SecurityLevels(this, config);

		// Location of master key
		nodeConfig.register("masterKeyFile", "master.keys", sortOrder++, true, true, "Node.masterKeyFile", "Node.masterKeyFileLong",
			new StringCallback() {

				@Override
				public String get() {
					if(masterKeysFile == null) return "none";
					else return masterKeysFile.getPath();
				}

				@Override
				public void set(String val) throws InvalidConfigValueException, NodeNeedRestartException {
					// FIXME l10n
					// FIXME wipe the old one and move
					throw new InvalidConfigValueException("Node.masterKeyFile cannot be changed on the fly, you must shutdown, wipe the old file and reconfigure");
				}

		});
		String value = nodeConfig.getString("masterKeyFile");
		File f;
		if (value.equalsIgnoreCase("none")) {
			f = null;
		} else {
			f = new File(value);

			if(f.exists() && !(f.canWrite() && f.canRead()))
				throw new NodeInitException(NodeInitException.EXIT_CANT_WRITE_MASTER_KEYS, "Cannot read from and write to master keys file "+f);
		}
		masterKeysFile = f;
		FileUtil.setOwnerRW(masterKeysFile);
		
		nodeConfig.register("showFriendsVisibilityAlert", false, sortOrder++, true, false, "Node.showFriendsVisibilityAlert", "Node.showFriendsVisibilityAlert", new BooleanCallback() {

			@Override
			public Boolean get() {
				synchronized(Node.this) {
					return showFriendsVisibilityAlert;
				}
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException,
					NodeNeedRestartException {
				synchronized(this) {
					if(val == showFriendsVisibilityAlert) return;
					if(val) return;
				}
				unregisterFriendsVisibilityAlert();
			}
			
			
			
		});
		
		showFriendsVisibilityAlert = nodeConfig.getBoolean("showFriendsVisibilityAlert");

        byte[] clientCacheKey = null;
        
        MasterSecret persistentSecret = null;
        for(int i=0;i<2; i++) {

            try {
                if(securityLevels.physicalThreatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
                    keys = MasterKeys.createRandom(secureRandom);
                } else {
                    keys = MasterKeys.read(masterKeysFile, secureRandom, "");
                }
                clientCacheKey = keys.clientCacheMasterKey;
                persistentSecret = keys.getPersistentMasterSecret();
                databaseKey = keys.createDatabaseKey(secureRandom);
                if(securityLevels.getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.HIGH) {
                    System.err.println("Physical threat level is set to HIGH but no password, resetting to NORMAL - probably timing glitch");
                    securityLevels.resetPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL.NORMAL);
                }
                break;
            } catch (MasterKeysWrongPasswordException e) {
                break;
            } catch (MasterKeysFileSizeException e) {
                System.err.println("Impossible: master keys file "+masterKeysFile+" too " + e.sizeToString() + "! Deleting to enable startup, but you will lose your client cache.");
                masterKeysFile.delete();
            } catch (IOException e) {
                break;
            }
        }

		// Boot ID
		bootID = random.nextLong();
		// Fixed length file containing boot ID. Accessed with random access file. So hopefully it will always be
		// written. Note that we set lastBootID to -1 if we can't _write_ our ID as well as if we can't read it,
		// because if we can't write it then we probably couldn't write it on the last bootup either.
		File bootIDFile = runDir.file("bootID");
		int BOOT_FILE_LENGTH = 64 / 4; // A long in padded hex bytes
		long oldBootID = -1;
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(bootIDFile, "rw");
			if(raf.length() < BOOT_FILE_LENGTH) {
				oldBootID = -1;
			} else {
				byte[] buf = new byte[BOOT_FILE_LENGTH];
				raf.readFully(buf);
				String s = new String(buf, "ISO-8859-1");
				try {
					oldBootID = Fields.bytesToLong(HexUtil.hexToBytes(s));
				} catch (NumberFormatException e) {
					oldBootID = -1;
				}
				raf.seek(0);
			}
			String s = HexUtil.bytesToHex(Fields.longToBytes(bootID));
			byte[] buf = s.getBytes("ISO-8859-1");
			if(buf.length != BOOT_FILE_LENGTH)
				System.err.println("Not 16 bytes for boot ID "+bootID+" - WTF??");
			raf.write(buf);
		} catch (IOException e) {
			oldBootID = -1;
			// If we have an error in reading, *or in writing*, we don't reliably know the last boot ID.
		} finally {
			Closer.close(raf);
		}
		lastBootID = oldBootID;

		nodeConfig.register("disableProbabilisticHTLs", false, sortOrder++, true, false, "Node.disablePHTLS", "Node.disablePHTLSLong",
				new BooleanCallback() {

					@Override
					public Boolean get() {
						return disableProbabilisticHTLs;
					}

					@Override
					public void set(Boolean val) throws InvalidConfigValueException {
						disableProbabilisticHTLs = val;
					}

		});

		disableProbabilisticHTLs = nodeConfig.getBoolean("disableProbabilisticHTLs");

		nodeConfig.register("maxHTL", DEFAULT_MAX_HTL, sortOrder++, true, false, "Node.maxHTL", "Node.maxHTLLong", new ShortCallback() {

					@Override
					public Short get() {
						return maxHTL;
					}

					@Override
					public void set(Short val) throws InvalidConfigValueException {
						if(val < 0) throw new InvalidConfigValueException("Impossible max HTL");
						maxHTL = val;
					}
		}, false);

		maxHTL = nodeConfig.getShort("maxHTL");

		 class TrafficClassCallback extends StringCallback implements EnumerableOptionCallback {
			 @Override
			 public String get() {
				 return trafficClass.name();
			 }

			 @Override
			 public void set(String tcName) throws InvalidConfigValueException, NodeNeedRestartException {
				 try {
					 trafficClass = TrafficClass.fromNameOrValue(tcName);
				 } catch (IllegalArgumentException e) {
					 throw new InvalidConfigValueException(e);
				 }
				 throw new NodeNeedRestartException("TrafficClass cannot change on the fly");
			 }

			 @Override
			 public String[] getPossibleValues() {
				 ArrayList<String> array = new ArrayList<String>();
				 for (TrafficClass tc : TrafficClass.values())
					 array.add(tc.name());
				 return array.toArray(new String[0]);
			 }
		 }
		 nodeConfig.register("trafficClass", TrafficClass.getDefault().name(), sortOrder++, true, false,
				     "Node.trafficClass", "Node.trafficClassLong",
				     new TrafficClassCallback());
		 String trafficClassValue = nodeConfig.getString("trafficClass");
		 try {
			 trafficClass = TrafficClass.fromNameOrValue(trafficClassValue);
		 } catch (IllegalArgumentException e) {
			 Logger.error(this, "Invalid trafficClass:"+trafficClassValue+" resetting the value to default.", e);
			 trafficClass = TrafficClass.getDefault();
		 }

		// FIXME maybe these should persist? They need to be private.
		decrementAtMax = random.nextDouble() <= DECREMENT_AT_MAX_PROB;
		decrementAtMin = random.nextDouble() <= DECREMENT_AT_MIN_PROB;

		// Determine where to bind to

		usm = new MessageCore(executor);

		// FIXME maybe these configs should actually be under a node.ip subconfig?
		ipDetector = new NodeIPDetector(this);
		sortOrder = ipDetector.registerConfigs(nodeConfig, sortOrder);

		// ARKs enabled?

		nodeConfig.register("enableARKs", true, sortOrder++, true, false, "Node.enableARKs", "Node.enableARKsLong", new BooleanCallback() {

			@Override
			public Boolean get() {
				return enableARKs;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException {
				throw new InvalidConfigValueException("Cannot change on the fly");
			}

			@Override
			public boolean isReadOnly() {
				        return true;
			        }
		});
		enableARKs = nodeConfig.getBoolean("enableARKs");

		nodeConfig.register("enablePerNodeFailureTables", true, sortOrder++, true, false, "Node.enablePerNodeFailureTables", "Node.enablePerNodeFailureTablesLong", new BooleanCallback() {

			@Override
			public Boolean get() {
				return enablePerNodeFailureTables;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException {
				throw new InvalidConfigValueException("Cannot change on the fly");
			}

			@Override
			public boolean isReadOnly() {
				        return true;
			      }
		});
		enablePerNodeFailureTables = nodeConfig.getBoolean("enablePerNodeFailureTables");

		nodeConfig.register("enableULPRDataPropagation", true, sortOrder++, true, false, "Node.enableULPRDataPropagation", "Node.enableULPRDataPropagationLong", new BooleanCallback() {

			@Override
			public Boolean get() {
				return enableULPRDataPropagation;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException {
				throw new InvalidConfigValueException("Cannot change on the fly");
			}

			@Override
			public boolean isReadOnly() {
				        return true;
			        }
		});
		enableULPRDataPropagation = nodeConfig.getBoolean("enableULPRDataPropagation");

		nodeConfig.register("enableSwapping", true, sortOrder++, true, false, "Node.enableSwapping", "Node.enableSwappingLong", new BooleanCallback() {

			@Override
			public Boolean get() {
				return enableSwapping;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException {
				throw new InvalidConfigValueException("Cannot change on the fly");
			}

			@Override
			public boolean isReadOnly() {
				        return true;
			        }
		});
		enableSwapping = nodeConfig.getBoolean("enableSwapping");

		/*
		 * Publish our peers' locations is enabled, even in MAXIMUM network security and/or HIGH friends security,
		 * because a node which doesn't publish its peers' locations will get dramatically less traffic.
		 *
		 * Publishing our peers' locations does make us slightly more vulnerable to some attacks, but I don't think
		 * it's a big difference: swapping reveals the same information, it just doesn't update as quickly. This
		 * may help slightly, but probably not dramatically against a clever attacker.
		 *
		 * FIXME review this decision.
		 */
		nodeConfig.register("publishOurPeersLocation", true, sortOrder++, true, false, "Node.publishOurPeersLocation", "Node.publishOurPeersLocationLong", new BooleanCallback() {

			@Override
			public Boolean get() {
				return publishOurPeersLocation;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException {
				publishOurPeersLocation = val;
			}
		});
		publishOurPeersLocation = nodeConfig.getBoolean("publishOurPeersLocation");

		nodeConfig.register("routeAccordingToOurPeersLocation", true, sortOrder++, true, false, "Node.routeAccordingToOurPeersLocation", "Node.routeAccordingToOurPeersLocation", new BooleanCallback() {

			@Override
			public Boolean get() {
				return routeAccordingToOurPeersLocation;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException {
				routeAccordingToOurPeersLocation = val;
			}
		});
		routeAccordingToOurPeersLocation = nodeConfig.getBoolean("routeAccordingToOurPeersLocation");

		nodeConfig.register("enableSwapQueueing", true, sortOrder++, true, false, "Node.enableSwapQueueing", "Node.enableSwapQueueingLong", new BooleanCallback() {
			@Override
			public Boolean get() {
				return enableSwapQueueing;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException {
				enableSwapQueueing = val;
			}

		});
		enableSwapQueueing = nodeConfig.getBoolean("enableSwapQueueing");

		nodeConfig.register("enablePacketCoalescing", true, sortOrder++, true, false, "Node.enablePacketCoalescing", "Node.enablePacketCoalescingLong", new BooleanCallback() {
			@Override
			public Boolean get() {
				return enablePacketCoalescing;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException {
				enablePacketCoalescing = val;
			}

		});
		enablePacketCoalescing = nodeConfig.getBoolean("enablePacketCoalescing");

		// Determine the port number
		// @see #191
		if(oldConfig != null && "-1".equals(oldConfig.get("node.listenPort")))
			throw new NodeInitException(NodeInitException.EXIT_COULD_NOT_BIND_USM, "Your freenet.ini file is corrupted! 'listenPort=-1'");
		NodeCryptoConfig darknetConfig = new NodeCryptoConfig(nodeConfig, sortOrder++, false, securityLevels);
		sortOrder += NodeCryptoConfig.OPTION_COUNT;

		darknetCrypto = new NodeCrypto(this, false, darknetConfig, startupTime, enableARKs);

		// Must be created after darknetCrypto
		dnsr = new DNSRequester(this);
		ps = new PacketSender(this);
		ticker = new PrioritizedTicker(executor, getDarknetPortNumber());
		if(executor instanceof PooledExecutor)
			((PooledExecutor)executor).setTicker(ticker);

		Logger.normal(Node.class, "Creating node...");

		shutdownHook.addEarlyJob(new Thread() {
			@Override
			public void run() {
				if (opennet != null)
					opennet.stop(false);
			}
		});

		shutdownHook.addEarlyJob(new Thread() {
			@Override
			public void run() {
				darknetCrypto.stop();
			}
		});

		// Bandwidth limit

		nodeConfig.register("outputBandwidthLimit", "15K", sortOrder++, false, true, "Node.outBWLimit", "Node.outBWLimitLong", new IntCallback() {
			@Override
			public Integer get() {
				//return BlockTransmitter.getHardBandwidthLimit();
				return outputBandwidthLimit;
			}
			@Override
			public void set(Integer obwLimit) throws InvalidConfigValueException {
				BandwidthManager.checkOutputBandwidthLimit(obwLimit);
				try {
					outputThrottle.changeNanosAndBucketSize(SECONDS.toNanos(1) / obwLimit, obwLimit/2);
				} catch (IllegalArgumentException e) {
					throw new InvalidConfigValueException(e);
				}
				synchronized(Node.this) {
					outputBandwidthLimit = obwLimit;
				}
			}
		});

		int obwLimit = nodeConfig.getInt("outputBandwidthLimit");
		if (obwLimit < minimumBandwidth) {
			obwLimit = minimumBandwidth; // upgrade slow nodes automatically
			Logger.normal(Node.class, "Output bandwidth was lower than minimum bandwidth. Increased to minimum bandwidth.");
		}

		outputBandwidthLimit = obwLimit;
		try {
			BandwidthManager.checkOutputBandwidthLimit(outputBandwidthLimit);
		} catch (InvalidConfigValueException e) {
			throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, e.getMessage());
		}

		// Bucket size of 0.5 seconds' worth of bytes.
		// Add them at a rate determined by the obwLimit.
		// Maximum forced bytes 80%, in other words, 20% of the bandwidth is reserved for
		// block transfers, so we will use that 20% for block transfers even if more than 80% of the limit is used for non-limited data (resends etc).
		int bucketSize = obwLimit/2;
		// Must have at least space for ONE PACKET.
		// FIXME: make compatible with alternate transports.
		bucketSize = Math.max(bucketSize, 2048);
		try {
		outputThrottle = new TokenBucket(bucketSize, SECONDS.toNanos(1) / obwLimit, obwLimit/2);
		} catch (IllegalArgumentException e) {
			throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, e.getMessage());
		}

		nodeConfig.register("inputBandwidthLimit", "-1", sortOrder++, false, true, "Node.inBWLimit", "Node.inBWLimitLong",	new IntCallback() {
			@Override
			public Integer get() {
				if(inputLimitDefault) return -1;
				return inputBandwidthLimit;
			}
			@Override
			public void set(Integer ibwLimit) throws InvalidConfigValueException {
				synchronized(Node.this) {
					BandwidthManager.checkInputBandwidthLimit(ibwLimit);

					if(ibwLimit == -1) {
						inputLimitDefault = true;
						ibwLimit = outputBandwidthLimit * 4;
					} else {
						inputLimitDefault = false;
					}

					inputBandwidthLimit = ibwLimit;
				}
			}
		});

		int ibwLimit = nodeConfig.getInt("inputBandwidthLimit");
		if(ibwLimit == -1) {
			inputLimitDefault = true;
			ibwLimit = obwLimit * 4;
		}
		else if (ibwLimit < minimumBandwidth) {
			ibwLimit = minimumBandwidth; // upgrade slow nodes automatically
			Logger.normal(Node.class, "Input bandwidth was lower than minimum bandwidth. Increased to minimum bandwidth.");
		}
		inputBandwidthLimit = ibwLimit;
		try {
			BandwidthManager.checkInputBandwidthLimit(inputBandwidthLimit);
		} catch (InvalidConfigValueException e) {
			throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, e.getMessage());
		}

		nodeConfig.register("amountOfDataToCheckCompressionRatio", "8MiB", sortOrder++,
				true, true, "Node.amountOfDataToCheckCompressionRatio",
				"Node.amountOfDataToCheckCompressionRatioLong", new LongCallback() {
			@Override
			public Long get() {
				return amountOfDataToCheckCompressionRatio;
			}
			@Override
			public void set(Long amountOfDataToCheckCompressionRatio) {
				synchronized(Node.this) {
					Node.this.amountOfDataToCheckCompressionRatio = amountOfDataToCheckCompressionRatio;
				}
			}
		}, true);

		amountOfDataToCheckCompressionRatio = nodeConfig.getLong("amountOfDataToCheckCompressionRatio");

		nodeConfig.register("minimumCompressionPercentage", "10", sortOrder++,
				true, true, "Node.minimumCompressionPercentage",
				"Node.minimumCompressionPercentageLong", new IntCallback() {
			@Override
			public Integer get() {
				return minimumCompressionPercentage;
			}
			@Override
			public void set(Integer minimumCompressionPercentage) {
				synchronized(Node.this) {
					if (minimumCompressionPercentage < 0 || minimumCompressionPercentage > 100) {
						Logger.normal(Node.class, "Wrong minimum compression percentage" + minimumCompressionPercentage);
						return;
					}

					Node.this.minimumCompressionPercentage = minimumCompressionPercentage;
				}
			}
		}, Dimension.NOT);

		minimumCompressionPercentage = nodeConfig.getInt("minimumCompressionPercentage");

		nodeConfig.register("maxTimeForSingleCompressor", "20m", sortOrder++,
				true, true, "Node.maxTimeForSingleCompressor",
				"Node.maxTimeForSingleCompressorLong", new IntCallback() {
			@Override
			public Integer get() {
						 return maxTimeForSingleCompressor;
					 }
			@Override
			public void set(Integer maxTimeForSingleCompressor) {
				synchronized(Node.this) {
					Node.this.maxTimeForSingleCompressor = maxTimeForSingleCompressor;
				}
			}
		}, Dimension.DURATION);

		maxTimeForSingleCompressor = nodeConfig.getInt("maxTimeForSingleCompressor");

		nodeConfig.register("connectionSpeedDetection", true, sortOrder++,
			true, true, "Node.connectionSpeedDetection",
			"Node.connectionSpeedDetectionLong", new BooleanCallback() {
			@Override
			public Boolean get() {
				return connectionSpeedDetection;
			}
			@Override
			public void set(Boolean connectionSpeedDetection) {
				synchronized(Node.this) {
					Node.this.connectionSpeedDetection = connectionSpeedDetection;
				}
			}
		});

		connectionSpeedDetection = nodeConfig.getBoolean("connectionSpeedDetection");

		nodeConfig.register("throttleLocalTraffic", false, sortOrder++, true, false, "Node.throttleLocalTraffic", "Node.throttleLocalTrafficLong", new BooleanCallback() {

			@Override
			public Boolean get() {
				return throttleLocalData;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException {
				throttleLocalData = val;
			}

		});

		throttleLocalData = nodeConfig.getBoolean("throttleLocalTraffic");

		String s = "Testnet mode DISABLED. You may have some level of anonymity. :)\n"+
		"Note that this version of Freenet is still a very early alpha, and may well have numerous bugs and design flaws.\n"+
		"In particular: YOU ARE WIDE OPEN TO YOUR IMMEDIATE PEERS! They can eavesdrop on your requests with relatively little difficulty at present (correlation attacks etc).";
		Logger.normal(this, s);
		System.err.println(s);

		File nodeFile = nodeDir.file("node-"+getDarknetPortNumber());
		File nodeFileBackup = nodeDir.file("node-"+getDarknetPortNumber()+".bak");
		// After we have set up testnet and IP address, load the node file
		try {
			// FIXME should take file directly?
			readNodeFile(nodeFile.getPath());
		} catch (IOException e) {
			try {
				System.err.println("Trying to read node file backup ...");
				readNodeFile(nodeFileBackup.getPath());
			} catch (IOException e1) {
				if(nodeFile.exists() || nodeFileBackup.exists()) {
					System.err.println("No node file or cannot read, (re)initialising crypto etc");
					System.err.println(e1.toString());
					e1.printStackTrace();
					System.err.println("After:");
					System.err.println(e.toString());
					e.printStackTrace();
				} else {
					System.err.println("Creating new cryptographic keys...");
				}
				initNodeFileSettings();
			}
		}

		// Then read the peers
		peers = new PeerManager(this, shutdownHook);
		
		tracker = new RequestTracker(peers, ticker);

		usm.setDispatcher(dispatcher=new NodeDispatcher(this));

		uptime = new UptimeEstimator(runDir, ticker, darknetCrypto.identityHash);

		// ULPRs

		failureTable = new FailureTable(this);

		nodeStats = new NodeStats(this, sortOrder, config.createSubConfig("node.load"), obwLimit, ibwLimit, lastVersion);

		// clientCore needs new load management and other settings from stats.
		clientCore = new NodeClientCore(this, config, nodeConfig, installConfig, getDarknetPortNumber(), sortOrder, oldConfig, fproxyConfig, toadlets, databaseKey, persistentSecret);
		toadlets.setCore(clientCore);

		if (JVMVersion.isEOL()) {
			clientCore.alerts.register(new JVMVersionAlert());
		}

		if(showFriendsVisibilityAlert)
			registerFriendsVisibilityAlert();
		
		// Node updater support

		System.out.println("Initializing Node Updater");
		try {
			nodeUpdater = NodeUpdateManager.maybeCreate(this, config);
		} catch (InvalidConfigValueException e) {
			e.printStackTrace();
			throw new NodeInitException(NodeInitException.EXIT_COULD_NOT_START_UPDATER, "Could not create Updater: "+e);
		}

		// Opennet

		final SubConfig opennetConfig = config.createSubConfig("node.opennet");
		opennetConfig.register("connectToSeednodes", true, 0, true, false, "Node.withAnnouncement", "Node.withAnnouncementLong", new BooleanCallback() {
			@Override
			public Boolean get() {
				return isAllowedToConnectToSeednodes;
			}
			@Override
			public void set(Boolean val) throws InvalidConfigValueException, NodeNeedRestartException {
				if (get().equals(val))
					        return;
				synchronized(Node.this) {
					isAllowedToConnectToSeednodes = val;
					if(opennet != null)
						throw new NodeNeedRestartException(l10n("connectToSeednodesCannotBeChangedMustDisableOpennetOrReboot"));
				}
			}
		});
		isAllowedToConnectToSeednodes = opennetConfig.getBoolean("connectToSeednodes");

		// Can be enabled on the fly
		opennetConfig.register("enabled", false, 0, true, true, "Node.opennetEnabled", "Node.opennetEnabledLong", new BooleanCallback() {
			@Override
			public Boolean get() {
				synchronized(Node.this) {
					return opennet != null;
				}
			}
			@Override
			public void set(Boolean val) throws InvalidConfigValueException {
				OpennetManager o;
				synchronized(Node.this) {
					if(val == (opennet != null)) return;
					if(val) {
						try {
							o = opennet = new OpennetManager(Node.this, opennetCryptoConfig, System.currentTimeMillis(), isAllowedToConnectToSeednodes);
						} catch (NodeInitException e) {
							opennet = null;
							throw new InvalidConfigValueException(e.getMessage());
						}
					} else {
						o = opennet;
						opennet = null;
					}
				}
				if(val) o.start();
				else o.stop(true);
				ipDetector.ipDetectorManager.notifyPortChange(getPublicInterfacePorts());
			}
		});
		boolean opennetEnabled = opennetConfig.getBoolean("enabled");

		opennetConfig.register("maxOpennetPeers", OpennetManager.MAX_PEERS_FOR_SCALING, 1, true, false, "Node.maxOpennetPeers",
				"Node.maxOpennetPeersLong", new IntCallback() {
					@Override
					public Integer get() {
						return maxOpennetPeers;
					}
					@Override
					public void set(Integer inputMaxOpennetPeers) throws InvalidConfigValueException {
						if(inputMaxOpennetPeers < 0) throw new InvalidConfigValueException(l10n("mustBePositive"));
						if(inputMaxOpennetPeers > OpennetManager.MAX_PEERS_FOR_SCALING) throw new InvalidConfigValueException(l10n("maxOpennetPeersMustBeTwentyOrLess", "maxpeers", Integer.toString(OpennetManager.MAX_PEERS_FOR_SCALING)));
						maxOpennetPeers = inputMaxOpennetPeers;
						}
					}
		, false);

		maxOpennetPeers = opennetConfig.getInt("maxOpennetPeers");
		if(maxOpennetPeers > OpennetManager.MAX_PEERS_FOR_SCALING) {
			Logger.error(this, "maxOpennetPeers may not be over "+OpennetManager.MAX_PEERS_FOR_SCALING);
			maxOpennetPeers = OpennetManager.MAX_PEERS_FOR_SCALING;
		}

		opennetCryptoConfig = new NodeCryptoConfig(opennetConfig, 2 /* 0 = enabled */, true, securityLevels);

		if(opennetEnabled) {
			opennet = new OpennetManager(this, opennetCryptoConfig, System.currentTimeMillis(), isAllowedToConnectToSeednodes);
			// Will be started later
		} else {
			opennet = null;
		}

		securityLevels.addNetworkThreatLevelListener(new SecurityLevelListener<NETWORK_THREAT_LEVEL>() {

			@Override
			public void onChange(NETWORK_THREAT_LEVEL oldLevel, NETWORK_THREAT_LEVEL newLevel) {
				if(newLevel == NETWORK_THREAT_LEVEL.HIGH
						|| newLevel == NETWORK_THREAT_LEVEL.MAXIMUM) {
					OpennetManager om;
					synchronized(Node.this) {
						om = opennet;
						if(om != null)
							opennet = null;
					}
					if(om != null) {
						om.stop(true);
						ipDetector.ipDetectorManager.notifyPortChange(getPublicInterfacePorts());
					}
				} else if(newLevel == NETWORK_THREAT_LEVEL.NORMAL
						|| newLevel == NETWORK_THREAT_LEVEL.LOW) {
					OpennetManager o = null;
					synchronized(Node.this) {
						if(opennet == null) {
							try {
								o = opennet = new OpennetManager(Node.this, opennetCryptoConfig, System.currentTimeMillis(), isAllowedToConnectToSeednodes);
							} catch (NodeInitException e) {
								opennet = null;
								Logger.error(this, "UNABLE TO ENABLE OPENNET: "+e, e);
								clientCore.alerts.register(new SimpleUserAlert(false, l10n("enableOpennetFailedTitle"), l10n("enableOpennetFailed", "message", e.getLocalizedMessage()), l10n("enableOpennetFailed", "message", e.getLocalizedMessage()), UserAlert.ERROR));
							}
						}
					}
					if(o != null) {
						o.start();
						ipDetector.ipDetectorManager.notifyPortChange(getPublicInterfacePorts());
					}
				}
				Node.this.config.store();
			}

		});

		opennetConfig.register("acceptSeedConnections", false, 2, true, true, "Node.acceptSeedConnectionsShort", "Node.acceptSeedConnections", new BooleanCallback() {

			@Override
			public Boolean get() {
				return acceptSeedConnections;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException {
				acceptSeedConnections = val;
			}

		});

		acceptSeedConnections = opennetConfig.getBoolean("acceptSeedConnections");

		if(acceptSeedConnections && opennet != null)
			opennet.crypto.socket.getAddressTracker().setHugeTracker();

		opennetConfig.finishedInitialization();

		nodeConfig.register("passOpennetPeersThroughDarknet", true, sortOrder++, true, false, "Node.passOpennetPeersThroughDarknet", "Node.passOpennetPeersThroughDarknetLong",
				new BooleanCallback() {

					@Override
					public Boolean get() {
						synchronized(Node.this) {
							return passOpennetRefsThroughDarknet;
						}
					}

					@Override
					public void set(Boolean val) throws InvalidConfigValueException {
						synchronized(Node.this) {
							passOpennetRefsThroughDarknet = val;
						}
					}

		});

		passOpennetRefsThroughDarknet = nodeConfig.getBoolean("passOpennetPeersThroughDarknet");

		this.extraPeerDataDir = userDir.file("extra-peer-data-"+getDarknetPortNumber());
		if (!((extraPeerDataDir.exists() && extraPeerDataDir.isDirectory()) || (extraPeerDataDir.mkdir()))) {
			String msg = "Could not find or create extra peer data directory";
			throw new NodeInitException(NodeInitException.EXIT_BAD_DIR, msg);
		}

		// Name
		nodeConfig.register("name", myName, sortOrder++, false, true, "Node.nodeName", "Node.nodeNameLong",
						new NodeNameCallback());
		myName = nodeConfig.getString("name");

		// Datastore
		nodeConfig.register("storeForceBigShrinks", false, sortOrder++, true, false, "Node.forceBigShrink", "Node.forceBigShrinkLong",
				new BooleanCallback() {

					@Override
					public Boolean get() {
						synchronized(Node.this) {
							return storeForceBigShrinks;
						}
					}

					@Override
					public void set(Boolean val) throws InvalidConfigValueException {
						synchronized(Node.this) {
							storeForceBigShrinks = val;
						}
					}

		});

		// Datastore

		nodeConfig.register("storeType", "ram", sortOrder++, true, true, "Node.storeType", "Node.storeTypeLong", new StoreTypeCallback());

		storeType = nodeConfig.getString("storeType");

		/*
		 * Very small initial store size, since the node will preallocate it when starting up for the first time,
		 * BLOCKING STARTUP, and since everyone goes through the wizard anyway...
		 */
		nodeConfig.register("storeSize", DEFAULT_STORE_SIZE, sortOrder++, false, true, "Node.storeSize", "Node.storeSizeLong",
				new LongCallback() {

					@Override
					public Long get() {
						return maxTotalDatastoreSize;
					}

					@Override
					public void set(Long storeSize) throws InvalidConfigValueException {
						if(storeSize < MIN_STORE_SIZE)
							throw new InvalidConfigValueException(l10n("invalidStoreSize"));
						long newMaxStoreKeys = storeSize / sizePerKey;
						if(newMaxStoreKeys == maxTotalKeys) return;
						// Update each datastore
						synchronized(Node.this) {
							maxTotalDatastoreSize = storeSize;
							maxTotalKeys = newMaxStoreKeys;
							maxStoreKeys = maxTotalKeys / 2;
							maxCacheKeys = maxTotalKeys - maxStoreKeys;
						}
						try {
							chkDatastore.setMaxKeys(maxStoreKeys, storeForceBigShrinks);
							chkDatacache.setMaxKeys(maxCacheKeys, storeForceBigShrinks);
							pubKeyDatastore.setMaxKeys(maxStoreKeys, storeForceBigShrinks);
							pubKeyDatacache.setMaxKeys(maxCacheKeys, storeForceBigShrinks);
							sskDatastore.setMaxKeys(maxStoreKeys, storeForceBigShrinks);
							sskDatacache.setMaxKeys(maxCacheKeys, storeForceBigShrinks);
						} catch (IOException e) {
							// FIXME we need to be able to tell the user.
							Logger.error(this, "Caught "+e+" resizing the datastore", e);
							System.err.println("Caught "+e+" resizing the datastore");
							e.printStackTrace();
						}
						//Perhaps a bit hackish...? Seems like this should be near it's definition in NodeStats.
						nodeStats.avgStoreCHKLocation.changeMaxReports((int)maxStoreKeys);
						nodeStats.avgCacheCHKLocation.changeMaxReports((int)maxCacheKeys);
						nodeStats.avgSlashdotCacheCHKLocation.changeMaxReports((int)maxCacheKeys);
						nodeStats.avgClientCacheCHKLocation.changeMaxReports((int)maxCacheKeys);

						nodeStats.avgStoreSSKLocation.changeMaxReports((int)maxStoreKeys);
						nodeStats.avgCacheSSKLocation.changeMaxReports((int)maxCacheKeys);
						nodeStats.avgSlashdotCacheSSKLocation.changeMaxReports((int)maxCacheKeys);
						nodeStats.avgClientCacheSSKLocation.changeMaxReports((int)maxCacheKeys);
					}
		}, true);

		maxTotalDatastoreSize = nodeConfig.getLong("storeSize");

		if(maxTotalDatastoreSize < MIN_STORE_SIZE && !storeType.equals("ram")) { // totally arbitrary minimum!
			throw new NodeInitException(NodeInitException.EXIT_INVALID_STORE_SIZE, "Store size too small");
		}

		maxTotalKeys = maxTotalDatastoreSize / sizePerKey;
		
		nodeConfig.register("storeUseSlotFilters", true, sortOrder++, true, false, "Node.storeUseSlotFilters", "Node.storeUseSlotFiltersLong", new BooleanCallback() {

			public Boolean get() {
				synchronized(Node.this) {
					return storeUseSlotFilters;
				}
			}

			public void set(Boolean val) throws InvalidConfigValueException,
					NodeNeedRestartException {
				synchronized(Node.this) {
					storeUseSlotFilters = val;
				}
				
				// FIXME l10n
				throw new NodeNeedRestartException("Need to restart to change storeUseSlotFilters");
			}
			
		});
		
		storeUseSlotFilters = nodeConfig.getBoolean("storeUseSlotFilters");
		
		nodeConfig.register("storeSaltHashSlotFilterPersistenceTime", ResizablePersistentIntBuffer.DEFAULT_PERSISTENCE_TIME, sortOrder++, true, false, 
				"Node.storeSaltHashSlotFilterPersistenceTime", "Node.storeSaltHashSlotFilterPersistenceTimeLong", new IntCallback() {

					@Override
					public Integer get() {
						return ResizablePersistentIntBuffer.getPersistenceTime();
					}

					@Override
					public void set(Integer val)
							throws InvalidConfigValueException,
							NodeNeedRestartException {
						if(val >= -1)
							ResizablePersistentIntBuffer.setPersistenceTime(val);
						else
							throw new InvalidConfigValueException(l10n("slotFilterPersistenceTimeError"));
					}
			
		}, false);

		nodeConfig.register("storeSaltHashResizeOnStart", false, sortOrder++, true, false,
				"Node.storeSaltHashResizeOnStart", "Node.storeSaltHashResizeOnStartLong", new BooleanCallback() {
			@Override
			public Boolean get() {
				return storeSaltHashResizeOnStart;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException, NodeNeedRestartException {
				storeSaltHashResizeOnStart = val;
			}
		});
		storeSaltHashResizeOnStart = nodeConfig.getBoolean("storeSaltHashResizeOnStart");

		this.storeDir = setupProgramDir(installConfig, "storeDir", userDir().file("datastore").getPath(), "Node.storeDirectory", "Node.storeDirectoryLong", nodeConfig);
		installConfig.finishedInitialization();

		final String suffix = getStoreSuffix();

		maxStoreKeys = maxTotalKeys / 2;
		maxCacheKeys = maxTotalKeys - maxStoreKeys;

		/*
		 * On Windows, setting the file length normally involves writing lots of zeros.
		 * So it's an uninterruptible system call that takes a loooong time. On OS/X,
		 * presumably the same is true. If the RNG is fast enough, this means that
		 * setting the length and writing random data take exactly the same amount
		 * of time. On most versions of Unix, holes can be created. However on all
		 * systems, predictable disk usage is a good thing. So lets turn it on by
		 * default for now, on all systems. The datastore can be read but mostly not
		 * written while the random data is being written.
		 */
		nodeConfig.register("storePreallocate", true, sortOrder++, true, true, "Node.storePreallocate", "Node.storePreallocateLong",
				new BooleanCallback() {
					@Override
                    public Boolean get() {
	                    return storePreallocate;
                    }

					@Override
                    public void set(Boolean val) throws InvalidConfigValueException, NodeNeedRestartException {
						storePreallocate = val;
						if (storeType.equals("salt-hash")) {
							setPreallocate(chkDatastore, val);
							setPreallocate(chkDatacache, val);
							setPreallocate(pubKeyDatastore, val);
							setPreallocate(pubKeyDatacache, val);
							setPreallocate(sskDatastore, val);
							setPreallocate(sskDatacache, val);
						}
                    }

					private void setPreallocate(StoreCallback<?> datastore,
							boolean val) {
						// Avoid race conditions by checking first.
						FreenetStore<?> store = datastore.getStore();
						if(store instanceof SaltedHashFreenetStore)
							((SaltedHashFreenetStore<?>)store).setPreallocate(val);
					}}
		);
		storePreallocate = nodeConfig.getBoolean("storePreallocate");

		if(File.separatorChar == '/' && System.getProperty("os.name").toLowerCase().indexOf("mac os") < 0) {
			securityLevels.addPhysicalThreatLevelListener(new SecurityLevelListener<SecurityLevels.PHYSICAL_THREAT_LEVEL>() {

				@Override
				public void onChange(PHYSICAL_THREAT_LEVEL oldLevel, PHYSICAL_THREAT_LEVEL newLevel) {
					try {
						if(newLevel == PHYSICAL_THREAT_LEVEL.LOW)
							nodeConfig.set("storePreallocate", false);
						else
							nodeConfig.set("storePreallocate", true);
					} catch (NodeNeedRestartException e) {
						// Ignore
					} catch (InvalidConfigValueException e) {
						// Ignore
					}
				}
			});
		}

		securityLevels.addPhysicalThreatLevelListener(new SecurityLevelListener<SecurityLevels.PHYSICAL_THREAT_LEVEL>() {

			@Override
			public void onChange(PHYSICAL_THREAT_LEVEL oldLevel, PHYSICAL_THREAT_LEVEL newLevel) {
					if(newLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
						synchronized(this) {
							clientCacheAwaitingPassword = false;
							databaseAwaitingPassword = false;
						}
						try {
                            killMasterKeysFile();
						    clientCore.clientLayerPersister.disableWrite();
						    clientCore.clientLayerPersister.waitForNotWriting();
                            clientCore.clientLayerPersister.deleteAllFiles();
						} catch (IOException e) {
							masterKeysFile.delete();
							Logger.error(this, "Unable to securely delete "+masterKeysFile);
							System.err.println(NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFile", "filename", masterKeysFile.getAbsolutePath()));
							clientCore.alerts.register(new SimpleUserAlert(true, NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFileTitle"), NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFile"), NodeL10n.getBase().getString("SecurityLevels.cantDeletePasswordFileTitle"), UserAlert.CRITICAL_ERROR));
						}
					}
					if(oldLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM && newLevel != PHYSICAL_THREAT_LEVEL.HIGH) {
					    // Not passworded.
					    // Create the master.keys.
					    // Keys must exist.
					    try {
					        MasterKeys keys;
					        synchronized(this) {
					            keys = Node.this.keys;
					        }
                            keys.changePassword(masterKeysFile, "", secureRandom);
                        } catch (IOException e) {
                            Logger.error(this, "Unable to create encryption keys file: "+masterKeysFile+" : "+e, e);
                            System.err.println("Unable to create encryption keys file: "+masterKeysFile+" : "+e);
                            e.printStackTrace();
                        }
					}
				}

			});

		if(securityLevels.physicalThreatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
			try {
				killMasterKeysFile();
			} catch (IOException e) {
				String msg = "Unable to securely delete old master.keys file when switching to MAXIMUM seclevel!!";
				System.err.println(msg);
				throw new NodeInitException(NodeInitException.EXIT_CANT_WRITE_MASTER_KEYS, msg);
			}
		}
		
		long defaultCacheSize;
		long memoryLimit = NodeStarter.getMemoryLimitBytes();
		// This is tricky because systems with low memory probably also have slow disks, but using 
		// up too much memory can be catastrophic...
		// Total alchemy, FIXME!
		if(memoryLimit == Long.MAX_VALUE || memoryLimit < 0)
			defaultCacheSize = 1024*1024;
		else if(memoryLimit <= 128*1024*1024)
			defaultCacheSize = 0; // Turn off completely for very small memory.
		else {
			// 9 stores, total should be 5% of memory, up to maximum of 1MB per store at 308MB+
			defaultCacheSize = Math.min(1024*1024, (memoryLimit - 128*1024*1024) / (20*9));
		}
		
		nodeConfig.register("cachingFreenetStoreMaxSize", defaultCacheSize, sortOrder++, true, false, "Node.cachingFreenetStoreMaxSize", "Node.cachingFreenetStoreMaxSizeLong",
			new LongCallback() {
				@Override
				public Long get() {
					synchronized(Node.this) {
						return cachingFreenetStoreMaxSize;
					}
				}

				@Override
				public void set(Long val) throws InvalidConfigValueException, NodeNeedRestartException {
					if(val < 0) throw new InvalidConfigValueException(l10n("invalidMemoryCacheSize"));
					// Any positive value is legal. In particular, e.g. 1200 bytes would cause us to cache SSKs but not CHKs.
					synchronized(Node.this) {
						cachingFreenetStoreMaxSize = val;
					}
					throw new NodeNeedRestartException("Caching Maximum Size cannot be changed on the fly");
				}
		}, true);
		
		cachingFreenetStoreMaxSize = nodeConfig.getLong("cachingFreenetStoreMaxSize");
		if(cachingFreenetStoreMaxSize < 0)
			throw new NodeInitException(NodeInitException.EXIT_BAD_CONFIG, l10n("invalidMemoryCacheSize"));
		
		nodeConfig.register("cachingFreenetStorePeriod", "300k", sortOrder++, true, false, "Node.cachingFreenetStorePeriod", "Node.cachingFreenetStorePeriod",
			new LongCallback() {
				@Override
				public Long get() {
					synchronized(Node.this) {
						return cachingFreenetStorePeriod;
					}
				}

				@Override
				public void set(Long val) throws InvalidConfigValueException, NodeNeedRestartException {
					synchronized(Node.this) {
						cachingFreenetStorePeriod = val;
					}
					throw new NodeNeedRestartException("Caching Period cannot be changed on the fly");
				}
		}, true);
		
		cachingFreenetStorePeriod = nodeConfig.getLong("cachingFreenetStorePeriod");
		
		if(cachingFreenetStoreMaxSize > 0 && cachingFreenetStorePeriod > 0) {
			cachingFreenetStoreTracker = new CachingFreenetStoreTracker(cachingFreenetStoreMaxSize, cachingFreenetStorePeriod, ticker);
		}

		boolean shouldWriteConfig = false;

		if(storeType.equals("bdb-index")) {
			System.err.println("Old format Berkeley DB datastore detected.");
			System.err.println("This datastore format is no longer supported.");
			System.err.println("The old datastore will be securely deleted.");
			storeType = "salt-hash";
			shouldWriteConfig = true;
			deleteOldBDBIndexStoreFiles();
		}
		if (storeType.equals("salt-hash")) {
			initRAMFS();
			initSaltHashFS(suffix, false, null);
		} else {
			initRAMFS();
		}

		if(databaseAwaitingPassword) createPasswordUserAlert();

		// Client cache

		// Default is 10MB, in memory only. The wizard will change this.

		nodeConfig.register("clientCacheType", "ram", sortOrder++, true, true, "Node.clientCacheType", "Node.clientCacheTypeLong", new ClientCacheTypeCallback());

		clientCacheType = nodeConfig.getString("clientCacheType");

		nodeConfig.register("clientCacheSize", DEFAULT_CLIENT_CACHE_SIZE, sortOrder++, false, true, "Node.clientCacheSize", "Node.clientCacheSizeLong",
				new LongCallback() {

					@Override
					public Long get() {
						return maxTotalClientCacheSize;
					}

					@Override
					public void set(Long storeSize) throws InvalidConfigValueException {
						if(storeSize < MIN_CLIENT_CACHE_SIZE)
							throw new InvalidConfigValueException(l10n("invalidStoreSize"));
						long newMaxStoreKeys = storeSize / sizePerKey;
						if(newMaxStoreKeys == maxClientCacheKeys) return;
						// Update each datastore
						synchronized(Node.this) {
							maxTotalClientCacheSize = storeSize;
							maxClientCacheKeys = newMaxStoreKeys;
						}
						try {
							chkClientcache.setMaxKeys(maxClientCacheKeys, storeForceBigShrinks);
							pubKeyClientcache.setMaxKeys(maxClientCacheKeys, storeForceBigShrinks);
							sskClientcache.setMaxKeys(maxClientCacheKeys, storeForceBigShrinks);
						} catch (IOException e) {
							// FIXME we need to be able to tell the user.
							Logger.error(this, "Caught "+e+" resizing the clientcache", e);
							System.err.println("Caught "+e+" resizing the clientcache");
							e.printStackTrace();
						}
					}
		}, true);

		maxTotalClientCacheSize = nodeConfig.getLong("clientCacheSize");

		if(maxTotalClientCacheSize < MIN_CLIENT_CACHE_SIZE) {
			throw new NodeInitException(NodeInitException.EXIT_INVALID_STORE_SIZE, "Client cache size too small");
		}

		maxClientCacheKeys = maxTotalClientCacheSize / sizePerKey;

		boolean startedClientCache = false;

		if (clientCacheType.equals("salt-hash")) {
		    if(clientCacheKey == null) {
		        System.err.println("Cannot open client-cache, it is passworded");
		        setClientCacheAwaitingPassword();
		    } else {
		        initSaltHashClientCacheFS(suffix, false, clientCacheKey);
		        startedClientCache = true;
		    }
		} else if(clientCacheType.equals("none")) {
			initNoClientCacheFS();
			startedClientCache = true;
		} else { // ram
			initRAMClientCacheFS();
			startedClientCache = true;
		}
		if(!startedClientCache)
			initRAMClientCacheFS();
		
		if(!clientCore.loadedDatabase() && databaseKey != null)  {
			try {
				lateSetupDatabase(databaseKey);
			} catch (MasterKeysWrongPasswordException e2) {
				System.err.println("Impossible: "+e2);
				e2.printStackTrace();
			} catch (MasterKeysFileSizeException e2) {
				System.err.println("Impossible: "+e2);
				e2.printStackTrace();
			} catch (IOException e2) {
				System.err.println("Unable to load database: "+e2);
				e2.printStackTrace();
			}
		}

		nodeConfig.register("useSlashdotCache", true, sortOrder++, true, false, "Node.useSlashdotCache", "Node.useSlashdotCacheLong", new BooleanCallback() {

			@Override
			public Boolean get() {
				return useSlashdotCache;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException, NodeNeedRestartException {
				useSlashdotCache = val;
			}

		});
		useSlashdotCache = nodeConfig.getBoolean("useSlashdotCache");

		nodeConfig.register("writeLocalToDatastore", false, sortOrder++, true, false, "Node.writeLocalToDatastore", "Node.writeLocalToDatastoreLong", new BooleanCallback() {

			@Override
			public Boolean get() {
				return writeLocalToDatastore;
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException, NodeNeedRestartException {
				writeLocalToDatastore = val;
			}

		});

		writeLocalToDatastore = nodeConfig.getBoolean("writeLocalToDatastore");

		// LOW network *and* physical seclevel = writeLocalToDatastore

		securityLevels.addNetworkThreatLevelListener(new SecurityLevelListener<NETWORK_THREAT_LEVEL>() {

			@Override
			public void onChange(NETWORK_THREAT_LEVEL oldLevel, NETWORK_THREAT_LEVEL newLevel) {
				if(newLevel == NETWORK_THREAT_LEVEL.LOW && securityLevels.getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.LOW)
					writeLocalToDatastore = true;
				else
					writeLocalToDatastore = false;
			}

		});

		securityLevels.addPhysicalThreatLevelListener(new SecurityLevelListener<PHYSICAL_THREAT_LEVEL>() {

			@Override
			public void onChange(PHYSICAL_THREAT_LEVEL oldLevel, PHYSICAL_THREAT_LEVEL newLevel) {
				if(newLevel == PHYSICAL_THREAT_LEVEL.LOW && securityLevels.getNetworkThreatLevel() == NETWORK_THREAT_LEVEL.LOW)
					writeLocalToDatastore = true;
				else
					writeLocalToDatastore = false;
			}

		});

		nodeConfig.register("slashdotCacheLifetime", MINUTES.toMillis(30), sortOrder++, true, false, "Node.slashdotCacheLifetime", "Node.slashdotCacheLifetimeLong", new LongCallback() {

			@Override
			public Long get() {
				return chkSlashdotcacheStore.getLifetime();
			}

			@Override
			public void set(Long val) throws InvalidConfigValueException, NodeNeedRestartException {
				if(val < 0) throw new InvalidConfigValueException("Must be positive!");
				chkSlashdotcacheStore.setLifetime(val);
				pubKeySlashdotcacheStore.setLifetime(val);
				sskSlashdotcacheStore.setLifetime(val);
			}

		}, false);

		long slashdotCacheLifetime = nodeConfig.getLong("slashdotCacheLifetime");

		nodeConfig.register("slashdotCacheSize", DEFAULT_SLASHDOT_CACHE_SIZE, sortOrder++, false, true, "Node.slashdotCacheSize", "Node.slashdotCacheSizeLong",
				new LongCallback() {

					@Override
					public Long get() {
						return maxSlashdotCacheSize;
					}

					@Override
					public void set(Long storeSize) throws InvalidConfigValueException {
						if(storeSize < MIN_SLASHDOT_CACHE_SIZE)
							throw new InvalidConfigValueException(l10n("invalidStoreSize"));
						int newMaxStoreKeys = (int) Math.min(storeSize / sizePerKey, Integer.MAX_VALUE);
						if(newMaxStoreKeys == maxSlashdotCacheKeys) return;
						// Update each datastore
						synchronized(Node.this) {
							maxSlashdotCacheSize = storeSize;
							maxSlashdotCacheKeys = newMaxStoreKeys;
						}
						try {
							chkSlashdotcache.setMaxKeys(maxSlashdotCacheKeys, storeForceBigShrinks);
							pubKeySlashdotcache.setMaxKeys(maxSlashdotCacheKeys, storeForceBigShrinks);
							sskSlashdotcache.setMaxKeys(maxSlashdotCacheKeys, storeForceBigShrinks);
						} catch (IOException e) {
							// FIXME we need to be able to tell the user.
							Logger.error(this, "Caught "+e+" resizing the slashdotcache", e);
							System.err.println("Caught "+e+" resizing the slashdotcache");
							e.printStackTrace();
						}
					}
		}, true);

		maxSlashdotCacheSize = nodeConfig.getLong("slashdotCacheSize");

		if(maxSlashdotCacheSize < MIN_SLASHDOT_CACHE_SIZE) {
			throw new NodeInitException(NodeInitException.EXIT_INVALID_STORE_SIZE, "Slashdot cache size too small");
		}

		maxSlashdotCacheKeys = (int) Math.min(maxSlashdotCacheSize / sizePerKey, Integer.MAX_VALUE);

		chkSlashdotcache = new CHKStore();
		chkSlashdotcacheStore = new SlashdotStore<CHKBlock>(chkSlashdotcache, maxSlashdotCacheKeys, slashdotCacheLifetime, PURGE_INTERVAL, ticker, this.clientCore.tempBucketFactory);
		pubKeySlashdotcache = new PubkeyStore();
		pubKeySlashdotcacheStore = new SlashdotStore<DSAPublicKey>(pubKeySlashdotcache, maxSlashdotCacheKeys, slashdotCacheLifetime, PURGE_INTERVAL, ticker, this.clientCore.tempBucketFactory);
		getPubKey.setLocalSlashdotcache(pubKeySlashdotcache);
		sskSlashdotcache = new SSKStore(getPubKey);
		sskSlashdotcacheStore = new SlashdotStore<SSKBlock>(sskSlashdotcache, maxSlashdotCacheKeys, slashdotCacheLifetime, PURGE_INTERVAL, ticker, this.clientCore.tempBucketFactory);

		// MAXIMUM seclevel = no slashdot cache.

		securityLevels.addNetworkThreatLevelListener(new SecurityLevelListener<NETWORK_THREAT_LEVEL>() {

			@Override
			public void onChange(NETWORK_THREAT_LEVEL oldLevel, NETWORK_THREAT_LEVEL newLevel) {
				if(newLevel == NETWORK_THREAT_LEVEL.MAXIMUM)
					useSlashdotCache = false;
				else if(oldLevel == NETWORK_THREAT_LEVEL.MAXIMUM)
					useSlashdotCache = true;
			}

		});

		nodeConfig.register("skipWrapperWarning", false, sortOrder++, true, false, "Node.skipWrapperWarning", "Node.skipWrapperWarningLong", new BooleanCallback() {

			@Override
			public void set(Boolean value) throws InvalidConfigValueException, NodeNeedRestartException {
				skipWrapperWarning = value;
			}

			@Override
			public Boolean get() {
				return skipWrapperWarning;
			}
		});

		skipWrapperWarning = nodeConfig.getBoolean("skipWrapperWarning");

		nodeConfig.register("maxPacketSize", 1280, sortOrder++, true, true, "Node.maxPacketSize", "Node.maxPacketSizeLong", new IntCallback() {

			@Override
			public Integer get() {
				synchronized(Node.this) {
					return maxPacketSize;
				}
			}

			@Override
			public void set(Integer val) throws InvalidConfigValueException,
					NodeNeedRestartException {
				synchronized(Node.this) {
					if(val == maxPacketSize) return;
					if(val < UdpSocketHandler.MIN_MTU) throw new InvalidConfigValueException("Must be over 576");
					if(val > 1492) throw new InvalidConfigValueException("Larger than ethernet frame size unlikely to work!");
					maxPacketSize = val;
				}
				updateMTU();
			}

		}, true);

		maxPacketSize = nodeConfig.getInt("maxPacketSize");
		
		nodeConfig.register("enableRoutedPing", false, sortOrder++, true, false, "Node.enableRoutedPing", "Node.enableRoutedPingLong", new BooleanCallback() {

			@Override
			public Boolean get() {
				synchronized(Node.this) {
					return enableRoutedPing;
				}
			}

			@Override
			public void set(Boolean val) throws InvalidConfigValueException,
					NodeNeedRestartException {
				synchronized(Node.this) {
					enableRoutedPing = val;
				}
			}
			
		});
		enableRoutedPing = nodeConfig.getBoolean("enableRoutedPing");

		nodeConfig.register(
			"enableNodeDiagnostics",
			false,
			sortOrder++,
			true,
			false,
			"Node.enableDiagnostics",
			"Node.enableDiagnosticsLong",
			new BooleanCallback() {
				@Override
				public Boolean get() {
					synchronized (Node.this) {
						return enableNodeDiagnostics;
					}
				}

				@Override
				public void set(Boolean val) {
					synchronized (Node.this) {
						enableNodeDiagnostics = val;
						nodeDiagnostics.stop();

						if (enableNodeDiagnostics) {
							nodeDiagnostics.start();
						}
					}
				}
			}
		);
		enableNodeDiagnostics = nodeConfig.getBoolean("enableNodeDiagnostics");

		updateMTU();

		// peers-offers/*.fref files
		peersOffersFrefFilesConfiguration(nodeConfig, sortOrder++);
		if (!peersOffersDismissed && checkPeersOffersFrefFiles())
			PeersOffersUserAlert.createAlert(this);

		/* Take care that no configuration options are registered after this point; they will not persist
		 * between restarts.
		 */
		nodeConfig.finishedInitialization();
		if(shouldWriteConfig) config.store();
		writeNodeFile();

		// Initialize the plugin manager
		Logger.normal(this, "Initializing Plugin Manager");
		System.out.println("Initializing Plugin Manager");
		pluginManager = new PluginManager(this, lastVersion);

		shutdownHook.addEarlyJob(new NativeThread("Shutdown plugins", NativeThread.HIGH_PRIORITY, true) {
			@Override
			public void realRun() {
				pluginManager.stop(SECONDS.toMillis(30)); // FIXME make it configurable??
			}
		});

		// FIXME
		// Short timeouts and JVM timeouts with nothing more said than the above have been seen...
		// I don't know why... need a stack dump...
		// For now just give it an extra 2 minutes. If it doesn't start in that time,
		// it's likely (on reports so far) that a restart will fix it.
		// And we have to get a build out because ALL plugins are now failing to load,
		// including the absolutely essential (for most nodes) JSTUN and UPnP.
		WrapperManager.signalStarting((int) MINUTES.toMillis(2));

		FetchContext ctx = clientCore.makeClient((short)0, true, false).getFetchContext();

		ctx.allowSplitfiles = false;
		ctx.dontEnterImplicitArchives = true;
		ctx.maxArchiveRestarts = 0;
		ctx.maxMetadataSize = 256;
		ctx.maxNonSplitfileRetries = 10;
		ctx.maxOutputLength = 4096;
		ctx.maxRecursionLevel = 2;
		ctx.maxTempLength = 4096;

		this.arkFetcherContext = ctx;

		registerNodeToNodeMessageListener(N2N_MESSAGE_TYPE_FPROXY, fproxyN2NMListener);
		registerNodeToNodeMessageListener(Node.N2N_MESSAGE_TYPE_DIFFNODEREF, diffNoderefListener);

		// FIXME this is a hack
		// toadlet server should start after all initialized
		// see NodeClientCore line 437
		if (toadlets.isEnabled()) {
			toadlets.finishStart();
			toadlets.createFproxy();
			toadlets.removeStartupToadlet();
		}

		Logger.normal(this, "Node constructor completed");
		System.out.println("Node constructor completed");

		new BandwidthManager(this).start();

		nodeDiagnostics = new DefaultNodeDiagnostics(this.nodeStats, this.ticker);
	}

	private void peersOffersFrefFilesConfiguration(SubConfig nodeConfig, int configOptionSortOrder) {
	 	final Node node = this;
		nodeConfig.register("peersOffersDismissed", false, configOptionSortOrder, true, true,
				"Node.peersOffersDismissed", "Node.peersOffersDismissedLong", new BooleanCallback() {

					@Override
					public Boolean get() {
						return peersOffersDismissed;
					}

					@Override
					public void set(Boolean val) {
						if (val) {
							for (UserAlert alert : clientCore.alerts.getAlerts())
								if (alert instanceof PeersOffersUserAlert)
									clientCore.alerts.unregister(alert);
						} else
							PeersOffersUserAlert.createAlert(node);
						peersOffersDismissed = val;
					}
				});
		peersOffersDismissed = nodeConfig.getBoolean("peersOffersDismissed");
	}

	private boolean checkPeersOffersFrefFiles() {
		File[] files = runDir.file("peers-offers").listFiles();
		if (files != null && files.length > 0) {
			for (File file : files) {
				if (file.isFile()) {
					String filename = file.getName();
					if (filename.endsWith(".fref"))
						return true;
				}
			}
		}
		return false;
	}

    /** Delete files from old BDB-index datastore. */
	private void deleteOldBDBIndexStoreFiles() {
		File dbDir = storeDir.file("database-"+getDarknetPortNumber());
		FileUtil.removeAll(dbDir);
		File dir = storeDir.dir();
		File[] list = dir.listFiles();
		for(File f : list) {
			String name = f.getName();
			if(f.isFile() && 
					name.toLowerCase().matches("((chk)|(ssk)|(pubkey))-[0-9]*\\.((store)|(cache))(\\.((keys)|(lru)))?")) {
				System.out.println("Deleting old datastore file \""+f+"\"");
				try {
					FileUtil.secureDelete(f);
				} catch (IOException e) {
					System.err.println("Failed to delete old datastore file \""+f+"\": "+e);
					e.printStackTrace();
				}
			}
		}
	}

	private void fixCertsFiles() {
		// Hack to update certificates file to fix update.cmd
		// startssl.pem: Might be useful for old versions of update.sh too?
		File certs = new File(PluginDownLoaderOfficialHTTPS.certfileOld);
		fixCertsFile(certs);
		if(FileUtil.detectedOS.isWindows) {
			// updater\startssl.pem: Needed for Windows update.cmd.
			certs = new File("updater", PluginDownLoaderOfficialHTTPS.certfileOld);
			fixCertsFile(certs);
		}
	}

	private void fixCertsFile(File certs) {
		long oldLength = certs.exists() ? certs.length() : -1;
		try {
			File tmpFile = File.createTempFile(PluginDownLoaderOfficialHTTPS.certfileOld, ".tmp", new File("."));
			PluginDownLoaderOfficialHTTPS.writeCertsTo(tmpFile);
			if(FileUtil.renameTo(tmpFile, certs)) {
				long newLength = certs.length();
				if(newLength != oldLength)
					System.err.println("Updated "+certs+" so that update scripts will work");
			} else {
				if(certs.length() != tmpFile.length()) {
					System.err.println("Cannot update "+certs+" : last-resort update scripts (in particular update.cmd on Windows) may not work");
					File manual = new File(PluginDownLoaderOfficialHTTPS.certfileOld+".new");
					manual.delete();
					if(tmpFile.renameTo(manual))
						System.err.println("Please delete "+certs+" and rename "+manual+" over it");
					else
						tmpFile.delete();
				}
			}
		} catch (IOException e) {
		}
	}

	/**
	** Sets up a program directory using the config value defined by the given
	** parameters.
	*/
	public ProgramDirectory setupProgramDir(SubConfig installConfig,
	  String cfgKey, String defaultValue, String shortdesc, String longdesc, String moveErrMsg,
	  SubConfig oldConfig) throws NodeInitException {
		ProgramDirectory dir = new ProgramDirectory(moveErrMsg);
		int sortOrder = ProgramDirectory.nextOrder();
		// forceWrite=true because currently it can't be changed on the fly, also for packages
		installConfig.register(cfgKey, defaultValue, sortOrder, true, true, shortdesc, longdesc, dir.getStringCallback());
		String dirName = installConfig.getString(cfgKey);
		try {
			dir.move(dirName);
		} catch (IOException e) {
			throw new NodeInitException(NodeInitException.EXIT_BAD_DIR, "could not set up directory: " + longdesc);
		}
		return dir;
	}

	protected ProgramDirectory setupProgramDir(SubConfig installConfig,
	  String cfgKey, String defaultValue, String shortdesc, String longdesc,
	  SubConfig oldConfig) throws NodeInitException {
		return setupProgramDir(installConfig, cfgKey, defaultValue, shortdesc, longdesc, null, oldConfig);
	}

	public void lateSetupDatabase(DatabaseKey databaseKey) throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
	    if(clientCore.loadedDatabase()) return;
		System.out.println("Starting late database initialisation");

		try {
		    if(!clientCore.lateInitDatabase(databaseKey))
		        failLateInitDatabase();
		} catch (NodeInitException e) {
		    failLateInitDatabase();
		}
	}

	private void failLateInitDatabase() {
		System.err.println("Failed late initialisation of database, closing...");
	}

	public void killMasterKeysFile() throws IOException {
		MasterKeys.killMasterKeys(masterKeysFile);
	}


	private void setClientCacheAwaitingPassword() {
		createPasswordUserAlert();
		synchronized(this) {
			clientCacheAwaitingPassword = true;
		}
	}

	/** Called when the client layer needs the decryption password. */
    void setDatabaseAwaitingPassword() {
        synchronized(this) {
            databaseAwaitingPassword = true;
        }
    }

	private final UserAlert masterPasswordUserAlert = new UserAlert() {

		final long creationTime = System.currentTimeMillis();

		@Override
		public String anchor() {
			return "password";
		}

		@Override
		public String dismissButtonText() {
			return null;
		}

		@Override
		public long getUpdatedTime() {
			return creationTime;
		}

		@Override
		public FCPMessage getFCPMessage() {
			return new FeedMessage(getTitle(), getShortText(), getText(), getPriorityClass(), getUpdatedTime());
		}

		@Override
		public HTMLNode getHTMLText() {
			HTMLNode content = new HTMLNode("div");
			SecurityLevelsToadlet.generatePasswordFormPage(false, clientCore.getToadletContainer(), content, false, false, false, null, null);
			return content;
		}

		@Override
		public short getPriorityClass() {
			return UserAlert.ERROR;
		}

		@Override
		public String getShortText() {
			return NodeL10n.getBase().getString("SecurityLevels.enterPassword");
		}

		@Override
		public String getText() {
			return NodeL10n.getBase().getString("SecurityLevels.enterPassword");
		}

		@Override
		public String getTitle() {
			return NodeL10n.getBase().getString("SecurityLevels.enterPassword");
		}

		@Override
		public boolean isEventNotification() {
			return false;
		}

		@Override
		public boolean isValid() {
			synchronized(Node.this) {
				return clientCacheAwaitingPassword || databaseAwaitingPassword;
			}
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
			return false;
		}

	};
	private void createPasswordUserAlert() {
		this.clientCore.alerts.register(masterPasswordUserAlert);
	}

	private void initRAMClientCacheFS() {
		chkClientcache = new CHKStore();
		new RAMFreenetStore<CHKBlock>(chkClientcache, (int) Math.min(Integer.MAX_VALUE, maxClientCacheKeys));
		pubKeyClientcache = new PubkeyStore();
		new RAMFreenetStore<DSAPublicKey>(pubKeyClientcache, (int) Math.min(Integer.MAX_VALUE, maxClientCacheKeys));
		sskClientcache = new SSKStore(getPubKey);
		new RAMFreenetStore<SSKBlock>(sskClientcache, (int) Math.min(Integer.MAX_VALUE, maxClientCacheKeys));
	}

	private void initNoClientCacheFS() {
		chkClientcache = new CHKStore();
		new NullFreenetStore<CHKBlock>(chkClientcache);
		pubKeyClientcache = new PubkeyStore();
		new NullFreenetStore<DSAPublicKey>(pubKeyClientcache);
		sskClientcache = new SSKStore(getPubKey);
		new NullFreenetStore<SSKBlock>(sskClientcache);
	}

	private String getStoreSuffix() {
		return "-" + getDarknetPortNumber();
	}

	private void finishInitSaltHashFS(final String suffix, NodeClientCore clientCore) {
		if(clientCore.alerts == null) throw new NullPointerException();
		chkDatastore.getStore().setUserAlertManager(clientCore.alerts);
		chkDatacache.getStore().setUserAlertManager(clientCore.alerts);
		pubKeyDatastore.getStore().setUserAlertManager(clientCore.alerts);
		pubKeyDatacache.getStore().setUserAlertManager(clientCore.alerts);
		sskDatastore.getStore().setUserAlertManager(clientCore.alerts);
		sskDatacache.getStore().setUserAlertManager(clientCore.alerts);
	}

	private void initRAMFS() {
		chkDatastore = new CHKStore();
		new RAMFreenetStore<CHKBlock>(chkDatastore, (int) Math.min(Integer.MAX_VALUE, maxStoreKeys));
		chkDatacache = new CHKStore();
		new RAMFreenetStore<CHKBlock>(chkDatacache, (int) Math.min(Integer.MAX_VALUE, maxCacheKeys));
		pubKeyDatastore = new PubkeyStore();
		new RAMFreenetStore<DSAPublicKey>(pubKeyDatastore, (int) Math.min(Integer.MAX_VALUE, maxStoreKeys));
		pubKeyDatacache = new PubkeyStore();
		getPubKey.setDataStore(pubKeyDatastore, pubKeyDatacache);
		new RAMFreenetStore<DSAPublicKey>(pubKeyDatacache, (int) Math.min(Integer.MAX_VALUE, maxCacheKeys));
		sskDatastore = new SSKStore(getPubKey);
		new RAMFreenetStore<SSKBlock>(sskDatastore, (int) Math.min(Integer.MAX_VALUE, maxStoreKeys));
		sskDatacache = new SSKStore(getPubKey);
		new RAMFreenetStore<SSKBlock>(sskDatacache, (int) Math.min(Integer.MAX_VALUE, maxCacheKeys));
	}

	private long cachingFreenetStoreMaxSize;
	private long cachingFreenetStorePeriod;
	private CachingFreenetStoreTracker cachingFreenetStoreTracker;

	private void initSaltHashFS(final String suffix, boolean dontResizeOnStart, byte[] masterKey) throws NodeInitException {
		try {
			final CHKStore chkDatastore = new CHKStore();
			final FreenetStore<CHKBlock> chkDataFS = makeStore("CHK", true, chkDatastore, dontResizeOnStart, masterKey);
			final CHKStore chkDatacache = new CHKStore();
			final FreenetStore<CHKBlock> chkCacheFS = makeStore("CHK", false, chkDatacache, dontResizeOnStart, masterKey);
			((SaltedHashFreenetStore<CHKBlock>) chkCacheFS.getUnderlyingStore()).setAltStore(((SaltedHashFreenetStore<CHKBlock>) chkDataFS.getUnderlyingStore()));
			final PubkeyStore pubKeyDatastore = new PubkeyStore();
			final FreenetStore<DSAPublicKey> pubkeyDataFS = makeStore("PUBKEY", true, pubKeyDatastore, dontResizeOnStart, masterKey);
			final PubkeyStore pubKeyDatacache = new PubkeyStore();
			final FreenetStore<DSAPublicKey> pubkeyCacheFS = makeStore("PUBKEY", false, pubKeyDatacache, dontResizeOnStart, masterKey);
			((SaltedHashFreenetStore<DSAPublicKey>) pubkeyCacheFS.getUnderlyingStore()).setAltStore(((SaltedHashFreenetStore<DSAPublicKey>) pubkeyDataFS.getUnderlyingStore()));
			final SSKStore sskDatastore = new SSKStore(getPubKey);
			final FreenetStore<SSKBlock> sskDataFS = makeStore("SSK", true, sskDatastore, dontResizeOnStart, masterKey);
			final SSKStore sskDatacache = new SSKStore(getPubKey);
			final FreenetStore<SSKBlock> sskCacheFS = makeStore("SSK", false, sskDatacache, dontResizeOnStart, masterKey);
			((SaltedHashFreenetStore<SSKBlock>) sskCacheFS.getUnderlyingStore()).setAltStore(((SaltedHashFreenetStore<SSKBlock>) sskDataFS.getUnderlyingStore()));
			
			boolean delay =
				chkDataFS.start(ticker, false) |
				chkCacheFS.start(ticker, false) |
				pubkeyDataFS.start(ticker, false) |
				pubkeyCacheFS.start(ticker, false) |
				sskDataFS.start(ticker, false) |
				sskCacheFS.start(ticker, false);

			if(delay) {

				System.err.println("Delayed init of datastore");

				initRAMFS();

				final Runnable migrate = new MigrateOldStoreData(false);

				this.getTicker().queueTimedJob(new Runnable() {

					@Override
					public void run() {
						System.err.println("Starting delayed init of datastore");
						try {
							chkDataFS.start(ticker, true);
							chkCacheFS.start(ticker, true);
							pubkeyDataFS.start(ticker, true);
							pubkeyCacheFS.start(ticker, true);
							sskDataFS.start(ticker, true);
							sskCacheFS.start(ticker, true);
						} catch (IOException e) {
							Logger.error(this, "Failed to start datastore: "+e, e);
							System.err.println("Failed to start datastore: "+e);
							e.printStackTrace();
							return;
						}

						Node.this.chkDatastore = chkDatastore;
						Node.this.chkDatacache = chkDatacache;
						Node.this.pubKeyDatastore = pubKeyDatastore;
						Node.this.pubKeyDatacache = pubKeyDatacache;
						getPubKey.setDataStore(pubKeyDatastore, pubKeyDatacache);
						Node.this.sskDatastore = sskDatastore;
						Node.this.sskDatacache = sskDatacache;

						finishInitSaltHashFS(suffix, clientCore);

						System.err.println("Finishing delayed init of datastore");
						migrate.run();
					}

				}, "Start store", 0, true, false); // Use Ticker to guarantee that this runs *after* constructors have completed.

			} else {

				Node.this.chkDatastore = chkDatastore;
				Node.this.chkDatacache = chkDatacache;
				Node.this.pubKeyDatastore = pubKeyDatastore;
				Node.this.pubKeyDatacache = pubKeyDatacache;
				getPubKey.setDataStore(pubKeyDatastore, pubKeyDatacache);
				Node.this.sskDatastore = sskDatastore;
				Node.this.sskDatacache = sskDatacache;

				this.getTicker().queueTimedJob(new Runnable() {

					@Override
					public void run() {
						Node.this.chkDatastore = chkDatastore;
						Node.this.chkDatacache = chkDatacache;
						Node.this.pubKeyDatastore = pubKeyDatastore;
						Node.this.pubKeyDatacache = pubKeyDatacache;
						getPubKey.setDataStore(pubKeyDatastore, pubKeyDatacache);
						Node.this.sskDatastore = sskDatastore;
						Node.this.sskDatacache = sskDatacache;

						finishInitSaltHashFS(suffix, clientCore);
					}

				}, "Start store", 0, true, false);
			}

		} catch (IOException e) {
			System.err.println("Could not open store: " + e);
			e.printStackTrace();
			throw new NodeInitException(NodeInitException.EXIT_STORE_OTHER, e.getMessage());
		}
    }

	private void initSaltHashClientCacheFS(final String suffix, boolean dontResizeOnStart, byte[] clientCacheMasterKey) throws NodeInitException {

		try {
			final CHKStore chkClientcache = new CHKStore();
			final FreenetStore<CHKBlock> chkDataFS = makeClientcache("CHK", true, chkClientcache, dontResizeOnStart, clientCacheMasterKey);
			final PubkeyStore pubKeyClientcache = new PubkeyStore();
			final FreenetStore<DSAPublicKey> pubkeyDataFS = makeClientcache("PUBKEY", true, pubKeyClientcache, dontResizeOnStart, clientCacheMasterKey);
			final SSKStore sskClientcache = new SSKStore(getPubKey);
			final FreenetStore<SSKBlock> sskDataFS = makeClientcache("SSK", true, sskClientcache, dontResizeOnStart, clientCacheMasterKey);

			boolean delay =
				chkDataFS.start(ticker, false) |
				pubkeyDataFS.start(ticker, false) |
				sskDataFS.start(ticker, false);

			if(delay) {

				System.err.println("Delayed init of client-cache");

				initRAMClientCacheFS();

				final Runnable migrate = new MigrateOldStoreData(true);

				getTicker().queueTimedJob(new Runnable() {

					@Override
					public void run() {
						System.err.println("Starting delayed init of client-cache");
						try {
							chkDataFS.start(ticker, true);
							pubkeyDataFS.start(ticker, true);
							sskDataFS.start(ticker, true);
						} catch (IOException e) {
							Logger.error(this, "Failed to start client-cache: "+e, e);
							System.err.println("Failed to start client-cache: "+e);
							e.printStackTrace();
							return;
						}
						Node.this.chkClientcache = chkClientcache;
						Node.this.pubKeyClientcache = pubKeyClientcache;
						getPubKey.setLocalDataStore(pubKeyClientcache);
						Node.this.sskClientcache = sskClientcache;

						System.err.println("Finishing delayed init of client-cache");
						migrate.run();
					}
				}, "Migrate store", 0, true, false);
			} else {
				Node.this.chkClientcache = chkClientcache;
				Node.this.pubKeyClientcache = pubKeyClientcache;
				getPubKey.setLocalDataStore(pubKeyClientcache);
				Node.this.sskClientcache = sskClientcache;
			}

		} catch (IOException e) {
			System.err.println("Could not open store: " + e);
			e.printStackTrace();
			throw new NodeInitException(NodeInitException.EXIT_STORE_OTHER, e.getMessage());
		}
    }

	private <T extends StorableBlock> FreenetStore<T> makeClientcache(String type, boolean isStore, StoreCallback<T> cb, boolean dontResizeOnStart, byte[] clientCacheMasterKey) throws IOException {
		FreenetStore<T> store = makeStore(type, "clientcache", maxClientCacheKeys, cb, dontResizeOnStart, clientCacheMasterKey);
		return store;
	}

	private <T extends StorableBlock> FreenetStore<T> makeStore(String type, boolean isStore, StoreCallback<T> cb, boolean dontResizeOnStart, byte[] clientCacheMasterKey) throws IOException {
		String store = isStore ? "store" : "cache";
		long maxKeys = isStore ? maxStoreKeys : maxCacheKeys;
		return makeStore(type, store, maxKeys, cb, dontResizeOnStart, clientCacheMasterKey);
	}

	private <T extends StorableBlock> FreenetStore<T> makeStore(String type, String store, long maxKeys, StoreCallback<T> cb, boolean lateStart, byte[] clientCacheMasterKey) throws IOException {
		Logger.normal(this, "Initializing "+type+" Data"+store);
		System.out.println("Initializing "+type+" Data"+store+" (" + maxStoreKeys + " keys)");

		SaltedHashFreenetStore<T> fs = SaltedHashFreenetStore.<T>construct(getStoreDir(), type+"-"+store, cb,
		        random, maxKeys, storeUseSlotFilters, shutdownHook, storePreallocate, storeSaltHashResizeOnStart && !lateStart, lateStart ? ticker : null, clientCacheMasterKey);
		cb.setStore(fs);
		if(cachingFreenetStoreMaxSize > 0)
			return new CachingFreenetStore<T>(cb, fs, cachingFreenetStoreTracker);
		else
			return fs;
	}

	public void start(boolean noSwaps) throws NodeInitException {
		
		// IMPORTANT: Read the peers only after we have finished initializing Node.
		// Peer constructors are complex and can call methods on Node.
		peers.tryReadPeers(nodeDir.file("peers-"+getDarknetPortNumber()).getPath(), darknetCrypto, null, false, false);
		peers.updatePMUserAlert();
		
		dispatcher.start(nodeStats); // must be before usm
		dnsr.start();
		peers.start(); // must be before usm
		nodeStats.start();
		uptime.start();
		failureTable.start();

		darknetCrypto.start();
		if(opennet != null)
			opennet.start();
		ps.start(nodeStats);
		ticker.start();
		scheduleVersionTransition();
		usm.start(ticker);

		if(isUsingWrapper()) {
			Logger.normal(this, "Using wrapper correctly: "+nodeStarter);
			System.out.println("Using wrapper correctly: "+nodeStarter);
		} else {
			Logger.error(this, "NOT using wrapper (at least not correctly).  Your freenet-ext.jar <http://downloads.freenetproject.org/alpha/freenet-ext.jar> and/or wrapper.conf <https://emu.freenetproject.org/svn/trunk/apps/installer/installclasspath/config/wrapper.conf> need to be updated.");
			System.out.println("NOT using wrapper (at least not correctly).  Your freenet-ext.jar <http://downloads.freenetproject.org/alpha/freenet-ext.jar> and/or wrapper.conf <https://emu.freenetproject.org/svn/trunk/apps/installer/installclasspath/config/wrapper.conf> need to be updated.");
		}
		Logger.normal(this, "Freenet 0.7.5 Build #"+Version.buildNumber()+" r"+Version.cvsRevision());
		System.out.println("Freenet 0.7.5 Build #"+Version.buildNumber()+" r"+Version.cvsRevision());
		Logger.normal(this, "FNP port is on "+darknetCrypto.getBindTo()+ ':' +getDarknetPortNumber());
		System.out.println("FNP port is on "+darknetCrypto.getBindTo()+ ':' +getDarknetPortNumber());
		// Start services

//		SubConfig pluginManagerConfig = new SubConfig("pluginmanager3", config);
//		pluginManager3 = new freenet.plugin_new.PluginManager(pluginManagerConfig);

		ipDetector.start();

		// Start sending swaps
		lm.start();

		// Node Updater
		try{
			Logger.normal(this, "Starting the node updater");
			nodeUpdater.start();
		}catch (Exception e) {
			e.printStackTrace();
			throw new NodeInitException(NodeInitException.EXIT_COULD_NOT_START_UPDATER, "Could not start Updater: "+e);
		}

		/* TODO: Make sure that this is called BEFORE any instances of HTTPFilter are created.
		 * HTTPFilter uses checkForGCJCharConversionBug() which returns the value of the static
		 * variable jvmHasGCJCharConversionBug - and this is initialized in the following function.
		 * If this is not possible then create a separate function to check for the GCJ bug and
		 * call this function earlier.
		 */
		checkForEvilJVMBugs();

		if(!NativeThread.HAS_ENOUGH_NICE_LEVELS)
			clientCore.alerts.register(new NotEnoughNiceLevelsUserAlert());

		this.clientCore.start(config);

		tracker.startDeadUIDChecker();

		// After everything has been created, write the config file back to disk.
		if(config instanceof FreenetFilePersistentConfig) {
			FreenetFilePersistentConfig cfg = (FreenetFilePersistentConfig) config;
			cfg.finishedInit(this.ticker);
			cfg.setHasNodeStarted();
		}
		config.store();

		// Process any data in the extra peer data directory
		peers.readExtraPeerData();

		if (enableNodeDiagnostics) {
			nodeDiagnostics.start();
		}

		Logger.normal(this, "Started node");

		hasStarted = true;
	}

	private void scheduleVersionTransition() {
		long now = System.currentTimeMillis();
		long transition = Version.transitionTime();
		if(now < transition)
			ticker.queueTimedJob(new Runnable() {

				@Override
				public void run() {
					freenet.support.Logger.OSThread.logPID(this);
					for(PeerNode pn: peers.myPeers()) {
						pn.updateVersionRoutablity();
					}
				}
			}, transition - now);
	}


	private static boolean jvmHasGCJCharConversionBug=false;

	private void checkForEvilJVMBugs() {
		// Now check whether we are likely to get the EvilJVMBug.
		// If we are running a Sun/Oracle or Blackdown JVM, on Linux, and LD_ASSUME_KERNEL is not set, then we are.

		String jvmVendor = System.getProperty("java.vm.vendor");
		String jvmSpecVendor = System.getProperty("java.specification.vendor","");
		String javaVersion = System.getProperty("java.version");
		String jvmName = System.getProperty("java.vm.name");
		String osName = System.getProperty("os.name");
		String osVersion = System.getProperty("os.version");

		boolean isOpenJDK = false;
		//boolean isOracle = false;

		if(logMINOR) Logger.minor(this, "JVM vendor: "+jvmVendor+", JVM name: "+jvmName+", JVM version: "+javaVersion+", OS name: "+osName+", OS version: "+osVersion);

		if(jvmName.startsWith("OpenJDK ")) {
			isOpenJDK = true;
		}
		
		//Add some checks for "Oracle" to futureproof against them renaming from "Sun".
		//Should have no effect because if a user has downloaded a new enough file for Oracle to have changed the name these bugs shouldn't apply.
		//Still, one never knows and this code might be extended to cover future bugs.
		if((!isOpenJDK) && (jvmVendor.startsWith("Sun ") || jvmVendor.startsWith("Oracle ")) || (jvmVendor.startsWith("The FreeBSD Foundation") && (jvmSpecVendor.startsWith("Sun ") || jvmSpecVendor.startsWith("Oracle "))) || (jvmVendor.startsWith("Apple "))) {
			//isOracle = true;
			// Sun/Oracle bugs

			// Spurious OOMs
			// http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4855795
			// http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=2138757
			// http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=2138759
			// Fixed in 1.5.0_10 and 1.4.2_13

			boolean is150 = javaVersion.startsWith("1.5.0_");
			boolean is160 = javaVersion.startsWith("1.6.0_");

			if(is150 || is160) {
				String[] split = javaVersion.split("_");
				String secondPart = split[1];
				if(secondPart.indexOf("-") != -1) {
					split = secondPart.split("-");
					secondPart = split[0];
				}
				int subver = Integer.parseInt(secondPart);

				Logger.minor(this, "JVM version: "+javaVersion+" subver: "+subver+" from "+secondPart);

			}

		} else if (jvmVendor.startsWith("Apple ") || jvmVendor.startsWith("\"Apple ")) {
			//Note that Sun/Oracle does not produce VMs for the Macintosh operating system, dont ask the user to find one...
		} else if(!isOpenJDK) {
			if(jvmVendor.startsWith("Free Software Foundation")) {
				// GCJ/GIJ.
				try {
					javaVersion = System.getProperty("java.version").split(" ")[0].replaceAll("[.]","");
					int jvmVersionInt = Integer.parseInt(javaVersion);

					if(jvmVersionInt <= 422 && jvmVersionInt >= 100) // make sure that no bogus values cause true
						jvmHasGCJCharConversionBug=true;
				}

				catch(Throwable t) {
					Logger.error(this, "GCJ version check is broken!", t);
				}
				clientCore.alerts.register(new SimpleUserAlert(true, l10n("usingGCJTitle"), l10n("usingGCJ"), l10n("usingGCJTitle"), UserAlert.WARNING));
			}
		}

		if(!isUsingWrapper() && !skipWrapperWarning) {
			clientCore.alerts.register(new SimpleUserAlert(true, l10n("notUsingWrapperTitle"), l10n("notUsingWrapper"), l10n("notUsingWrapperShort"), UserAlert.WARNING));
		}
		
		// Unfortunately debian's version of OpenJDK appears to have segfaulting issues.
		// Which presumably are exploitable.
		// So we can't recommend people switch just yet. :(
		
//		if(isOracle && Rijndael.AesCtrProvider == null) {
//			if(!(FileUtil.detectedOS == FileUtil.OperatingSystem.Windows || FileUtil.detectedOS == FileUtil.OperatingSystem.MacOS))
//				clientCore.alerts.register(new SimpleUserAlert(true, l10n("usingOracleTitle"), l10n("usingOracle"), l10n("usingOracleTitle"), UserAlert.WARNING));
//		}
	}

	public static boolean checkForGCJCharConversionBug() {
		return jvmHasGCJCharConversionBug; // should be initialized on early startup
	}

	private String l10n(String key) {
		return NodeL10n.getBase().getString("Node."+key);
	}

	private String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("Node."+key, pattern, value);
	}

	private String l10n(String key, String[] pattern, String[] value) {
		return NodeL10n.getBase().getString("Node."+key, pattern, value);
	}

	/**
	 * Export volatile data about the node as a SimpleFieldSet
	 */
	public SimpleFieldSet exportVolatileFieldSet() {
		return nodeStats.exportVolatileFieldSet();
	}

	/**
	 * Do a routed ping of another node on the network by its location.
	 * @param loc2 The location of the other node to ping. It must match
	 * exactly.
	 * @param pubKeyHash The hash of the pubkey of the target node. We match
	 * by location; this is just a shortcut if we get close.
	 * @return The number of hops it took to find the node, if it was found.
	 * Otherwise -1.
	 */
	public int routedPing(double loc2, byte[] pubKeyHash) {
		long uid = random.nextLong();
		int initialX = random.nextInt();
		Message m = DMT.createFNPRoutedPing(uid, loc2, maxHTL, initialX, pubKeyHash);
		Logger.normal(this, "Message: "+m);

		dispatcher.handleRouted(m, null);
		// FIXME: might be rejected
		MessageFilter mf1 = MessageFilter.create().setField(DMT.UID, uid).setType(DMT.FNPRoutedPong).setTimeout(5000);
		try {
			//MessageFilter mf2 = MessageFilter.create().setField(DMT.UID, uid).setType(DMT.FNPRoutedRejected).setTimeout(5000);
			// Ignore Rejected - let it be retried on other peers
			m = usm.waitFor(mf1/*.or(mf2)*/, null);
		} catch (DisconnectedException e) {
			Logger.normal(this, "Disconnected in waiting for pong");
			return -1;
		}
		if(m == null) return -1;
		if(m.getSpec() == DMT.FNPRoutedRejected) return -1;
		return m.getInt(DMT.COUNTER) - initialX;
	}

	/**
	 * Look for a block in the datastore, as part of a request.
	 * @param key The key to fetch.
	 * @param uid The UID of the request (for logging only).
	 * @param promoteCache Whether to promote the key if found.
	 * @param canReadClientCache If the request is local, we can read the client cache.
	 * @param canWriteClientCache If the request is local, and the client hasn't turned off
	 * writing to the client cache, we can write to the client cache.
	 * @param canWriteDatastore If the request HTL is too high, including if it is local, we
	 * cannot write to the datastore.
	 * @return A KeyBlock for the key requested or null.
	 */
	private KeyBlock makeRequestLocal(Key key, long uid, boolean canReadClientCache, boolean canWriteClientCache, boolean canWriteDatastore, boolean offersOnly) {
		KeyBlock kb = null;

		if (key instanceof NodeCHK) {
			kb = fetch(key, false, canReadClientCache, canWriteClientCache, canWriteDatastore, null);
		} else if (key instanceof NodeSSK) {
			NodeSSK sskKey = (NodeSSK) key;
			DSAPublicKey pubKey = sskKey.getPubKey();
			if (pubKey == null) {
				pubKey = getPubKey.getKey(sskKey.getPubKeyHash(), canReadClientCache, offersOnly, null);
				if (logMINOR)
					Logger.minor(this, "Fetched pubkey: " + pubKey);
				try {
					sskKey.setPubKey(pubKey);
				} catch (SSKVerifyException e) {
					Logger.error(this, "Error setting pubkey: " + e, e);
				}
			}
			if (pubKey != null) {
				if (logMINOR)
					Logger.minor(this, "Got pubkey: " + pubKey);
				kb = fetch(sskKey, canReadClientCache, canWriteClientCache, canWriteDatastore, false, null);
			} else {
				if (logMINOR)
					Logger.minor(this, "Not found because no pubkey: " + uid);
			}
		} else
			throw new IllegalStateException("Unknown key type: " + key.getClass());

		if (kb != null) {
			// Probably somebody waiting for it. Trip it.
			if (clientCore != null && clientCore.requestStarters != null) {
				if (kb instanceof CHKBlock) {
					clientCore.requestStarters.chkFetchSchedulerBulk.tripPendingKey(kb);
					clientCore.requestStarters.chkFetchSchedulerRT.tripPendingKey(kb);
				} else {
					clientCore.requestStarters.sskFetchSchedulerBulk.tripPendingKey(kb);
					clientCore.requestStarters.sskFetchSchedulerRT.tripPendingKey(kb);
				}
			}
			failureTable.onFound(kb);
			return kb;
		}

		return null;
	}

	/**
	 * Check the datastore, then if the key is not in the store,
	 * check whether another node is requesting the same key at
	 * the same HTL, and if all else fails, create a new
	 * RequestSender for the key/htl.
	 * @param closestLocation The closest location to the key so far.
	 * @param localOnly If true, only check the datastore.
	 * @return A KeyBlock if the data is in the store, otherwise
	 * a RequestSender, unless the HTL is 0, in which case NULL.
	 * RequestSender.
	 */
	public Object makeRequestSender(Key key, short htl, long uid, RequestTag tag, PeerNode source, boolean localOnly, boolean ignoreStore, boolean offersOnly, boolean canReadClientCache, boolean canWriteClientCache, boolean realTimeFlag) {
		boolean canWriteDatastore = canWriteDatastoreRequest(htl);
		if(logMINOR) Logger.minor(this, "makeRequestSender("+key+ ',' +htl+ ',' +uid+ ',' +source+") on "+getDarknetPortNumber());
		// In store?
		if(!ignoreStore) {
			KeyBlock kb = makeRequestLocal(key, uid, canReadClientCache, canWriteClientCache, canWriteDatastore, offersOnly);
			if (kb != null)
				return kb;
		}
		if(localOnly) return null;
		if(logMINOR) Logger.minor(this, "Not in store locally");

		// Transfer coalescing - match key only as HTL irrelevant
		RequestSender sender = key instanceof NodeCHK ? 
			tracker.getTransferringRequestSenderByKey((NodeCHK)key, realTimeFlag) : null;
		if(sender != null) {
			if(logMINOR) Logger.minor(this, "Data already being transferred: "+sender);
			sender.setTransferCoalesced();
			tag.setSender(sender, true);
			return sender;
		}

		// HTL == 0 => Don't search further
		if(htl == 0) {
			if(logMINOR) Logger.minor(this, "No HTL");
			return null;
		}

		sender = new RequestSender(key, null, htl, uid, tag, this, source, offersOnly, canWriteClientCache, canWriteDatastore, realTimeFlag);
		tag.setSender(sender, false);
		sender.start();
		if(logMINOR) Logger.minor(this, "Created new sender: "+sender);
		return sender;
	}

	/** Can we write to the datastore for a given request?
	 * We do not write to the datastore until 2 hops below maximum. This is an average of 4
	 * hops from the originator. Thus, data returned from local requests is never cached,
	 * finally solving The Register's attack, Bloom filter sharing doesn't give away your local
	 * requests and inserts, and *anything starting at high HTL* is not cached, including stuff
	 * from other nodes which hasn't been decremented far enough yet, so it's not ONLY local
	 * requests that don't get cached. */
	boolean canWriteDatastoreRequest(short htl) {
		return htl <= (maxHTL - 2);
	}

	/** Can we write to the datastore for a given insert?
	 * We do not write to the datastore until 3 hops below maximum. This is an average of 5
	 * hops from the originator. Thus, data sent by local inserts is never cached,
	 * finally solving The Register's attack, Bloom filter sharing doesn't give away your local
	 * requests and inserts, and *anything starting at high HTL* is not cached, including stuff
	 * from other nodes which hasn't been decremented far enough yet, so it's not ONLY local
	 * inserts that don't get cached. */
	boolean canWriteDatastoreInsert(short htl) {
		return htl <= (maxHTL - 3);
	}

	/**
	 * Fetch a block from the datastore.
	 * @param key
	 * @param canReadClientCache
	 * @param canWriteClientCache
	 * @param canWriteDatastore
	 * @param forULPR
	 * @param mustBeMarkedAsPostCachingChanges If true, the key must have the
	 * ENTRY_NEW_BLOCK flag (if saltedhash), indicating that it a) has been added
	 * since the caching changes in 1224 (since we didn't delete the stores), and b)
	 * that it wasn't added due to low network security caching everything, unless we
	 * are currently in low network security mode. Only applies to main store.
	 */
	public KeyBlock fetch(Key key, boolean canReadClientCache, boolean canWriteClientCache, boolean canWriteDatastore, boolean forULPR, BlockMetadata meta) {
		if(key instanceof NodeSSK)
			return fetch((NodeSSK)key, false, canReadClientCache, canWriteClientCache, canWriteDatastore, forULPR, meta);
		else if(key instanceof NodeCHK)
			return fetch((NodeCHK)key, false, canReadClientCache, canWriteClientCache, canWriteDatastore, forULPR, meta);
		else throw new IllegalArgumentException();
	}

	public SSKBlock fetch(NodeSSK key, boolean dontPromote, boolean canReadClientCache, boolean canWriteClientCache, boolean canWriteDatastore, boolean forULPR, BlockMetadata meta) {
		double loc=key.toNormalizedDouble();
		double dist=Location.distance(lm.getLocation(), loc);
		if(canReadClientCache) {
			try {
				SSKBlock block = sskClientcache.fetch(key, dontPromote || !canWriteClientCache, canReadClientCache, forULPR, false, meta);
				if(block != null) {
					nodeStats.avgClientCacheSSKSuccess.report(loc);
					if (dist > nodeStats.furthestClientCacheSSKSuccess)
					nodeStats.furthestClientCacheSSKSuccess=dist;
					if(logDEBUG) Logger.debug(this, "Found key "+key+" in client-cache");
					return block;
				}
			} catch (IOException e) {
				Logger.error(this, "Could not read from client cache: "+e, e);
			}
		}
		if(forULPR || useSlashdotCache || canReadClientCache) {
			try {
				SSKBlock block = sskSlashdotcache.fetch(key, dontPromote, canReadClientCache, forULPR, false, meta);
				if(block != null) {
					nodeStats.avgSlashdotCacheSSKSuccess.report(loc);
					if (dist > nodeStats.furthestSlashdotCacheSSKSuccess)
					nodeStats.furthestSlashdotCacheSSKSuccess=dist;
					if(logDEBUG) Logger.debug(this, "Found key "+key+" in slashdot-cache");
					return block;
				}
			} catch (IOException e) {
				Logger.error(this, "Could not read from slashdot/ULPR cache: "+e, e);
			}
		}
		boolean ignoreOldBlocks = !writeLocalToDatastore;
		if(canReadClientCache) ignoreOldBlocks = false;
		if(logMINOR) dumpStoreHits();
		try {

			nodeStats.avgRequestLocation.report(loc);
			SSKBlock block = sskDatastore.fetch(key, dontPromote || !canWriteDatastore, canReadClientCache, forULPR, ignoreOldBlocks, meta);
			if(block == null) {
				SSKStore store = oldSSK;
				if(store != null)
					block = store.fetch(key, dontPromote || !canWriteDatastore, canReadClientCache, forULPR, ignoreOldBlocks, meta);
			}
			if(block != null) {
				nodeStats.avgStoreSSKSuccess.report(loc);
				if (dist > nodeStats.furthestStoreSSKSuccess)
					nodeStats.furthestStoreSSKSuccess=dist;
				if(logDEBUG) Logger.debug(this, "Found key "+key+" in store");
				return block;
			}
			block=sskDatacache.fetch(key, dontPromote || !canWriteDatastore, canReadClientCache, forULPR, ignoreOldBlocks, meta);
			if(block == null) {
				SSKStore store = oldSSKCache;
				if(store != null)
					block = store.fetch(key, dontPromote || !canWriteDatastore, canReadClientCache, forULPR, ignoreOldBlocks, meta);
			}
			if (block != null) {
				nodeStats.avgCacheSSKSuccess.report(loc);
				if (dist > nodeStats.furthestCacheSSKSuccess)
					nodeStats.furthestCacheSSKSuccess=dist;
				if(logDEBUG) Logger.debug(this, "Found key "+key+" in cache");
			}
			return block;
		} catch (IOException e) {
			Logger.error(this, "Cannot fetch data: "+e, e);
			return null;
		}
	}

	public CHKBlock fetch(NodeCHK key, boolean dontPromote, boolean canReadClientCache, boolean canWriteClientCache, boolean canWriteDatastore, boolean forULPR, BlockMetadata meta) {
		double loc=key.toNormalizedDouble();
		double dist=Location.distance(lm.getLocation(), loc);
		if(canReadClientCache) {
			try {
				CHKBlock block = chkClientcache.fetch(key, dontPromote || !canWriteClientCache, false, meta);
				if(block != null) {
					nodeStats.avgClientCacheCHKSuccess.report(loc);
					if (dist > nodeStats.furthestClientCacheCHKSuccess)
					nodeStats.furthestClientCacheCHKSuccess=dist;
					return block;
				}
			} catch (IOException e) {
				Logger.error(this, "Could not read from client cache: "+e, e);
			}
		}
		if(forULPR || useSlashdotCache || canReadClientCache) {
			try {
				CHKBlock block = chkSlashdotcache.fetch(key, dontPromote, false, meta);
				if(block != null) {
					nodeStats.avgSlashdotCacheCHKSucess.report(loc);
					if (dist > nodeStats.furthestSlashdotCacheCHKSuccess)
					nodeStats.furthestSlashdotCacheCHKSuccess=dist;
					return block;
				}
			} catch (IOException e) {
				Logger.error(this, "Could not read from slashdot/ULPR cache: "+e, e);
			}
		}
		boolean ignoreOldBlocks = !writeLocalToDatastore;
		if(canReadClientCache) ignoreOldBlocks = false;
		if(logMINOR) dumpStoreHits();
		try {
			nodeStats.avgRequestLocation.report(loc);
			CHKBlock block = chkDatastore.fetch(key, dontPromote || !canWriteDatastore, ignoreOldBlocks, meta);
			if(block == null) {
				CHKStore store = oldCHK;
				if(store != null)
					block = store.fetch(key, dontPromote || !canWriteDatastore, ignoreOldBlocks, meta);
			}
			if (block != null) {
				nodeStats.avgStoreCHKSuccess.report(loc);
				if (dist > nodeStats.furthestStoreCHKSuccess)
					nodeStats.furthestStoreCHKSuccess=dist;
				return block;
			}
			block=chkDatacache.fetch(key, dontPromote || !canWriteDatastore, ignoreOldBlocks, meta);
			if(block == null) {
				CHKStore store = oldCHKCache;
				if(store != null)
					block = store.fetch(key, dontPromote || !canWriteDatastore, ignoreOldBlocks, meta);
			}
			if (block != null) {
				nodeStats.avgCacheCHKSuccess.report(loc);
				if (dist > nodeStats.furthestCacheCHKSuccess)
					nodeStats.furthestCacheCHKSuccess=dist;
			}
			return block;
		} catch (IOException e) {
			Logger.error(this, "Cannot fetch data: "+e, e);
			return null;
		}
	}

	CHKStore getChkDatacache() {
		return chkDatacache;
	}
	CHKStore getChkDatastore() {
		return chkDatastore;
	}
	SSKStore getSskDatacache() {
		return sskDatacache;
	}
	SSKStore getSskDatastore() {
		return sskDatastore;
	}

        CHKStore getChkSlashdotCache() {
            return chkSlashdotcache;
        }

        CHKStore getChkClientCache() {
            return chkClientcache;
        }

        SSKStore getSskSlashdotCache() {
            return sskSlashdotcache;
        }

        SSKStore getSskClientCache() {
            return sskClientcache;
        }

	/**
	 * This method returns all statistics info for our data store stats table
	 *
	 * @return map that has an entry for each data store instance type and corresponding stats
	 */
	public Map<DataStoreInstanceType, DataStoreStats> getDataStoreStats() {
		Map<DataStoreInstanceType, DataStoreStats> map = new LinkedHashMap<DataStoreInstanceType, DataStoreStats>();

		map.put(new DataStoreInstanceType(CHK, STORE), new StoreCallbackStats(chkDatastore, nodeStats.chkStoreStats()));
		map.put(new DataStoreInstanceType(CHK, CACHE), new StoreCallbackStats(chkDatacache, nodeStats.chkCacheStats()));
		map.put(new DataStoreInstanceType(CHK, SLASHDOT), new StoreCallbackStats(chkSlashdotcache,nodeStats.chkSlashDotCacheStats()));
		map.put(new DataStoreInstanceType(CHK, CLIENT), new StoreCallbackStats(chkClientcache, nodeStats.chkClientCacheStats()));

		map.put(new DataStoreInstanceType(SSK, STORE), new StoreCallbackStats(sskDatastore, nodeStats.sskStoreStats()));
		map.put(new DataStoreInstanceType(SSK, CACHE), new StoreCallbackStats(sskDatacache, nodeStats.sskCacheStats()));
		map.put(new DataStoreInstanceType(SSK, SLASHDOT), new StoreCallbackStats(sskSlashdotcache, nodeStats.sskSlashDotCacheStats()));
		map.put(new DataStoreInstanceType(SSK, CLIENT), new StoreCallbackStats(sskClientcache, nodeStats.sskClientCacheStats()));

		map.put(new DataStoreInstanceType(PUB_KEY, STORE), new StoreCallbackStats(pubKeyDatastore, new NotAvailNodeStoreStats()));
		map.put(new DataStoreInstanceType(PUB_KEY, CACHE), new StoreCallbackStats(pubKeyDatacache, new NotAvailNodeStoreStats()));
		map.put(new DataStoreInstanceType(PUB_KEY, SLASHDOT), new StoreCallbackStats(pubKeySlashdotcache, new NotAvailNodeStoreStats()));
		map.put(new DataStoreInstanceType(PUB_KEY, CLIENT), new StoreCallbackStats(pubKeyClientcache, new NotAvailNodeStoreStats()));

		return map;
	}

	public long getMaxTotalKeys() {
		return maxTotalKeys;
	}

	long timeLastDumpedHits;

	public void dumpStoreHits() {
		long now = System.currentTimeMillis();
		if(now - timeLastDumpedHits > 5000) {
			timeLastDumpedHits = now;
		} else return;
		Logger.minor(this, "Distribution of hits and misses over stores:\n"+
				"CHK Datastore: "+chkDatastore.hits()+ '/' +(chkDatastore.hits()+chkDatastore.misses())+ '/' +chkDatastore.keyCount()+
				"\nCHK Datacache: "+chkDatacache.hits()+ '/' +(chkDatacache.hits()+chkDatacache.misses())+ '/' +chkDatacache.keyCount()+
				"\nSSK Datastore: "+sskDatastore.hits()+ '/' +(sskDatastore.hits()+sskDatastore.misses())+ '/' +sskDatastore.keyCount()+
				"\nSSK Datacache: "+sskDatacache.hits()+ '/' +(sskDatacache.hits()+sskDatacache.misses())+ '/' +sskDatacache.keyCount());
	}

	public void storeShallow(CHKBlock block, boolean canWriteClientCache, boolean canWriteDatastore, boolean forULPR) {
		store(block, false, canWriteClientCache, canWriteDatastore, forULPR);
	}

	/**
	 * Store a datum.
	 * @param block
	 *      a KeyBlock
	 * @param deep If true, insert to the store as well as the cache. Do not set
	 * this to true unless the store results from an insert, and this node is the
	 * closest node to the target; see the description of chkDatastore.
	 */
	public void store(KeyBlock block, boolean deep, boolean canWriteClientCache, boolean canWriteDatastore, boolean forULPR) throws KeyCollisionException {
		if(block instanceof CHKBlock)
			store((CHKBlock)block, deep, canWriteClientCache, canWriteDatastore, forULPR);
		else if(block instanceof SSKBlock)
			store((SSKBlock)block, deep, false, canWriteClientCache, canWriteDatastore, forULPR);
		else throw new IllegalArgumentException("Unknown keytype ");
	}

	private void store(CHKBlock block, boolean deep, boolean canWriteClientCache, boolean canWriteDatastore, boolean forULPR) {
		try {
			double loc = block.getKey().toNormalizedDouble();
			if (canWriteClientCache) {
				chkClientcache.put(block, false);
				nodeStats.avgClientCacheCHKLocation.report(loc);
			}

			if ((forULPR || useSlashdotCache) && !(canWriteDatastore || writeLocalToDatastore)) {
				chkSlashdotcache.put(block, false);
				nodeStats.avgSlashdotCacheCHKLocation.report(loc);
			}
			if (canWriteDatastore || writeLocalToDatastore) {

				if (deep) {
					chkDatastore.put(block, !canWriteDatastore);
					nodeStats.avgStoreCHKLocation.report(loc);

				}
				chkDatacache.put(block, !canWriteDatastore);
				nodeStats.avgCacheCHKLocation.report(loc);
			}
			if (canWriteDatastore || forULPR || useSlashdotCache)
				failureTable.onFound(block);
		} catch (IOException e) {
			Logger.error(this, "Cannot store data: "+e, e);
		} catch (Throwable t) {
			System.err.println(t);
			t.printStackTrace();
			Logger.error(this, "Caught "+t+" storing data", t);
		}
		if(clientCore != null && clientCore.requestStarters != null) {
			clientCore.requestStarters.chkFetchSchedulerBulk.tripPendingKey(block);
			clientCore.requestStarters.chkFetchSchedulerRT.tripPendingKey(block);
		}
	}

	/** Store the block if this is a sink. Call for inserts. */
	public void storeInsert(SSKBlock block, boolean deep, boolean overwrite, boolean canWriteClientCache, boolean canWriteDatastore) throws KeyCollisionException {
		store(block, deep, overwrite, canWriteClientCache, canWriteDatastore, false);
	}

	/** Store only to the cache, and not the store. Called by requests,
	 * as only inserts cause data to be added to the store. */
	public void storeShallow(SSKBlock block, boolean canWriteClientCache, boolean canWriteDatastore, boolean fromULPR) throws KeyCollisionException {
		store(block, false, canWriteClientCache, canWriteDatastore, fromULPR);
	}

	public void store(SSKBlock block, boolean deep, boolean overwrite, boolean canWriteClientCache, boolean canWriteDatastore, boolean forULPR) throws KeyCollisionException {
		try {
			// Store the pubkey before storing the data, otherwise we can get a race condition and
			// end up deleting the SSK data.
			double loc = block.getKey().toNormalizedDouble();
			getPubKey.cacheKey((block.getKey()).getPubKeyHash(), (block.getKey()).getPubKey(), deep, canWriteClientCache, canWriteDatastore, forULPR || useSlashdotCache, writeLocalToDatastore);
			if(canWriteClientCache) {
				sskClientcache.put(block, overwrite, false);
				nodeStats.avgClientCacheSSKLocation.report(loc);
			}
			if((forULPR || useSlashdotCache) && !(canWriteDatastore || writeLocalToDatastore)) {
				sskSlashdotcache.put(block, overwrite, false);
				nodeStats.avgSlashdotCacheSSKLocation.report(loc);
			}
			if(canWriteDatastore || writeLocalToDatastore) {
				if(deep) {
					sskDatastore.put(block, overwrite, !canWriteDatastore);
					nodeStats.avgStoreSSKLocation.report(loc);
				}
				sskDatacache.put(block, overwrite, !canWriteDatastore);
				nodeStats.avgCacheSSKLocation.report(loc);
			}
			if(canWriteDatastore || forULPR || useSlashdotCache)
				failureTable.onFound(block);
		} catch (IOException e) {
			Logger.error(this, "Cannot store data: "+e, e);
		} catch (KeyCollisionException e) {
			throw e;
		} catch (Throwable t) {
			System.err.println(t);
			t.printStackTrace();
			Logger.error(this, "Caught "+t+" storing data", t);
		}
		if(clientCore != null && clientCore.requestStarters != null) {
			clientCore.requestStarters.sskFetchSchedulerBulk.tripPendingKey(block);
			clientCore.requestStarters.sskFetchSchedulerRT.tripPendingKey(block);
		}
	}

	final boolean decrementAtMax;
	final boolean decrementAtMin;

	/**
	 * Decrement the HTL according to the policy of the given
	 * NodePeer if it is non-null, or do something else if it is
	 * null.
	 */
	public short decrementHTL(PeerNode source, short htl) {
		if(source != null)
			return source.decrementHTL(htl);
		// Otherwise...
		if(htl >= maxHTL) htl = maxHTL;
		if(htl <= 0) {
			return 0;
		}
		if(htl == maxHTL) {
			if(decrementAtMax || disableProbabilisticHTLs) htl--;
			return htl;
		}
		if(htl == 1) {
			if(decrementAtMin || disableProbabilisticHTLs) htl--;
			return htl;
		}
		return --htl;
	}

	/**
	 * Fetch or create an CHKInsertSender for a given key/htl.
	 * @param key The key to be inserted.
	 * @param htl The current HTL. We can't coalesce inserts across
	 * HTL's.
	 * @param uid The UID of the caller's request chain, or a new
	 * one. This is obviously not used if there is already an
	 * CHKInsertSender running.
	 * @param source The node that sent the InsertRequest, or null
	 * if it originated locally.
	 * @param ignoreLowBackoff
	 * @param preferInsert
	 */
	public CHKInsertSender makeInsertSender(NodeCHK key, short htl, long uid, InsertTag tag, PeerNode source,
			byte[] headers, PartiallyReceivedBlock prb, boolean fromStore, boolean canWriteClientCache, boolean forkOnCacheable, boolean preferInsert, boolean ignoreLowBackoff, boolean realTimeFlag) {
		if(logMINOR) Logger.minor(this, "makeInsertSender("+key+ ',' +htl+ ',' +uid+ ',' +source+",...,"+fromStore);
		CHKInsertSender is = null;
		is = new CHKInsertSender(key, uid, tag, headers, htl, source, this, prb, fromStore, canWriteClientCache, forkOnCacheable, preferInsert, ignoreLowBackoff,realTimeFlag);
		is.start();
		// CHKInsertSender adds itself to insertSenders
		return is;
	}

	/**
	 * Fetch or create an SSKInsertSender for a given key/htl.
	 * @param key The key to be inserted.
	 * @param htl The current HTL. We can't coalesce inserts across
	 * HTL's.
	 * @param uid The UID of the caller's request chain, or a new
	 * one. This is obviously not used if there is already an
	 * SSKInsertSender running.
	 * @param source The node that sent the InsertRequest, or null
	 * if it originated locally.
	 * @param ignoreLowBackoff
	 * @param preferInsert
	 */
	public SSKInsertSender makeInsertSender(SSKBlock block, short htl, long uid, InsertTag tag, PeerNode source,
			boolean fromStore, boolean canWriteClientCache, boolean canWriteDatastore, boolean forkOnCacheable, boolean preferInsert, boolean ignoreLowBackoff, boolean realTimeFlag) {
		NodeSSK key = block.getKey();
		if(key.getPubKey() == null) {
			throw new IllegalArgumentException("No pub key when inserting");
		}

		getPubKey.cacheKey(key.getPubKeyHash(), key.getPubKey(), false, canWriteClientCache, canWriteDatastore, false, writeLocalToDatastore);
		Logger.minor(this, "makeInsertSender("+key+ ',' +htl+ ',' +uid+ ',' +source+",...,"+fromStore);
		SSKInsertSender is = null;
		is = new SSKInsertSender(block, uid, tag, htl, source, this, fromStore, canWriteClientCache, forkOnCacheable, preferInsert, ignoreLowBackoff, realTimeFlag);
		is.start();
		return is;
	}
	

	/**
	 * @return Some status information.
	 */
	public String getStatus() {
		StringBuilder sb = new StringBuilder();
		if (peers != null)
			sb.append(peers.getStatus());
		else
			sb.append("No peers yet");
		sb.append(tracker.getNumTransferringRequestSenders());
		sb.append('\n');
		return sb.toString();
	}

	/**
	 * @return TMCI peer list
	 */
	public String getTMCIPeerList() {
		StringBuilder sb = new StringBuilder();
		if (peers != null)
			sb.append(peers.getTMCIPeerList());
		else
			sb.append("No peers yet");
		return sb.toString();
	}

	/** Length of signature parameters R and S */
	static final int SIGNATURE_PARAMETER_LENGTH = 32;

	public ClientKeyBlock fetchKey(ClientKey key, boolean canReadClientCache, boolean canWriteClientCache, boolean canWriteDatastore) throws KeyVerifyException {
		if(key instanceof ClientCHK)
			return fetch((ClientCHK)key, canReadClientCache, canWriteClientCache, canWriteDatastore);
		else if(key instanceof ClientSSK)
			return fetch((ClientSSK)key, canReadClientCache, canWriteClientCache, canWriteDatastore);
		else
			throw new IllegalStateException("Don't know what to do with "+key);
	}

	public ClientKeyBlock fetch(ClientSSK clientSSK, boolean canReadClientCache, boolean canWriteClientCache, boolean canWriteDatastore) throws SSKVerifyException {
		DSAPublicKey key = clientSSK.getPubKey();
		if(key == null) {
			key = getPubKey.getKey(clientSSK.pubKeyHash, canReadClientCache, false, null);
		}
		if(key == null) return null;
		clientSSK.setPublicKey(key);
		SSKBlock block = fetch((NodeSSK)clientSSK.getNodeKey(true), false, canReadClientCache, canWriteClientCache, canWriteDatastore, false, null);
		if(block == null) {
			if(logMINOR)
				Logger.minor(this, "Could not find key for "+clientSSK);
			return null;
		}
		// Move the pubkey to the top of the LRU, and fix it if it
		// was corrupt.
		getPubKey.cacheKey(clientSSK.pubKeyHash, key, false, canWriteClientCache, canWriteDatastore, false, writeLocalToDatastore);
		return ClientSSKBlock.construct(block, clientSSK);
	}

	private ClientKeyBlock fetch(ClientCHK clientCHK, boolean canReadClientCache, boolean canWriteClientCache, boolean canWriteDatastore) throws CHKVerifyException {
		CHKBlock block = fetch(clientCHK.getNodeCHK(), false, canReadClientCache, canWriteClientCache, canWriteDatastore, false, null);
		if(block == null) return null;
		return new ClientCHKBlock(block, clientCHK);
	}

	public void exit(int reason) {
		try {
			this.park();
			System.out.println("Goodbye.");
			System.out.println(reason);
		} finally {
			System.exit(reason);
		}
	}

	public void exit(String reason){
		try {
			this.park();
			System.out.println("Goodbye. from "+this+" ("+reason+ ')');
		} finally {
			System.exit(0);
		}
	}

	/**
	 * Returns true if the node is shutting down.
	 * The packet receiver calls this for every packet, and boolean is atomic, so this method is not synchronized.
	 */
	public boolean isStopping() {
		return isStopping;
	}

	/**
	 * Get the node into a state where it can be stopped safely
	 * May be called twice - once in exit (above) and then again
	 * from the wrapper triggered by calling System.exit(). Beware!
	 */
	public void park() {
		synchronized(this) {
			if(isStopping) return;
			isStopping = true;
		}

		try {
			Message msg = DMT.createFNPDisconnect(false, false, -1, new ShortBuffer(new byte[0]));
			peers.localBroadcast(msg, true, false, peers.ctrDisconn);
		} catch (Throwable t) {
			try {
				// E.g. if we haven't finished startup
				Logger.error(this, "Failed to tell peers we are going down: "+t, t);
			} catch (Throwable t1) {
				// Ignore. We don't want to mess up the exit process!
			}
		}

		config.store();

        if(random instanceof PersistentRandomSource) {
            ((PersistentRandomSource) random).write_seed(true);
        }
	}

	public NodeUpdateManager getNodeUpdater(){
		return nodeUpdater;
	}

	public DarknetPeerNode[] getDarknetConnections() {
		return peers.getDarknetPeers();
	}

	public boolean addPeerConnection(PeerNode pn) {
		boolean retval = peers.addPeer(pn);
		peers.writePeersUrgent(pn.isOpennet());
		return retval;
	}

	public void removePeerConnection(PeerNode pn) {
		peers.disconnectAndRemove(pn, true, false, false);
	}

	public void onConnectedPeer() {
		if(logMINOR) Logger.minor(this, "onConnectedPeer()");
		ipDetector.onConnectedPeer();
	}

	public int getFNPPort(){
		return this.getDarknetPortNumber();
	}

	public boolean isOudated() {
		return peers.isOutdated();
	}

	private Map<Integer, NodeToNodeMessageListener> n2nmListeners = new HashMap<Integer, NodeToNodeMessageListener>();

	public synchronized void registerNodeToNodeMessageListener(int type, NodeToNodeMessageListener listener) {
		n2nmListeners.put(type, listener);
	}

	/**
	 * Handle a received node to node message
	 */
	public void receivedNodeToNodeMessage(Message m, PeerNode src) {
		int type = ((Integer) m.getObject(DMT.NODE_TO_NODE_MESSAGE_TYPE)).intValue();
		ShortBuffer messageData = (ShortBuffer) m.getObject(DMT.NODE_TO_NODE_MESSAGE_DATA);
		receivedNodeToNodeMessage(src, type, messageData, false);
	}

	public void receivedNodeToNodeMessage(PeerNode src, int type, ShortBuffer messageData, boolean partingMessage) {
		boolean fromDarknet = src instanceof DarknetPeerNode;

		NodeToNodeMessageListener listener = null;
		synchronized(this) {
			listener = n2nmListeners.get(type);
		}

		if(listener == null) {
			Logger.error(this, "Unknown n2nm ID: "+type+" - discarding packet length "+messageData.getLength());
			return;
		}

		listener.handleMessage(messageData.getData(), fromDarknet, src, type);
	}

	private NodeToNodeMessageListener diffNoderefListener = new NodeToNodeMessageListener() {

		@Override
		public void handleMessage(byte[] data, boolean fromDarknet, PeerNode src, int type) {
			Logger.normal(this, "Received differential node reference node to node message from "+src.getPeer());
			SimpleFieldSet fs = null;
			try {
				fs = new SimpleFieldSet(new String(data, "UTF-8"), false, true, false);
			} catch (IOException e) {
				Logger.error(this, "IOException while parsing node to node message data", e);
				return;
			}
			if(fs.get("n2nType") != null) {
				fs.removeValue("n2nType");
			}
			try {
				src.processDiffNoderef(fs);
			} catch (FSParseException e) {
				Logger.error(this, "FSParseException while parsing node to node message data", e);
				return;
			}
		}

	};

	private NodeToNodeMessageListener fproxyN2NMListener = new NodeToNodeMessageListener() {

		@Override
		public void handleMessage(byte[] data, boolean fromDarknet, PeerNode src, int type) {
			if(!fromDarknet) {
				Logger.error(this, "Got N2NTM from non-darknet node ?!?!?!: from "+src);
				return;
			}
			DarknetPeerNode darkSource = (DarknetPeerNode) src;
			Logger.normal(this, "Received N2NTM from '"+darkSource.getPeer()+"'");
			SimpleFieldSet fs = null;
			try {
				fs = new SimpleFieldSet(new String(data, "UTF-8"), false, true, false);
			} catch (UnsupportedEncodingException e) {
				throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
			} catch (IOException e) {
				Logger.error(this, "IOException while parsing node to node message data", e);
				return;
			}
			fs.putOverwrite("n2nType", Integer.toString(type));
			fs.putOverwrite("receivedTime", Long.toString(System.currentTimeMillis()));
			fs.putOverwrite("receivedAs", "nodeToNodeMessage");
			int fileNumber = darkSource.writeNewExtraPeerDataFile( fs, EXTRA_PEER_DATA_TYPE_N2NTM);
			if( fileNumber == -1 ) {
				Logger.error( this, "Failed to write N2NTM to extra peer data file for peer "+darkSource.getPeer());
			}
			// Keep track of the fileNumber so we can potentially delete the extra peer data file later, the file is authoritative
			try {
				handleNodeToNodeTextMessageSimpleFieldSet(fs, darkSource, fileNumber);
			} catch (FSParseException e) {
				// Shouldn't happen
				throw new Error(e);
			}
		}

	};

	/**
	 * Handle a node to node text message SimpleFieldSet
	 * @throws FSParseException
	 */
	public void handleNodeToNodeTextMessageSimpleFieldSet(SimpleFieldSet fs, DarknetPeerNode source, int fileNumber) throws FSParseException {
		if(logMINOR)
			Logger.minor(this, "Got node to node message: \n"+fs);
		int overallType = fs.getInt("n2nType");
		fs.removeValue("n2nType");
		if(overallType == Node.N2N_MESSAGE_TYPE_FPROXY) {
			handleFproxyNodeToNodeTextMessageSimpleFieldSet(fs, source, fileNumber);
		} else {
			Logger.error(this, "Received unknown node to node message type '"+overallType+"' from "+source.getPeer());
		}
	}

	private void handleFproxyNodeToNodeTextMessageSimpleFieldSet(SimpleFieldSet fs, DarknetPeerNode source, int fileNumber) throws FSParseException {
		int type = fs.getInt("type");
		if(type == Node.N2N_TEXT_MESSAGE_TYPE_USERALERT) {
			source.handleFproxyN2NTM(fs, fileNumber);
		} else if(type == Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER) {
			source.handleFproxyFileOffer(fs, fileNumber);
		} else if(type == Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_ACCEPTED) {
			source.handleFproxyFileOfferAccepted(fs, fileNumber);
		} else if(type == Node.N2N_TEXT_MESSAGE_TYPE_FILE_OFFER_REJECTED) {
			source.handleFproxyFileOfferRejected(fs, fileNumber);
		} else if(type == Node.N2N_TEXT_MESSAGE_TYPE_BOOKMARK) {
			source.handleFproxyBookmarkFeed(fs, fileNumber);
		} else if(type == Node.N2N_TEXT_MESSAGE_TYPE_DOWNLOAD) {
			source.handleFproxyDownloadFeed(fs, fileNumber);
		} else {
			Logger.error(this, "Received unknown fproxy node to node message sub-type '"+type+"' from "+source.getPeer());
		}
	}

	public String getMyName() {
		return myName;
	}

	public MessageCore getUSM() {
		return usm;
	}

	public LocationManager getLocationManager() {
		return lm;
	}

	public int getSwaps() {
		return LocationManager.swaps;
	}

	public int getNoSwaps() {
		return LocationManager.noSwaps;
	}

	public int getStartedSwaps() {
		return LocationManager.startedSwaps;
	}

	public int getSwapsRejectedAlreadyLocked() {
		return LocationManager.swapsRejectedAlreadyLocked;
	}

	public int getSwapsRejectedNowhereToGo() {
		return LocationManager.swapsRejectedNowhereToGo;
	}

	public int getSwapsRejectedRateLimit() {
		return LocationManager.swapsRejectedRateLimit;
	}

	public int getSwapsRejectedRecognizedID() {
		return LocationManager.swapsRejectedRecognizedID;
	}

	public PeerNode[] getPeerNodes() {
		return peers.myPeers();
	}

	public PeerNode[] getConnectedPeers() {
		return peers.connectedPeers();
	}

	/**
	 * Return a peer of the node given its ip and port, name or identity, as a String
	 */
	public PeerNode getPeerNode(String nodeIdentifier) {
		for(PeerNode pn: peers.myPeers()) {
			Peer peer = pn.getPeer();
			String nodeIpAndPort = "";
			if(peer != null) {
				nodeIpAndPort = peer.toString();
			}
			String identity = pn.getIdentityString();
			if(pn instanceof DarknetPeerNode) {
				DarknetPeerNode dpn = (DarknetPeerNode) pn;
				String name = dpn.myName;
				if(identity.equals(nodeIdentifier) || nodeIpAndPort.equals(nodeIdentifier) || name.equals(nodeIdentifier)) {
					return pn;
				}
			} else {
				if(identity.equals(nodeIdentifier) || nodeIpAndPort.equals(nodeIdentifier)) {
					return pn;
				}
			}
		}
		return null;
	}

	public boolean isHasStarted() {
		return hasStarted;
	}

	public void queueRandomReinsert(KeyBlock block) {
		clientCore.queueRandomReinsert(block);
	}

	public String getExtraPeerDataDir() {
		return extraPeerDataDir.getPath();
	}

	public boolean noConnectedPeers() {
		return !peers.anyConnectedPeers();
	}

	public double getLocation() {
		return lm.getLocation();
	}

	public double getLocationChangeSession() {
		return lm.getLocChangeSession();
	}

	public int getAverageOutgoingSwapTime() {
		return lm.getAverageSwapTime();
	}

	public long getSendSwapInterval() {
		return lm.getSendSwapInterval();
	}

	public int getNumberOfRemotePeerLocationsSeenInSwaps() {
		return lm.numberOfRemotePeerLocationsSeenInSwaps;
	}

	public boolean isAdvancedModeEnabled() {
		if(clientCore == null) return false;
		return clientCore.isAdvancedModeEnabled();
	}

	public boolean isFProxyJavascriptEnabled() {
		return clientCore.isFProxyJavascriptEnabled();
	}

	// FIXME convert these kind of threads to Checkpointed's and implement a handler
	// using the PacketSender/Ticker. Would save a few threads.

	public int getNumARKFetchers() {
		int x = 0;
		for(PeerNode p: peers.myPeers()) {
			if(p.isFetchingARK()) x++;
		}
		return x;
	}

	// FIXME put this somewhere else
	private volatile Object statsSync = new Object();

	/** The total number of bytes of real data i.e.&nbsp;payload sent by the node */
	private long totalPayloadSent;

	public void sentPayload(int len) {
		synchronized(statsSync) {
			totalPayloadSent += len;
		}
	}

	/**
	 * Get the total number of bytes of payload (real data) sent by the node
	 *
	 * @return Total payload sent in bytes
	 */
	public long getTotalPayloadSent() {
		synchronized(statsSync) {
			return totalPayloadSent;
		}
	}

	public void setName(String key) throws InvalidConfigValueException, NodeNeedRestartException {
		 config.get("node").getOption("name").setValue(key);
	}

	public Ticker getTicker() {
		return ticker;
	}

	public int getUnclaimedFIFOSize() {
		return usm.getUnclaimedFIFOSize();
	}

	/**
	 * Connect this node to another node (for purposes of testing)
	 */
	public void connectToSeednode(SeedServerTestPeerNode node) throws OpennetDisabledException, FSParseException, PeerParseException, ReferenceSignatureVerificationException {
		peers.addPeer(node,false,false);
	}
	public void connect(Node node, FRIEND_TRUST trust, FRIEND_VISIBILITY visibility) throws FSParseException, PeerParseException, ReferenceSignatureVerificationException, PeerTooOldException {
		peers.connect(node.darknetCrypto.exportPublicFieldSet(), darknetCrypto.packetMangler, trust, visibility);
	}

	public short maxHTL() {
		return maxHTL;
	}

	public int getDarknetPortNumber() {
		return darknetCrypto.portNumber;
	}

	public synchronized int getOutputBandwidthLimit() {
		return outputBandwidthLimit;
	}

	public synchronized int getInputBandwidthLimit() {
		if(inputLimitDefault)
			return outputBandwidthLimit * 4;
		return inputBandwidthLimit;
	}

	/**
	 * @return total datastore size in bytes.
	 */
	public synchronized long getStoreSize() {
		return maxTotalDatastoreSize;
	}

	@Override
	public synchronized void setTimeSkewDetectedUserAlert() {
		if(timeSkewDetectedUserAlert == null) {
			timeSkewDetectedUserAlert = new TimeSkewDetectedUserAlert();
			clientCore.alerts.register(timeSkewDetectedUserAlert);
		}
	}

	public File getNodeDir() { return nodeDir.dir(); }
	public File getCfgDir() { return cfgDir.dir(); }
	public File getUserDir() { return userDir.dir(); }
	public File getRunDir() { return runDir.dir(); }
	public File getStoreDir() { return storeDir.dir(); }
	public File getPluginDir() { return pluginDir.dir(); }

	public ProgramDirectory nodeDir() { return nodeDir; }
	public ProgramDirectory cfgDir() { return cfgDir; }
	public ProgramDirectory userDir() { return userDir; }
	public ProgramDirectory runDir() { return runDir; }
	public ProgramDirectory storeDir() { return storeDir; }
	public ProgramDirectory pluginDir() { return pluginDir; }


	public DarknetPeerNode createNewDarknetNode(SimpleFieldSet fs, FRIEND_TRUST trust, FRIEND_VISIBILITY visibility) throws FSParseException, PeerParseException, ReferenceSignatureVerificationException, PeerTooOldException {
		return new DarknetPeerNode(fs, this, darknetCrypto, false, trust, visibility);
	}

	public OpennetPeerNode createNewOpennetNode(SimpleFieldSet fs) throws FSParseException, OpennetDisabledException, PeerParseException, ReferenceSignatureVerificationException, PeerTooOldException {
		if(opennet == null) throw new OpennetDisabledException("Opennet is not currently enabled");
		return new OpennetPeerNode(fs, this, opennet.crypto, opennet, false);
	}

	public SeedServerTestPeerNode createNewSeedServerTestPeerNode(SimpleFieldSet fs) throws FSParseException, OpennetDisabledException, PeerParseException, ReferenceSignatureVerificationException, PeerTooOldException {
		if(opennet == null) throw new OpennetDisabledException("Opennet is not currently enabled");
		return new SeedServerTestPeerNode(fs, this, opennet.crypto, true);
	}

	public OpennetPeerNode addNewOpennetNode(SimpleFieldSet fs, ConnectionType connectionType) throws FSParseException, PeerParseException, ReferenceSignatureVerificationException {
		// FIXME: perhaps this should throw OpennetDisabledExcemption rather than returing false?
		if(opennet == null) return null;
		return opennet.addNewOpennetNode(fs, connectionType, false);
	}

	public byte[] getOpennetPubKeyHash() {
		return opennet.crypto.ecdsaPubKeyHash;
	}

	public byte[] getDarknetPubKeyHash() {
		return darknetCrypto.ecdsaPubKeyHash;
	}

	public synchronized boolean isOpennetEnabled() {
		return opennet != null;
	}

	public SimpleFieldSet exportDarknetPublicFieldSet() {
		return darknetCrypto.exportPublicFieldSet();
	}

	public SimpleFieldSet exportOpennetPublicFieldSet() {
		return opennet.crypto.exportPublicFieldSet();
	}

	public SimpleFieldSet exportDarknetPrivateFieldSet() {
		return darknetCrypto.exportPrivateFieldSet();
	}

	public SimpleFieldSet exportOpennetPrivateFieldSet() {
		return opennet.crypto.exportPrivateFieldSet();
	}

	/**
	 * Should the IP detection code only use the IP address override and the bindTo information,
	 * rather than doing a full detection?
	 */
	public synchronized boolean dontDetect() {
		// Only return true if bindTo is set on all ports which are in use
		if(!darknetCrypto.getBindTo().isRealInternetAddress(false, true, false)) return false;
		if(opennet != null) {
			if(opennet.crypto.getBindTo().isRealInternetAddress(false, true, false)) return false;
		}
		return true;
	}

	public int getOpennetFNPPort() {
		if(opennet == null) return -1;
		return opennet.crypto.portNumber;
	}

	public OpennetManager getOpennet() {
		return opennet;
	}

	public synchronized boolean passOpennetRefsThroughDarknet() {
		return passOpennetRefsThroughDarknet;
	}

	/**
	 * Get the set of public ports that need to be forwarded. These are internal
	 * ports, not necessarily external - they may be rewritten by the NAT.
	 * @return A Set of ForwardPort's to be fed to port forward plugins.
	 */
	public Set<ForwardPort> getPublicInterfacePorts() {
		HashSet<ForwardPort> set = new HashSet<ForwardPort>();
		// FIXME IPv6 support
		set.add(new ForwardPort("darknet", false, ForwardPort.PROTOCOL_UDP_IPV4, darknetCrypto.portNumber));
		if(opennet != null) {
			NodeCrypto crypto = opennet.crypto;
			if(crypto != null) {
				set.add(new ForwardPort("opennet", false, ForwardPort.PROTOCOL_UDP_IPV4, crypto.portNumber));
			}
		}
		return set;
	}

	/**
	 * Get the time since the node was started in milliseconds.
	 *
	 * @return Uptime in milliseconds
	 */
	public long getUptime() {
		return System.currentTimeMillis() - usm.getStartedTime();
	}

	public synchronized UdpSocketHandler[] getPacketSocketHandlers() {
		// FIXME better way to get these!
		if(opennet != null) {
			return new UdpSocketHandler[] { darknetCrypto.socket, opennet.crypto.socket };
			// TODO Auto-generated method stub
		} else {
			return new UdpSocketHandler[] { darknetCrypto.socket };
		}
	}

	public int getMaxOpennetPeers() {
		return maxOpennetPeers;
	}

	public void onAddedValidIP() {
		OpennetManager om;
		synchronized(this) {
			om = opennet;
		}
		if(om != null) {
			Announcer announcer = om.announcer;
			if(announcer != null) {
				announcer.maybeSendAnnouncement();
			}
		}
	}

	public boolean isSeednode() {
		return acceptSeedConnections;
	}

	/**
	 * Returns true if the packet receiver should try to decode/process packets that are not from a peer (i.e. from a seed connection)
	 * The packet receiver calls this upon receiving an unrecognized packet.
	 */
	public boolean wantAnonAuth(boolean isOpennet) {
		if(isOpennet)
			return opennet != null && acceptSeedConnections;
		else
			return false;
	}

	// FIXME make this configurable
	// Probably should wait until we have non-opennet anon auth so we can add it to NodeCrypto.
	public boolean wantAnonAuthChangeIP(boolean isOpennet) {
		return !isOpennet;
	}

	public boolean opennetDefinitelyPortForwarded() {
		OpennetManager om;
		synchronized(this) {
			om = this.opennet;
		}
		if(om == null) return false;
		NodeCrypto crypto = om.crypto;
		if(crypto == null) return false;
		return crypto.definitelyPortForwarded();
	}

	public boolean darknetDefinitelyPortForwarded() {
		if(darknetCrypto == null) return false;
		return darknetCrypto.definitelyPortForwarded();
	}

	public boolean hasKey(Key key, boolean canReadClientCache, boolean forULPR) {
		// FIXME optimise!
		if(key instanceof NodeCHK)
			return fetch((NodeCHK)key, true, canReadClientCache, false, false, forULPR, null) != null;
		else
			return fetch((NodeSSK)key, true, canReadClientCache, false, false, forULPR, null) != null;
	}

	/**
	 * Warning: does not announce change in location!
	 */
	public void setLocation(double loc) {
		lm.setLocation(loc);
	}

	public boolean peersWantKey(Key key) {
		return failureTable.peersWantKey(key, null);
	}

	private SimpleUserAlert alertMTUTooSmall;

	public final RequestClient nonPersistentClientBulk = new RequestClientBuilder().build();
	public final RequestClient nonPersistentClientRT = new RequestClientBuilder().realTime().build();

	public void setDispatcherHook(NodeDispatcherCallback cb) {
		this.dispatcher.setHook(cb);
	}

	public boolean shallWePublishOurPeersLocation() {
		return publishOurPeersLocation;
	}

	public boolean shallWeRouteAccordingToOurPeersLocation(int htl) {
		return routeAccordingToOurPeersLocation && htl > 1;
	}

	/** Can be called to decrypt client.dat* etc, or can be called when switching from another 
	 * security level to HIGH. */
	public void setMasterPassword(String password, boolean inFirstTimeWizard) throws AlreadySetPasswordException, MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
		MasterKeys k;
		synchronized(this) {
		    if(keys == null) {
		        // Decrypting.
		        keys = MasterKeys.read(masterKeysFile, secureRandom, password);
		        databaseKey = keys.createDatabaseKey(secureRandom);
		    } else {
		        // Setting password when changing to HIGH from another mode.
		        keys.changePassword(masterKeysFile, password, secureRandom);
		        return;
		    }
		    k = keys;
		}
		setPasswordInner(k, inFirstTimeWizard);
	}

	private void setPasswordInner(MasterKeys keys, boolean inFirstTimeWizard) throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
	    MasterSecret secret = keys.getPersistentMasterSecret();
        clientCore.setupMasterSecret(secret);
		boolean wantClientCache = false;
		boolean wantDatabase = false;
		synchronized(this) {
			wantClientCache = clientCacheAwaitingPassword;
			wantDatabase = databaseAwaitingPassword;
			databaseAwaitingPassword = false;
		}
		if(wantClientCache)
			activatePasswordedClientCache(keys);
		if(wantDatabase)
			lateSetupDatabase(keys.createDatabaseKey(secureRandom));
	}


	private void activatePasswordedClientCache(MasterKeys keys) {
		synchronized(this) {
			if(clientCacheType.equals("ram")) {
				System.err.println("RAM client cache cannot be passworded!");
				return;
			}
			if(!clientCacheType.equals("salt-hash")) {
				System.err.println("Unknown client cache type, cannot activate passworded store: "+clientCacheType);
				return;
			}
		}
		Runnable migrate = new MigrateOldStoreData(true);
		String suffix = getStoreSuffix();
		try {
			initSaltHashClientCacheFS(suffix, true, keys.clientCacheMasterKey);
		} catch (NodeInitException e) {
			Logger.error(this, "Unable to activate passworded client cache", e);
			System.err.println("Unable to activate passworded client cache: "+e);
			e.printStackTrace();
			return;
		}

		synchronized(this) {
			clientCacheAwaitingPassword = false;
		}

		executor.execute(migrate, "Migrate data from previous store");
	}

	public void changeMasterPassword(String oldPassword, String newPassword, boolean inFirstTimeWizard) throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException, AlreadySetPasswordException {
		if(securityLevels.getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.MAXIMUM)
			Logger.error(this, "Changing password while physical threat level is at MAXIMUM???");
		if(masterKeysFile.exists()) {
			keys.changePassword(masterKeysFile, newPassword, secureRandom);
			setPasswordInner(keys, inFirstTimeWizard);
		} else {
			setMasterPassword(newPassword, inFirstTimeWizard);
		}
	}

	public static class AlreadySetPasswordException extends Exception {

	   final private static long serialVersionUID = -7328456475029374032L;

	}

	public synchronized File getMasterPasswordFile() {
		return masterKeysFile;
	}

	boolean hasPanicked() {
		return hasPanicked;
	}

	public void panic() {
		hasPanicked = true;
		clientCore.clientLayerPersister.panic();
		clientCore.clientLayerPersister.killAndWaitForNotRunning();
		try {
			MasterKeys.killMasterKeys(getMasterPasswordFile());
		} catch (IOException e) {
			System.err.println("Unable to wipe master passwords key file!");
			System.err.println("Please delete " + getMasterPasswordFile()
					   + " to ensure that nobody can recover your old downloads.");
		}
		// persistent-temp will be cleaned on restart.
	}

	public void finishPanic() {
		WrapperManager.restart();
		System.exit(0);
	}


	public boolean awaitingPassword() {
		if(clientCacheAwaitingPassword) return true;
		if(databaseAwaitingPassword) return true;
		return false;
	}

	public boolean wantEncryptedDatabase() {
	    return this.securityLevels.getPhysicalThreatLevel() != PHYSICAL_THREAT_LEVEL.LOW;
	}
	
	public boolean wantNoPersistentDatabase() {
	    return this.securityLevels.getPhysicalThreatLevel() == PHYSICAL_THREAT_LEVEL.MAXIMUM;
	}

	public boolean hasDatabase() {
	    return !clientCore.clientLayerPersister.isKilledOrNotLoaded();
	}

        /**
         * @return canonical path of the database file in use.
         */
        public String getDatabasePath() throws IOException {
            return clientCore.clientLayerPersister.getWriteFilename().toString();
        }

	/** Should we commit the block to the store rather than the cache?
	 *
	 * <p>We used to check whether we are a sink by checking whether any peer has
	 * a closer location than we do. Then we made low-uptime nodes exempt from
	 * this calculation: if we route to a low uptime node with a closer location,
	 * we want to store it anyway since he may go offline. The problem was that
	 * if we routed to a low-uptime node, and there was another option that wasn't
	 * low-uptime but was closer to the target than we were, then we would not
	 * store in the store. Also, routing isn't always by the closest peer location:
	 * FOAF and per-node failure tables change it. So now, we consider the nodes
	 * we have actually routed to:</p>
	 *
	 * <p>Store in datastore if our location is closer to the target than:</p><ol>
	 * <li>the source location (if any, and ignoring if low-uptime)</li>
	 * <li>the locations of the nodes we just routed to (ditto)</li>
	 * </ol>
	 *
	 * @param key
	 * @param source
	 * @param routedTo
	 * @return
	 */
	public boolean shouldStoreDeep(Key key, PeerNode source, PeerNode[] routedTo) {
    	double myLoc = getLocation();
    	double target = key.toNormalizedDouble();
    	double myDist = Location.distance(myLoc, target);

    	// First, calculate whether we would have stored it using the old formula.
    	if(logMINOR) Logger.minor(this, "Should store for "+key+" ?");
    	// Don't sink store if any of the nodes we routed to, or our predecessor, is both high-uptime and closer to the target than we are.
    	if(source != null && !source.isLowUptime()) {
    		if(Location.distance(source, target) < myDist) {
    	    	if(logMINOR) Logger.minor(this, "Not storing because source is closer to target for "+key+" : "+source);
    			return false;
    		}
    	}
    	for(PeerNode pn : routedTo) {
    		if(Location.distance(pn, target) < myDist && !pn.isLowUptime()) {
    	    	if(logMINOR) Logger.minor(this, "Not storing because peer "+pn+" is closer to target for "+key+" his loc "+pn.getLocation()+" my loc "+myLoc+" target is "+target);
    			return false;
    		} else {
    			if(logMINOR) Logger.minor(this, "Should store maybe, peer "+pn+" loc = "+pn.getLocation()+" my loc is "+myLoc+" target is "+target+" low uptime is "+pn.isLowUptime());
    		}
    	}
    	if(logMINOR) Logger.minor(this, "Should store returning true for "+key+" target="+target+" myLoc="+myLoc+" peers: "+routedTo.length);
    	return true;
	}


	public boolean getWriteLocalToDatastore() {
		return writeLocalToDatastore;
	}

	public boolean getUseSlashdotCache() {
		return useSlashdotCache;
	}

	// FIXME remove the visibility alert after a few builds.

	public void createVisibilityAlert() {
		synchronized(this) {
			if(showFriendsVisibilityAlert) return;
			showFriendsVisibilityAlert = true;
		}
		// Wait until startup completed.
		this.getTicker().queueTimedJob(new Runnable() {

			@Override
			public void run() {
				config.store();
			}
		}, 0);
		registerFriendsVisibilityAlert();
	}
	
	private UserAlert visibilityAlert = new SimpleUserAlert(true, l10n("pleaseSetPeersVisibilityAlertTitle"), l10n("pleaseSetPeersVisibilityAlert"), l10n("pleaseSetPeersVisibilityAlert"), UserAlert.ERROR) {
		
		@Override
		public void onDismiss() {
			synchronized(Node.this) {
				showFriendsVisibilityAlert = false;
			}
			config.store();
			unregisterFriendsVisibilityAlert();
		}
		
	};
	
	private void registerFriendsVisibilityAlert() {
		if(clientCore == null || clientCore.alerts == null) {
			// Wait until startup completed.
			this.getTicker().queueTimedJob(new Runnable() {

				@Override
				public void run() {
					registerFriendsVisibilityAlert();
				}
				
			}, 0);
			return;
		}
		clientCore.alerts.register(visibilityAlert);
	}
	
	private void unregisterFriendsVisibilityAlert() {
		clientCore.alerts.unregister(visibilityAlert);
	}

	public int getMinimumMTU() {
		int mtu;
		synchronized(this) {
			mtu = maxPacketSize;
		}
		if(ipDetector != null) {
			int detected = ipDetector.getMinimumDetectedMTU();
			if(detected < mtu) return detected;
		}
		return mtu;
	}


	public void updateMTU() {
		this.darknetCrypto.socket.calculateMaxPacketSize();
		OpennetManager om = opennet;
		if(om != null) {
			om.crypto.socket.calculateMaxPacketSize();
		}
	}


	public static boolean isTestnetEnabled() {
		return false;
	}


	public MersenneTwister createRandom() {
		byte[] buf = new byte[16];
		random.nextBytes(buf);
		return new MersenneTwister(buf);
	}
	
	public boolean enableNewLoadManagement(boolean realTimeFlag) {
		NodeStats stats = this.nodeStats;
		if(stats == null) {
			Logger.error(this, "Calling enableNewLoadManagement before Node constructor completes! FIX THIS!", new Exception("error"));
			return false;
		}
		return stats.enableNewLoadManagement(realTimeFlag);
	}
	
	/** FIXME move to Probe.java? */
	public boolean enableRoutedPing() {
		return enableRoutedPing;
	}


	public boolean updateIsUrgent() {
		OpennetManager om = getOpennet();
		if(om != null) {
			if(om.announcer != null && om.announcer.isWaitingForUpdater())
				return true;
		}
		if(peers.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, true) > PeerManager.OUTDATED_MIN_TOO_NEW_DARKNET)
			return true;
		return false;
	}


    public byte[] getPluginStoreKey(String storeIdentifier) {
        DatabaseKey key;
        synchronized(this) {
            key = databaseKey;
        }
        if(key != null)
            return key.getPluginStoreKey(storeIdentifier);
        else
            return null;
    }

	public PluginManager getPluginManager() {
		return pluginManager;
	}


    DatabaseKey getDatabaseKey() {
        return databaseKey;
    }

    public NodeDiagnostics getNodeDiagnostics() {
        return nodeDiagnostics;
    }

    public boolean isNodeDiagnosticsEnabled() {
        return enableNodeDiagnostics;
    }
}
