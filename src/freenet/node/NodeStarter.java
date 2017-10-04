/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import org.tanukisoftware.wrapper.WrapperListener;
import org.tanukisoftware.wrapper.WrapperManager;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.UUID;

import freenet.config.FreenetFilePersistentConfig;
import freenet.config.InvalidConfigValueException;
import freenet.config.PersistentConfig;
import freenet.config.SubConfig;
import freenet.crypt.JceLoader;
import freenet.crypt.RandomSource;
import freenet.crypt.SSL;
import freenet.crypt.Yarrow;
import freenet.support.Executor;
import freenet.support.JVMVersion;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.LoggerHook.InvalidThresholdException;
import freenet.support.PooledExecutor;
import freenet.support.ProcessPriority;
import freenet.support.SimpleFieldSet;
import freenet.support.io.NativeThread;

import static java.util.concurrent.TimeUnit.MINUTES;

/**
 *  @author nextgens
 *
 *  A class to tie the wrapper and the node (needed for self-restarting support).
 *  
 *  There will only ever be one instance of NodeStarter.
 */
public class NodeStarter implements WrapperListener {

	private Node node;
	private static LoggingConfigHandler logConfigHandler;
	/*
	(File.separatorChar == '\\') &&
	(System.getProperty("os.arch").toLowerCase().matches("(i?[x0-9]86_64|amd64)")) ? 6 : 2;
	 */
	public static final int extBuildNumber;
	public static final String extRevisionNumber;

	static {
		extBuildNumber = ExtVersion.extBuildNumber();
		extRevisionNumber = ExtVersion.extRevisionNumber();
	}

	private FreenetFilePersistentConfig cfg;

	// experimental osgi support
	private static NodeStarter nodestarter_osgi = null;

	private static boolean isTestingVM;
	private static boolean isStarted;

	/** If false, this is some sort of multi-node testing VM */
	public synchronized static boolean isTestingVM() {
		if(isStarted)
			return isTestingVM;
		else
			throw new IllegalStateException();
	}
	
	/*---------------------------------------------------------------
	 * Constructors
	 *-------------------------------------------------------------*/
	private NodeStarter() {
		// Force it to load right now, and log what exactly is loaded.
		JceLoader.dumpLoaded();
	}

	public NodeStarter get() {
		return this;
	}

	/*---------------------------------------------------------------
	 * WrapperListener Methods
	 *-------------------------------------------------------------*/
	/**
	 * The start method is called when the WrapperManager is signaled by the
	 *	native wrapper code that it can start its application.  This
	 *	method call is expected to return, so a new thread should be launched
	 *	if necessary.
	 *
	 * @param args List of arguments used to initialize the application.
	 *
	 * @return Any error code if the application should exit on completion
	 *         of the start method.  If there were no problems then this
	 *         method should return null.
	 */
	@Override
	public Integer start(String[] args) {
		synchronized(NodeStarter.class) {
			if(isStarted) throw new IllegalStateException();
			isStarted = true;
			isTestingVM = false;
		}
		if(args.length > 1) {
			System.out.println("Usage: $ java freenet.node.Node <configFile>");
			return Integer.valueOf(-1);
		}
		String builtWithMessage = "freenet.jar built with freenet-ext.jar Build #" + ExtVersion.buildNumber + " r" + ExtVersion.cvsRevision+" running with ext build "+extBuildNumber+" r" + extRevisionNumber;
		Logger.normal(this, builtWithMessage);
		System.out.println(builtWithMessage);

		File configFilename;
		if(args.length == 0) {
			System.out.println("Using default config filename freenet.ini");
			configFilename = new File("freenet.ini");
		} else
			configFilename = new File(args[0]);

		// set Java's DNS cache not to cache forever, since many people
		// use dyndns hostnames
		java.security.Security.setProperty("networkaddress.cache.ttl", "0");
		java.security.Security.setProperty("networkaddress.cache.negative.ttl", "0");

		try {
			System.out.println("Creating config from "+configFilename);
			cfg = FreenetFilePersistentConfig.constructFreenetFilePersistentConfig(configFilename);
		} catch(IOException e) {
			System.out.println("Error : " + e);
			e.printStackTrace();
			return Integer.valueOf(-1);
		}

		// First, set up logging. It is global, and may be shared between several nodes.
		SubConfig loggingConfig = cfg.createSubConfig("logger");

		PooledExecutor executor = new PooledExecutor();

		try {
			System.out.println("Creating logger...");
			logConfigHandler = new LoggingConfigHandler(loggingConfig, executor);
		} catch(InvalidConfigValueException e) {
			System.err.println("Error: could not set up logging: " + e.getMessage());
			e.printStackTrace();
			return Integer.valueOf(-2);
		}

		System.out.println("Starting executor...");
		executor.start();

		// Prevent timeouts for a while. The DiffieHellman init for example could take some time on a very slow system.
		WrapperManager.signalStarting(500000);

		// Thread to keep the node up.
		// JVM deadlocks losing a lock when two threads of different types (daemon|app)
		// are contended for the same lock. So make USM daemon, and use useless to keep the JVM
		// up.
		// http://forum.java.sun.com/thread.jspa?threadID=343023&messageID=2942637 - last message
		Runnable useless =
			new Runnable() {

				@Override
				public void run() {
					while(true) {
						try {
							Thread.sleep(MINUTES.toMillis(60));
						} catch(InterruptedException e) {
							// Ignore
						} catch(Throwable t) {
							try {
								Logger.error(this, "Caught " + t, t);
							} catch(Throwable t1) {
								// Ignore
							}
						}
					}
				}
			};
		NativeThread plug = new NativeThread(useless, "Plug", NativeThread.MAX_PRIORITY, false);
		// Not daemon, but doesn't do anything.
		// Keeps the JVM alive.
		// DO NOT do anything in the plug thread, if you do you risk the EvilJVMBug.
		plug.setDaemon(false);
		plug.start();

		// Initialize SSL
		SubConfig sslConfig = cfg.createSubConfig("ssl");
		SSL.init(sslConfig);

		try {
			node = new Node(cfg, null, null, logConfigHandler, this, executor);
			node.start();
			System.out.println("Node initialization completed.");
		} catch(NodeInitException e) {
			System.err.println("Failed to load node: " + e.exitCode + " : " + e.getMessage());
			e.printStackTrace();
			System.exit(e.exitCode);
		}

		return null;
	}

	/**
	 * Called when the application is shutting down.  The Wrapper assumes that
	 *  this method will return fairly quickly.  If the shutdown code code
	 *  could potentially take a long time, then WrapperManager.signalStopping()
	 *  should be called to extend the timeout period.  If for some reason,
	 *  the stop method can not return, then it must call
	 *  WrapperManager.stopped() to avoid warning messages from the Wrapper.
	 *
	 * @param exitCode The suggested exit code that will be returned to the OS
	 *                 when the JVM exits.
	 *
	 * @return The exit code to actually return to the OS.  In most cases, this
	 *         should just be the value of exitCode, however the user code has
	 *         the option of changing the exit code if there are any problems
	 *         during shutdown.
	 */
	@Override
	public int stop(int exitCode) {
		System.err.println("Shutting down with exit code " + exitCode);
		node.park();
		// see #354
		WrapperManager.signalStopping(120000);

		return exitCode;
	}

	public void restart() {
		WrapperManager.restart();
	}

	/**
	 * Called whenever the native wrapper code traps a system control signal
	 *  against the Java process.  It is up to the callback to take any actions
	 *  necessary.  Possible values are: WrapperManager.WRAPPER_CTRL_C_EVENT,
	 *    WRAPPER_CTRL_CLOSE_EVENT, WRAPPER_CTRL_LOGOFF_EVENT, or
	 *    WRAPPER_CTRL_SHUTDOWN_EVENT
	 *
	 * @param event The system control signal.
	 */
	@Override
	public void controlEvent(int event) {
		if(WrapperManager.isControlledByNativeWrapper()) {
			// The Wrapper will take care of this event
		} else
			// We are not being controlled by the Wrapper, so
			//  handle the event ourselves.
			if((event == WrapperManager.WRAPPER_CTRL_C_EVENT) ||
				(event == WrapperManager.WRAPPER_CTRL_CLOSE_EVENT) ||
				(event == WrapperManager.WRAPPER_CTRL_SHUTDOWN_EVENT))
				WrapperManager.stop(0);
	}

	/*---------------------------------------------------------------
	 * Main Method
	 *-------------------------------------------------------------*/
	public static void main(String[] args) {
		// Immediately try entering background mode. This way also class
		//  loading will be subject to reduced priority. 
		ProcessPriority.enterBackgroundMode();
		
		// Start the application.  If the JVM was launched from the native
		//  Wrapper then the application will wait for the native Wrapper to
		//  call the application's start method.  Otherwise the start method
		//  will be called immediately.
		WrapperManager.start(new NodeStarter(), args);
	}

	static SemiOrderedShutdownHook shutdownHook;

    /**
     * @see #globalTestInit(File, boolean, LogLevel, String, boolean, RandomSource)
     * @deprecated Instead use {@link #globalTestInit(File, boolean, LogLevel, String, boolean,
     *             RandomSource)}.
     */
    @Deprecated
    public static RandomSource globalTestInit(String testName, boolean enablePlug,
            LogLevel logThreshold, String details, boolean noDNS) throws InvalidThresholdException {

        return globalTestInit(new File(testName), enablePlug, logThreshold, details, noDNS, null);
    }

	/**
	 * VM-specific init.
	 * Not Node-specific; many nodes may be created later.
     * @param baseDirectory
     *            The directory in which the test data will be placed. Will be created automatically
     *            if it does not exist. You should use the same one in
     *            {@link TestNodeParameters#baseDirectory} afterwards for each individual test node
     *            as long as it has a distinct port. See its JavaDoc.<br>
     *            The function will NOT fail if the directory exists already. You should make sure
     *            on your own to delete this before and after tests to ensure a clean state. Notice
     *            that JUnit provides a mechanism for automatic creation and deletion of test
     *            directories (TemporaryFolder).
     * @param RandomSource
     *            The random number generator of the Node. Null for the default of {@link Yarrow}.
     *            <br>You might want to use a {@link DummyRandomSource} in unit tests:<br>
     *            - Unlike Yarrow, it won't block startup waiting for entropy.<br>
     *            - It allows you to specify a seed which you then can print to stdout so randomized
     *               unit tests are reproducible.<br>
     *            - It should be a lot faster than Yarrow.<br> 
     * @return If you passed a {@link RandomSource}, the same one is returned. Otherwise, a new
     *         {@link Yarrow} is returned.
	 */
    public static RandomSource globalTestInit(File baseDirectory, boolean enablePlug,
            LogLevel logThreshold, String details, boolean noDNS, RandomSource randomSource)
                throws InvalidThresholdException {

		synchronized(NodeStarter.class) {
			if(isStarted) throw new IllegalStateException();
			isStarted = true;
			isTestingVM = true;
		}

        if((!baseDirectory.mkdir()) && ((!baseDirectory.exists())
            || (!baseDirectory.isDirectory()))) {

			System.err.println("Cannot create directory for test");
			System.exit(NodeInitException.EXIT_TEST_ERROR);
		}

		Logger.setupStdoutLogging(logThreshold, details);

		// set Java's DNS cache not to cache forever, since many people
		// use dyndns hostnames
		java.security.Security.setProperty("networkaddress.cache.ttl", "0");
		java.security.Security.setProperty("networkaddress.cache.negative.ttl", "0");

		// Setup RNG
        RandomSource random = randomSource != null ? randomSource : new Yarrow();

		if(enablePlug) {

			// Thread to keep the node up.
			// JVM deadlocks losing a lock when two threads of different types (daemon|app)
			// are contended for the same lock. So make USM daemon, and use useless to keep the JVM
			// up.
			// http://forum.java.sun.com/thread.jspa?threadID=343023&messageID=2942637 - last message
			Runnable useless =
				new Runnable() {

					@Override
					public void run() {
						while(true) {
							try {
								Thread.sleep(MINUTES.toMillis(60));
							} catch(InterruptedException e) {
								// Ignore
							} catch(Throwable t) {
								try {
									Logger.error(this, "Caught " + t, t);
								} catch(Throwable t1) {
									// Ignore
								}
							}
						}
					}
				};
			Thread plug = new Thread(useless, "Plug");
			// Not daemon, but doesn't do anything.
			// Keeps the JVM alive.
			// DO NOT do anything in the plug thread, if you do you risk the EvilJVMBug.
			plug.setDaemon(false);
			plug.start();
		}

		DNSRequester.DISABLE = noDNS;

		return random;
	}

    /**
     * @deprecated Use {@link #createTestNode(TestNodeParameters)} instead
     */
    @Deprecated
	public static Node createTestNode(int port, int opennetPort, String testName, boolean disableProbabilisticHTLs,
	                                  short maxHTL, int dropProb, RandomSource random,
	                                  Executor executor, int threadLimit, long storeSize, boolean ramStore,
	                                  boolean enableSwapping, boolean enableARKs, boolean enableULPRs, boolean enablePerNodeFailureTables,
	                                  boolean enableSwapQueueing, boolean enablePacketCoalescing,
	                                  int outputBandwidthLimit, boolean enableFOAF,
	                                  boolean connectToSeednodes, boolean longPingTimes, boolean useSlashdotCache, String ipAddressOverride) throws NodeInitException {
		return createTestNode(port, opennetPort, testName, disableProbabilisticHTLs, maxHTL, dropProb, random, executor,
		    threadLimit, storeSize, ramStore, enableSwapping, enableARKs, enableULPRs, enablePerNodeFailureTables,
		    enableSwapQueueing, enablePacketCoalescing, outputBandwidthLimit, enableFOAF, connectToSeednodes,
		    longPingTimes, useSlashdotCache, ipAddressOverride, false);
	}

    /**
     * TODO FIXME: Someone who understands all the parameters please add sane defaults. 
     */
    public static final class TestNodeParameters {
        /** The UDP port number. Each test node must have a different port number. */
        public int port;
        /** The UDP opennet port number. Each test node must have a different port number. */
        public int opennetPort;
        /** The directory where the test node will put all its data. <br>
         *  Will be created automatically if it does not exist.<br>
         *  {@link NodeStarter#createTestNode(TestNodeParameters)} will NOT fail if this exists.
         *  You should make sure on your own to delete this before and after tests to ensure
         *  a clean state. Notice that JUnit provides a mechanism for automatic creation
         *  and deletion of test directories (TemporaryFolder).<br>
         *  Notice that a subdirectory with the name being the port number of the node will be
         *  created there, and all data of the node will be put into it. So you can and should use
         *  the same baseDirectory when calling {@link NodeStarter#globalTestInit(File, boolean,
         *  LogLevel, String, boolean, RandomSource)} (which you have to do once for each Java VM):
         *  Each one will start with a fresh empty subdirectory for as long as each of them uses a
         *  unique port number. */
        public File baseDirectory = new File("freenet-test-node-" + UUID.randomUUID().toString());
        public boolean disableProbabilisticHTLs;
        public short maxHTL;
        public int dropProb;
        public RandomSource random;
        public Executor executor;
        public int threadLimit = 500;
        public long storeSize;
        public boolean ramStore;
        public boolean enableSwapping;
        public boolean enableARKs;
        public boolean enableULPRs;
        public boolean enablePerNodeFailureTables;
        public boolean enableSwapQueueing;
        public boolean enablePacketCoalescing;
        public int outputBandwidthLimit;
        public boolean enableFOAF;
        public boolean connectToSeednodes;
        public boolean longPingTimes;
        public boolean useSlashdotCache;
        public String ipAddressOverride;
        public boolean enableFCP;
        public boolean enablePlugins;
    }

    /**
     * Create a test node.
     * @param port The node port number. Each test node must have a different port
     * number.
     * @param testName The test name.
     * @throws NodeInitException If the node cannot start up for some reason, most
     * likely a config problem.
     * @deprecated Use {@link #createTestNode(TestNodeParameters)} instead
     */
    @Deprecated
    public static Node createTestNode(int port, int opennetPort, String testName,
            boolean disableProbabilisticHTLs, short maxHTL, int dropProb, RandomSource random,
            Executor executor, int threadLimit, long storeSize, boolean ramStore,
            boolean enableSwapping, boolean enableARKs, boolean enableULPRs,
            boolean enablePerNodeFailureTables, boolean enableSwapQueueing,
            boolean enablePacketCoalescing, int outputBandwidthLimit, boolean enableFOAF,
            boolean connectToSeednodes, boolean longPingTimes, boolean useSlashdotCache,
            String ipAddressOverride, boolean enableFCP)
                throws NodeInitException {

        TestNodeParameters params = new TestNodeParameters();
        params.port = port;
        params.opennetPort = opennetPort;
        params.baseDirectory = new File(testName);
        params.disableProbabilisticHTLs = disableProbabilisticHTLs;
        params.maxHTL = maxHTL;
        params.dropProb = dropProb;
        params.random = random;
        params.executor = executor;
        params.threadLimit = threadLimit;
        params.storeSize = storeSize;
        params.ramStore = ramStore;
        params.enableSwapping = enableSwapping;
        params.enableARKs = enableARKs;
        params.enableULPRs = enableULPRs;
        params.enablePerNodeFailureTables = enablePerNodeFailureTables;
        params.enableSwapQueueing = enableSwapQueueing;
        params.enablePacketCoalescing = enablePacketCoalescing;
        params.outputBandwidthLimit = outputBandwidthLimit;
        params.enableFOAF = enableFOAF;
        params.connectToSeednodes = connectToSeednodes;
        params.longPingTimes = longPingTimes;
        params.useSlashdotCache = useSlashdotCache;
        params.ipAddressOverride = ipAddressOverride;
        params.enableFCP = enableFCP;
            
        return createTestNode(params);
    }

    /**
	 * Create a test node.
	 * @throws NodeInitException If the node cannot start up for some reason, most
	 * likely a config problem.
	 */
    public static Node createTestNode(TestNodeParameters params) throws NodeInitException {
		
		synchronized(NodeStarter.class) {
			if((!isStarted) || (!isTestingVM)) 
				throw new IllegalStateException("Call globalTestInit() first!"); 
		}

        File baseDir = params.baseDirectory;
        File portDir = new File(baseDir, Integer.toString(params.port));
		if((!portDir.mkdir()) && ((!portDir.exists()) || (!portDir.isDirectory()))) {
			System.err.println("Cannot create directory for test");
			System.exit(NodeInitException.EXIT_TEST_ERROR);
		}

		// Set up config for testing
		SimpleFieldSet configFS = new SimpleFieldSet(false); // only happens once in entire simulation
        if(params.outputBandwidthLimit > 0) {
            configFS.put("node.outputBandwidthLimit", params.outputBandwidthLimit);
			configFS.put("node.throttleLocalTraffic", true);
		} else {
			// Even with throttleLocalTraffic=false, requests still count in NodeStats.
			// So set outputBandwidthLimit to something insanely high.
			configFS.put("node.outputBandwidthLimit", 16 * 1024 * 1024);
			configFS.put("node.throttleLocalTraffic", false);
		}
        configFS.put("node.useSlashdotCache", params.useSlashdotCache);
        configFS.put("node.listenPort", params.port);
        configFS.put("node.disableProbabilisticHTLs", params.disableProbabilisticHTLs);
		configFS.put("fproxy.enabled", false);
        configFS.put("fcp.enabled", params.enableFCP);
		configFS.put("fcp.port", 9481);
		configFS.put("fcp.ssl", false);
		configFS.put("pluginmanager.enabled", params.enablePlugins);
		configFS.put("console.enabled", false);
		configFS.putSingle("pluginmanager.loadplugin", "");
		configFS.put("node.updater.enabled", false);
		configFS.putSingle("node.install.tempDir", new File(portDir, "temp").toString());
		configFS.putSingle("node.install.storeDir", new File(portDir, "store").toString());
		configFS.put("fcp.persistentDownloadsEnabled", false);
		configFS.putSingle("node.throttleFile", new File(portDir, "throttle.dat").toString());
		configFS.putSingle("node.install.nodeDir", portDir.toString());
		configFS.putSingle("node.install.userDir", portDir.toString());
		configFS.putSingle("node.install.runDir", portDir.toString());
		configFS.putSingle("node.install.cfgDir", portDir.toString());
        configFS.put("node.maxHTL", params.maxHTL);
        configFS.put("node.testingDropPacketsEvery", params.dropProb);
		configFS.put("node.alwaysAllowLocalAddresses", true);
		configFS.put("node.includeLocalAddressesInNoderefs", true);
		configFS.put("node.enableARKs", false);
        configFS.put("node.load.threadLimit", params.threadLimit);
        if(params.ramStore)
			configFS.putSingle("node.storeType", "ram");
        configFS.put("node.storeSize", params.storeSize);
		configFS.put("node.disableHangCheckers", true);
        configFS.put("node.enableSwapping", params.enableSwapping);
        configFS.put("node.enableSwapQueueing", params.enableSwapQueueing);
        configFS.put("node.enableARKs", params.enableARKs);
        configFS.put("node.enableULPRDataPropagation", params.enableULPRs);
        configFS.put("node.enablePerNodeFailureTables", params.enablePerNodeFailureTables);
        configFS.put("node.enablePacketCoalescing", params.enablePacketCoalescing);
        configFS.put("node.publishOurPeersLocation", params.enableFOAF);
        configFS.put("node.routeAccordingToOurPeersLocation", params.enableFOAF);
        configFS.put("node.opennet.enabled", params.opennetPort > 0);
        configFS.put("node.opennet.listenPort", params.opennetPort);
		configFS.put("node.opennet.alwaysAllowLocalAddresses", true);
		configFS.put("node.opennet.oneConnectionPerIP", false);
		configFS.put("node.opennet.assumeNATed", true);
        configFS.put("node.opennet.connectToSeednodes", params.connectToSeednodes);
		configFS.put("node.encryptTempBuckets", false);
		configFS.put("node.encryptPersistentTempBuckets", false);
		configFS.put("node.enableRoutedPing", true);
        if(params.ipAddressOverride != null)
            configFS.putSingle("node.ipAddressOverride", params.ipAddressOverride);
        if(params.longPingTimes) {
			configFS.put("node.maxPingTime", 100000);
			configFS.put("node.subMaxPingTime", 50000);
		}
		configFS.put("node.respondBandwidth", true);
		configFS.put("node.respondBuild", true);
		configFS.put("node.respondIdentifier", true);
		configFS.put("node.respondLinkLengths", true);
		configFS.put("node.respondLocation", true);
		configFS.put("node.respondStoreSize", true);
		configFS.put("node.respondUptime", true);

		PersistentConfig config = new PersistentConfig(configFS);

        Node node = new Node(config, params.random, params.random, null, null, params.executor);

		//All testing environments connect the nodes as they want, even if the old setup is restored, it is not desired.
		node.peers.removeAllPeers();

		return node;
	}

	// experimental osgi support
	public static void start_osgi(String[] args) {
		nodestarter_osgi = new NodeStarter();
		nodestarter_osgi.start(args);
	}

	// experimental osgi support
	public static void stop_osgi(int exitCode) {
		nodestarter_osgi.stop(exitCode);
		nodestarter_osgi = null;
	}

	/** Get the memory limit in MB. Return -1 if we don't know, -2 for unlimited. */
	public static long getMemoryLimitMB() {
		long limit = getMemoryLimitBytes();
		if(limit <= 0) return limit;
		if(limit == Long.MAX_VALUE) return -2;
		limit /= (1024 * 1024);
		if(limit > Integer.MAX_VALUE)
			return -1; // Seems unlikely. FIXME 2TB limit!
		return limit;
	}
	
	/** Get the memory limit in bytes. Return -1 if we don't know. Compensate for odd JVMs' 
	 * behaviour. */
	public static long getMemoryLimitBytes() {
		long maxMemory = Runtime.getRuntime().maxMemory();
		if(maxMemory == Long.MAX_VALUE)
			return maxMemory;
		else if(maxMemory <= 0)
			return -1;
		else {
			if(maxMemory < (1024 * 1024)) {
				// Some weird buggy JVMs provide this number in MB IIRC?
				return maxMemory * 1024 * 1024;
			}
			return maxMemory;
		}
	}

	/** check whether the OS, JVM and wrapper are 64bits
	 * On Windows this will be always true (the wrapper we deploy is 32bits)
	 */
	public final static boolean isSomething32bits() {
		Properties wrapperProperties = WrapperManager.getProperties();
		return !JVMVersion.is32Bit() && !wrapperProperties.getProperty("wrapper.java.additional.auto_bits").startsWith("32");
	}
	
	/** Static instance of SecureRandom, as opposed to Node's copy. @see getSecureRandom() */
    private static SecureRandom globalSecureRandom;
	
	public static synchronized SecureRandom getGlobalSecureRandom() {
	    if(globalSecureRandom == null) {
	        globalSecureRandom = new SecureRandom();
	        globalSecureRandom.nextBytes(new byte[16]); // Force it to seed itself so it blocks now not later.
	    }
	    return globalSecureRandom;
	}

}
