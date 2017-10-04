/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.WeakHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

import org.tanukisoftware.wrapper.WrapperManager;

import freenet.client.ClientMetadata;
import freenet.client.DefaultMIMETypes;
import freenet.client.FetchContext;
import freenet.client.FetchResult;
import freenet.client.async.CacheFetchResult;
import freenet.client.async.ClientContext;
import freenet.client.async.DownloadCache;
import freenet.client.async.PersistenceDisabledException;
import freenet.client.async.PersistentJob;
import freenet.clients.fcp.ClientGet.ReturnType;
import freenet.clients.fcp.ClientRequest.Persistence;
import freenet.clients.fcp.FCPPluginConnection.SendDirection;
import freenet.config.Config;
import freenet.config.InvalidConfigValueException;
import freenet.config.SubConfig;
import freenet.crypt.SSL;
import freenet.io.AllowedHosts;
import freenet.io.NetworkInterface;
import freenet.io.SSLNetworkInterface;
import freenet.keys.FreenetURI;
import freenet.l10n.NodeL10n;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.RequestStarter;
import freenet.pluginmanager.FredPluginFCPMessageHandler;
import freenet.pluginmanager.FredPluginFCPMessageHandler.ClientSideFCPMessageHandler;
import freenet.pluginmanager.PluginNotFoundException;
import freenet.pluginmanager.PluginRespirator;
import freenet.support.Base64;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.BooleanCallback;
import freenet.support.api.Bucket;
import freenet.support.api.IntCallback;
import freenet.support.api.StringCallback;
import freenet.support.io.BucketTools;
import freenet.support.io.NativeThread;
import freenet.support.io.NoFreeBucket;

/**
 * FCP server process.
 */
public class FCPServer implements Runnable, DownloadCache {

	private final PersistentRequestRoot persistentRoot;
	private static boolean logMINOR;
	public final static int DEFAULT_FCP_PORT = 9481;
	NetworkInterface networkInterface;
	public final NodeClientCore core;
	final Node node;
	final int port;
	private static boolean ssl = false;
	public final boolean enabled;
	String bindTo;
	private String allowedHosts;
	AllowedHosts allowedHostsFullAccess;
    /** Stores {@link FCPPluginConnectionImpl} objects by ID and automatically garbage collects them
     *  so we don't have to bloat this class with that. */
	final FCPPluginConnectionTracker pluginConnectionTracker;
	final WeakHashMap<String, PersistentRequestClient> rebootClientsByName;
	final PersistentRequestClient globalRebootClient;
	PersistentRequestClient globalForeverClient;
	public static final int QUEUE_MAX_RETRIES = -1;
	public static final long QUEUE_MAX_DATA_SIZE = Long.MAX_VALUE;
	private boolean assumeDownloadDDAIsAllowed;
	private boolean assumeUploadDDAIsAllowed;
	private boolean neverDropAMessage;
	private int maxMessageQueueLength;

	public FCPServer(String ipToBindTo, String allowedHosts, String allowedHostsFullAccess, int port, Node node, NodeClientCore core, boolean isEnabled, boolean assumeDDADownloadAllowed, boolean assumeDDAUploadAllowed, boolean neverDropAMessage, int maxMessageQueueLength, PersistentRequestRoot persistentRoot) throws IOException, InvalidConfigValueException {
		this.bindTo = ipToBindTo;
		this.allowedHosts=allowedHosts;
		this.allowedHostsFullAccess = new AllowedHosts(allowedHostsFullAccess);
		this.port = port;
		this.enabled = isEnabled;
		this.node = node;
		this.core = core;
		this.assumeDownloadDDAIsAllowed = assumeDDADownloadAllowed;
		this.assumeUploadDDAIsAllowed = assumeDDAUploadAllowed;
		this.neverDropAMessage = neverDropAMessage;
		this.maxMessageQueueLength = maxMessageQueueLength;
		rebootClientsByName = new WeakHashMap<String, PersistentRequestClient>();
		this.persistentRoot = persistentRoot;
        globalForeverClient = persistentRoot.globalForeverClient;

        pluginConnectionTracker = new FCPPluginConnectionTracker();
        // pluginConnectionTracker.start() is called in maybeStart()


		globalRebootClient = new PersistentRequestClient("Global Queue", null, true, null, Persistence.REBOOT, null);

		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);

	}

	public void load() {
	    globalForeverClient.updateRequestStatusCache();
	}

	private void maybeGetNetworkInterface() {
		if (this.networkInterface!=null) return;

		NetworkInterface tempNetworkInterface = null;
		try {
			if(ssl) {
				tempNetworkInterface = SSLNetworkInterface.create(port, bindTo, allowedHosts, node.executor, true);
			} else {
				tempNetworkInterface = NetworkInterface.create(port, bindTo, allowedHosts, node.executor, true);
			}
		} catch (IOException be) {
			Logger.error(this, "Couldn't bind to FCP Port "+bindTo+ ':' +port+". FCP Server not started.", be);
			System.out.println("Couldn't bind to FCP Port "+bindTo+ ':' +port+". FCP Server not started.");
		}

		this.networkInterface = tempNetworkInterface;

	}

	public void maybeStart() {
		if (this.enabled) {
			maybeGetNetworkInterface();

			Logger.normal(this, "Starting FCP server on "+bindTo+ ':' +port+ '.');
			System.out.println("Starting FCP server on "+bindTo+ ':' +port+ '.');

			if (this.networkInterface != null) {
				Thread t = new Thread(this, "FCP server");
				t.setDaemon(true);
				t.start();
			}
		} else {
			Logger.normal(this, "Not starting FCP server as it's disabled");
			System.out.println("Not starting FCP server as it's disabled");
			this.networkInterface = null;
		}
		
		if(node.pluginManager.isEnabled()) {
		    // We need to start the FCPPluginConnectionTracker no matter whether this.enabled == true:
		    // If networked FCP is disabled, plugins might still communicate via non-networked
		    // intra-node FCP.
		    pluginConnectionTracker.start();
		}
	}

	@Override
	public void run() {
	    freenet.support.Logger.OSThread.logPID(this);
		while(true) {
			try {
				networkInterface.waitBound();
				realRun();
			} catch (IOException e) {
				if(logMINOR) Logger.minor(this, "Caught "+e, e);
			} catch (Throwable t) {
				Logger.error(this, "Caught "+t, t);
			}
			if (WrapperManager.hasShutdownHookBeenTriggered())
				return;
			try{
				Thread.sleep(2000);
			}catch (InterruptedException e) {}
		}
	}

	private void realRun() throws IOException {
		if(!node.isHasStarted()) return;
		// Accept a connection
		Socket s = networkInterface.accept();
		FCPConnectionHandler ch = new FCPConnectionHandler(s, this);
		ch.start();
	}

	static class FCPPortNumberCallback extends IntCallback  {

		private final NodeClientCore node;

		FCPPortNumberCallback(NodeClientCore node) {
			this.node = node;
		}

		@Override
		public Integer get() {
			return node.getFCPServer().port;
		}

		@Override
		public void set(Integer val) throws InvalidConfigValueException {
			if (!get().equals(val)) {
				throw new InvalidConfigValueException("Cannot change FCP port number on the fly");
			}
		}

		@Override
		public boolean isReadOnly() {
			return true;
		}
	}

	static class FCPEnabledCallback extends BooleanCallback {

		final NodeClientCore node;

		FCPEnabledCallback(NodeClientCore node) {
			this.node = node;
		}

		@Override
		public Boolean get() {
			return node.getFCPServer().enabled;
		}
//TODO: Allow it
		@Override
		public void set(Boolean val) throws InvalidConfigValueException {
			if (!get().equals(val)) {
				throw new InvalidConfigValueException(l10n("cannotStartOrStopOnTheFly"));
			}
		}

		@Override
		public boolean isReadOnly() {
			return true;
		}
	}

	static class FCPSSLCallback extends BooleanCallback {

		@Override
		public Boolean get() {
			return ssl;
		}

		@Override
		public void set(Boolean val) throws InvalidConfigValueException {
			if (get().equals(val))
				return;
			if(!SSL.available()) {
				throw new InvalidConfigValueException("Enable SSL support before use ssl with FCP");
			}
			ssl = val;
			throw new InvalidConfigValueException("Cannot change SSL on the fly, please restart freenet");
		}

		@Override
		public boolean isReadOnly() {
			return true;
		}
	}

	// FIXME: Consider moving everything except enabled into constructor
	// Actually we could move enabled in too with an exception???

	static class FCPBindtoCallback extends StringCallback {

		final NodeClientCore node;

		FCPBindtoCallback(NodeClientCore node) {
			this.node = node;
		}

		@Override
		public String get() {
			return node.getFCPServer().bindTo;
		}

		@Override
		public void set(String val) throws InvalidConfigValueException {
			String oldValue = get();
			if(!val.equals(oldValue)) {
				FCPServer server = node.getFCPServer();
				
				String[] failedAddresses = server.networkInterface.setBindTo(val, true);
				if(failedAddresses != null) {
					// This is an advanced option for reasons of reducing clutter,
					// but it is expected to be used by regular users, not devs.
					// So we translate the error messages.
					server.networkInterface.setBindTo(oldValue, true);
					throw new InvalidConfigValueException(l10n("couldNotChangeBindTo", "failedInterfaces", Arrays.toString(failedAddresses)));
				}
				
				server.networkInterface.setBindTo(val, true);
				server.bindTo = val;
				
				synchronized(server.networkInterface) {
					server.networkInterface.notifyAll();
				}
			}
		}
	}

	static class FCPAllowedHostsCallback extends StringCallback  {

		private final NodeClientCore node;

		public FCPAllowedHostsCallback(NodeClientCore node) {
			this.node = node;
		}

		@Override
		public String get() {
			FCPServer server = node.getFCPServer();
			if(server == null) return NetworkInterface.DEFAULT_BIND_TO;
			NetworkInterface netIface = server.networkInterface;
			return (netIface == null ? NetworkInterface.DEFAULT_BIND_TO : netIface.getAllowedHosts());
		}

		@Override
		public void set(String val) throws InvalidConfigValueException {
			if (!val.equals(get())) {
				try {
				node.getFCPServer().networkInterface.setAllowedHosts(val);
				} catch(IllegalArgumentException e) {
					throw new InvalidConfigValueException(e);
				}
			}
		}
	}

	static class FCPAllowedHostsFullAccessCallback extends StringCallback  {
		private final NodeClientCore node;

		public FCPAllowedHostsFullAccessCallback(NodeClientCore node) {
			this.node = node;
		}

		@Override
		public String get() {
			return node.getFCPServer().allowedHostsFullAccess.getAllowedHosts();
		}

		@Override
		public void set(String val) throws InvalidConfigValueException {
			if (!val.equals(get())) {
				try {
				node.getFCPServer().allowedHostsFullAccess.setAllowedHosts(val);
				} catch(IllegalArgumentException e) {
					throw new InvalidConfigValueException(e);
				}
			}
		}

	}
	static class AssumeDDADownloadIsAllowedCallback extends BooleanCallback {
		FCPServer server;

		@Override
		public Boolean get() {
			return server.assumeDownloadDDAIsAllowed;
		}

		@Override
		public void set(Boolean val) throws InvalidConfigValueException {
			if (get().equals(val))
				return;
			server.assumeDownloadDDAIsAllowed = val;
		}
	}

	static class AssumeDDAUploadIsAllowedCallback extends BooleanCallback {
		FCPServer server;

		@Override
		public Boolean get() {
			return server.assumeUploadDDAIsAllowed;
		}

		@Override
		public void set(Boolean val) throws InvalidConfigValueException {
			if (get().equals(val))
				return;
			server.assumeUploadDDAIsAllowed = val;
		}
	}

	static class NeverDropAMessageCallback extends BooleanCallback {
		FCPServer server;

		@Override
		public Boolean get() {
			return server.neverDropAMessage;
		}

		@Override
		public void set(Boolean val) throws InvalidConfigValueException {
			if (get().equals(val))
				return;
			server.neverDropAMessage = val;
		}
	}

	static class MaxMessageQueueLengthCallback extends IntCallback {
		FCPServer server;

		@Override
		public Integer get() {
			return server.maxMessageQueueLength;
		}

		@Override
		public void set(Integer val) throws InvalidConfigValueException {
			if(get().equals(val))
				return;
			server.maxMessageQueueLength = val;
		}
	}


	public static FCPServer maybeCreate(Node node, NodeClientCore core, Config config, PersistentRequestRoot root) throws IOException, InvalidConfigValueException {
		SubConfig fcpConfig = config.createSubConfig("fcp");
		short sortOrder = 0;
		fcpConfig.register("enabled", true, sortOrder++, true, false, "FcpServer.isEnabled", "FcpServer.isEnabledLong", new FCPEnabledCallback(core));
		fcpConfig.register("ssl", false, sortOrder++, true, true, "FcpServer.ssl", "FcpServer.sslLong", new FCPSSLCallback());
		fcpConfig.register("port", FCPServer.DEFAULT_FCP_PORT /* anagram of 1984, and 1000 up from old number */, 2, true, true, "FcpServer.portNumber", "FcpServer.portNumberLong", new FCPPortNumberCallback(core), false);
		fcpConfig.register("bindTo", NetworkInterface.DEFAULT_BIND_TO, sortOrder++, true, true, "FcpServer.bindTo", "FcpServer.bindToLong", new FCPBindtoCallback(core));
		fcpConfig.register("allowedHosts", NetworkInterface.DEFAULT_BIND_TO, sortOrder++, true, true, "FcpServer.allowedHosts", "FcpServer.allowedHostsLong", new FCPAllowedHostsCallback(core));
		fcpConfig.register("allowedHostsFullAccess", NetworkInterface.DEFAULT_BIND_TO, sortOrder++, true, true, "FcpServer.allowedHostsFullAccess", "FcpServer.allowedHostsFullAccessLong", new FCPAllowedHostsFullAccessCallback(core));

		AssumeDDADownloadIsAllowedCallback cb4;
		AssumeDDAUploadIsAllowedCallback cb5;
		NeverDropAMessageCallback cb6;
		MaxMessageQueueLengthCallback cb7;
		fcpConfig.register("assumeDownloadDDAIsAllowed", false, sortOrder++, true, false, "FcpServer.assumeDownloadDDAIsAllowed", "FcpServer.assumeDownloadDDAIsAllowedLong", cb4 = new AssumeDDADownloadIsAllowedCallback());
		fcpConfig.register("assumeUploadDDAIsAllowed", false, sortOrder++, true, false, "FcpServer.assumeUploadDDAIsAllowed", "FcpServer.assumeUploadDDAIsAllowedLong", cb5 = new AssumeDDAUploadIsAllowedCallback());
		fcpConfig.register("maxMessageQueueLength", 1024, sortOrder++, true, false, "FcpServer.maxMessageQueueLength", "FcpServer.maxMessageQueueLengthLong", cb7 = new MaxMessageQueueLengthCallback(), false);
		fcpConfig.register("neverDropAMessage", false, sortOrder++, true, false, "FcpServer.neverDropAMessage", "FcpServer.neverDropAMessageLong", cb6 = new NeverDropAMessageCallback());

		if(SSL.available()) {
			ssl = fcpConfig.getBoolean("ssl");
		}

		FCPServer fcp = new FCPServer(fcpConfig.getString("bindTo"), fcpConfig.getString("allowedHosts"), fcpConfig.getString("allowedHostsFullAccess"), fcpConfig.getInt("port"), node, core, fcpConfig.getBoolean("enabled"), fcpConfig.getBoolean("assumeDownloadDDAIsAllowed"), fcpConfig.getBoolean("assumeUploadDDAIsAllowed"), fcpConfig.getBoolean("neverDropAMessage"), fcpConfig.getInt("maxMessageQueueLength"), root);

		if(fcp != null) {
			cb4.server = fcp;
			cb5.server = fcp;
			cb6.server = fcp;
			cb7.server = fcp;
		}

		fcpConfig.finishedInitialization();
		return fcp;
	}

	public boolean neverDropAMessage() {
		return neverDropAMessage;
	}

	public int maxMessageQueueLength() {
		return maxMessageQueueLength;
	}

	private static String l10n(String key) {
		return NodeL10n.getBase().getString("FcpServer."+key);
	}

	private static String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("FcpServer."+key, pattern, value);
	}

    /**
     * <p>Creates and registers a {@link FCPPluginConnectionImpl} object for a FCP connection which
     * is attached by network.<br/>
     * In other words, the actual client application is NOT a plugin running within the node, it
     * only connected to the node via network.</p>
     * 
     * <p>The object is registered at the backend {@link FCPPluginConnectionTracker} and thus can be
     * queried from this server by ID via the frontend {@link #getPluginConnectionByID(UUID)} as
     * long as something else keeps a strong reference to it.<br/>
     * Once it becomes weakly reachable, it will be garbage-collected from the backend
     * {@link FCPPluginConnectionTracker} and {@link #getPluginConnectionByID(UUID)} will not
     * return it anymore.
     * <br>In other words, you don't have to take care of registering or unregistering connections.
     * You only have to take care of keeping a strong reference to them while they are in use.</p>
     * 
     * <p>ATTENTION: Only for internal use by the frontend function
     * {@link FCPConnectionHandler#getFCPPluginConnection(String)}.</p>
     * 
     * @see FCPPluginConnectionImpl
     *     The class JavaDoc of FCPPluginConnectionImpl explains the code path for both
     *     networked and non-networked FCP.
     */
    final FCPPluginConnectionImpl createFCPPluginConnectionForNetworkedFCP(String serverPluginName,
        FCPConnectionHandler messageHandler)
            throws PluginNotFoundException {
        
        FCPPluginConnectionImpl connection = FCPPluginConnectionImpl.constructForNetworkedFCP(
            pluginConnectionTracker, node.executor, node.pluginManager,
            serverPluginName, messageHandler);
        // The constructor function already did this for us
        /* pluginConnectionTracker.registerConnection(connection); */
        return connection;
    }

    /**
     * <p>Creates and registers a {@link FCPPluginConnection} object for FCP connections between
     * plugins running within the same node.<br/>
     * In other words, the actual client application is NOT connected to the node by network, it is
     * a plugin running within the node just like the server.</p>
     * 
     * <p>The object is registered at the backend {@link FCPPluginConnectionTracker} and thus can be
     * queried from this server by ID via the frontend {@link #getPluginConnectionByID(UUID)} as
     * long as something else keeps a strong reference to it.<br>
     * Once it becomes weakly reachable, it will be garbage-collected from the backend
     * {@link FCPPluginConnectionTracker} and {@link #getPluginConnectionByID(UUID)} will not
     * return it anymore.
     * <br>In other words, you don't have to take care of registering or unregistering connections.
     * You only have to take care of keeping a strong reference to them while they are in use.</p>
     * 
     * <p>ATTENTION: Only for internal use by the frontend function
     * {@link PluginRespirator#connectToOtherPlugin(String,
     * FredPluginFCPMessageHandler.ClientSideFCPMessageHandler)}. Plugins must use that instead.</p>
     * 
     * ATTENTION: Since this function is only to be used by the aforementioned connectToPlugin()
     * which in turn is only to be used by clients, the returned connection will have a default send
     * direction of {@link SendDirection#ToServer}.
     * 
     * @see FCPPluginConnectionImpl
     *     The class JavaDoc of FCPPluginConnectionImpl explains the code path for both networked
     *     and non-networked FCP.
     */
    public final FCPPluginConnection createFCPPluginConnectionForIntraNodeFCP(
            String serverPluginName, ClientSideFCPMessageHandler messageHandler)
                throws PluginNotFoundException {
        
        FCPPluginConnectionImpl connection = FCPPluginConnectionImpl.constructForIntraNodeFCP(
            pluginConnectionTracker, node.executor, node.pluginManager,
            serverPluginName, messageHandler);
        // The constructor function already did this for us
        /* pluginConnectionTracker.registerConnection(connection); */
        return connection.getDefaultSendDirectionAdapter(SendDirection.ToServer);
    }

    /**
     * <p><b>The documentation of {@link FCPPluginConnectionTracker#getConnection(UUID)} applies to
     * this function.</b></p>
     * 
     * ATTENTION: Only for internal use by the frontend function
     * {@link PluginRespirator#getPluginConnectionByID(UUID)}. Plugins must use that instead.<br>
     * <br>
     * 
     * ATTENTION: Since this function is only to be used by the aforementioned
     * getPluginConnectionByID() which in turn is only to be used by servers, the returned
     * connection will have a default send direction of {@link SendDirection#ToClient}.
     * 
     * @see FCPPluginConnectionTracker
     *     The JavaDoc of FCPPluginConnectionTracker explains the general purpose of this mechanism.
     */
    public final FCPPluginConnection getPluginConnectionByID(UUID connectionID) throws IOException {
        return pluginConnectionTracker.getConnection(connectionID)
                                      .getDefaultSendDirectionAdapter(SendDirection.ToClient);
    }

	public PersistentRequestClient registerRebootClient(String name, FCPConnectionHandler handler) {
		PersistentRequestClient oldClient;
		synchronized(this) {
			oldClient = rebootClientsByName.get(name);
			if(oldClient == null) {
				// Create new client
				PersistentRequestClient client = new PersistentRequestClient(name, handler, false, null, Persistence.REBOOT, null);
				rebootClientsByName.put(name, client);
				return client;
			} else {
				FCPConnectionHandler oldConn = oldClient.getConnection();
				// Have existing client
				if(oldConn == null) {
					// Easy
					oldClient.setConnection(handler);
					return oldClient;
				} else {
					// Kill old connection
					oldConn.setKilledDupe();
					oldConn.outputHandler.queue(new CloseConnectionDuplicateClientNameMessage());
					oldConn.close();
					oldClient.setConnection(handler);
					return oldClient;
				}
			}
		}
	}

	public PersistentRequestClient registerForeverClient(String name, FCPConnectionHandler handler) {
		return persistentRoot.registerForeverClient(name, handler);
	}

    public PersistentRequestClient getForeverClient(String name, FCPConnectionHandler handler) {
        return persistentRoot.getForeverClient(name, handler);
    }

	public void unregisterClient(PersistentRequestClient client) {
		if(client.persistence == Persistence.REBOOT) {
		synchronized(this) {
			String name = client.name;
			rebootClientsByName.remove(name);
		}
		} else {
			persistentRoot.maybeUnregisterClient(client);
		}
	}

	public RequestStatus[] getGlobalRequests() throws PersistenceDisabledException {
		if(core.killedDatabase()) throw new PersistenceDisabledException();
		List<RequestStatus> v = new ArrayList<RequestStatus>();
		globalRebootClient.addPersistentRequestStatus(v);
		if(globalForeverClient != null)
			globalForeverClient.addPersistentRequestStatus(v);
		return v.toArray(new RequestStatus[v.size()]);
	}

	public boolean removeGlobalRequestBlocking(final String identifier) throws MessageInvalidException, PersistenceDisabledException {
		if(!globalRebootClient.removeByIdentifier(identifier, true, core.clientContext)) {
			final CountDownLatch done = new CountDownLatch(1);
			final AtomicBoolean success = new AtomicBoolean();
			core.clientContext.jobRunner.queue(new PersistentJob() {

				@Override
				public String toString() {
					return "FCP removeGlobalRequestBlocking";
				}

				@Override
				public boolean run(ClientContext context) {
					boolean succeeded = false;
					try {
						succeeded = globalForeverClient.removeByIdentifier(identifier, true, core.clientContext);
					} catch (Throwable t) {
						Logger.error(this, "Caught removing identifier "+identifier+": "+t, t);
					} finally {
						success.set(succeeded);
						done.countDown();
					}
					return true;
				}

			}, NativeThread.HIGH_PRIORITY);
			while (done.getCount() > 0) {
				try {
					done.await();
				} catch (InterruptedException e) {
					// Ignore
				}
			}
			return success.get();
		} else return true;
	}

	public boolean removeAllGlobalRequestsBlocking() throws PersistenceDisabledException {
		globalRebootClient.removeAll();
		final CountDownLatch done = new CountDownLatch(1);
		final AtomicBoolean success = new AtomicBoolean();
		core.clientContext.jobRunner.queue(new PersistentJob() {

			@Override
			public String toString() {
				return "FCP removeAllGlobalRequestsBlocking";
			}

			@Override
			public boolean run(ClientContext context) {
				boolean succeeded = false;
				try {
					globalForeverClient.removeAll();
					succeeded = true;
				} catch (Throwable t) {
					Logger.error(this, "Caught while processing panic: "+t, t);
					System.err.println("PANIC INCOMPLETE: CAUGHT "+t);
					t.printStackTrace();
					System.err.println("Your requests have not been deleted!");
				} finally {
					success.set(succeeded);
					done.countDown();
				}
				return true;
			}

		}, NativeThread.HIGH_PRIORITY);
		while (done.getCount() > 0) {
			try {
				done.await();
			} catch (InterruptedException e) {
				// Ignore
			}
		}
		return success.get();
	}

	public void makePersistentGlobalRequestBlocking(final FreenetURI fetchURI, final boolean filterData,
	        final String expectedMimeType, final String persistenceTypeString, final String returnTypeString,
	        final boolean realTimeFlag, final File downloadsDir) throws NotAllowedException, IOException,
	        PersistenceDisabledException {
		class OutputWrapper {
			NotAllowedException ne;
			IOException ioe;
			boolean done;
		}

		final OutputWrapper ow = new OutputWrapper();
		core.clientContext.jobRunner.queue(new PersistentJob() {

			@Override
			public String toString() {
				return "FCP makePersistentGlobalRequestBlocking";
			}

			@Override
			public boolean run(ClientContext context) {
				NotAllowedException ne = null;
				IOException ioe = null;
				try {
					makePersistentGlobalRequest(fetchURI, filterData, expectedMimeType,
					        persistenceTypeString, returnTypeString, realTimeFlag, 
					        downloadsDir);
					return true;
				} catch (NotAllowedException e) {
					ne = e;
					return false;
				} catch (IOException e) {
					ioe = e;
					return false;
				} catch (Throwable t) {
					// Unexpected and severe, might even be OOM, just log it.
					Logger.error(this, "Failed to make persistent request: "+t, t);
					return false;
				} finally {
					synchronized(ow) {
						ow.ne = ne;
						ow.ioe = ioe;
						ow.done = true;
						ow.notifyAll();
					}
				}
			}

		}, NativeThread.HIGH_PRIORITY);

		synchronized(ow) {
			while(true) {
				if(!ow.done) {
					try {
						ow.wait();
					} catch (InterruptedException e) {
						// Ignore
					}
					continue;
				}
				if(ow.ioe != null) throw ow.ioe;
				if(ow.ne != null) throw ow.ne;
				return;
			}
		}
	}

	public boolean modifyGlobalRequestBlocking(final String identifier, final String newToken, final short newPriority) throws PersistenceDisabledException {
		ClientRequest req = this.globalRebootClient.getRequest(identifier);
		if(req != null) {
			req.modifyRequest(newToken, newPriority, this);
			return true;
		} else {
			class OutputWrapper {
				boolean success;
				boolean done;
			}
			final OutputWrapper ow = new OutputWrapper();
			core.clientContext.jobRunner.queue(new PersistentJob() {

				@Override
				public String toString() {
					return "FCP modifyGlobalRequestBlocking";
				}

				@Override
				public boolean run(ClientContext context) {
					boolean success = false;
					try {
						ClientRequest req = globalForeverClient.getRequest(identifier);
						if(req != null)
							req.modifyRequest(newToken, newPriority, FCPServer.this);
						success = true;
					} finally {
						synchronized(ow) {
							ow.success = success;
							ow.done = true;
							ow.notifyAll();
						}
					}
					return true;
				}

			}, NativeThread.HIGH_PRIORITY);

			synchronized(ow) {
				while(true) {
					if(!ow.done) {
						try {
							ow.wait();
						} catch (InterruptedException e) {
							// Ignore
						}
						continue;
					}
					return ow.success;
				}
			}
		}
	}

	public void makePersistentGlobalRequest(FreenetURI fetchURI, boolean filterData, String expectedMimeType, String persistenceTypeString, String returnTypeString, boolean realTimeFlag) throws NotAllowedException, IOException {
		makePersistentGlobalRequest(fetchURI, filterData, expectedMimeType, persistenceTypeString, returnTypeString, realTimeFlag, core.getDownloadsDir());
	}
	
	/**
	 * Create a persistent globally-queued request for a file.
	 * @param fetchURI The file to fetch.
	 * @param persistenceTypeString The persistence type.
	 * @param returnTypeString The return type.
	 * @param downloadsDir Target directory if downloading to disk. Must be valid!
	 * @throws NotAllowedException
	 * @throws IOException
	 */
	public void makePersistentGlobalRequest(FreenetURI fetchURI, boolean filterData, String expectedMimeType, String persistenceTypeString, String returnTypeString, boolean realTimeFlag, File downloadsDir) throws NotAllowedException, IOException {
		boolean persistence = persistenceTypeString.equalsIgnoreCase("reboot");
		ReturnType returnType = ReturnType.valueOf(returnTypeString.toUpperCase());
		File returnFilename = null;
		if(returnType == ReturnType.DISK) {
			returnFilename = makeReturnFilename(fetchURI, expectedMimeType, downloadsDir);
		}
//		public ClientGet(PersistentRequestClient globalClient, FreenetURI uri, boolean dsOnly, boolean ignoreDS,
//				int maxSplitfileRetries, int maxNonSplitfileRetries, long maxOutputLength,
//				short returnType, boolean persistRebootOnly, String identifier, int verbosity, short prioClass,
//				File returnFilename, File returnTempFilename) throws IdentifierCollisionException {

		try {
			innerMakePersistentGlobalRequest(fetchURI, filterData, persistence, returnType, "FProxy:"+fetchURI.getPreferredFilename(), returnFilename, realTimeFlag);
			return;
		} catch (IdentifierCollisionException ee) {
			try {
				innerMakePersistentGlobalRequest(fetchURI, filterData, persistence, returnType, "FProxy:"+fetchURI.getDocName(), returnFilename, realTimeFlag);
				return;
			} catch (IdentifierCollisionException e) {
				try {
					innerMakePersistentGlobalRequest(fetchURI, filterData, persistence, returnType, "FProxy:"+fetchURI.toString(false, false), returnFilename, realTimeFlag);
					return;
				} catch (IdentifierCollisionException e1) {
					// FIXME maybe use DateFormat
					try {
						innerMakePersistentGlobalRequest(fetchURI, filterData, persistence, returnType, "FProxy ("+System.currentTimeMillis()+ ')', returnFilename, realTimeFlag);
						return;
					} catch (IdentifierCollisionException e2) {
						while(true) {
							byte[] buf = new byte[8];
							try {
								core.random.nextBytes(buf);
								String id = "FProxy:"+Base64.encode(buf);
								innerMakePersistentGlobalRequest(fetchURI, filterData, persistence, returnType, id, returnFilename, realTimeFlag);
								return;
							} catch (IdentifierCollisionException e3) {}
						}
					}
				}
			}
		}
	}

	private File makeReturnFilename(FreenetURI uri, String expectedMimeType, File downloadsDir) {
		String ext;
		if((expectedMimeType != null) && (expectedMimeType.length() > 0) &&
				!expectedMimeType.equals(DefaultMIMETypes.DEFAULT_MIME_TYPE)) {
			ext = DefaultMIMETypes.getExtension(expectedMimeType);
		} else ext = null;
		String extAdd = (ext == null ? "" : '.' + ext);
		String preferred = uri.getPreferredFilename();
		String preferredWithExt = preferred;
		if(!(ext != null && preferredWithExt.endsWith(ext)))
			preferredWithExt += extAdd;
		File f = new File(downloadsDir, preferredWithExt);
		int x = 0;
		StringBuilder sb = new StringBuilder();
		for(;f.exists();sb.setLength(0)) {
			sb.append(preferred);
			sb.append('-');
			sb.append(x);
			sb.append(extAdd);
			f = new File(downloadsDir, sb.toString());
			x++;
		}
		return f;
	}

	private void innerMakePersistentGlobalRequest(FreenetURI fetchURI, boolean filterData, boolean persistRebootOnly, ReturnType returnType, String id, File returnFilename,
			boolean realTimeFlag) throws IdentifierCollisionException, NotAllowedException, IOException {
	    FetchContext defaultFetchContext = core.clientContext.getDefaultPersistentFetchContext();
		final ClientGet cg =
			new ClientGet(persistRebootOnly ? globalRebootClient : globalForeverClient, fetchURI, defaultFetchContext.localRequestOnly,
					defaultFetchContext.ignoreStore, filterData, QUEUE_MAX_RETRIES,
					QUEUE_MAX_RETRIES, QUEUE_MAX_DATA_SIZE, returnType, persistRebootOnly, id,
					Integer.MAX_VALUE, RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS, returnFilename, false, realTimeFlag, false, core);
		cg.register(false);
		cg.start(core.clientContext);
	}

	/**
	 * Returns the global FCP client.
	 *
	 * @return The global FCP client
	 */
	public PersistentRequestClient getGlobalForeverClient() {
		return globalForeverClient;
	}

	public ClientRequest getGlobalRequest(String identifier) {
		ClientRequest req = globalRebootClient.getRequest(identifier);
		if(req == null)
			req = globalForeverClient.getRequest(identifier);
		return req;
	}

	protected boolean isDownloadDDAAlwaysAllowed() {
		return assumeDownloadDDAIsAllowed;
	}

	protected boolean isUploadDDAAlwaysAllowed() {
		return assumeUploadDDAIsAllowed;
	}

	public void setCompletionCallback(RequestCompletionCallback cb) {
		if(globalForeverClient != null)
			globalForeverClient.addRequestCompletionCallback(cb);
		globalRebootClient.addRequestCompletionCallback(cb);
	}

	/** Start a request on the global queue. Return after it has started, 
	 * e.g. it will show up on the queue page, it will persist after 
	 * restart etc. Actually it won't persist until the next commit, but 
	 * it's close...
	 * @param req The request (insert etc) to start.
	 * @param container The database handle. This method must be called on a DBJob.
	 * @throws IdentifierCollisionException If there is already a request with that identifier.
	 * @throws DatabaseDisabledException If the database is disabled/broken/turned off, 
	 * if we are shutting down, if we are waiting for the user to give us the decryption 
	 * password etc.
	 */
	public void startBlocking(final ClientRequest req) throws IdentifierCollisionException, PersistenceDisabledException {
		if(req.persistence == Persistence.REBOOT) {
			req.start(core.clientContext);
		} else {
			class OutputWrapper {
				boolean done;
				IdentifierCollisionException collided;
			}
			final OutputWrapper ow = new OutputWrapper();
			core.clientContext.jobRunner.queue(new PersistentJob() {

				@Override
				public String toString() {
					return "FCP startBlocking";
				}

				@Override
				public boolean run(ClientContext context) {
					// Don't activate, it may not be stored yet.
					try {
						req.register(false);
						req.start(context);
					} catch (IdentifierCollisionException e) {
						ow.collided = e;
					} finally {
						synchronized(ow) {
							ow.done = true;
							ow.notifyAll();
						}
					}
					return true;
				}

			}, NativeThread.HIGH_PRIORITY);

			synchronized(ow) {
				while(true) {
					if(!ow.done) {
						try {
							ow.wait();
						} catch (InterruptedException e) {
							// Ignore
						}
					} else {
						if(ow.collided != null)
							throw ow.collided;
						return;
					}
				}
			}
		}
	}

	public boolean restartBlocking(final String identifier, final boolean disableFilterData) throws PersistenceDisabledException {
		ClientRequest req = globalRebootClient.getRequest(identifier);
		if(req != null) {
			req.restart(core.clientContext, disableFilterData);
			return true;
		} else {
			class OutputWrapper {
				boolean done;
				boolean success;
			}
			final OutputWrapper ow = new OutputWrapper();
            if(logMINOR) Logger.minor(this, "Queueing restart of "+identifier);
			core.clientContext.jobRunner.queue(new PersistentJob() {

				@Override
				public String toString() {
					return "FCP restartBlocking";
				}

				@Override
				public boolean run(ClientContext context) {
					boolean success = false;
					try {
						ClientRequest req = globalForeverClient.getRequest(identifier);
	                    if(logMINOR) Logger.minor(this, "Restarting "+req+" for "+identifier);
						if(req != null) {
							req.restart(context, disableFilterData);
							success = true;
						}
					} catch (PersistenceDisabledException e) {
						success = false;
					} finally {
						synchronized(ow) {
							ow.success = success;
							ow.done = true;
							ow.notifyAll();
						}
					}
					return true;
				}

			}, NativeThread.HIGH_PRIORITY);

			synchronized(ow) {
				while(true) {
					if(ow.done) return ow.success;
					try {
						ow.wait();
					} catch (InterruptedException e) {
						// Ignore
					}
				}
			}
		}
	}



	public FetchResult getCompletedRequestBlocking(final FreenetURI key) throws PersistenceDisabledException {
		ClientGet get = globalRebootClient.getCompletedRequest(key);
		if(get != null) {
			// FIXME race condition with free() - arrange refcounting for the data to prevent this
			return new FetchResult(new ClientMetadata(get.getMIMEType()), new NoFreeBucket(get.getBucket()));
		}

		FetchResult result = globalForeverClient.getRequestStatusCache().getShadowBucket(key, false);
		if(result != null) {
			return result;
		}

		class OutputWrapper {
			FetchResult result;
			boolean done;
		}

		final OutputWrapper ow = new OutputWrapper();

		core.clientContext.jobRunner.queue(new PersistentJob() {

			@Override
			public String toString() {
				return "FCP getCompletedRequestBlocking";
			}

			@Override
			public boolean run(ClientContext context) {
				FetchResult result = null;
				try {
					result = lookup(key, false, null);
				} finally {
					synchronized(ow) {
						ow.result = result;
						ow.done = true;
						ow.notifyAll();
					}
				}
				return false;
			}

		}, NativeThread.HIGH_PRIORITY);

		synchronized(ow) {
			while(true) {
				if(ow.done) {
					return ow.result;
				} else {
					try {
						ow.wait();
					} catch (InterruptedException e) {
						// Ignore
					}
				}
			}
		}
	}

	@Override
	public CacheFetchResult lookupInstant(FreenetURI key, boolean noFilter, boolean mustCopy, Bucket preferred) {
		ClientGet get = globalRebootClient.getCompletedRequest(key);

		Bucket origData = null;
		String mime = null;
		boolean filtered = false;

		if(get != null && ((!noFilter) || (!(filtered = get.filterData())))) {
			origData = new NoFreeBucket(get.getBucket());
			mime = get.getMIMEType();
		}

		if(origData == null && globalForeverClient != null) {
			CacheFetchResult result = globalForeverClient.getRequestStatusCache().getShadowBucket(key, noFilter);
			if(result != null) {
				mime = result.getMimeType();
				origData = result.asBucket();
				filtered = result.alreadyFiltered;
			}
		}

		if(origData == null) return null;

		if(!mustCopy)
			return new CacheFetchResult(new ClientMetadata(mime), origData, filtered);

		Bucket newData = null;
		try {
			if(preferred != null) newData = preferred;
			else newData = core.tempBucketFactory.makeBucket(origData.size());
			BucketTools.copy(origData, newData);
			if(origData.size() != newData.size()) {
				Logger.normal(this, "Maybe it disappeared under us?");
				newData.free();
				newData = null;
				return null;
			}
			return new CacheFetchResult(new ClientMetadata(mime), newData, filtered);
		} catch (IOException e) {
			// Maybe it was freed?
			Logger.normal(this, "Unable to copy data: "+e, e);
			return null;
		}

	}

	@Override
	public CacheFetchResult lookup(FreenetURI key, boolean mustCopy, Bucket preferred) {
		if(globalForeverClient == null) return null;
		ClientGet get = globalForeverClient.getCompletedRequest(key);
		if(get != null) {
			boolean filtered = get.filterData();
			Bucket origData = get.getBucket();
			Bucket newData = null;
			if(!mustCopy)
				newData = origData.createShadow();
			if(newData == null) {
				try {
					if(preferred != null)
						newData = preferred;
					else
						newData = core.tempBucketFactory.makeBucket(origData.size());
					BucketTools.copy(origData, newData);
				} catch (IOException e) {
					Logger.error(this, "Unable to copy data: "+e, e);
					return null;
				}
			}
			return new CacheFetchResult(new ClientMetadata(get.getMIMEType()), newData, filtered);
		}
		return null;
	}

}
