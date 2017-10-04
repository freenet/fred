/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.fcp;

import java.io.IOException;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.EnumMap;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import freenet.clients.fcp.FCPPluginMessage.ClientPermissions;
import freenet.node.NodeStarter;
import freenet.node.PrioRunnable;
import freenet.pluginmanager.FredPluginFCPMessageHandler;
import freenet.pluginmanager.FredPluginFCPMessageHandler.ClientSideFCPMessageHandler;
import freenet.pluginmanager.FredPluginFCPMessageHandler.PrioritizedMessageHandler;
import freenet.pluginmanager.FredPluginFCPMessageHandler.ServerSideFCPMessageHandler;
import freenet.pluginmanager.PluginManager;
import freenet.pluginmanager.PluginNotFoundException;
import freenet.pluginmanager.PluginRespirator;
import freenet.support.Executor;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.PooledExecutor;
import freenet.support.SimpleFieldSet;
import freenet.support.io.NativeThread;

/**
 * <b>Please first read the JavaDoc of the interface {@link FCPPluginConnection} which specifies
 * this class.</b><br><br>
 * 
 * ATTENTION:<br>
 * Objects of this class shall not be handed out directly to server or client applications.
 * Instead, only hand out a {@link DefaultSendDirectionAdapter} - which can be obtained by
 * {@link #getDefaultSendDirectionAdapter(SendDirection)}.<br>
 * This has two reasons:<br>
 * - The send functions which do not require a {@link SendDirection} will always throw an exception
 *   without an adapter ({@link #send(FCPPluginMessage)} and
 *   {@link #sendSynchronous(FCPPluginMessage, long)}).<br>
 * - Server plugins must not keep a strong reference to the FCPPluginConnectionImpl
 *   to ensure that the client disconnection mechanism of monitoring garbage collection works,
 *   see {@link PluginRespirator#connectToOtherPlugin(String, ClientSideFCPMessageHandler)}.
 *   The adapter prevents servers from keeping a strong reference by internally only keeping a
 *   {@link WeakReference} to the FCPPluginConnectionImpl.<br>
 * 
 * <h1>Internals</h1><br>
 * 
 * This section is not interesting to server or client implementations. You might want to read it
 * if you plan to work on the fred-side implementation of FCP plugin messaging.
 * 
 * <h2>Code path of sending messages</h2>
 * <p>There are two possible code paths for client connections, depending upon the location of the
 * client. The server is always running inside the node.<br><br>
 * 
 * NOTICE: These two code paths only apply to asynchronous, non-blocking messages. For blocking,
 * synchronous messages sent by {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)},
 * there is an overview at {@link #synchronousSends}. The overview was left out here because they
 * are built on top of regular messages, so the code paths mentioned here mostly apply.<br><br>
 * 
 * The two possible paths are:<br/>
 * <p>1. The server is running in the node, the client is not - also called networked FCP
 * connections:<br/>
 * - The client connects to the node via network and sends FCP message of type
 *   <a href="https://wiki.freenetproject.org/FCPv2/FCPPluginMessage">FCPPluginMessage</a> (which
 *   will be internally represented by class {@link FCPPluginClientMessage}).<br/>
 * - The {@link FCPServer} creates a {@link FCPConnectionHandler} whose
 *   {@link FCPConnectionInputHandler} receives the FCP message.<br/>
 * - The {@link FCPConnectionInputHandler} uses {@link FCPMessage#create(String, SimpleFieldSet)}
 *   to parse the message and obtain the actual {@link FCPPluginClientMessage}.<br/>
 * - The {@link FCPPluginClientMessage} uses {@link FCPConnectionHandler#getFCPPluginConnection(
 *   String)} to obtain the FCPPluginConnection to the server.<br/>
 * - The {@link FCPPluginClientMessage} uses {@link FCPPluginConnection#send(SendDirection,
 *   FCPPluginMessage)} to send the message to the server plugin.<br/>
 * - The FCP server plugin handles the message at
 *   {@link ServerSideFCPMessageHandler#handlePluginFCPMessage(FCPPluginConnection,
 *   FCPPluginMessage)}.<br/>
 * - As each FCPPluginConnection object exists for the lifetime of a network connection, the FCP
 *   server plugin may store the UUID of the FCPPluginConnection and query it via
 *   {@link PluginRespirator#getPluginConnectionByID(UUID)}. It can use this to send messages to the
 *   client application on its own, that is not triggered by any client messages.<br/>
 * </p>
 * <p>2. The server and the client are running in the same node, also called intra-node FCP
 * connections:</br>
 * - The client plugin uses {@link PluginRespirator#connectToOtherPlugin(String,
 *   FredPluginFCPMessageHandler.ClientSideFCPMessageHandler)} to try to create a connection.<br/>
 * - The {@link PluginRespirator} uses {@link FCPServer#createFCPPluginConnectionForIntraNodeFCP(
 *   String, FredPluginFCPMessageHandler.ClientSideFCPMessageHandler)} to get a
 *   FCPPluginConnection.<br>
 * - The client plugin uses the send functions of the FCPPluginConnection. Those are the same as
 *   with networked FCP connections.<br/>
 * - The FCP server plugin handles the message at
 *   {@link ServerSideFCPMessageHandler#handlePluginFCPMessage(FCPPluginConnection,
 *   FCPPluginMessage)}. That is the same handler as with networked FCP connections.<br/>
 * - The client plugin keeps a strong reference to the FCPPluginConnection in memory as long as
 *   it wants to keep the connection open.<br/>
 * - Same as with networked FCP connections, the FCP server plugin can store the UUID of the
 *   FCPPluginConnection and in the future re-obtain the connection by
 *   {@link PluginRespirator#getPluginConnectionByID(UUID)}. It can use this to send messages to the
 *   client application on its own, that is not triggered by any client messages. <br/>
 * - Once the client plugin is done with the connection, it discards the strong reference to the
 *   FCPPluginConnection. Because the {@link FCPPluginConnectionTracker} monitors garbage
 *   collection of FCPPluginConnection objects, getting rid of all strong references to a
 *   FCPPluginConnection is sufficient as a disconnection mechanism.<br/>
 *   Thus, an intra-node client connection is considered as disconnected once the
 *   FCPPluginConnection is not strongly referenced by the client plugin anymore. If a server
 *   plugin then tries to obtain the client connection by its UUID again (via the aforementioned
 *   {@link PluginRespirator#getPluginConnectionByID(UUID)}, the get will fail. So if the server
 *   plugin stores connection UUIDs, it needs no special disconnection mechanism except for
 *   periodically trying to send a message to each client. Once obtaining the client connection by
 *   its UUID fails, or sending the message fails, the server can opportunistically purge the UUID
 *   from its database.
 *   <br/>This mechanism also works for networked FCP.<br>
 * </p></p>
 */
final class FCPPluginConnectionImpl implements FCPPluginConnection {
    
    /** Automatically set to true by {@link Logger} if the log level is set to
     *  {@link LogLevel#DEBUG} for this class.
     *  Used as performance optimization to prevent construction of the log strings if it is not
     *  necessary. */
    private static transient volatile boolean logDEBUG = false;

    /** Automatically set to true by {@link Logger} if the log level is set to
     *  {@link LogLevel#MINOR} for this class.
     *  Used as performance optimization to prevent construction of the log strings if it is not
     *  necessary. */
    private static transient volatile boolean logMINOR = false;
    
    static {
        // Necessary for automatic setting of logDEBUG and logMINOR
        Logger.registerClass(FCPPluginConnectionImpl.class);
    }


    /**
     * Unique identifier among all {@link FCPPluginConnection}s.
     * @see #getID()
     */
    private final UUID id = UUID.randomUUID();

    /**
     * Executor upon which we run threads of the send functions.<br>
     * Since the send functions can be called very often, it would be inefficient to create a new
     * {@link Thread} for each one. An {@link Executor} prevents this by having a pool of Threads
     * which will be recycled.
     */
    private final Executor executor;

    /**
     * The class name of the plugin to which this FCPPluginConnectionImpl is connected.
     */
    private final String serverPluginName;

    /**
     * The FCP server plugin to which this connection is connected.
     * 
     * <p>TODO: Optimization / Memory leak fix: Monitor this with a {@link ReferenceQueue} and if it
     * becomes nulled, remove this FCPPluginConnectionImpl from the map
     * {@link FCPConnectionHandler#pluginConnectionsByServerName}.<br/>
     * Currently, it seems not necessary:<br/>
     * - It can only become null if the server plugin is unloaded / reloaded. Plugin unloading /
     *   reloading requires user interaction or auto update and shouldn't happen frequently.<br/>
     * - It would only leak one WeakReference per plugin per client network connection. That won't
     *   be much until we have very many network connections. The memory usage of having one thread
     *   per {@link FCPConnectionHandler} to monitor the ReferenceQueue would probably outweigh the
     *   savings.<br/>
     * - We already opportunistically clean the table at FCPConnectionHandler: If the client
     *   application which is behind the {@link FCPConnectionHandler} tries to send a message using
     *   a FCPPluginConnectionImpl whose server WeakReference is null, it is purged from the said
     *   table at FCPConnectionHandler. So memory will not leak as long as the clients keep trying
     *   to send messages to the nulled server plugin - which they probably will do because they did
     *   already in the past.<br/>
     * NOTICE: If you do implement this, make sure to not rewrite the ReferenceQueue polling thread
     *         but instead base it upon {@link FCPPluginConnectionTracker}. You should probably
     *         extract a generic class WeakValueMap from that one and use to to power both the
     *         existing class and the one which deals with this variable here.<br>
     *         Also, once you've implemented ReferenceQueue monitoring, remove
     *         {@link #isServerDead()} as it only was added for the opportunistic cleaning due to
     *         lack of a ReferenceQueue and is an ugly function besides that.
     * </p>
     * @see #isServerDead() Use isServerDead() to check whether this WeakReference is nulled.
     */
    private final WeakReference<ServerSideFCPMessageHandler> server;

    /**
     * For intra-node plugin connections, this is the connecting client.
     * For networked plugin connections, this is null.
     */
    private final ClientSideFCPMessageHandler client;

    /**
     * For networked plugin connections, this is the network connection to which this
     * FCPPluginConnectionImpl belongs.
     * For intra-node connections to plugins, this is null.
     * For each {@link FCPConnectionHandler}, there can only be one FCPPluginConnectionImpl for each
     * {@link #serverPluginName}.
     */
    private final FCPConnectionHandler clientConnection;
    
    /**
     * @see FCPPluginConnectionImpl#synchronousSends
     *     An overview of how synchronous sends and especially their threading work internally is
     *     provided at the map which stores them.
     */
    private static final class SynchronousSend {
        /**
         * {@link FCPPluginConnectionImpl#send(SendDirection, FCPPluginMessage)} shall call
         * {@link Condition#signal()} upon this once the reply message has been stored to
         * {@link #reply} to wake up the sleeping {@link FCPPluginConnectionImpl#sendSynchronous(
         * SendDirection, FCPPluginMessage, long)} thread which is waiting for the reply to arrive.
         */
        private final Condition completionSignal;
        
        public FCPPluginMessage reply = null;
        
        public SynchronousSend(Condition completionSignal) {
            this.completionSignal = completionSignal;
        }
    }

    /**
     * For each message sent with the <i>blocking</i> send function
     * {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)} this contains a
     * {@link SynchronousSend} object which shall be used to signal the completion of the
     * synchronous send to the blocking sendSynchronous() thread. Signaling the completion tells the
     * blocking sendSynchronous() function that the remote side has sent a reply message to
     * acknowledge that the original message was processed and sendSynchronous() may return now.
     * In addition, the reply is added to the SynchronousSend object so that sendSynchronous() can
     * return it to the caller.<br><br>
     * 
     * The key is the identifier {@link FCPPluginMessage#identifier} of the original message which
     * was sent by sendSynchronous().<br><br>
     * 
     * An entry shall be added by sendSynchronous() when a new synchronous send is started, and then
     * it shall wait for the Condition {@link SynchronousSend#completionSignal} to be signaled.<br>
     * When the reply message is received, the node will always dispatch it via
     * {@link #send(SendDirection, FCPPluginMessage)}. Thus, that function is obliged to check this
     * map for whether there is an entry for each received reply. If it contains a SynchronousSend
     * for the identifier of a given reply, send() shall store the reply message in it, and then
     * call {@link Condition#signal()} upon the SynchronousSend's Condition to cause the blocking
     * sendSynchronous() function to return.<br>
     * The sendSynchronous() shall take the job of removing the entry from this map.<br><br>
     * 
     * Thread safety is to be guaranteed by the {@link #synchronousSendsLock}.<br><br>
     * 
     * When implementing the mechanisms which use this map, please be aware of the fact that bogus
     * remote implementations could:<br>
     * - Not sent a reply message at all, even though they should. This shall be compensated by
     *   sendSynchronous() always specifying a timeout when waiting upon the Conditions.<br>
     * - Send <i>multiple</i> reply messages for the same identifier even though they should only
     *   send one. This probably won't matter though:<br>
     *   * The first arriving reply will complete the matching sendSynchronous() call.<br>
     *   * Any subsequent replies will not find a matching entry in this table, which is the
     *   same situation as if the reply was to a <i>non</i>-synchronous send. Non-synchronous sends
     *   are a normal thing, and thus handling their replies is implemented. It will cause the
     *   reply to be shipped to the message handler interface of the server/client instead of
     *   being returned by sendSynchronous() though, which could confuse it. But in that case
     *   it will probably just log an error message and continue working as normal.
     *   <br><br>
     * 
     * TODO: Optimization: We do not need the order of the map, and thus this could be a HashMap
     * instead of a TreeMap. We do not use a HashMap for scalability: Java HashMaps never shrink,
     * they only grow. As we cannot predict how much parallel synchronous sends server/client
     * implementations will run, we do need a shrinking map. So we use TreeMap. We should use
     * an automatically shrinking HashMap instead once we have one. This is also documented
     * <a href="https://bugs.freenetproject.org/view.php?id=6320">in the bugtracker</a>.
     */
    private final TreeMap<String, SynchronousSend> synchronousSends
        = new TreeMap<String, SynchronousSend>();
    
    /**
     * Shall be used to ensure thread-safety of {@link #synchronousSends}. <br>
     * (Please read its JavaDoc before continuing to read this JavaDoc: It explains the mechanism
     * of synchronous sends, and it is assumed that you understand it in what follows here.)<br><br>
     * 
     * It is a {@link ReadWriteLock} because synchronous sends shall by design be used infrequently,
     * and thus there will be more reads checking for an existing synchronous send than writes
     * to terminate one.
     * (It is a {@link ReentrantReadWriteLock} because that is currently the only implementation of
     * ReadWriteLock, the re-entrancy is probably not needed by the actual code.)
     */
    private final ReadWriteLock synchronousSendsLock = new ReentrantReadWriteLock();

    /**
     * A {@link DefaultSendDirectionAdapter} is an adapter which encapsulates a
     * FCPPluginConnectionImpl object with a default {@link SendDirection} to implement the send
     * functions which don't require a direction parameter:<br>
     * - {@link FCPPluginConnection#send(FCPPluginMessage)}<br>
     * - {@link FCPPluginConnection#sendSynchronous(FCPPluginMessage, long)}<br><br>
     *  
     * For each possible {@link SendDirection}, this map keeps the responsible adapter. */
    private final EnumMap<SendDirection, DefaultSendDirectionAdapter> defaultSendDirectionAdapters
        = new EnumMap<SendDirection, DefaultSendDirectionAdapter>(SendDirection.class);


    /**
     * For being used by networked FCP connections:<br/>
     * The server is running within the node, and its message handler is accessible as an
     * implementor of {@link ServerSideFCPMessageHandler}.<br/>
     * The client is not running within the node, it is attached by network with a
     * {@link FCPConnectionHandler}.<br/>
     * 
     * @see #constructForNetworkedFCP(FCPPluginConnectionTracker, Executor, PluginManager, String,
     *      FCPConnectionHandler)
     *     The public interface to this constructor.
     */
    private FCPPluginConnectionImpl(FCPPluginConnectionTracker tracker, Executor executor,
            String serverPluginName, ServerSideFCPMessageHandler serverPlugin,
            FCPConnectionHandler clientConnection) {
        
        assert(tracker != null);
        assert(executor != null);
        assert(serverPlugin != null);
        assert(serverPluginName != null);
        assert(clientConnection != null);
        
        this.executor = executor;
        this.serverPluginName = serverPluginName;
        this.server = new WeakReference<ServerSideFCPMessageHandler>(serverPlugin);
        this.client = null;
        this.clientConnection = clientConnection;
        this.defaultSendDirectionAdapters.put(SendDirection.ToServer,
                new SendToServerAdapter(this));
        // new SendToClientAdapter() will need to query this connection from the tracker already.
        // Thus, we have to register before constructing it.
        tracker.registerConnection(this);
        this.defaultSendDirectionAdapters.put(SendDirection.ToClient,
                new SendToClientAdapter(tracker, id));
    }
    
    /**
     * For being used by networked FCP connections:<br/>
     * The server is running within the node, and its message handler will be queried from the
     * {@link PluginManager} via the given String serverPluginName.<br/>
     * The client is not running within the node, it is attached by network with the given
     * {@link FCPConnectionHandler} clientConnection.<br><br>
     * 
     * The returned connection is registered at the given {@link FCPPluginConnectionTracker}.
     * <br><br>
     * 
     * ATTENTION:<br>
     * Objects of this class shall not be handed out directly to server or client applications.
     * Instead, only hand out a {@link DefaultSendDirectionAdapter} - which can be obtained by
     * {@link #getDefaultSendDirectionAdapter(SendDirection)}.<br>
     * This has two reasons:<br>
     * - The send functions which do not require a {@link SendDirection} will always throw an 
     *   exception without an adapter ({@link #send(FCPPluginMessage)} and
     *   {@link #sendSynchronous(FCPPluginMessage, long)}).<br>
     * - Server plugins must not keep a strong reference to the FCPPluginConnectionImpl
     *   to ensure that the client disconnection mechanism of monitoring garbage collection works,
     *   see {@link PluginRespirator#connectToOtherPlugin(String, ClientSideFCPMessageHandler)}.
     *   The adapter prevents servers from keeping a strong reference by internally only keeping a
     *   {@link WeakReference} to the FCPPluginConnectionImpl.<br>
     */
    static FCPPluginConnectionImpl constructForNetworkedFCP(FCPPluginConnectionTracker tracker,
            Executor executor, PluginManager serverPluginManager,
            String serverPluginName, FCPConnectionHandler clientConnection)
                throws PluginNotFoundException {
        
        assert(tracker != null);
        assert(executor != null);
        assert(serverPluginManager != null);
        assert(serverPluginName != null);
        assert(clientConnection != null);
        
        return new FCPPluginConnectionImpl(tracker, executor, serverPluginName,
            serverPluginManager.getPluginFCPServer(serverPluginName), clientConnection);
    }


    /**
     * For being used by intra-node connections between two plugins:<br/>
     * Both the server and the client are running within the same node, so objects of their FCP
     * message handling interfaces are available:<br/>
     * The server's message handler is accessible as an implementor of
     * {@link ServerSideFCPMessageHandler}.<br>
     * The client's message handler is accessible as an implementor of
     * {@link ClientSideFCPMessageHandler}.<br>
     * 
     * @see #constructForIntraNodeFCP(FCPPluginConnectionTracker, Executor, PluginManager, String,
     *      ClientSideFCPMessageHandler)
     *     The public interface to this constructor.
     */
    private FCPPluginConnectionImpl(FCPPluginConnectionTracker tracker, Executor executor,
            String serverPluginName, ServerSideFCPMessageHandler server,
            ClientSideFCPMessageHandler client) {
        
        assert(tracker != null);
        assert(executor != null);
        assert(serverPluginName != null);
        assert(server != null);
        assert(client != null);
        
        this.executor = executor;
        this.serverPluginName = serverPluginName;
        this.server = new WeakReference<ServerSideFCPMessageHandler>(server);
        this.client = client;
        this.clientConnection = null;
        this.defaultSendDirectionAdapters.put(SendDirection.ToServer,
                new SendToServerAdapter(this));
        // new SendToClientAdapter() will need to query this connection from the tracker already.
        // Thus, we have to register before constructing it.
        tracker.registerConnection(this);
        this.defaultSendDirectionAdapters.put(SendDirection.ToClient,
                new SendToClientAdapter(tracker, id));
    }

    /**
     * For being used by intra-node connections between two plugins:<br/>
     * Both the server and the client are running within the same node, so their FCP interfaces are
     * available:<br/>
     * The server plugin will be queried from given {@link PluginManager} via the given String
     * serverPluginName.<br>
     * The client message handler is available as the passed {@link ClientSideFCPMessageHandler}
     * client.<br><br>
     * 
     * The returned connection is registered at the given {@link FCPPluginConnectionTracker}.
     * <br><br>
     * 
     * ATTENTION:<br>
     * Objects of this class shall not be handed out directly to server or client applications.
     * Instead, only hand out a {@link DefaultSendDirectionAdapter} - which can be obtained by
     * {@link #getDefaultSendDirectionAdapter(SendDirection)}.<br>
     * This has two reasons:<br>
     * - The send functions which do not require a {@link SendDirection} will always throw an
     *   exception without an adapter ({@link #send(FCPPluginMessage)} and
     *   {@link #sendSynchronous(FCPPluginMessage, long)}).<br>
     * - Server plugins must not keep a strong reference to the FCPPluginConnectionImpl
     *   to ensure that the client disconnection mechanism of monitoring garbage collection works,
     *   see {@link PluginRespirator#connectToOtherPlugin(String, ClientSideFCPMessageHandler)}.
     *   The adapter prevents servers from keeping a strong reference by internally only keeping a
     *   {@link WeakReference} to the FCPPluginConnectionImpl.<br>
     */
    static FCPPluginConnectionImpl constructForIntraNodeFCP(FCPPluginConnectionTracker tracker,
            Executor executor, PluginManager serverPluginManager,
            String serverPluginName, ClientSideFCPMessageHandler client)
                throws PluginNotFoundException {
        
        assert(executor != null);
        assert(serverPluginManager != null);
        assert(serverPluginName != null);
        assert(client != null);
        
        return new FCPPluginConnectionImpl(tracker, executor, serverPluginName,
            serverPluginManager.getPluginFCPServer(serverPluginName), client);
    }
    
    /**
     * ONLY for being used in unit tests.<br>
     * This is similar to intra-node connections in regular operation: Both the server and client
     * are running in the same VM. You must implement both the server and client side message
     * handler in the unit test and pass them to this constructor.<br><br>
     * 
     * Notice: Some server plugins might use {@link PluginRespirator#getPluginConnectionByID(UUID)}
     * to obtain FCPPluginConnectionImpl objects. They likely won't work with connections created by
     * this because it doesn't create a PluginRespirator. To get a {@link PluginRespirator}
     * available in unit tests, you might want to use
     * {@link NodeStarter#createTestNode(freenet.node.NodeStarter.TestNodeParameters)} instead 
     * of this constructor:<br>
     * - The test node can be used to load the plugin as a JAR.<br>
     * - As loading a plugin by JAR is the same mode of operation as with a regular node,
     *   there will be a PluginRespirator available to it.<br>
     * - {@link PluginRespirator#connectToOtherPlugin(String, ClientSideFCPMessageHandler)} can then
     *   be used for obtaining a FCPPluginConnection instead of this constructor. This also is the
     *   function to obtain a FCPPluginConnection which is used in regular mode of operation.<br>
     * - The aforementioned {@link PluginRespirator#getPluginConnectionByID(UUID)} will then work
     *   for FCPPluginConnections obtained through the connectToOtherPlugin().
     */
    public static FCPPluginConnectionImpl constructForUnitTest(ServerSideFCPMessageHandler server,
        ClientSideFCPMessageHandler client) {
        
        assert(server != null);
        assert(client != null);
        FCPPluginConnectionTracker tracker = new FCPPluginConnectionTracker();
        tracker.start();
        return new FCPPluginConnectionImpl(
            tracker, new PooledExecutor(), server.toString(), server, client);
    }
    
    @Override
    public UUID getID() {
        return id;
    }

    /**
     * ATTENTION: Only for internal use in {@link FCPConnectionHandler#getFCPPluginConnection(
     * String)}.<br>
     * Server / client code should instead always send messages, for example via
     * {@link #send(SendDirection, FCPPluginMessage)}, to check whether the connection is alive.
     * This is to ensure that the implementation of this class could safely be changed to allow the
     * server to be attached by network instead of always running locally in the same node as it
     * currently is. Also see below.<br>
     * 
     * @return
     *     <p>True if the server plugin has been unloaded. Once this returns true, this
     *     FCPPluginConnectionImpl <b>cannot</b> be repaired, even if the server plugin is loaded
     *     again. Then you should discard this connection and create a fresh one.</p>
     * 
     *     <p><b>ATTENTION:</b> Future implementations of {@link FCPPluginConnection} might allow
     *     the server plugin to reside in a different node, and only be attached by network. Due to
     *     the unreliability of network connections, then this function will not be able to reliably
     *     detect whether the server is dead.<br>
     *     To prepare for that, you <b>must not</b> assume that the connection to the server is
     *     still fine just because this returns false = server is alive. Consider false / server is
     *     alive merely an indication, true / server is dead as the definite truth.<br>
     *     If you need to validate a connection to be alive, send periodic pings. </p>
     */
    boolean isServerDead() {
        return server.get() == null;
    }
    
    /**
     * @return
     *     The permission level of the client, depending on things such as its IP address.<br>
     *     For intra-node connections, it is {@link ClientPermissions#ACCESS_DIRECT}.<br><br>
     * 
     *     <b>ATTENTION:</b> The return value can change at any point in time, so you should check
     *     this before deploying each FCP message.<br>
     *     This is because the user is free to reconfigure IP-address restrictions on the node's web
     *     interface whenever he wants to.
     */
    private ClientPermissions getCurrentClientPermissions() {
        if(clientConnection != null) { // Networked FCP
            return clientConnection.hasFullAccess() ?
                ClientPermissions.ACCESS_FCP_FULL : ClientPermissions.ACCESS_FCP_RESTRICTED;
        } else { // Intra-node FCP
            assert(client != null);
            return ClientPermissions.ACCESS_DIRECT;
        }
    }

    @Override
    public void send(final SendDirection direction, FCPPluginMessage message) throws IOException {
        // We first have to compute the message.permissions field ourselves - we shall ignore what
        // caller said for security.
        ClientPermissions currentClientPermissions = (direction == SendDirection.ToClient) ?
             null // Server-to-client messages do not have permissions.
             : getCurrentClientPermissions();

        // We set the permissions by creating a fresh FCPPluginMessage object so the caller cannot
        // overwrite what we compute.
        message = FCPPluginMessage.constructRawMessage(currentClientPermissions, message.identifier,
            message.params, message.data, message.success, message.errorCode, message.errorMessage);

        // Now that the message is completely initialized, we can dump it to the logfile.
        if(logDEBUG) {
            Logger.debug(this, "send(): direction = " + direction + "; " + "message = " + message);
        }
        
        // True if the target server or client message handler is running in this VM.
        // This means that we can call its message handling function in a thread instead of
        // sending a message over the network.
        // Notice that we do not check for server != null because that is not allowed by this class.
        final boolean messageHandlerExistsLocally =
            (direction == SendDirection.ToServer) ||
            (direction == SendDirection.ToClient && client != null);
        
        if(!messageHandlerExistsLocally) {
            dispatchMessageByNetwork(direction, message);
            return;
        }
        
        assert(direction == SendDirection.ToServer ? server != null : client != null)
            : "We already decided that the message handler exists locally. "
            + "We should have only decided so if the handler is not null.";
        
        // The message handler is determined to be local at this point. There are two possible
        // types of local message handlers:
        // 1) An object provided by the server/client which implements FredPluginFCPMessageHandler.
        //    The message is delivered by executing a callback on that object, with the message
        //    as parameter.
        // 2) A call to sendSynchronous() which is blocking because it is waiting for a reply
        //    to the message it sent so it can return the reply message to the caller.
        //    The reply message is delivered by passing it to the sendSynchronous() thread through
        //    an internal table of this class.
        // 
        // The following function call checks for whether case 2 applies, and handles it if yes:
        // If there is such a waiting sendSynchronous() thread, it delivers the message to it, and
        // returns true, and we are done: By contract, messages are preferably delivered to
        // sendSynchronous().
        // If there was no sendSynchronous() thread, it returns false, and we must continue to
        // handle case 1.
        if(dispatchMessageLocallyToSendSynchronousThreadIfExisting(message))
            return;
        
        // We now know that the message handler is not attached by network, and that it is not a
        // sendSynchronous() thread. So the only thing it can be is a FredPluginFCPMessageHandler,
        // and we now determine whether it is the one of the client or the server.
        final FredPluginFCPMessageHandler messageHandler
            = (direction == SendDirection.ToServer) ? server.get() : client;

        if(messageHandler == null) {
            // server is a WeakReference which can be nulled if the server plugin was unloaded.
            // client is not a WeakReference, we already checked for it to be non-null.
            // Thus, in this case here, the server plugin has been unloaded so we can have
            // an error message which specifically talks about the *server* plugin.
            throw new IOException("The server plugin has been unloaded.");
        }
        
        // We now have the right FredPluginFCPMessageHandler, it is still alive, and so we can can
        // pass the message to it.
        dispatchMessageLocallyToMessageHandler(messageHandler, direction, message);
    }
    
    /**
     * Backend for {@link #send(SendDirection, FCPPluginMessage)} to dispatch messages which need
     * to be transported by network.<br><br>
     * 
     * This shall only be called for messages for which it was determined that the message handler
     * is not a plugin running in the local VM.
     */
    private void dispatchMessageByNetwork(final SendDirection direction,
            final FCPPluginMessage message)
                throws IOException {
        
        // The message handler is attached by network.
        // In theory, we could construct a mock FredPluginFCPMessagehandler object for it to
        // pretend it was a local message. But then we wouldn't know the reply message immediately
        // because the messages take time to travel over the network. This wouldn't work with the
        // local message dispatching code as it needs to know the reply immediately so it can send
        // it out. To get the reply, we would have to create a thread which would exist until the
        // reply arrives over the network.
        // So instead, for simplicity and reduced thread count, we just queue the message directly
        // to the network queue here and return.
        
        assert (direction == SendDirection.ToClient)
            : "By design, this class always shall execute in the same VM as the server plugin. "
            + "So for networked messages, we should always be sending to the client.";
        
        assert (clientConnection != null)
            : "Trying to send a message over the network to the client. "
            + "So the network connection to it should not be null.";
        
        if (clientConnection.isClosed())
            throw new IOException("Connection to client closed for " + this);
        
        clientConnection.send(new FCPPluginServerMessage(serverPluginName, message));
    }

    /**
     * Backend for {@link #send(SendDirection, FCPPluginMessage)} to dispatch messages to a thread
     * waiting in {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)} for the message.
     * <br><br>
     * 
     * This shall only be called for messages for which it was determined that the message handler
     * is a plugin running in the local VM.
     * 
     * @return
     *     True if there was a thread waiting for the message and the message was dispatched to it.
     *     You <b>must not</b> dispatch it to the {@link FredPluginFCPMessageHandler} then.<br><br>
     * 
     *     False if there was no thread waiting for the message. You <b>must<b/> dispatch it to the
     *     {@link FredPluginFCPMessageHandler} then.<br><br>
     * 
     *     (Both these rules are specified in the documentation of sendSynchronous().)
     * @see FCPPluginConnectionImpl#synchronousSends
     *     An overview of how synchronous sends and especially their threading work internally is
     *     provided at the map which stores them.
     */
    private boolean dispatchMessageLocallyToSendSynchronousThreadIfExisting(final FCPPluginMessage message) {

        // Since the message handler is determined to be local at this point, we now must check
        // whether it is a blocking sendSynchronous() thread instead of a regular
        // FredPluginFCPMessageHandler.
        // sendSynchronous() does the following: It sends a message and then blocks its thread
        // waiting for a message replying to it to arrive so it can return it to the caller.
        // If the message we are processing here is a reply, it might be the one which a
        // sendSynchronous() is waiting for.
        // So it is our job to pass the reply to a possibly existing sendSynchronous() thread.
        // We do this through the Map FCPPluginConnectionImpl.synchronousSends, which is guarded by
        // FCPPluginConnectionImpl.synchronousSendsLock. Also see the JavaDoc of the Map for an
        // overview of this mechanism.
        
        if(!message.isReplyMessage()) {
            return false;
        }

        // Since the JavaDoc of sendSynchronous() tells people to use it not very often due to
        // the impact upon thread count, we assume that the percentage of messages which pass
        // through here for which there is an actual sendSynchronous() thread waiting is small.
        // Thus, a ReadWriteLock is used, and we here only take the ReadLock, which can be taken
        // by *multiple* threads at once. We then read the map to check whether there is a
        //  waiter, and if there is, take the write lock to hand the message to it.
        // (The implementation of ReentrantReadWritelock does not allow upgrading a readLock()
        // to a writeLock(), so we must release it in between and re-check afterwards.)
        // TODO: Performance: If this turns out to be a bottleneck, add a
        // "Synchronous={True, False}" flag to messages so we only have to check the table if
        // Synchronous=True, and can return false immediately otherwise. (If Synchronous=True, we
        // still will have to check the table whether a waiter is existing because it might have
        // timed out already)

        synchronousSendsLock.readLock().lock();
        try {
            if(!synchronousSends.containsKey(message.identifier)) {
                return false;
            }
        } finally {
            synchronousSendsLock.readLock().unlock();
        }
        
        synchronousSendsLock.writeLock().lock();
        try {
            SynchronousSend synchronousSend = synchronousSends.get(message.identifier);
            if(synchronousSend == null) {
                // The waiting sendSynchronous() has probably returned already because its
                // timeout expired.
                // So by returning false, we ask the caller to deliver the message to the
                // regular message handling interface to make sure that it is not lost.
                return false;
            }

            assert(synchronousSend.reply == null)
                : "One identifier should not be used for multiple messages or replies";

            synchronousSend.reply = message;
            // Wake up the waiting synchronousSend() thread
            synchronousSend.completionSignal.signal();

            return true;
        } finally {
            synchronousSendsLock.writeLock().unlock();
        }
    }

    /**
     * Backend for {@link #send(SendDirection, FCPPluginMessage)} to dispatch messages to a
     * {@link FredPluginFCPMessageHandler}.<br><br>
     * 
     * This shall only be called for messages for which it was determined that the message handler
     * is a plugin running in the local VM.<br><br>
     * 
     * The message will be dispatched in a separate thread so this function can return quickly.
     */
    private void dispatchMessageLocallyToMessageHandler(
            final FredPluginFCPMessageHandler messageHandler, final SendDirection direction,
            final FCPPluginMessage message) {
        
        final Runnable messageDispatcher = new PrioRunnable() {
            @Override
            public void run() {
                FCPPluginMessage reply = null;
                
                try {
                    try {
                        reply = messageHandler.handlePluginFCPMessage(
                            getDefaultSendDirectionAdapter(direction.invert()), message);
                    } catch(Error e) {
                        // TODO: Code quality: This is a workaround for Java 6 not having
                        // "catch(RuntimeException | Error e)". Once we are on Java 7, remove this
                        // catch() block, and catch both types with the catch() block below.
                        throw new RuntimeException(e);
                    }
                } catch(RuntimeException e) {
                    // The message handler is a server or client implementation, and thus as third
                    // party code might have bugs. So we need to catch any undeclared throwables.
                    // Notice that this is not normal mode of operation: Instead of throwing,
                    // the JavaDoc requests message handlers to return a reply with success=false.
                    
                    String errorMessage = "FredPluginFCPMessageHandler threw."
                        + " See JavaDoc of its member interfaces for how signal errors properly."
                        + " connection = " + FCPPluginConnectionImpl.this
                        + "; SendDirection = " + direction
                        + "; message = " + message;
                    
                    Logger.error(messageHandler, errorMessage, e);
                    
                    if(!message.isReplyMessage()) {
                        // If the original message was not a reply already, we are allowed to send a
                        // reply with success=false to indicate the error to the remote side.
                        // This allows possibly existing, waiting sendSynchronous() calls to fail
                        // quickly instead of having to wait for the timeout because no reply
                        // arrives.
                        reply = FCPPluginMessage.constructReplyMessage(message, null, null, false,
                            "InternalError", errorMessage + "; Throwable = " + e.toString());
                    }
                }
                
                if(reply != null) {
                    // TODO: Performance: The below checks might be converted to assert() or
                    // be prefixed with if(logMINOR).
                    // Not doing this now since the FredPluginFCPMessageHandler API which specifies
                    // those requirements is new and thus quite a few client applications might be
                    // converted to it soon, and do those beginners mistakes.
                    // After everyone has gotten used to it, we can move to the more lax checking.
                    // An alternate solution would be to not use the FCPPluginMessage object
                    // which was returned by the message handler but always re-construct it to
                    // follow the standards.

                    // Replying to replies is disallowed to prevent infinite bouncing.
                    if(message.isReplyMessage()) {
                        Logger.error(messageHandler, "FredPluginFCPMessageHandler tried to send a"
                            + " reply to a reply. Discarding it. See JavaDoc of its member"
                            + " interfaces for how to do this properly."
                            + " connection = " + FCPPluginConnectionImpl.this
                            + "; original message SendDirection = " + direction
                            + "; original message = " + message
                            + "; reply = " + reply);
                        
                        reply = null;
                    } else if(!reply.isReplyMessage()) {
                        Logger.error(messageHandler, "FredPluginFCPMessageHandler tried to send a"
                            + " non-reply message as reply. See JavaDoc of its member interfaces"
                            + " for how to do this properly."
                            + " connection = " + FCPPluginConnectionImpl.this
                            + "; original message SendDirection = " + direction
                            + "; original message = " + message
                            + "; reply = " + reply);

                        reply = null;
                    } else if(!reply.identifier.equals(message.identifier)) {
                        Logger.error(messageHandler, "FredPluginFCPMessageHandler tried to send a"
                            + " reply with with different identifier than original message."
                            + " See JavaDoc of its member interfaces for how to do this properly."
                            + " connection = " + FCPPluginConnectionImpl.this
                            + "; original message SendDirection = " + direction
                            + "; original message = " + message
                            + "; reply = " + reply);

                        reply = null;
                    }
                } else if(reply == null) {
                    if(!message.isReplyMessage()) {
                        // The message handler did not not ship a reply even though it would have
                        // been allowed to because the original message was not a reply.
                        // This shouldn't be done: Not sending a success reply at least will cause
                        // sendSynchronous() threads to keep waiting for the reply until timeout.
                        Logger.warning(
                            messageHandler, "Fred did not receive a reply from the message "
                                          + "handler even though it was allowed to reply. "
                                          + "This would cause sendSynchronous() to timeout! "
                                          + " connection = " + FCPPluginConnectionImpl.this
                                          + "; SendDirection = " + direction
                                          + "; message = " + message);
                    }
                }
                
                // We already tried to set a reply if one is needed. If it is still null now, then
                // we do not have to send one for sure, so we can return.
                if(reply == null) {
                    return;
                }
                
                try {
                    send(direction.invert(), reply);
                } catch (IOException e) {
                    // The remote partner has disconnected, which can happen during normal
                    // operation.
                    // There is nothing we can do to get the IOException out to the caller of the
                    // initial send() of the original message which triggered the reply sending.
                    // - We are in a different thread, the initial send() has returned already.
                    // So we just log it, because it still might indicate problems if we try to
                    // send after disconnection.
                    // We log it marked as from the messageHandler instead of the
                    // FCPPluginConnectionImpl:
                    // The messageHandler will be an object of the server or client plugin,
                    // from a class contained in it. So there is a chance that the developer
                    // has logging enabled for that class, and thus we log it marked as from that.
                    
                    Logger.warning(messageHandler, "Sending reply from FredPluginFCPMessageHandler"
                        + " failed, the connection was closed already."
                        + " connection = " + FCPPluginConnectionImpl.this
                        + "; original message SendDirection = " + direction
                        + "; original message = " + message
                        + "; reply = " + reply, e);
                }
            }

            @Override
            public int getPriority() {
                NativeThread.PriorityLevel priority = NativeThread.PriorityLevel.NORM_PRIORITY;
                
                if(messageHandler instanceof PrioritizedMessageHandler) {
                    try {
                        priority = ((PrioritizedMessageHandler)messageHandler).getPriority(message);
                    } catch(Throwable t) {
                        Logger.error(messageHandler, "Message handler's getPriority() threw!", t);
                    }
                }
                
                return priority.value;
            }

            /** @return A suitable {@link String} for use as the name of this thread */
            @Override public String toString() {
                // Don't use FCPPluginConnection.toString() as it would be too long to fit in
                // the thread list on the Freenet FProxy web interface.
                return "FCPPluginConnection for " + serverPluginName;
            }
        };
        
        executor.execute(messageDispatcher, messageDispatcher.toString());
    }

    @Override
    public FCPPluginMessage sendSynchronous(SendDirection direction, FCPPluginMessage message,
            long timeoutNanoSeconds)
                throws IOException, InterruptedException {
        
        if(message.isReplyMessage()) {
            throw new IllegalArgumentException("sendSynchronous() cannot send reply messages: " +
                "If it did send a reply message, it would not get another reply back. " +
                "But a reply is needed for sendSynchronous() to determine when to return.");
        }
        
        assert(timeoutNanoSeconds > 0) : "Timeout should not be negative";
        
        assert(timeoutNanoSeconds <= TimeUnit.MINUTES.toNanos(1))
            : "Please use sane timeouts to prevent thread congestion";
        
        
        synchronousSendsLock.writeLock().lock();
        try {
            final Condition completionSignal = synchronousSendsLock.writeLock().newCondition();
            final SynchronousSend synchronousSend = new SynchronousSend(completionSignal);
            
            // An assert() instead of a throwing is fine:
            // - The constructor of FCPPluginMessage which we tell the user to use in the JavaDoc
            //   does generate a random identifier, so collisions will only happen if the user
            //   ignores the JavaDoc or changes the constructor.
            // - If the assert is not true, then the following put() will replace the old
            //   SynchronousSend, so its Condition will never get signaled, and its
            //   thread waiting in sendSynchronous() will timeout safely. It IS possible that this
            //   thread will then get a reply which does not belong to it. But the wrong reply will
            //   only affect the caller, the FCPPluginConnectionImpl will keep working fine,
            //   especially no threads will become stalled for ever. As the caller is at fault for
            //   the issue, it is fine if he breaks his own stuff :) The JavaDoc also documents this
            
            assert(!synchronousSends.containsKey(message.identifier))
                : "FCPPluginMessage.identifier should be unique";
            
            synchronousSends.put(message.identifier, synchronousSend);
            
            if(logMINOR) {
                Logger.minor(this, "sendSynchronous(): Started for identifier " + message.identifier
                                 + "; synchronousSends table size: " + synchronousSends.size());
            }
            
            send(direction, message);
            
            // Message is sent, now we wait for the reply message to be put into the SynchronousSend
            // object by the thread which receives the reply message.
            // - That usually happens at FCPPluginConnectionImpl.send().
            // Once it has put it into the SynchronousSend object, it will call signal() upon
            // our Condition completionSignal.
            // This will make the following awaitNanos() wake up and return true, which causes this
            // function to be able to return the reply.
            do {
                // The compleditionSignal is a Condition which was created from the
                // synchronousSendsLock.writeLock(), so it will be released by the awaitNanos()
                // while it is blocking, and re-acquired when it returns.
                timeoutNanoSeconds = completionSignal.awaitNanos(timeoutNanoSeconds);
                if(timeoutNanoSeconds <= 0) {
                    // Include the FCPPluginMessage in the Exception so the developer can determine
                    // whether it is an issue of the remote side taking a long time to execute
                    // for certain messages.
                    throw new IOException("sendSynchronous() timed out waiting for reply! "
                        + " connection = " + FCPPluginConnectionImpl.this
                        + "; SendDirection = " + direction
                        + "; message = " + message);
                }

                // The thread which sets synchronousSend.reply to be non-null calls
                // completionSignal.signal() only after synchronousSend.reply has been set.
                // So the naive assumption would be that at this point of code,
                // synchronousSend.reply would be non-null because awaitNanos() should only return
                // true after signal() was called.
                // However, Condition.awaitNanos() can wake up "spuriously", i.e. wake up without
                // actually having been signal()ed. See the JavaDoc of Condition.
                // So after awaitNanos() has returned true to indicate that it might have been
                // signaled we still need to check whether the semantic condition which would
                // trigger signaling is *really* met, which we do with this if:
                if(synchronousSend.reply != null) {
                    assert(synchronousSend.reply.identifier.equals(message.identifier));
                    
                    return synchronousSend.reply;
                }

                // The spurious wakeup described at the above if() has happened, so we loop.
            } while(true);
        } finally {
            // We MUST always remove the SynchronousSend object which we added to the map,
            // otherwise it will leak memory eternally.
            synchronousSends.remove(message.identifier);
            
            if(logMINOR) {
                Logger.minor(this, "sendSynchronous(): Done for identifier " + message.identifier
                                 + "; synchronousSends table size: " + synchronousSends.size());
            }
            
            synchronousSendsLock.writeLock().unlock();
        }
    }

    /**
     * Encapsulates a FCPPluginConnectionImpl object and a default {@link SendDirection} to
     * implement the send functions which don't require a direction parameter:<br>
     * - {@link FCPPluginConnection#send(FCPPluginMessage)}<br>
     * - {@link FCPPluginConnection#sendSynchronous(FCPPluginMessage, long)}<br><br>
     * 
     * An adapter is needed instead of storing this as a member variable in FCPPluginConnectionImpl
     * because a single FCPPluginConnectionImpl object is used by both to the the server AND the
     * client which it connects, and their default send direction will be different:<br>
     * A server will want to send to the client by default, but the client will want to default to
     * sending to the server.<br><br>
     * 
     * Is abstract and has two implementing child classes (to implement differing internal
     * requirements, see {@link #getConnection()}):<br>
     * - {@link SendToClientAdapter} for default direction {@link SendDirection#ToClient}.<br>
     * - {@link SendToServerAdapter} for default direction {@link SendDirection#ToServer}.<br><br>
     * 
     * NOTICE: Server plugins must not keep a strong reference to the FCPPluginConnectionImpl
     * to ensure that the client disconnection mechanism of monitoring garbage collection works.
     * This class also serves the purpose of preventing servers from keeping a strong reference:<br>
     * Uses of class FCPPluginConnectionImpl are told by the documentation to never hand out a
     * FCPPluginConnectionImpl itself to servers, but only give them adapters. Since the
     * {@link SendToClientAdapter} only keeps a {@link WeakReference} to the
     * FCPPluginConnectionImpl, by only handing out the adapter, servers are prevented from keeping
     * a strong reference to the FCPPluginConnectionImpl.
     */
    private abstract static class DefaultSendDirectionAdapter implements FCPPluginConnection {
        
        private final SendDirection defaultDirection;
        
        DefaultSendDirectionAdapter(SendDirection defaultDirection) {
            this.defaultDirection = defaultDirection;
        }
        
        /**
         * Returns the encapsulated backend FCPPluginConnection which shall be used for sending.<br>
         * <br>
         * 
         * Abstract because storage of a FCPPluginConnection object is different for servers and
         * clients and thus must be implemented in separate child classes:<br>
         * - Clients may and must store a FCPPluginConnection with a hard reference because a
         *   connection is considered as closed once there is no more hard reference to it.<br>
         *   Disconnection is detected by monitoring the FCPluginConnection for garbage collection.
         *   <br>
         * - Servers must store a FCPPluginConnection with a {@link WeakReference} (or always query
         *   it by UUID from the node) to ensure that they will get garbage connected once the
         *   client decides to disconnect by dropping all strong references.
         */
        protected abstract FCPPluginConnection getConnection() throws IOException;


        @Override public void send(FCPPluginMessage message) throws IOException {
            send(defaultDirection, message);
        }

        @Override public FCPPluginMessage sendSynchronous(FCPPluginMessage message,
                long timeoutNanoSeconds) throws IOException, InterruptedException {
            return sendSynchronous(defaultDirection, message, timeoutNanoSeconds);
        }

        @Override public void send(SendDirection direction, FCPPluginMessage message)
                throws IOException {
            getConnection().send(direction, message);
        }

        @Override public FCPPluginMessage sendSynchronous(SendDirection direction,
                FCPPluginMessage message, long timeoutNanoSeconds)
                    throws IOException, InterruptedException {
            return getConnection().sendSynchronous(direction, message, timeoutNanoSeconds);
        }
    }

    /**
     * Encapsulates a FCPPluginConnectionImpl object with a default {@link SendDirection} of
     * {@link SendDirection#ToClient} to implement the send functions which don't require a
     * direction parameter:<br>
     * - {@link FCPPluginConnection#send(FCPPluginMessage)}<br>
     * - {@link FCPPluginConnection#sendSynchronous(FCPPluginMessage, long)}<br><br>
     * 
     * ATTENTION: Must only be used by the server, not by the client: Clients must keep a strong
     * reference to the connection to prevent its garbage collection (= disconnection), but this
     * does not keep a strong reference.<br>
     * See section "Disconnecting properly" at {@link PluginRespirator#connectToOtherPlugin(
     * String, ClientSideFCPMessageHandler)}.<br><br>
     * 
     * NOTICE: Server plugins must not keep a strong reference to the FCPPluginConnectionImpl
     * to ensure that the client disconnection mechanism of monitoring garbage collection works.
     * This class also serves the purpose of preventing servers from keeping a strong reference:<br>
     * Uses of class FCPPluginConnectionImpl are told by the documentation to never hand out a
     * FCPPluginConnectionImpl itself to servers, but only give them adapters. Since the
     * SendToClientAdapter only keeps a {@link WeakReference} to the FCPPluginConnectionImpl, by
     * only handing out the adapter, servers are prevented from keeping a strong reference to the
     * FCPPluginConnectionImpl.<br>
     * As a consequence, please do never change this class to keep a strong reference to the
     * FCPPluginConnectionImpl.
     */
    private static final class SendToClientAdapter extends DefaultSendDirectionAdapter {

        /**
         * {@link WeakReference} to the underlying FCPPluginConnectionImpl.<br>
         * Once this becomes null, the connection is definitely dead - see
         * {@link FCPPluginConnectionTracker}.<br>
         * Notice: The ConnectionWeakReference child class of {@link WeakReference} is used because
         * it also stores the connection ID, which is needed for {@link #getID()}.
         */
        private final FCPPluginConnectionTracker.ConnectionWeakReference connectionRef;

        /**
         * For CPU performance of not calling
         * {@link FCPPluginConnectionTracker#getConnectionWeakReference(UUID)} for every
         * {@link #send(FCPPluginMessage)}, please use
         * {@link FCPPluginConnectionImpl#getDefaultSendDirectionAdapter(SendDirection)}
         * whenever possible to reuse adapters instead of creating new ones with this constructor.*/
        SendToClientAdapter(FCPPluginConnectionTracker tracker, UUID connectionID) {
            super(SendDirection.ToClient);

            // Reuse the WeakReference from the FCPPluginConnectionTracker instead of creating our
            // own one since it has to keep a WeakReference for every connection anyway, and
            // WeakReferences might be expensive to maintain for the VM.
            try {
                this.connectionRef = tracker.getConnectionWeakReference(connectionID);
            } catch (IOException e) {
                // This function should only be used during construction of the underlying
                // FCPPluginConnectionImpl. While it is being constructed, it should not be
                // considered as disconnected already, and thus the FCPPluginConnectionTracker
                // should never throw IOException.
                throw new RuntimeException("SHOULD NOT HAPPEN: ", e);
            }
        }

        @Override protected FCPPluginConnection getConnection() throws IOException {
            FCPPluginConnection connection = connectionRef.get();
            if(connection == null) {
                throw new IOException("Client has closed the connection. "
                                    + "Connection ID = " + connectionRef.connectionID);
            }
            return connection;
        }

        @Override public UUID getID() {
            return connectionRef.connectionID;
        }
        
        @Override public String toString() {
            String prefix = "SendToClientAdapter for ";
            try {
                return prefix + getConnection();
            } catch(IOException e) {
                return prefix + " FCPPluginConnectionImpl (" + e.getMessage() + ")";
            }
        }
    }

    /**
     * Encapsulates a FCPPluginConnectionImpl object with a default {@link SendDirection} of
     * {@link SendDirection#ToServer} to implement the send functions which don't require a
     * direction parameter:<br>
     * - {@link FCPPluginConnection#send(FCPPluginMessage)}<br>
     * - {@link FCPPluginConnection#sendSynchronous(FCPPluginMessage, long)}<br><br>
     * 
     * ATTENTION: Must only be used by the client, not by the server: Client disconnection is
     * implemented by monitoring the garbage collection of their FCPPluginConnectionImpl objects
     * - once the connection is not strong referenced anymore, it is considered as closed.
     * As this class keeps a strong reference to the connection, if servers did use it, they would
     * prevent client disconnection.<br>
     * See section "Disconnecting properly" at {@link PluginRespirator#connectToOtherPlugin(
     * String, ClientSideFCPMessageHandler)}.
     */
    private static final class SendToServerAdapter extends DefaultSendDirectionAdapter {

        private final FCPPluginConnection parent;

        /**
         * For CPU performance of not constructing objects for every {@link #send(FCPPluginMessage)}
         * please use {@link FCPPluginConnectionImpl#getDefaultSendDirectionAdapter(SendDirection)}
         * whenever possible to reuse adapters instead of creating new ones with this constructor.*/
        SendToServerAdapter(FCPPluginConnectionImpl parent) {
            super(SendDirection.ToServer);
            this.parent = parent;
        }

        @Override protected FCPPluginConnection getConnection() {
            return parent;
        }

        @Override public UUID getID() {
            return parent.getID();
        }
        
        @Override public String toString() {
            return "SendToServerAdapter for " + parent;
        }
    }

    /**
     * Returns a {@link DefaultSendDirectionAdapter} (which implements FCPPluginConnection) wrapped
     * around this FCPPluginConnectionImpl for which the following send functions will then always
     * send to the {@link SendDirection} which was passed to this function:<br>
     * - {@link FCPPluginConnection#send(FCPPluginMessage)}<br>
     * - {@link FCPPluginConnection#sendSynchronous(FCPPluginMessage, long)}<br><br>
     */
    public FCPPluginConnection getDefaultSendDirectionAdapter(SendDirection direction) {
        return defaultSendDirectionAdapters.get(direction);
    }


    /** 
     * @throws NoSendDirectionSpecifiedException
     *     Is always thrown since this function is only implemented for FCPPluginConnectionImpl
     *     objects which are wrapped inside a {@link DefaultSendDirectionAdapter}.<br>
     *     Objects of type FCPPluginConnectionImpl will never be handed out directly to the server
     *     or client application code, they will always be wrapped in such an adapter - so this
     *     function will work for servers and clients. */
    @Override public void send(FCPPluginMessage message) {
        throw new NoSendDirectionSpecifiedException();
    }

    /** 
     * @throws NoSendDirectionSpecifiedException
     *     Is always thrown since this function is only implemented for FCPPluginConnectionImpl
     *     objects which are wrapped inside a {@link DefaultSendDirectionAdapter}.<br>
     *     Objects of type FCPPluginConnectionImpl will never be handed out directly to the server
     *     or client application code, they will always be wrapped in such an adapter - so this
     *     function will work for servers and clients. */
    @Override public FCPPluginMessage sendSynchronous(FCPPluginMessage message,
            long timeoutNanoSeconds) {
        throw new NoSendDirectionSpecifiedException();
    }

    /**
     * @see FCPPluginConnectionImpl#send(FCPPluginMessage)
     * @see FCPPluginConnectionImpl#sendSynchronous(FCPPluginMessage, long) */
    @SuppressWarnings("serial")
    private static final class NoSendDirectionSpecifiedException
            extends UnsupportedOperationException {

        public NoSendDirectionSpecifiedException() {
            super("You must obtain a FCPPluginConnectionImpl with a default SendDirection via "
                + "getDefaultSendDirectionAdapter() before you may use this function!");
        }
    }


    @Override
    public String toString() {
        return "FCPPluginConnectionImpl (ID: " + id + "; server class: " + serverPluginName
             + "; server: " + (server != null ? server.get() : null)
             + "; client: " + client + "; clientConnection: " + clientConnection +  ")";
    }

    /**
     * ATTENTION: For unit test use only.
     * 
     * @return 
     *     The size of the backend table {@link #synchronousSends} of
     *     {@link #sendSynchronous(SendDirection, FCPPluginMessage, long)}
     */
    int getSendSynchronousCount() {
        synchronousSendsLock.readLock().lock();
        try {
            return synchronousSends.size();
        } finally {
            synchronousSendsLock.readLock().unlock();
        }
    }
}
