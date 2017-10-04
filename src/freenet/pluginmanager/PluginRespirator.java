package freenet.pluginmanager;

import java.io.IOException;
import java.lang.ref.ReferenceQueue;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.UUID;

import freenet.client.HighLevelSimpleClient;
import freenet.client.async.PersistenceDisabledException;
import freenet.client.filter.FilterCallback;
import freenet.clients.fcp.FCPPluginConnection;
import freenet.clients.fcp.FCPPluginMessage;
import freenet.clients.http.PageMaker;
import freenet.clients.http.SessionManager;
import freenet.clients.http.ToadletContainer;
import freenet.config.SubConfig;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.RequestStarter;
import freenet.support.HTMLNode;
import freenet.support.URIPreEncoder;
import freenet.support.api.HTTPRequest;
import freenet.support.plugins.helpers1.WebInterfaceToadlet;

public class PluginRespirator {
	private static final ArrayList<SessionManager> sessionManagers = new ArrayList<SessionManager>(4);
	
	/** For accessing Freenet: simple fetches and inserts, and the data you
	 * need (FetchContext etc) to start more complex ones. */
	private final HighLevelSimpleClient hlsc;
	/** For accessing the node. */
	private final Node node;
	private final FredPlugin plugin;
	private final PluginInfoWrapper pi;
	private final PluginStores stores;

	private PluginStore store;
	
	public PluginRespirator(Node node, PluginInfoWrapper pi) {
		this.node = node;
		this.hlsc = node.clientCore.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, false);
		this.plugin = pi.getPlugin();
		this.pi = pi;
		stores = node.clientCore.getPluginStores();
	}
	
	//public HighLevelSimpleClient getHLSimpleClient() throws PluginSecurityException {
	public HighLevelSimpleClient getHLSimpleClient() {
		return hlsc;
	}
	
	/** Get the node. Use this if you need access to low-level stuff, node config
	 * etc. */
	public Node getNode(){
		return node;
	}

	/** Create a GenericReadFilterCallback, which will filter URLs in 
	 * exactly the same way as the node does when filtering a page.
	 * @param path The base URI for the page being filtered. Not necessarily
	 * a FreenetURI.
	 */
	public FilterCallback makeFilterCallback(String path) {
		try {
			return node.clientCore.createFilterCallback(URIPreEncoder.encodeURI(path), null);
		} catch (URISyntaxException e) {
			throw new Error(e);
		}
	}
	
	/** Get the PageMaker. */
	public PageMaker getPageMaker(){
		ToadletContainer container = getToadletContainer();
		if(container == null) return null;
		return container.getPageMaker();
	}
	
	/**
	 * Add a valid form including the {@link NodeClientCore#formPassword}. See the JavaDoc there for an explanation of the purpose of this mechanism. 
	 * 
	 * <p><b>ATTENTION</b>: It is critically important to validate the form password when processing requests which "change the server state".
	 * Other words for this would be requests which change your database or "write" requests.
	 * Requests which only read values from the server don't have to validate the form password.</p>
	 * 
	 * <p>To validate that the right password was received, use {@link WebInterfaceToadlet#isFormPassword(HTTPRequest)}.</p> 
	 * 
	 * @param parentNode The parent HTMLNode.
	 * @param target Where to post to.
	 * @param name The id/name of the form.
	 * @return The form's HTMLNode. */
	public HTMLNode addFormChild(HTMLNode parentNode, String target, String name) {
		HTMLNode formNode =
			parentNode.addChild("form", new String[] { "action", "method", "enctype", "id", "name", "accept-charset" }, 
					new String[] { target, "post", "multipart/form-data", name, name, "utf-8"} );
		formNode.addChild("input", new String[] { "type", "name", "value" }, 
				new String[] { "hidden", "formPassword", node.clientCore.formPassword });
		
		return formNode;
	}
	
    /**
     * Get a PluginTalker so you can talk with other plugins.
     * 
     * @deprecated Use {@link #connectToOtherPlugin(String,
     *             FredPluginFCPMessageHandler.ClientSideFCPMessageHandler)} instead.
     */
    @Deprecated
	public PluginTalker getPluginTalker(FredPluginTalker fpt, String pluginname, String identifier) throws PluginNotFoundException {
		return new PluginTalker(fpt, node, pluginname, identifier);
	}

    /**
     * <i>NOTICE: This API is a rewrite of the whole code for plugin communication. It was added
     * 2015-03, and for some time after that may change in ways which break backward compatibility.
     * Thus any suggestions or pull requests for improvement of all involved interfaces and classes
     * are welcome!<br>
     * If you would not like to deal with adapting your plugins to possible changes, use the legacy
     * {@link #getPluginTalker(FredPluginTalker, String, String)} API meanwhile.</i><br>
     * 
     * <p>Creates a FCP client connection with another plugin which is a FCP server (= which
     * implements interface {@link FredPluginFCPMessageHandler.ServerSideFCPMessageHandler}).<br>
     * Currently, the remote plugin must run in the same node, but the fact that FCP is used lays
     * foundation for a future implementation to allow you to connect to other plugins by network,
     * no matter where they are running.</p>
     * 
     * <h1>Disconnecting properly</h1>
     * <p>The formally correct mechanism of disconnecting the returned {@link FCPPluginConnection}
     * is to null out the strong reference to it. The node internally keeps a {@link ReferenceQueue}
     * which allows it to detect the strong reference being nulled, which in turn makes the node
     * clean up its internal structures.<br>
     * Thus, you are encouraged to keep the returned {@link FCPPluginConnection} in memory and use
     * it for as long as you need it. Notice that keeping it in memory won't block unloading of the
     * server plugin. If the server plugin is unloaded, the send-functions will fail. To get
     * reconnected once the server plugin is loaded again, you must obtain a fresh client connection
     * from this function: Once an existing client connection is indicated as closed by a single
     * call to a send function throwing {@link IOException}, it <b>must be</b> considered as dead
     * for ever, reconnecting is not possible.<br>
     * While this does seem like you do not have to take care about disconnection at all, you
     * <b>must</b> make sure to not keep an excessive amount of {@link FCPPluginConnection} objects
     * strongly referenced to ensure that this mechanism works. Especially notice that a
     * {@link FCPPluginConnection} is safe and intended to be used for multiple messages, you should
     * <b>not</b> obtain a fresh one for every message you send.<br>
     * Also, you <b>should</b> make sure to periodically try to send a message over the
     * {@link FCPPluginConnection} and check whether you receive a reply to check whether the
     * connection still is alive: There is no other mechanism of indicating a closed connection to
     * you than not getting back any reply to messages you send. So if your plugin does send
     * messages very infrequently, and thus might keep a reference to a dead FCPPluginConnection for
     * a long time, it might be indicated to create a "keepalive-loop" which sends "ping" messages
     * periodically and reconnects if no "pong" message is received within a sane timeout. Whether a
     * server plugin supports a special "ping" message or requires you to use another type of
     * message as ping is left up to the implementation of the server plugin.</p>
     * 
     * <h1>Performance</h1>
     * <br>While you are formally connecting via FCP, there is no actual network connection being
     * created. The FCP messages are passed-through directly as Java objects. Therefore, this
     * mechanism should be somewhat efficient.<br>
     * Thus, plugins should communicate via FCP instead of passing objects of their own Java
     * classes even if they are running within the same node because this encourages implementation
     * of FCP servers, which in turn allows people to write alternative user interfaces for plugins.
     * <br/>Also, this will allow future changes to the node to make it able to run each plugin
     * within its own node and only connect them via real networked FCP connections. This could be
     * used for load balancing of plugins across multiple machines, CPU usage monitoring, sandboxing
     * and other nice stuff.</p>
     * 
     * @param pluginName
     *     The name of the main class of the plugin - that is the class which implements
     *     {@link FredPlugin}. See {@link PluginManager#getPluginInfoByClassName(String)}.
     * @param messageHandler
     *     An object of your plugin which implements the
     *     {@link FredPluginFCPMessageHandler.ClientSideFCPMessageHandler} interface. Its purpose is
     *     to handle FCP messages which the remote plugin sends back to your plugin.
     * @return
     *     A {@link FCPPluginConnection} representing the client connection.<br>
     *     Please do read the whole JavaDoc of this function to know how to use it properly. */
    public FCPPluginConnection connectToOtherPlugin(String pluginName,
            FredPluginFCPMessageHandler.ClientSideFCPMessageHandler messageHandler)
                throws PluginNotFoundException {
        
        if(messageHandler == null)
            throw new NullPointerException("messageHandler must not be null");
        
        // pluginName being null will be handled by createFCPPluginConnectionForIntraNodeFCP().
        
        return node.clientCore.getFCPServer().createFCPPluginConnectionForIntraNodeFCP(pluginName,
            messageHandler);
    }

    /**
     * Allows FCP server plugins, that is plugins which implement
     * {@link FredPluginFCPMessageHandler.ServerSideFCPMessageHandler}, to obtain an existing client
     * {@link FCPPluginConnection} by its {@link UUID} - if the client is still connected.<br><br>
     * 
     * May be used by servers which cannot store objects in memory, for example because they are
     * using a database: An {@link UUID} can be serialized to disk, serialization would not be
     * possible for a {@link FCPPluginConnection}.<br>
     * Servers are however free to instead keep the {@link FCPPluginConnection} in memory, usage
     * of this function is not mandatory.<br><br>
     * 
     * <b>Must not</b> be used by client plugins: They shall instead keep a hard reference to the
     * {@link FCPPluginConnection} in memory after they have received it from
     * {@link #connectToOtherPlugin(String,
     * FredPluginFCPMessageHandler.ClientSideFCPMessageHandler)}. If they did not keep a hard
     * reference and only stored the ID, the {@link FCPPluginConnection} would be garbage collected
     * and thus considered as disconnected.<br><br>
     * 
     * Before you use this function, you <b>should definitely</b> also read the JavaDoc of
     * {@link FredPluginFCPMessageHandler.ServerSideFCPMessageHandler#handlePluginFCPMessage(
     * FCPPluginConnection, FCPPluginMessage)} for full instructions on how to handle the lifecycle
     * of client connections and their disconnection.
     * 
     * @see FredPluginFCPMessageHandler.ServerSideFCPMessageHandler#handlePluginFCPMessage(
     *      FCPPluginConnection, FCPPluginMessage)
     *     The message handler at FredPluginFCPMessageHandler.ServerSideFCPMessageHandler provides
     *     an explanation of when to use this.
     * @param connectionID
     *     The connection's {@link UUID} as obtained by {@link FCPPluginConnection#getID()}.
     * @return
     *     The client connection if it is still connected.
     * @throws IOException
     *     If there has been no client connection with the given ID or if the client has
     *     disconnected already.<br>
     *     If this happens, you should consider the connection {@link UUID} as invalid forever and
     *     discard it. */
    public FCPPluginConnection getPluginConnectionByID(UUID connectionID) throws IOException {
        return node.clientCore.getFCPServer().getPluginConnectionByID(connectionID);
    }

	/** Get the ToadletContainer, which manages HTTP. You can then register
	 * toadlets on it, which allow integrating your plugin into the main
	 * menus, and are a more versatile interface than FredPluginHTTP. */
	public ToadletContainer getToadletContainer() {
		return node.clientCore.getToadletContainer();
	}
	
    /**
	 * Get a PluginStore that can be used by the plugin to put data in a database.
	 * The database used is the node's database, so all the encrypt/decrypt part
	 * is already automatically handled according to the physical security level.
	 * @param storeIdentifier PluginStore identifier, Plugin's name or some other identifier.
	 * @return PluginStore
	 * @throws DatabaseDisabledException
	 */
	public PluginStore getStore() throws PersistenceDisabledException {
	    synchronized(this) {
	        if(store != null) return store;
	        store = stores.loadPluginStore(this.plugin.getClass().getCanonicalName());
	        if(store == null)
	            store = new PluginStore();
	        return store;
	    }
	}

	/**
	 * This should be called by the plugin to store its PluginStore in the node's
	 * database.
	 * @param store Store to put.
	 * @param storeIdentifier Some string to identify the store, basically the plugin's name.
	 * @throws DatabaseDisabledException
	 */
	public void putStore(final PluginStore store) throws PersistenceDisabledException {
	    String name = this.plugin.getClass().getCanonicalName();
	    try {
            stores.writePluginStore(name, store);
        } catch (IOException e) {
            System.err.println("Unable to write plugin data for "+name+" : "+e);
            return;
        }
	}

	/**
	 * Get a new session manager for use with the specified path.
	 * 	See {@link SessionManager} for a detailed explanation of what cookie paths are.
	 * 
	 * The usage of the global "/" path is not allowed. You must use {@link getSessionManager(String cookieNamespace)}
	 * if you want your cookie to be valid in the "/" path.
	 * 
	 * This function is synchronized  on the SessionManager-list and therefore concurrency-proof.
	 * 
	 * @Deprecated We want cookies to be valid in the "/" path for menus to work even if the user is not in the menu of the given
	 * 				plugin. Therefore, we should use cookie namespaces instead.
	 */
	@Deprecated
	public SessionManager getSessionManager(URI cookiePath) {
		synchronized(sessionManagers) {
		for(SessionManager m : sessionManagers) {
			if(m.getCookiePath().equals(cookiePath))
				return m;
		}
		
		final SessionManager m = new SessionManager(cookiePath);
		sessionManagers.add(m);
		return m;
		}
	}
	
	/**
	 * Get a new session manager for use with the global "/" cookie path and the given cookie namespace.
	 * See {@link SessionManager} for a detailed explanation of what cookie namespaces are.
	 * 
	 * This function is synchronized  on the SessionManager-list and therefore concurrency-proof.
	 * 
	 * @param myCookieNamespace The name of the client application which uses this cookie. 
	 */
	public SessionManager getSessionManager(String cookieNamespace) {
		synchronized(sessionManagers) {
		for(SessionManager m : sessionManagers) {
			if(m.getCookieNamespace().equals(cookieNamespace))
				return m;
		}
		
		final SessionManager m = new SessionManager(cookieNamespace);
		sessionManagers.add(m);
		return m;
		}
	}

	/**
	 * Get the plugin's SubConfig. If the plugin does not implement
	 * FredPluginConfigurable, this will return null.
	 */
	public SubConfig getSubConfig() {
		return pi.getSubConfig();
	}

	/**
	 * Force a write of the plugin's config file. If the plugin does
	 * not implement FredPluginConfigurable, don't expect magic to
	 * happen.
	 */
	public void storeConfig() {
		pi.getConfig().store();
	}
}
