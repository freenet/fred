/**
 * A server to communicate with darknet app on mobiles on the lines of SimpleToadletServer
 */
package freenet.darknetapp;

import freenet.config.InvalidConfigValueException;
import freenet.config.NodeNeedRestartException;
import freenet.config.SubConfig;
import freenet.crypt.BCModifiedSSL;
import freenet.io.BCSSLNetworkInterface;
import freenet.io.NetworkInterface;
import freenet.l10n.NodeL10n;
import freenet.node.Node;
import freenet.node.PrioRunnable;
import freenet.support.Executor;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.OOMHandler;
import freenet.support.api.BooleanCallback;
import freenet.support.api.IntCallback;
import freenet.support.api.StringCallback;
import freenet.support.io.NativeThread;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import org.tanukisoftware.wrapper.WrapperManager;


/**
 * @author Illutionist
 * TODO: A general server base class that extends to SimpleToadletServer, FCPServer, DarknetAppServer etc.
 *       Many functions are rewritten in this implementation as SimpleToadletServer was linked heavily with fproxy 
 */
public class DarknetAppServer implements Runnable {
    private boolean enabled = true;
    private final int DEFAULT_PORT = 7859; 
    private String allowedHosts;
    private String bindTo;
    private int port = DEFAULT_PORT;
    private Thread myThread;
    private final Executor executor;
    private static Node node;
    private NetworkInterface networkInterface;
    private int maxDarknetAppConnections =10;	
    private int darknetAppConnections;
    private boolean finishedStartup = false;
    private int numPendingPeersCount = 0;
    public static String filename = "TempPeersFromDarknetApp.prop";
    public  List<String> pendingPeersNoderefList = new ArrayList<>();
            
    private static volatile boolean logMINOR;
	static {
            Logger.registerLogThresholdCallback(new LogThresholdCallback(){
                    @Override
                    public void shouldUpdate(){
                            logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
                    }
            });
	}
    public boolean isEnabled() {
        return myThread != null;
    }
    
    /**
     *  To be called by the node
     */
    public void start() {
        if (!enabled) return;
        if(myThread != null) {
            try {
                maybeGetNetworkInterface(true);
            } catch (IOException ex) {
                Logger.error(this,"Couldn't start DarkentAppServer - IOException",ex);
                return;
            }
                myThread.start();
                Logger.normal(this, "Starting DarknetAppServer on "+bindTo+ ':' +port);
        }
    }
    /*
     * To be called by the node
     */
    public void finishStartup() {
        synchronized(DarknetAppServer.class) {
            this.finishedStartup = true;
        }
    }
    public String getNodeRef() {
        if (!finishedStartup) return "";
        return node.exportDarknetPublicFieldSet().toString();
    }
    public DarknetAppServer(SubConfig darknetAppConfig, Node node, Executor executor) {
        this.executor = executor;
        this.node = node;
        int configItemOrder = 0;
   
        //  allowedHosts - "*" to allow all, bindTo - "0.0.0.0" to accept on all interfaces
        darknetAppConfig.register("numPendingPeersCount",0, configItemOrder++, true, true, "DarknetAppServer.newPeersCount", "DarknetAppServer.newPeersCountLong",
				new numPendingPeersCallback(), false);
        this.numPendingPeersCount = darknetAppConfig.getInt("numPendingPeersCount");
        darknetAppConfig.register("enabled", true, configItemOrder++, true, true, "DarknetAppServer.enabled", "DarknetAppServer.enabledLong",
				new  darknetAppEnabledCallback());
        this.enabled = darknetAppConfig.getBoolean("enabled");
        darknetAppConfig.register("port", DEFAULT_PORT, configItemOrder++, true, true, "DarknetAppServer.port", "DarknetAppServer.portLong",
				new darknetAppPortCallback(), false);
        this.port = darknetAppConfig.getInt("port");
        darknetAppConfig.register("allowedHosts", "*", configItemOrder++, true, true, "DarknetAppServer.allowedHosts", "DarknetAppServer.allowedHostsLong", 
                                new  darknetAppAllowedHostsCallback());				
        this.allowedHosts = darknetAppConfig.getString("allowedHosts");
        darknetAppConfig.register("bindTo", "0.0.0.0", configItemOrder++, true, true, "DarknetAppServer.bindTo", "DarknetAppServer.bindToLong",
				new darknetAppBindtoCallback());
        this.bindTo = darknetAppConfig.getString("bindTo"); 
        try {
            //always enable SSL - false to use plaintext
            maybeGetNetworkInterface(true);
        } catch (IOException ex) {
            Logger.error(this,"Couldn't start DarkentAppServer - IOException",ex);
            return;
        }
        loadTempRefsFile();
        if (!enabled) {
            myThread=null;
        }
        else {
            myThread = new Thread(this, "DarknetAppServer");
            myThread.setDaemon(true);
        }
        updatePendingPeersNoderefList(numPendingPeersCount);
    }

    /**
     * A properties file that stores the temporary node references
     * These references are yet to be approved by the node
     * As soon as user takes an action about these new peers, their reference would be removed
     */
    private void loadTempRefsFile() {
        File file = new File(filename);
        if (!file.exists()) try {
            file.createNewFile();
        } catch (IOException ex) {
            Logger.error(this,"Error Creating File To Save Exchanged Nodereferences"+ex);
        }
    }
    public void updatePendingPeersNoderefList(int numPendingPeers) {
        pendingPeersNoderefList.clear();
        if (numPendingPeers==0) return;
        Properties prop = new Properties();
        try {
            File file =  new File(DarknetAppServer.filename);
            prop.load(new FileInputStream(file));
        } catch (FileNotFoundException ex) {
            Logger.error(this, "Darknet App New Peers File Not Found",ex);
        } catch (IOException ex) {
            //File in Use..i.e. Synchronize with mobile is happening presently
            Logger.error(this, "File in Use - Synchronize with mobile is happening presently",ex);
        }
        for (int i=1;i<=numPendingPeers;i++) {
            pendingPeersNoderefList.add(prop.getProperty("newPeer"+i));
        }
    }
     /**
     * To change the temporary peers count. Mostly used by DarknetAppConnectionhandler and ConnectionsToadlet
     * @param count
     */
    public synchronized void changeNumPendingPeersCount(int count) {
        if (count==numPendingPeersCount) return;
        try {
            SubConfig darknetAppConfig = node.config.get("darknetApp");
            darknetAppConfig.set("numPendingPeersCount", String.valueOf(count));
            node.config.store();
            numPendingPeersCount = count;
            updatePendingPeersNoderefList(count);
        } catch (InvalidConfigValueException | NodeNeedRestartException ex) {
            Logger.error(this, "Exception while trying to change pendingpeers count",ex);
        }
    }
    public synchronized int getNumPendingPeersCount() {
        return numPendingPeersCount;
    }
    //Modified from SimpleToadletServer to use BCSSLNetworkInterface instead of SSLNetworkInterface
    private void maybeGetNetworkInterface(boolean ssl) throws IOException {
        if (this.networkInterface!=null) return;
        if(ssl) {
            if (!BCModifiedSSL.available()) throw new IOException();
            Logger.normal(this,"Certificate Pin-->>" + BCModifiedSSL.getSelfSignedCertificatePin());
            this.networkInterface = BCSSLNetworkInterface.create(port, this.bindTo, allowedHosts, executor, false);
        } else {
            this.networkInterface = NetworkInterface.create(port, this.bindTo, allowedHosts, executor, true);
        }
    }

    public String getPendingPeerNodeRef(int i) {
        return pendingPeersNoderefList.get(i-1);
    }
    public List<String> getPendingPeersNoderefList() {
        return ((List<String>) ((ArrayList) pendingPeersNoderefList).clone());
    }
    /**
     * This is necessary to be in the config for advanced users.
     * In case of an attack where our homeNode is bombarded with new references, the user can shift this to 0 and/or disable this server (using other config option)
     * Unnecessary changing of this value might cause instability in this app and/or losing temporary peer node references and so for advanced users
     */
    private class numPendingPeersCallback extends IntCallback {
        @Override
        public Integer get() {
            return numPendingPeersCount;
        }

        @Override
        public void set(Integer val) throws InvalidConfigValueException, NodeNeedRestartException {
            synchronized(DarknetAppServer.class) {
                numPendingPeersCount = val;
            }
        }
    }
    
    // Copied from SimpleToadletServer
    private class darknetAppBindtoCallback extends StringCallback  {
            @Override
            public String get() {
                    return bindTo;
            }

            @Override
            public void set(String bindTo) throws InvalidConfigValueException {
                    String oldValue = get();
                    if(!bindTo.equals(oldValue)) {
                            String[] failedAddresses = networkInterface.setBindTo(bindTo, false);
                            if(failedAddresses == null) {
                                    DarknetAppServer.this.bindTo = bindTo;
                            } else {
                                    // This is an advanced option for reasons of reducing clutter,
                                    // but it is expected to be used by regular users, not devs.
                                    // So we translate the error messages.
                                    networkInterface.setBindTo(oldValue, false);
                                    throw new InvalidConfigValueException(l10n("couldNotChangeBindTo", "failedInterfaces", Arrays.toString(failedAddresses)));
                            }
                    }
            }
    }
    
    // Copied from SimpleToadletServer
    private class darknetAppAllowedHostsCallback extends StringCallback  {
            @Override
            public String get() {
                    return networkInterface.getAllowedHosts();
            }

            @Override
            public void set(String allowedHosts) throws InvalidConfigValueException {
                    if (!allowedHosts.equals(get())) {
                            try {
                            networkInterface.setAllowedHosts(allowedHosts);
                            } catch(IllegalArgumentException e) {
                                    throw new InvalidConfigValueException(e);
                            }
                    }
            }
    }
    /**
     * When an advanced user changes port, the server is restarted on the fly
     * Although, the MDNS plugin might have to be restarted as it would still be broadcasting the old port
     */
    private class darknetAppPortCallback extends IntCallback  {
        @Override
        public Integer get() {
                return port;
        }

        @Override
        public void set(Integer newPort) throws NodeNeedRestartException {
                if(port != newPort) {
                      port = newPort;
                      try {
                          maybeGetNetworkInterface(true);
                      }
                      catch (IOException e) {
                          Logger.error(this,"Error while changing port",e);
                      }
                      if (enabled) {
                          synchronized(DarknetAppServer.class) {
                               myThread.interrupt();
                               myThread = new Thread(DarknetAppServer.this, "DarknetAppServer");
                               myThread.setDaemon(true);
                               myThread.start(); 
                               Logger.normal(this,"Restarting DarknetAppServer on "+bindTo+ ':' +port);
                          }
                      }
                }
        }
    }
    /**
     * Allows on the fly enabling and disabling
     */
    private class darknetAppEnabledCallback extends BooleanCallback  {
        @Override
        public Boolean get() {
                synchronized(DarknetAppServer.class) {
                        return myThread != null;
                }
        }
        @Override
        public void set(Boolean val) throws InvalidConfigValueException {
                if (get().equals(val))
                        return;
                synchronized(DarknetAppServer.class) {
                        if(val) {
                                // Start it
                                enabled = true;
                                myThread = new Thread(DarknetAppServer.this, "DarknetAppServer");
                        } else {
                                enabled = false;
                                myThread.interrupt();
                                myThread = null;
                                return;
                        }
                }
                myThread.setDaemon(true);
                myThread.start();
        }
    }
    
    private static String l10n(String key, String pattern, String value) {
        return NodeL10n.getBase().getString("DarknetAppServer."+key, pattern, value);
    }
    
    @Override
    public void run() {
    	if (networkInterface==null) {
    		Logger.error(this, "Could not start DarknetAppServer");
    		return;
    	}
        try {
            networkInterface.setSoTimeout(500);
	} catch (SocketException e1) {
            Logger.error(this, "Could not set so-timeout to 500ms; on-the-fly disabling of the interface will not work");
	}
    while(true) {
        synchronized(DarknetAppServer.class) {
                while(darknetAppConnections > maxDarknetAppConnections) {
                        try {
                            wait();
                        } catch (InterruptedException e) {
                                // Ignore
                        }
                }
                if(myThread == null) return;
        }
        Socket conn = networkInterface.accept();
        if (WrapperManager.hasShutdownHookBeenTriggered())
        if(conn == null)
            continue; // timeout
        if(logMINOR)
            Logger.minor(this, "Accepted connection");
        SocketHandler sh = new SocketHandler(conn);
        sh.start();
        }
    }
    //Modified to suit needs from SimpleToadletServer
    public class SocketHandler implements PrioRunnable {
        Socket sock;

        public SocketHandler(Socket conn) {
                this.sock = conn;
        }

        // A thread starts for each accepted socket connection
        void start() {
            new Thread(this).start();   
        }
        
        @Override
        public void run() {
            freenet.support.Logger.OSThread.logPID(this);
            synchronized(DarknetAppServer.class) {
                darknetAppConnections++;
            } 
                if(logMINOR) Logger.minor(this, "Handling connection");
                try {
                    // Handle the connected socket here. The data transfer to/from the mobile occurs in the following function
                    DarknetAppConnectionHandler.handle(sock,DarknetAppServer.this,node);
                } catch (OutOfMemoryError e) {
                        OOMHandler.handleOOM(e);
                        Logger.error(this, "OOM in SocketHandler");
                } catch (Throwable t) {
                        Logger.error(this, "Caught in DarknetAppServer: "+t, t);
                } finally {
                    synchronized(DarknetAppServer.class) {
                        darknetAppConnections--;
                        DarknetAppServer.class.notifyAll();
                    }
                }
                if(logMINOR) Logger.minor(this, "Handled connection");
        }

        @Override
        public int getPriority() {
                return NativeThread.HIGH_PRIORITY-3;
        }
    }   
}