package freenet.pluginmanager;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.HashSet;

import freenet.clients.http.ConfigToadlet;
import freenet.config.Config;
import freenet.config.FilePersistentConfig;
import freenet.config.SubConfig;
import freenet.l10n.NodeL10n;
import freenet.node.Node;
import freenet.support.JarClassLoader;
import freenet.support.Logger;
import freenet.support.io.Closer;

public class PluginInfoWrapper implements Comparable<PluginInfoWrapper> {

	private final String className;
	private Thread thread;
	private final long start;
	final PluginRespirator pr;
	private final String threadName;
	final FredPlugin plug;
	private final Config config;
	private final SubConfig subconfig;
	private final ConfigToadlet configToadlet;
	private final boolean isPproxyPlugin;
	private final boolean isThreadlessPlugin;
	private final boolean isIPDetectorPlugin;
	private final boolean isBandwidthIndicator;
	private final boolean isPortForwardPlugin;
	private final boolean isMultiplePlugin;
    /** Use {@link #isFCPServerPlugin} instead. */
    @Deprecated
    private final boolean isFCPPlugin;
    private final boolean isFCPServerPlugin;
	private final boolean isVersionedPlugin;
	private final boolean isLongVersionedPlugin;
	private final boolean isThemedPlugin;
	private final boolean isL10nPlugin;
	private final boolean isBaseL10nPlugin;
	private final boolean isConfigurablePlugin;
	private final boolean isOfficialPlugin;
	private final String filename;
	private HashSet<String> toadletLinks = new HashSet<String>();
	private volatile boolean stopping = false;
	private volatile boolean unregistered = false;
	
	public PluginInfoWrapper(Node node, FredPlugin plug, String filename, boolean isOfficial) throws IOException {
		this.plug = plug;
		className = plug.getClass().toString();
		this.filename = filename;
		this.pr = new PluginRespirator(node, this);
		threadName = 'p' + className.replaceAll("^class ", "") + '_' + hashCode();
		start = System.currentTimeMillis();

        // TODO: Code quality: Do we really need to cache these values? I don't care about the
        // memory overhead, but it's the pointless clutter it causes in the member variables, while
        // the information is right there and always accessible in the runtime type of plug.
        // When fixing this, please also consider the TODO at getFCPServerPlugin(). 
		isBandwidthIndicator = (plug instanceof FredPluginBandwidthIndicator);
		isPproxyPlugin = (plug instanceof FredPluginHTTP);
		isThreadlessPlugin = (plug instanceof FredPluginThreadless);
		isIPDetectorPlugin = (plug instanceof FredPluginIPDetector);
		isPortForwardPlugin = (plug instanceof FredPluginPortForward);
		isMultiplePlugin = (plug instanceof FredPluginMultiple);
        isFCPPlugin = (plug instanceof FredPluginFCP);
        isFCPServerPlugin
            = (plug instanceof FredPluginFCPMessageHandler.ServerSideFCPMessageHandler);
		isVersionedPlugin = (plug instanceof FredPluginVersioned);
		isLongVersionedPlugin = (plug instanceof FredPluginRealVersioned);
		isThemedPlugin = (plug instanceof FredPluginThemed);
		isL10nPlugin = (plug instanceof FredPluginL10n);
		isBaseL10nPlugin = (plug instanceof FredPluginBaseL10n);
		isConfigurablePlugin = (plug instanceof FredPluginConfigurable);
		if(isConfigurablePlugin) {
			config = FilePersistentConfig.constructFilePersistentConfig(new File(node.getCfgDir(), "plugin-"+getPluginClassName()+".ini"),
			             "config options for plugin: "+getPluginClassName());
			subconfig = config.createSubConfig(getPluginClassName());
			((FredPluginConfigurable)plug).setupConfig(subconfig);
			config.finishedInit();
			configToadlet = new ConfigToadlet(pr.getHLSimpleClient(), config, subconfig, node, node.clientCore, (FredPluginConfigurable)plug);
		} else {
			config = null;
			subconfig = null;
			configToadlet = null;
		}
		isOfficialPlugin = isOfficial;
	}

	void setThread(Thread ps) {
		if(thread != null)
			throw new IllegalStateException("Already set a thread");
		thread = ps;
		thread.setName(threadName);
	}
	
	@Override
	public String toString() {
		return "ID: \"" +threadName + "\", Name: "+ className +", Started: " + (new Date(start)).toString();
	}
	
	public String getThreadName() {
		return threadName;
	}
	
	public long getStarted() {
		return start;
	}
	
	public String getPluginClassName(){
		return plug.getClass().getName();
	}
	
	public String getPluginVersion() {
		if (isVersionedPlugin) {
			return ((FredPluginVersioned)plug).getVersion();
		} else {
			return NodeL10n.getBase().getString("PproxyToadlet.noVersion");
		}
	}
	
	public synchronized String[] getPluginToadletSymlinks(){
		return toadletLinks.toArray(new String[0]);
	}
	
	public synchronized boolean addPluginToadletSymlink(String linkfrom){
		if (toadletLinks.size() < 1)
			toadletLinks = new HashSet<String>();
		return toadletLinks.add(linkfrom);
	}
	
	public synchronized boolean removePluginToadletSymlink(String linkfrom){
		if (toadletLinks.size() < 1)
			return false;
		return toadletLinks.remove(linkfrom);
	}
	
	public void startShutdownPlugin(PluginManager manager, boolean reloading) {
		unregister(manager, reloading);
		// TODO add a timeout for plug.terminate() too
		System.out.println("Terminating plugin "+this.getFilename());
		try {
			plug.terminate();
		} catch (Throwable t) {
			Logger.error(this, "Error while terminating plugin.", t);
			System.err.println("Error while terminating plugin: "+t);
			t.printStackTrace();
		}
		synchronized(this) {
			stopping = true;
		}
	}

	public boolean finishShutdownPlugin(long maxWaitTime) {
		boolean success = true;
		if(thread != null) {
			thread.interrupt();
			// Will be removed when the thread exits.
			if(maxWaitTime >= 0) {
				try {
					thread.join(maxWaitTime);
				} catch (InterruptedException e) {
					Logger.normal(this, "stopPlugin interrupted while join()ed to terminating plugin thread - maybe one plugin stopping another???");
				}
				if(thread.isAlive()) {
					String error = "Waited for "+thread+" for "+plug+" to exit for "+maxWaitTime+"ms, and it is still alive!";
					Logger.error(this, error);
					System.err.println(error);
					success = false;
				}
			}
		}
		
		// Close the jar file, so we may delete / reload it
		ClassLoader cl = plug.getClass().getClassLoader();
		if (cl instanceof JarClassLoader) {
			Closer.close((JarClassLoader) cl);
		}
		return success;
	}
	
	/**
	 * Tell the plugin to quit. Interrupt it if it's a thread-based plugin which
	 * might be sleeping. Then call removePlugin() on it on the manager - either
	 * now, if it's threadless, or after it terminates, if it's thread based.
	 * @param manager The plugin manager object.
	 * @param maxWaitTime If a plugin is thread-based, we can wait for it to
	 * terminate. Set to -1 if you don't want to wait at all, 0 to wait forever
	 * or else a value in milliseconds.
	 **/
	public void stopPlugin(PluginManager manager, long maxWaitTime, boolean reloading) {
		startShutdownPlugin(manager, reloading);
		finishShutdownPlugin(maxWaitTime);
		// always remove plugin
		manager.removePlugin(this);
	}
	
	/**
	 * Unregister the plugin from any user interface or other callbacks it may be
	 * registered with. Call this before manager.removePlugin(): the plugin becomes
	 * unvisitable immediately, but it may take time for it to shut down completely.
	 */
	void unregister(PluginManager manager, boolean reloading) {
		synchronized(this) {
			if(unregistered) return;
			unregistered = true;
		}
		manager.unregisterPlugin(this, plug, reloading);
	}

	public boolean isPproxyPlugin() {
		return isPproxyPlugin;
	}

	public String getFilename() {
		return filename;
	}
	
	public boolean isBandwidthIndicator() {
		return isBandwidthIndicator;
	}

	public boolean isThreadlessPlugin() {
		return isThreadlessPlugin;
	}

	public boolean isIPDetectorPlugin() {
		return isIPDetectorPlugin;
	}
	
	public boolean isPortForwardPlugin() {
		return isPortForwardPlugin;
	}

	public boolean isMultiplePlugin() {
		return isMultiplePlugin;
	}

    /**
     * @deprecated Use {@link #isFCPServerPlugin()}
     */
    @Deprecated
    public boolean isFCPPlugin() {
        return isFCPPlugin;
    }

    public boolean isFCPServerPlugin() {
        return isFCPServerPlugin;
    }

    /**
     * If {@link #isFCPServerPlugin()} returns true, may be called to obtain the
     * {@link FredPluginFCPMessageHandler.ServerSideFCPMessageHandler} of the plugin.<br><br>
     * 
     * TODO: Code quality: Currently, all the other is...() functions are used by PluginManager
     * just to then manually cast the plugin main object to the desired type, i.e. it manually
     * does what the body of this function does. This restricts the API to require the plugin main
     * class to implement all the various interfaces. Instead, please add equivalents of this 
     * function for all the other is...(), and use those new functions everywhere in PluginManager.
     * This will a preparation for allowing plugins to implement the various interfaces in DIFFERENT
     * classes than their plugin main class - which will be a good idea for keeping plugin main
     * classes short.
     */
    public FredPluginFCPMessageHandler.ServerSideFCPMessageHandler
            getFCPServerPlugin() {

        return (FredPluginFCPMessageHandler.ServerSideFCPMessageHandler)plug;
    }

	public boolean isThemedPlugin() {
		return isThemedPlugin;
	}

	public boolean isL10nPlugin() {
		return isL10nPlugin;
	}

	public boolean isBaseL10nPlugin() {
		return isBaseL10nPlugin;
	}
	
	public boolean isConfigurablePlugin() {
		return isConfigurablePlugin;
	}

	public synchronized boolean isStopping() {
		return stopping;
	}

	public long getPluginLongVersion() {
		if (isLongVersionedPlugin) {
			return ((FredPluginRealVersioned)plug).getRealVersion();
		} else {
			return -1;
		}
	}

	public FredPlugin getPlugin() {
		return this.plug;
	}

	public PluginRespirator getPluginRespirator() {
		return pr;
	}

	@Override
	public int compareTo(PluginInfoWrapper pi) {
		return className.compareTo(pi.className);
	}

	public Config getConfig() {
		return config;
	}

	public SubConfig getSubConfig() {
		return subconfig;
	}

	public ConfigToadlet getConfigToadlet() {
		return configToadlet;
	}

	public boolean isOfficialPlugin() {
		return isOfficialPlugin;
	}

	public String getLocalisedPluginName() {
		String pluginName = getFilename();
		if(isOfficialPlugin())
			return PluginManager.getOfficialPluginLocalisedName(pluginName);
		else return pluginName;
	}
}
