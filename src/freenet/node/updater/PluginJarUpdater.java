package freenet.node.updater;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import freenet.client.FetchResult;
import freenet.clients.http.PproxyToadlet;
import freenet.keys.FreenetURI;
import freenet.l10n.NodeL10n;
import freenet.node.RequestClient;
import freenet.node.Version;
import freenet.node.useralerts.AbstractUserAlert;
import freenet.node.useralerts.UserAlert;
import freenet.pluginmanager.PluginInfoWrapper;
import freenet.pluginmanager.PluginManager;
import freenet.support.HTMLNode;
import freenet.support.Logger;
import freenet.support.api.Bucket;
import freenet.support.io.BucketTools;

public class PluginJarUpdater extends NodeUpdater {

	final String pluginName;
	final PluginManager pluginManager;
	private UserAlert alert;
	private boolean deployOnNoRevocation;
	private boolean deployOnNextNoRevocation;
	private boolean readyToDeploy;
	private FetchResult result;
	
	private final Object writeJarSync = new Object();
	private int writtenVersion;

	/**
	 * @return True if the caller should restart the revocation checker.
	 */
	boolean onNoRevocation() {
		synchronized(this) {
			if(!readyToDeploy) return false;
			if(deployOnNoRevocation) {
				// Lets go ...
			} else if(deployOnNextNoRevocation) {
				deployOnNoRevocation = true;
				deployOnNextNoRevocation = false;
				System.out.println("Deploying "+pluginName+" after next revocation check");
				return true;
			} else
				return false;
		}
		// Deploy it!
		if (!pluginManager.isPluginLoaded(pluginName)) {
			Logger.error(this, "Plugin is not loaded, so not deploying: "+pluginName);
			tempBlobFile.delete();
			return false;
		}
		System.out.println("Deploying new version of "+pluginName+" : unloading old version...");
		// Write the new version of the plugin before shutting down, so if there is a deadlock in terminate, we will still get the new version after a restart.
		try {
			writeJar();
		} catch (IOException e) {
			Logger.error(this, "Cannot deploy: "+e, e);
			System.err.println("Cannot deploy new version of "+pluginName+" : "+e);
			e.printStackTrace();
			return false; // Not much we can do ...
			// FIXME post a useralert
		}
		pluginManager.killPluginByFilename(pluginName, Integer.MAX_VALUE, true);
		pluginManager.startPluginAuto(pluginName, true);
		UserAlert a;
		synchronized(this) {
			a = alert;
			alert = null;
		}
		node.clientCore.alerts.unregister(a);
		return false;
	}
	
	PluginJarUpdater(NodeUpdateManager manager, FreenetURI URI, int current, int min, int max, String blobFilenamePrefix, String pluginName, PluginManager pm) {
		super(manager, URI, current, min, max, blobFilenamePrefix);
		this.pluginName = pluginName;
		this.pluginManager = pm;
	}

	@Override
	public String jarName() {
		return pluginName;
	}

	private int requiredNodeVersion;
	
	private static final String REQUIRED_NODE_VERSION_PREFIX = "Required-Node-Version: ";
	
	@Override
	protected void maybeParseManifest(FetchResult result) {
		requiredNodeVersion = -1;
		parseManifest(result);
		if(requiredNodeVersion != -1) {
			System.err.println("Required node version for plugin "+pluginName+": "+requiredNodeVersion);
			Logger.normal(this, "Required node version for plugin "+pluginName+": "+requiredNodeVersion);
		}
	}
	
	@Override
	protected void parseManifestLine(String line) {
		if(line.startsWith(REQUIRED_NODE_VERSION_PREFIX)) {
			requiredNodeVersion = Integer.parseInt(line.substring(REQUIRED_NODE_VERSION_PREFIX.length()));
		}
	}
	
	@Override
	protected void onStartFetching() {
		System.err.println("Starting to fetch plugin "+pluginName);
	}

	@Override
	protected void processSuccess(int build, FetchResult result, File blob) {
		Bucket oldResult = null;
		synchronized(this) {
			if(requiredNodeVersion > Version.buildNumber()) {
				System.err.println("Found version "+fetchedVersion+" of "+pluginName+" but needs node version "+requiredNodeVersion);
				// FIXME deploy it with the main jar
				tempBlobFile.delete();
				return;
			}
			if(this.result != null)
				oldResult = this.result.asBucket();
			this.result = result;
		}
		if(oldResult != null) oldResult.free();
		
		PluginInfoWrapper loaded = pluginManager.getPluginInfo(pluginName);
		
		if(loaded == null) {
			if(!node.pluginManager.isPluginLoadedOrLoadingOrWantLoad(pluginName)) {
				System.err.println("Don't want plugin: "+pluginName);
				Logger.error(this, "Don't want plugin: "+pluginName);
				tempBlobFile.delete();
				return;
			}
		}
		
		if(loaded.getPluginLongVersion() >= fetchedVersion) {
			tempBlobFile.delete();
			return;
		}
		// Create a useralert to ask the user to deploy the new version.
		
		UserAlert toRegister = null;
		synchronized(this) {
			readyToDeploy = true;
			if(alert != null) return;
			
			toRegister = alert = new AbstractUserAlert(true, l10n("pluginUpdatedTitle", "name", pluginName), l10n("pluginUpdatedText", "name", pluginName), l10n("pluginUpdatedShortText", "name", pluginName), null, UserAlert.ERROR, true, NodeL10n.getBase().getString("UserAlert.hide"), true, this) {
				
				@Override
				public void onDismiss() {
					synchronized(PluginJarUpdater.this) {
						alert = null;
					}
				}
				
				@Override
				public HTMLNode getHTMLText() {
					HTMLNode div = new HTMLNode("div");
					// Text saying the plugin has been updated...
					synchronized(this) {
					
						if(deployOnNoRevocation || deployOnNextNoRevocation) {
							div.addChild("#", l10n("willDeployAfterRevocationCheck", "name", pluginName));
						} else {
							div.addChild("#", l10n("pluginUpdatedText", new String[] { "name", "newVersion" }, new String[] { pluginName, Long.toString(fetchedVersion) }));
							
							// Form to deploy the updated version.
							// This is not the same as reloading because we haven't written it yet.
							
							HTMLNode formNode = div.addChild("form", new String[] { "action", "method" }, new String[] { PproxyToadlet.PATH, "post" });
							formNode.addChild("input", new String[] { "type", "name", "value" }, new String[] { "hidden", "formPassword", node.clientCore.formPassword });
							formNode.addChild("input", new String[] { "type", "name", "value" }, new String[] { "hidden", "update", pluginName });
							formNode.addChild("input", new String[] { "type", "value" }, new String[] { "submit", l10n("updatePlugin") });
						}
					}
					return div;
				}
			};
		}
		if(toRegister != null)
			node.clientCore.alerts.register(toRegister);
	}

	private String l10n(String key) {
		return NodeL10n.getBase().getString("PluginJarUpdater."+key);
	}

	private String l10n(String key, String name, String value) {
		return NodeL10n.getBase().getString("PluginJarUpdater."+key, name, value);
	}

	private String l10n(String key, String[] names, String[] values) {
		return NodeL10n.getBase().getString("PluginJarUpdater."+key, names, values);
	}
	
	public void writeJarTo(FetchResult result, File fNew) throws IOException {
		int fetched;
		synchronized(this) {
			fetched = fetchedVersion;
		}
		synchronized(writeJarSync) {
			if (!fNew.delete() && fNew.exists()) {
				System.err.println("Can't delete " + fNew + "!");
			}

			FileOutputStream fos;
			fos = new FileOutputStream(fNew);

			BucketTools.copyTo(result.asBucket(), fos, -1);

			fos.flush();
			fos.close();
		}
		synchronized(this) {
			writtenVersion = fetched;
		}
		System.err.println("Written " + jarName() + " to " + fNew);
	}

	void writeJar() throws IOException {
		writeJarTo(result, pluginManager.getPluginFilename(pluginName));
		UserAlert a;
		synchronized(this) {
			a = alert;
			alert = null;
		}
		if(a != null)
			node.clientCore.alerts.unregister(a);
	}

	@Override
	void kill() {
		super.kill();
		UserAlert a;
		synchronized(this) {
			a = alert;
			alert = null;
		}
		if(a != null)
			node.clientCore.alerts.unregister(a);
	}

	public synchronized void arm(boolean wasRunning) {
		if(wasRunning) {
			deployOnNextNoRevocation = true;
			System.out.println("Deploying "+pluginName+" after next but one revocation check");
		} else {
			deployOnNoRevocation = true;
			System.out.println("Deploying "+pluginName+" after next revocation check");
		}
	}

	@Override
	public RequestClient getRequestClient() {
		return pluginManager.singleUpdaterRequestClient;
	}
	
}
