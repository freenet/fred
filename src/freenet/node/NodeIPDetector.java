package freenet.node;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import freenet.config.InvalidConfigValueException;
import freenet.config.SubConfig;
import freenet.io.comm.FreenetInetAddress;
import freenet.io.comm.Peer;
import freenet.io.comm.UdpSocketHandler;
import freenet.l10n.NodeL10n;
import freenet.node.useralerts.IPUndetectedUserAlert;
import freenet.node.useralerts.InvalidAddressOverrideUserAlert;
import freenet.node.useralerts.SimpleUserAlert;
import freenet.node.useralerts.UserAlert;
import freenet.pluginmanager.DetectedIP;
import freenet.pluginmanager.FredPluginBandwidthIndicator;
import freenet.pluginmanager.FredPluginIPDetector;
import freenet.pluginmanager.FredPluginPortForward;
import freenet.support.HTMLNode;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.StringCallback;
import freenet.support.io.NativeThread;
import freenet.support.transport.ip.HostnameSyntaxException;
import freenet.support.transport.ip.IPAddressDetector;
import freenet.support.transport.ip.IPUtil;

/**
 * Detect the IP address of the node. Doesn't return port numbers, doesn't have access to per-port
 * information (NodeCrypto - UdpSocketHandler etc).
 */
public class NodeIPDetector {
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

	/** Parent node */
	final Node node;
	/** Ticker */
	/** Explicit forced IP address */
	FreenetInetAddress overrideIPAddress;
	/** Explicit forced IP address in string form because we want to keep it even if it's invalid and therefore unused */
	String overrideIPAddressString;
	/** IP address from last time */
	FreenetInetAddress oldIPAddress;
	/** Detected IP's and their NAT status from plugins */
	DetectedIP[] pluginDetectedIPs;
	/** Last detected IP address */
	FreenetInetAddress[] lastIPAddress;
	
	private class MinimumMTU {
		
		/** The minimum reported MTU on all detected interfaces */
		private int minimumMTU = Integer.MAX_VALUE;

		/** Report a new MTU from an interface or detector.
		 * If the minimum MTU has changed, returns true. */
		boolean report(int mtu) {
			if(mtu <= 0) return false;
			if(mtu < minimumMTU) {
				Logger.normal(this, "Reducing the MTU to "+minimumMTU);
				minimumMTU = mtu;
				return true;
			}
			return false;
		}

		public int get() {
			return minimumMTU > 0 ? minimumMTU : 1500;
		}

	}
	
	private final MinimumMTU minimumMTUIPv4 = new MinimumMTU();
	private final MinimumMTU minimumMTUIPv6 = new MinimumMTU();
	
	/** IP address detector */
	private final IPAddressDetector ipDetector;
	/** Plugin manager for plugin IP address detectors e.g. STUN */
	final IPDetectorPluginManager ipDetectorManager;
	/** UserAlert shown when ipAddressOverride has a hostname/IP address syntax error */
	private InvalidAddressOverrideUserAlert invalidAddressOverrideAlert;
	private boolean hasValidAddressOverride;
	/** UserAlert shown when we can't detect an IP address */
	private IPUndetectedUserAlert primaryIPUndetectedAlert;
	// FIXME redundant? see lastIPAddress
	FreenetInetAddress[] lastIP;
	/** Set when we have grounds to believe that we may be behind a symmetric NAT. */
	boolean maybeSymmetric;
	/** Have the detector plugins been queried (or found to be non-existent)? */
	private boolean hasDetectedPM;
	/** Have we checked peers and local interfaces for our IP address? */
	private boolean hasDetectedIAD;
	/** Subsidiary detectors: NodeIPPortDetector's which rely on this object */
	private NodeIPPortDetector[] portDetectors;
	private boolean hasValidIP;
	private boolean firstDetection = true;
	
	SimpleUserAlert maybeSymmetricAlert;
	
	public NodeIPDetector(Node node) {
		this.node = node;
		ipDetectorManager = new IPDetectorPluginManager(node, this);
		ipDetector = new IPAddressDetector(SECONDS.toMillis(10), this);
		invalidAddressOverrideAlert = new InvalidAddressOverrideUserAlert(node);
		primaryIPUndetectedAlert = new IPUndetectedUserAlert(node);
		portDetectors = new NodeIPPortDetector[0];
	}

	public synchronized void addPortDetector(NodeIPPortDetector detector) {
		portDetectors = Arrays.copyOf(portDetectors, portDetectors.length+1);
		portDetectors[portDetectors.length - 1] = detector;
	}
	
	/**
	 * What is my IP address? Use all globally available information (everything which isn't
	 * specific to a given port i.e. opennet or darknet) to determine our current IP addresses.
	 * Will include more than one IP in many cases when we are not strictly multi-homed. For 
	 * example, if we have a DNS name set, we will usually return an IP as well.
	 * 
	 * Will warn the user with a UserAlert if we don't have sufficient information.
	 */
	FreenetInetAddress[] detectPrimaryIPAddress(boolean dumpLocalAddresses) {
		boolean addedValidIP = false;
		Logger.minor(this, "Redetecting IPs...");
		ArrayList<FreenetInetAddress> addresses = new ArrayList<FreenetInetAddress>();
		if(overrideIPAddress != null) {
			// If the IP is overridden and the override is valid, the override has to be the first element.
			// overrideIPAddress will be null if the override is invalid
			addresses.add(overrideIPAddress);
			if(overrideIPAddress.isRealInternetAddress(false, true, false))
				addedValidIP = true;
		}
		
		if(!node.dontDetect()) {
			addedValidIP |= innerDetect(addresses);
		}
		
	   	if(node.clientCore != null) {
	   		boolean hadValidIP;
	   		synchronized(this) {
	   			hadValidIP = hasValidIP;
	   			hasValidIP = addedValidIP;
	   			if(firstDetection) {
	   				hadValidIP = !addedValidIP;
	   				firstDetection = false;
	   			}
	   		}
	   		if(hadValidIP != addedValidIP) {
	   			if (addedValidIP) {
	   				if(logMINOR) Logger.minor(this, "Got valid IP");
	   				onAddedValidIP();
	   			} else {
	   				if(logMINOR) Logger.minor(this, "No valid IP");
	   				onNotAddedValidIP();
	   			}
	   		}
	   	} else if(logMINOR)
	   		Logger.minor(this, "Client core not loaded");
	   	synchronized(this) {
	   		hasValidIP = addedValidIP;
	   	}
	   	lastIPAddress = addresses.toArray(new FreenetInetAddress[addresses.size()]);
	   	if(dumpLocalAddresses) {
	   		ArrayList<FreenetInetAddress> filtered = new ArrayList<FreenetInetAddress>(lastIPAddress.length);
	   		for(FreenetInetAddress addr: lastIPAddress) {
	   			if(addr == null) continue;
	   			if(addr == overrideIPAddress && addr.hasHostnameNoIP())
	   				filtered.add(addr);
	   			else if(addr.hasHostnameNoIP()) continue;
	   			else if(IPUtil.isValidAddress(addr.getAddress(), false))
	   				filtered.add(addr);
	   		}
	   		return filtered.toArray(new FreenetInetAddress[filtered.size()]);
	   	}
	   	return lastIPAddress;
	}
	
	boolean hasValidIP() {
		synchronized(this) {
			return hasValidIP;
		}
	}
	
	private void onAddedValidIP() {
		node.clientCore.alerts.unregister(primaryIPUndetectedAlert);
		node.onAddedValidIP();
	}
	
	private void onNotAddedValidIP() {
		node.clientCore.alerts.register(primaryIPUndetectedAlert);
	}
	
	/**
	 * Core of the IP detection algorithm.
	 * @param addresses
	 * @param addedValidIP
	 * @return
	 */
	private boolean innerDetect(List<FreenetInetAddress> addresses) {
		boolean addedValidIP = false;
		InetAddress[] detectedAddrs = ipDetector.getAddressNoCallback();
		assert(detectedAddrs != null);
		synchronized(this) {
			hasDetectedIAD = true;
		}
		for(InetAddress detectedAddr: detectedAddrs) {
			FreenetInetAddress addr = new FreenetInetAddress(detectedAddr);
			if(!addresses.contains(addr)) {
				Logger.normal(this, "Detected IP address: "+addr);
				addresses.add(addr);
				if(addr.isRealInternetAddress(false, false, false))
					addedValidIP = true;
			}
		}
		
		if((pluginDetectedIPs != null) && (pluginDetectedIPs.length > 0)) {
			for(DetectedIP pluginDetectedIP: pluginDetectedIPs) {
				InetAddress addr = pluginDetectedIP.publicAddress;
				if(addr == null) continue;
				FreenetInetAddress a = new FreenetInetAddress(addr);
				if(!addresses.contains(a)) {
					Logger.normal(this, "Plugin detected IP address: "+a);
					addresses.add(a);
					if(a.isRealInternetAddress(false, false, false))
						addedValidIP = true;
				}
			}
		}
		
		boolean hadAddedValidIP = addedValidIP;
		
		int confidence = 0;
		
		// Try to pick it up from our connections
		if(node.peers != null) {
			PeerNode[] peerList = node.peers.myPeers();
			HashMap<FreenetInetAddress,Integer> countsByPeer = new HashMap<FreenetInetAddress,Integer>();
			// FIXME use a standard mutable int object, we have one somewhere
			for(PeerNode pn: peerList) {
				if(!pn.isConnected()) {
					if(logDEBUG) Logger.minor(this, "Not connected");
					continue;
				}
				if(!pn.isRealConnection()) {
					// Only let seed server connections through.
					// We have to trust them anyway.
					if(!(pn instanceof SeedServerPeerNode)) continue;
					if(logMINOR) Logger.minor(this, "Not a real connection and not a seed node: "+pn);
				}
				if(logMINOR) Logger.minor(this, "Maybe a usable connection for IP: "+pn);
				Peer p = pn.getRemoteDetectedPeer();
				if(logMINOR) Logger.minor(this, "Remote detected peer: "+p);
				if(p == null || p.isNull()) continue;
				FreenetInetAddress addr = p.getFreenetAddress();
				if(logMINOR) Logger.minor(this, "Address: "+addr);
				if(addr == null) continue;
				if(!IPUtil.isValidAddress(addr.getAddress(false), false)) {
					if(logMINOR) Logger.minor(this, "Address not valid");
					continue;
				}
				if(logMINOR)
					Logger.minor(this, "Peer "+pn.getPeer()+" thinks we are "+addr);
				if(countsByPeer.containsKey(addr)) {
					countsByPeer.put(addr, countsByPeer.get(addr) + 1);
				} else {
					countsByPeer.put(addr, 1);
				}
			}
			if(countsByPeer.size() == 1) {
                Entry<FreenetInetAddress, Integer> countByPeer = countsByPeer.entrySet().iterator().next();
				FreenetInetAddress addr = countByPeer.getKey();
				confidence = countByPeer.getValue();
				Logger.minor(this, "Everyone agrees we are "+addr);
				if(!addresses.contains(addr)) {
					if(addr.isRealInternetAddress(false, false, false))
						addedValidIP = true;
					addresses.add(addr);
				}
			} else if(countsByPeer.size() > 1) {
				// Take two most popular addresses.
				FreenetInetAddress best = null;
				FreenetInetAddress secondBest = null;
				int bestPopularity = 0;
				int secondBestPopularity = 0;
				for(Map.Entry<FreenetInetAddress,Integer> entry : countsByPeer.entrySet()) {
					FreenetInetAddress cur = entry.getKey();
					int curPop = entry.getValue();
					Logger.minor(this, "Detected peer: "+cur+" popularity "+curPop);
					if(curPop >= bestPopularity) {
						secondBestPopularity = bestPopularity;
						bestPopularity = curPop;
						secondBest = best;
						best = cur;
					}
				}
				if(best != null) {
					boolean hasRealDetectedAddress = false;
					for(InetAddress detectedAddr: detectedAddrs) {
						if(IPUtil.isValidAddress(detectedAddr, false))
							hasRealDetectedAddress = true;
					}
					if((bestPopularity > 1) || !hasRealDetectedAddress) {
 						if(!addresses.contains(best)) {
							Logger.minor(this, "Adding best peer "+best+" ("+bestPopularity+ ')');
							addresses.add(best);
							if(best.isRealInternetAddress(false, false, false))
								addedValidIP = true;
						}
 						confidence = bestPopularity;
						if((secondBest != null) && (secondBestPopularity > 1)) {
							if(!addresses.contains(secondBest)) {
								Logger.minor(this, "Adding second best peer "+secondBest+" ("+secondBest+ ')');
								addresses.add(secondBest);
								if(secondBest.isRealInternetAddress(false, false, false))
									addedValidIP = true;
							}
						}
					}
				}
			}
		}
		
		// Add the old address only if we have no choice, or if we only have the word of two peers to go on.
		if((!(hadAddedValidIP || confidence > 2)) && (oldIPAddress != null) && !oldIPAddress.equals(overrideIPAddress)) {
			addresses.add(oldIPAddress);
			// Don't set addedValidIP.
			// There is an excellent chance that this is out of date.
			// So we still want to nag the user, until we have some confirmation.
		}
		
	   	return addedValidIP;
	}
	
	private String l10n(String key) {
		return NodeL10n.getBase().getString("NodeIPDetector."+key);
	}

	private String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("NodeIPDetector."+key, pattern, value);
	}

	FreenetInetAddress[] getPrimaryIPAddress(boolean dumpLocal) {
		if(lastIPAddress == null) return detectPrimaryIPAddress(dumpLocal);
		return lastIPAddress;
	}
	
	public boolean hasDirectlyDetectedIP() {
		InetAddress[] addrs = ipDetector.getAddress(node.executor);
		if(addrs == null || addrs.length == 0) return false;
		for(InetAddress addr: addrs) {
			if(IPUtil.isValidAddress(addr, false)) {
				if(logMINOR)
					Logger.minor(this, "Has a directly detected IP: "+addr);
				return true;
			}
		}
		return false;
	}

	/**
	 * Process a list of DetectedIP's from the IP detector plugin manager.
	 * DetectedIP's can tell us what kind of NAT we are behind as well as our public
	 * IP address.
	 */
	public void processDetectedIPs(DetectedIP[] list) {
		pluginDetectedIPs = list;
		boolean mtuChanged = false;
		for(DetectedIP pluginDetectedIP: pluginDetectedIPs)
		    reportMTU(pluginDetectedIP.mtu, pluginDetectedIP.publicAddress instanceof Inet6Address);
		redetectAddress();
	}

	/**
	 * Is called by IPAddressDetector to inform NodeIPDetector about the MTU
	 * associated to this interface
	 */
        public void reportMTU(int mtu, boolean forIPv6) {
	    boolean mtuChanged = false;
	    if(forIPv6)
		mtuChanged |= minimumMTUIPv6.report(mtu);
	    else	
		mtuChanged |= minimumMTUIPv4.report(mtu);

	    if (mtuChanged) node.updateMTU();
        }

	public void redetectAddress() {
		FreenetInetAddress[] newIP = detectPrimaryIPAddress(false);
		NodeIPPortDetector[] detectors;
		synchronized(this) {
			if(Arrays.equals(newIP, lastIP)) return;
			lastIP = newIP;
			detectors = portDetectors;
		}
		for(NodeIPPortDetector detector: detectors)
			detector.update();
		node.writeNodeFile();
	}

	public void setOldIPAddress(FreenetInetAddress freenetAddress) {
		this.oldIPAddress = freenetAddress;
	}

	public int registerConfigs(SubConfig nodeConfig, int sortOrder) {
		// IP address override
		nodeConfig.register("ipAddressOverride", "", sortOrder++, true, false, "NodeIPDectector.ipOverride", 
				"NodeIPDectector.ipOverrideLong", 
				new StringCallback() {

			@Override
			public String get() {
				if(overrideIPAddressString == null) return "";
				else return overrideIPAddressString;
			}
			
			@Override
			public void set(String val) throws InvalidConfigValueException {
				boolean hadValidAddressOverride = hasValidAddressOverride();
				// FIXME do we need to tell anyone?
				if(val.length() == 0) {
					// Set to null
					overrideIPAddressString = val;
					overrideIPAddress = null;
					lastIPAddress = null;
					redetectAddress();
					return;
				}
				FreenetInetAddress addr;
				try {
					addr = new FreenetInetAddress(val, false, true);
				} catch (HostnameSyntaxException e) {
					throw new InvalidConfigValueException(l10n("unknownHostErrorInIPOverride", "error", "hostname or IP address syntax error"));
				} catch (UnknownHostException e) {
					throw new InvalidConfigValueException(l10n("unknownHostErrorInIPOverride", "error", e.getMessage()));
				}
				// Compare as IPs.
				if(addr.equals(overrideIPAddress)) return;
				overrideIPAddressString = val;
				overrideIPAddress = addr;
				lastIPAddress = null;
				synchronized(this) {
					hasValidAddressOverride = true;
				}
				if(!hadValidAddressOverride) {
					onGetValidAddressOverride();
				}
				redetectAddress();
			}
		});
		
		hasValidAddressOverride = true;
		overrideIPAddressString = nodeConfig.getString("ipAddressOverride");
		if(overrideIPAddressString.length() == 0)
			overrideIPAddress = null;
		else {
			try {
				overrideIPAddress = new FreenetInetAddress(overrideIPAddressString, false, true);
			} catch (HostnameSyntaxException e) {
				synchronized(this) {
					hasValidAddressOverride = false;
				}
				String msg = "Invalid IP override syntax: "+overrideIPAddressString+" in config: "+e.getMessage();
				Logger.error(this, msg);
				System.err.println(msg+" but starting up anyway, ignoring the configured IP override");
				overrideIPAddress = null;
			} catch (UnknownHostException e) {
				// **FIXME** This never happens for this reason with current FreenetInetAddress(String, boolean, boolean) code; perhaps it needs review?
				String msg = "Unknown host: "+overrideIPAddressString+" in config: "+e.getMessage();
				Logger.error(this, msg);
				System.err.println(msg+" but starting up anyway with no IP override");
				overrideIPAddress = null;
			}
		}
		
		// Temporary IP address hint
		
		nodeConfig.register("tempIPAddressHint", "", sortOrder++, true, false, "NodeIPDectector.tempAddressHint", "NodeIPDectector.tempAddressHintLong", new StringCallback() {

			@Override
			public String get() {
				return "";
			}
			
			@Override
			public void set(String val) throws InvalidConfigValueException {
				if(val.length() == 0) {
					return;
				}
				if(overrideIPAddress != null) return;
				try {
					oldIPAddress = new FreenetInetAddress(val);
				} catch (UnknownHostException e) {
					throw new InvalidConfigValueException("Unknown host: "+e.getMessage());
				}
				redetectAddress();
			}
		});
		
		String ipHintString = nodeConfig.getString("tempIPAddressHint");
		if(ipHintString.length() > 0) {
			try {
				oldIPAddress = new FreenetInetAddress(ipHintString);
			} catch (UnknownHostException e) {
				String msg = "Unknown host: "+ipHintString+" in config: "+e.getMessage();
				Logger.error(this, msg);
				System.err.println(msg);
				oldIPAddress = null;
			}
		}
		
		return sortOrder;
	}

	/** Start all IP detection related processes */
	public void start() {
		boolean haveValidAddressOverride = hasValidAddressOverride();
		if(!haveValidAddressOverride) {
			onNotGetValidAddressOverride();
		}
		node.executor.execute(ipDetector, "IP address re-detector");
		redetectAddress();
		// 60 second delay for inserting ARK to avoid reinserting more than necessary if we don't detect IP on startup.
		// Not a FastRunnable as it can take a while to start the insert
		node.getTicker().queueTimedJob(new Runnable() {
			@Override
			public void run() {
				NodeIPPortDetector[] detectors;
				synchronized(this) {
					detectors = portDetectors;
				}
				for(NodeIPPortDetector detector: detectors)
					detector.startARK();
			}
		}, SECONDS.toMillis(60));
	}

	public void onConnectedPeer() {
		// Run off thread, but at high priority.
		// Initial messages don't need an up to date IP for the node itself, but
		// announcements do. However announcements are not sent instantly.
		node.executor.execute(new PrioRunnable() {

			@Override
			public void run() {
				ipDetectorManager.maybeRun();
			}

			@Override
			public int getPriority() {
				return NativeThread.HIGH_PRIORITY;
			}
			
		});
	}

	public void registerIPDetectorPlugin(FredPluginIPDetector detector) {
		ipDetectorManager.registerDetectorPlugin(detector);
	}

	public void unregisterIPDetectorPlugin(FredPluginIPDetector detector) {
		ipDetectorManager.unregisterDetectorPlugin(detector);
	}
	
	public synchronized boolean isDetecting() {
		return !(hasDetectedPM && hasDetectedIAD);
	}

	void hasDetectedPM() {
		if(logMINOR)
			Logger.minor(this, "hasDetectedPM() called", new Exception("debug"));
		synchronized(this) {
			hasDetectedPM = true;
		}
	}

	public int getMinimumDetectedMTU(boolean ipv6) {
		return ipv6 ? minimumMTUIPv6.get() : minimumMTUIPv4.get();
	}

	public int getMinimumDetectedMTU() {
		return Math.min(minimumMTUIPv4.get(), minimumMTUIPv6.get());
	}

	public void setMaybeSymmetric() {
		if(ipDetectorManager != null && ipDetectorManager.isEmpty()) {
			if(maybeSymmetricAlert == null) {
				maybeSymmetricAlert = new SimpleUserAlert(true, l10n("maybeSymmetricTitle"), 
						l10n("maybeSymmetric"), l10n("maybeSymmetricShort"), UserAlert.ERROR);
			}
			if(node.clientCore != null && node.clientCore.alerts != null)
				node.clientCore.alerts.register(maybeSymmetricAlert);
		} else {
			if(maybeSymmetricAlert != null)
				node.clientCore.alerts.unregister(maybeSymmetricAlert);
		}
	}

	public void registerPortForwardPlugin(FredPluginPortForward forward) {
		ipDetectorManager.registerPortForwardPlugin(forward);
	}

	public void unregisterPortForwardPlugin(FredPluginPortForward forward) {
		ipDetectorManager.unregisterPortForwardPlugin(forward);
	}
	
	//TODO: ugly: deal with multiple instances properly
	public synchronized void registerBandwidthIndicatorPlugin(FredPluginBandwidthIndicator indicator) {
		bandwidthIndicator = indicator;
	}
	public synchronized void unregisterBandwidthIndicatorPlugin(FredPluginBandwidthIndicator indicator) {
		bandwidthIndicator = null;
	}
	public synchronized FredPluginBandwidthIndicator getBandwidthIndicator() {
		return bandwidthIndicator;
	}
	private FredPluginBandwidthIndicator bandwidthIndicator;
	
	boolean hasValidAddressOverride() {
		synchronized(this) {
			return hasValidAddressOverride;
		}
	}
	
	private void onGetValidAddressOverride() {
		node.clientCore.alerts.unregister(invalidAddressOverrideAlert);
	}
	
	private void onNotGetValidAddressOverride() {
		node.clientCore.alerts.register(invalidAddressOverrideAlert);
	}

	public void addConnectionTypeBox(HTMLNode contentNode) {
		ipDetectorManager.addConnectionTypeBox(contentNode);
	}

	public boolean noDetectPlugins() {
		return !ipDetectorManager.hasDetectors();
	}

	public boolean hasJSTUN() {
		return ipDetectorManager.hasJSTUN();
	}
}
