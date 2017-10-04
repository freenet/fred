/**
 * 
 */
package freenet.node;

import java.io.UnsupportedEncodingException;
import java.net.UnknownHostException;

import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.async.BaseClientPutter;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientPutCallback;
import freenet.client.async.ClientPutter;
import freenet.client.async.PersistenceDisabledException;
import freenet.io.comm.Peer;
import freenet.io.comm.PeerParseException;
import freenet.keys.FreenetURI;
import freenet.keys.InsertableClientSSK;
import freenet.support.Logger;
import freenet.support.SimpleFieldSet;
import freenet.support.SimpleReadOnlyArrayBucket;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;
import freenet.support.api.RandomAccessBucket;

public class NodeARKInserter implements ClientPutCallback, RequestClient {

	/**
	 * 
	 */
	private final Node node;
	private final NodeCrypto crypto;
	private final String darknetOpennetString;
	private final NodeIPPortDetector detector;
	private static boolean logMINOR;
	private final boolean enabled;

	/**
	 * @param node
	 * @param old If true, use the old ARK rather than the new ARK
	 */
	NodeARKInserter(Node node, NodeCrypto crypto, NodeIPPortDetector detector, boolean enableARKs) {
		this.node = node;
		this.crypto = crypto;
		this.detector = detector;
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		if(crypto.isOpennet) darknetOpennetString = "Opennet";
		else darknetOpennetString = "Darknet";
		this.enabled = enableARKs;
	}

	private ClientPutter inserter;
	private boolean shouldInsert;
	private Peer[] lastInsertedPeers;
	private boolean canStart;
	void start() {
		if(!enabled) return;
		canStart = true;
		innerUpdate();
	}
	
	public void update() {
		// Called by detector code, which is critical and convoluted.
		// Run off-thread, break locks, avoid stalling caller.
		node.executor.execute(new Runnable() {

			@Override
			public void run() {
				innerUpdate();
			}
			
		});
	}
	
	private void innerUpdate() {
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		if(logMINOR) Logger.minor(this, "update()");
		if(!checkIPUpdated()) return;
		// We'll broadcast the new physical.udp entry to our connected peers via a differential node reference
		// We'll err on the side of caution and not update our peer to an empty physical.udp entry using a differential node reference
		SimpleFieldSet nfs = crypto.exportPublicFieldSet(false, false, true);
		String[] entries = nfs.getAll("physical.udp");
		if(entries != null) {
			SimpleFieldSet fs = new SimpleFieldSet(true);
			fs.putOverwrite("physical.udp", entries);
			if(logMINOR) Logger.minor(this, darknetOpennetString + " ref's physical.udp is '" + fs.toString() + "'");
			node.peers.locallyBroadcastDiffNodeRef(fs, !crypto.isOpennet, crypto.isOpennet);
		} else {
			if(logMINOR) Logger.minor(this, darknetOpennetString + " ref's physical.udp is null");
		}
		// Proceed with inserting the ARK
		if(logMINOR) Logger.minor(this, "Inserting " + darknetOpennetString + " ARK because peers list changed");
		
		if(inserter != null) {
			// Already inserting.
			// Re-insert after finished.
			synchronized(this) {
				shouldInsert = true;
			}

			return;
		}
		// Otherwise need to start an insert
		if(node.noConnectedPeers()) {
			// Can't start an insert yet
			synchronized (this) {
				shouldInsert = true;
			}
			return;
		}	

		startInserter();
	}

	private boolean checkIPUpdated() {
		Peer[] p = detector.detectPrimaryPeers();
		if(p == null) {
			if(logMINOR) Logger.minor(this, "Not inserting " + darknetOpennetString + " ARK because no IP address");
			return false; // no point inserting
		}
		synchronized (this) {
			if(lastInsertedPeers != null) {
				if(p.length != lastInsertedPeers.length) return true;
				for(int i=0;i<p.length;i++)
					if(!p[i].strictEquals(lastInsertedPeers[i]))
						return true;
			} else {
				// we've not inserted an ARK that we know about (ie since startup)
				return true;
			}
		}
		return false;
	}

	private void startInserter() {
		if(!canStart) {
			if(logMINOR) Logger.minor(this, darknetOpennetString + " ARK inserter can't start yet");
			return;
		}
		
		if(logMINOR) Logger.minor(this, "starting " + darknetOpennetString + " ARK inserter");
		
		SimpleFieldSet fs = crypto.exportPublicFieldSet(false, false, true);
		
		// Remove some unnecessary fields that only cause collisions.
		
		// Delete entire ark.* field for now. Changing this and automatically moving to the new may be supported in future.
		fs.removeSubset("ark");
		fs.removeValue("location");
		fs.removeValue("sig");
		//fs.remove("version"); - keep version because of its significance in reconnection
		
		String s = fs.toString();
		
		byte[] buf;
		try {
			buf = s.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		}
		
		RandomAccessBucket b = new SimpleReadOnlyArrayBucket(buf);
		
		long number = crypto.myARKNumber;
		InsertableClientSSK ark = crypto.myARK;
		FreenetURI uri = ark.getInsertURI().setKeyType("USK").setSuggestedEdition(number);
		
		if(logMINOR) Logger.minor(this, "Inserting " + darknetOpennetString + " ARK: " + uri + "  contents:\n" + s);
		
		InsertContext ctx = node.clientCore.makeClient((short)0, false).getInsertContext(true);
		inserter = new ClientPutter(this, b, uri,
					null, // Modern ARKs easily fit inside 1KB so should be pure SSKs => no MIME type; this improves fetchability considerably
					ctx,
					RequestStarter.INTERACTIVE_PRIORITY_CLASS, false, null, false, null, -1);

		try {
			
			node.clientCore.clientContext.start(inserter);
			
			synchronized (this) {
				if(fs.get("physical.udp") == null)
					lastInsertedPeers = null;
				else {
					try {
						String[] all = fs.getAll("physical.udp");
						Peer[] peers = new Peer[all.length];
						for(int i=0;i<all.length;i++)
							peers[i] = new Peer(all[i]);
						lastInsertedPeers = peers;
					} catch (PeerParseException e1) {
						Logger.error(this, "Error parsing own " + darknetOpennetString + " ref: "+e1+" : "+fs.get("physical.udp"), e1);
					} catch (UnknownHostException e1) {
						Logger.error(this, "Error parsing own " + darknetOpennetString + " ref: "+e1+" : "+fs.get("physical.udp"), e1);
					}
				}
			}
		} catch (InsertException e) {
			onFailure(e, inserter);	
		} catch (PersistenceDisabledException e) {
			// Impossible
		}
	}
	
	@Override
	public void onSuccess(BaseClientPutter state) {
		FreenetURI uri = state.getURI();
		if(logMINOR) Logger.minor(this, darknetOpennetString + " ARK insert succeeded: " + uri);
		synchronized (this) {
			inserter = null;
			if(!shouldInsert) return;
			shouldInsert = false;
		}
		startInserter();
	}

	@Override
	public void onFailure(InsertException e, BaseClientPutter state) {
		if(logMINOR) Logger.minor(this, darknetOpennetString + " ARK insert failed: "+e);
		synchronized(this) {
			lastInsertedPeers = null;
		}
		// :(
		// Better try again
		try {
			Thread.sleep(5000);
		} catch (InterruptedException e1) {
			// Ignore
		}
		
		startInserter();
	}

	@Override
	public void onGeneratedURI(FreenetURI uri, BaseClientPutter state) {
		if(logMINOR) Logger.minor(this, "Generated URI for " + darknetOpennetString + " ARK: "+uri);
		long l = uri.getSuggestedEdition();
		if(l < crypto.myARKNumber) {
			Logger.error(this, "Inserted " + darknetOpennetString + " ARK edition # lower than attempted: "+l+" expected "+crypto.myARKNumber);
		} else if(l > crypto.myARKNumber) {
			if(logMINOR) Logger.minor(this, darknetOpennetString + " ARK number moving from "+crypto.myARKNumber+" to "+l);
			crypto.myARKNumber = l;
			if(crypto.isOpennet)
				node.writeOpennetFile();
			else
				node.writeNodeFile();
			// We'll broadcast the new ARK edition to our connected peers via a differential node reference
			SimpleFieldSet fs = new SimpleFieldSet(true);
			fs.put("ark.number", crypto.myARKNumber);
			node.peers.locallyBroadcastDiffNodeRef(fs, !crypto.isOpennet, crypto.isOpennet);
		}
	}

	public void onConnectedPeer() {
		if(!checkIPUpdated()) return;
		synchronized (this) {
			if(!shouldInsert) return;
		}
		// Already inserting.
		if(inserter != null) return; 	

		synchronized (this) {
			shouldInsert = false;	
		}

		startInserter();
	}

	@Override
	public void onFetchable(BaseClientPutter state) {
		// Ignore, we don't care
	}

	@Override
	public boolean persistent() {
		return false;
	}

	@Override
	public boolean realTimeFlag() {
		return false;
	}

	@Override
	public void onGeneratedMetadata(Bucket metadata, BaseClientPutter state) {
		Logger.error(this, "Bogus onGeneratedMetadata() on "+this+" from "+state, new Exception("error"));
		metadata.free();
	}

    @Override
    public void onResume(ClientContext context) {
        // Not persistent.
    }

    @Override
    public RequestClient getRequestClient() {
        return this;
    }

}
