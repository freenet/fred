/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import freenet.crypt.CryptFormatException;
import freenet.crypt.DSAPublicKey;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.Message;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.PeerRestartedException;
import freenet.io.xfer.WaitedTooLongException;
import freenet.keys.NodeSSK;
import freenet.keys.SSKBlock;
import freenet.keys.SSKVerifyException;
import freenet.store.KeyCollisionException;
import freenet.support.Logger;
import freenet.support.ShortBuffer;
import freenet.support.Logger.LogLevel;
import freenet.support.io.NativeThread;

/**
 * Handles an incoming SSK insert.
 * SSKs need their own insert/request classes, see comments in SSKInsertSender.
 */
public class SSKInsertHandler implements PrioRunnable, ByteCounter {

	private static boolean logMINOR;
	
    static final int DATA_INSERT_TIMEOUT = 30000;
    
    final Node node;
    final long uid;
    final PeerNode source;
    final NodeSSK key;
    final long startTime;
    private SSKBlock block;
    private DSAPublicKey pubKey;
    private short htl;
    private SSKInsertSender sender;
    private byte[] data;
    private byte[] headers;
    private boolean canCommit;
    final InsertTag tag;
    private final boolean canWriteDatastore;
	private final boolean forkOnCacheable;
	private final boolean preferInsert;
	private final boolean ignoreLowBackoff;
	private final boolean realTimeFlag;

	private boolean collided = false;
    
    SSKInsertHandler(NodeSSK key, byte[] data, byte[] headers, short htl, PeerNode source, long id, Node node, long startTime, InsertTag tag, boolean canWriteDatastore, boolean forkOnCacheable, boolean preferInsert, boolean ignoreLowBackoff, boolean realTimeFlag) {
        this.node = node;
        this.uid = id;
        this.source = source;
        this.startTime = startTime;
        this.key = key;
        this.htl = htl;
        this.data = data;
        this.headers = headers;
        this.tag = tag;
        this.canWriteDatastore = canWriteDatastore;
        byte[] pubKeyHash = key.getPubKeyHash();
        pubKey = node.getPubKey.getKey(pubKeyHash, false, false, null);
        canCommit = false;
        logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
        this.forkOnCacheable = forkOnCacheable;
        this.preferInsert = preferInsert;
        this.ignoreLowBackoff = ignoreLowBackoff;
        this.realTimeFlag = realTimeFlag;
    }
    
    @Override
	public String toString() {
        return super.toString()+" for "+uid;
    }
    
    @Override
    public void run() {
        freenet.support.Logger.OSThread.logPID(this);
        try {
            realRun();
        } catch (Throwable t) {
            Logger.error(this, "Caught "+t, t);
        } finally {
            if(logMINOR) Logger.minor(this, "Exiting InsertHandler.run() for "+uid);
            tag.unlockHandler();
        }
    }

    private void realRun() {
        // Send Accepted
        Message accepted = DMT.createFNPSSKAccepted(uid, pubKey == null);
        
        try {
			source.sendAsync(accepted, null, this);
		} catch (NotConnectedException e1) {
			if(logMINOR) Logger.minor(this, "Lost connection to source");
			return;
		}
		
		while(headers == null || data == null || pubKey == null) {
			MessageFilter mfDataInsertRejected = MessageFilter.create().setType(DMT.FNPDataInsertRejected).setField(DMT.UID, uid).setSource(source).setTimeout(DATA_INSERT_TIMEOUT);
			MessageFilter mf = mfDataInsertRejected;
			if(headers == null) {
				MessageFilter m = MessageFilter.create().setType(DMT.FNPSSKInsertRequestHeaders).setField(DMT.UID, uid).setSource(source).setTimeout(DATA_INSERT_TIMEOUT);
				mf = m.or(mf);
			}
			if(data == null) {
				MessageFilter m = MessageFilter.create().setType(DMT.FNPSSKInsertRequestData).setField(DMT.UID, uid).setSource(source).setTimeout(DATA_INSERT_TIMEOUT);
				mf = m.or(mf);
			}
			if(pubKey == null) {
				MessageFilter m = MessageFilter.create().setType(DMT.FNPSSKPubKey).setField(DMT.UID, uid).setSource(source).setTimeout(DATA_INSERT_TIMEOUT);
				mf = m.or(mf);
			}
			Message msg;
			try {
				msg = node.usm.waitFor(mf, this);
			} catch (DisconnectedException e) {
				if(logMINOR) Logger.minor(this, "Lost connection to source on "+uid);
				return;
			}
			if(msg == null) {
				Logger.normal(this, "Failed to receive all parts (data="+(data==null?"null":"ok")+" headers="+(headers==null?"null":"ok")+" pk="+pubKey+") for "+uid);
				Message failed = DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_RECEIVE_FAILED);
				try {
					source.sendSync(failed, this, realTimeFlag);
				} catch (NotConnectedException e) {
					// Ignore
				} catch (SyncSendWaitedTooLongException e) {
					// Ignore
				}
				return;
			} else if(msg.getSpec() == DMT.FNPSSKInsertRequestHeaders) {
				headers = ((ShortBuffer)msg.getObject(DMT.BLOCK_HEADERS)).getData();
			} else if(msg.getSpec() == DMT.FNPSSKInsertRequestData) {
				data = ((ShortBuffer)msg.getObject(DMT.DATA)).getData();
			} else if(msg.getSpec() == DMT.FNPSSKPubKey) {
				byte[] pubkeyAsBytes = ((ShortBuffer)msg.getObject(DMT.PUBKEY_AS_BYTES)).getData();
				try {
					pubKey = DSAPublicKey.create(pubkeyAsBytes);
					if(logMINOR) Logger.minor(this, "Got pubkey on "+uid+" : "+pubKey);
					Message confirm = DMT.createFNPSSKPubKeyAccepted(uid);
					try {
						source.sendAsync(confirm, null, this);
					} catch (NotConnectedException e) {
						if(logMINOR) Logger.minor(this, "Lost connection to source on "+uid);
						return;
					}
				} catch (CryptFormatException e) {
					Logger.error(this, "Invalid pubkey from "+source+" on "+uid);
					msg = DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_SSK_ERROR);
					try {
						source.sendSync(msg, this, realTimeFlag);
					} catch (NotConnectedException ee) {
						// Ignore
					} catch (SyncSendWaitedTooLongException ee) {
						// Ignore
					}
					return;
				}
			} else if(msg.getSpec() == DMT.FNPDataInsertRejected) {
	        	try {
					source.sendAsync(DMT.createFNPDataInsertRejected(uid, msg.getShort(DMT.DATA_INSERT_REJECTED_REASON)), null, this);
				} catch (NotConnectedException e) {
					// Ignore.
				}
				return;
			} else {
				Logger.error(this, "Unexpected message? "+msg+" on "+this);
			}
		}
		
		try {
			key.setPubKey(pubKey);
			block = new SSKBlock(data, headers, key, false);
		} catch (SSKVerifyException e1) {
			Logger.error(this, "Invalid SSK from "+source, e1);
			Message msg = DMT.createFNPDataInsertRejected(uid, DMT.DATA_INSERT_REJECTED_SSK_ERROR);
			try {
				source.sendSync(msg, this, realTimeFlag);
			} catch (NotConnectedException e) {
				// Ignore
			} catch (SyncSendWaitedTooLongException e) {
				// Ignore
			}
			return;
		}
		
		SSKBlock storedBlock = node.fetch(key, false, false, false, canWriteDatastore, false, null);
		
		if((storedBlock != null) && !storedBlock.equals(block)) {
			try {
				RequestHandler.sendSSK(storedBlock.getRawHeaders(), storedBlock.getRawData(), false, pubKey, source, uid, this, realTimeFlag);
			} catch (NotConnectedException e1) {
				if(logMINOR) Logger.minor(this, "Lost connection to source on "+uid);
				return;
			} catch (WaitedTooLongException e1) {
				Logger.error(this, "Took too long to send ssk datareply to "+uid+" (because of throttling)");
				return;
			} catch (PeerRestartedException e) {
				if(logMINOR) Logger.minor(this, "Source restarted on "+uid);
				return;
			} catch (SyncSendWaitedTooLongException e) {
				Logger.error(this, "Took too long to send ssk datareply to "+uid);
				return;
			}
			block = storedBlock;
		}
		
		if(logMINOR) Logger.minor(this, "Got block for "+key+" for "+uid);
		
        if(htl > 0)
            sender = node.makeInsertSender(block, htl, uid, tag, source, false, false, canWriteDatastore, forkOnCacheable, preferInsert, ignoreLowBackoff, realTimeFlag);
        
        boolean receivedRejectedOverload = false;
        
        while(true) {
            synchronized(sender) {
                try {
                	if(sender.getStatus() == SSKInsertSender.NOT_FINISHED)
                		sender.wait(5000);
                } catch (InterruptedException e) {
                	// Ignore
                }
            }

            if((!receivedRejectedOverload) && sender.receivedRejectedOverload()) {
            	receivedRejectedOverload = true;
            	// Forward it
            	// Does not need to be sent synchronously since is non-terminal.
            	Message m = DMT.createFNPRejectedOverload(uid, false, true, realTimeFlag);
            	try {
					source.sendAsync(m, null, this);
				} catch (NotConnectedException e) {
					if(logMINOR) Logger.minor(this, "Lost connection to source");
					return;
				}
            }
            
            if(sender.hasRecentlyCollided()) {
            	// Forward collision
            	data = sender.getData();
            	headers = sender.getHeaders();
            	collided = true;
        		try {
					block = new SSKBlock(data, headers, key, true);
				} catch (SSKVerifyException e1) {
					// Is verified elsewhere...
					throw new Error("Impossible: " + e1, e1);
				}
				try {
					RequestHandler.sendSSK(headers, data, false, pubKey, source, uid, this, realTimeFlag);
				} catch (NotConnectedException e1) {
					if(logMINOR) Logger.minor(this, "Lost connection to source on "+uid);
					return;
				} catch (WaitedTooLongException e1) {
					Logger.error(this, "Took too long to send ssk datareply to "+uid+" because of bwlimiting");
					return;
				} catch (PeerRestartedException e) {
					Logger.error(this, "Peer restarted on "+uid);
					return;
				} catch (SyncSendWaitedTooLongException e) {
					Logger.error(this, "Took too long to send ssk datareply to "+uid);
					return;
				}
            }
            
            int status = sender.getStatus();
            
            if(status == SSKInsertSender.NOT_FINISHED) {
           		continue;
            }
            
            // Local RejectedOverload's (fatal).
            // Internal error counts as overload. It'd only create a timeout otherwise, which is the same thing anyway.
            // We *really* need a good way to deal with nodes that constantly R_O!
            if((status == SSKInsertSender.TIMED_OUT) ||
            		(status == SSKInsertSender.GENERATED_REJECTED_OVERLOAD) ||
            		(status == SSKInsertSender.INTERNAL_ERROR)) {
            	// Unlock early for originator, late for target; see UIDTag comments.
            	tag.unlockHandler();
                Message msg = DMT.createFNPRejectedOverload(uid, true, true, realTimeFlag);
                try {
					source.sendSync(msg, this, realTimeFlag);
				} catch (NotConnectedException e) {
					if(logMINOR) Logger.minor(this, "Lost connection to source");
					return;
				} catch (SyncSendWaitedTooLongException e) {
					Logger.error(this, "Took too long to send "+msg+" to "+source);
					return;
				}
                // Might as well store it anyway.
                if((status == SSKInsertSender.TIMED_OUT) ||
                		(status == SSKInsertSender.GENERATED_REJECTED_OVERLOAD))
                	canCommit = true;
                finish(status);
                return;
            }
            
            if((status == SSKInsertSender.ROUTE_NOT_FOUND) || (status == SSKInsertSender.ROUTE_REALLY_NOT_FOUND)) {
            	// Unlock early for originator, late for target; see UIDTag comments.
            	tag.unlockHandler();
                Message msg = DMT.createFNPRouteNotFound(uid, sender.getHTL());
                try {
					source.sendSync(msg, this, realTimeFlag);
				} catch (NotConnectedException e) {
					if(logMINOR) Logger.minor(this, "Lost connection to source");
					return;
				} catch (SyncSendWaitedTooLongException e) {
					Logger.error(this, "Took too long to send "+msg+" to source");
				}
                canCommit = true;
                finish(status);
                return;
            }
            
            if(status == SSKInsertSender.SUCCESS) {
            	// Unlock early for originator, late for target; see UIDTag comments.
            	tag.unlockHandler();
            	Message msg = DMT.createFNPInsertReply(uid);
            	try {
					source.sendSync(msg, this, realTimeFlag);
				} catch (NotConnectedException e) {
					if(logMINOR) Logger.minor(this, "Lost connection to source");
					return;
				} catch (SyncSendWaitedTooLongException e) {
					Logger.error(this, "Took too long to send "+msg+" to "+source);
				}
                canCommit = true;
                finish(status);
                return;
            }
            
            // Otherwise...?
            Logger.error(this, "Unknown status code: "+sender.getStatusString());
        	// Unlock early for originator, late for target; see UIDTag comments.
        	tag.unlockHandler();
            Message msg = DMT.createFNPRejectedOverload(uid, true, true, realTimeFlag);
            try {
				source.sendSync(msg, this, realTimeFlag);
			} catch (NotConnectedException e) {
				// Ignore
			} catch (SyncSendWaitedTooLongException e) {
				Logger.error(this, "Took too long to send "+msg+" to "+source);
			}
            finish(status);
            return;
        }
    }

    /**
     * If canCommit, and we have received all the data, and it
     * verifies, then commit it.
     */
    private void finish(int code) {
    	if(logMINOR) Logger.minor(this, "Finishing");
    	
    	if(canCommit) {
    		commit();
    	}
    	
        if(code != SSKInsertSender.TIMED_OUT && code != SSKInsertSender.GENERATED_REJECTED_OVERLOAD &&
        		code != SSKInsertSender.INTERNAL_ERROR && code != SSKInsertSender.ROUTE_REALLY_NOT_FOUND) {
        	int totalSent = getTotalSentBytes();
        	int totalReceived = getTotalReceivedBytes();
        	if(sender != null) {
        		totalSent += sender.getTotalSentBytes();
        		totalReceived += sender.getTotalReceivedBytes();
        	}
        	if(logMINOR) Logger.minor(this, "Remote SSK insert cost "+totalSent+ '/' +totalReceived+" bytes ("+code+ ')');
        	node.nodeStats.remoteSskInsertBytesSentAverage.report(totalSent);
        	node.nodeStats.remoteSskInsertBytesReceivedAverage.report(totalReceived);
        	if(code == SSKInsertSender.SUCCESS) {
        		// Can report both sides
        		node.nodeStats.successfulSskInsertBytesSentAverage.report(totalSent);
        		node.nodeStats.successfulSskInsertBytesReceivedAverage.report(totalReceived);
        	}
        }

    }

    private void commit() {
		try {
			node.store(block, node.shouldStoreDeep(key, source, sender == null ? new PeerNode[0] : sender.getRoutedTo()), collided, false, canWriteDatastore, false);
		} catch (KeyCollisionException e) {
			Logger.normal(this, "Collision on "+this);
		}
	}

	private final Object totalBytesSync = new Object();
    private int totalBytesSent;
    private int totalBytesReceived;
    
	@Override
	public void sentBytes(int x) {
		synchronized(totalBytesSync) {
			totalBytesSent += x;
		}
		node.nodeStats.insertSentBytes(true, x);
	}

	@Override
	public void receivedBytes(int x) {
		synchronized(totalBytesSync) {
			totalBytesReceived += x;
		}
		node.nodeStats.insertReceivedBytes(true, x);
	}
	
	public int getTotalSentBytes() {
		return totalBytesSent;
	}
	
	public int getTotalReceivedBytes() {
		return totalBytesReceived;
	}

	@Override
	public void sentPayload(int x) {
		node.sentPayload(x);
		node.nodeStats.insertSentBytes(true, -x);
	}

	@Override
	public int getPriority() {
		return NativeThread.HIGH_PRIORITY;
	}
    
}
