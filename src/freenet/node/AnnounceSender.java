/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import java.util.HashSet;

import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.Message;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.NotConnectedException;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.node.OpennetManager.ConnectionType;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.SimpleFieldSet;
import freenet.support.Logger.LogLevel;
import freenet.support.io.NativeThread;

public class AnnounceSender implements PrioRunnable, ByteCounter {
	private static volatile boolean logMINOR;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}


	// Constants
	static final int ACCEPTED_TIMEOUT = 10000;
	static final int ANNOUNCE_TIMEOUT = 120000; // longer than a regular request as have to transfer noderefs hop by hop etc
	static final int END_TIMEOUT = 30000; // After received the completion message, wait 30 seconds for any late reordered replies

	private final PeerNode source;
	private final long uid;
	private final OpennetManager om;
	private final Node node;
	private final long xferUID;
	private final int noderefLength;
	private final int paddedLength;
	private byte[] noderefBuf;
	private short htl;
	private final double target;
	private final AnnouncementCallback cb;
	private final PeerNode onlyNode;
	private int forwardedRefs;

	public AnnounceSender(double target, short htl, long uid, PeerNode source, OpennetManager om, Node node, long xferUID, int noderefLength, int paddedLength, AnnouncementCallback cb) {
		this.source = source;
		this.uid = uid;
		this.om = om;
		this.node = node;
		this.onlyNode = null;
		this.htl = htl;
		this.xferUID = xferUID;
		this.paddedLength = paddedLength;
		this.noderefLength = noderefLength;
		this.target = target;
		this.cb = cb;
	}

	public AnnounceSender(double target, OpennetManager om, Node node, AnnouncementCallback cb, PeerNode onlyNode) {
		source = null;
		this.uid = node.random.nextLong();
		// Prevent it being routed back to us.
		node.tracker.completed(uid);
		this.om = om;
		this.node = node;
		this.htl = node.maxHTL();
		this.target = target;
		this.cb = cb;
		this.onlyNode = onlyNode;
		noderefBuf = om.crypto.myCompressedFullRef();
		this.xferUID = 0;
		this.paddedLength = 0;
		this.noderefLength = 0;
	}

	@Override
	public void run() {
		try {
			realRun();
			node.nodeStats.reportAnnounceForwarded(forwardedRefs, source);
		} catch (Throwable t) {
			Logger.error(this, "Caught "+t+" announcing "+uid+" from "+source, t);
		} finally {
			if(source != null) {
				source.completedAnnounce(uid);
			}
			node.tracker.completed(uid);
			if(cb != null)
				cb.completed();
			node.nodeStats.endAnnouncement(uid);
		}
	}

	private void realRun() {
		boolean hasForwarded = false;
		if(source != null) {
			try {
				source.sendAsync(DMT.createFNPAccepted(uid), null, this);
			} catch (NotConnectedException e) {
				return;
			}
			if(!transferNoderef()) return;
		}

		// Now route it.

		HashSet<PeerNode> nodesRoutedTo = new HashSet<PeerNode>();
		PeerNode next = null;
		while(true) {
			if(logMINOR) Logger.minor(this, "htl="+htl);
			/*
			 * If we haven't routed to any node yet, decrement according to the source.
			 * If we have, decrement according to the node which just failed.
			 * Because:
			 * 1) If we always decrement according to source then we can be at max or min HTL
			 * for a long time while we visit *every* peer node. This is BAD!
			 * 2) The node which just failed can be seen as the requestor for our purposes.
			 */
			// Decrement at this point so we can DNF immediately on reaching HTL 0.
			if(onlyNode == null)
				htl = node.decrementHTL(hasForwarded ? next : source, htl);

			if(htl == 0) {
				// No more nodes.
				complete();
				return;
			}

			if(!node.isOpennetEnabled()) {
				complete();
				return;
			}

			if(onlyNode == null) {
				// Route it
				next = node.peers.closerPeer(source, nodesRoutedTo, target, true, node.isAdvancedModeEnabled(), -1,
				        null, null, htl, 0, source == null, false, false);
			} else {
				next = onlyNode;
				if(nodesRoutedTo.contains(onlyNode)) {
					rnf(onlyNode);
					return;
				}
			}

			if(next == null) {
				// Backtrack
				rnf(next);
				return;
			}
			if(logMINOR) Logger.minor(this, "Routing request to "+next);
			if(onlyNode == null)
				next.reportRoutedTo(target, source == null, false, source, nodesRoutedTo, htl);
			nodesRoutedTo.add(next);

			long xferUID = sendTo(next);
			if(xferUID == -1) continue;

			hasForwarded = true;

			Message msg = null;

			while(true) {

				/**
				 * What are we waiting for?
				 * FNPAccepted - continue
				 * FNPRejectedLoop - go to another node
				 * FNPRejectedOverload - go to another node
				 */

				MessageFilter mfAccepted = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(ACCEPTED_TIMEOUT).setType(DMT.FNPAccepted);
				MessageFilter mfRejectedLoop = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(ACCEPTED_TIMEOUT).setType(DMT.FNPRejectedLoop);
				MessageFilter mfRejectedOverload = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(ACCEPTED_TIMEOUT).setType(DMT.FNPRejectedOverload);
				MessageFilter mfOpennetDisabled = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(ACCEPTED_TIMEOUT).setType(DMT.FNPOpennetDisabled);

				// mfRejectedOverload must be the last thing in the or
				// So its or pointer remains null
				// Otherwise we need to recreate it below
				MessageFilter mf = mfAccepted.or(mfRejectedLoop.or(mfRejectedOverload.or(mfOpennetDisabled)));

				try {
					msg = node.usm.waitFor(mf, this);
					if(logMINOR) Logger.minor(this, "first part got "+msg);
				} catch (DisconnectedException e) {
					Logger.normal(this, "Disconnected from "+next+" while waiting for Accepted on "+uid);
					break;
				}

				if(msg == null) {
					if(logMINOR) Logger.minor(this, "Timeout waiting for Accepted");
					// Try next node
					msg = null;
					break;
				}

				if(msg.getSpec() == DMT.FNPRejectedLoop) {
					if(logMINOR) Logger.minor(this, "Rejected loop");
					// Find another node to route to
					msg = null;
					break;
				}

				if(msg.getSpec() == DMT.FNPRejectedOverload) {
					if(logMINOR) Logger.minor(this, "Rejected: overload");
					// Give up on this one, try another
					msg = null;
					break;
				}

				if(msg.getSpec() == DMT.FNPOpennetDisabled) {
					if(logMINOR) Logger.minor(this, "Opennet disabled");
					msg = null;
					break;
				}

				if(msg.getSpec() != DMT.FNPAccepted) {
					Logger.error(this, "Unrecognized message: "+msg);
					continue;
				}

				break;
			}

			if((msg == null) || (msg.getSpec() != DMT.FNPAccepted)) {
				// Try another node
				continue;
			}

			if(logMINOR) Logger.minor(this, "Got Accepted");
			
			if(cb != null)
				cb.acceptedSomewhere();

			// Send the rest

			try {
				sendRest(next, xferUID);
			} catch (NotConnectedException e1) {
				if(logMINOR)
					Logger.minor(this, "Not connected while sending noderef on "+next);
				continue;
			}

			// Otherwise, must be Accepted

			// So wait...

			while(true) {

				MessageFilter mfAnnounceCompleted = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(ANNOUNCE_TIMEOUT).setType(DMT.FNPOpennetAnnounceCompleted);
				MessageFilter mfRouteNotFound = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(ANNOUNCE_TIMEOUT).setType(DMT.FNPRouteNotFound);
				MessageFilter mfRejectedOverload = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(ANNOUNCE_TIMEOUT).setType(DMT.FNPRejectedOverload);
				MessageFilter mfAnnounceReply = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(ANNOUNCE_TIMEOUT).setType(DMT.FNPOpennetAnnounceReply);
				MessageFilter mfOpennetDisabled = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(ANNOUNCE_TIMEOUT).setType(DMT.FNPOpennetDisabled);
				MessageFilter mfNotWanted = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(ANNOUNCE_TIMEOUT).setType(DMT.FNPOpennetAnnounceNodeNotWanted);
				MessageFilter mfOpennetNoderefRejected = MessageFilter.create().setSource(next).setField(DMT.UID, uid).setTimeout(ANNOUNCE_TIMEOUT).setType(DMT.FNPOpennetNoderefRejected);
				MessageFilter mf = mfAnnounceCompleted.or(mfRouteNotFound.or(mfRejectedOverload.or(mfAnnounceReply.or(mfOpennetDisabled.or(mfNotWanted.or(mfOpennetNoderefRejected))))));

				try {
					msg = node.usm.waitFor(mf, this);
				} catch (DisconnectedException e) {
					Logger.normal(this, "Disconnected from "+next+" while waiting for announcement");
					break;
				}

				if(logMINOR) Logger.minor(this, "second part got "+msg);

				if(msg == null) {
					// Fatal timeout, must be terminal (IS_LOCAL==true)
					timedOut(next);
					return;
				}

				if(msg.getSpec() == DMT.FNPOpennetNoderefRejected) {
					int reason = msg.getInt(DMT.REJECT_CODE);
					Logger.normal(this, "Announce rejected by "+next+" : "+DMT.getOpennetRejectedCode(reason));
					msg = null;
					break;
				}

				if(msg.getSpec() == DMT.FNPOpennetAnnounceCompleted) {
					// Send the completion on immediately. We don't want to accumulate 30 seconds per hop!
					complete();
					mfAnnounceReply.setTimeout(END_TIMEOUT).setTimeoutRelativeToCreation(true);
					mfNotWanted.setTimeout(END_TIMEOUT).setTimeoutRelativeToCreation(true);
					mfAnnounceReply.clearOr();
					mfNotWanted.clearOr();
					mf = mfAnnounceReply.or(mfNotWanted);
					while(true)  {
						try {
							msg = node.usm.waitFor(mf, this);
						} catch (DisconnectedException e) {
							return;
						}
						if(msg == null) return;
						if(msg.getSpec() == DMT.FNPOpennetAnnounceReply) {
							validateForwardReply(msg, next);
							continue;
						}
						if(msg.getSpec() == DMT.FNPOpennetAnnounceNodeNotWanted) {
							if(cb != null)
								cb.nodeNotWanted();
							if(source != null) {
								try {
									sendNotWanted();
								} catch (NotConnectedException e) {
									Logger.warning(this, "Lost connection to source (announce completed)");
									return;
								}
							}
							continue;
						}
					}
				}

				if(msg.getSpec() == DMT.FNPRouteNotFound) {
					// Backtrack within available hops
					short newHtl = msg.getShort(DMT.HTL);
					if(newHtl < 0) newHtl = 0;
					if(newHtl < htl) htl = newHtl;
					break;
				}

				if(msg.getSpec() == DMT.FNPRejectedOverload) {
					// Give up on this one, try another
					break;
				}

				if(msg.getSpec() == DMT.FNPOpennetDisabled) {
					Logger.minor(this, "Opennet disabled");
					msg = null;
					break;
				}

				if(msg.getSpec() == DMT.FNPOpennetAnnounceReply) {
					validateForwardReply(msg, next);
					continue; // There may be more
				}

				if(msg.getSpec() == DMT.FNPOpennetAnnounceNodeNotWanted) {
					if(cb != null)
						cb.nodeNotWanted();
					if(source != null) {
						try {
							sendNotWanted();
						} catch (NotConnectedException e) {
							Logger.warning(this, "Lost connection to source (announce not wanted)");
							return;
						}
					}
					continue; // This message is propagated, they will send a Completed or RNF
				}

				Logger.error(this, "Unexpected message: "+msg);
			}
		}
	}
	
	private int waitingForTransfers = 0;

	/**
	 * Validate a reply, and relay it back to the source.
	 * @param msg2 The AnnouncementReply message.
	 * @return True unless we lost the connection to our request source.
	 */
	private void validateForwardReply(Message msg, final PeerNode next) {
		final long xferUID = msg.getLong(DMT.TRANSFER_UID);
		final int noderefLength = msg.getInt(DMT.NODEREF_LENGTH);
		final int paddedLength = msg.getInt(DMT.PADDED_LENGTH);
		synchronized(this) {
			waitingForTransfers++;
		}
		Runnable r = new Runnable() {

			@Override
			public void run() {
				try {
					byte[] noderefBuf = OpennetManager.innerWaitForOpennetNoderef(xferUID, paddedLength, noderefLength, next, false, uid, true, AnnounceSender.this, node);
					if(noderefBuf == null) {
						return; // Don't relay
					}
					SimpleFieldSet fs = OpennetManager.validateNoderef(noderefBuf, next, false);
					if(fs == null) {
						if(cb != null) cb.bogusNoderef("invalid noderef");
						return; // Don't relay
					}
					if(source != null) {
						// Now relay it
						try {
							forwardedRefs++;
							om.sendAnnouncementReply(uid, source, noderefBuf, AnnounceSender.this);
							if(cb != null) {
								cb.relayedNoderef();
							}
						} catch (NotConnectedException e) {
							// Hmmm...!
							return;
						}
					} else {
						// Add it
						try {
							OpennetPeerNode pn = node.addNewOpennetNode(fs, ConnectionType.ANNOUNCE);
							if(cb != null) {
								if(pn != null)
									cb.addedNode(pn);
								else
									cb.nodeNotAdded();
							}
						} catch (FSParseException e) {
							Logger.normal(this, "Failed to parse reply: "+e, e);
							if(cb != null) cb.bogusNoderef("parse failed: "+e);
						} catch (PeerParseException e) {
							Logger.normal(this, "Failed to parse reply: "+e, e);
							if(cb != null) cb.bogusNoderef("parse failed: "+e);
						} catch (ReferenceSignatureVerificationException e) {
							Logger.normal(this, "Failed to parse reply: "+e, e);
							if(cb != null) cb.bogusNoderef("parse failed: "+e);
						}
					}
					return;
				} finally {
					synchronized(AnnounceSender.this) {
						waitingForTransfers--;
						AnnounceSender.this.notifyAll();
					}
				}
			}
			
		};
		try {
			node.executor.execute(r);
		} catch (Throwable t) {
			synchronized(this) {
				waitingForTransfers--;
			}
		}
	}

	/**
	 * Send an AnnouncementRequest.
	 * @param next The node to send the announcement to.
	 * @return True if the announcement was successfully sent.
	 */
	private long sendTo(PeerNode next) {
		try {
			return om.startSendAnnouncementRequest(uid, next, noderefBuf, this, target, htl);
		} catch (NotConnectedException e) {
			if(logMINOR) Logger.minor(this, "Disconnected");
			return -1;
		}
	}

	/**
	 * Send an AnnouncementRequest.
	 * @param next The node to send the announcement to.
	 * @return True if the announcement was successfully sent.
	 * @throws NotConnectedException
	 */
	private void sendRest(PeerNode next, long xferUID) throws NotConnectedException {
		om.finishSentAnnouncementRequest(next, noderefBuf, this, xferUID);
	}

	private void timedOut(PeerNode next) {
		Message msg = DMT.createFNPRejectedOverload(uid, true, false, false);
		if(source != null) {
			try {
				source.sendAsync(msg, null, this);
			} catch (NotConnectedException e) {
				// Ok
			}
		}
		if(cb != null) cb.nodeFailed(next, "timed out");
	}

        private synchronized void waitForRunningTransfers() {
           while(waitingForTransfers > 0) {
              try {
                 wait();
              } catch (InterruptedException e) {
                 // Ignore.
              }
           }
        }

	private void rnf(PeerNode next) {
		waitForRunningTransfers();
		Message msg = DMT.createFNPRouteNotFound(uid, htl);
		if(source != null) {
			try {
				source.sendAsync(msg, null, this);
			} catch (NotConnectedException e) {
				// Ok
			}
		}
		if(cb != null) {
			if(next != null) cb.nodeFailed(next, "route not found");
			else cb.noMoreNodes();
		}
	}

	private void complete() {
		waitForRunningTransfers();
		Message msg = DMT.createFNPOpennetAnnounceCompleted(uid);
		if(source != null) {
			try {
				source.sendAsync(msg, null, this);
			} catch (NotConnectedException e) {
				// Oh well.
			}
		}
	}

	/**
	 * @return True unless the noderef is bogus.
	 */
	private boolean transferNoderef() {
		noderefBuf = OpennetManager.innerWaitForOpennetNoderef(xferUID, paddedLength, noderefLength, source, false, uid, true, this, node);
		if(noderefBuf == null) {
			return false;
		}
		SimpleFieldSet fs = OpennetManager.validateNoderef(noderefBuf, source, false);
		if(fs == null) {
			OpennetManager.rejectRef(uid, source, DMT.NODEREF_REJECTED_INVALID, this);
			return false;
		}
		// If we want it, add it and send it.
		try {
			// Allow reconnection - sometimes one side has the ref and the other side doesn't.
			if(om.addNewOpennetNode(fs, ConnectionType.ANNOUNCE, true) != null) {
				sendOurRef(source, om.crypto.myCompressedFullRef());
			} else {
				if(logMINOR)
					Logger.minor(this, "Don't need the node");
				sendNotWanted();
				// Okay, just route it.
			}
		} catch (FSParseException e) {
			Logger.warning(this, "Rejecting noderef: "+e, e);
			OpennetManager.rejectRef(uid, source, DMT.NODEREF_REJECTED_INVALID, this);
			return false;
		} catch (PeerParseException e) {
			Logger.warning(this, "Rejecting noderef: "+e, e);
			OpennetManager.rejectRef(uid, source, DMT.NODEREF_REJECTED_INVALID, this);
			return false;
		} catch (ReferenceSignatureVerificationException e) {
			Logger.warning(this, "Rejecting noderef: "+e, e);
			OpennetManager.rejectRef(uid, source, DMT.NODEREF_REJECTED_INVALID, this);
			return false;
		} catch (NotConnectedException e) {
			Logger.normal(this, "Could not receive noderef, disconnected");
			return false;
		}
		return true;
	}

	private void sendNotWanted() throws NotConnectedException {
		Message msg = DMT.createFNPOpennetAnnounceNodeNotWanted(uid);
		source.sendAsync(msg, null, this);
	}

	private void sendOurRef(PeerNode next, byte[] ref) throws NotConnectedException {
		om.sendAnnouncementReply(uid, next, ref, this);
	}

	@Override
	public void sentBytes(int x) {
		node.nodeStats.announceByteCounter.sentBytes(x);
	}

	@Override
	public void receivedBytes(int x) {
		node.nodeStats.announceByteCounter.receivedBytes(x);
	}

	@Override
	public void sentPayload(int x) {
		node.nodeStats.announceByteCounter.sentPayload(x);
		// Doesn't count.
	}

	@Override
	public int getPriority() {
		return NativeThread.HIGH_PRIORITY;
	}

}
