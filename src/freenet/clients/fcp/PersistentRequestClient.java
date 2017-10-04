package freenet.clients.fcp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientRequester;
import freenet.clients.fcp.ClientRequest.Persistence;
import freenet.clients.fcp.ListPersistentRequestsMessage.PersistentListJob;
import freenet.clients.fcp.ListPersistentRequestsMessage.TransientListJob;
import freenet.keys.FreenetURI;
import freenet.node.RequestClient;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;

/**
 * An FCP client.
 * Identified by its Name which is sent on connection. 
 * Tracks persistent requests for either PERSISTENCE_REBOOT or PERSISTENCE_FOREVER.
 */
public class PersistentRequestClient {
	
	public PersistentRequestClient(String name2, FCPConnectionHandler handler, boolean isGlobalQueue, RequestCompletionCallback cb, Persistence persistence, PersistentRequestRoot root) {
		this.name = name2;
		if(name == null) throw new NullPointerException();
		this.currentConnection = handler;
		final boolean forever = (persistence == Persistence.FOREVER);
		runningPersistentRequests = new ArrayList<ClientRequest>();
		completedUnackedRequests = new ArrayList<ClientRequest>();
		clientRequestsByIdentifier = new HashMap<String, ClientRequest>();
		this.isGlobalQueue = isGlobalQueue;
		this.persistence = persistence;
		assert(persistence == Persistence.FOREVER || persistence == Persistence.REBOOT);
		watchGlobalVerbosityMask = Integer.MAX_VALUE;
		lowLevelClient = new FCPClientRequestClient(this, forever, false);
		lowLevelClientRT = new FCPClientRequestClient(this, forever, true);
		completionCallbacks = new ArrayList<RequestCompletionCallback>();
		if(cb != null) completionCallbacks.add(cb);
		if(persistence == Persistence.FOREVER) {
			assert(root != null);
			this.root = root;
		} else
			this.root = null;
		if(isGlobalQueue)
		    statusCache = new RequestStatusCache();
		else
		    statusCache = null;
	}
	
	/** The persistent root object, null if persistence is PERSIST_REBOOT */
	final PersistentRequestRoot root;
	/** The client's Name sent in the ClientHello message */
	final String name;
	/** The current connection handler, if any. */
	private transient FCPConnectionHandler currentConnection;
	/** Currently running persistent requests */
	private final List<ClientRequest> runningPersistentRequests;
	/** Completed unacknowledged persistent requests */
	private final List<ClientRequest> completedUnackedRequests;
	/** ClientRequest's by identifier */
	private final Map<String, ClientRequest> clientRequestsByIdentifier;
	/** Are we the global queue? */
	public final boolean isGlobalQueue;
	/** Are we watching the global queue? */
	transient boolean watchGlobal;
	transient int watchGlobalVerbosityMask;
	/** FCPClients watching us. Lazy init, sync on clientsWatchingLock */
	private transient LinkedList<PersistentRequestClient> clientsWatching;
	private final Object clientsWatchingLock = new Object();
	private RequestClient lowLevelClient;
	private RequestClient lowLevelClientRT;
	private transient List<RequestCompletionCallback> completionCallbacks;
	/** The cache where ClientRequests report their progress */
	private transient final RequestStatusCache statusCache;
	/** Connection mode */
	final Persistence persistence;
	        
        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	public synchronized FCPConnectionHandler getConnection() {
		return currentConnection;
	}
	
	public synchronized void setConnection(FCPConnectionHandler handler) {
		this.currentConnection = handler;
	}

	public synchronized void onLostConnection(FCPConnectionHandler handler) {
		handler.freeDDAJobs();
		if(currentConnection == handler)
			currentConnection = null;
	}

	/**
	 * Called when a client request has finished, but is persistent. It has not been
	 * acked yet, so it should be moved to the unacked-completed-requests set.
	 */
	public void finishedClientRequest(ClientRequest get) {
		if(logMINOR)
			Logger.minor(this, "Finished client request", new Exception("debug"));
		assert(get.persistence == persistence);
		synchronized(this) {
			if(runningPersistentRequests.remove(get)) {
				completedUnackedRequests.add(get);
			}	
		}
		if(statusCache != null) {
			if(get instanceof ClientGet) {
				ClientGet download = (ClientGet)get;
				GetFailedMessage msg = download.getFailureMessage();
				FetchExceptionMode failureCode = null;
				String shortFailMessage = null;
				String longFailMessage = null;
				if(msg != null) {
					failureCode = msg.code;
					shortFailMessage = msg.getShortFailedMessage();
					longFailMessage = msg.getLongFailedMessage();
				}
				Bucket shadow = ((ClientGet) get).getBucket();
				if(shadow != null) shadow = shadow.createShadow();
				statusCache.finishedDownload(get.identifier, get.hasSucceeded(), ((ClientGet) get).getDataSize(), ((ClientGet) get).getMIMEType(), failureCode, longFailMessage, shortFailMessage, shadow, download.filterData());
			} else if(get instanceof ClientPutBase) {
				ClientPutBase upload = (ClientPutBase)get;
				PutFailedMessage msg = upload.getFailureMessage();
				InsertExceptionMode failureCode = null;
				String shortFailMessage = null;
				String longFailMessage = null;
				if(msg != null) {
					failureCode = msg.code;
					shortFailMessage = msg.getShortFailedMessage();
					longFailMessage = msg.getLongFailedMessage();
				}
				statusCache.finishedUpload(upload.getIdentifier(), upload.hasSucceeded(), upload.getGeneratedURI(), failureCode, shortFailMessage, longFailMessage);
			} else assert(false);
		}
	}

	public void queuePendingMessagesOnConnectionRestartAsync(FCPConnectionOutputHandler outputHandler, ClientContext context) {
		if(persistence == Persistence.FOREVER) {
			PersistentListJob job = new PersistentListJob(this, outputHandler, context, null) {

				@Override
				void complete(ClientContext context) {
					// Do nothing.
				}
				
			};
			job.run(context);
		} else {
			TransientListJob job = new TransientListJob(this, outputHandler, context, null) {

				@Override
				void complete(ClientContext context) {
					// Do nothing.
				}
				
			};
			job.run(context);

		}
	}
	
	
	
	/**
	 * Queue any and all pending messages from already completed, unacknowledged, persistent
	 * requests, to be immediately sent. This happens automatically on startup and hopefully
	 * will encourage clients to acknowledge persistent requests!
	 */
	public int queuePendingMessagesOnConnectionRestart(FCPConnectionOutputHandler outputHandler, String listRequestIdentifier, int offset, int max) {
		Object[] reqs;
		synchronized(this) {
			reqs = completedUnackedRequests.toArray();
		}
		int i = 0;
		for(i=offset;i<Math.min(reqs.length,offset+max);i++) {
			ClientRequest req = (ClientRequest) reqs[i];
			((ClientRequest)reqs[i]).sendPendingMessages(outputHandler, listRequestIdentifier, false, false);
		}
		return i;
	}
	
	/**
	 * Queue any and all pending messages from running requests. Happens on demand.
	 */
	public int queuePendingMessagesFromRunningRequests(FCPConnectionOutputHandler outputHandler, String listRequestIdentifier, int offset, int max) {
		Object[] reqs;
		synchronized(this) {
			reqs = runningPersistentRequests.toArray();
		}
		int i = 0;
		for(i=offset;i<Math.min(reqs.length,offset+max);i++) {
			ClientRequest req = (ClientRequest) reqs[i];
			req.sendPendingMessages(outputHandler, listRequestIdentifier, false, false);
		}
		return i;
	}
	
	public void register(ClientRequest cg) throws IdentifierCollisionException {
		assert(cg.persistence == persistence);
		if(logMINOR)
			Logger.minor(this, "Registering "+cg.getIdentifier());
		synchronized(this) {
			String ident = cg.getIdentifier();
			ClientRequest old = clientRequestsByIdentifier.get(ident);
			if((old != null) && (old != cg))
				throw new IdentifierCollisionException();
			if(cg.hasFinished()) {
				completedUnackedRequests.add(cg);
			} else {
				runningPersistentRequests.add(cg);
			}
			clientRequestsByIdentifier.put(ident, cg);
		}
		if(statusCache != null) {
			if(cg instanceof ClientGet) {
				statusCache.addDownload((DownloadRequestStatus)(cg.getStatus()));
			} else if(cg instanceof ClientPutBase) {
				statusCache.addUpload((UploadRequestStatus)(cg.getStatus()));
			}
		}
	}

	public boolean removeByIdentifier(String identifier, boolean kill, ClientContext context) {
		ClientRequest req;
		if(logMINOR) Logger.minor(this, "removeByIdentifier("+identifier+ ',' +kill+ ')');
		if(statusCache != null)
			statusCache.removeByIdentifier(identifier);
		synchronized(this) {
			req = clientRequestsByIdentifier.get(identifier);
//			if(container != null && req != null)
//				container.activate(req, 1);
			boolean removedFromRunning = false;
			if(req == null) {
				for(ClientRequest r : completedUnackedRequests) {
					if(r.getIdentifier().equals(identifier)) {
						req = r;
						completedUnackedRequests.remove(r);
						Logger.error(this, "Found completed unacked request "+r+" for identifier "+r.getIdentifier()+" but not in clientRequestsByIdentifier!!");
						break;
					}
				}
				if(req == null) {
					for(ClientRequest r : runningPersistentRequests) {
						if(r.getIdentifier().equals(identifier)) {
							req = r;
							runningPersistentRequests.remove(r);
							removedFromRunning = true;
							Logger.error(this, "Found running request "+r+" for identifier "+r.getIdentifier()+" but not in clientRequestsByIdentifier!!");
							break;
						}
					}
				}
				if(req == null) return false;
			} else if(!((removedFromRunning = runningPersistentRequests.remove(req)) || completedUnackedRequests.remove(req))) {
				Logger.error(this, "Removing "+identifier+": in clientRequestsByIdentifier but not in running/completed maps!");
				
				return false;
			}
			clientRequestsByIdentifier.remove(identifier);
		}
		if(kill) {
			if(logMINOR) Logger.minor(this, "Killing request "+req);
			req.cancel(context);
		}
        req.requestWasRemoved(context);
        RequestCompletionCallback[] callbacks = null;
        synchronized(this) {
        	if(completionCallbacks != null)
        		callbacks = completionCallbacks.toArray(new RequestCompletionCallback[completionCallbacks.size()]);
        }
		if(callbacks != null) {
			for(RequestCompletionCallback cb : callbacks)
				cb.onRemove(req);
		}
		return true;
	}

	public boolean hasPersistentRequests() {
		return !(runningPersistentRequests.isEmpty() && completedUnackedRequests.isEmpty());
	}

	public void addPersistentRequests(List<ClientRequest> v, boolean onlyForever) {
		synchronized(this) {
			for(ClientRequest req: runningPersistentRequests) {
				if(req == null) {
					Logger.error(this, "Request is null on runningPersistentRequests for "+this+" - database corruption??");
					continue;
				}
				if((req.isPersistentForever()) || !onlyForever)
					v.add(req);
			}
			v.addAll(completedUnackedRequests);
		}
	}
	
	/** From database */
	private void addPersistentRequestStatus(List<RequestStatus> status, boolean onlyForever) {
		// FIXME OPT merge with addPersistentRequests? Locking looks tricky.
		List<ClientRequest> reqs = new ArrayList<ClientRequest>();
		addPersistentRequests(reqs, onlyForever);
		for(ClientRequest req : reqs) {
			try {
				status.add(req.getStatus());
			} catch (Throwable t) {
				// Try to load the rest. :<
				Logger.error(this, "BROKEN REQUEST LOADING PERSISTENT REQUEST STATUS: "+t, t);
				// FIXME tell the user in wrapper.log or even in a useralert.
			}
			// FIXME deactivate? Unconditional deactivate depends on callers. Keep-as-is would need merge with addPersistentRequests.
		}
	}
	
	/** From cache */
	public void addPersistentRequestStatus(List<RequestStatus> status) {
		statusCache.addTo(status);
	}

	/**
	 * Enable or disable watch-the-global-queue.
	 * @param enabled Whether we want watch-global-queue to be enabled.
	 * @param verbosityMask If so, what verbosity mask to use (to filter messages
	 * generated by the global queue).
	 */
	public boolean setWatchGlobal(boolean enabled, int verbosityMask, FCPServer server) {
		if(isGlobalQueue) {
			Logger.error(this, "Set watch global on global queue!: "+this, new Exception("debug"));
			return false;
		}
		if(server.globalForeverClient == null) return false;
		if(watchGlobal && !enabled) {
			server.globalRebootClient.unwatch(this);
			server.globalForeverClient.unwatch(this);
			watchGlobal = false;
		} else if(enabled && !watchGlobal) {
			server.globalRebootClient.watch(this);
			server.globalForeverClient.watch(this);
			FCPConnectionHandler connHandler = getConnection();
			if(connHandler != null) {
				if(persistence == Persistence.REBOOT)
					server.globalRebootClient.queuePendingMessagesOnConnectionRestartAsync(connHandler.outputHandler, server.core.clientContext);
				else
					server.globalForeverClient.queuePendingMessagesOnConnectionRestartAsync(connHandler.outputHandler, server.core.clientContext);
			}
			watchGlobal = true;
		}
		// Otherwise the status is unchanged.
		this.watchGlobalVerbosityMask = verbosityMask;
		return true;
	}

	public void queueClientRequestMessage(FCPMessage msg, int verbosityLevel) {
		queueClientRequestMessage(msg, verbosityLevel, false);
	}
	
	public void queueClientRequestMessage(FCPMessage msg, int verbosityLevel, boolean useGlobalMask) {
		if(useGlobalMask && (verbosityLevel & watchGlobalVerbosityMask) != verbosityLevel)
			return;
		FCPConnectionHandler conn = getConnection();
		if(conn != null) {
			conn.outputHandler.queue(msg);
		}
		PersistentRequestClient[] clients;
		if(isGlobalQueue) {
			synchronized(clientsWatchingLock) {
				if(clientsWatching != null)
				clients = clientsWatching.toArray(new PersistentRequestClient[clientsWatching.size()]);
				else
					clients = null;
			}
			if(clients != null)
			for(PersistentRequestClient client: clients) {
				if(client.persistence != persistence) continue;
				client.queueClientRequestMessage(msg, verbosityLevel, true);
			}
		}
	}
	
	private void unwatch(PersistentRequestClient client) {
		if(!isGlobalQueue) return;
		synchronized(clientsWatchingLock) {
			if(clientsWatching != null)
			clientsWatching.remove(client);
		}
	}

	private void watch(PersistentRequestClient client) {
		if(!isGlobalQueue) return;
		synchronized(clientsWatchingLock) {
			if(clientsWatching == null)
				clientsWatching = new LinkedList<PersistentRequestClient>();
			clientsWatching.add(client);
		}
	}

	public synchronized ClientRequest getRequest(String identifier) {
		ClientRequest req = clientRequestsByIdentifier.get(identifier);
		return req;
	}

	@Override
	public String toString() {
		return super.toString()+ ':' +name;
	}

	/**
	 * Callback called when a request succeeds.
	 */
	public void notifySuccess(ClientRequest req) {
		assert(req.persistence == persistence);
        RequestCompletionCallback[] callbacks = null;
        synchronized(this) {
        	if(completionCallbacks != null)
        		callbacks = completionCallbacks.toArray(new RequestCompletionCallback[completionCallbacks.size()]);
        }
		if(callbacks != null) {
			for(RequestCompletionCallback cb : callbacks)
				cb.notifySuccess(req);
		}
	}

	/**
	 * Callback called when a request fails
	 * @param get
	 */
	public void notifyFailure(ClientRequest req) {
		assert(req.persistence == persistence);
        RequestCompletionCallback[] callbacks = null;
        synchronized(this) {
        	if(completionCallbacks != null)
        		callbacks = completionCallbacks.toArray(new RequestCompletionCallback[completionCallbacks.size()]);
        }
		if(callbacks != null) {
			for(RequestCompletionCallback cb : callbacks)
				cb.notifyFailure(req);
		}
	}
	
	public synchronized void addRequestCompletionCallback(RequestCompletionCallback cb) {
		if(completionCallbacks == null) completionCallbacks = new ArrayList<RequestCompletionCallback>(); // it is transient so it might be null
		completionCallbacks.add(cb);
	}
	
	public synchronized void removeRequestCompletionCallback(RequestCompletionCallback cb){
		if(completionCallbacks!=null) completionCallbacks.remove(cb);
	}

	public void removeAll() {
		HashSet<ClientRequest> toKill = new HashSet<ClientRequest>();
		if(statusCache != null)
			statusCache.clear();
		synchronized(this) {
			for(ClientRequest req: runningPersistentRequests) {
				toKill.add(req);
			}
			runningPersistentRequests.clear();
			for(ClientRequest req : completedUnackedRequests) {
				toKill.add(req);
			}
			completedUnackedRequests.clear();
			for(ClientRequest req : clientRequestsByIdentifier.values()) {
				toKill.add(req);
			}
			clientRequestsByIdentifier.clear();
		}
	}

	public ClientGet getCompletedRequest(FreenetURI key) {
		// FIXME speed this up with another hashmap or something.
		// FIXME keep a transient hashmap in RAM, use it for fproxy.
		// FIXME consider supporting inserts too.
		for(int i=0;i<completedUnackedRequests.size();i++) {
			ClientRequest req = completedUnackedRequests.get(i);
			if(!(req instanceof ClientGet)) continue;
			ClientGet getter = (ClientGet) req;
			if(getter.getURI().equals(key)) {
				return getter;
			}
		}
		return null;
	}

	public RequestStatusCache getRequestStatusCache() {
		return statusCache;
	}
	
	public void updateRequestStatusCache() {
	    updateRequestStatusCache(statusCache);
	}
	
	private void updateRequestStatusCache(RequestStatusCache cache) {
		if(persistence == Persistence.FOREVER) {
			System.out.println("Loading cache of request statuses...");
			ArrayList<RequestStatus> statuses = new ArrayList<RequestStatus>();
			addPersistentRequestStatus(statuses, true);
			for(RequestStatus status : statuses) {
				if(status instanceof DownloadRequestStatus)
					cache.addDownload((DownloadRequestStatus)status);
				else
					cache.addUpload((UploadRequestStatus)status);
			}
		}
	}

	public RequestClient lowLevelClient(boolean realTime) {
		if(realTime)
			return lowLevelClientRT;
		else
			return lowLevelClient;
	}
	
    public void addPersistentRequesters(List<ClientRequester> requesters) {
        for(ClientRequest req : runningPersistentRequests)
            requesters.add(req.getClientRequest());
        for(ClientRequest req : completedUnackedRequests)
            requesters.add(req.getClientRequest());
    }

    public void resume(ClientRequest clientRequest) {
        if(clientRequest.hasFinished())
            completedUnackedRequests.add(clientRequest);
        else
            runningPersistentRequests.add(clientRequest);
        String identifier = clientRequest.identifier;
        if(clientRequestsByIdentifier.get(identifier) != null) {
            if(clientRequest != clientRequestsByIdentifier.get(identifier))
                throw new IllegalArgumentException("Adding new client request "+clientRequest+
                        " with same name \""+identifier+"\" as "+
                        clientRequestsByIdentifier.get(identifier));
            else {
                Logger.error(this, "Adding the same identifier twice: "+identifier);
                return;
            }
        } else {
            clientRequestsByIdentifier.put(identifier, clientRequest);
        }
    }

}
