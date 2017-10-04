package freenet.clients.fcp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;

import freenet.client.async.ClientContext;
import freenet.client.async.ClientRequester;
import freenet.client.async.PersistenceDisabledException;
import freenet.client.async.PersistentJob;
import freenet.crypt.ChecksumChecker;
import freenet.keys.FreenetURI;
import freenet.node.PrioRunnable;
import freenet.node.RequestClient;
import freenet.node.RequestClientBuilder;
import freenet.node.RequestStarter;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.io.NativeThread;
import freenet.support.io.ResumeFailedException;
import freenet.support.io.StorageFormatException;

/**
 * A request process carried out by the node for an FCP client.
 * Examples: ClientGet, ClientPut, MultiGet.
 */
public abstract class ClientRequest implements Serializable {

    /**
     * ATTENTION: When incrementing this, please skip version 2. Version 2 had already temporarily
     * been used by a development branch. */
    private static final long serialVersionUID = 1L;
    /** URI to fetch, or target URI to insert to */
	protected FreenetURI uri;
	/** Unique request identifier */
	protected final String identifier;
	/** Verbosity level. Relevant to all ClientRequests, although they interpret it
	 * differently. */
	protected final int verbosity;
	/** Original FCPConnectionHandler. Null if persistence != connection */
	protected transient final FCPConnectionHandler origHandler;
	/** Is the request on the global queue? */
    protected final boolean global;
    /** If the request isn't on the global queue, what is the client's name? */
    protected final String clientName;
	/** Client */
	protected transient PersistentRequestClient client;
	/** Priority class */
	protected short priorityClass;
	/** Is the request scheduled as "real-time" (as opposed to bulk)? */
	protected final boolean realTime;
	/** Persistence type */
	protected final Persistence persistence;
	/** Has the request finished? */
	protected boolean finished;
	/** Client token (string to feed back to the client on a Persistent* when he does a
	 * ListPersistentRequests). */
	protected String clientToken;
	/** Timestamp : startup time */
	protected final long startupTime;
	/** Timestamp : completion time */
	protected long completionTime;

	protected transient RequestClient lowLevelClient;
	private final int hashCode; // for debugging it is good to have a persistent id
	
	@Override
	public int hashCode() {
		return hashCode;
	}

	private static volatile boolean logMINOR;
	
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	public ClientRequest(FreenetURI uri2, String identifier2, int verbosity2,
			FCPConnectionHandler handler, PersistentRequestClient client, short priorityClass2, Persistence persistenceType2, boolean realTime, String clientToken2, boolean global) {
		int hash = super.hashCode();
		if(hash == 0) hash = 1;
		hashCode = hash;
		this.uri = uri2;
		this.identifier = identifier2;
		if(global) {
			this.verbosity = Integer.MAX_VALUE;
			this.clientName = null;
		} else {
			this.verbosity = verbosity2;
			this.clientName = client.name;
	    }
		this.finished = false;
		this.priorityClass = priorityClass2;
		this.persistence = persistenceType2;
		this.clientToken = clientToken2;
		this.global = global;
		if(persistence == Persistence.CONNECTION) {
			this.origHandler = handler;
			lowLevelClient = origHandler.connectionRequestClient(realTime);
			this.client = null;
		} else {
			origHandler = null;
			this.client = client;
			assert client != null;
			assert(client.persistence == persistence);
			lowLevelClient = client.lowLevelClient(realTime);
		}
		assert lowLevelClient != null;
		this.startupTime = System.currentTimeMillis();
		this.realTime = realTime;
	}

	public ClientRequest(FreenetURI uri2, String identifier2, int verbosity2,
			FCPConnectionHandler handler, short priorityClass2, Persistence persistenceType2, final boolean realTime, String clientToken2, boolean global) {
		int hash = super.hashCode();
		if(hash == 0) hash = 1;
		hashCode = hash;
		this.uri = uri2;
		
		this.identifier = identifier2;
		this.finished = false;
		this.priorityClass = priorityClass2;
		this.persistence = persistenceType2;
		this.clientToken = clientToken2;
		this.global = global;
		if(persistence == Persistence.CONNECTION) {
			this.origHandler = handler;
			client = null;
			lowLevelClient = new RequestClientBuilder().realTime(realTime).build();
			this.clientName = null;
            this.verbosity = verbosity2;
		} else {
			origHandler = null;
			if(global) {
				client = persistence == Persistence.FOREVER ? handler.server.globalForeverClient : handler.server.globalRebootClient;
	            this.verbosity = Integer.MAX_VALUE;
	            clientName = null;
			} else {
				client = persistence == Persistence.FOREVER ? handler.getForeverClient() : handler.getRebootClient();
	            this.verbosity = verbosity2;
	            this.clientName = client.name;
			}
			lowLevelClient = client.lowLevelClient(realTime);
			if(lowLevelClient == null)
				throw new NullPointerException("No lowLevelClient from client: "+client+" global = "+global+" persistence = "+persistence);
		}
		if(lowLevelClient.persistent() != (persistence == Persistence.FOREVER))
			throw new IllegalStateException("Low level client.persistent="+lowLevelClient.persistent()+" but persistence type = "+persistence);
		if(client != null)
			assert(client.persistence == persistence);
		this.startupTime = System.currentTimeMillis();
		this.realTime = realTime;
	}
	
	protected ClientRequest() {
	    // For serialization.
	    identifier = null;
	    verbosity = 0;
	    origHandler = null;
	    global = false;
	    clientName = null;
	    realTime = false;
	    persistence = null;
	    startupTime = 0;
	    hashCode = 0;
	}

    /** Lost connection */
	public abstract void onLostConnection(ClientContext context);

	/** Send any pending messages for a persistent request e.g. after reconnecting */
	public abstract void sendPendingMessages(FCPConnectionOutputHandler handler, String listRequestIdentifier, boolean includeData, boolean onlyData);

	// Persistence

	public enum Persistence {
        /** Default: persists until connection loss. */
	    CONNECTION,
	    /** Reports to client by name; persists over connection loss.
	     * Not saved to disk, so dies on reboot. */
	    REBOOT,
        /** Same as reboot but saved to disk, persists forever. */
	    FOREVER;

        public static Persistence parseOrThrow(String persistenceString, String identifier, boolean global) throws MessageInvalidException {
            try {
                if(persistenceString == null) return Persistence.CONNECTION;
                else return Persistence.valueOf(persistenceString.toUpperCase());
            } catch (IllegalArgumentException e) {
                throw new MessageInvalidException(ProtocolErrorMessage.ERROR_PARSING_NUMBER, "Error parsing Persistence field: "+persistenceString, identifier, global);
            }
        }

        @Deprecated // Only for migration
        public static Persistence getByCode(short persistenceType) {
            if(persistenceType < 0 || persistenceType > values().length) throw new IllegalArgumentException();
            return values()[persistenceType];
        }
	}

	abstract void register(boolean noTags) throws IdentifierCollisionException;

	public void cancel(ClientContext context) {
		ClientRequester cr = getClientRequest();
		// It might have been finished on startup.
		if(logMINOR) Logger.minor(this, "Cancelling "+cr+" for "+this+" persistence = "+persistence);
		if(cr != null) cr.cancel(context);
		freeData();
	}

	public boolean isPersistentForever() {
		return persistence == Persistence.FOREVER;
	}

	/** Is the request persistent? False = we can drop the request if we lose the connection */
	public boolean isPersistent() {
		return persistence != Persistence.CONNECTION;
	}

	public boolean hasFinished() {
		return finished;
	}

	/** Get identifier string for request */
	public String getIdentifier() {
		return identifier;
	}

	protected abstract ClientRequester getClientRequest();

	/** Completed request dropped off the end without being acknowledged */
	public void dropped(ClientContext context) {
		cancel(context);
		freeData();
	}

	/** Return the priority class */
	public short getPriority(){
		return priorityClass;
	}

	/** Free cached data bucket(s) */
	protected abstract void freeData(); 

	/** Request completed. But we may have to stick around until we are acked. */
	protected void finish() {
		if(persistence == Persistence.CONNECTION)
			origHandler.finishedClientRequest(this);
		else
			client.finishedClientRequest(this);
	}

	public abstract double getSuccessFraction();

	public abstract double getTotalBlocks();
	public abstract double getMinBlocks();
	public abstract double getFetchedBlocks();
	public abstract double getFailedBlocks();
	public abstract double getFatalyFailedBlocks();

	public abstract String getFailureReason(boolean longDescription);

	/**
	 * Has the total number of blocks to insert been determined yet?
	 */
	public abstract boolean isTotalFinalized();

	/** Start the request, if it has not already been started. */
	public abstract void start(ClientContext context);

	protected boolean started;

	public boolean isStarted() {
		return started;
	}

	public abstract boolean hasSucceeded();

	/**
	 * Returns the time of the request’s last activity, or {@code 0} if there is
	 * no known last activity.
	 *
	 * @return The time of the request’s last activity, or {@code 0}
	 * @deprecated
	 *     Use {@link ClientRequester#getLatestSuccess()} instead. You can use 
	 *     {@link #getClientRequest()} to obtain the ClientRequester.
	 */
	@Deprecated
	public long getLastActivity() {
	    ClientRequester cr = getClientRequest();
	    // I have not actually read the code to find out whether this if() is needed.
	    // But this function is deprecated at the time of its writing and thus will be removed soon,
	    // so there is no reason to invest the time to read the code to see whether it will happen.
	    if (cr == null) {
	        return 0;
	    }
	    
	    return cr.getLatestSuccess().getTime();
	}

	public abstract boolean canRestart();

	public abstract boolean restart(ClientContext context, boolean disableFilterData) throws PersistenceDisabledException;

	/**
	 * Called after a ModifyPersistentRequest.
	 * Sends a PersistentRequestModified message to clients if any value changed. 
	 */
	public void modifyRequest(String newClientToken, short newPriorityClass, FCPServer server) {

		boolean clientTokenChanged = false;
		boolean priorityClassChanged = false;

		if(newClientToken != null) {
			if( clientToken != null ) {
				if( !newClientToken.equals(clientToken) ) {
					this.clientToken = newClientToken; // token changed
					clientTokenChanged = true;
				}
			} else {
				this.clientToken = newClientToken; // first time the token is set
				clientTokenChanged = true;
			}
		}
		
		if(newPriorityClass >= 0 && newPriorityClass != priorityClass) {
			this.priorityClass = newPriorityClass;
			ClientRequester r = getClientRequest();
			r.setPriorityClass(priorityClass, server.core.clientContext);
			priorityClassChanged = true;
			if(client != null) {
				RequestStatusCache cache = client.getRequestStatusCache();
				if(cache != null) {
					cache.setPriority(identifier, newPriorityClass);
				}
			}
		}

		if(! ( clientTokenChanged || priorityClassChanged ) ) {
			return; // quick return, nothing was changed
		}
		
		server.core.clientContext.jobRunner.setCheckpointASAP();
		
		// this could become too complex with more parameters, but for now its ok
		final PersistentRequestModifiedMessage modifiedMsg;
		if( clientTokenChanged && priorityClassChanged ) {
			modifiedMsg = new PersistentRequestModifiedMessage(identifier, global, priorityClass, clientToken);
		} else if( priorityClassChanged ) {
			modifiedMsg = new PersistentRequestModifiedMessage(identifier, global, priorityClass);
		} else if( clientTokenChanged ) {
			modifiedMsg = new PersistentRequestModifiedMessage(identifier, global, clientToken);
		} else {
			return; // paranoia, we should not be here if nothing was changed!
		}
		client.queueClientRequestMessage(modifiedMsg, 0);
	}

	public void restartAsync(final FCPServer server, final boolean disableFilterData) throws PersistenceDisabledException {
		synchronized(this) {
			this.started = false;
		}
		if(client != null) {
			RequestStatusCache cache = client.getRequestStatusCache();
			if(cache != null) {
				cache.updateStarted(identifier, false);
			}
		}
		if(persistence == Persistence.FOREVER) {
		server.core.clientContext.jobRunner.queue(new PersistentJob() {

			@Override
			public boolean run(ClientContext context) {
			    try {
			        restart(context, disableFilterData);
			    } catch (PersistenceDisabledException e) {
			        // Impossible
			    }
				return true;
			}
			
		}, NativeThread.HIGH_PRIORITY);
		} else {
			server.core.getExecutor().execute(new PrioRunnable() {

				@Override
				public int getPriority() {
					return NativeThread.NORM_PRIORITY;
				}

				@Override
				public void run() {
				    try {
                        restart(server.core.clientContext, disableFilterData);
                    } catch (PersistenceDisabledException e) {
                        // Impossible
                    }
				}
				
			}, "Restart request");
		}
	}

	/**
	 * Called after a RemovePersistentRequest. Send a PersistentRequestRemoved to the clients.
	 * If the request is in the database, delete it.
	 */
	public void requestWasRemoved(ClientContext context) {
		if(persistence != Persistence.FOREVER) return;
	}

	protected boolean isGlobalQueue() {
		if(client == null) return false;
		return client.isGlobalQueue;
	}

	public PersistentRequestClient getClient(){
		return client;
	}

	abstract RequestStatus getStatus();
	
	private static final long CLIENT_DETAIL_MAGIC = 0xebf0b4f4fa9f6721L;
	private static final int CLIENT_DETAIL_VERSION = 1;

    public void getClientDetail(DataOutputStream dos, ChecksumChecker checker) throws IOException {
        if(persistence != Persistence.FOREVER) return;
        dos.writeLong(CLIENT_DETAIL_MAGIC);
        dos.writeInt(CLIENT_DETAIL_VERSION);
        // Identify the request first.
        RequestIdentifier req = getRequestIdentifier();
        req.writeTo(dos);
        // Basic details needed for scheduling, reporting and completion.
        dos.writeBoolean(realTime);
        dos.writeInt(verbosity);
        dos.writeLong(startupTime);
        // persistence is assumed to be PERSIST_FOREVER.
        // uri will be handled by subclasses.
        // This can change.
        dos.writeShort(priorityClass);
        // This can change and is variable size.
        if(clientToken == null)
            dos.writeBoolean(false);
        else {
            dos.writeBoolean(true);
            dos.writeUTF(clientToken);
        }
        // Stuff that changes on completion
        dos.writeBoolean(finished);
    }
    
    protected ClientRequest(DataInputStream dis, RequestIdentifier reqID, 
            ClientContext context) throws IOException, StorageFormatException {
        long magic = dis.readLong();
        if(magic != CLIENT_DETAIL_MAGIC)
            throw new StorageFormatException("Bad magic");
        int version = dis.readInt();
        if(version != CLIENT_DETAIL_VERSION)
            throw new StorageFormatException("Bad version");
        RequestIdentifier copyReq = new RequestIdentifier(dis);
        if(!copyReq.equals(reqID))
            throw new StorageFormatException("Request identifier has changed");
        realTime = dis.readBoolean();
        verbosity = dis.readInt();
        startupTime = dis.readLong();
        priorityClass = dis.readShort();
        if(priorityClass < RequestStarter.MAXIMUM_PRIORITY_CLASS || 
                priorityClass > RequestStarter.PAUSED_PRIORITY_CLASS)
            throw new StorageFormatException("Bogus priority");
        if(dis.readBoolean())
            clientToken = dis.readUTF();
        else
            clientToken = null;
        finished = dis.readBoolean();
        persistence = Persistence.FOREVER;
        origHandler = null;
        identifier = reqID.identifier;
        global = reqID.globalQueue;
        clientName = reqID.clientName;
        hashCode = super.hashCode();
        // We can't wait until onResume() to get the client, because it may be used in the 
        // constructors.
        this.client = context.persistentRoot.makeClient(global, clientName);
        this.lowLevelClient = client.lowLevelClient(realTime);
    }

    /** Called just after serializing in the request. Called by the ClientRequester, i.e. the tree 
     * starts there, and we MUST NOT call back to it or we get an infinite recursion. The main 
     * purpose of this method is to give us an opportunity to connect to the various (transient) 
     * system utilities we get from ClientContext, e.g. bucket factories, the FCP persistent root 
     * etc. The base class implementation in ClientRequest will register the request with an 
     * PersistentRequestClient via the new PersistentRequestRoot.
     * @param context Contains all the important system utilities.
     * @throws ResumeFailedException 
     */
    public final void onResume(ClientContext context) throws ResumeFailedException {
        client = context.persistentRoot.makeClient(global, clientName);
        lowLevelClient = client.lowLevelClient(realTime);
        innerResume(context);
        ClientRequester req = getClientRequest();
        if(req != null) req.onResume(context); // Can legally be null.
        context.persistentRoot.resume(this, global, clientName);
    }
    
    protected abstract void innerResume(ClientContext context) throws ResumeFailedException;

    public RequestClient getRequestClient() {
        return lowLevelClient;
    }

    /** Get the RequestIdentifier. This just includes the queue and the identifier. */
    public RequestIdentifier getRequestIdentifier() {
        if(persistence == Persistence.CONNECTION) throw new IllegalStateException(); // Not associated with any client.
        return new RequestIdentifier(global, clientName, identifier, getType());
    }
    
    abstract RequestIdentifier.RequestType getType();

    public static ClientRequest restartFrom(DataInputStream dis, RequestIdentifier reqID,
            ClientContext context, ChecksumChecker checker) throws StorageFormatException, IOException, ResumeFailedException {
        switch(reqID.type) {
        case GET:
            return ClientGet.restartFrom(dis, reqID, context, checker);
        default:
            return null;
        }
    }

    /** Return true if we resumed the original fetch from stored data (usually a file for a 
     * splitfile download), rather than having to restart it (which happens in most other cases
     * when we resume). */
    public abstract boolean fullyResumed();

    /** Called just before the final write when the node is shutting down. Should write any dirty
     * data to disk etc. */
    public void onShutdown(ClientContext context) {
        ClientRequester request = getClientRequest();
        if(request != null)
            request.onShutdown(context);
    }
}
