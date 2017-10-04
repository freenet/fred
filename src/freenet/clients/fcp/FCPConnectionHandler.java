package freenet.clients.fcp;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import freenet.client.async.ClientContext;
import freenet.client.async.PersistenceDisabledException;
import freenet.client.async.PersistentJob;
import freenet.client.async.TooManyFilesInsertException;
import freenet.clients.fcp.ClientRequest.Persistence;
import freenet.node.RequestClient;
import freenet.node.RequestClientBuilder;
import freenet.pluginmanager.PluginManager;
import freenet.pluginmanager.PluginNotFoundException;
import freenet.pluginmanager.PluginRespirator;
import freenet.support.HexUtil;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.BucketFactory;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import freenet.support.io.NativeThread;

public class FCPConnectionHandler implements Closeable {
	private static final class DirectoryAccess {
		final boolean canWrite;
		final boolean canRead;
		
		public DirectoryAccess(boolean canRead, boolean canWrite) {
			this.canRead = canRead;
			this.canWrite = canWrite;
		}
	}
	
	public static class DDACheckJob {
		final File directory, readFilename, writeFilename;
		final String readContent, writeContent;
		
		/**
		 * null if not requested.
		 */
		DDACheckJob(Random r, File directory, File readFilename, File writeFilename) {
			this.directory = directory;
			this.readFilename = readFilename;
			this.writeFilename = writeFilename;
			
			byte[] random = new byte[128];
			
			r.nextBytes(random);
			this.readContent = HexUtil.bytesToHex(random);

			r.nextBytes(random);
			this.writeContent = HexUtil.bytesToHex(random);
		}
	}

	final FCPServer server;
	final Socket sock;
	final FCPConnectionInputHandler inputHandler;
	final Map<String, SubscribeUSK> uskSubscriptions;
	public final FCPConnectionOutputHandler outputHandler;
	private boolean isClosed;
	private boolean inputClosed;
	private boolean outputClosed;
	private String clientName;
	private PersistentRequestClient rebootClient;
	private PersistentRequestClient foreverClient;
	final BucketFactory bf;
	final HashMap<String, ClientRequest> requestsByIdentifier;

    /**
     * {@link FCPPluginConnectionImpl} indexed by the server plugin name (see
     * {@link PluginManager#getPluginFCPServer(String)}.<br><br>
     * 
     * This also serves the same purpose as the client which is connected to this would normally
     * be responsible for if it was running as a plugin in the node (as specified by
     * {@link PluginRespirator#connectToOtherPlugin(String, ClientSideFCPMessageHandler)}):<br>
     * It keeps strong references to the {@link FCPPluginConnectionImpl} objects, and thereby marks
     * them as alive.<br>
     * This in turn causes the {@link FCPPluginConnectionImpl} objects to stay available in the
     * {@link FCPPluginConnectionTracker}, which allows server plugins to query them by their ID.
     */
    private final TreeMap<String, FCPPluginConnectionImpl> pluginConnectionsByServerName
        = new TreeMap<String, FCPPluginConnectionImpl>();

    /**
     * Lock for {@link #pluginConnectionsByServerName}.
     * 
     * A {@link ReadWriteLock} because the usage pattern is mostly reads, very few writes -
     * {@link ReadWriteLock} can do that faster than a regular Lock.
     * (A {@link ReentrantReadWriteLock} because thats the only implementation of
     * {@link ReadWriteLock}.)
     */
    private final ReadWriteLock pluginConnectionsByServerName_Lock
        = new ReentrantReadWriteLock();

    /**
     * 16 random bytes hex-encoded as String. Unique for each instance of this class.
     * 
     * @deprecated Use {@link #connectionIdentifierUUID} instead.
     */
    @Deprecated
    public final String connectionIdentifier;
	
	/** Random UUID unique for each instance of this class */
	protected final UUID connectionIdentifierUUID;
	
	private static volatile boolean logMINOR;
	private boolean killedDupe;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	// We are confident that the given client can access those
	private final HashMap<String, DirectoryAccess> checkedDirectories = new HashMap<String, DirectoryAccess>();
	// DDACheckJobs in flight
	private final HashMap<File, DDACheckJob> inTestDirectories = new HashMap<File, DDACheckJob>();
	public final RequestClient connectionRequestClientBulk = new RequestClientBuilder().build();
	public final RequestClient connectionRequestClientRT = new RequestClientBuilder().realTime().build();

	public FCPConnectionHandler(Socket s, FCPServer server) {
		this.sock = s;
		this.server = server;
		isClosed = false;
		this.bf = server.core.tempBucketFactory;
		requestsByIdentifier = new HashMap<String, ClientRequest>();
		uskSubscriptions = new HashMap<String, SubscribeUSK>();
		this.inputHandler = new FCPConnectionInputHandler(this);
		this.outputHandler = new FCPConnectionOutputHandler(this);
		
		byte[] identifier = new byte[16];
		server.node.random.nextBytes(identifier);
		this.connectionIdentifier = HexUtil.bytesToHex(identifier);
		
        // The random 16-byte identifier was used before we added the UUID. Luckily, UUIDs are also
        // 16 byetes, so we can re-use the bytes.
        // TODO: When getting rid of the non-UUID connectionIdentifier, use UUID.randomUUID();
        this.connectionIdentifierUUID = UUID.nameUUIDFromBytes(identifier);
	}

    /**
     * Queues the message for sending at the {@link FCPConnectionOutputHandler}.<br>
     * <br>
     * 
     * ATTENTION: The function will return immediately before even trying to send the message, the
     * message will be sent asynchronously.<br>
     * As a consequence, this function not throwing does not give any guarantee whatsoever that the
     * message will ever be sent.
     */
    @SuppressWarnings("deprecation")
    public final void send(final FCPMessage message) {
        outputHandler.queue(message);
    }

	void start() {
		inputHandler.start();
		outputHandler.start();
	}

	@Override
	public void close() {
		ClientRequest[] requests;
		if(rebootClient != null)
			rebootClient.onLostConnection(this);
		if(foreverClient != null)
			foreverClient.onLostConnection(this);
		boolean dupe;
		SubscribeUSK[] uskSubscriptions2;
		synchronized(this) {
			if(isClosed) {
				// This is normal, both input and output handlers will call close().
				return;
			}
			isClosed = true;
			requests = new ClientRequest[requestsByIdentifier.size()];
			requests = requestsByIdentifier.values().toArray(requests);
			requestsByIdentifier.clear();
			uskSubscriptions2 = uskSubscriptions.values().toArray(new SubscribeUSK[uskSubscriptions.size()]);
			dupe = killedDupe;
		}
		for(ClientRequest req : requests)
			req.onLostConnection(server.core.clientContext);
		for(SubscribeUSK sub : uskSubscriptions2)
			sub.unsubscribe();
		if(!dupe) {
		    try {
		        server.core.clientContext.jobRunner.queue(new PersistentJob() {
		            
		            @Override
		            public boolean run(ClientContext context) {
		                if((rebootClient != null) && !rebootClient.hasPersistentRequests())
		                    server.unregisterClient(rebootClient);
		                if(foreverClient != null) {
		                    if(!foreverClient.hasPersistentRequests())
		                        server.unregisterClient(foreverClient);
		                }
		                return false;
		            }
		            
		        }, NativeThread.NORM_PRIORITY);
		    } catch (PersistenceDisabledException e) {
		        // Ignore
		    }
		}
		
		outputHandler.onClosed();
	}
	
	synchronized void setKilledDupe() {
		killedDupe = true;
	}
	
	public synchronized boolean isClosed() {
		return isClosed;
	}
	
	public void closedInput() {
		try {
			sock.shutdownInput();
		} catch (IOException e) {
			// Ignore
		}
		synchronized(this) {
			inputClosed = true;
			if(!outputClosed) return;
		}
		try {
			sock.close();
		} catch (IOException e) {
			// Ignore
		}
	}
	
	public void closedOutput() {
		try {
			sock.shutdownOutput();
		} catch (IOException e) {
			// Ignore
		}
		synchronized(this) {
			outputClosed = true;
			if(!inputClosed) return;
		}
		try {
			sock.close();
		} catch (IOException e) {
			// Ignore
		}
	}

	public void setClientName(final String name) {
		this.clientName = name;
		rebootClient = server.registerRebootClient(name, this);
		rebootClient.queuePendingMessagesOnConnectionRestartAsync(outputHandler, server.core.clientContext);
		// Create foreverClient lazily. Everything that needs it (especially creating ClientGet's etc) runs on a database job.
		if(logMINOR)
			Logger.minor(this, "Set client name: "+name);
		PersistentRequestClient client = server.getForeverClient(name, this);
		if(client != null) {
		    synchronized(this) {
		        foreverClient = client;
		    }
            foreverClient.queuePendingMessagesOnConnectionRestartAsync(outputHandler, server.core.clientContext);
		}
	}
	
	protected PersistentRequestClient createForeverClient(String name) {
		synchronized(FCPConnectionHandler.this) {
			if(foreverClient != null) return foreverClient;
		}
		PersistentRequestClient client = server.registerForeverClient(name, FCPConnectionHandler.this);
		synchronized(FCPConnectionHandler.this) {
			foreverClient = client;
			FCPConnectionHandler.this.notifyAll();
		}
		client.queuePendingMessagesOnConnectionRestartAsync(outputHandler, server.core.clientContext);
		return foreverClient;
	}

	public String getClientName() {
		return clientName;
	}

	// FIXME next 3 methods are in need of refactoring!
	
	/**
	 * Start a ClientGet. If there is an identifier collision, queue an IdentifierCollisionMessage.
	 * Hence, we can run stuff on other threads if we need to, as long as we send the right messages.
	 */
	public void startClientGet(final ClientGetMessage message) {
		final String id = message.identifier;
		final boolean global = message.global;
		ClientGet cg = null;
		boolean success;
		boolean persistent = message.persistence != Persistence.CONNECTION;
		synchronized(this) {
			if(isClosed) return;
			// We need to track non-persistent requests anyway, so we may as well check
			if(persistent)
				success = true;
			else
				success = !requestsByIdentifier.containsKey(id);
			if(success) {
				try {
					
					if(!persistent) {
						cg = new ClientGet(this, message, server.core);
						requestsByIdentifier.put(id, cg);
					} else if(message.persistence == Persistence.FOREVER) {
					    try {
					        server.core.clientContext.jobRunner.queue(new PersistentJob() {
					            
					            @Override
					            public boolean run(ClientContext context) {
					                ClientGet getter;
					                try {
					                    getter = new ClientGet(FCPConnectionHandler.this, message, server.core);
					                } catch (IdentifierCollisionException e1) {
					                    Logger.normal(this, "Identifier collision on "+this);
					                    FCPMessage msg = new IdentifierCollisionMessage(id, message.global);
					                    outputHandler.queue(msg);
					                    return false;
					                } catch (MessageInvalidException e1) {
					                    outputHandler.queue(new ProtocolErrorMessage(e1.protocolCode, false, e1.getMessage(), e1.ident, e1.global));
					                    return false;
					                }
					                try {
					                    getter.register(false);
					                } catch (IdentifierCollisionException e) {
					                    Logger.normal(this, "Identifier collision on "+this);
					                    FCPMessage msg = new IdentifierCollisionMessage(id, global);
					                    outputHandler.queue(msg);
					                    return false;
					                }
					                getter.start(context);
					                return true;
					            }
					            
					        }, NativeThread.HIGH_PRIORITY-1);
					    } catch (PersistenceDisabledException e) {
					        outputHandler.queue(new ProtocolErrorMessage(ProtocolErrorMessage.PERSISTENCE_DISABLED, false, "Persistence is disabled", id, global));
					        return;
					    }
						return; // Don't run the start() below
					} else {
						cg = new ClientGet(this, message, server.core);
					}
				} catch (IdentifierCollisionException e) {
					success = false;
				} catch (MessageInvalidException e) {
					outputHandler.queue(new ProtocolErrorMessage(e.protocolCode, false, e.getMessage(), e.ident, e.global));
					return;
				}
			}
		}
		if(message.persistence == Persistence.REBOOT)
			try {
				cg.register(false);
			} catch (IdentifierCollisionException e) {
				success = false;
			}
		if(!success) {
			Logger.normal(this, "Identifier collision on "+this);
			FCPMessage msg = new IdentifierCollisionMessage(id, message.global);
			outputHandler.queue(msg);
			return;
		} else {
			cg.start(server.core.clientContext);
		}
	}

	public void startClientPut(final ClientPutMessage message) {
		if(logMINOR)
			Logger.minor(this, "Starting insert ID=\""+message.identifier+ '"');
		final String id = message.identifier;
		final boolean global = message.global;
		ClientPut cp = null;
		boolean persistent = message.persistence != Persistence.CONNECTION;
		FCPMessage failedMessage = null;
		synchronized(this) {
			boolean success;
			if(isClosed) {
				if(logMINOR) Logger.minor(this, "Connection is closed");
				return;
			}
			// We need to track non-persistent requests anyway, so we may as well check
			if(persistent)
				success = true;
			else
				success = !requestsByIdentifier.containsKey(id);
			if(success) {
				if(!persistent) {
					try {
						cp = new ClientPut(this, message, server);
						requestsByIdentifier.put(id, cp);
					} catch (IdentifierCollisionException e) {
						success = false;
					} catch (MessageInvalidException e) {
						outputHandler.queue(new ProtocolErrorMessage(e.protocolCode, false, e.getMessage(), e.ident, e.global));
						return;
					} catch (MalformedURLException e) {
						failedMessage = new ProtocolErrorMessage(ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, true, e.getMessage(), id, message.global);
					} catch (IOException e) {
					    failedMessage = new ProtocolErrorMessage(ProtocolErrorMessage.IO_ERROR, true, e.getMessage(), id, message.global);
                    }
				} else if(message.persistence == Persistence.FOREVER) {
				    try {
				        server.core.clientContext.jobRunner.queue(new PersistentJob() {
				            
				            @Override
				            public boolean run(ClientContext context) {
				                ClientPut putter;
				                try {
				                    putter = new ClientPut(FCPConnectionHandler.this, message, server);
				                } catch (IdentifierCollisionException e) {
				                    Logger.normal(this, "Identifier collision on "+this);
				                    FCPMessage msg = new IdentifierCollisionMessage(id, message.global);
				                    outputHandler.queue(msg);
				                    return false;
				                } catch (MessageInvalidException e) {
				                    outputHandler.queue(new ProtocolErrorMessage(e.protocolCode, false, e.getMessage(), e.ident, e.global));
				                    return false;
				                } catch (MalformedURLException e) {
				                    outputHandler.queue(new ProtocolErrorMessage(ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, true, null, id, message.global));
				                    return false;
				                } catch (IOException e) {
                                    outputHandler.queue(new ProtocolErrorMessage(ProtocolErrorMessage.IO_ERROR, true, null, id, message.global));
                                    return false;
                                }
				                try {
				                    putter.register(false);
				                } catch (IdentifierCollisionException e) {
				                    Logger.normal(this, "Identifier collision on "+this);
				                    FCPMessage msg = new IdentifierCollisionMessage(id, global);
				                    outputHandler.queue(msg);
				                    return false;
				                }
				                putter.start(context);
				                return true;
				            }
				        
				        }, NativeThread.HIGH_PRIORITY-1);
				    } catch (PersistenceDisabledException e) {
				        outputHandler.queue(new ProtocolErrorMessage(ProtocolErrorMessage.PERSISTENCE_DISABLED, false, "Persistence is disabled", id, global));
				    }
					return; // Don't run the start() below
				} else {
					try {
						cp = new ClientPut(this, message, server);
					} catch (IdentifierCollisionException e) {
						success = false;
					} catch (MessageInvalidException e) {
						outputHandler.queue(new ProtocolErrorMessage(e.protocolCode, false, e.getMessage(), e.ident, e.global));
						return;
					} catch (MalformedURLException e) {
						failedMessage = new ProtocolErrorMessage(ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, true, null, id, message.global);
					} catch (IOException e) {
                        failedMessage = new ProtocolErrorMessage(ProtocolErrorMessage.IO_ERROR, true, null, id, message.global);
                    }
				}
			}
			if(!success) {
				Logger.normal(this, "Identifier collision on "+this);
				failedMessage = new IdentifierCollisionMessage(id, message.global);
			}
		}
		if(message.persistence == Persistence.REBOOT && cp != null)
			try {
				cp.register(false);
			} catch (IdentifierCollisionException e) {
				failedMessage = new IdentifierCollisionMessage(id, message.global);
			}
		if(failedMessage != null) {
			if(logMINOR) Logger.minor(this, "Failed: "+failedMessage);
			outputHandler.queue(failedMessage);
			if(cp != null)
			    cp.freeData();
			else
			    message.freeData();
			return;
		} else {
			Logger.minor(this, "Starting "+cp);
			cp.start(server.core.clientContext);
		}
	}

	public void startClientPutDir(final ClientPutDirMessage message, final HashMap<String, Object> buckets, final boolean wasDiskPut) {
		if(logMINOR)
			Logger.minor(this, "Start ClientPutDir");
		final String id = message.identifier;
		final boolean global = message.global;
		ClientPutDir cp = null;
		FCPMessage failedMessage = null;
		boolean persistent = message.persistence != Persistence.CONNECTION;
		// We need to track non-persistent requests anyway, so we may as well check
		boolean success;
		synchronized(this) {
			if(isClosed) return;
			if(!persistent)
				success = true;
			else
				success = !requestsByIdentifier.containsKey(id);
		}
		if(success) {
			if(!persistent) {
				try {
					cp = new ClientPutDir(this, message, buckets, wasDiskPut, server);
					synchronized(this) {
						requestsByIdentifier.put(id, cp);
					}
				} catch (IdentifierCollisionException e) {
					success = false;
				} catch (MalformedURLException e) {
					failedMessage = new ProtocolErrorMessage(ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, true, null, id, message.global);
				} catch (TooManyFilesInsertException e) {
					failedMessage = new ProtocolErrorMessage(ProtocolErrorMessage.TOO_MANY_FILES_IN_INSERT, true, null, id, message.global);
				}
				// FIXME register non-persistent requests in the constructors also, we already register persistent ones...
			} else if(message.persistence == Persistence.FOREVER) {
			    try {
			        server.core.clientContext.jobRunner.queue(new PersistentJob() {
			            
			            @Override
			            public boolean run(ClientContext context) {
			                ClientPutDir putter;
			                try {
			                    putter = new ClientPutDir(FCPConnectionHandler.this, message, buckets, wasDiskPut, server);
			                } catch (IdentifierCollisionException e) {
			                    Logger.normal(this, "Identifier collision on "+this);
			                    FCPMessage msg = new IdentifierCollisionMessage(id, message.global);
			                    outputHandler.queue(msg);
			                    return false;
			                } catch (MalformedURLException e) {
			                    outputHandler.queue(new ProtocolErrorMessage(ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, true, null, id, message.global));
			                    return false;
			                } catch (TooManyFilesInsertException e) {
			                    outputHandler.queue(new ProtocolErrorMessage(ProtocolErrorMessage.TOO_MANY_FILES_IN_INSERT, true, null, id, message.global));
			                    return false;
			                }
			                try {
			                    putter.register(false);
			                } catch (IdentifierCollisionException e) {
			                    Logger.normal(this, "Identifier collision on "+this);
			                    FCPMessage msg = new IdentifierCollisionMessage(id, global);
			                    outputHandler.queue(msg);
			                    return false;
			                }
			                putter.start(context);
			                return true;
			            }
			            
			        }, NativeThread.HIGH_PRIORITY-1);
			    } catch (PersistenceDisabledException e) {
			        outputHandler.queue(new ProtocolErrorMessage(ProtocolErrorMessage.PERSISTENCE_DISABLED, false, "Persistence is disabled", id, global));
			    }
				return; // Don't run the start() below
				
			} else {
				try {
					cp = new ClientPutDir(this, message, buckets, wasDiskPut, server);
				} catch (IdentifierCollisionException e) {
					success = false;
				} catch (MalformedURLException e) {
					failedMessage = new ProtocolErrorMessage(ProtocolErrorMessage.FREENET_URI_PARSE_ERROR, true, null, id, message.global);
				} catch (TooManyFilesInsertException e) {
					failedMessage = new ProtocolErrorMessage(ProtocolErrorMessage.TOO_MANY_FILES_IN_INSERT, true, null, id, message.global);
				}
			}
			if(!success) {
				Logger.normal(this, "Identifier collision on "+this);
				failedMessage = new IdentifierCollisionMessage(id, message.global);
			}
		}
		
		if(message.persistence == Persistence.REBOOT)
			try {
				cp.register(false);
			} catch (IdentifierCollisionException e) {
				failedMessage = new IdentifierCollisionMessage(id, message.global);
			}
		if(failedMessage != null) {
			// FIXME do we need to freeData???
			outputHandler.queue(failedMessage);
			if(cp != null)
				cp.cancel(server.core.clientContext);
			return;
		} else {
			if(logMINOR)
				Logger.minor(this, "Starting "+cp);
			cp.start(server.core.clientContext);
		}
	}
	
	public PersistentRequestClient getRebootClient() {
		return rebootClient;
	}

    /**
     * @return
     *     The {@link FCPPluginConnection} for the given serverPluginName (see
     *     {@link PluginManager#getPluginFCPServer(String)}). Atomically creates and stores it if
     *     there does not exist one yet. This ensures that for each FCPConnectionHandler, there can
     *     be only one {@link FCPPluginConnection} for a given serverPluginName.
     * @throws PluginNotFoundException
     *     If the specified plugin is not loaded or does not provide an FCP server.
     */
    FCPPluginConnection getFCPPluginConnection(String serverPluginName)
            throws PluginNotFoundException {

        // The suspected typical usage pattern of this function is that the great majority of calls
        // will return an existing FCPPluginConnection. Creating a fresh one will typically only
        // happen at the start of a connection and then it will be re-used a lot.
        // Therefore, it would cost a lot of performance to use synchronized() and we instead use a
        // ReadWriteLock which is optimal for such patterns.
        //
        // The double-checked locking pattern which this induces is necessary due to the fact that a
        // read-lock cannot be upgraded to a write lock.
        // The JavaDoc of ReentrantReadWriteLock specifically recommends this pattern, so it ought
        // to be a safe version of double-checked locking.
        
        pluginConnectionsByServerName_Lock.readLock().lock();
        try {
            // We use the actual *Impl instead of the interface because the implementation provides
            // isServerDead(), which the interface does not.
            FCPPluginConnectionImpl peekOldConnection
                = pluginConnectionsByServerName.get(serverPluginName);
            
            if(peekOldConnection != null && !peekOldConnection.isServerDead()) {
                return peekOldConnection;
            }
        } finally {
            // A read-lock cannot be upgraded to a write-lock so we must always unlock
            pluginConnectionsByServerName_Lock.readLock().unlock();
        }

        pluginConnectionsByServerName_Lock.writeLock().lock();
        try {
            // Re-check whether there is an existing connection since we had to re-acquire the lock
            // meanwhile.
            FCPPluginConnectionImpl oldConnection
                = pluginConnectionsByServerName.get(serverPluginName);
            
            if(oldConnection != null) {
                if(!oldConnection.isServerDead()) {
                    return oldConnection;
                } else {
                    // oldConnection.isDead() returned true because the WeakReference to the server
                    // has been nulled because the plugin was unloaded or reloaded.
                    // The connection should be discarded then. We have no ReferenceQueue to discard
                    // affected connections from the pluginConnectionsByServerName table, so we
                    // opportunistically clean nulled connections from it here.
                    // The reason why this is sufficient memory management is explained at
                    // FCPPluginConnectionImpl.server
                    // NOTICE: Even if there was automatic disposal of nulled references, we still
                    // would have to manually remove dead ones here: I have observed that it can
                    // take minutes until the JVM flushes a ReferenceQueue. So if we relied upon
                    // that only, during those minutes a client would be unable to send messages to
                    // a re-loaded server plugin because the continued existence of the dead old
                    // connection would prevent a new one from being created.
                    pluginConnectionsByServerName.remove(serverPluginName);
                }
            }

            FCPPluginConnectionImpl newConnection
                = server.createFCPPluginConnectionForNetworkedFCP(serverPluginName, this);
            
            pluginConnectionsByServerName.put(serverPluginName, newConnection);
            
            return newConnection;
        } finally {
            pluginConnectionsByServerName_Lock.writeLock().unlock();
        }
	}

	public PersistentRequestClient getForeverClient() {
		synchronized(this) {
			if(foreverClient == null) {
				foreverClient = createForeverClient(clientName);
			}
			return foreverClient;
		}
	}

	public void finishedClientRequest(ClientRequest get) {
		synchronized(this) {
			requestsByIdentifier.remove(get.getIdentifier());
		}
	}

	public boolean isGlobalSubscribed() {
		return rebootClient.watchGlobal;
	}

	public boolean hasFullAccess() {
		return server.allowedHostsFullAccess.allowed(sock.getInetAddress());
	}

	/**
	 * That method ought to be called before any DirectDiskAccess operation is performed by the node
	 * @param filename
	 * @param writeRequest : Are willing to write or to read ?
	 * @return boolean : allowed or not
	 */
	protected boolean allowDDAFrom(File filename, boolean writeRequest) {
		String parentDirectory = FileUtil.getCanonicalFile(filename).getParent();
		DirectoryAccess da = null;
		
		synchronized (checkedDirectories) {
				da = checkedDirectories.get(parentDirectory);
		}
		
		if(logMINOR)
			Logger.minor(this, "Checking DDA: "+da+" for "+parentDirectory);
		
		if(writeRequest)
			return (da == null ? server.isDownloadDDAAlwaysAllowed() : da.canWrite);
		else
			return (da == null ? server.isUploadDDAAlwaysAllowed() : da.canRead);
	}
	
	/**
	 * SHOULD BE CALLED ONLY FROM TestDDAComplete!
	 * @param path
	 * @param read
	 * @param write
	 */
	protected void registerTestDDAResult(String path, boolean read, boolean write) {
		DirectoryAccess da = new DirectoryAccess(read, write);
		
		synchronized (checkedDirectories) {
				checkedDirectories.put(path, da);
		}
		
		if(logMINOR)
			Logger.minor(this, "DDA: read="+read+" write="+write+" for "+path);
	}
	
	/**
	 * Return a DDACheckJob : the one we created and have enqueued
	 * @param path
	 * @param read : is Read access requested ?
	 * @param write : is Write access requested ?
	 * @return
	 * @throws IllegalArgumentException
	 * 
	 * FIXME: Maybe we need to enqueue a PS job to delete the created file after something like ... 5 mins ?
	 */
	protected DDACheckJob enqueueDDACheck(String path, boolean read, boolean write) throws IllegalArgumentException {
		File directory = FileUtil.getCanonicalFile(new File(path));
		if(!directory.exists() || !directory.isDirectory())
			throw new IllegalArgumentException("The specified path isn't a directory! or doesn't exist or the node doesn't have access to it!");
		
		// See #1856
		DDACheckJob job = null;
		synchronized (inTestDirectories) {
			job = inTestDirectories.get(directory);
		}
		if(job != null)
			throw new IllegalArgumentException("There is already a TestDDA going on for that directory!");
		
		File writeFile = (write ? new File(path, "DDACheck-" + server.node.fastWeakRandom.nextInt() + ".tmp") : null);
		File readFile = null;
		if(read) {
			try {
				readFile = File.createTempFile("DDACheck-", ".tmp", directory);
				readFile.deleteOnExit();
			} catch (IOException e) {
				// Now we know it: we can't write there ;)
				readFile = null;
			}
		}

		DDACheckJob result = new DDACheckJob(server.node.fastWeakRandom, directory, readFile, writeFile);
		synchronized (inTestDirectories) {
			inTestDirectories.put(directory, result);
		}
		
		if(read && (readFile != null) && readFile.canWrite()){
			// We don't want to attempt to write before: in case an IOException is raised, we want to inform the
			// client somehow that the node can't write there... And setting readFile to null means we won't inform
			// it on the status (as if it hadn't requested us to do the test).
			FileOutputStream fos = null;
			BufferedOutputStream bos = null;
			try {
				fos = new FileOutputStream(result.readFilename);
				bos = new BufferedOutputStream(fos);
				bos.write(result.readContent.getBytes("UTF-8"));
				bos.flush();
			} catch (IOException e) {
				Logger.error(this, "Got a IOE while creating the file (" + readFile.toString() + " ! " + e.getMessage());
			} finally {
				Closer.close(bos);
				Closer.close(fos);
			}
		}
		
		return result;
	}
	
	/**
	 * Return a DDACheckJob or null if not found
	 * @param path
	 * @return the DDACheckJob
	 * @throws IllegalArgumentException
	 */
	protected DDACheckJob popDDACheck(String path) throws IllegalArgumentException {
		File directory = FileUtil.getCanonicalFile(new File(path));
		if(!directory.exists() || !directory.isDirectory())
			throw new IllegalArgumentException("The specified path isn't a directory! or doesn't exist or the node doesn't have access to it!");
		
		synchronized (inTestDirectories) {
			return inTestDirectories.remove(directory);
		}
	}
	
	/**
	 * Delete the files we have created using DDATest
	 * called by PersistentRequestClient.onDisconnect(handler)
	 */
	protected void freeDDAJobs(){
		synchronized (inTestDirectories) {
			for(DDACheckJob job: inTestDirectories.values()) {
				if (job.readFilename != null)
					job.readFilename.delete();
			}
		}
	}

	public ClientRequest removeRequestByIdentifier(String identifier, boolean kill) {
		ClientRequest req;
		synchronized(this) {
			req = requestsByIdentifier.remove(identifier);
		}
		if(req != null) {
			if(kill)
				req.cancel(server.core.clientContext);
			req.requestWasRemoved(server.core.clientContext);
		}
		return req;
	}
	
	ClientRequest getRebootRequest(boolean global, FCPConnectionHandler handler, String identifier) {
		if(global)
			return handler.server.globalRebootClient.getRequest(identifier);
		else
			return handler.getRebootClient().getRequest(identifier);
	}
	
	ClientRequest getForeverRequest(boolean global, FCPConnectionHandler handler, String identifier) {
		if(global)
			return handler.server.globalForeverClient.getRequest(identifier);
		else
			return handler.getForeverClient().getRequest(identifier);
	}
	
	ClientRequest removePersistentRebootRequest(boolean global, String identifier) throws MessageInvalidException {
		PersistentRequestClient client =
			global ? server.globalRebootClient :
			getRebootClient();
		ClientRequest req = client.getRequest(identifier);
		if(req != null) {
			client.removeByIdentifier(identifier, true, server.core.clientContext);
		}
		return req;
	}
	
	ClientRequest removePersistentForeverRequest(boolean global, String identifier) throws MessageInvalidException {
		PersistentRequestClient client =
			global ? server.globalForeverClient :
			getForeverClient();
		ClientRequest req = client.getRequest(identifier);
		if(req != null) {
			client.removeByIdentifier(identifier, true, server.core.clientContext);
		}
		return req;
	}
	
	public synchronized void addUSKSubscription(String identifier, SubscribeUSK subscribeUSK) throws IdentifierCollisionException {
		if(uskSubscriptions.containsKey(identifier)) throw new IdentifierCollisionException();
		uskSubscriptions.put(identifier, subscribeUSK);
	}

	public void unsubscribeUSK(String identifier) throws MessageInvalidException {
		SubscribeUSK sub;
		synchronized(this) {
			sub = uskSubscriptions.remove(identifier);
			if(sub == null) throw new MessageInvalidException(ProtocolErrorMessage.NO_SUCH_IDENTIFIER, "No such identifier unsubscribing", identifier, false);
		}
		sub.unsubscribe();
	}

	public RequestClient connectionRequestClient(boolean realTime) {
		if(realTime)
			return connectionRequestClientRT;
		else
			return connectionRequestClientBulk;
	}

}
