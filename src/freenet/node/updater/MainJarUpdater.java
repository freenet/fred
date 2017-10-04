package freenet.node.updater;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Properties;

import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.FetchResult;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientGetCallback;
import freenet.client.async.ClientGetter;
import freenet.client.events.ClientEvent;
import freenet.client.events.ClientEventListener;
import freenet.client.events.SplitfileProgressEvent;
import freenet.clients.fcp.FCPMessage;
import freenet.clients.fcp.ClientPut.COMPRESS_STATE;
import freenet.clients.http.QueueToadlet;
import freenet.keys.FreenetURI;
import freenet.l10n.NodeL10n;
import freenet.node.RequestClient;
import freenet.node.RequestStarter;
import freenet.node.Version;
import freenet.node.updater.MainJarDependenciesChecker.AtomicDeployer;
import freenet.node.updater.MainJarDependenciesChecker.Deployer;
import freenet.node.updater.MainJarDependenciesChecker.JarFetcher;
import freenet.node.updater.MainJarDependenciesChecker.JarFetcherCallback;
import freenet.node.updater.MainJarDependenciesChecker.MainJarDependencies;
import freenet.node.updater.UpdateOverMandatoryManager.UOMDependencyFetcher;
import freenet.node.updater.UpdateOverMandatoryManager.UOMDependencyFetcherCallback;
import freenet.node.useralerts.UserAlert;
import freenet.support.HTMLNode;
import freenet.support.Logger;
import freenet.support.io.Closer;
import freenet.support.io.FileBucket;
import freenet.support.io.FileUtil;
import freenet.support.io.InsufficientDiskSpaceException;

public class MainJarUpdater extends NodeUpdater implements Deployer {
	
	static private volatile boolean logMINOR;
	static {
		Logger.registerClass(MainJarUpdater.class);
	}
	
	private final FetchContext dependencyCtx;
	private final ClientContext clientContext;

	MainJarUpdater(NodeUpdateManager manager, FreenetURI URI, int current, int min, int max, String blobFilenamePrefix) {
		super(manager, URI, current, min, max, blobFilenamePrefix);
		dependencyCtx = core.makeClient((short) 0, false).getFetchContext();
		dependencyCtx.allowSplitfiles = true;
		dependencyCtx.dontEnterImplicitArchives = false;
		dependencyCtx.maxNonSplitfileRetries = -1;
		dependencyCtx.maxSplitfileBlockRetries = -1;
		clientContext = core.clientContext;
		dependencies = new MainJarDependenciesChecker(this, manager.node.executor);
	}

	private final MainJarDependenciesChecker dependencies;
	
	@Override
	public String jarName() {
		return "freenet.jar";
	}
	
	public void start() {
		maybeProcessOldBlob();
		super.start();
	}
	
	@Override
	protected void maybeParseManifest(FetchResult result) {
		// Do nothing.
	}

	@Override
	protected void processSuccess(int fetched, FetchResult result, File blob) {
		manager.onDownloadedNewJar(result.asBucket(), fetched, blob);
		// NodeUpdateManager expects us to dependencies *AFTER* we tell it about the new jar.
		parseDependencies(result, fetched);
	}

	@Override
	protected void onStartFetching() {
		manager.onStartFetching();
	}
	
	// Dependency handling.
	
	private HashSet<DependencyJarFetcher> fetchers = new HashSet<DependencyJarFetcher>();
	private HashSet<DependencyJarFetcher> essentialFetchers = new HashSet<DependencyJarFetcher>();

	protected void parseDependencies(Properties props, int build) {
		synchronized(fetchers) {
			fetchers.clear();
		}
		MainJarDependencies deps = dependencies.handle(props, build);
		if(deps != null) {
			manager.onDependenciesReady(deps);
		}
	}

	@Override
	public void deploy(MainJarDependencies deps) {
		manager.onDependenciesReady(deps);
	}
	
	/** Glue code. */
	private class DependencyJarFetcher implements JarFetcher, ClientGetCallback, RequestClient, ClientEventListener {

		private final File filename;
		private final ClientGetter getter;
		private SplitfileProgressEvent lastProgress;
		private final JarFetcherCallback cb;
		private boolean fetched;
		private final byte[] expectedHash;
		private final long expectedLength;
		private final boolean essential;
		private final File tempFile;
		private UOMDependencyFetcher uomFetcher;
		private final boolean executable;
		
		DependencyJarFetcher(File filename, FreenetURI chk, long expectedLength, byte[] expectedHash, JarFetcherCallback cb, boolean essential, boolean executable) throws FetchException {
			FetchContext myCtx = new FetchContext(dependencyCtx, FetchContext.IDENTICAL_MASK);
			File parent = filename.getParentFile();
			if(parent == null) parent = new File(".");
			try {
				tempFile = File.createTempFile(filename.getName(), NodeUpdateManager.TEMP_FILE_SUFFIX, parent);
			} catch (InsufficientDiskSpaceException e) {
			    throw new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE);
			} catch (IOException e) {
				throw new FetchException(FetchExceptionMode.BUCKET_ERROR, "Cannot create temp file for "+filename+" in "+parent+" - disk full? permissions problem?");
			}
			getter = new ClientGetter(this,  
					chk, myCtx, RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
					new FileBucket(tempFile, false, false, false, false), null, null);
			myCtx.eventProducer.addEventListener(this);
			this.cb = cb;
			this.filename = filename;
			this.expectedHash = expectedHash;
			this.expectedLength = expectedLength;
			this.essential = essential;
			this.executable = executable;
		}
		
		@Override
		public void cancel() {
			final UOMDependencyFetcher f;
			synchronized(this) {
				fetched = true;
				f = uomFetcher;
			}
			MainJarUpdater.this.node.executor.execute(new Runnable() {

				@Override
				public void run() {
					getter.cancel(clientContext);
					if(f != null) f.cancel();
				}
				
			});
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
		public void onSuccess(FetchResult result, ClientGetter state) {
			synchronized(this) {
				if(fetched) {
					tempFile.delete();
					return;
				}
				fetched = true;
			}
            if(!MainJarDependenciesChecker.validFile(tempFile, expectedHash, expectedLength, executable)) {
                Logger.error(this, "Unable to download dependency "+filename+" : not the expected size or hash!");
                System.err.println("Download of "+filename+" for update failed because temp file appears to be corrupted!");
                if(cb != null)
                    cb.onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, "Downloaded jar from Freenet but failed consistency check: "+tempFile+" length "+tempFile.length()+" "));
                tempFile.delete();
                return;
            }
			if(!FileUtil.renameTo(tempFile, filename)) {
				Logger.error(this, "Unable to rename temp file "+tempFile+" to "+filename);
				System.err.println("Download of "+filename+" for update failed because cannot rename from "+tempFile);
				if(cb != null)
				    cb.onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, "Unable to rename temp file "+tempFile+" to "+filename));
                tempFile.delete();
				return;
			}
			if(cb != null) cb.onSuccess();
		}
		
		@Override
		public void onFailure(FetchException e, ClientGetter state) {
			tempFile.delete();
			synchronized(this) {
				if(fetched) return;
			}
			if(cb != null) cb.onFailure(e);
		}
		
		@Override
		public synchronized void receive(ClientEvent ce, ClientContext context) {
			if(ce instanceof SplitfileProgressEvent)
				lastProgress = (SplitfileProgressEvent) ce;
		}
		
		private void start() throws FetchException {
			getter.start(clientContext);
		}

		public synchronized HTMLNode renderRow() {
			HTMLNode row = new HTMLNode("tr");
			row.addChild("td").addChild("p", filename.toString());
			
			if(uomFetcher != null)
				row.addChild("td").addChild("#", l10n("fetchingFromUOM"));
			else if(lastProgress == null)
				row.addChild(QueueToadlet.createProgressCell(false, true, COMPRESS_STATE.WORKING, 0, 0, 0, 0, 0, false, false));
			else
				row.addChild(QueueToadlet.createProgressCell(false, 
						true, COMPRESS_STATE.WORKING, lastProgress.succeedBlocks, lastProgress.failedBlocks, lastProgress.fatallyFailedBlocks, lastProgress.minSuccessfulBlocks, lastProgress.totalBlocks, lastProgress.finalizedTotal, false));
			return row;
		}

		public void fetchFromUOM() {
			synchronized(this) {
				if(fetched) return;
				if(!essential) return;
			}
			UOMDependencyFetcher f = manager.uom.fetchDependency(expectedHash, expectedLength, filename, executable,
					new UOMDependencyFetcherCallback() {

						@Override
						public void onSuccess() {
							synchronized(DependencyJarFetcher.this) {
								if(fetched) return;
								fetched = true;
							}
							if(cb != null) cb.onSuccess();
						}
						
			});
			synchronized(this) {
				if(uomFetcher != null) {
					Logger.error(this, "Started UOMFetcher twice for "+filename, new Exception("error"));
					return;
				}
				uomFetcher = f;
			}
		}

	    @Override
	    public void onResume(ClientContext context) {
	        // Do nothing. Not persistent.
	    }

        @Override
        public RequestClient getRequestClient() {
            return this;
        }

	}
	
	@Override
	public JarFetcher fetch(FreenetURI uri, File downloadTo,
			long expectedLength, byte[] expectedHash, JarFetcherCallback cb, int build, boolean essential, boolean executable) throws FetchException {
		if(essential)
			System.out.println("Fetching "+downloadTo+" needed for new Freenet update "+build);
		else if(build != 0) // build 0 means it's a preload or a multi-file update.
			System.out.println("Preloading "+downloadTo+" needed for new Freenet update "+build);
		if(logMINOR) Logger.minor(this, "Fetching "+uri+" to "+downloadTo+" for next update");
		DependencyJarFetcher fetcher = new DependencyJarFetcher(downloadTo, uri, expectedLength, expectedHash, cb, essential, executable);
		synchronized(fetchers) {
			fetchers.add(fetcher);
			if(essential)
				essentialFetchers.add(fetcher);
		}
		fetcher.start();
		if(manager.uom.fetchingUOM()) {
			if(essential)
				fetcher.fetchFromUOM();
		}
		return fetcher;
	}
	
	public void onStartFetchingUOM() {
		DependencyJarFetcher[] f;
		synchronized(fetchers) {
			f = fetchers.toArray(new DependencyJarFetcher[fetchers.size()]);
		}
		for(DependencyJarFetcher fetcher : f)
			fetcher.fetchFromUOM();
	}
	
	public void renderProperties(HTMLNode alertNode) {
		synchronized(fetchers) {
			if(!fetchers.isEmpty()) {
				alertNode.addChild("p", l10n("fetchingDependencies")+":");
				HTMLNode table = alertNode.addChild("table");
				for(DependencyJarFetcher f : fetchers) {
					table.addChild(f.renderRow());
				}
			}
		}
	}

	private String l10n(String key) {
		return NodeL10n.getBase().getString("MainJarUpdater."+key);
	}

	public boolean brokenDependencies() {
		return dependencies.isBroken();
	}

	public void cleanupDependencies() {
		InputStream is = getClass().getResourceAsStream("/"+DEPENDENCIES_FILE);
		if(is == null) {
			System.err.println("Can't find dependencies file. Other nodes will not be able to use Update Over Mandatory through this one.");
			return;
		}
		Properties props = new Properties();
		try {
			props.load(is);
		} catch (IOException e) {
			System.err.println("Can't read dependencies file. Other nodes will not be able to use Update Over Mandatory through this one.");
			return;
		} finally {
			Closer.close(is);
		}
		dependencies.cleanup(props, this, Version.buildNumber());
	}

	@Override
	public void addDependency(byte[] expectedHash, File filename) {
		manager.uom.addDependency(expectedHash, filename);
	}

    @Override
    public void reannounce() {
        this.manager.broadcastUOMAnnouncesNew();
        this.manager.broadcastUOMAnnouncesOld();
    }

    @Override
    public void multiFileReplaceReadyToDeploy(final MainJarDependenciesChecker.AtomicDeployer atomicDeployer) {
        if(this.manager.isAutoUpdateAllowed()) {
            atomicDeployer.deployMultiFileUpdateOffThread();
        } else {
            final long now = System.currentTimeMillis();
            System.err.println("Not deploying multi-file update for "+atomicDeployer.name+" because auto-update is not enabled.");
            node.clientCore.alerts.register(new UserAlert() {

                private String l10n(String key) {
                    return NodeL10n.getBase().getString("MainJarUpdater.ConfirmMultiFileUpdater."+key);
                }
                
                @Override
                public boolean userCanDismiss() {
                    return true;
                }

                @Override
                public String getTitle() {
                    return l10n("title."+atomicDeployer.name);
                }

                @Override
                public String getText() {
                    return l10n("text."+atomicDeployer.name);
                }

                @Override
                public HTMLNode getHTMLText() {
                    return new HTMLNode("p", getText());
                    // FIXME separate button, then the alert could be dismissable? Only useful if it's permanently dismissable though, which means a config setting as well...
                }

                @Override
                public String getShortText() {
                    return getTitle();
                }

                @Override
                public short getPriorityClass() {
                    return UserAlert.ERROR;
                }

                @Override
                public boolean isValid() {
                    return true;
                }

                @Override
                public void isValid(boolean validity) {
                    // Ignore
                }

                @Override
                public String dismissButtonText() {
                    return NodeL10n.getBase().getDefaultString("UpdatedVersionAvailableUserAlert.updateNowButton");
                }

                @Override
                public boolean shouldUnregisterOnDismiss() {
                    return true;
                }

                @Override
                public void onDismiss() {
                    atomicDeployer.deployMultiFileUpdateOffThread();
                }

                @Override
                public String anchor() {
                    return "multi-file-update-confirm-"+atomicDeployer.name;
                }

                @Override
                public boolean isEventNotification() {
                    return false;
                }

                @Override
                public FCPMessage getFCPMessage() {
                    return null;
                }

                @Override
                public long getUpdatedTime() {
                    return now;
                }
                
            });
        }
    }

}
