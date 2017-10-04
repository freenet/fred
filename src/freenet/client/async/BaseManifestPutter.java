/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.async;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Stack;

import freenet.client.ClientMetadata;
import freenet.client.DefaultMIMETypes;
import freenet.client.InsertBlock;
import freenet.client.InsertContext;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.Metadata;
import freenet.client.MetadataUnresolvedException;
import freenet.client.ArchiveManager.ARCHIVE_TYPE;
import freenet.client.Metadata.DocumentType;
import freenet.client.Metadata.SimpleManifestComposer;
import freenet.client.events.SplitfileProgressEvent;
import freenet.keys.BaseClientKey;
import freenet.keys.FreenetURI;
import freenet.keys.Key;
import freenet.support.Logger;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.api.ManifestElement;
import freenet.support.api.RandomAccessBucket;
import freenet.support.io.BucketTools;
import freenet.support.io.ResumeFailedException;

/**
 * <P>Base class for site insertion.
 * This class contains all the insert logic, but not any 'pack logic'.
 * The pack logic have to be implement in a subclass in makePutHandlers.
 * <P>
 * Internal container redirect URIs:
 *  The internal container URIs should be always redirects to CHKs, not just include the metadata into manifest only.
 *  The (assumed) default behavior is the reuse of containers between editions,
 *  also ArchiveManger want to have a URI given, not Metadata.
 *  This rule also makes site update code/logic much more easier.
 * <P>
 * <DL>
 * <DT>container mode: <DD>the metadata are inside the root container (the final URI points to an archive)
 * <DT>freeform mode: <DD>the metadata are inserted separately.(the final URI points to a SimpleManifest)
 * </DL>
 * 
 * WARNING: Changing non-transient members on classes that are Serializable can result in 
 * restarting downloads or losing uploads.
 * </P>
 * @see freenet.client.async.PlainManifestPutter PlainManifestPutter, freenet.client.async.DefaultManifestPutter DefaultManifestPutter
 * 
 */
public abstract class BaseManifestPutter extends ManifestPutter {

    private static final long serialVersionUID = 1L;
    private static volatile boolean logMINOR;
	private static volatile boolean logDEBUG;

	static {
		Logger.registerClass(BaseManifestPutter.class);
	}
	
	/**
	 * ArchivePutHandler - wrapper for ContainerInserter
	 *
	 * Archives are not part of the site structure, they are used to group files that
	 * not fit into a container (for example a directory with brazilion files it)
	 * Archives are always inserted as CHK, references to items in it
	 * are normal redirects to CHK@blah,blub,AA/nameinarchive
	 *
	 */
	private final class ArchivePutHandler extends PutHandler {

        private static final long serialVersionUID = 1L;

        private ArchivePutHandler(BaseManifestPutter bmp, PutHandler parent, String name, HashMap<String, Object> data, FreenetURI insertURI) {
			super(bmp, parent, name, null, containerPutHandlers);
			this.origSFI = new ContainerInserter(this, this, data, insertURI, ctx, false, false, null, ARCHIVE_TYPE.TAR, forceCryptoKey, cryptoAlgorithm, realTimeFlag);
		}

		@Override
		public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
			if (logMINOR) Logger.minor(this, "onEncode(" + key.getURI().toString(false, false) + ") for " + this);

			synchronized (BaseManifestPutter.this) {
				// transform the placeholders to redirects (redirects to 'uri/name') and
				// remove from waitfor lists
				ArrayList<PutHandler> phv = putHandlersArchiveTransformMap.get(this);
				if(phv == null) return; // Already encoded.
				for (PutHandler ph : phv) {
					HashMap<String, Object> hm = putHandlersTransformMap.get(ph);
					perContainerPutHandlersWaitingForMetadata.get(ph.parentPutHandler).remove(ph);
					if (ph.targetInArchive == null)
						throw new NullPointerException();
					Metadata m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, key.getURI().setMetaString(new String[] { ph.targetInArchive }), cm);
					hm.put(ph.itemName, m);
					putHandlersTransformMap.remove(ph);
					try {
						tryStartParentContainer(ph.parentPutHandler, context);
					} catch (InsertException e) {
						fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null), context);
						return;
					}
				}
				putHandlersArchiveTransformMap.remove(this);
			}
		}

		@Override
		public void onSuccess(ClientPutState state, ClientContext context) {
			if (logMINOR) Logger.minor(this, "Completed '" + this.itemName + "' " + this);
			if (!containerPutHandlers.remove(this)) throw new IllegalStateException("was not in containerPutHandlers");
			
			super.onSuccess(state, context);
		}

	}

	/**
	 * ContainerPutHandler - wrapper for ContainerInserter
	 *
	 * Containers are an integral part of the site structure, they are
	 * inserted as CHK, the root container is inserted at targetURI.
	 * references to items in it are ARCHIVE_INTERNAL_REDIRECT
	 *
	 */
	private final class ContainerPutHandler extends PutHandler {

        private static final long serialVersionUID = 1L;

        private ContainerPutHandler(BaseManifestPutter bmp, PutHandler parent, String name, HashMap<String, Object> data, FreenetURI insertURI, HashSet<PutHandler> runningMap) {
			super(bmp, parent, name, null, runningMap);
			this.origSFI = new ContainerInserter(this, this, data, insertURI, ctx, false, false, null, ARCHIVE_TYPE.TAR, forceCryptoKey, cryptoAlgorithm, realTimeFlag);
		}

		@Override
		public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
			if (logMINOR) Logger.minor(this, "onEncode(" + key.getURI().toString(false, false) + ") for " + this);

			if (rootContainerPutHandler == this) {
				finalURI = key.getURI();
				cb.onGeneratedURI(finalURI, this);
			} else {
				synchronized (BaseManifestPutter.this) {
					HashMap<String, Object> hm = putHandlersTransformMap.get(this);
					perContainerPutHandlersWaitingForMetadata.get(parentPutHandler).remove(this);
					Metadata m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, key.getURI(), cm);
					hm.put(this.itemName, m);
					putHandlersTransformMap.remove(this);

					try {
						tryStartParentContainer(parentPutHandler, context);
					} catch (InsertException e) {
						fail(e, context);
						return;
					}
				}
			}
		}

		@Override
		public void onSuccess(ClientPutState state, ClientContext context) {
			if (logMINOR) Logger.minor(this, "Completed '" + this.itemName + "' " + this);

			if (rootContainerPutHandler == this) {
				if (containerPutHandlers.contains(this)) throw new IllegalStateException("was in containerPutHandlers");
				rootContainerPutHandler = null;
			} else {
				if (!containerPutHandlers.remove(this)) throw new IllegalStateException("was not in containerPutHandlers");
			}
			super.onSuccess(state, context);
		}
	}

	private final class ExternPutHandler extends PutHandler {

        private static final long serialVersionUID = 1L;

        private ExternPutHandler(BaseManifestPutter bmp, PutHandler parent, String name, RandomAccessBucket data, ClientMetadata cm2) {
			super(bmp, parent, name, cm2, runningPutHandlers);
			InsertBlock block = new InsertBlock(data, cm, FreenetURI.EMPTY_CHK_URI);
			this.origSFI = new SingleFileInserter(this, this, block, false, ctx, realTimeFlag, true, null, null, false, null, false, persistent(), 0, 0, null, cryptoAlgorithm, forceCryptoKey, -1);
		}

		@Override
		public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
			if (logMINOR) Logger.minor(this, "onEncode(" + key + ") for " + this);

			//debugDecompose("ExternPutHandler.onEncode Begin");
			if(metadata != null) {
				Logger.error(this, "Reassigning metadata: "+metadata, new Exception("debug"));
				//throw new IllegalStateException("Metadata set but we got a uri?!");
			}
			// The file was too small to have its own metadata, we get this instead.
			// So we make the key into metadata.
			Metadata m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, key.getURI(), cm);
			onMetadata(m, state, context);
			//debugDecompose("ExternPutHandler.onEncode End");
		}

		@Override
		public void onMetadata(Metadata m, ClientPutState state, ClientContext context) {
			//new Error("DEBUGME").printStackTrace();
			//debugDecompose("ExternPutHandler.onMetadata Begin");
			if(logMINOR) Logger.minor(this, "Assigning metadata: "+m+" for '"+this.itemName+"' "+this+" from "+state+" persistent="+persistent);
			if(metadata != null) {
				Logger.error(this, "Reassigning metadata", new Exception("debug"));
				return;
			}
			metadata = m;

			if (freeformMode) {
				boolean allMetadatas = false;

				synchronized(BaseManifestPutter.this) {
					putHandlersWaitingForMetadata.remove(this);
					allMetadatas = putHandlersWaitingForMetadata.isEmpty();
					if(!allMetadatas) {
						if(logMINOR)
							Logger.minor(this, "Still waiting for metadata: "+putHandlersWaitingForMetadata.size());
					}
				}
				if(allMetadatas) {
					// Will resolve etc.
					gotAllMetadata(context);
				} else {
					// Resolve now to speed up the insert.
					try {
					    if(m.writtenLength() > Metadata.MAX_SIZE_IN_MANIFEST)
							throw new MetadataUnresolvedException(new Metadata[] { m }, "Too big");
					} catch (MetadataUnresolvedException e) {
						try {
							resolve(e, context);
						} catch (IOException e1) {
							fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e1, null), context);
							return;
						} catch (InsertException e1) {
							fail(e1, context);
						}
					}
				}
			} else if (containerMode) {
				HashMap<String, Object> hm = putHandlersTransformMap.get(this);
				perContainerPutHandlersWaitingForMetadata.get(parentPutHandler).remove(this);
				hm.put(this.itemName, m);
				putHandlersTransformMap.remove(this);
				try {
					tryStartParentContainer(parentPutHandler, context);
				} catch (InsertException e) {
					fail(e, context);
					return;
				}
			} else {
				throw new RuntimeException("Neiter container nor freeform mode. Hu?");
			}
			//debugDecompose("ExternPutHandler.onMetadata End");
		}

		@Override
		public void onSuccess(ClientPutState state, ClientContext context) {
			super.onSuccess(state, context);
		}
	}

	// meta data inserter / resolver
	// these MPH are usually created on demand, so they are outside (main)constructor
	private final class MetaPutHandler extends PutHandler {

		// Metadata is not put with a cryptokey. It is derived from other stuff that is already encrypted with random keys.
		
        private static final long serialVersionUID = 1L;

        // final metadata
		private MetaPutHandler(BaseManifestPutter smp, PutHandler parent, InsertBlock insertBlock) {
			super(smp, parent, null, null, null);
			// Treat as splitfile for purposes of determining number of reinserts.
			this.origSFI = new SingleFileInserter(this, this, insertBlock, true, ctx, realTimeFlag, false, null, null, true, null, true, persistent(), 0, 0, null, cryptoAlgorithm, null, -1);
			if(logMINOR) Logger.minor(this, "Inserting root metadata: "+origSFI);
		}

		// resolver
		private MetaPutHandler(BaseManifestPutter smp, PutHandler parent, Metadata toResolve, BucketFactory bf) throws MetadataUnresolvedException, IOException {
			super(smp, parent, null, null, runningPutHandlers);
			RandomAccessBucket b = toResolve.toBucket(bf);
			metadata = toResolve;
			// Treat as splitfile for purposes of determining number of reinserts.
			InsertBlock ib = new InsertBlock(b, null, FreenetURI.EMPTY_CHK_URI);
			this.origSFI = new SingleFileInserter(this, this, ib, true, ctx, realTimeFlag, false, toResolve, null, true, null, true, persistent(), 0, 0, null, cryptoAlgorithm, null, -1);
			if(logMINOR) Logger.minor(this, "Inserting subsidiary metadata: "+origSFI+" for "+toResolve);
		}

		@Override
		public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
			if (logMINOR) Logger.minor(this, "onEncode(" + key.getURI().toString(false, false) + ") for " + this);

			if (rootMetaPutHandler == this) {
				finalURI = key.getURI();
				cb.onGeneratedURI(finalURI, this);
				return;
			}

			metadata.resolve(key.getURI());
		}

		@Override
		public void onSuccess(ClientPutState state, ClientContext context) {
			boolean wasRoot = false;
			synchronized (BaseManifestPutter.this) {
				if (rootMetaPutHandler == this) {
					//if (containerPutHandlers.contains(this)) throw new IllegalStateException("was in containerPutHandlers");
					rootMetaPutHandler = null;
					wasRoot = true;
				}
			}
			if (!wasRoot)
				resolveAndStartBase(context);
			super.onSuccess(state, context);

		}
	}

	/** Placeholder for Matadata, don't run it! */
	private final class JokerPutHandler extends PutHandler {

        private static final long serialVersionUID = 1L;

        /** a normal ( freeform) redirect */
		public JokerPutHandler(BaseManifestPutter bmp, 	String name, FreenetURI targetURI2, ClientMetadata cm2) {
			super(bmp, null, name, null, (Metadata)null, cm2);
			Metadata m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, targetURI2, cm2);
			metadata = m;
		}

		/** an archive redirect */
		public JokerPutHandler(BaseManifestPutter bmp, PutHandler parent, String name, ClientMetadata cm2) {
			super(bmp, parent, name, name, (Metadata)null, cm2);
			// we dont know the final uri, so preconstructing the metadata does not help here			Metadata m = new Metadata(Metadata.SIMPLE_REDIRECT, null, null, FreenetURI.EMPTY_CHK_URI, cm2);
		}

		/** a short symlink */
		public JokerPutHandler(BaseManifestPutter bmp, PutHandler parent, String name, String target) {
			super(bmp, parent, name, name, (Metadata)null, null);
			Metadata m = new Metadata(DocumentType.SYMBOLIC_SHORTLINK, null, null, target, null);
			metadata = m;
		}

	}

	// Only implements PutCompletionCallback for the final metadata insert
	abstract class PutHandler extends BaseClientPutter implements PutCompletionCallback {

        private static final long serialVersionUID = 1L;

        // run me
		private PutHandler(final BaseManifestPutter bmp, PutHandler parent, String name, ClientMetadata cm, HashSet<PutHandler> runningMap) {
			super(bmp.priorityClass, bmp.cb);
			this.persistent = bmp.persistent();
			this.cm = cm;
			this.itemName = name;
			metadata = null;
			parentPutHandler = parent;

			if (runningMap != null) {
				synchronized (runningMap) {
					if (runningMap.contains(this)) {
						Logger.error(this, "PutHandler already in 'runningMap': "+runningMap, new Error("error"));
					} else {
						runningMap.add(this);
					}
				}
			}

			synchronized (putHandlerWaitingForBlockSets) {
				if (putHandlerWaitingForBlockSets.contains(this)) {
					Logger.error(this, "PutHandler already in 'waitingForBlockSets'!", new Error("error"));
				} else {
					putHandlerWaitingForBlockSets.add(this);
				}
			}

			synchronized (putHandlersWaitingForFetchable) {
				if (putHandlersWaitingForFetchable.contains(this)) {
					Logger.error(this, "PutHandler already in 'waitingForFetchable'!", new Error("error"));
				} else {
					putHandlersWaitingForFetchable.add(this);
				}
			}
		}

		// place holder, don't run it
		private PutHandler(final BaseManifestPutter bmp, PutHandler parent, String name, String nameInArchive, Metadata md, ClientMetadata cm) {
			super(bmp.priorityClass, bmp.cb);
			this.persistent = bmp.persistent();
			this.cm = cm;
			this.itemName = name;
			this.origSFI = null;
			metadata = md;
			parentPutHandler = parent;
			this.targetInArchive = nameInArchive;
		}

		protected ClientPutState origSFI;
		private ClientPutState currentState;
		protected ClientMetadata cm;
		protected Metadata metadata;
		private String targetInArchive;
		protected final String itemName;
		protected final boolean persistent;
		protected final PutHandler parentPutHandler;

		public void start(ClientContext context) throws InsertException {
			//new Error("trace start "+this).printStackTrace();
			if (logDEBUG)
				Logger.debug(this, "Starting a PutHandler for '"+this.itemName+"' "+ this);

			if (origSFI == null) {
				fail(new IllegalStateException("origSFI is null on start(), impossible"), context);
			}

			if ((!(this instanceof MetaPutHandler)) && (metadata != null)) {
				fail(new IllegalStateException("metdata=" + metadata + " on start(), impossible"), context);
			}

			boolean ok;
			if ((this instanceof ContainerPutHandler) || (this instanceof ArchivePutHandler)) {
				if (this != rootContainerPutHandler) {
					synchronized (containerPutHandlers) {
						ok = containerPutHandlers.contains(this);
					}
					if (!ok) {
						throw new IllegalStateException("Starting a PutHandler thats not in 'containerPutHandlers'! "+this);
					}
				}
			} else {
				if (this != rootMetaPutHandler) {
					synchronized (runningPutHandlers) {
						ok = runningPutHandlers.contains(this);
					}
					if (!ok) {
						throw new IllegalStateException("Starting a PutHandler thats not in 'runningPutHandlers'! "+this);
					}
				}
			}

			synchronized (putHandlerWaitingForBlockSets) {
				ok = putHandlerWaitingForBlockSets.contains(this);
			}
			if (!ok) {
				Logger.error(this, "Starting a PutHandler thats not in 'waitingForBlockSets'! "+this, new Error("error"));
				//throw new IllegalStateException("Starting a PutHandler thats not in 'waitingForBlockSets'! "+this);
			}

			ClientPutState sfi;
			synchronized(this) {
				sfi = origSFI;
				currentState = sfi;
				origSFI = null;
			}
			sfi.schedule(context);
		}

		@Override
		public void cancel(ClientContext context) {
			if(logMINOR) Logger.minor(this, "Cancelling "+this, new Exception("debug"));
			ClientPutState oldState = null;
			synchronized(this) {
				if(cancelled) return;
				super.cancel();
				oldState = currentState;
			}
			if(oldState != null) oldState.cancel(context);
			onFailure(new InsertException(InsertExceptionMode.CANCELLED), oldState, context);
		}

		@Override
		public FreenetURI getURI() {
			return null;
		}

		@Override
		public boolean isFinished() {
			if(logMINOR) Logger.minor(this, "Finished "+this, new Exception("debug"));
			return BaseManifestPutter.this.finished || cancelled || BaseManifestPutter.this.cancelled;
		}

		@Override
		public void onSuccess(ClientPutState state, ClientContext context) {
			if (logDEBUG) {
				//temp hack, ignored if called via super
				Throwable t = new Throwable("DEBUG onSuccess");
				StackTraceElement te = t.getStackTrace()[1];
				if (!("BaseManifestPutter.java".equals(te.getFileName()) && "onSuccess".equals(te.getMethodName()))) {
					Logger.error(this, "Not called via super", t);
				}
				//temp hack end
			}

			if (logMINOR) Logger.minor(this, "Completed '" + this.itemName + "' " + this);

			if (putHandlersWaitingForFetchable.contains(this))
				BaseManifestPutter.this.onFetchable(this);

			ClientPutState oldState;
			synchronized(this) {
				oldState = currentState;
				currentState = null;
			}
			synchronized(BaseManifestPutter.this) {
				runningPutHandlers.remove(this);
				if(putHandlersWaitingForMetadata.remove(this)) {
					Logger.error(this, "PutHandler '"+this.itemName+"' was in waitingForMetadata in onSuccess() on "+this+" for "+BaseManifestPutter.this, new Error("debug"));
				}

				if(putHandlerWaitingForBlockSets.remove(this)) {
					Logger.error(this, "PutHandler was in waitingForBlockSets in onSuccess() on "+this+" for "+BaseManifestPutter.this, new Error("debug"));
				}
				if(putHandlersWaitingForFetchable.remove(this)) {
					Logger.error(this, "PutHandler was in waitingForFetchable in onSuccess() on "+this+" for "+BaseManifestPutter.this, new Error("debug"));
				}

				if(!runningPutHandlers.isEmpty()) {
					if(logMINOR) {
						Logger.minor(this, "Running put handlers: "+runningPutHandlers.size());
						for(Object o : runningPutHandlers) {
							Logger.minor(this, "Still running: "+o);
						}
					}
				}
			}
			tryComplete();
		}

		@Override
		public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
			ClientPutState oldState;
			synchronized(this) {
				oldState = currentState;
				currentState = null;
			}
			if(logMINOR) Logger.minor(this, "Failed: "+this+" - "+e, e);
			fail(e, context);
		}

		@Override
		public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void onTransition(ClientPutState oldState, ClientPutState newState, ClientContext context) {
			if(newState == null) throw new NullPointerException();

			// onTransition is *not* responsible for removing the old state, the caller is.
			synchronized (this) {
				if (currentState == oldState) {
					currentState = newState;
					if(logMINOR)
						Logger.minor(this, "onTransition: cur=" + currentState + ", old=" + oldState + ", new=" + newState+" for "+this);
					return;
				}
				Logger.error(this, "Ignoring onTransition: cur=" + currentState + ", old=" + oldState + ", new=" + newState+" for "+this);
			}
		}

		@Override
		public void onMetadata(Metadata m, ClientPutState state, ClientContext context) {
			throw new UnsupportedOperationException();
		}
		
		@Override
		public void onMetadata(Bucket meta, ClientPutState state,
				ClientContext context) {
			throw new UnsupportedOperationException();
		}

		/** The number of blocks that will be needed to fetch the data. We put this in the top block metadata. */
		protected int minSuccessFetchBlocks;
		
		@Override
		public void addBlock() {
			BaseManifestPutter.this.addBlock();
			synchronized(this) {
				minSuccessFetchBlocks++;
			}
		}

		@Override
		public void addBlocks(int num) {
			BaseManifestPutter.this.addBlocks(num);
			synchronized(this) {
				minSuccessFetchBlocks+=num;
			}
		}

		@Override
		public void completedBlock(boolean dontNotify, ClientContext context) {
			BaseManifestPutter.this.completedBlock(dontNotify, context);
		}

		@Override
		public void failedBlock(ClientContext context) {
			BaseManifestPutter.this.failedBlock(context);
		}

		@Override
		public void fatallyFailedBlock(ClientContext context) {
			BaseManifestPutter.this.fatallyFailedBlock(context);
		}

		@Override
		public synchronized void addMustSucceedBlocks(int blocks) {
			BaseManifestPutter.this.addMustSucceedBlocks(blocks);
			synchronized(this) {
				minSuccessFetchBlocks += blocks;
			}
		}
		
		@Override
		public synchronized void addRedundantBlocksInsert(int blocks) {
			BaseManifestPutter.this.addRedundantBlocksInsert(blocks);
		}
		
		@Override
		public synchronized int getMinSuccessFetchBlocks() {
			return minSuccessFetchBlocks;
		}
		
		@Override
		protected void innerNotifyClients(ClientContext context) {
		    BaseManifestPutter.this.notifyClients(context);
		}

		@Override
		public void onBlockSetFinished(ClientPutState state, ClientContext context) {
			boolean allBlockSets = false;
			synchronized(BaseManifestPutter.this) {
				putHandlerWaitingForBlockSets.remove(this);
				if (freeformMode) {
					allBlockSets = hasResolvedBase && putHandlerWaitingForBlockSets.isEmpty();
				} else {
					allBlockSets = putHandlerWaitingForBlockSets.isEmpty();
				}
			}
			if(allBlockSets)
				BaseManifestPutter.this.blockSetFinalized(context);
		}

		@Override
		public void onFetchable(ClientPutState state) {
			if(logMINOR) Logger.minor(this, "onFetchable " + this, new Exception("debug"));
			BaseManifestPutter.this.onFetchable(this);
		}

		@Override
		public void onTransition(ClientGetState oldState, ClientGetState newState, ClientContext context) {
			// Ignore
		}

		@Override
		public String toString() {
			if (logDEBUG) return super.toString() + " {"+this.itemName+'}';
			return super.toString();
		}

		@Override
		protected void innerToNetwork(ClientContext context) {
			// Ignore
		}
		
        @Override
        public void innerOnResume(ClientContext context) throws ResumeFailedException {
            super.innerOnResume(context);
            try {
                if(currentState != null)
                    currentState.onResume(context);
                if(origSFI != null)
                    origSFI.onResume(context);
            } catch (InsertException e) {
                Logger.error(this, "Failed to start insert on resume: "+e, e);
                throw new ResumeFailedException("Insert error: "+e);
            }
        }
        
        @Override
        public void onShutdown(ClientContext context) {
            ClientPutState s;
            synchronized(this) {
                s = currentState;
            }
            if(s != null) s.onShutdown(context);
        }
        
        @Override
        protected ClientBaseCallback getCallback() {
            return cb;
        }
        
        /** What is our priority class? */
        @Override
        public short getPriorityClass() {
            return BaseManifestPutter.this.getPriorityClass();
        }
        
        @Override
        public ClientRequestSchedulerGroup getSchedulerGroup() {
            return BaseManifestPutter.this;
        }

	}

	private final static String[] defaultDefaultNames =
		new String[] { "index.html", "index.htm", "default.html", "default.htm" };
	// All the default names are in the root.
	// Code will need to be changed if we have index/index.html or similar.
	
	/** if true top level metadata is a container */
	private boolean containerMode = false;
	/** if true top level metadata is a single chunk */
	private boolean freeformMode = false;

	/* common stuff, fields used in freeform and container mode */
	/** put is finalized if empty */
	private HashSet<PutHandler> putHandlerWaitingForBlockSets;
	/** if empty put is fetchable */
	private HashSet<PutHandler> putHandlersWaitingForFetchable;
	private HashSet<PutHandler> runningPutHandlers;

	// container stuff, all fields can be null'ed in freeform mode
	private ContainerBuilder rootContainerBuilder;
	private ContainerPutHandler rootContainerPutHandler;
	private HashSet<PutHandler> containerPutHandlers;
	private HashMap<PutHandler, HashSet<PutHandler>> perContainerPutHandlersWaitingForMetadata;
	/**
	 * PutHandler: the *PutHandler
	 * HashMap<String, Object>: the 'metadata dir' that contains the item inserted by PutHandler
	 * the *PutHandler fills in its result here (Metadata)
	 */
	private HashMap<PutHandler, HashMap<String, Object>> putHandlersTransformMap;
	private HashMap<ArchivePutHandler, ArrayList<PutHandler>> putHandlersArchiveTransformMap;

	// freeform stuff, all fields can be null'ed in container mode
	private FreeFormBuilder rootBuilder;
	private MetaPutHandler rootMetaPutHandler;
	private HashMap<String, Object> rootDir;
	private HashSet<PutHandler> putHandlersWaitingForMetadata;

	private FreenetURI finalURI;
	private final FreenetURI targetURI;
	private boolean finished;
	private final InsertContext ctx;
	final ClientPutCallback cb;

	private int numberOfFiles;
	private long totalSize;
	private Metadata baseMetadata;
	private boolean hasResolvedBase; // if this is true, the final block is ready for insert
	private boolean fetchable;
	final byte[] forceCryptoKey;
	final byte cryptoAlgorithm;

	public BaseManifestPutter(ClientPutCallback cb,
			HashMap<String, Object> manifestElements, short prioClass, FreenetURI target, String defaultName,
			InsertContext ctx, boolean randomiseCryptoKeys, byte [] forceCryptoKey, ClientContext context) throws TooManyFilesInsertException {
		super(prioClass, cb);
		this.targetURI = target;
		this.cb = cb;
		this.ctx = ctx;
		if(randomiseCryptoKeys && forceCryptoKey == null) {
			forceCryptoKey = new byte[32];
			context.random.nextBytes(forceCryptoKey);
		}
		this.forceCryptoKey = forceCryptoKey;
		
		CompatibilityMode mode = ctx.getCompatibilityMode();
		if(!(mode == CompatibilityMode.COMPAT_CURRENT || mode.ordinal() >= CompatibilityMode.COMPAT_1416.ordinal()))
			this.cryptoAlgorithm = Key.ALGO_AES_PCFB_256_SHA256;
		else
			this.cryptoAlgorithm = Key.ALGO_AES_CTR_256_SHA256;
		runningPutHandlers = new HashSet<PutHandler>();
		putHandlersWaitingForMetadata = new HashSet<PutHandler>();
		putHandlersWaitingForFetchable = new HashSet<PutHandler>();
		putHandlerWaitingForBlockSets = new HashSet<PutHandler>();
		containerPutHandlers = new HashSet<PutHandler>();
		perContainerPutHandlersWaitingForMetadata = new HashMap<PutHandler, HashSet<PutHandler>>();
		putHandlersTransformMap = new HashMap<PutHandler, HashMap<String, Object>>();
		putHandlersArchiveTransformMap = new HashMap<ArchivePutHandler, ArrayList<PutHandler>>();
		if(defaultName == null)
			defaultName = findDefaultName(manifestElements);
		makePutHandlers(manifestElements, defaultName);
		// builders are not longer needed after constructor
		rootBuilder = null;
		rootContainerBuilder = null;
	}
	
	private String findDefaultName(HashMap<String, Object> manifestElements) {
		// Find the default name if it has not been set explicitly.
		for(String name : defaultDefaultNames) {
			Object o = manifestElements.get(name);
			if(o == null) continue;
			if(o instanceof HashMap) continue;
			return name;
		}
		for(String name : defaultDefaultNames) {
			boolean found = false;
			for(Map.Entry<String, Object> entry : manifestElements.entrySet()) {
				Object o = entry.getValue();
				if(o == null) continue;
				if(o instanceof HashMap) continue;
				if(entry.getKey().equalsIgnoreCase(name)) {
					found = true;
					name = entry.getKey();
					break;
				}
			}
			if(!found) continue;
			return name;
		}
		return "";
	}

	public void start(ClientContext context) throws InsertException {
		if (logMINOR)
			Logger.minor(this, "Starting " + this+" persistence="+persistent()+ " containermode="+containerMode);
		PutHandler[] running;
		PutHandler[] containers;

		synchronized (this) {
			running = runningPutHandlers.toArray(new PutHandler[runningPutHandlers.size()]);
			if (containerMode) {
				containers = getContainersToStart(running.length > 0);
			} else {
				containers = null;
			}
		}

		try {
			for (int i = 0; i < running.length; i++) {
				running[i].start(context);
				if (logMINOR)
					Logger.minor(this, "Started " + i + " of " + running.length);
				if (isFinished()) {
					if (logMINOR)
						Logger.minor(this, "Already finished, killing start() on " + this);
					return;
				}
			}
			if (logMINOR)
				Logger.minor(this, "Started " + running.length + " PutHandler's for " + this);

			if (containerMode) {
				for (int i = 0; i < containers.length; i++) {
					containers[i].start(context);
					if (logMINOR)
						Logger.minor(this, "Started " + i + " of " + containers.length);
					if (isFinished()) {
						if (logMINOR)
							Logger.minor(this, "Already finished, killing start() on " + this);
						return;
					}
				}
				if (logMINOR)
					Logger.minor(this, "Started " + containers.length + " PutHandler's (containers) for " + this);

			}
			if (!containerMode && running.length == 0) {
				gotAllMetadata(context);
			}
		} catch (InsertException e) {
			synchronized(this) {
				finished = true;
			}
			cancelAndFinish(context);
			throw e;
		}
		//debugDecompose("Start - End");
	}

	private PutHandler[] getContainersToStart(boolean excludeRoot) {
		PutHandler[] maybeStartPH = containerPutHandlers.toArray(new PutHandler[containerPutHandlers.size()]);
		ArrayList<PutHandler> phToStart = new ArrayList<PutHandler>();

		for (PutHandler ph: maybeStartPH) {
			if (perContainerPutHandlersWaitingForMetadata.get(ph).isEmpty()) {
				phToStart.add(ph);
			}
		}
		if ((!excludeRoot) && (maybeStartPH.length == 0)) {
			phToStart.add(rootContainerPutHandler);
		}
		return phToStart.toArray(new PutHandler[phToStart.size()]);
	}

	/**
	 * Implement the pack logic.
	 *
	 * @param manifestElements A map from String to either ManifestElement or another String. This is the
	 * site structure, which will be split into containers and/or external inserts by the method.
	 * @throws TooManyFilesInsertException 
	 */
	protected abstract void makePutHandlers(HashMap<String, Object> manifestElements, String defaultName) throws TooManyFilesInsertException;

	@Override
	public FreenetURI getURI() {
		return finalURI;
	}

	@Override
	public synchronized boolean isFinished() {
		return finished || cancelled;
	}
	
	@Override
	public byte[] getSplitfileCryptoKey() {
		return forceCryptoKey;
	}

	/**
	 * Called when we have metadata for all the PutHandler's.
	 * This does *not* necessarily mean we can immediately insert the final metadata, since
	 * if these metadata's are too big, they will need to be inserted separately. See
	 * resolveAndStartBase().
	 * @param container
	 * @param context
	 */
	private void gotAllMetadata(ClientContext context) {
		if (containerMode) throw new IllegalStateException();
		if(logMINOR) Logger.minor(this, "Got all metadata");
		baseMetadata = makeMetadata(rootDir);
		context.jobRunner.setCheckpointASAP();
		resolveAndStartBase(context);
	}

	@SuppressWarnings("unchecked")
	private Metadata makeMetadata(HashMap<String, Object> dir) {
		SimpleManifestComposer smc = new SimpleManifestComposer();
		for(Map.Entry<String, Object> entry:dir.entrySet()) {
			String name = entry.getKey();
			Object item = entry.getValue();
			if (item == null) throw new NullPointerException();
			Metadata m;
			if (item instanceof HashMap) {
				m = makeMetadata((HashMap<String, Object>) item);
				if (m == null) throw new NullPointerException("HERE!!");
			} else {
				m = ((PutHandler)item).metadata;
				if (m == null) throw new NullPointerException("HERE!!" +item);
			}
			smc.addItem(name, m);
		}
		return smc.getMetadata();
	}

	/**
	 * Attempt to insert the base metadata and the container. If the base metadata cannot be resolved,
	 * try to resolve it: start inserts for each part that cannot be resolved, and wait for them to generate
	 * URIs that can be incorporated into the metadata. This method will then be called again, and will
	 * complete, or do more resolutions as necessary.
	 * @param container
	 * @param context
	 */
	private void resolveAndStartBase(ClientContext context) {
		//new Error("DEBUG_ME_resolveAndStartBase").printStackTrace();
	    RandomAccessBucket bucket = null;
		synchronized(this) {
			if(hasResolvedBase) return;
		}
		while(true) {
			try {
			    bucket = baseMetadata.toBucket(context.getBucketFactory(persistent()));
				if(logMINOR)
					Logger.minor(this, "Metadata bucket is "+bucket.size()+" bytes long");
				break;
			} catch (IOException e) {
				fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null), context);
				return;
			} catch (MetadataUnresolvedException e) {
				try {
					// Start the insert for the sub-Metadata.
					// Eventually it will generate a URI and call onEncode(), which will call back here.
					if(logMINOR) Logger.minor(this, "Main metadata needs resolving: "+e);
					resolve(e, context);
					return;
				} catch (IOException e1) {
					fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null), context);
					return;
				} catch (InsertException e2) {
					fail(e2, context);
					return;
				}
			}
		}
		if(bucket == null) return;
		synchronized(this) {
			if(hasResolvedBase) return;
			hasResolvedBase = true;
		}
		InsertBlock block;
		block = new InsertBlock(bucket, null, targetURI);
		try {
			rootMetaPutHandler = new MetaPutHandler(this, null, block);

			if(logMINOR) Logger.minor(this, "Inserting main metadata: "+rootMetaPutHandler+" for "+baseMetadata);
			rootMetaPutHandler.start(context);
		} catch (InsertException e) {
			fail(e, context);
			return;
		}
	}

	/**
	 * Start inserts for unresolved (too big) Metadata's. Eventually these will call back with an onEncode(),
	 * meaning they have the CHK, and we can progress to resolveAndStartBase().
	 * @param e
	 * @param container
	 * @param context
	 * @return
	 * @throws InsertException
	 * @throws IOException
	 */
	private void resolve(MetadataUnresolvedException e, ClientContext context) throws InsertException, IOException {
		new Error("RefactorME-resolve").printStackTrace();
		Metadata[] metas = e.mustResolve;
		for(Metadata m: metas) {
			if(logMINOR) Logger.minor(this, "Resolving "+m);
			if(m.isResolved()) {
				Logger.error(this, "Already resolved: "+m+" in resolve() - race condition???");
				continue;
			}
			try {
				MetaPutHandler ph = new MetaPutHandler(this, null, m, context.getBucketFactory(persistent()));
				ph.start(context);
			} catch (MetadataUnresolvedException e1) {
				resolve(e1, context);
			}
		}
	}

	private void tryComplete() {
		//debugDecompose("try complete");
		if(logDEBUG) Logger.debug(this, "try complete", new Error("trace tryComplete()"));
		synchronized(this) {
			if(finished || cancelled) {
				if(logMINOR) Logger.minor(this, "Already "+(finished?"finished":"cancelled"));
				return;
			}
			if (!runningPutHandlers.isEmpty()) {
				if (logDEBUG) Logger.debug(this, "Not finished, runningPutHandlers not empty.");
				return;
			}
			if (!containerPutHandlers.isEmpty()) {
				if (logDEBUG) Logger.debug(this, "Not finished, containerPutHandlers not empty.");
				return;
			}
			if (containerMode) {
				if (rootContainerPutHandler != null) {
					if (logDEBUG) Logger.debug(this, "Not finished, rootContainerPutHandler not empty.");
					return;
				}
			} else {
				if (rootMetaPutHandler != null) {
					if (logDEBUG) Logger.debug(this, "Not finished, rootMetaPutHandler not empty.");
					return;
				}
			}
			finished = true;
		}
		complete();
	}

	private void complete() {
		// FIXME we could remove the put handlers after inserting all files but not having finished the insert of the manifest
		// However it would complicate matters for no real gain in most cases...
		// Also doing it this way means we don't need to worry about
		cb.onSuccess(this);
	}

	private void fail(Exception e, ClientContext context) {
		InsertException ie = new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null);
		fail(ie, context);
	}

	private void fail(InsertException e, ClientContext context) {
		// Cancel all, then call the callback
		synchronized(this) {
			if(finished) return;
			finished = true;
		}
		cancelAndFinish(context);

		cb.onFailure(e, this);
	}

	/**
	 * Cancel all running inserters.
	 */
	private void cancelAndFinish(ClientContext context) {
		PutHandler[] running;
		synchronized(this) {
			running = runningPutHandlers.toArray(new PutHandler[runningPutHandlers.size()]);
		}

		if(logMINOR) Logger.minor(this, "PutHandler's to cancel: "+running.length);
		for(PutHandler putter : running) {
			putter.cancel(context);
		}
		// TODO
//		ClientPutState[] runningMeta;
//		if(persistent())
//			container.activate(metadataPuttersByMetadata, 2);
//		synchronized(this) {
//			runningMeta = metadataPuttersByMetadata.values().toArray(new ClientPutState[metadataPuttersByMetadata.size()]);
//		}
//
//		if(logMINOR) Logger.minor(this, "Metadata putters to cancel: "+runningMeta.length);
//		for(ClientPutState putter : runningMeta) {
//			boolean active = true;
//			if(persistent) {
//				active = container.ext().isActive(putter);
//				if(!active) container.activate(putter, 1);
//			}
//			putter.cancel(container, context);
//			if(!active) container.deactivate(putter, 1);
//			if(persistent) container.activate(this, 1);
//		}
	}

	@Override
	public void cancel(ClientContext context) {
		synchronized(this) {
			if(finished) return;
			if(super.cancel()) return;
		}
		fail(new InsertException(InsertExceptionMode.CANCELLED), context);
	}

	/** The number of blocks that will be needed to fetch the data. We put this in the top block metadata. */
	protected int minSuccessFetchBlocks;
	
	@Override
	public void addBlock() {
		synchronized(this) {
			minSuccessFetchBlocks++;
		}
		super.addBlock();
	}
	
	@Override
	public void addBlocks(int num) {
		synchronized(this) {
			minSuccessFetchBlocks+=num;
		}
		super.addBlocks(num);
	}
	
	/** Add one or more blocks to the number of requires blocks, and don't notify the clients. */
	@Override
	public void addMustSucceedBlocks(int blocks) {
		synchronized(this) {
			minSuccessFetchBlocks += blocks;
		}
		super.addMustSucceedBlocks(blocks);
	}

	/** Add one or more blocks to the number of requires blocks, and don't notify the clients. 
	 * These blocks are added to the minSuccessFetchBlocks for the insert, but not to the counter for what
	 * the requestor must fetch. */
	@Override
	public void addRedundantBlocksInsert(int blocks) {
		super.addMustSucceedBlocks(blocks);
	}

	@Override
	public void innerNotifyClients(ClientContext context) {
	    SplitfileProgressEvent e;
	    synchronized(this) {
	        e = new SplitfileProgressEvent(
	            this.totalBlocks,
	            this.successfulBlocks,
	            this.latestSuccess,
	            this.failedBlocks,
	            this.fatallyFailedBlocks,
	            this.latestFailure,
	            this.minSuccessBlocks,
	            this.minSuccessFetchBlocks,
	            this.blockSetFinalized);
	    }
		ctx.eventProducer.produceEvent(e, context);
	}

	@Override
	public int getMinSuccessFetchBlocks() {
		return minSuccessFetchBlocks;
	}
	
	@Override
	public void blockSetFinalized(ClientContext context) {
		super.blockSetFinalized(context);
	}

	public int countFiles() {
		return numberOfFiles;
	}

	public long totalSize() {
		return totalSize;
	}

	protected void onFetchable(PutHandler handler) {
		//new Error("Trace_ME onFetchable").printStackTrace();
		if(checkFetchable(handler)) {
			cb.onFetchable(this);
		}
	}

	private synchronized boolean checkFetchable(PutHandler handler) {
		//new Error("RefactorME").printStackTrace();
		if (!putHandlersWaitingForFetchable.remove(handler)) {
			throw new IllegalStateException("was not in putHandlersWaitingForFetchable! : "+handler);
		}
		if(fetchable) return false;
		if(!putHandlersWaitingForFetchable.isEmpty()) return false;
		fetchable = true;
		return true;
	}

	@Override
	public void onTransition(ClientGetState oldState, ClientGetState newState, ClientContext context) {
		// Ignore
	}

	@Override
	public void onTransition(ClientPutState from, ClientPutState to, ClientContext context) {
	    // Everything should be on the PutHandler's, right?
	    Logger.error(this, "Ignoring transition from "+from+" to "+to+" on "+this);
		// Ignore
	}

	@Override
	protected void innerToNetwork(ClientContext context) {
		// Ignore
	}

	private void tryStartParentContainer(PutHandler containerHandle2, ClientContext context) throws InsertException {
		//new Error("RefactorME").printStackTrace();
		if (containerHandle2 == null) throw new NullPointerException();
		//if (perContainerPutHandlersWaitingForMetadata.get(containerHandle2).isEmpty() && perContainerPutHandlersWaitingForFetchable.get(containerHandle2).isEmpty()) {
		if (perContainerPutHandlersWaitingForMetadata.get(containerHandle2).isEmpty()) {
			perContainerPutHandlersWaitingForMetadata.remove(containerHandle2);
			containerHandle2.start(context);
		} else {
			//System.out.println(" waiting m:"+perContainerPutHandlersWaitingForMetadata.get(containerHandle2).size()+" F:"+perContainerPutHandlersWaitingForFetchable.get(containerHandle2).size() + " for "+containerHandle2);
			if(logMINOR)
				Logger.minor(this, "(spc) waiting m:"+perContainerPutHandlersWaitingForMetadata.get(containerHandle2).size() + " for "+containerHandle2);
		}
	}

	// compose helper stuff

	protected final ClientMetadata guessMime(String name, ManifestElement me) {
		return guessMime(name, me.mimeOverride);
	}

	protected final ClientMetadata guessMime(String name, String mimetype) {
		String mimeType = mimetype;
		if((mimeType == null) && (name != null))
			mimeType = DefaultMIMETypes.guessMIMEType(name, true);
		ClientMetadata cm;
		if(mimeType == null || mimeType.equals(DefaultMIMETypes.DEFAULT_MIME_TYPE))
			cm = null;
		else
			cm = new ClientMetadata(mimeType);
		return cm;
	}

	public ContainerBuilder makeArchive() {
		return new ContainerBuilder(false, null, null, true);
	}

	protected ContainerBuilder getRootContainer() {
		if (freeformMode) throw new IllegalStateException("Already in freeform mode!");
		if (!containerMode) {
			containerMode = true;
			rootContainerBuilder = new ContainerBuilder(true);
		}
		return rootContainerBuilder;
	}

	protected FreeFormBuilder getRootBuilder() {
		if (containerMode) throw new IllegalStateException("Already in container mode!");
		if (!freeformMode) {
			freeformMode = true;
			rootBuilder = new FreeFormBuilder();
		}
		return rootBuilder;
	}

	protected abstract class ManifestBuilder implements Serializable {

        private static final long serialVersionUID = 1L;
        private final Stack<HashMap<String, Object>> dirStack;
		/** Map from name to either a Metadata (to be included as-is), a ManifestElement (either a redirect
		 * or a file), or another HashMap. Eventually processed by e.g. ContainerInserter.makeManifest()
		 * (for a ContainerBuilder). */
		protected HashMap<String, Object> currentDir;

		private ClientMetadata makeClientMetadata(String mime) {
			if (mime == null)
				return null;
			ClientMetadata cm = new ClientMetadata(mime.trim());
			if (cm.isTrivial())
				return null;
			return cm;
		}

		ManifestBuilder() {
			dirStack = new Stack<HashMap<String, Object>>();
		}

		public void pushCurrentDir() {
			dirStack.push(currentDir);
		}

		public void popCurrentDir() {
			currentDir = dirStack.pop();
		}

		/**
		 * make 'name' the current subdir (cd into it).<br>
		 * if it not exists, it is created.
		 *
		 * @param name name of the subdir
		 */
		public void makeSubDirCD(String name) {
			Object dir = currentDir.get(name);
			if (dir != null) {
				currentDir = Metadata.forceMap(dir);
			} else {
				currentDir = makeSubDir(currentDir, name);
			}
		}

		private HashMap<String, Object> makeSubDir(HashMap<String, Object> parentDir, String name) {
			if (parentDir.containsKey(name)) {
				throw new IllegalStateException("Item '"+name+"' already exist!");
			}
			HashMap<String, Object> newDir = new HashMap<String, Object>();
			parentDir.put(name , newDir);
			return newDir;
		}

		/**
		 * add a ManifestElement, either a redirect (target uri given) or an external
		 * @param name
		 * @param element
		 * @param isDefaultDoc
		 */
		public final void addElement(String name, ManifestElement element, boolean isDefaultDoc) {
			ClientMetadata cm = makeClientMetadata(element.mimeOverride);

			if (element.getData() != null) {
				addExternal(name, element.getData(), cm, isDefaultDoc);
				return;
			}
			if (element.targetURI != null) {
				addRedirect(name, element.targetURI, cm, isDefaultDoc);
				return;
			}
			throw new IllegalStateException("ME is neither a redirect nor dircet data. "+element);
		}

		/** Add a file as an external. It will be inserted separately and we will add a redirect to the
		 * metadata.
		 * @param name The name of the file (short name within the original folder, it's not in a container).
		 * @param data The data to be inserted.
		 * @param mimeOverride Optional MIME type override.
		 * @param isDefaultDoc If true, make this the default document.
		 */
		public final void addExternal(String name, RandomAccessBucket data, String mimeOverride, boolean isDefaultDoc) {
			assert(data != null);
			ClientMetadata cm = makeClientMetadata(mimeOverride);
			addExternal(name, data, cm, isDefaultDoc);
		}

		public final void addRedirect(String name, FreenetURI targetUri, String mimeOverride, boolean isDefaultDoc) {
			ClientMetadata cm = makeClientMetadata(mimeOverride);
			addRedirect(name, targetUri, cm, isDefaultDoc);
		}

		public abstract void addExternal(String name, RandomAccessBucket data, ClientMetadata cm, boolean isDefaultDoc);
		public abstract void addRedirect(String name, FreenetURI targetUri, ClientMetadata cm, boolean isDefaultDoc);
	}

	protected final class FreeFormBuilder extends ManifestBuilder {

        private static final long serialVersionUID = 1L;

        protected FreeFormBuilder() {
			rootDir = new HashMap<String, Object>();
			currentDir = rootDir;
		}

		@Override
		public void addExternal(String name, RandomAccessBucket data, ClientMetadata cm, boolean isDefaultDoc) {
			PutHandler ph;
			ph = new ExternPutHandler(BaseManifestPutter.this, null, name, data, cm);
//			putHandlersWaitingForMetadata.add(ph);
//			putHandlersWaitingForFetchable.add(ph);
			if(logMINOR) Logger.minor(this, "Inserting separately as PutHandler: "+name+" : "+ph+" persistent="+ph.persistent());
			numberOfFiles++;
			totalSize += data.size();
			currentDir.put(name, ph);
			if (isDefaultDoc) {
				ph = new JokerPutHandler(BaseManifestPutter.this, null, name, name);
				currentDir.put("", ph);
			}
		}

		@Override
		public void addRedirect(String name, FreenetURI targetURI2, ClientMetadata cm, boolean isDefaultDoc) {
			PutHandler ph;
			ph = new JokerPutHandler(BaseManifestPutter.this, name, targetURI2, cm);
			currentDir.put(name, ph);
			if (isDefaultDoc)
				currentDir.put("", ph);
		}
	}
	
	protected final class ContainerBuilder extends ManifestBuilder {

        private static final long serialVersionUID = 1L;
        /** Tree containing the status of the insert. Can have ManifestElement's (original files to
         * insert or bundle inside a container), HashMap's (more subdirs), Metadata (to be put into 
         * a container as metadata for e.g. an external file), a ContainerPutHandler or an 
         * ArchivePutHandler (for containers that are part of the structure, and external containers 
         * for overflow, respectively). */
        private final HashMap<String, Object> _rootDir;
		private final PutHandler selfHandle;

		private ContainerBuilder(boolean isRoot) {
			this(isRoot, null, null, false);
		}

		private ContainerBuilder(PutHandler parent, String name) {
			this(false, parent, name, false);
		}

		private ContainerBuilder(boolean isRoot, PutHandler parent, String name, boolean isArchive) {
			if (!containerMode) {
				throw new IllegalStateException("You can not add containers in free form mode!");
			}
			_rootDir = new HashMap<String, Object>();
			if (isArchive)
				selfHandle = new ArchivePutHandler(BaseManifestPutter.this,
						parent, name, _rootDir,
						(isRoot ? BaseManifestPutter.this.targetURI
								: FreenetURI.EMPTY_CHK_URI));
			else
				selfHandle = new ContainerPutHandler(BaseManifestPutter.this,
						parent, name, _rootDir,
						(isRoot ? BaseManifestPutter.this.targetURI
								: FreenetURI.EMPTY_CHK_URI), (isRoot ? null : containerPutHandlers));
			currentDir = _rootDir;
			if (isRoot) {
				rootContainerPutHandler = (ContainerPutHandler)selfHandle;
			} else {
				containerPutHandlers.add(selfHandle);
			}
			perContainerPutHandlersWaitingForMetadata.put(selfHandle, new HashSet<PutHandler>());
			//perContainerPutHandlersWaitingForFetchable.put(selfHandle, new HashSet<PutHandler>());
			if (isArchive) putHandlersArchiveTransformMap.put((ArchivePutHandler)selfHandle, new ArrayList<PutHandler>());
		}

		public ContainerBuilder makeSubContainer(String name) {
			ContainerBuilder subCon = new ContainerBuilder(selfHandle, name);
			currentDir.put(name, subCon.selfHandle);
			putHandlersTransformMap.put(subCon.selfHandle, currentDir);
			perContainerPutHandlersWaitingForMetadata.get(selfHandle).add(subCon.selfHandle);
			return subCon;
		}

		/**
		 * Add a ManifestElement, which can be a file in an archive, or a redirect.
		 * @param name The original name of the file (e.g. index.html).
		 * @param nameInArchive The fully qualified name of the file in the archive (e.g. testing/index.html).
		 * @param element The ManifestElement specifying the data, redirect, etc. Note that redirects are
		 * still included in containers, both for structural reasons and because the metadata can be large
		 * enough that we need to split it.
		 * @param isDefaultDoc If true, add a link from "" to this element, making it the default document
		 * in this container.
		 */
		public void addItem(String name, String nameInArchive, ManifestElement element, boolean isDefaultDoc) {
			ManifestElement me = new ManifestElement(element, name, nameInArchive);
			addItem(name, me, isDefaultDoc);
		}

		public void addItem(String name, ManifestElement element, boolean isDefaultDoc) {
			currentDir.put(name, element);
			if (isDefaultDoc) {
				Metadata m = new Metadata(DocumentType.SYMBOLIC_SHORTLINK, null, null, name, null);
				currentDir.put("", m);
			}
			numberOfFiles++;
			if(element.getData() != null)
			    totalSize += element.getSize();
		}

		@Override
		public void addRedirect(String name, FreenetURI targetUri, ClientMetadata cm, boolean isDefaultDoc) {
			Metadata m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, targetUri, cm);
			currentDir.put(name, m);
			if (isDefaultDoc) {
				currentDir.put("", m);
			}
		}

		@Override
		public void addExternal(String name, RandomAccessBucket data, ClientMetadata cm, boolean isDefaultDoc) {
			PutHandler ph = new ExternPutHandler(BaseManifestPutter.this, selfHandle, name, data, cm);
			perContainerPutHandlersWaitingForMetadata.get(selfHandle).add(ph);
			putHandlersTransformMap.put(ph, currentDir);
			if (isDefaultDoc) {
				Metadata m = new Metadata(DocumentType.SYMBOLIC_SHORTLINK, null, null, name, null);
				currentDir.put("", m);
			}
			numberOfFiles++;
			totalSize += data.size();
		}

		/** FIXME what is going on here? Why do we need to add a JokerPutHandler, when a lot of code just
		 * calls addItem()? */
		public void addArchiveItem(ContainerBuilder archive, String name, ManifestElement element, boolean isDefaultDoc) {
			assert(element.getData() != null);
			archive.addItem(name, new ManifestElement(element, name, name), false);
			PutHandler ph = new JokerPutHandler(BaseManifestPutter.this, selfHandle, name, guessMime(name, element.mimeOverride));
			putHandlersTransformMap.put(ph, currentDir);
			perContainerPutHandlersWaitingForMetadata.get(selfHandle).add(ph);
			putHandlersArchiveTransformMap.get(archive.selfHandle).add(ph);
			if (isDefaultDoc) {
				Metadata m = new Metadata(DocumentType.SYMBOLIC_SHORTLINK, null, null, name, null);
				currentDir.put("", m);
			}
			numberOfFiles++;
			if(element.getData() != null)
			    totalSize += element.getSize();
		}
	}
	
    @Override
    protected ClientBaseCallback getCallback() {
        return cb;
    }
    
    public static HashMap<String, Object> bucketsByNameToManifestEntries(HashMap<String,Object> bucketsByName) {
        HashMap<String,Object> manifestEntries = new HashMap<String,Object>();
        for(Map.Entry<String,Object> entry: bucketsByName.entrySet()) {
            String name = entry.getKey();
            Object o = entry.getValue();
            if(o instanceof ManifestElement) {
                manifestEntries.put(name, o);
            } else if(o instanceof Bucket) {
                RandomAccessBucket data = (RandomAccessBucket) o;
                manifestEntries.put(name, new ManifestElement(name, data, null, data.size()));
            } else if(o instanceof HashMap) {
                manifestEntries.put(name, bucketsByNameToManifestEntries(Metadata.forceMap(o)));
            } else
                throw new IllegalArgumentException(String.valueOf(o));
        }
        return manifestEntries;
    }
	
    public static ManifestElement[] flatten(HashMap<String,Object> manifestElements) {
        List<ManifestElement> v = new ArrayList<ManifestElement>();
        flatten(manifestElements, v, "");
        return v.toArray(new ManifestElement[v.size()]);
    }
    
    public static void flatten(HashMap<String,Object> manifestElements, List<ManifestElement> v, String prefix) {
        for(Map.Entry<String,Object> entry: manifestElements.entrySet()) {
            String name = entry.getKey();
            String fullName = prefix.length() == 0 ? name : prefix+ '/' +name;
            Object o = entry.getValue();
            if(o instanceof HashMap) {
                flatten(Metadata.forceMap(o), v, fullName);
            } else if(o instanceof ManifestElement) {
                ManifestElement me = (ManifestElement) o;
                v.add(new ManifestElement(me, fullName));
            } else
                throw new IllegalStateException(String.valueOf(o));
        }
    }
    
    @Override
    public void onShutdown(ClientContext context) {
        for(PutHandler h : runningPutHandlers)
            h.onShutdown(context);
        if(rootContainerPutHandler != null)
            rootContainerPutHandler.onShutdown(context);
        if(containerPutHandlers != null) {
            for(PutHandler h : containerPutHandlers)
                h.onShutdown(context);
        }
        if(rootMetaPutHandler != null)
            rootMetaPutHandler.onShutdown(context);
    }
    
    protected void innerOnResume(ClientContext context) throws ResumeFailedException {
        super.innerOnResume(context);
        for(PutHandler h : runningPutHandlers)
            h.onResume(context);
        if(rootContainerPutHandler != null)
            rootContainerPutHandler.onResume(context);
        if(containerPutHandlers != null) {
            for(PutHandler h : containerPutHandlers)
                h.onResume(context);
        }
        if(rootMetaPutHandler != null)
            rootMetaPutHandler.onResume(context);
    }
}
