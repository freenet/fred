/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.async;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.RandomAccessFile;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.List;

import freenet.client.ArchiveContext;
import freenet.client.ClientMetadata;
import freenet.client.DefaultMIMETypes;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.FetchResult;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.client.async.BinaryBlobWriter.BinaryBlobAlreadyClosedException;
import freenet.client.events.EnterFiniteCooldownEvent;
import freenet.client.events.ExpectedFileSizeEvent;
import freenet.client.events.ExpectedHashesEvent;
import freenet.client.events.ExpectedMIMEEvent;
import freenet.client.events.SendingToNetworkEvent;
import freenet.client.events.SplitfileCompatibilityModeEvent;
import freenet.client.events.SplitfileProgressEvent;
import freenet.client.filter.ContentFilter;
import freenet.client.filter.FilterMIMEType;
import freenet.client.filter.UnsafeContentTypeException;
import freenet.crypt.ChecksumChecker;
import freenet.crypt.HashResult;
import freenet.keys.ClientKeyBlock;
import freenet.keys.FreenetURI;
import freenet.support.Logger;
import freenet.support.api.Bucket;
import freenet.support.compress.CompressionOutputSizeException;
import freenet.support.compress.Compressor;
import freenet.support.compress.DecompressorThreadManager;
import freenet.support.io.Closer;
import freenet.support.io.FileBucket;
import freenet.support.io.FileUtil;
import freenet.support.io.InsufficientDiskSpaceException;
import freenet.support.io.NullOutputStream;
import freenet.support.io.ResumeFailedException;
import freenet.support.io.StorageFormatException;

/**
 * A high level data request. Follows redirects, downloads splitfiles, etc. Similar to what you get from FCP,
 * and is used internally to implement FCP. Also used by fproxy, and plugins, and so on. The current state
 * of the request is stored in currentState. The ClientGetState's do most of the work. SingleFileFetcher for
 * example fetches a key, parses the metadata, and if necessary creates other states to e.g. fetch splitfiles.
 */
public class ClientGetter extends BaseClientGetter
implements WantsCooldownCallback, FileGetCompletionCallback, Serializable {

    private static final long serialVersionUID = 1L;
    private static volatile boolean logMINOR;

	static {
		Logger.registerClass(ClientGetter.class);
	}

	/** Will be called when the request completes */
	final ClientGetCallback clientCallback;
	/** The initial Freenet URI being fetched. */
	FreenetURI uri;
	/** Settings for the fetch - max size etc */
	final FetchContext ctx;
	/** Checks for container loops. */
	final ArchiveContext actx;
	/** The current state of the request. SingleFileFetcher when processing metadata for fetching a simple
	 * key, SplitFileFetcher when fetching a splitfile, etc. */
	private ClientGetState currentState;
	/** Has the request finished? */
	private boolean finished;
	/** Number of times the fetch has been restarted because a container was out of date */
	private int archiveRestarts;
	/** If not null, Bucket to return the data in, otherwise we create one. If non-null, it is the
	 * responsibility of the callback to create and resume this bucket. */
	final Bucket returnBucket;
	/** If not null, BucketWrapper to return a binary blob in */
	private final BinaryBlobWriter binaryBlobWriter;
	/** If true, someone else is responsible for this BlobWriter, usually its a shared one */
	private final boolean dontFinalizeBlobWriter;
	/** The expected MIME type, if we know it. Should not change. */
	private String expectedMIME;
	/** The expected size of the file, if we know it. */
	private long expectedSize;
	/** If true, the metadata (mostly the expected size) shouldn't change further. */
	private boolean finalizedMetadata;
	/** Callback to spy on the metadata at each stage of the request */
	private SnoopMetadata snoopMeta;
	/** Callback to spy on the data at each stage of the request */
	private SnoopBucket snoopBucket;
	private HashResult[] hashes;
	private final Bucket initialMetadata;
	/** If set, and filtering is enabled, the MIME type we filter with must
	 * be compatible with this extension. */
	final String forceCompatibleExtension;
	private transient boolean resumedFetcher;

	// Shorter constructors for convenience and backwards compatibility.

	public ClientGetter(ClientGetCallback client,
		    FreenetURI uri, FetchContext ctx, short priorityClass) {
		this(client, uri, ctx, priorityClass, null, null, null);
	}

	public ClientGetter(ClientGetCallback client,
		    FreenetURI uri, FetchContext ctx, short priorityClass, Bucket returnBucket) {
		this(client, uri, ctx, priorityClass, returnBucket, null, null);
	}

	public ClientGetter(ClientGetCallback client,
		    FreenetURI uri, FetchContext ctx, short priorityClass, Bucket returnBucket, BinaryBlobWriter binaryBlobWriter) {
		this(client, uri, ctx, priorityClass, returnBucket, binaryBlobWriter, null);
	}

	public ClientGetter(ClientGetCallback client,
		    FreenetURI uri, FetchContext ctx, short priorityClass, Bucket returnBucket, BinaryBlobWriter binaryBlobWriter, Bucket initialMetadata) {
		this(client, uri, ctx, priorityClass, returnBucket, binaryBlobWriter, false, initialMetadata);
	}

	public ClientGetter(ClientGetCallback client,
			FreenetURI uri, FetchContext ctx, short priorityClass, Bucket returnBucket, BinaryBlobWriter binaryBlobWriter, boolean dontFinalizeBlobWriter, Bucket initialMetadata) {
		this(client, uri, ctx, priorityClass, returnBucket, binaryBlobWriter, dontFinalizeBlobWriter, initialMetadata, null);
	}

	/**
	 * Fetch a key.
	 * @param client The callback we will call when it is completed.
	 * @param uri The URI to fetch.
	 * @param ctx The config settings for the fetch.
	 * @param priorityClass The priority at which to schedule the request.
	 * @param clientContext The context object. Used for round-robin query balancing, also indicates whether
	 * the request is persistent.
	 * @param returnBucket The bucket to return the data in. Can be null. If not null, the ClientGetter must either
	 * write the data directly to the bucket, or copy it and free the original temporary bucket. Preferably the
	 * former, obviously!
	 * @param binaryBlobWriter If non-null, we will write all the keys accessed (or that could have been
	 * accessed in the case of redundant structures such as splitfiles) to this binary blob writer.
	 * @param dontFinalizeBlobWriter If true, the caller is responsible for BlobWriter finalization
	 */
	public ClientGetter(ClientGetCallback client,
			FreenetURI uri, FetchContext ctx, short priorityClass, Bucket returnBucket, BinaryBlobWriter binaryBlobWriter, boolean dontFinalizeBlobWriter, Bucket initialMetadata, String forceCompatibleExtension) {
		super(priorityClass, client.getRequestClient());
		this.clientCallback = client;
		this.returnBucket = returnBucket;
		this.uri = uri;
		this.ctx = ctx;
		this.finished = false;
		this.actx = new ArchiveContext(ctx.maxTempLength, ctx.maxArchiveLevels);
		this.binaryBlobWriter = binaryBlobWriter;
		this.dontFinalizeBlobWriter = dontFinalizeBlobWriter;
		this.initialMetadata = initialMetadata;
		archiveRestarts = 0;
		this.forceCompatibleExtension = forceCompatibleExtension;
	}

	/** Required because we implement {@link Serializable}. */
	protected ClientGetter() {
	    clientCallback = null;
	    ctx = null;
	    actx = null;
	    returnBucket = null;
	    binaryBlobWriter = null;
	    dontFinalizeBlobWriter = false;
	    initialMetadata = null;
	    forceCompatibleExtension = null;
	}

	public void start(ClientContext context) throws FetchException {
		start(false, null, context);
	}

	/** Start the request.
	 * @param restart If true, restart a finished request.
	 * @param overrideURI If non-null, change the URI we are fetching (usually when restarting).
	 * @param container The database, null if this is a non-persistent request; if this is a persistent
	 * request, we must be on the database thread, and we will pass the database handle around as needed.
	 * @param context The client context, contains important mostly non-persistent global objects.
	 * @return True if we restarted, false if we didn't (but only in a few cases).
	 * @throws FetchException If we were unable to restart.
	 */
	public boolean start(boolean restart, FreenetURI overrideURI, ClientContext context) throws FetchException {
		if(logMINOR)
			Logger.minor(this, "Starting "+this+" persistent="+persistent()+" for "+uri);
		try {
			// FIXME synchronization is probably unnecessary.
			// But we DEFINITELY do not want to synchronize while calling currentState.schedule(),
			// which can call onSuccess and thereby almost anything.
			HashResult[] oldHashes = null;
			String overrideMIME = ctx.overrideMIME;
			synchronized(this) {
				if(restart)
					clearCountersOnRestart();
				if(overrideURI != null) uri = overrideURI;
				if(finished) {
					if(!restart) return false;
					currentState = null;
					cancelled = false;
					finished = false;
				}
				if(!resumedFetcher) {
				    actx.clear();
	                expectedMIME = null;
	                expectedSize = 0;
	                oldHashes = hashes;
	                hashes = null;
	                finalBlocksRequired = 0;
	                finalBlocksTotal = 0;
	                resetBlocks();
				    currentState = SingleFileFetcher.create(this, this,
				            uri, ctx, actx, ctx.maxNonSplitfileRetries, 0, false, -1, true,
				            true, context, realTimeFlag, initialMetadata != null);
				}
                if(overrideMIME != null)
                    expectedMIME = overrideMIME;
			}
			if(cancelled) cancel();
			// schedule() may deactivate stuff, so store it now.
			if(currentState != null && !finished) {
				if(initialMetadata != null && currentState instanceof SingleFileFetcher && !resumedFetcher) {
					((SingleFileFetcher)currentState).startWithMetadata(initialMetadata, context);
				} else
					currentState.schedule(context);
			}
			if(cancelled) cancel();
		} catch (MalformedURLException e) {
			throw new FetchException(FetchExceptionMode.INVALID_URI, e);
		}
		return true;
	}

	@Override
	protected void clearCountersOnRestart() {
		this.archiveRestarts = 0;
		this.expectedMIME = null;
		this.expectedSize = 0;
		this.finalBlocksRequired = 0;
		this.finalBlocksTotal = 0;
		super.clearCountersOnRestart();
	}

	/**
	 * Called when the request succeeds.
	 * @param state The ClientGetState which retrieved the data.
	 */
	@Override
	public void onSuccess(StreamGenerator streamGenerator, ClientMetadata clientMetadata, List<? extends Compressor> decompressors, ClientGetState state, ClientContext context) {
		if(logMINOR)
			Logger.minor(this, "Succeeded from "+state+" on "+this);
		// Fetching the container is essentially a full success, we should update the latest known good.
		context.uskManager.checkUSK(uri, persistent(), false);
		try {
			if (binaryBlobWriter != null && !dontFinalizeBlobWriter) binaryBlobWriter.finalizeBucket();
		} catch (IOException ioe) {
			onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, "Failed to close binary blob stream: "+ioe), null, context);
			return;
		} catch (BinaryBlobAlreadyClosedException e) {
			onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, "Failed to close binary blob stream, already closed: "+e, e), null, context);
			return;
		}
		String mimeType = clientMetadata == null ? null : clientMetadata.getMIMEType();

		if(forceCompatibleExtension != null && ctx.filterData) {
		    if(mimeType == null) {
		        onFailure(new FetchException(FetchExceptionMode.MIME_INCOMPATIBLE_WITH_EXTENSION, "No MIME type but need specific extension \""+forceCompatibleExtension+"\""), null, context);
		        return;
		    }
			try {
				checkCompatibleExtension(mimeType);
			} catch (FetchException e) {
				onFailure(e, null, context);
				return;
			}
		}

		synchronized(this) {
			finished = true;
			currentState = null;
			expectedMIME = mimeType;

		}
		// Rest of method does not need to be synchronized.
		// Variables will be updated on exit of method, and the only thing that is
		// set is the returnBucket and the result. Not locking not only prevents
		// nested locking resulting in deadlocks, it also prevents long locks due to
		// doing massive encrypted I/Os while holding a lock.

		PipedOutputStream dataOutput = new PipedOutputStream();
		PipedInputStream dataInput = new PipedInputStream();
		OutputStream output = null;

		DecompressorThreadManager decompressorManager = null;
		ClientGetWorkerThread worker = null;
		Bucket finalResult = null;
		FetchResult result = null;

        long maxLen = -1;
        synchronized(this) {
            if(expectedSize > 0) {
                maxLen = expectedSize;
            }
        }
        if(ctx.filterData && maxLen >= 0) {
            maxLen = expectedSize * 2 + 1024;
        }
        if(maxLen == -1) {
            maxLen = Math.max(ctx.maxTempLength, ctx.maxOutputLength);
        }

		FetchException ex = null; // set on failure
		try {
			if(returnBucket == null) finalResult = context.getBucketFactory(persistent()).makeBucket(maxLen);
			else finalResult = returnBucket;
			if(logMINOR) Logger.minor(this, "Writing final data to "+finalResult+" return bucket is "+returnBucket);
			dataOutput .connect(dataInput);
			result = new FetchResult(clientMetadata, finalResult);

			// Decompress
			if(decompressors != null) {
				if(logMINOR) Logger.minor(this, "Decompressing...");
				decompressorManager =  new DecompressorThreadManager(dataInput, decompressors, maxLen);
				dataInput = decompressorManager.execute();
			}

			output = finalResult.getOutputStream();
			if(ctx.overrideMIME != null) mimeType = ctx.overrideMIME;
			worker = new ClientGetWorkerThread(new BufferedInputStream(dataInput), output, uri, mimeType, ctx.getSchemeHostAndPort(), hashes, ctx.filterData, ctx.charset, ctx.prefetchHook, ctx.tagReplacer, context.linkFilterExceptionProvider);
			worker.start();
			try {
				streamGenerator.writeTo(dataOutput, context);
			} catch(IOException e) {
				//Check if the worker thread caught an exception
				worker.getError();
				//If not, throw the original error
				throw e;
			}

			// An error will propagate backwards, so wait for the worker first.

			if(logMINOR) Logger.minor(this, "Waiting for hashing, filtration, and writing to finish");
			worker.waitFinished();

			if(decompressorManager != null) {
				if(logMINOR) Logger.minor(this, "Waiting for decompression to finalize");
				decompressorManager.waitFinished();
			}

			if(worker.getClientMetadata() != null) {
				clientMetadata = worker.getClientMetadata();
				result = new FetchResult(clientMetadata, finalResult);
			}
			// These must be updated for ClientGet.
			synchronized(this) {
			    this.expectedMIME = result.getMimeType();
			    this.expectedSize = result.size();
			}
		} catch(UnsafeContentTypeException e) {
			Logger.normal(this, "Error filtering content: will not validate", e);
			ex = e.createFetchException(ctx.overrideMIME != null ? ctx.overrideMIME : expectedMIME, expectedSize);
			/*Not really the state's fault*/
		} catch(URISyntaxException e) {
			//Impossible
			Logger.error(this, "URISyntaxException converting a FreenetURI to a URI!: "+e, e);
			ex = new FetchException(FetchExceptionMode.INTERNAL_ERROR, e);
			/*Not really the state's fault*/
		} catch(CompressionOutputSizeException e) {
			Logger.error(this, "Caught "+e, e);
			ex = new FetchException(FetchExceptionMode.TOO_BIG, e);
		} catch (InsufficientDiskSpaceException e) {
		    ex = new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE);
		} catch(IOException e) {
			Logger.error(this, "Caught "+e, e);
			ex = new FetchException(FetchExceptionMode.BUCKET_ERROR, e);
		} catch(FetchException e) {
			Logger.error(this, "Caught "+e, e);
			ex = e;
		} catch(Throwable t) {
			Logger.error(this, "Caught "+t, t);
			ex = new FetchException(FetchExceptionMode.INTERNAL_ERROR, t);
		} finally {
			Closer.close(dataInput);
			Closer.close(dataOutput);
			Closer.close(output);
		}
		if(ex != null) {
			onFailure(ex, state, context, true);
			if(finalResult != null && finalResult != returnBucket) {
				finalResult.free();
			}
			if(result != null) {
			Bucket data = result.asBucket();
			data.free();
			}
			return;
		}
		context.getJobRunner(persistent()).setCheckpointASAP();
		clientCallback.onSuccess(result, ClientGetter.this);
	}

    @Override
    public void onSuccess(File tempFile, long length, ClientMetadata metadata,
            ClientGetState state, ClientContext context) {
        context.uskManager.checkUSK(uri, persistent(), false);
        try {
            if (binaryBlobWriter != null && !dontFinalizeBlobWriter) binaryBlobWriter.finalizeBucket();
        } catch (IOException ioe) {
            onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, "Failed to close binary blob stream: "+ioe), null, context);
            return;
        } catch (BinaryBlobAlreadyClosedException e) {
            onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, "Failed to close binary blob stream, already closed: "+e, e), null, context);
            return;
        }
        File completionFile = getCompletionFile();
        assert(completionFile != null);
        assert(!ctx.filterData);
        Logger.normal(this, "Succeeding via truncation from "+tempFile+" to "+completionFile);
        FetchException ex = null;
        RandomAccessFile raf = null;
        FetchResult result = null;
        try {
            raf = new RandomAccessFile(tempFile, "rw");
            if(raf.length() < length)
                throw new IOException("File is shorter than target length "+length);
            raf.setLength(length);
            InputStream is = new BufferedInputStream(new FileInputStream(raf.getFD()));
            // Check hashes...

            DecompressorThreadManager decompressorManager = null;
            ClientGetWorkerThread worker = null;

            worker = new ClientGetWorkerThread(is, new NullOutputStream(), uri, null, ctx.getSchemeHostAndPort(), hashes, false, null, ctx.prefetchHook, ctx.tagReplacer, context.linkFilterExceptionProvider);
            worker.start();

            if(logMINOR) Logger.minor(this, "Waiting for hashing, filtration, and writing to finish");
            worker.waitFinished();

            is.close();
            is = null;
            raf = null; // FD is closed.

            // We are still here so it worked.

            if(!FileUtil.renameTo(tempFile, completionFile))
                throw new FetchException(FetchExceptionMode.BUCKET_ERROR, "Failed to rename from temp file "+tempFile);

            // Success!

            synchronized(this) {
                finished = true;
                currentState = null;
                expectedMIME = metadata.getMIMEType();
                expectedSize = length;
            }

            result = new FetchResult(metadata, returnBucket);

        } catch (IOException e) {
            Logger.error(this, "Failed while completing via truncation: "+e, e);
            ex = new FetchException(FetchExceptionMode.BUCKET_ERROR, e);
        } catch (URISyntaxException e) {
            Logger.error(this, "Impossible failure while completing via truncation: "+e, e);
            ex = new FetchException(FetchExceptionMode.INTERNAL_ERROR, e);
        } catch(FetchException e) {
            // Hashes failed.
            Logger.error(this, "Caught "+e, e);
            ex = e;
        } catch (Throwable e) {
            Logger.error(this, "Failed while completing via truncation: "+e, e);
            ex = new FetchException(FetchExceptionMode.INTERNAL_ERROR, e);
        }
        if(ex != null) {
            onFailure(ex, state, context, true);
            if(raf != null)
                try {
                    raf.close();
                } catch (IOException e) {
                    // Ignore.
                }
            tempFile.delete();
        } else {
            context.getJobRunner(persistent()).setCheckpointASAP();
            clientCallback.onSuccess(result, ClientGetter.this);
        }
    }

	/**
	 * Called when the request fails. Retrying will have already been attempted by the calling state, if
	 * appropriate; we have tried to get the data, and given up.
	 * @param e The reason for failure, in the form of a FetchException.
	 * @param state The failing state.
	 */
	@Override
	public void onFailure(FetchException e, ClientGetState state, ClientContext context) {
		onFailure(e, state, context, false);
	}

	/**
	 * Internal version. Adds one parameter.
	 * @param force If true, finished may already have been set. This is usually
	 * set when called from onSuccess after it has set finished = true.
	 */
	public void onFailure(FetchException e, ClientGetState state, ClientContext context, boolean force) {
		if(logMINOR)
			Logger.minor(this, "Failed from "+state+" : "+e+" on "+this, e);
		ClientGetState oldState = null;
		if(expectedSize > 0 && (e.expectedSize <= 0 || finalBlocksTotal != 0))
			e.expectedSize = expectedSize;

		context.getJobRunner(persistent()).setCheckpointASAP();

		if(e.mode == FetchExceptionMode.TOO_BIG && ctx.filterData) {
			// Check for MIME type issues first. Because of the filtering behaviour the user needs to see these first.
			if(e.finalizedSize()) {
				// Since the size is finalized, so must the MIME type be.
				String mime = e.getExpectedMimeType();
				if(ctx.overrideMIME != null)
					mime = ctx.overrideMIME;
				if(mime != null && !"".equals(mime)) {
					// Even if it's the default, it is set because we have the final size.
					UnsafeContentTypeException unsafe = ContentFilter.checkMIMEType(mime);
					if(unsafe != null) {
						e = unsafe.recreateFetchException(e, mime);
					}
				}
			}
		}

		while(true) {
			if(e.mode == FetchExceptionMode.ARCHIVE_RESTART) {
				int ar;
				synchronized(this) {
					archiveRestarts++;
					ar = archiveRestarts;
				}
				if(logMINOR)
					Logger.minor(this, "Archive restart on "+this+" ar="+ar);
				if(ar > ctx.maxArchiveRestarts)
					e = new FetchException(FetchExceptionMode.TOO_MANY_ARCHIVE_RESTARTS);
				else {
					try {
						start(context);
					} catch (FetchException e1) {
						e = e1;
						continue;
					}
					return;
				}
			}
			boolean alreadyFinished = false;
			synchronized(this) {
				if(finished && !force) {
					if(!cancelled)
						Logger.error(this, "Already finished - not calling callbacks on "+this, new Exception("error"));
					alreadyFinished = true;
				}
				finished = true;
				oldState = currentState;
				currentState = null;
				String mime = e.getExpectedMimeType();
				if(mime != null)
				    this.expectedMIME = mime;
			}
			if(!alreadyFinished) {
				try {
					if (binaryBlobWriter != null && !dontFinalizeBlobWriter) binaryBlobWriter.finalizeBucket();
				} catch (IOException ioe) {
					// the request is already failed but fblob creation failed too
					// the invalid fblob must be told, more important then an valid but incomplete fblob (ADNF for example)
					if(e.mode != FetchExceptionMode.CANCELLED && !force)
						e = new FetchException(FetchExceptionMode.BUCKET_ERROR, "Failed to close binary blob stream: "+ioe);
				} catch (BinaryBlobAlreadyClosedException ee) {
					if(e.mode != FetchExceptionMode.BUCKET_ERROR && e.mode != FetchExceptionMode.CANCELLED && !force)
						e = new FetchException(FetchExceptionMode.BUCKET_ERROR, "Failed to close binary blob stream, already closed: "+ee, ee);
				}
			}
			if(e.errorCodes != null && e.errorCodes.isOneCodeOnly())
				e = new FetchException(e.errorCodes.getFirstCodeFetch());
			if(e.mode == FetchExceptionMode.DATA_NOT_FOUND && super.successfulBlocks > 0)
				e = new FetchException(e, FetchExceptionMode.ALL_DATA_NOT_FOUND);
			if(logMINOR) Logger.minor(this, "onFailure("+e+", "+state+") on "+this+" for "+uri, e);
			final FetchException e1 = e;
			if(!alreadyFinished)
				clientCallback.onFailure(e1, ClientGetter.this);
			return;
		}
	}

	/**
	 * Cancel the request. This must result in onFailure() being called in order to
	 * send the client a cancel FetchException, and to removeFrom() the state.
	 */
	@Override
	public void cancel(ClientContext context) {
		if(logMINOR) Logger.minor(this, "Cancelling "+this, new Exception("debug"));
		ClientGetState s;
		synchronized(this) {
			if(super.cancel()) {
				if(logMINOR) Logger.minor(this, "Already cancelled "+this);
				return;
			}
			s = currentState;
		}
		if(s != null) {
			if(logMINOR) Logger.minor(this, "Cancelling "+s+" for "+this+" instance "+super.toString());
			s.cancel(context);
		} else {
			if(logMINOR) Logger.minor(this, "Nothing to cancel");
		}
	}

	/** Has the fetch completed? */
	@Override
	public synchronized boolean isFinished() {
		return finished || cancelled;
	}

	/** What was the URI we were fetching? */
	@Override
	public FreenetURI getURI() {
		return uri;
	}

	/**
	 * Notify clients listening to our ClientEventProducer of the current progress, in the form of a
	 * SplitfileProgressEvent.
	 */
	@Override
	protected void innerNotifyClients(ClientContext context) {
	    SplitfileProgressEvent e;
	    synchronized(this) {
	        int total = this.totalBlocks;
	        int minSuccess = this.minSuccessBlocks;
	        boolean finalized = blockSetFinalized;
	        if(this.finalBlocksRequired != 0) {
	            total = finalBlocksTotal;
	            minSuccess = finalBlocksRequired;
	            finalized = true;
	        }
	        e = new SplitfileProgressEvent(total,
	            this.successfulBlocks,
	            this.latestSuccess,
	            this.failedBlocks,
	            this.fatallyFailedBlocks,
	            this.latestFailure,
	            minSuccess,
	            0,
	            finalized);
	    }
	    // Already off-thread.
		ctx.eventProducer.produceEvent(e, context);
	}

	/**
	 * Notify clients that some part of the request has been sent to the network i.e. we have finished
	 * checking the datastore for at least some part of the request. Sent once only for any given request.
	 */
	@Override
	protected void innerToNetwork(ClientContext context) {
	    context.getJobRunner(persistent()).queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                ctx.eventProducer.produceEvent(new SendingToNetworkEvent(), context);
                return false;
            }

	    });
	}

	/**
	 * Called when no more blocks will be added to the total, and therefore we can confidently display a
	 * percentage for the overall progress. Will notify clients with a SplitfileProgressEvent.
	 */
	@Override
	public void onBlockSetFinished(ClientGetState state, ClientContext context) {
		if(logMINOR)
			Logger.minor(this, "Set finished", new Exception("debug"));
		blockSetFinalized(context);
	}

	/**
	 * Called when the current state creates a new state and we switch to that. For example, a
	 * SingleFileFetcher might switch to a SplitFileFetcher. Sometimes this will be called with oldState
	 * not equal to our currentState; this means that a subsidiary request has changed state, so we
	 * ignore it.
	 */
	@Override
	public void onTransition(ClientGetState oldState, ClientGetState newState, ClientContext context) {
		synchronized(this) {
			if(currentState == oldState) {
				currentState = newState;
				if(logMINOR) Logger.minor(this, "Transition: "+oldState+" -> "+newState+" on "+this+" persistent = "+persistent()+" instance = "+super.toString(), new Exception("debug"));
			} else {
				if(logMINOR) Logger.minor(this, "Ignoring transition: "+oldState+" -> "+newState+" because current = "+currentState+" on "+this+" persistent = "+persistent(), new Exception("debug"));
				return;
			}
		}
		if(persistent())
		    context.jobRunner.setCheckpointASAP();
	}

	/**
	 * Can the request be restarted?
	 */
	public boolean canRestart() {
		if(currentState != null && !finished) {
			if(logMINOR) Logger.minor(this, "Cannot restart because not finished for "+uri);
			return false;
		}
		return true;
	}

	/**
	 * Restart the request.
	 * @param redirect Use this URI instead of the old one.
	 * @param filterData
	 * @param context The database. We must be on the database thread! See ClientContext for convenience
	 * methods.
	 * @return True if we successfully restarted, false if we can't restart.
	 * @throws FetchException If something went wrong.
	 */
	public boolean restart(FreenetURI redirect, boolean filterData, ClientContext context) throws FetchException {
		ctx.filterData = filterData;
		return start(true, redirect, context);
	}

	@Override
	public String toString() {
		return super.toString();
	}

	// FIXME not persisting binary blob stuff - any stream won't survive shutdown...

	/**
	 * Add a block to the binary blob.
	 */
	protected void addKeyToBinaryBlob(ClientKeyBlock block, ClientContext context) {
		if(binaryBlobWriter == null) return;
		synchronized(this) {
		    if(finished) {
		        if(logMINOR) Logger.minor(this, "Add key to binary blob for "+this+" but already finished");
		        return;
		    }
		}
		if(logMINOR)
			Logger.minor(this, "Adding key "+block.getClientKey().getURI()+" to "+this, new Exception("debug"));
		try {
			binaryBlobWriter.addKey(block, context);
		} catch (IOException e) {
			Logger.error(this, "Failed to write key to binary blob stream: "+e, e);
			onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, "Failed to write key to binary blob stream: "+e), null, context);
		} catch (BinaryBlobAlreadyClosedException e) {
			Logger.error(this, "Failed to write key to binary blob stream (already closed??): "+e, e);
			onFailure(new FetchException(FetchExceptionMode.BUCKET_ERROR, "Failed to write key to binary blob stream (already closed??): "+e), null, context);
		}
	}

	/** Are we collecting a binary blob? */
	protected boolean collectingBinaryBlob() {
		return binaryBlobWriter != null;
	}

	/** Called when we know the MIME type of the final data
	 * @throws FetchException */
	@Override
	public void onExpectedMIME(ClientMetadata clientMetadata, ClientContext context) throws FetchException {
		if(finalizedMetadata) return;
		String mime = null;
		if(!clientMetadata.isTrivial())
			mime = clientMetadata.getMIMEType();
		if(ctx.overrideMIME != null)
			mime = ctx.overrideMIME;
		if(mime == null || mime.equals("")) return;
        synchronized(this) {
            expectedMIME = mime;
        }
		if(ctx.filterData) {
			UnsafeContentTypeException e = ContentFilter.checkMIMEType(mime);
			if(e != null) {
				throw e.createFetchException(mime, expectedSize);
			}
			if(forceCompatibleExtension != null)
				checkCompatibleExtension(mime);
		}
		context.getJobRunner(persistent()).queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                String mime;
                synchronized(this) {
                    mime = expectedMIME;
                }
                ctx.eventProducer.produceEvent(new ExpectedMIMEEvent(mime), context);
                return false;
            }

		});
	}

	private void checkCompatibleExtension(String mimeType) throws FetchException {
		FilterMIMEType type = ContentFilter.getMIMEType(mimeType);
		if(type == null)
			// Not our problem, will be picked up elsewhere.
			return;
		if(!DefaultMIMETypes.isValidExt(mimeType, forceCompatibleExtension))
			throw new FetchException(FetchExceptionMode.MIME_INCOMPATIBLE_WITH_EXTENSION);
	}

	/** Called when we have some idea of the length of the final data */
	@Override
	public void onExpectedSize(final long size, ClientContext context) {
		if(finalizedMetadata) return;
		if(finalBlocksRequired != 0) return;
		expectedSize = size;
		context.getJobRunner(persistent()).queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                ctx.eventProducer.produceEvent(new ExpectedFileSizeEvent(size), context);
                return false;
            }

		});
	}

	/** Called when we are fairly sure that the expected MIME and size won't change */
	@Override
	public void onFinalizedMetadata() {
		finalizedMetadata = true;
	}

	/** Are we sure the expected MIME and size won't change? */
	public boolean finalizedMetadata() {
		return finalizedMetadata;
	}

	/** @return The expected MIME type, if we know it. */
	public synchronized String expectedMIME() {
	    return expectedMIME;
	}

	/** @return The expected size of the returned data, if we know it. Could change. */
	public synchronized long expectedSize() {
	    return expectedSize;
	}

	/** @return The callback to be notified when we complete the request. */
	public ClientGetCallback getClientCallback() {
		return clientCallback;
	}

	/** Get the metadata snoop callback */
	public SnoopMetadata getMetaSnoop() {
		return snoopMeta;
	}

	/** Set a callback to snoop on metadata during fetches. Call this before
	 * starting the request. */
	public SnoopMetadata setMetaSnoop(SnoopMetadata newSnoop) {
		SnoopMetadata old = snoopMeta;
		snoopMeta = newSnoop;
		return old;
	}

	/** Get the intermediate data snoop callback */
	public SnoopBucket getBucketSnoop() {
		return snoopBucket;
	}

	/** Set a callback to snoop on buckets (all intermediary data - metadata, containers) during fetches.
	 * Call this before starting the request. */
	public SnoopBucket setBucketSnoop(SnoopBucket newSnoop) {
		SnoopBucket old = snoopBucket;
		snoopBucket = newSnoop;
		return old;
	}

	private int finalBlocksRequired;
	private int finalBlocksTotal;

	@Override
	public void onExpectedTopSize(long size, long compressed, int blocksReq, int blocksTotal, ClientContext context) {
		if(finalBlocksRequired != 0 || finalBlocksTotal != 0) return;
		if(logMINOR) Logger.minor(this, "New format metadata has top data: original size "+size+" (compressed "+compressed+") blocks "+blocksReq+" / "+blocksTotal);
		onExpectedSize(size, context);
		this.finalBlocksRequired = this.minSuccessBlocks + blocksReq;
		this.finalBlocksTotal = this.totalBlocks + blocksTotal;
		notifyClients(context);
	}

	@Override
	public void onSplitfileCompatibilityMode(final CompatibilityMode min,
	        final CompatibilityMode max, final byte[] customSplitfileKey,
	        final boolean dontCompress, final boolean bottomLayer, final boolean definitiveAnyway,
	        ClientContext context) {
	    context.getJobRunner(persistent()).queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                ctx.eventProducer.produceEvent(new SplitfileCompatibilityModeEvent(min, max, customSplitfileKey, dontCompress, bottomLayer || definitiveAnyway), context);
                return false;
            }

	    });
	}

	@Override
	public void onHashes(HashResult[] hashes, ClientContext context) {
		synchronized(this) {
			if(this.hashes != null) {
				if(!HashResult.strictEquals(hashes, this.hashes))
					Logger.error(this, "Two sets of hashes?!");
				return;
			}
			this.hashes = hashes;
		}
		HashResult[] clientHashes = hashes;
		if(persistent()) clientHashes = HashResult.copy(hashes);
		final HashResult[] h = clientHashes;
		context.getJobRunner(persistent()).queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                ctx.eventProducer.produceEvent(new ExpectedHashesEvent(h), context);
                return false;
            }

		});
	}

	@Override
	public void enterCooldown(ClientGetState state, long wakeupTime, ClientContext context) {
	    synchronized(this) {
	        if(state != currentState) return;
	    }
		if(wakeupTime == Long.MAX_VALUE) {
			// Ignore.
			// FIXME implement when implement clearCooldown().
			// It means everything that can be started has been started.
		} else {
		    // Already off-thread.
			ctx.eventProducer.produceEvent(new EnterFiniteCooldownEvent(wakeupTime), context);
		}
	}

	@Override
	public void clearCooldown(ClientGetState state) {
		// Ignore for now. FIXME.
	}

	public Bucket getBlobBucket() {
		return binaryBlobWriter.getFinalBucket();
	}

    public byte[] getClientDetail(ChecksumChecker checker) throws IOException {
        if(clientCallback instanceof PersistentClientCallback) {
            return getClientDetail((PersistentClientCallback)clientCallback, checker);
        } else
            return new byte[0];
    }

    /** Called for a persistent request after startup.
     * @throws ResumeFailedException */
    @Override
    public void innerOnResume(ClientContext context) throws ResumeFailedException {
        super.innerOnResume(context);
        if(currentState != null)
            try {
                currentState.onResume(context);
            } catch (FetchException e) {
                currentState = null;
                Logger.error(this, "Failed to resume: "+e, e);
                throw new ResumeFailedException(e);
            } catch (RuntimeException e) {
                // Severe serialization problems, lost a class silently etc.
                Logger.error(this, "Failed to resume: "+e, e);
                throw new ResumeFailedException(e);
            }
        // returnBucket is responsibility of the callback.
        notifyClients(context);
    }

    @Override
    protected ClientBaseCallback getCallback() {
        return clientCallback;
    }

    /** If the request is simple, e.g. a single, final splitfile fetch, then write enough
     * information to continue the request. Otherwise write a marker indicating that this is not
     * true, and return false. We don't need to write the expected MIME type, hashes etc, as the
     * caller will write them.
     * @throws IOException
     */
    public boolean writeTrivialProgress(DataOutputStream dos) throws IOException {
        if(!(this.binaryBlobWriter == null && this.snoopBucket == null && this.snoopMeta == null && initialMetadata == null)) {
            dos.writeBoolean(false);
            return false;
        }
        ClientGetState state = null;
        synchronized(this) {
            state = currentState;
        }
        if(state == null || !(state instanceof SplitFileFetcher)) {
            dos.writeBoolean(false);
            return false;
        }
        SplitFileFetcher fetcher = (SplitFileFetcher) state;
        if(fetcher.cb != this) {
            dos.writeBoolean(false);
            return false;
        }
        return ((SplitFileFetcher)state).writeTrivialProgress(dos);
    }

    public boolean resumeFromTrivialProgress(DataInputStream dis, ClientContext context) throws IOException {
        if(dis.readBoolean()) {
            try {
                currentState = new SplitFileFetcher(this, dis, context);
                resumedFetcher = true;
                return true;
            } catch (StorageFormatException e) {
                Logger.error(this, "Failed to restore from splitfile, restarting: "+e, e);
                return false;
            } catch (ResumeFailedException e) {
                Logger.error(this, "Failed to restore from splitfile, restarting: "+e, e);
                return false;
            } catch (IOException e) {
                Logger.error(this, "Failed to restore from splitfile, restarting: "+e, e);
                return false;
            }
        } else return false;
    }

    public boolean resumedFetcher() {
        return resumedFetcher;
    }

    @Override
    public void onShutdown(ClientContext context) {
        ClientGetState state;
        synchronized(this) {
            state = currentState;
        }
        if(state != null)
            state.onShutdown(context);
    }

    @Override
    public boolean isCurrentState(ClientGetState state) {
        synchronized(this) {
            return currentState == state;
        }
    }

    @Override
    public File getCompletionFile() {
        if(returnBucket == null) return null;
        if(!(returnBucket instanceof FileBucket)) return null;
        // Just a plain FileBucket. Not a temporary, not delayed free, etc.
        return ((FileBucket)returnBucket).getFile();
    }
}
