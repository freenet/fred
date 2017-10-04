package freenet.client.async;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.util.List;

import freenet.client.ClientMetadata;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.client.Metadata;
import freenet.client.MetadataParseException;
import freenet.crypt.CRCChecksumChecker;
import freenet.crypt.ChecksumChecker;
import freenet.crypt.ChecksumFailedException;
import freenet.keys.ClientCHKBlock;
import freenet.keys.FreenetURI;
import freenet.node.BaseSendableGet;
import freenet.support.Logger;
import freenet.support.api.LockableRandomAccessBuffer;
import freenet.support.compress.Compressor.COMPRESSOR_TYPE;
import freenet.support.io.BucketTools;
import freenet.support.io.InsufficientDiskSpaceException;
import freenet.support.io.PooledFileRandomAccessBuffer;
import freenet.support.io.ResumeFailedException;
import freenet.support.io.StorageFormatException;

/** Splitfile fetcher based on keeping as much state as possible, and in particular the downloaded blocks,
 * in a single file.
 * 
 * The main goals here are:
 * 1) Minimising disk seeks. E.g. in the older versions we abstracted out block storage, this 
 * caused a lot of unnecessary seeking and copying. It's better to keep the downloaded data close 
 * together on disk. 
 * 2) Robustness. This should be robust even against moderate levels of on-disk data corruption. 
 * And it's separate for each splitfile. And it has fixed disk usage, until it completes. Some of 
 * this robustness violates layering e.g. checking blocks against the CHKs they are supposed to 
 * represent. This actually simplifies matters e.g. when decoding a segment, and allows us to not 
 * only recover from almost any error (at least in the parts that change, which are most likely to 
 * be corrupted), but also to do so efficiently.
 * 
 * The SplitFileFetcher*Storage classes manage storing the data and FEC decoding. This class deals 
 * with everything else: The interface to the rest of the client layer, selection of keys to fetch, 
 * listening for blocks, etc.
 * 
 * PERSISTENCE ROADMAP:
 * Now: Currently this class does not support persistence.
 * 
 * Near future goal: Support persistence within the database. Stay in memory, do not deactivate.
 * Store this class in the database but not its *Storage classes. Load the SplitFileFetcherStorage 
 * on loading Freenet, resuming existing downloads.
 * => Significant improvement in reliability and disk I/O. In principle we could resume downloads
 * separately from the database e.g. if it breaks. Too complicated in practice because of other
 * data structures.
 * - Require: Add "persistence", hashCode, force no deactivation, activate where necessary (when
 * dealing with other stuff). Fill in context and load storage when activated on startup.
 * 
 * Longer term goal: Implement similar code for inserts. Eliminate db4o and persist everything that
 * remains with simple checkpointed serialisation.
 * 
 * LOCKING: (this) should be taken last, because it is used by e.g. SplitFileFetcherGet.isCancelled().
 * 
 * @author toad
 */
public class SplitFileFetcher implements ClientGetState, SplitFileFetcherStorageCallback, Serializable {
    
    private static final long serialVersionUID = 1L;
    private static volatile boolean logMINOR;
    static {
        Logger.registerClass(SplitFileFetcher.class);
    }

    /** Stores the progress of the download, including the actual data, in a separate file. 
     * Created in onResume() or in the constructor, so must be volatile. */
    private transient volatile SplitFileFetcherStorage storage;
    /** Kept here so we can resume from storage */
    private LockableRandomAccessBuffer raf;
    final ClientRequester parent;
    final GetCompletionCallback cb;
    /** If non-null, we will complete via truncation. */
    final FileGetCompletionCallback callbackCompleteViaTruncation;
    /** If non-null, this is the temporary file we have allocated for completion via truncation.
     * The download will be stored in this file until it is complete, at which point the storage
     * will truncate it and we will feed it to the callback. */
    final File fileCompleteViaTruncation;
    final boolean realTimeFlag;
    final FetchContext blockFetchContext;
    final long token;
    /** Storage doesn't have a ClientContext so we need one here. */
    private transient ClientContext context;
    /** Does the actual requests. 
     * Created in onResume() or in the constructor, so must be volatile. */
    private transient volatile SplitFileFetcherGet getter;
    private boolean failed;
    private boolean succeeded;
    private final boolean wantBinaryBlob;
    private final boolean persistent;
    
    public SplitFileFetcher(Metadata metadata, GetCompletionCallback rcb, ClientRequester parent,
            FetchContext fetchContext, boolean realTimeFlag, List<COMPRESSOR_TYPE> decompressors, 
            ClientMetadata clientMetadata, long token, boolean topDontCompress, 
            short topCompatibilityMode, boolean persistent, FreenetURI thisKey, boolean isFinalFetch,
            ClientContext context) 
            throws FetchException, MetadataParseException {
        this.persistent = persistent;
        this.cb = rcb;
        this.parent = parent;
        this.realTimeFlag = realTimeFlag;
        this.token = token;
        this.context = context;
        if(parent instanceof ClientGetter) {
            wantBinaryBlob = ((ClientGetter)parent).collectingBinaryBlob();
        } else {
            wantBinaryBlob = false;
        }
        blockFetchContext = new FetchContext(fetchContext, FetchContext.SPLITFILE_DEFAULT_BLOCK_MASK, true, null);
        if(parent.isCancelled())
            throw new FetchException(FetchExceptionMode.CANCELLED);
        
        try {
            // Completion via truncation.
            if(isFinalFetch && cb instanceof FileGetCompletionCallback && 
                    (decompressors == null || decompressors.size() == 0) &&
                    !fetchContext.filterData) {
                FileGetCompletionCallback fileCallback = ((FileGetCompletionCallback)cb);
                File targetFile = fileCallback.getCompletionFile();
                if(targetFile != null) {
                    callbackCompleteViaTruncation = fileCallback;
                    fileCompleteViaTruncation = File.createTempFile(targetFile.getName(), ".freenet-tmp", targetFile.getParentFile());
                    // Storage must actually create the RAF since it knows the length.
                } else {
                    callbackCompleteViaTruncation = null;
                    fileCompleteViaTruncation = null;
                }
            } else {
                callbackCompleteViaTruncation = null;
                fileCompleteViaTruncation = null;
            }
            // Construct the storage.
            ChecksumChecker checker = new CRCChecksumChecker();
            storage = new SplitFileFetcherStorage(metadata, this, decompressors, clientMetadata, 
                    topDontCompress, topCompatibilityMode, fetchContext, getSalter(),
                    thisKey, parent.getURI(), isFinalFetch, parent.getClientDetail(checker), 
                    context.random, context.tempBucketFactory, 
                    persistent ? context.persistentRAFFactory : context.tempRAFFactory, 
                    persistent ? context.jobRunner : context.dummyJobRunner, 
                    context.ticker, context.memoryLimitedJobRunner, checker, persistent,
                    fileCompleteViaTruncation, context.getFileRandomAccessBufferFactory(persistent), 
                    context.getChkFetchScheduler(realTimeFlag).fetchingKeys());
        } catch (InsufficientDiskSpaceException e) {
            throw new FetchException(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE);
        } catch (IOException e) {
            Logger.error(this, "Failed to start splitfile fetcher because of disk I/O error?: "+e, e);
            throw new FetchException(FetchExceptionMode.BUCKET_ERROR, e);
        }
        long eventualLength = Math.max(storage.decompressedLength, metadata.uncompressedDataLength());
        cb.onExpectedSize(eventualLength, context);
        if(metadata.uncompressedDataLength() > 0)
            cb.onFinalizedMetadata();
        if(eventualLength > 0 && fetchContext.maxOutputLength > 0 && eventualLength > fetchContext.maxOutputLength)
            throw new FetchException(FetchExceptionMode.TOO_BIG, eventualLength, true, clientMetadata.getMIMEType());
        getter = new SplitFileFetcherGet(this, storage);
        raf = storage.getRAF();
        if(logMINOR)
            Logger.minor(this, "Created "+(persistent?"persistent" : "transient")+" download for "+
                    thisKey+" on "+raf+" for "+this);
        lastNotifiedStoreFetch = System.currentTimeMillis();
    }
    
    protected SplitFileFetcher() {
        // For serialization.
        parent = null;
        cb = null;
        realTimeFlag = false;
        blockFetchContext = null;
        token = 0;
        wantBinaryBlob = false;
        persistent = true;
        callbackCompleteViaTruncation = null;
        fileCompleteViaTruncation = null;
    }

    @Override
    public void schedule(ClientContext context) {
        if(storage.start(false))
            getter.schedule(context, false);
    }
    
    /** Fail the whole splitfile request when we get an IOException on writing to or reading from 
     * the on-disk storage. Can be called asynchronously by SplitFileFetcher*Storage if an 
     * off-thread job (e.g. FEC decoding) breaks, or may be called when SplitFileFetcher*Storage
     * throws.
     * @param e The IOException, generated when accessing the on-disk storage.
     */
    @Override
    public void failOnDiskError(IOException e) {
        fail(new FetchException(FetchExceptionMode.BUCKET_ERROR));
    }
    
    /** Fail the whole splitfile request when we get unrecoverable data corruption, e.g. can't 
     * read the keys. FIXME ROBUSTNESS in some cases this could actually be recovered by 
     * restarting from the metadata or the original URI. */
    @Override
    public void failOnDiskError(ChecksumFailedException e) {
        fail(new FetchException(FetchExceptionMode.BUCKET_ERROR));
    }
    
    public void fail(FetchException e) {
        synchronized(this) {
            if(succeeded || failed) return;
            failed = true;
        }
        if(storage != null)
            context.getChkFetchScheduler(realTimeFlag).removePendingKeys(storage.keyListener, true);
        if(getter != null)
            getter.cancel(context);
        if(storage != null)
            storage.cancel();
        cb.onFailure(e, this, context);
    }

    @Override
    public void cancel(ClientContext context) {
        fail(new FetchException(FetchExceptionMode.CANCELLED));
    }

    @Override
    public long getToken() {
        return token;
    }

    /** The splitfile download succeeded. Generate a stream and send it to the 
     * GetCompletionCallback. See bug #6063 for a better way that probably is too much complexity
     * for the benefit. */
    @Override
    public void onSuccess() {
        boolean fail = false;
        synchronized(this) {
            if(failed) {
                fail = true;
            } else {
                if(succeeded) {
                    Logger.error(this, "Called onSuccess() twice on "+this, new Exception("debug"));
                    return;
                } else {
                    if(logMINOR) Logger.minor(this, "onSuccess() on "+this, new Exception("debug"));
                }
                succeeded = true;
            }
        }
        if(fail) {
            storage.finishedFetcher();
            return;
        }
        context.getChkFetchScheduler(realTimeFlag).removePendingKeys(storage.keyListener, true);
        getter.cancel(context);
        if(this.callbackCompleteViaTruncation != null) {
            long finalLength = storage.finalLength;
            this.callbackCompleteViaTruncation.onSuccess(fileCompleteViaTruncation, 
                    finalLength, storage.clientMetadata, this, context);
            // Don't need to call storage.finishedFetcher().
        } else {
            cb.onSuccess(storage.streamGenerator(), storage.clientMetadata, storage.decompressors, 
                    this, context);
            storage.finishedFetcher();
        }
    }
    
    @Override
    public void onClosed() {
        // Don't need to do anything.
    }

    public short getPriorityClass() {
        return this.parent.getPriorityClass();
    }

    @Override
    public void setSplitfileBlocks(int requiredBlocks, int remainingBlocks) {
        parent.addMustSucceedBlocks(requiredBlocks);
        parent.addBlocks(remainingBlocks);
        parent.notifyClients(context);
    }

    @Override
    public void onSplitfileCompatibilityMode(CompatibilityMode min, CompatibilityMode max,
            byte[] customSplitfileKey, boolean compressed, boolean bottomLayer,
            boolean definitiveAnyway) {
        cb.onSplitfileCompatibilityMode(min, max, customSplitfileKey, compressed, bottomLayer, definitiveAnyway, context);
    }

    @Override
    public void queueHeal(byte[] data, byte[] cryptoKey, byte cryptoAlgorithm) {
        try {
            context.healingQueue.queue(BucketTools.makeImmutableBucket(context.tempBucketFactory, data), cryptoKey, cryptoAlgorithm, context);
        } catch (IOException e) {
            // Nothing to be done, but need to log the error.
            Logger.error(this, "I/O error, failed to queue healing block: "+e, e);
        }
    }

    public boolean localRequestOnly() {
        return blockFetchContext.localRequestOnly;
    }

    public void toNetwork() {
        parent.toNetwork(context);
    }

    public boolean hasFinished() {
        return failed || succeeded;
    }
    
    /** Incremented whenever we fetch a block from the store */
    private int storeFetchCounter;
    /** Time when we last passed through a block fetch from the store */
    private long lastNotifiedStoreFetch;
    static final int STORE_NOTIFY_BLOCKS = 100;
    static final long STORE_NOTIFY_INTERVAL = 200;

    @Override
    public void onFetchedBlock() {
        boolean dontNotify = true;
        if(getter.hasQueued()) {
            dontNotify = false;
        } else {
            synchronized(this) {
                if(storeFetchCounter++ == STORE_NOTIFY_BLOCKS) {
                    storeFetchCounter = 0;
                    dontNotify = false;
                    lastNotifiedStoreFetch = System.currentTimeMillis();
                } else {
                    long now = System.currentTimeMillis();
                    if(now - lastNotifiedStoreFetch >= STORE_NOTIFY_INTERVAL) {
                        dontNotify = false;
                        lastNotifiedStoreFetch = now;
                    }
                }
            }
        }
        parent.completedBlock(dontNotify, context);
    }

    @Override
    public void onFailedBlock() {
        parent.failedBlock(context);
    }
    
    @Override
    public void onResume(int succeededBlocks, int failedBlocks, ClientMetadata meta, long finalSize) {
        for(int i=0;i<succeededBlocks-1;i++)
            parent.completedBlock(true, context);
        if(succeededBlocks > 0)
            parent.completedBlock(false, context);
        for(int i=0;i<failedBlocks-1;i++)
            parent.failedBlock(true, context);
        if(failedBlocks > 0)
            parent.failedBlock(false, context);
        parent.blockSetFinalized(context);
        try {
            cb.onExpectedMIME(meta, context);
        } catch (FetchException e) {
            fail(e);
            return;
        }
        cb.onExpectedSize(finalSize, context);
    }

    @Override
    public void maybeAddToBinaryBlob(ClientCHKBlock block) {
        if(parent instanceof ClientGetter) {
            ((ClientGetter)parent).addKeyToBinaryBlob(block, context);
        }
    }

    @Override
    public boolean wantBinaryBlob() {
        return wantBinaryBlob;
    }

    @Override
    public BaseSendableGet getSendableGet() {
        return getter;
    }

    @Override
    public void restartedAfterDataCorruption() {
        if(hasFinished()) return;
        Logger.error(this, "Restarting download "+this+" after data corruption");
        // We need to fetch more blocks. Some of them may even be in the datastore.
        getter.unregister(context, getPriorityClass());
        getter.schedule(context, false);
        context.jobRunner.setCheckpointASAP();
    }

    @Override
    public void clearCooldown() {
        if(hasFinished()) return;
        getter.clearWakeupTime(context);
    }

    @Override
    public void reduceCooldown(long wakeupTime) {
        getter.reduceWakeupTime(wakeupTime, context);
    }

    @Override
    public HasKeyListener getHasKeyListener() {
        return getter;
    }

    @Override
    public void onResume(ClientContext context) throws FetchException {
        if(logMINOR) Logger.minor(this, "Restarting SplitFileFetcher from storage...");
        boolean resumed = parent instanceof ClientGetter && ((ClientGetter)parent).resumedFetcher();
        this.context = context;
        try {
            KeySalter salter = getSalter();
            raf.onResume(context);
            this.storage = new SplitFileFetcherStorage(raf, this, blockFetchContext,
                    context.random, context.jobRunner, 
                    context.getChkFetchScheduler(realTimeFlag).fetchingKeys(), context.ticker, 
                    context.memoryLimitedJobRunner, new CRCChecksumChecker(), 
                    context.jobRunner.newSalt(),
                    callbackCompleteViaTruncation != null);
        } catch (ResumeFailedException e) {
            raf.free();
            Logger.error(this, "Failed to resume storage file: "+e+" for "+raf, e);
            throw new FetchException(FetchExceptionMode.BUCKET_ERROR, e);
        } catch (IOException e) {
            raf.free();
            Logger.error(this, "Failed to resume due to I/O error: "+e+" raf = "+raf, e);
            throw new FetchException(FetchExceptionMode.BUCKET_ERROR, e);
        } catch (StorageFormatException e) {
            raf.free();
            Logger.error(this, "Failed to resume due to storage error: "+e+" raf = "+raf, e);
            throw new FetchException(FetchExceptionMode.INTERNAL_ERROR, "Resume failed: "+e, e);
        } catch (FetchException e) {
            raf.free();
            throw e;
        }
        synchronized(this) {
            lastNotifiedStoreFetch = System.currentTimeMillis();
        }
        getter = new SplitFileFetcherGet(this, storage);
        if (storage.start(resumed)) {
            getter.schedule(context, storage.hasCheckedStore());
        }
    }

    @Override
    public KeySalter getSalter() {
        return context.getChkFetchScheduler(realTimeFlag).getGlobalKeySalter(persistent);
    }

    public boolean writeTrivialProgress(DataOutputStream dos) throws IOException {
        boolean done = false;
        synchronized(this) {
            done = failed || succeeded;
        }
        if(done) {
            dos.writeBoolean(false);
            return false;
        }
        dos.writeBoolean(true);
        if(callbackCompleteViaTruncation == null) {
            dos.writeBoolean(false);
            raf.storeTo(dos);
        } else {
            dos.writeBoolean(true);
            dos.writeUTF(fileCompleteViaTruncation.toString());
            dos.writeLong(raf.size());
        }
        dos.writeLong(token);
        return true;
    }
    
    public SplitFileFetcher(ClientGetter getter, DataInputStream dis, ClientContext context) 
    throws StorageFormatException, ResumeFailedException, IOException {
        Logger.normal(this, "Resuming splitfile download for "+this);
        boolean completeViaTruncation = dis.readBoolean();
        if(completeViaTruncation) {
            fileCompleteViaTruncation = new File(dis.readUTF());
            if(!fileCompleteViaTruncation.exists())
                throw new ResumeFailedException("Storage file does not exist: "+fileCompleteViaTruncation);
            callbackCompleteViaTruncation = (FileGetCompletionCallback) getter;
            long rafSize = dis.readLong();
            if(fileCompleteViaTruncation.length() != rafSize)
                throw new ResumeFailedException("Storage file is not of the correct length");
            // FIXME check against finalLength too, maybe we can finish straight away.
            this.raf = new PooledFileRandomAccessBuffer(fileCompleteViaTruncation, false, rafSize, -1, true);
        } else {
            this.raf = BucketTools.restoreRAFFrom(dis, context.persistentFG, context.persistentFileTracker, context.getPersistentMasterSecret());
            fileCompleteViaTruncation = null;
            callbackCompleteViaTruncation = null;
        }
        this.parent = getter;
        this.cb = getter;
        this.persistent = true;
        this.realTimeFlag = parent.realTimeFlag();
        token = dis.readLong();
        this.blockFetchContext = getter.ctx;
        this.wantBinaryBlob = getter.collectingBinaryBlob();
        // onResume() will do the rest.
        Logger.normal(this, "Resumed splitfile download for "+this);
        lastNotifiedStoreFetch = System.currentTimeMillis();
    }

    @Override
    public void onShutdown(ClientContext context) {
        storage.onShutdown(context);
    }

}
