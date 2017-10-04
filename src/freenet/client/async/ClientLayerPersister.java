package freenet.client.async;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import freenet.clients.fcp.ClientRequest;
import freenet.clients.fcp.RequestIdentifier;
import freenet.crypt.CRCChecksumChecker;
import freenet.crypt.ChecksumChecker;
import freenet.crypt.ChecksumFailedException;
import freenet.node.DatabaseKey;
import freenet.node.MasterKeysWrongPasswordException;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.NodeInitException;
import freenet.node.RequestStarterGroup;
import freenet.support.Executor;
import freenet.support.Logger;
import freenet.support.Ticker;
import freenet.support.api.Bucket;
import freenet.support.io.DelayedFree;
import freenet.support.io.FileBucket;
import freenet.support.io.FileUtil;
import freenet.support.io.PersistentTempBucketFactory;
import freenet.support.io.PrependLengthOutputStream;
import freenet.support.io.StorageFormatException;
import freenet.support.io.TempBucketFactory;

import static java.util.concurrent.TimeUnit.MINUTES;

/** Top level of persistence mechanism for ClientRequest's (persistent downloads and uploads).
 * Note that we use three different persistence mechanisms here:
 * 1) Splitfile persistence. The downloaded data and all the status for a splitfile is kept in a 
 * single random access file (technically a LockableRandomAccessBuffer).
 * 2) Java persistence. The overall list of ClientRequest's is stored to client.dat using 
 * serialization, by this class.
 * 3) A simple binary fallback. For complicated requests this will just record enough information 
 * to restart the request, but for simple splitfile downloads, we can resume from (1).
 * 
 * The reason for this seemingly unnecessary complexity is:
 * 1) Robustness, even against (reasonable) data corruption (e.g. on writing frequently written 
 * parts of files), and against problems in serialization.
 * 2) Minimising disk I/O (particularly disk seeks), especially in splitfile fetches. Decoding a 
 * segment takes effectively a single read and a couple of writes, for example. 
 * 3) Allowing us to store all the important information about a download, including the downloaded
 * data and the status, in a temporary file close to where the final file will be saved. Then we 
 * can (if there is no compression or filtering) simply truncate the file to complete.
 * 
 * Also, most of the important global structures are kept in RAM and recreated after downloads are
 * read in. Notably ClientRequestScheduler/Selector, which keep a tree of requests to choose from,
 * and a set of Bloom filters to identify which blocks belong to which request (we won't always get
 * a block as the direct result of doing our own requests).
 * 
 * Please don't shove it all into a database without serious consideration of the performance and
 * reliability implications! One query per block is not feasible on typical end user hardware, and
 * disks aren't reliable. Losing all downloads when there is a one byte data corruption is 
 * unacceptable. And blocks should be kept close to where they are supposed to end up...
 * 
 * Note that inserts may be somewhat less robust than requests. This is intentional as inserts 
 * should be relatively short-lived or they won't be much use to anyone as the data will have 
 * fallen out.
 * 
 * SCHEMA MIGRATION: Note that changing classes that are Serializable can result in restarting 
 * downloads or losing uploads.
 * @author toad
 */
public class ClientLayerPersister extends PersistentJobRunnerImpl {
    
    static final long INTERVAL = MINUTES.toMillis(10);
    private final Node node; // Needed for bandwidth stats putter
    private final NodeClientCore clientCore;
    private final PersistentTempBucketFactory persistentTempFactory;
    /** Needed for temporary storage when writing objects. Some of them might be big, e.g. site 
     * inserts. */
    private final TempBucketFactory tempBucketFactory;
    private final PersistentStatsPutter bandwidthStatsPutter;
    private byte[] salt;
    private boolean newSalt;
    private final ChecksumChecker checker;

    // Can be set later ...
    private Bucket writeToBucket;
    private File writeToFilename;
    private File writeToBackupFilename;
    private File deleteAfterSuccessfulWrite;
    private File otherDeleteAfterSuccessfulWrite;
    private File dir;
    private String baseName;
    
    private static final long MAGIC = 0xd332925f3caf4aedL;
    private static final int VERSION = 1;
    
    private static volatile boolean logMINOR;
    static {
        Logger.registerClass(ClientLayerPersister.class);
    }
    
    /** Load everything.
     * @param persistentTempFactory Only passed in so that we can call its pre- and post- commit
     * hooks. We don't explicitly save it; it must be populated lazily in onResume() like 
     * everything else. */
    public ClientLayerPersister(Executor executor, Ticker ticker, Node node, NodeClientCore core,
            PersistentTempBucketFactory persistentTempFactory, TempBucketFactory tempBucketFactory,
            PersistentStatsPutter stats) {
        super(executor, ticker, INTERVAL);
        this.node = node;
        this.clientCore = core;
        this.persistentTempFactory = persistentTempFactory;
        this.tempBucketFactory = tempBucketFactory;
        this.checker = new CRCChecksumChecker();
        this.bandwidthStatsPutter = stats;
    }
    
    /** Set the files to write to and set up encryption
     * @param noWrite If true, don't write the data to disk at all, and delete existing 
     * client.dat*.
     * @throws MasterKeysWrongPasswordException If we need the encryption key but it has not been 
     * supplied. */
    public void setFilesAndLoad(File dir, String baseName, boolean writeEncrypted, boolean noWrite, 
            DatabaseKey encryptionKey, ClientContext context, RequestStarterGroup requestStarters, 
            Random random) throws MasterKeysWrongPasswordException {
        if(noWrite)
            super.disableWrite();
        synchronized(serializeCheckpoints) {
            this.dir = dir;
            this.baseName = baseName;
            if(noWrite) {
                writeToBucket = null;
                writeToFilename = null;
                writeToBackupFilename = null;
                deleteFile(dir, baseName, false, false);
                deleteFile(dir, baseName, false, true);
                deleteFile(dir, baseName, true, false);
                deleteFile(dir, baseName, true, true);
                onStarted(true);
                if(salt == null) {
                    salt = new byte[32];
                    random.nextBytes(salt);
                    requestStarters.setGlobalSalt(salt);
                }
            } else if(!hasLoaded()) {
                // Some serialization failures cause us to fail only at the point of scheduling the request.
                // So if that happens we need to retry with serialization turned off.
                // The requests that loaded fine already will not be affected as we check for duplicates.
                if(innerSetFilesAndLoad(false, dir, baseName, writeEncrypted, encryptionKey, context, 
                        requestStarters, random)) {
                    Logger.error(this, "Some requests failed to restart after serializing. Trying to recover/restart ...");
                    System.err.println("Some requests failed to restart after serializing. Trying to recover/restart ...");
                    innerSetFilesAndLoad(true, dir, baseName, writeEncrypted, encryptionKey, context, 
                            requestStarters, random);
                }
                onStarted(noWrite);
            } else {
                innerSetFilesOnly(dir, baseName, writeEncrypted, encryptionKey);
                onStarted(false);
            }
        }
    }
    
    private void deleteFile(File dir, String baseName, boolean backup, boolean encrypted) {
        File f = makeFilename(dir, baseName, backup, encrypted);
        try {
            FileUtil.secureDelete(f);
        } catch (IOException e) {
            f.delete();
            if(f.exists()) {
                System.err.println("Failed to delete "+f+" when setting maximum security level.");
                System.err.println("There may be traces on disk of your previous download queue.");
                // FIXME useralert???
            }
        }
    }

    private void innerSetFilesOnly(File dir, String baseName, boolean writeEncrypted,
            DatabaseKey encryptionKey) throws MasterKeysWrongPasswordException {
        if(writeEncrypted && encryptionKey == null)
            throw new MasterKeysWrongPasswordException();
        File oldWriteToFilename = writeToFilename;
        writeToBucket = makeBucket(dir, baseName, false, writeEncrypted ? encryptionKey : null);
        writeToFilename = makeFilename(dir, baseName, false, writeEncrypted);
        writeToBackupFilename = makeFilename(dir, baseName, true, writeEncrypted);
        if(writeToFilename.equals(oldWriteToFilename)) return;
        System.out.println("Will save downloads to "+writeToFilename);
        deleteAfterSuccessfulWrite = makeFilename(dir, baseName, false, !writeEncrypted);
        otherDeleteAfterSuccessfulWrite = makeFilename(dir, baseName, true, !writeEncrypted);
        queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                return true; // Force a checkpoint ASAP.
                // This also avoids any possible locking issues.
            }
            
        });
    }

    private boolean innerSetFilesAndLoad(boolean noSerialize, File dir, String baseName, 
            boolean writeEncrypted, DatabaseKey encryptionKey, ClientContext context, 
            RequestStarterGroup requestStarters, Random random) throws MasterKeysWrongPasswordException {
        if(writeEncrypted && encryptionKey == null)
            throw new MasterKeysWrongPasswordException();
        File clientDat = new File(dir, baseName);
        File clientDatCrypt = new File(dir, baseName+".crypt");
        File clientDatBak = new File(dir, baseName+".bak");
        File clientDatBakCrypt = new File(dir, baseName+".bak.crypt");
        boolean clientDatExists = clientDat.exists();
        boolean clientDatCryptExists = clientDatCrypt.exists();
        boolean clientDatBakExists = clientDatBak.exists();
        boolean clientDatBakCryptExists = clientDatBakCrypt.exists();
        if(encryptionKey == null) {
            if(clientDatCryptExists || clientDatBakCryptExists)
                throw new MasterKeysWrongPasswordException();
        }
        boolean failedSerialize = false;
        PartialLoad loaded = new PartialLoad();
        if(clientDatExists) {
            innerLoad(loaded, makeBucket(dir, baseName, false, null), noSerialize, context, requestStarters);
        }
        if(clientDatCryptExists && loaded.needsMore()) {
            innerLoad(loaded, makeBucket(dir, baseName, false, encryptionKey), noSerialize, context, requestStarters);
        }
        if(clientDatBakExists) {
            innerLoad(loaded, makeBucket(dir, baseName, true, null), noSerialize, context, requestStarters);
        }
        if(clientDatBakCryptExists && loaded.needsMore()) {
            innerLoad(loaded, makeBucket(dir, baseName, true, encryptionKey), noSerialize, context, requestStarters);
        }
        
        deleteAfterSuccessfulWrite = writeEncrypted ? clientDat : clientDatCrypt;
        otherDeleteAfterSuccessfulWrite = writeEncrypted ? clientDatBak : clientDatBakCrypt;
        
        writeToBucket = makeBucket(dir, baseName, false, writeEncrypted ? encryptionKey : null);
        writeToFilename = makeFilename(dir, baseName, false, writeEncrypted);
        writeToBackupFilename = makeFilename(dir, baseName, true, writeEncrypted);
        
        if(loaded.doneSomething()) {
            if(!noSerialize) {
                onLoading();
                if(loaded.getSalt() == null) {
                    salt = new byte[32];
                    random.nextBytes(salt);
                    Logger.error(this, "Checksum failed for salt value");
                    System.err.println("Salt value corrupted, downloads will need to regenerate Bloom filters, this may cause some delay and disk/CPU usage...");
                    newSalt = true;
                } else {
                    salt = loaded.salt;
                }
            }
            int success = 0;
            int restoredRestarted = 0;
            int restoredFully = 0;
            int failed = 0;
            // Resume the requests.
            for(PartiallyLoadedRequest partial : loaded.partiallyLoadedRequests.values()) {
                ClientRequest req = partial.request;
                if(req == null) continue;
                try {
                    req.onResume(context);
                    if(partial.status == RequestLoadStatus.RESTORED_FULLY || 
                            partial.status == RequestLoadStatus.RESTORED_RESTARTED) {
                        req.start(context);
                    }
                    switch(partial.status) {
                    case LOADED:
                        success++;
                        break;
                    case RESTORED_FULLY:
                        restoredFully++;
                        break;
                    case RESTORED_RESTARTED:
                        restoredRestarted++;
                        break;
                    case FAILED:
                        failed++;
                        break;
                    }
                } catch (Throwable t) {
                    if(partial.status == RequestLoadStatus.LOADED)
                        failedSerialize = true;
                    failed++;
                    System.err.println("Unable to resume request "+req+" after loading it.");
                    Logger.error(this, "Unable to resume request "+req+" after loading it: "+t, t);
                    try {
                        req.cancel(context);
                    } catch (Throwable t1) {
                        Logger.error(this, "Unable to terminate "+req+" after failure: "+t1, t1);
                    }
                }
            }
            if(success > 0)
                System.out.println("Resumed "+success+" requests ...");
            if(restoredFully > 0)
                System.out.println("Restored "+restoredFully+" requests (in spite of data corruption)");
            if(restoredRestarted > 0)
                System.out.println("Restarted "+restoredRestarted+" requests (due to data corruption)");
            if(failed > 0)
                System.err.println("Failed to restore "+failed+" requests due to data corruption");
            return failedSerialize;
        } else {
            // FIXME backups etc!
            System.err.println("Starting request persistence layer without resuming ...");
            salt = new byte[32];
            random.nextBytes(salt);
            requestStarters.setGlobalSalt(salt);
            onStarted(false);
            return false;
        }
    }
    
    /** Create a Bucket for client.dat[.bak][.crypt].
     * @param dir The parent directory.
     * @param baseName The base name, usually "client.dat".
     * @param backup True if we want the .bak file.
     * @param encryptionKey Non-null if we want an encrypted file.
     */
    private Bucket makeBucket(File dir, String baseName, boolean backup, DatabaseKey encryptionKey) {
        File filename = makeFilename(dir, baseName, backup, encryptionKey != null);
        Bucket bucket = new FileBucket(filename, false, false, false, false);
        if(encryptionKey != null)
            bucket = encryptionKey.createEncryptedBucketForClientLayer(bucket);
        return bucket;
    }
    
    private File makeFilename(File parent, String baseName, boolean backup, boolean encrypted) {
        return new File(parent, baseName + (backup ? ".bak" : "") + (encrypted ? ".crypt" : ""));
                
    }

    private enum RequestLoadStatus {
        // In order of preference, best first.
        LOADED,
        RESTORED_FULLY,
        RESTORED_RESTARTED,
        FAILED
    }
    
    private class PartiallyLoadedRequest {
        final ClientRequest request;
        final RequestLoadStatus status;
        PartiallyLoadedRequest(ClientRequest request, RequestLoadStatus status) {
            this.request = request;
            this.status = status;
        }
    }
    
    private class PartialLoad {
        private final Map<RequestIdentifier, PartiallyLoadedRequest> partiallyLoadedRequests 
            = new HashMap<RequestIdentifier, PartiallyLoadedRequest>();
        
        private byte[] salt;
        
        private boolean somethingFailed;
        
        private boolean doneSomething;
        
        /** Add a partially loaded request. 
         * @param reqID The request identifier. Must be non-null; caller should regenerate it if
         * necessary. */
        void addPartiallyLoadedRequest(RequestIdentifier reqID, ClientRequest request, 
                RequestLoadStatus status) {
            if(reqID == null) {
                if(request == null) {
                    somethingFailed = true;
                    return;
                } else {
                    reqID = request.getRequestIdentifier();
                }
            }
            PartiallyLoadedRequest old = partiallyLoadedRequests.get(reqID);
            if(old == null || old.status.ordinal() > status.ordinal()) {
                partiallyLoadedRequests.put(reqID, new PartiallyLoadedRequest(request, status));
                if(!(status == RequestLoadStatus.LOADED || status == RequestLoadStatus.RESTORED_FULLY))
                    somethingFailed = true;
                doneSomething = true;
            }
        }

        public boolean needsMore() {
            return somethingFailed || !doneSomething;
        }

        public void setSomethingFailed() {
            somethingFailed = true;
        }
        
        public void setSalt(byte[] loadedSalt) {
            if(salt == null)
                salt = loadedSalt;
            doneSomething = true;
        }

        public byte[] getSalt() {
            return salt;
        }
        
        public boolean doneSomething() {
            return doneSomething;
        }
    }
    
    private void innerLoad(PartialLoad loaded, Bucket bucket, boolean noSerialize,
            ClientContext context, RequestStarterGroup requestStarters) {
        long length = bucket.size();
        InputStream fis = null;
        try {
            fis = bucket.getInputStream();
            innerLoad(loaded, fis, length, !noSerialize && !loaded.doneSomething(), context,
                    requestStarters, noSerialize);
        } catch (IOException e) {
            // FIXME tell user more obviously.
            Logger.error(this, "Failed to load persistent requests from "+bucket+" : "+e, e);
            System.err.println("Failed to load persistent requests from "+bucket+" : "+e);
            e.printStackTrace();
            loaded.setSomethingFailed();
        } catch (Throwable t) {
            Logger.error(this, "Failed to load persistent requests from "+bucket+" : "+t, t);
            System.err.println("Failed to load persistent requests from "+bucket+" : "+t);
            t.printStackTrace();
            loaded.setSomethingFailed();
        } finally {
            try {
                if(fis != null) fis.close();
            } catch (IOException e) {
                System.err.println("Failed to load persistent requests: "+e);
                e.printStackTrace();
            }
        }
    }

    private void innerLoad(PartialLoad loaded, InputStream fis, long length, boolean latest,
            ClientContext context, RequestStarterGroup requestStarters, boolean noSerialize) throws NodeInitException, IOException {
        ObjectInputStream ois = new ObjectInputStream(fis);
        long magic = ois.readLong();
        if(magic != MAGIC) throw new IOException("Bad magic");
        int version = ois.readInt();
        if(version != VERSION) throw new IOException("Bad version");
        byte[] salt = new byte[32];
        try {
            checker.readAndChecksum(ois, salt, 0, salt.length);
            loaded.setSalt(salt);
        } catch (ChecksumFailedException e1) {
            Logger.error(this, "Unable to read global salt (checksum failed)");
        }
        requestStarters.setGlobalSalt(salt);
        int requestCount = ois.readInt();
        for(int i=0;i<requestCount;i++) {
            ClientRequest request = null;
            RequestIdentifier reqID = readRequestIdentifier(ois);
            if(reqID != null && context.persistentRoot.hasRequest(reqID)) {
                Logger.warning(this, "Not reading request because already have it");
                skipChecksummedObject(ois, length); // Request itself
                skipChecksummedObject(ois, length); // Recovery data
                continue;
            }
            try {
                if(!noSerialize) {
                    request = (ClientRequest) readChecksummedObject(ois, length);
                    if(request != null) {
                        if(reqID != null) {
                            if(!reqID.sameIdentifier(request.getRequestIdentifier())) {
                                Logger.error(this, "Request does not match request identifier, discarding");
                                request = null;
                            } else {
                                loaded.addPartiallyLoadedRequest(reqID, request, RequestLoadStatus.LOADED);
                            }
                        }
                    }
                } else
                    skipChecksummedObject(ois, length);
            } catch (ChecksumFailedException e) {
                Logger.error(this, "Failed to load request (checksum failed)");
                System.err.println("Failed to load a request (checksum failed)");
            } catch (Throwable t) {
                // Some more serious problem. Try to load the rest anyway.
                Logger.error(this, "Failed to load request: "+t, t);
                System.err.println("Failed to load a request: "+t);
                t.printStackTrace();
            }
            if(request == null || logMINOR) {
                try {
                    ClientRequest restored = readRequestFromRecoveryData(ois, length, reqID);
                    if(request == null && restored != null) {
                        request = restored;
                        boolean loadedFully = restored.fullyResumed();
                        loaded.addPartiallyLoadedRequest(reqID, request, 
                                loadedFully ? RequestLoadStatus.RESTORED_FULLY : RequestLoadStatus.RESTORED_RESTARTED);
                    }
                } catch (ChecksumFailedException e) {
                    if(request == null) {
                        Logger.error(this, "Failed to recover a request (checksum failed)");
                        System.err.println("Failed to recover a request (checksum failed)");
                    } else {
                        Logger.error(this, "Test recovery failed: Checksum failed for "+reqID);
                    }
                    if(request == null)
                        loaded.addPartiallyLoadedRequest(reqID, null, RequestLoadStatus.FAILED);
                } catch (StorageFormatException e) {
                    if(request == null) {
                        Logger.error(this, "Failed to recovery a request (storage format): "+e, e);
                        System.err.println("Failed to recovery a request (storage format): "+e);
                        e.printStackTrace();
                    } else {
                        Logger.error(this, "Test recovery failed for "+reqID+" : "+e, e);
                    }
                    if(request == null)
                        loaded.addPartiallyLoadedRequest(reqID, null, RequestLoadStatus.FAILED);
                }
            } else {
                skipChecksummedObject(ois, length);
            }
        }
        if(latest) {
            try {
                // Don't bother with the buckets to free or the stats unless reading from the latest version (client.dat not client.dat.bak).
                readStatsAndBuckets(ois, length);
            } catch (Throwable t) {
                Logger.error(this, "Failed to restore stats and delete old temp files: "+t, t);
            }
        }
        ois.close();
        fis = null;
    }

    private void readStatsAndBuckets(ObjectInputStream ois, long length) throws IOException, ClassNotFoundException {
        PersistentStatsPutter storedStatsPutter = (PersistentStatsPutter) ois.readObject();
        this.bandwidthStatsPutter.addFrom(storedStatsPutter);
        int count = ois.readInt();
        DelayedFree[] buckets = new DelayedFree[count];
        for(int i=0;i<count;i++) {
            try {
                buckets[i] = (DelayedFree) readChecksummedObject(ois, length);
            } catch (ChecksumFailedException e) {
                Logger.warning(this, "Failed to load a bucket to free");
            }
        }
        persistentTempFactory.finishDelayedFree(buckets);
    }

    @Override
    protected void innerCheckpoint(boolean shutdown) {
        save(shutdown);
    }
    
    protected void save(boolean shutdown) {
        if(writeToFilename == null) return;
        if(writeToFilename.exists()) {
            FileUtil.renameTo(writeToFilename, writeToBackupFilename);
        }
        if(innerSave(shutdown)) {
            if(deleteAfterSuccessfulWrite != null) {
                deleteAfterSuccessfulWrite.delete();
                deleteAfterSuccessfulWrite = null;
            }
            if(otherDeleteAfterSuccessfulWrite != null) {
                otherDeleteAfterSuccessfulWrite.delete();
                otherDeleteAfterSuccessfulWrite = null;
            }
        }
    }
    
    private boolean innerSave(boolean shutdown) {
        DelayedFree[] buckets = persistentTempFactory.grabBucketsToFree();
        OutputStream fos = null;
        try {
            fos = writeToBucket.getOutputStream();
            BufferedOutputStream bos = new BufferedOutputStream(fos);
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeLong(MAGIC);
            oos.writeInt(VERSION);
            checker.writeAndChecksum(oos, salt);
            ClientRequest[] requests = getRequests();
            if(shutdown) {
                for(ClientRequest req : requests) {
                    if(req == null) continue;
                    try {
                        req.onShutdown(getClientContext());
                    } catch (Throwable t) {
                        Logger.error(this, "Caught while calling shutdown callback on "+req+": "+t, t);
                    }
                }
            }
            oos.writeInt(requests.length);
            for(ClientRequest req : requests) {
                // Write the request identifier so we can skip reading the request if we already have it.
                writeRequestIdentifier(oos, req.getRequestIdentifier());
                // Write the actual request.
                writeChecksummedObject(oos, req, req.toString());
                // Write recovery data. This is just enough to restart the request from scratch, 
                // but may support continuing the request in simple cases e.g. if a fetch is now
                // just a single splitfile.
                writeRecoveryData(oos, req);
            }
            bandwidthStatsPutter.updateData(node);
            oos.writeObject(bandwidthStatsPutter);
            if(buckets == null) {
                oos.writeInt(0);
            } else {
                oos.writeInt(buckets.length);
                for(DelayedFree bucket : buckets)
                    writeChecksummedObject(oos, bucket, null);
            }
            oos.close();
            fos = null;
            Logger.normal(this, "Saved "+requests.length+" requests to "+writeToFilename);
            persistentTempFactory.finishDelayedFree(buckets);
            return true;
        } catch (IOException e) {
            System.err.println("Failed to write persistent requests: "+e);
            e.printStackTrace();
            return false;
        } finally {
            try {
                if(fos != null) fos.close();
            } catch (IOException e) {
                System.err.println("Failed to write persistent requests: "+e);
                e.printStackTrace();
            }
        }
    }
    
    private void writeRecoveryData(ObjectOutputStream os, ClientRequest req) throws IOException {
        PrependLengthOutputStream oos = checker.checksumWriterWithLength(os, tempBucketFactory);
        DataOutputStream dos = new DataOutputStream(oos);
        try {
            req.getClientDetail(dos, checker);
            dos.close();
            oos = null;
        } catch (Throwable e) {
            Logger.error(this, "Unable to write recovery data for "+req+" : "+e, e);
            System.err.println("Unable to write recovery data for "+req+" : "+e);
            e.printStackTrace();
            oos.abort();
        } finally {
            if(oos != null) oos.close();
        }
    }
    
    private ClientRequest readRequestFromRecoveryData(ObjectInputStream is, long totalLength, RequestIdentifier reqID) throws IOException, ChecksumFailedException, StorageFormatException {
        InputStream tmp = checker.checksumReaderWithLength(is, this.tempBucketFactory, totalLength);
        try {
            DataInputStream dis = new DataInputStream(tmp);
            ClientRequest request = ClientRequest.restartFrom(dis, reqID, getClientContext(), checker);
            dis.close();
            dis = null;
            tmp = null;
            return request;
        } catch (Throwable t) {
            Logger.error(this, "Serialization failed: "+t, t);
            return null;
        } finally {
            if(tmp != null) tmp.close();
        }
    }

    private void writeChecksummedObject(ObjectOutputStream os, Object req, String name) throws IOException {
        PrependLengthOutputStream oos = checker.checksumWriterWithLength(os, tempBucketFactory);
        try {
            ObjectOutputStream innerOOS = new ObjectOutputStream(oos);
            innerOOS.writeObject(req);
            innerOOS.close();
            oos = null;
        } catch (Throwable e) {
            Logger.error(this, "Unable to write recovery data for "+name+" : "+e, e);
            oos.abort();
        } finally {
            if(oos != null) oos.close();
        }
    }
    
    private Object readChecksummedObject(ObjectInputStream is, long totalLength) throws IOException, ChecksumFailedException, ClassNotFoundException {
        InputStream ois = checker.checksumReaderWithLength(is, this.tempBucketFactory, totalLength);
        try {
            ObjectInputStream oo = new ObjectInputStream(ois);
            Object ret = oo.readObject();
            oo.close();
            oo = null;
            ois = null;
            return ret;
        } catch (Throwable t) {
            Logger.error(this, "Serialization failed: "+t, t);
            return null;
        } finally {
            if(ois != null) ois.close();
        }
    }

    private void skipChecksummedObject(ObjectInputStream is, long totalLength) throws IOException {
        long length = is.readLong();
        if(length > totalLength) throw new IOException("Too long: "+length+" > "+totalLength);
        FileUtil.skipFully(is, length + checker.checksumLength());
    }

    private ClientRequest[] getRequests() {
        return clientCore.getPersistentRequests();
    }

    public boolean newSalt() {
        return newSalt;
    }
    
    private RequestIdentifier readRequestIdentifier(DataInput is) throws IOException {
        short length = is.readShort();
        if(length <= 0) return null;
        byte[] buf = new byte[length];
        try {
            checker.readAndChecksum(is, buf, 0, length);
        } catch (ChecksumFailedException e) {
            Logger.error(this, "Checksum failed reading RequestIdentifier. This is not serious but means we will have to read the next request even if we don't need it.");
            return null;
        }
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(buf));
        try {
            return new RequestIdentifier(dis);
        } catch (IOException e) {
            Logger.error(this, "Failed to parse RequestIdentifier in spite of valid checksum (probably a bug): "+e, e);
            return null;
        }
    }
    
    private void writeRequestIdentifier(DataOutput os, RequestIdentifier req) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        OutputStream oos = checker.checksumWriter(baos);
        DataOutputStream dos = new DataOutputStream(oos);
        req.writeTo(dos);
        dos.close();
        byte[] buf = baos.toByteArray();
        os.writeShort(buf.length - checker.checksumLength());
        os.write(buf);
    }

    public synchronized File getWriteFilename() {
        return writeToFilename;
    }

    public void panic() {
        killAndWaitForNotWriting();
        deleteAllFiles();
    }
    
    public void deleteAllFiles() {
        synchronized(serializeCheckpoints) {
            deleteFile(dir, baseName, false, false);
            deleteFile(dir, baseName, false, true);
            deleteFile(dir, baseName, true, false);
            deleteFile(dir, baseName, true, true);
        }
    }

    public void disableWrite() {
        synchronized(serializeCheckpoints) {
            writeToFilename = null;
            writeToBackupFilename = null;
            writeToBucket = null;
        }
        super.disableWrite();
    }

}
