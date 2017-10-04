package freenet.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import freenet.client.FECCodec;
import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.async.PersistentJobRunner.CheckpointLock;
import freenet.crypt.ChecksumChecker;
import freenet.crypt.ChecksumFailedException;
import freenet.keys.CHKBlock;
import freenet.keys.CHKEncodeException;
import freenet.keys.ClientCHK;
import freenet.keys.ClientCHKBlock;
import freenet.node.KeysFetchingLocally;
import freenet.node.SendableRequestItem;
import freenet.node.SendableRequestItemKey;
import freenet.support.Logger;
import freenet.support.MemoryLimitedChunk;
import freenet.support.MemoryLimitedJob;
import freenet.support.MemoryLimitedJobRunner;
import freenet.support.api.LockableRandomAccessBuffer.RAFLock;
import freenet.support.io.CountedOutputStream;
import freenet.support.io.NativeThread;
import freenet.support.io.NullOutputStream;
import freenet.support.io.StorageFormatException;

/** A single segment within a splitfile to be inserted. */
public class SplitFileInserterSegmentStorage {
    
    private static volatile boolean logMINOR;
    private static volatile boolean logDEBUG;
    static {
        Logger.registerClass(SplitFileInserterSegmentStorage.class);
    }

    final SplitFileInserterStorage parent;

    final int segNo;
    final int dataBlockCount;
    final int crossCheckBlockCount;
    final int checkBlockCount;
    final int totalBlockCount;
    
    /** Has the segment been encoded? If so, all of the check blocks have been written. */
    private boolean encoded;
    private boolean encoding;

    private final int statusLength;
    /** Length of a single key stored on disk. Includes checksum. */
    private final int keyLength;
    
    // FIXME These are refilled by SplitFileInserterCrossSegmentStorage on construction...
    /** For each cross-segment block, the cross-segment responsible */
    private final SplitFileInserterCrossSegmentStorage[] crossSegmentBlockSegments;
    /** For each cross-segment block, the block number within that cross-segment */
    private final int[] crossSegmentBlockNumbers;
    
    private final boolean[] blocksHaveKeys;
    private int blocksWithKeysCounter;
    
    // These are only used in construction.
    private transient final boolean[] crossDataBlocksAllocated;
    private transient int crossDataBlocksAllocatedCount;
    private transient int crossCheckBlocksAllocatedCount;

    // These are also in parent but we need them here for easy access, especially as we don't want to
    // make the byte[] visible.
    /** For modern splitfiles, the crypto key is the same for every block. */
    private final byte[] splitfileCryptoKey;
    /** Crypto algorithm is the same for every block. */
    private final byte splitfileCryptoAlgorithm;
    
    /** LOCKING: Locked with (this) as needs to access encoded in chooseBlock */
    private final SplitFileInserterSegmentBlockChooser blockChooser;
    private boolean metadataDirty;
    
    /** Set if the insert is cancelled. */
    private boolean cancelled;
    
    public SplitFileInserterSegmentStorage(SplitFileInserterStorage parent, int segNo, 
            int dataBlocks, int checkBlocks, int crossCheckBlocks, int keyLength,
            byte splitfileCryptoAlgorithm, byte[] splitfileCryptoKey, Random random, int maxRetries,
            int consecutiveRNFsCountAsSuccess, KeysFetchingLocally keysFetching) {
        this.parent = parent;
        this.segNo = segNo;
        this.dataBlockCount = dataBlocks;
        this.checkBlockCount = checkBlocks;
        this.crossCheckBlockCount = crossCheckBlocks;
        totalBlockCount = dataBlockCount + crossCheckBlockCount + checkBlockCount;
        this.keyLength = keyLength;
        crossSegmentBlockSegments = new SplitFileInserterCrossSegmentStorage[crossCheckBlocks];
        crossSegmentBlockNumbers = new int[crossCheckBlocks];
        blocksHaveKeys = new boolean[totalBlockCount];
        this.splitfileCryptoAlgorithm = splitfileCryptoAlgorithm;
        this.splitfileCryptoKey = splitfileCryptoKey;
        crossDataBlocksAllocated = new boolean[dataBlocks + crossCheckBlocks];
        blockChooser = new SplitFileInserterSegmentBlockChooser(this, totalBlockCount, random, 
                maxRetries, keysFetching, consecutiveRNFsCountAsSuccess);
        try {
            CountedOutputStream cos = new CountedOutputStream(new NullOutputStream());
            DataOutputStream dos = new DataOutputStream(cos);
            innerStoreStatus(dos);
            dos.close();
            statusLength = (int) cos.written() + parent.checker.checksumLength();
        } catch (IOException e) {
            throw new Error(e); // Impossible
        }
    }

    /** Create a segment from the fixed settings stored in the RAF by writeFixedSettings(). 
     * @throws IOException 
     * @throws StorageFormatException */
    public SplitFileInserterSegmentStorage(SplitFileInserterStorage parent, DataInputStream dis, 
            int segNo, int keyLength, byte splitfileCryptoAlgorithm, byte[] splitfileCryptoKey, 
            Random random, int maxRetries, int consecutiveRNFsCountAsSuccess, 
            KeysFetchingLocally keysFetching) throws IOException, StorageFormatException {
        this.parent = parent;
        this.segNo = segNo;
        this.keyLength = keyLength;
        dataBlockCount = dis.readInt();
        if(dataBlockCount < 0)
            throw new StorageFormatException("Bogus data block count");
        crossCheckBlockCount = dis.readInt();
        if(crossCheckBlockCount < 0)
            throw new StorageFormatException("Bogus cross-check block count");
        if((crossCheckBlockCount == 0) != (parent.crossSegments == null))
            throw new StorageFormatException("Cross-check block count inconsistent with parent");
        checkBlockCount = dis.readInt();
        if(checkBlockCount < 0)
            throw new StorageFormatException("Bogus check block count");
        totalBlockCount = dataBlockCount + crossCheckBlockCount + checkBlockCount;
        if(totalBlockCount > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
            throw new StorageFormatException("Bogus total block count");
        this.statusLength = dis.readInt();
        if(statusLength < 0)
            throw new StorageFormatException("Bogus status length");
        crossSegmentBlockSegments = new SplitFileInserterCrossSegmentStorage[crossCheckBlockCount];
        crossSegmentBlockNumbers = new int[crossCheckBlockCount];
        blocksHaveKeys = new boolean[totalBlockCount];
        this.splitfileCryptoAlgorithm = splitfileCryptoAlgorithm;
        this.splitfileCryptoKey = splitfileCryptoKey;
        crossDataBlocksAllocated = new boolean[dataBlockCount + crossCheckBlockCount];
        blockChooser = new SplitFileInserterSegmentBlockChooser(this, totalBlockCount, random, 
                maxRetries, keysFetching, consecutiveRNFsCountAsSuccess);
        try {
            CountedOutputStream cos = new CountedOutputStream(new NullOutputStream());
            DataOutputStream dos = new DataOutputStream(cos);
            innerStoreStatus(dos);
            dos.close();
            int minStatusLength = (int) cos.written() + parent.checker.checksumLength();
            if(minStatusLength > statusLength)
                throw new StorageFormatException("Bad status length (too short)");
        } catch (IOException e) {
            throw new Error(e); // Impossible
        }
    }
    
    // These two are only used in construction...
    
    /** Allocate a cross-segment data block. Note that this algorithm must be reproduced exactly 
     * for splitfile compatibility; the Random seed is actually determined by the splitfile metadata.
     * @param random PRNG seeded from the splitfile metadata, which determines which blocks to
     * allocate in a deterministic manner.
     * @return The data block number allocated.
     */
    int allocateCrossDataBlock(Random random) {
        int size = dataBlockCount;
        if(crossDataBlocksAllocatedCount == size) return -1;
        int x = 0;
        for(int i=0;i<10;i++) {
            x = random.nextInt(size);
            if(!crossDataBlocksAllocated[x]) {
                crossDataBlocksAllocated[x] = true;
                crossDataBlocksAllocatedCount++;
                return x;
            }
        }
        for(int i=0;i<size;i++) {
            x++;
            if(x == size) x = 0;
            if(!crossDataBlocksAllocated[x]) {
                crossDataBlocksAllocated[x] = true;
                crossDataBlocksAllocatedCount++;
                return x;
            }
        }
        throw new IllegalStateException("Unable to allocate cross data block even though have not used all slots up???");
    }

    /** Allocate a cross-segment check block. **Note that this algorithm must be reproduced exactly 
     * for splitfile compatibility**; the Random seed is actually determined by the splitfile metadata.
     * @param seg The cross-segment to allocate a block for.
     * @param random PRNG seeded from the splitfile metadata, which determines which blocks to 
     * allocate in a deterministic manner.
     * @param crossSegmentBlockNumber Block number within the cross-segment.
     * @return The block number allocated (between dataBlockCount and dataBlockCount+crossSegmentCheckBlocks).
     */
    int allocateCrossCheckBlock(SplitFileInserterCrossSegmentStorage seg, Random random, int crossSegmentBlockNumber) {
        if(crossCheckBlocksAllocatedCount == crossCheckBlockCount) return -1;
        int x = crossCheckBlockCount - (1 + random.nextInt(crossCheckBlockCount));
        for(int i=0;i<crossCheckBlockCount;i++) {
            x++;
            if(x == crossCheckBlockCount) x = 0;
            if(crossSegmentBlockSegments[x] == null) {
                crossSegmentBlockSegments[x] = seg;
                crossSegmentBlockNumbers[x] = crossSegmentBlockNumber;
                crossCheckBlocksAllocatedCount++;
                return x + dataBlockCount;
            }
        }
        throw new IllegalStateException("Unable to allocate cross check block even though have not used all slots up???");
    }

    public void storeStatus(boolean force) {
        if(!parent.persistent) return;
        if(parent.hasFinished()) return;
        try {
            DataOutputStream dos;
            synchronized(this) {
                if(!force && !metadataDirty) return;
                if(cancelled) return;
                try {
                    dos = new DataOutputStream(parent.writeChecksummedTo(parent.segmentStatusOffset(segNo), statusLength));
                    innerStoreStatus(dos);
                } catch (IOException e) {
                    Logger.error(this, "Impossible: "+e, e);
                    return;
                }
                metadataDirty = false;
            }
            // Outside the lock is safe since if we fail we will fail the whole splitfile.
            dos.close();
        } catch (IOException e) {
            Logger.error(this, "I/O error writing segment status?: "+e, e);
            parent.failOnDiskError(e);
        }
    }

    private void innerStoreStatus(DataOutputStream dos) throws IOException {
        dos.writeInt(segNo); // To make checksum different.
        dos.writeBoolean(encoded);
        blockChooser.write(dos);
    }
    
    public void readStatus() throws IOException, ChecksumFailedException, StorageFormatException {
        byte[] data = new byte[statusLength-parent.checker.checksumLength()];
        parent.preadChecksummed(parent.getOffsetSegmentStatus(segNo), data, 0, data.length);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
        if(dis.readInt() != segNo) throw new StorageFormatException("Bad segment number");
        encoded = dis.readBoolean();
        blockChooser.read(dis);
    }

    public long storedStatusLength() {
        return statusLength;
    }

    public void writeFixedSettings(DataOutputStream dos) throws IOException {
        dos.writeInt(dataBlockCount);
        dos.writeInt(crossCheckBlockCount);
        dos.writeInt(checkBlockCount);
        dos.writeInt(statusLength);
    }
    
    static int getKeyLength(SplitFileInserterStorage parent) {
        return encodeKey(1, 1, ClientCHK.TEST_KEY, parent.hasSplitfileKey(), parent.checker).length;
    }
    
    private static byte[] encodeKey(int segNo, int blockNumber, ClientCHK key,
            boolean hasSplitfileKey, ChecksumChecker checker) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            dos.writeInt(segNo);
            dos.writeInt(blockNumber);
            dos.writeByte(1); // 1 = present, 0 = not present
            innerWriteKey(key, dos, hasSplitfileKey);
            dos.close();
        } catch (IOException e) {
            throw new Error(e); // Impossible
        }
        byte[] fullBuf = baos.toByteArray();
        byte[] bufNoKeyNumber = Arrays.copyOfRange(fullBuf, 8, fullBuf.length);
        byte[] ret = checker.appendChecksum(bufNoKeyNumber);
        return ret;
    }
    
    static void innerWriteKey(ClientCHK key, DataOutputStream dos, boolean hasSplitfileKey) throws IOException {
        if(hasSplitfileKey) {
            dos.write(key.getRoutingKey());
        } else {
            key.writeRawBinaryKey(dos);
        }
    }

    void clearKeys() throws IOException {
        // Just write 0's. Not valid.
        // FIXME optimise (write the whole lot at once).
        byte[] buf = new byte[keyLength];
        for(int i=0;i<totalBlockCount;i++) {
            parent.innerWriteSegmentKey(segNo, i, buf);
        }
    }
    
    void setKey(int blockNumber, ClientCHK key) throws IOException {
        if(logMINOR) Logger.minor(this, "Setting key "+key+" for block "+blockNumber+" on "+this, new Exception("debug"));
        try {
            ClientCHK oldKey = readKey(blockNumber);
            if(!oldKey.equals(key))
                throw new IOException("Key for block has changed! Data corruption or bugs in SplitFileInserter code");
        } catch (MissingKeyException e) {
            // Ok.
            writeKey(blockNumber, key);
        }
        // Must be called either way as we don't regenerate blocksHaveKeys on startup.
        setHasKey(blockNumber);
    }
    
    /** Write a key for a block.
     * @param blockNo The block number. Can be a data block, cross segment check block or check
     * block, in that numerical order.
     * @param key The key to write.
     * @throws IOException If we are unable to write the key. */
    void writeKey(int blockNumber, ClientCHK key) throws IOException {
        byte[] buf = encodeKey(segNo, blockNumber, key, parent.hasSplitfileKey(), parent.checker);
        parent.innerWriteSegmentKey(segNo, blockNumber, buf);
    }
    
    /** Set a flag indicating that we have a key. Call parent.onHasKeys if we have all of them.
     * Note that this structure is not persisted! */
    private void setHasKey(int blockNumber) {
        synchronized(this) {
            if(blocksHaveKeys[blockNumber]) return;
            blocksHaveKeys[blockNumber] = true;
            blocksWithKeysCounter++;
            if(blocksWithKeysCounter != totalBlockCount) return;
        }
        parent.onHasKeys();
    }
    
    public synchronized boolean hasKeys() {
        return blocksWithKeysCounter == totalBlockCount;
    }

    /** Called on startup to check which keys we actually have. Does nothing unless the segment 
     * claims to have been encoded already. FIXME consider calling this later on for robustness, 
     * but we would then need to re-encode ... */
    public void checkKeys() {
        synchronized(this) {
            if(!encoded) return;
        }
        try {
            for(int i=0;i<totalBlockCount;i++) {
                readKey(i);
            }
        } catch (IOException e) {
            parent.failOnDiskError(e);
            return;
        } catch (MissingKeyException e) {
            // Easy to recover so may as well...
            Logger.error(this, "Missing key even though segment encoded. Recovering by re-encoding...");
            synchronized(this) {
                encoded = false;
            }
            return;
        }
    }

    public int storedKeysLength() {
        return keyLength * totalBlockCount;
    }
    
    public byte[] readDataBlock(int blockNo) throws IOException {
        assert(blockNo >= 0 && blockNo < dataBlockCount);
        return parent.readSegmentDataBlock(segNo, blockNo);
    }
    
    private void writeCheckBlock(int checkBlockNo, byte[] buf) throws IOException {
        parent.writeSegmentCheckBlock(segNo, checkBlockNo, buf);
    }
    
    public byte[] readCheckBlock(int checkBlockNo) throws IOException {
        assert(checkBlockNo >= 0 && checkBlockNo < checkBlockCount);
        return parent.readSegmentCheckBlock(segNo, checkBlockNo);
    }

    public synchronized void startEncode(final short prio) {
        if(encoded) return;
        if(encoding) return;
        encoding = true;
        int totalBlockCount = dataBlockCount + checkBlockCount + crossCheckBlockCount;
        long limit = totalBlockCount * CHKBlock.DATA_LENGTH + 
            Math.max(parent.codec.maxMemoryOverheadDecode(dataBlockCount, crossCheckBlockCount),
                parent.codec.maxMemoryOverheadEncode(dataBlockCount, crossCheckBlockCount));
        if(logMINOR) Logger.minor(this, "Scheduling encode on "+this+" at priority "+prio+
                " blocks "+totalBlockCount+" memory limit "+limit);
        parent.memoryLimitedJobRunner.queueJob(new MemoryLimitedJob(limit) {
            
            @Override
            public int getPriority() {
                return prio;
            }
            
            @Override
            public boolean start(MemoryLimitedChunk chunk) {
                boolean shutdown = false;
                CheckpointLock lock = null;
                try {
                    lock = parent.jobRunner.lock();
                    innerEncode();
                } catch (PersistenceDisabledException e) {
                    // Will be retried on restarting.
                    shutdown = true;
                } finally {
                    chunk.release();
                    try {
                        if(!shutdown) {
                            // We do want to call the callback even if we threw something, because we 
                            // may be waiting to cancel. However we DON'T call it if we are shutting down.
                            synchronized(SplitFileInserterSegmentStorage.this) {
                                encoding = false;
                            }
                            parent.onFinishedEncoding(SplitFileInserterSegmentStorage.this);
                        }
                    } finally {
                        // Callback is part of the persistent job, unlock *after* calling it.
                        if(lock != null) lock.unlock(false, MemoryLimitedJobRunner.THREAD_PRIORITY);
                    }
                }
                return true;
            }
            
        });
    }

    private void innerEncode() {
        RAFLock lock = null;
        try {
            synchronized(this) {
                if(cancelled) return;
            }
            lock = parent.lockRAF();
            if(logMINOR) Logger.minor(this, "Encoding "+this+" for "+parent);
            byte[][] dataBlocks = readDataAndCrossCheckBlocks();
            generateKeys(dataBlocks, 0);
            byte[][] checkBlocks = new byte[checkBlockCount][];
            for(int i=0;i<checkBlocks.length;i++)
                checkBlocks[i] = new byte[CHKBlock.DATA_LENGTH];
            if(dataBlocks == null || checkBlocks == null) return; // Failed with disk error.
            parent.codec.encode(dataBlocks, checkBlocks, new boolean[checkBlocks.length], CHKBlock.DATA_LENGTH);
            for(int i=0;i<checkBlocks.length;i++)
                writeCheckBlock(i, checkBlocks[i]);
            generateKeys(checkBlocks, dataBlockCount + crossCheckBlockCount);
            synchronized(this) {
                encoded = true;
            }
            if(logMINOR) Logger.minor(this, "Encoded "+this+" for "+parent);
        } catch (IOException e) {
            parent.failOnDiskError(e);
        } catch (Throwable t) {
            Logger.error(this, "Failed: "+t, t);
            parent.fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR, t, null));
        } finally {
            if(lock != null) lock.unlock();
        }
    }

    /** Generate keys for each block and record them. 
     * @throws IOException */
    private void generateKeys(byte[][] dataBlocks, int offset) throws IOException {
        for(int i=0;i<dataBlocks.length;i++) {
            setKey(i + offset, encodeBlock(dataBlocks[i]).getClientKey());
        }
    }

    private byte[][] readDataAndCrossCheckBlocks() throws IOException {
        byte[][] data = new byte[dataBlockCount + crossCheckBlockCount][];
        RAFLock lock = parent.lockUnderlying();
        try {
            for(int i=0;i<dataBlockCount;i++)
                data[i] = readDataBlock(i);
        } finally {
            lock.unlock();
        }
        for(int i=0;i<crossCheckBlockCount;i++)
            data[i+dataBlockCount] = readCrossCheckBlock(i);
        return data;
    }

    private byte[] readCrossCheckBlock(int blockNo) throws IOException {
        return crossSegmentBlockSegments[blockNo].
            readCheckBlock(crossSegmentBlockNumbers[blockNo], segNo, blockNo + dataBlockCount);
    }

    public synchronized boolean isFinishedEncoding() {
        return encoded;
    }

    /** For unit tests. Generally for concurrency purposes we want something that won't change 
     * back, hence e.g. isFinishedEncoding(). */
    synchronized boolean isEncoding() {
        return encoding;
    }

    public ClientCHKBlock encodeBlock(int blockNo) throws IOException {
        if(parent.isFinishing()) {
            throw new IOException("Already finishing reading block "+blockNo+" for "+this+" for "+parent);
        }
        synchronized(this) {
            if(this.blockChooser.hasSucceeded(blockNo)) {
                Logger.error(this, "Already inserted block "+blockNo+" for "+this+" for "+parent);
                throw new IOException("Already inserted block "+blockNo+" for "+this+" for "+parent);
            }
        }
        byte[] buf = readBlock(blockNo);
        return encodeBlock(buf);
    }

    private byte[] readBlock(int blockNo) throws IOException {
        assert(blockNo >= 0 && blockNo < totalBlockCount);
        if(blockNo < dataBlockCount)
            return readDataBlock(blockNo);
        else if(blockNo < dataBlockCount + crossCheckBlockCount)
            return readCrossCheckBlock(blockNo - dataBlockCount);
        else
            return readCheckBlock(blockNo - (dataBlockCount + crossCheckBlockCount));
    }
    
    ClientCHKBlock encodeBlock(byte[] buf) {
        assert (buf.length == CHKBlock.DATA_LENGTH);
        ClientCHKBlock block;
        try {
            block = ClientCHKBlock.encodeSplitfileBlock(buf, splitfileCryptoKey,
                    splitfileCryptoAlgorithm);
        } catch (CHKEncodeException e) {
            throw new Error(e); // Impossible!
        }
        return block;
    }

    private ClientCHK innerReadKey(DataInputStream dis) throws IOException {
        if(splitfileCryptoKey != null) {
            byte[] routingKey = new byte[32];
            dis.readFully(routingKey);
            return new ClientCHK(routingKey, splitfileCryptoKey, false, splitfileCryptoAlgorithm, 
                    (short)-1);
        } else {
            return new ClientCHK(dis);
        }
    }

    ClientCHK readKey(int blockNumber) throws IOException, MissingKeyException {
        byte[] buf = parent.innerReadSegmentKey(segNo, blockNumber);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(segNo);
        dos.writeInt(blockNumber);
        dos.close();
        byte[] prefix = baos.toByteArray();
        byte[] checkBuf = new byte[prefix.length + buf.length];
        System.arraycopy(prefix, 0, checkBuf, 0, prefix.length);
        int checksumLength = parent.checker.checksumLength();
        System.arraycopy(buf, 0, checkBuf, prefix.length, buf.length - checksumLength);
        byte[] checksum = Arrays.copyOfRange(buf, buf.length - checksumLength, buf.length);
        if(parent.checker.checkChecksum(checkBuf, 0, checkBuf.length, checksum))
            throw new MissingKeyException();
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(buf));
        byte b = dis.readByte();
        if(b != 1) throw new MissingKeyException();
        ClientCHK key = innerReadKey(dis);
        setHasKey(blockNumber);
        if(logDEBUG) Logger.debug(this, "Returning "+key);
        return key;
    }

    public class MissingKeyException extends Exception {
        private static final long serialVersionUID = -6695311996193392803L;
    }

    /** Has the segment completed all inserts?
     * Should not change once we reach this state, but might be possible in case of disk errors 
     * causing losing keys etc. */
    public synchronized boolean hasSucceeded() {
        if(cancelled) return false;
        return blockChooser.hasSucceededAll();
    }

    /** Has the segment encoded all check blocks and cross-check blocks? */
    public synchronized boolean hasEncoded() {
        return encoded;
    }
    
    /** Called when a block insert succeeds */
    public void onInsertedBlock(int blockNo, ClientCHK key) {
        try {
            if(parent.hasFinished()) return;
            this.setKey(blockNo, key);
            if(blockChooser.onSuccess(blockNo))
                parent.callback.onInsertedBlock();
            lazyWriteMetadata();
        } catch (IOException e) {
            if(parent.hasFinished()) return; // Race condition possible as this is a callback
            parent.failOnDiskError(e);
        }
    }

    /** Called by BlockChooser when all blocks have been inserted. */
    void onInsertedAllBlocks() {
        if(logMINOR) Logger.minor(this, "Inserted all blocks in segment "+this);
        synchronized(this) {
            if(!encoded) return;
        }
        parent.segmentSucceeded(this);
    }
    
    public void onFailure(int blockNo, InsertException e) {
        if(logMINOR) Logger.minor(this, "Failed block "+blockNo+" with "+e+" for "+this+" for "+parent);
        if(parent.hasFinished()) return; // Race condition possible as this is a callback
        parent.addFailure(e);
        if(e.isFatal()) {
            parent.failFatalErrorInBlock();
        } else {
            if(e.mode == InsertExceptionMode.ROUTE_NOT_FOUND && 
                    blockChooser.consecutiveRNFsCountAsSuccess > 0) {
                try {
                    readKey(blockNo);
                    blockChooser.onRNF(blockNo);
                    parent.clearCooldown();
                    return;
                } catch (MissingKeyException e1) {
                    Logger.error(this, "RNF but no key on block "+blockNo+" on "+this);
                } catch (IOException e1) {
                    if(parent.hasFinished()) return; // Race condition possible as this is a callback
                    parent.failOnDiskError(e1);
                    return;
                }
            } else if(blockChooser.consecutiveRNFsCountAsSuccess > 0) {
                if(blockChooser.pushRNFs(blockNo)) {
                    parent.failTooManyRetriesInBlock();
                    return;
                }
            }
            if(blockChooser.onNonFatalFailure(blockNo)) {
                parent.failTooManyRetriesInBlock();
            } else {
                if(blockChooser.maxRetries >= 0) lazyWriteMetadata();
                parent.clearCooldown();
            }
        }
    }

    private void lazyWriteMetadata() {
        synchronized(this) {
            metadataDirty = true;
        }
        parent.lazyWriteMetadata();
    }

    public synchronized boolean hasCompletedOrFailed() {
        if(encoded) return true; // No more encoding jobs will run.
        if(encoding) return false; // Waiting for job to finish.
        if(cancelled) return true;
        if(blockChooser.hasSucceededAll()) return true;
        return false;
    }

    /** Caller must check hasCompletedOrFailed() explicitly after calling cancel() on all 
     * segments. 
     * @return True if the segment has completed cancellation. False if it is waiting for an 
     * encode, in which case a callback to parent will be made when the encode finishes. */
    public synchronized boolean cancel() {
        if(cancelled) return false;
        cancelled = true;
        if(hasCompletedOrFailed()) return true;
        return false;
    }
    
    public synchronized BlockInsert chooseBlock() {
        int chosenBlock = innerChooseBlock();
        if(chosenBlock == -1) return null;
        return new BlockInsert(this, chosenBlock);
    }
    
    synchronized int innerChooseBlock() {
        if(cancelled) return -1;
        return blockChooser.chooseKey();
    }

    static final class BlockInsert implements SendableRequestItemKey, SendableRequestItem {
        
        final SplitFileInserterSegmentStorage segment;
        final int blockNumber;
        final int hashCode;
        
        BlockInsert(SplitFileInserterSegmentStorage segment, int blockNumber) {
            this.segment = segment;
            this.blockNumber = blockNumber;
            hashCode = computeHashCode();
        }

        private int computeHashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + blockNumber;
            result = prime * result + ((segment == null) ? 0 : segment.hashCode());
            return result;
        }

        @Override
        public int hashCode() {
            return hashCode;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (!(obj instanceof BlockInsert))
                return false;
            BlockInsert other = (BlockInsert) obj;
            if (blockNumber != other.blockNumber)
                return false;
            return segment == other.segment;
        }

        @Override
        public void dump() {
            // Do nothing. We don't encode in advance.
        }

        @Override
        public SendableRequestItemKey getKey() {
            return this;
        }
        
        public String toString() {
            return "BlockInsert:"+segment+":"+blockNumber+"@memory:"+super.hashCode();
        }
        
    }

    /** Set the cross-segment associated with a cross-check block, which tells us how to read that 
     * block from disk.
     * @param crossSegment The cross-segment.
     * @param segmentBlockNumber The block number within this segment
     * @param crossSegmentBlockNumber The cross-check block number (usually between 0 and 2 inclusive).
     */
    void setCrossCheckBlock(SplitFileInserterCrossSegmentStorage crossSegment,
            int segmentBlockNumber, int crossSegmentBlockNumber) {
        crossSegmentBlockSegments[segmentBlockNumber-dataBlockCount] = crossSegment;
        crossSegmentBlockNumbers[segmentBlockNumber-dataBlockCount] = crossSegmentBlockNumber;
    }

    public int countSendableKeys() {
        return blockChooser.countFetchable();
    }
    
    public String toString() {
        return super.toString()+":"+parent;
    }

}
