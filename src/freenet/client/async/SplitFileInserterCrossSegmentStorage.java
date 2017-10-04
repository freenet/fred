package freenet.client.async;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import freenet.client.FECCodec;
import freenet.client.async.PersistentJobRunner.CheckpointLock;
import freenet.crypt.ChecksumFailedException;
import freenet.keys.CHKBlock;
import freenet.keys.ClientCHK;
import freenet.support.Logger;
import freenet.support.MemoryLimitedChunk;
import freenet.support.MemoryLimitedJob;
import freenet.support.MemoryLimitedJobRunner;
import freenet.support.api.LockableRandomAccessBuffer.RAFLock;
import freenet.support.io.CountedOutputStream;
import freenet.support.io.NativeThread;
import freenet.support.io.NullOutputStream;
import freenet.support.io.StorageFormatException;

public class SplitFileInserterCrossSegmentStorage {
    
    private static volatile boolean logMINOR;
    private static volatile boolean logDEBUG;
    static {
        Logger.registerClass(SplitFileInserterCrossSegmentStorage.class);
    }

    final SplitFileInserterStorage parent;
    final int segNo;
    final int dataBlockCount;
    final int crossCheckBlockCount;
    final int totalBlocks;
    
    private boolean encoded;
    private boolean encoding;
    private boolean cancelled;
    
    /** Segment for each block */
    private final SplitFileInserterSegmentStorage[] segments;
    /** Block number within the segment for each block */
    private final int[] blockNumbers;

    // Only used in construction.
    private transient int counter;
    
    private final int statusLength;
    
    
    // Set to true to encode block keys during *cross-segment* encoding, and thus detect e.g. storage bugs.
    // This will cause more disk I/O as we have to write the keys (more or less randomly).
    // FIXME turn off before merging into master.
    static final boolean DEBUG_ENCODE = true;
    
    public SplitFileInserterCrossSegmentStorage(SplitFileInserterStorage parent, int segNo, int segLen, int crossCheckBlocks) {
        this.parent = parent;
        this.segNo = segNo;
        this.dataBlockCount = segLen;
        this.crossCheckBlockCount = crossCheckBlocks;
        this.totalBlocks = dataBlockCount + crossCheckBlocks;
        segments = new SplitFileInserterSegmentStorage[totalBlocks];
        blockNumbers = new int[totalBlocks];
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

    /** Only used during construction */
    void addBlock(SplitFileInserterSegmentStorage seg, int blockNum) {
        segments[counter] = seg;
        blockNumbers[counter] = blockNum;
        if(logMINOR) Logger.minor(this, "Allocated cross-segment block "+counter+" to block "+blockNum+" on "+seg+" for "+this);
        counter++;
    }
    
    void addDataBlock(SplitFileInserterSegmentStorage seg, int blockNum) {
        assert(counter < dataBlockCount);
        assert(blockNum < seg.dataBlockCount);
        addBlock(seg, blockNum);
    }

    /** Only used during construction */
    void addCheckBlock(SplitFileInserterSegmentStorage seg, int blockNum) {
        assert(counter >= dataBlockCount);
        assert(blockNum >= seg.dataBlockCount && blockNum < seg.dataBlockCount + seg.crossCheckBlockCount);
        addBlock(seg, blockNum);
    }

    public void writeFixedSettings(DataOutputStream dos) throws IOException {
        dos.writeInt(dataBlockCount);
        dos.writeInt(crossCheckBlockCount);
        for(int i=0;i<totalBlocks;i++) {
            dos.writeInt(segments[i].segNo);
            dos.writeInt(blockNumbers[i]);
        }
        dos.writeInt(statusLength);
    }
    
    SplitFileInserterCrossSegmentStorage(SplitFileInserterStorage parent, DataInputStream dis, 
            int segNo) throws StorageFormatException, IOException {
        this.segNo = segNo;
        this.parent = parent;
        this.dataBlockCount = dis.readInt();
        if(dataBlockCount <= 0) throw new StorageFormatException("Negative cross-segment data block count");
        this.crossCheckBlockCount = dis.readInt();
        if(crossCheckBlockCount <= 0) throw new StorageFormatException("Negative cross-check block count");
        this.totalBlocks = dataBlockCount + crossCheckBlockCount;
        if(totalBlocks > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
            throw new StorageFormatException("Bogus total block count");
        segments = new SplitFileInserterSegmentStorage[totalBlocks];
        blockNumbers = new int[totalBlocks];
        for(int i=0;i<totalBlocks;i++) {
            int readSegmentNumber = dis.readInt();
            if(readSegmentNumber < 0 || readSegmentNumber >= parent.segments.length)
                throw new StorageFormatException("Bogus segment number "+readSegmentNumber);
            int readBlockNumber = dis.readInt();
            SplitFileInserterSegmentStorage segment = parent.segments[readSegmentNumber]; 
            if(readBlockNumber < 0 || 
                    (readBlockNumber >= segment.dataBlockCount + segment.crossCheckBlockCount)
                    || (i < dataBlockCount && readBlockNumber >= segment.dataBlockCount)
                    || (i >= dataBlockCount && readBlockNumber < segment.dataBlockCount))
                throw new StorageFormatException("Bogus block number "+readBlockNumber+" for slot "+i);
            segments[i] = segment;
            blockNumbers[i] = readBlockNumber;
        }
        for(int i=0;i<crossCheckBlockCount;i++) {
            segments[i+dataBlockCount].setCrossCheckBlock(this, blockNumbers[i+dataBlockCount], i+dataBlockCount);
        }
        statusLength = dis.readInt();
        if(statusLength < 0) throw new StorageFormatException("Bogus status length");
        try {
            CountedOutputStream cos = new CountedOutputStream(new NullOutputStream());
            DataOutputStream dos = new DataOutputStream(cos);
            innerStoreStatus(dos);
            dos.close();
            int computedStatusLength = (int) cos.written() + parent.checker.checksumLength();
            if(computedStatusLength > statusLength)
                throw new StorageFormatException("Stored status length smaller than required");
        } catch (IOException e) {
            throw new Error(e); // Impossible
        }
    }

    public synchronized void startEncode(final short prio) {
        if(encoded) return;
        if(cancelled) return;
        if(encoding) return;
        encoding = true;
        long limit = totalBlocks * CHKBlock.DATA_LENGTH + 
            Math.max(parent.codec.maxMemoryOverheadDecode(dataBlockCount, crossCheckBlockCount),
                parent.codec.maxMemoryOverheadEncode(dataBlockCount, crossCheckBlockCount));
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
                            synchronized(SplitFileInserterCrossSegmentStorage.this) {
                                encoding = false;
                            }
                            parent.onFinishedEncoding();
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

    /** Encode a segment. Much simpler than fetcher! */
    private void innerEncode() {
        try {
            synchronized(this) {
                if(cancelled) return;
            }
            if(logMINOR) Logger.minor(this, "Encoding "+this);
            byte[][] dataBlocks = readDataBlocks();
            byte[][] checkBlocks = new byte[crossCheckBlockCount][];
            for(int i=0;i<checkBlocks.length;i++)
                checkBlocks[i] = new byte[CHKBlock.DATA_LENGTH];
            if(dataBlocks == null || checkBlocks == null) return; // Failed with disk error.
            parent.codec.encode(dataBlocks, checkBlocks, new boolean[checkBlocks.length], CHKBlock.DATA_LENGTH);
            writeCheckBlocks(checkBlocks);
            synchronized(this) {
                encoded = true;
            }
            if(logMINOR) Logger.minor(this, "Finished encoding "+this);
            storeStatus();
        } catch (IOException e) {
            parent.failOnDiskError(e);
        }
    }

    private void writeCheckBlocks(byte[][] checkBlocks) throws IOException {
        RAFLock lock = parent.lockRAF();
        try {
            for(int i=0;i<checkBlocks.length;i++)
                writeCheckBlock(i, checkBlocks[i]);
        } finally {
            lock.unlock();
        }
    }

    private void writeCheckBlock(int checkBlockNo, byte[] buf) throws IOException {
        parent.writeCheckBlock(segNo, checkBlockNo, buf);
        if(DEBUG_ENCODE) {
            SplitFileInserterSegmentStorage segment = segments[checkBlockNo + dataBlockCount];
            ClientCHK key = segment.encodeBlock(buf).getClientKey();
            segment.setKey(blockNumbers[checkBlockNo + dataBlockCount], key);
        }
    }

    /** Read a cross-check block and check consistency 
     * @throws IOException */
    byte[] readCheckBlock(int slotNumberWithinCrossSegment, int segmentNumber, 
            int blockNoWithinSegment) throws IOException {
        assert(blockNumbers[slotNumberWithinCrossSegment] == blockNoWithinSegment);
        assert(segments[slotNumberWithinCrossSegment].segNo == segmentNumber);
        return parent.readCheckBlock(segNo, slotNumberWithinCrossSegment - dataBlockCount);
    }

    private byte[][] readDataBlocks() throws IOException {
        RAFLock lock = parent.lockUnderlying();
        try {
            byte[][] data = new byte[dataBlockCount][];
            for(int i=0;i<dataBlockCount;i++) {
                data[i] = segments[i].readDataBlock(blockNumbers[i]);
                if(DEBUG_ENCODE) {
                    ClientCHK key = segments[i].encodeBlock(data[i]).getClientKey();
                    segments[i].setKey(blockNumbers[i], key);
                }
            }
            return data;
        } finally {
            lock.unlock();
        }
    }

    public synchronized boolean isFinishedEncoding() {
        return encoded;
    }

    public int getAllocatedCrossCheckBlocks() {
        return counter;
    }
    
    public long storedStatusLength() {
        return statusLength;
    }
    
    public void storeStatus() {
        if(!parent.persistent) return;
        DataOutputStream dos;
        try {
            dos = new DataOutputStream(parent.writeChecksummedTo(parent.crossSegmentStatusOffset(segNo), statusLength));
            innerStoreStatus(dos);
        } catch (IOException e) {
            Logger.error(this, "Impossible: "+e, e);
            return;
        }
        try {
            dos.close();
        } catch (IOException e) {
            Logger.error(this, "I/O error writing segment status?: "+e, e);
            parent.failOnDiskError(e);
        }
    }

    private void innerStoreStatus(DataOutputStream dos) throws IOException {
        dos.writeInt(segNo); // To make checksum different.
        dos.writeBoolean(encoded);
    }
    
    void readStatus() throws IOException, ChecksumFailedException, StorageFormatException {
        byte[] data = new byte[statusLength-parent.checker.checksumLength()];
        parent.preadChecksummed(parent.crossSegmentStatusOffset(segNo), data, 0, data.length);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
        if(dis.readInt() != segNo) throw new StorageFormatException("Bad segment number");
        encoded = dis.readBoolean();
    }

    int[] getSegmentNumbers() {
        int[] ret = new int[totalBlocks];
        for(int i=0;i<totalBlocks;i++)
            ret[i] = segments[i].segNo;
        return ret;
    }
    
    int[] getBlockNumbers() {
        return blockNumbers.clone();
    }

    /** Cancel the encode.
     * @return True if we can complete cancelling now, false if we are encoding, in which case 
     * parent will get the usual callback when it is done.
     */
    public synchronized boolean cancel() {
        cancelled = true;
        if(encoding) return false;
        return true;
    }

    public synchronized boolean hasCompletedOrFailed() {
        if(encoding) return false;
        return encoded || cancelled;
    }
    
    /** For tests only */
    synchronized boolean isEncoding() {
        return encoding;
    }

    /** For tests only */
    synchronized boolean hasEncodedSuccessfully() {
        return encoded;
    }

}
