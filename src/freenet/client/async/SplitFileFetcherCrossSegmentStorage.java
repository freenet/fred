package freenet.client.async;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import freenet.client.FECCodec;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.async.PersistentJobRunner.CheckpointLock;
import freenet.keys.CHKBlock;
import freenet.keys.CHKEncodeException;
import freenet.keys.ClientCHK;
import freenet.keys.ClientCHKBlock;
import freenet.support.Logger;
import freenet.support.MemoryLimitedChunk;
import freenet.support.MemoryLimitedJob;
import freenet.support.MemoryLimitedJobRunner;
import freenet.support.io.NativeThread;
import freenet.support.io.StorageFormatException;

/** Cross-segments are "in parallel" with the main segments, an interlaced Reed-Solomon scheme 
 * similar to that used on CD's, allowing us to fill in blocks from other segments. There are 3
 * "cross-check blocks" in each segment, and therefore 3 in each cross-segment; the rest are data
 * blocks.
 */
public class SplitFileFetcherCrossSegmentStorage {
    
    private static volatile boolean logMINOR;

    static {
        Logger.registerClass(SplitFileFetcherCrossSegmentStorage.class);
    }

    public final int crossSegmentNumber;
    public final SplitFileFetcherStorage parent;
    
    /** Segment for each block */
    private final SplitFileFetcherSegmentStorage[] segments;
    /** Block number within the segment for each block */
    private final int[] blockNumbers;
    /** Whether each block in the cross-segment has been found. Kept up to date when blocks are
     * found in the other segments. However, as in a normal segment, these may not be 100% 
     * accurate! */
    private final boolean[] blocksFound;
    /** Number of data blocks chosen from the various segments. */
    final int dataBlockCount;
    /** Number of check blocks chosen from the various segments. Typically 3. */
    final int crossCheckBlockCount;
    final int totalBlocks;
    private int totalFound;
    /** If true, we are currrently decoding */
    private boolean tryDecode;
    /** True if the request has been terminated for some reason. */
    private boolean cancelled;
    /** If true, the segment has completed. Once a segment decode starts, finished must not be set
     * until it exits. */
    private boolean succeeded;
    private final FECCodec codec;
    /** Used in assigning blocks */
    private int counter;

    SplitFileFetcherCrossSegmentStorage(int segNo, int blocksPerSegment, int crossCheckBlocks, 
            SplitFileFetcherStorage parent, FECCodec codec) {
        this.crossSegmentNumber = segNo;
        this.parent = parent;
        this.dataBlockCount = blocksPerSegment;
        this.crossCheckBlockCount = crossCheckBlocks;
        totalBlocks = dataBlockCount + crossCheckBlocks;
        int totalBlocks = dataBlockCount + crossCheckBlocks;
        this.codec = codec;
        segments = new SplitFileFetcherSegmentStorage[totalBlocks];
        blockNumbers = new int[totalBlocks];
        blocksFound = new boolean[totalBlocks];
    }
    
    /** Called when a segment fetches a block that it believes to be relevant to us */
    public void onFetchedRelevantBlock(SplitFileFetcherSegmentStorage segment, int blockNo) {
        short priorityClass = parent.getPriorityClass();
        synchronized(this) {
            boolean found = false;
            for(int i=0;i<segments.length;i++) {
                if(segments[i] == segment && blockNumbers[i] == blockNo) {
                    found = true;
                    if(blocksFound[i]) {
                        // Already handled, don't loop.
                        return;
                    }
                    blocksFound[i] = true;
                    totalFound++;
                }
            }
            if(tryDecode || succeeded || cancelled) return;
            if(!found) {
                Logger.warning(this, "Block "+blockNo+" on "+segment+" not wanted by "+this);
                return;
            }
            if(totalFound < dataBlockCount) {
                if(logMINOR) Logger.minor(this, "Not decoding "+this+" : found "+totalFound+" blocks of "+dataBlockCount+" (total "+segments.length+")");
                return;
            }
            tryDecodeOrEncode(priorityClass);
        }
    }
    
    private synchronized void tryDecodeOrEncode(final short prio) {
        if(succeeded) return;
        if(tryDecode) return;
        if(cancelled) return;
        long limit = totalBlocks * CHKBlock.DATA_LENGTH + 
            Math.max(parent.fecCodec.maxMemoryOverheadDecode(dataBlockCount, crossCheckBlockCount),
                    parent.fecCodec.maxMemoryOverheadEncode(dataBlockCount, crossCheckBlockCount));
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
                    innerDecode();
                } catch (IOException e) {
                    Logger.error(this, "Failed to decode "+this+" because of disk error: "+e, e);
                    parent.failOnDiskError(e);
                } catch (PersistenceDisabledException e) {
                    shutdown = true;
                } finally {
                    chunk.release();
                    try {
                        if(!shutdown) {
                            // We do want to call the callback even if we threw something, because we 
                            // may be waiting to cancel. However we DON'T call it if we are shutting down.
                            synchronized(SplitFileFetcherCrossSegmentStorage.this) {
                                tryDecode = false;
                            }
                            parent.finishedEncoding(SplitFileFetcherCrossSegmentStorage.this);
                        }
                    } finally {
                        // Callback is part of the persistent job, unlock *after* calling it.
                        if(lock != null) lock.unlock(false, MemoryLimitedJobRunner.THREAD_PRIORITY);
                    }
                }
                return true;
            }
            
        });
        tryDecode = true;
    }
    
    /** Attempt FEC decoding. Check blocks before decoding in case there is disk corruption. Check
     * the new decoded blocks afterwards to ensure reproducible behaviour. */
    private void innerDecode() throws IOException {
        if(logMINOR) Logger.minor(this, "Trying to decode "+this+" for "+parent);
        boolean killed = false;
        synchronized(this) {
            if(succeeded) return;
            if(cancelled) {
                killed = true;
            }
        }
        if(killed) {
            return;
        }
        
        // readAllBlocks does most of the housekeeping for us, see below...
        byte[][] dataBlocks = readBlocks(false);
        byte[][] checkBlocks = readBlocks(true);
        if(dataBlocks == null || checkBlocks == null) return; // Failed with disk error.
        
        // Original status.
        boolean[] dataBlocksFound = wasNonNullFill(dataBlocks);
        boolean[] checkBlocksFound = wasNonNullFill(checkBlocks);

        int realTotalDataBlocks = count(dataBlocksFound);
        int realTotalCrossCheckBlocks = count(checkBlocksFound);
        int realTotalFound = realTotalDataBlocks + realTotalCrossCheckBlocks;
        
        if(realTotalFound < dataBlockCount) {
            // Not finished yet.
            return;
        }
        
        boolean decoded = false;
        boolean encoded = false;
        
        if(realTotalDataBlocks < dataBlockCount) {
            // Decode.
            codec.decode(dataBlocks, checkBlocks, dataBlocksFound, checkBlocksFound, 
                    CHKBlock.DATA_LENGTH);
            for(int i=0;i<dataBlockCount;i++) {
                if(!dataBlocksFound[i]) {
                    checkDecodedBlock(i, dataBlocks[i]);
                    dataBlocksFound[i] = true;
                }
            }
        }
        
        if(realTotalCrossCheckBlocks < crossCheckBlockCount) {
            // Decode.
            codec.encode(dataBlocks, checkBlocks, checkBlocksFound, CHKBlock.DATA_LENGTH);
            for(int i=0;i<crossCheckBlockCount;i++) {
                if(!checkBlocksFound[i]) {
                    checkDecodedBlock(i+dataBlockCount, checkBlocks[i]);
                }
            }
        }
        
        synchronized(this) {
            succeeded = true;
        }
        
        if(logMINOR) Logger.minor(this, "Completed a cross-segment: decoded="+decoded+" encoded="+encoded);
    }


    private void checkDecodedBlock(int i, byte[] data) {
        ClientCHK key = getKey(i);
        if(key == null) {
            Logger.error(this, "Key not found");
            failOffThread(new FetchException(FetchExceptionMode.INTERNAL_ERROR, "Key not found"));
            return;
        }
        ClientCHKBlock block = encodeBlock(key, data);
        String decoded = i >= dataBlockCount ? "Encoded" : "Decoded";
        if(block == null || !key.getNodeCHK().equals(block.getKey())) {
            Logger.error(this, decoded+" cross-segment block "+i+" failed!");
            failOffThread(new FetchException(FetchExceptionMode.SPLITFILE_DECODE_ERROR, decoded+" cross-segment block does not match expected key"));
            return;
        } else {
            reportBlockToSegmentOffThread(i, key, block, data);
        }
    }

    private ClientCHKBlock encodeBlock(ClientCHK key, byte[] data) {
        try {
            return ClientCHKBlock.encodeSplitfileBlock(data, key.getCryptoKey(), key.getCryptoAlgorithm());
        } catch (CHKEncodeException e) {
            return null;
        }
    }

    private void reportBlockToSegmentOffThread(final int blockNo, final ClientCHK key, 
            final ClientCHKBlock block, final byte[] data) {
        parent.jobRunner.queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                try {
                    // FIXME CPU USAGE Add another API to the segment to avoid re-decoding.
                    SplitFileSegmentKeys keys = segments[blockNo].getSegmentKeys();
                    if(keys == null) return false;
                    boolean success = segments[blockNo].innerOnGotKey(key.getNodeCHK(), block, keys, 
                            blockNumbers[blockNo], data);
                    if(success) {
                        if(logMINOR)
                            Logger.minor(this, "Successfully decoded cross-segment block");
                    } else {
                        // Not really a big deal, but potentially interesting...
                        Logger.warning(this, "Decoded cross-segment block but not wanted by segment");
                    }
                } catch (IOException e) {
                    parent.failOnDiskError(e);
                    return true;
                }
                return false;
            }
        });
    }

    private void failOffThread(final FetchException e) {
        parent.jobRunner.queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                parent.fail(e);
                return true;
            }
            
        });
    }

    private void failDiskOffThread(final IOException e) {
        parent.jobRunner.queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                parent.failOnDiskError(e);
                return true;
            }
            
        });
    }

    private ClientCHK getKey(int i) {
        return segments[i].getKey(blockNumbers[i]);
    }

    private static boolean[] wasNonNullFill(byte[][] blocks) {
        boolean[] nonNulls = new boolean[blocks.length];
        for(int i=0;i<blocks.length;i++) {
            if(blocks[i] == null) {
                blocks[i] = new byte[CHKBlock.DATA_LENGTH];
            } else {
                nonNulls[i] = true;
            }
        }
        return nonNulls;
    }

    /** Read all blocks from all segments, checking the contents of the block against each key.
     * @param If false, read data blocks, if true, read check blocks. (The FEC code takes separate
     * arrays).
     * @return An array of blocks, in the correct order. Each element is either a valid block or
     * null if the block is invalid or hasn't been fetched yet. Will tell the ordinary segment if 
     * the block is bogus. Will also update our blocksFound. */
    
    private byte[][] readBlocks(boolean checkBlocks) {
        int start = checkBlocks ? dataBlockCount : 0;
        int end = checkBlocks ? totalBlocks : dataBlockCount;
        byte[][] blocks = new byte[end-start][];
        for(int i=start;i<end;i++) {
            try {
                byte[] block = segments[i].checkAndGetBlockData(blockNumbers[i]);
                blocks[i-start] = block;
                synchronized(this) {
                    if(block != null) {
                        if(!blocksFound[i]) totalFound++;
                        blocksFound[i] = true;
                    } else {
                        if(blocksFound[i]) totalFound--;
                        blocksFound[i] = false;
                    }
                }
            } catch (IOException e) {
                failDiskOffThread(e);
                return null;
            }
        }
        return blocks;
    }
    
    private static int count(boolean[] array) {
        int total = 0;
        for(boolean b : array)
            if(b) total++;
        return total;
    }

    public void addDataBlock(SplitFileFetcherSegmentStorage seg, int blockNum) {
        segments[counter] = seg;
        blockNumbers[counter] = blockNum;
        counter++;
    }
    
    public synchronized boolean isDecoding() {
        return tryDecode;
    }

    public void writeFixedMetadata(DataOutputStream dos) throws IOException {
        dos.writeInt(dataBlockCount);
        dos.writeInt(crossCheckBlockCount);
        for(int i=0;i<totalBlocks;i++) {
            dos.writeInt(segments[i].segNo);
            dos.writeInt(blockNumbers[i]);
        }
    }
    
    public SplitFileFetcherCrossSegmentStorage(SplitFileFetcherStorage parent, int segNo,
            DataInputStream dis) throws IOException, StorageFormatException {
        this.parent = parent;
        this.crossSegmentNumber = segNo;
        this.codec = parent.fecCodec;
        this.dataBlockCount = dis.readInt();
        this.crossCheckBlockCount = dis.readInt();
        this.totalBlocks = dataBlockCount + crossCheckBlockCount;
        blocksFound = new boolean[totalBlocks];
        segments = new SplitFileFetcherSegmentStorage[totalBlocks];
        blockNumbers = new int[totalBlocks];
        for(int i=0;i<totalBlocks;i++) {
            int readSeg = dis.readInt();
            if(readSeg < 0 || readSeg >= parent.segments.length)
                throw new StorageFormatException("Invalid segment number "+readSeg);
            SplitFileFetcherSegmentStorage segment = parent.segments[readSeg];
            this.segments[i] = segment;
            int blockNo = dis.readInt();
            if(blockNo < 0 || blockNo >= segment.totalBlocks())
                throw new StorageFormatException("Invalid block number "+blockNo+" for segment "+segment.segNo);
            this.blockNumbers[i] = blockNo;
            segment.resumeCallback(blockNo, this);
        }
    }
    
    /** Should be called before scheduling, unlike restart(). Doesn't lock, i.e. part of 
     * construction. But we must have read metadata on the regular segments first, which won't be 
     * true in the constructor. */
    public void checkBlocks() {
        for(int i=0;i<totalBlocks;i++) {
            if(segments[i].hasBlock(blockNumbers[i])) {
                blocksFound[i] = true;
                totalFound++;
            }
        }
    }

    /** Check for blocks and try to decode. */
    public void restart() {
        synchronized(this) {
            if(succeeded) return;
        }
        short priorityClass = parent.getPriorityClass();
        synchronized(this) {
            if(totalBlocks < dataBlockCount) return;
            tryDecodeOrEncode(priorityClass);
        }
    }
    
    public void cancel() {
        synchronized(this) {
            cancelled = true;
            if(tryDecode) return;
            succeeded = true;
        }
        parent.finishedEncoding(this);
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

}
