package freenet.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import freenet.client.ArchiveManager.ARCHIVE_TYPE;
import freenet.client.ClientMetadata;
import freenet.client.FECCodec;
import freenet.client.FailureCodeTracker;
import freenet.client.InsertContext;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.Metadata;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.client.InsertException;
import freenet.client.Metadata.SplitfileAlgorithm;
import freenet.client.MetadataParseException;
import freenet.client.async.SplitFileInserterSegmentStorage.BlockInsert;
import freenet.client.async.SplitFileInserterSegmentStorage.MissingKeyException;
import freenet.crypt.ChecksumChecker;
import freenet.crypt.ChecksumFailedException;
import freenet.crypt.HashResult;
import freenet.crypt.MasterSecret;
import freenet.keys.CHKBlock;
import freenet.keys.ClientCHK;
import freenet.node.KeysFetchingLocally;
import freenet.support.HexUtil;
import freenet.support.Logger;
import freenet.support.MemoryLimitedJobRunner;
import freenet.support.RandomArrayIterator;
import freenet.support.Ticker;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.api.LockableRandomAccessBuffer;
import freenet.support.api.LockableRandomAccessBufferFactory;
import freenet.support.api.LockableRandomAccessBuffer.RAFLock;
import freenet.support.compress.Compressor.COMPRESSOR_TYPE;
import freenet.support.io.ArrayBucket;
import freenet.support.io.ArrayBucketFactory;
import freenet.support.io.BucketTools;
import freenet.support.io.FilenameGenerator;
import freenet.support.io.PersistentFileTracker;
import freenet.support.io.NullBucket;
import freenet.support.io.RAFInputStream;
import freenet.support.io.ResumeFailedException;
import freenet.support.io.StorageFormatException;
import freenet.support.math.MersenneTwister;

/**
 * Similar to SplitFileFetcherStorage. The status of a splitfile insert,
 * including the encoded check and cross-check blocks, is stored in a
 * RandomAccessBuffer separate to that containing the data itself. This class is
 * only concerned with encoding, storage etc, and should have as few
 * dependencies on the runtime as possible, partly so that it can be tested in
 * isolation. Actual details of inserting the blocks will be kept on
 * SplitFileInserter.
 * 
 * CONTENTS OF FILE: (for persistent case, transient leaves out most of the below)
 * * Magic, version etc. 
 * * Basic settings. 
 * * Settings for each segment. 
 * * Settings for each cross-segment (including block lists). 
 * * Padded last block (if necessary)
 * * Global status 
 * * (Padding to a 4096 byte boundary) 
 * * Cross-check blocks (by cross-segment). 
 * * Check blocks 
 * * Segment status 
 * * Segment key list (each key separately stored and checksummed)
 * 
 * Intentionally not as robust (against disk corruption in particular) as SplitFileFetcherStorage: 
 * We encode the block CHKs when we encode the check blocks, and if the block data has changed by
 * the time we insert the data, we fail; there's no way to obtain correct data. Similarly, we fail
 * if the keys are corrupted. However, for most of the duration of the insert neither the data, the
 * check blocks or the keys will be written, so it's still reasonable assuming you only get errrors
 * when writing, and it isn't really possible to improve on this much anyway...
 * 
 * @author toad
 * 
 */
public class SplitFileInserterStorage {

    private static volatile boolean logMINOR;
    private static volatile boolean logDEBUG;
    static {
        Logger.registerClass(SplitFileInserterStorage.class);
    }

    /** The original file to upload */
    final LockableRandomAccessBuffer originalData;
    /** The RAF containing check blocks, status etc. */
    private final LockableRandomAccessBuffer raf;
    private final long rafLength;
    /** Is the request persistent? */
    final boolean persistent;
    final SplitFileInserterStorageCallback callback;

    final SplitFileInserterSegmentStorage[] segments;
    final SplitFileInserterCrossSegmentStorage[] crossSegments;

    /** Random iterator for segment selection. LOCKING: cooldownLock must be held. */
    private final RandomArrayIterator<SplitFileInserterSegmentStorage> randomSegmentIterator;

    final int totalDataBlocks;
    final int totalCheckBlocks;

    /** FEC codec used to encode check and cross-check blocks */
    final FECCodec codec;

    /**
     * Length in bytes of the data being uploaded, i.e. the original file,
     * ignoring padding, check blocks etc.
     */
    final long dataLength;

    // These are kept for creating Metadata etc.
    /** MIME type etc. */
    private final ClientMetadata clientMetadata;
    /** Is the splitfile metadata? */
    private final boolean isMetadata;
    /** Compression codec that should be used to decompress the data. We do not
     * do the compression here but we need it to generate the Metadata. */
    private final COMPRESSOR_TYPE compressionCodec;
    /** Length of the file after decompression. */
    private final long decompressedLength;
    /** For reinserting old splitfiles etc. */
    private final CompatibilityMode cmode;
    private final byte[] hashThisLayerOnly;
    private final ARCHIVE_TYPE archiveType;
    
    // Top level stuff
    private final HashResult[] hashes;
    private final boolean topDontCompress;
    final int topRequiredBlocks;
    final int topTotalBlocks;
    private final long origDataSize;
    private final long origCompressedDataSize;

    /** Type of splitfile */
    private final SplitfileAlgorithm splitfileType;
    /** Nominal number of data blocks per segment. */
    private final int segmentSize;
    /** Nominal number of check blocks per segment. */
    private final int checkSegmentSize;
    /**
     * Number of segments which have 1 fewer block than segmentSize. Not
     * necessarily valid for very old compatibility modes.
     */
    private final int deductBlocksFromSegments;
    /**
     * Number of cross-check blocks per segment and therefore also per
     * cross-segment.
     */
    private final int crossCheckBlocks;

    /** For modern splitfiles, the crypto key is the same for every block. */
    private final byte[] splitfileCryptoKey;
    /** Crypto algorithm is the same for every block. */
    private final byte splitfileCryptoAlgorithm;
    /**
     * If true, the splitfile crypto key must be included in the metadata. If
     * false, it was auto-generated so can be left implicit.
     */
    private final boolean specifySplitfileKeyInMetadata;

    // Misc settings
    final ChecksumChecker checker;
    /** Length of a key as stored on disk */
    private final int keyLength;
    private final int maxRetries;
    private final int consecutiveRNFsCountAsSuccess;

    // System utilities.
    final MemoryLimitedJobRunner memoryLimitedJobRunner;
    final PersistentJobRunner jobRunner;
    final Ticker ticker;
    final Random random;

    /**
     * True if the size of the file is not exactly divisible by one block. If
     * so, we have the last block, after padding, stored in raf. (This means we
     * can change the padding algorithm slightly more easily)
     */
    private final boolean hasPaddedLastBlock;

    /** Status. Generally depends on the status of the individual segments...
     * Not persisted: Can be deduced from the state of the segments, except for the last 3 states, 
     * which are only used during completion (we don't keep the storage around once we're 
     * finished). */
    enum Status {
        NOT_STARTED, STARTED, ENCODED_CROSS_SEGMENTS, ENCODED, GENERATING_METADATA, SUCCEEDED, FAILED
    }

    private Status status;
    private final FailureCodeTracker errors;
    private boolean overallStatusDirty;
    
    // Not persisted, only used briefly during completion
    private InsertException failing;

    // These are kept here so we can set them in the main constructor after
    // we've constructed the segments.

    /** Offset in originalData to the start of each data segment */
    private final long[] underlyingOffsetDataSegments;
    private final long offsetPaddedLastBlock;
    private final long offsetOverallStatus;
    private final long[] offsetCrossSegmentBlocks;
    private final long[] offsetSegmentCheckBlocks;
    private final long[] offsetSegmentStatus;
    private final long[] offsetCrossSegmentStatus;
    private final long[] offsetSegmentKeys;

    private final int overallStatusLength;
    
    private final Object cooldownLock = new Object();
    private boolean noBlocksToSend;
    
    /**
     * Create a SplitFileInserterStorage.
     * 
     * @param originalData
     *            The original data as a RandomAccessBuffer. We need to be able
     *            to read single blocks.
     * @param rafFactory
     *            A factory (persistent or not as appropriate) used to create
     *            the temporary RAF storing check blocks etc.
     * @param bf
     *            A temporary Bucket factory used for temporarily storing the
     *            cross-segment settings.
     * @param topRequiredBlocks The minimum number of blocks needed to fetch the content, so far.
     * We will add to this for the final metadata.
     * @throws IOException
     * @throws InsertException
     */
    public SplitFileInserterStorage(LockableRandomAccessBuffer originalData,
            long decompressedLength, SplitFileInserterStorageCallback callback,
            COMPRESSOR_TYPE compressionCodec, ClientMetadata meta, boolean isMetadata, 
            ARCHIVE_TYPE archiveType, LockableRandomAccessBufferFactory rafFactory, 
            boolean persistent, InsertContext ctx, byte splitfileCryptoAlgorithm, 
            byte[] splitfileCryptoKey, byte[] hashThisLayerOnly, HashResult[] hashes, 
            BucketFactory bf, ChecksumChecker checker, Random random,
            MemoryLimitedJobRunner memoryLimitedJobRunner, PersistentJobRunner jobRunner,
            Ticker ticker, KeysFetchingLocally keysFetching, 
            boolean topDontCompress, int topRequiredBlocks, int topTotalBlocks, 
            long origDataSize, long origCompressedDataSize) throws IOException, InsertException {
        this.originalData = originalData;
        this.callback = callback;
        this.persistent = persistent;
        dataLength = originalData.size();
        if (dataLength > ((long) Integer.MAX_VALUE) * CHKBlock.DATA_LENGTH)
            throw new InsertException(InsertExceptionMode.TOO_BIG);
        totalDataBlocks = (int) ((dataLength + CHKBlock.DATA_LENGTH - 1) / CHKBlock.DATA_LENGTH);
        this.decompressedLength = decompressedLength;
        this.compressionCodec = compressionCodec;
        this.clientMetadata = meta;
        this.checker = checker;
        this.memoryLimitedJobRunner = memoryLimitedJobRunner;
        this.jobRunner = jobRunner;
        this.isMetadata = isMetadata;
        this.archiveType = archiveType;
        this.hashThisLayerOnly = hashThisLayerOnly;
        this.topDontCompress = topDontCompress;
        this.origDataSize = origDataSize;
        this.origCompressedDataSize = origCompressedDataSize;
        this.maxRetries = ctx.maxInsertRetries;
        this.errors = new FailureCodeTracker(true);
        this.ticker = ticker;
        this.random = random;

        // Work out how many blocks in each segment, crypto keys etc.
        // Complicated by back compatibility, i.e. the need to be able to
        // reinsert old splitfiles.
        // FIXME consider getting rid of support for very old splitfiles.

        int segs;
        cmode = ctx.getCompatibilityMode();
        if(cmode.ordinal() < CompatibilityMode.COMPAT_1255.ordinal()) {
            this.hashes = null;
            splitfileCryptoKey = null;
        } else {
            this.hashes = hashes;
        }
        if (cmode == CompatibilityMode.COMPAT_1250_EXACT) {
            segs = (totalDataBlocks + 128 - 1) / 128;
            segmentSize = 128;
            deductBlocksFromSegments = 0;
        } else {
            if (cmode == CompatibilityMode.COMPAT_1251) {
                // Max 131 blocks per segment.
                segs = (totalDataBlocks + 131 - 1) / 131;
            } else {
                // Algorithm from evanbd, see bug #2931.
                if (totalDataBlocks > 520) {
                    segs = (totalDataBlocks + 128 - 1) / 128;
                } else if (totalDataBlocks > 393) {
                    // maxSegSize = 130;
                    segs = 4;
                } else if (totalDataBlocks > 266) {
                    // maxSegSize = 131;
                    segs = 3;
                } else if (totalDataBlocks > 136) {
                    // maxSegSize = 133;
                    segs = 2;
                } else {
                    // maxSegSize = 136;
                    segs = 1;
                }
            }
            int segSize = (totalDataBlocks + segs - 1) / segs;
            if (ctx.splitfileSegmentDataBlocks < segSize) {
                segs = (totalDataBlocks + ctx.splitfileSegmentDataBlocks - 1)
                        / ctx.splitfileSegmentDataBlocks;
                segSize = (totalDataBlocks + segs - 1) / segs;
            }
            segmentSize = segSize;
            if (cmode == CompatibilityMode.COMPAT_CURRENT
                    || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal()) {
                // Even with basic even segment splitting, it is possible for
                // the last segment to be a lot smaller than the rest.
                // So drop a single data block from each of the last
                // [segmentSize-lastSegmentSize] segments instead.
                // Hence all the segments are within 1 block of segmentSize.
                int lastSegmentSize = totalDataBlocks - (segmentSize * (segs - 1));
                deductBlocksFromSegments = segmentSize - lastSegmentSize;
            } else {
                deductBlocksFromSegments = 0;
            }
        }

        int crossCheckBlocks = 0;

        // Cross-segment splitfile redundancy becomes useful at 20 segments.
        if (segs >= 20
                && (cmode == CompatibilityMode.COMPAT_CURRENT || cmode.ordinal() >= CompatibilityMode.COMPAT_1255
                        .ordinal())) {
            // The optimal number of cross-check blocks per segment (and per
            // cross-segment since there are the same number of cross-segments
            // as segments) is 3.
            crossCheckBlocks = 3;
        }

        this.crossCheckBlocks = crossCheckBlocks;

        this.splitfileType = ctx.getSplitfileAlgorithm();
        this.codec = FECCodec.getInstance(splitfileType);

        checkSegmentSize = codec.getCheckBlocks(segmentSize + crossCheckBlocks, cmode);

        this.splitfileCryptoAlgorithm = splitfileCryptoAlgorithm;
        if (splitfileCryptoKey != null) {
            this.splitfileCryptoKey = splitfileCryptoKey;
            specifySplitfileKeyInMetadata = true;
        } else if (cmode == CompatibilityMode.COMPAT_CURRENT
                || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal()) {
            if (hashThisLayerOnly != null) {
                this.splitfileCryptoKey = Metadata.getCryptoKey(hashThisLayerOnly);
            } else {
                this.splitfileCryptoKey = Metadata.getCryptoKey(hashes);
            }
            specifySplitfileKeyInMetadata = false;
        } else {
            this.splitfileCryptoKey = null;
            specifySplitfileKeyInMetadata = false;
        }

        int totalCheckBlocks = 0;
        int checkTotalDataBlocks = 0;
        underlyingOffsetDataSegments = new long[segs];
        keyLength = SplitFileInserterSegmentStorage.getKeyLength(this);
        this.consecutiveRNFsCountAsSuccess = ctx.consecutiveRNFsCountAsSuccess;
        segments = makeSegments(segmentSize, segs, totalDataBlocks, crossCheckBlocks,
                deductBlocksFromSegments,
                cmode, random, keysFetching, consecutiveRNFsCountAsSuccess);
        randomSegmentIterator = new RandomArrayIterator<SplitFileInserterSegmentStorage>(segments);
        for (SplitFileInserterSegmentStorage segment : segments) {
            totalCheckBlocks += segment.checkBlockCount;
            checkTotalDataBlocks += segment.dataBlockCount;
        }
        assert (checkTotalDataBlocks == totalDataBlocks);
        this.totalCheckBlocks = totalCheckBlocks;

        if (crossCheckBlocks != 0) {
            byte[] seed = Metadata.getCrossSegmentSeed(hashes, hashThisLayerOnly);
            if (logMINOR)
                Logger.minor(this, "Cross-segment seed: " + HexUtil.bytesToHex(seed));
            Random xsRandom = new MersenneTwister(seed);
            // Cross segment redundancy: Allocate the blocks.
            crossSegments = new SplitFileInserterCrossSegmentStorage[segs];
            int segLen = segmentSize;
            for (int i = 0; i < crossSegments.length; i++) {
                if (logMINOR)
                    Logger.minor(this, "Allocating blocks for cross segment " + i);
                if (segments.length - i == deductBlocksFromSegments) {
                    segLen--;
                }

                SplitFileInserterCrossSegmentStorage seg = new SplitFileInserterCrossSegmentStorage(
                        this, i, segLen, crossCheckBlocks);
                crossSegments[i] = seg;
                for (int j = 0; j < segLen; j++) {
                    // Allocate random data blocks
                    allocateCrossDataBlock(seg, xsRandom);
                }
                for (int j = 0; j < crossCheckBlocks; j++) {
                    // Allocate check blocks
                    allocateCrossCheckBlock(seg, xsRandom);
                }
            }
        } else {
            crossSegments = null;
        }

        // Now set up the RAF.
        
        // Setup offset arrays early so we can compute the length of encodeOffsets().
        if(crossSegments != null) {
            offsetCrossSegmentBlocks = new long[crossSegments.length];
            if(persistent)
                offsetCrossSegmentStatus = new long[crossSegments.length];
            else
                offsetCrossSegmentStatus = null;
        } else {
            offsetCrossSegmentBlocks = null;
            offsetCrossSegmentStatus = null;
        }
        
        offsetSegmentCheckBlocks = new long[segments.length];
        
        offsetSegmentKeys = new long[segments.length];
        if(persistent) {
            offsetSegmentStatus = new long[segments.length];
        } else {
            offsetSegmentStatus = null;
        }

        // First we have all the fixed stuff ...

        byte[] paddedLastBlock = null;
        if (dataLength % CHKBlock.DATA_LENGTH != 0) {
            this.hasPaddedLastBlock = true;
            long from = (dataLength / CHKBlock.DATA_LENGTH) * CHKBlock.DATA_LENGTH;
            byte[] buf = new byte[(int) (dataLength - from)];
            this.originalData.pread(from, buf, 0, buf.length);
            paddedLastBlock = BucketTools.pad(buf, CHKBlock.DATA_LENGTH, buf.length);
        } else {
            this.hasPaddedLastBlock = false;
        }
        
        byte[] header = null;
        Bucket segmentSettings = null, crossSegmentSettings = null;
        int offsetsLength = 0;
        if (persistent) {
            header = encodeHeader();
            offsetsLength = encodeOffsets().length;

            segmentSettings = encodeSegmentSettings(); // Checksummed with length
            try {
                crossSegmentSettings = encodeCrossSegmentSettings(bf); // Checksummed with length
            } catch (IOException e) {
                throw new InsertException(InsertExceptionMode.BUCKET_ERROR,
                        "Failed to write to temporary storage while creating splitfile inserter",
                        null);
            }
        }

        long ptr = 0;
        if (persistent) {
            ptr = header.length + offsetsLength + segmentSettings.size() +
                (crossSegmentSettings == null ? 0 : crossSegmentSettings.size());
            offsetOverallStatus = ptr;
            overallStatusLength = encodeOverallStatus().length;
            ptr += overallStatusLength;

            // Pad to a 4KB block boundary.
            int padding = 0;
            padding = (int) (ptr % 4096);
            if (padding != 0)
                padding = 4096 - padding;

            ptr += padding;
        } else {
            overallStatusLength = 0;
            offsetOverallStatus = 0;
        }

        this.offsetPaddedLastBlock = ptr;

        if (hasPaddedLastBlock)
            ptr += CHKBlock.DATA_LENGTH;

        if (crossSegments != null) {
            for (int i = 0; i < crossSegments.length; i++) {
                offsetCrossSegmentBlocks[i] = ptr;
                ptr += crossSegments[i].crossCheckBlockCount * CHKBlock.DATA_LENGTH;
            }
        }

        for (int i = 0; i < segments.length; i++) {
            offsetSegmentCheckBlocks[i] = ptr;
            ptr += segments[i].checkBlockCount * CHKBlock.DATA_LENGTH;
        }

        if (persistent) {
            for (int i = 0; i < segments.length; i++) {
                offsetSegmentStatus[i] = ptr;
                ptr += segments[i].storedStatusLength();
            }

            if (crossSegments != null) {
                for (int i = 0; i < crossSegments.length; i++) {
                    offsetCrossSegmentStatus[i] = ptr;
                    ptr += crossSegments[i].storedStatusLength();
                }
            }
        }
        
        for (int i = 0; i < segments.length; i++) {
            offsetSegmentKeys[i] = ptr;
            ptr += segments[i].storedKeysLength();
        }

        rafLength = ptr;
        this.raf = rafFactory.makeRAF(ptr);
        if (persistent) {
            ptr = 0;
            raf.pwrite(ptr, header, 0, header.length);
            ptr += header.length;
            byte[] encodedOffsets = encodeOffsets();
            assert(encodedOffsets.length == offsetsLength);
            raf.pwrite(ptr, encodedOffsets, 0, encodedOffsets.length);
            ptr += encodedOffsets.length;
            BucketTools.copyTo(segmentSettings, raf, ptr, Long.MAX_VALUE);
            ptr += segmentSettings.size();
            segmentSettings.free();
            if(crossSegmentSettings != null) {
                BucketTools.copyTo(crossSegmentSettings, raf, ptr, Long.MAX_VALUE);
                ptr += crossSegmentSettings.size();
                crossSegmentSettings.free();
            }
            writeOverallStatus(true);
        }
        if (hasPaddedLastBlock)
            raf.pwrite(offsetPaddedLastBlock, paddedLastBlock, 0, paddedLastBlock.length);
        if (persistent) {
            // Padding is initialized to random already.
            for (SplitFileInserterSegmentStorage segment : segments) {
                if(logMINOR) Logger.minor(this, "Clearing status for "+segment);
                segment.storeStatus(true);
            }
            if (crossSegments != null) {
                for (SplitFileInserterCrossSegmentStorage segment : crossSegments) {
                    if(logMINOR) Logger.minor(this, "Clearing status for "+segment);
                    segment.storeStatus();
                }
            }
        }
        // Encrypted RAFs are not initialised with 0's, so we need to clear explicitly (we do store keys even for transient inserts).
        for (SplitFileInserterSegmentStorage segment : segments) {
            segment.clearKeys();
        }
        // Keys are empty, and invalid.
        status = Status.NOT_STARTED;
        
        // Include the cross check blocks in the required blocks. The actual number needed may be 
        // slightly less, but this is consistent with fetching, and also with pre-1468 metadata. 
        int totalCrossCheckBlocks = crossCheckBlocks * segments.length;
        this.topRequiredBlocks = topRequiredBlocks + totalDataBlocks + totalCrossCheckBlocks;
        this.topTotalBlocks = topTotalBlocks + totalDataBlocks + totalCrossCheckBlocks + totalCheckBlocks;
    }

    /** Create a splitfile insert from stored data.
     * @param raf The file the insert was stored to. Caller must resume it before calling constructor.
     * @param originalData The original data to be inserted. Caller must resume it before calling constructor.
     * @param callback The parent callback (e.g. SplitFileInserter).
     * @param random
     * @param memoryLimitedJobRunner
     * @param jobRunner
     * @param ticker
     * @param keysFetching
     * @param persistentFG
     * @param persistentFileTracker
     * @param masterKey
     * @throws IOException 
     * @throws StorageFormatException 
     * @throws ChecksumFailedException 
     * @throws ResumeFailedException 
     */
    public SplitFileInserterStorage(LockableRandomAccessBuffer raf, 
            LockableRandomAccessBuffer originalData, SplitFileInserterStorageCallback callback, Random random, 
            MemoryLimitedJobRunner memoryLimitedJobRunner, PersistentJobRunner jobRunner, 
            Ticker ticker, KeysFetchingLocally keysFetching, FilenameGenerator persistentFG, 
            PersistentFileTracker persistentFileTracker, MasterSecret masterKey) 
    throws IOException, StorageFormatException, ChecksumFailedException, ResumeFailedException {
        this.persistent = true;
        this.callback = callback;
        this.ticker = ticker;
        this.memoryLimitedJobRunner = memoryLimitedJobRunner;
        this.jobRunner = jobRunner;
        this.random = random;
        this.raf = raf;
        rafLength = raf.size();
        InputStream ois = new RAFInputStream(raf, 0, rafLength);
        DataInputStream dis = new DataInputStream(ois);
        long magic = dis.readLong();
        if(magic != MAGIC)
            throw new StorageFormatException("Bad magic");
        int checksumType = dis.readInt();
        try {
            this.checker = ChecksumChecker.create(checksumType);
        } catch (IllegalArgumentException e) {
            throw new StorageFormatException("Bad checksum type");
        }
        InputStream is = checker.checksumReaderWithLength(ois, new ArrayBucketFactory(), 1024*1024);
        dis = new DataInputStream(is);
        int version = dis.readInt();
        if(version != VERSION)
            throw new StorageFormatException("Bad version");
        LockableRandomAccessBuffer rafOrig = BucketTools.restoreRAFFrom(dis, persistentFG, persistentFileTracker, masterKey);
        if(originalData == null) {
            this.originalData = rafOrig;
        } else {
            // Check that it's the same, but use the passed-in one.
            if(!originalData.equals(rafOrig))
                throw new StorageFormatException("Original data restored from different filename! Expected "+originalData+" but restored "+rafOrig);
            this.originalData = originalData;
        }
        this.totalDataBlocks = dis.readInt();
        if(totalDataBlocks <= 0) throw new StorageFormatException("Bad total data blocks "+totalDataBlocks);
        this.totalCheckBlocks = dis.readInt();
        if(totalCheckBlocks <= 0) throw new StorageFormatException("Bad total data blocks "+totalCheckBlocks);
        try {
            this.splitfileType = SplitfileAlgorithm.getByCode(dis.readShort());
        } catch (IllegalArgumentException e) {
            throw new StorageFormatException("Bad splitfile type");
        }
        try {
            this.codec = FECCodec.getInstance(splitfileType);
        } catch (IllegalArgumentException e) {
            throw new StorageFormatException("Bad splitfile codec type");
        }
        this.dataLength = dis.readLong();
        if(dataLength <= 0) throw new StorageFormatException("Bad data length");
        if(dataLength != originalData.size())
            throw new ResumeFailedException("Original data size is "+originalData.size()+" should be "+dataLength);
        if(((dataLength + CHKBlock.DATA_LENGTH - 1) / CHKBlock.DATA_LENGTH) != totalDataBlocks)
            throw new StorageFormatException("Data blocks "+totalDataBlocks+" not compatible with size "+dataLength);
        decompressedLength = dis.readLong();
        if(decompressedLength <= 0)
            throw new StorageFormatException("Bogus decompressed length");
        isMetadata = dis.readBoolean();
        short atype = dis.readShort();
        if(atype == -1) {
            archiveType = null;
        } else {
            archiveType = ARCHIVE_TYPE.getArchiveType(atype);
            if(archiveType == null) throw new StorageFormatException("Unknown archive type "+atype);
        }
        try {
            clientMetadata = ClientMetadata.construct(dis);
        } catch (MetadataParseException e) {
            throw new StorageFormatException("Failed to read MIME type: "+e);
        }
        short codec = dis.readShort();
        if(codec == (short)-1)
            compressionCodec = null;
        else {
            compressionCodec = COMPRESSOR_TYPE.getCompressorByMetadataID(codec);
            if(compressionCodec == null)
                throw new StorageFormatException("Unknown compression codec ID "+codec);
        }
        int segmentCount = dis.readInt();
        if(segmentCount <= 0) throw new StorageFormatException("Bad segment count");
        this.segmentSize = dis.readInt();
        if(segmentSize <= 0) throw new StorageFormatException("Bad segment size");
        this.checkSegmentSize = dis.readInt();
        if(checkSegmentSize <= 0) throw new StorageFormatException("Bad check segment size");
        this.crossCheckBlocks = dis.readInt();
        if(crossCheckBlocks < 0) throw new StorageFormatException("Bad cross-check block count");
        if(segmentSize + checkSegmentSize + crossCheckBlocks > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
            throw new StorageFormatException("Must be no more than "+FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT+" blocks per segment");
        this.splitfileCryptoAlgorithm = dis.readByte();
        if(!Metadata.isValidSplitfileCryptoAlgorithm(splitfileCryptoAlgorithm))
            throw new StorageFormatException("Invalid splitfile crypto algorithm "+splitfileCryptoAlgorithm);
        if(dis.readBoolean()) {
            splitfileCryptoKey = new byte[32];
            dis.readFully(splitfileCryptoKey);
        } else {
            splitfileCryptoKey = null;
        }
        this.keyLength = dis.readInt(); // FIXME validate
        if(keyLength < SplitFileInserterSegmentStorage.getKeyLength(this))
            throw new StorageFormatException("Invalid key length "+keyLength+" should be at least "+
                    SplitFileInserterSegmentStorage.getKeyLength(this));
        int compatMode = dis.readInt();
        if(compatMode < 0 || compatMode > CompatibilityMode.values().length)
            throw new StorageFormatException("Invalid compatibility mode "+compatMode);
        this.cmode = CompatibilityMode.values()[compatMode];
        this.deductBlocksFromSegments = dis.readInt();
        if(deductBlocksFromSegments < 0 || deductBlocksFromSegments > segmentCount)
            throw new StorageFormatException("Bad deductBlocksFromSegments");
        this.maxRetries = dis.readInt();
        if(maxRetries < -1) throw new StorageFormatException("Bad maxRetries");
        this.consecutiveRNFsCountAsSuccess = dis.readInt();
        if(consecutiveRNFsCountAsSuccess < 0)
            throw new StorageFormatException("Bad consecutiveRNFsCountAsSuccess");
        specifySplitfileKeyInMetadata = dis.readBoolean();
        if(dis.readBoolean()) {
            hashThisLayerOnly = new byte[32];
            dis.readFully(hashThisLayerOnly);
        } else {
            hashThisLayerOnly = null;
        }
        topDontCompress = dis.readBoolean();
        topRequiredBlocks = dis.readInt();
        topTotalBlocks = dis.readInt();
        origDataSize = dis.readLong();
        origCompressedDataSize = dis.readLong();
        hashes = HashResult.readHashes(dis);
        dis.close();
        this.hasPaddedLastBlock = (dataLength % CHKBlock.DATA_LENGTH != 0);
        this.segments = new SplitFileInserterSegmentStorage[segmentCount];
        randomSegmentIterator = new RandomArrayIterator<SplitFileInserterSegmentStorage>(segments);
        if(crossCheckBlocks != 0)
            this.crossSegments = new SplitFileInserterCrossSegmentStorage[segmentCount];
        else
            crossSegments = null;
        // Read offsets.
        is = checker.checksumReaderWithLength(ois, new ArrayBucketFactory(), 1024*1024);
        dis = new DataInputStream(is);
        if(hasPaddedLastBlock) {
            offsetPaddedLastBlock = readOffset(dis, rafLength, "offsetPaddedLastBlock");
        } else {
            offsetPaddedLastBlock = 0;
        }
        offsetOverallStatus = readOffset(dis, rafLength, "offsetOverallStatus");
        overallStatusLength = dis.readInt();
        if(overallStatusLength < 0) throw new StorageFormatException("Negative overall status length");
        if(overallStatusLength < FailureCodeTracker.getFixedLength(true))
            throw new StorageFormatException("Bad overall status length");
        // Will be read after offsets
        if(crossSegments != null) {
            offsetCrossSegmentBlocks = new long[crossSegments.length];
            for(int i=0;i<crossSegments.length;i++)
                offsetCrossSegmentBlocks[i] = readOffset(dis, rafLength, "cross-segment block offset");
        } else {
            offsetCrossSegmentBlocks = null;
        }
        offsetSegmentCheckBlocks = new long[segmentCount];
        for(int i=0;i<segmentCount;i++)
            offsetSegmentCheckBlocks[i] = readOffset(dis, rafLength, "segment check block offset");
        offsetSegmentStatus = new long[segmentCount];
        for(int i=0;i<segmentCount;i++)
            offsetSegmentStatus[i] = readOffset(dis, rafLength, "segment status offset");
        if(crossSegments != null) {
            offsetCrossSegmentStatus = new long[crossSegments.length];
            for(int i=0;i<crossSegments.length;i++)
                offsetCrossSegmentStatus[i] = readOffset(dis, rafLength, "cross-segment status offset");
        } else {
            offsetCrossSegmentStatus = null;
        }
        offsetSegmentKeys = new long[segmentCount];
        for(int i=0;i<segmentCount;i++)
            offsetSegmentKeys[i] = readOffset(dis, rafLength, "segment keys offset");
        dis.close();
        // Set up segments...
        underlyingOffsetDataSegments = new long[segmentCount];
        is = checker.checksumReaderWithLength(ois, new ArrayBucketFactory(), 1024*1024);
        dis = new DataInputStream(is);
        long blocks = 0;
        for(int i=0;i<segmentCount;i++) {
            segments[i] = new SplitFileInserterSegmentStorage(this, dis, i, keyLength, 
                    splitfileCryptoAlgorithm, splitfileCryptoKey, random, maxRetries, consecutiveRNFsCountAsSuccess, keysFetching);
            underlyingOffsetDataSegments[i] = blocks * CHKBlock.DATA_LENGTH;
            blocks += segments[i].dataBlockCount;
            assert(underlyingOffsetDataSegments[i] < dataLength);
        }
        dis.close();
        if(blocks != totalDataBlocks)
            throw new StorageFormatException("Total data blocks should be "+totalDataBlocks+" but is "+blocks);
        if(crossSegments != null) {
            is = checker.checksumReaderWithLength(ois, new ArrayBucketFactory(), 1024*1024);
            dis = new DataInputStream(is);
            for(int i=0;i<crossSegments.length;i++) {
                crossSegments[i] = new SplitFileInserterCrossSegmentStorage(this, dis, i);
            }
            dis.close();
        }
        ois.close();
        ois = new RAFInputStream(raf, offsetOverallStatus, rafLength - offsetOverallStatus);
        dis = new DataInputStream(checker.checksumReaderWithLength(ois, new ArrayBucketFactory(), 1024*1024));
        errors = new FailureCodeTracker(true, dis);
        dis.close();
        for(SplitFileInserterSegmentStorage segment : segments) {
            segment.readStatus();
        }
        if(crossSegments != null) {
            for(SplitFileInserterCrossSegmentStorage segment : crossSegments) {
                segment.readStatus();
            }
        }
        computeStatus();
    }
    
    private void computeStatus() {
        status = Status.STARTED;
        if(crossSegments != null) {
            for(SplitFileInserterCrossSegmentStorage segment : crossSegments) {
                if(!segment.isFinishedEncoding()) return;
            }
            status = Status.ENCODED_CROSS_SEGMENTS;
        }
        for(SplitFileInserterSegmentStorage segment : segments) {
            if(!segment.isFinishedEncoding()) return;
        }
        status = Status.ENCODED;
        // Last 3 statuses are only used during completion.
    }

    private long readOffset(DataInputStream dis, long rafLength, String error) throws IOException, StorageFormatException {
        long l = dis.readLong();
        if(l < 0) throw new StorageFormatException("Negative "+error);
        if(l > rafLength) throw new StorageFormatException("Too big "+error);
        return l;
    }
    
    private void writeOverallStatus(boolean force) throws IOException {
        byte[] buf;
        synchronized(this) {
            if(!persistent) return;
            if(!force && !overallStatusDirty) return;
            buf = encodeOverallStatus();
            assert(buf.length == overallStatusLength);
        }
        raf.pwrite(offsetOverallStatus, buf, 0, buf.length);
    }

    private byte[] encodeOverallStatus() {
        ArrayBucket bucket = new ArrayBucket(); // Will be small.
        try {
            OutputStream os = bucket.getOutputStream();
            OutputStream cos = checker.checksumWriterWithLength(os, new ArrayBucketFactory());
            DataOutputStream dos = new DataOutputStream(cos);
            synchronized(this) {
                errors.writeFixedLengthTo(dos);
                overallStatusDirty = false;
            }
            dos.close();
            os.close();
            return bucket.toByteArray();
        } catch (IOException e) {
            throw new Error(e); // Impossible
        }
    }

    private Bucket encodeSegmentSettings() {
        ArrayBucket bucket = new ArrayBucket(); // Will be small.
        try {
            OutputStream os = bucket.getOutputStream();
            OutputStream cos = checker.checksumWriterWithLength(os, new ArrayBucketFactory());
            DataOutputStream dos = new DataOutputStream(cos);
            for (SplitFileInserterSegmentStorage segment : segments) {
                segment.writeFixedSettings(dos);
            }
            dos.close();
            os.close();
            return bucket;
        } catch (IOException e) {
            throw new Error(e); // Impossible
        }
    }

    /**
     * This one could actually be rather large, since it includes the listing of
     * which blocks go in which cross-segments ...
     */
    private Bucket encodeCrossSegmentSettings(BucketFactory bf) throws IOException {
        if (crossSegments == null)
            return new NullBucket();
        Bucket bucket = bf.makeBucket(-1);
        OutputStream os = bucket.getOutputStream();
        OutputStream cos = checker.checksumWriterWithLength(os, new ArrayBucketFactory());
        DataOutputStream dos = new DataOutputStream(cos);
        for (SplitFileInserterCrossSegmentStorage segment : crossSegments) {
            segment.writeFixedSettings(dos);
        }
        dos.close();
        os.close();
        return bucket;
    }

    /** Includes magic, version, length, basic settings, checksum. */
    private byte[] encodeHeader() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            dos.writeLong(MAGIC);
            dos.writeInt(checker.getChecksumTypeID());
            OutputStream os = checker.checksumWriterWithLength(baos, new ArrayBucketFactory());
            dos = new DataOutputStream(os);
            dos.writeInt(VERSION);
            originalData.storeTo(dos);
            dos.writeInt(totalDataBlocks);
            dos.writeInt(totalCheckBlocks);
            dos.writeShort(splitfileType.code); // And hence the FECCodec
            dos.writeLong(dataLength);
            dos.writeLong(decompressedLength);
            dos.writeBoolean(isMetadata);
            if(archiveType == null)
                dos.writeShort((short) -1);
            else
                dos.writeShort(archiveType.metadataID);
            clientMetadata.writeTo(dos);
            if (compressionCodec == null)
                dos.writeShort((short) -1);
            else
                dos.writeShort(compressionCodec.metadataID);
            dos.writeInt(segments.length);
            dos.writeInt(segmentSize);
            dos.writeInt(checkSegmentSize);
            dos.writeInt(crossCheckBlocks);
            dos.writeByte(this.splitfileCryptoAlgorithm);
            dos.writeBoolean(this.splitfileCryptoKey != null);
            if (this.splitfileCryptoKey != null) {
                assert (splitfileCryptoKey.length == 32);
                dos.write(splitfileCryptoKey);
            }
            dos.writeInt(keyLength);
            dos.writeInt(cmode.ordinal());
            // hasPaddedLastBlock will be recomputed.
            dos.writeInt(deductBlocksFromSegments);
            dos.writeInt(maxRetries);
            dos.writeInt(consecutiveRNFsCountAsSuccess);
            dos.writeBoolean(specifySplitfileKeyInMetadata);
            dos.writeBoolean(hashThisLayerOnly != null);
            if(hashThisLayerOnly != null) {
                assert(hashThisLayerOnly.length == 32);
                dos.write(hashThisLayerOnly);
            }
            // Top level stuff
            dos.writeBoolean(topDontCompress);
            dos.writeInt(topRequiredBlocks);
            dos.writeInt(topTotalBlocks);
            dos.writeLong(origDataSize);
            dos.writeLong(origCompressedDataSize);
            HashResult.write(hashes, dos);
            dos.close();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new Error(e); // Impossible
        }
    }
    
    /** Encode the offsets. */
    private byte[] encodeOffsets() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            OutputStream os = checker.checksumWriterWithLength(baos, new ArrayBucketFactory());
            DataOutputStream dos = new DataOutputStream(os);
            if(this.hasPaddedLastBlock)
                dos.writeLong(offsetPaddedLastBlock);
            dos.writeLong(offsetOverallStatus);
            dos.writeInt(overallStatusLength);
            if(crossSegments != null) {
                for(long l : offsetCrossSegmentBlocks)
                    dos.writeLong(l);
            }
            for(long l : offsetSegmentCheckBlocks)
                dos.writeLong(l);
            for(long l : offsetSegmentStatus)
                dos.writeLong(l);
            if(crossSegments != null) {
                for(long l : offsetCrossSegmentStatus)
                    dos.writeLong(l);
            }
            for(long l : offsetSegmentKeys)
                dos.writeLong(l);
            dos.close();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new Error(e); // Impossible
        }
    }            

    private void allocateCrossDataBlock(SplitFileInserterCrossSegmentStorage segment, Random xsRandom) {
        int x = 0;
        for (int i = 0; i < 10; i++) {
            x = xsRandom.nextInt(segments.length);
            SplitFileInserterSegmentStorage seg = segments[x];
            int blockNum = seg.allocateCrossDataBlock(xsRandom);
            if (blockNum >= 0) {
                segment.addDataBlock(seg, blockNum);
                return;
            }
        }
        for (int i = 0; i < segments.length; i++) {
            x++;
            if (x == segments.length)
                x = 0;
            SplitFileInserterSegmentStorage seg = segments[x];
            int blockNum = seg.allocateCrossDataBlock(xsRandom);
            if (blockNum >= 0) {
                segment.addDataBlock(seg, blockNum);
                return;
            }
        }
        throw new IllegalStateException("Unable to allocate cross data block!");
    }

    private void allocateCrossCheckBlock(SplitFileInserterCrossSegmentStorage segment, Random xsRandom) {
        int x = 0;
        for (int i = 0; i < 10; i++) {
            x = xsRandom.nextInt(segments.length);
            SplitFileInserterSegmentStorage seg = segments[x];
            int blockNum = seg.allocateCrossCheckBlock(segment, xsRandom,
                    segment.getAllocatedCrossCheckBlocks());
            if (blockNum >= 0) {
                segment.addCheckBlock(seg, blockNum);
                return;
            }
        }
        for (int i = 0; i < segments.length; i++) {
            x++;
            if (x == segments.length)
                x = 0;
            SplitFileInserterSegmentStorage seg = segments[x];
            int blockNum = seg.allocateCrossCheckBlock(segment, xsRandom,
                    segment.getAllocatedCrossCheckBlocks());
            if (blockNum >= 0) {
                segment.addCheckBlock(seg, blockNum);
                return;
            }
        }
        throw new IllegalStateException("Unable to allocate cross data block!");
    }

    private SplitFileInserterSegmentStorage[] makeSegments(int segmentSize, int segCount,
            int dataBlocks, int crossCheckBlocks, int deductBlocksFromSegments,
            CompatibilityMode cmode, Random random, KeysFetchingLocally keysFetching, 
            int consecutiveRNFsCountAsSuccess) {
        SplitFileInserterSegmentStorage[] segments = new SplitFileInserterSegmentStorage[segCount];
        if (segCount == 1) {
            // Single segment
            int checkBlocks = codec.getCheckBlocks(dataBlocks + crossCheckBlocks, cmode);
            segments[0] = new SplitFileInserterSegmentStorage(this, 0, dataBlocks,
                    checkBlocks, crossCheckBlocks, keyLength, splitfileCryptoAlgorithm, splitfileCryptoKey, random, 
                    maxRetries, consecutiveRNFsCountAsSuccess, keysFetching);
        } else {
            int j = 0;
            int segNo = 0;
            int data = segmentSize;
            int check = codec.getCheckBlocks(data + crossCheckBlocks, cmode);
            for (int i = segmentSize;;) {
                this.underlyingOffsetDataSegments[segNo] = (long)j * CHKBlock.DATA_LENGTH;
                if (i > dataBlocks)
                    i = dataBlocks;
                if (data > (i - j)) {
                    // Last segment.
                    assert (segNo == segCount - 1);
                    data = i - j;
                    check = codec.getCheckBlocks(data + crossCheckBlocks, cmode);
                }
                j = i;
                segments[segNo] = new SplitFileInserterSegmentStorage(this, segNo,
                        data, check, crossCheckBlocks, keyLength, splitfileCryptoAlgorithm, splitfileCryptoKey, 
                        random, maxRetries, consecutiveRNFsCountAsSuccess, keysFetching);

                if (deductBlocksFromSegments != 0)
                    if (logMINOR)
                        Logger.minor(this, "INSERTING: Segment " + segNo + " of " + segCount
                                + " : " + data + " data blocks " + check + " check blocks");

                segNo++;
                if (i == dataBlocks)
                    break;
                // Deduct one block from each later segment, rather than having
                // a really short last segment.
                if (segCount - segNo == deductBlocksFromSegments) {
                    data--;
                    // Don't change check.
                }
                i += data;
            }
            assert (segNo == segCount);
        }
        return segments;
    }

    public void start() {
        boolean startSegments = (crossSegments == null);
        synchronized (this) {
            if(status == Status.NOT_STARTED) {
                status = Status.STARTED;
            }
            if(status == Status.ENCODED_CROSS_SEGMENTS) startSegments = true;
            if(status == Status.ENCODED) return;
            if(status == Status.FAILED || status == Status.GENERATING_METADATA || 
                    status == Status.SUCCEEDED) return;
        }
        for(SplitFileInserterSegmentStorage segment : segments)
            segment.checkKeys();
        Logger.normal(this, "Starting splitfile, "+countEncodedSegments()+"/"+segments.length+" segments encoded on "+this);
        if(crossSegments != null)
            Logger.normal(this, "Starting splitfile, "+countEncodedCrossSegments()+"/"+crossSegments.length+" cross-segments encoded on "+this);
        if(startSegments) {
            startSegmentEncode();
        } else {
            // Cross-segment encode must complete before main encode.
            startCrossSegmentEncode();
        }
    }

    public int countEncodedSegments() {
        int total = 0;
        for(SplitFileInserterSegmentStorage segment : segments) {
            if(segment.hasEncoded()) total++;
        }
        return total;
    }

    public int countEncodedCrossSegments() {
        int total = 0;
        for(SplitFileInserterCrossSegmentStorage segment : crossSegments) {
            if(segment.isFinishedEncoding()) total++;
        }
        return total;
    }

    private void startSegmentEncode() {
        short prio = callback.getPriorityClass();
        for (SplitFileInserterSegmentStorage segment : segments)
            segment.startEncode(prio);
    }

    private void startCrossSegmentEncode() {
        short prio = callback.getPriorityClass();
        // Start cross-segment encode.
        for (SplitFileInserterCrossSegmentStorage segment : crossSegments)
            segment.startEncode(prio);
    }

    /** Called when a cross-segment finishes encoding blocks. Can be called inside locks as it runs
     * off-thread.
     */
    public void onFinishedEncoding() {
        jobRunner.queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                synchronized(cooldownLock) {
                    noBlocksToSend = false;
                }
                callback.encodingProgress();
                if(maybeFail()) return true;
                if(allFinishedCrossEncoding()) {
                    onCompletedCrossSegmentEncode();
                }
                return false;
            }
            
        });
    }

    private boolean allFinishedCrossEncoding() {
        for (SplitFileInserterCrossSegmentStorage segment : crossSegments) {
            if (!segment.isFinishedEncoding())
                return false;
        }
        return true;
    }

    /** Called when a segment finishes encoding blocks. Can be called inside locks as it runs
     * off-thread.
     * @param completed
     */
    public void onFinishedEncoding(final SplitFileInserterSegmentStorage completed) {
        jobRunner.queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                synchronized(cooldownLock) {
                    noBlocksToSend = false;
                }
                completed.storeStatus(true);
                callback.encodingProgress();
                if(maybeFail()) return true;
                if(allFinishedEncoding()) {
                    onCompletedSegmentEncode();
                }
                return false;
            }
            
        });
    }

    private boolean allFinishedEncoding() {
        for (SplitFileInserterSegmentStorage segment : segments) {
            if (!segment.isFinishedEncoding())
                return false;
        }
        return true;
    }

    /** Called when we have completed encoding all the cross-segments */
    private void onCompletedCrossSegmentEncode() {
        synchronized (this) {
            if (status == Status.ENCODED_CROSS_SEGMENTS) return; // Race condition.
            if (status != Status.STARTED) {
                Logger.error(this, "Wrong state " + status+" for "+this, new Exception("error"));
                return;
            }
            status = Status.ENCODED_CROSS_SEGMENTS;
        }
        startSegmentEncode();
    }

    private void onCompletedSegmentEncode() {
        synchronized (this) {
            if(status == Status.ENCODED) return; // Race condition.
            if (!(status == Status.ENCODED_CROSS_SEGMENTS || (crossSegments == null && status == Status.STARTED))) {
                Logger.error(this, "Wrong state " + status+" for "+this, new Exception("error"));
                return;
            }
            status = Status.ENCODED;
        }
        callback.onFinishedEncode();
    }
    
    public void onHasKeys() {
        for (SplitFileInserterSegmentStorage segment : segments) {
            if (!segment.hasKeys())
                return;
        }
        callback.onHasKeys();
    }
    
    /**
     * Create an OutputStream that we can write formatted data to of a specific
     * length. On close(), it checks that the length is as expected, computes
     * the checksum, and writes the data to the specified position in the file.
     * 
     * @param fileOffset
     *            The position in the file (raf) of the first byte.
     * @param length
     *            The length, including checksum, of the data to be written.
     * @return
     */
    OutputStream writeChecksummedTo(final long fileOffset, final int length) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream(length);
        OutputStream cos = checker.checksumWriter(baos);
        return new FilterOutputStream(cos) {

            public void close() throws IOException {
                out.close();
                byte[] buf = baos.toByteArray();
                if (buf.length != length)
                    throw new IllegalStateException("Wrote wrong number of bytes: " + buf.length
                            + " should be " + length);
                raf.pwrite(fileOffset, buf, 0, length);
            }

        };
    }

    long segmentStatusOffset(int segNo) {
        return offsetSegmentStatus[segNo];
    }

    long crossSegmentStatusOffset(int segNo) {
        return offsetCrossSegmentStatus[segNo];
    }

    static final long MAGIC = 0x4d2a3f596bbf5de5L;
    static final int VERSION = 1;

    public boolean hasSplitfileKey() {
        return splitfileCryptoKey != null;
    }

    /**
     * Write a cross-check block to disk
     * 
     * @throws IOException
     */
    void writeCheckBlock(int segNo, int checkBlockNo, byte[] buf) throws IOException {
        synchronized (this) {
            if (status == Status.ENCODED || status == Status.ENCODED_CROSS_SEGMENTS)
                throw new IllegalStateException("Already encoded!?");
        }
        assert (segNo >= 0 && segNo < crossSegments.length);
        assert (checkBlockNo >= 0 && checkBlockNo < crossCheckBlocks);
        assert (buf.length == CHKBlock.DATA_LENGTH);
        long offset = offsetCrossSegmentBlocks[segNo] + checkBlockNo * CHKBlock.DATA_LENGTH;
        raf.pwrite(offset, buf, 0, buf.length);
    }

    public byte[] readCheckBlock(int segNo, int checkBlockNo) throws IOException {
        assert (segNo >= 0 && segNo < crossSegments.length);
        assert (checkBlockNo >= 0 && checkBlockNo < crossCheckBlocks);
        long offset = offsetCrossSegmentBlocks[segNo] + checkBlockNo * CHKBlock.DATA_LENGTH;
        byte[] buf = new byte[CHKBlock.DATA_LENGTH];
        raf.pread(offset, buf, 0, buf.length);
        return buf;
    }

    /**
     * Lock the main RAF open to avoid the pooled fd being closed when we are
     * doing a major I/O operation involving many reads/writes.
     */
    RAFLock lockRAF() throws IOException {
        return raf.lockOpen();
    }

    /**
     * Lock the originalData RAF open to avoid the pooled fd being closed when
     * we are doing a major I/O operation involving many reads/writes.
     * 
     * @throws IOException
     */
    RAFLock lockUnderlying() throws IOException {
        return originalData.lockOpen();
    }

    public byte[] readSegmentDataBlock(int segNo, int blockNo) throws IOException {
        assert (segNo >= 0 && segNo < segments.length);
        assert (blockNo >= 0 && blockNo < segments[segNo].dataBlockCount);
        byte[] buf = new byte[CHKBlock.DATA_LENGTH];
        if (hasPaddedLastBlock) {
            if (segNo == segments.length - 1 && blockNo == segments[segNo].dataBlockCount - 1) {
                // Don't need to lock, locking is just an optimisation.
                raf.pread(offsetPaddedLastBlock, buf, 0, buf.length);
                return buf;
            }
        }
        long offset = underlyingOffsetDataSegments[segNo] + blockNo * CHKBlock.DATA_LENGTH;
        assert(offset < dataLength);
        assert(offset + buf.length <= dataLength);
        originalData.pread(offset, buf, 0, buf.length);
        return buf;
    }

    public void writeSegmentCheckBlock(int segNo, int checkBlockNo, byte[] buf) throws IOException {
        assert (segNo >= 0 && segNo < segments.length);
        assert (checkBlockNo >= 0 && checkBlockNo < segments[segNo].checkBlockCount);
        assert (buf.length == CHKBlock.DATA_LENGTH);
        long offset = offsetSegmentCheckBlocks[segNo] + checkBlockNo * CHKBlock.DATA_LENGTH;
        raf.pwrite(offset, buf, 0, buf.length);
    }
    
    public byte[] readSegmentCheckBlock(int segNo, int checkBlockNo) throws IOException {
        assert (segNo >= 0 && segNo < segments.length);
        assert (checkBlockNo >= 0 && checkBlockNo < segments[segNo].checkBlockCount);
        byte[] buf = new byte[CHKBlock.DATA_LENGTH];
        long offset = offsetSegmentCheckBlocks[segNo] + checkBlockNo * CHKBlock.DATA_LENGTH;
        raf.pread(offset, buf, 0, buf.length);
        return buf;
    }
    
    /** Encode the Metadata. The caller must ensure that all segments have encoded keys first.
     * @throws MissingKeyException This indicates disk corruption or a bug (e.g. not all segments
     * had encoded keys). Since we don't checksum the blocks, there isn't much point in trying to
     * recover from losing a key; but at least we can detect that there was a problem.
     * 
     * (Package-visible for unit tests)
     */
    Metadata encodeMetadata() throws IOException, MissingKeyException {
        ClientCHK[] dataKeys = new ClientCHK[totalDataBlocks + crossCheckBlocks * segments.length];
        ClientCHK[] checkKeys = new ClientCHK[totalCheckBlocks];
        int dataPtr = 0;
        int checkPtr = 0;
        for(int segNo = 0; segNo < segments.length; segNo++) {
            SplitFileInserterSegmentStorage segment = segments[segNo];
            for(int i=0;i<segment.dataBlockCount+segment.crossCheckBlockCount;i++) {
                dataKeys[dataPtr++] = segment.readKey(i);
            }
            for(int i=0;i<segment.checkBlockCount;i++) {
                checkKeys[checkPtr++] = segment.readKey(i+segment.dataBlockCount+segment.crossCheckBlockCount);
            }
        }
        assert(dataPtr == dataKeys.length);
        assert(checkPtr == checkKeys.length);
        return new Metadata(splitfileType, dataKeys, checkKeys, segmentSize, checkSegmentSize, 
                deductBlocksFromSegments, clientMetadata, dataLength, archiveType, compressionCodec, 
                decompressedLength, isMetadata, hashes, hashThisLayerOnly, origDataSize, 
                origCompressedDataSize, topRequiredBlocks, topTotalBlocks, topDontCompress, 
                cmode, splitfileCryptoAlgorithm, splitfileCryptoKey, 
                specifySplitfileKeyInMetadata, crossCheckBlocks);
    }

    void innerWriteSegmentKey(int segNo, int blockNo, byte[] buf) throws IOException {
        assert (buf.length == SplitFileInserterSegmentStorage.getKeyLength(this));
        assert (segNo >= 0 && segNo < segments.length);
        assert (blockNo >= 0 && blockNo < segments[segNo].totalBlockCount);
        long fileOffset = this.offsetSegmentKeys[segNo] + keyLength * blockNo;
        if(logDEBUG) Logger.debug(this, "Writing key for block "+blockNo+" for segment "+segNo+" of "+this+" to "+fileOffset);
        raf.pwrite(fileOffset, buf, 0, buf.length);
    }
    
    byte[] innerReadSegmentKey(int segNo, int blockNo) throws IOException {
        byte[] buf = new byte[keyLength];
        long fileOffset = this.offsetSegmentKeys[segNo] + keyLength * blockNo;
        if(logDEBUG) Logger.debug(this, "Reading key for block "+blockNo+" for segment "+segNo+" of "+this+" to "+fileOffset);
        raf.pread(fileOffset, buf, 0, buf.length);
        return buf;
    }

    public int totalCrossCheckBlocks() {
        return segments.length * crossCheckBlocks;
    }

    /** Called when a segment completes. Can be called inside locks as it runs off-thread. */
    public void segmentSucceeded(final SplitFileInserterSegmentStorage completedSegment) {
        if(logMINOR) Logger.minor(this, "Succeeded segment "+completedSegment+" for "+callback);
        jobRunner.queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                if(logMINOR) Logger.minor(this, "Succeeding segment "+completedSegment+" for "+callback);
                if(maybeFail()) return true;
                if(allSegmentsSucceeded()) {
                    synchronized(this) {
                        assert(failing == null);
                        if(hasFinished()) return false;
                        status = Status.GENERATING_METADATA;
                    }
                    if(logMINOR) Logger.minor(this, "Generating metadata...");
                    try {
                        Metadata metadata = encodeMetadata();
                        synchronized(this) {
                            status = Status.SUCCEEDED;
                        }
                        callback.onSucceeded(metadata);
                    } catch (IOException e) {
                        InsertException e1 = new InsertException(InsertExceptionMode.BUCKET_ERROR);
                        synchronized(this) {
                            failing = e1;
                            status = Status.FAILED;
                        }
                        callback.onFailed(e1);
                    } catch (MissingKeyException e) {
                        // Fail here too. If we're getting disk corruption on keys, we're probably 
                        // getting it on the original data too.
                        InsertException e1 = new InsertException(InsertExceptionMode.BUCKET_ERROR, "Missing keys", null);
                        synchronized(this) {
                            failing = e1;
                            status = Status.FAILED;
                        }
                        callback.onFailed(e1);
                    }
                } else {
                    if(logMINOR) Logger.minor(this, "Not all segments succeeded for "+this);
                }
                return true;
            }
            
        });
    }

    private boolean maybeFail() {
        // Might have failed.
        // Have to check segments before checking for failure because of race conditions.
        if(allSegmentsCompletedOrFailed()) {
            InsertException e = null;
            synchronized(this) {
                if(failing == null) return false;
                e = failing;
                if(hasFinished()) {
                    if(logMINOR) Logger.minor(this, "Maybe fail returning true because already finished");
                    return true;
                }
                status = Status.FAILED;
            }
            if(logMINOR) Logger.minor(this, "Maybe fail returning true with error "+e);
            callback.onFailed(e);
            return true;
        } else {
            return false;
        }
    }

    private boolean allSegmentsCompletedOrFailed() {
        for(SplitFileInserterSegmentStorage segment : segments) {
            if(!segment.hasCompletedOrFailed()) return false;
        }
        if(crossSegments != null) {
            for(SplitFileInserterCrossSegmentStorage segment : crossSegments) {
                if(!segment.hasCompletedOrFailed()) return false;
            }
        }
        return true;
    }

    private boolean allSegmentsSucceeded() {
        for(SplitFileInserterSegmentStorage segment : segments) {
            if(!segment.hasSucceeded()) return false;
            if(logMINOR) Logger.minor(this, "Succeeded "+segment);
        }
        return true;
    }

    public void addFailure(InsertException e) {
        errors.inc(e.getMode());
        synchronized(this) {
            overallStatusDirty = true;
            lazyWriteMetadata();
        }
    }

    public void failOnDiskError(IOException e) {
        fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null));
    }
    
    public void failFatalErrorInBlock() {
        fail(new InsertException(InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS, errors, null));
    }
    
    public void failTooManyRetriesInBlock() {
        fail(new InsertException(InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS, errors, null));
    }
    
    void fail(final InsertException e) {
        synchronized(this) {
            if(this.status == Status.SUCCEEDED || this.status == Status.FAILED || 
                    this.status == Status.GENERATING_METADATA) {
                // Not serious but often indicates a problem e.g. we are sending requests after completing.
                // So log as ERROR for now.
                Logger.error(this, "Already finished ("+status+") but failing with "+e+" ("+this+")", e);
                return;
            }
            // Only fail once.
            if(failing != null) return;
            failing = e;
        }
        if(e.mode == InsertExceptionMode.BUCKET_ERROR || e.mode == InsertExceptionMode.INTERNAL_ERROR)
            Logger.error(this, "Failing: "+e+" for "+this, e);
        else
            Logger.normal(this, "Failing: "+e+" for "+this, e);
        jobRunner.queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                // Tell the segments to cancel.
                boolean allDone = true;
                for(SplitFileInserterSegmentStorage segment : segments) {
                    if(!segment.cancel()) allDone = false;
                }
                if(crossSegments != null) {
                    for(SplitFileInserterCrossSegmentStorage segment : crossSegments) {
                        if(!segment.cancel()) allDone = false;
                    }
                }
                if(allDone) {
                    synchronized(this) {
                        // Could have beaten us to it in callback.
                        if(hasFinished()) return false;
                        status = Status.FAILED;
                    }
                    callback.onFailed(e);
                    return true;
                } else {
                    // Wait for them to finish encoding.
                    return false;
                }
            }
            
        });
    }

    public synchronized boolean hasFinished() {
        return status == Status.SUCCEEDED || status == Status.FAILED;
    }

    public synchronized Status getStatus() {
        return status;
    }

    static final long LAZY_WRITE_METADATA_DELAY = TimeUnit.MINUTES.toMillis(5);
    
    private final PersistentJob writeMetadataJob = new PersistentJob() {

        @Override
        public boolean run(ClientContext context) {
            try {
                if(isFinishing()) return false;
                RAFLock lock = raf.lockOpen();
                try {
                    for(SplitFileInserterSegmentStorage segment : segments) {
                        segment.storeStatus(false);
                    }
                } finally {
                    lock.unlock();
                }
                writeOverallStatus(false);
                return false;
            } catch (IOException e) {
                if(isFinishing()) return false;
                Logger.error(this, "Failed writing metadata for "+SplitFileInserterStorage.this+": "+e, e);
                return false;
            }
        }
        
    };
    
    private final Runnable wrapLazyWriteMetadata = new Runnable() {

        @Override
        public void run() {
            jobRunner.queueNormalOrDrop(writeMetadataJob);
        }
        
    };

    public synchronized void lazyWriteMetadata() {
        if(!persistent) return;
        if(LAZY_WRITE_METADATA_DELAY != 0) {
            // The Runnable must be the same object for de-duplication.
            ticker.queueTimedJob(wrapLazyWriteMetadata, "Write metadata for splitfile", 
                    LAZY_WRITE_METADATA_DELAY, false, true);
        } else { // Must still be off-thread, multiple segments, possible locking issues...
            jobRunner.queueNormalOrDrop(writeMetadataJob);
        }
    }

    protected synchronized boolean isFinishing() {
        return this.failing != null || status == Status.FAILED || status == Status.SUCCEEDED || 
            status == Status.GENERATING_METADATA;
    }
    
    void onShutdown(ClientContext context) {
        writeMetadataJob.run(context);
    }
    
    void preadChecksummed(long fileOffset, byte[] buf, int offset, int length) throws IOException, ChecksumFailedException {
        byte[] checksumBuf = new byte[checker.checksumLength()];
        RAFLock lock = raf.lockOpen();
        try {
            raf.pread(fileOffset, buf, offset, length);
            raf.pread(fileOffset+length, checksumBuf, 0, checker.checksumLength());
        } finally {
            lock.unlock();
        }
        if(!checker.checkChecksum(buf, offset, length, checksumBuf)) {
            Arrays.fill(buf, offset, offset+length, (byte)0);
            throw new ChecksumFailedException();
        }
    }

    byte[] preadChecksummedWithLength(long fileOffset) throws IOException, ChecksumFailedException, StorageFormatException {
        byte[] checksumBuf = new byte[checker.checksumLength()];
        RAFLock lock = raf.lockOpen();
        byte[] lengthBuf = new byte[8];
        byte[] buf;
        int length;
        try {
            raf.pread(fileOffset, lengthBuf, 0, lengthBuf.length);
            long len = new DataInputStream(new ByteArrayInputStream(lengthBuf)).readLong();
            if(len + fileOffset > rafLength || len > Integer.MAX_VALUE || len < 0) 
                throw new StorageFormatException("Bogus length "+len);
            length = (int)len;
            buf = new byte[length];
            raf.pread(fileOffset+lengthBuf.length, buf, 0, length);
            raf.pread(fileOffset+length+lengthBuf.length, checksumBuf, 0, checker.checksumLength());
        } finally {
            lock.unlock();
        }
        if(!checker.checkChecksum(buf, 0, length, checksumBuf)) {
            Arrays.fill(buf, 0, length, (byte)0);
            throw new ChecksumFailedException();
        }
        return buf;
    }

    public long getOffsetSegmentStatus(int segNo) {
        return offsetSegmentStatus[segNo];
    }

    LockableRandomAccessBuffer getRAF() {
        return raf;
    }

    public void onResume() throws ResumeFailedException {
        if(crossSegments != null && status != Status.ENCODED_CROSS_SEGMENTS) {
            this.startCrossSegmentEncode();
        } else {
            this.startSegmentEncode();
        }
    }

    /** Choose a block to insert.
     * FIXME make SplitFileInserterSender per-segment, eliminate a lot of unnecessary complexity.
     */
    public BlockInsert chooseBlock() {
        // FIXME this should probably use SimpleBlockChooser and hence use lowest-retry-count from
        // each segment?
        // Less important for inserts than for requests though...
        synchronized(cooldownLock) {
            synchronized(this) {
                if (status == Status.FAILED || status == Status.SUCCEEDED
                        || status == Status.GENERATING_METADATA || failing != null) {
                    return null;
                }
            }
            // Generally segments are fairly well balanced, so we can usually pick a random segment
            // then a random key from it.
            randomSegmentIterator.reset(random);
            while (randomSegmentIterator.hasNext()) {
                SplitFileInserterSegmentStorage segment = randomSegmentIterator.next();
                BlockInsert ret = segment.chooseBlock();
                if (ret != null) {
                    noBlocksToSend = false;
                    return ret;
                }
            }

            noBlocksToSend = true;
            return null;
        }
    }
    
    public boolean noBlocksToSend() {
        synchronized(cooldownLock) {
            return noBlocksToSend;
        }
    }
    
    public long countAllKeys() {
        long total = 0;
        for(SplitFileInserterSegmentStorage segment : segments)
            total += segment.totalBlockCount;
        return total;
    }

    public long countSendableKeys() {
        long total = 0;
        for(SplitFileInserterSegmentStorage segment : segments)
            total += segment.countSendableKeys();
        return total;
    }

    public int getTotalBlockCount() {
        return totalDataBlocks + totalCheckBlocks + crossCheckBlocks * segments.length;
    }

    public void clearCooldown() {
        synchronized(cooldownLock) {
            noBlocksToSend = false;
        }
        this.callback.clearCooldown();
    }

    /** @return -1 if the insert has finished, 0 if has blocks to send, otherwise Long.MAX_VALUE. */
    public long getWakeupTime() {
        // LOCKING: hasFinished() uses (this), separate from cooldownLock.
        // It is safe to use both here (on the request selection thread), one after the other.
        if (hasFinished()) 
            return -1;
        if (noBlocksToSend())
            return Long.MAX_VALUE;
        else
            return 0;
    }

}
