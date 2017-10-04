package freenet.client.async;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import freenet.client.ClientMetadata;
import freenet.client.FailureCodeTracker;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.client.Metadata;
import freenet.client.Metadata.SplitfileAlgorithm;
import freenet.client.MetadataParseException;
import freenet.client.MetadataUnresolvedException;
import freenet.client.FECCodec;
import freenet.crypt.ChecksumChecker;
import freenet.crypt.ChecksumFailedException;
import freenet.crypt.HashType;
import freenet.crypt.MultiHashOutputStream;
import freenet.crypt.RandomSource;
import freenet.keys.CHKBlock;
import freenet.keys.ClientKey;
import freenet.keys.FreenetURI;
import freenet.keys.Key;
import freenet.node.KeysFetchingLocally;
import freenet.node.SendableRequestItem;
import freenet.node.SendableRequestItemKey;
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
import freenet.support.io.ArrayBucketFactory;
import freenet.support.io.BucketTools;
import freenet.support.io.FileRandomAccessBufferFactory;
import freenet.support.io.NativeThread;
import freenet.support.io.StorageFormatException;
import freenet.support.math.MersenneTwister;

/** <p>Stores the state for a SplitFileFetcher, persisted to a LockableRandomAccessBuffer (i.e. a 
 * single random access file), but with most of the metadata in memory. The data, and the larger
 * metadata such as the full keys, are read from disk when needed, and persisted to disk.</p>
 * 
 * <p>On disk format goals:</p>
 * <ol><li>Maximise robustness.</li>
 * <li>Minimise seeks.</li>
 * <li>Minimise disk usage.</li>
 * <li>Be as simple as realistically possible.</li></ol>
 * 
 * <p>Overall on-disk structure:
 * BLOCK STORAGE: Decoded data, one segment at a time (the last segment's size is rounded up to a 
 * whole block). Within each segment, the number of blocks is equal to the number of data blocks 
 * (plus the number of cross-check blocks if there are cross-check blocks), but they are not 
 * necessarily actually data blocks (they may be check blocks), and they may not be in the correct 
 * order. When we FEC decode, we read in the blocks, construct the CHKs to see what keys they 
 * belong to, check that we still have enough valid keys (update the metadata if the counts were 
 * wrong), do the decode, and write the data blocks back in the correct order; the segment is 
 * finished. When all the segments are finished, we generate a stream as usual, i.e. we still need
 * to copy the file. It may be possible in future to simply truncate the file but in many cases we
 * need to decompress or filter, and there are significant issues with code complexity and seeks 
 * during FEC decodes, see bug #6063. 
 * 
 * KEY LIST: The original key list. Not changed when a block is fetched.
 * - Fixed and checksummed (each segment has a checksum).
 * 
 * SEGMENT STATUS: The status of each segment, including the status of each block, including flags 
 * and where it is in the block storage within the segment.
 * - Checksummed per segment. So it needs to be written as a whole segment. Can be regenerated from 
 * the block store and key list, which happens routinely when FEC decoding.
 * 
 * BLOOM FILTERS: Main bloom filter. Segment bloom filters.
 * 
 * ORIGINAL METADATA: For extra robustness, keep the full original metadata.
 * 
 * ORIGINAL URL: If the original key is available, keep that too.
 * 
 * BASIC SETTINGS: Type of splitfile, length of file, overall decryption key, number of blocks and 
 * check blocks per segment, etc.
 * - Fixed and checksummed. Read as a block so we can check the checksum.
 * 
 * FOOTER:
 * Length of basic settings. (So we can seek back to get them)
 * Version number.
 * Checksum.
 * Magic value.
 * 
 * OTHER NOTES:
 * 
 * CHECKSUMS: 4-byte CRC32.
 * 
 * CONCURRENCY: Callbacks into fetcher should be run off-thread, as they will usually be inside a 
 * MemoryLimitedJob.
 * 
 * LOCKING: Trivial or taken last. Hence can be called inside e.g. RGA calls to getCooldownTime 
 * etc.
 * 
 * PERSISTENCE: This whole class is transient. It is recreated on startup by the 
 * SplitFileFetcher. Many of the fields are also transient, e.g. 
 * SplitFileFetcherSegmentStorage's cooldown fields.
 * @author toad
 */
public class SplitFileFetcherStorage {

    private static volatile boolean logMINOR;
    private static volatile boolean logDEBUG;
    static {
        Logger.registerClass(SplitFileFetcherStorage.class);
    }
    
    final SplitFileFetcherStorageCallback fetcher;
    // Metadata for the fetch
    /** The underlying presumably-on-disk storage. */ 
    private final LockableRandomAccessBuffer raf;
    private final long rafLength;
    /** If true we will complete the download by truncating the file. The file was passed in at
     * construction and we are not responsible for freeing it. Once all segments have decoded and
     * encoded we call onSuccess(), and we don't free the data. Also, if this is true, cross-check 
     * blocks will be kept on disk *AFTER* all the main data and check blocks for the whole file. */
    final boolean completeViaTruncation;
    /** The segments */
    final SplitFileFetcherSegmentStorage[] segments;
    /** The cross-segments. Null if no cross-segments. */
    final SplitFileFetcherCrossSegmentStorage[] crossSegments;
    /** Random iterator for segment selection. LOCKING: must synchronize on the iterator. */
    private final RandomArrayIterator<SplitFileFetcherSegmentStorage> randomSegmentIterator;

    /** If the splitfile has a common encryption algorithm, this is it. */
    final byte splitfileSingleCryptoAlgorithm;
    /** If the splitfile has a common encryption key, this is it. */
    final byte[] splitfileSingleCryptoKey;
    /** FEC codec for the splitfile, if needed. */
    public final FECCodec fecCodec;
    final Ticker ticker;
    final PersistentJobRunner jobRunner;
    final MemoryLimitedJobRunner memoryLimitedJobRunner;
    /** Final length of the downloaded data. *BEFORE* decompression, filtering, etc. I.e. this is 
     * the length of the data on disk, which will be written by the StreamGenerator. */
    final long finalLength;
    /** Final length of the downloaded data, after decompression. (May change if the data is 
     * filtered). */
    final long decompressedLength;
    final SplitfileAlgorithm splitfileType;
    /** MIME type etc. Set on construction and passed to onSuccess(). */
    final ClientMetadata clientMetadata;
    /** Decompressors. Set on construction and passed to onSuccess(). */
    final List<COMPRESSOR_TYPE> decompressors;
    /** False = Transient: We are using the RAF as scratch space, we only need to write the blocks,
     * and the keys (if we don't keep them in memory). True = Persistent: It must be possible to 
     * resume after a node restart. Ideally we'd like to be able to recover the download in its
     * entirety without needing any additional information, but at a minimum we want to be able to
     * continue it while passing in the usual external arguments (FetchContext, parent, etc). */
    final boolean persistent;
    
    private boolean finishedFetcher;
    private boolean finishedEncoding;
    private boolean cancelled;
    private boolean succeeded;
    
    /** Errors. For now, this is not persisted (FIXME). */
    private FailureCodeTracker errors;
    final int maxRetries;
    /** Every cooldownTries attempts, a key will enter cooldown, and won't be re-tried for a period. */
    final int cooldownTries;
    /** Cooldown lasts this long for each key. */
    final long cooldownLength;
    /** Only set if all segments are in cooldown. */
    private long overallCooldownWakeupTime;
    final CompatibilityMode finalMinCompatMode;
    
    /** Contains Bloom filters */
    final SplitFileFetcherKeyListener keyListener;
    
    final RandomSource random;
    
    // Metadata for the file i.e. stuff we need to be able to efficiently read/write it.
    /** Offset to start of the key lists in bytes */
    final long offsetKeyList;
    /** Offset to start of the segment status'es in bytes */
    final long offsetSegmentStatus;
    /** Offset to start of the general progress section */
    final long offsetGeneralProgress;
    /** Offset to start of the bloom filters in bytes */
    final long offsetMainBloomFilter;
    /** Offset to start of the per-segment bloom filters in bytes */
    final long offsetSegmentBloomFilters;
    /** Offset to start of the original metadata in bytes */
    final long offsetOriginalMetadata;
    /** Offset to start of the original details in bytes. "Original details" includes the URI to 
     * this download (if available), the original URI for the whole download (if available), 
     * whether this is the final fetch (it might be a metadata or container fetch), and data from
     * the ultimate client, e.g. the Identifier, whether it is on the Global queue, the client name
     * if it isn't etc. */
    final long offsetOriginalDetails;
    /** Offset to start of the basic settings in bytes */
    final long offsetBasicSettings;
    /** Length of all section checksums */
    final int checksumLength;
    /** Checksum implementation */
    final ChecksumChecker checksumChecker;
    private boolean hasCheckedDatastore;
    private boolean dirtyGeneralProgress;
    static final long HAS_CHECKED_DATASTORE_FLAG = 1;
    /** Fixed value posted at the end of the file (if plaintext!) */
    static final long END_MAGIC = 0x28b32d99416eb6efL;
    /** Current format version */
    static final int VERSION = 1;
    
    /** List of segments we need to tryStartDecode() on because their metadata was corrupted on
     * startup. */
    private List<SplitFileFetcherSegmentStorage> segmentsToTryDecode;
    
    /** Construct a new SplitFileFetcherStorage from metadata. Creates the RandomAccessBuffer and
     * writes the initial data to it. There is another constructor for resuming a download. 
     * @param metadata
     * @param fetcher
     * @param decompressors
     * @param clientMetadata
     * @param topDontCompress
     * @param topCompatibilityMode
     * @param origFetchContext
     * @param salt
     * @param thisKey
     * @param origKey
     * @param isFinalFetch
     * @param clientDetails
     * @param random
     * @param tempBucketFactory
     * @param rafFactory
     * @param exec
     * @param ticker
     * @param memoryLimitedJobRunner
     * @param checker 
     * @param persistent 
     * @param storageFile If non-null, we will use this file to store the data in. It must already
     * exist, and must be 0 bytes long. We will use it, and then when complete, truncate the file 
     * so it only contains the final data before calling onSuccess(). Also, in this case, 
     * rafFactory must be a DiskSpaceCheckingRandomAccessBufferFactory.
     * @param diskSpaceCheckingRAFFactory
     * @param keysFetching Must be passed in at this point as we will need it later. However, none
     * of this is persisted directly, so this is not a problem.
     * @throws FetchException If we failed to set up the download due to a problem with the metadata. 
     * @throws MetadataParseException 
     * @throws IOException If we were unable to create the file to store the metadata and 
     * downloaded blocks in. */
    public SplitFileFetcherStorage(Metadata metadata, SplitFileFetcherStorageCallback fetcher, 
            List<COMPRESSOR_TYPE> decompressors, ClientMetadata clientMetadata, 
            boolean topDontCompress, short topCompatibilityMode, FetchContext origFetchContext,
            KeySalter salt, FreenetURI thisKey, FreenetURI origKey,
            boolean isFinalFetch, byte[] clientDetails, RandomSource random, 
            BucketFactory tempBucketFactory, LockableRandomAccessBufferFactory rafFactory, 
            PersistentJobRunner exec, Ticker ticker, MemoryLimitedJobRunner memoryLimitedJobRunner, 
            ChecksumChecker checker, boolean persistent, 
            File storageFile, FileRandomAccessBufferFactory diskSpaceCheckingRAFFactory,
            KeysFetchingLocally keysFetching) 
    throws FetchException, MetadataParseException, IOException {
        this.fetcher = fetcher;
        this.jobRunner = exec;
        this.ticker = ticker;
        this.memoryLimitedJobRunner = memoryLimitedJobRunner;
        this.finalLength = metadata.dataLength();
        this.decompressedLength = metadata.uncompressedDataLength();
        this.splitfileType = metadata.getSplitfileType();
        this.fecCodec = FECCodec.getInstance(splitfileType);
        this.decompressors = decompressors;
        this.random = random;
        this.errors = new FailureCodeTracker(false);
        this.checksumChecker = checker;
        this.checksumLength = checker.checksumLength();
        this.persistent = persistent;
        this.completeViaTruncation = (storageFile != null);
        if(decompressors.size() > 1) {
            Logger.error(this, "Multiple decompressors: "+decompressors.size()+" - this is almost certainly a bug", new Exception("debug"));
        }
        this.clientMetadata = clientMetadata == null ? new ClientMetadata() : clientMetadata.clone(); // copy it as in SingleFileFetcher
        SplitFileSegmentKeys[] segmentKeys = metadata.getSegmentKeys();
        CompatibilityMode minCompatMode = metadata.getMinCompatMode();
        CompatibilityMode maxCompatMode = metadata.getMaxCompatMode();

        int crossCheckBlocks = metadata.getCrossCheckBlocks();
        
        maxRetries = origFetchContext.maxSplitfileBlockRetries;
        cooldownTries = origFetchContext.getCooldownRetries();
        cooldownLength = origFetchContext.getCooldownTime();
        this.splitfileSingleCryptoAlgorithm = metadata.getSplitfileCryptoAlgorithm();
        splitfileSingleCryptoKey = metadata.getSplitfileCryptoKey();
        
        // These are approximate values, the number of blocks per segment varies.
        int blocksPerSegment = metadata.getDataBlocksPerSegment();
        int checkBlocksPerSegment = metadata.getCheckBlocksPerSegment();
        
        int splitfileDataBlocks = 0;
        int splitfileCheckBlocks = 0;
        
        long storedBlocksLength = 0;
        long storedKeysLength = 0;
        long storedSegmentStatusLength = 0;
        /** Only non-zero if the cross-check blocks are stored separately i.e. if completeViaTruncation */
        long storedCrossCheckBlocksLength = 0;

        for(SplitFileSegmentKeys keys : segmentKeys) {
            int dataBlocks = keys.getDataBlocks();
            // Here data blocks include cross-segment blocks.
            int checkBlocks = keys.getCheckBlocks();
            splitfileDataBlocks += dataBlocks;
            splitfileCheckBlocks += checkBlocks;
            storedKeysLength +=
                SplitFileFetcherSegmentStorage.storedKeysLength(dataBlocks, checkBlocks, splitfileSingleCryptoKey != null, checksumLength);
            storedSegmentStatusLength +=
                SplitFileFetcherSegmentStorage.paddedStoredSegmentStatusLength(dataBlocks - crossCheckBlocks, checkBlocks, 
                        crossCheckBlocks, maxRetries != -1, checksumLength, persistent);
        }
        
        int totalCrossCheckBlocks = segmentKeys.length * crossCheckBlocks;
        splitfileDataBlocks -= totalCrossCheckBlocks;
        if(completeViaTruncation) {
            storedCrossCheckBlocksLength = (long)totalCrossCheckBlocks * CHKBlock.DATA_LENGTH;
            storedBlocksLength = (long)splitfileDataBlocks * CHKBlock.DATA_LENGTH;
        } else {
            storedCrossCheckBlocksLength = 0;
            storedBlocksLength = ((long)splitfileDataBlocks + totalCrossCheckBlocks) * CHKBlock.DATA_LENGTH;
        }
        
        int segmentCount = metadata.getSegmentCount();
        if (segmentCount <= 0) {
            throw new AssertionError("A splitfile has to have at least one segment");
        }
        
        if(splitfileType == SplitfileAlgorithm.NONREDUNDANT) {
            if(splitfileCheckBlocks > 0) {
                Logger.error(this, "Splitfile type is SPLITFILE_NONREDUNDANT yet "+splitfileCheckBlocks+" check blocks found!! : "+this);
                throw new FetchException(FetchExceptionMode.INVALID_METADATA, "Splitfile type is non-redundant yet have "+splitfileCheckBlocks+" check blocks");
            }
        } else if(splitfileType == SplitfileAlgorithm.ONION_STANDARD) {
            
            boolean dontCompress = decompressors.isEmpty();
            if(topCompatibilityMode != 0) {
                // If we have top compatibility mode, then we can give a definitive answer immediately, with the splitfile key, with dontcompress, etc etc.
                if(minCompatMode == CompatibilityMode.COMPAT_UNKNOWN ||
                        !(minCompatMode.ordinal() > topCompatibilityMode || maxCompatMode.ordinal() < topCompatibilityMode)) {
                    minCompatMode = maxCompatMode = CompatibilityMode.values()[topCompatibilityMode];
                    dontCompress = topDontCompress;
                } else
                    throw new FetchException(FetchExceptionMode.INVALID_METADATA, "Top compatibility mode is incompatible with detected compatibility mode");
            }
            // We assume we are the bottom layer. 
            // If the top-block stats are passed in then we can safely say the report is definitive.
            fetcher.onSplitfileCompatibilityMode(minCompatMode, maxCompatMode, metadata.getCustomSplitfileKey(), dontCompress, true, topCompatibilityMode != 0);

            if((blocksPerSegment > origFetchContext.maxDataBlocksPerSegment)
                    || (checkBlocksPerSegment > origFetchContext.maxCheckBlocksPerSegment))
                throw new FetchException(FetchExceptionMode.TOO_MANY_BLOCKS_PER_SEGMENT, "Too many blocks per segment: "+blocksPerSegment+" data, "+checkBlocksPerSegment+" check");
            
                
        } else throw new MetadataParseException("Unknown splitfile format: "+splitfileType);

        if(logMINOR)
            Logger.minor(this, "Algorithm: "+splitfileType+", blocks per segment: "+blocksPerSegment+
                    ", check blocks per segment: "+checkBlocksPerSegment+", segments: "+segmentCount+
                    ", data blocks: "+splitfileDataBlocks+", check blocks: "+splitfileCheckBlocks);
        segments = new SplitFileFetcherSegmentStorage[segmentCount]; // initially null on all entries
        randomSegmentIterator = new RandomArrayIterator<SplitFileFetcherSegmentStorage>(segments);
        
        long checkLength = 1L * (splitfileDataBlocks - segmentCount * crossCheckBlocks) * CHKBlock.DATA_LENGTH;
        if(checkLength > finalLength) {
            if(checkLength - finalLength > CHKBlock.DATA_LENGTH)
                throw new FetchException(FetchExceptionMode.INVALID_METADATA, "Splitfile is "+checkLength+" bytes long but length is "+finalLength+" bytes");
        }
        
        byte[] localSalt = new byte[32];
        random.nextBytes(localSalt);
        
        keyListener = new SplitFileFetcherKeyListener(fetcher, this, false, 
                localSalt, splitfileDataBlocks + totalCrossCheckBlocks + splitfileCheckBlocks, blocksPerSegment + 
                checkBlocksPerSegment, segmentCount);

        finalMinCompatMode = minCompatMode;
        
        this.offsetKeyList = storedBlocksLength + storedCrossCheckBlocksLength;
        this.offsetSegmentStatus = offsetKeyList + storedKeysLength;
        
        byte[] generalProgress = encodeGeneralProgress();
        
        if(persistent) {
            offsetGeneralProgress = offsetSegmentStatus + storedSegmentStatusLength;
            this.offsetMainBloomFilter = offsetGeneralProgress + generalProgress.length; 
            this.offsetSegmentBloomFilters = offsetMainBloomFilter + keyListener.paddedMainBloomFilterSize();
            this.offsetOriginalMetadata = offsetSegmentBloomFilters + 
                keyListener.totalSegmentBloomFiltersSize();
        } else {
            // Don't store anything except the blocks and the key list.
            offsetGeneralProgress = offsetMainBloomFilter = offsetSegmentBloomFilters = offsetOriginalMetadata = offsetSegmentStatus;
        }
            
        
        long dataOffset = 0;
        long crossCheckBlocksOffset = storedBlocksLength; // Only used if completeViaTruncation
        long segmentKeysOffset = offsetKeyList;
        long segmentStatusOffset = offsetSegmentStatus;
        
        for(int i=0;i<segments.length;i++) {
            // splitfile* will be overwritten, this is bad
            // so copy them
            SplitFileSegmentKeys keys = segmentKeys[i];
            // Segment keys getDataBlocks() includes cross-check blocks
            final int dataBlocks = keys.getDataBlocks() - crossCheckBlocks; 
            final int checkBlocks = keys.getCheckBlocks();
            if((dataBlocks > origFetchContext.maxDataBlocksPerSegment)
                    || (checkBlocks > origFetchContext.maxCheckBlocksPerSegment))
                throw new FetchException(FetchExceptionMode.TOO_MANY_BLOCKS_PER_SEGMENT, "Too many blocks per segment: "+blocksPerSegment+" data, "+checkBlocksPerSegment+" check");
            segments[i] = new SplitFileFetcherSegmentStorage(this, i,
                    dataBlocks,
                    checkBlocks, crossCheckBlocks, dataOffset, 
                    completeViaTruncation ? crossCheckBlocksOffset : -1, // Put at end if truncating.
                    segmentKeysOffset, segmentStatusOffset,
                    maxRetries != -1, keys, keysFetching);
            dataOffset += dataBlocks * CHKBlock.DATA_LENGTH;
            if(!completeViaTruncation) {
                dataOffset += crossCheckBlocks * CHKBlock.DATA_LENGTH;
            } else {
                crossCheckBlocksOffset += crossCheckBlocks * CHKBlock.DATA_LENGTH;
            }
            segmentKeysOffset += 
                SplitFileFetcherSegmentStorage.storedKeysLength(dataBlocks+crossCheckBlocks, checkBlocks, splitfileSingleCryptoKey != null, checksumLength);
            segmentStatusOffset +=
                SplitFileFetcherSegmentStorage.paddedStoredSegmentStatusLength(dataBlocks, checkBlocks, 
                        crossCheckBlocks, maxRetries != -1, checksumLength, persistent);
            for(int j=0;j<(dataBlocks+crossCheckBlocks+checkBlocks);j++) {
                keyListener.addKey(keys.getKey(j, null, false).getNodeKey(false), i, salt);
            }
            if(logDEBUG) Logger.debug(this, "Segment "+i+": data blocks offset "+
                    segments[i].segmentBlockDataOffset+" cross-check blocks offset "+segments[i].segmentCrossCheckBlockDataOffset+" for segment "+i+" of "+this);
        }
        assert(dataOffset == storedBlocksLength);
        if(completeViaTruncation)
            assert(crossCheckBlocksOffset == storedCrossCheckBlocksLength + storedBlocksLength);
        assert(segmentKeysOffset == storedBlocksLength + storedCrossCheckBlocksLength + storedKeysLength);
        assert(segmentStatusOffset == storedBlocksLength + storedCrossCheckBlocksLength + storedKeysLength + storedSegmentStatusLength);
        /* Lie about the required number of blocks. For a cross-segment splitfile, the actual 
         * number of blocks needed is somewhere between splitfileDataBlocks and 
         * splitfileDataBlocks + totalCrossCheckBlocks depending on what order we fetch them in. 
         * Progress over 100% is apparently more annoying than finishing at 98%... */
        fetcher.setSplitfileBlocks(splitfileDataBlocks + totalCrossCheckBlocks, splitfileCheckBlocks);
        
        keyListener.finishedSetup();
        
        if(crossCheckBlocks != 0) {
            Random crossSegmentRandom = new MersenneTwister(Metadata.getCrossSegmentSeed(metadata.getHashes(), metadata.getHashThisLayerOnly()));
            // Cross segment redundancy: Allocate the blocks.
            crossSegments = new SplitFileFetcherCrossSegmentStorage[segments.length];
            int segLen = blocksPerSegment;
            int deductBlocksFromSegments = metadata.getDeductBlocksFromSegments();
            for(int i=0;i<crossSegments.length;i++) {
                Logger.normal(this, "Allocating blocks (on fetch) for cross segment "+i);
                if(segments.length - i == deductBlocksFromSegments) {
                    segLen--;
                }
                SplitFileFetcherCrossSegmentStorage seg = 
                    new SplitFileFetcherCrossSegmentStorage(i, segLen, crossCheckBlocks, this, fecCodec);
                crossSegments[i] = seg;
                for(int j=0;j<segLen;j++) {
                    // Allocate random data blocks
                    allocateCrossDataBlock(seg, crossSegmentRandom);
                }
                for(int j=0;j<crossCheckBlocks;j++) {
                    // Allocate check blocks
                    allocateCrossCheckBlock(seg, crossSegmentRandom);
                }
            }
        } else {
            crossSegments = null;
        }
        
        long totalLength;
        Bucket metadataTemp;
        byte[] encodedURI;
        byte[] encodedBasicSettings;
        if(persistent) {
            // Write the metadata to a temporary file to get its exact length.
            metadataTemp = tempBucketFactory.makeBucket(-1);
            OutputStream os = metadataTemp.getOutputStream();
            OutputStream cos = checksumOutputStream(os);
            BufferedOutputStream bos = new BufferedOutputStream(cos);
            try {
                // Need something bigger than a CRC for this...
                MultiHashOutputStream mos = new MultiHashOutputStream(bos, HashType.SHA256.bitmask);
                metadata.writeTo(new DataOutputStream(mos));
                mos.getResults()[0].writeTo(bos);
            } catch (MetadataUnresolvedException e) {
                throw new FetchException(FetchExceptionMode.INTERNAL_ERROR, "Metadata not resolved starting splitfile fetch?!: "+e, e);
            }
            bos.close();
            long metadataLength = metadataTemp.size();
            offsetOriginalDetails = offsetOriginalMetadata + metadataLength;
            
            encodedURI = encodeAndChecksumOriginalDetails(thisKey, origKey, clientDetails, isFinalFetch);
            this.offsetBasicSettings = offsetOriginalDetails + encodedURI.length;
            
            encodedBasicSettings = 
                encodeBasicSettings(splitfileDataBlocks, 
                        splitfileCheckBlocks, crossCheckBlocks * segments.length);
            totalLength = 
                offsetBasicSettings + // rest of file
                encodedBasicSettings.length + // basic settings
                4 + // length of basic settings
                checksumLength + // might as well checksum the footer as well
                4 + // version
                4 + // flags
                2 + // checksum type
                8; // magic
        } else {
            totalLength = offsetSegmentStatus;
            offsetOriginalDetails = offsetBasicSettings = offsetSegmentStatus;
            metadataTemp = null;
            encodedURI = encodedBasicSettings = null;
        }
        
        // Create the actual LockableRandomAccessBuffer
        
        rafLength = totalLength;
        if(storageFile != null) {
            if(!storageFile.exists())
                throw new IOException("Must have already created storage file");
            if(storageFile.length() > 0)
                throw new IOException("Storage file must be empty");
            raf = diskSpaceCheckingRAFFactory.createNewRAF(storageFile, totalLength, random);
            Logger.normal(this, "Creating splitfile storage file for complete-via-truncation: "+storageFile);
        } else {
            raf = rafFactory.makeRAF(totalLength);
        }
        RAFLock lock = raf.lockOpen();
        try {
            for(int i=0;i<segments.length;i++) {
                SplitFileFetcherSegmentStorage segment = segments[i];
                segment.writeKeysWithChecksum(segmentKeys[i]);
            }
            if(persistent) {
                for(SplitFileFetcherSegmentStorage segment : segments)
                    segment.writeMetadata();
                raf.pwrite(offsetGeneralProgress, generalProgress, 0, generalProgress.length);
                keyListener.innerWriteMainBloomFilter(offsetMainBloomFilter);
                keyListener.initialWriteSegmentBloomFilters(offsetSegmentBloomFilters);
                BucketTools.copyTo(metadataTemp, raf, offsetOriginalMetadata, -1);
                metadataTemp.free();
                raf.pwrite(offsetOriginalDetails, encodedURI, 0, encodedURI.length);
                raf.pwrite(offsetBasicSettings, encodedBasicSettings, 0, encodedBasicSettings.length);
                
                // This bit tricky because version is included in the checksum.
                // When the RAF is encrypted, we use HMAC's and this is important.
                // FIXME is Fields.bytesToInt etc compatible with DataOutputStream.*?
                // FIXME if not, we need something that is ...
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                DataOutputStream dos = new DataOutputStream(baos);
                dos.writeInt(encodedBasicSettings.length - checksumLength);
                byte[] bufToWrite = baos.toByteArray();
                baos = new ByteArrayOutputStream();
                dos = new DataOutputStream(baos);
                dos.writeInt(0); // flags
                dos.writeShort(checksumChecker.getChecksumTypeID());
                dos.writeInt(VERSION);
                byte[] version = baos.toByteArray();
                byte[] bufToChecksum = Arrays.copyOf(bufToWrite, bufToWrite.length+version.length);
                System.arraycopy(version, 0, bufToChecksum, bufToWrite.length, version.length);
                byte[] checksum = 
                    checksumChecker.generateChecksum(bufToChecksum);
                // Pointers.
                raf.pwrite(offsetBasicSettings + encodedBasicSettings.length, bufToWrite, 0, 
                        bufToWrite.length);
                // Checksum.
                raf.pwrite(offsetBasicSettings + encodedBasicSettings.length + bufToWrite.length, 
                        checksum, 0, checksum.length);
                // Version.
                raf.pwrite(offsetBasicSettings + encodedBasicSettings.length + bufToWrite.length + 
                        checksum.length, version, 0, version.length);
                // Write magic last.
                baos = new ByteArrayOutputStream();
                dos = new DataOutputStream(baos);
                dos.writeLong(END_MAGIC);
                byte[] buf = baos.toByteArray();
                raf.pwrite(totalLength - 8, buf, 0, 8);
            }
        } finally {
            lock.unlock();
        }
        if(logMINOR) Logger.minor(this, "Fetching "+thisKey+" on "+this+" for "+fetcher);
    }
    
    /** Construct a SplitFileFetcherStorage from a stored RandomAccessBuffer, and appropriate local
     * settings passed in. Ideally this would work with only basic system utilities such as 
     * those on ClientContext, i.e. we'd be able to restore the splitfile download without knowing
     * anything about it.
     * @param newSalt True if the global salt has changed.
     * @throws IOException If the restore failed because of a failure to read from disk.
     * @throws StorageFormatException 
     * @throws FetchException If the request has already failed (but it wasn't processed before 
     * restarting). */
    public SplitFileFetcherStorage(LockableRandomAccessBuffer raf,
            SplitFileFetcherStorageCallback callback, FetchContext origContext,
            RandomSource random, PersistentJobRunner exec, KeysFetchingLocally keysFetching,
            Ticker ticker, MemoryLimitedJobRunner memoryLimitedJobRunner, ChecksumChecker checker, 
            boolean newSalt, boolean completeViaTruncation)
    throws IOException, StorageFormatException, FetchException {
        this.persistent = true;
        this.raf = raf;
        this.fetcher = callback;
        this.ticker = ticker;
        this.jobRunner = exec;
        this.memoryLimitedJobRunner = memoryLimitedJobRunner;
        this.random = random;
        this.checksumChecker = checker;
        this.checksumLength = checker.checksumLength();
        this.maxRetries = origContext.maxSplitfileBlockRetries;
        this.cooldownTries = origContext.getCooldownRetries();
        this.cooldownLength = origContext.getCooldownTime();
        this.errors = new FailureCodeTracker(false); // FIXME persist???
        this.completeViaTruncation = completeViaTruncation;
        // FIXME this is hideous! Rewrite the writing/parsing code here in a less ugly way. However, it works...
        rafLength = raf.size();
        if(raf.size() < 8 /* FIXME more! */)
            throw new StorageFormatException("Too short");
        // Last 8 bytes: Magic value.
        byte[] buf = new byte[8];
        raf.pread(rafLength-8, buf, 0, 8);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(buf));
        if(dis.readLong() != END_MAGIC)
            throw new StorageFormatException("Wrong magic bytes");
        // 4 bytes before that: Version.
        byte[] versionBuf = new byte[4];
        raf.pread(rafLength-12, versionBuf, 0, 4);
        dis = new DataInputStream(new ByteArrayInputStream(versionBuf));
        int version = dis.readInt();
        if(version != 1)
            throw new StorageFormatException("Wrong version "+version);
        // 2 bytes: Checksum type
        byte[] checksumTypeBuf = new byte[2];
        raf.pread(rafLength-14, checksumTypeBuf, 0, 2);
        dis = new DataInputStream(new ByteArrayInputStream(checksumTypeBuf));
        int checksumType = dis.readShort();
        if(checksumType != ChecksumChecker.CHECKSUM_CRC)
            throw new StorageFormatException("Unknown checksum type "+checksumType);
        // 4 bytes: Flags. Unused at present.
        byte[] flagsBuf = new byte[4];
        raf.pread(rafLength-18, flagsBuf, 0, 4);
        dis = new DataInputStream(new ByteArrayInputStream(flagsBuf));
        int flags = dis.readInt();
        if(flags != 0)
            throw new StorageFormatException("Unknown flags: "+flags);
        // 4 bytes basic settings length and a checksum, which includes both the settings length and the version.
        buf = new byte[14];
        raf.pread(rafLength-(22+checksumLength), buf, 0, 4);
        byte[] checksum = new byte[checksumLength];
        // Check the checksum.
        raf.pread(rafLength-(18+checksumLength), checksum, 0, checksumLength);
        System.arraycopy(flagsBuf, 0, buf, 4, 4);
        System.arraycopy(checksumTypeBuf, 0, buf, 8, 2);
        System.arraycopy(versionBuf, 0, buf, 10, 4);
        if(!checksumChecker.checkChecksum(buf, 0, 14, checksum))
            throw new StorageFormatException("Checksum failed on basic settings length and version");
        dis = new DataInputStream(new ByteArrayInputStream(buf));
        int basicSettingsLength = dis.readInt();
        if(basicSettingsLength < 0 || basicSettingsLength + 12 + 4 + checksumLength > raf.size() || 
                basicSettingsLength > 1024*1024)
            throw new StorageFormatException("Bad basic settings length");
        byte[] basicSettingsBuffer = new byte[basicSettingsLength];
        long basicSettingsOffset = rafLength-(18+4+checksumLength*2+basicSettingsLength);
        try {
            preadChecksummed(basicSettingsOffset, 
                    basicSettingsBuffer, 0, basicSettingsLength);
        } catch (ChecksumFailedException e) {
            throw new StorageFormatException("Basic settings checksum invalid");
        }
        dis = new DataInputStream(new ByteArrayInputStream(basicSettingsBuffer));
        try {
            short s = dis.readShort();
            try {
                splitfileType = SplitfileAlgorithm.getByCode(s);
            } catch (IllegalArgumentException e) {
                throw new StorageFormatException("Invalid splitfile type "+s);
            }
            this.fecCodec = FECCodec.getInstance(splitfileType);
            splitfileSingleCryptoAlgorithm = dis.readByte();
            if(!Metadata.isValidSplitfileCryptoAlgorithm(splitfileSingleCryptoAlgorithm))
                throw new StorageFormatException("Invalid splitfile crypto algorithm "+splitfileType);
            if(dis.readBoolean()) {
                splitfileSingleCryptoKey = new byte[32];
                dis.readFully(splitfileSingleCryptoKey);
            } else {
                splitfileSingleCryptoKey = null;
            }
            finalLength = dis.readLong();
            if(finalLength < 0)
                throw new StorageFormatException("Invalid final length "+finalLength);
            decompressedLength = dis.readLong();
            if(decompressedLength < 0)
                throw new StorageFormatException("Invalid decompressed length "+decompressedLength);
            try {
                clientMetadata = ClientMetadata.construct(dis);
            } catch (MetadataParseException e) {
                throw new StorageFormatException("Invalid MIME type");
            }
            int decompressorCount = dis.readInt();
            if(decompressorCount < 0)
                throw new StorageFormatException("Invalid decompressor count "+decompressorCount);
            decompressors = new ArrayList<COMPRESSOR_TYPE>(decompressorCount);
            for(int i=0;i<decompressorCount;i++) {
                short type = dis.readShort();
                COMPRESSOR_TYPE d = COMPRESSOR_TYPE.getCompressorByMetadataID(type);
                if(d == null) throw new StorageFormatException("Invalid decompressor ID "+type);
                decompressors.add(d);
            }
            offsetKeyList = dis.readLong();
            if(offsetKeyList < 0 || offsetKeyList > rafLength) 
                throw new StorageFormatException("Invalid offset (key list)");
            offsetSegmentStatus = dis.readLong();
            if(offsetSegmentStatus < 0 || offsetSegmentStatus > rafLength) 
                throw new StorageFormatException("Invalid offset (segment status)");
            offsetGeneralProgress = dis.readLong();
            if(offsetGeneralProgress < 0 || offsetGeneralProgress > rafLength) 
                throw new StorageFormatException("Invalid offset (general progress)");
            offsetMainBloomFilter = dis.readLong();
            if(offsetMainBloomFilter < 0 || offsetMainBloomFilter > rafLength) 
                throw new StorageFormatException("Invalid offset (main bloom filter)");
            offsetSegmentBloomFilters = dis.readLong();
            if(offsetSegmentBloomFilters < 0 || offsetSegmentBloomFilters > rafLength) 
                throw new StorageFormatException("Invalid offset (segment bloom filters)");
            offsetOriginalMetadata = dis.readLong();
            if(offsetOriginalMetadata < 0 || offsetOriginalMetadata > rafLength) 
                throw new StorageFormatException("Invalid offset (original metadata)");
            offsetOriginalDetails = dis.readLong();
            if(offsetOriginalDetails < 0 || offsetOriginalDetails > rafLength) 
                throw new StorageFormatException("Invalid offset (original metadata)");
            offsetBasicSettings = dis.readLong();
            if(offsetBasicSettings != basicSettingsOffset)
                throw new StorageFormatException("Invalid basic settings offset (not the same as computed)");
            if(completeViaTruncation != dis.readBoolean())
                throw new StorageFormatException("Complete via truncation flag is wrong");
            int compatMode = dis.readInt();
            if(compatMode < 0 || compatMode > CompatibilityMode.values().length)
                throw new StorageFormatException("Invalid compatibility mode "+compatMode);
            finalMinCompatMode = CompatibilityMode.values()[compatMode];
            int segmentCount = dis.readInt();
            if(segmentCount <= 0) throw new StorageFormatException("Invalid segment count "+segmentCount);
            this.segments = new SplitFileFetcherSegmentStorage[segmentCount];
            randomSegmentIterator = new RandomArrayIterator<SplitFileFetcherSegmentStorage>(segments);
            long totalDataBlocks = dis.readInt();
            if(totalDataBlocks < 0) 
                throw new StorageFormatException("Invalid total data blocks "+totalDataBlocks);
            int totalCheckBlocks = dis.readInt();
            if(totalCheckBlocks < 0) 
                throw new StorageFormatException("Invalid total check blocks "+totalDataBlocks);
            int totalCrossCheckBlocks = dis.readInt();
            if(totalCrossCheckBlocks < 0)
                throw new StorageFormatException("Invalid total cross-check blocks "+totalDataBlocks);
            if (totalDataBlocks + totalCheckBlocks + totalCrossCheckBlocks <= 0) {
                throw new StorageFormatException("Total number of blocks in splitfile is non-positive");
            }
            long dataOffset = 0;
            long crossCheckBlocksOffset;
            if(completeViaTruncation) {
                crossCheckBlocksOffset = totalDataBlocks * CHKBlock.DATA_LENGTH;
            } else {
                crossCheckBlocksOffset = 0;
            }
            long segmentKeysOffset = offsetKeyList;
            long segmentStatusOffset = offsetSegmentStatus;
            int countDataBlocks = 0;
            int countCheckBlocks = 0;
            int countCrossCheckBlocks = 0;
            for(int i=0;i<segments.length;i++) {
                segments[i] = new SplitFileFetcherSegmentStorage(this, dis, i, maxRetries != -1, 
                        dataOffset, completeViaTruncation ? crossCheckBlocksOffset : -1,
                                segmentKeysOffset, segmentStatusOffset, keysFetching);
                int dataBlocks = segments[i].dataBlocks;
                countDataBlocks += dataBlocks;
                int checkBlocks = segments[i].checkBlocks;
                countCheckBlocks += checkBlocks;
                int crossCheckBlocks = segments[i].crossSegmentCheckBlocks;
                countCrossCheckBlocks += crossCheckBlocks;
                dataOffset += dataBlocks * CHKBlock.DATA_LENGTH;
                if(completeViaTruncation)
                    crossCheckBlocksOffset += crossCheckBlocks * CHKBlock.DATA_LENGTH;
                else
                    dataOffset += crossCheckBlocks * CHKBlock.DATA_LENGTH;
                segmentKeysOffset += 
                    SplitFileFetcherSegmentStorage.storedKeysLength(dataBlocks+crossCheckBlocks, checkBlocks, splitfileSingleCryptoKey != null, checksumLength);
                segmentStatusOffset +=
                    SplitFileFetcherSegmentStorage.paddedStoredSegmentStatusLength(dataBlocks, checkBlocks, 
                            crossCheckBlocks, maxRetries != -1, checksumLength, true);
                if(dataOffset > rafLength)
                    throw new StorageFormatException("Data offset past end of file "+dataOffset+" of "+rafLength);
                if(segments[i].segmentCrossCheckBlockDataOffset > rafLength)
                    throw new StorageFormatException("Cross-check blocks offset past end of file "+segments[i].segmentCrossCheckBlockDataOffset+" of "+rafLength);
                if(logDEBUG) Logger.debug(this, "Segment "+i+": data blocks offset "+
                        segments[i].segmentBlockDataOffset+" cross-check blocks offset "+segments[i].segmentCrossCheckBlockDataOffset+" for segment "+i+" of "+this);
            }
            if(countDataBlocks != totalDataBlocks) 
                throw new StorageFormatException("Total data blocks "+countDataBlocks+" but expected "+totalDataBlocks);
            if(countCheckBlocks != totalCheckBlocks) 
                throw new StorageFormatException("Total check blocks "+countCheckBlocks+" but expected "+totalCheckBlocks);
            if(countCrossCheckBlocks != totalCrossCheckBlocks) 
                throw new StorageFormatException("Total cross-check blocks "+countCrossCheckBlocks+" but expected "+totalCrossCheckBlocks);
            int crossSegments = dis.readInt();
            if(crossSegments == 0)
                this.crossSegments = null;
            else
                this.crossSegments = new SplitFileFetcherCrossSegmentStorage[crossSegments];
            for(int i=0;i<crossSegments;i++) {
                this.crossSegments[i] = new SplitFileFetcherCrossSegmentStorage(this, i, dis);
            }
            this.keyListener = new SplitFileFetcherKeyListener(this, fetcher, dis, false, newSalt);
        } catch (IOException e) {
            // We are reading from an array! Bad as written perhaps?
            throw new StorageFormatException("Cannot read basic settings even though passed checksum: "+e, e);
        }
        for(SplitFileFetcherSegmentStorage segment : segments) {
            boolean needsDecode = false;
            try {
                segment.readMetadata();
                if(segment.hasFailed()) {
                    raf.close();
                    raf.free(); // Failed, so free it.
                    throw new FetchException(FetchExceptionMode.SPLITFILE_ERROR, errors);
                }
            } catch (ChecksumFailedException e) {
                Logger.error(this, "Progress for segment "+segment.segNo+" on "+this+" corrupted.");
                needsDecode = true;
            }
            if(segment.needsDecode())
                needsDecode = true;
            if(needsDecode) {
                if(segmentsToTryDecode == null)
                    segmentsToTryDecode = new ArrayList<SplitFileFetcherSegmentStorage>();
                segmentsToTryDecode.add(segment);
            }
        }
        for(int i=0;i<segments.length;i++) {
            SplitFileFetcherSegmentStorage segment = segments[i];
            try {
                segment.readSegmentKeys();
            } catch (ChecksumFailedException e) {
                throw new StorageFormatException("Keys corrupted");
            }
        }
        if(this.crossSegments != null) {
            for(SplitFileFetcherCrossSegmentStorage crossSegment : this.crossSegments)
                // Must be after reading the metadata for the plain segments.
                crossSegment.checkBlocks();
        }
        readGeneralProgress();
    }
    
    private void readGeneralProgress() throws IOException {
        try {
            byte[] buf = preadChecksummedWithLength(offsetGeneralProgress);
            ByteArrayInputStream bais = new ByteArrayInputStream(buf);
            DataInputStream dis = new DataInputStream(bais);
            long flags = dis.readLong();
            if((flags & HAS_CHECKED_DATASTORE_FLAG) != 0)
                hasCheckedDatastore = true;
            errors = new FailureCodeTracker(false, dis);
            dis.close();
        } catch (ChecksumFailedException e) {
            Logger.error(this, "Failed to read general progress: "+e);
            // Reset general progress
            this.hasCheckedDatastore = false;
            this.errors = new FailureCodeTracker(false);
        } catch (StorageFormatException e) {
            Logger.error(this, "Failed to read general progress: "+e);
            // Reset general progress
            this.hasCheckedDatastore = false;
            this.errors = new FailureCodeTracker(false);
        }
    }

    private byte[] encodeGeneralProgress() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            OutputStream ccos = checksumChecker.checksumWriterWithLength(baos, new ArrayBucketFactory());
            DataOutputStream dos = new DataOutputStream(ccos);
            long flags = 0;
            if(hasCheckedDatastore)
                flags |= HAS_CHECKED_DATASTORE_FLAG;
            dos.writeLong(flags);
            errors.writeFixedLengthTo(dos);
            dos.close();
        } catch (IOException e) {
            throw new Error(e);
        }
        byte[] ret = baos.toByteArray();
        return ret;
    }

    /** Start the storage layer.
     * @param resume True only if we are restarting without having serialized, i.e. from the file 
     * only. In this case we will need to tell the parent how many blocks have been fetched.
     * @return True if it should be scheduled immediately. If false, the storage layer will 
     * callback into the fetcher later.
     */
    public boolean start(boolean resume) {
        if(resume) {
            int splitfileDataBlocks = 0, splitfileCheckBlocks = 0, totalCrossCheckBlocks = 0;
            int succeededBlocks = 0;
            int failedBlocks = 0;
            for(SplitFileFetcherSegmentStorage segment : segments) {
                splitfileDataBlocks += segment.dataBlocks;
                splitfileCheckBlocks += segment.checkBlocks;
                totalCrossCheckBlocks += segment.crossSegmentCheckBlocks;
                succeededBlocks += segment.foundBlocks();
                failedBlocks += segment.failedBlocks();
            }
            fetcher.setSplitfileBlocks(splitfileDataBlocks + totalCrossCheckBlocks, splitfileCheckBlocks);
            fetcher.onResume(succeededBlocks, failedBlocks, clientMetadata, decompressedLength);
        }
        if(crossSegments != null) {
            for(SplitFileFetcherCrossSegmentStorage segment : crossSegments) {
                segment.restart();
            }
        }
        if(segmentsToTryDecode != null) {
            List<SplitFileFetcherSegmentStorage> brokenSegments;
            synchronized(SplitFileFetcherStorage.this) {
                brokenSegments = segmentsToTryDecode;
                segmentsToTryDecode = null;
            }
            if(brokenSegments != null) {
                for(SplitFileFetcherSegmentStorage segment : brokenSegments) {
                    segment.tryStartDecode();
                }
            }
        }
        if(keyListener.needsKeys()) {
            try {
                this.jobRunner.queue(new PersistentJob() {

                    @Override
                    public boolean run(ClientContext context) {
                        System.out.println("Regenerating filters for "+SplitFileFetcherStorage.this);
                        Logger.error(this, "Regenerating filters for "+SplitFileFetcherStorage.this);
                        KeySalter salt = fetcher.getSalter();
                        for(int i=0;i<segments.length;i++) {
                            SplitFileFetcherSegmentStorage segment = segments[i];
                            try {
                                try {
                                    SplitFileSegmentKeys keys = segment.readSegmentKeys();
                                    for(int j=0;j<keys.totalKeys();j++) {
                                        keyListener.addKey(keys.getKey(j, null, false).getNodeKey(false), i, salt);
                                    }
                                } catch (IOException e) {
                                    failOnDiskError(e);
                                    return false;
                                }
                            } catch (ChecksumFailedException e) {
                                failOnDiskError(e);
                                return false;
                            }
                        }
                        keyListener.addedAllKeys();
                        try {
                            keyListener.initialWriteSegmentBloomFilters(offsetSegmentBloomFilters);
                            keyListener.innerWriteMainBloomFilter(offsetMainBloomFilter);
                        } catch (IOException e) {
                            if(persistent)
                                failOnDiskError(e);
                        }
                        fetcher.restartedAfterDataCorruption();
                        Logger.warning(this, "Finished regenerating filters for "+SplitFileFetcherStorage.this);
                        System.out.println("Finished regenerating filters for "+SplitFileFetcherStorage.this);
                        return false;
                    }
                    
                }, NativeThread.LOW_PRIORITY+1);
            } catch (PersistenceDisabledException e) {
                // Ignore.
            }
            return false;
        }
        return true;
    }
    
    OutputStream checksumOutputStream(OutputStream os) {
        return checksumChecker.checksumWriter(os);
    }

    private byte[] encodeBasicSettings(int totalDataBlocks, int totalCheckBlocks, int totalCrossCheckBlocks) {
        return appendChecksum(innerEncodeBasicSettings(totalDataBlocks, totalCheckBlocks, totalCrossCheckBlocks));
    }
    
    /** Encode the basic settings (number of blocks etc) to a byte array */
    private byte[] innerEncodeBasicSettings(int totalDataBlocks, int totalCheckBlocks, 
            int totalCrossCheckBlocks) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            dos.writeShort(splitfileType.code);
            dos.writeByte(this.splitfileSingleCryptoAlgorithm);
            dos.writeBoolean(this.splitfileSingleCryptoKey != null);
            if(this.splitfileSingleCryptoKey != null) {
                assert(splitfileSingleCryptoKey.length == 32);
                dos.write(splitfileSingleCryptoKey);
            }
            dos.writeLong(this.finalLength);
            dos.writeLong(this.decompressedLength);
            clientMetadata.writeTo(dos);
            dos.writeInt(decompressors.size()); // FIXME enforce size limits???
            for(COMPRESSOR_TYPE c : decompressors)
                dos.writeShort(c.metadataID);
            dos.writeLong(offsetKeyList);
            dos.writeLong(offsetSegmentStatus);
            dos.writeLong(offsetGeneralProgress);
            dos.writeLong(offsetMainBloomFilter);
            dos.writeLong(offsetSegmentBloomFilters);
            dos.writeLong(offsetOriginalMetadata);
            dos.writeLong(offsetOriginalDetails);
            dos.writeLong(offsetBasicSettings);
            dos.writeBoolean(completeViaTruncation);
            dos.writeInt(finalMinCompatMode.ordinal());
            dos.writeInt(segments.length);
            dos.writeInt(totalDataBlocks);
            dos.writeInt(totalCheckBlocks);
            dos.writeInt(totalCrossCheckBlocks);
            for(SplitFileFetcherSegmentStorage segment : segments) {
                segment.writeFixedMetadata(dos);
            }
            if(this.crossSegments == null)
                dos.writeInt(0);
            else {
                dos.writeInt(crossSegments.length);
                for(SplitFileFetcherCrossSegmentStorage segment : crossSegments) {
                    segment.writeFixedMetadata(dos);
                }
            }
            keyListener.writeStaticSettings(dos);
        } catch (IOException e) {
            throw new Error(e); // Impossible
        }
        return baos.toByteArray();
    }

    /** Write details needed to restart the download from scratch, and to identify whether it is
     * useful to do so. */
    private byte[] encodeAndChecksumOriginalDetails(FreenetURI thisKey, FreenetURI origKey,
            byte[] clientDetails, boolean isFinalFetch) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeUTF(thisKey.toASCIIString());
        dos.writeUTF(origKey.toASCIIString());
        dos.writeBoolean(isFinalFetch);
        dos.writeInt(clientDetails.length);
        dos.write(clientDetails);
        dos.writeInt(maxRetries);
        dos.writeInt(cooldownTries);
        dos.writeLong(cooldownLength);
        return checksumChecker.appendChecksum(baos.toByteArray());
    }

    /** FIXME not used yet */
    private void allocateCrossDataBlock(SplitFileFetcherCrossSegmentStorage segment, Random random) {
        int x = 0;
        for(int i=0;i<10;i++) {
            x = random.nextInt(segments.length);
            SplitFileFetcherSegmentStorage seg = segments[x];
            int blockNum = seg.allocateCrossDataBlock(segment, random);
            if(blockNum >= 0) {
                segment.addDataBlock(seg, blockNum);
                return;
            }
        }
        for(int i=0;i<segments.length;i++) {
            x++;
            if(x == segments.length) x = 0;
            SplitFileFetcherSegmentStorage seg = segments[x];
            int blockNum = seg.allocateCrossDataBlock(segment, random);
            if(blockNum >= 0) {
                segment.addDataBlock(seg, blockNum);
                return;
            }
        }
        throw new IllegalStateException("Unable to allocate cross data block!");
    }

    /** FIXME not used yet */
    private void allocateCrossCheckBlock(SplitFileFetcherCrossSegmentStorage segment, Random random) {
        int x = 0;
        for(int i=0;i<10;i++) {
            x = random.nextInt(segments.length);
            SplitFileFetcherSegmentStorage seg = segments[x];
            int blockNum = seg.allocateCrossCheckBlock(segment, random);
            if(blockNum >= 0) {
                segment.addDataBlock(seg, blockNum);
                return;
            }
        }
        for(int i=0;i<segments.length;i++) {
            x++;
            if(x == segments.length) x = 0;
            SplitFileFetcherSegmentStorage seg = segments[x];
            int blockNum = seg.allocateCrossCheckBlock(segment, random);
            if(blockNum >= 0) {
                segment.addDataBlock(seg, blockNum);
                return;
            }
        }
        throw new IllegalStateException("Unable to allocate cross data block!");
    }
    
    public short getPriorityClass() {
        return fetcher.getPriorityClass();
    }

    /** A segment successfully completed. 
     * @throws PersistenceDisabledException */
    public void finishedSuccess(SplitFileFetcherSegmentStorage segment) {
        if(logMINOR) Logger.minor(this, "finishedSuccess on "+this+" from "+segment+" for "+fetcher, new Exception("debug"));
        if(!(completeViaTruncation || fetcher.wantBinaryBlob()))
            maybeComplete();
    }
    
    private void maybeComplete() {
        if(allSucceeded()) {
            callSuccessOffThread();
        } else if(allFinished() && !allSucceeded()) {
            // Some failed.
            fail(new FetchException(FetchExceptionMode.SPLITFILE_ERROR, errors));
        }
    }
    
    private void callSuccessOffThread() {
        jobRunner.queueNormalOrDrop(new PersistentJob() {
            
            @Override
            public boolean run(ClientContext context) {
                synchronized(SplitFileFetcherStorage.this) {
                    // Race conditions are possible, make sure we only call it once.
                    if(succeeded) return false;
                    succeeded = true;
                }
                fetcher.onSuccess();
                return true;
            }
            
        });
    }

    private boolean allSucceeded() {
        for(SplitFileFetcherSegmentStorage segment : segments) {
            if(!segment.hasSucceeded()) return false;
        }
        return true;
    }

    public StreamGenerator streamGenerator() {
        // FIXME truncation optimisation.
        return new StreamGenerator() {

            @Override
            public void writeTo(OutputStream os)
                    throws IOException {
                LockableRandomAccessBuffer.RAFLock lock = raf.lockOpen();
                try {
                    for(SplitFileFetcherSegmentStorage segment : segments) {
                        segment.writeToInner(os);
                    }
                    os.close();
                } catch (Throwable t) {
                    Logger.error(this, "Failed to write stream: "+t, t);
                } finally {
                    lock.unlock();
                }
            }

            @Override
            public long size() {
                return finalLength;
            }
            
        };
    }

    static final long LAZY_WRITE_METADATA_DELAY = TimeUnit.MINUTES.toMillis(5);
    
    private final PersistentJob writeMetadataJob = new PersistentJob() {

        @Override
        public boolean run(ClientContext context) {
            try {
                if(isFinishing()) return false;
                RAFLock lock = raf.lockOpen();
                try {
                    for(SplitFileFetcherSegmentStorage segment : segments) {
                        segment.writeMetadata(false);
                    }
                    keyListener.maybeWriteMainBloomFilter(offsetMainBloomFilter);
                } finally {
                    lock.unlock();
                }
                writeGeneralProgress(false);
                return false;
            } catch (IOException e) {
                if(isFinishing()) return false;
                Logger.error(this, "Failed writing metadata for "+SplitFileFetcherStorage.this+": "+e, e);
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

    public void lazyWriteMetadata() {
        if(!persistent) return;
        if(LAZY_WRITE_METADATA_DELAY != 0) {
            // The Runnable must be the same object for de-duplication.
            ticker.queueTimedJob(wrapLazyWriteMetadata, "Write metadata for splitfile", 
                    LAZY_WRITE_METADATA_DELAY, false, true);
        } else { // Must still be off-thread, multiple segments, possible locking issues...
            jobRunner.queueNormalOrDrop(writeMetadataJob);
        }
    }

    public void finishedFetcher() {
        synchronized(this) {
            if(finishedFetcher) {
                if(logMINOR) Logger.minor(this, "Already finishedFetcher");
                return;
            }
            finishedFetcher = true;
            if(completeViaTruncation && !cancelled) return; // Ignore.
            if(!finishedEncoding) return;
        }
        closeOffThread();
    }
    
    /** Called on a normal non-truncation completion. Frees the storage file off-thread. */
    private void closeOffThread() {
        jobRunner.queueNormalOrDrop(new PersistentJob() {
            
            @Override
            public boolean run(ClientContext context) {
                // ATOMICITY/DURABILITY: This will run after the checkpoint after completion.
                // So after restart, even if the checkpoint failed, we will be in a valid state.
                // This is why this is queue() not queueInternal().
                close();
                return true;
            }
            
        });
    }

    private void finishedEncoding() {
        // This is rather convoluted in the failure case ...
        boolean lateCompletion = false;
        boolean waitingForFetcher = false;
        synchronized(this) {
            if(finishedEncoding) {
                if(logMINOR) Logger.minor(this, "Already finishedEncoding");
                return;
            }
            if(logMINOR) Logger.minor(this, "Finished encoding");
            finishedEncoding = true;
            if(cancelled) {
                // Must close off-thread.
            } else if((completeViaTruncation || fetcher.wantBinaryBlob()) && !succeeded) {
                // Must complete.
                lateCompletion = true;
            } else {
                // May wait for fetcher.
                waitingForFetcher = !finishedFetcher;
            }
        }
        if(lateCompletion) {
            // We have not called onSuccess() or fail() yet.
            if(allFinished() && !allSucceeded()) {
                // No more blocks will be found, so fail *now*.
                fail(new FetchException(FetchExceptionMode.SPLITFILE_ERROR, errors));
            } else {
                if(completeViaTruncation) raf.close();
                maybeComplete();
                return;
            }
        }
        if(waitingForFetcher) return;
        closeOffThread();
    }
    
    /** Shutdown and free resources. CONCURRENCY: Caller is responsible for making sure this is 
     * not called on a MemoryLimitedJob thread. */
    void close() {
        if(logMINOR) Logger.minor(this, "Finishing "+this+" for "+fetcher, new Exception("debug"));
        raf.close();
        raf.free();
        fetcher.onClosed();
    }
    
    /** Called when a segment has finished encoding. It is possible that it has simply restarted; 
     * it is not guaranteed to have encoded all blocks etc. But we still need the callback in case
     * e.g. we are in the process of failing, and can't proceed until all the encode jobs have 
     * finished. */
    void finishedEncoding(SplitFileFetcherSegmentStorage segment) {
        if(logMINOR) Logger.minor(this, "Successfully decoded "+segment+" for "+this+" for "+fetcher);
        if(!allFinished()) return;
        finishedEncoding();
    }
    
    /** Called when a cross-segment has finished decoding. It doesn't necessarily have a "finished"
     * state, except if it was cancelled. */
    void finishedEncoding(SplitFileFetcherCrossSegmentStorage segment) {
        if(logMINOR) Logger.minor(this, "Successfully decoded "+segment+" for "+this+" for "+fetcher);
        if(!allFinished()) return;
        finishedEncoding();
    }
    
    private boolean allFinished() {
        // First, are any of the segments still working, that is, are they able to send requests,
        // or are they decoding/encoding?
        for(SplitFileFetcherSegmentStorage segment : segments) {
            if(!segment.isFinished()) return false;
        }
        // We cannot proceed unless none of the cross-segments is decoding.
        if(crossSegments != null) {
            for(SplitFileFetcherCrossSegmentStorage segment : crossSegments) {
                if(segment.isDecoding()) return false;
            }
        }
        return true;
    }
    
    /** Fail the request, off-thread. The callback will call cancel etc, so it won't immediately
     * shut down the storage.
     * @param e
     */
    public void fail(final FetchException e) {
        if(logMINOR) Logger.minor(this, "Failing "+this+" with error "+e+" and codes "+errors);
        jobRunner.queueNormalOrDrop(new PersistentJob() {
            
            @Override
            public boolean run(ClientContext context) {
                fetcher.fail(e);
                return true;
            }
                
        });
    }

    /** A segment ran out of retries. We have given up on that segment and therefore on the whole
     * splitfile. */
    public void failOnSegment() {
        fail(new FetchException(FetchExceptionMode.SPLITFILE_ERROR, errors));
    }

    public void failOnDiskError(final IOException e) {
        Logger.error(this, "Failing on disk error: "+e, e);
        jobRunner.queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                fetcher.failOnDiskError(e);
                return true;
            }
            
        });
    }

    public void failOnDiskError(final ChecksumFailedException e) {
        Logger.error(this, "Failing on unrecoverable corrupt data: "+e, e);
        jobRunner.queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                fetcher.failOnDiskError(e);
                return true;
            }
            
        });
    }

    public long countUnfetchedKeys() {
        long total = 0;
        for(SplitFileFetcherSegmentStorage segment : segments)
            total += segment.countUnfetchedKeys();
        return total;
    }

    public Key[] listUnfetchedKeys() {
        try {
            ArrayList<Key> keys = new ArrayList<Key>();
            for(SplitFileFetcherSegmentStorage segment : segments)
                segment.getUnfetchedKeys(keys);
            return keys.toArray(new Key[keys.size()]);
        } catch (IOException e) {
            failOnDiskError(e);
            return new Key[0];
        }
    }
    
    public long countSendableKeys() {
        long now = System.currentTimeMillis();
        long total = 0;
        for(SplitFileFetcherSegmentStorage segment : segments)
            total += segment.countSendableKeys();
        return total;
    }

    final class MyKey implements SendableRequestItem, SendableRequestItemKey {

        public MyKey(int n, int segNo, SplitFileFetcherStorage storage) {
            this.blockNumber = n;
            this.segmentNumber = segNo;
            this.get = storage;
            hashCode = initialHashCode();
        }

        final int blockNumber;
        final int segmentNumber;
        final SplitFileFetcherStorage get;
        final int hashCode;

        @Override
        public void dump() {
            // Ignore.
        }

        @Override
        public SendableRequestItemKey getKey() {
            return this;
        }
        
        @Override
        public boolean equals(Object o) {
            if(this == o) return true;
            if(!(o instanceof MyKey)) return false;
            MyKey k = (MyKey)o;
            return k.blockNumber == blockNumber && k.segmentNumber == segmentNumber && 
                k.get == get;
        }
        
        public int hashCode() {
            return hashCode;
        }

        private int initialHashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + blockNumber;
            result = prime * result + ((get == null) ? 0 : get.hashCode());
            result = prime * result + segmentNumber;
            return result;
        }
        
        public String toString() {
            return "MyKey:"+segmentNumber+":"+blockNumber;
        }

    }

    /** Choose a random key which can be fetched at the moment. Must not update any persistent data;
     * it's okay to update caches and other stuff that isn't stored to disk. If we fail etc we 
     * should do it off-thread.
     * 
     * FIXME make SplitFileFetcherGet per-segment, eliminate all this unnecessary complexity!
     * 
     * @return The block number to be fetched, as an integer.
     */
    public MyKey chooseRandomKey() {
        // FIXME this should probably use SimpleBlockChooser and hence use lowest-retry-count from each segment?
        synchronized(this) {
            if(finishedFetcher) return null;
        }
        // Generally segments are fairly well balanced, so we can usually pick a random segment 
        // then a random key from it.
        // FIXME OPT SCALABILITY A simpler option might be just to have one SplitFileFetcherGet per
        // segment, like the old code.
        synchronized(randomSegmentIterator) {
            randomSegmentIterator.reset(random);
            while (randomSegmentIterator.hasNext()) {
                SplitFileFetcherSegmentStorage segment = randomSegmentIterator.next();
                int ret = segment.chooseRandomKey();
                if (ret != -1) {
                    return new MyKey(ret, segment.segNo, this);
                }
            }
        }
        return null;
    }

    /** Cancel the download, stop all FEC decodes, and call close() off-thread when done. */
    void cancel() {
        synchronized(this) {
            cancelled = true;
        }
        for(SplitFileFetcherSegmentStorage segment : segments)
            segment.cancel();
        if(crossSegments != null) {
            for(SplitFileFetcherCrossSegmentStorage segment : crossSegments)
                segment.cancel();
        }
    }

    /** Local only is true and we've finished checking the datastore. If all segments are not 
     * already finished/decoding, we need to fail with DNF. If the segments fail to decode due to
     * data corruption, we will retry as usual. */
    public void finishedCheckingDatastoreOnLocalRequest() {
        // At this point, all the blocks will have been processed.
        if(hasFinished()) return; // Don't need to do anything.
        this.errors.inc(FetchExceptionMode.ALL_DATA_NOT_FOUND);
        for(SplitFileFetcherSegmentStorage segment : segments) {
            segment.onFinishedCheckingDatastoreNoFetch();
        }
        maybeComplete();
    }

    synchronized boolean hasFinished() {
        return cancelled || finishedFetcher;
    }
    
    synchronized boolean isFinishing() {
        return cancelled || finishedFetcher || finishedEncoding;
    }

    public void onFailure(MyKey key, FetchException fe) {
        if(logMINOR) Logger.minor(this, "Failure: "+fe.mode+" for block "+key.blockNumber+" for "+key.segmentNumber);
        synchronized(this) {
            if(cancelled || finishedFetcher) return;
            dirtyGeneralProgress = true;
        }
        errors.inc(fe.getMode());
        SplitFileFetcherSegmentStorage segment = segments[key.segmentNumber];
        segment.onNonFatalFailure(key.blockNumber);
        lazyWriteMetadata();
    }

    public ClientKey getKey(MyKey key) {
        try {
            return segments[key.segmentNumber].getSegmentKeys().getKey(key.blockNumber, null, false);
        } catch (IOException e) {
            this.failOnDiskError(e);
            return null;
        }
    }

    public int maxRetries() {
        return maxRetries;
    }

    public void failedBlock() {
        jobRunner.queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                fetcher.onFailedBlock();
                return false;
            }
            
        });
    }

    public boolean lastBlockMightNotBePadded() {
        return (finalMinCompatMode == CompatibilityMode.COMPAT_UNKNOWN || 
                finalMinCompatMode.ordinal() < CompatibilityMode.COMPAT_1416.ordinal());
    }

    public void restartedAfterDataCorruption() {
        jobRunner.queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                maybeClearCooldown();
                fetcher.restartedAfterDataCorruption();
                return false;
            }
            
        });
    }

    /** Separate lock for cooldown operations, which must be serialized. Must be taken *BEFORE*
     * segment locks. */
    private final Object cooldownLock = new Object();

    /** Called when a segment goes into overall cooldown. */
    void increaseCooldown(final long cooldownTime) {
        // Risky locking-wise, so run as a separate job.
        jobRunner.queueNormalOrDrop(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                long now = System.currentTimeMillis();
                long wakeupTime;
                synchronized(cooldownLock) {
                    if(cooldownTime < now) return false;
                    long oldCooldownTime = overallCooldownWakeupTime;
                    if(overallCooldownWakeupTime > now) return false; // Wait for it to wake up.
                    wakeupTime = Long.MAX_VALUE;
                    for(SplitFileFetcherSegmentStorage segment : segments) {
                        long segmentTime = segment.getOverallCooldownTime();
                        if(segmentTime < now) return false;
                        wakeupTime = Math.min(segmentTime, wakeupTime);
                    }
                    overallCooldownWakeupTime = wakeupTime;
                    if(overallCooldownWakeupTime < oldCooldownTime) return false;
                }
                fetcher.reduceCooldown(wakeupTime);
                return false;
            }
            
        });
    }

    /** Called when a segment exits cooldown e.g. due to a request completing and becoming 
     * retryable. Must NOT be called with segment locks held. */
    public void maybeClearCooldown() {
        synchronized(cooldownLock) {
            if(overallCooldownWakeupTime == 0 || 
                    overallCooldownWakeupTime < System.currentTimeMillis()) return;
            overallCooldownWakeupTime = 0;
        }
        fetcher.clearCooldown();
    }

    /** Returns -1 if the request is finished, otherwise the wakeup time. */
    public long getCooldownWakeupTime(long now) {
        // LOCKING: hasFinished() uses (this), separate from cooldownLock.
        // It is safe to use both here (on the request selection thread), one after the other.
        if (hasFinished()) return -1;
        synchronized(cooldownLock) {
            if (overallCooldownWakeupTime < now) overallCooldownWakeupTime = 0;
            return overallCooldownWakeupTime;
        }
    }
    
    // Operations with checksums and storage access.
    
    /** Append a CRC32 to a (short) byte[] */
    private byte[] appendChecksum(byte[] data) {
        return checksumChecker.appendChecksum(data);
    }
    
    void preadChecksummed(long fileOffset, byte[] buf, int offset, int length) throws IOException, ChecksumFailedException {
        byte[] checksumBuf = new byte[checksumLength];
        RAFLock lock = raf.lockOpen();
        try {
            raf.pread(fileOffset, buf, offset, length);
            raf.pread(fileOffset+length, checksumBuf, 0, checksumLength);
        } finally {
            lock.unlock();
        }
        if(!checksumChecker.checkChecksum(buf, offset, length, checksumBuf)) {
            Arrays.fill(buf, offset, offset+length, (byte)0);
            throw new ChecksumFailedException();
        }
    }

    byte[] preadChecksummedWithLength(long fileOffset) throws IOException, ChecksumFailedException, StorageFormatException {
        byte[] checksumBuf = new byte[checksumLength];
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
            raf.pread(fileOffset+length+lengthBuf.length, checksumBuf, 0, checksumLength);
        } finally {
            lock.unlock();
        }
        if(!checksumChecker.checkChecksum(buf, 0, length, checksumBuf)) {
            Arrays.fill(buf, 0, length, (byte)0);
            throw new ChecksumFailedException();
        }
        return buf;
    }

    /** Create an OutputStream that we can write formatted data to of a specific length. On 
     * close(), it checks that the length is as expected, computes the checksum, and writes the
     * data to the specified position in the file.
     * @param fileOffset The position in the file (raf) of the first byte.
     * @param length The length, including checksum, of the data to be written.
     * @return
     */
    OutputStream writeChecksummedTo(final long fileOffset, final int length) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream(length);
        OutputStream cos = checksumOutputStream(baos);
        return new FilterOutputStream(cos) {
            
            public void close() throws IOException {
                out.close();
                byte[] buf = baos.toByteArray();
                if(buf.length != length)
                    throw new IllegalStateException("Wrote wrong number of bytes: "+buf.length+" should be "+length);
                raf.pwrite(fileOffset, buf, 0, length);
            }
            
        };
    }

    RAFLock lockRAFOpen() throws IOException {
        return raf.lockOpen();
    }

    void writeBlock(SplitFileFetcherSegmentStorage segment, int slotNumber, byte[] data) 
    throws IOException {
        raf.pwrite(segment.blockOffset(slotNumber), data, 0, data.length);
    }

    byte[] readBlock(SplitFileFetcherSegmentStorage segment, int slotNumber) 
    throws IOException {
        long offset = segment.blockOffset(slotNumber);
        if(logDEBUG) Logger.minor(this, "Reading block "+slotNumber+" for "+segment.segNo+"/"+segments.length+" from "+offset+" RAF length is "+raf.size());
        byte[] buf = new byte[CHKBlock.DATA_LENGTH];
        raf.pread(offset, buf, 0, buf.length);
        return buf;
    }

    /** Needed for resuming. */
    LockableRandomAccessBuffer getRAF() {
        return raf;
    }

    public synchronized void setHasCheckedStore(ClientContext context) {
        hasCheckedDatastore = true;
        dirtyGeneralProgress = true;
        if(!persistent) return;
        writeMetadataJob.run(context);
    }

    private synchronized void writeGeneralProgress(boolean force) {
        if(!dirtyGeneralProgress && !force) return;
        dirtyGeneralProgress = false;
        byte[] generalProgress = encodeGeneralProgress();
        try {
            raf.pwrite(offsetGeneralProgress, generalProgress, 0, generalProgress.length);
        } catch (IOException e) {
            failOnDiskError(e);
        }
    }

    public synchronized boolean hasCheckedStore() {
        return hasCheckedDatastore;
    }

    void onShutdown(ClientContext context) {
        writeMetadataJob.run(context);
    }

}
