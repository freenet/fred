package freenet.client.async;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;

import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.crypt.ChecksumFailedException;
import freenet.crypt.SHA256;
import freenet.keys.CHKBlock;
import freenet.keys.Key;
import freenet.keys.KeyBlock;
import freenet.keys.NodeCHK;
import freenet.node.SendableGet;
import freenet.support.BinaryBloomFilter;
import freenet.support.BloomFilter;
import freenet.support.CountingBloomFilter;
import freenet.support.Logger;
import freenet.support.io.StorageFormatException;

public class SplitFileFetcherKeyListener implements KeyListener {
    
    private static volatile boolean logMINOR;
    static {
        Logger.registerClass(SplitFileFetcherKeyListener.class);
    }
    
    final SplitFileFetcherStorage storage;
    final SplitFileFetcherStorageCallback fetcher;
    /** Salt used in the secondary Bloom filters if the primary matches.
     * The primary Bloom filters use the already-salted saltedKey. */
    private final byte[] localSalt;
    /** Size of the main Bloom filter in bytes. */
    private final int mainBloomFilterSizeBytes;
    /** Default mainBloomElementsPerKey. False positives is approx
     * 0.6185^[this number], so 19 gives us 0.01% false positives, which should
     * be acceptable even if there are thousands of splitfiles on the queue. */
    static final int DEFAULT_MAIN_BLOOM_ELEMENTS_PER_KEY = 19;
    /** Number of hashes for the main filter. */
    private final int mainBloomK;
    /** What proportion of false positives is acceptable for the per-segment
     * Bloom filters? This is divided by the number of segments, so it is (roughly)
     * an overall probability of any false positive given that we reach the
     * per-segment filters. IMHO 1 in 100 is adequate. */
    static final double ACCEPTABLE_BLOOM_FALSE_POSITIVES_ALL_SEGMENTS = 0.01;
    /** Size of per-segment bloom filter in bytes. This is calculated from the
     * above constant and the number of segments, and rounded up. */
    private final int perSegmentBloomFilterSizeBytes;
    /** Number of hashes for the per-segment bloom filters. */
    private final int perSegmentK;
    /** The overall bloom filter, containing all the keys, salted with the global hash. When a key
     * is found, it is removed from this. */
    private final CountingBloomFilter filter;
    /** The per-segment bloom filters, containing the keys for each segment. These are not changed. */
    private final BinaryBloomFilter[] segmentFilters;
    private boolean finishedSetup;
    private final boolean persistent;
    /** Does the main bloom filter need writing? */
    private boolean dirty;
    private transient boolean mustRegenerateMainFilter;
    private transient boolean mustRegenerateSegmentFilters;
    
    /** Create a set of bloom filters for a new download.
     * @throws FetchException */
    public SplitFileFetcherKeyListener(SplitFileFetcherStorageCallback fetcher, SplitFileFetcherStorage storage, 
            boolean persistent, byte[] localSalt, int origSize, int segBlocks, int segments) 
    throws FetchException {
        if (origSize <= 0) {
            throw new FetchException(FetchExceptionMode.INTERNAL_ERROR, "Cannot listen for non-positive number of blocks: " + origSize);
        }
        if (segBlocks <= 0) {
            throw new FetchException(FetchExceptionMode.INTERNAL_ERROR, "Cannot listen for non-positive number of blocks per segment: " + segBlocks);
        }
        if (segments <= 0) {
            throw new FetchException(FetchExceptionMode.INTERNAL_ERROR, "Cannot listen for non-positive number of segments: " + segments);
        }
        this.fetcher = fetcher;
        this.storage = storage;
        this.localSalt = localSalt;
        this.persistent = persistent;
        int mainElementsPerKey = DEFAULT_MAIN_BLOOM_ELEMENTS_PER_KEY;
        mainBloomK = (int) (mainElementsPerKey * 0.7);
        long elementsLong = origSize * mainElementsPerKey;
        // REDFLAG: SIZE LIMIT: 3.36TB limit!
        if(elementsLong > Integer.MAX_VALUE)
            throw new FetchException(FetchExceptionMode.TOO_BIG, "Cannot fetch splitfiles with more than "+(Integer.MAX_VALUE/mainElementsPerKey)+" keys! (approx 3.3TB)");
        int mainSizeBits = (int)elementsLong; // counting filter
        mainSizeBits = (mainSizeBits + 7) & ~7; // round up to bytes
        mainBloomFilterSizeBytes = mainSizeBits / 8 * 2; // counting filter
        double acceptableFalsePositives = ACCEPTABLE_BLOOM_FALSE_POSITIVES_ALL_SEGMENTS / segments;
        int perSegmentBitsPerKey = (int) Math.ceil(Math.log(acceptableFalsePositives) / Math.log(0.6185));
        if(segBlocks > origSize)
            segBlocks = origSize;
        int perSegmentSize = perSegmentBitsPerKey * segBlocks;
        perSegmentSize = (perSegmentSize + 7) & ~7;
        perSegmentBloomFilterSizeBytes = perSegmentSize / 8;
        perSegmentK = BloomFilter.optimialK(perSegmentSize, segBlocks);
        segmentFilters = new BinaryBloomFilter[segments];
        byte[] segmentsFilterBuffer = new byte[perSegmentBloomFilterSizeBytes * segments];
        ByteBuffer baseBuffer = ByteBuffer.wrap(segmentsFilterBuffer);
        int start = 0;
        int end = perSegmentBloomFilterSizeBytes;
        for(int i=0;i<segments;i++) {
            baseBuffer.position(start);
            baseBuffer.limit(end);
            ByteBuffer slice;
            
            slice = baseBuffer.slice();
            segmentFilters[i] = new BinaryBloomFilter(slice, perSegmentBloomFilterSizeBytes * 8, perSegmentK);
            start += perSegmentBloomFilterSizeBytes;
            end += perSegmentBloomFilterSizeBytes;
        }
        byte[] filterBuffer = new byte[mainBloomFilterSizeBytes];
        filter = new CountingBloomFilter(mainBloomFilterSizeBytes * 8 / 2, mainBloomK, filterBuffer);
        filter.setWarnOnRemoveFromEmpty();
    }
    
    public SplitFileFetcherKeyListener(SplitFileFetcherStorage storage, 
            SplitFileFetcherStorageCallback callback, DataInputStream dis, boolean persistent, boolean newSalt) 
    throws IOException, StorageFormatException {
        this.storage = storage;
        this.fetcher = callback;
        this.persistent = persistent;
        localSalt = new byte[32];
        dis.readFully(localSalt);
        mainBloomFilterSizeBytes = dis.readInt();
        // FIXME impose an upper bound based on estimate of bits per key.
        if(mainBloomFilterSizeBytes < 0)
            throw new StorageFormatException("Bad main bloom filter size");
        mainBloomK = dis.readInt();
        if(mainBloomK < 1)
            throw new StorageFormatException("Bad main bloom filter K");
        perSegmentBloomFilterSizeBytes = dis.readInt();
        if(perSegmentBloomFilterSizeBytes < 0)
            throw new StorageFormatException("Bad per segment bloom filter size");
        perSegmentK = dis.readInt();
        if(perSegmentK < 0)
            throw new StorageFormatException("Bad per segment bloom filter K");
        int segments = storage.segments.length;
        segmentFilters = new BinaryBloomFilter[segments];
        byte[] segmentsFilterBuffer = new byte[perSegmentBloomFilterSizeBytes * segments];
        try {
            storage.preadChecksummed(storage.offsetSegmentBloomFilters, segmentsFilterBuffer, 0, segmentsFilterBuffer.length);
        } catch (ChecksumFailedException e) {
            Logger.error(this, "Checksummed read for segment filters at "+storage.offsetSegmentBloomFilters+" failed for "+this+": "+e);
            mustRegenerateSegmentFilters = true;
        }
        ByteBuffer baseBuffer = ByteBuffer.wrap(segmentsFilterBuffer);
        int start = 0;
        int end = perSegmentBloomFilterSizeBytes;
        for(int i=0;i<segments;i++) {
            baseBuffer.position(start);
            baseBuffer.limit(end);
            ByteBuffer slice;
            
            slice = baseBuffer.slice();
            segmentFilters[i] = new BinaryBloomFilter(slice, perSegmentBloomFilterSizeBytes * 8, perSegmentK);
            start += perSegmentBloomFilterSizeBytes;
            end += perSegmentBloomFilterSizeBytes;
        }
        byte[] filterBuffer = new byte[mainBloomFilterSizeBytes];
        if(!newSalt) {
            try {
                storage.preadChecksummed(storage.offsetMainBloomFilter, filterBuffer, 0, mainBloomFilterSizeBytes);
            } catch (ChecksumFailedException e) {
                Logger.error(this, "Checksummed read for main filters at "+storage.offsetMainBloomFilter+" failed for "+this+": "+e);
                mustRegenerateMainFilter = true;
            }
        } else {
            mustRegenerateMainFilter = true;
        }
        filter = new CountingBloomFilter(mainBloomFilterSizeBytes * 8 / 2, mainBloomK, filterBuffer);
        filter.setWarnOnRemoveFromEmpty();
    }

    /**
     * SplitFileFetcher adds keys in whatever blocks are convenient.
     * @param keys
     */
    synchronized void addKey(Key key, int segNo, KeySalter salter) {
        if(finishedSetup && !(mustRegenerateMainFilter || mustRegenerateSegmentFilters)) 
            throw new IllegalStateException();
        if(mustRegenerateMainFilter || !finishedSetup) {
            byte[] saltedKey = salter.saltKey(key);
            filter.addKey(saltedKey);
        }
        if(mustRegenerateSegmentFilters || !finishedSetup) {
            byte[] localSalted = localSaltKey(key);
            segmentFilters[segNo].addKey(localSalted);
        }
//      if(!segmentFilters[segNo].checkFilter(localSalted))
//          Logger.error(this, "Key added but not in filter: "+key+" on "+this);
    }
    
    synchronized void finishedSetup() {
        finishedSetup = true;
    }

    private byte[] localSaltKey(Key key) {
        MessageDigest md = SHA256.getMessageDigest();
        md.update(key.getRoutingKey());
        md.update(localSalt);
        byte[] ret = md.digest();
        SHA256.returnMessageDigest(md);
        return ret;
    }
    
    /** The segment bloom filters should only need to be written ONCE, and can all be written at 
     * once. Include a checksum. */
    void initialWriteSegmentBloomFilters(long fileOffset) throws IOException {
        OutputStream cos = storage.writeChecksummedTo(fileOffset, totalSegmentBloomFiltersSize());
        for(BinaryBloomFilter segFilter : segmentFilters) {
            segFilter.writeTo(cos);
        }
        cos.close();
    }
    
    int totalSegmentBloomFiltersSize() {
        return perSegmentBloomFilterSizeBytes * segmentFilters.length + storage.checksumLength;
    }
    
    void maybeWriteMainBloomFilter(long fileOffset) throws IOException {
        synchronized(this) {
            if(!dirty) return;
            dirty = false;
        }
        innerWriteMainBloomFilter(fileOffset);
    }

    /** Write the main segment filter, which does get updated. Include a checksum. */
    void innerWriteMainBloomFilter(long fileOffset) throws IOException {
        OutputStream cos = storage.writeChecksummedTo(fileOffset, paddedMainBloomFilterSize());
        filter.writeTo(cos);
        cos.close();
    }
    
    public int paddedMainBloomFilterSize() {
        assert(mainBloomFilterSizeBytes == filter.getSizeBytes());
        return mainBloomFilterSizeBytes + storage.checksumLength;
    }

    @Override
    public boolean probablyWantKey(Key key, byte[] saltedKey) {
        if(filter.checkFilter(saltedKey)) {
            byte[] salted = localSaltKey(key);
            for(int i=0;i<segmentFilters.length;i++) {
                if(segmentFilters[i].checkFilter(salted)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public short definitelyWantKey(Key key) {
        // Caller has already called probablyWantKey(), so don't do it again.
        byte[] salted = localSaltKey(key);
        for(int i=0;i<segmentFilters.length;i++) {
            if(segmentFilters[i].checkFilter(salted)) {
                if(storage.segments[i].definitelyWantKey((NodeCHK)key))
                    return fetcher.getPriorityClass();
            }
        }
        return -1;
    }

    @Override
    public SendableGet[] getRequestsForKey(Key key) {
        // FIXME Ignored. We don't use the cooldown *queue*.
        return null;
    }

    @Override
    public boolean handleBlock(Key key, byte[] saltedKey, KeyBlock block, ClientContext context) {
        // Caller has already called probablyWantKey(), so don't do it again.
        boolean found = false;
        byte[] salted = localSaltKey(key);
        if(logMINOR)
            Logger.minor(this, "handleBlock("+key+") on "+this+" for "+fetcher, new Exception("debug"));
        for(int i=0;i<segmentFilters.length;i++) {
            boolean match;
            synchronized(this) {
                match = segmentFilters[i].checkFilter(salted);
            }
            if(match) {
                try {
                    found = storage.segments[i].onGotKey((NodeCHK)key, (CHKBlock)block);
                } catch (IOException e) {
                    fetcher.failOnDiskError(e);
                    return false;
                }
            }
        }
        if(found) {
            synchronized(this) {
                dirty = true;
            }
            filter.removeKey(saltedKey);
            if(persistent)
                storage.lazyWriteMetadata();
        }
        return found;
    }

    @Override
    public boolean persistent() {
        return persistent;
    }

    @Override
    public short getPriorityClass() {
        return fetcher.getPriorityClass();
    }

    @Override
    public long countKeys() {
        // FIXME remove. Only used by persistent fetches.
        throw new UnsupportedOperationException();
    }

    @Override
    public HasKeyListener getHasKeyListener() {
        return fetcher.getHasKeyListener();
    }

    @Override
    public void onRemove() {
        // Ignore.
    }

    @Override
    public boolean isEmpty() {
        return storage.hasFinished();
    }

    @Override
    public boolean isSSK() {
        return false;
    }

    public void writeStaticSettings(DataOutputStream dos) throws IOException {
        dos.write(localSalt);
        dos.writeInt(mainBloomFilterSizeBytes);
        dos.writeInt(mainBloomK);
        dos.writeInt(perSegmentBloomFilterSizeBytes);
        dos.writeInt(perSegmentK);
    }

    public boolean needsKeys() {
        return mustRegenerateMainFilter || mustRegenerateSegmentFilters;
    }

    public void addedAllKeys() {
        mustRegenerateMainFilter = false;
        mustRegenerateSegmentFilters = false;
        finishedSetup = true;
    }

}
