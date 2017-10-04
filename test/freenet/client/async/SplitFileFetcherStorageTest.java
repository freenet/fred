package freenet.client.async;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import freenet.client.ClientMetadata;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.HighLevelSimpleClientImpl;
import freenet.client.InsertContext;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.client.Metadata;
import freenet.client.Metadata.SplitfileAlgorithm;
import freenet.client.MetadataParseException;
import freenet.client.MetadataUnresolvedException;
import freenet.client.OnionFECCodec;
import freenet.client.events.SimpleEventProducer;
import freenet.crypt.CRCChecksumChecker;
import freenet.crypt.ChecksumFailedException;
import freenet.crypt.DummyRandomSource;
import freenet.keys.CHKBlock;
import freenet.keys.CHKEncodeException;
import freenet.keys.ClientCHK;
import freenet.keys.ClientCHKBlock;
import freenet.keys.FreenetURI;
import freenet.keys.Key;
import freenet.keys.NodeCHK;
import freenet.node.BaseSendableGet;
import freenet.node.KeysFetchingLocally;
import freenet.node.SendableInsert;
import freenet.node.SendableRequestItemKey;
import freenet.support.CheatingTicker;
import freenet.support.DummyJobRunner;
import freenet.support.MemoryLimitedJobRunner;
import freenet.support.PooledExecutor;
import freenet.support.Ticker;
import freenet.support.WaitableExecutor;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.api.LockableRandomAccessBuffer;
import freenet.support.api.LockableRandomAccessBufferFactory;
import freenet.support.compress.Compressor.COMPRESSOR_TYPE;
import freenet.support.io.ArrayBucketFactory;
import freenet.support.io.BucketTools;
import freenet.support.io.ByteArrayRandomAccessBufferFactory;
import freenet.support.io.NativeThread;
import freenet.support.io.StorageFormatException;
import junit.framework.TestCase;

public class SplitFileFetcherStorageTest extends TestCase {
    
    // Setup code is considerable. See below for actual tests ...
    
    static DummyRandomSource random;
    static final KeySalter salt = new KeySalter() {

        @Override
        public byte[] saltKey(Key key) {
            return key.getRoutingKey();
        }
        
    };
    static BucketFactory bf = new ArrayBucketFactory();
    static LockableRandomAccessBufferFactory rafFactory = new ByteArrayRandomAccessBufferFactory();
    static final WaitableExecutor exec = new WaitableExecutor(new PooledExecutor());
    static final PersistentJobRunner jobRunner = new DummyJobRunner(exec, null);
    static final Ticker ticker = new CheatingTicker(exec);
    static MemoryLimitedJobRunner memoryLimitedJobRunner = new MemoryLimitedJobRunner(9*1024*1024L, 20, exec, NativeThread.JAVA_PRIORITY_RANGE);
    static final int BLOCK_SIZE = CHKBlock.DATA_LENGTH;
    private static final OnionFECCodec codec = new OnionFECCodec();
    private static final int MAX_SEGMENT_SIZE = 256;
    static final int KEY_LENGTH = 32;
    static final CompatibilityMode COMPATIBILITY_MODE = InsertContext.CompatibilityMode.COMPAT_1416;
    static FreenetURI URI;
    private static final List<COMPRESSOR_TYPE> NO_DECOMPRESSORS = Collections.emptyList();
    
    public void setUp() {
        // Reset RNG for each test (it's static so not reset by junit).
        random = new DummyRandomSource(1234);
        URI = FreenetURI.generateRandomCHK(random);
    }
    
    static class TestSplitfile {
        final Bucket originalData;
        final Metadata metadata;
        final byte[][] dataBlocks;
        final byte[][] checkBlocks;
        final ClientCHK[] dataKeys;
        final ClientCHK[] checkKeys;
        private final byte[] cryptoKey;
        private final byte cryptoAlgorithm;
        private final int[] segmentDataBlockCount;
        private final int[] segmentCheckBlockCount;
        private final boolean persistent;
        final MyKeysFetchingLocally fetchingKeys;
        
        private TestSplitfile(Bucket data, Metadata m, byte[][] originalDataBlocks,
                byte[][] originalCheckBlocks, ClientCHK[] dataKeys, ClientCHK[] checkKeys,
                byte[] cryptoKey, byte cryptoAlgorithm, int[] segmentDataBlockCount, 
                int[] segmentCheckBlockCount, boolean persistent) {
            this.originalData = data;
            this.metadata = m;
            this.dataBlocks = originalDataBlocks;
            this.checkBlocks = originalCheckBlocks;
            this.dataKeys = dataKeys;
            this.checkKeys = checkKeys;
            this.cryptoKey = cryptoKey;
            this.cryptoAlgorithm = cryptoAlgorithm;
            this.segmentDataBlockCount = segmentDataBlockCount;
            this.segmentCheckBlockCount = segmentCheckBlockCount;
            this.persistent = persistent;
            this.fetchingKeys = new MyKeysFetchingLocally();
        }
        
        void free() {
            originalData.free();
        }

        static TestSplitfile constructSingleSegment(long size, int checkBlocks, String mime, boolean persistent) throws IOException, CHKEncodeException, MetadataUnresolvedException, MetadataParseException {
            assertTrue(checkBlocks <= MAX_SEGMENT_SIZE);
            assertTrue(size < MAX_SEGMENT_SIZE * (long)BLOCK_SIZE);
            Bucket data = makeRandomBucket(size);
            byte[][] originalDataBlocks = splitAndPadBlocks(data, size);
            int dataBlocks = originalDataBlocks.length;
            assertTrue(dataBlocks <= MAX_SEGMENT_SIZE);
            assertTrue(dataBlocks + checkBlocks <= MAX_SEGMENT_SIZE);
            byte[][] originalCheckBlocks = constructBlocks(checkBlocks);
            codec.encode(originalDataBlocks, originalCheckBlocks, falseArray(checkBlocks), BLOCK_SIZE);
            ClientMetadata cm = new ClientMetadata(mime);
            // FIXME no hashes for now.
            // FIXME no compression for now.
            byte[] cryptoKey = randomKey();
            byte cryptoAlgorithm = Key.ALGO_AES_CTR_256_SHA256;
            ClientCHK[] dataKeys = makeKeys(originalDataBlocks, cryptoKey, cryptoAlgorithm);
            ClientCHK[] checkKeys = makeKeys(originalCheckBlocks, cryptoKey, cryptoAlgorithm);
            Metadata m = new Metadata(SplitfileAlgorithm.ONION_STANDARD, dataKeys, checkKeys, dataBlocks, 
                    checkBlocks, 0, cm, size, null, null, size, false, null, null, size, size, dataBlocks, 
                    dataBlocks + checkBlocks, false, COMPATIBILITY_MODE, 
                    cryptoAlgorithm, cryptoKey, true, 0);
            // Make sure the metadata is reusable.
            // FIXME also necessary as the above constructor doesn't set segments.
            Bucket metaBucket = m.toBucket(bf);
            Metadata m1 = Metadata.construct(metaBucket);
            Bucket copyBucket = m1.toBucket(bf);
            assertTrue(BucketTools.equalBuckets(metaBucket, copyBucket));
            metaBucket.free();
            copyBucket.free();
            return new TestSplitfile(data, m1, originalDataBlocks, originalCheckBlocks, dataKeys, checkKeys, 
                    cryptoKey, cryptoAlgorithm, null, null, persistent);
        }

        /**
         * Create a multi-segment test splitfile. The main complication with multi-segment is that we can't 
         * choose the number of blocks in each segment arbitrarily; that depends on the metadata format; the
         * caller must ensure that the number are consistent.
         * @param size
         * @param segmentDataBlockCount The actual number of data blocks in each segment. Must be consistent 
         * with the other parameters; this cannot be chosen freely due to the metadata format.
         * @param segmentCheckBlockCount The actual number of check blocks in each segment. Must be consistent 
         * with the other parameters; this cannot be chosen freely due to the metadata format. 
         * @param segmentSize The "typical" number of data blocks in a segment.
         * @param checkSegmentSize The "typical" number of check blocks in a segment.
         * @param deductBlocksFromSegments The number of segments from which a single block has been deducted.
         * This is used when the number of data blocks isn't an exact multiple of the number of segments.
         * @param topCompatibilityMode The "short" value of the definitive compatibility mode used to create
         * the splitfile. This must again be consistent with the rest, as it is sometimes used in decoding.
         * @param mime
         * @return
         * @throws IOException
         * @throws CHKEncodeException
         * @throws MetadataUnresolvedException
         * @throws MetadataParseException
         */
        static TestSplitfile constructMultipleSegments(long size, int[] segmentDataBlockCount, 
                int[] segmentCheckBlockCount, int segmentSize, int checkSegmentSize, 
                int deductBlocksFromSegments, CompatibilityMode topCompatibilityMode, String mime, boolean persistent) 
        throws IOException, CHKEncodeException, MetadataUnresolvedException, MetadataParseException {
            int dataBlocks = sum(segmentDataBlockCount);
            int checkBlocks = sum(segmentCheckBlockCount);
            int segments = segmentDataBlockCount.length;
            assertEquals((size + BLOCK_SIZE - 1) / BLOCK_SIZE, dataBlocks);
            assertEquals(segments, segmentCheckBlockCount.length);
            Bucket data = makeRandomBucket(size);
            byte[][] originalDataBlocks = splitAndPadBlocks(data, size);
            byte[][] originalCheckBlocks = constructBlocks(checkBlocks);
            int startDataBlock = 0;
            int startCheckBlock = 0;
            for(int seg=0;seg<segments;seg++) {
                byte[][] segmentDataBlocks = Arrays.copyOfRange(originalDataBlocks, startDataBlock, startDataBlock + segmentDataBlockCount[seg]);
                byte[][] segmentCheckBlocks = Arrays.copyOfRange(originalCheckBlocks, startCheckBlock, startCheckBlock + segmentCheckBlockCount[seg]);
                codec.encode(segmentDataBlocks, segmentCheckBlocks, falseArray(segmentCheckBlocks.length), BLOCK_SIZE);
                startDataBlock += segmentDataBlockCount[seg];
                startCheckBlock += segmentCheckBlockCount[seg];
            }
            ClientMetadata cm = new ClientMetadata(mime);
            // FIXME no hashes for now.
            // FIXME no compression for now.
            byte[] cryptoKey = randomKey();
            byte cryptoAlgorithm = Key.ALGO_AES_CTR_256_SHA256;
            ClientCHK[] dataKeys = makeKeys(originalDataBlocks, cryptoKey, cryptoAlgorithm);
            ClientCHK[] checkKeys = makeKeys(originalCheckBlocks, cryptoKey, cryptoAlgorithm);
            Metadata m = new Metadata(SplitfileAlgorithm.ONION_STANDARD, dataKeys, checkKeys, segmentSize, 
                    checkSegmentSize, deductBlocksFromSegments, cm, size, null, null, size, false, null, null, 
                    size, size, dataBlocks, dataBlocks + checkBlocks, false, topCompatibilityMode, 
                    cryptoAlgorithm, cryptoKey, true /* FIXME try older splitfiles pre-single-key?? */, 
                    0);
            // Make sure the metadata is reusable.
            // FIXME also necessary as the above constructor doesn't set segments.
            Bucket metaBucket = m.toBucket(bf);
            Metadata m1 = Metadata.construct(metaBucket);
            Bucket copyBucket = m1.toBucket(bf);
            assertTrue(BucketTools.equalBuckets(metaBucket, copyBucket));
            metaBucket.free();
            copyBucket.free();
            return new TestSplitfile(data, m1, originalDataBlocks, originalCheckBlocks, dataKeys, checkKeys, 
                    cryptoKey, cryptoAlgorithm, segmentDataBlockCount, segmentCheckBlockCount, persistent);
        }
        
        public CHKBlock encodeDataBlock(int i) throws CHKEncodeException {
            return ClientCHKBlock.encodeSplitfileBlock(dataBlocks[i], cryptoKey, cryptoAlgorithm).getBlock();
        }
        
        public CHKBlock encodeCheckBlock(int i) throws CHKEncodeException {
            return ClientCHKBlock.encodeSplitfileBlock(checkBlocks[i], cryptoKey, cryptoAlgorithm).getBlock();
        }
        
        public CHKBlock encodeBlock(int block) throws CHKEncodeException {
            if(block < dataBlocks.length)
                return encodeDataBlock(block);
            else
                return encodeCheckBlock(block - dataBlocks.length);
        }

        public int findCheckBlock(byte[] data, int start) {
            start++;
            for(int i=start;i<checkBlocks.length;i++) {
                if(checkBlocks[i] == data) return i;
            }
            for(int i=start;i<checkBlocks.length;i++) {
                if(Arrays.equals(checkBlocks[i], data)) return i;
            }
            return -1;
        }

        public int findDataBlock(byte[] data, int start) {
            start++;
            for(int i=start;i<dataBlocks.length;i++) {
                if(dataBlocks[i] == data) return i;
            }
            for(int i=start;i<dataBlocks.length;i++) {
                if(Arrays.equals(dataBlocks[i], data)) return i;
            }
            return -1;
        }

        public StorageCallback createStorageCallback() {
            return new StorageCallback(this);
        }
        
        public SplitFileFetcherStorage createStorage(StorageCallback cb) throws FetchException, MetadataParseException, IOException {
            return createStorage(cb, makeFetchContext());
        }

        public SplitFileFetcherStorage createStorage(final StorageCallback cb, FetchContext ctx) throws FetchException, MetadataParseException, IOException {
            LockableRandomAccessBufferFactory f = new LockableRandomAccessBufferFactory() {

                @Override
                public LockableRandomAccessBuffer makeRAF(long size) throws IOException {
                    LockableRandomAccessBuffer t = rafFactory.makeRAF(size);
                    cb.snoopRAF(t);
                    return t;
                }

                @Override
                public LockableRandomAccessBuffer makeRAF(byte[] initialContents, int offset,
                        int size, boolean readOnly) throws IOException {
                    LockableRandomAccessBuffer t = rafFactory.makeRAF(initialContents, offset, size, readOnly);
                    cb.snoopRAF(t);
                    return t;
                }
                
            };
            return new SplitFileFetcherStorage(metadata, cb, NO_DECOMPRESSORS, metadata.getClientMetadata(), false,
                    (short) COMPATIBILITY_MODE.ordinal(), ctx, salt, URI, URI, true, new byte[0], random, bf,
                    f, jobRunner, ticker, memoryLimitedJobRunner, new CRCChecksumChecker(), persistent, null, null, fetchingKeys);
        }

        /** Restore a splitfile fetcher from a file. 
         * @throws StorageFormatException 
         * @throws IOException 
         * @throws FetchException */
        public SplitFileFetcherStorage createStorage(StorageCallback cb, FetchContext ctx,
                LockableRandomAccessBuffer raf) throws IOException, StorageFormatException, FetchException {
            assertTrue(persistent);
            return new SplitFileFetcherStorage(raf, cb, ctx, random, jobRunner, fetchingKeys, ticker, memoryLimitedJobRunner, new CRCChecksumChecker(), false, false);
        }

        public FetchContext makeFetchContext() {
            return HighLevelSimpleClientImpl.makeDefaultFetchContext(Long.MAX_VALUE, Long.MAX_VALUE,
                    new SimpleEventProducer());
        }

        public void verifyOutput(SplitFileFetcherStorage storage) throws IOException {
            StreamGenerator g = storage.streamGenerator();
            Bucket out = bf.makeBucket(-1);
            OutputStream os = out.getOutputStream();
            g.writeTo(os);
            os.close();
            assertTrue(BucketTools.equalBuckets(originalData, out));
            out.free();
        }

        public NodeCHK getCHK(int block) {
            if(block < dataBlocks.length)
                return dataKeys[block].getNodeCHK();
            else
                return checkKeys[block-dataBlocks.length].getNodeCHK();
        }

        public int segmentFor(int block) {
            int total = 0;
            // Must be consistent with the getCHK() counting etc.
            // Count data blocks first then check blocks.
            for(int i=0;i<segmentDataBlockCount.length;i++) {
                total += segmentDataBlockCount[i];
                if(block < total) return i;
            }
            for(int i=0;i<segmentCheckBlockCount.length;i++) {
                total += segmentCheckBlockCount[i];
                if(block < total) return i;
            }
            
            return -1;
        }

    }
    
    public static ClientCHK[] makeKeys(byte[][] blocks, byte[] cryptoKey, byte cryptoAlgorithm) throws CHKEncodeException {
        ClientCHK[] keys = new ClientCHK[blocks.length];
        for(int i=0;i<blocks.length;i++)
            keys[i] = ClientCHKBlock.encodeSplitfileBlock(blocks[i], cryptoKey, cryptoAlgorithm).getClientKey();
        return keys;
    }
    
    public static int sum(int[] values) {
        int total = 0;
        for(int x : values) total += x;
        return total;
    }

    static class StorageCallback implements SplitFileFetcherStorageCallback {
        
        final TestSplitfile splitfile;
        final boolean[] encodedBlocks;
        private boolean succeeded;
        private boolean closed;
        private boolean failed;
        private boolean hasRestartedOnCorruption;
        private LockableRandomAccessBuffer raf;

        public StorageCallback(TestSplitfile splitfile) {
            this.splitfile = splitfile;
            encodedBlocks = new boolean[splitfile.dataBlocks.length + splitfile.checkBlocks.length];
        }

        synchronized void snoopRAF(LockableRandomAccessBuffer t) {
            this.raf = t;
        }
        
        synchronized LockableRandomAccessBuffer getRAF() {
            return raf;
        }

        @Override
        public synchronized void onSuccess() {
            succeeded = true;
            notifyAll();
        }

        @Override
        public synchronized void onClosed() {
            closed = true;
            notifyAll();
        }

        @Override
        public short getPriorityClass() {
            return 0;
        }

        @Override
        public synchronized void failOnDiskError(IOException e) {
            failed = true;
            notifyAll();
            System.err.println("Failed on disk error: "+e);
            e.printStackTrace();
        }

        @Override
        public void setSplitfileBlocks(int requiredBlocks, int remainingBlocks) {
            assertEquals(requiredBlocks, splitfile.dataBlocks.length);
            assertEquals(remainingBlocks, splitfile.checkBlocks.length);
        }

        @Override
        public void onSplitfileCompatibilityMode(CompatibilityMode min, CompatibilityMode max,
                byte[] customSplitfileKey, boolean compressed, boolean bottomLayer,
                boolean definitiveAnyway) {
            // Ignore. FIXME?
        }

        @Override
        public void queueHeal(byte[] data, byte[] cryptoKey, byte cryptoAlgorithm) {
            assertTrue(Arrays.equals(cryptoKey, splitfile.cryptoKey));
            assertEquals(cryptoAlgorithm, splitfile.cryptoAlgorithm);
            int x = -1;
            boolean progress = false;
            while((x = splitfile.findCheckBlock(data, x)) != -1) {
                synchronized(this) {
                    encodedBlocks[x+splitfile.dataBlocks.length] = true;
                }
                progress = true;
            }
            if(!progress) {
                // Data block?
                while((x = splitfile.findDataBlock(data, x)) != -1) {
                    synchronized(this) {
                        encodedBlocks[x] = true;
                    }
                    progress = true;
                }
            }
            if(!progress) {
                System.err.println("Queued healing block not in the original block list");
                assertTrue(false);
            }
            assertTrue(progress);
        }
        
        synchronized void markDownloadedBlock(int block) {
            encodedBlocks[block] = true;
        }

        public synchronized void checkFailed() {
            assertFalse(failed);
        }

        public synchronized void waitForFinished() {
            while(!(succeeded || failed)) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    // Ignore.
                }
            }
        }
        
        public synchronized void waitForFailed() {
            while(!(succeeded || failed)) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    // Ignore.
                }
            }
            assertTrue(failed);
        }
        
        public void waitForFree(SplitFileFetcherStorage storage) {
            synchronized(this) {
                while(!closed) {
                    try {
                        wait();
                    } catch (InterruptedException e) {
                        // Ignore.
                    }
                }
                assertTrue(succeeded);
            }
            int x = 0;
            synchronized(this) {
                for(int i=0;i<encodedBlocks.length;i++)
                    assertTrue("Block "+i+" not found or decoded", encodedBlocks[i]);
            }
        }

        @Override
        public void onFetchedBlock() {
            // Ignore.
        }

        @Override
        public void fail(FetchException fe) {
            synchronized(this) {
                failed = true;
                notifyAll();
            }
        }

        @Override
        public void onFailedBlock() {
            // Ignore.
        }

        @Override
        public void maybeAddToBinaryBlob(ClientCHKBlock decodedBlock) {
            // Ignore.
        }

        @Override
        public boolean wantBinaryBlob() {
            return false;
        }

        @Override
        public BaseSendableGet getSendableGet() {
            return null;
        }

        @Override
        public void restartedAfterDataCorruption() {
            // Will be used in a different test.
            synchronized(this) {
                hasRestartedOnCorruption = true;
            }
        }

        @Override
        public void clearCooldown() {
            // Ignore.
        }
        
        @Override
        public void reduceCooldown(long wakeupTime) {
            // Ignore.
        }

        @Override
        public HasKeyListener getHasKeyListener() {
            return null;
        }

        @Override
        public void failOnDiskError(ChecksumFailedException e) {
            synchronized(this) {
                failed = true;
                notifyAll();
            }
        }

        @Override
        public KeySalter getSalter() {
            return salt;
        }

        @Override
        public void onResume(int succeeded, int failed, ClientMetadata mimeType, long finalSize) {
            // Ignore.
        }
        
    }

    public static Bucket makeRandomBucket(long size) throws IOException {
        Bucket b = bf.makeBucket(size);
        BucketTools.fill(b, random, size);
        return b;
    }

    public static byte[][] splitAndPadBlocks(Bucket data, long size) throws IOException {
        int n = (int) ((size + BLOCK_SIZE - 1) / BLOCK_SIZE);
        byte[][] blocks = new byte[n][];
        InputStream is = data.getInputStream();
        DataInputStream dis = new DataInputStream(is);
        for(int i=0;i<n;i++) {
            blocks[i] = new byte[BLOCK_SIZE];
            if(i < n-1) {
                dis.readFully(blocks[i]);
            } else {
                int length = (int) (size - i*BLOCK_SIZE);
                dis.readFully(blocks[i], 0, length);
                // Now pad it ...
                blocks[i] = BucketTools.pad(blocks[i], BLOCK_SIZE, length);
            }
        }
        return blocks;
    }

    public static byte[] randomKey() {
        byte[] buf = new byte[KEY_LENGTH];
        random.nextBytes(buf);
        return buf;
    }

    public static boolean[] falseArray(int checkBlocks) {
        return new boolean[checkBlocks];
    }

    public static byte[][] constructBlocks(int n) {
        byte[][] blocks = new byte[n][];
        for(int i=0;i<n;i++) blocks[i] = new byte[BLOCK_SIZE];
        return blocks;
    }
    
    // Actual tests ...
    
    public void testSingleSegment() throws CHKEncodeException, IOException, FetchException, MetadataParseException, MetadataUnresolvedException {
        // 2 data blocks.
        //testSingleSegment(1, 2, BLOCK_SIZE);
        // We don't test this case because it just copies the data block to the check blocks.
        // Which breaks some of the scripts here.
        testSingleSegment(2, 1, BLOCK_SIZE*2);
        testSingleSegment(2, 1, BLOCK_SIZE+1);
        testSingleSegment(2, 2, BLOCK_SIZE*2);
        testSingleSegment(2, 2, BLOCK_SIZE+1);
        testSingleSegment(2, 3, BLOCK_SIZE*2);
        testSingleSegment(2, 3, BLOCK_SIZE+1);
        testSingleSegment(128, 128, BLOCK_SIZE*128);
        testSingleSegment(128, 128, BLOCK_SIZE*128-1);
        testSingleSegment(129, 127, BLOCK_SIZE*129);
        testSingleSegment(129, 127, BLOCK_SIZE*129-1);
        testSingleSegment(127, 129, BLOCK_SIZE*127);
        testSingleSegment(127, 129, BLOCK_SIZE*127-1);
    }
    
    private void testSingleSegment(int dataBlocks, int checkBlocks, long size) throws CHKEncodeException, IOException, FetchException, MetadataParseException, MetadataUnresolvedException {
        assertTrue(dataBlocks * (long)BLOCK_SIZE >= size);
        TestSplitfile test = TestSplitfile.constructSingleSegment(size, checkBlocks, null, false);
        testDataBlocksOnly(test);
        if(checkBlocks >= dataBlocks)
            testCheckBlocksOnly(test);
        testRandomMixture(test);
        test.free();
    }

    private void testDataBlocksOnly(TestSplitfile test) throws IOException, CHKEncodeException, FetchException, MetadataParseException {
        StorageCallback cb = test.createStorageCallback();
        SplitFileFetcherStorage storage = test.createStorage(cb);
        SplitFileFetcherSegmentStorage segment = storage.segments[0];
        for(int i=0;i<test.checkBlocks.length;i++) {
            segment.onNonFatalFailure(test.dataBlocks.length+i);
        }
        for(int i=0;i<test.dataBlocks.length;i++) {
            assertFalse(segment.hasStartedDecode());
            assertTrue(segment.onGotKey(test.dataKeys[i].getNodeCHK(), test.encodeDataBlock(i)));
            cb.markDownloadedBlock(i);
        }
        cb.checkFailed();
        assertTrue(segment.hasStartedDecode());
        cb.checkFailed();
        waitForDecode(segment);
        cb.checkFailed();
        cb.waitForFinished();
        cb.checkFailed();
        test.verifyOutput(storage);
        cb.checkFailed();
        storage.finishedFetcher();
        cb.checkFailed();
        waitForFinished(segment);
        cb.checkFailed();
        cb.waitForFree(storage);
        cb.checkFailed();
    }

    private void testCheckBlocksOnly(TestSplitfile test) throws IOException, CHKEncodeException, FetchException, MetadataParseException {
        StorageCallback cb = test.createStorageCallback();
        SplitFileFetcherStorage storage = test.createStorage(cb);
        SplitFileFetcherSegmentStorage segment = storage.segments[0];
        for(int i=0;i<test.dataBlocks.length;i++) {
            segment.onNonFatalFailure(i);
        }
        for(int i=test.dataBlocks.length;i<test.checkBlocks.length;i++) {
            segment.onNonFatalFailure(i+test.dataBlocks.length);
        }
        for(int i=0;i<test.dataBlocks.length /* only need that many to decode */;i++) {
            assertFalse(segment.hasStartedDecode());
            assertTrue(segment.onGotKey(test.checkKeys[i].getNodeCHK(), test.encodeCheckBlock(i)));
            cb.markDownloadedBlock(i + test.dataBlocks.length);
        }
        cb.checkFailed();
        assertTrue(segment.hasStartedDecode());
        cb.checkFailed();
        waitForDecode(segment);
        cb.checkFailed();
        cb.waitForFinished();
        cb.checkFailed();
        test.verifyOutput(storage);
        cb.checkFailed();
        storage.finishedFetcher();
        cb.checkFailed();
        waitForFinished(segment);
        cb.checkFailed();
        cb.waitForFree(storage);
        cb.checkFailed();
    }
    
    private void testRandomMixture(TestSplitfile test) throws FetchException, MetadataParseException, IOException, CHKEncodeException {
        StorageCallback cb = test.createStorageCallback();
        SplitFileFetcherStorage storage = test.createStorage(cb);
        SplitFileFetcherSegmentStorage segment = storage.segments[0];
        int total = test.dataBlocks.length+test.checkBlocks.length;
        for(int i=0;i<total;i++)
            segment.onNonFatalFailure(i); // We want healing on all blocks that aren't found.
        boolean[] hits = new boolean[total];
        for(int i=0;i<test.dataBlocks.length;i++) {
            int block;
            do {
                block = random.nextInt(total);
            } while (hits[block]);
            hits[block] = true;
            assertFalse(segment.hasStartedDecode());
            assertTrue(segment.onGotKey(test.getCHK(block), test.encodeBlock(block)));
            cb.markDownloadedBlock(block);
        }
        //printChosenBlocks(hits);
        cb.checkFailed();
        assertTrue(segment.hasStartedDecode());
        cb.checkFailed();
        waitForDecode(segment);
        cb.checkFailed();
        cb.waitForFinished();
        cb.checkFailed();
        test.verifyOutput(storage);
        cb.checkFailed();
        storage.finishedFetcher();
        cb.checkFailed();
        waitForFinished(segment);
        cb.checkFailed();
        cb.waitForFree(storage);
        cb.checkFailed();
    }
    
    // FIXME LATER Test cross-segment.

    public void testMultiSegment() throws CHKEncodeException, IOException, MetadataUnresolvedException, MetadataParseException, FetchException {
        // We have to be consistent with the format, but we can in fact play with the segment sizes 
        // to some degree.
        
        // Simplest case: Same number of blocks in each segment.
        // 2 blocks in each of 2 segments.
        testMultiSegment(32768*4, new int[] { 2, 2 }, new int[] { 3, 3 }, 2, 3, 0, 
                InsertContext.CompatibilityMode.COMPAT_1416);
        testMultiSegment(32768*4-1, new int[] { 2, 2 }, new int[] { 3, 3 }, 2, 3, 0, 
                InsertContext.CompatibilityMode.COMPAT_1416);
        
        // 3 blocks in 3 segments
        testMultiSegment(32768*9-1, new int[] { 3, 3, 3 }, new int[] { 4, 4, 4 }, 3, 4, 0, 
                InsertContext.CompatibilityMode.COMPAT_1416);
        
        // Deduct blocks. This is how we handle this situation in modern splitfiles.
        testMultiSegment(32768*7-1, new int[] { 3, 2, 2 }, new int[] { 4, 4, 4 }, 3, 4, 2, 
                InsertContext.CompatibilityMode.COMPAT_1416);
        
        // Sharp truncation. This is how we used to handle non-divisible numbers...
        testMultiSegment(32768*9-1, new int[] { 7, 2 }, new int[] { 7, 2 }, 7, 7, 0,
                InsertContext.CompatibilityMode.COMPAT_1416);
        // Still COMPAT_1416 because has crypto key etc.
        
        // FIXME test old splitfiles.
        // FIXME test really old splitfiles: last data block not padded
        // FIXME test really old splitfiles: non-redundant support
    }
    
    private void testMultiSegment(long size, int[] segmentDataBlockCount, 
                int[] segmentCheckBlockCount, int segmentSize, int checkSegmentSize, 
                int deductBlocksFromSegments, CompatibilityMode topCompatibilityMode) throws CHKEncodeException, IOException, MetadataUnresolvedException, MetadataParseException, FetchException {
        TestSplitfile test = TestSplitfile.constructMultipleSegments(size, segmentDataBlockCount,
                segmentCheckBlockCount, segmentSize, checkSegmentSize, deductBlocksFromSegments,
                topCompatibilityMode, null, false);
        testRandomMixtureMultiSegment(test);
        test.free();

    }

    private void testRandomMixtureMultiSegment(TestSplitfile test) throws CHKEncodeException, IOException, FetchException, MetadataParseException {
        StorageCallback cb = test.createStorageCallback();
        SplitFileFetcherStorage storage = test.createStorage(cb);
        int total = test.dataBlocks.length+test.checkBlocks.length;
        for(SplitFileFetcherSegmentStorage segment : storage.segments) {
            for(int i=0;i<segment.totalBlocks();i++)
                segment.onNonFatalFailure(i); // We want healing on all blocks that aren't found.
        }
        boolean[] hits = new boolean[total];
        for(int i=0;i<test.dataBlocks.length;i++) {
            int block;
            do {
                block = random.nextInt(total);
            } while (hits[block]);
            hits[block] = true;
            SplitFileFetcherSegmentStorage segment = storage.segments[test.segmentFor(block)];
            if(segment.hasStartedDecode()) {
                i--;
                continue;
            }
            assertTrue(segment.onGotKey(test.getCHK(block), test.encodeBlock(block)));
            cb.markDownloadedBlock(block);
        }
        printChosenBlocks(hits);
        cb.checkFailed();
        for(SplitFileFetcherSegmentStorage segment : storage.segments)
            assertTrue(segment.hasStartedDecode()); // All segments have started decoding.
        cb.checkFailed();
        for(SplitFileFetcherSegmentStorage segment : storage.segments)
            waitForDecode(segment);
        cb.checkFailed();
        cb.waitForFinished();
        cb.checkFailed();
        test.verifyOutput(storage);
        cb.checkFailed();
        storage.finishedFetcher();
        cb.checkFailed();
        for(SplitFileFetcherSegmentStorage segment : storage.segments)
            waitForFinished(segment);
        cb.checkFailed();
        cb.waitForFree(storage);
        cb.checkFailed();
    }

    private void printChosenBlocks(boolean[] hits) {
        StringBuilder sb = new StringBuilder();
        sb.append("Blocks: ");
        for(int i=0;i<hits.length;i++) {
            if(hits[i]) {
                sb.append(i);
                sb.append(" ");
            }
        }
        sb.setLength(sb.length()-1);
        System.out.println(sb.toString());
    }

    private void waitForFinished(SplitFileFetcherSegmentStorage segment) {
        while(!segment.isFinished()) {
            assertFalse(segment.hasFailed());
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                // Ignore.
            }
        }
    }

    private void waitForDecode(SplitFileFetcherSegmentStorage segment) {
        while(!segment.hasSucceeded()) {
            assertFalse(segment.hasFailed());
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                // Ignore.
            }
        }
    }
    
    static class MyKeysFetchingLocally implements KeysFetchingLocally {
        private final HashSet<Key> keys = new HashSet<Key>();

        @Override
        public long checkRecentlyFailed(Key key, boolean realTime) {
            return 0;
        }

        @Override
        public boolean hasKey(Key key, BaseSendableGet getterWaiting) {
            return keys.contains(key);
        }

        @Override
        public boolean hasInsert(SendableRequestItemKey token) {
            return false;
        }

        public void add(Key k) {
            keys.add(k);
        }

        public void clear() {
            keys.clear();
        }
        
    }
    
    public void testChooseKeyOneTry() throws CHKEncodeException, IOException, MetadataUnresolvedException, MetadataParseException, FetchException {
        int dataBlocks = 3, checkBlocks = 3;
        TestSplitfile test = TestSplitfile.constructSingleSegment(dataBlocks*BLOCK_SIZE, checkBlocks, null, false);
        StorageCallback cb = test.createStorageCallback();
        FetchContext ctx = test.makeFetchContext();
        ctx.maxSplitfileBlockRetries = 0;
        SplitFileFetcherStorage storage = test.createStorage(cb, ctx);
        boolean[] tried = new boolean[dataBlocks+checkBlocks];
        innerChooseKeyTest(dataBlocks, checkBlocks, storage.segments[0], tried, test, false);
        assertEquals(storage.chooseRandomKey(), null);
        cb.waitForFailed();
    }
    
    private void innerChooseKeyTest(int dataBlocks, int checkBlocks, SplitFileFetcherSegmentStorage storage, boolean[] tried, TestSplitfile test, boolean cooldown) {
        final MyKeysFetchingLocally keys = test.fetchingKeys;
        keys.clear();
        for(int i=0;i<dataBlocks+checkBlocks;i++) {
            int chosen = storage.chooseRandomKey();
            assertTrue(chosen != -1);
            assertFalse(tried[chosen]);
            tried[chosen] = true;
            Key k = test.getCHK(chosen);
            keys.add(k);
        }
        // Every block has been tried.
        for(boolean b : tried) {
            assertTrue(b);
        }
        if(cooldown) {
            assertEquals(storage.chooseRandomKey(), -1);
            // In infinite cooldown, waiting for all requests to complete.
            assertEquals(storage.getOverallCooldownTime(), Long.MAX_VALUE);
        }
        // Every request is running.
        // When we complete a request, we remove it from KeysFetchingLocally *and* call onNonFatalFailure.
        // This will reset the cooldown.
        for(int i=0;i<dataBlocks+checkBlocks;i++) {
            storage.onNonFatalFailure(i);
        }
        if(!cooldown) {
            // Cleared cooldown, if any.
            assertEquals(storage.getOverallCooldownTime(), 0);
        }
        assertTrue(storage.getOverallCooldownTime() != Long.MAX_VALUE || storage.hasFailed());
        // Now all the requests have completed, the keys are no longer being fetched.
        keys.clear();
        // Will be able to fetch keys immediately, unless in cooldown.
    }

    public void testChooseKeyThreeTries() throws CHKEncodeException, IOException, MetadataUnresolvedException, MetadataParseException, FetchException {
        int dataBlocks = 3, checkBlocks = 3;
        TestSplitfile test = TestSplitfile.constructSingleSegment(dataBlocks*BLOCK_SIZE, checkBlocks, null, false);
        StorageCallback cb = test.createStorageCallback();
        FetchContext ctx = test.makeFetchContext();
        ctx.maxSplitfileBlockRetries = 2;
        SplitFileFetcherStorage storage = test.createStorage(cb, ctx);
        for(int i=0;i<3;i++) {
            boolean[] tried = new boolean[dataBlocks+checkBlocks];
            innerChooseKeyTest(dataBlocks, checkBlocks, storage.segments[0], tried, test, false);
        }
        assertEquals(storage.chooseRandomKey(), null);
        cb.waitForFailed();
    }
    
    public void testChooseKeyCooldown() throws CHKEncodeException, IOException, MetadataUnresolvedException, MetadataParseException, FetchException, InterruptedException {
        int dataBlocks = 3, checkBlocks = 3;
        int COOLDOWN_TIME = 200;
        TestSplitfile test = TestSplitfile.constructSingleSegment(dataBlocks*BLOCK_SIZE, checkBlocks, null, false);
        StorageCallback cb = test.createStorageCallback();
        FetchContext ctx = test.makeFetchContext();
        ctx.maxSplitfileBlockRetries = 5;
        ctx.setCooldownRetries(3);
        ctx.setCooldownTime(COOLDOWN_TIME, true);
        SplitFileFetcherStorage storage = test.createStorage(cb, ctx);
        // 3 tries for each block.
        long now = System.currentTimeMillis();
        for(int i=0;i<3;i++) {
            boolean[] tried = new boolean[dataBlocks+checkBlocks];
            innerChooseKeyTest(dataBlocks, checkBlocks, storage.segments[0], tried, test, true);
        }
        assertTrue(storage.segments[0].getOverallCooldownTime() > now);
        assertFalse(storage.segments[0].getOverallCooldownTime() == Long.MAX_VALUE);
        // Now in cooldown.
        test.fetchingKeys.clear();
        assertEquals(storage.chooseRandomKey(), null);
        Thread.sleep((long)(COOLDOWN_TIME+COOLDOWN_TIME/2+1));
        cb.checkFailed();
        // Should be out of cooldown now.
        for(int i=0;i<3;i++) {
            boolean[] tried = new boolean[dataBlocks+checkBlocks];
            innerChooseKeyTest(dataBlocks, checkBlocks, storage.segments[0], tried, test, true);
        }
        // Now it should fail.
        cb.waitForFailed();
    }
    
    public void testWriteReadSegmentKeys() throws FetchException, MetadataParseException, IOException, CHKEncodeException, MetadataUnresolvedException, ChecksumFailedException {
        int dataBlocks = 3, checkBlocks = 3;
        TestSplitfile test = TestSplitfile.constructSingleSegment(dataBlocks*BLOCK_SIZE, checkBlocks, null, true);
        StorageCallback cb = test.createStorageCallback();
        SplitFileFetcherStorage storage = test.createStorage(cb);
        SplitFileFetcherSegmentStorage segment = storage.segments[0];
        SplitFileSegmentKeys keys = segment.getSegmentKeys();
        SplitFileSegmentKeys moreKeys = segment.readSegmentKeys();
        assertTrue(keys.equals(moreKeys));
        storage.close();
    }

    /** Test persistence: Create and then reload. Don't do anything. */
    public void testPersistenceReload() throws CHKEncodeException, IOException, MetadataUnresolvedException, MetadataParseException, FetchException, StorageFormatException {
        int dataBlocks = 2;
        int checkBlocks = 3;
        long size = 32768*2-1;
        assertTrue(dataBlocks * (long)BLOCK_SIZE >= size);
        TestSplitfile test = TestSplitfile.constructSingleSegment(size, checkBlocks, null, true);
        StorageCallback cb = test.createStorageCallback();
        SplitFileFetcherStorage storage = test.createStorage(cb);
        // No need to shutdown the old storage.
        storage = test.createStorage(cb, test.makeFetchContext(), cb.getRAF());
        storage.close();
    }
    
    public void testPersistenceReloadThenFetch() throws IOException, StorageFormatException, CHKEncodeException, MetadataUnresolvedException, MetadataParseException, FetchException {
        int dataBlocks = 2;
        int checkBlocks = 3;
        long size = 32768*2-1;
        assertTrue(dataBlocks * (long)BLOCK_SIZE >= size);
        TestSplitfile test = TestSplitfile.constructSingleSegment(size, checkBlocks, null, true);
        StorageCallback cb = test.createStorageCallback();
        SplitFileFetcherStorage storage = test.createStorage(cb);
        // No need to shutdown the old storage.
        storage = test.createStorage(cb, test.makeFetchContext(), cb.getRAF());
        SplitFileFetcherSegmentStorage segment = storage.segments[0];
        assertFalse(segment.corruptMetadata());
        int total = test.dataBlocks.length+test.checkBlocks.length;
        for(int i=0;i<total;i++)
            segment.onNonFatalFailure(i); // We want healing on all blocks that aren't found.
        boolean[] hits = new boolean[total];
        for(int i=0;i<test.dataBlocks.length;i++) {
            int block;
            do {
                block = random.nextInt(total);
            } while (hits[block]);
            hits[block] = true;
            assertFalse(segment.hasStartedDecode());
            assertTrue(segment.onGotKey(test.getCHK(block), test.encodeBlock(block)));
            cb.markDownloadedBlock(block);
        }
        //printChosenBlocks(hits);
        cb.checkFailed();
        assertTrue(segment.hasStartedDecode());
        cb.checkFailed();
        waitForDecode(segment);
        cb.checkFailed();
        cb.waitForFinished();
        cb.checkFailed();
        test.verifyOutput(storage);
        cb.checkFailed();
        storage.finishedFetcher();
        cb.checkFailed();
        waitForFinished(segment);
        cb.checkFailed();
        cb.waitForFree(storage);
        cb.checkFailed();
    }
    
    public void testPersistenceReloadThenChooseKey() throws IOException, StorageFormatException, CHKEncodeException, MetadataUnresolvedException, MetadataParseException, FetchException {
        int dataBlocks = 2;
        int checkBlocks = 3;
        long size = 32768*2-1;
        assertTrue(dataBlocks * (long)BLOCK_SIZE >= size);
        TestSplitfile test = TestSplitfile.constructSingleSegment(size, checkBlocks, null, true);
        StorageCallback cb = test.createStorageCallback();
        FetchContext ctx = test.makeFetchContext();
        ctx.maxSplitfileBlockRetries = 2;
        SplitFileFetcherStorage storage = test.createStorage(cb, ctx);
        // No need to shutdown the old storage.
        storage = test.createStorage(cb, ctx, cb.getRAF());
        for(int i=0;i<3;i++) {
            boolean[] tried = new boolean[dataBlocks+checkBlocks];
            innerChooseKeyTest(dataBlocks, checkBlocks, storage.segments[0], tried, test, false);
        }
        test.fetchingKeys.clear();
        assertEquals(storage.chooseRandomKey(), null);
        cb.waitForFailed();
    }
    
    public void testPersistenceReloadBetweenChooseKey() throws IOException, StorageFormatException, CHKEncodeException, MetadataUnresolvedException, MetadataParseException, FetchException {
        int dataBlocks = 2;
        int checkBlocks = 3;
        long size = 32768*2-1;
        assertTrue(dataBlocks * (long)BLOCK_SIZE >= size);
        TestSplitfile test = TestSplitfile.constructSingleSegment(size, checkBlocks, null, true);
        StorageCallback cb = test.createStorageCallback();
        FetchContext ctx = test.makeFetchContext();
        ctx.maxSplitfileBlockRetries = 2;
        SplitFileFetcherStorage storage = test.createStorage(cb, ctx);
        // No need to shutdown the old storage.
        storage = test.createStorage(cb, ctx, cb.getRAF());
        for(int i=0;i<3;i++) {
            boolean[] tried = new boolean[dataBlocks+checkBlocks];
            innerChooseKeyTest(dataBlocks, checkBlocks, storage.segments[0], tried, test, false);
            // Reload.
            exec.waitForIdle();
            try {
                storage = test.createStorage(cb, ctx, cb.getRAF());
                assertTrue(i != 2);
                storage.start(false);
            } catch (FetchException e) {
                if(i != 2) throw e; // Already failed on the final iteration, otherwise is an error.
                return;
            }
        }
        test.fetchingKeys.clear();
        assertEquals(storage.chooseRandomKey(), null);
        cb.waitForFailed();
    }
    
    public void testPersistenceReloadBetweenFetches() throws IOException, StorageFormatException, CHKEncodeException, MetadataUnresolvedException, MetadataParseException, FetchException {
        int dataBlocks = 2;
        int checkBlocks = 3;
        long size = 32768*2-1;
        assertTrue(dataBlocks * (long)BLOCK_SIZE >= size);
        TestSplitfile test = TestSplitfile.constructSingleSegment(size, checkBlocks, null, true);
        StorageCallback cb = test.createStorageCallback();
        SplitFileFetcherStorage storage = test.createStorage(cb);
        // No need to shutdown the old storage.
        storage = test.createStorage(cb, test.makeFetchContext(), cb.getRAF());
        SplitFileFetcherSegmentStorage segment = storage.segments[0];
        assertFalse(segment.corruptMetadata());
        int total = test.dataBlocks.length+test.checkBlocks.length;
        for(int i=0;i<total;i++)
            segment.onNonFatalFailure(i); // We want healing on all blocks that aren't found.
        boolean[] hits = new boolean[total];
        for(int i=0;i<test.dataBlocks.length;i++) {
            int block;
            do {
                block = random.nextInt(total);
            } while (hits[block]);
            hits[block] = true;
            assertFalse(segment.hasStartedDecode());
            assertTrue(segment.onGotKey(test.getCHK(block), test.encodeBlock(block)));
            cb.markDownloadedBlock(block);
            if(i != test.dataBlocks.length-1) {
                // Reload.
                exec.waitForIdle();
                storage = test.createStorage(cb, test.makeFetchContext(), cb.getRAF());
                segment = storage.segments[0];
                storage.start(false);
            }
        }
        //printChosenBlocks(hits);
        cb.checkFailed();
        assertTrue(segment.hasStartedDecode());
        cb.checkFailed();
        waitForDecode(segment);
        cb.checkFailed();
        cb.waitForFinished();
        cb.checkFailed();
        test.verifyOutput(storage);
        cb.checkFailed();
        storage.finishedFetcher();
        cb.checkFailed();
        waitForFinished(segment);
        cb.checkFailed();
        cb.waitForFree(storage);
        cb.checkFailed();
    }
    
}
