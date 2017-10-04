package freenet.client.async;

import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

import junit.framework.TestCase;

import freenet.client.ClientMetadata;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.HighLevelSimpleClientImpl;
import freenet.client.InsertContext;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.Metadata;
import freenet.client.MetadataParseException;
import freenet.client.MetadataUnresolvedException;
import freenet.client.async.SplitFileInserterSegmentStorage.BlockInsert;
import freenet.client.async.SplitFileInserterSegmentStorage.MissingKeyException;
import freenet.client.async.SplitFileInserterStorage.Status;
import freenet.client.events.SimpleEventProducer;
import freenet.crypt.CRCChecksumChecker;
import freenet.crypt.ChecksumChecker;
import freenet.crypt.ChecksumFailedException;
import freenet.crypt.DummyRandomSource;
import freenet.crypt.HashResult;
import freenet.crypt.HashType;
import freenet.crypt.MultiHashInputStream;
import freenet.crypt.RandomSource;
import freenet.keys.CHKBlock;
import freenet.keys.ClientCHKBlock;
import freenet.keys.FreenetURI;
import freenet.keys.Key;
import freenet.node.BaseSendableGet;
import freenet.node.KeysFetchingLocally;
import freenet.node.SendableInsert;
import freenet.node.SendableRequestItemKey;
import freenet.support.CheatingTicker;
import freenet.support.DummyJobRunner;
import freenet.support.MemoryLimitedJobRunner;
import freenet.support.PooledExecutor;
import freenet.support.TestProperty;
import freenet.support.Ticker;
import freenet.support.WaitableExecutor;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.api.LockableRandomAccessBuffer;
import freenet.support.api.LockableRandomAccessBufferFactory;
import freenet.support.compress.Compressor.COMPRESSOR_TYPE;
import freenet.support.io.ArrayBucketFactory;
import freenet.support.io.BarrierRandomAccessBuffer;
import freenet.support.io.BucketTools;
import freenet.support.io.ByteArrayRandomAccessBufferFactory;
import freenet.support.io.FileUtil;
import freenet.support.io.FilenameGenerator;
import freenet.support.io.NativeThread;
import freenet.support.io.NullOutputStream;
import freenet.support.io.PersistentFileTracker;
import freenet.support.io.PooledFileRandomAccessBufferFactory;
import freenet.support.io.RAFBucket;
import freenet.support.io.RAFInputStream;
import freenet.support.io.ReadOnlyRandomAccessBuffer;
import freenet.support.io.ResumeFailedException;
import freenet.support.io.StorageFormatException;
import freenet.support.io.TempBucketFactory;
import freenet.support.io.TrivialPersistentFileTracker;

public class SplitFileInserterStorageTest extends TestCase {
    
    final LockableRandomAccessBufferFactory smallRAFFactory = new ByteArrayRandomAccessBufferFactory();
    final FilenameGenerator fg;
    final PersistentFileTracker persistentFileTracker;
    final LockableRandomAccessBufferFactory bigRAFFactory;
    final BucketFactory smallBucketFactory;
    final BucketFactory bigBucketFactory;
    final File dir;
    final InsertContext baseContext;
    final WaitableExecutor executor;
    final Ticker ticker;
    final byte cryptoAlgorithm = Key.ALGO_AES_CTR_256_SHA256;
    final byte[] cryptoKey;
    final ChecksumChecker checker;
    final MemoryLimitedJobRunner memoryLimitedJobRunner;
    final PersistentJobRunner jobRunner;
    final KeySalter salt = new KeySalter() {

        @Override
        public byte[] saltKey(Key key) {
            return key.getRoutingKey();
        }
        
    };
    private final FreenetURI URI;
    
    public SplitFileInserterStorageTest() throws IOException {
        dir = new File("split-file-inserter-storage-test");
        dir.mkdir();
        executor = new WaitableExecutor(new PooledExecutor());
        ticker = new CheatingTicker(executor);
        RandomSource r = new DummyRandomSource(12345);
        fg = new FilenameGenerator(r, true, dir, "freenet-test");
        persistentFileTracker = new TrivialPersistentFileTracker(dir, fg);
        bigRAFFactory = new PooledFileRandomAccessBufferFactory(fg, r);
        smallBucketFactory = new ArrayBucketFactory();
        bigBucketFactory = new TempBucketFactory(executor, fg, 0, 0, r, false, 0, null);
        baseContext = HighLevelSimpleClientImpl.makeDefaultInsertContext(new SimpleEventProducer());
        cryptoKey = new byte[32];
        r.nextBytes(cryptoKey);
        checker = new CRCChecksumChecker();
        memoryLimitedJobRunner = new MemoryLimitedJobRunner(9*1024*1024L, 20, executor, NativeThread.JAVA_PRIORITY_RANGE);
        jobRunner = new DummyJobRunner(executor, null);
        URI = FreenetURI.generateRandomCHK(r);
    }
    
    class MyCallback implements SplitFileInserterStorageCallback {
        
        private boolean finishedEncode;
        private boolean hasKeys;
        private boolean succeededInsert;
        private InsertException failed;
        private Metadata metadata;

        @Override
        public synchronized void onFinishedEncode() {
            finishedEncode = true;
            notifyAll();
        }

        @Override
        public synchronized void onHasKeys() {
            hasKeys = true;
            notifyAll();
        }
        
        @Override
        public void encodingProgress() {
            // Ignore.
        }
        
        private void checkFailed() throws InsertException {
            if(failed != null)
                throw failed;
        }

        public synchronized void waitForFinishedEncode() throws InsertException {
            while(!finishedEncode) {
                checkFailed();
                try {
                    wait();
                } catch (InterruptedException e) {
                    // Ignore.
                }
            }
        }

        public synchronized void waitForHasKeys() throws InsertException {
            while(!hasKeys) {
                checkFailed();
                try {
                    wait();
                } catch (InterruptedException e) {
                    // Ignore.
                }
            }
        }

        @Override
        public synchronized void onSucceeded(Metadata metadata) {
            succeededInsert = true;
            this.metadata = metadata;
            notifyAll();
        }
        
        public synchronized Metadata waitForSucceededInsert() throws InsertException {
            while(!succeededInsert) {
                checkFailed();
                try {
                    wait();
                } catch (InterruptedException e) {
                    // Ignore.
                }
            }
            return metadata;
        }

        @Override
        public synchronized void onFailed(InsertException e) {
            failed = e;
            notifyAll();
        }

        @Override
        public void onInsertedBlock() {
            // Ignore.
        }

        @Override
        public void clearCooldown() {
            // Ignore.
        }

        public synchronized boolean hasFailed() {
            return failed != null;
        }

        public synchronized boolean hasFinishedEncode() {
            return finishedEncode;
        }

        @Override
        public short getPriorityClass() {
            return 0;
        }

    }
    
    public void testSmallSplitfileNoLastBlock() throws IOException, InsertException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        KeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, baseContext.clone(), 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        assertEquals(storage.segments[0].dataBlockCount, 2);
        assertEquals(storage.segments[0].checkBlockCount, 3);
        assertEquals(storage.segments[0].crossCheckBlockCount, 0);
        assertTrue(storage.getStatus() == Status.ENCODED);
    }

    public void testSmallSplitfileWithLastBlock() throws IOException, InsertException {
        Random r = new Random(12122);
        long size = 65535;
        byte[] originalData = new byte[(int)size];
        r.nextBytes(originalData);
        LockableRandomAccessBuffer data = smallRAFFactory.makeRAF(originalData, 0, originalData.length, true);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        KeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, baseContext.clone(), 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        // Now check the data blocks...
        assertEquals(storage.segments.length, 1);
        assertEquals(storage.segments[0].dataBlockCount, 2);
        assertEquals(storage.segments[0].checkBlockCount, 3);
        assertEquals(storage.segments[0].crossCheckBlockCount, 0);
        assertTrue(Arrays.equals(storage.readSegmentDataBlock(0, 0), Arrays.copyOfRange(originalData, 0, CHKBlock.DATA_LENGTH)));
        int truncateLength = (int) (size % CHKBlock.DATA_LENGTH);
        long offsetLastBlock = size - truncateLength;
        byte[] buf = storage.readSegmentDataBlock(0, 1);
        assert(buf.length == CHKBlock.DATA_LENGTH);
        byte[] truncated = Arrays.copyOfRange(buf, 0, truncateLength);
        byte[] originalLastBlock = Arrays.copyOfRange(originalData, (int)offsetLastBlock, originalData.length);
        assertEquals(originalLastBlock.length, truncated.length);
        assertTrue(Arrays.equals(originalLastBlock, truncated));
        assertTrue(storage.getStatus() == Status.ENCODED);
    }
    
    public void testSmallSplitfileHasKeys() throws IOException, InsertException, MissingKeyException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        context.earlyEncode = true;
        KeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        assertEquals(storage.segments[0].dataBlockCount, 2);
        assertEquals(storage.segments[0].checkBlockCount, 3);
        assertEquals(storage.segments[0].crossCheckBlockCount, 0);
        cb.waitForHasKeys();
        for(int i=0;i<storage.segments[0].dataBlockCount+storage.segments[0].checkBlockCount+storage.segments[0].crossCheckBlockCount;i++)
            storage.segments[0].readKey(i);
        storage.encodeMetadata();
        assertTrue(storage.getStatus() == Status.ENCODED);
    }

    public void testSmallSplitfileCompletion() throws IOException, InsertException, MissingKeyException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        KeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        SplitFileInserterSegmentStorage segment = storage.segments[0];
        assertEquals(segment.dataBlockCount, 2);
        assertEquals(segment.checkBlockCount, 3);
        assertEquals(segment.crossCheckBlockCount, 0);
        assertEquals(storage.getStatus(), Status.ENCODED);
        for(int i=0;i<segment.totalBlockCount;i++) {
            segment.onInsertedBlock(i, segment.encodeBlock(i).getClientKey());
        }
        cb.waitForSucceededInsert();
        assertEquals(storage.getStatus(), Status.SUCCEEDED);
    }

    public void testSmallSplitfileChooseCompletion() throws IOException, InsertException, MissingKeyException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        context.maxInsertRetries = 2;
        MyKeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        SplitFileInserterSegmentStorage segment = storage.segments[0];
        assertEquals(segment.dataBlockCount, 2);
        assertEquals(segment.checkBlockCount, 3);
        assertEquals(segment.crossCheckBlockCount, 0);
        assertEquals(storage.getStatus(), Status.ENCODED);
        boolean[] chosenBlocks = new boolean[segment.totalBlockCount];
        // Choose and fail all blocks.
        for(int i=0;i<segment.totalBlockCount;i++) {
            BlockInsert chosen = segment.chooseBlock();
            assertTrue(chosen != null);
            keys.addInsert(chosen);
            assertFalse(chosenBlocks[chosen.blockNumber]);
            chosenBlocks[chosen.blockNumber] = true;
            segment.onFailure(chosen.blockNumber, new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND));
        }
        keys.clear();
        // Choose and succeed all blocks.
        chosenBlocks = new boolean[segment.totalBlockCount];
        for(int i=0;i<segment.totalBlockCount;i++) {
            BlockInsert chosen = segment.chooseBlock();
            keys.addInsert(chosen);
            assertTrue(chosen != null);
            assertFalse(chosenBlocks[chosen.blockNumber]);
            chosenBlocks[chosen.blockNumber] = true;
            segment.onInsertedBlock(chosen.blockNumber, segment.encodeBlock(chosen.blockNumber).getClientKey());
        }
        cb.waitForSucceededInsert();
        assertEquals(storage.getStatus(), Status.SUCCEEDED);
    }

    public void testSmallSplitfileChooseCooldown() throws IOException, InsertException, MissingKeyException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        context.maxInsertRetries = 2;
        context.consecutiveRNFsCountAsSuccess = 2;
        MyKeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        SplitFileInserterSegmentStorage segment = storage.segments[0];
        assertEquals(segment.dataBlockCount, 2);
        assertEquals(segment.checkBlockCount, 3);
        assertEquals(segment.crossCheckBlockCount, 0);
        assertEquals(storage.getStatus(), Status.ENCODED);
        boolean[] chosenBlocks = new boolean[segment.totalBlockCount];
        assertFalse(storage.noBlocksToSend());
        // Choose and fail all blocks.
        for(int i=0;i<segment.totalBlockCount;i++) {
            BlockInsert chosen = segment.chooseBlock();
            assertTrue(chosen != null);
            keys.addInsert(chosen);
            assertFalse(chosenBlocks[chosen.blockNumber]);
            chosenBlocks[chosen.blockNumber] = true;
        }
        assertNull(storage.chooseBlock());
        assertTrue(storage.noBlocksToSend());
        for(int i=0;i<segment.totalBlockCount;i++) {
            segment.onFailure(i, new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND));
            assertFalse(storage.noBlocksToSend());
        }
        keys.clear();
        // Choose and succeed all blocks.
        chosenBlocks = new boolean[segment.totalBlockCount];
        for(int i=0;i<segment.totalBlockCount;i++) {
            BlockInsert chosen = segment.chooseBlock();
            keys.addInsert(chosen);
            assertTrue(chosen != null);
            assertFalse(chosenBlocks[chosen.blockNumber]);
            chosenBlocks[chosen.blockNumber] = true;
            segment.onInsertedBlock(chosen.blockNumber, segment.encodeBlock(chosen.blockNumber).getClientKey());
        }
        cb.waitForSucceededInsert();
        assertEquals(storage.getStatus(), Status.SUCCEEDED);
    }

    public void testSmallSplitfileChooseCooldownNotRNF() throws IOException, InsertException, MissingKeyException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        context.maxInsertRetries = 2;
        MyKeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        SplitFileInserterSegmentStorage segment = storage.segments[0];
        assertEquals(segment.dataBlockCount, 2);
        assertEquals(segment.checkBlockCount, 3);
        assertEquals(segment.crossCheckBlockCount, 0);
        assertEquals(storage.getStatus(), Status.ENCODED);
        boolean[] chosenBlocks = new boolean[segment.totalBlockCount];
        assertFalse(storage.noBlocksToSend());
        // Choose and fail all blocks.
        for(int i=0;i<segment.totalBlockCount;i++) {
            BlockInsert chosen = segment.chooseBlock();
            assertTrue(chosen != null);
            keys.addInsert(chosen);
            assertFalse(chosenBlocks[chosen.blockNumber]);
            chosenBlocks[chosen.blockNumber] = true;
        }
        assertNull(storage.chooseBlock());
        assertTrue(storage.noBlocksToSend());
        for(int i=0;i<segment.totalBlockCount;i++) {
            // We need to test this path too.
            segment.onFailure(i, new InsertException(InsertExceptionMode.REJECTED_OVERLOAD));
            assertFalse(storage.noBlocksToSend());
        }
        keys.clear();
        // Choose and succeed all blocks.
        chosenBlocks = new boolean[segment.totalBlockCount];
        for(int i=0;i<segment.totalBlockCount;i++) {
            BlockInsert chosen = segment.chooseBlock();
            keys.addInsert(chosen);
            assertTrue(chosen != null);
            assertFalse(chosenBlocks[chosen.blockNumber]);
            chosenBlocks[chosen.blockNumber] = true;
            segment.onInsertedBlock(chosen.blockNumber, segment.encodeBlock(chosen.blockNumber).getClientKey());
        }
        cb.waitForSucceededInsert();
        assertEquals(storage.getStatus(), Status.SUCCEEDED);
    }

    public void testSmallSplitfileConsecutiveRNFsHack() throws IOException, InsertException, MissingKeyException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        context.maxInsertRetries = 0;
        context.consecutiveRNFsCountAsSuccess = 2;
        MyKeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        SplitFileInserterSegmentStorage segment = storage.segments[0];
        assertEquals(segment.dataBlockCount, 2);
        assertEquals(segment.checkBlockCount, 3);
        assertEquals(segment.crossCheckBlockCount, 0);
        assertEquals(storage.getStatus(), Status.ENCODED);
        boolean[] chosenBlocks = new boolean[segment.totalBlockCount];
        // First RNF.
        for(int i=0;i<segment.totalBlockCount;i++) {
            BlockInsert chosen = segment.chooseBlock();
            assertTrue(chosen != null);
            keys.addInsert(chosen);
            assertFalse(chosenBlocks[chosen.blockNumber]);
            chosenBlocks[chosen.blockNumber] = true;
            segment.setKey(chosen.blockNumber, segment.encodeBlock(chosen.blockNumber).getClientKey());
            segment.onFailure(chosen.blockNumber, new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND));
        }
        chosenBlocks = new boolean[segment.totalBlockCount];
        // Second RNF.
        keys.clear();
        for(int i=0;i<segment.totalBlockCount;i++) {
            BlockInsert chosen = segment.chooseBlock();
            assertTrue(chosen != null);
            keys.addInsert(chosen);
            assertFalse(chosenBlocks[chosen.blockNumber]);
            chosenBlocks[chosen.blockNumber] = true;
            segment.onFailure(chosen.blockNumber, new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND));
        }
        // Should count as success at this point.
        cb.waitForSucceededInsert();
        assertEquals(storage.getStatus(), Status.SUCCEEDED);
    }

    public void testSmallSplitfileConsecutiveRNFsHackFailure() throws IOException, InsertException, MissingKeyException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        // Do 2 RNFs and then a RejectedOverload. Should fail at that point.
        context.maxInsertRetries = 2;
        context.consecutiveRNFsCountAsSuccess = 3;
        MyKeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        SplitFileInserterSegmentStorage segment = storage.segments[0];
        assertEquals(segment.dataBlockCount, 2);
        assertEquals(segment.checkBlockCount, 3);
        assertEquals(segment.crossCheckBlockCount, 0);
        assertEquals(storage.getStatus(), Status.ENCODED);
        segment.setKey(0, segment.encodeBlock(0).getClientKey());
        segment.onFailure(0, new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND));
        assertEquals(storage.getStatus(), Status.ENCODED);
        segment.onFailure(0, new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND));
        assertEquals(storage.getStatus(), Status.ENCODED);
        segment.onFailure(0, new InsertException(InsertExceptionMode.REJECTED_OVERLOAD));
        // Should count as success at this point.
        try {
            cb.waitForSucceededInsert();
            assertTrue(false);
        } catch (InsertException e) {
            // Expected.
            assertEquals(e.mode, InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS);
            assertTrue(e.errorCodes != null);
            assertEquals(e.errorCodes.getErrorCount(InsertExceptionMode.ROUTE_NOT_FOUND), 2);
            assertEquals(e.errorCodes.getErrorCount(InsertExceptionMode.REJECTED_OVERLOAD), 1);
            assertEquals(e.errorCodes.totalCount(), 3);
            assertEquals(storage.getStatus(), Status.FAILED);
        }
    }

    public void testSmallSplitfileFailureMaxRetries() throws IOException, InsertException, MissingKeyException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        context.consecutiveRNFsCountAsSuccess = 0;
        context.maxInsertRetries = 2;
        KeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        SplitFileInserterSegmentStorage segment = storage.segments[0];
        assertEquals(segment.dataBlockCount, 2);
        assertEquals(segment.checkBlockCount, 3);
        assertEquals(segment.crossCheckBlockCount, 0);
        assertEquals(storage.getStatus(), Status.ENCODED);
        for(int i=0;i<3;i++) {
            segment.onFailure(0, new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND));
        }
        try {
            cb.waitForSucceededInsert();
            assertTrue(false);
        } catch (InsertException e) {
            assertEquals(e.mode, InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS);
            assertTrue(e.errorCodes != null);
            assertEquals(e.errorCodes.getErrorCount(InsertExceptionMode.ROUTE_NOT_FOUND), 3);
            assertEquals(e.errorCodes.totalCount(), 3);
            assertEquals(storage.getStatus(), Status.FAILED);
        }
    }

    public void testSmallSplitfileFailureFatalError() throws IOException, InsertException, MissingKeyException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        context.maxInsertRetries = 2;
        KeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        SplitFileInserterSegmentStorage segment = storage.segments[0];
        assertEquals(segment.dataBlockCount, 2);
        assertEquals(segment.checkBlockCount, 3);
        assertEquals(segment.crossCheckBlockCount, 0);
        assertEquals(storage.getStatus(), Status.ENCODED);
        assertTrue(InsertException.isFatal(InsertExceptionMode.INTERNAL_ERROR));
        segment.onFailure(0, new InsertException(InsertExceptionMode.INTERNAL_ERROR));
        try {
            cb.waitForSucceededInsert();
            assertTrue(false);
        } catch (InsertException e) {
            assertEquals(e.mode, InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS);
            assertTrue(e.errorCodes != null);
            assertEquals(e.errorCodes.getErrorCount(InsertExceptionMode.INTERNAL_ERROR), 1);
            assertEquals(e.errorCodes.totalCount(), 1);
            assertEquals(storage.getStatus(), Status.FAILED);
        }
    }

    private HashResult[] getHashes(LockableRandomAccessBuffer data) throws IOException {
        InputStream is = new RAFInputStream(data, 0, data.size());
        MultiHashInputStream hashStream = new MultiHashInputStream(is, HashType.SHA256.bitmask);
        FileUtil.copy(is, new NullOutputStream(), data.size());
        is.close();
        return hashStream.getResults();
    }

    private LockableRandomAccessBuffer generateData(Random random, long size) throws IOException {
        // Use small factory for anything <= 256KiB
        LockableRandomAccessBufferFactory f = size > 262144 ? bigRAFFactory : smallRAFFactory;
        return generateData(random, size, f);
    }

    private LockableRandomAccessBuffer generateData(Random random, long size,
            LockableRandomAccessBufferFactory factory) throws IOException {
        LockableRandomAccessBuffer thing = factory.makeRAF(size);
        BucketTools.fill(thing, random, 0, size);
        return new ReadOnlyRandomAccessBuffer(thing);
    }
    
    public void testRoundTripSimple() throws FetchException, MetadataParseException, Exception {
        testRoundTripSimpleRandom(CHKBlock.DATA_LENGTH*2, CompatibilityMode.COMPAT_CURRENT);
        testRoundTripSimpleRandom(CHKBlock.DATA_LENGTH*2-1, CompatibilityMode.COMPAT_CURRENT);
        testRoundTripSimpleRandom(CHKBlock.DATA_LENGTH*128, CompatibilityMode.COMPAT_CURRENT);
        testRoundTripSimpleRandom(CHKBlock.DATA_LENGTH*128+1, CompatibilityMode.COMPAT_CURRENT);
        testRoundTripSimpleRandom(CHKBlock.DATA_LENGTH*192, CompatibilityMode.COMPAT_CURRENT);
        testRoundTripSimpleRandom(CHKBlock.DATA_LENGTH*192+1, CompatibilityMode.COMPAT_CURRENT);
    }
    
    public void testRoundTripOneBlockSegment() throws IOException, InsertException, MissingKeyException, FetchException, MetadataParseException, Exception {
        testRoundTripSimpleRandom(CHKBlock.DATA_LENGTH*(128+1)-1, CompatibilityMode.COMPAT_1250_EXACT);
    }
    
    public void testRoundTripCrossSegment() throws IOException, InsertException, MissingKeyException, FetchException, MetadataParseException, Exception {
        if(!TestProperty.EXTENSIVE) return;
        // Test cross-segment:
        testRoundTripCrossSegmentRandom(CHKBlock.DATA_LENGTH*128*21);
    }
    
    public void testRoundTripDataBlocksOnly() throws IOException, InsertException, MissingKeyException, FetchException, MetadataParseException, Exception {
        testRoundTripCrossSegmentDataBlocks(CHKBlock.DATA_LENGTH*128*5);
        if(!TestProperty.EXTENSIVE) return;
        // Test cross-segment:
        testRoundTripCrossSegmentDataBlocks(CHKBlock.DATA_LENGTH*128*21);
    }
    
    public void testResumeCrossSegment() throws InsertException, IOException, MissingKeyException, StorageFormatException, ChecksumFailedException, ResumeFailedException, MetadataUnresolvedException {
        if(!TestProperty.EXTENSIVE) return;
        testResumeCrossSegment(CHKBlock.DATA_LENGTH*128*21);
    }
    
    public void testEncodeAfterShutdownCrossSegment() throws InsertException, IOException, MissingKeyException, StorageFormatException, ChecksumFailedException, ResumeFailedException, MetadataUnresolvedException {
        if(!TestProperty.EXTENSIVE) return;
        testEncodeAfterShutdownCrossSegment(CHKBlock.DATA_LENGTH*128*21);
    }
    
    public void testRepeatedEncodeAfterShutdown() throws InsertException, IOException, MissingKeyException, StorageFormatException, ChecksumFailedException, ResumeFailedException, MetadataUnresolvedException {
        testRepeatedEncodeAfterShutdownCrossSegment(CHKBlock.DATA_LENGTH*128*5); // Not cross-segment.
        if(!TestProperty.EXTENSIVE) return;
        testRepeatedEncodeAfterShutdownCrossSegment(CHKBlock.DATA_LENGTH*128*21); // Cross-segment.
    }
    
    static class MyKeysFetchingLocally implements KeysFetchingLocally {
        private final HashSet<Key> keys = new HashSet<Key>();
        private final HashSet<SendableRequestItemKey> inserts = new HashSet<SendableRequestItemKey>();

        @Override
        public long checkRecentlyFailed(Key key, boolean realTime) {
            return 0;
        }

        public void addInsert(SendableRequestItemKey chosen) {
            inserts.add(chosen);
        }

        @Override
        public boolean hasKey(Key key, BaseSendableGet getterWaiting) {
            return keys.contains(key);
        }

        @Override
        public boolean hasInsert(SendableRequestItemKey token) {
            return inserts.contains(token);
        }

        public void add(Key k) {
            keys.add(k);
        }

        public void clear() {
            keys.clear();
            inserts.clear();
        }
        
    }
    
    private void testRoundTripSimpleRandom(long size, CompatibilityMode cmode) throws IOException, InsertException, MissingKeyException, FetchException, MetadataParseException, Exception {
        RandomSource r = new DummyRandomSource(12123);
        LockableRandomAccessBuffer data = generateData(r, size);
        Bucket dataBucket = new RAFBucket(data);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        context.earlyEncode = true;
        context.setCompatibilityMode(cmode);
        cmode = context.getCompatibilityMode();
        KeysFetchingLocally keys = new MyKeysFetchingLocally();
        boolean old = cmode.code < CompatibilityMode.COMPAT_1255.code;
        byte cryptoAlgorithm = this.cryptoAlgorithm;
        if(!(cmode == CompatibilityMode.COMPAT_CURRENT || cmode.ordinal() >= CompatibilityMode.COMPAT_1416.ordinal()))
            cryptoAlgorithm = Key.ALGO_AES_PCFB_256_SHA256;
        else
            cryptoAlgorithm = Key.ALGO_AES_CTR_256_SHA256;
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, old ? null : cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertTrue(storage.getStatus() == Status.ENCODED);
        // Encoded. Now try to decode it ...
        cb.waitForHasKeys();
        Metadata metadata = storage.encodeMetadata();

        // Ugly hack because Metadata behaves oddly.
        // FIXME make Metadata behave consistently and get rid.
        Bucket metaBucket = metadata.toBucket(smallBucketFactory);
        Metadata m1 = Metadata.construct(metaBucket);
        Bucket copyBucket = m1.toBucket(smallBucketFactory);
        assertTrue(BucketTools.equalBuckets(metaBucket, copyBucket));
        
        MyFetchCallback fcb = new MyFetchCallback();
        
        FetchContext fctx = HighLevelSimpleClientImpl.makeDefaultFetchContext(size*2, size*2, new SimpleEventProducer());
        
        SplitFileFetcherStorage fetcherStorage = new SplitFileFetcherStorage(m1, fcb, new ArrayList<COMPRESSOR_TYPE>(),
                new ClientMetadata(), false, cmode.code, fctx, salt, URI, URI, true, new byte[0],
                r, smallBucketFactory, smallRAFFactory, jobRunner, ticker, memoryLimitedJobRunner, 
                checker, false, null, null, keys);
        
        fetcherStorage.start(false);
        
        // Fully decode one segment at a time, ignore cross-segment.
        
        for(int i=0;i<storage.segments.length;i++) {
            SplitFileFetcherSegmentStorage fetcherSegment = fetcherStorage.segments[i];
            SplitFileInserterSegmentStorage inserterSegment = storage.segments[i];
            int minBlocks = inserterSegment.dataBlockCount + inserterSegment.crossCheckBlockCount;
            int totalBlocks = inserterSegment.totalBlockCount;
            boolean[] fetched = new boolean[totalBlocks];
            if(i == storage.segments.length-1 && cmode.ordinal() < CompatibilityMode.COMPAT_1255.ordinal())
                fetched[inserterSegment.dataBlockCount-1] = true; // We don't use the last block of the last segment for old splitfiles
            for(int j=0;j<minBlocks;j++) {
                int blockNo;
                do {
                    blockNo = r.nextInt(totalBlocks);
                } while (fetched[blockNo]);
                fetched[blockNo] = true;
                ClientCHKBlock block = inserterSegment.encodeBlock(blockNo);
                assertFalse(fetcherSegment.hasStartedDecode());
                boolean success = fetcherSegment.onGotKey(block.getClientKey().getNodeCHK(), block.getBlock());
                assertTrue(success);
                fcb.checkFailed();
            }
            assertTrue(fetcherSegment.hasStartedDecode());
            fcb.checkFailed();
            waitForDecode(fetcherSegment);
        }
        fcb.waitForFinished();
        verifyOutput(fetcherStorage, dataBucket);
        fetcherStorage.finishedFetcher();
        fcb.waitForFree();
    }
    
    private void testResumeCrossSegment(long size) throws InsertException, IOException, MissingKeyException, StorageFormatException, ChecksumFailedException, ResumeFailedException, MetadataUnresolvedException {
        Random r = new Random(12121);
        LockableRandomAccessBuffer data = generateData(r, size);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        MyKeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, true, baseContext.clone(), 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        cb.waitForHasKeys();
        executor.waitForIdle();
        Metadata metadata = storage.encodeMetadata();
        assertTrue(storage.getStatus() == Status.ENCODED);
        Bucket mBucket1 = bigBucketFactory.makeBucket(-1);
        DataOutputStream os = new DataOutputStream(mBucket1.getOutputStream());
        metadata.writeTo(os);
        os.close();
        SplitFileInserterStorage resumed = new SplitFileInserterStorage(storage.getRAF(), data, cb, r, 
                memoryLimitedJobRunner, jobRunner, ticker, keys, fg, persistentFileTracker, null);
        // Doesn't need to start since already encoded.
        Metadata metadata2 = storage.encodeMetadata();
        Bucket mBucket2 = bigBucketFactory.makeBucket(-1);
        os = new DataOutputStream(mBucket2.getOutputStream());
        metadata2.writeTo(os);
        os.close();
        assertTrue(BucketTools.equalBuckets(mBucket1, mBucket2));
        // Choose and succeed all blocks.
        boolean[][] chosenBlocks = new boolean[storage.segments.length][];
        for(int i=0;i<storage.segments.length;i++) {
            int blocks = storage.segments[i].totalBlockCount;
            chosenBlocks[i] = new boolean[blocks];
            assertEquals(storage.segments[i].totalBlockCount, resumed.segments[i].totalBlockCount);
        }
        int totalBlocks = storage.getTotalBlockCount();
        assertEquals(totalBlocks, resumed.getTotalBlockCount());
        for(int i=0;i<totalBlocks;i++) {
            BlockInsert chosen = resumed.chooseBlock();
            if(chosen == null) {
                assertFalse(true);
            } else {
                keys.addInsert(chosen);
            }
            assertTrue(chosen != null);
            assertFalse(chosenBlocks[chosen.segment.segNo][chosen.blockNumber]);
            chosenBlocks[chosen.segment.segNo][chosen.blockNumber] = true;
            chosen.segment.onInsertedBlock(chosen.blockNumber, 
                    chosen.segment.encodeBlock(chosen.blockNumber).getClientKey());
        }
        cb.waitForSucceededInsert();
        assertEquals(Status.SUCCEEDED, resumed.getStatus());
    }
    
    private void testEncodeAfterShutdownCrossSegment(long size) throws InsertException, IOException, MissingKeyException, StorageFormatException, ChecksumFailedException, ResumeFailedException, MetadataUnresolvedException {
        Random r = new Random(12121);
        LockableRandomAccessBuffer data = generateData(r, size);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        MyKeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, true, baseContext.clone(), 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        executor.waitForIdle();
        // Has not encoded anything.
        for(SplitFileInserterSegmentStorage segment : storage.segments)
            assert(!segment.isFinishedEncoding());
        SplitFileInserterStorage resumed = new SplitFileInserterStorage(storage.getRAF(), data, cb, r, 
                memoryLimitedJobRunner, jobRunner, ticker, keys, fg, persistentFileTracker, null);
        resumed.start();
        cb.waitForFinishedEncode();
        cb.waitForHasKeys();
        executor.waitForIdle();
        resumed.encodeMetadata();
        assertTrue(resumed.getStatus() == Status.ENCODED);
        resumed.originalData.free();
        resumed.getRAF().free();
    }
    
    private void testRepeatedEncodeAfterShutdownCrossSegment(long size) throws InsertException, IOException, MissingKeyException, StorageFormatException, ChecksumFailedException, ResumeFailedException, MetadataUnresolvedException {
        Random r = new Random(12121);
        LockableRandomAccessBuffer data = generateData(r, size);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        MyKeysFetchingLocally keys = new MyKeysFetchingLocally();
        // Only enough for one segment at a time.
        MemoryLimitedJobRunner memoryLimitedJobRunner = new MemoryLimitedJobRunner(9*1024*1024L, 1, executor, NativeThread.JAVA_PRIORITY_RANGE);
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, true, baseContext.clone(), 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        executor.waitForIdle();
        // Has not encoded anything.
        for(SplitFileInserterSegmentStorage segment : storage.segments)
            assert(!segment.isFinishedEncoding());
        SplitFileInserterStorage resumed = null;
        if(storage.crossSegments != null) {
            for(int i=0;i<storage.crossSegments.length;i++) {
                memoryLimitedJobRunner = new MemoryLimitedJobRunner(9*1024*1024L, 1, executor, NativeThread.JAVA_PRIORITY_RANGE);
                resumed = new SplitFileInserterStorage(storage.getRAF(), data, cb, r, 
                        memoryLimitedJobRunner, jobRunner, ticker, keys, fg, persistentFileTracker, null);
                assertEquals(i, countEncodedCrossSegments(resumed));
                resumed.start();
                // The memoryLimitedJobRunner will only encode one segment at a time.
                // Wait for it to encode one segment.
                memoryLimitedJobRunner.shutdown();
                memoryLimitedJobRunner.waitForShutdown();
                executor.waitForIdle();
                assertEquals(i+1, countEncodedCrossSegments(resumed));
            }
        }
        
        for(int i=0;i<storage.segments.length;i++) {
            memoryLimitedJobRunner = new MemoryLimitedJobRunner(9*1024*1024L, 1, executor, NativeThread.JAVA_PRIORITY_RANGE);
            resumed = new SplitFileInserterStorage(storage.getRAF(), data, cb, r, 
                    memoryLimitedJobRunner, jobRunner, ticker, keys, fg, persistentFileTracker, null);
            assertEquals(i, countEncodedSegments(resumed));
            if(storage.crossSegments != null) {
                assertEquals(resumed.crossSegments.length, countEncodedCrossSegments(resumed));
                assertTrue(resumed.getStatus() == Status.ENCODED_CROSS_SEGMENTS);
            }
            resumed.start();
            // The memoryLimitedJobRunner will only encode one segment at a time.
            // Wait for it to encode one segment.
            memoryLimitedJobRunner.shutdown();
            memoryLimitedJobRunner.waitForShutdown();
            executor.waitForIdle();
            assertEquals(i+1, countEncodedSegments(resumed));
        }
        
        cb.waitForFinishedEncode();
        cb.waitForHasKeys();
        executor.waitForIdle();
        resumed.encodeMetadata();
        assertTrue(resumed.getStatus() == Status.ENCODED);
        resumed.originalData.free();
        resumed.getRAF().free();
    }
    
    private int countEncodedSegments(SplitFileInserterStorage storage) {
        int total = 0;
        for(SplitFileInserterSegmentStorage segment : storage.segments) {
            if(segment.isFinishedEncoding()) total++;
        }
        return total;
    }

    private int countEncodedCrossSegments(SplitFileInserterStorage storage) {
        int total = 0;
        for(SplitFileInserterCrossSegmentStorage segment : storage.crossSegments) {
            if(segment.isFinishedEncoding()) total++;
        }
        return total;
    }

    private void testRoundTripCrossSegmentRandom(long size) throws IOException, InsertException, MissingKeyException, FetchException, MetadataParseException, Exception {
        RandomSource r = new DummyRandomSource(12123);
        LockableRandomAccessBuffer data = generateData(r, size);
        Bucket dataBucket = new RAFBucket(data);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        context.earlyEncode = true;
        KeysFetchingLocally keysFetching = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keysFetching, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        // Encoded. Now try to decode it ...
        cb.waitForHasKeys();
        Metadata metadata = storage.encodeMetadata();
        assertTrue(storage.getStatus() == Status.ENCODED);

        // Ugly hack because Metadata behaves oddly.
        // FIXME make Metadata behave consistently and get rid.
        Bucket metaBucket = metadata.toBucket(smallBucketFactory);
        Metadata m1 = Metadata.construct(metaBucket);
        Bucket copyBucket = m1.toBucket(smallBucketFactory);
        assertTrue(BucketTools.equalBuckets(metaBucket, copyBucket));
        
        MyFetchCallback fcb = new MyFetchCallback();
        
        FetchContext fctx = HighLevelSimpleClientImpl.makeDefaultFetchContext(size*2, size*2, new SimpleEventProducer());
        
        short cmode = (short) context.getCompatibilityMode().ordinal();
        
        SplitFileFetcherStorage fetcherStorage = new SplitFileFetcherStorage(m1, fcb, new ArrayList<COMPRESSOR_TYPE>(),
                new ClientMetadata(), false, cmode, fctx, salt, URI, URI, true, new byte[0],
                r, smallBucketFactory, smallRAFFactory, jobRunner, ticker, memoryLimitedJobRunner, 
                checker, false, null, null, keysFetching);
        
        fetcherStorage.start(false);
        
        int segments = storage.segments.length;
        for(int i=0;i<segments;i++) {
            assertEquals(storage.crossSegments[i].dataBlockCount, fetcherStorage.crossSegments[i].dataBlockCount);
            assertTrue(Arrays.equals(storage.crossSegments[i].getSegmentNumbers(), fetcherStorage.crossSegments[i].getSegmentNumbers()));
            assertTrue(Arrays.equals(storage.crossSegments[i].getBlockNumbers(), fetcherStorage.crossSegments[i].getBlockNumbers()));
        }
        
        // Cross-segment decode.
        // We want to ensure it completes in exactly the number of blocks expected, but we need to
        // ensure at each step that the block hasn't already been decoded.
        
        int requiredBlocks = fcb.getRequiredBlocks();
        
        int dataBlocks = (int)((size + CHKBlock.DATA_LENGTH-1)/CHKBlock.DATA_LENGTH);
        
        int expectedBlocks = dataBlocks;
        if(storage.crossSegments != null)
            expectedBlocks += storage.segments.length * 3;
        
        assertEquals(expectedBlocks, requiredBlocks);
        
        int i=0;
        while(true) {
            executor.waitForIdle(); // Wait for no encodes/decodes running.
            if(!addRandomBlock(storage, fetcherStorage, r)) break;
            fcb.checkFailed();
            i++;
        }

        // Cross-check doesn't necessarily complete in exactly the number of required blocks.
        assertTrue(i >= dataBlocks);
        assertTrue("Downloaded more blocks than data+cross check", i < expectedBlocks);
        assertTrue("No cross-segment blocks decoded", i < expectedBlocks - 1);
        executor.waitForIdle(); // Wait for no encodes/decodes running.
        fcb.waitForFinished();
        verifyOutput(fetcherStorage, dataBucket);
        fetcherStorage.finishedFetcher();
        fcb.waitForFree();
    }
    
    private void testRoundTripCrossSegmentDataBlocks(long size) throws IOException, InsertException, MissingKeyException, FetchException, MetadataParseException, Exception {
        RandomSource r = new DummyRandomSource(12123);
        LockableRandomAccessBuffer data = generateData(r, size);
        Bucket dataBucket = new RAFBucket(data);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        context.earlyEncode = true;
        KeysFetchingLocally keysFetching = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keysFetching, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        // Encoded. Now try to decode it ...
        cb.waitForHasKeys();
        Metadata metadata = storage.encodeMetadata();
        assertTrue(storage.getStatus() == Status.ENCODED);

        // Ugly hack because Metadata behaves oddly.
        // FIXME make Metadata behave consistently and get rid.
        Bucket metaBucket = metadata.toBucket(smallBucketFactory);
        Metadata m1 = Metadata.construct(metaBucket);
        Bucket copyBucket = m1.toBucket(smallBucketFactory);
        assertTrue(BucketTools.equalBuckets(metaBucket, copyBucket));
        
        MyFetchCallback fcb = new MyFetchCallback();
        
        FetchContext fctx = HighLevelSimpleClientImpl.makeDefaultFetchContext(size*2, size*2, new SimpleEventProducer());
        
        short cmode = (short) context.getCompatibilityMode().ordinal();
        
        SplitFileFetcherStorage fetcherStorage = new SplitFileFetcherStorage(m1, fcb, new ArrayList<COMPRESSOR_TYPE>(),
                new ClientMetadata(), false, cmode, fctx, salt, URI, URI, true, new byte[0],
                r, smallBucketFactory, smallRAFFactory, jobRunner, ticker, memoryLimitedJobRunner, 
                checker, false, null, null, keysFetching);
        
        fetcherStorage.start(false);
        
        if(storage.crossSegments != null) {
            int segments = storage.segments.length;
            for(int i=0;i<segments;i++) {
                assertEquals(storage.crossSegments[i].dataBlockCount, fetcherStorage.crossSegments[i].dataBlockCount);
                assertTrue(Arrays.equals(storage.crossSegments[i].getSegmentNumbers(), fetcherStorage.crossSegments[i].getSegmentNumbers()));
                assertTrue(Arrays.equals(storage.crossSegments[i].getBlockNumbers(), fetcherStorage.crossSegments[i].getBlockNumbers()));
            }
        }
        
        // It should be able to decode from just the data blocks.
        
        for(int segNo=0;segNo<storage.segments.length;segNo++) {
            SplitFileInserterSegmentStorage inserterSegment = storage.segments[segNo];
            SplitFileFetcherSegmentStorage fetcherSegment = fetcherStorage.segments[segNo];
            for(int blockNo=0;blockNo<inserterSegment.dataBlockCount;blockNo++) {
                ClientCHKBlock block = inserterSegment.encodeBlock(blockNo);
                boolean success = fetcherSegment.onGotKey(block.getClientKey().getNodeCHK(), block.getBlock());
                assertTrue(success);
            }
        }
        
        executor.waitForIdle(); // Wait for no encodes/decodes running.
        fcb.waitForFinished();
        verifyOutput(fetcherStorage, dataBucket);
        fetcherStorage.finishedFetcher();
        fcb.waitForFree();
    }
    
    /** Add a random block that has not been added already or decoded already. 
     * @throws IOException */
    private boolean addRandomBlock(SplitFileInserterStorage storage,
            SplitFileFetcherStorage fetcherStorage, Random random) throws IOException {
        int segCount = storage.segments.length;
        boolean[] exhaustedSegments = new boolean[segCount];
        for(int i=0;i<segCount;i++) {
            while(true) {
                int segNo = random.nextInt(segCount);
                if(exhaustedSegments[segNo]) continue;
                SplitFileFetcherSegmentStorage segment = fetcherStorage.segments[segNo];
                if(segment.isDecodingOrFinished()) {
                    exhaustedSegments[segNo] = true;
                    break;
                }
                while(true) {
                    int blockNo = random.nextInt(segment.totalBlocks());
                    if(segment.hasBlock(blockNo)) {
                        continue;
                    }
                    ClientCHKBlock block = storage.segments[segNo].encodeBlock(blockNo);
                    boolean success = segment.onGotKey(block.getClientKey().getNodeCHK(), block.getBlock());
                    assertTrue(success);
                    return true;
                }
            }
        }
        return false;
    }

    private void verifyOutput(SplitFileFetcherStorage storage, Bucket originalData) throws IOException {
        StreamGenerator g = storage.streamGenerator();
        Bucket out = smallBucketFactory.makeBucket(-1);
        OutputStream os = out.getOutputStream();
        g.writeTo(os);
        os.close();
        assertTrue(BucketTools.equalBuckets(originalData, out));
        out.free();
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
    
    class MyFetchCallback implements SplitFileFetcherStorageCallback {
        
        
        private boolean succeeded;
        private boolean failed;
        private int queuedHealing;
        private boolean closed;
        private int requiredBlocks;
        private int totalBlocks;
        private int fetchedBlocks;
        private int failedBlocks;
        private Exception failedException;
        private int restartedAfterDataCorruption;

        @Override
        public synchronized void onSuccess() {
            succeeded = true;
            notifyAll();
        }

        public synchronized int getRequiredBlocks() {
            return requiredBlocks;
        }

        public synchronized void waitForFree() throws Exception {
            while(true) {
                checkFailed();
                if(closed) return;
                wait();
            }
        }

        public synchronized void waitForFinished() throws Exception {
            while(true) {
                checkFailed();
                if(succeeded) return;
                wait();
            }
        }

        public synchronized void checkFailed() throws Exception {
            if(!failed) return;
            if(failedException != null) throw failedException;
            assertFalse(true);
        }

        @Override
        public short getPriorityClass() {
            return 0;
        }

        @Override
        public synchronized void failOnDiskError(IOException e) {
            System.err.println(e);
            e.printStackTrace();
            failed = true;
            failedException = e;
            notifyAll();
        }

        @Override
        public void failOnDiskError(ChecksumFailedException e) {
            System.err.println(e);
            e.printStackTrace();
            failed = true;
            failedException = e;
            notifyAll();
        }

        @Override
        public synchronized void setSplitfileBlocks(int requiredBlocks, int remainingBlocks) {
            this.requiredBlocks = requiredBlocks;
            this.totalBlocks = requiredBlocks + remainingBlocks;
            // Ignore
        }

        @Override
        public void onSplitfileCompatibilityMode(CompatibilityMode min, CompatibilityMode max,
                byte[] customSplitfileKey, boolean compressed, boolean bottomLayer,
                boolean definitiveAnyway) {
            // Ignore.
        }

        @Override
        public synchronized void queueHeal(byte[] data, byte[] cryptoKey, byte cryptoAlgorithm) {
            queuedHealing++;
        }

        @Override
        public synchronized void onClosed() {
            closed = true;
            notifyAll();
        }

        @Override
        public synchronized void onFetchedBlock() {
            fetchedBlocks++;
        }

        @Override
        public synchronized void onFailedBlock() {
            failedBlocks++;
        }

        @Override
        public void onResume(int succeededBlocks, int failedBlocks, ClientMetadata mimeType,
                long finalSize) {
            // Ignore.
        }

        @Override
        public synchronized void fail(FetchException e) {
            System.err.println(e);
            e.printStackTrace();
            failed = true;
            failedException = e;
            notifyAll();
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
        public synchronized void restartedAfterDataCorruption() {
            restartedAfterDataCorruption++;
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
        public KeySalter getSalter() {
            return salt;
        }

    }

    public void testCancel() throws IOException, InsertException, MissingKeyException {
        Random r = new Random(12124);
        long size = 32768*6;
        BarrierRandomAccessBuffer data = new BarrierRandomAccessBuffer(generateData(r, size));
        HashResult[] hashes = getHashes(data);
        data.pause();
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        context.earlyEncode = true;
        KeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        assertEquals(storage.getStatus(), Status.STARTED);
        assertEquals(storage.segments.length, 1);
        SplitFileInserterSegmentStorage segment = storage.segments[0];
        segment.onFailure(0, new InsertException(InsertExceptionMode.INTERNAL_ERROR));
        data.proceed(); // Now it will complete encoding, and then report in, and then fail.
        try {
            cb.waitForFinishedEncode();
            assertFalse(true); // Should have failed.
        } catch (InsertException e) {
            assertFalse(segment.isEncoding());
            assertEquals(storage.getStatus(), Status.FAILED);
        }
    }
    
    public void testCancelAlt() throws IOException, InsertException, MissingKeyException {
        // We need to check that onFailed() isn't called until after all the cross segment encode threads have finished.
        Random r = new Random(12124);
        testCancelAlt(r, 32768*6);
    }
    
    public void testCancelAltCrossSegment() throws IOException, InsertException, MissingKeyException {
        // We need to check that onFailed() isn't called until after all the cross segment encode threads have finished.
        Random r = new Random(0xb395f44d);
        testCancelAlt(r, CHKBlock.DATA_LENGTH*128*21);
    }

    private void testCancelAlt(Random r, long size) throws IOException, InsertException {
        // FIXME tricky to wait for "all threads are in pread()", when # threads != # segments.
        // So just set max threads to 1 (only affects this test).
        memoryLimitedJobRunner.setMaxThreads(1);
        BarrierRandomAccessBuffer data = new BarrierRandomAccessBuffer(generateData(r, size));
        HashResult[] hashes = getHashes(data);
        data.pause();
        MyCallback cb = new MyCallback();
        InsertContext context = baseContext.clone();
        context.earlyEncode = true;
        KeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, false, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        assertEquals(storage.getStatus(), Status.STARTED);
        if(storage.crossSegments != null)
            assertTrue(allCrossSegmentsEncoding(storage));
        else 
            assertTrue(allSegmentsEncoding(storage));
        SplitFileInserterSegmentStorage segment = storage.segments[0];
        assertTrue(memoryLimitedJobRunner.getRunningThreads() > 0);
        // Wait for one segment to be in pread().
        data.waitForWaiting();
        segment.onFailure(0, new InsertException(InsertExceptionMode.INTERNAL_ERROR));
        assertFalse(cb.hasFailed()); // Callback must not have been called yet.
        data.proceed(); // Now it will complete encoding, and then report in, and then fail.
        try {
            cb.waitForFinishedEncode();
            assertFalse(true); // Should have failed now.
        } catch (InsertException e) {
            if(storage.segments.length > 2) {
                assertFalse(cb.hasFinishedEncode());
                assertTrue(anySegmentNotEncoded(storage));
            }
            assertEquals(memoryLimitedJobRunner.getRunningThreads(), 0);
            assertFalse(anySegmentEncoding(storage));
            assertEquals(storage.getStatus(), Status.FAILED);
        }
    }
    
    private boolean allSegmentsEncoding(SplitFileInserterStorage storage) {
        for(SplitFileInserterSegmentStorage segment : storage.segments)
            if(!segment.isEncoding()) return false;
        return true;
    }
    
    private boolean allCrossSegmentsEncoding(SplitFileInserterStorage storage) {
        if(storage.crossSegments != null) {
            for(SplitFileInserterCrossSegmentStorage segment : storage.crossSegments)
                if(!segment.isEncoding()) return false;
        }
        return true;
    }

    private boolean anySegmentEncoding(SplitFileInserterStorage storage) {
        for(SplitFileInserterSegmentStorage segment : storage.segments)
            if(segment.isEncoding()) return true;
        if(storage.crossSegments != null) {
            for(SplitFileInserterCrossSegmentStorage segment : storage.crossSegments)
                if(segment.isEncoding()) return true;
        }
        return false;
    }

    private boolean anySegmentNotEncoded(SplitFileInserterStorage storage) {
        for(SplitFileInserterSegmentStorage segment : storage.segments)
            if(!segment.hasEncoded()) return true;
        if(storage.crossSegments != null) {
            for(SplitFileInserterCrossSegmentStorage segment : storage.crossSegments)
                if(!segment.hasEncodedSuccessfully()) return true;
        }
        return false;
    }

    public void testPersistentSmallSplitfileNoLastBlockCompletion() throws IOException, InsertException, StorageFormatException, ChecksumFailedException, ResumeFailedException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size, bigRAFFactory);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        KeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, true, baseContext.clone(), 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        assertEquals(storage.segments[0].dataBlockCount, 2);
        assertEquals(storage.segments[0].checkBlockCount, 3);
        assertEquals(storage.segments[0].crossCheckBlockCount, 0);
        assertTrue(storage.getStatus() == Status.ENCODED);
        executor.waitForIdle();
        SplitFileInserterStorage resumed = new SplitFileInserterStorage(storage.getRAF(), data, cb, r, 
                memoryLimitedJobRunner, jobRunner, ticker, keys, fg, persistentFileTracker, null);
        assertEquals(resumed.segments.length, 1);
        SplitFileInserterSegmentStorage segment = resumed.segments[0];
        assertEquals(segment.dataBlockCount, 2);
        assertEquals(segment.checkBlockCount, 3);
        assertEquals(segment.crossCheckBlockCount, 0);
        assertTrue(resumed.getStatus() == Status.ENCODED);
        for(int i=0;i<segment.totalBlockCount;i++) {
            segment.onInsertedBlock(i, segment.encodeBlock(i).getClientKey());
        }
        cb.waitForSucceededInsert();
        assertEquals(Status.SUCCEEDED, resumed.getStatus());
    }

    public void testPersistentSmallSplitfileNoLastBlockCompletionAfterResume() throws IOException, InsertException, StorageFormatException, ChecksumFailedException, ResumeFailedException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size, bigRAFFactory);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        KeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, true, baseContext.clone(), 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        assertEquals(storage.segments[0].dataBlockCount, 2);
        assertEquals(storage.segments[0].checkBlockCount, 3);
        assertEquals(storage.segments[0].crossCheckBlockCount, 0);
        assertTrue(storage.getStatus() == Status.ENCODED);
        SplitFileInserterStorage resumed = null;
        for(int i=0;i<storage.segments[0].totalBlockCount;i++) {
            executor.waitForIdle();
            resumed = new SplitFileInserterStorage(storage.getRAF(), data, cb, r, 
                    memoryLimitedJobRunner, jobRunner, ticker, keys, fg, persistentFileTracker, null);
            assertEquals(resumed.segments.length, 1);
            SplitFileInserterSegmentStorage segment = resumed.segments[0];
            assertEquals(segment.dataBlockCount, 2);
            assertEquals(segment.checkBlockCount, 3);
            assertEquals(segment.crossCheckBlockCount, 0);
            assertTrue(resumed.getStatus() == Status.ENCODED);
            segment.onInsertedBlock(i, segment.encodeBlock(i).getClientKey());
        }
        cb.waitForSucceededInsert();
        assertEquals(Status.SUCCEEDED, resumed.getStatus());
    }
    
    public void testPersistentSmallSplitfileWithLastBlockCompletionAfterResume() throws IOException, InsertException, StorageFormatException, ChecksumFailedException, ResumeFailedException {
        Random r = new Random(12121);
        long size = 65535; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size, bigRAFFactory);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        KeysFetchingLocally keys = new MyKeysFetchingLocally();
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, true, baseContext.clone(), 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        assertEquals(storage.segments[0].dataBlockCount, 2);
        assertEquals(storage.segments[0].checkBlockCount, 3);
        assertEquals(storage.segments[0].crossCheckBlockCount, 0);
        assertTrue(storage.getStatus() == Status.ENCODED);
        SplitFileInserterStorage resumed = null;
        for(int i=0;i<storage.segments[0].totalBlockCount;i++) {
            executor.waitForIdle();
            resumed = new SplitFileInserterStorage(storage.getRAF(), data, cb, r, 
                    memoryLimitedJobRunner, jobRunner, ticker, keys, fg, persistentFileTracker, null);
            assertEquals(resumed.segments.length, 1);
            SplitFileInserterSegmentStorage segment = resumed.segments[0];
            assertEquals(segment.dataBlockCount, 2);
            assertEquals(segment.checkBlockCount, 3);
            assertEquals(segment.crossCheckBlockCount, 0);
            assertTrue(resumed.getStatus() == Status.ENCODED);
            segment.onInsertedBlock(i, segment.encodeBlock(i).getClientKey());
        }
        cb.waitForSucceededInsert();
        assertEquals(Status.SUCCEEDED, resumed.getStatus());
    }
    
    public void testPersistentSmallSplitfileNoLastBlockFailAfterResume() throws IOException, InsertException, StorageFormatException, ChecksumFailedException, ResumeFailedException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size, bigRAFFactory);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        KeysFetchingLocally keys = new MyKeysFetchingLocally();
        InsertContext context = baseContext.clone();
        context.consecutiveRNFsCountAsSuccess = 0;
        context.maxInsertRetries = 2;
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, true, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        assertEquals(storage.segments[0].dataBlockCount, 2);
        assertEquals(storage.segments[0].checkBlockCount, 3);
        assertEquals(storage.segments[0].crossCheckBlockCount, 0);
        assertTrue(storage.getStatus() == Status.ENCODED);
        SplitFileInserterStorage resumed = null;
        
        for(int i=0;i<3;i++) {
            executor.waitForIdle();
            resumed = new SplitFileInserterStorage(storage.getRAF(), data, cb, r, 
                    memoryLimitedJobRunner, jobRunner, ticker, keys, fg, persistentFileTracker, null);
            assertEquals(resumed.segments.length, 1);
            SplitFileInserterSegmentStorage segment = resumed.segments[0];
            assertEquals(segment.dataBlockCount, 2);
            assertEquals(segment.checkBlockCount, 3);
            assertEquals(segment.crossCheckBlockCount, 0);
            assertTrue(resumed.getStatus() == Status.ENCODED);
            segment.onFailure(0, new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND));
        }
        try {
            cb.waitForSucceededInsert();
            assertTrue(false);
        } catch (InsertException e) {
            assertEquals(e.mode, InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS);
            assertTrue(e.errorCodes != null);
            assertEquals(3, e.errorCodes.getErrorCount(InsertExceptionMode.ROUTE_NOT_FOUND));
            assertEquals(e.errorCodes.totalCount(), 3);
            assertEquals(Status.FAILED, resumed.getStatus());
        }
        assertEquals(Status.FAILED, resumed.getStatus());
    }

    public void testPersistentSmallSplitfileNoLastBlockChooseAfterResume() throws IOException, InsertException, StorageFormatException, ChecksumFailedException, ResumeFailedException {
        Random r = new Random(12121);
        long size = 65536; // Exact multiple, so no last block
        LockableRandomAccessBuffer data = generateData(r, size, bigRAFFactory);
        HashResult[] hashes = getHashes(data);
        MyCallback cb = new MyCallback();
        MyKeysFetchingLocally keys = new MyKeysFetchingLocally();
        InsertContext context = baseContext.clone();
        context.consecutiveRNFsCountAsSuccess = 0;
        context.maxInsertRetries = 1;
        SplitFileInserterStorage storage = new SplitFileInserterStorage(data, size, cb, null,
                new ClientMetadata(), false, null, smallRAFFactory, true, context, 
                cryptoAlgorithm, cryptoKey, null, hashes, smallBucketFactory, checker, 
                r, memoryLimitedJobRunner, jobRunner, ticker, keys, false, 0, 0, 0, 0);
        storage.start();
        cb.waitForFinishedEncode();
        assertEquals(storage.segments.length, 1);
        assertEquals(storage.segments[0].dataBlockCount, 2);
        assertEquals(storage.segments[0].checkBlockCount, 3);
        assertEquals(storage.segments[0].crossCheckBlockCount, 0);
        assertTrue(storage.getStatus() == Status.ENCODED);
        SplitFileInserterStorage resumed = null;
        int totalBlockCount = storage.segments[0].totalBlockCount;
        
        boolean[] chosenBlocks = new boolean[totalBlockCount];
        // Choose and fail all blocks.
        for(int i=0;i<totalBlockCount;i++) {
            executor.waitForIdle();
            resumed = new SplitFileInserterStorage(storage.getRAF(), data, cb, r, 
                    memoryLimitedJobRunner, jobRunner, ticker, keys, fg, persistentFileTracker, null);
            assertEquals(resumed.segments.length, 1);
            SplitFileInserterSegmentStorage segment = resumed.segments[0];
            assertEquals(segment.dataBlockCount, 2);
            assertEquals(segment.checkBlockCount, 3);
            assertEquals(segment.crossCheckBlockCount, 0);
            assertTrue(resumed.getStatus() == Status.ENCODED);

            BlockInsert chosen = segment.chooseBlock();
            assertTrue(chosen != null);
            keys.addInsert(chosen);
            assertFalse(chosenBlocks[chosen.blockNumber]);
            chosenBlocks[chosen.blockNumber] = true;
            segment.onFailure(chosen.blockNumber, new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND));
        }
        keys.clear();
        // Choose and succeed all blocks.
        chosenBlocks = new boolean[totalBlockCount];
        for(int i=0;i<totalBlockCount;i++) {
            executor.waitForIdle();
            resumed = new SplitFileInserterStorage(storage.getRAF(), data, cb, r, 
                    memoryLimitedJobRunner, jobRunner, ticker, keys, fg, persistentFileTracker, null);
            assertEquals(resumed.segments.length, 1);
            SplitFileInserterSegmentStorage segment = resumed.segments[0];
            assertEquals(segment.dataBlockCount, 2);
            assertEquals(segment.checkBlockCount, 3);
            assertEquals(segment.crossCheckBlockCount, 0);
            assertTrue(resumed.getStatus() == Status.ENCODED);

            BlockInsert chosen = segment.chooseBlock();
            keys.addInsert(chosen);
            assertTrue(chosen != null);
            assertFalse(chosenBlocks[chosen.blockNumber]);
            chosenBlocks[chosen.blockNumber] = true;
            segment.onInsertedBlock(chosen.blockNumber, segment.encodeBlock(chosen.blockNumber).getClientKey());
        }
        cb.waitForSucceededInsert();
        assertEquals(resumed.getStatus(), Status.SUCCEEDED);
    }

}
