package freenet.support.io;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import freenet.support.api.LockableRandomAccessBuffer.RAFLock;
import freenet.support.io.PooledFileRandomAccessBuffer.FDTracker;

public class PooledFileRandomAccessBufferTest extends RandomAccessBufferTestBase {

    private static final int[] TEST_LIST = new int[] { 0, 1, 32, 64, 32768, 1024*1024, 1024*1024+1 };
    
    public PooledFileRandomAccessBufferTest() {
        super(TEST_LIST);
    }

    private File base = new File("tmp.pooled-random-access-file-wrapper-test");
    
    public void setUp() {
        base.mkdir();
    }
    
    public void tearDown() {
        FileUtil.removeAll(base);
    }
    
    private Random r = new Random(222831072);
    private FDTracker fds = new FDTracker(100);
    
    @Override
    protected PooledFileRandomAccessBuffer construct(long size) throws IOException {
        File f = File.createTempFile("test", ".tmp", base);
        return new PooledFileRandomAccessBuffer(f, false, size, -1, true, fds);
    }

    /** Simplest test for pooling. TODO Add more. */
    public void testSimplePooling() throws IOException {
        for(int sz : TEST_LIST)
            innerTestSimplePooling(sz);
    }
    
    private void innerTestSimplePooling(int sz) throws IOException {
        fds.setMaxFDs(1);
        PooledFileRandomAccessBuffer a = construct(sz);
        PooledFileRandomAccessBuffer b = construct(sz);
        byte[] buf1 = new byte[sz];
        byte[] buf2 = new byte[sz];
        Random r = new Random(1153);
        r.nextBytes(buf1);
        r.nextBytes(buf2);
        a.pwrite(0, buf1, 0, buf1.length);
        b.pwrite(0, buf2, 0, buf2.length);
        byte[] cmp1 = new byte[sz];
        byte[] cmp2 = new byte[sz];
        a.pread(0, cmp1, 0, cmp1.length);
        b.pread(0, cmp2, 0, cmp2.length);
        assertTrue(Arrays.equals(cmp1, buf1));
        assertTrue(Arrays.equals(cmp2, buf2));
        a.close();
        b.close();
        a.free();
        b.free();
    }

    /** Test that locking and unlocking do something */
    public void testLock() throws IOException {
        int sz = 1024;
        fds.setMaxFDs(1);
        assertEquals(fds.getOpenFDs(), 0);
        assertEquals(fds.getClosableFDs(), 0);
        PooledFileRandomAccessBuffer a = construct(sz);
        PooledFileRandomAccessBuffer b = construct(sz);
        assertEquals(fds.getOpenFDs(), 1);
        assertEquals(fds.getClosableFDs(), 1);
        assertFalse(a.isLocked());
        assertFalse(b.isLocked());
        RAFLock lock = a.lockOpen();
        try {
            assertTrue(a.isLocked());
            assertFalse(b.isLocked());
            assertEquals(fds.getOpenFDs(), 1);
            assertEquals(fds.getClosableFDs(), 0);
        } finally {
            lock.unlock();
            assertFalse(a.isLocked());
            assertEquals(fds.getOpenFDs(), 1);
            assertEquals(fds.getClosableFDs(), 1);
        }
        a.close();
        b.close();
        assertEquals(fds.getOpenFDs(), 0);
        assertEquals(fds.getClosableFDs(), 0);
        a.free();
        b.free();
    }
    
    /** Thanks bertm */
    public void testLocksB() throws IOException {
        fds.setMaxFDs(1);
        PooledFileRandomAccessBuffer a = construct(0);
        PooledFileRandomAccessBuffer b = construct(0);
        RAFLock lock = b.lockOpen();
        lock.unlock();
        a.close();
        b.close();
        a.free();
        b.free();
        assertEquals(fds.getOpenFDs(), 0);
        assertEquals(fds.getClosableFDs(), 0);
    }
    
    public void testLockedNotClosable() throws IOException {
        int sz = 1024;
        fds.setMaxFDs(2);
        PooledFileRandomAccessBuffer a = construct(sz);
        PooledFileRandomAccessBuffer b = construct(sz);
        assertEquals(fds.getOpenFDs(), 2);
        assertEquals(fds.getClosableFDs(), 2);
        assertTrue(a.isOpen());
        assertTrue(b.isOpen());
        assertFalse(a.isLocked());
        assertFalse(b.isLocked());
        // Open and open FD -> locked
        RAFLock la = a.lockOpen();
        assertEquals(fds.getOpenFDs(), 2);
        assertEquals(fds.getClosableFDs(), 1);
        RAFLock lb = b.lockOpen();
        assertEquals(fds.getOpenFDs(), 2);
        assertEquals(fds.getClosableFDs(), 0);
        la.unlock();
        lb.unlock();
        assertEquals(fds.getOpenFDs(), 2);
        assertEquals(fds.getClosableFDs(), 2);
        a.close();
        b.close();
    }
    
    public void testLockedNotClosableFromNotOpenFD() throws IOException {
        int sz = 1024;
        fds.setMaxFDs(2);
        PooledFileRandomAccessBuffer a = construct(sz);
        PooledFileRandomAccessBuffer b = construct(sz);
        assertEquals(fds.getOpenFDs(), 2);
        assertEquals(fds.getClosableFDs(), 2);
        assertTrue(a.isOpen());
        assertTrue(b.isOpen());
        // Close the RAFs to exercise the other code path.
        a.closeRAF();
        b.closeRAF();
        assertFalse(a.isLocked());
        assertFalse(b.isLocked());
        // Open and open FD -> locked
        RAFLock la = a.lockOpen();
        assertEquals(fds.getOpenFDs(), 1);
        assertEquals(fds.getClosableFDs(), 1);
        RAFLock lb = b.lockOpen();
        assertEquals(fds.getOpenFDs(), 2);
        assertEquals(fds.getClosableFDs(), 0);
        la.unlock();
        lb.unlock();
        assertEquals(fds.getOpenFDs(), 2);
        assertEquals(fds.getClosableFDs(), 2);
        a.close();
        b.close();
    }
    
    /** Test that locking enforces limits and blocks when appropriate. 
     * @throws InterruptedException */
    public void testLockBlocking() throws IOException, InterruptedException {
        int sz = 1024;
        fds.setMaxFDs(1);
        assertEquals(fds.getOpenFDs(), 0);
        final PooledFileRandomAccessBuffer a = construct(sz);
        final PooledFileRandomAccessBuffer b = construct(sz);
        assertEquals(fds.getOpenFDs(), 1);
        assertFalse(a.isLocked());
        assertFalse(b.isLocked());
        RAFLock lock = a.lockOpen();
        assertTrue(a.isOpen());
        assertEquals(fds.getOpenFDs(), 1);
        // Now try to lock on a second thread.
        // It should wait until the first thread unlocks.
        class Status {
            boolean hasStarted;
            boolean hasLocked;
            boolean canFinish;
            boolean hasFinished;
            boolean success;
        }
        final Status s = new Status();
        Runnable r = new Runnable() {
            
            @Override
            public void run() {
                synchronized(s) {
                    s.hasStarted = true;
                    s.notify();
                }
                try {
                    RAFLock lock = b.lockOpen();
                    synchronized(s) {
                        s.hasLocked = true;
                        s.notify();
                    }
                    synchronized(s) {
                        while(!s.canFinish)
                            try {
                                s.wait();
                            } catch (InterruptedException e) {
                                // Ignore.
                            }
                    }
                    lock.unlock();
                    synchronized(s) {
                        s.success = true;
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    fail("Caught IOException trying to lock: "+e);
                } finally {
                    synchronized(s) {
                        s.hasFinished = true;
                        s.notify();
                    }
                }
            }
            
        };
        new Thread(r).start();
        // Wait for it to start.
        synchronized(s) {
            while(!s.hasStarted) {
                s.wait();
            }
            assertFalse(s.hasLocked);
            assertFalse(s.hasFinished);
        }
        assertEquals(fds.getOpenFDs(), 1);
        assertTrue(a.isOpen());
        assertFalse(b.isOpen());
        // Wait while holding lock, to give it some time to progress if it's buggy.
        Thread.sleep(100);
        synchronized(s) {
            assertFalse(s.hasLocked);
            assertFalse(s.hasFinished);
        }
        assertEquals(fds.getOpenFDs(), 1);
        assertTrue(a.isOpen());
        assertFalse(b.isOpen());
        // Now release lock.
        lock.unlock();
        // Wait for it to proceed.
        synchronized(s) {
            while(!(s.hasLocked || s.hasFinished))
                s.wait();
            assertTrue(s.hasLocked);
        }
        assertFalse(a.isOpen());
        assertTrue(b.isOpen());
        assertTrue(b.isLocked());
        assertEquals(fds.getOpenFDs(), 1);
        
        // Now let it proceed.
        synchronized(s) {
            s.canFinish = true;
            s.notifyAll();
            while(!s.hasFinished) {
                s.wait();
            }
            assertTrue(s.success);
        }
        assertFalse(a.isLocked());
        assertFalse(b.isLocked());
        assertEquals(fds.getClosableFDs(), 1);
        assertEquals(fds.getOpenFDs(), 1);
        a.close();
        assertEquals(fds.getOpenFDs(), 1);
        b.close();
        assertEquals(fds.getOpenFDs(), 0);
        a.free();
        b.free();
    }
    
    // FIXME more tests???
    
}
