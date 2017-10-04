package freenet.support.io;

import java.io.File;
import java.io.IOException;
import java.util.Random;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import freenet.support.Logger;
import freenet.support.api.LockableRandomAccessBuffer;
import freenet.support.api.LockableRandomAccessBufferFactory;

public class DiskSpaceCheckingRandomAccessBufferFactory implements LockableRandomAccessBufferFactory, 
    DiskSpaceChecker, FileRandomAccessBufferFactory {

    private final LockableRandomAccessBufferFactory underlying;
    private final File dir;
    private volatile long minDiskSpace;
    
    /** LOCKING: We synchronize throughout the whole operation to prevent fragmentation and to have
     * an accurate free space estimate. FIXME ideally this would be per-filesystem. It might be 
     * possible to get that information from Java (1.7) via java.nio.file. */
    private static final Lock lock = new ReentrantLock(true);
    
    public DiskSpaceCheckingRandomAccessBufferFactory(LockableRandomAccessBufferFactory underlying, 
            File dir, long minDiskSpace) {
        this.underlying = underlying;
        this.dir = dir;
        this.minDiskSpace = minDiskSpace;
    }
    
    public void setMinDiskSpace(long min) {
        if(min < 0) throw new IllegalArgumentException();
        this.minDiskSpace = min;
    }
    
    @Override
    public LockableRandomAccessBuffer makeRAF(long size) throws IOException {
        lock.lock();
        try {
            if(dir.getUsableSpace() > size + minDiskSpace)
                return underlying.makeRAF(size);
            else
                throw new InsufficientDiskSpaceException();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public synchronized LockableRandomAccessBuffer makeRAF(byte[] initialContents, int offset, int size, boolean readOnly)
            throws IOException {
        lock.lock();
        try {
            if(dir.getUsableSpace() > size + minDiskSpace)
                return underlying.makeRAF(initialContents, offset, size, readOnly);
            else
                throw new InsufficientDiskSpaceException();
        } finally {
            lock.unlock();
        }
    }
    
    public String toString() {
        return super.toString()+":"+underlying.toString();
    }
    
    /** Create a new RAF for a specified file, which must exist but be 0 bytes long. Will delete 
     * the file if an RAF cannot be created.
     * @throws InsufficientDiskSpaceException If there is not enough disk space.
     * @throws IOException If some other disk I/O error occurs. */
    public PooledFileRandomAccessBuffer createNewRAF(File file, long size, Random random) throws IOException {
        lock.lock();
        PooledFileRandomAccessBuffer ret = null;
        try {
            if(!file.exists()) throw new IOException("File does not exist");
            if(file.length() != 0) throw new IOException("File is wrong length");
            // FIXME ideally we would have separate locks for each filesystem ...
            if(dir.getUsableSpace() > size + minDiskSpace) {
                ret = new PooledFileRandomAccessBuffer(file, false, size, -1, true);
                return ret;
            } else {
                throw new InsufficientDiskSpaceException();
            }
        } finally {
            if(ret == null) file.delete();
            lock.unlock();
        }
    }

    @Override
    public boolean checkDiskSpace(File file, int toWrite, int bufferSize) {
        if(!FileUtil.isParent(dir, file)) {
            Logger.error(this, "Not checking disk space because "+file+" is not child of "+dir);
            return true;
        }
        lock.lock();
        try {
            if(dir.getUsableSpace() - (toWrite + bufferSize) < minDiskSpace)
                return false;
            else
                return true;
        } finally {
            lock.unlock();
        }
    }

}
