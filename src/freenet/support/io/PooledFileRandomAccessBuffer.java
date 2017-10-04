package freenet.support.io;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.Serializable;
import java.util.Iterator;
import java.util.LinkedHashSet;

import freenet.client.async.ClientContext;
import freenet.support.Logger;
import freenet.support.WrapperKeepalive;
import freenet.support.api.LockableRandomAccessBuffer;

/** Random access files with a limited number of open files, using a pool. 
 * LOCKING OPTIMISATION: Contention on DEFAULT_FDTRACKER likely here. It's not clear how to avoid that, FIXME.
 * However, this is doing disk I/O (even if cached, system calls), so maybe it's not a big deal ... 
 * 
 * FIXME does this need a shutdown hook? I don't see why it would matter ... ??? */
public class PooledFileRandomAccessBuffer implements LockableRandomAccessBuffer, Serializable {
    
    private static volatile boolean logMINOR;
    static {
        Logger.registerClass(PooledFileRandomAccessBuffer.class);
    }
    
    private static final long serialVersionUID = 1L;

    static class FDTracker {
        private int maxOpenFDs;
        private int totalOpenFDs = 0;
        private final LinkedHashSet<PooledFileRandomAccessBuffer> closables = new LinkedHashSet<PooledFileRandomAccessBuffer>();
        FDTracker(int maxOpenFDs) {
            this.maxOpenFDs = maxOpenFDs;
        }

        /** Set the size of the fd pool */
        synchronized void setMaxFDs(int max) {
            if(max <= 0) throw new IllegalArgumentException();
            maxOpenFDs = max;
        }

        /** How many fd's are open right now? Mainly for tests but also for stats. */
        synchronized int getOpenFDs() {
            return totalOpenFDs;
        }

        synchronized int getClosableFDs() {
            return closables.size();
        }
    }
    private static final FDTracker DEFAULT_FDTRACKER = new FDTracker(100);
    private final FDTracker fds;
    
    public final File file;
    private final boolean readOnly;
    /** >0 means locked. We will wait until we get the lock if necessary, this is always accurate. 
     * LOCKING: Synchronized on fds. */
    private int lockLevel;
    /** The actual RAF. Non-null only if open. LOCKING: Synchronized on (this).
     * LOCKING: Always take (this) last, i.e. after fds. */
    private transient RandomAccessFile raf;
    private final long length;
    private boolean closed;
    /** -1 = not persistent-temp. Otherwise the ID. We need the ID so we can move files if the 
     * prefix changes. */
    private final long persistentTempID;
    private boolean secureDelete;
    private final boolean deleteOnFree;

    /** Create a RAF backed by a file.
     * @param file 
     * @param readOnly
     * @param forceLength
     * @param persistentTempID The tempfile ID, or -1.
     * @throws IOException
     */
    public PooledFileRandomAccessBuffer(File file, boolean readOnly, long forceLength, long persistentTempID, boolean deleteOnFree) throws IOException {
        this(file, readOnly, forceLength, persistentTempID, deleteOnFree, DEFAULT_FDTRACKER);
    }

    // For unit testing
    PooledFileRandomAccessBuffer(File file, boolean readOnly, long forceLength, long persistentTempID, boolean deleteOnFree, FDTracker fds) throws IOException {
        this.file = file;
        this.readOnly = readOnly;
        this.persistentTempID = persistentTempID;
        this.deleteOnFree = deleteOnFree;
        this.fds = fds;
        lockLevel = 0;
        // Check the parameters and get the length.
        // Also, unlock() adds to the closeables queue, which is essential.
        RAFLock lock = lockOpen();
        try {
            long currentLength = raf.length();
            if(forceLength >= 0 && forceLength != currentLength) {
                if(readOnly) throw new IOException("Read only but wrong length");
                // Preallocate space. We want predictable disk usage, not minimal disk usage, especially for downloads.
                try (WrapperKeepalive wrapperKeepalive = new WrapperKeepalive()) {
                    wrapperKeepalive.start();
                    Fallocate.forChannel(raf.getChannel(), forceLength).fromOffset(currentLength).execute();
                }
                raf.setLength(forceLength); 
                currentLength = forceLength;
            }
            this.length = currentLength;
            lock.unlock();
        } catch (IOException e) {
            synchronized(this) {
                raf.close();
                raf = null;
            }
            throw e;
        }
    }

    public PooledFileRandomAccessBuffer(File file, byte[] initialContents,
            int offset, int size, long persistentTempID, boolean deleteOnFree, boolean readOnly) throws IOException {
        this.file = file;
        this.readOnly = readOnly;
        this.length = size;
        this.persistentTempID = persistentTempID;
        this.deleteOnFree = deleteOnFree;
        this.fds = DEFAULT_FDTRACKER;
        lockLevel = 0;
        RAFLock lock = lockOpen(true);
        try {
            raf.write(initialContents, offset, size);
            lock.unlock();
        } catch (IOException e) {
            synchronized(this) {
                raf.close();
                raf = null;
            }
            throw e;
        }
    }
    
    protected PooledFileRandomAccessBuffer() {
        // For serialization.
        file = null;
        readOnly = false;
        length = 0;
        persistentTempID = -1;
        deleteOnFree = false;
        fds = null;
    }

    @Override
    public long size() {
        return length;
    }

    @Override
    public void pread(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
        if(fileOffset < 0) throw new IllegalArgumentException();
        RAFLock lock = lockOpen();
        try {
            // FIXME Use NIO! This is absurd!
            synchronized(this) {
                raf.seek(fileOffset);
                raf.readFully(buf, bufOffset, length);
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
        if(fileOffset < 0) throw new IllegalArgumentException();
        if(readOnly) throw new IOException("Read only");
        RAFLock lock = lockOpen();
        try {
            if(fileOffset + length > this.length)
                throw new IOException("Length limit exceeded");
            // FIXME Use NIO (which has proper pwrite, with concurrency)! This is absurd!
            synchronized(this) {
                raf.seek(fileOffset);
                raf.write(buf, bufOffset, length);
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void close() {
        if(logMINOR) Logger.minor(this, "Closing "+this, new Exception("debug"));
        synchronized(fds) {
            if(lockLevel != 0)
                throw new IllegalStateException("Must unlock first!");
            closed = true;
            // Essential to avoid memory leak!
            // Potentially slow but only happens on close(). Plus the size of closables is bounded anyway by the fd limit.
            fds.closables.remove(this);
            closeRAF();
        }
    }

    @Override
    public RAFLock lockOpen() throws IOException {
        return lockOpen(false);
    }
    
    private RAFLock lockOpen(boolean forceWrite) throws IOException {
        RAFLock lock = new RAFLock() {

            @Override
            protected void innerUnlock() {
                PooledFileRandomAccessBuffer.this.unlock();
            }
            
        };
        synchronized(fds) {
            while(true) {
                fds.closables.remove(this);
                if(closed) throw new IOException("Already closed "+this);
                if(raf != null) {
                    lockLevel++; // Already open, may or may not be already locked.
                    return lock;
                } else if(fds.totalOpenFDs < fds.maxOpenFDs) {
                    raf = new RandomAccessFile(file, (readOnly && !forceWrite) ? "r" : "rw");
                    lockLevel++;
                    fds.totalOpenFDs++;
                    return lock;
                } else {
                    PooledFileRandomAccessBuffer closable = pollFirstClosable();
                    if(closable != null) {
                        closable.closeRAF();
                        continue;
                    }
                    try {
                        fds.wait();
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }
            }
        }
    }
    
    private PooledFileRandomAccessBuffer pollFirstClosable() {
        synchronized(fds) {
            Iterator<PooledFileRandomAccessBuffer> it = fds.closables.iterator();
            if (it.hasNext()) {
                PooledFileRandomAccessBuffer first = it.next();
                it.remove();
                return first;
            }
            return null;
        }
    }

    /** Exposed for tests only. Used internally. Must be unlocked. */
    protected void closeRAF() {
        synchronized(fds) {
            if(lockLevel != 0) throw new IllegalStateException();
            if(raf == null) return;
            try {
                raf.close();
            } catch (IOException e) {
                Logger.error(this, "Error closing "+this+" : "+e, e);
            }
            raf = null;
            fds.totalOpenFDs--;
        }
    }

    private void unlock() {
        synchronized(fds) {
            lockLevel--;
            if(lockLevel > 0) return;
            fds.closables.add(this);
            fds.notify();
        }
    }
    
    public void setSecureDelete(boolean secureDelete) {
        this.secureDelete = secureDelete;
    }

    @Override
    public void free() {
        close();
        if(!deleteOnFree) return;
        if(secureDelete) {
            try {
                FileUtil.secureDelete(file);
            } catch (IOException e) {
                Logger.error(this, "Unable to delete "+file+" : "+e, e);
                System.err.println("Unable to delete temporary file "+file);
            }
        } else {
            file.delete();
        }
    }
    
    boolean isOpen() {
        synchronized(fds) {
            return raf != null;
        }
    }
    
    boolean isLocked() {
        synchronized(fds) {
            return lockLevel != 0;
        }
    }

    @Override
    public void onResume(ClientContext context) throws ResumeFailedException {
        if(!file.exists()) throw new ResumeFailedException("File does not exist: "+file);
        if(length > file.length()) throw new ResumeFailedException("Bad length");
        if(persistentTempID != -1)
            context.persistentFileTracker.register(file);
    }
    
    public String toString() {
        return super.toString()+":"+file;
    }
    
    static final int MAGIC = 0x297c550a;
    static final int VERSION = 1;
    
    @Override
    public void storeTo(DataOutputStream dos) throws IOException {
        dos.writeInt(MAGIC);
        dos.writeInt(VERSION);
        dos.writeUTF(file.toString());
        dos.writeBoolean(readOnly);
        dos.writeLong(length);
        dos.writeLong(persistentTempID);
        dos.writeBoolean(deleteOnFree);
        if(deleteOnFree)
            dos.writeBoolean(secureDelete);
    }

    /** Caller has already checked magic 
     * @throws StorageFormatException 
     * @throws IOException 
     * @throws ResumeFailedException */
    PooledFileRandomAccessBuffer(DataInputStream dis, FilenameGenerator fg, PersistentFileTracker persistentFileTracker) 
    throws StorageFormatException, IOException, ResumeFailedException {
        int version = dis.readInt();
        if(version != VERSION) throw new StorageFormatException("Bad version");
        File f = new File(dis.readUTF());
        readOnly = dis.readBoolean();
        length = dis.readLong();
        persistentTempID = dis.readLong();
        deleteOnFree = dis.readBoolean();
        if(deleteOnFree)
            secureDelete = dis.readBoolean();
        else
            secureDelete = false;
        fds = DEFAULT_FDTRACKER;
        if(length < 0) throw new StorageFormatException("Bad length");
        if(persistentTempID != -1) {
            // File must exist!
            if(!f.exists()) {
                // Maybe moved after the last checkpoint?
                f = fg.getFilename(persistentTempID);
                if(f.exists()) {
                    persistentFileTracker.register(f);
                    file = f;
                    return;
                }
            }
            file = fg.maybeMove(f, persistentTempID);
            if(!f.exists())
                throw new ResumeFailedException("Persistent tempfile lost "+f);
        } else {
            file = f;
            if(!f.exists())
                throw new ResumeFailedException("Lost file "+f);
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (deleteOnFree ? 1231 : 1237);
        result = prime * result + ((file == null) ? 0 : file.hashCode());
        result = prime * result + (int) (length ^ (length >>> 32));
        result = prime * result + (int) (persistentTempID ^ (persistentTempID >>> 32));
        result = prime * result + (readOnly ? 1231 : 1237);
        result = prime * result + (secureDelete ? 1231 : 1237);
        return result;
    }

    /** Must reimplement equals() as two PooledRAFWrapper's could well be the same storage object
     * i.e. file on disk. This is particularly important during resuming a splitfile insert. */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        PooledFileRandomAccessBuffer other = (PooledFileRandomAccessBuffer) obj;
        if (deleteOnFree != other.deleteOnFree) {
            return false;
        }
        if (!file.equals(other.file)) {
            return false;
        }
        if (length != other.length) {
            return false;
        }
        if (persistentTempID != other.persistentTempID) {
            return false;
        }
        if (readOnly != other.readOnly) {
            return false;
        }
        if (secureDelete != other.secureDelete) {
            return false;
        }
        return true;
    }

}
