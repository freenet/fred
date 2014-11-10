package freenet.support.io;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import freenet.support.Logger;

public class RandomAccessFileWrapper implements RandomAccessThing {

	final RandomAccessFile raf;
	final File file;
	private boolean closed = false;
	private final long length;
	private final boolean readOnly;
	private boolean secureDelete;
	
	public RandomAccessFileWrapper(RandomAccessFile raf, File filename, boolean readOnly) throws IOException {
		this.raf = raf;
		this.file = filename;
		length = raf.length();
        this.readOnly = readOnly;
	}
	
    public RandomAccessFileWrapper(File filename, long length, boolean readOnly) throws IOException {
        raf = new RandomAccessFile(filename, readOnly ? "r" : "rw");
        raf.setLength(length);
        this.length = length;
        this.file = filename;
        this.readOnly = readOnly;
    }

    public RandomAccessFileWrapper(File filename, boolean readOnly) throws IOException {
        raf = new RandomAccessFile(filename, readOnly ? "r" : "rw");
        this.length = raf.length();
        this.file = filename;
        this.readOnly = readOnly;
    }

    @Override
	public void pread(long fileOffset, byte[] buf, int bufOffset, int length)
			throws IOException {
	    if(fileOffset < 0) throw new IllegalArgumentException();
        if(fileOffset + length > this.length)
            throw new IOException("Length limit exceeded");
        // FIXME Use NIO (which has proper pread, with concurrency)! This is absurd!
		synchronized(this) {
			raf.seek(fileOffset);
			raf.readFully(buf, bufOffset, length);
		}
	}

	@Override
	public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length)
			throws IOException {
        if(fileOffset < 0) throw new IllegalArgumentException();
	    if(fileOffset + length > this.length)
	        throw new IOException("Length limit exceeded");
	    if(readOnly) throw new IOException("Read only");
        // FIXME Use NIO (which has proper pwrite, with concurrency)! This is absurd!
		synchronized(this) {
			raf.seek(fileOffset);
			raf.write(buf, bufOffset, length);
		}
	}

	@Override
	public long size() throws IOException {
	    return length;
	}

	@Override
	public void close() {
		synchronized(this) {
			if(closed) return;
			closed = true;
		}
		try {
			raf.close();
		} catch (IOException e) {
			Logger.error(this, "Could not close "+raf+" : "+e+" for "+this, e);
		}
	}

    @Override
    public void free() {
        close();
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
    
    public void setSecureDelete(boolean secureDelete) {
        this.secureDelete = secureDelete;
    }

}
