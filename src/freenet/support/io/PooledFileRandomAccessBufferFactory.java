package freenet.support.io;

import java.io.File;
import java.io.IOException;
import java.util.Random;

import freenet.support.api.LockableRandomAccessBuffer;
import freenet.support.api.LockableRandomAccessBufferFactory;

/** Creates temporary RAFs using a FilenameGenerator. */
public class PooledFileRandomAccessBufferFactory implements LockableRandomAccessBufferFactory {
    
    private final FilenameGenerator fg;
    private final Random seedRandom;
    private volatile boolean enableCrypto;

    public PooledFileRandomAccessBufferFactory(FilenameGenerator filenameGenerator, Random seedRandom) {
        fg = filenameGenerator;
        this.seedRandom = seedRandom;
    }
    
    public void enableCrypto(boolean enable) {
        this.enableCrypto = enable;
    }

    @Override
    public LockableRandomAccessBuffer makeRAF(long size) throws IOException {
        long id = fg.makeRandomFilename();
        File file = fg.getFilename(id);
        LockableRandomAccessBuffer ret = null;
        try {
            ret = new PooledFileRandomAccessBuffer(file, false, size, id, true);
            return ret;
        } finally {
            if(ret == null) file.delete();
        }
    }

    @Override
    public LockableRandomAccessBuffer makeRAF(byte[] initialContents, int offset, int size, boolean readOnly)
            throws IOException {
        long id = fg.makeRandomFilename();
        File file = fg.getFilename(id);
        LockableRandomAccessBuffer ret = null;
        try {
            ret = new PooledFileRandomAccessBuffer(file, initialContents, offset, size, id, true, readOnly);
            return ret;
        } finally {
            if(ret == null) file.delete();
        }
    }

}
