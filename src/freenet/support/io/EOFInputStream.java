/*
 * This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL.
 */



package freenet.support.io;

//~--- JDK imports ------------------------------------------------------------

import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * An InputStream that always throws EOFException on any read that fails
 * with end of file. 
 */
public class EOFInputStream extends FilterInputStream {
    public EOFInputStream(InputStream in) {
        super(in);
    }

    @Override
    public int read() throws IOException {
        int ret = in.read();

        if (ret < 0) {
            throw new EOFException();
        }

        return ret;
    }

    @Override
    public int read(byte[] b) throws IOException {
        int ret = in.read(b);

        if (ret < 0) {
            throw new EOFException();
        }

        return ret;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int ret = in.read(b, off, len);

        if (ret < 0) {
            throw new EOFException();
        }

        return ret;
    }
}
