/*
 * This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL.
 */



package freenet.node.fcp;

//~--- non-JDK imports --------------------------------------------------------

import com.db4o.ObjectContainer;

import freenet.support.SimpleFieldSet;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.io.BucketTools;
import freenet.support.io.NullBucket;

//~--- JDK imports ------------------------------------------------------------

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Specialized DirPutFile for direct uploads.
 */
public class DirectDirPutFile extends DirPutFile {
    private final Bucket data;
    private final long length;

    private DirectDirPutFile(String name, String mimeType, long length, Bucket data) {
        super(name, mimeType);
        this.length = length;
        this.data = data;
    }

    public static DirectDirPutFile create(String name, String contentTypeOverride, SimpleFieldSet subset,
            String identifier, boolean global, BucketFactory bf)
            throws MessageInvalidException {
        String s = subset.get("DataLength");

        if (s == null) {
            throw new MessageInvalidException(ProtocolErrorMessage.MISSING_FIELD,
                                              "UploadFrom=direct requires a DataLength for " + name, identifier,
                                              global);
        }

        long length;
        Bucket data;

        try {
            length = Long.parseLong(s);
        } catch (NumberFormatException e) {
            throw new MessageInvalidException(ProtocolErrorMessage.ERROR_PARSING_NUMBER,
                                              "Could not parse DataLength: " + e.toString(), identifier, global);
        }

        try {
            if (length == 0) {
                data = new NullBucket();
            } else {
                data = bf.makeBucket(length);
            }
        } catch (IOException e) {
            throw new MessageInvalidException(ProtocolErrorMessage.INTERNAL_ERROR,
                                              "Internal error: could not allocate temp bucket: " + e.toString(),
                                              identifier, global);
        }

        String mimeType;

        if (contentTypeOverride == null) {
            mimeType = DirPutFile.guessMIME(name);
        } else {
            mimeType = contentTypeOverride;
        }

        return new DirectDirPutFile(name, mimeType, length, data);
    }

    public long bytesToRead() {
        return length;
    }

    public void read(InputStream is) throws IOException {
        BucketTools.copyFrom(data, is, length);
    }

    public void write(OutputStream os) throws IOException {
        BucketTools.copyTo(data, os, length);
    }

    @Override
    public Bucket getData() {
        return data;
    }

    @Override
    public void removeFrom(ObjectContainer container) {
        data.free();
        data.removeFrom(container);
        container.delete(this);
    }
}
