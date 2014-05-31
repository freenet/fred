/*
 * This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL.
 */



package freenet.node.fcp;

//~--- non-JDK imports --------------------------------------------------------

import freenet.support.Logger;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.io.BucketTools;
import freenet.support.io.NullBucket;

//~--- JDK imports ------------------------------------------------------------

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class DataCarryingMessage extends BaseDataCarryingMessage {
    protected Bucket bucket;
    protected boolean freeOnSent;

    Bucket createBucket(BucketFactory bf, long length, FCPServer server) throws IOException {
        return bf.makeBucket(length);
    }

    abstract String getIdentifier();

    abstract boolean isGlobal();

    void setFreeOnSent() {
        freeOnSent = true;
    }

    @Override
    public void readFrom(InputStream is, BucketFactory bf, FCPServer server)
            throws IOException, MessageInvalidException {
        long len = dataLength();

        if (len < 0) {
            return;
        }

        if (len == 0) {
            bucket = new NullBucket();

            return;
        }

        Bucket tempBucket;

        try {
            tempBucket = createBucket(bf, len, server);
        } catch (IOException e) {
            Logger.error(this, "Bucket error: " + e, e);

            throw new MessageInvalidException(ProtocolErrorMessage.INTERNAL_ERROR, e.toString(), getIdentifier(),
                                              isGlobal());
        }

        BucketTools.copyFrom(tempBucket, is, len);
        this.bucket = tempBucket;
    }

    @Override
    protected void writeData(OutputStream os) throws IOException {
        long len = dataLength();

        if (len > 0) {
            BucketTools.copyTo(bucket, os, len);
        }

        if (freeOnSent) {
            bucket.free();    // Always transient so no removeFrom() needed.
        }
    }

    @Override
    String getEndString() {
        return "Data";
    }
}
