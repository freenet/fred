package freenet.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import junit.framework.TestCase;

import freenet.client.events.SimpleEventProducer;
import freenet.support.io.ArrayBucket;
import freenet.support.io.StorageFormatException;

public class FetchContextTest extends TestCase {
    
    public void testPersistence() throws IOException, StorageFormatException {
        FetchContext context = 
            HighLevelSimpleClientImpl.makeDefaultFetchContext(Long.MAX_VALUE, Long.MAX_VALUE,
                    new SimpleEventProducer());
        ArrayBucket bucket = new ArrayBucket();
        DataOutputStream dos = new DataOutputStream(bucket.getOutputStream());
        context.writeTo(dos);
        dos.close();
        assert(bucket.size() != 0);
        DataInputStream dis = new DataInputStream(bucket.getInputStream());
        FetchContext ctx = new FetchContext(dis);
        dis.close();
        assertTrue(ctx.equals(context));
        bucket.free();
    }

}
