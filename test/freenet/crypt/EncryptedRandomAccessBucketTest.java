package freenet.crypt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import freenet.client.async.ClientContext;
import freenet.support.api.Bucket;
import freenet.support.api.LockableRandomAccessBuffer;
import freenet.support.api.RandomAccessBucket;
import freenet.support.io.ArrayBucket;
import freenet.support.io.BucketTestBase;
import freenet.support.io.BucketTools;
import freenet.support.io.FileBucket;
import freenet.support.io.FileUtil;
import freenet.support.io.RAFBucket;
import freenet.support.io.FileRandomAccessBuffer;
import freenet.support.io.RandomAccessBufferTestBase;
import freenet.support.io.ResumeFailedException;
import freenet.support.io.StorageFormatException;

public class EncryptedRandomAccessBucketTest extends BucketTestBase {
    
    private final static MasterSecret secret = new MasterSecret();
    private final static EncryptedRandomAccessBufferType[] types = 
        EncryptedRandomAccessBufferType.values();
    
    static{
        Security.addProvider(new BouncyCastleProvider());
    }
    
    @Override
    protected Bucket makeBucket(long size) throws IOException {
        ArrayBucket underlying = new ArrayBucket();
        return new EncryptedRandomAccessBucket(types[0], underlying, secret);
    }

    @Override
    protected void freeBucket(Bucket bucket) throws IOException {
        bucket.free();
    }
    
    public void testIrregularWrites() throws IOException {
        Random r = new Random(6032405);
        int length = 1024*64+1;
        byte[] data = new byte[length];
        RandomAccessBucket bucket = (RandomAccessBucket) makeBucket(length);
        OutputStream os = bucket.getOutputStream();
        r.nextBytes(data);
        for(int written=0;written<length;) {
            int toWrite = Math.min(length - written, 4095);
            os.write(data, written, toWrite);
            written += toWrite;
        }
        os.close();
        InputStream is = bucket.getInputStream();
        for(int moved=0;moved<length;) {
            int readBytes = Math.min(length - moved, 4095);
            byte[] buf = new byte[readBytes];
            readBytes = is.read(buf);
            assertTrue(readBytes > 0);
            assertTrue(Arrays.equals(Arrays.copyOfRange(buf, 0, readBytes), Arrays.copyOfRange(data, moved, moved+readBytes)));
            moved += readBytes;
        }
        is.close();
        bucket.free();
    }
    
    public void testIrregularWritesNotOverlapping() throws IOException {
        Random r = new Random(6032405);
        int length = 1024*64+1;
        byte[] data = new byte[length];
        RandomAccessBucket bucket = (RandomAccessBucket) makeBucket(length);
        OutputStream os = bucket.getOutputStream();
        r.nextBytes(data);
        for(int written=0;written<length;) {
            int toWrite = Math.min(length - written, 4095);
            os.write(data, written, toWrite);
            written += toWrite;
        }
        os.close();
        InputStream is = bucket.getInputStream();
        for(int moved=0;moved<length;) {
            int readBytes = Math.min(length - moved, 4093); // Co-prime with 4095
            byte[] buf = new byte[readBytes];
            readBytes = is.read(buf);
            assertTrue(readBytes > 0);
            assertTrue(Arrays.equals(Arrays.copyOfRange(buf, 0, readBytes), Arrays.copyOfRange(data, moved, moved+readBytes)));
            moved += readBytes;
        }
        is.close();
        bucket.free();
    }
    
    public void testBucketToRAF() throws IOException {
        Random r = new Random(6032405);
        int length = 1024*64+1;
        byte[] data = new byte[length];
        RandomAccessBucket bucket = (RandomAccessBucket) makeBucket(length);
        OutputStream os = bucket.getOutputStream();
        r.nextBytes(data);
        for(int written=0;written<length;) {
            int toWrite = Math.min(length - written, 4095);
            os.write(data, written, toWrite);
            written += toWrite;
        }
        os.close();
        InputStream is = bucket.getInputStream();
        for(int moved=0;moved<length;) {
            int readBytes = Math.min(length - moved, 4095);
            byte[] buf = new byte[readBytes];
            readBytes = is.read(buf);
            assertTrue(readBytes > 0);
            assertTrue(Arrays.equals(Arrays.copyOfRange(buf, 0, readBytes), Arrays.copyOfRange(data, moved, moved+readBytes)));
            moved += readBytes;
        }
        LockableRandomAccessBuffer raf = bucket.toRandomAccessBuffer();
        assertEquals(length, raf.size());
        RAFBucket wrapped = new RAFBucket(raf);
        assertTrue(BucketTools.equalBuckets(bucket, wrapped));
        for(int i=0;i<100;i++) {
            int end = length == 1 ? 1 : r.nextInt(length)+1;
            int start = r.nextInt(end);
            RandomAccessBufferTestBase.checkArraySectionEqualsReadData(data, raf, start, end, true);
        }
    }
    
    private File base = new File("tmp.encrypted-random-access-thing-test");
    
    @Before
    public void setUp() {
        base.mkdir();
    }
    
    @After
    public void tearDown() {
        FileUtil.removeAll(base);
    }

    @Test
    public void testStoreTo() throws IOException, StorageFormatException, ResumeFailedException, GeneralSecurityException {
        File tempFile = File.createTempFile("test-storeto", ".tmp", base);
        byte[] buf = new byte[4096];
        Random r = new Random(1267612);
        r.nextBytes(buf);
        FileBucket fb = new FileBucket(tempFile, false, false, false, true);
        EncryptedRandomAccessBucket erab = new EncryptedRandomAccessBucket(types[0], fb, secret);
        OutputStream os = erab.getOutputStream();
        os.write(buf, 0, buf.length);
        os.close();
        InputStream is = erab.getInputStream();
        byte[] tmp = new byte[buf.length];
        is.read(tmp, 0, buf.length);
        is.close();
        assertArrayEquals(buf, tmp);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        erab.storeTo(dos);
        dos.close();
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
        ClientContext context = new ClientContext(0, null, null, null, null, null, null, null,
                null, r, null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null);
        context.setPersistentMasterSecret(secret);
        EncryptedRandomAccessBucket restored = (EncryptedRandomAccessBucket) BucketTools.restoreFrom(dis, context.persistentFG, context.persistentFileTracker, secret);
        assertEquals(buf.length, restored.size());
        assertEquals(erab, restored);
        tmp = new byte[buf.length];
        is = erab.getInputStream();
        is.read(tmp, 0, buf.length);
        assertArrayEquals(buf, tmp);
        is.close();
        restored.free();
    }
    
    @Test
    public void testSerialize() throws IOException, StorageFormatException, ResumeFailedException, GeneralSecurityException, ClassNotFoundException {
        File tempFile = File.createTempFile("test-storeto", ".tmp", base);
        byte[] buf = new byte[4096];
        Random r = new Random(1267612);
        r.nextBytes(buf);
        FileBucket fb = new FileBucket(tempFile, false, false, false, true);
        EncryptedRandomAccessBucket erab = new EncryptedRandomAccessBucket(types[0], fb, secret);
        OutputStream os = erab.getOutputStream();
        os.write(buf, 0, buf.length);
        os.close();
        InputStream is = erab.getInputStream();
        byte[] tmp = new byte[buf.length];
        is.read(tmp, 0, buf.length);
        is.close();
        assertArrayEquals(buf, tmp);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(erab);
        oos.close();
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
        ClientContext context = new ClientContext(0, null, null, null, null, null, null, null,
                null, r, null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null);
        context.setPersistentMasterSecret(secret);
        ObjectInputStream ois = new ObjectInputStream(dis);
        EncryptedRandomAccessBucket restored = (EncryptedRandomAccessBucket) ois.readObject();
        restored.onResume(context);
        assertEquals(buf.length, restored.size());
        assertEquals(erab, restored);
        tmp = new byte[buf.length];
        is = erab.getInputStream();
        is.read(tmp, 0, buf.length);
        assertArrayEquals(buf, tmp);
        is.close();
        restored.free();
    }
    
}
