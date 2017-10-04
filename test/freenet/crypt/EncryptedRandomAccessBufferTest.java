/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.crypt;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import freenet.client.async.ClientContext;
import freenet.support.io.BucketTools;
import freenet.support.io.ByteArrayRandomAccessBuffer;
import freenet.support.io.FileUtil;
import freenet.support.io.FileRandomAccessBuffer;
import freenet.support.io.ResumeFailedException;
import freenet.support.io.StorageFormatException;

public class EncryptedRandomAccessBufferTest {
    private final static EncryptedRandomAccessBufferType[] types = 
            EncryptedRandomAccessBufferType.values();
    private final static byte[] message;
    static {
        try {
            message = "message".getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new Error(e);
        }
    }
    private final static MasterSecret secret = new MasterSecret();
    private final static long falseMagic = 0x2c158a6c8882ffd3L;
    
    static{
        Security.addProvider(new BouncyCastleProvider());
    }
    
    @Rule public ExpectedException thrown= ExpectedException.none();
    
    @Test
    public void testSuccesfulRoundTrip() throws IOException, GeneralSecurityException{
        for(EncryptedRandomAccessBufferType type: types){
            byte[] bytes = new byte[100];
            ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
            EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(type, barat, secret, true);
            erat.pwrite(0, message, 0, message.length);
            byte[] result = new byte[message.length];
            erat.pread(0, result, 0, result.length);
            erat.close();
            assertArrayEquals(message, result);
        }
    }
    
    @Test
    public void testSuccesfulRoundTripReadHeader() throws IOException, GeneralSecurityException{
        for(EncryptedRandomAccessBufferType type: types){
            byte[] bytes = new byte[100];
            ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
            EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(type, barat, secret, true);
            erat.pwrite(0, message, 0, message.length);
            erat.close();
            ByteArrayRandomAccessBuffer barat2 = new ByteArrayRandomAccessBuffer(bytes);
            EncryptedRandomAccessBuffer erat2 = new EncryptedRandomAccessBuffer(type, barat2, secret, false);
            byte[] result = new byte[message.length];
            erat2.pread(0, result, 0, result.length);
            erat2.close();
            assertArrayEquals(message, result);
        }
    }
    
    @Test
    public void testWrongERATType() throws IOException, GeneralSecurityException {
        byte[] bytes = new byte[100];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
        erat.close();
        ByteArrayRandomAccessBuffer barat2 = new ByteArrayRandomAccessBuffer(bytes);
        thrown.expect(IOException.class);
        thrown.expectMessage("This is not an EncryptedRandomAccessBuffer"); // Different header lengths.
        EncryptedRandomAccessBuffer erat2 = new EncryptedRandomAccessBuffer(types[1], barat2, 
                secret, false);
    }
    
    @Test
    public void testUnderlyingRandomAccessThingTooSmall() 
            throws GeneralSecurityException, IOException {
        byte[] bytes = new byte[10];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        thrown.expect(IOException.class);
        thrown.expectMessage("Underlying RandomAccessBuffer is not long enough to include the "
                + "footer.");
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
    }
    
    @Test
    public void testWrongMagic() throws IOException, GeneralSecurityException{
        byte[] bytes = new byte[100];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
        erat.close();
        ByteArrayRandomAccessBuffer barat2 = new ByteArrayRandomAccessBuffer(bytes);
        byte[] magic = ByteBuffer.allocate(8).putLong(falseMagic).array();
        barat2.pwrite(types[0].headerLen-8, magic, 0, 8);
        thrown.expect(IOException.class);
        thrown.expectMessage("This is not an EncryptedRandomAccessBuffer!");
        EncryptedRandomAccessBuffer erat2 = new EncryptedRandomAccessBuffer(types[0], barat2, secret, false);
    }
    
    @Test
    public void testWrongMasterSecret() throws IOException, GeneralSecurityException{
        byte[] bytes = new byte[100];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
        erat.close();
        ByteArrayRandomAccessBuffer barat2 = new ByteArrayRandomAccessBuffer(bytes);
        thrown.expect(GeneralSecurityException.class);
        thrown.expectMessage("MAC is incorrect");
        EncryptedRandomAccessBuffer erat2 = new EncryptedRandomAccessBuffer(types[0], barat2, 
                new MasterSecret(), false);
    }
    
    @Test (expected = NullPointerException.class)
    public void testEncryptedRandomAccessThingNullInput1() 
            throws GeneralSecurityException, IOException {
        byte[] bytes = new byte[10];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(null, barat, secret, true);
    }
    
    @Test (expected = NullPointerException.class)
    public void testEncryptedRandomAccessThingNullByteArray() 
            throws GeneralSecurityException, IOException {
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(null);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
    }
    
    @Test (expected = NullPointerException.class)
    public void testEncryptedRandomAccessThingNullBARAT() 
            throws GeneralSecurityException, IOException {
        ByteArrayRandomAccessBuffer barat = null;
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
    }
    
    @Test (expected = NullPointerException.class)
    public void testEncryptedRandomAccessThingNullInput3() 
            throws GeneralSecurityException, IOException {
        byte[] bytes = new byte[10];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, null, true);
    }

    @Test
    public void testSize() throws IOException, GeneralSecurityException {
        byte[] bytes = new byte[100];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
        assertEquals(erat.size(), barat.size()-types[0].headerLen);
    }

    @Test
    public void testPreadFileOffsetTooSmall() throws IOException, GeneralSecurityException {
        byte[] bytes = new byte[100];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
        byte[] result = new byte[20];
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Cannot read before zero");
        erat.pread(-1, result, 0, 20);
    }
    
    @Test
    public void testPreadFileOffsetTooBig() throws IOException, GeneralSecurityException {
        byte[] bytes = new byte[100];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
        int len = 20;
        byte[] result = new byte[len];
        int offset = 100;
        thrown.expect(IOException.class);
        thrown.expectMessage("Cannot read after end: trying to read from "+offset+" to "+
                (offset+len)+" on block length "+erat.size());
        erat.pread(offset, result, 0, len);
    }
    
    @Test
    public void testPwriteFileOffsetTooSmall() throws IOException, GeneralSecurityException {
        byte[] bytes = new byte[100];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
        byte[] result = new byte[20];
        thrown.expect(IllegalArgumentException.class);
        thrown.expectMessage("Cannot read before zero");
        erat.pwrite(-1, result, 0, 20);
    }
    
    @Test
    public void testPwriteFileOffsetTooBig() throws IOException, GeneralSecurityException {
        byte[] bytes = new byte[100];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
        int len = 20;
        byte[] result = new byte[len];
        int offset = 100;
        thrown.expect(IOException.class);
        thrown.expectMessage("Cannot write after end: trying to write from "+offset+" to "+
                (offset+len)+" on block length "+erat.size());
        erat.pwrite(offset, result, 0, len);
    }

    @Test
    public void testClose() throws IOException, GeneralSecurityException {
        byte[] bytes = new byte[100];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
        erat.close();
        erat.close();
    }

    @Test
    public void testClosePread() throws IOException, GeneralSecurityException {
        byte[] bytes = new byte[100];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
        erat.close();
        byte[] result = new byte[20];
        thrown.expect(IOException.class);
        thrown.expectMessage("This RandomAccessBuffer has already been closed. It can no longer"
                    + " be read from.");
        erat.pread(0, result, 0, 20);
    }

    @Test
    public void testClosePwrite() throws IOException, GeneralSecurityException {
        byte[] bytes = new byte[100];
        ByteArrayRandomAccessBuffer barat = new ByteArrayRandomAccessBuffer(bytes);
        EncryptedRandomAccessBuffer erat = new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
        erat.close();
        byte[] result = new byte[20];
        thrown.expect(IOException.class);
        thrown.expectMessage("This RandomAccessBuffer has already been closed. It can no longer"
                    + " be written to.");
        erat.pwrite(0, result, 0, 20);
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
        FileRandomAccessBuffer rafw = new FileRandomAccessBuffer(tempFile, buf.length+types[0].headerLen, false);
        EncryptedRandomAccessBuffer eraf = new EncryptedRandomAccessBuffer(types[0], rafw, secret, true);
        eraf.pwrite(0, buf, 0, buf.length);
        byte[] tmp = new byte[buf.length];
        eraf.pread(0, tmp, 0, buf.length);
        assertArrayEquals(buf, tmp);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        eraf.storeTo(dos);
        dos.close();
        eraf.close();
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
        ClientContext context = new ClientContext(0, null, null, null, null, null, null, null,
                null, r, null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null);
        context.setPersistentMasterSecret(secret);
        EncryptedRandomAccessBuffer restored = (EncryptedRandomAccessBuffer) BucketTools.restoreRAFFrom(dis, context.persistentFG, context.persistentFileTracker, secret);
        assertEquals(buf.length, restored.size());
        //assertEquals(rafw, restored);
        tmp = new byte[buf.length];
        restored.pread(0, tmp, 0, buf.length);
        assertArrayEquals(buf, tmp);
        restored.close();
        restored.free();
    }
    
    @Test
    public void testSerialize() throws IOException, StorageFormatException, ResumeFailedException, GeneralSecurityException, ClassNotFoundException {
        File tempFile = File.createTempFile("test-storeto", ".tmp", base);
        byte[] buf = new byte[4096];
        Random r = new Random(1267612);
        r.nextBytes(buf);
        FileRandomAccessBuffer rafw = new FileRandomAccessBuffer(tempFile, buf.length+types[0].headerLen, false);
        EncryptedRandomAccessBuffer eraf = new EncryptedRandomAccessBuffer(types[0], rafw, secret, true);
        eraf.pwrite(0, buf, 0, buf.length);
        byte[] tmp = new byte[buf.length];
        eraf.pread(0, tmp, 0, buf.length);
        assertArrayEquals(buf, tmp);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(eraf);
        oos.close();
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
        ClientContext context = new ClientContext(0, null, null, null, null, null, null, null,
                null, r, null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null);
        context.setPersistentMasterSecret(secret);
        ObjectInputStream ois = new ObjectInputStream(dis);
        EncryptedRandomAccessBuffer restored = (EncryptedRandomAccessBuffer) ois.readObject();
        restored.onResume(context);
        assertEquals(buf.length, restored.size());
        assertEquals(eraf, restored);
        tmp = new byte[buf.length];
        restored.pread(0, tmp, 0, buf.length);
        assertArrayEquals(buf, tmp);
        restored.close();
        restored.free();
    }
    
}
