package freenet.crypt;

import java.io.DataInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class AEADInputStream extends FilterInputStream {
    
    private static final int MAC_SIZE_BITS = AEADOutputStream.MAC_SIZE_BITS;
    private final AEADBlockCipher cipher;
    private boolean finished;
    
    /** Create a decrypting, authenticating InputStream. IMPORTANT: We only authenticate when 
     * closing the stream, so do NOT use Closer.close() etc and swallow IOException's on close(),
     * as that's what we will throw if authentication fails. We will read the nonce from the 
     * stream; it functions similarly to an IV.
     * @param is The underlying InputStream. 
     * @param key The encryption key.
     * @param nonce The nonce. This serves the function of an IV. As a nonce, this MUST be unique. 
     * We will write it to the stream so the other side can pick it up, like an IV. 
     * @param mainCipher The BlockCipher for encrypting data. E.g. AES; not a block mode. This will
     * be used for encrypting a fairly large amount of data so could be any of the 3 BC AES impl's.
     * @param hashCipher The BlockCipher for the final hash. E.g. AES, not a block mode. This will
     * not be used very much so should be e.g. an AESLightEngine. */
    public AEADInputStream(InputStream is, byte[] key, BlockCipher hashCipher, 
            BlockCipher mainCipher) throws IOException {
        super(is);
        byte[] nonce = new byte[mainCipher.getBlockSize()];
        new DataInputStream(is).readFully(nonce);
        if ((nonce[0] & 0x80) != 0) {
            throw new IOException("Invalid or corrupted cipher nonce value in data stream");
        }
        cipher = new OCBBlockCipher_v149(hashCipher, mainCipher);
        KeyParameter keyParam = new KeyParameter(key);
        AEADParameters params = new AEADParameters(keyParam, MAC_SIZE_BITS, nonce);
        cipher.init(false, params);
        excess = new byte[mainCipher.getBlockSize()];
        excessEnd = 0;
        excessPtr = 0;
    }
    
    public final int getIVSize() {
        return cipher.getUnderlyingCipher().getBlockSize() / 8;
    }
    
    private final byte[] onebyte = new byte[1];
    
    private final byte[] excess;
    private int excessEnd;
    private int excessPtr;
    
    @Override
    public int read() throws IOException {
        int length = read(onebyte);
        if(length <= 0) return -1;
        else return onebyte[0];
    }
    
    @Override
    public int read(byte[] buf) throws IOException {
        return read(buf, 0, buf.length);
    }
    
    @Override
    public int read(byte[] buf, int offset, int length) throws IOException {
        if(length < 0) return -1;
        if(length == 0) return 0;
        if(excessEnd != 0) {
            length = Math.min(length, excessEnd - excessPtr);
            if(length > 0) {
                System.arraycopy(excess, excessPtr, buf, offset, length);
                excessPtr += length;
                if(excessEnd == excessPtr) {
                    excessEnd = 0;
                    excessPtr = 0;
                }
                return length;
            }
        }
        if(finished) return -1;
        // FIXME OPTIMISE Can we avoid allocating new buffers here? We can't safely use in=out when
        // calling cipher.processBytes().
        while(true) {
            byte[] temp = new byte[length];
            int read = in.read(temp);
            if(read == 0) return read; // Nasty ambiguous case.
            if(read < 0) {
                // End of stream.
                // The last few bytes will still be in the cipher's buffer and have to be retrieved by doFinal().
                try {
                    excessEnd = cipher.doFinal(excess, 0);
                } catch (InvalidCipherTextException e) {
                    throw new AEADVerificationFailedException();
                }
                finished = true;
                if(excessEnd > 0)
                    return read(buf, offset, length);
                else
                    return -1;
            }
            if(read <= 0) return read;
            assert(read <= length);
            int outLength = cipher.getUpdateOutputSize(read);
            if(outLength > length) {
                byte[] outputTemp = new byte[outLength];
                int decryptedBytes = cipher.processBytes(temp, 0, read, outputTemp, 0);
                assert(decryptedBytes == outLength);
                System.arraycopy(outputTemp, 0, buf, offset, length);
                excessEnd = outLength - length;
                assert(excessEnd < excess.length);
                System.arraycopy(outputTemp, length, excess, 0, excessEnd);
                return length;
            } else {
                int decryptedBytes = cipher.processBytes(temp, 0, read, buf, offset);
                if(decryptedBytes > 0) return decryptedBytes;
            }
        }
    }
    
    @Override
    public int available() throws IOException {
        int excess = excessEnd - excessPtr;
        if(excess > 0) return excess;
        if(finished) return 0;
        // FIXME Not very accurate as may include the MAC - or it may not, this is not the full 
        // length of the stream. Maybe we should return 0?
        return in.available();
    }
    
    @Override
    public long skip(long n) throws IOException {
        // FIXME unit test skip()
        long skipped = 0;
        byte[] temp = new byte[excess.length];
        while(n > 0) {
            int excessLeft = excessEnd - excessPtr;
            if(excessLeft > 0) {
                if(n < excessLeft) {
                    excessPtr += (int)n;
                    return n;
                }
                n -= excessLeft;
                skipped += excessLeft;
                excessEnd = 0;
                excessPtr = 0;
                continue;
            }
            if(n < temp.length) {
                int read = read(temp, 0, (int)n);
                if(read <= 0) return skipped;
                skipped += read;
                n -= read;
            } else {
                int read = read(temp);
                if(read <= 0) return skipped;
                skipped += read;
                n -= read;
            }
        }
        return skipped;
    }
    
    @Override
    public void close() throws IOException {
        if(!finished)
            // Must read the rest of the data to check hash integrity.
            skip(Long.MAX_VALUE);
        in.close();
    }
    
    @Override
    public boolean markSupported() {
        return false;
    }
    
    @Override
    public void mark(int readlimit) {
        throw new UnsupportedOperationException();
    }
    
    @Override
    public void reset() throws IOException {
        throw new IOException("Mark/reset not supported");
    }
    
    public static AEADInputStream createAES(InputStream is, byte[] key) throws IOException {
        AESEngine mainCipher = new AESEngine();
        AESLightEngine hashCipher = new AESLightEngine();
        return new AEADInputStream(is, key, hashCipher, mainCipher);
    }

}
