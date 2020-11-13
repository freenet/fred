package freenet.client.filter;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;
import freenet.support.api.Bucket;
import freenet.support.io.ArrayBucket;
import freenet.support.io.BucketTools;

public class M3UFilterTest extends TestCase {
    protected static String[][] testPlaylists = {
        { "./m3u/safe.m3u", "./m3u/safe_madesafe.m3u" },
        { "./m3u/unsafe.m3u", "./m3u/unsafe_madesafe.m3u" },
    };

    private static final String SCHEME_HOST_PORT = "http://localhost:8888";
    private static final String BASE_KEY = "USK@0I8gctpUE32CM0iQhXaYpCMvtPPGfT4pjXm01oid5Zc,3dAcn4fX2LyxO6uCnWFTx-2HKZ89uruurcKwLSCxbZ4,AQACAAE/FakeM3UHostingFreesite/23/";
    private static final String BASE_URI = '/' + BASE_KEY;

    public void testSuiteTest() throws IOException {
        M3UFilter filter = new M3UFilter();

        for (String[] test : testPlaylists) {
            String original = test[0];
            String correct = test[1];
            Bucket ibo;
            Bucket ibprocessed = new ArrayBucket();
            Bucket ibc;
            try {
                ibo = resourceToBucket(original);
            } catch (IOException e) {
                System.out.println(original + " not found");
                throw e;
            }
            try {
                ibc = resourceToBucket(correct);
            } catch (IOException e) {
                System.out.println(correct + " not found");
                throw e;
            }

            try {
                filter.readFilter(ibo.getInputStream(), ibprocessed.getOutputStream(), "UTF-8", null,
                    SCHEME_HOST_PORT, new GenericReadFilterCallback(new URI(BASE_URI), null, null, null));
                String result = ibprocessed.toString();

                assertTrue(original + " should be filtered as " + correct + " but was filtered as\n" + result + "\ninstead of the correct\n" + bucketToString((ArrayBucket)ibc), result.equals(bucketToString((ArrayBucket)ibc)));
            } catch (DataFilterException dfe) {
                assertTrue("Filtering " + original + " failed", false);
            } catch (URISyntaxException use) {
                assertTrue("Creating URI from BASE_URI " + BASE_URI + " failed", false);
            }
        }
    }

    protected ArrayBucket resourceToBucket(String filename) throws IOException {
        InputStream is = getClass().getResourceAsStream(filename);
        if (is == null) throw new java.io.FileNotFoundException();
        ArrayBucket ab = new ArrayBucket();
        BucketTools.copyFrom(ab, is, Long.MAX_VALUE);
        return ab;
    }

    protected String bucketToString(ArrayBucket bucket) throws IOException {
        return new String(bucket.toByteArray());
    }

}
