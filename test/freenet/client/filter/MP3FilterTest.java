package freenet.client.filter;

import junit.framework.TestCase;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import freenet.support.api.Bucket;
import freenet.support.io.ArrayBucket;
import freenet.support.io.BucketTools;

public class MP3FilterTest extends TestCase {
    private static final String RESOURCE_PATH = "mp3/";

    /** Known good files, should pass filter unaltered. */
    private static final String[] GOOD = {
        // MPEG ADTS, layer III, v2.5, 8 kbps, 8 kHz, Stereo
        "8khz-8kbps-cbr-stereo.mp3",
        // MPEG ADTS, layer III, v2.5, 48 kbps, 11.025 kHz, Stereo
        "11khz-48kbps-cbr-stereo.mp3",
        // MPEG ADTS, layer III, v2, 56 kbps, 16 kHz, Stereo
        "16khz-56kbps-cbr-stereo.mp3",
        // MPEG ADTS, layer III, v2, 96 kbps, 22.05 kHz, Stereo
        "22khz-96kbps-cbr-stereo.mp3",
        // MPEG ADTS, layer III, v1, 96 kbps, 32 kHz, Stereo
        "32khz-96kbps-cbr-stereo.mp3",
        // MPEG ADTS, layer III, v1, 96 kbps, 44.1 kHz, Stereo
        "44khz-96kbps-cbr-stereo.mp3",
        // MPEG ADTS, layer III, v1, 128 kbps, 48 kHz, Stereo
        "48khz-64kbps-vbr-stereo.mp3",
        // MPEG ADTS, layer III, v1, 128 kbps, 48 kHz, JntStereo
        "48khz-96kbps-vbr-joint.mp3",
        // MPEG ADTS, layer III, v1, 128 kbps, 48 kHz, Stereo
        "48khz-128kbps-cbr-stereo.mp3",
        // MPEG ADTS, layer III, v1, 320 kbps, 48 kHz, JntStereo
        "48khz-320kbps-cbr-joint.mp3"
    };

    /** Pairs of unfiltered file and their expected output file. */
    private static final String[][] FILTER_PAIRS = {
        // random + 48khz-96kbps-vbr-joint + random + 48khz-96kbps-vbr-joint + random
        // Random data is to be removed, leaving file with duplicate 48khz-96kbps-vbr-joint
        new String[] {
            "48khz-96kbps-vbr-joint-randompadding-unfiltered.mp3",
            "48khz-96kbps-vbr-joint-randompadding-expected.mp3"
        },
        // 48khz-128kbps-cbr-stereo with ID3v2 tags to be stripped
        new String[] {
            "48khz-128kbps-cbr-stereo-id3v2.mp3",
            "48khz-128kbps-cbr-stereo.mp3"
        }
    };

    public void testKnownGood() {
        for (String good : GOOD) {
            assertEqualAfterFilter(good, good);
        }
    }

    public void testFilterPairs() {
        for (String[] pair : FILTER_PAIRS) {
            assertEqualAfterFilter(pair[0], pair[1]);
        }
    }

    /**
     * Asserts that the test file in the first argument, after passing through the content filter,
     * is equal to the reference file in the second argument.
     *
     * @param fileUnfiltered  the test file
     * @param fileExpected    the reference file
     */
    private static void assertEqualAfterFilter(String fileUnfiltered, String fileExpected) {
        Bucket input = resourceToBucket(fileUnfiltered);
        Bucket expected = resourceToBucket(fileExpected);
        Bucket filtered = filterMP3(input);
        assertTrue("Filtered and expected output are not identical. " +
            "Input = " + fileUnfiltered + ", expected = " + fileExpected,
            equalBuckets(filtered, expected)
        );
    }

    /**
     * Checks for equality of Bucket contents.
     */
    private static boolean equalBuckets(Bucket a, Bucket b) {
        try {
            return Arrays.equals(BucketTools.toByteArray(a), BucketTools.toByteArray(b));
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    /**
     * Runs a Bucket through the content filter.
     *
     * @throws AssertionError on failure
     */
    private static Bucket filterMP3(Bucket input) {
        ContentDataFilter filter = new MP3Filter();
        Bucket output = new ArrayBucket();

        InputStream inStream;
        OutputStream outStream;
        try {
            inStream = input.getInputStream();
            outStream = output.getOutputStream();
        } catch (IOException e) {
            throw new AssertionError(e);
        }

        try {
            filter.readFilter(inStream, outStream, "", null, null, null);
        } catch (Exception e) {
            throw new AssertionError("Unexpected exception in the content filter.", e);
        }

        try {
            inStream.close();
            outStream.close();
        } catch (IOException e) {
            throw new AssertionError(e);
        }

        return output;
    }

    /**
     * Loads a resource relative to the resource path into a Bucket.
     *
     * @throws AssertionError on failure
     */
    private static Bucket resourceToBucket(String filename) {
        InputStream is = MP3FilterTest.class.getResourceAsStream(RESOURCE_PATH + filename);
        if (is == null) {
            throw new AssertionError("Test resource could not be opened: " + filename);
        }
        Bucket ab = new ArrayBucket();
        try {
            BucketTools.copyFrom(ab, is, Long.MAX_VALUE);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
        return ab;
    }
}
