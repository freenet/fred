package freenet.client.filter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.HashMap;

import junit.framework.TestCase;

/**
 * Unit test for (parts of) {@link JPEGFilter}.
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public class JPEGFilterTest extends TestCase {

	public void testThatAThumbnailExtensionCodeIsPreserved() throws IOException {
		JPEGFilter jpegFilter = new JPEGFilter(true, true);
		byte[] jpegFile = createValidJpegFileWithThumbnail();
		InputStream inputStream = new ByteArrayInputStream(jpegFile);
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		jpegFilter.readFilter(inputStream, outputStream, "UTF-8", new HashMap<>(), null, new NullFilterCallback());
		byte[] filteredJpegFile = outputStream.toByteArray();
		assertTrue(Arrays.equals(jpegFile, filteredJpegFile));
	}

	private byte[] createValidJpegFileWithThumbnail() throws IOException {
		ByteArrayOutputStream jpegFile = new ByteArrayOutputStream();
		writeStartOfImageMarker(jpegFile);
		writeAppMarker(jpegFile, 0, new byte[]{0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
		writeAppMarker(jpegFile, 0, new byte[]{0x4a, 0x46, 0x58, 0x58, 0x00, 0x13, 0x01, 0x01, 0x00, 0x7f, 0x00});
		writeEndOfImageMarker(jpegFile);
		return jpegFile.toByteArray();
	}

	private void writeStartOfImageMarker(OutputStream outputStream) throws IOException {
		outputStream.write(new byte[]{(byte) 0xff, (byte) 0xd8});
	}

	private void writeAppMarker(OutputStream outputStream, int app, byte[] payload) throws IOException {
		outputStream.write(new byte[]{(byte) 0xff, (byte) (0xe0 + app)});
		int payloadLengthIncludingLength = payload.length + 2;
		outputStream.write(new byte[]{(byte) ((payloadLengthIncludingLength >> 8) & 0xff), (byte) (payloadLengthIncludingLength & 0xff)});
		outputStream.write(payload);
	}

	private void writeEndOfImageMarker(ByteArrayOutputStream outputStream) throws IOException {
		outputStream.write(new byte[]{(byte) 0xff, (byte) 0xd9});
	}

}
