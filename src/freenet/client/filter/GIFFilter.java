/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.filter;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.HashMap;

import freenet.l10n.NodeL10n;

/**
 * Content filter for GIF's.
 * This throws out all optional non-raster data that it cannot validate.
 *
 * References:
 * https://www.w3.org/Graphics/GIF/spec-gif87.txt
 * https://www.w3.org/Graphics/GIF/spec-gif89a.txt
 */
public class GIFFilter implements ContentDataFilter {

	static final int HEADER_SIZE = 6;
	static final byte[] gif87aHeader =
		{ (byte)'G', (byte)'I', (byte)'F', (byte)'8', (byte)'7', (byte)'a' };
	static final byte[] gif89aHeader =
		{ (byte)'G', (byte)'I', (byte)'F', (byte)'8', (byte)'9', (byte)'a' };


	@Override
	public void readFilter(
      InputStream input, OutputStream output, String charset, HashMap<String, String> otherParams,
      String schemeHostAndPort, FilterCallback cb) throws DataFilterException, IOException {
		DataInputStream dis = new DataInputStream(input);
		try {
			// Check the header
			byte[] headerCheck = new byte[HEADER_SIZE];
			dis.readFully(headerCheck);
			final boolean isGIF87a = Arrays.equals(headerCheck, gif87aHeader);
			final boolean isGIF89a = Arrays.equals(headerCheck, gif89aHeader);
			if (!isGIF87a && !isGIF89a) {
				throwDataError(l10n("invalidHeaderTitle"), l10n("invalidHeader"));
			}
			output.write(headerCheck);
			if (isGIF87a) {
				GIF87aValidator.filter(input, output);
			} else if (isGIF89a) {
				GIF89aValidator.filter(input, output);
			}
		} catch (EOFException e) {
			throwDataError(l10n("unexpectedEOFTitle"), l10n("unexpectedEOF"));
		}
		output.flush();
	}

	private static abstract class GIFValidator {
		private final InputStream input;
		private final OutputStream output;

		// Screen descriptor data
		protected int screenWidth;
		protected int screenHeight;
		protected int screenFlags;
		protected int screenColors; // Parsed from screenFlags
		protected int screenBackgroundColor;
		protected int screenAspectRatio;

		// ",": Image separator character
		private static final int IMAGE_SEPARATOR = 0x2C;
		// ";": GIF terminator
		private static final int GIF_TERMINATOR = 0x3B;
		// "!": GIF Extension Block Introducer
		protected static final int EXTENSION_INTRODUCER = 0x21;

		protected GIFValidator(InputStream input, OutputStream output) {
			this.input = input;
			this.output = output;
		}

		/** Checks whether the parsed screen descriptor is valid. */
		protected boolean validateScreenDescriptor() {
			// Not in the specification, but check whether the background color index is within
			// the bounds of the Global Color Table just to be sure.
			return screenBackgroundColor < screenColors;
		}

		/** Checks whether the given image flags are valid. */
		protected boolean validateImageFlags(int imageFlags) {
			return true;
		}

		/** Filters the next extension blocks, and skips it when it is unsupported or invalid. */
		protected void filterExtensionBlock() throws IOException {
			skipExtensionBlock();
		}

		/** Signals that image data is found. If the image data is valid, it will be written
		  * immediately after this method returns. */
		protected void foundImageData(boolean valid) throws IOException {
			// Do nothing.
		}

		/** Filters a complete GIF stream; assuming its header has already been read. */
		protected final void filter() throws IOException, DataFilterException {
			readScreenDescriptor();
			if (!validateScreenDescriptor()) {
				throwDataError(l10n("invalidHeaderTitle"), l10n("invalidHeader"));
			}
			writeScreenDescriptor();
			final boolean hasGlobalColorMap = (screenFlags & 0x80) == 0x80;
			if (hasGlobalColorMap) {
				copy(3 * screenColors);
			}
			filterData();
		}

		/** Reads the screen descriptor from the input and parses it. */
		private void readScreenDescriptor() throws IOException, DataFilterException {
			screenWidth = readShort();
			screenHeight = readShort();
			screenFlags = readByte();
			screenBackgroundColor = readByte();
			screenAspectRatio = readByte();

			final int bitsPerPixel = (screenFlags & 0x07) + 1;
			screenColors = 1 << bitsPerPixel;
		}

		/** Writes the previously parsed and validated screen descriptor to the output. */
		private void writeScreenDescriptor() throws IOException {
			writeShort(screenWidth);
			writeShort(screenHeight);
			writeByte(screenFlags);
			writeByte(screenBackgroundColor);
			writeByte(screenAspectRatio);
		}

		/** Looks for data blocks and filters them according to their type. */
		private void filterData() throws IOException, DataFilterException {
			boolean imageSeen = false;
			boolean terminated = false;
			int lastByte;
			while (!terminated && (lastByte = input.read()) != -1) {
				switch(lastByte) {
					case IMAGE_SEPARATOR:
						imageSeen |= filterImage();
						break;
					case GIF_TERMINATOR:
						terminated |= imageSeen;
						break;
					case EXTENSION_INTRODUCER:
						filterExtensionBlock();
						break;
					default:
						// The specification expects us to skip other data; we can simply omit it.
				}
			}
			if (!imageSeen) {
				throwDataError(l10n("noDataTitle"), l10n("noData"));
			}
			if (!terminated) {
				throwDataError(l10n("unterminatedGifTitle"), l10n("unterminatedGif"));
			}
			// There may still be trailing data at this point; we can simply omit it.
			writeByte(GIF_TERMINATOR);
		}

		/** Filters a render block. Actual LZW data is *not* checked. */
		private boolean filterImage() throws IOException, DataFilterException {
			final int imageLeft = readShort();
			final int imageTop = readShort();
			final int imageWidth = readShort();
			final int imageHeight = readShort();
			final int imageFlags = readByte();
			final boolean hasLocalColorMap = (imageFlags & 0x80) == 0x80;
			final byte[] localColorMap;
			if (hasLocalColorMap) {
				final int bitsPerPixel = (imageFlags & 0x07) + 1;
				final int imageColors = 1 << bitsPerPixel;
				localColorMap = readBytes(3 * imageColors);
			} else {
				localColorMap = new byte[0];
			}
			final int lzwCodeSize = readByte();
			if (imageLeft + imageWidth > screenWidth || imageTop + imageHeight > screenHeight ||
					lzwCodeSize < 2 || lzwCodeSize >= 12 || !validateImageFlags(imageFlags)) {
				foundImageData(false);
				skipSubBlocks();
				return false;
			} else {
				foundImageData(true);
				writeByte(IMAGE_SEPARATOR);
				writeShort(imageLeft);
				writeShort(imageTop);
				writeShort(imageWidth);
				writeShort(imageHeight);
				writeByte(imageFlags);
				writeBytes(localColorMap);
				writeByte(lzwCodeSize);
				copySubBlocks();
				return true;
			}
		}

		/** Skips an entire extension block; assumes the extension indicator is already read. */
		private void skipExtensionBlock() throws IOException {
			skip(1); // extension function
			skipSubBlocks();
		}

		/** Skips all subblocks in the input, until the empty terminator subblock is found. */
		protected final void skipSubBlocks() throws IOException {
			int length;
			while ((length = readByte()) != 0) {
				skip(length);
			}
		}

		/** Copies all subblocks to the output, until the empty terminator subblock is found. */
		protected final void copySubBlocks() throws IOException {
			int length;
			while ((length = readByte()) != 0) {
				writeByte(length);
				copy(length);
			}
			writeByte(0);
		}

		/** Copy a small number of bytes from input to output. */
		protected final void copy(int length) throws IOException {
			for (int i = 0; i < length; i++) {
				writeByte(readByte());
			}
		}

		/** Read an unsigned byte from the input. */
		protected final int readByte() throws IOException {
			int val = input.read();
			if (val == -1) {
				throw new EOFException();
			}
			return val;
		}

		/** Write an unsigned byte to the output. */
		protected final void writeByte(int val) throws IOException {
			output.write(val & 0xFF);
		}

		/** Read a number of bytes from the input. */
		protected final byte[] readBytes(int num) throws IOException {
			byte[] buf = new byte[num];
			int remaining = buf.length;
			while (remaining > 0) {
				int read = input.read(buf, buf.length - remaining, remaining);
				if (read <= 0) {
					throw new EOFException();
				}
				remaining -= read;
			}
			return buf;
		}

		/** Write all given bytes to the output. */
		protected final void writeBytes(byte[] data) throws IOException {
			output.write(data);
		}

		/** Read a little-endian unsigned short from the input. */
		protected final int readShort() throws IOException {
			int lsb = readByte();
			int msb = readByte();
			return (msb << 8) | lsb;
		}

		/** Write a little-endian unsigned short to the output. */
		protected final void writeShort(int val) throws IOException {
			output.write(val & 0xFF);
			output.write((val >>> 8) & 0xFF);
		}

		/** Skip the given number of bytes of the input. */
		protected final void skip(int num) throws IOException {
			long remaining = num;
			long skipped;
			while (remaining > 0) {
				skipped = input.skip(remaining);
				remaining -= skipped;
				if (skipped == 0) {
					readByte();
					remaining--;
				}
			}
		}
	}

	private static class GIF87aValidator extends GIFValidator {
		private GIF87aValidator(InputStream input, OutputStream output) {
			super(input, output);
		}

		@Override
		protected boolean validateScreenDescriptor() {
			// The sort flag and aspect ratio indicator must be 0 in GIF87a.
			final boolean sort = (screenFlags & 0x08) == 0x08;
			if (sort || screenAspectRatio != 0) {
				return false;
			}
			return super.validateScreenDescriptor();
		}

		@Override
		protected boolean validateImageFlags(int imageFlags) {
			// The disposal method must be 0 in GIF87a.
			return (imageFlags & 0x38) == 0x00 && super.validateImageFlags(imageFlags);
		}

		static void filter(InputStream input, OutputStream output)
				throws IOException, DataFilterException {
			new GIF87aValidator(input, output).filter();
		}
	}

	private static class GIF89aValidator extends GIFValidator {
		// Whether we have a valid graphic control block to output.
		private boolean hasGraphicControl = false;
		private int gcFlags;
		private int gcDelayTime;
		private int gcTransparentColor;

		// Whether the (render, extension) block is yet to be written.
		private boolean firstBlock = true;

		// Extension function label for the graphic control extension
		private static final int GRAPHIC_CONTROL_LABEL = 0xF9;
		// Extension function label for application extensions
		private static final int APPLICATION_LABEL = 0xFF;
		// Signatures for the Netscape 2.0 / AnimExts 1.0 extensions
		private static final byte[] NETSCAPE2_0_SIG = new byte[] {
			(byte)'N', (byte)'E', (byte)'T', (byte)'S', (byte)'C', (byte)'A', (byte)'P',
			(byte)'E', (byte)'2', (byte)'.', (byte)'0'
		};
		private static final byte[] ANIMEXTS1_0_SIG = new byte[] {
			(byte)'A', (byte)'N', (byte)'I', (byte)'M', (byte)'E', (byte)'X', (byte)'T',
			(byte)'S', (byte)'1', (byte)'.', (byte)'0'
		};

		private GIF89aValidator(InputStream input, OutputStream output) {
			super(input, output);
		}

		static void filter(InputStream input, OutputStream output)
				throws IOException, DataFilterException {
			new GIF89aValidator(input, output).filter();
		}

		@Override
		protected void filterExtensionBlock() throws IOException {
			int label = readByte();
			switch (label) {
				case GRAPHIC_CONTROL_LABEL:
					readGraphicControl();
					break;
				case APPLICATION_LABEL:
					filterApplicationBlock();
					break;
				default:
					skipSubBlocks();
			}
		}

		@Override
		protected void foundImageData(boolean success) throws IOException {
			if (success && hasGraphicControl) {
				writeGraphicControl();
			}
			// Graphic control only applies to the single following render block; we must drop
			// it when we encounter an invalid render block.
			hasGraphicControl = false;
			if (success) {
				firstBlock = false;
			}
		}

		/** Filters an application extension block; assuming its indicator and label are already
		  * read. Currently the only supported extension is the Loop Extension. */
		private void filterApplicationBlock() throws IOException {
			final int length = readByte();
			final byte[] signature = readBytes(length);
			final int remaining;
			if (Arrays.equals(signature, ANIMEXTS1_0_SIG) ||
					Arrays.equals(signature, NETSCAPE2_0_SIG)) {
				// Netscape 2.0 / AnimExts 1.0 extension.
				final int subLength = readByte();
				if (subLength == 3) {
					final int subID = readByte();
					final int loopCount = readShort();
					remaining = readByte();
					if (remaining == 0 && subID == 0x01 && firstBlock) {
						// Valid Loop Extension, and this is the first block.
						writeByte(EXTENSION_INTRODUCER);
						writeByte(APPLICATION_LABEL);
						writeByte(NETSCAPE2_0_SIG.length);
						writeBytes(NETSCAPE2_0_SIG);
						writeByte(subLength);
						writeByte(subID);
						writeShort(loopCount);
						writeByte(0);
						firstBlock = false;
					}
				} else {
					remaining = subLength;
				}
			} else {
				remaining = readByte();
			}
			if (remaining != 0) {
				skip(remaining);
				skipSubBlocks();
			}
		}

		/** Reads a graphic control block; assuming its indicator and label are already read. */
		private void readGraphicControl() throws IOException {
			if (hasGraphicControl) {
				// Graphic control may only appear once per render block.
				skipSubBlocks();
				return;
			}
			final int length = readByte();
			if (length != 4) {
				// Length must be 4.
				skip(length);
				skipSubBlocks();
				return;
			}
			gcFlags = readByte();
			gcDelayTime = readShort();
			gcTransparentColor = readByte();
			final int terminator = readByte();
			if (terminator != 0) {
				// There is more data: this should not happen. Skip the rest of the stream.
				skip(terminator);
				skipSubBlocks();
				return;
			}

			final int disposalMethod = (gcFlags & 0x1C) >>> 2;
			if (disposalMethod >= 4) {
				// Undefined disposal method.
				return;
			}

			hasGraphicControl = true;
		}

		/** Writes a complete graphic control block. */
		private void writeGraphicControl() throws IOException {
			writeByte(EXTENSION_INTRODUCER);
			writeByte(GRAPHIC_CONTROL_LABEL);
			writeByte(4);
			writeByte(gcFlags);
			writeShort(gcDelayTime);
			writeByte(gcTransparentColor);
			writeByte(0);
			firstBlock = false;
		}
	}

	private static String l10n(String key) {
		return NodeL10n.getBase().getString("GIFFilter."+key);
	}

	private static void throwDataError(String shortReason, String reason) throws DataFilterException {
		// Throw an exception
		String message = l10n("notGif");
		if (reason != null) {
			message += ' ' + reason;
		}
		if (shortReason != null) {
			message += " - (" + shortReason + ')';
		}
		throw new DataFilterException(shortReason, shortReason, message);
	}

}
