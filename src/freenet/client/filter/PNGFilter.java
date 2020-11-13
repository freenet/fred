/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.filter;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.zip.CRC32;

import freenet.l10n.NodeL10n;
import freenet.support.HexUtil;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;
import freenet.support.io.Closer;
import freenet.support.io.FileBucket;

/**
 * Content filter for PNG's. Only allows valid chunks (valid CRC, known chunk type).
 *
 * It can strip the timestamp and "text(.)*" chunks if asked to
 *
 * FIXME: validate chunk contents where possible.
 */
public class PNGFilter implements ContentDataFilter {

	private final boolean deleteText;
	private final boolean deleteTimestamp;
	private final boolean checkCRCs;
	static final byte[] pngHeader = { (byte) 137, (byte) 80, (byte) 78, (byte) 71, (byte) 13, (byte) 10, (byte) 26,
	        (byte) 10 };
	static final String[] HARMLESS_CHUNK_TYPES = {
	// http://www.w3.org/TR/PNG/
	        "tRNS", "cHRM", "gAMA", "iCCP", // FIXME Embedded ICC profile: could this conceivably cause a web lookup?
	        "sBIT", // FIXME rather obscure ??
	        "sRGB", "bKGD", "hIST", "pHYs", "sPLT",
	        // APNG chunks (Firefox 3 will support APNG)
	        // http://wiki.mozilla.org/APNG_Specification
	        "acTL", "fcTL", "fdAT"
	// MNG isn't supported by Firefox and IE because of lack of market demand. Big surprise
	// given nobody supports it! It is supported by Konqueror though. Complex standard,
	// not worth it for the time being.

	// This might be a useful source of info too (e.g. on private chunks):
	// http://fresh.t-systems-sfr.com/unix/privat/pngcheck-2.3.0.tar.gz:a/pngcheck-2.3.0/pngcheck.c
	};

        private static volatile boolean logMINOR;
        private static volatile boolean logDEBUG;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
                                logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}

	PNGFilter(boolean deleteText, boolean deleteTimestamp, boolean checkCRCs) {
		this.deleteText = deleteText;
		this.deleteTimestamp = deleteTimestamp;
		this.checkCRCs = checkCRCs;
	}

	@Override
	public void readFilter(
			InputStream input, OutputStream output, String charset, HashMap<String, String> otherParams,
			String schemeHostAndPort, FilterCallback cb) throws DataFilterException, IOException {
		readFilter(input, output, charset, otherParams, cb, deleteText, deleteTimestamp, checkCRCs);
		output.flush();
	}

	public void readFilter(InputStream input, OutputStream output, String charset, HashMap<String, String> otherParams,
			FilterCallback cb, boolean deleteText, boolean deleteTimestamp, boolean checkCRCs)
			throws DataFilterException, IOException {
		DataInputStream dis = null;
		boolean hasSeenIHDR = false;
		boolean hasSeenIEND = false;
		boolean hasSeenIDAT = false;
		try {
                        long offset = 0;
			dis = new DataInputStream(input);
			// Check the header
			byte[] headerCheck = new byte[pngHeader.length];
			dis.readFully(headerCheck);
                        offset+=pngHeader.length;
			if (!Arrays.equals(headerCheck, pngHeader)) {
				// Throw an exception
				String message = l10n("invalidHeader");
				String title = l10n("invalidHeaderTitle");
				throw new DataFilterException(title, title, message);
			}

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DataOutputStream dos = new DataOutputStream(baos);
			output.write(pngHeader);
			if (logMINOR)
				Logger.minor(this, "Writing the PNG header to the output bucket");

			// Check the chunks :
			// @see http://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html#C.Summary-of-standard-chunks
			String lastChunkType = "";

			while (!hasSeenIEND) {
				boolean skip = false;
				baos.reset();
				String chunkTypeString = null;
				// Length of the chunk
				byte[] lengthBytes = new byte[4];
				try {
					dis.readFully(lengthBytes);
					offset+=4;
				} catch (EOFException e) {
					// FIXME optimise out the throw, don't use readFully?
					// This will happen once per filtering.
					// We can't use available() for reasons explained in
					// the javadocs for ContentDataFilter.
					break;
				}

				int length = ((lengthBytes[0] & 0xff) << 24) + ((lengthBytes[1] & 0xff) << 16)
				        + ((lengthBytes[2] & 0xff) << 8) + (lengthBytes[3] & 0xff);
				if (logMINOR)
					Logger.minor(this, "length " + length+ "(offset=0x"+Long.toHexString(offset)+") ");
				if (dos != null)
					dos.write(lengthBytes);

				// Type of the chunk : Should match [a-zA-Z]{4}
				dis.readFully(lengthBytes);
                                offset+=4;
				StringBuilder sb = new StringBuilder();
				byte[] chunkTypeBytes = new byte[4];
				for (int i = 0; i < 4; i++) {
					char val = (char) lengthBytes[i];
					if ((val >= 65 && val <= 99) || (val >= 97 && val <= 122)) {
						chunkTypeBytes[i] = lengthBytes[i];
						sb.append(val);
					} else {
						String chunkName = HexUtil.bytesToHex(lengthBytes, 0, 4);
						throwError("Unknown Chunk", "The name of the chunk is invalid! (" + chunkName + ")");
					}
				}
				chunkTypeString = sb.toString();
				if (logMINOR)
					Logger.minor(this, "name " + chunkTypeString);
				if (dos != null)
					dos.write(chunkTypeBytes);

				// Content of the chunk
				byte[] chunkData = new byte[length];
				if(length > 0) {
					dis.readFully(chunkData, 0, length);
					offset+=length;
					if (logMINOR)
						if (logDEBUG)
							Logger.minor(this, "data (offset=0x"+Long.toHexString(offset)+") "+ (chunkData.length == 0 ? "null" : HexUtil.bytesToHex(chunkData)));
						else
							Logger.minor(this, "data " + chunkData.length);
					if (dos != null)
						dos.write(chunkData);
				}

				// CRC of the chunk
				byte[] crcLengthBytes = new byte[4];
				dis.readFully(crcLengthBytes);
				offset+=4;
				if(logMINOR) Logger.minor(this, "CRC offset=0x"+Long.toHexString(offset));
				if (dos != null)
					dos.write(crcLengthBytes);

				if (checkCRCs) {
					long readCRC = (((crcLengthBytes[0] & 0xff) << 24) + ((crcLengthBytes[1] & 0xff) << 16)
					        + ((crcLengthBytes[2] & 0xff) << 8) + (crcLengthBytes[3] & 0xff)) & 0x00000000ffffffffL;
					CRC32 crc = new CRC32();
					crc.update(chunkTypeBytes);
					if(length > 0)
                                            crc.update(chunkData);
					long computedCRC = crc.getValue();

					if (readCRC != computedCRC) {
						skip = true;
						if (logMINOR)
							Logger.minor(this, "CRC of the chunk " + chunkTypeString + " doesn't match ("
							        + Long.toHexString(readCRC) + " but should be " + Long.toHexString(computedCRC)
							        + ")!");
					}
				}

				boolean validChunkType = false;

				if (!skip && "IHDR".equals(chunkTypeString)) { // http://www.w3.org/TR/PNG/#11IHDR
					if (hasSeenIHDR)
						throwError("Duplicate IHDR", "Two IHDR chunks detected!!");
					if(length != 13)
						throwError("IHDR length!= 13", "The length of the IHDR file is not 13");
					long width = ((chunkData[0] & 0xff) << 24) + ((chunkData[1] & 0xff) << 16) + ((chunkData[2] & 0xff) << 8) + (chunkData[3] & 0xff);
					long height = ((chunkData[4] & 0xff) << 24) + ((chunkData[5] & 0xff) << 16) + ((chunkData[6] & 0xff) << 8) + (chunkData[7] & 0xff);
					if(width < 1 || height < 1)
						throwError("Width or Height is invalid", "Width or Height is invalid (<1)");
					int bitDepth = chunkData[8];
					int colourType = chunkData[9];
					throwOnInvalidColour(bitDepth, colourType);
					int compressionMethod = chunkData[10];
					if(compressionMethod != 0)
						throwError("Invalid CompressionMethod", "Invalid CompressionMethod! "+compressionMethod);
					int filterMethod = chunkData[11];
					if(filterMethod != 0)
						throwError("Invalid FilterMethod", "Invalid FilterMethod! "+filterMethod);
					int interlaceMethod = chunkData[12];
					if(interlaceMethod < 0 || interlaceMethod >1)
						throwError("Invalid InterlaceMethod", "Invalid InterlaceMethod! "+interlaceMethod);

					if(logMINOR)
						Logger.minor(this, "Info from IHDR: width="+width+"px height="+height+"px bitDepth="+bitDepth+
								" colourType="+colourType+" compressionMethod="+compressionMethod+" filterMethod="+
								filterMethod+" interlaceMethod="+interlaceMethod);
					hasSeenIHDR = true;
					validChunkType = true;
				}

				if (!hasSeenIHDR)
					throwError("No IHDR chunk!", "No IHDR chunk!");

				if (!skip && "IEND".equals(chunkTypeString)) {
					if (hasSeenIEND)
						throwError("Two IEND chunks detected!!", "Two IEND chunks detected!!");
					hasSeenIEND = true;
					validChunkType = true;
				}

				if (!skip && "PLTE".equalsIgnoreCase(chunkTypeString)) {
					if (hasSeenIDAT)
						throwError("PLTE must be before IDAT", "PLTE must be before IDAT");
					validChunkType = true;
				}

				if (!skip && "IDAT".equalsIgnoreCase(chunkTypeString)) {
					if (hasSeenIDAT && !"IDAT".equalsIgnoreCase(lastChunkType))
						throwError("Multiple IDAT chunks must be consecutive!",
						        "Multiple IDAT chunks must be consecutive!");
					hasSeenIDAT = true;
					validChunkType = true;
				}

				if (!validChunkType) {
					for (int i = 0; i < HARMLESS_CHUNK_TYPES.length; i++) {
						if (HARMLESS_CHUNK_TYPES[i].equals(chunkTypeString))
							validChunkType = true;
					}
				}

				if ("text".equalsIgnoreCase(chunkTypeString) || "itxt".equalsIgnoreCase(chunkTypeString)
				        || "ztxt".equalsIgnoreCase(chunkTypeString)) {
					if (deleteText)
						skip = true;
					else
						validChunkType = true;
				} else if (deleteTimestamp && "time".equalsIgnoreCase(chunkTypeString)) {
					if (deleteTimestamp)
						skip = true;
					else
						validChunkType = true;
				}

				if (!validChunkType) {
					if (logMINOR)
						Logger.minor(this, "Skipping unknown chunk type " + chunkTypeString);
					skip = true;
				}

				else if (!skip && output != null) {
					if (logMINOR)
						Logger
						        .minor(this, "Writing " + chunkTypeString + " (" + baos.size()
						                + ") to the output bucket");
					baos.writeTo(output);
					baos.flush();
				}
				lastChunkType = chunkTypeString;
			}

			if (!hasSeenIEND)
				throwError("Missing IEND", "Missing IEND");
			if (!hasSeenIHDR)
				throwError("Missing IHDR", "Missing IHDR");
			return; // Strip everything after IEND.
		} catch (ArrayIndexOutOfBoundsException e) {
			throwError("ArrayIndexOutOfBoundsException while filtering", "ArrayIndexOutOfBoundsException while filtering");
		} catch (NegativeArraySizeException e) {
			throwError("NegativeArraySizeException while filtering", "NegativeArraySizeException while filtering");
		} catch (EOFException e) {
			if(hasSeenIEND && hasSeenIHDR) return;
			throwError("EOF Exception while filtering", "EOF Exception while filtering");
		}
	}

	@SuppressWarnings("fallthrough")
	private void throwOnInvalidColour(int bitDepth, int colourType) throws DataFilterException {
		switch (bitDepth) {
			case 1:
			case 2:
			case 4:
				if(colourType != 0 && colourType != 3)
					throwError("Invalid colourType/bitDepth combination!",
							"Invalid colourType/bitDepth combination! ("+colourType+'|'+bitDepth+')');
				break;
			case 16:
				if(colourType == 3)
					throwError("Invalid colourType/bitDepth combination!",
							"Invalid colourType/bitDepth combination! ("+colourType+'|'+bitDepth+')');
			case 8:
				if(colourType == 0 || colourType ==2 || colourType ==3 || colourType ==4|| colourType ==6)
					break;
			default: throwError("Invalid colourType/bitDepth combination!",
					"Invalid colourType/bitDepth combination! ("+colourType+'|'+bitDepth+')');
		}
	}

	private String l10n(String key) {
		return NodeL10n.getBase().getString("PNGFilter." + key);
	}

	public static void main(String arg[]) throws Throwable {
		final File fin = new File("/tmp/test.png");
		final File fout = new File("/tmp/test2.png");
		fout.delete();
		final Bucket inputBucket = new FileBucket(fin, true, false, false, false);
		final Bucket outputBucket = new FileBucket(fout, false, true, false, false);
		InputStream inputStream = null;
		OutputStream outputStream = null;
		try {
			inputStream = inputBucket.getInputStream();
			outputStream = outputBucket.getOutputStream();
			Logger.setupStdoutLogging(LogLevel.MINOR, "");

			ContentFilter.filter(inputStream, outputStream, "image/png",
					new URI("http://127.0.0.1:8888/"), null, null, null, null);
		} finally {
			Closer.close(inputStream);
			Closer.close(outputStream);
			inputBucket.free();
			outputBucket.free();
		}
	}

	private void throwError(String shortReason, String reason) throws DataFilterException {
		// Throw an exception
		String message = "Invalid PNG";
		if (reason != null)
			message += ' ' + reason;
		if (shortReason != null)
			message += " - " + shortReason;
		DataFilterException e = new DataFilterException(shortReason, shortReason, message);
		Logger.normal(this, "Throwing " + e.getMessage(), e);
		throw e;
	}
}
