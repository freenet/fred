package freenet.client.filter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;

import freenet.l10n.NodeL10n;
import freenet.support.Logger;

public class MP3Filter implements ContentDataFilter {

	// Various sources on the Internet.
	// The most comprehensive one appears to be:
	// http://mpgedit.org/mpgedit/mpeg_format/mpeghdr.htm
	// Others:
	// http://www.mp3-tech.org/programmer/frame_header.html
	// http://www.codeproject.com/KB/audio-video/mpegaudioinfo.aspx
	// http://www.id3.org/mp3Frame
	// http://www.mp3-converter.com/mp3codec/

	static final short[] [] [] bitRateIndices = {
		//Version 2.5
		{
			{},
			{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160},
			{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160},
			{0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256}
		},
		//Reserved
		{
		},
		//Version 2.0
		{
			{},
			{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160},
			{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160},
			{0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256}
		},
		//Version 1
		{
			{},
			{0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320},
			{0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384},
			{0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448}
		}
	};

	static final int[] [] sampleRateIndices = {
		//Version 2.5
		{11025, 12000, 8000},
		//Reserved
		{},
		//Version 2.0
		{22050, 24000, 16000},
		//Version 1
		{44100, 48000, 32000}
	};

	// Samples per frame for each [version][layer]
	static final int[][] samplesPerFrame = {
		// Version 2.5
		{ 0, 576, 1152, 384 },
		// Reserved
		{},
		// Version 2
		{ 0, 576, 1152, 384 },
		// Version 1
		{ 0, 1152, 1152, 384 }
	};

	// Bits per slot for each layer
	static final int[] bitsPerSlot = {
		// Reserved
		0,
		// Layer III
		8,
		// Layer II
		8,
		// Layer I
		32
	};

	@Override
	public void readFilter(
      InputStream input, OutputStream output,
      String charset, HashMap<String, String> otherParams,
      String schemeHostAndPort, FilterCallback cb) throws DataFilterException, IOException {
		filter(input, output);
	}

	public void filter(InputStream input, OutputStream output) throws DataFilterException, IOException {
		//FIXME: Add support for free formatted files(highly uncommon)
		DataInputStream in = new DataInputStream(input);
		DataOutputStream out = new DataOutputStream(output);
		boolean foundStream = true;
		int totalFrames = 0;
		int totalCRCs = 0;
		int foundFrames = 0;
		int maxFoundFrames = 0;
		long countLostSyncBytes = 0;
		int countFreeBitrate = 0;
		try {
		int frameHeader = in.readInt();
		foundStream = (frameHeader & 0xffe00000) == 0xffe00000;
		// Seek ahead until we find the Frame sync
		while (true) {
			if (foundStream && (frameHeader & 0xffe00000) == 0xffe00000) {
				// Populate header details
				final byte version = (byte) ((frameHeader & 0x00180000) >>> 19); //2 bits
				if (version == 1) {
					foundStream = false;
					continue; // Not valid
				}
				final byte layer = (byte) ((frameHeader & 0x00060000) >>> 17); //2 bits
				if (layer == 0) {
					foundStream = false;
					continue; // Not valid
				}
				// WARNING: layer is encoded! 1 = layer 3, 2 = layer 2, 3 = layer 1!
				final boolean hasCRC = ((frameHeader & 0x00010000) >>> 16) != 1; //1 bit, but inverted
				final byte bitrateIndex = (byte) ((frameHeader & 0x0000f000) >>> 12); //4 bits
				if (bitrateIndex == 0) {
					// FIXME It looks like it would be very hard to support free bitrate.
					// Unfortunately, this is used occasionally e.g. on the chaosradio mp3's.
					foundStream = false;
					countFreeBitrate++;
					continue; // Not valid
				}
				if (bitrateIndex == 15) {
					foundStream = false;
					continue; // Not valid
				}
				final byte samplerateIndex = (byte) ((frameHeader & 0x00000c00) >>> 10); //2 bits
				if (samplerateIndex == 3) {
					foundStream = false;
					continue; // Not valid
				}
				final boolean paddingBit = ((frameHeader & 0x00000200) >>> 9) == 1;
				// We skip the following bits here (listed for future reference):
				// Private         0x00000100  (1 bit)
				// Channel mode    0x000000c0  (2 bits)
				// Mode extension  0x00000030  (2 bits)
				// Copyright       0x00000008  (1 bit)
				// Original        0x00000004  (1 bit)
				// FIXME A small boost in security might be gained by clearing the latter two.
				byte emphasis = (byte) ((frameHeader & 0x00000003));
				if (emphasis == 2) {
					foundStream = false;
					continue; // Not valid
				}

				// Generate other values from tables
				final int bitrate = bitRateIndices[version][layer][bitrateIndex] * 1000;
				final int samplerate = sampleRateIndices[version][samplerateIndex];
				final int samples = samplesPerFrame[version][layer];
				final int granularity = bitsPerSlot[layer];
				int frameLength = samples / granularity * bitrate / samplerate;
				frameLength += paddingBit ? 1 : 0;
				frameLength *= granularity / 8;

				short crc = 0;
				if (hasCRC) {
					totalCRCs++;
					crc = in.readShort();
					Logger.normal(this, "Found a CRC");
					// FIXME calculate the CRC. It applies to a large number of frames, dependant on the format.
				}
				// Write out the frame
				byte[] frame = null;
				frame = new byte[frameLength-4];
				in.readFully(frame);
				out.writeInt(frameHeader);
				// FIXME CRCs may or may not work. I have not been able to find an mp3 file with CRCs but without free bitrate.
				if (hasCRC)
					out.writeShort(crc);
				out.write(frame);
				totalFrames++;
				foundFrames++;
				if (countLostSyncBytes != 0)
					Logger.normal(this, "Lost sync for "+countLostSyncBytes+" bytes");
				countLostSyncBytes = 0;
				frameHeader = in.readInt();
			} else if (!foundStream && (frameHeader & 0xffffff00) == 0x49443300) {
				// This is an ID3v2 header, see http://id3.org/id3v2.3.0#ID3v2_header
				// Skip minor version, flags
				in.skip(2);
				// ID3 tag size
				byte[] encodedSize = new byte[4];
				in.readFully(encodedSize);
				int size = 0;
				size |= (encodedSize[0] & 0x7F) << 21;
				size |= (encodedSize[1] & 0x7F) << 14;
				size |= (encodedSize[2] & 0x7F) << 7;
				size |= (encodedSize[3] & 0x7F);
				in.skip(size);
				Logger.normal(this, "Skipped " + size + " bytes of ID3v2 data");
				frameHeader = in.readInt();
				foundStream = (frameHeader & 0xffe00000) == 0xffe00000;
			} else if (!foundStream && (frameHeader & 0xffffff00) == 0x54414700) {
				// This is an ID3v1 header
				// ID3v1 is of fixed length (128 bytes), from which we have already read the first 4
				in.skip(124);
				Logger.normal(this, "Skipped an ID3v1 TAG");
				frameHeader = in.readInt();
				foundStream = (frameHeader & 0xffe00000) == 0xffe00000;
			} else {
				if(foundFrames != 0)
					Logger.normal(this, "Series of frames: "+foundFrames);
				if(foundFrames > maxFoundFrames) maxFoundFrames = foundFrames;
				foundFrames = 0;
				frameHeader = frameHeader << 8;
				frameHeader |= (in.readUnsignedByte());
				if((frameHeader & 0xffe00000) == 0xffe00000) {
					foundStream = true;
				} else {
					countLostSyncBytes++;
				}
			}

		}
		} catch (EOFException e) {
			if(foundFrames != 0)
				Logger.normal(this, "Series of frames: "+foundFrames);
			if(countLostSyncBytes != 0)
				Logger.normal(this, "Lost sync for "+countLostSyncBytes+" bytes");
			if(totalFrames == 0 || maxFoundFrames < 10) {
				if(countFreeBitrate > 100)
					throw new DataFilterException(l10n("freeBitrateNotSupported"), l10n("freeBitrateNotSupported"), l10n("freeBitrateNotSupportedExplanation"));
				if(totalFrames == 0)
					throw new DataFilterException(l10n("bogusMP3NoFrames"), l10n("bogusMP3NoFrames"), l10n("bogusMP3NoFramesExplanation"));
			}

			out.flush();
			Logger.normal(this, totalFrames+" frames, of which "+totalCRCs+" had a CRC");
			return;
		}
	}

	private String l10n(String key) {
		return NodeL10n.getBase().getString("MP3Filter."+key);
	}

	public static void main(String[] args) throws DataFilterException, IOException {
		File f = new File(args[0]);
		FileInputStream fis = new FileInputStream(f);
		File out = new File(args[0]+".filtered.mp3");
		FileOutputStream fos = new FileOutputStream(out);
		MP3Filter filter = new MP3Filter();
//		// Skip some bytes for testing resyncing.
//		byte[] buf = new byte[4096];
//		fis.read(buf);
//		fis.read(buf);
//		fis.read(buf);
//		fis.read(buf);
		filter.readFilter(fis, fos, null, null, null, null);
		fis.close();
		fos.close();
	}

}
