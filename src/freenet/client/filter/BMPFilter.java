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
import freenet.support.io.FileUtil;

/**
 * @author kurmiashish
 * This class would verify whether the BMP header is valid or not
 Reference:
 http://www.fastgraph.com/help/bmp_header_format.html
 http://en.wikipedia.org/wiki/BMP_file_format
 */
public class BMPFilter implements ContentDataFilter {


	static final byte[] bmpHeaderwindows =
	{ (byte)'B', (byte)'M'};

	static final byte[] bmpHeaderos2bArray =
	{ (byte)'B', (byte)'A'};

	static final byte[] bmpHeaderos2cIcon =
	{ (byte)'C', (byte)'I'};


	static final byte[] bmpHeaderos2cPointer =
	{ (byte)'C', (byte)'P'};


	static final byte[] bmpHeaderos2Icon =
	{ (byte)'I', (byte)'C'};


	static final byte[] bmpHeaderos2Pointer =
	{ (byte)'P', (byte)'T'};


	private int unsignedByte(byte b)
	{
		if (b >= 0)
			return b;
		else
			return 256+b;
	}


	public int readInt(DataInputStream dis) throws IOException
	{
		int result;
		byte[] data = new byte[4];

		result = dis.read(data);
		if (result < 0) // end of file reached
		throw new EOFException();

		result = (unsignedByte(data[2]) << 16) | (unsignedByte(data[1]) << 8) | unsignedByte(data[0]);
		result|=(unsignedByte(data[3]) << 24);

		return result;
	}


	public int readShort(DataInputStream dis) throws IOException
	{
		int result = dis.read();
		if (result < 0)// end of file reached
			throw new EOFException();

		int r2 = dis.read();
		if (r2 < 0)// end of file reached
			throw new EOFException();

		return result | (r2*256);
	}


	@Override
	public void readFilter(
      InputStream input, OutputStream output, String charset, HashMap<String, String> otherParams,
      String schemeHostAndPort, FilterCallback cb) throws DataFilterException, IOException {
		DataInputStream dis = new DataInputStream(input);
		dis.mark(54);
		byte[] StartWord = new byte[2];
		dis.readFully(StartWord);
		if((!Arrays.equals(StartWord, bmpHeaderwindows)) && (!Arrays.equals(StartWord, bmpHeaderos2bArray)) && (!Arrays.equals(StartWord, bmpHeaderos2cIcon)) && (!Arrays.equals(StartWord, bmpHeaderos2cPointer)) && (!Arrays.equals(StartWord, bmpHeaderos2Icon)) && (!Arrays.equals(StartWord, bmpHeaderos2Pointer))) {	//Checking the first word
			throwHeaderError(l10n("InvalidStartWordT"), l10n("InvalidStartWordD"));
		}

		int fileSize = readInt(dis); // read total file size
		byte[] skipbytes=new byte[4];
		dis.readFully(skipbytes);
		int headerSize = readInt(dis); // read file header size or pixel offset
		if(headerSize<0) {
			throwHeaderError(l10n("InvalidOffsetT"), l10n("InvalidOffsetD"));
		}

		int size_bitmapinfoheader=readInt(dis);
		if(size_bitmapinfoheader!=40) {
			throwHeaderError(l10n("InvalidBitMapInfoHeaderSizeT"), l10n("InvalidBitMapInfoHeaderSizeD"));
		}

		int imageWidth = readInt(dis); // read width
		int imageHeight = readInt(dis); // read height
		if(imageWidth<0 || imageHeight<0) {
			throwHeaderError(l10n("InvalidDimensionT"), l10n("InvalidDimensionD"));
		}

		int no_plane=readShort(dis);
		if(no_plane!=1) { // No of planes should be 1
			throwHeaderError(l10n("InvalidNoOfPlanesT"), l10n("InvalidNoOfPlanesD"));
		}

		int bitDepth = readShort(dis);
		// Bit depth should be 1,2,4,8,16 or 32.
		if(bitDepth!=1 && bitDepth!=2 && bitDepth!=4 && bitDepth!=8 && bitDepth!=16 && bitDepth!=24 && bitDepth!=32) {
			throwHeaderError(l10n("InvalidBitDepthT"), l10n("InvalidBitDepthD"));
		}

		int compression_type=readInt(dis);
		if( !(compression_type>=0 && compression_type<=3) ) {
			throwHeaderError(l10n("Invalid Compression type"), l10n("Compression type field is set to "+compression_type+" instead of 0-3"));
		}

		int imagedatasize=readInt(dis);
		if(fileSize!=headerSize+imagedatasize) {
			throwHeaderError(l10n("InvalidFileSizeT"), l10n("InvalidFileSizeD"));
		}

		int horizontal_resolution=readInt(dis);
		int vertical_resolution=readInt(dis);
		if(horizontal_resolution<0 || vertical_resolution<0) {
			throwHeaderError(l10n("InvalidResolutionT"), l10n("InvalidResolutionD"));
		}

		if(compression_type==0) {
			// Verifying the file size w.r.t. image dimensions(width and height), bitDepth with imagedatasize(including padding).
			int bitsPerLine = imageWidth * bitDepth;

			//Lines are padded to a 4 byte boundary
			if(bitsPerLine % 32 != 0) {
				bitsPerLine += 32 - bitsPerLine % 32;
			}

			int bytesPerLine = bitsPerLine / 8;
			int calculatedsize = bytesPerLine * imageHeight;
			if(calculatedsize!=imagedatasize) {
				throwHeaderError(l10n("InvalidImageDataSizeT"), l10n("InvalidImageDataSizeD" ));
			}
		}
		dis.reset();

		FileUtil.copy(dis, output, -1);
		output.flush();
	}

	private static String l10n(String key) {
		return NodeL10n.getBase().getString("BMPFilter."+key);
	}

	private void throwHeaderError(String shortReason, String reason) throws DataFilterException {
		// Throw an exception
		String message = l10n("notBMP");
		if(reason != null) message += ' ' + reason;
		if(shortReason != null)
			message += " - (" + shortReason + ')';
		throw new DataFilterException(shortReason, shortReason, message);
	}

}
