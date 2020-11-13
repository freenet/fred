/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.filter;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.util.HashMap;

import freenet.support.HexUtil;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.io.Closer;
import freenet.support.io.NullWriter;

public class CSSReadFilter implements ContentDataFilter, CharsetExtractor {

        private static volatile boolean logDEBUG;
        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
                                logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	@Override
	public void readFilter(
      InputStream input, OutputStream output, String charset, HashMap<String, String> otherParams,
      String schemeHostAndPort, FilterCallback cb) throws DataFilterException, IOException {
		if (logDEBUG)
			Logger.debug(
				this,
				"running "
					+ this
					+ "with charset"+charset);
		Reader r = null;
		Writer w = null;
		try {
			try {
				InputStreamReader isr = new InputStreamReader(input, charset);
				OutputStreamWriter osw = new OutputStreamWriter(output, charset);
				r = new BufferedReader(isr, 32768);
				w = new BufferedWriter(osw, 32768);

			} catch(UnsupportedEncodingException e) {
				throw UnknownCharsetException.create(e, charset);
			}
			CSSParser parser = new CSSParser(r, w, false, cb, charset, false, false);
			parser.parse();
		}
		finally {
			w.flush();
		}

	}

	@Override
	public String getCharset(byte [] input, int length, String charset) throws DataFilterException, IOException {
		if(logDEBUG)
			Logger.debug(this, "Fetching charset for CSS with initial charset "+charset);
		if(input.length > getCharsetBufferSize() && logMINOR) {
			Logger.minor(this, "More data than was strictly needed was passed to the charset extractor for extraction");
		}
		InputStream strm = new ByteArrayInputStream(input, 0, length);
		NullWriter w = new NullWriter();
		InputStreamReader isr;
		BufferedReader r = null;
		try {
			try {
				isr = new InputStreamReader(strm, charset);
				r = new BufferedReader(isr, 32768);
			} catch(UnsupportedEncodingException e) {
				throw UnknownCharsetException.create(e, charset);
			}
			CSSParser parser = new CSSParser(r, w, false, new NullFilterCallback(), null, true, false);
			parser.parse();
			r.close();
			r = null;
			return parser.detectedCharset();
		}
		finally {
			Closer.close(strm);
			Closer.close(r);
			Closer.close(w);
		}
	}

	// CSS 2.1 section 4.4.
	// In all cases these will be confirmed by calling getCharset().
	// We do not use all of the BOMs suggested.
	// Also, we do not use true BOMs.

	// We do check for ascii, even though it's the first one to check for anyway, because of the "as specified" rule: if it starts with @charset in ascii, it MUST have a valid charset, or we ignore the whole sheet, as per the spec.
	static final byte[] ascii = parse("40 63 68 61 72 73 65 74 20 22");
	static final byte[] utf16be = parse("00 40 00 63 00 68 00 61 00 72 00 73 00 65 00 74 00 20 00 22");
	static final byte[] utf16le = parse("40 00 63 00 68 00 61 00 72 00 73 00 65 00 74 00 20 00 22 00");
	static final byte[] utf32_le = parse("40 00 00 00 63 00 00 00 68 00 00 00 61 00 00 00 72 00 00 00 73 00 00 00 65 00 00 00 74 00 00 00 20 00 00 00 22 00 00 00");
	static final byte[] utf32_be = parse("00 00 00 40 00 00 00 63 00 00 00 68 00 00 00 61 00 00 00 72 00 00 00 73 00 00 00 65 00 00 00 74 00 00 00 20 00 00 00 22");
	static final byte[] ebcdic = parse("7C 83 88 81 99 A2 85 A3 40 7F");
	static final byte[] ibm1026 = parse("AE 83 88 81 99 A2 85 A3 40 FC");

	// Not supported.
	static final byte[] utf32_2143 = parse("00 00 40 00 00 00 63 00 00 00 68 00 00 00 61 00 00 00 72 00 00 00 73 00 00 00 65 00 00 00 74 00 00 00 20 00 00 00 22 00");
	static final byte[] utf32_3412 = parse("00 40 00 00 00 63 00 00 00 68 00 00 00 61 00 00 00 72 00 00 00 73 00 00 00 65 00 00 00 74 00 00 00 20 00 00 00 22 00 00");
	static final byte[] gsm = parse("00 63 68 61 72 73 65 74 20 22");

	static final int maxBOMLength = Math.max(utf16be.length, Math.max(utf16le.length, Math.max(utf32_le.length, Math.max(utf32_be.length, Math.max(ebcdic.length, Math.max(ibm1026.length, Math.max(utf32_2143.length, Math.max(utf32_3412.length, gsm.length))))))));

	static byte[] parse(String s) {
		s = s.replaceAll(" ", "");
		return HexUtil.hexToBytes(s);
	}

	@Override
	public BOMDetection getCharsetByBOM(byte[] input, int length) throws DataFilterException, IOException {
		if(ContentFilter.startsWith(input, ascii, length))
			return new BOMDetection("UTF-8", true);
		if(ContentFilter.startsWith(input, utf16be, length))
			return new BOMDetection("UTF-16BE", true);
		if(ContentFilter.startsWith(input, utf16le, length))
			return new BOMDetection("UTF-16LE", true);
		if(ContentFilter.startsWith(input, utf32_be, length))
			return new BOMDetection("UTF-32BE", true);
		if(ContentFilter.startsWith(input, utf32_le, length))
			return new BOMDetection("UTF-32LE", true);
		if(ContentFilter.startsWith(input, ebcdic, length))
			return new BOMDetection("IBM01140", true);
		if(ContentFilter.startsWith(input, ibm1026, length))
			return new BOMDetection("IBM1026", true);

		// Unsupported BOMs

		if(ContentFilter.startsWith(input, utf32_2143, length))
			throw new UnsupportedCharsetInFilterException("UTF-32-2143");
		if(ContentFilter.startsWith(input, utf32_3412, length))
			throw new UnsupportedCharsetInFilterException("UTF-32-3412");
		if(ContentFilter.startsWith(input, gsm, length))
			throw new UnsupportedCharsetInFilterException("GSM 03.38");
		return null;
	}

	public static String filterMediaList(String media) {
		String[] split = media.split(",");
		boolean first = true;
		StringBuffer sb = new StringBuffer();
		for(String m : split) {
			m = m.trim();
			int i;
			for(i=0;i<m.length();i++) {
				char c = m.charAt(i);
				if(!('a' <= c && 'z' >= c) || ('A' <= c && 'Z' >= c) || ('0' <= c && '9' >= c) || c == '-')
					break;
			}
			m = m.substring(0, i);
			if(FilterUtils.isMedia(m)) {
				if(!first) sb.append(", ");
				sb.append(m);
				first = false;
			}
		}
		if(sb.length() != 0) return sb.toString();
		else return null;
	}

	@Override
	public int getCharsetBufferSize() {
		return 64; //This should be a reasonable number of bytes to read in
	}

}
