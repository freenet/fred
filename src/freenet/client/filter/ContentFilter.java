/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.filter;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedHashMap;

import freenet.client.filter.CharsetExtractor.BOMDetection;
import freenet.l10n.NodeL10n;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.io.FileUtil;

/**
 * Freenet content filter. This doesn't actually do any filtering,
 * it organizes everything and maintains the database.
 */
public class ContentFilter {

	static final Hashtable<String, FilterMIMEType> mimeTypesByName = new Hashtable<String, FilterMIMEType>();
	
	/** The HTML mime types are defined here, to allow other modules to identify it*/
	public static final String[] HTML_MIME_TYPES=new String[]{"text/html", "application/xhtml+xml", "text/xml+xhtml", "text/xhtml", "application/xhtml"};
	
        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	static {
		init();
	}
	
	public static void init() {
		// Register known MIME types
		
		// Plain text
		register(new FilterMIMEType("text/plain", "txt", new String[0], new String[] { "text", "pot" },
				true, true, null, false, false, false, false, false, false,
				l10n("textPlainReadAdvice"),
				true, "US-ASCII", null, false));
		
		// GIF - has a filter 
		register(new FilterMIMEType("image/gif", "gif", new String[0], new String[0], 
				true, false, new GIFFilter(), false, false, false, false, false, false,
				l10n("imageGifReadAdvice"),
				false, null, null, false));
		
		// JPEG - has a filter
		register(new FilterMIMEType("image/jpeg", "jpeg", new String[0], new String[] { "jpg" },
				true, false, new JPEGFilter(true, true), false, false, false, false, false, false,
				l10n("imageJpegReadAdvice"),
				false, null, null, false));
		
		// PNG - has a filter
		register(new FilterMIMEType("image/png", "png", new String[] { "image/x-png" }, new String[0],
				true, false, new PNGFilter(true, true, true), false, false, false, false, true, false,
				l10n("imagePngReadAdvice"),
				false, null, null, false));


		// BMP - has a filter
		// Reference: http://filext.com/file-extension/BMP
		register(new FilterMIMEType("image/bmp", "bmp", new String[] { "image/x-bmp","image/x-bitmap","image/x-xbitmap","image/x-win-bitmap","image/x-windows-bmp","image/ms-bmp","image/x-ms-bmp","application/bmp","application/x-bmp","application/x-win-bitmap"  }, new String[0],
				true, false, new BMPFilter(), false, false, false, false, true, false,
				l10n("imageBMPReadAdvice"),
				false, null, null, false));	


		/* MP3
		 *
		 * Reference: http://www.mp3-tech.org/programmer/frame_header.html
		 */
		register(new FilterMIMEType("audio/mpeg", "mp3", new String[] {"audio/mp3", "audio/x-mp3", "audio/x-mpeg", "audio/mpeg3", "audio/x-mpeg3", "audio/mpg", "audio/x-mpg", "audio/mpegaudio"},
				new String[0], true, false, new MP3Filter(), true, true, false, true, false, false,
				l10n("audioMP3ReadAdvice"), false, null, null, false));

		// ICO needs filtering.
		// Format is not the same as BMP iirc.
		// DoS: http://www.kb.cert.org/vuls/id/290961
		// Remote code exec: http://www.microsoft.com/technet/security/bulletin/ms09-062.mspx
		
//		// ICO - probably safe - FIXME check this out, write filters
//		register(new FilterMIMEType("image/x-icon", "ico", new String[] { "image/vnd.microsoft.icon", "image/ico", "application/ico"}, 
//				new String[0], true, false, null, null, false, false, false, false, false, false,
//				l10n("imageIcoReadAdvice"),
//				false, null, null, false));
		
		// PDF - very dangerous - FIXME ideally we would have a filter, this is such a common format...
		register(new FilterMIMEType("application/pdf", "pdf", new String[] { "application/x-pdf" }, new String[0],
				false, false, null, true, true, true, false, true, true,
				l10n("applicationPdfReadAdvice"),
				false, null, null, false));
		
		// HTML - dangerous if not filtered
		register(new FilterMIMEType(HTML_MIME_TYPES[0], "html", Arrays.asList(HTML_MIME_TYPES).subList(1, HTML_MIME_TYPES.length).toArray(new String[HTML_MIME_TYPES.length-1]), new String[] { "htm" },
				false, false /* maybe? */, new HTMLFilter(),
				true, true, true, true, true, true, 
				l10n("textHtmlReadAdvice"),
				true, "iso-8859-1", new HTMLFilter(), false));
		
		// CSS - danagerous if not filtered, not sure about the filter
		register(new FilterMIMEType("text/css", "css", new String[0], new String[0],
				false, false /* unknown */, new CSSReadFilter(),
				true, true, true, true, true, false,
				l10n("textCssReadAdvice"),
				true, "utf-8", new CSSReadFilter(), true));
		
	}
	
	private static String l10n(String key) {
		return NodeL10n.getBase().getString("ContentFilter."+key);
	}

	public static void register(FilterMIMEType mimeType) {
		synchronized(mimeTypesByName) {
			mimeTypesByName.put(mimeType.primaryMimeType, mimeType);
			String[] alt = mimeType.alternateMimeTypes;
			if(alt != null) {
				for(String a: alt)
					mimeTypesByName.put(a, mimeType);
			}
		}
	}

	public static String stripMIMEType(String mimeType) {
		if(mimeType == null) return null;
		int x; 
		if((x=mimeType.indexOf(';')) != -1) {
			mimeType = mimeType.substring(0, x).trim();
		}
		return mimeType;
	}
	
	public static FilterMIMEType getMIMEType(String mimeType) {
		if(mimeType == null) return null;
		return mimeTypesByName.get(stripMIMEType(mimeType));
	}

	/**
	 * Filter some data.
	 * 
	 * @param input
	 *            Source stream to read data from
	 * @param output
	 *            Stream to write filtered data to
	 * @param typeName
	 *            MIME type for input data
	 * @param maybeCharset 
	 * 			  MIME type of the referring document, as a hint, some types,
	 * 			  such as CSS, will inherit it if no other data is available.
	 * @return 
	 * @throws IOException
	 *             If an internal error involving s occurred.
	 * @throws UnsafeContentTypeException
	 *             If the MIME type is declared unsafe (e.g. pdf files)
	 * @throws IllegalStateException
	 *             If data is invalid (e.g. corrupted file) and the filter have no way to recover.
	 */
	public static FilterStatus filter(InputStream input, OutputStream output, String typeName, URI baseURI, FoundURICallback cb, TagReplacerCallback trc , String maybeCharset) throws UnsafeContentTypeException, IOException {
		return filter(input, output, typeName, baseURI, cb, trc, maybeCharset, null);
	}

	/**
	 * Filter some data.
	 *
	 * @param input
	 *            Source stream to read data from
	 * @param output
	 *            Stream to write filtered data to
	 * @param typeName
	 *            MIME type for input data
	 * @param maybeCharset
	 * 			  MIME type of the referring document, as a hint, some types,
	 * 			  such as CSS, will inherit it if no other data is available.
	 * @return
	 * @throws IOException
	 *             If an internal error involving s occurred.
	 * @throws UnsafeContentTypeException
	 *             If the MIME type is declared unsafe (e.g. pdf files)
	 * @throws IllegalStateException
	 *             If data is invalid (e.g. corrupted file) and the filter have no way to recover.
	 */
	public static FilterStatus filter(InputStream input, OutputStream output, String typeName, URI baseURI, FoundURICallback cb, TagReplacerCallback trc , String maybeCharset, LinkFilterExceptionProvider linkFilterExceptionProvider) throws UnsafeContentTypeException, IOException {
		return filter(input, output, typeName, maybeCharset, new GenericReadFilterCallback(baseURI, cb,trc, linkFilterExceptionProvider));
	}

	/**
	 * Filter some data.
	 * 
	 * @param input
	 *            Source stream to read data from
	 * @param output
	 *            Stream to write filtered data to
	 * @param typeName
	 *            MIME type for input data
	 * @param maybeCharset 
	 * 			  MIME type of the referring document, as a hint, some types,
	 * 			  such as CSS, will inherit it if no other data is available.
	 * @throws IOException
	 *             If an internal error involving buckets occurred.
	 * @throws UnsafeContentTypeException
	 *             If the MIME type is declared unsafe (e.g. pdf files)
	 * @throws IllegalStateException
	 *             If data is invalid (e.g. corrupted file) and the filter have no way to recover.
	 */
	public static FilterStatus filter(InputStream input, OutputStream output, String typeName, String maybeCharset, FilterCallback filterCallback) throws UnsafeContentTypeException, IOException {
		if(logMINOR) Logger.minor(ContentFilter.class, "Filtering data of type"+typeName);
		String type = typeName;
		String options = "";
		String charset = null;
		HashMap<String, String> otherParams = null;
		input = new BufferedInputStream(input);

		// First parse the MIME type
		
		int idx = type.indexOf(';');
		if(idx != -1) {
			options = type.substring(idx+1);
			type = type.substring(0, idx);
			// Parse options
			// Format: <type>/<subtype>[ optional white space ];[ optional white space ]<param>=<value>; <param2>=<value2>; ...
			String[] rawOpts = options.split(";");
			for(String raw: rawOpts) {
				idx = raw.indexOf('=');
				if(idx == -1) {
					Logger.error(ContentFilter.class, "idx = -1 for '=' on option: "+raw+" from "+typeName);
					continue;
				}
				String before = raw.substring(0, idx).trim();
				String after = raw.substring(idx+1).trim();
				if(before.equals("charset")) {
					charset = after;
				} else {
					if (otherParams == null)
						otherParams = new LinkedHashMap<String, String>();
					otherParams.put(before, after);
				}
			}
		}
		
		// Now look for a FilterMIMEType handler
		
		FilterMIMEType handler = getMIMEType(type);
		
		if(handler == null)
			throw new UnknownContentTypeException(typeName);
		else {
			// Run the read filter if there is one.
			if(handler.readFilter != null) {
				if(handler.takesACharset && ((charset == null) || (charset.length() == 0))) {
					int bufferSize = handler.charsetExtractor.getCharsetBufferSize();
					input.mark(bufferSize);
					byte[] charsetBuffer = new byte[bufferSize];
					int bytesRead = 0, offset = 0, toread=0;
					while(true) {
                                                toread = bufferSize - offset;
						bytesRead = input.read(charsetBuffer, offset, toread);
						if(bytesRead == -1 || toread == 0) break;
						offset += bytesRead;
					}
					input.reset();
					charset = detectCharset(charsetBuffer, offset, handler, maybeCharset);
				}
				try {
					handler.readFilter.readFilter(input, output, charset, filterCallback);
				}
				catch(EOFException e) {
					throw new DataFilterException(l10n("EOFMessage"), l10n("EOFMessage"), l10n("EOFDescription"));
				}
				catch(IOException e) {
					throw e;
				} finally {
					if(filterCallback != null)
						filterCallback.onFinished();
				}
				if(charset != null) type = type + "; charset="+charset;
				output.flush();
				return new FilterStatus(charset, typeName);
			}
			
			if(handler.safeToRead) {
				FileUtil.copy(input, output, -1);
				output.flush();
				return new FilterStatus(charset, typeName);
			}
			
			handler.throwUnsafeContentTypeException();
		}
		return null;
	}

	public static String detectCharset(byte[] input, int length, FilterMIMEType handler, String maybeCharset) throws IOException {
		// Detect charset
		String charset = detectBOM(input, length);
		if((charset == null) && (handler.charsetExtractor != null)) {
			BOMDetection bom = handler.charsetExtractor.getCharsetByBOM(input, length);
			if(bom != null) {
				charset = bom.charset;
				if(charset != null) {
					// These detections are not firm, and can detect a family e.g. ASCII, EBCDIC,
					// so check with the full extractor.
					try {
						if((charset = handler.charsetExtractor.getCharset(input, length, charset)) != null) {
							if(logMINOR)
								Logger.minor(ContentFilter.class, "Returning charset: "+charset);
							return charset;
						} else if(bom.mustHaveCharset)
							throw new UndetectableCharsetException(bom.charset);
					} catch (DataFilterException e) {
						// Ignore
					}
					
				}
			}

			// Obviously, this is slow!
			// This is why we need to detect on insert.
			
			if(handler.defaultCharset != null) {
				try {
					if((charset = handler.charsetExtractor.getCharset(input, length, handler.defaultCharset)) != null) {
				        if(logMINOR)
				        	Logger.minor(ContentFilter.class, "Returning charset: "+charset);
						return charset;
					}
				} catch (DataFilterException e) {
					// Ignore
				}
			}
			try {
				if((charset = handler.charsetExtractor.getCharset(input, length, "ISO-8859-1")) != null)
					return charset;
			} catch (DataFilterException e) {
				// Ignore
			}
			try {
				if((charset = handler.charsetExtractor.getCharset(input, length, "UTF-8")) != null)
					return charset;
			} catch (DataFilterException e) {
				// Ignore
			}
			try {
				if((charset = handler.charsetExtractor.getCharset(input, length, "UTF-16")) != null)
					return charset;
			} catch (DataFilterException e) {
				// Ignore
			}
			try {
				if((charset = handler.charsetExtractor.getCharset(input, length, "UTF-32")) != null)
					return charset;
			} catch (UnsupportedEncodingException e) {
				// Doesn't seem to be supported by prior to 1.6.
		        if(logMINOR)
		        	Logger.minor(ContentFilter.class, "UTF-32 not supported");
			} catch (DataFilterException e) {
				// Ignore
			}
			
		}
		
		// If no BOM, use the charset from the referring document.
		if(handler.useMaybeCharset && maybeCharset != null && (maybeCharset.length() != 0))
			return maybeCharset;
		
		if(charset != null)
			return charset;
		
		// If it doesn't have a BOM, then it's *probably* safe to use as default.
		
		return handler.defaultCharset;
	}

	/**
	 * Detect a Byte Order Mark, a sequence of bytes which identifies a document as encoded with a 
	 * specific charset.
	 * @throws IOException 
	 */
	private static String detectBOM(byte[] input, int length) throws IOException {
		if(startsWith(input, bom_utf8, length))
			return "UTF-8";
		if(startsWith(input, bom_utf16_be, length))
			return "UTF-16BE";
		if(startsWith(input, bom_utf16_le, length))
			return "UTF-16LE";
		if(startsWith(input, bom_utf32_be, length))
			return "UTF-32BE";
		if(startsWith(input, bom_utf32_le, length))
			return "UTF-32LE";
		// We do NOT support UTF-32-2143 or UTF-32-3412
		// Java does not have charset support for them, and well,
		// very few people create web content on a PDP-11!

		if(startsWith(input, bom_utf32_2143, length))
			throw new UnsupportedCharsetInFilterException("UTF-32-2143");
		if(startsWith(input, bom_utf32_3412, length))
			throw new UnsupportedCharsetInFilterException("UTF-32-3412");

		if(startsWith(input, bom_scsu, length))
			return "SCSU";
		if(startsWith(input, bom_utf7_1, length) || startsWith(input, bom_utf7_2, length) || startsWith(input, bom_utf7_3, length) || startsWith(input, bom_utf7_4, length) || startsWith(input, bom_utf7_5, length))
			return "UTF-7";
		if(startsWith(input, bom_utf_ebcdic, length))
			return "UTF-EBCDIC";
		if(startsWith(input, bom_bocu_1, length))
			return "BOCU-1";
		return null;
	}
	
	// Byte Order Mark's - from Wikipedia. We keep all of them because a rare encoding might
	// be deliberately used by an attacker to confuse the filter, because at present a charset
	// is not mandatory, and because some browsers may pick these up anyway even if one is present.
	
	static byte[] bom_utf8 = new byte[] { (byte)0xEF, (byte)0xBB, (byte)0xBF };
	static byte[] bom_utf16_be = new byte[] { (byte)0xFE, (byte)0xFF };
	static byte[] bom_utf16_le = new byte[] { (byte)0xFF, (byte)0xFE };
	static byte[] bom_utf32_be = new byte[] { (byte)0, (byte)0, (byte)0xFE, (byte)0xFF };
	static byte[] bom_utf32_le = new byte[] { (byte)0xFF, (byte)0xFE, (byte)0, (byte)0 };
	static byte[] bom_scsu = new byte[] { (byte)0x0E, (byte)0xFE, (byte)0xFF };
	static byte[] bom_utf7_1 = new byte[] { (byte)0x2B, (byte)0x2F, (byte)0x76, (byte) 0x38 };
	static byte[] bom_utf7_2 = new byte[] { (byte)0x2B, (byte)0x2F, (byte)0x76, (byte) 0x39 };
	static byte[] bom_utf7_3 = new byte[] { (byte)0x2B, (byte)0x2F, (byte)0x76, (byte) 0x2B };
	static byte[] bom_utf7_4 = new byte[] { (byte)0x2B, (byte)0x2F, (byte)0x76, (byte) 0x2F };
	static byte[] bom_utf7_5 = new byte[] { (byte)0x2B, (byte)0x2F, (byte)0x76, (byte) 0x38, (byte) 0x2D };
	static byte[] bom_utf_ebcdic = new byte[] { (byte)0xDD, (byte)0x73, (byte)0x66, (byte)0x73 };
	static byte[] bom_bocu_1 = new byte[] { (byte)0xFB, (byte)0xEE, (byte)0x28 };
	
	// These BOMs are invalid. That is, we do not support them, they will produce an unrecoverable error, since we cannot decode them, but the browser might be able to, as e.g. the CSS spec refers to them.
	static byte[] bom_utf32_2143 = new byte[] { (byte)0x00, (byte)0x00, (byte)0xff, (byte)0xfe };
	static byte[] bom_utf32_3412 = new byte[] { (byte)0xfe, (byte)0xff, (byte)0x00, (byte)0x00 };

	public static boolean startsWith(byte[] data, byte[] cmp, int length) {
		if(cmp.length > length) return false;
		for(int i=0;i<cmp.length;i++) {
			if(data[i] != cmp[i]) return false;
		}
		return true;
	}

	public static class FilterStatus {
		public final String charset;
		public final String mimeType;

		FilterStatus(String charset, String mimeType) {
			this.charset = charset;
			this.mimeType = mimeType;
		}
	}

	/** Check whether we can safely handle a specific MIME type. Usually
	 * called when we haven't downloaded the data yet so can't filter it,
	 * so we can know whether there will be problems later.
	 * @return An UnsafeContentTypeException if there is a problem. */
	public static UnsafeContentTypeException checkMIMEType(String expectedMIME) {
		FilterMIMEType handler = getMIMEType(expectedMIME);
		if(handler == null || (handler.readFilter == null && !handler.safeToRead)) {
			if(handler == null) {
				if(logMINOR) Logger.minor(ContentFilter.class, "Unable to get filter handler for MIME type "+expectedMIME);
				return new UnknownContentTypeException(expectedMIME);
			}
			else {
				if(logMINOR) Logger.minor(ContentFilter.class, "Unable to filter unsafe MIME type "+expectedMIME);
				return new KnownUnsafeContentTypeException(handler);
			}
		}
		return null;
	}
}
