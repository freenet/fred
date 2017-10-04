/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.filter;

import junit.framework.TestCase;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.LinkedHashMap;

import freenet.client.filter.ContentFilter.FilterStatus;
import freenet.client.filter.HTMLFilter.ParsedTag;
import freenet.client.filter.HTMLFilter.TagVerifier;
import freenet.clients.http.ExternalLinkToadlet;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.TestProperty;
import freenet.support.io.ArrayBucket;

/**
 * A simple meta-test to track regressions of the content-filter
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class ContentFilterTest extends TestCase {
	private static final String BASE_URI_PROTOCOL = "http";
	private static final String BASE_URI_CONTENT = "localhost:8888";
	private static final String BASE_KEY = "USK@0I8gctpUE32CM0iQhXaYpCMvtPPGfT4pjXm01oid5Zc,3dAcn4fX2LyxO6uCnWFTx-2HKZ89uruurcKwLSCxbZ4,AQACAAE/Ultimate-Freenet-Index/55/";
	private static final String BASE_URI = BASE_URI_PROTOCOL+"://"+BASE_URI_CONTENT+'/';
	private static final String ALT_BASE_URI = BASE_URI_PROTOCOL+"://"+BASE_URI_CONTENT+'/'+BASE_KEY;

	private static final String EXTERNAL_LINK = "www.evilwebsite.gov";
	private static final String EXTERNAL_LINK_OK = "<a />";
	// check that external links are not allowed
	private static final String EXTERNAL_LINK_CHECK1 = "<a href=\""+EXTERNAL_LINK+"\"/>";
	private static final String EXTERNAL_LINK_CHECK2 = "<a href=\""+BASE_URI_PROTOCOL+"://"+EXTERNAL_LINK+"\"/>";
	private static final String EXTERNAL_LINK_CHECK3 = "<a href=\""+BASE_URI_CONTENT+"@http://"+EXTERNAL_LINK+"\"/>";

	private static final String INTERNAL_RELATIVE_LINK = "<a href=\"/KSK@gpl.txt\" />";
	private static final String INTERNAL_ABSOLUTE_LINK = "<a href=\""+BASE_URI+"KSK@gpl.txt\" />";

	private static final String INTERNAL_RELATIVE_LINK1 = "<a href=\"test.html\" />";

	// @see bug #710
	private static final String ANCHOR_TEST = "<a href=\"#test\" />";
	private static final String ANCHOR_TEST_EMPTY = "<a href=\"#\" />";
	private static final String ANCHOR_TEST_SPECIAL = "<a href=\"#!$()*+,;=:@ABC0123-._~xyz%3f\" />"; // RFC3986 / RFC 2396
	private static final String ANCHOR_TEST_SPECIAL2 = "<a href=\"#!$&'()*+,;=:@ABC0123-._~xyz%3f\" />";
	private static final String ANCHOR_TEST_SPECIAL2_RESULT = "<a href=\"#!$&amp;&#39;()*+,;=:@ABC0123-._~xyz%3f\" />";

	// @see bug #2496
	private static final String ANCHOR_RELATIVE1 = "<a href=\"/KSK@test/test.html#C2\">";
	private static final String ANCHOR_RELATIVE2 = "<a href=\"/KSK@test/path/test.html#C2\">";
	private static final String ANCHOR_FALSE_POS1 = "<a href=\"/KSK@test/path/test.html#%23\">"; // yes, this is valid
	private static final String ANCHOR_FALSE_POS2 = "<a href=\"/KSK@test/path/%23.html#2\">"; // yes, this is valid too

	// evil hack for #2496 + #2451, <SPACE><#> give <SPACE><%23>
	private static final String ANCHOR_MIXED = "<a href=\"/KSK@test/path/music #1.ogg\">";
	private static final String ANCHOR_MIXED_RESULT = "<a href=\"/KSK@test/path/music%20%231.ogg\">";

	// @see bug #2451
	private static final String POUNT_CHARACTER_ENCODING_TEST = "<a href=\"/CHK@DUiGC5D1ZsnFpH07WGkNVDujNlxhtgGxXBKrMT-9Rkw,~GrAWp02o9YylpxL1Fr4fPDozWmebhGv4qUoFlrxnY4,AAIC--8/Testing - [blah] Apostrophe' - gratuitous 1 AND CAPITAL LETTERS!!!!.ogg\" />";
	private static final String POUNT_CHARACTER_ENCODING_TEST_RESULT = "<a href=\"/CHK@DUiGC5D1ZsnFpH07WGkNVDujNlxhtgGxXBKrMT-9Rkw,~GrAWp02o9YylpxL1Fr4fPDozWmebhGv4qUoFlrxnY4,AAIC--8/Testing%20-%20%5bblah%5d%20Apostrophe%27%20-%20gratuitous%201%20AND%20CAPITAL%20LETTERS%21%21%21%21.ogg\" />";
	// @see bug #2297
	private static final String PREVENT_FPROXY_ACCESS = "<a href=\""+BASE_URI+"\"/>";
	// @see bug #2921
	private static final String PREVENT_EXTERNAL_ACCESS_CSS_SIMPLE = "<style>div { background: url("+BASE_URI+") }</style>";
	private static final String PREVENT_EXTERNAL_ACCESS_CSS_CASE = "<style>div { background: uRl("+BASE_URI+") }</style>";
	private static final String PREVENT_EXTERNAL_ACCESS_CSS_ESCAPE = "<style>div { background: \\u\\r\\l("+BASE_URI+") }</style>";
	private static final String WHITELIST_STATIC_CONTENT = "<a href=\"/static/themes/clean/theme.css\" />";
	private static final String XHTML_VOIDELEMENT="<html xmlns=\"http://www.w3.org/1999/xhtml\"><br><hr></html>";
	private static final String XHTML_VOIDELEMENTC="<html xmlns=\"http://www.w3.org/1999/xhtml\"><br /><hr /></html>";
	private static final String XHTML_INCOMPLETEDOCUMENT="<html xmlns=\"http://www.w3.org/1999/xhtml\"><body> <h1> helloworld <h2> helloworld";
	private static final String XHTML_INCOMPLETEDOCUMENTC="<html xmlns=\"http://www.w3.org/1999/xhtml\"><body> <h1> helloworld <h2> helloworld</h2></h1></body></html>";
	private static final String XHTML_IMPROPERNESTING="<html xmlns=\"http://www.w3.org/1999/xhtml\"><b><i>helloworld</b></i></html>";
	private static final String XHTML_IMPROPERNESTINGC="<html xmlns=\"http://www.w3.org/1999/xhtml\"><b><i>helloworld</i></b></html>";

	private static final String CSS_STRING_NEWLINES = "<style>* { content: \"this string does not terminate\n}\nbody {\nbackground: url(http://www.google.co.uk/intl/en_uk/images/logo.gif); }\n\" }</style>";
	private static final String CSS_STRING_NEWLINESC = "<style>* {}\nbody { }\n</style>";

	private static final String HTML_STYLESHEET_MAYBECHARSET = "<link rel=\"stylesheet\" href=\"test.css\">";
	private static final String HTML_STYLESHEET_MAYBECHARSETC = "<link rel=\"stylesheet\" href=\"test.css?type=text/css&amp;maybecharset=iso-8859-1\" type=\"text/css\">";

	private static final String HTML_STYLESHEET_CHARSET = "<link rel=\"stylesheet\" charset=\"utf-8\" href=\"test.css\">";
	private static final String HTML_STYLESHEET_CHARSETC = "<link rel=\"stylesheet\" charset=\"utf-8\" href=\"test.css?type=text/css%3b%20charset=utf-8\" type=\"text/css\">";

	private static final String HTML_STYLESHEET_CHARSET_BAD = "<link rel=\"stylesheet\" charset=\"utf-8&max-size=4194304\" href=\"test.css\">";
	private static final String HTML_STYLESHEET_CHARSET_BADC = "<link rel=\"stylesheet\" href=\"test.css?type=text/css&amp;maybecharset=iso-8859-1\" type=\"text/css\">";

	private static final String HTML_STYLESHEET_CHARSET_BAD1 = "<link rel=\"stylesheet\" type=\"text/css; charset=utf-8&max-size=4194304\" href=\"test.css\">";
	private static final String HTML_STYLESHEET_CHARSET_BAD1C = "<link rel=\"stylesheet\" type=\"text/css\" href=\"test.css?type=text/css&amp;maybecharset=iso-8859-1\">";

	private static final String HTML_STYLESHEET_WITH_MEDIA = "<LINK REL=\"stylesheet\" TYPE=\"text/css\"\nMEDIA=\"print, handheld\" HREF=\"foo.css\">";
	private static final String HTML_STYLESHEET_WITH_MEDIAC = "<LINK rel=\"stylesheet\" type=\"text/css\" media=\"print, handheld\" href=\"foo.css?type=text/css&amp;maybecharset=iso-8859-1\">";

	private static final String FRAME_SRC_CHARSET = "<frame src=\"test.html?type=text/html; charset=UTF-8\">";
	private static final String FRAME_SRC_CHARSETC = "<frame src=\"test.html?type=text/html%3b%20charset=UTF-8\">";

	private static final String FRAME_SRC_CHARSET_BAD = "<frame src=\"test.html?type=text/html; charset=UTF-8&max-size=4194304\">";
	private static final String FRAME_SRC_CHARSET_BADC = "<frame src=\"test.html?type=text/html%3b%20charset=UTF-8\">";

	private static final String FRAME_SRC_CHARSET_BAD1 = "<frame src=\"test.html?type=text/html; charset=UTF-8%26max-size=4194304\">";
	private static final String FRAME_SRC_CHARSET_BAD1C = "<frame src=\"test.html?type=text/html\">";

	private static final String SPAN_WITH_STYLE = "<span style=\"font-family: verdana, sans-serif; color: red;\">";
	
	private static final String BASE_HREF = "<base href=\"/"+BASE_KEY+"\">";
	private static final String BAD_BASE_HREF = "<base href=\"/\">";
	private static final String BAD_BASE_HREF2 = "<base href=\"//www.google.com\">";
	private static final String BAD_BASE_HREF3 = "<base>";
	private static final String BAD_BASE_HREF4 = "<base id=\"blah\">";
	private static final String BAD_BASE_HREF5 = "<base href=\"http://www.google.com/\">";
	private static final String DELETED_BASE_HREF = "<!-- deleted invalid base href -->";
	
	// From CSS spec

	private static final String CSS_SPEC_EXAMPLE1 = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\">\n<HTML>\n  <HEAD>\n  <TITLE>Bach's home page</TITLE>\n  <STYLE type=\"text/css\">\n    body {\n      font-family: \"Gill Sans\", sans-serif;\n      font-size: 12pt;\n      margin: 3em;\n\n    }\n  </STYLE>\n  </HEAD>\n  <BODY>\n    <H1>Bach's home page</H1>\n    <P>Johann Sebastian Bach was a prolific composer.\n  </BODY>\n</HTML>";

	public void testHTMLFilter() throws Exception {
		if (TestProperty.VERBOSE) {
			Logger.setupStdoutLogging(LogLevel.MINOR, "freenet.client.filter.Generic:DEBUG");
		}

		// General sanity checks
		// is "relativization" working?
		assertEquals(INTERNAL_RELATIVE_LINK, HTMLFilter(INTERNAL_RELATIVE_LINK));
		assertEquals(INTERNAL_RELATIVE_LINK, HTMLFilter(INTERNAL_RELATIVE_LINK, true));
		assertEquals(INTERNAL_RELATIVE_LINK1, HTMLFilter(INTERNAL_RELATIVE_LINK1, true));
		assertEquals(INTERNAL_RELATIVE_LINK, HTMLFilter(INTERNAL_ABSOLUTE_LINK));
		// are external links stripped out ?
		assertTrue(HTMLFilter(EXTERNAL_LINK_CHECK1).startsWith(EXTERNAL_LINK_OK));
		assertTrue(HTMLFilter(EXTERNAL_LINK_CHECK2).contains(ExternalLinkToadlet.PATH));
		assertTrue(HTMLFilter(EXTERNAL_LINK_CHECK3).startsWith(EXTERNAL_LINK_OK));

		// regression testing
		// bug #710
		assertEquals(ANCHOR_TEST, HTMLFilter(ANCHOR_TEST));
		assertEquals(ANCHOR_TEST_EMPTY, HTMLFilter(ANCHOR_TEST_EMPTY));
		assertEquals(ANCHOR_TEST_SPECIAL, HTMLFilter(ANCHOR_TEST_SPECIAL));
		assertEquals(ANCHOR_TEST_SPECIAL2_RESULT, HTMLFilter(ANCHOR_TEST_SPECIAL2));
		// bug #2496
		assertEquals(ANCHOR_RELATIVE1, HTMLFilter(ANCHOR_RELATIVE1));
		assertEquals(ANCHOR_RELATIVE2, HTMLFilter(ANCHOR_RELATIVE2));
		assertEquals(ANCHOR_FALSE_POS1, HTMLFilter(ANCHOR_FALSE_POS1));
		assertEquals(ANCHOR_FALSE_POS2, HTMLFilter(ANCHOR_FALSE_POS2));
		// EVIL HACK TEST for #2496 + #2451
		assertEquals(ANCHOR_MIXED_RESULT, HTMLFilter(ANCHOR_MIXED));
		// bug #2451
		assertEquals(POUNT_CHARACTER_ENCODING_TEST_RESULT, HTMLFilter(POUNT_CHARACTER_ENCODING_TEST));
		// bug #2297
		assertTrue(HTMLFilter(PREVENT_FPROXY_ACCESS).contains(ExternalLinkToadlet.PATH));
		// bug #2921
		assertTrue(HTMLFilter(PREVENT_EXTERNAL_ACCESS_CSS_SIMPLE).contains("div { }"));
		assertTrue(HTMLFilter(PREVENT_EXTERNAL_ACCESS_CSS_ESCAPE).contains("div { }"));
		assertTrue(HTMLFilter(PREVENT_EXTERNAL_ACCESS_CSS_CASE).contains("div { }"));
		assertEquals(WHITELIST_STATIC_CONTENT, HTMLFilter(WHITELIST_STATIC_CONTENT));
		assertEquals(XHTML_VOIDELEMENTC,HTMLFilter(XHTML_VOIDELEMENT));
		assertEquals(XHTML_INCOMPLETEDOCUMENTC,HTMLFilter(XHTML_INCOMPLETEDOCUMENT));
		assertEquals(XHTML_IMPROPERNESTINGC,HTMLFilter(XHTML_IMPROPERNESTING));

		assertEquals(CSS_STRING_NEWLINESC,HTMLFilter(CSS_STRING_NEWLINES));

		assertEquals(HTML_STYLESHEET_MAYBECHARSETC, HTMLFilter(HTML_STYLESHEET_MAYBECHARSET, true));
		assertEquals(HTML_STYLESHEET_CHARSETC, HTMLFilter(HTML_STYLESHEET_CHARSET, true));
		assertEquals(HTML_STYLESHEET_CHARSET_BADC, HTMLFilter(HTML_STYLESHEET_CHARSET_BAD, true));
		assertEquals(HTML_STYLESHEET_CHARSET_BAD1C, HTMLFilter(HTML_STYLESHEET_CHARSET_BAD1, true));
		assertEquals(HTML_STYLESHEET_WITH_MEDIAC, HTMLFilter(HTML_STYLESHEET_WITH_MEDIA, true));

		assertEquals(FRAME_SRC_CHARSETC, HTMLFilter(FRAME_SRC_CHARSET, true));
		assertEquals(FRAME_SRC_CHARSET_BADC, HTMLFilter(FRAME_SRC_CHARSET_BAD, true));
		assertEquals(FRAME_SRC_CHARSET_BAD1C, HTMLFilter(FRAME_SRC_CHARSET_BAD1, true));

		assertEquals(CSS_SPEC_EXAMPLE1, HTMLFilter(CSS_SPEC_EXAMPLE1));

		assertEquals(SPAN_WITH_STYLE, HTMLFilter(SPAN_WITH_STYLE));
		
		assertEquals(BASE_HREF, HTMLFilter(BASE_HREF));
		assertEquals(DELETED_BASE_HREF, HTMLFilter(BAD_BASE_HREF));
		assertEquals(DELETED_BASE_HREF, HTMLFilter(BAD_BASE_HREF2));
		assertEquals(DELETED_BASE_HREF, HTMLFilter(BAD_BASE_HREF3));
		assertEquals(DELETED_BASE_HREF, HTMLFilter(BAD_BASE_HREF4));
		assertEquals(DELETED_BASE_HREF, HTMLFilter(BAD_BASE_HREF5));
	}
	
	private static final String META_TIME_ONLY = "<meta http-equiv=\"refresh\" content=\"5\">";
	private static final String META_TIME_ONLY_WRONG_CASE = "<meta http-equiv=\"RefResH\" content=\"5\">";
	private static final String META_TIME_ONLY_TOO_SHORT = "<meta http-equiv=\"refresh\" content=\"0\">";
	private static final String META_TIME_ONLY_NEGATIVE = "<meta http-equiv=\"refresh\" content=\"-5\">";
	
	private static final String META_TIME_ONLY_BADNUM1 = "<meta http-equiv=\"refresh\" content=\"5.5\">";
	private static final String META_TIME_ONLY_BADNUM2 = "<meta http-equiv=\"refresh\" content=\"\">";
	private static final String META_TIME_ONLY_BADNUM_OUT = "<!-- doesn't parse as number in meta refresh -->";
	
	private static final String META_VALID_REDIRECT = "<meta http-equiv=\"refresh\" content=\"30; url=/KSK@gpl.txt\">";
	private static final String META_VALID_REDIRECT_NOSPACE = "<meta http-equiv=\"refresh\" content=\"30;url=/KSK@gpl.txt\">";
	
	private static final String META_BOGUS_REDIRECT1 = "<meta http-equiv=\"refresh\" content=\"30; url=/\">";
	private static final String META_BOGUS_REDIRECT2 = "<meta http-equiv=\"refresh\" content=\"30; url=/plugins\">";
	private static final String META_BOGUS_REDIRECT3 = "<meta http-equiv=\"refresh\" content=\"30; url=http://www.google.com\">";
	private static final String META_BOGUS_REDIRECT4 = "<meta http-equiv=\"refresh\" content=\"30; url=//www.google.com\">";
	private static final String META_BOGUS_REDIRECT5 = "<meta http-equiv=\"refresh\" content=\"30; url=\"/KSK@gpl.txt\"\">";
	private static final String META_BOGUS_REDIRECT6 = "<meta http-equiv=\"refresh\" content=\"30; /KSK@gpl.txt\">";
	private static final String META_BOGUS_REDIRECT1_OUT = "<!-- GenericReadFilterCallback.malformedRelativeURL-->";
	private static final String META_BOGUS_REDIRECT3_OUT = "<meta http-equiv=\"refresh\" content=\"30; url=/external-link/?_CHECKED_HTTP_=http://www.google.com\">";
	private static final String META_BOGUS_REDIRECT4_OUT = "<!-- GenericReadFilterCallback.deletedURI-->";
	private static final String META_BOGUS_REDIRECT_NO_URL = "<!-- no url but doesn't parse as number in meta refresh -->";
	
	public void testMetaRefresh() throws Exception {
		HTMLFilter.metaRefreshSamePageMinInterval = 5;
		HTMLFilter.metaRefreshRedirectMinInterval = 30;
		assertEquals(META_TIME_ONLY, headFilter(META_TIME_ONLY));
		assertEquals(META_TIME_ONLY, headFilter(META_TIME_ONLY_WRONG_CASE));
		assertEquals(META_TIME_ONLY, headFilter(META_TIME_ONLY_TOO_SHORT));
		assertEquals("", headFilter(META_TIME_ONLY_NEGATIVE));
		assertEquals(META_TIME_ONLY_BADNUM_OUT, headFilter(META_TIME_ONLY_BADNUM1));
		assertEquals(META_TIME_ONLY_BADNUM_OUT, headFilter(META_TIME_ONLY_BADNUM2));
		assertEquals(META_VALID_REDIRECT, headFilter(META_VALID_REDIRECT));
		assertEquals(META_VALID_REDIRECT, headFilter(META_VALID_REDIRECT_NOSPACE));
		assertEquals(META_BOGUS_REDIRECT1_OUT, headFilter(META_BOGUS_REDIRECT1));
		assertEquals(META_BOGUS_REDIRECT1_OUT, headFilter(META_BOGUS_REDIRECT2));
		assertEquals(META_BOGUS_REDIRECT3_OUT, headFilter(META_BOGUS_REDIRECT3));
		assertEquals(META_BOGUS_REDIRECT4_OUT, headFilter(META_BOGUS_REDIRECT4));
		assertEquals(META_BOGUS_REDIRECT1_OUT, headFilter(META_BOGUS_REDIRECT5));
		assertEquals(META_BOGUS_REDIRECT_NO_URL, headFilter(META_BOGUS_REDIRECT6));
		HTMLFilter.metaRefreshSamePageMinInterval = -1;
		HTMLFilter.metaRefreshRedirectMinInterval = -1;
		assertEquals("", headFilter(META_TIME_ONLY));
		assertEquals("", headFilter(META_TIME_ONLY_WRONG_CASE));
		assertEquals("", headFilter(META_TIME_ONLY_TOO_SHORT));
		assertEquals("", headFilter(META_TIME_ONLY_NEGATIVE));
		assertEquals("", headFilter(META_TIME_ONLY_BADNUM1));
		assertEquals("", headFilter(META_TIME_ONLY_BADNUM2));
		assertEquals("", headFilter(META_VALID_REDIRECT));
		assertEquals("", headFilter(META_VALID_REDIRECT_NOSPACE));
		assertEquals("", headFilter(META_BOGUS_REDIRECT1));
		assertEquals("", headFilter(META_BOGUS_REDIRECT2));
		assertEquals("", headFilter(META_BOGUS_REDIRECT3));
		assertEquals("", headFilter(META_BOGUS_REDIRECT4));
		assertEquals("", headFilter(META_BOGUS_REDIRECT5));
		assertEquals("", headFilter(META_BOGUS_REDIRECT6));
	}

	private String headFilter(String data) throws Exception {
		String s = HTMLFilter("<head>"+data+"</head>");
		if(s == null) return s;
		if(!s.startsWith("<head>"))
			assertTrue("Head deleted???: "+s, false);
		s = s.substring("<head>".length());
		if(!s.endsWith("</head>"))
			assertTrue("Head close deleted???: "+s, false);
		s = s.substring(0, s.length() - "</head>".length());
		return s;
	}

	public void testEvilCharset() throws IOException {
		// This is why we need to disallow characters before <html> !!
		String s = "<html><body><a href=\"http://www.google.com/\">Blah</a>";
		String end = "</body></html>";
		String alt = "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-16\"></head><body><a href=\"http://www.freenetproject.org/\">Blah</a></body></html>";
		if((s.length()+end.length()) % 2 == 1)
			s += " ";
		s = s+end;
		byte[] buf;
		try {
			buf = s.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new Error(e);
		}
		byte[] utf16bom = new byte[] { (byte)0xFE, (byte)0xFF };
		byte[] bufUTF16 = alt.getBytes("UTF-16");
		byte[] total = new byte[buf.length+utf16bom.length+bufUTF16.length];
		System.arraycopy(utf16bom, 0, total, 0, utf16bom.length);
		System.arraycopy(buf, 0, total, utf16bom.length, buf.length);
		System.arraycopy(bufUTF16, 0, total, utf16bom.length+buf.length, bufUTF16.length);
		HTMLFilter filter = new HTMLFilter();
		boolean failed = false;
		FileOutputStream fos;
		try {
			ArrayBucket out = new ArrayBucket();
			filter.readFilter(new ArrayBucket(total).getInputStream(), out.getOutputStream(), "UTF-16", null);
			fos = new FileOutputStream("output.utf16");
			fos.write(out.toByteArray());
			fos.close();
			failed = true;
			assertFalse("Filter accepted dangerous UTF8 text with BOM as UTF16! (HTMLFilter)", true);
		} catch (DataFilterException e) {
			System.out.println("Failure: "+e);
			e.printStackTrace();
			if(e.getCause() != null) {
				e.getCause().printStackTrace();
			}
			// Ok.
		}
		try {
			ArrayBucket out = new ArrayBucket();
			FilterStatus fo = ContentFilter.filter(new ArrayBucket(total).getInputStream(), out.getOutputStream(), "text/html", null, null);
			fos = new FileOutputStream("output.filtered");
			fos.write(out.toByteArray());
			fos.close();
			failed = true;
			assertFalse("Filter accepted dangerous UTF8 text with BOM as UTF16! (ContentFilter) - Detected charset: "+fo.charset, true);
		} catch (DataFilterException e) {
			System.out.println("Failure: "+e);
			e.printStackTrace();
			if(e.getCause() != null) {
				e.getCause().printStackTrace();
			}
			// Ok.
		}

		if(failed) {
			fos = new FileOutputStream("unfiltered");
			fos.write(total);
			fos.close();
		}
	}

	public static String HTMLFilter(String data) throws Exception {
		if(data.startsWith("<html")) return HTMLFilter(data, false);
		if(data.startsWith("<?")) return HTMLFilter(data, false);
		String s = HTMLFilter("<html>"+data+"</html>", false);
		assertTrue(s.startsWith("<html>"));
		s = s.substring("<html>".length());
		assertTrue("s = \""+s+"\"", s.endsWith("</html>"));
		s = s.substring(0, s.length() - "</html>".length());
		return s;
	}

	public static String HTMLFilter(String data, boolean alt) throws Exception {
		String returnValue;
		String typeName = "text/html";
		URI baseURI = new URI(alt ? ALT_BASE_URI : BASE_URI);
		byte[] dataToFilter = data.getBytes("UTF-8");
		ArrayBucket input = new ArrayBucket(dataToFilter);
		ArrayBucket output = new ArrayBucket();
		InputStream inputStream = input.getInputStream();
		OutputStream outputStream = output.getOutputStream();
		ContentFilter.filter(inputStream, outputStream, typeName, baseURI, null, null, null);
		inputStream.close();
		outputStream.close();
		returnValue = output.toString();
		output.free();
		input.free();
		return returnValue;
	}

	static public class TagVerifierTest extends TestCase {
		static String tagname;
		LinkedHashMap<String, String> attributes;
		ParsedTag HTMLTag;
		TagVerifier verifier;
		HTMLFilter filter;
		HTMLFilter.HTMLParseContext pc;

		@Override
		public void setUp() throws Exception {
			filter = new HTMLFilter();
			attributes = new LinkedHashMap<String, String>();
			pc = filter.new HTMLParseContext(null, null, "utf-8", new GenericReadFilterCallback(new URI(ALT_BASE_URI), null, null, null), false);
		}

		@Override
		public void tearDown() {
			filter = null;
			attributes = null;
			pc = null;
			tagname = null;
			verifier = null;
			HTMLTag = null;
		}

		public void testHTMLTagWithInvalidNS() throws DataFilterException{
			tagname = "html";
			verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);

			//Place an invalid namespace into the tag
			attributes.put("xmlns", "http://www.w3.org/1909/xhtml");
			//Place a unparsed attribute into the tag
			attributes.put("version", "-//W3C//DTD HTML 4.01 Transitional//EN");

			HTMLTag = new ParsedTag(tagname, attributes);
			final String HTML_INVALID_XMLNS = "<html version=\"-//W3C//DTD HTML 4.01 Transitional//EN\" />";

			assertEquals("HTML tag containing an invalid xmlns", HTML_INVALID_XMLNS, verifier.sanitize(HTMLTag, pc).toString());
		}

		public void testLinkTag() throws DataFilterException {
			tagname = "link";
			verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);

			attributes.put("rel", "stylesheet");
			attributes.put("type", "text/css");
			attributes.put("target", "_blank");
			attributes.put("media", "print, handheld");
			attributes.put("href", "foo.css");

			HTMLTag = new ParsedTag(tagname, attributes);

			final String LINK_STYLESHEET = "<link rel=\"stylesheet\" type=\"text/css\" target=\"_blank\" media=\"print, handheld\" href=\"foo.css?type=text/css&amp;maybecharset=utf-8\" />";

			assertEquals("Link tag importing CSS", LINK_STYLESHEET, verifier.sanitize(HTMLTag, pc).toString());
		}

		public void testMetaTagHTMLContentType() throws DataFilterException {
			tagname = "meta";
			verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);

			attributes.put("http-equiv","Content-type");
			attributes.put("content","text/html; charset=UTF-8");
			HTMLTag = new ParsedTag(tagname, attributes);

			assertEquals("Meta tag describing HTML content-type", HTMLTag.toString(), verifier.sanitize(HTMLTag, pc).toString());
		}

		public void testMetaTagXHTMLContentType() throws DataFilterException {
			tagname = "meta";
			verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);

			attributes.put("http-equiv","Content-type");
			attributes.put("content","application/xhtml+xml; charset=UTF-8");
			HTMLTag = new ParsedTag(tagname, attributes);

			assertEquals("Meta tag describing XHTML content-type", HTMLTag.toString(), verifier.sanitize(HTMLTag, pc).toString());
		}

		public void testMetaTagUnknownContentType() throws DataFilterException {
			tagname = "meta";
			verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);

			attributes.put("http-equiv","Content-type");
			attributes.put("content","want/fishsticks; charset=UTF-8");
			HTMLTag = new ParsedTag(tagname, attributes);

			try {
				verifier.sanitize(HTMLTag, pc);
				assertTrue("Meta tag describing an unknown content-type: should throw an error", false);
			} catch (DataFilterException e) {
				// Ok.
			}
		}

		public void testBodyTag() throws DataFilterException {
			tagname = "body";
			verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);

			attributes.put("bgcolor", "pink");
			//Let's pretend the following is malicious JavaScript
			attributes.put("onload", "evil_scripting_magic");

			HTMLTag = new ParsedTag(tagname, attributes);

			final String BODY_TAG = "<body bgcolor=\"pink\" />";

			assertEquals("Body tag", BODY_TAG, verifier.sanitize(HTMLTag, pc).toString());
		}

		public void testFormTag() throws DataFilterException {
			tagname = "form";
			verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);

			attributes.put("method", "POST");
			//Place a bad charset into the tag. This will get replaced with utf-8
			attributes.put("accept-charset", "iso-8859-1");
			attributes.put("action", "/library/");

			HTMLTag = new ParsedTag(tagname, attributes);
			final String FORM_TAG = "<form method=\"POST\" accept-charset=\"UTF-8\" action=\"/library/\" enctype=\"multipart/form-data\" />";

			assertEquals("Form tag", FORM_TAG, verifier.sanitize(HTMLTag, pc).toString());
		}

		public void testInvalidFormMethod() throws DataFilterException {
			tagname = "form";
			verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);

			attributes.put("method", "INVALID_METHOD");
			attributes.put("action", "/library/");

			HTMLTag = new ParsedTag(tagname, attributes);

			assertNull("Form tag with an invalid method", verifier.sanitize(HTMLTag, pc));
		}

		public void testValidInputTag() throws DataFilterException {
			tagname = "input";
			verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);

			attributes.put("type", "text");

			HTMLTag = new ParsedTag(tagname, attributes);

			assertEquals("Input tag with a valid type", HTMLTag.toString(), verifier.sanitize(HTMLTag, pc).toString());
		}

		public void testInvalidInputTag() throws DataFilterException {
			tagname = "input";
			verifier = HTMLFilter.allowedTagsVerifiers.get(tagname);

			attributes.put("type", "INVALID_TYPE");

			HTMLTag = new ParsedTag(tagname, attributes);

			assertNull("Input tag with an invalid type", verifier.sanitize(HTMLTag, pc));
		}
	}
	
	public void testLowerCaseExtensions() {
		for(FilterMIMEType type : ContentFilter.mimeTypesByName.values()) {
			String ext = type.primaryExtension;
			if(ext != null)
				assertEquals(ext, ext.toLowerCase());
			String[] exts = type.alternateExtensions;
			if(ext != null)
				for(String s : exts)
					assertEquals(s, s.toLowerCase());
		}
	}
}
