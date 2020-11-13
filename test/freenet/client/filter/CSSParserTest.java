package freenet.client.filter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map.Entry;

import junit.framework.TestCase;
import freenet.client.filter.CharsetExtractor.BOMDetection;
import freenet.client.filter.ContentFilter.FilterStatus;
import freenet.l10n.NodeL10n;
import freenet.support.SimpleReadOnlyArrayBucket;
import freenet.support.LoggerHook.InvalidThresholdException;
import freenet.support.api.Bucket;
import freenet.support.io.ArrayBucket;
import freenet.support.io.BucketTools;

public class CSSParserTest extends TestCase {


	// FIXME should specify exact output values
	/** CSS1 Selectors */
	private final static HashMap<String,String> CSS1_SELECTOR= new HashMap<String,String>();
	static
	{
		CSS1_SELECTOR.put("h1 {}","h1");
		CSS1_SELECTOR.put("h1:link {}","h1:link");
		CSS1_SELECTOR.put("h1:visited {}","");
		CSS1_SELECTOR.put("h1.warning {}","h1.warning");
		CSS1_SELECTOR.put("h1#myid {}","h1#myid");
		CSS1_SELECTOR.put("h1 h2 {}","h1 h2");
		CSS1_SELECTOR.put("h1:active {}","h1:active");
		CSS1_SELECTOR.put("h1:hover {}","h1:hover");
		CSS1_SELECTOR.put("h1:focus {}" ,"h1:focus");
		CSS1_SELECTOR.put("h1:first-line {}" ,"h1:first-line");
		CSS1_SELECTOR.put("h1:first-letter {}" ,"h1:first-letter");




	}

	// FIXME should specify exact output values
	/** CSS2 Selectors */
	private final static HashMap<String,String> CSS2_SELECTOR= new HashMap<String,String>();
	static
	{
		CSS2_SELECTOR.put("* {}","*");
		CSS2_SELECTOR.put("h1[foo] {}","h1[foo]");
		CSS2_SELECTOR.put("h1[foo=\"bar\"] {}", "h1[foo=\"bar\"]");
		CSS2_SELECTOR.put("h1[foo=bar] {}", "h1[foo=bar] {}");
		CSS2_SELECTOR.put("h1[foo~=\"bar\"] {}", "h1[foo~=\"bar\"]");
		CSS2_SELECTOR.put("h1[foo|=\"en\"] {}","h1[foo|=\"en\"]");
		CSS2_SELECTOR.put("[foo|=\"en\"] {}","[foo|=\"en\"]");
		CSS2_SELECTOR.put("h1:first-child {}","h1:first-child");
		CSS2_SELECTOR.put("h1:lang(fr) {}","h1:lang(fr)");
		CSS2_SELECTOR.put("h1>h2 {}","h1>h2");
		CSS2_SELECTOR.put("h1+h2 {}", "h1+h2");
		CSS2_SELECTOR.put("div.foo {}", "div.foo");
		CSS2_SELECTOR.put("p.marine.pastoral { color: green }", "p.marine.pastoral");
		CSS2_SELECTOR.put("[lang=fr] {}", "[lang=fr] {}");
		CSS2_SELECTOR.put(".warning {}", ".warning {}");
		CSS2_SELECTOR.put("#myid {}", "#myid {}");
		CSS2_SELECTOR.put("h1#chapter1 {}", "h1#chapter1 {}");
		CSS2_SELECTOR.put("h1 em { color: blue;}", "h1 em { color: blue;}");
		CSS2_SELECTOR.put("div * p { color: blue;}", "div * p { color: blue;}");
		CSS2_SELECTOR.put("div p *[href] { color: blue;}", "div p *[href] { color: blue;}");
		CSS2_SELECTOR.put("body > P { line-height: 1.3 }", "body>P { line-height: 1.3 }");
		CSS2_SELECTOR.put("div ol>li p { color: green;}", "div ol>li p { color: green;}");
		CSS2_SELECTOR.put("h1 + h2 { margin-top: -5mm }", "h1+h2 { margin-top: -5mm }");
		CSS2_SELECTOR.put("h1.opener + h2 { margin-top: -5mm }", "h1.opener+h2 { margin-top: -5mm }");
		CSS2_SELECTOR.put("span[class=example] { color: blue; }", "span[class=example] { color: blue; }");
		CSS2_SELECTOR.put("span[hello=\"Cleveland\"][goodbye=\"Columbus\"] { color: blue; }", "span[hello=\"Cleveland\"][goodbye=\"Columbus\"] { color: blue; }");
		CSS2_SELECTOR.put("div > p:first-child { text-indent: 0 }", "div>p:first-child { text-indent: 0 }");
		CSS2_SELECTOR.put("div > p:FIRST-CHILD { text-indent: 0 }", "div>p:FIRST-CHILD { text-indent: 0 }");
		CSS2_SELECTOR.put("p:first-child em { font-weight : bold }", "p:first-child em { font-weight: bold }");
		CSS2_SELECTOR.put("* > a:first-child {}", "*>a:first-child {}");
		CSS2_SELECTOR.put(":link { color: red }", ":link { color: red }");
		// REDFLAG: link vs visited is safe for Freenet as there is no scripting.
		// If there was scripting it would not be safe, although datastore probing is probably the greater threat.
		CSS2_SELECTOR.put("a.external:visited { color: blue }", "");
		CSS2_SELECTOR.put("a:focus:hover { background: white }", "a:focus:hover { background: white }");
		CSS2_SELECTOR.put("p:first-line { text-transform: uppercase;}", "p:first-line { text-transform: uppercase;}");
		// CONFORMANCE: :first-line can only be attached to block-level, we don't enforce this, it is not dangerous.
		CSS2_SELECTOR.put("p:first-letter { font-size: 3em; font-weight: normal }", "p:first-letter { font-size: 3em; font-weight: normal }");

		// Spaces in a selector string
		CSS2_SELECTOR.put("h1[foo=\"bar bar\"] {}", "h1[foo=\"bar bar\"]");
		CSS2_SELECTOR.put("h1[foo=\"bar+bar\"] {}", "h1[foo=\"bar+bar\"]");
		CSS2_SELECTOR.put("h1[foo=\"bar\\\" bar\"] {}", "h1[foo=\"bar\\\" bar\"]");
		// Wierd one from the CSS spec
		CSS2_SELECTOR.put("p[example=\"public class foo\\\n{\\\n    private int x;\\\n\\\n    foo(int x) {\\\n        this.x = x;\\\n    }\\\n\\\n}\"] { color: red }",
				"p[example=\"public class foo{    private int x;    foo(int x) {        this.x = x;    }}\"] { color: red }");
		// Escaped anything inside an attribute selector. This is allowed.
		CSS2_SELECTOR.put("h1[foo=\"hello\\202 \"] {}", "h1[foo=\"hello\\202 \"] {}");
		// Escaped quotes inside a string inside an attribute selector. This is allowed.
		CSS2_SELECTOR.put("h1[foo=\"\\\"test\\\"\"] {}", "h1[foo=\"\\\"test\\\"\"] {}");
		CSS2_SELECTOR.put("a:focus:hover { background: white;}", "a:focus:hover { background: white;}");
		// Whitespace before > or +, and selector chaining.
		CSS2_SELECTOR.put("h1[foo] h2 > p + b { color: green;}", "h1[foo] h2>p+b { color: green;}");
		CSS2_SELECTOR.put("h1[foo] h2 > p + b:before { color: green;}", "h1[foo] h2>p+b:before { color: green;}");
		CSS2_SELECTOR.put("table          { border-collapse: collapse; border: 5px solid yellow; } *#col1         { border: 3px solid black; } td             { border: 1px solid red; padding: 1em; } td.cell5       { border: 5px dashed blue; } td.cell6       { border: 5px solid green; }",
				"table { border-collapse: collapse; border: 5px solid yellow; } *#col1 { border: 3px solid black; } td { border: 1px solid red; padding: 1em; } td.cell5 { border: 5px dashed blue; } td.cell6 { border: 5px solid green; }");
		CSS2_SELECTOR.put("td { border-right: hidden; border-bottom: hidden }", "td { border-right: hidden; border-bottom: hidden }");


		// CONFORMANCE: We combine pseudo-classes and pseudo-elements, so we allow pseudo-elements on earlier selectors. This is against the spec, CSS2 section 5.10.
	}

	private final static HashSet<String> CSS2_BAD_SELECTOR= new HashSet<String>();
	static
	{
		// Doubled =
		CSS2_BAD_SELECTOR.add("h1[foo=bar=bat] {}");
		CSS2_BAD_SELECTOR.add("h1[foo~=bar~=bat] {}");
		CSS2_BAD_SELECTOR.add("h1[foo|=bar|=bat] {}");
		// Escaping ]
		CSS2_BAD_SELECTOR.add("h1[foo=bar\\] {}");
		CSS2_BAD_SELECTOR.add("h1[foo=\"bar\\] {}");
		// Unclosed string
		CSS2_BAD_SELECTOR.add("h1[foo=\"bar] {}");

		CSS2_BAD_SELECTOR.add("h1:langblahblah(fr) {}");

		// THE FOLLOWING ARE VALID BUT DISALLOWED
		// ] inside string inside attribute selector: way too confusing for parsers.
		// FIXME one day we should escape the ] to make this both valid and easy to parse, rather than dropping it.
		CSS2_BAD_SELECTOR.add("h1[foo=\"bar]\"] {}");
		CSS2_BAD_SELECTOR.add("h1[foo=bar\\]] {}");
		// Closing an escape with \r\n. This is supported by verifying and splitting logic, but not by the tokeniser.
		// FIXME fix this.
		CSS2_BAD_SELECTOR.add("h1[foo=\"hello\\202\r\n\"] {}");
	}


	/** CSS3 Selectors */
	private final static HashMap<String,String> CSS3_SELECTOR= new HashMap<String,String>();
	static
	{
		CSS3_SELECTOR.put("tr:nth-child(odd) { background-color: red; }","tr:nth-child(odd) { background-color: red; }");
		CSS3_SELECTOR.put("tr:nth-child(even) { background-color: yellow; }","tr:nth-child(even) { background-color: yellow; }");
		CSS3_SELECTOR.put("tr:nth-child(1) {}","tr:nth-child(1)");
		CSS3_SELECTOR.put("tr:nth-child(-1) {}","tr:nth-child(-1)");
		CSS3_SELECTOR.put("tr:nth-child(+1) {}","tr:nth-child(+1)");
		CSS3_SELECTOR.put("tr:nth-child(10) {}","tr:nth-child(10)");
		CSS3_SELECTOR.put("tr:nth-child(100) {}","tr:nth-child(100)");
		CSS3_SELECTOR.put("tr:nth-child(n) {}","tr:nth-child(n)");
		CSS3_SELECTOR.put("tr:nth-child(-n) {}","tr:nth-child(-n)");
		CSS3_SELECTOR.put("tr:nth-child(-n+1) {}","tr:nth-child(-n+1)");
		CSS3_SELECTOR.put("tr:nth-child(n-1) {}","tr:nth-child(n-1)");
		CSS3_SELECTOR.put("tr:nth-child(-n-1) {}","tr:nth-child(-n-1)");
		CSS3_SELECTOR.put("tr:nth-child(-2n+1) {}","tr:nth-child(-2n+1)");
		CSS3_SELECTOR.put("tr:nth-child(-2n-1) {}","tr:nth-child(-2n-1)");
		CSS3_SELECTOR.put("tr:nth-child(2n) {}","tr:nth-child(2n)");
		CSS3_SELECTOR.put("tr:nth-child(10n) {}","tr:nth-child(10n)");
		CSS3_SELECTOR.put("tr:nth-child(n+1) {}","tr:nth-child(n+1)");
		CSS3_SELECTOR.put("tr:nth-child(n+10) {}","tr:nth-child(n+10)");
		CSS3_SELECTOR.put("tr:nth-child(2n+1) {}","tr:nth-child(2n+1)");
		CSS3_SELECTOR.put("tr:nth-child(2n-1) {}","tr:nth-child(2n-1)");
		CSS3_SELECTOR.put("tr:nth-child(999999) {}","tr:nth-child(999999)");  // FilterUtils.MAX_NTH
		CSS3_SELECTOR.put("tr:nth-child(-999999) {}","tr:nth-child(-999999)");  // -FilterUtils.MAX_NTH
		CSS3_SELECTOR.put("tr:nth-last-child(1) {}","tr:nth-last-child(1)");
		CSS3_SELECTOR.put("tr:nth-last-child(odd) {}","tr:nth-last-child(odd)");
		CSS3_SELECTOR.put("tr:nth-last-child(even) {}","tr:nth-last-child(even)");
		CSS3_SELECTOR.put("h1:nth-of-type(1) {}","h1:nth-of-type(1)");
		CSS3_SELECTOR.put("h1:nth-of-type(odd) {}","h1:nth-of-type(odd)");
		CSS3_SELECTOR.put("h1:nth-of-type(even) {}","h1:nth-of-type(even)");
		CSS3_SELECTOR.put("h1:nth-last-of-type(1) {}","h1:nth-last-of-type(1)");
		CSS3_SELECTOR.put("h1:nth-last-of-type(odd) {}","h1:nth-last-of-type(odd)");
		CSS3_SELECTOR.put("h1:nth-last-of-type(even) {}","h1:nth-last-of-type(even)");
	}

	private final static HashSet<String> CSS3_BAD_SELECTOR= new HashSet<String>();
	static
	{
		CSS3_BAD_SELECTOR.add("tr:nth-child() {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(-) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(+) {}");
		// an+b only - allow nothing more.
		CSS3_BAD_SELECTOR.add("tr:nth-child(2+n) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(2n+1+1) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(+-2n) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(-+2n) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(2n1) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(n3) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(n+n) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(2n+-1) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(2n-+1) {}");
		// Out of Integer range.
		CSS3_BAD_SELECTOR.add("tr:nth-child(999999999999999) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(1000000) {}");  // FilterUtils.MAX_NTH + 1
		CSS3_BAD_SELECTOR.add("tr:nth-child(-1000000) {}");  // -FilterUtils.MAX_NTH - 1
		CSS3_BAD_SELECTOR.add("tr:nth-child(999999999999999n) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(n+999999999999999) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(999999999999999n+999999999999999) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(999999999999999n-999999999999999) {}");
		// Misbracketing.
		CSS3_BAD_SELECTOR.add("h1:nth-of-type(1 {}");
		CSS3_BAD_SELECTOR.add("h1:nth-of-type(1)) {}");
		CSS3_BAD_SELECTOR.add("h1:nth-of-type((1) {}");
		CSS3_BAD_SELECTOR.add("h1:nth-of-type(n+1 {}");
		CSS3_BAD_SELECTOR.add("h1:nth-of-type(n+1)) {}");
		CSS3_BAD_SELECTOR.add("h1:nth-of-type((n+1) {}");
		CSS3_BAD_SELECTOR.add("h1:nth-of-type)n+1( {}");
		CSS3_BAD_SELECTOR.add("h1:nth-of-type)(n+1)( {}");
		// Invalid whitespace.
		CSS3_BAD_SELECTOR.add("tr:nth-child(2 n) {}");
		// Whitespace not supported at all.
		CSS3_BAD_SELECTOR.add("tr:nth-child( n+2) {}");
		CSS3_BAD_SELECTOR.add("tr:nth-child(n + 2) {}");
	}

	private static final String CSS_STRING_NEWLINES = "* { content: \"this string does not terminate\n}\nbody {\nbackground: url(http://www.google.co.uk/intl/en_uk/images/logo.gif); }\n\" }";
	private static final String CSS_STRING_NEWLINESC = "* {}\nbody { }\n";

	private static final String CSS_BACKGROUND_URL = "* { background: url(/SSK@qd-hk0vHYg7YvK2BQsJMcUD5QSF0tDkgnnF6lnWUH0g,xTFOV9ddCQQk6vQ6G~jfL6IzRUgmfMcZJ6nuySu~NUc,AQACAAE/activelink-index-text-76/activelink.png); }";
	private static final String CSS_BACKGROUND_URLC = "* { background: url(\"/SSK@qd-hk0vHYg7YvK2BQsJMcUD5QSF0tDkgnnF6lnWUH0g,xTFOV9ddCQQk6vQ6G~jfL6IzRUgmfMcZJ6nuySu~NUc,AQACAAE/activelink-index-text-76/activelink.png\"); }";

	private static final String CSS_LCASE_BACKGROUND_URL = "* { background: url(/ssk@qd-hk0vHYg7YvK2BQsJMcUD5QSF0tDkgnnF6lnWUH0g,xTFOV9ddCQQk6vQ6G~jfL6IzRUgmfMcZJ6nuySu~NUc,AQACAAE/activelink-index-text-76/activelink.png); }\n";
	private static final String CSS_LCASE_BACKGROUND_URLC = "* { background: url(\"/SSK@qd-hk0vHYg7YvK2BQsJMcUD5QSF0tDkgnnF6lnWUH0g,xTFOV9ddCQQk6vQ6G~jfL6IzRUgmfMcZJ6nuySu~NUc,AQACAAE/activelink-index-text-76/activelink.png\"); }\n";

	// not adding ?type=text/css is exploitable, so check for it.
	private static final String CSS_IMPORT = "  @import url(\"/KSK@test\");\n@import url(\"/KSK@test2\");";
	private static final String CSS_IMPORTC = "  @import url(\"/KSK@test?type=text/css&maybecharset=UTF-8\");\n@import url(\"/KSK@test2?type=text/css&maybecharset=UTF-8\");";

	private static final String CSS_IMPORT_TYPE = "@import url(\"/KSK@test?type=text/plain\");";
	private static final String CSS_IMPORT_TYPEC = "@import url(\"/KSK@test?type=text/css&maybecharset=UTF-8\");";

	private static final String CSS_IMPORT2 = "@import url(\"/chk@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/1-1.html\") screen;";
	private static final String CSS_IMPORT2C = "@import url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/1-1.html?type=text/css&maybecharset=UTF-8\") screen;";

	private static final String CSS_IMPORT_MULTI_MEDIA = "@import url(\"/chk@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/1-1.html\") projection, tv;";
	private static final String CSS_IMPORT_MULTI_MEDIAC = "@import url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/1-1.html?type=text/css&maybecharset=UTF-8\") projection, tv;";

	private static final String CSS_IMPORT_MULTI_MEDIA_BOGUS = "@import url(\"/chk@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/1-1.html\") projection, tvvv;";
	private static final String CSS_IMPORT_MULTI_MEDIA_BOGUSC = "@import url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/1-1.html?type=text/css&maybecharset=UTF-8\") projection;";

	private static final String CSS_IMPORT_MULTI_MEDIA_ALL = "@import url(\"/chk@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/1-1.html\") all;";
	private static final String CSS_IMPORT_MULTI_MEDIA_ALLC = "@import url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/1-1.html?type=text/css&maybecharset=UTF-8\") all;";

	private static final String CSS_IMPORT_SPACE_IN_STRING = "@import url(\"/chk@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test page\") screen;";
	private static final String CSS_IMPORT_SPACE_IN_STRINGC = "@import url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page?type=text/css&maybecharset=UTF-8\") screen;";

	private static final String CSS_IMPORT_QUOTED_STUFF = "@import url(\"/chk@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test page \\) \\\\ \\\' \\\" \") screen;";
	private static final String CSS_IMPORT_QUOTED_STUFFC = "@import url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page%20%29%20%5c%20%27%20%22%20?type=text/css&maybecharset=UTF-8\") screen;";

	private static final String CSS_IMPORT_QUOTED_STUFF2 = "@import url(/chk@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test page \\) \\\\ \\\' \\\" ) screen;";
	private static final String CSS_IMPORT_QUOTED_STUFF2C = "@import url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page%20%29%20%5c%20%27%20%22?type=text/css&maybecharset=UTF-8\") screen;";

	private static final String CSS_IMPORT_NOURL_TWOMEDIAS = "@import \"/chk@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/1-1.html\" screen tty;";
	private static final String CSS_IMPORT_NOURL_TWOMEDIASC = "@import url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/1-1.html?type=text/css&maybecharset=UTF-8\") screen, tty;";

	private static final String CSS_IMPORT_BRACKET = "@import url(\"/KSK@thingy\\)\");";
	private static final String CSS_IMPORT_BRACKETC = "@import url(\"/KSK@thingy%29?type=text/css&maybecharset=UTF-8\");";

	// Unquoted URL is invalid.
	private static final String CSS_IMPORT_UNQUOTED = "@import style.css;";

	private static final String CSS_LATE_IMPORT = "@import \"subs.css\";\nh1 { color: blue;}\n@import \"list.css\";";
	private static final String CSS_LATE_IMPORTC = "@import url(\"subs.css?type=text/css&maybecharset=UTF-8\");\nh1 { color: blue;}\n";

	private static final String CSS_LATE_IMPORT2 = "@import \"subs.css\";\n@media print {\n@import \"print-main.css\";\n\n}\nh1 { color: blue }";
	private static final String CSS_LATE_IMPORT2C = "@import url(\"subs.css?type=text/css&maybecharset=UTF-8\");\n@media print {}\nh1 { color: blue }";

	private static final String CSS_LATE_IMPORT3 = "@import \"subs.css\";\n@media print {\n@import \"print-main.css\";\nbody { font-size: 10pt;}\n}\nh1 { color: blue }";
	private static final String CSS_LATE_IMPORT3C = "@import url(\"subs.css?type=text/css&maybecharset=UTF-8\");\n@media print {}\nh1 { color: blue }";

	// Quoted without url() is valid.
	private static final String CSS_IMPORT_NOURL = "@import \"style.css\";";
	private static final String CSS_IMPORT_NOURLC = "@import url(\"style.css?type=text/css&maybecharset=UTF-8\");";

	private static final String CSS_ESCAPED_LINK = "* { background: url(\\00002f\\00002fwww.google.co.uk/intl/en_uk/images/logo.gif); }\n";
	private static final String CSS_ESCAPED_LINKC = "* { }\n";

	private static final String CSS_ESCAPED_LINK2 = "* { background: url(\\/\\/www.google.co.uk/intl/en_uk/images/logo.gif); }\n";
	private static final String CSS_ESCAPED_LINK2C = "* { }\n";

	// CSS2.1 spec, 4.1.7
	private static final String CSS_DELETE_INVALID_SELECTOR = "h1, h2 {color: green }\nh3, h4 & h5 {color: red }\nh6 {color: black }\n";
	private static final String CSS_DELETE_INVALID_SELECTORC = "h1, h2 {color: green }\nh6 {color: black }\n";

	private static final String LATE_CHARSET = "h3 { color:red;}\n@charset \"UTF-8\";";
	private static final String LATE_CHARSETC = "h3 { color:red;}\n";

	private static final String WRONG_CHARSET = "@charset \"UTF-16\";";
	private static final String NONSENSE_CHARSET = "@charset \"idiot\";";

	private static final String LATE_BOM = "h3 { color:red;}\n\ufeffh4 { color:blue;}";
	private static final String LATE_BOMC = "h3 { color:red;}\nh4 { color:blue;}";

	private static final String BOM = "\ufeffh3 { color:red;}";

	private static final String COMMENT = "/* this is a comment */h1 { color: red;}";
	private static final String COMMENTC = "h1 { color: red;}";

	private static final String CSS_COMMA_WHITESPACE = "body { padding: 0px;\n}\n\nh1, h2, h3 {\nmargin: 0px;\n}";

	private static final String CSS_BOGUS_AT_RULE = "@three-dee { h3 { color: red;} }\nh1 { color: blue;}";
	private static final String CSS_BOGUS_AT_RULEC = "\nh1 { color: blue;}";

	private static final String PRESERVE_CDO_CDC = "<!-- @import url(\"style.css\");\n<!-- @media screen { <!-- h3 { color: red;} } -->";
	private static final String PRESERVE_CDO_CDCC = "<!-- @import url(\"style.css?type=text/css&maybecharset=UTF-8\");\n<!-- @media screen { <!-- h3 { color: red;}} -->";

	private static final String BROKEN_BEFORE_IMPORT = "@import \"test\n@import \"test.css\";\n@import \"test2.css\";";
	private static final String BROKEN_BEFORE_IMPORTC = "\n@import url(\"test2.css?type=text/css&maybecharset=UTF-8\");";

	private static final String BROKEN_BEFORE_MEDIA = "@import \"test\n@media all { * { color: red }} @media screen { h1 { color: blue }}";
	private static final String BROKEN_BEFORE_MEDIAC = " @media screen { h1 { color: blue }}";

	// Invalid media type

	private static final String CSS_INVALID_MEDIA_CASCADE = "@media blah { h1, h2 { color: green;} }";

	private final static LinkedHashMap<String, String> propertyTests = new LinkedHashMap<String, String>();
	static {
		// Check that the last part of a double bar works
		propertyTests.put("@media speech { h1 { azimuth: behind }; }", "@media speech { h1 { azimuth: behind }}");

		propertyTests.put("h1 { color: red; rotation: 70minutes }", "h1 { color: red; }");
		propertyTests.put("@media screen { h1 { color: red; }\nh1[id=\"\n]}", "@media screen { h1 { color: red; }}");
		propertyTests.put("@media screen { h1 { color: red; }}", "@media screen { h1 { color: red; }}");
		propertyTests.put("p { color: green;\nfont-family: 'Courier New Times\ncolor: red;\ncolor: green;\n}", "p { color: green;\ncolor: green;\n}");
		propertyTests.put("p { font-family: 'Courier New Times\ncolor: red;\ncolor: green;\n}", "p {\ncolor: green;\n}");
		propertyTests.put("@media screen { h1[id=\"\n]}", "@media screen {}");
		propertyTests.put("img { float: left }", "img { float: left }");
		propertyTests.put("img { float: left here }", "img { }");
		propertyTests.put("img { background: \"red\" }", "img { }");
		propertyTests.put("img { border-width: 3 }", "img { }");
		// 4.2 Malformed declarations
		propertyTests.put("p { color:green }", "p { color:green }");
		propertyTests.put("p { color:green; color }", "p { color:green;  }");
		propertyTests.put("p { color:green; color: }", "p { color:green; }");
		propertyTests.put("p { color:red;   color:; color:green }", "p { color:red; color:green }");
		propertyTests.put("p { color:green; color{;color:maroon} }", "p { color:green;  }");
		// 4.2 Malformed statements, with a valid rule added on
		propertyTests.put("p @here {color: red}\ntd { color:red;}", "\ntd { color:red;}");
		propertyTests.put("@foo @bar;\ntd { color:red;}", "\ntd { color:red;}");
		propertyTests.put("}} {{ - }}", "");
		propertyTests.put(") ( {} ) p {color: red }", "");
		propertyTests.put(") ( {} ) p {color: red }\ntd { color:red;}", "\ntd { color:red;}");

		propertyTests.put("td { background-position:bottom;}\n", "td { background-position:bottom;}\n");
		propertyTests.put("td { background:repeat-x;}\n", "td { background:repeat-x;}\n");
		propertyTests.put("td { background: scroll transparent url(\"something.png\") }\n", "td { background: scroll transparent url(\"something.png\") }\n");
		propertyTests.put("td { background: scroll transparent url(\"something.png\") right }\n", "td { background: scroll transparent url(\"something.png\") right }\n");
		propertyTests.put("td { background: scroll transparent url(\"something.png\") right top }\n", "td { background: scroll transparent url(\"something.png\") right top }\n");
		propertyTests.put("td { background: scroll transparent url(\"something.png\") right top repeat }\n", "td { background: scroll transparent url(\"something.png\") right top repeat }\n");
		// Broken - extra slot at end, double bar only matches one element for each.
		propertyTests.put("td { background: scroll transparent url(\"something.png\") right top repeat url(\"something-else.png\") }\n", "td { }\n");

		// Double bar: recurse after recognising last element
		propertyTests.put("td { background:repeat-x none;}\n", "td { background:repeat-x none;}\n");
		propertyTests.put("td { background:repeat-x none transparent;}\n", "td { background:repeat-x none transparent;}\n");
		propertyTests.put("td { background:repeat-x none transparent scroll;}\n", "td { background:repeat-x none transparent scroll;}\n");

		propertyTests.put("td { background-position: bottom right }\n", "td { background-position: bottom right }\n");
		propertyTests.put("td { background-position: bottom right center }\n", "td { }\n");

		// Typo should not cause it to throw!
		propertyTests.put("td { background:no;}\n", "td {}\n");
		// This one was throwing NumberFormatException in double bar verifier
		propertyTests.put("td { background:repeat-x no;}\n", "td {}\n");
		propertyTests.put("td { background:repeat-x no transparent;}\n", "td {}\n");
		propertyTests.put("td { background:repeat-x no transparent scroll;}\n", "td {}\n");

		propertyTests.put("@media speech { h1 { azimuth: 30deg }; }", "@media speech { h1 { azimuth: 30deg }}");
		propertyTests.put("@media speech { h1 { azimuth: 0.877171rad }; }", "@media speech { h1 { azimuth: 0.877171rad }}");
		propertyTests.put("@media speech { h1 { azimuth: left-side behind }; }", "@media speech { h1 { azimuth: left-side behind }}");
		// Invalid combination
		propertyTests.put("@media speech { h1 { azimuth: left-side behind 30deg }; }", "@media speech { h1 { }}");
		propertyTests.put("@media speech { h1 { azimuth: inherit }; }", "@media speech { h1 { azimuth: inherit }}");
		// Wrong media type
		propertyTests.put("h1 { azimuth: inherit }", "h1 { }");

		// Partially bogus media
		propertyTests.put("@media screen, 3D {\n  P { color: green; }\n}", "@media screen {\n  P { color: green; }}");
		propertyTests.put("@media screen, tv {\n  P { color: green; }\n}", "@media screen, tv {\n  P { color: green; }}");

		propertyTests.put("td { background-attachment: scroll}", "td { background-attachment: scroll}");
		propertyTests.put("td { background-color: rgb(255, 255, 255)}", "td { background-color: rgb(255, 255, 255)}");
		propertyTests.put("td { background-color: #fff}", "td { background-color: #fff}");
		propertyTests.put("td { background-color: #ffffff}", "td { background-color: #ffffff}");
		propertyTests.put("td { background-color: rgb(100%,0%,50%)}", "td { background-color: rgb(100%,0%,50%)}");
		propertyTests.put("td { background-color: rgb(100%, 0%, 50%)}", "td { background-color: rgb(100%, 0%, 50%)}");
		// Values outside the standard RGB device gamut are allowed by the spec, they will be clipped and may be representible on some devices.
		propertyTests.put("td { background-color: rgb(300, 0, 0)}", "td { background-color: rgb(300, 0, 0)}");
		propertyTests.put("td { background-color: rgb(255, -10, 0)}", "td { background-color: rgb(255, -10, 0)}");
		propertyTests.put("td { background-color: rgb(110%, 0%, 0%)}", "td { background-color: rgb(110%, 0%, 0%)}");
		propertyTests.put("td { background-color: rgb(5.5%, -100%, 0%)}", "td { background-color: rgb(5.5%, -100%, 0%)}");

		// Invalid element
		propertyTests.put("silly { background-attachment: scroll}", "");
		// Percentage in background-position
		propertyTests.put("h3 { background-position: 30% top}", "h3 { background-position: 30% top}");
		propertyTests.put("h3 { background-position: 120% top}", "h3 { background-position: 120% top}");
		propertyTests.put("h3 { background-position: 8.5% top}", "h3 { background-position: 8.5% top}");
		propertyTests.put("p { line-height: 120% }", "p { line-height: 120% }");
		// Fractional lengths
		propertyTests.put("h3 { background-position: 3.3cm 20%}", "h3 { background-position: 3.3cm 20%}");
		// Negative fractional lengths
		propertyTests.put("h3 { background-position: -0.87em 20%}", "h3 { background-position: -0.87em 20%}");

		// Urls
		propertyTests.put("li { list-style: url(/KSK@redball.png) disc}", "li { list-style: url(\"/KSK@redball.png\") disc}");

		// Url with an encoded space
		propertyTests.put("h3 { background-image: url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }", "h3 { background-image: url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }");
		// Url with a space
		propertyTests.put("h3 { background-image: url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test page\") }", "h3 { background-image: url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }");
		// Url with lower case chk@
		propertyTests.put("h3 { background-image: url(\"/chk@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }", "h3 { background-image: url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }");

		// url without "" in properties
		propertyTests.put("h3 { background-image: url(/chk@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page) }", "h3 { background-image: url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }");

		// Escapes in strings
		propertyTests.put("h3 { background-image: url(/KSK@\\something.png);}", "h3 { background-image: url(\"/KSK@something.png\");}");
		propertyTests.put("h3 { background-image: url(/KSK@\\something.png?type=image/png\\26 force=true);}", "h3 { background-image: url(\"/KSK@something.png?type=image/png\");}");
		propertyTests.put("h3 { background-image: url(/KSK@\\something.png?type=image/png\\000026force=true);}", "h3 { background-image: url(\"/KSK@something.png?type=image/png\");}");
		propertyTests.put("h3 { background-image: url(/KSK@\\\"something\\\".png?type=image/png\\000026force=true);}", "h3 { background-image: url(\"/KSK@%22something%22.png?type=image/png\");}");
		// urls with whitespace after url(
		propertyTests.put("h3 { background-image: url( /KSK@\\\"something\\\".png?type=image/png\\000026force=true );}", "h3 { background-image: url(\"/KSK@%22something%22.png?type=image/png\");}");
		propertyTests.put("h3 { background-image: url( \"/KSK@\\\"something\\\".png?type=image/png\\000026force=true\" );}", "h3 { background-image: url(\"/KSK@%22something%22.png?type=image/png\");}");

		// Invalid because sabotages tokenisation with the standard grammar (CSS2.1 4.3.4)
		propertyTests.put("h3 { background-image: url(/KSK@));}", "h3 {}");
		propertyTests.put("h3 { background-image: url(/KSK@');}", "h3 {} ");
		propertyTests.put("h3 { background-image: url(/KSK@\");}", "h3 {} ");
		propertyTests.put("h3 { background-image: url(/KSK@ test ));}", "h3 {}");
		// This *is* valid.
		propertyTests.put("h3 { background-image: url(/KSK@ );}", "h3 { background-image: url(\"/KSK@\");}");

		// Quoting the wierd bits
		propertyTests.put("h3 { background-image: url(/KSK@\\));}", "h3 { background-image: url(\"/KSK@%29\");}");
		propertyTests.put("h3 { background-image: url(/KSK@\\');}", "h3 { background-image: url(\"/KSK@%27\");}");
		propertyTests.put("h3 { background-image: url(/KSK@\\\");}", "h3 { background-image: url(\"/KSK@%22\");}");
		propertyTests.put("h3 { background-image: url(/KSK@\\ );}", "h3 { background-image: url(\"/KSK@%20\");}");
		// Valid in quoted URLs
		propertyTests.put("h3 { background-image: url(\"/KSK@)\");}", "h3 { background-image: url(\"/KSK@%29\");}");
		propertyTests.put("h3 { background-image: url(\"/KSK@'\");}", "h3 { background-image: url(\"/KSK@%27\");}");
		propertyTests.put("h3 { background-image: url(\"/KSK@\\\"\");}", "h3 { background-image: url(\"/KSK@%22\");}");
		propertyTests.put("h3 { background-image: url(\"/KSK@ \");}", "h3 { background-image: url(\"/KSK@%20\");}");


		// Mixed background
		propertyTests.put("h3 { background: url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }", "h3 { background: url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }");
		// CSS is case insensitive except for parts not under CSS control.
		propertyTests.put("h3 { BACKGROUND: URL(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }", "h3 { BACKGROUND: URL(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }");
		propertyTests.put("h3 { BACKGROUND: URL(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test page\") }", "h3 { BACKGROUND: url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }");
		// HTML tags are case insensitive, but we downcase them.
		propertyTests.put("H3 { BACKGROUND: URL(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test page\") }", "H3 { BACKGROUND: url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }");
		propertyTests.put("h3 { background: scroll url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }", "h3 { background: scroll url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }");
		propertyTests.put("h3 { background: scroll #f00 url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }", "h3 { background: scroll #f00 url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }");
		propertyTests.put("h3 { background: scroll #f00 url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }", "h3 { background: scroll #f00 url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }");
		propertyTests.put("h3 { background: scroll rgb(100%, 2%, 1%) url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }", "h3 { background: scroll rgb(100%, 2%, 1%) url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }");
		propertyTests.put("h3 { background: 3.3cm 20%;}", "h3 { background: 3.3cm 20%;}");
		propertyTests.put("h3 { background: scroll 3.3cm 20%;}", "h3 { background: scroll 3.3cm 20%;}");
		propertyTests.put("h3 { background: scroll rgb(100%, 2%, 1%) 3.3cm 20%;}", "h3 { background: scroll rgb(100%, 2%, 1%) 3.3cm 20%;}");
		propertyTests.put("h3 { background: 3.3cm 20% url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\");}", "h3 { background: 3.3cm 20% url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\");}");
		propertyTests.put("h3 { background: scroll rgb(100%, 2%, 1%) 3.3cm 20% url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }", "h3 { background: scroll rgb(100%, 2%, 1%) 3.3cm 20% url(\"/CHK@~~vxVQDfC9m8sR~M9zWJQKzCxLeZRWy6T1pWLM2XX74,2LY7xwOdUGv0AeJ2WKRXZG6NmiUL~oqVLKnh3XdviZU,AAIC--8/test%20page\") }");
		// CSS escapes, url escapes, combinations of the two
		propertyTests.put("h3 { background: url(\"\\/\\/www.google.com/google.png\");}", "h3 {}");
		propertyTests.put("h3 { background: url(\"\\2f \\2f www.google.com/google.png\");}", "h3 {}");
		propertyTests.put("h3 { background: url(\"\\00002f\\00002fwww.google.com/google.png\");}", "h3 {}");
		propertyTests.put("h3 { background: url(\"%2f%2fwww.google.com/google.png\");}", "h3 {}");
		propertyTests.put("h3 { background: url(\"\\25 2f\\25 2fwww.google.com/google.png\");}", "h3 {}");

		// Counters
		propertyTests.put("table { counter-increment: counter1 1}", "table { counter-increment: counter1 1}");
		// Counters with whacky identifiers
		propertyTests.put("table { counter-increment: \u0202ounter1 1}", "table { counter-increment: \u0202ounter1 1}");
		propertyTests.put("table { counter-increment: \\202 ounter1 1}", "table { counter-increment: \\202 ounter1 1}");
		propertyTests.put("table { counter-increment: c\\ounter1 1}", "table { counter-increment: c\\ounter1 1}");
		propertyTests.put("table { counter-increment: c\\ ounter1 1}", "table { counter-increment: c\\ ounter1 1}");
		propertyTests.put("table { counter-increment: c\\ \\}ounter1 1}", "table { counter-increment: c\\ \\}ounter1 1}");
		propertyTests.put("table { counter-increment: c\\ \\}oun\\:ter1 1}", "table { counter-increment: c\\ \\}oun\\:ter1 1}");
		propertyTests.put("table { counter-increment: c\\ \\}oun\\:ter1\\; 1}", "table { counter-increment: c\\ \\}oun\\:ter1\\; 1}");
		propertyTests.put("table { counter-increment: \\2 \\32 \\ c\\ \\}oun\\:ter1\\; 1}", "table { counter-increment: \\2 \\32 \\ c\\ \\}oun\\:ter1\\; 1}");
		propertyTests.put("table { counter-increment: \\000032\\2 \\32 \\ c\\ \\}oun\\:ter1\\; 1}", "table { counter-increment: \\000032\\2 \\32 \\ c\\ \\}oun\\:ter1\\; 1}");

		// Varying the number of words matched by each occurrence in a double bar.
		propertyTests.put("table { counter-reset: mycounter 1 hiscounter myothercounter 2;}", "table { counter-reset: mycounter 1 hiscounter myothercounter 2;}");

		// Content tests
		propertyTests.put("h1 { content: \"string with spaces\" }", "h1 { content: \"string with spaces\" }");
		propertyTests.put("h1 { content: attr(\\ \\ attr\\ with\\ spaces) }", "h1 { content: attr(\\ \\ attr\\ with\\ spaces) }");
		propertyTests.put("h1 { content: \"string with spaces\" attr(\\ \\ attr\\ with\\ spaces) }", "h1 { content: \"string with spaces\" attr(\\ \\ attr\\ with\\ spaces) }");
		propertyTests.put("h1 { content: \"string with curly brackets { }\";}", "h1 { content: \"string with curly brackets { }\";}");
		propertyTests.put("h1 { content: \"\\\"\";}", "h1 { content: \"\\\"\";}");
		// Invalid escapes in a string
		propertyTests.put("h1 { content: \"\\1\";}", "h1 {}");
		propertyTests.put("h1 { content: \"\\f\";}", "h1 {}");
		propertyTests.put("h1 { content: \"\\\n\";}", "h1 {}");
		propertyTests.put("h1 { content: \"\\\r\";}", "h1 {}");
		propertyTests.put("h1 { content: \"\\\f\";}", "h1 {}");
		// Valid escapes in a string
		propertyTests.put("h1 { content: \"\\202 \";}", "h1 { content: \"\\202 \";}");
		propertyTests.put("h1 { content: \"\\g \";}", "h1 { content: \"\\g \";}");
		propertyTests.put("h1 { content: \"\\\t \";}", "h1 { content: \"\\\t \";}");
		propertyTests.put("h1 { content: \"\\} \";}", "h1 { content: \"\\} \";}");
		// Valid escapes in an identifier
		propertyTests.put("h1 { content: attr(\\202 \\ test);}", "h1 { content: attr(\\202 \\ test);}");
		propertyTests.put("h1 { content: attr(\\000202\\ test);}", "h1 { content: attr(\\000202\\ test);}");
		propertyTests.put("h1 { content: attr(\\;\\ test);}", "h1 { content: attr(\\;\\ test);}");
		propertyTests.put("h1 { content: attr(\\}\\ test);}", "h1 { content: attr(\\}\\ test);}");
		// Refer to counters
		propertyTests.put("h1 { content: counter(\\202 \\ \\test, none);}", "h1 { content: counter(\\000202\\000020test, none);}");
		propertyTests.put("h1:before {content: counter(chapno, upper-roman) \". \"}", "h1:before {content: counter(chapno, upper-roman) \". \"}");
		propertyTests.put("p.special:before {content: \"Special! \"}", "p.special:before {content: \"Special! \"}");

		// Strip nulls
		propertyTests.put("h2 { color: red }", "h2 { color: red }");
		propertyTests.put("h2 { color: red\0 }", "h2 { color: red }");

		// Lengths must have a unit
		propertyTests.put("h2 { border-width: 1.5em;}\n","h2 { border-width: 1.5em;}\n");
		propertyTests.put("h2 { border-width: 12px;}\n","h2 { border-width: 12px;}\n");
		propertyTests.put("h2 { border-width: -12px;}\n","h2 { border-width: -12px;}\n");
		propertyTests.put("h2 { border-width: 1.5;}\n","h2 {}\n");
		propertyTests.put("h2 { border-width: 0;}\n","h2 { border-width: 0;}\n");
		propertyTests.put("h2 { border-width: 10;}\n","h2 {}\n");
		propertyTests.put("h1 { margin: 0.5em;}", "h1 { margin: 0.5em;}");
		propertyTests.put("h1 { margin: 1ex;}", "h1 { margin: 1ex;}");
		propertyTests.put("p { font-size: 12px;}", "p { font-size: 12px;}");
		propertyTests.put("h3 { word-spacing: 4mm }", "h3 { word-spacing: 4mm }");
		// CSS 3.0 Length units (ch, rem, vw, vh, vmin, vmax)
		propertyTests.put("img { max-height: 12ch;}\n","img { max-height: 12ch;}\n");
		propertyTests.put("img { max-height: 12rem;}\n","img { max-height: 12rem;}\n");
		propertyTests.put("img { max-height: 12vw;}\n","img { max-height: 12vw;}\n");
		propertyTests.put("img { max-height: 12vh}\n","img { max-height: 12vh}\n");
		propertyTests.put("img { max-height: 12vmin }\n","img { max-height: 12vmin }\n");
		propertyTests.put("img { max-height: 1.2vmax }\n","img { max-height: 1.2vmax }\n");

		// Fonts
		propertyTests.put("h2 { font-family: times new roman;}\n", "h2 { font-family: times new roman;}\n");
		propertyTests.put("h2 { font-family: Times New Roman;}\n", "h2 { font-family: Times New Roman;}\n");
		propertyTests.put("h2 { font-family: \"Times New Roman\";}\n", "h2 { font-family: \"Times New Roman\";}\n");
		propertyTests.put("h2 { font-family: inherit;}\n", "h2 { font-family: inherit;}\n");
		propertyTests.put("h2 { font-family: \"Times New Roman\" , \"Arial\";}\n","h2 { font-family: \"Times New Roman\" , \"Arial\";}\n");
		propertyTests.put("h2 { font-family: \"Times New Roman\", \"Arial\";}\n","h2 { font-family: \"Times New Roman\", \"Arial\";}\n");
		propertyTests.put("h2 { font-family: \"Times New Roman\", \"Arial\", \"Helvetica\";}\n","h2 { font-family: \"Times New Roman\", \"Arial\", \"Helvetica\";}\n");
		propertyTests.put("h2 { font-family: \"Times New Roman\", Arial;}\n","h2 { font-family: \"Times New Roman\", Arial;}\n");
		propertyTests.put("h2 { font-family: Times New Roman, Arial;}\n","h2 { font-family: Times New Roman, Arial;}\n");
		propertyTests.put("h2 { font-family: serif, Times New Roman, Arial;}\n","h2 { font-family: serif, Times New Roman, Arial;}\n");
		propertyTests.put("h2 { font: Times New Roman;}\n", "h2 { font: Times New Roman;}\n");
		propertyTests.put("h2 { font: \"Times New Roman\";}\n", "h2 { font: \"Times New Roman\";}\n");
		propertyTests.put("h2 { font: medium \"Times New Roman\";}\n", "h2 { font: medium \"Times New Roman\";}\n");
		propertyTests.put("h2 { font: medium Times New Roman, Arial Black;}\n", "h2 { font: medium Times New Roman, Arial Black;}\n");
		propertyTests.put("h2 { font: italic small-caps 500 1.5em Times New Roman, Arial Black;}\n", "h2 { font: italic small-caps 500 1.5em Times New Roman, Arial Black;}\n");
		propertyTests.put("h2 { font: 1.5em/12pt Times New Roman, Arial Black;}\n", "h2 { font: 1.5em/12pt Times New Roman, Arial Black;}\n");
		propertyTests.put("h2 { font: small-caps 1.5em/12pt Times New Roman, Arial Black;}\n", "h2 { font: small-caps 1.5em/12pt Times New Roman, Arial Black;}\n");
		propertyTests.put("h2 { font: 500 1.5em/12pt Times New Roman, Arial Black;}\n", "h2 { font: 500 1.5em/12pt Times New Roman, Arial Black;}\n");
		propertyTests.put("h2 { font: small-caps 500 1.5em/12pt Times New Roman, Arial Black;}\n", "h2 { font: small-caps 500 1.5em/12pt Times New Roman, Arial Black;}\n");
		propertyTests.put("h2 { font: 500 \"Times New Roman\";}\n", "h2 { font: 500 \"Times New Roman\";}\n");
		propertyTests.put("h2 { font-weight: 500;}\n", "h2 { font-weight: 500;}\n");
		propertyTests.put("h2 { font: normal \"Times New Roman\";}\n", "h2 { font: normal \"Times New Roman\";}\n");
		propertyTests.put("h2 { font: 500 normal \"Times New Roman\";}\n", "h2 { font: 500 normal \"Times New Roman\";}\n");
		propertyTests.put("h2 { font: 500 normal Times New Roman;}\n", "h2 { font: 500 normal Times New Roman;}\n");
		propertyTests.put("h2 { font: 500 normal Times New Roman, Arial Black;}\n", "h2 { font: 500 normal Times New Roman, Arial Black;}\n");
		propertyTests.put("h2 { font: 500 normal 1.5em/12pt Times New Roman, Arial Black;}\n", "h2 { font: 500 normal 1.5em/12pt Times New Roman, Arial Black;}\n");
		propertyTests.put("h2 { font: small-caps 500 normal 1.5em/12pt Times New Roman, Arial Black;}\n", "h2 { font: small-caps 500 normal 1.5em/12pt Times New Roman, Arial Black;}\n");
		// There was a point where this worked, it's wrong.
		propertyTests.put("h2 { font: times 10pt new roman;}\n", "h2 {}\n");
		propertyTests.put("h2 { font: 10pt times new roman;}\n", "h2 { font: 10pt times new roman;}\n");

		// Space is not required either after or before comma!
		propertyTests.put("h2 { font-family: Verdana,sans-serif }", "h2 { font-family: Verdana,sans-serif }");
		// Case in generic keywords
		propertyTests.put("h2 { font-family: Verdana,Sans-Serif }", "h2 { font-family: Verdana,Sans-Serif }");
		// This one is from the text Activelink Index
		propertyTests.put("h2 { font: normal 12px/15px Verdana,sans-serif }", "h2 { font: normal 12px/15px Verdana,sans-serif }");
		// From Activelink Index. This is invalid but browsers will probably change sans to sans-serif; and we will allow it as it might be a generic font family.
		propertyTests.put("h2 { font:normal 12px/15px Verdana,sans}", "h2 { font:normal 12px/15px Verdana,sans}");
		// Some fonts that are not on the list but are syntactically valid
		propertyTests.put("h2 { font-family: Times New Reman;}\n", "h2 { font-family: Times New Reman;}\n");
		propertyTests.put("h2 { font-family: \"Times New Reman\";}\n", "h2 { font-family: \"Times New Reman\";}\n");
		propertyTests.put("h2 { font: Times New Reman;}\n", "h2 { font: Times New Reman;}\n");
		propertyTests.put("h2 { font-family: zaphod beeblebrox,bitstream vera sans,arial,sans-serif}", "h2 { font-family: zaphod beeblebrox,bitstream vera sans,arial,sans-serif}");
		// NOT syntactically valid
		propertyTests.put("h2 { font-family: http://www.badguy.com/myfont.ttf}", "h2 {}");
		propertyTests.put("h2 { font-family: times new roman,arial,verdana }", "h2 { font-family: times new roman,arial,verdana }");
		// Misc
		propertyTests.put("h2 {\n  font-weight: bold;\n  font-size: 12px;\n  line-height: 14px;\n  font-family: Helvetica;\n  font-variant: normal;\n  font-style: normal\n}", "h2 {\n  font-weight: bold;\n  font-size: 12px;\n  line-height: 14px;\n  font-family: Helvetica;\n  font-variant: normal;\n  font-style: normal\n}");
		propertyTests.put("h1 { color: red; font-style: 12pt }", "h1 { color: red; }");
		propertyTests.put("p { color: blue; font-vendor: any;\n    font-variant: small-caps }", "p { color: blue;\n    font-variant: small-caps }");
		propertyTests.put("em em { font-style: normal }", "em em { font-style: normal }");

		// voice-family
		propertyTests.put("@media aural { p[character=romeo]\n     { voice-family: \"Laurence Olivier\", charles, male }}", "@media aural { p[character=romeo] { voice-family: \"Laurence Olivier\", charles, male }}");

		// Short percentage value
		propertyTests.put("body { bottom: 1%;}", "body { bottom: 1%;}");
		// Shape
		propertyTests.put("p { clip: rect(5px, 40px, 45px, 5px); }", "p { clip: rect(5px, 40px, 45px, 5px); }");
		propertyTests.put("p { clip: rect(auto, auto, 45px, 5px); }", "p { clip: rect(auto, auto, 45px, 5px); }");

		// play-during
		propertyTests.put("@media speech { blockquote.sad { play-during: url(\"violins.aiff\") }}", "@media speech { blockquote.sad { play-during: url(\"violins.aiff\") }}");
		propertyTests.put("@media speech { blockquote Q   { play-during: url(\"harp.wav\") mix }}", "@media speech { blockquote Q { play-during: url(\"harp.wav\") mix }}");
		propertyTests.put("@media speech { span.quiet     { play-during: none } }", "@media speech { span.quiet { play-during: none }}");

		// Grandchildren
		propertyTests.put("div { color: red;}", "div { color: red;}");
		propertyTests.put("div * { color: red;}", "div * { color: red;}");
		propertyTests.put("div * p { color: red;}", "div * p { color: red;}");
		propertyTests.put("div * p[href] { color: red;}", "div * p[href] { color: red;}");
		propertyTests.put("div p *[href] { color: red;}", "div p *[href] { color: red;}");

		// Quotes not allowed around keywords
		propertyTests.put("* { width: \"auto\";}", "* {}");
		propertyTests.put("* { border: \"none\";}", "* {}");
		propertyTests.put("* { background: \"red\";}", "* {}");

		// Keywords may not be quoted
		propertyTests.put("* { color: r\\ed; }", "* { }");
		propertyTests.put("* { width: au\\to }", "* { }");

		// Block parsing error handling
		propertyTests.put("* { causta: \"}\" + ({7} * '\\'') } h2 { color: red;}", "* { } h2 { color: red;}");
		propertyTests.put("* { causta: \"}\" + ({inner-property: blahblahblah;} * '\\'') } h2 { color: red;}", "* { } h2 { color: red;}");

		// Auto-close of style sheet. NOT IMPLEMENTED! The first test tests that we handle unclosed sheet sanely, the second is commented out but would test closing it and parsing it.
		propertyTests.put("@media screen {\n  p:before { content: 'Hello", "@media screen {\n  p:before {}} ");
		//propertyTests.put("@media screen {\n  p:before { content: 'Hello", "@media screen {\n  p:before { content: 'Hello'; }}");

		// Integers
		propertyTests.put("p { line-height: 0;}", "p { line-height: 0;}");
		propertyTests.put("p { line-height: -0;}", "p { line-height: -0;}");
		propertyTests.put("p { line-height: +0;}", "p { line-height: +0;}");
		propertyTests.put("p { line-height: +0.1;}", "p { line-height: +0.1;}");

		// !important
		propertyTests.put("body {\n  color: black !important;\n  background: white !important;\n}", "body {\n  color: black !important;\n  background: white !important;\n}");
		propertyTests.put("p { text-indent: 1em ! important }", "p { text-indent: 1em ! important }");

		// Box model
		propertyTests.put("LI { color: white; background: blue; margin: 12px 12px 12px 12px; padding: 12px 0px 12px 12px; list-style: none }", "LI { color: white; background: blue; margin: 12px 12px 12px 12px; padding: 12px 0px 12px 12px; list-style: none }");
		propertyTests.put("LI.withborder { border-style: dashed; border-width: medium; border-color: lime; }", "LI.withborder { border-style: dashed; border-width: medium; border-color: lime; }");
		propertyTests.put("li { margin-top: inherit; margin-bottom: auto; margin-right: 12px; margin-left: 33%; }", "li { margin-top: inherit; margin-bottom: auto; margin-right: 12px; margin-left: 33%; }");
		propertyTests.put("h3 { padding: 32in 3.3%; }", "h3 { padding: 32in 3.3%; }");
		propertyTests.put("h3 { padding: inherit }", "h3 { padding: inherit }");
		propertyTests.put("h1 { border-width: thin medium thick 23pc }", "h1 { border-width: thin medium thick 23pc }");
		propertyTests.put("div { border-color: red transparent green #f0f }", "div { border-color: red transparent green #f0f }");
		propertyTests.put("#xy34 { border-style: none dotted solid inset }", "#xy34 { border-style: none dotted solid inset }");
		propertyTests.put("#xy34 { border-style: solid dotted }", "#xy34 { border-style: solid dotted }");
		propertyTests.put("h1 { border-bottom: thick solid red }", "h1 { border-bottom: thick solid red }");
		propertyTests.put("h1[foo] { border: solid red; }", "h1[foo] { border: solid red; }");
		propertyTests.put("div { box-sizing: content-box; }", "div { box-sizing: content-box; }");
		propertyTests.put("div { box-sizing: border-box; }", "div { box-sizing: border-box; }");
		propertyTests.put("div { box-sizing: invalidValueToTestFilter; }", "div { }");
		propertyTests.put("div { box-sizing: inherit; }", "div { box-sizing: inherit; }");

		// Visual formatting
		propertyTests.put("body { display: inline }\np { display: block }", "body { display: inline }\np { display: block }");
		propertyTests.put("body.abc { display: run-in }", "body.abc { display: run-in }");
		propertyTests.put("body.abc { display: none }", "body.abc { display: none }");
		propertyTests.put("body.abc { display: inherit }", "body.abc { display: inherit }");
		propertyTests.put("div { display: list-item; }", "div { display: list-item; }");
		propertyTests.put("div { display: list-item flow; }", "div { display: list-item flow; }");
		propertyTests.put("div { display: list-item block flow; }", "div { display: list-item block flow; }");
		propertyTests.put("div { display: block list-item flow; }", "div { display: block list-item flow; }");
		propertyTests.put("div { display: inline-block; }", "div { display: inline-block; }");
		propertyTests.put("div { display: inline-flex; }", "div { display: inline-flex; }");
		propertyTests.put("div { display: table; }", "div { display: table; }");
		propertyTests.put("div { display: ruby; }", "div { display: ruby; }");
		propertyTests.put("div { display: ruby-text-container; }", "div { display: ruby-text-container; }");
		propertyTests.put("@media screen { h1#first { position: fixed } }\n@media print { h1#first { position: static } }", "@media screen { h1#first { position: fixed }}\n@media print { h1#first { position: static }}");
		propertyTests.put("body { top: auto; left: inherit; right: 23em; bottom: 3.2% }", "body { top: auto; left: inherit; right: 23em; bottom: 3.2% }");
		propertyTests.put("EM { padding: 2px; margin: 1em; border-width: medium; border-style: dashed; line-height: 2.4em; }", "EM { padding: 2px; margin: 1em; border-width: medium; border-style: dashed; line-height: 2.4em; }");
		propertyTests.put("p { width: 10em; border: solid aqua; }\nspan { float: left; width: 5em; height: 5em; border: solid blue; }", "p { width: 10em; border: solid aqua; }\nspan { float: left; width: 5em; height: 5em; border: solid blue; }");
		propertyTests.put("img.icon { float: left; margin-left: 0; }", "img.icon { float: left; margin-left: 0; }");
		propertyTests.put("i { float: inherit } b { float: none }", "i { float: inherit } b { float: none }");
		propertyTests.put("img { clear: right }", "img { clear: right }");
		propertyTests.put("body { display: block; font-size:12px; line-height: 200%; width: 400px; height: 400px }", "body { display: block; font-size:12px; line-height: 200%; width: 400px; height: 400px }");
		propertyTests.put("#inner { float: right; width: 130px; color: blue }", "#inner { float: right; width: 130px; color: blue }");
		propertyTests.put(".abc { z-index: auto; } h1 p { z-index: 3; } h2 p { z-index: inherit }", ".abc { z-index: auto; } h1 p { z-index: 3; } h2 p { z-index: inherit }");
		propertyTests.put("blockquote { direction: rtl; unicode-bidi: BIDI-OVERRIDE }", "blockquote { direction: rtl; unicode-bidi: BIDI-OVERRIDE }");

		// Visual details
		propertyTests.put("p { width: 100px } h1,h2,h3 { width: 150% } body { width: auto }", "p { width: 100px } h1,h2,h3 { width: 150% } body { width: auto }");
		propertyTests.put("body { min-width: 80%; max-width: 32px; } table { max-width: none }", "body { min-width: 80%; max-width: 32px; } table { max-width: none }");
		propertyTests.put("p { height: 100px; min-height: inherit; max-height: 33% }", "p { height: 100px; min-height: inherit; max-height: 33% }");
		propertyTests.put("div { line-height: 1.2; font-size: 10pt }", "div { line-height: 1.2; font-size: 10pt }");
		propertyTests.put("div { line-height: 1.2em; font-size: 10pt }", "div { line-height: 1.2em; font-size: 10pt }");
		propertyTests.put("div { line-height: 120%; font-size: 10pt }", "div { line-height: 120%; font-size: 10pt }");
		propertyTests.put("th { vertical-align: 67%; } td { vertical-align: 33px } li { vertical-align: sub }", "th { vertical-align: 67%; } td { vertical-align: 33px } li { vertical-align: sub }");

		// Visual effects
		propertyTests.put("#scroller { overflow: scroll; height: 5em; margin: 5em; }", "#scroller { overflow: scroll; height: 5em; margin: 5em; }");
		propertyTests.put("body { clip: auto } h1,h2,h3 { clip: inherit } p { clip: rect(5px, 40px, 45px, 5px); }", "body { clip: auto } h1,h2,h3 { clip: inherit } p { clip: rect(5px, 40px, 45px, 5px); }");
		propertyTests.put("#container2 { position: absolute; top: 2in; left: 2in; width: 2in; visibility: hidden; }", "#container2 { position: absolute; top: 2in; left: 2in; width: 2in; visibility: hidden; }");

		// Generated content
		propertyTests.put("p.note:before { content: \"Note: \" } p.note { border: solid green }", "p.note:before { content: \"Note: \" } p.note { border: solid green }");
		propertyTests.put("q:before { content: open-quote; color: red }", "q:before { content: open-quote; color: red }");
		propertyTests.put("body:after { content: \"The End\"; display: block; margin-top: 2em; text-align: center; }", "body:after { content: \"The End\"; display: block; margin-top: 2em; text-align: center; }");
		propertyTests.put("h1:before { content: \"Chapter \" counter(test) \" \" open-quote attr(chaptername) close-quote }", "h1:before { content: \"Chapter \" counter(test) \" \" open-quote attr(chaptername) close-quote }");
		propertyTests.put("em:before { content: url(\"emphasis.png\") }", "em:before { content: url(\"emphasis.png\") }");
		propertyTests.put("body { quotes: none }", "body { quotes: none }");
		propertyTests.put("body { quotes: inherit }", "body { quotes: inherit }");
		propertyTests.put("body { quotes: \"'\" \"'\" }", "body { quotes: \"'\" \"'\" }");
		propertyTests.put("body:lang(en) { quotes: \"'\" \"'\" \"\\\"\" \"\\\"\" }", "body:lang(en) { quotes: \"'\" \"'\" \"\\\"\" \"\\\"\" }");
		propertyTests.put("body { quotes: \"'\" \"'\" \"\\\"\" }", "body { }");
		propertyTests.put("blockquote p:before     { content: open-quote } blockquote p:after      { content: no-close-quote } blockquote p.last:after { content: close-quote }", "blockquote p:before { content: open-quote } blockquote p:after { content: no-close-quote } blockquote p.last:after { content: close-quote }");
		propertyTests.put("H1:before {\n    content: \"Chapter \" counter(chapter) \". \";\n    counter-increment: chapter;  /* Add 1 to chapter */\n}", "H1:before {\n    content: \"Chapter \" counter(chapter) \". \";\n    counter-increment: chapter;  \n}");
		propertyTests.put("OL { counter-reset: item }\nLI { display: block }\nLI:before { content: counter(item) \". \"; counter-increment: item }", "OL { counter-reset: item }\nLI { display: block }\nLI:before { content: counter(item) \". \"; counter-increment: item }");
		propertyTests.put("LI:before { content: counters(item, \".\") }", "LI:before { content: counters(item, \".\") }");
		propertyTests.put("LI:before { content: counters(item, \".\") \" \" }", "LI:before { content: counters(item, \".\") \" \" }");
		propertyTests.put("OL { counter-reset: item }\nLI { display: block }\nLI:before { content: counters(item, \".\") \" \"; counter-increment: item }", "OL { counter-reset: item }\nLI { display: block }\nLI:before { content: counters(item, \".\") \" \"; counter-increment: item }");
		propertyTests.put("H1:before        { content: counter(chno, upper-latin) \". \" }", "H1:before { content: counter(chno, upper-latin) \". \" }");
		propertyTests.put("BLOCKQUOTE:after { content: \" [\" counter(bq, lower-greek) \"]\" }", "BLOCKQUOTE:after { content: \" [\" counter(bq, lower-greek) \"]\" }");
		propertyTests.put("ol { list-style-type: lower-roman }   ", "ol { list-style-type: lower-roman }   ");
		propertyTests.put("ol { list-style-image: url(ol.png); } ul { list-style-image: none }", "ol { list-style-image: url(\"ol.png\"); } ul { list-style-image: none }");
		propertyTests.put("ul         { list-style: outside }\nul.compact { list-style: inside }", "ul { list-style: outside }\nul.compact { list-style: inside }");
		propertyTests.put("ul { list-style: upper-roman inside url(ul.png) }", "ul { list-style: upper-roman inside url(\"ul.png\") }");
		propertyTests.put("ol.alpha > li { list-style: lower-alpha }", "ol.alpha>li { list-style: lower-alpha }");

		// Paged media
		propertyTests.put("@page { margin: 3cm; }", "@page { margin: 3cm; }");
		propertyTests.put("@page :left {\n  margin-left: 4cm;\n  margin-right: 3cm;\n}", "@page :left {\n  margin-left: 4cm;\n  margin-right: 3cm;\n}");
		propertyTests.put("@page :first { margin-top: 10cm } * { margin: 10px }", "@page :first { margin-top: 10cm } * { margin: 10px }");
		propertyTests.put("h1 { page-break-before: always; orphans: 3; widows: 4 } h2 { page-break-after: inherit; orphans: 277; widows: inherit } h3 { page-break-inside: avoid; orphans: inherit; widows: 10 }", "h1 { page-break-before: always; orphans: 3; widows: 4 } h2 { page-break-after: inherit; orphans: 277; widows: inherit } h3 { page-break-inside: avoid; orphans: inherit; widows: 10 }");

		// Colors
		propertyTests.put("em { color: rgb(255,0,0) }", "em { color: rgb(255,0,0) }");
		propertyTests.put("body { background: url(\"background.jpeg\") }", "body { background: url(\"background.jpeg\") }");
		propertyTests.put("body { background-color: green } table { background-color: transparent } h1, h2, h3 { background-color: #F00 }", "body { background-color: green } table { background-color: transparent } h1, h2, h3 { background-color: #F00 }");
		propertyTests.put("body { background-image: url(\"marble.png\") } p { background-image: none }", "body { background-image: url(\"marble.png\") } p { background-image: none }");
		propertyTests.put("body {\n  background: white url(\"pendant.png\");\n  background-repeat: repeat-y;\n  background-position: center;\n}", "body {\n  background: white url(\"pendant.png\");\n  background-repeat: repeat-y;\n  background-position: center;\n}");
		propertyTests.put("body { background-attachment: fixed }", "body { background-attachment: fixed }");
		propertyTests.put("body { background: white url(ledger.png) fixed; }", "body { background: white url(\"ledger.png\") fixed; }");
		propertyTests.put("body { background-position: 100% 100% } h1 { background-position: 3% bottom } h2 { background-position: 3cm 2mm } h3 { background-position: right } h4 { background-position: center bottom } h5 { background-position: inherit }", "body { background-position: 100% 100% } h1 { background-position: 3% bottom } h2 { background-position: 3cm 2mm } h3 { background-position: right } h4 { background-position: center bottom } h5 { background-position: inherit }");
		propertyTests.put("body { background: url(\"banner.jpeg\") right top }", "body { background: url(\"banner.jpeg\") right top }");
		propertyTests.put("body { background: url(\"banner.jpeg\") center }", "body { background: url(\"banner.jpeg\") center }");
		propertyTests.put("P { background: url(\"chess.png\") gray 50% repeat fixed }", "P { background: url(\"chess.png\") gray 50% repeat fixed }");

		// Text
		propertyTests.put("p { text-indent: 3em }", "p { text-indent: 3em }");
		propertyTests.put("p { text-indent: 33% }", "p { text-indent: 33% }");
		propertyTests.put("div.important { text-align: center }", "div.important { text-align: center }");
		propertyTests.put("a:visited,a:link { text-decoration: underline }", "a:link { text-decoration: underline }");
		propertyTests.put("blockquote { text-decoration: underline overline line-through blink } h1 { text-decoration: none } h2 { text-decoration: inherit }","blockquote { text-decoration: underline overline line-through blink } h1 { text-decoration: none } h2 { text-decoration: inherit }");
		propertyTests.put("blockquote { letter-spacing: 0.1em }", "blockquote { letter-spacing: 0.1em }");
		propertyTests.put("blockquote { letter-spacing: normal }", "blockquote { letter-spacing: normal }");
		propertyTests.put("h1 { word-spacing: 1em }", "h1 { word-spacing: 1em }");
		propertyTests.put("h1 { text-transform: uppercase }", "h1 { text-transform: uppercase }");
		propertyTests.put("pre        { white-space: pre } p          { white-space: normal } td[nowrap] { white-space: nowrap }", "pre { white-space: pre } p { white-space: normal } td[nowrap] { white-space: nowrap }");
		propertyTests.put("pre[wrap]  { white-space: pre-wrap }", "pre[wrap] { white-space: pre-wrap }");
		propertyTests.put("th { text-align: center; font-weight: bold }", "th { text-align: center; font-weight: bold }");
		propertyTests.put("th { vertical-align: baseline } td { vertical-align: middle }", "th { vertical-align: baseline } td { vertical-align: middle }");
		propertyTests.put("caption { caption-side: top }", "caption { caption-side: top }");

		// Tables
		propertyTests.put("table    { display: table }\ntr       { display: table-row }\nthead    { display: table-header-group }\ntbody    { display: table-row-group }\ntfoot    { display: table-footer-group }\ncol      { display: table-column }\ncolgroup { display: table-column-group }\ntd, th   { display: table-cell }\ncaption  { display: table-caption }",
				"table { display: table }\ntr { display: table-row }\nthead { display: table-header-group }\ntbody { display: table-row-group }\ntfoot { display: table-footer-group }\ncol { display: table-column }\ncolgroup { display: table-column-group }\ntd, th { display: table-cell }\ncaption { display: table-caption }");
		propertyTests.put("caption { caption-side: bottom; \n width: auto;\n text-align: left }", "caption { caption-side: bottom; \n width: auto;\n text-align: left }");
		propertyTests.put("table { table-layout: fixed; margin-left: 2em;margin-right: 2em }", "table { table-layout: fixed; margin-left: 2em;margin-right: 2em }");
		propertyTests.put("table { border-collapse: collapse; border-spacing: 12em 11cm; border-spacing: 10px; border-spacing: 0; border-spacing: inherit }", "table { border-collapse: collapse; border-spacing: 12em 11cm; border-spacing: 10px; border-spacing: 0; border-spacing: inherit }");
		propertyTests.put("table      { border: outset 10pt; border-collapse: separate; border-spacing: 15pt } td { border: inset 5pt } td.special { border: inset 10pt }", "table { border: outset 10pt; border-collapse: separate; border-spacing: 15pt } td { border: inset 5pt } td.special { border: inset 10pt }");
		// Checking properties against elements is invalid because of inheritance. empty-cells applies to td, th only, but if set on table it is inherited, this example taken from CSS2.1 spec.
		propertyTests.put("table { empty-cells: show }", "table { empty-cells: show }");

		// User interface
		propertyTests.put(":link,:visited { cursor: url(example.svg#linkcursor) url(hyper.cur) pointer }", ":link { cursor: url(\"example.svg#linkcursor\") url(\"hyper.cur\") pointer }");
		propertyTests.put(":link,:visited { cursor: url(example.svg#linkcursor), url(hyper.cur), pointer }", ":link { cursor: url(\"example.svg#linkcursor\"), url(\"hyper.cur\"), pointer }");
		propertyTests.put(":link,:visited { cursor: url(example.svg#linkcursor) 2 5, url(hyper.cur), pointer }", ":link { cursor: url(\"example.svg#linkcursor\") 2 5, url(\"hyper.cur\"), pointer }");
                propertyTests.put(":link,:visited { cursor: url(example.svg#linkcursor) 2, url(hyper.cur), pointer }", ":link { }");

		// UI colors
		propertyTests.put("p { color: WindowText; background-color: Window }", "p { color: WindowText; background-color: Window }");
		propertyTests.put("button { outline : thick solid}", "button { outline: thick solid}");
		propertyTests.put(":focus  { outline: thick solid black }", ":focus { outline: thick solid black }");
		propertyTests.put(":active { outline: thick solid red }", ":active { outline: thick solid red }");

		// Aural style sheets
		propertyTests.put("@media speech {\n  body { voice-family: Paul }\n}", "@media speech {\n  body { voice-family: Paul }}");
		propertyTests.put("@media aural {\n  body { voice-family: Paul }\n}", "@media aural {\n  body { voice-family: Paul }}");
		propertyTests.put("@media speech { h1, h2, h3, h4, h5, h6 { voice-family: Paul; stress: 20; richness: 90; cue-before: url(\"ping.au\") } p.heidi { azimuth: center-left } p.peter { azimuth: right } p.goat { volume: x-soft }}",
				"@media speech { h1, h2, h3, h4, h5, h6 { voice-family: Paul; stress: 20; richness: 90; cue-before: url(\"ping.au\") } p.heidi { azimuth: center-left } p.peter { azimuth: right } p.goat { volume: x-soft }}");
		propertyTests.put("@media speech { body { volume: 10 } h1, h2 { volume: 50% } h3, h4 { volume: silent } p { volume: inherit }}",
				"@media speech { body { volume: 10 } h1, h2 { volume: 50% } h3, h4 { volume: silent } p { volume: inherit }}");
		propertyTests.put("@media aural { q { speak: spell-out }}", "@media aural { q { speak: spell-out }}");
		propertyTests.put("@media aural { blockquote { pause-after: 1s } h1 { pause-before: 10% } p { pause-after: inherit }}",
				"@media aural { blockquote { pause-after: 1s } h1 { pause-before: 10% } p { pause-after: inherit }}");
		propertyTests.put("@media speech { h1 { pause: 10ms 10% } p { pause: inherit }}", "@media speech { h1 { pause: 10ms 10% } p { pause: inherit }}");
		propertyTests.put("@media speech { h1 { cue-before: none; cue-after: url(\"h1.au\") } }", "@media speech { h1 { cue-before: none; cue-after: url(\"h1.au\") }}");
		propertyTests.put("@media speech { a {cue-before: url(\"bell.aiff\"); cue-after: url(\"dong.wav\") }}","@media speech { a {cue-before: url(\"bell.aiff\"); cue-after: url(\"dong.wav\") }}");
		propertyTests.put("@media speech { h1 {cue-before: url(\"pop.au\"); cue-after: url(\"pop.au\") }}", "@media speech { h1 {cue-before: url(\"pop.au\"); cue-after: url(\"pop.au\") }}");
		propertyTests.put("@media speech { h1 {cue: url(\"pop.au\") }}", "@media speech { h1 {cue: url(\"pop.au\") }}");
		propertyTests.put("@media aural { blockquote.sad { play-during: url(\"violins.aiff\") }}", "@media aural { blockquote.sad { play-during: url(\"violins.aiff\") }}");
		propertyTests.put("@media aural { blockquote Q   { play-during: url(\"harp.wav\") mix }}","@media aural { blockquote Q { play-during: url(\"harp.wav\") mix }}");
		propertyTests.put("@media speech { span.quiet     { play-during: none }}", "@media speech { span.quiet { play-during: none }}");
		propertyTests.put("@media speech { h1   { elevation: above } tr.a { elevation: 60deg } tr.b { elevation: 30deg } tr.c { elevation: level }}", "@media speech { h1 { elevation: above } tr.a { elevation: 60deg } tr.b { elevation: 30deg } tr.c { elevation: level }}");
		propertyTests.put("@media speech { body { speech-rate: slow } i,em { speech-rate: 450.1 }}","@media speech { body { speech-rate: slow } i,em { speech-rate: 450.1 }}");
		propertyTests.put("@media speech { body { pitch: x-low } i { pitch: 5kHz } b { pitch: 500Hz }}", "@media speech { body { pitch: x-low } i { pitch: 5kHz } b { pitch: 500Hz }}");
		propertyTests.put("@media speech { body { pitch-range: 50; stress: 20 } h1,h2,h3 { pitch-range: 10.0; stress: 5.0 } p { pitch-range: inherit; stress: inherit; richness: 20 }}", "@media speech { body { pitch-range: 50; stress: 20 } h1,h2,h3 { pitch-range: 10.0; stress: 5.0 } p { pitch-range: inherit; stress: inherit; richness: 20 }}");
		propertyTests.put("@media speech { .phone { speak-punctuation: code; speak-numeral: digits }}", "@media speech { .phone { speak-punctuation: code; speak-numeral: digits }}");
		propertyTests.put("@media speech { table { speak-header: always } table.quick { speak-header: once } table.sub { speak-header: inherit }}", "@media speech { table { speak-header: always } table.quick { speak-header: once } table.sub { speak-header: inherit }}");
		propertyTests.put("@media speech { h1 { voice-family: announcer, male } p.part.romeo  { voice-family: romeo, male } p.part.juliet { voice-family: juliet, female }}", "@media speech { h1 { voice-family: announcer, male } p.part.romeo { voice-family: romeo, male } p.part.juliet { voice-family: juliet, female }}");

		// Banned selectors
		propertyTests.put(":visited { color:red }", "");
		propertyTests.put("a:visited { color:red }", "");
		propertyTests.put(":visited,:active { color:red }", ":active { color:red }");
		propertyTests.put("a:visited,:active { color:red }", ":active { color:red }");
		propertyTests.put(":active,:visited { color:red }", ":active { color:red }");
		propertyTests.put(":active,a:visited { color:red }", ":active { color:red }");
		propertyTests.put(":focus,:visited,:active { color:red }", ":focus,:active { color:red }");
		propertyTests.put(":focus,a:visited,:active { color:red }", ":focus,:active { color:red }");

		// Flex-box Test
		propertyTests.put("nav > ul { display: flex; }", "nav>ul { display: flex; }");
		propertyTests.put("nav > ul > li {\n  min-width: 100px;\n  /* Prevent items from getting too small for their content. */\n  }", "nav>ul>li {\n  min-width: 100px;\n  \n  }");
		propertyTests.put("nav > ul > #login {\n  margin-left: auto;\n}", "nav>ul>#login {\n  margin-left: auto;\n}");
		propertyTests.put("nav > ul { display: flex; }", "nav>ul { display: flex; }");
		propertyTests.put("div { flex-flow: row nowrap; }", "div { flex-flow: row nowrap; }");
		propertyTests.put("div { flex-grow: 5; }", "div { flex-grow: 5; }");
		propertyTests.put("div { flex: 64 content; }", "div { flex: 64 content; }");
		propertyTests.put("div { flex-grow: 5; }", "div { flex-grow: 5; }");
		propertyTests.put("div { flex-basis: 5px; }", "div { flex-basis: 5px; }");
		propertyTests.put("div { flex-basis: content; }", "div { flex-basis: content; }");
		propertyTests.put("div { flex: 64 ; }", "div { flex: 64; }");
		propertyTests.put("nav { flex-shrink: 3; }", "nav { flex-shrink: 3; }");
		propertyTests.put("div { flex-wrap: nowrap ; }", "div { flex-wrap: nowrap; }");
		propertyTests.put("div { flex-wrap: wrap ; }", "div { flex-wrap: wrap; }");
		propertyTests.put("div { flex-wrap: wrap-reverse; }", "div { flex-wrap: wrap-reverse; }");
		propertyTests.put("div { flex-direction: column-reverse; }", "div { flex-direction: column-reverse; }");
		propertyTests.put("div { order: 5; flex-basis: content; }", "div { order: 5; flex-basis: content; }");
		propertyTests.put("div { justify-content: flex-start; }", "div { justify-content: flex-start; }");
		propertyTests.put("div { justify-content: flex-end; }", "div { justify-content: flex-end; }");
		propertyTests.put("div { justify-content: center; }", "div { justify-content: center; }");
		propertyTests.put("div { justify-content: space-between; }", "div { justify-content: space-between; }");
		propertyTests.put("div { justify-content: space-around; }", "div { justify-content: space-around; }");
		propertyTests.put("div { justify-items: legacy center; }", "div { justify-items: legacy center; }");
		propertyTests.put("div { justify-items: auto; }", "div { justify-items: auto; }");
		propertyTests.put("div { justify-items: baseline; }", "div { justify-items: baseline; }");
		propertyTests.put("div { justify-items: true left; }", "div { justify-items: true left; }");
		propertyTests.put("div { justify-items: self-start; }", "div { justify-items: self-start; }");
		propertyTests.put("div { justify-items: self-start legacy left; }", "div { }");
		propertyTests.put("div { justify-items: left; }", "div { justify-items: left; }");
		propertyTests.put("div { align-self: true center; }", "div { align-self: true center; }");
		propertyTests.put("div { align-self: center true; }", "div { align-self: center true; }");
		propertyTests.put("div { align-self: center true center; }", "div { }");
		propertyTests.put("div { justify-self: true center; }", "div { justify-self: true center; }");
		propertyTests.put("div { justify-self: center true; }", "div { justify-self: center true; }");
		propertyTests.put("div { justify-self: center true center; }", "div { }");

		propertyTests.put("div { align-content: flex-start; }", "div { align-content: flex-start; }");
		propertyTests.put("div { align-content: space-between; }", "div { align-content: space-between; }");
		propertyTests.put("div { align-content: true flex-start; }", "div { align-content: true flex-start; }");
		propertyTests.put("div { align-content: flex-start safe; }", "div { align-content: flex-start safe; }");
		propertyTests.put("div { align-self: baseline; }", "div { align-self: baseline; }");
		propertyTests.put("div { align-self: stretch; }", "div { align-self: stretch; }");
		propertyTests.put("div { align-items: stretch; }", "div { align-items: stretch; }");
		propertyTests.put("div { align-items: flex-end; }", "div { align-items: flex-end; }");
		// all valid properties but too many of them
		propertyTests.put("div { display: block list-item flow list-item; }", "div { }");
		// all valid but repeated when repetition is not allowed
		propertyTests.put("div { display: list-item flow flow; }", "div { }");
		propertyTests.put("div { display: invalidItem; }", "div { }");
		propertyTests.put("div { display: block invalidItem; }", "div { }");

		// Navigation Attributes for CSS3 UI
		propertyTests.put("body { nav-down: auto; }",  "body { nav-down: auto; }");
		propertyTests.put("body { nav-down: h2#java current; }",  "body { nav-down: h2#java current; }");
		propertyTests.put("body { nav-up: #java root; }",  "body { nav-up: #java root; }");
		propertyTests.put("body { nav-left: div.bold '<target-name>'; }",  "body { }");
		propertyTests.put("button#foo { nav-left: #bar \"sidebar\"; }", "button#foo { nav-left: #bar \"sidebar\"; }");
		propertyTests.put("button#foo { nav-left: invalidSelector \"sidebar\"; }", "button#foo { }");
	}

	FilterMIMEType cssMIMEType;

	@Override
	public void setUp() throws InvalidThresholdException {
		new NodeL10n();
		//if (TestProperty.VERBOSE) {
		//	Logger.setupStdoutLogging(LogLevel.MINOR, "freenet.client.filter:DEBUG");
		//}
		ContentFilter.init();
		cssMIMEType = ContentFilter.getMIMEType("text/css");
	}

	public void testCSS1Selector() throws IOException, URISyntaxException {


		Collection<String> c = CSS1_SELECTOR.keySet();
		Iterator<String> itr = c.iterator();
		while(itr.hasNext())
		{

			String key=itr.next();
			String value=CSS1_SELECTOR.get(key);
			assertTrue("key=\""+key+"\" value=\""+filter(key)+"\" should be \""+value+"\"", filter(key).contains(value));
		}

		assertTrue("key=\""+CSS_DELETE_INVALID_SELECTOR+"\" value=\""+filter(CSS_DELETE_INVALID_SELECTOR)+"\" should be \""+CSS_DELETE_INVALID_SELECTORC+"\"", CSS_DELETE_INVALID_SELECTORC.equals(filter(CSS_DELETE_INVALID_SELECTOR)));
		assertTrue("key=\""+CSS_INVALID_MEDIA_CASCADE+"\" value=\""+filter(CSS_INVALID_MEDIA_CASCADE)+"\"", "".equals(filter(CSS_INVALID_MEDIA_CASCADE)));
	}

	public void testCSS2Selector() throws IOException, URISyntaxException {
		Collection<String> c = CSS2_SELECTOR.keySet();
		Iterator<String> itr = c.iterator();
		int i=0;
		while(itr.hasNext())
		{
			String key=itr.next();
			String value=CSS2_SELECTOR.get(key);
			System.err.println("Test "+(i++)+" : "+key+" -> "+value);
			assertTrue("key="+key+" value=\""+filter(key)+"\" should be \""+value+"\"", filter(key).contains(value));
		}

		i=0;
		for(String key : CSS2_BAD_SELECTOR) {
			System.err.println("Bad selector test "+(i++));
			assertTrue("".equals(filter(key)));
		}

	}

	public void testCSS3Selector() throws IOException, URISyntaxException {
		Collection<String> c = CSS3_SELECTOR.keySet();
		Iterator<String> itr = c.iterator();
		int i=0;
		while(itr.hasNext())
		{
			String key=itr.next();
			String value=CSS3_SELECTOR.get(key);
			System.err.println("CSS3 test"+(i++)+" : "+key+" -> "+value);
			assertTrue("key="+key+" value=\""+filter(key)+"\" should be \""+value+"\"", filter(key).contains(value));
		}

		i=0;
		for(String key : CSS3_BAD_SELECTOR) {
			System.err.println("CSS3 bad selector test "+(i++));
			assertTrue("".equals(filter(key)));
		}

	}

	public void testNewlines() throws IOException, URISyntaxException {
		assertTrue("key=\""+CSS_STRING_NEWLINES+"\" value=\""+filter(CSS_STRING_NEWLINES)+"\" should be: \""+CSS_STRING_NEWLINESC+"\"", CSS_STRING_NEWLINESC.equals(filter(CSS_STRING_NEWLINES)));
	}

	public void testBackgroundURL() throws IOException, URISyntaxException {
		assertTrue("key="+CSS_BACKGROUND_URL+" value=\""+filter(CSS_BACKGROUND_URL)+"\" should be \""+CSS_BACKGROUND_URLC+"\"", CSS_BACKGROUND_URLC.equals(filter(CSS_BACKGROUND_URL)));

		assertTrue("key="+CSS_LCASE_BACKGROUND_URL+" value=\""+filter(CSS_LCASE_BACKGROUND_URL)+"\"", CSS_LCASE_BACKGROUND_URLC.equals(filter(CSS_LCASE_BACKGROUND_URL)));
	}

	public void testImports() throws IOException, URISyntaxException {
		assertTrue("key="+CSS_IMPORT+" value=\""+filter(CSS_IMPORT)+"\"", CSS_IMPORTC.equals(filter(CSS_IMPORT)));
		assertTrue("key="+CSS_IMPORT2+" value=\""+filter(CSS_IMPORT2)+"\"", CSS_IMPORT2C.equals(filter(CSS_IMPORT2)));
		assertTrue("key="+CSS_IMPORT_MULTI_MEDIA+" value=\""+filter(CSS_IMPORT_MULTI_MEDIA)+"\"", CSS_IMPORT_MULTI_MEDIAC.equals(filter(CSS_IMPORT_MULTI_MEDIA)));
		assertTrue("key="+CSS_IMPORT_MULTI_MEDIA_BOGUS+" value=\""+filter(CSS_IMPORT_MULTI_MEDIA_BOGUS)+"\"", CSS_IMPORT_MULTI_MEDIA_BOGUSC.equals(filter(CSS_IMPORT_MULTI_MEDIA_BOGUS)));
		assertTrue("key="+CSS_IMPORT_MULTI_MEDIA_ALL+" value=\""+filter(CSS_IMPORT_MULTI_MEDIA_ALL)+"\"", CSS_IMPORT_MULTI_MEDIA_ALLC.equals(filter(CSS_IMPORT_MULTI_MEDIA_ALL)));
		assertTrue("key="+CSS_IMPORT_TYPE+" value=\""+filter(CSS_IMPORT_TYPE)+"\"", CSS_IMPORT_TYPEC.equals(filter(CSS_IMPORT_TYPE)));
		assertTrue("key="+CSS_IMPORT_SPACE_IN_STRING+" value=\""+filter(CSS_IMPORT_SPACE_IN_STRING)+"\"", CSS_IMPORT_SPACE_IN_STRINGC.equals(filter(CSS_IMPORT_SPACE_IN_STRING)));
		assertTrue("key="+CSS_IMPORT_QUOTED_STUFF+" value=\""+filter(CSS_IMPORT_QUOTED_STUFF)+"\"", CSS_IMPORT_QUOTED_STUFFC.equals(filter(CSS_IMPORT_QUOTED_STUFF)));
		assertTrue("key="+CSS_IMPORT_QUOTED_STUFF2+" value=\""+filter(CSS_IMPORT_QUOTED_STUFF2)+"\"", CSS_IMPORT_QUOTED_STUFF2C.equals(filter(CSS_IMPORT_QUOTED_STUFF2)));
		assertTrue("key="+CSS_IMPORT_NOURL_TWOMEDIAS+" value=\""+filter(CSS_IMPORT_NOURL_TWOMEDIAS)+"\"", CSS_IMPORT_NOURL_TWOMEDIASC.equals(filter(CSS_IMPORT_NOURL_TWOMEDIAS)));
		assertTrue("key="+CSS_IMPORT_UNQUOTED+" should be empty", "".equals(filter(CSS_IMPORT_UNQUOTED)));
		assertTrue("key="+CSS_IMPORT_NOURL+" value=\""+filter(CSS_IMPORT_NOURL)+"\"", CSS_IMPORT_NOURLC.equals(filter(CSS_IMPORT_NOURL)));
		assertTrue("key="+CSS_IMPORT_BRACKET+" value=\""+filter(CSS_IMPORT_BRACKET)+"\"", CSS_IMPORT_BRACKETC.equals(filter(CSS_IMPORT_BRACKET)));
		assertTrue("key="+CSS_LATE_IMPORT+" value=\""+filter(CSS_LATE_IMPORT)+"\"", CSS_LATE_IMPORTC.equals(filter(CSS_LATE_IMPORT)));
		assertTrue("key="+CSS_LATE_IMPORT2+" value=\""+filter(CSS_LATE_IMPORT2)+"\"", CSS_LATE_IMPORT2C.equals(filter(CSS_LATE_IMPORT2)));
		assertTrue("key="+CSS_LATE_IMPORT3+" value=\""+filter(CSS_LATE_IMPORT3)+"\"", CSS_LATE_IMPORT3C.equals(filter(CSS_LATE_IMPORT3)));
		assertTrue("key="+CSS_BOGUS_AT_RULE+" value=\""+filter(CSS_BOGUS_AT_RULE)+"\"", CSS_BOGUS_AT_RULEC.equals(filter(CSS_BOGUS_AT_RULE)));
		assertTrue("key="+PRESERVE_CDO_CDC+" value=\""+filter(PRESERVE_CDO_CDC)+"\"", PRESERVE_CDO_CDCC.equals(filter(PRESERVE_CDO_CDC)));
		assertTrue("key="+BROKEN_BEFORE_IMPORT+" value=\""+filter(BROKEN_BEFORE_IMPORT)+"\"", BROKEN_BEFORE_IMPORTC.equals(filter(BROKEN_BEFORE_IMPORT)));
		assertTrue("key="+BROKEN_BEFORE_MEDIA+" value=\""+filter(BROKEN_BEFORE_MEDIA)+"\"", BROKEN_BEFORE_MEDIAC.equals(filter(BROKEN_BEFORE_MEDIA)));
	}

	public void testEscape() throws IOException, URISyntaxException {
		assertTrue("key="+CSS_ESCAPED_LINK+" value=\""+filter(CSS_ESCAPED_LINK)+"\"", CSS_ESCAPED_LINKC.equals(filter(CSS_ESCAPED_LINK)));
		assertTrue("key="+CSS_ESCAPED_LINK2+" value=\""+filter(CSS_ESCAPED_LINK2)+"\"", CSS_ESCAPED_LINK2C.equals(filter(CSS_ESCAPED_LINK2)));
	}

	public void testProperties() throws IOException, URISyntaxException {
		for(Entry<String, String> entry : propertyTests.entrySet()) {
			String key = entry.getKey();
			String value = entry.getValue();
			assertTrue("key=\""+key+"\" encoded=\""+filter(key)+"\" should be \""+value+"\"", value.equals(filter(key)));
		}
	}

	private String filter(String css) throws IOException, URISyntaxException {
		StringWriter w = new StringWriter();
		GenericReadFilterCallback cb = new GenericReadFilterCallback(new URI("/CHK@OR904t6ylZOwoobMJRmSn7HsPGefHSP7zAjoLyenSPw,x2EzszO4Kqot8akqmKYXJbkD-fSj6noOVGB-K2YisZ4,AAIC--8/1-works.html"), null, null, null);
		CSSParser p = new CSSParser(new StringReader(css), w, false, cb, "UTF-8", false, false);
		p.parse();
		return w.toString();
	}

	public void testCharset() throws IOException, URISyntaxException {
		// Test whether @charset is passed through when it is correct.
		String test = "@charset \"UTF-8\";\nh2 { color: red;}";
		assertTrue("key=\""+test+"\" value=\""+filter(test)+"\"", filter(test).equals(test));
		// No quote marks
		String testUnquoted = "@charset UTF-8;\nh2 { color: red;}";
		assertTrue("key=\""+test+"\" value=\""+filter(test)+"\"", filter(testUnquoted).equals(test));
		// Test whether the parse fails when @charset is not correct.
		String testFail = "@charset ISO-8859-1;\nh2 { color: red;};";
		try {
			filter(test).equals("");
			assertFalse("Bogus @charset should have been deleted, but result is \""+filter(testFail)+"\"", false);
		} catch (IOException e) {
			// Ok.
		}
		// Test charset extraction
		getCharsetTest("UTF-8");
		getCharsetTest("UTF-16BE");
		getCharsetTest("UTF-16LE");
		// not availiable in java 1.5.0_22
		// getCharsetTest("UTF-32BE");
		// getCharsetTest("UTF-32LE");

		getCharsetTest("ISO-8859-1", "UTF-8");
		getCharsetTest("ISO-8859-15", "UTF-8");
		// FIXME add more ascii-based code pages?

		// IBM 1141-1144, 1147, 1149 do not use the same EBCDIC codes for the basic english alphabet.
		// But we can support these four EBCDIC variants.

		getCharsetTest("IBM01140");
		getCharsetTest("IBM01145", "IBM01140");
		getCharsetTest("IBM01146", "IBM01140");
		getCharsetTest("IBM01148", "IBM01140");

		getCharsetTest("IBM1026");

		// Some unsupported charsets. These should not get through the filter.

		charsetTestUnsupported("IBM01141");
		charsetTestUnsupported("IBM01142");
		charsetTestUnsupported("IBM01143");
		charsetTestUnsupported("IBM01144");
		charsetTestUnsupported("IBM01147");
		charsetTestUnsupported("IBM01149");

		// Late charset is invalid
		assertTrue("key="+LATE_CHARSET+" value=\""+filter(LATE_CHARSET)+"\"", LATE_CHARSETC.equals(filter(LATE_CHARSET)));
		try {
			String output = filter(WRONG_CHARSET);
			assertFalse("Should complain that detected charset differs from real charset, but returned \""+output+"\"", true);
		} catch (IOException e) {
			// Ok.
			// FIXME should have a dedicated exception.
		}
		try {
			String output = filter(NONSENSE_CHARSET);
			assertFalse("wrong charset output is \""+output+"\" but it should throw!", true);
		} catch (UnsupportedCharsetInFilterException e) {
			// Ok.
		}

		assertTrue(BOM.equals(filter(BOM)));
		assertTrue("output=\""+filter(LATE_BOM)+"\"",LATE_BOMC.equals(filter(LATE_BOM)));
	}

	private void getCharsetTest(String charset) throws DataFilterException, IOException, URISyntaxException {
		getCharsetTest(charset, null);
	}

	private void getCharsetTest(String charset, String family) throws DataFilterException, IOException, URISyntaxException {
		String original = "@charset \""+charset+"\";\nh2 { color: red;}";
		byte[] bytes = original.getBytes(charset);
		CSSReadFilter filter = new CSSReadFilter();
		ArrayBucket inputBucket = new ArrayBucket(bytes);
		ArrayBucket outputBucket = new ArrayBucket();
		InputStream inputStream = inputBucket.getInputStream();
		OutputStream outputStream = outputBucket.getOutputStream();
		// Detect with original charset.
		String detectedCharset = filter.getCharset(bytes, bytes.length, charset);
		assertTrue("Charset detected \""+detectedCharset+"\" should be \""+charset+"\" even when parsing with correct charset", charset.equalsIgnoreCase(detectedCharset));
		BOMDetection bom = filter.getCharsetByBOM(bytes, bytes.length);
		String bomCharset = detectedCharset = bom == null ? null : bom.charset;
		assertTrue("Charset detected \""+detectedCharset+"\" should be \""+charset+"\" or \""+family+"\" from getCharsetByBOM", detectedCharset == null || charset.equalsIgnoreCase(detectedCharset) || (family != null && family.equalsIgnoreCase(detectedCharset)));
		detectedCharset = ContentFilter.detectCharset(bytes, bytes.length, cssMIMEType, null);
		assertTrue("Charset detected \""+detectedCharset+"\" should be \""+charset+"\" from ContentFilter.detectCharset bom=\""+bomCharset+"\"", charset.equalsIgnoreCase(detectedCharset));
		FilterStatus filterStatus = ContentFilter.filter(inputStream, outputStream, "text/css", new URI("/CHK@OR904t6ylZOwoobMJRmSn7HsPGefHSP7zAjoLyenSPw,x2EzszO4oobMJRmSn7HsPGefHSP7zAjoLyenSPw,x2EzszO4Kqot8akqmKYXJbkD-fSj6noOVGB-K2YisZ4,AAIC--8/1-works.html"),
        null, null, null, null);
		inputStream.close();
		outputStream.close();
		assertEquals("text/css", filterStatus.mimeType);
		assertEquals(charset, filterStatus.charset);
		String filtered = new String(BucketTools.toByteArray(outputBucket), charset);
		assertTrue("ContentFilter.filter() returns \""+filtered+"\" not original \""+original+"\" for charset \""+charset+"\"", original.equals(filtered));
	}

	private void charsetTestUnsupported(String charset) throws DataFilterException, IOException, URISyntaxException {
		String original = "@charset \""+charset+"\";\nh2 { color: red;}";
		byte[] bytes = original.getBytes(charset);
		CSSReadFilter filter = new CSSReadFilter();
		SimpleReadOnlyArrayBucket inputBucket = new SimpleReadOnlyArrayBucket(bytes);
		Bucket outputBucket = new ArrayBucket();
		InputStream inputStream = inputBucket.getInputStream();
		OutputStream outputStream = outputBucket.getOutputStream();
		String detectedCharset;
		BOMDetection bom = filter.getCharsetByBOM(bytes, bytes.length);
		String bomCharset = detectedCharset = bom == null ? null : bom.charset;
		assertTrue("Charset detected \""+detectedCharset+"\" should be unknown testing unsupported charset \""+charset+"\" from getCharsetByBOM", detectedCharset == null);
		detectedCharset = ContentFilter.detectCharset(bytes, bytes.length, cssMIMEType, null);
		assertTrue("Charset detected \""+detectedCharset+"\" should be unknown testing unsupported charset \""+charset+"\" from ContentFilter.detectCharset bom=\""+bomCharset+"\"", charset == null || "utf-8".equalsIgnoreCase(detectedCharset));
		try {
			FilterStatus filterStatus = ContentFilter.filter(inputStream, outputStream, "text/css", new URI("/CHK@OR904t6ylZOwoobMJRmSn7HsPGefHSP7zAjoLyenSPw,x2EzszO4Kqot8akqmKYXJbkD-fSj6noOVGB-K2YisZ4,AAIC--8/1-works.html"),
          null,null, null, null);
			// It is safe to return utf-8, as long as we clobber the actual content; utf-8 is the default, but other stuff decoded to it is unlikely to be coherent...
			assertTrue("ContentFilter.filter() returned charset \""+filterStatus.charset+"\" should be unknown testing  unsupported charset \""+charset+"\"", filterStatus.charset.equalsIgnoreCase(charset) || filterStatus.charset.equalsIgnoreCase("utf-8"));//If we switch to JUnit 4, this may be replaced with an assertThat
			assertEquals("text/css", filterStatus.mimeType);
			String filtered = new String(BucketTools.toByteArray(outputBucket), charset);
			assertTrue("ContentFilter.filter() returns something: \""+filtered+"\" should be empty as unsupported charset, original: \""+original+"\" for charset \""+charset+"\"", filtered.equals(""));
		} catch (UnsupportedCharsetInFilterException e) {
			// Ok.
		} catch (IOException e) {
			// Ok.
		}
		finally {
			inputStream.close();
			outputStream.close();
		}
	}

	public void testMaybeCharset() throws UnsafeContentTypeException, URISyntaxException, IOException {
		testUseMaybeCharset("UTF-8");
		testUseMaybeCharset("UTF-16");
		// not availiable in java 1.5.0_22
		// testUseMaybeCharset("UTF-32LE");
		testUseMaybeCharset("IBM01140");
	}

	private void testUseMaybeCharset(String charset) throws URISyntaxException, UnsafeContentTypeException, IOException {
		String original = "h2 { color: red;}";
		byte[] bytes = original.getBytes(charset);
		SimpleReadOnlyArrayBucket inputBucket = new SimpleReadOnlyArrayBucket(bytes);
		Bucket outputBucket = new ArrayBucket();
		InputStream inputStream = inputBucket.getInputStream();
		OutputStream outputStream = outputBucket.getOutputStream();
		FilterStatus filterStatus = ContentFilter.filter(inputStream, outputStream, "text/css", new URI("/CHK@OR904t6ylZOwoobMJRmSn7HsPGefHSP7zAjoLyenSPw,x2EzszO4Kqot8akqmKYXJbkD-fSj6noOVGB-K2YisZ4,AAIC--8/1-works.html"),
        null,null, null, charset);
		inputStream.close();
		outputStream.close();
		assertEquals(charset, filterStatus.charset);
		assertEquals("text/css", filterStatus.mimeType);
		String filtered = new String(BucketTools.toByteArray(outputBucket), charset);
		assertTrue("ContentFilter.filter() returns \""+filtered+"\" not original \""+original+"\" with maybeCharset \""+charset+"\"", original.equals(filtered));
	}

	public void testComment() throws IOException, URISyntaxException {
		assertTrue("value=\""+filter(COMMENT)+"\"",COMMENTC.equals(filter(COMMENT)));
	}

	public void testWhitespace() throws IOException, URISyntaxException {
		assertTrue("value=\""+filter(CSS_COMMA_WHITESPACE)+"\"", CSS_COMMA_WHITESPACE.equals(filter(CSS_COMMA_WHITESPACE)));
	}

	public void testDoubleCommentStart() throws IOException, URISyntaxException {
		assertEquals("Double comment start does not crash", filter("/*/*"), "");
	}

	public void testTripleCommentStart() throws IOException, URISyntaxException {
		assertEquals("Triple comment start does not crash", filter("/*/*/*"), "");
	}
}
