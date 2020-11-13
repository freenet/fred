/* -*- Mode: java; c-basic-indent: 4; tab-width: 4 -*- */

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
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.charset.MalformedInputException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Stack;
import java.util.StringTokenizer;

import freenet.clients.http.ToadletContextImpl;
import freenet.l10n.NodeL10n;
import freenet.support.HTMLDecoder;
import freenet.support.HTMLEncoder;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.URLDecoder;
import freenet.support.URLEncodedFormatException;
import freenet.support.io.NullWriter;

public class HTMLFilter implements ContentDataFilter, CharsetExtractor {

	private static boolean logMINOR;
	private static boolean logDEBUG;

	private static final boolean deleteWierdStuff = true;
	private static final boolean deleteErrors = true;
	/** If true, allow documents that don't have an <html> tag or have other tags before it.
	 * In all cases we disallow text before the first valid tag. This is because if we don't,
	 * charset detection can be ambiguous, potentially resulting in attacks. */
	private static final boolean allowNoHTMLTag = true;

	// FIXME make these configurable on a per-document level.
	// Maybe by merging with TagReplacerCallback???
	// For now they're just global.
	/** -1 means don't allow it */
	public static int metaRefreshSamePageMinInterval = 1;
	/** -1 means don't allow it */
	public static int metaRefreshRedirectMinInterval = 30;

	@Override
	public void readFilter(
      InputStream input, OutputStream output, String charset, HashMap<String, String> otherParams,
      String schemeHostAndPort, FilterCallback cb) throws DataFilterException, IOException {
		if(cb == null) cb = new NullFilterCallback();
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
		if(logMINOR) Logger.minor(this, "readFilter(): charset="+charset);
		Reader r = null;
		Writer w = null;
		InputStreamReader isr = null;
		OutputStreamWriter osw = null;
		try {
			isr = new InputStreamReader(input, charset);
			osw = new OutputStreamWriter(output, charset);
			r = new BufferedReader(isr, 4096);
			w = new BufferedWriter(osw, 4096);
		} catch(UnsupportedEncodingException e) {
			throw UnknownCharsetException.create(e, charset);
		}
		HTMLParseContext pc = new HTMLParseContext(r, w, charset, cb, false);
		pc.run();
		w.flush();
	}

	@Override
	public String getCharset(byte[] input, int length, String parseCharset) throws DataFilterException, IOException {
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		if(logMINOR) Logger.minor(this, "getCharset(): default="+parseCharset);
		if(length > getCharsetBufferSize() && Logger.shouldLog(LogLevel.MINOR, this)) {
			Logger.minor(this, "More data than was strictly needed was passed to the charset extractor for extraction");
		}
		ByteArrayInputStream strm = new ByteArrayInputStream(input, 0, length);
		Writer w = new NullWriter();
		Reader r;
		try {
			r = new BufferedReader(new InputStreamReader(strm, parseCharset), 4096);
		} catch (UnsupportedEncodingException e) {
			strm.close();
			throw e;
		}
		HTMLParseContext pc = new HTMLParseContext(r, w, null, new NullFilterCallback(), true);
		try {
			pc.run();
		} catch (MalformedInputException e) {
			// Not this charset
			return null;
		} catch (IOException e) {
			throw e;
		} catch (Throwable t) {
			// Ignore ALL errors
			if(logMINOR) Logger.minor(this, "Caught "+t+" trying to detect MIME type with "+parseCharset);
		}
		try {
			r.close();
		} catch (IOException e) {
			throw e;
		} catch (Throwable t) {
			if(logMINOR) Logger.minor(this, "Caught "+t+" closing stream after trying to detect MIME type with "+parseCharset);
		}
		if(logMINOR) Logger.minor(this, "Returning charset "+pc.detectedCharset);
		return pc.detectedCharset;
	}

	class HTMLParseContext {
		Reader r;
		Writer w;
		String charset;
		String detectedCharset;
		final FilterCallback cb;
		final boolean onlyDetectingCharset;
		boolean isXHTML=false;
		Stack<String> openElements;
		boolean failedDetectCharset;

		/** If <head> is found, then it is true. It is needed that if <title> or <meta> is found outside <head> or if a <body> is found first, then insert a <head> too*/
		boolean wasHeadElementFound=false;
		/** We can only have <head> once, and <meta>/<title> can't be outside it. This helps with robustness against charset attacks and allows us to stop looking for <meta> as soon as we see </head> when detecting charset. */
		boolean headEnded=false;

		HTMLParseContext(Reader r, Writer w, String charset, FilterCallback cb, boolean onlyDetectingCharset) {
			this.r = r;
			this.w = w;
			this.charset = charset;
			this.cb = cb;
			this.onlyDetectingCharset = onlyDetectingCharset;
			openElements=new Stack<String>();
		}

		public void setisXHTML(boolean value) {
			isXHTML=value;
		}

		public boolean getisXHTML() {
			return isXHTML;
		}

		public void pushElementInStack(String element) {
			openElements.push(element);
		}

		public String popElementFromStack() {
			if(openElements.size()>0)
				return openElements.pop();
			else
				return null;
		}

		public String peekTopElement() {
			if(openElements.isEmpty()) return null;
			return openElements.peek();
		}

		void run() throws IOException, DataFilterException {

			/**
			 * TOKENIZE Modes:
			 * <p>0) in text transitions: '<' ->(1) 1) in tag, not in
			 * quotes/comment/whitespace transitions: whitespace -> (4) (save
			 * current element) '"' -> (2) '--' at beginning of tag -> (3) '>' ->
			 * process whole tag 2) in tag, in quotes transitions: '"' -> (1)
			 * '>' -> grumble about markup in quotes in tag might confuse older
			 * user-agents (stay in current state) 3) in tag, in comment
			 * transitions: '-->' -> save/ignore comment, go to (0) '<' or '>' ->
			 * grumble about markup in comments 4) in tag, in whitespace
			 * transitions: '"' -> (2) '>' -> save tag, (0) anything else not
			 * whitespace -> (1)
			 * </p>
			 */
			StringBuilder b = new StringBuilder(100);
			StringBuilder balt = new StringBuilder(4000);
			List<String> splitTag = new ArrayList<String>();
			String currentTag = null;
			char pprevC = 0;
			char prevC = 0;
			char c = 0;
			mode = INTEXT;

			// No text before <html>
			boolean textAllowed = false;

			boolean firstChar = true;

			while (true) {
				// If detecting charset, stop after </head> even if haven't found <meta> charset tag.
				if(onlyDetectingCharset && failedDetectCharset)
					return;
				// If detecting charset, and found it, stop afterwards.
				if(onlyDetectingCharset && detectedCharset != null)
					return;
				int x;

				try {
					x = r.read();
				}
				/**
				 * libgcj up to at least 4.2.2 has a bug: InputStreamReader.refill() throws this exception when BufferedInputReader.refill() returns false for EOF. See:
				 * line 299 at InputStreamReader.java (in refill()): http://www.koders.com/java/fidD8F7E2EB1E4C22DA90EBE0130306AE30F876AB00.aspx?s=refill#L279
				 * line 355 at BufferedInputStream.java (in refill()): http://www.koders.com/java/fid1949641524FAC0083432D79793F554CD85F46759.aspx?s=refill#L355
				 * TODO: remove this when the gcj bug is fixed and the affected gcj versions are outdated.
				 */
				catch(java.io.CharConversionException cce) {
					if(freenet.node.Node.checkForGCJCharConversionBug()) /* only ignore the exception on affected libgcj */
						x = -1;
					else
						throw cce;
				}

				if (x == -1) {
					switch (mode) {
						case INTEXT :
							if(textAllowed) {
								saveText(b, currentTag, w, this);
							} else {
								if(!b.toString().trim().equals(""))
									throwFilterException(l10n("textBeforeHTML"));
							}
							break;
						case INTAG:
							w.write("<!-- truncated page: last tag not unfinished -->");
							break;
						case INTAGQUOTES:
							w.write("<!-- truncated page: deleted unfinished tag: still in quotes -->");
							break;
						case INTAGSQUOTES:
							w.write("<!-- truncated page: deleted unfinished tag: still in single quotes -->");
							break;
						case INTAGWHITESPACE:
							w.write("<!-- truncated page: deleted unfinished tag: still in whitespace -->");
							break;
						case INTAGCOMMENT:
							w.write("<!-- truncated page: deleted unfinished comment -->");
							break;
						case INTAGCOMMENTCLOSING:
							w.write("<!-- truncated page: deleted unfinished comment, might be closing -->");
							break;
						default:
							// Dump unfinished tag
							break;
					}
					break;
				} else {
					pprevC = prevC;
					prevC = c;
					c = (char) x;
					if(c == 0xFEFF) {
						if(firstChar) {
							// BOM
							if(w != null)
								w.write(c);
						} else {
							// Null character (zero width non breaking space). Get rid.
						}
						continue;
					}
					if(c == 0) {
						// Delete nulls. They can cause all sorts of problems and also can result from messing around with charsets.
						continue;
					}
					firstChar = false;
					switch (mode) {
						case INTEXT :
							if (c == '<') {
								if(textAllowed) {
									saveText(b, currentTag, w, this);
								} else {
									if(!b.toString().trim().equals(""))
										throwFilterException(l10n("textBeforeHTML"));
								}
								b.setLength(0);
								balt.setLength(0);
								mode = INTAG;
							} else {
								b.append(c);
							}
							break;
						case INTAG :
							balt.append(c);
							if (HTMLDecoder.isWhitespace(c)) {
								splitTag.add(b.toString());
								mode = INTAGWHITESPACE;
								b.setLength(0);
							} else if ((c == '<') && Character.isWhitespace(balt.charAt(0))) {
								// Previous was an un-escaped < in a script.

								if(textAllowed) {
									saveText(b, currentTag, w, this);
								} else {
									if(!b.toString().trim().equals(""))
										throwFilterException(l10n("textBeforeHTML"));
								}

								balt.setLength(0);
								b.setLength(0);
								splitTag.clear();
							} else if (c == '>') {
								splitTag.add(b.toString());
								b.setLength(0);
								String s = processTag(splitTag, w, this);
								currentTag = s;
								splitTag.clear();
								balt.setLength(0);
								mode = INTEXT;
								if(s != null && (allowNoHTMLTag || (s.equals("html") || (!isXHTML) && s.equalsIgnoreCase("html"))))
									textAllowed = true;
							} else if (
								(b.length() == 2)
									&& (c == '-')
									&& (prevC == '-')
									&& (pprevC == '!')) {
								mode = INTAGCOMMENT;
								b.append(c);
							} else if (c == '"') {
								mode = INTAGQUOTES;
								b.append(c);
							} else if (c == '\'') {
								mode = INTAGSQUOTES;
								b.append(c);
							} else if (c == '/') { /* Probable end tag */
								currentTag = null; /* We didn't remember what was the last tag, so ... */
								b.append(c);
							} else {
								b.append(c);
							}
							break;
						case INTAGQUOTES :
							// Inside double-quotes, single quotes are just another character, perfectly legal in a URL.
							if (c == '"') {
								mode = INTAG;
								b.append(c); // Part of the element
							} else if (c == '>') {
								b.append("&gt;");
							} else if (c == '<') {
								b.append("&lt;");
//							} else if (c=='&') {
//								b.append("&amp;");
							} else if (c== '\u00A0') {
								b.append("&nbsp;");
							}
							else {
								b.append(c);
							}
							break;
						case INTAGSQUOTES :
							if (c == '\'') {
								mode = INTAG;
								b.append(c); // Part of the element
							} else if (c == '<') {
								b.append("&lt;");
							} else if (c == '>') {
								b.append("&gt;");
//							}else if (c=='&') {
//								b.append("&amp;");
							} else if (c== '\u00A0') {
								b.append("&nbsp;");
							}
							else {
								b.append(c);
							}
							break;
							/*
							 * Comments are often used to temporarily disable
							 * markup; I shall allow it. (avian) White space is
							 * not permitted between the markup declaration
							 * open delimiter ("
							 * <!") and the comment open delimiter ("--"), but
							 * is permitted between the comment close delimiter
							 * ("--") and the markup declaration close
							 * delimiter (">"). A common error is to include a
							 * string of hyphens ("---") within a comment.
							 * Authors should avoid putting two or more
							 * adjacent hyphens inside comments. However, the
							 * only browser that actually gets it right is IE
							 * (others either don't allow it or allow other
							 * chars as well). The only safe course of action
							 * is to allow any and all chars, but eat them.
							 * (avian)
							 */
						case INTAGCOMMENT :
							if ((b.length() >= 4) && (c == '-') && (prevC == '-')) {
								b.append(c);
								mode = INTAGCOMMENTCLOSING;
							} else
								b.append(c);
							break;
						case INTAGCOMMENTCLOSING :
							if (c == '>') {
								saveComment(b, w, this);
								b.setLength(0);
								mode = INTEXT;
							} else {
								b.append(c);
								if(c != '-')
									mode = INTAGCOMMENT;
							}
							break;
						case INTAGWHITESPACE :
							if (c == '"') {
								mode = INTAGQUOTES;
								b.append(c);
							} else if (c == '\'') {
								// e.g. <div align = 'center'> (avian)
								// This will be converted automatically to double quotes \"
								// Note that SINGLE QUOTES ARE LEGAL IN URLS ...
								// If we have single quotes inside single quotes, we could get into a major mess here... but that's really malformed code, and it will still be safe, it will just be unreadable.
								mode = INTAGSQUOTES;
								b.append(c);
							} else if (c == '>') {
								if (!killTag) {
									currentTag = processTag(splitTag, w, this);
								} else {
									currentTag = null;
								}
								killTag = false;
								splitTag.clear();
								b.setLength(0);
								balt.setLength(0);
								mode = INTEXT;
								if(currentTag != null && (allowNoHTMLTag || (currentTag.equals("html") || (!isXHTML) && currentTag.equalsIgnoreCase("html"))))
									textAllowed = true;
							} else if ((c == '<') && Character.isWhitespace(balt.charAt(0))) {
								// Previous was an un-escaped < in a script.

								if(textAllowed) {
									saveText(b, currentTag, w, this);
								} else {
									if(!b.toString().trim().equals(""))
										throwFilterException(l10n("textBeforeHTML"));
								}
								balt.setLength(0);
								b.setLength(0);
								splitTag.clear();
								mode = INTAG;
							} else if (HTMLDecoder.isWhitespace(c)) {
								// More whitespace, what fun
							} else {
								mode = INTAG;
								b.append(c);
							}
					}
				}
			}
			/**While detecting the charset, if head is not closed inside
			 * the interval which we are examining, something is wrong, and it's
			 * possible that the file has been given a freakishly large head, so
			 * that we'll miss a charset declaration.*/
			if(onlyDetectingCharset && openElements.contains("head")) {
				throw new MalformedInputException(1024*64);
			}
			//Writing the remaining tags for XHTML if any
			if(getisXHTML())
			{
				while(openElements.size()>0)
					w.write("</"+openElements.pop()+">");
			}
			w.flush();
			return;
		}
		int mode;
		static final int INTEXT = 0;
		static final int INTAG = 1;
		static final int INTAGQUOTES = 2;
		static final int INTAGSQUOTES = 3;
		static final int INTAGCOMMENT = 4;
		static final int INTAGCOMMENTCLOSING = 5;
		static final int INTAGWHITESPACE = 6;
		boolean killTag = false; // just this one
		boolean writeStyleScriptWithTag = false; // just this one
		boolean expectingBadComment = false;
		// has to be set on or off explicitly by tags
		boolean inStyle = false; // has to be set on or off explicitly by tags
		boolean inScript = false; // has to be set on or off explicitly by tags
		boolean killText = false; // has to be set on or off explicitly by tags
		boolean killStyle = false;
		int styleScriptRecurseCount = 0;
		String currentStyleScriptChunk = "";
		StringBuilder writeAfterTag = new StringBuilder(1024);

		public void closeXHTMLTag(String element, Writer w) throws IOException {
			// Assume that missing closes are way more common than extra closes.
			if(openElements.isEmpty()) return;
			if(element.equals(openElements.peek())) {
				w.write("</"+openElements.pop()+">");
			}
			else {
				if(openElements.contains(element)) {
					while(true) {
						String top = openElements.pop();
						w.write("</"+top+">");
						if(top.equals(element)) return;
					}
				} // Else it has already been closed.
			}
		}
	}


	void saveText(StringBuilder s, String tagName, Writer w, HTMLParseContext pc)
		throws IOException {

		if(pc.onlyDetectingCharset) return;

		if(logDEBUG) Logger.debug(this, "Saving text: "+s.toString());
		if (pc.killText) {
			return;
		}

		StringBuilder out = new StringBuilder(s.length()*2);

		for(int i=0;i<s.length();i++) {
			char c = s.charAt(i);
			if(c == '<' && !(pc.inStyle || pc.inScript)) {
				//Scripts and styles parsed elsewhere
				out.append("&lt;");
			}
			else if((c < 32) && (c != '\t') && (c != '\n') && (c != '\r')) {
				// Not a real character
				// STRONGLY suggests somebody is using a bogus charset.
				// This could be in order to break the filter.
				if(logDEBUG) Logger.debug(this, "Removing '"+c+"' from the output stream");
				continue;
			}
			else {
				out.append(c);
			}
		}
		String sout = out.toString();

		if (pc.inStyle || pc.inScript) {
			pc.currentStyleScriptChunk += sout;
			return; // is parsed and written elsewhere
		}
		if(pc.cb != null)
			pc.cb.onText(HTMLDecoder.decode(sout), tagName); /* Tag name is given as type for the text */

		w.write(sout);
	}

	String processTag(List<String> splitTag, Writer w, HTMLParseContext pc)
		throws IOException, DataFilterException {
		// First, check that it is a recognized tag
		if(logDEBUG) {
			for(int i=0;i<splitTag.size();i++)
				Logger.debug(this, "Tag["+i+"]="+splitTag.get(i));
		}
		ParsedTag t = new ParsedTag(splitTag);
		if (!pc.killTag) {
			t = t.sanitize(pc);
			if (t != null) {
				// We have to check whether <head> exists etc even if we are just checking the charset.
				// This enables us to quit when we see </head>.

				//We need to make sure that <head> is present in the document. If it is not, then GWT javascript won't get loaded.
				//To achieve this, we keep track whether we processed the <head>
				if(t.element.compareTo("head")==0 && !t.startSlash){
					pc.wasHeadElementFound=true;
				} else if(t.element.compareTo("head")==0 && t.startSlash) {
					pc.headEnded = true;
					if(pc.onlyDetectingCharset) pc.failedDetectCharset = true;
				//If we found a <title> or a <meta> without a <head>, then we need to add them to a <head>
				}else if((t.element.compareTo("meta")==0 || t.element.compareTo("title")==0) && pc.wasHeadElementFound==false){
					pc.openElements.push("head");
					pc.wasHeadElementFound=true;
					String headContent=pc.cb.processTag(new ParsedTag("head", new HashMap<String, String>()));
					if(headContent!=null && !pc.onlyDetectingCharset){
						w.write(headContent);
					}
				}else if((t.element.compareTo("meta")==0 || t.element.compareTo("title")==0) && pc.headEnded){
					throwFilterException(l10n("metaOutsideHead"));
				//If we found a <body> and haven't closed <head> already, then we do
				}else if(t.element.compareTo("body") == 0 &&  pc.openElements.contains("head")){
					if(!pc.onlyDetectingCharset) w.write("</head>");
					pc.headEnded = true;
					if(pc.onlyDetectingCharset) pc.failedDetectCharset = true;
					pc.openElements.pop();
				//If we found a <body> and no <head> before it, then we insert it
				}else if(t.element.compareTo("body")==0 && pc.wasHeadElementFound==false){
					pc.wasHeadElementFound=true;
					String headContent=pc.cb.processTag(new ParsedTag("head", new HashMap<String, String>()));
					if(headContent!=null){
						if(!pc.onlyDetectingCharset) w.write(headContent+"</head>");
						pc.headEnded = true;
						if(pc.onlyDetectingCharset) pc.failedDetectCharset = true;
					}
				}

				if(!pc.onlyDetectingCharset) {

					//If the tag needs replacement, then replace it
					String newContent=pc.cb.processTag(t);
					if(newContent!=null){
						w.write(newContent);
						if(t.endSlash==false){
							pc.openElements.push(t.element);
						}
					}else{
						if (pc.writeStyleScriptWithTag) {
							pc.writeStyleScriptWithTag = false;
							String style = pc.currentStyleScriptChunk;
							if ((style == null) || (style.length() == 0))
								pc.writeAfterTag.append("<!-- "+l10n("deletedUnknownStyle")+" -->");
							else
								w.write(style);
							pc.currentStyleScriptChunk = "";
						}

						t.write(w,pc);
						if (pc.writeAfterTag.length() > 0) {
							w.write(pc.writeAfterTag.toString());
							pc.writeAfterTag = new StringBuilder(1024);
						}
					}
				} else
					pc.writeStyleScriptWithTag = false;
			}
			if(t == null || t.startSlash || t.endSlash) {
				if(!pc.openElements.isEmpty())
					return pc.openElements.peek();
				if (pc.writeAfterTag.length() > 0) {
					w.write(pc.writeAfterTag.toString());
					pc.writeAfterTag = new StringBuilder(1024);
				}
				return null;
			} else return t.element;
		} else {
			pc.killTag = false;
			pc.writeStyleScriptWithTag = false;
			return null;
		}
	}

	void saveComment(StringBuilder s, Writer w, HTMLParseContext pc)
		throws IOException {
		if(pc.onlyDetectingCharset) return;
		if((s.length() > 3) && (s.charAt(0) == '!') && (s.charAt(1) == '-') && (s.charAt(2) == '-')) {
			s.delete(0, 3);
			if(s.charAt(s.length()-1) == '-')
				s.setLength(s.length()-1);
			if(s.charAt(s.length()-1) == '-')
				s.setLength(s.length()-1);
		}
		if(logDEBUG) Logger.debug(this, "Saving comment: "+s.toString());
		if (pc.expectingBadComment)
			return; // ignore it

		if (pc.inStyle || pc.inScript) {
			pc.currentStyleScriptChunk += s;
			return; // </style> handler should write
		}
		if (pc.killTag) {
			pc.killTag = false;
			return;
		}
		StringBuilder sb = new StringBuilder();
		for(int i=0;i<s.length();i++) {
			char c = s.charAt(i);
			if(c == '<') {
				sb.append("&lt;");
			} else if(c == '>') {
				sb.append("&gt;");
			} else {
				sb.append(c);
			}
		}
		s = sb;
		w.write("<!-- ");
		w.write(s.toString());
		w.write(" -->");
	}

	static void throwFilterException(String msg) throws DataFilterException {
		// FIXME
		String longer = l10n("failedToParseLabel");
		throw new DataFilterException(longer, longer, msg);
	}

	public static class ParsedTag {
		public final String element;
		public final String[] unparsedAttrs;
		final boolean startSlash;
		final boolean endSlash;
		/*
		 * public ParsedTag(ParsedTag t) { this.element = t.element;
		 * this.unparsedAttrs = (String[]) t.unparsedAttrs.clone();
		 * this.startSlash = t.startSlash; this.endSlash = t.endSlash; }
		 */

		public ParsedTag(String elementName,Map<String,String> attributes){
			this.element=elementName;
			startSlash=false;
			endSlash=true;
			String[] attrs=new String[attributes.size()];
			int pos=0;
			for(Entry<String,String> entry:attributes.entrySet()){
				attrs[pos++]=entry.getKey()+"=\""+entry.getValue()+"\"";
			}
			this.unparsedAttrs = attrs;
		}

		public ParsedTag(ParsedTag t, String[] outAttrs) {
			this.element = t.element;
			this.unparsedAttrs = outAttrs;
			this.startSlash = t.startSlash;
			this.endSlash = t.endSlash;
		}

		public ParsedTag(ParsedTag t, Map<String,String> attributes){
			String[] attrs=new String[attributes.size()];
			int pos=0;
			for(Entry<String,String> entry:attributes.entrySet()){
				attrs[pos++]=entry.getKey()+"=\""+entry.getValue()+"\"";
			}
			this.element = t.element;
			this.unparsedAttrs = attrs;
			this.startSlash = t.startSlash;
			this.endSlash = t.endSlash;
		}

		public ParsedTag(List<String> v) {
			int len = v.size();
			if (len == 0) {
				element = null;
				unparsedAttrs = new String[0];
				startSlash = endSlash = false;
				return;
			}
			String s = v.get(len - 1);
			if (((len - 1 != 0) || (s.length() > 1)) && s.endsWith("/")) {
				s = s.substring(0, s.length() - 1);
				v.set(len - 1, s);
				if (s.length() == 0)
					len--;
				endSlash = true;
				// Don't need to set it back because everything is an I-value
			} else endSlash = false;
			s = v.get(0);
			if ((s.length() > 1) && s.startsWith("/")) {
				s = s.substring(1);
				v.set(0, s);
				startSlash = true;
			} else startSlash = false;
			element = v.get(0);
			if (len > 1) {
				unparsedAttrs = new String[len - 1];
				for (int x = 1; x < len; x++)
					unparsedAttrs[x - 1] = v.get(x);
			} else
				unparsedAttrs = new String[0];
			if(logDEBUG) Logger.debug(this, "Element = "+element);
		}

		public ParsedTag sanitize(HTMLParseContext pc) throws DataFilterException {
			TagVerifier tv =
				allowedTagsVerifiers.get(element.toLowerCase());
			if(logDEBUG) Logger.debug(this, "Got verifier: "+tv+" for "+element);
			if (tv == null) {
				if (deleteWierdStuff) {
					return null;
				} else {
					String err = "<!-- "+HTMLEncoder.encode(l10n("unknownTag", "tag", element))+ " -->";
					if (!deleteErrors)
						throwFilterException(l10n("unknownTagLabel") + ' ' + err);
					return null;
				}
			}
			return tv.sanitize(this, pc);
		}

		@Override
		public String toString() {
			if (element == null)
				return "";
			StringBuilder sb = new StringBuilder("<");
			if (startSlash)
				sb.append('/');
			sb.append(element);
			if (unparsedAttrs != null) {
				int n = unparsedAttrs.length;
				for (int i = 0; i < n; i++) {
					sb.append(' ').append(unparsedAttrs[i]);
				}
			}
			if (endSlash)
				sb.append(" /");
			sb.append('>');
			return sb.toString();
		}

		public Map<String,String> getAttributesAsMap(){
			Map<String,String> map=new HashMap<String, String>();
			for(String attr: unparsedAttrs) {
				String name=attr.substring(0,attr.indexOf('='));
				String value=attr.substring(attr.indexOf('=')+2,attr.length()-1);
				map.put(name, value);
			}
			return map;
		}

		public void htmlwrite(Writer w,HTMLParseContext pc) throws IOException {
			String s = toString();
			if(pc.getisXHTML())
			{
				if(ElementInfo.isVoidElement(element) && s.charAt(s.length()-2)!='/')
				{
					s=s.substring(0,s.length()-1)+" />";
				}
			}
			if (s != null) {
				w.write(s);
			}
		}

		public void write(Writer w,HTMLParseContext pc) throws IOException {
			if(!startSlash)
			{
				if(ElementInfo.tryAutoClose(element) && element.equals(pc.peekTopElement()))
					pc.closeXHTMLTag(element, w);
				if(pc.getisXHTML() &&  !ElementInfo.isVoidElement(element))
					pc.pushElementInStack(element);
				htmlwrite(w,pc);
			}
			else
			{
				if(pc.getisXHTML())
				{
					pc.closeXHTMLTag(element, w);
				}
				else
				{
					htmlwrite(w,pc);
				}
			}
		}
	}

	public static Set<String> getAllowedHTMLTags() {
		return Collections.unmodifiableSet(allowedHTMLTags);
	}

	private static final Set<String> allowedHTMLTags = new HashSet<String>();
	static final Map<String, TagVerifier> allowedTagsVerifiers =
		Collections.unmodifiableMap(getAllowedTagVerifiers());
	private static final String[] emptyStringArray = new String[0];

	private static Map<String, TagVerifier> getAllowedTagVerifiers()
	{
		Map<String, TagVerifier> allowedTagsVerifiers = new HashMap<String, TagVerifier>();

		allowedTagsVerifiers.put("?xml", new XmlTagVerifier());
		allowedTagsVerifiers.put(
			"!doctype",
			new DocTypeTagVerifier("!doctype"));
		allowedTagsVerifiers.put("html", new HtmlTagVerifier());
		allowedTagsVerifiers.put(
			"head",
			new TagVerifier(
				"head",
				new String[] { "id" },
				// Don't support profiles.
				// We don't know what format they might be in, whether they will be parsed even though they have bogus MIME types (which seems likely), etc.
				new String[] { /*"profile"*/ },
				null,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"title",
			new TagVerifier("title", new String[] { "id" }));
		allowedTagsVerifiers.put("meta", new MetaTagVerifier());
		allowedTagsVerifiers.put(
			"body",
			new CoreTagVerifier(
				"body",
				new String[] { "bgcolor", "text", "link", "vlink", "alink" },
				null,
				new String[] { "background" },
				new String[] { "onload", "onunload" },
				emptyStringArray));
		String[] group =
			{ "div", "h1", "h2", "h3", "h4", "h5", "h6", "p", "caption" };
		for (String x: group)
			allowedTagsVerifiers.put(
				x,
				new CoreTagVerifier(
					x,
					new String[] { "align" },
					emptyStringArray,
					emptyStringArray,
					emptyStringArray,
					emptyStringArray));
		String[] group2 =
			{
				"span",
				"address",
				"em",
				"strong",
				"dfn",
				"code",
				"samp",
				"kbd",
				"var",
				"cite",
				"abbr",
				"acronym",
				"sub",
				"sup",
				"dt",
				"dd",
				"tt",
				"i",
				"b",
				"big",
				"small",
				"strike",
				"s",
				"u",
				"noframes",
				"fieldset",
// Delete <noscript> / </noscript>. So we can at least see the non-scripting code.
//				"noscript",
				"xmp",
				"listing",
				"plaintext",
				"center",
				"bdo",
				"aside",
				"header",
				"nav",
				"footer",
				"article",
				"section",
				"hgroup"};
		for (String x: group2)
			allowedTagsVerifiers.put(
				x,
				new CoreTagVerifier(
					x,
					emptyStringArray,
					emptyStringArray,
					emptyStringArray,
					emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"blockquote",
			new CoreTagVerifier(
				"blockquote",
				emptyStringArray,
				new String[] { "cite" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"q",
			new CoreTagVerifier(
				"q",
				emptyStringArray,
				new String[] { "cite" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"br",
			new BaseCoreTagVerifier(
				"br",
				new String[] { "clear" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"pre",
			new CoreTagVerifier(
				"pre",
				new String[] { "width", "xml:space" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"ins",
			new CoreTagVerifier(
				"ins",
				new String[] { "datetime" },
				new String[] { "cite" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"del",
			new CoreTagVerifier(
				"del",
				new String[] { "datetime" },
				new String[] { "cite" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"ul",
			new CoreTagVerifier(
				"ul",
				new String[] { "type", "compact" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"ol",
			new CoreTagVerifier(
				"ol",
				new String[] { "type", "compact", "start" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"li",
			new CoreTagVerifier(
				"li",
				new String[] { "type", "value" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"dl",
			new CoreTagVerifier(
				"dl",
				new String[] { "compact" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"dir",
			new CoreTagVerifier(
				"dir",
				new String[] { "compact" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"menu",
			new CoreTagVerifier(
				"menu",
				new String[] { "compact" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"table",
			new CoreTagVerifier(
				"table",
				new String[] {
					"summary",
					"width",
					"border",
					"frame",
					"rules",
					"cellspacing",
					"cellpadding",
					"align",
					"bgcolor" },
				emptyStringArray,
				new String[] { "background" },
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"thead",
			new CoreTagVerifier(
				"thead",
				new String[] { "align", "char", "charoff", "valign" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"tfoot",
			new CoreTagVerifier(
				"tfoot",
				new String[] { "align", "char", "charoff", "valign" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"tbody",
			new CoreTagVerifier(
				"tbody",
				new String[] { "align", "char", "charoff", "valign" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"colgroup",
			new CoreTagVerifier(
				"colgroup",
				new String[] {
					"span",
					"width",
					"align",
					"char",
					"charoff",
					"valign" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"col",
			new CoreTagVerifier(
				"col",
				new String[] {
					"span",
					"width",
					"align",
					"char",
					"charoff",
					"valign" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"tr",
			new CoreTagVerifier(
				"tr",
				new String[] {
					"align",
					"char",
					"charoff",
					"valign",
					"bgcolor" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"th",
			new CoreTagVerifier(
				"th",
				new String[] {
					"abbr",
					"axis",
					"headers",
					"scope",
					"rowspan",
					"colspan",
					"align",
					"char",
					"charoff",
					"valign",
					"nowrap",
					"bgcolor",
					"width",
					"height" },
				emptyStringArray,
				new String[] { "background" },
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"td",
			new CoreTagVerifier(
				"td",
				new String[] {
					"abbr",
					"axis",
					"headers",
					"scope",
					"rowspan",
					"colspan",
					"align",
					"char",
					"charoff",
					"valign",
					"nowrap",
					"bgcolor",
					"width",
					"height" },
				emptyStringArray,
				new String[] { "background" },
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"a",
			new LinkTagVerifier(
				"a",
				new String[] {
					"accesskey",
					"tabindex",
					"name",
					"shape",
					"coords",
					"target" },
				emptyStringArray,
				emptyStringArray,
				new String[] { "onfocus", "onblur" }));
		allowedTagsVerifiers.put(
			"link",
			new LinkTagVerifier(
				"link",
				new String[] { "media", "target" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"base",
			new BaseHrefTagVerifier(
				"base",
				new String[] { "id", "target" },
				new String[] { /* explicitly sanitized by class */ }));
		allowedTagsVerifiers.put(
			"img",
			new CoreTagVerifier(
				"img",
				new String[] {
					"alt",
					"name",
					"height",
					"width",
					"ismap",
					"align",
					"border",
					"hspace",
					"vspace" },
				new String[] { "longdesc", "usemap" },
				new String[] { "src" },
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"map",
			new CoreTagVerifier(
				"map",
				new String[] { "name" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"area",
			new CoreTagVerifier(
				"area",
				new String[] {
					"accesskey",
					"tabindex",
					"shape",
					"coords",
					"nohref",
					"alt",
					"target" },
				new String[] { "href" },
				emptyStringArray,
				new String[] { "onfocus", "onblur" },
				emptyStringArray));
		allowedTagsVerifiers.put(
			"audio", // currently just minimal support
			new MediaTagVerifier(
				"audio",
				emptyStringArray,
				emptyStringArray, // uris
				new String[] { "src" }, // inline uris
				emptyStringArray,
				new String[] { // boolean attributes
					"preload",
					"controls",
					"loop"}));
		allowedTagsVerifiers.put(
			"video", // currently just minimal support
			new MediaTagVerifier(
				"video",
				new String[] {"width", "height" },
				emptyStringArray, // uris
				new String[] { "src", "poster" }, // inline uris
				emptyStringArray,
				new String[] { // boolean attributes
					"preload",
					"controls",
					"loop"}));
		allowedTagsVerifiers.put(
			"source", // currently just minimal support
			new MediaTagVerifier(
				"source",
				emptyStringArray, // media is disallowed because it might leak device info, type is disallowed because it could allow tricking a browser into interpreting a file with another mime-type.
				emptyStringArray, // uris
				new String[] { "src" }, // inline uris
				emptyStringArray,
				emptyStringArray));
		// TODO: param tag?
		// http://www.w3.org/TR/html4/struct/objects.html#h-13.3.2
		// applet tag PROHIBITED - we do not support applets
		allowedTagsVerifiers.put("style", new StyleTagVerifier());
		allowedTagsVerifiers.put(
			"font",
			new BaseCoreTagVerifier(
				"font",
				new String[] { "size", "color", "face" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"basefont",
			new BaseCoreTagVerifier(
				"basefont",
				new String[] { "size", "color", "face" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"hr",
			new CoreTagVerifier(
				"hr",
				new String[] { "align", "noshade", "size", "width" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"frameset",
			new CoreTagVerifier(
				"frameset",
				new String[] { "rows", "cols" },
				emptyStringArray,
				emptyStringArray,
				new String[] { "onload", "onunload" },
				emptyStringArray,
				false));
		allowedTagsVerifiers.put(
			"frame",
			new BaseCoreTagVerifier(
				"frame",
				new String[] {
					"name",
					"frameborder",
					"marginwidth",
					"marginheight",
					"noresize",
					"scrolling" },
				new String[]  { "longdesc" },
				new String[] { "src" },
				emptyStringArray));
		allowedTagsVerifiers.put(
			"iframe",
			new BaseCoreTagVerifier(
				"iframe",
				new String[] {
					"name",
					"frameborder",
					"marginwidth",
					"marginheight",
					"scrolling",
					"align",
					"height",
					"width" },
				new String[] { "longdesc"},
				new String[] { "src" },
				emptyStringArray));

		allowedTagsVerifiers.put(
			"form",
			new FormTagVerifier(
				"form",
				new String[] {
					"name" }, // FIXME add a whitelist filter for accept
					// All other attributes are handled by FormTagVerifier.
				new String[] { },
				new String[] { "onsubmit", "onreset" }));
		allowedTagsVerifiers.put(
			"input",
			new InputTagVerifier(
				"input",
				new String[] {
					"accesskey",
					"tabindex",
					"type",
					"name",
					"value",
					"checked",
					"disabled",
					"readonly",
					"size",
					"maxlength",
					"alt",
					"ismap",
					"accept",
					"align" },
				new String[] { "usemap" },
				new String[] { "src" },
				new String[] { "onfocus", "onblur", "onselect", "onchange" }));
		allowedTagsVerifiers.put(
			"button",
			new CoreTagVerifier(
				"button",
				new String[] {
					"accesskey",
					"tabindex",
					"name",
					"value",
					"type",
					"disabled" },
				emptyStringArray,
				emptyStringArray,
				new String[] { "onfocus", "onblur" },
				emptyStringArray));
		allowedTagsVerifiers.put(
			"select",
			new CoreTagVerifier(
				"select",
				new String[] {
					"name",
					"size",
					"multiple",
					"disabled",
					"tabindex" },
				emptyStringArray,
				emptyStringArray,
				new String[] { "onfocus", "onblur", "onchange" },
				emptyStringArray));
		allowedTagsVerifiers.put(
			"optgroup",
			new CoreTagVerifier(
				"optgroup",
				new String[] { "disabled", "label" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"option",
			new CoreTagVerifier(
				"option",
				new String[] { "selected", "disabled", "label", "value" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"textarea",
			new CoreTagVerifier(
				"textarea",
				new String[] {
					"accesskey",
					"tabindex",
					"name",
					"rows",
					"cols",
					"disabled",
					"readonly" },
				emptyStringArray,
				emptyStringArray,
				new String[] { "onfocus", "onblur", "onselect", "onchange" },
				emptyStringArray));
		allowedTagsVerifiers.put(
			"isindex",
			new BaseCoreTagVerifier(
				"isindex",
				new String[] { "prompt" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"label",
			new CoreTagVerifier(
				"label",
				new String[] { "for", "accesskey" },
				emptyStringArray,
				emptyStringArray,
				new String[] { "onfocus", "onblur" },
				emptyStringArray));
		allowedTagsVerifiers.put(
			"legend",
			new CoreTagVerifier(
				"legend",
				new String[] { "accesskey", "align" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put("script", new ScriptTagVerifier());
		/* MathML 3.0 support for presentation markup, deprecated attributes
		 * not included so don't try using them. xref not supported as it is
		 * mainly used to link presentation and content in parallel markup.
		 *
		 * Content markup not supported as it is larger and presumably not
		 * used that much, and **HAS SECURITY ISSUES**: Content markup uses
		 * Content Dictionaries, which by default are loaded from a default
		 * URL on the web.
		 * See attributes: cdgroup, definitionURL, cd.
		 * Elements: csymbol, annotation, annotation-xml. */
		allowedTagsVerifiers.put(
			"math",
			new CoreTagVerifier(
				"math",
				new String[] {
					"accent",
					"accentunder",
					"align",
					"alignmentscope",
					"altimg-height",
					"altimg-valign",
					"altimg-width",
					"alttext",
					"bevelled",
					"charalign",
					"charspacing",
					"close",
					"columnalign",
					"columnlines",
					"columnspacing",
					"columnspan",
					"columnwidth",
					"crossout",
					"decimalpoint",
					"depth",
					"denomalign",
					"dir",
					"display",
					"displaystyle",
					"edge",
					"equalcolumns",
					"equalrows",
					"fence",
					"form",
					"frame",
					"framespacing",
					"groupalign",
					"height",
					"indentalign",
					"indentalignfirst",
					"indentalignlast",
					"indentshift",
					"indentshiftfirst",
					"indentshiftlast",
					"indenttarget",
					"infixlinebreakstyle",
					"largeop",
					"leftoverhang",
					"length",
					"linebreak",
					"linebreakmultchar",
					"linebreakstyle",
					"lineleading",
					"location",
					"lquote",
					"lspace",
					"linethickness",
					"longdivstyle",
					"mathbackground",
					"mathcolor",
					"mathsize",
					"mathvariant",
					"maxsize",
					"maxwidth",
					"minlabelspacing",
					"minsize",
					"movablelimits",
					"mslinethickness",
					"notation",
					"numalign",
					"open",
					"overflow",
					"position",
					"rightoverhang",
					"rowalign",
					"rowlines",
					"rowspacing",
					"rowspan",
					"rquote",
					"rspace",
					"scriptlevel",
					"scriptminsize",
					"scriptsizemultiplier",
					"separator",
					"separators",
					"shift",
					"side",
					"stackalign",
					"stretchy",
					"subscriptshift",
					"superscriptshift",
					"symmetric",
					"voffset",
					"width" },
				new String[] { "href" },
				new String[] { "altimg" },
				emptyStringArray,
                emptyStringArray));
		//MathML Presentation tags follow
		String[] mathmlempty =
			{
				"mprescripts",
				"none"};
		for (String x: mathmlempty)
			allowedTagsVerifiers.put(
				x,
				new CoreTagVerifier(
					x,
					emptyStringArray,
					emptyStringArray,
					emptyStringArray,
					emptyStringArray,
					emptyStringArray));
		String[] mathmlpresent =
			{
				"merror",
				"mphantom",
				"mroot",
				"msqrt"};
		for (String x: mathmlpresent)
			allowedTagsVerifiers.put(
				x,
				new CoreTagVerifier(
					x,
					new String[] { "mathbackground", "mathcolor" },
					new String[] { "href" },
					emptyStringArray,
					emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"msub",
			new CoreTagVerifier(
				"msub",
				new String[] { "mathbackground", "mathcolor", "subscriptshift" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
                    emptyStringArray));
		allowedTagsVerifiers.put(
			"msup",
			new CoreTagVerifier(
				"msup",
				new String[] { "mathbackground", "mathcolor", "superscriptshift" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		String[] mathmlscripts =
			{
				"msubsup",
				"mmultiscripts"};
		for (String x: mathmlscripts)
			allowedTagsVerifiers.put(
				x,
				new CoreTagVerifier(
					x,
					new String[] { "mathbackground", "mathcolor", "subscriptshift", "superscriptshift" },
					new String[] { "href" },
					emptyStringArray,
					emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
		    "msrow",
			new CoreTagVerifier(
				"msrow",
				new String[] { "mathbackground", "mathcolor", "position" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"msgroup",
			new CoreTagVerifier(
				"msgroup",
				new String[] { "mathbackground", "mathcolor", "position", "shift" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"menclose",
			new CoreTagVerifier(
				"menclose",
				new String[] { "mathbackground", "mathcolor", "notation" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"msline",
			new CoreTagVerifier(
				"msline",
				new String[] { "leftoverhang", "length", "mathbackground", "mathcolor", "mslinethickness", "position", "rightoverhang" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"maligngroup",
			new CoreTagVerifier(
				"maligngroup",
				new String[] { "groupalign", "mathbackground", "mathcolor" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"malignmark",
			new CoreTagVerifier(
				"malignmark",
				new String[] { "edge", "mathbackground", "mathcolor" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"mrow",
			new CoreTagVerifier(
				"mrow",
				new String[] { "dir", "mathbackground", "mathcolor" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		String[] mathmlitem =
			{
				"mi",
				"mn",
				"mtext"};
		for (String x: mathmlitem)
			allowedTagsVerifiers.put(
				x,
				new CoreTagVerifier(
					x,
					new String[] { "dir", "mathbackground", "mathcolor", "mathsize", "mathvariant" },
					new String[] { "href" },
					emptyStringArray,
					emptyStringArray,
					emptyStringArray));
	    allowedTagsVerifiers.put(
			"ms",
			new CoreTagVerifier(
				"ms",
				new String[] { "dir", "lquote", "mathbackground", "mathcolor", "mathsize", "mathvariant", "rquote" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"mpadded",
			new CoreTagVerifier(
				"mpadded",
				new String[] { "depth", "height", "lspace", "mathbackground", "mathcolor", "voffset", "width" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"mspace",
			new CoreTagVerifier(
				"mspace",
				new String[] {
					"depth",
					"dir",
					"height",
					"indentalign",
					"indentalignfirst",
					"indentalignlast",
					"indentshift",
					"indentshiftfirst",
					"indentshiftlast",
					"indenttarget",
					"linebreak",
					"mathbackground",
					"mathcolor",
					"mathsize",
					"mathvariant",
					"width" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"mscarry",
			new CoreTagVerifier(
				"mscarry",
				new String[] { "crossout", "location", "mathbackground", "mathcolor" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"mscarries",
			new CoreTagVerifier(
				"mscarries",
				new String[] { "crossout", "location", "mathbackground", "mathcolor", "position", "scriptsizemultiplier" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		String[] mathmltr =
			{
				"mtr",
				"mlabeledtr"};
		for (String x: mathmltr)
			allowedTagsVerifiers.put(
				x,
				new CoreTagVerifier(
					x,
					new String[] { "columnalign", "groupalign", "mathbackground", "mathcolor", "rowalign" },
					new String[] { "href" },
					emptyStringArray,
					emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"mtd",
			new CoreTagVerifier(
				"mtd",
				new String[] { "columnalign", "columnspan", "groupalign", "mathbackground", "mathcolor", "rowalign", "rowspan" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"mfenced",
			new CoreTagVerifier(
				"mfenced",
				new String[] { "close", "mathbackground", "mathcolor", "open", "separators" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
					emptyStringArray));
		allowedTagsVerifiers.put(
			"mfrac",
			new CoreTagVerifier(
				"mfrac",
				new String[] { "bevelled", "denomalign", "linethickness", "mathbackground", "mathcolor", "numalign" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"mglyph",
			new CoreTagVerifier(
				"mglyph",
				new String[] { "alt", "height", "mathbackground", "mathcolor", "valign", "width" },
				new String[] { "href" },
				new String[] { "src" },
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"mstack",
			new CoreTagVerifier(
				"mstack",
				new String[] { "align", "charalign", "charspacing", "mathbackground", "mathcolor", "stackalign" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"mlongdiv",
			new CoreTagVerifier(
				"mlongdiv",
				new String[] { "align", "charalign", "charspacing", "longdivstyle", "mathbackground", "mathcolor", "stackalign" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
		    "mtable",
			new CoreTagVerifier(
				"mtable",
				new String[] {
					"align",
					"alignmentscope",
					"columnalign",
					"columnlines",
					"columnspacing",
					"columnwidth",
					"displaystyle",
					"equalcolumns",
					"equalrows",
					"frame",
					"framespacing",
					"groupalign",
					"mathbackground",
					"mathcolor",
					"minlabelspacing",
					"rowalign",
					"rowlines",
					"rowspacing",
					"side",
					"width" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"munder",
			new CoreTagVerifier(
				"munder",
				new String[] { "accentunder", "align", "mathbackground", "mathcolor" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"mo",
			new CoreTagVerifier(
				"mo",
				new String[] {
					"accent",
					"dir",
					"fence",
					"form",
					"indentalign",
					"indentalignfirst",
					"indentalignlast",
					"indentshift",
					"indentshiftfirst",
					"indentshiftlast",
					"indenttarget",
					"largeop",
					"linebreak",
					"linebreakmultchar",
					"linebreakstyle",
					"lineleading",
					"lspace",
					"mathbackground",
					"mathcolor",
					"mathsize",
					"mathvariant",
					"maxsize",
					"minsize",
					"movablelimits",
					"rspace",
					"separator",
					"stretchy",
					"symmetric" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"mover",
			new CoreTagVerifier(
				"mover",
				new String[] { "accent", "align", "mathbackground", "mathcolor" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"munderover",
			new CoreTagVerifier(
				"munderover",
				new String[] { "accent", "accentunder", "align", "mathbackground", "mathcolor" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		allowedTagsVerifiers.put(
			"mstyle",
			new CoreTagVerifier(
				"mstyle",
				new String[] {
					"accent",
					"accentunder",
					"align",
					"alignmentscope",
					"bevelled",
					"charalign",
					"charspacing",
					"close",
					"columnalign",
					"columnlines",
					"columnspacing",
					"columnspan",
					"columnwidth",
					"crossout",
					"decimalpoint",
					"depth",
					"denomalign",
					"dir",
					"displaystyle",
					"edge",
					"equalcolumns",
					"equalrows",
					"fence",
					"form",
					"frame",
					"framespacing",
					"groupalign",
					"height",
					"indentalign",
					"indentalignfirst",
					"indentalignlast",
					"indentshift",
					"indentshiftfirst",
					"indentshiftlast",
					"indenttarget",
					"infixlinebreakstyle",
					"largeop",
					"leftoverhang",
					"length",
					"linebreak",
					"linebreakmultchar",
					"linebreakstyle",
					"lineleading",
					"location",
					"lquote",
					"lspace",
					"linethickness",
					"longdivstyle",
					"mathbackground",
					"mathcolor",
					"mathsize",
					"mathvariant",
					"maxsize",
					"minlabelspacing",
					"minsize",
					"movablelimits",
					"mslinethickness",
					"notation",
					"numalign",
					"open",
					"position",
					"rightoverhang",
					"rowalign",
					"rowlines",
					"rowspacing",
					"rowspan",
					"rquote",
					"rspace",
					"scriptlevel",
					"scriptminsize",
					"scriptsizemultiplier",
					"separator",
					"separators",
					"shift",
					"side",
					"stackalign",
					"stretchy",
					"subscriptshift",
					"superscriptshift",
					"symmetric",
					"voffset",
					"width" },
				new String[] { "href" },
				emptyStringArray,
				emptyStringArray,
				emptyStringArray));
		// <maction> would go here though it seems a bit pointless and may require extra filtering
		// MathML content tags would go here if anyone used them

		return allowedTagsVerifiers;
	}

	static class TagVerifier {
		private final String tag;
		//Attributes which need no sanitation
		private final HashSet<String> allowedAttrs;
		//Attributes which will be sanitized by child classes
		protected final HashSet<String> parsedAttrs;
		private final HashSet<String> uriAttrs;
		private final HashSet<String> inlineURIAttrs;
		final HashSet<String> booleanAttrs;

		TagVerifier(String tag, String[] allowedAttrs) {
			this(tag, allowedAttrs, null, null, null);
		}

		TagVerifier(String tag, String[] allowedAttrs, String[] uriAttrs, String[] inlineURIAttrs, String[] booleanAttrs) {
			this.tag = tag;
			this.allowedAttrs = new HashSet<String>();
			this.parsedAttrs = new HashSet<String>();
			if (allowedAttrs != null) {
				for (String allowedAttr: allowedAttrs)
					this.allowedAttrs.add(allowedAttr);
			}
			this.uriAttrs = new HashSet<String>();
			if (uriAttrs != null) {
				for (String uriAttr: uriAttrs)
					this.uriAttrs.add(uriAttr);
			}
			this.inlineURIAttrs = new HashSet<String>();
			if (inlineURIAttrs != null) {
				for (String inlineURIAttr: inlineURIAttrs)
					this.inlineURIAttrs.add(inlineURIAttr);
			}
			this.booleanAttrs = new HashSet<String>();
			if (booleanAttrs != null) {
				for(int x = 0; x < booleanAttrs.length; x++) {
					this.booleanAttrs.add(booleanAttrs[x]);
				}
			}
		}

		ParsedTag sanitize(ParsedTag t, HTMLParseContext pc) throws DataFilterException {
			/** Map contains the attributes, in order. The key is always the name
			 * of the attribute, but the value can be a raw Object if it has no value.
			 * "src" is different to "src=". Arguably we should probably use null in
			 * the first case and "" in the second case ... FIXME */
			Map<String, Object> h = new LinkedHashMap<String, Object>();
			boolean equals = false;
			String prevX = "";
			if (t.unparsedAttrs != null)
				for (String s: t.unparsedAttrs) {
					if (equals) {
						equals = false;
						s = stripQuotes(s);
						h.remove(prevX);
						h.put(prevX, s);
						prevX = "";
					} else {
						int idx = s.indexOf('=');
						if (idx == s.length() - 1) {
							equals = true;
							if (idx == 0) {
								// prevX already set
							} else {
								prevX = s.substring(0, s.length() - 1);
								prevX = prevX.toLowerCase();
							}
						} else if (idx > -1) {
							String x = s.substring(0, idx);
							if (x.length() == 0)
								x = prevX;
							x = x.toLowerCase();
							String y;
							if (idx == s.length() - 1)
								y = "";
							else
								y = s.substring(idx + 1, s.length());
							y = stripQuotes(y);
							h.remove(x);
							h.put(x, y);
							prevX = x;
						} else {
							h.remove(s);
							h.put(s, new Object());
							prevX = s;
						}
					}
				}
			h = sanitizeHash(h, t, pc);
			if (h == null) return null;
			//Remove any blank entries
			for(Iterator<Entry<String, Object>> it = h.entrySet().iterator(); it.hasNext();){
				Map.Entry<String, Object> entry = it.next();
				if(entry.getValue() == null || entry.getValue().equals("") && pc.isXHTML){
					it.remove();
				}
			}
			//If the tag has no attributes, and this is not allowable, remove it
            if(h.isEmpty() && expungeTagIfNoAttributes()) return null;
			if (t.startSlash)
				return new ParsedTag(t, (String[])null);
			String[] outAttrs = new String[h.size()];
			int i = 0;
			for (Map.Entry<String, Object> entry : h.entrySet()) {
				String x = entry.getKey();
				Object o = entry.getValue();
				String y;
				if (o instanceof String)
					y = (String) o;
				else
					y = null;
				StringBuilder out = new StringBuilder(x);
				if (y != null)
					out.append( "=\"" ).append( y ).append( '"' );
				outAttrs[i++] = out.toString();
			}
			return new ParsedTag(t, outAttrs);
		}

		Map<String, Object> sanitizeHash(Map<String, Object> h,
			ParsedTag p,
			HTMLParseContext pc) throws DataFilterException {
			Map<String, Object> hn = new LinkedHashMap<String, Object>();
			for (Map.Entry<String, Object> entry : h.entrySet()) {
				if(logDEBUG) Logger.debug(this, "HTML Filter is sanitizing: "+entry.getKey()+" = "+entry.getValue());
				String x = entry.getKey();
				Object o = entry.getValue();

				boolean inline = inlineURIAttrs.contains(x);

				//URI attributes require additional processing
				if (inline || uriAttrs.contains(x)) {
					if(!inline) {
						if(logMINOR) Logger.minor(this, "Non-inline URI attribute: "+x);
					} else {
						if(logMINOR) Logger.minor(this, "Inline URI attribute: "+x);
					}
					// URI
					if (o instanceof String) {
						// Java's URL handling doesn't seem suitable
						String uri = (String) o;
						uri = HTMLDecoder.decode(uri);
						uri = htmlSanitizeURI(uri, null, null, null, pc.cb, pc, inline);
						if (uri == null) {
							continue;
						}
						uri = HTMLEncoder.encode(uri);
						o = uri;
					}
					// FIXME: rewrite absolute URLs, handle ?date= etc
					if(logDEBUG) Logger.debug(this, "HTML Filter is putting "+(inline?"inline":"")+" uri attribute: "+x+" =  "+o);
					hn.put(x, o);
					continue;
				}

				/*We create a placeholder for each parsed attribute in the
				 * sanitized output. This ensures the order of the attributes.
				 * Subclasses will take care of parsing and replacing these values.
				 * If they don't, we'll remove the placeholder later.*/
				if(parsedAttrs.contains(x)) {
					hn.put(x, null);
					continue;
				}

				/*If the attribute is to be passed through without sanitation*/
				if(allowedAttrs.contains(x)) {
					hn.put(x, o);
					continue;
				}
				/*Boolean attributes must either be empty or equal to their own name*/
				if(booleanAttrs.contains(x)) {
					String value = null;
					if(o instanceof String ) value = (String) o;
					if((value != null && value.equalsIgnoreCase(x)) || (!pc.isXHTML && o == null)) {
						hn.put(x, o);
						continue;
					}
				}
				// lang, xml:lang and dir can go on anything
				// lang or xml:lang = language [ "-" country [ "-" variant ] ]
				// The variant can be just about anything; no way to test (avian)
				if (x.equals("xml:lang") ||x.equals("lang") || (x.equals("dir") && (o instanceof String) && (((String)o).equalsIgnoreCase("ltr") || ((String)o).equalsIgnoreCase("rtl")))) {
					if(logDEBUG) Logger.debug(this, "HTML Filter is putting attribute: "+x+" =  "+o);
					hn.put(x, o);
				}
			}
			return hn;
		}

		/*If this function returns true, this tag will be removed from
		 * the sanitized output if it has no attributes*/
		protected boolean expungeTagIfNoAttributes() {
			return false;
		}
	}

	static String stripQuotes(String s) {
		final String quotes = "\"'";
		if (s.length() >= 2) {
			int n = quotes.length();
			for (int x = 0; x < n; x++) {
				char cc = quotes.charAt(x);
				if ((s.charAt(0) == cc) && (s.charAt(s.length() - 1) == cc)) {
					if (s.length() > 2)
						s = s.substring(1, s.length() - 1);
					else
						s = "";
					break;
				}
			}
		}
		return s;
	}

	//	static String[] titleString = new String[] {"title"};

	static abstract class ScriptStyleTagVerifier extends TagVerifier {
		ScriptStyleTagVerifier(
			String tag,
			String[] allowedAttrs,
			String[] uriAttrs) {
			super(tag, allowedAttrs, uriAttrs, null, null);
		}

		abstract void setStyle(boolean b, HTMLParseContext pc);

		abstract boolean getStyle(HTMLParseContext pc);

		abstract void processStyle(HTMLParseContext pc);

		@Override
		Map<String, Object> sanitizeHash(Map<String, Object> h,
			ParsedTag p,
			HTMLParseContext pc) throws DataFilterException {
			Map<String, Object> hn = super.sanitizeHash(h, p, pc);
			if (p.startSlash) {
				return finish(h, hn, pc);
			} else {
				return start(h, hn, pc);
			}
		}

		Map<String, Object> finish(Map<String, Object> h, Map<String, Object> hn,
			HTMLParseContext pc) throws DataFilterException {
			if(logDEBUG) Logger.debug(this, "Finishing script/style");
			// Finishing
			setStyle(false, pc);
			pc.styleScriptRecurseCount--;
			if (pc.styleScriptRecurseCount < 0) {
				if (deleteErrors)
					pc.writeAfterTag.append(
						"<!-- " + l10n("tooManyNestedStyleOrScriptTags") + " -->");
				else
					throwFilterException(l10n("tooManyNestedStyleOrScriptTagsLong"));
				return null;
			}
			if(!pc.killStyle) {
				processStyle(pc);
				pc.writeStyleScriptWithTag = true;
			} else {
				pc.killStyle = false;
				pc.currentStyleScriptChunk = "";
			}
			pc.expectingBadComment = false;
			// Pass it on, no params for </style>
			return hn;
		}

		Map<String, Object> start(Map<String, Object> h, Map<String, Object> hn, HTMLParseContext pc)
		        throws DataFilterException {
			if(logDEBUG) Logger.debug(this, "Starting script/style");
			pc.styleScriptRecurseCount++;
			if (pc.styleScriptRecurseCount > 1) {
				if (deleteErrors)
					pc.writeAfterTag.append("<!-- " + l10n("tooManyNestedStyleOrScriptTags") + " -->");
				else
					throwFilterException(l10n("tooManyNestedStyleOrScriptTagsLong"));
				return null;
			}
			setStyle(true, pc);
			String type = getHashString(h, "type");
			if (type != null) {
				if (!type.equalsIgnoreCase("text/css") /* FIXME */
					) {
					pc.killStyle = true;
					pc.expectingBadComment = true;
					return null; // kill the tag
				}
				hn.put("type", "text/css");
			}
			return hn;
		}
	}

	static class StyleTagVerifier extends ScriptStyleTagVerifier {
		StyleTagVerifier() {
			super(
				"style",
				new String[] { "id", "media", "title", "xml:space" },
				emptyStringArray);
		}

		@Override
		void setStyle(boolean b, HTMLParseContext pc) {
			pc.inStyle = b;
		}

		@Override
		boolean getStyle(HTMLParseContext pc) {
			return pc.inStyle;
		}

		@Override
		void processStyle(HTMLParseContext pc) {
			try {
				pc.currentStyleScriptChunk =
					sanitizeStyle(pc.currentStyleScriptChunk, pc.cb, pc, false);
			} catch (DataFilterException e) {
				Logger.error(this, "Error parsing style: "+e, e);
				pc.currentStyleScriptChunk = "";
			}
		}
	}

	static class ScriptTagVerifier extends ScriptStyleTagVerifier {
		ScriptTagVerifier() {
			super(
				"script",
				new String[] {
					"id",
					"charset",
					"type",
					"language",
					"defer",
					"xml:space" },
				new String[] { "src" });
			/*
			 * FIXME: src not supported type ignored (we will need to check
			 * this when if/when we support scripts charset ignored
			 */
		}

		@Override
		Map<String, Object> sanitizeHash(Map<String, Object> hn, ParsedTag p, HTMLParseContext pc)
		        throws DataFilterException {
			// Call parent so we swallow the scripting
			super.sanitizeHash(hn, p, pc);
			return null; // Lose the tags
		}

		@Override
		void setStyle(boolean b, HTMLParseContext pc) {
			pc.inScript = b;
		}

		@Override
		boolean getStyle(HTMLParseContext pc) {
			return pc.inScript;
		}

		@Override
		void processStyle(HTMLParseContext pc) {
			pc.currentStyleScriptChunk =
				sanitizeScripting(pc.currentStyleScriptChunk);
		}
	}

	static class BaseCoreTagVerifier extends TagVerifier {
		private static final String[] locallyVerifiedAttrs = new String[] {
			"id",
			"class",
			"style"
		};

		BaseCoreTagVerifier(
			String tag,
			String[] allowedAttrs,
			String[] uriAttrs,
			String[] inlineURIAttrs, String[] booleanAttrs) {
			super(tag, allowedAttrs, uriAttrs, inlineURIAttrs, booleanAttrs);
			allowedHTMLTags.add(tag);
			for(String attr : locallyVerifiedAttrs) {
				this.parsedAttrs.add(attr);
			}
		}

		@Override
		Map<String, Object> sanitizeHash(Map<String, Object> h,
			ParsedTag p,
			HTMLParseContext pc) throws DataFilterException {
			Map<String, Object> hn = super.sanitizeHash(h, p, pc);
			// %i18n dealt with by TagVerifier
			// %coreattrs
			String id = getHashString(h, "id");
			if (id != null) {
				hn.put("id", id);
				// hopefully nobody will be stupid enough to encode URLs into
				// the unique ID... :)
			}
			String classNames = getHashString(h, "class");
			if (classNames != null) {
				hn.put("class", classNames);
				// ditto
			}
			String style = getHashString(h, "style");
			if (style != null) {
				style = sanitizeStyle(style, pc.cb, pc, true);
				if (style != null)
					style = escapeQuotes(style);
				if (style != null)
					hn.put("style", style);
			}
			String title = getHashString(h, "title");
			if (title != null) {
				// PARANOIA: title is PLAIN TEXT, right? In all user agents? :)
				hn.put("title", title);
			}
			return hn;
		}
	}

	static class CoreTagVerifier extends BaseCoreTagVerifier {
		private final HashSet<String> eventAttrs;
		private static final String[] stdEvents =
			new String[] {
				"onclick",
				"ondblclick",
				"onmousedown",
				"onmouseup",
				"onmouseover",
				"onmousemove",
				"onmouseout",
				"onkeypress",
				"onkeydown",
				"onkeyup",
				"onload",
				"onfocus",
				"onblur",
				"oncontextmenu",
				"onresize",
				"onscroll",
				"onunload",
				"onmouseenter",
				"onchange",
				"onreset",
				"onselect",
				"onsubmit",
				"onerror",
			};

		CoreTagVerifier(
			String tag,
			String[] allowedAttrs,
			String[] uriAttrs,
			String[] inlineURIAttrs,
			String[] eventAttrs,
            String[] booleanAttrs) {
			this(tag, allowedAttrs, uriAttrs, inlineURIAttrs, eventAttrs, booleanAttrs, true);
		}

		CoreTagVerifier(
			String tag,
			String[] allowedAttrs,
			String[] uriAttrs,
			String[] inlineURIAttrs,
			String[] eventAttrs,
			String[] booleanAttrs, boolean addStdEvents) {
			super(tag, allowedAttrs, uriAttrs, inlineURIAttrs, booleanAttrs);
			this.eventAttrs = new HashSet<String>();
			if (eventAttrs != null) {
				for (String eventAttr: eventAttrs) {
					this.eventAttrs.add(eventAttr);
					this.parsedAttrs.add(eventAttr);
				}
			}
			if (addStdEvents) {
				for (String stdEvent: stdEvents) {
					this.eventAttrs.add(stdEvent);
					this.parsedAttrs.add(stdEvent);
				}
			}
		}

		@Override
		Map<String, Object> sanitizeHash(Map<String, Object> h,
			ParsedTag p,
			HTMLParseContext pc) throws DataFilterException {
			Map<String, Object> hn = super.sanitizeHash(h, p, pc);
			// events (default and added)
			for (String name: eventAttrs) {
				String arg = getHashString(h, name);
				if (arg != null) {
					arg = sanitizeScripting(arg);
					if (arg != null)
						hn.put(name, arg);
				}
			}

			return hn;
		}
	}

	static class LinkTagVerifier extends CoreTagVerifier {
		private static final String[] locallyVerifiedAttrs = new String[] {
			"type",
			"charset",
			"rel",
			"rev",
			"media",
			"hreflang",
			"href"
		};

		LinkTagVerifier(
			String tag,
			String[] allowedAttrs,
			String[] uriAttrs,
			String[] inlineURIAttrs,
			String[] eventAttrs) {
			super(tag, allowedAttrs, uriAttrs, inlineURIAttrs, eventAttrs, null);
			for(String attr : locallyVerifiedAttrs) {
				this.parsedAttrs.add(attr);
			}
		}

		@Override
		Map<String, Object> sanitizeHash(Map<String, Object> h,
			ParsedTag p,
			HTMLParseContext pc) throws DataFilterException {
			Map<String, Object> hn = super.sanitizeHash(h, p, pc);
			String hreflang = getHashString(h, "hreflang");
			String charset = null;
			String maybecharset = null;
			String type = getHashString(h, "type");
			if (type != null) {
				String[] typesplit = splitType(type);
				type = typesplit[0];
				if ((typesplit[1] != null) && (typesplit[1].length() > 0))
					charset = typesplit[1];
				if(logDEBUG)
					Logger.debug(
							this,
							"Processing link tag, type="
							+ type
							+ ", charset="
							+ charset);
			}
			String c = getHashString(h, "charset");
			if (c != null)
				charset = c;
			if(charset != null) {
				try {
					charset = URLDecoder.decode(charset, false);
				} catch (URLEncodedFormatException e) {
					charset = null;
				}
			}
			if(charset != null && charset.indexOf('&') != -1)
				charset = null;
			if(charset != null && !Charset.isSupported(charset))
				charset = null;

			// Is it a style sheet?
			// Also, sanitise rel type
			// If neither rel nor rev, return null

			String rel = getHashString(h, "rel");

			String parsedRel = "", parsedRev = "";
			boolean isStylesheet = false;
			boolean isIcon = false;

			if(rel != null) {

				rel = rel.toLowerCase();

				StringTokenizer tok = new StringTokenizer(rel, " ");
				int i=0;
				String prevToken = null;
				StringBuffer sb = new StringBuffer(rel.length());
				while (tok.hasMoreTokens()) {
					String token = tok.nextToken();
					if(token.equalsIgnoreCase("stylesheet")) {
						if(token.equalsIgnoreCase("stylesheet")) {
							isStylesheet = true;
							if(!((i == 0 || i == 1 && prevToken != null && prevToken.equalsIgnoreCase("alternate"))))
								return null;
							if(tok.hasMoreTokens())
								return null; // Disallow extra tokens after "stylesheet"
						}
					} else if (token.equalsIgnoreCase("icon")) {
						isIcon = true;
					} else if(!isStandardLinkType(token)) continue;

					i++;
					if(sb.length() == 0)
						sb.append(token);
					else {
						sb.append(' ');
						sb.append(token);
					}
					prevToken = token;
				}

				parsedRel = sb.toString();
			}

			String rev = getHashString(h, "rev");
			if(rev != null) {

				StringBuffer sb = new StringBuffer(rev.length());
				rev = rev.toLowerCase();

				StringTokenizer tok = new StringTokenizer(rev, " ");
				sb = new StringBuffer(rev.length());

				while (tok.hasMoreTokens()) {
					String token = tok.nextToken();
					if(!isStandardLinkType(token)) continue;
					if(sb.length() == 0)
						sb.append(token);
					else {
						sb.append(' ');
						sb.append(token);
					}
				}


				parsedRev = sb.toString();

			}

			// Allow no rel or rev, even on <link>, as per HTML spec.

			if(parsedRel.length() != 0)
				hn.put("rel", parsedRel);
			if(parsedRev.length() != 0)
				hn.put("rev", parsedRev);

			if(rel != null) {
				if(rel.equals("stylesheet") || rel.equals("alternate stylesheet"))
					isStylesheet = true;
			} else {
				// Not a stylesheet.
				if(type != null && type.startsWith("text/css"))
					return null; // Not a stylesheet, so can't take a stylesheet type.
			}

			if(isStylesheet) {
				if(charset == null) {
					// Browser will use the referring document's charset if there
					// is no BOM and we don't specify one in HTTP.
					// So we need to pass this information to the filter.
					// We cannot force the mime type with the charset, because if
					// we do that, we might be wrong - if there is a BOM or @charset
					// we want to use that. E.g. chinese pages might have the
					// page in GB18030 and the borrowed CSS in ISO-8859-1 or UTF-8.
					maybecharset = pc.charset;
				}
				String media = getHashString(h, "media");
				if(media != null)
					media = CSSReadFilter.filterMediaList(media);
				if(media != null)
					hn.put("media", media);
				if(type != null && !type.startsWith("text/css"))
					return null; // Different style language e.g. XSL, not supported.
				type = "text/css";
			}
			String href = getHashString(h, "href");
			if (href != null) {
				href = HTMLDecoder.decode(href);
				if (isIcon) {
					href = htmlSanitizeURI(href, type, null, null, pc.cb, pc, false);
				} else {
					href = htmlSanitizeURI(href, type, charset, maybecharset, pc.cb, pc, false);
				}
				if (href != null) {
					href = HTMLEncoder.encode(href);
					hn.put("href", href);
					if (type != null)
						hn.put("type", type);
					if (charset != null)
						hn.put("charset", charset);
					if ((charset != null) && (hreflang != null))
						hn.put("hreflang", hreflang);
				}
			}
			// FIXME: allow these if the charset and encoding are encoded into
			// the URL
			return hn;
		}

		// Does not include stylesheet
		private static final HashSet<String> standardRelTypes = new HashSet<String>();
		static {
			for(String s : new String[] {
					"alternate",
					"start",
					"next",
					"prev",
					"contents",
					"index",
					"glossary",
					"copyright",
					"chapter",
					"section",
					"subsection",
					"appendix",
					"help",
					"bookmark"
			}) standardRelTypes.add(s);
		}

		private boolean isStandardLinkType(String token) {
			return standardRelTypes.contains(token.toLowerCase());
		}
	}

    /** Verify media tags (audio and video). This needs its own
     * verifier, because different from images, browsers use content
     * sniffing to find out whether to display it as media
     * content. Using text/plain as content type would allow
     * exploiting this to run unfiltered files as media files. We fix
     * this by encoding the mime type into the uri.*/
	static class MediaTagVerifier extends CoreTagVerifier {
		private static final String[] locallyVerifiedAttrs = new String[] {
			"src"
		};

		MediaTagVerifier(
			String tag,
			String[] allowedAttrs,
			String[] uriAttrs,
			String[] inlineURIAttrs,
			String[] eventAttrs,
			String[] booleanAttrs) {
			super(tag, allowedAttrs, uriAttrs, inlineURIAttrs, eventAttrs, booleanAttrs);
			for(String attr : locallyVerifiedAttrs) {
				this.parsedAttrs.add(attr);
			}
		}

		@Override
		Map<String, Object> sanitizeHash(Map<String, Object> h,
			ParsedTag p,
			HTMLParseContext pc) throws DataFilterException {
			Map<String, Object> hn = super.sanitizeHash(h, p, pc);
			String hreflang = getHashString(h, "hreflang");
			String charset = null;
			String maybecharset = null;

			String src = getHashString(h, "src");
			if (src != null) {
				src = HTMLDecoder.decode(src);
				String type = ContentFilter.mimeTypeForSrc(src);
				src = htmlSanitizeURI(src, type, null, null, pc.cb, pc, false);
				if (src != null) {
					src = HTMLEncoder.encode(src);
					hn.put("src", src);
                }
			}
			return hn;
		}
	}

	// We do not allow forms to act anywhere else than on /
	static class FormTagVerifier extends CoreTagVerifier{
		private static final String[] locallyVerifiedAttrs = new String[] {
			"method",
			"action",
			"enctype",
			"accept-charset"
		};

		FormTagVerifier(
			String tag,
			String[] allowedAttrs,
			String[] uriAttrs,
			String[] eventAttrs) {
			super(tag, allowedAttrs, uriAttrs, null, eventAttrs, null);
			for(String attr : locallyVerifiedAttrs) {
				this.parsedAttrs.add(attr);
			}
		}

		@Override
		Map<String, Object> sanitizeHash(Map<String, Object> h,
			ParsedTag p,
			HTMLParseContext pc) throws DataFilterException {
			Map<String, Object> hn = super.sanitizeHash(h, p, pc);
			if(p.startSlash) {
				// Allow, but only with standard elements
				return hn;
			}
			String method = getHashString(h, "method");
			String action = getHashString(h, "action");
			String finalAction;
			try {
				finalAction = pc.cb.processForm(method, action);
			} catch (CommentException e) {
	            pc.writeAfterTag.append("<!-- ").append(HTMLEncoder.encode(e.toString())).append(" -->");
				return null;
			}
			if(finalAction == null) return null;
			hn.put("method", method);
			hn.put("action", finalAction);
			// Force enctype and accept-charset to acceptable values.
			hn.put("enctype", "multipart/form-data");
			hn.put("accept-charset", "UTF-8");
			return hn;
		}
	}

	static class InputTagVerifier extends CoreTagVerifier{
		private final HashSet<String> allowedTypes;
		private String[] types = new String[]{
			"text",
			"password",
			"checkbox",
			"radio",
			"submit",
			"reset",
			// no ! file
			"hidden",
			"image",
			"button"
		};

		InputTagVerifier(
			String tag,
			String[] allowedAttrs,
			String[] uriAttrs,
			String[] inlineURIAttrs,
			String[] eventAttrs) {
			super(tag, allowedAttrs, uriAttrs, inlineURIAttrs, eventAttrs, null);
			this.allowedTypes = new HashSet<String>();
			if (types != null) {
				for (String type: types) {
					this.allowedTypes.add(type);
				}
			}
		}

		@Override
		Map<String, Object> sanitizeHash(Map<String, Object> h,
			ParsedTag p,
			HTMLParseContext pc) throws DataFilterException {
			Map<String, Object> hn = super.sanitizeHash(h, p, pc);

			// We drop the whole <input> if type isn't allowed
			if(!allowedTypes.contains(hn.get("type"))){
				return null;
			}

			return hn;
		}
	}

	static class MetaTagVerifier extends TagVerifier {
		private static final String[] allowedContentTypes = ContentFilter.HTML_MIME_TYPES;
		private static final String[] locallyVerifiedAttrs = {
			"http-equiv",
			"name",
			"content"
		};

		MetaTagVerifier() {
			super("meta", new String[] { "id" });
			for(String attr : locallyVerifiedAttrs) {
				this.parsedAttrs.add(attr);
				}
			}

		@Override
		Map<String, Object> sanitizeHash(Map<String, Object> h,
			ParsedTag p,
			HTMLParseContext pc) throws DataFilterException {
			Map<String, Object> hn = super.sanitizeHash(h, p, pc);
			/*
			 * Several possibilities: a) meta http-equiv=X content=Y b) meta
			 * name=X content=Y
			 */
			String http_equiv = getHashString(h, "http-equiv");
			String name = getHashString(h, "name");
			String content = getHashString(h, "content");
			String scheme = getHashString(h, "scheme");
			if(logMINOR) Logger.minor(this, "meta: name="+name+", content="+content+", http-equiv="+http_equiv+", scheme="+scheme);
			if (content != null) {
				if ((name != null) && (http_equiv == null)) {
					if (name.equalsIgnoreCase("Author")) {
						hn.put("name", name);
						hn.put("content", content);
					} else if (name.equalsIgnoreCase("Keywords")) {
						hn.put("name", name);
						hn.put("content", content);
					} else if (name.equalsIgnoreCase("Description")) {
						hn.put("name", name);
						hn.put("content", content);
					}
				} else if ((http_equiv != null) && (name == null)) {
					if (http_equiv.equalsIgnoreCase("Expires")) {
						try {
							ToadletContextImpl.parseHTTPDate(content);
							hn.put("http-equiv", http_equiv);
							hn.put("content", content);
						} catch (ParseException e) {
							// Delete it.
							return null;
						}
					} else if (
						http_equiv.equalsIgnoreCase("Content-Script-Type")) {
						// We don't support script at this time.
					} else if (
						http_equiv.equalsIgnoreCase("Content-Style-Type")) {
						// FIXME: charsets
						if (content.equalsIgnoreCase("text/css")) {
							// FIXME: selectable style languages - only matters
							// when we have implemented more than one
							// FIXME: if we ever do allow it... the spec
							// http://www.w3.org/TR/html4/present/styles.html#h-14.2.1
							// says only the last definition counts...
							//        but it only counts if it's in the HEAD section,
							// so we DONT need to parse the whole doc
							hn.put("http-equiv", http_equiv);
							hn.put("content", content);
						}
						// FIXME: add some more headers - Dublin Core?
					} else if (http_equiv.equalsIgnoreCase("Content-Type")) {
						if(logMINOR) Logger.minor(this, "Found http-equiv content-type="+content);
						String[] typesplit = splitType(content);
						if(logDEBUG) {
							for(int i=0;i<typesplit.length;i++)
								Logger.debug(this, "["+i+"] = "+typesplit[i]);
						}
						boolean detected = false;
						for (String allowedContentType: allowedContentTypes) {
							if (typesplit[0].equalsIgnoreCase(allowedContentType)) {
								if((typesplit[1] == null) || (pc.charset != null && typesplit[1]
								        .equalsIgnoreCase(pc.charset))) {
									hn.put("http-equiv", http_equiv);
									hn.put("content", typesplit[0]
									    + (typesplit[1] != null ? "; charset="
										+ typesplit[1] : ""));
								} else if(typesplit[1] != null && pc.charset != null && !typesplit[1].equalsIgnoreCase(pc.charset)) {
									throwFilterException(l10n("wrongCharsetInMeta"));
								} else if(typesplit[1] != null) {
									if(pc.detectedCharset != null)
										throwFilterException(l10n("multipleCharsetsInMeta"));
									pc.detectedCharset = typesplit[1].trim();
								}
								detected = true;
								break;
							}
						}
						if(!detected)
							throwFilterException(l10n("invalidMetaType"));
					} else if (
						http_equiv.equalsIgnoreCase("Content-Language")) {
						if(content.matches("((?>[a-zA-Z0-9]*)(?>-[A-Za-z0-9]*)*(?>,\\s*)?)*") && (!content.trim().equals(""))) {
							hn.put("http-equiv", "Content-Language");
							hn.put("content", content);
						}
					} else if (http_equiv.equalsIgnoreCase("refresh")) {
						int idx = content.indexOf(';');
						if(idx == -1 && metaRefreshSamePageMinInterval >= 0) {
							try {
								int seconds = Integer.parseInt(content);
								if(seconds < 0) return null;
								if(seconds < metaRefreshSamePageMinInterval)
									seconds = metaRefreshSamePageMinInterval;
								hn.put("http-equiv", "refresh");
								hn.put("content", Integer.toString(seconds));
							} catch (NumberFormatException e) {
								// Delete.
								pc.writeAfterTag.append("<!-- doesn't parse as number in meta refresh -->");
								return null;
							}
						} else if(metaRefreshRedirectMinInterval >= 0) {
							int seconds;
							String before = content.substring(0, idx);
							String after = content.substring(idx+1).trim();
							try {
								seconds = Integer.parseInt(before);
								if(seconds < 0) return null;
								if(seconds < metaRefreshRedirectMinInterval) seconds = metaRefreshRedirectMinInterval;
								if(!after.toLowerCase().startsWith("url=")) {
									pc.writeAfterTag.append("<!-- no url but doesn't parse as number in meta refresh -->");
									return null;
								}
								after = after.substring("url=".length()).trim();
								try {
									String url = sanitizeURI(after, null, null, null, pc.cb, false);
									hn.put("http-equiv", "refresh");
									hn.put("content", ""+seconds+"; url="+HTMLEncoder.encode(url));
								} catch (CommentException e) {
									pc.writeAfterTag.append("<!-- "+e.getMessage()+"-->");
									// Delete
									return null;
								}
							} catch (NumberFormatException e) {
								pc.writeAfterTag.append("<!-- doesn't parse as number in meta refresh possibly with url -->");
								// Delete.
								return null;
							}
						}
					}
				}
			}

			/* try HTML5 meta charset declaration. */
			String charset = getHashString(h, "charset");
			if (charset != null) {
				if ((pc.detectedCharset != null) && !charset.equals(pc.detectedCharset)) {
					throwFilterException(l10n("multipleCharsetsInMeta"));
				}
				pc.detectedCharset = charset;
			}

			return hn;
		}

		@Override
		protected boolean expungeTagIfNoAttributes() {
			return true;
		}
	}

	static class DocTypeTagVerifier extends TagVerifier {
		DocTypeTagVerifier(String tag) {
			super(tag, null);
		}

		private static final Map<String, Object> DTDs = new HashMap<String, Object>();

		static {
			DTDs.put(
				"-//W3C//DTD XHTML 1.0 Strict//EN",
				"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd");
			DTDs.put(
				"-//W3C//DTD XHTML 1.0 Transitional//EN",
				"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd");
			DTDs.put(
				"-//W3C//DTD XHTML 1.0 Frameset//EN",
				"http://www.w3.org/TR/xhtml1/DTD/xhtml1-frameset.dtd");
			DTDs.put(
				"-//W3C//DTD XHTML 1.1//EN",
				"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd");
			DTDs.put(
				"-//W3C//DTD HTML 4.01//EN",
				"http://www.w3.org/TR/html4/strict.dtd");
			DTDs.put(
				"-//W3C//DTD HTML 4.01 Transitional//EN",
				"http://www.w3.org/TR/html4/loose.dtd");
			DTDs.put(
				"-//W3C//DTD HTML 4.01 Frameset//EN",
				"http://www.w3.org/TR/html4/frameset.dtd");
			DTDs.put("-//W3C//DTD HTML 3.2 Final//EN", new Object());
		}

		@Override
		ParsedTag sanitize(ParsedTag t, HTMLParseContext pc) {
			// HTML5 is just <!doctype html>
			if(t.unparsedAttrs.length == 1) {
				if (!t.unparsedAttrs[0].equalsIgnoreCase("html"))
					return null;
				return t;
			}
			if (!((t.unparsedAttrs.length == 3) || (t.unparsedAttrs.length == 4)))
				return null;
			if (!t.unparsedAttrs[0].equalsIgnoreCase("html"))
				return null;
			if(t.unparsedAttrs[1].equalsIgnoreCase("system") && t.unparsedAttrs.length == 3) {
				// HTML5 allows <!DOCTYPE html SYSTEM "about:legacy-compat"> (either kind of quotes)
				String s = stripQuotes(t.unparsedAttrs[2]);
				if(s.equals("about:legacy-compat") && t.unparsedAttrs.length == 3) {
					return t;
				} else return null;
			}
			if (!t.unparsedAttrs[1].equalsIgnoreCase("public"))
				return null;
			String s = stripQuotes(t.unparsedAttrs[2]);
			if (!DTDs.containsKey(s))
				return null;
			if (t.unparsedAttrs.length == 4) {
				String ss = stripQuotes(t.unparsedAttrs[3]);
				String spec = getHashString(DTDs, s);
				if ((spec != null) && !spec.equals(ss))
					return null;
			}
			return t;
		}
	}

	static class XmlTagVerifier extends TagVerifier {
		XmlTagVerifier() {
			super("?xml", null);
		}

		@Override
		ParsedTag sanitize(ParsedTag t, HTMLParseContext pc) throws DataFilterException {
			if (t.unparsedAttrs.length != 2 && t.unparsedAttrs.length != 3) {
				if (logMINOR) Logger.minor(this, "Deleting xml declaration, invalid length");
				return null;
			}
			if (t.unparsedAttrs.length == 3 && !t.unparsedAttrs[2].equals("?")) {
				if (logMINOR) Logger.minor(this, "Deleting xml declaration, invalid ending (length 2)");
				return null;
			}
			if (t.unparsedAttrs.length == 2 && !t.unparsedAttrs[1].endsWith("?")) {
				if (logMINOR) Logger.minor(this, "Deleting xml declaration, invalid ending (length 3)");
				return null;
			}
			if (!(t.unparsedAttrs[0].equals("version=\"1.0\"") || t.unparsedAttrs[0].equals("version='1.0'"))) {
				if (logMINOR) Logger.minor(this, "Deleting xml declaration, invalid version");
				return null;
			}
			String encodingAttr = t.unparsedAttrs[1];
			if(encodingAttr.startsWith("encoding=\"")) {
				if(!encodingAttr.endsWith("\"")) {
					if (logMINOR) Logger.minor(this, "Deleting xml declaration, invalid encoding");
					return null;
				}
			} else if(encodingAttr.startsWith("encoding='")) {
				if(!encodingAttr.endsWith("'")) {
					if (logMINOR) Logger.minor(this, "Deleting xml declaration, invalid encoding");
					return null;
				}
			} else {
				if (logMINOR) Logger.minor(this, "Deleting xml declaration, invalid encoding");
				return null;
			}

			String charset = encodingAttr.substring("encoding='".length(), encodingAttr.length()-1);

			if (!charset.equalsIgnoreCase(pc.charset)) {
				if(pc.charset != null && !charset.equalsIgnoreCase(pc.charset)) {
					if (logMINOR) Logger.minor(this, "Deleting xml declaration (invalid charset "
							+ charset + " should be "+pc.charset + ")");
					return null;
				} else if(pc.detectedCharset != null) {
					throwFilterException(l10n("multipleCharsetsInMeta"));
				} else {
					pc.detectedCharset = charset;
				}
			}
			return t;
		}
	}

	static class HtmlTagVerifier extends TagVerifier {
		private static final String[] locallyVerifiedAttrs = new String[] { "xmlns" };
		HtmlTagVerifier() {
			super("html", new String[] { "id", "version" });
			for(String attr : locallyVerifiedAttrs) {
				parsedAttrs.add(attr);
			}
		}

		@Override
		Map<String, Object> sanitizeHash(Map<String, Object> h,
			ParsedTag p,
			HTMLParseContext pc) throws DataFilterException {
			Map<String, Object> hn = super.sanitizeHash(h, p, pc);
			String xmlns = getHashString(h, "xmlns");
			if ((xmlns != null) && xmlns.equals("http://www.w3.org/1999/xhtml")) {
				hn.put("xmlns", xmlns);
				pc.setisXHTML(true);
			}
			return hn;
		}
	}

	static class BaseHrefTagVerifier extends TagVerifier {
		private static final String[] locallyVerifiedAttrs = new String[] {
			"href"};

		BaseHrefTagVerifier(String tag, String[] allowedAttrs, String[] uriAttrs) {
			super(tag, allowedAttrs, uriAttrs, null, emptyStringArray);
			for(String attr : locallyVerifiedAttrs) {
				this.parsedAttrs.add(attr);
			}
		}

		@Override
		Map<String, Object> sanitizeHash(Map<String, Object> h,
				ParsedTag p,
				HTMLParseContext pc) throws DataFilterException {
			Map<String, Object> hn = super.sanitizeHash(h, p, pc);
			String baseHref = getHashString(h, "href");
			if(baseHref != null) {
				// Decode and encode for the same reason we do in sanitizeHash().
				baseHref = HTMLDecoder.decode(baseHref);
				String ref = pc.cb.onBaseHref(baseHref);
				if(ref != null) {
					hn.put("href", HTMLEncoder.encode(ref));
					return hn;
				}
			}
			pc.writeAfterTag.append("<!-- deleted invalid base href -->");
			return null;
		}

	}

	static String sanitizeStyle(String style, FilterCallback cb, HTMLParseContext hpc, boolean isInline) throws DataFilterException {
		if(style == null) return null;
		if(hpc.onlyDetectingCharset) return null;
		Reader r = new StringReader(style);
		Writer w = new StringWriter();
		style = style.trim();
		if(logMINOR) Logger.minor(HTMLFilter.class, "Sanitizing style: " + style);
		CSSParser pc = new CSSParser(r, w, false, cb, hpc.charset, false, isInline);
		try {
			pc.parse();
		} catch (IOException e) {
			Logger.error(
				HTMLFilter.class,
				"IOException parsing inline CSS!");
		} catch (Error e) {
			if (e.getMessage().equals("Error: could not match input")) {
				// this sucks, it should be a proper exception
				Logger.normal(
					HTMLFilter.class,
					"CSS Parse Error!",
					e);
				return "/* "+l10n("couldNotParseStyle")+" */";
			} else
				throw e;
		}
		String s = w.toString();
		if ((s == null) || (s.length() == 0))
			return null;
		//		Core.logger.log(SaferFilter.class, "Style now: " + s, LogLevel.DEBUG);
		if(logMINOR) Logger.minor(HTMLFilter.class, "Style finally: " + s);
		return s;
	}

	static String escapeQuotes(String s) {
		StringBuilder buf = new StringBuilder(s.length());
		for (int x = 0; x < s.length(); x++) {
			char c = s.charAt(x);
			if (c == '\"') {
				buf.append("&quot;");
			} else {
				buf.append(c);
			}
		}
		return buf.toString();
	}

	static String sanitizeScripting(String script) {
		// Kill it. At some point we may want to allow certain recipes - FIXME
		return null;
	}

	static String sanitizeURI(String uri, FilterCallback cb, boolean inline) throws CommentException {
		return sanitizeURI(uri, null, null, null, cb, inline);
	}

	/*
	 * While we're only interested in the type and the charset, the format is a
	 * lot more flexible than that. (avian) TEXT/PLAIN; format=flowed;
	 * charset=US-ASCII IMAGE/JPEG; name=test.jpeg; x-unix-mode=0644
	 */
	public static String[] splitType(String type) {
		StringFieldParser sfp;
		String charset = null, param, name, value;
		int x;

		sfp = new StringFieldParser(type, ';');
		type = sfp.nextField().trim();
		while (sfp.hasMoreFields()) {
			param = sfp.nextField();
			x = param.indexOf('=');
			if (x != -1) {
				name = param.substring(0, x).trim();
				value = param.substring(x + 1).trim();
				if (name.equals("charset"))
					charset = value;
			}
		}
		return new String[] { type, charset };
	}

	// A simple string splitter
	// StringTokenizer doesn't work well for our purpose. (avian)
	static class StringFieldParser {
		private String str;
		private int maxPos, curPos;
		private char c;

		public StringFieldParser(String str) {
			this(str, '\t');
		}

		public StringFieldParser(String str, char c) {
			this.str = str;
			this.maxPos = str.length();
			this.curPos = 0;
			this.c = c;
		}

		public boolean hasMoreFields() {
			return curPos <= maxPos;
		}

		public String nextField() {
			int start, end;

			if (curPos > maxPos)
				return null;
			start = curPos;
			while ((curPos < maxPos) && (str.charAt(curPos) != c))
				curPos++;
			end = curPos;
			curPos++;
			return str.substring(start, end);
		}
	}

	static String htmlSanitizeURI(
			String suri,
			String overrideType,
			String overrideCharset,
			String maybeCharset,
			FilterCallback cb,
			HTMLParseContext pc,
			boolean inline) {
		try {
			return sanitizeURI(suri, overrideType, overrideCharset, maybeCharset, cb, inline);
		} catch (CommentException e) {
            pc.writeAfterTag.append("<!-- ").append(HTMLEncoder.encode(e.toString())).append(" -->");
			return null;
		}
	}

	static String sanitizeURI(
		String suri,
		String overrideType,
		String overrideCharset,
		String maybeCharset,
		FilterCallback cb, boolean inline) throws CommentException {
		if(logMINOR)
			Logger.minor(HTMLFilter.class, "Sanitizing URI: "+suri+" ( override type "+overrideType +" override charset "+overrideCharset+" ) inline="+inline, new Exception("debug"));
		boolean addMaybe = false;
		if((overrideCharset != null) && (overrideCharset.length() > 0))
			overrideType += "; charset="+overrideCharset;
		else if(maybeCharset != null)
			addMaybe = true;
		String retval = cb.processURI(suri, overrideType, false, inline);
		if(addMaybe) {
			if(retval.indexOf('?') != -1)
				retval += "&maybecharset="+maybeCharset;
			else
				retval += "?maybecharset="+maybeCharset;
		}
		return retval;
	}

	static String getHashString(Map<String, Object> h, String key) {
		Object o = h.get(key);
		if (o == null)
			return null;
		if (o instanceof String)
			return (String) o;
		else
			return null;
	}

	private static String l10n(String key) {
		return NodeL10n.getBase().getString("HTMLFilter."+key);
	}

	private static String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("HTMLFilter."+key, pattern, value);
	}

	@Override
	public BOMDetection getCharsetByBOM(byte[] input, int length) throws DataFilterException {
		// No enhanced BOMs.
		// FIXME XML BOMs???
		return null;
	}

	@Override
	public int getCharsetBufferSize() {
		//Read in 64 kilobytes. The charset could be defined anywhere in the head section
		return 1024*64;
	}
}

