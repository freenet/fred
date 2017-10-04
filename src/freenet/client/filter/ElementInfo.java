package freenet.client.filter;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class ElementInfo {

	public static final boolean disallowUnknownSpecificFonts = false;
	/** If true, and above is false, allow font names only if they consist
	 * entirely of spaces, numbers, letters, and ._-,+~
	 */
	public static final boolean disallowNonAlnumFonts = true;
	
	public static final int UPPERLIMIT = 10;
	
	public static final Set<String> VOID_ELEMENTS = 
		Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
			"area",
			"base",
			"basefont",
			"bgsound",
			"br",
			"col",
			"command",
			"embed",
			"event-source",
			"frame",
			"hr",
			"img",
			"input",
			"keygen",
			"link",
			"meta",
			"param",
			"source",
			"spacer",
			"wbr"
	)));

	public static final Set<String> HTML_ELEMENTS = 
		Collections.unmodifiableSet(new HashSet<String>(HTMLFilter.getAllowedHTMLTags()));

	public static final Set<String> REPLACED_ELEMENTS =
		Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
			"img",
			"object",
			"textarea",
			"select",
			"input", // ??? Most input's aren't???
			"applet",
			"button"
	)));

	// FIXME add some more languages.
	public static final Set<String> LANGUAGES =
		Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
			"az",
			"be",
			"bg",
			"cs",
			"de",
			"el",
			"en",
			"es",
			"fi",
			"fr",
			"id",
			"it",
			"ja",
			"ka",
			"kk",
			"ky",
			"lv",
			"mo",
			"nl",
			"no",
			"pl",
			"pt",
			"ro",
			"ru",
			"sv",
			"tl",
			"tr",
			"tt",
			"uk",
			"zh-hans",
			"zh-hant"
	)));

	public static final Set<String> MEDIA = 
		Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
			"all",
			"aural",
			"braille",
			"embossed",
			"handheld",
			"print",
			"projection",
			"screen",
			"speech",
			"tty",
			"tv"
	)));

	public static final Set<String> VISUALMEDIA =
		Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
			"handheld",
			"print",
			"projection",
			"screen",
			"tty",
			"tv"
	)));

	public static final Set<String> AURALMEDIA = 
		Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
			"speech",
			"aural"
	)));

	public static final Set<String> VISUALPAGEDMEDIA = 
		Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
			"embossed",
			"handheld",
			"print",
			"projection",
			"screen",
			"tty",
			"tv"
	)));

	public static final Set<String> VISUALINTERACTIVEMEDIA =
		Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
			"braille",
			"handheld",
			"print",
			"projection",
			"screen",
			"speech",
			"tty",
			"tv"
	)));

	public static final Set<String> FONTS =
		Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
			"arial",
			"helvetica",
			"arial black",
			"gadget",
			"comic sans ms",
			"comic sans ms5",
			"courier new",
			"courier6",
			"monospace georgia1",
			"georgia",
			"impact",
			"impact5",
			"charcoal6",
			"lucida console",
			"monaco5",
			"lucida sans unicode",
			"lucida grande",
			"palatino linotype",
			"book antiqua3",
			"palatino6",
			"tahoma",
			"geneva",
			"times new roman",
			"times",
			"trebuchet ms1",
			"verdana",
			"webdings",
			"webdings2",
			"wingdings",
			"zapf dingbats",
			"wingdings2",
			"zapf dingbats2",
			"ms sans serif4",
			"ms serif4",
			"new york6"
	)));

	public static final Set<String> GENERIC_FONT_KEYWORDS = 
		Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
			"serif",
			"sans-serif",
			"cursive",
			"fantasy",
			"monospace"
	)));

	public static final Set<String> GENERIC_VOICE_KEYWORDS = 
		Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
			"male",
			"female",
			"child"
	)));

	public static final Set<String> PSEUDOCLASS =
		Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
			"first-child",
			"last-child",
			"nth-child",
			"nth-last-child",
			"nth-of-type",
			"nth-last-of-type",
			"link",
			"visited",
			"hover",
			"active",
			"focus",
			"lang",
			"first-line",
			"first-letter",
			"before",
			"after",
			"target"
	)));

	public static final Set<String> BANNED_PSEUDOCLASS =
		Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
			// :visited is considered harmful as it may leak browser history to an adversary.
			// This may not be obvious immediately, but :visited gives an adversary the
			// opportunity to tailor the page to the user's browser history, and may capture
			// this information based on where the user interacts (e.g. he can alternate the
			// visibility of buttons/links on the page based on browser history to encode
			// exactly which sites of interest a user has visited in the past, and use the
			// click to either 1) send this information somewhere through a reachable social
			// networking plugin, or 2) somehow present this knowledge to the user as a scare
			// tactic)
			//
			// The fact that CSS can do Boolean algebra[1] makes this attack easy: the attacker
			// can query a large number of sites in the browser history using only a limited number
			// of previously mentioned buttons or links.
			//
			// A general lack of :visited does not harm the user experience much; especially on
			// Freenet where we often use USKs to visit sites, which are implemented through
			// permanent redirects. Users should hence already expect :visited not to work
			// occasionally. The downside is that some (if only a few) freesites will look
			// less pretty. Given the lack of harm to the overall user experience, and the
			// effectiveness of potential attacks through :visited, we disallow :visited in
			// CSS selectors (by ignoring it).
			//
			// TL;DR: Protecting the user is the main purpose of the CSS ContentFilter, :visited 
			//        is considered too much of a danger, so we scrub that pseudoclass.
			//
			// [1] http://lcamtuf.coredump.cx/css_calc/
			"visited"
	)));

	public static boolean isSpecificFontFamily(String font) {
		if(disallowUnknownSpecificFonts) {
			return FONTS.contains(font);
		} else if(disallowNonAlnumFonts) {
			for(int i=0;i<font.length();i++) {
				char c = font.charAt(i);
				if(!(Character.isLetterOrDigit(c) || c == ' ' || c == '.' || c == '_' || c == '-' || c == ',' || c == '+' || c == '~')) return false;
			}
			return true;
		}
		// Allow anything. The caller will have enforced that unquoted font names must not contain non-identifier characters.
		return true;
	}
	
	public static boolean isSpecificVoiceFamily(String font) {
//		if(disallowUnknownSpecificFonts) {
//			return FONTS.contains(font);
		//} else 
		if(disallowNonAlnumFonts) {
			for(int i=0;i<font.length();i++) {
				char c = font.charAt(i);
				if(!(Character.isLetterOrDigit(c) || c == ' ' || c == '.' || c == '_' || c == '-' || c == ',' || c == '+' || c == '~')) return false;
			}
			return true;
		}
		// Allow anything. The caller will have enforced that unquoted font names must not contain non-identifier characters.
		return true;
	}
	
	/** font must be lower-case */
	public static boolean isGenericFontFamily(String font) {
		return GENERIC_FONT_KEYWORDS.contains(font);
	}
	
	/** font must be lower-case */
	public static boolean isGenericVoiceFamily(String font) {
		return GENERIC_VOICE_KEYWORDS.contains(font);
	}
	
	public static boolean isWordPrefixOrMatchOfSpecificFontFamily(String prefix) {
		String extraSpace = prefix + " ";
		for(String s : FONTS)
			if(s.equals(prefix) || s.startsWith(extraSpace)) return true;
		return false;
	}
	
	public static boolean isVoidElement(String element) {
		return VOID_ELEMENTS.contains(element);
	}
	
	/** These elements are frequently used one after the other, and are invalid inside each other.
	 * AFAICS only <li>. */
	public static boolean tryAutoClose(String element) {
		if("li".equals(element)) return true;
		return false;
	}
	
	public static boolean isValidHTMLTag(String tag)
	{
		return (HTML_ELEMENTS.contains(tag.toLowerCase())||VOID_ELEMENTS.contains(tag.toLowerCase()));
	}
	
	/**
	 * According to the HTML spec, ID must begin with a letter A-Za-z, and 
	 * may be followed by any number of [a-zA-Z0-9-_:.]. It is not spelled
	 * out what is allowed in class, but we are assuming the same is true
	 * there.
	 * @return Whether the string is a valid ID for HTML purposes.
	 */
	public static boolean isValidName(String name)
	{
		if(name.length()==0)
		{
			return false;
		}
		else
		{
			if(!((name.charAt(0)>='a' && name.charAt(0)<='z') || (name.charAt(0)>='A' && name.charAt(0)<='Z')))
			{
				return false;
			}
			else
			{
				
				for(int i=1;i<name.length();i++)
				{
					if(!((name.charAt(i)>='a' && name.charAt(i)<='z') || (name.charAt(i)>='A' && name.charAt(i)<='Z') || (name.charAt(i)>='0' && name.charAt(i)<='9') || name.charAt(i)=='_' || name.charAt(i)==':'  || name.charAt(i)=='.' || name.charAt(i)=='-'))
					{
						return false;
					}
				}
				
			}
			return true;
		}
	}
	
	public static boolean isValidIdentifier(String name)
	{
		if(name.length()==0)
		{
			return false;
		}
		else
		{
			boolean escape = false;
			boolean escapeNewline = false;
			boolean digitsAllowed = false;
			int unicodeChars = 0;
			for(int i=0;i<name.length();i++) {
				char c = name.charAt(i);
				if(escape) {
					// Whitespace after an escape can be \r\n
					if(escapeNewline) {
						escapeNewline = false;
						escape = false;
						if(c == '\n') continue;
					}
					escapeNewline = false;
					if(('0' <= c && '9' >= c) || ('a' <= c && 'f' >= c) || ('A' <= c && 'F' >= c)) {
						if(unicodeChars == 5) {
							// Full 6 character escape.
							unicodeChars = 0;
							escape = false;
							continue;
						} else {
							unicodeChars++;
							continue;
						}
					}
					if(unicodeChars > 0) {
						if(c == '\r') {
							escapeNewline = true;
							unicodeChars = 0;
							continue;
						} else if(!(c == '\n' || c == '\f' || c == '\t' || c == ' ')) {
							// Only whitespace is allowed after a unicode character escape.
							return false;
						}
					}
					if(c == '\r' || c == '\n' || c == '\f')
						// Explicitly not allowed to escape these, see grammar, and 4.1.3.
						return false;
					// Directly escaped character
					escape = false;
					continue;
				}
				if(digitsAllowed && c>='0' && c<='9') {
					continue;
				}
				if(c == '-') continue;
				digitsAllowed = true;
				if(c == '_') continue;
				if(c == '\\') {
					escape = true;
					continue;
				}
				if(c>='a' && c<='z') continue;
				if(c>='A' && c<='Z') continue;
				// Spec strictly speaking allows control chars, but let's disallow them here as a paranoid precaution.
				if(c >= 0xA1 && !Character.isISOControl(c)) continue;
				return false;
			}
			
			if(escape) {
				// Still in an escape.
				// Might be dangerous e.g. escaping the ] in E[foo=blah] could change the meaning completely.
				return false;
			}
			
			return true;
		}
	}
	
		public static boolean isBannedPseudoClass(String cname)
		{
			if(cname.indexOf(':') != -1) {
				// Pseudo-classes can be chained, at least dynamic ones can, see CSS2.1 section 5.11.3
				String[] split = cname.split(":");
				for(String s : split)
					if(isBannedPseudoClass(s)) return true;
				return false;
			}
			cname=cname.toLowerCase();
			return BANNED_PSEUDOCLASS.contains(cname);
		}
		
		public static boolean isValidPseudoClass(String cname)
		{
			if(cname.indexOf(':') != -1) {
				// Pseudo-classes can be chained, at least dynamic ones can, see CSS2.1 section 5.11.3
				String[] split = cname.split(":");
				for(String s : split)
					if(!isValidPseudoClass(s)) return false;
				return true;
			}
			cname=cname.toLowerCase();
			if(PSEUDOCLASS.contains(cname))
				return true;

			
			else if(cname.indexOf("lang")!=-1 && LANGUAGES.contains(getPseudoClassArg(cname, "lang")))
			{
				// FIXME accept unknown languages as long as they are [a-z-]
				return true;
			}
			
			else if(cname.indexOf("nth-child")!=-1 && FilterUtils.isNth(getPseudoClassArg(cname, "nth-child")))
				return true;
			else if(cname.indexOf("nth-last-child")!=-1 && FilterUtils.isNth(getPseudoClassArg(cname, "nth-last-child")))
				return true;
			else if(cname.indexOf("nth-of-type")!=-1 && FilterUtils.isNth(getPseudoClassArg(cname, "nth-of-type")))
				return true;
			else if(cname.indexOf("nth-last-of-type")!=-1 && FilterUtils.isNth(getPseudoClassArg(cname, "nth-last-of-type")))
				return true;
			
			return false;
		} 
		public static String getPseudoClassArg(String cname, String cname_sans_arg) {
			String arg="";
			int cnameIndex=cname.indexOf(cname_sans_arg);
			int firstIndex=cname.indexOf('(');
			int secondIndex=cname.lastIndexOf(')');
			if(cname.substring(cnameIndex+cname_sans_arg.length(),firstIndex).trim().equals("") && cname.substring(0,cnameIndex).trim().equals("") && cname.substring(secondIndex+1,cname.length()).trim().equals(""))
			{
				arg=CSSTokenizerFilter.removeOuterQuotes(cname.substring(firstIndex+1,secondIndex).trim());
			}
			return arg;
		}

		/** Is the string valid and safe?
		 * @param name The string to parse, in its original encoded form.
		 */
		public static boolean isValidString(String name)
		{
			boolean escape = false;
			boolean escapeNewline = false;
			int unicodeChars = 0;
			for(int i=0;i<name.length();i++) {
			char c = name.charAt(i);
				if(escape) {
					// Whitespace after an escape can be \r\n
					if(escapeNewline) {
						escapeNewline = false;
						escape = false;
						if(c == '\n') continue;
					}
					escapeNewline = false;
					if(('0' <= c && '9' >= c) || ('a' <= c && 'f' >= c) || ('A' <= c && 'F' >= c)) {
						if(unicodeChars == 5) {
							// Full 6 character escape.
							unicodeChars = 0;
							escape = false;
							continue;
						} else {
							unicodeChars++;
							continue;
						}
					}
					if(unicodeChars > 0) {
						if(c == '\r') {
							escapeNewline = true;
							unicodeChars = 0;
							continue;
						} else if(!(c == '\n' || c == '\f' || c == '\t' || c == ' ')) {
							// Only whitespace is allowed after a unicode character escape.
							return false;
						}
					}
					if(c == '\r') {
						escapeNewline = true;
						continue;
					}
					if(c == '\r' || c == '\n' || c == '\f') {
						// Newline is allowed escaped in a string. 
						escape = false;
						continue;
					}
					
					// Directly escaped character
					escape = false;
					continue;
				}
				
				// No unquoted quotes
				if(c == '\'' || c == '\"') return false;
				
				// No unquoted newlines
				if(c == '\r' || c == '\n' || c == '\f') return false;
				
				if(c == '\\') {
					escape = true;
					continue;
				}
				
				// Allow everything else.
				continue;
			}
			
			if(escape) {
				// Still in an escape.
				// Might be dangerous.
				return false;
			}
				
			return true;
		}
		
		// FIXME get rid of ALLOW_ALL_VALID_STRINGS and isValidStringDecoded or implement something.
		// Note this trips up findbugs in CSSTokenizerFilter.
		public static final boolean ALLOW_ALL_VALID_STRINGS = true;

		public static boolean isValidStringDecoded() {
			// REDFLAG: All strings which are parsed and decoded correctly (which has happened before this point) are valid.
			// That is pretty much what the spec says, and there would seem to be no risk, except for with wierd extensions, which can act on plain text so there isn't much we can do.
			return true;
		}

		public static boolean isValidStringWithQuotes(String string) {
			if(string.length() < 2) return false;
			if((string.charAt(0) == '\'' && string.charAt(string.length()-1) == '\'') ||
					(string.charAt(0) == '\"' && string.charAt(string.length()-1) == '\"')) {
				string = string.substring(1, string.length()-1);
				return isValidString(string);
			} else return false;
		}

			
						

}
