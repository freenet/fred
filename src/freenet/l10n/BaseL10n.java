/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.l10n;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.NoSuchElementException;

import freenet.clients.http.TranslationToadlet;
import freenet.support.HTMLEncoder;
import freenet.support.HTMLNode;
import freenet.support.Logger;
import freenet.support.SimpleFieldSet;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;

/**
 * This is the core of all the localization stuff. This method can get
 * localized strings from any SimpleFieldSet file, and can, if necessary,
 * use a custom ClassLoader. The language can be changed at anytime.
 *
 * Note : do not use this class *as is*, use NodeL10n.getBase() or
 * PluginL10n.getBase().
 *
 * Note : this class also supports using/saving/editing overriden translations.
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 * @author Artefact2
 */
public class BaseL10n {

	/**
	 * Central list of languages and the codes to identify them.
	 * When adding new ones, use ISO639-2 or 3 if there is a code for the desired language available
	 * there. If not, fall back to RFC5646 (= "IETF language tags").
	 * 
	 * TODO: Code quality: Switch from this manually maintained list to a predefined one. Use
	 * standard Java class {@link Locale}.
	 * Discussion at https://github.com/freenet/fred/pull/500 has shown that the IETF list is
	 * the best choice. It is a combination of ISO639-3 codes (for which we already have class
	 * {@link ISO639_3}) and a standard country list. And most importantly: It is understood
	 * by standard Java class {@link Locale}.
	 * Bugtracker entry for this: https://bugs.freenetproject.org/view.php?id=6857
	 * 
	 * @see "http://www.omniglot.com/language/names.htm"
	 * @see "http://loc.gov/standards/iso639-2/php/code_list.php"
	 * @see "http://tools.ietf.org/html/rfc5646" */
	public enum LANGUAGE {

		// Windows language codes must be preceded with WINDOWS and be in upper case hex, 4 digits.
		// See http://www.autohotkey.com/docs/misc/Languages.htm
		
		CROATIAN("hr", "Hrvatski", "hrv", new String[] { "WINDOWS041A" }),
		ENGLISH("en", "English", "eng", new String[] { "WINDOWS0409", "WINDOWS0809", "WINDOWS0C09", "WINDOWS1009", "WINDOWS1409", "WINDOWS1809", "WINDOWS1C09", "WINDOWS2009", "WINDOWS2409", "WINDOWS2809", "WINDOWS2C09", "WINDOWS3009", "WINDOWS3409"}),
		HUNGARIAN("hu", "magyar", "hun", new String[] { "WINDOWS040E" }),
		SPANISH("es", "Español", "spa", new String[] { "WINDOWS040A", "WINDOWS080A", "WINDOWS0C0A", "WINDOWS100A", "WINDOWS140A", "WINDOWS180A", "WINDOWS1C0A", "WINDOWS200A", "WINDOWS240A", "WINDOWS280A", "WINDOWS2C0A", "WINDOWS300A", "WINDOWS340A", "WINDOWS380A", "WINDOWS3C0A", "WINDOWS400A", "WINDOWS440A", "WINDOWS480A", "WINDOWS4C0A", "WINDOWS500A"}),
		DANISH("da", "Dansk", "dan", new String[] { "WINDOWS0406" }),
		DUTCH("nl", "Nederlands", "nld", new String[] { "WINDOWS0413", "WINDOWS0813"}),
		GERMAN("de", "Deutsch", "deu", new String[] { "WINDOWS0407", "WINDOWS0807", "WINDOWS0C07", "WINDOWS1007", "WINDOWS1407"}),
		FINNISH("fi", "Suomi", "fin", new String[] { "WINDOWS040B"}),
		FRENCH("fr", "Français", "fra", new String[] { "WINDOWS040C", "WINDOWS080C", "WINDOWS0C0C", "WINDOWS100C", "WINDOWS140C", "WINDOWS180C"}),
		ITALIAN("it", "Italiano", "ita", new String[] { "WINDOWS0410", "WINDOWS0810"}),
		// TODO: This does not adhere to RFC5646. Fix it as part of changing the whole list to
		// RFC5646. Find a way to rename this without breaking the language in all plugins.
		NORWEGIAN("nb-no", "Bokmål", "nob", new String[] { "WINDOWS0414", "WINDOWS0814"}),
		POLISH("pl", "Polski", "pol", new String[] { "WINDOWS0415"}),
		SWEDISH("sv", "Svenska", "swe", new String[] { "WINDOWS041D", "WINDOWS081D"}),
		// TODO: This does not adhere to RFC5646. Fix it as part of changing the whole list to
		// RFC5646. Find a way to rename this without breaking the language in all plugins.
		CHINESE("zh-cn", "中文(简体)", "chn", new String[] { "WINDOWS0804", "WINDOWS1004" }),
		// simplified chinese, used on mainland, Singapore and Malaysia
		// TODO: This does not adhere to RFC5646. Fix it as part of changing the whole list to
		// RFC5646. Find a way to rename this without breaking the language in all plugins.
		CHINESE_TAIWAN("zh-tw", "中文(繁體)", "zh-tw", new String[] { "WINDOWS0404", "WINDOWS0C04", "WINDOWS1404" }), 
		// traditional chinese, used in Taiwan, Hong Kong and Macau
		RUSSIAN("ru", "Русский", "rus", new String[] { "WINDOWS0419" }), // Just one variant for russian. Belorussian is separate, code page 423, speakers may or may not speak russian, I'm not including it.
		JAPANESE("ja", "日本語", "jpn", new String[] { "WINDOWS0411" }),
		PORTUGUESE("pt-PT", "Português do Portugal", "pt", new String[] { "WINDOWS0816" }),
		// TODO: This does not adhere to RFC5646. Fix it as part of changing the whole list to
		// RFC5646. Find a way to rename this without breaking the language in all plugins.
		BRAZILIAN_PORTUGUESE("pt-br", "Português do Brasil", "pt-br", new String[] { "WINDOWS0416" }),
		GREEK("el", "Ελληνικά", "ell", new String[] { "WINDOWS0408" }),
		UNLISTED("unlisted", "unlisted", "unlisted", new String[] {});
		/** The identifier we use internally : MUST BE UNIQUE! */
		public final String shortCode;
		/** The identifier shown to the user */
		public final String fullName;
		/** The mapping with the installer's l10n (@see bug #2424); MUST BE UNIQUE! */
		public final String isoCode;
		public final String[] aliases;

		private LANGUAGE(String shortCode, String fullName, String isoCode, String[] aliases) {
			this.shortCode = shortCode;
			this.fullName = fullName;
			this.isoCode = isoCode;
			this.aliases = aliases;
		}

		LANGUAGE(LANGUAGE l) {
			this(l.shortCode, l.fullName, l.isoCode, l.aliases);
		}

		/**
		 * Create a new LANGUAGE object from either its short code, its full
		 * name or its ISO code.
		 * @param whatever Short code, full name or ISO code.
		 * @return LANGUAGE
		 */
		public static LANGUAGE mapToLanguage(String whatever) {
			for (LANGUAGE currentLanguage : LANGUAGE.values()) {
				if (currentLanguage.shortCode.equalsIgnoreCase(whatever) ||
						currentLanguage.fullName.equalsIgnoreCase(whatever) ||
						currentLanguage.isoCode.equalsIgnoreCase(whatever) ||
						currentLanguage.toString().equalsIgnoreCase(whatever)) {
					return currentLanguage;
				}
				if(currentLanguage.aliases != null) {
					for(String s : currentLanguage.aliases)
						if(whatever.equalsIgnoreCase(s)) return currentLanguage;
				}
			}
			return null;
		}

		public static String[] valuesWithFullNames() {
			LANGUAGE[] allValues = values();
			ArrayList<String> result = new ArrayList<String>(allValues.length);
			for (int i = 0; i < allValues.length; i++) {
				// We will return the full names sorted alphabetically. To ensure that the user
				// notices the special "UNLISTED" language code, we add it to the end of the list
				// after sorting, so now we skip it.
				if(allValues[i] != UNLISTED)
					result.add(allValues[i].fullName);
			}

			Collections.sort(result);
			result.add(UNLISTED.fullName);

			return result.toArray(new String[result.size()]);
		}

		public static LANGUAGE getDefault() {
			return ENGLISH;
		}
	}
    
    /**
     * State enum for {@link L10nStringIterator}. Declared here for
     * {@link #getStrings(String, FallbackState)}.
     */
    private enum FallbackState {
        CURRENT_LANG,
        FALLBACK_LANG,
        KEY,
        END
    }
    
    /**
     * Iterator that returns the strings associated with a key in order of preference. First the
     * value in the current language (if any), then the value in the fallback language (if any),
     * and then just the key itself.
     */
    private class L10nStringIterator implements Iterator<String> {
        private final String key;
        private FallbackState state;
        
        public L10nStringIterator(String key, FallbackState state) {
            this.key = key;
            this.state = state;
        }
        
        @Override
        public boolean hasNext() {
            return state != FallbackState.END;
        }
        
        @Override
        public String next() {
            if (state == FallbackState.CURRENT_LANG) { 
                state = FallbackState.FALLBACK_LANG;
                String value = getString(key, true);
                if (value != null) {
                    return value;
                }
            }
            if (state == FallbackState.FALLBACK_LANG) {
                state = FallbackState.KEY;
                if (getSelectedLanguage() != LANGUAGE.getDefault()) {
                    String value = getFallbackString(key);
                    if (value != null) {
                        return value;
                    }
                }
            }
            if (state == FallbackState.KEY) {
                state = FallbackState.END;
                return key;
            }
            throw new NoSuchElementException();
        }
        
        @Override
        public void remove() {
            throw new UnsupportedOperationException();
        }
    }
    
	private LANGUAGE lang;
	private String l10nFilesBasePath;
	private String l10nFilesMask;
	private String l10nOverrideFilesMask;
	private SimpleFieldSet currentTranslation = null;
	private SimpleFieldSet fallbackTranslation = null;
	private SimpleFieldSet translationOverride;
	private ClassLoader cl;

	private static ClassLoader getClassLoaderFallback() {
		ClassLoader _cl;
		// getClassLoader() can return null on some implementations if the boot classloader was used.
		_cl = BaseL10n.class.getClassLoader();
		if (_cl == null) {
			_cl = ClassLoader.getSystemClassLoader();
		}
		return _cl;
	}

	public BaseL10n(String l10nFilesBasePath, String l10nFilesMask, String l10nOverrideFilesMask) {
		this(l10nFilesBasePath, l10nFilesMask, l10nOverrideFilesMask, LANGUAGE.getDefault());
	}

	public BaseL10n(String l10nFilesBasePath, String l10nFilesMask, String l10nOverrideFilesMask, final LANGUAGE lang) {
		this(l10nFilesBasePath, l10nFilesMask, l10nOverrideFilesMask, lang, getClassLoaderFallback());
	}

	/**
	 * Create a new BaseL10n object.
	 *
	 * Note : you shouldn't have to run this yourself. Use PluginL10n or NodeL10n.
	 * @param l10nFilesBasePath Base path of the l10n files, ex. "com/mycorp/myproject/l10n"
	 * @param l10nFilesMask Mask of the l10n files, ex. "messages_${lang}.l10n"
	 * @param l10nOverrideFilesMask Same as l10nFilesMask, but for overriden messages.
	 * @param lang Language to use.
	 * @param cl ClassLoader to use.
	 */
	public BaseL10n(String l10nFilesBasePath, String l10nFilesMask, String l10nOverrideFilesMask, final LANGUAGE lang, final ClassLoader cl) {
		if (!l10nFilesBasePath.endsWith("/")) {
			l10nFilesBasePath += "/";
		}

		this.l10nFilesBasePath = l10nFilesBasePath;
		this.l10nFilesMask = l10nFilesMask;
		this.l10nOverrideFilesMask = l10nOverrideFilesMask;
		this.cl = cl;
		this.setLanguage(lang);
	}

	/**
	 * Get the full base name of the L10n file used by the current language.
	 * @return String
	 */
	public String getL10nFileName(LANGUAGE lang) {
		return this.l10nFilesBasePath + this.l10nFilesMask.replace("${lang}", lang.shortCode);
	}

	/**
	 * Get the full base name of the L10n override file used by the current language.
	 * @return String
	 */
	public String getL10nOverrideFileName(LANGUAGE lang) {
		return this.l10nOverrideFilesMask.replace("${lang}", lang.shortCode);
	}

	/**
	 * Use a new language, and load the SimpleFieldSets accordingly.
	 * @param selectedLanguage New language to use.
	 * @throws MissingResourceException If the l10n file could not be found.
	 */
	public void setLanguage(final LANGUAGE selectedLanguage) throws MissingResourceException {
		if (selectedLanguage == null) {
			throw new MissingResourceException("LANGUAGE given is null !", this.getClass().getName(), "");
		}

		this.lang = selectedLanguage;

		Logger.normal(this.getClass(), "Changing the current language to : " + this.lang);

		try {
			this.loadOverrideFileOrBackup();
		} catch (IOException e) {
			this.translationOverride = null;
			Logger.error(this, "IOError while accessing the file!" + e.getMessage(), e);
		}

		this.currentTranslation = this.loadTranslation(lang);
		if (this.currentTranslation == null) {
			Logger.error(this, "The translation file for " + lang + " is invalid. The node will load an empty template.");
			this.currentTranslation = null;
		}
	}

	/**
	 * Try loading the override file, or the backup override file if it
	 * exists.
	 * @throws IOException
	 */
	private void loadOverrideFileOrBackup() throws IOException {
		final File tmpFile = new File(this.getL10nOverrideFileName(this.lang));
		if (tmpFile.exists() && tmpFile.canRead() && tmpFile.length() > 0) {
			Logger.normal(this, "Override file detected : let's try to load it");
			this.translationOverride = SimpleFieldSet.readFrom(tmpFile, false, false);
		} else {
			// try to restore a backup
			final File backup = new File(tmpFile.getParentFile(), tmpFile.getName() + ".bak");
			if (backup.exists() && backup.length() > 0) {
				Logger.normal(this, "Override-backup file detected : let's try to load it");
				this.translationOverride = SimpleFieldSet.readFrom(backup, false, false);
			} else {
				this.translationOverride = null;
			}
		}
	}

	/**
	 * Load the l10n file for a custom language and return its parsed SimpleFieldSet.
	 * @param lang Language to use.
	 * @return SimpleFieldSet
	 */
	private SimpleFieldSet loadTranslation(LANGUAGE lang) {
		SimpleFieldSet result = null;
		InputStream in = null;

		try {
			// Returns null on lookup failures:
			in = this.cl.getResourceAsStream(this.getL10nFileName(lang));
			if (in != null) {
				result = SimpleFieldSet.readFrom(in, false, false);
			} else {
				System.err.println("Could not get resource : " + this.getL10nFileName(lang));
			}
		} catch (Exception e) {
			System.err.println("Error while loading the l10n file from " + this.getL10nFileName(lang) + " :" + e.getMessage());
			e.printStackTrace();
			result = null;
		} finally {
			Closer.close(in);
		}

		return result;
	}

	/**
	 * Load the fallback translation. Synchronized.
	 */
	private synchronized void loadFallback() {
		if (this.fallbackTranslation == null) {
			this.fallbackTranslation = loadTranslation(LANGUAGE.getDefault());
			if(fallbackTranslation == null)
				fallbackTranslation = new SimpleFieldSet(true);
		}
	}

	/**
	 * Get the language currently used by this BaseL10n.
	 * @return LANGUAGE
	 */
	public LANGUAGE getSelectedLanguage() {
		return this.lang;
	}

	/**
	 * Returns true if a key is overriden.
	 * @param key Key to check override status
	 * @return boolean
	 */
	public boolean isOverridden(String key) {
		if (this.translationOverride == null) {
			return false;
		}
		return this.translationOverride.get(key) != null;
	}

	/**
	 * Override a custom key with a new value.
	 * @param key Key to override.
	 * @param value New value of that key.
	 */
	public void setOverride(String key, String value) {
		key = key.trim();
		value = value.trim();
		// Is the override already declared ? if not, create it.
		if (this.translationOverride == null) {
			this.translationOverride = new SimpleFieldSet(false);
		}

		// If there is no need to keep it in the override, remove it...
		// unless the original/default is the same as the translation
		if ("".equals(value) || (currentTranslation != null && value.equals(this.currentTranslation.get(key)))) {
			this.translationOverride.removeValue(key);
		} else {
			value = value.replaceAll("(\r|\n|\t)+", "");

			// Set the value of the override
			this.translationOverride.putOverwrite(key, value);
			Logger.normal(this.getClass(), "Got a new translation key: set the Override!");
		}

		// Save the file to disk
		saveTranslationFile();
	}

	/**
	 * Save the SimpleFieldSet of overriden keys in a file.
	 */
	private void saveTranslationFile() {
		FileOutputStream fos = null;
		File finalFile = new File(this.getL10nOverrideFileName(this.lang));

		try {
			// We don't set deleteOnExit on it : if the save operation fails, we want a backup
			File tempFile = File.createTempFile(finalFile.getName(), ".bak", finalFile.getParentFile());;
			Logger.minor(this.getClass(), "The temporary filename is : " + tempFile);

			fos = new FileOutputStream(tempFile);
			this.translationOverride.writeToBigBuffer(fos);
			fos.close();
			fos = null;

			FileUtil.renameTo(tempFile, finalFile);
			Logger.normal(this.getClass(), "Override file saved successfully!");
		} catch (IOException e) {
			Logger.error(this.getClass(), "Error while saving the translation override: " + e.getMessage(), e);
		} finally {
			Closer.close(fos);
		}
	}

	/**
	 * Get a copy of the currently used SimpleFieldSet.
	 * @return SimpleFieldSet
	 */
	public SimpleFieldSet getCurrentLanguageTranslation() {
		return (this.currentTranslation == null ? null : new SimpleFieldSet(currentTranslation));
	}

	/**
	 * Get a copy of the currently used SimpleFieldSet (overriden messages).
	 * @return SimpleFieldSet
	 */
	public SimpleFieldSet getOverrideForCurrentLanguageTranslation() {
		return (this.translationOverride == null ? null : new SimpleFieldSet(translationOverride));
	}

	/**
	 * Get the SimpleFieldSet of the default language (should be english).
	 * @return SimpleFieldSet
	 */
	public SimpleFieldSet getDefaultLanguageTranslation() {
		this.loadFallback();

		return new SimpleFieldSet(this.fallbackTranslation);

	}

	/**
	 * Get a localized string. Return "" (empty string) if it doesn't exist.
	 * @param key Key to search for.
	 * @return String
	 */
	public String getString(String key) {
        return getStrings(key).iterator().next();
	}

	/**
	 * Get a localized string. Return "" (empty string) if it doesn't exist.
	 * @param key Key to search for.
	 * @param replacementValue Replacement value for all ${*}.
	 * @return String
	 */
	public String getString(String key, String replacementValue) {
		String string = getStrings(key).iterator().next();
		return string.replaceAll("\\$\\{.*}", replacementValue);
	}

	/**
	 * Get a localized string.
	 * @param key Key to search for.
	 * @param returnNullIfNotFound If this is true, will return null if the key is not found.
	 * @return String
	 */
	public String getString(String key, boolean returnNullIfNotFound) {
        if (!returnNullIfNotFound) {
            return getString(key);
        }
        
		String result = null;
		if (this.translationOverride != null) {
			result = this.translationOverride.get(key);
		}

		if (result != null) {
			return result;
		}

		if (this.currentTranslation != null) {
			result = this.currentTranslation.get(key);
		}

        if (result == null) {
			Logger.normal(this.getClass(), "The translation for " + key + " hasn't been found (" + this.getSelectedLanguage() + ")! please tell the maintainer.");
		}
        return result;
	}
    
    /**
     * Enumerate strings associated with a key in order of preference.
     */
    private Iterable<String> getStrings(final String key) {
        return getStrings(key, FallbackState.CURRENT_LANG);
    }
    
    /**
     * Enumerate strings associated with a key in order of preference, starting with a specified
     * one.
     */
    private Iterable<String> getStrings(final String key, final FallbackState initialState) {
        return new Iterable<String>() {
            @Override
            public Iterator<String> iterator() {
                return new L10nStringIterator(key, initialState);
            }
        };
    }

	/**
	 * Get a localized string and put it in a HTMLNode for the translation page.
	 * @param key Key to search for.
	 * @return HTMLNode
	 */
	public HTMLNode getHTMLNode(String key) {
		return getHTMLNode(key, null, null);
	}
	
	/**
	 * Get a localized string and put it in a HTMLNode for the translation page.
	 * @param key Key to search for.
	 * @param patterns Patterns to replace. May be null, if so values must also be null.
	 * @param values Values to replace patterns with.
	 * @return HTMLNode
	 */
	public HTMLNode getHTMLNode(String key, String[] patterns, String[] values) {
		String value = this.getString(key, true);
		if (value != null) {
			if(patterns != null)
				return new HTMLNode("#", getString(key, patterns, values));
			else
				return new HTMLNode("#", value);
		}
		HTMLNode translationField = new HTMLNode("span", "class", "translate_it");
		if(patterns != null)
			translationField.addChild("#", getDefaultString(key, patterns, values));
		else
			translationField.addChild("#", getDefaultString(key));
		translationField.addChild("a", "href", TranslationToadlet.TOADLET_URL + "?translate=" + key).addChild("small", " (translate it in your native language!)");

		return translationField;
	}
    
    /**
     * Get the value for a key in the fallback translation, or null.
     */
    private String getFallbackString(String key) {
        this.loadFallback();

        String result = this.fallbackTranslation.get(key);

        if (result == null) {
            Logger.error(this.getClass(), "The default translation for " + key + " hasn't been found!");
            System.err.println("The default translation for " + key + " hasn't been found!");
            new Exception().printStackTrace();
        }
        return result;
    }

	/**
	 * Get the default value for a key.
	 * @param key Key to search for.
	 * @return String
	 */
	public String getDefaultString(String key) {
        return getStrings(key, FallbackState.FALLBACK_LANG).iterator().next();
	}

	/**
	 * Get the default value for a key.
	 * @param key Key to search for.
	 * @return String
	 */
	public String getDefaultString(String key, String[] patterns, String[] values) {
		assert (patterns.length == values.length);
		String result = getDefaultString(key);

		for (int i = 0; i < patterns.length; i++) {
			result = result.replaceAll("\\$\\{" + patterns[i] + "\\}", quoteReplacement(values[i]));
		}

		return result;
	}
	
	/**
	 * Get a localized string, and replace on-the-fly some values.
	 * @param key Key to search for.
	 * @param patterns Patterns to replace, ${ and } are not included.
	 * @param values Replacement values.
	 * @return String
	 */
	public String getString(String key, String[] patterns, String[] values) {
		assert (patterns.length == values.length);
		String result = getString(key);

		for (int i = 0; i < patterns.length; i++) {
			result = result.replaceAll("\\$\\{" + patterns[i] + "\\}", quoteReplacement(values[i]));
		}

		return result;
	}

	/**
	 * Get a localized string, and replace on-the-fly a value.
	 * @param key Key to search for.
	 * @param pattern Pattern to replace, ${ and } not included.
	 * @param value Replacement value.
	 * @return String
	 */
	public String getString(String key, String pattern, String value) {
		return getString(key, new String[]{pattern}, new String[]{value}); // FIXME code efficiently!
	}

	/**
	 * Escape null, $ and \.
	 * @param s String to parse
	 * @return String
	 */
	private String quoteReplacement(String s) {
		if (s == null) {
			return "(null)";
		}
		if ((s.indexOf('\\') == -1) && (s.indexOf('$') == -1)) {
			return s;
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '\\') {
				sb.append('\\');
				sb.append('\\');
			} else if (c == '$') {
				sb.append('\\');
				sb.append('$');
			} else {
				sb.append(c);
			}
		}
		return sb.toString();
	}

	/**
	 * Parse a localized string and put the result in a HTMLNode.
	 * @param node The result will be put in this HTMLNode.
	 * @param key Key to search for.
	 * @param patterns Patterns to replace, ${ and } are not included.
	 * @param values Replacement values.
	 * @deprecated Use {@link #addL10nSubstitution(HTMLNode, String, String[], HTMLNode[])} instead.
	 */
	@Deprecated
	public void addL10nSubstitution(HTMLNode node, String key, String[] patterns, String[] values) {
		String result = HTMLEncoder.encode(getString(key));
		assert (patterns.length == values.length);
		for (int i = 0; i < patterns.length; i++) {
			result = result.replaceAll("\\$\\{" + patterns[i] + "\\}", quoteReplacement(values[i]));
		}
		node.addChild("%", result);
	}

	/**
	 * Loads an L10n string, replaces variables such as ${link} or ${bold} in it with {@link HTMLNode}s
	 * and adds the result to the given HTMLNode.
	 * 
	 * This is *much* safer than the deprecated {@link #addL10nSubstitution(HTMLNode, String, String[], String[])}. 
	 * Callers won't accidentally pass in unencoded strings and cause vulnerabilities.
	 * Callers should try to reuse parameters if possible.
	 * We automatically close each tag: When a pattern ${name} is matched, we search for
	 * ${/name}. If we find it, we make the tag enclose everything between the two; if we
	 * can't find it, we just add it with no children. It is not possible to create an
	 * HTMLNode representing a tag closure, so callers will need to change their code to
	 * not pass in /link or similar, and in some cases will need to change the l10n 
	 * strings themselves to always close the tag properly, rather than using a generic
	 * /link for multiple links as we use in some places.
	 * 
	 * <p><b>Examples</b>:
	 * <p>TranslationLookup.string=This is a ${link}link${/link} about ${text}.</p>
	 * <p>
	 * <code>addL10nSubstitution(html, "TranslationLookup.string", new String[] { "link", "text" },
	 *   new HTMLNode[] { HTMLNode.link("/KSK@gpl.txt"), HTMLNode.text("blah") });</code>
	 * </p>
	 * <br>
	 * <p>TranslationLookup.string=${bold}This${/bold} is a bold text.</p>
	 * <p>
	 * <code>addL10nSubstitution(html, "TranslationLookup.string", new String[] { "bold" },
	 *   new HTMLNode[] { HTMLNode.STRONG });</code>
	 * </p>
	 * 
	 * @param node The {@link HTMLNode} to which the L10n should be added after substitution was done.
	 * @param key The key of the L10n string which shall be used. 
	 * @param patterns Specifies things such as ${link} which shall be replaced in the L10n string with {@link HTMLNode}s.
	 * @param values For each entry in the previous array parameter, this array specifies the {@link HTMLNode} with which it shall be replaced. 
	 */
	public void addL10nSubstitution(HTMLNode node, String key, String[] patterns, HTMLNode[] values) {
        List<HTMLNode> newContent = getHTMLWithSubstitutions(key, patterns, values);
        node.addChildren(newContent);
	}
    
    /**
     * Attempt to parse any substitution variables found in a l10n string. Intended for use in
     * tests.
     */
    void attemptParse(String value) throws L10nParseException {
        String[] patterns = new String[0];
        HTMLNode[] values = new HTMLNode[0];
        performHTMLSubstitutions(value, patterns, values);
    }
    
    /**
     * Look up a l10n string and replace substitution variables to generate a list of
     * {@link HTMLNode}s.
     */
    private List<HTMLNode> getHTMLWithSubstitutions(String key, String[] patterns, HTMLNode[] values) {
        for (String value : getStrings(key)) {
            // catch errors caused by bad translation strings
            try {
                return performHTMLSubstitutions(value, patterns, values);
            } catch (L10nParseException e) {
                Logger.error(this, "Error in l10n value \""+value+"\" for "+key, e);
            }
        }
        // this should never happen, because the last item from getStrings() will be the key itself
        return Collections.singletonList(new HTMLNode("#"));
    }
    
    /**
     * Convert a string to a list of {@link HTMLNode}s, replacing substitution variables found in
     * {@code patterns} with corresponding nodes from {@code values}.
     */
    private List<HTMLNode> performHTMLSubstitutions(String value, String[] patterns,
            HTMLNode[] values) throws L10nParseException {
        HTMLNode tempNode = new HTMLNode("#");
        addHTMLSubstitutions(tempNode, value, patterns, values);
        return tempNode.getChildren();
    }

    /**
     * Adds a string to an {@link HTMLNode}, replacing substitution variables found in
     * {@code patterns} with corresponding nodes from {@code values}.
     */
    private void addHTMLSubstitutions(HTMLNode node, String value,
            String[] patterns, HTMLNode[] values) throws L10nParseException {
		int x;
		while(!value.equals("") && (x = value.indexOf("${")) != -1) {
			String before = value.substring(0, x);
			if(before.length() > 0)
				node.addChild("#", before);
			value = value.substring(x);
			int y = value.indexOf('}');
			if(y == -1) {
                throw new L10nParseException("Unclosed braces");
			}
			String lookup = value.substring(2, y);
			value = value.substring(y+1);
			if(lookup.startsWith("/")) {
                throw new L10nParseException("Starts with /");
			}
			
			HTMLNode subnode = null;
			
			for(int i=0;i<patterns.length;i++) {
				if(patterns[i].equals(lookup)) {
					subnode = values[i];
					break;
				}
			}

			String searchFor = "${/"+lookup+"}";
			x = value.indexOf(searchFor);
			if(x == -1) {
				// It goes up to the end of the tag. It has no contents.
				if(subnode != null) {
                    node.addChild(subnode.clone());
				}
			} else {
				// It has contents. Must recurse.
				String inner = value.substring(0, x);
				String rest = value.substring(x + searchFor.length());
				if(subnode != null) {
					subnode = subnode.clone();
					node.addChild(subnode);
				} else {
                    subnode = node;
				}
                addHTMLSubstitutions(subnode, inner, patterns, values);
				value = rest;
			}
		}
		if(!value.equals(""))
			node.addChild("#", value);
	}
	
	public String[] getAllNamesWithPrefix(String prefix){
		if(fallbackTranslation==null){
			return new String[]{};
		}
		List<String> toReturn=new ArrayList<String>();
		Iterator<String> it= fallbackTranslation.keyIterator();
		while(it.hasNext()){
			String key=it.next();
			if(key.startsWith(prefix)){
				toReturn.add(key);
			}
		}
		return toReturn.toArray(new String[toReturn.size()]);
	}
}
