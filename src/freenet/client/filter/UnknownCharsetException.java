package freenet.client.filter;

import freenet.l10n.NodeL10n;

public class UnknownCharsetException extends DataFilterException {
	private static final long serialVersionUID = 1L;
	public final String charset;
	
	private UnknownCharsetException(String warning, String warning2, String string, String charset) {
		super(warning, warning2, string);
		this.charset = charset;
	}

	public static UnknownCharsetException create(String charset) {
		String explTitle = l10nDF("unknownCharsetTitle");
		String expl = l10nDF("unknownCharset");

		String warning = l10nDF("warningUnknownCharsetTitle", "charset", charset);
		return new UnknownCharsetException(warning, warning, explTitle + " " + expl, charset);
	}

	private static String l10nDF(String key) {
		// All the strings here are generic
		return NodeL10n.getBase().getString("ContentDataFilter."+key);
	}

	private static String l10nDF(String key, String pattern, String value) {
		// All the strings here are generic
		return NodeL10n.getBase().getString("ContentDataFilter."+key, pattern, value);
	}

}
