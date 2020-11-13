/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.filter;

import freenet.client.filter.HTMLFilter.ParsedTag;

public class NullFilterCallback implements FilterCallback {

	@Override
	public String processURI(String uri, String overrideType) {
		return null;
	}

	@Override
	public String onBaseHref(String baseHref) {
		return null;
	}

	@Override
	public void onText(String s, String type) {
		// Do nothing
	}

	@Override
	public String processForm(String method, String action) {
		return null;
	}

	@Override
	public String processURI(String uri, String overrideType, boolean noRelative, boolean inline) throws CommentException {
		return null;
	}

	@Override
	public String processURI(String uri, String overrideType, String forceSchemeHostAndPort, boolean inline)
			throws CommentException {
		return null;
	}

	@Override
	public String processTag(ParsedTag pt) {
		return null;
	}

	@Override
	public void onFinished() {
		// Ignore.
	}

}
