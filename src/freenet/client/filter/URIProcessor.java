package freenet.client.filter;

import java.net.URISyntaxException;

/** This interface provides methods for URI transformations */
public interface URIProcessor {

	/** Processes an URI. If it is unsafe, then return null */
	public String processURI(String u, String overrideType, boolean noRelative, boolean inline) throws CommentException;

	/**
	 * Makes an URI absolute
	 *
	 * @param uri
	 *            - The uri to be absolutize
	 * @return The absolute URI
	 */
	public String makeURIAbsolute(String uri) throws URISyntaxException;

}
