/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.filter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;

/**
 * Data filter for a specific MIME type.
 */
public interface ContentDataFilter {

	/** Filter data for reading. Objective is to ensure the data is safe if
	 * rendered by e.g. a web browser, and to guarantee that it is of the
	 * correct type. Filters should usually be implemented as "white list",
	 * that is, they should parse everything, and when encountering
	 * anything they cannot parse, should delete it, or throw a DataFilterException.
	 * IMPORTANT Implementation note: The InputStream may be a PipedInputStream
	 * (or conceivably even a network stream). Implementations MUST NOT ASSUME
	 * that input.available() == 0 => EOF!
	 * @param input Stream to read potentially unsafe data from.
	 * @param output Stream to write safe (but possibly incomplete) data to.
	 * @param charset Character set of the data if appropriate for this MIME type.
	 * @param otherParams Other type parameters if appropriate.
	 * @param schemeHostAndPort Scheme, host and port of the node as seen in the request.
	 * @param cb Filter callback for modifying HTML tags. Irrelevant for most MIME types. In future we
	 * might need this for other types.
	 * @throws DataFilterException If the data cannot be filtered. Any data
	 * written so far should be discarded if possible.
	 * @throws IOException If there was a failure to read from the input data
	 * or write to the output data. Implementations should not throw this
	 * if data is merely badly formatted - any such exceptions should be
	 * caught and converted to a DataFilterException.
	 */
	public void readFilter(
			InputStream input, OutputStream output, String charset, HashMap<String, String> otherParams,
			String schemeHostAndPort, FilterCallback cb) throws DataFilterException, IOException;
}
