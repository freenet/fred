/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client;

import java.util.HashMap;
import java.util.Set;

import freenet.client.async.ClientGetCallback;
import freenet.client.async.ClientGetter;
import freenet.client.async.ClientPutCallback;
import freenet.client.async.ClientPutter;
import freenet.client.events.ClientEventListener;
import freenet.keys.FreenetURI;
import freenet.node.RequestClient;
import freenet.support.api.Bucket;

public interface HighLevelSimpleClient {

	/**
	 * Set the maximum length of the fetched data.
	 */
	public void setMaxLength(long maxLength);

	/**
	 * Set the maximum length of any intermediate data, e.g. ZIP manifests.
	 */
	public void setMaxIntermediateLength(long maxIntermediateLength);

	/**
	 * Blocking fetch of a URI
	 * @throws FetchException If there is an error fetching the data
	 */
	public FetchResult fetch(FreenetURI uri) throws FetchException;

	/**
	 * Blocking fetch from metadata
	 * @throws FetchException If there is an error fetching the data
	 */
	public FetchResult fetchFromMetadata(Bucket initialMetadata) throws FetchException;

	/**
	 * Blocking fetch of a URI with a configurable max-size.
	 * @param maxSize The maximum size in bytes of the return data or any intermediary data processed
	 * to obtain the final output (e.g. containers).
	 */
	public FetchResult fetch(FreenetURI uri, long maxSize) throws FetchException;

	/**
	 * Blocking fetch of a URI with a configurable max-size and context object.
	 * @param context Used mainly for scheduling, we round-robin between request clients within a given
	 * priority and retry count. Also indicates whether the request is persistent, and if so, can remove it.
	 */
	public FetchResult fetch(FreenetURI uri, long maxSize, RequestClient context) throws FetchException;

	/**
	 * Non-blocking fetch of a URI with a configurable max-size (in bytes), context object, callback and context.
	 * Will return immediately, the callback will be called later.
	 * @param callback Will be called when the request completes, fails, etc. If the request is persistent
	 * this will be called on the database thread with a container parameter.
	 * @param fctx Fetch context so you can customise the search process.
	 * @return The ClientGetter object, which will have been started already.
	 */
	public ClientGetter fetch(FreenetURI uri, ClientGetCallback callback, FetchContext fctx, short prio) throws FetchException;

	/**
	 * Non-blocking fetch of a URI with a configurable max-size (in bytes), context object, callback and context.
	 * Will return immediately, the callback will be called later.
	 * @param callback Will be called when the request completes, fails, etc. If the request is persistent
	 * this will be called on the database thread with a container parameter.
	 * @param fctx Fetch context so you can customise the search process.
	 * @return The ClientGetter object, which will have been started already.
	 */
	public ClientGetter fetchFromMetadata(Bucket initialMetadata, ClientGetCallback callback, FetchContext fctx, short prio) throws FetchException;

	/**
	 * Non-blocking fetch of a URI with a configurable max-size (in bytes), context object, callback and context.
	 * Will return immediately, the callback will be called later.
	 * @param callback Will be called when the request completes, fails, etc. If the request is persistent
	 * this will be called on the database thread with a container parameter.
	 * @param fctx Fetch context so you can customise the search process.
	 * @param maxSize IGNORED. FIXME DEPRECATE
	 * @return The ClientGetter object, which will have been started already.
	 */
	public ClientGetter fetch(FreenetURI uri, long maxSize, ClientGetCallback callback, FetchContext fctx) throws FetchException;

	/**
	 * Non-blocking fetch of a URI with a configurable max-size (in bytes), context object, callback and context.
	 * Will return immediately, the callback will be called later.
	 * @param callback Will be called when the request completes, fails, etc. If the request is persistent
	 * this will be called on the database thread with a container parameter.
	 * @param fctx Fetch context so you can customise the search process.
	 * @param priorityClass What priority to start at. It is much more efficient to specify it here than to change it later.
	 * @return The ClientGetter object, which will have been started already.
	 */
	public ClientGetter fetch(FreenetURI uri, long maxSize, ClientGetCallback callback, FetchContext fctx, short priorityClass) throws FetchException;

	/**
	 * Blocking insert.
	 * @param filenameHint If set, insert a single-file manifest containing only this file, under the given filename.
	 * @throws InsertException If there is an error inserting the data
	 */
	public FreenetURI insert(InsertBlock insert, boolean getCHKOnly, String filenameHint) throws InsertException;

	/**
	 * Blocking insert.
	 * @param filenameHint If set, insert a single-file manifest containing only this file, under the given filename.
	 * @throws InsertException If there is an error inserting the data
	 */
	public FreenetURI insert(InsertBlock insert, boolean getCHKOnly, String filenameHint, short priority) throws InsertException;

	/**
	 * Blocking insert.
	 * @param filenameHint If set, insert a single-file manifest containing only this file, under the given filename.
	 * @throws InsertException If there is an error inserting the data
	 */
	public FreenetURI insert(InsertBlock insert, String filenameHint, short priority, InsertContext ctx) throws InsertException;

	/**
	 * Non-blocking insert.
	 * @param isMetadata If true, insert metadata.
	 * @param cb Will be called when the insert completes. If the request is persistent
	 * this will be called on the database thread with a container parameter.
	 * @param ctx Insert context so you can customise the insertion process.
	 */
	public ClientPutter insert(InsertBlock insert, String filenameHint, boolean isMetadata, InsertContext ctx, ClientPutCallback cb) throws InsertException;

	/**
	 * Non-blocking insert.
	 * @param isMetadata If true, insert metadata.
	 * @param cb Will be called when the insert completes. If the request is persistent
	 * this will be called on the database thread with a container parameter.
	 * @param ctx Insert context so you can customise the insertion process.
	 */
	public ClientPutter insert(InsertBlock insert, String filenameHint, boolean isMetadata, InsertContext ctx, ClientPutCallback cb, short priority) throws InsertException;

	/**
	 * Blocking insert of a redirect.
	 */
	public FreenetURI insertRedirect(FreenetURI insertURI, FreenetURI target) throws InsertException;

	/**
	 * Blocking insert of multiple files as a manifest (or zip manifest, etc).
	 * The map can contain either string -> bucket, string -> manifestitem or string -> map, the latter
	 * indicating subdirs.
	 */
	public FreenetURI insertManifest(FreenetURI insertURI, HashMap<String, Object> bucketsByName, String defaultName) throws InsertException;

	/**
	 * Blocking insert of multiple files as a manifest (or zip manifest, etc).
	 * The map can contain either string -> bucket, string -> manifestitem or string -> map, the latter
	 * indicating subdirs.
	 */
	public FreenetURI insertManifest(FreenetURI insertURI, HashMap<String, Object> bucketsByName, String defaultName, short priorityClass) throws InsertException;

	/**
	 * Blocking insert of multiple files as a manifest, with a crypto key override.
	 */
	public FreenetURI insertManifest(FreenetURI insertURI, HashMap<String, Object> bucketsByName, String defaultName, short priorityClass, byte[] forceCryptoKey) throws InsertException;

	/**
	 * Get the FetchContext so you can customise the search process. Has settings for all sorts of things
	 * such as how many times to retry each block, whether to follow redirects, whether to open containers,
	 * etc. IMPORTANT: This is created new for each and every request! Changing settings here will not
	 * change them on fetch()'es unless you pass the modified FetchContext in to the fetch() call.
	 */
	public FetchContext getFetchContext();
	public FetchContext getFetchContext(long size);
	public FetchContext getFetchContext(long size, String schemeHostAndPort);

	/**
	 * Get an InsertContext. Has settings for controlling the insertion process, for example which
	 * compression algorithms to try.
	 * @param forceNonPersistent If true, force the request to use the non-persistent
	 * bucket pool.
	 */
	public InsertContext getInsertContext(boolean forceNonPersistent);

	/**
	 * Add a ClientEventListener.
	 */
	public void addEventHook(ClientEventListener listener);

	/**
	 * Generates a new key pair, consisting of the insert URI at index 0 and the
	 * request URI at index 1.
	 *
	 * @param docName
	 *            The document name
	 * @return An array containing the insert and request URI
	 */
	public FreenetURI[] generateKeyPair(String docName);

	/**
	 * Prefetch a key at a very low priority. If it hasn't been fetched within the timeout,
	 * kill the fetch.
	 * @param allowedTypes Kill the request if the MIME type is not one of these types. Normally null.
	 */
	public void prefetch(FreenetURI uri, long timeout, long maxSize, Set<String> allowedTypes);

	/**
	 * Prefetch a key at the given priority. If it hasn't been fetched within the timeout,
	 * kill the fetch.
	 * @param allowedTypes Kill the request if the MIME type is not one of these types. Normally null.
	 */
	public void prefetch(FreenetURI uri, long timeout, long maxSize, Set<String> allowedTypes, short prio);

	public HighLevelSimpleClient clone();

}
