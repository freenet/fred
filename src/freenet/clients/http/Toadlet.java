/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.http;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.net.URI;

import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchResult;
import freenet.client.FetchWaiter;
import freenet.client.HighLevelSimpleClient;
import freenet.client.InsertBlock;
import freenet.client.InsertException;
import freenet.client.async.ClientGetter;
import freenet.keys.FreenetURI;
import freenet.l10n.NodeL10n;
import freenet.node.RequestClient;
import freenet.support.HTMLEncoder;
import freenet.support.HTMLNode;
import freenet.support.Logger;
import freenet.support.MultiValueTable;
import freenet.support.api.Bucket;
import freenet.support.api.HTTPRequest;

/**
 * API similar to Servlets. Originally the reason for not using servlets was to support
 * continuations, but that hasn't been implemented, and modern servlets do support continuations
 * anyway. Also it was supposed to be simpler, which may not be true any more. Many plugins wrap
 * their own API around this!
 * FIXME consider using servlets.
 *
 * Important API complexity: The methods for handling the actual requests are synthetic:
 *
 * Methods are handled via handleMethodGET/POST/whatever ( URI uri, HTTPRequest request, ToadletContext ctx )
 * Typically this throws IOException and ToadletContextClosedException.
 */
public abstract class Toadlet {

	/** Handle a GET request.
	 * Other methods are accessed via handleMethodPOST etc, invoked via reflection. But all toadlets
	 * are expected to support GET.
	 * @param uri The URI being fetched.
	 * @param request The original HTTPRequest, convenient for e.g. fetching ?blah=blah parameters.
	 * @param ctx The request context. Mainly used for sending a reply; this identifies which
	 * request we are replying to. Also gives access to lots of important objects e.g. PageMaker. */
	public abstract void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException;

	public static final String HANDLE_METHOD_PREFIX = "handleMethod";

	public abstract String path();

	/**
	 * Primary purpose of this function is being overridden in your Toadlet implementations - for the following purpose:
	 *
	 * When displaying this Toadlet, the web interface should show the menu from which it was selected as opened, and mark the
	 * appropriate entry as selected in the menu. This function may return the Toadlet whose menu shall be opened and whose
	 * entry shall be marked as selected in the menu.
	 *
	 * It is necessary to have this function instead of just marking <code>Toadlet.this</code> as selected:
	 * Some Toadlets won't be added to a menu. They will be only accessible through other Toadlets. For example
	 * a Toadlet for deleting a single download might only be accessible through the Toadlet which shows all downloads.
	 * For still being able to figure out the menu entry through which those so-called invisible Toadlets where accessed,
	 * this function is necessary.
	 *
	 * @param context Can be used to decide the return value, for example to check session cookies using {@link SessionManager}.
     * @return
     *     The result of {@link #showAsToadlet()}, which is <code>this</code> by default.<br>
     *     This behavior is for backwards compatibility with existing code which overrides that
     *     function.<br><br>
     *
     *     Override this function to return something else for invisible Toadlets as explained
     *     above.
	 */
	public Toadlet showAsToadlet(ToadletContext context) {
	    return showAsToadlet();
	}

	/**
	 * @deprecated Use {@link #showAsToadlet(ToadletContext)} instead. Internally fred will always call that function, which calls this function by default,
	 *             so old code which only overrides this function still works.
	 *             TODO: When removing this deprecated function, change {@link #showAsToadlet(ToadletContext)} to return <code>this</code> by default, as
	 *             already specified in its JavaDoc.
	 * @return <code>this</code>
	 */
	@Deprecated
	public Toadlet showAsToadlet() {
        // DO NOT CHANGE THIS ANYMORE: Otherwise showAsToadlet(ToadletContext) will not follow the
        // contract of its JavaDoc.
        return this;
	}

	/**
	 * Override to return true if the toadlet should handle POSTs that don't have the correct form
	 * password. Otherwise they will be rejected and not passed to the toadlet.
	 */
	public boolean allowPOSTWithoutPassword() {
		return false;
	}

	protected Toadlet(HighLevelSimpleClient client) {
		this.client = client;
	}

	final HighLevelSimpleClient client;
	ToadletContainer container;

	private String supportedMethodsCache;

	private static String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("Toadlet."+key, new String[] { pattern }, new String[] { value });
	}

	private static String l10n(String key) {
		return NodeL10n.getBase().getString("Toadlet."+key);
	}

	/**
	 * Which methods are supported by this Toadlet.
	 * Should return a string containing the methods supported, separated by commas
	 * For example: "GET, PUT" (in which case both 'handleMethodGET()' and 'handleMethodPUT()'
	 * must be implemented).
	 *
	 * IMPORTANT: This will discover inherited methods because of getMethod()
	 * below. If you do not want to expose a method implemented by a parent
	 * class, then *OVERRIDE THIS METHOD*.
	 */
	public final String findSupportedMethods() {
		if (supportedMethodsCache == null) {
			Method methlist[] = this.getClass().getMethods();
			StringBuilder sb = new StringBuilder();
			for (Method m: methlist) {
				String name = m.getName();
				if (name.startsWith(HANDLE_METHOD_PREFIX)) {
					sb.append(name.substring(HANDLE_METHOD_PREFIX.length()));
					sb.append(", ");
				}
			}
			if (sb.length() >= 2) {
				// remove last ", "
				sb.deleteCharAt(sb.length()-1);
				sb.deleteCharAt(sb.length()-1);
			}
			supportedMethodsCache = sb.toString();
		}
		return supportedMethodsCache;
	}

	/**
	 * Client calls from the above messages to run a Freenet request.
	 * This method may block (or suspend).
	 * @param maxSize Maximum length of returned content.
	 * @param clientContext Client context object. This should be the same for any group of related requests, but different
	 * for any two unrelated requests. Request selection round-robin's over these, within any priority and retry count class,
	 * and above the level of individual block fetches.
	 */
	FetchResult fetch(FreenetURI uri, long maxSize, RequestClient clientContext, FetchContext fctx) throws FetchException {
		// For now, just run it blocking.
		FetchWaiter fw = new FetchWaiter(clientContext);
		@SuppressWarnings("unused")
		ClientGetter getter = client.fetch(uri, 1, fw, fctx);
		return fw.waitForCompletion();

	}
	/**
	 * Returns a default FetchContext
	 * @param maxSize The maximum allowable size of the fetch's result
	 * @return A default FetchContext
	 */
	FetchContext getFetchContext(long maxSize, String schemeHostAndPort) {
		//We want to retrieve a FetchContext we may override
		return client.getFetchContext(maxSize, schemeHostAndPort);
	}

	FreenetURI insert(InsertBlock insert, String filenameHint, boolean getCHKOnly) throws InsertException {
		// For now, just run it blocking.
		insert.desiredURI.checkInsertURI();
		return client.insert(insert, getCHKOnly, filenameHint);
	}

	/**
	 * Write an HTTP response, e.g. a page, an image, an error message, with no special headers.
	 * @param ctx The specific request to reply to.
	 * @param code The HTTP reply code to use.
	 * @param mimeType The MIME type of the data we are returning.
	 * @param desc The HTTP response description for the code.
	 * @param data The data to write as the response body.
	 * @param offset The offset within data of the first byte to send.
	 * @param length The number of bytes of data to send as the response body.
	 */
	protected void writeReply(ToadletContext ctx, int code, String mimeType, String desc, byte[] data, int offset, int length) throws ToadletContextClosedException, IOException {
		ctx.sendReplyHeaders(code, desc, null, mimeType, length);
		ctx.writeData(data, offset, length);
	}

	/**
	 * Write an HTTP response, e.g. a page, an image, an error message, with no special headers.
	 * @param ctx The specific request to reply to.
	 * @param code The HTTP reply code to use.
	 * @param mimeType The MIME type of the data we are returning.
	 * @param desc The HTTP response description for the code.
	 * @param data The Bucket which contains the reply data. This
	 *        function assumes ownership of the Bucket, calling free()
	 *        on it when done. If this behavior is undesired, callers
	 *        can wrap their Bucket in a NoFreeBucket.
	 *
	 * @see freenet.support.io.NoFreeBucket
	 */
	protected void writeReply(ToadletContext ctx, int code, String mimeType, String desc, Bucket data) throws ToadletContextClosedException, IOException {
		writeReply(ctx, code, mimeType, desc, null, data);
	}

	/**
	 * Write an HTTP response, e.g. a page, an image, an error message, possibly with custom
	 * headers, for example, we may want to send a redirect, or a file with a specified filename.
	 * @param ctx The specific request to reply to.
	 * @param code The HTTP reply code to use.
	 * @param mimeType The MIME type of the data we are returning.
	 * @param desc The HTTP response description for the code.
	 * @param headers The additional HTTP headers to send.
	 * @param data The Bucket which contains the reply data. This
	 *        function assumes ownership of the Bucket, calling free()
	 *        on it when done. If this behavior is undesired, callers
	 *        can wrap their Bucket in a NoFreeBucket.
	 *
	 * @see freenet.support.io.NoFreeBucket
	 */
	protected void writeReply(ToadletContext context, int code, String mimeType, String desc, MultiValueTable<String, String> headers, Bucket data) throws ToadletContextClosedException, IOException {
		context.sendReplyHeaders(code, desc, headers, mimeType, data.size());
		context.writeData(data);
	}

	/**
	 * Write a text-based HTTP response, e.g. a page or an error message, with no special headers.
	 * @param ctx The specific request to reply to.
	 * @param code The HTTP reply code to use.
	 * @param mimeType The MIME type of the data we are returning.
	 * @param desc The HTTP response description for the code.
	 * @param reply The reply data, as a String (so only use this for text-based replies, e.g.
	 * HTML, plain text etc).
	 */
	protected void writeReply(ToadletContext ctx, int code, String mimeType, String desc, String reply) throws ToadletContextClosedException, IOException {
		writeReply(ctx, code, mimeType, desc, null, reply, false);
	}

	/**
	 * Write an HTTP response as HTML.
	 * @param ctx The specific request to reply to.
	 * @param code The HTTP reply code to use.
	 * @param desc The HTTP response description for the code.
	 * @param reply The HTML page, as a String.
	 */
	protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply) throws ToadletContextClosedException, IOException {
		writeReply(ctx, code, "text/html; charset=utf-8", desc, null, reply, false);
	}

	/**
	 * Write an HTTP response as plain text.
	 * @param ctx The specific request to reply to.
	 * @param code The HTTP reply code to use.
	 * @param desc The HTTP response description for the code.
	 * @param reply The text of the page, as a String.
	 */
	protected void writeTextReply(ToadletContext ctx, int code, String desc, String reply) throws ToadletContextClosedException, IOException {
		writeReply(ctx, code, "text/plain; charset=utf-8", desc, null, reply, true);
	}

    /**
     * Write an HTTP response as HTML, possibly with custom headers, for example, we may want to
     * send a redirect, or a file with a specified filename.
     * @param ctx The specific request to reply to.
     * @param code The HTTP reply code to use.
     * @param desc The HTTP response description for the code.
     * @param headers The additional HTTP headers to send.
     * @param reply The HTML page, as a String.
     */
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, MultiValueTable<String, String> headers, String reply) throws ToadletContextClosedException, IOException {
        writeHTMLReply(ctx, code, desc, headers, reply, false);
    }

	/**
	 * Write an HTTP response as HTML, possibly with custom headers, for example, we may want to
	 * send a redirect, or a file with a specified filename.
	 * @param ctx The specific request to reply to.
	 * @param code The HTTP reply code to use.
	 * @param desc The HTTP response description for the code.
	 * @param headers The additional HTTP headers to send.
	 * @param reply The HTML page, as a String.
	 */
	protected void writeHTMLReply(ToadletContext ctx, int code, String desc, MultiValueTable<String, String> headers, String reply, boolean forceDisableJavascript) throws ToadletContextClosedException, IOException {
		writeReply(ctx, code, "text/html; charset=utf-8", desc, headers, reply, forceDisableJavascript);
	}

	/**
	 * Write an HTTP response as plain text, possibly with custom headers, for example, we may want
	 * to send a redirect, or a file with a specified filename.
	 * @param ctx The specific request to reply to.
	 * @param code The HTTP reply code to use.
	 * @param desc The HTTP response description for the code.
	 * @param headers The additional HTTP headers to send.
	 * @param reply The text of the page, as a String.
	 */
	protected void writeTextReply(ToadletContext ctx, int code, String desc, MultiValueTable<String, String> headers, String reply) throws ToadletContextClosedException, IOException {
		writeReply(ctx, code, "text/plain; charset=utf-8", desc, headers, reply, true);
	}

	protected void writeReply(ToadletContext context, int code, String mimeType, String desc, MultiValueTable<String, String> headers, String reply) throws ToadletContextClosedException, IOException {
	    writeReply(context, code, mimeType, desc, headers, reply, false);
	}

	protected void writeReply(ToadletContext context, int code, String mimeType, String desc, MultiValueTable<String, String> headers, String reply, boolean forceDisableJavascript) throws ToadletContextClosedException, IOException {
	    byte[] buffer = reply.getBytes("UTF-8");
	    writeReply(context, code, mimeType, desc, headers, buffer, 0, buffer.length, forceDisableJavascript);
	}

	/**
	 * Write a generated HTTP response, e.g. a page, an image, an error message, possibly with
	 * custom headers, for example, we may want to send a redirect, or a file with a specified
	 * filename. This should not be used for fproxy content i.e. content downloaded from Freenet.
	 * @param context The specific request to reply to.
	 * @param code The HTTP reply code to use.
	 * @param mimeType The MIME type of the data we are returning.
	 * @param desc The HTTP response description for the code.
	 * @param headers The additional HTTP headers to send.
	 * @param data The data to write as the response body.
	 * @param offset The offset within data of the first byte to send.
	 * @param length The number of bytes of data to send as the response body.
	 */
	private void writeReply(ToadletContext context, int code, String mimeType, String desc, MultiValueTable<String, String> headers, byte[] buffer, int startIndex, int length, boolean forceDisableJavascript) throws ToadletContextClosedException, IOException {
	    context.sendReplyHeaders(code, desc, headers, mimeType, length, forceDisableJavascript);
		context.writeData(buffer, startIndex, length);
	}

	/**
	 * Do a permanent redirect (HTTP Status 301).
	 *
	 * This will write rudimentary HTML, but typically browsers will follow
	 * the Location header.
	 * TODO Refactor with writeTemporaryRedirect.
	 * @param ctx
	 * @param msg
	 * @param location
	 * @throws ToadletContextClosedException
	 * @throws IOException
	 */
	static void writePermanentRedirect(ToadletContext ctx, String msg, String location) throws ToadletContextClosedException, IOException {
		MultiValueTable<String, String> mvt = new MultiValueTable<String, String>();
		mvt.put("Location", location);
		if(msg == null) msg = "";
		else msg = HTMLEncoder.encode(msg);
		String redirDoc =
			"<html><head><title>"+msg+"</title></head><body><h1>" +
			l10n("permRedirectWithReason", "reason", msg)+
			"</h1><a href=\""+HTMLEncoder.encode(location)+"\">"+l10n("clickHere")+"</a></body></html>";
		byte[] buf;
		try {
			buf = redirDoc.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		}
		ctx.sendReplyHeaders(301, "Moved Permanently", mvt, "text/html; charset=UTF-8", buf.length);
		ctx.writeData(buf, 0, buf.length);
	}

	/**
	 * Do a temporary redirect (HTTP Status 302).
	 *
	 * This will write rudimentary HTML, but typically browsers will follow
	 * the Location header.
	 * TODO Refactor with writePermanentRedirect.
	 * @param ctx
	 * @param msg Message to be used in HTML (not visible in general).
	 * @param location New location (URL)
	 * @throws ToadletContextClosedException
	 * @throws IOException
	 */
	protected void writeTemporaryRedirect(ToadletContext ctx, String msg, String location) throws ToadletContextClosedException, IOException {
		MultiValueTable<String, String> mvt = new MultiValueTable<String, String>();
		mvt.put("Location", location);
		if(msg == null) msg = "";
		else msg = HTMLEncoder.encode(msg);
		String redirDoc =
			"<html><head><title>"+msg+"</title></head><body><h1>" +
			l10n("tempRedirectWithReason", "reason", msg)+
			"</h1><a href=\""+HTMLEncoder.encode(location)+"\">" +
			l10n("clickHere") + "</a></body></html>";
		byte[] buf;
		try {
			buf = redirDoc.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		}
		ctx.sendReplyHeaders(302, "Found", mvt, "text/html; charset=UTF-8", buf.length);
		ctx.writeData(buf, 0, buf.length);
	}

	/**
	 * Send a simple error page.
	 */
	protected void sendErrorPage(ToadletContext ctx, int code, String desc, String message) throws ToadletContextClosedException, IOException {
		sendErrorPage(ctx, code, desc, new HTMLNode("#", message));
	}

	/**
	 * Send a slightly more complex error page.
	 */
	protected void sendErrorPage(ToadletContext ctx, int code, String desc, HTMLNode message) throws ToadletContextClosedException, IOException {
		PageNode page = ctx.getPageMaker().getPageNode(desc, ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;

		HTMLNode infoboxContent = ctx.getPageMaker().getInfobox("infobox-error", desc, contentNode, null, true);
		infoboxContent.addChild(message);
		infoboxContent.addChild("br");
		infoboxContent.addChild("a", "href", ".", l10n("returnToPrevPage"));
		infoboxContent.addChild("br");
		addHomepageLink(infoboxContent);

		writeHTMLReply(ctx, code, desc, pageNode.generate());
	}

	/**
	 * Send an error page from an exception.
	 * @param ctx The context object for this request.
	 * @param desc The title of the error page
	 * @param message The message to be sent to the user. The stack trace will follow.
	 * @param t The Throwable which caused the error.
	 * @throws IOException If there is an error writing the reply.
	 * @throws ToadletContextClosedException If the context has already been closed.
	 */
	protected void sendErrorPage(ToadletContext ctx, String desc, String message, Throwable t) throws ToadletContextClosedException, IOException {
		PageNode page = ctx.getPageMaker().getPageNode(desc, ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;

		HTMLNode infoboxContent = ctx.getPageMaker().getInfobox("infobox-error", desc, contentNode, null, true);
		infoboxContent.addChild("#", message);
		infoboxContent.addChild("br");
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		pw.println(t);
		t.printStackTrace(pw);
		pw.close();
		// FIXME what is the modern (CSS/XHTML) equivalent of <pre>?
		infoboxContent.addChild("pre", sw.toString());
		infoboxContent.addChild("br");
		infoboxContent.addChild("a", "href", ".", l10n("returnToPrevPage"));
		addHomepageLink(infoboxContent);

		writeHTMLReply(ctx, 500, desc, pageNode.generate());
	}

	/**
	 * @throws IOException See {@link #sendErrorPage(ToadletContext, int, String, String)}
	 * @throws ToadletContextClosedException See {@link #sendErrorPage(ToadletContext, int, String, String)}
	 */
    void sendUnauthorizedPage(ToadletContext ctx) throws ToadletContextClosedException, IOException {
        sendErrorPage(ctx, 403, NodeL10n.getBase().getString("Toadlet.unauthorizedTitle"), NodeL10n.getBase().getString("Toadlet.unauthorized"));
    }

	protected void writeInternalError(Throwable t, ToadletContext ctx) throws ToadletContextClosedException, IOException {
		Logger.error(this, "Caught "+t, t);
		String msg = "<html><head><title>"+NodeL10n.getBase().getString("Toadlet.internalErrorTitle")+
				"</title></head><body><h1>"+NodeL10n.getBase().getString("Toadlet.internalErrorPleaseReport")+"</h1><pre>";
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		while (t != null) {
			t.printStackTrace(pw);
			t = t.getCause();
		}
		pw.flush();
		msg = msg + sw.toString() + "</pre></body></html>";
		writeHTMLReply(ctx, 500, "Internal Error", msg);
	}

	protected static void addHomepageLink(HTMLNode content) {
		content.addChild("a", new String[]{"href", "title"}, new String[]{"/", l10n("homepage")}, l10n("returnToNodeHomepage"));
	}

	/**
	 * Get the client impl. DO NOT call the blocking methods on it!!
	 * Just use it for configuration etc.
	 */
	protected HighLevelSimpleClient getClientImpl() {
		return client;
	}
}
