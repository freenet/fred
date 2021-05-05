package freenet.clients.http;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.StringJoiner;
import java.util.TimeZone;

import freenet.clients.http.FProxyFetchInProgress.REFILTER_POLICY;
import freenet.clients.http.annotation.AllowData;
import freenet.clients.http.bookmark.BookmarkManager;
import freenet.l10n.NodeL10n;
import freenet.node.useralerts.UserAlertManager;
import freenet.support.HTMLEncoder;
import freenet.support.HTMLNode;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.MultiValueTable;
import freenet.support.TimeUtil;
import freenet.support.URIPreEncoder;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.api.HTTPRequest;
import freenet.support.io.BucketTools;
import freenet.support.io.FileUtil;
import freenet.support.io.LineReadingInputStream;
import freenet.support.io.TooLongException;

import static java.util.concurrent.TimeUnit.DAYS;
/**
 * ToadletContext implementation, including all the icky HTTP parsing etc.
 * An actual ToadletContext object represents a request, after we have parsed the 
 * headers. It provides methods to send replies.
 * @author root
 *
 */
public class ToadletContextImpl implements ToadletContext {
	
	private static final Class<?> HANDLE_PARAMETERS[] = new Class<?>[] {
		URI.class, HTTPRequest.class, ToadletContext.class
	};

	/* methods listed here are *not* configurable with
	 * AllowData annotation
	 */
	private static final String METHODS_MUST_HAVE_DATA = "POST";
	private static final String METHODS_CANNOT_HAVE_DATA = "GET";
	private static final String METHODS_RESTRICTED_MODE = "GET POST";
	
	private final MultiValueTable<String,String> headers;
	private ArrayList<ReceivedCookie> cookies; // Null until the first time the user queries us for a ReceivedCookie.
	private ArrayList<Cookie> replyCookies; // Null until the first time the user sets a Cookie.
	private final OutputStream sockOutputStream;
	private final PageMaker pagemaker;
	private final BucketFactory bf;
	private final ToadletContainer container;
	private final UserAlertManager userAlertManager;
	private final BookmarkManager bookmarkManager;
	private final InetAddress remoteAddr;
	private Exception firstReplySendingException;
	private volatile Toadlet activeToadlet;
	
	/** The unique id of the request*/
	private final String uniqueId;
	
	private URI uri;

        private static volatile boolean logMINOR;
        private static volatile boolean logDEBUG;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
                                logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}
	
	/** Is the context closed? If so, don't allow any more writes. This is because there
	 * may be later requests.
	 */
	private boolean closed;
	private boolean shouldDisconnect;
	
	public ToadletContextImpl(Socket sock, MultiValueTable<String,String> headers, BucketFactory bf, PageMaker pageMaker, ToadletContainer container, UserAlertManager userAlertManager, BookmarkManager bookmarkManager, URI uri, long uniqueID) throws IOException {
		this.headers = headers;
		this.cookies = null;
		this.replyCookies = null;
		this.closed = false;
		this.uri=uri;
		sockOutputStream = sock.getOutputStream();
		remoteAddr = sock.getInetAddress();
		if(logDEBUG)
			Logger.debug(this, "Connection from "+remoteAddr);
		this.bf = bf;
		this.pagemaker = pageMaker;
		this.container = container;
		this.userAlertManager = userAlertManager;
		this.bookmarkManager = bookmarkManager;
		//Generate an unique id
		uniqueId=String.valueOf(Math.random());
	}
	
	private void close() {
		closed = true;
	}
	
	private void sendMethodNotAllowed(String method, boolean shouldDisconnect) throws ToadletContextClosedException, IOException {
		if(closed) throw new ToadletContextClosedException();
		MultiValueTable<String,String> mvt = new MultiValueTable<String,String>();
		mvt.put("Allow", "GET, PUT");
		sendError(sockOutputStream, 405, "Method Not Allowed", l10n("methodNotAllowed"), shouldDisconnect, mvt);
	}
	
	private static String l10n(String key) {
		return NodeL10n.getBase().getString("ToadletContextImpl."+key);
	}

	private static String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("ToadletContextImpl."+key, new String[] { pattern }, new String[] { value });
	}

	/**
	 * Send an error message. Caller provides the HTTP code, reason string, and a message, which
	 * will become the title and the h1'ed contents of the error page. 
	 */
	private static void sendError(OutputStream os, int code, String httpReason, String message, boolean shouldDisconnect, MultiValueTable<String,String> mvt) throws IOException {
		sendHTMLError(os, code, httpReason, "<html><head><title>"+message+"</title></head><body><h1>"+message+"</h1></body>", shouldDisconnect, mvt);
	}
	
	/**
	 * Send an error message, containing full HTML from a String.
	 * @param os The OutputStream to send the message to.
	 * @param code The HTTP status code.
	 * @param httpReason The HTTP reason string for the HTTP status code. Do not make stuff up,
	 * use the official reason string, or some browsers may break.
	 * @param htmlMessage The HTML string to send.
	 * @param disconnect Whether to disconnect from the client afterwards.
	 * @param mvt Any additional headers.
	 * @throws IOException If we could not send the error message.
	 */
	private static void sendHTMLError(OutputStream os, int code, String httpReason, String htmlMessage, boolean disconnect, MultiValueTable<String,String> mvt) throws IOException {
		if(mvt == null) mvt = new MultiValueTable<String,String>();
		byte[] messageBytes = htmlMessage.getBytes("UTF-8");
		sendReplyHeaders(os, code, httpReason, mvt, "text/html; charset=UTF-8", messageBytes.length, null, disconnect, false, false);
		os.write(messageBytes);
	}
	
	private void sendNoToadletError(boolean shouldDisconnect) throws ToadletContextClosedException, IOException {
		if(closed) throw new ToadletContextClosedException();
		sendError(sockOutputStream, 404, "Not Found", l10n("noSuchToadlet"), shouldDisconnect, null);
	}
	
	private static void sendURIParseError(OutputStream os, boolean shouldDisconnect, Throwable e) throws IOException {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		e.printStackTrace(pw);
		pw.close();
		String message = "<html><head><title>"+l10n("uriParseErrorTitle")+"</title></head><body><p>"+HTMLEncoder.encode(e.getMessage())+"</p><pre>\n"+sw.toString();
		sendHTMLError(os, 400, "Bad Request", message, shouldDisconnect, null);
	}

	public void sendReplyHeaders(int code, String desc, MultiValueTable<String,String> mvt, String mimeType, long length) throws ToadletContextClosedException, IOException {
	    sendReplyHeaders(code, desc, mvt, mimeType, length, false);
	}
	
	public void sendReplyHeaders(int code, String desc, MultiValueTable<String,String> mvt, String mimeType, long length, boolean forceDisableJavascript) throws ToadletContextClosedException, IOException {
	    boolean enableJavascript = (!forceDisableJavascript) && container.isFProxyJavascriptEnabled();
	    sendReplyHeaders(code, desc, mvt, mimeType, length, null, false, false, enableJavascript);
	}

	@Deprecated
	public void sendReplyHeaders(int code, String desc, MultiValueTable<String,String> mvt, String mimeType, long length, Date mTime) throws ToadletContextClosedException, IOException {
	    if(mTime != null)
	        sendReplyHeadersStatic(code, desc, mvt, mimeType, length, mTime);
	    else
	        sendReplyHeaders(code, desc, mvt, mimeType, length);
	}
	
	public void sendReplyHeadersStatic(int replyCode, String replyDescription, MultiValueTable<String,String> mvt, String mimeType, long contentLength, Date mTime) throws ToadletContextClosedException, IOException {
	    if(mTime == null) throw new IllegalArgumentException();
	    sendReplyHeaders(replyCode, replyDescription, mvt, mimeType, contentLength, mTime, false, false, false);
	}
	
	@Override
	public void sendReplyHeadersFProxy(int replyCode, String replyDescription, MultiValueTable<String,String> mvt, String mimeType, long contentLength) throws ToadletContextClosedException, IOException {
	    boolean enableJavascript = false;
	    if(container.isFProxyWebPushingEnabled() && container.isFProxyJavascriptEnabled())
	        enableJavascript = true;
	    sendReplyHeaders(replyCode, replyDescription, mvt, mimeType, contentLength, null, false, true, enableJavascript);
	}
	
	private void sendReplyHeaders(int replyCode, String replyDescription, MultiValueTable<String,String> mvt, String mimeType, long contentLength, Date mTime, boolean isOutlinkConfirmationPage, boolean allowFrames, boolean enableJavascript) throws ToadletContextClosedException, IOException {
		if(closed) throw new ToadletContextClosedException();
		if(firstReplySendingException != null) {
			throw new IllegalStateException("Already sent headers!", firstReplySendingException);
		}
		firstReplySendingException = new Exception();
		
		if(replyCookies != null) {
			if (mvt == null) {
				mvt = new MultiValueTable<String,String>();
			}
			
			// We do NOT use "set-cookie2" even though we should according though RFC2965 - Firefox 3.0.14 ignores it for me!
			
			for(Cookie cookie : replyCookies) {
				final String cookieHeader = cookie.encodeToHeaderValue();
				mvt.put("set-cookie", cookieHeader);
				if(logMINOR)
					Logger.minor(this, "set-cookie: " + cookieHeader);
			}
		}
		sendReplyHeaders(sockOutputStream, replyCode, replyDescription, mvt, mimeType, contentLength, mTime, shouldDisconnect, enableJavascript, allowFrames);
	}
	
	@Override
	public PageMaker getPageMaker() {
		return pagemaker;
	}
	
	@Override
	public String getFormPassword() {
		return container.getFormPassword();
	}
	
	@Override
	public boolean checkFormPassword(HTTPRequest request)
			throws ToadletContextClosedException, IOException {
		return checkFormPassword(request, "/");
	}
	
	@Override
	public boolean checkFormPassword(HTTPRequest request, String redirectTo)
			throws ToadletContextClosedException, IOException {
		if (!hasFormPassword(request)) {
			MultiValueTable<String, String> headers = new MultiValueTable<String, String>();
			headers.put("Location", redirectTo);
			sendReplyHeaders(302, "Found", headers, null, 0);
			return false;
		} else {
			return true;
		}
	}
	
	/**
	 * @see ToadletContext#checkFullAccess(Toadlet)
	 */
	@Override
    public boolean checkFullAccess(Toadlet toadlet) throws ToadletContextClosedException, IOException {
        if(isAllowedFullAccess()) {
            return true;
        } else {
            toadlet.sendUnauthorizedPage(this);
            return false;
        }
    }
	
	@Override
	public boolean hasFormPassword(HTTPRequest request) throws IOException {
		String pass = request.getPartAsStringFailsafe("formPassword", 32);
		byte[] inputBytes = pass.getBytes("UTF-8");
		byte[] compareBytes = getFormPassword().getBytes("UTF-8");
		if(!MessageDigest.isEqual(inputBytes, compareBytes)) {
			if (logMINOR)
				Logger.minor(this, "Bad formPassword: " + pass);
			return false;
		} else return true;
	}
	
	@Override
	public UserAlertManager getAlertManager() {
		return userAlertManager;
	}
	
	@Override
	public BookmarkManager getBookmarkManager() {
		return bookmarkManager;
	}
	
	@Override
	public MultiValueTable<String,String> getHeaders() {
		return headers;
	}
	
	private void parseCookies() throws ParseException {
		if(cookies != null)
			return;
		
		int cookieAmount = headers.countAll("cookie");
		
		if(cookieAmount == 0)
			return;
		
		cookies = new ArrayList<ReceivedCookie>(cookieAmount + 1);
		
		for(String cookieHeader : headers.iterateAll("cookie")) {
			ArrayList<ReceivedCookie> parsedCookies = ReceivedCookie.parseHeader(cookieHeader);
			cookies.addAll(parsedCookies);
		}
	}
	
	@Override
	public ReceivedCookie getCookie(URI domain, URI path, String name) throws ParseException {
		parseCookies();
		
		if(cookies == null) // There are no cookies.
			return null;
		
		name = name.toLowerCase();
		
		//String stringDomain = domain==null ? null : domain.toString().toLowerCase();
		//String stringPath = path.toString();
		
		// RFC2965: Two cookies are equal if name and domain are equal with case-insensitive comparison and path is equal with case-sensitive comparison.
		//getName() / getDomain() returns lowercase and getPath() returns the original path.
		
		// UNFORTUNATELY firefox will ONLY give us the name and the value of the cookie, so we ignore everything else.
		
		for(ReceivedCookie cookie : cookies) {
			try {
			//if(stringDomain != null) {
			//	URI cookieDomain = cookie.getDomain();
			//	
			//	if(cookieDomain==null || !stringDomain.equals(cookieDomain.toString()))
			//		continue;
			//}
			//
			//if(cookie.getPath().toString().equals(stringPath) && cookie.getName().equals(name))
			//	return cookie;
				
				if(cookie.getName().equals(name))
					return cookie;
			}
			catch(RuntimeException e) {
				Logger.error(this, "Error in cookie", e);
			}
		}
		
		return null;
	}
	
	@Override
	public void setCookie(Cookie newCookie) {
		if(replyCookies == null)
			replyCookies = new ArrayList<Cookie>(4);
		
		replyCookies.add(newCookie);
	}
	
	static void sendReplyHeaders(OutputStream sockOutputStream, int replyCode, String replyDescription, MultiValueTable<String,String> mvt, String mimeType, long contentLength, Date mTime, boolean disconnect, boolean allowScripts, boolean allowFrames) throws IOException {
		
		// Construct headers
		if(mvt == null)
			mvt = new MultiValueTable<String,String>();
		if(mimeType != null)
			if(mimeType.equalsIgnoreCase("text/html")){
				mvt.put("content-type", mimeType+"; charset=UTF-8");
			}else{
				mvt.put("content-type", mimeType);
			}
		if(contentLength >= 0)
			mvt.put("content-length", Long.toString(contentLength));

		boolean allowCaching; // For privacy reasons, only static
							  // content may be cached
		if (mTime == null) {
			allowCaching = false;
		} else {
			allowCaching = true;
		}
		String expiresTime;
		String cacheControl;
		if (allowCaching) {
			// use an expiry time of 30 day from now, about the frequency of Freenet releases
			// Expires is needed for older browsers
			expiresTime = TimeUtil.makeHTTPDate(System.currentTimeMillis() + DAYS.toMillis(30));
			cacheControl = "public, max-age=" + String.valueOf(3600 * 24 * 30);
		} else {
			expiresTime = "Thu, 01 Jan 1970 00:00:00 GMT";
			// no-cache for Internet Explorer, no-store for Firefox
			cacheControl = "private, max-age=0, must-revalidate, no-cache, no-store, post-check=0, pre-check=0";
			mvt.put("pragma", "no-cache");
		}
		mvt.put("expires", expiresTime);
		mvt.put("cache-control", cacheControl);
		
		String nowString = TimeUtil.makeHTTPDate(System.currentTimeMillis());
		String lastModString;
		if (mTime == null) {
			lastModString = nowString;
		} else {
			lastModString = TimeUtil.makeHTTPDate(mTime.getTime());
		}
		
		mvt.put("last-modified", lastModString);
		mvt.put("date", nowString);
		if(disconnect)
			mvt.put("connection", "close");
		else
			mvt.put("connection", "keep-alive");
		String contentSecurityPolicy = generateCSP(allowScripts, allowFrames);
		mvt.put("content-security-policy", contentSecurityPolicy);
		mvt.put("x-content-security-policy", contentSecurityPolicy);
		mvt.put("x-webkit-csp", contentSecurityPolicy);
		mvt.put("x-frame-options", allowFrames ? "SAMEORIGIN" : "DENY");
		StringBuilder buf = new StringBuilder(1024);
		buf.append("HTTP/1.1 ");
		buf.append(replyCode);
		buf.append(' ');
		buf.append(replyDescription);
		buf.append("\r\n");
		for(Enumeration<String> e = mvt.keys();e.hasMoreElements();) {
			String key = e.nextElement();
			Object[] list = mvt.getArray(key);
			key = fixKey(key);
			for(int i=0;i<list.length;i++) {
				String val = (String) list[i];
				buf.append(key);
				buf.append(": ");
				buf.append(val);
				buf.append("\r\n");
			}
		}
		buf.append("\r\n");
		sockOutputStream.write(buf.toString().getBytes("US-ASCII"));
	}
	
	private static String generateCSP(boolean allowScripts, boolean allowFrames) {
	    StringBuilder sb = new StringBuilder();
	    // allow access to blobs, because these are purely local
	    sb.append("default-src 'self' blob:; script-src ");
	    // "options inline-script" is old syntax needed for older Firefox's.
	    sb.append(allowScripts
					? "'self' 'unsafe-inline'; options inline-script"
					: generateRestrictedScriptSrc());
	    sb.append("; frame-src ");
        sb.append(allowFrames ? "'self'" : "'none'");
        sb.append("; object-src 'none'");
        // Always send unsafe-inline for CSS. This is safe given it can't use external stuff anyway.
        // It's only strictly needed for fproxy.
        sb.append("; style-src 'self' 'unsafe-inline'");
        return sb.toString();
    }

	private static String generateRestrictedScriptSrc() {
		// TODO: auto-generate these hashes from the path to the source file
		String[] allowedScriptHashes = new String[] {
				"sha256-Q62svpg2DVmqkdDQuG/nKUpYqz8FRjSWYbenaFrxXoQ=" // freenet/clients/http/staticfiles/js/m3u-player.js
		};
		if (allowedScriptHashes.length == 0) {
			return "'none'";
		} else {
			StringJoiner stringJoiner = new StringJoiner("' '", "'", "'");
			for (String source : allowedScriptHashes) {
				stringJoiner.add(source);
			}
			return stringJoiner.toString();
		}
	}

	static TimeZone TZ_UTC = TimeZone.getTimeZone("UTC");

	public static Date parseHTTPDate(String httpDate) throws java.text.ParseException{
		SimpleDateFormat sdf = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'",Locale.US);
		sdf.setTimeZone(TZ_UTC);
		return sdf.parse(httpDate);
	}
	
	/** Fix key case to be conformant to HTTP expectations.
	 * Note that HTTP is case insensitive on header names, but we may as well
	 * send something as close to the spec as possible in case of broken clients... 
	 */
	private static String fixKey(String key) {
		StringBuilder sb = new StringBuilder(key.length());
		char prev = 0;
		for(int i=0;i<key.length();i++) {
			char c = key.charAt(i);
			if((i == 0) || (prev == '-')) {
				c = Character.toUpperCase(c);
			}
			sb.append(c);
			prev = c;
		}
		return sb.toString();
	}
	
	/**
	 * Handle an incoming connection. Blocking, obviously.
	 */
	public static void handle(Socket sock, ToadletContainer container, PageMaker pageMaker, UserAlertManager userAlertManager, BookmarkManager bookmarkManager) {
		try {
			InputStream is = new BufferedInputStream(sock.getInputStream(), 4096);
			
			LineReadingInputStream lis = new LineReadingInputStream(is);
			
			while(true) {
				
				String firstLine = lis.readLine(32768, 128, false); // ISO-8859-1 or US-ASCII, _not_ UTF-8
				if (firstLine == null) {
					sock.close();
					return;
				} else if (firstLine.equals("")) {
					continue;
				}
				
				if(logMINOR)
					Logger.minor(ToadletContextImpl.class, "first line: "+firstLine);
				
				String[] split = firstLine.split(" ");
				
				if(split.length != 3)
					throw new ParseException("Could not parse request line (split.length="+split.length+"): "+firstLine, -1);
				
				if(!split[2].startsWith("HTTP/1."))
					throw new ParseException("Unrecognized protocol "+split[2], -1);
				
				URI uri;
				try {
					uri = URIPreEncoder.encodeURI(split[1]).normalize();
					if(logMINOR) Logger.minor(ToadletContextImpl.class, "URI: "+uri+" path "+uri.getPath()+" host "+uri.getHost()+" frag "+uri.getFragment()+" port "+uri.getPort()+" query "+uri.getQuery()+" scheme "+uri.getScheme());
				} catch (URISyntaxException e) {
					sendURIParseError(sock.getOutputStream(), true, e);
					return;
				}
				String method = split[0];
				
				MultiValueTable<String,String> headers = new MultiValueTable<String,String>();
				
				while(true) {
					String line = lis.readLine(32768, 128, false); // ISO-8859 or US-ASCII, not UTF-8
					if (line == null) {
						sock.close();
						return;
					}
					//System.out.println("Length="+line.length()+": "+line);
					if(line.length() == 0) break;
					int index = line.indexOf(':');
					if (index < 0) {
						throw new ParseException("Missing ':' in request header field", -1);
					}
					String before = line.substring(0, index).toLowerCase();
					String after = line.substring(index+1);
					after = after.trim();
					headers.put(before, after);
				}
				
				boolean disconnect = shouldDisconnectAfterHandled(split[2].equals("HTTP/1.0"), headers) || !container.enablePersistentConnections();

				boolean allowPost = container.allowPosts();
				BucketFactory bf = container.getBucketFactory();
				
				ToadletContextImpl ctx = new ToadletContextImpl(sock, headers, bf, pageMaker, container, userAlertManager, bookmarkManager, uri, container.generateUniqueID());
				ctx.shouldDisconnect = disconnect;
				
				/*
				 * copy the data into a bucket now,
				 * before we go into the redirect loop
				 */
				
				Bucket data;


				String slen = headers.get("content-length");

				if (METHODS_MUST_HAVE_DATA.contains(method)) {
					// <method> must have data
					if (slen == null) {
						ctx.shouldDisconnect = true;
						ctx.sendReplyHeaders(400, "Bad Request", null, null, -1);
						return;
					}
				} else if (METHODS_CANNOT_HAVE_DATA.contains(method)) {
					// <method> can not have data
					if (slen != null) {
						ctx.shouldDisconnect = true;
						ctx.sendReplyHeaders(400, "Bad Request", null, null, -1);
						return;
					}
				}

				if (slen != null) {
					long len;
					try {
						len = Integer.parseInt(slen);
						if(len < 0) throw new NumberFormatException("content-length less than 0");
					} catch (NumberFormatException e) {
						ctx.shouldDisconnect = true;
						ctx.sendReplyHeaders(400, "Bad Request", null, null, -1);
						return;
					}
					if(allowPost && ((!container.publicGatewayMode()) || ctx.isAllowedFullAccess())) {
						data = bf.makeBucket(len);
						BucketTools.copyFrom(data, is, len);
					} else {
						FileUtil.skipFully(is, len);
						if (method.equals("POST")) {
							ctx.sendMethodNotAllowed("POST", true);
						} else {
							sendError(sock.getOutputStream(), 403, "Forbidden", "Content not allowed in this configuration", true, null);
						}
						ctx.close();
						return;
					}
				} else {
					// we're not doing to use it, but we have to keep
					// the compiler happy
					data = null;
				}

				if (!container.enableExtendedMethodHandling()) {
					if (!METHODS_RESTRICTED_MODE.contains(method)) {
						sendError(sock.getOutputStream(), 403, "Forbidden", "Method not allowed in this configuration", true, null);
						return;
					}
				}

				// Handle it.
				try {
					boolean redirect = true;
					while (redirect) {
						// don't go around the loop unless set explicitly
						redirect = false;
						
						Toadlet t;
						try {
							t = container.findToadlet(uri);
						} catch (PermanentRedirectException e) {
							Toadlet.writePermanentRedirect(ctx, "Found elsewhere", e.newuri.toASCIIString());
							break;
						}
					
						if(t == null) {
							ctx.sendNoToadletError(ctx.shouldDisconnect);
							break;
						}

						// if the Toadlet does not support the method, we don't need to parse the data
						// also due this pre check a 'NoSuchMethodException' should never appear
						if (!(t.findSupportedMethods().contains(method))) {
							ctx.sendMethodNotAllowed(method, ctx.shouldDisconnect);
							break;
						}

						HTTPRequestImpl req = new HTTPRequestImpl(uri, data, ctx, method);
						
						// require form password if it's a POST, unless the toadlet requests otherwise
						if (method.equals("POST") && !t.allowPOSTWithoutPassword()) {
							if (!ctx.checkFormPassword(req, t.path())) {
								break;
							}
						}
						
						if(ctx.isAllowedFullAccess()) {
							ctx.getPageMaker().parseMode(req, container);
						}
						
						try {
							callToadletMethod(t, method, uri, req, ctx, data, sock, redirect);
						} catch (RedirectException re) {
							uri = re.newuri;
							redirect = true;
						} finally {
							req.freeParts();
						}
					}
					if(ctx.shouldDisconnect) {
						sock.close();
						return;
					}
				} finally {
					if(data != null) data.free();
				}
			}
			
		} catch (ParseException e) {
			try {
				sendError(sock.getOutputStream(), 400, "Bad Request", l10n("parseErrorWithError", "error", e.getMessage()), true, null);
			} catch (IOException e1) {
				// Ignore
			}
		} catch (TooLongException e) {
			try {
				sendError(sock.getOutputStream(), 400, "Bad Request", l10n("headersLineTooLong"), true, null);
			} catch (IOException e1) {
				// Ignore
			}
		} catch (IOException e) {
			// ignore and return
		} catch (ToadletContextClosedException e) {
			Logger.error(ToadletContextImpl.class, "ToadletContextClosedException while handling connection!");
		} catch (Throwable t) {
			Logger.error(ToadletContextImpl.class, "Caught error: "+t+" handling socket", t);
			try {
				String msg = "<html><head><title>"+NodeL10n.getBase().getString("Toadlet.internalErrorTitle")+
						"</title></head><body><h1>"+NodeL10n.getBase().getString("Toadlet.internalErrorPleaseReport")+"</h1><pre>";
				StringWriter sw = new StringWriter();
				PrintWriter pw = new PrintWriter(sw);
				t.printStackTrace(pw);
				pw.flush();
				msg = msg + sw.toString() + "</pre></body></html>";
				byte[] messageBytes = msg.getBytes("UTF-8");
				sendReplyHeaders(sock.getOutputStream(), 500, "Internal failure", null, "text/html; charset=UTF-8", messageBytes.length, null, true, false, false);
				sock.getOutputStream().write(messageBytes);
			} catch (IOException e1) {
				// ignore and return
			}
		}
	}
	
	private static void callToadletMethod(Toadlet t, String method, URI uri, HTTPRequestImpl req, 
			ToadletContextImpl ctx, Bucket data, Socket sock, boolean methodIsConfigurable) throws Throwable {
		String methodName = Toadlet.HANDLE_METHOD_PREFIX + method;
		if("GET".equals(method)) {
			// Short cut the common case.
			if (data != null) {
				sendError(sock.getOutputStream(), 400, "Bad Request", "Content not allowed", true, null);
				ctx.close();
				return;
			}
			ctx.setActiveToadlet(t);
			t.handleMethodGET(uri, req, ctx);
			return;
		}
		try {
			Class<? extends Toadlet> c = t.getClass();
			Method m = c.getMethod(methodName, HANDLE_PARAMETERS);
			if (methodIsConfigurable) {
				AllowData anno = m.getAnnotation(AllowData.class);
				if (anno == null) {
					if (data != null) {
						sendError(sock.getOutputStream(), 400, "Bad Request", "Content not allowed", true, null);
						ctx.close();
						return;
					}
				} else if (anno.value()) {
					if (data == null) {
						sendError(sock.getOutputStream(), 400, "Bad Request", "Missing Content", true, null);
						ctx.close();
						return;
					}
				}
			}
			ctx.setActiveToadlet(t);
			Object arglist[] = new Object[] {uri, req, ctx};
			m.invoke(t, arglist);
		} catch (InvocationTargetException ite) {
			throw ite.getCause();
		}
	}

	private void setActiveToadlet(Toadlet t) {
		this.activeToadlet = t;
	}
	
	@Override
	public Toadlet activeToadlet() {
		return activeToadlet;
	}

	/**
	 * Should the connection be closed after handling this request?
	 * @param isHTTP10 Did the client specify HTTP/1.0?
	 * @param headers Client headers.
	 * @return True if the connection should be closed.
	 */
	private static boolean shouldDisconnectAfterHandled(boolean isHTTP10, MultiValueTable<String,String> headers) {
		String connection = headers.get("connection");
		if(connection != null) {
			if(connection.equalsIgnoreCase("close"))
				return true;
			
			if(connection.equalsIgnoreCase("keep-alive"))
				return false;
		}
		if(isHTTP10 == true)
			return true;
		else
			// HTTP 1.1
			return false;
	}
	
	@Override
	public void writeData(byte[] data, int offset, int length) throws ToadletContextClosedException, IOException {
		if(closed) throw new ToadletContextClosedException();
		sockOutputStream.write(data, offset, length);
	}
	
	@Override
	public void writeData(byte[] data) throws ToadletContextClosedException, IOException {
		writeData(data, 0, data.length);
	}
	
	/**
	 * @param data The Bucket which contains the reply data. This
	 *        function assumes ownership of the Bucket, calling free()
	 *        on it when done. If this behavior is undesired, callers
	 *        can wrap their Bucket in a NoFreeBucket.
	 *
	 * @see freenet.support.io.NoFreeBucket
	 */
	@Override
	public void writeData(Bucket data) throws ToadletContextClosedException, IOException {
		if(closed) throw new ToadletContextClosedException();
		BucketTools.copyTo(data, sockOutputStream, Long.MAX_VALUE);
		data.free();
	}
	
	@Override
	public BucketFactory getBucketFactory() {
		return bf;
	}

	@Override
	public HTMLNode addFormChild(HTMLNode parentNode, String target, String name) {
		return container.addFormChild(parentNode, target, name);
	}

	@Override
	public boolean isAllowedFullAccess() {
		return container.isAllowedFullAccess(remoteAddr);
	}
	
	@Override
	public boolean isAdvancedModeEnabled() {
		return container.isAdvancedModeEnabled();
	}

	@Override
	public boolean doRobots() {
		return container.doRobots();
	}

	@Override
	public void forceDisconnect() {
		this.shouldDisconnect = true;
	}

	@Override
	public ToadletContainer getContainer() {
		return container;
	}

	@Override
	public boolean disableProgressPage() {
		return container.disableProgressPage();
	}
	
	@Override
	public String getUniqueId(){
		return uniqueId;
	}
	
	@Override
	public URI getUri() {
		return uri;
	}

	@Override
	public REFILTER_POLICY getReFilterPolicy() {
		return container.getReFilterPolicy();
	}
}
