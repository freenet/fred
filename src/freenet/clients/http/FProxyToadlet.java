package freenet.clients.http;

import static java.util.concurrent.TimeUnit.HOURS;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import freenet.client.DefaultMIMETypes;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.FetchResult;
import freenet.client.HighLevelSimpleClient;
import freenet.client.async.ClientContext;
import freenet.client.filter.ContentFilter;
import freenet.client.filter.FilterMIMEType;
import freenet.client.filter.FoundURICallback;
import freenet.client.filter.PushingTagReplacerCallback;
import freenet.client.filter.UnsafeContentTypeException;
import freenet.clients.http.ajaxpush.DismissAlertToadlet;
import freenet.clients.http.ajaxpush.LogWritebackToadlet;
import freenet.clients.http.ajaxpush.PushDataToadlet;
import freenet.clients.http.ajaxpush.PushFailoverToadlet;
import freenet.clients.http.ajaxpush.PushKeepaliveToadlet;
import freenet.clients.http.ajaxpush.PushLeavingToadlet;
import freenet.clients.http.ajaxpush.PushNotificationToadlet;
import freenet.clients.http.ajaxpush.PushTesterToadlet;
import freenet.clients.http.updateableelements.ProgressBarElement;
import freenet.clients.http.updateableelements.ProgressInfoElement;
import freenet.config.Config;
import freenet.config.SubConfig;
import freenet.crypt.SHA256;
import freenet.keys.FreenetURI;
import freenet.keys.USK;
import freenet.l10n.NodeL10n;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.RequestClient;
import freenet.node.RequestClientBuilder;
import freenet.node.RequestStarter;
import freenet.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import freenet.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import freenet.pluginmanager.PluginInfoWrapper;
import freenet.support.HTMLEncoder;
import freenet.support.HTMLNode;
import freenet.support.HexUtil;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.MediaType;
import freenet.support.MultiValueTable;
import freenet.support.SizeUtil;
import freenet.support.URIPreEncoder;
import freenet.support.URLEncoder;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.api.HTTPRequest;
import freenet.support.io.BucketTools;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import freenet.support.io.NoFreeBucket;

public final class FProxyToadlet extends Toadlet implements RequestClient {

	private static byte[] random;
	final NodeClientCore core;
	final ClientContext context;
	final FProxyFetchTracker fetchTracker;

	static final Set<String> prefetchAllowedTypes = new HashSet<>(Arrays.asList(
			"image/png",
			"image/jpeg",
			"image/gif",
			"audio/mp3",
			"audio/ogg",
			"video/ogg",
			"application/ogg"
	));

	// ?force= links become invalid after 2 hours.
	private static final long FORCE_GRAIN_INTERVAL = HOURS.toMillis(1);
	/** Maximum size for transparent pass-through. See config passthroughMaxSizeProgress */
	public static long MAX_LENGTH_WITH_PROGRESS = (100*1024*1024) * 11 / 10; // 100MiB plus a bit due to buggy inserts, because our Windows installer is >70 MiB nowadays
	public static long MAX_LENGTH_NO_PROGRESS = (2*1024*1024) * 11 / 10; // 2MiB plus a bit due to buggy inserts

	static final URI welcome;
	public static final short PRIORITY = RequestStarter.INTERACTIVE_PRIORITY_CLASS;
	static {
		try {
			welcome = new URI("/welcome/");
		} catch (URISyntaxException e) {
			throw new Error("Broken URI constructor: "+e, e);
		}
	}

        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	// FIXME make this configurable (or get rid of prefetch support)
	static final int MAX_PREFETCH = 50;

	public FProxyToadlet(final HighLevelSimpleClient client, NodeClientCore core, FProxyFetchTracker tracker) {
		super(client);
		client.setMaxLength(MAX_LENGTH_NO_PROGRESS);
		client.setMaxIntermediateLength(MAX_LENGTH_NO_PROGRESS);
		this.core = core;
		this.context = core.clientContext;
		fetchTracker = tracker;
	}

	@Override
	public boolean allowPOSTWithoutPassword() {
		return true;
	}

	public void handleMethodPOST(URI uri, HTTPRequest req, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {
		String ks = uri.getPath();

		if (ks.equals("/")||ks.startsWith("/servlet/")) {
			try {
	            throw new RedirectException("/welcome/");
			} catch (URISyntaxException e) {
				// HUH!?!
			}
		}
	}

	private void handleDownload(ToadletContext context, Bucket data, BucketFactory bucketFactory, String mimeType, String requestedMimeType, String forceString, boolean forceDownload, String basePath, FreenetURI key, String extras, String referrer, boolean downloadLink, ToadletContext ctx, NodeClientCore core, boolean dontFreeData, String maybeCharset) throws ToadletContextClosedException, IOException {
		if(logMINOR)
			Logger.minor(FProxyToadlet.class, "handleDownload(data.size="+data.size()+", mimeType="+mimeType+", requestedMimeType="+requestedMimeType+", forceDownload="+forceDownload+", basePath="+basePath+", key="+key);
		String extrasNoMime = extras; // extras will not include MIME type to start with - REDFLAG maybe it should be an array
		if(requestedMimeType != null) {
			if(mimeType == null || !requestedMimeType.equals(mimeType)) {
				if(extras == null) extras = "";
				extras = extras + "&type=" + requestedMimeType;
			}
		}
		long size = data.size();

		long now = System.currentTimeMillis();
		boolean force = false;
		if(forceString != null) {
			if(forceString.equals(getForceValue(key, now)) ||
					forceString.equals(getForceValue(key, now-FORCE_GRAIN_INTERVAL)))
				force = true;
		}

		if((!force) && (!forceDownload)) {
			//Horrible hack needed for GWT as it relies on document.write() which is not supported in xhtml
			if(mimeType.compareTo("application/xhtml+xml")==0){
				mimeType="text/html";
			}
			if(isSniffedAsFeed(data) && !(mimeType.startsWith("application/rss+xml"))) {
				PageNode page = context.getPageMaker().getPageNode(l10n("dangerousRSSTitle"), context);
				HTMLNode pageNode = page.outer;
				HTMLNode contentNode = page.content;

				HTMLNode infobox = contentNode.addChild("div", "class", "infobox infobox-alert");
				infobox.addChild("div", "class", "infobox-header", l10n("dangerousRSSSubtitle"));
				HTMLNode infoboxContent = infobox.addChild("div", "class", "infobox-content");
				infoboxContent.addChild("#", NodeL10n.getBase().getString("FProxyToadlet.dangerousRSS", new String[] { "type" }, new String[] { mimeType }));
				infoboxContent.addChild("p", l10n("options"));
				HTMLNode optionList = infoboxContent.addChild("ul");
				HTMLNode option = optionList.addChild("li");

				NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.openPossRSSAsPlainText", new String[] { "link", "bold" },
						new HTMLNode[] {
						HTMLNode.link(basePath+key.toString()+"?type=text/plain&force="+getForceValue(key,now)+extrasNoMime),
						HTMLNode.STRONG
				});
				// 	FIXME: is this safe? See bug #131
				option = optionList.addChild("li");
				NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.openPossRSSForceDisk", new String[] { "link", "bold" },
						new HTMLNode[] {
						HTMLNode.link(basePath+key.toString()+"?forcedownload"+extras),
						HTMLNode.STRONG
				});
				boolean mimeRSS = mimeType.startsWith("application/xml+rss") || mimeType.startsWith("text/xml"); /* blergh! */
				if(!(mimeRSS || mimeType.startsWith("text/plain"))) {
					option = optionList.addChild("li");
					NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.openRSSForce", new String[] { "link", "bold", "mime" },
							new HTMLNode[] {
							HTMLNode.link(basePath+key.toString()+"?force="+getForceValue(key, now)+extras), HTMLNode.STRONG, HTMLNode.text(mimeType) });
				}
				option = optionList.addChild("li");
				NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.openRSSAsRSS", new String[] { "link", "bold" },
						new HTMLNode[] {
						HTMLNode.link(basePath + key.toString() + "?type=application/xml+rss&force=" + getForceValue(key, now)+extrasNoMime),
						HTMLNode.STRONG });
				addDownloadOptions(ctx, optionList, key, mimeType, true, false, core); // FIXME Or false, false? Or true, true? We don't have filter for rss/atom anyway, so it will be useless - only more confusion and clicking for user. When we *will* have one, we can just get rid of this warning page.
				if(referrer != null) {
					option = optionList.addChild("li");
					NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.backToReferrer", new String[] { "link" },
							new HTMLNode[] { HTMLNode.link(referrer) });
				}
				option = optionList.addChild("li");
				NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.backToFProxy", new String[] { "link" },
						new HTMLNode[] { HTMLNode.link("/") });

				byte[] pageBytes = pageNode.generate().getBytes("UTF-8");
				context.sendReplyHeaders(200, "OK", new MultiValueTable<String, String>(), "text/html; charset=utf-8", pageBytes.length);
				context.writeData(pageBytes);
				return;
			}
		}

		if (forceDownload) {
			MultiValueTable<String, String> headers = new MultiValueTable<String, String>();
			headers.put("Content-Disposition", "attachment; filename=\"" + key.getPreferredFilename() + '"');
			headers.put("Cache-Control", "private");
			headers.put("Content-Transfer-Encoding", "binary");
            headers.put("X-Content-Type-Options", "nosniff");
			// really the above should be enough, but ...
			// was application/x-msdownload, but some unix browsers offer to open that in Wine as default!
			// it is important that this type not be understandable, but application/octet-stream doesn't work.
			// see http://onjava.com/pub/a/onjava/excerpt/jebp_3/index3.html
			// Testing on FF3.5.1 shows that application/x-force-download wants to run it in wine,
			// whereas application/force-download wants to save it.
			context.sendReplyHeadersFProxy(200, "OK", headers, "application/force-download", size);
			context.writeData(data);
		} else {
			// Send the data, intact
			MultiValueTable<String, String> hdr = context.getHeaders();

			MultiValueTable<String, String> retHdr = new MultiValueTable<String, String>();
			/*
			 * Firefox and its derivatives may use the MIME type implied by the filename extension for
			 * plain text, unless a Content-Encoding is specified.
			 *
			 * See https://developer.mozilla.org/en-US/docs/Mozilla/How_Mozilla_determines_MIME_Types#HTTP
			 */
			retHdr.put("Content-Encoding", "identity");

			String rangeStr = hdr.get("range");
			// was a range request
			if (rangeStr != null) {

				long range[];
				try {
					range = parseRange(rangeStr);
				} catch (HTTPRangeException e) {
					ctx.sendReplyHeaders(416, "Requested Range Not Satisfiable", null, null, 0);
					return;
				}
				if (range[1] == -1 || range[1] >= size) {
					range[1] = size - 1;
				}
				InputStream is = null;
				OutputStream os = null;
				Bucket tmpRange = bucketFactory.makeBucket(range[1] - range[0]);
				try {
					is = data.getInputStream();
					os = tmpRange.getOutputStream();
					if (range[0] > 0)
						FileUtil.skipFully(is, range[0]);
					FileUtil.copy(is, os, range[1] - range[0] + 1);
					// FIXME catch IOException here and tell the user there is a problem instead of just closing the connection.
					// Currently there is no way to tell the difference between an IOE caused by the connection to the client and an internal one, we just close the connection in both cases.
					os.close(); os = null; // If we can't write, we need to throw, so we don't send too little data.
				} finally {
					Closer.close(is);
					Closer.close(os);
				}
				retHdr.put("Content-Range", "bytes " + range[0] + "-" + range[1] + "/" + size);
                retHdr.put("X-Content-Type-Options", "nosniff");
				context.sendReplyHeadersFProxy(206, "Partial content", retHdr, mimeType, tmpRange.size());
				context.writeData(tmpRange);
			} else {
                retHdr.put("X-Content-Type-Options", "nosniff");
                if (container.enableCachingForChkAndSskKeys() && (key.isCHK() || key.isSSK())) {
                    context.sendReplyHeadersStatic(200, "OK", retHdr, mimeType, size, new Date());
                } else {
                    context.sendReplyHeadersFProxy(200, "OK", retHdr, mimeType, size);
                }
				context.writeData(data);
			}
		}
	}

	static final HTMLNode DOWNLOADS_LINK = QueueToadlet.DOWNLOADS_LINK;

	private static void addDownloadOptions(ToadletContext ctx, HTMLNode optionList, FreenetURI key, String mimeType,
	        boolean disableFiltration, boolean dontShowFilter, NodeClientCore core) {
		PHYSICAL_THREAT_LEVEL threatLevel = core.node.securityLevels.getPhysicalThreatLevel();
		NETWORK_THREAT_LEVEL netLevel = core.node.securityLevels.getNetworkThreatLevel();
		boolean filterChecked = !(((threatLevel == PHYSICAL_THREAT_LEVEL.LOW &&
		        netLevel == NETWORK_THREAT_LEVEL.LOW)) || disableFiltration);
		if((filterChecked) && mimeType != null && !mimeType.equals("application/octet-stream") &&
			!mimeType.equals("")) {
			FilterMIMEType type = ContentFilter.getMIMEType(mimeType);
			if((type == null || (!(type.safeToRead || type.readFilter != null))) &&
				        !(threatLevel == PHYSICAL_THREAT_LEVEL.HIGH ||
				        threatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM ||
				        netLevel == NETWORK_THREAT_LEVEL.HIGH ||
				        netLevel == NETWORK_THREAT_LEVEL.MAXIMUM))
				filterChecked = false;
		}
		//Display FProxy option to download to disk if the user isn't at maximum physical threat level
		//and hasn't disabled downloading to disk.
		if (threatLevel != PHYSICAL_THREAT_LEVEL.MAXIMUM && !core.isDownloadDisabled()) {
			HTMLNode option = optionList.addChild("li");
			HTMLNode optionForm = ctx.addFormChild(option, "/downloads/", "tooBigQueueForm");
			optionForm.addChild("input",
			        new String[] { "type", "name", "value" },
			        new String[] { "hidden", "key", key.toString() });
			optionForm.addChild("input",
			        new String[] { "type", "name", "value" },
			        new String[] { "hidden", "return-type", "disk" });
			optionForm.addChild("input",
			        new String[] { "type", "name", "value" },
			        new String[] { "hidden", "persistence", "forever" });
			if (mimeType != null && !mimeType.equals("")) {
				optionForm.addChild("input",
				        new String[] { "type", "name", "value" },
				        new String[] { "hidden", "type", mimeType });
			}
			optionForm.addChild("input", new String[] { "type", "name", "value" },
			        new String[] { "submit", "download", l10n("downloadInBackgroundToDiskButton") });
			String downloadLocation = core.getDownloadsDir().getAbsolutePath();
			//If the download directory isn't allowed, yet downloading is, at least one directory must
			//have been explicitly defined, so take the first one.
			if (!core.allowDownloadTo(core.getDownloadsDir())) {
				downloadLocation = core.getAllowedDownloadDirs()[0].getAbsolutePath();
			}
			NodeL10n.getBase().addL10nSubstitution(optionForm, "FProxyToadlet.downloadInBackgroundToDisk",
			        new String[] { "dir", "page" },
			        new HTMLNode[] { new HTMLNode("input",
			                new String[] { "type", "name", "value", "maxlength", "size" },
			                new String[] { "text", "path", downloadLocation,
			                        Integer.toString(QueueToadlet.MAX_FILENAME_LENGTH),
			                        String.valueOf(downloadLocation.length())}),
			                DOWNLOADS_LINK });
			optionForm.addChild("#", " ");
			NodeL10n.getBase().addL10nSubstitution(optionForm,
			        "FProxyToadlet.downloadToDiskWarningNotFiltered",
			        new String[] {"bold" }, new HTMLNode[] { HTMLNode.STRONG });
			optionForm.addChild("input",
			        new String[] { "type", "name", "value" },
			        new String[] { "submit", "select-location",
				        NodeL10n.getBase().getString("QueueToadlet.browseToChange")+"..."} );
			if(!dontShowFilter) {
				HTMLNode filterControl = optionForm.addChild("div", l10n("filterData"));
				HTMLNode f = filterControl.addChild("input",
				        new String[] { "type", "name", "value" },
				        new String[] { "checkbox", "filterData", "filterData"});
				if(filterChecked) f.addAttribute("checked", "checked");
				filterControl.addChild("div", l10n("filterDataMessage"));
			}
			if (threatLevel == PHYSICAL_THREAT_LEVEL.HIGH) {
				optionForm.addChild("br");
				NodeL10n.getBase().addL10nSubstitution(optionForm,
				        "FProxyToadlet.downloadToDiskSecurityWarning",
				        new String[] {"bold" }, new HTMLNode[] { HTMLNode.STRONG });
				//optionForm.addChild("#", l10n("downloadToDiskSecurityWarning") + " ");
			}
		}

		//Display fetch option if not at low physical security or the user has disabled downloading to disk.
		if (threatLevel != PHYSICAL_THREAT_LEVEL.LOW || core.isDownloadDisabled()) {
			HTMLNode option = optionList.addChild("li");
			HTMLNode optionForm = ctx.addFormChild(option, "/downloads/", "tooBigQueueForm");
			optionForm.addChild("input",
			        new String[] { "type", "name", "value" },
			        new String[] { "hidden", "key", key.toString() });
			optionForm.addChild("input",
			        new String[] { "type", "name", "value" },
			        new String[] { "hidden", "return-type", "direct" });
			optionForm.addChild("input",
			        new String[] { "type", "name", "value" },
			        new String[] { "hidden", "persistence", "forever" });
			if (mimeType != null && !mimeType.equals("")) {
				optionForm.addChild("input",
				        new String[] { "type", "name", "value" },
				        new String[] { "hidden", "type", mimeType });
			}
			optionForm.addChild("input", new String[] { "type", "name", "value" },
			        new String[] { "submit", "download", l10n("downloadInBackgroundToTempSpaceButton") });
			NodeL10n.getBase().addL10nSubstitution(optionForm,
			        "FProxyToadlet.downloadInBackgroundToTempSpace",
			        new String[] { "page", "bold" }, new HTMLNode[] { DOWNLOADS_LINK, HTMLNode.STRONG });
			if(!dontShowFilter) {
				HTMLNode filterControl = optionForm.addChild("div", l10n("filterData"));
				HTMLNode f = filterControl.addChild("input",
						new String[] { "type", "name", "value" },
						new String[] { "checkbox", "filterData", "filterData"});
				if(filterChecked) f.addAttribute("checked", "checked");
				filterControl.addChild("div", l10n("filterDataMessage"));
			}
		}
	}

	public static String l10n(String msg) {
		return NodeL10n.getBase().getString("FProxyToadlet."+msg);
	}

	/** Does the first 512 bytes of the data contain anything that Firefox might regard as RSS?
	 * This is a horrible evil hack; we shouldn't be doing blacklisting, we should be doing whitelisting.
	 * REDFLAG Expect future security issues!
	 * @throws IOException */
	private static boolean isSniffedAsFeed(Bucket data) throws IOException {
		DataInputStream is = null;
		try {
			int sz = (int) Math.min(data.size(), 512);
			if(sz == 0)
				return false;
			is = new DataInputStream(data.getInputStream());
			byte[] buf = new byte[sz];
			// FIXME Fortunately firefox doesn't detect RSS in UTF16 etc ... yet
			is.readFully(buf);
			return RssSniffer.isSniffedAsFeed(buf);
		}
		finally {
			Closer.close(is);
		}
	}

	public void handleMethodGET(URI uri, HTTPRequest httprequest, ToadletContext ctx)
	throws ToadletContextClosedException, IOException, RedirectException {
		innerHandleMethodGET(uri, httprequest, ctx, 0);
	}

	static final int MAX_RECURSION = 5;

	private void innerHandleMethodGET(URI uri, HTTPRequest httprequest, ToadletContext ctx, int recursion)
			throws ToadletContextClosedException, IOException, RedirectException {

		String ks = uri.getPath();

		MultiValueTable<String,String> headers = ctx.getHeaders();
		final String ua = headers.get("user-agent");
		final String accept = headers.get("accept");
		if(logMINOR) Logger.minor(this, "UA = "+ua+" accept = "+accept);
		final boolean canSendProgress =
			isBrowser(ua) && !ctx.disableProgressPage() && (accept == null || accept.indexOf("text/html") > -1) && !httprequest.isParameterSet("forcedownload");

		long defaultMaxSize = canSendProgress ? MAX_LENGTH_WITH_PROGRESS : MAX_LENGTH_NO_PROGRESS;

		// max-retries
		// Less than -1 = use default.
		// 0 = one try only, don't retry
		// 1 = two tries
		// 2 = three tries
		// 3 or more = GO INTO COOLDOWN EVERY 3 TRIES! TAKES *MUCH* LONGER!!! STRONGLY NOT RECOMMENDED!!!
		int maxRetries = httprequest.getIntParam("max-retries", -2);

		long maxSize;
		long maxSizeDownload;

		boolean restricted = (container.publicGatewayMode() && !ctx.isAllowedFullAccess());

		boolean overrideSize = false;
		maxSize = defaultMaxSize;
		maxSizeDownload = MAX_LENGTH_WITH_PROGRESS;
		if(!restricted) {
			if(httprequest.isParameterSet("max-size")) {
				maxSize = maxSizeDownload = httprequest.getLongParam("max-size", defaultMaxSize);
				overrideSize = true;
			}
		}

		if (ks.equals("/")) {
			if (httprequest.isParameterSet("key")) {
				String k = httprequest.getParam("key");
				FreenetURI newURI;
				try {
					newURI = new FreenetURI(k);
				} catch (MalformedURLException e) {
					Logger.normal(this, "Invalid key: "+e+" for "+k, e);
					sendErrorPage(ctx, 404, l10n("notFoundTitle"), NodeL10n.getBase().getString("FProxyToadlet.invalidKeyWithReason", new String[] { "reason" }, new String[] { e.toString() }));
					return;
				}

				if(logMINOR) Logger.minor(this, "Redirecting to FreenetURI: "+newURI);
				String requestedMimeType = httprequest.getParam("type");
				String location = getLink(newURI, requestedMimeType, maxSize, httprequest.getParam("force", null), httprequest.isParameterSet("forcedownload"), maxRetries, overrideSize);
				writeTemporaryRedirect(ctx, null, location);
				return;
			}

			/*
			 * Redirect to the welcome page because no key was specified.
			 */
			try {
				throw new RedirectException(new URI(null, null, null, -1, welcome.getPath(), uri.getQuery(), uri.getFragment()));
			} catch (URISyntaxException e) {
				/*
				 * This shouldn't happen because all the inputs to the URI constructor come from getters
				 * of existing URIs.
				 */
				Logger.error(FProxyToadlet.class, "Unexpected syntax error in URI: " + e);
				writeTemporaryRedirect(ctx, "Internal error. Please check logs and report.", WelcomeToadlet.PATH);
				return;
			}
		}else if(ks.equals("/favicon.ico")){
		    try {
                throw new RedirectException(StaticToadlet.ROOT_URL+"favicon.ico");
            } catch (URISyntaxException e) {
                throw new Error(e);
            }
		} else if(ks.startsWith("/feed/") || ks.equals("/feed")) {
			String schemeHostAndPort = getSchemeHostAndPort(ctx);
			String atom = ctx.getAlertManager().getAtom(schemeHostAndPort);
			byte[] buf = atom.getBytes("UTF-8");
			ctx.sendReplyHeadersFProxy(200, "OK", null, "application/atom+xml", buf.length);
			ctx.writeData(buf, 0, buf.length);
			return;
		}else if(ks.equals("/robots.txt") && ctx.doRobots()){
			this.writeTextReply(ctx, 200, "Ok", "User-agent: *\nDisallow: /");
			return;
		}else if(ks.startsWith("/darknet/") || ks.equals("/darknet")) { //TODO (pre-build 1045 url format) remove when obsolete
			writePermanentRedirect(ctx, "obsoleted", "/friends/");
			return;
		}else if(ks.startsWith("/opennet/") || ks.equals("/opennet")) { //TODO (pre-build 1045 url format) remove when obsolete
			writePermanentRedirect(ctx, "obsoleted", "/strangers/");
			return;
		} else if(ks.startsWith("/queue/")) {
			writePermanentRedirect(ctx, "obsoleted", "/downloads/");
			return;
		} else if(ks.startsWith("/config/")) {
			writePermanentRedirect(ctx, "obsoleted", "/config/node");
			return;
		}

		if(ks.startsWith("/"))
			ks = ks.substring(1);

		//first check of httprange before get
		// only valid number format is checked here
		String rangeStr = ctx.getHeaders().get("range");
		if (rangeStr != null) {
			try {
				parseRange(rangeStr);
			} catch (HTTPRangeException e) {
				Logger.normal(this, "Invalid Range Header: "+rangeStr, e);
				ctx.sendReplyHeaders(416, "Requested Range Not Satisfiable", null, null, 0);
				return;
			}
		}

		FreenetURI key;
		try {
			key = new FreenetURI(ks);
		} catch (MalformedURLException e) {
			PageNode page = ctx.getPageMaker().getPageNode(l10n("invalidKeyTitle"), ctx);
			HTMLNode pageNode = page.outer;
			HTMLNode contentNode = page.content;

			HTMLNode errorInfobox = contentNode.addChild("div", "class", "infobox infobox-error");
			errorInfobox.addChild("div", "class", "infobox-header", NodeL10n.getBase().getString("FProxyToadlet.invalidKeyWithReason", new String[] { "reason" }, new String[] { e.toString() }));
			HTMLNode errorContent = errorInfobox.addChild("div", "class", "infobox-content");
			errorContent.addChild("#", l10n("expectedKeyButGot"));
			errorContent.addChild("code", ks);
			errorContent.addChild("br");
			errorContent.addChild(ctx.getPageMaker().createBackLink(ctx, l10n("goBack")));
			errorContent.addChild("br");
			addHomepageLink(errorContent);

			this.writeHTMLReply(ctx, 400, l10n("invalidKeyTitle"), pageNode.generate());
			return;
		}

		FetchContext fctx = getFetchContext(maxSize, getSchemeHostAndPort(ctx));
		// max-size=-1 => use default
		maxSize = fctx.maxOutputLength;

		//We should run the ContentFilter by default
		String forceString = httprequest.getParam("force");
		long now = System.currentTimeMillis();
		boolean force = false;
		if(forceString != null) {
			if(forceString.equals(getForceValue(key, now)) ||
					forceString.equals(getForceValue(key, now-FORCE_GRAIN_INTERVAL)))
				force = true;
		}
		if(restricted)
			maxRetries = -2;
		if(maxRetries >= -1) {
			fctx.maxNonSplitfileRetries = maxRetries;
			fctx.maxSplitfileBlockRetries = maxRetries;
		}
		if (!force && !httprequest.isParameterSet("forcedownload")) fctx.filterData = true;
		else if(logMINOR) Logger.minor(this, "Content filter disabled via request parameter");
		//Load the fetch context with the callbacks needed for web-pushing, if enabled
		if(container.enableInlinePrefetch()) {
			fctx.prefetchHook = new FoundURICallback() {

				List<FreenetURI> uris = new ArrayList<FreenetURI>();

				@Override
				public void foundURI(FreenetURI uri) {
					// Ignore
				}

				@Override
				public void foundURI(FreenetURI uri, boolean inline) {
					if(!inline) return;
					if(logMINOR) Logger.minor(this, "Prefetching "+uri);
					synchronized(this) {
						if(uris.size() < MAX_PREFETCH)
							// FIXME Maybe we should do this randomly, but since it's a DoS protection (in an obscure feature), if so we should do it in constant space!
							uris.add(uri);
					}
				}

				@Override
				public void onText(String text, String type, URI baseURI) {
					// Ignore
				}

				@Override
				public void onFinishedPage() {
					core.node.executor.execute(new Runnable() {

						@Override
						public void run() {
							for(FreenetURI uri : uris) {
								client.prefetch(uri, SECONDS.toMillis(60), 512*1024, prefetchAllowedTypes);
							}
						}

					});
				}

			};

		}
		if(container.isFProxyWebPushingEnabled()) fctx.tagReplacer = new PushingTagReplacerCallback(core.getFProxy().fetchTracker, defaultMaxSize, ctx);

		String requestedMimeType = httprequest.getParam("type", null);
		fctx.overrideMIME = requestedMimeType;
		String override = (requestedMimeType == null) ? "" : "?type="+URLEncoder.encode(requestedMimeType,true);
		String maybeCharset = httprequest.isParameterSet("maybecharset") ? httprequest.getParam("maybecharset", null) : null;
		fctx.charset = maybeCharset;
		if(override.equals("") && maybeCharset != null)
			override = "?maybecharset="+URLEncoder.encode(maybeCharset, true);
		// No point passing ?force= across a redirect, since the key will change.
		// However, there is every point in passing ?forcedownload.
		if(httprequest.isParameterSet("forcedownload")) {
			if(override.length() == 0) override = "?forcedownload";
			else override = override+"&forcedownload";
		}

		Bucket data = null;
		String mimeType = null;
		String referer = sanitizeReferer(ctx);
		FetchException fe = null;


		FProxyFetchResult fr = null;

			FProxyFetchWaiter fetch = null;
			try {
				fetch = fetchTracker.makeFetcher(key, maxSize, fctx, ctx.getReFilterPolicy());
			} catch (FetchException e) {
            fe = e;
			}
			if(fetch != null)
			while(true) {
			fr = fetch.getResult(!canSendProgress);
			if(fr.hasData()) {

				if(fr.getFetchCount() > 1 && !fr.hasWaited() && fr.getFetchCount() > 1 && key.isUSK() && context.uskManager.lookupKnownGood(USK.create(key)) > key.getSuggestedEdition()) {
					Logger.normal(this, "Loading later edition...");
					fetch.progress.requestImmediateCancel();
					fr = null;
					fetch = null;
					try {
						fetch = fetchTracker.makeFetcher(key, maxSize, fctx, ctx.getReFilterPolicy());
					} catch (FetchException e) {
                            fe = e;
					}
					if(fetch == null) break;
					continue;
				}

				if(logMINOR) Logger.minor(this, "Found data");
				data = new NoFreeBucket(fr.data);
				mimeType = fr.mimeType;
				fetch.close(); // Not waiting any more, but still locked the results until sent
				break;
			} else if(fr.failed != null) {
				if(logMINOR) Logger.minor(this, "Request failed");
				fe = fr.failed;
				fetch.close(); // Not waiting any more, but still locked the results until sent
				break;
			} else if(canSendProgress) {
				if(logMINOR) Logger.minor(this, "Still in progress");
				// Still in progress
				boolean isJsEnabled=ctx.getContainer().isFProxyJavascriptEnabled() && ua != null && !ua.contains("AppleWebKit/");
				boolean isWebPushingEnabled = false;
				PageNode page = ctx.getPageMaker().getPageNode(l10n("fetchingPageTitle"), ctx);
				HTMLNode pageNode = page.outer;
				String location = getLink(key, requestedMimeType, maxSize, httprequest.getParam("force", null), httprequest.isParameterSet("forcedownload"), maxRetries, overrideSize);
				HTMLNode headNode=page.headNode;
				if(isJsEnabled){
					//If the user has enabled javascript, we add a <noscript> http refresh(if he has disabled it in the browser)
					headNode.addChild("noscript").addChild("meta", "http-equiv", "Refresh").addAttribute("content", "2;URL=" + location);
						// If pushing is disabled, but js is enabled, then we add the original progresspage.js
						if ((isWebPushingEnabled = ctx.getContainer().isFProxyWebPushingEnabled()) == false) {
							HTMLNode scriptNode = headNode.addChild("script", "//abc");
							scriptNode.addAttribute("type", "text/javascript");
							scriptNode.addAttribute("src", "/static/js/progresspage.js");
						}
				}else{
					//If he disabled it, we just put the http refresh meta, without the noscript
					headNode.addChild("meta", "http-equiv", "Refresh").addAttribute("content", "2;URL=" + location);
				}
				HTMLNode contentNode = page.content;
				HTMLNode infobox = contentNode.addChild("div", "class", "infobox infobox-information");
				infobox.addChild("div", "class", "infobox-header", l10n("fetchingPageBox"));
				HTMLNode infoboxContent = infobox.addChild("div", "class", "infobox-content");
				infoboxContent.addAttribute("id", "infoContent");
				infoboxContent.addChild(new ProgressInfoElement(fetchTracker, key, fctx, maxSize, ctx.isAdvancedModeEnabled(), ctx, isWebPushingEnabled));


				HTMLNode table = infoboxContent.addChild("table", "border", "0");
				HTMLNode progressCell = table.addChild("tr").addChild("td", "class", "request-progress");
				if(fr.totalBlocks <= 0)
					progressCell.addChild("#", NodeL10n.getBase().getString("QueueToadlet.unknown"));
				else {
					progressCell.addChild(new ProgressBarElement(fetchTracker,key,fctx,maxSize,ctx, isWebPushingEnabled));
				}

				infobox = contentNode.addChild("div", "class", "infobox infobox-information");
				infobox.addChild("div", "class", "infobox-header", l10n("fetchingPageOptions"));
				infoboxContent = infobox.addChild("div", "class", "infobox-content");

				HTMLNode optionList = infoboxContent.addChild("ul");
				optionList.addChild("li").addChild("p", l10n("progressOptionZero"));

				addDownloadOptions(ctx, optionList, key, mimeType, false, false, core);

				optionList.addChild("li").addChild(ctx.getPageMaker().createBackLink(ctx, l10n("goBackToPrev")));
				optionList.addChild("li").addChild("a", new String[] { "href", "title" },
						new String[] { "/", NodeL10n.getBase().getString("Toadlet.homepage") }, l10n("abortToHomepage"));

				MultiValueTable<String, String> retHeaders = new MultiValueTable<String, String>();
				//retHeaders.put("Refresh", "2; url="+location);
				writeHTMLReply(ctx, 200, "OK", retHeaders, pageNode.generate());
				fr.close();
				fetch.close();
				return;
			} else if(fr != null)
				fr.close();
			}

		try {
			if(logMINOR)
				Logger.minor(this, "FProxy fetching "+key+" ("+maxSize+ ')');
			if(data == null && fe == null) {
				boolean needsFetch=true;
				//If we don't have the data, then check if an FProxyFetchInProgress has. It can happen when one FetchInProgress downloaded an image
				//asynchronously, then loads it. This way a FetchInprogress will have the full image, and no need to block.
				FProxyFetchInProgress progress=fetchTracker.getFetchInProgress(key, maxSize, fctx);
				if(progress!=null){
					FProxyFetchWaiter waiter=null;
					FProxyFetchResult result=null;
					try{
						waiter=progress.getWaiter();
						result=waiter.getResult(false);
						if(result.failed==null && result.data!=null){
							mimeType=result.mimeType;
							data=result.data;
							data=ctx.getBucketFactory().makeBucket(result.data.size());
							BucketTools.copy(result.data, data);
							needsFetch=false;
						}
					}finally{
						if(waiter!=null){
							progress.close(waiter);
						}
						if(result!=null){
							progress.close(result);
						}
					}
				}
				if(needsFetch){
					//If we don't have the data, then we need to fetch it and block until it is available
					FetchResult result = fetch(key, maxSize, new RequestClientBuilder().realTime().build(), fctx);

					// Now, is it safe?

					data = result.asBucket();
					mimeType = result.getMimeType();
				}
			} else if(fe != null) throw fe;

			handleDownload(ctx, data, ctx.getBucketFactory(), mimeType, requestedMimeType, forceString, httprequest.isParameterSet("forcedownload"), "/", key, "&max-size="+maxSizeDownload, referer, true, ctx, core, fr != null, maybeCharset);
		} catch (FetchException e) {
			//Handle exceptions thrown from the ContentFilter
			String msg = e.getMessage();
			if(logMINOR) {
				Logger.minor(this, "Failed to fetch "+uri+" : "+e);
			}
			if(e.newURI != null) {
				if(accept != null && (accept.startsWith("text/css") || accept.startsWith("image/")) && recursion++ < MAX_RECURSION) {
					// If it's an image or a CSS fetch, auto-follow the redirect, up to a limit.
					String link = getLink(e.newURI, requestedMimeType, maxSize, httprequest.getParam("force", null), httprequest.isParameterSet("forcedownload"), maxRetries, overrideSize);
					try {
						uri = new URI(link);
						innerHandleMethodGET(uri, httprequest, ctx, recursion);
						return;
					} catch (URISyntaxException e1) {
						Logger.error(this, "Caught "+e1+" parsing new link "+link, e1);
					}
				}
				Toadlet.writePermanentRedirect(ctx, msg,
					getLink(e.newURI, requestedMimeType, maxSize, httprequest.getParam("force", null), httprequest.isParameterSet("forcedownload"), maxRetries, overrideSize));
			} else if(e.mode == FetchExceptionMode.TOO_BIG) {
				PageNode page = ctx.getPageMaker().getPageNode(l10n("fileInformationTitle"), ctx);
				HTMLNode pageNode = page.outer;
				HTMLNode contentNode = page.content;

				HTMLNode infobox = contentNode.addChild("div", "class", "infobox infobox-information");
				infobox.addChild("div", "class", "infobox-header", l10n("largeFile"));
				HTMLNode infoboxContent = infobox.addChild("div", "class", "infobox-content");
				HTMLNode fileInformationList = infoboxContent.addChild("ul");
				HTMLNode option = fileInformationList.addChild("li");
				option.addChild("#", (l10n("filenameLabel") + ' '));
				option.addChild("a", "href", '/' + key.toString(), getFilename(key, e.getExpectedMimeType()));

				String mime = writeSizeAndMIME(fileInformationList, e);

				infobox = contentNode.addChild("div", "class", "infobox infobox-information");
				infobox.addChild("div", "class", "infobox-header", l10n("explanationTitle"));
				infoboxContent = infobox.addChild("div", "class", "infobox-content");
				infoboxContent.addChild("#", l10n("largeFileExplanationAndOptions"));
				HTMLNode optionList = infoboxContent.addChild("ul");
				//HTMLNode optionTable = infoboxContent.addChild("table", "border", "0");
				if(!restricted) {
					option = optionList.addChild("li");
					HTMLNode optionForm = option.addChild("form", new String[] { "action", "method" }, new String[] {'/' + key.toString(), "get" });
					optionForm.addChild("input", new String[] { "type", "name", "value" }, new String[] { "hidden", "max-size", String.valueOf(e.expectedSize == -1 ? Long.MAX_VALUE : e.expectedSize*2) });
					if (requestedMimeType != null)
						optionForm.addChild("input", new String[] { "type", "name", "value" }, new String[] { "hidden", "type", requestedMimeType });
					if(maxRetries >= -1)
						optionForm.addChild("input", new String[] { "type", "name", "value" }, new String[] { "hidden", "max-retries", Integer.toString(maxRetries) });
					optionForm.addChild("input", new String[] { "type", "name", "value" }, new String[] { "submit", "fetch", l10n("fetchLargeFileAnywayAndDisplayButton") });
					optionForm.addChild("#", " - " + l10n("fetchLargeFileAnywayAndDisplay"));
					addDownloadOptions(ctx, optionList, key, mime, false, false, core);
				}


				//optionTable.addChild("tr").addChild("td", "colspan", "2").addChild("a", new String[] { "href", "title" }, new String[] { "/", NodeL10n.getBase().getString("Toadlet.homepage") }, l10n("abortToHomepage"));
				optionList.addChild("li").addChild("a", new String[] { "href", "title" }, new String[] { "/", NodeL10n.getBase().getString("Toadlet.homepage") }, l10n("abortToHomepage"));

				//option = optionTable.addChild("tr").addChild("td", "colspan", "2");
				optionList.addChild("li").addChild(ctx.getPageMaker().createBackLink(ctx, l10n("goBackToPrev")));

				writeHTMLReply(ctx, 200, "OK", pageNode.generate());
			} else {
				PageNode page = ctx.getPageMaker().getPageNode(e.getShortMessage(), ctx);
				HTMLNode pageNode = page.outer;
				HTMLNode contentNode = page.content;

				HTMLNode infobox = contentNode.addChild("div", "class", "infobox infobox-error");
				infobox.addChild("div", "class", "infobox-header", l10n("errorWithReason", "error", e.getShortMessage()));
				HTMLNode infoboxContent = infobox.addChild("div", "class", "infobox-content");
				HTMLNode fileInformationList = infoboxContent.addChild("ul");
				HTMLNode option = fileInformationList.addChild("li");
				option.addChild("#", (l10n("filenameLabel") + ' '));
				option.addChild("a", "href", '/' + key.toString(), getFilename(key, e.getExpectedMimeType()));

				String mime = writeSizeAndMIME(fileInformationList, e);
				infobox = contentNode.addChild("div", "class", "infobox infobox-error");
				infobox.addChild("div", "class", "infobox-header", l10n("explanationTitle"));
				UnsafeContentTypeException filterException = null;
				if(e.getCause() != null && e.getCause() instanceof UnsafeContentTypeException) {
					filterException = (UnsafeContentTypeException)e.getCause();
				}
				infoboxContent = infobox.addChild("div", "class", "infobox-content");
				if(filterException == null)
					infoboxContent.addChild("p", l10n("unableToRetrieve"));
				else
					infoboxContent.addChild("p", l10n("unableToSafelyDisplay"));
				if(e.isFatal() && filterException == null)
					infoboxContent.addChild("p", l10n("errorIsFatal"));
				infoboxContent.addChild("p", msg);
				if(filterException != null) {
					if(filterException.details() != null) {
						HTMLNode detailList = infoboxContent.addChild("ul");
						for(String detail : filterException.details()) {
							detailList.addChild("li", detail);
						}
					}
				}
				if(e.errorCodes != null) {
					infoboxContent.addChild("p").addChild("pre").addChild("#", e.errorCodes.toVerboseString());
				}

				infobox = contentNode.addChild("div", "class", "infobox infobox-error");
				infobox.addChild("div", "class", "infobox-header", l10n("options"));
				infoboxContent = infobox.addChild("div", "class", "infobox-content");

				HTMLNode optionList = infoboxContent.addChild("ul");

				PluginInfoWrapper keyUtil;
				if((e.mode == FetchExceptionMode.NOT_IN_ARCHIVE || e.mode == FetchExceptionMode.NOT_ENOUGH_PATH_COMPONENTS)) {
					// first look for the newest version
					if ((keyUtil = core.node.pluginManager.getPluginInfo("plugins.KeyUtils.KeyUtilsPlugin")) != null) {
						option = optionList.addChild("li");
						if (keyUtil.getPluginLongVersion() < 5010)
							NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.openWithKeyExplorer", new String[] { "link" }, new HTMLNode[] { HTMLNode.link("/KeyUtils/?automf=true&key=" + key.toString()) });
						else {
							NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.openWithKeyExplorer", new String[] { "link" }, new HTMLNode[] { HTMLNode.link("/KeyUtils/?key=" + key.toString()) });
							option = optionList.addChild("li");
							NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.openWithSiteExplorer", new String[] { "link" }, new HTMLNode[] { HTMLNode.link("/KeyUtils/Site?key=" + key.toString()) });
						}
					} else if ((keyUtil = core.node.pluginManager.getPluginInfo("plugins.KeyExplorer.KeyExplorer")) != null) {
						option = optionList.addChild("li");
						if (keyUtil.getPluginLongVersion() > 4999)
							NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.openWithKeyExplorer", new String[] { "link" }, new HTMLNode[] { HTMLNode.link("/KeyExplorer/?automf=true&key=" + key.toString())});
						else
							NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.openWithKeyExplorer", new String[] { "link" }, new HTMLNode[] { HTMLNode.link("/plugins/plugins.KeyExplorer.KeyExplorer/?key=" + key.toString())});
					}
				}
				if(filterException != null) {
					if((mime.equals("application/x-freenet-index")) && (core.node.pluginManager.isPluginLoaded("plugins.ThawIndexBrowser.ThawIndexBrowser"))) {
						option = optionList.addChild("li");
						NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.openAsThawIndex", new String[] { "link" }, new HTMLNode[] { HTMLNode.link("/plugins/plugins.ThawIndexBrowser.ThawIndexBrowser/?key=" + key.toString())});
					}
					option = optionList.addChild("li");
					// FIXME: is this safe? See bug #131
					MediaType textMediaType = new MediaType("text/plain");
					textMediaType.setParameter("charset", (e.getExpectedMimeType() != null) ? MediaType.getCharsetRobust(e.getExpectedMimeType()) : null);
					NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.openAsText", new String[] { "link" }, new HTMLNode[] { HTMLNode.link(getLink(key, textMediaType.toString(), maxSize, null, false, maxRetries, overrideSize)) });
					option = optionList.addChild("li");
					NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.openForceDisk", new String[] { "link" }, new HTMLNode[] { HTMLNode.link(getLink(key, mime, maxSize, null, true, maxRetries, overrideSize)) });
					if(!(mime.equals("application/octet-stream") || mime.equals("application/x-msdownload") || !DefaultMIMETypes.isPlausibleMIMEType(mime))) {
						option = optionList.addChild("li");
						NodeL10n.getBase().addL10nSubstitution(option, "FProxyToadlet.openForce", new String[] { "link", "mime" }, new HTMLNode[] { HTMLNode.link(getLink(key, mime, maxSize, getForceValue(key, now), false, maxRetries, overrideSize)), HTMLNode.text(HTMLEncoder.encode(mime))});
					}
				}

				if((!e.isFatal() || filterException != null) && (ctx.isAllowedFullAccess() || !container.publicGatewayMode())) {
					addDownloadOptions(ctx, optionList, key, mimeType, filterException != null, filterException != null, core);
					if(filterException == null)
						optionList.addChild("li").
							addChild("a", "href", getLink(key, requestedMimeType, maxSize, httprequest.getParam("force", null),
									httprequest.isParameterSet("forcedownload"), maxRetries, overrideSize)).addChild("#", l10n("retryNow"));
				}

				optionList.addChild("li").addChild("a", new String[] { "href", "title" }, new String[] { "/", NodeL10n.getBase().
						getString("Toadlet.homepage") }, l10n("abortToHomepage"));

				optionList.addChild("li").addChild(ctx.getPageMaker().createBackLink(ctx, l10n("goBackToPrev")));
				this.writeHTMLReply(ctx, (e.mode == FetchExceptionMode.NOT_IN_ARCHIVE) ? 404 : 500 /* close enough - FIXME probably should depend on status code */,
						"Internal Error", pageNode.generate());
			}
		} catch (SocketException e) {
			// Probably irrelevant
			if(e.getMessage().equals("Broken pipe")) {
				if(logMINOR)
					Logger.minor(this, "Caught "+e+" while handling GET", e);
			} else {
				Logger.normal(this, "Caught "+e);
			}
			throw e;
		} catch (Throwable t) {
			writeInternalError(t, ctx);
		} finally {
			if(fr == null && data != null) data.free();
			if(fr != null) fr.close();
		}
	}

	private String getSchemeHostAndPort(ToadletContext ctx) {
		MultiValueTable<String, String> headers = ctx.getHeaders();
		Map<String, String> forwarded = parseForwardedHeader(headers.get("Forwarded"));
		String uriScheme = ctx.getUri().getScheme();
		String uriHost = ctx.getUri().getHost();
		String protocol = forwarded.getOrDefault("proto",
				headers.containsKey("X-Forwarded-Proto")
						? headers.get("X-Forwarded-Proto")
				    : uriScheme != null && !uriScheme.trim().isEmpty() ? uriScheme : "http");
		String host = forwarded.getOrDefault("host",
				headers.containsKey("X-Forwarded-Host")
						? headers.get("X-Forwarded-Host")
				    : uriHost != null && !uriHost.trim().isEmpty() ? uriHost : headers.get("host"));
		return protocol + "://" + host;
	}

	private Map<String, String> parseForwardedHeader(String forwarded) {
		if (forwarded == null || forwarded.trim().isEmpty()) {
			return new HashMap<>();
		}
		Map<String, String> headerParams = new HashMap<>();

		// if a multi-value header is given, only use the first value.
		int indexOfComma = forwarded.indexOf(',');
		if (indexOfComma != -1) {
			forwarded = forwarded.substring(0, indexOfComma);
		}
		boolean hasAtLeastOneKey = forwarded.indexOf('=') != -1;
		boolean hasMultipleKeys = forwarded.indexOf(';') != -1;
		String[] fields;
		if (hasMultipleKeys) {
			fields = forwarded.split(";");
		} else if (hasAtLeastOneKey) {
			fields = new String[]{ forwarded };
		} else {
			return headerParams;
		}
		for (String field : fields) {
			if (field.indexOf('=') != 1) {
				String[] keyAndValue = field.split("=");
				headerParams.put(keyAndValue[0], keyAndValue[1]);
			}
		}
		return headerParams;
	}

	private boolean isBrowser(String ua) {
		if(ua == null) return false;
		return (ua.contains("Mozilla/") || ua.contains("Opera/"));
	}

	private static String writeSizeAndMIME(HTMLNode fileInformationList, FetchException e) {
		boolean finalized = e.finalizedSize();
		long size = e.expectedSize;
		String mime = e.getExpectedMimeType();
		writeSizeAndMIME(fileInformationList, size, mime, finalized);
		return mime;
	}

	private static void writeSizeAndMIME(HTMLNode fileInformationList, long size, String mime, boolean finalized) {
		if(size > 0) {
			if (finalized) {
				fileInformationList.addChild("li", (l10n("sizeLabel") + ' ') + SizeUtil.formatSize(size));
			} else {
				fileInformationList.addChild("li", (l10n("sizeLabel") + ' ')+ SizeUtil.formatSize(size) + l10n("mayChange"));
			}
		} else {
			fileInformationList.addChild("li", l10n("sizeUnknown"));
		}
		if(mime != null) {
			fileInformationList.addChild("li", NodeL10n.getBase().getString("FProxyToadlet."+(finalized ? "mimeType" : "expectedMimeType"), new String[] { "mime" }, new String[] { mime }));
		} else {
			fileInformationList.addChild("li", l10n("unknownMIMEType"));
		}
	}

	private String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("FProxyToadlet."+key, new String[] { pattern }, new String[] { value });
	}

	public static String l10n(String key, String[] pattern, String[] value) {
		return NodeL10n.getBase().getString("FProxyToadlet."+key, pattern, value);
	}

	private String getLink(FreenetURI uri, String requestedMimeType, long maxSize, String force,
			boolean forceDownload, int maxRetries, boolean appendMaxSize) {
		StringBuilder sb = new StringBuilder();
		sb.append("/");
		sb.append(uri.toASCIIString());
		char c = '?';
		if(requestedMimeType != null && requestedMimeType.length() != 0) {
			sb.append(c).append("type=").append(URLEncoder.encode(requestedMimeType,false)); c = '&';
		}
		if(maxSize > 0 && appendMaxSize) {
			sb.append(c).append("max-size=").append(maxSize); c = '&';
		}
		if(force != null) {
			sb.append(c).append("force=").append(force); c = '&';
		}
		if(forceDownload) {
			sb.append(c).append("forcedownload=true"); c = '&';
		}
		if(maxRetries >= -1) {
			sb.append(c).append("max-retries=").append(maxRetries); c = '&';
		}
		return sb.toString();
	}

	private String sanitizeReferer(ToadletContext ctx) {
		// FIXME we do something similar in the GenericFilterCallback thingy?
		String referer = ctx.getHeaders().get("referer");
		if(referer != null) {
			try {
				URI refererURI = new URI(URIPreEncoder.encode(referer));
				String path = refererURI.getPath();
				while(path.startsWith("/")) path = path.substring(1);
				if("".equals(path)) return "/";
				FreenetURI furi = new FreenetURI(path);
				HTTPRequest req = new HTTPRequestImpl(refererURI, "GET");
				String type = req.getParam("type");
				referer = "/" + furi.toString();
				if(type != null && type.length() > 0)
					referer += "?type=" + type;
			} catch (MalformedURLException e) {
				referer = "/";
				Logger.normal(this, "Caught MalformedURLException on the referer : "+e.getMessage());
			} catch (Throwable t) {
				Logger.error(this, "Caught handling referrer: "+t+" for "+referer, t);
				referer = null;
			}
		}
		return referer;
	}

	private static String getForceValue(FreenetURI key, long time) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		try{
			bos.write(random);
			bos.write(key.toString().getBytes("UTF-8"));
			bos.write(Long.toString(time / FORCE_GRAIN_INTERVAL).getBytes("UTF-8"));
		} catch (IOException e) {
			throw new Error(e);
		}

		String f = HexUtil.bytesToHex(SHA256.digest(bos.toByteArray()));
		return f;
	}

	public static void maybeCreateFProxyEtc(NodeClientCore core, Node node, Config config,
	        SimpleToadletServer server) throws IOException {

		// FIXME how to change these on the fly when the interface language is changed?

		HighLevelSimpleClient client = core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true);

		random = new byte[32];
		core.random.nextBytes(random);

		FProxyFetchTracker fetchTracker = new FProxyFetchTracker(core.clientContext, client.getFetchContext(),
				new RequestClientBuilder().realTime().build());


		FProxyToadlet fproxy = new FProxyToadlet(client, core, fetchTracker);
		core.setFProxy(fproxy);

		server.registerMenu("/",
		        "FProxyToadlet.categoryBrowsing", "FProxyToadlet.categoryTitleBrowsing", null);
		server.registerMenu("/downloads/",
		        "FProxyToadlet.categoryQueue", "FProxyToadlet.categoryTitleQueue", null);
		server.registerMenu("/friends/",
		        "FProxyToadlet.categoryFriends", "FProxyToadlet.categoryTitleFriends", null);
		server.registerMenu("/chat/",
		        "FProxyToadlet.categoryChat", "FProxyToadlet.categoryTitleChat", null);
		server.registerMenu("/alerts/",
		        "FProxyToadlet.categoryStatus", "FProxyToadlet.categoryTitleStatus", null);
		server.registerMenu("/seclevels/",
		        "FProxyToadlet.categoryConfig", "FProxyToadlet.categoryTitleConfig", null);

		server.register(fproxy, "FProxyToadlet.categoryBrowsing", "/", false, "FProxyToadlet.welcomeTitle",
		        "FProxyToadlet.welcome", false, null);

		DecodeToadlet decodeKeywordURL = new DecodeToadlet(client, core);
		server.register(decodeKeywordURL, null, "/decode/", true, false);

		InsertFreesiteToadlet siteinsert = new InsertFreesiteToadlet(client);
		server.register(siteinsert, "FProxyToadlet.categoryBrowsing", "/insertsite/", true,
		        "FProxyToadlet.insertFreesiteTitle", "FProxyToadlet.insertFreesite", false, null);

		UserAlertsToadlet alerts = new UserAlertsToadlet(client);
		server.register(alerts, "FProxyToadlet.categoryStatus", "/alerts/", true, "FProxyToadlet.alertsTitle",
		        "FProxyToadlet.alerts", true, null);

		QueueToadlet downloadToadlet = new QueueToadlet(core, core.getFCPServer(), client, false);
		server.register(downloadToadlet, "FProxyToadlet.categoryQueue", "/downloads/", true,
		        "FProxyToadlet.downloadsTitle", "FProxyToadlet.downloads", false, downloadToadlet);
		LocalDownloadDirectoryToadlet localDownloadDirectoryToadlet =
		        new LocalDownloadDirectoryToadlet(core, client, "/downloads/");
		server.register(localDownloadDirectoryToadlet, null, localDownloadDirectoryToadlet.path(), true, false);
		QueueToadlet uploadToadlet = new QueueToadlet(core, core.getFCPServer(), client, true);
		server.register(uploadToadlet, "FProxyToadlet.categoryQueue", "/uploads/", true,
		         "FProxyToadlet.uploadsTitle", "FProxyToadlet.uploads", false, uploadToadlet);

		FileInsertWizardToadlet fiw = new FileInsertWizardToadlet(client, core);
		server.register(fiw, "FProxyToadlet.categoryQueue", FileInsertWizardToadlet.PATH, true,
		        "FProxyToadlet.uploadFileWizardTitle", "FProxyToadlet.uploadFileWizard", false, fiw);
		uploadToadlet.setFIW(fiw);

		LocalFileInsertToadlet localFileInsertToadlet = new LocalFileInsertToadlet(core, client);
		server.register(localFileInsertToadlet, null, LocalFileInsertToadlet.PATH, true, false);

		ContentFilterToadlet contentFilterToadlet = new ContentFilterToadlet(client, core);
		server.register(contentFilterToadlet, "FProxyToadlet.categoryQueue", ContentFilterToadlet.PATH, true,
		        "FProxyToadlet.filterFileTitle", "FProxyToadlet.filterFile", false, contentFilterToadlet);

		LocalFileFilterToadlet localFileFilterToadlet = new LocalFileFilterToadlet(core, client);
		server.register(localFileFilterToadlet, null, LocalFileFilterToadlet.PATH, true, false);

		SymlinkerToadlet symlinkToadlet = new SymlinkerToadlet(client, node);
		server.register(symlinkToadlet, null, "/sl/", true, false);

		SecurityLevelsToadlet seclevels = new SecurityLevelsToadlet(client, node, core);
		server.register(seclevels, "FProxyToadlet.categoryConfig", "/seclevels/", true,
		        "FProxyToadlet.seclevelsTitle", "FProxyToadlet.seclevels", true, null);

		if(node.pluginManager.isEnabled()) {
		    PproxyToadlet pproxy = new PproxyToadlet(client, node);
		    server.register(pproxy, "FProxyToadlet.categoryConfig", "/plugins/", true, "FProxyToadlet.pluginsTitle",
		            "FProxyToadlet.plugins", true, null);
		}

		SubConfig[] sc = config.getConfigs();
		Arrays.sort(sc);

		for(SubConfig cfg : sc) {
			String prefix = cfg.getPrefix();
			if(prefix.equals("security-levels") || prefix.equals("pluginmanager")) continue;
			LocalDirectoryConfigToadlet localDirectoryConfigToadlet =
			        new LocalDirectoryConfigToadlet(core, client, "/config/"+prefix);
			ConfigToadlet configtoadlet = new ConfigToadlet(localDirectoryConfigToadlet.path(), client,
			        config, cfg, node, core);
			server.register(configtoadlet, "FProxyToadlet.categoryConfig", "/config/"+prefix, true,
			        "ConfigToadlet."+prefix, "ConfigToadlet.title."+prefix, true, configtoadlet);
			server.register(localDirectoryConfigToadlet, null, localDirectoryConfigToadlet.path(), true,
			        false);
		}

		WelcomeToadlet welcometoadlet = new WelcomeToadlet(client, node);
		server.register(welcometoadlet, null, "/welcome/", true, false);

		ExternalLinkToadlet externalLinkToadlet = new ExternalLinkToadlet(client, node);
		server.register(externalLinkToadlet, null, ExternalLinkToadlet.PATH, true, false);

		DarknetConnectionsToadlet friendsToadlet = new DarknetConnectionsToadlet(node, core, client);
		server.register(friendsToadlet, "FProxyToadlet.categoryFriends", "/friends/", true,
		        "FProxyToadlet.friendsTitle", "FProxyToadlet.friends", true, null);

		DarknetAddRefToadlet addRefToadlet = new DarknetAddRefToadlet(node, client, friendsToadlet);
		server.register(addRefToadlet, "FProxyToadlet.categoryFriends", "/addfriend/", true,
		        "FProxyToadlet.addFriendTitle", "FProxyToadlet.addFriend", true, null);

		OpennetConnectionsToadlet opennetToadlet = new OpennetConnectionsToadlet(node, core, client);
		server.register(opennetToadlet, "FProxyToadlet.categoryStatus", "/strangers/", true,
		        "FProxyToadlet.opennetTitle", "FProxyToadlet.opennet", true, opennetToadlet);

		ChatForumsToadlet chatForumsToadlet = new ChatForumsToadlet(client, node.pluginManager);
		server.register(chatForumsToadlet, "FProxyToadlet.categoryChat", "/chat/", true,
		        "FProxyToadlet.chatForumsTitle", "FProxyToadlet.chatForums", true, chatForumsToadlet);

		N2NTMToadlet n2ntmToadlet = new N2NTMToadlet(node, core, client);
		server.register(n2ntmToadlet, null, "/send_n2ntm/", true, true);
		LocalFileN2NMToadlet localFileN2NMToadlet = new LocalFileN2NMToadlet(core, client);
		server.register(localFileN2NMToadlet, null, LocalFileN2NMToadlet.PATH, true, false);

		BookmarkEditorToadlet bookmarkEditorToadlet = new BookmarkEditorToadlet(client, core);
		server.register(bookmarkEditorToadlet, null, "/bookmarkEditor/", true, false);

		BrowserTestToadlet browserTestToadlet = new BrowserTestToadlet(client);
		server.register(browserTestToadlet, null, "/test/", true, false);

		StatisticsToadlet statisticsToadlet = new StatisticsToadlet(node, core, client);
		server.register(statisticsToadlet, "FProxyToadlet.categoryStatus", "/stats/", true,
		        "FProxyToadlet.statsTitle", "FProxyToadlet.stats", true, null);

		DiagnosticToadlet diagnosticToadlet = new DiagnosticToadlet(node, core, core.getFCPServer(), client);
		server.register(diagnosticToadlet, "FProxyToadlet.categoryStatus", "/diagnostic/", true,
		        "FProxyToadlet.diagnosticTitle", "FProxyToadlet.diagnostic", true, null);

		ConnectivityToadlet connectivityToadlet = new ConnectivityToadlet(client, node);
		server.register(connectivityToadlet, "FProxyToadlet.categoryStatus", "/connectivity/", true,
		        "ConnectivityToadlet.connectivityTitle", "ConnectivityToadlet.connectivity", true, null);

		TranslationToadlet translationToadlet = new TranslationToadlet(client, core);
		server.register(translationToadlet, "FProxyToadlet.categoryConfig", TranslationToadlet.TOADLET_URL,
		        true, "TranslationToadlet.title", "TranslationToadlet.titleLong", true, null);

		FirstTimeWizardToadlet firstTimeWizardToadlet = new FirstTimeWizardToadlet(client, node, core);
		server.register(firstTimeWizardToadlet, null, FirstTimeWizardToadlet.TOADLET_URL, true, false);

		SimpleHelpToadlet simpleHelpToadlet = new SimpleHelpToadlet(client, core);
		server.register(simpleHelpToadlet, null, "/help/", true, false);

		PushDataToadlet pushDataToadlet = new PushDataToadlet(client);
		server.register(pushDataToadlet, null, pushDataToadlet.path(), true, false);

		PushNotificationToadlet pushNotificationToadlet = new PushNotificationToadlet(client);
		server.register(pushNotificationToadlet, null, pushNotificationToadlet.path(), true, false);

		PushKeepaliveToadlet pushKeepaliveToadlet = new PushKeepaliveToadlet(client);
		server.register(pushKeepaliveToadlet, null, pushKeepaliveToadlet.path(), true, false);

		PushFailoverToadlet pushFailoverToadlet = new PushFailoverToadlet(client);
		server.register(pushFailoverToadlet, null, pushFailoverToadlet.path(), true, false);

		PushTesterToadlet pushTesterToadlet = new PushTesterToadlet(client);
		server.register(pushTesterToadlet, null, pushTesterToadlet.path(), true, false);

		PushLeavingToadlet pushLeavingToadlet = new PushLeavingToadlet(client);
		server.register(pushLeavingToadlet, null, pushLeavingToadlet.path(), true, false);

		ImageCreatorToadlet imageCreatorToadlet = new ImageCreatorToadlet(client);
		server.register(imageCreatorToadlet, null, imageCreatorToadlet.path(), true, false);

		LogWritebackToadlet logWritebackToadlet = new LogWritebackToadlet(client);
		server.register(logWritebackToadlet, null, logWritebackToadlet.path(), true, false);

		DismissAlertToadlet dismissAlertToadlet = new DismissAlertToadlet(client);
		server.register(dismissAlertToadlet, null, dismissAlertToadlet.path(), true, false);
	}

	/**
	 * Get expected filename for a file.
	 * @param uri The original URI.
	 * @param expectedMimeType The expected MIME type.
	 */
	private static String getFilename(FreenetURI uri, String expectedMimeType) {
		return DefaultMIMETypes.forceExtension(uri.getPreferredFilename(), expectedMimeType);
	}

	private static long[] parseRange(String hdrrange) throws HTTPRangeException {

		long result[] = new long[2];
		try {
			String[] units = hdrrange.split("=", 2);
			// FIXME are MBytes and co valid? if so, we need to adjust the values and
			// return always bytes
			if (!"bytes".equals(units[0])) {
				throw new HTTPRangeException("Unknown unit, only 'bytes' supportet yet");
			}
			String[] range = units[1].split("-", 2);
			result[0] = Long.parseLong(range[0]);
			if (result[0] < 0)
				throw new HTTPRangeException("Negative 'from' value");
			if (range[1].trim().length() > 0) {
				result[1] = Long.parseLong(range[1]);
				if (result[1] <= result[0])
					throw new HTTPRangeException("'from' value must be less then 'to' value");
			} else {
				result[1] = -1;
			}
		} catch (NumberFormatException nfe) {
			throw new HTTPRangeException(nfe);
		} catch (IndexOutOfBoundsException ioobe) {
			throw new HTTPRangeException(ioobe);
		}
		return result;
	}

	@Override
	public boolean persistent() {
		return false;
	}

	@Override
	public String path() {
		return "/";
	}

	@Override
	public boolean realTimeFlag() {
		return true;
	}

}
