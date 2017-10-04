/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.http;

import org.tanukisoftware.wrapper.WrapperManager;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.HashSet;
import java.util.List;

import freenet.client.ClientMetadata;
import freenet.client.HighLevelSimpleClient;
import freenet.client.InsertBlock;
import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.clients.http.PageMaker.RenderParameters;
import freenet.clients.http.bookmark.BookmarkCategory;
import freenet.clients.http.bookmark.BookmarkItem;
import freenet.clients.http.bookmark.BookmarkManager;
import freenet.keys.FreenetURI;
import freenet.l10n.NodeL10n;
import freenet.node.DarknetPeerNode;
import freenet.node.Node;
import freenet.node.NodeStarter;
import freenet.node.Version;
import freenet.node.useralerts.UserAlert;
import freenet.support.HTMLNode;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.MultiValueTable;
import freenet.support.URLDecoder;
import freenet.support.api.HTTPRequest;
import freenet.support.api.RandomAccessBucket;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import freenet.support.io.LineReadingInputStream;

public class WelcomeToadlet extends Toadlet {

    final Node node;

    private static volatile boolean logMINOR;
    static {
        Logger.registerLogThresholdCallback(new LogThresholdCallback() {

            @Override
            public void shouldUpdate() {
                logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
            }
        });
    }

    WelcomeToadlet(HighLevelSimpleClient client, Node node) {
        super(client);
        this.node = node;
    }
    
    void redirectToRoot(ToadletContext ctx) throws ToadletContextClosedException, IOException {
        MultiValueTable<String, String> headers = new MultiValueTable<String, String>();
        headers.put("Location", "/");
        ctx.sendReplyHeaders(302, "Found", headers, null, 0);
        return;
    }

    private void addCategoryToList(BookmarkCategory cat, HTMLNode list, boolean noActiveLinks, ToadletContext ctx) {
		if(ctx.getPageMaker().getTheme().forceActivelinks) {
			noActiveLinks = false;
		}

        List<BookmarkItem> items = cat.getItems();
        if (items.size() > 0) {
            // FIXME CSS noborder ...
            HTMLNode table = list.addChild("li").addChild("table", new String[]{"border", "style"}, new String[]{"0", "border: none"});
            for (int i = 0; i < items.size(); i++) {
                BookmarkItem item = items.get(i);
                HTMLNode row = table.addChild("tr");
                HTMLNode cell = row.addChild("td", "style", "border: none");
                if (item.hasAnActivelink() && !noActiveLinks) {
                    String initialKey = item.getKey();
                    String key = '/' + initialKey + (initialKey.endsWith("/") ? "" : "/") + "activelink.png";
                    cell.addChild("a", "href", '/' + item.getKey()).addChild("img", new String[]{"src", "height", "width", "alt", "title"},
                            new String[]{ key, "36", "108", "activelink", item.getDescription()});
                } else {
                    cell.addChild("#", " ");
                }
                cell = row.addChild("td", "style", "border: none");
                cell.addChild("a", new String[]{"href", "title", "class"}, new String[]{ '/' + item.getKey(), item.getDescription(), "bookmark-title"}, item.getVisibleName());
                String explain = item.getShortDescription();
                if(explain != null && explain.length() > 0) {
                	cell.addChild("#", " (");
                	cell.addChild("#", explain);
                	cell.addChild("#", ")");
                }
            }
        }

        List<BookmarkCategory> cats = cat.getSubCategories();
        for (int i = 0; i < cats.size(); i++) {
            list.addChild("li", "class", "cat", cats.get(i).getVisibleName());
            addCategoryToList(cats.get(i), list.addChild("li").addChild("ul"), noActiveLinks, ctx);
        }
    }
    
    public boolean allowPOSTWithoutPassword() {
    	// We need to show some confirmation pages.
    	return true;
    }

    public boolean showSearchBox() {
        // Only show it if Library is loaded.
        return (node.pluginManager != null &&
                node.pluginManager.isPluginLoaded("plugins.Library.Main"));
    }
    
    public boolean showSearchBoxLoading() {
        // Only show it if Library is loaded.
        return (node.pluginManager == null ||
                (!node.pluginManager.isPluginLoaded("plugins.Library.Main") &&
                 node.pluginManager.isPluginLoadedOrLoadingOrWantLoad("Library")));
    }

    public void addSearchBox(HTMLNode contentNode) {
        // This function still contains legacy cruft because we might
        // need that again when Library becomes usable again.
        HTMLNode searchBox = contentNode.addChild("div", "class", "infobox infobox-normal");
        searchBox.addAttribute("id", "search-freenet");
        searchBox.addChild("div", "class", "infobox-header").addChild("span", "class", "search-title-label", NodeL10n.getBase().getString("WelcomeToadlet.searchBoxLabel"));
        HTMLNode searchBoxContent = searchBox.addChild("div", "class", "infobox-content");
        // Search form
        if (showSearchBox()) {
            // FIXME: Remove this once we have a non-broken index.
            searchBoxContent.addChild("span", "class", "search-warning-text", l10n("searchBoxWarningSlow"));
            HTMLNode searchForm = container.addFormChild(searchBoxContent, "/library/", "searchform");
            searchForm.addChild("input", new String[] { "type", "size", "name" }, new String[] { "text", "80", "search" });
            searchForm.addChild("input", new String[] { "type", "name", "value" }, new String[] { "submit", "find", l10n("searchFreenet") });
            // Search must be in a new window so that the user is able to browse the bookmarks.
            searchForm.addAttribute("target", "_blank");
        } else if (showSearchBoxLoading()) {
            // Warn that search plugin is not loaded.
            HTMLNode textSpan = searchBoxContent.addChild("span", "class", "search-not-availible-warning");
            NodeL10n.getBase().addL10nSubstitution(textSpan, "WelcomeToadlet.searchPluginLoading", new String[] { "link" }, new HTMLNode[] { HTMLNode.link("/plugins/") });
        } else {
            // Warn that search plugin is not loaded.
            HTMLNode textSpan = searchBoxContent.addChild("span", "class", "search-not-availible-warning");
            NodeL10n.getBase().addL10nSubstitution(textSpan, "WelcomeToadlet.searchPluginNotLoaded", new String[] { "link" }, new HTMLNode[] { HTMLNode.link("/plugins/") });
        }
    }

    @SuppressWarnings("UnusedParameters")
    public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx) throws ToadletContextClosedException, IOException {
        if(!ctx.checkFullAccess(this))
            return;

        if (request.getPartAsStringFailsafe("updateconfirm", 32).length() > 0) {
        	if(!ctx.checkFormPassword(request)) return;
            // false for no navigation bars, because that would be very silly
            PageNode page = ctx.getPageMaker().getPageNode(l10n("updatingTitle"), ctx);
            HTMLNode pageNode = page.outer;
            HTMLNode contentNode = page.content;
            HTMLNode content = ctx.getPageMaker().getInfobox("infobox-information", l10n("updatingTitle"), contentNode, null, true);
            content.addChild("p").addChild("#", l10n("updating"));
            content.addChild("p").addChild("#", l10n("thanks"));
            writeHTMLReply(ctx, 200, "OK", pageNode.generate());
            Logger.normal(this, "Node is updating/restarting");
            node.getNodeUpdater().arm();
        } else if (request.getPartAsStringFailsafe("update", 32).length() > 0) {
        	PageNode page = ctx.getPageMaker().getPageNode(l10n("nodeUpdateConfirmTitle"), ctx);
            HTMLNode pageNode = page.outer;
            HTMLNode contentNode = page.content;
            HTMLNode content = ctx.getPageMaker().getInfobox("infobox-query", l10n("nodeUpdateConfirmTitle"), contentNode, "update-node-confirm", true);
            content.addChild("p").addChild("#", l10n("nodeUpdateConfirm"));
            HTMLNode updateForm = ctx.addFormChild(content, "/", "updateConfirmForm");
            updateForm.addChild("input", new String[]{"type", "name", "value"}, new String[]{"submit", "cancel", NodeL10n.getBase().getString("Toadlet.cancel")});
            updateForm.addChild("input", new String[]{"type", "name", "value"}, new String[]{"submit", "updateconfirm", l10n("update")});
            writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	} else if (request.isPartSet("getThreadDump")) {
    	if(!ctx.checkFormPassword(request)) return;
            PageNode page = ctx.getPageMaker().getPageNode(l10n("threadDumpTitle"), ctx);
            HTMLNode pageNode = page.outer;
            HTMLNode contentNode = page.content;
            if (node.isUsingWrapper()) {
            	ctx.getPageMaker().getInfobox("#", l10n("threadDumpSubTitle"), contentNode, "thread-dump-generation", true).
            		addChild("#", l10n("threadDumpWithFilename", "filename", WrapperManager.getProperties().getProperty("wrapper.logfile")));
                System.out.println("Thread Dump:");
                WrapperManager.requestThreadDump();
            } else {
            	ctx.getPageMaker().getInfobox("infobox-error", l10n("threadDumpSubTitle"), contentNode, "thread-dump-generation", true).
            		addChild("#", l10n("threadDumpNotUsingWrapper"));
            }
            this.writeHTMLReply(ctx, 200, "OK", pageNode.generate());
        } else if (request.isPartSet("disable")) {
        	if(!ctx.checkFormPassword(request)) return;
	    int validAlertsRemaining = 0;
            UserAlert[] alerts = ctx.getAlertManager().getAlerts();
            for (UserAlert alert: alerts) {
                if (request.getIntPart("disable", -1) == alert.hashCode()) {
                    // Won't be dismissed if it's not allowed anyway
                    if (alert.userCanDismiss() && alert.shouldUnregisterOnDismiss()) {
                        alert.onDismiss();
                        Logger.normal(this, "Unregistering the userAlert " + alert.hashCode());
                        ctx.getAlertManager().unregister(alert);
                    } else {
                        Logger.normal(this, "Disabling the userAlert " + alert.hashCode());
                        alert.isValid(false);
                    }
                } else if(alert.isValid()) {
					validAlertsRemaining++;
				}
            }
            writePermanentRedirect(ctx, l10n("disabledAlert"), (validAlertsRemaining > 0 ? "/alerts/" : "/"));
            return;
        } else if (request.isPartSet("key") && request.isPartSet("filename")) {
        	if(!ctx.checkFormPassword(request)) return;
        	// FIXME do we still use this? where?
        	// FIXME If we support it from freesites we need a confirmation page with the formPassword.
            FreenetURI key = new FreenetURI(request.getPartAsStringFailsafe("key", Short.MAX_VALUE));
            String type = request.getPartAsStringFailsafe("content-type", 128);
            if (type == null) {
                type = "text/plain";
            }
            ClientMetadata contentType = new ClientMetadata(type);

            RandomAccessBucket bucket = request.getPart("filename");

            PageNode page = ctx.getPageMaker().getPageNode(l10n("insertedTitle"), ctx);
            HTMLNode pageNode = page.outer;
            HTMLNode contentNode = page.content;
            HTMLNode content;
            String filenameHint = null;
            if (key.getKeyType().equals("CHK")) {
                String[] metas = key.getAllMetaStrings();
                if ((metas != null) && (metas.length > 1)) {
                    filenameHint = metas[0];
                }
            }
            InsertBlock block = new InsertBlock(bucket, contentType, key);
            try {
                key = this.insert(block, filenameHint, false);
                content = ctx.getPageMaker().getInfobox("infobox-success", l10n("insertSucceededTitle"), contentNode, "successful-insert", false);
                String u = key.toString();
                NodeL10n.getBase().addL10nSubstitution(content, "WelcomeToadlet.keyInsertedSuccessfullyWithKeyAndName",
                        new String[]{"link", "name"},
                        new HTMLNode[] { HTMLNode.link("/"+u), HTMLNode.text(u) });
            } catch (InsertException e) {
            	content = ctx.getPageMaker().getInfobox("infobox-error", l10n("insertFailedTitle"), contentNode, "failed-insert", false);
                content.addChild("#", l10n("insertFailedWithMessage", "message", e.getMessage()));
                content.addChild("br");
                if (e.uri != null) {
                    content.addChild("#", l10n("uriWouldHaveBeen", "uri", e.uri.toString()));
                }
                InsertExceptionMode mode = e.getMode();
                if ((mode == InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS) || (mode == InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS)) {
                    content.addChild("br"); /* TODO */
                    content.addChild("#", l10n("splitfileErrorLabel"));
                    content.addChild("pre", e.errorCodes.toVerboseString());
                }
            }

            content.addChild("br");
            addHomepageLink(content);

            writeHTMLReply(ctx, 200, "OK", pageNode.generate());
            request.freeParts();
            bucket.free();
            return;
        } else if (request.isPartSet("key")) {
            if(!ctx.checkFormPassword(request)) return;
            String key;
            try {
              key = URLDecoder.decode(new FreenetURI(request.getPartAsStringFailsafe("key", Short.MAX_VALUE)).toURI("/").toString(), false);
            } catch (Exception e) {
              sendErrorPage(ctx, l10n("invalidURI"), l10n("invalidURILong"), e);
              return;
            }
            writeTemporaryRedirect(ctx, "OK", key);
            return;
        } else if (request.isPartSet("exit")) {
        	PageNode page = ctx.getPageMaker().getPageNode(l10n("shutdownConfirmTitle"), ctx);
            HTMLNode pageNode = page.outer;
            HTMLNode contentNode = page.content;
            HTMLNode content = ctx.getPageMaker().getInfobox("infobox-query", l10n("shutdownConfirmTitle"), contentNode, "shutdown-confirm", true);
            content.addChild("p").addChild("#", l10n("shutdownConfirm"));
            HTMLNode shutdownForm = ctx.addFormChild(content.addChild("p"), "/", "confirmShutdownForm");
            shutdownForm.addChild("input", new String[]{"type", "name", "value"}, new String[]{"submit", "cancel", NodeL10n.getBase().getString("Toadlet.cancel")});
            shutdownForm.addChild("input", new String[]{"type", "name", "value"}, new String[]{"submit", "shutdownconfirm", l10n("shutdown")});
            writeHTMLReply(ctx, 200, "OK", pageNode.generate());
            return;
        } else if (request.isPartSet("shutdownconfirm")) {
        	if(!ctx.checkFormPassword(request)) return;
            MultiValueTable<String, String> headers = new MultiValueTable<String, String>();
            headers.put("Location", "/?terminated&formPassword=" + ctx.getFormPassword());
            ctx.sendReplyHeaders(302, "Found", headers, null, 0);
            node.ticker.queueTimedJob(new Runnable() {

				@Override
                        public void run() {
                            node.exit("Shutdown from fproxy");
                        }
                    }, 1);
            return;
        } else if (request.isPartSet("restart")) {
        	PageNode page = ctx.getPageMaker().getPageNode(l10n("restartConfirmTitle"), ctx);
            HTMLNode pageNode = page.outer;
            HTMLNode contentNode = page.content;
            HTMLNode content = ctx.getPageMaker().getInfobox("infobox-query", l10n("restartConfirmTitle"), contentNode, "restart-confirm", true);
            content.addChild("p").addChild("#", l10n("restartConfirm"));
            HTMLNode restartForm = ctx.addFormChild(content.addChild("p"), "/", "confirmRestartForm");
            restartForm.addChild("input", new String[]{"type", "name", "value"}, new String[]{"submit", "cancel", NodeL10n.getBase().getString("Toadlet.cancel")});
            restartForm.addChild("input", new String[]{"type", "name", "value"}, new String[]{"submit", "restartconfirm", l10n("restart")});
            writeHTMLReply(ctx, 200, "OK", pageNode.generate());
            return;
        } else if (request.isPartSet("restartconfirm")) {
        	if(!ctx.checkFormPassword(request)) return;
            MultiValueTable<String, String> headers = new MultiValueTable<String, String>();
            headers.put("Location", "/?restarted&formPassword=" + ctx.getFormPassword());
            ctx.sendReplyHeaders(302, "Found", headers, null, 0);
            node.ticker.queueTimedJob(new Runnable() {

				@Override
                        public void run() {
                            node.getNodeStarter().restart();
                        }
                    }, 1);
            return;
        } else if(request.isPartSet("dismiss-events")) {
        	if(!ctx.checkFormPassword(request)) return;
        	String alertsToDump = request.getPartAsStringFailsafe("events", Integer.MAX_VALUE);
        	String[] alertAnchors = alertsToDump.split(",");
        	HashSet<String> toDump = new HashSet<String>();
        	for(String alertAnchor : alertAnchors) toDump.add(alertAnchor);
        	ctx.getAlertManager().dumpEvents(toDump);
        	redirectToRoot(ctx);
        } else {
            redirectToRoot(ctx);
        }
    }

	public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx) throws ToadletContextClosedException, IOException {
        if (ctx.isAllowedFullAccess()) {

            if (request.isParameterSet("latestlog")) {
                final File logs = new File(node.config.get("logger").getString("dirname") + File.separator + "freenet-latest.log");
                String text = readLogTail(logs, 100000);
                this.writeTextReply(ctx, 200, "OK", text);
                return;
            } else if (request.isParameterSet("terminated")) {
                if ((!request.isParameterSet("formPassword")) || !request.getParam("formPassword").equals(ctx.getFormPassword())) {
                    redirectToRoot(ctx);
                    return;
                }
                // Tell the user that the node is shutting down
                PageNode page = ctx.getPageMaker().getPageNode("Node Shutdown", ctx, new RenderParameters().renderNavigationLinks(false));
                HTMLNode pageNode = page.outer;
                HTMLNode contentNode = page.content;
                ctx.getPageMaker().getInfobox("infobox-information", l10n("shutdownDone"), contentNode, "shutdown-progressing", true).
                	addChild("#", l10n("thanks"));

                WelcomeToadlet.maybeDisplayWrapperLogfile(ctx, contentNode);

                this.writeHTMLReply(ctx, 200, "OK", pageNode.generate());
                return;
            } else if (request.isParameterSet("restarted")) {
                if ((!request.isParameterSet("formPassword")) || !request.getParam("formPassword").equals(ctx.getFormPassword())) {
                    redirectToRoot(ctx);
                    return;
                }
                sendRestartingPage(ctx);
                return;
            } else if (request.getParam("newbookmark").length() > 0) {
            	PageNode page = ctx.getPageMaker().getPageNode(l10n("confirmAddBookmarkTitle"), ctx);
                HTMLNode pageNode = page.outer;
                HTMLNode contentNode = page.content;
                HTMLNode infoboxContent = ctx.getPageMaker().getInfobox("#", l10n("confirmAddBookmarkSubTitle"), contentNode, "add-bookmark-confirm", true);
                HTMLNode addForm = ctx.addFormChild(infoboxContent, "/bookmarkEditor/", "editBookmarkForm");
                addForm.addChild("#", l10n("confirmAddBookmarkWithKey", "key", request.getParam("newbookmark")));
                addForm.addChild("br");
                String key = request.getParam("newbookmark");
                if (key.startsWith("freenet:")) {
                    key = key.substring(8);
                }
                addForm.addChild("input", new String[]{"type", "name", "value"}, new String[]{"hidden", "key", key});
                if(request.isParameterSet("hasAnActivelink")) {
                	addForm.addChild("input", new String[]{"type", "name", "value"}, new String[]{"hidden","hasAnActivelink",request.getParam("hasAnActivelink")});
                }
				addForm.addChild("label", "for", "name", NodeL10n.getBase().getString("BookmarkEditorToadlet.nameLabel") + ' ');
                addForm.addChild("input", new String[]{"type", "name", "value"}, new String[]{"text", "name", request.getParam("desc")});
                addForm.addChild("br");
                addForm.addChild("input", new String[]{"type", "name", "value"}, new String[]{"hidden", "bookmark", "/"});
                addForm.addChild("input", new String[]{"type", "name", "value"}, new String[]{"hidden", "action", "addItem"});
                addForm.addChild("label", "for", "descB", NodeL10n.getBase().getString("BookmarkEditorToadlet.descLabel") + ' ');
                addForm.addChild("br");
                addForm.addChild("textarea", new String[]{"id", "name", "row", "cols"}, new String[]{"descB", "descB", "3", "70"});
                if(node.getDarknetConnections().length > 0) {
                	addForm.addChild("br");
                	addForm.addChild("br");
                	if (node.isFProxyJavascriptEnabled()) {
                		addForm.addChild("script", new String[] {"type", "src"}, new String[] {"text/javascript",  "/static/js/checkall.js"});
                	}
                	
                	HTMLNode peerTable = addForm.addChild("table", "class", "darknet_connections");
                	if (node.isFProxyJavascriptEnabled()) {
                		HTMLNode headerRow = peerTable.addChild("tr");
                		headerRow.addChild("th").addChild("input", new String[] { "type", "onclick" }, new String[] { "checkbox", "checkAll(this, 'darknet_connections')" });
                		headerRow.addChild("th", NodeL10n.getBase().getString("QueueToadlet.recommendToFriends"));
                	} else {
                		peerTable.addChild("tr").addChild("th", "colspan", "2", NodeL10n.getBase().getString("QueueToadlet.recommendToFriends"));
                	}
                	for(DarknetPeerNode peer : node.getDarknetConnections()) {
                		HTMLNode peerRow = peerTable.addChild("tr", "class", "darknet_connections_normal");
                		peerRow.addChild("td", "class", "peer-marker").addChild("input", new String[] { "type", "name" }, new String[] { "checkbox", "node_" + peer.hashCode() });
                		peerRow.addChild("td", "class", "peer-name").addChild("#", peer.getName());
                	}

                	addForm.addChild("label", "for", "descB", (NodeL10n.getBase().getString("BookmarkEditorToadlet.publicDescLabel") + ' '));
                	addForm.addChild("br");
                	addForm.addChild("textarea", new String[]{"id", "name", "row", "cols"}, new String[]{"descB", "publicDescB", "3", "70"}, "");
                }
                addForm.addChild("br");

                addForm.addChild("input", new String[]{"type", "name", "value"}, new String[]{"submit", "addbookmark", NodeL10n.getBase().getString("BookmarkEditorToadlet.addBookmark")});

                this.writeHTMLReply(ctx, 200, "OK", pageNode.generate());
                return;
        } else if (uri.getQuery() != null && uri.getQuery().startsWith("_CHECKED_HTTP_=")) {
		//Redirect requests for escaped URLs using the old destination to ExternalLinkToadlet.
		super.writeTemporaryRedirect(ctx, "Depreciated", ExternalLinkToadlet.PATH+'?'+uri.getQuery());
		return;
        }
        }

        PageNode page = ctx.getPageMaker().getPageNode(l10n("homepageFullTitle"), ctx);
        HTMLNode pageNode = page.outer;
        HTMLNode contentNode = page.content;

        String useragent = ctx.getHeaders().get("user-agent");

        if (useragent != null) {
            useragent = useragent.toLowerCase();
            if ((useragent.indexOf("msie") > -1) && (useragent.indexOf("opera") == -1)) {
            	ctx.getPageMaker().getInfobox("infobox-alert", l10n("ieWarningTitle"), contentNode, "internet-explorer-used", true).
                	addChild("#", l10n("ieWarning"));
            }
        }

        // Alerts
        if (ctx.isAllowedFullAccess()) {
			contentNode.addChild(ctx.getAlertManager().createSummary());
        }
		
        if (ctx.getPageMaker().getTheme().fetchKeyBoxAboveBookmarks) {
            this.putFetchKeyBox(ctx, contentNode);
        }
        
        // Bookmarks
        HTMLNode bookmarkBox = contentNode.addChild("div", "class", "infobox infobox-normal bookmarks-box");
        HTMLNode bookmarkBoxHeader = bookmarkBox.addChild("div", "class", "infobox-header");
        bookmarkBoxHeader.addChild("a", new String[]{"class", "title"}, new String[]{"bookmarks-header-text", NodeL10n.getBase().getString("BookmarkEditorToadlet.myBookmarksExplanation")}, NodeL10n.getBase().getString("BookmarkEditorToadlet.myBookmarksTitle"));
        if (ctx.isAllowedFullAccess()) {
            bookmarkBoxHeader.addChild("span", "class", "edit-bracket", "[");
            bookmarkBoxHeader.addChild("span", "id", "bookmarkedit").addChild("a", new String[]{"href", "class"}, new String[]{"/bookmarkEditor/", "interfacelink"}, NodeL10n.getBase().getString("BookmarkEditorToadlet.edit"));
            bookmarkBoxHeader.addChild("span", "class", "edit-bracket", "]");
        }

        HTMLNode bookmarkBoxContent = bookmarkBox.addChild("div", "class", "infobox-content");
        
        
        HTMLNode bookmarksList = bookmarkBoxContent.addChild("ul", "id", "bookmarks");
		if (ctx.isAllowedFullAccess() || !ctx.getContainer().publicGatewayMode()) {
			addCategoryToList(BookmarkManager.MAIN_CATEGORY, bookmarksList, (!container.enableActivelinks()) || (useragent != null && useragent.contains("khtml") && !useragent.contains("chrome")), ctx);
		}
		else {
			addCategoryToList(BookmarkManager.DEFAULT_CATEGORY, bookmarksList, (!container.enableActivelinks()) || (useragent != null && useragent.contains("khtml") && !useragent.contains("chrome")), ctx);
		}

        // Search Box
        if (showSearchBox()) {
            addSearchBox(contentNode);
        }

        // Fetch key box if the theme wants it below the bookmarks.
        if (!ctx.getPageMaker().getTheme().fetchKeyBoxAboveBookmarks) {
            this.putFetchKeyBox(ctx, contentNode);
        }

        // Version info and Quit Form
        HTMLNode versionContent = ctx.getPageMaker().getInfobox("infobox-information", l10n("versionHeader"), contentNode, "freenet-version", true);
        versionContent.addChild("span", "class", "freenet-full-version",
                NodeL10n.getBase().getString("WelcomeToadlet.version", new String[]{"fullVersion", "build", "rev"},
                new String[]{Version.publicVersion(), Integer.toString(Version.buildNumber()), Version.cvsRevision()}));
        versionContent.addChild("br");
        versionContent.addChild("span", "class", "freenet-ext-version",
        		NodeL10n.getBase().getString("WelcomeToadlet.extVersion", new String[]{"build", "rev"},
        				new String[]{Integer.toString(NodeStarter.extBuildNumber), NodeStarter.extRevisionNumber}));
        versionContent.addChild("br");
        if (ctx.isAllowedFullAccess()) {
        	HTMLNode shutdownForm = ctx.addFormChild(versionContent, ".", "shutdownForm");
            shutdownForm.addChild("input", new String[]{"type", "name"}, new String[]{"hidden", "exit"});
            
            shutdownForm.addChild("input", new String[]{"type", "value"}, new String[]{"submit", l10n("shutdownNode")});
            if (node.isUsingWrapper()) {
                HTMLNode restartForm = ctx.addFormChild(versionContent, ".", "restartForm");
                restartForm.addChild("input", new String[]{"type", "name"}, new String[]{"hidden", "restart"});
                restartForm.addChild("input", new String[]{"type", "name", "value"}, new String[]{"submit", "restart2", l10n("restartNode")});
            }
        }

        this.writeHTMLReply(ctx, 200, "OK", pageNode.generate());
    }

	private void putFetchKeyBox(ToadletContext ctx, HTMLNode contentNode) {
		// Fetch-a-key box
		HTMLNode fetchKeyContent = ctx.getPageMaker().getInfobox("infobox-normal", l10n("fetchKeyLabel"), contentNode, "fetch-key", true);
		fetchKeyContent.addAttribute("id", "keyfetchbox");
                HTMLNode fetchKeyForm = fetchKeyContent.addChild("form", new String[]{ "method" }, new String[]{ "POST" }).addChild("div");
                fetchKeyForm.addChild("span", "class", "fetch-key-label", l10n("keyRequestLabel") + ' ');
                fetchKeyForm.addChild("input", new String[]{ "type", "size", "name" }, new String[]{ "text", "80", "key" });
                fetchKeyForm.addChild("input", new String[]{ "type", "name", "value" }, new String[]{ "hidden", "formPassword", ctx.getFormPassword() });
                fetchKeyForm.addChild("input", new String[]{ "type", "value" }, new String[]{ "submit", l10n("fetch") });
	}

    private void sendRestartingPage(ToadletContext ctx) throws ToadletContextClosedException, IOException {
        writeHTMLReply(ctx, 200, "OK", sendRestartingPageInner(ctx).generate());
	}
    
    static HTMLNode sendRestartingPageInner(ToadletContext ctx) {
        // Tell the user that the node is restarting
        PageNode page = ctx.getPageMaker().getPageNode("Node Restart", ctx, new RenderParameters().renderNavigationLinks(false));
        HTMLNode pageNode = page.outer;
        HTMLNode headNode = page.headNode;
        headNode.addChild("meta", new String[]{"http-equiv", "content"}, new String[]{"refresh", "20; url="});
        HTMLNode contentNode = page.content;
        ctx.getPageMaker().getInfobox("infobox-information", l10n("restartingTitle"), contentNode, "shutdown-progressing", true).
        	addChild("#", l10n("restarting"));
        Logger.normal(WelcomeToadlet.class, "Node is restarting");
        return pageNode;
    }

    private static String l10n(String key) {
        return NodeL10n.getBase().getString("WelcomeToadlet." + key);
    }

    private static String l10n(String key, String pattern, String value) {
        return NodeL10n.getBase().getString("WelcomeToadlet." + key, new String[]{pattern}, new String[]{value});
    }

    public static void maybeDisplayWrapperLogfile(ToadletContext ctx, HTMLNode contentNode) {
        final File logs = new File("wrapper.log");
        long logSize = logs.length();
        if(logs.exists() && logs.isFile() && logs.canRead() && (logSize > 0)) {
            HTMLNode logInfoboxContent = ctx.getPageMaker().getInfobox("infobox-info", "Current status", contentNode, "start-progress", true);
            LineReadingInputStream logreader = null;
            try {
                logreader = FileUtil.getLogTailReader(logs, 2000);
            	String line;
            	while ((line = logreader.readLine(100000, 200, true)) != null) {
            	    logInfoboxContent.addChild("#", line);
            	    logInfoboxContent.addChild("br");
            	}
            } catch(IOException e) {}
            finally {
                Closer.close(logreader);
            }
        }
    }

    /**
     * Reads and returns the content of <code>logfile</code>. At most <code>byteLimit</code>
     * bytes will be read. If <code>byteLimit</code> is less than the size of <code>logfile</code>,
     * the first part of the file will be skipped. If this leaves a partial line at the beginning
     * of the content to return, that partial line will also be skipped.
     * @param logfile The file to read
     * @param byteLimit The maximum number of bytes to read
     * @return The trailing portion of the file
     * @throws IOException if an I/O error occurs
     */
    private static String readLogTail(File logfile, long byteLimit) throws IOException {
        LineReadingInputStream stream = null;
        try {
            stream = FileUtil.getLogTailReader(logfile, byteLimit);
            return FileUtil.readUTF(stream).toString();
        } finally {
            Closer.close(stream);
        }
    }

	public static final String PATH = "/";

	@Override
	public String path() {
		// So it matches "Browse Freenet" on the menu
		return PATH;
	}
}
