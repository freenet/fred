package freenet.clients.http;

import java.io.IOException;
import java.net.URI;

import freenet.clients.http.PageMaker.RenderParameters;
import freenet.l10n.NodeL10n;
import freenet.node.Node;
import freenet.support.HTMLNode;
import freenet.support.api.HTTPRequest;

/**
 * Toadlet for "Freenet is starting up" page.
 */
public class StartupToadlet extends Toadlet {

	private StaticToadlet staticToadlet;
	private volatile boolean isPRNGReady = false;

	public StartupToadlet(StaticToadlet staticToadlet) {
		super(null);
		this.staticToadlet = staticToadlet;
	}

	public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {
		// If we don't disconnect we will have pipelining issues
		ctx.forceDisconnect();

		String path = uri.getPath();
		if(path.startsWith(StaticToadlet.ROOT_URL) && staticToadlet != null)
			staticToadlet.handleMethodGET(uri, req, ctx);
		else {
			String desc = NodeL10n.getBase().getString("StartupToadlet.title");
			PageNode page = ctx.getPageMaker().getPageNode(desc, ctx, new RenderParameters().renderStatus(false).renderNavigationLinks(false).renderModeSwitch(false));
			HTMLNode pageNode = page.outer;
			HTMLNode headNode = page.headNode;
			headNode.addChild("meta", new String[]{"http-equiv", "content"}, new String[]{"refresh", "1; url="});
			HTMLNode contentNode = page.content;

			if(!isPRNGReady) {
				HTMLNode prngInfoboxContent = ctx.getPageMaker().getInfobox("infobox-error", Node.getEntropyErrorDetailedText(), contentNode, null, true);
				Node.getEntropyErrorDetailedText(prngInfoboxContent.addChild("#"));
			}

			HTMLNode infoboxContent = ctx.getPageMaker().getInfobox("infobox-error", desc, contentNode, null, true);
			infoboxContent.addChild("#", NodeL10n.getBase().getString("StartupToadlet.isStartingUp"));

			WelcomeToadlet.maybeDisplayWrapperLogfile(ctx, contentNode);

			//TODO: send a Retry-After header ?
			writeHTMLReply(ctx, 503, desc, pageNode.generate());
		}
	}

	public void setIsPRNGReady() {
		isPRNGReady = true;
	}

	@Override
	public String path() {
		return "/";
	}
}
