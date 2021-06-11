package freenet.clients.http;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.font.FontRenderContext;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.sql.Date;
import java.text.ParseException;

import javax.imageio.ImageIO;

import freenet.client.HighLevelSimpleClient;
import freenet.support.MultiValueTable;
import freenet.support.api.Bucket;
import freenet.support.api.HTTPRequest;

/** This toadlet creates a PNG image with the specified text. */
public class ImageCreatorToadlet extends Toadlet {

	private static final String ROOT_URL = "/imagecreator/";

	/** The default width */
	public static final int		DEFAULT_WIDTH	= 100;

	/** The default height */
	public static final int		DEFAULT_HEIGHT	= 100;

	private static final short WIDTH_AND_HEIGHT_LIMIT = 3500;

	/**
	 * The last modification time of the class, it is required for the
	 * client-side cache.
	 * If anyone makes modifications to this class, this needs to be updated.
	 */
	public static final Date LAST_MODIFIED = new Date(1593361729000L);

	protected ImageCreatorToadlet(HighLevelSimpleClient client) {
		super(client);
	}

	public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {
		boolean needsGeneration = true;
		// If the browser has requested this image, then it will send this header
		if (ctx.getHeaders().containsKey("if-modified-since")) {
			try {
				// If the received date is equal to the last modification of this class, then it doesn't need regeneration
				if (ToadletContextImpl.parseHTTPDate(ctx.getHeaders().get("if-modified-since")).compareTo(LAST_MODIFIED) == 0) {
					// So we just send the NOT_MODIFIED response, and skip the generation
					ctx.sendReplyHeadersStatic(304, "Not Modified", null, "image/png", 0, LAST_MODIFIED);
					needsGeneration = false;
				}
			} catch (ParseException pe) {
				// If something goes wrong, we regenerate
			}
		}
		if (needsGeneration) {
			// The text that will be drawn
			String text = req.getParam("text");
			// If width or height is specified, we use it, if not, then we use the default
			int requiredWidth = req.getParam("width").compareTo("") != 0 ? Integer.parseInt(req.getParam("width").endsWith("px")?req.getParam("width").substring(0, req.getParam("width").length()-2):req.getParam("width")) : DEFAULT_WIDTH;
			int requiredHeight = req.getParam("height").compareTo("") != 0 ? Integer.parseInt(req.getParam("height").endsWith("px")?req.getParam("height").substring(0, req.getParam("height").length()-2):req.getParam("height")) : DEFAULT_HEIGHT;
			// Validate image size
			if (requiredWidth <= 0 || requiredHeight <= 0) {
				writeHTMLReply(ctx, 400, "Bad request", "Illegal argument");
			}
			if (requiredWidth > WIDTH_AND_HEIGHT_LIMIT || requiredHeight > WIDTH_AND_HEIGHT_LIMIT) {
				writeHTMLReply(ctx, 400, "Bad request",
						"Too large (max " + WIDTH_AND_HEIGHT_LIMIT + "x" + WIDTH_AND_HEIGHT_LIMIT + "px)");
			}
			// This is the image we are making
			BufferedImage buffer = new BufferedImage(requiredWidth, requiredHeight, BufferedImage.TYPE_INT_RGB);
			Graphics2D g2 = buffer.createGraphics();
			g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
			FontRenderContext fc = g2.getFontRenderContext();
			specifyMaximumFontSizeThatFitsInImage(g2, fc, requiredWidth, requiredHeight, text);
			Rectangle2D bounds = g2.getFont().getStringBounds(text, fc);
			// actually do the drawing
			g2.setColor(new Color(0, 0, 0));
			g2.fillRect(0, 0, requiredWidth, requiredHeight);
			g2.setColor(new Color(255, 255, 255));
			// We position it to the center. Note that this is not the upper left corner
			g2.drawString(text, (int) (requiredWidth / 2 - bounds.getWidth() / 2), (int) (requiredHeight / 2 + bounds.getHeight() / 4));

			// Write the data, and send the modification data to let the client cache it
			Bucket data = ctx.getBucketFactory().makeBucket(-1);
			try (OutputStream os = data.getOutputStream()) {
				ImageIO.write(buffer, "png", os);
			}
			MultiValueTable<String, String> headers = new MultiValueTable<>();
			ctx.sendReplyHeadersStatic(200, "OK", headers, "image/png", data.size(), LAST_MODIFIED);
			ctx.writeData(data);
		}
	}

	@Override
	public String path() {
		return ROOT_URL;
	}

	void specifyMaximumFontSizeThatFitsInImage(Graphics2D g2, FontRenderContext fc,
												int imageWidth, int imageHeight, String text) {
		int minFontSize = 1;
		int maxFontSize = Math.max(imageWidth, imageHeight);
		int betweenFontSize = betweenFontSize(minFontSize, maxFontSize);
		g2.setFont(g2.getFont().deriveFont((float) betweenFontSize));
		while (maxFontSize > minFontSize) {
			Rectangle2D bounds = g2.getFont().getStringBounds(text, fc);
			if (bounds.getWidth() > imageWidth || bounds.getHeight() > imageHeight) {
				maxFontSize = betweenFontSize - 1;
			} else {
				minFontSize = betweenFontSize;
			}
			betweenFontSize = betweenFontSize(minFontSize, maxFontSize);
			g2.setFont(g2.getFont().deriveFont((float) betweenFontSize));
		}
	}

	private int betweenFontSize(int from, int to) {
		int between = from + (to - from) / 2;
		if (between == from) {
			return to; // depends on specifyMaximumFontSizeThatFitsInImage
		}
		return between;
	}
}
