package freenet.clients.http;

import org.junit.Test;

import java.awt.*;
import java.awt.font.FontRenderContext;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;

import static org.junit.Assert.*;

public class ImageCreatorToadletTest {

    @Test
    public void specifyMaximumFontSizeThatFitsInImageTest() {
        String text = "Test";
        Graphics2D g2 = new BufferedImage(ImageCreatorToadlet.DEFAULT_WIDTH, ImageCreatorToadlet.DEFAULT_HEIGHT,
                BufferedImage.TYPE_INT_RGB).createGraphics();
        FontRenderContext fc = g2.getFontRenderContext();
        ImageCreatorToadlet imageCreatorToadlet = new ImageCreatorToadlet(null);

        imageCreatorToadlet.specifyMaximumFontSizeThatFitsInImage(g2, fc,
                ImageCreatorToadlet.DEFAULT_WIDTH, ImageCreatorToadlet.DEFAULT_HEIGHT, text);
        Rectangle2D bounds = g2.getFont().getStringBounds(text, fc);
        assertTrue("Inscription does not fit on the canvas",
                bounds.getWidth() <= ImageCreatorToadlet.DEFAULT_WIDTH
                        && bounds.getHeight() <= ImageCreatorToadlet.DEFAULT_HEIGHT);

        g2.setFont(g2.getFont().deriveFont((float) g2.getFont().getSize() + 1));
        bounds = g2.getFont().getStringBounds(text, fc);
        assertFalse("Large print should not fit on the canvas",
                bounds.getWidth() <= ImageCreatorToadlet.DEFAULT_WIDTH
                        && bounds.getHeight() <= ImageCreatorToadlet.DEFAULT_HEIGHT);
    }
}
