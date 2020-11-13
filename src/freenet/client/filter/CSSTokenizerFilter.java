/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */

package freenet.client.filter;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import freenet.support.Fields;
import freenet.support.Logger;
import freenet.support.api.Bucket;
import freenet.support.io.Closer;
import freenet.support.io.FileBucket;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;

/** Comprehensive CSS2.1 filter. The old jflex-based filter was very far
 * from comprehensive.
 * @author kurmiashish
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 *
 * FIXME: Rewrite to parse properly. This works but is rather spaghettified.
 * JFlex on its own obviously won't work, but JFlex plus a proper grammar
 * should work fine.
 *
 * According to the CSS2.1 spec, in some cases spaces between tokens are
 * optional. We do NOT support this! A grammar-based parser might, although
 * really it's horrible, we shouldn't support it if it's not widely used...
 * See end of 1.4.2.1.
 */
class CSSTokenizerFilter {
	private Reader r;
	Writer w = null;
	FilterCallback cb;
	private static volatile boolean logDEBUG;
	private final String passedCharset;
	private String detectedCharset;
	private final boolean stopAtDetectedCharset;
	private final boolean isInline;

	static {
		Logger.registerClass(CSSTokenizerFilter.class);
	}

	CSSTokenizerFilter(){
		passedCharset = "UTF-8";
		stopAtDetectedCharset = false;
		isInline = false;
	}

	CSSTokenizerFilter(Reader r, Writer w, FilterCallback cb, String charset, boolean stopAtDetectedCharset, boolean isInline) {
		this.r=r;
		this.w = w;
		this.cb=cb;
		passedCharset = charset;
		this.stopAtDetectedCharset = stopAtDetectedCharset;
		this.isInline = isInline;
	}

	public boolean isValidURI(String URI)
	{
		try
		{
			return URI.equals(cb.processURI(URI, null));
		}
		catch(CommentException e)
		{
			return false;
		}
	}


	//Function to merge two arrays into third array.
	public static <T> T[] concat(T[] a, T[] b) {
		final int alen = a.length;
		final int blen = b.length;
		if (alen == 0) {
			return b;
		}
		if (blen == 0) {
			return a;
		}
		@SuppressWarnings("unchecked") final T[] result = (T[]) java.lang.reflect.Array.newInstance(a.getClass().getComponentType(), alen + blen);
		System.arraycopy(a, 0, result, 0, alen);
		System.arraycopy(b, 0, result, alen, blen);
		return result;
	}


	/* To save the memory, only those Verifier objects would be created which are actually present in the CSS document.
	 * allelementVerifiers contains all the CSS property tags as String. All loaded Verifier objects are stored in elementVerifier.
	 * When retrieving a Verifier object, first it is searched in elementVerifiers to see if it is already loaded.
	 * If it is not loaded then allelementVerifiers is checked to see if the property name is valid. If it is valid, then the desired Verifier object is loaded in allelemntVerifiers.
	 */

	// FIXME this is probably overkill, initialising all of them on startup would probably be cleaner code, less synchronization, at very little memory cost.
	// FIXME check how many bytes we save by lazy init here.

	private final static Map<String, CSSPropertyVerifier> elementVerifiers = new HashMap<String, CSSPropertyVerifier>();
	private final static HashSet<String> allelementVerifiers=new HashSet<String>();
	//Reference http://www.w3.org/TR/CSS2/propidx.html
	static {
		allelementVerifiers.add("align-content");
		allelementVerifiers.add("align-items");
		allelementVerifiers.add("align-self");
		allelementVerifiers.add("azimuth");
		allelementVerifiers.add("background-attachment");
		allelementVerifiers.add("background-clip");
		allelementVerifiers.add("background-color");
		allelementVerifiers.add("background-image");
		allelementVerifiers.add("background-origin");
		allelementVerifiers.add("background-position");
		allelementVerifiers.add("background-repeat");
		allelementVerifiers.add("background-size");
		allelementVerifiers.add("background");
		allelementVerifiers.add("border-collapse");
		allelementVerifiers.add("border-color");
		allelementVerifiers.add("border-top-color");
		allelementVerifiers.add("border-bottom-color");
		allelementVerifiers.add("border-right-color");
		allelementVerifiers.add("border-left-color");
		allelementVerifiers.add("border-spacing");
		allelementVerifiers.add("border-style");
		allelementVerifiers.add("border-top-style");
		allelementVerifiers.add("border-bottom-style");
		allelementVerifiers.add("border-left-style");
		allelementVerifiers.add("border-right-style");
		allelementVerifiers.add("border-left");
		allelementVerifiers.add("border-top");
		allelementVerifiers.add("border-right");
		allelementVerifiers.add("border-bottom");
		allelementVerifiers.add("border-top-color");
		allelementVerifiers.add("border-right-color");
		allelementVerifiers.add("border-bottom-color");
		allelementVerifiers.add("border-left-color");
		allelementVerifiers.add("border-top-style");
		allelementVerifiers.add("border-right-style");
		allelementVerifiers.add("border-bottom-style");
		allelementVerifiers.add("border-top-width");
		allelementVerifiers.add("border-right-width");
		allelementVerifiers.add("border-bottom-width");
		allelementVerifiers.add("border-left-width");
		allelementVerifiers.add("border-width");
		allelementVerifiers.add("border-top-width");
		allelementVerifiers.add("border-bottom-width");
		allelementVerifiers.add("border-left-width");
		allelementVerifiers.add("border-right-width");
		allelementVerifiers.add("border-radius");
		allelementVerifiers.add("border-top-radius");
		allelementVerifiers.add("border-bottom-radius");
		allelementVerifiers.add("border-left-radius");
		allelementVerifiers.add("border-right-radius");
		allelementVerifiers.add("border-image-source");
		allelementVerifiers.add("border-image-slice");
		allelementVerifiers.add("border-image-width");
		allelementVerifiers.add("border-image-outset");
		allelementVerifiers.add("border-image-repeat");
		allelementVerifiers.add("border-image");
		allelementVerifiers.add("border");
		allelementVerifiers.add("bottom");
		allelementVerifiers.add("box-decoration-break");
		allelementVerifiers.add("box-shadow");
		allelementVerifiers.add("box-sizing");
		allelementVerifiers.add("box-suppress");
		allelementVerifiers.add("caption-side");
		allelementVerifiers.add("caret-color");
		allelementVerifiers.add("clear");
		allelementVerifiers.add("clip");
                allelementVerifiers.add("break-before");
                allelementVerifiers.add("break-after");
                allelementVerifiers.add("break-inside");
                allelementVerifiers.add("column-count");
                allelementVerifiers.add("column-fill");
                allelementVerifiers.add("column-gap");
                allelementVerifiers.add("column-rule-color");
                allelementVerifiers.add("column-rule-style");
                allelementVerifiers.add("column-rule-width");
                allelementVerifiers.add("column-span");
		allelementVerifiers.add("column-rule");
                allelementVerifiers.add("column-width");
		allelementVerifiers.add("columns");
		allelementVerifiers.add("color");
		allelementVerifiers.add("color-interpolation");
		allelementVerifiers.add("color-rendering");
		allelementVerifiers.add("content");
		allelementVerifiers.add("counter-increment");
		allelementVerifiers.add("counter-reset");
		allelementVerifiers.add("cue-after");
		allelementVerifiers.add("cue-before");
		allelementVerifiers.add("cue");
		allelementVerifiers.add("cursor");
		allelementVerifiers.add("direction");
		allelementVerifiers.add("display");
		allelementVerifiers.add("elevation");
		allelementVerifiers.add("empty-cells");
		allelementVerifiers.add("flex");
		allelementVerifiers.add("flex-basis");
		allelementVerifiers.add("flex-direction");
		allelementVerifiers.add("flex-flow");
		allelementVerifiers.add("flex-grow");
		allelementVerifiers.add("flex-shrink");
		allelementVerifiers.add("flex-wrap");
		allelementVerifiers.add("float");
		allelementVerifiers.add("font-family");
		allelementVerifiers.add("font-size");
		allelementVerifiers.add("font-style");
		allelementVerifiers.add("font-variant");
		allelementVerifiers.add("font-weight");
		allelementVerifiers.add("font");
		allelementVerifiers.add("hanging-punctuation");
		allelementVerifiers.add("height");
		allelementVerifiers.add("justify-content");
		allelementVerifiers.add("justify-items");
		allelementVerifiers.add("justify-self");
		allelementVerifiers.add("left");
		allelementVerifiers.add("letter-spacing");
		allelementVerifiers.add("line-break");
		allelementVerifiers.add("line-height");
		allelementVerifiers.add("list-style-image");
		allelementVerifiers.add("list-style-position");
		allelementVerifiers.add("list-style-type");
		allelementVerifiers.add("list-style");
		allelementVerifiers.add("margin-right");
		allelementVerifiers.add("margin-left");
		allelementVerifiers.add("margin-top");
		allelementVerifiers.add("margin-bottom");
		allelementVerifiers.add("margin");
		allelementVerifiers.add("max-height");
		allelementVerifiers.add("max-width");
		allelementVerifiers.add("min-height");
		allelementVerifiers.add("min-width");
		allelementVerifiers.add("nav-down");
		allelementVerifiers.add("nav-left");
		allelementVerifiers.add("nav-right");
		allelementVerifiers.add("nav-up");
		allelementVerifiers.add("opacity");
		allelementVerifiers.add("order");
		allelementVerifiers.add("orphans");
		allelementVerifiers.add("outline-color");
		allelementVerifiers.add("outline-offset");
		allelementVerifiers.add("outline-style");
		allelementVerifiers.add("outline-width");
		allelementVerifiers.add("outline");
		allelementVerifiers.add("overflow");
		allelementVerifiers.add("padding-top");
		allelementVerifiers.add("padding-right");
		allelementVerifiers.add("padding-bottom");
		allelementVerifiers.add("padding-left");
		allelementVerifiers.add("padding");
		allelementVerifiers.add("page-break-after");
		allelementVerifiers.add("page-break-before");
		allelementVerifiers.add("page-break-inside");
		allelementVerifiers.add("pause-after");
		allelementVerifiers.add("pause-before");
		allelementVerifiers.add("pause");
		allelementVerifiers.add("pitch-range");
		allelementVerifiers.add("pitch");
		allelementVerifiers.add("play-during");
		allelementVerifiers.add("punctuation-trim");
		allelementVerifiers.add("position");
		allelementVerifiers.add("quotes");
		allelementVerifiers.add("resize");
		allelementVerifiers.add("richness");
		allelementVerifiers.add("right");
		allelementVerifiers.add("speak-header");
		allelementVerifiers.add("speak-numeral");
		allelementVerifiers.add("speak-punctuation");
		allelementVerifiers.add("speak");
		allelementVerifiers.add("speech-rate");
		allelementVerifiers.add("stress");
		allelementVerifiers.add("table-layout");
		allelementVerifiers.add("text-align");
		allelementVerifiers.add("text-align-last");
		allelementVerifiers.add("text-autospace");
		allelementVerifiers.add("text-decoration");
		allelementVerifiers.add("text-decoration-color");
		allelementVerifiers.add("text-decoration-line");
		allelementVerifiers.add("text-decoration-skip");
		allelementVerifiers.add("text-decoration-style");
		allelementVerifiers.add("text-emphasis");
		allelementVerifiers.add("text-emphasis-color");
		allelementVerifiers.add("text-emphasis-position");
		allelementVerifiers.add("text-emphasis-style");
		allelementVerifiers.add("text-indent");
		allelementVerifiers.add("text-justify");
		allelementVerifiers.add("text-outline");
		allelementVerifiers.add("text-overflow");
		allelementVerifiers.add("text-shadow");
		allelementVerifiers.add("text-transform");
		allelementVerifiers.add("text-underline-position");
		allelementVerifiers.add("text-wrap");
		allelementVerifiers.add("top");
		allelementVerifiers.add("transform");
		allelementVerifiers.add("transform-origin");
		allelementVerifiers.add("unicode-bidi");
		allelementVerifiers.add("vertical-align");
		allelementVerifiers.add("visibility");
		allelementVerifiers.add("voice-family");
		allelementVerifiers.add("volume");
		allelementVerifiers.add("white-space");
		allelementVerifiers.add("white-space-collapsing");
		allelementVerifiers.add("widows");
		allelementVerifiers.add("width");
		allelementVerifiers.add("word-break");
		allelementVerifiers.add("word-spacing");
                allelementVerifiers.add("word-wrap");
		allelementVerifiers.add("z-index");


	}

	/*
	 * Array for storing additional Verifier objects for validating Regular expressions in CSS Property value
	 * e.g. [ <color> | transparent]{1,4}. It is explained in detail in CSSPropertyVerifier class
	 */
	private final static CSSPropertyVerifier[] auxilaryVerifiers=new CSSPropertyVerifier[145];
	static
	{
		/*CSSPropertyVerifier(String[] allowedValues,String[] possibleValues,String expression,boolean onlyValueVerifier)*/
		//for background-position
		auxilaryVerifiers[2]=new CSSPropertyVerifier(Arrays.asList("left","center","right"),Arrays.asList("pe","le"),null,null,true);
		auxilaryVerifiers[3]=new CSSPropertyVerifier(Arrays.asList("top","center","bottom"),Arrays.asList("pe","le"),null,null,true);
		auxilaryVerifiers[4]=new CSSPropertyVerifier(Arrays.asList("left","center","right"),null,null,null,true);
		auxilaryVerifiers[5]=new CSSPropertyVerifier(Arrays.asList("top","center","bottom"),null,null,null,true);
		//<border-color>
		auxilaryVerifiers[11]=new CSSPropertyVerifier(Arrays.asList("transparent"),Arrays.asList("co"),null,null,true);
		//<border-style>
		auxilaryVerifiers[13]=new CSSPropertyVerifier(Arrays.asList("none","hidden","dotted","dashed","solid","double","groove","ridge","inset","outset"),Arrays.asList("le"),null,null,true);
		//<border-width>
		auxilaryVerifiers[14]=new CSSPropertyVerifier(Arrays.asList("thin","medium","thick"),Arrays.asList("le"),null,null,true);
		//<border-top-color>
		auxilaryVerifiers[15]=new CSSPropertyVerifier(Arrays.asList("transparent"),Arrays.asList("co"),null,null,true);

		// <background-clip> <background-origin>
		auxilaryVerifiers[61]=new CSSPropertyVerifier(Arrays.asList("border-box", "padding-box", "content-box"),null,null,null,true);
		// <border-radius>
		auxilaryVerifiers[64]=new CSSPropertyVerifier(null,Arrays.asList("le", "pe"),null,null,true);

		// <shadow>
		auxilaryVerifiers[71]=new CSSPropertyVerifier(Arrays.asList("inset"), null, null, null, true);
		auxilaryVerifiers[72]=new CSSPropertyVerifier(null, Arrays.asList("le"), null, null, true);
		auxilaryVerifiers[73]=new CSSPropertyVerifier(null, Arrays.asList("co"), null, null, true);
		auxilaryVerifiers[74]=new CSSPropertyVerifier(null, null, Arrays.asList("72<1,4>"), null, true);
		auxilaryVerifiers[75]=new CSSPropertyVerifier(null, null, Arrays.asList("71a74a73"), null, true);

		// <border-image-source>
		auxilaryVerifiers[76]=new CSSPropertyVerifier(Arrays.asList("none"),Arrays.asList("ur"),null,null,true);

		// <border-image-slice>
		auxilaryVerifiers[68]=new CSSPropertyVerifier(Arrays.asList("auto"),Arrays.asList("le","pe","in"),null,null,true);
		auxilaryVerifiers[77]=new CSSPropertyVerifier(null,null,Arrays.asList("68<1,4>"),null,true);

		// <border-image-repeat>
		auxilaryVerifiers[70]=new CSSPropertyVerifier(Arrays.asList("stretch","repeat","round"),null,null,null,true);
		auxilaryVerifiers[78]=new CSSPropertyVerifier(null,null,Arrays.asList("70<1,2>"),null,true);

		// <text-shadow>
		auxilaryVerifiers[79]=new CSSPropertyVerifier(null, null, Arrays.asList("74a73"), null, true);

		// <spacing-limit>
		auxilaryVerifiers[85]=new CSSPropertyVerifier(Arrays.asList("normal"), Arrays.asList("le","pe"), null, null, true);

		// <text-decoration-line>
		auxilaryVerifiers[100] = new CSSPropertyVerifier(Arrays.asList("underline"), null, null, null, true);
		auxilaryVerifiers[101] = new CSSPropertyVerifier(Arrays.asList("overline"), null, null, null, true);
		auxilaryVerifiers[102] = new CSSPropertyVerifier(Arrays.asList("line-through"), null, null, null, true);
		auxilaryVerifiers[115] = new CSSPropertyVerifier(Arrays.asList("none"),null,null,Arrays.asList("100a101a102"));
		auxilaryVerifiers[116] = new CSSPropertyVerifier(Arrays.asList("blink"), null, null, null, true);
		// <text-decoration-color>
		auxilaryVerifiers[103] = new CSSPropertyVerifier(null, Arrays.asList("co"), null, null, true);
		// <text-decoration-style>
		auxilaryVerifiers[104] = new CSSPropertyVerifier(Arrays.asList("solid", "double", "dotted", "dashed", "wave"), null, null, null, true);

		// <text-emphasis-style>
		auxilaryVerifiers[105]=new CSSPropertyVerifier(Arrays.asList("filled","open"),null,null,null,true);
		auxilaryVerifiers[106]=new CSSPropertyVerifier(Arrays.asList("dot","circle","double-circle","triangle","sesame"),null,null,null,true);
		auxilaryVerifiers[107]=new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.VISUALMEDIA,Arrays.asList("st"),Arrays.asList("105a106"));

		// <align-content> and <justify-content>
		// auto | <baseline-position> | <content-distribution> || [ <overflow-position>? && <content-position> ]
		// <content-position> = center | start | end | flex-start | flex-end | left | right
		auxilaryVerifiers[121] = new CSSPropertyVerifier(Arrays.asList("auto", "baseline", "last-baseline", "space-between", "space-around", "space-evenly", "stretch"), null, null, null, true);
		// <overflow-position>
		auxilaryVerifiers[122] = new CSSPropertyVerifier(Arrays.asList("true", "safe"), null, null, null, true);
		auxilaryVerifiers[123] = new CSSPropertyVerifier(Arrays.asList("center", "start", "end", "flex-start", "flex-end", "left", "right"), null, null, null, true);
		auxilaryVerifiers[124] = new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("122 123", "123", "123 122"), true,true);

		// <align-items>
		// auto | stretch | <baseline-position> | [ <item-position> && <overflow-position>? ]
		auxilaryVerifiers[125] = new CSSPropertyVerifier(Arrays.asList("auto", "stretch", "baseline", "last-baseline"), null, null, null, true);
		// <item-position> = center | start | end | self-start | self-end | flex-start | flex-end | left | right;
		auxilaryVerifiers[126] = new CSSPropertyVerifier(Arrays.asList("center", "start", "end", "self-start", "self-end", "flex-start", "flex-end", "left", "right"), null, null, null, true);
		// [ <item-position> && <overflow-position>? ]
		auxilaryVerifiers[127] = new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("122 126", "126", "126 122"), true,true);

		// <justify-items>
		// auto | stretch | <baseline-position> | [ <item-position> && <overflow-position>? ] | [ legacy && [ left | right | center ] ]
		auxilaryVerifiers[128] = new CSSPropertyVerifier(Arrays.asList("legacy"), null, null, null, true);
		auxilaryVerifiers[129] = new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("4 128", "128 4"), true,true);
		auxilaryVerifiers[130] = new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("122 126", "126", "126 122"), true,true);

		// used in nav-down, nav-left, nav-right and nav-up
		auxilaryVerifiers[143] = new CSSPropertyVerifier(null, Arrays.asList("se"), null, null, true);
		auxilaryVerifiers[144] = new CSSPropertyVerifier(Arrays.asList("current", "root"), Arrays.asList("st"), null, null, true);
	}
	/* This function loads a verifier object in elementVerifiers.
	 * After the object has been loaded, property name is removed from allelementVerifier.
	 */
	private static void addVerifier(String element)
	{
		if ("align-content".equalsIgnoreCase(element)) {
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA, null,Arrays.asList("121a124"), true,true));
			allelementVerifiers.remove(element);
		} else if("align-items".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, Arrays.asList("125", "127"), true, true));
			allelementVerifiers.remove(element);
		} else if("align-self".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(Arrays.asList("auto", "stretch", "baseline", "last-baseline"), ElementInfo.VISUALMEDIA, null, Arrays.asList("127"), true, true));
			allelementVerifiers.remove(element);
		} else if("azimuth".equalsIgnoreCase(element)) {
			auxilaryVerifiers[0]=new CSSPropertyVerifier(Arrays.asList("left-side","far-left","left","center-left","center","center-right","right","far-right","right-side"),null,null,null,true);
			auxilaryVerifiers[1]=new CSSPropertyVerifier(Arrays.asList("behind"),null,null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("leftwards","rightwards"),ElementInfo.AURALMEDIA,Arrays.asList("an"),Arrays.asList("0a1")));
			allelementVerifiers.remove(element);
		}
		else if("background-attachment".equalsIgnoreCase(element)){
			auxilaryVerifiers[60] = new CSSPropertyVerifier(Arrays.asList("local","scroll","fixed"), null, null, null, true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("60<1,65535>"), true,true));
			allelementVerifiers.remove(element);
		}
		else if("background-clip".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("61<1,65535>"), true,true));
			allelementVerifiers.remove(element);

		}
		else if("background-color".equalsIgnoreCase(element)){
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("transparent"),ElementInfo.VISUALMEDIA,Arrays.asList("co")));
			allelementVerifiers.remove(element);

		}
		else if("background-image".equalsIgnoreCase(element)){
			auxilaryVerifiers[56] = new CSSPropertyVerifier(Arrays.asList("none"),Arrays.asList("ur"),null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("56<1,65535>"), true,true));
			allelementVerifiers.remove(element);
		}
		else if("background-origin".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("61<1,65535>"), true,true));
			allelementVerifiers.remove(element);

		}
		else if("background-position".equalsIgnoreCase(element))
		{       // FIXME: css3 http://www.w3.org/TR/css3-background/#background-position
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("2 3?","4a5")));
			allelementVerifiers.remove(element);
		}
		else if("background-repeat".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[57] = new CSSPropertyVerifier(Arrays.asList("repeat","space","round","no-repeat"),null,null,null,true);
			auxilaryVerifiers[58] = new CSSPropertyVerifier(Arrays.asList("repeat-x","repeat-y"), null, null, null, true);
			auxilaryVerifiers[59] = new CSSPropertyVerifier(null, null, Arrays.asList("58","57<1,2>"), null, true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("59<1,65535>"), true,true));
			allelementVerifiers.remove(element);
		}
		else if("background-size".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[61] = new CSSPropertyVerifier(Arrays.asList("auto"),Arrays.asList("le", "pe"),null,null,true);
			auxilaryVerifiers[62] = new CSSPropertyVerifier(Arrays.asList("cover", "contain"), null, null, null, true);
			auxilaryVerifiers[63] = new CSSPropertyVerifier(null, null, Arrays.asList("61<1,2>", "62"), null, true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("63<1,65535>"), true,true));
			allelementVerifiers.remove(element);
		}
		else if("background".equalsIgnoreCase(element))
		{    // FIXME: CSS3 http://www.w3.org/TR/css3-background/#background
			//background-attachment
			auxilaryVerifiers[6]=new CSSPropertyVerifier(Arrays.asList("scroll","fixed"),null,null,null,true);
			//background-color
			auxilaryVerifiers[7]=new CSSPropertyVerifier(Arrays.asList("transparent"),Arrays.asList("co"),null,null,true);
			//background-image
			auxilaryVerifiers[8]=new CSSPropertyVerifier(Arrays.asList("none"),Arrays.asList("ur"),null,null,true);
			//background-position
			auxilaryVerifiers[9]=new CSSPropertyVerifier(null,null,Arrays.asList("2 3?","4a5"),null,true);
			//background-repeat
			auxilaryVerifiers[10]=new CSSPropertyVerifier(Arrays.asList("repeat","repeat-x","repeat-y","no-repeat"),null,null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("6a7a8a9a10")));
			allelementVerifiers.remove(element);
		}
		else if("border-collapse".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("collapse","separate"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);

		}
		else if("border-color".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,Arrays.asList("co"),Arrays.asList("11<1,4>")));
			allelementVerifiers.remove(element);

		}
		else if("border-top-color".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null, null, Arrays.asList("11"), ElementInfo.VISUALMEDIA, true));
			allelementVerifiers.remove(element);
		}
		else if("border-bottom-color".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null, null, Arrays.asList("11"), ElementInfo.VISUALMEDIA, true));
			allelementVerifiers.remove(element);
		}
		else if("border-left-color".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null, null, Arrays.asList("11"), ElementInfo.VISUALMEDIA, true));
			allelementVerifiers.remove(element);
		}
		else if("border-right-color".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null, null, Arrays.asList("11"), ElementInfo.VISUALMEDIA, true));
			allelementVerifiers.remove(element);
		}
		else if("border-spacing".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[12]=new CSSPropertyVerifier(null,Arrays.asList("le"),null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("12 12?")));
			allelementVerifiers.remove(element);
		}
		else if("border-style".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("13<1,4>")));
			allelementVerifiers.remove(element);
		}
		else if("border-top-style".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null, null, Arrays.asList("13"), ElementInfo.VISUALMEDIA, true));
			allelementVerifiers.remove(element);
		}
		else if("border-bottom-style".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null, null, Arrays.asList("13"), ElementInfo.VISUALMEDIA, true));
			allelementVerifiers.remove(element);
		}
		else if("border-left-style".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null, null, Arrays.asList("13"), ElementInfo.VISUALMEDIA, true));
			allelementVerifiers.remove(element);
		}
		else if("border-right-style".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null, null, Arrays.asList("13"), ElementInfo.VISUALMEDIA, true));
			allelementVerifiers.remove(element);
		}
		else if("border-left".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("13a14a15")));
			allelementVerifiers.remove(element);
		}
		else if("border-top".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("13a14a15")));
			allelementVerifiers.remove(element);
		}
		else if("border-right".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("13a14a15")));
			allelementVerifiers.remove(element);
		}
		else if("border-bottom".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("13a14a15")));
			allelementVerifiers.remove(element);
		}
		else if("border-top-color".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("transparent"),ElementInfo.VISUALMEDIA,Arrays.asList("co")));
			allelementVerifiers.remove(element);

		}
		else if("border-right-color".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("transparent"),ElementInfo.VISUALMEDIA,Arrays.asList("co")));
			allelementVerifiers.remove(element);
		}
		else if("border-bottom-color".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("transparent"),ElementInfo.VISUALMEDIA,Arrays.asList("co")));
			allelementVerifiers.remove(element);
		}
		else if("border-left-color".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("transparent"),ElementInfo.VISUALMEDIA,Arrays.asList("co")));
			allelementVerifiers.remove(element);
		}
		else if("border-top-style".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none","hidden","dotted","dashed","solid","double","groove","ridge","inset","outset"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("border-right-style".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none","hidden","dotted","dashed","solid","double","groove","ridge","inset","outset"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("border-bottom-style".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none","hidden","dotted","dashed","solid","double","groove","ridge","inset","outset"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("border-left-style".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none","hidden","dotted","dashed","solid","double","groove","ridge","inset","outset"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("border-top-width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("thin","medium","thick"),ElementInfo.VISUALMEDIA,Arrays.asList("le")));
			allelementVerifiers.remove(element);
		}
		else if("border-right-width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("thin","medium","thick"),ElementInfo.VISUALMEDIA,Arrays.asList("le")));
			allelementVerifiers.remove(element);
		}
		else if("border-bottom-width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("thin","medium","thick"),ElementInfo.VISUALMEDIA,Arrays.asList("le")));
			allelementVerifiers.remove(element);
		}
		else if("border-left-width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("thin","medium","thick"),ElementInfo.VISUALMEDIA,Arrays.asList("le")));
			allelementVerifiers.remove(element);
		}
		else if("border-width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("14<1,4>")));
			allelementVerifiers.remove(element);
		}
		else if("border-top-width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("14")));
			allelementVerifiers.remove(element);
		}
		else if("border-bottom-width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("14")));
			allelementVerifiers.remove(element);
		}
		else if("border-left-width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("14")));
			allelementVerifiers.remove(element);
		}
		else if("border-right-width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("14")));
			allelementVerifiers.remove(element);
		}
		else if("border".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("13a14a15")));
			allelementVerifiers.remove(element);
		}
		else if("border-radius".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[65]=new CSSPropertyVerifier(Arrays.asList("/"),null,null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("64<1,4>", "64<1,4> 65 64<1,4>")));
			allelementVerifiers.remove(element);
		}
		else if("border-top-radius".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("64<1,2>")));
			allelementVerifiers.remove(element);
		}
		else if("border-bottom-radius".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("64<1,2>")));
			allelementVerifiers.remove(element);
		}
		else if("border-left-radius".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("64<1,2>")));
			allelementVerifiers.remove(element);
		}
		else if("border-right-radius".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("64<1,2>")));
			allelementVerifiers.remove(element);
		}
		else if("border-image-source".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("76")));
			allelementVerifiers.remove(element);
		}
		else if("border-image-slice".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[66]=new CSSPropertyVerifier(null,Arrays.asList("pe","in"),null,null,true);
			auxilaryVerifiers[67]=new CSSPropertyVerifier(Arrays.asList("fill"),null,null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("66<1,4> 67?")));
			allelementVerifiers.remove(element);
		}
		else if("border-image-width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("77")));
			allelementVerifiers.remove(element);
		}
		else if("border-image-outset".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[69]=new CSSPropertyVerifier(null,Arrays.asList("le","in"),null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("69<1,4>")));
			allelementVerifiers.remove(element);
		}
		else if("border-image-repeat".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("78")));
			allelementVerifiers.remove(element);
		}
		else if("border-image".equalsIgnoreCase(element))
		{ // FIXME: css3: not sure how to do the rest
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("76a77a78")));
			allelementVerifiers.remove(element);
		}
		else if("bottom".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);

		}
		else if("box-decoration-break".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("slice","clone"),ElementInfo.VISUALMEDIA,null));
			allelementVerifiers.remove(element);

		}
		else if("box-shadow".equalsIgnoreCase(element))
		{ // way more permissive than it should be
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"), ElementInfo.VISUALMEDIA, null, Arrays.asList("75<1,65535>"), true, true));
			allelementVerifiers.remove(element);

		} else if ("box-sizing".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(Arrays.asList("content-box", "border-box"), ElementInfo.VISUALMEDIA, null));
			allelementVerifiers.remove(element);
		} else if ("box-suppress".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(Arrays.asList("show", "discard", "hide"), ElementInfo.VISUALMEDIA, null));
			allelementVerifiers.remove(element);
		}
		else if("caption-side".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("top","bottom"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);

		} else if ("caret-color".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(Arrays.asList("auto", "transparent"), ElementInfo.VISUALMEDIA, Arrays.asList("co")));
			allelementVerifiers.remove(element);
		}
		else if("clear".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none","left","right","both"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("clip".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("sh")));
			allelementVerifiers.remove(element);
		}
                else if("break-after".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto","always","avoid","left","right", "page", "column", "avoid-page", "avoid-column" ),ElementInfo.VISUALPAGEDMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("break-before".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto","always","avoid","left","right", "page", "column", "avoid-page", "avoid-column" ),ElementInfo.VISUALPAGEDMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("break-inside".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto","avoid","avoid-page", "avoid-column"),ElementInfo.VISUALPAGEDMEDIA));
			allelementVerifiers.remove(element);
		}
                else if("column-count".equalsIgnoreCase(element))
                {
                        elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("in")));
			allelementVerifiers.remove(element);
                }
                else if("column-fill".equalsIgnoreCase(element))
                {
                        elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto", "balance"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
                }
                else if("column-gap".equalsIgnoreCase(element))
                {
                        elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("normal"),ElementInfo.VISUALMEDIA,Arrays.asList("le")));
			allelementVerifiers.remove(element);
                }
                else if("column-rule-color".equalsIgnoreCase(element))
                {

			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,Arrays.asList("co")));
			allelementVerifiers.remove(element);
                }
                else if("column-rule-style".equalsIgnoreCase(element))
                {
                        elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("13<1,4>")));
			allelementVerifiers.remove(element);
                }
                else if("column-rule-width".equalsIgnoreCase(element))
                {
                        elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("14<1,4>")));
			allelementVerifiers.remove(element);
                }
		else if("column-rule".equalsIgnoreCase(element))
                {
			// column-rule-width
			auxilaryVerifiers[54] = new CSSPropertyVerifier(null,null,null,Arrays.asList("14<1,4>"));
			// border-style
			auxilaryVerifiers[55] = new CSSPropertyVerifier(null,null,null,Arrays.asList("13<1,4>"));
			// color || transparent 13
                        elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("54a55a15")));
			allelementVerifiers.remove(element);
                }
                else if("column-span".equalsIgnoreCase(element))
                {
                        elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("1", "all"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
                }
                else if("column-width".equalsIgnoreCase(element))
                {
                        elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("le")));
			allelementVerifiers.remove(element);
                }
		else if("columns".equalsIgnoreCase(element))
		{
			// column-width
			auxilaryVerifiers[52]=new CSSPropertyVerifier(Arrays.asList("auto"),Arrays.asList("le"),null,null,true);
			// column-count
			auxilaryVerifiers[53]=new CSSPropertyVerifier(Arrays.asList("auto"),Arrays.asList("in"),null,null,true);

			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("52a53")));
			allelementVerifiers.remove(element);
		}
                else if ("color".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,Arrays.asList("co")));
			allelementVerifiers.remove(element);

		}
		else if ("color-interpolation".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto","sRGB","linearRGB"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);

		}
		else if ("color-rendering".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto","optimizeSpeed","optimizeQuality"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);

		}
		else if("content".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[16]=new ContentPropertyVerifier(Arrays.asList("open-quote","close-quote","no-open-quote", "no-close-quote"));
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("normal","none"),ElementInfo.MEDIA,null,Arrays.asList("16<1,"+ ElementInfo.UPPERLIMIT+">")));
			allelementVerifiers.remove(element);
		}
		else if("counter-increment".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[17]=new CSSPropertyVerifier(null,Arrays.asList("id"),null,null,true);
			auxilaryVerifiers[18]=new CSSPropertyVerifier(null,Arrays.asList("in"),null,null,true);
			auxilaryVerifiers[19]=new CSSPropertyVerifier(null,null,Arrays.asList("17 18?"),null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.MEDIA,null,Arrays.asList("19<1,"+ElementInfo.UPPERLIMIT+">[1,2]")));
			allelementVerifiers.remove(element);
		}
		else if("counter-reset".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[20]=new CSSPropertyVerifier(null,Arrays.asList("id"),null,null,true);
			auxilaryVerifiers[21]=new CSSPropertyVerifier(null,Arrays.asList("in"),null,null,true);
			auxilaryVerifiers[22]=new CSSPropertyVerifier(null,null,Arrays.asList("20 21?"),null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.MEDIA,null,Arrays.asList("22<1,"+ElementInfo.UPPERLIMIT+">[1,2]")));
			allelementVerifiers.remove(element);
		}
		else if("cue-after".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.AURALMEDIA,Arrays.asList("ur")));
			allelementVerifiers.remove(element);

		}
		else if("cue-before".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.AURALMEDIA,Arrays.asList("ur")));
			allelementVerifiers.remove(element);
		}
		else if("cue".equalsIgnoreCase(element))
		{
			//cue-before
			auxilaryVerifiers[23]=new CSSPropertyVerifier(Arrays.asList("none"),Arrays.asList("ur"),null,null,true);
			//cue-after
			auxilaryVerifiers[24]=new CSSPropertyVerifier(Arrays.asList("none"),Arrays.asList("ur"),null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.MEDIA,null,Arrays.asList("23a24")));
			allelementVerifiers.remove(element);

		}
		else if("cursor".equalsIgnoreCase(element))
		{
			// <cursor> = [ [<url> [<x> <y>]?,]*
			// [ auto | default | none |
			//   context-menu | help | pointer | progress | wait |
			//   cell | crosshair | text | vertical-text |
			//   alias | copy | move | no-drop | not-allowed | grab | grabbing |
			//   e-resize | n-resize | ne-resize | nw-resize | s-resize | se-resize | sw-resize | w-resize | ew-resize | ns-resize | nesw-resize | nwse-resize | col-resize | row-resize | all-scroll | zoom-in | zoom-out
			//  ] ]
			auxilaryVerifiers[25]=new CSSPropertyVerifier(null,Arrays.asList("ur"),null,null,true);
			auxilaryVerifiers[141] = new CSSPropertyVerifier(null, Arrays.asList("in", "re"), null, null, true);
			auxilaryVerifiers[142] = new CSSPropertyVerifier(null, null, null, Arrays.asList("25 141 141", "25"), true, true);
			auxilaryVerifiers[26] = new CSSPropertyVerifier(
			Arrays.asList("auto", "default", "none",
					"context-menu", "help", "pointer", "progress", "wait",
					"cell", "crosshair", "text", "vertical-text",
					"alias", "copy", "move", "no-drop", "not-allowed", "grab", "grabbing",
					"e-resize", "n-resize", "ne-resize", "nw-resize", "s-resize", "se-resize", "sw-resize", "w-resize", "ew-resize", "ns-resize", "nesw-resize", "nwse-resize", "col-resize", "row-resize", "all-scroll", "zoom-in", "zoom-out"),null,null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALINTERACTIVEMEDIA,null,Arrays.asList("142<0,"+ElementInfo.UPPERLIMIT+">[1,3] 26"),false,true));
			allelementVerifiers.remove(element);
		}
		else if("direction".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("ltr","rtl"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("display".equalsIgnoreCase(element))
		{
			// [ <display-outside> || <display-inside> ] | <display-listitem> | <display-internal> | <display-box> | <display-legacy>
			// <display-outside>
			auxilaryVerifiers[131] = new CSSPropertyVerifier(Arrays.asList("block", "inline", "run-in"), null, null, null, true);
			// <display-inside>
			auxilaryVerifiers[132] = new CSSPropertyVerifier(Arrays.asList("flow", "flow-root", "table", "flex", "grid", "ruby"), null, null, null, true);
			// list-item
			auxilaryVerifiers[133] = new CSSPropertyVerifier(Arrays.asList("list-item"), null, null, null, true);
			// flow | flow-root
			auxilaryVerifiers[134] = new CSSPropertyVerifier(Arrays.asList("flow", "flow-root"), null, null, null, true);
			// <display-listitem> = list-item && <display-outside>? && [ flow | flow-root ]?
			auxilaryVerifiers[135] = new CSSPropertyVerifier(null, null, Arrays.asList("131?"), null, true);
			auxilaryVerifiers[136] = new CSSPropertyVerifier(null, null, Arrays.asList("134?"), null, true);
			// <display-internal>
			auxilaryVerifiers[137] = new CSSPropertyVerifier(Arrays.asList("table-row-group", "table-header-group", "table-footer-group", "table-row", "table-cell", "table-column-group", "table-column", "table-caption", "ruby-base", "ruby-text", "ruby-base-container", "ruby-text-container"), null, null, null, true);
			// <display-box>
			auxilaryVerifiers[138] = new CSSPropertyVerifier(Arrays.asList("contents", "none"), null, null, null, true);
			// <display-legacy>
			auxilaryVerifiers[139] = new CSSPropertyVerifier(Arrays.asList("inline-block", "inline-list-item", "inline-table", "inline-flex", "inline-grid"), null, null, null, true);

			auxilaryVerifiers[140] = new CSSPropertyVerifier(null, null, Arrays.asList("133b135b136"), null, true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null, null, Arrays.asList("131a132", "140<0,1>[1,3]", "137", "138", "139"), null, true));
			allelementVerifiers.remove(element);
		}
		else if("elevation".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("below","level","above","higher","lower"),ElementInfo.AURALMEDIA,Arrays.asList("an")));
			allelementVerifiers.remove(element);
		}
		else if("empty-cells".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("show","hide"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("float".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("left","right","none"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		} else if ("flex".equalsIgnoreCase(element)) {
			// flex: none | <flex-grow> <flex-shrink>? || <flex-basis>
			// flex-grow and flex-shrink are both integers so we can use one auxilaryVerifier
			auxilaryVerifiers[119] = new CSSPropertyVerifier(null, null, Arrays.asList("in"));
			auxilaryVerifiers[120] = new CSSPropertyVerifier(Arrays.asList("content", "auto"), null, null, null, true);
			elementVerifiers.put(element, new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, Arrays.asList("119a120")));
			allelementVerifiers.remove(element);
		} else if ("flex-basis".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(Arrays.asList("content", "auto"), ElementInfo.VISUALMEDIA, Arrays.asList("le", "pe")));
			allelementVerifiers.remove(element);
		} else if ("flex-direction".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(Arrays.asList("row", "row-reverse", "column", "column-reverse"), ElementInfo.VISUALMEDIA, null));
			allelementVerifiers.remove(element);
		} else if ("flex-flow".equalsIgnoreCase(element)) {
			// flex-flow: <flex-direction> || <flex-wrap>
			// flex-direction:
			auxilaryVerifiers[117] = new CSSPropertyVerifier(Arrays.asList("row", "row-reverse", "column", "column-reverse"), null, null, null, true);
			// flex-wrap:
			auxilaryVerifiers[118] = new CSSPropertyVerifier(Arrays.asList("nowrap", "wrap", "wrap-reverse"), null, null, null, true);
			elementVerifiers.put(element, new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, null, Arrays.asList("117a118")));
			allelementVerifiers.remove(element);
		} else if ("flex-grow".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, Arrays.asList("in")));
			allelementVerifiers.remove(element);
		} else if ("flex-shrink".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, Arrays.asList("in")));
			allelementVerifiers.remove(element);
		} else if ("flex-wrap".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(Arrays.asList("nowrap", "wrap", "wrap-reverse"), ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("font-family".equalsIgnoreCase(element))
		{

			elementVerifiers.put(element,new FontPropertyVerifier(false));
			allelementVerifiers.remove(element);
		}
		else if("font-size".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("xx-small","x-small","small","medium","large","x-large","xx-large","larger","smaller"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("font-style".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("normal","italic","oblique"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("font-variant".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("normal","small-caps"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("font-weight".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("normal","bold","bolder","lighter","100","200","300","400","500","600","700","800","900"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("font".equalsIgnoreCase(element))
		{

			//font-style
			auxilaryVerifiers[27]=new CSSPropertyVerifier(Arrays.asList("normal","italic","oblique"),null,null,null,true);
			//font-variant
			auxilaryVerifiers[28]=new CSSPropertyVerifier(Arrays.asList("normal","small-caps"),null,null,null,true);
			//font-weight
			auxilaryVerifiers[29]=new CSSPropertyVerifier(Arrays.asList("normal","bold","bolder","lighter","100","200","300","400","500","600","700","800","900"),null,null,null,true);
			//30-32
			auxilaryVerifiers[30]=new CSSPropertyVerifier(null,null,Arrays.asList("27a28a29"),null,true);
			/*
			//font-size
			auxilaryVerifiers[31]=new CSSPropertyVerifier(Arrays.asList("xx-small","x-small","small","medium","large","x-large","xx-large","larger","smaller"),null,null,true);
			//line-height
			auxilaryVerifiers[32]=new CSSPropertyVerifier(Arrays.asList("normal"),Arrays.asList("le","pe","re","in"),null,true);

			auxilaryVerifiers[55]=new CSSPropertyVerifier(Arrays.asList("/"),null,null,true);
			auxilaryVerifiers[56]=new CSSPropertyVerifier(null,null,Arrays.asList("55 32"),true);
			 */
			auxilaryVerifiers[31]=new FontPartPropertyVerifier();
			//font-family
			auxilaryVerifiers[59]=new FontPropertyVerifier(true);


			/*
			 * old font family
			auxilaryVerifiers[53]=new CSSPropertyVerifier(ElementInfo.FONTS,null,null,true);
			auxilaryVerifiers[54]=new CSSPropertyVerifier(null,null,Arrays.asList("53 53<0,"+ElementInfo.UPPERLIMIT+">"),true);
			 */
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("caption","icon","menu","message-box","small-caption","status-bar"),ElementInfo.VISUALMEDIA,null,Arrays.asList("30<0,1>[1,3] 31<0,1>[1,3] 59"),false,true));
			//elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("caption","icon","menu","message-box","small-caption","status-bar"),ElementInfo.VISUALMEDIA,null,Arrays.asList("31<1,1>[1,3]")));
			allelementVerifiers.remove(element);
		}
		else if("hanging-punctuation".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[97]=new CSSPropertyVerifier(Arrays.asList("allow-end","force-end"),null,null,null,true);
			auxilaryVerifiers[98]=new CSSPropertyVerifier(Arrays.asList("first"),null,null,null,true);
			auxilaryVerifiers[99]=new CSSPropertyVerifier(Arrays.asList("last"),null,null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.VISUALMEDIA,null,Arrays.asList("97a98a99")));
			allelementVerifiers.remove(element);
		}
		else if("height".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		} else if ("justify-content".equalsIgnoreCase(element)) {
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("121a124"), true,true));
			allelementVerifiers.remove(element);
		} else if ("justify-items".equalsIgnoreCase(element)) {
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("125", "130", "129"), true,true));
			allelementVerifiers.remove(element);
		} else if ("justify-self".equalsIgnoreCase(element)) {
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto", "stretch", "baseline", "last-baseline"), ElementInfo.VISUALMEDIA, null, Arrays.asList("127"), true, true));
			allelementVerifiers.remove(element);
		}
		else if("left".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("letter-spacing".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,null,ElementInfo.VISUALMEDIA,Arrays.asList("85<1,3>")));
			allelementVerifiers.remove(element);
		}
		else if("line-height".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("normal"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe","re","in")));
			allelementVerifiers.remove(element);
		}
		else if("line-break".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto","newspaper","normal","strict","keep-all"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("list-style-image".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.VISUALMEDIA,Arrays.asList("ur")));
			allelementVerifiers.remove(element);
		}
		else if("list-style-position".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("inside","outside"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("list-style-type".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("disc","circle","square","decimal","decimal-leading-zero","lower-roman","upper-roman","lower-greek","lower-latin","upper-latin","armenian","georgian","lower-alpha","upper-alpha","none"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("list-style".equalsIgnoreCase(element))
		{
			//list-style-image
			auxilaryVerifiers[33]=new CSSPropertyVerifier(Arrays.asList("none"),Arrays.asList("ur"),null,null,true);
			//list-style-position
			auxilaryVerifiers[34]=new CSSPropertyVerifier(Arrays.asList("inside","outside"),null,null,null,true);
			//list-style-type
			auxilaryVerifiers[35]=new CSSPropertyVerifier(Arrays.asList("disc","circle","square","decimal","decimal-leading-zero","lower-roman","upper-roman","lower-greek","lower-latin","upper-latin","armenian","georgian","lower-alpha","upper-alpha","none"),null,null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("33a34a35")));
			allelementVerifiers.remove(element);
		}
		else if("margin-right".equalsIgnoreCase(element))
		{
			//margin-width=Length|Percentage|Auto
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("margin-left".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("margin-top".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("margin-bottom".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("margin".equalsIgnoreCase(element))
		{
			//margin-width
			auxilaryVerifiers[36]=new CSSPropertyVerifier(Arrays.asList("auto"),Arrays.asList("le","pe"),null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("36<1,4>")));
			allelementVerifiers.remove(element);
		}
		else if("max-height".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("max-width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("min-height".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("min-width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		} else if ("nav-down".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(Arrays.asList("auto"), ElementInfo.VISUALINTERACTIVEMEDIA, null, Arrays.asList("143 144?")));
			allelementVerifiers.remove(element);
		} else if ("nav-left".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(Arrays.asList("auto"), ElementInfo.VISUALINTERACTIVEMEDIA, null, Arrays.asList("143 144?")));
			allelementVerifiers.remove(element);
		} else if ("nav-right".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(Arrays.asList("auto"), ElementInfo.VISUALINTERACTIVEMEDIA, null, Arrays.asList("143 144?")));
			allelementVerifiers.remove(element);
		} else if ("nav-up".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(Arrays.asList("auto"), ElementInfo.VISUALINTERACTIVEMEDIA, null, Arrays.asList("143 144?")));
			allelementVerifiers.remove(element);
		}
		else if("opacity".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALPAGEDMEDIA,Arrays.asList("re")));
			allelementVerifiers.remove(element);
		} else if ("order".equalsIgnoreCase(element)) {
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALPAGEDMEDIA,Arrays.asList("in")));
			allelementVerifiers.remove(element);
		}
		else if("orphans".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALPAGEDMEDIA,Arrays.asList("in")));
			allelementVerifiers.remove(element);
		}
		else if("outline-color".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("invert"),ElementInfo.VISUALINTERACTIVEMEDIA,Arrays.asList("co")));
			allelementVerifiers.remove(element);
		} else if ("outline-offset".equalsIgnoreCase(element)) {
			elementVerifiers.put(element, new CSSPropertyVerifier(null, ElementInfo.VISUALMEDIA, Arrays.asList("le")));
			allelementVerifiers.remove(element);
		}
		else if("outline-style".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none","hidden","dotted","dashed","solid","double","groove","ridge","inset","outset"),ElementInfo.VISUALINTERACTIVEMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("outline-width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("thin","medium","thick"),ElementInfo.VISUALINTERACTIVEMEDIA,Arrays.asList("le")));
			allelementVerifiers.remove(element);
		}
		else if("outline".equalsIgnoreCase(element))
		{
			//outline-color
			auxilaryVerifiers[37]=new CSSPropertyVerifier(Arrays.asList("invert"),Arrays.asList("co"),null,null,true);
			//outline-style
			auxilaryVerifiers[38]=new CSSPropertyVerifier(Arrays.asList("none","hidden","dotted","dashed","solid","double","groove","ridge","inset","outset"),null,null,null,true);
			//outline-width
			auxilaryVerifiers[39]=new CSSPropertyVerifier(Arrays.asList("thin","medium","thick"),Arrays.asList("le"),null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALINTERACTIVEMEDIA,Arrays.asList("le"),Arrays.asList("37a38a39")));
			allelementVerifiers.remove(element);
		}
		else if("overflow".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("visible","hidden","scroll","auto"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("padding-top".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);

		}
		else if("padding-right".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("padding-bottom".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("padding-left".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("padding".equalsIgnoreCase(element))
		{
			//padding-width
			auxilaryVerifiers[40]=new CSSPropertyVerifier(null,Arrays.asList("le","pe"),null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("40<1,4>")));
			allelementVerifiers.remove(element);
		}
		else if("page-break-after".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto","always","avoid","left","right"),ElementInfo.VISUALPAGEDMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("page-break-before".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto","always","avoid","left","right"),ElementInfo.VISUALPAGEDMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("page-break-inside".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto","avoid"),ElementInfo.VISUALPAGEDMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("pause-after".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.AURALMEDIA,Arrays.asList("ti","pe")));
			allelementVerifiers.remove(element);
		}
		else if("pause-before".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.AURALMEDIA,Arrays.asList("ti","pe")));
			allelementVerifiers.remove(element);
		}
		else if("pause".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[41]=new CSSPropertyVerifier(null,Arrays.asList("ti","pe"),null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,null,null,Arrays.asList("41<1,2>")));
			allelementVerifiers.remove(element);

		}
		else if("pitch-range".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.AURALMEDIA,Arrays.asList("in","re")));
			allelementVerifiers.remove(element);
		}
		else if("pitch".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("x-low","low","medium","high","x-high"),ElementInfo.AURALMEDIA,Arrays.asList("fr")));
			allelementVerifiers.remove(element);

		}
		else if("play-during".equalsIgnoreCase(element))
		{

			auxilaryVerifiers[42]=new CSSPropertyVerifier(null,Arrays.asList("ur"),null,null,true);
			auxilaryVerifiers[43]=new CSSPropertyVerifier(Arrays.asList("mix"),null,null,null,true);
			auxilaryVerifiers[44]=new CSSPropertyVerifier(Arrays.asList("repeat"),null,null,null,true);
			auxilaryVerifiers[45]=new CSSPropertyVerifier(null,null,Arrays.asList("43a44"),null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto","none"),ElementInfo.AURALMEDIA,null,Arrays.asList("42 45<0,1>[1,2]")));
			allelementVerifiers.remove(element);


		}
		else if("punctuation-trim".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[86]=new CSSPropertyVerifier(Arrays.asList("start"),null,null,null,true);
			auxilaryVerifiers[87]=new CSSPropertyVerifier(Arrays.asList("end","allow-end"),null,null,null,true);
			auxilaryVerifiers[88]=new CSSPropertyVerifier(Arrays.asList("adjacent"),null,null,null,true);
			auxilaryVerifiers[89]=new CSSPropertyVerifier(null,null,Arrays.asList("86a87a88"),null,true);

			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.AURALMEDIA,null,Arrays.asList("89")));
			allelementVerifiers.remove(element);
		}
		else if("position".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("static","relative","absolute","fixed"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("quotes".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[46]=new CSSPropertyVerifier(null,Arrays.asList("st"),null,null,true);
			auxilaryVerifiers[47]=new CSSPropertyVerifier(null,null,Arrays.asList("46 46"),null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),null,ElementInfo.VISUALMEDIA,Arrays.asList("47<1,"+ ElementInfo.UPPERLIMIT+">[2,2]")));
			allelementVerifiers.remove(element);
		} else if ("resize".equalsIgnoreCase(element)) {
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none", "both", "horizontal", "vertical"),ElementInfo.VISUALMEDIA,null));
			allelementVerifiers.remove(element);
		}
		else if("richness".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.AURALMEDIA,Arrays.asList("re","in")));
			allelementVerifiers.remove(element);
		}
		else if("right".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("speak-header".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("once","always"),ElementInfo.AURALMEDIA));
			allelementVerifiers.remove(element);

		}
		else if("speak-numeral".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("digits","continuous"),ElementInfo.AURALMEDIA));
			allelementVerifiers.remove(element);

		}
		else if("speak-punctuation".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("code", "none"),ElementInfo.AURALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("speak".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("normal","none","spell-out"),ElementInfo.AURALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("speech-rate".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("x-slow","slow","medium","fast","x-fast","faster","slower"),ElementInfo.AURALMEDIA,Arrays.asList("re","in")));
			allelementVerifiers.remove(element);
		}
		else if("stress".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.AURALMEDIA,Arrays.asList("re","in")));
			allelementVerifiers.remove(element);
		}
		else if("table-layout".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier( Arrays.asList("auto","fixed"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("text-align".equalsIgnoreCase(element))
		{  // FIXME: We don't support "one character" as the spec says http://www.w3.org/TR/css3-text/#text-align0
			elementVerifiers.put(element,new CSSPropertyVerifier( Arrays.asList("start","end","left","right","center","justify","match-parent"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("text-align-last".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("start","end","left","right","center","justify"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("text-autospace".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[90]=new CSSPropertyVerifier(Arrays.asList("ideograph-numeric"),null,null,null,true);
			auxilaryVerifiers[91]=new CSSPropertyVerifier(Arrays.asList("ideograph-alpha"),null,null,null,true);
			auxilaryVerifiers[92]=new CSSPropertyVerifier(Arrays.asList("ideograph-space"),null,null,null,true);
			auxilaryVerifiers[93]=new CSSPropertyVerifier(Arrays.asList("ideograph-parenthesis"),null,null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.VISUALMEDIA,null,Arrays.asList("90a91a92a93")));
			allelementVerifiers.remove(element);

		}
		else if("text-decoration".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("115a103a104a116")));
			allelementVerifiers.remove(element);

		}
		else if("text-decoration-color".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("103")));
			allelementVerifiers.remove(element);

		}
		else if("text-decoration-line".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.VISUALMEDIA,null,Arrays.asList("100a101a102")));
			allelementVerifiers.remove(element);

		}
		else if("text-decoration-skip".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[48]=new CSSPropertyVerifier(Arrays.asList("images"),null,null,null,true);
			auxilaryVerifiers[49]=new CSSPropertyVerifier(Arrays.asList("spaces"),null,null,null,true);
			auxilaryVerifiers[50]=new CSSPropertyVerifier(Arrays.asList("ink"),null,null,null,true);
			auxilaryVerifiers[51]=new CSSPropertyVerifier(Arrays.asList("all"),null,null,null,true);

			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.VISUALMEDIA,null,Arrays.asList("48a49a50a51")));
			allelementVerifiers.remove(element);
		}
		else if("text-decoration-style".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("104")));
			allelementVerifiers.remove(element);

		}
		else if("text-emphasis".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("103a107")));
			allelementVerifiers.remove(element);

		}
		else if("text-emphasis-color".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("103")));
			allelementVerifiers.remove(element);

		}
		else if("text-emphasis-position".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("over","under"),ElementInfo.VISUALMEDIA,null,null));
			allelementVerifiers.remove(element);

		}
		else if("text-emphasis-style".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("107")));
			allelementVerifiers.remove(element);

		}
		else if("text-indent".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[94]=new CSSPropertyVerifier(Arrays.asList("hanging", "each-line"),null,null,null,true);
			auxilaryVerifiers[95]=new CSSPropertyVerifier(null,null,Arrays.asList("94<0,2>"),null,true);
			auxilaryVerifiers[96]=new CSSPropertyVerifier(null,Arrays.asList("le","pe"),null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("96 95")));
			allelementVerifiers.remove(element);
		}
		else if("text-justify".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[83]=new CSSPropertyVerifier(Arrays.asList("inter-word","inter-ideograph","inter-cluster","distribute","kashida"),null,null,null,true);
			auxilaryVerifiers[84]=new CSSPropertyVerifier(Arrays.asList("trim"),null,null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,null,Arrays.asList("84a83")));
			allelementVerifiers.remove(element);
		}
		else if("text-outline".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[108]=new CSSPropertyVerifier(null,null,Arrays.asList("73 72 72<0,1>"),null,true);
			auxilaryVerifiers[109]=new CSSPropertyVerifier(null,null,Arrays.asList("72 72<0,1> 73"),null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.VISUALMEDIA,null,Arrays.asList("108a109")));
			allelementVerifiers.remove(element);
		}
		else if("text-overflow".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("clip","ellipsis"),ElementInfo.VISUALMEDIA,Arrays.asList("st")));
			allelementVerifiers.remove(element);
		}
		else if("text-shadow".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("none"),ElementInfo.VISUALMEDIA,null,Arrays.asList("79<0,65535>"),true,true));
			allelementVerifiers.remove(element);
		}
		else if("text-transform".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier( Arrays.asList("capitalize","uppercase","lowercase","none","fullwidth","large-kana"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("text-underline-position".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier( Arrays.asList("auto","under","alphabetic","over"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("text-wrap".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier( Arrays.asList("normal","unrestricted","none","suppress"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("top".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier( Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("transform".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[110]=new CSSPropertyVerifier(null,Arrays.asList("tr"),null,null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("110<0,65536>"),true, true));
			allelementVerifiers.remove(element);
		}
		else if("transform-origin".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[111]=new CSSPropertyVerifier(null,null,Arrays.asList("2 3<0,1>"),null,true);
			auxilaryVerifiers[112]=new CSSPropertyVerifier(Arrays.asList("left","center","right"),null,null,null,true);
			auxilaryVerifiers[113]=new CSSPropertyVerifier(Arrays.asList("top","center","bottom"),null,null,null,true);
			auxilaryVerifiers[114]=new CSSPropertyVerifier(null,null,Arrays.asList("112a113"),null,true);

			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,null,Arrays.asList("111","114"),true, true));
			allelementVerifiers.remove(element);
		}
		else if("unicode-bidi".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier( Arrays.asList("normal", "embed", "bidi-override"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("vertical-align".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("baseline","sub","super","top","text-top","middle","bottom","text-bottom"),ElementInfo.VISUALMEDIA,Arrays.asList("pe","le")));
			allelementVerifiers.remove(element);
		}
		else if("visibility".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("visible","hidden","collapse"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("voice-family".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new VoiceFamilyPropertyVerifier(false));
			allelementVerifiers.remove(element);
		}
		else if("volume".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("silent","x-soft","soft","medium","loud","x-loud"),ElementInfo.AURALMEDIA,Arrays.asList("re","le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("white-space".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("normal","pre","nowrap","pre-wrap","pre-line"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("white-space-collapsing".equalsIgnoreCase(element))
		{
			auxilaryVerifiers[80]=new CSSPropertyVerifier(Arrays.asList("preserve","preserve-break"),null,null,null,true);
			auxilaryVerifiers[81]=new CSSPropertyVerifier(Arrays.asList("trim-inner"),null,null,null,true);
			auxilaryVerifiers[82]=new CSSPropertyVerifier(null,null,Arrays.asList("80a81"),null,true);
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("collapse" ,"discard"),null,ElementInfo.VISUALMEDIA,Arrays.asList("82")));
			allelementVerifiers.remove(element);
		}
		else if("widows".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,ElementInfo.VISUALMEDIA,Arrays.asList("in")));
			allelementVerifiers.remove(element);
		}
		else if("width".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("le","pe")));
			allelementVerifiers.remove(element);
		}
		else if("word-break".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("normal","break-all","hyphenate"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("word-spacing".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(null,null,ElementInfo.VISUALMEDIA,Arrays.asList("85<1,3>")));
			allelementVerifiers.remove(element);
		}
		else if("word-wrap".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("normal", "break-word"),ElementInfo.VISUALMEDIA));
			allelementVerifiers.remove(element);
		}
		else if("z-index".equalsIgnoreCase(element))
		{
			elementVerifiers.put(element,new CSSPropertyVerifier(Arrays.asList("auto"),ElementInfo.VISUALMEDIA,Arrays.asList("in")));
			allelementVerifiers.remove(element);
		}
	}


	/*
	 * This function returns the Verifier for a property. If it is not already loaded in the elementVerifier, then it is loaded and then returned to the caller.
	 * FIXME: Lazy init probably doesn't make sense, but while we are initting lazily, we need to hold a lock here.
	 */
	private synchronized static CSSPropertyVerifier getVerifier(String element)
	{
		element=element.toLowerCase();
		if(elementVerifiers.get(element)!=null)
			return elementVerifiers.get(element);
		else if(allelementVerifiers.contains(element))
		{
			addVerifier(element);
			return elementVerifiers.get(element);
		}
		else
			return null;
	}
	/*
	 * This function accepts media, list of HTML elements, CSS property and value and determines whether it is valid or not.
	 * @media print
	 * {
	 * h1, h2 , h4, h4 {font-size: 10pt}
	 * }
	 * media: print
	 * elements: [h1, h2, h3, h4]
	 * token: font-size
	 * value: 10pt
	 *
	 */
	private boolean verifyToken(String[] media,String[] elements,CSSPropertyVerifier obj,ParsedWord[] words)
	{
		if(words == null) return false;
		if(logDEBUG) Logger.debug(this, "verifyToken for "+CSSPropertyVerifier.toString(words));
		if(obj==null)
		{
			return false;
		}
		int important = checkImportant(words);
		if(important > 0) {
			if(words.length == important) return true; // Eh? !important on its own!
			words = Arrays.copyOf(words, words.length-important);
		}
		return obj.checkValidity(media, elements, words, cb);

	}

	private int checkImportant(ParsedWord[] words) {
		if(words.length == 0) return 0;
		if(words.length >= 1 && words[words.length-1] instanceof SimpleParsedWord) {
			if(((SimpleParsedWord)words[words.length-1]).original.equalsIgnoreCase("!important")) return 1;
		}
		if(words.length >= 2 && words[words.length-1] instanceof ParsedIdentifier && words[words.length-2] instanceof SimpleParsedWord) {
			if(((SimpleParsedWord)words[words.length-2]).original.equals("!") &&
				((ParsedIdentifier)words[words.length-1]).original.equalsIgnoreCase("important"))
				return 2;
		}
		return 0;
	}

	/*
	 * This function accepts an HTML element(along with class name, ID, pseudo class and attribute selector) and determines whether it is valid or not.
	 * Returns null on failure (invalid selector), empty string on banned (but otherwise valid) selector.
	 * @param elementName A selector which may include an HTML element.
	 * @param isIDSelector True if we only allow an ID selector, which must include an ID, may
	 * include an element name or *, but must not contain anything else.
	 */
	public static String HTMLelementVerifier(String elementString, boolean isIDSelector)
	{
		if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "varifying element/selector: \""+elementString+"\"");
		String HTMLelement="",pseudoClass="",className="",id="";
		StringBuilder fBuffer=new StringBuilder();
		ArrayList<String> attSelections = null;
		while(elementString.indexOf('[')!=-1 && elementString.indexOf(']')!=-1 && (elementString.indexOf('[')<elementString.indexOf(']')))
		{
		    if(isIDSelector) return null;
			String attSelection=elementString.substring(elementString.indexOf('[')+1,elementString.indexOf(']')).trim();
			StringBuilder buf=new StringBuilder(elementString);
			buf.delete(elementString.indexOf('['), elementString.indexOf(']')+1);
			elementString=buf.toString();
			if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "attSelection="+attSelection+"  elementString="+elementString);
			if(attSelections == null) attSelections = new ArrayList<String>();
			attSelections.add(attSelection);
		}
		if(elementString.indexOf(':')!=-1)
		{
		    if(isIDSelector) return null;
			int index=elementString.indexOf(':');
			if(index!=elementString.length()-1)
			{
				pseudoClass=elementString.substring(index+1,elementString.length()).trim();
				HTMLelement=elementString.substring(0,index).trim();
				if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "pseudoclass="+pseudoClass+" HTMLelement="+HTMLelement);
			}
			else
			{
				HTMLelement=elementString.trim();
			}
		}
		else
			HTMLelement=elementString.trim();

		if(HTMLelement.indexOf('.')!=-1)
		{
		    if(isIDSelector) return null;
			int index=HTMLelement.indexOf('.');
			if(index!=HTMLelement.length()-1)
			{
				className=HTMLelement.substring(index+1,HTMLelement.length()).trim();
				HTMLelement=HTMLelement.substring(0,index).trim();
				if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "class="+className+" HTMLelement="+HTMLelement);
			}

		}
		else if(HTMLelement.indexOf('#')!=-1)
		{
		    // Allowed in an ID selector.
			int index=HTMLelement.indexOf('#');
			if(index!=HTMLelement.length()-1)
			{
				id=HTMLelement.substring(index+1,HTMLelement.length()).trim();
				HTMLelement=HTMLelement.substring(0,index).trim();
				if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "id="+id+" element="+HTMLelement);
			}

		}
		if(isIDSelector && "".equals(id)) return null; // No ID

		boolean elementValid =
		    "*".equals(HTMLelement) ||
		    (ElementInfo.isValidHTMLTag(HTMLelement.toLowerCase())) ||
		    ("".equals(HTMLelement.trim()) &&
                    ((!className.equals("")) || (!id.equals("")) || attSelections!=null ||
                            !pseudoClass.equals("")));
		if(!elementValid) return null;
		
		if(!className.equals("")) {
		    // Note that the definition of isValidName() allows chained classes because it allows . in class names.
		    if(!ElementInfo.isValidName(className))
		        return null;
		} else if(!id.equals("")) {
		    if(!ElementInfo.isValidName(id))
		        return null;
		}

		if(!pseudoClass.equals("")) {
		    if(!ElementInfo.isValidPseudoClass(pseudoClass)) {
		        return null;
		    } else if(ElementInfo.isBannedPseudoClass(pseudoClass)) {
		        return "";
		    }
		}

		if(attSelections!=null) {
		    String[] attSelectionParts;

		    for(String attSelection : attSelections) {
		        if(attSelection.indexOf("|=")!=-1) {
		            attSelectionParts=new String[2];
		            attSelectionParts[0]=attSelection.substring(0,attSelection.indexOf("|="));
		            attSelectionParts[1]=attSelection.substring(attSelection.indexOf("|=")+2,
		                    attSelection.length());
		        } else if(attSelection.indexOf("~=")!=-1) {
		            attSelectionParts=new String[2];
		            attSelectionParts[0]=attSelection.substring(0,attSelection.indexOf("~="));
		            attSelectionParts[1]=attSelection.substring(attSelection.indexOf("~=")+2,
		                    attSelection.length());
		        } else if(attSelection.indexOf('=') != -1){
		            attSelectionParts=new String[2];
		            attSelectionParts[0]=attSelection.substring(0,attSelection.indexOf('='));
		            attSelectionParts[1]=attSelection.substring(attSelection.indexOf('=')+1,
		                    attSelection.length());
		        } else {
		            attSelectionParts=new String[] { attSelection };
		        }

		        //Verifying whether each character is alphanumeric or _
		        if(logDEBUG) Logger.debug(CSSTokenizerFilter.class,
		                "HTMLelementVerifier length of attSelectionParts="+
		                attSelectionParts.length);

		        if(attSelectionParts[0].length()==0)
		            return null;
		        else {
		            char c=attSelectionParts[0].charAt(0);
		            if(!((c>='a' && c<='z') || (c>='A' && c<='Z')))
		                return null;
		            for(int i=1;i<attSelectionParts[0].length();i++) {
		                if(!((c>='a' && c<='z') || (c>='A' && c<='Z') || c=='_' || c=='-'))
		                    return null;
		            }
		        }

		        if(attSelectionParts.length > 1) {
		            // What about the right hand side?
		            // The grammar says it's an IDENT.
		            if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "RHS is \""+
		                    attSelectionParts[1]+"\"");
		            if(!(ElementInfo.isValidIdentifier(attSelectionParts[1]) ||
		                    ElementInfo.isValidStringWithQuotes(attSelectionParts[1])))
		                return null;
		        }
		    }
		}

		fBuffer.append(HTMLelement);
		if(!className.equals("")) {
		    fBuffer.append('.');
		    fBuffer.append(className);
		} else if(!id.equals("")) {
		    fBuffer.append('#');
		    fBuffer.append(id);
		}
		if(!pseudoClass.equals("")) {
		    fBuffer.append(':');
		    fBuffer.append(pseudoClass);
		}
		if(attSelections!=null) {
		    for(String attSelection:attSelections) {
		        fBuffer.append('[');
		        fBuffer.append(attSelection);
		        fBuffer.append(']');
		    }
		}
		return fBuffer.toString();
	}

	/*
	 * This function works with different operators, +, >, " " and verifies each HTML element with HTMLelementVerifier(String elementString)
	 * e.g. div > p:first-child
	 * This would call HTMLelementVerifier with div and p:first-child
	 * Returns null on failure (selector invalid), empty string on banned but otherwise valid selector.
	 */
	public String recursiveSelectorVerifier(String selectorString)
	{
		if (logDEBUG) Logger.debug(this, "selector: \""+selectorString+"\"");
		selectorString=selectorString.trim();

		// Parse but don't tokenise.

		int index = -1;
		char selector = 0;

		char c;
		char quoting = 0;
		boolean escaping = false;
		int bracketing = 0;
		boolean eatLF = false;
		int escapedDigits = 0;
		for(int i=0;i<selectorString.length();i++) {
			c = selectorString.charAt(i);
			if(c == '+' && quoting == 0 && !escaping && bracketing == 0) {
				if(index == -1 || index == i-1 && selector == ' ') {
					index = i;
					selector = c;
				}
			} else if(c == '>' && quoting == 0 && !escaping) {
				if(index == -1 || index == i-1 && selector == ' ') {
					index = i;
					selector = c;
				}
			} else if(c == ' ' && quoting == 0 && !escaping) {
				if(index == -1 || index == i-1 && selector == ' ') {
					index = i;
					selector = c;
				}
			} else if(c == '(' && quoting == 0 && !escaping) {
				bracketing += 1;
			} else if(c == ')' && quoting == 0 && !escaping) {
				bracketing -= 1;
			} else if(c == '\'' && quoting == 0 && !escaping) {
				quoting = c;
			} else if(c == '\"' && quoting == 0 && !escaping) {
				quoting = c;
			} else if(c == quoting && !escaping) {
				quoting = 0;
			} else if(c == '\n' && eatLF) {
				// Ok
				escaping = false;
				eatLF = false;
			} else if((c == '\r' || c == '\n' || c == '\f') && !(quoting != 0 && escaping)) {
				// No newlines unless in a string *and* quoted!
				if(logDEBUG) Logger.debug(this, "no newlines unless in a string *and* quoted at index "+i);
				return null;
			} else if(c == '\r' && escaping && escapedDigits == 0) {
				escaping = false;
				eatLF = true;
			} else if((c == '\n' || c == '\f') && escaping) {
				if(escapedDigits == 0)
					escaping = false;
				else {
					if(logDEBUG) Logger.debug(this, "invalid newline escaping at char "+i);
					return null; // Invalid
				}
			} else if(escaping && ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
				escapedDigits++;
				if(escapedDigits == 6)
					escaping = false;
			} else if(escaping && escapedDigits > 0 && (" \t\r\n\f".indexOf(c) != -1)) {
				escaping = false;
				if(c == '\r') eatLF = true;
			} else if(c == '\\' && !escaping) {
				escaping = true;
			} else if(c == '\\' && escaping && escapedDigits > 0) {
				if(logDEBUG) Logger.debug(this, "backslash but already escaping with digits at char "+i);
				return null; // Invalid
			} else if(c == '\\' && escaping) {
				escaping = false;
			} else if(escaping) {
				// Any other character can be escaped.
				escaping = false;
			}
			eatLF = false;
		}

		if(logDEBUG) Logger.debug(this, "index="+index+" quoting="+quoting+" selector="+selector+" for \""+selectorString+"\"");

		if(quoting != 0) return null; // Mismatched quotes
		if(bracketing != 0) return null; // Mismatched brackets

		if(index == -1)
			return HTMLelementVerifier(selectorString, false);

		String[] parts=new String[2];

		parts[0]=selectorString.substring(0,index).trim();
		parts[1]=selectorString.substring(index+1,selectorString.length()).trim();
		if(logDEBUG) Logger.debug(this, "recursiveSelectorVerifier parts[0]=" + parts[0]+" parts[1]="+parts[1]);
		parts[0]=HTMLelementVerifier(parts[0], false);
		parts[1]=recursiveSelectorVerifier(parts[1]);
		if(parts[0]!=null && parts[1]!=null)
			return parts[0]+selector+parts[1];
		else
			return null;

	}



	// main function
	public void parse() throws IOException {

		final int STATE1=1; //State corresponding to @page,@media etc
		final int STATE2=2; //State corresponding to HTML element like body
		final int STATE3=3; //State corresponding to CSS properties

		/* e.g.
		 * STATE1
		 * @media screen {
		 * STATE2	STATE3
		 * h2 		{text-align:left;}
		 * }
		 */
		final int STATECOMMENT=4;
		final int STATE1INQUOTE=5;
		final int STATE2INQUOTE=6;
		final int STATE3INQUOTE=7;
		char currentQuote='"';
		int stateBeforeComment=0;
		int currentState=1;
		boolean isState1Present=false;
		String elements[]=null;
		StringBuilder filteredTokens=new StringBuilder();
		StringBuilder buffer=new StringBuilder();
		int openBraces=0;
		String defaultMedia="screen";
		String[] currentMedia=new String[] {defaultMedia};
		String propertyName="",propertyValue="";
		boolean ignoreElementsS1=false,ignoreElementsS2=false,ignoreElementsS3=false, closeIgnoredS2=false;
		int x;
		char c=0,prevc=0;
		boolean s2Comma=false;
		boolean canImport=true; //import statement can occur only in the beginning

		String whitespaceAfterColon = "";
		String whitespaceBeforeProperty = "";

		boolean charsetPossible = true;
		boolean bomPossible = true;
		int openBracesStartingS3 = 0;
		boolean forPage = false;

		if(isInline) {
			currentState = STATE3;
		}

		while(true)
		{
			try
			{
				x=r.read();
			}
			catch(IOException e)
			{
				throw e;
			}

			if(x==-1)
			{
				if(currentState == STATE3 && c != ';' && !propertyName.isEmpty() && propertyValue.isEmpty()) {
					// Finish off the current property.
					// Common for e.g. HTML: style='background-image:url(blah)'
					x = ';';
				} else {
					break;
				}
			}
			if(x == (char) 0xFEFF) {
				if(bomPossible) {
					// BOM
					if(logDEBUG) Logger.debug(this, "Ignoring BOM");
					w.write(x);
				}
				continue;
			}
			bomPossible = false;
			prevc=c;
			c=(char) x;
			if(logDEBUG) Logger.debug(this, "Read: "+c+ " 0x"+Integer.toHexString(c));
			if(prevc=='/' && c=='*' && currentState!=STATE1INQUOTE && currentState!=STATE2INQUOTE && currentState!=STATE3INQUOTE&&currentState!=STATECOMMENT)
			{
				stateBeforeComment=currentState;
				currentState=STATECOMMENT;
				if(buffer.charAt(buffer.length()-1)=='/')
				{
					buffer.deleteCharAt(buffer.length()-1);
				}
				if(logDEBUG) Logger.debug(this, "Comment detected: buffer="+buffer);
				prevc = 0;
			}
			if(c == 0)
				continue; // Strip nulls
			switch(currentState)
			{
			case STATE1:
				switch(c){
				case '\n':
				case ' ':
				case '\t':
					buffer.append(c);
					if(logDEBUG) Logger.debug(this, "STATE1 CASE whitespace: "+c);
					break;

				case '@':
					if(prevc != '\\') {
						isState1Present=true;
						if(logDEBUG) Logger.debug(this, "STATE1 CASE @: "+c);
					}
					buffer.append(c);
					break;

				case '{':
					charsetPossible=false;
					if(stopAtDetectedCharset)
						return;
					if(prevc == '\\') {
						// Leave in buffer, encoded.
						buffer.append(c);
						break;
					}
					openBraces++;
					isState1Present=false;

					int i = 0;
					for(i=0;i<buffer.length();i++) {
						char c1 = buffer.charAt(i);
						if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
							continue;
						break;
					}
					String braceSpace = buffer.substring(0, i);
					buffer.delete(0, i);
					if(buffer.length() > 4 && buffer.substring(0, 4).equals("<!--")) {
						braceSpace +=buffer.substring(0, 4);
						if(" \t\r\n".indexOf(buffer.charAt(4))==-1) {
							Logger.error(this, "<!-- not followed by whitespace!");
							return;
						}
						buffer.delete(0, 4);
						for(i=0;i<buffer.length();i++) {
							char c1 = buffer.charAt(i);
							if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
								continue;
							break;
						}
						braceSpace += buffer.substring(0, i);
						buffer.delete(0, i);
					}
					for(i=buffer.length()-1;i>=0;i--) {
						char c1 = buffer.charAt(i);
						if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
							continue;
						break;
					}
					i++;
					String postSpace = buffer.substring(i);
					buffer.setLength(i);
					String orig = buffer.toString().trim();
					ParsedWord[] parts=split(orig, false);
					if(logDEBUG) Logger.debug(this, "Split: "+CSSPropertyVerifier.toString(parts));
					buffer.setLength(0);
					boolean valid = false;
					if(parts != null) {
					if(parts.length<1)
					{
						ignoreElementsS1=true;
						if(logDEBUG) Logger.debug(this, "STATE1 CASE {: Does not have one part. ignoring "+buffer.toString());
						valid = false;
					}
					else if(parts[0] instanceof SimpleParsedWord && "@media".equals(((SimpleParsedWord)parts[0]).original.toLowerCase()))
					{
						if(parts.length<2)
						{
							ignoreElementsS1=true;
							if(logDEBUG) Logger.debug(this, "STATE1 CASE {: Does not have two parts. ignoring "+buffer.toString());
							valid = false;
						} else {
						ArrayList<String> medias = commaListFromIdentifiers(parts, 1);
						if(medias != null && medias.size() > 0) {
							for(i=0;i<medias.size();i++) {
								if(!FilterUtils.isMedia(medias.get(i))) {
									// Unrecognised media, don't pass it.
									medias.remove(i);
									i--; // Don't skip next
								}
							}
						}
						if(medias != null && medias.size() > 0) {
							filteredTokens.append(braceSpace);
							filteredTokens.append("@media ");
							boolean first = true;
							for(String media : medias) {
								if(!first) filteredTokens.append(", ");
								first = false;
								filteredTokens.append(media);
							}
							filteredTokens.append(postSpace);
							filteredTokens.append("{");
							valid = true;
							currentMedia = medias.toArray(new String[medias.size()]);
						}
						}
					} else if(parts[0] instanceof SimpleParsedWord && "@page".equals(((SimpleParsedWord)parts[0]).original.toLowerCase()))
						{
						if(parts.length == 0) {
							valid = true;
						} else {
							valid = true;
							for(int j=1;j<parts.length;j++) {
								if(!(parts[j] instanceof SimpleParsedWord)) {
									valid = false;
									break;
								} else {
									String s = ((SimpleParsedWord)parts[j]).original;
									if(!(s.equalsIgnoreCase(":left") || s.equalsIgnoreCase(":right") || s.equals(":first"))) {
										valid = false;
										break;
									}
								}
							}
						}
						if(valid) {
							forPage = true;
							filteredTokens.append(braceSpace);
							filteredTokens.append(orig);
							filteredTokens.append(postSpace);
							filteredTokens.append("{");
						}
					}
					} // else valid = false
					if(!valid)
					{
						ignoreElementsS1=true;
						// No valid media types.
						if(logDEBUG) Logger.debug(this, "STATE1 CASE {: Failed verification test. ignoring "+buffer.toString());
					} else {
						w.write(filteredTokens.toString());
						filteredTokens.setLength(0);
					}
					buffer.setLength(0);
					s2Comma=false;
					if(forPage) {
						currentState=STATE3;
						openBracesStartingS3 = openBraces;
					} else {
						currentState=STATE2;
					}
					buffer.setLength(0);
					break;
				case ';':
					if(prevc == '\\') {
						// Leave in buffer, encoded.
						buffer.append(c);
						break;
					}
					if(logDEBUG) Logger.debug(this, "buffer in state 1 ; : \""+buffer.toString()+"\"");
					//should be @import

					for(i=0;i<buffer.length();i++) {
						char c1 = buffer.charAt(i);
						if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
							continue;
						break;
					}
					w.write(buffer.substring(0, i));
					buffer.delete(0, i);

					if(buffer.length() > 4 && buffer.substring(0, 4).equals("<!--")) {
						w.write(buffer.substring(0, 4));
						if(" \t\r\n".indexOf(buffer.charAt(4))==-1) {
							Logger.error(this, "<!-- not followed by whitespace!");
							return;
						}
						buffer.delete(0, 4);
						for(i=0;i<buffer.length();i++) {
							char c1 = buffer.charAt(i);
							if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
								continue;
							break;
						}
						w.write(buffer.substring(0, i));
						buffer.delete(0, i);
					}

					// If ignoreElementsS1, then just delete everything up to the semicolon. After that, fresh start.
					if(canImport && !ignoreElementsS1 && buffer.toString().contains("@import"))
					{
						if(logDEBUG) Logger.debug(this, "STATE1 CASE ;statement="+buffer.toString());

						String strbuffer=buffer.toString().trim();
						int importIndex=strbuffer.toLowerCase().indexOf("@import");
						if("".equals(strbuffer.substring(0,importIndex).trim()))
						{
							String str1=strbuffer.substring(importIndex+7,strbuffer.length());
							ParsedWord[] strparts=split(str1, false);
							if(strparts != null && strparts.length > 0 && (strparts[0] instanceof ParsedURL || strparts[0] instanceof ParsedString)) {
								String uri;
								if(strparts[0] instanceof ParsedString) {
									uri = ((ParsedString)strparts[0]).getDecoded();
								} else {
									uri = ((ParsedURL)strparts[0]).getDecoded();
								}
								ArrayList<String> medias = commaListFromIdentifiers(strparts, 1);

								if(medias != null) { // None gives [0], broke gives null
									StringBuilder output = new StringBuilder();
									output.append("@import url(\"");
									try {
										// Add ?maybecharset= even though there might be a ?type= with a charset, we will ignore maybecharset if there is.
										// We behave similarly in <link rel=stylesheet...> if there is a ?type= in the URL.
										String s = cb.processURI(uri, "text/css");
										if(passedCharset != null) {
											if(s.indexOf('?') == -1)
												s += "?maybecharset="+passedCharset;
											else
												s += "&maybecharset="+passedCharset;
										}
										output.append(s);
										output.append("\")");
										boolean first = true;
										for(String media : medias) {
											if(FilterUtils.isMedia(media)) {
												if(!first) output.append(", ");
												else output.append(' ');
												first = false;
												output.append(media);
											}
										}
										output.append(";");
										w.write(output.toString());
									} catch (CommentException e) {
										// Don't write anything
									}
								}
							}
						}
					} else if(charsetPossible && buffer.toString().startsWith("@charset ")) {
						// charsetPossible is incompatible with ignoreElementsS1
						String s = buffer.delete(0, "@charset ".length()).toString();
						s = removeOuterQuotes(s);
						detectedCharset = s;
						if(logDEBUG) Logger.debug(this, "Detected charset: \""+detectedCharset+"\"");
						if(!Charset.isSupported(detectedCharset)) {
							Logger.normal(this, "Charset not supported: "+detectedCharset);
							throw new UnsupportedCharsetInFilterException("Charset not supported: "+detectedCharset);
						}
						if(stopAtDetectedCharset) return;
						if(passedCharset != null && !detectedCharset.equalsIgnoreCase(passedCharset)) {
							Logger.normal(this, "Detected charset \""+detectedCharset+"\" differs from passed in charset \""+passedCharset+"\"");
							throw new IOException("Detected charset differs from passed in charset");
						}
						w.write("@charset \""+detectedCharset+"\";");
					}
					isState1Present=false;
					ignoreElementsS1 = false;
					buffer.setLength(0);
					charsetPossible=false;
					break;
				case '"':
				case '\'':
					if(prevc == '\\') {
						// Leave in buffer, encoded.
						buffer.append(c);
						break;
					}
					buffer.append(c);
					currentState=STATE1INQUOTE;
					currentQuote=c;
					break;
				default:
					buffer.append(c);
				if(!isState1Present)
				{
					String s = buffer.toString().trim();
					if(!(s.equals("") || s.equals("/") || s.equals("<") || s.equals("<!") || s.equals("<!-") || s.equals("<!--")))
						currentState=STATE2;
				}
				if(logDEBUG) Logger.debug(this, "STATE1 default CASE: "+c);
				break;

				}
				break;

			case STATE1INQUOTE:
				if(logDEBUG) Logger.debug(this, "STATE1INQUOTE: "+c);
				switch(c)
				{
				case '"':
					if(currentQuote=='"' && prevc!='\\')
						currentState=STATE1;
					buffer.append(c);
					break;
				case '\'':
					if(currentQuote=='\'' && prevc!='\\')
						currentState=STATE1;
					buffer.append(c);
					break;
				case '\n':
					if(prevc == '\r') {
						break;
					}
					// Otherwise same as \r ...
				case '\f':
				case '\r':
					if(prevc != '\\') {
						ignoreElementsS1 = true;
						currentState = STATE1;
						break;
					} else {
						// Wipe out the \ as well.
						buffer.setLength(buffer.length()-1);
						break;
					}
				default:
					buffer.append(c);
				break;
				}
				break;


			case STATE2:
				canImport=false;
				charsetPossible=false;
				if(stopAtDetectedCharset)
					return;
				switch(c)
				{
				case '{':
					if(prevc == '\\') {
						// Leave in buffer, encoded.
						buffer.append(c);
						break;
					}

					int i = 0;
					for(i=0;i<buffer.length();i++) {
						char c1 = buffer.charAt(i);
						if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
							continue;
						break;
					}
					if(logDEBUG) Logger.debug(this, "Appending whitespace in state2: \""+buffer.substring(0,i)+"\"");
					String ws = buffer.substring(0, i);
					buffer.delete(0, i);

					if(buffer.length() > 4 && buffer.substring(0, 4).equals("<!--")) {
						ws+=buffer.substring(0, 4);
						if(" \t\r\n".indexOf(buffer.charAt(4))==-1) {
							Logger.error(this, "<!-- not followed by whitespace!");
							return;
						}
						buffer.delete(0, 4);
						for(i=0;i<buffer.length();i++) {
							char c1 = buffer.charAt(i);
							if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
								continue;
							break;
						}
						ws+=buffer.substring(0, i);
						buffer.delete(0, i);
					}

					openBraces++;
					if(!buffer.toString().trim().equals(""))
					{
						String filtered=recursiveSelectorVerifier(buffer.toString());
						if(filtered!=null && !"".equals(filtered))
						{
							if(s2Comma)
							{
								filteredTokens.append(",");
								s2Comma=false;
							}
							filteredTokens.append(ws);
							filteredTokens.append(filtered);
							filteredTokens.append(" {");
						}
						else if(s2Comma && "".equals(filtered))
						{
							// There was a comma, so filteredTokens already contains some tokens.
							// The current selector is valid, yet banned. Ignore it.
							s2Comma=false;
							filteredTokens.append(ws);
							filteredTokens.append(" {");
						}
						else
						{
							ignoreElementsS2=true;
							// If there was a comma, filteredTokens may contain some tokens.
							// These are invalid, as per the spec: we wipe the whole selector out.
							// Also, not wiping filteredTokens here does bad things:
							// we would write the filtered tokens, without the { or }, so we end up prepending it to the next rule, which is not what we want as it changes the next rule's meaning.
							filteredTokens.setLength(0);
						}
						if(logDEBUG) Logger.debug(this, "STATE2 CASE { filtered elements"+filtered);
					} else {
						// No valid selector, wipe it out as above.
						ignoreElementsS2=true;
						// If there was a comma, filteredTokens may contain some tokens.
						// These are invalid, as per the spec: we wipe the whole selector out.
						// Also, not wiping filteredTokens here does bad things:
						// we would write the filtered tokens, without the { or }, so we end up prepending it to the next rule, which is not what we want as it changes the next rule's meaning.
						filteredTokens.setLength(0);
					}
					currentState=STATE3;
					openBracesStartingS3 = openBraces;
					if(logDEBUG) Logger.debug(this, "STATE2 -> STATE3, openBracesStartingS3 = "+openBracesStartingS3);
					buffer.setLength(0);
					break;

				case ',':
					if(prevc == '\\') {
						// Leave in buffer, encoded.
						buffer.append(c);
						break;
					}
					for(i=0;i<buffer.length();i++) {
						char c1 = buffer.charAt(i);
						if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
							continue;
						break;
					}
					if(logDEBUG) Logger.debug(this, "Appending whitespace in state2: \""+buffer.substring(0,i)+"\"");
					ws = buffer.substring(0, i);
					buffer.delete(0, i);

					if(!s2Comma) {
						if(buffer.length() > 4 && buffer.substring(0, 4).equals("<!--")) {
							filteredTokens.append(buffer.substring(0, 4));
							if(" \t\r\n".indexOf(buffer.charAt(4))==-1) {
								Logger.error(this, "<!-- not followed by whitespace!");
								return;
							}
							buffer.delete(0, 4);
							for(i=0;i<buffer.length();i++) {
								char c1 = buffer.charAt(i);
								if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
									continue;
								break;
							}
							filteredTokens.append(buffer.substring(0, i));
							buffer.delete(0, i);
						}
					}


					String filtered=recursiveSelectorVerifier(buffer.toString().trim());
					if(logDEBUG) Logger.debug(this, "STATE2 CASE , filtered elements"+filtered);
					if(filtered!=null && !"".equals(filtered))
					{
						if(s2Comma)
							filteredTokens.append(",");
						else
							s2Comma=true;
						filteredTokens.append(ws);
						filteredTokens.append(filtered);
					}
					else if("".equals(filtered))
					{
						// This selector was banned. Ignore it.
						filteredTokens.append(ws);
					}
					buffer.setLength(0);
					break;


				case '}':
					if(prevc == '\\') {
						// Leave in buffer, encoded.
						buffer.append(c);
						break;
					}
					if(openBraces > 0 && !ignoreElementsS1) {
						openBraces--;
						// ignoreElementsS2 is irrelevant here, we are not *adding to* filteredTokens.
						if(openBraces >= 0)
							filteredTokens.append('}');
						else
							openBraces = 0;
						if(logDEBUG) Logger.debug(this, "Writing \""+filteredTokens+"\"");
						w.write(filteredTokens.toString());
					} else {
						if(openBraces > 0) openBraces--;
						// Ignore.
						// We are going back to STATE1, so reset ignoreElementsS1
						ignoreElementsS1 = false;
					}
					filteredTokens.setLength(0);
					buffer.setLength(0);
					currentMedia=new String[] {defaultMedia};
					isState1Present=false;
					currentState=STATE1;
					if(isInline) return;
					if(logDEBUG) Logger.debug(this, "STATE2 CASE }: "+c);
					break;

				case '"':
				case '\'':
					if(prevc == '\\') {
						// Leave in buffer, encoded.
						buffer.append(c);
						break;
					}
					buffer.append(c);
					currentState=STATE2INQUOTE;
					currentQuote=c;
					break;

				default:
					buffer.append(c);
				if(logDEBUG) Logger.debug(this, "STATE2 default CASE: "+c);
				break;
				}
				break;

			case STATE2INQUOTE:
				if(logDEBUG) Logger.debug(this, "STATE2INQUOTE: "+c);
				charsetPossible=false;
				switch(c)
				{
				case '"':
					if(currentQuote=='"'&& prevc!='\\')
						currentState=STATE2;
					buffer.append(c);
					break;
				case '\'':
					if(currentQuote=='\''&& prevc!='\\')
						currentState=STATE2;
					buffer.append(c);
					break;
				case '\n':
					if(prevc == '\r') {
						break;
					}
					// Otherwise same as \r ...
				case '\f':
				case '\r':
					if(prevc != '\\') {
						ignoreElementsS2 = true;
						closeIgnoredS2 = true;
						currentState = STATE2;
						break;
					} else {
						// Wipe out the \ as well.
						buffer.setLength(buffer.length()-1);
						break;
					}
				default:
					buffer.append(c);
				break;
				}
				break;

			case STATE3:
				charsetPossible=false;
				if(stopAtDetectedCharset)
					return;
				switch(c)
				{
				case ':':
					if(prevc == '\\') {
						// Leave in buffer, encoded.
						buffer.append(c);
						break;
					}
					if(openBraces > openBracesStartingS3) {
						// Correctly tokenise bogus properties containing {}'s, see CSS2.1 section 4.1.6.
						buffer.append(c);
						if(logDEBUG) Logger.debug(this, "openBraces now "+openBraces+" not moving on because openBracesStartingS3="+openBracesStartingS3+" in S3");
						break;
					}
					int i = 0;
					for(i=0;i<buffer.length();i++) {
						char c1 = buffer.charAt(i);
						if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
							continue;
						break;
					}
					if(logDEBUG) Logger.debug(this, "Appending whitespace: "+buffer.substring(0,i));
					whitespaceBeforeProperty = buffer.substring(0, i);
					propertyName=buffer.delete(0, i).toString().trim();
					if(logDEBUG) Logger.debug(this, "Property name: "+propertyName);
					buffer.setLength(0);
					if(logDEBUG) Logger.debug(this, "STATE3 CASE :: "+c);
					break;

				case ';':
					if(prevc == '\\') {
						// Leave in buffer, encoded.
						buffer.append(c);
						break;
					}
					if(openBraces > openBracesStartingS3) {
						// Correctly tokenise bogus properties containing {}'s, see CSS2.1 section 4.1.6.
						buffer.append(c);
						if(logDEBUG) Logger.debug(this, "openBraces now "+openBraces+" not moving on because openBracesStartingS3="+openBracesStartingS3+" in S3");
						break;
					}

					i = 0;
					for(i=0;i<buffer.length();i++) {
						char c1 = buffer.charAt(i);
						if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
							continue;
						break;
					}
					if(logDEBUG) Logger.debug(this, "Appending whitespace after colon: \""+buffer.substring(0,i)+"\"");
					whitespaceAfterColon = buffer.substring(0, i);
					propertyValue=buffer.delete(0, i).toString().trim();
					if(logDEBUG) Logger.debug(this, "Property value: "+propertyValue);
					buffer.setLength(0);

					CSSPropertyVerifier obj=getVerifier(propertyName);
					if(obj != null) {
					ParsedWord[] words = split(propertyValue, obj.allowCommaDelimiters);
					if(logDEBUG) Logger.debug(this, "Split: "+CSSPropertyVerifier.toString(words));
					if(words != null && !ignoreElementsS2 && !ignoreElementsS3 && verifyToken(currentMedia,elements,obj,words))
					{
						if(changedAnything(words)) propertyValue = reconstruct(words);
						filteredTokens.append(whitespaceBeforeProperty);
						whitespaceBeforeProperty = "";
						filteredTokens.append(propertyName);
                                                filteredTokens.append(':');
                                                filteredTokens.append(whitespaceAfterColon);
                                                filteredTokens.append(propertyValue);
                                                filteredTokens.append(';');
						if(logDEBUG) Logger.debug(this, "STATE3 CASE ;: appending "+ propertyName+":"+propertyValue);
						if(logDEBUG) Logger.debug(this, "filtered tokens now: \""+filteredTokens.toString()+"\"");
					} else {
						if(logDEBUG) Logger.debug(this, "filtered tokens now (ignored): \""+filteredTokens.toString()+"\" words="+CSSPropertyVerifier.toString(words)+" ignoreS1="+ignoreElementsS1+" ignoreS2="+ignoreElementsS2+" ignoreS3="+ignoreElementsS3);
					}
					} else {
						if(logDEBUG) Logger.debug(this, "No such property name \""+propertyName+"\"");
					}
					ignoreElementsS3 = false;
					propertyName="";
					propertyValue="";
					break;
				case '}':
					if(prevc == '\\') {
						// Leave in buffer, encoded.
						buffer.append(c);
						break;
					}
					openBraces--;
					if(openBraces > openBracesStartingS3-1) {
						// Correctly tokenise bogus properties containing {}'s, see CSS2.1 section 4.1.6.
						buffer.append(c);
						if(logDEBUG) Logger.debug(this, "openBraces now "+openBraces+" not moving on because openBracesStartingS3="+openBracesStartingS3+" in S3");
						if(openBraces < 0) openBraces = 0;
						break;
					}
					if(openBraces < 0) openBraces = 0;
					for(i=buffer.length()-1;i>=0;i--) {
						char c1 = buffer.charAt(i);
						if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
							continue;
						break;
					}
					i++;
					String postSpace = buffer.substring(i);
					buffer.setLength(i);
					// This (string!=) is okay as we set it directly by propertyName="" to indicate there is no property name.
					if(propertyName!="")
					{

						i = 0;
						for(i=0;i<buffer.length();i++) {
							char c1 = buffer.charAt(i);
							if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
								continue;
							break;
						}
						if(logDEBUG) Logger.debug(this, "Appending whitespace after colon (}): "+buffer.substring(0,i));
						whitespaceAfterColon = buffer.substring(0, i);
						buffer.delete(0, i);

						propertyValue=buffer.toString().trim();
						if(logDEBUG) Logger.debug(this, "Property value: "+propertyValue);
						buffer.setLength(0);

						obj=getVerifier(propertyName);
						if(logDEBUG) Logger.debug(this, "Found PropertyName:"+propertyName+" propertyValue:"+propertyValue);
						if(obj != null) {
							ParsedWord[] words = split(propertyValue,obj.allowCommaDelimiters);
							if(logDEBUG) Logger.debug(this, "Split: "+CSSPropertyVerifier.toString(words));
							if(!ignoreElementsS2 && !ignoreElementsS3 && verifyToken(currentMedia,elements,obj,words))
							{
								if(changedAnything(words)) propertyValue = reconstruct(words);
								filteredTokens.append(whitespaceBeforeProperty);
								whitespaceBeforeProperty = "";
								filteredTokens.append(propertyName);
                                                                filteredTokens.append(':');
                                                                filteredTokens.append(whitespaceAfterColon);
                                                                filteredTokens.append(propertyValue);
								if(logDEBUG) Logger.debug(this, "STATE3 CASE }: appending "+ propertyName+":"+propertyValue);
							}
						} else {
							if(logDEBUG) Logger.debug(this, "No such property name \""+propertyName+"\"");
						}
						propertyName="";
					} else {
						// Whitespace at end
						i = 0;
						for(i=0;i<buffer.length();i++) {
							char c1 = buffer.charAt(i);
							if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
								continue;
							break;
						}
						if(logDEBUG) Logger.debug(this, "Appending whitespace after colon (}): "+buffer.substring(0,i));
						filteredTokens.append(buffer.substring(0, i));
						buffer.delete(0, i);

					}
					ignoreElementsS3 = false;
					if((!ignoreElementsS2) || closeIgnoredS2) {
						filteredTokens.append(postSpace);
						filteredTokens.append("}");
						closeIgnoredS2 = false;
						ignoreElementsS2 = false;
					} else
						ignoreElementsS2=false;
					if(!ignoreElementsS1) {
						w.write(filteredTokens.toString());
						if(logDEBUG) Logger.debug(this, "writing filtered tokens: \""+filteredTokens.toString()+"\"");
					}
					filteredTokens.setLength(0);
					whitespaceAfterColon = "";
					if(forPage) {
						forPage = false;
						currentState = STATE1;
					} else {
						currentState=STATE2;
					}
					if(isInline) return;
					buffer.setLength(0);
					s2Comma=false;
					if(logDEBUG) Logger.debug(this, "STATE3 CASE }: "+c);
					break;

				case '{':
					// Correctly tokenise invalid properties including {}, see CSS2 section 4.1.6.
					openBraces++;
					buffer.append(c);
					if(logDEBUG) Logger.debug(this, "openBraces now "+openBraces+" in S3");
					break;
				case '"':
				case '\'':
					if(prevc == '\\') {
						// Leave in buffer, encoded.
						buffer.append(c);
						break;
					}
					buffer.append(c);
					currentState=STATE3INQUOTE;
					currentQuote=c;
					break;

				default:
					buffer.append(c);
				if(logDEBUG) Logger.debug(this, "STATE3 default CASE : "+c);
				break;

				}
				break;

			case STATE3INQUOTE:
				charsetPossible=false;
				if(stopAtDetectedCharset)
					return;
				if(logDEBUG) Logger.debug(this, "STATE3INQUOTE: "+c);
				switch(c)
				{
				case '"':
					if(currentQuote=='"'&& prevc!='\\')
						currentState=STATE3;
					buffer.append(c);
					break;
				case '\'':
					if(currentQuote=='\''&& prevc!='\\')
						currentState=STATE3;
					buffer.append(c);
					break;
				case '\n':
					if(prevc == '\r') {
						break;
					}
					// Otherwise same as \r ...
				case '\r':
				case '\f':
					if(prevc != '\\') {
						ignoreElementsS3 = true;
						currentState = STATE3;
						break;
					} else {
						// Wipe out the \ as well.
						buffer.setLength(buffer.length()-1);
						break;
					}
				default:
					buffer.append(c);
				break;
				}
				break;

			case STATECOMMENT:
				// FIXME sanitize (remove potentially dangerous chars) and preserve comments.
				charsetPossible=false;
				if(stopAtDetectedCharset)
					return;
				switch(c)
				{
				case '/':
					if(prevc=='*')
					{
						currentState=stateBeforeComment;
						c = 0;
						if(logDEBUG) Logger.debug(this, "Exiting the comment state "+currentState);
					}
					break;
				}
				break;
			}
		}

		if(logDEBUG) Logger.debug(this, "Filtered tokens: \""+filteredTokens+"\"");
		w.write(filteredTokens.toString());
		for(int i=0;i<openBraces;i++)
			w.write('}');

		if(logDEBUG) Logger.debug(this, "Remaining buffer: \""+buffer+"\"");

		int i = 0;
		for(i=0;i<buffer.length();i++) {
			char c1 = buffer.charAt(i);
			if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
				continue;
			break;
		}
		w.write(buffer.substring(0, i));
		buffer.delete(0, i);

		while(buffer.toString().trim().equals("-->")) {
			w.write("-->");
			buffer.delete(0, 3);
			for(i=0;i<buffer.length();i++) {
				char c1 = buffer.charAt(i);
				if(c1 == ' ' || c1 == '\f' || c1 == '\t' || c1 == '\r' || c1 == '\n')
					continue;
				break;
			}
			w.write(buffer.substring(0, i));
			buffer.delete(0, i);
		}

		// FIXME CSS2.1 section 4.2 "Unexpected end of style sheet".
		// We do NOT auto-close at the end.
		// It might be worth implementing this one day.

	}

	private String reconstruct(ParsedWord[] words) {
		StringBuilder sb = new StringBuilder();
		boolean first = true;
		ParsedWord lastWord = null;
		for(ParsedWord word : words) {
			if(lastWord != null && lastWord.postComma)
				sb.append(',');
			lastWord = word;
			if(!first) sb.append(" ");
			if(!word.changed) {
				sb.append(word.original);
				if(logDEBUG) Logger.debug(this, "Adding word (original): \""+word.original+"\"");
			} else {
				sb.append(word.encode(false)); // FIXME check if charset is full unicode, if so pass true
				if(logDEBUG) Logger.debug(this, "Adding word (new): \""+word.encode(false)+"\"");
			}
			first = false;
		}
		if(logDEBUG) Logger.debug(this, "Reconstructed: \""+sb.toString()+"\"");
		return sb.toString();
	}


	private boolean changedAnything(ParsedWord[] words) {
		for(ParsedWord word : words) {
			if(word.changed) return true;
		}
		return false;
	}


	private ArrayList<String> commaListFromIdentifiers(ParsedWord[] strparts, int offset) {
		ArrayList<String> medias = new ArrayList<String>(strparts.length-1);
		if(strparts.length <= offset) {
			// Nothing to munch
		} else if(strparts.length == offset+1 && strparts[1] instanceof ParsedIdentifier) {
			medias.add(((ParsedIdentifier)strparts[1]).getDecoded());
		} else {
			boolean first = true;
			for(ParsedWord word : strparts) {
				if(first) {
					first = false;
					continue;
				}
				if(word instanceof ParsedIdentifier) {
					medias.add(((ParsedIdentifier)word).getDecoded());
				} else if(word instanceof SimpleParsedWord) {
					String data = ((SimpleParsedWord)word).original;
					String[] split = FilterUtils.removeWhiteSpace(data.split(","),false);
                                        medias.addAll(Arrays.asList(split));
				} else return null;
			}
		}
		return medias;
	}

	static abstract class ParsedWord {

		final String original;
		/** Has decoded changed? If not we can use the original. */
		protected boolean changed;
		public boolean postComma;

		public ParsedWord(String original, boolean changed) {
			this.original = original;
			this.changed = changed;
		}

		public String encode(boolean unicode) {
			if(!changed)
				return original;
			else {
				StringBuilder out = new StringBuilder();
				innerEncode(unicode, out);
				return out.toString();
			}
		}

                @Override
		public String toString() {
			return super.toString()+":\""+original+"\"";
		}

		abstract protected void innerEncode(boolean unicode, StringBuilder out);

	}

	/** Note that this does not represent functionThingy's.
	 * counter() for example can contain a string, it is difficult to
	 * determine whether to encode strings if we don't know they are strings!
	 * This only handles keywords and strings.
	 */
	static abstract class BaseParsedWord extends ParsedWord {
		private String decoded;

		/**
		 * @param original
		 * @param decoded
		 * @param changed Set this to true if we don't like the original
		 * encoding and have changed something during decode.
		 */
		BaseParsedWord(String original, String decoded, boolean changed) {
			super(original, changed);
			this.decoded = decoded;
		}

		@Override
		protected void innerEncode(boolean unicode, StringBuilder out) {
			char prevc = 0;
			char c = 0;
			for(int i=0;i<decoded.length();i++) {
				prevc = c;
				c = decoded.charAt(i);
				if(!mustEncode(c, i, prevc, unicode)) {
					out.append(c);
				} else {
					encodeChar(c, out);
				}
			}
		}

		abstract protected boolean mustEncode(char c, int i, char prevc, boolean unicode);

		private void encodeChar(char c, StringBuilder sb) {
			String s = Integer.toHexString(c);
			sb.append('\\');
			if(s.length() == 6)
				sb.append(s);
			else if(s.length() > 6)
				throw new IllegalStateException();
			else {
				int x = 6 - s.length();
				for(int i=0;i<x;i++)
					sb.append('0');
				sb.append(s);
			}
		}

		public String getDecoded() {
			return decoded;
		}

		public void setNewValue(String s) {
			this.changed = true;
			this.decoded = s;
		}

	}

	static class ParsedIdentifier extends BaseParsedWord {

		ParsedIdentifier(String original, String decoded, boolean changed) {
			super(original, decoded, changed);
		}

		@Override
		protected boolean mustEncode(char c, int i, char prevc, boolean unicode) {
			// It is an identifier.
			if((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
					(c >= '0' && c <= '9') || c == '-' || c == '_'
						|| (c >= (char)0x00A1 && unicode)) {
				// Cannot start with a digit or a hyphen followed by a digit.
				if(!((i == 0 && (c >= '0' && c <= '9')) ||
						(i == 1 && prevc == '-' &&
								(c >= '0' && c <= '9'))))
					return false;
			}
			return true;
		}

	}

	static class ParsedString extends BaseParsedWord {

		ParsedString(String original, String decoded, boolean changed, char stringChar) {
			super(original, decoded, changed);
			this.stringChar = stringChar;
		}

		/** Is the word quoted? If true, the word is completely enclosed
		 * by the given string character (either ' or "), which are not
		 * included in the decoded string. */
		final char stringChar;

		@Override
		protected boolean mustEncode(char c, int i, char prevc, boolean unicode) {
			// It is a string.
			// Anything is allowed in a string...
			if(c == '\r' || c == '\n' || c == '\f')
				// Except newlines.
				return true;
			else if(c == stringChar)
				// And the quote itself.
				return true;
			else if(c < 32 || (c >= (char)0x0080 && !unicode))
				// And control chars, and anything outside Basic Latin (unless we know the output charset is unicode-complete).
				return true;
			return false;
		}

                @Override
		protected void innerEncode(boolean unicode, StringBuilder out) {
			out.append(stringChar);
			super.innerEncode(unicode, out);
			out.append(stringChar);
		}

	}

	static class ParsedURL extends ParsedString {

		ParsedURL(String original, String decoded, boolean changed, char stringChar) {
			super(original, decoded, changed || stringChar == 0, stringChar == 0 ? '"' : stringChar);
		}

                @Override
		protected void innerEncode(boolean unicode, StringBuilder out) {
			out.append("url(");
			super.innerEncode(unicode, out);
			out.append(')');
		}

		public void setNewURL(String s) {
			super.setNewValue(s);
		}

	}

	static class ParsedAttr extends ParsedIdentifier {

		ParsedAttr(String original, String decoded, boolean changed) {
			super(original, decoded, changed);
		}

                @Override
		protected void innerEncode(boolean unicode, StringBuilder out) {
			out.append("attr(");
			super.innerEncode(unicode, out);
			out.append(')');
		}

	}

	/** Simple parsed word, doesn't need encoding, won't be changed. Used
	 * for lengths, percentages, angles, etc. All characters must be safe
	 * and non-problematic. This is used for everything from lengths and
	 * percentages to rgb(...) with spaces in it. Anything we don't
	 * understand gets a SimpleParsedWord.
	 * */
	static class SimpleParsedWord extends ParsedWord {

		public SimpleParsedWord(String original) {
			super(original, false);
		}

		@Override
		protected void innerEncode(boolean unicode, StringBuilder out) {
			out.append(original);
		}

	}

	/** Counters need special handling, partly because they contain
	 * attributes and strings. */
	static class ParsedCounter extends ParsedWord {
		public ParsedCounter(String original, ParsedIdentifier identifier, ParsedIdentifier listType, ParsedString separatorString) {
			super(original, true);
			this.identifier = identifier;
			this.listType = listType;
			this.separatorString = separatorString;
		}

		private final ParsedIdentifier identifier;
		private final ParsedIdentifier listType;
		private final ParsedString separatorString;

		@Override
		protected void innerEncode(boolean unicode, StringBuilder out) {
			if(separatorString != null)
				out.append("counters(");
			else
				out.append("counter(");
			identifier.innerEncode(unicode, out);
			if(separatorString != null) {
				out.append(", ");
				separatorString.innerEncode(unicode, out);
			}
			if(listType != null) {
				out.append(", ");
				listType.innerEncode(unicode, out);
			}
			out.append(')');
			if(postComma) out.append(',');
		}

		protected boolean addComma() {
			return false;
		}

	}

	/** Split up a string, taking into account CSS rules for escaping,
	 * strings, identifiers.
	 * @param str1
	 * @return
	 */
	private static ParsedWord[] split(String input, boolean allowCommaDelimiters) {
		if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "Splitting \""+input+"\" allowCommaDelimiters="+allowCommaDelimiters);
		ArrayList<ParsedWord> words = new ArrayList<ParsedWord>();
		ParsedWord lastWord = null;
		char c = 0;
		// ", ' or 0 (not in string)
		char stringchar = 0;
		boolean escaping = false;
		/** Eat the next linefeed due to an escape closing. We turned the
		 * \r into a space, so we just ignore the \n. */
		boolean eatLF = false;
		/** The original token */
		StringBuilder origToken = new StringBuilder(input.length());
		/** The decoded token */
		StringBuilder decodedToken = new StringBuilder(input.length());
		/** We don't like the original token, it bends the spec in unacceptable ways */
		boolean dontLikeOrigToken = false;
		StringBuilder escape = new StringBuilder(6);
		boolean couldBeIdentifier = true;
		boolean addComma = false;
		// Brackets prevent tokenisation, see e.g. rgb().
		int bracketCount = 0;
		for(int i=0;i<input.length();i++) {
			c = input.charAt(i);
			if(stringchar == 0) {
				if(eatLF && c == '\n') {
					eatLF = false;
					continue;
				} else
					eatLF = false;
				// Not in a string
				if(!escaping) {
					if((" \t\r\n\f".indexOf(c) != -1 || (allowCommaDelimiters && c == ',')) && bracketCount == 0) {
						if(c == ',') {
							if(decodedToken.length() == 0) {
								if(lastWord == null) {
									if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "Extra comma before first element in \""+input+"\" i="+i);
									return null;
								} else if(lastWord.postComma) {
									if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "Extra comma after element "+lastWord+" in \""+input+"\" i="+i);
									// Allow it, delete it.
									lastWord.changed = true;
								} else
									lastWord.postComma = true;
							// Comma is not added to the buffer, so this works even for element , element
							} else {
								if(addComma) {
									if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "Extra comma after a comma in \""+input+"\" i="+i);
									return null;
								}
								addComma = true;
							}
						}
						// Legal CSS whitespace
						if(decodedToken.length() > 0) {
							ParsedWord word = parseToken(origToken, decodedToken, dontLikeOrigToken, couldBeIdentifier);
							if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "Token: orig: \""+origToken.toString()+"\" decoded: \""+decodedToken.toString()+"\" dontLike="+dontLikeOrigToken+" couldBeIdentifier="+couldBeIdentifier+" parsed "+word);
							if(word == null) return null;
							if(addComma) {
								word.postComma = true;
								addComma = false;
							}
							words.add(word);
							origToken.setLength(0);
							decodedToken.setLength(0);
							dontLikeOrigToken = false;
							couldBeIdentifier = true;
							lastWord = word;
						} // Else ignore.
					} else if(c == '\"') {
						stringchar = c;
						origToken.append(c);
						decodedToken.append(c);
						couldBeIdentifier = false;
					} else if(c == '\'') {
						stringchar = c;
						origToken.append(c);
						decodedToken.append(c);
						couldBeIdentifier = false;
					} else if(c == '\\') {
						origToken.append(c);
						escape.setLength(0);
						escaping = true;
					} else if(c == '(') {
						bracketCount++;
						origToken.append(c);
						decodedToken.append(c);
						couldBeIdentifier = false;
					} else if(c == ')') {
						bracketCount--;
						if(bracketCount < 0)
							return null;
						origToken.append(c);
						decodedToken.append(c);
						couldBeIdentifier = false;
					} else {
						if(couldBeIdentifier) {
							if(!((c >= '0' && c <= '9' && origToken.length() > 0) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_' || c >= 0xA1))
								couldBeIdentifier = false;
							if(origToken.length() == 1 && origToken.charAt(0) == '-' && (c >= '0' && c <= '9'))
								couldBeIdentifier = false;
						}
						origToken.append(c);
						decodedToken.append(c);
					}
				} else if(escaping && escape.length() == 0) {
					if(c == '\"' || c == '\'') {
						escaping = false;
						origToken.append(c);
						decodedToken.append(c);
					} else if((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
						escape.append(c);
					} else if(c == '\n' || c == '\r' || c == '\f') {
						// Newline. Can only be escaped in a string.
						// Not valid so return null.
						return null;
					} else {
						escaping = false;
						origToken.append(c);
						decodedToken.append(c);
					}
				} else /*if(escaping && escape.length() != 0)*/ {
					if((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
						escape.append(c);
						if(escape.length() == 6) {
							origToken.append(escape);
							decodedToken.append((char)Integer.parseInt(escape.toString(), 16));
							escape.setLength(0);
							escaping = false;
						}
					} else if(" \t\r\n\f".indexOf(c) != -1) {
						// Whitespace other than CR terminates the escape without any further significance.
						origToken.append(escape);
						decodedToken.append((char)Integer.parseInt(escape.toString(), 16));
						// Convert it to standard whitespace to avoid any complications.
						origToken.append(" ");
						escape.setLength(0);
						escaping = false;
						// \r terminates the escape but might be followed by a \n
						if(c == '\r')
							eatLF = true;
					} else {
						// Already started the escape, anything other than a hex digit or whitespace is invalid.
						return null;
					}
				}
			} else {
				// We are in a string.

				if(eatLF && c == '\n') {
					// Slightly different meaning here.
					// Here we do want to include it in the string.
					eatLF = false;
					origToken.append(c);
					// Don't add to decoded because it is invisible along with the preceding \
					continue;
				} else
					eatLF = false;

				if(c == stringchar && !escaping) {
					origToken.append(c);
					decodedToken.append(c);
					stringchar = 0;
				} else if(c == '\f' || c == '\r' || c == '\n' && !escaping) {
					// Invalid end of line in string.
					// The whole construct is invalid.
					// That is, usually everything up to the next semicolon.
					return null;
				} else if(c == '\\' && !escaping) {
					escaping = true;
					escape.setLength(0);
					origToken.append(c);
				} else if(escaping && escape.length() == 0) {
					if(c == '\"' || c == '\'') {
						escaping = false;
						origToken.append(c);
						decodedToken.append(c);
					} else if((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
						escape.append(c);
					} else if(c == '\r' || c == '\n' || c == '\f') {
						// In a string, an escaped newline is equal to nothing.
						origToken.append(c);
						// Do not add to decodedToken because both the \ and the \n are ignored.
						// Eat the \n if necessary (copy it to the origToken but not the decodedToken)
						if(c == '\r') eatLF = true;
					} else {
						origToken.append(c);
						decodedToken.append(c);
						// Escape one character.
						escaping = false;
					}
				} else if(escaping/* && escape.length() > 0*/) {
					if((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
						escape.append(c);
						if(escape.length() == 6) {
							origToken.append(escape);
							decodedToken.append((char)Integer.parseInt(escape.toString(), 16));
							escape.setLength(0);
							escaping = false;
						}
					} else if(" \t\r\n\f".indexOf(c) != -1) {
						// Whitespace other than CR terminates the escape without any further significance.
						origToken.append(escape);
						decodedToken.append((char)Integer.parseInt(escape.toString(), 16));
						escape.setLength(0);
						escaping = false;
						// \r terminates the escape but might be followed by a \n
						if(c == '\r') {
							eatLF = true;
							// Messy...
							dontLikeOrigToken = true;
						}
					} else {
						// Already started the escape, anything other than a hex digit or whitespace is invalid.
						return null;
					}
				} else { // escaping = false
					origToken.append(c);
					decodedToken.append(c);
				}
			}

		}
		if(escaping && escape.length() > 0) {
			origToken.append(escape);
			decodedToken.append((char)Integer.parseInt(escape.toString(), 16));
		} else if(escaping) {
			// Newline rule?
			dontLikeOrigToken = true;
		}
		if(origToken.length() > 0) {
			if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "Token: orig: \""+origToken.toString()+"\" decoded: \""+decodedToken.toString()+"\" dontLike="+dontLikeOrigToken+" couldBeIdentifier="+couldBeIdentifier);
			ParsedWord word = parseToken(origToken, decodedToken, dontLikeOrigToken, couldBeIdentifier);
			if(word == null) return null;
			words.add(word);
		}
		return words.toArray(new ParsedWord[words.size()]);
	}


	private static ParsedWord parseToken(StringBuilder origToken, StringBuilder decodedToken, boolean dontLikeOrigToken, boolean couldBeIdentifier) {
		if(origToken.length() > 2) {
			char c = origToken.charAt(0);
			if(c == '\'' || c == '\"') {
				char d = origToken.charAt(origToken.length()-1);
				if(c == d) {
					// The word is a string.
					decodedToken.setLength(decodedToken.length()-1);
					decodedToken.deleteCharAt(0);
					return new ParsedString(origToken.toString(), decodedToken.toString(), dontLikeOrigToken, c);
				} else {
					if(d != ',') {
						// No whitespace after a string...
						return null;
					} else return new SimpleParsedWord(origToken.toString());
				}
			}
		}

		String s = origToken.toString();
		if(couldBeIdentifier)
			return new ParsedIdentifier(s, decodedToken.toString(), dontLikeOrigToken);

		String sl = s.toLowerCase();
		if(sl.startsWith("url(")) {
			if(s.endsWith(")")) {
				decodedToken.delete(0, 4);
				decodedToken.setLength(decodedToken.length()-1);
				if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "stripped: "+decodedToken);

				// Trim whitespace from both ends

				String strippedOrig = s.substring(4, s.length()-1);
				int i;
				for(i=0;i<strippedOrig.length();i++) {
					char c = strippedOrig.charAt(i);
					if(!(c == ' ' || c == '\t')) break;
				}
				decodedToken.delete(0, i);
				strippedOrig = strippedOrig.substring(i);
				for(i=strippedOrig.length()-1;i>=0;i--) {
					char c = strippedOrig.charAt(i);
					if(!(c == ' ' || c == '\t')) break;
					if(i > 0 && strippedOrig.charAt(i-1) == '\\') break;
				}
				decodedToken.setLength(decodedToken.length()-(strippedOrig.length()-i-1));
				strippedOrig = strippedOrig.substring(0, i+1);

				if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "whitespace stripped: "+strippedOrig+" decoded "+decodedToken);

				if(strippedOrig.length() == 0) return null;

				if(strippedOrig.length() > 2) {
					char c = strippedOrig.charAt(0);
					if(c == '\'' || c == '\"') {
						char d = strippedOrig.charAt(strippedOrig.length()-1);
						if(c == d) {
							// The word is a string.
							decodedToken.setLength(decodedToken.length()-1);
							decodedToken.deleteCharAt(0);
							if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "creating url(): orig=\""+origToken.toString()+"\" decoded=\""+decodedToken.toString()+"\"");
							return new ParsedURL(origToken.toString(), decodedToken.toString(), dontLikeOrigToken, c);
						} else
							return null;
					}
				}
				return new ParsedURL(origToken.toString(), decodedToken.toString(), dontLikeOrigToken, (char)0);
			} else return null;
		}

		if(sl.startsWith("attr(")) {
			if(s.endsWith(")")) {
				decodedToken.delete(0, 5);
				decodedToken.setLength(decodedToken.length()-1);

				// Trim whitespace from both ends

				String strippedOrig = s.substring(4, s.length()-1);
				int i;
				for(i=0;i<strippedOrig.length();i++) {
					char c = strippedOrig.charAt(i);
					if(!(c == ' ' || c == '\t')) break;
				}
				decodedToken.delete(0, i);
				strippedOrig = strippedOrig.substring(i);
				for(i=strippedOrig.length()-1;i>=0;i--) {
					char c = strippedOrig.charAt(i);
					if(!(c == ' ' || c == '\t')) break;
					if(i > 0 && strippedOrig.charAt(i-1) == '\\') break;
				}
				decodedToken.setLength(decodedToken.length()-(strippedOrig.length()-i-1));
				strippedOrig = strippedOrig.substring(0, i+1);

				if(strippedOrig.length() == 0) return null;

				return new ParsedAttr(origToken.toString(), decodedToken.toString(), dontLikeOrigToken);
			} else return null;
		}

		boolean plural = false;
		if(sl.startsWith("counter(") || (plural = sl.startsWith("counters("))) {
			if(s.endsWith(")")) {
				int len = plural ? "counters(".length() : "counter(".length();
				decodedToken.delete(0, len);
				decodedToken.setLength(decodedToken.length()-1);

				// Trim whitespace from both ends

				String strippedOrig = s.substring(len, s.length()-1);
				int i;
				for(i=0;i<strippedOrig.length();i++) {
					char c = strippedOrig.charAt(i);
					if(!(c == ' ' || c == '\t')) break;
				}
				decodedToken.delete(0, i);
				strippedOrig = strippedOrig.substring(i);
				for(i=strippedOrig.length()-1;i>=0;i--) {
					char c = strippedOrig.charAt(i);
					if(!(c == ' ' || c == '\t')) break;
					if(i > 0 && strippedOrig.charAt(i-1) == '\\') break;
				}
				decodedToken.setLength(decodedToken.length()-(strippedOrig.length()-i-1));
				strippedOrig = strippedOrig.substring(0, i+1);

				if(strippedOrig.length() == 0) return null;

				String[] split = FilterUtils.removeWhiteSpace(strippedOrig.split(","),false);
				if(split.length == 0 || (plural && split.length > 3) || ((!plural) && split.length > 2) || (plural && split.length < 2))
					return null;

				ParsedIdentifier ident = makeParsedIdentifier(split[0]);
				if(ident == null) return null;
				ParsedString separator = null;
				ParsedIdentifier listType = null;
				if(plural) {
					separator = makeParsedString(split[1]);
					if(separator == null) return null;
				}
				if(((!plural) && split.length == 2) || (plural && split.length == 3)) {
					listType = makeParsedIdentifier(split[split.length-1]);
					if(listType == null) return null;
				}
				return new ParsedCounter(origToken.toString(), ident, listType, separator);
			} else return null;
		}

		return new SimpleParsedWord(origToken.toString());
	}

	private static ParsedIdentifier makeParsedIdentifier(String string) {
		ParsedWord[] words = split(string,false);
		if(words == null) return null;
		if(words.length != 1) return null;
		if(!(words[0] instanceof ParsedIdentifier)) return null;
		return (ParsedIdentifier)words[0];
	}

	private static ParsedString makeParsedString(String string) {
		ParsedWord[] words = split(string,false);
		if(words == null) return null;
		if(words.length != 1) return null;
		if(!(words[0] instanceof ParsedString)) return null;
		return (ParsedString)words[0];
	}

	/*
	 * Basic class to verify value for a CSS Property. This class can verify values which are
	 * Integer,Real,Percentage, <Length>, <Angle>, <Color>, <URI>, <Shape> and so on.
	 * parserExpression is used for verifying regular expression for Property value
	 * e.g. [ <color> | transparent]{1,4}.
	 */
	static class CSSPropertyVerifier
	{
		public final boolean onlyValueVerifier;
		public final boolean allowCommaDelimiters;

		public final Set<String> allowedValues; //immutable HashSet for all String constants that this CSS property can assume like "auto"
												// Defaulting Keywords ("initial", "inherit" and "unset") are always accepted
		public final Set<String> allowedMedia; // immutable HashSet for all valid Media for this CSS property.

		/*
		 * in, re etc stands for different code strings using which these boolean values can be set in
		 * constructor like passing in,re would set isInteger and isReal.
		 */
		public final boolean isInteger;    //in
		public final boolean isReal;       //re
		public final boolean isPercentage; //pe
		public final boolean isLength;     //le
		public final boolean isAngle;      //an
		public final boolean isColor;      //co
		public final boolean isURI;        //ur
		public final boolean isIDSelector;   //se
		public final boolean isShape;      //sh
		public final boolean isString;     //st
		public final boolean isCounter;    //co
		public final boolean isIdentifier; //id
		public final boolean isTime;       //ti
		public final boolean isFrequency;  //fr
		public final boolean isTransform;  //tr

		private final List<String> parserExpressions;

		CSSPropertyVerifier(boolean allowCommaDelimiters)
		{
			this(null, null, null, null, false, allowCommaDelimiters);
		}

		CSSPropertyVerifier(Collection<String> allowedValues,
		                    Collection<String> allowedMedia)
		{
			this(allowedValues, allowedMedia, null, null);
		}

		CSSPropertyVerifier(Collection<String> allowedValues,
		                    Collection<String> allowedMedia,
		                    Collection<String> possibleValues)
		{
			this(allowedValues, allowedMedia, possibleValues, null);
		}

		CSSPropertyVerifier(Collection<String> allowedValues,
		                    Collection<String> possibleValues,
		                    Collection<String> parseExpression,
		                    Collection<String> allowedMedia,
		                    boolean onlyValueVerifier)
		{
			this(allowedValues, allowedMedia, possibleValues, parseExpression, onlyValueVerifier, false);
		}

		CSSPropertyVerifier(Collection<String> allowedValues,
		                    Collection<String> allowedMedia,
		                    Collection<String> possibleValues,
		                    Collection<String> parseExpression)
		{
			this(allowedValues, allowedMedia, possibleValues, parseExpression, false, false);
		}

		CSSPropertyVerifier(Collection<String> allowedValues,
		                    Collection<String> allowedMedia,
		                    Collection<String> possibleValues,
		                    Collection<String> parseExpression,
		                    boolean onlyValueVerifier,
		                    boolean allowCommaDelimiters)
		{
			this.onlyValueVerifier = onlyValueVerifier;
			this.allowCommaDelimiters = allowCommaDelimiters;

			boolean isInteger, isReal, isPercentage, isLength, isAngle, isColor,
				isIDSelector, isURI, isShape, isString, isCounter, isIdentifier,
				isTime, isFrequency, isTransform;
			isInteger = isReal = isPercentage = isLength = isAngle = isColor = isURI
				= isShape = isString = isCounter = isIdentifier = isTime = isIDSelector
				= isFrequency = isTransform = false;
			if(possibleValues != null) {
				for(String possibleValue : possibleValues) {
					if("in".equals(possibleValue))
						isInteger=true; //in
					else if("re".equals(possibleValue))
						isReal=true;	//re
					else if("pe".equals(possibleValue))
						isPercentage=true;	//pe
					else if("le".equals(possibleValue))
						isLength=true;	//le
					else if("an".equals(possibleValue))
						isAngle=true;	//an
					else if("co".equals(possibleValue))
						isColor=true; //co
					else if("ur".equals(possibleValue))
						isURI=true;	//ur
					else if ("se".equals(possibleValue)) {
						isIDSelector = true; //se
					}
					else if("sh".equals(possibleValue))
						isShape=true;	//sh
					else if("st".equals(possibleValue))
						isString=true;//st
					else if("co".equals(possibleValue))
						isCounter=true; //co
					else if("id".equals(possibleValue))
						isIdentifier=true; //id
					else if("ti".equals(possibleValue))
						isTime=true; //ti
					else if("fr".equals(possibleValue))
						isFrequency=true; //fr
					else if("tr".equals(possibleValue))
						isTransform=true; //tr
				}
			}
			this.isInteger = isInteger;
			this.isReal = isReal;
			this.isPercentage = isPercentage;
			this.isLength = isLength;
			this.isAngle = isAngle;
			this.isColor = isColor;
			this.isURI = isURI;
			this.isIDSelector = isIDSelector;
			this.isShape = isShape;
			this.isString = isString;
			this.isCounter = isCounter;
			this.isIdentifier = isIdentifier;
			this.isTime = isTime;
			this.isFrequency = isFrequency;
			this.isTransform = isTransform;

			if (allowedValues != null) {
				this.allowedValues = Collections.unmodifiableSet(new HashSet<String>(allowedValues));
			} else {
				this.allowedValues = null;
			}

			if (allowedMedia != null) {
				this.allowedMedia = Collections.unmodifiableSet(new HashSet<String>(allowedMedia));
			} else {
				this.allowedMedia = null;
			}

			if (parseExpression != null) {
				this.parserExpressions = Collections.unmodifiableList(new ArrayList<String>(parseExpression));
			} else {
				this.parserExpressions = Collections.emptyList();
			}
		}

		public static boolean isIntegerChecker(String value)
		{
			try{
				Integer.parseInt(value); //CSS Property has a valid integer.
				return true;
			}
			catch(Exception e) {return false; }

		}


		public static boolean isRealChecker(String value)
		{
			try
			{
				Float.parseFloat(value); //Valid float
				return true;
			}
			catch(Exception e){return false; }
		}

		public static boolean isValidURI(ParsedURL word, FilterCallback cb)
		{
			String w = CSSTokenizerFilter.removeOuterQuotes(word.getDecoded());
			//if(debug) Logger.debug(this, "CSSPropertyVerifier isVaildURI called cb="+cb);
			try
			{
				//if(debug) Logger.debug(this, "CSSPropertyVerifier isVaildURI "+cb.processURI(URI, null));
				String s = cb.processURI(w, null);
				if(s == null || s.equals("")) return false;
				if(s.equals(w)) return true;
				if(logDEBUG) Logger.debug(CSSTokenizerFilter.class, "New url: \""+s+"\" from \""+w+"\"");
				word.setNewURL(s);
				return true;
			}
			catch(CommentException e)
			{
				//if(debug) Logger.debug(this, "CSSPropertyVerifier isVaildURI Exception"+e.toString());
				return false;
			}

		}

		public boolean checkValidity(ParsedWord[] words, FilterCallback cb)
		{
			return this.checkValidity(null,null, words, cb);
		}

		public boolean checkValidity(ParsedWord word, FilterCallback cb)
		{
			return this.checkValidity(null,null, new ParsedWord[] { word }, cb);
		}

		// Verifies whether this CSS property can have a value under given media and HTML elements
		public boolean checkValidity(String[] media,String[] elements,ParsedWord[] words, FilterCallback cb)
		{

			if(logDEBUG) Logger.debug(this, "checkValidity for "+toString(words)+" for "+this);
			if(!onlyValueVerifier)
			{
				if(allowedMedia!=null) {
					boolean allowed = false;
					for(String m : media)
						if(allowedMedia.contains(m)) {
							allowed = true;
							break;
						}
					if(!allowed) {
						if(logDEBUG) Logger.debug(this, "checkValidity Media of the element is not allowed.Media="+Fields.commaList(media)+" allowed Media="+allowedMedia.toString());

						return false;
					}
				}
				// CONFORMANCE: ELEMENT CHECKING DISABLED:
				// We do NOT check whether a property is allowed for a specific element.
				// According to the spec, all properties are defined for all elements,
				// and in many cases they will be set on one element to which they do
				// not apply, and then be inherited to other elements for which they do apply.
				// FOR EXAMPLE, IN THE SPEC:
				// 17.6.1.1 empty-cells Applies to: 'table-cell' elements
				// In 17.2, 'table-cell' is explicitly defined:
				// table-cell (In HTML: TD, TH)     Specifies that an element represents a table cell.
				// Yet the example for empty-cells is:
				// The following rule causes borders and backgrounds to be drawn around all cells:
				// table { empty-cells: show }
				// Hence it is not appropriate to check which property is valid for which element.

				// In security terms, there is no danger in allowing every property on every element.
			}

			if(words.length == 1) {

			if(words[0] instanceof ParsedIdentifier) {
				String lowerCaseWord = ((ParsedIdentifier)words[0]).original.toLowerCase();
				if (allowedValues != null && allowedValues.contains(lowerCaseWord)) {
					// CSS Property has one of the explicitly defined values
					return true;
				}
				if (lowerCaseWord.equals("initial") || lowerCaseWord.equals("inherit") || lowerCaseWord.equals("unset")) {
					// CSS Property is one of the Defaulting Keywords (http://www.w3.org/TR/css3-cascade/#defaulting-keywords)
					return true;
				}
			}


			if(words[0] instanceof SimpleParsedWord) {

				String word = ((SimpleParsedWord)words[0]).original;

				// Numeric explicitly defined value is possible
				if(allowedValues != null && allowedValues.contains(word))
					return true;

				// These are all numeric so they will have parsed as a SimpleParsedWord.

				if(isInteger && isIntegerChecker(word))
				{
					return true;
				}

				if(isReal && isRealChecker(word))
				{
					return true;
				}

				if(isPercentage && FilterUtils.isPercentage(word)) //Valid percentage X%
				{
					return true;
				}

				if(isLength && FilterUtils.isLength(word,false)) //Valid unit Vxx where xx is unit or V
				{
					return true;
				}

				if(isAngle && FilterUtils.isAngle(word))
				{
					return true;
				}
				// This is not numeric but will still have parsed as a SimpleParsedWord, as it either starts with a # or has brackets in.
				if(isColor)
				{
					if(FilterUtils.isColor(word))
						return true;
				}

				if(isShape)
				{
					if(FilterUtils.isValidCSSShape(word))
						return true;
				}

				if(isFrequency)
				{
					if(FilterUtils.isFrequency(word))
						return true;
				}

				if(isTime) {
					if(FilterUtils.isTime(word))
						return true;
				}

				if(isTransform) {
					if(FilterUtils.isCSSTransform(word))
						return true;
				}
			}

			if(words[0] instanceof ParsedIdentifier && isColor) {
				if(FilterUtils.isColor(((ParsedIdentifier)words[0]).original))
					return true;

			}
			if(isURI && words[0] instanceof ParsedURL)

			{
				return isValidURI((ParsedURL)words[0], cb);
			}

			if(isIdentifier && words[0] instanceof ParsedIdentifier)
			{
				return true;
			}

			if (isIDSelector) {
			    // In accordance with spec for e.g. nav-*, we only allow ID selectors.
			    // See http://www.w3.org/TR/css3-ui/
			    // REDFLAG If we allow more general selectors (which some browsers may accept) we
			    // have two new problems:
			    // 1) They may occupy more than one word, which greatly complicates parsing here,
			    // 2) We should sanitize the selectors, not just pass them on. Which in turn may
			    // cause them to take up more than one word!
				String result = HTMLelementVerifier(words[0].original, true);
				if (!(result == null || result.equals(""))) {
					return true;
				}
			}

			if(isString && words[0] instanceof ParsedString)
			{
				if(ElementInfo.ALLOW_ALL_VALID_STRINGS || ElementInfo.isValidStringDecoded(((ParsedString)words[0]).getDecoded()))
					return true;
				else
					return false;
			}

			}

			/*
			 * Parser expressions
			 * Original syntax: http://www.w3.org/TR/CSS2/about.html#value-defs
			 * We encode it a bit differently...
			 * 1 || 2 => 1a2
			 * [1][2] =>1 2
			 * 1 && 2 => 1b2
			 * 1<1,4> => 1<1,4>
			 * 1* => 1<0,65536>
			 * 1? => 1?
			 *
			 * Note that we do not (correctly) implement operator precedence. Brackets must be
			 * implemented using auxiliary expression verifiers. && and || may only join numbered
			 * expressions. There is no support for the single bar, again we use multiple
			 * alternative numbered patterns for this.
			 */
			/*
			 * For each parserExpression, recursiveParserExpressionVerifier() would be called with parserExpression and value.
			 */
			for(String parserExpression : parserExpressions)
			{
				boolean result=recursiveParserExpressionVerifier(parserExpression,words,cb);

				if(result)
					return true;
			}
			return false;
		}
		/* parserExpression string would be interpreted as 1 || 2 => 1a2 here 1a2 would be written to parse 1 || 2 where 1 and 2 are auxilaryVerifiers[1] and auxilaryVerifiers[2] respectively i.e. indices in auxilaryVerifiers
		 * [1][2] => 1 2
		 * 1<1,4> => 1<1,4>
		 * 1* => 1<0,65536>
		 * 1? => 1?
		 * 1+ => 1<1,65536>
		 * 1&&2 => 1b2   (see doubleAmpersandVerifier())
		 * Additional expressions that can be passed to the function
		 * 1 2 => both 1 and 2 should return true where 1 and 2 are again indices in auxiliaryVerifier array.
		 * [a,b]=> give at least a tokens and at the most b tokens(part of values) to this block of expression.
		 * e.g. 1[2,3] and the value is "hello world program" then object 1 would be tested with "hello world"
		 * and "hello world program".
		 * The main logic of this function is find a set of values for different part of the ParserExpression so that each part returns true.
		 * e.g. Suppose the expression is
		 * (1 || 2) 3
		 * where object 1 can consume upto 2 tokens, 2 can consume upto 2 tokens and 3 would consume one and only one token.
		 * This expression would be encoded as
		 * "1a2" for 1 || 2 Using this, third object would be created say 4 e.g. 4="1a2"
		 * Now the main object would be given the parserExpression as
		 * "4<0,4> 3"
		 * This function would call
		 * 4 with 0 tokens and 3 with the remaining
		 * 4 with 1 tokens and 3 with the remaining
		 * and so on.
		 * If all combinations are failed then it would return false. If any combination gives true value
		 * then return value would be true.
		 */
		public boolean recursiveParserExpressionVerifier(String expression,ParsedWord[] words, FilterCallback cb)
		{
			if(logDEBUG) Logger.debug(this, "1recursiveParserExpressionVerifier called: with "+expression+" "+toString(words));
			if((expression==null || ("".equals(expression.trim()))))
			{
				if(words==null || words.length == 0)
					return true;
				else
					return false;
			}

			int tokensCanBeGivenLowerLimit=1,tokensCanBeGivenUpperLimit=1;
			for(int i=0;i<expression.length();i++)
			{
				if(expression.charAt(i)=='a') //Identifying ||
				{
					int noOfa=0;
					int endIndex=expression.length();
					//Detecting the other end
					for(int j=0;j<expression.length();j++)
					{
					    char c = expression.charAt(j);
					    if(c == 'a') {
                            noOfa++;
					    } else if(!('0' <= c && '9' >= c)) {
							endIndex=j;
							break;
						}
					}
					String firstPart=expression.substring(0,endIndex);
					String secondPart="";
					if(endIndex!=expression.length())
						secondPart=expression.substring(endIndex+1,expression.length());
					int j = 1;
					if((secondPart.equals(""))) {
						// This is an optimisation: If no second part, there cannot be any words assigned to the second part, so the first part must match everything.
						// It is equivalent to running the loop, because each time the second part will fail, because it is trying to match "" to a nonzero number of words.
						// This happens every time we have "1a2a3" with nothing after it, so it is tested by the unit tests already.
						j = words.length;
					}
					for(;j<=words.length;j++)
					{
						if(logDEBUG) Logger.debug(this, "2Making recursiveDoubleBarVerifier to consume "+j+" words");
						ParsedWord[] partToPassToDB = Arrays.copyOf(words, j);
						if(logDEBUG) Logger.debug(this, "3Calling recursiveDoubleBarVerifier with "+firstPart+" "+CSSPropertyVerifier.toString(partToPassToDB));
						if(recursiveDoubleBarVerifier(firstPart,partToPassToDB,cb)) //This function is written to verify || operator.
						{
							ParsedWord[] partToPass = Arrays.copyOfRange(words, j, words.length);
							if(logDEBUG) Logger.debug(this, "4recursiveDoubleBarVerifier true calling itself with "+secondPart+CSSPropertyVerifier.toString(partToPass));
							if(recursiveParserExpressionVerifier(secondPart,partToPass,cb))
								return true;
						}
						if(logDEBUG) Logger.debug(this, "5Back to recursiveDoubleBarVerifier "+j+" "+(noOfa+1)+" "+words.length);
					}
					return false;
				} else if (expression.charAt(i) == 'b') {
					// detecting b which is the && operator
					int endIndex = expression.length();
                    // Find the end of a chain of 1b2b3...
					for (int j = 0; j < expression.length(); j++) {
					    char c = expression.charAt(j);
					    if(!(c == 'b' || '0' <= c && '9' >= c)) {
							endIndex=j;
							break;
						}
					}
					String firstPart = expression.substring(0,endIndex);
					String secondPart = "";
					if (endIndex != expression.length()) {
						secondPart = expression.substring(endIndex+1,expression.length());
					}
					for (int j = words.length; j >= 1; j--) {
						ParsedWord[] partToPassToDA = Arrays.copyOf(words, j);
						if (doubleAmpersandVerifier(firstPart, partToPassToDA, cb)) {
							ParsedWord[] partToPass = Arrays.copyOfRange(words, j, words.length);
							if (recursiveParserExpressionVerifier(secondPart,partToPass,cb)) {
								return true;
							}
						}
					}
					return false;
				}
				else if(expression.charAt(i)==' ')
				{
					String firstPart=expression.substring(0,i);
					String secondPart=expression.substring(i+1,expression.length());
					if(words!=null && words.length>0)
					{
						int index=Integer.parseInt(firstPart);
						boolean result=CSSTokenizerFilter.auxilaryVerifiers[index].checkValidity(words[0], cb);
						if(result)
						{
							ParsedWord[] partToPass = Arrays.copyOfRange(words, 1, words.length);
							if(logDEBUG) Logger.debug(this, "8First part is true. partToPass="+CSSPropertyVerifier.toString(partToPass));
							if(recursiveParserExpressionVerifier(secondPart,partToPass, cb))
								return true;
						}
					}
					return false;
				}
				else if(expression.charAt(i)=='?')
				{
					String firstPart=expression.substring(0,i);
					String secondPart=expression.substring(i+1,expression.length());
					int index=Integer.parseInt(firstPart);
					if(words.length>0)
					{
						boolean result= CSSTokenizerFilter.auxilaryVerifiers[index].checkValidity(words[0], cb);
						if(result)
						{
							ParsedWord[] partToPass = Arrays.copyOfRange(words, 1, words.length);
							if(recursiveParserExpressionVerifier(secondPart,partToPass, cb))
								return true;
						}
					}
					else if(recursiveParserExpressionVerifier(secondPart,words, cb))
						return true;

					return false;
				}
				else if(expression.charAt(i)=='<')
				{
					int tindex=expression.indexOf('>');
					if(tindex>i)
					{
						int firstIndex=tindex+1;
						if((tindex!=expression.length()-1) && expression.charAt(tindex+1)=='[')
						{
							int indexOfSecondBracket=expression.indexOf(']');
							if(indexOfSecondBracket>(tindex+1))
							{
								tokensCanBeGivenLowerLimit=Integer.parseInt(expression.substring(tindex+2,indexOfSecondBracket).split(",")[0]);
								tokensCanBeGivenUpperLimit=Integer.parseInt(expression.substring(tindex+2,indexOfSecondBracket).split(",")[1]);
								firstIndex=expression.indexOf(']')+1;
							}
						}
						String firstPart=expression.substring(0,i);
						String secondPart=expression.substring(firstIndex,expression.length());
						if(secondPart.length() > 0 && secondPart.charAt(0) == ' ') {
							secondPart = secondPart.substring(1);
						} else if(secondPart.length() > 0) {
							throw new IllegalStateException("Don't know what to do with char after <>[]: "+secondPart.charAt(0));
						}
						if(logDEBUG) Logger.debug(this, "9in < firstPart="+firstPart+" secondPart="+secondPart+" tokensCanBeGivenLowerLimit="+tokensCanBeGivenLowerLimit+" tokensCanBeGivenUpperLimit="+tokensCanBeGivenUpperLimit);
						int index=Integer.parseInt(firstPart);
						String[] strLimits=expression.substring(i+1,tindex).split(",");
						if(strLimits.length==2)
						{
							int lowerLimit=Integer.parseInt(strLimits[0]);
							int upperLimit=Integer.parseInt(strLimits[1]);

							if(recursiveVariableOccuranceVerifier(index, words, lowerLimit,upperLimit,tokensCanBeGivenLowerLimit,tokensCanBeGivenUpperLimit, secondPart, cb))
								return true;
						}
					}

					return false;
				}

			}
			//Single verifier object
			if(logDEBUG) Logger.debug(this, "10Single token:"+expression);
			int index=Integer.parseInt(expression);
			return CSSTokenizerFilter.auxilaryVerifiers[index].checkValidity(words, cb);


		}
		/**
		 * Takes b expressions and evaluates them.<br/>
		 * "&&" means all of the expressions must occur in any order.<br/>
		 * CSS Grammar <code>list-item && [ block | nonsense ] && [ more ]?</code><br/>
		 * Will accept the following inputs as valid:<br/>
		 * <code>list-item block</code><br/>
		 * <code>block list-item more</code><br/>
		 * <code>more nonsense list-item</code><br/>
		 * You can model that using the b expression: <code>1b2b3</code> where 1 is ["list-item"] 2 is ["block", "nonsense"] and 3 is "4?" and 4 is ["more"].<br/>
		 * @param expression the expression, explained above
		 * @param words tokens to parse
		 * @param cb
		 * @return true if all the verifiers and all the words were consumed, false otherwise.
		 */
		public boolean doubleAmpersandVerifier(String expression, ParsedWord[] words, FilterCallback cb) {
			String ignoredParts="";
			String firstPart = "";
			int lastB = -1;
			// Check for invalid patterns.
			assert(expression.length() != 0);
			assert(expression.charAt(expression.length()-1) != 'b');
			assert(expression.charAt(0) != 'b');

			// Get all the verifiers in one list, we need to check them individually
			List<CSSPropertyVerifier> propertyVerifierList = new ArrayList<CSSPropertyVerifier>();
			for (int i = 0; i <= expression.length(); i++) {
				if(i == expression.length() || expression.charAt(i)=='b') {
					if(!firstPart.equals("")) {
						if(ignoredParts.length() == 0) {
							ignoredParts = firstPart;
						} else {
							ignoredParts = ignoredParts+"b"+firstPart;
						}
					}
					else ignoredParts = "";
					firstPart = expression.substring(lastB+1,i);
					lastB = i;

					int index = Integer.parseInt(firstPart);
					propertyVerifierList.add(CSSTokenizerFilter.auxilaryVerifiers[index]);
				}
			}

			// Check each group of words in each verifier a maximum of maxLoops times
			// and only if we have some property verifiers to test against in the list.
			// Since some property verifiers will return a positive match on an empty
			// list we do not want that potential false positive and so here we are
			// forcing the verifier to take at least one word.
			int maxLoops = words.length;
			while (maxLoops-- > 0 && propertyVerifierList.size() != 0) {
				for(int i = words.length; i > 0; i--) {
					ParsedWord[] tokensToVerify = Arrays.copyOf(words, i);
					boolean tokenConsumed = false;
					for (int j = 0; j < propertyVerifierList.size(); j++) {
						CSSPropertyVerifier propertyVerifier = propertyVerifierList.get(j);
						if (propertyVerifier.checkValidity(tokensToVerify, cb)) {
							if (words.length - tokensToVerify.length > 0) {
								words = Arrays.copyOfRange(words, tokensToVerify.length, words.length);
							} else {
								words = new ParsedWord[0];
							}
							propertyVerifierList.remove(j);
							tokenConsumed = true;
							break;
						}
					}
					if (tokenConsumed) {
						break;
					}
				}
				if (words.length == 0) {
					break;
				}
			}

			// Little optimisation to allow us to quit early
			// any propertyVerifiers left will not accept any words in the list or
			// they would have been accepted earlier. We know the next step will fail
			// so we can abort now.
			if (words.length > 0) {
				return false;
			}

			// Verifiers that still remain in the list may accept an empty word array
			// here we will let those verifiers accept an empty array if they want to.
			boolean result = true;
			for (int i = 0; i < propertyVerifierList.size(); i++) {
				CSSPropertyVerifier verifier = propertyVerifierList.get(i);
				result = result && verifier.checkValidity(words, cb);
			}

			return result;
		}
		/*
		 * This function takes an array of string and concatenates everything in a " " seperated string.
		 */
		public static String getStringFromArray(String[] parts,int lowerIndex,int upperIndex)
		{
			StringBuilder buffer=new StringBuilder();
			if(parts!=null && lowerIndex<parts.length)
			{
				for(int i=lowerIndex;i<upperIndex && i<parts.length;i++) {
					buffer.append(parts[i]);
                                        buffer.append(' ');
                                }
				return buffer.toString();
			}
			else
				return "";

		}
		/*
		 * This function takes an array of string and concatenates everything in a " " seperated string.
		 */
		public static String getStringFromArray(String[] parts) {
			return getStringFromArray(parts, 0, parts.length-1);
		}
		//Creates a new sub array from the main array and returns it.
		public static ParsedWord[] getSubArray(ParsedWord[] array,int lowerIndex,int upperIndex)
		{
			ParsedWord[] arrayToReturn=new ParsedWord[upperIndex-lowerIndex];
			if(array!=null && lowerIndex<array.length)
			{
				for(int i=lowerIndex;i<upperIndex && i<array.length;i++)
				{
					arrayToReturn[i-lowerIndex]=array[i];
				}
				return arrayToReturn;
			}
			else
				return new ParsedWord[0];
		}
		/*
		 * For verifying part of the ParseExpression with [] operator.
		 */
		public boolean recursiveVariableOccuranceVerifier(int verifierIndex,ParsedWord[] valueParts,int lowerLimit,int upperLimit,int tokensCanBeGivenLowerLimit,int tokensCanBeGivenUpperLimit, String secondPart, FilterCallback cb)
		{

			if(logDEBUG) Logger.debug(this, "recursiveVariableOccurranceVerifier("+verifierIndex+","+toString(valueParts)+","+lowerLimit+","+upperLimit+","+tokensCanBeGivenLowerLimit+","+tokensCanBeGivenUpperLimit+","+secondPart+")");
			if((valueParts==null || valueParts.length==0) && lowerLimit == 0)
				return true;

			if(lowerLimit <= 0) {
				// There could be secondPart.
				if(recursiveParserExpressionVerifier(secondPart, valueParts, cb)) {
					if(logDEBUG) Logger.debug(this, "recursiveVariableOccurranceVerifier completed by "+secondPart);
					return true;
				}
			}

			// There can be no more parts.
			if(upperLimit == 0) {
				if(logDEBUG) Logger.debug(this, "recursiveVariableOccurranceVerifier: no more parts");
				return false;
			}

			for(int i=tokensCanBeGivenLowerLimit; i<=tokensCanBeGivenUpperLimit && i <= valueParts.length;i++) {
				ParsedWord[] before = Arrays.copyOf(valueParts, i);
				if(CSSTokenizerFilter.auxilaryVerifiers[verifierIndex].checkValidity(before, cb)) {
					if(logDEBUG) Logger.debug(this, "first "+i+" tokens using "+verifierIndex+" match "+toString(before));
					if(i == valueParts.length && lowerLimit <= 1) {
						if(recursiveParserExpressionVerifier(secondPart, new ParsedWord[0], cb)) {
							if(logDEBUG) Logger.debug(this, "recursiveVariableOccurranceVerifier completed with no more parts by "+secondPart);
							return true;
						} else {
							if(logDEBUG) Logger.debug(this, "recursiveVariableOccurranceVerifier: satisfied self but nothing left to match "+secondPart);
							return false;
						}
					} else if(i == valueParts.length && lowerLimit > 1)
						return false;
					ParsedWord[] after = Arrays.copyOfRange(valueParts, i, valueParts.length);
					if(logDEBUG) Logger.debug(this, "rest of tokens: "+toString(after));
					if(recursiveVariableOccuranceVerifier(verifierIndex, after, lowerLimit-1, upperLimit-1, tokensCanBeGivenLowerLimit, tokensCanBeGivenUpperLimit, secondPart, cb))
						return true;
				}
			}

			return false;
		}

		static String toString(ParsedWord[] words) {
			if(words == null) return null;
			StringBuilder sb = new StringBuilder();
			boolean first = true;
			for(ParsedWord word : words) {
				if(!first) sb.append(",");
				first = false;
				sb.append(word);
			}
			return sb.toString();
		}

		/*
		 * This function verifies || operator. This function returns true only if it can consume entire value for the given parseExpression
		 * e.g. expression is [1 || 2 || 3 || 4] and value is "Hello world program"
		 * Then this function would try all combinations of objects so that the expression can consume this value.
		 * 1 would try to consume "Hello" and rest would try to consume "world program"
		 * 2 would try to consume "Hello" and rest would try to consume "world program"
		 * 3 would try to consume "Hello" and rest would try to consume "world program"
		 * and so on.
		 */
		public boolean recursiveDoubleBarVerifier(String expression,ParsedWord[] words,FilterCallback cb)
		{
			if(logDEBUG) Logger.debug(this, "11in recursiveDoubleBarVerifier expression="+expression+" value="+toString(words));
			if(words==null || words.length == 0)
				return true;

			String ignoredParts="";
			String firstPart = "";
			String secondPart = "";
			int lastA = -1;
			// Check for invalid patterns.
			assert(expression.length() != 0);
			assert(expression.charAt(expression.length()-1) != 'a');
			assert(expression.charAt(0) != 'a');
			for(int i=0;i<=expression.length();i++)
			{
				if(i == expression.length() || expression.charAt(i)=='a')
				{
					if(!firstPart.equals("")) {
						if(ignoredParts.length() == 0)
							ignoredParts = firstPart;
						else
							ignoredParts = ignoredParts+"a"+firstPart;
					}
					else ignoredParts = "";
					firstPart=expression.substring(lastA+1,i);
					lastA = i;
					if(i == expression.length())
						secondPart = "";
					else
						secondPart=expression.substring(i+1,expression.length());
					if(logDEBUG) Logger.debug(this, "12in a firstPart="+firstPart+" secondPart="+secondPart+" for expression "+expression+" i "+i);

					boolean result=false;

					int index=Integer.parseInt(firstPart);
					for(int j=0;j<words.length;j++)
					{
						// Check the first j+1 words against this verifier: A single verifier can consume more than one word.
						result=CSSTokenizerFilter.auxilaryVerifiers[index].checkValidity(getSubArray(words, 0, j+1), cb);
						if(logDEBUG) Logger.debug(this, "14in for loop result:"+result+" for "+toString(words)+" for "+firstPart);
						if(result)
						{
							// Check the remaining words...
							ParsedWord[] valueToPass = Arrays.copyOfRange(words, j+1, words.length);
							if(valueToPass.length == 0) {
								// We have matched everything against the subset we have considered so far.
								if(logDEBUG) Logger.debug(this, "14opt No more words to pass, have matched everything");
								return true;
							}
							// Against the rest of the pattern: the part that we've tried and failed plus the part that we haven't tried yet.
							// NOT against the verifier we were just considering, because the double-bar operator expects no more than one match from each component of the pattern.
							String pattern = ignoredParts+((("".equals(ignoredParts))||("".equals(secondPart)))?"":"a")+secondPart;
							if(logDEBUG) Logger.debug(this, "14a "+toString(getSubArray(words, 0, j+1))+" can be consumed by "+index+ " passing on expression="+pattern+ " value="+toString(valueToPass));
							if(pattern.equals("")) return false;
							result=recursiveDoubleBarVerifier(pattern,valueToPass, cb);
							if(result)
							{
								if(logDEBUG) Logger.debug(this, "15else part is true, value consumed="+words[j]);
								return true;
							}
						}
					}
				}
			}

			if(lastA != -1) return false;
			//Single token
			int index=Integer.parseInt(expression);
			if(logDEBUG) Logger.debug(this, "16Single token:"+expression+" with value=*"+Fields.commaList(words)+"* validity="+CSSTokenizerFilter.auxilaryVerifiers[index].checkValidity(words,cb));
			return CSSTokenizerFilter.auxilaryVerifiers[index].checkValidity(words,cb);


		}





	}
	//CSSPropertyVerifier class extended for verifying content property.
	static class ContentPropertyVerifier extends CSSPropertyVerifier
	{

		ContentPropertyVerifier(Collection<String> allowedValues)
		{
			super(allowedValues,null,null,null);
		}

		@Override
		public boolean checkValidity(String[] media,String[] elements,ParsedWord[] value,FilterCallback cb)
		{
			if(logDEBUG) Logger.debug(this, "ContentPropertyVerifier checkValidity called: "+toString(value));

			if(value.length != 1) return false;

			if(value[0] instanceof ParsedIdentifier && allowedValues!=null && allowedValues.contains(((ParsedIdentifier)value[0]).getDecoded()))
				return true;

			//String processing
			if(value[0] instanceof ParsedString) {
				if(ElementInfo.ALLOW_ALL_VALID_STRINGS || ElementInfo.isValidStringDecoded(((ParsedString)value[0]).getDecoded()))
					return true;
				else
					return false;
			}

			if(value[0] instanceof ParsedCounter) {
				ParsedCounter counter = (ParsedCounter)value[0];
				if(counter.listType != null) {
					HashSet<String> listStyleType=new HashSet<String>();
					listStyleType.add("disc");
					listStyleType.add("circle");
					listStyleType.add("square");
					listStyleType.add("decimal");
					listStyleType.add("decimal-leading-zero");
					listStyleType.add("lower-roman");
					listStyleType.add("upper-roman");
					listStyleType.add("lower-greek");
					listStyleType.add("lower-latin");
					listStyleType.add("upper-latin");
					listStyleType.add("armenian");
					listStyleType.add("georgian");
					listStyleType.add("lower-alpha");
					listStyleType.add("upper-alpha");
					listStyleType.add("none");
					if(!listStyleType.contains(counter.listType.getDecoded())) return false;
				}
				if(counter.separatorString != null && !(ElementInfo.ALLOW_ALL_VALID_STRINGS || ElementInfo.isValidStringDecoded(counter.separatorString.getDecoded())))
					return false;
				return true;
			}

			if(value[0] instanceof ParsedAttr) {
				return true;
			}

			if(value[0] instanceof ParsedURL) {
				// CONFORMANCE: This is required by the spec, and quite useful in practice.
				// Browsers in practice only support images here.
				// However, as long as they respect the MIME type - and if they don't we are screwed anyway - this should be safe even if it allows including text, CSS and HTML.
				// Note also that generated content cannot alter the parse tree, so what can be done is presumably severely limited.
				return isValidURI((ParsedURL)value[0], cb);
			}

			return false;

		}



	}

	//For verifying ’font-size’[ / ’line-height’]? of Font property

	static class FontPartPropertyVerifier extends CSSPropertyVerifier
	{
		FontPartPropertyVerifier() {
			super(false);
		}

		@Override
		public boolean checkValidity(String[] media,String[] elements,ParsedWord[] value,FilterCallback cb)
		{

			if(logDEBUG) Logger.debug(this, "FontPartPropertyVerifier called with "+toString(value));
			CSSPropertyVerifier fontSize=new CSSPropertyVerifier(Arrays.asList("xx-small","x-small","small","medium","large","x-large","xx-large","larger","smaller"),Arrays.asList("le","pe"),null,null,true);
			if(fontSize.checkValidity(value, cb)) return true;

			for(ParsedWord word : value) {
				// Token by token
				if(fontSize.checkValidity(word, cb)) continue;
				if(word instanceof SimpleParsedWord) {
					String orig = ((SimpleParsedWord)word).original;
					if(orig.indexOf("/")!=-1)
					{
						int slashIndex=orig.indexOf("/");
						String firstPart=orig.substring(0,slashIndex);
						String secondPart=orig.substring(slashIndex+1,orig.length());
						if(logDEBUG) Logger.debug(this, "FontPartPropertyVerifier FirstPart="+firstPart+" secondPart="+secondPart);
						CSSPropertyVerifier lineHeight=new CSSPropertyVerifier(Arrays.asList("normal"),Arrays.asList("le","pe","re","in"),null,null,true);
						ParsedWord[] first = split(firstPart,false);
						ParsedWord[] second = split(secondPart,false);
						if(first.length == 1 && second.length == 1 &&
								fontSize.checkValidity(first, cb) && lineHeight.checkValidity(second,cb))
							continue;
					}
				}
				return false;

			}
			return true;

		}

	}

	static abstract class FamilyPropertyVerifier extends CSSPropertyVerifier {

		FamilyPropertyVerifier(boolean valueOnly, Set<String> mediaTypes) {
			super(null, mediaTypes, null, null, valueOnly, true);
		}

		// FIXME: We do not change the tokens.
		// We probably should put in quotes around unquoted font family names, put spaces after commas etc, but
		// this may be a bit tricky: we'd have to put spaces etc inside some words, and delete some words...
		// Quite possible, but not a high priority, "verdana,arial,times new roman,sans-serif" is not dangerous, it's just hard to parse.

		@Override
		public boolean checkValidity(String[] media,String[] elements,ParsedWord[] value,FilterCallback cb)
		{
			if(logDEBUG) Logger.debug(this, "font verifier: "+toString(value));
			if(value.length == 1) {
				if(value[0] instanceof ParsedIdentifier && "inherit".equalsIgnoreCase(((ParsedIdentifier)value[0]).original)) {
				//CSS Property has one of the explicitly defined values
					if(logDEBUG) Logger.debug(this, "font: inherit");
					return true;
				}
			}
			if(allowedMedia!=null && !onlyValueVerifier) {
				boolean allowed = false;
				for(String m : media)
					if(allowedMedia.contains(m)) {
						allowed = true;
						break;
					}
				if(!allowed) {
					if(logDEBUG) Logger.debug(this, "checkValidity Media of the element is not allowed.Media="+Fields.commaList(media)+" allowed Media="+allowedMedia.toString());

					return false;
				}
			}
			ArrayList<String> fontWords = new ArrayList<String>();
			// FIXME delete fonts we don't know about but let through ones we do.
			// Or allow unknown fonts given [a-z][A-Z][0-9] ???
outer:		for(int i=0;i<value.length;i++) {
				ParsedWord word = value[i];
				String s = null;
				if(word instanceof ParsedString) {
					String decoded = (((ParsedString)word).getDecoded());
					if(logDEBUG) Logger.debug(this, "decoded: \""+decoded+"\"");
					// It's actually quoted, great.
					if(isSpecificFamily(decoded.toLowerCase())) {
						continue;
					} if(isGenericFamily(decoded.toLowerCase())) {
						continue;
					} else
						s = decoded;
				} else if(word instanceof ParsedIdentifier) {
					s = (((ParsedIdentifier)word).getDecoded());
					if(isGenericFamily(s)) {
						continue;
					}
					if(isSpecificFamily(s)) {
						continue;
					}
					if(word.postComma) {
						if(logDEBUG) Logger.debug(this, "Word ends in comma, but is not a valid font on its own: "+word+" (index "+i+")");
						return false;
					}
				} else
					return false;
				// Unquoted multi-word font, or unquoted single-word font.
				// Unfortunately fonts can be ambiguous...
				// Therefore we do not accept a single-word font unless it is either quoted or ends in a comma.
				fontWords.clear();
				assert(s != null);
				fontWords.add(s);
				if(logDEBUG) Logger.debug(this, "first word: \""+s+"\"");
				if(i == value.length-1) {
					if(logDEBUG) Logger.debug(this, "last word. font words: "+getStringFromArray(fontWords.toArray(new String[fontWords.size()]))+" valid="+validFontWords(fontWords));
					return validFontWords(fontWords);
				}
				if(!possiblyValidFontWords(fontWords))
					return false;
				boolean last = false;
				for(int j=i+1;j<value.length;j++) {
					ParsedWord newWord = value[j];
					if (j == value.length-1) last = true;
					String s1;
					if(newWord instanceof ParsedIdentifier) {
						s1 = ((ParsedIdentifier)newWord).original;
						fontWords.add(s1);
						if(logDEBUG) Logger.debug(this, "adding word: \""+s1+"\"");
						if(last) {
							if(newWord.postComma) {
								if(logDEBUG) Logger.debug(this, "not valid: trailing comma at end");
							}
							if(validFontWords(fontWords)) {
								// Valid. Good.
								if(logDEBUG) Logger.debug(this, "font: reached last in inner loop, valid. font words: "+getStringFromArray(fontWords.toArray(new String[fontWords.size()])));
								return true;
							}
						}
						if(newWord.postComma) {
							// Words must be a valid font when put together
							if(validFontWords(fontWords)) {
								fontWords.clear();
								i = j;
								continue outer;
							} else {
								if(logDEBUG) Logger.debug(this, "comma but can't parse font words: "+Fields.commaList(fontWords.toArray(new String[fontWords.size()])));
								return false;
							}
						}
					} else {
						if(logDEBUG) Logger.debug(this, "cannot parse "+newWord);
						return false;
					}
				}
				// Still looking for another keyword...
				if(validFontWords(fontWords))
					return true;
				return false;
			}
			if(logDEBUG) Logger.debug(this, "font: reached end, valid");
			return true;
			}

		private boolean possiblyValidFontWords(ArrayList<String> fontWords) {
			if(ElementInfo.disallowUnknownSpecificFonts) {
				StringBuilder sb = new StringBuilder();
				boolean first = true;
				for(String s : fontWords) {
					if(!first) sb.append(' ');
					first = false;
					sb.append(s);
				}
				String s = sb.toString().toLowerCase();
				return ElementInfo.isWordPrefixOrMatchOfSpecificFontFamily(s);
			} else {
				for(String s : fontWords)
					if(!isSpecificFamily(s)) return false;
				return true;
			}
		}

		private boolean validFontWords(ArrayList<String> fontWords) {
			for(String s : fontWords) {
				if(s == null) throw new NullPointerException();
			}
			if(fontWords.size() == 1) {
				if(isGenericFamily(fontWords.get(0).toLowerCase()))
					return true;
			}
			StringBuilder sb = new StringBuilder();
			boolean first = true;
			for(String s : fontWords) {
				if(!first) sb.append(' ');
				first = false;
				sb.append(s);
			}
			return isSpecificFamily(sb.toString().toLowerCase());
		}

		abstract boolean isSpecificFamily(String s);

		abstract boolean isGenericFamily(String s);

	}

	static class FontPropertyVerifier extends FamilyPropertyVerifier {

		FontPropertyVerifier(boolean valueOnly) {
			super(valueOnly, ElementInfo.VISUALMEDIA);
		}

		@Override
		boolean isSpecificFamily(String s) {
			return ElementInfo.isSpecificFontFamily(s);
		}

		@Override
		boolean isGenericFamily(String s) {
			return ElementInfo.isGenericFontFamily(s);
		}

	}

	static class VoiceFamilyPropertyVerifier extends FamilyPropertyVerifier {

		VoiceFamilyPropertyVerifier(boolean valueOnly) {
			super(valueOnly, ElementInfo.AURALMEDIA);
		}

		@Override
		boolean isSpecificFamily(String s) {
			return ElementInfo.isSpecificVoiceFamily(s);
		}

		@Override
		boolean isGenericFamily(String s) {
			return ElementInfo.isGenericVoiceFamily(s);
		}

	}

	public static String removeOuterQuotes(String decoded) {
		if(decoded.length() < 2) return decoded;
		char first = decoded.charAt(0);
		if(!(first == '\'' || first == '\"')) return decoded;
		if(decoded.charAt(decoded.length()-1) == first) {
			return decoded.substring(1, decoded.length()-1);
		}
		return decoded;
	}

	public String detectedCharset() {
		return detectedCharset;
	}

    public static void main(String arg[]) throws Throwable {
        final File fin = new File("/tmp/test.css");
        final File fout = new File("/tmp/test2.css");
        fout.delete();
        final Bucket inputBucket = new FileBucket(fin, true, false, false, false);
        final Bucket outputBucket = new FileBucket(fout, false, true, false, false);
        InputStream inputStream = null;
        OutputStream outputStream = null;
        try {
            inputStream = inputBucket.getInputStream();
            outputStream = outputBucket.getOutputStream();
            Logger.setupStdoutLogging(Logger.LogLevel.DEBUG, "");

            ContentFilter.filter(inputStream, outputStream, "text/css",
                    new URI("http://127.0.0.1:8888/freenet:USK@ZupQjDFZSc3I4orBpl1iTEAPZKo2733RxCUbZ2Q7iH0,EO8Tuf8SP3lnDjQdAPdCM2ve2RaUEN8m-hod3tQ5oQE,AQACAAE/jFreesite/19/Style/"), null, null, null, null);
        } finally {
            Closer.close(inputStream);
            Closer.close(outputStream);
            inputBucket.free();
            outputBucket.free();
        }
    }
}
