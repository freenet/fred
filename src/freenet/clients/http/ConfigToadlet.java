/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.http;

import java.io.IOException;
import java.net.URI;

import freenet.client.HighLevelSimpleClient;
import freenet.config.Config;
import freenet.config.ConfigCallback;
import freenet.config.EnumerableOptionCallback;
import freenet.config.InvalidConfigValueException;
import freenet.config.NodeNeedRestartException;
import freenet.config.Option;
import freenet.config.SubConfig;
import freenet.config.WrapperConfig;
import freenet.l10n.NodeL10n;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.ProgramDirectory;
import freenet.node.useralerts.AbstractUserAlert;
import freenet.node.useralerts.UserAlert;
import freenet.pluginmanager.FredPluginConfigurable;
import freenet.support.HTMLNode;
import freenet.support.Logger;
import freenet.support.MultiValueTable;
import freenet.support.Logger.LogLevel;
import freenet.support.URLEncoder;
import freenet.support.api.BooleanCallback;
import freenet.support.api.HTTPRequest;

/**
 * Node Configuration Toadlet. Accessible from <code>http://.../config/</code>.
 */
// FIXME: add logging, comments
public class ConfigToadlet extends Toadlet implements LinkEnabledCallback {
	// If a setting has to be more than a meg, something is seriously wrong!
	private static final int MAX_PARAM_VALUE_SIZE = 1024*1024;
	private String directoryBrowserPath;
	private final SubConfig subConfig;
	private final Config config;
	private final NodeClientCore core;
	private final Node node;
	/** plugin is always null except when this ConfigToadlet serves a plugin */
	private final FredPluginConfigurable plugin;
	private boolean needRestart = false;
	private NeedRestartUserAlert needRestartUserAlert;

	/**
	 * Prompt for node restart
	 */
	private class NeedRestartUserAlert extends AbstractUserAlert {
		@Override
		public String getTitle() {
			return l10n("needRestartTitle");
		}

		@Override
		public String getText() {
			return getHTMLText().toString();
		}

		@Override
		public String getShortText() {
			return l10n("needRestartShort");
		}

		@Override
		public HTMLNode getHTMLText() {
			HTMLNode alertNode = new HTMLNode("div");
			alertNode.addChild("#", l10n("needRestart"));

			if (node.isUsingWrapper()) {
				alertNode.addChild("br");
				HTMLNode restartForm = alertNode.addChild("form",
				        new String[] { "action", "method", "enctype", "id",  "accept-charset" },
				        new String[] { "/", "post", "multipart/form-data", "restartForm", "utf-8"})
				        .addChild("div");
				restartForm.addChild("input",
				        new String[] { "type", "name", "value" },
				        new String[] { "hidden", "formPassword", node.clientCore.formPassword });
				restartForm.addChild("div");
				restartForm.addChild("input",//
				        new String[] { "type", "name" },//
				        new String[] { "hidden", "restart" });
				restartForm.addChild("input", //
				        new String[] { "type", "name", "value" },//
				        new String[] { "submit", "restart2",
				                 l10n( "restartNode") });
			}

			return alertNode;
		}

		@Override
		public short getPriorityClass() {
			return UserAlert.WARNING;
		}

		@Override
		public boolean isValid() {
			return needRestart;
		}

		@Override
		public boolean userCanDismiss() {
			return false;
		}
	}

	public ConfigToadlet(String directoryBrowserPath, HighLevelSimpleClient client, Config conf,
	        SubConfig subConfig, Node node, NodeClientCore core) {
		this(directoryBrowserPath, client, conf, subConfig, node, core, null);
	}

	public ConfigToadlet(HighLevelSimpleClient client, Config conf, SubConfig subConfig, Node node,
	        NodeClientCore core) {
		this(client, conf, subConfig, node, core, null);
	}

	public ConfigToadlet(String directoryBrowserPath, HighLevelSimpleClient client, Config conf,
	        SubConfig subConfig, Node node, NodeClientCore core, FredPluginConfigurable plugin) {
		this(client, conf, subConfig, node, core, plugin);
		this.directoryBrowserPath = directoryBrowserPath;
	}

	public ConfigToadlet(HighLevelSimpleClient client, Config conf, SubConfig subConfig, Node node,
	        NodeClientCore core, FredPluginConfigurable plugin) {
		super(client);
		config=conf;
		this.core = core;
		this.node = node;
		this.subConfig = subConfig;
		this.plugin = plugin;
		this.directoryBrowserPath = "/unset-browser-path/";
	}

	public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx) throws
	        ToadletContextClosedException, IOException, RedirectException {
		if (!ctx.isAllowedFullAccess()) {
			super.sendErrorPage(ctx, 403, NodeL10n.getBase().getString("Toadlet.unauthorizedTitle"),
			        NodeL10n.getBase().getString("Toadlet.unauthorized"));
			return;
		}
		
		String pass = request.getPartAsStringFailsafe("formPassword", 32);
		if((pass == null) || !pass.equals(core.formPassword)) {
			MultiValueTable<String,String> headers = new MultiValueTable<String,String>();
			headers.put("Location", path());
			ctx.sendReplyHeaders(302, "Found", headers, null, 0);
			return;
		}

		 //Returning from directory selector with a selection, re-render config page with any changes.
		if(request.isPartSet("select-dir")) {
			handleMethodGET(uri, request, ctx);
			return;
		}

		//Entering directory selector from config page.
		//This would be two loops if it checked for a redirect (key.startsWith("select-directory.")) before
		//constructing params string. It always constructs it, then redirects if it turns out to be needed.
		boolean directorySelector = false;
		String params = "?";
		String value;
		for(String key : request.getParts()) {
			 //Prepare parts for page selection redirect:
			//Extract option and put into "select-for"; preserve others.
			value = request.getPartAsStringFailsafe(key, MAX_PARAM_VALUE_SIZE);
			if(key.startsWith("select-directory.")) {
				params +="select-for="+URLEncoder.encode(key.substring("select-directory.".length()),true)+'&';
				directorySelector = true;
			} else {
				params += URLEncoder.encode(key,true)+'='+URLEncoder.encode(value, true)+'&';
			}
		}
		if(directorySelector) {
			MultiValueTable<String, String> headers = new MultiValueTable<String, String>(1);
			//params ends in &. Download directory browser starts in default download directory.
			headers.put("Location", directoryBrowserPath+params+
			        "path="+core.getDownloadsDir().getAbsolutePath());
			ctx.sendReplyHeaders(302, "Found", headers, null, 0);
			return;
		}

		StringBuilder errbuf = new StringBuilder();
		boolean logMINOR = Logger.shouldLog(LogLevel.MINOR, this);

		for(SubConfig sc : config.getConfigs()) {
			String prefix = sc.getPrefix();
			String configName;

			for(Option<?> o : sc.getOptions()) {
				configName=o.getName();
				if(logMINOR) Logger.minor(this, "Setting "+prefix+ '.' +configName);

				//This ignores unrecognized parameters.
				if(request.isPartSet(prefix+ '.' +configName)) {
					value = request.getPartAsStringFailsafe(prefix+ '.' +configName,
					        MAX_PARAM_VALUE_SIZE);
					if(!(o.getValueString().equals(value))){
						if(logMINOR) Logger.minor(this, "Setting "+prefix+ '.' +configName+
						        " to "+value);
						try{
							o.setValue(value);
						} catch (InvalidConfigValueException e) {
							errbuf.append(o.getName()).append(' ')
							        .append(e.getMessage()).append('\n');
						} catch (NodeNeedRestartException e) {
							needRestart = true;
						} catch (Exception e){
							errbuf.append(o.getName()).append(' ').append(e).append('\n');
							Logger.error(this, "Caught "+e, e);
						}
					}
				}
			}

			// Wrapper params
			String wrapperConfigName = "wrapper.java.maxmemory";
			if(request.isPartSet(wrapperConfigName)) {
				value = request.getPartAsStringFailsafe(wrapperConfigName, MAX_PARAM_VALUE_SIZE);
				if(!WrapperConfig.getWrapperProperty(wrapperConfigName).equals(value)) {
					if(logMINOR) Logger.minor(this, "Setting "+wrapperConfigName+" to "+value);
					WrapperConfig.setWrapperProperty(wrapperConfigName, value);
				}
			}
		}
		config.store();

		PageNode page = ctx.getPageMaker().getPageNode(l10n("appliedTitle"), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;

		if (errbuf.length() == 0) {
			HTMLNode content = ctx.getPageMaker().getInfobox("infobox-success", l10n("appliedTitle"),
			        contentNode, "configuration-applied", true);
			content.addChild("#", l10n("appliedSuccess"));

			if (needRestart) {
				content.addChild("br");
				content.addChild("#", l10n("needRestart"));

				if (node.isUsingWrapper()) {
					content.addChild("br");
					HTMLNode restartForm = ctx.addFormChild(content, "/", "restartForm");
					restartForm.addChild("input",//
					        new String[] { "type", "name" },//
					        new String[] { "hidden", "restart" });
					restartForm.addChild("input", //
					        new String[] { "type", "name", "value" },//
					        new String[] { "submit", "restart2",//
					                l10n( "restartNode") });
				}

				if (needRestartUserAlert == null) {
					needRestartUserAlert = new NeedRestartUserAlert();
					node.clientCore.alerts.register(needRestartUserAlert);
				}
			}
		} else {
			HTMLNode content = ctx.getPageMaker().getInfobox("infobox-error", l10n("appliedFailureTitle"),
			        contentNode, "configuration-error", true).addChild("div", "class", "infobox-content");
			content.addChild("#", l10n("appliedFailureExceptions"));
			content.addChild("br");
			content.addChild("#", errbuf.toString());
		}

		HTMLNode content = ctx.getPageMaker().getInfobox("infobox-normal", l10n("possibilitiesTitle"),
		        contentNode, "configuration-possibilities", false);
		content.addChild("a", new String[]{"href", "title"}, new String[]{path(), l10n("shortTitle")},
		        l10n("returnToNodeConfig"));
		content.addChild("br");
		addHomepageLink(content);

		writeHTMLReply(ctx, 200, "OK", pageNode.generate());

	}

	private static final String l10n(String string) {
		return NodeL10n.getBase().getString("ConfigToadlet." + string);
	}

	public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx) throws ToadletContextClosedException,
	        IOException {

		if(!ctx.isAllowedFullAccess()) {
			super.sendErrorPage(ctx, 403,
			        NodeL10n.getBase().getString("Toadlet.unauthorizedTitle"),
			        NodeL10n.getBase().getString("Toadlet.unauthorized"));
			return;
		}

		final int mode = ctx.getPageMaker().parseMode(req, container);

		PageNode page = ctx.getPageMaker().getPageNode(NodeL10n.getBase().
		        getString("ConfigToadlet.fullTitle", new String[]{"name"},
		        new String[]{node.getMyName()}), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;

		contentNode.addChild(core.alerts.createSummary());

		HTMLNode infobox = contentNode.addChild("div", "class", "infobox infobox-normal");
		infobox.addChild("div", "class", "infobox-header", l10n("title"));
		HTMLNode configNode = infobox.addChild("div", "class", "infobox-content");
		HTMLNode formNode = ctx.addFormChild(configNode, path(), "configForm");

		//Invisible apply button at the top so that an enter keypress will apply settings instead of
		//going to a directory browser if present.
		formNode.addChild("input",
		        new String[] { "type", "value", "style" },
		        new String[] { "submit", l10n("apply"), "visibility:hidden"});

		if(subConfig.getPrefix().equals("node") && WrapperConfig.canChangeProperties()) {
			String configName = "wrapper.java.maxmemory";
			String curValue = WrapperConfig.getWrapperProperty(configName);
			//If persisted from directory browser, override. This is a POST HTTPRequest.
			if(req.isPartSet(configName)) {
				curValue = req.getPartAsStringFailsafe(configName, MAX_PARAM_VALUE_SIZE);
			}
			if(curValue != null) {
				formNode.addChild("div", "class", "configprefix", l10n("wrapper"));
				HTMLNode list = formNode.addChild("ul", "class", "config");
				HTMLNode item = list.addChild("li");
				// FIXME how to get the real default???
				String defaultValue = "128";
				item.addChild("span", new String[]{ "class", "title", "style" },
				        new String[]{ "configshortdesc",
				                NodeL10n.getBase().getString("ConfigToadlet.defaultIs",
				        new String[] { "default" }, new String[] { defaultValue }),
				        "cursor: help;" }).addChild(
				                NodeL10n.getBase().getHTMLNode("WrapperConfig."+configName+".short"));
				item.addChild("span", "class", "config").addChild("input",
				        new String[] { "type", "class", "name", "value" },
				        new String[] { "text", "config", configName, curValue });
				item.addChild("span", "class", "configlongdesc").addChild(
				        NodeL10n.getBase().getHTMLNode("WrapperConfig."+configName+".long"));
			}
		}

			short displayedConfigElements = 0;
			HTMLNode configGroupUlNode = new HTMLNode("ul", "class", "config");
			
			String overriddenOption = null;
			String overriddenValue = null;
			
			//A value changed by the directory selector takes precedence.
			if(req.isPartSet("select-for") && req.isPartSet("select-dir")) {
				overriddenOption = req.getPartAsStringFailsafe("select-for",
				        MAX_PARAM_VALUE_SIZE);
				overriddenValue = req.getPartAsStringFailsafe("filename",
						MAX_PARAM_VALUE_SIZE);
			}

			for(Option<?> o : subConfig.getOptions()) {
				if(! (mode == PageMaker.MODE_SIMPLE && o.isExpert())){
					displayedConfigElements++;
					String configName = o.getName();
					String fullName = subConfig.getPrefix() + '.' + configName;
					String value = o.getValueString();

					// If ConfigToadlet is serving a plugin, ask the plugin to translate the
					// config descriptions, otherwise use the node's BaseL10n instance like
					// normal.
					HTMLNode shortDesc = (plugin == null) ?
					        NodeL10n.getBase().getHTMLNode(o.getShortDesc()) :
					        new HTMLNode("#", plugin.getString(o.getShortDesc()));
					HTMLNode longDesc = (plugin == null) ?
					        NodeL10n.getBase().getHTMLNode(o.getLongDesc()) :
					        new HTMLNode("#", plugin.getString(o.getLongDesc()));

					HTMLNode configItemNode = configGroupUlNode.addChild("li");
					configItemNode.addChild("a", new String[]{"name", "id"},
					        new String[]{configName, configName}).addChild("span",
					        new String[]{ "class", "title", "style" },
					        new String[]{ "configshortdesc",
					                NodeL10n.getBase().getString("ConfigToadlet.defaultIs",
					                new String[] { "default" },
					                new String[] { o.getDefault() }) +
					                (mode >= PageMaker.MODE_ADVANCED ? " ["+ fullName + ']' : ""),
					        "cursor: help;" }).addChild(shortDesc);
					HTMLNode configItemValueNode =
					        configItemNode.addChild("span", "class", "config");
					if(value == null){
						Logger.error(this, fullName + "has returned null from config!);");
						continue;
					}

					//Values persisted through browser override currently applied ones
					if(req.isPartSet(fullName)) {
						//TODO: This may have to be Base64 encoded
						value = req.getPartAsStringFailsafe(fullName, MAX_PARAM_VALUE_SIZE);
					}
					if(overriddenOption != null && overriddenOption.equals(fullName))
						value = overriddenValue;
					ConfigCallback<?> callback = o.getCallback();
					if(callback instanceof EnumerableOptionCallback)
						configItemValueNode.addChild(addComboBox(value,
						        (EnumerableOptionCallback) callback, fullName,
						        callback.isReadOnly()));
					else if(callback instanceof BooleanCallback)
						configItemValueNode.addChild(addBooleanComboBox(Boolean.valueOf(value),
						        fullName, callback.isReadOnly()));
					else if(callback instanceof ProgramDirectory.DirectoryCallback &&
					        !callback.isReadOnly()){
						configItemValueNode.addChild(addTextBox(value, fullName, o, false));
						configItemValueNode.addChild("input",
						        new String[] { "type", "name", "value" },
						        new String[] { "submit", "select-directory."+fullName,
						                NodeL10n.getBase().
						                        getString("QueueToadlet.browseToChange") });
					}
					else if (callback.isReadOnly())
						configItemValueNode.addChild(addTextBox(value, fullName, o, true));
					else //if (!callback.isReadOnly())
						configItemValueNode.addChild(addTextBox(value, fullName, o, false));

					configItemNode.addChild("span", "class", "configlongdesc").addChild(longDesc);
				}
			}

			if(displayedConfigElements > 0) {
				formNode.addChild("div", "class", "configprefix", (plugin == null) ?
				        l10n(subConfig.getPrefix()) :
				        plugin.getString(subConfig.getPrefix()));
				formNode.addChild("a", "id", subConfig.getPrefix());
				formNode.addChild(configGroupUlNode);
			}

		formNode.addChild("input", new String[] { "type", "value" }, new String[] { "submit", l10n("apply")});
		formNode.addChild("input", new String[] { "type", "value" }, new String[] { "reset",  l10n("reset")});

		this.writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	}

	private HTMLNode addTextBox(String value, String fullName, Option<?> o, boolean disabled) {
		HTMLNode result;

		if(disabled) {
			result = new HTMLNode("input",
			         new String[] { "type", "class", "disabled", "alt", "name", "value" }, //
			         new String[] { "text", "config", "disabled", o.getShortDesc(), fullName, value });
		}
		else {
			result = new HTMLNode("input",
			         new String[] { "type", "class", "alt", "name", "value" }, //
			         new String[] { "text", "config", o.getShortDesc(), fullName, value });
		}

		return result;
	}

	private HTMLNode addComboBox(String value, EnumerableOptionCallback o, String fullName, boolean disabled) {
		HTMLNode result;

		if (disabled)
			result = new HTMLNode("select", //
			         new String[] { "name", "disabled" }, //
			         new String[] { fullName, "disabled" });
		else
			result = new HTMLNode("select", "name", fullName);

		for(String possibleValue : o.getPossibleValues()) {
			if(possibleValue.equals(value))
				result.addChild("option",
				        new String[] { "value", "selected" },
				        new String[] { possibleValue, "selected" }, possibleValue);
			else
				result.addChild("option", "value", possibleValue, possibleValue);
		}

		return result;
	}

	private HTMLNode addBooleanComboBox(boolean value, String fullName, boolean disabled) {
		HTMLNode result;

		if (disabled)
			result = new HTMLNode("select", //
			         new String[] { "name", "disabled" }, //
			         new String[] {fullName, "disabled" });
		else
			result = new HTMLNode("select", "name", fullName);

		if (value) {
			result.addChild("option",
			        new String[] { "value", "selected" },
			        new String[] { "true", "selected" },
			        l10n("true"));
			result.addChild("option", "value", "false", l10n("false"));
		} else {
			result.addChild("option", "value", "true", l10n("true"));
			result.addChild("option",
			        new String[] { "value", "selected" },
			        new String[] { "false", "selected" },
			        l10n("false"));
		}

		return result;
	}

	@Override
	public String path() {
		return "/config/"+subConfig.getPrefix();
	}

	@Override
	public boolean isEnabled(ToadletContext ctx) {
		Option<?>[] o = subConfig.getOptions();
		if(core.isAdvancedModeEnabled()) return true;
		for(Option<?> option : o)
			if(!option.isExpert()) return true;
		return false;
	}
}
