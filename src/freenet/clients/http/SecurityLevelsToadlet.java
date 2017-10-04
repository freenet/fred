/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.http;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;

import freenet.client.HighLevelSimpleClient;
import freenet.clients.http.wizardsteps.PageHelper;
import freenet.clients.http.wizardsteps.WizardL10n;
import freenet.l10n.NodeL10n;
import freenet.node.MasterKeysFileSizeException;
import freenet.node.MasterKeysWrongPasswordException;
import freenet.node.Node;
import freenet.node.Node.AlreadySetPasswordException;
import freenet.node.NodeClientCore;
import freenet.node.SecurityLevels;
import freenet.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import freenet.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import freenet.support.HTMLNode;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.MultiValueTable;
import freenet.support.api.HTTPRequest;
import freenet.support.io.FileUtil;
import freenet.support.io.FileUtil.OperatingSystem;

/**
 * The security levels page.
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 *
 */
public class SecurityLevelsToadlet extends Toadlet {

	public static final int MAX_PASSWORD_LENGTH = 1024;
	private final NodeClientCore core;
	private final Node node;

        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	SecurityLevelsToadlet(HighLevelSimpleClient client, Node node, NodeClientCore core) {
		super(client);
		this.core = core;
		this.node = node;
	}

	@SuppressWarnings("UnusedParameters")
	public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {
        if(!ctx.checkFullAccess(this))
            return;

		if(request.isPartSet("seclevels")) {
			// Handle the security level changes.
			HTMLNode pageNode = null;
			HTMLNode content = null;
			HTMLNode ul = null;
			HTMLNode formNode = null;
			boolean changedAnything = false;
			String configName = "security-levels.networkThreatLevel";
			String confirm = "security-levels.networkThreatLevel.confirm";
			String tryConfirm = "security-levels.networkThreatLevel.tryConfirm";
			String networkThreatLevel = request.getPartAsStringFailsafe(configName, 128);
			NETWORK_THREAT_LEVEL newThreatLevel = SecurityLevels.parseNetworkThreatLevel(networkThreatLevel);
			if(newThreatLevel != null) {
				if(newThreatLevel != node.securityLevels.getNetworkThreatLevel()) {
					if(!request.isPartSet(confirm) && !request.isPartSet(tryConfirm)) {
						HTMLNode warning = node.securityLevels.getConfirmWarning(newThreatLevel, confirm);
						if(warning != null) {
							PageNode page = ctx.getPageMaker().getPageNode(NodeL10n.getBase().getString("ConfigToadlet.fullTitle"), ctx);
							pageNode = page.outer;
							content = page.content;
							formNode = ctx.addFormChild(content, ".", "configFormSecLevels");
							ul = formNode.addChild("ul", "class", "config");
							HTMLNode seclevelGroup = ul.addChild("li");

							seclevelGroup.addChild("input", new String[] { "type", "name", "value" }, new String[] { "hidden", configName, networkThreatLevel });
							HTMLNode infobox = seclevelGroup.addChild("div", "class", "infobox infobox-information");
							infobox.addChild("div", "class", "infobox-header", l10nSec("networkThreatLevelConfirmTitle", "mode", SecurityLevels.localisedName(newThreatLevel)));
							HTMLNode infoboxContent = infobox.addChild("div", "class", "infobox-content");
							infoboxContent.addChild(warning);
							infoboxContent.addChild("input", new String[] { "type", "name", "value" }, new String[] { "hidden", tryConfirm, "on" });
						} else {
							// Apply immediately, no confirm needed.
							node.securityLevels.setThreatLevel(newThreatLevel);
							changedAnything = true;
						}
					} else if(request.isPartSet(confirm)) {
						// Apply immediately, user confirmed it.
						node.securityLevels.setThreatLevel(newThreatLevel);
						changedAnything = true;
					}
				}
			}

			configName = "security-levels.physicalThreatLevel";
			confirm = "security-levels.physicalThreatLevel.confirm";
			tryConfirm = "security-levels.physicalThreatLevel.tryConfirm";
			String physicalThreatLevel = request.getPartAsStringFailsafe(configName, 128);
			PHYSICAL_THREAT_LEVEL newPhysicalLevel = SecurityLevels.parsePhysicalThreatLevel(physicalThreatLevel);
			PHYSICAL_THREAT_LEVEL oldPhysicalLevel = core.node.securityLevels.getPhysicalThreatLevel();
			if(logMINOR) Logger.minor(this, "New physical threat level: "+newPhysicalLevel+" old = "+node.securityLevels.getPhysicalThreatLevel());
			if(newPhysicalLevel != null) {
				if(newPhysicalLevel == oldPhysicalLevel && newPhysicalLevel == PHYSICAL_THREAT_LEVEL.HIGH) {
					String password = request.getPartAsStringFailsafe("masterPassword", MAX_PASSWORD_LENGTH);
					String oldPassword = request.getPartAsStringFailsafe("oldPassword", MAX_PASSWORD_LENGTH);
					String confirmPassword = request.getPartAsStringFailsafe("confirmMasterPassword", MAX_PASSWORD_LENGTH);
					if (!oldPassword.isEmpty() && !confirmPassword.isEmpty() && !password.isEmpty() && password.equals(confirmPassword)) {
						try {
							core.node.changeMasterPassword(password);
						} catch (MasterKeysWrongPasswordException e) {
							sendChangePasswordForm(ctx, true, false, newPhysicalLevel.name());
							return;
						} catch (MasterKeysFileSizeException e) {
							sendPasswordFileCorruptedPage(ctx);
							if(changedAnything)
								core.storeConfig();
							return;
						} catch (AlreadySetPasswordException e) {
							sendChangePasswordForm(ctx, false, true, newPhysicalLevel.name());
							if(changedAnything)
								core.storeConfig();
							return;
						}
					} else if (!password.isEmpty() || !oldPassword.isEmpty() || !confirmPassword.isEmpty()) {
						sendChangePasswordForm(ctx, false, true, newPhysicalLevel.name());
						if(changedAnything)
							core.storeConfig();
						return;
					}
				}
				if(newPhysicalLevel != oldPhysicalLevel) {
					// No confirmation for changes to physical threat level.
					if(newPhysicalLevel == PHYSICAL_THREAT_LEVEL.HIGH && node.securityLevels.getPhysicalThreatLevel() != newPhysicalLevel) {
						// Check for password
						String password = request.getPartAsStringFailsafe("masterPassword", MAX_PASSWORD_LENGTH);
						String confirmPassword = request.getPartAsStringFailsafe("confirmMasterPassword", MAX_PASSWORD_LENGTH);
						if (!password.isEmpty() && !confirmPassword.isEmpty() && password.equals(confirmPassword)) {
							try {
								if(oldPhysicalLevel == PHYSICAL_THREAT_LEVEL.NORMAL || oldPhysicalLevel == PHYSICAL_THREAT_LEVEL.LOW)
									core.node.changeMasterPassword(password);
								else
									core.node.setMasterPassword(password);
							} catch (AlreadySetPasswordException e) {
								sendChangePasswordForm(ctx, false, false, newPhysicalLevel.name());
								return;
							} catch (MasterKeysWrongPasswordException e) {
								System.err.println("Wrong password!");
								PageNode page = ctx.getPageMaker().getPageNode(l10nSec("passwordPageTitle"), ctx);
								pageNode = page.outer;
								HTMLNode contentNode = page.content;

								content = ctx.getPageMaker().getInfobox("infobox-error",
										l10nSec("passwordWrongTitle"), contentNode, "wrong-password", true).
										addChild("div", "class", "infobox-content");
								SecurityLevelsToadlet.generatePasswordFormPage(true, ctx.getContainer(), content, false, false, true, newPhysicalLevel.name(), null);
								addBackToSeclevelsLink(content);
								writeHTMLReply(ctx, 200, "OK", pageNode.generate());
								if(changedAnything)
									core.storeConfig();
								return;
							} catch (MasterKeysFileSizeException e) {
								sendPasswordFileCorruptedPage(ctx);
								if(changedAnything)
									core.storeConfig();
								return;
							}
						} else {
							if (password.isEmpty() || confirmPassword.isEmpty()) {
								sendPasswordPage(ctx, true, newPhysicalLevel.name());
							} else {
								sendPasswordPageMismatch(ctx, newPhysicalLevel.name());
							}
							if(changedAnything)
								core.storeConfig();
							return;
						}
					}
					if((newPhysicalLevel == PHYSICAL_THREAT_LEVEL.LOW || newPhysicalLevel == PHYSICAL_THREAT_LEVEL.NORMAL) &&
							oldPhysicalLevel == PHYSICAL_THREAT_LEVEL.HIGH) {
						// Check for password
						String password = request.getPartAsStringFailsafe("masterPassword", SecurityLevelsToadlet.MAX_PASSWORD_LENGTH);
						if (!password.isEmpty()) {
							// This is actually the OLD password ...
							try {
								core.node.changeMasterPassword("");
							} catch (IOException e) {
								if(!core.node.getMasterPasswordFile().exists()) {
									// Ok.
									System.out.println("Master password file no longer exists, assuming this is deliberate");
								} else {
									System.err.println("Cannot change password as cannot write new passwords file: "+e);
									e.printStackTrace();
									String msg = "<html><head><title>"+l10nSec("cantWriteNewMasterKeysFileTitle")+
										"</title></head><body><h1>"+l10nSec("cantWriteNewMasterKeysFileTitle")+"</h1><p>"+l10nSec("cantWriteNewMasterKeysFile")+"<pre>";
									StringWriter sw = new StringWriter();
									PrintWriter pw = new PrintWriter(sw);
									e.printStackTrace(pw);
									pw.flush();
									msg = msg + sw.toString() + "</pre></body></html>";
									writeHTMLReply(ctx, 500, "Internal Error", msg);
									if(changedAnything)
										core.storeConfig();
									return;
								}
							} catch (MasterKeysWrongPasswordException e) {
								System.err.println("Wrong password!");
								PageNode page = ctx.getPageMaker().getPageNode(l10nSec("passwordForDecryptTitle"), ctx);
								pageNode = page.outer;
								HTMLNode contentNode = page.content;

								content = ctx.getPageMaker().getInfobox("infobox-error",
										l10nSec("passwordWrongTitle"), contentNode, "wrong-password", true).
										addChild("div", "class", "infobox-content");

								SecurityLevelsToadlet.generatePasswordFormPage(true, ctx.getContainer(), content, false, true, false, newPhysicalLevel.name(), null);

								addBackToSeclevelsLink(content);

								writeHTMLReply(ctx, 200, "OK", pageNode.generate());
								if(changedAnything)
									core.storeConfig();
								return;
							} catch (MasterKeysFileSizeException e) {
								sendPasswordFileCorruptedPage(ctx);
								if(changedAnything)
									core.storeConfig();
								return;
							} catch (AlreadySetPasswordException e) {
								sendChangePasswordForm(ctx, false, true, newPhysicalLevel.name());
								if(changedAnything)
									core.storeConfig();
								return;
							}
						} else if(core.node.getMasterPasswordFile().exists()) {
							// We need the old password
							PageNode page = ctx.getPageMaker().getPageNode(l10nSec("passwordForDecryptTitle"), ctx);
							pageNode = page.outer;
							HTMLNode contentNode = page.content;

							content = ctx.getPageMaker().getInfobox("infobox-error",
									l10nSec("passwordForDecryptTitle"), contentNode, "password-prompt", false).
									addChild("div", "class", "infobox-content");

							if (password.isEmpty()) {
								content.addChild("p", l10nSec("passwordNotZeroLength"));
							}

							SecurityLevelsToadlet.generatePasswordFormPage(false, ctx.getContainer(), content, false, true, false, newPhysicalLevel.name(), null);

							addBackToSeclevelsLink(content);

							writeHTMLReply(ctx, 200, "OK", pageNode.generate());
							if(changedAnything)
								core.storeConfig();
							return;

						}

					}
					if(newPhysicalLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM) {
						try {
							core.node.killMasterKeysFile();
						} catch (IOException e) {
							sendCantDeleteMasterKeysFile(ctx, newPhysicalLevel.name());
							return;
						}
					}
					node.securityLevels.setThreatLevel(newPhysicalLevel);
					changedAnything = true;
				}
			}

			if(changedAnything)
				core.storeConfig();

			if(pageNode != null) {
				formNode.addChild("input", new String[] { "type", "name", "value" }, new String[] { "hidden", "seclevels", "on" });
				formNode.addChild("input", new String[] { "type", "value" }, new String[] { "submit", l10n("apply")});
				formNode.addChild("input", new String[] { "type", "value" }, new String[] { "reset",  l10n("undo")});
				writeHTMLReply(ctx, 200, "OK", pageNode.generate());
				return;
			} else {
				MultiValueTable<String, String> headers = new MultiValueTable<String, String>();
				headers.put("Location", "/seclevels/");
				ctx.sendReplyHeaders(302, "Found", headers, null, 0);
				return;
			}
		} else {

			if(request.isPartSet("masterPassword")) {
				String masterPassword = request.getPartAsStringFailsafe("masterPassword", 1024);
				if (masterPassword.isEmpty()) {
					sendPasswordPage(ctx, true, null);
					return;
				}
				System.err.println("Setting master password");
				try {
					node.setMasterPassword(masterPassword);
				} catch (AlreadySetPasswordException e) {
					System.err.println("Already set master password");
					Logger.error(this, "Already set master password");
					MultiValueTable<String,String> headers = new MultiValueTable<String,String>();
					headers.put("Location", "/");
					ctx.sendReplyHeaders(302, "Found", headers, null, 0);
					return;
				} catch (MasterKeysWrongPasswordException e) {
					sendPasswordFormPage(true, ctx);
					return;
				} catch (MasterKeysFileSizeException e) {
					sendPasswordFileCorruptedPage(ctx);
					return;
				}
				MultiValueTable<String,String> headers = new MultiValueTable<String,String>();
				if(request.isPartSet("redirect")) {
					String to = request.getPartAsStringFailsafe("redirect", 100);
					if(to.startsWith("/")) {
						headers.put("Location", to);
						ctx.sendReplyHeaders(302, "Found", headers, null, 0);
						return;
					}
				}
				headers.put("Location", "/");
				ctx.sendReplyHeaders(302, "Found", headers, null, 0);
				return;
			}

			try {
				throw new RedirectException("/seclevels/");
			} catch (URISyntaxException e) {
				// Impossible
			}
		}

		MultiValueTable<String,String> headers = new MultiValueTable<String,String>();
		headers.put("Location", "/");
		ctx.sendReplyHeaders(302, "Found", headers, null, 0);
	}

	private void sendCantDeleteMasterKeysFile(ToadletContext ctx, String physicalSecurityLevel) throws ToadletContextClosedException, IOException {
		HTMLNode pageNode = sendCantDeleteMasterKeysFileInner(ctx, node.getMasterPasswordFile().getPath(), false, physicalSecurityLevel);
		writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	}

	public static void sendCantDeleteMasterKeysFileInner(PageHelper helper, String filename, String physicalSecurityLevel) {
		HTMLNode contentNode = helper.getPageContent(l10nSec("cantDeletePasswordFileTitle"));
		HTMLNode content = helper.getInfobox("infobox-error",
		        l10nSec("cantDeletePasswordFileTitle"), contentNode, "password-error", true).
		        addChild("div", "class", "infobox-content");
		HTMLNode form = helper.addFormChild(content, "/wizard/", "masterPasswordForm");
		sendCantDeleteMasterKeysFileInner(content, form, filename, physicalSecurityLevel);
	}

	public static HTMLNode sendCantDeleteMasterKeysFileInner(ToadletContext ctx, String filename, boolean forFirstTimeWizard, String physicalSecurityLevel) {
		PageNode page = ctx.getPageMaker().getPageNode(l10nSec("cantDeletePasswordFileTitle"), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;

		HTMLNode content = ctx.getPageMaker().getInfobox("infobox-error",
				l10nSec("cantDeletePasswordFileTitle"), contentNode, "password-error", true).
				addChild("div", "class", "infobox-content");

		HTMLNode form = forFirstTimeWizard ? ctx.addFormChild(content, "/wizard/", "masterPasswordForm") :
			ctx.addFormChild(content, "/seclevels/", "masterPasswordForm");

		sendCantDeleteMasterKeysFileInner(content, form, filename, physicalSecurityLevel);
		return pageNode;
	}

	private static void sendCantDeleteMasterKeysFileInner(HTMLNode content, HTMLNode form, String filename, String physicalSecurityLevel) {
		form.addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "hidden", "security-levels.physicalThreatLevel", physicalSecurityLevel });
		form.addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "hidden", "seclevels", "true" });

		form.addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "submit", "tryAgain", l10nSec("cantDeletePasswordFileButton") });

		content.addChild("p", l10nSec("cantDeletePasswordFile", "filename", filename));
	}

	/** Send a form asking the user to change the password.
	 * @throws IOException
	 * @throws ToadletContextClosedException */
	private void sendChangePasswordForm(ToadletContext ctx, boolean wrongPassword, boolean emptyPassword, String physicalSecurityLevel) throws ToadletContextClosedException, IOException {

		// Must set a password!
		PageNode page = ctx.getPageMaker().getPageNode(l10nSec("changePasswordTitle"), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;

		HTMLNode content = ctx.getPageMaker().getInfobox("infobox-error",
				l10nSec("changePasswordTitle"), contentNode, "password-change", true).
				addChild("div", "class", "infobox-content");

		if(emptyPassword) {
			content.addChild("p", l10nSec("passwordNotZeroLength"));
		}

		if(wrongPassword) {
			content.addChild("p", l10nSec("wrongOldPassword"));
		}

		HTMLNode form = ctx.addFormChild(content, path(), "changePasswordForm");

		addPasswordChangeForm(form);

		if(physicalSecurityLevel != null) {
			form.addChild("input", new String[] { "type", "name", "value" }, new String[] { "hidden", "security-levels.physicalThreatLevel", physicalSecurityLevel });
			form.addChild("input", new String[] { "type", "name", "value" }, new String[] { "hidden", "seclevels", "true" });
		}
		addBackToSeclevelsLink(content);

		writeHTMLReply(ctx, 200, "OK", pageNode.generate());

	}

	private void sendPasswordPage(ToadletContext ctx, boolean emptyPassword, String threatlevel) throws ToadletContextClosedException, IOException {

		// Must set a password!
		PageNode page = ctx.getPageMaker().getPageNode(l10nSec("setPasswordTitle"), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;

		HTMLNode content = ctx.getPageMaker().getInfobox("infobox-error",
				l10nSec("setPasswordTitle"), contentNode, "password-prompt", false).
				addChild("div", "class", "infobox-content");

		if(emptyPassword) {
			content.addChild("p", l10nSec("passwordNotZeroLength"));
		}

		SecurityLevelsToadlet.generatePasswordFormPage(false, ctx.getContainer(), content, false, false, true, threatlevel, null);

		addBackToSeclevelsLink(content);

		writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	}

	private static void addBackToSeclevelsLink(HTMLNode content) {
		content.addChild("p").addChild("a", "href", PATH, l10nSec("backToSecurityLevels"));
	}

    public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx) throws ToadletContextClosedException, IOException {
        if(!ctx.checkFullAccess(this))
            return;

		PageNode page = ctx.getPageMaker().getPageNode(NodeL10n.getBase().getString("SecurityLevelsToadlet.fullTitle"), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;

		contentNode.addChild(ctx.getAlertManager().createSummary());

		drawSecurityLevelsPage(contentNode, ctx);

		this.writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	}

	private void drawSecurityLevelsPage(HTMLNode contentNode, ToadletContext ctx) {
		HTMLNode infobox = contentNode.addChild("div", "class", "infobox infobox-normal");
		infobox.addChild("div", "class", "infobox-header", l10nSec("title"));
		HTMLNode configNode = infobox.addChild("div", "class", "infobox-content");
		HTMLNode formNode = ctx.addFormChild(configNode, ".", "configFormSecLevels");
		// Network security level
		formNode.addChild("div", "class", "configprefix", l10nSec("networkThreatLevelShort"));
		HTMLNode ul = formNode.addChild("ul", "class", "config");
		HTMLNode seclevelGroup = ul.addChild("li");
		seclevelGroup.addChild("#", l10nSec("networkThreatLevel.opennetIntro"));

		NETWORK_THREAT_LEVEL networkLevel = node.securityLevels.getNetworkThreatLevel();

		HTMLNode p = seclevelGroup.addChild("p");
		p.addChild("b", l10nSec("networkThreatLevel.opennetLabel"));
		p.addChild("#", ": "+l10nSec("networkThreatLevel.opennetExplain"));
		HTMLNode div = seclevelGroup.addChild("div", "class", "opennetDiv");
		
		String controlName = "security-levels.networkThreatLevel";
		for(NETWORK_THREAT_LEVEL level : NETWORK_THREAT_LEVEL.getOpennetValues()) {
			HTMLNode input;
			if(level == networkLevel) {
				input = div.addChild("p").addChild("input", new String[] { "type", "checked", "name", "value" }, new String[] { "radio", "on", controlName, level.name() });
			} else {
				input = div.addChild("p").addChild("input", new String[] { "type", "name", "value" }, new String[] { "radio", controlName, level.name() });
			}
			input.addChild("b", l10nSec("networkThreatLevel.name."+level));
			input.addChild("#", ": ");
			NodeL10n.getBase().addL10nSubstitution(input, "SecurityLevels.networkThreatLevel.choice."+level, new String[] { "bold" },
					new HTMLNode[] { HTMLNode.STRONG });
			HTMLNode inner = input.addChild("p").addChild("i");

			NodeL10n.getBase().addL10nSubstitution(inner, "SecurityLevels.networkThreatLevel.desc."+level, new String[] { "bold" },
					new HTMLNode[] { HTMLNode.STRONG });
		}

		p = seclevelGroup.addChild("p");
		p.addChild("b", l10nSec("networkThreatLevel.darknetLabel"));
		p.addChild("#", ": "+l10nSec("networkThreatLevel.darknetExplain"));
		div = seclevelGroup.addChild("div", "class", "darknetDiv");
		
		for(NETWORK_THREAT_LEVEL level : NETWORK_THREAT_LEVEL.getDarknetValues()) {
			HTMLNode input;
			if(level == networkLevel) {
				input = div.addChild("p").addChild("input", new String[] { "type", "checked", "name", "value" }, new String[] { "radio", "on", controlName, level.name() });
			} else {
				input = div.addChild("p").addChild("input", new String[] { "type", "name", "value" }, new String[] { "radio", controlName, level.name() });
			}
			input.addChild("b", l10nSec("networkThreatLevel.name."+level));
			input.addChild("#", ": ");
			NodeL10n.getBase().addL10nSubstitution(input, "SecurityLevels.networkThreatLevel.choice."+level, new String[] { "bold" },
					new HTMLNode[] { HTMLNode.STRONG });
			HTMLNode inner = input.addChild("p").addChild("i");
			NodeL10n.getBase().addL10nSubstitution(inner, "SecurityLevels.networkThreatLevel.desc."+level, new String[] { "bold", "link" },
					new HTMLNode[] { HTMLNode.STRONG, HTMLNode.link("/wizard/?step=OPENNET") });
		}
		seclevelGroup.addChild("p").addChild("b", l10nSec("networkThreatLevel.opennetFriendsWarning"));

		// Physical security level
		formNode.addChild("div", "class", "configprefix", l10nSec("physicalThreatLevelShort"));
		ul = formNode.addChild("ul", "class", "config");
		seclevelGroup = ul.addChild("li");
		seclevelGroup.addChild("#", l10nSec("physicalThreatLevel"));
		
		NodeL10n.getBase().addL10nSubstitution(seclevelGroup.addChild("p").addChild("i"), "SecurityLevels.physicalThreatLevelFDE",
		        new String[]{"bold", "link"},
		        new HTMLNode[]{HTMLNode.STRONG,
		                HTMLNode.linkInNewWindow(ExternalLinkToadlet.escape(l10nSec("physicalThreatLevelFDELink")))});
		HTMLNode swapWarning = seclevelGroup.addChild("p").addChild("i");
		OperatingSystem os = FileUtil.detectedOS;
		swapWarning.addChild("#", NodeL10n.getBase().getString("SecurityLevels.physicalThreatLevelSwapfile",
		        "operatingSystem",
		        NodeL10n.getBase().getString("OperatingSystemName."+os.name())));
		if(os == FileUtil.OperatingSystem.Windows) {
			swapWarning.addChild("#", " " + WizardL10n.l10nSec("physicalThreatLevelSwapfileWindows"));
		}

		PHYSICAL_THREAT_LEVEL physicalLevel = node.securityLevels.getPhysicalThreatLevel();

		controlName = "security-levels.physicalThreatLevel";
		for(PHYSICAL_THREAT_LEVEL level : PHYSICAL_THREAT_LEVEL.values()) {
			HTMLNode input;
			if(level == physicalLevel) {
				input = seclevelGroup.addChild("p").addChild("input", new String[] { "type", "checked", "name", "value" }, new String[] { "radio", "on", controlName, level.name() });
			} else {
				input = seclevelGroup.addChild("p").addChild("input", new String[] { "type", "name", "value" }, new String[] { "radio", controlName, level.name() });
			}
			input.addChild("b", l10nSec("physicalThreatLevel.name."+level));
			input.addChild("#", ": ");
			NodeL10n.getBase().addL10nSubstitution(input, "SecurityLevels.physicalThreatLevel.choice."+level, new String[] { "bold" },
					new HTMLNode[] { HTMLNode.STRONG });
			HTMLNode inner = input.addChild("p").addChild("i");
			NodeL10n.getBase().addL10nSubstitution(inner, "SecurityLevels.physicalThreatLevel.desc."+level, new String[] { "bold" },
					new HTMLNode[] { HTMLNode.STRONG });
			if(level == PHYSICAL_THREAT_LEVEL.MAXIMUM && node.hasDatabase()) {
				inner.addChild("b", " "+l10nSec("warningMaximumWillDeleteQueue"));
			}
			if(level == PHYSICAL_THREAT_LEVEL.HIGH) {
				if(physicalLevel == level) {
					addPasswordChangeForm(inner);
				} else {
					p = inner.addChild("p", l10nSec("setPassword"));
					generatePasswordConfirmationForm(inner);
				}
			}
		}

		// FIXME implement the rest, it should be very similar to the above.

		formNode.addChild("input", new String[] { "type", "name", "value" }, new String[] { "hidden", "seclevels", "on" });
		formNode.addChild("input", new String[] { "type", "value" }, new String[] { "submit", l10n("apply")});
		formNode.addChild("input", new String[] { "type", "value" }, new String[] { "reset",  l10n("undo")});
	}

	private void addPasswordChangeForm(HTMLNode inner) {
		HTMLNode table = inner.addChild("table", "border", "0");
		HTMLNode row = table.addChild("tr");
		HTMLNode cell = row.addChild("td");
		cell.addChild("label", "for", "oldPasswordBox", l10nSec("oldPasswordLabel"));
		cell = row.addChild("td");
		cell.addChild("input", new String[] { "id", "type", "name", "size" }, new String[] { "oldPasswordBox", "password", "oldPassword", "100" });
		row = table.addChild("tr");
		row = table.addChild("tr");
		cell = row.addChild("td");
		cell.addChild("label", "for", "newPasswordBox", l10nSec("newPasswordLabel"));
		cell = row.addChild("td");
		cell.addChild("input", new String[] { "id", "type", "name", "size" }, new String[] { "newPasswordBox", "password", "masterPassword", "100" });
		row = table.addChild("tr");
		cell = row.addChild("td");
		cell.addChild("label", "for", "confirmPasswordBox", l10nSec("confirmNewPasswordLabel"));
		cell = row.addChild("td");
		cell.addChild("input", new String[] { "id", "type", "name", "size" }, new String[] { "confirmPasswordBox", "password", "confirmMasterPassword", "100" });
		HTMLNode p = inner.addChild("p");
		p.addChild("input", new String[] { "type", "name", "value" }, new String[] { "submit", "changePassword", l10nSec("changePasswordButton") });
	}

	static final String PATH = "/seclevels/";

	@Override
	public String path() {
		return PATH;
	}

	private static String l10n(String string) {
		return NodeL10n.getBase().getString("ConfigToadlet." + string);
	}

	private static String l10nSec(String key) {
		return NodeL10n.getBase().getString("SecurityLevels."+key);
	}

	private static String l10nSec(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("SecurityLevels."+key, pattern, value);
	}

	void sendPasswordFileCorruptedPage(ToadletContext ctx) throws ToadletContextClosedException, IOException {
		HTMLNode page = sendPasswordFileCorruptedPageInner(ctx, node.getMasterPasswordFile().getPath());
		writeHTMLReply(ctx, 500, "Internal Server Error", page.generate());
	}

	public static void sendPasswordFileCorruptedPageInner(PageHelper helper, String masterPasswordFile) {
		HTMLNode contentNode = helper.getPageContent(l10nSec("passwordFileCorruptedTitle"));
		HTMLNode infoBox = helper.getInfobox("infobox-error",
		        l10nSec("passwordFileCorruptedTitle"), contentNode, "password-error", false).
		        addChild("div", "class", "infobox-content");
		sendPasswordFileCorruptedPageInner(infoBox, masterPasswordFile);
	}

	public static HTMLNode sendPasswordFileCorruptedPageInner(ToadletContext ctx, String masterPasswordFile) {
		PageNode page = ctx.getPageMaker().getPageNode(l10nSec("passwordFileCorruptedTitle"), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;
		HTMLNode infoBox = ctx.getPageMaker().getInfobox("infobox-error",
		        l10nSec("passwordFileCorruptedTitle"), contentNode, "password-error", false).
		        addChild("div", "class", "infobox-content");
		sendPasswordFileCorruptedPageInner(infoBox, masterPasswordFile);
		return pageNode;
	}

	/** Send a page asking what to do when the master password file has been corrupted.
	 * @param infoBox containing more information. Will be added to.
	 * @param masterPasswordFile path to master password file */
	private static void sendPasswordFileCorruptedPageInner(HTMLNode infoBox, String masterPasswordFile) {
		infoBox.addChild("p", l10nSec("passwordFileCorrupted", "file", masterPasswordFile));

		addHomepageLink(infoBox);

		addBackToSeclevelsLink(infoBox);
	}

	/** Send a page asking for the master password.
	 * @param wasWrong If true, we want the master password because the user entered the wrong
	 * password.
	 * @param ctx
	 * @throws IOException
	 * @throws ToadletContextClosedException
	 */
	private void sendPasswordFormPage(boolean wasWrong, ToadletContext ctx) throws ToadletContextClosedException, IOException {
		PageNode page = ctx.getPageMaker().getPageNode(l10nSec("passwordPageTitle"), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;

		HTMLNode content = ctx.getPageMaker().getInfobox("infobox-error",
				wasWrong ? l10nSec("passwordWrongTitle") : l10nSec("enterPasswordTitle"), contentNode, "password-error", false).
				addChild("div", "class", "infobox-content");

		generatePasswordFormPage(wasWrong, ctx.getContainer(), content, false, false, false, null, null);

		addHomepageLink(content);

		writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	}

	/** Send a page asking for the master password.
	* @param ctx
	* @throws IOException
	* @throws ToadletContextClosedException
	*/
	private void sendPasswordPageMismatch(ToadletContext ctx, String threatLevel) throws ToadletContextClosedException, IOException {
		PageNode page = ctx.getPageMaker().getPageNode(l10nSec("passwordPageTitle"), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;
		HTMLNode content = ctx.getPageMaker().getInfobox("infobox-error",
				l10nSec("setPasswordTitle"), contentNode, "password-error", false).addChild("div", "class", "infobox-content");
		content.addChild("p", l10nSec("passwordsDoNotMatch"));
		generatePasswordFormPage(false, ctx.getContainer(), content, false, false, true, threatLevel, null);
		addBackToSeclevelsLink(content);
		writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	}

	/**
	 * @param forFirstTimeWizard used to determine form target: wizard if in the wizard, this toadlet if not.
	 */
	public static void generatePasswordFormPage(boolean wasWrong, ToadletContainer ctx, HTMLNode content, boolean forFirstTimeWizard, boolean forDowngrade, boolean forUpgrade, String physicalSecurityLevel, String redirect) {

		String postTo = forFirstTimeWizard ? FirstTimeWizardToadlet.TOADLET_URL : SecurityLevelsToadlet.PATH;
		HTMLNode form = ctx.addFormChild(content, postTo, "masterPasswordForm");
		generatePasswordFormPage(wasWrong, form, content, forDowngrade, forUpgrade, physicalSecurityLevel, redirect);
	}

	private static void generatePasswordConfirmationForm(HTMLNode formNode) {
		HTMLNode table = formNode.addChild("table", "border", "0");
		HTMLNode row = table.addChild("tr");
		HTMLNode cell = row.addChild("td");
		cell.addChild("label", "for", "passwordBox", l10nSec("passwordLabel"));
		cell = row.addChild("td");
		cell.addChild("input",
				new String[] { "id", "type", "name", "size" },
				new String[] { "passwordBox", "password", "masterPassword", "100" });
		row = table.addChild("tr");
		row = table.addChild("tr");
		cell = row.addChild("td");
		cell.addChild("label", "for", "confirmPasswordBox", l10nSec("confirmPasswordLabel"));
		cell = row.addChild("td");
		cell.addChild("input",
				new String[] { "id", "type", "name", "size" },
				new String[] { "confirmPasswordBox", "password", "confirmMasterPassword", "100"});
	}

	public static void generatePasswordFormPage(boolean wasWrong, HTMLNode formNode, HTMLNode content, boolean forDowngrade, boolean forUpgrade, String physicalSecurityLevel, String redirect) {
		if (forDowngrade && !wasWrong) {
			content.addChild("#", l10nSec("passwordForDecrypt"));
		} else if (wasWrong) {
			content.addChild("#", l10nSec("passwordWrong"));
		} else if (forUpgrade) {
			content.addChild("#", l10nSec("setPassword"));
		} else {
			content.addChild("#", l10nSec("enterPassword"));
		}

		//Creates a table for password prompt and the confirmation box.
		if (forUpgrade) {
			generatePasswordConfirmationForm(formNode);
		} else {
			formNode.addChild("label", "for", "passwordBox", l10nSec("passwordLabel"));
			formNode.addChild("input",
					new String[] { "id", "type", "name", "size" },
					new String[] { "passwordBox", "password", "masterPassword", "100" });
		}

		if(physicalSecurityLevel != null) {
			formNode.addChild("input",
			        new String[] { "type", "name", "value" },
			        new String[] { "hidden", "security-levels.physicalThreatLevel", physicalSecurityLevel });
			formNode.addChild("input",
			        new String[] { "type", "name", "value" },
			        new String[] { "hidden", "seclevels", "true" });
		}
		if(redirect != null) {
			formNode.addChild("input",
			        new String[] { "type", "name", "value" },
			        new String[] { "hidden", "redirect", redirect });
		}
		formNode.addChild("input",
		        new String[] { "type", "value" },
		        new String[] { "submit", l10nSec("passwordSubmit") });
	}
}
