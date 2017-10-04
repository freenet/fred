package freenet.clients.http.wizardsteps;

import java.io.IOException;

import freenet.clients.http.ExternalLinkToadlet;
import freenet.clients.http.FirstTimeWizardToadlet;
import freenet.clients.http.SecurityLevelsToadlet;
import freenet.l10n.NodeL10n;
import freenet.node.MasterKeysFileSizeException;
import freenet.node.MasterKeysWrongPasswordException;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.SecurityLevels;
import freenet.support.HTMLNode;
import freenet.support.Logger;
import freenet.support.api.HTTPRequest;
import freenet.support.io.FileUtil;
import freenet.support.io.FileUtil.OperatingSystem;

/**
 * Allows the user to set the physical security level.
 */
public class SECURITY_PHYSICAL implements Step {

	private final NodeClientCore core;

	private enum PASSWORD_PROMPT {
		SET_BLANK, //Requested new password was blank
		DECRYPT_WRONG, //Decryption password was wrong
		DECRYPT_BLANK,  //Decryption password was blank
		SET_NO_MATCH //The new password pair that was requested does not match.
	}

	/**
	 * Constructs a new SECURITY_PHYSICAL GET handler.
	 * @param core used to check or set the current security level and password.
	 */
	public SECURITY_PHYSICAL(NodeClientCore core) {
		this.core = core;
	}

	@Override
	public void getStep(HTTPRequest request, PageHelper helper) {

		if (request.isParameterSet("error")) {
			if (errorHandler(request, helper)) {
				//Error page generated successfully.
				return;
			}
			//Problem generating error page; generate default.
		}

		HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("physicalSecurityPageTitle"));
		HTMLNode infoboxContent = helper.getInfobox("infobox-normal",
		        WizardL10n.l10nSec("physicalThreatLevelShort"), contentNode, null, false);
		infoboxContent.addChild("p", WizardL10n.l10nSec("physicalThreatLevel"));

		HTMLNode form = helper.addFormChild(infoboxContent, ".", "physicalSecurityForm");
		HTMLNode div = form.addChild("div", "class", "opennetDiv");
		String controlName = "security-levels.physicalThreatLevel";
		HTMLNode swapWarning = div.addChild("p").addChild("i");
		NodeL10n.getBase().addL10nSubstitution(swapWarning, "SecurityLevels.physicalThreatLevelTruecrypt",
		        new String[]{"bold", "truecrypt"},
		        new HTMLNode[]{HTMLNode.STRONG,
		                HTMLNode.linkInNewWindow(ExternalLinkToadlet.escape("http://www.truecrypt.org/"))});
		OperatingSystem os = FileUtil.detectedOS;
		div.addChild("p", NodeL10n.getBase().getString("SecurityLevels.physicalThreatLevelSwapfile",
		        "operatingSystem",
		        NodeL10n.getBase().getString("OperatingSystemName."+os.name())));
		if(os == FileUtil.OperatingSystem.Windows) {
			swapWarning.addChild("#", " " + WizardL10n.l10nSec("physicalThreatLevelSwapfileWindows"));
		}
		for(SecurityLevels.PHYSICAL_THREAT_LEVEL level : SecurityLevels.PHYSICAL_THREAT_LEVEL.values()) {
			HTMLNode input;
			input = div.addChild("p").addChild("input",
			        new String[] { "type", "name", "value" },
			        new String[] { "radio", controlName, level.name() });
			input.addChild("b", WizardL10n.l10nSec("physicalThreatLevel.name." + level));
			input.addChild("#", ": ");
			NodeL10n.getBase().addL10nSubstitution(input, "SecurityLevels.physicalThreatLevel.choice."+level, new String[] { "bold" }, new HTMLNode[] { HTMLNode.STRONG });
			if(level == SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH &&
			        core.node.securityLevels.getPhysicalThreatLevel() != level) {
				// Add password form on high security if not already at high security.
				HTMLNode p = div.addChild("p");
				p.addChild("label", "for", "passwordBox", WizardL10n.l10nSec("setPasswordLabel")+":");
				p.addChild("input", new String[] { "id", "type", "name" }, new String[] { "passwordBox", "password", "masterPassword" });
				// Confirm password box
				p.addChild("label", "for", "confirmPasswordBox", WizardL10n.l10nSec("confirmPasswordLabel")+":");
				p.addChild("input", new String[] { "id", "type", "name" }, new String[] { "confirmPasswordBox", "password", "confirmMasterPassword" });
			}
		}
		div.addChild("#", WizardL10n.l10nSec("physicalThreatLevelEnd"));
		form.addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "submit", "back", NodeL10n.getBase().getString("Toadlet.back")});
		form.addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "submit", "next", NodeL10n.getBase().getString("Toadlet.next")});
	}

	/**
	 * Internal error handler wrapper with the hope of making the code more readable.
	 * @param request defines which error and information about it
	 * @param helper creates page, infoboxes, forms.
	 * @return whether an error page was successfully generated.
	 */
	private boolean errorHandler(HTTPRequest request, PageHelper helper) {
		String physicalThreatLevel = request.getParam("newThreatLevel");
		SecurityLevels.PHYSICAL_THREAT_LEVEL newThreatLevel = SecurityLevels.parsePhysicalThreatLevel(physicalThreatLevel);
		String error = request.getParam("error");

		if (error.equals("pass")) {
			//Password prompt requested
			PASSWORD_PROMPT type;
			try {
				type = PASSWORD_PROMPT.valueOf(request.getParam("type"));
			}  catch (IllegalArgumentException e) {
				//Render the default page if unable to parse password prompt type.
				return false;
			}

			final String pageTitleKey;
			final String infoboxTitleKey;
			final boolean forDowngrade;
			final boolean forUpgrade;
			final boolean wasWrong = type == PASSWORD_PROMPT.DECRYPT_WRONG;

			switch (type) {
				case SET_BLANK:
					pageTitleKey = "passwordPageTitle";
					infoboxTitleKey = "enterPasswordTitle";
					forDowngrade = false;
					forUpgrade = true;
					break;
				case DECRYPT_WRONG:
					pageTitleKey ="passwordForDecryptTitle";
					infoboxTitleKey = "passwordWrongTitle";
					forDowngrade = false;
					forUpgrade = false;
					break;
				case DECRYPT_BLANK:
					pageTitleKey = "passwordForDecryptTitle";
					infoboxTitleKey = "passwordForDecryptTitle";
					forDowngrade = true;
					forUpgrade = false;
					break;
				case SET_NO_MATCH:
					pageTitleKey = "passwordPageTitle";
					infoboxTitleKey = "enterPasswordTitle";
					forDowngrade = false;
					forUpgrade = true;
					break;
				default:
					//Unanticipated value for type!
					return false;
			}

			HTMLNode contentNode = helper.getPageContent(WizardL10n.l10nSec(pageTitleKey));

			HTMLNode content = helper.getInfobox("infobox-error", WizardL10n.l10nSec(infoboxTitleKey),
			        contentNode, null, true);

			if (type == PASSWORD_PROMPT.SET_BLANK || type == PASSWORD_PROMPT.DECRYPT_BLANK) {
				content.addChild("p", WizardL10n.l10nSec("passwordNotZeroLength"));
			} else if (type == PASSWORD_PROMPT.SET_NO_MATCH) {
				content.addChild("p", WizardL10n.l10nSec("passwordsDoNotMatch"));
			}

			HTMLNode form = helper.addFormChild(content, ".", "masterPasswordForm");

			SecurityLevelsToadlet.generatePasswordFormPage(wasWrong, form, content, forDowngrade, forUpgrade,
			        newThreatLevel.name(), null);

			addBackToPhysicalSeclevelsButton(form);
			return true;
		} else if (error.equals("corrupt")) {
			//Password file corrupt
			SecurityLevelsToadlet.sendPasswordFileCorruptedPageInner(helper, core.node.getMasterPasswordFile().getPath());
			return true;
		} else if (error.equals("delete")) {
			SecurityLevelsToadlet.sendCantDeleteMasterKeysFileInner(helper, core.node.getMasterPasswordFile().getPath(), newThreatLevel.name());
			return true;
		}

		//Error type was not recognized.
		return false;
	}

	public SecurityLevels.PHYSICAL_THREAT_LEVEL getCurrentLevel() {
		return core.node.securityLevels.getPhysicalThreatLevel();
	}

	@Override
	public String postStep(HTTPRequest request) throws IOException {
		final String errorCorrupt = FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL+"&error=corrupt";
		String pass = request.getPartAsStringFailsafe("masterPassword", SecurityLevelsToadlet.MAX_PASSWORD_LENGTH);
		String confirmPass = request.getPartAsStringFailsafe("confirmMasterPassword", SecurityLevelsToadlet.MAX_PASSWORD_LENGTH);
		final boolean passwordIsBlank = pass.isEmpty() && confirmPass.isEmpty();
		final boolean passwordsDoNotMatch = !pass.equals(confirmPass);

		String physicalThreatLevel = request.getPartAsStringFailsafe("security-levels.physicalThreatLevel", 128);
		SecurityLevels.PHYSICAL_THREAT_LEVEL oldThreatLevel = core.node.securityLevels.getPhysicalThreatLevel();
		SecurityLevels.PHYSICAL_THREAT_LEVEL newThreatLevel = SecurityLevels.parsePhysicalThreatLevel(physicalThreatLevel);
		if (FirstTimeWizardToadlet.shouldLogMinor()) {
			Logger.minor(this, "Old threat level: " + oldThreatLevel + " new threat level: " + newThreatLevel);
		}

		/*If the user didn't select a network security level before clicking continue, the selected
		* security level could not be determined, clicked back from a password error page, redirect to the main page.*/
		if (newThreatLevel == null || !request.isPartSet("security-levels.physicalThreatLevel") ||
		        request.isPartSet("backToMain")) {
			return FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL.name();
		}
		//Changing to high physical threat level: set password.
		if (newThreatLevel == SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH && oldThreatLevel != newThreatLevel) {
			if (passwordIsBlank) {
				// Must set the password to something non-blank.
				return promptPassword(newThreatLevel, PASSWORD_PROMPT.SET_BLANK);
			} else if (passwordsDoNotMatch) {
				//Must Confirm the password before setting it
				return promptPassword(newThreatLevel, PASSWORD_PROMPT.SET_NO_MATCH);
			} else {
				try {
					if(oldThreatLevel == SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL ||
					        oldThreatLevel == SecurityLevels.PHYSICAL_THREAT_LEVEL.LOW) {
						core.node.changeMasterPassword(pass);
					} else {
						core.node.setMasterPassword(pass);
					}
				} catch (Node.AlreadySetPasswordException e) {
					// Do nothing, already set a password.
				} catch (MasterKeysWrongPasswordException e) {
					throw new IOException("Incorrect password when changing from another level to high", e);
				} catch (MasterKeysFileSizeException e) {
					return errorCorrupt;
				}
			}
		}
		//Decreasing to low or normal from high: remove password.
		if ((newThreatLevel == SecurityLevels.PHYSICAL_THREAT_LEVEL.LOW || newThreatLevel == SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL) &&
			        oldThreatLevel == SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH) {
			if (passwordIsBlank) {
				//Prompt for the old password, which is needed to decrypt
				return promptPassword(newThreatLevel, PASSWORD_PROMPT.DECRYPT_BLANK);
			} else if (core.node.getMasterPasswordFile().exists()) {
				//Old password for decryption specified.
				try {
					core.node.changeMasterPassword("");
				} catch (IOException e) {
					if(!core.node.getMasterPasswordFile().exists()) {
						// Ok.
						System.out.println("Master password file no longer exists, assuming this is deliberate");
					} else {
						System.err.println("Cannot change password as cannot write new passwords file: "+e);
						e.printStackTrace();
						throw new IOException("cantWriteNewMasterKeysFile", e);
					}
				} catch (MasterKeysWrongPasswordException e) {
					return promptPassword(newThreatLevel, PASSWORD_PROMPT.DECRYPT_WRONG);
				} catch (MasterKeysFileSizeException e) {
					return errorCorrupt;
				} catch (Node.AlreadySetPasswordException e) {
					System.err.println("Already set a password when changing it - maybe master.keys copied in at the wrong moment???");
				}
			}

		}
		//Maximum threat level: remove master keys file.
		if (newThreatLevel == SecurityLevels.PHYSICAL_THREAT_LEVEL.MAXIMUM) {
			try {
				core.node.killMasterKeysFile();
			} catch (IOException e) {
				return FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL+
				        "&error=delete&newThreatLevel="+newThreatLevel.name();
			}
		}
		setThreatLevel(newThreatLevel, oldThreatLevel);
		return FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name();
	}

	/**
	 * Internal utility function for displaying a password prompt.
	 * @param newThreatLevel the user-selected threat level, to be used in creating the form.
	 * @param type what type of prompt needed
	 * @return URL to display the requested page
	 */
	private String promptPassword(SecurityLevels.PHYSICAL_THREAT_LEVEL newThreatLevel, PASSWORD_PROMPT type) {
		if (type == PASSWORD_PROMPT.DECRYPT_WRONG) {
			System.err.println("Wrong password!");
		}
		StringBuilder destination = new StringBuilder(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL+
		        "&error=pass&newThreatLevel=").append(newThreatLevel.name()).append("&type=").append(type.name());
		return destination.toString();
	}

	public void setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL newThreatLevel, SecurityLevels.PHYSICAL_THREAT_LEVEL oldThreatLevel) throws IOException {
		core.node.securityLevels.setThreatLevel(newThreatLevel);
		core.storeConfig();
		try {
			core.node.lateSetupDatabase(null);
		} catch (MasterKeysWrongPasswordException e) {
			// Ignore, impossible???
			System.err.println("Failed starting up database while switching physical security level to "+newThreatLevel+" from "+oldThreatLevel+" : wrong password - this is impossible, it should have been handled by the other cases, suggest you remove master.keys");
		} catch (MasterKeysFileSizeException e) {
			System.err.println("Failed starting up database while switching physical security level to "+newThreatLevel+" from "+oldThreatLevel+" : "+core.node.getMasterPasswordFile()+" is too " + e.sizeToString());
		}
	}

	private void addBackToPhysicalSeclevelsButton(HTMLNode form) {
		form.addChild("p").addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "submit", "backToMain", WizardL10n.l10n("backToSecurityLevels")});
	}
}
