/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.http;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.EnumMap;

import freenet.client.HighLevelSimpleClient;
import freenet.clients.http.wizardsteps.BANDWIDTH;
import freenet.clients.http.wizardsteps.BANDWIDTH_MONTHLY;
import freenet.clients.http.wizardsteps.BANDWIDTH_RATE;
import freenet.clients.http.wizardsteps.BROWSER_WARNING;
import freenet.clients.http.wizardsteps.DATASTORE_SIZE;
import freenet.clients.http.wizardsteps.MISC;
import freenet.clients.http.wizardsteps.NAME_SELECTION;
import freenet.clients.http.wizardsteps.OPENNET;
import freenet.clients.http.wizardsteps.PageHelper;
import freenet.clients.http.wizardsteps.PersistFields;
import freenet.clients.http.wizardsteps.SECURITY_NETWORK;
import freenet.clients.http.wizardsteps.SECURITY_PHYSICAL;
import freenet.clients.http.wizardsteps.Step;
import freenet.clients.http.wizardsteps.WELCOME;
import freenet.config.Config;
import freenet.config.SubConfig;
import freenet.l10n.NodeL10n;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.SecurityLevels;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.BooleanCallback;
import freenet.support.api.HTTPRequest;

/**
 * A first time wizard aimed to ease the configuration of the node.
 */
public class FirstTimeWizardToadlet extends Toadlet {
	private final NodeClientCore core;
	private final EnumMap<WIZARD_STEP, Step> steps;
	private final MISC stepMISC;
	private final SECURITY_NETWORK stepSECURITY_NETWORK;
	private final SECURITY_PHYSICAL stepSECURITY_PHYSICAL;

        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	public enum WIZARD_STEP {
		WELCOME,
		BROWSER_WARNING,
		MISC,
		OPENNET,
		SECURITY_NETWORK,
		SECURITY_PHYSICAL,
		NAME_SELECTION,
		DATASTORE_SIZE,
		BANDWIDTH,
		BANDWIDTH_MONTHLY,
		BANDWIDTH_RATE,
		COMPLETE //Redirects to front page
	}

	public enum WIZARD_PRESET {
		LOW,
		HIGH
	}

	FirstTimeWizardToadlet(HighLevelSimpleClient client, Node node, NodeClientCore core) {
		//Generic Toadlet-related initialization.
		super(client);
		this.core = core;
		Config config = node.config;

		addWizardConfiguration(config);

		//Add step handlers that aren't set by presets
		steps = new EnumMap<WIZARD_STEP, Step>(WIZARD_STEP.class);
		steps.put(WIZARD_STEP.WELCOME, new WELCOME(config));
		steps.put(WIZARD_STEP.BROWSER_WARNING, new BROWSER_WARNING());
		steps.put(WIZARD_STEP.NAME_SELECTION, new NAME_SELECTION(config));
		steps.put(WIZARD_STEP.DATASTORE_SIZE, new DATASTORE_SIZE(core, config));
		steps.put(WIZARD_STEP.OPENNET, new OPENNET());
		steps.put(WIZARD_STEP.BANDWIDTH, new BANDWIDTH());
		steps.put(WIZARD_STEP.BANDWIDTH_MONTHLY, new BANDWIDTH_MONTHLY(core, config));
		steps.put(WIZARD_STEP.BANDWIDTH_RATE, new BANDWIDTH_RATE(core, config));

		//Add step handlers that are set by presets
		stepMISC = new MISC(core, config);
		steps.put(WIZARD_STEP.MISC, stepMISC);

		stepSECURITY_NETWORK = new SECURITY_NETWORK(core);
		steps.put(WIZARD_STEP.SECURITY_NETWORK, stepSECURITY_NETWORK);

		stepSECURITY_PHYSICAL = new SECURITY_PHYSICAL(core);
		steps.put(WIZARD_STEP.SECURITY_PHYSICAL, stepSECURITY_PHYSICAL);
	}

	public static final String TOADLET_URL = "/wizard/";

	private void addWizardConfiguration(Config configuration) {
		SubConfig wizardConfiguration = new SubConfig("firstTimeWizard", configuration);
		wizardConfiguration.register("loadUPnPPlugin", true, 0, true, false, "FirstTimeWizardToadlet.loadUPnPPlugin", "FirstTimeWizardToadlet.loadUPnPPluginLong", createLoadUPnPPluginCallback());
		wizardConfiguration.register("enableAutoUpdater", true, 1, true, false, "FirstTimeWizardToadlet.enableAutoUpdater", "FirstTimeWizardToadlet.enableAutoUpdaterLong", createEnableAutoUpdaterCallback());
		loadUPnPPlugin = wizardConfiguration.getBoolean("loadUPnPPlugin");
		enableAutoUpdater = wizardConfiguration.getBoolean("enableAutoUpdater");
		wizardConfiguration.finishedInitialization();
	}

	private boolean loadUPnPPlugin;

	private BooleanCallback createLoadUPnPPluginCallback() {
		return new BooleanCallback() {
			@Override
			public Boolean get() {
				return loadUPnPPlugin;
			}

			@Override
			public void set(Boolean value) {
				loadUPnPPlugin = value;
			}
		};
	}

	private boolean enableAutoUpdater;

	private BooleanCallback createEnableAutoUpdaterCallback() {
		return new BooleanCallback() {
			@Override
			public Boolean get() {
				return enableAutoUpdater;
			}

			@Override
			public void set(Boolean value) {
				enableAutoUpdater = value;
			}
		};
	}

	public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx) throws ToadletContextClosedException, IOException {
        if(!ctx.checkFullAccess(this))
            return;

		//Read the current step from the URL parameter, defaulting to the welcome page if unset or invalid..
		WIZARD_STEP currentStep;
		try {
			currentStep = WIZARD_STEP.valueOf(request.getParam("step", WIZARD_STEP.WELCOME.toString()));
		} catch (IllegalArgumentException e) {
			currentStep = WIZARD_STEP.WELCOME;
		}

		PersistFields persistFields = new PersistFields(request);

		//Skip the browser warning page if using Chrome in incognito mode
		if (currentStep == WIZARD_STEP.BROWSER_WARNING &&
				request.isChrome() && request.isIncognito()) {
			super.writeTemporaryRedirect(ctx, "Skipping unneeded warning",
			        persistFields.appendTo(TOADLET_URL+"?step=MISC"));
			return;
		} else if (currentStep == WIZARD_STEP.MISC && persistFields.isUsingPreset()) {
			/*If using a preset, skip the miscellaneous page as both high and low security set those settings.
			 * This overrides the persistence fields.*/
			StringBuilder redirectBase = new StringBuilder(TOADLET_URL+"?step=");
			if (persistFields.preset == WIZARD_PRESET.HIGH) {
				redirectBase.append("SECURITY_NETWORK&preset=HIGH&confirm=true&opennet=false&security-levels.networkThreatLevel=HIGH");
			} else /*if (persistFields.preset == WIZARD_PRESET.LOW)*/ {
				redirectBase.append("DATASTORE_SIZE&preset=LOW&opennet=true");
			}
			//addPersistFields() is not used here because the fields are overridden.
			super.writeTemporaryRedirect(ctx, "Skipping to next necessary step", redirectBase.toString());
			return;
		} else if (currentStep == WIZARD_STEP.SECURITY_NETWORK && !request.isParameterSet("opennet")) {
			//If opennet isn't defined when attempting to set network security level, ask again.
			super.writeTemporaryRedirect(ctx, "Need opennet choice",
			        persistFields.appendTo(TOADLET_URL+"?step=OPENNET"));
			return;
		} else if (currentStep == WIZARD_STEP.NAME_SELECTION && core.node.isOpennetEnabled()) {
			//Skip node name selection if not in darknet mode.
			super.writeTemporaryRedirect(ctx, "Skip name selection",
			        persistFields.appendTo(stepURL(WIZARD_STEP.DATASTORE_SIZE.name())));
			return;
		} else if (currentStep == WIZARD_STEP.COMPLETE) {
			super.writeTemporaryRedirect(ctx, "Wizard complete", WelcomeToadlet.PATH);
			return;
		}

		Step getStep = steps.get(currentStep);
		PageHelper helper = new PageHelper(ctx, persistFields, currentStep);
		getStep.getStep(request, helper);
		writeHTMLReply(ctx, 200, "OK", helper.getPageOuter().generate());
	}

	/**
	 * @return whether wizard steps should log minor events.
	 */
	public static boolean shouldLogMinor() {
		return logMINOR;
	}

	@SuppressWarnings("UnusedParameters")
	public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx) throws ToadletContextClosedException, IOException {
        if(!ctx.checkFullAccess(this))
            return;

		WIZARD_STEP currentStep;
		try {
			//Attempt to parse the current step, defaulting to WELCOME if unspecified or invalid.
			String currentValue = request.getPartAsStringFailsafe("step", 20);
			currentStep = currentValue.isEmpty() ? WIZARD_STEP.WELCOME : WIZARD_STEP.valueOf(currentValue);
		} catch (IllegalArgumentException e) {
			//Failed to parse enum value, default to welcome.
			//TODO: Should this be an error page instead?
			currentStep = WIZARD_STEP.WELCOME;
		}

		PersistFields persistFields = new PersistFields(request);
		String redirectTarget;

		if (currentStep.equals(WIZARD_STEP.WELCOME) &&
		        (request.isPartSet("presetLow") || request.isPartSet("presetHigh") || request.isPartSet("presetNone"))) {

			/*Apply presets and UPnP is enabled first to allow it time to load (and thus enable
			  autodetection) before hitting the bandwidth page. This also effectively sets the preset field.*/
			StringBuilder redirectTo = new StringBuilder(TOADLET_URL+"?step=BROWSER_WARNING&incognito=");
			redirectTo.append(request.getPartAsStringFailsafe("incognito", 5));

			//Translate button name to preset value on the query string.
			if (request.isPartSet("presetLow")) {
				//Low security preset
				stepMISC.setUPnP(loadUPnPPlugin);
				stepMISC.setAutoUpdate(enableAutoUpdater);
				redirectTo.append("&preset=LOW&opennet=true");
				stepSECURITY_NETWORK.setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.LOW);
				stepSECURITY_PHYSICAL.setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL,
				        stepSECURITY_PHYSICAL.getCurrentLevel());
			} else if (request.isPartSet("presetHigh")) {
				//High security preset
				stepMISC.setUPnP(loadUPnPPlugin);
				stepMISC.setAutoUpdate(enableAutoUpdater);
				redirectTo.append("&preset=HIGH&opennet=false");
			}

			super.writeTemporaryRedirect(ctx, "Wizard set preset", redirectTo.toString());
			return;
		} else if (request.isPartSet("back")) {
			//User chose back, return to previous page.
			redirectTarget = getPreviousStep(currentStep, persistFields.preset).name();
		} else {
			try {
				redirectTarget = steps.get(currentStep).postStep(request);

				//Opennet step can change the persisted value for opennet.
				if (currentStep == WIZARD_STEP.OPENNET) {
					try {
						HTTPRequest newRequest = new HTTPRequestImpl(new URI(
						        stepURL(redirectTarget)), "GET");
						//Only continue if a value for opennet has been selected.
						if (newRequest.isPartSet("opennet")) {
							redirectTarget = WIZARD_STEP.SECURITY_NETWORK.name();
							persistFields = new PersistFields(persistFields.preset, newRequest);
						}
					} catch (URISyntaxException e) {
						Logger.error(this, "Unexpected invalid query string from OPENNET step! "+e, e);
						redirectTarget = WIZARD_STEP.WELCOME.name();
					}
				}
			} catch (IOException e) {
				String title;
				if (e.getMessage().equals("cantWriteNewMasterKeysFile")) {
					//Recognized as being unable to write to the master keys file.
					title = NodeL10n.getBase().getString("SecurityLevels.cantWriteNewMasterKeysFileTitle");
				} else {
					//Some other error.
					title = NodeL10n.getBase().getString("Toadlet.internalErrorPleaseReport");
				}

				//Very loud error message, with descriptive title and header if possible.
				StringBuilder msg = new StringBuilder("<html><head><title>").append(title).
				        append("</title></head><body><h1>").append(title).append("</h1><pre>");

				//Print stack trace.
				StringWriter sw = new StringWriter();
				PrintWriter pw = new PrintWriter(sw);
				e.printStackTrace(pw);
				pw.flush();
				msg.append(sw.toString()).append("</pre>");

				//Include internal exception if one exists.
				Throwable internal = e.getCause();
				if (internal != null) {
					msg.append("<h1>").
					        append(NodeL10n.getBase().getString("Toadlet.internalErrorPleaseReport")).
					        append("</h1>").append("<pre>");

					sw = new StringWriter();
					pw = new PrintWriter(sw);
					internal.printStackTrace(pw);
					pw.flush();
					msg.append(sw.toString()).append("</pre>");
				}
				msg.append("</body></html>");
				writeHTMLReply(ctx, 500, "Internal Error", msg.toString());
				return;
			}
		}
		super.writeTemporaryRedirect(ctx, "Wizard redirect", stepURL(persistFields.appendTo(redirectTarget)));
	}

	private String stepURL(String step) {
		return TOADLET_URL+"?step="+step;
	}

	//FIXME: There really has to be a better way to find the previous step, but with an enum there's no decrement.
	//FIXME: Would a set work better than an enum?
	public static WIZARD_STEP getPreviousStep(WIZARD_STEP currentStep, WIZARD_PRESET preset) {

		//Might be obvious, but still: No breaks needed in cases because their only contents are returns.

		//First pages for the presets
		if (preset == WIZARD_PRESET.HIGH) {
			switch (currentStep) {
				case SECURITY_NETWORK:
				case SECURITY_PHYSICAL:
					//Go back to the beginning from the warning or the physical security page.
					return WIZARD_STEP.WELCOME;
				default:
					//do nothing
			}
		} else  if (preset == WIZARD_PRESET.LOW) {
			switch (currentStep) {
				case DATASTORE_SIZE:
					//Go back to the beginning from the datastore page.
					return WIZARD_STEP.WELCOME;
				default:
					//do nothing
			}
		}

		//Otherwise normal order.
		switch (currentStep) {
			case MISC:
			case BROWSER_WARNING:
				return WIZARD_STEP.WELCOME;
			case OPENNET:
				return WIZARD_STEP.MISC;
			case SECURITY_NETWORK:
				return WIZARD_STEP.OPENNET;
			case SECURITY_PHYSICAL:
				return WIZARD_STEP.SECURITY_NETWORK;
			case NAME_SELECTION:
				return WIZARD_STEP.SECURITY_PHYSICAL;
			case DATASTORE_SIZE:
				return WIZARD_STEP.NAME_SELECTION;
			case BANDWIDTH:
				return WIZARD_STEP.DATASTORE_SIZE;
			case BANDWIDTH_MONTHLY:
			case BANDWIDTH_RATE:
				return WIZARD_STEP.BANDWIDTH;
			default:
				//do nothing
		}

		//Should be matched by this point, unknown step.
		return WIZARD_STEP.WELCOME;
	}

	@Override
	public String path() {
		return TOADLET_URL;
	}
}
