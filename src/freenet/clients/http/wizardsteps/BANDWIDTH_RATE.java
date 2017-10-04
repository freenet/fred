package freenet.clients.http.wizardsteps;

import java.text.DecimalFormat;

import freenet.clients.http.FirstTimeWizardToadlet;
import freenet.config.Config;
import freenet.config.InvalidConfigValueException;
import freenet.l10n.NodeL10n;
import freenet.node.NodeClientCore;
import freenet.support.HTMLNode;
import freenet.support.Logger;
import freenet.support.SizeUtil;
import freenet.support.URLEncoder;
import freenet.support.api.HTTPRequest;

/**
 * Allows the user to set bandwidth limits with an emphasis on limiting to certain download and upload rates.
 */
public class BANDWIDTH_RATE extends BandwidthManipulator implements Step {

	private final BandwidthLimit[] limits;

	public BANDWIDTH_RATE(NodeClientCore core, Config config) {
		super(core, config);
		final int KiB = 1024;
		limits = new BandwidthLimit[] {
				// FIXME feedback on typical real world ratios on slow connections would be helpful.
				
//				// Dial-up
//				// 57.6/33.6; call it 4KB/sec each way
//				new BandwidthLimit(4*KiB, 4*KiB, "bandwidthConnectionDialUp"),
//				// 128kbps symmetrical = 16KB/sec each way, take half so 8KB/sec each way
//				new BandwidthLimit(8*KiB, 8*KiB, "bandwidthConnectionISDN"),
//				// 256kbps/64kbps developing world broadband
//				new BandwidthLimit(16*KiB, 4*KiB, "bandwidthConnectionSlow256"),
//				// 512kbps/128kbps very slow broadband
//				new BandwidthLimit(32*KiB, 8*KiB, "bandwidthConnectionSlow512"),
//				// 1Mbps/128kbps
//				new BandwidthLimit(64*KiB, 8*KiB, "bandwidthConnection1M"),
//				// 2Mbps/128kbps (slow often => poor ratios)
//				new BandwidthLimit(128*KiB, 8*KiB, "bandwidthConnection2M"),
				// 4Mbps/256kbps
				new BandwidthLimit(256*KiB, 16*KiB, "bandwidthConnection4M", false),
				// 6Mbps/256kbps - 6Mbps is common in parts of china, as well as being the real value in lots of DSL areas
				new BandwidthLimit(384*KiB, 16*KiB, "bandwidthConnection6M", true),
				// 8Mbps/512kbps - UK DSL1 is either 448k up or 832k up
				new BandwidthLimit(512*KiB, 32*KiB, "bandwidthConnection8M", false),
				// 12Mbps/1Mbps - typical DSL2
				new BandwidthLimit(768*KiB, 64*KiB, "bandwidthConnection12M", false),
				// 20Mbps/1Mbps - fast DSL2
				new BandwidthLimit(1280*KiB, 64*KiB, "bandwidthConnection20M", false),
				// 20Mbps/5Mbps - Slow end of VDSL
				new BandwidthLimit(1280*KiB, 320*KiB, "bandwidthConnectionVDSL", false),
				// 100Mbps fibre etc
				new BandwidthLimit(2048*KiB, 2048*KiB, "bandwidthConnection100M", false)
		};
	}

	@Override
	public void getStep(HTTPRequest request, PageHelper helper) {
		HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("bandwidthLimit"));
		
		HTMLNode formNode = helper.addFormChild(contentNode, ".", "limit");

		if (request.isParameterSet("parseError")) {
			parseErrorBox(contentNode, helper, request.getParam("parseTarget"));
		}

		HTMLNode infoBox = helper.getInfobox("infobox-normal", WizardL10n.l10n("bandwidthLimitRateTitle"),
		        formNode, null, false);
		NodeL10n.getBase().addL10nSubstitution(infoBox, "FirstTimeWizardToadlet.bandwidthLimitRate",
		        new String[] { "bold", "coreSettings" }, new HTMLNode[] { HTMLNode.STRONG, 
		                new HTMLNode("#", NodeL10n.getBase().getString("ConfigToadlet.node"))});

		//Table header
		HTMLNode table = infoBox.addChild("table");
		HTMLNode headerRow = table.addChild("tr");
		headerRow.addChild("th", WizardL10n.l10n("bandwidthConnectionHeader"));
		headerRow.addChild("th", WizardL10n.l10n("bandwidthDownloadHeader"));
		headerRow.addChild("th", WizardL10n.l10n("bandwidthUploadHeader"));
		headerRow.addChild("th", WizardL10n.l10n("bandwidthSelect"));

		boolean addedDefault = false;
		
		BandwidthLimit detected = detectBandwidthLimits();
		if (detected.downBytes > 0 && detected.upBytes > 0) {
			//Detected limits reasonable; add half of both as recommended option.
			BandwidthLimit usable = new BandwidthLimit(detected.downBytes/2, detected.upBytes/2, "bandwidthDetected", true);
			addLimitRow(table, usable, true, true);
			addedDefault = true;
		}

		BandwidthLimit current = getCurrentBandwidthLimitsOrNull();
		if(current != null) {
			addLimitRow(table, current, false, !addedDefault);
			addedDefault = true;
		}
		
		for (BandwidthLimit limit : limits) {
			addLimitRow(table, limit, false, !addedDefault);
		}

		//Add custom option.
		HTMLNode customForm = table.addChild("tr");
		customForm.addChild("td", WizardL10n.l10n("bandwidthCustom"));
		customForm.addChild("td").addChild("input",
		        new String[] { "type", "name" },
		        new String[] { "text", "customDown" });
		customForm.addChild("td").addChild("input",
		        new String[] { "type", "name" },
		        new String[] { "text", "customUp" });
		// This is valid if it's filled in. So don't show the selector.
		// FIXME javascript to auto-select it?
//		customForm.addChild("td").addChild("input",
//				new String[] { "type", "name", "value" },
//				new String[] { "radio", "bandwidth", "custom" });

		infoBox.addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "submit", "back", NodeL10n.getBase().getString("Toadlet.back")});
		infoBox.addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "submit", "next", NodeL10n.getBase().getString("Toadlet.next")});
	}

	@Override
	public String postStep(HTTPRequest request)  {

		String limitSelected = request.getPartAsStringFailsafe("bandwidth", 100);

		String down = request.getPartAsStringFailsafe("customDown", 20);
		String up = request.getPartAsStringFailsafe("customUp", 20);

		// Try to parse custom limit first.
		if(!down.equals("") && !up.equals("")) {
			String failedLimits = attemptSet(up, down);

			if (!failedLimits.isEmpty()) {
				//Some at least one limit failed to parse.
				return "BANDWIDTH_RATE&parseError=true&parseTarget="+
				        URLEncoder.encode(failedLimits, true);
			}

			//Success
			setWizardComplete();
			return FirstTimeWizardToadlet.WIZARD_STEP.COMPLETE.name();
		}

		if(!limitSelected.isEmpty()) {
			int x = limitSelected.indexOf('/');
			if(x != -1) {
				String downString = limitSelected.substring(0, x);
				String upString = limitSelected.substring(x+1);
				//Pre-defined limit selected.
				String preset = attemptSet(upString, downString);
				if(!preset.isEmpty()) {
					//Error parsing predefined limit.
					//This should not happen, as there are no units to confound the parser.
					Logger.error(this, "Failed to parse pre-defined limit! Please report.");
					return FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH_RATE+"&parseError=true&parseTarget="+
							URLEncoder.encode(preset, true);
				}
			}
		} else {
			Logger.error(this, "No bandwidth limit set!");
			return FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH_RATE.name();
		}
		
		setWizardComplete();
		return FirstTimeWizardToadlet.WIZARD_STEP.COMPLETE.name();
	}

	/**
	 * Attempts to set bandwidth limits.
	 * @param up output limit
	 * @param down input limit
	 * @return a space-separated string of the messages from any exceptions thrown when setting limits. If both are successful, an empty string.
	 */
	private String attemptSet(String up, String down) {
		String failedLimits = "";
		try {
			setBandwidthLimit(down, false);
		} catch (InvalidConfigValueException e) {
			failedLimits = e.getMessage();
		}
		try {
			setBandwidthLimit(up, true);
		} catch (InvalidConfigValueException e) {
			if (!failedLimits.isEmpty()) failedLimits += ' ';
			failedLimits += e.getMessage();
		}
		return failedLimits;
	}

	/**
	 * Adds a row to the table for the given limit. Adds download limit, upload limit, and selection button.
	 * @param table Table to add a row to.
	 * @param limit Limit to display.
	 * @param recommended Whether to mark the limit with (Recommended) next to the select button.
	 */
	private void addLimitRow(HTMLNode table, BandwidthLimit limit, boolean recommended, boolean useMaybeDefault) {
		HTMLNode row = table.addChild("tr");
		row.addChild("td", WizardL10n.l10n(limit.descriptionKey));
		String downColumn = SizeUtil.formatSize(limit.downBytes)+WizardL10n.l10n("bandwidthPerSecond");
		if(limit.downBytes >= 32*1024) {
			downColumn += " (= ";
			if(limit.downBytes < 256*1024)
				downColumn += new DecimalFormat("0.0").format(((double)((limit.downBytes*8)))/(1024*1024));
			else
				downColumn += ((limit.downBytes*8)/(1024*1024));
			downColumn+="Mbps)";
		}
		row.addChild("td", downColumn);
		row.addChild("td", SizeUtil.formatSize(limit.upBytes)+WizardL10n.l10n("bandwidthPerSecond"));

		HTMLNode buttonCell = row.addChild("td");
		
		HTMLNode radio = 
			buttonCell.addChild("input",
					new String[] { "type", "name", "value" },
					new String[] { "radio", "bandwidth", limit.downBytes+"/"+limit.upBytes });
		if(recommended || (useMaybeDefault && limit.maybeDefault))
			radio.addAttribute("checked", "checked");
		if (recommended) {
			buttonCell.addChild("#", WizardL10n.l10n("autodetectedSuggestedLimit"));
		}
	}
}
