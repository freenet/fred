package freenet.clients.http;

import freenet.client.HighLevelSimpleClient;
import freenet.clients.http.wizardsteps.BandwidthLimit;
import freenet.clients.http.wizardsteps.BandwidthManipulator;
import freenet.clients.http.wizardsteps.DATASTORE_SIZE;
import freenet.config.Config;
import freenet.config.ConfigException;
import freenet.config.Option;
import freenet.l10n.NodeL10n;
import freenet.node.*;
import freenet.pluginmanager.PluginNotFoundException;
import freenet.support.Fields;
import freenet.support.IllegalValueException;
import freenet.support.Logger;
import freenet.support.api.HTTPRequest;
import freenet.support.io.DatastoreUtil;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static java.util.concurrent.TimeUnit.SECONDS;

public class FirstTimeWizardNewToadlet extends WebTemplateToadlet {

    static final String TOADLET_URL = "/wiz/";

    private final NodeClientCore core;

    private final Config config;

    private static final String l10nPrefix = "FirstTimeWizardToadlet.";

    private boolean isPasswordEmpty;

    private final int KiB = 1024;

    FirstTimeWizardNewToadlet(HighLevelSimpleClient client, NodeClientCore core, Config config) {
        super(client);
        this.core = core;
        this.config = config;
    }

    @Override
    public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
            throws ToadletContextClosedException, IOException {
        if(!ctx.checkFullAccess(this)) {
            return;
        }

        isPasswordEmpty =
                core.node.securityLevels.getPhysicalThreatLevel() != SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH;
        showForm(ctx, new FormModel().toModel());
    }

    public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
            throws ToadletContextClosedException, IOException {
        if(!ctx.checkFullAccess(this)) {
            return;
        }

        FormModel formModel = new FormModel(request);

        if (formModel.isValid()) {
            formModel.save();
            super.writeTemporaryRedirect(ctx, "Wizard complete", WelcomeToadlet.PATH);
        }

        // form model not valid
        showForm(ctx, formModel.toModel());
    }

    private void showForm(ToadletContext ctx, Map<String, Object> model)
            throws IOException, ToadletContextClosedException {
        model.put("formPassword", core.getToadletContainer().getFormPassword());
        PageNode page = ctx.getPageMaker().getPageNode(l10n("homepageTitle"), ctx,
                new PageMaker.RenderParameters().renderNavigationLinks(false).renderStatus(false));
        page.addCustomStyleSheet("/static/first-time-wizard.css");
        addChild(page.content, "first-time-wizard", model, l10nPrefix);
        this.writeHTMLReply(ctx, 200, "OK", page.outer.generate());
    }

    @Override
    public String path() {
        return TOADLET_URL;
    }

    private static String l10n(String key) {
        return NodeL10n.getBase().getString(l10nPrefix + key);
    }

    private static String l10n(String key, String value) {
        return NodeL10n.getBase().getString(l10nPrefix + key, value);
    }

    private class FormModel {

        private String knowSomeone = "";

        private String connectToStrangers = "";

        private String haveMonthlyLimit = "";

        private String downloadLimit = "900";

        private String uploadLimit = "300";

        private String bandwidthMonthlyLimit = "50";

        private String storageLimit;

        private String setPassword = "";

        private String password = "";

        private String downloadLimitDetected;

        private String uploadLimitDetected;

        private Map<String, String> errors = new HashMap<>();

        FormModel() {
            float storage = 1;
            @SuppressWarnings("unchecked")
            Option<Long> sizeOption = (Option<Long>) config.get("node").getOption("storeSize");
            if(!sizeOption.isDefault()) {
                @SuppressWarnings("unchecked")
                Option<Long> clientCacheSizeOption = (Option<Long>) config.get("node").getOption("clientCacheSize");
                @SuppressWarnings("unchecked")
                Option<Long> slashdotCacheSizeOption = (Option<Long>) config.get("node").getOption("slashdotCacheSize");
                long totalSize = sizeOption.getValue() + clientCacheSizeOption.getValue() + slashdotCacheSizeOption.getValue();
                storage = (float) totalSize / DatastoreUtil.oneGiB;
            }
            else {
                long autodetectedDatastoreSize = DatastoreUtil.autodetectDatastoreSize(core, config);
                if (autodetectedDatastoreSize > 0) {
                    storage = (float) autodetectedDatastoreSize / DatastoreUtil.oneGiB;
                }
            }
            storageLimit = String.format("%.2f", storage);

            detectBandwidthLimit();
            if (downloadLimitDetected != null) {
                downloadLimit = downloadLimitDetected;
            }
            if (uploadLimitDetected != null) {
                uploadLimit = uploadLimitDetected;
            }
        }

        FormModel(HTTPRequest request) {
            knowSomeone = request.getPartAsStringFailsafe("knowSomeone", 20);
            connectToStrangers = request.getPartAsStringFailsafe("connectToStrangers", 20);
            haveMonthlyLimit = request.getPartAsStringFailsafe("haveMonthlyLimit", 20);
            downloadLimit = request.getPartAsStringFailsafe("downLimit", 100);
            uploadLimit = request.getPartAsStringFailsafe("upLimit", 100);
            bandwidthMonthlyLimit = request.getPartAsStringFailsafe("monthlyLimit", 100);
            storageLimit = request.getPartAsStringFailsafe("storage", 100);
            setPassword = request.getPartAsStringFailsafe("setPassword", 20);
            password = request.getPartAsStringFailsafe("password", SecurityLevelsToadlet.MAX_PASSWORD_LENGTH + 1);
            String passwordConfirmation = request.getPartAsStringFailsafe("confirmPassword", SecurityLevelsToadlet.MAX_PASSWORD_LENGTH);

            // validate
            if (haveMonthlyLimit.isEmpty()) {
                try {
                    long downloadLimit = this.downloadLimit.isEmpty() ? 0 : Fields.parseInt(this.downloadLimit + "KiB");
                    if (downloadLimit < Node.getMinimumBandwidth()) {
                        errors.put("downloadLimitError",
                                l10n("valid.downloadLimit", Integer.toString(Node.getMinimumBandwidth() / KiB)));
                    }
                } catch (NumberFormatException e) {
                    errors.put("downloadLimitError",
                            l10n("valid.number.prefix.downloadLimit") + " " + e.getMessage());
                }

                try {
                    long uploadLimit = this.uploadLimit.isEmpty() ? 0 : Fields.parseInt(this.uploadLimit + "KiB");
                    if (uploadLimit < Node.getMinimumBandwidth()) {
                        errors.put("uploadLimitError",
                                l10n("valid.uploadLimit", Integer.toString(Node.getMinimumBandwidth() / KiB)));
                    }
                    int nanosInSecond = (int) SECONDS.toNanos(1);
                    if (nanosInSecond < uploadLimit) { // see Node set outputBandwidthLimit
                        errors.put("uploadLimitError",
                                l10n("valid.uploadLimitMax", Integer.toString(nanosInSecond / KiB)));
                    }
                } catch (NumberFormatException e) {
                    errors.put("uploadLimitError",
                            l10n("valid.number.prefix.uploadLimit") + " " + e.getMessage());
                }
            } else {
                try {
                    double monthlyLimit = 0;
                    if (!bandwidthMonthlyLimit.isEmpty()) {
                        monthlyLimit = Double.parseDouble(bandwidthMonthlyLimit);
                    }
                    if (monthlyLimit < BandwidthLimit.minMonthlyLimit) {
                        errors.put("bandwidthMonthlyLimitError",
                                l10n("valid.bandwidthMonthlyLimit", String.format("%.2f", BandwidthLimit.minMonthlyLimit)));
                    }
                } catch (NumberFormatException e) {
                    errors.put("bandwidthMonthlyLimitError",
                            l10n("valid.number.prefix.bandwidthMonthlyLimit") + " " + e.getMessage());
                }
            }

            try {
                long storageLimit = this.storageLimit.isEmpty() ? 0 : Fields.parseLong(this.storageLimit + "GiB");
                if (storageLimit < Node.MIN_STORE_SIZE * 5 / 4) { // min store size + 10% for client cache + 10% for slashdot cache
                    errors.put("storageLimitError", NodeL10n.getBase().getString("Node.invalidMinStoreSizeWithCaches"));
                } else {
                    long maxDatastoreSize = DatastoreUtil.maxDatastoreSize();
                    if (storageLimit > maxDatastoreSize) {
                        errors.put("storageLimitError",
                                NodeL10n.getBase().getString("Node.invalidMaxStoreSize",
                                        String.format("%.2f", (float) maxDatastoreSize / DatastoreUtil.oneGiB)));
                    }
                }
            } catch (NumberFormatException e) {
                errors.put("storageLimitError",
                        l10n("valid.number.prefix.storageLimit") + " " + e.getMessage());
            }

            if (!setPassword.isEmpty()) {
                if (password.isEmpty()) {
                    errors.put("passwordError", NodeL10n.getBase().getString("SecurityLevels.passwordNotZeroLength"));
                }
                if (password.length() > SecurityLevelsToadlet.MAX_PASSWORD_LENGTH) {
                    errors.put("passwordError", NodeL10n.getBase().getString("SecurityLevels.passwordTooLong"));
                }
                if (!password.equals(passwordConfirmation)) {
                    errors.put("passwordError", NodeL10n.getBase().getString("SecurityLevels.passwordsDoNotMatch"));
                }
            }
        }

        private boolean isValid() {
            return errors.isEmpty();
        }

        private void detectBandwidthLimit() {
            try {
                BandwidthLimit detected =
                        BandwidthManipulator.detectBandwidthLimits(core.node.ipDetector.getBandwidthIndicator());

                // Detected limits reasonable; add half of both as recommended option.
                downloadLimitDetected = Long.toString(detected.downBytes / 2 / KiB);
                uploadLimitDetected = Long.toString(detected.upBytes / 2 / KiB);
            } catch (PluginNotFoundException | IllegalValueException e) {
                Logger.normal(this, e.getMessage(), e);
            }
        }

        private Map<String, Object> toModel() {
            HashMap<String, Object> model = new HashMap<>();
            model.put("knowSomeone", knowSomeone.length() > 0 ? "checked" : "");
            model.put("connectToStrangers", connectToStrangers.length() > 0 ? "checked" : "");
            model.put("haveMonthlyLimit", haveMonthlyLimit.length() > 0 ? "checked" : "");
            model.put("downloadLimit", downloadLimit);
            model.put("uploadLimit", uploadLimit);
            model.put("bandwidthMonthlyLimit", bandwidthMonthlyLimit);
            model.put("minBandwidthMonthlyLimit", String.format("%.2f", BandwidthLimit.minMonthlyLimit));
            model.put("storageLimit", storageLimit);
            if (isPasswordEmpty) {
                model.put("setPassword", setPassword.length() > 0 ? "checked" : "");
            }
            model.put("isPasswordEmpty", isPasswordEmpty);

            if (downloadLimitDetected == null || uploadLimitDetected == null) {
                detectBandwidthLimit();
            }
            model.put("downloadLimitDetected", downloadLimitDetected != null ? downloadLimitDetected : l10n("bandwidthCommonInternetConnectionSpeedsDetectedUnavailable"));
            model.put("uploadLimitDetected", uploadLimitDetected != null ? uploadLimitDetected : l10n("bandwidthCommonInternetConnectionSpeedsDetectedUnavailable"));

            model.put("errors", errors);

            return model;
        }

        private void save() {
            if (knowSomeone.isEmpty()) {
                // Opennet
                core.node.securityLevels.setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.LOW);
            } else {
                if (connectToStrangers.isEmpty()) {
                    // Darknet
                    core.node.securityLevels.setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.HIGH);
                } else {
                    // Opennet + Darknet
                    core.node.securityLevels.setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL);
                }
            }

            try {
                if (haveMonthlyLimit.isEmpty()) { // save download & uploadLimit
                    config.get("node").set("inputBandwidthLimit", downloadLimit + "KiB");
                    config.get("node").set("outputBandwidthLimit", uploadLimit + "KiB");
                } else { // save bandwidthMonthlyLimit
                    BandwidthLimit bandwidth = new BandwidthLimit(Fields.parseLong(bandwidthMonthlyLimit + "GiB"));
                    config.get("node").set("inputBandwidthLimit", Long.toString(bandwidth.downBytes));
                    config.get("node").set("outputBandwidthLimit", Long.toString(bandwidth.upBytes));
                }
            } catch (ConfigException e) {
                Logger.error(this, "Should not happen, please report! " + e, e);
            }

            DATASTORE_SIZE.setDatastoreSize(storageLimit + "GiB", config, this);

            // TODO: not sure
            if (isPasswordEmpty) {
                try {
                    if (setPassword.isEmpty()) {
                        core.node.securityLevels.setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
                        core.node.setMasterPassword("", true);
                    } else {
                        core.node.securityLevels.setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
                        core.node.setMasterPassword(password, true);
                    }
                } catch (Node.AlreadySetPasswordException | MasterKeysWrongPasswordException | MasterKeysFileSizeException | IOException e) {
                    Logger.error(this, "Should not happen, please report! " + e, e);
                }
            }

            core.storeConfig();
        }
    }
}
