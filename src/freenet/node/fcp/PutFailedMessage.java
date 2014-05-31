/*
 * This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL.
 */



package freenet.node.fcp;

//~--- non-JDK imports --------------------------------------------------------

import com.db4o.ObjectContainer;

import freenet.client.FailureCodeTracker;
import freenet.client.InsertException;

import freenet.keys.FreenetURI;

import freenet.node.Node;

import freenet.support.SimpleFieldSet;

//~--- JDK imports ------------------------------------------------------------

import java.net.MalformedURLException;

public class PutFailedMessage extends FCPMessage {
    final int code;
    final String codeDescription;
    final String extraDescription;
    final String shortCodeDescription;
    final FailureCodeTracker tracker;
    final FreenetURI expectedURI;
    final String identifier;
    final boolean global;
    final boolean isFatal;

    /**
     * zero arg c'tor for db4o on jamvm
     */
    @SuppressWarnings("unused")
    private PutFailedMessage() {
        tracker = null;
        shortCodeDescription = null;
        isFatal = false;
        identifier = null;
        global = false;
        extraDescription = null;
        expectedURI = null;
        codeDescription = null;
        code = 0;
    }

    /**
     * Construct from a fieldset. Used in serialization of persistent requests.
     * Will need to be made more tolerant of syntax errors if is used in an FCP
     * client library. FIXME.
     * @param useVerboseFields If true, read in verbose fields (CodeDescription
     * etc), if false, reconstruct them from the error code.
     * @throws MalformedURLException
     */
    public PutFailedMessage(SimpleFieldSet fs, boolean useVerboseFields) throws MalformedURLException {
        identifier = fs.get("Identifier");

        if (identifier == null) {
            throw new NullPointerException();
        }

        global = fs.getBoolean("Global", false);
        code = Integer.parseInt(fs.get("Code"));

        if (useVerboseFields) {
            codeDescription = fs.get("CodeDescription");
            isFatal = fs.getBoolean("Fatal", false);
            shortCodeDescription = fs.get("ShortCodeDescription");
        } else {
            codeDescription = InsertException.getMessage(code);
            isFatal = InsertException.isFatal(code);
            shortCodeDescription = InsertException.getShortMessage(code);
        }

        extraDescription = fs.get("ExtraDescription");

        String euri = fs.get("ExpectedURI");

        if ((euri != null) && (euri.length() > 0)) {
            expectedURI = new FreenetURI(euri);
        } else {
            expectedURI = null;
        }

        SimpleFieldSet trackerSubset = fs.subset("Errors");

        if (trackerSubset != null) {
            tracker = new FailureCodeTracker(true, trackerSubset);
        } else {
            tracker = null;
        }
    }

    public PutFailedMessage(InsertException e, String identifier, boolean global) {
        this.code = e.getMode();
        this.codeDescription = InsertException.getMessage(code);
        this.shortCodeDescription = InsertException.getShortMessage(code);
        this.extraDescription = e.extra;
        this.tracker = e.errorCodes;
        this.expectedURI = e.uri;
        this.identifier = identifier;
        this.global = global;
        this.isFatal = InsertException.isFatal(code);
    }

    @Override
    public SimpleFieldSet getFieldSet() {
        return getFieldSet(true);
    }

    public SimpleFieldSet getFieldSet(boolean verbose) {
        SimpleFieldSet fs = new SimpleFieldSet(true);

        if (identifier == null) {
            throw new NullPointerException();
        }

        fs.putSingle("Identifier", identifier);
        fs.put("Global", global);
        fs.put("Code", code);

        if (verbose) {
            fs.putSingle("CodeDescription", codeDescription);
        }

        if (extraDescription != null) {
            fs.putSingle("ExtraDescription", extraDescription);
        }

        if (tracker != null) {
            fs.tput("Errors", tracker.toFieldSet(verbose));
        }

        if (verbose) {
            fs.put("Fatal", isFatal);
        }

        if (verbose) {
            fs.putSingle("ShortCodeDescription", shortCodeDescription);
        }

        if (expectedURI != null) {
            fs.putSingle("ExpectedURI", expectedURI.toString());
        }

        return fs;
    }

    @Override
    public String getName() {
        return "PutFailed";
    }

    @Override
    public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
        throw new MessageInvalidException(ProtocolErrorMessage.INVALID_MESSAGE,
                                          "PutFailed goes from server to client not the other way around", identifier,
                                          global);
    }

    @Override
    public void removeFrom(ObjectContainer container) {
        container.activate(this, 5);    // everything

        if (tracker != null) {
            tracker.removeFrom(container);
        }

        if (expectedURI != null) {
            expectedURI.removeFrom(container);
        }

        container.delete(this);
    }

    public String getShortFailedMessage() {
        return shortCodeDescription;
    }

    public String getLongFailedMessage() {
        if (extraDescription != null) {
            return shortCodeDescription + ": " + extraDescription;
        } else {
            return shortCodeDescription;
        }
    }
}
