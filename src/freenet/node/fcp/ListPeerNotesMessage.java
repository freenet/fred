/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node.fcp;

import com.db4o.ObjectContainer;

import freenet.node.DarknetPeerNode;
import freenet.node.Node;
import freenet.node.PeerNode;
import freenet.support.SimpleFieldSet;

public class ListPeerNotesMessage extends FCPMessage {

    static final String NAME = "ListPeerNotes";
    final SimpleFieldSet fs;
    final String identifier;
    
    public ListPeerNotesMessage(SimpleFieldSet fs) {
        this.fs = fs;
        this.identifier = fs.get("Identifier");
        fs.removeValue("Identifier");
    }
    
    @Override
    public SimpleFieldSet getFieldSet() {
        return new SimpleFieldSet(true);
    }
    
    @Override
    public String getName() {
        return NAME;
    }
    
    @Override
    public void run(FCPConnectionHandler handler, Node node)
            throws MessageInvalidException {
        if(!handler.hasFullAccess()) {
            throw new MessageInvalidException(ProtocolErrorMessage.ACCESS_DENIED, "ListPeerNotes requires full access", identifier, false);
        }
        String nodeIdentifier = fs.get("NodeIdentifier");
        if( nodeIdentifier == null ) {
            throw new MessageInvalidException(ProtocolErrorMessage.MISSING_FIELD, "Error: NodeIdentifier field missing", identifier, false);
        }
        PeerNode pn = node.getPeerNode(nodeIdentifier);
        if(pn == null) {
            FCPMessage msg = new UnknownNodeIdentifierMessage(nodeIdentifier, identifier);
            handler.outputHandler.queue(msg);
            return;
        }
        if(!(pn instanceof DarknetPeerNode)) {
            throw new MessageInvalidException(ProtocolErrorMessage.DARKNET_ONLY, "ModifyPeer only available for darknet peers", identifier, false);
        }
        DarknetPeerNode dpn = (DarknetPeerNode) pn;
        // **FIXME** this should be generalized for multiple peer notes per peer, after PeerNode is similarly generalized
        String noteText = dpn.getPrivateDarknetCommentNote();
        handler.outputHandler.queue(new PeerNote(nodeIdentifier, noteText, Node.PEER_NOTE_TYPE_PRIVATE_DARKNET_COMMENT, identifier));
        handler.outputHandler.queue(new EndListPeerNotesMessage(nodeIdentifier, identifier));
    }

    @Override
    public void removeFrom(ObjectContainer container) {
        throw new UnsupportedOperationException();
    }
    
}
