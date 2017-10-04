package freenet.client.async;

import java.io.IOException;

import freenet.client.InsertException;
import freenet.client.async.SplitFileInserterSegmentStorage.BlockInsert;
import freenet.keys.CHKBlock;
import freenet.keys.ClientCHK;
import freenet.keys.ClientCHKBlock;
import freenet.keys.ClientKey;
import freenet.node.KeysFetchingLocally;
import freenet.node.LowLevelPutException;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.RequestClient;
import freenet.node.RequestScheduler;
import freenet.node.SendableInsert;
import freenet.node.SendableRequestItem;
import freenet.node.SendableRequestSender;
import freenet.store.KeyCollisionException;
import freenet.support.Logger;
import freenet.support.io.ResumeFailedException;

/**
 * Interface to the low level insertion code for inserting a splitfile.
 * 
 * PERSISTENCE: Not persisted, recreated on resume by SplitFileInserter.
 * @author toad
 */
@SuppressWarnings("serial") // Not persisted.
public class SplitFileInserterSender extends SendableInsert {
    
    final SplitFileInserter parent;
    final SplitFileInserterStorage storage;

    public SplitFileInserterSender(SplitFileInserter parent, SplitFileInserterStorage storage) {
        super(parent.persistent, parent.realTime); // Persistence should be from parent so that e.g. callbacks get run on the right jobRunner.
        this.parent = parent;
        this.storage = storage;
    }

    @Override
    public void onSuccess(SendableRequestItem keyNum, ClientKey key, ClientContext context) {
        BlockInsert block = (BlockInsert) keyNum;
        block.segment.onInsertedBlock(block.blockNumber, (ClientCHK) key);
    }

    @Override
    public void onFailure(LowLevelPutException e, SendableRequestItem keyNum, ClientContext context) {
        InsertException e1 = InsertException.constructFrom(e);
        if(keyNum == null) {
            storage.fail(e1);
        } else {
            BlockInsert block = (BlockInsert) keyNum;
            block.segment.onFailure(block.blockNumber, e1);
        }
    }

    @Override
    public boolean canWriteClientCache() {
        return parent.ctx.canWriteClientCache;
    }

    @Override
    public boolean localRequestOnly() {
        return parent.ctx.localRequestOnly;
    }

    @Override
    public boolean forkOnCacheable() {
        return parent.ctx.forkOnCacheable;
    }

    @Override
    public void onEncode(SendableRequestItem token, ClientKey key, ClientContext context) {
        BlockInsert block = (BlockInsert) token;
        // Should already be set. This is a sanity check.
        try {
            if(storage.hasFinished()) return;
            block.segment.setKey(block.blockNumber, (ClientCHK) key);
        } catch (IOException e) {
            if(storage.hasFinished()) return; // Race condition possible as this is a callback
            storage.failOnDiskError(e);
        }
    }

    @Override
    public boolean isEmpty() {
        return isCancelled();
    }

    @Override
    protected void innerOnResume(ClientContext context) throws InsertException,
            ResumeFailedException {
        throw new UnsupportedOperationException(); // Not persisted.
    }

    @Override
    public short getPriorityClass() {
        return parent.parent.getPriorityClass();
    }

    @Override
    public SendableRequestItem chooseKey(KeysFetchingLocally keys, ClientContext context) {
        return storage.chooseBlock();
    }

    @Override
    public long countAllKeys() {
        return storage.countAllKeys();
    }

    @Override
    public long countSendableKeys() {
        return storage.countSendableKeys();
    }
    
    class MySendableRequestSender implements SendableRequestSender {
        
        @Override
        public boolean send(NodeClientCore node, final RequestScheduler sched, ClientContext context,
                final ChosenBlock request) {
            final BlockInsert token = (BlockInsert) request.token;
            try {
                ClientCHKBlock clientBlock = token.segment.encodeBlock(token.blockNumber);
                CHKBlock block = clientBlock.getBlock();
                final ClientCHK key = clientBlock.getClientKey();
                context.getJobRunner(request.isPersistent()).queueNormalOrDrop(new PersistentJob() {
                    
                    @Override
                    public boolean run(ClientContext context) {
                        onEncode(token, key, context);
                        return false;
                    }
                    
                });
                if(request.localRequestOnly) {
                    try {
                        node.node.store(block, false, request.canWriteClientCache, true, false);
                    } catch (KeyCollisionException e) {
                        throw new LowLevelPutException(LowLevelPutException.COLLISION);
                    }
                } else {
                    node.realPut(block, request.canWriteClientCache, request.forkOnCacheable, Node.PREFER_INSERT_DEFAULT, Node.IGNORE_LOW_BACKOFF_DEFAULT, request.realTimeFlag);
                }
                request.onInsertSuccess(key, context);
                return true;
            } catch (final LowLevelPutException e) {
                request.onFailure(e, context);
                return true;
            } catch (final IOException e) {
                context.getJobRunner(request.isPersistent()).queueNormalOrDrop(new PersistentJob() {
                    
                    @Override
                    public boolean run(ClientContext context) {
                        try {
                            storage.failOnDiskError(e);
                        } finally {
                            // Must terminate the request anyway.
                            request.onFailure(new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, "Disk error", e), context);
                        }
                        return true;
                    }
                });
                return true;
            } catch (Throwable t) {
                Logger.error(this, "Failed to send insert: "+t, t);
                // We still need to terminate the insert.
                request.onFailure(new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR, "Failed: "+t, t), context);
                return true;
            }
        }

        @Override
        public boolean sendIsBlocking() {
            return true;
        }
        
    }
    
    final MySendableRequestSender sender = new MySendableRequestSender();
    
    @Override
    public SendableRequestSender getSender() {
        return sender;
    }

    @Override
    public boolean isCancelled() {
        return storage.hasFinished();
    }

    @Override
    public RequestClient getClient() {
        return parent.parent.getClient();
    }

    @Override
    public ClientRequester getClientRequest() {
        return parent.parent;
    }

    @Override
    public boolean isSSK() {
        return false;
    }

    public void schedule(ClientContext context) {
        if(getParentGrabArray() != null) return; // If change priority will unregister first.
        context.getChkInsertScheduler(parent.realTime).registerInsert(this);
    }
    
    @Override
    public long getWakeupTime(ClientContext context, long now) {
        return storage.getWakeupTime();
    }
}
