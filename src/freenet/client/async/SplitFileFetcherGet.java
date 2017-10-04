package freenet.client.async;

import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.async.SplitFileFetcherStorage.MyKey;
import freenet.keys.ClientKey;
import freenet.keys.Key;
import freenet.node.KeysFetchingLocally;
import freenet.node.LowLevelGetException;
import freenet.node.RequestClient;
import freenet.node.SendableGet;
import freenet.node.SendableRequestItem;
import freenet.support.Logger;

/** Actually does the splitfile fetch. Only one fetcher object for an entire splitfile.
 * 
 * PERSISTENCE: Not persistent, recreated on startup by SplitFileFetcher. */
@SuppressWarnings("serial")
public class SplitFileFetcherGet extends SendableGet implements HasKeyListener {
    
    private static volatile boolean logMINOR;
    static {
        Logger.registerClass(SplitFileFetcherGet.class);
    }

    final SplitFileFetcher parent;
    final SplitFileFetcherStorage storage;

    public SplitFileFetcherGet(SplitFileFetcher fetcher, SplitFileFetcherStorage storage) {
        super(fetcher.parent, fetcher.realTimeFlag);
        this.parent = fetcher;
        this.storage = storage;
    }

    @Override
    public ClientKey getKey(SendableRequestItem token) {
        MyKey key = (MyKey) token;
        if(key.get != storage) throw new IllegalArgumentException();
        return storage.getKey(key);
    }

    @Override
    public Key[] listKeys() {
        return storage.listUnfetchedKeys();
    }

    @Override
    public FetchContext getContext() {
        return parent.blockFetchContext;
    }

    @Override
    public void onFailure(LowLevelGetException e, SendableRequestItem token,
            ClientContext context) {
        FetchException fe = translateException(e);
        if(fe.isDefinitelyFatal()) {
            // If the error is definitely-fatal it means there is either a serious local problem
            // or the inserted data was corrupt. So we fail the entire splitfile immediately.
            // We don't track which blocks have fatally failed.
            if(logMINOR) Logger.minor(this, "Fatal failure: "+fe+" for "+token);
            parent.fail(fe);
        } else {
            MyKey key = (MyKey) token;
            if(key.get != storage) throw new IllegalArgumentException();
            storage.onFailure(key, fe);
        }
    }
    
    @Override
    public long getWakeupTime(ClientContext context, long now) {
        long wakeTime = storage.getCooldownWakeupTime(now);
        if(wakeTime == 0) return 0;
        return wakeTime;
    }

    @Override
    public long getCooldownWakeup(SendableRequestItem token) {
        MyKey key = (MyKey) token;
        return storage.segments[key.segmentNumber].getCooldownTime(key.blockNumber);
    }

    @Override
    public boolean preRegister(ClientContext context, boolean toNetwork) {
        if(!toNetwork) return false;
        // Notify clients of all the work we've done checking the datastore.
        if(parent.localRequestOnly()) {
            storage.finishedCheckingDatastoreOnLocalRequest();
            return true;
        } else {
            storage.setHasCheckedStore(context);
        }
        parent.toNetwork();
        parent.parent.notifyClients(context);
        return false;
    }

    @Override
    public short getPriorityClass() {
        return parent.getPriorityClass();
    }

    @Override
    /** Choose a random key to fetch. Must not modify anything that is persisted. */
    public SendableRequestItem chooseKey(KeysFetchingLocally keys, ClientContext context) {
        return storage.chooseRandomKey();
    }

    @Override
    public long countAllKeys() {
        return storage.countUnfetchedKeys();
    }

    @Override
    public long countSendableKeys() {
        return storage.countSendableKeys();
    }

    @Override
    public boolean isCancelled() {
        // FIXME locking on this is a bit different to the old code ... is it safe?
        return parent.hasFinished();
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

    /**
     * Schedule the fetch.
     * @param context
     * @param ignoreStore If true, don't check the datastore before re-registering the requests to
     * run. Should be true when rescheduling after a normal cooldown, false after recovering from
     * data corruption (the blocks may still be in the store), false otherwise.
     */
    public void schedule(ClientContext context, boolean ignoreStore) {
        ClientRequestScheduler sched = context.getChkFetchScheduler(realTimeFlag);
        BlockSet blocks = parent.blockFetchContext.blocks;
        sched.register(this, new SendableGet[] { this }, persistent, blocks, ignoreStore);
    }

    @Override
    public KeyListener makeKeyListener() {
        return storage.keyListener;
    }

    public void cancel(ClientContext context) {
        unregister(context, parent.getPriorityClass());
    }

    /** Has preRegister() been called? */
    public boolean hasQueued() {
        return storage.hasCheckedStore();
    }

    @Override
    protected ClientGetState getClientGetState() {
        return parent;
    }
    
}
