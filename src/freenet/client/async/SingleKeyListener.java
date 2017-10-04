package freenet.client.async;

import freenet.keys.Key;
import freenet.keys.KeyBlock;
import freenet.keys.NodeSSK;
import freenet.node.LowLevelGetException;
import freenet.node.SendableGet;
import freenet.support.Logger;

public class SingleKeyListener implements KeyListener {
	
	private final Key key;
	private final BaseSingleFileFetcher fetcher;
	private boolean done;
	private short prio;
	private final boolean persistent;

	public SingleKeyListener(Key key, BaseSingleFileFetcher fetcher, short prio, boolean persistent) {
		this.key = key;
		this.fetcher = fetcher;
		this.prio = prio;
		this.persistent = persistent;
	}

	@Override
	public long countKeys() {
		if(done) return 0;
		else return 1;
	}

	@Override
	public short definitelyWantKey(Key key) {
		if(!key.equals(this.key)) return -1;
		else return prio;
	}

	@Override
	public HasKeyListener getHasKeyListener() {
		return fetcher;
	}

	@Override
	public short getPriorityClass() {
		return prio;
	}

	@Override
	public SendableGet[] getRequestsForKey(Key key) {
		if(!key.equals(this.key)) return null;
		return new SendableGet[] { fetcher };
	}

	@Override
	public boolean handleBlock(Key key, byte[] saltedKey, KeyBlock found, ClientContext context) {
		if(!key.equals(this.key)) return false;
		try {
			fetcher.onGotKey(key, found, context);
		} catch (Throwable t) {
			Logger.error(this, "Failed: "+t, t);
			fetcher.onFailure(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR), null, context);
		}
		synchronized(this) {
			done = true;
		}
		return true;
	}

	@Override
	public boolean persistent() {
		return persistent;
	}

	@Override
	public boolean probablyWantKey(Key key, byte[] saltedKey) {
		if(done) return false;
		return key.equals(this.key);
	}

	@Override
	public synchronized void onRemove() {
		done = true;
	}

	@Override
	public boolean isEmpty() {
		return done;
	}

	@Override
	public boolean isSSK() {
		return key instanceof NodeSSK;
	}

}
