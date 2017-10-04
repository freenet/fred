package freenet.clients.http;

import java.util.ArrayList;
import java.util.Enumeration;

import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.async.ClientContext;
import freenet.clients.http.FProxyFetchInProgress.REFILTER_POLICY;
import freenet.keys.FreenetURI;
import freenet.node.RequestClient;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.MultiValueTable;
import freenet.support.Logger.LogLevel;

public class FProxyFetchTracker implements Runnable {

	private static volatile boolean logMINOR;
	
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
	final MultiValueTable<FreenetURI, FProxyFetchInProgress> fetchers;
	final ClientContext context;
	private long fetchIdentifiers;
	private final FetchContext fctx;
	private final RequestClient rc;
	private boolean queuedJob;
	private boolean requeue;

	public FProxyFetchTracker(ClientContext context, FetchContext fctx, RequestClient rc) {
		fetchers = new MultiValueTable<FreenetURI, FProxyFetchInProgress>();
		this.context = context;
		this.fctx = fctx;
		this.rc = rc;
	}
	
	public FProxyFetchWaiter makeFetcher(FreenetURI key, long maxSize, FetchContext fctx, REFILTER_POLICY refilterPolicy) throws FetchException {
		FProxyFetchInProgress progress;
		/* LOCKING:
		 * Call getWaiter() inside the fetchers lock, since we will purge old 
		 * fetchers inside that lock, hence avoid a race condition. FetchInProgress 
		 * lock is always taken last. */
		synchronized(fetchers) {
			FProxyFetchWaiter waiter=makeWaiterForFetchInProgress(key, maxSize, fctx != null ? fctx : this.fctx);
			if(waiter!=null){
				return waiter;
			}
			progress = new FProxyFetchInProgress(this, key, maxSize, fctx != null ? fctx : this.fctx, rc, refilterPolicy);
			fetchers.put(key, progress);
		}
		try {
			progress.start(context);
		} catch (FetchException e) {
			synchronized(fetchers) {
				fetchers.removeElement(key, progress);
			}
			throw e;
		}
		if(logMINOR) Logger.minor(this, "Created new fetcher: "+progress, new Exception());
		return progress.getWaiter();
		// FIXME promote a fetcher when it is re-used
		// FIXME get rid of fetchers over some age
	}
	
	void removeFetcher(FProxyFetchInProgress progress) {
		synchronized(fetchers) {
			fetchers.removeElement(progress.uri, progress);
		}
	}
	
	public FProxyFetchWaiter makeWaiterForFetchInProgress(FreenetURI key,long maxSize, FetchContext fctx){
		FProxyFetchInProgress progress=getFetchInProgress(key, maxSize, fctx);
		if(progress!=null){
			return progress.getWaiter();
		}
		return null;
	}
	
	/** Gets an FProxyFetchInProgress identified by the URI and the maxsize. If no such FetchInProgress exists, then returns null.
	 * @param key - The URI of the fetch
	 * @param maxSize - The maxSize of the fetch
	 * @param fctx TODO
	 * @return The FetchInProgress if found, null otherwise*/
	public FProxyFetchInProgress getFetchInProgress(FreenetURI key, long maxSize, FetchContext fctx){
		synchronized (fetchers) {
			Object[] check = fetchers.getArray(key);
			if(check != null) {
				for(int i=0;i<check.length;i++) {
					FProxyFetchInProgress progress = (FProxyFetchInProgress) check[i];
					if((progress.maxSize == maxSize && progress.notFinishedOrFatallyFinished())
							|| progress.hasData()){
						if(logMINOR) Logger.minor(this, "Found "+progress);
						if(fctx != null && !progress.fetchContextEquivalent(fctx)) continue;
						if(logMINOR) Logger.minor(this, "Using "+progress);
						return progress;
					} else
						if(logMINOR) Logger.minor(this, "Skipping "+progress);
				}
			}
		}
		return null;
	}

	public void queueCancel() {
		if(logMINOR) Logger.minor(this, "Queueing removal of old FProxyFetchInProgress's");
		synchronized(this) {
			if(queuedJob) {
				requeue = true;
				return;
			}
			queuedJob = true;
		}
		context.ticker.queueTimedJob(this, FProxyFetchInProgress.LIFETIME);
	}

	@Override
	public void run() {
		if(logMINOR) Logger.minor(this, "Removing old FProxyFetchInProgress's");
		ArrayList<FProxyFetchInProgress> toRemove = null;
		boolean needRequeue = false;
		synchronized(fetchers) {
			if(requeue) {
				requeue = false;
				needRequeue = true;
			} else {
				queuedJob = false;
			}
			// Horrible hack, FIXME
			Enumeration<FreenetURI> e = fetchers.keys();
			while(e.hasMoreElements()) {
				FreenetURI uri = e.nextElement();
				// Really horrible hack, FIXME
				for(FProxyFetchInProgress f : fetchers.iterateAll(uri)) {
					// FIXME remove on the fly, although cancel must wait
					if(f.canCancel()) {
						if(toRemove == null) toRemove = new ArrayList<FProxyFetchInProgress>();
						toRemove.add(f);
					}
				}
			}
			if(toRemove != null)
			for(FProxyFetchInProgress r : toRemove) {
				if(logMINOR){
					Logger.minor(this,"Removed fetchinprogress:"+r);
				}
				fetchers.removeElement(r.uri, r);
			}
		}
		if(toRemove != null)
		for(FProxyFetchInProgress r : toRemove) {
			if(logMINOR)
				Logger.minor(this, "Cancelling for "+r);
			r.finishCancel();
		}
		if(needRequeue)
			context.ticker.queueTimedJob(this, FProxyFetchInProgress.LIFETIME);
	}

	public int makeRandomElementID() {
		return context.fastWeakRandom.nextInt();
	}

}
