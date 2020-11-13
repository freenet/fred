package freenet.clients.http;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import freenet.client.ClientMetadata;
import freenet.client.DefaultMIMETypes;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.FetchResult;
import freenet.client.async.CacheFetchResult;
import freenet.client.async.ClientContext;
import freenet.client.async.ClientGetCallback;
import freenet.client.async.ClientGetter;
import freenet.client.async.PersistenceDisabledException;
import freenet.client.events.ClientEvent;
import freenet.client.events.ClientEventListener;
import freenet.client.events.ExpectedFileSizeEvent;
import freenet.client.events.ExpectedMIMEEvent;
import freenet.client.events.SendingToNetworkEvent;
import freenet.client.events.SplitfileProgressEvent;
import freenet.client.filter.ContentFilter;
import freenet.client.filter.FilterMIMEType;
import freenet.client.filter.UnknownContentTypeException;
import freenet.keys.FreenetURI;
import freenet.keys.USK;
import freenet.node.RequestClient;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;
import freenet.support.io.Closer;

/**
 * Fetching a page for a browser.
 *
 * LOCKING: The lock on this object is always taken last.
 */
public class FProxyFetchInProgress implements ClientEventListener, ClientGetCallback {

	/** What to do when we find data which matches the request but it has already been
	 * filtered, assuming we want a filtered copy. */
	public enum REFILTER_POLICY {
		RE_FILTER, // Re-run the filter over data that has already been filtered. Probably requires allocating a new temp file.
		ACCEPT_OLD, // Accept the old filtered data. Only as safe as the filter when the data was originally downloaded.
		RE_FETCH // Fetch the data again. Unnecessary in most cases, avoids any possibility of filter artefacts.
	}

	private final REFILTER_POLICY refilterPolicy;

	private static volatile boolean logMINOR;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {

			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	/** The key we are fetching */
	public final FreenetURI uri;
	/** The maximum size specified by the client */
	public final long maxSize;
	/** Fetcher */
	private final ClientGetter getter;
	/** Any request which is waiting for a progress screen or data.
	 * We may want to wake requests separately in future. */
	private final ArrayList<FProxyFetchWaiter> waiters;
	private final ArrayList<FProxyFetchResult> results;
	/** Gets notified with every change*/
	private final List<FProxyFetchListener> listener=Collections.synchronizedList(new ArrayList<FProxyFetchListener>());
	/** The data, if we have it */
	private Bucket data;
	/** Creation time */
	private final long timeStarted;
	/** Finished? */
	private boolean finished;
	/** Size, if known */
	private long size;
	/** MIME type, if known */
	private String mimeType;
	/** Gone to network? */
	private boolean goneToNetwork;
	/** Total blocks */
	private int totalBlocks;
	/** Required blocks */
	private int requiredBlocks;
	/** Fetched blocks */
	private int fetchedBlocks;
	/** Failed blocks */
	private int failedBlocks;
	/** Fatally failed blocks */
	private int fatallyFailedBlocks;
	private int fetchedBlocksPreNetwork;
	/** Finalized the block set? */
	private boolean finalizedBlocks;
	/** Fetch failed */
	private FetchException failed;
	private boolean hasWaited;
	private boolean hasNotifiedFailure;
	/** Last time the fetch was accessed from the fproxy end */
	private long lastTouched;
	final FProxyFetchTracker tracker;
	/** Show even non-fatal failures for 5 seconds. Necessary for javascript to work,
	 * because it fetches the page and then reloads it if it isn't a progress update. */
	private long timeFailed;
	/** If this is set, then it can be removed instantly, doesn't need to wait for 30sec*/
	private boolean requestImmediateCancel=false;
	private int fetched = 0;
	/** Stores the fetch context this class was created with*/
	private FetchContext fctx;
	private boolean cancelled = false;
	private final RequestClient rc;

	public FProxyFetchInProgress(FProxyFetchTracker tracker, FreenetURI key, long maxSize2, long identifier, ClientContext context, FetchContext fctx, RequestClient rc, REFILTER_POLICY refilter) {
		this.refilterPolicy = refilter;
		this.tracker = tracker;
		this.uri = key;
		this.maxSize = maxSize2;
		this.timeStarted = System.currentTimeMillis();
		this.fctx = fctx;
        this.rc = rc;
		FetchContext alteredFctx = new FetchContext(fctx, FetchContext.IDENTICAL_MASK);
		alteredFctx.maxOutputLength = fctx.maxTempLength = maxSize;
		alteredFctx.eventProducer.addEventListener(this);
		waiters = new ArrayList<FProxyFetchWaiter>();
		results = new ArrayList<FProxyFetchResult>();
		getter = new ClientGetter(this, uri, alteredFctx, FProxyToadlet.PRIORITY, null, null, null);
	}

	public synchronized FProxyFetchWaiter getWaiter() {
		lastTouched = System.currentTimeMillis();
		FProxyFetchWaiter waiter = new FProxyFetchWaiter(this);
		waiters.add(waiter);
		return waiter;
	}

	public FProxyFetchTracker getTracker() {
		return tracker;
	}

	public synchronized void addCustomWaiter(FProxyFetchWaiter waiter){
		waiters.add(waiter);
	}

	synchronized FProxyFetchResult innerGetResult(boolean hasWaited) {
		lastTouched = System.currentTimeMillis();
		FProxyFetchResult res;
		if(data != null)
			res = new FProxyFetchResult(this, data, mimeType, timeStarted, goneToNetwork, getETA(), hasWaited);
		else {
			res = new FProxyFetchResult(this, mimeType, size, timeStarted, goneToNetwork,
					totalBlocks, requiredBlocks, fetchedBlocks, failedBlocks, fatallyFailedBlocks, finalizedBlocks, failed, getETA(), hasWaited);
		}
		results.add(res);
		if(data != null || failed != null) {
			res.setFetchCount(fetched);
			fetched++;
		}
		return res;
	}

	public void start(ClientContext context) throws FetchException {
		try {
			if(!checkCache(context))
				context.start(getter);
		} catch (FetchException e) {
			synchronized(this) {
				this.failed = e;
				this.finished = true;
			}
		} catch (PersistenceDisabledException e) {
			// Impossible
			Logger.error(this, "Failed to start: "+e);
			synchronized(this) {
				this.failed = new FetchException(FetchExceptionMode.INTERNAL_ERROR, e);
				this.finished = true;
			}
		}
	}

	/** Look up the key in the downloads queue.
	 * @return True if it was found and we don't need to start the request. */
	private boolean checkCache(ClientContext context) {
		// Fproxy uses lookupInstant() with mustCopy = false. I.e. it can reuse stuff unsafely. If the user frees it it's their fault.
		if(bogusUSK(context)) return false;
		CacheFetchResult result = context.downloadCache == null ? null : context.downloadCache.lookupInstant(uri, !fctx.filterData, false, null);
		if(result == null) return false;
		Bucket data = null;
		String mimeType = null;
		if((!fctx.filterData) && (!result.alreadyFiltered)) {
			if(fctx.overrideMIME == null || fctx.overrideMIME.equals(result.getMimeType())) {
				// Works as-is.
				// Any time we re-use old content we need to remove the tracker because it may not remain available.
				tracker.removeFetcher(this);
				onSuccess(result, null);
				return true;
			} else if(fctx.overrideMIME != null && !fctx.overrideMIME.equals(result.getMimeType())) {
				// Change the MIME type.
				tracker.removeFetcher(this);
				onSuccess(new FetchResult(new ClientMetadata(fctx.overrideMIME), result.asBucket()), null);
				return true;
			}
		} else if(result.alreadyFiltered) {
			if(refilterPolicy == REFILTER_POLICY.RE_FETCH || !fctx.filterData) {
				// Can't use it.
				return false;
			} else if(fctx.filterData) {
				if(shouldAcceptCachedFilteredData(fctx, result)) {
					if(refilterPolicy == REFILTER_POLICY.ACCEPT_OLD) {
						tracker.removeFetcher(this);
						onSuccess(result, null);
						return true;
					} // else re-filter
				} else
					return false;
			} else {
				return false;
			}
		}
		data = result.asBucket();
		mimeType = result.getMimeType();
		if(mimeType == null || mimeType.equals("")) mimeType = DefaultMIMETypes.DEFAULT_MIME_TYPE;
		if(fctx.overrideMIME != null && !result.alreadyFiltered)
			mimeType = fctx.overrideMIME;
		else if(fctx.overrideMIME != null && !mimeType.equals(fctx.overrideMIME)) {
			// Doesn't work.
			return false;
		}
		String fullMimeType = mimeType;
		mimeType = ContentFilter.stripMIMEType(mimeType);
		FilterMIMEType type = ContentFilter.getMIMEType(mimeType);
		if(type == null || ((!type.safeToRead) && type.readFilter == null)) {
			UnknownContentTypeException e = new UnknownContentTypeException(mimeType);
			data.free();
			onFailure(new FetchException(e.getFetchErrorCode(), data.size(), e, mimeType), null);
			return true;
		} else if(type.safeToRead) {
			tracker.removeFetcher(this);
			onSuccess(new FetchResult(new ClientMetadata(mimeType), data), null);
			return true;
		} else {
			// Try to filter it.
			Bucket output = null;
			InputStream is = null;
			OutputStream os = null;
			try {
				output = context.tempBucketFactory.makeBucket(-1);
				is = data.getInputStream();
				os = output.getOutputStream();
				ContentFilter.filter(is, os, fullMimeType, uri.toURI("/"), fctx.getSchemeHostAndPort(), null, null, fctx.charset, context.linkFilterExceptionProvider);
				is.close();
				is = null;
				os.close();
				os = null;
				// Since we are not re-using the data bucket, we can happily stay in the FProxyFetchTracker.
				this.onSuccess(new FetchResult(new ClientMetadata(fullMimeType), output), null);
				output = null;
				return true;
			} catch (IOException e) {
				Logger.normal(this, "Failed filtering coalesced data in fproxy");
				// Failed. :|
				// Let it run normally.
				return false;
			} catch (URISyntaxException e) {
				Logger.error(this, "Impossible: "+e, e);
				return false;
			} finally {
				Closer.close(is);
				Closer.close(os);
				Closer.close(output);
				Closer.close(data);
			}
		}
	}

	/** If the key is a USK and a) we are requested to do an exhaustive search, or b)
	 * there is a later version, then we can't use the download queue as a cache.
	 * @return True if we can't use the download queue, false if we can. */
	private boolean bogusUSK(ClientContext context) {
		if(!uri.isUSK()) return false;
		long edition = uri.getSuggestedEdition();
		if(edition < 0)
			return true; // Need to do the fetch.
		USK usk;
		try {
			usk = USK.create(uri);
		} catch (MalformedURLException e) {
			return false; // Will fail later.
		}
		long ret = context.uskManager.lookupKnownGood(usk);
		if(ret == -1) return false;
		return ret > edition;
	}

	private boolean shouldAcceptCachedFilteredData(FetchContext fctx,
			CacheFetchResult result) {
		// FIXME allow the charset if it's the same
		if(fctx.charset != null) return false;
		if(fctx.overrideMIME == null) {
			return true;
		} else {
			String finalMIME = result.getMimeType();
			if(fctx.overrideMIME.equals(finalMIME))
				return true;
			else if(ContentFilter.stripMIMEType(finalMIME).equals(fctx.overrideMIME) && fctx.charset == null)
				return true;
			// FIXME we could make this work in a few more cases... it doesn't matter much though as usually people don't override the MIME type!
		}
		return false;
	}

	@Override
	public void receive(ClientEvent ce, ClientContext context) {
		try{
			if(ce instanceof SplitfileProgressEvent) {
				SplitfileProgressEvent split = (SplitfileProgressEvent) ce;
				synchronized(this) {
					int oldReq = requiredBlocks - (fetchedBlocks + failedBlocks + fatallyFailedBlocks);
					totalBlocks = split.totalBlocks;
					fetchedBlocks = split.succeedBlocks;
					requiredBlocks = split.minSuccessfulBlocks;
					failedBlocks = split.failedBlocks;
					fatallyFailedBlocks = split.fatallyFailedBlocks;
					finalizedBlocks = split.finalizedTotal;
					int req = requiredBlocks - (fetchedBlocks + failedBlocks + fatallyFailedBlocks);
					if(!(req > 1024 && oldReq <= 1024)) return;
				}
			} else if(ce instanceof SendingToNetworkEvent) {
				synchronized(this) {
					if(goneToNetwork) return;
					goneToNetwork = true;
					fetchedBlocksPreNetwork = fetchedBlocks;
				}
			} else if(ce instanceof ExpectedMIMEEvent) {
				synchronized(this) {
					this.mimeType = ((ExpectedMIMEEvent)ce).expectedMIMEType;
				}
				if(!goneToNetwork) return;
			} else if(ce instanceof ExpectedFileSizeEvent) {
				synchronized(this) {
					this.size = ((ExpectedFileSizeEvent)ce).expectedSize;
				}
				if(!goneToNetwork) return;
			} else return;
			wakeWaiters(false);
		}finally{
			for(FProxyFetchListener l:new ArrayList<FProxyFetchListener>(listener)){
				l.onEvent();
			}
		}
	}

	private void wakeWaiters(boolean finished) {
		FProxyFetchWaiter[] waiting;
		synchronized(this) {
			waiting = waiters.toArray(new FProxyFetchWaiter[waiters.size()]);
		}
		for(FProxyFetchWaiter w : waiting) {
			w.wakeUp(finished);
		}
		if(finished==true){
			for(FProxyFetchListener l:new ArrayList<FProxyFetchListener>(listener)){
				l.onEvent();
			}
		}
	}

	@Override
	public void onFailure(FetchException e, ClientGetter state) {
		synchronized(this) {
			this.failed = e;
			this.finished = true;
			this.timeFailed = System.currentTimeMillis();
		}
		wakeWaiters(true);
	}

	@Override
	public void onSuccess(FetchResult result, ClientGetter state) {
		Bucket droppedData = null;
		synchronized(this) {
			if(cancelled)
				droppedData = result.asBucket();
			else
				this.data = result.asBucket();
			this.mimeType = result.getMimeType();
			this.finished = true;
		}
		wakeWaiters(true);
		if(droppedData != null)
			droppedData.free();
	}

	public synchronized boolean hasData() {
		return data != null;
	}

	public synchronized boolean finished() {
		return finished;
	}

	public void close(FProxyFetchWaiter waiter) {
		synchronized(this) {
			waiters.remove(waiter);
			if(!results.isEmpty()) return;
			if(!waiters.isEmpty()) return;
		}
		tracker.queueCancel(this);
	}

	/** Keep for 30 seconds after last access */
	static final long LIFETIME = SECONDS.toMillis(30);

	/** Caller should take the lock on FProxyToadlet.fetchers, then call this
	 * function, if it returns true then finish the cancel outside the lock.
	 */
	public synchronized boolean canCancel() {
		if(!waiters.isEmpty()) return false;
		if(!results.isEmpty()) return false;
		if(!listener.isEmpty()) return false;
		if(lastTouched + LIFETIME >= System.currentTimeMillis() && !requestImmediateCancel) {
			if(logMINOR) Logger.minor(this, "Not able to cancel for "+this+" : "+uri+" : "+maxSize);
			return false;
		}
		if(logMINOR) Logger.minor(this, "Can cancel for "+this+" : "+uri+" : "+maxSize);
		return true;
	}

	/** Finish the cancel process, freeing the data if necessary. The fetch
	 * must have been removed from the tracker already, so it won't be reused. */
	public void finishCancel() {
		if(logMINOR) Logger.minor(this, "Finishing cancel for "+this+" : "+uri+" : "+maxSize);
		try {
			getter.cancel(tracker.context);
		} catch (Throwable t) {
			// Ensure we get to the next bit
			Logger.error(this, "Failed to cancel: "+t, t);
		}
		Bucket d;
		synchronized(this) {
			d = data;
			cancelled = true;
		}
		if(d != null) {
			try {
				d.free();
			} catch (Throwable t) {
				// Ensure we get to the next bit
				Logger.error(this, "Failed to free: "+t, t);
			}
		}
	}

	public void close(FProxyFetchResult result) {
		synchronized(this) {
			results.remove(result);
			if(!results.isEmpty()) return;
			if(!waiters.isEmpty()) return;
		}
		tracker.queueCancel(this);
	}

	public synchronized long getETA() {
		if(!goneToNetwork) return -1;
		if(requiredBlocks <= 0) return -1;
		if(fetchedBlocks >= requiredBlocks) return -1;
		if(fetchedBlocks - fetchedBlocksPreNetwork < 5) return -1;
		return ((System.currentTimeMillis() - timeStarted) * (requiredBlocks - fetchedBlocksPreNetwork)) / (fetchedBlocks - fetchedBlocksPreNetwork);
	}

	public synchronized boolean notFinishedOrFatallyFinished() {
		if(data == null && failed == null) return true;
		if(failed != null && failed.isFatal()) return true;
		if(failed != null && !hasNotifiedFailure) {
			hasNotifiedFailure = true;
			return true;
		}
		if(failed != null && (System.currentTimeMillis() - timeFailed < 1000 || fetched < 2)) // Once for javascript and once for the user when it re-pulls.
			return true;
		return false;
	}

	public synchronized boolean hasNotifiedFailure() {
		return true;
	}

	public synchronized boolean hasWaited() {
		return hasWaited;
	}

	public synchronized void setHasWaited() {
		hasWaited = true;
	}

	/** Adds a listener that will be notified when a change occurs to this fetch
	 * @param listener - The listener to be added*/
	public synchronized void addListener(FProxyFetchListener listener){
		if(logMINOR){
			Logger.minor(this,"Registered listener:"+listener);
		}
		this.listener.add(listener);
	}

	/** Removes a listener
	 * @param listener - The listener to be removed*/
	public synchronized void removeListener(FProxyFetchListener listener){
		if(logMINOR){
			Logger.minor(this,"Removed listener:"+listener);
		}
		this.listener.remove(listener);
		if(logMINOR){
			Logger.minor(this,"can cancel now?:"+canCancel());
		}
	}

	/** Allows the fetch to be removed immediately*/
	public synchronized void requestImmediateCancel(){
		requestImmediateCancel=true;
	}

	public synchronized long lastTouched() {
		return lastTouched;
	}

	public boolean fetchContextEquivalent(FetchContext context) {
		if(this.fctx.filterData != context.filterData) return false;
		if(this.fctx.maxOutputLength != context.maxOutputLength) return false;
		if(this.fctx.maxTempLength != context.maxTempLength) return false;
		if(this.fctx.charset == null && context.charset != null) return false;
		if(this.fctx.charset != null && !this.fctx.charset.equals(context.charset)) return false;
		if(this.fctx.overrideMIME == null && context.overrideMIME != null) return false;
		if(this.fctx.overrideMIME != null && !this.fctx.overrideMIME.equals(context.overrideMIME)) return false;
		return true;
	}

    @Override
    public void onResume(ClientContext context) {
        throw new UnsupportedOperationException(); // Not persistent.
    }

    @Override
    public RequestClient getRequestClient() {
        return rc;
    }

}
