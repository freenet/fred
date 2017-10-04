/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.async;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.util.Arrays;

import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.Metadata;
import freenet.keys.BaseClientKey;
import freenet.keys.FreenetURI;
import freenet.keys.InsertableUSK;
import freenet.keys.USK;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;
import freenet.support.io.BucketTools;
import freenet.support.io.ResumeFailedException;

/**
 * Insert a USK. The algorithm is simply to do a thorough search for the latest edition, and insert at the
 * following slot. Thereafter, if we get a collision, increment our slot; if we get more than 5 consecutive
 * collisions, search for the latest slot again.
 */
public class USKInserter implements ClientPutState, USKFetcherCallback, PutCompletionCallback, Serializable {

    private static final long serialVersionUID = 1L;
    private static volatile boolean logMINOR;
	
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
	// Stuff to be passed on to the SingleBlockInserter
	final BaseClientPutter parent;
	Bucket data;
	final short compressionCodec;
	final InsertContext ctx;
	final PutCompletionCallback cb;
	final boolean isMetadata;
	final int sourceLength;
	final int token;
	public final Object tokenObject;
	final boolean persistent;
	final boolean realTimeFlag;
	
	final InsertableUSK privUSK;
	final USK pubUSK;
	/** Scanning for latest slot */
	private USKFetcherTag fetcher;
	/** Insert the actual SSK */
	private SingleBlockInserter sbi;
	private long edition;
	/** Number of collisions while trying to insert so far */
	private int consecutiveCollisions;
	private boolean finished;
	/** After attempting inserts on this many slots, go back to the Fetcher */
	private static final long MAX_TRIED_SLOTS = 10;
	private boolean freeData;
	final int hashCode;
	private final int extraInserts;
	final byte cryptoAlgorithm;
	final byte[] forceCryptoKey;
	
	@Override
	public void schedule(ClientContext context) throws InsertException {
		// Caller calls schedule()
		// schedule() calls scheduleFetcher()
		// scheduleFetcher() creates a Fetcher (set up to tell us about author-errors as well as valid inserts)
		// (and starts it)
		// when this completes, onFoundEdition() calls scheduleInsert()
		// scheduleInsert() starts a SingleBlockInserter
		// if that succeeds, we complete
		// if that fails, we increment our index and try again (in the callback)
		// if that continues to fail 5 times, we go back to scheduleFetcher()
		scheduleFetcher(context);
	}

	/**
	 * Schedule a Fetcher to find us the latest inserted key of the USK.
	 * The Fetcher must be insert-mode, in other words, it must know that we want the latest edition,
	 * including author errors and so on.
	 */
	private void scheduleFetcher(ClientContext context) {
		synchronized(this) {
			if(logMINOR)
				Logger.minor(this, "scheduling fetcher for "+pubUSK.getURI());
			if(finished) return;
			fetcher = context.uskManager.getFetcherForInsertDontSchedule(persistent ? pubUSK.copy() : pubUSK, this, parent.getClient(), persistent, ctx.ignoreUSKDatehints);
			if(logMINOR)
				Logger.minor(this, "scheduled: "+fetcher);
		}
		fetcher.schedule(context);
	}

	@Override
	public void onFoundEdition(long l, USK key, ClientContext context, boolean lastContentWasMetadata, short codec, byte[] hisData, boolean newKnownGood, boolean newSlotToo) {
		boolean alreadyInserted = false;
		synchronized(this) {
			edition = Math.max(l, edition);
			consecutiveCollisions = 0;
			if((lastContentWasMetadata == isMetadata) && hisData != null
					&& (codec == compressionCodec)) {
				try {
					byte[] myData = BucketTools.toByteArray(data);
					if(Arrays.equals(myData, hisData)) {
						// Success
						alreadyInserted = true;
						finished = true;
						sbi = null;
					}
				} catch (IOException e) {
					Logger.error(this, "Could not decode: "+e, e);
				}
			}
			if(persistent) {
				fetcher = null;
			}
		}
		if(alreadyInserted) {
			// Success!
			parent.completedBlock(true, context);
			cb.onEncode(pubUSK.copy(edition), this, context);
			insertSucceeded(context, l);
			if(freeData) {
				data.free();
			}
		} else {
			scheduleInsert(context);
		}
	}

	private void insertSucceeded(ClientContext context, long edition) {
		if(ctx.ignoreUSKDatehints) {
			if(logMINOR) Logger.minor(this, "Inserted to edition "+edition);
			cb.onSuccess(this, context);
			return;
		}
		if(logMINOR) Logger.minor(this, "Inserted to edition "+edition+" - inserting USK date hints...");
		USKDateHint hint = USKDateHint.now();
		MultiPutCompletionCallback m = new MultiPutCompletionCallback(cb, parent, tokenObject, persistent, true);
		byte[] hintData;
		try {
			hintData = hint.getData(edition).getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new Error(e); // Impossible
		}
		FreenetURI[] hintURIs = hint.getInsertURIs(privUSK);
		boolean added = false;
		for(FreenetURI uri : hintURIs) {
			try {
				Bucket bucket = BucketTools.makeImmutableBucket(context.getBucketFactory(persistent), hintData);
				SingleBlockInserter sb = 
					new SingleBlockInserter(parent, bucket, (short) -1, uri,
							ctx, realTimeFlag, m, false, sourceLength, token, true, true /* we don't use it */, null, context, persistent, true, extraInserts, cryptoAlgorithm, forceCryptoKey);
				Logger.normal(this, "Inserting "+uri+" with "+sb+" for insert of "+pubUSK);
				m.add(sb);
				sb.schedule(context);
				added = true;
			} catch (IOException e) {
				Logger.error(this, "Unable to insert USK date hints due to disk I/O error: "+e, e);
				if(!added) {
					cb.onFailure(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, pubUSK.getSSK(edition).getURI()), this, context);
					return;
				} // Else try to insert the other hints.
			} catch (InsertException e) {
				Logger.error(this, "Unable to insert USK date hints due to error: "+e, e);
				if(!added) {
					cb.onFailure(e, this, context);
					return;
				} // Else try to insert the other hints.
			}
		}
		cb.onTransition(this, m, context);
		m.arm(context);
	}

	private void scheduleInsert(ClientContext context) {
		long edNo = Math.max(edition, context.uskManager.lookupLatestSlot(pubUSK)+1);
		synchronized(this) {
			if(finished) return;
			edition = edNo;
			if(logMINOR)
				Logger.minor(this, "scheduling insert for "+pubUSK.getURI()+ ' ' +edition);
			sbi = new SingleBlockInserter(parent, data, compressionCodec, privUSK.getInsertableSSK(edition).getInsertURI(),
					ctx, realTimeFlag, this, isMetadata, sourceLength, token, false, true /* we don't use it */, tokenObject, context, persistent, false, extraInserts, cryptoAlgorithm, forceCryptoKey);
		}
		try {
			sbi.schedule(context);
		} catch (InsertException e) {
			synchronized(this) {
				finished = true;
			}
			if(freeData) {
				data.free();
				synchronized(this) {
					data = null;
				}
			}
			cb.onFailure(e, this, context);
		}
	}

	@Override
	public synchronized void onSuccess(ClientPutState state, ClientContext context) {
		USK newEdition = pubUSK.copy(edition);
		finished = true;
		sbi = null;
		FreenetURI targetURI = pubUSK.getSSK(edition).getURI();
		FreenetURI realURI = ((SingleBlockInserter)state).getURI(context);
		if(!targetURI.equals(realURI))
			Logger.error(this, "URI should be "+targetURI+" actually is "+realURI);
		else {
			if(logMINOR)
				Logger.minor(this, "URI should be "+targetURI+" actually is "+realURI);
			context.uskManager.updateKnownGood(pubUSK, edition, context);
		}
		if(freeData) {
			data.free();
			data = null;
		}
		cb.onEncode(newEdition, this, context);
		insertSucceeded(context, edition);
		// FINISHED!!!! Yay!!!
	}

	@Override
	public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
		synchronized(this) {
			sbi = null;
			if(e.getMode() == InsertExceptionMode.COLLISION) {
				// Try the next slot
				edition++;
				consecutiveCollisions++;
				if(consecutiveCollisions > MAX_TRIED_SLOTS)
					scheduleFetcher(context);
				else
					scheduleInsert(context);
			} else {
				Bucket d = null;
				synchronized(this) {
					finished = true;
					if(freeData) {
						d = data;
						data = null;
					}
				}
				if(freeData) {
					d.free();
				}
				cb.onFailure(e, state, context);
			}
		}
	}

	@Override
	public int hashCode() {
		return hashCode;
	}
	
	public USKInserter(BaseClientPutter parent, Bucket data, short compressionCodec, FreenetURI uri, 
			InsertContext ctx, PutCompletionCallback cb, boolean isMetadata, int sourceLength, int token, 
			boolean addToParent, Object tokenObject, ClientContext context, boolean freeData, boolean persistent, boolean realTimeFlag, int extraInserts, byte cryptoAlgorithm, byte[] forceCryptoKey) throws MalformedURLException {
		this.hashCode = super.hashCode();
		this.tokenObject = tokenObject;
		this.persistent = persistent;
		this.parent = parent;
		this.data = data;
		this.compressionCodec = compressionCodec;
		this.ctx = ctx;
		this.cb = cb;
		this.isMetadata = isMetadata;
		this.sourceLength = sourceLength;
		this.token = token;
		if(addToParent) {
			parent.addMustSucceedBlocks(1);
			parent.notifyClients(context);
		}
		privUSK = InsertableUSK.createInsertable(uri);
		pubUSK = privUSK.getUSK();
		edition = pubUSK.suggestedEdition;
		this.freeData = freeData;
		this.extraInserts = extraInserts;
		this.cryptoAlgorithm = cryptoAlgorithm;
		this.forceCryptoKey = forceCryptoKey;
		this.realTimeFlag = realTimeFlag;
	}
	
	protected USKInserter() {
	    // For serialization.
	    this.hashCode = 0;
	    this.tokenObject = null;
	    this.persistent = false;
	    this.parent = null;
	    this.data = null;
	    this.compressionCodec = 0;
	    this.ctx = null;
	    this.cb = null;
	    this.isMetadata = false;
	    this.sourceLength = 0;
	    this.token = 0;
	    this.privUSK = null;
	    this.pubUSK = null;
	    this.edition = 0;
	    this.freeData = false;
	    this.extraInserts = 0;
	    this.cryptoAlgorithm = 0;
	    this.forceCryptoKey = null;
	    this.realTimeFlag = false;
	}

	@Override
	public BaseClientPutter getParent() {
		return parent;
	}

	@Override
	public void cancel(ClientContext context) {
		USKFetcherTag tag;
		synchronized(this) {
			if(finished) return;
			finished = true;
			tag = fetcher;
			fetcher = null;
		}
		if(tag != null) {
			tag.cancel(context);
		}
		if(sbi != null) {
			sbi.cancel(context); // will call onFailure, which will removeFrom()
		}
		if(freeData) {
			if(data == null) {
				Logger.error(this, "data == null in cancel() on "+this, new Exception("error"));
			} else {
				data.free();
				synchronized(this) {
					data = null;
				}
			}
		}
		cb.onFailure(new InsertException(InsertExceptionMode.CANCELLED), this, context);
	}

	@Override
	public void onFailure(ClientContext context) {
		if(logMINOR) Logger.minor(this, "Fetcher failed to find the given edition or any later edition on "+this);
		scheduleInsert(context);
	}

	@Override
	public void onCancelled(ClientContext context) {
		synchronized(this) {
		    fetcher = null;
			if(finished) return;
		}
		Logger.error(this, "Unexpected onCancelled()", new Exception("error"));
		cancel(context);
	}

	@Override
	public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
		// Ignore
	}

	@Override
	public void onTransition(ClientPutState oldState, ClientPutState newState, ClientContext context) {
		// Shouldn't happen
		Logger.error(this, "Got onTransition("+oldState+ ',' +newState+ ')');
	}

	@Override
	public void onMetadata(Metadata m, ClientPutState state, ClientContext context) {
		// Shouldn't happen
		Logger.error(this, "Got onMetadata("+m+ ',' +state+ ')');
	}

	@Override
	public void onBlockSetFinished(ClientPutState state, ClientContext context) {
		// Ignore
	}

	@Override
	public Object getToken() {
		return tokenObject;
	}

	@Override
	public void onFetchable(ClientPutState state) {
		// Ignore
	}

	@Override
	public short getPollingPriorityNormal() {
		return parent.getPriorityClass();
	}

	@Override
	public short getPollingPriorityProgress() {
		return parent.getPriorityClass();
	}

	@Override
	public void onMetadata(Bucket meta, ClientPutState state, ClientContext context) {
		Logger.error(this, "onMetadata on "+this+" from "+state, new Exception("error"));
		meta.free();
	}
	
	private transient boolean resumed = false;

    @Override
    public void onResume(ClientContext context) throws InsertException, ResumeFailedException {
        if(resumed) return;
        resumed = true;
        if(data != null) data.onResume(context);
        if(cb != null && cb != parent) cb.onResume(context);
        if(fetcher != null) fetcher.onResume(context);
        if(sbi != null) sbi.onResume(context);
    }

    @Override
    public void onShutdown(ClientContext context) {
        SingleBlockInserter sbi;
        synchronized(this) {
            sbi = this.sbi;
        }
        if(sbi != null) sbi.onShutdown(context);
    }

}
