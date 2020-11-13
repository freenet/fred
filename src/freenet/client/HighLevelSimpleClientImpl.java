/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client;

import java.io.IOException;
import java.util.HashMap;
import java.util.Set;

import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.Metadata.DocumentType;
import freenet.client.async.BaseManifestPutter;
import freenet.client.async.ClientGetCallback;
import freenet.client.async.ClientGetter;
import freenet.client.async.ClientPutCallback;
import freenet.client.async.ClientPutter;
import freenet.client.async.DefaultManifestPutter;
import freenet.client.async.PersistenceDisabledException;
import freenet.client.async.TooManyFilesInsertException;
import freenet.client.events.ClientEventListener;
import freenet.client.events.ClientEventProducer;
import freenet.client.events.EventLogger;
import freenet.client.events.SimpleEventProducer;
import freenet.crypt.RandomSource;
import freenet.keys.FreenetURI;
import freenet.keys.InsertableClientSSK;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.RequestClient;
import freenet.node.RequestScheduler;
import freenet.node.RequestStarter;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.api.RandomAccessBucket;
import freenet.support.compress.Compressor;
import freenet.support.io.NullBucket;
import freenet.support.io.PersistentFileTracker;

public class HighLevelSimpleClientImpl implements HighLevelSimpleClient, RequestClient, Cloneable {

	private final short priorityClass;
	private final BucketFactory bucketFactory;
	private final BucketFactory persistentBucketFactory;
	private final PersistentFileTracker persistentFileTracker;
	private final NodeClientCore core;
	/** One CEP for all requests and inserts */
	private final ClientEventProducer eventProducer;
	private long curMaxLength;
	private long curMaxTempLength;
	private int curMaxMetadataLength;
	private final RandomSource random;
	private final boolean realTimeFlag;
	static final int MAX_RECURSION = 10;
	static final int MAX_ARCHIVE_RESTARTS = 2;
	static final int MAX_ARCHIVE_LEVELS = 10;
	static final boolean DONT_ENTER_IMPLICIT_ARCHIVES = true;
	// COOLDOWN_RETRIES-1 so we don't have to wait on the cooldown queue; HLSC is designed
	// for interactive requests mostly.
	/** Number of retries allowed per block in a splitfile. */
	static final int SPLITFILE_BLOCK_RETRIES = Math.min(3, RequestScheduler.COOLDOWN_RETRIES-1);
	/** Number of retries allowed on non-splitfile fetches. */
	static final int NON_SPLITFILE_RETRIES = Math.min(3, RequestScheduler.COOLDOWN_RETRIES-1);
	static final int USK_RETRIES = RequestScheduler.COOLDOWN_RETRIES - 1;
	/** Whether to fetch splitfiles. Don't turn this off! */
	static final boolean FETCH_SPLITFILES = true;
	/** Whether to follow redirects etc. If false, we only fetch a plain block of data.
	 * Don't turn this off either! */
	static final boolean FOLLOW_REDIRECTS = true;
	/** If set, only check the local datastore, don't send an actual request out.
	 * Don't turn this off either. */
	static final boolean LOCAL_REQUESTS_ONLY = false;
	/** By default, write to the client cache. Turn this off if you are fetching big stuff. */
	static final boolean CAN_WRITE_CLIENT_CACHE = true;
	/** By default, don't write local inserts to the client cache. */
	static final boolean CAN_WRITE_CLIENT_CACHE_INSERTS = false;
	/** Number of retries on inserts */
	static final int INSERT_RETRIES = 10;
	/** Number of RNFs on insert that make a success, or -1 on large networks */
	static final int CONSECUTIVE_RNFS_ASSUME_SUCCESS = 2;
	// going by memory usage only; 4kB per stripe
	static final int MAX_SPLITFILE_BLOCKS_PER_SEGMENT = 256;
	static final int MAX_SPLITFILE_CHECK_BLOCKS_PER_SEGMENT = 256;
	// For scaling purposes, 128 data 128 check blocks i.e. one check block per data block.
	public static final int SPLITFILE_SCALING_BLOCKS_PER_SEGMENT = 128;
	/* The number of data blocks in a segment depends on how many segments there are.
	 * FECCodec.standardOnionCheckBlocks will automatically reduce check blocks to compensate for more than half data blocks. */
	public static final int SPLITFILE_BLOCKS_PER_SEGMENT = 136;
	public static final int SPLITFILE_CHECK_BLOCKS_PER_SEGMENT = 128;
	public static final int EXTRA_INSERTS_SINGLE_BLOCK = 2;
	public static final int EXTRA_INSERTS_SPLITFILE_HEADER = 2;
	/*Whether or not to filter fetched content*/
	static final boolean FILTER_DATA = false;

	public HighLevelSimpleClientImpl(NodeClientCore node, BucketFactory bf, RandomSource r, short priorityClass, boolean forceDontIgnoreTooManyPathComponents, boolean realTimeFlag) {
		this.core = node;
		this.priorityClass = priorityClass;
		bucketFactory = bf;
		this.persistentFileTracker = node.persistentTempBucketFactory;
		random = r;
		this.eventProducer = new SimpleEventProducer();
		eventProducer.addEventListener(new EventLogger(LogLevel.MINOR, false));
		curMaxLength = Long.MAX_VALUE;
		curMaxTempLength = Long.MAX_VALUE;
		curMaxMetadataLength = 1024 * 1024;
		this.persistentBucketFactory = node.persistentTempBucketFactory;
		this.realTimeFlag = realTimeFlag;
	}

	public HighLevelSimpleClientImpl(HighLevelSimpleClientImpl hlsc) {
		this.eventProducer = new SimpleEventProducer();
		this.priorityClass = hlsc.priorityClass;
		this.bucketFactory = hlsc.bucketFactory;
		this.persistentBucketFactory = hlsc.persistentBucketFactory;
		this.persistentFileTracker = hlsc.persistentFileTracker;
		this.core = hlsc.core;
		this.curMaxLength = hlsc.curMaxLength;
		this.curMaxMetadataLength = hlsc.curMaxMetadataLength;
		this.curMaxTempLength = hlsc.curMaxTempLength;
		this.random = hlsc.random;
		this.realTimeFlag = hlsc.realTimeFlag;
	}

	@Override
	public HighLevelSimpleClientImpl clone() {
		// Cloneable shuts up findbugs, but we need a new SimpleEventProducer().
		return new HighLevelSimpleClientImpl(this);
	}

	@Override
	public void setMaxLength(long maxLength) {
		curMaxLength = maxLength;
	}

	@Override
	public void setMaxIntermediateLength(long maxIntermediateLength) {
		curMaxTempLength = maxIntermediateLength;
	}

	/**
	 * Fetch a key. Either returns the data, or throws an exception.
	 */
	@Override
	public FetchResult fetch(FreenetURI uri) throws FetchException {
		if(uri == null) throw new NullPointerException();
		FetchContext context = getFetchContext();
		FetchWaiter fw = new FetchWaiter(this);
		ClientGetter get = new ClientGetter(fw, uri, context, priorityClass, null, null, null);
		try {
			core.clientContext.start(get);
		} catch (PersistenceDisabledException e) {
			// Impossible
		}
		return fw.waitForCompletion();
	}

	/**
	 * Fetch a key. Either returns the data, or throws an exception.
	 */
	@Override
	public FetchResult fetchFromMetadata(Bucket initialMetadata) throws FetchException {
		if(initialMetadata == null) throw new NullPointerException();
		FetchContext context = getFetchContext();
		FetchWaiter fw = new FetchWaiter(this);
		ClientGetter get = new ClientGetter(fw, FreenetURI.EMPTY_CHK_URI, context, priorityClass, null, null, initialMetadata);
		try {
			core.clientContext.start(get);
		} catch (PersistenceDisabledException e) {
			// Impossible
		}
		return fw.waitForCompletion();
	}

	@Override
	public FetchResult fetch(FreenetURI uri, long overrideMaxSize) throws FetchException {
		return fetch(uri, overrideMaxSize, this);
	}

	@Override
	public FetchResult fetch(FreenetURI uri, long overrideMaxSize, RequestClient clientContext) throws FetchException {
		if(uri == null) throw new NullPointerException();
		FetchWaiter fw = new FetchWaiter(clientContext);
		FetchContext context = getFetchContext(overrideMaxSize);
		ClientGetter get = new ClientGetter(fw, uri, context, priorityClass, null, null, null);
		try {
			core.clientContext.start(get);
		} catch (PersistenceDisabledException e) {
			// Impossible
		}
		return fw.waitForCompletion();
	}

	@Override
	public ClientGetter fetch(FreenetURI uri, long maxSize, ClientGetCallback callback, FetchContext fctx) throws FetchException {
		return fetch(uri, maxSize, callback, fctx, priorityClass);
	}

	@Override
	public ClientGetter fetch(FreenetURI uri, long maxSize, ClientGetCallback callback, FetchContext fctx, short prio) throws FetchException {
		return fetch(uri, callback, fctx, prio);
	}

	@Override
	public ClientGetter fetch(FreenetURI uri, ClientGetCallback callback, FetchContext fctx, short prio) throws FetchException {
		if(uri == null) throw new NullPointerException();
		ClientGetter get = new ClientGetter(callback, uri, fctx, prio, null, null, null);
		try {
			core.clientContext.start(get);
		} catch (PersistenceDisabledException e) {
			// Impossible
		}
		return get;
	}

	@Override
	public ClientGetter fetchFromMetadata(Bucket initialMetadata, ClientGetCallback callback, FetchContext fctx, short prio) throws FetchException {
		if(initialMetadata == null) throw new NullPointerException();
		ClientGetter get = new ClientGetter(callback, FreenetURI.EMPTY_CHK_URI, fctx, prio, null, null, initialMetadata);
		try {
			core.clientContext.start(get);
		} catch (PersistenceDisabledException e) {
			// Impossible
		}
		return get;
	}

	@Override
	public FreenetURI insert(InsertBlock insert, boolean getCHKOnly, String filenameHint) throws InsertException {
		return insert(insert, getCHKOnly, filenameHint, priorityClass);
	}

	@Override
	public FreenetURI insert(InsertBlock insert, boolean getCHKOnly, String filenameHint, short priority) throws InsertException {
		return insert(insert, getCHKOnly, filenameHint, false, priority);
	}

	public FreenetURI insert(InsertBlock insert, boolean getCHKOnly, String filenameHint, boolean isMetadata, short priority) throws InsertException {
		InsertContext context = getInsertContext(true);
		context.getCHKOnly = getCHKOnly;
		return insert(insert, filenameHint, isMetadata, priority, context);
	}

	@Override
	public FreenetURI insert(InsertBlock insert, String filenameHint, short priority, InsertContext ctx) throws InsertException {
		return insert(insert, filenameHint, false, priority, ctx);
	}

	public FreenetURI insert(InsertBlock insert, String filenameHint, boolean isMetadata, short priority, InsertContext ctx) throws InsertException {
		return insert(insert, filenameHint, isMetadata, priority, ctx, null);
	}

	public FreenetURI insert(InsertBlock insert, String filenameHint, boolean isMetadata, short priority, InsertContext ctx, byte[] forceCryptoKey) throws InsertException {
		PutWaiter pw = new PutWaiter(this);
		ClientPutter put = new ClientPutter(pw, insert.getData(), insert.desiredURI, insert.clientMetadata,
				ctx, priority,
				isMetadata, filenameHint, false, core.clientContext, forceCryptoKey, -1);
		try {
			core.clientContext.start(put);
		} catch (PersistenceDisabledException e) {
			// Impossible
		}
		return pw.waitForCompletion();
	}

	@Override
	public ClientPutter insert(InsertBlock insert, String filenameHint, boolean isMetadata, InsertContext ctx, ClientPutCallback cb) throws InsertException {
		return insert(insert, filenameHint, isMetadata, ctx, cb, priorityClass);
	}

	@Override
	public ClientPutter insert(InsertBlock insert, String filenameHint, boolean isMetadata, InsertContext ctx, ClientPutCallback cb, short priority) throws InsertException {
		ClientPutter put = new ClientPutter(cb, insert.getData(), insert.desiredURI, insert.clientMetadata,
				ctx, priority,
				isMetadata, filenameHint, false, core.clientContext, null, -1);
		try {
			core.clientContext.start(put);
		} catch (PersistenceDisabledException e) {
			// Impossible
		}
		return put;
	}

	@Override
	public FreenetURI insertRedirect(FreenetURI insertURI, FreenetURI targetURI) throws InsertException {
		Metadata m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, targetURI, new ClientMetadata());
		RandomAccessBucket b;
		try {
			b = m.toBucket(bucketFactory);
		} catch (IOException e) {
			Logger.error(this, "Bucket error: "+e, e);
			throw new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null);
		} catch (MetadataUnresolvedException e) {
			Logger.error(this, "Impossible error: "+e, e);
			throw new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null);
		}

		InsertBlock block = new InsertBlock(b, null, insertURI);
		FreenetURI uri = insert(block, false, null, true, priorityClass);
		block.free();
		return uri;
	}

	@Override
	public FreenetURI insertManifest(FreenetURI insertURI, HashMap<String, Object> bucketsByName, String defaultName) throws InsertException {
		return insertManifest(insertURI, bucketsByName, defaultName, priorityClass);
	}

	@Override
	public FreenetURI insertManifest(FreenetURI insertURI, HashMap<String, Object> bucketsByName, String defaultName, short priorityClass) throws InsertException {
		return insertManifest(insertURI, bucketsByName, defaultName, priorityClass, null);
	}

	@Override
	public FreenetURI insertManifest(FreenetURI insertURI, HashMap<String, Object> bucketsByName, String defaultName, short priorityClass, byte[] forceCryptoKey) throws InsertException {
		PutWaiter pw = new PutWaiter(this);
		DefaultManifestPutter putter;
        try {
            putter = new DefaultManifestPutter(pw, BaseManifestPutter.bucketsByNameToManifestEntries(bucketsByName), priorityClass, insertURI, defaultName, getInsertContext(true), false, forceCryptoKey, core.clientContext);
        } catch (TooManyFilesInsertException e1) {
            throw new InsertException(InsertExceptionMode.TOO_MANY_FILES);
        }
		try {
			core.clientContext.start(putter);
		} catch (PersistenceDisabledException e) {
			// Impossible
		}
		return pw.waitForCompletion();
	}

	@Override
	public void addEventHook(ClientEventListener listener) {
		eventProducer.addEventListener(listener);
	}

	@Override
	public FetchContext getFetchContext() {
		return getFetchContext(-1);
	}

	@Override
	public FetchContext getFetchContext(long overrideMaxSize) {
		return getFetchContext(-1, null);
	}

	@Override
	public FetchContext getFetchContext(long overrideMaxSize, String schemeHostAndPort) {
		long maxLength = curMaxLength;
		long maxTempLength = curMaxTempLength;
		if(overrideMaxSize >= 0) {
			maxLength = overrideMaxSize;
			maxTempLength = overrideMaxSize;
		}
		return
			new FetchContext(maxLength, maxTempLength, curMaxMetadataLength,
				MAX_RECURSION, MAX_ARCHIVE_RESTARTS, MAX_ARCHIVE_LEVELS, DONT_ENTER_IMPLICIT_ARCHIVES,
				SPLITFILE_BLOCK_RETRIES, NON_SPLITFILE_RETRIES, USK_RETRIES,
				FETCH_SPLITFILES, FOLLOW_REDIRECTS, LOCAL_REQUESTS_ONLY,
				FILTER_DATA, MAX_SPLITFILE_BLOCKS_PER_SEGMENT, MAX_SPLITFILE_CHECK_BLOCKS_PER_SEGMENT,
				bucketFactory, eventProducer,
				false, CAN_WRITE_CLIENT_CACHE, null, null, schemeHostAndPort);
	}

	public static FetchContext makeDefaultFetchContext(long maxLength, long maxTempLength,
	        BucketFactory bucketFactory, SimpleEventProducer eventProducer) {
        return
        new FetchContext(maxLength, maxTempLength, 1024*1024,
            MAX_RECURSION, MAX_ARCHIVE_RESTARTS, MAX_ARCHIVE_LEVELS, DONT_ENTER_IMPLICIT_ARCHIVES,
            SPLITFILE_BLOCK_RETRIES, NON_SPLITFILE_RETRIES, USK_RETRIES,
            FETCH_SPLITFILES, FOLLOW_REDIRECTS, LOCAL_REQUESTS_ONLY,
            FILTER_DATA, MAX_SPLITFILE_BLOCKS_PER_SEGMENT, MAX_SPLITFILE_CHECK_BLOCKS_PER_SEGMENT,
            bucketFactory, eventProducer,
            false, CAN_WRITE_CLIENT_CACHE, null, null, null);
	}

	@Override
	public InsertContext getInsertContext(boolean forceNonPersistent) {
		return new InsertContext(
				INSERT_RETRIES, CONSECUTIVE_RNFS_ASSUME_SUCCESS,
				SPLITFILE_BLOCKS_PER_SEGMENT, SPLITFILE_CHECK_BLOCKS_PER_SEGMENT,
				eventProducer, CAN_WRITE_CLIENT_CACHE_INSERTS, Node.FORK_ON_CACHEABLE_DEFAULT, false,
				Compressor.DEFAULT_COMPRESSORDESCRIPTOR, EXTRA_INSERTS_SINGLE_BLOCK,
				EXTRA_INSERTS_SPLITFILE_HEADER, InsertContext.CompatibilityMode.COMPAT_DEFAULT);
	}

    public static InsertContext makeDefaultInsertContext(BucketFactory bucketFactory,
            SimpleEventProducer eventProducer) {
        return new InsertContext(
                INSERT_RETRIES, CONSECUTIVE_RNFS_ASSUME_SUCCESS,
                SPLITFILE_BLOCKS_PER_SEGMENT, SPLITFILE_CHECK_BLOCKS_PER_SEGMENT,
                eventProducer, CAN_WRITE_CLIENT_CACHE_INSERTS, Node.FORK_ON_CACHEABLE_DEFAULT, false,
                Compressor.DEFAULT_COMPRESSORDESCRIPTOR, EXTRA_INSERTS_SINGLE_BLOCK,
                EXTRA_INSERTS_SPLITFILE_HEADER, InsertContext.CompatibilityMode.COMPAT_DEFAULT);
    }

	@Override
	public FreenetURI[] generateKeyPair(String docName) {
		InsertableClientSSK key = InsertableClientSSK.createRandom(random, docName);
		return new FreenetURI[] { key.getInsertURI(), key.getURI() };
	}

	private final ClientGetCallback nullCallback = new NullClientCallback(this);

	@Override
	public void prefetch(FreenetURI uri, long timeout, long maxSize, Set<String> allowedTypes) {
		prefetch(uri, timeout, maxSize, allowedTypes, RequestStarter.PREFETCH_PRIORITY_CLASS);
	}

	@Override
	public void prefetch(FreenetURI uri, long timeout, long maxSize, Set<String> allowedTypes, short prio) {
		FetchContext ctx = getFetchContext(maxSize);
		ctx.allowedMIMETypes = allowedTypes;
		final ClientGetter get = new ClientGetter(nullCallback, uri, ctx, prio, new NullBucket(), null, null);
		core.getTicker().queueTimedJob(new Runnable() {
			@Override
			public void run() {
				get.cancel(core.clientContext);
			}

		}, timeout);
		try {
			core.clientContext.start(get);
		} catch (FetchException e) {
			// Ignore
		} catch (PersistenceDisabledException e) {
			// Impossible
		}
	}

	@Override
	public boolean persistent() {
		return false;
	}

	@Override
	public boolean realTimeFlag() {
		return realTimeFlag;
	}

}
