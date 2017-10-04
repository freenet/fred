package freenet.client;

import java.io.Serializable;

import freenet.client.ArchiveManager.ARCHIVE_TYPE;
import freenet.client.async.ClientContext;
import freenet.keys.FreenetURI;
import freenet.support.Logger;
import freenet.support.api.Bucket;
import freenet.support.compress.Compressor.COMPRESSOR_TYPE;

class ArchiveHandlerImpl implements ArchiveHandler, Serializable {

    private static final long serialVersionUID = 1L;
    private static volatile boolean logMINOR;

	static {
		Logger.registerClass(ArchiveHandlerImpl.class);
	}

	private final FreenetURI key;
	private boolean forceRefetchArchive;
	ARCHIVE_TYPE archiveType;
	COMPRESSOR_TYPE compressorType;

	ArchiveHandlerImpl(FreenetURI key, ARCHIVE_TYPE archiveType, COMPRESSOR_TYPE ctype, boolean forceRefetchArchive) {
		this.key = key;
		this.archiveType = archiveType;
		this.compressorType = ctype;
		this.forceRefetchArchive = forceRefetchArchive;
	}

	@Override
	public Bucket get(String internalName, ArchiveManager manager)
			throws ArchiveFailureException, ArchiveRestartException,
			MetadataParseException, FetchException {

		if(forceRefetchArchive) return null;

		Bucket data;

		// Fetch from cache
		if(logMINOR)
			Logger.minor(this, "Checking cache: "+key+ ' ' +internalName);
		if((data = manager.getCached(key, internalName)) != null) {
			return data;
		}

		return null;
	}

	@Override
	public Bucket getMetadata(ArchiveManager manager) throws ArchiveFailureException,
			ArchiveRestartException, MetadataParseException, FetchException {
		return get(".metadata", manager);
	}

	@Override
	public void extractToCache(Bucket bucket, ArchiveContext actx,
			String element, ArchiveExtractCallback callback,
			ArchiveManager manager, ClientContext context) throws ArchiveFailureException,
			ArchiveRestartException {
		forceRefetchArchive = false; // now we don't need to force refetch any more
		ArchiveStoreContext ctx = manager.makeContext(key, archiveType, false);
		manager.extractToCache(key, archiveType, compressorType, bucket, actx, ctx, element, callback, context);
	}

	@Override
	public ARCHIVE_TYPE getArchiveType() {
		return archiveType;
	}

	public COMPRESSOR_TYPE getCompressorType() {
		return compressorType;
	}

	@Override
	public FreenetURI getKey() {
		return key;
	}

	@Override
	public ArchiveHandler cloneHandler() {
		return new ArchiveHandlerImpl(key, archiveType, compressorType, forceRefetchArchive);
	}

}
