/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import freenet.client.async.BlockSet;
import freenet.client.events.ClientEventProducer;
import freenet.client.events.SimpleEventProducer;
import freenet.client.filter.FoundURICallback;
import freenet.client.filter.TagReplacerCallback;
import freenet.node.RequestScheduler;
import freenet.support.api.BucketFactory;
import freenet.support.io.StorageFormatException;

/** Context for a Fetcher. Contains all the settings a Fetcher needs to know
 * about. FIXME these should be final or private, with getters/setters and
 * checking for valid values e.g. maxRecursionLevel >= 1. */
public class FetchContext implements Cloneable, Serializable {

    private static final long serialVersionUID = 1L;
    public static final int IDENTICAL_MASK = 0;
	public static final int SPLITFILE_DEFAULT_BLOCK_MASK = 1;
	public static final int SPLITFILE_DEFAULT_MASK = 2;
	public static final int SET_RETURN_ARCHIVES = 4;
	/** Maximum length of the final returned data */
	public long maxOutputLength;
	/** Maximum length of data fetched in order to obtain the final data - metadata, containers, etc. */
	public long maxTempLength;
	/** 1 = only fetch a single block. 2 = allow one redirect, e.g. metadata
	 * block pointing to actual data block. Etc. 0 may work sometimes but
	 * is not recommended. */
	public int maxRecursionLevel;
	public int maxArchiveRestarts;
	/** Maximum number of manifest lookups during a request. A manifest lookup is looking up a part
	 * of a pathname in a "manifest", which is essentially a directory (folder). Usually manifest
	 * lookups are inside containers (archives), which are usually tar files, which may or may not
	 * be compressed (compression occurs transparently on a different level). This is not
	 * necessarily the same as the number of slashes in the key after the part for the key itself,
	 * since keys can redirect to other keys. If you are fetching user-uploaded keys, e.g. in
	 * fproxy, especially freesites, you will want this to be non-zero. However if you are using
	 * keys only internally, and never upload freesites, you should set this to 0.
	 * @see ArchiveContext where this is enforced. */
	public int maxArchiveLevels;
	public boolean dontEnterImplicitArchives;
	/** Maximum number of retries (after the original attempt) for a
	 * splitfile block. -1 = try forever or until success or a fatal error.
	 * A fatal error is either an internal error (problem with the node) or
	 * something resulting from the original data being corrupt as inserted.
	 * So with retries = -1 we will not report Data not found, Route not
	 * found, All data not found, etc, because these are nonfatal errors and
	 * we will retry. Note that after every 3 attempts the request is put
	 * on the cooldown queue for 30 minutes, so the cost of retries = -1 is
	 * really not that high. */
	public int maxSplitfileBlockRetries;
	/** Maximum number of retries (after the original attempt) for a
	 * non-splitfile block. -1 = try forever or until success or a fatal
	 * error.. -1 = try forever or until success or a fatal error.
	 * A fatal error is either an internal error (problem with the node) or
	 * something resulting from the original data being corrupt as inserted.
	 * So with retries = -1 we will not report Data not found, Route not
	 * found, All data not found, etc, because these are nonfatal errors and
	 * we will retry. Note that after every 3 attempts the request is put
	 * on the cooldown queue for 30 minutes, so the cost of retries = -1 is
	 * really not that high. */
	public int maxNonSplitfileRetries;
	public final int maxUSKRetries;
	/** Whether to download splitfiles */
	public boolean allowSplitfiles;
	/** Whether to follow simple redirects */
	public boolean followRedirects;
	/** If true, only read from the datastore and caches, do not send the request to the network */
	public boolean localRequestOnly;
	/** If true, send the request to the network without checking whether the data is in the local store */
	public boolean ignoreStore;
	/** Client events will be published to this, you can subscribe to them */
	public final ClientEventProducer eventProducer;
	public int maxMetadataSize;
	/** Maximum number of data blocks per segment for splitfiles */
	public int maxDataBlocksPerSegment;
	/** Maximum number of check blocks per segment for splitfiles. */
	public int maxCheckBlocksPerSegment;
	/** If true, and we get a ZIP manifest, and we have no meta-strings left, then
	 * return the manifest contents as data. */
	public boolean returnZIPManifests;
	/*If true, filter the fetched data*/
	public boolean filterData;
	public final boolean ignoreTooManyPathComponents;
	/** If set, contains a set of blocks to be consulted before checking the datastore. */
	public final BlockSet blocks;
	/** If non-null, the request will be stopped if it has a MIME type that is not one of these,
	 * or has no MIME type. */
	public Set<String> allowedMIMETypes;
	/** If not-null, the request, if it requires a charset for filtration, will be assumed
	 * to use this charset */
	public String charset;
	/** Do we have responsibility for removing the ClientEventProducer from the database? */
	private final boolean hasOwnEventProducer;
	/** Can this request write to the client-cache? We don't store all requests in the client cache,
	 * in particular big stuff usually isn't written to it, to maximise its effectiveness. */
	public boolean canWriteClientCache;
	/**Prefetch hook for HTML documents. Only really necessary for FProxy's web-pushing*/
	public FoundURICallback prefetchHook;
	/**Callback needed for web-pushing*/
	public TagReplacerCallback tagReplacer;
	/**Force the content fiter to use this MIME type*/
	public String overrideMIME;
	/** Number of attempts before we go into cooldown. Must be less than or equal to
	 * RequestScheduler.COOLDOWN_RETRIES. */
	private int cooldownRetries;
	/** Time period for which we go into cooldown. Must be NO LESS THAN
	 * RequestScheduler.COOLDOWN_PERIOD, because ULPRs will ensure rapid success
	 * with that interval or less. */
	private long cooldownTime;

	/** Ignore USK DATEHINTs */
	public boolean ignoreUSKDatehints;

  /** scheme, host and port: force the prefix of a URI. Example: https://localhost:1234 */
  private final String schemeHostAndPort;

  public FetchContext(long curMaxLength,
			long curMaxTempLength, int maxMetadataSize, int maxRecursionLevel, int maxArchiveRestarts, int maxArchiveLevels,
			boolean dontEnterImplicitArchives,
			int maxSplitfileBlockRetries, int maxNonSplitfileRetries, int maxUSKRetries,
			boolean allowSplitfiles, boolean followRedirects, boolean localRequestOnly,
			boolean filterData, int maxDataBlocksPerSegment, int maxCheckBlocksPerSegment,
			BucketFactory bucketFactory,
			ClientEventProducer producer,
			boolean ignoreTooManyPathComponents, boolean canWriteClientCache, String charset, String overrideMIME,
      String schemeHostAndPort) {
    this.blocks = null;
		this.maxOutputLength = curMaxLength;
		if(maxOutputLength < 0) throw new IllegalArgumentException("Bad max output length");
		this.maxTempLength = curMaxTempLength;
		if(maxTempLength < 0) throw new IllegalArgumentException("Bad max temp length");
		this.maxMetadataSize = maxMetadataSize;
        if(maxMetadataSize < 0) throw new IllegalArgumentException("Bad max metadata size");
		this.maxRecursionLevel = maxRecursionLevel;
		if(maxRecursionLevel < 0) throw new IllegalArgumentException("Bad max recursion level");
		this.maxArchiveRestarts = maxArchiveRestarts;
		if(maxArchiveRestarts < 0) throw new IllegalArgumentException("Bad max archive restarts");
		this.maxArchiveLevels = maxArchiveLevels;
		if(maxArchiveLevels < 0) throw new IllegalArgumentException("Bad max archive levels");
		this.dontEnterImplicitArchives = dontEnterImplicitArchives;
		this.maxSplitfileBlockRetries = maxSplitfileBlockRetries;
		if(maxSplitfileBlockRetries < -1) throw new IllegalArgumentException("Bad max splitfile block retries");
		this.maxNonSplitfileRetries = maxNonSplitfileRetries;
		if(maxNonSplitfileRetries < -1) throw new IllegalArgumentException("Bad non-splitfile retries");
		this.maxUSKRetries = maxUSKRetries;
		if(maxUSKRetries < -1) throw new IllegalArgumentException("Bad max USK retries");
		this.allowSplitfiles = allowSplitfiles;
		this.followRedirects = followRedirects;
		this.localRequestOnly = localRequestOnly;
		this.eventProducer = producer;
		this.maxDataBlocksPerSegment = maxDataBlocksPerSegment;
        if(maxDataBlocksPerSegment < 0 || maxDataBlocksPerSegment > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
            throw new IllegalArgumentException("Bad max blocks per segment");
		this.maxCheckBlocksPerSegment = maxCheckBlocksPerSegment;
        if(maxCheckBlocksPerSegment < 0 || maxCheckBlocksPerSegment > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
            throw new IllegalArgumentException("Bad max blocks per segment");
		this.filterData = filterData;
		this.ignoreTooManyPathComponents = ignoreTooManyPathComponents;
		this.canWriteClientCache = canWriteClientCache;
		this.charset = charset;
		this.overrideMIME = overrideMIME;
		this.cooldownRetries = RequestScheduler.COOLDOWN_RETRIES;
		this.cooldownTime = RequestScheduler.COOLDOWN_PERIOD;
		this.ignoreUSKDatehints = false; // FIXME
		hasOwnEventProducer = true;
    this.schemeHostAndPort = schemeHostAndPort;
	}

	/** Copy a FetchContext, creating a new EventProducer and not changing the blocks list.
     * @param ctx The old FetchContext to copy.
     * @param maskID Mask mode for the copy operation e.g. SPLITFILE_DEFAULT_BLOCK_MASK.
     */
    public FetchContext(FetchContext ctx, int maskID) {
        this(ctx, maskID, false, null);
    }

	/** Copy a FetchContext.
	 * @param ctx The old FetchContext to copy.
	 * @param maskID Mask mode for the copy operation e.g. SPLITFILE_DEFAULT_BLOCK_MASK.
	 * @param keepProducer If true, keep the existing EventProducer. Must be false if we are
	 * creating a new request. Can be true if we are masking the FetchContext within a single
	 * request, e.g. to download a container. This is important so that we see the progress updates
	 * for the request and not for other requests sharing the FetchContext, but also it could break
	 * serialization.
	 * @param blocks Storing a BlockSet to the database is not supported, see comments on SimpleBlockSet.objectCanNew().
	 */
	public FetchContext(FetchContext ctx, int maskID, boolean keepProducer, BlockSet blocks) {
		if(keepProducer)
			this.eventProducer = ctx.eventProducer;
		else
			this.eventProducer = new SimpleEventProducer();
		hasOwnEventProducer = !keepProducer;
		this.ignoreTooManyPathComponents = ctx.ignoreTooManyPathComponents;
		if(blocks != null)
			this.blocks = blocks;
		else
			this.blocks = ctx.blocks;

		this.allowedMIMETypes = ctx.allowedMIMETypes;
		this.maxUSKRetries = ctx.maxUSKRetries;
		this.localRequestOnly = ctx.localRequestOnly;
		this.maxArchiveLevels = ctx.maxArchiveLevels;
		this.maxMetadataSize = ctx.maxMetadataSize;
		this.maxNonSplitfileRetries = ctx.maxNonSplitfileRetries;
		this.maxOutputLength = ctx.maxOutputLength;
		this.maxSplitfileBlockRetries = ctx.maxSplitfileBlockRetries;
		this.maxTempLength = ctx.maxTempLength;
		this.allowSplitfiles = ctx.allowSplitfiles;
		this.dontEnterImplicitArchives = ctx.dontEnterImplicitArchives;
		this.followRedirects = ctx.followRedirects;
		this.maxArchiveRestarts = ctx.maxArchiveRestarts;
		this.maxCheckBlocksPerSegment = ctx.maxCheckBlocksPerSegment;
		this.maxDataBlocksPerSegment = ctx.maxDataBlocksPerSegment;
		this.filterData = ctx.filterData;
		this.maxRecursionLevel = ctx.maxRecursionLevel;
		this.returnZIPManifests = ctx.returnZIPManifests;
		this.canWriteClientCache = ctx.canWriteClientCache;
		this.prefetchHook = ctx.prefetchHook;
		this.tagReplacer = ctx.tagReplacer;
		this.overrideMIME = ctx.overrideMIME;
		this.cooldownRetries = ctx.cooldownRetries;
		this.cooldownTime = ctx.cooldownTime;
		this.ignoreUSKDatehints = ctx.ignoreUSKDatehints;
		this.schemeHostAndPort = ctx.schemeHostAndPort;

		if(maskID == IDENTICAL_MASK || maskID == SPLITFILE_DEFAULT_MASK) {
			// DEFAULT
		} else if(maskID == SPLITFILE_DEFAULT_BLOCK_MASK) {
			this.maxRecursionLevel = 1;
			this.maxArchiveRestarts = 0;
			this.dontEnterImplicitArchives = true;
			this.allowSplitfiles = false;
			this.followRedirects = false;
			this.maxDataBlocksPerSegment = 0;
			this.maxCheckBlocksPerSegment = 0;
			this.returnZIPManifests = false;
		} else if (maskID == SET_RETURN_ARCHIVES) {
			this.returnZIPManifests = true;
		}
		else throw new IllegalArgumentException();
	}

    /** Make public, but just call parent for a field for field copy */
	@Override
	public FetchContext clone() {
		try {
			return (FetchContext) super.clone();
		} catch (CloneNotSupportedException e) {
			// Impossible
			throw new Error(e);
		}
	}

	public void setCooldownRetries(int cooldownRetries) {
		if(cooldownRetries < 0)
			throw new IllegalArgumentException("Bogus negative retries");
		if(cooldownRetries > RequestScheduler.COOLDOWN_RETRIES)
			throw new IllegalArgumentException("Invalid COOLDOWN_RETRIES: Must be <= "+RequestScheduler.COOLDOWN_RETRIES+" since the network will not tolerate more than that");
		this.cooldownRetries = cooldownRetries;
	}

	/** Set the cooldown time */
	public void setCooldownTime(long cooldownTime) {
	    setCooldownTime(cooldownTime, false);
	}

	/** Only for tests */
	public void setCooldownTime(long cooldownTime, boolean force) {
		if(cooldownTime < 0)
			throw new IllegalArgumentException("Bogus negative cooldown time");
		if(cooldownTime < RequestScheduler.COOLDOWN_PERIOD && !force)
			throw new IllegalArgumentException("Invalid COOLDOWN_PERIOD: Must be >= "+RequestScheduler.COOLDOWN_PERIOD+" since ULPRs will ensure fast response at that level");
		this.cooldownTime = cooldownTime;
	}

	public int getCooldownRetries() {
		return cooldownRetries;
	}

  public String getSchemeHostAndPort() {
    return schemeHostAndPort;
  }

	public long getCooldownTime() {
		return cooldownTime;
	}

    private static final long CLIENT_DETAIL_MAGIC = 0x5ae53b0ce18dd821L;
    private static final int CLIENT_DETAIL_VERSION = 1;

    public void writeTo(DataOutputStream dos) throws IOException {
        dos.writeLong(CLIENT_DETAIL_MAGIC);
        dos.writeInt(CLIENT_DETAIL_VERSION);
        dos.writeLong(maxOutputLength);
        dos.writeLong(maxTempLength);
        dos.writeInt(maxRecursionLevel);
        dos.writeInt(maxArchiveRestarts);
        dos.writeInt(maxArchiveLevels);
        dos.writeBoolean(dontEnterImplicitArchives);
        dos.writeInt(maxSplitfileBlockRetries);
        dos.writeInt(maxNonSplitfileRetries);
        dos.writeInt(maxUSKRetries);
        dos.writeBoolean(allowSplitfiles);
        dos.writeBoolean(followRedirects);
        dos.writeBoolean(localRequestOnly);
        dos.writeBoolean(ignoreStore);
        dos.writeInt(maxMetadataSize);
        dos.writeInt(maxDataBlocksPerSegment);
        dos.writeInt(maxCheckBlocksPerSegment);
        dos.writeBoolean(returnZIPManifests);
        dos.writeBoolean(filterData);
        dos.writeBoolean(ignoreTooManyPathComponents);
        if(blocks != null) throw new UnsupportedOperationException("Binary blob not supported");
        if(allowedMIMETypes != null) {
            dos.writeInt(allowedMIMETypes.size());
            for(String s : allowedMIMETypes)
                dos.writeUTF(s);
        } else {
            dos.writeInt(0);
        }
        if(charset == null)
            dos.writeUTF("");
        else
            dos.writeUTF(charset);
        dos.writeBoolean(canWriteClientCache);
        if(prefetchHook != null) throw new UnsupportedOperationException("Prefetch hook not supported");
        if(tagReplacer != null) throw new UnsupportedOperationException("Tag replacer not supported");
        if(overrideMIME != null)
            dos.writeUTF(overrideMIME);
        else
            dos.writeUTF("");
        dos.writeInt(cooldownRetries);
        dos.writeLong(cooldownTime);
        dos.writeBoolean(ignoreUSKDatehints);
        if (schemeHostAndPort != null)
          dos.writeUTF(schemeHostAndPort);
        else
          dos.writeUTF("");
    }

    /** Create from a saved form, e.g. for restarting a request from scratch. Will create its own
     * SimpleEventProducer.
     * @param dis
     * @throws StorageFormatException If the data is badly formatted or cannot be read.
     * @throws IOException If unable to read from the stream.
     */
    public FetchContext(DataInputStream dis) throws StorageFormatException, IOException {
        long magic = dis.readLong();
        if(magic != CLIENT_DETAIL_MAGIC)
            throw new StorageFormatException("Bad magic for fetch settings (FetchContext)");
        int version = dis.readInt();
        if(version != CLIENT_DETAIL_VERSION)
            throw new StorageFormatException("Bad version for fetch settings (FetchContext)");
        maxOutputLength = dis.readLong();
        if(maxOutputLength < 0) throw new StorageFormatException("Bad max output length");
        maxTempLength = dis.readLong();
        if(maxTempLength < 0) throw new StorageFormatException("Bad max temp length");
        maxRecursionLevel = dis.readInt();
        if(maxRecursionLevel < 0) throw new StorageFormatException("Bad max recursion level");
        maxArchiveRestarts = dis.readInt();
        if(maxArchiveRestarts < 0) throw new StorageFormatException("Bad max archive restarts");
        maxArchiveLevels = dis.readInt();
        if(maxArchiveLevels < 0) throw new StorageFormatException("Bad max archive levels");
        dontEnterImplicitArchives = dis.readBoolean();
        maxSplitfileBlockRetries = dis.readInt();
        if(maxSplitfileBlockRetries < -1) throw new StorageFormatException("Bad max splitfile block retries");
        maxNonSplitfileRetries = dis.readInt();
        if(maxNonSplitfileRetries < -1) throw new StorageFormatException("Bad non-splitfile retries");
        maxUSKRetries = dis.readInt();
        if(maxUSKRetries < -1) throw new StorageFormatException("Bad max USK retries");
        allowSplitfiles = dis.readBoolean();
        followRedirects = dis.readBoolean();
        localRequestOnly = dis.readBoolean();
        ignoreStore = dis.readBoolean();
        maxMetadataSize = dis.readInt();
        if(maxMetadataSize < 0) throw new StorageFormatException("Bad max metadata size");
        maxDataBlocksPerSegment = dis.readInt();
        if(maxDataBlocksPerSegment < 0 || maxDataBlocksPerSegment > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
            throw new StorageFormatException("Bad max blocks per segment");
        maxCheckBlocksPerSegment = dis.readInt();
        if(maxCheckBlocksPerSegment < 0 || maxCheckBlocksPerSegment > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
            throw new StorageFormatException("Bad max blocks per segment");
        returnZIPManifests = dis.readBoolean();
        filterData = dis.readBoolean();
        ignoreTooManyPathComponents = dis.readBoolean();
        int x = dis.readInt();
        if(x < 0) throw new StorageFormatException("Bad allowed MIME types length "+x);
        if(x == 0) {
            allowedMIMETypes = null;
        } else {
            allowedMIMETypes = new HashSet<String>();
            for(int i=0;i<x;i++) {
                allowedMIMETypes.add(dis.readUTF());
            }
        }
        String s = dis.readUTF();
        if(s.equals(""))
            charset = null;
        else
            charset = s;
        canWriteClientCache = dis.readBoolean();
        s = dis.readUTF();
        if(s.equals(""))
            overrideMIME = null;
        else
            overrideMIME = s;
        cooldownRetries = dis.readInt();
        cooldownTime = dis.readLong();
        ignoreUSKDatehints = dis.readBoolean();
        try {
          s = dis.readUTF();
        } catch (EOFException e) {
          // input stream reached EOF, so it must have been and old version without scehmeHostAndPort.
          s = "";
        }
        if(s.equals(""))
          schemeHostAndPort = null;
        else
          schemeHostAndPort = s;
        hasOwnEventProducer = true;
        eventProducer = new SimpleEventProducer();
        blocks = null;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        // eventProducer is not included, assumed to be unique.
        result = prime * result + (allowSplitfiles ? 1231 : 1237);
        result = prime * result + ((allowedMIMETypes == null) ? 0 : allowedMIMETypes.hashCode());
        // Don't include blocks. It doesn't implement content-based hashCode() and equals(). FIXME
        result = prime * result + (canWriteClientCache ? 1231 : 1237);
        result = prime * result + ((charset == null) ? 0 : charset.hashCode());
        result = prime * result + cooldownRetries;
        result = prime * result + (int) (cooldownTime ^ (cooldownTime >>> 32));
        result = prime * result + (dontEnterImplicitArchives ? 1231 : 1237);
        result = prime * result + (filterData ? 1231 : 1237);
        result = prime * result + (followRedirects ? 1231 : 1237);
        result = prime * result + (hasOwnEventProducer ? 1231 : 1237);
        result = prime * result + (ignoreStore ? 1231 : 1237);
        result = prime * result + (ignoreTooManyPathComponents ? 1231 : 1237);
        result = prime * result + (ignoreUSKDatehints ? 1231 : 1237);
        result = prime * result + (localRequestOnly ? 1231 : 1237);
        result = prime * result + maxArchiveLevels;
        result = prime * result + maxArchiveRestarts;
        result = prime * result + maxCheckBlocksPerSegment;
        result = prime * result + maxDataBlocksPerSegment;
        result = prime * result + maxMetadataSize;
        result = prime * result + maxNonSplitfileRetries;
        result = prime * result + (int) (maxOutputLength ^ (maxOutputLength >>> 32));
        result = prime * result + maxRecursionLevel;
        result = prime * result + maxSplitfileBlockRetries;
        result = prime * result + (int) (maxTempLength ^ (maxTempLength >>> 32));
        result = prime * result + maxUSKRetries;
        result = prime * result + ((overrideMIME == null) ? 0 : overrideMIME.hashCode());
        result = prime * result + ((prefetchHook == null) ? 0 : prefetchHook.hashCode());
        result = prime * result + (returnZIPManifests ? 1231 : 1237);
        result = prime * result + ((tagReplacer == null) ? 0 : tagReplacer.hashCode());
        result = prime * result + ((schemeHostAndPort == null) ? 0 : schemeHostAndPort.hashCode());
        return result;
    }

    /** Are two InsertContext's equal? Ignores the EventProducer, compares only the actual config
     * values. */
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        FetchContext other = (FetchContext) obj;
        // eventProducer is ignored.
        if (allowSplitfiles != other.allowSplitfiles)
            return false;
        if (allowedMIMETypes == null) {
            if (other.allowedMIMETypes != null)
                return false;
        } else if (!allowedMIMETypes.equals(other.allowedMIMETypes))
            return false;
        // We *DO* compare on blocks, which means that two FetchContext's can be non-equal even
        // though the are really the same, until blocks has a proper equals(). FIXME
        if (blocks == null) {
            if (other.blocks != null)
                return false;
        } else if (!blocks.equals(other.blocks))
            return false;
        if (canWriteClientCache != other.canWriteClientCache)
            return false;
        if (charset == null) {
            if (other.charset != null)
                return false;
        } else if (!charset.equals(other.charset))
            return false;
        if (cooldownRetries != other.cooldownRetries)
            return false;
        if (cooldownTime != other.cooldownTime)
            return false;
        if (dontEnterImplicitArchives != other.dontEnterImplicitArchives)
            return false;
        if (filterData != other.filterData)
            return false;
        if (followRedirects != other.followRedirects)
            return false;
        if (hasOwnEventProducer != other.hasOwnEventProducer)
            return false;
        if (ignoreStore != other.ignoreStore)
            return false;
        if (ignoreTooManyPathComponents != other.ignoreTooManyPathComponents)
            return false;
        if (ignoreUSKDatehints != other.ignoreUSKDatehints)
            return false;
        if (localRequestOnly != other.localRequestOnly)
            return false;
        if (maxArchiveLevels != other.maxArchiveLevels)
            return false;
        if (maxArchiveRestarts != other.maxArchiveRestarts)
            return false;
        if (maxCheckBlocksPerSegment != other.maxCheckBlocksPerSegment)
            return false;
        if (maxDataBlocksPerSegment != other.maxDataBlocksPerSegment)
            return false;
        if (maxMetadataSize != other.maxMetadataSize)
            return false;
        if (maxNonSplitfileRetries != other.maxNonSplitfileRetries)
            return false;
        if (maxOutputLength != other.maxOutputLength)
            return false;
        if (maxRecursionLevel != other.maxRecursionLevel)
            return false;
        if (maxSplitfileBlockRetries != other.maxSplitfileBlockRetries)
            return false;
        if (maxTempLength != other.maxTempLength)
            return false;
        if (maxUSKRetries != other.maxUSKRetries)
            return false;
        if (overrideMIME == null) {
            if (other.overrideMIME != null)
                return false;
        } else if (!overrideMIME.equals(other.overrideMIME))
            return false;
        if (prefetchHook == null) {
            if (other.prefetchHook != null)
                return false;
        } else if (!prefetchHook.equals(other.prefetchHook))
            return false;
        if (returnZIPManifests != other.returnZIPManifests)
            return false;
        if (tagReplacer == null) {
            if (other.tagReplacer != null)
                return false;
        } else if (!tagReplacer.equals(other.tagReplacer))
            return false;
        if (schemeHostAndPort == null) {
            if (other.schemeHostAndPort != null)
                return false;
        } else if (!schemeHostAndPort.equals(other.schemeHostAndPort))
            return false;
        return true;
    }


}
