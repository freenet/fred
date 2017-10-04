/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import net.contrapunctus.lzma.LzmaInputStream;

import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

import freenet.client.async.ClientContext;
import freenet.keys.FreenetURI;
import freenet.support.ExceptionWrapper;
import freenet.support.LRUMap;
import freenet.support.Logger;
import freenet.support.MutableBoolean;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.compress.CompressionOutputSizeException;
import freenet.support.compress.Compressor;
import freenet.support.compress.Compressor.COMPRESSOR_TYPE;
import freenet.support.io.BucketTools;
import freenet.support.io.Closer;

/**
 * Cache of recently decoded archives:
 * - Keep up to N ArchiveHandler's in RAM (this can be large; we don't keep the
 * files open due to the limitations of the java.util.zip API)
 * - Keep up to Y bytes (after padding and overheads) of decoded data on disk
 * (the OS is quite capable of determining what to keep in actual RAM)
 *
 * Always take the lock on ArchiveStoreContext before the lock on ArchiveManager, NOT the other way around.
 */
public class ArchiveManager {

	public static final String METADATA_NAME = ".metadata";
	private static boolean logMINOR;

	public enum ARCHIVE_TYPE {
	    // WARNING: This enum is persisted. Changing member names may break downloads/uploads.
		ZIP((short)0, new String[] { "application/zip", "application/x-zip" }), 	/* eventually get rid of ZIP support at some point */
		TAR((short)1, new String[] { "application/x-tar" });

		public final short metadataID;
		public final String[] mimeTypes;

		/** cached values(). Never modify or pass this array to outside code! */
		private static final ARCHIVE_TYPE[] values = values();

		private ARCHIVE_TYPE(short metadataID, String[] mimeTypes) {
			this.metadataID = metadataID;
			this.mimeTypes = mimeTypes;
		}

		public static boolean isValidMetadataID(short id) {
			for(ARCHIVE_TYPE current : values)
				if(id == current.metadataID)
					return true;
			return false;
		}

		/**
		 * Is the given MIME type an archive type that we can deal with?
		 */
		public static boolean isUsableArchiveType(String type) {
			for(ARCHIVE_TYPE current : values)
				for(String ctype : current.mimeTypes)
					if(ctype.equalsIgnoreCase(type))
						return true;
			return false;
		}

		/** If the given MIME type is an archive type that we can deal with,
		 * get its archive type number (see the ARCHIVE_ constants in Metadata).
		 */
		public static ARCHIVE_TYPE getArchiveType(String type) {
			for(ARCHIVE_TYPE current : values)
				for(String ctype : current.mimeTypes)
					if(ctype.equalsIgnoreCase(type))
						return current;
			return null;
		}

		public static ARCHIVE_TYPE getArchiveType(short type) {
			for(ARCHIVE_TYPE current : values)
				if(current.metadataID == type)
					return current;
			return null;
		}

		public static ARCHIVE_TYPE getDefault() {
			return TAR;
		}
	}

	final long maxArchivedFileSize;

	// ArchiveHandler's
	final int maxArchiveHandlers;
	private final LRUMap<FreenetURI, ArchiveStoreContext> archiveHandlers;

	// Data cache
	/** Maximum number of cached ArchiveStoreItems */
	final int maxCachedElements;
	/** Maximum cached data in bytes */
	final long maxCachedData;
	/** Currently cached data in bytes */
	private long cachedData;
	/** Map from ArchiveKey to ArchiveStoreElement */
	private final LRUMap<ArchiveKey, ArchiveStoreItem> storedData;
	/** Bucket Factory */
	private final BucketFactory tempBucketFactory;

	/**
	 * Create an ArchiveManager.
	 * @param maxHandlers The maximum number of cached ArchiveHandler's i.e. the
	 * maximum number of containers to track.
	 * @param maxCachedData The maximum size of the cache directory, in bytes.
	 * @param maxArchiveSize The maximum size of an archive.
	 * @param maxArchivedFileSize The maximum extracted size of a single file in any
	 * archive.
	 * @param maxCachedElements The maximum number of cached elements (an element is a
	 * file extracted from an archive. It is stored, encrypted and padded, in a single
	 * file.
	 * @param tempBucketFactory
	 */
	public ArchiveManager(int maxHandlers, long maxCachedData, long maxArchivedFileSize, int maxCachedElements, BucketFactory tempBucketFactory) {
		maxArchiveHandlers = maxHandlers;
		// FIXME PERFORMANCE I'm assuming there isn't much locality here, so it's faster to use the FAST_COMPARATOR.
		// This may not be true if there are a lot of sites with many containers all inserted as individual SSKs?
		archiveHandlers = LRUMap.createSafeMap(FreenetURI.FAST_COMPARATOR);
		this.maxCachedElements = maxCachedElements;
		this.maxCachedData = maxCachedData;
		storedData = new LRUMap<ArchiveKey, ArchiveStoreItem>();
		this.maxArchivedFileSize = maxArchivedFileSize;
		this.tempBucketFactory = tempBucketFactory;
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
	}

	/** Add an ArchiveHandler by key */
	private synchronized void putCached(FreenetURI key, ArchiveStoreContext zip) {
		if(logMINOR) Logger.minor(this, "Put cached AH for "+key+" : "+zip);
		archiveHandlers.push(key, zip);
		while(archiveHandlers.size() > maxArchiveHandlers)
			archiveHandlers.popKey(); // dump it
	}

	/** Get an ArchiveHandler by key */
	ArchiveStoreContext getCached(FreenetURI key) {
		if(logMINOR) Logger.minor(this, "Get cached AH for "+key);
		ArchiveStoreContext handler = archiveHandlers.get(key);
		if(handler == null) return null;
		archiveHandlers.push(key, handler);
		return handler;
	}

	/**
	 * Create an archive handler. This does not need to know how to
	 * fetch the key, because the methods called later will ask.
	 * It will try to serve from cache, but if that fails, will
	 * re-fetch.
	 * @param key The key of the archive that we are extracting data from.
	 * @param archiveType The archive type, defined in Metadata.
	 * @return An archive handler.
	 */
	synchronized ArchiveStoreContext makeContext(FreenetURI key, ARCHIVE_TYPE archiveType, boolean returnNullIfNotFound) {
		ArchiveStoreContext handler = null;
		handler = getCached(key);
		if(handler != null) return handler;
		if(returnNullIfNotFound) return null;
		handler = new ArchiveStoreContext(key, archiveType);
		putCached(key, handler);
		return handler;
	}

	/**
	 * Create an archive handler. This does not need to know how to
	 * fetch the key, because the methods called later will ask.
	 * It will try to serve from cache, but if that fails, will
	 * re-fetch.
	 * @param key The key of the archive that we are extracting data from.
	 * @param archiveType The archive type, defined in Metadata.
	 * @return An archive handler.
	 */
	public ArchiveHandler makeHandler(FreenetURI key, ARCHIVE_TYPE archiveType, COMPRESSOR_TYPE ctype, boolean forceRefetch) {
		return new ArchiveHandlerImpl(key, archiveType, ctype, forceRefetch);
	}

	/**
	 * Get a cached, previously extracted, file from an archive.
	 * @param key The key used to fetch the archive.
	 * @param filename The name of the file within the archive.
	 * @return A Bucket containing the data requested, or null.
	 * @throws ArchiveFailureException
	 */
	public Bucket getCached(FreenetURI key, String filename) throws ArchiveFailureException {
		if(logMINOR) Logger.minor(this, "Fetch cached: "+key+ ' ' +filename);
		ArchiveKey k = new ArchiveKey(key, filename);
		ArchiveStoreItem asi = null;
		synchronized (this) {
			asi = storedData.get(k);
			if(asi == null) return null;
			// Promote to top of LRU
			storedData.push(k, asi);
		}
		if(logMINOR) Logger.minor(this, "Found data");
		return asi.getReaderBucket();
	}

	/**
	 * Remove a file from the cache. Called after it has been removed from its
	 * ArchiveHandler.
	 * @param item The ArchiveStoreItem to remove.
	 */
	synchronized void removeCachedItem(ArchiveStoreItem item) {
		long size = item.spaceUsed();
		storedData.removeKey(item.key);
		// Hard disk space limit = remove it here.
		// Soft disk space limit would be to remove it outside the lock.
		// Soft disk space limit = we go over the limit significantly when we
		// are overloaded.
		cachedData -= size;
		if(logMINOR) Logger.minor(this, "removeCachedItem: "+item);
		item.close();
	}

	/**
	 * Extract data to cache. Call synchronized on ctx.
	 * @param key The key the data was fetched from.
	 * @param archiveType The archive type. Must be Metadata.ARCHIVE_ZIP | Metadata.ARCHIVE_TAR.
	 * @param data The actual data fetched.
	 * @param archiveContext The context for the whole fetch process.
	 * @param ctx The ArchiveStoreContext for this key.
	 * @param element A particular element that the caller is especially interested in, or null.
	 * @param callback A callback to be called if we find that element, or if we don't.
	 * @throws ArchiveFailureException If we could not extract the data, or it was too big, etc.
	 * @throws ArchiveRestartException
	 * @throws ArchiveRestartException If the request needs to be restarted because the archive
	 * changed.
	 */
	public void extractToCache(FreenetURI key, ARCHIVE_TYPE archiveType, COMPRESSOR_TYPE ctype, final Bucket data, ArchiveContext archiveContext, ArchiveStoreContext ctx, String element, ArchiveExtractCallback callback, ClientContext context) throws ArchiveFailureException, ArchiveRestartException {
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);

		MutableBoolean gotElement = element != null ? new MutableBoolean() : null;

		if(logMINOR) Logger.minor(this, "Extracting "+key);
		ctx.removeAllCachedItems(this); // flush cache anyway
		final long expectedSize = ctx.getLastSize();
		final long archiveSize = data.size();
		/** Set if we need to throw a RestartedException rather than returning success,
		 * after we have unpacked everything.
		 */
		boolean throwAtExit = false;
		if((expectedSize != -1) && (archiveSize != expectedSize)) {
			throwAtExit = true;
			ctx.setLastSize(archiveSize);
		}
		byte[] expectedHash = ctx.getLastHash();
		if(expectedHash != null) {
			byte[] realHash;
			try {
				realHash = BucketTools.hash(data);
			} catch (IOException e) {
				throw new ArchiveFailureException("Error reading archive data: "+e, e);
			}
			if(!Arrays.equals(realHash, expectedHash))
				throwAtExit = true;
			ctx.setLastHash(realHash);
		}

		if(archiveSize > archiveContext.maxArchiveSize)
			throw new ArchiveFailureException("Archive too big ("+archiveSize+" > "+archiveContext.maxArchiveSize+")!");
		else if(archiveSize <= 0)
			throw new ArchiveFailureException("Archive too small! ("+archiveSize+')');
		else if(logMINOR)
			Logger.minor(this, "Container size (possibly compressed): "+archiveSize+" for "+data);

		InputStream is = null;
		try {
			final ExceptionWrapper wrapper;
			if((ctype == null) || (ARCHIVE_TYPE.ZIP == archiveType)) {
				if(logMINOR) Logger.minor(this, "No compression");
				is = data.getInputStream();
				wrapper = null;
			} else if(ctype == COMPRESSOR_TYPE.BZIP2) {
				if(logMINOR) Logger.minor(this, "dealing with BZIP2");
				is = new BZip2CompressorInputStream(data.getInputStream());
				wrapper = null;
			} else if(ctype == COMPRESSOR_TYPE.GZIP) {
				if(logMINOR) Logger.minor(this, "dealing with GZIP");
				is = new GZIPInputStream(data.getInputStream());
				wrapper = null;
			} else if(ctype == COMPRESSOR_TYPE.LZMA_NEW) {
				// LZMA internally uses pipe streams, so we may as well do it here.
				// In fact we need to for LZMA_NEW, because of the properties bytes.
				PipedInputStream pis = new PipedInputStream();
				PipedOutputStream pos = new PipedOutputStream();
				pis.connect(pos);
				final OutputStream os = new BufferedOutputStream(pos);
				wrapper = new ExceptionWrapper();
				context.mainExecutor.execute(new Runnable() {

					@Override
					public void run() {
						InputStream is = null;
						try {
							Compressor.COMPRESSOR_TYPE.LZMA_NEW.decompress(is = data.getInputStream(), os, data.size(), expectedSize);
						} catch (CompressionOutputSizeException e) {
							Logger.error(this, "Failed to decompress archive: "+e, e);
							wrapper.set(e);
						} catch (IOException e) {
							Logger.error(this, "Failed to decompress archive: "+e, e);
							wrapper.set(e);
						} finally {
							try {
								os.close();
							} catch (IOException e) {
								Logger.error(this, "Failed to close PipedOutputStream: "+e, e);
							}
							Closer.close(is);
						}
					}
					
				});
				is = pis;
			} else if(ctype == COMPRESSOR_TYPE.LZMA) {
				if(logMINOR) Logger.minor(this, "dealing with LZMA");
				is = new LzmaInputStream(data.getInputStream());
				wrapper = null;
			} else {
				wrapper = null;
			}

			if(ARCHIVE_TYPE.ZIP == archiveType)
				handleZIPArchive(ctx, key, is, element, callback, gotElement, throwAtExit, context);
			else if(ARCHIVE_TYPE.TAR == archiveType)
				handleTARArchive(ctx, key, is, element, callback, gotElement, throwAtExit, context);
		else
				throw new ArchiveFailureException("Unknown or unsupported archive algorithm " + archiveType);
			if(wrapper != null) {
				Exception e = wrapper.get();
				if(e != null) throw new ArchiveFailureException("An exception occured decompressing: "+e.getMessage(), e);
			}
		} catch (IOException ioe) {
			throw new ArchiveFailureException("An IOE occured: "+ioe.getMessage(), ioe);
		}finally {
			Closer.close(is);
	}
	}

	private void handleTARArchive(ArchiveStoreContext ctx, FreenetURI key, InputStream data, String element, ArchiveExtractCallback callback, MutableBoolean gotElement, boolean throwAtExit, ClientContext context) throws ArchiveFailureException, ArchiveRestartException {
		if(logMINOR) Logger.minor(this, "Handling a TAR Archive");
		TarArchiveInputStream tarIS = null;
		try {
			tarIS = new TarArchiveInputStream(data);

			// MINOR: Assumes the first entry in the tarball is a directory.
			ArchiveEntry entry;

			byte[] buf = new byte[32768];
			HashSet<String> names = new HashSet<String>();
			boolean gotMetadata = false;

outerTAR:		while(true) {
				try {
				entry = tarIS.getNextEntry();
				} catch (IllegalArgumentException e) {
					// Annoyingly, it can throw this on some corruptions...
					throw new ArchiveFailureException("Error reading archive: "+e.getMessage(), e);
				}
				if(entry == null) break;
				if(entry.isDirectory()) continue;
				String name = stripLeadingSlashes(entry.getName());
				if(names.contains(name)) {
					Logger.error(this, "Duplicate key "+name+" in archive "+key);
					continue;
				}
				long size = entry.getSize();
				if(name.equals(".metadata"))
					gotMetadata = true;
				if(size > maxArchivedFileSize && !name.equals(element)) {
					addErrorElement(ctx, key, name, "File too big: "+size+" greater than current archived file size limit "+maxArchivedFileSize, true);
				} else {
					// Read the element
					long realLen = 0;
					Bucket output = tempBucketFactory.makeBucket(size);
					OutputStream out = output.getOutputStream();

					try {
						int readBytes;
						while((readBytes = tarIS.read(buf)) > 0) {
							out.write(buf, 0, readBytes);
							readBytes += realLen;
							if(readBytes > maxArchivedFileSize) {
								addErrorElement(ctx, key, name, "File too big: "+maxArchivedFileSize+" greater than current archived file size limit "+maxArchivedFileSize, true);
								out.close();
								out = null;
								output.free();
								continue outerTAR;
							}
						}
						
					} finally {
						if(out != null) out.close();
					}
					if(size <= maxArchivedFileSize) {
						addStoreElement(ctx, key, name, output, gotElement, element, callback, context);
						names.add(name);
						trimStoredData();
					} else {
						// We are here because they asked for this file.
						callback.gotBucket(output, context);
						gotElement.value = true;
						addErrorElement(ctx, key, name, "File too big: "+size+" greater than current archived file size limit "+maxArchivedFileSize, true);
					}
				}
			}

			// If no metadata, generate some
			if(!gotMetadata) {
				generateMetadata(ctx, key, names, gotElement, element, callback, context);
				trimStoredData();
			}
			if(throwAtExit) throw new ArchiveRestartException("Archive changed on re-fetch");

			if((!gotElement.value) && element != null)
				callback.notInArchive(context);

		} catch (IOException e) {
			throw new ArchiveFailureException("Error reading archive: "+e.getMessage(), e);
		} finally {
			Closer.close(tarIS);
		}
	}

	private void handleZIPArchive(ArchiveStoreContext ctx, FreenetURI key, InputStream data, String element, ArchiveExtractCallback callback, MutableBoolean gotElement, boolean throwAtExit, ClientContext context) throws ArchiveFailureException, ArchiveRestartException {
		if(logMINOR) Logger.minor(this, "Handling a ZIP Archive");
		ZipInputStream zis = null;
		try {
			zis = new ZipInputStream(data);

			// MINOR: Assumes the first entry in the zip is a directory.
			ZipEntry entry;

			byte[] buf = new byte[32768];
			HashSet<String> names = new HashSet<String>();
			boolean gotMetadata = false;

outerZIP:		while(true) {
				entry = zis.getNextEntry();
				if(entry == null) break;
				if(entry.isDirectory()) continue;
				String name = stripLeadingSlashes(entry.getName());
				if(names.contains(name)) {
					Logger.error(this, "Duplicate key "+name+" in archive "+key);
					continue;
				}
				long size = entry.getSize();
				if(name.equals(".metadata"))
					gotMetadata = true;
				if(size > maxArchivedFileSize && !name.equals(element)) {
					addErrorElement(ctx, key, name, "File too big: "+maxArchivedFileSize+" greater than current archived file size limit "+maxArchivedFileSize, true);
				} else {
					// Read the element
					long realLen = 0;
					Bucket output = tempBucketFactory.makeBucket(size);
					OutputStream out = output.getOutputStream();
					try {
						
						int readBytes;
						while((readBytes = zis.read(buf)) > 0) {
							out.write(buf, 0, readBytes);
							readBytes += realLen;
							if(readBytes > maxArchivedFileSize) {
								addErrorElement(ctx, key, name, "File too big: "+maxArchivedFileSize+" greater than current archived file size limit "+maxArchivedFileSize, true);
								out.close();
								out = null;
								output.free();
								continue outerZIP;
							}
						}
						
					} finally {
						if(out != null) out.close();
					}
					if(size <= maxArchivedFileSize) {
						addStoreElement(ctx, key, name, output, gotElement, element, callback, context);
						names.add(name);
						trimStoredData();
					} else {
						// We are here because they asked for this file.
						callback.gotBucket(output, context);
						gotElement.value = true;
						addErrorElement(ctx, key, name, "File too big: "+size+" greater than current archived file size limit "+maxArchivedFileSize, true);
					}
				}
			}

			// If no metadata, generate some
			if(!gotMetadata) {
				generateMetadata(ctx, key, names, gotElement, element, callback, context);
				trimStoredData();
			}
			if(throwAtExit) throw new ArchiveRestartException("Archive changed on re-fetch");

			if((!gotElement.value) && element != null)
				callback.notInArchive(context);

		} catch (IOException e) {
			throw new ArchiveFailureException("Error reading archive: "+e.getMessage(), e);
		} finally {
			if(zis != null) {
				try {
					zis.close();
				} catch (IOException e) {
					Logger.error(this, "Failed to close stream: "+e, e);
				}
			}
		}
	}

	private String stripLeadingSlashes(String name) {
		while(name.length() > 1 && name.charAt(0) == '/')
			name = name.substring(1);
		return name;
	}

	/**
	 * Generate fake metadata for an archive which doesn't have any.
	 * @param ctx The context object.
	 * @param key The key from which the archive we are unpacking was fetched.
	 * @param names Set of names in the archive.
	 * @param element2
	 * @param gotElement
	 * @param callbackName If we generate a
	 * @throws ArchiveFailureException
	 */
	private ArchiveStoreItem generateMetadata(ArchiveStoreContext ctx, FreenetURI key, Set<String> names, MutableBoolean gotElement, String element2, ArchiveExtractCallback callback, ClientContext context) throws ArchiveFailureException {
		/* What we have to do is to:
		 * - Construct a filesystem tree of the names.
		 * - Turn each level of the tree into a Metadata object, including those below it, with
		 * simple manifests and archive internal redirects.
		 * - Turn the master Metadata object into binary metadata, with all its subsidiaries.
		 * - Create a .metadata entry containing this data.
		 */
		// Root directory.
		// String -> either itself, or another HashMap
		HashMap<String, Object> dir = new HashMap<String, Object>();
		for (String name : names) {
			addToDirectory(dir, name, "");
		}
		Metadata metadata = new Metadata(dir, "");
		int x = 0;
		Bucket bucket = null;
		while(true) {
			try {
				bucket = metadata.toBucket(tempBucketFactory);
				return addStoreElement(ctx, key, ".metadata", bucket, gotElement, element2, callback, context);
			} catch (MetadataUnresolvedException e) {
				try {
					x = resolve(e, x, tempBucketFactory, ctx, key, gotElement, element2, callback, context);
				} catch (IOException e1) {
					throw new ArchiveFailureException("Failed to create metadata: "+e1, e1);
				}
			} catch (IOException e1) {
				Logger.error(this, "Failed to create metadata: "+e1, e1);
				throw new ArchiveFailureException("Failed to create metadata: "+e1, e1);
			}
		}
	}

	private int resolve(MetadataUnresolvedException e, int x, BucketFactory bf, ArchiveStoreContext ctx, FreenetURI key, MutableBoolean gotElement, String element2, ArchiveExtractCallback callback, ClientContext context) throws IOException, ArchiveFailureException {
		for(Metadata m: e.mustResolve) {
			try {
			    addStoreElement(ctx, key, ".metadata-"+(x++), m.toBucket(bf), gotElement, element2, callback, context);
			} catch (MetadataUnresolvedException e1) {
				x = resolve(e, x, bf, ctx, key, gotElement, element2, callback, context);
				continue;
			}
		}
		return x;
	}

	private void addToDirectory(HashMap<String, Object> dir, String name, String prefix) throws ArchiveFailureException {
		int x = name.indexOf('/');
		if(x < 0) {
			if(dir.containsKey(name)) {
				throw new ArchiveFailureException("Invalid archive: contains "+prefix+name+" twice");
			}
			dir.put(name, name);
		} else {
			String before = name.substring(0, x);
			String after;
			if(x == name.length()-1) {
				// Last char
				after = "";
			} else
				after = name.substring(x+1, name.length());
			Object o = dir.get(before);
			if (o == null) {
				dir.put(before, o = new HashMap<String, Object>());
			} else if (o instanceof String) {
				throw new ArchiveFailureException("Invalid archive: contains "+name+" as both file and dir");
			}
			addToDirectory(Metadata.forceMap(o), after, prefix + before + '/');
		}
	}

	/**
	 * Add an error element to the cache. This happens when a single file in the archive
	 * is invalid (usually because it is too large).
	 * @param ctx The ArchiveStoreContext which must be notified about this element's creation.
	 * @param key The key from which the archive was fetched.
	 * @param name The name of the file within the archive.
	 * @param error The error message to be included on the eventual exception thrown,
	 * if anyone tries to extract the data for this element.
	 */
	private void addErrorElement(ArchiveStoreContext ctx, FreenetURI key, String name, String error, boolean tooBig) {
		ErrorArchiveStoreItem element = new ErrorArchiveStoreItem(ctx, key, name, error, tooBig);
		element.addToContext();
		if(logMINOR) Logger.minor(this, "Adding error element: "+element+" for "+key+ ' ' +name);
		ArchiveStoreItem oldItem;
		synchronized (this) {
			oldItem = storedData.get(element.key);
			storedData.push(element.key, element);
			if(oldItem != null) {
				oldItem.close();
				cachedData -= oldItem.spaceUsed();
				if(logMINOR) Logger.minor(this, "Dropping old store element from archive cache: "+oldItem);
			}
		}
	}

	/**
	 * Add a store element.
	 * @param callbackName If set, the name of the file for which we must call the callback if this file happens to
	 * match.
	 * @param gotElement Flag indicating whether we've already found the file for the callback. If so we must not call
	 * it again.
	 * @param callback Callback to be called if we do find it. We must getReaderBucket() before adding the data to the
	 * LRU, otherwise it may be deleted before it reaches the client.
	 * @throws ArchiveFailureException If a failure occurred resulting in the data not being readable. Only happens if
	 * callback != null.
	 */
	private ArchiveStoreItem addStoreElement(ArchiveStoreContext ctx, FreenetURI key, String name, Bucket temp, MutableBoolean gotElement, String callbackName, ArchiveExtractCallback callback, ClientContext context) throws ArchiveFailureException {
		RealArchiveStoreItem element = new RealArchiveStoreItem(ctx, key, name, temp);
		element.addToContext();
		if(logMINOR) Logger.minor(this, "Adding store element: "+element+" ( "+key+ ' ' +name+" size "+element.spaceUsed()+" )");
		ArchiveStoreItem oldItem;
		// Let it throw, if it does something is drastically wrong
		Bucket matchBucket = null;
		if((!gotElement.value) && name.equals(callbackName)) {
			matchBucket = element.getReaderBucket();
		}
		synchronized (this) {
			oldItem = storedData.get(element.key);
			storedData.push(element.key, element);
			cachedData += element.spaceUsed();
			if(oldItem != null) {
				cachedData -= oldItem.spaceUsed();
				if(logMINOR) Logger.minor(this, "Dropping old store element from archive cache: "+oldItem);
				oldItem.close();
			}
		}
		if(matchBucket != null) {
			callback.gotBucket(matchBucket, context);
			gotElement.value = true;
		}
		return element;
	}

	/**
	 * Drop any stored data beyond the limit.
	 * Call synchronized on storedData.
	 */
	private void trimStoredData() {
		synchronized(this) {
		while(true) {
			ArchiveStoreItem item;
				if(cachedData <= maxCachedData && storedData.size() <= maxCachedElements) return;
				if(storedData.isEmpty()) {
					// Race condition? cachedData out of sync?
					Logger.error(this, "storedData is empty but still over limit: cachedData="+cachedData+" / "+maxCachedData);
					return;
				}
				item = storedData.popValue();
				long space = item.spaceUsed();
				cachedData -= space;
				// Hard limits = delete file within lock, soft limits = delete outside of lock
				// Here we use a hard limit
			if(logMINOR)
				Logger.minor(this, "Dropping "+item+" : cachedData="+cachedData+" of "+maxCachedData+" stored items : "+storedData.size()+" of "+maxCachedElements);
			item.close();
		}
		}
	}

}
