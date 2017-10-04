/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.async;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;

import freenet.client.ClientMetadata;
import freenet.client.DefaultMIMETypes;
import freenet.client.InsertBlock;
import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.Metadata;
import freenet.client.MetadataUnresolvedException;
import freenet.client.ArchiveManager.ARCHIVE_TYPE;
import freenet.client.Metadata.DocumentType;
import freenet.client.Metadata.SimpleManifestComposer;
import freenet.client.async.BaseManifestPutter.PutHandler;
import freenet.keys.FreenetURI;
import freenet.support.Logger;
import freenet.support.api.Bucket;
import freenet.support.api.ManifestElement;
import freenet.support.api.RandomAccessBucket;
import freenet.support.io.BucketTools;
import freenet.support.io.Closer;
import freenet.support.io.ResumeFailedException;

/**
 * Insert a bunch of files as single Archive with .metadata
 * pack the container/archive, then hand it off to SimpleFileInserter
 *
 * TODO persistence
 * TODO add a MAX_SIZE for the final container(file)
 * 
 * @author saces
 * 
 */
public class ContainerInserter implements ClientPutState, Serializable {

    private static final long serialVersionUID = 1L;
    private static volatile boolean logMINOR;
	private static volatile boolean logDEBUG;

	static {
		Logger.registerClass(ContainerInserter.class);
	}

	private static class ContainerElement {
		private final Bucket data;
		private final String targetInArchive;
		
		private ContainerElement(Bucket data2, String targetInArchive2) {
			data = data2;
			targetInArchive = targetInArchive2;
		}
	}

	private ArrayList<ContainerElement> containerItems;

	private final BaseClientPutter parent;
	private final PutCompletionCallback cb;
	private boolean cancelled;
	private boolean finished;
	private final boolean persistent;
	/** See ContainerBuilder._rootDir. */
	private final HashMap<String, Object> origMetadata;
	private final ARCHIVE_TYPE archiveType;
	private final FreenetURI targetURI;
	private final Object token;
	private final InsertContext ctx;
	private final boolean reportMetadataOnly;
	private final boolean dontCompress;
	final byte[] forceCryptoKey;
	final byte cryptoAlgorithm;
	private final boolean realTimeFlag;

	/**
	 * Insert a bunch of files as single Archive with .metadata
	 * 
	 * @param parent2
	 * @param cb2
	 * @param metadata2
	 * @param targetURI2 The caller need to clone it for persistance
	 * @param ctx2
	 * @param dontCompress2
	 * @param reportMetadataOnly2
	 * @param token2
	 * @param archiveType2
	 * @param forceCryptoKey
	 * @param cryptoAlgorithm
	 * @param realTimeFlag
	 * 
	 */
	public ContainerInserter(
			BaseClientPutter parent2, 
			PutCompletionCallback cb2, 
			HashMap<String, Object> metadata2,
			FreenetURI targetURI2,
			InsertContext ctx2,
			boolean dontCompress2,
			boolean reportMetadataOnly2,
			Object token2,
			ARCHIVE_TYPE archiveType2,
			byte[] forceCryptoKey,
			byte cryptoAlgorithm,
			boolean realTimeFlag) {
		parent = parent2;
		cb = cb2;
		hashCode = super.hashCode();
		persistent = parent.persistent();
		origMetadata = metadata2;
		archiveType = archiveType2;
		targetURI = targetURI2;
		token = token2;
		ctx = ctx2;
		dontCompress = dontCompress2;
		reportMetadataOnly = reportMetadataOnly2;
		containerItems = new ArrayList<ContainerElement>();
		this.forceCryptoKey = forceCryptoKey;
		this.cryptoAlgorithm = cryptoAlgorithm;
		this.realTimeFlag = realTimeFlag;
	}

	@Override
	public void cancel(ClientContext context) {
		synchronized(this) {
			if(cancelled) return;
			cancelled = true;
		}
		// Must call onFailure so get removeFrom()'ed
		cb.onFailure(new InsertException(InsertExceptionMode.CANCELLED), this, context);
	}

	@Override
	public BaseClientPutter getParent() {
		return parent;
	}

	@Override
	public Object getToken() {
		return token;
	}

	@Override
	public void schedule(ClientContext context) throws InsertException {
		start(context);
	}


	private void start(ClientContext context) {
		if(logDEBUG) Logger.debug(this, "Atempt to start a container inserter", new Exception("debug"));
		
		makeMetadata(context);
		
		synchronized(this) {
			if(finished) return;
		}
		
		InsertBlock block;
		OutputStream os = null;
		try {
		    RandomAccessBucket outputBucket = context.getBucketFactory(persistent).makeBucket(-1);
			os = new BufferedOutputStream(outputBucket.getOutputStream());
			String mimeType = (archiveType == ARCHIVE_TYPE.TAR ?
				createTarBucket(os) :
				createZipBucket(os));
			os = null; // create*Bucket closes os
			if(logMINOR)
				Logger.minor(this, "Archive size is "+outputBucket.size());
			
			if(logMINOR) Logger.minor(this, "We are using "+archiveType);
			
			// Now we have to insert the Archive we have generated.
			
			// Can we just insert it, and not bother with a redirect to it?
			// Thereby exploiting implicit manifest support, which will pick up on .metadata??
			// We ought to be able to !!
			block = new InsertBlock(outputBucket, new ClientMetadata(mimeType), targetURI);
		} catch (IOException e) {
			fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null), context);
			return;
		} finally {
			Closer.close(os);
		}
		
		boolean dc = dontCompress;
		if (!dontCompress) {
			dc = (archiveType == ARCHIVE_TYPE.ZIP);
		}
		
		// Treat it as a splitfile for purposes of determining reinsert count.
		SingleFileInserter sfi = new SingleFileInserter(parent, cb, block, false, ctx, realTimeFlag, reportMetadataOnly, token, archiveType, true, null, true, persistent, 0, 0, null, cryptoAlgorithm, forceCryptoKey, -1);
		if(logMINOR)
			Logger.minor(this, "Inserting container: "+sfi+" for "+this);
		cb.onTransition(this, sfi, context);
		try {
			sfi.schedule(context);
		} catch (InsertException e) {
			fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null), context);
			return;
		}
	}

	private void makeMetadata(ClientContext context) {

		Bucket bucket = null;
		int x = 0;

		Metadata md = makeManifest(origMetadata, "");

		while(true) {
			try {
				bucket = md.toBucket(context.getBucketFactory(persistent));
				containerItems.add(new ContainerElement(bucket, ".metadata"));
				return;
			} catch (MetadataUnresolvedException e) {
				try {
					x = resolve(e, x, null, null, context);
				} catch (IOException e1) {
					fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null), context);
					return;
				}
			} catch (IOException e) {
				fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null), context);
				return;
			}
		}
		
	}

	private int resolve(MetadataUnresolvedException e, int x, FreenetURI key, String element2, ClientContext context) throws IOException {
		Metadata[] metas = e.mustResolve;
		for(Metadata m: metas) {
			try {
				Bucket bucket = m.toBucket(context.getBucketFactory(persistent));
				String nameInArchive = ".metadata-"+(x++);
				containerItems.add(new ContainerElement(bucket, nameInArchive));
				m.resolve(nameInArchive);
			} catch (MetadataUnresolvedException e1) {
				x = resolve(e, x, key, element2, context);
			}
		}
		return x;
	}

	private void fail(InsertException e, ClientContext context) {
		// Cancel all, then call the callback
		synchronized(this) {
			if(finished) return;
			finished = true;
		}
		cb.onFailure(e, this, context);
	}

	// A persistent hashCode is helpful in debugging, and also means we can put
	// these objects into sets etc when we need to.
	
	private final int hashCode;
	
	@Override
	public int hashCode() {
		return hashCode;
	}
	
	/**
	** OutputStream os will be close()d if this method returns successfully.
	*/
	private String createTarBucket(OutputStream os) throws IOException {
		if(logMINOR) Logger.minor(this, "Create a TAR Bucket");
		
		TarArchiveOutputStream tarOS = new TarArchiveOutputStream(os);
		try {
			tarOS.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
			TarArchiveEntry ze;

			for (ContainerElement ph : containerItems) {
				if (logMINOR)
					Logger.minor(this, "Putting into tar: " + ph + " data length " + ph.data.size() + " name " + ph.targetInArchive);
				ze = new TarArchiveEntry(ph.targetInArchive);
				ze.setModTime(0);
				long size = ph.data.size();
				ze.setSize(size);
				tarOS.putArchiveEntry(ze);
				BucketTools.copyTo(ph.data, tarOS, size);
				tarOS.closeArchiveEntry();
			}
		} finally {
			tarOS.close();
		}
		
		return ARCHIVE_TYPE.TAR.mimeTypes[0];
	}
	
	private String createZipBucket(OutputStream os) throws IOException {
		if(logMINOR) Logger.minor(this, "Create a ZIP Bucket");
		
		ZipOutputStream zos = new ZipOutputStream(os);
		try {
			ZipEntry ze;

			for (ContainerElement ph : containerItems) {
				ze = new ZipEntry(ph.targetInArchive);
				ze.setTime(0);
				zos.putNextEntry(ze);
				BucketTools.copyTo(ph.data, zos, ph.data.size());
				zos.closeEntry();
			}
		} finally {
			zos.close();
		}

		return ARCHIVE_TYPE.ZIP.mimeTypes[0];
	}

	private Metadata makeManifest(HashMap<String, Object> manifestElements, String archivePrefix) {
		SimpleManifestComposer smc = new Metadata.SimpleManifestComposer();
		for (Map.Entry<String, Object> me : manifestElements.entrySet()) {
			String name = me.getKey();
			Object o = me.getValue();
			if(o instanceof HashMap) {
				@SuppressWarnings("unchecked")
				HashMap<String,Object> hm = (HashMap<String, Object>) o;
				HashMap<String,Object> subMap = new HashMap<String,Object>();
				//System.out.println("Decompose: "+name+" (SubDir)");
				smc.addItem(name, makeManifest(hm, archivePrefix+name+ '/'));
				if(logDEBUG)
					Logger.debug(this, "Sub map for "+name+" : "+subMap.size()+" elements from "+hm.size());
			} else if (o instanceof Metadata) {
				//already Metadata, take it as is
				//System.out.println("Decompose: "+name+" (Metadata)");
				smc.addItem(name, (Metadata)o);
			} else {
				ManifestElement element = (ManifestElement) o;
				String mimeType = element.getMimeType();
				ClientMetadata cm;
				if(mimeType == null || mimeType.equals(DefaultMIMETypes.DEFAULT_MIME_TYPE))
					cm = null;
				else
					cm = new ClientMetadata(mimeType);
				Metadata m;
				if(element.targetURI != null) {
					//System.out.println("Decompose: "+name+" (ManifestElement, Redirect)");
					m = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, element.targetURI, cm);
				} else {
					//System.out.println("Decompose: "+name+" (ManifestElement, Data)");
					containerItems.add(new ContainerElement(element.getData(), archivePrefix+name));
					m = new Metadata(DocumentType.ARCHIVE_INTERNAL_REDIRECT, null, null, archivePrefix+element.fullName, cm);
				}
				smc.addItem(name, m);
			}
		}
		return smc.getMetadata();
	}
	
	private transient boolean resumed = false;

    @Override
    public void onResume(ClientContext context) throws InsertException, ResumeFailedException {
        synchronized(this) {
            if(resumed) return;
            resumed = true;
        }
        if(cb != null && cb != parent)
            cb.onResume(context);
        if(containerItems != null) {
            for(ContainerElement e : containerItems) {
                if(e.data != null)
                    e.data.onResume(context);
            }
        }
        resumeMetadata(origMetadata, context);
        // Do not call start(). start() immediately transitions to another state.
    }
    
    @SuppressWarnings("unchecked")
    public static void resumeMetadata(Map<String, Object> map, ClientContext context) throws ResumeFailedException {
        Map<String, Object> manifestElements = map;
        for (Object o : manifestElements.values()) {
            if(o instanceof HashMap) {
                resumeMetadata((Map<String, Object>)o, context);
            } else if(o instanceof ManifestElement) {
                ManifestElement e = (ManifestElement) o;
                e.onResume(context);
            } else if(o instanceof Metadata) {
                // Ignore
            } else if(o instanceof PutHandler) {
                PutHandler handler = (PutHandler) o;
                handler.onResume(context);
            } else if(o instanceof ManifestElement) {
                ((ManifestElement)o).onResume(context);
            } else throw new IllegalArgumentException("Unknown manifest element: "+o);
        }
    }

    @Override
    public void onShutdown(ClientContext context) {
        // Ignore.
    }
}
