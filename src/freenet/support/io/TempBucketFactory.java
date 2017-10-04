/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.support.io;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Queue;
import java.util.Random;
import java.util.concurrent.LinkedBlockingQueue;

import freenet.client.async.ClientContext;
import freenet.crypt.EncryptedRandomAccessBucket;
import freenet.crypt.EncryptedRandomAccessBuffer;
import freenet.crypt.EncryptedRandomAccessBufferType;
import freenet.crypt.MasterSecret;
import freenet.support.Executor;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.SizeUtil;
import freenet.support.TimeUtil;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.api.LockableRandomAccessBuffer;
import freenet.support.api.LockableRandomAccessBufferFactory;
import freenet.support.api.RandomAccessBucket;

/**
 * Temporary Bucket Factory
 * 
 * Buckets created by this factory can be either:
 *	- ArrayBuckets
 * OR
 *	- FileBuckets
 * 
 * ArrayBuckets are used if and only if:
 *	1) there is enough room remaining on the pool (@see maxRamUsed and @see bytesInUse)
 *	2) the initial size is smaller than (@maxRAMBucketSize)
 * 
 * Depending on how they are used they might switch from one type to another transparently.
 * 
 * Currently they are two factors considered for a migration:
 *	- if they are long-lived or not (@see RAMBUCKET_MAX_AGE)
 *	- if their size is over RAMBUCKET_CONVERSION_FACTOR*maxRAMBucketSize
 */
public class TempBucketFactory implements BucketFactory, LockableRandomAccessBufferFactory {
	public final static long defaultIncrement = 4096;
	public final static float DEFAULT_FACTOR = 1.25F;
	
	private final FilenameGenerator filenameGenerator;
	private final PooledFileRandomAccessBufferFactory underlyingDiskRAFFactory;
	private final DiskSpaceCheckingRandomAccessBufferFactory diskRAFFactory;
	private volatile long minDiskSpace;
	private long bytesInUse = 0;
	private final Executor executor;
	private volatile boolean reallyEncrypt;
	private final MasterSecret secret;
	
	/** How big can the defaultSize be for us to consider using RAMBuckets? */
	private long maxRAMBucketSize;
	/** How much memory do we dedicate to the RAMBucketPool? (in bytes) */
	private long maxRamUsed;

	/** How old is a long-lived RAMBucket? */
	private final static long RAMBUCKET_MAX_AGE = MINUTES.toMillis(5);
	/** How many times the maxRAMBucketSize can a RAMBucket be before it gets migrated? */
	final static int RAMBUCKET_CONVERSION_FACTOR = 4;
	
	final static boolean TRACE_BUCKET_LEAKS = false;

        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
	private interface Migratable {

        long creationTime();

        boolean migrateToDisk() throws IOException;
	    
	};
	
	public class TempBucket implements Bucket, Migratable, RandomAccessBucket {
		/** The underlying bucket itself */
		private RandomAccessBucket currentBucket;
		/** We have to account the size of the underlying bucket ourself in order to be able to access it fast */
		private long currentSize;
		/** Has an OutputStream been opened at some point? */
		private boolean hasWritten;
		/** A link to the "real" underlying outputStream, even if we migrated */
		private OutputStream os = null;
		/** All the open-streams to reset or close on migration or free() */
		private final ArrayList<TempBucketInputStream> tbis;
		/** An identifier used to know when to deprecate the InputStreams */
		private short osIndex;
		/** A timestamp used to evaluate the age of the bucket and maybe consider it for a migration */
		public final long creationTime;
		private boolean hasBeenFreed = false;
		
		private final Throwable tracer;
		
		public TempBucket(long now, RandomAccessBucket cur) {
			if(cur == null)
				throw new NullPointerException();
			if (TRACE_BUCKET_LEAKS)
				tracer = new Throwable();
			else
				tracer = null;
			this.currentBucket = cur;
			this.creationTime = now;
			this.osIndex = 0;
			this.tbis = new ArrayList<TempBucketInputStream>(1);
			if(logMINOR) Logger.minor(TempBucket.class, "Created "+this, new Exception("debug"));
		}
		
		private synchronized void closeInputStreams(boolean forFree) {
			for(ListIterator<TempBucketInputStream> i = tbis.listIterator(); i.hasNext();) {
				TempBucketInputStream is = i.next();
					if(forFree) {
						i.remove();
						try {
							is.close();
						} catch (IOException e) {
							Logger.error(this, "Caught "+e+" closing "+is);
						}
					} else {
						try {
							is._maybeResetInputStream();
						} catch(IOException e) {
							i.remove();
							Closer.close(is);
						}
					}
			}
		}
		
		/** A blocking method to force-migrate from a RAMBucket to a FileBucket */
		public final boolean migrateToDisk() throws IOException {
			Bucket toMigrate = null;
			long size;
			synchronized(this) {
				if(!isRAMBucket() || hasBeenFreed)
					// Nothing to migrate! We don't want to switch back to ram, do we?					
					return false;
				toMigrate = currentBucket;
				RandomAccessBucket tempFB = _makeFileBucket();
				size = currentSize;
				if(os != null) {
					os.flush();
					os.close();
					// DO NOT INCREMENT THE osIndex HERE!
					os = tempFB.getOutputStreamUnbuffered();
					if(size > 0)
						BucketTools.copyTo(toMigrate, os, size);
				} else {
					if(size > 0) {
						OutputStream temp = tempFB.getOutputStreamUnbuffered();
						try {
						BucketTools.copyTo(toMigrate, temp, size);
						} finally {
						temp.close();
						}
					}
				}
				if(toMigrate.isReadOnly())
					tempFB.setReadOnly();
				
				closeInputStreams(false);
				
				currentBucket = tempFB;
				// We need streams to be reset to point to the new bucket
			}
			if(logMINOR)
				Logger.minor(this, "We have migrated "+toMigrate.hashCode());
			
			synchronized(ramBucketQueue) {
				ramBucketQueue.remove(getReference());
			}
			
			// We can free it on-thread as it's a rambucket
			toMigrate.free();
			// Might have changed already so we can't rely on currentSize!
			_hasFreed(size);
			return true;
		}
		
		public synchronized final boolean isRAMBucket() {
			return (currentBucket instanceof ArrayBucket);
		}
		
		@Override
		public OutputStream getOutputStream() throws IOException {
		    return new BufferedOutputStream(getOutputStreamUnbuffered());
		}

		@Override
		public synchronized OutputStream getOutputStreamUnbuffered() throws IOException {
			if(os != null)
				throw new IOException("Only one OutputStream per bucket on "+this+" !");
			if(hasBeenFreed) throw new IOException("Already freed");
			// Hence we don't need to reset currentSize / _hasTaken() if a bucket is reused.
			// FIXME we should migrate to disk rather than throwing.
			hasWritten = true;
			osIndex++;
			OutputStream tos = new TempBucketOutputStream();
			if(logMINOR)
				Logger.minor(this, "Got "+tos+" for "+this, new Exception());
			return tos;
		}

		private class TempBucketOutputStream extends OutputStream {
		    long lastCheckedSize = 0;
		    long CHECK_DISK_EVERY = 4096;
			boolean closed = false;
			TempBucketOutputStream() throws IOException {
				if(os == null)
					os = currentBucket.getOutputStreamUnbuffered();
			}
			
			private void _maybeMigrateRamBucket(long futureSize) throws IOException {
				if (closed) {
					return;
				}
				if(isRAMBucket()) {
					boolean shouldMigrate = false;
					boolean isOversized = false;
					
					if(futureSize >= Math.min(Integer.MAX_VALUE, maxRAMBucketSize * RAMBUCKET_CONVERSION_FACTOR)) {
						isOversized = true;
						shouldMigrate = true;
					} else if ((futureSize - currentSize) + bytesInUse >= maxRamUsed)
						shouldMigrate = true;
					
					if(shouldMigrate) {
						if(logMINOR) {
							if(isOversized)
								Logger.minor(this, "The bucket "+TempBucket.this+" is over "+SizeUtil.formatSize(maxRAMBucketSize*RAMBUCKET_CONVERSION_FACTOR)+": we will force-migrate it to disk.");
							else
								Logger.minor(this, "The bucketpool is full: force-migrate before we go over the limit");
						}
						migrateToDisk();
					}
				} else {
				    // Check for excess disk usage.
				    if(futureSize - lastCheckedSize >= CHECK_DISK_EVERY) {
				        if(filenameGenerator.getDir().getUsableSpace() + (futureSize - currentSize) <
				                minDiskSpace)
				            throw new InsufficientDiskSpaceException();
				        lastCheckedSize = futureSize;
				    }
				}
			}
			
			@Override
			public final void write(int b) throws IOException {
				synchronized(TempBucket.this) {
                    if(hasBeenFreed) throw new IOException("Already freed");
					long futureSize = currentSize + 1;
					_maybeMigrateRamBucket(futureSize);
					os.write(b);
					currentSize = futureSize;
					if(isRAMBucket()) // We need to re-check because it might have changed!
						_hasTaken(1);
				}
			}
			
			@Override
			public final void write(byte b[], int off, int len) throws IOException {
				synchronized(TempBucket.this) {
				    if(hasBeenFreed) throw new IOException("Already freed");
					long futureSize = currentSize + len;
					_maybeMigrateRamBucket(futureSize);
					os.write(b, off, len);
					currentSize = futureSize;
					if(isRAMBucket()) // We need to re-check because it might have changed!
						_hasTaken(len);
				}
			}
			
			@Override
			public final void flush() throws IOException {
				synchronized(TempBucket.this) {
				    if(hasBeenFreed) return;
					_maybeMigrateRamBucket(currentSize);
					if(!closed)
						os.flush();
				}
			}
			
			@Override
			public final void close() throws IOException {
				synchronized(TempBucket.this) {
					if(closed) return;
					_maybeMigrateRamBucket(currentSize);
					os.flush();
					os.close();
					os = null;
					closed = true;
				}
			}
		}
		
		@Override
		public InputStream getInputStream() throws IOException {
		    return new BufferedInputStream(getInputStreamUnbuffered());
		}

		@Override
		public synchronized InputStream getInputStreamUnbuffered() throws IOException {
			if(!hasWritten)
				throw new IOException("No OutputStream has been openned! Why would you want an InputStream then?");
			if(hasBeenFreed) throw new IOException("Already freed");
			TempBucketInputStream is = new TempBucketInputStream(osIndex);
			tbis.add(is);
			if(logMINOR)
				Logger.minor(this, "Got "+is+" for "+this, new Exception());
			return is;
		}
		
		private class TempBucketInputStream extends InputStream {
			/** The current InputStream we use from the underlying bucket */
			private InputStream currentIS;
			/** Keep a counter to know where we are on the stream (useful when we have to reset and skip) */
			private long index = 0;
			/** Will change if a new OutputStream is openned: used to detect deprecation */
			private final short idx;
			
			TempBucketInputStream(short idx) throws IOException {
				this.idx = idx;
				this.currentIS = currentBucket.getInputStreamUnbuffered();
			}
			
			public void _maybeResetInputStream() throws IOException {
				if(idx != osIndex)
					close();
				else {
					Closer.close(currentIS);
					currentIS = currentBucket.getInputStreamUnbuffered();
					long toSkip = index;
					while(toSkip > 0) {
						toSkip -= currentIS.skip(toSkip);
					}
				}
			}
			
			@Override
			public final int read() throws IOException {
				synchronized(TempBucket.this) {
                    if(hasBeenFreed) throw new IOException("Already freed");
					int toReturn = currentIS.read();
					if(toReturn != -1)
						index++;
					return toReturn;
				}
			}
			
			@Override
			public int read(byte b[]) throws IOException {
				synchronized(TempBucket.this) {
                    if(hasBeenFreed) throw new IOException("Already freed");
					return read(b, 0, b.length);
				}
			}
			
			@Override
			public int read(byte b[], int off, int len) throws IOException {
				synchronized(TempBucket.this) {
                    if(hasBeenFreed) throw new IOException("Already freed");
					int toReturn = currentIS.read(b, off, len);
					if(toReturn > 0)
						index += toReturn;
					return toReturn;
				}
			}
			
			@Override
			public long skip(long n) throws IOException {
				synchronized(TempBucket.this) {
                    if(hasBeenFreed) throw new IOException("Already freed");
					long skipped = currentIS.skip(n);
					index += skipped;
					return skipped;
				}
			}
			
			@Override
			public int available() throws IOException {
				synchronized(TempBucket.this) {
                    if(hasBeenFreed) throw new IOException("Already freed");
					return currentIS.available();
				}
			}
			
			@Override
			public boolean markSupported() {
				return false;
			}
			
			@Override
			public final void close() throws IOException {
				synchronized(TempBucket.this) {
					Closer.close(currentIS);
					tbis.remove(this);
				}
			}
		}

		@Override
		public synchronized String getName() {
			return currentBucket.getName();
		}

		@Override
		public synchronized long size() {
			return currentSize;
		}

		@Override
		public synchronized boolean isReadOnly() {
			return currentBucket.isReadOnly();
		}

		@Override
		public synchronized void setReadOnly() {
			currentBucket.setReadOnly();
		}

		@Override
		public synchronized void free() {
		    Bucket cur;
		    synchronized(this) {
		        if(hasBeenFreed) return;
		        hasBeenFreed = true;
		        
		        Closer.close(os);
		        closeInputStreams(true);
		        if(isRAMBucket()) {
		            // If it's in memory we must free before removing from the queue.
		            currentBucket.free();
		            _hasFreed(currentSize);
		            synchronized(ramBucketQueue) {
		                ramBucketQueue.remove(getReference());
		            }
		            return;
		        } else {
		            // Better to free outside the lock if it's not in-memory.
		            cur = currentBucket;
		        }
		    }
		    cur.free();
		}
		
		/** Called only by TempRandomAccessBuffer */
		private synchronized void onFreed() {
            hasBeenFreed = true;
		}

		@Override
		public RandomAccessBucket createShadow() {
			return currentBucket.createShadow();
		}

		private WeakReference<Migratable> weakRef = new WeakReference<Migratable>(this);

		public WeakReference<Migratable> getReference() {
			return weakRef;
		}
		
		@Override
		protected void finalize() throws Throwable {
		    // If it's been converted to a TempRandomAccessBuffer, finalize() will only be called 
		    // if *neither* object is reachable.
			if (!hasBeenFreed) {
				if (TRACE_BUCKET_LEAKS)
					Logger.error(this, "TempBucket not freed, size=" + size() + ", isRAMBucket=" + isRAMBucket()+" : "+this, tracer);
				else
				    Logger.error(this, "TempBucket not freed, size=" + size() + ", isRAMBucket=" + isRAMBucket()+" : "+this);
				free();
			}
                        super.finalize();
		}

        @Override
        public long creationTime() {
            return creationTime;
        }

        @Override
        public void onResume(ClientContext context) {
            // Not persistent.
            throw new IllegalStateException();
        }

        @Override
        public void storeTo(DataOutputStream dos) throws IOException {
            throw new UnsupportedOperationException(); // Not persistent.
        }

        @Override
        public LockableRandomAccessBuffer toRandomAccessBuffer() throws IOException {
            synchronized(this) {
                if(hasBeenFreed) throw new IOException("Already freed");
                if(os != null) throw new IOException("Can't migrate with open OutputStream's");
                if(!tbis.isEmpty()) throw new IOException("Can't migrate with open InputStream's");
                setReadOnly();
                TempRandomAccessBuffer raf = new TempRandomAccessBuffer(currentBucket.toRandomAccessBuffer(), creationTime, !isRAMBucket(), this);
                if(isRAMBucket()) {
                    synchronized(ramBucketQueue) {
                        // No change in space usage.
                        ramBucketQueue.remove(getReference());
                        ramBucketQueue.add(raf.getReference());
                    }
                }
                currentBucket = new RAFBucket(raf);
                return raf;
            }
        }

        /** Only for testing */
        synchronized Bucket getUnderlying() {
            return currentBucket;
        }
	}
	
	// Storage accounting disabled by default.
	public TempBucketFactory(Executor executor, FilenameGenerator filenameGenerator, long maxBucketSizeKeptInRam, long maxRamUsed, Random weakPRNG, boolean reallyEncrypt, long minDiskSpace, MasterSecret masterSecret) {
		this.filenameGenerator = filenameGenerator;
		this.maxRamUsed = maxRamUsed;
		this.maxRAMBucketSize = maxBucketSizeKeptInRam;
		this.reallyEncrypt = reallyEncrypt;
		this.executor = executor;
		this.underlyingDiskRAFFactory = new PooledFileRandomAccessBufferFactory(filenameGenerator, weakPRNG);
		underlyingDiskRAFFactory.enableCrypto(reallyEncrypt);
		this.minDiskSpace = minDiskSpace;
		this.diskRAFFactory = new DiskSpaceCheckingRandomAccessBufferFactory(underlyingDiskRAFFactory, 
		        filenameGenerator.getDir(), minDiskSpace - maxRamUsed);
		this.secret = masterSecret;
	}
	
	private synchronized void _hasTaken(long size) {
		bytesInUse += size;
	}
	
	private synchronized void _hasFreed(long size) {
		bytesInUse -= size;
	}
	
	public synchronized long getRamUsed() {
		return bytesInUse;
	}
	
	public synchronized void setMaxRamUsed(long size) {
		maxRamUsed = size;
	}
	
	public synchronized long getMaxRamUsed() {
		return maxRamUsed;
	}
	
	public synchronized void setMaxRAMBucketSize(long size) {
		maxRAMBucketSize = size;
		diskRAFFactory.setMinDiskSpace(minDiskSpace - maxRamUsed);
	}
	
	public synchronized long getMaxRAMBucketSize() {
		return maxRAMBucketSize;
	}
	
	public void setEncryption(boolean value) {
	    reallyEncrypt = value;
		underlyingDiskRAFFactory.enableCrypto(value);
	}
	
	public synchronized void setMinDiskSpace(long min) {
	    minDiskSpace = min;
	    diskRAFFactory.setMinDiskSpace(minDiskSpace - maxRamUsed);
	}
	
	public boolean isEncrypting() {
	    return reallyEncrypt;
	}

	static final double MAX_USAGE_LOW = 0.8;
	static final double MAX_USAGE_HIGH = 0.9;
    public static final EncryptedRandomAccessBufferType CRYPT_TYPE = EncryptedRandomAccessBufferType.ChaCha128;
	
	/**
	 * Create a temp bucket
	 * 
	 * @param size
	 *            Maximum size
	 * @return A temporary Bucket
	 * @exception IOException
	 *                If it is not possible to create a temp bucket due to an
	 *                I/O error
	 */
	public TempBucket makeBucket(long size) throws IOException {
		RandomAccessBucket realBucket = null;
		boolean useRAMBucket = false;
		long now = System.currentTimeMillis();
		
		synchronized(this) {
			if((size > 0) && (size <= maxRAMBucketSize) && (bytesInUse < maxRamUsed) && (bytesInUse + size <= maxRamUsed)) {
				useRAMBucket = true;
			}
			if(bytesInUse >= maxRamUsed * MAX_USAGE_HIGH && !runningCleaner) {
				runningCleaner = true;
				executor.execute(cleaner);
			}
		}
		
		// Do we want a RAMBucket or a FileBucket?
		realBucket = (useRAMBucket ? new ArrayBucket() : _makeFileBucket());
		
		TempBucket toReturn = new TempBucket(now, realBucket);
		if(useRAMBucket) { // No need to consider them for migration if they can't be migrated
			synchronized(ramBucketQueue) {
				ramBucketQueue.add(toReturn.getReference());
			}
		} else {
		    // If we know the disk space requirement in advance, check it.
		    if(size != -1 && size != Long.MAX_VALUE) {
		        if(filenameGenerator.getDir().getUsableSpace() + size < minDiskSpace)
		            throw new InsufficientDiskSpaceException();
		    }
		}
		return toReturn;
}
	
	boolean runningCleaner = false;
	
	private final Runnable cleaner = new Runnable() {

		@Override
		public void run() {
		    boolean saidSo = false;
			try {
				long now = System.currentTimeMillis();
				// First migrate all the old buckets.
				while(true) {
				    try {
                        cleanBucketQueue(now, false);
                    } catch (InsufficientDiskSpaceException e) {
                        if(!saidSo) {
                            Logger.error(this, "Insufficient disk space to migrate in-RAM buckets to disk!");
                            System.err.println("Out of disk space!");
                            saidSo = true;
                        }
                        try {
                            Thread.sleep(1000);
                        } catch (InterruptedException e1) {
                            // Ignore.
                        }
                        continue;
                    }
				    break;
				}
				saidSo = false;
				while(true) {
					// Now migrate buckets until usage is below the lower threshold.
					synchronized(TempBucketFactory.this) {
						if(bytesInUse <= maxRamUsed * MAX_USAGE_LOW) return;
					}
					try {
                        if(!cleanBucketQueue(System.currentTimeMillis(), true)) return;
                    } catch (InsufficientDiskSpaceException e) {
                        if(!saidSo) {
                            Logger.error(this, "Insufficient disk space to migrate in-RAM buckets to disk!");
                            System.err.println("Out of disk space!");
                            saidSo = true;
                        }
                        try {
                            Thread.sleep(1000);
                        } catch (InterruptedException e1) {
                            // Ignore.
                        }
                    }
				}
			} finally {
				synchronized(TempBucketFactory.this) {
					runningCleaner = false;
				}
			}
		}
		
	};
	
	/** Migrate all long-lived buckets from the queue.
	 * @param now The current time (System.currentTimeMillis()).
	 * @param force If true, migrate one bucket which isn't necessarily long lived, 
	 * just to free up space. Otherwise we will migrate all long-lived buckets but
	 * not any others. 
	 * @return True if we migrated any buckets.
	 * @throws InsufficientSpaceException If there is not enough space to migrate buckets to disk.
	 */
	private boolean cleanBucketQueue(long now, boolean force) throws InsufficientDiskSpaceException {
		boolean shouldContinue = true;
		// create a new list to avoid race-conditions
		Queue<Migratable> toMigrate = null;
                if(logMINOR)
			Logger.minor(this, "Starting cleanBucketQueue");
		do {
			synchronized(ramBucketQueue) {
				final WeakReference<Migratable> tmpBucketRef = ramBucketQueue.peek();
				if (tmpBucketRef == null)
					shouldContinue = false;
				else {
					Migratable tmpBucket = tmpBucketRef.get();
					if (tmpBucket == null) {
						ramBucketQueue.remove(tmpBucketRef);
						continue; // ugh. this is freed
					}

					// Don't access the buckets inside the lock, will deadlock.
					if (tmpBucket.creationTime() + RAMBUCKET_MAX_AGE > now && !force)
						shouldContinue = false;
					else {
						if (logMINOR)
							Logger.minor(this, "The bucket "+tmpBucket+" is " + TimeUtil.formatTime(now - tmpBucket.creationTime())
							        + " old: we will force-migrate it to disk.");
						ramBucketQueue.remove(tmpBucketRef);
						if(toMigrate == null) toMigrate = new LinkedList<Migratable>();
						toMigrate.add(tmpBucket);
						force = false;
					}
				}
			}
		} while(shouldContinue);

		if(toMigrate == null) return false;
		if(toMigrate.size() > 0) {
			if(logMINOR)
				Logger.minor(this, "We are going to migrate " + toMigrate.size() + " RAMBuckets");
			for(Migratable tmpBucket : toMigrate) {
				try {
					tmpBucket.migrateToDisk();
				} catch (InsufficientDiskSpaceException e) {
				    throw e;
				} catch(IOException e) {
					Logger.error(tmpBucket, "An IOE occured while migrating long-lived buckets:" + e.getMessage(), e);
				}
			}
			return true;
		}
		return false;
	}
	
	private final Queue<WeakReference<Migratable>> ramBucketQueue = new LinkedBlockingQueue<WeakReference<Migratable>>();
	
	private RandomAccessBucket _makeFileBucket() throws IOException {
		RandomAccessBucket ret = new TempFileBucket(filenameGenerator.makeRandomFilename(), filenameGenerator, true);
		// Do we want it to be encrypted?
		if(reallyEncrypt) {
            ret = new PaddedRandomAccessBucket(ret);
		    ret = new EncryptedRandomAccessBucket(CRYPT_TYPE, ret, secret);
		}
		return ret;
	}
	
	/** Unlike a TempBucket, the size is fixed, so migrate only happens on the migration thread. */
	class TempRandomAccessBuffer extends SwitchableProxyRandomAccessBuffer implements Migratable {
	    
	    protected boolean hasMigrated = false;
	    /** If false, there is in-memory storage that needs to be freed. */
	    private boolean hasFreedRAM = false;
	    private final long creationTime;
	    /** Kept in RAM so that finalizer is called on the TempBucket when *both* the 
	     * TempRandomAccessBuffer *and* the TempBucket are no longer reachable, in which case we
	     * will free from the TempBucket. If this is null, then the TempRAB can free in finalizer. 
	     */
	    private final TempBucket original;
	    
	    /** For debugging leaks if TRACE_BUCKET_LEAKS is enabled */
	    private final Throwable tracer;
	    
	    TempRandomAccessBuffer(int size, long time) throws IOException {
	        super(new ByteArrayRandomAccessBuffer(size), size);
	        creationTime = time;
	        hasMigrated = false;
	        original = null;
            if (TRACE_BUCKET_LEAKS)
                tracer = new Throwable();
            else
                tracer = null;
	    }

        public TempRandomAccessBuffer(byte[] initialContents, int offset, int size, long time, boolean readOnly) throws IOException {
            super(new ByteArrayRandomAccessBuffer(initialContents, offset, size, readOnly), size);
            creationTime = time;
            hasMigrated = false;
            original = null;
            if (TRACE_BUCKET_LEAKS)
                tracer = new Throwable();
            else
                tracer = null;
        }

        public TempRandomAccessBuffer(LockableRandomAccessBuffer underlying, long creationTime, boolean migrated, TempBucket tempBucket) throws IOException {
            super(underlying, underlying.size());
            this.creationTime = creationTime;
            this.hasMigrated = hasFreedRAM = migrated;
            this.original = tempBucket;
            if (TRACE_BUCKET_LEAKS)
                tracer = new Throwable();
            else
                tracer = null;
        }

        @Override
        protected LockableRandomAccessBuffer innerMigrate(LockableRandomAccessBuffer underlying) throws IOException {
            ByteArrayRandomAccessBuffer b = (ByteArrayRandomAccessBuffer)underlying;
            byte[] buf = b.getBuffer();
            return diskRAFFactory.makeRAF(buf, 0, (int)size, b.isReadOnly());
        }

        @Override
        public void free() {
            if(!super.innerFree()) return;
            if(logMINOR) Logger.minor(this, "Freed "+this, new Exception("debug"));
            if(original != null) {
                // Tell the TempBucket to prevent log spam. Don't call free().
                original.onFreed();
            }
        }
        
        @Override
        protected void afterFreeUnderlying() {
            // Called when the in-RAM storage has been freed.
            synchronized(this) {
                if(hasFreedRAM) return;
                hasFreedRAM = true;
            }
            _hasFreed(size);
            synchronized(ramBucketQueue) {
                ramBucketQueue.remove(getReference());
            }
        }
        
        private WeakReference<Migratable> weakRef = new WeakReference<Migratable>(this);

        public WeakReference<Migratable> getReference() {
            return weakRef;
        }

        @Override
        public long creationTime() {
            return creationTime;
        }

        @Override
        public boolean migrateToDisk() throws IOException {
            synchronized(this) {
                if(hasMigrated) return false;
                hasMigrated = true;
            }
            migrate();
            return true;
        }

        public synchronized boolean hasMigrated() {
            return hasMigrated;
        }

        @Override
        public void onResume(ClientContext context) {
            // Not persistent.
            throw new UnsupportedOperationException();
        }

        @Override
        public void storeTo(DataOutputStream dos) throws IOException {
            throw new UnsupportedOperationException();
        }
        
        @Override
        protected void finalize() throws Throwable {
            if(original != null) return; // TempBucket's responsibility if there was one.
            // If it's been converted to a TempRandomAccessBuffer, finalize() will only be called 
            // if *neither* object is reachable.
            if (!hasBeenFreed()) {
                if (TRACE_BUCKET_LEAKS)
                    Logger.error(this, "TempRandomAccessBuffer not freed, size=" + size() +" : "+this, tracer);
                else
                    Logger.error(this, "TempRandomAccessBuffer not freed, size=" + size() +" : "+this);
                free();
            }
            super.finalize();
        }

	}

	@Override
    public LockableRandomAccessBuffer makeRAF(long size) throws IOException {
	    if(size < 0) throw new IllegalArgumentException();
	    if(size > Integer.MAX_VALUE) return diskRAFFactory.makeRAF(size);
	    
	    long now = System.currentTimeMillis();
	    
	    TempRandomAccessBuffer raf = null;
	    
	    synchronized(this) {
	        if((size > 0) && (size <= maxRAMBucketSize) && (bytesInUse < maxRamUsed) && (bytesInUse + size <= maxRamUsed)) {
	            raf = new TempRandomAccessBuffer((int)size, now);
	            bytesInUse += size;
	        }
	        if(bytesInUse >= maxRamUsed * MAX_USAGE_HIGH && !runningCleaner) {
	            runningCleaner = true;
	            executor.execute(cleaner);
	        }
	    }
	    
	    if(raf != null) {
            synchronized(ramBucketQueue) {
                ramBucketQueue.add(raf.getReference());
            }
            return raf;
	    } else {
	        boolean encrypt;
	        encrypt = this.reallyEncrypt;
	        long realSize = size;
	        long paddedSize = size;
	        if(encrypt) {
	            realSize += TempBucketFactory.CRYPT_TYPE.headerLen;
	            paddedSize = PaddedEphemerallyEncryptedBucket.paddedLength(realSize, PaddedEphemerallyEncryptedBucket.MIN_PADDED_SIZE);
	        }
	        LockableRandomAccessBuffer ret = diskRAFFactory.makeRAF(paddedSize);
	        if(encrypt) {
	            if(realSize != paddedSize)
	                ret = new PaddedRandomAccessBuffer(ret, realSize);
	            try {
	                ret = new EncryptedRandomAccessBuffer(CRYPT_TYPE, ret, secret, true);
	            } catch (GeneralSecurityException e) {
	                Logger.error(this, "Cannot create encrypted tempfile: "+e, e);
	            }
	        }
	        return ret;
	    }
    }

    @Override
    public LockableRandomAccessBuffer makeRAF(byte[] initialContents, int offset, int size, boolean readOnly)
            throws IOException {
        if(size < 0) throw new IllegalArgumentException();
        
        long now = System.currentTimeMillis();
        
        TempRandomAccessBuffer raf = null;
        
        synchronized(this) {
            if((size > 0) && (size <= maxRAMBucketSize) && (bytesInUse < maxRamUsed) && (bytesInUse + size <= maxRamUsed)) {
                raf = new TempRandomAccessBuffer(initialContents, offset, size, now, readOnly);
                bytesInUse += size;
            }
            if(bytesInUse >= maxRamUsed * MAX_USAGE_HIGH && !runningCleaner) {
                runningCleaner = true;
                executor.execute(cleaner);
            }
        }
        
        if(raf != null) {
            synchronized(ramBucketQueue) {
                ramBucketQueue.add(raf.getReference());
            }
            return raf;
        } else {
            if(reallyEncrypt) {
                // FIXME do the encryption in memory? Test it ...
                LockableRandomAccessBuffer ret = makeRAF(size);
                ret.pwrite(0, initialContents, offset, size);
                if(readOnly) ret = new ReadOnlyRandomAccessBuffer(ret);
                return ret;
            }
            return diskRAFFactory.makeRAF(initialContents, offset, size, readOnly);
        }
    }

    public DiskSpaceCheckingRandomAccessBufferFactory getUnderlyingRAFFactory() {
        return diskRAFFactory;
    }
}
