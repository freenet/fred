package freenet.client.async;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.crypt.HashResult;
import freenet.crypt.MultiHashInputStream;
import freenet.keys.CHKBlock;
import freenet.keys.SSKBlock;
import freenet.node.PrioRunnable;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.api.RandomAccessBucket;
import freenet.support.compress.CompressJob;
import freenet.support.compress.CompressionOutputSizeException;
import freenet.support.compress.InvalidCompressionCodecException;
import freenet.support.compress.Compressor.COMPRESSOR_TYPE;
import freenet.support.io.Closer;
import freenet.support.io.NativeThread;

/**
 * Compress a file in order to insert it. This class acts as a tag in the database to ensure that inserts
 * are not forgotten about, and also can be run on a non-database thread from an executor.
 * 
 * @author toad
 */
public class InsertCompressor implements CompressJob {
	
	/** The SingleFileInserter we report to. We were created by it and when we have compressed our data we will
	 * call a method to process it and schedule the data. */
	public final SingleFileInserter inserter;
	/** The original data */
	final RandomAccessBucket origData;
	/** If we can get it into one block, don't compress any further */
	public final int minSize;
	/** BucketFactory */
	public final BucketFactory bucketFactory;
	public final boolean persistent;
	public final String compressorDescriptor;
	private transient boolean scheduled;
	private static volatile boolean logMINOR;
	private final long generateHashes;
	private final boolean pre1254;
	
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
	
	public InsertCompressor(SingleFileInserter inserter2, RandomAccessBucket origData2, int minSize2, BucketFactory bf, boolean persistent, long generateHashes, boolean pre1254) {
		this.inserter = inserter2;
		this.origData = origData2;
		this.minSize = minSize2;
		this.bucketFactory = bf;
		this.persistent = persistent;
		this.compressorDescriptor = inserter.ctx.compressorDescriptor;
		this.generateHashes = generateHashes;
		this.pre1254 = pre1254;
	}

	public void init(final ClientContext ctx) {
		synchronized(this) {
			// Can happen with the above activation and lazy query evaluation.
			if(scheduled) {
				Logger.error(this, "Already scheduled compression, not rescheduling");
				return;
			}
			scheduled = true;
		}
		if(logMINOR)
			Logger.minor(this, "Compressing "+this+" : origData.size="+origData.size()+" for "+inserter+" origData="+origData+" hashes="+generateHashes);
		ctx.rc.enqueueNewJob(this);
	}

	@Override
	public void tryCompress(final ClientContext context) throws InsertException {
		long origSize = origData.size();
		long origNumberOfBlocks = origSize/CHKBlock.DATA_LENGTH;
		COMPRESSOR_TYPE bestCodec = null;
		RandomAccessBucket bestCompressedData = origData;
		long bestCompressedDataSize = origSize;
		long bestNumberOfBlocks = origNumberOfBlocks;
		
		HashResult[] hashes = null;
		
		if(logMINOR) Logger.minor(this, "Attempt to compress the data");
		// Try to compress the data.
		// Try each algorithm, starting with the fastest and weakest.
		// Stop when run out of algorithms, or the compressed data fits in a single block.
		try {
			COMPRESSOR_TYPE[] comps = COMPRESSOR_TYPE.getCompressorsArray(compressorDescriptor, pre1254);
			boolean first = true;
			for (final COMPRESSOR_TYPE comp : comps) {
				boolean shouldFreeOnFinally = true;
				RandomAccessBucket result = null;
				try {
					if(logMINOR)
						Logger.minor(this, "Attempt to compress using " + comp);
					// Only produce if we are compressing *the original data*
					if(persistent) {
						context.jobRunner.queue(new PersistentJob() {

							@Override
							public boolean run(ClientContext context) {
								inserter.onStartCompression(comp, context);
								return false;
							}

						}, NativeThread.NORM_PRIORITY+1);
					} else {
						try {
							inserter.onStartCompression(comp, context);
						} catch (Throwable t) {
							Logger.error(this, "Transient insert callback threw "+t, t);
						}
					}

					InputStream is = null;
					OutputStream os = null;
					MultiHashInputStream hasher = null;
					try {
						is = origData.getInputStream();
						result = bucketFactory.makeBucket(-1);
						os = result.getOutputStream();
						if(first && generateHashes != 0) {
							if(logMINOR) Logger.minor(this, "Generating hashes: "+generateHashes);
							is = hasher = new MultiHashInputStream(is, generateHashes);
						}
						try {
							comp.compress(is, os, origSize, bestCompressedDataSize);
						} catch (RuntimeException e) {
							// ArithmeticException has been seen in bzip2 codec.
							Logger.error(this, "Compression failed with codec "+comp+" : "+e, e);
							// Try the next one
							// RuntimeException is iffy, so lets not try the hasher.
							continue;
						} catch (CompressionOutputSizeException e) {
							if(hasher != null) {
								is.skip(Long.MAX_VALUE);
								hashes = hasher.getResults();
								first = false;
							}
							continue; // try next compressor type
						}
						if(hasher != null) {
							hashes = hasher.getResults();
							first = false;
						}
					} finally {
						Closer.close(is);
						Closer.close(os);
					}
					long resultSize = result.size();
					long resultNumberOfBlocks = resultSize/CHKBlock.DATA_LENGTH;
					// minSize is {SSKBlock,CHKBlock}.MAX_COMPRESSED_DATA_LENGTH
					if(resultSize <= minSize) {
						if(logMINOR)
							Logger.minor(this, "New size " + resultSize + " smaller then minSize "
											   + minSize);

						bestCodec = comp;
						if(bestCompressedData != null && bestCompressedData != origData)
							// Don't need to removeFrom() : we haven't stored it.
							bestCompressedData.free();
						bestCompressedData = result;
						bestCompressedDataSize = resultSize;
						bestNumberOfBlocks = resultNumberOfBlocks;
						shouldFreeOnFinally = false;
						break;
					}
					if(resultNumberOfBlocks < bestNumberOfBlocks) {
						if(logMINOR)
							Logger.minor(this, "New size "+resultSize+" ("+resultNumberOfBlocks+" blocks) better than old best "+bestCompressedDataSize+ " ("+bestNumberOfBlocks+" blocks)");
						if(bestCompressedData != null && bestCompressedData != origData)
							bestCompressedData.free();
						bestCompressedData = result;
						bestCompressedDataSize = resultSize;
						bestNumberOfBlocks = resultNumberOfBlocks;
						bestCodec = comp;
						shouldFreeOnFinally = false;
					}
				} catch (PersistenceDisabledException e) {
				    if(!context.jobRunner.shuttingDown())
				        Logger.error(this, "Database disabled compressing data", new Exception("error"));
					shouldFreeOnFinally = true;
					if(bestCompressedData != null && bestCompressedData != origData && bestCompressedData != result)
						bestCompressedData.free();
				} finally {
					if(shouldFreeOnFinally && (result != null) && result != origData)
						result.free();
				}
			}
			
			final CompressionOutput output = new CompressionOutput(bestCompressedData, bestCodec, hashes);
			
			if(persistent) {
			
				context.jobRunner.queue(new PersistentJob() {
					
				    // This can wait until after the next checkpoint, because it's still in the
				    // persistentInsertCompressors list, so will be restarted if necessary.
					@Override
					public boolean run(ClientContext context) {
						inserter.onCompressed(output, context);
						return true;
					}
					
				}, NativeThread.NORM_PRIORITY+1);
			} else {
				// We do it off thread so that RealCompressor can release the semaphore
				context.mainExecutor.execute(new PrioRunnable() {

					@Override
					public int getPriority() {
						return NativeThread.NORM_PRIORITY;
					}

					@Override
					public void run() {
						try {
							inserter.onCompressed(output, context);
						} catch (Throwable t) {
							Logger.error(this, "Caught "+t+" running compression job", t);
						}
					}
					
				}, "Insert thread for "+this);
			}
		} catch (PersistenceDisabledException e) {
			Logger.error(this, "Database disabled compressing data", new Exception("error"));
			if(bestCompressedData != null && bestCompressedData != origData)
				bestCompressedData.free();
		} catch (InvalidCompressionCodecException e) {
			fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR, e, null), context, bestCompressedData);
		} catch (final IOException e) {
			fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null), context, bestCompressedData);
		}	
	}

	private void fail(final InsertException ie, ClientContext context, Bucket bestCompressedData) {
		if(persistent) {
			try {
				context.jobRunner.queue(new PersistentJob() {
					
					@Override
					public boolean run(ClientContext context) {
						inserter.cb.onFailure(ie, inserter, context);
						return true;
					}
					
				}, NativeThread.NORM_PRIORITY+1);
			} catch (PersistenceDisabledException e1) {
				Logger.error(this, "Database disabled compressing data", new Exception("error"));
				if(bestCompressedData != null && bestCompressedData != origData)
					bestCompressedData.free();
			}
		} else {
			inserter.cb.onFailure(ie, inserter, context);
		}
	}

	/**
	 * Create an InsertCompressor, add it to the database, schedule it.
	 * @param ctx
	 * @param inserter
	 * @param origData
	 * @param minSize
	 * @param bf
	 * @param persistent
	 * @param generateHashes
	 * @param pre1254
	 * @return
	 */
	public static InsertCompressor start(ClientContext ctx, SingleFileInserter inserter, 
	        RandomAccessBucket origData, int minSize, BucketFactory bf, boolean persistent, long generateHashes, boolean pre1254) {
		InsertCompressor compressor = new InsertCompressor(inserter, origData, minSize, bf, persistent, generateHashes, pre1254);
		compressor.init(ctx);
		return compressor;
	}

	@Override
	public void onFailure(final InsertException e, ClientContext context) {
		if(persistent) {
			try {
				context.jobRunner.queue(new PersistentJob() {
					
					@Override
					public boolean run(ClientContext context) {
						inserter.cb.onFailure(e, inserter, context);
						return true;
					}
					
				}, NativeThread.NORM_PRIORITY+1);
			} catch (PersistenceDisabledException e1) {
				// Can't do anything
			}
		} else {
			inserter.cb.onFailure(e, inserter, context);
		}
		
	}

}
