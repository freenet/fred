/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.async;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashSet;

import freenet.keys.ClientKeyBlock;
import freenet.keys.Key;
import freenet.support.Logger;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.io.BucketTools;

/**
 * Helper class to write FBlobs. Threadsafe, allows multiple getters to
 * write to the same BinaryBlobWriter.
 *
 * @author saces
 */
public final class BinaryBlobWriter {
    
    private static volatile boolean logMINOR;

    static {
        Logger.registerClass(BinaryBlobWriter.class);
    }
    
	private final HashSet<Key> _binaryBlobKeysAddedAlready;
	private final BucketFactory _bf;
	private final ArrayList<Bucket> _buckets;
	private final Bucket _out;
	private final boolean _isSingleBucket;

	private boolean _started = false;
	private boolean _finalized = false;

	private transient DataOutputStream _stream_cache = null;

	/**
	 * Persistent/'BigFile' constructor
	 * @param bf BucketFactory to generate internal buckets from
	 */
	public BinaryBlobWriter(BucketFactory bf) {
		_binaryBlobKeysAddedAlready = new HashSet<Key>();
		_buckets = new ArrayList<Bucket>();
		_bf = bf;
		_out = null;
		_isSingleBucket = false;
	}

	/**
	 * Transient constructor
	 * @param out Bucket to write the result to
	 */
	public BinaryBlobWriter(Bucket out) {
		_binaryBlobKeysAddedAlready = new HashSet<Key>();
		_buckets = null;
		_bf = null;
		assert out != null;
		_out = out;
		_isSingleBucket = true;
	}

	private DataOutputStream getOutputStream() throws IOException, BinaryBlobAlreadyClosedException {
		if (_finalized) {
			throw new BinaryBlobAlreadyClosedException("Already finalized (getting final data) on "+this);
		}
		if (_stream_cache==null) {
			if (_isSingleBucket) {
				_stream_cache = new DataOutputStream(_out.getOutputStream());
			} else {
				Bucket newBucket = _bf.makeBucket(-1);
				_buckets.add(newBucket);
				_stream_cache = new DataOutputStream(newBucket.getOutputStream());
			}
		}
		if (!_started) {
			BinaryBlob.writeBinaryBlobHeader(_stream_cache);
			_started = true;
		}
		return _stream_cache;
	}

	/**
	 * Add a block to the binary blob.
	 * @throws IOException
	 * @throws BinaryBlobAlreadyClosedException 
	 */
	public synchronized void addKey(ClientKeyBlock block) throws IOException, BinaryBlobAlreadyClosedException {
		Key key = block.getKey();
		if(_binaryBlobKeysAddedAlready.contains(key)) return;
		BinaryBlob.writeKey(getOutputStream(), block.getBlock(), key);
		_binaryBlobKeysAddedAlready.add(key);
	}

	/**
	 * finalize the return bucket
	 * @throws IOException
	 * @throws BinaryBlobAlreadyClosedException 
	 */
	public void finalizeBucket() throws IOException, BinaryBlobAlreadyClosedException {
		if (_finalized) {
			throw new BinaryBlobAlreadyClosedException("Already finalized (closing blob).");
		}
		finalizeBucket(true);
	}

	private void finalizeBucket(boolean mark) throws IOException, BinaryBlobAlreadyClosedException {
		if (_finalized) throw new BinaryBlobAlreadyClosedException("Already finalized (closing blob - 2).");
		if(logMINOR) Logger.minor(this, "Finalizing binary blob "+this, new Exception("debug"));
		if (!_isSingleBucket) {
			if (!mark && (_buckets.size()==1)) {
				return;
			}
			Bucket out = _bf.makeBucket(-1);
			getSnapshot(out, mark);
			for (int i=0,n=_buckets.size(); i<n;i++) {
				_buckets.get(i).free();
			}
			if (mark) {
				out.setReadOnly();
			}
			_buckets.clear();
			_buckets.add(0, out);
		} else if (mark){
			DataOutputStream out = new DataOutputStream(getOutputStream());
			try {
			BinaryBlob.writeEndBlob(out);
			} finally {
			out.close();
			}
		}
		if (mark) {
			_finalized = true;
		}
	}

	public synchronized void getSnapshot(Bucket bucket) throws IOException, BinaryBlobAlreadyClosedException {
		if (_buckets.isEmpty()) return;
		if (_finalized) {
			BucketTools.copy(_buckets.get(0), bucket);
			return;
		}
		getSnapshot(bucket, true);
	}

	private void getSnapshot(Bucket bucket, boolean addEndmarker) throws IOException, BinaryBlobAlreadyClosedException {
		if (_buckets.isEmpty()) return;
		if (_finalized) {
			throw new BinaryBlobAlreadyClosedException("Already closed (getting final data snapshot)");
		}
		OutputStream out = bucket.getOutputStream();
		try {
		for (int i=0,n=_buckets.size(); i<n;i++) {
			BucketTools.copyTo(_buckets.get(i), out, -1);
		}
		if (addEndmarker) {
			DataOutputStream dout = new DataOutputStream(out);
			BinaryBlob.writeEndBlob(dout);
			dout.flush();
		}
		} finally {
			out.close();
		}
	}

	public synchronized Bucket getFinalBucket() {
		if (!_finalized) {
			throw new IllegalStateException("Not finalized!");
		}
		if (_isSingleBucket) {
			return _out;
		} else {
			return _buckets.get(0);
		}
	}

	public static class BinaryBlobAlreadyClosedException extends Exception {

		private static final long serialVersionUID = -1L;

		public BinaryBlobAlreadyClosedException(String message) {
			super(message);
		}
		
	}

	public boolean isFinalized() {
		return _finalized;
	}
}
