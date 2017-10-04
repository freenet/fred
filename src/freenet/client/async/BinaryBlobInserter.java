package freenet.client.async;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;

import freenet.client.FailureCodeTracker;
import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.keys.CHKBlock;
import freenet.keys.ClientKey;
import freenet.keys.Key;
import freenet.keys.KeyBlock;
import freenet.keys.SSKBlock;
import freenet.node.LowLevelPutException;
import freenet.node.RequestClient;
import freenet.node.SendableRequestItem;
import freenet.node.SimpleSendableInsert;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.api.Bucket;

public class BinaryBlobInserter implements ClientPutState {

	final ClientPutter parent;
	final RequestClient clientContext;
	final MySendableInsert[] inserters;
	final FailureCodeTracker errors;
	final int maxRetries;
	final int consecutiveRNFsCountAsSuccess;
	private boolean logMINOR;
	private int completedBlocks;
	private int succeededBlocks;
	private boolean fatal;
	final InsertContext ctx;
	final boolean realTimeFlag;

	BinaryBlobInserter(Bucket blob, ClientPutter parent, RequestClient clientContext, boolean tolerant, short prioClass, InsertContext ctx, ClientContext context)
	throws IOException, BinaryBlobFormatException {
		logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
		this.ctx = ctx;
		this.maxRetries = ctx.maxInsertRetries;
		this.consecutiveRNFsCountAsSuccess = ctx.consecutiveRNFsCountAsSuccess;
		this.parent = parent;
		this.clientContext = clientContext;
		this.errors = new FailureCodeTracker(true);
		this.realTimeFlag = clientContext.realTimeFlag();
		DataInputStream dis = new DataInputStream(blob.getInputStream());

		BlockSet blocks = new SimpleBlockSet();

		try {
			BinaryBlob.readBinaryBlob(dis, blocks, tolerant);
		} finally {
			dis.close();
		}

		ArrayList<MySendableInsert> myInserters = new ArrayList<MySendableInsert>();
		int x=0;
		for(Key key: blocks.keys()) {
			KeyBlock block = blocks.get(key);
			MySendableInsert inserter =
				new MySendableInsert(x++, block, prioClass, getScheduler(block, context), clientContext);
			myInserters.add(inserter);
		}

		inserters = myInserters.toArray(new MySendableInsert[myInserters.size()]);
		parent.addMustSucceedBlocks(inserters.length);
		parent.notifyClients(context);
	}

	private ClientRequestScheduler getScheduler(KeyBlock block, ClientContext context) {
		if(block instanceof CHKBlock)
			return context.getChkInsertScheduler(realTimeFlag);
		else if(block instanceof SSKBlock)
			return context.getSskInsertScheduler(realTimeFlag);
		else throw new IllegalArgumentException("Unknown block type "+block.getClass()+" : "+block);
	}

	@Override
	public void cancel(ClientContext context) {
		for(MySendableInsert inserter: inserters) {
			if(inserter != null)
				inserter.cancel(context);
		}
		parent.onFailure(new InsertException(InsertExceptionMode.CANCELLED), this, context);
	}

	@Override
	public BaseClientPutter getParent() {
		return parent;
	}

	@Override
	public Object getToken() {
		return clientContext;
	}

	@Override
	public void schedule(ClientContext context) throws InsertException {
		for(MySendableInsert inserter: inserters) {
			inserter.schedule();
		}
	}

	class MySendableInsert extends SimpleSendableInsert {

        private static final long serialVersionUID = 1L;
        final int blockNum;
		private int consecutiveRNFs;
		private int retries;

		public MySendableInsert(int i, KeyBlock block, short prioClass, ClientRequestScheduler scheduler, RequestClient client) {
			super(block, prioClass, client, scheduler);
			this.blockNum = i;
		}

		@Override
		public void onSuccess(SendableRequestItem keyNum, ClientKey key, ClientContext context) {
			synchronized(this) {
				if(inserters[blockNum] == null) return;
				inserters[blockNum] = null;
				completedBlocks++;
				succeededBlocks++;
			}
			parent.completedBlock(false, context);
			maybeFinish(context);
		}

		// FIXME duplicated code from SingleBlockInserter
		// FIXME combine it somehow
		@Override
		public void onFailure(LowLevelPutException e, SendableRequestItem keyNum, ClientContext context) {
			synchronized(BinaryBlobInserter.this) {
				if(inserters[blockNum] == null) return;
			}
			if(parent.isCancelled()) {
				fail(true, context);
				return;
			}
			logMINOR = Logger.shouldLog(LogLevel.MINOR, BinaryBlobInserter.this);
			switch(e.code) {
			case LowLevelPutException.COLLISION:
				fail(false, context);
				break;
			case LowLevelPutException.INTERNAL_ERROR:
				errors.inc(InsertExceptionMode.INTERNAL_ERROR);
				break;
			case LowLevelPutException.REJECTED_OVERLOAD:
				errors.inc(InsertExceptionMode.REJECTED_OVERLOAD);
				break;
			case LowLevelPutException.ROUTE_NOT_FOUND:
				errors.inc(InsertExceptionMode.ROUTE_NOT_FOUND);
				break;
			case LowLevelPutException.ROUTE_REALLY_NOT_FOUND:
				errors.inc(InsertExceptionMode.ROUTE_REALLY_NOT_FOUND);
				break;
			default:
				Logger.error(this, "Unknown LowLevelPutException code: "+e.code);
				errors.inc(InsertExceptionMode.INTERNAL_ERROR);
			}
			if(e.code == LowLevelPutException.ROUTE_NOT_FOUND) {
				consecutiveRNFs++;
				if(logMINOR) Logger.minor(this, "Consecutive RNFs: "+consecutiveRNFs+" / "+consecutiveRNFsCountAsSuccess);
				if(consecutiveRNFs == consecutiveRNFsCountAsSuccess) {
					if(logMINOR) Logger.minor(this, "Consecutive RNFs: "+consecutiveRNFs+" - counting as success");
					onSuccess(keyNum, null, context);
					return;
				}
			} else
				consecutiveRNFs = 0;
			if(logMINOR) Logger.minor(this, "Failed: "+e);
			retries++;
			if((retries > maxRetries) && (maxRetries != -1)) {
				fail(false, context);
				return;
			}
			this.clearWakeupTime(context);
			// Retry *this block*
			this.schedule();
		}

		private void fail(boolean fatal, ClientContext context) {
			synchronized(BinaryBlobInserter.this) {
				if(inserters[blockNum] == null) return;
				inserters[blockNum] = null;
				completedBlocks++;
				if(fatal) BinaryBlobInserter.this.fatal = true;
			}
			if(fatal)
				parent.fatallyFailedBlock(context);
			else
				parent.failedBlock(context);
			maybeFinish(context);
		}

	}

	public void maybeFinish(ClientContext context) {
		boolean success;
		boolean wasFatal;
		synchronized(this) {
			if(completedBlocks != inserters.length)
				return;
			success = completedBlocks == succeededBlocks;
			wasFatal = fatal;
		}
		if(success) {
			parent.onSuccess(this, context);
		} else if(wasFatal)
			parent.onFailure(new InsertException(InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS, errors, null), this, context);
		else
			parent.onFailure(new InsertException(InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS, errors, null), this, context);
	}

    @Override
    public void onResume(ClientContext context) throws InsertException {
        // TODO binary blob inserter isn't persistent yet, right?
        throw new InsertException(InsertExceptionMode.INTERNAL_ERROR, "Persistence not supported yet", null);
    }

    @Override
    public void onShutdown(ClientContext context) {
        // Ignore.
    }

}
