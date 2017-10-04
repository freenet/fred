package freenet.node;

import freenet.support.Logger;
import freenet.support.TimeUtil;

/**
 * Represents an insert.
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class InsertTag extends UIDTag {
	
	final boolean ssk;
	
	enum START {
		LOCAL,
		REMOTE
	}
	
	final START start;
	private Throwable handlerThrew;
	private boolean senderStarted;
	private boolean senderFinished;
	
	InsertTag(boolean ssk, START start, PeerNode source, boolean realTimeFlag, long uid, Node node) {
		super(source, realTimeFlag, uid, node);
		this.start = start;
		this.ssk = ssk;
	}
	
	public synchronized void startedSender() {
		senderStarted = true;
	}
	
	public void finishedSender() {
		boolean noRecordUnlock;
		synchronized(this) {
			senderFinished = true;
			if(!mustUnlock()) return;
			noRecordUnlock = this.noRecordUnlock;
		}
		innerUnlock(noRecordUnlock);
	}

	@Override
	protected synchronized boolean mustUnlock() {
		if(senderStarted && !senderFinished) return false;
		return super.mustUnlock();
	}
	
	public synchronized void handlerThrew(Throwable t) {
		handlerThrew = t;
	}

	@Override
	public void logStillPresent(Long uid) {
		StringBuffer sb = new StringBuffer();
		sb.append("Still present after ").append(TimeUtil.formatTime(age()));
		sb.append(" : ").append(uid).append(" : start=").append(start);
		sb.append(" ssk=").append(ssk);
		sb.append(" thrown=").append(handlerThrew);
		sb.append(" : ");
		sb.append(super.toString());
		if(handlerThrew != null)
			Logger.error(this, sb.toString(), handlerThrew);
		else
			Logger.error(this, sb.toString());
	}

	@Override
	public synchronized int expectedTransfersIn(boolean ignoreLocalVsRemote) {
		if(!accepted) return 0;
		return ((!isLocal()) || ignoreLocalVsRemote) ? 1 : 0;
	}

	@Override
	public synchronized int expectedTransfersOut(boolean ignoreLocalVsRemote,
			int outwardTransfersPerInsert, boolean forAccept) {
		if(!accepted) return 0;
		if(notRoutedOnwards) return 0;
		else return outwardTransfersPerInsert;
	}

	@Override
	public boolean isSSK() {
		return ssk;
	}

	@Override
	public boolean isInsert() {
		return true;
	}

	@Override
	public boolean isOfferReply() {
		return false;
	}

}
