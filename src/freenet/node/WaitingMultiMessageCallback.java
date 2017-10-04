package freenet.node;

public class WaitingMultiMessageCallback extends MultiMessageCallback {

	
	
	@Override
	synchronized void finish() {
		notifyAll();
	}

	public synchronized void waitFor() {
		while(!finished()) {
			try {
				wait();
			} catch (InterruptedException e) {
				// Ignore
			}
		}
	}

	@Override
	void sent() {
		// Ignore
	}

}
