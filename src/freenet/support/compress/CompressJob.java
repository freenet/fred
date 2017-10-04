package freenet.support.compress;

import freenet.client.InsertException;
import freenet.client.async.ClientContext;

public interface CompressJob {
	public abstract void tryCompress(ClientContext context) throws InsertException;
	public abstract void onFailure(InsertException e, ClientContext context);
}
