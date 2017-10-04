package freenet.client.async;

import freenet.keys.FreenetURI;
import freenet.support.api.Bucket;

public interface DownloadCache {
	
	public CacheFetchResult lookupInstant(FreenetURI key, boolean noFilter, boolean mustCopy, Bucket preferred);

	public CacheFetchResult lookup(FreenetURI key, boolean mustCopy, Bucket preferred);

}
