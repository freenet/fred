/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.async;

import freenet.client.FetchException;
import freenet.client.FetchResult;

/** Internal callback interface for requests. Methods are called on the database thread if the request
 * is persistent, otherwise on whatever thread completed the request (therefore with a null container).
 * 
 * <i>NOTICE: This interface provides onSuccess and onFailure methods for getting 
 * notified about the progress of the fetch process. <br/>
 * If you want to get more detailed progress notifications you have to also implement {@link ClientEventListener} 
 * interface and subscribe your callback to the {@link ClientEventProducer} of the getter's
 * {@link FetchContext} using event producer's addEventListener method. <br/>
 * This way your callback will be able to receive {@link SplitfileProgressEvent} and other events 
 * during the fetch process.</i>
 */
public interface ClientGetCallback extends ClientBaseCallback {
	/** Called on successful fetch. Caller should schedule a job on the Ticker
	 * or Executor (on the ClientContext) if it needs to do much work. */
	public void onSuccess(FetchResult result, ClientGetter state);

	/** Called on failed/canceled fetch. Caller should schedule a job on the Ticker
	 * or Executor (on the ClientContext) if it needs to do much work. */
	public void onFailure(FetchException e, ClientGetter state);
}
