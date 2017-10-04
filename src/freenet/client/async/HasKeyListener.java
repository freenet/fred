package freenet.client.async;

import java.io.IOException;

/**
 * Interface to show that we can create a KeyListener callback.
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public interface HasKeyListener {
	
	/**
	 * Create a KeyListener, a transient object used to determine which keys we
	 * want, and to handle any blocks found.
	 * @return Null if the HasKeyListener is finished/cancelled/etc.
	 * @throws IOException 
	 */
	KeyListener makeKeyListener();

	/**
	 * Is it cancelled?
	 */
	boolean isCancelled();

}
