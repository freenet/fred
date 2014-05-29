/*
 * This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL.
 */



package freenet.client.async;

/**
 * An element in the in-memory-only cooldown queue. Tracks retry counts and cooldown
 * times for a request which has maxRetries = -1 and therefore does not need to store them
 * persistently.
 *
 * IMPORTANT: THESE CAN BE INNER CLASSES OF THE OBJECT THEY ARE TRACKING BUT **MUST
 * BE STATIC**, otherwise we get a major memory leak!
 * @author toad
 */
public interface CooldownTrackerItem {}
