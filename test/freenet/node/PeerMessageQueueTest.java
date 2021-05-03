/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import junit.framework.TestCase;

public class PeerMessageQueueTest extends TestCase {
	public void testUrgentTimeEmpty() {
		PeerMessageQueue pmq = new PeerMessageQueue();
		assertEquals(Long.MAX_VALUE, pmq.getNextUrgentTime(System.currentTimeMillis()));
	}

	public void testUrgentTime() {
		PeerMessageQueue pmq = new PeerMessageQueue();

		//Constructor might take some time, so grab a range
		long start = System.currentTimeMillis();
		MessageItem item = new MessageItem(new byte[1024], null, false, null, (short) 0, false, false);
		long end = System.currentTimeMillis();

		pmq.queueAndEstimateSize(item, 1024);

		//The timeout for item should be within (start + 100) and (end + 100)
		long urgentTime = pmq.getNextUrgentTime(System.currentTimeMillis());
		if(!((urgentTime >= (start + 100)) && (urgentTime <= (end + 100)))) {
			fail("Timeout not in expected range. Expected: " + (start + 100) + "->" + (end + 100) + ", actual: " + urgentTime);
		}
	}

	/* Test that getNextUrgentTime() returns the correct value, even when the items on the queue
	 * aren't ordered by their timeout value, eg. when an item was readded because we couldn't send
	 * it. */
	public void testUrgentTimeQueuedWrong() {
		PeerMessageQueue pmq = new PeerMessageQueue();

		//Constructor might take some time, so grab a range
		long start = System.currentTimeMillis();
		MessageItem itemUrgent = new MessageItem(new byte[1024], null, false, null, (short) 0, false, false);
		long end = System.currentTimeMillis();

		//Sleep for a little while to get a later timeout
		try {
			Thread.sleep(1);
		} catch (InterruptedException e) {

		}

		MessageItem itemNonUrgent = new MessageItem(new byte[1024], null, false, null, (short) 0, false, false);

		//Queue the least urgent item first to get the wrong order
		pmq.queueAndEstimateSize(itemNonUrgent, 1024);
		pmq.queueAndEstimateSize(itemUrgent, 1024);

		//getNextUrgentTime() should return the timeout of itemUrgent, which is within (start + 100)
		//and (end + 100)
		long urgentTime = pmq.getNextUrgentTime(System.currentTimeMillis());
		if(!((urgentTime >= (start + 100)) && (urgentTime <= (end + 100)))) {
			fail("Timeout not in expected range. Expected: " + (start + 100) + "->" + (end + 100) + ", actual: " + urgentTime);
		}
	}

	public void testGrabQueuedMessageItem() {
		PeerMessageQueue pmq = new PeerMessageQueue();

		MessageItem itemUrgent = new MessageItem(new byte[1024], null, false, null, (short) 0, false, false);

		//Sleep for a little while to get a later timeout
		try {
			Thread.sleep(1);
		} catch (InterruptedException e) {

		}

		MessageItem itemNonUrgent = new MessageItem(new byte[1024], null, false, null, (short) 0, false, false);

		//Queue the least urgent item first to get the wrong order
		pmq.queueAndEstimateSize(itemNonUrgent, 1024);
		pmq.queueAndEstimateSize(itemUrgent, 1024);

		//grabQueuedMessageItem() should return the most urgent item, even though it was queued last
		assertSame(itemUrgent, pmq.grabQueuedMessageItem(0));
	}
}
