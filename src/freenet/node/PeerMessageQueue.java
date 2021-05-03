package freenet.node;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.ListIterator;
import java.util.Map;

import freenet.io.comm.DMT;
import freenet.support.DoublyLinkedList;
import freenet.support.DoublyLinkedListImpl;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.MutableBoolean;

/**
 * Queue of messages to send to a node. Ordered first by priority then by time.
 * Will soon be round-robin between different transfers/UIDs/clients too.
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class PeerMessageQueue {

	private static volatile boolean logMINOR;
	private static volatile boolean logDEBUG;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
				logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}

	/* WARNING: you must invalidate or update cachedNextUrgentTime and cachedQueueSize when any of queuesByPriority[] changed */
	private final PrioQueue[] queuesByPriority;

	private long cachedNextUrgentTime = Long.MAX_VALUE; // cached getNextUrgentTime; Long.MIN_VALUE if invalid; Long.MAX_VALUE for empty queue (initial value); uses "synchronized(this)" lock
	private int cachedQueueSize = 0; // lower bound for queue size; -1 if invalid; 0 for empty queue (initial value)
	private boolean cachedQueueSizeIsComplete = true; // true if cachedQueueSize covers full queue (otherwise cachedQueueSize is only lower bound); ignored when cachedQueueSize is invalid (-1)

	private static final int MESSAGE_OVERHEAD = 2;
	
	private boolean mustSendLoadRT;
	private boolean mustSendLoadBulk;
	
	private class PrioQueue {
		
		// FIXME refactor into PrioQueue and RoundRobinByUIDPrioQueue
		PrioQueue(long timeout, boolean timeoutSinceLastSend) {
			this.timeout = timeout;
			this.roundRobinBetweenUIDs = timeoutSinceLastSend;
		}
		
		/** The timeout, period after which messages become urgent. */
		final long timeout;
		/** If true, do round-robin between UID's, and count the timeout relative
		 * to the last send. Block transfers need this - both realtime and bulk. */
		final boolean roundRobinBetweenUIDs;
		
		private class Items extends DoublyLinkedListImpl.Item<Items> {
			/** List of messages to send. Stuff to send first is at the beginning. */
			final LinkedList<MessageItem> items;
			final long id;
			long timeLastSent;
			Items(long id, long initialTimeLastSent) {
				items = new LinkedList<MessageItem>();
				this.id = id;
				timeLastSent = initialTimeLastSent;
			}
			public void addLast(MessageItem item) {
				items.addLast(item);
			}
			public void addFirst(MessageItem item) {
				items.addFirst(item);
			}
			public boolean remove(MessageItem item) {
				return items.remove(item);
			}
			@Override
			public String toString() {
				return super.toString()+":"+id+":"+items.size()+":"+timeLastSent;
			}
		}
		
		/** Maximum inter-packet time is 2 minutes for a block transfer (when we have bulk
		 * flag this will be no higher, and it might be reduced to 30 seconds). Requests
		 * can wait for 2 minutes now, maybe 10 minutes in future, but round-robin is 
		 * intended for frequent messages - it doesn't matter in that case. So 3 minutes 
		 * is plenty. */
		static final long FORGET_AFTER = 3*60*1000;

		/** Using DoublyLinkedListImpl so that we can move stuff around without the 
		 * iterator failing, and also delete efficiently. Ordered by timeLastSent,
		 * NOT by timeout. Items we have not yet sent are at the beginning with 
		 * timeLastSent = -1. */
		DoublyLinkedListImpl<Items> nonEmptyItemsWithID;
		/** Items which have been sent within the last 10 minutes, so we need to track
		 * them for good round-robin, but which we don't have anything queued on right now. */
		DoublyLinkedListImpl<Items> emptyItemsWithID;
		Map<Long, Items> itemsByID;
		/** Non-urgent messages. Same order as in Items, so stuff to send first is at
		 * the beginning. */
		LinkedList<MessageItem> itemsNonUrgent;
		// Construct structures lazily, we're protected by the overall synchronized.

		/** Add a new message. For a normal priority level, we just add it to the end of the list.
		 * It will be sent after the messages that are already queued, and its deadline is effectively
		 * the time it was submitted plus the timeout. For a priority level using round robin between
		 * peers, it is the same unless we have recently sent a message with the same UID. If we have,
		 * the timeout is relative to the last send. */
		public void addLast(MessageItem item) {
			// Clear the deadline for the item.
			item.clearDeadline();
			if(logMINOR) checkOrder();
			if(roundRobinBetweenUIDs) {
				long id = item.getID();
				if(itemsByID != null) {
					Items it = itemsByID.get(id);
					if(it != null && it.timeLastSent > 0 && it.timeLastSent + timeout <= System.currentTimeMillis()) {
						it.addLast(item);
						if(it.getParent() == emptyItemsWithID)
							moveFromEmptyToNonEmptyBackward(it);
						else
							assert(it.getParent() == nonEmptyItemsWithID);
						if(logMINOR) checkOrder();
						return;
					}
				}
			}
			addToNonUrgent(item);
		}
		
		private void addToNonUrgent(MessageItem item) {
			if(itemsNonUrgent == null)
				itemsNonUrgent = new LinkedList<MessageItem>();
			ListIterator<MessageItem> it = itemsNonUrgent.listIterator(itemsNonUrgent.size());
			// MessageItem's can be created out of order, so the timestamps may not be consistent.
			// CONCURRENCY: This is not a problem in addNonUrgentMessages() because it is always called from one thread.
			while(true) {
				if(!it.hasPrevious()) {
					it.add(item);
					if(logMINOR) checkOrder();
					return;
				}
				MessageItem prev = it.previous();
				if(item.submitted >= prev.submitted) {
					it.next();
					it.add(item);
					if(logMINOR) checkOrder();
					return;
				}
			}
		}

		private void moveToUrgent(long now) {
			if(logMINOR) checkOrder();
			if(itemsNonUrgent == null) return;
			ListIterator<MessageItem> it = itemsNonUrgent.listIterator();
			int moved = 0;
			while(it.hasNext()) {
				MessageItem item = it.next();
				Items list = null;
				long id = item.getID();
				if(itemsByID != null)
					list = itemsByID.get(id);
				boolean moveIt = false;
				if(list != null && roundRobinBetweenUIDs) {
					if(list.timeLastSent + timeout <= now)
						moveIt = true;
				}
				if(item.submitted + timeout <= now) {
					moveIt = true;
				}
				if(moveIt) {
					if(logMINOR) Logger.minor(this, "Moving message to urgent list: "+item);
					if(logMINOR) checkOrder();
					// Move to urgent list
					if(itemsByID == null) {
						itemsByID = new HashMap<Long, Items>();
						if(nonEmptyItemsWithID == null)
							nonEmptyItemsWithID = new DoublyLinkedListImpl<Items>();
						list = new Items(id, item.submitted);
						addToNonEmptyForward(list);
						itemsByID.put(id, list);
						if(logMINOR) checkOrder();
					} else {
						if(list == null) {
							list = new Items(id, item.submitted);
							if(nonEmptyItemsWithID == null)
								nonEmptyItemsWithID = new DoublyLinkedListImpl<Items>();
							addToNonEmptyForward(list);
							itemsByID.put(id, list);
							if(logMINOR) checkOrder();
						} else {
							if(list.items.isEmpty()) {
								if(list.getParent() == nonEmptyItemsWithID) {
									Logger.error(this, "Was empty but was in nonEmptyItemsWithID: "+list);
								} else {
									assert(list.getParent() == emptyItemsWithID);
									// It already exists, so it has a valid time.
									// Which is probably in the past, so use Forward.
									// Must add it to the list before moving to non-empty because of assertion.
									moveFromEmptyToNonEmptyForward(list);
								}
							} else {
								assert(list.getParent() == nonEmptyItemsWithID);
							}
							if(logMINOR) checkOrder();
						}
					}
					list.addLast(item);
					it.remove();
					moved++;
					if(logMINOR) checkOrder();
				} else if(!roundRobinBetweenUIDs)
					break;
			}
			if(logDEBUG && moved > 0)
				Logger.debug(this, "Moved "+moved+" items to urgent round-robin");
			if(logMINOR) checkOrder();
		}

		private void moveFromEmptyToNonEmptyForward(Items list) {
			// Presumably is in emptyItemsWithID
			assert(list.items.isEmpty());
			if(logMINOR) {
				if(list.getParent() == nonEmptyItemsWithID) {
					Logger.error(this, "Already in non-empty yet empty?!");
					return;
				}
			}
			if(emptyItemsWithID != null)
				emptyItemsWithID.remove(list);
			addToNonEmptyForward(list);
		}
		
		private void addToNonEmptyForward(Items list) {
			if(nonEmptyItemsWithID == null)
				nonEmptyItemsWithID = new DoublyLinkedListImpl<Items>();
			Enumeration<Items> it = nonEmptyItemsWithID.elements();
			while(it.hasMoreElements()) {
				Items compare = it.nextElement();
				if(compare.timeLastSent >= list.timeLastSent) {
					nonEmptyItemsWithID.insertPrev(compare, list);
					return;
				}
			}
			nonEmptyItemsWithID.push(list);
		}

		private void moveFromEmptyToNonEmptyBackward(Items list) {
			// Presumably is in emptyItemsWithID
			emptyItemsWithID.remove(list);
			addToNonEmptyBackward(list);
		}
		
		private void addToNonEmptyBackward(Items list) {
			if(nonEmptyItemsWithID == null)
				nonEmptyItemsWithID = new DoublyLinkedListImpl<Items>();
			Enumeration<Items> it = nonEmptyItemsWithID.reverseElements();
			while(it.hasMoreElements()) {
				Items compare = it.nextElement();
				if(compare.timeLastSent <= list.timeLastSent) {
					nonEmptyItemsWithID.insertNext(compare, list);
					return;
				}
			}
			nonEmptyItemsWithID.unshift(list);
		}

		private void addToEmptyBackward(Items list) {
			if(emptyItemsWithID == null)
				emptyItemsWithID = new DoublyLinkedListImpl<Items>();
			Enumeration<Items> it = emptyItemsWithID.reverseElements();
			while(it.hasMoreElements()) {
				Items compare = it.nextElement();
				if(compare.timeLastSent <= list.timeLastSent) {
					emptyItemsWithID.insertNext(compare, list);
					return;
				}
			}
			emptyItemsWithID.unshift(list);
		}

		/** Add a new message to the beginning i.e. send it as soon as possible (e.g. if
		 * we tried to send it and failed); it is assumed to already be urgent. */
		public void addFirst(MessageItem item) {
			// Keep the old deadline for the item.
			if(!roundRobinBetweenUIDs) {
				addToNonUrgent(item);
				return;
			}
			if(logMINOR) checkOrder();
			long id = item.getID();
			Items list;
			if(itemsByID == null) {
				itemsByID = new HashMap<Long, Items>();
				if(nonEmptyItemsWithID == null)
					nonEmptyItemsWithID = new DoublyLinkedListImpl<Items>();
				list = new Items(id, -1);
				addToNonEmptyForward(list);
				itemsByID.put(id, list);
			} else {
				list = itemsByID.get(id);
				if(list == null) {
					list = new Items(id, -1);
					if(nonEmptyItemsWithID == null)
						nonEmptyItemsWithID = new DoublyLinkedListImpl<Items>();
					nonEmptyItemsWithID.unshift(list);
					itemsByID.put(id, list);
				} else {
					if(list.items.isEmpty()) {
						assert(list.getParent() == emptyItemsWithID);
						// It already exists, so it has a valid time.
						// Which is probably in the past, so use Forward.
						moveFromEmptyToNonEmptyForward(list);
					} else
						assert(list.getParent() == nonEmptyItemsWithID);
				}
			}
			list.addFirst(item);
			if(logMINOR) checkOrder();
		}

		public int size() {
			int size = 0;
			if(nonEmptyItemsWithID != null)
				for(Items items : nonEmptyItemsWithID)
					size += items.items.size();
			if(itemsNonUrgent != null)
				size += itemsNonUrgent.size();
			return size;
		}

		public int addTo(MessageItem[] output, int ptr) {
			if(nonEmptyItemsWithID != null)
				for(Items list : nonEmptyItemsWithID)
					for(MessageItem item : list.items)
						output[ptr++] = item;
			if(itemsNonUrgent != null)
				for(MessageItem item : itemsNonUrgent)
					output[ptr++] = item;
			return ptr;
		}
		
		/** Check that nonEmptyItemsWithID is ordered correctly. 
		 * LOCKING: Caller must synchronize on PeerMessageQueue.this. */
		private void checkOrder() {
			if(nonEmptyItemsWithID != null) {
				long prev = -1;
				Items prevItems = null;
				for(Items items : nonEmptyItemsWithID) {
					long thisTime = items.timeLastSent;
					if(thisTime < prev)
						Logger.error(this, "Inconsistent order in non empty items with ID: prev timeout was "+prev+" for "+prevItems+" but this timeout is "+thisTime+" for "+items, new Exception("error"));
					prev = thisTime;
					prevItems = items;
				}
			}
			if(itemsNonUrgent != null) {
				long prev = -1;
				MessageItem prevItem = null;
				for(MessageItem item : itemsNonUrgent) {
					if(item.submitted < prev)
						Logger.error(this, "Inconsistent order in itemsNonUrgent: prev submitted at "+prev+" but this at "+item.submitted+" prev is "+prevItem+" this is "+item);
					prev = item.submitted;
					prevItem = item;
				}
			}
		}

		/** Note that this does NOT consider the length of the queue, which can trigger a
		 * send. This is intentional, and is relied upon by the bulk-or-realtime logic in
		 * addMessages().
		 * @param t The initial urgent time. What we return must be less than or 
		 * equal to this. Convenient for chaining. 
		 * @param stopIfBeforeTime If the next urgent time is <= to this time, 
		 * return immediately.
		 */
		public long getNextUrgentTime(long t, long stopIfBeforeTime) {
			if(!roundRobinBetweenUIDs) {
				if(itemsNonUrgent != null && !itemsNonUrgent.isEmpty()) {
					t = Math.min(t, itemsNonUrgent.getFirst().submitted + timeout);
					if(t <= stopIfBeforeTime) return t;
				}
				assert(nonEmptyItemsWithID == null);
				assert(itemsByID == null);
			} else {
				if(nonEmptyItemsWithID != null) {
					for(Items items : nonEmptyItemsWithID) {
						if(items.items.size() == 0) continue;
						if(items.timeLastSent > 0) {
							t = Math.min(t, items.timeLastSent + timeout);
							if(t <= stopIfBeforeTime) return t;
						} else {
							// It is possible that something requeued isn't urgent, so check anyway.
							t = Math.min(t, items.items.getFirst().submitted + timeout);
							if(t <= stopIfBeforeTime) return t;
						}
					}
				}
				if(itemsNonUrgent != null && !itemsNonUrgent.isEmpty()) {
					for(MessageItem item : itemsNonUrgent) {
						long uid = item.getID();
						Items items = itemsByID == null ? null : itemsByID.get(uid);
						if(items != null && items.timeLastSent > 0) {
							t = Math.min(t, items.timeLastSent + timeout);
							if(t <= stopIfBeforeTime) return t;
						} else {
							t = Math.min(t, item.submitted + timeout);
							if(t <= stopIfBeforeTime) return t;
							if(itemsByID == null) break; // Only the first one matters, since none have been sent.
						}
					}
				}
			}
			return t;
		}

		/**
		 * Add the size of messages in this queue to <code>length</code> until
		 * length is larger than <code>maxSize</code>, or all messages have
		 * been added.
		 * @param length the starting length
		 * @param maxSize the size at which to stop
		 * @return the resulting length after adding messages
		 */
		public int addSize(int length, int maxSize) {
			if(itemsNonUrgent != null) {
				for(MessageItem item : itemsNonUrgent) {
					length += item.getLength() + MESSAGE_OVERHEAD;
					if(length > maxSize) return length;
				}
			}
			if(nonEmptyItemsWithID != null) {
				for(Items list : nonEmptyItemsWithID) {
					for(MessageItem item : list.items) {
						length += item.getLength() + MESSAGE_OVERHEAD;
						if(length > maxSize) return length;
					}
				}
			}
			return length;
		}
		
		private MessageItem addNonUrgentMessages(long now, MutableBoolean addPeerLoadStatsRT, MutableBoolean addPeerLoadStatsBulk) {
			if(logMINOR) checkOrder();
			if(itemsNonUrgent == null) return null;
			MessageItem ret;
			for(ListIterator<MessageItem> items = itemsNonUrgent.listIterator();items.hasNext();) {
				MessageItem item = items.next();
				items.remove();
				item.setDeadline(item.submitted + timeout);
				ret = item;
				if(itemsByID != null) {
					long id = item.getID();
					Items tracker = itemsByID.get(id);
					if(tracker != null) {
						tracker.timeLastSent = now;
						DoublyLinkedList<? super Items> parent = tracker.getParent();
						// Demote the corresponding tracker to maintain round-robin.
						if(tracker.items.isEmpty()) {
							if(logDEBUG) Logger.debug(this, "Moving "+tracker+" to end of empty list in addNonUrgentMessages");
							if(emptyItemsWithID == null)
								emptyItemsWithID = new DoublyLinkedListImpl<Items>();
							if(parent == null) {
								Logger.error(this, "Tracker is in itemsByID but not in either list! (empty)");
							} else if(parent == emptyItemsWithID) {
								// Normal. Remove it so we can re-add it in the right place.
								emptyItemsWithID.remove(tracker);
							} else if(parent == nonEmptyItemsWithID) {
								Logger.error(this, "Tracker is in non empty items list when is empty");
								nonEmptyItemsWithID.remove(tracker);
							} else
								assert(false);
							addToEmptyBackward(tracker);
						} else {
							if(logDEBUG) Logger.debug(this, "Moving "+tracker+" to end of non-empty list in addNonUrgentMessages");
							if(nonEmptyItemsWithID == null)
								nonEmptyItemsWithID = new DoublyLinkedListImpl<Items>();
							if(parent == null) {
								Logger.error(this, "Tracker is in itemsByID but not in either list! (non-empty)");
							} else if(parent == nonEmptyItemsWithID) {
								// Normal. Remove it so we can re-add it in the right place.
								nonEmptyItemsWithID.remove(tracker);
							} else if(parent == emptyItemsWithID) {
								Logger.error(this, "Tracker is in empty items list when is non-empty");
								emptyItemsWithID.remove(tracker);
							} else
								assert(false);
							addToNonEmptyBackward(tracker);
						}
					}
				}
				if(mustSendLoadRT && item.sendLoadRT && !addPeerLoadStatsRT.value) {
					addPeerLoadStatsRT.value = true;
					mustSendLoadRT = false;
				} else if(mustSendLoadBulk && item.sendLoadBulk && !addPeerLoadStatsBulk.value) {
					addPeerLoadStatsBulk.value = true;
					mustSendLoadBulk = false;
				}
				if(logMINOR) checkOrder();
				
				if(ret != null) return ret;
			}
			if(logMINOR) checkOrder();
			return null;
		}

		/**
		 * Add messages to <code>messages</code> until there are no more
		 * messages to add.
		 *
		 * @param now the current time
		 * @param messages the list that messages will be added to
		 * @param maxMessages 
		 * @return the size of <code>messages</code>, multiplied by -1 if there were
		 * messages that didn't fit
		 */
		private MessageItem addUrgentMessages(long now, MutableBoolean addPeerLoadStatsRT, MutableBoolean addPeerLoadStatsBulk) {
			if(logMINOR) checkOrder();
			MessageItem ret;
			while(true) {
				int lists = 0;
				if(nonEmptyItemsWithID == null) {
					if(logMINOR) Logger.minor(this, "No non-empty items to send, not sending any urgent messages");
					return null;
				}
				lists += nonEmptyItemsWithID.size();
				Items list = nonEmptyItemsWithID.head();
				for(int i=0;i<lists && list != null;i++) {
					if(logMINOR) checkOrder();
					if(list.items.isEmpty()) {
						// Should not happen, but check for it anyway since it keeps happening. :(
						Logger.error(this, "List is in nonEmptyItemsWithID yet it is empty?!: "+list);
						nonEmptyItemsWithID.remove(list);
						addToEmptyBackward(list);
						if(nonEmptyItemsWithID.isEmpty()) {
							if(logMINOR) Logger.minor(this, "Run out of non-empty items to send");
							return null;
						}
						list = nonEmptyItemsWithID.head();
						continue;
					}
					MessageItem item = list.items.getFirst();
					list.items.removeFirst();
					// Move to end of list.
					Items prev = list.getPrev();
					nonEmptyItemsWithID.remove(list);
					item.setDeadline(list.timeLastSent + timeout);
					list.timeLastSent = now;
					if(!list.items.isEmpty()) {
						if(logDEBUG) Logger.debug(this, "Moving "+list+" to end of non empty list in addUrgentMessages");
						addToNonEmptyBackward(list);
					} else {
						if(logDEBUG) Logger.debug(this, "Moving "+list+" to end of empty list in addUrgentMessages");
						addToEmptyBackward(list);
					}
					if(prev == null)
						list = nonEmptyItemsWithID.head();
					else
						list = prev.getNext();
					ret = item;
					if(mustSendLoadRT && item.sendLoadRT && !addPeerLoadStatsRT.value) {
						addPeerLoadStatsRT.value = true;
						mustSendLoadRT = false;
					} else if(mustSendLoadBulk && item.sendLoadBulk && !addPeerLoadStatsBulk.value) {
						addPeerLoadStatsBulk.value = true;
						mustSendLoadBulk = false;
					}
					if(logMINOR) checkOrder();
					if(ret != null) return ret;
				}
				if(logDEBUG)
					Logger.debug(this, "No more messages queued at this priority");
				if(logMINOR) checkOrder();
				return null;
			}
		}

		
		/**
		 * Add urgent messages, then non-urgent messages. Add a load message if need to.
		 * @param size
		 * @param now
		 * @param messages
		 * @param addPeerLoadStatsRT Will be set if the caller needs to include a load stats message for
		 * realtime (i.e. a realtime request completes etc).
		 * @param addPeerLoadStatsBulk Will be set if the caller needs to include a load stats message for
		 * bulk (i.e. a bulk request completes etc).
		 * @param incomplete Will be set if there were more messages but they did not fit. If this is
		 * not set, we can try another priority.
		 * @return
		 */
		MessageItem addPriorityMessages(long now, MutableBoolean addPeerLoadStatsRT, MutableBoolean addPeerLoadStatsBulk) {
			// Urgent messages first.
			if(logMINOR) {
				int nonEmpty = nonEmptyItemsWithID == null ? 0 : nonEmptyItemsWithID.size();
				int empty = emptyItemsWithID == null ? 0 : emptyItemsWithID.size();
				int byID = itemsByID == null ? 0 : itemsByID.size();
				if(nonEmpty + empty < byID) {
					Logger.error(this, "Leaking itemsByID? non empty = "+nonEmpty+" empty = "+empty+" by ID = "+byID+" on "+this);
				} else if(logDEBUG)
					Logger.debug(this, "Items: non empty "+nonEmpty+" empty "+empty+" by ID "+byID+" on "+this);
			}
			if(roundRobinBetweenUIDs)
				moveToUrgent(now);
			clearOldNonUrgent(now);
			if(roundRobinBetweenUIDs) {
				MessageItem item = addUrgentMessages(now, addPeerLoadStatsRT, addPeerLoadStatsBulk);
				if(item != null) return item;
			} else {
				assert(itemsByID == null);
			}
			// 	If no more urgent messages, try to add some non-urgent messages too.
			return addNonUrgentMessages(now, addPeerLoadStatsRT, addPeerLoadStatsBulk);
		}

		private void clearOldNonUrgent(long now) {
			if(logMINOR) checkOrder();
			int removed = 0;
			if(emptyItemsWithID == null) return;
			while(true) {
				if(logMINOR) checkOrder();
				if(emptyItemsWithID.isEmpty()) return;
				Items list = emptyItemsWithID.head();
				if(!list.items.isEmpty()) {
					// FIXME remove paranoia
					Logger.error(this, "List with items in emptyItemsWithID!!");
					emptyItemsWithID.remove(list);
					addToNonEmptyBackward(list);
					return;
				}
				if(list.timeLastSent == -1 || now - list.timeLastSent > FORGET_AFTER) {
					// FIXME: Urgh, what a braindead API! remove(Object) on a Map<Long, Items> !?!?!?!
					// Anyway we'd better check the return value!
					Items old = itemsByID.remove(list.id);
					if(old == null)
						Logger.error(this, "List was not in the items by ID tracker: "+list.id);
					else if(old != list)
						Logger.error(this, "Different list in the items by ID tracker: "+old+" not "+list+" for "+list.id);
					emptyItemsWithID.remove(list);
					removed++;
				} else {
					if(logDEBUG && removed > 0)
						Logger.debug(this, "Removed "+removed+" old empty UID trackers");
					break;
				}
			}
		}

		public void clear() {
			emptyItemsWithID = null;
			nonEmptyItemsWithID = null;
			itemsByID = null;
			itemsNonUrgent = null;
			if(logMINOR) checkOrder();
		}

		public boolean removeMessage(MessageItem item) {
			if(logMINOR) checkOrder();
			long id = item.getID();
			Items list;
			if(itemsByID != null) {
				list = itemsByID.get(id);
				if(list != null) {
					if(list.remove(item)) {
						if(list.items.isEmpty()) {
							nonEmptyItemsWithID.remove(list);
							addToEmptyBackward(list);
						}
						if(logMINOR) checkOrder();
						return true;
					}
				}
			}
			if(logMINOR) checkOrder();
			if(itemsNonUrgent != null)
				return itemsNonUrgent.remove(item);
			else
				return false;
		}
		
		public void removeUIDs(Long[] list) {
			if(logMINOR) checkOrder();
			if(itemsByID == null) return;
			for(Long l : list) {
				Items items = itemsByID.get(l);
				if(items == null) continue;
				if(items.items.isEmpty()) {
					itemsByID.remove(l);
					assert(emptyItemsWithID != null);
					assert(items.getParent() == emptyItemsWithID);
					emptyItemsWithID.remove(items);
				}
			}
			if(logMINOR) checkOrder();
		}

		public boolean isEmpty() {
			if(itemsNonUrgent != null && !itemsNonUrgent.isEmpty()) {
				return false;
			}
			if(nonEmptyItemsWithID != null) {
				for(Items items : nonEmptyItemsWithID) {
					if(items.items.size() == 0) continue;
					return false;
				}
			}
			return true;
		}

	}

	PeerMessageQueue() {
		queuesByPriority = new PrioQueue[DMT.NUM_PRIORITIES];
		for(int i=0;i<queuesByPriority.length;i++) {
			if(i == DMT.PRIORITY_BULK_DATA)
				// Bulk: round-robin between UID's (timeout since last sent), long timeout.
				queuesByPriority[i] = new PrioQueue(PacketSender.MAX_COALESCING_DELAY_BULK, true);
			else if(i == DMT.PRIORITY_REALTIME_DATA)
				// Realtime: round-robin between UID's (timeout since last sent), short timeout.
				queuesByPriority[i] = new PrioQueue(PacketSender.MAX_COALESCING_DELAY, true);
			else
				// Everything else: Still round-robin between UID's, but timeout on submitted.
				queuesByPriority[i] = new PrioQueue(PacketSender.MAX_COALESCING_DELAY, false);
		}
	}

	/**
	 * Queue a <code>MessageItem</code> and return an estimate of the size of
	 * this queue. The value returned is the estimated number of bytes
	 * needed for sending the all messages in this queue. Note that if the
	 * returned estimate is higher than 1024, it might not cover all messages.
	 * @param item the <code>MessageItem</code> to queue
	 * @return an estimate of the size of this queue
	 */
	public synchronized int queueAndEstimateSize(MessageItem item, int maxSize) {
		enqueuePrioritizedMessageItem(item);
		if (cachedQueueSize >= 0) {
			if (cachedQueueSizeIsComplete || cachedQueueSize > maxSize) {
				return cachedQueueSize;
			}
		}
		int x = 0;
		for(PrioQueue pq : queuesByPriority) {
			x = pq.addSize(x, maxSize);
			if (x > maxSize) {
				cachedQueueSize = Math.max(cachedQueueSize, x);
				cachedQueueSizeIsComplete = false;
				return x;
			}
		}
		cachedQueueSize = cachedQueueSize;
		cachedQueueSizeIsComplete = true;
		return x;
	}

	public synchronized long getMessageQueueLengthBytes() {
		if (cachedQueueSize>=0 && cachedQueueSizeIsComplete) {
			return cachedQueueSize;
		}
		long x = 0;
		for(PrioQueue pq : queuesByPriority) {
			if(pq.itemsNonUrgent != null) {
				for(MessageItem item : pq.itemsNonUrgent)
					x += item.getLength() + MESSAGE_OVERHEAD;
			}
			if(pq.nonEmptyItemsWithID != null)
				for(PrioQueue.Items q : pq.nonEmptyItemsWithID)
					for(MessageItem it : q.items)
						x += it.getLength() + MESSAGE_OVERHEAD;
		}
		cachedQueueSize = x > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int)x;
		cachedQueueSizeIsComplete = !(x > Integer.MAX_VALUE);
		return x;
	}

	private synchronized void enqueuePrioritizedMessageItem(MessageItem addMe) {
		//Assume it goes on the end, both the common case
		short prio = addMe.getPriority();
		queuesByPriority[prio].addLast(addMe);
		/* adjust cache */
		cachedNextUrgentTime = Math.min(cachedNextUrgentTime, addMe.submitted + queuesByPriority[prio].timeout); // won't change value if was "invalid" before
		if (cachedQueueSize >= 0) {
			// adjust cached value
			cachedQueueSize += addMe.getLength() + MESSAGE_OVERHEAD;
		} else {
			// initial estimation (covers only just-added MessageItem)
			cachedQueueSize = addMe.getLength() + MESSAGE_OVERHEAD;
			cachedQueueSizeIsComplete = false;
		}
		if(addMe.sendLoadRT)
			mustSendLoadRT = true;
		if(addMe.sendLoadBulk)
			mustSendLoadBulk = true;
	}

	/**
	 * like enqueuePrioritizedMessageItem, but adds it to the front of those in the same priority.
	 * 
	 * WARNING: Pulling a message and then pushing it back will mess up the fairness 
	 * between UID's send order. Try to avoid it.
	 */
	synchronized void pushfrontPrioritizedMessageItem(MessageItem addMe) {
		//Assume it goes on the front
		short prio = addMe.getPriority();
		queuesByPriority[prio].addFirst(addMe);
		// adjust cache
		cachedNextUrgentTime = Math.min(cachedNextUrgentTime, addMe.submitted + queuesByPriority[prio].timeout); // won't change value if was invalid before
		if (cachedQueueSize >= 0) {
			// adjust cached value
			cachedQueueSize += addMe.getLength() + MESSAGE_OVERHEAD;
		} else {
			// initial estimation (covers only just-added MessageItem)
			cachedQueueSize = addMe.getLength() + MESSAGE_OVERHEAD;
			cachedQueueSizeIsComplete = false;
		}
		if(addMe.sendLoadRT)
			mustSendLoadRT = true;
		if(addMe.sendLoadBulk)
			mustSendLoadBulk = true;
	}

	public synchronized MessageItem[] grabQueuedMessageItems() {
		int size = 0;
		for(PrioQueue queue : queuesByPriority)
			size += queue.size();
		MessageItem[] output = new MessageItem[size];
		int ptr = 0;
		for(PrioQueue queue : queuesByPriority) {
			ptr = queue.addTo(output, ptr);
			queue.clear();
		}
		/* reset cache to initial state */
		cachedNextUrgentTime = Long.MAX_VALUE;
		cachedQueueSize = 0;
		cachedQueueSizeIsComplete = true;
		return output;
	}

	/**
	 * Get the time at which the next message must be sent. If any message is
	 * overdue, we will return a value less than now, which may not be completely
	 * accurate.
	 * @param returnIfBefore The current time. If the next urgent time is less than 
	 * this we return immediately rather than computing an accurate past value. 
	 * Set to Long.MAX_VALUE if you want an accurate value.
	 * @return The next urgent time, but can be too high if it is less than now.
	 */
	public synchronized long getNextUrgentTime(long returnIfBefore) {
		if (cachedNextUrgentTime > Long.MIN_VALUE) {
			return cachedNextUrgentTime;
		}
		long t = Long.MAX_VALUE;
		for(PrioQueue queue: queuesByPriority) {
			t = queue.getNextUrgentTime(t, returnIfBefore);
			if(t <= returnIfBefore) return t; // How much in the past doesn't matter, as long as it's in the past.
		}
		cachedNextUrgentTime = t;
		return t;
	}

	@Deprecated
	public long getNextUrgentTime(long t, long stopIfBeforeTime) {
		return Math.min(t, getNextUrgentTime(stopIfBeforeTime));
	}

	/**
	 * Returns <code>true</code> if there are messages that will timeout before
	 * <code>now</code>.
	 * @param now the timeout for messages waiting to be sent
	 * @return <code>true</code> if there are messages that will timeout before
	 * <code>now</code>
	 */
	public boolean mustSendNow(long now) {
		return getNextUrgentTime(now) <= now;
	}

	/**
	 * Returns <code>true</code> if <code>minSize</code> + the length of all
	 * messages in this queue is greater than <code>maxSize</code>.
	 * @param minSize the starting size
	 * @param maxSize the maximum size
	 * @return <code>true</code> if <code>minSize</code> + the length of all
	 * messages in this queue is greater than <code>maxSize</code>
	 */
	public synchronized boolean mustSendSize(int minSize, int maxSize) {
		if (cachedQueueSize >= 0) {
			if (minSize + cachedQueueSize > maxSize) {
				return true;
			}
			if (cachedQueueSizeIsComplete) {
				return false;
			}
		}
		int length = minSize;
		for(PrioQueue items : queuesByPriority) {
			length = items.addSize(length, maxSize);
			if(length > maxSize) {
				cachedQueueSize = Math.max(cachedQueueSize, length - minSize);
				cachedQueueSizeIsComplete = false;
				return true;
			}
		}
		cachedQueueSize = length - minSize;
		cachedQueueSizeIsComplete = true;
		return false;
	}

	/** Grab a message to send. WARNING: PeerMessageQueue not only removes the message,
	 * it assumes it has been sent for purposes of fairness between UID's. You should try
	 * not to call this function if you are not going to be able to send the message: 
	 * check in advance if possible. */
	public synchronized MessageItem grabQueuedMessageItem(int minPriority) {
		long now = System.currentTimeMillis();
		
		MutableBoolean addPeerLoadStatsRT = new MutableBoolean();
		MutableBoolean addPeerLoadStatsBulk = new MutableBoolean();
		
		addPeerLoadStatsRT.value = true;
		addPeerLoadStatsBulk.value = true;

		long savedNextUrgentTime = cachedNextUrgentTime;
		int savedQueueSize = cachedQueueSize;

		/* queuesByPriority is expected to be modified, invalidate cache */
		cachedNextUrgentTime = Long.MIN_VALUE;
		cachedQueueSize = -1;
		
		for(int i=minPriority;i<DMT.PRIORITY_REALTIME_DATA;i++) {
			if(logMINOR) Logger.minor(this, "Adding from priority "+i);
			MessageItem ret = queuesByPriority[i].addPriorityMessages(now, addPeerLoadStatsRT, addPeerLoadStatsBulk);
			if(ret != null) return ret;
		}
		
		// Include bulk or realtime, whichever is more urgent.
		
		boolean tryRealtimeFirst = true;
		
		// If one is empty, try the other.
		// Otherwise try whichever is more urgent, favouring realtime if there is a draw.
		// Realtime is supposed to be bursty.
		
		if(queuesByPriority[DMT.PRIORITY_REALTIME_DATA].isEmpty()) {
			tryRealtimeFirst = false;
		} else if(queuesByPriority[DMT.PRIORITY_BULK_DATA].isEmpty()) {
			tryRealtimeFirst = true;
		} else {
			long rtNextUrgentTime = queuesByPriority[DMT.PRIORITY_REALTIME_DATA].getNextUrgentTime(Long.MAX_VALUE, 0);
			if(queuesByPriority[DMT.PRIORITY_BULK_DATA].getNextUrgentTime(Long.MAX_VALUE, rtNextUrgentTime) >= rtNextUrgentTime) {
				tryRealtimeFirst = true;
			} else {
				tryRealtimeFirst = false;
			}
		}
		
		// FIXME token bucket?
		if(tryRealtimeFirst) {
			// Try realtime first
			if(logMINOR) Logger.minor(this, "Trying realtime first");
			MessageItem ret = queuesByPriority[DMT.PRIORITY_REALTIME_DATA].addPriorityMessages(now, addPeerLoadStatsRT, addPeerLoadStatsBulk);
			if(ret != null) return ret;
			if(logMINOR) Logger.minor(this, "Trying bulk");
			ret = queuesByPriority[DMT.PRIORITY_BULK_DATA].addPriorityMessages(now, addPeerLoadStatsRT, addPeerLoadStatsBulk);
			if(ret != null) return ret;
		} else {
			// Try bulk first
			if(logMINOR) Logger.minor(this, "Trying bulk first");
			MessageItem ret = queuesByPriority[DMT.PRIORITY_BULK_DATA].addPriorityMessages(now, addPeerLoadStatsRT, addPeerLoadStatsBulk);
			if(ret != null) return ret;
			if(logMINOR) Logger.minor(this, "Trying realtime");
			ret = queuesByPriority[DMT.PRIORITY_REALTIME_DATA].addPriorityMessages(now, addPeerLoadStatsRT, addPeerLoadStatsBulk);
			if(ret != null) return ret;
		}
		for(int i=DMT.PRIORITY_BULK_DATA+1;i<DMT.NUM_PRIORITIES;i++) {
			if(i < minPriority) continue;
			if(logMINOR) Logger.minor(this, "Adding from priority "+i);
			MessageItem ret = queuesByPriority[i].addPriorityMessages(now, addPeerLoadStatsRT, addPeerLoadStatsBulk);
			if(ret != null) return ret;
		}
		// MessageItem was not removed from queues, restore cache (was not changed)
		cachedNextUrgentTime = savedNextUrgentTime;
		cachedQueueSize = savedQueueSize;
		// Nothing to send.
		return null;
	}
	
	public boolean removeMessage(MessageItem message) {
		synchronized(this) {
			short prio = message.getPriority();
			if(!queuesByPriority[prio].removeMessage(message)) return false;
			if (cachedNextUrgentTime == message.submitted + queuesByPriority[prio].timeout) {
				// invalidate cache only if removed message had same urgentTime as cached
				// TODO investigate if condition is not practically always true (by then, it is more efficient to unconditionally invalidate cache)
				cachedNextUrgentTime = Long.MIN_VALUE;
			}
			if (cachedQueueSize >= 0 && cachedQueueSizeIsComplete) {
				// adjust cached queue size
				cachedQueueSize -= message.getLength() + MESSAGE_OVERHEAD;
			} else {
				// cached size covers only part of queue, removed message might be not included -> invalidate cache
				cachedQueueSize = -1;
			}
		}
		message.onFailed();
		return true;
	}

	public synchronized void removeUIDsFromMessageQueues(Long[] list) {
		for(PrioQueue queue : queuesByPriority) {
			queue.removeUIDs(list);
		}
		/* queue.removeUIDs() only purges emptyItemsWithID; cachedQueueSize and cachedNextUrgentTime remain valid */
	}
}

