package freenet.support;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.util.Arrays;

import org.tanukisoftware.wrapper.WrapperManager;

import freenet.client.async.ClientContext;
import freenet.client.async.ClientRequestSelector;
import freenet.client.async.RequestSelectionTreeNode;

/**
 * An array which supports very fast remove-and-return-a-random-element.
 * 
 * This is *NOT* persistent. The request selection structures are reconstructed on restart. However
 * it used to be, and probably has a lot of cruft and inefficiency as a result. 
 * 
 * LOCKING: There is a single lock for the entire tree, the ClientRequestSelector. This must be 
 * taken before calling any methods on RGA or SRGA. See the javadocs there for deeper explanation.
 * 
 * FIXME Simplify and improve performance. A lot of this is O(n), and this should probably be fixed. 
 * Memory usage was an issue but probably isn't now given that the individual items are now quite 
 * large (entire splitfiles or at least entire segments).
 */
public class RandomGrabArray implements RemoveRandom, RequestSelectionTreeNode {
	private static volatile boolean logMINOR;
	
	static {
		Logger.registerClass(RandomGrabArray.class);
	}
	
	private static class Block {
		RandomGrabArrayItem[] reqs;
	}
	
	/** Array of items. Non-null's followed by null's. 
	 * We used to have a Set so we could check whether something is in the set quickly.
	 * We got rid of this because for persistent requests it is vastly faster to just loop the
	 * loop and check ==, and for non-persistent requests it doesn't matter much. */
	private Block[] blocks;
	/** Index of first null item. */
	private int index;
	private final static int MIN_SIZE = 32;
	private final static int BLOCK_SIZE = 1024;
	private final int hashCode;
	private RemoveRandomParent parent;
	protected ClientRequestSelector root;
	private long wakeupTime;

	public RandomGrabArray(RemoveRandomParent parent, ClientRequestSelector root) {
		this.blocks = new Block[] { new Block() };
		blocks[0].reqs = new RandomGrabArrayItem[MIN_SIZE];
		index = 0;
		this.hashCode = super.hashCode();
		this.parent = parent;
		this.root = root;
	}
	
	@Override
	public int hashCode() {
		return hashCode;
	}
	
	public void add(RandomGrabArrayItem req, ClientContext context) {
		if(context != null && req.getWakeupTime(context, System.currentTimeMillis()) < 0) { 
			if(logMINOR) Logger.minor(this, "Is finished already: "+req);
			return;
		}
		req.setParentGrabArray(this); // will store() self
		synchronized(root) {
			if(context != null) {
			    clearWakeupTime(context);
			}
			int x = 0;
			if(blocks.length == 1 && index < BLOCK_SIZE) {
				for(int i=0;i<index;i++) {
					if(blocks[0].reqs[i] == req) {
						return;
					}
				}
				if(index >= blocks[0].reqs.length) {
					blocks[0].reqs = Arrays.copyOf(blocks[0].reqs, Math.min(BLOCK_SIZE, blocks[0].reqs.length*2));
				}
				blocks[0].reqs[index++] = req;
				if(logMINOR) Logger.minor(this, "Added "+req+" before index "+index);
				return;
			}
			int targetBlock = index / BLOCK_SIZE;
			for(int i=0;i<blocks.length;i++) {
				Block block = blocks[i];
				if(i != (blocks.length - 1) && block.reqs.length != BLOCK_SIZE) {
					Logger.error(this, "Block "+i+" of "+blocks.length+" is wrong size: "+block.reqs.length+" should be "+BLOCK_SIZE);
				}
				for(int j=0;j<block.reqs.length;j++) {
					if(x >= index) break;
					if(block.reqs[j] == req) {
						if(logMINOR) Logger.minor(this, "Already contains "+req+" : "+this+" size now "+index);
						return;
					}
					if(block.reqs[j] == null) {
						Logger.error(this, "reqs["+i+"."+j+"] = null on "+this);
					}
					x++;
				}
			}
			if(blocks.length <= targetBlock) {
				if(logMINOR)
					Logger.minor(this, "Adding blocks on "+this);
				Block[] newBlocks = Arrays.copyOf(blocks, targetBlock+1);
				for(int i=blocks.length;i<newBlocks.length;i++) {
					newBlocks[i] = new Block();
					newBlocks[i].reqs = new RandomGrabArrayItem[BLOCK_SIZE];
				}
				blocks = newBlocks;
			}
			Block target = blocks[targetBlock];
			target.reqs[index++ % BLOCK_SIZE] = req;
			if(logMINOR) Logger.minor(this, "Added: "+req+" to "+this+" size now "+index);
		}
	}
	
	/** Must be less than BLOCK_SIZE */
	static final int MAX_EXCLUDED = 10;
	
	@Override
	public RemoveRandomReturn removeRandom(RandomGrabArrayItemExclusionList excluding, ClientContext context, long now) {
		if(logMINOR) Logger.minor(this, "removeRandom() on "+this+" index="+index);
		synchronized(root) {
			if(index == 0) {
				if(logMINOR) Logger.minor(this, "All null on "+this);
				return null;
			}
			if(index < MAX_EXCLUDED) {
				return removeRandomExhaustiveSearch(excluding, context, now);
			}
			RandomGrabArrayItem ret = removeRandomLimited(excluding, context, now);
			if(ret != null)
				return new RemoveRandomReturn(ret);
			if(index == 0) {
				if(logMINOR) Logger.minor(this, "All null on "+this);
				return null;
			}
			return removeRandomExhaustiveSearch(excluding, context, now);
		}
	}
	
	private RandomGrabArrayItem removeRandomLimited(
			RandomGrabArrayItemExclusionList excluding,
			ClientContext context, long now) {
		int excluded = 0;
		while(true) {
			int i = context.fastWeakRandom.nextInt(index);
			int blockNo = i / BLOCK_SIZE;
			RandomGrabArrayItem ret, oret;
			ret = blocks[blockNo].reqs[i % BLOCK_SIZE];
			if(ret == null) {
				Logger.error(this, "reqs["+i+"] = null");
				remove(blockNo, i);
				continue;
			}
			if(ret.getWakeupTime(context, now) > 0) {
				excluded++;
				if(excluded > MAX_EXCLUDED) {
					return null;
				}
				continue;
			}
			oret = ret;
			long itemWakeTime = ret.getWakeupTime(context, now);
			if(itemWakeTime == -1) {
				if(logMINOR) Logger.minor(this, "Not returning because cancelled: "+ret);
				ret = null;
				// Will be removed in the do{} loop
				// Tell it that it's been removed first.
				oret.setParentGrabArray(null);
			}
			if(itemWakeTime == 0)
				itemWakeTime = excluding.exclude(ret, context, now);
			if(ret != null && itemWakeTime > 0) {
				excluded++;
				if(excluded > MAX_EXCLUDED) {
					return null;
				}
				continue;
			}
			if(ret != null) {
				if(logMINOR) Logger.minor(this, "Returning (cannot remove): "+ret+" of "+index);
				return ret;
			}
			// Remove an element.
			do {
				remove(blockNo, i);
				oret = blocks[blockNo].reqs[i % BLOCK_SIZE];
				// Check for nulls, but don't check for cancelled, since we'd have to activate.
			} while (index > i && oret == null);
			int newBlockCount;
			// Shrink array
			if(blocks.length == 1 && index < blocks[0].reqs.length / 4 && blocks[0].reqs.length > MIN_SIZE) {
				// Shrink array
				blocks[0].reqs = Arrays.copyOf(blocks[0].reqs, Math.max(index * 2, MIN_SIZE));
			} else if(blocks.length > 1 &&
					(newBlockCount = (((index + (BLOCK_SIZE/2)) / BLOCK_SIZE) + 1)) < 
					blocks.length) {
				if(logMINOR)
					Logger.minor(this, "Shrinking blocks on "+this);
				blocks = Arrays.copyOf(blocks, newBlockCount);
			}
			return ret;
		}
	}

	private RemoveRandomReturn removeRandomExhaustiveSearch(
			RandomGrabArrayItemExclusionList excluding,
			ClientContext context, long now) {
		if(logMINOR)
			Logger.minor(this, "Doing exhaustive search and compaction on "+this);
		long wakeupTime = Long.MAX_VALUE;
		RandomGrabArrayItem ret = null;
		int random = -1;
		while(true) {
			RandomGrabArrayItem[] reqsReading = blocks[0].reqs;
			RandomGrabArrayItem[] reqsWriting = blocks[0].reqs;
			int blockNumReading = 0;
			int blockNumWriting = 0;
			int offset = -1;
			int writeOffset = -1;
			int exclude = 0;
			int valid = 0;
			int validIndex = -1;
			int target = 0;
			RandomGrabArrayItem chosenItem = null;
			RandomGrabArrayItem validItem = null;
			for(int i=0;i<index;i++) {
				offset++;
				// Compact the array.
				RandomGrabArrayItem item;
				if(offset == BLOCK_SIZE) {
					offset = 0;
					blockNumReading++;
					reqsReading = blocks[blockNumReading].reqs;
				}
				item = reqsReading[offset];
				if(item == null) {
					if(logMINOR) Logger.minor(this, "Found null item at offset "+offset+" i="+i+" block = "+blockNumReading+" on "+this);
					continue;
				}
				boolean excludeItem = false;
				long itemWakeTime = item.getWakeupTime(context, now);
				if (itemWakeTime > 0) {
					// The item is in cooldown, will be wanted later.
					excludeItem = true;
					if (itemWakeTime < wakeupTime) {
						wakeupTime = itemWakeTime;
					}
				} else if (itemWakeTime == -1) {
					// The item is no longer needed and should be removed.
					if(logMINOR) {
						Logger.minor(this, "Removing "+item+" on "+this);
					}
					// We are doing compaction here. We don't need to swap with the end; we write valid ones to the target location.
					reqsReading[offset] = null;
					item.setParentGrabArray(null);
					continue;
				} else {
					long excludeTime = excluding.exclude(item, context, now);
					if (excludeTime > 0) {
						excludeItem = true;
						if(excludeTime < wakeupTime) {
							wakeupTime = excludeTime;
						}
					}
				}
				writeOffset++;
				if(writeOffset == BLOCK_SIZE) {
					writeOffset = 0;
					blockNumWriting++;
					reqsWriting = blocks[blockNumWriting].reqs;
				}
				if(i != target) {
					reqsReading[offset] = null;
					reqsWriting[writeOffset] = item;
				} // else the request can happily stay where it is
				target++;
				if(excludeItem) {
					exclude++;
				} else {
					if(valid == random) { // Picked on previous round
						chosenItem = item;
					}
					if(validIndex == -1) {
						// Take the first valid item
						validIndex = target-1;
						validItem = item;
					}
					valid++;
				}
			}
			if(index != target) {
				index = target;
			}
			// We reach this point if 1) the random number we picked last round is invalid because an item became cancelled or excluded
			// or 2) we are on the first round anyway.
			if(chosenItem != null) {
				ret = chosenItem;
				if(logMINOR) Logger.minor(this, "Chosen random item "+ret+" out of "+valid+" total "+index);
				return new RemoveRandomReturn(ret);
			}
			if(valid == 0 && exclude == 0) {
				if(logMINOR) Logger.minor(this, "No valid or excluded items total "+index);
				return null; // Caller should remove the whole RGA
			} else if(valid == 0) {
				if(logMINOR) Logger.minor(this, "No valid items, "+exclude+" excluded items total "+index);
				setWakeupTime(wakeupTime, context);
				return new RemoveRandomReturn(wakeupTime);
			} else if(valid == 1) {
				ret = validItem;
				if(logMINOR) Logger.minor(this, "No valid or excluded items apart from "+ret+" total "+index);
				return new RemoveRandomReturn(ret);
			} else {
				random = context.fastWeakRandom.nextInt(valid);
				if(logMINOR) Logger.minor(this, "Looping to choose valid item "+random+" of "+valid+" (excluded "+exclude+")");
				// Loop
			}
		}
	}

	/**
	 * blockNo is assumed to be already active. The last block is assumed not 
	 * to be.
	 */
	private void remove(int blockNo, int i) {
		index--;
		int endBlock = index / BLOCK_SIZE;
		if(blocks.length == 1 || blockNo == endBlock) {
			RandomGrabArrayItem[] items = blocks[blockNo].reqs;
			int idx = index % BLOCK_SIZE;
			items[i % BLOCK_SIZE] = items[idx];
			items[idx] = null;
		} else {
			RandomGrabArrayItem[] toItems = blocks[blockNo].reqs;
			RandomGrabArrayItem[] endItems = blocks[endBlock].reqs;
			toItems[i % BLOCK_SIZE] = endItems[index % BLOCK_SIZE];
			endItems[index % BLOCK_SIZE] = null;
		}
	}

	public void remove(RandomGrabArrayItem it, ClientContext context) {
		if(logMINOR)
			Logger.minor(this, "Removing "+it+" from "+this);
		
		boolean matched = false;
		boolean empty = false;
		synchronized(root) {
			if(blocks.length == 1) {
				Block block = blocks[0];
				for(int i=0;i<index;i++) {
					if(block.reqs[i] == it) {
						block.reqs[i] = block.reqs[--index];
						block.reqs[index] = null;
						matched = true;
						break;
					}
				}
				if(index == 0) empty = true;
			} else {
				int x = 0;
				for(int i=0;i<blocks.length;i++) {
					Block block = blocks[i];
					for(int j=0;j<block.reqs.length;j++) {
						if(x >= index) break;
						x++;
						if(block.reqs[j] == it) {
							int pullFrom = --index;
							int idx = pullFrom % BLOCK_SIZE;
							int endBlock = pullFrom / BLOCK_SIZE;
							if(i == endBlock) {
								block.reqs[j] = block.reqs[idx];
								block.reqs[idx] = null;
							} else {
								Block fromBlock = blocks[endBlock];
								block.reqs[j] = fromBlock.reqs[idx];
								fromBlock.reqs[idx] = null;
							}
							matched = true;
							break;
						}
					}
				}
				if(index == 0) empty = true;
			}
		}
		// Caller will typically clear it before calling for synchronization reasons.
		RandomGrabArray oldArray = it.getParentGrabArray();
		if(oldArray == this)
			it.setParentGrabArray(null);
		else if(oldArray != null)
			Logger.error(this, "Removing item "+it+" from "+this+" but RGA is "+it.getParentGrabArray(), new Exception("debug"));
		if(!matched) {
			if(logMINOR) Logger.minor(this, "Not found: "+it+" on "+this);
			return;
		}
		if(empty && parent != null) {
			parent.maybeRemove(this, context);
		}
	}

	public boolean isEmpty() {
	    synchronized(root) {
	        return index == 0;
	    }
	}
	
	public boolean contains(RandomGrabArrayItem item) {
		synchronized(root) {
			if(blocks.length == 1) {
				Block block = blocks[0];
				for(int i=0;i<index;i++) {
					if(block.reqs[i] == item) {
						return true;
					}
				}
			} else {
				int x = 0;
				for(int i=0;i<blocks.length;i++) {
					Block block = blocks[i];
					for(int j=0;j<block.reqs.length;j++) {
						if(x >= index) break;
						x++;
						if(block.reqs[i] == item) {
							return true;
						}
					}
				}
			}
		}
		return false;
	}
	
	public int size() {
	    synchronized(root) {
	        return index;
	    }
	}

	public RandomGrabArrayItem get(int idx) {
	    synchronized(root) {
	        int blockNo = idx / BLOCK_SIZE;
	        RandomGrabArrayItem item = blocks[blockNo].reqs[idx % BLOCK_SIZE];
	        return item;
	    }
	}
	
	// REDFLAG this method does not move cooldown items.
	// At present it is only called on startup so this is okay.
	public void moveElementsTo(RandomGrabArray existingGrabber) {
		WrapperManager.signalStarting((int) MINUTES.toMillis(5));
		for(Block block: blocks) {
			for(int j=0;j<block.reqs.length;j++) {
				RandomGrabArrayItem item = block.reqs[j];
				if(item == null) continue;
				item.setParentGrabArray(null);
				existingGrabber.add(item, null);
				block.reqs[j] = null;
			}
			System.out.println("Moved block in RGA "+this);
		}
	}

	@Override
	public void setParent(RemoveRandomParent newParent) {
	    synchronized(root) {
	        this.parent = newParent;
	    }
	}

    @Override
    public RequestSelectionTreeNode getParentGrabArray() {
        synchronized(root) {
            return parent;
        }
    }

    @Override
    public long getWakeupTime(ClientContext context, long now) {
        synchronized(root) {
            if(wakeupTime < now) wakeupTime = 0;
            return wakeupTime;
        }
    }
    
    /** Set the wakeup time, and update parents recursively if it is reduced. If it is increased
     * we don't need to bother parents as they will recompute the next time they need to. Only
     * called by removeRandomExhaustive() i.e. after checking <b>all</b> our 
     * RandomGrabArrayItem's and finding that none of them are ready to send.
     * @param wakeupTime
     * @param context
     */
    private void setWakeupTime(long wakeupTime, ClientContext context) {
        if(logMINOR) Logger.minor(this, "setCooldownTime("+(wakeupTime-System.currentTimeMillis())+") on "+this);
        synchronized(root) {
            if(this.wakeupTime > wakeupTime) {
                this.wakeupTime = wakeupTime; // Set before calling parent.
                if(parent != null) parent.reduceWakeupTime(wakeupTime, context);
            } else {
                this.wakeupTime = wakeupTime;
            }
        }
    }

    @Override
    public boolean reduceWakeupTime(long wakeupTime, ClientContext context) {
        if(logMINOR) Logger.minor(this, "reduceCooldownTime("+(wakeupTime-System.currentTimeMillis())+") on "+this);
        synchronized(root) {
            if(this.wakeupTime > wakeupTime) {
                this.wakeupTime = wakeupTime;
                if(parent != null) parent.reduceWakeupTime(wakeupTime, context);
                return true;
            }
            return false;
        }
    }

    @Override
    public void clearWakeupTime(ClientContext context) {
        if(logMINOR) Logger.minor(this, "clearCooldownTime() on "+this);
        synchronized(root) {
            wakeupTime = 0;
            if(parent != null) parent.clearWakeupTime(context);
        }
    }
	
}
