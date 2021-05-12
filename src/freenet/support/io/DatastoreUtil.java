package freenet.support.io;

import freenet.config.Config;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.NodeStarter;
import freenet.support.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class DatastoreUtil {

    public static final long oneMiB = 1024 * 1024;
    public static final long oneGiB = 1024 * 1024 * 1024;

    public static long maxDatastoreSize() {
        long maxDatastoreSize;

        // check ram limitations
        long maxMemory = NodeStarter.getMemoryLimitBytes();
        if (maxMemory == Long.MAX_VALUE || maxMemory < 128 * oneMiB) {
            maxDatastoreSize = oneGiB; // 1GB default if don't know or very small memory.
        } else {
            // Don't use the first 100MB for slot filters.
            long available = maxMemory - 100 * oneMiB;
            // Don't use more than 50% of available memory for slot filters.
            available = available / 2;
            // Slot filters are 4 bytes per slot.
            long slots = available / 4;
            // There are 3 types of keys. We want the number of { SSK, CHK, pubkey } i.e. the number of slots in each store.
            slots /= 3;
            // We return the total size, so we don't need to worry about cache vs store or even client cache.
            // One key of all 3 types combined uses Node.sizePerKey bytes on disk. So we get a size.
            maxDatastoreSize = slots * Node.sizePerKey; // in total this is (RAM - 100 MiB) / 24 * ~32 KiB
        }

        // check free disc space
        try {
            long unallocatedSpace = Files.getFileStore(Paths.get("")).getUnallocatedSpace();
            // TODO: leave some free space
            // probably limit 256GB see comments of the autodetectDatastoreSize method
            return unallocatedSpace < maxDatastoreSize ? unallocatedSpace : maxDatastoreSize;
        } catch (IOException e) {
            Logger.error(DatastoreUtil.class, "Error querying space", e);
        }

        return maxDatastoreSize;
    }

    public static long autodetectDatastoreSize(NodeClientCore core, Config config) {
        if (!config.get("node").getOption("storeSize").isDefault()) {
            return -1;
        }

        long freeSpace = core.node.getStoreDir().getUsableSpace();

        if (freeSpace <= 0) {
            return -1;
        } else {
            long shortSize;
            // Maximum for Freenet: 256GB. That's a 128MiB bloom filter.
            long bloomFilter128MiBMax = 256 * oneGiB;
            // Maximum to suggest to keep Disk I/O managable. This
            // value might need revisiting when hardware or
            // filesystems change.
            long diskIoMax = 20 * oneGiB;

            // Choose a suggested store size based on available free space.
            if (freeSpace > 50 * oneGiB) {
                // > 50 GiB: Use 10% free space; minimum 10 GiB. Limited by bloom filters and disk I/O.
                shortSize = Math.max(10 * oneGiB,
                        Math.min(freeSpace / 10,
                                Math.min(diskIoMax,
                                        bloomFilter128MiBMax)));
            } else if (freeSpace > 5 * oneGiB) {
                // > 5 GiB: Use 20% free space, minimum 2 GiB.
                shortSize = Math.max(freeSpace / 5, 2 * oneGiB);
            } else if (freeSpace > 2 * oneGiB) {
                // > 2 GiB: 512 MiB.
                shortSize = 512 * oneMiB;
            } else {
                // <= 2 GiB: 256 MiB.
                shortSize = 256 * oneMiB;
            }

            return shortSize;
        }
    }
}
