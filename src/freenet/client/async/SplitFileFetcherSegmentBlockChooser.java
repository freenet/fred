package freenet.client.async;

import java.io.IOException;
import java.util.Random;

import freenet.node.KeysFetchingLocally;

public class SplitFileFetcherSegmentBlockChooser extends CooldownBlockChooser {

    public SplitFileFetcherSegmentBlockChooser(int blocks, Random random, int maxRetries,
            int cooldownTries, long cooldownTime, SplitFileFetcherSegmentStorage segment,
            KeysFetchingLocally keysFetching, int ignoreLastBlock) {
        super(blocks, random, maxRetries, cooldownTries, cooldownTime);
        this.segment = segment;
        this.keysFetching = keysFetching;
        this.ignoreLastBlock = ignoreLastBlock;
    }
    
    private final SplitFileFetcherSegmentStorage segment;
    private final KeysFetchingLocally keysFetching;
    private final int ignoreLastBlock;
    
    @Override
    protected boolean checkValid(int chosen) {
        if(!super.checkValid(chosen)) return false;
        if(chosen == ignoreLastBlock) return false;
        try {
            SplitFileSegmentKeys keys = segment.getSegmentKeys();
            if(keysFetching.hasKey(keys.getNodeKey(chosen, null), segment.parent.fetcher.getSendableGet()))
                return false;
            return true;
        } catch (final IOException e) {
            segment.parent.jobRunner.queueNormalOrDrop(new PersistentJob() {
                
                @Override
                public boolean run(ClientContext context) {
                    segment.parent.failOnDiskError(e);
                    return true;
                }
                
            });
            return false;
        }
    }

}
