package freenet.client.async;

public class SplitFileFetcherCrossSegmentStorage {

    public final int crossSegmentNumber;
    
    SplitFileFetcherCrossSegmentStorage(int segNo) {
        crossSegmentNumber = segNo;
    }
    
    /** Called when a segment fetches a block that it believes to be relevant to us */
    public void onFetchedRelevantBlock(SplitFileFetcherSegmentStorage segment) {
        // TODO Auto-generated method stub
        
    }

    public void addDataBlock(SplitFileFetcherSegmentStorage seg, int blockNum) {
        // TODO Auto-generated method stub
        
    }

}
