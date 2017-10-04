package freenet.node;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;

import org.junit.After;
import org.junit.Test;

import freenet.client.ClientMetadata;
import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchResult;
import freenet.client.FetchWaiter;
import freenet.client.HighLevelSimpleClient;
import freenet.client.InsertBlock;
import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.async.BinaryBlobWriter;
import freenet.client.async.ClientGetter;
import freenet.crypt.DummyRandomSource;
import freenet.keys.FreenetURI;
import freenet.keys.InsertableClientSSK;
import freenet.node.NodeStarter.TestNodeParameters;
import freenet.support.Executor;
import freenet.support.Logger;
import freenet.support.TestProperty;
import freenet.support.LoggerHook.InvalidThresholdException;
import freenet.support.PooledExecutor;
import freenet.support.SimpleReadOnlyArrayBucket;
import freenet.support.api.Bucket;
import freenet.support.api.RandomAccessBucket;
import freenet.support.io.BucketTools;
import freenet.support.io.FileUtil;

/** Creates a node, inserts data to it, and fetches the data back.
 * Note that we need one JUnit class per node because we need to actually exit the JVM
 * to get rid of all the node threads.
 * @author toad
 */
public class NodeAndClientLayerTest extends NodeAndClientLayerTestBase {

    private static final File dir = new File("test-fetch-pull-single-node");
    
    @Test
    public void testFetchPullSingleNode() throws InvalidThresholdException, NodeInitException, InsertException, FetchException, IOException {
        if(!TestProperty.EXTENSIVE) return;
        DummyRandomSource random = new DummyRandomSource(25312);
        final Executor executor = new PooledExecutor();
        FileUtil.removeAll(dir);
        dir.mkdir();
        NodeStarter.globalTestInit(dir, false, 
                Logger.LogLevel.ERROR, "", true, random);
        TestNodeParameters params = new TestNodeParameters();
        params.random = new DummyRandomSource(253121);
        params.ramStore = true;
        params.storeSize = FILE_SIZE * 3;
        params.baseDirectory = dir;
        params.executor = executor;
        Node node = NodeStarter.createTestNode(params);
        node.start();
        HighLevelSimpleClient client = node.clientCore.makeClient((short)0, false);
        InsertContext ictx = client.getInsertContext(true);
        ictx.localRequestOnly = true;
        InsertBlock block = generateBlock(random);
        FreenetURI uri = 
                client.insert(block, "", (short)0, ictx);
        assertEquals(uri.getKeyType(), "SSK");
        FetchContext ctx = client.getFetchContext(FILE_SIZE*2);
        ctx.localRequestOnly = true;
        FetchWaiter fw = new FetchWaiter(rc);
        client.fetch(uri, FILE_SIZE*2, fw, ctx, (short)0);
        FetchResult result = fw.waitForCompletion();
        assertTrue(BucketTools.equalBuckets(result.asBucket(), block.getData()));
    }
    
    @After
    public void cleanUp() {
        FileUtil.removeAll(dir);
    }
    
}
