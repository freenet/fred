package freenet.node;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;

import org.junit.After;
import org.junit.Test;

import freenet.client.FetchContext;
import freenet.client.FetchException;
import freenet.client.FetchResult;
import freenet.client.FetchWaiter;
import freenet.client.HighLevelSimpleClient;
import freenet.client.InsertBlock;
import freenet.client.InsertContext;
import freenet.client.InsertException;
import freenet.client.async.BinaryBlob;
import freenet.client.async.BinaryBlobFormatException;
import freenet.client.async.BinaryBlobWriter;
import freenet.client.async.ClientGetter;
import freenet.client.async.SimpleBlockSet;
import freenet.crypt.DummyRandomSource;
import freenet.keys.FreenetURI;
import freenet.node.NodeStarter.TestNodeParameters;
import freenet.support.Executor;
import freenet.support.Logger;
import freenet.support.LoggerHook.InvalidThresholdException;
import freenet.support.PooledExecutor;
import freenet.support.TestProperty;
import freenet.support.api.Bucket;
import freenet.support.io.BucketTools;
import freenet.support.io.FileUtil;

public class NodeAndClientLayerBlobTest extends NodeAndClientLayerTestBase {

    private static final File dir = new File("test-fetch-pull-blob-single-node");
    
    @Test
    public void testFetchPullBlobSingleNode() throws InvalidThresholdException, NodeInitException, InsertException, FetchException, IOException, BinaryBlobFormatException {
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
        HighLevelSimpleClient client = 
                node.clientCore.makeClient((short)0, false);
        // First do an ordinary insert.
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
        // Now fetch the blob...
        fw = new FetchWaiter(rc);
        Bucket blobBucket = node.clientCore.tempBucketFactory.makeBucket(FILE_SIZE*3);
        BinaryBlobWriter bbw = new BinaryBlobWriter(blobBucket);
        ClientGetter getter = new ClientGetter(fw, uri, ctx, (short) 0, null, bbw, false, null, null);
        getter.start(node.clientCore.clientContext);
        fw.waitForCompletion();
        assertTrue(blobBucket.size() > 0);
        // Now bootstrap a second node, and fetch using the blob on that node.
        params = new TestNodeParameters();
        params.random = new DummyRandomSource(253121);
        params.ramStore = true;
        params.storeSize = FILE_SIZE * 3;
        params.baseDirectory = new File(dir, "fetchNode");
        params.baseDirectory.mkdir();
        params.executor = executor;
        Node node2 = NodeStarter.createTestNode(params);
        node2.start();
        HighLevelSimpleClient client2 = 
                node.clientCore.makeClient((short)0, false);
        FetchContext ctx2 = client.getFetchContext(FILE_SIZE*2);
        SimpleBlockSet blocks = new SimpleBlockSet();
        DataInputStream dis = new DataInputStream(blobBucket.getInputStream());
        BinaryBlob.readBinaryBlob(dis, blocks, true);
        ctx2 = new FetchContext(ctx2, FetchContext.IDENTICAL_MASK, true, blocks);
        fw = new FetchWaiter(rc);
        getter = client2.fetch(uri, FILE_SIZE*2, fw, ctx2, (short)0);
        result = fw.waitForCompletion();
        assertTrue(BucketTools.equalBuckets(result.asBucket(), block.getData()));
    }
    
    @After
    public void cleanUp() {
        FileUtil.removeAll(dir);
    }
    
}
