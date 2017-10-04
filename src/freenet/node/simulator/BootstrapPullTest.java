package freenet.node.simulator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.Socket;

import freenet.support.math.MersenneTwister;

import freenet.client.FetchException;
import freenet.client.HighLevelSimpleClient;
import freenet.crypt.RandomSource;
import freenet.keys.FreenetURI;
import freenet.node.Node;
import freenet.node.NodeInitException;
import freenet.node.NodeStarter;
import freenet.support.PooledExecutor;
import freenet.support.SimpleFieldSet;
import freenet.support.TimeUtil;
import freenet.support.Logger.LogLevel;
import freenet.support.LoggerHook.InvalidThresholdException;
import freenet.support.io.FileUtil;
import freenet.support.io.LineReadingInputStream;

/**
 * Insert a random block of data to an established node via FCP, then
 * bootstrap a newbie node and pull it from that.
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class BootstrapPullTest {

	public static int TEST_SIZE = 1024*1024;

	public static int EXIT_NO_SEEDNODES = 257;
	public static int EXIT_FAILED_TARGET = 258;
	public static int EXIT_INSERT_FAILED = 259;
	public static int EXIT_FETCH_FAILED = 260;
	public static int EXIT_INSERTER_PROBLEM = 261;
	public static int EXIT_THREW_SOMETHING = 262;

	public static int DARKNET_PORT = 5000;
	public static int OPENNET_PORT = 5001;

	/**
	 * @param args
	 * @throws InvalidThresholdException
	 * @throws IOException
	 * @throws NodeInitException
	 * @throws InterruptedException
	 */
	public static void main(String[] args) throws InvalidThresholdException, IOException, NodeInitException, InterruptedException {
		Node secondNode = null;
		try {
		String ipOverride = null;
		if(args.length > 0)
			ipOverride = args[0];
        File dir = new File("bootstrap-pull-test");
        FileUtil.removeAll(dir);
        RandomSource random = NodeStarter.globalTestInit(dir.getPath(), false, LogLevel.ERROR, "", false);
        byte[] seed = new byte[64];
        random.nextBytes(seed);
        MersenneTwister fastRandom = new MersenneTwister(seed);
        File seednodes = new File("seednodes.fref");
        if(!seednodes.exists() || seednodes.length() == 0 || !seednodes.canRead()) {
        	System.err.println("Unable to read seednodes.fref, it doesn't exist, or is empty");
        	System.exit(EXIT_NO_SEEDNODES);
        }
        File secondInnerDir = new File(dir, Integer.toString(DARKNET_PORT));
        secondInnerDir.mkdir();
        FileInputStream fis = new FileInputStream(seednodes);
        FileUtil.writeTo(fis, new File(secondInnerDir, "seednodes.fref"));
        fis.close();

        // Create the test data
        System.out.println("Creating test data.");
        File dataFile = File.createTempFile("testdata", ".tmp", dir);
        OutputStream os = new FileOutputStream(dataFile);
        byte[] buf = new byte[4096];
        for(long written = 0; written < TEST_SIZE;) {
        	fastRandom.nextBytes(buf);
        	int toWrite = (int) Math.min(TEST_SIZE - written, buf.length);
        	os.write(buf, 0, toWrite);
        	written += toWrite;
        }
        os.close();

        // Insert it to the established node.
        System.out.println("Inserting test data to an established node.");
        FreenetURI uri = insertData(dataFile);

        // Bootstrap a second node.
        secondInnerDir.mkdir();
        fis = new FileInputStream(seednodes);
        FileUtil.writeTo(fis, new File(secondInnerDir, "seednodes.fref"));
        fis.close();
        PooledExecutor executor = new PooledExecutor();
        secondNode = NodeStarter.createTestNode(DARKNET_PORT, OPENNET_PORT, dir.getPath(), false, Node.DEFAULT_MAX_HTL, 0, random, executor, 1000, 5*1024*1024, true, true, true, true, true, true, true, 12*1024, false, true, false, false, ipOverride);
        secondNode.start();

		if (!TestUtil.waitForNodes(secondNode)) {
			secondNode.park();
			System.exit(EXIT_FAILED_TARGET);
		}

        // Fetch the data
        long startFetchTime = System.currentTimeMillis();
        HighLevelSimpleClient client = secondNode.clientCore.makeClient((short)0, false);
        try {
			client.fetch(uri);
		} catch (FetchException e) {
			System.err.println("FETCH FAILED: "+e);
			e.printStackTrace();
			System.exit(EXIT_FETCH_FAILED);
			return;
		}
		long endFetchTime = System.currentTimeMillis();
		System.out.println("RESULT: Fetch took "+(endFetchTime-startFetchTime)+"ms ("+TimeUtil.formatTime(endFetchTime-startFetchTime)+") of "+uri+" .");
		secondNode.park();
		System.exit(0);
	    } catch (Throwable t) {
	    	System.err.println("CAUGHT: "+t);
	    	t.printStackTrace();
	    	try {
	    		if(secondNode != null)
	    			secondNode.park();
	    	} catch (Throwable t1) {}
	    	System.exit(EXIT_THREW_SOMETHING);
	    }
	}

	private static FreenetURI insertData(File dataFile) throws IOException {
        long startInsertTime = System.currentTimeMillis();
        InetAddress localhost = InetAddress.getByName("127.0.0.1");
        Socket sock = new Socket(localhost, 9481);
        OutputStream sockOS = sock.getOutputStream();
        InputStream sockIS = sock.getInputStream();
        System.out.println("Connected to node.");
        LineReadingInputStream lis = new LineReadingInputStream(sockIS);
        OutputStreamWriter osw = new OutputStreamWriter(sockOS, "UTF-8");
        osw.write("ClientHello\nExpectedVersion=0.7\nName=BootstrapPullTest-"+System.currentTimeMillis()+"\nEnd\n");
        osw.flush();
       	String name = lis.readLine(65536, 128, true);
       	SimpleFieldSet fs = new SimpleFieldSet(lis, 65536, 128, true, false, true);
       	if(!name.equals("NodeHello")) {
       		System.err.println("No NodeHello from insertor node!");
       		System.exit(EXIT_INSERTER_PROBLEM);
       	}
       	System.out.println("Connected to "+sock);
       	osw.write("ClientPut\nIdentifier=test-insert\nURI=CHK@\nVerbosity=1023\nUploadFrom=direct\nMaxRetries=-1\nDataLength="+TEST_SIZE+"\nData\n");
       	osw.flush();
       	InputStream is = new FileInputStream(dataFile);
       	FileUtil.copy(is, sockOS, TEST_SIZE);
       	System.out.println("Sent data");
       	while(true) {
           	name = lis.readLine(65536, 128, true);
           	fs = new SimpleFieldSet(lis, 65536, 128, true, false, true);
       		System.out.println("Got FCP message: \n"+name);
       		System.out.print(fs.toOrderedString());
       		if(name.equals("ProtocolError")) {
       			System.err.println("Protocol error when inserting data.");
       			System.exit(EXIT_INSERTER_PROBLEM);
       		}
       		if(name.equals("PutFailed")) {
       			System.err.println("Insert failed");
       			System.exit(EXIT_INSERT_FAILED);
       		}
       		if(name.equals("PutSuccessful")) {
       	        long endInsertTime = System.currentTimeMillis();
       			FreenetURI uri = new FreenetURI(fs.get("URI"));
       	        System.out.println("RESULT: Insert took "+(endInsertTime-startInsertTime)+"ms ("+TimeUtil.formatTime(endInsertTime-startInsertTime)+") to "+uri+" .");
       			sockOS.close();
       			sockIS.close();
       			sock.close();
       			return uri;
       		}
       	}
	}
}
