/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.text.DateFormat;
import java.time.Clock;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Deque;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import freenet.client.FetchException;
import freenet.client.FetchResult;
import freenet.client.HighLevelSimpleClient;
import freenet.client.InsertBlock;
import freenet.client.InsertException;
import freenet.crypt.RandomSource;
import freenet.crypt.SHA256;
import freenet.crypt.Util;
import freenet.io.comm.ByteCounter;
import freenet.io.comm.DMT;
import freenet.io.comm.DisconnectedException;
import freenet.io.comm.Message;
import freenet.io.comm.MessageFilter;
import freenet.io.comm.NotConnectedException;
import freenet.keys.ClientCHK;
import freenet.keys.ClientKSK;
import freenet.keys.ClientKey;
import freenet.keys.ClientSSK;
import freenet.keys.FreenetURI;
import freenet.support.Base64;
import freenet.support.Fields;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.ShortBuffer;
import freenet.support.TimeSortedHashtable;
import freenet.support.io.ArrayBucket;
import freenet.support.io.Closer;
import freenet.support.math.BootstrappingDecayingRunningAverage;

/**
 * @author amphibian
 *
 * Tracks the Location of the node. Negotiates swap attempts.
 * Initiates swap attempts. Deals with locking.
 */
public class LocationManager implements ByteCounter {

    public static final String FOIL_PITCH_BLACK_ATTACK_PREFIX = "mitigate-pitch-black-attack-";
    public static long PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY = DAYS.toMillis(1);
    public static long PITCH_BLACK_MITIGATION_STARTUP_DELAY = MINUTES.toMillis(10);

    public class MyCallback extends SendMessageOnErrorCallback {

        RecentlyForwardedItem item;

        public MyCallback(Message message, PeerNode pn, RecentlyForwardedItem item) {
            super(message, pn, LocationManager.this);
            this.item = item;
        }

		@Override
        public void disconnected() {
            super.disconnected();
            removeRecentlyForwardedItem(item);
        }

		@Override
        public void acknowledged() {
            item.successfullyForwarded = true;
        }
    }

    static final long TIMEOUT = SECONDS.toMillis(60);
    static final int SWAP_MAX_HTL = 10;
    /** Number of swap evaluations, either incoming or outgoing, between resetting our location.
     * There is a 2 in SWAP_RESET chance that a reset will occur on one or other end of a swap request.
     *
     * ALCHEMY: This depends on a number of factors, not least the size of the network. It is hard to
     * get a good value from simulations. But it can take time to recover after a random reset, so we
     * have increased it from 4000 to 16000 on 8 april 2008. At the time location churn was significant,
     * and some of it likely caused by this. OTOH if we get major keyspace fragmentation, we must
     * reduce it to 8000 or 4000. */
    static final int SWAP_RESET = 16000;
	// FIXME vary automatically
    static final long SEND_SWAP_INTERVAL = SECONDS.toMillis(8);
    /** The average time between sending a swap request, and completion. */
    final BootstrappingDecayingRunningAverage averageSwapTime;
    /** Minimum swap delay */
    static final long MIN_SWAP_TIME = Node.MIN_INTERVAL_BETWEEN_INCOMING_SWAP_REQUESTS;
    /** Maximum swap delay */
    static final long MAX_SWAP_TIME = MINUTES.toMillis(1);
    /** Don't start swapping until our peers have had a reasonable chance to reconnect. */
    private static final long STARTUP_DELAY = MINUTES.toMillis(1);
    private static boolean logMINOR;
    final RandomSource r;
    final SwapRequestSender sender;
    final Node node;
    long timeLastSuccessfullySwapped;
    public static Clock clockForTesting = Clock.systemDefaultZone();

    public LocationManager(RandomSource r, Node node) {
        loc = r.nextDouble();
        sender = new SwapRequestSender();
        this.r = r;
        this.node = node;
        recentlyForwardedIDs = new Hashtable<Long, RecentlyForwardedItem>();
        // FIXME persist to disk!
        averageSwapTime = new BootstrappingDecayingRunningAverage(SEND_SWAP_INTERVAL, 0, Integer.MAX_VALUE, 20, null);
        timeLocSet = System.currentTimeMillis();

        logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
    }

    private double loc;
    private long timeLocSet;
    private double locChangeSession = 0.0;

    int numberOfRemotePeerLocationsSeenInSwaps = 0;

    /**
     * @return The current Location of this node.
     */
    public synchronized double getLocation() {
        return loc;
    }

    /**
     * @param l
     */
    public synchronized void setLocation(double l) {
    	if(!Location.isValid(l)) {
    		Logger.error(this, "Setting invalid location: "+l, new Exception("error"));
    		return;
    	}
        this.loc = l;
        timeLocSet = System.currentTimeMillis();
    }

    public synchronized void updateLocationChangeSession(double newLoc) {
    	double oldLoc = loc;
		double diff = Location.change(oldLoc, newLoc);
		if(logMINOR) Logger.minor(this, "updateLocationChangeSession: oldLoc: "+oldLoc+" -> newLoc: "+newLoc+" moved: "+diff);
		this.locChangeSession += diff;
    }

    /**
     * Start a thread to send FNPSwapRequests every second when
     * we are not locked.
     */
    public void start() {
    	if(node.enableSwapping) {
          node.getTicker().queueTimedJob(sender, STARTUP_DELAY);
      }
		node.ticker.queueTimedJob(new Runnable() {

			@Override
			public void run() {
				try {
					clearOldSwapChains();
					removeTooOldQueuedItems();
				} finally {
					node.ticker.queueTimedJob(this, SECONDS.toMillis(10));
				}
			}

		}, SECONDS.toMillis(10));
    	// Insert key to probe whether its part of the keyspace is operational. If it is not, switch location to it.
        node.ticker.queueTimedJob(new Runnable() {

            @Override
            public void run() {
                node.ticker.queueTimedJob(this, PITCH_BLACK_MITIGATION_FREQUENCY_ONE_DAY);
                if (swappingDisabled()) {
                    return;
                }
                LocalDateTime now = LocalDateTime.now(clockForTesting);
                String isoDateStringToday = DateTimeFormatter.ISO_DATE
                    .format(now);
                String isoDateStringYesterday = DateTimeFormatter.ISO_DATE
                    .format(now.minus(Duration.ofDays(1)));
                File[] previousInsertFromToday = node.userDir().dir()
                    .listFiles((file, name) -> name.startsWith(getPitchBlackPrefix(
                        isoDateStringToday)));
                HighLevelSimpleClient highLevelSimpleClient = node.clientCore.makeClient(
                    RequestStarter.INTERACTIVE_PRIORITY_CLASS,
                    true,
                    false);

                if (previousInsertFromToday != null
                    && previousInsertFromToday.length == 0) {
                    byte[] randomContentForKSK = new byte[20];
                    node.secureRandom.nextBytes(randomContentForKSK);
                    String randomPart = Base64.encode(randomContentForKSK);
                    String nameForInsert = getPitchBlackPrefix(isoDateStringToday + "-" + randomPart);
                    tryToInsertPitchBlackCheck(highLevelSimpleClient, nameForInsert);
                }

                File[] foilPitchBlackStatusFiles = node.userDir().dir()
                    .listFiles((file, name) -> name.startsWith(getPitchBlackPrefix("")));
                if (foilPitchBlackStatusFiles != null) {
                    File[] successfulInsertFromYesterday = Arrays.stream(foilPitchBlackStatusFiles)
                        .filter(file -> file.getName().contains(isoDateStringYesterday))
                        .toArray(File[]::new);
                    for (File f : successfulInsertFromYesterday) {
                        tryToRequestPitchBlackCheckFromYesterday(
                            highLevelSimpleClient,
                            successfulInsertFromYesterday[0]
                        );
                        // cleanup file, regardless of success
                        if (!f.delete()) {
                            f.deleteOnExit();
                        }
                    }
                    // delete files from more than one day ago
                    File[] leftoverFiles = Arrays.stream(foilPitchBlackStatusFiles)
                        .filter(file -> !file.getName().contains(isoDateStringToday))
                        .toArray(File[]::new);
                    for (File f : leftoverFiles) {
                        if (!f.delete()) {
                            f.deleteOnExit();
                        }
                    }
                }
            }
        }, PITCH_BLACK_MITIGATION_STARTUP_DELAY);
    }

    public String getPitchBlackPrefix(String middleSubstring) {
        return FOIL_PITCH_BLACK_ATTACK_PREFIX + middleSubstring;
    }

    private void tryToRequestPitchBlackCheckFromYesterday(
        HighLevelSimpleClient highLevelSimpleClient,
        File insertInfoFromYesterday) {
        ClientKSK insertFromYesterday = ClientKSK.create(insertInfoFromYesterday.getName());
        byte[] expectedContent;
        try {
            expectedContent = Files.readAllBytes(insertInfoFromYesterday.toPath());
        } catch (FileNotFoundException e) {
            Logger.warning(
                e,
                "Could not read from insert info file from yesterday because the file was not found: "
                    + insertInfoFromYesterday.getName());
            return;
        } catch (IOException e) {
            Logger.warning(
                e,
                "Could not read from insert info file from yesterday: "
                    + insertInfoFromYesterday.getName());
            return;
        }
        // check the SSK
        FetchResult sskFetchResult = null;
        try {
            sskFetchResult = highLevelSimpleClient.fetch(insertFromYesterday.getURI());
            if (!Arrays.equals(expectedContent, sskFetchResult.asByteArray())) {
                // if we received false data, this is definitely an attack: move there to provide a good node in the location
                switchLocationToDefendAgainstPitchBlackAttack(insertFromYesterday);
            }
        } catch (FetchException e) {
            if (isRequestExceptionBecauseUriIsNotAvailable(e) && node.fastWeakRandom.nextBoolean()) {
                // switch to the attacked location with only 50% probability,
                // because it could be caused by the defensive swap of another node
                // which made its current content inaccessible.
                switchLocationToDefendAgainstPitchBlackAttack(insertFromYesterday);
            }
            return;
        } catch (IOException e) {
            Logger.warning(
                e,
                "Could not convert fetched data into byteArray. fetch: "
                    + sskFetchResult);
            return;
        }
        // check the CHK
        ArrayBucket randomBucketToInsert = new ArrayBucket(expectedContent);
        InsertBlock chkInsertBlock = new InsertBlock(
            randomBucketToInsert,
            null,
            FreenetURI.EMPTY_CHK_URI);
        FreenetURI calculatedChkUri;
        try {
            calculatedChkUri = highLevelSimpleClient.insert(chkInsertBlock, true, null);
        } catch (InsertException e) {
            Logger.error(
                e,
                "Could not create CHK for expected content.");
            return;
        }
        try {
            highLevelSimpleClient.fetch(calculatedChkUri);
        } catch (FetchException e) {
            if (isRequestExceptionBecauseUriIsNotAvailable(e) && node.fastWeakRandom.nextBoolean()) {
                // switch to the attacked location with only 50% probability,
                // because it could be caused by the defensive swap of another node
                // which made its current content inaccessible.
                try {
                    switchLocationToDefendAgainstPitchBlackAttack(new ClientCHK(calculatedChkUri));
                } catch (MalformedURLException exception) {
                    Logger.error(
                        exception,
                        "Could not create ClientCHK from CHKUri for calculated CHK URI:"
                            + calculatedChkUri);
                    return;
                }
            }
        }

    }

    private void switchLocationToDefendAgainstPitchBlackAttack(ClientKey insertFromYesterday) {
        double probedLocationFromYesterday = insertFromYesterday
            .getNodeKey()
            .toNormalizedDouble();
        if (insertFromYesterday instanceof ClientSSK) {
            // decide between SSK and pubkey at random, because they always break together.
            if (node.fastWeakRandom.nextBoolean()) {
                probedLocationFromYesterday = Util.keyDigestAsNormalizedDouble(
                    ((ClientSSK) insertFromYesterday).getPubKey().getRoutingKey());
            }
        }
        Logger.warning(
            this,
            "could not fetch the insert from yesterday: "
                + insertFromYesterday.getURI().toString()
                + ", assuming we are under attack: switching location to failed location: "
                + probedLocationFromYesterday);
        setLocation(probedLocationFromYesterday);
    }

    private void tryToInsertPitchBlackCheck(
        HighLevelSimpleClient highLevelSimpleClient,
        String nameForInsert) {
        // create some random data of up to 1021 bytes to insert to the KSK
        byte[] contentLengthSource = new byte[2];
        node.fastWeakRandom.nextBytes(contentLengthSource);
        // bytes are -127 to 128,
        // so this gives us 253 to 1021 bytes of size
        int contentLength = (5 * 127)
            + (3 * contentLengthSource[0])
            + contentLengthSource[1] / 64; // -1 to 2
        byte[] randomContentToInsert = new byte[contentLength];
        node.fastWeakRandom.nextBytes(randomContentToInsert);
        ArrayBucket randomBucketToInsert = new ArrayBucket(randomContentToInsert);
        // create the KSK
        ClientKSK insertForToday = (ClientKSK.create(nameForInsert));
        InsertBlock kskInsertBlock = new InsertBlock(
            randomBucketToInsert,
            null,
            insertForToday.getInsertURI());
        // create the CHK
        InsertBlock chkInsertBlock = new InsertBlock(
            randomBucketToInsert,
            null,
            FreenetURI.EMPTY_CHK_URI);
        try {
            highLevelSimpleClient.insert(kskInsertBlock, false, null);
            highLevelSimpleClient.insert(chkInsertBlock, false, null);
            // create a file to check on the next run tomorrow
            File succeededInsertFile = node.userDir().file(nameForInsert);
            try (FileOutputStream fileOutputStream = new FileOutputStream(succeededInsertFile)) {
                fileOutputStream.write(randomContentToInsert);
            } catch (IOException e) {
                Logger.error(
                    e,
                    "Could not write successful insert content to file: " + nameForInsert);
            }
        } catch (InsertException e) {
            Logger.error(
                this,
                "could not insert pitch black detection data to KSK for today: "
                    + insertForToday.getURI().toString()
                    + ", trying again tomorrow.");
        }
    }

    private static boolean isRequestExceptionBecauseUriIsNotAvailable(FetchException fetchException) {
        return FetchException.FetchExceptionMode.DATA_NOT_FOUND.equals(fetchException.getMode());
    }

    /**
     * Sends an FNPSwapRequest every second unless the LM is locked
     * (which it will be most of the time)
     */
    public class SwapRequestSender implements Runnable {

        @Override
        public void run() {
            freenet.support.Logger.OSThread.logPID(this);
		    Thread.currentThread().setName("SwapRequestSender");
            while(true) {
                try {
                    long startTime = System.currentTimeMillis();
                    double nextRandom = r.nextDouble();
                    while(true) {
                        long sleepTime = getSendSwapInterval();
                        sleepTime *= nextRandom;
                        sleepTime = Math.min(sleepTime, Integer.MAX_VALUE);
                        long endTime = startTime + sleepTime;
                        long now = System.currentTimeMillis();
                        long diff = endTime - now;
                        try {
                            if(diff > 0)
                                Thread.sleep(Math.min((int)diff, SECONDS.toMillis(10)));
                        } catch (InterruptedException e) {
                            // Ignore
                        }
                        if(System.currentTimeMillis() >= endTime) break;
                    }
                    // FIXME shut down the swap initiator thread when swapping is disabled and re-enable it when swapping comes back up.
                    if(swappingDisabled()) {
                    	continue;
                    }
                    // Don't send one if we are locked
                    if(lock()) {
                        if(System.currentTimeMillis() - timeLastSuccessfullySwapped > SECONDS.toMillis(30)) {
                            try {
                                boolean myFlag = false;
                                double myLoc = getLocation();
                                for(PeerNode pn: node.peers.connectedPeers()) {
                                	PeerLocation l = pn.location;
                                    if(pn.isRoutable()) {
                                    	synchronized(l) {
                                    		double ploc = l.getLocation();
                                    		if(Location.equals(ploc, myLoc)) {
                                    			// Don't reset location unless we're SURE there is a problem.
                                    			// If the node has had its location equal to ours for at least 2 minutes, and ours has been likewise...
                                    			long now = System.currentTimeMillis();
                                    			if(now - l.getLocationSetTime() > MINUTES.toMillis(2) && now - timeLocSet > MINUTES.toMillis(2)) {
                                    				myFlag = true;
                                    				// Log an ERROR
                                    				// As this is an ERROR, it results from either a bug or malicious action.
                                    				// If it happens very frequently, it indicates either an attack or a serious bug.
                                    				Logger.error(this, "Randomizing location: my loc="+myLoc+" but loc="+ploc+" for "+pn);
                                    				break;
                                    			} else {
                                    				Logger.normal(this, "Node "+pn+" has identical location to us, waiting until this has persisted for 2 minutes...");
                                    			}
                                    		}
                                    	}
                                    }
                                }
                                if(myFlag) {
                                    setLocation(node.random.nextDouble());
                                    announceLocChange(true, true, true);
                                    node.writeNodeFile();
                                }
                            } finally {
                                unlock(false);
                            }
                        } else unlock(false);
                    } else {
                        continue;
                    }
                    // Send a swap request
                    startSwapRequest();
                } catch (Throwable t) {
                    Logger.error(this, "Caught "+t, t);
                }
            }
        }
    }

    /**
     * Create a new SwapRequest, send it from this node out into
     * the wilderness.
     */
    private void startSwapRequest() {
    	node.executor.execute(new OutgoingSwapRequestHandler(),
                "Outgoing swap request handler for port "+node.getDarknetPortNumber());
    }

    /**
     * Should we swap? LOCKING: Call without holding locks.
     * @return
     */
    public boolean swappingDisabled() {
    	// Swapping on opennet nodes, even hybrid nodes, causes significant and unnecessary location churn.
    	// Simulations show significantly improved performance if all opennet enabled nodes don't participate in swapping.
    	// FIXME: Investigate the possibility of enabling swapping on hybrid nodes with mostly darknet peers (more simulation needed).
    	// FIXME: Hybrid nodes with all darknet peers who haven't upgraded to HIGH.
    	// Probably we should have a useralert for this to get the user to do the right thing ... but we could auto-detect
    	// it and start swapping... however, we should not start swapping just because we temporarily have no opennet peers
    	// on startup.
    	return node.isOpennetEnabled();
	}

	public long getSendSwapInterval() {
    	long interval = (long) averageSwapTime.currentValue();
    	if(interval < MIN_SWAP_TIME)
    		interval = MIN_SWAP_TIME;
    	if(interval > MAX_SWAP_TIME)
    		interval = MAX_SWAP_TIME;
    	return interval;
	}

	/**
     * Similar to OutgoingSwapRequestHandler, except that we did
     * not initiate the SwapRequest.
     */
    public class IncomingSwapRequestHandler implements Runnable {

        Message origMessage;
        PeerNode pn;
        long uid;
        RecentlyForwardedItem item;

        IncomingSwapRequestHandler(Message msg, PeerNode pn, RecentlyForwardedItem item) {
            this.origMessage = msg;
            this.pn = pn;
            this.item = item;
            uid = origMessage.getLong(DMT.UID);
        }

        @Override
        public void run() {
		    freenet.support.Logger.OSThread.logPID(this);
            MessageDigest md = SHA256.getMessageDigest();

            boolean reachedEnd = false;
            try {
            // We are already locked by caller
            // Because if we can't get lock they need to send a reject

            // Firstly, is their message valid?

            byte[] hisHash = ((ShortBuffer)origMessage.getObject(DMT.HASH)).getData();

            if(hisHash.length != md.getDigestLength()) {
                Logger.error(this, "Invalid SwapRequest from peer: wrong length hash "+hisHash.length+" on "+uid);
                // FIXME: Should we send a reject?
                return;
            }

            // Looks okay, lets get on with it
            // Only one ID because we are only receiving
            addForwardedItem(uid, uid, pn, null);

            // Create my side

            long random = r.nextLong();
            double myLoc = getLocation();
            double[] friendLocs = node.peers.getPeerLocationDoubles(false);
            long[] myValueLong = new long[1+1+friendLocs.length];
            myValueLong[0] = random;
            myValueLong[1] = Double.doubleToLongBits(myLoc);
            for(int i=0;i<friendLocs.length;i++)
                myValueLong[i+2] = Double.doubleToLongBits(friendLocs[i]);
            byte[] myValue = Fields.longsToBytes(myValueLong);

            byte[] myHash = md.digest(myValue);

            Message m = DMT.createFNPSwapReply(uid, myHash);

            MessageFilter filter =
                MessageFilter.create().setType(DMT.FNPSwapCommit).setField(DMT.UID, uid).setTimeout(TIMEOUT).setSource(pn);

            node.usm.send(pn, m, LocationManager.this);

            Message commit;
            try {
                commit = node.usm.waitFor(filter, LocationManager.this);
            } catch (DisconnectedException e) {
            	if(logMINOR) Logger.minor(this, "Disconnected from "+pn+" while waiting for SwapCommit");
                return;
            }

            if(commit == null) {
                // Timed out. Abort
                Logger.error(this, "Timed out waiting for SwapCommit on "+uid+" - this can happen occasionally due to connection closes, if it happens often, there may be a serious problem");
                return;
            }

            // We have a SwapCommit

            byte[] hisBuf = ((ShortBuffer)commit.getObject(DMT.DATA)).getData();

            if((hisBuf.length % 8 != 0) || (hisBuf.length < 16)) {
                Logger.error(this, "Bad content length in SwapComplete - malicious node? on "+uid);
                return;
            }

            // First does it verify?

            byte[] rehash = md.digest(hisBuf);

            if(!java.util.Arrays.equals(rehash, hisHash)) {
                Logger.error(this, "Bad hash in SwapCommit - malicious node? on "+uid);
                return;
            }

            // Now decode it

            long[] hisBufLong = Fields.bytesToLongs(hisBuf);
	    if(hisBufLong.length < 2) {
		    Logger.error(this, "Bad buffer length (no random, no location)- malicious node? on "+uid);
		    return;
	    }

            long hisRandom = hisBufLong[0];

            double hisLoc = Double.longBitsToDouble(hisBufLong[1]);
            if(!Location.isValid(hisLoc)) {
                Logger.error(this, "Bad loc: "+hisLoc+" on "+uid);
                return;
            }
            registerKnownLocation(hisLoc);

            double[] hisFriendLocs = new double[hisBufLong.length-2];
            for(int i=0;i<hisFriendLocs.length;i++) {
                hisFriendLocs[i] = Double.longBitsToDouble(hisBufLong[i+2]);
                if(!Location.isValid(hisFriendLocs[i])) {
                    Logger.error(this, "Bad friend loc: "+hisFriendLocs[i]+" on "+uid);
                    return;
                }
                registerLocationLink(hisLoc, hisFriendLocs[i]);
                registerKnownLocation(hisFriendLocs[i]);
            }

            numberOfRemotePeerLocationsSeenInSwaps += hisFriendLocs.length;

            // Send our SwapComplete

            Message confirm = DMT.createFNPSwapComplete(uid, myValue);
            //confirm.addSubMessage(DMT.createFNPSwapLocations(extractUIDs(friendLocsAndUIDs)));

            node.usm.send(pn, confirm, LocationManager.this);

            boolean shouldSwap = shouldSwap(myLoc, friendLocs, hisLoc, hisFriendLocs, random ^ hisRandom);

            spyOnLocations(commit, true, shouldSwap, myLoc);

            if(shouldSwap) {
                timeLastSuccessfullySwapped = System.currentTimeMillis();
                // Swap
                updateLocationChangeSession(hisLoc);
                setLocation(hisLoc);
                if(logMINOR) Logger.minor(this, "Swapped: "+myLoc+" <-> "+hisLoc+" - "+uid);
                swaps++;
                announceLocChange(true, false, false);
                node.writeNodeFile();
            } else {
            	if(logMINOR) Logger.minor(this, "Didn't swap: "+myLoc+" <-> "+hisLoc+" - "+uid);
                noSwaps++;
            }

            reachedEnd = true;

            // Randomise our location every 2*SWAP_RESET swap attempts, whichever way it went.
            if(node.random.nextInt(SWAP_RESET) == 0) {
                setLocation(node.random.nextDouble());
                announceLocChange(true, true, false);
                node.writeNodeFile();
            }

            SHA256.returnMessageDigest(md);
        } catch (Throwable t) {
            Logger.error(this, "Caught "+t, t);
        } finally {
            unlock(reachedEnd); // we only count the time taken by our outgoing swap requests
            removeRecentlyForwardedItem(item);
        }
        }

    }

    /**
     * Locks the LocationManager.
     * Sends an FNPSwapRequest out into the network.
     * Waits for a reply.
     * Etc.
     */
    public class OutgoingSwapRequestHandler implements Runnable {

        RecentlyForwardedItem item;

        @Override
        public void run() {
		    freenet.support.Logger.OSThread.logPID(this);
            long uid = r.nextLong();
            if(!lock()) return;
            boolean reachedEnd = false;
            try {
                startedSwaps++;
                // We can't lock friends_locations, so lets just
                // pretend that they're locked
                long random = r.nextLong();
                double myLoc = getLocation();
                double[] friendLocs = node.peers.getPeerLocationDoubles(false);
                long[] myValueLong = new long[1+1+friendLocs.length];
                myValueLong[0] = random;
                myValueLong[1] = Double.doubleToLongBits(myLoc);
                for(int i=0;i<friendLocs.length;i++)
                    myValueLong[i+2] = Double.doubleToLongBits(friendLocs[i]);
                byte[] myValue = Fields.longsToBytes(myValueLong);

                byte[] myHash = SHA256.digest(myValue);

                Message m = DMT.createFNPSwapRequest(uid, myHash, SWAP_MAX_HTL);

                PeerNode pn = node.peers.getRandomPeer();
                if(pn == null) {
                    // Nowhere to send
                    return;
                }
                // Only 1 ID because we are sending; we won't receive
                item = addForwardedItem(uid, uid, null, pn);

                if(logMINOR) Logger.minor(this, "Sending SwapRequest "+uid+" to "+pn);

                MessageFilter filter1 =
                    MessageFilter.create().setType(DMT.FNPSwapRejected).setField(DMT.UID, uid).setSource(pn).setTimeout(TIMEOUT);
                MessageFilter filter2 =
                    MessageFilter.create().setType(DMT.FNPSwapReply).setField(DMT.UID, uid).setSource(pn).setTimeout(TIMEOUT);
                MessageFilter filter = filter1.or(filter2);

                node.usm.send(pn, m, LocationManager.this);

                if(logMINOR) Logger.minor(this, "Waiting for SwapReply/SwapRejected on "+uid);
                Message reply;
                try {
                    reply = node.usm.waitFor(filter, LocationManager.this);
                } catch (DisconnectedException e) {
                	if(logMINOR) Logger.minor(this, "Disconnected while waiting for SwapReply/SwapRejected for "+uid);
                    return;
                }

                if(reply == null) {
                    if(pn.isRoutable() && (System.currentTimeMillis() - pn.timeLastConnectionCompleted() > TIMEOUT*2)) {
                        // Timed out! Abort...
                        Logger.error(this, "Timed out waiting for SwapRejected/SwapReply on "+uid);
                    }
                    return;
                }

                if(reply.getSpec() == DMT.FNPSwapRejected) {
                    // Failed. Abort.
                	if(logMINOR) Logger.minor(this, "Swap rejected on "+uid);
                    return;
                }

                // We have an FNPSwapReply, yay
                // FNPSwapReply is exactly the same format as FNPSwapRequest
                byte[] hisHash = ((ShortBuffer)reply.getObject(DMT.HASH)).getData();

                Message confirm = DMT.createFNPSwapCommit(uid, myValue);
                //confirm.addSubMessage(DMT.createFNPSwapLocations(extractUIDs(friendLocsAndUIDs)));

                filter1.clearOr();
                MessageFilter filter3 = MessageFilter.create().setField(DMT.UID, uid).setType(DMT.FNPSwapComplete).setTimeout(TIMEOUT).setSource(pn);
                filter = filter1.or(filter3);

                node.usm.send(pn, confirm, LocationManager.this);

                if(logMINOR) Logger.minor(this, "Waiting for SwapComplete: uid = "+uid);

                try {
                    reply = node.usm.waitFor(filter, LocationManager.this);
                } catch (DisconnectedException e) {
                	if(logMINOR) Logger.minor(this, "Disconnected waiting for SwapComplete on "+uid);
                    return;
                }

                if(reply == null) {
                    if(pn.isRoutable() && (System.currentTimeMillis() - pn.timeLastConnectionCompleted() > TIMEOUT*2)) {
                        // Hrrrm!
                        Logger.error(this, "Timed out waiting for SwapComplete - malicious node?? on "+uid);
                    }
                    return;
                }

                if(reply.getSpec() == DMT.FNPSwapRejected) {
                    Logger.error(this, "Got SwapRejected while waiting for SwapComplete. This can happen occasionally because of badly timed disconnects, but if it happens frequently it indicates a bug or an attack");
                    return;
                }

                byte[] hisBuf = ((ShortBuffer)reply.getObject(DMT.DATA)).getData();

                if((hisBuf.length % 8 != 0) || (hisBuf.length < 16)) {
                    Logger.error(this, "Bad content length in SwapComplete - malicious node? on "+uid);
                    return;
                }

                // First does it verify?

                byte[] rehash = SHA256.digest(hisBuf);

                if(!java.util.Arrays.equals(rehash, hisHash)) {
                    Logger.error(this, "Bad hash in SwapComplete - malicious node? on "+uid);
                    return;
                }

                // Now decode it

		    long[] hisBufLong = Fields.bytesToLongs(hisBuf);
		    if(hisBufLong.length < 2) {
			    Logger.error(this, "Bad buffer length (no random, no location)- malicious node? on " + uid);
			    return;
		    }

                long hisRandom = hisBufLong[0];

                double hisLoc = Double.longBitsToDouble(hisBufLong[1]);
                if(!Location.isValid(hisLoc)) {
                    Logger.error(this, "Bad loc: "+hisLoc+" on "+uid);
                    return;
                }
                registerKnownLocation(hisLoc);

                double[] hisFriendLocs = new double[hisBufLong.length-2];
                for(int i=0;i<hisFriendLocs.length;i++) {
                    hisFriendLocs[i] = Double.longBitsToDouble(hisBufLong[i+2]);
                    if(!Location.isValid(hisFriendLocs[i])) {
                        Logger.error(this, "Bad friend loc: "+hisFriendLocs[i]+" on "+uid);
                        return;
                    }
                    registerLocationLink(hisLoc, hisFriendLocs[i]);
                    registerKnownLocation(hisFriendLocs[i]);
                }

                numberOfRemotePeerLocationsSeenInSwaps += hisFriendLocs.length;

                boolean shouldSwap = shouldSwap(myLoc, friendLocs, hisLoc, hisFriendLocs, random ^ hisRandom);

                spyOnLocations(reply, true, shouldSwap, myLoc);

                if(shouldSwap) {
                    timeLastSuccessfullySwapped = System.currentTimeMillis();
                    // Swap
                    updateLocationChangeSession(hisLoc);
                    setLocation(hisLoc);
                    if(logMINOR) Logger.minor(this, "Swapped: "+myLoc+" <-> "+hisLoc+" - "+uid);
                    swaps++;
                    announceLocChange(true, false, false);
                    node.writeNodeFile();
                } else {
                	if(logMINOR) Logger.minor(this, "Didn't swap: "+myLoc+" <-> "+hisLoc+" - "+uid);
                    noSwaps++;
                }

                reachedEnd = true;

                // Randomise our location every 2*SWAP_RESET swap attempts, whichever way it went.
                if(node.random.nextInt(SWAP_RESET) == 0) {
                    setLocation(node.random.nextDouble());
                    announceLocChange(true, true, false);
                    node.writeNodeFile();
                }

            } catch (Throwable t) {
                Logger.error(this, "Caught "+t, t);
            } finally {
                unlock(reachedEnd);
                if(item != null)
                    removeRecentlyForwardedItem(item);
            }
        }

    }

    /**
     * Tell all connected peers that our location has changed
     */
    protected void announceLocChange() {
	    announceLocChange(false, false, false);
    }

    private void announceLocChange(boolean log, boolean randomReset, boolean fromDupLocation) {
        Message msg = DMT.createFNPLocChangeNotificationNew(getLocation(), node.peers.getPeerLocationDoubles(true));
        node.peers.localBroadcast(msg, false, true, this);
	if(log)
		recordLocChange(randomReset, fromDupLocation);
    }

    private void recordLocChange(final boolean randomReset, final boolean fromDupLocation) {
        node.executor.execute(new Runnable() {

			@Override
			public void run() {
				File locationLog = node.nodeDir().file("location.log.txt");
				if(locationLog.exists() && locationLog.length() > 1024*1024*10)
					locationLog.delete();
				FileOutputStream os = null;
				try {
					os = new FileOutputStream(locationLog, true);
					BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(os, "ISO-8859-1"));
					DateFormat df = DateFormat.getDateTimeInstance();
					df.setTimeZone(TimeZone.getTimeZone("GMT"));
					bw.write(""+df.format(new Date())+" : "+getLocation()+(randomReset ? " (random reset"+(fromDupLocation?" from duplicated location" : "")+")" : "")+'\n');
					bw.close();
					os = null;
				} catch (IOException e) {
					Logger.error(this, "Unable to write changed location to "+locationLog+" : "+e, e);
				} finally {
					Closer.close(os);
				}
			}

        }, "Record new location");
	}

	private boolean locked;

    public static int swaps;
    public static int noSwaps;
    public static int startedSwaps;
    public static int swapsRejectedAlreadyLocked;
    public static int swapsRejectedNowhereToGo;
    public static int swapsRejectedRateLimit;
    public static int swapsRejectedRecognizedID;

    long lockedTime;

    /**
     * Lock the LocationManager.
     * @return True if we managed to lock the LocationManager,
     * false if it was already locked.
     */
    synchronized boolean lock() {
        if(locked) {
        	if(logMINOR) Logger.minor(this, "Already locked");
        	return false;
        }
        if(logMINOR) Logger.minor(this, "Locking on port "+node.getDarknetPortNumber());
        locked = true;
        lockedTime = System.currentTimeMillis();
        return true;
    }

    /**
     * Unlock the node for swapping.
     * @param logSwapTime If true, log the swap time. */
    void unlock(boolean logSwapTime) {
    	Message nextMessage;
    	synchronized(this) {
        if(!locked)
            throw new IllegalStateException("Unlocking when not locked!");
        long lockTime = System.currentTimeMillis() - lockedTime;
        if(logMINOR) {
        	Logger.minor(this, "Unlocking on port "+node.getDarknetPortNumber());
        	Logger.minor(this, "lockTime: "+lockTime);
        }
        averageSwapTime.report(lockTime);

        if(incomingMessageQueue.isEmpty()) {
        	locked = false;
        	return;
        }

        // Otherwise, stay locked, and start the next one from the queue.

        nextMessage = incomingMessageQueue.removeFirst();
        lockedTime = System.currentTimeMillis();

    	}

        long oldID = nextMessage.getLong(DMT.UID);
        long newID = oldID+1;
        PeerNode pn = (PeerNode) nextMessage.getSource();

    	innerHandleSwapRequest(oldID, newID, pn, nextMessage);
    }

    /**
     * Should we swap? This method implements the core of the Freenet
     * 0.7 routing algorithm - the criteria for swapping.
     * Oskar says this is derived from the Metropolis-Hastings algorithm.
     *
     * Anyway:
     * Two nodes choose each other and decide to attempt a switch. They
     * calculate the distance of all their edges currently (that is the
     * distance between their currend ID and that of their neighbors), and
     * multiply up all these values to get A. Then they calculate the
     * distance to all their neighbors as it would be if they switched
     * IDs, and multiply up these values to get B.
     *
     * If A > B then they switch.
     *
     * If A <= B, then calculate p = A / B. They then switch with
     * probability p (that is, switch if rand.nextFloat() < p).
     *
     * @param myLoc My location as a double.
     * @param friendLocs Locations of my friends as doubles.
     * @param hisLoc His location as a double
     * @param hisFriendLocs Locations of his friends as doubles.
     * @param rand Shared random number used to decide whether to swap.
     * @return
     */
    private boolean shouldSwap(double myLoc, double[] friendLocs, double hisLoc, double[] hisFriendLocs, long rand) {

        // A = distance from us to all our neighbours, for both nodes,
        // all multiplied together

        // Dump

    	if(Math.abs(hisLoc - myLoc) <= Double.MIN_VALUE * 2)
    		return false; // Probably swapping with self

        StringBuilder sb = new StringBuilder();

        sb.append("my: ").append(myLoc).append(", his: ").append(hisLoc).append(", myFriends: ");
        sb.append(friendLocs.length).append(", hisFriends: ").append(hisFriendLocs.length).append(" mine:\n");

        for(double loc: friendLocs) {
            sb.append(loc);
            sb.append(' ');
        }

        sb.append("\nhis:\n");

        for(double loc: hisFriendLocs) {
            sb.append(loc);
            sb.append(' ');
        }

        if(logMINOR) Logger.minor(this, sb.toString());

        double A = 1.0;
        for(double loc: friendLocs) {
            if(Math.abs(loc - myLoc) <= Double.MIN_VALUE*2) continue;
            A *= Location.distance(loc, myLoc);
        }
        for(double loc: hisFriendLocs) {
            if(Math.abs(loc - hisLoc) <= Double.MIN_VALUE*2) continue;
            A *= Location.distance(loc, hisLoc);
        }

        // B = the same, with our two values swapped
        double B = 1.0;
        for(double loc: friendLocs) {
            if(Math.abs(loc - hisLoc) <= Double.MIN_VALUE*2) continue;
            B *= Location.distance(loc, hisLoc);
        }
        for(double loc: hisFriendLocs) {
            if(Math.abs(loc - myLoc) <= Double.MIN_VALUE*2) continue;
            B *= Location.distance(loc, myLoc);
        }

        //Logger.normal(this, "A="+A+" B="+B);

        if(A>B) return true;

        double p = A / B;

        // Take last 63 bits, then turn into a double
        double randProb = ((double)(rand & Long.MAX_VALUE))
                / ((double) Long.MAX_VALUE);

        //Logger.normal(this, "p="+p+" randProb="+randProb);

        if(randProb < p) return true;
        return false;
    }

    static final double SWAP_ACCEPT_PROB = 0.25;

    final Hashtable<Long, RecentlyForwardedItem> recentlyForwardedIDs;

    static class RecentlyForwardedItem {
        final long incomingID; // unnecessary?
        final long outgoingID;
        final long addedTime;
        long lastMessageTime; // can delete when no messages for 2*TIMEOUT
        final PeerNode requestSender;
        PeerNode routedTo;
        // Set when a request is accepted. Unset when we send one.
        boolean successfullyForwarded;

        RecentlyForwardedItem(long id, long outgoingID, PeerNode from, PeerNode to) {
            this.incomingID = id;
            this.outgoingID = outgoingID;
            requestSender = from;
            routedTo = to;
            addedTime = System.currentTimeMillis();
            lastMessageTime = addedTime;
        }
    }

    /** Queue of swap requests to handle after this one. */
    private final Deque<Message> incomingMessageQueue = new LinkedList<Message>();

    static final int MAX_INCOMING_QUEUE_LENGTH = 10;

    /** Prevent timeouts and deadlocks due to A waiting for B waiting for A */
    static final long MAX_TIME_ON_INCOMING_QUEUE = SECONDS.toMillis(30);

    void removeTooOldQueuedItems() {
    	while(true) {
    		Message first;
    		synchronized(this) {
    			if(incomingMessageQueue.isEmpty()) return;
    			first = incomingMessageQueue.getFirst();
    			if(first.age() < MAX_TIME_ON_INCOMING_QUEUE) return;
    			incomingMessageQueue.removeFirst();
    			if(logMINOR) Logger.minor(this, "Cancelling queued item: "+first+" - too long on queue, maybe circular waiting?");
    			swapsRejectedAlreadyLocked++;
    		}
            long oldID = first.getLong(DMT.UID);
            PeerNode pn = (PeerNode) first.getSource();

            // Reject
            Message reject = DMT.createFNPSwapRejected(oldID);
            try {
                pn.sendAsync(reject, null, this);
            } catch (NotConnectedException e1) {
            	if(logMINOR) Logger.minor(this, "Lost connection rejecting SwapRequest (locked) from "+pn);
            }
    	}
    }

    /**
     * Handle an incoming SwapRequest
     * @return True if we have handled the message, false if it needs
     * to be handled otherwise.
     */
    public boolean handleSwapRequest(Message m, PeerNode pn) {
        final long oldID = m.getLong(DMT.UID);
        final long newID = oldID + 1;
        /**
         * UID is used to record the state i.e. UID x, came in from node a, forwarded to node b.
         * We increment it on each hop, because in order for the node selection to be as random as
         * possible we *must allow loops*! I.e. the same swap chain may pass over the same node
         * twice or more. However, if we get a request with either the incoming or the outgoing
         * UID, we can safely kill it as it's clearly the result of a bug.
         */
        RecentlyForwardedItem item = recentlyForwardedIDs.get(oldID);
        if(item != null) {
        	if(logMINOR) Logger.minor(this, "Rejecting - same ID as previous request");
            // Reject
            Message reject = DMT.createFNPSwapRejected(oldID);
            try {
                pn.sendAsync(reject, null, this);
            } catch (NotConnectedException e) {
            	if(logMINOR) Logger.minor(this, "Lost connection to "+pn+" rejecting SwapRequest");
            }
            swapsRejectedRecognizedID++;
            return true;
        }
        if(pn.shouldRejectSwapRequest()) {
        	if(logMINOR) Logger.minor(this, "Advised to reject SwapRequest by PeerNode - rate limit");
            // Reject
            Message reject = DMT.createFNPSwapRejected(oldID);
            try {
                pn.sendAsync(reject, null, this);
            } catch (NotConnectedException e) {
            	if(logMINOR) Logger.minor(this, "Lost connection rejecting SwapRequest from "+pn);
            }
            swapsRejectedRateLimit++;
            return true;
        }
        if(logMINOR) Logger.minor(this, "SwapRequest from "+pn+" - uid="+oldID);
        int htl = m.getInt(DMT.HTL);
        if(htl > SWAP_MAX_HTL) {
        	Logger.error(this, "Bogus swap HTL: "+htl+" from "+pn+" uid="+oldID);
        	htl = SWAP_MAX_HTL;
        }
        htl--;
        if(!node.enableSwapping || htl <= 0 && swappingDisabled()) {
            // Reject
            Message reject = DMT.createFNPSwapRejected(oldID);
            try {
                pn.sendAsync(reject, null, this);
            } catch (NotConnectedException e1) {
            	if(logMINOR) Logger.minor(this, "Lost connection rejecting SwapRequest (locked) from "+pn);
            }
            return true;
        }
        // Either forward it or handle it
        if(htl <= 0) {
        	if(logMINOR) Logger.minor(this, "Accepting?... "+oldID);
            // Accept - handle locally
        	lockOrQueue(m, oldID, newID, pn);
        	return true;
        } else {
            m.set(DMT.HTL, htl);
            m.set(DMT.UID, newID);
            if(logMINOR) Logger.minor(this, "Forwarding... "+oldID);
            while(true) {
                // Forward
                PeerNode randomPeer = node.peers.getRandomPeer(pn);
                if(randomPeer == null) {
                	if(logMINOR) Logger.minor(this, "Late reject "+oldID);
                    Message reject = DMT.createFNPSwapRejected(oldID);
                    try {
                        pn.sendAsync(reject, null, this);
                    } catch (NotConnectedException e1) {
                        Logger.normal(this, "Late reject but disconnected from sender: "+pn);
                    }
                    swapsRejectedNowhereToGo++;
                    return true;
                }
                if(logMINOR) Logger.minor(this, "Forwarding "+oldID+" to "+randomPeer);
                item = addForwardedItem(oldID, newID, pn, randomPeer);
                item.successfullyForwarded = false;
                try {
                    // Forward the request.
                    // Note that we MUST NOT send this blocking as we are on the
                    // receiver thread.
                    randomPeer.sendAsync(m.cloneAndDropSubMessages(), new MyCallback(DMT.createFNPSwapRejected(oldID), pn, item), LocationManager.this);
                } catch (NotConnectedException e) {
                	if(logMINOR) Logger.minor(this, "Not connected");
                    // Try a different node
                    continue;
                }
                return true;
            }
        }
    }

    /**
     * If we can obtain the lock, then execute the swap by calling innerHandleSwapRequest().
     * If we can queue the message, queue it.
     * Otherwise, reject it.
     */
    void lockOrQueue(Message msg, long oldID, long newID, PeerNode pn) {
    	boolean runNow = false;
    	boolean reject = false;
		if(logMINOR)
			Logger.minor(this, "Locking on port "+node.getDarknetPortNumber()+" for uid "+oldID+" from "+pn);
    	synchronized(this) {
    		if(!locked) {
    			locked = true;
    			runNow = true;
    	        lockedTime = System.currentTimeMillis();
    		} else {
    			// Locked.
    			if((!node.enableSwapQueueing) ||
    					incomingMessageQueue.size() > MAX_INCOMING_QUEUE_LENGTH) {
    				// Reject anyway.
    				reject = true;
    				swapsRejectedAlreadyLocked++;
    				if(logMINOR) Logger.minor(this, "Incoming queue length too large: "+incomingMessageQueue.size()+" rejecting "+msg);
    			} else {
    				// Queue it.
    				incomingMessageQueue.addLast(msg);
    				if(logMINOR) Logger.minor(this, "Queued "+msg+" queue length "+incomingMessageQueue.size());
    			}
    		}
    	}
    	if(reject) {
    		if(logMINOR) Logger.minor(this, "Rejecting "+msg);
            Message rejected = DMT.createFNPSwapRejected(oldID);
            try {
                pn.sendAsync(rejected, null, this);
            } catch (NotConnectedException e1) {
            	if(logMINOR) Logger.minor(this, "Lost connection rejecting SwapRequest (locked) from "+pn);
            }
    	} else if(runNow) {
    		if(logMINOR) Logger.minor(this, "Running "+msg);
    		boolean completed = false;
    		try {
    			innerHandleSwapRequest(oldID, newID, pn, msg);
    			completed = true;
    		} finally {
    			if(!completed)
    				unlock(false);
    		}
    	}
    }

    private void innerHandleSwapRequest(long oldID, long newID, PeerNode pn, Message m) {
    	RecentlyForwardedItem item = addForwardedItem(oldID, newID, pn, null);
        // Locked, do it
        IncomingSwapRequestHandler isrh =
            new IncomingSwapRequestHandler(m, pn, item);
        if(logMINOR) Logger.minor(this, "Handling... "+oldID+" from "+pn);
        node.executor.execute(isrh, "Incoming swap request handler for port "+node.getDarknetPortNumber());
	}

	private RecentlyForwardedItem addForwardedItem(long uid, long oid, PeerNode pn, PeerNode randomPeer) {
        RecentlyForwardedItem item = new RecentlyForwardedItem(uid, oid, pn, randomPeer);
        synchronized(recentlyForwardedIDs) {
        	recentlyForwardedIDs.put(uid, item);
			recentlyForwardedIDs.put(oid, item);
        }
        return item;
    }

    /**
     * Handle an unmatched FNPSwapReply
     * @return True if we recognized and forwarded this reply.
     */
    public boolean handleSwapReply(Message m, PeerNode source) {
        final long uid = m.getLong(DMT.UID);
		RecentlyForwardedItem item = recentlyForwardedIDs.get(uid);
        if(item == null) {
            Logger.error(this, "Unrecognized SwapReply: ID "+uid);
            return false;
        }
        if(item.requestSender == null) {
        	if(logMINOR) Logger.minor(this, "SwapReply from "+source+" on chain originated locally "+uid);
            return false;
        }
        if(item.routedTo == null) {
            Logger.error(this, "Got SwapReply on "+uid+" but routedTo is null!");
            return false;
        }
        if(source != item.routedTo) {
            Logger.error(this, "Unmatched swapreply "+uid+" from wrong source: From "+source+
                    " should be "+item.routedTo+" to "+item.requestSender);
            return true;
        }
        item.lastMessageTime = System.currentTimeMillis();
        // Returning to source - use incomingID
        byte[] hisHash = ((ShortBuffer)m.getObject(DMT.HASH)).getData();
        Message fwd = DMT.createFNPSwapReply(item.incomingID, hisHash);
        if(logMINOR) Logger.minor(this, "Forwarding SwapReply "+uid+" from "+source+" to "+item.requestSender);
        try {
            item.requestSender.sendAsync(fwd, null, this);
        } catch (NotConnectedException e) {
        	if(logMINOR) Logger.minor(this, "Lost connection forwarding SwapReply "+uid+" to "+item.requestSender);
        }
        return true;
    }

    /**
     * Handle an unmatched FNPSwapRejected
     * @return True if we recognized and forwarded this message.
     */
    public boolean handleSwapRejected(Message m, PeerNode source) {
        final long uid = m.getLong(DMT.UID);
		RecentlyForwardedItem item = recentlyForwardedIDs.get(uid);
        if(item == null) return false;
        if(item.requestSender == null){
        	if(logMINOR) Logger.minor(this, "Got a FNPSwapRejected without any requestSender set! we can't and won't claim it! UID="+uid);
        	return false;
        }
        if(item.routedTo == null) {
            Logger.error(this, "Got SwapRejected on "+uid+" but routedTo is null!");
            return false;
        }
        if(source != item.routedTo) {
            Logger.error(this, "Unmatched swapreply "+uid+" from wrong source: From "+source+
                    " should be "+item.routedTo+" to "+item.requestSender);
            return true;
        }
        removeRecentlyForwardedItem(item);
        item.lastMessageTime = System.currentTimeMillis();
        if(logMINOR) Logger.minor(this, "Forwarding SwapRejected "+uid+" from "+source+" to "+item.requestSender);
        m = m.cloneAndDropSubMessages();
        // Returning to source - use incomingID
        m.set(DMT.UID, item.incomingID);
        try {
            item.requestSender.sendAsync(m, null, this);
        } catch (NotConnectedException e) {
        	if(logMINOR) Logger.minor(this, "Lost connection forwarding SwapRejected "+uid+" to "+item.requestSender);
        }
        return true;
    }

    /**
     * Handle an unmatched FNPSwapCommit
     * @return True if we recognized and forwarded this message.
     */
    public boolean handleSwapCommit(Message m, PeerNode source) {
        final long uid = m.getLong(DMT.UID);
		RecentlyForwardedItem item = recentlyForwardedIDs.get(uid);
        if(item == null) return false;
        if(item.routedTo == null) return false;
        if(source != item.requestSender) {
            Logger.error(this, "Unmatched swapreply "+uid+" from wrong source: From "+source+
                    " should be "+item.requestSender+" to "+item.routedTo);
            return true;
        }
        item.lastMessageTime = System.currentTimeMillis();
        if(logMINOR) Logger.minor(this, "Forwarding SwapCommit "+uid+ ',' +item.outgoingID+" from "+source+" to "+item.routedTo);
        m = m.cloneAndDropSubMessages();
        // Sending onwards - use outgoing ID
        m.set(DMT.UID, item.outgoingID);
        try {
            item.routedTo.sendAsync(m, new SendMessageOnErrorCallback(DMT.createFNPSwapRejected(item.incomingID), item.requestSender, this), this);
        } catch (NotConnectedException e) {
        	if(logMINOR) Logger.minor(this, "Lost connection forwarding SwapCommit "+uid+" to "+item.routedTo);
        }
        spyOnLocations(m, false);
        return true;
    }

	/**
     * Handle an unmatched FNPSwapComplete
     * @return True if we recognized and forwarded this message.
     */
    public boolean handleSwapComplete(Message m, PeerNode source) {
        final long uid = m.getLong(DMT.UID);
        if(logMINOR) Logger.minor(this, "handleSwapComplete("+uid+ ')');
        RecentlyForwardedItem item = recentlyForwardedIDs.get(uid);
        if(item == null) {
        	if(logMINOR) Logger.minor(this, "Item not found: "+uid+": "+m);
            return false;
        }
        if(item.requestSender == null) {
        	if(logMINOR) Logger.minor(this, "Not matched "+uid+": "+m);
            return false;
        }
        if(item.routedTo == null) {
            Logger.error(this, "Got SwapComplete on "+uid+" but routedTo == null! (meaning we accepted it, presumably)");
            return false;
        }
        if(source != item.routedTo) {
            Logger.error(this, "Unmatched swapreply "+uid+" from wrong source: From "+source+
                    " should be "+item.routedTo+" to "+item.requestSender);
            return true;
        }
        if(logMINOR) Logger.minor(this, "Forwarding SwapComplete "+uid+" from "+source+" to "+item.requestSender);
        m = m.cloneAndDropSubMessages();
        // Returning to source - use incomingID
        m.set(DMT.UID, item.incomingID);
        try {
            item.requestSender.sendAsync(m, null, this);
        } catch (NotConnectedException e) {
            Logger.normal(this, "Lost connection forwarding SwapComplete "+uid+" to "+item.requestSender);
        }
        item.lastMessageTime = System.currentTimeMillis();
        removeRecentlyForwardedItem(item);
        spyOnLocations(m, false);
        return true;
    }

    private void spyOnLocations(Message m, boolean ignoreIfOld) {
    	spyOnLocations(m, ignoreIfOld, false, -1.0);
    }

    /** Spy on locations in somebody else's swap request. Greatly increases the
     * speed at which we can gather location data to estimate the network's size.
     * @param swappingWithMe True if this node is participating in the swap, false if it is
     * merely spying on somebody else's swap.
     */
    private void spyOnLocations(Message m, boolean ignoreIfOld, boolean swappingWithMe, double myLoc) {

    	long[] uids = null;

    	Message uidsMessage = m.getSubMessage(DMT.FNPSwapNodeUIDs);
    	if(uidsMessage != null) {
    		uids = Fields.bytesToLongs(((ShortBuffer) uidsMessage.getObject(DMT.NODE_UIDS)).getData());
    	}

        byte[] data = ((ShortBuffer)m.getObject(DMT.DATA)).getData();

        if(data.length < 16 || data.length % 8 != 0) {
        	Logger.error(this, "Data invalid length in swap commit: "+data.length, new Exception("error"));
        	return;
        }

        double[] locations = Fields.bytesToDoubles(data, 8, data.length-8);

        double hisLoc = locations[0];
        if(!Location.isValid(hisLoc)) {
        	Logger.error(this, "Invalid hisLoc in swap commit: "+hisLoc, new Exception("error"));
        	return;
        }

        if(uids != null) {
        	registerKnownLocation(hisLoc, uids[0]);
        	if(swappingWithMe)
        		registerKnownLocation(myLoc, uids[0]);
        } else if (!ignoreIfOld)
        	registerKnownLocation(hisLoc);

        for(int i=1;i<locations.length;i++) {
        	double loc = locations[i];
        	if(uids != null) {
        		registerKnownLocation(loc, uids[i-1]);
        		registerLink(uids[0], uids[i-1]);
        	} else if(!ignoreIfOld) {
        		registerKnownLocation(loc);
        		registerLocationLink(hisLoc, loc);
        	}
        }

	}

    public void clearOldSwapChains() {
        long now = System.currentTimeMillis();
        synchronized(recentlyForwardedIDs) {
            RecentlyForwardedItem[] items = new RecentlyForwardedItem[recentlyForwardedIDs.size()];
            if(items.length < 1)
            	return;
            items = recentlyForwardedIDs.values().toArray(items);
            for(RecentlyForwardedItem item: items) {
                if(now - item.lastMessageTime > (TIMEOUT*2)) {
                    removeRecentlyForwardedItem(item);
                }
            }
        }
    }

    /**
     * We lost the connection to a node, or it was restarted.
     */
    public void lostOrRestartedNode(PeerNode pn) {
        List<RecentlyForwardedItem> v = new ArrayList<RecentlyForwardedItem>();
        synchronized(recentlyForwardedIDs) {
        	Set<Map.Entry<Long, RecentlyForwardedItem>> entrySet = recentlyForwardedIDs.entrySet();
			for (Map.Entry<Long, RecentlyForwardedItem> entry : entrySet) {
				Long l = entry.getKey();
				RecentlyForwardedItem item = entry.getValue();

                if(item == null) {
                	Logger.error(this, "Key is "+l+" but no value on recentlyForwardedIDs - shouldn't be possible");
                	continue;
                }
                if(item.routedTo != pn) continue;
                if(item.successfullyForwarded) {
                    v.add(item);
                }
            }

			// remove them
			for (RecentlyForwardedItem item : v)
				removeRecentlyForwardedItem(item);
        }
		int dumped=v.size();
		if (dumped!=0 && logMINOR)
			Logger.minor(this, "lostOrRestartedNode dumping "+dumped+" swap requests for "+pn.getPeer());
        for(RecentlyForwardedItem item : v) {
            // Just reject it to avoid locking problems etc
            Message msg = DMT.createFNPSwapRejected(item.incomingID);
            if(logMINOR) Logger.minor(this, "Rejecting in lostOrRestartedNode: "+item.incomingID+ " from "+item.requestSender);
            try {
                item.requestSender.sendAsync(msg, null, this);
            } catch (NotConnectedException e1) {
                Logger.normal(this, "Both sender and receiver disconnected for "+item);
            }
        }
    }

    private void removeRecentlyForwardedItem(RecentlyForwardedItem item) {
    	if(logMINOR) Logger.minor(this, "Removing: "+item);
        if(item == null) {
            Logger.error(this, "removeRecentlyForwardedItem(null)", new Exception("error"));
        }
        synchronized(recentlyForwardedIDs) {
        	recentlyForwardedIDs.remove(item.incomingID);
			recentlyForwardedIDs.remove(item.outgoingID);
        }
    }

    private static final long MAX_AGE = DAYS.toMillis(7);

    private final TimeSortedHashtable<Double> knownLocs = new TimeSortedHashtable<Double>();

    void registerLocationLink(double d, double t) {
    	if(logMINOR) Logger.minor(this, "Known Link: "+d+ ' ' +t);
    }

    void registerKnownLocation(double d, long uid) {
    	if(logMINOR) Logger.minor(this, "LOCATION: "+d+" UID: "+uid);
    	registerKnownLocation(d);
    }

    void registerKnownLocation(double d) {
    	if(logMINOR) Logger.minor(this, "Known Location: "+d);
        long now = System.currentTimeMillis();

        synchronized(knownLocs) {
        	Logger.minor(this, "Adding location "+d+" knownLocs size "+knownLocs.size());
        	knownLocs.push(d, now);
        	Logger.minor(this, "Added location "+d+" knownLocs size "+knownLocs.size());
        	knownLocs.removeBefore(now - MAX_AGE);
        	Logger.minor(this, "Added and pruned location "+d+" knownLocs size "+knownLocs.size());
        }
		if(logMINOR) Logger.minor(this, "Estimated net size(session): "+knownLocs.size());
    }

    void registerLink(long uid1, long uid2) {
    	if(logMINOR) Logger.minor(this, "UID LINK: "+uid1+" , "+uid2);
    }

    //Return the estimated network size based on locations seen after timestamp or for the whole session if -1
    public int getNetworkSizeEstimate(long timestamp) {
   		return knownLocs.countValuesAfter(timestamp);
	}

    /**
     * Method called by Node.getKnownLocations(long timestamp)
     *
     * @return an array containing two cells : Locations and their last seen time for a given timestamp.
     */
    public Object[] getKnownLocations(long timestamp) {
    	synchronized (knownLocs) {
    		return knownLocs.pairsAfter(timestamp, new Double[knownLocs.size()]);
    	}
	}

	public static void setClockForTesting(Clock clock) {
        clockForTesting = clock;
  }

	public static Clock getClockForTesting() {
        return clockForTesting;
  }

	public static double[] extractLocs(PeerNode[] peers, boolean indicateBackoff) {
		double[] locs = new double[peers.length];
		for(int i=0;i<peers.length;i++) {
			locs[i] = peers[i].getLocation();
			if(indicateBackoff) {
				if(peers[i].isRoutingBackedOffEither())
					locs[i] += 1;
				else
					locs[i] = -1 - locs[i];
			}
		}
		return locs;
	}

	public static long[] extractUIDs(PeerNode[] peers) {
		long[] uids = new long[peers.length];
		for(int i=0;i<peers.length;i++)
			uids[i] = peers[i].swapIdentifier;
		return uids;
	}

	public synchronized double getLocChangeSession() {
		return locChangeSession;
	}

	public int getAverageSwapTime() {
		return (int) averageSwapTime.currentValue();
	}

	@Override
	public void receivedBytes(int x) {
		node.nodeStats.swappingReceivedBytes(x);
	}

	@Override
	public void sentBytes(int x) {
		node.nodeStats.swappingSentBytes(x);
	}

	@Override
	public void sentPayload(int x) {
		Logger.error(this, "LocationManager sentPayload()?", new Exception("debug"));
	}
}
