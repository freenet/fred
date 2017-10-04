/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node;

import freenet.client.async.ClientContext;
import freenet.client.async.ClientRequestScheduler;
import freenet.config.Config;
import freenet.config.EnumerableOptionCallback;
import freenet.config.InvalidConfigValueException;
import freenet.config.SubConfig;
import freenet.crypt.RandomSource;
import freenet.keys.Key;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.SimpleFieldSet;
import freenet.support.TimeUtil;
import freenet.support.api.StringCallback;
import freenet.support.math.BootstrappingDecayingRunningAverage;

import static java.util.concurrent.TimeUnit.MINUTES;

public class RequestStarterGroup {
	private static volatile boolean logMINOR;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	private final ThrottleWindowManager throttleWindowBulk;
	private final ThrottleWindowManager throttleWindowRT;
	// These are for diagnostic purposes
	private final ThrottleWindowManager throttleWindowCHK;
	private final ThrottleWindowManager throttleWindowSSK;
	private final ThrottleWindowManager throttleWindowInsert;
	private final ThrottleWindowManager throttleWindowRequest;
	final MyRequestThrottle chkRequestThrottleBulk;
	final RequestStarter chkRequestStarterBulk;
	final MyRequestThrottle chkInsertThrottleBulk;
	final RequestStarter chkInsertStarterBulk;
	final MyRequestThrottle sskRequestThrottleBulk;
	final RequestStarter sskRequestStarterBulk;
	final MyRequestThrottle sskInsertThrottleBulk;
	final RequestStarter sskInsertStarterBulk;
	
	final MyRequestThrottle chkRequestThrottleRT;
	final RequestStarter chkRequestStarterRT;
	final MyRequestThrottle chkInsertThrottleRT;
	final RequestStarter chkInsertStarterRT;
	final MyRequestThrottle sskRequestThrottleRT;
	final RequestStarter sskRequestStarterRT;
	final MyRequestThrottle sskInsertThrottleRT;
	final RequestStarter sskInsertStarterRT;

	public final ClientRequestScheduler chkFetchSchedulerBulk;
	public final ClientRequestScheduler chkPutSchedulerBulk;
	public final ClientRequestScheduler sskFetchSchedulerBulk;
	public final ClientRequestScheduler sskPutSchedulerBulk;
	public final ClientRequestScheduler chkFetchSchedulerRT;
	public final ClientRequestScheduler chkPutSchedulerRT;
	public final ClientRequestScheduler sskFetchSchedulerRT;
	public final ClientRequestScheduler sskPutSchedulerRT;

	private final NodeStats stats;
	RequestStarterGroup(Node node, NodeClientCore core, int portNumber, RandomSource random, Config config, SimpleFieldSet fs, ClientContext ctx) throws InvalidConfigValueException {
		SubConfig schedulerConfig = config.createSubConfig("node.scheduler");
		this.stats = core.nodeStats;
		
		throttleWindowBulk = new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindow"), node);
		throttleWindowRT = new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindowRT"), node);
		
		throttleWindowCHK = new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindowCHK"), node);
		throttleWindowSSK = new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindowSSK"), node);
		throttleWindowInsert = new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindowInsert"), node);
		throttleWindowRequest = new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindowRequest"), node);
		chkRequestThrottleBulk = new MyRequestThrottle(5000, fs == null ? null : fs.subset("CHKRequestThrottle"), 32768, false);
		chkRequestThrottleRT = new MyRequestThrottle(5000, fs == null ? null : fs.subset("CHKRequestThrottleRT"), 32768, true);
		chkRequestStarterBulk = new RequestStarter(core, chkRequestThrottleBulk, "CHK Request starter ("+portNumber+ ')', stats.localChkFetchBytesSentAverage, stats.localChkFetchBytesReceivedAverage, false, false, false);
		chkRequestStarterRT = new RequestStarter(core, chkRequestThrottleRT, "CHK Request starter ("+portNumber+ ')', stats.localChkFetchBytesSentAverage, stats.localChkFetchBytesReceivedAverage, false, false, true);
		chkFetchSchedulerBulk = new ClientRequestScheduler(false, false, false, random, chkRequestStarterBulk, node, core, "CHKrequester", ctx);
		chkFetchSchedulerRT = new ClientRequestScheduler(false, false, true, random, chkRequestStarterRT, node, core, "CHKrequester", ctx);
		chkRequestStarterBulk.setScheduler(chkFetchSchedulerBulk);
		chkRequestStarterRT.setScheduler(chkFetchSchedulerRT);
		
		registerSchedulerConfig(schedulerConfig, "CHKrequester", chkFetchSchedulerBulk, chkFetchSchedulerRT, false, false);
		
		//insertThrottle = new ChainedRequestThrottle(10000, 2.0F, requestThrottle);
		// FIXME reenable the above
		chkInsertThrottleBulk = new MyRequestThrottle(20000, fs == null ? null : fs.subset("CHKInsertThrottle"), 32768, false);
		chkInsertThrottleRT = new MyRequestThrottle(20000, fs == null ? null : fs.subset("CHKInsertThrottleRT"), 32768, true);
		chkInsertStarterBulk = new RequestStarter(core, chkInsertThrottleBulk, "CHK Insert starter ("+portNumber+ ')', stats.localChkInsertBytesSentAverage, stats.localChkInsertBytesReceivedAverage, true, false, false);
		chkInsertStarterRT = new RequestStarter(core, chkInsertThrottleRT, "CHK Insert starter ("+portNumber+ ')', stats.localChkInsertBytesSentAverage, stats.localChkInsertBytesReceivedAverage, true, false, true);
		chkPutSchedulerBulk = new ClientRequestScheduler(true, false, false, random, chkInsertStarterBulk, node, core, "CHKinserter", ctx);
		chkPutSchedulerRT = new ClientRequestScheduler(true, false, true, random, chkInsertStarterRT, node, core, "CHKinserter", ctx);
		chkInsertStarterBulk.setScheduler(chkPutSchedulerBulk);
		chkInsertStarterRT.setScheduler(chkPutSchedulerRT);
		
		registerSchedulerConfig(schedulerConfig, "CHKinserter", chkPutSchedulerBulk, chkPutSchedulerRT, false, true);
		
		sskRequestThrottleBulk = new MyRequestThrottle(5000, fs == null ? null : fs.subset("SSKRequestThrottle"), 1024, false);
		sskRequestThrottleRT = new MyRequestThrottle(5000, fs == null ? null : fs.subset("SSKRequestThrottleRT"), 1024, true);
		sskRequestStarterBulk = new RequestStarter(core, sskRequestThrottleBulk, "SSK Request starter ("+portNumber+ ')', stats.localSskFetchBytesSentAverage, stats.localSskFetchBytesReceivedAverage, false, true, false);
		sskRequestStarterRT = new RequestStarter(core, sskRequestThrottleRT, "SSK Request starter ("+portNumber+ ')', stats.localSskFetchBytesSentAverage, stats.localSskFetchBytesReceivedAverage, false, true, true);
		sskFetchSchedulerBulk = new ClientRequestScheduler(false, true, false, random, sskRequestStarterBulk, node, core, "SSKrequester", ctx);
		sskFetchSchedulerRT = new ClientRequestScheduler(false, true, true, random, sskRequestStarterRT, node, core, "SSKrequester", ctx);
		sskRequestStarterBulk.setScheduler(sskFetchSchedulerBulk);
		sskRequestStarterRT.setScheduler(sskFetchSchedulerRT);
		
		registerSchedulerConfig(schedulerConfig, "SSKrequester", sskFetchSchedulerBulk, sskFetchSchedulerRT, true, false);
		
		//insertThrottle = new ChainedRequestThrottle(10000, 2.0F, requestThrottle);
		// FIXME reenable the above
		sskInsertThrottleBulk = new MyRequestThrottle(20000, fs == null ? null : fs.subset("SSKInsertThrottle"), 1024, false);
		sskInsertThrottleRT = new MyRequestThrottle(20000, fs == null ? null : fs.subset("SSKInsertThrottleRT"), 1024, true);
		sskInsertStarterBulk = new RequestStarter(core, sskInsertThrottleBulk, "SSK Insert starter ("+portNumber+ ')', stats.localSskInsertBytesSentAverage, stats.localSskFetchBytesReceivedAverage, true, true, false);
		sskInsertStarterRT = new RequestStarter(core, sskInsertThrottleRT, "SSK Insert starter ("+portNumber+ ')', stats.localSskInsertBytesSentAverage, stats.localSskFetchBytesReceivedAverage, true, true, true);
		sskPutSchedulerBulk = new ClientRequestScheduler(true, true, false, random, sskInsertStarterBulk, node, core, "SSKinserter", ctx);
		sskPutSchedulerRT = new ClientRequestScheduler(true, true, true, random, sskInsertStarterRT, node, core, "SSKinserter", ctx);
		sskInsertStarterBulk.setScheduler(sskPutSchedulerBulk);
		sskInsertStarterRT.setScheduler(sskPutSchedulerRT);
		
		registerSchedulerConfig(schedulerConfig, "SSKinserter", sskPutSchedulerBulk, sskPutSchedulerRT, true, true);
		
		schedulerConfig.finishedInitialization();
	}
	
	private void registerSchedulerConfig(SubConfig schedulerConfig,
			String name, ClientRequestScheduler csBulk,
			ClientRequestScheduler csRT, boolean forSSKs, boolean forInserts) throws InvalidConfigValueException {
		PrioritySchedulerCallback callback = new PrioritySchedulerCallback();
		schedulerConfig.register(name+"_priority_policy", ClientRequestScheduler.PRIORITY_SOFT, name.hashCode(), true, false,
				"RequestStarterGroup.scheduler"+(forSSKs?"SSK" : "CHK")+(forInserts?"Inserts":"Requests"),
				"RequestStarterGroup.schedulerLong",
				callback);
		callback.init(csRT, csBulk, schedulerConfig.getString(name+"_priority_policy"));
	}

	public void start() {
		chkRequestStarterRT.start();
		chkInsertStarterRT.start();
		sskRequestStarterRT.start();
		sskInsertStarterRT.start();
		chkRequestStarterBulk.start();
		chkInsertStarterBulk.start();
		sskRequestStarterBulk.start();
		sskInsertStarterBulk.start();
	}
	
	public class MyRequestThrottle implements BaseRequestThrottle {
		private final BootstrappingDecayingRunningAverage roundTripTime;
		/** Data size for purposes of getRate() */
		private final int size;
		private final boolean realTime;

		public MyRequestThrottle(int rtt, SimpleFieldSet fs, int size, boolean realTime) {
			roundTripTime = new BootstrappingDecayingRunningAverage(rtt, 10, MINUTES.toMillis(5), 10, fs == null ? null : fs.subset("RoundTripTime"));
			this.size = size;
			this.realTime = realTime;
		}

		@Override
		public synchronized long getDelay() {
			double rtt = roundTripTime.currentValue();
			double winSizeForMinPacketDelay = rtt / MIN_DELAY;
			double _simulatedWindowSize = getThrottleWindow().currentValue(realTime);
			if (_simulatedWindowSize > winSizeForMinPacketDelay) {
				_simulatedWindowSize = winSizeForMinPacketDelay;
			}
			if (_simulatedWindowSize < 1.0) {
				_simulatedWindowSize = 1.0F;
			}
			// return (long) (_roundTripTime / _simulatedWindowSize);
			return Math.max(MIN_DELAY, Math.min((long) (rtt / _simulatedWindowSize), MAX_DELAY));
		}

		private ThrottleWindowManager getThrottleWindow() {
			return RequestStarterGroup.this.getThrottleWindow(realTime);
		}

		public synchronized void successfulCompletion(long rtt) {
			roundTripTime.report(Math.max(rtt, 10));
			if(logMINOR)
				Logger.minor(this, "Reported successful completion: "+rtt+" on "+this+" avg "+roundTripTime.currentValue());
		}
		
		@Override
		public String toString() {
			return "rtt: "+roundTripTime.currentValue()+" _s="+getThrottleWindow().currentValue(realTime)+" RT="+realTime;
		}

		public SimpleFieldSet exportFieldSet() {
			SimpleFieldSet fs = new SimpleFieldSet(false);
			fs.put("RoundTripTime", roundTripTime.exportFieldSet(false));
			return fs;
		}

		public double getRTT() {
			return roundTripTime.currentValue();
		}

		public long getRate() {
			return (long) ((1000.0 / getDelay()) * size);
		}
	}

	public static class PrioritySchedulerCallback extends StringCallback implements EnumerableOptionCallback {
		ClientRequestScheduler csRT;
		ClientRequestScheduler csBulk;
		private final String[] possibleValues = new String[]{ ClientRequestScheduler.PRIORITY_HARD, ClientRequestScheduler.PRIORITY_SOFT };
		
		public void init(ClientRequestScheduler csRT, ClientRequestScheduler csBulk, String config) throws InvalidConfigValueException{
			this.csRT = csRT;
			this.csBulk = csBulk;
			set(config);
		}
		
		@Override
		public String get(){
			if(csBulk != null)
				return csBulk.getChoosenPriorityScheduler();
			else
				return ClientRequestScheduler.PRIORITY_SOFT;
		}
		
		@Override
		public void set(String val) throws InvalidConfigValueException{
			String value;
			if(val == null || val.equalsIgnoreCase(get())) return;
			if(val.equalsIgnoreCase(ClientRequestScheduler.PRIORITY_HARD)){
				value = ClientRequestScheduler.PRIORITY_HARD;
			}else if(val.equalsIgnoreCase(ClientRequestScheduler.PRIORITY_SOFT)){
				value = ClientRequestScheduler.PRIORITY_SOFT;
			}else{
				throw new InvalidConfigValueException("Invalid priority scheme");
			}
			csBulk.setPriorityScheduler(value);
			csRT.setPriorityScheduler(value);
		}
		
		@Override
		public String[] getPossibleValues() {
			return possibleValues;
		}
	}

	public ThrottleWindowManager getThrottleWindow(boolean realTime) {
		if(realTime) return throttleWindowRT;
		else return throttleWindowBulk;
	}

	public void requestCompleted(boolean isSSK, boolean isInsert, Key key, boolean realTime) {
		getThrottleWindow(realTime).requestCompleted();
		(isSSK ? throttleWindowSSK : throttleWindowCHK).requestCompleted();
		(isInsert ? throttleWindowInsert : throttleWindowRequest).requestCompleted();
		stats.reportOutgoingRequestLocation(key.toNormalizedDouble());
	}
	
	public void rejectedOverload(boolean isSSK, boolean isInsert, boolean realTime) {
		getThrottleWindow(realTime).rejectedOverload();
		(isSSK ? throttleWindowSSK : throttleWindowCHK).rejectedOverload();
		(isInsert ? throttleWindowInsert : throttleWindowRequest).rejectedOverload();
	}
	
	/**
	 * Persist the throttle data to a SimpleFieldSet.
	 */
	SimpleFieldSet persistToFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(false);
		fs.put("ThrottleWindow", throttleWindowBulk.exportFieldSet(false));
		fs.put("ThrottleWindowRT", throttleWindowRT.exportFieldSet(false));
		fs.put("ThrottleWindowCHK", throttleWindowCHK.exportFieldSet(false));
		fs.put("ThrottleWindowSSK", throttleWindowCHK.exportFieldSet(false));
		fs.put("CHKRequestThrottle", chkRequestThrottleBulk.exportFieldSet());
		fs.put("SSKRequestThrottle", sskRequestThrottleBulk.exportFieldSet());
		fs.put("CHKInsertThrottle", chkInsertThrottleBulk.exportFieldSet());
		fs.put("SSKInsertThrottle", sskInsertThrottleBulk.exportFieldSet());
		fs.put("CHKRequestThrottleRT", chkRequestThrottleRT.exportFieldSet());
		fs.put("SSKRequestThrottleRT", sskRequestThrottleRT.exportFieldSet());
		fs.put("CHKInsertThrottleRT", chkInsertThrottleRT.exportFieldSet());
		fs.put("SSKInsertThrottleRT", sskInsertThrottleRT.exportFieldSet());
		return fs;
	}
	
	public double getWindow(boolean realTime) {
		return getThrottleWindow(realTime).currentValue(realTime);
	}

	public double getRTT(boolean isSSK, boolean isInsert, boolean realTime) {
		return getThrottle(isSSK, isInsert, realTime).getRTT();
	}

	public double getDelay(boolean isSSK, boolean isInsert, boolean realTime) {
		return getThrottle(isSSK, isInsert, realTime).getDelay();
	}
	
	MyRequestThrottle getThrottle(boolean isSSK, boolean isInsert, boolean realTime) {
		if(realTime) {
			if(isSSK) {
				if(isInsert) return sskInsertThrottleRT;
				else return sskRequestThrottleRT;
			} else {
				if(isInsert) return chkInsertThrottleRT;
				else return chkRequestThrottleRT;
			}
		} else {
			if(isSSK) {
				if(isInsert) return sskInsertThrottleBulk;
				else return sskRequestThrottleBulk;
			} else {
				if(isInsert) return chkInsertThrottleBulk;
				else return chkRequestThrottleBulk;
			}
		}
	}

	public String statsPageLine(boolean isSSK, boolean isInsert, boolean realTime) {
		StringBuilder sb = new StringBuilder(100);
		sb.append(isSSK ? "SSK" : "CHK");
		sb.append(' ');
		sb.append(isInsert ? "Insert" : "Request");
		sb.append(' ');
		sb.append(realTime ? "RealTime" : "Bulk");
		sb.append(" RTT=");
		MyRequestThrottle throttle = getThrottle(isSSK, isInsert, realTime);
		sb.append(TimeUtil.formatTime((long)throttle.getRTT(), 2, true));
		sb.append(" delay=");
		sb.append(TimeUtil.formatTime(throttle.getDelay(), 2, true));
		sb.append(" bw=");
		sb.append(throttle.getRate());
		sb.append("B/sec");
		return sb.toString();
	}

	public String diagnosticThrottlesLine(boolean mode) {
		StringBuilder sb = new StringBuilder();
		if(mode) {
			sb.append("Request window: ");
			sb.append(throttleWindowRequest.toString());
			sb.append(", Insert window: ");
			sb.append(throttleWindowInsert.toString());
		} else {
			sb.append("CHK window: ");
			sb.append(throttleWindowCHK.toString());
			sb.append(", SSK window: ");
			sb.append(throttleWindowSSK.toString());
		}
		return sb.toString();
	}

	public double getRealWindow(boolean realTime) {
		return getThrottleWindow(realTime).realCurrentValue();
	}

	public long countQueuedRequests() {
		return chkFetchSchedulerBulk.countQueuedRequests() +
			sskFetchSchedulerBulk.countQueuedRequests() +
			chkPutSchedulerBulk.countQueuedRequests() +
			sskPutSchedulerBulk.countQueuedRequests() +
			chkFetchSchedulerRT.countQueuedRequests() +
			sskFetchSchedulerRT.countQueuedRequests() +
			chkPutSchedulerRT.countQueuedRequests() +
			sskPutSchedulerRT.countQueuedRequests();
	}

	public ClientRequestScheduler getScheduler(boolean ssk, boolean insert,
			boolean realTime) {
		if(realTime) {
			if(insert) {
				return ssk ? sskPutSchedulerRT : chkPutSchedulerRT;
			} else {
				return ssk ? sskFetchSchedulerRT : chkFetchSchedulerRT;
			}
		} else {
			if(insert) {
				return ssk ? sskPutSchedulerBulk : chkPutSchedulerBulk;
			} else {
				return ssk ? sskFetchSchedulerBulk : chkFetchSchedulerBulk;
			}
		}
	}

    public void setGlobalSalt(byte[] salt) {
        chkFetchSchedulerBulk.startCore(salt);
        sskFetchSchedulerBulk.startCore(salt);
        chkPutSchedulerBulk.startCore(salt);
        sskPutSchedulerBulk.startCore(salt);
        chkFetchSchedulerRT.startCore(salt);
        sskFetchSchedulerRT.startCore(salt);
        chkPutSchedulerRT.startCore(salt);
        sskPutSchedulerRT.startCore(salt);
    }

}
