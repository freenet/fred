package freenet.clients.http.wizardsteps;

import freenet.node.Node;
import freenet.support.io.DatastoreUtil;

/**
 * A bandwidth usage rate limit, measured in bytes.
 */
public class BandwidthLimit {

	/**
	 * Seconds in 30 days. Used for limit calculations.
	 */
	public static final double secondsPerMonth = 2592000d;

	/*
	 * Bandwidth used if both the upload and download limit are at the minimum. In GB. Assumes 24/7 uptime.
	 * 49.4384765625 GiB
	 */
	public static final Double minMonthlyLimit = 2 * Node.getMinimumBandwidth() * secondsPerMonth / DatastoreUtil.oneGiB;

	/**
	 * Download limit in bytes.
	 */
	public final long downBytes;

	/**
	 * Upload limit in bytes.
	 */
	public final long upBytes;
	
	public final String descriptionKey;
	
	public final boolean maybeDefault;

	public BandwidthLimit(long downBytes, long upBytes, String descriptionKey, boolean maybeDefault) {
		this.downBytes = downBytes;
		this.upBytes = upBytes;
		this.descriptionKey = descriptionKey;
		this.maybeDefault = maybeDefault;
	}

	/**
	 * Calculate download and upload limit
	 * @param bytesPerMonth monthly bandwidth limit
	 */
	public BandwidthLimit(long bytesPerMonth) {
		/*
		 * Fraction of total limit used for download. Asymptotically from 0.5 at the minimum cap to 0.8.
		 *
		 * Q: Why do we do this? It does not actually work, since download cannot be larger than upload
		 *  for any long amount of time.
		 * A: Upload is limited because maxing it out increases latency... http://bufferbloat.net/
		 *  And fred (line most layered P2Ps) deals very poorly with high-latency links
		 *
		 * This 50/50 split is consistent with the assumption in the definition of minCap that the upload and
		 * download limits are equal.
		 */
		double bytesPerSecond = bytesPerMonth / secondsPerMonth;
		double minBytesPerSecond = Node.getMinimumBandwidth();
		double bwinc = bytesPerSecond - 2 * minBytesPerSecond; // min for up and min for down
		double asymptoticDlFraction = 4. / 5.;
		double dllimit = minBytesPerSecond + (bwinc * asymptoticDlFraction);
		double ullimit = minBytesPerSecond + (bwinc * (1 - asymptoticDlFraction));
		downBytes = (long) Math.ceil(dllimit);
		upBytes = (long) Math.ceil(ullimit);
		descriptionKey = "Monthly bandwidth limit";
		maybeDefault = false;
	}
}
