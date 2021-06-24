/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node.diagnostics;

import freenet.node.diagnostics.threads.*;
import freenet.support.Ticker;
import freenet.node.NodeStats;

/**
 *  @author desyncr
 *
 *  A class to retrieve data to build diagnostic dumps to help in determining
 *  node bottlenecks or misconfiguration.
 *
 *  This class launches various threads at intervals to retrieve information. This information
 *  is available through the public methods.
 *  Some data pointers are obtained from NodeStats object.
 */
public class DefaultNodeDiagnostics implements NodeDiagnostics {
    private final DefaultThreadDiagnostics defaultThreadDiagnostics;

   /**
     * @param nodeStats Used to retrieve data points.
     * @param ticker Used to queue timed jobs.
     */
    public DefaultNodeDiagnostics(NodeStats nodeStats, Ticker ticker) {
        defaultThreadDiagnostics = new DefaultThreadDiagnostics(nodeStats, ticker);
    }

    public void start() {
        defaultThreadDiagnostics.start();
    }

    public void stop() {
        defaultThreadDiagnostics.stop();
    }

    /**
     * @return List of threads registered in NodeStats.getThreads()
     */
    @Override
    public ThreadDiagnostics getThreadDiagnostics() {
        return defaultThreadDiagnostics;
    }
}
