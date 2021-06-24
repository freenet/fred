/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node.diagnostics.threads;

import freenet.node.*;
import freenet.node.diagnostics.*;
import freenet.support.*;

import java.lang.management.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.stream.*;

/**
 * Runnable thread to retrieve node thread's information and compiling it into
 * an array of NodeThreadInfo objects.
 */
public class DefaultThreadDiagnostics implements Runnable, ThreadDiagnostics {
    private final String name;
    private final int monitorInterval;

    private final NodeStats nodeStats;
    private final Ticker ticker;

    /** Sleep interval to calculate % CPU used by each thread */
    private static final int DEFAULT_MONITOR_INTERVAL = 1000;
    private static final String DEFAULT_MONITOR_THREAD_NAME = "NodeDiagnostics: thread monitor";

    /** Initialising with an empty NodeThreadSnapshot to avoid possible race conditions */
    private final AtomicReference<NodeThreadSnapshot> nodeThreadSnapshot =
            new AtomicReference<>(
                    new NodeThreadSnapshot(new ArrayList<>(), DEFAULT_MONITOR_INTERVAL)
            );

    private final ThreadMXBean threadMxBean = ManagementFactory.getThreadMXBean();

    /** Map to track thread's CPU differences between intervals of time */
    private final Map<Long, Long> threadCpu = new HashMap<>();

    /**
     * @param nodeStats Used to retrieve data points
     * @param ticker Used to queue timed jobs
     * @param name Thread name
     * @param monitorInterval Sleep intervals to retrieve CPU usage
     */
    public DefaultThreadDiagnostics(NodeStats nodeStats, Ticker ticker, String name, int monitorInterval) {
        this.nodeStats = nodeStats;
        this.ticker = ticker;
        this.name = name;
        this.monitorInterval = monitorInterval;
    }

    /**
     * @param nodeStats Used to retrieve data points
     * @param ticker Used to queue timed jobs
     */
    public DefaultThreadDiagnostics(NodeStats nodeStats, Ticker ticker) {
        this(nodeStats, ticker, DEFAULT_MONITOR_THREAD_NAME, DEFAULT_MONITOR_INTERVAL);
    }

    /**
     * @return Current snapshot.
     */
    public NodeThreadSnapshot getThreadSnapshot() {
        return nodeThreadSnapshot.get();
    }

    /**
     * Schedule this class execution in seconds.
     *
     * @param interval Time internal in seconds.
     */
    private void scheduleNext(int interval) {
        ticker.queueTimedJob(
            this,
            name,
            interval,
            false,
            true
        );
    }

    /**
     * Start the execution.
     */
    public void start() {
        scheduleNext(0);
    }

    public void stop() {
        ticker.removeQueuedJob(this);
    }

    private void scheduleNext() {
        scheduleNext(monitorInterval);
    }

    /**
     * Calculate the "delta" CPU time for a given thread. This method keeps
     * track of the previous CPU Time and calculates the difference between that
     * snapshot and the current CPU Time.
     *
     * If there's no previous snapshot of CPU Time for the thread this method
     * will return 0.
     *
     * @param threadId Thread ID to get the CPU usage
     * @return Delta CPU time (nanoseconds)
     */
    private long getCpuTimeDelta(long threadId) {
        long current = threadMxBean.getThreadCpuTime(threadId);

        long cpuUsage = current - threadCpu.getOrDefault(threadId, current);
        threadCpu.put(threadId, current);

        return cpuUsage;
    }

    /**
     * Remove threads that aren't present in the last snapshot.
     *
     * @param threads List of active threads.
     */
    private void purgeInactiveThreads(List<NodeThreadInfo> threads) {
        List<Long> activeThreads = threads.stream()
                .map(NodeThreadInfo::getId)
                .collect(Collectors.toList());

        threadCpu.keySet()
                .removeIf(key -> !activeThreads.contains(key));
    }

    @Override
    public void run() {
        List<NodeThreadInfo> threads = Arrays.stream(nodeStats.getThreads())
            .filter(Objects::nonNull)
            .filter(thread -> thread.getThreadGroup() != null)
            .map(thread -> new NodeThreadInfo(
                    thread.getId(),
                    thread.getName(),
                    thread.getPriority(),
                    thread.getThreadGroup().getName(),
                    thread.getState().toString(),
                    getCpuTimeDelta(thread.getId())
                )
            )
            .collect(Collectors.toList());

        nodeThreadSnapshot.set(
                new NodeThreadSnapshot(threads, monitorInterval)
        );

        purgeInactiveThreads(threads);
        scheduleNext();
    }
}
