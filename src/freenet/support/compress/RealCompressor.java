/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.support.compress;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;

import freenet.client.InsertException;
import freenet.client.InsertException.InsertExceptionMode;
import freenet.client.async.ClientContext;
import freenet.node.PrioRunnable;
import freenet.support.Logger;
import freenet.support.io.NativeThread;

public class RealCompressor {
    private final ExecutorService executorService;
    private ClientContext context;

    private static volatile boolean logMINOR;
    static {
        Logger.registerClass(RealCompressor.class);
    }

    public RealCompressor() {
        this.executorService = Executors.newFixedThreadPool(getMaxRunningCompressionThreads(),
                                                            new CompressorThreadFactory());
    }

    public void setClientContext(ClientContext context) {
        this.context = context;
    }

    public void enqueueNewJob(final CompressJob j) {
        if(logMINOR)
            Logger.minor(this, "Enqueueing compression job: "+j);

        Future<String> task = null;
        while(!executorService.isShutdown() && task == null) {
            try {
                    task = executorService.submit(new PrioRunnable() {
                    @Override
                    public void run() {
                        freenet.support.Logger.OSThread.logPID(this);
                        try {
                            try {
                                j.tryCompress(context);
                            } catch (InsertException e) {
                                j.onFailure(e, context);
                            } catch (Throwable t) {
                                Logger.error(this, "Caught in OffThreadCompressor: " + t, t);
                                System.err.println("Caught in OffThreadCompressor: " + t);
                                t.printStackTrace();
                                // Try to fail gracefully
                                j.onFailure(
                                    new InsertException(InsertExceptionMode.INTERNAL_ERROR, t,
                                                        null),
                                    context);
                            }

                        } catch (Throwable t) {
                            Logger.error(this, "Caught " + t + " in " + this, t);
                        }
                    }

                    @Override
                    public int getPriority() {
                        return NativeThread.MIN_PRIORITY;
                    }
                }, "Compressor thread for " + j);
                if(logMINOR)
                    Logger.minor(this, "Compression job: "+j+ "has been enqueued.");
            }catch (RejectedExecutionException e) {
                Logger.error(this, "RejectedExectutionException for "+j,e);
                task = null;
            }
        }
    }

    private static int getMaxRunningCompressionThreads() {
        int maxRunningThreads = 1;

        String osName = System.getProperty("os.name");
        if(!osName.contains("Windows") && (osName.toLowerCase().indexOf("mac os x") > 0) || (!NativeThread.usingNativeCode()))
            // OS/X niceness is really weak, so we don't want any more background CPU load than necessary
            // Also, on non-Windows, we need the native threads library to be working.
            maxRunningThreads = 1;
        else {
            // Most other OSs will have reasonable niceness, so go by RAM.
            Runtime r = Runtime.getRuntime();
            int max = r.availableProcessors(); // FIXME this may change in a VM, poll it
            long maxMemory = r.maxMemory();
            if(maxMemory < 128 * 1024 * 1024)
                max = 1;
            else
                // one compressor thread per (128MB of ram + available core)
                max = Math.min(max, (int) (Math.min(Integer.MAX_VALUE, maxMemory / (128 * 1024 * 1024))));
            maxRunningThreads = max;
        }
        Logger.minor(RealCompressor.class, "Maximum Compressor threads: " + maxRunningThreads);
        return maxRunningThreads;
    }

    public void shutdown() {
        // TODO: should we wait here?
        this.executorService.shutdown();
    }

    public static class CompressorThreadFactory implements ThreadFactory {
        @Override
        public Thread newThread(Runnable r) {
            return new NativeThread(r, "Compressor thread", NativeThread.MIN_PRIORITY, true);
        }
    }
}
