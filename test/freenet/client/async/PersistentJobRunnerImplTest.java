package freenet.client.async;

import freenet.support.CheatingTicker;
import freenet.support.Executor;
import freenet.support.PooledExecutor;
import freenet.support.Ticker;
import freenet.support.WaitableExecutor;
import freenet.support.io.NativeThread;
import junit.framework.TestCase;

public class PersistentJobRunnerImplTest extends TestCase {
    
    final WaitableExecutor exec = new WaitableExecutor(new PooledExecutor());
    final Ticker ticker = new CheatingTicker(exec);
    final JobRunner jobRunner;
    final ClientContext context;
    
    public PersistentJobRunnerImplTest() {
        jobRunner = new JobRunner(exec, ticker, 1000);
        context = new ClientContext(0, null, exec, null, null, null, null, null, null, null, ticker, null, null, null, null, null, null, null, null, null, null, null, null, null, null);
        jobRunner.start(context);
        jobRunner.onStarted(false);
        exec.waitForIdle();
        jobRunner.grabHasCheckpointed();
    }
    
    private class WakeableJob implements PersistentJob {
        private boolean wake;
        private boolean started;
        private boolean finished;

        @Override
        public boolean run(ClientContext context) {
            synchronized(this) {
                started = true;
                notifyAll();
                while(!wake) {
                    try {
                        wait();
                    } catch (InterruptedException e) {
                        // Ignore.
                    }
                }
                finished = true;
                notifyAll();
            }
            return false;
        }
        
        public synchronized void wakeUp() {
            wake = true;
            notifyAll();
        }
        
        public synchronized boolean started() {
            return started;
        }
        
        public synchronized boolean finished() {
            return finished;
        }

        public synchronized void waitForStarted() {
            while(!started) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    // Ignore.
                }
            }
        }
        
    }
    
    private class JobRunner extends PersistentJobRunnerImpl {
        
        private boolean hasCheckpointed;

        public JobRunner(Executor executor, Ticker ticker, long interval) {
            super(executor, ticker, interval);
            // TODO Auto-generated constructor stub
        }

        @Override
        public boolean newSalt() {
            // Ignore.
            return false;
        }

        @Override
        protected synchronized void innerCheckpoint(boolean shutdown) {
            hasCheckpointed = true;
            notifyAll();
        }
        
        public synchronized boolean grabHasCheckpointed() {
            boolean ret = hasCheckpointed;
            hasCheckpointed = false;
            return ret;
        }

    }
    
    private class WaitAndCheckpoint implements Runnable {

        private final JobRunner jobRunner;
        private boolean started;
        private boolean finished;
        
        public WaitAndCheckpoint(JobRunner jobRunner2) {
            jobRunner = jobRunner2;
        }

        @Override
        public void run() {
            synchronized(this) {
                started = true;
                notifyAll();
            }
            try {
                jobRunner.waitAndCheckpoint();
            } catch (PersistenceDisabledException e) {
                System.err.println("Impossible: "+e);
                return;
            }
            assertTrue(jobRunner.grabHasCheckpointed());
            synchronized(this) {
                finished = true;
                notifyAll();
            }
        }

        public synchronized boolean hasStarted() {
            return started;
        }
        
        public synchronized void waitForFinished() {
            while(!finished) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    // Ignore.
                }
            }
        }

        public synchronized void waitForStarted() {
            while(!started) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    // Ignore.
                }
            }
        }
        
    }
    
    public void testWaitForCheckpoint() throws PersistenceDisabledException {
        jobRunner.onLoading();
        WakeableJob w = new WakeableJob();
        jobRunner.queue(w, NativeThread.NORM_PRIORITY);
        w.waitForStarted();
        WaitAndCheckpoint checkpointer = new WaitAndCheckpoint(jobRunner);
        new Thread(checkpointer).start();
        checkpointer.waitForStarted();
        w.wakeUp();
        checkpointer.waitForFinished();
        assertTrue(w.finished());
    }
    
    public void testDisabledCheckpointing() throws PersistenceDisabledException {
        jobRunner.setCheckpointASAP();
        exec.waitForIdle();
        assertFalse(jobRunner.mustCheckpoint()); // Has checkpointed, now false.
        jobRunner.disableWrite();
        assertFalse(jobRunner.mustCheckpoint());
        jobRunner.setCheckpointASAP();
        assertFalse(jobRunner.mustCheckpoint());
        
        // Run a job which will request a checkpoint.
        jobRunner.queue(new PersistentJob() {

            @Override
            public boolean run(ClientContext context) {
                return true;
            }
            
        }, NativeThread.NORM_PRIORITY);
        // Wait for the job to complete.
        exec.waitForIdle();
        assertFalse(jobRunner.mustCheckpoint());
    }

}
