/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.support.math;

import freenet.support.Logger;
import freenet.support.Logger.LogLevel;

/**
 * Simple running average: linear mean of the last N reports.
 * @author amphibian
 */
public final class SimpleRunningAverage implements RunningAverage, Cloneable {
	private static final long serialVersionUID = -1;
    final double[] refs;
    int nextSlotPtr=0;
    int curLen=0;
    double total=0;
    int totalReports = 0;
    final double initValue;
    private boolean logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);

    @Override
	public final SimpleRunningAverage clone() {
    	// Deep copy needed. Implement Cloneable to shut up findbugs.
        return new SimpleRunningAverage(this);
    }
    
    /**
     * Clear the SRA
     */
    public synchronized void clear() {
        nextSlotPtr = 0;
        curLen = 0;
        totalReports = 0;
        total = 0;
        for(int i=0;i<refs.length;i++) refs[i] = 0.0;
    }
    
    /**
     *
     * @param length
     * @param initValue
     */
    public SimpleRunningAverage(int length, double initValue) {
        refs = new double[length];
        this.initValue = initValue;
        totalReports = 0;
    }
    
    /**
     *
     * @param a
     */
    public SimpleRunningAverage(SimpleRunningAverage a) {
        this.curLen = a.curLen;
        this.initValue = a.initValue;
        this.nextSlotPtr = a.nextSlotPtr;
        this.refs = a.refs.clone();
        this.total = a.total;
        this.totalReports = a.totalReports;
    }

    /**
     *
     * @return
     */
    @Override
    public synchronized double currentValue() {
        if(curLen == 0) return initValue;
        return total/curLen;
    }

    @Override
    public synchronized double valueIfReported(double r) {
        if(curLen < refs.length) {
            return (total+r)/(curLen+1);
        } else {
            // Don't increment curLen because it won't be incremented.
            return (total+r-refs[nextSlotPtr])/curLen;
        }
    }

    /**
     *
     * @param d
     */
    @Override
    public synchronized void report(double d) {
        totalReports++;
		if (logDEBUG)
			Logger.debug(this, "report(" + d + ") on " + this);
		if (curLen < refs.length)
			curLen++;
		else
			total -= popValue();
		pushValue(d);
		total += d;
	}

    /**
     *
     * @param value
     */
    protected synchronized void pushValue(double value){
		refs[nextSlotPtr] = value;
		nextSlotPtr++;
		if(nextSlotPtr >= refs.length) nextSlotPtr = 0;
    }

    /**
     *
     * @return
     */
    protected synchronized double popValue(){
		return refs[nextSlotPtr];
	}

    @Override
	public synchronized String toString() {
        return super.toString() + ": curLen="+curLen+", ptr="+nextSlotPtr+", total="+
        	total+", average="+total/curLen;
    }
    
    /**
     *
     * @param d
     */
    @Override
    public void report(long d) {
        report((double)d);
    }

    public void writeDataTo() {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized long countReports() {
        return totalReports;
    }

    /**
     *
     * @param targetValue
     * @return
     */
    public synchronized double minReportForValue(double targetValue) {
        if(curLen < refs.length) {
            /** Don't need to remove any values before reporting,
             * so is slightly simpler.
             * (total + report) / (curLen + 1) >= targetValue =>
             * report / (curLen + 1) >= targetValue - total/(curLen+1)
             * => report >= (targetValue - total/(curLen + 1)) * (curLen+1)
             * => report >= targetValue * (curLen + 1) - total
             * EXAMPLE:
             * Mean (5, 5, 5, 5, 5, X) = 10 
             * X = 10 * 6 - 25 = 35
             * => Mean = (25 + 35) / 6 = 60/6 = 10
             */
            return targetValue * (curLen + 1) - total;
        } else {
            /** Essentially the same, but:
             * 1) Length will be curLen, not curLen+1, because is full.
             * 2) Take off the value that will be taken off first.
             */
            return targetValue * curLen - (total - refs[nextSlotPtr]);
        }
    }
}
