/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.http;


/**
 * If thrown, something wrong with http range
 */
public class HTTPRangeException extends Exception {
    private static final long serialVersionUID = -1;

    public HTTPRangeException(Throwable cause) {
        super(cause);
    }

    public HTTPRangeException(String msg) {
        super(msg);
    }

    @Override
    public final synchronized Throwable fillInStackTrace() {
        return null;
    }
}