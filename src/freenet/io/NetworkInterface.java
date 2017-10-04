/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

package freenet.io;

import java.io.Closeable;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.List;
import java.util.Queue;
import java.util.StringTokenizer;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.tanukisoftware.wrapper.WrapperManager;

import freenet.io.AddressIdentifier.AddressType;
import freenet.support.Executor;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;

/**
 * Replacement for {@link ServerSocket} that can handle multiple bind addresses
 * and allows IP address level filtering.
 * 
 * @author David Roden &lt;droden@gmail.com&gt;
 * @version $Id$
 */
public class NetworkInterface implements Closeable {
    
	private static volatile boolean logMINOR;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
            @Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}
        public static final String DEFAULT_BIND_TO = "127.0.0.1,0:0:0:0:0:0:0:1";
        
	/** Object for synchronisation purpose. */
	private final Lock lock = new ReentrantLock();
	
	/** Signalled when we have bound the interface i.e. acceptors.size() > 0 */
	private final Condition boundCondition = lock.newCondition();
	
	/** Signalled when !acceptedSockets.isEmpty() */
	private final Condition socketCondition = lock.newCondition();
	
	/** Signalled when an Acceptor has closed */
	private final Condition acceptorClosedCondition = lock.newCondition();

	/** Acceptors created by this interface. */
	private final List<Acceptor>  acceptors = new ArrayList<Acceptor>();

	/** Queue of accepted client connections. */
	private final Queue<Socket> acceptedSockets = new ArrayDeque<Socket>();
	
	/** AllowedHosts structure */
	protected final AllowedHosts allowedHosts;

	/** The timeout set by {@link #setSoTimeout(int)}. */
	private int timeout = 0;

	/** The port to bind to. */
	private final int port;

	/** The number of running acceptors. */
	private int runningAcceptors = 0;
	
	private volatile boolean shutdown = false;
	
	private final Executor executor;

	// FIXME make configurable
	static final int maxQueueLength = 100;

	public static NetworkInterface create(int port, String bindTo, String allowedHosts, Executor executor, boolean ignoreUnbindableIP6) throws IOException {
		NetworkInterface iface = new NetworkInterface(port, allowedHosts, executor);
		String[] failedBind = iface.setBindTo(bindTo, ignoreUnbindableIP6);
		if(failedBind != null) {
			System.err.println("Could not bind to some of the interfaces specified for port "+port+" : "+Arrays.toString(failedBind));
		}
		return iface;
	}
	
	/**
	 * Creates a new network interface that can bind to several addresses and
	 * allows connection filtering on IP address level.
	 * 
	 * @param bindTo
	 *            A comma-separated list of addresses to bind to
	 * @param allowedHosts
	 *            A comma-separated list of allowed addresses
	 */
	protected NetworkInterface(int port, String allowedHosts, Executor executor) throws IOException {
		this.port = port;
		this.allowedHosts = new AllowedHosts(allowedHosts);
		this.executor = executor;
	}

	protected ServerSocket createServerSocket() throws IOException {
		return new ServerSocket();
	}
	
	/**
	 * Sets the list of IP address this network interface binds to.
	 * 
	 * @param bindTo
	 *            A comma-separated list of IP address to bind to
	 * @return List of addresses that we failed to bind to, or null if completely successful.
	 */
	public String[] setBindTo(String bindTo, boolean ignoreUnbindableIP6) {
                if(bindTo == null || bindTo.equals("")) bindTo = NetworkInterface.DEFAULT_BIND_TO;
		StringTokenizer bindToTokens = new StringTokenizer(bindTo, ",");
		List<String> bindToTokenList = new ArrayList<String>();
		List<String> brokenList = null;
		while (bindToTokens.hasMoreTokens()) {
			bindToTokenList.add(bindToTokens.nextToken().trim());
		}
		/* stop the old acceptors. */
		for (Acceptor acceptor : grabAcceptors()) {
			try {
				acceptor.close();
			} catch (IOException e) {
				/* swallow exception. */
			}
		}
		lock.lock();
		try {
			while(runningAcceptors > 0) {
				acceptorClosedCondition.awaitUninterruptibly();
				if(shutdown || WrapperManager.hasShutdownHookBeenTriggered()) return null;
			}
		} finally {
			lock.unlock();
		}
		for (int serverSocketIndex = 0; serverSocketIndex < bindToTokenList.size(); serverSocketIndex++) {
			InetSocketAddress addr = null;
			String address = bindToTokenList.get(serverSocketIndex);
			try {
				ServerSocket serverSocket = createServerSocket();
				addr = new InetSocketAddress(address, port);
				serverSocket.setReuseAddress(true);
				serverSocket.bind(addr);
				Acceptor acceptor = new Acceptor(serverSocket);
				try {
					acceptor.setSoTimeout(timeout);
				} catch (SocketException e) {
					Logger.error(this, "Unable to setSoTimeout in setBindTo() on "+addr);
				}
				lock.lock();
				try {
					acceptors.add(acceptor);
					runningAcceptors++;
					executor.execute(acceptor, "Network Interface Acceptor for "+acceptor.serverSocket);
				} finally {
					lock.unlock();
				}
			} catch (IOException e) {
				if(e instanceof SocketException && ignoreUnbindableIP6 && addr != null && 
						addr.getAddress() instanceof Inet6Address)
					continue;
				System.err.println("Unable to bind to address "+address+" for port "+port);
				Logger.error(this, "Unable to bind to address "+address+" for port "+port);
				if(brokenList == null) brokenList = new ArrayList<String>();
				brokenList.add(address);
			}
		}
		// Signal at the end, even if the last one didn't succeed.
		lock.lock();
		try {
			boundCondition.signalAll();
		} finally {
			lock.unlock();
		}

		return brokenList == null ? null : brokenList.toArray(new String[brokenList.size()]);
	}

	public void setAllowedHosts(String allowedHosts) {
		this.allowedHosts.setAllowedHosts(allowedHosts);
	}

	/**
	 * Sets the SO_TIMEOUT value on the server sockets.
	 * 
	 * @param timeout
	 *            The timeout in milliseconds, <code>0</code> to disable
	 * @throws SocketException
	 *             if the SO_TIMEOUT value can not be set
	 * @see ServerSocket#setSoTimeout(int)
	 */
	public void setSoTimeout(int timeout) throws SocketException {
		for (Acceptor acceptor : getAcceptors()) {
			acceptor.setSoTimeout(timeout);
		}
		this.timeout = timeout;
	}

	/**
	 * Waits for a connection. If a timeout has been set using
	 * {@link #setSoTimeout(int)} and no connection is established this method
	 * will return after the specified timeout has been expired, throwing a
	 * {@link SocketTimeoutException}. If no timeout has been set this method
	 * will wait until a connection has been established.
	 * 
	 * @return The socket that is connected to the client or null
     * if the timeout has expired waiting for a connection
	 */
	public Socket accept() {
		lock.lock();
		try {
			Socket socket;
			while ((socket = acceptedSockets.poll()) == null ) {
				if (shutdown)
					return null;
				if (WrapperManager.hasShutdownHookBeenTriggered())
					return null;
				if (acceptors.size() == 0) {
					return null;
				}
				socketCondition.awaitUninterruptibly();
				if (timeout > 0) {
					socket = acceptedSockets.poll();
					break;
				}
			}
			return socket;
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Closes this interface and all underlying server sockets.
	 * 
	 * @throws IOException
	 *             if an I/O exception occurs
	 * @see ServerSocket#close()
	 */
	@Override
	public void close() throws IOException {
		IOException exception = null;
		shutdown = true;
		/* stop the old acceptors. */
		for (Acceptor acceptor : grabAcceptors()) {
			try {
				acceptor.close();
			} catch (IOException ioe1) {
				exception = ioe1;
			}
		}
		lock.lock();
		try {
			boundCondition.signalAll();
			acceptorClosedCondition.signalAll();
			socketCondition.signalAll();
		} finally {
			lock.unlock();
		}
		if (exception != null) {
			throw exception;
		}
	}

	private Acceptor[] grabAcceptors() {
		Acceptor[] oldAcceptors;
		lock.lock();
		try {
			oldAcceptors = acceptors.toArray(new Acceptor[acceptors.size()]);
			acceptors.clear();
			return oldAcceptors;
		} finally {
			lock.unlock();
		}
	}

	private Acceptor[] getAcceptors() {
		lock.lock();
		try {
			return acceptors.toArray(new Acceptor[acceptors.size()]);
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Gets called by an acceptor if it has stopped.
	 */
	private void acceptorStopped() {
		lock.lock();
		try {
			runningAcceptors--;
			acceptorClosedCondition.signalAll();
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Wrapper around a {@link ServerSocket} that checks whether the incoming
	 * connection is allowed.
	 * 
	 * @author David Roden &lt;droden@gmail.com&gt;
	 * @version $Id$
	 */
	private class Acceptor implements Runnable {

		/** The {@link ServerSocket} to listen on. */
		private final ServerSocket serverSocket;

		/** Whether this acceptor has been closed. */
		private boolean closed = false;

		/**
		 * Creates a new acceptor on the specified server socket.
		 * 
		 * @param serverSocket
		 *            The server socket to listen on
		 */
		public Acceptor(ServerSocket serverSocket) {
			this.serverSocket = serverSocket;
		}

		/**
		 * Sets the SO_TIMEOUT value on this acceptor's server socket.
		 * 
		 * @param timeout
		 *            The timeout in milliseconds, or <code>0</code> to
		 *            disable
		 * @throws SocketException
		 *             if the SO_TIMEOUT value can not be set
		 * @see ServerSocket#setSoTimeout(int)
		 */
		public void setSoTimeout(int timeout) throws SocketException {
			serverSocket.setSoTimeout(timeout);
		}

		/**
		 * Closes this acceptor and the underlying server socket.
		 * 
		 * @throws IOException
		 *             if an I/O exception occurs
		 * @see ServerSocket#close()
		 */
		public void close() throws IOException {
			closed = true;
			serverSocket.close();
		}

		/**
		 * Main method that accepts connections and checks the address against
		 * the list of allowed hosts.
		 * 
		 * @see NetworkInterface#allowedHosts
		 */
		@Override
		public void run() {
		    freenet.support.Logger.OSThread.logPID(this);
			while (!closed) {
				try {
					Socket clientSocket = serverSocket.accept();
					InetAddress clientAddress = clientSocket.getInetAddress();
					if(logMINOR)
						Logger.minor(Acceptor.class, "Connection from " + clientAddress);
					
					AddressType clientAddressType = AddressIdentifier.getAddressType(clientAddress.getHostAddress());

					/* check if the ip address is allowed */
					if (allowedHosts.allowed(clientAddress) && acceptedSockets.size() <= maxQueueLength) {
						lock.lock();
						try {
							acceptedSockets.add(clientSocket);
							socketCondition.signalAll();
						} finally {
							lock.unlock();
						}
					} else {
						try {
							clientSocket.close();
						} catch (IOException ioe1) {
						}
						Logger.normal(Acceptor.class, "Denied connection to " + clientAddress);
					}
				} catch (SocketTimeoutException ste1) {
					if(logMINOR)
						Logger.minor(this, "Timeout");
				} catch (IOException ioe1) {
					if(logMINOR)
						Logger.minor(this, "Caught " + ioe1);
				}
			}
			NetworkInterface.this.acceptorStopped();
		}

	}

	public String getAllowedHosts() {
		return allowedHosts.getAllowedHosts();
	}

	public boolean isBound() {
		lock.lock();
		try {
			return this.acceptors.size() != 0;
		} finally {
			lock.unlock();
		}
	}

	public void waitBound() {
		lock.lock();
		try {
			if(acceptors.size() > 0) return;
			while (true) {
				Logger.error(this, "Network interface isn't bound, waiting");
				boundCondition.awaitUninterruptibly();
				if(acceptors.size() > 0) {
					Logger.error(this, "Finished waiting, network interface is now bound");
					return;
				}
				if (shutdown)
					return;
				if (WrapperManager.hasShutdownHookBeenTriggered())
					return;
			}
		} finally {
			lock.unlock();
		}
	}

}
