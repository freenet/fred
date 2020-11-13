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

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLServerSocket;

import freenet.crypt.SSL;
import freenet.support.Executor;

/**
 * An SSL extension to the {@link NetworkInterface}
 * @author ET
 */
public class SSLNetworkInterface extends NetworkInterface {

	public static NetworkInterface create(int port, String bindTo, String allowedHosts, Executor executor, boolean ignoreUnbindableIP6) throws IOException {
		NetworkInterface iface = new SSLNetworkInterface(port, allowedHosts, executor);
		String[] failedBind = iface.setBindTo(bindTo, ignoreUnbindableIP6);
		if(failedBind != null) {
			System.err.println("Could not bind to some of the interfaces specified for port "+port+" : "+Arrays.toString(failedBind));
		}
		return iface;
	}

	/**
	 * See {@link NetworkInterface}
	 */
	protected SSLNetworkInterface(int port, String allowedHosts, Executor executor) throws IOException {
		super(port, allowedHosts, executor);
	}

	/**
	 * {@inheritDoc}
	 *
	 */
	@Override
	protected ServerSocket createServerSocket() throws IOException {
		SSLServerSocket serverSocket = (SSLServerSocket) SSL.createServerSocket();
		serverSocket.setNeedClientAuth(false);
		serverSocket.setUseClientMode(false);
		serverSocket.setWantClientAuth(false);

		List<String> enabledCiphers = new ArrayList<>();
		for(String cipher : serverSocket.getSupportedCipherSuites()) {
			if(ALLOWED_CIPHERS.contains(cipher)) {
				enabledCiphers.add(cipher);
			}
		}
		serverSocket.setEnabledCipherSuites(enabledCiphers.toArray(new String[0]));

		return serverSocket;
	}
	private static final Set<String> ALLOWED_CIPHERS = new HashSet(Arrays.asList(
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
			"TLS_EMPTY_RENEGOTIATION_INFO_SCSV"));
}
