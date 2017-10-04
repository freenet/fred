/*
 * Dijjer - A Peer to Peer HTTP Cache
 * Copyright (C) 2004,2005 Change.Tv, Inc
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package freenet.io.comm;

import java.io.DataInput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import freenet.io.WritableToDataOutputStream;
import freenet.support.transport.ip.HostnameSyntaxException;
import freenet.support.transport.ip.IPUtil;

/**
 * @author ian
 *
 * To change the template for this generated type comment go to Window - Preferences - Java - Code Generation - Code and
 * Comments
 */
public class Peer implements WritableToDataOutputStream {

    public static class LocalAddressException extends Exception {
    	private static final long serialVersionUID = -1;
	}

	public static final String VERSION = "$Id: Peer.java,v 1.4 2005/08/25 17:28:19 amphibian Exp $";

    private final FreenetInetAddress addr;
	private final int _port;

	public Peer(DataInput dis) throws IOException {
		addr = new FreenetInetAddress(dis);
		_port = dis.readInt();
		if(_port > 65535 || _port < 0) throw new IOException("bogus port");
	}

	public Peer(DataInput dis, boolean checkHostnameOrIPSyntax) throws HostnameSyntaxException, IOException {
		addr = new FreenetInetAddress(dis, checkHostnameOrIPSyntax);
		_port = dis.readInt();
		if(_port > 65535 || _port < 0) throw new IOException("bogus port");
	}

	/**
	 * Create a Peer from an InetAddress and a port. The IP address is primary; that is
	 * to say, it will remain the same regardless of DNS changes. Don't do this if you
	 * are dealing with domain names whose IP may change.
	 */
	public Peer(InetAddress address, int port) {
		addr = new FreenetInetAddress(address);
		_port = port;
		if(_port > 65535 || _port < 0) throw new IllegalArgumentException("bogus port");
	}

	/**
	 * Create a Peer from a string. This may be an IP address or a domain name. If it
	 * is the latter, the name is primary rather than the IP address; 
	 * getHandshakeAddress() will do a new lookup on the name, and change the IP address
	 * if the domain name has changed.
	 * @param physical The string to be parsed, in the format [ ip or domain name ]:[ port number].
	 * @throws PeerParseException If the string is not valid e.g. if it doesn't contain a 
	 * port.
	 * @throws UnknownHostException If allowUnknown is not set, and a domain name which does
	 * not exist was passed in.
	 */
    public Peer(String physical) throws PeerParseException, UnknownHostException {
        int offset = physical.lastIndexOf(':'); // ipv6
        if(offset < 0) throw new PeerParseException();
        String host = physical.substring(0, offset);
        addr = new FreenetInetAddress(host);
        String strport = physical.substring(offset+1);
        try {
            _port = Integer.parseInt(strport);
            if(_port < 0 || _port > 65535) throw new PeerParseException("Invalid port "+_port);
        } catch (NumberFormatException e) {
            throw new PeerParseException(e);
        }
	}

	/**
	 * Create a Peer from a string. This may be an IP address or a domain name. If it
	 * is the latter, the name is primary rather than the IP address; 
	 * getHandshakeAddress() will do a new lookup on the name, and change the IP address
	 * if the domain name has changed.
	 * @param physical The string to be parsed, in the format [ ip or domain name ]:[ port number].
	 * @param allowUnknown If true, allow construction of the Peer even if the domain name
	 * lookup fails.
	 * @param checkHostnameOrIPSyntax If true, validate the syntax of the given DNS hostname or IPv4
	 * IP address
	 * @throws HostnameSyntaxException If the string is not formatted as a proper DNS hostname
	 * or IPv4 IP address
	 * @throws PeerParseException If the string is not valid e.g. if it doesn't contain a 
	 * port.
	 * @throws UnknownHostException If allowUnknown is not set, and a domain name which does
	 * not exist was passed in.
	 */
    public Peer(String physical, boolean allowUnknown, boolean checkHostnameOrIPSyntax) throws HostnameSyntaxException, PeerParseException, UnknownHostException {
        int offset = physical.lastIndexOf(':'); // ipv6
        if(offset < 0) 
        	throw new PeerParseException("No port number: \""+physical+"\"");
        String host = physical.substring(0, offset);
        addr = new FreenetInetAddress(host, allowUnknown, checkHostnameOrIPSyntax);
        String strport = physical.substring(offset+1);
        try {
            _port = Integer.parseInt(strport);
            if(_port < 0 || _port > 65535) throw new PeerParseException("Invalid port "+_port);
        } catch (NumberFormatException e) {
            throw new PeerParseException(e);
        }
    }
    
    public Peer(FreenetInetAddress addr, int port) {
    	this.addr = addr;
    	if(addr == null) throw new NullPointerException();
    	this._port = port;
		if(_port > 65535 || _port < 0) throw new IllegalArgumentException("bogus port");
	}

	public boolean isNull() {
		return _port == 0;
	}
	
	// FIXME same issues as with FreenetInetAddress.laxEquals/equals/strictEquals
	public boolean laxEquals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof Peer)) {
			return false;
		}

		final Peer peer = (Peer) o;

		if (_port != peer._port) {
			return false;
		}
		if(!addr.laxEquals(peer.addr))
			return false;
		return true;
	}

	// FIXME same issues as with FreenetInetAddress.laxEquals/equals/strictEquals
	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof Peer)) {
			return false;
		}

		final Peer peer = (Peer) o;

		if (_port != peer._port) {
			return false;
		}
		if(!addr.equals(peer.addr))
			return false;
		return true;
	}

	public boolean strictEquals(Object o) {
		if (this == o) {
			return true;
		}
		if(o == null) return false;
		if (!(o instanceof Peer)) {
			return false;
		}

		final Peer peer = (Peer) o;

		if (_port != peer._port) {
			return false;
		}
		if(!addr.strictEquals(peer.addr))
			return false;
		return true;
	}

	/**
	 * Get the IP address. Look it up if necessary, but return the last value if it
	 * has ever been looked up before; will not trigger a new lookup if it has been
	 * looked up before.
	 */
	public InetAddress getAddress() {
		return getAddress(true);
	}

	/**
	 * Get the IP address. Look it up if allowed to, but return the last value if it
	 * has ever been looked up before; will not trigger a new lookup if it has been
	 * looked up before.
	 */
	public InetAddress getAddress(boolean doDNSRequest) {
		return addr.getAddress(doDNSRequest);
	}
	
	public InetAddress getAddress(boolean doDNSRequest, boolean allowLocal) throws LocalAddressException {
		InetAddress a = addr.getAddress(doDNSRequest);
		if(a == null) return null;
		if(allowLocal || IPUtil.isValidAddress(a, false)) return a;
		throw new LocalAddressException();
	}
	
	/**
	 * Get the IP address, looking up the hostname if the hostname is primary, even if
	 * it has been looked up before. Typically called on a reconnect attempt, when the
	 * dyndns address may have changed.
	 */
	public InetAddress getHandshakeAddress() {
		return addr.getHandshakeAddress();
	}
	
	@Override
	public int hashCode() {
		return addr.hashCode() + _port;
	}

	public int getPort() {
		return _port;
	}

	@Override
	public String toString() {
		return addr.toString() + ':' + _port;
	}

	@Override
	public void writeToDataOutputStream(DataOutputStream dos) throws IOException {
		addr.writeToDataOutputStream(dos);
		dos.writeInt(_port);
	}

	public FreenetInetAddress getFreenetAddress() {
		return addr;
	}

	public boolean isRealInternetAddress(boolean lookup, boolean defaultVal, boolean allowLocalAddresses) {
		return addr.isRealInternetAddress(lookup, defaultVal, allowLocalAddresses);
	}

	/**
	 * Get the address:port string, but prefer numeric IPs - don't return the name.
	 */
	public String toStringPrefNumeric() {
		return addr.toStringPrefNumeric()+':'+_port;
	}

	public Peer dropHostName() {
		FreenetInetAddress newAddr = addr.dropHostname();
		if(newAddr == null) return null;
		if(addr != newAddr) {
			return new Peer(newAddr, _port);
		} else return this;
	}

	/** Is this peer using IPv6? */
	public boolean isIPv6(boolean defaultValue) {
		if(addr == null) return defaultValue;
		return addr.isIPv6(defaultValue);
	}
}
