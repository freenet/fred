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

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import freenet.io.AddressIdentifier.AddressType;
import freenet.support.Logger;

/** Implementation of allowedHosts */
public class AllowedHosts {
	
	protected final List<AddressMatcher> addressMatchers = new ArrayList<AddressMatcher>();
	
	public AllowedHosts(String allowedHosts) {
		setAllowedHosts(allowedHosts);
	}

	/**
	 * Sets the list of allowed hosts to <code>allowedHosts</code>. The new
	 * list is in effect immediately after this method has finished.
	 * 
	 * @param allowedHosts
	 *            The new list of allowed hosts s
	 */
	public void setAllowedHosts(String allowedHosts) {
                if(allowedHosts == null || allowedHosts.equals("")) allowedHosts = NetworkInterface.DEFAULT_BIND_TO;
		StringTokenizer allowedHostsTokens = new StringTokenizer(allowedHosts, ",");
		List<AddressMatcher> newAddressMatchers = new ArrayList<AddressMatcher>();
		while (allowedHostsTokens.hasMoreTokens()) {
			String allowedHost = allowedHostsTokens.nextToken().trim();
			String hostname = allowedHost;
			if (allowedHost.indexOf('/') != -1) {
				hostname = allowedHost.substring(0, allowedHost.indexOf('/'));
			}
			AddressType addressType = AddressIdentifier.getAddressType(hostname);
			if (addressType == AddressType.IPv4) {
				newAddressMatchers.add(new Inet4AddressMatcher(allowedHost));
			} else if (addressType == AddressType.IPv6) {
				newAddressMatchers.add(new Inet6AddressMatcher(allowedHost));
			} else if (allowedHost.equals("*")) {
				newAddressMatchers.add(new EverythingMatcher());
			} else {
				Logger.error(NetworkInterface.class, "Ignoring invalid allowedHost: " + allowedHost);
			}
		}
		synchronized (this) {
			this.addressMatchers.clear();
			this.addressMatchers.addAll(newAddressMatchers);
		}
	}

	public synchronized boolean allowed(InetAddress clientAddress) {
		for(AddressMatcher matcher: addressMatchers) {
			if(matcher.matches(clientAddress)) return true;
		}
		return false;
	}

	public synchronized String getAllowedHosts() {
		StringBuilder sb = new StringBuilder();
		for(int i=0;i<addressMatchers.size();i++) {
			AddressMatcher matcher = addressMatchers.get(i);
			if(matcher instanceof EverythingMatcher) return "*";
			if(i != 0) sb.append(',');
			sb.append(matcher.getHumanRepresentation());
		}
		return sb.toString();
	}

}
