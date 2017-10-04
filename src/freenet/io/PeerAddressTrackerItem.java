/* Copyright 2007 Freenet Project Inc.
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

import java.net.UnknownHostException;

import freenet.io.comm.Peer;
import freenet.io.comm.PeerParseException;
import freenet.node.FSParseException;
import freenet.support.SimpleFieldSet;

public class PeerAddressTrackerItem extends AddressTrackerItem {
	
	public final Peer peer;

	public PeerAddressTrackerItem(long timeDefinitelyNoPacketsReceived, 
			long timeDefinitelyNoPacketsSent, Peer peer) {
		super(timeDefinitelyNoPacketsReceived, timeDefinitelyNoPacketsSent);
		this.peer = peer;
	}
	
	public PeerAddressTrackerItem(SimpleFieldSet fs) throws FSParseException {
		super(fs);
		try {
			peer = new Peer(fs.getString("Address"));
		} catch (UnknownHostException e) {
			throw (FSParseException)new FSParseException("Unknown domain name in Address: "+e).initCause(e);
		} catch (PeerParseException e) {
			throw new FSParseException(e);
		}
	}

	@Override
	public SimpleFieldSet toFieldSet() {
		SimpleFieldSet fs = super.toFieldSet();
		fs.putOverwrite("Address", peer.toStringPrefNumeric());
		return fs;
	}

}
