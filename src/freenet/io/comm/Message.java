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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import freenet.support.ByteBufferInputStream;
import freenet.support.Fields;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Serializer;
import freenet.support.ShortBuffer;
import freenet.support.Logger.LogLevel;

/**
 * A Message which can be read from and written to a DatagramPacket.
 * 
 * SECURITY REDFLAG WARNING: Messages should normally be recreated rather 
 * than passed on. Messages can contain sub-messages, these are used to
 * avoid having to add whole new message types every time we add one field
 * to a message... Passing on a message as-is means it includes the 
 * sub-messages, which could lead to e.g. labelling, communication between
 * colluding nodes along a request route, and just wasting bytes.
 * 
 * FIXME we should get rid of sub-messages.
 *
 * @author ian
 */
public class Message {

	public static final String VERSION = "$Id: Message.java,v 1.11 2005/09/15 18:16:04 amphibian Exp $";
	private static volatile boolean logMINOR;
	private static volatile boolean logDEBUG;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
				logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}

	private final MessageType _spec;
	private final WeakReference<? extends PeerContext> _sourceRef;
	private final boolean _internal;
	private final HashMap<String, Object> _payload = new HashMap<String, Object>(8);
	private List<Message> _subMessages;
	public final long localInstantiationTime;
	final int _receivedByteCount;
	short priority;
	private boolean needsLoadRT;
	private boolean needsLoadBulk;
	
	public static Message decodeMessageFromPacket(byte[] buf, int offset, int length, PeerContext peer, int overhead) {
		ByteBufferInputStream bb = new ByteBufferInputStream(buf, offset, length);
		return decodeMessage(bb, peer, length + overhead, true, false, false);
	}
	
	public static Message decodeMessageLax(byte[] buf, PeerContext peer, int overhead) {
		ByteBufferInputStream bb = new ByteBufferInputStream(buf);
		return decodeMessage(bb, peer, buf.length + overhead, true, false, true);
	}

	private static Message decodeMessage(ByteBufferInputStream bb, PeerContext peer, int recvByteCount,
	        boolean mayHaveSubMessages, boolean inSubMessage, boolean veryLax) {
		MessageType mspec;
		try {
			mspec = MessageType.getSpec(bb.readInt(), veryLax);
		} catch (IOException e1) {
			if (logMINOR) Logger.minor(Message.class,"Failed to read message type: "+e1, e1);
			return null;
		}
		if (mspec == null) {
			if (logMINOR) Logger.minor(Message.class, "Bogus message type");
			return null;
		}
		if (mspec.isInternalOnly()) {
			if(logMINOR) Logger.minor(Message.class, "Internal only message");
			return null; // silently discard internal-only messages
		}
		Message m = new Message(mspec, peer, recvByteCount);
		try {
			for (String name : mspec.getOrderedFields()) {
				Class<?> type = mspec.getFields().get(name);
				if (type.equals(LinkedList.class)) { // Special handling for LinkedList to deal with element type
					m.set(name, Serializer
					      .readListFromDataInputStream(mspec.getLinkedListTypes().get(name), bb));
				} else {
					m.set(name, Serializer.readFromDataInputStream(type, bb));
				}
			}
			if (mayHaveSubMessages) {
				while (bb.remaining() > 2) { // sizeof(unsigned short) == 2
					ByteBufferInputStream bb2;
					try {
						int size = bb.readUnsignedShort();
						if (bb.remaining() < size) return m;
						bb2 = bb.slice(size);
					} catch (EOFException e) {
						if (logMINOR) Logger.minor(Message.class, "No submessages, returning: "+m);
						return m;
					}
					try {
						Message subMessage = decodeMessage(bb2, peer, 0, false, true, veryLax);
						if (subMessage == null) return m;
						if (logMINOR) Logger.minor(Message.class, "Adding submessage: "+subMessage);
						m.addSubMessage(subMessage);
					} catch (Throwable t) {
						Logger.error(Message.class, "Failed to read sub-message: "+t, t);
					}
				}
			}
		} catch (EOFException e) {
			String msg = peer.getPeer()+" sent a message packet that ends prematurely while deserialising "+mspec.getName();
			if (inSubMessage) {
				if (logMINOR) Logger.minor(Message.class, msg+" in sub-message", e);
			} else Logger.error(Message.class, msg, e);
			return null;
		} catch (IOException e) {
			Logger.error(Message.class, "Unexpected IOException: "+e+" reading from buffer stream", e);
			return null;
		}
		if (logMINOR) Logger.minor(Message.class, "Returning message: "+m+" from "+m.getSource());
		return m;
	}

	public Message(MessageType spec) {
		this(spec, null, 0);
	}

	private Message(MessageType spec, PeerContext source, int recvByteCount) {
		localInstantiationTime = System.currentTimeMillis();
		_spec = spec;
		if (source == null) {
			_internal = true;
			_sourceRef = null;
		} else {
			_internal = false;
			_sourceRef = source.getWeakRef();
		}
		_receivedByteCount = recvByteCount;
		priority = spec.getDefaultPriority();
	}

	/** Drops sub-messages, and makes it locally originated */
	private Message(Message m) {
		_spec = m._spec;
		_sourceRef = null;
		_internal = m._internal;
		_payload.putAll(m._payload);
		_subMessages = null;
		localInstantiationTime = System.currentTimeMillis();
		_receivedByteCount = 0;
		priority = m.priority;
		needsLoadRT = m.needsLoadRT;
		needsLoadBulk = m.needsLoadBulk;
	}

	public boolean getBoolean(String key) {
		return (Boolean) _payload.get(key);
	}

	public byte getByte(String key) {
		return (Byte) _payload.get(key);
	}

	public short getShort(String key) {
		return (Short) _payload.get(key);
	}

	public int getInt(String key) {
		return (Integer) _payload.get(key);
	}

	public long getLong(String key) {
		return (Long) _payload.get(key);
	}

	public double getDouble(String key) {
		return (Double) _payload.get(key);
	}

	public float getFloat(String key) {
		return (Float) _payload.get(key);
	}

	public double[] getDoubleArray(String key) {
		return ((double[]) _payload.get(key));
	}

	public float[] getFloatArray(String key) {
		return (float[]) _payload.get(key);
	}

	public String getString(String key) {
		return (String)_payload.get(key);
	}

	public Object getObject(String key) {
		return _payload.get(key);
	}
	
	public byte[] getShortBufferBytes(String key) {
		ShortBuffer buffer = (ShortBuffer) getObject(key);
		return buffer.getData();
	}

	public void set(String key, boolean b) {
		set(key, Boolean.valueOf(b));
	}

	public void set(String key, byte b) {
		set(key, Byte.valueOf(b));
	}

	public void set(String key, short s) {
		set(key, Short.valueOf(s));
	}

	public void set(String key, int i) {
		set(key, Integer.valueOf(i));
	}

	public void set(String key, long l) {
		set(key, Long.valueOf(l));
	}

	public void set(String key, double d) {
		set(key, Double.valueOf(d));
	}

	public void set(String key, float f) {
		set(key, Float.valueOf(f));
	}

	public void set(String key, Object value) {
		if (!_spec.checkType(key, value)) {
			if (value == null) {
				throw new IncorrectTypeException("Got null for " + key);
			}
			throw new IncorrectTypeException("Got " + value.getClass() + ", expected " + _spec.typeOf(key));
		}
		_payload.put(key, value);
	}

	public byte[] encodeToPacket() {
		return encodeToPacket(true);
	}

	private byte[] encodeToPacket(boolean includeSubMessages) {

		if (logDEBUG) Logger.debug(this, "My spec code: "+_spec.getName().hashCode()+" for "+_spec.getName());
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		try {
			dos.writeInt(_spec.getName().hashCode());
			for (String name : _spec.getOrderedFields()) {
				Serializer.writeToDataOutputStream(_payload.get(name), dos);
			}
			dos.flush();
		} catch (IOException e) {
			e.printStackTrace();
			throw new IllegalStateException(e.getMessage());
		}

		if (_subMessages != null && includeSubMessages) {
			for (Message _subMessage : _subMessages) {
				byte[] temp = _subMessage.encodeToPacket(false);
				try {
					dos.writeShort(temp.length);
					dos.write(temp);
				} catch (IOException e) {
					e.printStackTrace();
					throw new IllegalStateException(e.getMessage());
				}
			}
		}

		byte[] buf = baos.toByteArray();
		if (logDEBUG) Logger.debug(this, "Length: "+buf.length+", hash: "+Fields.hashCode(buf));
		return buf;
	}

	@Override
	public String toString() {
		StringBuilder ret = new StringBuilder(1000);
		String comma = "";
		ret.append(_spec.getName()).append(" {");
		for (String name : _spec.getFields().keySet()) {
			ret.append(comma);
			ret.append(name).append('=').append(_payload.get(name));
			comma = ", ";
		}
		ret.append('}');
		return ret.toString();
	}

	public PeerContext getSource() {
		return _sourceRef == null ? null : _sourceRef.get();
	}

	public boolean isInternal() {
	    return _internal;
	}

	public MessageType getSpec() {
		return _spec;
	}

	public boolean isSet(String fieldName) {
		return _payload.containsKey(fieldName);
	}

	public Object getFromPayload(String fieldName) throws FieldNotSetException {
		Object r =  _payload.get(fieldName);
		if (r == null) {
			throw new FieldNotSetException(fieldName+" not set");
		}
		return r;
	}

	public static class FieldNotSetException extends RuntimeException {
		private static final long serialVersionUID = 1L;

		public FieldNotSetException(String message) {
			super(message);
		}
	}

	/**
	 * Set fields for a routed-to-a-specific-node message.
	 * @param nodeIdentity
	 */
	public void setRoutedToNodeFields(long uid, double targetLocation, short htl, byte[] nodeIdentity) {
		set(DMT.UID, uid);
		set(DMT.TARGET_LOCATION, targetLocation);
		set(DMT.HTL, htl);
		set(DMT.NODE_IDENTITY, new ShortBuffer(nodeIdentity));
	}

	public int receivedByteCount() {
		return _receivedByteCount;
	}

	public void addSubMessage(Message subMessage) {
		if (_subMessages == null) _subMessages = new ArrayList<Message>();
		_subMessages.add(subMessage);
	}

	public Message getSubMessage(MessageType t) {
		if (_subMessages == null) return null;
		for (Message m : _subMessages) {
			if (m.getSpec() == t) return m;
		}
		return null;
	}

	public Message grabSubMessage(MessageType t) {
		if (_subMessages == null) return null;
		for (int i=0;i<_subMessages.size();i++) {
			Message m = _subMessages.get(i);
			if (m.getSpec() == t) {
				_subMessages.remove(i);
				return m;
			}
		}
		return null;
	}

	public long age() {
		return System.currentTimeMillis() - localInstantiationTime;
	}

	public short getPriority() {
		return priority;
	}
	
	public void boostPriority() {
		priority--;
	}

	public boolean needsLoadRT() {
		return needsLoadRT;
	}
	
	public boolean needsLoadBulk() {
		return needsLoadBulk;
	}
	
	public void setNeedsLoadRT() {
		needsLoadRT = true;
	}
	
	public void setNeedsLoadBulk() {
		needsLoadBulk = true;
	}

	/** Clone the message, clear sub-messages and set originator to self. */
	public Message cloneAndDropSubMessages() {
		return new Message(this);
	}

}
