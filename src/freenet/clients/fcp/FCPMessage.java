package freenet.clients.fcp;

import java.io.IOException;
import java.io.OutputStream;

import freenet.node.Node;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.SimpleFieldSet;
import freenet.support.Logger.LogLevel;
import freenet.support.api.BucketFactory;
import freenet.support.io.PersistentTempBucketFactory;

public abstract class FCPMessage {
	/*
	 * Fields used by FCP messages. These are in TitleCaps by convention.
	 */
	public static final String BUILD = "Build";
	public static final String CODE = "Code";
	public static final String HTL = "HopsToLive";
	public static final String IDENTIFIER = "Identifier";
	public static final String LINK_LENGTHS = "LinkLengths";
	public static final String LOCAL = "Local";
	public static final String LOCATION = "Location";
	public static final String OUTPUT_BANDWIDTH = "OutputBandwidth";
	public static final String PROBE_IDENTIFIER = "ProbeIdentifier";
	public static final String STORE_SIZE = "StoreSize";
	public static final String TYPE = "Type";
	public static final String UPTIME_PERCENT = "UptimePercent";
	public static final String BULK_CHK_REQUEST_REJECTS = "Rejects.Bulk.Request.CHK";
	public static final String BULK_SSK_REQUEST_REJECTS = "Rejects.Bulk.Request.SSK";
	public static final String BULK_CHK_INSERT_REJECTS = "Rejects.Bulk.Insert.CHK";
	public static final String BULK_SSK_INSERT_REJECTS = "Rejects.Bulk.Insert.SSK";
	public static final String OUTPUT_BANDWIDTH_CLASS = "OutputBandwidthClass";
	public static final String OVERALL_BULK_OUTPUT_CAPACITY_USAGE = "OverallBulkOutputCapacityUsage";
	

        private static volatile boolean logDEBUG;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logDEBUG = Logger.shouldLog(LogLevel.DEBUG, this);
			}
		});
	}

	public void send(OutputStream os) throws IOException {
		SimpleFieldSet sfs = getFieldSet();
		if(sfs == null) {
			Logger.warning(this, "Not sending message "+this);
			return;
		}
		sfs.setEndMarker(getEndString());
		String msg = sfs.toString();
		os.write((getName()+ '\n').getBytes("UTF-8"));
		os.write(msg.getBytes("UTF-8"));
		if(logDEBUG) {
			Logger.debug(this, "Outgoing FCP message:\n"+getName()+'\n'+sfs.toString());
			Logger.debug(this, "Being handled by "+this);
		}
	}

	String getEndString() {
		return "EndMessage";
	}
	
	public abstract SimpleFieldSet getFieldSet();

	public abstract String getName();
	
	/**
	 * Create a message from a SimpleFieldSet, and the message's name, if possible. 
	 */
	public static FCPMessage create(String name, SimpleFieldSet fs, BucketFactory bfTemp, PersistentTempBucketFactory bfPersistent) throws MessageInvalidException {
		if(name.equals(AddPeer.NAME))
			return new AddPeer(fs);
		if(name.equals(ClientGetMessage.NAME))
			return new ClientGetMessage(fs);
		if(name.equals(ClientHelloMessage.NAME))
			return new ClientHelloMessage(fs);
		if(name.equals(ClientPutComplexDirMessage.NAME))
			return new ClientPutComplexDirMessage(fs, bfTemp, bfPersistent);
		if(name.equals(ClientPutDiskDirMessage.NAME))
			return new ClientPutDiskDirMessage(fs);
		if(name.equals(ClientPutMessage.NAME))
			return new ClientPutMessage(fs);
		if(name.equals(SendBookmarkMessage.NAME))
			return new SendBookmarkMessage(fs);
		if(name.equals(SendURIMessage.NAME))
			return new SendURIMessage(fs);
		if(name.equals(SendTextMessage.NAME))
			return new SendTextMessage(fs);
		if(name.equals(DisconnectMessage.NAME))
			return new DisconnectMessage();
        if(name.equals(FCPPluginClientMessage.NAME))
            return new FCPPluginClientMessage(fs);
		if(name.equals(GenerateSSKMessage.NAME))
			return new GenerateSSKMessage(fs);
		if(name.equals(GetConfig.NAME))
			return new GetConfig(fs);
		if(name.equals(GetNode.NAME))
			return new GetNode(fs);
		if(name.equals(GetPluginInfo.NAME))
			return new GetPluginInfo(fs);
		if(name.equals(GetRequestStatusMessage.NAME))
			return new GetRequestStatusMessage(fs);
		if(name.equals(ListPeerMessage.NAME))
			return new ListPeerMessage(fs);
		if(name.equals(ListPeersMessage.NAME))
			return new ListPeersMessage(fs);
		if(name.equals(ListPeerNotesMessage.NAME))
			return new ListPeerNotesMessage(fs);
		if(name.equals(ListPersistentRequestsMessage.NAME))
			return new ListPersistentRequestsMessage(fs);
		if(name.equals(LoadPlugin.NAME))
			return new LoadPlugin(fs);
		if(name.equals(ModifyConfig.NAME))
			return new ModifyConfig(fs);
		if(name.equals(ModifyPeer.NAME))
			return new ModifyPeer(fs);
		if(name.equals(ModifyPeerNote.NAME))
			return new ModifyPeerNote(fs);
		if(name.equals(ModifyPersistentRequest.NAME))
			return new ModifyPersistentRequest(fs);
		if(name.equals(ReloadPlugin.NAME))
			return new ReloadPlugin(fs);
		if(name.equals(RemovePeer.NAME))
			return new RemovePeer(fs);
		if(name.equals(RemovePersistentRequest.NAME)
				|| name.equals(RemovePersistentRequest.ALT_NAME))
			return new RemovePersistentRequest(fs);
		if(name.equals(RemovePlugin.NAME))
			return new RemovePlugin(fs);
		if(name.equals(ShutdownMessage.NAME))
			return new ShutdownMessage();
		if(name.equals(WatchFeedsMessage.NAME))
			return new WatchFeedsMessage(fs);
		if(name.equals(SubscribeUSKMessage.NAME))
			return new SubscribeUSKMessage(fs);
		if(name.equals(WatchFeedsMessage.NAME))
			return new WatchFeedsMessage(fs);
		if(name.equals(UnsubscribeUSKMessage.NAME))
			return new UnsubscribeUSKMessage(fs);
		if(name.equals(TestDDARequestMessage.NAME))
			return new TestDDARequestMessage(fs);
		if(name.equals(TestDDAResponseMessage.NAME))
			return new TestDDAResponseMessage(fs);
		if(name.equals(WatchGlobal.NAME))
			return new WatchGlobal(fs);
		if(name.equals(ProbeRequest.NAME)) return new ProbeRequest(fs);
		if(name.equals(FilterMessage.NAME))
			return new FilterMessage(fs, bfTemp);
		if(name.equals("Void"))
			return null;

		throw new MessageInvalidException(ProtocolErrorMessage.INVALID_MESSAGE, "Unknown message name "+name, null, false);
	}
	
	/**
	 * Create a message from a SimpleFieldSet, and the message's name, if possible. 
	 * Useful for FCPClients
	 */
	public static FCPMessage create(String name, SimpleFieldSet fs) throws MessageInvalidException {
		return FCPMessage.create(name, fs, null, null);
	}

	/**
	 * Returns an FCP message that delegates the methods {@link #getFieldSet()}, {@link #getName()},
	 * and {@link #run(FCPConnectionHandler, Node)} to the given FCP message, adding a
	 * “ListRequestIdentifier” field to the {@link SimpleFieldSet} returned by {@link
	 * #getFieldSet()}.
	 *
	 * @param fcpMessage
	 *         The FCP message to wrap
	 * @param listRequestIdentifier
	 *         The list request identifier to add (may be {@code null} in which case nothing is
	 *         added)
	 * @return The new FCP message
	 */
	public static FCPMessage withListRequestIdentifier(final FCPMessage fcpMessage, final String listRequestIdentifier) {
		if ((listRequestIdentifier == null) || (fcpMessage == null)) {
			return fcpMessage;
		}
		return new FCPMessage() {
			@Override
			public void send(OutputStream os) throws IOException {
				fcpMessage.send(os);
			}

			@Override
			String getEndString() {
				return fcpMessage.getEndString();
			}

			@Override
			public SimpleFieldSet getFieldSet() {
				SimpleFieldSet fieldSet = fcpMessage.getFieldSet();
				fieldSet.putOverwrite("ListRequestIdentifier", listRequestIdentifier);
				return fieldSet;
			}

			@Override
			public String getName() {
				return fcpMessage.getName();
			}

			@Override
			public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
				fcpMessage.run(handler, node);
			}
		};
	}

	/** Do whatever it is that we do with this type of message. 
	 * @throws MessageInvalidException */
	public abstract void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException;

}
