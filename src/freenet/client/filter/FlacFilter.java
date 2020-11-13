package freenet.client.filter;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;

import freenet.l10n.NodeL10n;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;

/**Filters native FLAC data.
 * Format details may be found at <a href="http://flac.sourceforge.net/format.html"> http://flac.sourceforge.net/format.html</a>
 * @author sajack
 */
public class FlacFilter implements ContentDataFilter {
	static final byte[] magicNumber = new byte[] {0x66, 0x4C, 0x61, 0x43};
	enum State {UNINITIALIZED, STREAMINFO_FOUND, METADATA_FOUND, STREAM_FINISHED};

	public void readFilter(
      InputStream input, OutputStream output,
      String charset, HashMap<String, String> otherParams,
      String schemeHostAndPort, FilterCallback cb) throws DataFilterException, IOException {
		boolean logMINOR = Logger.shouldLog(LogLevel.MINOR, this.getClass());
		FlacPacketFilter parser = new FlacPacketFilter();
		DataInputStream in = new DataInputStream(input);
		State currentState = State.UNINITIALIZED;
		short frameHeader = 0;
		for(byte magicCharacter : magicNumber) {
			if(magicCharacter != in.readByte()) throw new DataFilterException(l10n("InvalidFLACStreamTitle"), l10n("InvalidFLACStreamTitle"), l10n("InvalidFLACStreamMessage"));
		}
		output.write(magicNumber);

		//Grab packets
		while(currentState != State.STREAM_FINISHED) {
			CodecPacket packet = null;
			try {
				if(currentState == State.METADATA_FOUND) frameHeader = (short) (in.readUnsignedShort() & 0x0000FFFF);
				byte[] payload = null;
				switch(currentState) {
				case UNINITIALIZED:
					if(logMINOR) Logger.minor(this, "Reading metadata packet");
					int header = in.readInt();
					payload = new byte[header & 0x00FFFFFF];
					if(logMINOR) Logger.minor(this, "About to read "+payload.length+" bytes");
					in.readFully(payload);
					packet = new FlacMetadataBlock(header, payload);
					if(logMINOR) Logger.minor(this, ((FlacMetadataBlock)packet).getMetadataBlockType()+" packet read");
					break;
				case METADATA_FOUND:
					if(logMINOR) Logger.minor(this, "Reading audio packet");
					boolean firstHalfOfSyncHeaderFound = false;
					ArrayList<Byte> buffer = new ArrayList<Byte>();
					int data = 0;
					buffer.add(Byte.valueOf((byte) ((frameHeader & 0xFF00) >>> 8)));
					buffer.add(Byte.valueOf((byte) (frameHeader & 0x00FF)));
					boolean running = true;
					while(running) {
						try {
							data = in.readUnsignedByte();
						} catch(EOFException e) {
							currentState = State.STREAM_FINISHED;
							running = false;
							frameHeader = 0;
							payload = new byte[buffer.size()];
							for(int i = 0; i < buffer.size(); i++) {
								byte item = buffer.get(i);
								payload[i] = item;
							}
							packet = new FlacFrame(payload);
						}
						if(!firstHalfOfSyncHeaderFound) {
							if((data & 0xFF) == 0xFF) {
								firstHalfOfSyncHeaderFound = true;
								continue;
							}
						} else {
							if((data & 0x7E) == 0x7D) {
								frameHeader = (short) (0xFF00 | data);
								payload = new byte[buffer.size()];
								for(int i = 0; i < buffer.size(); i++) {
									byte item = buffer.get(i);
									payload[i] = item;
								}
								running = false;
								packet = new FlacFrame(payload);
							} else {
								firstHalfOfSyncHeaderFound = false;
								buffer.add(Byte.valueOf((byte) 0xFF));
							}
						}
						buffer.add(Byte.valueOf((byte) (data & 0xFF)));
					}
				}
				if(currentState == State.UNINITIALIZED && packet instanceof FlacMetadataBlock && ((FlacMetadataBlock) packet).isLastMetadataBlock()) {
					currentState = State.METADATA_FOUND;
				}
				packet = parser.parse(packet);
				if(packet != null) output.write(packet.toArray());
			} catch(EOFException e) {
				return;
			}
		}
	}

	public void writeFilter(InputStream input, OutputStream output,
			String charset, HashMap<String, String> otherParams,
			FilterCallback cb) throws DataFilterException, IOException {
		// TODO Auto-generated method stub

	}

	private static String l10n(String key) {
		return NodeL10n.getBase().getString("FLAC."+key);
	}
}
