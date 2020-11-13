package freenet.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;

import freenet.client.DefaultMIMETypes;
import freenet.client.async.ClientContext;
import freenet.client.filter.ContentFilter;
import freenet.client.filter.FilterOperation;
import freenet.client.filter.UnsafeContentTypeException;
import freenet.client.filter.ContentFilter.FilterStatus;
import freenet.node.FSParseException;
import freenet.node.Node;
import freenet.support.Logger;
import freenet.support.SimpleFieldSet;
import freenet.support.api.Bucket;
import freenet.support.api.BucketFactory;
import freenet.support.io.Closer;
import freenet.support.io.FileBucket;

/**
 * Message for testing the content filter on a file.  Server will respond with a FilterResultMessage.
 *
 * Filter
 * Identifier=filter1 // identifier
 * Operation=BOTH // READ/WRITE/BOTH (ignored for now)
 * MimeType=text/html // required if DataSource=DIRECT
 *
 * DataSource=DISK // read a file from disk
 * Filename=/home/bob/file.html // path to the file
 * End
 * or
 * DataSource=DIRECT // the data is in the message
 * DataLength=1000 // 1000 bytes
 * Data
 */
public class FilterMessage extends DataCarryingMessage {
	public static final String NAME = "Filter";

	private final String identifier;
	private final FilterOperation operation;
	private final DataSource dataSource;
	private final String mimeType;
	private final long dataLength;
	private final String filename;

	private final BucketFactory bf;

	public FilterMessage(SimpleFieldSet fs, BucketFactory bf) throws MessageInvalidException {
		try {
			identifier = fs.getString(IDENTIFIER);
		} catch (FSParseException e) {
			throw new MessageInvalidException(ProtocolErrorMessage.MISSING_FIELD, "Must contain an " + IDENTIFIER + " field", null, false);
		}
		String op;
		try {
			op = fs.getString("Operation");
		} catch (FSParseException e) {
			throw new MessageInvalidException(ProtocolErrorMessage.MISSING_FIELD, "Must contain an Operation field", identifier, false);
		}
		try {
			operation = FilterOperation.valueOf(op);
		} catch (IllegalArgumentException e) {
			throw new MessageInvalidException(ProtocolErrorMessage.INVALID_FIELD, "Illegal Operation value", identifier, false);
		}
		String ds;
		try {
			ds = fs.getString("DataSource");
		} catch (FSParseException e) {
			throw new MessageInvalidException(ProtocolErrorMessage.MISSING_FIELD, "Must contain a DataSource field", identifier, false);
		}
		try {
			dataSource = DataSource.valueOf(ds);
		} catch (IllegalArgumentException e) {
			throw new MessageInvalidException(ProtocolErrorMessage.INVALID_FIELD, "Illegal DataSource value", identifier, false);
		}
		String inputMimeType = fs.get("MimeType");
		filename = fs.get("Filename");
		if (dataSource == DataSource.DIRECT) {
			mimeType = inputMimeType;
			if (mimeType == null) {
				throw new MessageInvalidException(ProtocolErrorMessage.MISSING_FIELD, "Must contain a MimeType field", identifier, false);
			}
			String dl = fs.get("DataLength");
			if (dl == null) {
				throw new MessageInvalidException(ProtocolErrorMessage.MISSING_FIELD, "Must contain a DataLength field", identifier, false);
			}
			try {
				dataLength = fs.getLong("DataLength");
			} catch (FSParseException e) {
				throw new MessageInvalidException(ProtocolErrorMessage.ERROR_PARSING_NUMBER, "DataLength field must be a long", identifier, false);
			}
		} else if (dataSource == DataSource.DISK) {
			if (filename == null) {
				throw new MessageInvalidException(ProtocolErrorMessage.MISSING_FIELD, "Must contain a Filename field", identifier, false);
			}
			File file = new File(filename);
			if (!file.exists()) {
				throw new MessageInvalidException(ProtocolErrorMessage.FILE_NOT_FOUND, null, identifier, false);
			}
			if (!file.isFile()) {
				throw new MessageInvalidException(ProtocolErrorMessage.NOT_A_FILE_ERROR, null, identifier, false);
			}
			if (!file.canRead()) {
				throw new MessageInvalidException(ProtocolErrorMessage.COULD_NOT_READ_FILE, null, identifier, false);
			}
			if (inputMimeType != null) {
				mimeType = inputMimeType;
			} else {
				mimeType = bestGuessMimeType(filename);
				if (mimeType == null) {
					throw new MessageInvalidException(ProtocolErrorMessage.BAD_MIME_TYPE, "Could not determine MIME type from filename", identifier, false);
				}
			}
			dataLength = -1;
			this.bucket = new FileBucket(file, true, false, false, false);
		} else {
			throw new MessageInvalidException(ProtocolErrorMessage.INVALID_FIELD, "Illegal DataSource value", identifier, false);
		}
		this.bf = bf;
	}

	@Override
	String getIdentifier() {
		return identifier;
	}

	@Override
	boolean isGlobal() {
		return false;
	}

	@Override
	long dataLength() {
		return dataLength;
	}

	@Override
	public SimpleFieldSet getFieldSet() {
		SimpleFieldSet fs = new SimpleFieldSet(true);
		fs.putSingle(IDENTIFIER, identifier);
		fs.putOverwrite("Operation", operation.name());
		fs.putOverwrite("DataSource", dataSource.name());
		fs.putOverwrite("MimeType", mimeType);
		fs.putOverwrite("Filename", filename);
		fs.put("DataLength", dataLength);
		return fs;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
		if (bucket == null) {
			throw new MessageInvalidException(ProtocolErrorMessage.MISSING_FIELD, "Must contain data", identifier, false);
		}
		Bucket resultBucket;
		try {
			resultBucket = bf.makeBucket(-1);
		} catch (IOException e) {
			Logger.error(this, "Failed to create temporary bucket", e);
			throw new MessageInvalidException(ProtocolErrorMessage.INTERNAL_ERROR, e.toString(), identifier, false);
		}
		String resultCharset = null;
		String resultMimeType = null;
		boolean unsafe = false;
		InputStream input = null;
		OutputStream output = null;
		try {
			input = bucket.getInputStream();
			output = resultBucket.getOutputStream();
			FilterStatus status = applyFilter(input, output, handler.server.core.clientContext);
			resultCharset = status.charset;
			resultMimeType = status.mimeType;
		} catch (UnsafeContentTypeException e) {
			unsafe = true;
		} catch (IOException e) {
			Logger.error(this, "IO error running content filter", e);
			throw new MessageInvalidException(ProtocolErrorMessage.INTERNAL_ERROR, e.toString(), identifier, false);
		} finally {
			Closer.close(input);
			Closer.close(output);
		}
		FilterResultMessage response = new FilterResultMessage(identifier, resultCharset, resultMimeType, unsafe, resultBucket);
		handler.send(response);
	}

	private FilterStatus applyFilter(InputStream input, OutputStream output, ClientContext clientContext) throws MessageInvalidException, UnsafeContentTypeException, IOException {
		URI fakeUri;
		try {
			fakeUri = new URI("http://127.0.0.1:8888/");
		} catch (URISyntaxException e) {
			Logger.error(this, "Inexplicable URI error", e);
			throw new MessageInvalidException(ProtocolErrorMessage.INTERNAL_ERROR, e.toString(), identifier, false);
		}
		//TODO: check operation, once ContentFilter supports write filtering
		return ContentFilter.filter(input, output, mimeType, fakeUri, null, null, null, null, clientContext.linkFilterExceptionProvider);
	}

	private String bestGuessMimeType(String filename)
	{
		String guessedMimeType = null;
		if (filename != null) {
			guessedMimeType = DefaultMIMETypes.guessMIMEType(filename, true);
		}
		return guessedMimeType;
	}

}
