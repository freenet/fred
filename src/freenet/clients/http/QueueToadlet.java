/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.http;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

import freenet.client.DefaultMIMETypes;
import freenet.client.FetchException;
import freenet.client.FetchException.FetchExceptionMode;
import freenet.client.HighLevelSimpleClient;
import freenet.client.HighLevelSimpleClientImpl;
import freenet.client.InsertContext;
import freenet.client.InsertContext.CompatibilityMode;
import freenet.client.MetadataUnresolvedException;
import freenet.client.async.ClientContext;
import freenet.client.async.PersistenceDisabledException;
import freenet.client.async.PersistentJob;
import freenet.client.async.TooManyFilesInsertException;
import freenet.client.filter.ContentFilter;
import freenet.client.filter.FilterMIMEType;
import freenet.client.filter.KnownUnsafeContentTypeException;
import freenet.clients.fcp.ClientGet;
import freenet.clients.fcp.ClientPut;
import freenet.clients.fcp.ClientPut.COMPRESS_STATE;
import freenet.clients.fcp.ClientPutBase.UploadFrom;
import freenet.clients.fcp.ClientPutDir;
import freenet.clients.fcp.ClientRequest;
import freenet.clients.fcp.ClientRequest.Persistence;
import freenet.clients.fcp.DownloadRequestStatus;
import freenet.clients.fcp.FCPServer;
import freenet.clients.fcp.IdentifierCollisionException;
import freenet.clients.fcp.MessageInvalidException;
import freenet.clients.fcp.NotAllowedException;
import freenet.clients.fcp.RequestCompletionCallback;
import freenet.clients.fcp.RequestStatus;
import freenet.clients.fcp.UploadDirRequestStatus;
import freenet.clients.fcp.UploadFileRequestStatus;
import freenet.clients.fcp.UploadRequestStatus;
import freenet.keys.FreenetURI;
import freenet.l10n.NodeL10n;
import freenet.node.DarknetPeerNode;
import freenet.node.Node;
import freenet.node.NodeClientCore;
import freenet.node.RequestStarter;
import freenet.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import freenet.node.useralerts.StoringUserEvent;
import freenet.node.useralerts.UserAlert;
import freenet.support.Fields;
import freenet.support.HTMLNode;
import freenet.support.HexUtil;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.MultiValueTable;
import freenet.support.SizeUtil;
import freenet.support.TimeUtil;
import freenet.support.api.HTTPRequest;
import freenet.support.api.HTTPUploadedFile;
import freenet.support.api.RandomAccessBucket;
import freenet.support.io.BucketTools;
import freenet.support.io.Closer;
import freenet.support.io.FileBucket;
import freenet.support.io.FileUtil;
import freenet.support.io.NativeThread;

public class QueueToadlet extends Toadlet implements RequestCompletionCallback, LinkEnabledCallback {

	public enum QueueColumn {
		IDENTIFIER,
		SIZE,
		MIME_TYPE,
		PERSISTENCE,
		KEY,
		FILENAME,
		PRIORITY,
		FILES,
		TOTAL_SIZE,
		PROGRESS,
		REASON,
		LAST_ACTIVITY,
		LAST_FAILURE,
		COMPAT_MODE
	}

	private enum QueueType {
		CompletedDownloadToTemp(true, false, false),
		CompletedDownloadToDisk(true, false, false),
		CompletedUpload(true, false, true),
		CompletedDirUpload(true, false, true),
		FailedDownload(false, true, false),
		FailedUpload(false, true, true),
		FailedDirUpload(false, true, true),
		FailedBadMIMEType(false, true, false),
		FailedUnknownMIMEType(false, true, false),
		UncompletedDownload(false, false, false),
		UncompletedUpload(false, false, true),
		UncompletedDirUpload(false, false, true);

		final boolean isCompleted;
		final boolean isFailed;
		final boolean isUpload;

		private QueueType(boolean isCompleted, boolean isFailed, boolean isUpload) {
			this.isCompleted = isCompleted;
			this.isFailed = isFailed;
			this.isUpload = isUpload;
		}
	}

	private static final int MAX_IDENTIFIER_LENGTH = 1024*1024;
	static final int MAX_FILENAME_LENGTH = 1024*1024;
	private static final int MAX_TYPE_LENGTH = 1024;
	static final int MAX_KEY_LENGTH = 1024*1024;

	private NodeClientCore core;
	final FCPServer fcp;
	private FileInsertWizardToadlet fiw;

	private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	void setFIW(FileInsertWizardToadlet fiw) {
		this.fiw = fiw;
	}

	private boolean isReversed = false;
	private final boolean uploads;

    private static final String KEY_LIST_LOCATION = "listKeys.txt";

	public QueueToadlet(NodeClientCore core, FCPServer fcp, HighLevelSimpleClient client, boolean uploads) {
		super(client);
		this.core = core;
		this.fcp = fcp;
		this.uploads = uploads;
		if(fcp == null) throw new NullPointerException();
		fcp.setCompletionCallback(this);
		try {
			loadCompletedIdentifiers();
		} catch (PersistenceDisabledException e) {
			// The user will know soon enough
		}
	}
	
	public void handleMethodPOST(URI uri, HTTPRequest request, final ToadletContext ctx) throws ToadletContextClosedException, IOException, RedirectException {

		if(container.publicGatewayMode() && !ctx.isAllowedFullAccess()) {
		    sendUnauthorizedPage(ctx);
			return;
		}

		try {
			// Browse... button on upload page
			if (request.isPartSet("insert-local")) {
				
				FreenetURI insertURI;
				String keyType = request.getPartAsStringFailsafe("keytype", 10);
				if ("CHK".equals(keyType)) {
					insertURI = new FreenetURI("CHK@");
					if(fiw != null)
						fiw.reportCanonicalInsert();
				} else if("SSK".equals(keyType)) {
					insertURI = new FreenetURI("SSK@");
					if(fiw != null)
						fiw.reportRandomInsert();
				} else if("specify".equals(keyType)) {
					try {
						String u = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
						insertURI = new FreenetURI(u);
						if(logMINOR)
							Logger.minor(this, "Inserting key: "+insertURI+" ("+u+")");
					} catch (MalformedURLException mue1) {
						writeError(l10n("errorInvalidURI"),
						           l10n("errorInvalidURIToU"), ctx, false, true);
						return;
					}
				} else {
					writeError(l10n("errorMustSpecifyKeyTypeTitle"),
					           l10n("errorMustSpecifyKeyType"), ctx, false, true);
					return;
				}
				MultiValueTable<String, String> responseHeaders = new MultiValueTable<String, String>();
				responseHeaders.put("Location", LocalFileInsertToadlet.PATH+"?key="+insertURI.toASCIIString()+
				        "&compress="+String.valueOf(request.getPartAsStringFailsafe("compress", 128).length() > 0)+
				        "&compatibilityMode="+request.getPartAsStringFailsafe("compatibilityMode", 100)+
				        "&overrideSplitfileKey="+request.getPartAsStringFailsafe("overrideSplitfileKey", 65));
				ctx.sendReplyHeaders(302, "Found", responseHeaders, null, 0);
				return;
			} else if (request.isPartSet("select-location")) {
				try {
					throw new RedirectException(LocalDirectoryConfigToadlet.basePath()+"/downloads/");
				} catch (URISyntaxException e) {
					//Shouldn't happen, path is defined as such.
				}
			}

			if(request.isPartSet("delete_request") && (request.getPartAsStringFailsafe("delete_request", 128).length() > 0)) {
				// Confirm box
				PageNode page = ctx.getPageMaker().getPageNode(l10n("confirmDeleteTitle"), ctx);
				HTMLNode inner = page.content;
				HTMLNode content = ctx.getPageMaker().getInfobox("infobox-warning", l10n("confirmDeleteTitle"), inner, "confirm-delete-title", true);
				
				HTMLNode deleteNode = new HTMLNode("p");
				HTMLNode deleteForm = ctx.addFormChild(deleteNode, path(), "queueDeleteForm");
				HTMLNode infoList = deleteForm.addChild("ul");
				
				for(String part : request.getParts()) {
					if(!part.startsWith("identifier-")) continue;
					part = part.substring("identifier-".length());
					if(part.length() > 50) continue; // It's just a number 
					
					String identifier = request.getPartAsStringFailsafe("identifier-"+part, MAX_IDENTIFIER_LENGTH);
					if(identifier == null) continue;
					String filename = request.getPartAsStringFailsafe("filename-"+part, MAX_FILENAME_LENGTH);
					String keyString = request.getPartAsStringFailsafe("key-"+part, MAX_KEY_LENGTH);
					String type = request.getPartAsStringFailsafe("type-"+part, MAX_TYPE_LENGTH);
					String size = request.getPartAsStringFailsafe("size-"+part, 50);
					if(filename != null) {
						HTMLNode line = infoList.addChild("li");
						line.addChild("#", NodeL10n.getBase().getString("FProxyToadlet.filenameLabel")+" ");
						if(keyString != null) {
							line.addChild("a", "href", "/"+keyString, filename);
						} else {
							line.addChild("#", filename);
						}
					}
					if(type != null && !type.equals("")) {
						HTMLNode line = infoList.addChild("li");
						boolean finalized = request.isPartSet("finalizedType");
						line.addChild("#", NodeL10n.getBase().getString("FProxyToadlet."+(finalized ? "mimeType" : "expectedMimeType"), new String[] { "mime" }, new String[] { type }));
					}
					if(size != null) {
						HTMLNode line = infoList.addChild("li");
						line.addChild("#", NodeL10n.getBase().getString("FProxyToadlet.sizeLabel") + " " + size);
					}
					infoList.addChild("#", l10n("deleteFileFromTemp"));
					infoList.addChild("input", new String[] { "type", "name", "value", "checked" },
					        new String[] { "checkbox", "identifier-"+part, identifier, "checked" });
				}
				
				content.addChild("p", l10n("confirmDelete"));
				content.addChild(deleteNode);

				deleteForm.addChild("input",
				        new String[] { "type", "name", "value" },
				        new String[] { "submit", "remove_request", NodeL10n.getBase().getString("Toadlet.yes") });
				deleteForm.addChild("input",
				        new String[] { "type", "name", "value" },
				        new String[] { "submit", "cancel", NodeL10n.getBase().getString("Toadlet.no") });

				this.writeHTMLReply(ctx, 200, "OK", page.outer.generate());
				return;
			} else if(request.isPartSet("remove_request") && (request.getPartAsStringFailsafe("remove_request", 128).length() > 0)) {
				// Remove all requested (i.e. selected) requests from the queue, regardless of
				// their status
				// FIXME optimise into a single database job.
				
				String identifier = "";
				try {
					for(String part : request.getParts()) {
						if(!part.startsWith("identifier-")) continue;
						identifier = part.substring("identifier-".length());
						if(identifier.length() > 50) continue;
						identifier = request.getPartAsStringFailsafe(part, MAX_IDENTIFIER_LENGTH);
						if(logMINOR) Logger.minor(this, "Removing "+identifier);
						fcp.removeGlobalRequestBlocking(identifier);
					}
				} catch (MessageInvalidException e) {
					this.sendErrorPage(ctx, 200,
							l10n("failedToRemoveRequest"),
							l10n("failedToRemove",
							        new String[]{ "id", "message" },
							        new String[]{ identifier, e.getMessage()}
							));
					return;
				} catch (PersistenceDisabledException e) {
					sendPersistenceDisabledError(ctx);
					return;
				}
				writePermanentRedirect(ctx, "Done", path());
				return;
			} else if(request.isPartSet("remove_finished_uploads_request") && (request.getPartAsStringFailsafe("remove_finished_uploads_request", 128).length() > 0)) {
				// Remove all finished single-file uploads
				String identifier = "";
				try {
					RequestStatus[] reqs = fcp.getGlobalRequests();
					for (RequestStatus r : reqs) {
						if (r instanceof UploadFileRequestStatus) {
							UploadFileRequestStatus upload = (UploadFileRequestStatus) r;
							if (upload.hasSucceeded()) {
								identifier = upload.getIdentifier();
								fcp.removeGlobalRequestBlocking(identifier);
							}
						}
					}
				} catch (MessageInvalidException e) {
					this.sendErrorPage(ctx, 200,
							l10n("failedToRemoveRequest"),
							l10n("failedToRemove",
							        new String[]{ "id", "message" },
							        new String[]{ identifier, e.getMessage()}
							));
					return;
				} catch (PersistenceDisabledException e) {
					sendPersistenceDisabledError(ctx);
					return;
				}
				writePermanentRedirect(ctx, "Done", path());
				return;
				
			} else if(request.isPartSet("remove_finished_downloads_request") && (request.getPartAsStringFailsafe("remove_finished_downloads_request", 128).length() > 0)) {
				// Remove all finished downloads
				String identifier = "";
				try {
					RequestStatus[] reqs = fcp.getGlobalRequests();
					for (RequestStatus r : reqs) {
						if (r instanceof DownloadRequestStatus) {
							DownloadRequestStatus download = (DownloadRequestStatus) r;
							if (download.isPersistent() && download.hasSucceeded() && download.isTotalFinalized() && !download.toTempSpace()) {
								identifier = download.getIdentifier();
								fcp.removeGlobalRequestBlocking(identifier);
							}
						}
					}
				} catch (MessageInvalidException e) {
					this.sendErrorPage(ctx, 200,
							l10n("failedToRemoveRequest"),
							l10n("failedToRemove",
							        new String[]{ "id", "message" },
							        new String[]{ identifier, e.getMessage()}
							));
					return;
				} catch (PersistenceDisabledException e) {
					sendPersistenceDisabledError(ctx);
					return;
				}
				writePermanentRedirect(ctx, "Done", path());
				return;
			}
			else if(request.isPartSet("restart_request") && (request.getPartAsStringFailsafe("restart_request", 128).length() > 0)) {
				boolean disableFilterData = request.isPartSet("disableFilterData");
				
				
				String identifier = "";
				for(String part : request.getParts()) {
					if(!part.startsWith("identifier-")) continue;
					identifier = part.substring("identifier-".length());
					if(identifier.length() > 50) continue;
					identifier = request.getPartAsStringFailsafe(part, MAX_IDENTIFIER_LENGTH);
					if(logMINOR) Logger.minor(this, "Restarting "+identifier);
					try {
						fcp.restartBlocking(identifier, disableFilterData);
					} catch (PersistenceDisabledException e) {
						sendPersistenceDisabledError(ctx);
						return;
					}
				}
				writePermanentRedirect(ctx, "Done", path());
				return;
			} else if(request.isPartSet("panic") && (request.getPartAsStringFailsafe("panic", 128).length() > 0)) {
				if(SimpleToadletServer.noConfirmPanic) {
					core.node.killMasterKeysFile();
					core.node.panic();
					sendPanicingPage(ctx);
					core.node.finishPanic();
					return;
				} else {
					sendConfirmPanicPage(ctx);
					return;
				}
			} else if(request.isPartSet("confirmpanic") && (request.getPartAsStringFailsafe("confirmpanic", 128).length() > 0)) {
				core.node.killMasterKeysFile();
				core.node.panic();
				sendPanicingPage(ctx);
				core.node.finishPanic();
				return;
			} else if(request.isPartSet("download")) {
				// Queue a download
				if(!request.isPartSet("key")) {
					writeError(l10n("errorNoKey"), l10n("errorNoKeyToD"), ctx);
					return;
				}
				String expectedMIMEType = null;
				if(request.isPartSet("type")) {
					expectedMIMEType = request.getPartAsStringFailsafe("type", MAX_TYPE_LENGTH);
				}
				FreenetURI fetchURI;
				try {
					fetchURI = new FreenetURI(request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH));
				} catch (MalformedURLException e) {
					writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToD"), ctx);
					return;
				}
				String persistence = request.getPartAsStringFailsafe("persistence", 32);
				String returnType = request.getPartAsStringFailsafe("return-type", 32);
				boolean filterData = request.isPartSet("filterData");
				String downloadPath;
				File downloadsDir = null;
				//Download to disk disabled and initialized.
				if (request.isPartSet("path") && !core.isDownloadDisabled()) {
					downloadPath = request.getPartAsStringFailsafe("path", MAX_FILENAME_LENGTH);
					try {
						downloadsDir = getDownloadsDir(downloadPath);
					} catch (NotAllowedException e) {
						downloadDisallowedPage(e, downloadPath, ctx);
						return;
					}
				//Downloading to disk not initialized and/or disabled.
				} else returnType = "direct";
				try {
					fcp.makePersistentGlobalRequestBlocking(fetchURI, filterData, expectedMIMEType, persistence, returnType, false, downloadsDir);
				} catch (NotAllowedException e) {
					this.writeError(l10n("errorDToDisk"), l10n("errorDToDiskConfig"), ctx);
					return;
				} catch (PersistenceDisabledException e) {
					sendPersistenceDisabledError(ctx);
					return;
				}
				writePermanentRedirect(ctx, "Done", path());
				return;
			} else if(request.isPartSet("bulkDownloads")) {
				String bulkDownloadsAsString = request.getPartAsStringFailsafe("bulkDownloads", 262144);
				String[] keys = bulkDownloadsAsString.split("\n");
				if(("".equals(bulkDownloadsAsString)) || (keys.length < 1)) {
					writePermanentRedirect(ctx, "Done", path());
					return;
				}
				LinkedList<String> success = new LinkedList<String>(), failure = new LinkedList<String>();
				boolean filterData = request.isPartSet("filterData");
				String target = request.getPartAsStringFailsafe("target", 128);
				if(target == null) target = "direct";
				String downloadPath;
				File downloadsDir = null;
				if (request.isPartSet("path") && !core.isDownloadDisabled()) {
					downloadPath = request.getPartAsStringFailsafe("path", MAX_FILENAME_LENGTH);
					try {
						downloadsDir = getDownloadsDir(downloadPath);
					} catch (NotAllowedException e) {
						downloadDisallowedPage(e, downloadPath, ctx);
						return;
					}
				} else target = "direct";

				for(int i=0; i<keys.length; i++) {
					String currentKey = keys[i];

					// trim leading/trailing space
					currentKey = currentKey.trim();
					if (currentKey.length() == 0)
						continue;

					try {
						FreenetURI fetchURI = new FreenetURI(currentKey);
						fcp.makePersistentGlobalRequestBlocking(fetchURI, filterData, null,
						        "forever", target, false, downloadsDir);
						success.add(fetchURI.toString(true, false));
					} catch (Exception e) {
						failure.add(currentKey);
						Logger.error(this,
						        "An error occured while attempting to download key("+i+") : "+
						        currentKey+ " : "+e.getMessage());
					}
				}

				boolean displayFailureBox = failure.size() > 0;
				boolean displaySuccessBox = success.size() > 0;

				PageNode page = ctx.getPageMaker().getPageNode(l10n("downloadFiles"), ctx);
				HTMLNode pageNode = page.outer;
				HTMLNode contentNode = page.content;

				HTMLNode alertContent = ctx.getPageMaker().getInfobox(
				        (displayFailureBox ? "infobox-warning" : "infobox-info"),
				        l10n("downloadFiles"), contentNode, "grouped-downloads", true);
				if(displaySuccessBox) {
					HTMLNode successDiv = alertContent.addChild("ul");
					successDiv.addChild("#", l10n("enqueuedSuccessfully", "number",
					        String.valueOf(success.size())));
					for(String s: success) {
						HTMLNode line = successDiv.addChild("li");
						line.addChild("#", s);
					}
					successDiv.addChild("br");
				}
				if(displayFailureBox) {
					HTMLNode failureDiv = alertContent.addChild("ul");
					if(displayFailureBox) {
						failureDiv.addChild("#", l10n("enqueuedFailure", "number",
						        String.valueOf(failure.size())));
						for(String f: failure) {
							HTMLNode line = failureDiv.addChild("li");
							line.addChild("#", f);
						}
					}
					failureDiv.addChild("br");
				}
				alertContent.addChild("a", "href", path(),
				        NodeL10n.getBase().getString("Toadlet.returnToQueuepage"));
				writeHTMLReply(ctx, 200, "OK", pageNode.generate());
				return;
			} else if (request.isPartSet("change_priority_top")) {
				handleChangePriority(request, ctx, "_top");
				return;
			} else if (request.isPartSet("change_priority_bottom")) {
				handleChangePriority(request, ctx, "_bottom");
				return;
				// FIXME factor out the next 3 items, they are very messy!
			} else if (request.getPartAsStringFailsafe("insert", 128).length() > 0) {
				final FreenetURI insertURI;
				String keyType = request.getPartAsStringFailsafe("keytype", 10);
				if ("CHK".equals(keyType)) {
					insertURI = new FreenetURI("CHK@");
					if(fiw != null)
						fiw.reportCanonicalInsert();
				} else if("SSK".equals(keyType)) {
					insertURI = new FreenetURI("SSK@");
					if(fiw != null)
						fiw.reportRandomInsert();
				} else if("specify".equals(keyType)) {
					try {
						String u = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
						insertURI = new FreenetURI(u);
						if(logMINOR)
							Logger.minor(this, "Inserting key: "+insertURI+" ("+u+")");
					} catch (MalformedURLException mue1) {
						writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), ctx, false, true);
						return;
					}
				} else {
					writeError(l10n("errorMustSpecifyKeyTypeTitle"),
					           l10n("errorMustSpecifyKeyType"), ctx, false, true);
					return;
				}
				final HTTPUploadedFile file = request.getUploadedFile("filename");
				if (file == null || file.getFilename().trim().length() == 0) {
					writeError(l10n("errorNoFileSelected"), l10n("errorNoFileSelectedU"), ctx, false, true);
					return;
				}
				final boolean compress = request.getPartAsStringFailsafe("compress", 128).length() > 0;
				final String identifier = file.getFilename() + "-fred-" + System.currentTimeMillis();
				final String compatibilityMode = request.getPartAsStringFailsafe("compatibilityMode", 100);
				final CompatibilityMode cmode;
				if(compatibilityMode.equals(""))
					cmode = CompatibilityMode.COMPAT_DEFAULT.intern();
				else
					cmode = CompatibilityMode.valueOf(compatibilityMode).intern();
				String s = request.getPartAsStringFailsafe("overrideSplitfileKey", 65);
				final byte[] overrideSplitfileKey;
				if(s != null && !s.equals(""))
					overrideSplitfileKey = HexUtil.hexToBytes(s);
				else
					overrideSplitfileKey = null;
				final String fnam;
				if(insertURI.getKeyType().equals("CHK") || keyType.equals("SSK"))
					fnam = file.getFilename();
				else
					fnam = null;
				/* copy bucket data */
				final RandomAccessBucket copiedBucket = core.persistentTempBucketFactory.makeBucket(file.getData().size());
				BucketTools.copy(file.getData(), copiedBucket);
				final CountDownLatch done = new CountDownLatch(1);
				try {
					core.clientLayerPersister.queue(new PersistentJob() {

						@Override
						public String toString() {
							return "QueueToadlet StartInsert";
						}

						@Override
						public boolean run(ClientContext context) {
							try {
							final ClientPut clientPut;
							try {
								clientPut = new ClientPut(fcp.getGlobalForeverClient(), insertURI, identifier, Integer.MAX_VALUE, RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS, Persistence.FOREVER, null, false, !compress, -1, UploadFrom.DIRECT, null, file.getContentType(), copiedBucket, null, fnam, false, false, Node.FORK_ON_CACHEABLE_DEFAULT, HighLevelSimpleClientImpl.EXTRA_INSERTS_SINGLE_BLOCK, HighLevelSimpleClientImpl.EXTRA_INSERTS_SPLITFILE_HEADER, false, cmode, overrideSplitfileKey, false, fcp.core);
								if(clientPut != null)
									try {
										fcp.startBlocking(clientPut);
									} catch (IdentifierCollisionException e) {
										Logger.error(this, "Cannot put same file twice in same millisecond");
										writePermanentRedirect(ctx, "Done", path());
										return false;
									}
								writePermanentRedirect(ctx, "Done", path());
								return true;
							} catch (IdentifierCollisionException e) {
								Logger.error(this, "Cannot put same file twice in same millisecond");
								writePermanentRedirect(ctx, "Done", path());
								return false;
							} catch (NotAllowedException e) {
								writeError(l10n("errorAccessDenied"), l10n("errorAccessDeniedFile", "file", file.getFilename()), ctx, false, true);
								return false;
							} catch (FileNotFoundException e) {
								writeError(l10n("errorNoFileOrCannotRead"), l10n("errorAccessDeniedFile", "file", file.getFilename()), ctx, false, true);
								return false;
							} catch (MalformedURLException mue1) {
								writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), ctx, false, true);
								return false;
							} catch (MetadataUnresolvedException e) {
								Logger.error(this, "Unresolved metadata in starting insert from data uploaded from browser: "+e, e);
								writePermanentRedirect(ctx, "Done", path());
								return false;
								// FIXME should this be a proper localised message? It shouldn't happen... but we'd like to get reports if it does.
							} catch (Throwable t) {
								writeInternalError(t, ctx);
								return false;
							} finally {
								done.countDown();
							}
							} catch (IOException e) {
								// Ignore
								return false;
							} catch (ToadletContextClosedException e) {
								// Ignore
								return false;
							}
						}

					}, NativeThread.HIGH_PRIORITY+1);
				} catch (PersistenceDisabledException e1) {
					sendPersistenceDisabledError(ctx);
					return;
				}
				while (done.getCount() > 0) {
					try {
						done.await();
					} catch (InterruptedException e) {
						// Ignore
					}
				}
				return;
			} else if (request.isPartSet(LocalFileBrowserToadlet.selectFile)) {
				final String filename = request.getPartAsStringFailsafe("filename", MAX_FILENAME_LENGTH);
				if(logMINOR) Logger.minor(this, "Inserting local file: "+filename);
				final File file = new File(filename);
				final String identifier = file.getName() + "-fred-" + System.currentTimeMillis();
				final String contentType = DefaultMIMETypes.guessMIMEType(filename, false);
				final FreenetURI furi;
				final String key = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
				final boolean compress = request.isPartSet("compress");
				final String compatibilityMode = request.getPartAsStringFailsafe("compatibilityMode", 100);
				final CompatibilityMode cmode;
				if(compatibilityMode.equals(""))
					cmode = CompatibilityMode.COMPAT_DEFAULT;
				else
					cmode = CompatibilityMode.valueOf(compatibilityMode);
				String s = request.getPartAsStringFailsafe("overrideSplitfileKey", 65);
				final byte[] overrideSplitfileKey;
				if(s != null && !s.equals(""))
					overrideSplitfileKey = HexUtil.hexToBytes(s);
				else
					overrideSplitfileKey = null;
				if(key != null) {
					try {
						furi = new FreenetURI(key);
					} catch (MalformedURLException e) {
						writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), ctx);
						return;
					}
				} else {
					furi = new FreenetURI("CHK@");
				}
				final String target;
				if(furi.getDocName() != null)
					target = null;
				else
					target = file.getName();
				final CountDownLatch done = new CountDownLatch(1);
				try {
					core.clientLayerPersister.queue(new PersistentJob() {

						@Override
						public String toString() {
							return "QueueToadlet StartLocalFileInsert";
						}

						@Override
						public boolean run(ClientContext context) {
							final ClientPut clientPut;
							try {
							try {
								clientPut = new ClientPut(fcp.getGlobalForeverClient(), furi, identifier, Integer.MAX_VALUE, RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS, Persistence.FOREVER, null, false, !compress, -1, UploadFrom.DISK, file, contentType, new FileBucket(file, true, false, false, false), null, target, false, false, Node.FORK_ON_CACHEABLE_DEFAULT, HighLevelSimpleClientImpl.EXTRA_INSERTS_SINGLE_BLOCK, HighLevelSimpleClientImpl.EXTRA_INSERTS_SPLITFILE_HEADER, false, cmode, overrideSplitfileKey, false, fcp.core);
								if(logMINOR) Logger.minor(this, "Started global request to insert "+file+" to CHK@ as "+identifier);
								if(clientPut != null)
									try {
										fcp.startBlocking(clientPut);
									} catch (IdentifierCollisionException e) {
										Logger.error(this, "Cannot put same file twice in same millisecond");
										writePermanentRedirect(ctx, "Done", path());
										return false;
									} catch (PersistenceDisabledException e) {
										// Impossible???
									}
								writePermanentRedirect(ctx, "Done", path());
								return true;
							} catch (IdentifierCollisionException e) {
								Logger.error(this, "Cannot put same file twice in same millisecond");
								writePermanentRedirect(ctx, "Done", path());
								return false;
							} catch (MalformedURLException e) {
								writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), ctx);
								return false;
							} catch (FileNotFoundException e) {
								writeError(l10n("errorNoFileOrCannotRead"), l10n("errorAccessDeniedFile", "file", target), ctx);
								return false;
							} catch (NotAllowedException e) {
								writeError(l10n("errorAccessDenied"), l10n("errorAccessDeniedFile", new String[]{ "file" }, new String[]{ file.getName() }), ctx);
								return false;
							} catch (MetadataUnresolvedException e) {
								Logger.error(this, "Unresolved metadata in starting insert from data from file: "+e, e);
								writePermanentRedirect(ctx, "Done", path());
								return false;
								// FIXME should this be a proper localised message? It shouldn't happen... but we'd like to get reports if it does.
							} finally {
								done.countDown();
							}
							} catch (IOException e) {
								// Ignore
								return false;
							} catch (ToadletContextClosedException e) {
								// Ignore
								return false;
							}
						}

					}, NativeThread.HIGH_PRIORITY+1);
				} catch (PersistenceDisabledException e1) {
					sendPersistenceDisabledError(ctx);
					return;
				}
				while (done.getCount() > 0) {
					try {
						done.await();
					} catch (InterruptedException e) {
						// Ignore
					}
				}
				return;
			} else if (request.isPartSet(LocalFileBrowserToadlet.selectDir)) {
				final String filename = request.getPartAsStringFailsafe("filename", MAX_FILENAME_LENGTH);
				if(logMINOR) Logger.minor(this, "Inserting local directory: "+filename);
				final File file = new File(filename);
				final String identifier = file.getName() + "-fred-" + System.currentTimeMillis();
				final FreenetURI furi;
				final String key = request.getPartAsStringFailsafe("key", MAX_KEY_LENGTH);
				final boolean compress = request.isPartSet("compress");
				String s = request.getPartAsStringFailsafe("overrideSplitfileKey", 65);
				final byte[] overrideSplitfileKey;
				if(s != null && !s.equals(""))
					overrideSplitfileKey = HexUtil.hexToBytes(s);
				else
					overrideSplitfileKey = null;
				if(key != null) {
					try {
						furi = new FreenetURI(key);
					} catch (MalformedURLException e) {
						writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), ctx);
						return;
					}
				} else {
					furi = new FreenetURI("CHK@");
				}
				final CountDownLatch done = new CountDownLatch(1);
				try {
					core.clientLayerPersister.queue(new PersistentJob() {

						@Override
						public String toString() {
							return "QueueToadlet StartLocalDirInsert";
						}

						@Override
						public boolean run(ClientContext context) {
							ClientPutDir clientPutDir;
							try {
							try {
								clientPutDir = new ClientPutDir(fcp.getGlobalForeverClient(), furi, identifier, Integer.MAX_VALUE, RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS, Persistence.FOREVER, null, false, !compress, -1, file, null, false, /* make include hidden files configurable? FIXME */ false, true, false, false, Node.FORK_ON_CACHEABLE_DEFAULT, HighLevelSimpleClientImpl.EXTRA_INSERTS_SINGLE_BLOCK, HighLevelSimpleClientImpl.EXTRA_INSERTS_SPLITFILE_HEADER, false, overrideSplitfileKey, fcp.core);
								if(logMINOR) Logger.minor(this, "Started global request to insert dir "+file+" to "+furi+" as "+identifier);
								if(clientPutDir != null)
									try {
										fcp.startBlocking(clientPutDir);
									} catch (IdentifierCollisionException e) {
										Logger.error(this, "Cannot put same file twice in same millisecond");
										writePermanentRedirect(ctx, "Done", path());
										return false;
									} catch (PersistenceDisabledException e) {
										sendPersistenceDisabledError(ctx);
										return false;
									}
								writePermanentRedirect(ctx, "Done", path());
								return true;
							} catch (IdentifierCollisionException e) {
								Logger.error(this, "Cannot put same directory twice in same millisecond");
								writePermanentRedirect(ctx, "Done", path());
								return false;
							} catch (MalformedURLException e) {
								writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), ctx);
								return false;
							} catch (FileNotFoundException e) {
								writeError(l10n("errorNoFileOrCannotRead"), l10n("errorAccessDeniedFile", "file", file.toString()), ctx);
								return false;
							} catch (TooManyFilesInsertException e) {
								writeError(l10n("tooManyFilesInOneFolder"), l10n("tooManyFilesInOneFolder"), ctx);
								return false;
							} finally {
								done.countDown();
							}
							} catch (IOException e) {
								// Ignore
								return false;
							} catch (ToadletContextClosedException e) {
								// Ignore
								return false;
							}
						}

					}, NativeThread.HIGH_PRIORITY+1);
				} catch (PersistenceDisabledException e1) {
					sendPersistenceDisabledError(ctx);
					return;
				}
				while (done.getCount() > 0) {
					try {
						done.await();
					} catch (InterruptedException e) {
						// Ignore
					}
				}
				return;
			} else if (request.isPartSet("recommend_request")) {
				PageNode page = ctx.getPageMaker().getPageNode(l10n("recommendAFileToFriends"), ctx);
				HTMLNode pageNode = page.outer;
				HTMLNode contentNode = page.content;
				HTMLNode infoboxContent = ctx.getPageMaker().getInfobox("#", l10n("recommendAFileToFriends"), contentNode, "recommend-file", true);
				HTMLNode form = ctx.addFormChild(infoboxContent, path(), "recommendForm2");
				
				int x = 0;
				for(String part : request.getParts()) {
					if(!part.startsWith("identifier-")) continue;
					String key = request.getPartAsStringFailsafe("key-"+part.substring("identifier-".length()), MAX_KEY_LENGTH);
					if(key == null || key.equals("")) continue;
					form.addChild("#", l10n("key") + ":");
					form.addChild("br");
					form.addChild("#", key);
					form.addChild("br");
					form.addChild("input", new String[] { "type", "name", "value" },
							new String[] { "hidden", "key-"+x, key });
				}
				form.addChild("label", "for", "descB", (l10n("recommendDescription") + ' '));
				form.addChild("br");
				form.addChild("textarea",
				        new String[]{"id", "name", "row", "cols"},
				        new String[]{"descB", "description", "3", "70"});
				form.addChild("br");
				if (core.node.isFProxyJavascriptEnabled()) {
					form.addChild("script", new String[] {"type", "src"}, new String[] {"text/javascript",  "/static/js/checkall.js"});
				}
				HTMLNode peerTable = form.addChild("table", "class", "darknet_connections");
				if (core.node.isFProxyJavascriptEnabled()) {
					HTMLNode headerRow = peerTable.addChild("tr");
					headerRow.addChild("th").addChild("input", new String[] { "type", "onclick" }, new String[] { "checkbox", "checkAll(this, 'darknet_connections')" });
					headerRow.addChild("th", l10n("recommendToFriends"));
				} else {
					peerTable.addChild("tr").addChild("th", "colspan", "2", l10n("recommendToFriends"));
				}
				for(DarknetPeerNode peer : core.node.getDarknetConnections()) {
					HTMLNode peerRow = peerTable.addChild("tr", "class", "darknet_connections_normal");
					peerRow.addChild("td", "class", "peer-marker").addChild("input",
					        new String[] { "type", "name" }, 
					        new String[] { "checkbox", "node_" + peer.hashCode() });
					peerRow.addChild("td", "class", "peer-name").addChild("#", peer.getName());
				}

				form.addChild("input",
				        new String[]{"type", "name", "value"},
				        new String[]{"submit", "recommend_uri", l10n("recommend")});

				this.writeHTMLReply(ctx, 200, "OK", pageNode.generate());
				return;
			} else if(request.isPartSet("recommend_uri") && request.isPartSet("URI")) {
				String description = request.getPartAsStringFailsafe("description", 32768);
				ArrayList<FreenetURI> uris = new ArrayList<FreenetURI>();
				for(String part : request.getParts()) {
					if(!part.startsWith("key-")) continue;
					String key = request.getPartAsStringFailsafe(part, MAX_KEY_LENGTH);
					try {
						FreenetURI furi = new FreenetURI(key);
						uris.add(furi);
					} catch (MalformedURLException e) {
						writeError(l10n("errorInvalidURI"), l10n("errorInvalidURIToU"), ctx);
						return;
					}
				}
				
				for(DarknetPeerNode peer : core.node.getDarknetConnections()) {
					if(request.isPartSet("node_" + peer.hashCode())) {
						for(FreenetURI furi : uris)
							peer.sendDownloadFeed(furi, description);
					}
				}
				writePermanentRedirect(ctx, "Done", path());
				return;
			}
		} finally {
			request.freeParts();
		}
		this.handleMethodGET(uri, new HTTPRequestImpl(uri, "GET"), ctx);
	}

	private void handleChangePriority(HTTPRequest request, ToadletContext ctx, String suffix) throws ToadletContextClosedException, IOException {
		short newPriority = Short.parseShort(request.getPartAsStringFailsafe("priority"+suffix, 32));
		String identifier = "";
		for(String part : request.getParts()) {
			if(!part.startsWith("identifier-")) continue;
			identifier = part.substring("identifier-".length());
			if(identifier.length() > 50) continue;
			identifier = request.getPartAsStringFailsafe(part, MAX_IDENTIFIER_LENGTH);
			try {
				fcp.modifyGlobalRequestBlocking(identifier, null, newPriority);
			} catch (PersistenceDisabledException e) {
				sendPersistenceDisabledError(ctx);
				return;
			}
		}
		writePermanentRedirect(ctx, "Done", path());
	}

	private void downloadDisallowedPage (NotAllowedException e, String downloadPath, ToadletContext ctx)
	        throws IOException, ToadletContextClosedException {
		PageNode page = ctx.getPageMaker().getPageNode(l10n("downloadFiles"), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;
		Logger.warning(this, e.toString());
		HTMLNode alert = ctx.getPageMaker().getInfobox("infobox-alert",
			l10n("downloadFiles"), contentNode, "grouped-downloads", true);
		alert.addChild("ul", l10n("downloadDisallowed", "directory", downloadPath));
		alert.addChild("a", "href", path(),
			NodeL10n.getBase().getString("Toadlet.returnToQueuepage"));
		writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	}

	private File getDownloadsDir (String downloadPath) throws NotAllowedException {
		File downloadsDir = new File(downloadPath);
		//Invalid if it's disallowed, doesn't exist, isn't a directory, or can't be created.
		if(!core.allowDownloadTo(downloadsDir) || !((downloadsDir.exists() && 
				downloadsDir.isDirectory()) || !downloadsDir.mkdirs())) {
			throw new NotAllowedException();
		}
		return downloadsDir;
	}

	private void sendPanicingPage(ToadletContext ctx) throws ToadletContextClosedException, IOException {
		writeHTMLReply(ctx, 200, "OK", WelcomeToadlet.sendRestartingPageInner(ctx).generate());
	}

	private void sendConfirmPanicPage(ToadletContext ctx) throws ToadletContextClosedException, IOException {
		PageNode page = ctx.getPageMaker().getPageNode(l10n("confirmPanicButtonPageTitle"), ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;

		HTMLNode content = ctx.getPageMaker().getInfobox("infobox-error",
		        l10n("confirmPanicButtonPageTitle"), contentNode, "confirm-panic", true).
		        addChild("div", "class", "infobox-content");

		content.addChild("p", l10n("confirmPanicButton"));

		HTMLNode form = ctx.addFormChild(content, path(), "confirmPanicButton");
		form.addChild("p").addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "submit", "confirmpanic", l10n("confirmPanicButtonYes") });
		form.addChild("p").addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "submit", "noconfirmpanic", l10n("confirmPanicButtonNo") });

		if(uploads)
			content.addChild("p").addChild("a", "href", path(), l10n("backToUploadsPage"));
		else
			content.addChild("p").addChild("a", "href", path(), l10n("backToDownloadsPage"));

		writeHTMLReply(ctx, 200, "OK", pageNode.generate());
	}

	private void sendPersistenceDisabledError(ToadletContext ctx) throws ToadletContextClosedException, IOException {
		String title = l10n("awaitingPasswordTitle"+(uploads ? "Uploads" : "Downloads"));
		if(core.node.awaitingPassword()) {
			PageNode page = ctx.getPageMaker().getPageNode(title, ctx);
			HTMLNode pageNode = page.outer;
			HTMLNode contentNode = page.content;

			HTMLNode infoboxContent = ctx.getPageMaker().getInfobox("infobox-error", title, contentNode, null, true);

			SecurityLevelsToadlet.generatePasswordFormPage(false, container, infoboxContent, false, false, false, null, path());

			addHomepageLink(infoboxContent);

			writeHTMLReply(ctx, 500, "Internal Server Error", pageNode.generate());
			return;

		}
		if(core.node.isStopping())
			sendErrorPage(ctx, 200,
					l10n("shuttingDownTitle"),
					l10n("shuttingDown"));
		else
			sendErrorPage(ctx, 200,
					l10n("persistenceBrokenTitle"),
					l10n("persistenceBroken",
							new String[]{ "TEMPDIR", "DBFILE" },
							new String[]{ FileUtil.getCanonicalFile(core.getPersistentTempDir()).toString()+File.separator, core.node.getDatabasePath() }
					));
	}

	private void writeError(String header, String message, ToadletContext context) throws ToadletContextClosedException, IOException {
		writeError(header, message, context, true, false);
	}

	private void writeError(String header, String message, ToadletContext context, boolean returnToQueuePage, boolean returnToInsertPage) throws ToadletContextClosedException, IOException {
		PageMaker pageMaker = context.getPageMaker();
		PageNode page = pageMaker.getPageNode(header, context);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;
		if(context.isAllowedFullAccess())
			contentNode.addChild(context.getAlertManager().createSummary());
		HTMLNode infoboxContent = pageMaker.getInfobox("infobox-error", header, contentNode, "queue-error", false);
		infoboxContent.addChild("#", message);
		if(returnToQueuePage)
			NodeL10n.getBase().addL10nSubstitution(infoboxContent.addChild("div"), "QueueToadlet.returnToQueuePage", new String[] { "link" }, new HTMLNode[] { HTMLNode.link(path()) });
		else if(returnToInsertPage)
			NodeL10n.getBase().addL10nSubstitution(infoboxContent.addChild("div"), "QueueToadlet.tryAgainUploadFilePage", new String[] { "link" }, new HTMLNode[] { HTMLNode.link(FileInsertWizardToadlet.PATH) });
		writeHTMLReply(context, 400, "Bad request", pageNode.generate());
	}

	public void handleMethodGET(URI uri, final HTTPRequest request, final ToadletContext ctx)
	throws ToadletContextClosedException, IOException, RedirectException {

		// We ensure that we have a FCP server running
		if(!fcp.enabled){
			writeError(l10n("fcpIsMissing"), l10n("pleaseEnableFCP"), ctx, false, false);
			return;
		}

		if(container.publicGatewayMode() && !ctx.isAllowedFullAccess()) {
		    sendUnauthorizedPage(ctx);
			return;
		}

		final String requestPath = request.getPath().substring(path().length());

		boolean countRequests = false;
		boolean listKeys = false;

		if (requestPath.length() > 0) {
			if(requestPath.equals("countRequests.html") || requestPath.equals("/countRequests.html")) {
				countRequests = true;
			} else if(requestPath.equals(KEY_LIST_LOCATION)) {
				listKeys = true;
			}
		}

		class OutputWrapper {
			boolean done;
			HTMLNode pageNode;
			String plainText;
		}

		final OutputWrapper ow = new OutputWrapper();

		final PageMaker pageMaker = ctx.getPageMaker();

		final boolean count = countRequests;
		final boolean keys = listKeys;
		
		if(!(count || keys)) {
			try {
				RequestStatus[] reqs = fcp.getGlobalRequests();
				MultiValueTable<String, String> pageHeaders = new MultiValueTable<String, String>();
				HTMLNode pageNode = handleGetInner(pageMaker, reqs, request, ctx);
				writeHTMLReply(ctx, 200, "OK", pageHeaders, pageNode.generate());
				return;
			} catch (PersistenceDisabledException e) {
				sendPersistenceDisabledError(ctx);
				return;
			}
		}

		try {
			core.clientContext.jobRunner.queue(new PersistentJob() {

				@Override
				public String toString() {
					return "QueueToadlet ShowQueue";
				}

				@Override
				public boolean run(ClientContext context) {
					HTMLNode pageNode = null;
					String plainText = null;
					try {
						if(count) {
							long queued = core.requestStarters.chkFetchSchedulerBulk.countPersistentWaitingKeys() + core.requestStarters.chkFetchSchedulerRT.countPersistentWaitingKeys();
							Logger.minor(this, "Total waiting CHKs: "+queued);
							long reallyQueued = core.requestStarters.chkFetchSchedulerBulk.countQueuedRequests() + core.requestStarters.chkFetchSchedulerRT.countQueuedRequests();
							Logger.minor(this, "Total queued CHK requests (including transient): "+reallyQueued);
							PageNode page = pageMaker.getPageNode(l10n("title"), ctx);
							pageNode = page.outer;
							HTMLNode contentNode = page.content;
							/* add alert summary box */
							if(ctx.isAllowedFullAccess())
								contentNode.addChild(ctx.getAlertManager().createSummary());
							HTMLNode infoboxContent = pageMaker.getInfobox("infobox-information", "Queued requests status", contentNode, null, false);
							infoboxContent.addChild("p", "Total awaiting CHKs: "+queued);
							infoboxContent.addChild("p", "Total queued CHK requests: "+reallyQueued);
							return false;
						} else /*if(keys)*/ {
							try {
								plainText = makeKeysList(uploads);
							} catch (PersistenceDisabledException e) {
								plainText = null;
							}
							return false;
						}
					} finally {
						synchronized(ow) {
							ow.done = true;
							ow.pageNode = pageNode;
							ow.plainText = plainText;
							ow.notifyAll();
						}
					}
				}
			// Do not use maximal priority: There may be exceptional cases which have higher priority than the UI, to get rid of excessive garbage for example.
			}, NativeThread.HIGH_PRIORITY);
		} catch (PersistenceDisabledException e1) {
			sendPersistenceDisabledError(ctx);
			return;
		}

		HTMLNode pageNode;
		String plainText;
		synchronized(ow) {
			while(true) {
				if(ow.done) {
					pageNode = ow.pageNode;
					plainText = ow.plainText;
					break;
				}
				try {
					ow.wait();
				} catch (InterruptedException e) {
					// Ignore
				}
			}
		}

		MultiValueTable<String, String> pageHeaders = new MultiValueTable<String, String>();
		if(pageNode != null)
			writeHTMLReply(ctx, 200, "OK", pageHeaders, pageNode.generate());
		else if(plainText != null)
			this.writeReply(ctx, 200, "text/plain", "OK", plainText);
		else {
			if(core.killedDatabase())
				sendPersistenceDisabledError(ctx);
			else
				this.writeError("Internal error", "Internal error", ctx);
		}

	}

	protected String makeKeysList(boolean inserts) throws PersistenceDisabledException {
		RequestStatus[] reqs = fcp.getGlobalRequests();

		StringBuilder sb = new StringBuilder();

		for(RequestStatus req: reqs) {
			if(!inserts && req instanceof DownloadRequestStatus) {
				DownloadRequestStatus get = (DownloadRequestStatus)req;
				FreenetURI uri = get.getURI();
				sb.append(uri.toString());
				sb.append("\n");
			} else if (inserts && req instanceof UploadRequestStatus) {
                UploadRequestStatus put = (UploadRequestStatus)req;
				FreenetURI uri = put.getURI();
                if (uri != null) {
                    sb.append(uri.toString());
                    sb.append("\n");
                }
            }
		}
		return sb.toString();
	}

	private HTMLNode handleGetInner(PageMaker pageMaker, RequestStatus[] reqs, final HTTPRequest request, ToadletContext ctx) throws PersistenceDisabledException {

		// First, get the queued requests, and separate them into different types.
		LinkedList<DownloadRequestStatus> completedDownloadToDisk = new LinkedList<DownloadRequestStatus>();
		LinkedList<DownloadRequestStatus> completedDownloadToTemp = new LinkedList<DownloadRequestStatus>();
		LinkedList<UploadFileRequestStatus> completedUpload = new LinkedList<UploadFileRequestStatus>();
		LinkedList<UploadDirRequestStatus> completedDirUpload = new LinkedList<UploadDirRequestStatus>();

		LinkedList<DownloadRequestStatus> failedDownload = new LinkedList<DownloadRequestStatus>();
		LinkedList<UploadFileRequestStatus> failedUpload = new LinkedList<UploadFileRequestStatus>();
		LinkedList<UploadDirRequestStatus> failedDirUpload = new LinkedList<UploadDirRequestStatus>();

		LinkedList<DownloadRequestStatus> uncompletedDownload = new LinkedList<DownloadRequestStatus>();
		LinkedList<UploadFileRequestStatus> uncompletedUpload = new LinkedList<UploadFileRequestStatus>();
		LinkedList<UploadDirRequestStatus> uncompletedDirUpload = new LinkedList<UploadDirRequestStatus>();

		Map<String, LinkedList<DownloadRequestStatus>> failedUnknownMIMEType = new HashMap<String, LinkedList<DownloadRequestStatus>>();
		Map<String, LinkedList<DownloadRequestStatus>> failedBadMIMEType = new HashMap<String, LinkedList<DownloadRequestStatus>>();

		if(logMINOR)
			Logger.minor(this, "Request count: "+reqs.length);

		if(reqs.length < 1){
		    return sendEmptyQueuePage(ctx, pageMaker);
		}

		short lowestQueuedPrio = RequestStarter.PAUSED_PRIORITY_CLASS;

		long totalQueuedDownloadSize = 0;
		long totalQueuedUploadSize = 0;

		boolean added = false;
		for(RequestStatus req: reqs) {
			if(req instanceof DownloadRequestStatus && !uploads) {
				DownloadRequestStatus download = (DownloadRequestStatus)req;
				if(download.hasSucceeded()) {
					if(download.toTempSpace())
						completedDownloadToTemp.add(download);
					else // to disk
						completedDownloadToDisk.add(download);
				} else if(download.hasFinished()) {
				    FetchExceptionMode failureCode = download.getFailureCode();
					String mimeType = download.getMIMEType();
					if(mimeType == null && (failureCode == FetchExceptionMode.CONTENT_VALIDATION_UNKNOWN_MIME || failureCode == FetchExceptionMode.CONTENT_VALIDATION_BAD_MIME)) {
						Logger.error(this, "MIME type is null but failure code is "+FetchException.getMessage(failureCode)+" for "+download.getIdentifier()+" : "+download.getURI());
						mimeType = DefaultMIMETypes.DEFAULT_MIME_TYPE;
					}
					if(failureCode == FetchExceptionMode.CONTENT_VALIDATION_UNKNOWN_MIME) {
						mimeType = ContentFilter.stripMIMEType(mimeType);
						LinkedList<DownloadRequestStatus> list = failedUnknownMIMEType.get(mimeType);
						if(list == null) {
							list = new LinkedList<DownloadRequestStatus>();
							failedUnknownMIMEType.put(mimeType, list);
						}
						list.add(download);
					} else if(failureCode == FetchExceptionMode.CONTENT_VALIDATION_BAD_MIME) {
						mimeType = ContentFilter.stripMIMEType(mimeType);
						FilterMIMEType type = ContentFilter.getMIMEType(mimeType);
						LinkedList<DownloadRequestStatus> list;
						if(type == null) {
							Logger.error(this, "Bad MIME failure code yet MIME is "+mimeType+" which does not have a handler!");
							list = failedUnknownMIMEType.get(mimeType);
							if(list == null) {
								list = new LinkedList<DownloadRequestStatus>();
								failedUnknownMIMEType.put(mimeType, list);
							}
						} else {
							list = failedBadMIMEType.get(mimeType);
							if(list == null) {
								list = new LinkedList<DownloadRequestStatus>();
								failedBadMIMEType.put(mimeType, list);
							}
						}
						list.add(download);
					} else {
						failedDownload.add(download);
					}
				} else {
					short prio = download.getPriority();
					if(prio < lowestQueuedPrio)
						lowestQueuedPrio = prio;
					uncompletedDownload.add(download);
					long size = download.getDataSize();
					if(size > 0)
						totalQueuedDownloadSize += size;
				}
				added = true;
			} else if(req instanceof UploadFileRequestStatus && uploads) {
				UploadFileRequestStatus upload = (UploadFileRequestStatus)req;
				if(upload.hasSucceeded()) {
					completedUpload.add(upload);
				} else if(upload.hasFinished()) {
					failedUpload.add(upload);
				} else {
					short prio = upload.getPriority();
					if(prio < lowestQueuedPrio)
						lowestQueuedPrio = prio;
					uncompletedUpload.add(upload);
				}
				long size = upload.getDataSize();
				if(size > 0)
					totalQueuedUploadSize += size;
				added = true;
			} else if(req instanceof UploadDirRequestStatus && uploads) {
				UploadDirRequestStatus upload = (UploadDirRequestStatus)req;
				if(upload.hasSucceeded()) {
					completedDirUpload.add(upload);
				} else if(upload.hasFinished()) {
					failedDirUpload.add(upload);
				} else {
					short prio = upload.getPriority();
					if(prio < lowestQueuedPrio)
						lowestQueuedPrio = prio;
					uncompletedDirUpload.add(upload);
				}
				long size = upload.getTotalDataSize();
				if(size > 0)
					totalQueuedUploadSize += size;
                added = true;
			}
		}
		if(!added) {
		    return sendEmptyQueuePage(ctx, pageMaker);
		}
		Logger.minor(this, "Total queued downloads: "+SizeUtil.formatSize(totalQueuedDownloadSize));
		Logger.minor(this, "Total queued uploads: "+SizeUtil.formatSize(totalQueuedUploadSize));

		Comparator<RequestStatus> jobComparator = new Comparator<RequestStatus>() {
			@Override
			public int compare(RequestStatus firstRequest, RequestStatus secondRequest) {
				
				if(firstRequest == secondRequest) return 0; // Short cut.
				
				int result = 0;
				boolean isSet = true;

				if(request.isParameterSet("sortBy")){
					final String sortBy = request.getParam("sortBy");

					if(sortBy.equals("id")){
						result = firstRequest.getIdentifier().compareToIgnoreCase(secondRequest.getIdentifier());
						if(result == 0)
							result = firstRequest.getIdentifier().compareTo(secondRequest.getIdentifier());
					}else if(sortBy.equals("size")){
						result = Fields.compare(firstRequest.getTotalBlocks(), secondRequest.getTotalBlocks());
					}else if(sortBy.equals("progress")){
						boolean firstFinalized = firstRequest.isTotalFinalized();
						boolean secondFinalized = secondRequest.isTotalFinalized();
						if(firstFinalized && !secondFinalized)
							result = 1;
						else if(secondFinalized && !firstFinalized)
							result = -1;
						else {
							double firstProgress = ((double)firstRequest.getFetchedBlocks()) / ((double)firstRequest.getMinBlocks());
							double secondProgress = ((double)secondRequest.getFetchedBlocks()) / ((double)secondRequest.getMinBlocks());
							result = Fields.compare(firstProgress, secondProgress);
						}
					} else if (sortBy.equals("lastActivity")) {
                        result = Fields.compare(firstRequest.getLastSuccess(),
                                                secondRequest.getLastSuccess());
                    } else if (sortBy.equals("lastFailure")) {
                        result = Fields.compare(firstRequest.getLastFailure(),
                                                secondRequest.getLastFailure());
					}else
						isSet=false;
				}else
					isSet=false;

				if(!isSet){
					result = Fields.compare(firstRequest.getPriority(), secondRequest.getPriority());
					if(result == 0)
						result = firstRequest.getIdentifier().compareTo(secondRequest.getIdentifier());
				}

				if(result == 0){
					return 0;
				}else if(request.isParameterSet("reversed")){
					isReversed = true;
					return result > 0 ? -1 : 1;
				}else{
					isReversed = false;
					return result < 0 ? -1 : 1;
				}
			}
		};

		Collections.sort(completedDownloadToDisk, jobComparator);
		Collections.sort(completedDownloadToTemp, jobComparator);
		Collections.sort(completedUpload, jobComparator);
		Collections.sort(completedDirUpload, jobComparator);
		Collections.sort(failedDownload, jobComparator);
		Collections.sort(failedUpload, jobComparator);
		Collections.sort(failedDirUpload, jobComparator);
		Collections.sort(uncompletedDownload, jobComparator);
		Collections.sort(uncompletedUpload, jobComparator);
		Collections.sort(uncompletedDirUpload, jobComparator);

		String pageName;
		if(uploads)
			pageName =
				"(" + (uncompletedDirUpload.size() + uncompletedUpload.size()) +
				'/' + (failedDirUpload.size() + failedUpload.size()) +
				'/' + (completedDirUpload.size() + completedUpload.size()) +
				") "+l10n("titleUploads");
		else
			pageName =
				"(" + uncompletedDownload.size() +
				'/' + failedDownload.size() +
				'/' + (completedDownloadToDisk.size() + completedDownloadToTemp.size()) +
				") "+l10n("titleDownloads");

		PageNode page = pageMaker.getPageNode(pageName, ctx);
		HTMLNode pageNode = page.outer;
		HTMLNode contentNode = page.content;

		/* add alert summary box */
		if(ctx.isAllowedFullAccess())
			contentNode.addChild(ctx.getAlertManager().createSummary());

		/* navigation bar */
		InfoboxNode infobox = pageMaker.getInfobox("navbar", l10n("requestNavigation"), null, false);
		HTMLNode navigationBar = infobox.outer;
		HTMLNode navigationContent = infobox.content.addChild("ul");
		boolean includeNavigationBar = false;
		if (!completedDownloadToTemp.isEmpty()) {
			navigationContent.addChild("li").addChild("a", "href", "#completedDownloadToTemp", l10n("completedDtoTemp", new String[]{ "size" }, new String[]{ String.valueOf(completedDownloadToTemp.size()) }));
			includeNavigationBar = true;
		}
		if (!completedDownloadToDisk.isEmpty()) {
			navigationContent.addChild("li").addChild("a", "href", "#completedDownloadToDisk", l10n("completedDtoDisk", new String[]{ "size" }, new String[]{ String.valueOf(completedDownloadToDisk.size()) }));
			includeNavigationBar = true;
		}
		if (!completedUpload.isEmpty()) {
			navigationContent.addChild("li").addChild("a", "href", "#completedUpload", l10n("completedU", new String[]{ "size" }, new String[]{ String.valueOf(completedUpload.size()) }));
			includeNavigationBar = true;
		}
		if (!completedDirUpload.isEmpty()) {
			navigationContent.addChild("li").addChild("a", "href", "#completedDirUpload", l10n("completedDU", new String[]{ "size" }, new String[]{ String.valueOf(completedDirUpload.size()) }));
			includeNavigationBar = true;
		}
		if (!failedDownload.isEmpty()) {
			navigationContent.addChild("li").addChild("a", "href", "#failedDownload", l10n("failedD", new String[]{ "size" }, new String[]{ String.valueOf(failedDownload.size()) }));
			includeNavigationBar = true;
		}
		if (!failedUpload.isEmpty()) {
			navigationContent.addChild("li").addChild("a", "href", "#failedUpload", l10n("failedU", new String[]{ "size" }, new String[]{ String.valueOf(failedUpload.size()) }));
			includeNavigationBar = true;
		}
		if (!failedDirUpload.isEmpty()) {
			navigationContent.addChild("li").addChild("a", "href", "#failedDirUpload", l10n("failedDU", new String[]{ "size" }, new String[]{ String.valueOf(failedDirUpload.size()) }));
			includeNavigationBar = true;
		}
		if (failedUnknownMIMEType.size() > 0) {
			String[] types = failedUnknownMIMEType.keySet().toArray(new String[failedUnknownMIMEType.size()]);
			Arrays.sort(types);
			for(String type : types) {
				String atype = type.replace("-", "--").replace('/', '-');
				navigationContent.addChild("li").addChild("a", "href", "#failedDownload-unknowntype-"+atype, l10n("failedDUnknownMIME", new String[]{ "size", "type" }, new String[]{ String.valueOf(failedUnknownMIMEType.get(type).size()), type }));
			}
		}
		if (failedBadMIMEType.size() > 0) {
			String[] types = failedBadMIMEType.keySet().toArray(new String[failedBadMIMEType.size()]);
			Arrays.sort(types);
			for(String type : types) {
				String atype = type.replace("-", "--").replace('/', '-');
				navigationContent.addChild("li").addChild("a", "href", "#failedDownload-badtype-"+atype, l10n("failedDBadMIME", new String[]{ "size", "type" }, new String[]{ String.valueOf(failedBadMIMEType.get(type).size()), type }));
			}
		}
		if (!uncompletedDownload.isEmpty()) {
			navigationContent.addChild("li").addChild("a", "href", "#uncompletedDownload", l10n("DinProgress", new String[]{ "size" }, new String[]{ String.valueOf(uncompletedDownload.size()) }));
			includeNavigationBar = true;
		}
		if (!uncompletedUpload.isEmpty()) {
			navigationContent.addChild("li").addChild("a", "href", "#uncompletedUpload", l10n("UinProgress", new String[]{ "size" }, new String[]{ String.valueOf(uncompletedUpload.size()) }));
			includeNavigationBar = true;
		}
		if (!uncompletedDirUpload.isEmpty()) {
			navigationContent.addChild("li").addChild("a", "href", "#uncompletedDirUpload", l10n("DUinProgress", new String[]{ "size" }, new String[]{ String.valueOf(uncompletedDirUpload.size()) }));
			includeNavigationBar = true;
		}
		if (totalQueuedDownloadSize > 0) {
			navigationContent.addChild("li", l10n("totalQueuedDownloads", "size", SizeUtil.formatSize(totalQueuedDownloadSize)));
			includeNavigationBar = true;
		}
		if (totalQueuedUploadSize > 0) {
			navigationContent.addChild("li", l10n("totalQueuedUploads", "size", SizeUtil.formatSize(totalQueuedUploadSize)));
			includeNavigationBar = true;
		}

        navigationContent.addChild("li").addChild("a", "href", KEY_LIST_LOCATION,
                                                  l10n("openKeyList"));

		if (includeNavigationBar) {
			contentNode.addChild(navigationBar);
		}

		final String[] priorityClasses = new String[] {
				l10n("priority0"),
				l10n("priority1"),
				l10n("priority2"),
				l10n("priority3"),
				l10n("priority4"),
				l10n("priority5"),
				l10n("priority6")
		};

		boolean advancedModeEnabled = pageMaker.advancedMode(request, this.container);

		HTMLNode legendContent = pageMaker.getInfobox("legend", l10n("legend"), contentNode, "queue-legend", true);
		HTMLNode legendTable = legendContent.addChild("table", "class", "queue");
		HTMLNode legendRow = legendTable.addChild("tr");
		for(int i=0; i<7; i++){
		    if(i > RequestStarter.INTERACTIVE_PRIORITY_CLASS || advancedModeEnabled || i <= lowestQueuedPrio)
		        legendRow.addChild("td", "class", "priority" + i, priorityClasses[i]);
		}

		if (SimpleToadletServer.isPanicButtonToBeShown) {
		    // There may be persistent downloads etc under other PersistentRequestClient's, so still show it.
			contentNode.addChild(createPanicBox(pageMaker, ctx));
		}

		final QueueColumn[] advancedModeFailure = new QueueColumn[] {
		        QueueColumn.IDENTIFIER,
		        QueueColumn.FILENAME,
		        QueueColumn.SIZE,
		        QueueColumn.MIME_TYPE,
		        QueueColumn.PROGRESS,
		        QueueColumn.REASON,
		        QueueColumn.PERSISTENCE,
		        QueueColumn.KEY };
		
		final QueueColumn[] simpleModeFailure = new QueueColumn[] {
		        QueueColumn.FILENAME,
		        QueueColumn.SIZE,
		        QueueColumn.PROGRESS,
		        QueueColumn.REASON,
		        QueueColumn.KEY };

		if (!completedDownloadToTemp.isEmpty()) {
			contentNode.addChild("a", "id", "completedDownloadToTemp");
			HTMLNode completedDownloadsToTempContent = pageMaker.getInfobox("completed_requests", l10n("completedDinTempDirectory", new String[]{ "size" }, new String[]{ String.valueOf(completedDownloadToTemp.size()) }), contentNode, "request-completed", false);
			if (advancedModeEnabled) {
				completedDownloadsToTempContent.addChild(createRequestTable(ctx, completedDownloadToTemp, new QueueColumn[] { QueueColumn.IDENTIFIER, QueueColumn.SIZE, QueueColumn.MIME_TYPE, QueueColumn.PERSISTENCE, QueueColumn.KEY, QueueColumn.COMPAT_MODE }, priorityClasses, advancedModeEnabled, "completed-temp", QueueType.CompletedDownloadToTemp));
			} else {
				completedDownloadsToTempContent.addChild(createRequestTable(ctx, completedDownloadToTemp, new QueueColumn[] { QueueColumn.SIZE, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "completed-temp", QueueType.CompletedDownloadToTemp));
			}
		}

		if (!completedDownloadToDisk.isEmpty()) {
			contentNode.addChild("a", "id", "completedDownloadToDisk");
			HTMLNode completedToDiskInfoboxContent = pageMaker.getInfobox("completed_requests", l10n("completedDinDownloadDirectory", new String[]{ "size" }, new String[]{ String.valueOf(completedDownloadToDisk.size()) }), contentNode, "request-completed", false);
			if (advancedModeEnabled) {
				completedToDiskInfoboxContent.addChild(createRequestTable(ctx, completedDownloadToDisk, new QueueColumn[] { QueueColumn.IDENTIFIER, QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.MIME_TYPE, QueueColumn.PERSISTENCE, QueueColumn.KEY, QueueColumn.COMPAT_MODE }, priorityClasses, advancedModeEnabled, "completed-disk", QueueType.CompletedDownloadToDisk));
			} else {
				completedToDiskInfoboxContent.addChild(createRequestTable(ctx, completedDownloadToDisk, new QueueColumn[] { QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "completed-disk", QueueType.CompletedDownloadToDisk));
			}
		}

		if (!completedUpload.isEmpty()) {
			contentNode.addChild("a", "id", "completedUpload");
			HTMLNode completedUploadInfoboxContent = pageMaker.getInfobox("completed_requests", l10n("completedU", new String[]{ "size" }, new String[]{ String.valueOf(completedUpload.size()) }), contentNode, "download-completed", false);
			if (advancedModeEnabled) {
				completedUploadInfoboxContent.addChild(createRequestTable(ctx, completedUpload, new QueueColumn[] { QueueColumn.IDENTIFIER, QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.MIME_TYPE, QueueColumn.PERSISTENCE, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "completed-upload-file", QueueType.CompletedUpload));
			} else  {
				completedUploadInfoboxContent.addChild(createRequestTable(ctx, completedUpload, new QueueColumn[] { QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "completed-upload-file", QueueType.CompletedUpload));
			}
		}

		if (!completedDirUpload.isEmpty()) {
			contentNode.addChild("a", "id", "completedDirUpload");
			HTMLNode completedUploadDirContent = pageMaker.getInfobox("completed_requests", l10n("completedUDirectory", new String[]{ "size" }, new String[]{ String.valueOf(completedDirUpload.size()) }), contentNode, "download-completed", false);
			if (advancedModeEnabled) {
				completedUploadDirContent.addChild(createRequestTable(ctx, completedDirUpload, new QueueColumn[] { QueueColumn.IDENTIFIER, QueueColumn.FILES, QueueColumn.TOTAL_SIZE, QueueColumn.PERSISTENCE, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "completed-upload-dir", QueueType.CompletedDirUpload));
			} else {
				completedUploadDirContent.addChild(createRequestTable(ctx, completedDirUpload, new QueueColumn[] { QueueColumn.FILES, QueueColumn.TOTAL_SIZE, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "completed-upload-dir", QueueType.CompletedDirUpload));
			}
		}

		if (!failedDownload.isEmpty()) {
			contentNode.addChild("a", "id", "failedDownload");
			HTMLNode failedContent = pageMaker.getInfobox("failed_requests", l10n("failedD", new String[]{ "size" }, new String[]{ String.valueOf(failedDownload.size()) }), contentNode, "download-failed", false);
			if (advancedModeEnabled) {
				failedContent.addChild(createRequestTable(ctx, failedDownload, advancedModeFailure, priorityClasses, advancedModeEnabled, "failed-download", QueueType.FailedDownload));
			} else {
				failedContent.addChild(createRequestTable(ctx, failedDownload, simpleModeFailure, priorityClasses, advancedModeEnabled, "failed-download", QueueType.FailedDownload));
			}
		}

		if (!failedUpload.isEmpty()) {
			contentNode.addChild("a", "id", "failedUpload");
			HTMLNode failedContent = pageMaker.getInfobox("failed_requests", l10n("failedU", new String[]{ "size" }, new String[]{ String.valueOf(failedUpload.size()) }), contentNode, "upload-failed", false);
			if (advancedModeEnabled) {
				failedContent.addChild(createRequestTable(ctx, failedUpload, advancedModeFailure, priorityClasses, advancedModeEnabled, "failed-upload-file", QueueType.FailedUpload));
			} else {
				failedContent.addChild(createRequestTable(ctx, failedUpload, simpleModeFailure, priorityClasses, advancedModeEnabled, "failed-upload-file", QueueType.FailedUpload));
			}
		}

		if (!failedDirUpload.isEmpty()) {
			contentNode.addChild("a", "id", "failedDirUpload");
			HTMLNode failedContent = pageMaker.getInfobox("failed_requests", l10n("failedU", new String[]{ "size" }, new String[]{ String.valueOf(failedDirUpload.size()) }), contentNode, "upload-failed", false);
			if (advancedModeEnabled) {
				failedContent.addChild(createRequestTable(ctx, failedDirUpload, new QueueColumn[] { QueueColumn.IDENTIFIER, QueueColumn.FILES, QueueColumn.TOTAL_SIZE, QueueColumn.PROGRESS, QueueColumn.REASON, QueueColumn.PERSISTENCE, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "failed-upload-dir", QueueType.FailedDirUpload));
			} else {
				failedContent.addChild(createRequestTable(ctx, failedDirUpload, new QueueColumn[] { QueueColumn.FILES, QueueColumn.TOTAL_SIZE, QueueColumn.PROGRESS, QueueColumn.REASON, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "failed-upload-dir", QueueType.FailedDirUpload));
			}
		}

		if(!failedBadMIMEType.isEmpty()) {
			String[] types = failedBadMIMEType.keySet().toArray(new String[failedBadMIMEType.size()]);
			Arrays.sort(types);
			for(String type : types) {
				LinkedList<DownloadRequestStatus> getters = failedBadMIMEType.get(type);
				String atype = type.replace("-", "--").replace('/', '-');
				contentNode.addChild("a", "id", "failedDownload-badtype-"+atype);
				FilterMIMEType typeHandler = ContentFilter.getMIMEType(type);
				HTMLNode failedContent = pageMaker.getInfobox("failed_requests", l10n("failedDBadMIME", new String[]{ "size", "type" }, new String[]{ String.valueOf(getters.size()), type }), contentNode, "download-failed-"+atype, false);
				// FIXME add a class for easier styling.
				KnownUnsafeContentTypeException e = new KnownUnsafeContentTypeException(typeHandler);
				failedContent.addChild("p", l10n("badMIMETypeIntro", "type", type));
				List<String> detail = e.details();
				if(detail != null && !detail.isEmpty()) {
					HTMLNode list = failedContent.addChild("ul");
					for(String s : detail)
						list.addChild("li", s);
				}
				failedContent.addChild("p", l10n("mimeProblemFetchAnyway"));
				Collections.sort(getters, jobComparator);
				if (advancedModeEnabled) {
					failedContent.addChild(createRequestTable(ctx, getters, new QueueColumn[] { QueueColumn.IDENTIFIER, QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.PERSISTENCE, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "failed-download-file-badmime", type, QueueType.FailedBadMIMEType));
				} else {
					failedContent.addChild(createRequestTable(ctx, getters, new QueueColumn[] { QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "failed-download-file-badmime", type, QueueType.FailedBadMIMEType));
				}
			}
		}

		if(!failedUnknownMIMEType.isEmpty()) {
			String[] types = failedUnknownMIMEType.keySet().toArray(new String[failedUnknownMIMEType.size()]);
			Arrays.sort(types);
			for(String type : types) {
				LinkedList<DownloadRequestStatus> getters = failedUnknownMIMEType.get(type);
				String atype = type.replace("-", "--").replace('/', '-');
				contentNode.addChild("a", "id", "failedDownload-unknowntype-"+atype);
				HTMLNode failedContent = pageMaker.getInfobox("failed_requests", l10n("failedDUnknownMIME", new String[]{ "size", "type" }, new String[]{ String.valueOf(getters.size()), type }), contentNode, "download-failed-"+atype, false);
				// FIXME add a class for easier styling.
				failedContent.addChild("p", NodeL10n.getBase().getString("UnknownContentTypeException.explanation", "type", type));
				failedContent.addChild("p", l10n("mimeProblemFetchAnyway"));
				Collections.sort(getters, jobComparator);
				if (advancedModeEnabled) {
					failedContent.addChild(createRequestTable(ctx, getters, new QueueColumn[] { QueueColumn.IDENTIFIER, QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.PERSISTENCE, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "failed-download-file-unknownmime", type, QueueType.FailedUnknownMIMEType));
				} else {
					failedContent.addChild(createRequestTable(ctx, getters, new QueueColumn[] { QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "failed-download-file-unknownmime", type, QueueType.FailedUnknownMIMEType));
				}
			}

		}

		if (!uncompletedDownload.isEmpty()) {
			contentNode.addChild("a", "id", "uncompletedDownload");
			HTMLNode uncompletedContent = pageMaker.getInfobox("requests_in_progress", l10n("wipD", new String[]{ "size" }, new String[]{ String.valueOf(uncompletedDownload.size()) }), contentNode, "download-progressing", false);
			if (advancedModeEnabled) {
                uncompletedContent.addChild(
                    createRequestTable(
                        ctx, uncompletedDownload,
                        new QueueColumn[] {
                            QueueColumn.IDENTIFIER, QueueColumn.PRIORITY, QueueColumn.SIZE,
                            QueueColumn.MIME_TYPE, QueueColumn.PROGRESS, QueueColumn.LAST_ACTIVITY,
                            /* FIXME: This column has been disabled since it will always show
                             * "never" even if parts of the file transfer failed due to temporary
                             * reasons such as "data not found" / "route not found" / etc. This is
                             * due to shortcomings in the underlying event framework. Please
                             * re-enable it once the underlying issue is fixed:
                             * https://bugs.freenetproject.org/view.php?id=6526 */
                            // QueueColumn.LAST_FAILURE,
                            QueueColumn.PERSISTENCE, QueueColumn.FILENAME,
                            QueueColumn.KEY, QueueColumn.COMPAT_MODE },
                        priorityClasses, advancedModeEnabled, "uncompleted-download",
                        QueueType.UncompletedDownload)
                );
			} else {
				uncompletedContent.addChild(createRequestTable(ctx, uncompletedDownload, new QueueColumn[] { QueueColumn.PRIORITY, QueueColumn.SIZE, QueueColumn.PROGRESS, QueueColumn.LAST_ACTIVITY, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "uncompleted-download", QueueType.UncompletedDownload));
			}
		}

		if (!uncompletedUpload.isEmpty()) {
			contentNode.addChild("a", "id", "uncompletedUpload");
			HTMLNode uncompletedContent = pageMaker.getInfobox("requests_in_progress", l10n("wipU", new String[]{ "size" }, new String[]{ String.valueOf(uncompletedUpload.size()) }), contentNode, "upload-progressing", false);
			if (advancedModeEnabled) {
                uncompletedContent.addChild(
                    createRequestTable(
                        ctx, uncompletedUpload,
                        new QueueColumn[] {
                            QueueColumn.IDENTIFIER, QueueColumn.PRIORITY, QueueColumn.SIZE,
                            QueueColumn.MIME_TYPE, QueueColumn.PROGRESS, QueueColumn.LAST_ACTIVITY,
                            /* FIXME: This column has been disabled since it will always show
                             * "never" even if parts of the file transfer failed due to temporary
                             * reasons such as "data not found" / "route not found" / etc. This is
                             * due to shortcomings in the underlying event framework. Please
                             * re-enable it once the underlying issue is fixed:
                             * https://bugs.freenetproject.org/view.php?id=6526 */
                            // QueueColumn.LAST_FAILURE,
                            QueueColumn.PERSISTENCE, QueueColumn.FILENAME,
                            QueueColumn.KEY },
                        priorityClasses, advancedModeEnabled, "uncompleted-upload-file",
                        QueueType.UncompletedUpload)
                );
			} else {
				uncompletedContent.addChild(createRequestTable(ctx, uncompletedUpload, new QueueColumn[] { QueueColumn.PRIORITY, QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.PROGRESS, QueueColumn.LAST_ACTIVITY, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "uncompleted-upload-file", QueueType.UncompletedUpload));
			}
		}

		if (!uncompletedDirUpload.isEmpty()) {
			contentNode.addChild("a", "id", "uncompletedDirUpload");
			HTMLNode uncompletedContent = pageMaker.getInfobox("requests_in_progress", l10n("wipDU", new String[]{ "size" }, new String[]{ String.valueOf(uncompletedDirUpload.size()) }), contentNode, "download-progressing upload-progressing", false);
			if (advancedModeEnabled) {
                uncompletedContent.addChild(
                    createRequestTable(
                        ctx, uncompletedDirUpload,
                        new QueueColumn[] {
                            QueueColumn.IDENTIFIER, QueueColumn.FILES, QueueColumn.PRIORITY,
                            QueueColumn.TOTAL_SIZE, QueueColumn.PROGRESS, QueueColumn.LAST_ACTIVITY,
                            /* FIXME: This column has been disabled since it will always show
                             * "never" even if parts of the file transfer failed due to temporary
                             * reasons such as "data not found" / "route not found" / etc. This is
                             * due to shortcomings in the underlying event framework. Please
                             * re-enable it once the underlying issue is fixed:
                             * https://bugs.freenetproject.org/view.php?id=6526 */
                            // QueueColumn.LAST_FAILURE,
                            QueueColumn.PERSISTENCE, QueueColumn.KEY },
                        priorityClasses, advancedModeEnabled, "uncompleted-upload-dir",
                        QueueType.UncompletedDirUpload)
                );
			} else {
				uncompletedContent.addChild(createRequestTable(ctx, uncompletedDirUpload, new QueueColumn[] { QueueColumn.PRIORITY, QueueColumn.FILES, QueueColumn.TOTAL_SIZE, QueueColumn.PROGRESS, QueueColumn.LAST_ACTIVITY, QueueColumn.KEY }, priorityClasses, advancedModeEnabled, "uncompleted-upload-dir", QueueType.UncompletedDirUpload));
			}
		}

		if(!uploads) {
			contentNode.addChild(createBulkDownloadForm(ctx, pageMaker));
		}

		return pageNode;
	}

	private HTMLNode sendEmptyQueuePage(ToadletContext ctx, PageMaker pageMaker) {
        PageNode page = pageMaker.getPageNode(l10n("title"+(uploads?"Uploads":"Downloads")), ctx);
        HTMLNode pageNode = page.outer;
        HTMLNode contentNode = page.content;
        /* add alert summary box */
        if(ctx.isAllowedFullAccess())
            contentNode.addChild(ctx.getAlertManager().createSummary());
        HTMLNode infoboxContent = pageMaker.getInfobox("infobox-information", l10n("globalQueueIsEmpty"), contentNode, "queue-empty", true);
        infoboxContent.addChild("#", l10n("noTaskOnGlobalQueue"));
        if(!uploads)
            contentNode.addChild(createBulkDownloadForm(ctx, pageMaker));
        return pageNode;
    }

    private HTMLNode createReasonCell(String failureReason) {
		HTMLNode reasonCell = new HTMLNode("td", "class", "request-reason");
		if (failureReason == null) {
			reasonCell.addChild("span", "class", "failure_reason_unknown", l10n("unknown"));
		} else {
			reasonCell.addChild("span", "class", "failure_reason_is", failureReason);
		}
		return reasonCell;
	}

	public static HTMLNode createProgressCell(boolean advancedMode, boolean started, COMPRESS_STATE compressing, int fetched, int failed, int fatallyFailed, int min, int total, boolean finalized, boolean upload) {
		HTMLNode progressCell = new HTMLNode("td", "class", "request-progress");
		if (!started) {
			progressCell.addChild("#", l10n("starting"));
			return progressCell;
		}
		if(compressing == COMPRESS_STATE.WAITING && advancedMode) {
			progressCell.addChild("#", l10n("awaitingCompression"));
			return progressCell;
		}
		if(compressing != COMPRESS_STATE.WORKING) {
			progressCell.addChild("#", l10n("compressing"));
			return progressCell;
		}

		//double frac = p.getSuccessFraction();
		if (!advancedMode || total < min /* FIXME why? */) {
			total = min;
		}

		if ((fetched < 0) || (total <= 0)) {
			progressCell.addChild("span", "class", "progress_fraction_unknown", l10n("unknown"));
		} else {
			int fetchedPercent = (int) (fetched / (double) total * 100);
			int failedPercent = (int) (failed / (double) total * 100);
			int fatallyFailedPercent = (int) (fatallyFailed / (double) total * 100);
			int minPercent = (int) (min / (double) total * 100);
			HTMLNode progressBar = progressCell.addChild("div", "class", "progressbar");
			progressBar.addChild("div", new String[] { "class", "style" }, new String[] { "progressbar-done", "width: " + fetchedPercent + "%;" });

			if (failed > 0)
				progressBar.addChild("div", new String[] { "class", "style" }, new String[] { "progressbar-failed", "width: " + failedPercent + "%;" });
			if (fatallyFailed > 0)
				progressBar.addChild("div", new String[] { "class", "style" }, new String[] { "progressbar-failed2", "width: " + fatallyFailedPercent + "%;" });
			if ((fetched + failed + fatallyFailed) < min)
				progressBar.addChild("div", new String[] { "class", "style" }, new String[] { "progressbar-min", "width: " + (minPercent - fetchedPercent) + "%;" });

			NumberFormat nf = NumberFormat.getInstance();
			nf.setMaximumFractionDigits(1);
			String prefix = '('+Integer.toString(fetched) + "/ " + Integer.toString(min)+"): ";
			if (finalized) {
				progressBar.addChild("div", new String[] { "class", "title" }, new String[] { "progress_fraction_finalized", prefix + l10n("progressbarAccurate") }, nf.format((int) ((fetched / (double) min) * 1000) / 10.0) + '%');
			} else {
				String text = nf.format((int) ((fetched / (double) min) * 1000) / 10.0)+ '%';
				if(!finalized)
					text = "" + fetched + " ("+text+"??)";
				progressBar.addChild("div", new String[] { "class", "title" }, new String[] { "progress_fraction_not_finalized", prefix + NodeL10n.getBase().getString(upload ? "QueueToadlet.uploadProgressbarNotAccurate" : "QueueToadlet.progressbarNotAccurate") }, text);
			}
		}
		return progressCell;
	}

	private HTMLNode createNumberCell(int numberOfFiles) {
		HTMLNode numberCell = new HTMLNode("td", "class", "request-files");
		numberCell.addChild("span", "class", "number_of_files", String.valueOf(numberOfFiles));
		return numberCell;
	}

	private HTMLNode createFilenameCell(File filename) {
		HTMLNode filenameCell = new HTMLNode("td", "class", "request-filename");
		if (filename != null) {
			filenameCell.addChild("span", "class", "filename_is", filename.toString());
		} else {
			filenameCell.addChild("span", "class", "filename_none", l10n("none"));
		}
		return filenameCell;
	}

	private HTMLNode createPriorityCell(short priorityClass, String[] priorityClasses) {
		HTMLNode priorityCell = new HTMLNode("td", "class", "request-priority");
		if(priorityClass < 0 || priorityClass >= priorityClasses.length) {
			priorityCell.addChild("span", "class", "priority_unknown", l10n("unknown"));
		} else {
			priorityCell.addChild("span", "class", "priority_is", priorityClasses[priorityClass]);
		}
		return priorityCell;
	}

	private HTMLNode createPriorityControl(short priorityClass, String[] priorityClasses, boolean advancedModeEnabled, boolean isUpload, String controlSuffix) {
		HTMLNode priorityDiv = new HTMLNode("div", "class", "request-priority nowrap");
		priorityDiv.addChild("input", new String[] { "type", "name", "value" }, new String[] { "submit", "change_priority" + controlSuffix, NodeL10n.getBase().getString(isUpload ? "QueueToadlet.changeUploadPriorities" : "QueueToadlet.changeDownloadPriorities") });
		HTMLNode prioritySelect = priorityDiv.addChild("select", "name", "priority"+controlSuffix);
		for (int p = 0; p < RequestStarter.NUMBER_OF_PRIORITY_CLASSES; p++) {
			if(p <= RequestStarter.INTERACTIVE_PRIORITY_CLASS && !advancedModeEnabled) continue;
			if (p == priorityClass) {
				prioritySelect.addChild("option", new String[] { "value", "selected" }, new String[] { String.valueOf(p), "selected" }, priorityClasses[p]);
			} else {
				prioritySelect.addChild("option", "value", String.valueOf(p), priorityClasses[p]);
			}
		}
		return priorityDiv;
	}
	
	private HTMLNode createRecommendControl() {
		HTMLNode recommendDiv = new HTMLNode("div", "class", "request-recommend");
		recommendDiv.addChild("input", new String[] { "type", "name", "value" }, new String[] { "submit", "recommend_request", l10n("recommendFilesToFriends") });
		return recommendDiv;
	}

	/** Create a delete or restart control at the top of a table. It applies to whichever requests are checked in the table below. */
	private HTMLNode createDeleteControl(String mimeType, QueueType queueType) {
		HTMLNode deleteDiv = new HTMLNode("div", "class", "request-delete");
		if (queueType == QueueType.CompletedDownloadToTemp) {
			deleteDiv.addChild("input", new String[] { "type", "name", "value" }, new String[] { "submit", "delete_request", l10n("deleteFilesFromTemp") });
		} else if (!queueType.isCompleted) {
			deleteDiv.addChild("input", new String[] { "type", "name", "value" }, new String[] { "submit", "remove_request", l10n("cancelSelected") });
		} else {
			deleteDiv.addChild("input", new String[] { "type", "name", "value" }, new String[] { "submit", "remove_request", l10n("removeFilesFromList") });
		}
		if (queueType == QueueType.CompletedDownloadToDisk) {
			deleteDiv.addChild("input", new String[] { "type", "name", "value" }, new String[] { "submit", "remove_finished_downloads_request", l10n("removeFinishedDownloads") });
		}
		if (queueType == QueueType.CompletedUpload) {
			deleteDiv.addChild("input", new String[] { "type", "name", "value" }, new String[] { "submit", "remove_finished_uploads_request", l10n("removeFinishedUploads") });
		}
		if (queueType.isFailed) {
			String restartName = NodeL10n.getBase().getString("QueueToadlet.restartSelected");
			deleteDiv.addChild("input", new String[] { "type", "name", "value" }, new String[] { "submit", "restart_request", restartName });
			if(mimeType != null) {
				HTMLNode input = deleteDiv.addChild("input", new String[] { "type", "name", "value" }, new String[] {"checkbox", "disableFilterData", "disableFilterData" });
				deleteDiv.addChild("#", l10n("disableFilter", "type", mimeType));
			}
		}
		return deleteDiv;
	}

	private HTMLNode createPanicBox(PageMaker pageMaker, ToadletContext ctx) {
		InfoboxNode infobox = pageMaker.getInfobox("infobox-alert", l10n("panicButtonTitle"), "panic-button", true);
		HTMLNode panicBox = infobox.outer;
		HTMLNode panicForm = ctx.addFormChild(infobox.content, path(), "queuePanicForm");
		panicForm.addChild("#", (SimpleToadletServer.noConfirmPanic ? l10n("panicButtonNoConfirmation") : l10n("panicButtonWithConfirmation")) + ' ');
		panicForm.addChild("input", new String[] { "type", "name", "value" }, new String[] { "submit", "panic", l10n("panicButton") });
		return panicBox;
	}

	private HTMLNode createIdentifierCell(FreenetURI uri, String identifier, boolean directory) {
		HTMLNode identifierCell = new HTMLNode("td", "class", "request-identifier");
		if (uri != null) {
			identifierCell.addChild("span", "class", "identifier_with_uri").addChild("a", "href", "/" + uri + (directory ? "/" : ""), identifier);
		} else {
			identifierCell.addChild("span", "class", "identifier_without_uri", identifier);
		}
		return identifierCell;
	}

	private HTMLNode createPersistenceCell(boolean persistent, boolean persistentForever) {
		HTMLNode persistenceCell = new HTMLNode("td", "class", "request-persistence");
		if (persistentForever) {
			persistenceCell.addChild("span", "class", "persistence_forever", l10n("persistenceForever"));
		} else if (persistent) {
			persistenceCell.addChild("span", "class", "persistence_reboot", l10n("persistenceReboot"));
		} else {
			persistenceCell.addChild("span", "class", "persistence_none", l10n("persistenceNone"));
		}
		return persistenceCell;
	}

	private HTMLNode createTypeCell(String type) {
		HTMLNode typeCell = new HTMLNode("td", "class", "request-type");
		if (type != null) {
			typeCell.addChild("span", "class", "mimetype_is", type);
		} else {
			typeCell.addChild("span", "class", "mimetype_unknown", l10n("unknown"));
		}
		return typeCell;
	}

	private HTMLNode createSizeCell(long dataSize, boolean confirmed, boolean advancedModeEnabled) {
		HTMLNode sizeCell = new HTMLNode("td", "class", "request-size");
		if (dataSize > 0 && (confirmed || advancedModeEnabled)) {
			sizeCell.addChild("span", "class", "filesize_is", (confirmed ? "" : ">= ") + SizeUtil.formatSize(dataSize) + (confirmed ? "" : " ??"));
		} else {
			sizeCell.addChild("span", "class", "filesize_unknown", l10n("unknown"));
		}
		return sizeCell;
	}

	private HTMLNode createKeyCell(FreenetURI uri, boolean addSlash) {
		HTMLNode keyCell = new HTMLNode("td", "class", "request-key");
		if (uri != null) {
			keyCell.addChild("span", "class", "key_is").addChild("a", "href", '/' + uri.toString() + (addSlash ? "/" : ""), uri.toShortString() + (addSlash ? "/" : ""));
		} else {
			keyCell.addChild("span", "class", "key_unknown", l10n("unknown"));
		}
		return keyCell;
	}

	private HTMLNode createBulkDownloadForm(ToadletContext ctx, PageMaker pageMaker) {
		InfoboxNode infobox = pageMaker.getInfobox(
		        l10n("downloadFiles"), "grouped-downloads", true);
		HTMLNode downloadBox = infobox.outer;
		HTMLNode downloadBoxContent = infobox.content;
		HTMLNode downloadForm = ctx.addFormChild(downloadBoxContent, path(), "queueDownloadForm");
		downloadForm.addChild("#", l10n("downloadFilesInstructions"));
		downloadForm.addChild("br");
		downloadForm.addChild("textarea",
		        new String[] { "id", "name", "cols", "rows" },
		        new String[] { "bulkDownloads", "bulkDownloads", "120", "8" });
		downloadForm.addChild("br");
		PHYSICAL_THREAT_LEVEL threatLevel = core.node.securityLevels.getPhysicalThreatLevel();
		//Force downloading to encrypted space if high/maximum threat level or if the user has disabled
		//downloading to disk.
		if(threatLevel == PHYSICAL_THREAT_LEVEL.HIGH || threatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM ||
		        core.isDownloadDisabled()) {
			downloadForm.addChild("input",
			        new String[] { "type", "name", "value" },
			        new String[] { "hidden", "target", "direct" });
		} else if(threatLevel == PHYSICAL_THREAT_LEVEL.LOW) {
			downloadForm.addChild("input",
			        new String[] { "type", "name", "value" },
			        new String[] { "hidden", "target", "disk" });
			selectLocation(downloadForm);
		} else {
			downloadForm.addChild("br");
			downloadForm.addChild("input",
			        new String[] { "type", "value", "name" },
			        new String[] { "radio", "disk", "target" },
					//Nicer spacing for radio button
			        ' '+l10n("bulkDownloadSelectOptionDisk")+' ');
			selectLocation(downloadForm);
			downloadForm.addChild("br");
			downloadForm.addChild("input",
			        new String[] { "type", "value", "name", "checked" },
			        new String[] { "radio", "direct", "target", "checked" },
			        ' '+l10n("bulkDownloadSelectOptionDirect")+' ');
		}
		HTMLNode filterControl = downloadForm.addChild("div", l10n("filterData"));
		filterControl.addChild("input",
		        new String[] { "type", "name", "value", "checked" },
		        new String[] { "checkbox", "filterData", "filterData", "checked"});
		filterControl.addChild("#", l10n("filterDataMessage"));
		downloadForm.addChild("br");
		downloadForm.addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "submit", "insert", l10n("download") });
		return downloadBox;
	}

	private void selectLocation(HTMLNode node) {
		String downloadLocation = core.getDownloadsDir().getAbsolutePath();
		//If the download directory isn't allowed, yet downloading is, at least one directory must
		//have been explicitly defined, so take the first one.
		if (!core.allowDownloadTo(core.getDownloadsDir())) {
			downloadLocation = core.getAllowedDownloadDirs()[0].getAbsolutePath();
		}
		node.addChild("input",
		        new String[] { "type", "name", "value", "maxlength", "size" },
		        new String[] { "text", "path", downloadLocation, Integer.toString(MAX_FILENAME_LENGTH),
		                String.valueOf(downloadLocation.length())});
		node.addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "submit", "select-location", l10n("browseToChange")+"..." });
	}

	/**
	 * Creates a table cell that contains the time of the last activity, as per
	 * {@link TimeUtil#formatTime(long)}.
	 *
	 * @param now
	 *            The current time (for a unified point of reference for the
	 *            whole page)
	 * @param lastActivity
	 *            The last activity of the request
	 * @return The created table cell HTML node
	 */
	private HTMLNode createLastActivityCell(long now, Date lastActivity) {
		HTMLNode lastActivityCell = new HTMLNode("td", "class", "request-last-activity");
		if (lastActivity == null) {
            // During normal operation, lastActivity will never be null even if there was no
            // activity yet. It will default to the Date when the request was added. (See
            // ClientRequester.getLatestSuccess() for the usability motivation behind that.)
            // lastActivity can however be null if the user had been using a pre-release of
            // purge-db4o which did not store the lastActivity Date to the database yet.
            // Thus, we initialize to "unknown" instead of "never" to stress that there was possibly
            // activity but we cannot know because the Date was not stored yet.
			lastActivityCell.addChild("i", l10n("lastActivity.unknown"));
		} else {
            lastActivityCell.addChild("#", l10n("lastActivity.ago", "time",
                TimeUtil.formatTime(now - lastActivity.getTime())));
		}
		return lastActivityCell;
	}
	
    /** @see #createLastActivityCell(long, Date) */
    private HTMLNode createLastFailureCell(long now, Date lastFailure) {
        HTMLNode lastFailureCell = new HTMLNode("td", "class", "request-last-failure");
        if (lastFailure == null) {
            // This is "never"  instead of "unknown" because the backend of RequestStatus uses null
            // to signalize that no failure has happened yet.
            lastFailureCell.addChild("i", l10n("lastFailure.never"));
        } else {
            lastFailureCell.addChild("#", l10n("lastFailure.ago", "time",
                TimeUtil.formatTime(now - lastFailure.getTime())));
        }
        return lastFailureCell;
    }

	private HTMLNode createRequestTable(ToadletContext ctx, List<? extends RequestStatus> requests, QueueColumn[] columns, String[] priorityClasses, boolean advancedModeEnabled, String id, QueueType queueType) {
		return createRequestTable(ctx, requests, columns, priorityClasses, advancedModeEnabled, id, null, queueType);
	}
	
	private HTMLNode createRequestTable(ToadletContext ctx, List<? extends RequestStatus> requests, QueueColumn[] columns, String[] priorityClasses, boolean advancedModeEnabled, String id, String mimeType, QueueType queueType) {
		boolean hasFriends = core.node.getDarknetConnections().length > 0;
		long now = System.currentTimeMillis();
		
		HTMLNode formDiv = new HTMLNode("div", "class", "request-table-form");
		HTMLNode form = ctx.addFormChild(formDiv, path(), "request-table-form-"+id+(advancedModeEnabled?"-advanced":"-simple"));
		
		createRequestTableButtons(form, mimeType, hasFriends, advancedModeEnabled, priorityClasses, true, queueType);

		HTMLNode table = form.addChild("table", "class", "requests");
		HTMLNode headerRow = table.addChild("tr", "class", "table-header");

		// Checkbox header
		headerRow.addChild("th"); // No description

		//Add a header for each column.
		for (QueueColumn column : columns) {
			switch (column) {
				case IDENTIFIER:
					headerRow.addChild("th").addChild("a", "href", (isReversed ? "?sortBy=id" : "?sortBy=id&reversed")).addChild("#", l10n("identifier"));
					break;
				case SIZE:
					headerRow.addChild("th").addChild("a", "href", (isReversed ? "?sortBy=size" : "?sortBy=size&reversed")).addChild("#", l10n("size"));
					break;
				case MIME_TYPE:
					headerRow.addChild("th", l10n("mimeType"));
					break;
				case PERSISTENCE:
					headerRow.addChild("th", l10n("persistence"));
					break;
				case KEY:
					headerRow.addChild("th", l10n("key"));
					break;
				case FILENAME:
					headerRow.addChild("th", l10n("fileName"));
					break;
				case PRIORITY:
					headerRow.addChild("th", l10n("priority"));
					break;
				case FILES:
					headerRow.addChild("th", l10n("files"));
					break;
				case TOTAL_SIZE:
					headerRow.addChild("th", l10n("totalSize"));
					break;
				case PROGRESS:
					headerRow.addChild("th").addChild("a", "href", (isReversed ? "?sortBy=progress" : "?sortBy=progress&reversed")).addChild("#", l10n("progress"));
					break;
				case REASON:
					headerRow.addChild("th", l10n("reason"));
					break;
				case LAST_ACTIVITY:
					headerRow.addChild("th").addChild("a", "href", (isReversed ? "?sortBy=lastActivity" : "?sortBy=lastActivity&reversed"),  l10n("lastActivity"));
					break;
                case LAST_FAILURE:
                    headerRow.addChild("th").addChild("a", "href",
                            (isReversed ? "?sortBy=lastFailure" : "?sortBy=lastFailure&reversed"),
                            l10n("lastFailure"));
                    break;
				case COMPAT_MODE:
					headerRow.addChild("th", l10n("compatibilityMode"));
					break;
			}
		}
		//Add a row with a checkbox for each request.
		int x = 0;
		for (RequestStatus clientRequest : requests) {
			HTMLNode requestRow = table.addChild("tr", "class", "priority" + clientRequest.getPriority());
			requestRow.addChild(createCheckboxCell(clientRequest, x++));

			for (QueueColumn column : columns) {
				switch (column) {
					case IDENTIFIER:
						requestRow.addChild(createIdentifierCell(clientRequest.getURI(), clientRequest.getIdentifier(), clientRequest instanceof UploadDirRequestStatus));
						break;
					case SIZE:
						boolean isFinal = true;
						if(clientRequest instanceof DownloadRequestStatus)
							isFinal = ((DownloadRequestStatus)clientRequest).isTotalFinalized();
						requestRow.addChild(createSizeCell(clientRequest.getDataSize(), isFinal, advancedModeEnabled));
						break;
					case MIME_TYPE:
						if (clientRequest instanceof DownloadRequestStatus) {
							requestRow.addChild(createTypeCell(((DownloadRequestStatus) clientRequest).getMIMEType()));
						} else if (clientRequest instanceof UploadFileRequestStatus) {
							requestRow.addChild(createTypeCell(((UploadFileRequestStatus) clientRequest).getMIMEType()));
						}
						break;
					case PERSISTENCE:
						requestRow.addChild(createPersistenceCell(clientRequest.isPersistent(), clientRequest.isPersistentForever()));
						break;
					case KEY:
						if (clientRequest instanceof DownloadRequestStatus) {
							requestRow.addChild(createKeyCell(((DownloadRequestStatus) clientRequest).getURI(), false));
						} else if (clientRequest instanceof UploadFileRequestStatus) {
							requestRow.addChild(createKeyCell(((UploadFileRequestStatus) clientRequest).getFinalURI(), false));
						}else {
							requestRow.addChild(createKeyCell(((UploadDirRequestStatus) clientRequest).getFinalURI(), true));
						}
						break;
					case FILENAME:
						if (clientRequest instanceof DownloadRequestStatus) {
							requestRow.addChild(createFilenameCell(((DownloadRequestStatus) clientRequest).getDestFilename()));
						} else if (clientRequest instanceof UploadFileRequestStatus) {
							requestRow.addChild(createFilenameCell(((UploadFileRequestStatus) clientRequest).getOrigFilename()));
						}
						break;
					case PRIORITY:
						requestRow.addChild(createPriorityCell(clientRequest.getPriority(), priorityClasses));
						break;
					case FILES:
						requestRow.addChild(createNumberCell(((UploadDirRequestStatus) clientRequest).getNumberOfFiles()));
						break;
					case TOTAL_SIZE:
						requestRow.addChild(createSizeCell(((UploadDirRequestStatus) clientRequest).getTotalDataSize(), true, advancedModeEnabled));
						break;
					case PROGRESS:
						if(clientRequest instanceof UploadFileRequestStatus)
							requestRow.addChild(createProgressCell(ctx.isAdvancedModeEnabled(),
									clientRequest.isStarted(), ((UploadFileRequestStatus)clientRequest).isCompressing(),
									clientRequest.getFetchedBlocks(), clientRequest.getFailedBlocks(),
									clientRequest.getFatalyFailedBlocks(), clientRequest.getMinBlocks(),
									clientRequest.getTotalBlocks(),
									clientRequest.isTotalFinalized() || clientRequest instanceof UploadFileRequestStatus,
									queueType.isUpload));
						else
							requestRow.addChild(createProgressCell(ctx.isAdvancedModeEnabled(),
									clientRequest.isStarted(), COMPRESS_STATE.WORKING,
									clientRequest.getFetchedBlocks(), clientRequest.getFailedBlocks(),
									clientRequest.getFatalyFailedBlocks(), clientRequest.getMinBlocks(),
									clientRequest.getTotalBlocks(),
									clientRequest.isTotalFinalized() || clientRequest instanceof UploadFileRequestStatus,
									queueType.isUpload));
						break;
					case REASON:
						requestRow.addChild(createReasonCell(clientRequest.getFailureReason(false)));
						break;
					case LAST_ACTIVITY:
						requestRow.addChild(createLastActivityCell(now, clientRequest.getLastSuccess()));
						break;
                    case LAST_FAILURE:
                        requestRow.addChild(createLastFailureCell(now,
                                clientRequest.getLastFailure()));
                        break;
					case COMPAT_MODE:
						if(clientRequest instanceof DownloadRequestStatus) {
							requestRow.addChild(createCompatModeCell((DownloadRequestStatus)clientRequest));
						} else {
							requestRow.addChild("td");
						}
						break;
				}
			}
		}
		createRequestTableButtons(form, mimeType, hasFriends, advancedModeEnabled, priorityClasses, false, queueType);
		return formDiv;
	}

	private void createRequestTableButtons(HTMLNode form, String mimeType, boolean hasFriends,
		   boolean advancedModeEnabled, String[] priorityClasses, boolean top, QueueType queueType) {
		form.addChild(createDeleteControl(mimeType, queueType));
		if (hasFriends && !(queueType.isUpload && queueType.isFailed)) {
			form.addChild(createRecommendControl());
		}
		if (!(queueType.isFailed || queueType.isCompleted)) {
			form.addChild(createPriorityControl(RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS, priorityClasses, advancedModeEnabled, queueType.isUpload, top ? "_top" : "_bottom"));
		}
	}

	private HTMLNode createCheckboxCell(RequestStatus clientRequest, int counter) {
		HTMLNode cell = new HTMLNode("td", "class", "checkbox-cell");
		String identifier = clientRequest.getIdentifier();
		cell.addChild("input", new String[] { "type", "name", "value" },
				new String[] { "checkbox", "identifier-"+counter, identifier } );
		FreenetURI uri;
		long size = -1;
		String filename = null;
		if(clientRequest instanceof DownloadRequestStatus) {
			uri = clientRequest.getURI();
			size = clientRequest.getDataSize();
		} else if(clientRequest instanceof UploadRequestStatus) {
			uri = ((UploadRequestStatus)clientRequest).getFinalURI();
			size = clientRequest.getDataSize();
		} else {
			uri = null;
		}
		if(uri != null) {
			cell.addChild("input", new String[] { "type", "name", "value" },
					new String[] { "hidden", "key-"+counter, uri.toASCIIString() });
		}
		filename = clientRequest.getPreferredFilenameSafe();
		if(size != -1)
			cell.addChild("input", new String[] { "type", "name", "value" },
					new String[] { "hidden", "size-"+counter, Long.toString(size) });
		if(filename != null)
			cell.addChild("input", new String[] { "type", "name", "value" },
					new String[] { "hidden", "filename-"+counter, filename });
		return cell;
	}

	private HTMLNode createCompatModeCell(DownloadRequestStatus get) {
		HTMLNode compatCell = new HTMLNode("td", "class", "request-compat-mode");
		InsertContext.CompatibilityMode[] compat = get.getCompatibilityMode();
		if(!(compat[0] == InsertContext.CompatibilityMode.COMPAT_UNKNOWN && compat[1] == InsertContext.CompatibilityMode.COMPAT_UNKNOWN)) {
			if(compat[0] == compat[1])
				compatCell.addChild("#", NodeL10n.getBase().getString("InsertContext.CompatibilityMode."+compat[0].name())); // FIXME l10n
			else
				compatCell.addChild("#", NodeL10n.getBase().getString("InsertContext.CompatibilityMode."+compat[0].name())+" - "+NodeL10n.getBase().getString("InsertContext.CompatibilityMode."+compat[1].name())); // FIXME l10n
			byte[] overrideCryptoKey = get.getOverriddenSplitfileCryptoKey();
			if(overrideCryptoKey != null)
				compatCell.addChild("#", " - "+l10n("overriddenCryptoKeyInCompatCell")+": "+HexUtil.bytesToHex(overrideCryptoKey));
			if(get.detectedDontCompress())
				compatCell.addChild("#", " ("+l10n("dontCompressInCompatCell")+")");
		}
		return compatCell;
	}

	/**
	 * List of completed request identifiers which the user hasn't acknowledged yet.
	 */
	private final HashSet<String> completedRequestIdentifiers = new HashSet<String>();

	private final Map<String, GetCompletedEvent> completedGets = new LinkedHashMap<String, GetCompletedEvent>();
	private final Map<String, PutCompletedEvent> completedPuts = new LinkedHashMap<String, PutCompletedEvent>();
	private final Map<String, PutDirCompletedEvent> completedPutDirs = new LinkedHashMap<String, PutDirCompletedEvent>();

	@Override
	public void notifyFailure(ClientRequest req) {
		// FIXME do something???
	}

	@Override
	public void notifySuccess(ClientRequest req) {
		if(uploads == req instanceof ClientGet) return;
		synchronized(completedRequestIdentifiers) {
			completedRequestIdentifiers.add(req.getIdentifier());
		}
		registerAlert(req); // should be safe here
		saveCompletedIdentifiersOffThread();
	}

	private void saveCompletedIdentifiersOffThread() {
		core.getExecutor().execute(new Runnable() {
			@Override
			public void run() {
				saveCompletedIdentifiers();
			}
		}, "Save completed identifiers");
	}

	private void loadCompletedIdentifiers() throws PersistenceDisabledException {
		String dl = uploads ? "uploads" : "downloads";
		File completedIdentifiersList = core.node.userDir().file("completed.list."+dl);
		File completedIdentifiersListNew = core.node.userDir().file("completed.list."+dl+".bak");
		File oldCompletedIdentifiersList = core.node.userDir().file("completed.list");
		boolean migrated = false;
		if(!readCompletedIdentifiers(completedIdentifiersList)) {
			if(!readCompletedIdentifiers(completedIdentifiersListNew)) {
				readCompletedIdentifiers(oldCompletedIdentifiersList);
				migrated = true;
			}
		} else
			oldCompletedIdentifiersList.delete();
		final boolean writeAnyway = migrated;
		core.clientContext.jobRunner.queue(new PersistentJob() {

			@Override
			public String toString() {
				return "QueueToadlet LoadCompletedIdentifiers";
			}

			@Override
			public boolean run(ClientContext context) {
				String[] identifiers;
				boolean changed = writeAnyway;
				synchronized(completedRequestIdentifiers) {
					identifiers = completedRequestIdentifiers.toArray(new String[completedRequestIdentifiers.size()]);
				}
				for(String identifier: identifiers) {
					ClientRequest req = fcp.getGlobalRequest(identifier);
					if(req == null || req instanceof ClientGet == uploads) {
						synchronized(completedRequestIdentifiers) {
							completedRequestIdentifiers.remove(identifier);
						}
						changed = true;
						continue;
					}
					registerAlert(req);
				}
				if(changed) saveCompletedIdentifiers();
				return false;
			}

		}, NativeThread.HIGH_PRIORITY);
	}

	private boolean readCompletedIdentifiers(File file) {
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
			BufferedInputStream bis = new BufferedInputStream(fis);
			InputStreamReader isr = new InputStreamReader(bis, "UTF-8");
			BufferedReader br = new BufferedReader(isr);
			synchronized(completedRequestIdentifiers) {
				completedRequestIdentifiers.clear();
				while(true) {
					String identifier = br.readLine();
					if(identifier == null) return true;
					completedRequestIdentifiers.add(identifier);
				}
			}
		} catch (EOFException e) {
			// Normal
			return true;
		} catch (FileNotFoundException e) {
			// Normal
			return false;
		} catch (UnsupportedEncodingException e) {
			throw new Error("Impossible: JVM doesn't support UTF-8: " + e, e);
		} catch (IOException e) {
			Logger.error(this, "Could not read completed identifiers list from "+file);
			return false;
		} finally {
			Closer.close(fis);
		}
	}

	private void saveCompletedIdentifiers() {
		FileOutputStream fos = null;
		BufferedWriter bw = null;
		String dl = uploads ? "uploads" : "downloads";
		File completedIdentifiersList = core.node.userDir().file("completed.list."+dl);
		File completedIdentifiersListNew = core.node.userDir().file("completed.list."+dl+".bak");
		File temp;
		try {
			temp = File.createTempFile("completed.list", ".tmp", core.node.getUserDir());
			temp.deleteOnExit();
			fos = new FileOutputStream(temp);
			OutputStreamWriter osw = new OutputStreamWriter(fos, "UTF-8");
			bw = new BufferedWriter(osw);
			String[] identifiers;
			synchronized(completedRequestIdentifiers) {
				identifiers = completedRequestIdentifiers.toArray(new String[completedRequestIdentifiers.size()]);
			}
			for(String identifier: identifiers)
				bw.write(identifier+'\n');
		} catch (FileNotFoundException e) {
			Logger.error(this, "Unable to save completed requests list (can't find node directory?!!?): "+e, e);
			return;
		} catch (IOException e) {
			Logger.error(this, "Unable to save completed requests list: "+e, e);
			return;
		} finally {
			if(bw != null) {
				try {
					bw.close();
				} catch (IOException e) {
					try {
						fos.close();
					} catch (IOException e1) {
						// Ignore
					}
				}
			} else {
				try {
					fos.close();
				} catch (IOException e1) {
					// Ignore
				}
			}
		}
		completedIdentifiersListNew.delete();
		temp.renameTo(completedIdentifiersListNew);
		if(!completedIdentifiersListNew.renameTo(completedIdentifiersList)) {
			completedIdentifiersList.delete();
			if(!completedIdentifiersListNew.renameTo(completedIdentifiersList)) {
				Logger.error(this, "Unable to store completed identifiers list because unable to rename "+completedIdentifiersListNew+" to "+completedIdentifiersList);
			}
		}
	}

	private void registerAlert(ClientRequest req) {
		final String identifier = req.getIdentifier();
		if(logMINOR)
			Logger.minor(this, "Registering alert for "+identifier);
		if(!req.hasFinished()) {
			if(logMINOR)
				Logger.minor(this, "Request hasn't finished: "+req+" for "+identifier, new Exception("debug"));
			return;
		}
		if(req instanceof ClientGet) {
			FreenetURI uri = ((ClientGet)req).getURI();
			if(uri == null) {
				Logger.error(this, "No URI for supposedly finished request "+req);
				return;
			}
			long size = ((ClientGet)req).getDataSize();
			GetCompletedEvent event = new GetCompletedEvent(identifier, uri, size);
			synchronized(completedGets) {
				completedGets.put(identifier, event);
			}
			core.alerts.register(event);
		} else if(req instanceof ClientPut) {
			FreenetURI uri = ((ClientPut)req).getFinalURI();
			if(uri == null) {
				Logger.error(this, "No URI for supposedly finished request "+req);
				return;
			}
			long size = ((ClientPut)req).getDataSize();
			PutCompletedEvent event = new PutCompletedEvent(identifier, uri, size);
			synchronized(completedPuts) {
				completedPuts.put(identifier, event);
			}
			core.alerts.register(event);
		} else if(req instanceof ClientPutDir) {
			FreenetURI uri = ((ClientPutDir)req).getFinalURI();
			if(uri == null) {
				Logger.error(this, "No URI for supposedly finished request "+req);
				return;
			}
			long size = ((ClientPutDir)req).getTotalDataSize();
			int files = ((ClientPutDir)req).getNumberOfFiles();
			PutDirCompletedEvent event = new PutDirCompletedEvent(identifier, uri, size, files);
			synchronized(completedPutDirs) {
				completedPutDirs.put(identifier, event);
			}
			core.alerts.register(event);
		}
	}

	static String l10n(String key) {
		return NodeL10n.getBase().getString("QueueToadlet."+key);
	}

	static String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("QueueToadlet."+key, pattern, value);
	}

	static String l10n(String key, String[] pattern, String[] value) {
		return NodeL10n.getBase().getString("QueueToadlet."+key, pattern, value);
	}

	@Override
	public void onRemove(ClientRequest req) {
		String identifier = req.getIdentifier();
		synchronized(completedRequestIdentifiers) {
			completedRequestIdentifiers.remove(identifier);
		}
		if(req instanceof ClientGet)
			synchronized(completedGets) {
				completedGets.remove(identifier);
			}
		else if(req instanceof ClientPut)
			synchronized(completedPuts) {
				completedPuts.remove(identifier);
			}
		else if(req instanceof ClientPutDir)
			synchronized(completedPutDirs) {
				completedPutDirs.remove(identifier);
			}
		saveCompletedIdentifiersOffThread();
	}

	@Override
	public boolean isEnabled(ToadletContext ctx) {
		return (!container.publicGatewayMode()) || ((ctx != null) && ctx.isAllowedFullAccess());
	}

	static final String PATH_UPLOADS = "/uploads/";
	static final String PATH_DOWNLOADS = "/downloads/";
	
	static final HTMLNode DOWNLOADS_LINK = 
		HTMLNode.link(PATH_DOWNLOADS).setReadOnly();
	static final HTMLNode UPLOADS_LINK =
		HTMLNode.link(PATH_UPLOADS).setReadOnly();

	@Override
	public String path() {
		if(uploads)
			return PATH_UPLOADS;
		else
			return PATH_DOWNLOADS;
	}

	private class GetCompletedEvent extends StoringUserEvent<GetCompletedEvent> {

		private final String identifier;
		private final FreenetURI uri;
		private final long size;

		public GetCompletedEvent(String identifier, FreenetURI uri, long size) {
			super(Type.GetCompleted, true, null, null, null, null, UserAlert.MINOR, true, NodeL10n.getBase().getString("UserAlert.hide"), true, null, completedGets);
			this.identifier = identifier;
			this.uri = uri;
			this.size = size;
		}

		@Override
		public void onDismiss() {
			super.onDismiss();
			saveCompletedIdentifiersOffThread();
		}

		@Override
		public void onEventDismiss() {
			synchronized(completedRequestIdentifiers) {
				completedRequestIdentifiers.remove(identifier);
			}
		}

		@Override
		public HTMLNode getEventHTMLText() {
			HTMLNode text = new HTMLNode("div");
			NodeL10n.getBase().addL10nSubstitution(text, "QueueToadlet.downloadSucceeded",
					new String[] { "link", "origlink", "filename", "size" },
					new HTMLNode[] { HTMLNode.link("/"+uri.toASCIIString()+"?max-size="+size), HTMLNode.link("/"+uri.toASCIIString()), HTMLNode.text(uri.getPreferredFilename()), HTMLNode.text(SizeUtil.formatSize(size))});
			return text;
		}

		@Override
		public String getTitle() {
			String title = null;
			synchronized(events) {
				if(events.size() == 1)
					title = l10n("downloadSucceededTitle", "filename", uri.getPreferredFilename());
				else
					title = l10n("downloadsSucceededTitle", "nr", Integer.toString(events.size()));
			}
			return title;
		}

		@Override
		public String getShortText() {
			return getTitle();
		}

		@Override
		public String getEventText() {
			return l10n("downloadSucceededTitle", "filename", uri.getPreferredFilename());
		}

	}

	private class PutCompletedEvent extends StoringUserEvent<PutCompletedEvent> {

		private final String identifier;
		private final FreenetURI uri;
		private final long size;

		public PutCompletedEvent(String identifier, FreenetURI uri, long size) {
			super(Type.PutCompleted, true, null, null, null, null, UserAlert.MINOR, true, NodeL10n.getBase().getString("UserAlert.hide"), true, null, completedPuts);
			this.identifier = identifier;
			this.uri = uri;
			this.size = size;
		}

		@Override
		public void onDismiss() {
			super.onDismiss();
			saveCompletedIdentifiersOffThread();
		}

		@Override
		public void onEventDismiss() {
			synchronized(completedRequestIdentifiers) {
				completedRequestIdentifiers.remove(identifier);
			}
		}

		@Override
		public HTMLNode getEventHTMLText() {
			HTMLNode text = new HTMLNode("div");
			NodeL10n.getBase().addL10nSubstitution(text, "QueueToadlet.uploadSucceeded",
					new String[] { "link", "filename", "size" },
					new HTMLNode[] { HTMLNode.link("/"+uri.toASCIIString()), HTMLNode.text(uri.getPreferredFilename()), HTMLNode.text(SizeUtil.formatSize(size))});
			return text;
		}

		@Override
		public String getTitle() {
			String title = null;
			synchronized(events) {
				if(events.size() == 1)
					title = l10n("uploadSucceededTitle", "filename", uri.getPreferredFilename());
				else
					title = l10n("uploadsSucceededTitle", "nr", Integer.toString(events.size()));
			}
			return title;
		}

		@Override
		public String getShortText() {
			return getTitle();
		}

		@Override
		public String getEventText() {
			return l10n("uploadSucceededTitle", "filename", uri.getPreferredFilename());
		}

	}

	private class PutDirCompletedEvent extends StoringUserEvent<PutDirCompletedEvent> {

		private final String identifier;
		private final FreenetURI uri;
		private final long size;
		private final int files;

		public PutDirCompletedEvent(String identifier, FreenetURI uri, long size, int files) {
			super(Type.PutDirCompleted, true, null, null, null, null, UserAlert.MINOR, true, NodeL10n.getBase().getString("UserAlert.hide"), true, null, completedPutDirs);
			this.identifier = identifier;
			this.uri = uri;
			this.size = size;
			this.files = files;
		}

		@Override
		public void onDismiss() {
			super.onDismiss();
			saveCompletedIdentifiersOffThread();
		}

		@Override
		public void onEventDismiss() {
			synchronized(completedRequestIdentifiers) {
				completedRequestIdentifiers.remove(identifier);
			}
		}

		@Override
		public HTMLNode getEventHTMLText() {
			String name = uri.getPreferredFilename();
			HTMLNode text = new HTMLNode("div");
			NodeL10n.getBase().addL10nSubstitution(text, "QueueToadlet.siteUploadSucceeded",
					new String[] { "link", "filename", "size", "files" },
					new HTMLNode[] { HTMLNode.link("/"+uri.toASCIIString()), HTMLNode.text(name), HTMLNode.text(SizeUtil.formatSize(size)), HTMLNode.text(files) });
			return text;
		}

		@Override
		public String getTitle() {
			String title = null;
			synchronized(events) {
				if(events.size() == 1)
					title = l10n("siteUploadSucceededTitle", "filename", uri.getPreferredFilename());
				else
					title = l10n("sitesUploadSucceededTitle", "nr", Integer.toString(events.size()));
			}
			return title;
		}

		@Override
		public String getShortText() {
			return getTitle();
		}

		@Override
		public String getEventText() {
			return l10n("siteUploadSucceededTitle", "filename", uri.getPreferredFilename());
		}

	}

}
