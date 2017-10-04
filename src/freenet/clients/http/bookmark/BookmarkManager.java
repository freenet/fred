/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.clients.http.bookmark;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import freenet.client.async.ClientContext;
import freenet.client.async.USKCallback;
import freenet.clients.http.FProxyToadlet;
import freenet.keys.FreenetURI;
import freenet.keys.USK;
import freenet.l10n.NodeL10n;
import freenet.node.FSParseException;
import freenet.node.NodeClientCore;
import freenet.node.RequestClient;
import freenet.node.RequestStarter;
import freenet.node.SemiOrderedShutdownHook;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.Logger.LogLevel;
import freenet.support.SimpleFieldSet;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;

public class BookmarkManager implements RequestClient {

	public static final SimpleFieldSet DEFAULT_BOOKMARKS;
	private final NodeClientCore node;
	private final USKUpdatedCallback uskCB = new USKUpdatedCallback();
	public static final BookmarkCategory MAIN_CATEGORY = new BookmarkCategory("/");
	public static final BookmarkCategory DEFAULT_CATEGORY = new BookmarkCategory("\\");
	private final HashMap<String, Bookmark> bookmarks = new HashMap<String, Bookmark>();
	private final File bookmarksFile;
	private final File backupBookmarksFile;
	private boolean isSavingBookmarks = false;
	private boolean isSavingBookmarksLazy = false;
	static {
		String name = "freenet/clients/http/staticfiles/defaultbookmarks.dat";
		SimpleFieldSet defaultBookmarks = null;
		InputStream in = null;
		try {
			ClassLoader loader = BookmarkManager.class.getClassLoader();

			// Returns null on lookup failures:
			in = loader.getResourceAsStream(name);
			if(in != null)
				defaultBookmarks = SimpleFieldSet.readFrom(in, false, false);
		} catch(Exception e) {
			Logger.error(BookmarkManager.class, "Error while loading the default bookmark file from " + name + " :" + e.getMessage(), e);
		} finally {
			Closer.close(in);
			DEFAULT_BOOKMARKS = defaultBookmarks;
		}
	}

        private static volatile boolean logMINOR;
	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback(){
			@Override
			public void shouldUpdate(){
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	public BookmarkManager(NodeClientCore n, boolean publicGateway) {
		putPaths("/", MAIN_CATEGORY);
		this.node = n;
		this.bookmarksFile = n.node.userDir().file("bookmarks.dat");
		this.backupBookmarksFile = n.node.userDir().file("bookmarks.dat.bak");

		try {
			// Read the backup file if necessary
			if(!bookmarksFile.exists() || bookmarksFile.length() == 0)
				throw new IOException();
			Logger.normal(this, "Attempting to read the bookmark file from " + bookmarksFile.toString());
			SimpleFieldSet sfs = SimpleFieldSet.readFrom(bookmarksFile, false, true);
			readBookmarks(MAIN_CATEGORY, sfs);
		} catch(MalformedURLException mue) {
		} catch(IOException ioe) {
			Logger.error(this, "Error reading the bookmark file (" + bookmarksFile.toString() + "):" + ioe.getMessage(), ioe);

			try {
				if(backupBookmarksFile.exists() && backupBookmarksFile.canRead() && backupBookmarksFile.length() > 0) {
					Logger.normal(this, "Attempting to read the backup bookmark file from " + backupBookmarksFile.toString());
					SimpleFieldSet sfs = SimpleFieldSet.readFrom(backupBookmarksFile, false, true);
					readBookmarks(MAIN_CATEGORY, sfs);
				} else {
					Logger.normal(this, "We couldn't find the backup either! - " + FileUtil.getCanonicalFile(backupBookmarksFile));
					// restore the default bookmark set
					readBookmarks(MAIN_CATEGORY, DEFAULT_BOOKMARKS);
				}
			} catch(IOException e) {
				Logger.error(this, "Error reading the backup bookmark file !" + e.getMessage(), e);
			}
		}
		//populate defaults for hosts without full access permissions if we're in gateway mode.
		if (publicGateway) {
			putPaths("\\", DEFAULT_CATEGORY);
			readBookmarks(DEFAULT_CATEGORY, DEFAULT_BOOKMARKS);
		}
		
		SemiOrderedShutdownHook.get().addEarlyJob(new Thread() {
			BookmarkManager bm = BookmarkManager.this;
			
			@Override public void run() {
				// The USKUpdatedCallback only does storeBookmarksLazy() to accumulate changes
				// before writing to disk until 5 minutes expire. As USK updates are visible in the
				// UI by notifications, we need to ensure to save them before shutdown to not
				// confuse the users with disappearing notifications.
				bm.storeBookmarks();
				bm = null;
			}
		});
	}

	public void reAddDefaultBookmarks() {
		BookmarkCategory bc = new BookmarkCategory(l10n("defaultBookmarks") + " - " + new Date());
		addBookmark("/", bc);
		_innerReadBookmarks("/", bc, DEFAULT_BOOKMARKS);
	}

	private class USKUpdatedCallback implements USKCallback {

		@Override
		public void onFoundEdition(long edition, USK key, ClientContext context, boolean wasMetadata, short codec, byte[] data, boolean newKnownGood, boolean newSlotToo) {
			if(!newKnownGood) {
				FreenetURI uri = key.copy(edition).getURI();
				node.makeClient(PRIORITY_PROGRESS, false).prefetch(uri, MINUTES.toMillis(60), FProxyToadlet.MAX_LENGTH_WITH_PROGRESS, null, PRIORITY_PROGRESS);
				return;
			}
			List<BookmarkItem> items = MAIN_CATEGORY.getAllItems();
			boolean matched = false;
			boolean updated = false;
			for(int i = 0; i < items.size(); i++) {
				if(!"USK".equals(items.get(i).getKeyType()))
					continue;

				try {
					FreenetURI furi = new FreenetURI(items.get(i).getKey());
					USK usk = USK.create(furi);

					if(usk.equals(key, false)) {
						if(logMINOR) Logger.minor(this, "Updating bookmark for "+furi+" to edition "+edition);
						matched = true;
						BookmarkItem item = items.get(i);
						updated |= item.setEdition(edition);
						// We may have bookmarked the same site twice, so continue the search.
					}
				} catch(MalformedURLException mue) {
				}
			}
			if(updated) {
				storeBookmarksLazy();
			} else if(!matched) {
				Logger.error(this, "No match for bookmark "+key+" edition "+edition);
			}
		}

		@Override
		public short getPollingPriorityNormal() {
			return PRIORITY;
		}

		@Override
		public short getPollingPriorityProgress() {
			return PRIORITY_PROGRESS;
		}
	}

	public String l10n(String key) {
		return NodeL10n.getBase().getString("BookmarkManager." + key);
	}

	public String parentPath(String path) {
		if(path.equals("/"))
			return "/";

		return path.substring(0, path.substring(0, path.length() - 1).lastIndexOf('/')) + "/";
	}

	public Bookmark getBookmarkByPath(String path) {
		synchronized(bookmarks) {
			return bookmarks.get(path);
		}
	}

	public BookmarkCategory getCategoryByPath(String path) {
		Bookmark cat = getBookmarkByPath(path);
		if(cat instanceof BookmarkCategory)
			return (BookmarkCategory) cat;

		return null;
	}

	public BookmarkItem getItemByPath(String path) {
		if(getBookmarkByPath(path) instanceof BookmarkItem)
			return (BookmarkItem) getBookmarkByPath(path);

		return null;
	}

	public void addBookmark(String parentPath, Bookmark bookmark) {
		if(logMINOR)
			Logger.minor(this, "Adding bookmark " + bookmark + " to " + parentPath);
		BookmarkCategory parent = getCategoryByPath(parentPath);
		parent.addBookmark(bookmark);
		putPaths(parentPath + bookmark.getName() + ((bookmark instanceof BookmarkCategory) ? "/" : ""),
			bookmark);

		if(bookmark instanceof BookmarkItem)
			subscribeToUSK((BookmarkItem)bookmark);
	}

	public void renameBookmark(String path, String newName) {
		Bookmark bookmark = getBookmarkByPath(path);
		String oldName = bookmark.getName();
		String oldPath = '/' + oldName;
		String newPath = path.substring(0, path.indexOf(oldPath)) + '/' + newName + (bookmark instanceof BookmarkCategory ? "/" : "");

		bookmark.setName(newName);
		synchronized(bookmarks) {
			Iterator<String> it = bookmarks.keySet().iterator();
			while(it.hasNext()) {
				String s = it.next();
				if(s.startsWith(path)) {
					it.remove();
				}
			}
			putPaths(newPath, bookmark);
		}
		storeBookmarks();
	}

	public void moveBookmark(String bookmarkPath, String newParentPath) {
		Bookmark b = getBookmarkByPath(bookmarkPath);
		addBookmark(newParentPath, b);

		getCategoryByPath(parentPath(bookmarkPath)).removeBookmark(b);
		removePaths(bookmarkPath);
	}

	public void removeBookmark(String path) {
		Bookmark bookmark = getBookmarkByPath(path);
		if(bookmark == null)
			return;

		if(bookmark instanceof BookmarkCategory) {
			BookmarkCategory cat = (BookmarkCategory) bookmark;
			for(int i = 0; i < cat.size(); i++)
				removeBookmark(path + cat.get(i).getName() + ((cat.get(i) instanceof BookmarkCategory) ? "/"
					: ""));
		} else {
			if(((BookmarkItem) bookmark).getKeyType().equals("USK")) {
				try {
					USK u = ((BookmarkItem) bookmark).getUSK();
					if(!wantUSK(u, (BookmarkItem)bookmark)) {
						this.node.uskManager.unsubscribe(u, this.uskCB);
					}
				} catch(MalformedURLException mue) {
				}
			}
		}

		getCategoryByPath(parentPath(path)).removeBookmark(bookmark);
		synchronized(bookmarks) {
			bookmarks.remove(path);
		}
	}

	private boolean wantUSK(USK u, BookmarkItem ignore) {
		List<BookmarkItem> items = MAIN_CATEGORY.getAllItems();
		for(BookmarkItem item : items) {
			if(item == ignore)
				continue;
			if(!"USK".equals(item.getKeyType()))
				continue;

			try {
				FreenetURI furi = new FreenetURI(item.getKey());
				USK usk = USK.create(furi);

				if(usk.equals(u, false)) return true;
			} catch(MalformedURLException mue) {
			}
		}
		return false;
	}

	public void moveBookmarkUp(String path, boolean store) {
		BookmarkCategory parent = getCategoryByPath(parentPath(path));
		parent.moveBookmarkUp(getBookmarkByPath(path));

		if(store)
			storeBookmarks();
	}

	public void moveBookmarkDown(String path, boolean store) {
		BookmarkCategory parent = getCategoryByPath(parentPath(path));
		parent.moveBookmarkDown(getBookmarkByPath(path));

		if(store)
			storeBookmarks();
	}

	private void putPaths(String path, Bookmark b) {
		synchronized(bookmarks) {
			bookmarks.put(path, b);
		}
		if(b instanceof BookmarkCategory)
			for(int i = 0; i < ((BookmarkCategory) b).size(); i++) {
				Bookmark child = ((BookmarkCategory) b).get(i);
				putPaths(path + child.getName() + (child instanceof BookmarkItem ? "" : "/"), child);
			}

	}

	private void removePaths(String path) {
		if(getBookmarkByPath(path) instanceof BookmarkCategory) {
			BookmarkCategory cat = getCategoryByPath(path);
			for(int i = 0; i < cat.size(); i++)
				removePaths(path + cat.get(i).getName() + (cat.get(i) instanceof BookmarkCategory ? "/" : ""));
		}
		bookmarks.remove(path);
	}

	public FreenetURI[] getBookmarkURIs() {
		List<BookmarkItem> items = MAIN_CATEGORY.getAllItems();
		FreenetURI[] uris = new FreenetURI[items.size()];
		for(int i = 0; i < items.size(); i++)
			uris[i] = items.get(i).getURI();

		return uris;
	}
	
	public void storeBookmarksLazy() {
		synchronized(bookmarks) {
			if(isSavingBookmarksLazy) return;
			isSavingBookmarksLazy = true;
			node.node.ticker.queueTimedJob(new Runnable() {

				@Override
				public void run() {
					try {
						storeBookmarks();
					} finally {
						isSavingBookmarksLazy = false;
					}
				}

			}, MINUTES.toMillis(5));
		}
	}

	public void storeBookmarks() {
		Logger.normal(this, "Attempting to save bookmarks to " + bookmarksFile.toString());
		SimpleFieldSet sfs = null;
		synchronized(bookmarks) {
			if(isSavingBookmarks)
				return;
			isSavingBookmarks = true;

			sfs = toSimpleFieldSet();
		}
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(backupBookmarksFile);
			sfs.writeToBigBuffer(fos);
			fos.close();
			fos = null;
			if(!FileUtil.renameTo(backupBookmarksFile, bookmarksFile))
				Logger.error(this, "Unable to rename " + backupBookmarksFile.toString() + " to " + bookmarksFile.toString());
		} catch(IOException ioe) {
			Logger.error(this, "An error has occured saving the bookmark file :" + ioe.getMessage(), ioe);
		} finally {
			Closer.close(fos);

			synchronized(bookmarks) {
				isSavingBookmarks = false;
			}
		}
	}

	private void readBookmarks(BookmarkCategory category, SimpleFieldSet sfs) {
		_innerReadBookmarks("", category, sfs);
	}

	static final short PRIORITY = RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS;
	static final short PRIORITY_PROGRESS = RequestStarter.UPDATE_PRIORITY_CLASS;

	private void subscribeToUSK(BookmarkItem item) {
		if("USK".equals(item.getKeyType()))
			try {
				USK u = item.getUSK();
				this.node.uskManager.subscribe(u, this.uskCB, true, this);
			} catch(MalformedURLException mue) {}
	}

	private synchronized void _innerReadBookmarks(String prefix, BookmarkCategory category, SimpleFieldSet sfs) {
		boolean hasBeenParsedWithoutAnyProblem = true;
		boolean isRoot = ("".equals(prefix) && MAIN_CATEGORY.equals(category));
		synchronized(bookmarks) {
			if(!isRoot)
				putPaths(prefix + category.name + '/', category);

			try {
				int nbBookmarks = sfs.getInt(BookmarkItem.NAME);
				int nbCategories = sfs.getInt(BookmarkCategory.NAME);

				for(int i = 0; i < nbBookmarks; i++) {
					SimpleFieldSet subset = sfs.getSubset(BookmarkItem.NAME + i);
					try {
						BookmarkItem item = new BookmarkItem(subset, this, node.alerts);
						String name = (isRoot ? "" : prefix + category.name) + '/' + item.name;
						putPaths(name, item);
						category.addBookmark(item);
						item.registerUserAlert();
						subscribeToUSK(item);
					} catch(MalformedURLException e) {
						throw new FSParseException(e);
					}
				}

				for(int i = 0; i < nbCategories; i++) {
					SimpleFieldSet subset = sfs.getSubset(BookmarkCategory.NAME + i);
					BookmarkCategory currentCategory = new BookmarkCategory(subset);
					category.addBookmark(currentCategory);
					String name = (isRoot ? "/" : (prefix + category.name + '/'));
					_innerReadBookmarks(name, currentCategory, subset.getSubset("Content"));
				}

			} catch(FSParseException e) {
				Logger.error(this, "Error parsing the bookmarks file!", e);
				hasBeenParsedWithoutAnyProblem = false;
			}

		}
		if(hasBeenParsedWithoutAnyProblem)
			storeBookmarks();
	}


	public SimpleFieldSet toSimpleFieldSet() {
		SimpleFieldSet sfs = new SimpleFieldSet(true);

		sfs.put("Version", 1);
		synchronized(bookmarks) {
			sfs.putAllOverwrite(BookmarkManager.toSimpleFieldSet(MAIN_CATEGORY));
		}

		return sfs;
	}

	public static SimpleFieldSet toSimpleFieldSet(BookmarkCategory cat) {
		SimpleFieldSet sfs = new SimpleFieldSet(true);
		List<BookmarkCategory> bc = cat.getSubCategories();

		for(int i = 0; i < bc.size(); i++) {
			BookmarkCategory currentCat = bc.get(i);
			sfs.put(BookmarkCategory.NAME + i, currentCat.getSimpleFieldSet());
		}
		sfs.put(BookmarkCategory.NAME, bc.size());


		List<BookmarkItem> bi = cat.getItems();
		for(int i = 0; i < bi.size(); i++)
			sfs.put(BookmarkItem.NAME + i, bi.get(i).getSimpleFieldSet());
		sfs.put(BookmarkItem.NAME, bi.size());

		return sfs;
	}

	@Override
	public boolean persistent() {
		return false;
	}

	@Override
	public boolean realTimeFlag() {
		return false;
	}
}
