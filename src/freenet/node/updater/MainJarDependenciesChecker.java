/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.node.updater;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.MalformedURLException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.tanukisoftware.wrapper.WrapperManager;

import freenet.client.FetchException;
import freenet.crypt.SHA256;
import freenet.keys.FreenetURI;
import freenet.node.PrioRunnable;
import freenet.node.Version;
import freenet.support.Executor;
import freenet.support.Fields;
import freenet.support.HexUtil;
import freenet.support.Logger;
import freenet.support.io.Closer;
import freenet.support.io.FileBucket;
import freenet.support.io.FileUtil;
import freenet.support.io.FileUtil.CPUArchitecture;
import freenet.support.io.FileUtil.OperatingSystem;
import freenet.support.io.NativeThread;

/**
 * Parses the dependencies.properties file and ensures we have all the 
 * libraries required to use the next version. Calls the Deployer to do the
 * actual fetches, and to deploy the new version when we have everything 
 * ready.
 * 
 * We used to support a range of freenet-ext.jar versions. However, 
 * supporting ranges creates a lot of complexity, especially with Update 
 * Over Mandatory support.
 * 
 * File format of dependencies.properties:
 * [module].type=[module type]
 * CLASSPATH means the file must be downloaded, and then added to the 
 * classpath in wrapper.conf, before the update can be loaded.
 * 
 * OPTIONAL_PRELOAD means we just want to download the file.
 * 
 * [module].version=[version number]
 * Can often be parsed from MANIFEST.MF in Jar's, but that is NOT mandatory.
 * 
 * [module].filename=[preferred filename]
 * For CLASSPATH, this should be unique, i.e. include the version in the 
 * filename, e.g. freenet-ext-29.jar. For OPTIONAL_PRELOAD, we will often 
 * overwrite existing files.
 * 
 * [module].sha256=[hash in hex]
 * SHA256 hash of the file.
 * 
 * [module].filename-regex=[regular expression]
 * Matches filenames for this module. Only required for CLASSPATH. Note that
 * filenames will be toLowerCase()'ed first (but the regex isn't).
 * 
 * [module].key=[CHK URI]
 * Where to fetch the file from if we don't have it.
 * 
 * [module].size=[decimal size in bytes]
 * Size of the file.
 *
 * Optional:
 * 
 * [module].order=[decimal integer order, default is 0]
 * Ordering of CLASSPATH files within the wrapper.conf. E.g. freenet-ext.jar
 * is usually the last element because we want the earlier files to override
 * classes in it.
 * 
 * [module].os=[comma delimited list of OS's and pseudo-OS's]
 * OS's: See FileUtil.OperatingSystem: MacOS Linux FreeBSD GenericUnix Windows
 * Pseudo-Os's: ALL_WINDOWS ALL_UNIX ALL_MAC (these correspond to the booleans 
 * on FileUtil.OperatingSystem).
 * 
 * @author toad
 *
 */
public class MainJarDependenciesChecker {
	
	private static volatile boolean logMINOR;
	static {
		Logger.registerClass(MainJarDependenciesChecker.class);
	}
	
	// Lightweight interfaces, mundane glue code implemented by the caller.
	// FIXME unit testing should be straightforward, AND WOULD BE A GOOD IDEA!
	
	class MainJarDependencies {
		/** The freenet.jar build to be deployed. It might be possible to
		 * deploy a new build without changing the wrapper. */
		final int build;
		/** The actual dependencies. */
		final Set<Dependency> dependencies;
		/** True if we must rewrite wrapper.conf, i.e. if any new jars have
		 * been added, or new versions of existing jars. Won't be reliably
		 * true in case of jars being removed at present. FIXME see comments
		 * in handle() about deletion placeholders! */
		final boolean mustRewriteWrapperConf;
		
		MainJarDependencies(TreeSet<Dependency> dependencies, int build) {
			this.dependencies = Collections.unmodifiableSortedSet(dependencies);
			this.build = build;
			boolean mustRewrite = false;
			for(Dependency d : dependencies) {
				if(d.oldFilename == null || !d.oldFilename.equals(d.newFilename)) {
					mustRewrite = true;
					break;
				}
				if(File.pathSeparatorChar == ':' &&
						d.oldFilename != null && d.oldFilename.getName().equalsIgnoreCase("freenet-ext.jar.new")) {
					// If wrapper.conf currently contains freenet-ext.jar.new, we need to update wrapper.conf even
					// on unix. Reason: freenet-ext.jar.new won't be read if it's not the first item on the classpath,
					// because freenet.jar includes freenet-ext.jar implicitly via its manifest.
					mustRewrite = true;
					break;
				}
			}
			mustRewriteWrapperConf = mustRewrite;
		}
	}
	
	interface Deployer {
		public void deploy(MainJarDependencies deps);
		public JarFetcher fetch(FreenetURI uri, File downloadTo, long expectedLength, byte[] expectedHash, JarFetcherCallback cb, int build, boolean essential, boolean executable) throws FetchException;
		/** Called by cleanup with the dependencies we can serve for the current version. 
		 * @param expectedHash The hash of the file's contents, which is also
		 * listed in the dependencies file.
		 * @param filename The local file to serve it from. */
		public void addDependency(byte[] expectedHash, File filename);
		/** We have just downloaded a dependency needed for the current build. Reannounce to tell
		 * our peers about it. */
        public void reannounce();
        /** A multi-file update (e.g. wrapper update) is ready to deploy. It may need a restart.
         * We may need the user's permission to deploy it, or we may be able to deploy it 
         * immediately. The Deployer must call atomicDeployer.deployMultiFileUpdateOffThread() 
         * when ready.
         * @param atomicDeployer
         */
        public void multiFileReplaceReadyToDeploy(AtomicDeployer atomicDeployer);
	}
	
	interface JarFetcher {
		public void cancel();
	}
	
	interface JarFetcherCallback {
		public void onSuccess();
		public void onFailure(FetchException e);
	}

	/** A dependency, for purposes of writing the new wrapper.conf. Contains its new filename, its
	 * priority (order) in the wrapper.conf classpath, and all that is needed to identify the 
	 * previous line referring to this file.
	 * @author toad 
	 */
	final class Dependency implements Comparable<Dependency> {
	    /** The old filename, if known. This will be in wrapper.conf. */
		private File oldFilename;
		/** The new filename, to which we will download the file. */
		private File newFilename;
		/** Pattern to recognise filenames for this dependency in the last resort. */
		private Pattern regex;
		/** Priority of the dependency within the wrapper.conf classpath. Smaller value = earlier
		 * in the classpath = used first. */
		private int order;
		
		private Dependency(File oldFilename, File newFilename, Pattern regex, int order) {
			this.oldFilename = oldFilename;
			this.newFilename = newFilename;
			this.regex = regex;
			this.order = order;
		}
		
		public File oldFilename() {
			return oldFilename;
		}
		
		public File newFilename() {
			return newFilename;
		}
		
		public Pattern regex() {
			return regex;
		}

		@Override
		public int compareTo(Dependency arg0) {
			if(this == arg0) return 0;
			if(order > arg0.order) return 1;
			else if(order < arg0.order) return -1;
			// Filename comparisons aren't very reliable (e.g. "./test" versus "test" are not equals()!), go by getName() first.
			int ret = newFilename.getName().compareTo(arg0.newFilename.getName());
			if(ret != 0) return ret;
			return newFilename.compareTo(arg0.newFilename);
		}

        public int order() {
            return order;
        }
		
	}
	
	MainJarDependenciesChecker(Deployer deployer, Executor executor) {
		this.deployer = deployer;
		this.executor = executor;
	}

	private final Deployer deployer;
	/** The final filenames we will use in the update, which we have 
	 * already downloaded. */
	private final TreeSet<Dependency> dependencies = new TreeSet<Dependency>();
	/** Set if the update can't be deployed because the dependencies file is 
	 * broken. We should wait for an update with a valid file. 
	 */
	private boolean broken = false;
	/** The build we are about to deploy */
	private int build;
	
	private class Downloader implements JarFetcherCallback {

	    /** The JarFetcher which fetches the dependency from Freenet or via UOM. */
		final JarFetcher fetcher;
		/** The dependency. Will be added to the set of downloaded dependencies after the fetch 
		 * completes if this is an essential dependency for the build currently being fetched. */
		final Dependency dep;
		/** True if this dependency is required prior to deploying the next build. False if it's
		 * just OPTIONAL_PRELOAD. */
		final boolean essential;
		/** The build number that this dependency is being downloaded for */
		final int forBuild;

		/** Construct with a Dependency, so we can add it when we're done. */
		Downloader(Dependency dep, FreenetURI uri, byte[] expectedHash, long expectedSize, boolean essential, boolean executable, int forBuild) throws FetchException {
			fetcher = deployer.fetch(uri, dep.newFilename, expectedSize, expectedHash, this, build, essential, executable);
			this.dep = dep;
			this.essential = essential;
			this.forBuild = forBuild;
		}

		@Override
		public void onSuccess() {
			if(!essential) {
				System.out.println("Downloaded "+dep.newFilename+" - may be used by next update");
				return;
			}
			System.out.println("Downloaded "+dep.newFilename+" needed for update "+forBuild+"...");
			boolean toDeploy = false;
			boolean forCurrentVersion = false;
			synchronized(MainJarDependenciesChecker.this) {
				downloaders.remove(this);
				if(forBuild == build) { // If the dependency is for the build we are about to deploy...
				    dependencies.add(dep);
				    toDeploy = ready();
				} else {
				    forCurrentVersion = (forBuild == Version.buildNumber());
				}
			}
			if(toDeploy) deploy();
			else if(forCurrentVersion) deployer.reannounce();
		}

		@Override
		public void onFailure(FetchException e) {
			if(!essential) {
				Logger.error(this, "Failed to pre-load "+dep.newFilename+" : "+e, e);
			} else {
				System.err.println("Failed to fetch "+dep.newFilename+" needed for next update ("+e.getShortMessage()+"). Will try again if we find a new freenet.jar.");
				synchronized(MainJarDependenciesChecker.this) {
					downloaders.remove(this);
					if(forBuild != build) return;
					broken = true;
				}
			}
		}
		
		public void cancel() {
			fetcher.cancel();
		}
		
	}
	
	/** The dependency downloads currently running which are required for the next build. Hence 
	 * non-essential (preload) dependencies are not added to this set. */
	private final HashSet<Downloader> downloaders = new HashSet<Downloader>();
	private final Executor executor;
	
	/** Parse the Properties file. Check whether we have the jars it refers to.
	 * If not, start fetching them.
	 * @param props The Properties parsed from the dependencies.properties file.
	 * @return The set of filenames needed if we can deploy immediately, in 
	 * which case the caller MUST deploy. */
	public synchronized MainJarDependencies handle(Properties props, int build) {
		try {
			return innerHandle(props, build);
		} catch (RuntimeException e) {
			broken = true;
			Logger.error(this, "MainJarDependencies parsing update dependencies.properties file broke: "+e, e);
			throw e;
		} catch (Error e) {
			broken = true;
			Logger.error(this, "MainJarDependencies parsing update dependencies.properties file broke: "+e, e);
			throw e;
		}
	}
	
	enum DEPENDENCY_TYPE {
	    
		/** A jar we want to put on the classpath. Normally we move to a new filename when there is
		 * a new version of such a dependency; supports most features of dependencies.properties. */
		CLASSPATH,
		/** A jar we want to put on the classpath but after that we won't update it even if there 
		 * is a new version. Used for wrapper.jar since we will update it via a separate mechanism,
		 * because we have to update other files too. No regex support - must match the exact 
		 * filename. We do however check for 0 length files just in case. */
		OPTIONAL_CLASSPATH_NO_UPDATE,
		/** A file to download, which does not block the update. */
		OPTIONAL_PRELOAD,
		/** Deploy multiple files at once, all or nothing, then do a full restart on the wrapper. 
		 * On Windows this needs an external EXE which waits for shutdown, replaces the files, then 
		 * starts Freenet back up; on Linux and Mac we can just use a shell script. */
		OPTIONAL_ATOMIC_MULTI_FILES_WITH_RESTART;

        final boolean optional;
        
        DEPENDENCY_TYPE() {
            this.optional = this.name().startsWith("OPTIONAL_");
        }
        
	}
	
	private synchronized MainJarDependencies innerHandle(Properties props, int build) {
		// FIXME support deletion placeholders.
		// I.e. when we remove a library we put a placeholder in to tell this code to delete it.
		// It's not acceptable to just delete stuff we don't know about.
		clear(build);
		HashSet<String> processed = new HashSet<String>();
		File[] list = new File(".").listFiles(new FileFilter() {

			@Override
			public boolean accept(File arg0) {
				if(!arg0.isFile()) return false;
				// Ignore non-jars regardless of what the regex says.
				String name = arg0.getName().toLowerCase();
				if(!(name.endsWith(".jar") || name.endsWith(".jar.new"))) return false;
				// FIXME similar checks elsewhere, factor out?
				if(name.equals("freenet.jar") || name.equals("freenet.jar.new") || name.equals("freenet-stable-latest.jar") || name.equals("freenet-stable-latest.jar.new"))
					return false;
				return true;
			}
			
		});
outer:	for(String propName : props.stringPropertyNames()) {
			if(!propName.contains(".")) continue;
			String baseName = propName.split("\\.")[0];
			if(!processed.add(baseName)) continue;
			String s = props.getProperty(baseName+".type");
			if(s == null) {
				Logger.error(this, "dependencies.properties broken? missing type for \""+baseName+"\"");
				broken = true;
				continue;
			}
			DEPENDENCY_TYPE type;
			try {
				type = DEPENDENCY_TYPE.valueOf(s);
				if(type == DEPENDENCY_TYPE.OPTIONAL_ATOMIC_MULTI_FILES_WITH_RESTART) {
				    // Ignore. Handle in cleanup().
				    continue;
				}
			} catch (IllegalArgumentException e) {
				if(s.startsWith("OPTIONAL_")) {
					// We don't understand it, but that's OK as it's optional.
					if(logMINOR) Logger.minor(this, "Ignoring non-essential dependency type \""+s+"\" for \""+baseName+"\"");
					continue;
				}
				// We don't understand it, and it's not optional, so we can't deploy the update.
				Logger.error(this, "dependencies.properties broken? unrecognised type for \""+baseName+"\"");
				broken = true;
				continue;
			}
			
			// Check operating system restrictions.
			s = props.getProperty(baseName+".os");
			if(s != null) {
				if(!matchesCurrentOS(s)) {
					Logger.normal(this, "Ignoring "+baseName+" as not relevant to this operating system");
					continue;
				}
			}
            // Check architecture restrictions.
			s = props.getProperty(baseName+".arch");
			if(s != null) {
			    if(!matchesCurrentArch(s)) {
                    Logger.normal(this, "Ignoring "+baseName+" as not relevant to this architecture");
                    continue;
			    }
			}
			// Version is used in cleanup().
			String version = props.getProperty(baseName+".version");
			if(version == null) {
				Logger.error(this, "dependencies.properties broken? missing version");
				broken = true;
				continue;
			}
			File filename = null;
			s = props.getProperty(baseName+".filename");
			// FIXME use nodeDir
			if(s != null) filename = new File(s);
			if(filename == null) {
				Logger.error(this, "dependencies.properties broken? missing filename");
				broken = true;
				continue;
			}
			if(filename.getParentFile() != null)
			    filename.getParentFile().mkdirs();
			FreenetURI maxCHK = null;
			s = props.getProperty(baseName+".key");
			if(s == null) {
				Logger.error(this, "dependencies.properties broken? missing "+baseName+".key");
				// Can't fetch it. :(
			} else {
				try {
					maxCHK = new FreenetURI(s);
				} catch (MalformedURLException e) {
					Logger.error(this, "Unable to parse CHK for "+baseName+": \""+s+"\": "+e, e);
					maxCHK = null;
				}
			}
			// FIXME where to get the proper folder from? That seems to be an issue in UpdateDeployContext as well...
			
			Pattern p = null;
			if(type == DEPENDENCY_TYPE.CLASSPATH) {
				// Regex used for matching filenames.
				String regex = props.getProperty(baseName+".filename-regex");
				if(regex == null && type == DEPENDENCY_TYPE.CLASSPATH) {
					// Not a critical error. Just means we can't clean it up, and can't identify whether we already have a compatible jar.
					Logger.error(this, "No "+baseName+".filename-regex in dependencies.properties - we will not be able to clean up old versions of files, and may have to download the latest version unnecessarily");
					// May be fatal later on depending on what else we have.
				}
				try {
					if(regex != null)
						p = Pattern.compile(regex);
				} catch (PatternSyntaxException e) {
					Logger.error(this, "Bogus Pattern \""+regex+"\" in dependencies.properties");
					p = null;
				}
			}
			
			byte[] expectedHash = parseExpectedHash(props.getProperty(baseName+".sha256"), baseName);
			if(expectedHash == null) {
				System.err.println("Unable to update to build "+build+": dependencies.properties broken: No hash for "+baseName);
				broken = true;
				continue;
			}
			
			s = props.getProperty(baseName+".size");
			long size = -1;
			if(s != null) {
				try {
					size = Long.parseLong(s);
				} catch (NumberFormatException e) {
					size = -1;
				}
			}
			if(size < 0) {
				System.err.println("Unable to update to build "+build+": dependencies.properties broken: Broken length for "+baseName+" : \""+s+"\"");
				broken = true;
				continue;
			}
			
			int order = 0;
			File currentFile = null;

			if(type == DEPENDENCY_TYPE.CLASSPATH || type == DEPENDENCY_TYPE.OPTIONAL_CLASSPATH_NO_UPDATE) {
				s = props.getProperty(baseName+".order");
				if(s != null) {
					try {
						// Order is an optional field.
						// For most stuff we don't care.
						// But if it's present it must be correct!
						order = Integer.parseInt(s);
					} catch (NumberFormatException e) {
						System.err.println("Unable to update to build "+build+": dependencies.properties broken: Broken order for "+baseName+" : \""+s+"\"");
						broken = true;
						continue;
					}
				}
				
				currentFile = getDependencyInUse(p);
			}
			
            // Executable?
            boolean executable = false;
            s = props.getProperty(baseName+".executable");
            if(s != null) {
                executable = Boolean.parseBoolean(s);
            }
			
			if(type == DEPENDENCY_TYPE.OPTIONAL_CLASSPATH_NO_UPDATE && filename.exists()) {
			    if(filename.canRead() && filename.length() > 0) {
			        System.out.println("Assuming non-updated dependency file is current: "+filename);
			        dependencies.add(new Dependency(currentFile, filename, p, order));
			        continue;
			    } else {
			        System.out.println("Non-updated dependency is empty?: "+filename+" - will try to fetch it");
			        filename.delete();
			    }
			}
			if(validFile(filename, expectedHash, size, executable)) {
				// Nothing to do. Yay!
				System.out.println("Found file required by the new Freenet version: "+filename);
				// Use it.
				if(type == DEPENDENCY_TYPE.CLASSPATH)
					dependencies.add(new Dependency(currentFile, filename, p, order));
				continue;
			}
			// Check the version currently in use.
			if(currentFile != null && validFile(currentFile, expectedHash, size, executable)) {
				System.out.println("Existing version of "+currentFile+" is OK for update.");
				// Use it.
				if(type == DEPENDENCY_TYPE.CLASSPATH)
					dependencies.add(new Dependency(currentFile, currentFile, p, order));
				continue;
			}
			if(type == DEPENDENCY_TYPE.CLASSPATH) {
				if(p == null) {
					// No way to check existing files.
					if(maxCHK != null) {
						try {
							fetchDependency(maxCHK, new Dependency(currentFile, filename, p, order), expectedHash, size, true, executable);
						} catch (FetchException fe) {
							broken = true;
							Logger.error(this, "Failed to start fetch: "+fe, fe);
							System.err.println("Failed to start fetch of essential component for next release: "+fe);
						}
					} else {
						// Critical error.
						System.err.println("Unable to fetch "+baseName+" because no URI and no regex to match old versions.");
						broken = true;
						continue;
					} 
					continue;
				}
				for(File f : list) {
					String name = f.getName();
					if(!p.matcher(name.toLowerCase()).matches()) continue;
					if(validFile(f, expectedHash, size, executable)) {
						// Use it.
						System.out.println("Found "+name+" - meets requirement for "+baseName+" for next update.");
						dependencies.add(new Dependency(currentFile, f, p, order));
						continue outer;
					}
				}
			}
			if(maxCHK == null) {
				System.err.println("Cannot fetch "+baseName+" for update because no CHK and no old file");
				broken = true;
				continue;
			}
			// Otherwise we need to fetch it.
			try {
				fetchDependency(maxCHK, new Dependency(currentFile, filename, p, order), expectedHash, size, type != DEPENDENCY_TYPE.OPTIONAL_PRELOAD, executable);
			} catch (FetchException e) {
				broken = true;
				Logger.error(this, "Failed to start fetch: "+e, e);
				System.err.println("Failed to start fetch of essential component for next release: "+e);
			}
		}
		if(ready())
			return new MainJarDependencies(new TreeSet<Dependency>(dependencies), build);
		else
			return null;
	}
	
	private static boolean matchesCurrentOS(String s) {
		OperatingSystem myOS = FileUtil.detectedOS;
		String[] osList = s.split(",");
		for(String os : osList) {
			os = os.trim();
			if(myOS.toString().equalsIgnoreCase(os)) {
				return true;
			}
			if(os.equalsIgnoreCase("ALL_WINDOWS") &&
					myOS.isWindows) {
				return true;
			}
			if(os.equalsIgnoreCase("ALL_UNIX") &&
					myOS.isUnix) {
				return true;
			}
			if(os.equalsIgnoreCase("ALL_MAC") &&
					myOS.isMac) {
				return true;
			}
		}
		return false;
	}

    private static boolean matchesCurrentArch(String s) {
        CPUArchitecture myCPU = FileUtil.detectedArch;
        String[] archList = s.split(",");
        for(String arch : archList) {
            arch = arch.trim();
            if(myCPU.toString().equalsIgnoreCase(arch)) {
                return true;
            }
        }
        return false;
    }

	/** Should be called on startup, before any fetches have started. Will 
	 * remove unnecessary files and start blob fetches for files we don't 
	 * have blobs for.
	 * @param props The dependencies.properties from the running version.
	 * @return True unless something went wrong.
	 */
	public boolean cleanup(Properties props, final Deployer deployer, int build) {
		// This method should not change anything, but can call the callbacks.
		HashSet<String> processed = new HashSet<String>();
		final ArrayList<File> toDelete = new ArrayList<File>();
		File[] listMain = new File(".").listFiles(new FileFilter() {

			@Override
			public boolean accept(File arg0) {
				if(!arg0.isFile()) return false;
				String name = arg0.getName().toLowerCase();
				// Cleanup old updater tempfiles.
				if(name.endsWith(NodeUpdateManager.TEMP_FILE_SUFFIX) || name.endsWith(NodeUpdateManager.TEMP_BLOB_SUFFIX)) {
					toDelete.add(arg0);
					return false;
				}
				// Ignore non-jars regardless of what the regex says.
				if(!name.endsWith(".jar")) return false;
				// FIXME similar checks elsewhere, factor out?
				if(name.equals("freenet.jar") || name.equals("freenet.jar.new") || name.equals("freenet-stable-latest.jar") || name.equals("freenet-stable-latest.jar.new"))
					return false;
				return true;
			}
			
		});
		for(File f : toDelete) {
			System.out.println("Deleting old temp file \""+f+"\"");
			f.delete();
		}
		for(String propName : props.stringPropertyNames()) {
			if(!propName.contains(".")) continue;
			String baseName = propName.split("\\.")[0];
			if(!processed.add(baseName)) continue;
			String s = props.getProperty(baseName+".type");
			if(s == null) {
				Logger.error(MainJarDependencies.class, "dependencies.properties broken? missing type for \""+baseName+"\"");
				continue;
			}
			final DEPENDENCY_TYPE type;
			try {
				type = DEPENDENCY_TYPE.valueOf(s);
			} catch (IllegalArgumentException e) {
				if(s.startsWith("OPTIONAL_")) {
					if(logMINOR) Logger.minor(MainJarDependencies.class, "Ignoring non-essential dependency type \""+s+"\" for \""+baseName+"\"");
					continue;
				}
				Logger.error(MainJarDependencies.class, "dependencies.properties broken? unrecognised type for \""+baseName+"\"");
				continue;
			}
			
	         // Check operating system restrictions.
            s = props.getProperty(baseName+".os");
            if(s != null) {
                if(!matchesCurrentOS(s)) {
                    Logger.normal(MainJarDependenciesChecker.class, "Ignoring "+baseName+" as not relevant to this operating system");
                    continue;
                }
            }
            // Check architecture restrictions.
            s = props.getProperty(baseName+".arch");
            if(s != null) {
                if(!matchesCurrentArch(s)) {
                    Logger.normal(this, "Ignoring "+baseName+" as not relevant to this architecture");
                    continue;
                }
            }

            // For wrapper updates.
            // 3.2 tolerates "java" being a script, 3.5 does not, so we must not upgrade in this case.
            String mustBeOnPathNotAScript = props.getProperty(baseName+".mustBeOnPathNotAScript");
            if(mustBeOnPathNotAScript != null && !isOnPathNotAScript(mustBeOnPathNotAScript)) {
                Logger.normal(this, "Ignoring "+baseName+" because needs \""+mustBeOnPathNotAScript+"\" on the path and not a script");
                System.out.println( "Ignoring "+baseName+" because needs \""+mustBeOnPathNotAScript+"\" on the path and not a script"); // FIXME remove when tested
                continue;
            }
            
            if(type == DEPENDENCY_TYPE.OPTIONAL_ATOMIC_MULTI_FILES_WITH_RESTART) {
                parseAtomicMultiFilesWithRestart(props, baseName);
                continue;
            }
			
			// Version is useful for checking for obsolete versions of files.
			String version = props.getProperty(baseName+".version");
			if(version == null) {
				Logger.error(MainJarDependencies.class, "dependencies.properties broken? missing version");
				return false;
			}
			File filename = null;
			s = props.getProperty(baseName+".filename");
			// FIXME use nodeDir
			if(s != null) filename = new File(s);
			if(filename == null) {
				Logger.error(MainJarDependencies.class, "dependencies.properties broken? missing filename");
				return false;
			}
			
			final FreenetURI key;
			s = props.getProperty(baseName+".key");
			if(s == null) {
				Logger.error(MainJarDependencies.class, "dependencies.properties broken? missing "+baseName+".key");
				return false;
			}
			try {
				key = new FreenetURI(s);
			} catch (MalformedURLException e) {
				Logger.error(MainJarDependencies.class, "Unable to parse CHK for "+baseName+": \""+s+"\": "+e, e);
				return false;
			}
			
			Pattern p = null;
			// Regex used for matching filenames.
			if(type == DEPENDENCY_TYPE.CLASSPATH) {
				String regex = props.getProperty(baseName+".filename-regex");
				if(regex == null) {
					Logger.error(MainJarDependencies.class, "No "+baseName+".filename-regex in dependencies.properties");
					return false;
				}
				try {
					p = Pattern.compile(regex);
				} catch (PatternSyntaxException e) {
					Logger.error(MainJarDependencies.class, "Bogus Pattern \""+regex+"\" in dependencies.properties");
					return false;
				}
			}
			
			final byte[] expectedHash = parseExpectedHash(props.getProperty(baseName+".sha256"), baseName);
			if(expectedHash == null) {
				System.err.println("Unable to update to build "+build+": dependencies.properties broken: No hash for "+baseName);
				return false;
			}
			
			s = props.getProperty(baseName+".size");
			long size = -1;
			if(s != null) {
				try {
					size = Long.parseLong(s);
				} catch (NumberFormatException e) {
					size = -1;
				}
			}
			if(size < 0) {
				System.err.println("Unable to update to build "+build+": dependencies.properties broken: Broken length for "+baseName+" : \""+s+"\"");
				return false;
			}
			
			s = props.getProperty(baseName+".order");
			if(s != null) {
				try {
					// Order is an optional field.
					// For most stuff we don't care.
					// But if it's present it must be correct!
					Integer.parseInt(s);
				} catch (NumberFormatException e) {
					System.err.println("Unable to update to build "+build+": dependencies.properties broken: Broken order for "+baseName+" : \""+s+"\"");
					continue;
				}
			}
			
			File currentFile = null;
			if(type == DEPENDENCY_TYPE.CLASSPATH)
				currentFile = getDependencyInUse(p);
			
			if(type == DEPENDENCY_TYPE.OPTIONAL_CLASSPATH_NO_UPDATE && filename.exists()) {
			    if(filename.canRead() && filename.length() > 0) {
			        Logger.normal(MainJarDependenciesChecker.class, "Assuming non-updated dependency file is current: "+filename);
			        continue;
			    } else {
			        System.out.println("Non-updated dependency is empty?: "+filename+" - will try to fetch it");
			        filename.delete();
			    }
			}
			
			if(!(type == DEPENDENCY_TYPE.CLASSPATH || type == DEPENDENCY_TYPE.OPTIONAL_PRELOAD || 
			        type == DEPENDENCY_TYPE.OPTIONAL_CLASSPATH_NO_UPDATE)) {
			    // Whitelist types to preload.
			    // Update this if new types need to be preloaded.
			    continue;
			}
			
            // Executable?
            boolean executable = false;
            s = props.getProperty(baseName+".executable");
            if(s != null) {
                executable = Boolean.parseBoolean(s);
            }
            
            if(type == DEPENDENCY_TYPE.OPTIONAL_PRELOAD && filename.exists())
                currentFile = filename;

			// Serve the file if it meets the hash in the dependencies.properties.
			if(currentFile != null && currentFile.exists() && 
			        validFile(currentFile, expectedHash, size, executable)) {
			    // File is OK.
			    if(!type.optional) {
			        System.out.println("Will serve "+currentFile+" for UOM");
			        deployer.addDependency(expectedHash, currentFile);
			    }
			} else if(currentFile != null && !type.optional) {
			    // Will be dealt with during update. For now ignore it. Not safe to preload it, since it's on the classpath, whether it exists or not.
			    System.out.println("Component "+baseName+" is using a non-standard file, we cannot serve the file "+filename+" via UOM to other nodes. Hence they may not be able to download the update from us.");
			} else {
			    // Optional update, or not present in spite of being required.
				final File file = filename;
				try {
					System.out.println("Preloading "+filename+(type.optional ? "" : " for the next update..."));
					deployer.fetch(key, filename, size, expectedHash, new JarFetcherCallback() {

						@Override
						public void onSuccess() {
							System.out.println("Preloaded "+file+" which will be needed when we upgrade.");
							if(!type.optional) {
							    System.out.println("Will serve "+file+" for UOM");
							    deployer.addDependency(expectedHash, file);
							}
						}

						@Override
						public void onFailure(FetchException e) {
							Logger.error(this, "Failed to preload "+file+" from "+key+" : "+e, e);
						}
						
					}, type.optional ? 0 : build, false, executable);
				} catch (FetchException e) {
					Logger.error(MainJarDependencies.class, "Failed to preload "+file+" from "+key+" : "+e, e);
				}
			}
			
			if(currentFile == null) 
				continue; // Ignore any old versions we might have missed that were actually on the classpath.
			String currentFileVersion = getDependencyVersion(currentFile);
			if(currentFileVersion == null)
				continue; // If no version in the current version, no version in any other either, can't reliably detect outdated jars. E.g. freenet-ext.jar up to v29!
			// Now delete bogus dependencies.
			for(File f : listMain) {
				String name = f.getName().toLowerCase();
				if(!p.matcher(name).matches()) continue;
				// Comparing File's by equals() is dodgy, e.g. ./blah != blah. So use getName().
				// Even on *nix some filesystems are case insensitive.
				if(name.equalsIgnoreCase(currentFile.getName())) continue;
				if(inClasspath(name)) continue; // Paranoia!
				String fileVersion = getDependencyVersion(f);
				if(fileVersion == null) {
					f.delete();
					System.out.println("Deleting old dependency file (no version): "+f);
					continue;
				}
				if(Fields.compareVersion(fileVersion, version) <= 0) {
					f.delete();
					System.out.println("Deleting old dependency file (outdated): "+f);
				} // Keep newer versions.
			}
		}
		return true;
	}
	
	static final byte[] SCRIPT_HEAD;
	
	static {
	    try {
	        SCRIPT_HEAD = "#!".getBytes("UTF-8");
	    } catch(UnsupportedEncodingException e) {
	        throw new Error(e);
	    }
	}
	
	private boolean isOnPathNotAScript(String toFind) {
	    String path = System.getenv("PATH"); // Upper case should work on both linux and Windows
	    if(path == null) return false;
	    String[] split = path.split(File.pathSeparator);
	    for(String s : split) {
	        File f = new File(s);
	        if(f.exists() && f.isDirectory()) {
	            f = new File(f, toFind);
	            if(f.exists() && f.canExecute()) {
	                if(!f.canRead()) {
	                    Logger.error(this, "On path and can execute but not read, so can't check whether it is a script?!: "+f);
	                    return false;
	                }
	                if(f.length() < SCRIPT_HEAD.length) {
	                    Logger.error(this, "Found "+toFind+" on path but less than "+SCRIPT_HEAD+" bytes long, so can't check whether it is a script - will the shell try the next match? We can't tell whether it is a script or not ...");
	                    return false; // Weird!
	                }
	                try {
                        FileInputStream fis = new FileInputStream(f);
                        byte[] buf = new byte[SCRIPT_HEAD.length];
                        DataInputStream dis = new DataInputStream(fis);
                        try {
                            dis.read(buf);
                            return !Arrays.equals(buf, SCRIPT_HEAD);
                        } catch (IOException e) {
                            Logger.error(this, "Unable to read "+f+" to check whether it is a script: "+e+" - disk corruption problems???", e);
                            return false;
                        } finally {
	                        Closer.close(fis);
	                        Closer.close(dis);
                        }
                    } catch (FileNotFoundException e) {
                        // Impossible.
                    }
	            }
	        }
	    }
	    Logger.normal(this, "Could not find "+toFind+" on the path");
	    return false; // Not found on the path.
    }

    enum MUST_EXIST {
        /** File may or may not exist */
        FALSE,
	    /** File must exist but we don't care about its content (we're going to replace it) */
	    TRUE,
	    /** File must exist and have exactly the contents expected (it's a prerequisite) */
	    EXACT
	}
	
	/** Handle a request to atomically update a set of files and restart the wrapper properly, that 
	 * is, using an external script (just telling it to restart is inadequate in this case). FORMAT:
	 *  type=OPTIONAL_ATOMIC_MULTI_FILES_WITH_RESTART
	 *  os=ALL_UNIX // handled by caller
	 *  files.1.mustExist=true // do not deploy if the file did not exist previously
	 * OR files.1.mustExist=false // create the file if it's not there
	 *  files.1.sha256=...
	 *  files.1.filename=wrapper.jar
	 *  files.1.chk=CHK@...
	 *  files.2....
	 * @return False if something broke.
	 */
	private boolean parseAtomicMultiFilesWithRestart(Properties props, String name) {
	    AtomicDeployer atomicDeployer = createRestartingAtomicDeployer(name);
	    if(atomicDeployer == null) return false; // Platform not supported?
	    boolean nothingToDo = true;
	    for(String propName : props.stringPropertyNames()) {
	        String[] split = propName.split("\\.");
	        if(split.length != 4) continue;
	        // namefordeploy.nameforfile.filename=...
	        // nameforfile is not necessarily the filename, which might contain . / etc.
	        if(!split[0].equals(name)) continue;
	        if(!split[1].equals("files")) continue;
	        if(!split[3].equals("filename")) continue;
	        String fileBase = name+".files."+split[2];
	        // Filename.
	        File filename = null;
	        String s = props.getProperty(fileBase+".filename");
	        if(s == null) break;
	        filename = new File(s);
	        // Key.
	        final FreenetURI key;
	        s = props.getProperty(fileBase+".key");
	        if(s == null) {
	            Logger.error(MainJarDependencies.class, "dependencies.properties broken? missing "+fileBase+".key in atomic multi-files list");
                atomicDeployer.cleanup();
	            return false;
	        }
	        try {
	            key = new FreenetURI(s);
	        } catch (MalformedURLException e) {
	            Logger.error(MainJarDependencies.class, "Unable to parse CHK for multi-files replace for "+fileBase+": \""+s+"\": "+e, e);
                atomicDeployer.cleanup();
	            return false;
	        }
	        // Size.
	        s = props.getProperty(fileBase+".size");
	        long size = -1;
	        if(s != null) {
	            try {
	                size = Long.parseLong(s);
	            } catch (NumberFormatException e) {
	                Logger.error(MainJarDependencies.class, "Unable to parse size for multi-files replace for "+fileBase+": \""+s+"\": "+e, e);
                    atomicDeployer.cleanup();
	                return false;
	            }
	        }
            // Must exist?
	        MUST_EXIST mustExist;
            s = props.getProperty(fileBase+".mustExist");
            if(s == null) {
                mustExist = MUST_EXIST.FALSE;
            } else {
                try {
                    mustExist = MUST_EXIST.valueOf(s.toUpperCase());
                } catch (IllegalArgumentException e) {
                    Logger.error(MainJarDependencies.class, "Unable to past mustExist \""+s+"\" for "+fileBase);
                    atomicDeployer.cleanup();
                    return false;
                }
            }
            boolean mustBeOnClassPath = false;
            s = props.getProperty(fileBase+".mustBeOnClassPath");
            if(s != null) {
                mustBeOnClassPath = Boolean.parseBoolean(s);
            }
	        // SHA256 hash
            byte[] expectedHash = parseExpectedHash(props.getProperty(fileBase+".sha256"), fileBase);
            if(expectedHash == null) {
                System.err.println("dependencies.properties multi-file replace broken: No hash for "+fileBase);
                atomicDeployer.cleanup();
                return false;
            }
            // Executable?
            boolean executable = false;
            s = props.getProperty(fileBase+".executable");
            if(s != null) {
                executable = Boolean.parseBoolean(s);
            }
            if(!filename.exists()) {
                if(mustExist != MUST_EXIST.FALSE) {
                    System.out.println("Not running multi-file replace "+name+" : File does not exist: "+filename);
                    atomicDeployer.cleanup();
                    return false;
                }
                nothingToDo = false;
                System.out.println("Multi-file replace: Must create "+filename+" for "+name);
            } else if(!validFile(filename, expectedHash, size, executable)) {
                if(mustExist == MUST_EXIST.EXACT) {
                    System.out.println("Not running multi-file replace: Not compatible with old version of prerequisite "+filename);
                    atomicDeployer.cleanup();
                    return false;
                }
                System.out.println("Multi-file replace: Must update "+filename+" for "+name);
                nothingToDo = false;
            } else if(mustExist == MUST_EXIST.EXACT)
                continue;
            if(mustBeOnClassPath) {
                File f = getDependencyInUse(Pattern.compile(Pattern.quote(filename.getName())));
                if(f == null) {
                    System.err.println("Not running multi-file replace: File must be on classpath: "+filename+" for "+name);
                    atomicDeployer.cleanup();
                    return false;
                }
            }
            AtomicDependency dependency;
            try {
                dependency = new AtomicDependency(filename, key, size, expectedHash, executable);
            } catch (IOException e) {
                System.err.println("Unable to start multi-file update for "+name+" : "+e);
                atomicDeployer.cleanup();
                return false;
            }
            atomicDeployer.add(dependency);
	    }
	    if(nothingToDo) {
	        System.out.println("Multi-file replace: Nothing to do for "+name+".");
	        atomicDeployer.cleanup();
	        return false; // Valid no-op.
	    }
	    atomicDeployer.start();
	    return true;
    }
	
	static final String UPDATER_BACKUP_SUFFIX = ".update.bak.tmp";
	
	/** A file to be replaced as part of a multi-file replace. */
	private class AtomicDependency implements JarFetcherCallback {
	    
	    /** Temporary file to store the downloaded data in until it is ready to deploy */
	    private final File tempFilename;
	    /** Temporary file to store a copy of the old file in until the deploy has succeeded */
	    private final File backupFilename;
	    private final File filename;
	    private final FreenetURI key;
	    private final long size;
	    private final byte[] expectedHash;
	    private final boolean executable;
	    private AtomicDeployer myDeployer;
	    private JarFetcher fetcher;
	    private boolean nothingToBackup;
	    private boolean triedDeploy;
	    private boolean succeededFetch;
	    private boolean backedUp;

        public AtomicDependency(File filename, FreenetURI key, long size, byte[] expectedHash, boolean executable) throws IOException {
            this.filename = filename;
            this.key = key;
            this.size = size;
            this.expectedHash = expectedHash;
            this.executable = executable;
            File parent = filename.getAbsoluteFile().getParentFile();
            if(parent == null) parent = new File(".");
            File[] list = parent.listFiles();
            for(File f : list) {
                String name = f.getName();
                if(name.startsWith(filename.getName()) && name.endsWith(UPDATER_BACKUP_SUFFIX)) 
                    f.delete();
            }
            this.tempFilename = File.createTempFile(filename.getName(), ".tmp", parent);
            tempFilename.deleteOnExit();
            this.backupFilename = File.createTempFile(filename.getName(), UPDATER_BACKUP_SUFFIX, parent);
        }
        
        public boolean start(AtomicDeployer myDeployer) {
            synchronized(this) {
                if(this.myDeployer != null) return true; // Already running.
                this.myDeployer = myDeployer;
            }
            System.out.println("Fetching "+filename+" from "+key);
            try {
                JarFetcher fetcher = deployer.fetch(key, tempFilename, size, expectedHash, this, build, false, executable /* we use rename, so ideally we'd like the temp file to be executable if the target will be */);
                synchronized(this) {
                    this.fetcher = fetcher;
                }
                return true;
            } catch (FetchException e) {
                Logger.error(this, "Unable to start fetch for "+filename+" from "+key+" size "+size+" expected hash "+HexUtil.bytesToHex(expectedHash)+" : "+e, e);
                System.err.println("Unable to start fetch for "+filename+" for multi-file replace");
                return false;
            }
        }

        @Override
        public void onSuccess() {
            AtomicDeployer d;
            synchronized(this) {
                succeededFetch = true;
                d = myDeployer;
            }
            System.out.println("Fetched "+filename+" from "+key);
            d.onSuccess(this);
        }

        @Override
        public void onFailure(FetchException e) {
            System.out.println("Failed to fetch "+filename+" from "+key);
            getDeployer().onFailure(this);
        }

        private synchronized AtomicDeployer getDeployer() {
            return myDeployer;
        }

        public void cancel() {
            JarFetcher f;
            synchronized(this) {
                f = fetcher;
                fetcher = null;
            }
            if(f == null) return;
            f.cancel();
        }
        
        boolean backupOriginal() {
            System.out.println("Backing up "+filename+" to "+backupFilename);
            if(!filename.exists()) {
                synchronized(this) {
                    nothingToBackup = true;
                    backedUp = true;
                }
                return true;
            }
            if(FileUtil.copyFile(filename, backupFilename)) {
                synchronized(this) {
                    backedUp = true;
                }
                if(executable)
                    return backupFilename.setExecutable(true) || backupFilename.canExecute();
                return true;
            } else return false;
        }
        
        boolean deploy() {
            System.out.println("Deploying "+tempFilename+" to "+filename);
            synchronized(this) {
                assert(succeededFetch);
                assert(backedUp);
                triedDeploy = true;
            }
            if(!filename.exists()) {
                if(tempFilename.renameTo(filename)) {
                    if(executable) 
                        return filename.setExecutable(true) || filename.canExecute();
                    return true;
                } else 
                    return false;
            } else {
                if(tempFilename.renameTo(filename)) {
                    if(executable) 
                        return filename.setExecutable(true) || filename.canExecute();
                    return true;
                }
                filename.delete();
                if(tempFilename.renameTo(filename)) {
                    if(executable) 
                        return filename.setExecutable(true) || filename.canExecute();
                    return true;
                } else
                    return false;
            }
        }
        
        boolean revertFromBackup() {
            synchronized(this) {
                assert(succeededFetch);
                assert(backedUp);
                if(!triedDeploy) return true; // Valid no-op.
            }
            System.out.println("Reverting from backup "+backupFilename+" to "+filename);
            boolean nothingToBackup;
            synchronized(this) {
                nothingToBackup = this.nothingToBackup;
            }
            if(nothingToBackup) {
                if(!filename.delete() && filename.exists()) {
                    System.err.println("Unable to delete file while reverting multi-file deploy: "+filename);
                    tempFilename.delete();
                    return true; // Usually this is OK.
                } else {
                    tempFilename.delete();
                    return true;
                }
            } else {
                if(!backupFilename.renameTo(filename)) return false;
                if(executable) {
                    if(filename.setExecutable(true) || filename.canExecute()) {
                        tempFilename.delete();
                        return true;
                    } else return false;
                } else {
                    tempFilename.delete();
                    return true;
                }
            }
        }
        
        void cleanup() {
            tempFilename.delete();
            backupFilename.delete();
        }
	    
	}
	
	private AtomicDeployer createRestartingAtomicDeployer(String name) {
	    if(FileUtil.detectedOS.isUnix || FileUtil.detectedOS.isMac) {
	        return new UnixRestartingAtomicDeployer(name);
	    } else if(FileUtil.detectedOS.isWindows) {
	        System.out.println("Multi-file update for "+name+" not supported on Windows at present, see bug #5883");
	        // FIXME implement Windows support using bug #5883.
	        return null;
	    } else {
            System.out.println("Multi-file update for "+name+" not supported on unknown non-unix non-windows OS "+FileUtil.detectedOS);
	        return null;
	    }
	}
	
	/** Deploys a multi-file replace without a restart */
	class AtomicDeployer {
	    
	    private final Set<AtomicDependency> dependencies = new HashSet<AtomicDependency>();
	    private final Set<AtomicDependency> dependenciesWaiting = new HashSet<AtomicDependency>();
	    private boolean failed;
	    private boolean started;
	    final String name;

	    /** Create an AtomicDeployer, which will wait for the downloads and then deploy a 
	     * multi-file replace atomically, that is all at once.
	     * @param name The internal name of the deployment job. For UI purposes we will simply
	     * feed this into the localisation code.
	     */
        public AtomicDeployer(String name) {
            this.name = name;
        }

        public void cleanup() {
            for(AtomicDependency dep : dependencies()) {
                dep.cancel();
                dep.cleanup();
            }
        }

        public void onFailure(AtomicDependency dep) {
            synchronized(this) {
                failed = true;
                dependenciesWaiting.remove(dep);
            }
            System.err.println("Unable to deploy multi-file update "+name+" because fetch failed for "+dep.filename);
            cleanup();
        }

        public void onSuccess(AtomicDependency dep) {
            synchronized(this) {
                assert(dependencies.contains(dep));
                dependenciesWaiting.remove(dep);
                if(!dependenciesWaiting.isEmpty()) return;
                if(failed) return;
            }
            readyToDeploy();
        }

        private void readyToDeploy() {
            deployer.multiFileReplaceReadyToDeploy(this);
        }

        public synchronized void add(AtomicDependency dependency) {
            if(started) {
                Logger.error(this, "Already started!");
                failed = true;
                return;
            }
            dependencies.add(dependency);
            dependenciesWaiting.add(dependency);
        }
        
        public void start() {
            for(AtomicDependency dep : dependencies()) {
                if(!dep.start(this)) {
                    System.err.println("Unable to start fetch for "+this);
                    AtomicDependency[] deps;
                    synchronized(this) {
                        failed = true;
                        deps = dependencies();
                    }
                    for(AtomicDependency kill : deps) {
                        kill.cancel();
                    }
                    return;
                }
            }
            synchronized(this) {
                started = true;
            }
        }
        
        private synchronized AtomicDependency[] dependencies() {
            return dependencies.toArray(new AtomicDependency[dependencies.size()]);
        }

        public void deployMultiFileUpdateOffThread() {
            executor.execute(new PrioRunnable() {

                @Override
                public void run() {
                    synchronized(NodeUpdateManager.deployLock()) {
                        if(deployMultiFileUpdate())
                            NodeUpdateManager.waitForever();
                    }
                }

                @Override
                public int getPriority() {
                    return NativeThread.MAX_PRIORITY;
                }
                
            });
        }
        
        protected boolean deployMultiFileUpdate() {
            if(!innerDeployMultiFileUpdate()) {
                System.err.println("Failed to deploy multi-file update "+name);
                return false;
            } else return true;
        }

        /** Replace all the files or none of the files */
        boolean innerDeployMultiFileUpdate() {
            synchronized(this) {
                if(failed || !started) {
                    Logger.error(this, "Not deploying: failed="+failed+" started="+started, new Exception("error"));
                    return false;
                }
            }
            AtomicDependency[] deps = dependencies();
            for(AtomicDependency dep : deps) {
                if(!dep.backupOriginal()) {
                    System.err.println("Unable to backup dependency "+dep.filename+" - aborting multi-file update deployment "+name);
                    return false;
                }
            }
            boolean failedDeploy = false;
            for(AtomicDependency dep : deps) {
                if(!dep.deploy()) {
                    failedDeploy = true;
                    System.err.println("Unable to update file "+dep.filename+" from "+dep.tempFilename+" - aborting multi-file update deployment "+name);
                    break;
                }
            }
            if(failedDeploy) {
                System.err.println("Deploying multi-file update failed: "+name);
                System.err.println("Restoring files from backups");
                for(AtomicDependency dep : deps) {
                    if(!dep.revertFromBackup()) {
                        System.err.println("Restoring file from backup failed. Freenet may fail to start on next restart! You should move "+dep.backupFilename+" to "+dep.filename);
                        // FIXME useralert???
                    }
                }
            }
            return !failedDeploy;
        }
	    
	}
	
	/** Deploys a multi-file replace with a restart */
	private abstract class RestartingAtomicDeployer extends AtomicDeployer {

        public RestartingAtomicDeployer(String name) {
            super(name);
        }
	    
	}
	
	/** Deploys a multi-file replace on *nix with a restart, using a simple shell script */
	private class UnixRestartingAtomicDeployer extends RestartingAtomicDeployer {

        public UnixRestartingAtomicDeployer(String name) {
            super(name);
        }
        
        @Override
        protected boolean deployMultiFileUpdate() {
            if(!WrapperManager.isControlledByNativeWrapper()) return false;
            File restartScript;
            try {
                restartScript = createRestartScript();
            } catch (IOException e) {
                System.err.println("Unable to deploy multi-file update for "+name+" because cannot write script to restart the wrapper: "+e);
                Logger.error(this, "Unable to deploy multi-file update for "+name+" because cannot write script to restart the wrapper: "+e, e);
                return false;
            }
            if(restartScript == null) return false;
            File shell = findShell();
            if(shell == null) return false;
            if(innerDeployMultiFileUpdate()) {
                try { // FIXME use nodeDir
                    if(Runtime.getRuntime().exec(new String[] { shell.toString(), restartScript.toString() }) == null) {
                        System.err.println("Unable to start restarter script "+restartScript+" with shell "+shell+" -> cannot deploy multi-file update for "+name);
                        return false;
                    }
                } catch (IOException e) {
                    System.err.println("Unable to start restarter script "+restartScript+" with shell "+shell+" -> cannot deploy multi-file update for "+name+" : "+e);
                    Logger.error(this, "Unable to start restarter script "+restartScript+" with shell "+shell+" -> cannot deploy multi-file update for "+name+" : "+e, e);
                    return false;
                }
                System.out.println("Shutting down Freenet for hard restart after deploying multi-file update for "+name+". The script "+restartScript+" should start it back up.");
                WrapperManager.stop(0);
                return true;
            } else return false;
        }

        private File findShell() {
            File f = new File("/bin/sh");
            if(f.exists() && f.canExecute()) return f;
            f = new File("/bin/bash");
            if(f.exists() && f.canExecute()) return f;
            System.err.println("Unable to find system shell");
            return null;
        }
	    
        static final String RESTART_SCRIPT_NAME = "tempRestartFreenet.sh";
        
        private File createRestartScript() throws IOException {
            // FIXME use nodeDir
            File runsh = new File("run.sh");
            String runshNoNice = "run.nonice-for-update.sh";
            if(!(runsh.exists() && runsh.canExecute())) {
                System.err.println("Cannot find run.sh so cannot deploy multi-file update for "+name);
                return null;
            }
            // EVIL HACK
            if(!createRunShNoNice(runsh, new File(runshNoNice))) {
                return null;
            }
            if(!new File("/dev/null").exists()) {
                System.err.println("Cannot deploy multi-file update for "+name+" without /dev/null");
                return null;
            }
            File restartFreenet = new File(RESTART_SCRIPT_NAME);
            restartFreenet.delete();
            FileBucket fb = new FileBucket(restartFreenet, false, true, false, false);
            OutputStream os = null;
            try {
                os = new BufferedOutputStream(fb.getOutputStream());
                OutputStreamWriter osw = new OutputStreamWriter(os, "ISO-8859-1"); // Right???
                osw.write("#!/bin/sh\n"); // FIXME exec >/dev/null 2>&1 ???? Believed to be portable.
                //osw.write("trap true PIPE\n"); - should not be necessary
                osw.write("while kill -0 "+WrapperManager.getWrapperPID()+" > /dev/null 2>&1; do sleep 1; done\n");
                osw.write("./"+runshNoNice+" start > /dev/null 2>&1\n");
                osw.write("rm "+RESTART_SCRIPT_NAME+"\n");
                osw.write("rm "+runshNoNice+"\n");
                osw.close();
                osw = null; 
                os = null;
                return restartFreenet;
            } finally {
                Closer.close(os);
            }
        }

        /** Evil hack: Rewrite run.sh so it has PRIORITY=0. 
         * REDFLAG FIXME TODO Surely we can improve on this? This mechanism is only used for 
         * updating very old wrapper installs - but we'll want to update the wrapper in the future
         * too, and the ability to restart the wrapper fully is likely useful, so maybe we won't 
         * just get rid of this - in which case maybe we want to improve on this.
         * @throws IOException */ 
        private boolean createRunShNoNice(File input, File output) throws IOException {
            final String charset = "UTF-8";
            InputStream is = null;
            OutputStream os = null;
            boolean failed = false;
            try {
                is = new FileInputStream(input);
                BufferedReader br = new BufferedReader(new InputStreamReader(new BufferedInputStream(is), charset));
                os = new FileOutputStream(output);
                Writer w = new BufferedWriter(new OutputStreamWriter(new BufferedOutputStream(os), charset));
                boolean writtenPrio = false;
                String line;
                while((line = br.readLine()) != null) {
                    if((!writtenPrio) && line.startsWith("PRIORITY=")) {
                        writtenPrio = true;
                        line = "PRIORITY="; // = don't use nice.
                    }
                    w.write(line+"\n");
                }
                // We want to see exceptions on close() here.
                br.close();
                is = new FileInputStream(input);
                w.close();
                os = null;
                if(!(output.setExecutable(true) || output.canExecute())) {
                    failed = true;
                    return false;
                }
                return true;
            } catch (UnsupportedEncodingException e) {
                throw new Error(e);
            } catch (IOException e) {
                failed = true;
                return false;
            } finally {
                Closer.close(is);
                Closer.close(os);
                if(failed) output.delete();
            }
        }

	}

    public static String getDependencyVersion(File currentFile) {
        // We can't use parseProperties because there are multiple sections.
    	InputStream is = null;
        try {
        	is = new FileInputStream(currentFile);
        	ZipInputStream zis = new ZipInputStream(is);
        	ZipEntry ze;
        	while(true) {
        		ze = zis.getNextEntry();
        		if(ze == null) break;
        		if(ze.isDirectory()) continue;
        		String name = ze.getName();
        		
        		if(name.equals("META-INF/MANIFEST.MF")) {
        			final String key = "Implementation-Version";
        			BufferedInputStream bis = new BufferedInputStream(zis);
        			Manifest m = new Manifest(bis);
        			bis.close();
        			bis = null;
        			Attributes a = m.getMainAttributes();
        			if(a != null) {
        				String ver = a.getValue(key);
        				if(ver != null) return ver;
        			}
        			a = m.getAttributes("common");
        			if(a != null) {
        				String ver = a.getValue(key);
        				if(ver != null) return ver;
        			}
        		}
        	}
        	Logger.error(MainJarDependenciesChecker.class, "Unable to get dependency version from "+currentFile);
        	return null;
        } catch (FileNotFoundException e) {
        	return null;
        } catch (IOException e) {
        	return null;
        } finally {
        	Closer.close(is);
        }
	}

    /** Find the current filename, on the classpath, of the dependency given.
     * Note that this may not actually exist, and the caller should check!
     * However, even a non-existent filename may be useful when updating 
     * wrapper.conf.
     */
	private static File getDependencyInUse(Pattern p) {
		if(p == null) return null; // Optional in some cases.
		String classpath = System.getProperty("java.class.path");
		String[] split = classpath.split(File.pathSeparator);
		for(String s : split) {
			File f = new File(s);
			if(p.matcher(f.getName().toLowerCase()).matches())
				return f;
		}
		return null;
	}
	
    private static boolean inClasspath(String name) {
		String classpath = System.getProperty("java.class.path");
		String[] split = classpath.split(File.pathSeparator);
		for(String s : split) {
			File f = new File(s);
			if(name.equalsIgnoreCase(f.getName()))
				return true;
		}
		return false;
	}

	private static byte[] parseExpectedHash(String sha256, String baseName) {
		if(sha256 == null) {
			Logger.error(MainJarDependencies.class, "No SHA256 for "+baseName+" in dependencies.properties");
			return null;
		}
		try {
			return HexUtil.hexToBytes(sha256);
		} catch (NumberFormatException e) {
			Logger.error(MainJarDependencies.class, "Bogus expected hash: \""+sha256+"\" : "+e, e);
			return null;
		} catch (IndexOutOfBoundsException e) {
			Logger.error(MainJarDependencies.class, "Bogus expected hash: \""+sha256+"\" : "+e, e);
			return null;
		}
	}

	public static boolean validFile(File filename, byte[] expectedHash, long size, boolean executable) {
		if(filename == null) return false;
		if(!filename.exists()) return false;
		if(filename.length() != size) {
			System.out.println("File exists while updating but length is wrong ("+filename.length()+" should be "+size+") for "+filename);
			return false;
		}
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(filename);
			MessageDigest md = SHA256.getMessageDigest();
			SHA256.hash(fis, md);
			byte[] hash = md.digest();
			SHA256.returnMessageDigest(md);
			fis.close();
			fis = null;
			if(Arrays.equals(hash, expectedHash)) {
                if(executable && !filename.canExecute()) {
                    filename.setExecutable(true);
                }
			    return true;
			} else {
			    return false;
			}
		} catch (FileNotFoundException e) {
			Logger.error(MainJarDependencies.class, "File not found: "+filename);
			return false;
		} catch (IOException e) {
			System.err.println("Unable to read "+filename+" for updater");
			return false;
		} finally {
			Closer.close(fis);
		}
	}

	private synchronized void clear(int build) {
		dependencies.clear();
		broken = false;
		this.build = build;
		final Downloader[] toCancel = downloaders.toArray(new Downloader[downloaders.size()]);
		executor.execute(new Runnable() {

			@Override
			public void run() {
				for(Downloader d : toCancel)
					d.cancel();
			}
			
		});
		downloaders.clear();
	}

	/** Unlike other methods here, this should be called outside the lock. */
	public void deploy() {
		TreeSet<Dependency> f;
		synchronized(this) {
			f = new TreeSet<Dependency>(dependencies);
		}
		if(logMINOR) Logger.minor(this, "Deploying build "+build+" with "+f.size()+" dependencies");
		deployer.deploy(new MainJarDependencies(f, build));
	}

	private synchronized void fetchDependency(FreenetURI chk, Dependency dep, byte[] expectedHash, long expectedSize, boolean essential, boolean executable) throws FetchException {
		Downloader d = new Downloader(dep, chk, expectedHash, expectedSize, essential, executable, build);
		if(essential)
			downloaders.add(d);
	}

	private synchronized boolean ready() {
		if(broken) return false;
		if(!downloaders.isEmpty()) return false;
		return true;
	}
	
	public synchronized boolean isBroken() {
		return broken;
	}

}
