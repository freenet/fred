/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.support.io;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import freenet.client.DefaultMIMETypes;
import freenet.node.NodeStarter;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger;
import freenet.support.SizeUtil;
import freenet.support.StringValidityChecker;
import freenet.support.Logger.LogLevel;

final public class FileUtil {

	public static final int BUFFER_SIZE = 32*1024;

	/**
	 * Returns a line reading stream for the content of <code>logfile</code>. The stream will
	 * contain at most <code>byteLimit</code> bytes. If <code>byteLimit</code> is less than the
	 * size of <code>logfile</code>, the first part of the file will be skipped. If this leaves a
	 * partial line at the beginning of the content to read, that partial line will also be
	 * skipped.
	 * @param logfile The file to open
	 * @param byteLimit The maximum number of bytes to read
	 * @return A line reader for the trailing portion of the file
	 * @throws java.io.IOException if an I/O error occurs
	 */
	public static LineReadingInputStream getLogTailReader(File logfile, long byteLimit) throws IOException {
	    long length = logfile.length();
	    long skip = 0;
	    if (length > byteLimit) {
	        skip = length - byteLimit;
	    }

	    FileInputStream fis = null;
	    LineReadingInputStream lis = null;
	    try {
	        fis = new FileInputStream(logfile);
	        lis = new LineReadingInputStream(fis);
	        if (skip > 0) {
	            lis.skip(skip);
	            lis.readLine(100000, 200, true);
	        }
	    } catch (IOException e) {
	        Closer.close(lis);
	        Closer.close(fis);
	        throw e;
	    }
	    return lis;
	}

	public static enum OperatingSystem {
		Unknown(false, false, false), // Special-cased in filename sanitising code.
		MacOS(false, true, true), // OS/X in that it can run scripts.
		Linux(false, false, true),
		FreeBSD(false, false, true),
		GenericUnix(false, false, true),
		Windows(true, false, false);
		
		public final boolean isWindows;
		public final boolean isMac;
		public final boolean isUnix;
		OperatingSystem(boolean win, boolean mac, boolean unix) {
			this.isWindows = win;
			this.isMac = mac;
			this.isUnix = unix;
		};
	};
	
	public static enum CPUArchitecture {
	    Unknown,
	    X86,
	    X86_64,
	    PPC_32,
	    PPC_64,
	    ARM,
	    SPARC,
	    IA64
	}

	public static final OperatingSystem detectedOS;
	
	/** Caveat: Sometimes this may not be entirely accurate, e.g. we may not be able to distinguish
	 * 32-bit from 64-bit, we may be using the wrong JVM for the platform, we may be using an x86 
	 * wrapper or JVM on an IA64 system etc. This *should* be the version the JVM is running. */
	public static final CPUArchitecture detectedArch;

	private static final Charset fileNameCharset;

	static {
		detectedOS = detectOperatingSystem();
		
		detectedArch = detectCPUArchitecture();

		// I did not find any way to detect the Charset of the file system so I'm using the file encoding charset.
		// On Windows and Linux this is set based on the users configured system language which is probably equal to the filename charset.
		// The worst thing which can happen if we misdetect the filename charset is that downloads fail because the filenames are invalid:
		// We disallow path and file separator characters anyway so its not possible to cause files to be stored in arbitrary places.
		fileNameCharset = getFileEncodingCharset();
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

	/**
	 * Detects the operating system in which the JVM is running. Returns OperatingSystem.Unknown if the OS is unknown or an error occured.
	 * Therefore this function should never throw.
	 */
	private static OperatingSystem detectOperatingSystem() { // TODO: Move to the proper class
		try {
			final String name =  System.getProperty("os.name").toLowerCase();

			// Order the if() by probability instead alphabetically to decrease the false-positive rate in case they decide to call it "Windows Mac" or whatever

			// Please adapt sanitizeFileName when adding new OS.

			if(name.indexOf("win") >= 0)
				return OperatingSystem.Windows;

			if(name.indexOf("mac") >= 0)
				return OperatingSystem.MacOS;

			if(name.indexOf("linux") >= 0)
				return OperatingSystem.Linux;
			
			if(name.indexOf("freebsd") >= 0)
				return OperatingSystem.FreeBSD;
			
			if(name.indexOf("unix") >= 0)
				return OperatingSystem.GenericUnix;
			else if(File.separatorChar == '/')
				return OperatingSystem.GenericUnix;
			else if(File.separatorChar == '\\')
				return OperatingSystem.Windows;

			Logger.error(FileUtil.class, "Unknown operating system:" + name);
		} catch(Throwable t) {
			Logger.error(FileUtil.class, "Operating system detection failed", t);
		}

		return OperatingSystem.Unknown;
	}
	
	private static CPUArchitecture detectCPUArchitecture() { // TODO Move to the proper class
	    try {
	        final String name = System.getProperty("os.arch").toLowerCase();
	        if(name.equals("x86") || name.equals("i386") || name.matches("i[3-9]86"))
	            return CPUArchitecture.X86;
	        if(name.equals("amd64") || name.equals("x86-64") || name.equals("x86_64") ||
	                name.equals("x86") || name.equals("em64t") || name.equals("x8664") ||
	                name.equals("8664"))
	            return CPUArchitecture.X86_64;
	        if(name.startsWith("arm"))
	            return CPUArchitecture.ARM; // FIXME arm64 support?
	        if(name.equals("ppc") || name.equals("powerpc"))
	            return CPUArchitecture.PPC_32;
	        if(name.equals("ppc64"))
	            return CPUArchitecture.PPC_64;
	        if(name.startsWith("ia64"))
	            return CPUArchitecture.IA64;
	    } catch (Throwable t) {
	        Logger.error(FileUtil.class, "CPU architecture detection failed", t);
	    }
	    return CPUArchitecture.Unknown;
	}

	/**
	 * Returns the Charset which is equal to the "file.encoding" property.
	 * This property is set to the users configured system language on windows for example.
	 *
	 * If any error occurs, the default Charset is returned. Therefore this function should never throw.
	 */
	public static Charset getFileEncodingCharset() {
		try {
			return Charset.forName(System.getProperty("file.encoding"));
		} catch(Throwable t) {
			return Charset.defaultCharset();
		}
	}


	/** Round up a value to the next multiple of a power of 2 */
	private static long roundup_2n (long val, int blocksize) {
		int mask=blocksize-1;
		return (val+mask)&~mask;
	}

	/**
	 * Guesstimate real disk usage for a file with a given filename, of a given length.
	 */
	public static long estimateUsage(File file, long flen) {
		/**
		 * It's possible that none of these assumptions are accurate for any filesystem;
		 * this is intended to be a plausible worst case.
		 */
		// Assume 4kB clusters for calculating block usage (NTFS)
		long blockUsage = roundup_2n(flen, 4096);
		// Assume 512 byte filename entries, with 100 bytes overhead, for filename overhead (NTFS)
		String filename = file.getName();
		int nameLength;
		try {
			nameLength = Math.max(filename.getBytes("UTF-16").length, filename.getBytes("UTF-8").length) + 100;
		} catch (UnsupportedEncodingException e) {
			// Impossible.
			throw new RuntimeException("UTF-16 or UTF-8 charset not supported?!");
		} 
		long filenameUsage = roundup_2n(nameLength, 512);
		// Assume 50 bytes per block tree overhead with 1kB blocks (reiser3 worst case)
		long extra = (roundup_2n(flen, 1024) / 1024) * 50;
		return blockUsage + filenameUsage + extra;
	}

	/**
	 *  Is possParent a parent of filename?
	 * Why doesn't java provide this? :(
	 * */
	public static boolean isParent(File poss, File filename) {
		File canon = FileUtil.getCanonicalFile(poss);
		File canonFile = FileUtil.getCanonicalFile(filename);

		if(isParentInner(poss, filename)) return true;
		if(isParentInner(poss, canonFile)) return true;
		if(isParentInner(canon, filename)) return true;
		if(isParentInner(canon, canonFile)) return true;
		return false;
	}

	private static boolean isParentInner(File possParent, File filename) {
		while(true) {
			if(filename.equals(possParent)) return true;
			filename = filename.getParentFile();
			if(filename == null) return false;
		}
	}

	public static File getCanonicalFile(File file) {
		// Having some problems storing File's in db4o ...
		// It would start up, and canonicalise a file with path "/var/lib/freenet-experimental/persistent-temp-24374"
		// to /var/lib/freenet-experimental/var/lib/freenet-experimental/persistent-temp-24374
		// (where /var/lib/freenet-experimental is the current working dir)
		// Regenerating from path worked. So do that here.
		// And yes, it's voodoo.
		String name = file.getPath();
		if(File.pathSeparatorChar == '\\') {
			name = name.toLowerCase();
		}
		file = new File(name);
		File result;
		try {
			result = file.getAbsoluteFile().getCanonicalFile();
		} catch (IOException e) {
			result = file.getAbsoluteFile();
		}
		return result;
	}

    /**
     * Reads the entire content of a file as UTF-8 and returns it.
     * @param file The file to read
     * @return The content of <code>file</code>
     * @throws FileNotFoundException if <code>file</code> cannot be opened
     * @throws IOException if an I/O error occurs
     */
    public static StringBuilder readUTF(File file) throws FileNotFoundException, IOException {
        return readUTF(file, 0);
    }

    /**
     * Reads the content of a file as UTF-8, starting at a specified offset, and returns it.
     * @param file The file to read
     * @param offset The point in <code>file</code> at which to start reading
     * @return The content of <code>file</code>, starting at <code>offset</code>
     * @throws FileNotFoundException if <code>file</code> cannot be opened
     * @throws IOException if an I/O error occurs
     */
	public static StringBuilder readUTF(File file, long offset) throws FileNotFoundException, IOException {
		StringBuilder result = new StringBuilder();
		FileInputStream fis = null;
		BufferedInputStream bis = null;
		InputStreamReader isr = null;

		try {
			fis = new FileInputStream(file);
			skipFully(fis, offset);
			bis = new BufferedInputStream(fis);
			isr = new InputStreamReader(bis, "UTF-8");

			char[] buf = new char[4096];
			int length = 0;

			while((length = isr.read(buf)) > 0) {
				result.append(buf, 0, length);
			}

		} finally {
			Closer.close(isr);
			Closer.close(bis);
			Closer.close(fis);
		}
		return result;
	}
	
	/**
	 * Reads the entire content of a stream as UTF-8 and returns it.
	 * @param stream The stream to read
	 * @return The content of <code>stream</code>
	 * @throws IOException if an I/O error occurs
	 */
	public static StringBuilder readUTF(InputStream stream) throws IOException {
	    return readUTF(stream, 0);
	}
	
	/**
	 * Reads the content of a stream as UTF-8, starting at a specified offset, and returns it.
	 * @param stream The stream to read
	 * @param offset The point in <code>stream</code> at which to start reading
	 * @return The content of <code>stream</code>, starting at <code>offset</code>
	 * @throws IOException if an I/O error occurs
	 */
	public static StringBuilder readUTF(InputStream stream, long offset) throws IOException {
	    StringBuilder result = new StringBuilder();
	    skipFully(stream, offset);
	    InputStreamReader reader = null;
	    try {
	        reader = new InputStreamReader(stream, "UTF-8");
	        char[] buf = new char[4096];
	        int length = 0;
	        while((length = reader.read(buf)) > 0) {
	            result.append(buf, 0, length);
	        }
	    } finally {
	        Closer.close(reader);
	    }
	    return result;
	}

	/**
	 * Reliably skip a number of bytes or throw.
	 */
	public static void skipFully(InputStream is, long skip) throws IOException {
		long skipped = 0;
		while(skipped < skip) {
			long x = is.skip(skip - skipped);
			if(x <= 0) throw new IOException("Unable to skip "+(skip - skipped)+" bytes");
			skipped += x;
		}
	}

	public static boolean writeTo(InputStream input, File target) throws FileNotFoundException, IOException {
		DataInputStream dis = null;
		FileOutputStream fos = null;
		File file = File.createTempFile("temp", ".tmp", target.getParentFile());
		if(logMINOR)
			Logger.minor(FileUtil.class, "Writing to "+file+" to be renamed to "+target);

		try {
			dis = new DataInputStream(input);
			fos = new FileOutputStream(file);

			int len = 0;
			byte[] buffer = new byte[4096];
			while ((len = dis.read(buffer)) > 0) {
				fos.write(buffer, 0, len);
			}
		} finally {
			if(dis != null) dis.close();
			if(fos != null) fos.close();
		}

		if(FileUtil.renameTo(file, target))
			return true;
		else {
			file.delete();
			return false;
		}
	}

        public static boolean renameTo(File orig, File dest) {
            // Try an atomic rename
            // Shall we prevent symlink-race-conditions here ?
            if(orig.equals(dest))
                throw new IllegalArgumentException("Huh? the two file descriptors are the same!");
            if(!orig.exists()) {
            	throw new IllegalArgumentException("Original doesn't exist!");
            }
            if (!orig.renameTo(dest)) {
                // Not supported on some systems (Windows)
                if (!dest.delete()) {
                    if (dest.exists()) {
                        Logger.error("FileUtil", "Could not delete " + dest + " - check permissions");
                        System.err.println("Could not delete " + dest + " - check permissions");
                    }
                }
                if (!orig.renameTo(dest)) {
                	String err = "Could not rename " + orig + " to " + dest +
                    	(dest.exists() ? " (target exists)" : "") +
                    	(orig.exists() ? " (source exists)" : "") +
                    	" - check permissions";
                    Logger.error(FileUtil.class, err);
                    System.err.println(err);
                    return false;
                }
            }
            return true;
        }

        /**
         * Like renameTo(), but can move across filesystems, by copying the data.
         * @param orig
         * @param dest
         * @param overwrite
         */
    	public static boolean moveTo(File orig, File dest, boolean overwrite) {
            if(orig.equals(dest))
                throw new IllegalArgumentException("Huh? the two file descriptors are the same!");
            if(!orig.exists()) {
            	throw new IllegalArgumentException("Original doesn't exist!");
            }
            if(dest.exists()) {
            	if(overwrite)
            		dest.delete();
            	else {
            		System.err.println("Not overwriting "+dest+" - already exists moving "+orig);
            		return false;
            	}
            }
    		if(!orig.renameTo(dest))
    		    return copyFile(orig, dest);
    		else return true;
    	}

    /**
     * Sanitizes the given filename to be valid on the given operating system.
     * If OperatingSystem.Unknown is specified this function will generate a filename which fullfils the restrictions of all known OS, currently
     * this is MacOS, Unix and Windows.
     */
	public static String sanitizeFileName(final String fileName, OperatingSystem targetOS, String extraChars) {
		// Filter out any characters which do not exist in the charset.
		final CharBuffer buffer = fileNameCharset.decode(fileNameCharset.encode(fileName)); // Charset are thread-safe

		final StringBuilder sb = new StringBuilder(fileName.length() + 1);

		switch(targetOS) {
			case Unknown: break;
			case MacOS: break;
			case Linux: break;
			case FreeBSD: break;
			case GenericUnix: break;
			case Windows: break;
			default:
				Logger.error(FileUtil.class, "Unsupported operating system: " + targetOS);
				targetOS = OperatingSystem.Unknown;
				break;
		}
		
		char def = ' ';
		if(extraChars.indexOf(' ') != -1) {
			def = '_';
			if(extraChars.indexOf(def) != -1) {
				def = '-';
				if(extraChars.indexOf(def) != -1)
					throw new IllegalArgumentException("What do you want me to use instead of spaces???");
			}
		}

		for(char c : buffer.array()) { // Note that this will add extra whitespace to the end, which we will trim later.
			
			if(extraChars.indexOf(c) != -1) {
				sb.append(def);
				continue;
			}
			
			// Control characters and whitespace are converted to space for all OS.
			// We do not check for the file separator character because it is included in each OS list of reserved characters.
			if(Character.getType(c) == Character.CONTROL || Character.isWhitespace(c)) {
				sb.append(def);
				continue;
			}


			if(targetOS == OperatingSystem.Unknown || targetOS.isWindows) {
				if(StringValidityChecker.isWindowsReservedPrintableFilenameCharacter(c)) {
					sb.append(def);
					continue;
				}
			}

			if(targetOS == OperatingSystem.Unknown || targetOS.isMac) {
				if(StringValidityChecker.isMacOSReservedPrintableFilenameCharacter(c)) {
					sb.append(def);
					continue;
				}
			}
			
			if(targetOS == OperatingSystem.Unknown || targetOS.isUnix) {
				if(StringValidityChecker.isUnixReservedPrintableFilenameCharacter(c)) {
					sb.append(def);
					continue;
				}
			}
			
			// Nothing did continue; so the character is okay
			sb.append(c);
		}

		// In windows, the last character of a filename may not be space or dot. We cut them off
		if(targetOS == OperatingSystem.Unknown || targetOS.isWindows) {
			int lastCharIndex = sb.length() - 1;
			while(lastCharIndex >= 0) {
				char lastChar = sb.charAt(lastCharIndex);
				if(lastChar == ' ' ||  lastChar == '.')
					sb.deleteCharAt(lastCharIndex--);
				else
					break;
			}
		}

		// Now the filename might be one of the reserved filenames in Windows (CON etc.) and we must replace it if it is...
		if(targetOS == OperatingSystem.Unknown || targetOS.isWindows) {
			if(StringValidityChecker.isWindowsReservedFilename(sb.toString()))
				sb.insert(0, '_');
		}

		if(sb.length() == 0) {
			sb.append("Invalid filename"); // TODO: L10n
		}

		return sb.toString().trim(); // Trim leading and trailing whitespace.
		// Some of the trailing whitespace may be from the CharBuffer.
	}

	public static String sanitize(String fileName) {
		return sanitizeFileName(fileName, detectedOS, "");
	}

	public static String sanitizeFileNameWithExtras(String fileName, String extraChars) {
		return sanitizeFileName(fileName, detectedOS, extraChars);
	}


	public static String sanitize(String filename, String mimeType) {
		filename = sanitize(filename);
		if(mimeType == null) return filename;
		return DefaultMIMETypes.forceExtension(filename, mimeType);
	}

	/**
	 * Find the length of an input stream. This method will consume the complete
	 * input stream until its {@link InputStream#read(byte[])} method returns
	 * <code>-1</code>, thus signalling the end of the stream.
	 *
	 * @param source
	 *            The input stream to find the length of
	 * @return The numbe of bytes that can be read from the stream
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static long findLength(InputStream source) throws IOException {
		long length = 0;
		byte[] buffer = new byte[BUFFER_SIZE];
		int read = 0;
		while (read > -1) {
			read = source.read(buffer);
			if (read != -1) {
				length += read;
			}
		}
		return length;
	}

	/**
	 * Copies <code>length</code> bytes from the source input stream to the
	 * destination output stream. If <code>length</code> is <code>-1</code>
	 * as much bytes as possible will be copied (i.e. until
	 * {@link InputStream#read()} returns <code>-1</code> to signal the end of
	 * the stream).
	 *
	 * @param source
	 *            The input stream to read from
	 * @param destination
	 *            The output stream to write to
	 * @param length
	 *            The number of bytes to copy
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static void copy(InputStream source, OutputStream destination, long length) throws IOException {
		long remaining = length;
		byte[] buffer = new byte[BUFFER_SIZE];
		int read = 0;
		while ((remaining == -1) || (remaining > 0)) {
			read = source.read(buffer, 0, ((remaining > BUFFER_SIZE) || (remaining == -1)) ? BUFFER_SIZE : (int) remaining);
			if (read == -1) {
				if (length == -1) {
					return;
				}
				throw new EOFException("stream reached eof");
			}
			destination.write(buffer, 0, read);
			if (remaining > 0)
				remaining -= read;
		}
	}
	
	public static boolean secureDeleteAll(File wd) throws IOException {
		if(!wd.isDirectory()) {
			System.err.println("DELETING FILE "+wd);
			try {
				secureDelete(wd);
			} catch (IOException e) {
				Logger.error(FileUtil.class, "Could not delete file: "+wd, e);
				return false;
			}
		} else {
			for(File subfile: wd.listFiles()) {
				if(!removeAll(subfile)) return false;
			}
			if(!wd.delete()) {
				Logger.error(FileUtil.class, "Could not delete directory: "+wd);
			}
		}
		return true;
	}


	/** Delete everything in a directory. Only use this when we are *very sure* there is no
	 * important data below it! */
	public static boolean removeAll(File wd) {
		if(!wd.isDirectory()) {
			System.err.println("DELETING FILE "+wd);
			if(!wd.delete() && wd.exists()) {
				Logger.error(FileUtil.class, "Could not delete file: "+wd);
				return false;
			}
		} else {
			for(File subfile: wd.listFiles()) {
				if(!removeAll(subfile)) return false;
			}
			if(!wd.delete()) {
				Logger.error(FileUtil.class, "Could not delete directory: "+wd);
			}
		}
		return true;
	}
	
	public static void secureDelete(File file) throws IOException {
		// FIXME somebody who understands these things should have a look at this...
		if(!file.exists()) return;
		long size = file.length();
		if(size > 0) {
			RandomAccessFile raf = null;
			try {
				System.out.println("Securely deleting "+file+" which is of length "+size+" bytes...");
				raf = new RandomAccessFile(file, "rw");
				long count;
				// Random data first.
				raf.seek(0);
				fill(new RandomAccessFileOutputStream(raf), size);
				raf.getFD().sync();
				raf.close();
				raf = null;
			} finally {
				Closer.close(raf);
			}
		}
		if((!file.delete()) && file.exists())
			throw new IOException("Unable to delete file "+file);
	}

	/**
	** Set owner-only RW on the given file.
	*/
	public static boolean setOwnerRW(File f) {
		return setOwnerPerm(f, true, true, false);
	}

	/**
	** Set owner-only RWX on the given file.
	*/
	public static boolean setOwnerRWX(File f) {
		return setOwnerPerm(f, true, true, true);
	}

	/**
	** Set owner-only permissions on the given file.
	*/
	public static boolean setOwnerPerm(File f, boolean r, boolean w, boolean x) {
		/* JDK6 replace when we upgrade
		boolean b = f.setReadable(false, false);
		b &= f.setWritable(false, false);
		b &= f.setExecutable(false, false);
		b &= f.setReadable(r, true);
		b &= f.setWritable(w, true);
		b &= f.setExecutable(x, true);
		return b;
		*/

		boolean success = true;
		try {

			String[] methods = {"setReadable", "setWritable", "setExecutable"};
			boolean[] perms = {r, w, x};

			for (int i=0; i<methods.length; ++i) {
				Method m = File.class.getDeclaredMethod(methods[i], boolean.class, boolean.class);
				if (m != null) {
					success &= (Boolean)m.invoke(f, false, false);
					success &= (Boolean)m.invoke(f, perms[i], true);
				}
			}

		} catch (NoSuchMethodException e) {
			success = false;
		} catch (java.lang.reflect.InvocationTargetException e) {
			success = false;
		} catch (IllegalAccessException e) {
			success = false;
		} catch (ExceptionInInitializerError e) {
			success = false;
		} catch (RuntimeException e) {
			success = false;
		}
		return success;
	}

	public static boolean equals(File a, File b) {
	    if(a == b) return true;
	    if(a.equals(b)) return true;
		a = getCanonicalFile(a);
		b = getCanonicalFile(b);
		return a.equals(b);
	}

	/** Create a temp file in a specific directory. Null = ".". 
	 * @throws IOException */
	public static File createTempFile(String prefix, String suffix,
			File directory) throws IOException {
		if(directory == null) directory = new File(".");
		return File.createTempFile(prefix, suffix, directory);
	}

	public static boolean copyFile(File copyFrom, File copyTo) {
		copyTo.delete();
		boolean executable = copyFrom.canExecute();
		FileBucket outBucket = new FileBucket(copyTo, false, true, false, false);
		FileBucket inBucket = new FileBucket(copyFrom, true, false, false, false);
		try {
			BucketTools.copy(inBucket, outBucket);
			if(executable) {
			    if(!(copyTo.setExecutable(true) || copyTo.canExecute())) {
			        System.err.println("Unable to preserve executable bit when copying "+copyFrom+" to "+copyTo+" - you may need to make it executable!");
			        // return false; ??? FIXME debatable.
			    }
			}
			return true;
		} catch (IOException e) {
			System.err.println("Unable to copy from "+copyFrom+" to "+copyTo);
			return false;
		}
	}
	
	private static CipherInputStream cis;
	private static ZeroInputStream zis = new ZeroInputStream();
	private static long cisCounter;
	
	/** Write hard to identify random data to the OutputStream. Does not drain the global secure 
	 * random number generator, and is significantly faster than it.
	 * @param os The stream to write to.
	 * @param length The number of bytes to write.
	 * @throws IOException If unable to write to the stream.
	 */
	public static void fill(OutputStream os, long length) throws IOException {
	    long remaining = length;
	    byte[] buffer = new byte[BUFFER_SIZE];
	    int read = 0;
	    while ((remaining == -1) || (remaining > 0)) {
	        synchronized(FileUtil.class) {
	            if(cis == null || cisCounter > Long.MAX_VALUE/2) {
	                // Reset it well before the birthday paradox (note this is actually counting bytes).
	                byte[] key = new byte[16];
	                byte[] iv = new byte[16];
	                SecureRandom rng = NodeStarter.getGlobalSecureRandom();
	                rng.nextBytes(key);
	                rng.nextBytes(iv);
	                AESFastEngine e = new AESFastEngine();
	                SICBlockCipher ctr = new SICBlockCipher(e);
	                ctr.init(true, new ParametersWithIV(new KeyParameter(key),iv));
	                cis = new CipherInputStream(zis, new BufferedBlockCipher(ctr));
	                cisCounter = 0;
	            }
	            read = cis.read(buffer, 0, ((remaining > BUFFER_SIZE) || (remaining == -1)) ? BUFFER_SIZE : (int) remaining);
	            cisCounter += read;
	        }
	        if (read == -1) {
	            if (length == -1) {
	                return;
	            }
	            throw new EOFException("stream reached eof");
	        }
	        os.write(buffer, 0, read);
	        if (remaining > 0)
	            remaining -= read;
	    }
	    
	}

	/** @deprecated */
	@Deprecated
    public static void fill(OutputStream os, Random random, long length) throws IOException {
        long moved = 0;
        byte[] buf = new byte[BUFFER_SIZE];
        while(moved < length) {
            int toRead = (int)Math.min(BUFFER_SIZE, length - moved);
            random.nextBytes(buf);
            os.write(buf, 0, toRead);
            moved += toRead;
        }
    }

    public static boolean equalStreams(InputStream a, InputStream b, long size) throws IOException {
        byte[] aBuffer = new byte[BUFFER_SIZE];
        byte[] bBuffer = new byte[BUFFER_SIZE];
        DataInputStream aIn = new DataInputStream(a);
        DataInputStream bIn = new DataInputStream(b);
        long checked = 0;
        while(checked < size) {
            int toRead = (int)Math.min(BUFFER_SIZE, size - checked);
            aIn.readFully(aBuffer, 0, toRead);
            bIn.readFully(bBuffer, 0, toRead);
            if(!MessageDigest.isEqual(aBuffer, bBuffer))
                return false;
            checked += toRead;
        }
        return true;
    }

}
