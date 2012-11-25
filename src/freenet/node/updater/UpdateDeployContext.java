package freenet.node.updater;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Properties;
import java.util.regex.Pattern;

import org.tanukisoftware.wrapper.WrapperManager;

import freenet.l10n.NodeL10n;
import freenet.node.NodeInitException;
import freenet.node.updater.MainJarDependenciesChecker.Dependency;
import freenet.node.updater.MainJarDependenciesChecker.MainJarDependencies;
import freenet.support.io.Closer;

/**
 * Handles the wrapper.conf, essentially.
 */
public class UpdateDeployContext {

	public static class UpdateCatastropheException extends Exception {

		private static final long serialVersionUID = 1L;
		File oldConfig;
		File newConfig;
		
		UpdateCatastropheException(File oldConfig, File newConfig) {
			super(l10n("updateCatastrophe", new String[] { "old", "new" },
					new String[] { oldConfig.toString(), newConfig.toString() }));
			this.oldConfig = oldConfig;
			this.newConfig = newConfig;
		}
		
	}

	File mainJar;
	int mainClasspathNo;
	int extClasspathNo;
	File newMainJar;
	boolean mainJarAbsolute;
	final MainJarDependencies deps;
	
	UpdateDeployContext(MainJarDependencies deps) throws UpdaterParserException {
		Properties p = WrapperManager.getProperties();
		this.deps = deps;
		
		for(int propNo=1;true;propNo++) {
			String prop = p.getProperty("wrapper.java.classpath."+propNo);
			if(prop == null) break;
			File f = new File(prop);
			boolean isAbsolute = f.isAbsolute();
			String name = f.getName().toLowerCase();
			if(mainJar == null) {
				if(name.equals("freenet-ext.jar") || name.equals("freenet-ext.jar.new") || (name.startsWith("freenet-ext") && name.endsWith(".jar")))
					// Don't match freenet-ext.jar!
					continue;
				// Try to match it
				if((name.startsWith("freenet") && (name.endsWith(".jar")))) {
					mainJar = f;
					newMainJar = new File(mainJar.getParent(), "freenet.jar.new");
					mainJarAbsolute = isAbsolute;
					mainClasspathNo = propNo;
					continue;
				} else if((name.startsWith("freenet") && (name.endsWith(".jar.new")))) {
					mainJar = f;
					newMainJar = new File(mainJar.getParent(), "freenet.jar");
					mainJarAbsolute = isAbsolute;
					mainClasspathNo = propNo;
					continue;
				}
			}
			// Else try to match from dependencies.
			
		}
		
		if(mainJar == null)
			throw new UpdaterParserException(l10n("cannotUpdateNoMainJar"));
	}

	private String l10n(String key) {
		return NodeL10n.getBase().getString("UpdateDeployContext."+key);
	}

	public static String l10n(String key, String[] patterns, String[] values) {
		return NodeL10n.getBase().getString("UpdateDeployContext."+key, patterns, values);
	}

	public static String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("UpdateDeployContext."+key, pattern, value);
	}

	File getMainJar() {
		return mainJar;
	}

	File getNewMainJar() {
		return newMainJar;
	}

	void rewriteWrapperConf(boolean writtenNewJar) throws IOException, UpdateCatastropheException, UpdaterParserException {
		
		// Rewrite wrapper.conf
		// Don't just write it out from properties; we want to keep it as close to what it was as possible.

		File oldConfig = new File("wrapper.conf");
		File newConfig = new File("wrapper.conf.new");
		
		if(!oldConfig.exists()) {
			File wrapperDir = new File("wrapper");
			if(wrapperDir.exists() && wrapperDir.isDirectory()) {
				File o = new File(wrapperDir, "wrapper.conf");
				if(o.exists()) {
					oldConfig = o;
					newConfig = new File(wrapperDir, "wrapper.conf.new");
				}
			}
		}
		
		FileInputStream fis = new FileInputStream(oldConfig);
		BufferedInputStream bis = new BufferedInputStream(fis);
		InputStreamReader isr = new InputStreamReader(bis);
		BufferedReader br = new BufferedReader(isr);
		
		FileOutputStream fos = new FileOutputStream(newConfig);
		OutputStreamWriter osw = new OutputStreamWriter(fos);
		BufferedWriter bw = new BufferedWriter(osw);

		String line;
			
		boolean writtenReload = false;
		
		String newMain = mainJarAbsolute ? newMainJar.getAbsolutePath() : newMainJar.getPath();
		
		String mainRHS = null;
		
		ArrayList<String> otherLines = new ArrayList<String>();
		ArrayList<String> classpath = new ArrayList<String>();
		
		// We MUST put the ext (and all other dependencies) before the main jar, 
		// or auto-update of freenet-ext.jar on Windows won't work.
		// The main jar refers to freenet-ext.jar so that java -jar freenet.jar works.
		// Therefore, on Windows, if we update freenet-ext.jar, it will use freenet.jar and freenet-ext.jar
		// and freenet-ext.jar.new as well. The old freenet-ext.jar will take precedence, and we won't be
		// able to overwrite either of them, so we'll just restart every 5 minutes forever!
		
		while((line = br.readLine()) != null) {
			// The classpath numbers are not reliable.
			// We have to check the content.
			
			boolean dontWrite = false;
			
			if(line.startsWith("wrapper.java.classpath.")) {
				line = line.substring("wrapper.java.classpath.".length());
				int idx = line.indexOf('=');
				if(idx != -1) {
					// Ignore the numbers.
					String rhs = line.substring(idx+1);
					dontWrite = true;
					if(rhs.equals("freenet.jar") || rhs.equals("freenet.jar.new") || 
							rhs.equals("freenet-stable-latest.jar") || rhs.equals("freenet-stable-latest.jar.new") ||
							rhs.equals("freenet-testing-latest.jar") || rhs.equals("freenet-testing-latest.jar.new")) {
						if(writtenNewJar)
							mainRHS = newMain;
						else
							mainRHS = rhs;
					} else {
						// Is it on the list of dependencies?
						Dependency dep = findDependencyByRHSFilename(new File(rhs));
						if(dep != null) {
							System.out.println("Found dependency "+dep.oldFilename());
						} else { // dep == null
							// If not, it's something the user has added, we just keep it.
							classpath.add(rhs);
						}
					}
				}
			} else if(line.equalsIgnoreCase("wrapper.restart.reload_configuration=TRUE")) {
				writtenReload = true;
			}
			if(!dontWrite)
				otherLines.add(line);
		}
		br.close();
		
		// Write classpath first
		
		if(mainRHS == null) {
			bw.close();
			throw new UpdaterParserException(l10n("updateFailedNonStandardConfig", 
					new String[] { "main" }, new String[] { Boolean.toString(mainRHS != null) } ));
		}
		
		// As above, we need to write ALL the dependencies BEFORE we write the main jar.
		int count = 1; // Classpath is 1-based.
		for(Dependency d : deps.dependencies) {
			bw.write("wrapper.java.classpath."+count+"="+d.newFilename()+'\n');
			count++;
		}
		
		// Write the main jar.
		bw.write("wrapper.java.classpath."+count+"="+mainRHS+'\n');
		count++;
		for(String s : classpath) {
			bw.write("wrapper.java.classpath."+count+"="+s+'\n');
			count++;
		}
		
		for(String s : otherLines)
			bw.write(s+'\n');

		if(!writtenReload) {
			// Add it.
			bw.write("wrapper.restart.reload_configuration=TRUE\n");
		}
		
		bw.close();

		if(!newConfig.renameTo(oldConfig)) {
			if(!oldConfig.delete()) {
				throw new UpdaterParserException(l10n("updateFailedCannotDeleteOldConfig", "old", oldConfig.toString()));
			}
			if(!newConfig.renameTo(oldConfig)) {
				throw new UpdateCatastropheException(oldConfig, newConfig);
			}
		}
		
		// New config installed.
		
		System.err.println("Rewritten wrapper.conf for build "+deps.build+" and "+deps.dependencies.size()+" dependencies.");
	}

	private Dependency findDependencyByRHSFilename(File rhs) {
		String rhsName = rhs.getName().toLowerCase();
		for(Dependency dep : deps.dependencies) {
			File f = dep.oldFilename();
			if(f == null) {
				// Not in use.
				continue;
			}
			if(rhs.equals(f)) return dep;
			if(rhsName.equals(f.getName())) return dep;
		}
		for(Dependency dep : deps.dependencies) {
			Pattern p = dep.regex();
			if(p != null) {
				if(p.matcher(rhs.getName().toLowerCase()).matches()) return dep;
			}
		}
		return null;
	}

	public enum CHANGED {
		ALREADY, // Found the comment, so it has already been changed
		SUCCESS, // Succeeded
		FAIL // Failed e.g. due to unable to write wrapper.conf.
	}

	public static CHANGED tryIncreaseMemoryLimit(int extraMemoryMB,
			String markerComment) {
		// Rewrite wrapper.conf
		// Don't just write it out from properties; we want to keep it as close to what it was as possible.

		File oldConfig = new File("wrapper.conf");
		File newConfig = new File("wrapper.conf.new");
		
		if(!oldConfig.exists()) {
			File wrapperDir = new File("wrapper");
			if(wrapperDir.exists() && wrapperDir.isDirectory()) {
				File o = new File(wrapperDir, "wrapper.conf");
				if(o.exists()) {
					oldConfig = o;
					newConfig = new File(wrapperDir, "wrapper.conf.new");
				}
			}
		}
		
		FileInputStream fis = null;
		BufferedInputStream bis = null;
		InputStreamReader isr = null;
		BufferedReader br = null;
		FileOutputStream fos = null;
		OutputStreamWriter osw = null;
		BufferedWriter bw = null;
		
		boolean success = false;
		
		try {
		
		fis = new FileInputStream(oldConfig);
		bis = new BufferedInputStream(fis);
		isr = new InputStreamReader(bis);
		br = new BufferedReader(isr);
		
		fos = new FileOutputStream(newConfig);
		osw = new OutputStreamWriter(fos);
		bw = new BufferedWriter(osw);

		String line;
		
		while((line = br.readLine()) != null) {
			
			if(line.equals("#" + markerComment))
				return CHANGED.ALREADY;
			
			if(line.startsWith("wrapper.java.maxmemory=")) {
				try {
					int memoryLimit = Integer.parseInt(line.substring("wrapper.java.maxmemory=".length()));
					int newMemoryLimit = memoryLimit + extraMemoryMB;
					// There have been some cases where really high limits have caused the JVM to do bad things.
					if(newMemoryLimit > 2048) newMemoryLimit = 2048;
					bw.write('#' + markerComment + '\n');
					bw.write("wrapper.java.maxmemory="+newMemoryLimit+'\n');
					success = true;
					continue;
				} catch (NumberFormatException e) {
					// Grrrrr!
				}
			}
			
			bw.write(line+'\n');
		}
		br.close();
		
		} catch (IOException e) {
			newConfig.delete();
			System.err.println("Unable to rewrite wrapper.conf with new memory limit.");
			return CHANGED.FAIL;
		} finally {
			Closer.close(br);
			Closer.close(isr);
			Closer.close(bis);
			Closer.close(fis);
			Closer.close(bw);
			Closer.close(osw);
			Closer.close(fos);
		}
		
		if(success) {
			if(!newConfig.renameTo(oldConfig)) {
				if(!oldConfig.delete()) {
					System.err.println("Unable to move rewritten wrapper.conf with new memory limit "+newConfig+" over old config "+oldConfig+" : unable to delete old config");
					return CHANGED.FAIL;
				}
				if(!newConfig.renameTo(oldConfig)) {
					System.err.println("Old wrapper.conf deleted but new wrapper.conf cannot be renamed!");
					System.err.println("FREENET WILL NOT START UNTIL YOU RENAME "+newConfig+" to "+oldConfig);
					System.exit(NodeInitException.EXIT_BROKE_WRAPPER_CONF);
				}
			}
			System.err.println("Rewritten wrapper.conf for new memory limit");
			return CHANGED.SUCCESS;
		} else {
			newConfig.delete();
			return CHANGED.FAIL;
		}
	}

}
