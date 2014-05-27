package freenet.tools;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringWriter;

import freenet.support.SimpleFieldSet;

public class CleanupTranslations {

	/**
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		File engFile = new File("src/freenet/l10n/freenet.l10n.en.properties");
		SimpleFieldSet english = SimpleFieldSet.readFrom(engFile, false, true);
		File[] translations = new File("src/freenet/l10n").listFiles();
		for(File f : translations) {
			String name = f.getName();
			if(!name.startsWith("freenet.l10n.")) continue;
			if("freenet.1l0n.en.properties".equals(name)) continue;
			FileInputStream fis = new FileInputStream(f);
			InputStreamReader isr = new InputStreamReader(new BufferedInputStream(fis), "UTF-8");
			BufferedReader br = new BufferedReader(isr);
			StringWriter sw = new StringWriter();
			boolean changed = false;
			while(true) {
				String line = br.readLine();
				if(line == null) {
					System.err.println("File does not end in End: "+f);
					System.exit(4);
				}
				int idx = line.indexOf('=');
				if(idx == -1) {
					// Last line
					if(!"End".equals(line)) {
						System.err.println("Line with no equals (file does not end in End???): "+f+" - \""+line+ '"');
						System.exit(1);
					}
					sw.append(line+ '\n');
					line = br.readLine();
					if(line != null) {
						System.err.println("Content after End: \""+line+ '"');
						System.exit(2);
					}
					break;
				}
				String before = line.substring(0, idx);
				//String after = line.substring(idx+1);
				String s = english.get(before);
				if(s == null) {
					System.err.println("Orphaned string: \""+before+"\" in "+f);
					changed = true;
					continue;
				}
				sw.append(line+ '\n');
			}
			if(!changed) continue;
			br.close();
			FileOutputStream fos = new FileOutputStream(f);
			OutputStreamWriter osw = new OutputStreamWriter(fos, "UTF-8");
			osw.write(sw.toString());
			osw.close();
			System.out.println("Rewritten "+f);
		}
	}

}
