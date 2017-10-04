/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.async;

import java.util.HashMap;
import java.util.Map;

import freenet.client.InsertContext;
import freenet.keys.FreenetURI;
import freenet.support.Logger;
import freenet.support.api.ManifestElement;
import freenet.support.io.ResumeFailedException;

/**
 * <P>plain/dumb manifest putter: every file item is a redirect (no containers at all)
 * 
 * <P>default doc:<BR>
 * defaultName is just the name, without any '/'!<BR>
 * each item &lt;defaultName&gt; is the default doc in the corresponding dir.
 */

public class PlainManifestPutter extends BaseManifestPutter {

    private static final long serialVersionUID = 1L;
    private static volatile boolean logDEBUG;

	static {
		Logger.registerClass(PlainManifestPutter.class);
	}

	public PlainManifestPutter(ClientPutCallback clientCallback, HashMap<String, Object> manifestElements, short prioClass, FreenetURI target, String defaultName, InsertContext ctx,
			byte[] forceCryptoKey, ClientContext context) throws TooManyFilesInsertException {
		super(clientCallback, manifestElements, prioClass, target, defaultName, ctx, ClientPutter.randomiseSplitfileKeys(target, ctx), forceCryptoKey, context);
	}

	@Override
	protected void makePutHandlers(HashMap<String,Object> manifestElements, String defaultName) {
		if(logDEBUG) Logger.debug(this, "Root map : "+manifestElements.size()+" elements");
		makePutHandlers(getRootBuilder(), manifestElements, defaultName);
	}
	
	@SuppressWarnings("unchecked")
	private void makePutHandlers(FreeFormBuilder builder, HashMap<String, Object> manifestElements, Object defaultName) {
		for(Map.Entry<String, Object> entry:manifestElements.entrySet()) {
			String name = entry.getKey();
			Object o = entry.getValue();
			if(o instanceof HashMap) {
				HashMap<String,Object> subMap = (HashMap<String,Object>)o;
				builder.pushCurrentDir();
				builder.makeSubDirCD(name);
				makePutHandlers(builder, subMap, defaultName);
				builder.popCurrentDir();
				if(logDEBUG) Logger.debug(this, "Sub map for "+name+" : "+subMap.size()+" elements");
			} else {
				ManifestElement element = (ManifestElement) o;
				builder.addElement(name, element, name.equals(defaultName));
			}
		}
	}

    @Override
    public void innerOnResume(ClientContext context) throws ResumeFailedException {
        super.innerOnResume(context);
        notifyClients(context);
    }
}

