package freenet.pluginmanager;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import freenet.config.SubConfig;
import freenet.crypt.AEADCryptBucket;
import freenet.node.FSParseException;
import freenet.node.Node;
import freenet.node.NodeInitException;
import freenet.node.ProgramDirectory;
import freenet.support.IllegalBase64Exception;
import freenet.support.SimpleFieldSet;
import freenet.support.api.Bucket;
import freenet.support.io.FileBucket;
import freenet.support.io.FileUtil;
import freenet.support.io.PaddedBucket;

public class PluginStores {
    
    final Node node;
    private final ProgramDirectory pluginStoresDir;
    
    public PluginStores(Node node, SubConfig installConfig) throws NodeInitException {
        this.node = node;
        pluginStoresDir = node.setupProgramDir(installConfig, "pluginStoresDir", "plugin-data", 
                "NodeClientCore.pluginStoresDir", "NodeClientCore.pluginStoresDir", null);
        File dir = pluginStoresDir.dir();
        if(!(dir.mkdirs() || (dir.exists() && dir.isDirectory() && dir.canRead() && dir.canWrite()))) {
            System.err.println("Unable to create folder for plugin data: "+pluginStoresDir.dir());
        }
    }

    private void writePluginStoreInner(String storeIdentifier, PluginStore pluginStore, boolean isEncrypted, boolean backup) throws IOException {
        Bucket bucket = makePluginStoreBucket(storeIdentifier, isEncrypted, backup);
        OutputStream os = bucket.getOutputStream();
        try {
            if(pluginStore != null) {
                pluginStore.exportStoreAsSFS().writeTo(os);
            }
        } finally {
            os.close();
        }
    }
    
    private File getPluginStoreFile(String storeIdentifier, boolean encrypted, boolean backup) {
        String filename = storeIdentifier;
        filename += ".data";
        if(backup)
            filename += ".bak";
        if(encrypted)
            filename += ".crypt";
        return pluginStoresDir.file(filename);
    }

    private Bucket makePluginStoreBucket(String storeIdentifier, boolean isEncrypted, boolean backup) 
    throws FileNotFoundException {
        File f = getPluginStoreFile(storeIdentifier, isEncrypted, backup);
        Bucket bucket = new FileBucket(f, false, true, false, false);
        if(isEncrypted) {
            byte[] key = node.getPluginStoreKey(storeIdentifier);
            if(key != null) {
                // We pad then encrypt, which is wasteful, but we have no way to persist the size.
                // Unfortunately AEADCryptBucket needs to know the real termination point.
                bucket = new AEADCryptBucket(bucket, key);
                bucket = new PaddedBucket(bucket);
            }
        }
        return bucket;
    }
    
    private Bucket findPluginStoreBucket(String storeIdentifier, boolean isEncrypted, boolean backup) 
    throws FileNotFoundException {
        File f = getPluginStoreFile(storeIdentifier, isEncrypted, backup);
        if(!f.exists()) return null;
        Bucket bucket = new FileBucket(f, false, false, false, false);
        if(isEncrypted) {
            byte[] key = node.getPluginStoreKey(storeIdentifier);
            if(key != null) {
                // We pad then encrypt, which is wasteful, but we have no way to persist the size.
                // Unfortunately AEADCryptBucket needs to know the real termination point.
                bucket = new AEADCryptBucket(bucket, key);
                bucket = new PaddedBucket(bucket, bucket.size());
            }
        }
        return bucket;
    }

    public PluginStore loadPluginStore(String storeIdentifier) {
        boolean isEncrypted = node.wantEncryptedDatabase();
        PluginStore store = loadPluginStore(storeIdentifier, isEncrypted, false);
        if(store != null) return store;
        store = loadPluginStore(storeIdentifier, isEncrypted, true);
        if(store != null) return store;
        isEncrypted = !isEncrypted;
        store = loadPluginStore(storeIdentifier, isEncrypted, false);
        if(store != null) return store;
        store = loadPluginStore(storeIdentifier, isEncrypted, true);
        return store;
    }
    
    private PluginStore loadPluginStore(String storeIdentifier, boolean isEncrypted, boolean backup) {
        Bucket bucket;
        try {
            bucket = findPluginStoreBucket(storeIdentifier, isEncrypted, backup);
            if(bucket == null) return null;
        } catch (FileNotFoundException e) {
            return null;
        }
        InputStream is = null;
        try {
            try {
                is = bucket.getInputStream();
                SimpleFieldSet fs = SimpleFieldSet.readFrom(is, false, false, true, true);
                return new PluginStore(fs);
            } finally {
                // Do NOT use Closer.close().
                // We use authenticated encryption, which will throw at close() time if the file is corrupt,
                // or has been modified while the node was offline etc.
                if(is != null) is.close();
            }
        } catch (IOException e) {
            // Hence, if close() throws, we DO need to catch it here.
            System.err.println("Unable to load plugin data for "+storeIdentifier+" : "+e);
            System.err.println("This could be caused by data corruption or bugs in Freenet.");
            // FIXME crypto - possible it's caused by attack while offline.
            return null;
        } catch (IllegalBase64Exception e) {
            // Hence, if close() throws, we DO need to catch it here.
            System.err.println("Unable to load plugin data for "+storeIdentifier+" : "+e);
            System.err.println("This could be caused by data corruption or bugs in Freenet.");
            // FIXME crypto - possible it's caused by attack while offline.
            return null;
        } catch (FSParseException e) {
            // Hence, if close() throws, we DO need to catch it here.
            System.err.println("Unable to load plugin data for "+storeIdentifier+" : "+e);
            System.err.println("This could be caused by data corruption or bugs in Freenet.");
            // FIXME crypto - possible it's caused by attack while offline.
            return null;
        }
    }

    public void writePluginStore(String storeIdentifier, PluginStore store) throws IOException {
        boolean isEncrypted = node.wantEncryptedDatabase();
        File backup = getPluginStoreFile(storeIdentifier, isEncrypted, true);
        File main = getPluginStoreFile(storeIdentifier, isEncrypted, false);
        if(backup.exists() && main.exists()) {
            FileUtil.secureDelete(backup);
        }
        if(main.exists()) {
            if(!main.renameTo(backup))
                System.err.println("Unable to rename "+main+" to "+backup+" when writing pluginstore for "+storeIdentifier);
        }
        writePluginStoreInner(storeIdentifier, store, isEncrypted, false);
        File f = getPluginStoreFile(storeIdentifier, !isEncrypted, true);
        if(f.exists()) {
            FileUtil.secureDelete(f);
        }
        f = getPluginStoreFile(storeIdentifier, !isEncrypted, false);
        if(f.exists()) {
            FileUtil.secureDelete(f);
        }
    }

}
