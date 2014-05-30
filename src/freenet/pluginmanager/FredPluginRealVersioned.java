/*
 * This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL.
 */



package freenet.pluginmanager;

/** Version of a plugin in a form that is easy to compare. */
public interface FredPluginRealVersioned {

    /**
     * The version of the plugin in a form that is easy to compare: a long!
     * Version 150 will always be later than version 20. 
     */
    public long getRealVersion();

    // There is no point in reporting the dependancies or the minimum node version,
    // because we have already been loaded!
    // SVN revisions are going away, so there is no point returning them either.
    // Git has hashes, which are strings.
}
