/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */
package freenet.client.filter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashMap;

import freenet.clients.http.ExternalLinkToadlet;
import freenet.l10n.NodeL10n;

/**
 * Content filter for M3Us
 *
 * This one kills every comment and ensures that every file is a safe
 * URL. Currently far too strict: allows only relative paths with as
 * letters alphanumeric or - and exactly one dot.
 *
 * The structure of a simple M3U is just a list of valid relative
 * URLs.  The structure of an extended M3U is as follows (taken from
 * http://schworak.com/blog/e39/m3u-play-list-specification/ ):
 *
 * #EXTM3U
 * #EXTINF:233,Title 1
 * Somewhere\title1.mp3
 * #EXTINF:129,Title 2
 * http://www.site.com/~user/title2.mp3
 * #EXTINF:-1,Stream
 * stream-2016-01-03.m3u
 *
 * #EXTM3U starts the File
 * #EXTINF:<length in seconds>,<title>
 * <path>
 *
 * Might be useful to extend to m3u8:
 * https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/StreamingMediaGuide/HTTPStreamingArchitecture/HTTPStreamingArchitecture.html#//apple_ref/doc/uid/TP40008332-CH101-SW10
 */
public class M3UFilter implements ContentDataFilter {

    static final byte[] CHAR_COMMENT_START =
        { (byte)'#' };
    static final byte[] CHAR_NEWLINE =
        { (byte)'\n' };
    static final byte[] CHAR_CARRIAGE_RETURN =
        { (byte)'\r' };
    static final int MAX_URI_LENGTH = 16384;
    static final String badUriReplacement = "#bad-uri-removed";
    private final long MAX_LENGTH_NO_PROGRESS = (100*1024*1024 * 11) / 10; // 100MiB: playlists are a different usecase, and we want to allow transparent pass-through for most files accessed via a playlist, likely through an external palyer. See FProxyToadlet.MAX_LENGTH_NO_PROGRESS for the default. This value must be synchronized with the test data!
    // TODO: Add parsing of ext-comments to allow for gapless playback.
    // static final int COMMENT_EXT_SIZE = 4;
    // static final byte[] COMMENT_EXT_START =
    //  { (byte)'#', (byte)'E', (byte)'X', (byte)'T' };
    // static final int EXT_HEADER_SIZE = 7;
    // static final byte[] EXT_HEADER =
    // { (byte)'#', (byte)'E', (byte)'X', (byte)'T', (byte)'M', (byte)'3', (byte)'U' };

    @Override
    public void readFilter(
        InputStream input, OutputStream output, String charset, HashMap<String, String> otherParams,
        String schemeHostAndPort, FilterCallback cb) throws DataFilterException, IOException {
        // TODO: Check the header whether this is an ext m3u.
        // TODO: Check the EXTINF headers instead of killing comments.
        // Check whether the line is a comment
        boolean isComment = false;
        boolean isBadUri = false;
        int numberOfDotsInUri = 0;
        int readcount;
        byte[] nextbyte = new byte[1];
        byte[] fileUri;
        int fileIndex;
        /* TODO: select the type per suffix. Right now we can get away
         * with just forcing mp3 since we only have a filter for
         * that.*/
        /* We need to force the type, because browsers might use
         * content type sniffing in the media tag and audio-players,
         * so people could insert as text/plain to circumvent the
         * filter.*/
        String uriForcetypeMp3Suffix = "?type=audio/mpeg";
        DataInputStream dis = new DataInputStream(input);
        DataOutputStream dos = new DataOutputStream(output);
        readcount = dis.read(nextbyte);
        // read each line manually
        while (readcount != -1) {
            if (isCommentStart(nextbyte)) {
                isComment = true;
            } else {
                isComment = false;
            }
            // skip empty lines
            if (isNewline(nextbyte)) {
                readcount = dis.read(nextbyte);
                continue;
            }
            // read one line as a fileUri
            numberOfDotsInUri = 0;
            isBadUri = false;
            fileIndex = 0;
            fileUri = new byte[MAX_URI_LENGTH];
            while (readcount != -1) {
                if (!isComment &&
                    // do not include carriage return in filenames
                    !isCarriageReturn(nextbyte) &&
                    // enforce maximum path length to avoid OOM attacks
                    fileIndex <= MAX_URI_LENGTH) {
                    // store the read byte
                    fileUri[fileIndex] = nextbyte[0];
                    fileIndex += readcount;
                }
                readcount = dis.read(nextbyte);
                if (isNewline(nextbyte) || readcount == -1) {
                    if (!isComment) {
                        // remove too long paths
                        if (fileIndex <= MAX_URI_LENGTH) {
                            boolean lineIsEmpty = fileIndex == 0;
                            if (!lineIsEmpty) {
                                String uriold = new String(fileUri, 0, fileIndex, "UTF-8");
                                // System.out.println(uriold);
                                // clean up the URL: allow sub-m3us and mp3/ogg/flac (what we can filter)
                                String filtered;
                                try {
                                    String subMimetype = ContentFilter.mimeTypeForSrc(uriold);
                                    // add prefix for the host name
                                    // for absolute path names,
                                    // because otherwise external
                                    // clients could be tricked into
                                    // accessing local files (and some
                                    // just don't work, especially not
                                    // with downloaded files). This
                                    // can however make downloaded
                                    // files leak information about
                                    // the local setup (host and
                                    // port).

                                    // mirroring tools like `wget -mk`
                                    // strip the absolute path again,
                                    // so mirroring should not be
                                    // impaired.
                                    filtered = cb.processURI(uriold, subMimetype,
                                        schemeHostAndPort, true);
                                    // allow transparent pass through
                                    // for all but the largest files,
                                    // but not for external
                                    // links. This check is safe,
                                    // since false positives will just
                                    // lead to a file to not be played
                                    // (players will get progress-bar
                                    // HTML content instead).
                                    if (!filtered.contains(ExternalLinkToadlet.PATH)
                                        && !filtered.contains(ExternalLinkToadlet.magicHTTPEscapeString)) {
                                        if (filtered.contains("?")) {
                                            filtered += "&";
                                        } else {
                                            filtered += "?";
                                        }
                                        filtered += "max-size=" + MAX_LENGTH_NO_PROGRESS;
                                    }

                                } catch (CommentException e) {
                                    filtered = badUriReplacement;
                                } catch (Exception e) {
                                    filtered = badUriReplacement;
                                }
                                if (filtered == null) {
                                    filtered = badUriReplacement;
                                }
                                try {
                                    dos.write(filtered.getBytes("UTF-8"));
                                } catch (Exception e) {
                                    dos.write(badUriReplacement.getBytes("UTF-8"));
                                }
                            }
                            // write the newline if we're not at EOF
                            if (readcount != -1){
                                dos.write(nextbyte);
                            }
                        }
                    }
                    // skip the newline
                    readcount = dis.read(nextbyte);
                    break; // skip to next line
                }
            }
        }
        dos.flush();
        dos.close();
        output.flush();
    }

    private static boolean isCommentStart(byte[] nextbyte) {
        return Arrays.equals(nextbyte, CHAR_COMMENT_START);
    }

    private static boolean isNewline(byte[] nextbyte) {
        return Arrays.equals(nextbyte, CHAR_NEWLINE);
    }

    private static boolean isCarriageReturn(byte[] nextbyte) {
        return Arrays.equals(nextbyte, CHAR_CARRIAGE_RETURN);
    }

    private static String l10n(String key) {
        return NodeL10n.getBase().getString("M3UFilter."+key);
    }

}
