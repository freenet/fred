// [[file:m3u-player.org::*The script][The script:1]]
// @license magnet:?xt=urn:btih:cf05388f2679ee054f2beb29a391d25f4e673ac3&amp;dn=gpl-2.0.txt GPL-v2-or-Later
// When changing even a single letter in this file, you MUST adjust
// freenet.clients.http.ToadletContextImpl.generateRestrictedScriptSrc,
// otherwise the CSP policy will prevent loading this script.
// use the following shell-command to get the new hash:
// sha256sum m3u-player.js | cut -d " " -f 1 | xxd -r -p | base64
// AVOID unicode characters. They may change on the way to the
// browser, invalidating the CSP header.
// Also you MUST escape any ampersand and less-than or greater-than signs,
// because this file will be inlined into the site.
const playlists = {};
const prefetchedTracks = new Map(); // use a map for insertion order, so we can just blow away old entries.
// maximum prefetched blobs that are kept.
const MAX_PREFETCH_KEEP = 10;
// maximum allowed number of entries in a playlist to prevent OOM attacks against the browser with self-referencing playlists
const MAX_PLAYLIST_LENGTH = 1000;
const PLAYLIST_MIME_TYPES = ["audio/x-mpegurl", "audio/mpegurl", "application/vnd.apple.mpegurl","application/mpegurl","application/x-mpegurl"];
function stripUrlParameters(link) {
  const url = new URL(link, window.location);
  url.search = "";
  url.hash = "";
  return url.href;
}
function isPlaylist(link) {
  const linkHref = stripUrlParameters(link);
  return linkHref.endsWith(".m3u") || linkHref.endsWith(".m3u8");
}
function isBlob(link) {
  return new URL(link, window.location).protocol == 'blob';
}
/**
 * Replace the host of the link with the host seen by the browser to get around CSP restrictions.
 * This must be applied to all links read from anywhere.
 * invalid links will fail at the URL constructor.
 *
 * Keep in mind that the link here is user input, though already
 * filtered by the m3u-filter (we check against the
 * PLAYLIST_MIME_TYPES whether Freenet saw this as m3u-list),
 * and all user input is potentially evil.
 */
function replaceHost(link) {
  const url = new URL(link, window.location);
  if (url.protocol !== 'blob:') {
    url.host = window.location.host;
    url.port = window.location.port;
  }
  // cannot access unprivileged resources from a privileged site. If Freenet is proxied via https, we need https for the content.
  if (url.protocol === 'http:') {
    if (window.location.protocol === 'https:') {
      url.protocol = 'https:';
    }
  }
  return url.href;
}
function parsePlaylist(textContent) {
  return textContent.match(/^(?!#)(?!\s).*$/mg)
    .filter(s => s) // filter removes empty strings
    .map(replaceHost); // now all tracks point to our local installation. The m3u-filter ensures that they are valid keys.
}
/**
 * Download the given playlist, parse it, and store the tracks in the
 * global playlists object using the url as key.
 *
 * Runs callback once the playlist downloaded successfully.
 */
function fetchPlaylist(url, onload, onerror) {
  const playlistFetcher = new XMLHttpRequest();
  playlistFetcher.open("GET", url, true);
  playlistFetcher.responseType = "blob"; // to get a mime type
  playlistFetcher.onload = () => {
    if (PLAYLIST_MIME_TYPES.includes(playlistFetcher.response.type)) { // security check to ensure that filters have run
      const reader = new FileReader();
      const load = onload; // propagate to inner scope
      reader.addEventListener("loadend", e => {
        playlists[url] = parsePlaylist(reader.result);
        onload();
      });
      reader.readAsText(playlistFetcher.response);
    } else {
      console.error("playlist must have one of the playlist MIME type '" + PLAYLIST_MIME_TYPES + "' but it had MIME type '" + playlistFetcher.response.type + "'.");
      onerror();
    }
  };
  playlistFetcher.onerror = onerror;
  playlistFetcher.abort = onerror;
  playlistFetcher.send();
}
function prefetchTrack(url, onload) {
  if (prefetchedTracks.has(url)) {
    return;
  }
  // first cleanup: kill the oldest entries until we're back at the allowed size
  while (prefetchedTracks.size > MAX_PREFETCH_KEEP) {
    const key = prefetchedTracks.keys().next().value;
    const track = prefetchedTracks.get(key);
    prefetchedTracks.delete(key);
  }
  // first set the prefetched to the url so we will never request twice
  prefetchedTracks.set(url, url);
  // now start replacing it with a blob
  const xhr = new XMLHttpRequest();
  xhr.open("GET", url, true);
  xhr.responseType = "blob";
  xhr.onload = () => {
    prefetchedTracks.set(url, xhr.response);
    if (onload) {
      onload();
    }
  };
  xhr.send();
}
function updateSrc(mediaTag, callback) {
  const playlistUrl = mediaTag.getAttribute("playlist");
  const trackIndex =  mediaTag.getAttribute("track-index");
  // deepcopy playlists to avoid shared mutation
  let playlist = [...playlists[playlistUrl]];
  let trackUrl = playlist[trackIndex];
  // strip out the host; we do not need that in Freenet
  // download and splice in playlists as needed
  if (isPlaylist(trackUrl)) {
    if (playlist.length >= MAX_PLAYLIST_LENGTH) {
      // skip playlist if we already have too many tracks
      changeTrack(mediaTag, +1);
    } else {
      // do not use the cached playlist here, though it is tempting: it might genuinely change to allow for updates
      fetchPlaylist(
        trackUrl,
        () => {
          playlist.splice(trackIndex, 1, ...playlists[trackUrl]);
          playlists[playlistUrl] = playlist;
          updateSrc(mediaTag, callback);
        },
        () => callback());
    }
  } else {
    let url = prefetchedTracks.has(trackUrl)
        ? prefetchedTracks.get(trackUrl) instanceof Blob
        ? URL.createObjectURL(prefetchedTracks.get(trackUrl))
        : trackUrl : trackUrl;
    const oldUrl = mediaTag.getAttribute("src");
    // prevent size flickering by setting height before src change
    const canvas = document.createElement("canvas");
    if (!isNaN(mediaTag.duration)) { // already loaded a valid file so the size should fit
      // fix height to the height of the current video. Re-run after setting the source.
      mediaTag.height = (mediaTag.clientWidth * mediaTag.videoHeight) / mediaTag.videoWidth;
      // take screenshot of video and overlay it to mask short-term flicker.
      canvas.width = mediaTag.clientWidth;
      canvas.height = mediaTag.clientHeight;
      const context = canvas.getContext("2d");
      context.scale(mediaTag.clientWidth / mediaTag.videoWidth, mediaTag.clientHeight / mediaTag.videoHeight);
      context.drawImage(mediaTag, 0, 0);
      canvas.hidden = true;
      mediaTag.parentNode.insertBefore(canvas, mediaTag.nextSibling);
      canvas.style.position = "absolute";
      canvas.style.marginLeft = "-" + mediaTag.clientWidth + "px";
      canvas.hidden = false;
    }
    mediaTag.setAttribute("src", url);
    mediaTag.oncanplaythrough = () => {
      if (!isNaN(mediaTag.duration)) { // already loaded a valid file
        // fix height to the height of the current video. Re-run after setting the source.
        mediaTag.height = (mediaTag.clientWidth * mediaTag.videoHeight) / mediaTag.videoWidth;
      }
      // remove overlay
      canvas.hidden = true;
      canvas.remove(); // to allow garbage collection
    };
    setTimeout(() => canvas.remove(), 300); // fallback
    // replace the url when done, because a blob from an xhr request
    // is more reliable in the media tag; 
    // the normal URL caused jumping prematurely to the next track.
    if (url == trackUrl) {
      prefetchTrack(trackUrl, () => {
        if (mediaTag.paused) {
          if (url == mediaTag.getAttribute("src")) {
            if (mediaTag.currentTime === 0) {
              mediaTag.setAttribute("src", URL.createObjectURL(
                prefetchedTracks.get(url)));
            }
          }
        }
      });
    }
    // allow releasing memory
    if (isBlob(oldUrl)) {
      URL.revokeObjectURL(oldUrl);
    }
    // update title
    mediaTag.parentElement.querySelector(".m3u-player--title").title = stripUrlParameters(trackUrl);
    mediaTag.parentElement.querySelector(".m3u-player--title").textContent = stripUrlParameters(trackUrl);
    // start prefetching the next three tracks.
    for (const i of [1, 2, 3]) {
      if (playlist.length > Number(trackIndex) + i) {
        prefetchTrack(playlist[Number(trackIndex) + i]);
      }
    }
    callback();
  }
}
function changeTrack(mediaTag, diff) {
  const currentTrackIndex = Number(mediaTag.getAttribute("track-index"));
  const nextTrackIndex = currentTrackIndex + diff;
  const tracks = playlists[mediaTag.getAttribute("playlist")];
  if (nextTrackIndex >= 0) { // do not collapse the if clauses with double-and, that does not survive inlining
    if (tracks.length > nextTrackIndex) {
    mediaTag.setAttribute("track-index", nextTrackIndex);
      updateSrc(mediaTag, () => mediaTag.play());
    }
  }
}

/**
 * Turn a media tag into playlist player.
 */
function initPlayer(mediaTag) {
  mediaTag.setAttribute("playlist", replaceHost(mediaTag.getAttribute("src")));
  mediaTag.setAttribute("track-index", 0);
  const url = mediaTag.getAttribute("playlist");
  const wrapper = mediaTag.parentElement.insertBefore(document.createElement("div"), mediaTag);
  const controls = document.createElement("div");
  const left = document.createElement("span");
  const title = document.createElement("span");
  const right = document.createElement("span");
  controls.appendChild(left);
  controls.appendChild(title);
  controls.appendChild(right);
  left.classList.add("m3u-player--left");
  right.classList.add("m3u-player--right");
  title.classList.add("m3u-player--title");
  title.style.overflow = "hidden";
  title.style.textOverflow = "ellipsis";
  title.style.whiteSpace = "nowrap";
  title.style.opacity = "0.3";
  title.style.direction = "rtl"; // for truncation on the left
  title.style.paddingLeft = "0.5em";
  title.style.paddingRight = "0.5em";
  controls.style.display = "flex";
  controls.style.justifyContent = "space-between";
  const styleTag = document.createElement("style");
  styleTag.innerHTML = ".m3u-player--left:hover, .m3u-player--right:hover {color: wheat; background-color: DarkSlateGray}";
  wrapper.appendChild(styleTag);
  wrapper.appendChild(controls);
  controls.style.width = mediaTag.getBoundingClientRect().width.toString() + "px";
  // appending the media tag to the wrapper removes it from the outer scope but keeps the event listeners
  wrapper.appendChild(mediaTag);
  left.innerHTML = "&lt;"; // not textContent, because we MUST escape
                           // the tag here and textContent shows the
                           // escaped version
  left.onclick = () => changeTrack(mediaTag, -1);
  right.innerHTML = "&gt;";
  right.onclick = () => changeTrack(mediaTag, +1);
  fetchPlaylist(
    url,
    () => {
      updateSrc(mediaTag, () => null);
      mediaTag.addEventListener("ended", event => {
        if (mediaTag.currentTime >= mediaTag.duration) {
          changeTrack(mediaTag, +1);
        }
      });
    },
    () => null);
  // keep the controls aligned to the media tag
  mediaTag.resizeObserver = new ResizeObserver(entries => {
    controls.style.width = entries[0].contentRect.width.toString() + "px";
  });
  mediaTag.resizeObserver.observe(mediaTag);
}
function processTag(mediaTag) {
  const canPlayClaim = mediaTag.canPlayType('audio/x-mpegurl');
  let supportsPlaylists = !!canPlayClaim;
  if (canPlayClaim == 'maybe') { // yes, seriously: specced as you only know when you try
    supportsPlaylists = false;
  }
  if (!supportsPlaylists) {
    if (isPlaylist(mediaTag.getAttribute("src"))) {
      initPlayer(mediaTag);
    }
  }
}
document.addEventListener('DOMContentLoaded', () => {
  const nodes = document.querySelectorAll("audio,video");
  nodes.forEach(processTag);
});
// @license-end
// The script:1 ends here
