// Service Worker for Budget Reference Tables
// Strategy:
//  - App shell (this repo's own files): precached on install, served cache-first,
//    so the whole UI works with zero network connection.
//  - Third-party CDN assets (Dexie, Font Awesome + its font files): cached at
//    runtime with a stale-while-revalidate strategy, so the first online visit
//    seeds the cache and every visit after that works offline too.
//  - Everything here only ever stores the static *code* of the app. It never
//    sees user data — the app's own data lives in IndexedDB inside the page,
//    and (per the page's CSP) never leaves the device over the network.

const VERSION = 'v1.2.7'; // bump this on every deploy that changes cached files —
// forces the browser to install a fresh Service Worker, discard old caches
// (see activate() below), and re-fetch everything instead of serving stale
// precached copies of index.html/sw.js forever.
// This is a *cache-busting* version, separate from the human-readable
// APP_VERSION/APP_VERSION_DATE badge shown in index.html's bottom-right
// corner. The two don't sync automatically (different files) — when you
// bump one for a real deploy, bump the other too. See the matching
// reminder comment above APP_VERSION in index.html.
const SHELL_CACHE = `budgetref-shell-${VERSION}`;
const RUNTIME_CACHE = `budgetref-runtime-${VERSION}`;

const SHELL_URLS = [
  './',
  './index.html',
  './manifest.json',
  './lib/chart.umd.min.js',
  './icons/icon-72.png',
  './icons/icon-96.png',
  './icons/icon-128.png',
  './icons/icon-144.png',
  './icons/icon-152.png',
  './icons/icon-192.png',
  './icons/icon-384.png',
  './icons/icon-512.png',
  './icons/icon-maskable-192.png',
  './icons/icon-maskable-512.png',
  './icons/apple-touch-icon.png',
  './icons/favicon.ico',
];

// Third-party origins this app is allowed (by its CSP) to load from — cached
// at runtime rather than precached, since they're cross-origin.
const RUNTIME_ORIGINS = ['https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE)
      .then((cache) => cache.addAll(SHELL_URLS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys
          .filter((key) => key !== SHELL_CACHE && key !== RUNTIME_CACHE)
          .map((key) => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

function isRuntimeAsset(url) {
  return RUNTIME_ORIGINS.some((origin) => url.href.startsWith(origin));
}

// Cache-first for the app shell: instant load, always available offline.
async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;
  try {
    const response = await fetch(request);
    return response;
  } catch (err) {
    // Navigation fallback: if a page request isn't precached for some reason,
    // fall back to the cached index.html shell instead of a hard offline error.
    if (request.mode === 'navigate') {
      const shell = await caches.match('./index.html');
      if (shell) return shell;
    }
    throw err;
  }
}

// Stale-while-revalidate for third-party CDN assets: serve from cache
// immediately if we have it, and refresh the cache in the background so the
// next load picks up updates.
async function staleWhileRevalidate(request) {
  const cache = await caches.open(RUNTIME_CACHE);
  const cached = await cache.match(request);
  // Plain (CORS-mode) fetch — NOT { mode: 'no-cors' }. Both jsDelivr and
  // cdnjs send Access-Control-Allow-Origin: *, so a normal fetch already
  // succeeds and yields a real, readable response. Using no-cors here would
  // produce an *opaque* response, and the page loads these two assets with
  // SRI (integrity="..." crossorigin="anonymous") — an opaque response can
  // never satisfy an integrity check, so the browser silently blocks the
  // script/stylesheet from executing once this Service Worker is controlling
  // the page. That looks exactly like "everything broke after reopening"
  // (Dexie undefined, passcode checks throwing) even though the passcode
  // was never wrong.
  const networkFetch = fetch(request)
    .then((response) => {
      cache.put(request, response.clone());
      return response;
    })
    .catch(() => cached); // offline and nothing new — fall back to what we had
  return cached || networkFetch;
}

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);

  if (isRuntimeAsset(url)) {
    event.respondWith(staleWhileRevalidate(request));
    return;
  }

  if (url.origin === self.location.origin) {
    event.respondWith(cacheFirst(request));
  }
  // Anything else (unexpected third-party origin) is left to the network as-is.
});