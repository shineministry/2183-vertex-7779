/**
 * sw.js — Online Vault Service Worker
 *
 * Routing strategy:
 *  • Backend API calls        → Always network-only (auth-bearing, never cached)
 *  • AI / chat endpoints      → Network-only (never cached)
 *  • Vault /docs/* blobs      → Network-only; offline fallback via page IndexedDB
 *                               (features.js → fetchVaultDocWithOfflineFallback)
 *  • Navigation (HTML pages)  → Network-first, fall back to cached /index.html
 *  • Same-origin shell assets → Cache-first, populate on first fetch
 *  • External CDN assets      → Network-first, cache fallback
 *
 * Encrypted vault blobs are cached in IndexedDB by features.js.
 * The SW never tries to cache them to avoid auth/CORS complexity.
 *
 * Login-after-logout fix:
 *  The page sends CLEAR_SESSION via postMessage on logout.
 *  The SW purges the entire cache so the next page load is a clean
 *  network fetch — no stale authenticated shell is served.
 */

const CACHE = "online-vault-v7";   // bump this string to force a full cache refresh

const BACKEND_HOST = "backend.shinumaths989.workers.dev";

// Assets pre-cached at install time (app shell)
const PRECACHE_URLS = [
  "/",
  "/index.html",
  "/favicon.png",
  "/auth.js",
  "/offline-auth.js",
  "/pdf.min.js",
  "/pdf.worker.min.js",
  "/profile.png",
  "/features.js",
  "/ProfileSt.png",
  "/ProfileK.png",
  "/datetime.js",
  "/pdfjs-init.js",
  "/security.js",
  "/session.js",
  "/sha256.js",
  "/startup.js",
  "/style.css",
  "/vault-data.js",
  "/viewer.js",
  "/vault-ui.js"
];

// URL path fragments that must NEVER be cached (AI chat, streaming, live data)
const NEVER_CACHE_PATTERNS = [
  "/ai-chat",
  "/chat",
  "/openai",
  "/gemini",
  "/anthropic",
  "/stream"
];

// ─────────────────────────────────────────────────────────────────────────────
// Install — pre-cache app shell assets
// ─────────────────────────────────────────────────────────────────────────────
self.addEventListener("install", function(event) {
  event.waitUntil(
    caches.open(CACHE).then(function(cache) {
      // Use individual add() with per-item catches so a single missing
      // asset (e.g. /profile.png missing in dev) does not abort the whole install.
      return Promise.allSettled(
        PRECACHE_URLS.map(function(url) {
          return cache.add(url).catch(function(err) {
            console.warn("[SW] Precache miss:", url, err);
          });
        })
      );
    })
  );
  self.skipWaiting();
});

// ─────────────────────────────────────────────────────────────────────────────
// Activate — purge any old caches, claim clients immediately
// ─────────────────────────────────────────────────────────────────────────────
self.addEventListener("activate", function(event) {
  event.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys
          .filter(function(key) { return key !== CACHE; })
          .map(function(key) {
            console.log("[SW] Removing old cache:", key);
            return caches.delete(key);
          })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

// ─────────────────────────────────────────────────────────────────────────────
// Fetch — routing
// ─────────────────────────────────────────────────────────────────────────────
self.addEventListener("fetch", function(event) {
  var request = event.request;
  var url     = new URL(request.url);

  // Only handle HTTP/HTTPS
  if (url.protocol !== "http:" && url.protocol !== "https:") return;

  // Only handle GET (POST/PUT/DELETE go straight to network)
  if (request.method !== "GET") return;

  // 1. Backend API — always network-only (auth tokens, never cache)
  if (url.hostname === BACKEND_HOST) {
    // /docs/* offline fallback: return a detectable 503 so the page's
    // fetchVaultDocWithOfflineFallback() can read from IndexedDB instead.
    if (url.pathname.startsWith("/docs/")) {
      // Let the fetch fail naturally when offline.
      // viewer.js catches the TypeError and reads from IndexedDB.
      // The old 503 JSON response was being thrown as an Error by
      // viewer.js, bypassing the IndexedDB fallback entirely.
      return; // passthrough — no SW interception
    }
    // All other backend calls: pure network passthrough
    return;
  }

  // 2. AI / chat endpoints — network-only, no cache at all
  var neverCache = NEVER_CACHE_PATTERNS.some(function(p) {
    return url.pathname.includes(p);
  });
  if (neverCache) {
    event.respondWith(fetch(request));
    return;
  }

  // 3. Non-same-origin requests (CDN fonts, scripts, etc.) — network-first, cache fallback
  if (url.origin !== self.location.origin) {
    event.respondWith(networkFirst(request));
    return;
  }

  // 4. Navigation (HTML pages) — network-first so a fresh login page is always served
  if (request.mode === "navigate") {
    event.respondWith(networkFirst(request));
    return;
  }

  // Auth scripts should update immediately after offline-login fixes.
  if (["/auth.js", "/offline-auth.js", "/sw.js"].includes(url.pathname)) {
    event.respondWith(networkFirst(request));
    return;
  }

  // 5. Same-origin shell assets (JS, CSS, images) — cache-first
  event.respondWith(cacheFirst(request));
});

// ─────────────────────────────────────────────────────────────────────────────
// Strategies
// ─────────────────────────────────────────────────────────────────────────────

async function networkFirst(request) {
  try {
    var response = await fetch(request);
    if (isCacheable(response)) {
      var cache = await caches.open(CACHE);
      await cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    var cached = await caches.match(request);
    if (cached) return cached;

    // For navigation requests serve the cached shell so the app still loads
    if (request.mode === "navigate") {
      var fallback = await caches.match("/index.html");
      if (fallback) return fallback;
    }

    return new Response("Offline", {
      status: 503,
      headers: { "Content-Type": "text/plain" }
    });
  }
}

async function cacheFirst(request) {
  var cached = await caches.match(request);
  if (cached) return cached;

  try {
    var response = await fetch(request);
    if (isCacheable(response)) {
      var cache = await caches.open(CACHE);
      await cache.put(request, response.clone());
    }
    return response;
  } catch (err) {
    return new Response("Offline", {
      status: 503,
      headers: { "Content-Type": "text/plain" }
    });
  }
}

function isCacheable(response) {
  if (!response || !response.ok) return false;
  var type = response.type;
  return type === "basic" || type === "default";
}

// ─────────────────────────────────────────────────────────────────────────────
// Message handler
// ─────────────────────────────────────────────────────────────────────────────
self.addEventListener("message", function(event) {
  if (!event.data) return;

  switch (event.data.type) {

    // Force the waiting SW to activate immediately (useful after updates)
    case "SKIP_WAITING":
      self.skipWaiting();
      break;

    // Called by the page on logout — wipes the entire cache so the next
    // page load fetches a fresh unauthenticated shell from the network.
    // This is the fix for "login doesn't work after logout".
    case "CLEAR_SESSION":
      caches.delete(CACHE).then(function() {
        console.log("[SW] Cache cleared on logout");
        if (event.source) {
          event.source.postMessage({ type: "SESSION_CLEARED" });
        }
      });
      break;

    // Manual full cache clear (dev / debug use)
    case "CLEAR_CACHE":
      caches.delete(CACHE).then(function() {
        if (event.source) {
          event.source.postMessage({ type: "CACHE_CLEARED" });
        }
      });
      break;
  }
});
