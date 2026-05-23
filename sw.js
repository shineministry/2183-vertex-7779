const CACHE = "online-vault-v3";

const PRECACHE_URLS = [
  "/",
  "/index.html",
  "/favicon.png",
  "/profile.png"
];

const BACKEND_HOST = "backend.shinumaths989.workers.dev";

self.addEventListener("install", function(event) {
  event.waitUntil(
    caches.open(CACHE).then(function(cache) {
      return cache.addAll(PRECACHE_URLS).catch(function(error) {
        console.error("Service worker precache failed:", error);
      });
    })
  );

  self.skipWaiting();
});

self.addEventListener("activate", function(event) {
  event.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys
          .filter(function(key) {
            return key !== CACHE;
          })
          .map(function(key) {
            return caches.delete(key);
          })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

self.addEventListener("fetch", function(event) {
  var request = event.request;
  var url = new URL(request.url);

  if (url.hostname === BACKEND_HOST) {
    return;
  }

  if (request.method !== "GET") {
    return;
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return;
  }

  if (url.origin !== self.location.origin) {
    return;
  }

  if (request.mode === "navigate") {
    event.respondWith(networkFirst(request));
    return;
  }

  event.respondWith(cacheFirst(request));
});

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

    if (cached) {
      return cached;
    }

    var fallback = await caches.match("/index.html");

    if (fallback) {
      return fallback;
    }

    return new Response("Offline", {
      status: 503,
      headers: {
        "Content-Type": "text/plain"
      }
    });
  }
}

async function cacheFirst(request) {
  var cached = await caches.match(request);

  if (cached) {
    return cached;
  }

  var response = await fetch(request);

  if (isCacheable(response)) {
    var cache = await caches.open(CACHE);
    await cache.put(request, response.clone());
  }

  return response;
}

function isCacheable(response) {
  if (!response || !response.ok) {
    return false;
  }

  var type = response.type;

  return type === "basic" || type === "default";
}
