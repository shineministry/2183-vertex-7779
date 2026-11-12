// Cache only the public vault application. Private documents use the encrypted IndexedDB cache.
const CACHE = "online-vault-v44";
const SHELL = "/index.html";
const ASSETS = new Set([
  "/pdf.min.js",
  "/pdfjs-init.js",
  "/manifest.json",
  "/style.css",
  "/sha256.js",
  "/offline-auth.js?v=20261112.07",
  "/device-integrity.js",
  "/auth.js?v=20261112-localai",
  "/session.js?v=20261112.06",
  "/vault-data.js?v=20260628-photosfix1",
  "/viewer.js?v=20261022-sigstamp2",
  "/features.js?v=20260628-photosfix1",
  "/vault-ui.js?v=20261112-accesslog",
  "/datetime.js",
  "/security.js",
  "/startup.js",
  "/offline-ai.js?v=20261112.05",
  "/pdf.worker.min.js"
]);

self.addEventListener("install", event => {
  // Cache.addAll writes the complete release as one batch. A failed install leaves the previous worker active.
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    await cache.addAll([SHELL, ...ASSETS].map(path => new Request(path, { cache: "reload" })));
    await self.skipWaiting();
  })());
});

self.addEventListener("activate", event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(key => key.startsWith("online-vault-v") && key !== CACHE)
      .map(key => caches.delete(key)));
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", event => {
  const request = event.request;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || request.method !== "GET" ||
      request.headers.has("Authorization") || request.cache === "no-store") return;

  if (request.mode === "navigate" && (url.pathname === "/" || url.pathname === SHELL)) {
    event.respondWith(loadShell(request));
    return;
  }
  if (ASSETS.has(url.pathname + url.search)) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE);
      return await cache.match(request) || fetch(request);
    })());
  }
});

async function loadShell(request) {
  try {
    const response = await fetch(request);
    if (response.status < 500) return response;
  } catch {
    // The static shell works with the vault's existing offline sign-in.
  }
  const cache = await caches.open(CACHE);
  return await cache.match(SHELL) || new Response("Vault offline setup is incomplete. Open the vault once while connected.", {
    status: 503,
    headers: { "Content-Type": "text/plain; charset=UTF-8" }
  });
}

self.addEventListener("message", event => {
  // The app clears its session independently. The public shell is needed to sign in again offline.
  if (event.data?.type === "CLEAR_SESSION") {
    event.source?.postMessage({ type: "SESSION_CLEARED" });
  }
});
