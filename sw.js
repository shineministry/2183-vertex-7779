const CACHE = 'online-vault';
const WORKER = 'https://backend.shinumaths989.workers.dev';

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(['/index.html','/favicon.png','/profile.png'])));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  if(url.origin === WORKER){
    e.respondWith(caches.match(e.request).then(cached => {
      if(cached) return cached;
      return fetch(e.request).then(r => {
        caches.open(CACHE).then(c => c.put(e.request, r.clone()));
        return r;
      }).catch(() => cached);
    }));
    return;
  }

  if(url.origin === self.location.origin){
    e.respondWith(caches.match(e.request).then(cached => cached || fetch(e.request)));
    return;
  }

  e.respondWith(fetch(e.request).catch(() => new Response('Offline', { status: 503 })));
});
