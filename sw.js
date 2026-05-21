const CACHE = 'online-vault-v2';

const WORKER =
'https://backend.shinumaths989.workers.dev';


// =========================
// INSTALL
// =========================

self.addEventListener('install', event => {

  event.waitUntil(

    caches.open(CACHE).then(cache => {

      return cache.addAll([

        '/',
        '/index.html',
        '/favicon.png',
        '/profile.png'

      ]);

    })

  );

  self.skipWaiting();

});


// =========================
// ACTIVATE
// =========================

self.addEventListener('activate', event => {

  event.waitUntil(

    caches.keys().then(keys =>

      Promise.all(

        keys
          .filter(key => key !== CACHE)
          .map(key => caches.delete(key))

      )

    )

  );

  self.clients.claim();

});


// =========================
// FETCH
// =========================

self.addEventListener('fetch', event => {

  const url =
    new URL(event.request.url);


  // =========================
  // WORKER REQUESTS
  // =========================

  if (url.origin === WORKER) {

    event.respondWith(

      caches.match(event.request).then(cached => {

        // RETURN CACHE FIRST

        if (cached) {
          return cached;
        }

        // FETCH FROM NETWORK

        return fetch(event.request)

          .then(async response => {

            // INVALID RESPONSE

            if (
              !response ||
              !response.ok
            ) {

              return response;

            }

            // CLONE RESPONSE SAFELY

            const responseClone =
              response.clone();

            // STORE IN CACHE

            const cache =
              await caches.open(CACHE);

            await cache.put(
              event.request,
              responseClone
            );

            // RETURN ORIGINAL RESPONSE

            return response;

          })

          .catch(() => {

            // OFFLINE FALLBACK

            return cached ||

              new Response(
                'Offline',
                {
                  status: 503,
                  headers: {
                    'Content-Type':
                    'text/plain'
                  }
                }
              );

          });

      })

    );

    return;

  }


  // =========================
  // LOCAL FILES
  // =========================

  if (url.origin === self.location.origin) {

    event.respondWith(

      caches.match(event.request)

        .then(cached => {

          return (

            cached ||

            fetch(event.request)

              .then(async response => {

                // CACHE SUCCESSFUL FILES

                if (
                  response &&
                  response.ok
                ) {

                  const responseClone =
                    response.clone();

                  const cache =
                    await caches.open(CACHE);

                  await cache.put(
                    event.request,
                    responseClone
                  );

                }

                return response;

              })

          );

        })

    );

    return;

  }


  // =========================
  // EXTERNAL REQUESTS
  // =========================

  event.respondWith(

    fetch(event.request)

      .catch(() =>

        new Response(
          'Offline',
          {
            status: 503,
            headers: {
              'Content-Type':
              'text/plain'
            }
          }
        )

      )

  );

});
