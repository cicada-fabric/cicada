const CACHE_NAME = 'cicada-static-v1';
const STATIC_ASSETS = ['/', '/assets/app.css', '/assets/app.js', '/assets/goal-detail.js', '/assets/attachments.js', '/assets/voice.js', '/assets/events.js', '/manifest.webmanifest', '/icon.svg'];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))));
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin || (!url.pathname.startsWith('/assets/') && url.pathname !== '/' && url.pathname !== '/manifest.webmanifest')) return;
  event.respondWith(caches.match(request).then(cached => cached || fetch(request)));
});
