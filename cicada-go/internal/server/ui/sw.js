const CACHE_NAME = 'cicada-static-v2';
const STATIC_ASSETS = ['/', '/assets/app.css', '/assets/app.js', '/assets/goal-detail.js', '/assets/attachments.js', '/assets/voice.js', '/assets/push.js', '/assets/events.js', '/manifest.webmanifest', '/icon.svg'];

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

self.addEventListener('push', event => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch { data = {body: event.data?.text() || ''}; }
  const title = data.title || 'Cicada notification';
  event.waitUntil(self.registration.showNotification(title, {
    body: data.body || '',
    tag: data.id || 'cicada-notification',
    renotify: data.priority === 'P0' || data.priority === 'P1',
    requireInteraction: data.priority === 'P0',
    data: {goal_id: data.goal_id || ''},
  }));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(clients.matchAll({type: 'window', includeUncontrolled: true}).then(existing => {
    const target = existing.find(client => 'focus' in client);
    if (target) return target.focus();
    return clients.openWindow('/');
  }));
});
