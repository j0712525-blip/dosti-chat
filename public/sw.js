// Dosti Chat — service worker: push notifications + offline cache (PWA).
const CACHE = 'dosti-v3';
const CORE = ['/', '/index.html', '/manifest.json', '/icon-192.png', '/icon-512.png', '/lock.js'];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(CORE)).then(() => self.skipWaiting()).catch(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Cache-first for GETs (app shell + icons); network fallback for the rest.
self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  if (url.pathname.startsWith('/ws') || url.pathname.startsWith('/uploads')) return; // never cache live data
  if (url.pathname.startsWith('/api/')) return; // API data (incl. avatars) is always network-fresh
  e.respondWith(
    caches.match(e.request).then(
      (hit) =>
        hit ||
        fetch(e.request).then((res) => {
          if (res.ok && url.origin === self.location.origin) {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put(e.request, copy));
          }
          return res;
        }).catch(() => caches.match('/'))
    )
  );
});

self.addEventListener('push', (e) => {
  const d = e.data ? e.data.json() : {};
  e.waitUntil(
    self.registration.showNotification(d.title || 'Dosti Chat', {
      body: d.body || '',
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      tag: d.tag || 'dosti',
      renotify: true,
      data: { url: d.url || '/' },
    })
  );
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        try {
          if (new URL(c.url).pathname + new URL(c.url).search === url) return c.focus();
        } catch { /* ignore */ }
      }
      for (const c of list) {
        if ('focus' in c) return c.focus();
      }
      return self.clients.openWindow(url);
    })
  );
});
