// Offline support: keep the app's files on the device and refresh them in the background.
const CACHE = 'timetable-v4';
const FILES = ['./', './index.html', './manifest.json', './img/welcome.webp', './icons/icon-180.png', './icons/icon-192.png', './icons/icon-512.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(FILES)).catch(() => {})); self.skipWaiting(); });
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET' || new URL(e.request.url).origin !== location.origin) return;
  // Network first (always newest version when online), saved copy when offline
  e.respondWith(fetch(e.request).then(res => {
    if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); }
    return res;
  }).catch(() => caches.match(e.request).then(hit => hit || caches.match('./index.html'))));
});

// Reminder notifications sent by the Timetable reminder service
self.addEventListener('push', e => {
  let m = {}; try { m = e.data ? e.data.json() : {}; } catch (_) { m = { title: e.data ? e.data.text() : 'Timetable' }; }
  e.waitUntil(self.registration.showNotification(m.title || 'Timetable', {
    body: m.body || '', tag: m.tag || undefined, icon: './icons/icon-192.png', badge: './icons/icon-192.png', data: { date: m.date || '' }
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type:'window', includeUncontrolled:true }).then(list => {
    for (const c of list) if ('focus' in c) return c.focus();
    return self.clients.openWindow('./');
  }));
});
