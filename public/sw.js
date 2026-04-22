// Q&A Tutoring PWA - Service Worker
const CACHE_VERSION = 'qa-v1';
const STATIC_CACHE = CACHE_VERSION + '-static';
const DYNAMIC_CACHE = CACHE_VERSION + '-dynamic';
const IMAGE_CACHE = CACHE_VERSION + '-images';

// Static assets to pre-cache on install
const STATIC_ASSETS = [
  '/',
  '/manifest.json',
  '/icon-192.svg',
  '/icon-512.svg',
  '/offline.html',
];

// External resources to cache on first use
const CACHEABLE_HOSTS = [
  'cdn.jsdelivr.net',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
];

// Install: pre-cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    }).then(() => self.skipWaiting())
  );
});

// Activate: clean old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== STATIC_CACHE && key !== DYNAMIC_CACHE && key !== IMAGE_CACHE)
          .map((key) => caches.delete(key))
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch: smart caching strategy
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  
  // Skip non-GET requests
  if (event.request.method !== 'GET') return;
  
  // API calls: Network first, no cache (except images)
  if (url.pathname.startsWith('/api/')) {
    // R2 images: Cache first (they don't change)
    if (url.pathname.startsWith('/api/images/')) {
      event.respondWith(cacheFirst(event.request, IMAGE_CACHE, 30 * 24 * 60 * 60));
      return;
    }
    // Other API: Network only (fresh data)
    return;
  }
  
  // External CDN resources: Cache first
  if (CACHEABLE_HOSTS.some(host => url.hostname === host)) {
    event.respondWith(cacheFirst(event.request, STATIC_CACHE, 7 * 24 * 60 * 60));
    return;
  }
  
  // HTML pages: Network first with offline fallback
  if (event.request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(networkFirstWithFallback(event.request));
    return;
  }
  
  // Everything else: Stale-while-revalidate
  event.respondWith(staleWhileRevalidate(event.request, DYNAMIC_CACHE));
});

// Cache first: Return cached version, fallback to network
async function cacheFirst(request, cacheName, maxAge) {
  const cached = await caches.match(request);
  if (cached) return cached;
  
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(cacheName);
      cache.put(request, response.clone());
    }
    return response;
  } catch (e) {
    return new Response('', { status: 408 });
  }
}

// Network first with offline fallback for HTML pages
async function networkFirstWithFallback(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      // Cache successful HTML responses
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch (e) {
    // Try cache
    const cached = await caches.match(request);
    if (cached) return cached;
    // Show offline page
    const offlinePage = await caches.match('/offline.html');
    if (offlinePage) return offlinePage;
    return new Response('<h1>오프라인</h1><p>인터넷 연결을 확인해주세요.</p>', {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }
}

// Stale-while-revalidate: Return cached, update in background
async function staleWhileRevalidate(request, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(request);
  
  const networkPromise = fetch(request).then((response) => {
    if (response.ok) cache.put(request, response.clone());
    return response;
  }).catch(() => null);
  
  return cached || await networkPromise || new Response('', { status: 408 });
}
