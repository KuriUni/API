/* Cache only the public application shell. API responses and credentials are never cached. */
const CACHE='tuti-mobile-sso-only-20261022-1';
const SHELL=['./','./index.html','./app.css?v=20261020-modern-2','./refresh.css?v=20261020-modern-2','./app.js','./manifest.webmanifest'];
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(c=>c.addAll(SHELL)).then(()=>self.skipWaiting())));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',event=>{const url=new URL(event.request.url);if(url.origin!==self.location.origin||url.pathname.includes('/api/'))return;if(event.request.method!=='GET')return;event.respondWith(fetch(event.request).then(response=>{if(response.ok){const copy=response.clone();caches.open(CACHE).then(c=>c.put(event.request,copy));}return response;}).catch(()=>caches.match(event.request).then(r=>r||caches.match('./index.html'))));});
