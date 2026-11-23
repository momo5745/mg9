const C='mg9-v9';
const A=['./','./index.html','./manifest.webmanifest','./card.jpg','./hero.jpg','./me.jpg','./icon-192.png','./icon-512.png','./apple-touch-icon.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(A)));self.skipWaiting()});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{if(e.request.method!=='GET')return;const u=new URL(e.request.url);if(u.origin!==location.origin)return;
 if(e.request.mode==='navigate'){e.respondWith(fetch(e.request.url,{cache:'no-store'}).then(r=>{const cp=r.clone();caches.open(C).then(c=>c.put('./index.html',cp));return r}).catch(()=>caches.match('./index.html')));return}
 e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request).then(res=>{const cp=res.clone();caches.open(C).then(c=>c.put(e.request,cp));return res})))});
self.addEventListener('push',e=>{let d={};try{d=e.data.json()}catch(_){d={title:'MG9',body:e.data?e.data.text():''}}e.waitUntil(self.registration.showNotification(d.title||'MG9',{body:d.body||'',tag:d.tag||'mg9',icon:'icon-192.png',badge:'icon-192.png',data:{url:d.url||'./'}}))});
self.addEventListener('notificationclick',e=>{e.notification.close();const url=(e.notification.data&&e.notification.data.url)||'./';e.waitUntil((async()=>{const cs=await clients.matchAll({type:'window',includeUncontrolled:true});const go=new URL(url,self.location.href).searchParams.get('go');for(const c of cs){if('focus' in c){await c.focus();if(go)c.postMessage({go});return}}if(clients.openWindow)await clients.openWindow(url)})())});
