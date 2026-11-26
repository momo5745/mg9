// MG9 : serveur de notifications (Cloudflare Worker + KV "MG9")
const ORIGIN = 'https://momo5745.github.io';
const APP = 'https://momo5745.github.io/mg9/';
const CITY = {
  'America/Chicago': { n: 'Chicago Heights', lat: 41.5061, lng: -87.6356, f: 15, i: 15 },
  'Europe/Paris': { n: 'Metz', lat: 49.1193, lng: 6.1757, f: 18, i: 17 },
  'Africa/Tunis': { n: 'Tunis', lat: 36.8065, lng: 10.1815, f: 18, i: 18 },
};
const cityOf = tz => CITY[tz] || CITY['America/Chicago'];

/* ---------- utilitaires ---------- */
const enc = new TextEncoder();
const b64u = buf => { const b = new Uint8Array(buf); let s = ''; for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const unb64u = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const r = atob(s); const u = new Uint8Array(r.length); for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i); return u; };
const cat = (...a) => { const n = a.reduce((x, y) => x + y.length, 0), o = new Uint8Array(n); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
async function hmac(key, data) { const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); return new Uint8Array(await crypto.subtle.sign('HMAC', k, data)); }

/* ---------- clés VAPID (créées une seule fois, gardées dans KV) ---------- */
async function vapid(env) {
  let v = await env.MG9.get('vapid', 'json');
  if (!v) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
    v = { pub: b64u(pub), jwk: await crypto.subtle.exportKey('jwk', kp.privateKey) };
    await env.MG9.put('vapid', JSON.stringify(v));
  }
  return v;
}
async function vapidAuth(v, endpoint) {
  const aud = new URL(endpoint).origin;
  const h = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const c = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: APP })));
  const key = await crypto.subtle.importKey('jwk', v.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(h + '.' + c));
  return `vapid t=${h}.${c}.${b64u(sig)}, k=${v.pub}`;
}

/* ---------- chiffrement Web Push (RFC 8291, aes128gcm) ---------- */
async function encrypt(sub, payload, salt, asKeys) {
  const uaPub = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const as = asKeys || await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, as.privateKey, 256));
  salt = salt || crypto.getRandomValues(new Uint8Array(16));
  const prkKey = await hmac(auth, shared);
  const ikm = await hmac(prkKey, cat(enc.encode('WebPush: info\0'), uaPub, asPub, new Uint8Array([1])));
  const prk = await hmac(salt, ikm);
  const cek = (await hmac(prk, cat(enc.encode('Content-Encoding: aes128gcm\0'), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, cat(enc.encode('Content-Encoding: nonce\0'), new Uint8Array([1])))).slice(0, 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, cat(enc.encode(payload), new Uint8Array([2]))));
  const hdr = new Uint8Array(21); hdr.set(salt, 0); new DataView(hdr.buffer).setUint32(16, 4096); hdr[20] = 65;
  return cat(hdr, asPub, ct);
}
async function sendPush(env, id, sub, msg) {
  const v = await vapid(env);
  const body = await encrypt(sub, JSON.stringify(msg));
  const r = await fetch(sub.endpoint, { method: 'POST', body, headers: { 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '3600', Urgency: 'high', Authorization: await vapidAuth(v, sub.endpoint) } });
  if (r.status === 404 || r.status === 410) await env.MG9.delete('sub:' + id);
  return r.status;
}

/* ---------- heures de prière ---------- */
const rad = d => d * Math.PI / 180, deg = r => r * 180 / Math.PI;
const fix = (a, b) => { a = a - b * Math.floor(a / b); return a < 0 ? a + b : a; };
function sunPos(jd) {
  const D = jd - 2451545.0, g = fix(357.529 + 0.98560028 * D, 360), q = fix(280.459 + 0.98564736 * D, 360);
  const L = fix(q + 1.915 * Math.sin(rad(g)) + 0.020 * Math.sin(rad(2 * g)), 360), e = 23.439 - 0.00000036 * D;
  const RA = fix(deg(Math.atan2(Math.cos(rad(e)) * Math.sin(rad(L)), Math.cos(rad(L)))) / 15, 24);
  return { decl: deg(Math.asin(Math.sin(rad(e)) * Math.sin(rad(L)))), eqt: q / 15 - RA };
}
function prayerTimes(y, m, d, c) {
  // renvoie des heures UTC (décimales) pour la date locale y-m-d
  let A = Math.floor((14 - m) / 12), Y = y + 4800 - A, M = m + 12 * A - 3;
  const jd0 = d + Math.floor((153 * M + 2) / 5) + 365 * Y + Math.floor(Y / 4) - Math.floor(Y / 100) + Math.floor(Y / 400) - 32045 - 0.5;
  const jd = jd0 - c.lng / (15 * 24);
  const mid = t => fix(12 - sunPos(jd + t).eqt, 24);
  const ang = (a, t, ccw) => { const s = sunPos(jd + t), n = mid(t); const T = deg(Math.acos((-Math.sin(rad(a)) - Math.sin(rad(s.decl)) * Math.sin(rad(c.lat))) / (Math.cos(rad(s.decl)) * Math.cos(rad(c.lat))))) / 15; return n + (ccw ? -T : T); };
  const asr = t => { const s = sunPos(jd + t); const a = -deg(Math.atan(1 / (1 + Math.tan(rad(Math.abs(c.lat - s.decl)))))); return ang(a, t); };
  let T = { fajr: 5, sunrise: 6, dhuhr: 12, asr: 13, maghrib: 18, isha: 18 };
  for (let k = 0; k < 2; k++) {
    const p = x => x / 24;
    T = { fajr: ang(c.f, p(T.fajr), 1), sunrise: ang(0.833, p(T.sunrise), 1), dhuhr: mid(p(T.dhuhr)), asr: asr(p(T.asr)), maghrib: ang(0.833, p(T.maghrib)), isha: ang(c.i, p(T.isha)) };
  }
  // hautes latitudes (ex. Metz en été) : méthode de l'angle
  const night = 24 - (T.maghrib - T.sunrise), pf = c.f / 60 * night, pi = c.i / 60 * night;
  if (isNaN(T.fajr) || T.sunrise - T.fajr > pf) T.fajr = T.sunrise - pf;
  if (isNaN(T.isha) || T.isha - T.maghrib > pi) T.isha = T.maghrib + pi;
  const o = {}; for (const k in T) o[k] = T[k] - c.lng / 15; return o; // heures UTC
}

/* ---------- temps local ---------- */
function local(tz, date) {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', weekday: 'short', hourCycle: 'h23' }).formatToParts(date).map(x => [x.type, x.value]));
  return { d: `${p.year}-${p.month}-${p.day}`, y: +p.year, m: +p.month, day: +p.day, min: +p.hour * 60 + +p.minute, dw: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(p.weekday) };
}
function prayersLocal(tz, L) {
  const c = cityOf(tz), ut = prayerTimes(L.y, L.m, L.day, c), base = Date.UTC(L.y, L.m - 1, L.day), o = {};
  for (const k in ut) { const dt = new Date(base + ut[k] * 3600e3); const l = local(tz, dt); o[k] = l.d === L.d ? l.min : (l.d < L.d ? l.min - 1440 : l.min + 1440); }
  return o;
}
const hm = m => String(Math.floor(((m % 1440) + 1440) % 1440 / 60)).padStart(2, '0') + ':' + String(((m % 60) + 60) % 60).padStart(2, '0');

/* ---------- le planning intelligent ---------- */
const PRN = { fajr: 'Fajr', dhuhr: 'Dhuhr', asr: "'Asr", maghrib: 'Maghrib', isha: "'Ishâ'" };
function plan(tz, L, st) {
  const P = prayersLocal(tz, L), city = cityOf(tz).n;
  st = st && st.d === L.d ? st : { d: L.d, fresh: true }; // nouvelle journée : rien n'est fait
  const pr = st.pr || [], N = [];
  const add = (k, at, title, body, go, cond = true) => { if (cond) N.push({ k, at: Math.round(at), title, body, go }); };
  // heure de chaque prière
  for (const k of ['fajr', 'dhuhr', 'asr', 'maghrib', 'isha']) add('p_' + k, P[k], `C'est l'heure de ${PRN[k]}`, `${hm(P[k])} à ${city}. Coche-la dans MG9 une fois faite.`, 'pg:prayers', !pr.includes(k));
  // rappel avant la fin du temps
  const ends = { fajr: P.sunrise, dhuhr: P.asr, asr: P.maghrib, maghrib: P.isha };
  for (const k in ends) add('e_' + k, ends[k] - 20, `${PRN[k]} pas encore cochée`, `Il reste environ 20 minutes avant la fin de son temps.`, 'pg:prayers', !pr.includes(k));
  add('e_isha', 22 * 60 + 45, "'Ishâ' pas encore cochée", "Prie-la avant de dormir, puis le witr.", 'pg:prayers', !pr.includes('isha'));
  // adhkar
  add('adhM', P.fajr + 25, 'Adhkar du matin', "Le meilleur moment, c'est maintenant (après le Fajr, avant le lever du soleil).", 'adhkar:M', !st.adhM);
  add('adhM2', P.sunrise + 60, 'Adhkar du matin pas encore faits', '5 minutes, et tu es protégé jusqu\'au soir.', 'adhkar:M', !st.adhM);
  add('adhS', P.asr + 25, 'Adhkar du soir', "Après le 'Asr et avant le Maghrib : c'est le moment.", 'adhkar:S', !st.adhS);
  add('coucher', 22 * 60 + 30, 'Witr + adhkar du coucher', 'Termine ta journée en beauté avant de dormir.', 'adhkar:C', !st.adhC || !st.witr);
  // corps et foot
  add('chk', 8 * 60 + 15, 'Check-in forme', '30 secondes : sommeil, énergie, courbatures. MG9 adapte ta séance.', 'chk', !st.chk);
  if (st.train !== false) add('sess', 15 * 60, 'Ta séance du jour t\'attend', st.sessT ? st.sessT : 'Échauffement 12 min, puis on y va.', 'playToday', !st.sess);
  add('load', 20 * 60 + 30, "Note l'effort de ta séance", 'Durée et difficulté : 10 secondes pour suivre ta charge.', 'loadadd', !!st.sess && !st.load);
  const miss = (st.protT || 140) - (st.prot || 0);
  add('prot1', 13 * 60 + 30, 'Protéines', `Tu en es à ${st.prot || 0} g sur ${st.protT || 140}. Pense à un repas riche en protéines ce midi.`, 'pg:nutri', (st.prot || 0) < (st.protT || 140) / 3);
  add('prot2', 19 * 60 + 30, `Il te manque ${miss} g de protéines`, miss > 40 ? 'Idée : poulet-riz, ou un steak haché 5 % + 3 œufs.' : 'Idée : un skyr ou du fromage blanc ce soir.', 'pg:nutri', miss > 15);
  add('eau', 16 * 60, 'Hydratation', `${st.water || 0} bouteille(s) de 50 cl sur ${st.waterT || 6} pour l'instant. Bois-en une maintenant.`, 'pg:nutri', (st.water || 0) < (st.waterT || 6) / 2);
  // Coran, anglais, école
  const qg = st.qg || 2;
  add('quran', 9 * 60 + 30, `Coran : ${qg} page${qg > 1 ? 's' : ''} aujourd'hui`, st.qp ? (qg > 1 ? `Pages ${st.qp} à ${Math.min(604, st.qp + qg - 1)}.` : `Page ${st.qp}.`) : 'Quelques minutes suffisent.', 'tab:vie', !st.quran);
  add('quran2', 21 * 60, 'Coran pas encore lu aujourd\'hui', `Il est encore temps : ${qg} page${qg > 1 ? 's' : ''} avant de dormir.`, 'tab:vie', !st.quran);
  if (L.dw === 5) add('kahf', 11 * 60, 'Vendredi : sourate al-Kahf', 'Pages 293 à 304. Une lumière jusqu\'au vendredi suivant.', 'tab:vie', !st.kahf);
  add('eng', 12 * 60 + 30, 'Anglais : ta session du jour', '8 exercices différents, 3 minutes.', 'eng', !st.eng);
  if ([2, 4, 6].includes(L.dw)) add('sys', 18 * 60, 'Admin sys et réseaux', 'Ton défi du jour : sous-réseaux, terminal, ports.', 'pg:sys', !st.sys);
  if ([0, 1, 2, 3, 4].includes(L.dw)) add('hw', 19 * 60, (st.hw || 0) > 1 ? `${st.hw} devoirs à rendre d'ici demain` : 'Un devoir à rendre d\'ici demain', 'Ouvre MG9 pour voir lesquels.', 'pg:hw', (st.hw || 0) > 0);
  if (L.dw === 0 || L.dw === 3) add('jeune', 21 * 60 + 30, `Demain c'est ${L.dw === 0 ? 'lundi' : 'jeudi'}`, 'Jeûne sunna ? Si tu le fais, pense au sahûr avant le Fajr.', 'tab:vie');
  return N.sort((a, b) => a.at - b.at);
}

/* ---------- cron : toutes les 15 minutes ---------- */
async function run(env, now) {
  const list = await env.MG9.list({ prefix: 'sub:' });
  for (const k of list.keys) {
    const id = k.name.slice(4), rec = await env.MG9.get(k.name, 'json'); if (!rec) continue;
    const tz = rec.tz || 'America/Chicago', L = local(tz, now);
    const st = await env.MG9.get('st:' + id, 'json');
    const sentK = 'sent:' + id + ':' + L.d, sent = (await env.MG9.get(sentK, 'json')) || [];
    const due = plan(tz, L, st).filter(n => n.at <= L.min && n.at > L.min - 30 && !sent.includes(n.k));
    if (!due.length) continue;
    const n = due[due.length - 1]; // une seule notif à la fois : la plus récente
    await sendPush(env, id, rec.sub, { title: n.title, body: n.body, tag: n.k, url: APP + '?go=' + encodeURIComponent(n.go || '') });
    await env.MG9.put(sentK, JSON.stringify([...sent, ...due.map(x => x.k)]), { expirationTtl: 3 * 86400 });
  }
}

/* ---------- API ---------- */
const H = { 'Access-Control-Allow-Origin': ORIGIN, 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'content-type', 'Content-Type': 'application/json' };
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: H });
const okId = id => typeof id === 'string' && /^[a-z0-9]{16,40}$/.test(id);
export default {
  async fetch(req, env) {
    const u = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { headers: H });
    if (u.pathname === '/vapid') return J({ key: (await vapid(env)).pub });
    if (u.pathname === '/plan') { const tz = u.searchParams.get('tz') || 'America/Chicago', L = local(tz, new Date()); return J({ city: cityOf(tz).n, prayers: Object.fromEntries(Object.entries(prayersLocal(tz, L)).map(([k, v]) => [k, hm(v)])), plan: plan(tz, L, null).map(n => hm(n.at) + ' ' + n.title) }); }
    if (req.method !== 'POST') return J({ ok: true, app: 'MG9 push' });
    let b; try { b = JSON.parse(await req.text()); } catch (e) { return J({ error: 'json' }, 400); }
    if (!okId(b.id)) return J({ error: 'id' }, 400);
    if (u.pathname === '/sub') {
      if (!b.sub || !b.sub.endpoint || !/^https:\/\//.test(b.sub.endpoint) || !b.sub.keys) return J({ error: 'sub' }, 400);
      await env.MG9.put('sub:' + b.id, JSON.stringify({ sub: b.sub, tz: b.tz || 'America/Chicago', at: Date.now() }));
      return J({ ok: true });
    }
    if (u.pathname === '/state') {
      if (!b.st || typeof b.st !== 'object' || JSON.stringify(b.st).length > 2000) return J({ error: 'st' }, 400);
      await env.MG9.put('st:' + b.id, JSON.stringify(b.st), { expirationTtl: 7 * 86400 });
      if (b.tz) { const r = await env.MG9.get('sub:' + b.id, 'json'); if (r && r.tz !== b.tz) await env.MG9.put('sub:' + b.id, JSON.stringify({ ...r, tz: b.tz })); }
      return J({ ok: true });
    }
    if (u.pathname === '/test') {
      const r = await env.MG9.get('sub:' + b.id, 'json'); if (!r) return J({ error: 'nosub' }, 404);
      const s = await sendPush(env, b.id, r.sub, { title: 'MG9', body: 'Les notifications marchent. Touche pour ouvrir MG9.', tag: 'test', url: APP + '?go=tab%3Afoot' });
      return J({ ok: s < 300, status: s });
    }
    if (u.pathname === '/unsub') { await env.MG9.delete('sub:' + b.id); return J({ ok: true }); }
    return J({ error: 'route' }, 404);
  },
  async scheduled(ev, env, ctx) { ctx.waitUntil(run(env, new Date(ev.scheduledTime))); },
};
