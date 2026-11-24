// Timetable reminders: runs every minute (Supabase Cron), finds reminders that are due
// and sends them as notifications to every device the person turned notifications on for.
// Secret needed (Edge Functions → Secrets): VAPID_PRIVATE

const VAPID_PUBLIC = 'BCZNELbcnqfLIoxOod4yNgDg_AXqT7onSMqDU3czz5B0ZwbdyFWB8zILgWfDEoAOothIMZn11iHsIHMUvVKdEZA';
const VAPID_SUBJECT = 'https://nadinehisham2-dev.github.io/Timetable-app/';
const WINDOW_MS = 4 * 60 * 1000;   // catch anything due in the last 4 minutes (cron can run late)

/* ---------- small helpers ---------- */
const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const concat = (...arrs) => { const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0)); let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; } return out; };
async function hmac(key, data) { const k = await crypto.subtle.importKey('raw', key, { name:'HMAC', hash:'SHA-256' }, false, ['sign']); return new Uint8Array(await crypto.subtle.sign('HMAC', k, data)); }

/* ---------- Web Push (RFC 8291 aes128gcm + VAPID) ---------- */
async function vapidHeader(endpoint, privateD) {
  const pub = unb64u(VAPID_PUBLIC);
  const key = await crypto.subtle.importKey('jwk', { kty:'EC', crv:'P-256', d:privateD, x:b64u(pub.slice(1, 33)), y:b64u(pub.slice(33, 65)), ext:true },
    { name:'ECDSA', namedCurve:'P-256' }, false, ['sign']);
  const head = b64u(enc.encode(JSON.stringify({ typ:'JWT', alg:'ES256' })));
  const body = b64u(enc.encode(JSON.stringify({ aud:new URL(endpoint).origin, exp:Math.floor(Date.now() / 1000) + 12 * 3600, sub:VAPID_SUBJECT })));
  const sig = await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, key, enc.encode(`${head}.${body}`));
  return `vapid t=${head}.${body}.${b64u(sig)}, k=${VAPID_PUBLIC}`;
}
async function encryptPayload(sub, text) {
  const uaPublic = unb64u(sub.keys.p256dh), authSecret = unb64u(sub.keys.auth);
  const as = await crypto.subtle.generateKey({ name:'ECDH', namedCurve:'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name:'ECDH', namedCurve:'P-256' }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name:'ECDH', public:uaKey }, as.privateKey, 256));
  const prkKey = await hmac(authSecret, ecdh);
  const ikm = (await hmac(prkKey, concat(enc.encode('WebPush: info\0'), uaPublic, asPublic, new Uint8Array([1])))).slice(0, 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hmac(salt, ikm);
  const cek = (await hmac(prk, concat(enc.encode('Content-Encoding: aes128gcm\0'), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, concat(enc.encode('Content-Encoding: nonce\0'), new Uint8Array([1])))).slice(0, 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name:'AES-GCM', iv:nonce }, aes, concat(enc.encode(text), new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]);   // record size 4096
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, cipher);
}
async function sendPush(sub, message, privateD) {
  const res = await fetch(sub.endpoint, {
    method:'POST',
    headers:{ Authorization: await vapidHeader(sub.endpoint, privateD), 'Content-Encoding':'aes128gcm', 'Content-Type':'application/octet-stream', TTL:'3600', Urgency:'high' },
    body: await encryptPayload(sub, JSON.stringify(message)),
  });
  return res.status;
}

/* ---------- Same rules as the app ---------- */
const pad = n => String(n).padStart(2, '0');
const isoOf = d => `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
const parseU = s => { const [y, m, d] = s.split('-').map(Number); return new Date(Date.UTC(y, m - 1, d)); };
const addDays = (s, n) => { const d = parseU(s); d.setUTCDate(d.getUTCDate() + n); return isoOf(d); };
const toMin = t => { if (!t) return null; const [h, m] = t.split(':').map(Number); return h * 60 + m; };
function weekNo(iso) { const dn = parseU(iso).getTime() / 864e5; return Math.floor((dn - (new Date(dn * 864e5).getUTCDay() + 1) % 7) / 7); }
function occurs(e, date) {
  if (!e.repeat) return e.date === date;
  if ((e.skip || []).includes(date)) return false;
  if ((e.extra || []).includes(date)) return true;
  if (date < e.date) return false;
  if (e.repeat.until && date > e.repeat.until) return false;
  const d = parseU(date), r = e.repeat, anchor = r.anchor || e.date, dow = d.getUTCDay();
  if (r.freq === 'daily') return true;
  if (r.freq === 'weekly') { if (!(r.days || []).includes(dow)) return false; const n = r.every || 1; return n === 1 || ((weekNo(date) - weekNo(anchor)) % n + n) % n === 0; }
  if (r.freq === 'monthly') return d.getUTCDate() === parseU(anchor).getUTCDate();
  if (r.freq === 'monthNth') {
    if (!(r.days || []).includes(dow)) return false;
    const day = d.getUTCDate(), nth = Math.ceil(day / 7), last = day + 7 > new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
    return (r.nths || []).some(k => k === nth || (k === -1 && last));
  }
  return false;
}
function cairoOffset(y, m, d) {   // hours ahead of UTC in Alexandria that day (summer/winter time)
  try {
    const parts = new Intl.DateTimeFormat('en-GB', { timeZone:'Africa/Cairo', year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', hourCycle:'h23' }).formatToParts(new Date(Date.UTC(y, m, d, 12)));
    const g = k => +parts.find(x => x.type === k).value;
    const off = (Date.UTC(g('year'), g('month') - 1, g('day'), g('hour'), g('minute')) - Date.UTC(y, m, d, 12)) / 36e5;
    return isFinite(off) ? Math.round(off * 4) / 4 : 2;
  } catch (_) { return 2; }
}
const cairoToUtc = (date, mins) => { const [y, m, d] = date.split('-').map(Number); return Date.UTC(y, m - 1, d, 0, mins) - cairoOffset(y, m - 1, d) * 36e5; };
const cairoToday = () => { const n = Date.now(); const d = new Date(n); return isoOf(new Date(n + cairoOffset(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) * 36e5)); };
// Prayer times for Alexandria, Egyptian General Authority of Survey (same as the app)
const LAT = 31.2001, LNG = 29.9187, rad = d => d * Math.PI / 180, deg = r => r * 180 / Math.PI;
const fix = (a, b) => { a = a - b * Math.floor(a / b); return a < 0 ? a + b : a; };
function sunPos(jd) {
  const D = jd - 2451545.0, g = fix(357.529 + 0.98560028 * D, 360), q = fix(280.459 + 0.98564736 * D, 360);
  const L = fix(q + 1.915 * Math.sin(rad(g)) + 0.020 * Math.sin(rad(2 * g)), 360), e = 23.439 - 0.00000036 * D;
  const RA = fix(deg(Math.atan2(Math.cos(rad(e)) * Math.sin(rad(L)), Math.cos(rad(L)))) / 15, 24);
  return { decl: deg(Math.asin(Math.sin(rad(e)) * Math.sin(rad(L)))), eqt: q / 15 - RA };
}
function prayerMinutes(date) {
  const [y, m, d] = date.split('-').map(Number);
  let Y = y, M = m; if (M <= 2) { Y--; M += 12; }
  const A = Math.floor(Y / 100), B = 2 - A + Math.floor(A / 4);
  const jd0 = Math.floor(365.25 * (Y + 4716)) + Math.floor(30.6001 * (M + 1)) + d + B - 1524.5 - LNG / (15 * 24);
  const noon = t => fix(12 - sunPos(jd0 + t).eqt, 24);
  const angleTime = (angle, t, ccw) => { const dec = sunPos(jd0 + t).decl; const T = deg(Math.acos((-Math.sin(rad(angle)) - Math.sin(rad(dec)) * Math.sin(rad(LAT))) / (Math.cos(rad(dec)) * Math.cos(rad(LAT))))) / 15; return noon(t) + (ccw ? -T : T); };
  const asrTime = t => { const dec = sunPos(jd0 + t).decl; return angleTime(-deg(Math.atan(1 / (1 + Math.tan(rad(Math.abs(LAT - dec)))))), t); };
  let t = { fajr:5, sunrise:6, dhuhr:12, asr:13, maghrib:18, isha:18 };
  for (let i = 0; i < 2; i++) { const f = k => t[k] / 24; t = { fajr:angleTime(19.5, f('fajr'), true), sunrise:angleTime(0.833, f('sunrise'), true), dhuhr:noon(f('dhuhr')), asr:asrTime(f('asr')), maghrib:angleTime(0.833, f('maghrib')), isha:angleTime(17.5, f('isha')) }; }
  const tz = cairoOffset(y, m - 1, d), out = {};
  for (const k in t) out[k] = Math.round((t[k] + tz - LNG / 15) * 60);
  return out;
}
function fmtTime(mins) { let h = Math.floor(mins / 60) % 24, m = mins % 60; const ap = h >= 12 ? 'pm' : 'am'; h = h % 12 || 12; return m ? `${h}:${pad(m)}${ap}` : `${h}${ap}`; }
const remindText = m => m === 0 ? 'now' : m % 10080 === 0 ? `in ${m / 10080} week${m > 10080 ? 's' : ''}` : m % 1440 === 0 ? (m === 1440 ? 'tomorrow' : `in ${m / 1440} days`) : m % 60 === 0 ? `in ${m / 60} hour${m > 60 ? 's' : ''}` : `in ${m} min`;
const NEXT_OF = { fajr:['sunrise', 'Sunrise', 0], dhuhr:['asr', 'Asr', 0], asr:['maghrib', 'Maghrib', 0], maghrib:['isha', 'Isha', 0], isha:['fajr', 'Fajr', 1] };
const PRAYERS = [['fajr', 'Fajr'], ['dhuhr', 'Dhuhr'], ['asr', 'Asr'], ['maghrib', 'Maghrib'], ['isha', 'Isha']];

// Everything due between (now - WINDOW_MS) and now for one person's timetable
function dueReminders(data, now) {
  const out = [], places = data.places || [], today = cairoToday();
  const maxDays = Math.min(60, Math.ceil(Math.max(0, ...(data.entries || []).map(e => e.remind || 0)) / 1440) + 1);
  for (let i = -1; i <= maxDays; i++) {
    const date = addDays(today, i);
    for (const e of data.entries || []) {
      if (e.remind == null || !occurs(e, date)) continue;
      const startMin = toMin(e.start) ?? 8 * 60, at = cairoToUtc(date, startMin) - e.remind * 60000;
      if (at > now || at <= now - WINDOW_MS) continue;
      const p = places.find(x => x.id === e.placeId) || { name:'Reminder' };
      out.push({ key:`${e.id}|${date}|${e.remind}`, title:`${p.name}${e.start ? ' at ' + fmtTime(startMin) : ''}`,
        body:[remindText(e.remind) === 'now' ? 'Starting now' : `Starts ${remindText(e.remind)}`, ...(e.tasks || []).filter(Boolean)].join(' · '), date });
    }
    if (i > 1) continue;   // yesterday is included so Isha's 'before Fajr' reminder works after midnight
    const pt = prayerMinutes(date), pr = data.prayerRemind || {};
    for (const [k, name] of PRAYERS) {
      const m = pr[k]; if (m == null) continue;
      const at = cairoToUtc(date, pt[k]) - m * 60000;
      if (at > now || at <= now - WINDOW_MS) continue;
      out.push({ key:`prayer|${k}|${date}|${m}`, title: m ? `🕌 ${name} ${remindText(m)}` : `🕌 It's time for ${name}`, body:`${name} at ${fmtTime(pt[k])}`, date });
    }
    // second reminder: before the next prayer (so this prayer isn't missed)
    const pe = data.prayerEnd || {};
    for (const [k, name] of PRAYERS) {
      const m = pe[k]; if (m == null) continue;
      const [nk, nName, add] = NEXT_OF[k], nDate = addDays(date, add), nMin = prayerMinutes(nDate)[nk];
      const at = cairoToUtc(nDate, nMin) - m * 60000;
      if (at > now || at <= now - WINDOW_MS) continue;
      out.push({ key:`prayerend|${k}|${date}|${m}`, title:`🕌 Have you prayed ${name}?`, body:`${nName} is ${remindText(m)} (${fmtTime(nMin)})`, date });
    }
  }
  return out;
}

/* ---------- Database (service role, server side only) ---------- */
const SB_URL = (globalThis.Deno && Deno.env.get('SUPABASE_URL')) || '';
const SB_KEY = (globalThis.Deno && (Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || Deno.env.get('SB_SECRET_KEY'))) || '';
async function db(path, method = 'GET', body, prefer) {
  const res = await fetch(`${SB_URL}/rest/v1/${path}`, { method, headers:{ apikey:SB_KEY, Authorization:`Bearer ${SB_KEY}`, 'Content-Type':'application/json', ...(prefer ? { Prefer:prefer } : {}) }, body: body ? JSON.stringify(body) : undefined });
  if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`);
  return res.status === 204 || res.status === 201 ? null : res.json();
}
const cors = { 'Access-Control-Allow-Origin':'*', 'Access-Control-Allow-Headers':'authorization, apikey, content-type', 'Access-Control-Allow-Methods':'POST, OPTIONS' };
const reply = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers:{ ...cors, 'Content-Type':'application/json' } });

async function handler(req) {
  if (req.method === 'OPTIONS') return new Response('ok', { headers:cors });
  const privateD = (globalThis.Deno && Deno.env.get('VAPID_PRIVATE')) || '';
  if (!privateD) return reply({ error:'VAPID_PRIVATE secret is missing' }, 500);
  const body = await req.json().catch(() => ({}));

  // Test button in the app: send a notification to this person's devices right now
  if (body.test) {
    const token = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
    const who = await fetch(`${SB_URL}/auth/v1/user`, { headers:{ apikey:SB_KEY, Authorization:`Bearer ${token}` } });
    if (!who.ok) return reply({ error:'Please sign in again' }, 401);
    const user = await who.json();
    const subs = await db(`push_subs?select=endpoint,sub&user_id=eq.${user.id}`);
    let sent = 0;
    for (const s of subs) { const st = await sendPush(s.sub, { title:'✅ Notifications work', body:'Your Timetable reminders will arrive like this.' }, privateD); if (st < 300) sent++; else if (st === 404 || st === 410) await db(`push_subs?endpoint=eq.${encodeURIComponent(s.endpoint)}`, 'DELETE'); }
    const last = await db('push_sent?select=sent_at&key=eq.cron-last');
    return reply({ sent, devices: subs.length, lastCheck: last[0] ? last[0].sent_at : null });
  }

  // Every minute (Cron): send whatever is due
  const now = Date.now();
  await db('push_sent', 'POST', { key:'cron-last', sent_at:new Date(now).toISOString() }, 'resolution=merge-duplicates,return=minimal');
  const subs = await db('push_subs?select=endpoint,user_id,sub');
  if (!subs.length) return reply({ sent:0 });
  const users = [...new Set(subs.map(s => s.user_id))];
  const rows = await db(`timetables?select=user_id,data&user_id=in.(${users.join(',')})`);
  let sent = 0;
  for (const row of rows) {
    const due = dueReminders(row.data || {}, now);
    for (const r of due) {
      const key = `${row.user_id}|${r.key}`;
      const already = await db(`push_sent?select=key&key=eq.${encodeURIComponent(key)}`);
      if (already.length) continue;
      await db('push_sent', 'POST', { key }, 'resolution=ignore-duplicates,return=minimal');
      for (const s of subs.filter(x => x.user_id === row.user_id)) {
        const st = await sendPush(s.sub, { title:r.title, body:r.body, tag:r.key, date:r.date }, privateD).catch(() => 0);
        if (st && st < 300) sent++;
        else if (st === 404 || st === 410) await db(`push_subs?endpoint=eq.${encodeURIComponent(s.endpoint)}`, 'DELETE');
      }
    }
  }
  if (new Date(now).getUTCMinutes() === 0) await db(`push_sent?sent_at=lt.${new Date(now - 10 * 864e5).toISOString()}&key=neq.cron-last`, 'DELETE').catch(() => {});
  return reply({ sent });
}

if (globalThis.Deno) Deno.serve(handler);
else globalThis.__reminders = { encryptPayload, vapidHeader, dueReminders, prayerMinutes, occurs, cairoToUtc };
