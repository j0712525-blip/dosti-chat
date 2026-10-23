// Dosti Chat v1 — test suite.
// Spawns the real server (temp DATA_DIR/UPLOAD_DIR), keeps the v0.1 flows,
// and adds: restart persistence, ciphertext check (real AES-GCM), edit/delete/reply,
// typing relay, 3-peer mesh signaling, upload, /config, push subscribe, App Lock.
//
// NOTE: the server echoes chat broadcasts to ALL peers including the sender
// (v0.1 flow — the client dedupes via cid). This test drains each client's
// queue in exact order so every assertion reads the intended message.
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const WebSocket = require('ws');
const { DatabaseSync } = require('node:sqlite');
const Lock = require('./public/lock.js');

const APP = __dirname;
const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), 'dosti-test-'));
const DATA_DIR = path.join(tmpBase, 'data');
const UPLOAD_DIR = path.join(tmpBase, 'uploads');
const PORT = 3210;

let passed = 0, failed = 0;
function check(name, cond) {
  if (cond) { passed++; console.log('PASS - ' + name); }
  else { failed++; console.log('FAIL - ' + name); }
}

function startServer() {
  const p = spawn(process.execPath, ['server.js'], {
    cwd: APP,
    env: { ...process.env, PORT: String(PORT), DATA_DIR, UPLOAD_DIR, SWEEP_MS: '200' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  p.stderr.on('data', (d) => process.stderr.write('[srv] ' + d));
  return p;
}
function waitReady(p) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('server not ready')), 12000);
    const h = (d) => { if (d.toString().includes('chal raha hai')) { clearTimeout(t); p.stdout.removeListener('data', h); resolve(); } };
    p.stdout.on('data', h);
  });
}
function stopServer(p) {
  return new Promise((resolve) => {
    if (p.exitCode !== null) return resolve();
    const t = setTimeout(() => { try { p.kill('SIGKILL'); } catch {} }, 3000);
    p.once('exit', () => { clearTimeout(t); resolve(); });
    p.kill();
  });
}

// Buffered WS client — no lost messages between awaits.
function makeClient(ws) {
  const queue = [], waiters = [];
  ws.on('message', (d) => {
    const m = JSON.parse(d.toString());
    if (waiters.length) waiters.shift()(m); else queue.push(m);
  });
  return {
    next(timeoutMs = 5000) {
      if (queue.length) return Promise.resolve(queue.shift());
      return new Promise((resolve, reject) => {
        // NOTE: the waiter removes itself on timeout AND on resolve,
        // otherwise a stale waiter would swallow a later message.
        const waiter = (m) => {
          clearTimeout(t);
          const i = waiters.indexOf(waiter);
          if (i >= 0) waiters.splice(i, 1);
          resolve(m);
        };
        const t = setTimeout(() => {
          const i = waiters.indexOf(waiter);
          if (i >= 0) waiters.splice(i, 1);
          reject(new Error('timeout waiting for message'));
        }, timeoutMs);
        waiters.push(waiter);
      });
    },
    send(o) { ws.send(JSON.stringify(o)); },
    close() { try { ws.close(); } catch {} },
  };
}
function rawConnect() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:${PORT}/ws`);
    ws.once('open', () => resolve(makeClient(ws)));
    ws.once('error', reject);
  });
}
// v2: every socket must present an account session token first.
async function connect(token) {
  const c = await rawConnect();
  if (token) {
    const okP = c.next();
    c.send({ type: 'auth', token });
    const ok = await okP;
    if (ok.type !== 'auth-ok') throw new Error('WS auth failed: ' + JSON.stringify(ok));
  }
  return c;
}
function httpGet(p, headers) {
  return new Promise((resolve, reject) => {
    http.get({ port: PORT, path: p, headers: headers || {} }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    }).on('error', reject);
  });
}
function httpPost(p, body, contentType, headers) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      port: PORT, path: p, method: 'POST',
      headers: { 'Content-Type': contentType, 'Content-Length': body.length, ...(headers || {}) },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

// Real client-side encryption (same params as the browser client).
async function roomKey(code) {
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(code), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: new TextEncoder().encode('dosti-chat-v1'), iterations: 100000, hash: 'SHA-256' },
    km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encText(key, t) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(t));
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv); out.set(new Uint8Array(ct), 12);
  return Buffer.from(out).toString('base64');
}

(async () => {
  let srv = startServer();
  await waitReady(srv);

  // ---- v2 auth: register / login / session gating ----
  const regRes = await httpPost('/api/auth/register', JSON.stringify({
    name: 'Tester', email: 'test@example.com', password: 'secret1',
  }), 'application/json');
  const regJ = JSON.parse(regRes.body);
  check('auth: register ok, returns session token',
    regRes.status === 200 && typeof regJ.token === 'string' && regJ.token.length >= 32 && regJ.account.email === 'test@example.com');
  const TOKEN = regJ.token;
  const authH = { Authorization: 'Bearer ' + TOKEN };

  const dupRes = await httpPost('/api/auth/register', JSON.stringify({
    name: 'Tester2', email: 'test@example.com', password: 'secret2',
  }), 'application/json');
  check('auth: duplicate email rejected', dupRes.status === 409);

  const shortRes = await httpPost('/api/auth/register', JSON.stringify({
    name: 'Shorty', email: 'short@example.com', password: '123',
  }), 'application/json');
  check('auth: short password rejected', shortRes.status === 400);

  const badLogin = await httpPost('/api/auth/login', JSON.stringify({
    email: 'test@example.com', password: 'wrongpass',
  }), 'application/json');
  check('auth: wrong password rejected', badLogin.status === 401);

  const loginRes = await httpPost('/api/auth/login', JSON.stringify({
    email: 'test@example.com', password: 'secret1',
  }), 'application/json');
  const loginJ = JSON.parse(loginRes.body);
  check('auth: login ok', loginRes.status === 200 && typeof loginJ.token === 'string');

  const meRes = await httpGet('/api/auth/me', authH);
  check('auth: /me with token', meRes.status === 200 && JSON.parse(meRes.body.toString()).account.email === 'test@example.com');
  check('auth: /me without token → 401', (await httpGet('/api/auth/me')).status === 401);
  check('auth: /config without token → 401', (await httpGet('/config')).status === 401);

  const badWs = await rawConnect();
  badWs.send({ type: 'create-room', userId: 'uBad', name: 'Bad' });
  const badMsg = await badWs.next();
  check('auth: unauthenticated WS rejected', badMsg.type === 'auth-error');
  badWs.close();

  // ---- v0.1 flow: create room ----
  const a = await connect(TOKEN);
  a.send({ type: 'create-room', userId: 'uTestA', name: 'Ali', avatar: '😎' });
  const created = await a.next();
  check('room created: 6-char code, peerId = userId',
    created.type === 'room-created' && /^[A-Z0-9]{6}$/.test(created.roomCode) && created.peerId === 'uTestA');
  const code = created.roomCode;
  const key = await roomKey(code);

  // ---- v0.1 flow: join ----            // queues: a:[], b:[]
  const b = await connect(TOKEN);
  const bJoinP = b.next(), aPeerP = a.next();
  b.send({ type: 'join', roomCode: code, userId: 'uTestB', name: 'Bestie', avatar: '🥀' });
  const joined = await bJoinP;
  check('join ok, sees Ali with avatar',
    joined.type === 'joined' && joined.peers.length === 1 && joined.peers[0].name === 'Ali' && joined.peers[0].avatar === '😎');
  check('members list present', Array.isArray(joined.members) && joined.members.length === 2);
  const pj = await aPeerP;
  check('peer-joined broadcast with avatar', pj.type === 'peer-joined' && pj.id === 'uTestB' && pj.avatar === '🥀');

  // ---- encrypted chat relay ----       // a:[chat#1], b:[chat#1] → consume b's
  const SECRET = 'asli secret message ' + Date.now();
  const ct1 = await encText(key, SECRET);
  const chatP = b.next();
  a.send({ type: 'chat', kind: 'text', payload: ct1, cid: 'c1' });
  const chat = await chatP;
  check('chat relayed with id + echoed cid',
    chat.type === 'chat' && typeof chat.id === 'number' && chat.cid === 'c1' && chat.payload === ct1 && chat.from === 'uTestA');
  // a's queue still holds its own echo: [chat#1]

  // ---- (b) ciphertext in DB — server never sees plaintext ----
  const db = new DatabaseSync(path.join(DATA_DIR, 'chat.db'));
  const row = db.prepare('SELECT payload FROM messages WHERE id=?').get(chat.id);
  check('DB stores ciphertext only (no plaintext)',
    !!row && row.payload === ct1 && !row.payload.includes('asli secret'));

  // ---- v0.1 flow: signal relay ----
  const sigP = b.next();
  a.send({ type: 'signal', to: 'uTestB', data: { kind: 'offer', sdp: 'FAKE', video: true } });
  const sig = await sigP;
  check('signal relayed', sig.type === 'signal' && sig.from === 'uTestA' && sig.data.kind === 'offer');

  // ---- (d) typing relay ----
  const tyP = b.next();
  a.send({ type: 'typing', typing: true });
  const ty = await tyP;
  check('typing relayed', ty.type === 'typing' && ty.from === 'uTestA' && ty.typing === true && ty.name === 'Ali');
  const tyP2 = b.next();
  a.send({ type: 'typing', typing: false });
  check('typing=false relayed', (await tyP2).typing === false);

  // ---- (c) reply ----                  // b:[chat#2] → consume b's (b's queue is empty)
  const ct2 = await encText(key, 'reply wala message');
  const repP = b.next();
  b.send({ type: 'chat', kind: 'text', payload: ct2, replyTo: chat.id });
  const rep = await repP;
  check('reply carries replyTo', rep.type === 'chat' && rep.replyTo === chat.id);
  const replyId = rep.id;
  // a's queue: [chat#1, chat#2]

  // ---- (c) edit by owner ----          // b:[] → edit broadcast lands cleanly
  const ctEdit = await encText(key, 'edited text');
  const edP = b.next();
  a.send({ type: 'edit', id: chat.id, payload: ctEdit });
  const ed = await edP;
  check('edit broadcast', ed.type === 'edit' && ed.id === chat.id && ed.edited === true);
  const erow = db.prepare('SELECT payload, edited FROM messages WHERE id=?').get(chat.id);
  check('edit persisted', erow.payload === ctEdit && erow.edited === 1);
  // a's queue: [chat#1, chat#2, edit]

  // ---- edit by non-owner must be ignored ----
  await a.next(); await a.next(); await a.next(); // drain a's queue
  b.send({ type: 'edit', id: chat.id, payload: 'HACK' });
  let leaked = false;
  try { await a.next(400); leaked = true; } catch { /* timeout = good */ }
  check('non-owner edit ignored', !leaked);

  // ---- (c) delete by owner ----
  const delP = a.next();
  b.send({ type: 'delete', id: replyId });
  const del = await delP;
  check('delete broadcast', del.type === 'delete' && del.id === replyId);
  const drow = db.prepare('SELECT payload, deleted FROM messages WHERE id=?').get(replyId);
  check('delete persisted as marker', drow.payload === 'deleted' && drow.deleted === 1);

  // ---- ticks ----
  const tickP = a.next();
  b.send({ type: 'read', upToTs: 123456789 });
  const tick = await tickP;
  check('ticks relayed', tick.type === 'ticks' && tick.userId === 'uTestB' && tick.upToTs === 123456789);

  // ---- v0.1 flow: bad code rejected ----
  const c0 = await connect(TOKEN);
  c0.send({ type: 'join', roomCode: 'ZZZZZZ', userId: 'uX', name: 'X' });
  check('bad code rejected', (await c0.next()).type === 'error');
  c0.close();

  // ---- presence: C joins ----          // b has stale [delete] queued — drain first
  await b.next(); // drain stale delete
  const c = await connect(TOKEN);
  const cJoinP = c.next();
  c.send({ type: 'join', roomCode: code, userId: 'uTestC', name: 'Chintu', avatar: '🔥' });
  const cj = await cJoinP;
  check('C joined, sees 2 online peers', cj.type === 'joined' && cj.peers.length === 2);
  await a.next(); // drain peer-joined on a
  await b.next(); // drain peer-joined on b

  // ---- C leaves → peer-left + lastSeen ----
  c.close();
  const plP = a.next(), plB = b.next();
  const pl = await plP;
  await plB; // drain b's copy
  check('peer-left carries lastSeen', pl.type === 'peer-left' && pl.id === 'uTestC' && pl.lastSeen > 0);
  const urow = db.prepare('SELECT lastSeen FROM users WHERE userId=?').get('uTestC');
  check('lastSeen persisted', !!urow && urow.lastSeen > 0);

  // ---- (e) 3-peer mesh signaling ----
  const c2 = await connect(TOKEN);
  const c2JoinP = c2.next();
  c2.send({ type: 'join', roomCode: code, userId: 'uTestC', name: 'Chintu', avatar: '🔥' });
  await c2JoinP;
  await a.next(); // drain peer-joined
  await b.next(); // drain peer-joined
  const sB = b.next(), sC = c2.next();
  a.send({ type: 'signal', to: 'uTestB', data: { kind: 'offer', sdp: 'MESH1', group: true } });
  a.send({ type: 'signal', to: 'uTestC', data: { kind: 'offer', sdp: 'MESH2', group: true } });
  const [mB, mC] = await Promise.all([sB, sC]);
  check('mesh: A→B group offer', mB.type === 'signal' && mB.from === 'uTestA' && mB.data.group === true);
  check('mesh: A→C group offer', mC.type === 'signal' && mC.from === 'uTestA' && mC.data.group === true);

  // ---- upload (encrypted bytes) ----
  const boundary = '----dostitest123';
  const fileBytes = Buffer.from('ENCRYPTEDFILEBYTES');
  const mpBody = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="f.bin"\r\nContent-Type: application/octet-stream\r\n\r\n`),
    fileBytes,
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
  const upNoAuth = await httpPost(`/upload?room=${code}`, mpBody, `multipart/form-data; boundary=${boundary}`);
  check('auth: upload without token → 401', upNoAuth.status === 401);
  const up = await httpPost(`/upload?room=${code}`, mpBody, `multipart/form-data; boundary=${boundary}`, authH);
  const upJ = JSON.parse(up.body);
  check('upload returns unguessable name', up.status === 200 && /^[0-9a-f]{32}$/.test(upJ.file));
  const dl = await httpGet(`/uploads/${code}/${upJ.file}`, authH);
  check('uploaded bytes served back', dl.status === 200 && dl.body.equals(fileBytes));
  check('auth: download without token → 401', (await httpGet(`/uploads/${code}/${upJ.file}`)).status === 401);

  // ---- /config ----
  const cfgJ = JSON.parse((await httpGet('/config', authH)).body.toString());
  check('/config: iceServers + vapidPublicKey',
    Array.isArray(cfgJ.iceServers) && cfgJ.iceServers.length > 0 &&
    typeof cfgJ.vapidPublicKey === 'string' && cfgJ.vapidPublicKey.length > 20);

  // ---- push subscribe ----
  const subRes = await httpPost('/push/subscribe', JSON.stringify({
    userId: 'uTestB', room: code,
    sub: { endpoint: 'https://example.com/push/123', keys: { p256dh: 'x', auth: 'y' } },
  }), 'application/json', authH);
  check('push subscribe ok', subRes.status === 200 && JSON.parse(subRes.body).ok === true);
  check('push sub stored', !!db.prepare('SELECT sub FROM push_subs WHERE userId=? AND room=?').get('uTestB', code));

  // ---- v2: reactions ----            // a:[], b:[], c2:[] → broadcasts land in order
  const rxP = b.next();
  a.send({ type: 'reaction', id: chat.id, emoji: '❤️' });
  const rx = await rxP;
  check('reaction broadcast (on)',
    rx.type === 'reaction' && rx.id === chat.id && rx.emoji === '❤️' && rx.userId === 'uTestA' && rx.on === true);
  await a.next(); // sender's own copy
  check('reaction persisted',
    !!db.prepare('SELECT 1 AS x FROM reactions WHERE msgId=? AND userId=? AND emoji=?').get(chat.id, 'uTestA', '❤️'));
  const rxP2 = b.next();
  a.send({ type: 'reaction', id: chat.id, emoji: '❤️' });
  check('reaction toggle off', (await rxP2).on === false);
  await a.next();
  check('reaction removed from DB', !db.prepare('SELECT 1 AS x FROM reactions WHERE msgId=?').get(chat.id));
  const rxP3 = b.next();               // back ON — restart check verifies restore
  a.send({ type: 'reaction', id: chat.id, emoji: '❤️' });
  await rxP3; await a.next();

  // ---- v2: pin ----
  const pinP = b.next();
  a.send({ type: 'pin', id: chat.id });
  const pinM = await pinP;
  check('pin broadcast', pinM.type === 'pin' && pinM.id === chat.id);
  await a.next();
  check('pin persisted',
    (db.prepare('SELECT pinnedId FROM room_settings WHERE room=?').get(code) || {}).pinnedId === chat.id);
  const pinP2 = b.next();
  a.send({ type: 'pin', id: null });
  check('unpin broadcast', (await pinP2).id === null);
  await a.next();
  const pinP3 = b.next();              // pinned again — restart check verifies restore
  a.send({ type: 'pin', id: chat.id });
  await pinP3; await a.next();

  // ---- v2: disappearing messages + expiry sweep (SWEEP_MS=200 in test env) ----
  const disP = b.next();
  a.send({ type: 'disappear', ms: 400 });
  const disM = await disP;
  check('disappear broadcast', disM.type === 'disappear' && disM.ms === 400 && disM.by === 'Ali');
  await a.next();
  const ctExp = await encText(key, 'gayab hone wala message');
  const expP = b.next();
  a.send({ type: 'chat', kind: 'text', payload: ctExp, cid: 'cx1' });
  const expM = await expP;
  check('expiring chat carries expiresAt', expM.type === 'chat' && expM.expiresAt > expM.ts);
  await a.next(); // sender echo
  const expId = expM.id;
  const gone = await b.next(8000);
  check('expire broadcast after sweep', gone.type === 'expire' && gone.id === expId);
  await a.next(8000); // sender's expire copy
  check('expired message hard-deleted', !db.prepare('SELECT 1 AS x FROM messages WHERE id=?').get(expId));
  const disP2 = b.next();
  a.send({ type: 'disappear', ms: 0 });
  await disP2; await a.next();

  // ---- v2: generic file upload round-trip (any file type) ----
  const fBoundary = '----dostifile42';
  const pdfBytes = Buffer.from('ENCRYPTED-PDF-BYTES-%PDF-1.4');
  const fBody = Buffer.concat([
    Buffer.from(`--${fBoundary}\r\nContent-Disposition: form-data; name="file"; filename="report.pdf"\r\nContent-Type: application/pdf\r\n\r\n`),
    pdfBytes,
    Buffer.from(`\r\n--${fBoundary}--\r\n`),
  ]);
  const fUp = await httpPost(`/upload?room=${code}`, fBody, `multipart/form-data; boundary=${fBoundary}`, authH);
  const fUpJ = JSON.parse(fUp.body);
  const fDl = await httpGet(`/uploads/${code}/${fUpJ.file}`, authH);
  check('generic file upload/download round-trip',
    fUp.status === 200 && fDl.status === 200 && fDl.body.equals(pdfBytes));

  // ---- v2: vault — server stores opaque ciphertext only ----
  const vaultBlob = await encText(key, JSON.stringify({ rooms: [{ code: 'MARKRM', name: 'gizli room' }] }));
  const vPut = await fetch(`http://localhost:${PORT}/api/vault`, {
    method: 'PUT', headers: { ...authH, 'Content-Type': 'application/json' },
    body: JSON.stringify({ blob: vaultBlob }),
  });
  check('vault: PUT ok', vPut.status === 200);
  const vGetJ = await (await fetch(`http://localhost:${PORT}/api/vault`, { headers: authH })).json();
  check('vault: GET round-trip', vGetJ.blob === vaultBlob);
  check('vault: requires auth', (await fetch(`http://localhost:${PORT}/api/vault`)).status === 401);
  const vrow = db.prepare('SELECT blob FROM vaults').get();
  check('vault: DB stores ciphertext only',
    !!vrow && vrow.blob === vaultBlob && !vrow.blob.includes('MARKRM') && !vrow.blob.includes('gizli'));

  // ================= v3: accounts, contacts, DMs, presence, avatars =================
  const API = `http://localhost:${PORT}`;
  async function jfetch(method, p, token, body) {
    const r = await fetch(API + p, {
      method,
      headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), 'Content-Type': 'application/json' },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    let j = null;
    try { j = await r.json(); } catch {}
    return { status: r.status, headers: r.headers, j };
  }
  async function nextType(client, type, timeout = 8000) {
    const t0 = Date.now();
    for (;;) {
      const m = await client.next(Math.max(1, timeout - (Date.now() - t0)));
      if (m.type === type) return m;
    }
  }

  // second + third accounts (C registers WITH the optional phone)
  const AID = regJ.account.id;
  const regB = await jfetch('POST', '/api/auth/register', null, { name: 'Bestie Two', email: 'bestie2@example.com', password: 'secret2' });
  check('v3: register B ok', regB.status === 200 && regB.j.account && typeof regB.j.account.id === 'number');
  const TOKEN_B = regB.j.token, BID = regB.j.account.id;
  const regC = await jfetch('POST', '/api/auth/register', null, { name: 'Third Person', email: 'third@example.com', password: 'secret3', phone: '+1 (555) 010-2030' });
  const TOKEN_C = regC.j.token, CID = regC.j.account.id;
  check('v3: register with optional phone (normalized)',
    regC.status === 200 && regC.j.account.phone === '+15550102030');

  // ---- pubkey set/get (RSA-OAEP, like the browser's WebCrypto pair) ----
  const { publicKey: pubB, privateKey: privB } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pubJwkB = pubB.export({ format: 'jwk' });
  check('v3: pubkey PUT requires auth', (await jfetch('PUT', '/api/auth/pubkey', null, { pubKey: pubJwkB })).status === 401);
  check('v3: pubkey PUT ok', (await jfetch('PUT', '/api/auth/pubkey', TOKEN_B, { pubKey: pubJwkB })).status === 200);
  const pkGet = await jfetch('GET', `/api/users/${BID}/pubkey`, TOKEN);
  check('v3: pubkey GET round-trip',
    pkGet.status === 200 && pkGet.j.pubKey && pkGet.j.pubKey.kty === 'RSA' && pkGet.j.pubKey.n === pubJwkB.n);
  const meB = await jfetch('GET', '/api/auth/me', TOKEN_B);
  check('v3: /me reports hasPubKey + pubKey',
    meB.j.account.hasPubKey === true && meB.j.pubKey && meB.j.pubKey.n === pubJwkB.n);

  // ---- profile: phone set later via profile update ----
  check('v3: invalid phone rejected', (await jfetch('PUT', '/api/auth/profile', TOKEN_B, { phone: 'abc' })).status === 400);
  const profB = await jfetch('PUT', '/api/auth/profile', TOKEN_B, { name: 'Bestie Two', phone: '+92 300-1234567' });
  check('v3: profile update sets phone (normalized)',
    profB.status === 200 && profB.j.account.phone === '+923001234567');

  // ---- user search: name / email / phone / not-found / auth / no self ----
  const sNameHit = ((await jfetch('GET', '/api/users/search?q=' + encodeURIComponent('Bestie'), TOKEN)).j.users || [])
    .find((u) => u.id === BID);
  check('v3: search by name finds user (+phone shown)', !!sNameHit && sNameHit.phone === '+923001234567');
  check('v3: search by email finds user',
    ((await jfetch('GET', '/api/users/search?q=' + encodeURIComponent('third@example'), TOKEN)).j.users || [])
      .some((u) => u.id === CID));
  check('v3: search by phone digits finds user',
    ((await jfetch('GET', '/api/users/search?q=' + encodeURIComponent('3001234'), TOKEN)).j.users || [])
      .some((u) => u.id === BID));
  const sNone = await jfetch('GET', '/api/users/search?q=' + encodeURIComponent('zzzznope'), TOKEN);
  check('v3: search not found → empty list', sNone.status === 200 && Array.isArray(sNone.j.users) && sNone.j.users.length === 0);
  check('v3: search requires auth', (await jfetch('GET', '/api/users/search?q=Bestie', null)).status === 401);
  check('v3: search excludes self',
    !((await jfetch('GET', '/api/users/search?q=' + encodeURIComponent('Tester'), TOKEN)).j.users || [])
      .some((u) => u.id === AID));

  // ---- profile photo (PP): set → GET bytes/type; oversize rejected ----
  const jpgBytes = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(64, 7), Buffer.from([0xff, 0xd9])]);
  const avPut = await jfetch('PUT', '/api/auth/avatar', TOKEN_B, { data: jpgBytes.toString('base64') });
  check('v3: avatar PUT ok, avatarVer=1', avPut.status === 200 && avPut.j.avatarVer === 1 && avPut.j.hasAvatar === true);
  const avGet = await fetch(`${API}/api/users/${BID}/avatar`, { headers: { Authorization: 'Bearer ' + TOKEN } });
  const avBytes = Buffer.from(await avGet.arrayBuffer());
  check('v3: avatar GET returns same bytes + image content type',
    avGet.status === 200 && avBytes.equals(jpgBytes) && (avGet.headers.get('content-type') || '').includes('image/jpeg'));
  check('v3: avatar GET requires auth', (await fetch(`${API}/api/users/${BID}/avatar`)).status === 401);
  check('v3: oversize avatar rejected',
    (await jfetch('PUT', '/api/auth/avatar', TOKEN_B, { data: Buffer.alloc(301 * 1024, 1).toString('base64') })).status === 400);
  const sAvHit = ((await jfetch('GET', '/api/users/search?q=' + encodeURIComponent('Bestie'), TOKEN)).j.users || [])
    .find((u) => u.id === BID);
  check('v3: search payload shows hasAvatar + avatarVer + phone',
    !!sAvHit && sAvHit.hasAvatar === true && sAvHit.avatarVer === 1 && sAvHit.phone === '+923001234567');

  // ---- contact request → accept (real RSA envelope, browser-equivalent) ----
  check('v3: self-add rejected',
    (await jfetch('POST', '/api/contacts/request', TOKEN, { toId: AID, envelope: 'x'.repeat(40) })).status === 400);
  const dmCode = 'DMV3X9';
  const envelope = crypto.publicEncrypt(
    { key: pubB, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(dmCode, 'utf8')).toString('base64');
  const reqAB = await jfetch('POST', '/api/contacts/request', TOKEN, { toId: BID, envelope });
  check('v3: contact request created', reqAB.status === 200 && typeof reqAB.j.requestId === 'number');
  check('v3: duplicate pending request rejected',
    (await jfetch('POST', '/api/contacts/request', TOKEN, { toId: BID, envelope })).status === 409);
  const inHit = ((await jfetch('GET', '/api/contacts/requests', TOKEN_B)).j.incoming || [])
    .find((r) => r.id === reqAB.j.requestId);
  check('v3: recipient sees incoming request + envelope', !!inHit && inHit.envelope === envelope && inHit.fromId === AID);
  const decCode = crypto.privateDecrypt(
    { key: privB, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(inHit.envelope, 'base64')).toString('utf8');
  check('v3: envelope decrypts to the DM code', decCode === dmCode);
  const dmRoomId = crypto.createHash('sha256').update(decCode).digest('hex');
  check('v3: non-recipient cannot respond',
    (await jfetch('POST', '/api/contacts/respond', TOKEN, { requestId: reqAB.j.requestId, accept: true, dmRoomId })).status === 403);
  check('v3: accept ok',
    (await jfetch('POST', '/api/contacts/respond', TOKEN_B, { requestId: reqAB.j.requestId, accept: true, dmRoomId })).status === 200);
  const crows = db.prepare('SELECT owner_id, contact_id, dm_room_id FROM contacts').all();
  check('v3: accept creates BOTH contact rows with the dmRoomId',
    crows.length === 2
    && crows.some((r) => r.owner_id === AID && r.contact_id === BID && r.dm_room_id === dmRoomId)
    && crows.some((r) => r.owner_id === BID && r.contact_id === AID && r.dm_room_id === dmRoomId));
  const cAHit = ((await jfetch('GET', '/api/contacts', TOKEN)).j.contacts || []).find((c) => c.contactId === BID);
  check('v3: contacts list (A) has B with dmRoomId + phone + hasAvatar + online flag',
    !!cAHit && cAHit.dmRoomId === dmRoomId && cAHit.phone === '+923001234567'
    && cAHit.hasAvatar === true && typeof cAHit.online === 'boolean');
  check('v3: contacts list (B) has A',
    ((await jfetch('GET', '/api/contacts', TOKEN_B)).j.contacts || [])
      .some((c) => c.contactId === AID && c.dmRoomId === dmRoomId));
  check('v3: request to an existing contact rejected',
    (await jfetch('POST', '/api/contacts/request', TOKEN, { toId: BID, envelope })).status === 409);

  // ---- decline path: A → C, C declines ----
  const reqAC = await jfetch('POST', '/api/contacts/request', TOKEN, { toId: CID, envelope: 'y'.repeat(40) });
  check('v3: request to C created', reqAC.status === 200);
  check('v3: decline ok',
    (await jfetch('POST', '/api/contacts/respond', TOKEN_C, { requestId: reqAC.j.requestId, accept: false })).status === 200);
  check('v3: declined → no contact row',
    !((await jfetch('GET', '/api/contacts', TOKEN)).j.contacts || []).some((c) => c.contactId === CID));
  check('v3: declined request leaves the pending list',
    ((await jfetch('GET', '/api/contacts/requests', TOKEN_C)).j.incoming || []).length === 0);

  // ---- end-to-end DM: B opens the room with the decrypted code, A joins ----
  const dmKey = await roomKey(dmCode);
  const dB = await connect(TOKEN_B);
  dB.send({ type: 'create-room-with-code', roomCode: dmCode, userId: 'uDmB', name: 'Bestie Two', avatar: '🥀' });
  const dBj = await nextType(dB, 'joined');
  check('v3: DM room created on demand via code',
    dBj.roomCode === dmCode && Array.isArray(dBj.history) && dBj.history.length === 0);
  const dA = await connect(TOKEN);
  dA.send({ type: 'join', roomCode: dmCode, userId: 'uDmA', name: 'Ali', avatar: '😎' });
  const dAj = await nextType(dA, 'joined');
  check('v3: requester joins the DM room', dAj.type === 'joined' && dAj.peers.some((p) => p.id === 'uDmB'));
  const dmCt1 = await encText(dmKey, 'salam bestie — personal chat');
  dA.send({ type: 'chat', kind: 'text', payload: dmCt1, cid: 'dm1' });
  const dmMsg1 = await nextType(dB, 'chat');
  check('v3: DM message A→B (ciphertext relay)', dmMsg1.payload === dmCt1 && dmMsg1.from === 'uDmA');
  await nextType(dA, 'chat'); // A's own echo
  const dmCt2 = await encText(dmKey, 'walaikum salam!');
  dB.send({ type: 'chat', kind: 'text', payload: dmCt2, cid: 'dm2' });
  const dmMsg2 = await nextType(dA, 'chat');
  check('v3: DM message B→A', dmMsg2.payload === dmCt2 && dmMsg2.from === 'uDmB');
  await nextType(dB, 'chat'); // B's own echo
  const lastDm = await jfetch('GET', `/api/rooms/${dmCode}/last?since=0&me=uDmA`, TOKEN);
  check('v3: /last returns DM tail + unread count',
    lastDm.status === 200 && !!lastDm.j.msg && lastDm.j.msg.payload === dmCt2 && lastDm.j.unread === 1);
  check('v3: /last requires auth', (await jfetch('GET', `/api/rooms/${dmCode}/last`, null)).status === 401);
  dA.close(); dB.close();

  // ---- presence: online flip on connect, push to contact, lastSeen ----
  // dB's close above is async — wait until the server has fully registered
  // B as offline, otherwise B's socket count never transitions 0→1 below.
  for (let i = 0; i < 50; i++) {
    const cc = ((await jfetch('GET', '/api/contacts', TOKEN)).j.contacts || []).find((c) => c.contactId === BID);
    if (cc && cc.online === false) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  const aP = await connect(TOKEN);
  const bP = await connect(TOKEN_B);
  const presOn = await nextType(aP, 'presence');
  check('v3: presence push — contact came online', presOn.contactId === BID && presOn.online === true);
  const cOn = ((await jfetch('GET', '/api/contacts', TOKEN)).j.contacts || []).find((c) => c.contactId === BID);
  check('v3: contacts list shows online=true', !!cOn && cOn.online === true);
  bP.close();
  const presOff = await nextType(aP, 'presence');
  check('v3: presence push — contact went offline with lastSeen',
    presOff.contactId === BID && presOff.online === false && presOff.lastSeen > 0);
  const cOff = ((await jfetch('GET', '/api/contacts', TOKEN)).j.contacts || []).find((c) => c.contactId === BID);
  check('v3: contacts list shows online=false + lastSeen', !!cOff && cOff.online === false && cOff.lastSeen > 0);
  aP.close();

  // ================= v4: name-only (anon) entry — no email, no password =================
  const anonRes = await jfetch('POST', '/api/auth/anon', null, { name: 'Anon One' });
  check('v4: anon create ok — token + account, no real email',
    anonRes.status === 200 && typeof anonRes.j.token === 'string' && anonRes.j.token.length >= 32
    && anonRes.j.account.name === 'Anon One' && anonRes.j.account.email === null);
  const TOK_A1 = anonRes.j.token, A1ID = anonRes.j.account.id;
  check('v4: anon without a name rejected', (await jfetch('POST', '/api/auth/anon', null, {})).status === 400);
  check('v4: anon token opens gated /config', (await jfetch('GET', '/config', TOK_A1)).status === 200);
  const meA1 = await jfetch('GET', '/api/auth/me', TOK_A1);
  check('v4: anon /me returns the same account',
    meA1.status === 200 && meA1.j.account.id === A1ID && meA1.j.account.name === 'Anon One');
  const wsA1 = await connect(TOK_A1);   // connect() asserts the WS auth-ok handshake
  wsA1.send({ type: 'create-room', userId: 'uAnon1', name: 'Anon One', avatar: '😎' });
  const a1Room = await wsA1.next();
  check('v4: anon WS accepted + can create a room',
    a1Room.type === 'room-created' && /^[A-Z0-9]{6}$/.test(a1Room.roomCode));
  wsA1.close();

  // anon profile / pubkey / avatar updates all work off the anon token
  const profA1 = await jfetch('PUT', '/api/auth/profile', TOK_A1, { name: 'Anon One', phone: '+92 321-5556677' });
  check('v4: anon profile update (phone) works',
    profA1.status === 200 && profA1.j.account.phone === '+923215556677');
  const anon2 = await jfetch('POST', '/api/auth/anon', null, { name: 'Anon Two' });
  const TOK_A2 = anon2.j.token, A2ID = anon2.j.account.id;
  check('v4: second anon create ok (distinct account)', anon2.status === 200 && A2ID !== A1ID);
  const { publicKey: pubA2, privateKey: privA2 } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pubJwkA2 = pubA2.export({ format: 'jwk' });
  check('v4: anon pubkey PUT ok', (await jfetch('PUT', '/api/auth/pubkey', TOK_A2, { pubKey: pubJwkA2 })).status === 200);
  check('v4: anon avatar PUT ok',
    (await jfetch('PUT', '/api/auth/avatar', TOK_A2, { data: jpgBytes.toString('base64') })).status === 200);
  check('v4: search by name finds an anon account',
    ((await jfetch('GET', '/api/users/search?q=' + encodeURIComponent('Anon Two'), TOK_A1)).j.users || [])
      .some((u) => u.id === A2ID));

  // two anon accounts: contact-request → accept → DM messages, end to end
  const dmCode4 = 'DMV4Z2';
  const env4 = crypto.publicEncrypt(
    { key: pubA2, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(dmCode4, 'utf8')).toString('base64');
  const req4 = await jfetch('POST', '/api/contacts/request', TOK_A1, { toId: A2ID, envelope: env4 });
  check('v4: anon contact request created', req4.status === 200 && typeof req4.j.requestId === 'number');
  const in4 = ((await jfetch('GET', '/api/contacts/requests', TOK_A2)).j.incoming || [])
    .find((r) => r.id === req4.j.requestId);
  const dec4 = crypto.privateDecrypt(
    { key: privA2, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(in4.envelope, 'base64')).toString('utf8');
  const dmRoomId4 = crypto.createHash('sha256').update(dec4).digest('hex');
  check('v4: anon accept ok',
    (await jfetch('POST', '/api/contacts/respond', TOK_A2, { requestId: req4.j.requestId, accept: true, dmRoomId: dmRoomId4 })).status === 200);
  check('v4: anon contacts exist both ways',
    ((await jfetch('GET', '/api/contacts', TOK_A1)).j.contacts || []).some((c) => c.contactId === A2ID)
    && ((await jfetch('GET', '/api/contacts', TOK_A2)).j.contacts || []).some((c) => c.contactId === A1ID));
  const dmKey4 = await roomKey(dmCode4);
  const dA2 = await connect(TOK_A2);
  dA2.send({ type: 'create-room-with-code', roomCode: dmCode4, userId: 'uAnon2', name: 'Anon Two', avatar: '🥀' });
  await nextType(dA2, 'joined');
  const dA1 = await connect(TOK_A1);
  dA1.send({ type: 'join', roomCode: dmCode4, userId: 'uAnon1', name: 'Anon One', avatar: '😎' });
  await nextType(dA1, 'joined');
  const dmCt41 = await encText(dmKey4, 'salam — naam wala login');
  dA1.send({ type: 'chat', kind: 'text', payload: dmCt41, cid: 'v41' });
  const dmMsg41 = await nextType(dA2, 'chat');
  check('v4: anon DM message A1→A2', dmMsg41.payload === dmCt41 && dmMsg41.from === 'uAnon1');
  await nextType(dA1, 'chat'); // A1's own echo
  const dmCt42 = await encText(dmKey4, 'jawab bhi aa gaya');
  dA2.send({ type: 'chat', kind: 'text', payload: dmCt42, cid: 'v42' });
  const dmMsg42 = await nextType(dA1, 'chat');
  check('v4: anon DM message A2→A1', dmMsg42.payload === dmCt42 && dmMsg42.from === 'uAnon2');
  await nextType(dA2, 'chat'); // A2's own echo
  dA1.close(); dA2.close();

  // ---- static assets ----
  const pg = await httpGet('/');
  check('client page served', pg.status === 200 && pg.body.toString().includes('Dosti Chat'));
  check('sw.js served', (await httpGet('/sw.js')).body.toString().includes('push'));
  check('manifest served', JSON.parse((await httpGet('/manifest.json')).body.toString()).name === 'Dosti Chat');
  const ic = await httpGet('/icon-192.png');
  check('icon png served', ic.status === 200 && ic.headers['content-type'] === 'image/png' && ic.body[0] === 0x89 && ic.body[1] === 0x50);
  check('lock.js served', (await httpGet('/lock.js')).body.toString().includes('DostiLock'));

  // ---- App Lock unit tests ----
  const h1 = await Lock.hashPin('1234');
  check('lock: hash is 64-hex, never plaintext', /^[0-9a-f]{64}$/.test(h1) && h1 !== '1234');
  check('lock: correct PIN verifies', (await Lock.verifyPin('1234', h1)) === true);
  check('lock: wrong PIN rejected', (await Lock.verifyPin('0000', h1)) === false);
  const stored = JSON.parse(JSON.stringify(h1)); // reload-like: fresh copy of the stored hash
  check('lock: verifies after reload-like state', (await Lock.verifyPin('1234', stored)) === true);
  const plainSha = crypto.createHash('sha256').update('1234', 'utf8').digest('hex');
  check('lock: salted (differs from plain sha256)', h1 !== plainSha);
  check('lock: deterministic', (await Lock.hashPin('1234')) === h1);
  check('lock: different PINs → different hashes', (await Lock.hashPin('4321')) !== h1);
  const l2 = Lock.nextLockoutState(2), l3 = Lock.nextLockoutState(3);
  check('lock: 2 fails → not locked out', l2.lockedOut === false);
  check('lock: 3 fails → 30s cooldown', l3.lockedOut === true && l3.cooldownMs === 30000);
  check('lock: validPin', Lock.validPin('1234') && !Lock.validPin('12') && !Lock.validPin('abcd'));

  [a, b, c2].forEach((x) => x.close());
  db.close();

  // ============ (a) history persists across a server restart ============
  await stopServer(srv);
  srv = startServer();
  await waitReady(srv);
  const a2 = await connect(TOKEN);
  const j2 = a2.next();
  a2.send({ type: 'join', roomCode: code, userId: 'uTestA2', name: 'Ali2', avatar: '😎' });
  const joined2 = await j2;
  const hist = joined2.history || [];
  const editedMsg = hist.find((x) => x.id === chat.id);
  const deletedMsg = hist.find((x) => x.id === replyId);
  check('restart: join works + history survived', joined2.type === 'joined' && hist.length >= 2);
  check('restart: edited message intact', !!editedMsg && editedMsg.payload === ctEdit && editedMsg.edited === true);
  check('restart: deleted marker intact', !!deletedMsg && deletedMsg.payload === 'deleted' && deletedMsg.deleted === true);
  const rxHist = (joined2.reactions || {})[chat.id] || [];
  check('restart: reactions restored', rxHist.some((r) => r.emoji === '❤️' && r.userId === 'uTestA'));
  check('restart: pin restored', !!joined2.roomState && joined2.roomState.pinnedId === chat.id);
  a2.close();
  await stopServer(srv);

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('TEST ERROR:', e); process.exit(1); });
