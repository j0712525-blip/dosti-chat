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
