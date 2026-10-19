// Dosti Chat v1 — server
// Node + Express (static files) + ws (chat + WebRTC signaling).
// Permanent history in SQLite (node:sqlite — built-in, no native modules).
// E2E: the server only ever stores/relays CIPHERTEXT (AES-GCM, client-side, room-key).
//      Plaintext names / typing / ticks / presence stay plaintext (by design).
// Push: web-push (VAPID). No Firebase.

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const webpush = require('web-push');
const { WebSocketServer } = require('ws');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------------------------------------------------------------- DB ---
const db = new DatabaseSync(path.join(DATA_DIR, 'chat.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  room TEXT NOT NULL,
  userId TEXT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'text',      -- text | photo | audio ; payload is ALWAYS ciphertext
  payload TEXT NOT NULL,                  -- base64(iv + AES-GCM ciphertext), or 'deleted'
  replyTo INTEGER,
  ts INTEGER NOT NULL,
  edited INTEGER NOT NULL DEFAULT 0,
  deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room, id);
CREATE TABLE IF NOT EXISTS users(
  userId TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  avatar TEXT NOT NULL DEFAULT '🙂',
  lastSeen INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS room_members(
  room TEXT NOT NULL,
  userId TEXT NOT NULL,
  lastSeen INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(room, userId)
);
CREATE TABLE IF NOT EXISTS push_subs(
  userId TEXT NOT NULL,
  room TEXT NOT NULL,
  sub TEXT NOT NULL,
  PRIMARY KEY(userId, room)
);
`);

const qAddMsg   = db.prepare(`INSERT INTO messages(room,userId,name,kind,payload,replyTo,ts) VALUES(?,?,?,?,?,?,?)`);
const qTrim     = db.prepare(`DELETE FROM messages WHERE room=? AND id NOT IN (SELECT id FROM messages WHERE room=? ORDER BY id DESC LIMIT 500)`);
const qHistory  = db.prepare(`
  SELECT m.id, m.room, m.userId, m.name, COALESCE(u.avatar,'🙂') AS avatar,
         m.kind, m.payload, m.replyTo, m.ts, m.edited, m.deleted
  FROM messages m LEFT JOIN users u ON u.userId = m.userId
  WHERE m.room = ? ORDER BY m.id DESC LIMIT 100`);
const qUpsertUser = db.prepare(`INSERT INTO users(userId,name,avatar,lastSeen) VALUES(?,?,?,?)
  ON CONFLICT(userId) DO UPDATE SET name=excluded.name, avatar=excluded.avatar`);
const qTouchUser  = db.prepare(`UPDATE users SET lastSeen=? WHERE userId=?`);
const qMember     = db.prepare(`INSERT INTO room_members(room,userId,lastSeen) VALUES(?,?,?)
  ON CONFLICT(room,userId) DO UPDATE SET lastSeen=excluded.lastSeen`);
const qMembers    = db.prepare(`
  SELECT m.userId, COALESCE(u.name,'?') AS name, COALESCE(u.avatar,'🙂') AS avatar, m.lastSeen
  FROM room_members m LEFT JOIN users u ON u.userId = m.userId
  WHERE m.room = ? ORDER BY m.lastSeen DESC LIMIT 50`);
const qRoomExists = db.prepare(`SELECT 1 AS x FROM messages WHERE room=? UNION SELECT 1 FROM room_members WHERE room=? LIMIT 1`);
const qEdit       = db.prepare(`UPDATE messages SET payload=?, edited=1 WHERE id=? AND userId=? AND deleted=0`);
const qDelete     = db.prepare(`UPDATE messages SET payload='deleted', deleted=1 WHERE id=? AND userId=? AND deleted=0`);
const qAddSub     = db.prepare(`INSERT INTO push_subs(userId,room,sub) VALUES(?,?,?)
  ON CONFLICT(userId,room) DO UPDATE SET sub=excluded.sub`);
const qDelSub     = db.prepare(`DELETE FROM push_subs WHERE userId=? AND room=?`);
const qSubsRoom   = db.prepare(`SELECT userId, sub FROM push_subs WHERE room=? AND userId != ?`);
const qSubsUser   = db.prepare(`SELECT sub FROM push_subs WHERE userId=?`);

// ------------------------------------------------------------- VAPID ---
// Generated once into .vapid.json (mode 600). Keys are NEVER logged.
const vapidPath = path.join(__dirname, '.vapid.json');
let vapid;
if (fs.existsSync(vapidPath)) {
  vapid = JSON.parse(fs.readFileSync(vapidPath, 'utf8'));
} else {
  vapid = webpush.generateVAPIDKeys();
  fs.writeFileSync(vapidPath, JSON.stringify(vapid), { mode: 0o600 });
}
webpush.setVapidDetails('mailto:dosti-chat@localhost', vapid.publicKey, vapid.privateKey);

// ------------------------------------------------------------ uploads --
// Files are uploaded ENCRYPTED (client encrypts bytes with the room key first).
// Filenames are 128-bit random hex — unguessable URLs.
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const room = cleanCode(req.query.room);
    if (!room) return cb(new Error('bad room'));
    const dir = path.join(UPLOAD_DIR, room);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (_req, _file, cb) => cb(null, crypto.randomBytes(16).toString('hex')),
});
const upload = multer({ storage, limits: { fileSize: 15 * 1024 * 1024 } });

// --------------------------------------------------------------- app ---
const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR, { dotfiles: 'deny', index: false }));

app.get('/health', (_req, res) => res.json({ ok: true }));

// ICE config (STUN default, TURN via env) + VAPID public key for push subscribe.
app.get('/config', (_req, res) => {
  const iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
  if (process.env.TURN_URLS) {
    const turn = { urls: process.env.TURN_URLS.split(',').map((s) => s.trim()).filter(Boolean) };
    if (process.env.TURN_USER) turn.username = process.env.TURN_USER;
    if (process.env.TURN_PASS) turn.credential = process.env.TURN_PASS;
    iceServers.push(turn);
  }
  res.json({ iceServers, vapidPublicKey: vapid.publicKey });
});

app.post('/upload', (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: 'Upload fail ho gaya: ' + err.message });
    if (!req.file) return res.status(400).json({ error: 'Koi file nahi mili' });
    res.json({ file: req.file.filename });
  });
});

app.post('/push/subscribe', (req, res) => {
  const { userId, room, sub } = req.body || {};
  const code = cleanCode(room);
  if (!userId || !code || !sub || !sub.endpoint) return res.status(400).json({ error: 'bad request' });
  qAddSub.run(String(userId), code, JSON.stringify(sub));
  res.json({ ok: true });
});

app.post('/push/unsubscribe', (req, res) => {
  const { userId, room } = req.body || {};
  const code = cleanCode(room);
  if (userId && code) qDelSub.run(String(userId), code);
  res.json({ ok: true });
});

// ---------------------------------------------------------------- push -
function pushToRoom(room, exceptUserId, payload) {
  const data = JSON.stringify(payload);
  for (const s of qSubsRoom.all(room, exceptUserId)) {
    webpush.sendNotification(JSON.parse(s.sub), data).catch((e) => {
      // dead subscription → drop it
      if (e && (e.statusCode === 404 || e.statusCode === 410)) qDelSub.run(s.userId, room);
    });
  }
}
function pushToUser(userId, payload) {
  const data = JSON.stringify(payload);
  for (const s of qSubsUser.all(userId)) {
    webpush.sendNotification(JSON.parse(s.sub), data).catch(() => {});
  }
}

// ----------------------------------------------------------- websocket -
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

// code -> { peers: Map(userId -> {ws, name, avatar}) }
const rooms = new Map();

function makeCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}
function cleanCode(c) {
  const s = String(c || '').toUpperCase().trim();
  return /^[A-Z0-9]{6}$/.test(s) ? s : null;
}
function cleanName(n) {
  return String(n || 'Guest').trim().slice(0, 30) || 'Guest';
}
function cleanAvatar(a) {
  const s = String(a || '🙂').trim();
  return s ? [...s][0] : '🙂';
}
function cleanUserId(u) {
  const s = String(u || '').trim().slice(0, 64);
  return /^[A-Za-z0-9_-]{1,64}$/.test(s) ? s : null;
}

function getRoom(code) {
  let room = rooms.get(code);
  if (!room) {
    // Recreate from DB so invite links survive a server restart.
    if (!qRoomExists.get(code, code)) return null;
    room = { peers: new Map() };
    rooms.set(code, room);
  }
  return room;
}

function broadcast(room, msg, exceptUserId) {
  const raw = JSON.stringify(msg);
  for (const [uid, peer] of room.peers) {
    if (uid !== exceptUserId && peer.ws.readyState === 1) peer.ws.send(raw);
  }
}

function rowToMsg(r) {
  return {
    id: r.id, from: r.userId, name: r.name, avatar: r.avatar,
    kind: r.kind, payload: r.payload, replyTo: r.replyTo,
    ts: r.ts, edited: !!r.edited, deleted: !!r.deleted,
  };
}

function leaveRoom(ws) {
  const { roomCode, userId } = ws;
  if (!roomCode || !userId) return;
  const now = Date.now();
  qMember.run(roomCode, userId, now);       // remember last seen per room…
  qTouchUser.run(now, userId);              // …and globally
  const room = rooms.get(roomCode);
  if (room) {
    room.peers.delete(userId);
    broadcast(room, { type: 'peer-left', id: userId, lastSeen: now });
    if (room.peers.size === 0) rooms.delete(roomCode);
  }
  ws.roomCode = null;
  ws.userId = null;
}

// If the same userId connects twice (two tabs), the newest wins.
function kickDuplicate(room, userId) {
  const old = room.peers.get(userId);
  if (old && old.ws.readyState === 1) {
    try { old.ws.send(JSON.stringify({ type: 'kicked', message: 'Dusri tab/device se connect ho gaye ho.' })); } catch {}
    try { old.ws.close(); } catch {}
  }
}

wss.on('connection', (ws) => {
  ws.on('message', (raw) => {
    let m;
    try { m = JSON.parse(raw); } catch { return; }

    // ------------------------------------------------------- create ---
    if (m.type === 'create-room') {
      const userId = cleanUserId(m.userId);
      if (!userId) return ws.send(JSON.stringify({ type: 'error', message: 'Identity missing hai.' }));
      leaveRoom(ws);
      let code;
      do { code = makeCode(); } while (rooms.has(code) || qRoomExists.get(code, code));
      const name = cleanName(m.name), avatar = cleanAvatar(m.avatar);
      const room = { peers: new Map() };
      rooms.set(code, room);
      room.peers.set(userId, { ws, name, avatar });
      ws.roomCode = code; ws.userId = userId;
      const now = Date.now();
      qUpsertUser.run(userId, name, avatar, now);
      qMember.run(code, userId, now);
      ws.send(JSON.stringify({ type: 'room-created', roomCode: code, peerId: userId }));
      return;
    }

    // ---------------------------------------------------------- join ---
    if (m.type === 'join') {
      const userId = cleanUserId(m.userId);
      const code = cleanCode(m.roomCode);
      if (!userId) return ws.send(JSON.stringify({ type: 'error', message: 'Identity missing hai.' }));
      const room = code && getRoom(code);
      if (!room) {
        ws.send(JSON.stringify({ type: 'error', message: 'Room code galat hai. Code dobara check karo.' }));
        return;
      }
      leaveRoom(ws);
      kickDuplicate(room, userId);
      const name = cleanName(m.name), avatar = cleanAvatar(m.avatar);
      room.peers.set(userId, { ws, name, avatar });
      ws.roomCode = code; ws.userId = userId;
      const now = Date.now();
      qUpsertUser.run(userId, name, avatar, now);
      qMember.run(code, userId, now);

      const peers = [...room.peers.entries()]
        .filter(([uid]) => uid !== userId)
        .map(([uid, p]) => ({ id: uid, name: p.name, avatar: p.avatar, online: true }));
      const members = qMembers.all(code).map((r) => ({
        userId: r.userId, name: r.name, avatar: r.avatar,
        online: room.peers.has(r.userId),
        lastSeen: room.peers.has(r.userId) ? now : r.lastSeen,
      }));
      const history = qHistory.all(code).reverse().map(rowToMsg);
      ws.send(JSON.stringify({ type: 'joined', roomCode: code, peerId: userId, peers, members, history }));
      broadcast(room, { type: 'peer-joined', id: userId, name, avatar }, userId);
      return;
    }

    const room = rooms.get(ws.roomCode);
    const me = room && room.peers.get(ws.userId);
    if (!room || !me) return;

    // ---------------------------------------------------------- chat ---
    if (m.type === 'chat') {
      const kind = ['text', 'photo', 'audio'].includes(m.kind) ? m.kind : 'text';
      const payload = String(m.payload || '');
      if (!payload || payload.length > 30 * 1024 * 1024) return;   // ciphertext only, sane cap
      const replyTo = Number.isInteger(m.replyTo) ? m.replyTo : null;
      const ts = Date.now();
      const info = qAddMsg.run(ws.roomCode, ws.userId, me.name, kind, payload, replyTo, ts);
      qTrim.run(ws.roomCode, ws.roomCode);
      const out = {
        type: 'chat', id: Number(info.lastInsertRowid),
        from: ws.userId, name: me.name, avatar: me.avatar,
        kind, payload, replyTo, ts, edited: false, deleted: false,
        cid: m.cid || null,   // echo client's temp id so it can dedupe
      };
      broadcast(room, out);
      // push (server never sees plaintext — body is generic)
      const body = kind === 'photo' ? `${me.name} ne 📷 photo bheji`
        : kind === 'audio' ? `${me.name} ne 🎤 voice note bheja`
        : `${me.name}: naya message 💬`;
      pushToRoom(ws.roomCode, ws.userId, { title: 'Dosti Chat', body, url: '/?room=' + ws.roomCode });
      return;
    }

    // ---------------------------------------------------------- edit ---
    if (m.type === 'edit') {
      const payload = String(m.payload || '');
      if (!payload || !Number.isInteger(m.id)) return;
      const r = qEdit.run(payload, m.id, ws.userId);
      if (r.changes > 0) broadcast(room, { type: 'edit', id: m.id, payload, edited: true });
      return;
    }

    // -------------------------------------------------------- delete ---
    if (m.type === 'delete') {
      if (!Number.isInteger(m.id)) return;
      const r = qDelete.run(m.id, ws.userId);
      if (r.changes > 0) broadcast(room, { type: 'delete', id: m.id });
      return;
    }

    // --------------------------------------------------------- typing ---
    if (m.type === 'typing') {
      broadcast(room, { type: 'typing', from: ws.userId, name: me.name, typing: !!m.typing }, ws.userId);
      return;
    }

    // ----------------------------------------------------------- read ---
    if (m.type === 'read') {
      const upToTs = Number(m.upToTs) || Date.now();
      broadcast(room, { type: 'ticks', userId: ws.userId, upToTs }, ws.userId);
      return;
    }

    // --------------------------------------------------------- signal ---
    // Generic WebRTC relay (1:1 offers/answers/ICE + group-call mesh).
    if (m.type === 'signal') {
      const target = room.peers.get(m.to);
      if (!target || target.ws.readyState !== 1) return;
      target.ws.send(JSON.stringify({ type: 'signal', from: ws.userId, name: me.name, data: m.data }));
      // Incoming call → wake the callee with a push (even if app is in background).
      if (m.data && m.data.kind === 'offer') {
        pushToUser(m.to, {
          title: 'Dosti Chat 📞',
          body: `${me.name} ${m.data.video ? 'video' : 'voice'} call kar raha hai…`,
          url: '/?room=' + ws.roomCode,
          tag: 'call-' + ws.roomCode,
        });
      }
      return;
    }

    // ---------------------------------------------------------- leave ---
    if (m.type === 'leave') {
      leaveRoom(ws);
      ws.send(JSON.stringify({ type: 'left' }));
    }
  });

  ws.on('close', () => leaveRoom(ws));
  ws.on('error', () => {});
});

server.listen(PORT, () => {
  console.log(`Dosti Chat chal raha hai: http://localhost:${PORT}`);
});
