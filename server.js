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
CREATE TABLE IF NOT EXISTS reactions(
  room TEXT NOT NULL,
  msgId INTEGER NOT NULL,
  userId TEXT NOT NULL,
  emoji TEXT NOT NULL,
  ts INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(room, msgId, userId, emoji)
);
CREATE TABLE IF NOT EXISTS room_settings(
  room TEXT PRIMARY KEY,
  disappearMs INTEGER NOT NULL DEFAULT 0,
  pinnedId INTEGER
);
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  passHash TEXT NOT NULL,
  salt TEXT NOT NULL,
  createdAt INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions(
  tokenHash TEXT PRIMARY KEY,
  accountId INTEGER NOT NULL,
  expiresAt INTEGER NOT NULL,
  createdAt INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS vaults(
  accountId INTEGER PRIMARY KEY,
  blob TEXT NOT NULL,
  updatedAt INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS contacts(
  owner_id INTEGER NOT NULL,
  contact_id INTEGER NOT NULL,
  dm_room_id TEXT NOT NULL,
  createdAt INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(owner_id, contact_id)
);
CREATE TABLE IF NOT EXISTS contact_requests(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_id INTEGER NOT NULL,
  to_id INTEGER NOT NULL,
  envelope TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  createdAt INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_creq_to ON contact_requests(to_id, status);
CREATE INDEX IF NOT EXISTS idx_creq_from ON contact_requests(from_id, status);
`);
// v3 account columns (phone / DM public key / profile photo / last seen).
for (const sql of [
  `ALTER TABLE accounts ADD COLUMN phone TEXT`,
  `ALTER TABLE accounts ADD COLUMN pubKey TEXT`,
  `ALTER TABLE accounts ADD COLUMN avatar BLOB`,
  `ALTER TABLE accounts ADD COLUMN avatarMime TEXT`,
  `ALTER TABLE accounts ADD COLUMN avatarVer INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE accounts ADD COLUMN lastSeen INTEGER NOT NULL DEFAULT 0`,
]) { try { db.exec(sql); } catch { /* column already there */ } }
// Migration for DBs created before disappearing messages existed.
try { db.exec(`ALTER TABLE messages ADD COLUMN expiresAt INTEGER`); } catch { /* column already there */ }

const qAddMsg   = db.prepare(`INSERT INTO messages(room,userId,name,kind,payload,replyTo,ts,expiresAt) VALUES(?,?,?,?,?,?,?,?)`);
const qTrim     = db.prepare(`DELETE FROM messages WHERE room=? AND id NOT IN (SELECT id FROM messages WHERE room=? ORDER BY id DESC LIMIT 500)`);
const qHistory  = db.prepare(`
  SELECT m.id, m.room, m.userId, m.name, COALESCE(u.avatar,'🙂') AS avatar,
         m.kind, m.payload, m.replyTo, m.ts, m.edited, m.deleted, m.expiresAt
  FROM messages m LEFT JOIN users u ON u.userId = m.userId
  WHERE m.room = ? AND (m.expiresAt IS NULL OR m.expiresAt > ?) ORDER BY m.id DESC LIMIT 100`);
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
// --- v2: reactions / room settings / expiry ---
const qGetReaction  = db.prepare(`SELECT 1 AS x FROM reactions WHERE room=? AND msgId=? AND userId=? AND emoji=?`);
const qAddReaction  = db.prepare(`INSERT OR REPLACE INTO reactions(room,msgId,userId,emoji,ts) VALUES(?,?,?,?,?)`);
const qDelReaction  = db.prepare(`DELETE FROM reactions WHERE room=? AND msgId=? AND userId=? AND emoji=?`);
const qDelReactionsFor = db.prepare(`DELETE FROM reactions WHERE msgId=?`);
const qReactionsRoom = db.prepare(`SELECT msgId, emoji, userId FROM reactions WHERE room=? ORDER BY ts`);
const qGetSettings  = db.prepare(`SELECT disappearMs, pinnedId FROM room_settings WHERE room=?`);
const qSetDisappear = db.prepare(`INSERT INTO room_settings(room,disappearMs) VALUES(?,?)
  ON CONFLICT(room) DO UPDATE SET disappearMs=excluded.disappearMs`);
const qSetPin       = db.prepare(`INSERT INTO room_settings(room,pinnedId) VALUES(?,?)
  ON CONFLICT(room) DO UPDATE SET pinnedId=excluded.pinnedId`);
const qMsgInRoom    = db.prepare(`SELECT id, deleted FROM messages WHERE id=? AND room=?`);
const qExpired      = db.prepare(`SELECT id, room FROM messages WHERE expiresAt IS NOT NULL AND expiresAt <= ?`);
const qHardDelete   = db.prepare(`DELETE FROM messages WHERE id=?`);
// --- v2: accounts / sessions / vault ---
const qAccountByEmail = db.prepare(`SELECT id, email, name, passHash, salt FROM accounts WHERE email=?`);
const qAddAccount     = db.prepare(`INSERT INTO accounts(email,name,passHash,salt,createdAt,phone) VALUES(?,?,?,?,?,?)`);
const qAddSession     = db.prepare(`INSERT INTO sessions(tokenHash,accountId,expiresAt,createdAt) VALUES(?,?,?,?)`);
const qGetSession     = db.prepare(`SELECT s.accountId, s.expiresAt, a.email, a.name, a.phone, a.avatarVer,
  (a.avatar IS NOT NULL) AS hasAvatar, (a.pubKey IS NOT NULL) AS hasPubKey
  FROM sessions s JOIN accounts a ON a.id = s.accountId WHERE s.tokenHash=?`);
const qDelSession     = db.prepare(`DELETE FROM sessions WHERE tokenHash=?`);
const qGetVault       = db.prepare(`SELECT blob FROM vaults WHERE accountId=?`);
const qPutVault       = db.prepare(`INSERT INTO vaults(accountId,blob,updatedAt) VALUES(?,?,?)
  ON CONFLICT(accountId) DO UPDATE SET blob=excluded.blob, updatedAt=excluded.updatedAt`);
// --- v3: contacts / requests / presence / profile ---
const qAccountById    = db.prepare(`SELECT id, email, name, phone, pubKey, avatarMime, avatarVer, lastSeen,
  (avatar IS NOT NULL) AS hasAvatar, (pubKey IS NOT NULL) AS hasPubKey FROM accounts WHERE id=?`);
const qSetPubKey      = db.prepare(`UPDATE accounts SET pubKey=? WHERE id=?`);
const qSetProfile     = db.prepare(`UPDATE accounts SET name=?, phone=? WHERE id=?`);
const qSetAvatar      = db.prepare(`UPDATE accounts SET avatar=?, avatarMime=?, avatarVer=avatarVer+1 WHERE id=?`);
const qGetAvatar      = db.prepare(`SELECT avatar, avatarMime FROM accounts WHERE id=?`);
const qTouchAccount   = db.prepare(`UPDATE accounts SET lastSeen=? WHERE id=?`);
const qSearchUsers    = db.prepare(`SELECT id, email, name, phone, pubKey, avatarVer,
  (avatar IS NOT NULL) AS hasAvatar FROM accounts
  WHERE id != ? AND (LOWER(name) LIKE ? OR LOWER(email) LIKE ?) ORDER BY name LIMIT 20`);
const qPhoneUsers     = db.prepare(`SELECT id, email, name, phone, pubKey, avatarVer,
  (avatar IS NOT NULL) AS hasAvatar FROM accounts WHERE id != ? AND phone IS NOT NULL ORDER BY name LIMIT 100`);
const qAddContact     = db.prepare(`INSERT OR IGNORE INTO contacts(owner_id, contact_id, dm_room_id, createdAt) VALUES(?,?,?,?)`);
const qMyContacts     = db.prepare(`SELECT c.contact_id AS contactId, c.dm_room_id AS dmRoomId,
  a.name, a.email, a.phone, a.avatarVer, a.lastSeen, (a.avatar IS NOT NULL) AS hasAvatar
  FROM contacts c JOIN accounts a ON a.id = c.contact_id WHERE c.owner_id=? ORDER BY a.name`);
const qIsContact      = db.prepare(`SELECT 1 AS x FROM contacts WHERE owner_id=? AND contact_id=?`);
const qContactOwners  = db.prepare(`SELECT owner_id FROM contacts WHERE contact_id=?`);
const qAddRequest     = db.prepare(`INSERT INTO contact_requests(from_id,to_id,envelope,status,createdAt) VALUES(?,?,?,'pending',?)`);
const qPendingBetween = db.prepare(`SELECT id FROM contact_requests WHERE status='pending'
  AND ((from_id=? AND to_id=?) OR (from_id=? AND to_id=?))`);
const qIncomingReqs   = db.prepare(`SELECT r.id, r.from_id AS fromId, r.envelope, r.createdAt,
  a.name AS fromName, a.email AS fromEmail, a.phone AS fromPhone, a.avatarVer AS fromAvatarVer,
  (a.avatar IS NOT NULL) AS fromHasAvatar
  FROM contact_requests r JOIN accounts a ON a.id = r.from_id
  WHERE r.to_id=? AND r.status='pending' ORDER BY r.createdAt`);
const qOutgoingReqs   = db.prepare(`SELECT r.id, r.to_id AS toId, r.createdAt, a.name AS toName
  FROM contact_requests r JOIN accounts a ON a.id = r.to_id
  WHERE r.from_id=? AND r.status='pending' ORDER BY r.createdAt`);
const qGetRequest     = db.prepare(`SELECT id, from_id, to_id, status FROM contact_requests WHERE id=?`);
const qSetReqStatus   = db.prepare(`UPDATE contact_requests SET status=? WHERE id=?`);
const qLastMsg        = db.prepare(`
  SELECT m.id, m.room, m.userId, m.name, COALESCE(u.avatar,'🙂') AS avatar,
         m.kind, m.payload, m.replyTo, m.ts, m.edited, m.deleted, m.expiresAt
  FROM messages m LEFT JOIN users u ON u.userId = m.userId
  WHERE m.room = ? AND (m.expiresAt IS NULL OR m.expiresAt > ?) ORDER BY m.id DESC LIMIT 1`);
const qCountAfter     = db.prepare(`SELECT COUNT(*) AS n FROM messages
  WHERE room=? AND ts > ? AND userId != ? AND (expiresAt IS NULL OR expiresAt > ?)`);

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

// ------------------------------------------------------------ auth -----
// Email + password accounts. Passwords hashed with scrypt (built-in) +
// per-user salt. Sessions: random 32-byte token; only its SHA-256 is stored.
const SESSION_MS = 30 * 24 * 3600 * 1000;   // 30 days
function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (e, dk) => (e ? reject(e) : resolve(dk)));
  });
}
async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const dk = await scryptAsync(password, salt);
  return { salt: salt.toString('hex'), hash: dk.toString('hex') };
}
async function verifyPassword(password, saltHex, hashHex) {
  const dk = await scryptAsync(password, Buffer.from(saltHex, 'hex'));
  const want = Buffer.from(hashHex, 'hex');
  return dk.length === want.length && crypto.timingSafeEqual(dk, want);
}
function tokenHash(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}
function makeSession(accountId) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  qAddSession.run(tokenHash(token), accountId, now + SESSION_MS, now);
  return token;
}
function accountForToken(token) {
  if (!token || typeof token !== 'string') return null;
  const s = qGetSession.get(tokenHash(token));
  if (!s) return null;
  if (s.expiresAt <= Date.now()) { qDelSession.run(tokenHash(token)); return null; }
  return {
    id: s.accountId, email: s.email, name: s.name, phone: s.phone || null,
    hasAvatar: !!s.hasAvatar, avatarVer: s.avatarVer || 0, hasPubKey: !!s.hasPubKey,
  };
}
// Anon (v4) accounts carry an internal placeholder email (…@local) that is
// never a credential and never shown to clients — name-only identities
// simply have no email.
function pubEmail(e) { return e && String(e).endsWith('@local') ? null : (e || null); }
// Public account shape for API responses (never hashes / private material).
function publicAccount(a) {
  if (!a) return null;
  return {
    id: a.id, email: pubEmail(a.email), name: a.name, phone: a.phone || null,
    hasAvatar: !!a.hasAvatar, avatarVer: a.avatarVer || 0, hasPubKey: !!a.hasPubKey,
  };
}
function bearer(req) {
  const h = String(req.headers.authorization || '');
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}
function requireAuth(req, res, next) {
  const acc = accountForToken(bearer(req));
  if (!acc) return res.status(401).json({ error: 'Pehle login karo' });
  req.account = acc;
  next();
}
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function cleanEmail(e) {
  const s = String(e || '').trim().toLowerCase().slice(0, 120);
  return EMAIL_RE.test(s) ? s : null;
}
// Phone is OPTIONAL account metadata (never a login credential).
// Returns: undefined = field not provided, null = clear it, false = invalid,
// otherwise the normalized number (spaces/dashes/parens stripped, leading + kept).
function cleanPhone(p) {
  if (p === undefined || p === null) return undefined;
  const s = String(p).trim();
  if (!s) return null;
  const norm = s.replace(/[\s\-()]/g, '');
  return /^\+?\d{7,15}$/.test(norm) ? norm : false;
}

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
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 } });

// --------------------------------------------------------------- app ---
const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', requireAuth, express.static(UPLOAD_DIR, { dotfiles: 'deny', index: false }));

app.get('/health', (_req, res) => res.json({ ok: true }));

// ------------------------------------------------------- auth routes ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const email = cleanEmail(req.body && req.body.email);
    const name = cleanName(req.body && req.body.name);
    const password = String((req.body && req.body.password) || '');
    const phone = cleanPhone(req.body && req.body.phone);
    if (!email) return res.status(400).json({ error: 'Email sahi likho' });
    if (!name || name === 'Guest') return res.status(400).json({ error: 'Apna naam likho' });
    if (password.length < 6) return res.status(400).json({ error: 'Password kam se kam 6 characters ka ho' });
    if (phone === false) return res.status(400).json({ error: 'Phone number sahi likho' });
    if (qAccountByEmail.get(email)) return res.status(409).json({ error: 'Is email se account pehle se hai — login karo' });
    const { salt, hash } = await hashPassword(password);
    const info = qAddAccount.run(email, name, hash, salt, Date.now(), phone || null);
    const account = publicAccount(qAccountById.get(Number(info.lastInsertRowid)));
    res.json({ ok: true, token: makeSession(account.id), account });
  } catch (e) { res.status(500).json({ error: 'Server masla: ' + e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = cleanEmail(req.body && req.body.email);
    const password = String((req.body && req.body.password) || '');
    const acc = email && qAccountByEmail.get(email);
    if (!acc || !(await verifyPassword(password, acc.salt, acc.passHash))) {
      return res.status(401).json({ error: 'Email ya password galat hai' });
    }
    const account = publicAccount(qAccountById.get(acc.id));
    res.json({ ok: true, token: makeSession(acc.id), account });
  } catch (e) { res.status(500).json({ error: 'Server masla: ' + e.message }); }
});

// v4: name-only entry. No email, no password — the client just sends a
// display name and gets a normal account + session token. The account's
// email is an internal placeholder (…@local) and its password hash is of
// a random throwaway secret, so the email login route can never sign in
// as an anon account. Identity therefore lives on the device (the token
// in localStorage); the token machinery still gates every endpoint/WS.
app.post('/api/auth/anon', async (req, res) => {
  try {
    const name = cleanName(req.body && req.body.name);
    if (!name || name === 'Guest') return res.status(400).json({ error: 'Apna naam likho' });
    const email = 'anon-' + crypto.randomBytes(10).toString('hex') + '@local';
    const { salt, hash } = await hashPassword(crypto.randomBytes(32).toString('hex'));
    const info = qAddAccount.run(email, name, hash, salt, Date.now(), null);
    const account = publicAccount(qAccountById.get(Number(info.lastInsertRowid)));
    res.json({ ok: true, token: makeSession(account.id), account });
  } catch (e) { res.status(500).json({ error: 'Server masla: ' + e.message }); }
});

app.post('/api/auth/logout', (req, res) => {
  const t = bearer(req);
  if (t) qDelSession.run(tokenHash(t));
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  const acc = accountForToken(bearer(req));
  if (!acc) return res.status(401).json({ error: 'Pehle login karo' });
  const row = qAccountById.get(acc.id);
  let pubKey = null;
  try { pubKey = row && row.pubKey ? JSON.parse(row.pubKey) : null; } catch { pubKey = null; }
  res.json({ ok: true, account: publicAccount(row), pubKey });
});

// Encrypted room vault — server stores ONLY opaque ciphertext.
app.get('/api/vault', requireAuth, (req, res) => {
  const v = qGetVault.get(req.account.id);
  res.json({ ok: true, blob: v ? v.blob : null });
});
app.put('/api/vault', requireAuth, (req, res) => {
  const blob = req.body && req.body.blob;
  if (typeof blob !== 'string' || blob.length > 200 * 1024) {
    return res.status(400).json({ error: 'Vault blob sahi nahi hai' });
  }
  qPutVault.run(req.account.id, blob, Date.now());
  res.json({ ok: true });
});

// ------------------------------------------------- v3: profile / keys --
app.put('/api/auth/profile', requireAuth, (req, res) => {
  const row = qAccountById.get(req.account.id);
  if (!row) return res.status(404).json({ error: 'Account nahi mila' });
  let name = row.name;
  if (req.body && 'name' in req.body) {
    name = cleanName(req.body.name);
    if (!name || name === 'Guest') return res.status(400).json({ error: 'Apna naam likho' });
  }
  let phone = row.phone || null;
  if (req.body && 'phone' in req.body) {
    const p = cleanPhone(req.body.phone);
    if (p === false) return res.status(400).json({ error: 'Phone number sahi likho' });
    phone = p || null;
  }
  qSetProfile.run(name, phone, req.account.id);
  res.json({ ok: true, account: publicAccount(qAccountById.get(req.account.id)) });
});

app.put('/api/auth/pubkey', requireAuth, (req, res) => {
  const pk = req.body && req.body.pubKey;
  const raw = typeof pk === 'string' ? pk : (pk ? JSON.stringify(pk) : '');
  let jwk = null;
  try { jwk = JSON.parse(raw); } catch { /* invalid */ }
  if (!jwk || jwk.kty !== 'RSA' || !jwk.n || !jwk.e || raw.length > 4000) {
    return res.status(400).json({ error: 'Public key sahi nahi hai' });
  }
  qSetPubKey.run(raw, req.account.id);
  res.json({ ok: true });
});

// Profile photo: small image stored against the account (metadata, never
// message content). Hard cap 300KB; type sniffed from magic bytes.
const AVATAR_MAX = 300 * 1024;
app.put('/api/auth/avatar', requireAuth, (req, res) => {
  let data = String((req.body && req.body.data) || '');
  const m = data.match(/^data:(image\/[a-z+]+);base64,([\s\S]*)$/);
  if (m) data = m[2];
  if (!data) return res.status(400).json({ error: 'Photo nahi mili' });
  let buf;
  try { buf = Buffer.from(data, 'base64'); } catch { return res.status(400).json({ error: 'Photo sahi nahi hai' }); }
  if (!buf.length) return res.status(400).json({ error: 'Photo sahi nahi hai' });
  if (buf.length > AVATAR_MAX) return res.status(400).json({ error: 'Photo 300KB se bari hai — choti photo chuno' });
  let mime = 'image/jpeg';
  if (buf[0] === 0x89 && buf[1] === 0x50) mime = 'image/png';
  else if (buf.length > 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') mime = 'image/webp';
  else if (!(buf[0] === 0xff && buf[1] === 0xd8)) return res.status(400).json({ error: 'Sirf JPEG / PNG / WebP photo chalegi' });
  qSetAvatar.run(buf, mime, req.account.id);
  const row = qAccountById.get(req.account.id);
  res.json({ ok: true, avatarVer: row.avatarVer, hasAvatar: true });
});

app.get('/api/users/:id/avatar', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'bad id' });
  const row = qGetAvatar.get(id);
  if (!row || !row.avatar) return res.status(404).json({ error: 'Photo nahi hai' });
  res.set('Content-Type', row.avatarMime || 'image/jpeg');
  res.set('Cache-Control', 'private, no-cache');
  res.send(Buffer.from(row.avatar));
});

app.get('/api/users/:id/pubkey', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'bad id' });
  const row = qAccountById.get(id);
  if (!row) return res.status(404).json({ error: 'User nahi mila' });
  let pubKey = null;
  try { pubKey = row.pubKey ? JSON.parse(row.pubKey) : null; } catch { pubKey = null; }
  res.json({ ok: true, pubKey });
});

// --------------------------------------------- v3: search / contacts ---
function userSearchShape(r, myId) {
  let pubKey = null;
  try { pubKey = r.pubKey ? JSON.parse(r.pubKey) : null; } catch { pubKey = null; }
  return {
    id: r.id, name: r.name, email: pubEmail(r.email), phone: r.phone || null,
    hasAvatar: !!r.hasAvatar, avatarVer: r.avatarVer || 0,
    hasPubKey: !!pubKey, pubKey,
    isContact: !!qIsContact.get(myId, r.id),
    requestPending: !!qPendingBetween.get(myId, r.id, r.id, myId),
  };
}
app.get('/api/users/search', requireAuth, (req, res) => {
  const q = String(req.query.q || '').trim();
  if (q.length < 2) return res.json({ ok: true, users: [] });
  const me = req.account.id;
  const like = '%' + q.toLowerCase().replace(/[%_]/g, '') + '%';
  const byId = new Map();
  for (const r of qSearchUsers.all(me, like, like)) byId.set(r.id, r);
  const digits = q.replace(/\D/g, '');
  if (digits.length >= 3) {
    for (const r of qPhoneUsers.all(me)) {
      const pd = String(r.phone || '').replace(/\D/g, '');
      if (pd && pd.includes(digits)) byId.set(r.id, r);
    }
  }
  res.json({ ok: true, users: [...byId.values()].slice(0, 20).map((r) => userSearchShape(r, me)) });
});

// Contact request: `envelope` is the DM room code encrypted with the
// recipient's RSA public key — the server only stores the ciphertext blob.
app.post('/api/contacts/request', requireAuth, (req, res) => {
  const me = req.account.id;
  const toId = Number(req.body && req.body.toId);
  const envelope = String((req.body && req.body.envelope) || '');
  if (!Number.isInteger(toId)) return res.status(400).json({ error: 'User sahi nahi hai' });
  if (toId === me) return res.status(400).json({ error: 'Khud ko add nahi kar sakte' });
  if (!qAccountById.get(toId)) return res.status(404).json({ error: 'User nahi mila' });
  if (!envelope || envelope.length < 10 || envelope.length > 4096) {
    return res.status(400).json({ error: 'Request data sahi nahi hai' });
  }
  if (qIsContact.get(me, toId)) return res.status(409).json({ error: 'Ye pehle se tumhara contact hai' });
  if (qPendingBetween.get(me, toId, toId, me)) {
    return res.status(409).json({ error: 'Request pehle se pending hai' });
  }
  const info = qAddRequest.run(me, toId, envelope, Date.now());
  sendToAccount(toId, { type: 'contact-request', fromId: me, fromName: req.account.name });
  res.json({ ok: true, requestId: Number(info.lastInsertRowid) });
});

app.get('/api/contacts/requests', requireAuth, (req, res) => {
  const me = req.account.id;
  const incoming = qIncomingReqs.all(me).map((r) => ({
    id: r.id, fromId: r.fromId, fromName: r.fromName, fromEmail: pubEmail(r.fromEmail),
    fromPhone: r.fromPhone || null, hasAvatar: !!r.fromHasAvatar,
    avatarVer: r.fromAvatarVer || 0, envelope: r.envelope, createdAt: r.createdAt,
  }));
  const outgoing = qOutgoingReqs.all(me).map((r) => ({
    id: r.id, toId: r.toId, toName: r.toName, createdAt: r.createdAt,
  }));
  res.json({ ok: true, incoming, outgoing });
});

app.post('/api/contacts/respond', requireAuth, (req, res) => {
  const me = req.account.id;
  const requestId = Number(req.body && req.body.requestId);
  const accept = !!(req.body && req.body.accept);
  const r = Number.isInteger(requestId) ? qGetRequest.get(requestId) : null;
  if (!r) return res.status(404).json({ error: 'Request nahi mili' });
  if (r.to_id !== me) return res.status(403).json({ error: 'Ye request tumhare liye nahi hai' });
  if (r.status !== 'pending') return res.status(400).json({ error: 'Request pehle hi handle ho chuki hai' });
  if (accept) {
    // dmRoomId is a SHA-256 hash of the DM code — NOT the code itself,
    // so the server never holds anything that can derive the E2E key.
    const dmRoomId = String((req.body && req.body.dmRoomId) || '');
    if (!/^[0-9a-f]{16,64}$/i.test(dmRoomId)) {
      return res.status(400).json({ error: 'DM room id sahi nahi hai' });
    }
    const now = Date.now();
    qAddContact.run(me, r.from_id, dmRoomId, now);
    qAddContact.run(r.from_id, me, dmRoomId, now);
    qSetReqStatus.run('accepted', r.id);
  } else {
    qSetReqStatus.run('declined', r.id);
  }
  sendToAccount(r.from_id, { type: 'contacts-changed' });
  res.json({ ok: true });
});

app.get('/api/contacts', requireAuth, (req, res) => {
  const me = req.account.id;
  const contacts = qMyContacts.all(me).map((r) => {
    const p = presenceOf(r.contactId);
    return {
      contactId: r.contactId, name: r.name, email: pubEmail(r.email), phone: r.phone || null,
      hasAvatar: !!r.hasAvatar, avatarVer: r.avatarVer || 0, dmRoomId: r.dmRoomId,
      online: p.online, lastSeen: p.lastSeen || r.lastSeen || 0,
    };
  });
  res.json({ ok: true, contacts });
});

// Dashboard helper: last message (ciphertext) + unread count for one room.
app.get('/api/rooms/:code/last', requireAuth, (req, res) => {
  const code = cleanCode(req.params.code);
  if (!code) return res.status(400).json({ error: 'Code sahi nahi hai' });
  const now = Date.now();
  const since = Number(req.query.since) || 0;
  const meUser = cleanUserId(req.query.me) || '';
  const row = qLastMsg.get(code, now);
  const cnt = qCountAfter.get(code, since, meUser, now);
  res.json({ ok: true, msg: row ? rowToMsg(row) : null, unread: cnt ? cnt.n : 0 });
});

// ICE config (STUN default, TURN via env) + VAPID public key for push subscribe.
app.get('/config', requireAuth, (_req, res) => {
  const iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];
  if (process.env.TURN_URLS) {
    const turn = { urls: process.env.TURN_URLS.split(',').map((s) => s.trim()).filter(Boolean) };
    if (process.env.TURN_USER) turn.username = process.env.TURN_USER;
    if (process.env.TURN_PASS) turn.credential = process.env.TURN_PASS;
    iceServers.push(turn);
  }
  res.json({ iceServers, vapidPublicKey: vapid.publicKey });
});

app.post('/upload', requireAuth, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: 'Upload fail ho gaya: ' + err.message });
    if (!req.file) return res.status(400).json({ error: 'Koi file nahi mili' });
    res.json({ file: req.file.filename });
  });
});

app.post('/push/subscribe', requireAuth, (req, res) => {
  const { userId, room, sub } = req.body || {};
  const code = cleanCode(room);
  if (!userId || !code || !sub || !sub.endpoint) return res.status(400).json({ error: 'bad request' });
  qAddSub.run(String(userId), code, JSON.stringify(sub));
  res.json({ ok: true });
});

app.post('/push/unsubscribe', requireAuth, (req, res) => {
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
    expiresAt: r.expiresAt || null,
  };
}

function roomState(code) {
  const s = qGetSettings.get(code);
  return { disappearMs: s ? s.disappearMs : 0, pinnedId: s ? s.pinnedId : null };
}

function roomReactions(code) {
  const out = {};
  for (const r of qReactionsRoom.all(code)) {
    (out[r.msgId] ||= []).push({ emoji: r.emoji, userId: r.userId });
  }
  return out;
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

// ------------------------------------------------- v3: presence ------
// Account-level presence: accountId -> live authed sockets. A contact is
// "online" while at least one of their sockets is connected; lastSeen is
// stamped (memory + DB) when the final socket goes away.
const accountSockets = new Map();   // accountId -> Set<ws>
const accountLastSeen = new Map();  // accountId -> ts
function presenceOf(accountId) {
  const set = accountSockets.get(accountId);
  let lastSeen = accountLastSeen.get(accountId) || 0;
  if (!lastSeen) {
    const row = qAccountById.get(accountId);
    lastSeen = row ? (row.lastSeen || 0) : 0;
    if (lastSeen) accountLastSeen.set(accountId, lastSeen);
  }
  return { online: !!(set && set.size), lastSeen };
}
function sendToAccount(accountId, obj) {
  const set = accountSockets.get(accountId);
  if (!set) return;
  const raw = JSON.stringify(obj);
  for (const s of set) {
    if (s.readyState === 1) { try { s.send(raw); } catch {} }
  }
}
function pushPresence(accountId) {
  const p = presenceOf(accountId);
  const evt = { type: 'presence', contactId: accountId, online: p.online, lastSeen: p.lastSeen };
  for (const r of qContactOwners.all(accountId)) sendToAccount(r.owner_id, evt);
}
function trackConnect(ws) {
  if (!ws.accountId) return;
  let set = accountSockets.get(ws.accountId);
  const wasOnline = !!(set && set.size);
  if (!set) { set = new Set(); accountSockets.set(ws.accountId, set); }
  set.add(ws);
  if (!wasOnline) pushPresence(ws.accountId);
}
function trackDisconnect(ws) {
  if (!ws.accountId) return;
  const set = accountSockets.get(ws.accountId);
  if (!set) return;
  set.delete(ws);
  if (!set.size) {
    accountSockets.delete(ws.accountId);
    const now = Date.now();
    accountLastSeen.set(ws.accountId, now);
    qTouchAccount.run(now, ws.accountId);
    pushPresence(ws.accountId);
  }
}

// Shared join flow. allowCreate (DMs) registers a fresh code on first use;
// plain joins keep the v1 rule — unknown codes are rejected.
function joinRoom(ws, m, allowCreate) {
  const userId = cleanUserId(m.userId);
  const code = cleanCode(m.roomCode);
  if (!userId) return ws.send(JSON.stringify({ type: 'error', message: 'Identity missing hai.' }));
  let room = code && getRoom(code);
  if (!room) {
    if (!allowCreate || !code) {
      ws.send(JSON.stringify({ type: 'error', message: 'Room code galat hai. Code dobara check karo.' }));
      return;
    }
    room = { peers: new Map() };
    rooms.set(code, room);
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
  const history = qHistory.all(code, now).reverse().map(rowToMsg);
  ws.send(JSON.stringify({
    type: 'joined', roomCode: code, peerId: userId, peers, members, history,
    reactions: roomReactions(code), roomState: roomState(code),
  }));
  broadcast(room, { type: 'peer-joined', id: userId, name, avatar }, userId);
}

wss.on('connection', (ws) => {
  ws.authed = false;
  ws.accountId = null;
  const authTimer = setTimeout(() => { try { ws.close(4001, 'auth required'); } catch {} }, 10000);

  ws.on('message', (raw) => {
    let m;
    try { m = JSON.parse(raw); } catch { return; }

    // --------------------------------------------------------- auth ---
    // First message MUST be {type:'auth', token}. Everything else is
    // rejected until a valid account session is presented.
    if (!ws.authed) {
      if (m.type === 'auth') {
        const acc = accountForToken(m.token);
        if (!acc) {
          ws.send(JSON.stringify({ type: 'auth-error', message: 'Login session khatam hai — dobara login karo.' }));
          clearTimeout(authTimer);
          try { ws.close(4001, 'bad token'); } catch {}
          return;
        }
        ws.authed = true;
        ws.accountId = acc.id;
        clearTimeout(authTimer);
        ws.send(JSON.stringify({ type: 'auth-ok', account: acc }));
        trackConnect(ws);
        return;
      }
      ws.send(JSON.stringify({ type: 'auth-error', message: 'Pehle login karo.' }));
      clearTimeout(authTimer);
      try { ws.close(4001, 'auth required'); } catch {}
      return;
    }

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
    if (m.type === 'join') { joinRoom(ws, m, false); return; }
    // DM rooms spring into existence under their agreed code (contact flow).
    if (m.type === 'create-room-with-code') { joinRoom(ws, m, true); return; }

    const room = rooms.get(ws.roomCode);
    const me = room && room.peers.get(ws.userId);
    if (!room || !me) return;

    // ---------------------------------------------------------- chat ---
    if (m.type === 'chat') {
      const kind = ['text', 'photo', 'audio', 'video', 'file', 'location'].includes(m.kind) ? m.kind : 'text';
      const payload = String(m.payload || '');
      if (!payload || payload.length > 30 * 1024 * 1024) return;   // ciphertext only, sane cap
      const replyTo = Number.isInteger(m.replyTo) ? m.replyTo : null;
      const ts = Date.now();
      const { disappearMs } = roomState(ws.roomCode);
      const expiresAt = disappearMs > 0 ? ts + disappearMs : null;
      const info = qAddMsg.run(ws.roomCode, ws.userId, me.name, kind, payload, replyTo, ts, expiresAt);
      qTrim.run(ws.roomCode, ws.roomCode);
      const out = {
        type: 'chat', id: Number(info.lastInsertRowid),
        from: ws.userId, name: me.name, avatar: me.avatar,
        kind, payload, replyTo, ts, edited: false, deleted: false,
        expiresAt,
        cid: m.cid || null,   // echo client's temp id so it can dedupe
      };
      broadcast(room, out);
      // push (server never sees plaintext — body is generic)
      const body = kind === 'photo' ? `${me.name} ne 📷 photo bheji`
        : kind === 'audio' ? `${me.name} ne 🎤 voice note bheja`
        : kind === 'video' ? `${me.name} ne 🎬 video note bheja`
        : kind === 'file' ? `${me.name} ne 📁 file bheji`
        : kind === 'location' ? `${me.name} ne 📍 location bheji`
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
      if (r.changes > 0) {
        broadcast(room, { type: 'delete', id: m.id });
        // a deleted pinned message unpins itself everywhere
        if (roomState(ws.roomCode).pinnedId === m.id) {
          qSetPin.run(ws.roomCode, null);
          broadcast(room, { type: 'pin', id: null });
        }
      }
      return;
    }

    // ----------------------------------------------------- reactions ---
    const REACTION_EMOJIS = ['❤️', '😂', '😮', '😢', '😡', '👍'];
    if (m.type === 'reaction') {
      if (!Number.isInteger(m.id) || !REACTION_EMOJIS.includes(m.emoji)) return;
      const msg = qMsgInRoom.get(m.id, ws.roomCode);
      if (!msg || msg.deleted) return;
      let on;
      if (qGetReaction.get(ws.roomCode, m.id, ws.userId, m.emoji)) {
        qDelReaction.run(ws.roomCode, m.id, ws.userId, m.emoji);
        on = false;
      } else {
        qAddReaction.run(ws.roomCode, m.id, ws.userId, m.emoji, Date.now());
        on = true;
      }
      // broadcast to ALL (incl. sender) so every client converges
      broadcast(room, { type: 'reaction', id: m.id, emoji: m.emoji, userId: ws.userId, name: me.name, on });
      return;
    }

    // ------------------------------------------------------------ pin ---
    if (m.type === 'pin') {
      if (m.id === null) {
        qSetPin.run(ws.roomCode, null);
        broadcast(room, { type: 'pin', id: null });
        return;
      }
      if (!Number.isInteger(m.id)) return;
      const msg = qMsgInRoom.get(m.id, ws.roomCode);
      if (!msg || msg.deleted) return;
      qSetPin.run(ws.roomCode, m.id);
      broadcast(room, { type: 'pin', id: m.id, by: me.name });
      return;
    }

    // ------------------------------------------------------ disappear ---
    if (m.type === 'disappear') {
      const ms = Number(m.ms);
      if (!Number.isInteger(ms) || ms < 0 || ms > 7 * 24 * 3600 * 1000) return;
      qSetDisappear.run(ws.roomCode, ms);
      broadcast(room, { type: 'disappear', ms, by: me.name });
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

  ws.on('close', () => { leaveRoom(ws); trackDisconnect(ws); });
  ws.on('error', () => {});
});

// ------------------------------------------------------ expiry sweep -
// Hard-delete expired (disappearing) messages, clean their reactions, and
// tell live clients to drop them. History queries also filter expired rows,
// so this is about storage + live updates, not correctness of history.
const SWEEP_MS = Number(process.env.SWEEP_MS) || 30000;
setInterval(() => {
  try {
    const expired = qExpired.all(Date.now());
    if (!expired.length) return;
    const byRoom = new Map();
    for (const r of expired) {
      qHardDelete.run(r.id);
      qDelReactionsFor.run(r.id);
      if (!byRoom.has(r.room)) byRoom.set(r.room, []);
      byRoom.get(r.room).push(r.id);
    }
    for (const [code, ids] of byRoom) {
      const room = rooms.get(code);
      const st = roomState(code);
      if (st.pinnedId && ids.includes(st.pinnedId)) {
        qSetPin.run(code, null);
        if (room) broadcast(room, { type: 'pin', id: null });
      }
      if (room) for (const id of ids) broadcast(room, { type: 'expire', id });
    }
  } catch (e) { console.warn('sweep fail', e); }
}, SWEEP_MS).unref();

server.listen(PORT, () => {
  console.log(`Dosti Chat chal raha hai: http://localhost:${PORT}`);
});
