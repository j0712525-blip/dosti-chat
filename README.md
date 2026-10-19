# Dosti Chat 💬🔒

Apni private chat web app — text, photos, voice notes, 1:1 + group calls — sirf invite walon ke liye.
End-to-end encrypted (room key), App Lock (PIN), push notifications, PWA install.

## Chalane ka tareeqa

```bash
cd app
npm install
npm start
```

Phir browser mein kholo: `http://localhost:3000`

## Kaise use karein

1. Apna naam + avatar chuno → **Naya room banao** → 6-harf ka invite code milega.
2. **🔗 Invite** dabao aur link doston ko bhejo (email/WhatsApp/SMS — kahin se bhi). Link kholne par code khud lag jayega.
3. Chat karo 💬, 📷 photo ya 🎤 voice note bhejo, kisi message par ↩ reply / ✏️ edit / 🗑 delete karo.
4. Kisi dost ke naam ke saath **📹** (video) / **📞** (voice) dabao — ya **👥 Group call** se sab ko ek saath bulao.
5. **🔒 App Lock**: join screen par 4-digit PIN set karo — phir app kholte waqt PIN mangega. Room header mein 🔒 dabane se foran lock lag jata hai.

## Features (v1)

- **Rooms + invite codes/links** — code jiske paas, wohi join kar sakta hai
- **Text chat** — permanent history (SQLite), restart ke baad bhi rehti hai
- **🔒 E2E encryption** — har message AES-GCM-256 se lock hota hai; key room code se banti hai (PBKDF2, 100k rounds). Server par sirf ciphertext store hota hai
- **📷 Photos / 🎤 Voice notes** — file bytes bhi encrypt ho kar upload hote hain
- **✓✓ Read ticks**, **typing…** indicator, **online / last seen**
- **Reply / quote, edit, delete** (sirf apne messages)
- **Emoji avatars** + naam
- **1:1 voice/video calls** + **👥 group call (mesh)**
- **🔔 Push notifications** — web-push (VAPID), Firebase nahi. Message ya call aaye to phone par alert
- **🔒 App Lock** — 4-digit PIN, SHA-256 hash mein store (plaintext kabhi nahi), 3 ghalat tries → 30s cooldown
- **PWA** — "Add to Home Screen" se app jaisa install, offline cache

## Env vars

| Var | Kaam | Default |
|---|---|---|
| `PORT` | Server port | `3000` |
| `TURN_URLS` | TURN server URLs (comma-separated) | Google STUN only |
| `TURN_USER` / `TURN_PASS` | TURN credentials | — |
| `DATA_DIR` | SQLite DB folder | `./data` |
| `UPLOAD_DIR` | Encrypted uploads folder | `./uploads` |

VAPID keys pehli run par `.vapid.json` mein ban jati hain (kabhi log nahi hotin).

## Free TURN options (agar kuch networks par call na lage)

- **Metered** — free tier (thori limit ke saath): `turn:standard.relay.metered.ca:80`
- **Self-hosted coturn** — apne server par (sab se reliable)
- Bina TURN ke zyada tar ghar/mobile networks par STUN hi kaafi hai

## Honest limits

- **Group call 3–4 logon tak smooth** — mesh mein har banda har bande se judta hai, zyada logon par quality giregi
- **E2E room-key based hai** — jiske paas invite code hai woh parh sakta hai (code = chaabi). Code private rakho
- **Push ke liye HTTPS + notification permission** chahiye
- **Phone par mic/camera ke liye HTTPS** zaroori hai (ya localhost) — deploy ke waqt HTTPS host chahiye
- **Strict networks** (kuch hostel/office WiFi) mein calls ke liye TURN lagana parega
- **Sender naam / typing / ticks / online status** encrypted nahi hain (design se — sirf message content lock hota hai)

## Technical notes

- **Server:** Node.js + Express + `ws` WebSocket; history/users/push-subs SQLite (`node:sqlite`, built-in — koi native module nahi)
- **Calls:** WebRTC peer-to-peer, DTLS-SRTP encrypted media; signaling server ke through relay hoti hai
- **Uploads:** 15MB limit, file names 128-bit random (unguessable URLs), bytes encrypted
- **Tests:** `node test.js` — 45 checks (flows, ciphertext, restart persistence, mesh signaling, App Lock)
