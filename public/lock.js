// Dosti Chat — App Lock logic (shared by browser + Node tests).
// PIN is NEVER stored as plaintext: only SHA-256(salt + '::' + pin) goes to localStorage.
// Uses WebCrypto (available in browsers and Node 24), so this file loads in both.
(function (root, factory) {
  const Lock = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = Lock;
  else root.DostiLock = Lock;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const SALT = 'dosti-lock-v1';       // fixed salt, same on every device
  const MAX_TRIES = 3;                // wrong tries before cooldown
  const COOLDOWN_MS = 30000;          // 30 second cooldown
  const PIN_LEN = 4;

  async function sha256hex(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  }

  // Hash a PIN for storage. Never store or log the raw PIN.
  async function hashPin(pin) {
    return sha256hex(SALT + '::' + String(pin));
  }

  // Constant-time-ish comparison of a PIN against a stored hash.
  async function verifyPin(pin, storedHash) {
    if (!storedHash || typeof storedHash !== 'string') return false;
    const h = await hashPin(pin);
    if (h.length !== storedHash.length) return false;
    let diff = 0;
    for (let i = 0; i < h.length; i++) diff |= h.charCodeAt(i) ^ storedHash.charCodeAt(i);
    return diff === 0;
  }

  function validPin(pin) {
    return typeof pin === 'string' && new RegExp('^[0-9]{' + PIN_LEN + '}$').test(pin);
  }

  // Pure cooldown logic (no DOM) — easy to unit test.
  // fails = number of consecutive wrong tries so far.
  function nextLockoutState(fails) {
    if (fails >= MAX_TRIES) return { lockedOut: true, cooldownMs: COOLDOWN_MS };
    return { lockedOut: false, cooldownMs: 0, triesLeft: MAX_TRIES - fails };
  }

  return { SALT, MAX_TRIES, COOLDOWN_MS, PIN_LEN, hashPin, verifyPin, validPin, nextLockoutState };
});
