// Zero-knowledge vault crypto — runs entirely in the browser. The vault
// passphrase never leaves this page: it is stretched (PBKDF2) into a key that
// unwraps a random data key (DEK), which stays in memory for the session and
// encrypts/decrypts secret values locally. The server only ever sees ciphertext.
const ZK = (() => {
  let dek = null; // CryptoKey (AES-GCM), null when locked
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const ITERS = 310000; // PBKDF2 iterations (OWASP-ish)

  const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

  async function deriveKEK(passphrase, salt, iters) {
    const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: iters, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']);
  }

  async function wrap(kek) {
    const iv = rand(12);
    const wrapped = await crypto.subtle.wrapKey('raw', dek, kek, { name: 'AES-GCM', iv });
    const out = new Uint8Array(iv.length + wrapped.byteLength);
    out.set(iv); out.set(new Uint8Array(wrapped), iv.length);
    return toB64(out);
  }

  // Create a fresh keyring for a new passphrase; sets the DEK in memory.
  async function create(passphrase) {
    const salt = rand(16);
    const kek = await deriveKEK(passphrase, salt, ITERS);
    dek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    return { wrapped: await wrap(kek), salt: toB64(salt), iters: String(ITERS) };
  }

  // Unlock with a passphrase + server-stored keyring. Throws on wrong passphrase.
  async function unlock(passphrase, keyring) {
    const salt = fromB64(keyring.salt);
    const iters = parseInt(keyring.iters, 10) || ITERS;
    const kek = await deriveKEK(passphrase, salt, iters);
    const combined = fromB64(keyring.wrapped);
    dek = await crypto.subtle.unwrapKey('raw', combined.slice(12), kek,
      { name: 'AES-GCM', iv: combined.slice(0, 12) },
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  // Re-wrap the current DEK under a new passphrase (change passphrase).
  async function rewrap(passphrase) {
    if (!dek) throw new Error('vault is locked');
    const salt = rand(16);
    return { wrapped: await wrap(await deriveKEK(passphrase, salt, ITERS)), salt: toB64(salt), iters: String(ITERS) };
  }

  // --- security keys -------------------------------------------------------
  // A security key wraps the SAME data key the passphrase does, so it is a
  // second door rather than a different room. The WebAuthn prf extension gives
  // a stable 32-byte secret per (key, salt) pair; that is already uniformly
  // random, so it is stretched with HKDF for domain separation rather than
  // PBKDF2, which exists to make guessing expensive and has nothing to guess
  // here.
  async function kekFromPRF(prfBytes) {
    const base = await crypto.subtle.importKey('raw', prfBytes, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('certguard-vault-prf-v1') },
      base, { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']);
  }

  // Wrap the current DEK for a security key. Requires an unlocked vault: you
  // cannot hand a key something you do not currently hold.
  async function wrapForKey(prfBytes) {
    if (!dek) throw new Error('vault is locked');
    return wrap(await kekFromPRF(prfBytes));
  }

  async function unlockWithKey(prfBytes, wrapped) {
    const kek = await kekFromPRF(prfBytes);
    const combined = fromB64(wrapped);
    dek = await crypto.subtle.unwrapKey('raw', combined.slice(12), kek,
      { name: 'AES-GCM', iv: combined.slice(0, 12) },
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  async function encrypt(plaintext) {
    const iv = rand(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dek, enc.encode(plaintext));
    const out = new Uint8Array(iv.length + ct.byteLength);
    out.set(iv); out.set(new Uint8Array(ct), iv.length);
    return toB64(out);
  }

  async function decrypt(encoded) {
    const combined = fromB64(encoded);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: combined.slice(0, 12) }, dek, combined.slice(12));
    return dec.decode(pt);
  }

  // Masked last-4 hint, computed locally (low sensitivity).
  const hint = (s) => (s ? '••' + (s.length > 4 ? s.slice(-4) : s) : '');

  return {
    create, unlock, rewrap, encrypt, decrypt, hint,
    wrapForKey, unlockWithKey,
    isUnlocked: () => dek !== null,
    lock: () => { dek = null; },
  };
})();
