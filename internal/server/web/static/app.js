// Login page. On first run (no users yet) this becomes a "create your admin
// account" screen; otherwise it's a normal sign-in. Same form, several modes.
//
// Passkeys are offered WITHOUT the server being asked anything about the
// address being typed. Two mechanisms do that:
//
//   1. Conditional UI — the browser lists saved passkeys for this site in the
//      email field's own autofill dropdown. It knows what it has locally; the
//      server is never consulted, so nothing leaks about who is registered.
//   2. An explicit button that starts a usernameless ceremony. The challenge is
//      identical whatever accounts exist.
//
// Which layout is shown first is remembered per browser in localStorage. That
// is a local preference, not a fact about the account, so a returning user gets
// the passkey-first screen they expect while an instance exposed to the
// internet still answers every stranger identically.
const $ = (id) => document.getElementById(id);
const PREF_KEY = 'certguard-passkey-first';

let setupMode = false;
let mode = localStorage.getItem(PREF_KEY) === '1' ? 'passkey' : 'password';
let conditional = null; // AbortController for the in-flight autofill ceremony

async function initLogin() {
  try {
    const res = await fetch('/api/v1/setup/status');
    const data = await res.json();
    if (data.needs_setup) {
      setupMode = true;
      mode = 'password'; // nothing to sign in with yet
      $('loginSubtitle').textContent = 'Welcome — create your admin account';
      $('loginBtn').textContent = 'Create account';
      $('hint').textContent = 'First-time setup: the account you make here is the administrator.';
      $('hint').hidden = false;
    }
  } catch (_) { /* fall back to normal login */ }
  applyMode();
  if (!setupMode) startConditionalUI();
}

function applyMode() {
  const passkey = mode === 'passkey' && WebAuthnKit.supported() && !setupMode;
  if (!passkey) mode = mode === 'passkey' && !WebAuthnKit.supported() ? 'password' : mode;
  $('passwordField').hidden = passkey;
  $('password').required = !passkey;     // a hidden required field blocks submit
  $('loginBtn').hidden = passkey;
  $('keyBtn').hidden = !passkey;
  $('usePasswordLink').hidden = !passkey;
  // The way back is always available when keys are usable at all — offering it
  // depends on the browser, never on the account.
  $('useKeyLink').hidden = passkey || setupMode || !WebAuthnKit.supported();
  if (passkey) $('codeField').hidden = true;
}

function rememberPasskeyFirst() {
  try { localStorage.setItem(PREF_KEY, '1'); } catch (_) { /* private mode */ }
}

async function beginPasskey() {
  const res = await fetch('/api/v1/auth/passkey/begin', { method: 'POST' });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Could not start');
  return res.json();
}

async function finishPasskey(cred) {
  const res = await fetch('/api/v1/auth/passkey/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(WebAuthnKit.encodeAssertion(cred)),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Passkey rejected');
  rememberPasskeyFirst();
  window.location.href = '/';
}

// Offer saved passkeys in the email field's autofill. Silent by design: if the
// browser cannot do it, or the user ignores it and types a password, nothing
// should appear to have happened.
async function startConditionalUI() {
  try {
    if (!WebAuthnKit.supported()) return;
    if (!PublicKeyCredential.isConditionalMediationAvailable) return;
    if (!(await PublicKeyCredential.isConditionalMediationAvailable())) return;
    const opts = await beginPasskey();
    conditional = new AbortController();
    const cred = await navigator.credentials.get({
      publicKey: WebAuthnKit.decodeRequest(opts),
      mediation: 'conditional',
      signal: conditional.signal,
    });
    await finishPasskey(cred);
  } catch (_) {
    // Aborted because the user chose another path, or declined. Not an error.
  }
}

// Any deliberate action supersedes the autofill offer; leaving it running would
// hold a challenge the next ceremony is about to replace.
function cancelConditional() {
  if (conditional) { conditional.abort(); conditional = null; }
}

$('usePasswordLink').addEventListener('click', () => {
  cancelConditional();
  mode = 'password';
  try { localStorage.removeItem(PREF_KEY); } catch (_) { /* private mode */ }
  applyMode();
  $('password').focus();
  startConditionalUI(); // still offer autofill on the password screen
});

$('useKeyLink').addEventListener('click', () => {
  mode = 'passkey';
  applyMode();
});

$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (mode === 'passkey') { signInWithPasskey(); return; }
  cancelConditional();
  const err = $('error');
  err.hidden = true;
  const body = { email: $('email').value, password: $('password').value, code: $('code').value };
  const path = setupMode ? '/api/v1/setup' : '/api/v1/auth/login';
  try {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.ok) {
      window.location.href = '/';
      return;
    }
    const data = await res.json().catch(() => ({}));
    if (data.error === '2fa_required') {
      // The password was right. The server says which second factors this
      // account has — safe to reveal now, since the password already proved
      // who is asking.
      const methods = data.methods || ['totp'];
      const wantsCode = methods.includes('totp');
      const wantsKey = methods.includes('webauthn') && WebAuthnKit.supported();
      const wasPrompted = !$('codeField').hidden;

      $('codeField').hidden = !wantsCode;
      if (wantsCode) {
        $('loginBtn').textContent = 'Verify';
        $('code').focus();
      } else if (wantsKey) {
        // A key is the only second factor: prompt for it rather than leaving
        // the user on a form with nothing left to fill in.
        signInWithKeyAsSecondFactor();
        return;
      }
      err.textContent = wasPrompted && wantsCode ? 'Incorrect code — try again' : '';
      err.hidden = !err.textContent;
      return;
    }
    err.textContent = data.error || (setupMode ? 'Could not create account' : 'Sign in failed');
    err.hidden = false;
  } catch (_) {
    err.textContent = 'Network error';
    err.hidden = false;
  }
});

// Usernameless: no address is sent, and the authenticator says who it is.
async function signInWithPasskey() {
  cancelConditional();
  const err = $('error');
  err.hidden = true;
  const btn = $('keyBtn');
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Waiting for your passkey…';
  try {
    const opts = await beginPasskey();
    const cred = await navigator.credentials.get({ publicKey: WebAuthnKit.decodeRequest(opts) });
    await finishPasskey(cred);
  } catch (e) {
    err.textContent = WebAuthnKit.explain(e) + ' — you can use your password instead.';
    err.hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

// The other flow: password already accepted, key is the second factor. Here the
// address IS known, so the server can name the allowed credentials.
async function signInWithKeyAsSecondFactor() {
  const err = $('error');
  err.hidden = true;
  try {
    const begin = await fetch('/api/v1/auth/webauthn/begin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: $('email').value, password: $('password').value }),
    });
    if (!begin.ok) throw new Error((await begin.json().catch(() => ({}))).error || 'Could not start');
    const cred = await navigator.credentials.get({
      publicKey: WebAuthnKit.decodeRequest(await begin.json()),
    });
    const finish = await fetch('/api/v1/auth/webauthn/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(WebAuthnKit.encodeAssertion(cred)),
    });
    if (finish.ok) { window.location.href = '/'; return; }
    throw new Error((await finish.json().catch(() => ({}))).error || 'Security key rejected');
  } catch (e) {
    err.textContent = WebAuthnKit.explain(e);
    err.hidden = false;
  }
}

$('keyBtn').addEventListener('click', signInWithPasskey);

initLogin();
