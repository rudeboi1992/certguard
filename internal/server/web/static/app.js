// Login page. On first run (no users yet) this becomes a "create your admin
// account" screen; otherwise it's a normal sign-in. Same form, several modes.
//
// The page is passkey-first: once an address is entered, it asks the server
// whether that account has a security key and, if so, hides the password box
// and offers the key instead. "Use password instead" goes back to the classic
// password (+ TOTP) path, and nothing here removes that option — a key can
// always be declined.
const $ = (id) => document.getElementById(id);
let setupMode = false;
let mode = 'password';     // 'password' | 'passkey'
let probedEmail = '';      // address the current passkey answer belongs to
let userChose = false;     // the user picked a mode; stop overriding it

async function initLogin() {
  try {
    const res = await fetch('/api/v1/setup/status');
    const data = await res.json();
    if (data.needs_setup) {
      setupMode = true;
      $('loginSubtitle').textContent = 'Welcome — create your admin account';
      $('loginBtn').textContent = 'Create account';
      $('hint').textContent = 'First-time setup: the account you make here is the administrator.';
      $('hint').hidden = false;
    }
  } catch (_) { /* fall back to normal login */ }
}
initLogin();

function applyMode() {
  const passkey = mode === 'passkey';
  $('passwordField').hidden = passkey;
  $('password').required = !passkey;      // else the hidden box blocks submit
  $('loginBtn').hidden = passkey;
  $('keyBtn').hidden = !passkey;
  $('usePasswordLink').hidden = !passkey;
  // Only offer the way back once we know this account actually has a key.
  $('useKeyLink').hidden = passkey || probedEmail !== $('email').value.trim().toLowerCase();
  if (passkey) $('codeField').hidden = true;
}

// Ask whether this address can use a key. Failures leave the page on the
// password path, which always works.
async function probeMethods() {
  if (setupMode || userChose) return;
  const email = $('email').value.trim().toLowerCase();
  if (!email || !email.includes('@') || email === probedEmail) return;
  try {
    const res = await fetch('/api/v1/auth/methods', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    if (!res.ok) return;
    const data = await res.json();
    probedEmail = email;
    if (data.passkey && WebAuthnKit.supported()) {
      mode = 'passkey';
      applyMode();
    }
  } catch (_) { /* stay on the password path */ }
}

$('email').addEventListener('blur', probeMethods);
// Enter in the address field should also switch, rather than submitting an
// empty password and getting an error.
$('email').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !setupMode) { e.preventDefault(); probeMethods(); }
});
// Typing a different address invalidates the previous answer.
$('email').addEventListener('input', () => {
  if ($('email').value.trim().toLowerCase() !== probedEmail && mode === 'passkey' && !userChose) {
    mode = 'password';
    applyMode();
  }
});

$('usePasswordLink').addEventListener('click', () => {
  userChose = true;
  mode = 'password';
  applyMode();
  $('password').focus();
});

$('useKeyLink').addEventListener('click', () => {
  userChose = true;
  mode = 'passkey';
  applyMode();
});

$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  // In passkey mode the primary button is the key, not a form submit.
  if (mode === 'passkey') { signInWithKey(); return; }
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
      // The server says which factors this account actually has, so the page
      // offers exactly those rather than showing a code box to someone who
      // only registered a security key.
      const methods = data.methods || ['totp'];
      const wantsCode = methods.includes('totp');
      const wantsKey = methods.includes('webauthn') && WebAuthnKit.supported();
      const wasPrompted = !$('codeField').hidden;

      $('codeField').hidden = !wantsCode;
      if (wantsCode) {
        $('loginBtn').textContent = 'Verify';
        $('code').focus();
      } else if (wantsKey) {
        // Password accepted but a key is the only second factor: go straight
        // to it rather than leaving the user on a form with nothing to fill in.
        mode = 'passkey';
        applyMode();
        signInWithKey();
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

// Sign in with a key. Sends the password when we have one (the key is then a
// second factor); sends none in passkey mode, where the server demands the
// authenticator verify the user instead.
async function signInWithKey() {
  const err = $('error');
  err.hidden = true;
  const btn = $('keyBtn');
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = 'Touch your key…';
  try {
    const body = { email: $('email').value };
    if (mode !== 'passkey') body.password = $('password').value;
    const begin = await fetch('/api/v1/auth/webauthn/begin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!begin.ok) {
      const d = await begin.json().catch(() => ({}));
      throw new Error(d.error || 'Could not start');
    }
    const opts = await begin.json();
    const cred = await navigator.credentials.get({ publicKey: WebAuthnKit.decodeRequest(opts) });
    const finish = await fetch('/api/v1/auth/webauthn/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(WebAuthnKit.encodeAssertion(cred)),
    });
    if (finish.ok) {
      window.location.href = '/';
      return;
    }
    const d = await finish.json().catch(() => ({}));
    throw new Error(d.error || 'Security key rejected');
  } catch (e) {
    err.textContent = WebAuthnKit.explain(e);
    // A key that cannot verify the user cannot carry a passwordless sign-in.
    // Say what to do about it rather than leaving a dead end.
    if (mode === 'passkey') {
      err.textContent += ' — you can use your password instead.';
    }
    err.hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

$('keyBtn').addEventListener('click', signInWithKey);
