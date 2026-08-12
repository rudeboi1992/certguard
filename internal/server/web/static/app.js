// Login page. On first run (no users yet) this becomes a "create your admin
// account" screen; otherwise it's a normal sign-in. Same form, two modes.
const $ = (id) => document.getElementById(id);
let setupMode = false;

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

$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
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
      const wasPrompted = !$('codeField').hidden || !$('keyBtn').hidden;

      $('codeField').hidden = !wantsCode;
      $('loginBtn').hidden = !wantsCode;
      $('keyBtn').hidden = !wantsKey;
      if (wantsCode) {
        $('loginBtn').textContent = 'Verify';
        $('code').focus();
      }
      // With a key as the only factor there is nothing to type, so go straight
      // to the prompt instead of making the user press another button.
      if (wantsKey && !wantsCode && !wasPrompted) {
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

// Second step of signing in with a key: the password has already been accepted,
// so the server will issue a challenge for this account's registered keys.
async function signInWithKey() {
  const err = $('error');
  err.hidden = true;
  const btn = $('keyBtn');
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = 'Touch your key…';
  try {
    const begin = await fetch('/api/v1/auth/webauthn/begin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: $('email').value, password: $('password').value }),
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
    err.hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

$('keyBtn').addEventListener('click', signInWithKey);
