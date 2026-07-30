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
      const wasPrompted = !$('codeField').hidden;
      $('codeField').hidden = false;
      $('loginBtn').textContent = 'Verify';
      $('code').focus();
      err.textContent = wasPrompted ? 'Incorrect code — try again' : '';
      err.hidden = !wasPrompted;
      return;
    }
    err.textContent = data.error || (setupMode ? 'Could not create account' : 'Sign in failed');
    err.hidden = false;
  } catch (_) {
    err.textContent = 'Network error';
    err.hidden = false;
  }
});
