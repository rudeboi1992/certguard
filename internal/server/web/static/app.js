// Login page: POST credentials to the JSON API, then redirect to the dashboard.
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = document.getElementById('error');
  err.hidden = true;
  const body = {
    email: document.getElementById('email').value,
    password: document.getElementById('password').value,
  };
  try {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.ok) {
      window.location.href = '/';
      return;
    }
    const data = await res.json().catch(() => ({}));
    err.textContent = data.error || 'Sign in failed';
    err.hidden = false;
  } catch (_) {
    err.textContent = 'Network error';
    err.hidden = false;
  }
});
