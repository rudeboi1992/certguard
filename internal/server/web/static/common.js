// Shared helpers used by both the dashboard and the settings page: element
// lookup, API calls, toasts, HTML escaping, date formatting, the current user,
// the theme toggle, and sign-out.

const $ = (id) => document.getElementById(id);
let isAdmin = false;
let currentUserId = null;

function toast(msg, isError) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  t.style.background = isError ? 'var(--urgent)' : '';
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.hidden = true), 3200);
}

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 401) {
    window.location.href = '/login';
    throw new Error('unauthenticated');
  }
  return res;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toISOString().slice(0, 10);
}

// loadWhoami sets isAdmin/currentUserId and fills the header. Each page decides
// what to show based on isAdmin after this resolves.
async function loadWhoami() {
  const res = await api('GET', '/api/v1/auth/whoami');
  const data = await res.json();
  const u = data.user;
  isAdmin = u && u.role === 'admin';
  currentUserId = u && u.id;
  $('whoami').textContent = `${u.email} · ${u.role}`;
  return u;
}

// --- light / dark theme toggle (flat single-colour icons, no emoji) ---
const ICON_MOON = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z"/></svg>';
const ICON_SUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4.2"/><path d="M12 3v1.6M12 19.4V21M3 12h1.6M19.4 12H21M5.6 5.6l1.1 1.1M17.3 17.3l1.1 1.1M18.4 5.6l-1.1 1.1M6.7 17.3l-1.1 1.1"/></svg>';
function effectiveTheme() {
  const explicit = document.documentElement.getAttribute('data-theme');
  if (explicit) return explicit;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
function updateThemeIcon() {
  $('themeToggle').innerHTML = effectiveTheme() === 'dark' ? ICON_SUN : ICON_MOON;
}
$('themeToggle').addEventListener('click', () => {
  const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('certguard-theme', next); } catch (e) {}
  updateThemeIcon();
});
updateThemeIcon();

// --- sign out ---
$('logout').addEventListener('click', async () => {
  await api('POST', '/api/v1/auth/logout');
  window.location.href = '/login';
});
