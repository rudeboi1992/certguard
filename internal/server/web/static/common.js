// Shared helpers used by both the dashboard and the settings page: element
// lookup, API calls, toasts, HTML escaping, date formatting, the current user,
// the theme toggle, and sign-out.

const $ = (id) => document.getElementById(id);
let isAdmin = false;
let currentUserId = null;
let secretsEnabled = false;

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

// relTime renders a compact "how long ago" label, e.g. "just now", "5m ago".
function relTime(iso) {
  if (!iso) return '';
  const then = new Date(iso).getTime();
  if (isNaN(then)) return '';
  const s = Math.max(0, (Date.now() - then) / 1000);
  if (s < 45) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm ago';
  const h = Math.floor(m / 60);
  if (h < 24) return h + 'h ago';
  const d = Math.floor(h / 24);
  if (d < 30) return d + 'd ago';
  const mo = Math.floor(d / 30);
  if (mo < 12) return mo + 'mo ago';
  return Math.floor(mo / 12) + 'y ago';
}

// loadWhoami sets isAdmin/currentUserId and fills the header. Each page decides
// what to show based on isAdmin after this resolves.
async function loadWhoami() {
  const res = await api('GET', '/api/v1/auth/whoami');
  const data = await res.json();
  const u = data.user;
  isAdmin = u && u.role === 'admin';
  currentUserId = u && u.id;
  secretsEnabled = !!data.secrets_enabled;
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

// --- custom auto-hiding scrollbars + "more content below" glow ---
// Scrollbars are transparent until the element is actively scrolled (a
// `.scrolling` class is added briefly), and any card whose body has more to
// scroll gets a slow amber breathing glow at its bottom edge.
(function scrollAffordance() {
  const timers = new WeakMap();
  function markScrolling(el) {
    if (!el || !el.classList) return;
    el.classList.add('scrolling');
    clearTimeout(timers.get(el));
    timers.set(el, setTimeout(() => el.classList.remove('scrolling'), 900));
  }
  function updateGlow(body) {
    const card = body.closest && body.closest('.widget');
    if (!card) return;
    const more = body.scrollHeight - body.scrollTop - body.clientHeight > 2;
    card.classList.toggle('can-scroll-down', more);
  }
  let raf = 0;
  function updateAll() {
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = 0;
      document.querySelectorAll('.widget-body').forEach(updateGlow);
    });
  }
  document.addEventListener('scroll', (e) => {
    const t = e.target === document ? document.documentElement : e.target;
    markScrolling(t);
    if (t && t.classList && t.classList.contains('widget-body')) updateGlow(t);
  }, true);
  function wire() {
    const bodies = [...document.querySelectorAll('.widget-body')];
    if (!bodies.length) return;
    const ro = new ResizeObserver(updateAll);
    const mo = new MutationObserver(updateAll);
    bodies.forEach((b) => { ro.observe(b); mo.observe(b, { childList: true, subtree: true }); });
    window.addEventListener('resize', updateAll);
    updateAll();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();
})();
