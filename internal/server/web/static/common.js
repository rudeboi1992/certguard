// Shared helpers used by both the dashboard and the settings page: element
// lookup, API calls, toasts, HTML escaping, date formatting, the current user,
// the theme toggle, and sign-out.

const $ = (id) => document.getElementById(id);
let isAdmin = false;
let currentUserId = null;
let secretsEnabled = false;
let vaultLocked = false; // vault is passphrase-protected and currently locked
let vaultLockable = false; // a passphrase is set, so it can be locked on demand
let zkEnabled = false;   // zero-knowledge mode: all secret crypto is client-side
let caAvailable = false; // a CA cert is available for download
let caUrl = '/ca.crt';   // where the CA download button points

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

// Short form for narrow layouts: mm/dd/yy. UTC to match fmtDate, so a row can
// show either without the two disagreeing near midnight.
function fmtDateShort(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getUTCMonth() + 1)}/${p(d.getUTCDate())}/${p(d.getUTCFullYear() % 100)}`;
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

// --- shared inventory vocabulary ---
// These describe what a tracked entry *is* and how close it is to expiring, so
// every page that shows entries agrees. They started out in dashboard.js and
// moved here when the inventory page needed the same categories and the same
// urgency thresholds — two copies would have drifted, and a category that is
// amber on one page and grey on another is worse than no colour at all.

// [value, label, colour]. The colour keys the calendar legend and the type
// pills; "other" grey is also the fallback for an unlabeled entry.
const CATEGORIES = [
  ['certificate', 'Certificate', '#3b82f6'],
  ['api-key', 'API key', '#8b5cf6'],
  ['subscription', 'Subscription', '#14b8a6'],
  ['domain', 'Domain', '#f59e0b'],
  ['service', 'Service/Contract', '#ec4899'],
  ['other', 'Other', '#94a3b8'],
];
function categoryLabel(v) {
  const f = CATEGORIES.find((c) => c[0] === v);
  return f ? f[1] : (v || '');
}
function categoryColor(v) {
  const f = CATEGORIES.find((c) => c[0] === v);
  return f ? f[2] : '#94a3b8'; // unlabeled → "other" grey
}
// hex "#rrggbb" → "rgba(r,g,b,a)" for tinted backgrounds.
function hexA(hex, a) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
}

// expiryLevel classifies purely by days remaining (expired counts as urgent).
function expiryLevel(days) {
  if (days <= 3) return 'urgent'; // includes expired (days < 0)
  if (days <= 7) return 'warn';
  if (days <= 30) return 'notice';
  return 'ok';
}

function fmtRemaining(days) {
  if (days < 0) return `expired ${Math.abs(days)}d ago`;
  if (days === 0) return 'today';
  if (days === 1) return '1 day';
  return `${days} days`;
}

function daysUntil(iso) {
  return Math.round((new Date(iso) - new Date()) / 86400000);
}

// chainRisk mirrors model.ChainRisk in Go: the intermediate that expires
// soonest AND before the leaf, or null when nothing in the chain gives out
// first. A link outliving the certificate is deliberately not a risk —
// renewing on the usual schedule fetches a fresh chain anyway, so flagging it
// would put a warning on every endpoint whose CA rotates on a longer cycle.
function chainRisk(c) {
  const leaf = Date.parse(c.expires_at);
  let best = null;
  let bestAt = Infinity;
  for (const link of c.chain || []) {
    const at = Date.parse(link.not_after);
    if (Number.isNaN(at)) continue;              // never captured / zero date
    if (!Number.isNaN(leaf) && at >= leaf) continue;
    if (at < bestAt) { best = link; bestAt = at; }
  }
  return best;
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
  zkEnabled = !!data.zk_enabled;
  caAvailable = !!data.ca_available;
  if (data.ca_url) caUrl = data.ca_url;
  // The status page only exists when the operator enabled it, which nav.js
  // cannot know at render time — so it is added here instead.
  if (data.status_public && window.navAddItem) navAddItem('/status', 'Status', 'status');
  // In zero-knowledge mode the vault is "locked" until the browser unlocks it
  // with the passphrase this session; otherwise fall back to server-side state.
  vaultLocked = zkEnabled
    ? !ZK.isUnlocked()
    : (!!data.secrets_enabled && !!data.vault_passphrase && !data.vault_unlocked);
  // Auto mode (key file on disk) has nothing to lock — only a passphrase vault,
  // or zero-knowledge mode, can be closed again on demand.
  vaultLockable = zkEnabled || (!!data.secrets_enabled && !!data.vault_passphrase);
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
    // `hidden`/`style` matter as much as childList: switching a tab (e.g. the
    // Add-entry panes) only flips `hidden` on a pane, which changes the body's
    // scrollHeight without resizing the body itself — so neither childList nor
    // the ResizeObserver fires and the glow would stay stale. `class` is left
    // out on purpose: markScrolling() toggles it on these very elements.
    bodies.forEach((b) => {
      ro.observe(b);
      mo.observe(b, { childList: true, subtree: true, attributes: true, attributeFilter: ['hidden', 'style'] });
    });
    window.addEventListener('resize', updateAll);
    updateAll();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();
})();
