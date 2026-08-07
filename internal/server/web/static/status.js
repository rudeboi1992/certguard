// Public status page. Deliberately standalone — no common.js, no nav, no
// vault — because it is served to unauthenticated callers and must not depend
// on anything that assumes a session. The endpoint behind it returns counts
// only; there is no name, host, issuer or date to render here even if the page
// wanted to show one.

const el = (id) => document.getElementById(id);

// The theme toggle is the one shared behaviour worth keeping, and it is three
// lines. Importing common.js for it would drag in loadWhoami and a redirect to
// /login on the 401 that follows.
const ICON_MOON = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z"/></svg>';
const ICON_SUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4.2"/><path d="M12 3v1.6M12 19.4V21M3 12h1.6M19.4 12H21M5.6 5.6l1.1 1.1M17.3 17.3l1.1 1.1M18.4 5.6l-1.1 1.1M6.7 17.3l-1.1 1.1"/></svg>';
function effectiveTheme() {
  const explicit = document.documentElement.getAttribute('data-theme');
  if (explicit) return explicit;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
function paintThemeIcon() {
  el('themeToggle').innerHTML = effectiveTheme() === 'dark' ? ICON_SUN : ICON_MOON;
}
el('themeToggle').addEventListener('click', () => {
  const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('certguard-theme', next); } catch (e) {}
  paintThemeIcon();
});
paintThemeIcon();

function fmtAgo(iso) {
  if (!iso) return 'never';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 90) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return m + ' minutes ago';
  const h = Math.floor(m / 60);
  if (h < 48) return h + ' hours ago';
  return Math.floor(h / 24) + ' days ago';
}

function render(d) {
  // Worst-first: one expired certificate is the headline however many healthy
  // ones sit beside it.
  let level = 'ok', headline = 'All certificates healthy';
  if (d.expired > 0) {
    level = 'urgent';
    headline = `${d.expired} expired`;
  } else if (d.problems > 0) {
    level = 'warn';
    headline = `${d.problems} not checking cleanly`;
  } else if (d.expiring > 0) {
    level = 'notice';
    headline = `${d.expiring} expiring within 30 days`;
  }
  el('stDot').className = 'st-dot ' + level;
  el('stHeadline').textContent = headline;
  el('stSub').textContent = d.tracked
    ? `${d.tracked} item${d.tracked === 1 ? '' : 's'} monitored · last checked ${fmtAgo(d.last_check)}`
    : 'Nothing is being monitored yet.';

  const tiles = [
    ['Healthy', d.healthy, 'ok'],
    ['Expiring', d.expiring, 'notice'],
    ['Expired', d.expired, 'urgent'],
    ['Problems', d.problems, 'untrusted'],
  ];
  el('stTiles').innerHTML = tiles.map(([label, n, cls]) =>
    `<div class="inv-tile st-tile"><span class="inv-tile-n ${n ? cls : ''}">${n}</span>
     <span class="inv-tile-l">${label}</span></div>`).join('');

  el('stFoot').textContent = 'This page reports counts only. Sign in to see what is tracked.';
}

async function load() {
  try {
    const res = await fetch('/api/v1/status/public', { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error('unavailable');
    render(await res.json());
  } catch (e) {
    el('stDot').className = 'st-dot urgent';
    el('stHeadline').textContent = 'Status unavailable';
    el('stSub').textContent = 'The status endpoint did not answer.';
    el('stFoot').textContent = '';
  }
}

load();
// Slow refresh: the underlying checks run every few hours, so anything faster
// would be polling for changes that cannot have happened.
setInterval(load, 60000);
