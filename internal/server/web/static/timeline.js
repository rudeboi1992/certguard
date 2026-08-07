// Timeline: twelve months at a time, every expiry plotted on the day it falls.
//
// The dashboard's calendar answers "what is expiring this month" inside a card.
// This answers the question a card cannot: what does the whole year look like —
// where the clusters are, which month is quiet, whether four things renew in
// the same week. That needs the width of a page.
//
// Shared helpers come from common.js; the vault UI from vault-ui.js.

let items = [];
let anchor = new Date(); // first month shown is this month
let selectedKey = null;  // "YYYY-MM-DD" of the open day, if any

const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December'];
const DOW = ['M', 'T', 'W', 'T', 'F', 'S', 'S'];

// Dates are compared as UTC calendar days throughout. Expiries are stored as
// RFC3339 UTC, and a local-time bucket would move an entry to the wrong day for
// anyone east or west of UTC — which is exactly the kind of off-by-one nobody
// notices until a renewal is missed.
function dayKey(d) {
  return d.getUTCFullYear() + '-' + String(d.getUTCMonth() + 1).padStart(2, '0')
    + '-' + String(d.getUTCDate()).padStart(2, '0');
}
const keyOf = (iso) => dayKey(new Date(iso));
function todayKey() { return dayKey(new Date()); }

// Monday-first weekday index; getUTCDay() is Sunday-first.
function mondayIndex(d) { return (d.getUTCDay() + 6) % 7; }

function bucket() {
  const by = new Map();
  for (const it of items) {
    const k = keyOf(it.cert.expires_at);
    if (!by.has(k)) by.set(k, []);
    by.get(k).push(it);
  }
  return by;
}

function monthCells(year, month, by) {
  const first = new Date(Date.UTC(year, month, 1));
  const days = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
  const lead = mondayIndex(first);
  const today = todayKey();
  let html = '';
  for (let i = 0; i < lead; i++) html += '<span class="tl-day empty" aria-hidden="true"></span>';
  for (let d = 1; d <= days; d++) {
    const key = `${year}-${String(month + 1).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    const on = by.get(key) || [];
    let cls = 'tl-day';
    if (key === today) cls += ' today';
    if (key === selectedKey) cls += ' selected';
    if (on.length) {
      // The worst entry on a day colours it — a day holding one expired and
      // one healthy certificate is an expired day.
      const worst = on.reduce((w, it) =>
        Math.min(w, it.days_remaining), Infinity);
      cls += ' has ' + expiryLevel(worst);
    }
    const label = on.length
      ? `${d} ${MONTHS[month]}: ${on.length} expiring — ${on.map((x) => x.cert.name).join(', ')}`
      : `${d} ${MONTHS[month]}`;
    html += `<button type="button" class="${cls}" data-day="${key}"${on.length ? '' : ' tabindex="-1"'}
      title="${escapeHtml(label)}" aria-label="${escapeHtml(label)}"><span class="tl-dnum">${d}</span>${
      on.length ? `<span class="tl-dots">${on.slice(0, 3).map((it) =>
        `<i style="background:${categoryColor(it.cert.category)}"></i>`).join('')}${
        on.length > 3 ? `<em>+${on.length - 3}</em>` : ''}</span>` : ''}</button>`;
  }
  return html;
}

function render() {
  const by = bucket();
  const grid = $('tlMonths');
  let html = '';
  for (let i = 0; i < 12; i++) {
    const d = new Date(Date.UTC(anchor.getUTCFullYear(), anchor.getUTCMonth() + i, 1));
    const y = d.getUTCFullYear(), m = d.getUTCMonth();
    // Count for the month, so a glance across the page shows where the work is.
    let n = 0;
    for (const [k, v] of by) {
      if (k.startsWith(`${y}-${String(m + 1).padStart(2, '0')}`)) n += v.length;
    }
    html += `<div class="tl-month">
      <div class="tl-mhead"><span class="tl-mname">${MONTHS[m]}<span class="muted"> ${y}</span></span>
        ${n ? `<span class="pill ${n ? 'cat' : ''}">${n}</span>` : '<span class="muted small">—</span>'}</div>
      <div class="tl-dow">${DOW.map((x) => `<span>${x}</span>`).join('')}</div>
      <div class="tl-grid">${monthCells(y, m, by)}</div>
    </div>`;
  }
  grid.innerHTML = html;
  grid.querySelectorAll('[data-day]').forEach((b) => {
    b.addEventListener('click', () => selectDay(b.dataset.day));
  });

  const from = new Date(Date.UTC(anchor.getUTCFullYear(), anchor.getUTCMonth(), 1));
  const to = new Date(Date.UTC(anchor.getUTCFullYear(), anchor.getUTCMonth() + 11, 1));
  $('tlLabel').textContent = `${MONTHS[from.getUTCMonth()]} ${from.getUTCFullYear()} — ${MONTHS[to.getUTCMonth()]} ${to.getUTCFullYear()}`;
  $('tlEmpty').hidden = items.length !== 0;
  renderDetail(by);
}

function selectDay(key) {
  selectedKey = selectedKey === key ? null : key;
  render();
  if (selectedKey) {
    const card = $('tlDetailCard');
    if (!card.hidden) card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

function renderDetail(by) {
  const card = $('tlDetailCard');
  if (!selectedKey) { card.hidden = true; return; }
  const on = (by.get(selectedKey) || []).slice().sort((a, b) => a.days_remaining - b.days_remaining);
  if (!on.length) { card.hidden = true; return; }
  card.hidden = false;
  $('tlDetailTitle').textContent = `${on.length} expiring on ${selectedKey}`;
  $('tlDetail').innerHTML = on.map((it) => {
    const c = it.cert;
    const col = categoryColor(c.category);
    return `<div class="tl-drow">
      <span class="tl-dname"><strong>${escapeHtml(c.name)}</strong>${
        c.host ? `<br><span class="muted small mono">${escapeHtml(c.host)}${c.port ? ':' + c.port : ''}</span>` : ''}</span>
      ${c.category ? `<span class="pill" style="background:${hexA(col, .15)};color:${col}">${escapeHtml(categoryLabel(c.category))}</span>` : '<span></span>'}
      <span class="pill ${expiryLevel(it.days_remaining)}">${fmtRemaining(it.days_remaining)}</span>
      <a class="btn ghost small" href="/inventory?q=${encodeURIComponent(c.name)}">Open</a>
    </div>`;
  }).join('');
}

function shiftMonths(n) {
  anchor = new Date(Date.UTC(anchor.getUTCFullYear(), anchor.getUTCMonth() + n, 1));
  render();
}

$('tlPrev').addEventListener('click', () => shiftMonths(-12));
$('tlNext').addEventListener('click', () => shiftMonths(12));
$('tlToday').addEventListener('click', () => { anchor = new Date(); selectedKey = null; render(); });

async function load() {
  const res = await api('GET', '/api/v1/certs');
  items = await res.json();
  $('tlLegend').innerHTML = CATEGORIES.map(([v, l, c]) =>
    `<span class="leg"><i style="background:${c}"></i>${escapeHtml(l)}</span>`).join('');
  const next = items.filter((it) => it.days_remaining >= 0)
    .sort((a, b) => a.days_remaining - b.days_remaining)[0];
  $('tlSub').textContent = items.length
    ? `${items.length} tracked` + (next ? ` · next is ${next.cert.name} in ${fmtRemaining(next.days_remaining)}` : '')
    : 'Nothing tracked yet.';
  render();
}

setVaultRefresh(() => load());

(async () => {
  await loadWhoami();
  syncVaultUi();
  await load();
})().catch((e) => toast(e.message || 'Failed to load the timeline', true));
