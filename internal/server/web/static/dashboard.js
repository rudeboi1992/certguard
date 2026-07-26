// Dashboard: scan endpoints, add/track expirations, and the calendar. Shared
// helpers ($, api, toast, escapeHtml, fmtDate, isAdmin, loadWhoami, theme,
// sign-out) live in common.js, loaded first.

let currentItems = [];

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
  return `${days} days`;
}

function daysUntil(iso) {
  return Math.round((new Date(iso) - new Date()) / 86400000);
}

// Pull one RDN value (e.g. "CN") out of a DN string like "CN=foo,O=bar,C=US".
function dnField(dn, key) {
  for (const part of (dn || '').split(',')) {
    const [k, ...rest] = part.split('=');
    if (k.trim() === key) return rest.join('=').trim();
  }
  return '';
}

// Render the full certificate readout under the scan form.
function renderScanDetail(s) {
  const el = $('scanDetail');
  const rows = [];
  const add = (k, v) => { if (v) rows.push(`<div class="sd-row"><span class="sd-k">${k}</span><span class="sd-v">${v}</span></div>`); };

  add('Subject', escapeHtml(dnField(s.subject, 'CN') || s.subject || ''));
  add('Issuer', escapeHtml(dnField(s.issuer, 'O') || dnField(s.issuer, 'CN') || s.issuer || ''));
  add('Valid from', fmtDate(s.not_before));
  add('Expires', `${fmtDate(s.not_after)} <span class="muted">(${fmtRemaining(daysUntil(s.not_after))})</span>`);
  if (s.dns_names && s.dns_names.length) add('Covers', s.dns_names.map(escapeHtml).join(', '));
  add('Key', escapeHtml([s.key_type, s.signature_algorithm].filter(Boolean).join(' · ')));
  add('Chain', `${s.chain_length} certificate${s.chain_length === 1 ? '' : 's'}`);
  add('SHA-256', `<span class="mono sd-fp">${escapeHtml(s.sha256)}</span>`);
  const trust = s.trust_error
    ? `<span class="pill untrusted" title="${escapeHtml(s.trust_error)}">untrusted</span> <span class="muted small">${escapeHtml(s.trust_error)}</span>`
    : '<span class="pill ok">ok</span>';
  rows.push(`<div class="sd-row"><span class="sd-k">Trust</span><span class="sd-v">${trust}</span></div>`);

  el.innerHTML = `<div class="sd-title">${escapeHtml(s.host)}:${s.port}</div>` + rows.join('');
  el.hidden = false;
}

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
function categoryOptions(selected) {
  return CATEGORIES.map(([v, l]) =>
    `<option value="${v}"${v === selected ? ' selected' : ''}>${l}</option>`).join('');
}
// hex "#rrggbb" → "rgba(r,g,b,a)" for tinted backgrounds.
function hexA(hex, a) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
}
function renderLegend() {
  const el = $('calLegend');
  if (!el) return;
  el.innerHTML = CATEGORIES.map(([v, l, c]) =>
    `<span class="leg"><i style="background:${c}"></i>${escapeHtml(l)}</span>`).join('');
}

async function loadCerts() {
  const res = await api('GET', '/api/v1/certs');
  currentItems = await res.json();
  // Summary + calendar reflect the full set; compute once per fetch.
  let urgent = 0, soon = 0;
  for (const it of currentItems) {
    const level = expiryLevel(it.days_remaining);
    if (level === 'urgent') urgent++;
    else if (level === 'warn' || level === 'notice') soon++;
  }
  renderSummary(currentItems.length, soon, urgent);
  renderCalendar();
  renderCerts();
}

// Re-render the list (rows only) when the search text or sort order changes.
['trackedSearch', 'trackedSort'].forEach((id) => {
  const el = $(id);
  if (el) el.addEventListener('input', renderCerts);
});

// Apply the current search text + sort order to a copy of currentItems.
function filterSortItems() {
  const q = (($('trackedSearch') || {}).value || '').trim().toLowerCase();
  let items = currentItems.slice();
  if (q) {
    items = items.filter((it) => {
      const c = it.cert;
      return (c.name || '').toLowerCase().includes(q)
        || (c.host || '').toLowerCase().includes(q)
        || (c.category || '').toLowerCase().includes(q)
        || categoryLabel(c.category).toLowerCase().includes(q);
    });
  }
  const sort = (($('trackedSort') || {}).value) || 'expiry-asc';
  items.sort((a, b) => {
    if (sort === 'name') return (a.cert.name || '').localeCompare(b.cert.name || '');
    if (sort === 'added') return (b.cert.id || 0) - (a.cert.id || 0);
    if (sort === 'expiry-desc') return b.days_remaining - a.days_remaining;
    return a.days_remaining - b.days_remaining; // soonest first (default)
  });
  return items;
}

// renderCerts (re)draws the list from currentItems. Summary/calendar/fingerprint
// stats always reflect the FULL set; only the visible rows are filtered/sorted.
function renderCerts() {
  const rows = $('certRows');
  rows.innerHTML = '';

  // Group entries by fingerprint so we can flag ones that are the same cert.
  const fpGroups = {};
  for (const it of currentItems) {
    const fp = it.cert.sha256;
    if (fp) (fpGroups[fp] ||= []).push({ id: it.cert.id, name: it.cert.name });
  }

  const items = filterSortItems();
  for (const it of items) {
    const c = it.cert;
    const days = it.days_remaining;
    const trusted = !c.last_error;
    const level = expiryLevel(days);

    const catCol = categoryColor(c.category);
    const typeCell = c.category
      ? `<span class="pill" style="background:${hexA(catCol, 0.15)};color:${catCol}">${escapeHtml(categoryLabel(c.category))}</span>`
      : `<span class="muted small">${c.kind}</span>`;
    const sans = c.dns_names || [];
    const coverToggle = sans.length > 1
      ? `<br><button class="cover-toggle" data-cover="${c.id}" aria-expanded="false">▸ covers ${sans.length} domains</button>`
      : '';
    let fpLine = '';
    if (c.sha256) {
      const others = (fpGroups[c.sha256] || []).filter((g) => g.id !== c.id).map((g) => g.name);
      const dup = others.length
        ? ` <span class="pill dup" title="Same certificate as: ${escapeHtml(others.join(', '))}">duplicate</span>`
        : '';
      fpLine = `<br><span class="mono muted small" title="SHA-256: ${escapeHtml(c.sha256)}">${c.sha256.slice(0, 12)}…</span>${dup}`;
    }
    // Endpoints show when they were last checked, plus a rescan-now button.
    let checkLine = '';
    const isEndpoint = c.kind === 'endpoint' || !!c.host;
    if (isEndpoint) {
      const checked = c.last_scanned_at ? `checked ${escapeHtml(relTime(c.last_scanned_at))}` : 'never checked';
      const rescan = isAdmin ? `<button class="rescan-btn" data-rescan="${c.id}" title="Rescan this endpoint now">↻ rescan</button> · ` : '';
      checkLine = `<br><span class="checkline muted small">${rescan}${checked}</span>`;
    }
    const inlineActions = [
      isAdmin ? `<button class="btn ghost small" data-edit="${c.id}">Edit</button>` : '',
      isAdmin ? `<button class="btn link" data-del="${c.id}">Delete</button>` : '',
    ].join(' ');
    const swipeActions = isAdmin
      ? `<button class="swipe-act edit" data-edit="${c.id}">Edit</button>` +
        `<button class="swipe-act del" data-del="${c.id}">Delete</button>`
      : '';
    const trustCell = trusted
      ? '<span class="pill ok">ok</span>'
      : `<span class="pill untrusted" title="${escapeHtml(c.last_error)}">untrusted</span>`;

    const row = document.createElement('div');
    row.className = 'trow';
    row.dataset.row = c.id;
    row.innerHTML = `
      <div class="trow-actions" aria-hidden="true">${swipeActions}</div>
      <div class="trow-surface">
        <div class="tcol tc-name"><strong>${escapeHtml(c.name)}</strong>${c.host ? `<br><span class="muted small">${escapeHtml(c.host)}:${c.port}</span>` : ''}${fpLine}${checkLine}${coverToggle}</div>
        <div class="tcol tc-meta">
          <span class="tc-type">${typeCell}</span>
          <span class="tc-exp">${fmtDate(c.expires_at)}</span>
          <span class="tc-trust">${trustCell}</span>
        </div>
        <div class="tcol tc-rem"><span class="pill ${level}">${fmtRemaining(days)}</span></div>
        <div class="tcol tc-actions">${inlineActions}</div>
      </div>`;
    rows.appendChild(row);
  }
  $('empty').hidden = currentItems.length !== 0;
  if ($('trackedToolbar')) $('trackedToolbar').hidden = currentItems.length === 0;
  if ($('noMatch')) $('noMatch').hidden = !(currentItems.length !== 0 && items.length === 0);
  const hint = $('empty').closest('.widget-body').querySelector('.swipe-hint');
  if (hint) hint.hidden = items.length === 0 || !isAdmin;

  openRow = null;
  rows.querySelectorAll('[data-del]').forEach((b) =>
    b.addEventListener('click', () => deleteCert(b.dataset.del)));
  rows.querySelectorAll('[data-edit]').forEach((b) =>
    b.addEventListener('click', () => startEdit(b.dataset.edit)));
  rows.querySelectorAll('[data-cover]').forEach((b) =>
    b.addEventListener('click', () => toggleCover(b)));
  rows.querySelectorAll('[data-rescan]').forEach((b) =>
    b.addEventListener('click', () => rescanCert(b.dataset.rescan, b)));
  rows.querySelectorAll('.trow').forEach(attachSwipe);
}

// Rescan a single endpoint on demand, then refresh the list.
async function rescanCert(id, btn) {
  if (btn) { btn.disabled = true; btn.textContent = '↻ scanning…'; }
  const res = await api('POST', `/api/v1/certs/${id}/rescan`);
  const d = await res.json().catch(() => ({}));
  if (res.ok) toast('Rescanned ✓');
  else toast(d.error || 'Rescan failed', true);
  loadCerts();
}

// --- swipe-to-reveal Edit/Delete on entry rows (mobile card layout) ---
let openRow = null;
function swipeReveal(row) {
  const a = row.querySelector('.trow-actions');
  return (a && a.offsetWidth) || 0;
}
function closeSwipe(row) {
  if (!row) return;
  row.classList.remove('open', 'dragging');
  const s = row.querySelector('.trow-surface');
  if (s) s.style.setProperty('--sx', '0px');
  if (openRow === row) openRow = null;
}
function openSwipe(row) {
  const s = row.querySelector('.trow-surface');
  const reveal = swipeReveal(row);
  if (!s || !reveal) return;
  if (openRow && openRow !== row) closeSwipe(openRow);
  row.classList.add('open');
  s.style.setProperty('--sx', `-${reveal}px`);
  openRow = row;
}
function attachSwipe(row) {
  const surface = row.querySelector('.trow-surface');
  const actions = row.querySelector('.trow-actions');
  if (!surface || !actions) return;
  let x0 = 0, y0 = 0, base = 0, active = false, decided = false, horiz = false, pid = null;
  // Swipe only applies in the mobile card layout (actions hidden on desktop grid).
  const enabled = () => getComputedStyle(actions).display !== 'none' && actions.children.length > 0;
  surface.addEventListener('pointerdown', (e) => {
    if (!enabled()) return;
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    x0 = e.clientX; y0 = e.clientY; pid = e.pointerId;
    base = row.classList.contains('open') ? -swipeReveal(row) : 0;
    active = true; decided = false; horiz = false;
  });
  surface.addEventListener('pointermove', (e) => {
    if (!active) return;
    const dx = e.clientX - x0, dy = e.clientY - y0;
    if (!decided) {
      if (Math.abs(dx) < 8 && Math.abs(dy) < 8) return;
      decided = true; horiz = Math.abs(dx) > Math.abs(dy);
      if (horiz) { row.classList.add('dragging'); try { surface.setPointerCapture(pid); } catch (_) {} }
    }
    if (!horiz) return;
    e.preventDefault();
    const t = Math.max(-swipeReveal(row), Math.min(0, base + dx));
    surface.style.setProperty('--sx', t + 'px');
  });
  const finish = (e) => {
    if (!active) return;
    active = false;
    row.classList.remove('dragging');
    if (!horiz) return;
    const t = base + (e.clientX - x0);
    if (t < -swipeReveal(row) / 2) openSwipe(row);
    else closeSwipe(row);
  };
  surface.addEventListener('pointerup', finish);
  surface.addEventListener('pointercancel', finish);
}
// Tapping anywhere outside the open row closes it.
document.addEventListener('pointerdown', (e) => {
  if (openRow && !openRow.contains(e.target)) closeSwipe(openRow);
}, true);

// Expand/collapse the full list of domains (SANs) a cert covers.
function toggleCover(btn) {
  const id = btn.dataset.cover;
  const it = currentItems.find((x) => String(x.cert.id) === String(id));
  const sans = (it && it.cert.dns_names) || [];
  const row = document.querySelector(`.trow[data-row="${id}"]`);
  const next = row && row.nextElementSibling;
  if (next && next.classList.contains('cover-row')) {
    next.remove();
    btn.setAttribute('aria-expanded', 'false');
    btn.textContent = `▸ covers ${sans.length} domains`;
    return;
  }
  const cr = document.createElement('div');
  cr.className = 'cover-row';
  cr.innerHTML = `<div class="cover-list">${
    sans.map((s) => `<span class="cover-chip">${escapeHtml(s)}</span>`).join('')
  }</div>`;
  row.after(cr);
  btn.setAttribute('aria-expanded', 'true');
  btn.textContent = `▾ covers ${sans.length} domains`;
}

// Inline rename / re-label a row.
function startEdit(id) {
  const it = currentItems.find((x) => String(x.cert.id) === String(id));
  if (!it) return;
  const row = document.querySelector(`.trow[data-row="${id}"]`);
  if (!row) return;
  closeSwipe(row);
  const c = it.cert;
  row.classList.add('editing');
  row.innerHTML = `
    <div class="edit-row">
      <input type="text" class="edit-name" value="${escapeHtml(c.name)}">
      <select class="edit-cat">${categoryOptions(c.category || 'certificate')}</select>
      <button class="btn primary small" data-save>Save</button>
      <button class="btn ghost small" data-cancel>Cancel</button>
    </div>`;
  row.querySelector('[data-save]').addEventListener('click', () => saveEdit(id, row));
  row.querySelector('[data-cancel]').addEventListener('click', () => loadCerts());
  row.querySelector('.edit-name').focus();
}

async function saveEdit(id, tr) {
  const name = tr.querySelector('.edit-name').value.trim();
  const category = tr.querySelector('.edit-cat').value;
  if (!name) { toast('Name is required', true); return; }
  const res = await api('PATCH', `/api/v1/certs/${id}`, { name, category });
  if (res.ok) { toast('Saved'); loadCerts(); }
  else { const d = await res.json().catch(() => ({})); toast(d.error || 'Save failed', true); }
}

function renderSummary(total, soon, urgent) {
  $('summary').innerHTML = `
    <div class="stat"><div class="n">${total}</div><div class="muted">tracked</div></div>
    <div class="stat"><div class="n" style="color:var(--warn)">${soon}</div><div class="muted">expiring ≤30 days</div></div>
    <div class="stat"><div class="n" style="color:var(--urgent)">${urgent}</div><div class="muted">urgent / expired</div></div>`;
}

async function deleteCert(id) {
  const res = await api('DELETE', `/api/v1/certs/${id}`);
  if (res.status === 204) { toast('Deleted'); loadCerts(); }
  else toast('Delete failed', true);
}

// --- Add-entry tabs (Scan / Manual) ---
document.querySelectorAll('.add-tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.add-tab').forEach((t) => t.classList.toggle('active', t === tab));
    document.querySelectorAll('.add-pane').forEach((p) => { p.hidden = p.id !== tab.dataset.pane; });
  });
});

// --- scan endpoint ---
$('scanForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const target = $('scanTarget').value.trim();
  const name = $('scanName').value.trim();
  const status = $('scanStatus');
  $('scanDetail').hidden = true;
  status.hidden = false;
  status.className = 'status';
  status.textContent = `Scanning ${target}…`;
  try {
    const res = await api('POST', '/api/v1/scan', { target, name });
    const data = await res.json();
    if (res.ok) {
      status.className = 'status ok';
      status.textContent = `Saved: expires ${fmtDate(data.scan.not_after)}${data.scan.trust_error ? ' (untrusted)' : ''}`;
      renderScanDetail(data.scan);
      $('scanTarget').value = '';
      $('scanName').value = '';
      loadCerts();
    } else {
      status.className = 'status err';
      status.textContent = data.error || 'Scan failed';
    }
  } catch (_) {
    status.className = 'status err';
    status.textContent = 'Scan failed';
  }
});

// --- manual / file add ---
$('manualForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = {
    name: $('certName').value.trim(),
    kind: $('certKind').value,
    category: $('certCategory').value,
    expires_at: $('certExpiry').value, // YYYY-MM-DD
    subject: $('certSubject').value,
    issuer: $('certIssuer').value,
    sha256: $('certSha256').value,
  };
  const res = await api('POST', '/api/v1/certs', body);
  if (res.status === 201) {
    toast('Entry added');
    e.target.reset();
    $('certKind').value = 'manual';
    $('dropZone').classList.remove('parsed');
    loadCerts();
  } else {
    const data = await res.json().catch(() => ({}));
    toast(data.error || 'Could not add', true);
  }
});

// --- drag & drop (client-side parse) ---
const dz = $('dropZone');
const fileInput = $('fileInput');
dz.addEventListener('click', () => fileInput.click());
dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('dragover'); });
dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
dz.addEventListener('drop', (e) => {
  e.preventDefault();
  dz.classList.remove('dragover');
  if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', (e) => { if (e.target.files.length) handleFile(e.target.files[0]); });

async function handleFile(file) {
  try {
    const meta = await window.CertParser.parseFile(file, () =>
      prompt('Enter certificate password (leave blank if none):'));
    $('certName').value = meta.name;
    $('certExpiry').value = meta.expiry.toISOString().slice(0, 10);
    $('certSubject').value = meta.subject || '';
    $('certIssuer').value = meta.issuer || '';
    $('certSha256').value = meta.sha256 || '';
    $('certKind').value = 'file';
    $('certCategory').value = 'certificate';
    dz.classList.add('parsed');
    toast(`Parsed ${meta.name} — review and click Add`);
  } catch (err) {
    toast(err.message || 'Could not parse certificate', true);
  }
}

// --- calendar (year overview → click a month to zoom in) ---
// Dates are bucketed by the UTC day of expiry so the calendar matches the dates
// shown in the table (avoids off-by-one shifts in timezones behind UTC).
let calView = 'year'; // 'year' | 'month' | 'day'
let calYear, calMonth, calDay;
(function initCal() {
  const n = new Date();
  calYear = n.getUTCFullYear();
  calMonth = n.getUTCMonth();
  calDay = n.getUTCDate();
})();
// Move the focused day by a number of days, rolling over months/years.
function shiftDay(delta) {
  const d = new Date(Date.UTC(calYear, calMonth, calDay + delta));
  calYear = d.getUTCFullYear();
  calMonth = d.getUTCMonth();
  calDay = d.getUTCDate();
}

function utcKey(iso) {
  const d = new Date(iso);
  return `${d.getUTCFullYear()}-${d.getUTCMonth()}-${d.getUTCDate()}`;
}
function bucketByDay() {
  const byDay = {};
  for (const it of currentItems) {
    if (!it.cert.expires_at) continue;
    (byDay[utcKey(it.cert.expires_at)] ||= []).push(it);
  }
  return byDay;
}
function todayKey() {
  const n = new Date();
  return `${n.getUTCFullYear()}-${n.getUTCMonth()}-${n.getUTCDate()}`;
}

function renderCalendar() {
  if (!$('calGrid')) return;
  if (calView === 'year') renderYear();
  else if (calView === 'month') renderMonth();
  else renderDay();
}

function renderYear() {
  const grid = $('calGrid');
  grid.className = 'cal-year';
  grid.innerHTML = '';
  $('calWeekdays').hidden = true;
  $('calYearBtn').hidden = true;
  $('calLabel').textContent = String(calYear);

  const byDay = bucketByDay();
  const tKey = todayKey();
  for (let m = 0; m < 12; m++) {
    const mini = document.createElement('div');
    mini.className = 'mini-month';
    const title = new Date(Date.UTC(calYear, m, 1))
      .toLocaleString(undefined, { month: 'short', timeZone: 'UTC' });
    const firstDow = new Date(Date.UTC(calYear, m, 1)).getUTCDay();
    const dim = new Date(Date.UTC(calYear, m + 1, 0)).getUTCDate();
    let cells = '';
    let count = 0;
    for (let i = 0; i < firstDow; i++) cells += '<span class="mini-cell empty"></span>';
    for (let d = 1; d <= dim; d++) {
      const key = `${calYear}-${m}-${d}`;
      const list = byDay[key];
      let cls = 'mini-cell';
      let style = '';
      if (list) {
        count += list.length;
        cls += ' has';
        style = ` style="background:${hexA(categoryColor(list[0].cert.category), 0.42)}"`;
      }
      if (key === tKey) cls += ' today';
      cells += `<span class="${cls}"${style}>${d}</span>`;
    }
    mini.innerHTML =
      `<div class="mini-title">${title}${count ? ` <span class="mini-count">${count}</span>` : ''}</div>` +
      `<div class="mini-grid">${cells}</div>`;
    mini.addEventListener('click', () => { calView = 'month'; calMonth = m; renderCalendar(); });
    grid.appendChild(mini);
  }
}

function renderMonth() {
  const grid = $('calGrid');
  grid.className = 'cal-grid';
  grid.innerHTML = '';
  $('calWeekdays').hidden = false;
  $('calYearBtn').hidden = false;
  $('calYearBtn').textContent = '◱ Year';
  $('calLabel').textContent = new Date(Date.UTC(calYear, calMonth, 1))
    .toLocaleString(undefined, { month: 'long', year: 'numeric', timeZone: 'UTC' });

  const byDay = bucketByDay();
  const firstDow = new Date(Date.UTC(calYear, calMonth, 1)).getUTCDay();
  const daysInMonth = new Date(Date.UTC(calYear, calMonth + 1, 0)).getUTCDate();
  const tKey = todayKey();

  for (let i = 0; i < firstDow; i++) {
    const c = document.createElement('div');
    c.className = 'cal-cell empty';
    grid.appendChild(c);
  }
  for (let day = 1; day <= daysInMonth; day++) {
    const key = `${calYear}-${calMonth}-${day}`;
    const cell = document.createElement('div');
    cell.className = 'cal-cell' + (key === tKey ? ' today' : '');
    let html = `<div class="cal-day">${day}</div>`;
    const list = byDay[key];
    if (list) {
      cell.classList.add('has');
      // Compact dots (shown on narrow screens where the text bars don't fit).
      html += '<div class="cal-dots">';
      const cats = [...new Set(list.map((it) => it.cert.category))].slice(0, 4);
      for (const c of cats) html += `<span class="cal-dot" style="background:${categoryColor(c)}"></span>`;
      html += '</div>';
      // Text bars (shown when the cell is wide enough).
      html += '<div class="cal-events">';
      for (const it of list.slice(0, 3)) {
        const col = categoryColor(it.cert.category);
        html += `<div class="cal-ev" style="background:${hexA(col, 0.2)};border-left:3px solid ${col}" title="${escapeHtml(it.cert.name)} — ${fmtRemaining(it.days_remaining)}">${escapeHtml(it.cert.name)}</div>`;
      }
      if (list.length > 3) html += `<div class="cal-more">+${list.length - 3} more</div>`;
      html += '</div>';
    }
    cell.innerHTML = html;
    const d = day;
    cell.addEventListener('click', () => { calView = 'day'; calDay = d; renderCalendar(); });
    grid.appendChild(cell);
  }
}

function renderDay() {
  const grid = $('calGrid');
  grid.className = 'cal-day-view';
  grid.innerHTML = '';
  $('calWeekdays').hidden = true;
  $('calYearBtn').hidden = false;
  $('calYearBtn').textContent = '‹ Month';
  const dObj = new Date(Date.UTC(calYear, calMonth, calDay));
  $('calLabel').textContent = dObj.toLocaleDateString(undefined,
    { weekday: 'short', month: 'long', day: 'numeric', year: 'numeric', timeZone: 'UTC' });

  const list = bucketByDay()[`${calYear}-${calMonth}-${calDay}`] || [];
  if (!list.length) {
    grid.innerHTML = '<p class="muted cal-empty-day">Nothing expires on this day.</p>';
    return;
  }
  for (const it of list) {
    const col = categoryColor(it.cert.category);
    const row = document.createElement('div');
    row.className = 'day-item';
    row.style.borderLeftColor = col;
    row.innerHTML =
      `<div class="day-item-main">` +
        `<div class="day-item-name">${escapeHtml(it.cert.name)}</div>` +
        `<div class="day-item-sub">` +
          `<span class="pill" style="background:${hexA(col, 0.15)};color:${col}">${escapeHtml(categoryLabel(it.cert.category))}</span>` +
          ` <span class="muted">${escapeHtml(fmtRemaining(it.days_remaining))}</span>` +
        `</div>` +
      `</div>` +
      `<a class="btn ghost small" href="/api/v1/certs/${it.cert.id}/calendar.ics" title="Add this to your calendar">📅</a>`;
    grid.appendChild(row);
  }
}

$('calPrev').addEventListener('click', () => {
  if (calView === 'year') calYear--;
  else if (calView === 'day') shiftDay(-1);
  else if (--calMonth < 0) { calMonth = 11; calYear--; }
  renderCalendar();
});
$('calNext').addEventListener('click', () => {
  if (calView === 'year') calYear++;
  else if (calView === 'day') shiftDay(1);
  else if (++calMonth > 11) { calMonth = 0; calYear++; }
  renderCalendar();
});
// Zoom back out one level: day → month → year.
$('calYearBtn').addEventListener('click', () => {
  calView = calView === 'day' ? 'month' : 'year';
  renderCalendar();
});

// initial load
loadWhoami().then(() => {
  // Viewers don't get the scan / add-entry widgets at all.
  if (!isAdmin) {
    document.querySelectorAll('#dashGrid .widget[data-admin]').forEach((w) => w.remove());
  }
  initWidgetGrid($('dashGrid'), 'certguard-dash-layout', {
    addSelect: $('addSectionDash'),
    resetBtn: $('resetDashLayout'),
    // Shipped default arrangement: Add + Tracked side by side at a matched
    // height (fits the manual-entry form), Calendar full-width below. The
    // heights are only applied on multi-column (desktop) layouts.
    defaults: {
      order: ['w-add', 'w-tracked', 'w-calendar'],
      spans: { 'w-add': 2, 'w-tracked': 2, 'w-calendar': 4 },
      heights: { 'w-add': 625, 'w-tracked': 625 },
    },
  });
  renderLegend();
  loadCerts();
}).catch(() => {});
