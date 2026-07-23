// Dashboard: fetches data from the JSON API and renders it. All mutations go
// through the same API the CLI and automation use.

const $ = (id) => document.getElementById(id);

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

// expiryLevel classifies purely by days remaining (expired counts as urgent).
// Trust is tracked separately so an expired cert is never miscounted just
// because it also fails verification.
function expiryLevel(days) {
  if (days <= 3) return 'urgent'; // includes expired (days < 0)
  if (days <= 7) return 'warn';
  if (days <= 30) return 'notice';
  return 'ok';
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toISOString().slice(0, 10);
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

let isAdmin = false;
let currentItems = [];

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

async function loadWhoami() {
  const res = await api('GET', '/api/v1/auth/whoami');
  const data = await res.json();
  const u = data.user;
  isAdmin = u && u.role === 'admin';
  $('whoami').textContent = `${u.email} · ${u.role}`;
  $('adminControls').hidden = !isAdmin;
}

async function loadCerts() {
  const res = await api('GET', '/api/v1/certs');
  currentItems = await res.json();
  const rows = $('certRows');
  rows.innerHTML = '';

  let urgent = 0, soon = 0;
  for (const it of currentItems) {
    const c = it.cert;
    const days = it.days_remaining;
    const trusted = !c.last_error;
    const level = expiryLevel(days);
    if (level === 'urgent') urgent++;
    else if (level === 'warn' || level === 'notice') soon++;

    const catCol = categoryColor(c.category);
    const typeCell = c.category
      ? `<span class="pill" style="background:${hexA(catCol, 0.15)};color:${catCol}">${escapeHtml(categoryLabel(c.category))}</span>`
      : `<span class="muted small">${c.kind}</span>`;
    const actions = [
      `<a class="btn ghost small" href="/api/v1/certs/${c.id}/calendar.ics" title="Add to calendar">📅</a>`,
      isAdmin ? `<button class="btn ghost small" data-edit="${c.id}">Edit</button>` : '',
      isAdmin ? `<button class="btn link" data-del="${c.id}">Delete</button>` : '',
    ].join(' ');

    const tr = document.createElement('tr');
    tr.dataset.row = c.id;
    tr.innerHTML = `
      <td><strong>${escapeHtml(c.name)}</strong>${c.host ? `<br><span class="muted small">${escapeHtml(c.host)}:${c.port}</span>` : ''}</td>
      <td>${typeCell}</td>
      <td>${fmtDate(c.expires_at)}</td>
      <td><span class="pill ${level}">${fmtRemaining(days)}</span></td>
      <td>${trusted ? '<span class="pill ok">ok</span>' : `<span class="pill untrusted" title="${escapeHtml(c.last_error)}">untrusted</span>`}</td>
      <td class="actions">${actions}</td>`;
    rows.appendChild(tr);
  }
  $('empty').hidden = currentItems.length !== 0;

  renderSummary(currentItems.length, soon, urgent);
  renderCalendar();

  rows.querySelectorAll('[data-del]').forEach((b) =>
    b.addEventListener('click', () => deleteCert(b.dataset.del)));
  rows.querySelectorAll('[data-edit]').forEach((b) =>
    b.addEventListener('click', () => startEdit(b.dataset.edit)));
}

// Inline rename / re-label a row.
function startEdit(id) {
  const it = currentItems.find((x) => String(x.cert.id) === String(id));
  if (!it) return;
  const tr = document.querySelector(`tr[data-row="${id}"]`);
  if (!tr) return;
  const c = it.cert;
  tr.innerHTML = `
    <td colspan="6">
      <div class="edit-row">
        <input type="text" class="edit-name" value="${escapeHtml(c.name)}">
        <select class="edit-cat">${categoryOptions(c.category || 'certificate')}</select>
        <button class="btn primary small" data-save>Save</button>
        <button class="btn ghost small" data-cancel>Cancel</button>
      </div>
    </td>`;
  tr.querySelector('[data-save]').addEventListener('click', () => saveEdit(id, tr));
  tr.querySelector('[data-cancel]').addEventListener('click', () => loadCerts());
  tr.querySelector('.edit-name').focus();
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

// --- notification channels ---
async function loadChannels() {
  const res = await api('GET', '/api/v1/channels');
  const chans = await res.json();
  const rows = $('channelRows');
  rows.innerHTML = '';
  for (const c of chans) {
    const th = c.thresholds && c.thresholds.trim() ? c.thresholds : '30,7,3';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="pill notice">${c.type}</span></td>
      <td class="mono">${escapeHtml(c.target)}</td>
      <td class="muted small">${escapeHtml(th)}</td>
      <td class="actions">
        <button class="btn ghost small" data-test="${c.id}">Test</button>
        <button class="btn link" data-delch="${c.id}">Remove</button>
      </td>`;
    rows.appendChild(tr);
  }
  $('noChannels').hidden = chans.length !== 0;
  rows.querySelectorAll('[data-test]').forEach((b) =>
    b.addEventListener('click', () => testChannel(b.dataset.test)));
  rows.querySelectorAll('[data-delch]').forEach((b) =>
    b.addEventListener('click', () => deleteChannel(b.dataset.delch)));
}

$('channelForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = {
    type: $('chType').value,
    target: $('chTarget').value.trim(),
    thresholds: $('chThresholds').value.trim(),
  };
  const res = await api('POST', '/api/v1/channels', body);
  if (res.status === 201) {
    toast('Channel added');
    e.target.reset();
    loadChannels();
  } else {
    const d = await res.json().catch(() => ({}));
    toast(d.error || 'Could not add channel', true);
  }
});

async function testChannel(id) {
  toast('Sending test…');
  const res = await api('POST', `/api/v1/channels/${id}/test`);
  if (res.ok) toast('Test notification sent ✓');
  else {
    const d = await res.json().catch(() => ({}));
    toast(d.error || 'Test failed', true);
  }
}

async function deleteChannel(id) {
  const res = await api('DELETE', `/api/v1/channels/${id}`);
  if (res.status === 204) { toast('Channel removed'); loadChannels(); }
  else toast('Remove failed', true);
}

// --- calendar (year overview → click a month to zoom in) ---
// Dates are bucketed by the UTC day of expiry so the calendar matches the dates
// shown in the table (avoids off-by-one shifts in timezones behind UTC).
let calView = 'year'; // 'year' | 'month'
let calYear, calMonth;
(function initCal() {
  const n = new Date();
  calYear = n.getUTCFullYear();
  calMonth = n.getUTCMonth();
})();

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
  else renderMonth();
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
      html += '<div class="cal-events">';
      for (const it of list.slice(0, 3)) {
        const col = categoryColor(it.cert.category);
        html += `<div class="cal-ev" style="background:${hexA(col, 0.2)};border-left:3px solid ${col}" title="${escapeHtml(it.cert.name)} — ${fmtRemaining(it.days_remaining)}">${escapeHtml(it.cert.name)}</div>`;
      }
      if (list.length > 3) html += `<div class="cal-more">+${list.length - 3} more</div>`;
      html += '</div>';
    }
    cell.innerHTML = html;
    grid.appendChild(cell);
  }
}

$('calPrev').addEventListener('click', () => {
  if (calView === 'year') calYear--;
  else if (--calMonth < 0) { calMonth = 11; calYear--; }
  renderCalendar();
});
$('calNext').addEventListener('click', () => {
  if (calView === 'year') calYear++;
  else if (++calMonth > 11) { calMonth = 0; calYear++; }
  renderCalendar();
});
$('calYearBtn').addEventListener('click', () => { calView = 'year'; renderCalendar(); });

// --- light / dark theme toggle ---
// Flat, single-colour icons (currentColor) — no emoji.
const ICON_MOON = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z"/></svg>';
const ICON_SUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4.2"/><path d="M12 3v1.6M12 19.4V21M3 12h1.6M19.4 12H21M5.6 5.6l1.1 1.1M17.3 17.3l1.1 1.1M18.4 5.6l-1.1 1.1M6.7 17.3l-1.1 1.1"/></svg>';
function effectiveTheme() {
  const explicit = document.documentElement.getAttribute('data-theme');
  if (explicit) return explicit;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
function updateThemeIcon() {
  // Show the mode you'd switch TO.
  $('themeToggle').innerHTML = effectiveTheme() === 'dark' ? ICON_SUN : ICON_MOON;
}
$('themeToggle').addEventListener('click', () => {
  const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('certguard-theme', next); } catch (e) {}
  updateThemeIcon();
});
updateThemeIcon();
renderLegend();

// --- logout ---
$('logout').addEventListener('click', async () => {
  await api('POST', '/api/v1/auth/logout');
  window.location.href = '/login';
});

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// initial load
loadWhoami().then(() => { loadCerts(); loadChannels(); }).catch(() => {});
