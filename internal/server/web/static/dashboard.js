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

// Row action icons. Labelled via title + aria-label so they stay accessible
// without the text; the detail popup keeps worded buttons, where there's room.
const ICON_EDIT = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>';
const ICON_DEL = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2"/><path d="M19 6l-1 14a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1L5 6"/><path d="M10 11v6M14 11v6"/></svg>';

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
  renderDerivedCards();
}

// Re-render the list (rows only) when the search text or sort order changes.
// A new query means a new result set, so go back to the first page.
['trackedSearch', 'trackedSort'].forEach((id) => {
  const el = $(id);
  if (el) el.addEventListener('input', () => { shownCount = PAGE; renderCerts(); });
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

// Build one row element, with its handlers already attached.
function buildRow(it) {
  const c = it.cert;
  const days = it.days_remaining;
  const trusted = !c.last_error;
  const level = expiryLevel(days);

  const catCol = categoryColor(c.category);
  const typeCell = c.category
    ? `<span class="pill" style="background:${hexA(catCol, 0.15)};color:${catCol}">${escapeHtml(categoryLabel(c.category))}</span>`
    : `<span class="muted small">${c.kind}</span>`;
  const isEndpoint = c.kind === 'endpoint' || !!c.host;
  const inlineActions = isAdmin
    ? `<button class="icon-btn" data-edit="${c.id}" title="Edit" aria-label="Edit ${escapeHtml(c.name)}">${ICON_EDIT}</button>` +
      `<button class="icon-btn danger" data-del="${c.id}" title="Delete" aria-label="Delete ${escapeHtml(c.name)}">${ICON_DEL}</button>`
    : '';
  const swipeActions = isAdmin
    ? `<button class="swipe-act edit" data-edit="${c.id}" title="Edit" aria-label="Edit ${escapeHtml(c.name)}">${ICON_EDIT}</button>` +
      `<button class="swipe-act del" data-del="${c.id}" title="Delete" aria-label="Delete ${escapeHtml(c.name)}">${ICON_DEL}</button>`
    : '';
  // Trust is only a real signal for endpoints we actually connect to. A manual
  // entry is never scanned, so `!last_error` was rendering a reassuring "ok"
  // that verified nothing — its status is its expiry, carried by the days
  // pill. Leave the cell empty rather than claim a check that never ran.
  const trustCell = !isEndpoint
    ? ''
    : trusted
      ? '<span class="pill ok">ok</span>'
      : `<span class="pill untrusted" title="${escapeHtml(c.last_error)}">untrusted</span>`;

  const row = document.createElement('div');
  row.className = 'trow';
  row.dataset.row = c.id;
  row.innerHTML = `
    <div class="trow-actions" aria-hidden="true">${swipeActions}</div>
    <div class="trow-surface">
      <div class="tcol tc-name"><strong>${escapeHtml(c.name)}</strong></div>
      <div class="tcol tc-meta">
        <span class="tc-exp"><span class="d-long">${fmtDate(c.expires_at)}</span><span class="d-short">${fmtDateShort(c.expires_at)}</span></span>
        <span class="tc-type">${typeCell}</span>
        <span class="tc-rem"><span class="pill ${level}">${fmtRemaining(days)}</span></span>
        <span class="tc-trust">${trustCell}</span>
      </div>
      <div class="tcol tc-actions">${inlineActions}</div>
    </div>`;

  row.querySelectorAll('[data-del]').forEach((b) =>
    b.addEventListener('click', () => deleteCert(b.dataset.del)));
  row.querySelectorAll('[data-edit]').forEach((b) =>
    b.addEventListener('click', () => startEdit(b.dataset.edit)));
  attachSwipe(row);
  // Tap a row for the full readout. Ignore taps on the row's own controls, and
  // ignore the tap that ends a swipe (or the one that just closes an open row).
  row.querySelector('.trow-surface').addEventListener('click', (e) => {
    if (e.target.closest('button, a, input, select, textarea, label')) return;
    if (row.dataset.swiped) return;
    if (row.classList.contains('open')) { closeSwipe(row); return; }
    openDetail(row.dataset.row);
  });
  return row;
}

// The list renders a page at a time. A sentinel after the rows loads the next
// page whenever it comes into view inside the card, so the card first fills to
// its own height — leaving the tip visible at the bottom — and only fetches
// more as you scroll. Long inventories no longer build hundreds of rows up
// front, which also keeps the masonry re-pack cheap.
const PAGE = 12;
let shownCount = PAGE;
let moreObserver = null;

function renderCerts() {
  const rows = $('certRows');
  rows.innerHTML = '';

  const items = filterSortItems();
  if (shownCount < PAGE) shownCount = PAGE;
  for (const it of items.slice(0, shownCount)) rows.appendChild(buildRow(it));
  openRow = null;
  setupMoreObserver(items.length);

  $('empty').hidden = currentItems.length !== 0;
  if ($('trackedToolbar')) $('trackedToolbar').hidden = currentItems.length === 0;
  if ($('noMatch')) $('noMatch').hidden = !(currentItems.length !== 0 && items.length === 0);
  const hint = $('swipeHint');
  if (hint) hint.hidden = items.length === 0 || !isAdmin;

  // Keep an open popup in step with the data it was built from.
  if (detailId !== null) {
    const still = currentItems.find((x) => String(x.cert.id) === String(detailId));
    if (still) renderDetail(still); else closeDetail();
  }
}

// Watch a sentinel just below the last row, scoped to the card's scroll box.
// While it's on screen we keep appending — that fills a tall card on load —
// and once it's pushed out of view the next page waits for a scroll.
function setupMoreObserver(total) {
  const rows = $('certRows');
  const body = rows.closest('.widget-body');
  let sentinel = $('moreSentinel');
  if (!sentinel) {
    sentinel = document.createElement('div');
    sentinel.id = 'moreSentinel';
    sentinel.className = 'more-sentinel';
    sentinel.innerHTML = '<span class="muted small">Loading more…</span>';
  }
  rows.after(sentinel);
  if (moreObserver) { moreObserver.disconnect(); moreObserver = null; }
  if (shownCount >= total) { sentinel.hidden = true; return; }
  sentinel.hidden = false;
  moreObserver = new IntersectionObserver((entries) => {
    if (!entries.some((e) => e.isIntersecting)) return;
    const all = filterSortItems();
    const next = all.slice(shownCount, shownCount + PAGE);
    if (!next.length) { moreObserver.disconnect(); sentinel.hidden = true; return; }
    // Each row in the batch rises a beat after the one above it, so a page
    // arrives as a wave rather than a block. Only on rows paged in by a scroll
    // — a full re-render (rescan, search, delete) must not re-animate.
    next.forEach((it, i) => {
      const row = buildRow(it);
      row.classList.add('flow-in');
      row.style.setProperty('--i', i);
      row.addEventListener('animationend', () => {
        row.classList.remove('flow-in');
        row.style.removeProperty('--i');
      }, { once: true });
      rows.appendChild(row);
    });
    shownCount += next.length;
    rows.after(sentinel);
    if (shownCount >= all.length) { moreObserver.disconnect(); sentinel.hidden = true; }
    // No rootMargin: stop as soon as the sentinel clears the bottom edge, so the
    // first load is about one card's worth rather than two.
  }, { root: body });
  moreObserver.observe(sentinel);
}

// --- vault unlock ---
// In zero-knowledge mode the passphrase is stretched in the browser and unwraps
// the data key locally (nothing is sent to the server). Otherwise it posts to the
// server-side passphrase vault.
function showVaultUnlock() {
  const dlg = $('vaultDialog'); if (!dlg) return;
  const go = async () => {
    const errEl = $('vaultLockErr');
    errEl.hidden = true;
    const pass = $('vaultPass').value;
    if (zkEnabled) {
      try {
        const res = await api('GET', '/api/v1/vault/keyring');
        if (!res.ok) throw new Error('keyring unavailable');
        await ZK.unlock(pass, await res.json());
        vaultLocked = false;
        closeVaultDialog();
        syncVaultUi();
        toast('Vault unlocked ✓');
        loadCerts();
      } catch (e) {
        errEl.textContent = 'Incorrect passphrase';
        errEl.hidden = false;
      }
      return;
    }
    const res = await api('POST', '/api/v1/vault/unlock', { passphrase: pass });
    if (res.ok) { location.reload(); return; }
    const d = await res.json().catch(() => ({}));
    errEl.textContent = d.error || 'Unlock failed';
    errEl.hidden = false;
  };
  $('vaultLockErr').hidden = true;
  $('vaultPass').value = '';
  $('vaultUnlockBtn').onclick = go;
  $('vaultPass').onkeydown = (e) => { if (e.key === 'Enter') go(); };
  // showModal stacks: opened from Reveal inside the detail popup, this lands on
  // top of it rather than behind, which an inline banner could never do.
  if (!dlg.open) dlg.showModal();
  $('vaultPass').focus();
}

function closeVaultDialog() {
  const dlg = $('vaultDialog');
  if (dlg && dlg.open) dlg.close();
}

// One button beside the wordmark, showing and toggling the vault's state. It
// only appears where there is something to lock — a passphrase vault or ZK mode
// — since in auto mode the key sits on disk and "locking" would be theatre.
const ICON_LOCKED = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10.5" width="16" height="10" rx="2.2"/><path d="M8 10.5V7.6a4 4 0 0 1 8 0v2.9"/></svg>';
const ICON_UNLOCKED = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10.5" width="16" height="10" rx="2.2"/><path d="M8 10.5V7.4a4 4 0 0 1 7.7-1.5"/></svg>';

function syncVaultUi() {
  const btn = $('vaultLockBtn');
  if (!btn) return;
  btn.hidden = !(vaultLockable && isAdmin);
  btn.innerHTML = vaultLocked ? ICON_LOCKED : ICON_UNLOCKED;
  btn.classList.toggle('locked', vaultLocked);
  const label = vaultLocked ? 'Vault locked — click to unlock' : 'Vault unlocked — click to lock';
  btn.title = label;
  btn.setAttribute('aria-label', label);
}

// Locked → offer the passphrase box. Unlocked → close the vault again.
function toggleVault() {
  if (vaultLocked) showVaultUnlock(); else lockVault();
}

// Close the vault without signing out. ZK mode drops the data key from memory;
// otherwise the server forgets its unwrapped copy.
async function lockVault() {
  if (zkEnabled) {
    ZK.lock();
  } else {
    const res = await api('POST', '/api/v1/vault/lock');
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      toast(d.error || 'Could not lock the vault', true);
      return;
    }
  }
  vaultLocked = true;
  syncVaultUi();
  toast('Vault locked');
  loadCerts();
}
if ($('vaultLockBtn')) $('vaultLockBtn').addEventListener('click', toggleVault);
if ($('vaultClose')) $('vaultClose').addEventListener('click', closeVaultDialog);
['coverAddClose', 'coverAddSkip'].forEach((id) => {
  if ($(id)) $(id).addEventListener('click', () => $('coverAddDialog').close());
});
if ($('coverAddDialog')) {
  $('coverAddDialog').addEventListener('click', (e) => {
    if (e.target === $('coverAddDialog')) $('coverAddDialog').close();
  });
}
if ($('vaultDialog')) {
  $('vaultDialog').addEventListener('click', (e) => {
    if (e.target === $('vaultDialog')) closeVaultDialog();
  });
}

// Reveal a stored secret: copy to clipboard and show it inline briefly. In
// zero-knowledge mode the server returns ciphertext that we decrypt locally.
async function revealSecret(id, btn) {
  if (vaultLocked || (zkEnabled && !ZK.isUnlocked())) {
    vaultLocked = true; syncVaultUi();
    showVaultUnlock();
    return;
  }
  const res = await api('GET', `/api/v1/certs/${id}/secret`);
  const d = await res.json().catch(() => ({}));
  // 423 Locked: the passphrase vault was closed since this page loaded (another
  // tab, a restart, a timeout). Offer the box here instead of a dead-end toast.
  if (res.status === 423) {
    vaultLocked = true; syncVaultUi();
    showVaultUnlock();
    return;
  }
  if (!res.ok) { toast(d.error || 'Reveal failed', true); return; }
  let value = d.value;
  if (zkEnabled) {
    try { value = await ZK.decrypt(d.enc); }
    catch (e) { toast('Could not decrypt — wrong passphrase?', true); return; }
  }
  let copied = false;
  try { await navigator.clipboard.writeText(value); copied = true; } catch (e) {}
  const span = btn.closest('.secretline');
  if (!span) { toast(copied ? 'Secret copied ✓' : value); return; }
  span.innerHTML = `🔑 <code class="secret-reveal">${escapeHtml(value)}</code> <button class="secret-btn" data-hide>hide</button>`;
  span.querySelector('[data-hide]').addEventListener('click', () => loadCerts());
  toast(copied ? 'Secret copied to clipboard ✓' : 'Secret revealed');
  setTimeout(() => { if (document.body.contains(span)) loadCerts(); }, 30000);
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
    // A swipe ends with a click event on the surface; flag the row briefly so
    // the tap-for-details handler ignores it.
    row.dataset.swiped = '1';
    setTimeout(() => { delete row.dataset.swiped; }, 350);
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

// --- entry detail popup ---
// Rows carry only name / type / date / days / status so the card stays usable
// in a narrow column. Everything else — host, fingerprint, SANs, scan state,
// stored secret — lives here and opens on tap.
let detailId = null;

// Other entries sharing this fingerprint, i.e. literally the same certificate.
function duplicatesOf(c) {
  if (!c.sha256) return [];
  return currentItems
    .filter((x) => x.cert.sha256 === c.sha256 && x.cert.id !== c.id)
    .map((x) => x.cert.name);
}

// Rows accumulate here so the domain branch and the certificate branch can
// share one painter (finishDetail).
let detailRows = [];

function renderDetail(it) {
  const c = it.cert;
  const days = it.days_remaining;
  const isEndpoint = c.kind === 'endpoint' || !!c.host;
  detailRows = [];
  const add = (k, v) => { if (v) detailRows.push(`<div class="sd-row"><span class="sd-k">${k}</span><span class="sd-v">${v}</span></div>`); };

  const catCol = categoryColor(c.category);
  add('Type', c.category
    ? `<span class="pill" style="background:${hexA(catCol, 0.15)};color:${catCol}">${escapeHtml(categoryLabel(c.category))}</span>`
    : `<span class="muted">${escapeHtml(c.kind || '')}</span>`);
  add('Expires', `${fmtDate(c.expires_at)} <span class="pill ${expiryLevel(days)}">${fmtRemaining(days)}</span>`);

  // A domain registration reuses the same columns for different facts, so it
  // gets its own labels rather than reading "Issuer: Bluehost Inc."
  if (c.kind === 'domain') {
    add('Domain', `<span class="mono">${escapeHtml(c.host || '')}</span>`);
    add('Registrar', escapeHtml(c.issuer || ''));
    if (c.not_before && new Date(c.not_before).getUTCFullYear() > 2000) add('Registered', fmtDate(c.not_before));
    add('Status', escapeHtml(c.subject || ''));
    const ns = c.dns_names || [];
    if (ns.length) add('Nameservers', `<div class="cover-list">${ns.map((n) => `<span class="cover-chip">${escapeHtml(n)}</span>`).join('')}</div>`);
    if (c.last_error) add('Last lookup', `<span class="pill untrusted">failed</span> <span class="muted small">${escapeHtml(c.last_error)}</span>`);
    else if (c.last_scanned_at) add('Last checked', `<span class="muted">checked ${escapeHtml(relTime(c.last_scanned_at))}</span>` +
      (isAdmin ? ` · <button class="rescan-btn" data-drescan="${c.id}" title="Look this domain up again now">↻ refresh now</button>` : ''));
    add('Added', fmtDate(c.created_at));
    finishDetail(c);
    return;
  }
  if (isEndpoint) add('Endpoint', `<span class="mono">${escapeHtml(c.host)}:${c.port}</span>`);
  // Manual entries serialize a zero not_before; only show a real one.
  if (c.not_before && new Date(c.not_before).getUTCFullYear() > 2000) add('Valid from', fmtDate(c.not_before));
  add('Subject', escapeHtml(dnField(c.subject, 'CN') || c.subject || ''));
  add('Issuer', escapeHtml(dnField(c.issuer, 'O') || dnField(c.issuer, 'CN') || c.issuer || ''));
  const sans = c.dns_names || [];
  if (sans.length) {
    // Covering a name is not the same as serving it: a host picks a certificate
    // per vhost via SNI, so any of these may be answered by something else.
    const check = isAdmin
      ? `<button class="rescan-btn cover-check" data-coverage="${c.id}" title="Connect to each name and report the certificate it actually serves">↻ check what each serves</button>`
      : '';
    add(`Covers ${sans.length > 1 ? `(${sans.length})` : ''}`.trim(),
      `<div class="cover-list">${sans.map((s) => `<span class="cover-chip">${escapeHtml(s)}</span>`).join('')}</div>` +
      (check ? `<div class="cover-actions">${check}</div>` : '') +
      '<div class="cover-results" hidden></div>');
  }
  add('Key', escapeHtml([c.key_type, c.signature_algorithm].filter(Boolean).join(' · ')));
  add('Serial', c.serial ? `<span class="mono sd-fp">${escapeHtml(c.serial)}</span>` : '');
  if (c.sha256) {
    const dups = duplicatesOf(c);
    const note = dups.length
      ? `<div class="muted small dup-note">Same certificate as ${escapeHtml(dups.join(', '))}</div>`
      : '';
    add('SHA-256', `<span class="mono sd-fp">${escapeHtml(c.sha256)}</span>${note}`);
  }
  if (isEndpoint) {
    add('Trust', c.last_error
      ? `<span class="pill untrusted">untrusted</span> <span class="muted small">${escapeHtml(c.last_error)}</span>`
      : '<span class="pill ok">ok</span>');
    const checked = c.last_scanned_at ? `checked ${escapeHtml(relTime(c.last_scanned_at))}` : 'never checked';
    const rescan = isAdmin ? ` · <button class="rescan-btn" data-drescan="${c.id}" title="Rescan this endpoint now">↻ rescan now</button>` : '';
    add('Last checked', `<span class="muted">${checked}</span>${rescan}`);
  }
  if (c.has_secret) {
    const rev = isAdmin ? ` · <button class="secret-btn" data-dreveal="${c.id}">reveal</button>` : '';
    add('Secret', `<span class="secretline">🔑 ${escapeHtml(c.secret_hint || 'secret set')}${rev}</span>`);
  }
  add('Notes', escapeHtml(c.notes || ''));
  // Always last, and the one thing a bare manual entry can always show.
  add('Added', fmtDate(c.created_at));

  finishDetail(c);
}

// Shared tail for every flavour of detail popup: paint the rows collected so
// far, build the action row, and wire the buttons.
function finishDetail(c) {
  $('detailTitle').textContent = c.name;
  $('detailBody').innerHTML = detailRows.join('');
  $('detailActions').innerHTML = [
    `<a class="btn ghost small" href="/api/v1/certs/${c.id}/calendar.ics">📆 Add to calendar</a>`,
    isAdmin ? `<span class="spacer"></span><button class="btn ghost small" data-dedit="${c.id}">Edit</button>` : '',
    isAdmin ? `<button class="btn link" data-ddel="${c.id}">Delete</button>` : '',
  ].join(' ');

  const body = $('detailBody'), acts = $('detailActions');
  const on = (sel, fn) => { const b = body.querySelector(sel) || acts.querySelector(sel); if (b) b.addEventListener('click', () => fn(b)); };
  on('[data-drescan]', (b) => rescanCert(b.dataset.drescan, b));
  on('[data-coverage]', (b) => checkCoverage(b.dataset.coverage, b));
  on('[data-dreveal]', (b) => revealSecret(b.dataset.dreveal, b));
  on('[data-dedit]', (b) => { const id = b.dataset.dedit; closeDetail(); startEdit(id); });
  on('[data-ddel]', (b) => deleteCert(b.dataset.ddel));
}

// Connect to every name this certificate covers and report what each actually
// serves. Results are grouped, because the interesting ones are the mismatches:
// a name covered here but answered by a different certificate is a renewal trap
// — letting this one lapse still breaks that host.
const COVER_LABEL = {
  match: 'serving this certificate',
  different: 'serving a DIFFERENT certificate',
  wildcard: 'wildcard — nothing to connect to',
  unreachable: 'could not connect',
};
async function checkCoverage(id, btn) {
  const box = btn.closest('.sd-v').querySelector('.cover-results');
  btn.disabled = true;
  btn.textContent = '↻ checking…';
  const res = await api('POST', `/api/v1/certs/${id}/coverage`);
  const d = await res.json().catch(() => ({}));
  btn.disabled = false;
  btn.textContent = '↻ check what each serves';
  if (!res.ok) { toast(d.error || 'Coverage check failed', true); return; }

  const rows = (d.names || []).map((n) => {
    const cls = { match: 'ok', different: 'warn', wildcard: 'dup', unreachable: 'untrusted' }[n.status] || 'dup';
    let sub = COVER_LABEL[n.status] || n.status;
    if (n.status === 'different' && n.subject) {
      sub = `served by <strong>${escapeHtml(dnField(n.subject, 'CN') || n.subject)}</strong>` +
        (n.issuer ? ` · ${escapeHtml(dnField(n.issuer, 'O') || n.issuer)}` : '') +
        (n.not_after ? ` · expires ${fmtDate(n.not_after)}` : '');
    } else if (n.status === 'unreachable' && n.detail) {
      sub = escapeHtml(n.detail);
    } else if (n.status === 'match' && n.not_after) {
      sub = `serving this certificate · expires ${fmtDate(n.not_after)}`;
    }
    return `<div class="cover-row"><span class="pill ${cls}">${n.status}</span>` +
      `<span class="cover-row-body"><span class="mono">${escapeHtml(n.name)}</span>` +
      `<span class="muted small">${sub}</span></span></div>`;
  }).join('');

  const diff = (d.names || []).filter((n) => n.status === 'different').length;
  const bad = (d.names || []).filter((n) => n.status === 'unreachable').length;
  const summary = diff || bad
    ? `<p class="muted small cover-summary">${diff} name${diff === 1 ? '' : 's'} served by a different certificate` +
      (bad ? `, ${bad} unreachable` : '') + ` — port ${d.port}.</p>`
    : `<p class="muted small cover-summary">Every reachable name serves this certificate — port ${d.port}.</p>`;
  box.innerHTML = summary + rows;
  box.hidden = false;
}

// --- track a domain registration ---
if ($('domainForm')) $('domainForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const target = $('domainTarget').value.trim();
  const status = $('domainStatus');
  status.hidden = false;
  status.className = 'status';
  status.textContent = `Looking up ${target}…`;
  try {
    const res = await api('POST', '/api/v1/domains', { domain: target });
    const d = await res.json().catch(() => ({}));
    if (res.ok) {
      status.className = 'status ok';
      const l = d.lookup || {};
      status.textContent = `Tracking ${l.domain} — ${l.registrar || 'registrar unknown'}, expires ${fmtDate(l.expires_at)}`;
      $('domainTarget').value = '';
      loadCerts();
    } else {
      status.className = 'status err';
      status.textContent = d.error || 'Lookup failed';
    }
  } catch (_) {
    status.className = 'status err';
    status.textContent = 'Lookup failed';
  }
});

// After a scan, check whether the names this certificate covers are actually
// served by it. Where they are not, offer to track those certificates too —
// they are separate things with separate expiry dates, and nothing about the
// scanned entry would ever warn you about them.
async function offerCoverageAdds(saved, status) {
  if (!isAdmin || !saved || !saved.id) return;
  const sans = (saved.dns_names || []).filter((n) => !n.startsWith('*.'));
  if (sans.length < 2) return; // only itself — nothing else to look at
  if (status) { status.className = 'status'; status.textContent = `Checking the ${sans.length} names it covers…`; }
  const res = await api('POST', `/api/v1/certs/${saved.id}/coverage`);
  if (!res.ok) { if (status) status.hidden = true; return; }
  const d = await res.json().catch(() => ({}));

  // One entry per distinct certificate, not per name: four hostnames served by
  // the same certificate are one thing to track, not four.
  const known = new Set(currentItems.map((i) => i.cert.sha256).filter(Boolean));
  const groups = new Map();
  for (const n of d.names || []) {
    if (n.status !== 'different' || !n.sha256 || known.has(n.sha256)) continue;
    if (!groups.has(n.sha256)) groups.set(n.sha256, { ...n, names: [] });
    groups.get(n.sha256).names.push(n.name);
  }
  const found = [...groups.values()];

  // Every hostname this scan touched, including the SANs of the certificates
  // found behind them — that union is what reveals domains like unibox.biz,
  // which appears on a neighbouring certificate and nowhere else.
  const hosts = new Set([saved.host, ...(saved.dns_names || [])].filter(Boolean));
  for (const n of d.names || []) {
    hosts.add(n.name);
    for (const s of n.dns_names || []) hosts.add(s);
  }
  if (status) status.textContent = 'Looking up domain registrations…';
  const domains = await domainCandidates([...hosts]);

  if (status) {
    status.className = 'status ok';
    const bits = [];
    if (found.length) bits.push(`${found.length} other certificate${found.length === 1 ? '' : 's'}`);
    if (domains.length) bits.push(`${domains.length} domain registration${domains.length === 1 ? '' : 's'}`);
    status.textContent = bits.length
      ? `Found ${bits.join(' and ')} worth tracking`
      : 'Nothing else found — every reachable name serves this certificate';
  }
  if (found.length || domains.length) showCoverageAdd(found, domains, saved.name);
}

// Ask the server which registrable domains a pile of hostnames belong to. The
// reduction needs the Public Suffix List, which lives server-side.
async function domainCandidates(hosts) {
  const res = await api('POST', '/api/v1/domains/candidates', { hosts });
  if (!res.ok) return [];
  const d = await res.json().catch(() => ({}));
  // Keep only what is both untracked and actually has a published expiry —
  // a ccTLD that publishes none, or a name nobody registered, is not
  // something we can put a date on.
  return (d.domains || []).filter((x) => !x.tracked && x.expires_at && !x.error);
}

// Where to actually track a certificate we found behind an alias. The alias
// works, but tracking cpigauges.com beats tracking
// www.cpigaugescom.uniweldproducts.com — same certificate, and the entry says
// what the thing IS. Taken from the certificate's own CN/SANs rather than
// derived from the alias, which cannot be reversed reliably.
function canonicalHost(g) {
  const cn = dnField(g.subject, 'CN');
  if (cn && !cn.startsWith('*.')) return cn;
  const real = (g.dns_names || []).find((n) => !n.startsWith('*.'));
  return real || g.names[0];
}

function showCoverageAdd(found, domains, fromName) {
  const dlg = $('coverAddDialog');
  if (!dlg) return;
  const parts = [];
  if (found.length) parts.push(`${found.length} other certificate${found.length === 1 ? '' : 's'}`);
  if (domains.length) parts.push(`${domains.length} domain registration${domains.length === 1 ? '' : 's'}`);
  $('coverAddIntro').textContent =
    `Scanning ${fromName} turned up ${parts.join(' and ')}. Each expires on its own schedule — track them too?`;

  $('coverAddDomains').hidden = domains.length === 0;
  $('coverAddDomainList').innerHTML = domains.map((g, i) => `
    <label class="cover-add-item">
      <input type="checkbox" data-dpick="${i}" checked>
      <span class="cover-add-body">
        <span class="cover-add-title">${escapeHtml(g.domain)}</span>
        <span class="muted small">${escapeHtml(g.registrar || 'registrar unknown')} · expires ${fmtDate(g.expires_at)}</span>
        ${(g.status || []).length ? `<span class="muted small">${escapeHtml(g.status.join(', '))}</span>` : ''}
      </span>
    </label>`).join('');
  $('coverAddList').innerHTML = found.map((g, i) => {
    const host = canonicalHost(g);
    const also = (g.dns_names || []).filter((n) => !n.startsWith('*.') && n !== host);
    return `
    <label class="cover-add-item">
      <input type="checkbox" data-pick="${i}" checked>
      <span class="cover-add-body">
        <span class="cover-add-title">${escapeHtml(host)}</span>
        <span class="muted small">${escapeHtml(dnField(g.issuer, 'O') || g.issuer || '')}${g.not_after ? ` · expires ${fmtDate(g.not_after)}` : ''}</span>
        <span class="muted small">found behind ${g.names.map((n) => escapeHtml(n)).join(', ')}</span>
        ${also.length ? `<span class="muted small">also covers ${also.map((n) => escapeHtml(n)).join(', ')}</span>` : ''}
      </span>
    </label>`;
  }).join('');

  $('coverAddGo').onclick = async () => {
    const picks = [...$('coverAddList').querySelectorAll('[data-pick]')]
      .filter((cb) => cb.checked).map((cb) => found[+cb.dataset.pick]);
    const dpicks = [...$('coverAddDomainList').querySelectorAll('[data-dpick]')]
      .filter((cb) => cb.checked).map((cb) => domains[+cb.dataset.dpick]);
    if (!picks.length && !dpicks.length) { dlg.close(); return; }
    $('coverAddGo').disabled = true;
    $('coverAddGo').textContent = 'Adding…';
    let ok = 0;
    for (const g of dpicks) {
      const r = await api('POST', '/api/v1/domains', { domain: g.domain, name: g.domain });
      if (r.ok) ok++;
    }
    for (const g of picks) {
      // Scan one hostname per certificate — the same path a manual scan takes,
      // so these are ordinary endpoint entries that rescan on their own. Try the
      // real domain first; fall back to the alias we found it behind, since the
      // canonical name is only a claim on the certificate until it resolves.
      const host = canonicalHost(g);
      let r = await api('POST', '/api/v1/scan', { target: host, name: host });
      if (!r.ok && host !== g.names[0]) {
        r = await api('POST', '/api/v1/scan', { target: g.names[0], name: host });
      }
      if (r.ok) ok++;
    }
    $('coverAddGo').disabled = false;
    $('coverAddGo').textContent = 'Add selected';
    dlg.close();
    toast(`Added ${ok} certificate${ok === 1 ? '' : 's'}`);
    loadCerts();
  };
  if (!dlg.open) dlg.showModal();
  dlg.focus();
}

function openDetail(id) {
  const it = currentItems.find((x) => String(x.cert.id) === String(id));
  if (!it) return;
  detailId = it.cert.id;
  renderDetail(it);
  const dlg = $('entryDetail');
  if (!dlg.open) dlg.showModal();
  // showModal() focuses the first focusable descendant, which here is the ×.
  // iOS paints a focus ring on it, so the close button opens looking selected.
  // Focus the dialog itself instead (it carries tabindex="-1").
  dlg.focus();
}

function closeDetail() {
  detailId = null;
  const dlg = $('entryDetail');
  if (dlg && dlg.open) dlg.close();
}

// Close via the ×, a click on the backdrop, or Esc (which <dialog> handles for
// us and surfaces as a `close` event) — all have to clear the tracked id.
if ($('entryDetail')) {
  const dlg = $('entryDetail');
  $('detailClose').addEventListener('click', () => closeDetail());
  dlg.addEventListener('click', (e) => { if (e.target === dlg) closeDetail(); });
  dlg.addEventListener('close', () => { detailId = null; });
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
  const secretRow = secretsEnabled ? `
      <div class="edit-secret-row">
        <input type="text" class="edit-secret" placeholder="${c.has_secret ? 'Replace secret (leave blank to keep ' + escapeHtml(c.secret_hint || 'set') + ')' : 'Add a secret / key value (optional)'}">
        ${c.has_secret ? '<label class="clear-sec"><input type="checkbox" class="edit-clearsec"> clear</label>' : ''}
      </div>` : '';
  row.innerHTML = `
    <div class="edit-row">
      <input type="text" class="edit-name" value="${escapeHtml(c.name)}">
      <select class="edit-cat">${categoryOptions(c.category || 'certificate')}</select>
      <button class="btn primary small" data-save>Save</button>
      <button class="btn ghost small" data-cancel>Cancel</button>
    </div>${secretRow}`;
  row.querySelector('[data-save]').addEventListener('click', () => saveEdit(id, row));
  row.querySelector('[data-cancel]').addEventListener('click', () => loadCerts());
  row.querySelector('.edit-name').focus();
}

async function saveEdit(id, tr) {
  const name = tr.querySelector('.edit-name').value.trim();
  const category = tr.querySelector('.edit-cat').value;
  if (!name) { toast('Name is required', true); return; }
  const res = await api('PATCH', `/api/v1/certs/${id}`, { name, category });
  if (!res.ok) { const d = await res.json().catch(() => ({})); toast(d.error || 'Save failed', true); return; }
  // Secret changes (optional): a new value replaces it; the clear box wipes it.
  const secInput = tr.querySelector('.edit-secret');
  const clearBox = tr.querySelector('.edit-clearsec');
  if (secInput && secInput.value) {
    if (zkEnabled && !ZK.isUnlocked()) { showVaultUnlock(); toast('Unlock the vault first', true); return; }
    await api('PUT', `/api/v1/certs/${id}/secret`, await secretBody(secInput.value));
  } else if (clearBox && clearBox.checked) {
    await api('PUT', `/api/v1/certs/${id}/secret`, await secretBody(''));
  }
  toast('Saved'); loadCerts();
}

// secretBody builds the /secret PUT payload. In zero-knowledge mode the value is
// encrypted in the browser and only ciphertext + a masked hint are sent.
async function secretBody(plaintext) {
  if (!zkEnabled) return { value: plaintext };
  if (!plaintext) return { enc: '', hint: '' };
  return { enc: await ZK.encrypt(plaintext), hint: ZK.hint(plaintext) };
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
      offerCoverageAdds(data.saved, status);
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
  const secretVal = $('certSecret').value;
  // Non-ZK: the server encrypts the secret it's handed. ZK: the create call can't
  // take a plaintext secret, so attach it separately as ciphertext after create.
  if (secretsEnabled && secretVal && !zkEnabled) body.secret = secretVal;
  if (zkEnabled && secretVal && !ZK.isUnlocked()) { showVaultUnlock(); toast('Unlock the vault first', true); return; }
  const res = await api('POST', '/api/v1/certs', body);
  if (res.status === 201) {
    if (zkEnabled && secretVal) {
      const created = await res.json().catch(() => ({}));
      if (created.id) await api('PUT', `/api/v1/certs/${created.id}/secret`, await secretBody(secretVal));
    }
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

// ===== Optional insight cards (all derive from currentItems + a little extra) =====
let dashChannels = [];
let schedStatus = null;

async function loadDashExtras() {
  try { dashChannels = await (await api('GET', '/api/v1/channels')).json(); } catch (e) { dashChannels = []; }
  try { schedStatus = await (await api('GET', '/api/v1/scan/status')).json(); } catch (e) { schedStatus = null; }
  renderDerivedCards();
}

function renderDerivedCards() {
  renderSoon(); renderProblems(); renderNextUp(); renderIssuers();
  renderAudit(); renderScanHealth(); renderRenewals();
  renderAlertPreview(); renderScheduler();
}

// small formatting helpers
function shortErr(s) { s = (s || '').replace(/\s+/g, ' ').trim(); return s.length > 44 ? s.slice(0, 44) + '…' : s; }

// A pill has to stay short. Go's network errors are long and repeat the host —
// "dial ameriflame.net:443: dial tcp: lookup ameriflame.net: no such host" —
// and a pill that long squeezes the name beside it down to one character per
// line. Reduce the common failures to a few words; the full text stays in the
// title attribute.
function netErrLabel(s) {
  const t = (s || '').toLowerCase();
  if (/no such host|server misbehaving|dns/.test(t)) return 'no DNS';
  if (/connection refused/.test(t)) return 'refused';
  if (/i\/o timeout|deadline exceeded|timed? ?out/.test(t)) return 'timed out';
  if (/connection reset/.test(t)) return 'reset';
  if (/no route to host/.test(t)) return 'no route';
  if (/network is unreachable/.test(t)) return 'unreachable';
  if (/certificate|x509/.test(t)) return 'untrusted';
  const short = (s || '').replace(/\s+/g, ' ').trim();
  return short.length > 22 ? short.slice(0, 22) + '…' : (short || 'failed');
}
// Pull a friendly issuer name (Organization, else Common Name) out of the DN,
// coping with escaped commas inside a value like "O=Cloudflare\, Inc.".
function shortIssuer(dn) {
  const s = (dn || '').trim();
  if (!s) return '—';
  const m = /O=(.*?)(?:,\s*[A-Za-z]+=|$)/i.exec(s) || /CN=(.*?)(?:,\s*[A-Za-z]+=|$)/i.exec(s);
  const v = m ? m[1] : s;
  return v.replace(/\\/g, '').replace(/^"|"$/g, '').trim() || '—';
}
function humanDuration(sec) {
  if (sec % 3600 === 0) return (sec / 3600) + 'h';
  if (sec % 60 === 0) return (sec / 60) + 'm';
  return sec + 's';
}
function relFuture(ms) {
  const s = (ms - Date.now()) / 1000;
  if (s <= 0) return 'due now';
  const h = Math.floor(s / 3600); if (h >= 1) return 'in ' + h + 'h';
  return 'in ' + Math.max(1, Math.floor(s / 60)) + 'm';
}
const isEndpointItem = (it) => it.cert.kind === 'endpoint' || !!it.cert.host;

function renderSoon() {
  const el = $('soonBody'); if (!el) return;
  const items = currentItems.filter((it) => it.days_remaining <= 30).sort((a, b) => a.days_remaining - b.days_remaining);
  if (!items.length) { el.innerHTML = '<p class="empty-ok">✓ Nothing expiring in the next 30 days.</p>'; return; }
  el.innerHTML = items.map((it) => {
    const c = it.cert, lvl = expiryLevel(it.days_remaining);
    return `<div class="mini-row"><span class="mini-name">${escapeHtml(c.name)}</span><span class="muted small mini-date">${fmtDate(c.expires_at)}</span><span class="pill ${lvl}">${fmtRemaining(it.days_remaining)}</span></div>`;
  }).join('');
}

function renderProblems() {
  const el = $('problemsBody'); if (!el) return;
  const rows = [];

  // A failed scan or a failed registry lookup.
  for (const it of currentItems) {
    const c = it.cert;
    if (!c.last_error) continue;
    rows.push({ name: c.name, sub: c.host ? `${c.host}${c.port ? ':' + c.port : ''}` : '',
      note: netErrLabel(c.last_error), title: c.last_error, cls: 'untrusted' });
  }

  // A covered name that no longer resolves. This is the quiet one: the
  // certificate scans clean, so nothing else notices — but HTTP-01 validation
  // of a dead name fails the renewal for the WHOLE certificate, taking the
  // names that do work down with it.
  for (const it of currentItems) {
    const c = it.cert;
    for (const n of c.coverage || []) {
      if (n.status !== 'unreachable') continue;
      rows.push({ name: n.name, sub: `breaks renewal of ${c.name}`,
        note: netErrLabel(n.detail), title: n.detail || '', cls: 'untrusted' });
    }
  }

  if (!rows.length) { el.innerHTML = '<p class="empty-ok">✓ No trust, scan, or coverage problems.</p>'; return; }
  el.innerHTML = rows.map((r) =>
    `<div class="mini-row"><span class="mini-name">${escapeHtml(r.name)}` +
    (r.sub ? `<br><span class="muted small">${escapeHtml(r.sub)}</span>` : '') +
    `</span><span class="pill ${r.cls}" title="${escapeHtml(r.title)}">${escapeHtml(r.note)}</span></div>`).join('');
}

function renderNextUp() {
  const el = $('nextupBody'); if (!el) return;
  if (!currentItems.length) { el.innerHTML = '<p class="muted">Nothing tracked yet.</p>'; return; }
  const it = [...currentItems].sort((a, b) => a.days_remaining - b.days_remaining)[0];
  const lvl = expiryLevel(it.days_remaining);
  el.innerHTML = `<div class="nextup"><div class="nextup-num ${lvl}">${fmtRemaining(it.days_remaining)}</div><div class="nextup-name">${escapeHtml(it.cert.name)}</div><div class="muted small">${fmtDate(it.cert.expires_at)}</div></div>`;
}

function renderIssuers() {
  const el = $('issuersBody'); if (!el) return;
  const map = {};
  for (const it of currentItems) { const iss = shortIssuer(it.cert.issuer); map[iss] = (map[iss] || 0) + 1; }
  const rows = Object.entries(map).sort((a, b) => b[1] - a[1]);
  if (!rows.length) { el.innerHTML = '<p class="muted">Nothing tracked yet.</p>'; return; }
  const max = rows[0][1];
  el.innerHTML = rows.map(([iss, n]) =>
    `<div class="kv"><span class="kv-label" title="${escapeHtml(iss)}">${escapeHtml(iss)}</span><span class="kv-bar"><span style="width:${Math.round(n / max * 100)}%"></span></span><span class="kv-num">${n}</span></div>`).join('');
}

function renderAudit() {
  const el = $('auditBody'); if (!el) return;
  const issues = [];
  for (const it of currentItems) {
    const c = it.cert, probs = [];
    // Domain registrations are not certificates. Every one of these checks is
    // a TLS notion — the 398-day cap is a CA/Browser Forum rule — so auditing a
    // domain registered for a decade flagged it as "long validity (9131d)".
    if (c.kind === 'domain') continue;
    const m = /RSA[- ]?(\d+)/i.exec(c.key_type || '');
    if (m && +m[1] < 2048) probs.push('weak key (' + escapeHtml(c.key_type) + ')');
    if (/sha1|md5/i.test(c.signature_algorithm || '')) probs.push('weak signature');
    // Only real (scanned/parsed) certs have a not_before; manual entries serialize
    // the zero date (0001-01-01), which would look absurdly long — skip those.
    if (c.not_before && c.expires_at && new Date(c.not_before).getUTCFullYear() > 2000) {
      const days = (new Date(c.expires_at) - new Date(c.not_before)) / 86400000;
      if (days > 398) probs.push('long validity (' + Math.round(days) + 'd)');
    }
    if (probs.length) issues.push({ name: c.name, probs });
  }
  if (!issues.length) { el.innerHTML = '<p class="empty-ok">✓ No weak keys, signatures, or over-long certs.</p>'; return; }
  el.innerHTML = issues.map((i) =>
    `<div class="mini-row"><span class="mini-name">${escapeHtml(i.name)}</span><span class="audit-flags">${i.probs.map((p) => `<span class="pill warn">${p}</span>`).join('')}</span></div>`).join('');
}

function renderScanHealth() {
  const el = $('scanhealthBody'); if (!el) return;
  const eps = currentItems.filter(isEndpointItem);
  if (!eps.length) { el.innerHTML = '<p class="muted">No live endpoints tracked.</p>'; return; }
  const staleMs = (schedStatus && schedStatus.interval_seconds ? schedStatus.interval_seconds * 2500 : 24 * 3600 * 1000);
  const bad = [];
  for (const it of eps) {
    const c = it.cert;
    if (c.last_error) bad.push({ c, cls: 'untrusted', note: shortErr(c.last_error) });
    else if (!c.last_scanned_at) bad.push({ c, cls: 'notice', note: 'never checked' });
    else if (Date.now() - new Date(c.last_scanned_at) > staleMs) bad.push({ c, cls: 'notice', note: 'checked ' + relTime(c.last_scanned_at) });
  }
  if (!bad.length) { el.innerHTML = `<p class="empty-ok">✓ All ${eps.length} endpoints healthy.</p>`; return; }
  el.innerHTML = bad.map((b) =>
    `<div class="mini-row"><span class="mini-name">${escapeHtml(b.c.name)}<br><span class="muted small">${escapeHtml(b.c.host)}:${b.c.port}</span></span><span class="pill ${b.cls}">${escapeHtml(b.note)}</span></div>`).join('');
}

function renderRenewals() {
  const el = $('renewalsBody'); if (!el) return;
  const recent = currentItems.filter((it) => {
    const nb = it.cert.not_before; if (!nb) return false;
    const age = Date.now() - new Date(nb);
    return age >= 0 && age <= 14 * 86400000;
  }).sort((a, b) => new Date(b.cert.not_before) - new Date(a.cert.not_before));
  if (!recent.length) { el.innerHTML = '<p class="muted">No certificates issued in the last 14 days.</p>'; return; }
  el.innerHTML = recent.map((it) => {
    const c = it.cert;
    return `<div class="mini-row"><span class="mini-name">${escapeHtml(c.name)}</span><span class="muted small mini-date">exp ${fmtDate(c.expires_at)}</span><span class="pill ok">issued ${escapeHtml(relTime(c.not_before))}</span></div>`;
  }).join('');
}

function channelWantsThreshold(ch, t) {
  const s = (ch.thresholds || '').trim();
  if (!s) return true;
  return s.split(',').map((x) => parseInt(x.trim(), 10)).includes(t);
}
function renderAlertPreview() {
  const el = $('alertsBody'); if (!el) return;
  if (!dashChannels.length) { el.innerHTML = '<p class="muted">No alert channels yet — add one in <a href="/settings">Settings</a>.</p>'; return; }
  const THR = [30, 7, 3], WINDOW = 14, upcoming = [];
  for (const it of currentItems) {
    const D = it.days_remaining; if (D <= 0) continue;
    const t = THR.find((x) => x < D); if (t === undefined) continue;
    const inDays = D - t; if (inDays < 0 || inDays > WINDOW) continue;
    const chans = [...new Set(dashChannels.filter((ch) => channelWantsThreshold(ch, t)).map((ch) => ch.type))];
    if (!chans.length) continue;
    upcoming.push({ name: it.cert.name, inDays, t, chans });
  }
  upcoming.sort((a, b) => a.inDays - b.inDays);
  if (!upcoming.length) { el.innerHTML = `<p class="empty-ok">✓ No alerts due in the next ${WINDOW} days.</p>`; return; }
  el.innerHTML = upcoming.map((u) =>
    `<div class="mini-row"><span class="mini-name">${escapeHtml(u.name)}<br><span class="muted small">${u.t}-day alert → ${escapeHtml(u.chans.join(', '))}</span></span><span class="pill ${u.inDays <= 1 ? 'urgent' : 'notice'}">${u.inDays === 0 ? 'today' : 'in ' + u.inDays + 'd'}</span></div>`).join('');
}

function renderScheduler() {
  const el = $('schedulerBody'); if (!el) return;
  const times = currentItems.filter((it) => it.cert.last_scanned_at).map((it) => new Date(it.cert.last_scanned_at).getTime());
  const last = times.length ? Math.max(...times) : 0;
  const enabled = schedStatus && schedStatus.enabled;
  const intS = schedStatus && schedStatus.interval_seconds;
  let html = `<div class="kv2"><span class="muted">Auto-scan</span><span>${enabled ? `<span class="pill ok">on</span> · every ${humanDuration(intS)}` : '<span class="pill untrusted">off</span>'}</span></div>`;
  html += `<div class="kv2"><span class="muted">Last scan</span><span>${last ? escapeHtml(relTime(new Date(last).toISOString())) : 'never'}</span></div>`;
  if (enabled && last && intS) html += `<div class="kv2"><span class="muted">Next scan</span><span>${escapeHtml(relFuture(last + intS * 1000))}</span></div>`;
  if (isAdmin) html += `<button class="btn primary small" id="scanAllBtn">Scan all now</button>`;
  el.innerHTML = html;
  const b = $('scanAllBtn'); if (b) b.addEventListener('click', scanAll);
}
async function scanAll() {
  const b = $('scanAllBtn'); if (b) { b.disabled = true; b.textContent = 'Scanning…'; }
  const res = await api('POST', '/api/v1/scan/all');
  const d = await res.json().catch(() => ({}));
  if (res.ok) toast(`Scanned ${d.scanned}/${d.total}${d.errors ? `, ${d.errors} failed` : ''} ✓`);
  else toast(d.error || 'Scan failed', true);
  loadCerts();
}

function initNotes() {
  const t = $('notesInput'); if (!t) return;
  try { t.value = localStorage.getItem('certguard-notes') || ''; } catch (e) {}
  let timer = null;
  t.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => { try { localStorage.setItem('certguard-notes', t.value); } catch (e) {} }, 400);
  });
}

// initial load
loadWhoami().then(() => {
  // Viewers don't get the scan / add-entry widgets at all.
  if (!isAdmin) {
    document.querySelectorAll('#dashGrid .widget[data-admin]').forEach((w) => w.remove());
  }
  initWidgetGrid($('dashGrid'), 'certguard-dash-layout', {
    addButton: $('addSectionDash'),
    addDialog: $('addSectionDialog'),
    addGrid: $('addSectionGrid'),
    resetBtn: $('resetDashLayout'),
    centerToggle: $('centerDashLayout'),
    compactToggle: $('compactDashLayout'),
    // Shipped default arrangement: Add + Tracked side by side, Calendar
    // full-width below. Neither of the top two carries a stored height any
    // more — Add-entry is data-autoheight (sizes to its content) and Tracked
    // is data-matchheight="w-add" (follows it), so the pair stays level.
    defaults: {
      order: ['w-add', 'w-tracked', 'w-calendar'],
      spans: { 'w-add': 2, 'w-tracked': 2, 'w-calendar': 4 },
      heights: {},
      // The optional insight cards ship hidden — add them via "＋ Add section".
      hidden: ['w-soon', 'w-problems', 'w-nextup', 'w-issuers', 'w-audit',
        'w-scanhealth', 'w-renewals', 'w-alerts', 'w-scheduler', 'w-notes'],
    },
  });
  if (secretsEnabled && $('secretField')) $('secretField').hidden = false;
  // Don't open the prompt on load — the button shows the state, and clicking it
  // is what asks for the passphrase.
  syncVaultUi();
  renderLegend();
  initNotes();
  loadDashExtras();
  loadCerts();
}).catch(() => {});
