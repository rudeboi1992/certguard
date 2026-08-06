// Inventory: one table holding every tracked entry, whatever its kind.
//
// The dashboard's tracked list answers "what needs attention soon" — it lives
// in a card, pages 12 rows at a time, and sorts by expiry. This page answers
// the other question: "what do we have?" Everything is present at once, every
// column is sortable, and the filters compose, so it can be read as an
// inventory rather than a worklist.
//
// Shared helpers ($, api, toast, escapeHtml, fmtDate, relTime, CATEGORIES,
// categoryLabel, categoryColor, hexA, expiryLevel, fmtRemaining, isAdmin,
// loadWhoami, theme, sign-out) come from common.js, loaded first.

let allItems = [];
const expanded = new Set(); // ids whose detail row is open, kept across renders

// --- classification -------------------------------------------------------

// expiryLevel() folds expired into "urgent" because a pill only has so many
// colours and both mean "act now". An inventory wants them apart: "3 expired"
// and "3 expiring this week" call for completely different work, and a count
// that merges them hides the worse one. Buckets are exclusive, so the tiles
// sum to the total.
function bucket(days) {
  if (days < 0) return 'expired';
  if (days <= 3) return 'urgent';
  if (days <= 7) return 'warn';
  if (days <= 30) return 'notice';
  return 'ok';
}

// Same definition the dashboard's Problems card uses: a failed scan or registry
// lookup, or a covered name that no longer resolves. The second one is the
// quiet failure — the certificate itself scans clean, but HTTP-01 validation of
// a dead SAN fails the renewal for the whole certificate.
function problemsOf(c) {
  const out = [];
  if (c.last_error) out.push({ what: c.name, why: c.last_error });
  for (const n of c.coverage || []) {
    if (n.status === 'unreachable') out.push({ what: n.name, why: n.detail || 'unreachable' });
  }
  return out;
}
const hasProblem = (c) => problemsOf(c).length > 0;

// What this entry points at. Domains are stored on port 0 so a cert and a
// registration for the same name can coexist — showing ":0" would be noise.
function targetOf(c) {
  if (c.kind === 'domain') return c.host || '';
  if (c.host) return c.port ? `${c.host}:${c.port}` : c.host;
  return '';
}

const KIND_LABEL = { endpoint: 'Endpoint', domain: 'Domain', file: 'File', manual: 'Manual' };
const kindLabel = (k) => KIND_LABEL[k] || k || '';

const TILES = [
  ['all', 'Tracked', ''],
  ['expired', 'Expired', 'urgent'],
  ['urgent', '3 days', 'urgent'],
  ['warn', '7 days', 'warn'],
  ['notice', '30 days', 'notice'],
  ['ok', 'Healthy', 'ok'],
  ['problems', 'Problems', 'untrusted'],
];

// --- state ----------------------------------------------------------------

const state = { q: '', category: '', kind: '', status: 'all', secretsOnly: false, sort: 'remaining', dir: 1 };

// Every column sorts ascending on first click, which lands on the useful end
// of all of them: A→Z for the text columns, and worst-first for the rest,
// because in each case the value you care about is the *smallest* one —
// fewest days left, earliest expiry, longest un-checked, problems before ok
// (see the state ordering below). A second click reverses.

function sortValue(it, key) {
  const c = it.cert;
  switch (key) {
    case 'name': return (c.name || '').toLowerCase();
    case 'category': return categoryLabel(c.category).toLowerCase();
    case 'kind': return kindLabel(c.kind).toLowerCase();
    case 'target': return targetOf(c).toLowerCase();
    case 'issuer': return (c.issuer || '').toLowerCase();
    case 'expires': return new Date(c.expires_at).getTime() || 0;
    case 'remaining': return it.days_remaining;
    // Worst state first: broken, then untrusted-by-absence, then fine.
    case 'state': return hasProblem(c) ? 0 : (c.kind === 'endpoint' || c.host ? 1 : 2);
    case 'checked': return c.last_scanned_at ? new Date(c.last_scanned_at).getTime() : 0;
    default: return 0;
  }
}

function visibleItems() {
  const q = state.q.trim().toLowerCase();
  let items = allItems.filter((it) => {
    const c = it.cert;
    if (state.category && c.category !== state.category) return false;
    if (state.kind && c.kind !== state.kind) return false;
    if (state.secretsOnly && !c.has_secret) return false;
    if (state.status === 'problems') { if (!hasProblem(c)) return false; }
    else if (state.status !== 'all' && bucket(it.days_remaining) !== state.status) return false;
    if (!q) return true;
    return [c.name, c.host, c.issuer, c.subject, c.notes, categoryLabel(c.category),
      kindLabel(c.kind), ...(c.dns_names || [])]
      .some((f) => (f || '').toLowerCase().includes(q));
  });
  items.sort((a, b) => {
    const av = sortValue(a, state.sort), bv = sortValue(b, state.sort);
    if (av < bv) return -state.dir;
    if (av > bv) return state.dir;
    // Stable, predictable tiebreak so equal rows don't shuffle between renders.
    return (a.cert.name || '').localeCompare(b.cert.name || '');
  });
  return items;
}

// --- rendering ------------------------------------------------------------

function renderTiles() {
  const counts = { all: allItems.length, expired: 0, urgent: 0, warn: 0, notice: 0, ok: 0, problems: 0 };
  for (const it of allItems) {
    counts[bucket(it.days_remaining)]++;
    if (hasProblem(it.cert)) counts.problems++;
  }
  $('invTiles').innerHTML = TILES.map(([key, label, cls]) => {
    const on = state.status === key;
    const zero = counts[key] === 0 && key !== 'all';
    return `<button type="button" class="inv-tile${on ? ' on' : ''}${zero ? ' zero' : ''}" data-status="${key}"
      aria-pressed="${on}"><span class="inv-tile-n ${cls}">${counts[key]}</span>
      <span class="inv-tile-l">${escapeHtml(label)}</span></button>`;
  }).join('');
  $('invTiles').querySelectorAll('[data-status]').forEach((b) =>
    b.addEventListener('click', () => {
      // Clicking the active tile clears it, so a filter is never a dead end.
      state.status = (state.status === b.dataset.status) ? 'all' : b.dataset.status;
      render();
    }));
}

function stateCell(c) {
  const probs = problemsOf(c);
  if (probs.length) {
    const title = probs.map((p) => `${p.what}: ${p.why}`).join('\n');
    const label = probs.length > 1 ? `${probs.length} problems` : 'problem';
    return `<span class="pill untrusted" title="${escapeHtml(title)}">${label}</span>`;
  }
  // Only endpoints are actually connected to, so only they can report "ok".
  // A manual entry has never been checked; claiming ok would verify nothing.
  if (c.kind === 'endpoint' || c.host) return '<span class="pill ok">ok</span>';
  return '<span class="muted small">—</span>';
}

function buildRow(it) {
  const c = it.cert;
  const days = it.days_remaining;
  const col = categoryColor(c.category);
  const target = targetOf(c);
  const isOpen = expanded.has(c.id);

  const tr = document.createElement('tr');
  tr.className = 'inv-row' + (isOpen ? ' open' : '');
  tr.dataset.id = c.id;
  tr.tabIndex = 0;
  tr.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  tr.innerHTML = `
    <td class="inv-name"><span class="inv-caret" aria-hidden="true"></span><strong>${escapeHtml(c.name)}</strong>${
      c.has_secret && secretsEnabled
        ? ' <span class="inv-key" title="Has a stored secret — expand to reveal">🔑</span>'
        : ''}</td>
    <td class="col-type">${c.category
      ? `<span class="pill" style="background:${hexA(col, 0.15)};color:${col}">${escapeHtml(categoryLabel(c.category))}</span>`
      : '<span class="muted small">—</span>'}</td>
    <td class="col-src muted small">${escapeHtml(kindLabel(c.kind))}</td>
    <td class="col-target mono small">${target ? escapeHtml(target) : '<span class="muted">—</span>'}</td>
    <td class="col-issuer small">${c.issuer ? escapeHtml(c.issuer) : '<span class="muted">—</span>'}</td>
    <td class="inv-exp col-expires">${fmtDate(c.expires_at)}</td>
    <td class="col-rem"><span class="pill ${expiryLevel(days)}">${fmtRemaining(days)}</span></td>
    <td class="col-state">${stateCell(c)}</td>
    <td class="col-checked muted small">${c.last_scanned_at ? escapeHtml(relTime(c.last_scanned_at)) : '—'}</td>`;

  const toggle = () => {
    if (expanded.has(c.id)) expanded.delete(c.id); else expanded.add(c.id);
    render();
  };
  tr.addEventListener('click', (e) => {
    if (e.target.closest('a, button')) return;
    toggle();
  });
  tr.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
  });
  return tr;
}

function detailRow(it) {
  const c = it.cert;
  const kv = [];
  const add = (k, v) => { if (v) kv.push(`<div class="inv-d-k">${escapeHtml(k)}</div><div class="inv-d-v">${v}</div>`); };

  add('Subject', c.subject ? escapeHtml(c.subject) : '');
  add(c.kind === 'domain' ? 'Registrar' : 'Issuer', c.issuer ? escapeHtml(c.issuer) : '');
  add('Serial', c.serial ? `<span class="mono">${escapeHtml(c.serial)}</span>` : '');
  add('SHA-256', c.sha256 ? `<span class="mono inv-sha">${escapeHtml(c.sha256)}</span>` : '');
  add('Key', [c.key_type, c.signature_algorithm].filter(Boolean).map(escapeHtml).join(' · '));
  add('Valid from', c.not_before && !c.not_before.startsWith('0001') ? fmtDate(c.not_before) : '');
  add('Expires', `${fmtDate(c.expires_at)} — ${escapeHtml(fmtRemaining(it.days_remaining))}`);
  add(c.kind === 'domain' ? 'Nameservers' : 'Covered names',
    (c.dns_names || []).length ? (c.dns_names || []).map((n) => `<span class="inv-san">${escapeHtml(n)}</span>`).join(' ') : '');
  add('Added', fmtDate(c.created_at));
  add('Last checked', c.last_scanned_at ? `${fmtDate(c.last_scanned_at)} <span class="muted small">(${escapeHtml(relTime(c.last_scanned_at))})</span>` : '');
  add('Auto rescan', c.kind === 'endpoint' || c.kind === 'domain' ? (c.auto_rescan ? 'on' : 'off') : '');

  // Same .secretline markup the dashboard uses, so revealSecret() in
  // vault-ui.js can swap the value in place without knowing which page it is
  // on. Reveal is admin-only and goes through the vault, which prompts for the
  // passphrase if it is locked.
  if (c.has_secret && secretsEnabled) {
    const rev = isAdmin ? ` · <button class="secret-btn" data-reveal="${c.id}">reveal</button>` : '';
    add('Secret', `<span class="secretline">🔑 ${escapeHtml(c.secret_hint || 'secret set')}${rev}</span>`);
  }

  // Notes are editable in place for admins — the whole point of showing them
  // here is that this is where you are already looking when you think of one.
  // Viewers see the text if there is any, and nothing if there isn't.
  if (isAdmin) {
    add('Notes', `<div class="inv-notes">
      <textarea class="inv-notes-in" data-notes="${c.id}" rows="2"
        placeholder="Add a note…" aria-label="Notes for ${escapeHtml(c.name)}">${escapeHtml(c.notes || '')}</textarea>
      <div class="inv-notes-act">
        <button type="button" class="btn primary small" data-notes-save="${c.id}" disabled>Save</button>
        <span class="muted small" data-notes-state="${c.id}"></span>
      </div></div>`);
  } else {
    add('Notes', c.notes ? escapeHtml(c.notes) : '');
  }
  add('Error', c.last_error ? `<span class="inv-err">${escapeHtml(c.last_error)}</span>` : '');

  // Coverage is the one thing a flat key/value list can't carry: it is a
  // per-name verdict, and "which of these names is broken" is the whole point.
  let cov = '';
  if ((c.coverage || []).length) {
    const rows = c.coverage.map((n) => {
      const cls = n.status === 'match' ? 'ok' : n.status === 'unreachable' ? 'untrusted'
        : n.status === 'different' ? 'notice' : '';
      return `<div class="inv-cov-row"><span class="mono small">${escapeHtml(n.name)}</span>
        <span class="pill ${cls}"${n.detail ? ` title="${escapeHtml(n.detail)}"` : ''}>${escapeHtml(n.status)}</span>
        ${n.subject ? `<span class="muted small">${escapeHtml(n.subject)}</span>` : ''}</div>`;
    }).join('');
    cov = `<div class="inv-cov"><div class="inv-d-k">Coverage${c.coverage_at ? ` <span class="muted small">${escapeHtml(relTime(c.coverage_at))}</span>` : ''}</div>
      <div class="inv-cov-list">${rows}</div></div>`;
  }

  const tr = document.createElement('tr');
  tr.className = 'inv-detail';
  tr.innerHTML = `<td colspan="9"><div class="inv-d-wrap"><div class="inv-d-grid">${kv.join('')}</div>${cov}</div></td>`;

  const reveal = tr.querySelector('[data-reveal]');
  if (reveal) reveal.addEventListener('click', () => revealSecret(reveal.dataset.reveal, reveal));

  const ta = tr.querySelector('[data-notes]');
  if (ta) {
    const save = tr.querySelector('[data-notes-save]');
    const stateEl = tr.querySelector('[data-notes-state]');
    // The baseline lives on the element, not in this closure, so that a save
    // can move it. Held in the closure it would go stale the moment you saved,
    // and reverting to the previous text would leave Save greyed out.
    ta.dataset.orig = c.notes || '';
    ta.addEventListener('input', () => {
      save.disabled = ta.value === ta.dataset.orig;
      stateEl.textContent = '';
    });
    // Ctrl/Cmd+Enter saves without reaching for the mouse.
    ta.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && !save.disabled) {
        e.preventDefault();
        saveNotes(c.id, ta, save, stateEl);
      }
    });
    save.addEventListener('click', () => saveNotes(c.id, ta, save, stateEl));
  }
  return tr;
}

// Save one entry's notes. PATCH replaces name/category/notes together, so the
// current name and category are sent back unchanged — omitting the name is a
// 400, not a partial update.
async function saveNotes(id, ta, btn, stateEl) {
  const it = allItems.find((x) => String(x.cert.id) === String(id));
  if (!it) return;
  const c = it.cert;
  const value = ta.value;
  btn.disabled = true;
  stateEl.textContent = 'Saving…';
  const res = await api('PATCH', `/api/v1/certs/${id}`, {
    name: c.name, category: c.category, notes: value,
  });
  if (!res.ok) {
    const d = await res.json().catch(() => ({}));
    stateEl.textContent = '';
    btn.disabled = false;
    toast(d.error || 'Could not save notes', true);
    return;
  }
  const updated = await res.json().catch(() => null);
  c.notes = updated && typeof updated.notes === 'string' ? updated.notes : value;
  ta.dataset.orig = c.notes;
  stateEl.textContent = 'Saved ✓';
  toast('Notes saved ✓');
  // Deliberately not re-rendering: that would rebuild this textarea and throw
  // away the caret. The row already shows what was saved, and search picks the
  // new text up on the next render.
}

function render() {
  renderTiles();
  const items = visibleItems();
  const body = $('invRows');
  body.innerHTML = '';
  for (const it of items) {
    body.appendChild(buildRow(it));
    if (expanded.has(it.cert.id)) body.appendChild(detailRow(it));
  }

  // Mark the sorted column so the header shows which way the list is ordered.
  document.querySelectorAll('#invHead .th-sort').forEach((th) => {
    const on = th.dataset.sort === state.sort;
    th.classList.toggle('sorted', on);
    th.classList.toggle('desc', on && state.dir === -1);
    th.setAttribute('aria-sort', on ? (state.dir === 1 ? 'ascending' : 'descending') : 'none');
  });

  const filtered = state.q || state.category || state.kind || state.secretsOnly || state.status !== 'all';
  $('invEmpty').hidden = allItems.length !== 0;
  $('invNoMatch').hidden = !(allItems.length !== 0 && items.length === 0);
  $('invTable').hidden = items.length === 0;
  $('invReset').hidden = !filtered;
  $('invSearchClear').hidden = !state.q;
  $('invCount').textContent = items.length === allItems.length
    ? `${items.length} ${items.length === 1 ? 'entry' : 'entries'}`
    : `${items.length} of ${allItems.length} shown`;
}

// --- CSV ------------------------------------------------------------------

// Exports what is on screen, not the whole inventory — the filters are the
// point of the export ("send me everything expiring this month").
function exportCsv() {
  const items = visibleItems();
  if (!items.length) { toast('Nothing to export', true); return; }
  const cell = (v) => {
    const s = v === null || v === undefined ? '' : String(v);
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const head = ['name', 'type', 'source', 'target', 'issuer', 'expires_at', 'days_remaining',
    'state', 'last_scanned_at', 'last_error', 'covered_names'];
  const lines = [head.join(',')];
  for (const it of items) {
    const c = it.cert;
    lines.push([c.name, categoryLabel(c.category), kindLabel(c.kind), targetOf(c), c.issuer,
      fmtDate(c.expires_at), it.days_remaining,
      hasProblem(c) ? 'problem' : (c.kind === 'endpoint' || c.host ? 'ok' : ''),
      c.last_scanned_at ? fmtDate(c.last_scanned_at) : '', c.last_error || '',
      (c.dns_names || []).join(' ')].map(cell).join(','));
  }
  // \r\n so Excel doesn't run the rows together; BOM so it reads UTF-8 names.
  const blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `certguard-inventory-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  toast(`Exported ${items.length} ${items.length === 1 ? 'row' : 'rows'}`);
}

// --- wiring ---------------------------------------------------------------

$('invSearch').addEventListener('input', (e) => { state.q = e.target.value; render(); });
$('invSearchClear').addEventListener('click', () => {
  state.q = ''; $('invSearch').value = ''; $('invSearch').focus(); render();
});
$('invCategory').addEventListener('change', (e) => { state.category = e.target.value; render(); });
$('invKind').addEventListener('change', (e) => { state.kind = e.target.value; render(); });
$('invSecrets').addEventListener('change', (e) => { state.secretsOnly = e.target.checked; render(); });
$('invCsv').addEventListener('click', exportCsv);
$('invReset').addEventListener('click', () => {
  state.q = ''; state.category = ''; state.kind = ''; state.status = 'all'; state.secretsOnly = false;
  $('invSearch').value = ''; $('invCategory').value = ''; $('invKind').value = '';
  $('invSecrets').checked = false;
  render();
});

document.querySelectorAll('#invHead .th-sort').forEach((th) => {
  th.addEventListener('click', () => {
    const key = th.dataset.sort;
    if (state.sort === key) state.dir = -state.dir;
    else { state.sort = key; state.dir = 1; }
    render();
  });
});

// "/" focuses search, Escape clears it — this page is mostly looking things up.
document.addEventListener('keydown', (e) => {
  if (e.key === '/' && !/^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName)) {
    e.preventDefault(); $('invSearch').focus();
  } else if (e.key === 'Escape' && document.activeElement === $('invSearch')) {
    state.q = ''; $('invSearch').value = ''; render();
  }
});

async function load() {
  const res = await api('GET', '/api/v1/certs');
  allItems = await res.json();

  // Only offer types that are actually in use — a filter that can only ever
  // return nothing is noise.
  const used = new Set(allItems.map((it) => it.cert.category).filter(Boolean));
  $('invCategory').innerHTML = '<option value="">All</option>' +
    CATEGORIES.filter(([v]) => used.has(v))
      .map(([v, l]) => `<option value="${v}">${escapeHtml(l)}</option>`).join('');

  // Same rule as the type filter: only offer it when it can match something.
  $('invSecretsWrap').hidden = !(secretsEnabled && allItems.some((it) => it.cert.has_secret));

  const soonest = allItems.filter((it) => it.days_remaining >= 0)
    .reduce((m, it) => (m === null || it.days_remaining < m ? it.days_remaining : m), null);
  $('invSub').textContent = allItems.length === 0
    ? 'Nothing tracked yet.'
    : `${allItems.length} ${allItems.length === 1 ? 'entry' : 'entries'}` +
      (soonest === null ? '' : ` · next expiry in ${soonest} ${soonest === 1 ? 'day' : 'days'}`);
  render();
}

// Locking or unlocking the vault changes which secrets can be revealed, so
// re-read the list when it happens.
setVaultRefresh(() => load());

(async () => {
  await loadWhoami();
  syncVaultUi();
  // Deep link from elsewhere, e.g. /inventory?status=expired.
  const want = new URLSearchParams(location.search).get('status');
  if (want && TILES.some(([k]) => k === want)) state.status = want;
  await load();
})().catch((e) => toast(e.message || 'Failed to load inventory', true));
