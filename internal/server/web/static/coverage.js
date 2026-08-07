// Coverage: every covered name across every certificate, and what each one
// actually serves.
//
// The data already existed — the scheduler refreshes it and the inventory shows
// it per entry — but only one certificate at a time. The failure it exists to
// catch is a single dead SAN taking a renewal down with it, and finding that
// meant expanding rows one by one. Here every name is on one page, worst first.

let items = [];
const state = { q: '', status: 'all' };
const busy = new Set(); // cert ids with a check in flight

// Verdicts, in the order they matter. "unchecked" is ours, not the server's:
// a certificate with several names and no coverage record has never been
// looked at, which is worth saying rather than showing as a clean sheet.
const TILES = [
  ['all', 'Names', ''],
  ['unreachable', 'Unreachable', 'untrusted'],
  ['different', 'Different cert', 'notice'],
  ['match', 'Matching', 'ok'],
  ['wildcard', 'Wildcard', ''],
  ['unchecked', 'Not checked', ''],
];
const VERDICT_CLASS = {
  match: 'ok', different: 'notice', unreachable: 'untrusted', wildcard: '', unchecked: '',
};
const VERDICT_WHY = {
  match: 'serves this exact certificate',
  different: 'resolves, but serves a different certificate — normal with SNI, worth knowing',
  unreachable: 'does not resolve or refuses connections — this will fail the next renewal',
  wildcard: 'not a hostname, so there is nothing to connect to',
  unchecked: 'no coverage check has run for this certificate yet',
};

// Only certificates can have covered names; a domain registration has
// nameservers in the same field, which are not SANs and must not be treated
// as coverage.
const isCertLike = (c) => c.kind !== 'domain';

// Flatten to one row per (certificate, name).
function rows() {
  const out = [];
  for (const it of items) {
    const c = it.cert;
    if (!isCertLike(c)) continue;
    const names = c.dns_names || [];
    if (!names.length) continue;
    const cov = c.coverage || [];
    if (!cov.length) {
      for (const n of names) {
        out.push({ cert: c, item: it, name: n, status: 'unchecked', detail: '' });
      }
      continue;
    }
    for (const n of cov) {
      out.push({ cert: c, item: it, name: n.name, status: n.status, detail: n.detail || '', subject: n.subject, sha256: n.sha256 });
    }
  }
  return out;
}

function visible(all) {
  const q = state.q.trim().toLowerCase();
  return all.filter((r) => {
    if (state.status !== 'all' && r.status !== state.status) return false;
    if (!q) return true;
    return r.name.toLowerCase().includes(q) || (r.cert.name || '').toLowerCase().includes(q)
      || (r.subject || '').toLowerCase().includes(q);
  });
}

function renderTiles(all) {
  const counts = { all: all.length };
  for (const [k] of TILES) if (k !== 'all') counts[k] = 0;
  for (const r of all) counts[r.status] = (counts[r.status] || 0) + 1;
  $('covTiles').innerHTML = TILES.map(([key, label, cls]) => {
    const on = state.status === key;
    const zero = !counts[key] && key !== 'all';
    return `<button type="button" class="inv-tile${on ? ' on' : ''}${zero ? ' zero' : ''}" data-status="${key}"
      aria-pressed="${on}"><span class="inv-tile-n ${cls}">${counts[key] || 0}</span>
      <span class="inv-tile-l">${escapeHtml(label)}</span></button>`;
  }).join('');
  $('covTiles').querySelectorAll('[data-status]').forEach((b) =>
    b.addEventListener('click', () => {
      state.status = state.status === b.dataset.status ? 'all' : b.dataset.status;
      render();
    }));
}

function render() {
  const all = rows();
  renderTiles(all);
  const shown = visible(all);

  // Grouped by certificate, because "which certificate does this break" is the
  // question a bare list of names cannot answer.
  const groups = new Map();
  for (const r of shown) {
    if (!groups.has(r.cert.id)) groups.set(r.cert.id, { cert: r.cert, item: r.item, names: [] });
    groups.get(r.cert.id).names.push(r);
  }
  // Worst first: a certificate with an unreachable name outranks one without.
  const rank = { unreachable: 0, unchecked: 1, different: 2, wildcard: 3, match: 4 };
  const ordered = [...groups.values()].sort((a, b) => {
    const wa = Math.min(...a.names.map((n) => rank[n.status] ?? 9));
    const wb = Math.min(...b.names.map((n) => rank[n.status] ?? 9));
    return wa - wb || (a.cert.name || '').localeCompare(b.cert.name || '');
  });

  $('covList').innerHTML = ordered.map((g) => {
    const c = g.cert;
    const broken = g.names.filter((n) => n.status === 'unreachable').length;
    const checked = c.coverage_at
      ? `checked ${escapeHtml(relTime(c.coverage_at))}`
      : 'never checked';
    return `<section class="card cov-card${broken ? ' broken' : ''}">
      <div class="cov-head">
        <span class="cov-cert">
          <strong>${escapeHtml(c.name)}</strong>
          <span class="muted small">${escapeHtml(c.host || '')}${c.port ? ':' + c.port : ''} · ${g.names.length} name${g.names.length === 1 ? '' : 's'} · ${checked}</span>
        </span>
        ${broken ? `<span class="pill untrusted">${broken} unreachable</span>` : ''}
        <span class="pill ${expiryLevel(g.item.days_remaining)}">${fmtRemaining(g.item.days_remaining)}</span>
        ${isAdmin ? `<button type="button" class="btn ghost small" data-check="${c.id}"${busy.has(c.id) ? ' disabled' : ''}>${busy.has(c.id) ? '↻ checking…' : '↻ Check'}</button>` : ''}
      </div>
      <div class="cov-names">
        ${g.names.map((n) => `<div class="cov-row">
          <span class="mono small cov-name">${escapeHtml(n.name)}</span>
          <span class="pill ${VERDICT_CLASS[n.status] || ''}" title="${escapeHtml(VERDICT_WHY[n.status] || '')}">${escapeHtml(n.status)}</span>
          <span class="muted small cov-why">${escapeHtml(n.detail || n.subject || VERDICT_WHY[n.status] || '')}</span>
        </div>`).join('')}
      </div>
    </section>`;
  }).join('');

  $('covList').querySelectorAll('[data-check]').forEach((b) =>
    b.addEventListener('click', async () => {
      const ok = await checkOne(b.dataset.check);
      // Re-read either way: on success to show the new verdicts, on failure to
      // clear the "checking…" state the button is stuck in.
      await load();
      if (ok) toast('Coverage updated ✓');
    }));

  const filtered = state.q || state.status !== 'all';
  $('covReset').hidden = !filtered;
  $('covSearchClear').hidden = !state.q;
  $('covCheckAll').hidden = !isAdmin || !items.length;
  const empty = $('covEmpty');
  if (!all.length) {
    empty.hidden = false;
    empty.textContent = 'No certificate here covers more than its own hostname, so there is nothing to check.';
  } else if (!shown.length) {
    empty.hidden = false;
    empty.textContent = 'No covered names match these filters.';
  } else {
    empty.hidden = true;
  }
}

async function checkOne(id, quiet) {
  const n = Number(id);
  busy.add(n);
  render();
  try {
    const res = await api('POST', `/api/v1/certs/${id}/coverage`);
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      if (!quiet) toast(d.error || 'Coverage check failed', true);
      return false;
    }
    return true;
  } finally {
    busy.delete(n);
  }
}

// Sequential on purpose: each check opens a TLS connection per covered name,
// and firing every certificate at once would be a burst of hundreds of
// handshakes at whatever is on the other end.
async function checkAll() {
  const withNames = items.filter((it) => isCertLike(it.cert) && (it.cert.dns_names || []).length > 1);
  if (!withNames.length) { toast('Nothing to check'); return; }
  const btn = $('covCheckAll');
  btn.disabled = true;
  let done = 0, failed = 0;
  for (const it of withNames) {
    btn.textContent = `↻ checking ${done + 1}/${withNames.length}…`;
    if (!(await checkOne(it.cert.id, true))) failed++;
    done++;
  }
  btn.disabled = false;
  btn.textContent = '↻ Check all';
  await load();
  toast(failed ? `Checked ${done}, ${failed} failed` : `Checked ${done} certificate${done === 1 ? '' : 's'} ✓`, failed > 0);
}

$('covSearch').addEventListener('input', (e) => { state.q = e.target.value; render(); });
$('covSearchClear').addEventListener('click', () => {
  state.q = ''; $('covSearch').value = ''; $('covSearch').focus(); render();
});
$('covReset').addEventListener('click', () => {
  state.q = ''; state.status = 'all'; $('covSearch').value = ''; render();
});
$('covCheckAll').addEventListener('click', checkAll);

async function load() {
  const res = await api('GET', '/api/v1/certs');
  items = await res.json();
  render();
}

setVaultRefresh(() => load());

(async () => {
  await loadWhoami();
  syncVaultUi();
  await load();
  // Deep link, e.g. /coverage?status=unreachable from the dashboard.
  const want = new URLSearchParams(location.search).get('status');
  if (want && TILES.some(([k]) => k === want)) { state.status = want; render(); }
})().catch((e) => toast(e.message || 'Failed to load coverage', true));
