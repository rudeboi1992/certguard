// Activity: the log of what changed, newest first.
//
// This is the one page whose data does not come from /certs — it reads the
// events table, which is written by the API handlers (who did what) and the
// scheduler (what the checks found). It is also the only view that survives a
// deletion: the log denormalises the entry's name precisely so that "who
// removed this, and when" still has an answer afterwards.

let events = [];
const state = { q: '', kind: '' };

// [kind, label, pill class, icon]. The wording is what the line reads as, not
// the constant — "scan_failed" is a database value, "Check failed" is English.
const KINDS = [
  ['', 'Everything', '', '•'],
  ['added', 'Added', 'ok', '＋'],
  ['updated', 'Edited', 'cat', '✎'],
  ['deleted', 'Removed', 'urgent', '×'],
  ['renewed', 'Renewed', 'ok', '↻'],
  ['scan_failed', 'Check failed', 'untrusted', '!'],
  ['scan_recovered', 'Recovered', 'ok', '✓'],
  ['coverage_broken', 'Coverage broke', 'untrusted', '⚠'],
  ['chain_expiring', 'Chain expiring', 'untrusted', '⛓'],
  ['key_added', 'Key registered', 'ok', '🔐'],
  ['key_removed', 'Key removed', 'urgent', '🔓'],
  ['key_clone_warning', 'Key warning', 'urgent', '⚠'],
  ['notified', 'Alerted', 'notice', '✉'],
];
const meta = (k) => KINDS.find((x) => x[0] === k) || [k, k, '', '•'];

function visible() {
  const q = state.q.trim().toLowerCase();
  return events.filter((e) => {
    if (state.kind && e.kind !== state.kind) return false;
    if (!q) return true;
    return [e.cert_name, e.actor, e.detail, meta(e.kind)[1]]
      .some((f) => (f || '').toLowerCase().includes(q));
  });
}

function renderTiles() {
  const counts = { '': events.length };
  for (const e of events) counts[e.kind] = (counts[e.kind] || 0) + 1;
  $('actTiles').innerHTML = KINDS.map(([key, label, cls]) => {
    const on = state.kind === key;
    const zero = !counts[key] && key !== '';
    return `<button type="button" class="inv-tile${on ? ' on' : ''}${zero ? ' zero' : ''}" data-kind="${key}"
      aria-pressed="${on}"><span class="inv-tile-n ${cls}">${counts[key] || 0}</span>
      <span class="inv-tile-l">${escapeHtml(label)}</span></button>`;
  }).join('');
  $('actTiles').querySelectorAll('[data-kind]').forEach((b) =>
    b.addEventListener('click', () => {
      state.kind = state.kind === b.dataset.kind ? '' : b.dataset.kind;
      render();
    }));
}

// Group by calendar day so the feed reads as a diary rather than an
// undifferentiated stream of timestamps.
function dayLabel(iso) {
  const d = new Date(iso);
  const today = new Date();
  const key = (x) => x.toISOString().slice(0, 10);
  if (key(d) === key(today)) return 'Today';
  const y = new Date(today.getTime() - 86400000);
  if (key(d) === key(y)) return 'Yesterday';
  return key(d);
}

function render() {
  renderTiles();
  const shown = visible();
  const feed = $('actFeed');
  let html = '';
  let lastDay = null;
  for (const e of shown) {
    const day = dayLabel(e.at);
    if (day !== lastDay) {
      html += `<li class="act-day"><span>${escapeHtml(day)}</span></li>`;
      lastDay = day;
    }
    const [, label, cls, icon] = meta(e.kind);
    const time = new Date(e.at);
    const hhmm = String(time.getHours()).padStart(2, '0') + ':' + String(time.getMinutes()).padStart(2, '0');
    html += `<li class="act-row">
      <span class="act-icon ${cls}" aria-hidden="true">${icon}</span>
      <span class="act-body">
        <span class="act-line">
          <span class="pill ${cls}">${escapeHtml(label)}</span>
          ${e.cert_name ? `<strong>${escapeHtml(e.cert_name)}</strong>` : '<span class="muted">(entry removed)</span>'}
        </span>
        ${e.detail ? `<span class="act-detail muted small">${escapeHtml(e.detail)}</span>` : ''}
        <span class="act-meta muted small">${escapeHtml(hhmm)} · ${escapeHtml(relTime(e.at))}${
          e.actor ? ' · ' + escapeHtml(e.actor) : ' · scheduler'}</span>
      </span>
    </li>`;
  }
  feed.innerHTML = html;

  const filtered = state.q || state.kind;
  $('actReset').hidden = !filtered;
  $('actSearchClear').hidden = !state.q;
  const empty = $('actEmpty');
  if (!events.length) {
    empty.hidden = false;
    empty.textContent = 'Nothing has been recorded yet. Add, edit or remove an entry — or wait for a check to find something — and it will show up here.';
  } else if (!shown.length) {
    empty.hidden = false;
    empty.textContent = 'No activity matches these filters.';
  } else {
    empty.hidden = true;
  }
  $('actCount').textContent = shown.length === events.length
    ? `${events.length} event${events.length === 1 ? '' : 's'}`
    : `${shown.length} of ${events.length} shown`;
}

$('actSearch').addEventListener('input', (e) => { state.q = e.target.value; render(); });
$('actSearchClear').addEventListener('click', () => {
  state.q = ''; $('actSearch').value = ''; $('actSearch').focus(); render();
});
$('actReset').addEventListener('click', () => {
  state.q = ''; state.kind = ''; $('actSearch').value = ''; render();
});
$('actRefresh').addEventListener('click', () => load().then(() => toast('Reloaded')));

async function load() {
  // Filtering happens client-side so the tiles can show real counts; the
  // server limit is the only cap.
  const res = await api('GET', '/api/v1/events?limit=500');
  events = await res.json();
  render();
}

setVaultRefresh(() => load());

(async () => {
  await loadWhoami();
  syncVaultUi();
  await load();
})().catch((e) => toast(e.message || 'Failed to load activity', true));
