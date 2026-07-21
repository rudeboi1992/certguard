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

function urgency(days, trusted) {
  if (!trusted) return 'untrusted';
  if (days < 0 || days <= 3) return 'urgent';
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

let isAdmin = false;

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
  const items = await res.json();
  const rows = $('certRows');
  rows.innerHTML = '';

  let urgent = 0, soon = 0;
  for (const it of items) {
    const c = it.cert;
    const days = it.days_remaining;
    const trusted = !c.last_error;
    const level = urgency(days, trusted);
    if (level === 'urgent') urgent++;
    else if (level === 'warn' || level === 'notice') soon++;

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${escapeHtml(c.name)}</strong>${c.host ? `<br><span class="muted small">${escapeHtml(c.host)}:${c.port}</span>` : ''}</td>
      <td><span class="muted small">${c.kind}</span></td>
      <td>${fmtDate(c.expires_at)}</td>
      <td><span class="pill ${level}">${fmtRemaining(days)}</span></td>
      <td>${trusted ? '<span class="pill ok">ok</span>' : `<span class="pill untrusted" title="${escapeHtml(c.last_error)}">untrusted</span>`}</td>
      <td>${isAdmin ? `<button class="btn link" data-del="${c.id}">Delete</button>` : ''}</td>`;
    rows.appendChild(tr);
  }
  $('empty').hidden = items.length !== 0;

  renderSummary(items.length, soon, urgent);

  rows.querySelectorAll('[data-del]').forEach((b) =>
    b.addEventListener('click', () => deleteCert(b.dataset.del)));
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
  const status = $('scanStatus');
  status.hidden = false;
  status.className = 'status';
  status.textContent = `Scanning ${target}…`;
  try {
    const res = await api('POST', '/api/v1/scan', { target });
    const data = await res.json();
    if (res.ok) {
      status.className = 'status ok';
      status.textContent = `Saved: expires ${fmtDate(data.scan.not_after)}${data.scan.trust_error ? ' (untrusted)' : ''}`;
      $('scanTarget').value = '';
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
    expires_at: $('certExpiry').value, // YYYY-MM-DD
    subject: $('certSubject').value,
    issuer: $('certIssuer').value,
    sha256: $('certSha256').value,
  };
  const res = await api('POST', '/api/v1/certs', body);
  if (res.status === 201) {
    toast('Certificate added');
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
    dz.classList.add('parsed');
    toast(`Parsed ${meta.name} — review and click Add`);
  } catch (err) {
    toast(err.message || 'Could not parse certificate', true);
  }
}

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
loadWhoami().then(loadCerts).catch(() => {});
