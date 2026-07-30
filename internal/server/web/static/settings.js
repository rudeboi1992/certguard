// Settings page: notification channels (any user manages their own) and user
// management (admin only). Shared helpers come from common.js.

// --- notification channels ---
async function loadChannels() {
  const res = await api('GET', '/api/v1/channels');
  const chans = await res.json();
  const rows = $('channelRows');
  rows.innerHTML = '';
  for (const c of chans) {
    const th = c.thresholds && c.thresholds.trim() ? c.thresholds : '30,7,3';
    const row = document.createElement('div');
    row.className = 'set-row';
    row.innerHTML = `
      <span class="pill notice set-tag">${escapeHtml(c.type)}</span>
      <span class="set-target mono" title="${escapeHtml(c.target)}">${escapeHtml(c.target)}</span>
      <span class="set-meta muted small" title="Alert thresholds (days)">${escapeHtml(th)}</span>
      <span class="set-actions">
        <button class="btn ghost small" data-test="${c.id}">Test</button>
        <button class="btn link" data-delch="${c.id}">Remove</button>
      </span>`;
    rows.appendChild(row);
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

// --- users (admin) ---
async function loadUsers() {
  if (!isAdmin) return;
  const res = await api('GET', '/api/v1/users');
  const users = await res.json();
  const rows = $('userRows');
  rows.innerHTML = '';
  for (const u of users) {
    const isSelf = u.id === currentUserId;
    const row = document.createElement('div');
    row.className = 'set-row';
    row.innerHTML = `
      <span class="set-target" title="${escapeHtml(u.email)}">${escapeHtml(u.email)}${isSelf ? ' <span class="muted small">(you)</span>' : ''}</span>
      <span class="pill ${u.role === 'admin' ? 'notice' : 'ok'} set-tag">${escapeHtml(u.role)}</span>
      <span class="set-meta set-date muted small">joined ${fmtDate(u.created_at)}</span>
      <span class="set-actions">${isSelf ? '' : `<button class="btn link" data-deluser="${u.id}">Remove</button>`}</span>`;
    rows.appendChild(row);
  }
  rows.querySelectorAll('[data-deluser]').forEach((b) =>
    b.addEventListener('click', () => deleteUser(b.dataset.deluser)));
}

$('userForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const body = {
    email: $('uEmail').value.trim(),
    password: $('uPassword').value,
    role: $('uRole').value,
  };
  const res = await api('POST', '/api/v1/users', body);
  if (res.status === 201) {
    toast('User added');
    e.target.reset();
    loadUsers();
  } else {
    const d = await res.json().catch(() => ({}));
    toast(d.error || 'Could not add user', true);
  }
});

async function deleteUser(id) {
  const res = await api('DELETE', `/api/v1/users/${id}`);
  if (res.status === 204) { toast('User removed'); loadUsers(); }
  else { const d = await res.json().catch(() => ({})); toast(d.error || 'Remove failed', true); }
}

// --- backup / recovery (admin) ---
async function downloadBackup(path, filename) {
  const res = await api('GET', path);
  if (!res.ok) { const d = await res.json().catch(() => ({})); toast(d.error || 'Download failed', true); return; }
  const blob = await res.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast('Downloaded ✓');
}
if ($('dlKey')) $('dlKey').addEventListener('click', () => downloadBackup('/api/v1/backup/key', 'certguard.key'));
if ($('dlDb')) $('dlDb').addEventListener('click', () => downloadBackup('/api/v1/backup/db', 'certguard-backup.db'));

// Sidebar links → smooth-scroll the section to the top.
document.querySelectorAll('#settingsNav a').forEach((a) => {
  a.addEventListener('click', (e) => {
    e.preventDefault();
    const el = document.getElementById(a.dataset.nav);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
});

// Draggable / resizable / hideable widget grid (shared module).
initWidgetGrid($('settingsGrid'), 'certguard-settings-layout', {
  addSelect: $('addSectionSettings'),
  resetBtn: $('resetLayout'),
  defaults: {
    order: ['notifyCard', 'usersCard', 'backupCard'],
    spans: { notifyCard: 2, usersCard: 2, backupCard: 2 },
  },
});

// initial load
loadWhoami().then(() => {
  $('usersCard').hidden = !isAdmin;
  if ($('navUsers')) $('navUsers').hidden = !isAdmin;
  // Backup is admin-only; the key download only makes sense with the vault on.
  if ($('backupCard')) $('backupCard').hidden = !isAdmin;
  if ($('navBackup')) $('navBackup').hidden = !isAdmin;
  if ($('dlKey')) $('dlKey').disabled = !secretsEnabled;
  if (!secretsEnabled && $('backupNote')) $('backupNote').textContent = 'The secret vault is off (no master key), so there is no key to back up — just the database.';
  loadChannels();
  loadUsers();
}).catch(() => {});
