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

// --- security: two-factor + vault passphrase ---
function renderTwoFA(enabled) {
  if (!$('twofaOff')) return;
  $('twofaOff').hidden = enabled;
  $('twofaOn').hidden = !enabled;
  $('twofaSetup').hidden = true;
  $('twofaStatus').textContent = enabled
    ? 'Two-factor is ON — a code from your authenticator is required at sign-in.'
    : 'Add a time-based code from an authenticator app as a second factor at sign-in.';
}
if ($('twofaEnableBtn')) $('twofaEnableBtn').addEventListener('click', async () => {
  const res = await api('POST', '/api/v1/2fa/setup');
  const d = await res.json().catch(() => ({}));
  if (!res.ok) { toast(d.error || 'Setup failed', true); return; }
  $('twofaSecret').textContent = 'Key: ' + d.secret;
  $('twofaQR').src = '/api/v1/2fa/qr?t=' + Date.now();
  $('twofaOff').hidden = true;
  $('twofaSetup').hidden = false;
  $('twofaCode').focus();
});
if ($('twofaConfirmBtn')) $('twofaConfirmBtn').addEventListener('click', async () => {
  const res = await api('POST', '/api/v1/2fa/enable', { code: $('twofaCode').value.trim() });
  const d = await res.json().catch(() => ({}));
  if (res.ok) { toast('Two-factor enabled ✓'); renderTwoFA(true); }
  else toast(d.error || 'Could not enable', true);
});
if ($('twofaDisableBtn')) $('twofaDisableBtn').addEventListener('click', async () => {
  const res = await api('POST', '/api/v1/2fa/disable', { code: $('twofaDisableCode').value.trim() });
  const d = await res.json().catch(() => ({}));
  if (res.ok) { toast('Two-factor disabled'); $('twofaDisableCode').value = ''; renderTwoFA(false); }
  else toast(d.error || 'Could not disable', true);
});

// --- zero-knowledge vault controls ---
function renderVaultSec() {
  if (!isAdmin || !secretsEnabled || !$('vaultSec')) return;
  $('vaultSec').hidden = false;
  if (zkEnabled) {
    $('vaultSecStatus').textContent = ZK.isUnlocked()
      ? 'Zero-knowledge is ON and unlocked in this browser.'
      : 'Zero-knowledge is ON. Enter the current and a new passphrase to rotate it.';
    $('vaultCur').hidden = false;
    $('vaultCur').placeholder = 'current passphrase';
    $('vaultEnableBtn').hidden = true;
    $('vaultChangeBtn').hidden = false;
    $('vaultDisableBtn').hidden = false;
  } else {
    $('vaultSecStatus').textContent = 'Off — turn on to encrypt every secret in your browser. The server never sees your passphrase or plaintext.';
    $('vaultCur').hidden = true;
    $('vaultEnableBtn').hidden = false;
    $('vaultChangeBtn').hidden = true;
    $('vaultDisableBtn').hidden = true;
  }
}

// Turn on zero-knowledge: re-encrypt any existing (server-side) secrets in the
// browser under the new passphrase, then hand the server only the keyring +
// ciphertext. The server drops its own key material.
async function enableZK() {
  const pass = $('vaultNew').value;
  if (pass.length < 8) { toast('Passphrase must be at least 8 characters', true); return; }
  if (!confirm('Turn on zero-knowledge encryption?\n\nEveryone who needs the vault will need this passphrase. If it is lost, the stored secrets cannot be recovered.')) return;
  $('vaultEnableBtn').disabled = true;
  try {
    // Pull existing secrets as plaintext (needs the current server vault unlocked).
    const migrated = [];
    const listRes = await api('GET', '/api/v1/certs');
    const list = await listRes.json().catch(() => ([]));
    // Each list item wraps the cert: { cert: {...}, days_remaining }.
    const withSecret = (Array.isArray(list) ? list : []).map((it) => it.cert).filter((c) => c && c.has_secret);
    const plaintexts = [];
    for (const c of withSecret) {
      const r = await api('GET', `/api/v1/certs/${c.id}/secret`);
      if (!r.ok) continue;
      const d = await r.json().catch(() => ({}));
      if (d.value) plaintexts.push({ id: c.id, value: d.value });
    }
    // Create the keyring (sets the browser DEK) then encrypt the plaintexts under it.
    const keyring = await ZK.create(pass);
    for (const p of plaintexts) {
      migrated.push({ id: p.id, enc: await ZK.encrypt(p.value), hint: ZK.hint(p.value) });
    }
    const res = await api('POST', '/api/v1/vault/keyring', { ...keyring, secrets: migrated });
    if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || 'enable failed'); }
    zkEnabled = true;
    $('vaultNew').value = '';
    toast('Zero-knowledge enabled ✓');
    renderVaultSec();
  } catch (e) {
    ZK.lock();
    toast(e.message || 'Could not enable zero-knowledge', true);
  } finally {
    $('vaultEnableBtn').disabled = false;
  }
}

// Rotate the passphrase: unlock with the current one (if needed), re-wrap the
// same data key under the new one, store the new keyring. Secrets are untouched.
async function changeZK() {
  const cur = $('vaultCur').value;
  const next = $('vaultNew').value;
  if (next.length < 8) { toast('New passphrase must be at least 8 characters', true); return; }
  try {
    if (!ZK.isUnlocked()) {
      const kr = await (await api('GET', '/api/v1/vault/keyring')).json();
      await ZK.unlock(cur, kr);
    }
    const keyring = await ZK.rewrap(next);
    const res = await api('POST', '/api/v1/vault/keyring', keyring);
    if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || 'change failed'); }
    $('vaultCur').value = ''; $('vaultNew').value = '';
    toast('Passphrase changed ✓');
    renderVaultSec();
  } catch (e) {
    toast(e.message === 'change failed' ? e.message : 'Current passphrase is incorrect', true);
  }
}

async function disableZK() {
  if (!confirm('Disable zero-knowledge?\n\nAll stored secret values will be permanently wiped (the server cannot read them). Entries themselves are kept.')) return;
  const res = await api('DELETE', '/api/v1/vault/keyring');
  if (!res.ok) { const d = await res.json().catch(() => ({})); toast(d.error || 'Failed', true); return; }
  ZK.lock();
  zkEnabled = false;
  toast('Zero-knowledge disabled — stored secrets wiped');
  renderVaultSec();
}
if ($('vaultEnableBtn')) $('vaultEnableBtn').addEventListener('click', enableZK);
if ($('vaultChangeBtn')) $('vaultChangeBtn').addEventListener('click', changeZK);
if ($('vaultDisableBtn')) $('vaultDisableBtn').addEventListener('click', disableZK);

// Sidebar links → smooth-scroll the section to the top.
document.querySelectorAll('#settingsNav a').forEach((a) => {
  a.addEventListener('click', (e) => {
    e.preventDefault();
    const el = document.getElementById(a.dataset.nav);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
});

// initial load
loadWhoami().then((u) => {
  $('usersCard').hidden = !isAdmin;
  if ($('navUsers')) $('navUsers').hidden = !isAdmin;
  // Backup is admin-only; the key download only makes sense with the vault on.
  if ($('backupCard')) $('backupCard').hidden = !isAdmin;
  if ($('navBackup')) $('navBackup').hidden = !isAdmin;
  if ($('dlKey')) $('dlKey').disabled = !secretsEnabled;
  if (!secretsEnabled && $('backupNote')) $('backupNote').textContent = 'The secret vault is off (no master key), so there is no key to back up — just the database.';
  // Security card: 2FA for everyone; vault passphrase for admins.
  if ($('securityCard')) $('securityCard').hidden = false;
  renderTwoFA(!!(u && u.totp_enabled));
  renderVaultSec();
  if ($('caSec')) {
    $('caSec').hidden = !caAvailable; // shown only when a CA is available
    const caLink = $('caSec').querySelector('a');
    if (caLink) caLink.href = caUrl;  // certguard's /ca.crt, or an external URL (bundled Caddy)
  }
  loadChannels();
  loadUsers();
}).catch(() => {});
