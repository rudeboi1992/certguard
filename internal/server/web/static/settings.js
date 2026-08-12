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

// --- appearance (per-browser, same storage as the theme) ---
// prefs-init.js reads these before the page paints; this only writes them and
// applies the one change that is visible without a reload.
(function appearancePrefs() {
  var nav = $('prefNav'), home = $('prefHome');
  if (!nav || !home) return;
  const NAV_LABEL = { menu: 'Navigation is a menu', icons: 'Navigation shows inline icons', text: 'Navigation shows inline text' };
  // Pages flagged false in pages.js stay in the nav but are not offered here.
  const PAGES = (window.CG_PAGES || [['/', 'Dashboard']]).filter((p) => p[2] !== false);
  home.innerHTML = PAGES.map(([href, label]) =>
    `<option value="${href}">${escapeHtml(label)}</option>`).join('');
  try {
    const saved = localStorage.getItem('certguard-nav');
    nav.value = (saved === 'text' || saved === 'icons') ? saved : 'menu';
    // Older builds stored "dashboard"/"inventory" instead of a path.
    const savedHome = localStorage.getItem('certguard-home');
    const asPath = savedHome === 'dashboard' ? '/' : savedHome === 'inventory' ? '/inventory' : savedHome;
    home.value = PAGES.some(([h]) => h === asPath) ? asPath : '/';
  } catch (e) {}
  nav.addEventListener('change', () => {
    try { localStorage.setItem('certguard-nav', nav.value); } catch (e) {}
    // One set of markup serves all three; this attribute picks the layout, so
    // the change lands immediately on this page too.
    document.documentElement.setAttribute('data-nav', nav.value);
    toast(NAV_LABEL[nav.value] || 'Navigation updated');
  });
  home.addEventListener('change', () => {
    try { localStorage.setItem('certguard-home', home.value); } catch (e) {}
    const label = (PAGES.find(([h]) => h === home.value) || [, home.value])[1];
    toast(`Home is now ${label}`);
  });
})();

// --- security keys ---
// A key is always a second factor at sign-in. It can additionally hold a
// wrapped copy of the vault data key, which is what "unlocks vault" means on a
// row — that half needs the prf extension and an unlocked vault to set up.
let keysCache = [];

// What a key's row offers for the vault. prf_supported is -1 when the key was
// registered before certguard asked, in which case the only honest thing is to
// let the operator try.
function vaultAction(k) {
  if (k.unlocks_vault) {
    return `<span class="pill ok" title="This key can unlock the secret vault">vault</span>
            <button class="btn link" data-unpair="${k.id}">Unpair vault</button>`;
  }
  if (k.prf_supported === 0) {
    return `<span class="pill muted-pill" title="This key cannot derive a vault secret. It still works as a second factor.">no vault</span>`;
  }
  return `<button class="btn ghost small" data-pair="${k.id}">Use for vault</button>`;
}

async function loadKeys() {
  const rows = $('keyRows');
  if (!rows) return;
  if (!WebAuthnKit.supported()) {
    $('keysUnsupported').hidden = false;
    $('keyAddBtn').disabled = true;
  }
  // Security keys are bound to a domain, so an instance reached by IP cannot
  // register one. Say so here rather than letting the browser throw later.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(location.hostname) || location.hostname.includes(':')) {
    const el = $('keysNoHost');
    el.textContent = `Security keys need a hostname. This page is open at ${location.hostname}, which is an IP address — reach certguard by a domain name to register one.`;
    el.hidden = false;
    $('keyAddBtn').disabled = true;
  }
  let keys = [];
  try {
    const res = await api('GET', '/api/v1/webauthn/credentials');
    if (res.ok) keys = await res.json();
  } catch { /* leave the list empty */ }
  keysCache = keys;
  rows.innerHTML = '';
  for (const k of keys) {
    const row = document.createElement('div');
    row.className = 'set-row';
    const used = k.last_used_at ? `last used ${relTime(k.last_used_at)}` : 'never used';
    row.innerHTML = `
      <span class="pill notice set-tag">🔐 key</span>
      <span class="set-target">${escapeHtml(k.name || 'Security key')}</span>
      <span class="set-meta muted small">${escapeHtml(used)}</span>
      <span class="set-actions">
        ${vaultAction(k)}
        <button class="btn link" data-delkey="${k.id}">Remove</button>
      </span>`;
    rows.appendChild(row);
  }
  $('noKeys').hidden = keys.length !== 0;
  rows.querySelectorAll('[data-delkey]').forEach((b) =>
    b.addEventListener('click', () => removeKey(b.dataset.delkey)));
  rows.querySelectorAll('[data-pair]').forEach((b) =>
    b.addEventListener('click', () => pairKeyWithVault(b.dataset.pair, b)));
  rows.querySelectorAll('[data-unpair]').forEach((b) =>
    b.addEventListener('click', () => unpairKeyFromVault(b.dataset.unpair)));
}

async function registerKey() {
  const btn = $('keyAddBtn');
  const name = ($('keyName').value || '').trim() || 'Security key';
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = 'Touch your key…';
  try {
    const begin = await api('POST', '/api/v1/webauthn/register/begin');
    if (!begin.ok) throw new Error((await begin.json().catch(() => ({}))).error || 'Could not start');
    const opts = await begin.json();
    // Ask for prf at CREATION, not only when asserting. An authenticator
    // enables its hmac-secret when the credential is made, so a key registered
    // without this can never produce a vault secret afterwards — it would
    // silently come back empty at pairing time.
    const cred = await navigator.credentials.create({
      publicKey: { ...WebAuthnKit.decodeCreation(opts), extensions: { prf: {} } },
    });
    // The creation result says whether this credential can derive a vault
    // secret. Recording it now means the key's row can state that plainly,
    // instead of the operator finding out from a failed pairing later.
    const ext = cred.getClientExtensionResults();
    const prf = ext && ext.prf && typeof ext.prf.enabled === 'boolean'
      ? (ext.prf.enabled ? '1' : '0')
      : '';
    const res = await api('POST',
      `/api/v1/webauthn/register/finish?name=${encodeURIComponent(name)}${prf ? `&prf=${prf}` : ''}`,
      WebAuthnKit.encodeAttestation(cred));
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Registration failed');
    $('keyName').value = '';
    toast(prf === '0'
      ? 'Security key registered — it cannot unlock the vault, but works as a second factor'
      : 'Security key registered');
    loadKeys();
  } catch (e) {
    toast(WebAuthnKit.explain(e));
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

// Give a key its own wrapped copy of the vault data key. Requires the vault to
// be unlocked right now — you cannot hand over a key you do not currently hold.
async function pairKeyWithVault(id, btn) {
  const key = keysCache.find((k) => String(k.id) === String(id));
  if (!key) return;
  if (!zkEnabled) {
    toast('Turn on zero-knowledge mode first — that is the vault a key can unlock');
    return;
  }
  if (!ZK.isUnlocked()) {
    // Offer the way out rather than just naming the problem: a page load starts
    // locked, so this is the normal state to arrive in, not an error.
    toast('Unlock the vault, then pair the key');
    showVaultUnlock();
    return;
  }
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Touch your key…';
  try {
    const salt = WebAuthnKit.randomSalt();
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: WebAuthnKit.randomSalt(),
        allowCredentials: [{ type: 'public-key', id: WebAuthnKit.b64uToBuf(key.credential_id) }],
        // Required, not preferred. On a hardware key the prf secret comes from
        // CTAP2 hmac-secret, which the authenticator will only compute once it
        // has verified the user — so with "preferred" the browser may skip the
        // PIN and the extension then returns nothing at all. That failure looks
        // exactly like a key that cannot do prf, which is what made this so
        // confusing to diagnose.
        userVerification: 'required',
        extensions: WebAuthnKit.prfExtension(salt),
      },
    });
    const prf = WebAuthnKit.prfResult(cred);
    if (!prf) {
      // Reaching here despite requiring verification means the key really has
      // no hmac-secret to draw on, rather than simply not having been asked.
      toast('This key cannot derive a vault secret. It still works as a second factor for signing in.');
      return;
    }
    const wrapped = await ZK.wrapForKey(prf);
    const res = await api('PUT', `/api/v1/vault/wrappers/${encodeURIComponent(key.credential_id)}`,
      { wrapped, prf_salt: WebAuthnKit.toB64(salt) });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Could not save');
    toast('This key now unlocks the vault');
    loadKeys();
  } catch (e) {
    toast(WebAuthnKit.explain(e));
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

async function unpairKeyFromVault(id) {
  const key = keysCache.find((k) => String(k.id) === String(id));
  if (!key) return;
  const res = await api('DELETE', `/api/v1/vault/wrappers/${encodeURIComponent(key.credential_id)}`);
  if (res.status === 204) {
    toast('Key no longer unlocks the vault');
    loadKeys();
  } else {
    toast('Could not unpair');
  }
}

async function removeKey(id) {
  const key = keysCache.find((k) => String(k.id) === String(id));
  const label = key ? (key.name || 'this key') : 'this key';
  if (!confirm(`Remove ${label}? You will not be able to sign in with it afterwards.`)) return;
  const res = await api('DELETE', `/api/v1/webauthn/credentials/${id}`);
  if (res.status === 204) {
    toast('Security key removed');
    loadKeys();
  } else {
    toast('Could not remove key');
  }
}

$('keyAddBtn')?.addEventListener('click', registerKey);

// --- about / build info ---
// Only the rows the build actually carries are drawn: an unstamped build has no
// commit or date, and empty rows read as missing data rather than as absent.
let buildInfo = null;

async function loadAbout() {
  const grid = $('aboutGrid');
  if (!grid) return;
  let v;
  try {
    const res = await api('GET', '/api/v1/version');
    if (!res.ok) throw new Error(res.status);
    v = await res.json();
  } catch {
    grid.innerHTML = '<dt>Version</dt><dd class="muted">unavailable</dd>';
    return;
  }
  buildInfo = v;
  const rows = [['Version', v.version + (v.dirty ? ' (modified)' : '')]];
  // The full hash is what git wants; the short one is what people read.
  if (v.commit) rows.push(['Commit', v.commit.slice(0, 12)]);
  if (v.build_date) rows.push(['Built', v.build_date.replace('T', ' ').replace('Z', ' UTC')]);
  rows.push(['Runtime', `${v.go_version} · ${v.os}/${v.arch}`]);
  grid.innerHTML = rows
    .map(([k, val]) => `<dt>${escapeHtml(k)}</dt><dd class="mono">${escapeHtml(val)}</dd>`)
    .join('');
}

$('copyBuild')?.addEventListener('click', async () => {
  if (!buildInfo) return;
  const v = buildInfo;
  const text = [
    `certguard ${v.version}${v.dirty ? ' (modified)' : ''}`,
    v.commit ? `commit ${v.commit}` : '',
    v.build_date ? `built ${v.build_date}` : '',
    `${v.go_version} ${v.os}/${v.arch}`,
  ].filter(Boolean).join('\n');
  try {
    await navigator.clipboard.writeText(text);
    toast('Build details copied');
  } catch {
    toast('Could not copy to clipboard');
  }
});

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
  loadAbout();
  loadKeys();
  // The topbar lock button and the unlock dialog come from vault-ui.js; without
  // this the button stays hidden and pairing a key would have no way to unlock.
  syncVaultUi();
}).catch(() => {});

// Locking or unlocking changes whether a key can be paired, so redraw the rows.
setVaultRefresh(() => { renderVaultSec(); loadKeys(); });
