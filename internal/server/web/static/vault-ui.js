// Vault UI shared by every page that shows secrets: the lock button in the
// topbar, the unlock dialog, and the reveal-a-secret flow.
//
// This started out inside dashboard.js. The inventory page needs the same
// three things, and they are genuinely one feature — reveal is meaningless
// without a way to unlock, and the lock button is how you tell which state you
// are in — so all of it moved here rather than being partly duplicated.
//
// Requires common.js (for $, api, toast, escapeHtml, isAdmin, vaultLocked,
// vaultLockable, zkEnabled) and zk.js (for ZK), both loaded first.

// Pages set this to whatever re-reads their data, since locking, unlocking, or
// hiding a revealed secret all change what the page should be showing.
let vaultRefresh = () => {};
function setVaultRefresh(fn) { vaultRefresh = fn; }

const ICON_LOCKED = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10.5" width="16" height="10" rx="2.2"/><path d="M8 10.5V7.6a4 4 0 0 1 8 0v2.9"/></svg>';
const ICON_UNLOCKED = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10.5" width="16" height="10" rx="2.2"/><path d="M8 10.5V7.4a4 4 0 0 1 7.7-1.5"/></svg>';

// The dialog is injected rather than copied into each page's HTML, so there is
// one definition of it. Pages only supply the #vaultLockBtn in their topbar.
(function injectVaultDialog() {
  if (document.getElementById('vaultDialog')) return;
  const dlg = document.createElement('dialog');
  dlg.id = 'vaultDialog';
  dlg.className = 'detail-modal vault-modal';
  dlg.setAttribute('aria-labelledby', 'vaultTitle');
  dlg.innerHTML = `
    <div class="vault-head">
      <span class="vault-badge" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10.5" width="16" height="10" rx="2.2"/><path d="M8 10.5V7.6a4 4 0 0 1 8 0v2.9"/></svg>
      </span>
      <span class="vault-copy">
        <strong class="vault-title" id="vaultTitle">Vault locked</strong>
        <span class="vault-sub muted">Enter your passphrase to reveal or store secrets.</span>
      </span>
      <button type="button" class="widget-hide" id="vaultClose" title="Close" aria-label="Close">&times;</button>
    </div>
    <div class="vault-form">
      <input type="password" id="vaultPass" placeholder="Passphrase" autocomplete="current-password">
      <button class="btn primary" id="vaultUnlockBtn">Unlock</button>
    </div>
    <button type="button" class="btn ghost vault-key-btn" id="vaultKeyBtn" hidden>🔐 Unlock with security key</button>
    <p id="vaultLockErr" class="error small" hidden></p>`;
  document.body.appendChild(dlg);
})();

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
        vaultRefresh();
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
  offerKeyUnlock();
  // showModal stacks: opened from Reveal inside the detail popup, this lands on
  // top of it rather than behind, which an inline banner could never do.
  if (!dlg.open) dlg.showModal();
  $('vaultPass').focus();
}

// Show the security-key button only when this account actually has a key paired
// with the vault. Offering it otherwise would prompt for a key that cannot
// produce the right secret, and the failure would look like a broken key rather
// than one that was never set up.
//
// Only meaningful under zero-knowledge mode: that is the only configuration
// where the browser holds a data key for a security key to wrap.
async function offerKeyUnlock() {
  const btn = $('vaultKeyBtn');
  if (!btn) return;
  btn.hidden = true;
  // typeof, not a truthiness check: a page that forgot to load webauthn.js
  // would throw a ReferenceError here and take the whole vault dialog with it.
  if (!zkEnabled || typeof WebAuthnKit === 'undefined' || !WebAuthnKit.supported()) return;
  let paired = [];
  try {
    const res = await api('GET', '/api/v1/webauthn/credentials');
    if (!res.ok) return;
    paired = (await res.json()).filter((k) => k.unlocks_vault);
  } catch { return; }
  if (!paired.length) return;
  btn.hidden = false;
  btn.onclick = () => unlockWithKey(paired, btn);
}

async function unlockWithKey(paired, btn) {
  const errEl = $('vaultLockErr');
  errEl.hidden = true;
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Touch your key…';
  try {
    // Each key wraps the data key under its own prf salt, so the salt has to
    // come from the server before the ceremony, not after. Allowing all paired
    // keys at once would leave us unable to say which salt to use, so the first
    // is offered and the rest are alternatives only if it is absent.
    const key = paired[0];
    const meta = await api('GET', `/api/v1/vault/wrappers/${encodeURIComponent(key.credential_id)}`);
    if (!meta.ok) throw new Error('This key is not paired with the vault');
    const { wrapped, prf_salt: prfSalt } = await meta.json();
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: WebAuthnKit.randomSalt(),
        allowCredentials: [{ type: 'public-key', id: WebAuthnKit.b64uToBuf(key.credential_id) }],
        userVerification: 'preferred',
        extensions: WebAuthnKit.prfExtension(WebAuthnKit.fromB64(prfSalt)),
      },
    });
    const prf = WebAuthnKit.prfResult(cred);
    if (!prf) throw new Error('This key did not return a vault secret');
    await ZK.unlockWithKey(prf, wrapped);
    vaultLocked = false;
    closeVaultDialog();
    syncVaultUi();
    toast('Vault unlocked ✓');
    vaultRefresh();
  } catch (e) {
    errEl.textContent = WebAuthnKit.explain(e);
    errEl.hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

function closeVaultDialog() {
  const dlg = $('vaultDialog');
  if (dlg && dlg.open) dlg.close();
}

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

function toggleVault() {
  if (vaultLocked) showVaultUnlock(); else lockVault();
}

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
  vaultRefresh();
}

// Reveal one entry's secret in place, copying it to the clipboard. The value is
// hidden again after 30s so a revealed key doesn't sit on screen indefinitely.
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
  span.querySelector('[data-hide]').addEventListener('click', () => vaultRefresh());
  toast(copied ? 'Secret copied to clipboard ✓' : 'Secret revealed');
  setTimeout(() => { if (document.body.contains(span)) vaultRefresh(); }, 30000);
}

if ($('vaultLockBtn')) $('vaultLockBtn').addEventListener('click', toggleVault);
if ($('vaultClose')) $('vaultClose').addEventListener('click', closeVaultDialog);
// Clicking the backdrop closes it too. <dialog> reports the dialog itself as
// the target for backdrop clicks, so this only fires outside the panel.
if ($('vaultDialog')) {
  $('vaultDialog').addEventListener('click', (e) => {
    if (e.target === $('vaultDialog')) closeVaultDialog();
  });
}
