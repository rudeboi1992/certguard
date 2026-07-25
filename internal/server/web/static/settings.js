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

// --- users (admin) ---
async function loadUsers() {
  if (!isAdmin) return;
  const res = await api('GET', '/api/v1/users');
  const users = await res.json();
  const rows = $('userRows');
  rows.innerHTML = '';
  for (const u of users) {
    const isSelf = u.id === currentUserId;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(u.email)}${isSelf ? ' <span class="muted small">(you)</span>' : ''}</td>
      <td><span class="pill ${u.role === 'admin' ? 'notice' : 'ok'}">${u.role}</span></td>
      <td class="muted small">joined ${fmtDate(u.created_at)}</td>
      <td class="actions">${isSelf ? '' : `<button class="btn link" data-deluser="${u.id}">Remove</button>`}</td>`;
    rows.appendChild(tr);
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

// --- settings sidebar nav + draggable / resizable widget grid ---
(function initLayout() {
  const grid = $('settingsGrid');
  if (!grid) return;
  const LS = 'certguard-settings-layout';

  const spanOf = (card) => {
    const m = /span\s+(\d)/.exec(card.style.gridColumn || '');
    return m ? +m[1] : 4;
  };
  const save = () => {
    const order = [...grid.children].map((c) => c.id);
    const spans = {};
    for (const c of grid.children) spans[c.id] = spanOf(c);
    try { localStorage.setItem(LS, JSON.stringify({ order, spans })); } catch (e) {}
  };
  const load = () => {
    let data;
    try { data = JSON.parse(localStorage.getItem(LS) || 'null'); } catch (e) {}
    if (!data) return;
    (data.order || []).forEach((id) => {
      const el = document.getElementById(id);
      if (el && el.parentElement === grid) grid.appendChild(el);
    });
    for (const id in (data.spans || {})) {
      const el = document.getElementById(id);
      if (el) el.style.gridColumn = 'span ' + data.spans[id];
    }
  };

  // Sidebar links → smooth-scroll the section to the top.
  document.querySelectorAll('#settingsNav a').forEach((a) => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      const el = document.getElementById(a.dataset.nav);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  // Drag to reorder (grab the grip).
  let dragged = null;
  grid.querySelectorAll('.widget-grip').forEach((grip) => {
    grip.addEventListener('dragstart', (e) => {
      dragged = grip.closest('.widget');
      dragged.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
      try { e.dataTransfer.setDragImage(dragged, 24, 16); } catch (_) {}
    });
    grip.addEventListener('dragend', () => {
      if (dragged) dragged.classList.remove('dragging');
      dragged = null;
      save();
    });
  });
  grid.querySelectorAll('.widget').forEach((card) => {
    card.addEventListener('dragover', (e) => { if (dragged && dragged !== card) e.preventDefault(); });
    card.addEventListener('drop', (e) => {
      e.preventDefault();
      if (!dragged || dragged === card) return;
      const kids = [...grid.children];
      if (kids.indexOf(dragged) < kids.indexOf(card)) card.after(dragged);
      else grid.insertBefore(dragged, card);
      save();
    });
  });

  // Drag the right edge to resize width (snap to 1–4 columns).
  grid.querySelectorAll('.widget-resize').forEach((h) => {
    h.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      const card = h.closest('.widget');
      const gap = parseFloat(getComputedStyle(grid).columnGap) || 0;
      const colW = (grid.clientWidth - gap * 3) / 4;
      const startX = e.clientX;
      const startW = spanOf(card) * colW + (spanOf(card) - 1) * gap;
      h.setPointerCapture(e.pointerId);
      const move = (ev) => {
        const w = startW + (ev.clientX - startX);
        const span = Math.max(1, Math.min(4, Math.round((w + gap) / (colW + gap))));
        card.style.gridColumn = 'span ' + span;
      };
      const up = () => {
        h.releasePointerCapture(e.pointerId);
        h.removeEventListener('pointermove', move);
        h.removeEventListener('pointerup', up);
        save();
      };
      h.addEventListener('pointermove', move);
      h.addEventListener('pointerup', up);
    });
  });

  const reset = $('resetLayout');
  if (reset) reset.addEventListener('click', () => {
    try { localStorage.removeItem(LS); } catch (e) {}
    location.reload();
  });

  load();
})();

// initial load
loadWhoami().then(() => {
  $('usersCard').hidden = !isAdmin;
  if ($('navUsers')) $('navUsers').hidden = !isAdmin;
  loadChannels();
  loadUsers();
}).catch(() => {});
