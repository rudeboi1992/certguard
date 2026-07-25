// Reusable widget grid: drag to reorder (via the grip), drag the right edge to
// resize width (1–4 columns), hide a section (×), and re-add hidden ones through
// an "Add section" <select>. Layout (order + widths + hidden) persists per
// browser under storageKey. Used by both the dashboard and settings pages.
//
// Expected markup: a grid container whose direct children are `.widget` cards,
// each with an id, a data-title, a `.widget-grip[draggable]`, a `.widget-hide`
// button, and a `.widget-resize` handle.
function initWidgetGrid(grid, storageKey, opts) {
  opts = opts || {};
  if (!grid) return;
  const addSelect = opts.addSelect || null;
  const resetBtn = opts.resetBtn || null;

  const widgets = () => [...grid.children].filter((c) => c.classList.contains('widget'));
  const spanOf = (card) => {
    const m = /span\s+(\d)/.exec(card.style.gridColumn || '');
    return m ? +m[1] : 4;
  };
  const isOff = (card) => card.classList.contains('widget-off');

  function save() {
    const order = widgets().map((c) => c.id);
    const spans = {};
    const hidden = [];
    for (const c of widgets()) {
      spans[c.id] = spanOf(c);
      if (isOff(c)) hidden.push(c.id);
    }
    try { localStorage.setItem(storageKey, JSON.stringify({ order, spans, hidden })); } catch (e) {}
  }

  function refreshAdd() {
    if (!addSelect) return;
    const off = widgets().filter(isOff);
    addSelect.innerHTML = '<option value="">＋ Add section…</option>' +
      off.map((c) => `<option value="${c.id}">${escapeHtml(c.dataset.title || c.id)}</option>`).join('');
    addSelect.disabled = off.length === 0;
  }

  function apply() {
    let data;
    try { data = JSON.parse(localStorage.getItem(storageKey) || 'null'); } catch (e) {}
    if (data) {
      (data.order || []).forEach((id) => {
        const el = document.getElementById(id);
        if (el && el.parentElement === grid) grid.appendChild(el);
      });
      for (const id in (data.spans || {})) {
        const el = document.getElementById(id);
        if (el) el.style.gridColumn = 'span ' + data.spans[id];
      }
      (data.hidden || []).forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.classList.add('widget-off');
      });
    }
    refreshAdd();
  }

  // hide / add
  grid.querySelectorAll('.widget-hide').forEach((b) =>
    b.addEventListener('click', () => {
      b.closest('.widget').classList.add('widget-off');
      refreshAdd();
      save();
    }));
  if (addSelect) addSelect.addEventListener('change', () => {
    const el = addSelect.value && document.getElementById(addSelect.value);
    if (el) { el.classList.remove('widget-off'); addSelect.value = ''; refreshAdd(); save(); }
  });
  if (resetBtn) resetBtn.addEventListener('click', () => {
    try { localStorage.removeItem(storageKey); } catch (e) {}
    location.reload();
  });

  // drag to reorder
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
      const kids = widgets();
      if (kids.indexOf(dragged) < kids.indexOf(card)) card.after(dragged);
      else grid.insertBefore(dragged, card);
      save();
    });
  });

  // drag the right edge to resize width (snap 1–4 columns). Listeners live on
  // window during the drag so events aren't lost when the cursor moves fast off
  // the thin handle.
  grid.querySelectorAll('.widget-resize').forEach((h) => {
    h.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      const card = h.closest('.widget');
      const gap = parseFloat(getComputedStyle(grid).columnGap) || 0;
      const colW = (grid.clientWidth - gap * 3) / 4;
      const startX = e.clientX;
      const startW = spanOf(card) * colW + (spanOf(card) - 1) * gap;
      const move = (ev) => {
        const w = startW + (ev.clientX - startX);
        const span = Math.max(1, Math.min(4, Math.round((w + gap) / (colW + gap))));
        card.style.gridColumn = 'span ' + span;
      };
      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        save();
      };
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
    });
  });

  apply();
}
