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

  // drag to reorder — pointer-based (reliable across browsers, unlike native
  // HTML5 drag-and-drop). While dragging we only highlight the widget under the
  // cursor; the actual reorder happens once on release, which avoids the
  // layout-shift oscillation that live-reordering a tall card causes.
  grid.querySelectorAll('.widget-drag').forEach((handle) => {
    handle.addEventListener('pointerdown', (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      const card = handle.closest('.widget');
      let moved = false;
      let target = null;
      const clearTarget = () => { if (target) target.classList.remove('drop-target'); target = null; };
      const move = (ev) => {
        if (!moved) {
          moved = true;
          card.classList.add('dragging');
          document.body.classList.add('dragging-widget');
        }
        const el = document.elementFromPoint(ev.clientX, ev.clientY);
        const over = el && el.closest('.widget');
        if (over === target) return;
        clearTarget();
        if (over && over !== card && over.parentElement === grid && !over.classList.contains('widget-off')) {
          target = over;
          target.classList.add('drop-target');
        }
      };
      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        card.classList.remove('dragging');
        document.body.classList.remove('dragging-widget');
        if (target) {
          const t = target;
          clearTarget();
          const kids = widgets();
          if (kids.indexOf(card) < kids.indexOf(t)) t.after(card);
          else grid.insertBefore(card, t);
          save();
        }
      };
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
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
