// Reusable widget grid with a masonry layout: cards keep a column-span width
// (1–4 of a 4-column grid) but are packed vertically so there are no big gaps —
// each card drops into the lowest available slot. Supports drag-to-reorder,
// drag-the-right-edge to resize width, hide (×) + "Add section", and persists
// order/width/hidden per browser. Used by the dashboard and settings pages.
function initWidgetGrid(grid, storageKey, opts) {
  opts = opts || {};
  if (!grid) return;
  const addSelect = opts.addSelect || null;
  const resetBtn = opts.resetBtn || null;
  const GAP = 20;   // matches the 1.25rem design gap
  const COLS = 4;

  const widgets = () => [...grid.children].filter((c) => c.classList.contains('widget'));
  const visible = () => widgets().filter((c) => !c.classList.contains('widget-off'));
  const spanOf = (c) => Math.max(1, Math.min(COLS, parseInt(c.dataset.span, 10) || 4));
  const heights = new Map();

  // Seed span from any initial inline grid-column, then stop using the grid.
  widgets().forEach((c) => {
    if (!c.dataset.span) {
      const m = /span\s+(\d)/.exec(c.style.gridColumn || '');
      c.dataset.span = m ? m[1] : '4';
    }
    c.style.gridColumn = '';
  });

  // --- masonry layout ---
  let scheduled = false;
  function relayout() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => { scheduled = false; layout(); });
  }
  function layout() {
    const cards = visible();
    const cw = grid.clientWidth;
    if (!cw) return;
    const cols = cw < 640 ? 1 : COLS;
    const colW = (cw - GAP * (cols - 1)) / cols;
    const spans = cards.map((c) => Math.min(spanOf(c), cols));
    cards.forEach((c, i) => { c.style.width = (spans[i] * colW + (spans[i] - 1) * GAP) + 'px'; });
    const hs = cards.map((c) => c.offsetHeight); // one reflow after all widths set
    const bottoms = new Array(cols).fill(0);
    cards.forEach((c, i) => {
      const span = spans[i];
      let bestCol = 0, bestTop = Infinity;
      for (let s = 0; s <= cols - span; s++) {
        const top = Math.max(...bottoms.slice(s, s + span));
        if (top < bestTop - 0.5) { bestTop = top; bestCol = s; }
      }
      c.style.left = (bestCol * (colW + GAP)) + 'px';
      c.style.top = bestTop + 'px';
      const b = bestTop + hs[i] + GAP;
      for (let s = bestCol; s < bestCol + span; s++) bottoms[s] = b;
      heights.set(c.id, hs[i]);
    });
    grid.style.height = Math.max(0, Math.max(0, ...bottoms) - GAP) + 'px';
    if (!grid.classList.contains('ready')) requestAnimationFrame(() => grid.classList.add('ready'));
  }

  // --- persistence ---
  function save() {
    const order = widgets().map((c) => c.id);
    const spans = {};
    const heightsMap = {};
    const hidden = [];
    for (const c of widgets()) {
      spans[c.id] = spanOf(c);
      if (c.dataset.height) heightsMap[c.id] = +c.dataset.height;
      if (c.classList.contains('widget-off')) hidden.push(c.id);
    }
    try { localStorage.setItem(storageKey, JSON.stringify({ order, spans, heights: heightsMap, hidden })); } catch (e) {}
  }
  // Give a card an explicit height (content scrolls inside); min keeps the bar usable.
  function setHeight(card, h) {
    h = Math.max(96, Math.round(h));
    card.style.height = h + 'px';
    card.style.maxHeight = 'none';
    card.dataset.height = h;
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
        if (el) el.dataset.span = data.spans[id];
      }
      for (const id in (data.heights || {})) {
        const el = document.getElementById(id);
        if (el) setHeight(el, data.heights[id]);
      }
      (data.hidden || []).forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.classList.add('widget-off');
      });
    }
    refreshAdd();
    layout();
  }
  function refreshAdd() {
    if (!addSelect) return;
    const off = widgets().filter((c) => c.classList.contains('widget-off'));
    addSelect.innerHTML = '<option value="">＋ Add section…</option>' +
      off.map((c) => `<option value="${c.id}">${escapeHtml(c.dataset.title || c.id)}</option>`).join('');
    addSelect.disabled = off.length === 0;
  }

  // --- hide / add / reset ---
  grid.querySelectorAll('.widget-hide').forEach((b) =>
    b.addEventListener('click', () => {
      b.closest('.widget').classList.add('widget-off');
      refreshAdd(); save(); layout();
    }));
  if (addSelect) addSelect.addEventListener('change', () => {
    const el = addSelect.value && document.getElementById(addSelect.value);
    if (el) { el.classList.remove('widget-off'); addSelect.value = ''; refreshAdd(); save(); layout(); }
  });
  if (resetBtn) resetBtn.addEventListener('click', () => {
    try { localStorage.removeItem(storageKey); } catch (e) {}
    location.reload();
  });

  // --- drag to reorder (pointer-based; highlight target, reorder on release) ---
  grid.querySelectorAll('.widget-drag').forEach((handle) => {
    handle.addEventListener('pointerdown', (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      const card = handle.closest('.widget');
      let moved = false, target = null;
      const clear = () => { if (target) target.classList.remove('drop-target'); target = null; };
      const move = (ev) => {
        if (!moved) { moved = true; card.classList.add('dragging'); document.body.classList.add('dragging-widget'); }
        const el = document.elementFromPoint(ev.clientX, ev.clientY);
        const over = el && el.closest('.widget');
        if (over === target) return;
        clear();
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
          const t = target; clear();
          const kids = widgets();
          if (kids.indexOf(card) < kids.indexOf(t)) t.after(card);
          else grid.insertBefore(card, t);
          save(); layout();
        }
      };
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
    });
  });

  // --- drag the right edge to resize width (snap 1–4 columns), live re-pack ---
  grid.querySelectorAll('.widget-resize').forEach((h) => {
    h.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      const card = h.closest('.widget');
      const cw = grid.clientWidth;
      const cols = cw < 640 ? 1 : COLS;
      const colW = (cw - GAP * (cols - 1)) / cols;
      const startX = e.clientX;
      const startSpan = Math.min(spanOf(card), cols);
      const startW = startSpan * colW + (startSpan - 1) * GAP;
      const move = (ev) => {
        const w = startW + (ev.clientX - startX);
        const span = Math.max(1, Math.min(cols, Math.round((w + GAP) / (colW + GAP))));
        if (String(span) !== card.dataset.span) { card.dataset.span = span; layout(); }
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

  // --- drag the bottom edge to resize height (content scrolls inside) ---
  // The vertical handle is injected next to each existing width handle so it
  // applies on every resizable card without extra markup.
  widgets().forEach((card) => {
    if (!card.querySelector('.widget-resize') || card.querySelector('.widget-resize-v')) return;
    const vh = document.createElement('span');
    vh.className = 'widget-resize-v';
    vh.title = 'Drag to resize height';
    card.appendChild(vh);
    vh.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      const startY = e.clientY;
      const startH = card.offsetHeight;
      const move = (ev) => { setHeight(card, startH + (ev.clientY - startY)); layout(); };
      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        save();
      };
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
    });
  });

  // --- re-pack when content height changes or the window resizes ---
  const ro = new ResizeObserver(() => {
    for (const c of visible()) {
      if (Math.abs((heights.get(c.id) || 0) - c.offsetHeight) > 1) { relayout(); return; }
    }
  });
  widgets().forEach((c) => ro.observe(c));
  window.addEventListener('resize', relayout);

  apply();
}
