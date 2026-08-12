// Zoomed-out layout editor: the whole dashboard as a small map you place cards
// on.
//
// Rearranging the real cards means dragging full-size panels through a page
// that scrolls, so the card you want and the place you want it are rarely on
// screen together. At this size the entire layout fits in one view and a move
// is one short drag.
//
// It is a true miniature, not a list: the map is the same four columns and the
// same row units as the grid, at a fixed scale, so a tile's position here *is*
// its position there. It drives the real grid through the handle
// initWidgetGrid returns, so placement and persistence have one implementation.
// Changes apply live to the page behind the dialog — an editor that only
// previewed would need its own copy of the placement rules to stay honest.
function initLayoutEditor(api, opts) {
  const dlg = document.getElementById(opts.dialog);
  const map = document.getElementById(opts.map);
  const openBtn = document.getElementById(opts.openButton);
  if (!api || !dlg || !map || !openBtn) return;

  const SCALE = 4;      // px per row unit in the miniature
  const MIN_ROWS = 5;   // matches the grid's own floor
  let cards = [];
  let drag = null;

  const colW = () => (map.clientWidth - 8) / api.columns;

  function draw() {
    const cw = colW();
    const bottom = cards.filter((c) => !c.hidden)
      .reduce((m, c) => Math.max(m, c.row + c.rows), 0);
    map.style.height = Math.max(120, bottom * SCALE + 8) + 'px';

    map.innerHTML = cards.map((c) => {
      if (c.hidden) return '';
      const d = drag && drag.id === c.id;
      return `<div class="lm-tile${d ? ' dragging' : ''}" data-id="${c.id}"
        style="left:${(c.col * cw + 4).toFixed(1)}px; top:${c.row * SCALE + 4}px;
               width:${(c.span * cw - 4).toFixed(1)}px; height:${c.rows * SCALE - 4}px">
        <span class="lm-name">${escapeHtml(c.title)}</span>
        <button type="button" class="lm-eye" data-vis="${c.id}" title="Hide"
          aria-label="Hide ${escapeHtml(c.title)}">👁</button>
        <span class="lm-corner" data-corner="${c.id}" title="Drag to resize" aria-hidden="true"></span>
      </div>`;
    }).join('')
      + '<div class="lm-drop" id="lmDrop" hidden></div>';

    // Hidden cards live in a tray under the map: they are still part of the
    // arrangement, but they have no position to show.
    const off = cards.filter((c) => c.hidden);
    const tray = document.getElementById(opts.tray);
    if (tray) {
      tray.hidden = off.length === 0;
      tray.innerHTML = off.length
        ? '<span class="muted small">Hidden:</span>' + off.map((c) =>
          `<button type="button" class="lm-chip" data-vis="${c.id}"
             title="Put ${escapeHtml(c.title)} back on the dashboard">＋ ${escapeHtml(c.title)}</button>`).join('')
        : '';
    }
    wire();
  }

  function wire() {
    const root = [map, document.getElementById(opts.tray)].filter(Boolean);
    root.forEach((el) => {
      el.querySelectorAll('[data-vis]').forEach((b) =>
        b.addEventListener('click', () => toggleVis(b.dataset.vis)));
    });
    map.querySelectorAll('.lm-tile').forEach((t) => {
      t.tabIndex = 0;
      t.addEventListener('pointerdown', (e) => startDrag(e, t));
      t.addEventListener('keydown', (e) => onKey(e, t.dataset.id));
    });
  }

  const find = (id) => cards.find((c) => c.id === id);

  function commit(c) {
    api.place(c.id, { c: c.col, r: c.row, w: c.span, h: c.rows });
    api.commit();
    cards = api.cards();   // re-read: a placement can push other cards down
    draw();
  }

  // Red alignment guides shown while a tile is being moved: a line appears
  // wherever one of the moving tile's four edges lines up with the same edge —
  // or the touching edge — of another card, so rows and columns can be levelled
  // by eye. Cleared on drop; not shown while resizing.
  function clearGuides() { map.querySelectorAll('.lm-guide').forEach((g) => g.remove()); }
  function addGuide(cls, prop, px) {
    const d = document.createElement('div');
    d.className = 'lm-guide ' + cls;
    d.style[prop] = px + 'px';
    map.appendChild(d);
  }
  function showGuides(c) {
    clearGuides();
    const cw = colW();
    const others = cards.filter((o) => !o.hidden && o.id !== c.id);
    const cL = c.col, cR = c.col + c.span, cT = c.row, cB = c.row + c.rows;
    let L = false, R = false, T = false, B = false;
    for (const o of others) {
      const oL = o.col, oR = o.col + o.span, oT = o.row, oB = o.row + o.rows;
      if (oL === cL || oR === cL) L = true;
      if (oL === cR || oR === cR) R = true;
      if (oT === cT || oB === cT) T = true;
      if (oT === cB || oB === cB) B = true;
    }
    if (L) addGuide('lm-guide-v', 'left', cL * cw + 4);
    if (R) addGuide('lm-guide-v', 'left', cR * cw);
    if (T) addGuide('lm-guide-h', 'top', cT * SCALE + 4);
    if (B) addGuide('lm-guide-h', 'top', cB * SCALE);
  }

  // Magnetise the dragged tile's top or bottom edge onto a nearby card's top or
  // bottom edge, in any column, so rows line up as you pass them. Rows are
  // fine-grained, so without this pull an exact match almost never happens on a
  // free drag and the red line never appears — this is what makes levelling with
  // a card two columns over actually work. Returns the possibly-snapped row.
  function snapRow(c, row) {
    const SNAP = 3; // rows (~12px in the miniature)
    const others = cards.filter((o) => !o.hidden && o.id !== c.id);
    let best = row, bestDist = SNAP + 1;
    for (const o of others) {
      for (const ln of [o.row, o.row + o.rows]) {
        const dTop = Math.abs(row - ln);
        if (dTop < bestDist) { bestDist = dTop; best = ln; }
        const dBottom = Math.abs((row + c.rows) - ln);
        if (dBottom < bestDist) { bestDist = dBottom; best = ln - c.rows; }
      }
    }
    return Math.max(0, best);
  }

  // Resizing counterpart: magnetise the bottom edge (the one the corner drags)
  // onto a nearby card's top or bottom edge, so height lines up with the cards
  // around it. Returns the possibly-snapped row count.
  function snapHeight(c, rows) {
    const SNAP = 3;
    const others = cards.filter((o) => !o.hidden && o.id !== c.id);
    const bottom = c.row + rows;
    let best = rows, bestDist = SNAP + 1;
    for (const o of others) {
      for (const ln of [o.row, o.row + o.rows]) {
        const d = Math.abs(bottom - ln);
        if (d < bestDist && ln - c.row >= MIN_ROWS) { bestDist = d; best = ln - c.row; }
      }
    }
    return Math.max(MIN_ROWS, best);
  }

  function toggleVis(id) {
    const c = find(id);
    if (!c) return;
    api.setHidden(id, !c.hidden);
    api.commit();
    cards = api.cards();
    draw();
  }

  function onKey(e, id) {
    const c = find(id);
    if (!c) return;
    const step = e.shiftKey ? 4 : 1;
    let handled = true;
    if (e.key === 'ArrowLeft') c.col = Math.max(0, c.col - 1);
    else if (e.key === 'ArrowRight') c.col = Math.min(api.columns - c.span, c.col + 1);
    else if (e.key === 'ArrowUp') c.row = Math.max(0, c.row - step);
    else if (e.key === 'ArrowDown') c.row = c.row + step;
    else handled = false;
    if (!handled) return;
    e.preventDefault();
    commit(c);
    const el = map.querySelector(`.lm-tile[data-id="${id}"]`);
    if (el) el.focus();
  }

  function startDrag(e, tile) {
    if (e.button !== undefined && e.button !== 0) return;
    if (e.target.closest('button')) return;      // the eye is a click, not a drag
    const id = tile.dataset.id;
    const c = find(id);
    if (!c) return;
    e.preventDefault();

    // The bottom-right corner resizes; anywhere else on the tile moves it.
    const corner = !!e.target.closest('[data-corner]');
    const box = tile.getBoundingClientRect();
    const grabX = e.clientX - box.left, grabY = e.clientY - box.top;
    const x0 = e.clientX, y0 = e.clientY;
    const start = { col: c.col, row: c.row, span: c.span, rows: c.rows };
    let moved = false;

    const onMove = (ev) => {
      if (!moved && Math.hypot(ev.clientX - x0, ev.clientY - y0) < 3) return;
      if (!moved) { moved = true; drag = { id }; tile.classList.add('dragging'); }
      const m = map.getBoundingClientRect();
      const cw = colW();
      if (corner) {
        // Span from where the right edge is dragged (whole columns); height from
        // the bottom edge, magnetised onto a nearby card's edge so it can be
        // levelled while resizing, the same as while moving.
        c.span = Math.max(1, Math.min(api.columns - start.col,
          Math.round((ev.clientX - m.left) / cw) - start.col));
        const rawRows = Math.max(MIN_ROWS, Math.round((ev.clientY - m.top) / SCALE) - start.row);
        c.rows = snapHeight(c, rawRows);
      } else {
        // Position is taken from the tile's top-left corner, not the pointer,
        // so where you grabbed it does not change where it lands.
        c.col = Math.max(0, Math.min(api.columns - c.span,
          Math.round((ev.clientX - grabX - m.left - 4) / cw)));
        const rawRow = Math.max(0, Math.round((ev.clientY - grabY - m.top - 4) / SCALE));
        c.row = snapRow(c, rawRow);   // magnetise an edge to a nearby card's edge
      }
      const marker = document.getElementById('lmDrop');
      if (marker) {
        marker.hidden = false;
        marker.style.left = (c.col * cw + 4) + 'px';
        marker.style.top = (c.row * SCALE + 4) + 'px';
        marker.style.width = (c.span * cw - 4) + 'px';
        marker.style.height = (c.rows * SCALE - 4) + 'px';
      }
      if (corner) {
        tile.style.transform = '';
        tile.style.width = (c.span * cw - 4) + 'px';
        tile.style.height = (c.rows * SCALE - 4) + 'px';
      } else {
        tile.style.transform = `translate(${ev.clientX - x0}px, ${ev.clientY - y0}px)`;
      }
      showGuides(c);   // red lines while both moving and resizing
    };

    const onUp = () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
      drag = null;
      clearGuides();
      if (moved) commit(c); else draw();
    };

    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);
  }

  openBtn.addEventListener('click', () => {
    cards = api.cards();
    if (!dlg.open) dlg.showModal();
    draw();   // after showModal: the map has no width while the dialog is closed
  });
  const close = document.getElementById(opts.closeButton);
  if (close) close.addEventListener('click', () => dlg.close());
  // Tidy from inside the arranger: compact the real grid, then re-read so the
  // miniature reflects where every card ended up.
  const tidy = opts.tidyButton && document.getElementById(opts.tidyButton);
  if (tidy && api.compact) {
    tidy.addEventListener('click', () => { api.compact(); cards = api.cards(); draw(); });
  }
  dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });
}
