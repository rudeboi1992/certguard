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
        <span class="lm-tools">
          <button type="button" class="lm-btn" data-narrow="${c.id}" title="Narrower"
            aria-label="Make ${escapeHtml(c.title)} narrower"${c.span <= 1 ? ' disabled' : ''}>‹</button>
          <span class="lm-span">${c.span}</span>
          <button type="button" class="lm-btn" data-wide="${c.id}" title="Wider"
            aria-label="Make ${escapeHtml(c.title)} wider"${c.col + c.span >= api.columns ? ' disabled' : ''}>›</button>
          <button type="button" class="lm-btn lm-eye" data-vis="${c.id}" title="Hide"
            aria-label="Hide ${escapeHtml(c.title)}">👁</button>
        </span>
        <span class="lm-vgrip" data-tall="${c.id}" title="Drag to change height"></span>
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
      el.querySelectorAll('[data-wide]').forEach((b) =>
        b.addEventListener('click', () => resize(b.dataset.wide, +1)));
      el.querySelectorAll('[data-narrow]').forEach((b) =>
        b.addEventListener('click', () => resize(b.dataset.narrow, -1)));
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

  function resize(id, d) {
    const c = find(id);
    if (!c) return;
    c.span = Math.max(1, Math.min(api.columns - c.col, c.span + d));
    commit(c);
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
    if (e.target.closest('button')) return;
    const id = tile.dataset.id;
    const c = find(id);
    if (!c) return;
    e.preventDefault();

    const tall = !!e.target.closest('[data-tall]');
    const box = tile.getBoundingClientRect();
    const grabX = e.clientX - box.left, grabY = e.clientY - box.top;
    const x0 = e.clientX, y0 = e.clientY;
    const start = { col: c.col, row: c.row, span: c.span, rows: c.rows };
    let moved = false;

    const onMove = (ev) => {
      if (!moved && Math.hypot(ev.clientX - x0, ev.clientY - y0) < 3) return;
      if (!moved) { moved = true; drag = { id }; tile.classList.add('dragging'); }
      const m = map.getBoundingClientRect();
      if (tall) {
        // Bottom grip: height only.
        c.rows = Math.max(MIN_ROWS, Math.round(start.rows + (ev.clientY - y0) / SCALE));
      } else {
        // Position is taken from the tile's top-left corner, not the pointer,
        // so where you grabbed it does not change where it lands.
        const left = ev.clientX - grabX - m.left - 4;
        const top = ev.clientY - grabY - m.top - 4;
        c.col = Math.max(0, Math.min(api.columns - c.span, Math.round(left / colW())));
        c.row = Math.max(0, Math.round(top / SCALE));
      }
      const marker = document.getElementById('lmDrop');
      if (marker) {
        marker.hidden = false;
        marker.style.left = (c.col * colW() + 4) + 'px';
        marker.style.top = (c.row * SCALE + 4) + 'px';
        marker.style.width = (c.span * colW() - 4) + 'px';
        marker.style.height = (c.rows * SCALE - 4) + 'px';
      }
      tile.style.transform = tall ? '' : `translate(${ev.clientX - x0}px, ${ev.clientY - y0}px)`;
      if (tall) tile.style.height = (c.rows * SCALE - 4) + 'px';
    };

    const onUp = () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
      drag = null;
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
