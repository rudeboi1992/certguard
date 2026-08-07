// Zoomed-out layout editor: the whole dashboard as a small map you can drag
// cards around in.
//
// Rearranging the real cards means dragging full-size panels through a page
// that scrolls, so the card you want and the place you want it are rarely on
// screen together. At this size the entire layout fits in one view and a move
// is one short drag.
//
// It drives the real grid through the handle initWidgetGrid returns, so
// ordering, spans and the storage format have exactly one implementation.
// Changes apply live to the page behind the dialog — the point is to see the
// result, and an editor that only previews would need its own packer to be
// honest about what you are going to get.
function initLayoutEditor(api, opts) {
  const dlg = document.getElementById(opts.dialog);
  const map = document.getElementById(opts.map);
  const openBtn = document.getElementById(opts.openButton);
  if (!api || !dlg || !map || !openBtn) return;

  let model = [];        // [{id,title,span,hidden,height}] in order
  let dragId = null;     // id being dragged
  let dropAt = -1;       // index it would land at

  // Pointer events rather than HTML5 drag-and-drop: the same gesture then
  // works with a mouse, a trackpad and a finger. HTML5 DnD does not fire for
  // touch at all, and this is exactly the sort of thing you would rearrange on
  // a tablet.
  function tileHtml(c, i) {
    const dragging = c.id === dragId;
    return `<div class="lm-tile${c.hidden ? ' off' : ''}${dragging ? ' dragging' : ''}"
        data-id="${c.id}" data-i="${i}" style="--span:${c.span};--h:${Math.round(c.height)}px">
      <span class="lm-grip" aria-hidden="true">⠿</span>
      <span class="lm-name">${escapeHtml(c.title)}</span>
      <span class="lm-tools">
        <button type="button" class="lm-btn" data-narrow="${c.id}" title="Narrower"
          aria-label="Make ${escapeHtml(c.title)} narrower"${c.span <= 1 ? ' disabled' : ''}>‹</button>
        <span class="lm-span" title="Columns wide">${c.span}</span>
        <button type="button" class="lm-btn" data-wide="${c.id}" title="Wider"
          aria-label="Make ${escapeHtml(c.title)} wider"${c.span >= api.columns ? ' disabled' : ''}>›</button>
        <button type="button" class="lm-btn lm-eye" data-vis="${c.id}"
          title="${c.hidden ? 'Show' : 'Hide'}" aria-pressed="${c.hidden ? 'false' : 'true'}"
          aria-label="${c.hidden ? 'Show' : 'Hide'} ${escapeHtml(c.title)}">${c.hidden ? '🚫' : '👁'}</button>
      </span>
    </div>`;
  }

  function render() {
    map.innerHTML = model.map(tileHtml).join('')
      + '<div class="lm-drop" id="lmDrop" hidden></div>';
    map.querySelectorAll('[data-wide]').forEach((b) =>
      b.addEventListener('click', () => bumpSpan(b.dataset.wide, +1)));
    map.querySelectorAll('[data-narrow]').forEach((b) =>
      b.addEventListener('click', () => bumpSpan(b.dataset.narrow, -1)));
    map.querySelectorAll('[data-vis]').forEach((b) =>
      b.addEventListener('click', () => toggleVis(b.dataset.vis)));
    map.querySelectorAll('.lm-tile').forEach((t) => {
      t.addEventListener('pointerdown', (e) => startDrag(e, t));
      // Keyboard equivalent, because a drag is not reachable without a pointer.
      t.tabIndex = 0;
      t.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowLeft' && e.shiftKey) { e.preventDefault(); bumpSpan(t.dataset.id, -1); }
        else if (e.key === 'ArrowRight' && e.shiftKey) { e.preventDefault(); bumpSpan(t.dataset.id, +1); }
        else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') { e.preventDefault(); move(t.dataset.id, -1); }
        else if (e.key === 'ArrowRight' || e.key === 'ArrowDown') { e.preventDefault(); move(t.dataset.id, +1); }
      });
    });
    const empty = model.every((c) => c.hidden);
    let note = document.getElementById('lmEmpty');
    if (note) note.hidden = !empty;
  }

  function commit() {
    api.setOrder(model.map((c) => c.id));
    model.forEach((c) => { api.setSpan(c.id, c.span); api.setHidden(c.id, c.hidden); });
    api.commit();
    // Re-read heights: a span change alters how tall a card renders, and the
    // miniature is only useful if its proportions keep matching the page.
    const fresh = new Map(api.cards().map((c) => [c.id, c.height]));
    model.forEach((c) => { if (fresh.has(c.id)) c.height = fresh.get(c.id); });
  }

  function bumpSpan(id, d) {
    const c = model.find((x) => x.id === id);
    if (!c) return;
    const next = Math.max(1, Math.min(api.columns, c.span + d));
    if (next === c.span) return;
    c.span = next;
    commit(); render();
  }

  function toggleVis(id) {
    const c = model.find((x) => x.id === id);
    if (!c) return;
    c.hidden = !c.hidden;
    commit(); render();
  }

  function move(id, d) {
    const i = model.findIndex((x) => x.id === id);
    const j = i + d;
    if (i < 0 || j < 0 || j >= model.length) return;
    model.splice(j, 0, model.splice(i, 1)[0]);
    commit(); render();
    const el = map.querySelector(`.lm-tile[data-id="${id}"]`);
    if (el) el.focus();
  }

  // Where would a drop at (x,y) land? Same reading-order rule the real grid
  // uses: the first tile that starts below the pointer, or sits on the same
  // band to its right.
  function dropIndex(x, y) {
    const tiles = [...map.querySelectorAll('.lm-tile')].filter((t) => t.dataset.id !== dragId);
    for (let i = 0; i < tiles.length; i++) {
      const r = tiles[i].getBoundingClientRect();
      if (y < r.top || (y <= r.bottom && x < r.left + r.width / 2)) {
        return model.findIndex((c) => c.id === tiles[i].dataset.id);
      }
    }
    return model.length;
  }

  function startDrag(e, tile) {
    if (e.button !== undefined && e.button !== 0) return;
    if (e.target.closest('button')) return; // the ‹ › and eye controls
    e.preventDefault();
    const id = tile.dataset.id;
    const x0 = e.clientX, y0 = e.clientY;
    let moved = false;

    const onMove = (ev) => {
      if (!moved && Math.hypot(ev.clientX - x0, ev.clientY - y0) < 4) return;
      if (!moved) { moved = true; dragId = id; render(); map.classList.add('dragging'); }
      dropAt = dropIndex(ev.clientX, ev.clientY);
      const marker = document.getElementById('lmDrop');
      const tiles = [...map.querySelectorAll('.lm-tile')].filter((t) => t.dataset.id !== dragId);
      const ref = tiles[Math.min(dropAt, tiles.length - 1)];
      if (marker && ref) {
        const r = ref.getBoundingClientRect(), m = map.getBoundingClientRect();
        marker.hidden = false;
        marker.style.left = (r.left - m.left + (dropAt >= tiles.length ? r.width : 0) - 3) + 'px';
        marker.style.top = (r.top - m.top) + 'px';
        marker.style.height = r.height + 'px';
      }
      // Follow the pointer, so the tile visibly comes with you.
      const el = map.querySelector(`.lm-tile[data-id="${id}"]`);
      if (el) el.style.transform = `translate(${ev.clientX - x0}px, ${ev.clientY - y0}px)`;
    };

    const onUp = () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
      map.classList.remove('dragging');
      if (moved && dropAt >= 0) {
        const from = model.findIndex((c) => c.id === id);
        const item = model.splice(from, 1)[0];
        // Removing the item first shifts every later index down by one.
        model.splice(dropAt > from ? dropAt - 1 : dropAt, 0, item);
        commit();
      }
      dragId = null; dropAt = -1;
      render();
    };

    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);
  }

  openBtn.addEventListener('click', () => {
    model = api.cards();
    render();
    if (!dlg.open) dlg.showModal();
  });
  const close = document.getElementById(opts.closeButton);
  if (close) close.addEventListener('click', () => dlg.close());
  dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });
}
