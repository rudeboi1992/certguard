// Reusable widget grid with a masonry layout: cards keep a column-span width
// (1–4 of a 4-column grid) but are packed vertically so there are no big gaps —
// each card drops into the lowest available slot. Supports drag-to-reorder,
// drag-the-right-edge to resize width, hide (×) + "Add section", and persists
// order/width/hidden per browser. Used by the dashboard and settings pages.
function initWidgetGrid(grid, storageKey, opts) {
  opts = opts || {};
  if (!grid) return;
  const addButton = opts.addButton || null;
  const addDialog = opts.addDialog || null;
  const addGrid = opts.addGrid || null;
  const resetBtn = opts.resetBtn || null;
  const centerToggle = opts.centerToggle || null;
  const compactToggle = opts.compactToggle || null;
  let centered = false;
  let compact = true;
  const GAP = 20;   // matches the 1.25rem design gap
  const COLS = 4;

  const widgets = () => [...grid.children].filter((c) => c.classList.contains('widget'));
  const visible = () => widgets().filter((c) => !c.classList.contains('widget-off'));
  const spanOf = (c) => Math.max(1, Math.min(COLS, parseInt(c.dataset.span, 10) || 4));
  const heights = new Map();
  // Cards that follow another card's height (see data-matchheight in layout()).
  const matchers = widgets()
    .map((card) => ({ card, target: document.getElementById(card.dataset.matchheight || '') }))
    .filter((m) => m.target && m.target !== m.card);
  // `data-sized` marks a card the user has given a height to by hand. It beats
  // both automatic modes — fit-to-content (data-autoheight) and following
  // another card (data-matchheight) — because an explicit drag or double-click
  // should stick. It persists, and "Reset layout" clears it.
  const follows = (c) => !c.dataset.sized && matchers.some((m) => m.card === c);
  const markSized = (c) => { c.dataset.sized = '1'; };

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
  function metrics() {
    const cw = grid.clientWidth;
    const cols = cw < 640 ? 1 : COLS;
    return { cw, cols, colW: (cw - GAP * (cols - 1)) / cols };
  }

  // Pure packer: takes [{el, span, h}] in preference order and reports where
  // each lands, without touching the DOM. Kept separate from layout() so a drag
  // can pack a *hypothetical* order and preview it before committing.
  //
  // Skyline packing. Repeatedly take the lowest point on the skyline and put a
  // card there; if nothing fits, raise that gap to the next step up.
  //
  // `compact` decides which card gets tried. On, we scan for the FIRST
  // remaining card that fits the gap, so a hole beside a short card gets
  // backfilled by a later narrow card instead of staying empty forever. Off, we
  // only ever try the next card in order — a wide card after a short one leaves
  // a visible hole, and where a card sits follows directly from where it is in
  // the order. Denser vs. predictable; the toggle is the user's call.
  function pack(items, cols, colW) {
    const bottoms = new Array(cols).fill(0);
    const pending = items.slice();
    const pos = new Map();
    let guard = pending.length * cols + cols + 8; // belt and braces against a stall
    while (pending.length && guard-- > 0) {
      const level = Math.min(...bottoms);
      let pick = -1, pickCol = -1;
      for (let k = 0; k < pending.length && pick < 0; k++) {
        for (let s = 0; s <= cols - pending[k].span; s++) {
          if (Math.max(...bottoms.slice(s, s + pending[k].span)) <= level + 0.5) {
            pick = k; pickCol = s; break;
          }
        }
        if (!compact) break; // strict order: never look past the next card
      }
      if (pick < 0) {
        // Nothing fits this gap — raise it to the next step up and try again.
        // That leaves real dead space, but only where no card could have gone.
        const higher = bottoms.filter((b) => b > level + 0.5);
        if (!higher.length) break;
        const next = Math.min(...higher);
        for (let s = 0; s < cols; s++) if (bottoms[s] <= level + 0.5) bottoms[s] = next;
        continue;
      }
      const it = pending.splice(pick, 1)[0];
      const top = Math.max(...bottoms.slice(pickCol, pickCol + it.span));
      pos.set(it.el, {
        left: pickCol * (colW + GAP), top,
        w: it.span * colW + (it.span - 1) * GAP, h: it.h,
      });
      for (let s = pickCol; s < pickCol + it.span; s++) bottoms[s] = top + it.h + GAP;
    }
    return { pos, height: Math.max(0, Math.max(0, ...bottoms) - GAP) };
  }

  // Write packed positions out. `skip` is the card under the pointer during a
  // drag: it follows the cursor instead, and its slot gets the drop outline.
  // Returns the placement map so the caller can find that slot.
  function applyPack(items, cw, cols, colW, skip) {
    const { pos, height } = pack(items, cols, colW);
    // Center the packed block: shift every card by half the unused width. Cards
    // that already span the full grid produce no offset, so this only shows
    // once something has been narrowed.
    let shift = 0;
    if (centered) {
      let maxRight = 0;
      pos.forEach((p) => { maxRight = Math.max(maxRight, p.left + p.w); });
      shift = Math.max(0, (cw - maxRight) / 2);
    }
    pos.forEach((p, el) => {
      if (el === skip) return;
      el.style.left = (p.left + shift) + 'px';
      el.style.top = p.top + 'px';
    });
    grid.style.height = height + 'px';
    return { pos, shift };
  }

  function layout() {
    const cards = visible();
    const { cw, cols, colW } = metrics();
    if (!cw) return;
    const spans = cards.map((c) => Math.min(spanOf(c), cols));
    cards.forEach((c, i) => { c.style.width = (spans[i] * colW + (spans[i] - 1) * GAP) + 'px'; });
    // `data-matchheight="<id>"` pins a card to the live height of another one,
    // so a pair sitting side by side stays visually level even though the
    // target sizes to its own content. Only on multi-column layouts — stacked
    // in one column there is nothing to line up with, and forcing a height
    // there would just make the follower scroll.
    matchers.forEach(({ card, target }) => {
      if (!follows(card)) return; // released by a manual resize — leave it alone
      if (cols === 1 || card.classList.contains('widget-off') || target.classList.contains('widget-off')) {
        card.style.height = '';
      } else {
        card.style.height = target.offsetHeight + 'px';
        card.style.maxHeight = 'none';
      }
    });
    const items = cards.map((c, i) => ({ el: c, span: spans[i], h: c.offsetHeight }));
    items.forEach((it) => heights.set(it.el.id, it.h));
    applyPack(items, cw, cols, colW, null);
    if (!grid.classList.contains('ready')) requestAnimationFrame(() => grid.classList.add('ready'));
  }

  // --- persistence ---
  function save() {
    const order = widgets().map((c) => c.id);
    const spans = {};
    const heightsMap = {};
    const hidden = [];
    const sized = [];
    for (const c of widgets()) {
      spans[c.id] = spanOf(c);
      if (c.dataset.height) heightsMap[c.id] = +c.dataset.height;
      if (c.classList.contains('widget-off')) hidden.push(c.id);
      if (c.dataset.sized) sized.push(c.id);
    }
    try { localStorage.setItem(storageKey, JSON.stringify({ order, spans, heights: heightsMap, hidden, centered, compact, sized })); } catch (e) {}
  }
  // Cards marked `data-autoheight` grow to fit their content and ignore stored
  // heights — until the user drags or double-clicks their bottom edge, at which
  // point data-sized takes over and they behave like any other card.
  const autoHeight = (c) => c.hasAttribute('data-autoheight') && !c.dataset.sized;

  // Give a card an explicit height (content scrolls inside); min keeps the bar usable.
  function setHeight(card, h) {
    if (autoHeight(card) || follows(card)) return;
    h = Math.max(96, Math.round(h));
    card.style.height = h + 'px';
    card.style.maxHeight = 'none';
    card.dataset.height = h;
  }
  // The tallest card sharing this one's row. Masonry has no real rows, but
  // cards packed at the same top edge read as one, so that's the grouping.
  // Returns this card's own height when it sits alone, i.e. a no-op.
  function rowTallest(card) {
    const top = parseFloat(card.style.top) || 0;
    const peers = visible().filter((c) => Math.abs((parseFloat(c.style.top) || 0) - top) < 2);
    return Math.max(...peers.map((c) => c.offsetHeight));
  }

  // The height at which this card's content would exactly fit. Measured with
  // the forced height lifted, because reading scrollHeight against the current
  // box only ever reports "at least what it is now" — when content is shorter
  // than the card, scrollHeight equals clientHeight.
  function contentHeight(card) {
    const body = card.querySelector('.widget-body');
    if (!body) return 0;
    const prevH = card.style.height, prevMax = card.style.maxHeight;
    card.style.height = 'auto';
    card.style.maxHeight = 'none';
    const natural = card.offsetHeight - body.clientHeight + body.scrollHeight;
    card.style.height = prevH;
    card.style.maxHeight = prevMax;
    return natural;
  }

  // Snap a dragged height to something meaningful. The old version collected
  // every other card's raw height and took the first within 14px — so a card
  // in a completely different row could capture the drag, and matching a
  // height didn't line any edges up unless the two happened to start at the
  // same y. These targets are all expressed as "where does my bottom edge
  // land", which is what you actually see:
  //   - flush with any other card's bottom edge
  //   - flush with any other card's top edge
  //   - exactly fitting my own content
  // Nearest target wins rather than first, so the pull is never surprising.
  const SNAP = 12;
  function applySnap(card, h, natural) {
    const myTop = parseFloat(card.style.top) || 0;
    const cands = [];
    if (natural > 96) cands.push(natural);
    for (const c of visible()) {
      if (c === card) continue;
      const t = parseFloat(c.style.top) || 0;
      const ch = heights.get(c.id) || 0;
      if (!ch) continue;
      cands.push(t + ch - myTop); // my bottom flush with theirs
      cands.push(t - GAP - myTop); // my bottom flush with their top edge
    }
    let best = null, bestD = SNAP;
    for (const s of cands) {
      if (s < 96) continue;
      const d = Math.abs(h - s);
      if (d < bestD) { bestD = d; best = s; }
    }
    return best === null ? { h, hit: false } : { h: best, hit: true };
  }

  // A line across the grid at the edge a snap has locked onto.
  let guideEl = null;
  function showGuide(y) {
    if (y === null) { if (guideEl) { guideEl.remove(); guideEl = null; } return; }
    if (!guideEl) {
      guideEl = document.createElement('div');
      guideEl.className = 'snap-guide';
      grid.appendChild(guideEl);
    }
    guideEl.style.top = y + 'px';
  }
  function apply() {
    let data, fromDefault = false;
    try { data = JSON.parse(localStorage.getItem(storageKey) || 'null'); } catch (e) {}
    // First run (or after Reset): seed the shipped default arrangement.
    if (!data && opts.defaults) { data = opts.defaults; fromDefault = true; }
    if (data) {
      centered = !!data.centered;
      compact = data.compact !== false; // absent in older layouts → keep the default
      (data.order || []).forEach((id) => {
        const el = document.getElementById(id);
        if (el && el.parentElement === grid) grid.appendChild(el);
      });
      for (const id in (data.spans || {})) {
        const el = document.getElementById(id);
        if (el) el.dataset.span = data.spans[id];
      }
      // Before any heights: a hand-sized card has to be flagged again first, or
      // setHeight() would refuse its stored height and fall back to automatic.
      (data.sized || []).forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.dataset.sized = '1';
      });
      // Skip the shipped default heights on a single-column (mobile) layout —
      // a forced height there just makes a card scroll. User-set heights apply.
      const skipHeights = fromDefault && grid.clientWidth < 640;
      for (const id in (data.heights || {})) {
        if (skipHeights) break;
        const el = document.getElementById(id);
        if (el) setHeight(el, data.heights[id]);
      }
      // Hidden state has to be driven both ways. The optional cards ship with
      // `widget-off` in the markup, so only ever *adding* it meant a section
      // the user added came back hidden on the next load. Cards the saved
      // layout has never seen (added by a later release) keep their shipped
      // default rather than being force-shown.
      const known = new Set(data.order || []);
      const hidden = new Set(data.hidden || []);
      widgets().forEach((c) => {
        if (hidden.has(c.id)) c.classList.add('widget-off');
        else if (known.has(c.id)) c.classList.remove('widget-off');
      });
    }
    refreshAdd();
    syncCenterToggle();
    layout();
  }
  function syncCenterToggle() {
    if (centerToggle) {
      centerToggle.classList.toggle('on', centered);
      centerToggle.setAttribute('aria-pressed', centered ? 'true' : 'false');
    }
    if (compactToggle) {
      compactToggle.classList.toggle('on', compact);
      compactToggle.setAttribute('aria-pressed', compact ? 'true' : 'false');
    }
  }
  // The picker lists every hidden card as a titled tile describing what it
  // shows, three across. It stays open after a pick so several can be added in
  // one go, and closes itself once there is nothing left to add.
  function refreshAdd() {
    const off = widgets().filter((c) => c.classList.contains('widget-off'));
    if (addButton) {
      addButton.disabled = off.length === 0;
      addButton.textContent = off.length ? `＋ Add section (${off.length})` : '＋ Add section';
    }
    if (!addGrid) return;
    addGrid.innerHTML = off.length
      ? off.map((c) => `
          <button type="button" class="section-card" data-add="${c.id}">
            <span class="section-card-title">${escapeHtml(c.dataset.title || c.id)}</span>
            <span class="section-card-desc">${escapeHtml(c.dataset.desc || '')}</span>
            <span class="section-card-cta">＋ Add</span>
          </button>`).join('')
      : '<p class="muted">Every section is already on the dashboard.</p>';
    addGrid.querySelectorAll('[data-add]').forEach((b) => b.addEventListener('click', () => {
      const el = document.getElementById(b.dataset.add);
      if (!el) return;
      el.classList.remove('widget-off');
      refreshAdd(); save(); layout();
      if (!addGrid.querySelector('[data-add]') && addDialog && addDialog.open) addDialog.close();
      el.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }));
  }

  // --- hide / add / reset ---
  grid.querySelectorAll('.widget-hide').forEach((b) =>
    b.addEventListener('click', () => {
      b.closest('.widget').classList.add('widget-off');
      refreshAdd(); save(); layout();
    }));
  if (addButton && addDialog) {
    addButton.addEventListener('click', () => { refreshAdd(); addDialog.showModal(); });
    addDialog.addEventListener('click', (e) => { if (e.target === addDialog) addDialog.close(); });
    const close = addDialog.querySelector('#addSectionClose');
    if (close) close.addEventListener('click', () => addDialog.close());
  }
  if (centerToggle) centerToggle.addEventListener('click', () => {
    centered = !centered;
    syncCenterToggle(); save(); layout();
  });
  if (compactToggle) compactToggle.addEventListener('click', () => {
    compact = !compact;
    syncCenterToggle(); save(); layout();
  });
  if (resetBtn) resetBtn.addEventListener('click', () => {
    try { localStorage.removeItem(storageKey); } catch (e) {}
    location.reload();
  });

  // --- drag to reorder: live reflow with a drop outline ---
  // The card follows the pointer while every other card animates to the layout
  // it would have if you let go now, and a dashed outline marks the slot the
  // dragged card would take. Nothing is committed until release.
  //
  // Where in the order does the pointer sit? Walk the other cards in order and
  // stop at the first one that comes *after* the pointer in reading order —
  // either below it, or on the same band and to its right.
  function dropIndex(x, y, dragged) {
    const others = visible().filter((c) => c !== dragged);
    for (let i = 0; i < others.length; i++) {
      const r = others[i].getBoundingClientRect();
      if (y < r.top || (y <= r.bottom && x < r.left + r.width / 2)) return i;
    }
    return others.length;
  }

  grid.querySelectorAll('.widget-drag').forEach((handle) => {
    handle.addEventListener('pointerdown', (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      const card = handle.closest('.widget');
      const x0 = e.clientX, y0 = e.clientY;
      const left0 = parseFloat(card.style.left) || 0;
      const top0 = parseFloat(card.style.top) || 0;
      let moved = false, ghost = null, index = -1, sizes = null;

      const begin = () => {
        moved = true;
        card.classList.add('dragging');
        document.body.classList.add('dragging-widget');
        ghost = document.createElement('div');
        ghost.className = 'widget-ghost';
        grid.appendChild(ghost);
        // Freeze spans/heights for the drag so every preview packs identically.
        const { cols } = metrics();
        sizes = visible().map((c) => ({ el: c, span: Math.min(spanOf(c), cols), h: c.offsetHeight }));
      };

      const preview = (ev) => {
        const { cw, cols, colW } = metrics();
        const others = sizes.filter((s) => s.el !== card);
        const mine = sizes.find((s) => s.el === card);
        const list = others.slice();
        list.splice(index, 0, mine);
        const { pos, shift } = applyPack(list, cw, cols, colW, card);
        const p = pos.get(card);
        if (p && ghost) {
          ghost.style.left = (p.left + shift) + 'px';
          ghost.style.top = p.top + 'px';
          ghost.style.width = p.w + 'px';
          ghost.style.height = p.h + 'px';
        }
        // The card itself tracks the pointer, offset from where it started.
        card.style.left = (left0 + ev.clientX - x0) + 'px';
        card.style.top = (top0 + ev.clientY - y0) + 'px';
      };

      const move = (ev) => {
        if (!moved) {
          if (Math.abs(ev.clientX - x0) < 5 && Math.abs(ev.clientY - y0) < 5) return;
          begin();
        }
        const next = dropIndex(ev.clientX, ev.clientY, card);
        if (next !== index) index = next;
        preview(ev);
      };

      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        card.classList.remove('dragging');
        document.body.classList.remove('dragging-widget');
        if (ghost) { ghost.remove(); ghost = null; }
        if (moved && index >= 0) {
          const others = visible().filter((c) => c !== card);
          grid.insertBefore(card, others[index] || null);
          save();
        }
        layout();
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
    vh.title = 'Drag to resize height · double-click to match the tallest card in the row';
    card.appendChild(vh);
    // Double-click levels this card with the tallest one beside it.
    vh.addEventListener('dblclick', (e) => {
      e.preventDefault();
      const target = rowTallest(card);
      markSized(card);
      setHeight(card, target);
      layout(); save();
    });
    vh.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      markSized(card);
      const startY = e.clientY;
      const startH = card.offsetHeight;
      const natural = contentHeight(card); // measured once — it forces a reflow
      const move = (ev) => {
        const raw = Math.max(96, startH + (ev.clientY - startY));
        const snapped = applySnap(card, raw, natural);
        setHeight(card, snapped.h);
        layout();
        showGuide(snapped.hit ? (parseFloat(card.style.top) || 0) + snapped.h : null);
      };
      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        showGuide(null);
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
