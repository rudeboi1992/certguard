// Widget grid with explicit placement: every card owns a column, a row, a width
// in columns and a height in row units, and stays exactly where it was put.
// Supports drag-to-place, drag-the-edges to resize, hide (×) + "Add section",
// and persists the arrangement per browser.
//
// This replaced a masonry packer that derived positions from card order. It was
// denser, but a move recomputed every position, so nudging one card reshuffled
// others and a deliberate gap could not survive — the layout was never quite
// where you left it.
function initWidgetGrid(grid, storageKey, opts) {
  opts = opts || {};
  if (!grid) return;
  const addButton = opts.addButton || null;
  const addDialog = opts.addDialog || null;
  const addGrid = opts.addGrid || null;
  const resetBtn = opts.resetBtn || null;
  const tidyBtn = opts.tidyBtn || null;
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

  // --- explicit grid placement ---
  //
  // Every card owns a rectangle: a column (0-based), a row, a width in columns
  // and a height in row units. Nothing is derived from DOM order, so a card
  // stays exactly where it was put. The masonry packer this replaces recomputed
  // every position from scratch whenever anything changed, so moving one card
  // reshuffled several others and there was no way to leave a deliberate gap.
  //
  // ROW is the vertical pitch including the gutter, so a card h rows tall is
  // h*ROW - GAP pixels and the gap below falls out of the arithmetic.
  const ROW = 20;
  const MIN_H = 5;  // 80px — less than this leaves no room for the card's own bar

  const numAttr = (c, k, dflt) => {
    const v = parseInt(c.dataset[k], 10);
    return Number.isFinite(v) ? v : dflt;
  };
  const wOf = (c) => Math.max(1, Math.min(COLS, numAttr(c, 'w', spanOf(c))));
  const colOf = (c) => Math.max(0, Math.min(COLS - wOf(c), numAttr(c, 'col', 0)));
  const rowOf = (c) => Math.max(0, numAttr(c, 'row', 0));
  const hOf = (c) => Math.max(MIN_H, numAttr(c, 'h', 12));
  const rectOf = (c) => ({ c: colOf(c), r: rowOf(c), w: wOf(c), h: hOf(c) });
  const isPlaced = (c) => c.dataset.col !== undefined && c.dataset.row !== undefined;

  function setRect(card, r) {
    const w = Math.max(1, Math.min(COLS, r.w));
    const col = Math.max(0, Math.min(COLS - w, r.c));
    card.dataset.col = col;
    card.dataset.row = Math.max(0, r.r);
    card.dataset.w = w;
    card.dataset.h = Math.max(MIN_H, r.h);
    card.dataset.span = w; // the width handle and the arranger still read span
  }

  const overlaps = (a, b) =>
    a.c < b.c + b.w && b.c < a.c + a.w && a.r < b.r + b.h && b.r < a.r + a.h;

  // Push whatever the moved card now sits on top of downwards, and whatever
  // those in turn land on. Only ever downwards: moving one card must not haul
  // unrelated cards upward into space the user deliberately left empty.
  function resolve(moved) {
    const others = visible().filter((c) => c !== moved);
    const rects = new Map(others.map((c) => [c, rectOf(c)]));
    const movedR = rectOf(moved);
    let guard = (others.length + 1) * COLS + 16;
    let again = true;
    while (again && guard-- > 0) {
      again = false;
      const all = [[moved, movedR]].concat(others.map((c) => [c, rects.get(c)]));
      for (const pair of all) {
        for (const other of all) {
          if (pair[0] === other[0] || other[0] === moved) continue; // moved never yields
          if (!overlaps(pair[1], other[1])) continue;
          other[1].r = pair[1].r + pair[1].h;
          again = true;
        }
      }
    }
    others.forEach((c) => setRect(c, rects.get(c)));
  }

  function metrics() {
    const cw = grid.clientWidth;
    const cols = cw < 640 ? 1 : COLS;
    return { cw, cols, colW: (cw - GAP * (cols - 1)) / cols };
  }

  let scheduled = false;
  function relayout() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => { scheduled = false; layout(); });
  }

  function layout() {
    const m = metrics();
    const cards = visible();
    // One column: columns and row units stop meaning anything, so stack in
    // reading order at natural height. A phone cannot honour a four-column
    // arrangement, and forcing row heights there only makes cards scroll
    // inside themselves.
    if (m.cols === 1) {
      let top = 0;
      cards.slice()
        .sort((a, b) => rowOf(a) - rowOf(b) || colOf(a) - colOf(b))
        .forEach((c) => {
          c.style.left = '0px';
          c.style.top = top + 'px';
          c.style.width = m.cw + 'px';
          c.style.height = '';
          c.style.maxHeight = 'none';
          top += c.offsetHeight + GAP;
        });
      grid.style.height = Math.max(0, top - GAP) + 'px';
      if (!grid.classList.contains('ready')) requestAnimationFrame(() => grid.classList.add('ready'));
      return;
    }
    let bottom = 0;
    for (const c of cards) {
      const r = rectOf(c);
      c.style.left = Math.round(r.c * (m.colW + GAP)) + 'px';
      c.style.top = (r.r * ROW) + 'px';
      c.style.width = Math.round(r.w * m.colW + (r.w - 1) * GAP) + 'px';
      c.style.height = (r.h * ROW - GAP) + 'px';
      c.style.maxHeight = 'none';
      bottom = Math.max(bottom, (r.r + r.h) * ROW);
      heights.set(c.id, r.h * ROW - GAP);
    }
    grid.style.height = Math.max(0, bottom - GAP) + 'px';
    if (!grid.classList.contains('ready')) requestAnimationFrame(() => grid.classList.add('ready'));
  }

  // The tallest a card may be sized automatically. "Fit the content" has to be
  // bounded, because some cards' content is unbounded: the calendar's is a full
  // twelve-month year and the tracked list's is every entry, so fitting them
  // literally produced cards well over 1500px that pushed everything else off
  // the screen and made the page one enormous scroll. Past this the card keeps
  // the height and its body scrolls, which is what the old engine's 78vh cap
  // did before heights became explicit.
  const maxAutoRows = () => Math.max(MIN_H, Math.floor((window.innerHeight * 0.78) / ROW));

  // How many rows a card needs to show its content.
  //
  // The cap applies to *automatic* sizing only — first placement and the
  // migration from the old format — where an unbounded fit produced cards well
  // over 1500px that buried everything below them. It must not apply when the
  // user double-clicks the bottom edge: that is an explicit "fit this", and
  // stopping at 78% of the window means the content still scrolls, which reads
  // as the card refusing to snap to the right place. Asked directly, fit
  // exactly; the card can always be dragged smaller afterwards.
  function contentRows(card, capped) {
    const prevH = card.style.height, prevMax = card.style.maxHeight;
    card.style.height = 'auto';
    card.style.maxHeight = 'none';
    const need = card.offsetHeight;
    card.style.height = prevH;
    card.style.maxHeight = prevMax;
    const want = Math.ceil((need + GAP) / ROW);
    return Math.max(MIN_H, capped === false ? want : Math.min(maxAutoRows(), want));
  }

  // --- persistence ---
  function save() {
    const pos = {};
    const hidden = [];
    for (const c of widgets()) {
      pos[c.id] = rectOf(c);
      if (c.classList.contains('widget-off')) hidden.push(c.id);
    }
    try { localStorage.setItem(storageKey, JSON.stringify({ v: 2, pos, hidden })); } catch (e) {}
  }
  // A card's height is a row count now, so the old pixel helpers — fit to
  // content, follow another card, snap to a neighbour — are gone. Dragging the
  // bottom edge sets rows directly, and "fit to content" is a double-click.

  function apply() {
    let data;
    try { data = JSON.parse(localStorage.getItem(storageKey) || 'null'); } catch (e) {}
    if (!data && opts.defaults) data = opts.defaults;
    if (data) {
      if (data.pos) {
        for (const id in data.pos) {
          const el = document.getElementById(id);
          if (el) setRect(el, data.pos[id]);
        }
      } else {
        // A layout saved by the masonry version: order + spans + pixel heights.
        // Flow it into rectangles once, so an existing arrangement stays
        // recognisable instead of being reset to the shipped default.
        migrate(data);
      }
      const known = new Set(data.pos ? Object.keys(data.pos) : (data.order || []));
      const hidden = new Set(data.hidden || []);
      widgets().forEach((c) => {
        if (hidden.has(c.id)) c.classList.add('widget-off');
        else if (known.has(c.id)) c.classList.remove('widget-off');
      });
    }
    // Anything still unplaced — a card shipped by a later release, or a first
    // run without defaults — goes below everything else rather than on top of
    // it, sized to its own content.
    placeUnplaced();
    refreshAdd();
    layout();
  }

  function migrate(data) {
    const order = (data.order || widgets().map((c) => c.id));
    const bottoms = new Array(COLS).fill(0);
    order.forEach((id) => {
      const el = document.getElementById(id);
      if (!el) return;
      const w = Math.max(1, Math.min(COLS, (data.spans || {})[id] || spanOf(el)));
      const px = (data.heights || {})[id];
      const h = px ? Math.max(MIN_H, Math.ceil((px + GAP) / ROW)) : contentRows(el);
      let best = 0, bestTop = Infinity;
      for (let c = 0; c + w <= COLS; c++) {
        const top = Math.max.apply(null, bottoms.slice(c, c + w));
        if (top < bestTop) { bestTop = top; best = c; }
      }
      setRect(el, { c: best, r: bestTop, w: w, h: h });
      for (let c = best; c < best + w; c++) bottoms[c] = bestTop + h;
    });
  }

  function placeUnplaced() {
    let bottom = visible().filter(isPlaced)
      .reduce((m, c) => Math.max(m, rowOf(c) + hOf(c)), 0);
    for (const c of visible()) {
      if (isPlaced(c)) continue;
      setRect(c, { c: 0, r: bottom, w: Math.max(1, Math.min(COLS, spanOf(c))), h: contentRows(c) });
      bottom += hOf(c);
    }
  }

  // Pull every card up into the vertical gaps, keeping its column and width.
  //
  // This is the one action that reclaims space, and it is deliberately opt-in
  // (the Tidy button): an ordinary drag leaves the gap you made on purpose, so
  // the layout stays where you put it. Tidy is for when you want the holes gone.
  //
  // Cards are packed top-to-bottom against a per-column running bottom, so each
  // one only rises to rest on whatever is above it in its own columns. Two cards
  // that shared a row and had the same thing above them still share a row after,
  // because they settle onto the same bottom — alignment survives.
  function compact() {
    const placed = visible().filter(isPlaced)
      .sort((a, b) => rowOf(a) - rowOf(b) || colOf(a) - colOf(b));
    const colBottom = new Array(COLS).fill(0);
    for (const c of placed) {
      const r = rectOf(c);
      let top = 0;
      for (let x = r.c; x < r.c + r.w; x++) top = Math.max(top, colBottom[x]);
      setRect(c, { c: r.c, r: top, w: r.w, h: r.h });
      for (let x = r.c; x < r.c + r.w; x++) colBottom[x] = top + r.h;
    }
    save();
    layout();
  }

  // Give a just-shown card a position that overlaps nothing. Its stored spot is
  // kept when still free — so hiding and immediately re-adding a card leaves it
  // where it was — but a card with no position, or one whose old spot is now
  // taken, drops below everything, exactly where placeUnplaced puts a new one.
  // The card must already be visible (widget-off removed) so contentRows can
  // measure it.
  function placeIntoFreeSpace(card) {
    const others = visible().filter((x) => x !== card);
    const clashes = !isPlaced(card) ||
      others.some((x) => isPlaced(x) && overlaps(rectOf(card), rectOf(x)));
    if (!clashes) return;
    const bottom = others.filter(isPlaced)
      .reduce((m, x) => Math.max(m, rowOf(x) + hOf(x)), 0);
    setRect(card, { c: 0, r: bottom, w: Math.max(1, Math.min(COLS, spanOf(card))), h: contentRows(card) });
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
    addGrid.innerHTML = '';
    if (!off.length) {
      addGrid.innerHTML = '<p class="muted">Every section is already on the dashboard.</p>';
      return;
    }
    for (const c of off) {
      const tile = document.createElement('div');
      // Not a <button>: the preview clones real card bodies, which contain form
      // controls, and interactive content nested in a button is invalid and
      // swallows clicks. role + keyboard handler give the same behaviour.
      tile.className = 'section-card';
      tile.setAttribute('role', 'button');
      tile.tabIndex = 0;
      tile.dataset.add = c.id;
      tile.appendChild(sectionPreview(c));
      const meta = document.createElement('span');
      meta.className = 'section-card-meta';
      meta.innerHTML =
        `<span class="section-card-title">${escapeHtml(c.dataset.title || c.id)}</span>` +
        `<span class="section-card-desc">${escapeHtml(c.dataset.desc || '')}</span>`;
      tile.appendChild(meta);
      const add = () => {
        c.classList.remove('widget-off');
        // Placing it is not optional. Hiding a card only sets widget-off and
        // leaves its grid position behind, and a card that was never shown has
        // none at all (rectOf then reads 0,0). Handing either straight to
        // layout() drops it on top of whatever now sits there — the overlap
        // this fixes — so give it a clear spot first.
        placeIntoFreeSpace(c);
        refreshAdd(); save(); layout();
        if (!addGrid.querySelector('[data-add]') && addDialog && addDialog.open) addDialog.close();
        c.scrollIntoView({ block: 'center', behavior: 'smooth' });
      };
      tile.addEventListener('click', add);
      tile.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); add(); }
      });
      addGrid.appendChild(tile);
    }
  }

  // Illustrative thumbnails. Cloning the live body was honest but useless for
  // exactly the cards worth previewing: Problems, Security audit and Scan
  // health are all a single "✓ nothing wrong" line on a healthy install, so the
  // picker showed an empty box for the sections that matter most. These samples
  // use each renderer's own markup and classes, so they look like the real card
  // in the state you'd want to be warned about. Anything without a sample —
  // Add, Tracked, Calendar — still clones its live body, which is always
  // populated and recognisable.
  // 0.6 renders the sample at ~1.7x tile width, close to a real card column, and
  // keeps the pill text legible — the point is to read the outcome, not just
  // recognise a shape.
  const PREVIEW_SCALE = 0.6;
  const row = (name, sub, pill, cls) =>
    `<div class="mini-row"><span class="mini-name">${name}` +
    (sub ? `<br><span class="muted small">${sub}</span>` : '') +
    `</span><span class="pill ${cls}">${pill}</span></div>`;
  const SAMPLES = {
    'w-soon':
      row('vpn.example.com', '', '3 days', 'urgent') +
      row('Cloudflare API token', '', '11 days', 'warn') +
      row('*.internal.lan', '', '24 days', 'notice') +
      row('billing.example.com', '', '29 days', 'notice'),
    'w-problems':
      row('legacy.example.com', 'legacy.example.com:8443', 'self-signed', 'untrusted') +
      row('mail.example.com', 'mail.example.com:993', 'expired', 'untrusted') +
      row('vpn.example.com', 'vpn.example.com:443', 'hostname mismatch', 'untrusted'),
    'w-nextup':
      '<div class="nextup"><div class="nextup-num urgent">3 days</div>' +
      '<div class="nextup-name">vpn.example.com</div>' +
      '<div class="muted small">2026-08-07</div></div>',
    'w-issuers':
      ['Let\'s Encrypt 24', 'DigiCert Inc 6', 'Google Trust 3', 'Internal CA 1']
        .map((s, i) => {
          const n = s.split(' ').pop();
          return `<div class="kv"><span class="kv-label">${s.slice(0, -n.length - 1)}</span>` +
            `<span class="kv-bar"><span style="width:${[100, 25, 13, 4][i]}%"></span></span>` +
            `<span class="kv-num">${n}</span></div>`;
        }).join(''),
    'w-audit':
      `<div class="mini-row"><span class="mini-name">legacy.example.com</span>` +
      `<span class="audit-flags"><span class="pill warn">weak key (RSA-1024)</span></span></div>` +
      `<div class="mini-row"><span class="mini-name">old-appliance.lan</span>` +
      `<span class="audit-flags"><span class="pill warn">weak signature</span></span></div>` +
      `<div class="mini-row"><span class="mini-name">*.internal.lan</span>` +
      `<span class="audit-flags"><span class="pill warn">long validity (825d)</span></span></div>`,
    'w-scanhealth':
      row('mail.example.com', 'mail.example.com:993', 'connection refused', 'untrusted') +
      row('nas.internal.lan', 'nas.internal.lan:5001', 'checked 6d ago', 'notice') +
      row('backup.example.com', 'backup.example.com:443', 'never checked', 'notice'),
    'w-renewals':
      `<div class="mini-row"><span class="mini-name">www.example.com</span>` +
      `<span class="muted small mini-date">exp 2026-11-04</span>` +
      `<span class="pill ok">issued 2d ago</span></div>` +
      `<div class="mini-row"><span class="mini-name">api.example.com</span>` +
      `<span class="muted small mini-date">exp 2026-11-01</span>` +
      `<span class="pill ok">issued 5d ago</span></div>` +
      `<div class="mini-row"><span class="mini-name">*.internal.lan</span>` +
      `<span class="muted small mini-date">exp 2027-01-19</span>` +
      `<span class="pill ok">issued 11d ago</span></div>`,
    'w-alerts':
      row('vpn.example.com', '3-day alert → email, slack', 'today', 'urgent') +
      row('Cloudflare API token', '7-day alert → email', 'in 4d', 'notice') +
      row('*.internal.lan', '30-day alert → webhook', 'in 9d', 'notice'),
    'w-scheduler':
      '<div class="kv2"><span class="muted">Auto-scan</span><span><span class="pill ok">on</span> · every 6h</span></div>' +
      '<div class="kv2"><span class="muted">Last scan</span><span>18m ago</span></div>' +
      '<div class="kv2"><span class="muted">Next scan</span><span>in 5h</span></div>' +
      '<button class="btn primary small" tabindex="-1">Scan all now</button>',
    'w-notes':
      '<div class="notes-input" style="min-height:0;padding:.6rem .7rem">' +
      'Renew the wildcard before the 12th — Sam has the DNS token.<br><br>' +
      'FortiGate contract quote: see ticket #4192.</div>',
  };

  function sectionPreview(card) {
    const box = document.createElement('span');
    box.className = 'section-card-preview';
    const inner = document.createElement('span');
    inner.className = 'section-card-preview-inner';
    inner.style.width = (100 / PREVIEW_SCALE) + '%';
    inner.style.transform = `scale(${PREVIEW_SCALE})`;
    inner.setAttribute('aria-hidden', 'true');
    if (SAMPLES[card.id]) {
      inner.innerHTML = SAMPLES[card.id];
    } else {
      const body = card.querySelector('.widget-body');
      if (!body) return box;
      const clone = body.cloneNode(true);
      // Ids would duplicate live ones and break getElementById across the page.
      clone.removeAttribute('id');
      clone.querySelectorAll('[id]').forEach((n) => n.removeAttribute('id'));
      // A long list would clone hundreds of rows for a box that shows a few.
      clone.querySelectorAll('.trow').forEach((r, i) => { if (i >= 6) r.remove(); });
      clone.querySelectorAll('input, select, textarea, button, a').forEach((n) => { n.tabIndex = -1; });
      inner.appendChild(clone);
    }
    box.appendChild(inner);
    return box;
  }

  // --- hide / add / reset ---
  grid.querySelectorAll('.widget-hide').forEach((b) =>
    b.addEventListener('click', () => {
      b.closest('.widget').classList.add('widget-off');
      refreshAdd(); save(); layout();
    }));
  if (addButton && addDialog) {
    // Focus the dialog, not its × — see the note in openDetail().
    addButton.addEventListener('click', () => { refreshAdd(); addDialog.showModal(); addDialog.focus(); });
    addDialog.addEventListener('click', (e) => { if (e.target === addDialog) addDialog.close(); });
    const close = addDialog.querySelector('#addSectionClose');
    if (close) close.addEventListener('click', () => addDialog.close());
  }
  if (tidyBtn) tidyBtn.addEventListener('click', () => compact());
  if (resetBtn) resetBtn.addEventListener('click', () => {
    try { localStorage.removeItem(storageKey); } catch (e) {}
    location.reload();
  });

  // --- auto-scroll while dragging near a window edge ---
  // Dragging a card to a row that is off screen would otherwise be impossible:
  // the pointer hits the edge of the window and stops. While it is held within
  // EDGE pixels of the top or bottom, scroll the page and tell the drag how far
  // we moved, so it can keep its arithmetic in terms of the document rather
  // than the viewport.
  const EDGE = 60;
  let edgeTimer = 0, edgeY = 0, edgeCb = null;
  function edgeTrack(y) { edgeY = y; }
  function edgeScrollOn(cb, y) {
    edgeCb = cb; edgeY = y;
    if (edgeTimer) return;
    edgeTimer = setInterval(() => {
      const h = window.innerHeight;
      let d = 0;
      if (edgeY < EDGE) d = -Math.ceil((EDGE - edgeY) / 6);
      else if (edgeY > h - EDGE) d = Math.ceil((edgeY - (h - EDGE)) / 6);
      if (!d) return;
      const before = window.scrollY;
      window.scrollBy(0, d);
      const actual = window.scrollY - before; // clamped at the ends of the page
      if (actual && edgeCb) edgeCb(actual);
    }, 16);
  }
  function edgeScrollOff() {
    clearInterval(edgeTimer);
    edgeTimer = 0; edgeCb = null;
  }

  // --- drag to place ---
  // The card follows the pointer and an outline shows the cell it would occupy.
  // Nothing else moves until release, and then only cards the drop lands on,
  // which are pushed straight down. That is the whole point of the rewrite:
  // where a card ends up is where you dropped it.
  function cellAt(clientX, clientY, r) {
    const m = metrics();
    const box = grid.getBoundingClientRect();
    const col = Math.round((clientX - box.left) / (m.colW + GAP));
    const row = Math.round((clientY - box.top) / ROW);
    return { c: Math.max(0, Math.min(COLS - r.w, col)), r: Math.max(0, row), w: r.w, h: r.h };
  }

  grid.querySelectorAll('.widget-drag').forEach((handle) => {
    handle.addEventListener('pointerdown', (e) => {
      if (e.button !== 0) return;
      if (metrics().cols === 1) return; // single column: nothing to place
      e.preventDefault();
      const card = handle.closest('.widget');
      const start = rectOf(card);
      const box = card.getBoundingClientRect();
      const grabX = e.clientX - box.left, grabY = e.clientY - box.top;
      const x0 = e.clientX, y0 = e.clientY;
      const left0 = parseFloat(card.style.left) || 0;
      const top0 = parseFloat(card.style.top) || 0;
      let moved = false, ghost = null, target = start;
      let lastX = e.clientX, lastY = e.clientY, autoScrolled = 0;

      const begin = () => {
        moved = true;
        card.classList.add('dragging');
        document.body.classList.add('dragging-widget');
        ghost = document.createElement('div');
        ghost.className = 'widget-ghost';
        grid.appendChild(ghost);
      };

      const paint = (delta) => {
        if (delta) autoScrolled += delta;
        if (!moved) return;
        // The cell is taken from the card's top-left corner, not the pointer,
        // so where you grabbed it does not change where it lands.
        target = cellAt(lastX - grabX, lastY - grabY + autoScrolled, start);
        const m = metrics();
        ghost.style.left = Math.round(target.c * (m.colW + GAP)) + 'px';
        ghost.style.top = (target.r * ROW) + 'px';
        ghost.style.width = Math.round(target.w * m.colW + (target.w - 1) * GAP) + 'px';
        ghost.style.height = (target.h * ROW - GAP) + 'px';
        card.style.left = (left0 + lastX - x0) + 'px';
        card.style.top = (top0 + lastY - y0 + autoScrolled) + 'px';
      };

      let raf = 0;
      const move = (ev) => {
        lastX = ev.clientX; lastY = ev.clientY;
        if (!moved && Math.hypot(ev.clientX - x0, ev.clientY - y0) < 4) return;
        if (!moved) begin();
        edgeTrack(ev.clientY);
        if (raf) return;                       // one repaint per frame
        raf = requestAnimationFrame(() => { raf = 0; paint(0); });
      };
      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        edgeScrollOff();
        if (raf) cancelAnimationFrame(raf);
        card.classList.remove('dragging');
        document.body.classList.remove('dragging-widget');
        if (ghost) ghost.remove();
        if (moved) {
          setRect(card, target);
          resolve(card);
          save();
        }
        layout();
      };
      edgeScrollOn(paint, e.clientY);
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
    });
  });

  // A blue dashed outline (the same one the move drag uses) that previews a
  // resize target. Resizing shows this rather than mutating the card on every
  // pixel: reflowing the whole grid under the pointer was jumpy, and the card's
  // final size is clearer as an outline that lands on release.
  function makeGhost() {
    const g = document.createElement('div');
    g.className = 'widget-ghost';
    grid.appendChild(g);
    return g;
  }
  function placeGhost(g, r) {
    const m = metrics();
    g.style.left = Math.round(r.c * (m.colW + GAP)) + 'px';
    g.style.top = (r.r * ROW) + 'px';
    g.style.width = Math.round(r.w * m.colW + (r.w - 1) * GAP) + 'px';
    g.style.height = (r.h * ROW - GAP) + 'px';
  }

  // --- drag the right edge to resize width (1–4 columns) ---
  grid.querySelectorAll('.widget-resize').forEach((h) => {
    h.addEventListener('pointerdown', (e) => {
      if (metrics().cols === 1) return;
      e.preventDefault();
      const card = h.closest('.widget');
      const startX = e.clientX;
      const start = rectOf(card);
      const m = metrics();
      const startW = start.w * m.colW + (start.w - 1) * GAP;
      let target = start;
      const ghost = makeGhost();
      placeGhost(ghost, start);
      const move = (ev) => {
        const px = startW + (ev.clientX - startX);
        const w = Math.max(1, Math.min(COLS - start.c, Math.round((px + GAP) / (m.colW + GAP))));
        target = { c: start.c, r: start.r, w: w, h: start.h };
        placeGhost(ghost, target);
      };
      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        ghost.remove();
        setRect(card, target); resolve(card); save(); layout();
      };
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
    });
  });

  // --- drag the bottom edge to resize height (in row units) ---
  widgets().forEach((card) => {
    if (!card.querySelector('.widget-resize') || card.querySelector('.widget-resize-v')) return;
    const vh = document.createElement('span');
    vh.className = 'widget-resize-v';
    vh.title = 'Drag to resize height · double-click to fit the content';
    card.appendChild(vh);

    // Double-click fits the card to its own content — the height where nothing
    // scrolls inside and no space is wasted below. This is uncapped on purpose:
    // it is an explicit "fit this", so an unusually tall card is honoured rather
    // than clipped at the automatic ceiling. Aligning a card with its neighbours
    // is now the Tidy button's job, which is more predictable than the old
    // double-click that could silently shrink a card to match the one beside it.
    vh.addEventListener('dblclick', (ev) => {
      ev.preventDefault();
      const r = rectOf(card);
      setRect(card, { c: r.c, r: r.r, w: r.w, h: contentRows(card, false) });
      resolve(card); layout(); save();
    });

    vh.addEventListener('pointerdown', (e) => {
      if (metrics().cols === 1) return;
      e.preventDefault();
      const start = rectOf(card);
      const startY = e.clientY;
      const startPx = start.h * ROW - GAP;
      let lastY = e.clientY, autoScrolled = 0, target = start;
      const ghost = makeGhost();
      placeGhost(ghost, start);
      const paint = (delta) => {
        if (delta) autoScrolled += delta;
        // Height follows the pointer plus the scrolling WE did — never
        // window.scrollY. Shrinking the last card shortens the document, the
        // browser clamps the scroll position, and reading scrollY fed that
        // back in as more shrinking.
        const px = startPx + (lastY - startY) + autoScrolled;
        const h = Math.max(MIN_H, Math.round((px + GAP) / ROW));
        target = { c: start.c, r: start.r, w: start.w, h: h };
        placeGhost(ghost, target);
      };
      const move = (ev) => { lastY = ev.clientY; edgeTrack(ev.clientY); paint(0); };
      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        edgeScrollOff();
        ghost.remove();
        setRect(card, target); resolve(card); save(); layout();
      };
      edgeScrollOn(paint, e.clientY);
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
    });

    // Bottom-right corner: resize width AND height in one drag, so a card can be
    // reshaped without two separate pulls at two separate edges. It sits in the
    // 12×14px notch the right and bottom edge handles leave for it.
    const cg = document.createElement('span');
    cg.className = 'widget-resize-c';
    cg.title = 'Drag to resize';
    card.appendChild(cg);
    cg.addEventListener('pointerdown', (e) => {
      if (metrics().cols === 1) return;
      e.preventDefault();
      const start = rectOf(card);
      const m = metrics();
      const startX = e.clientX, startY = e.clientY;
      const startWpx = start.w * m.colW + (start.w - 1) * GAP;
      const startHpx = start.h * ROW - GAP;
      let lastX = e.clientX, lastY = e.clientY, autoScrolled = 0, target = start;
      const ghost = makeGhost();
      placeGhost(ghost, start);
      const paint = (delta) => {
        if (delta) autoScrolled += delta;
        const wpx = startWpx + (lastX - startX);
        const hpx = startHpx + (lastY - startY) + autoScrolled;
        const w = Math.max(1, Math.min(COLS - start.c, Math.round((wpx + GAP) / (m.colW + GAP))));
        const h = Math.max(MIN_H, Math.round((hpx + GAP) / ROW));
        target = { c: start.c, r: start.r, w: w, h: h };
        placeGhost(ghost, target);
      };
      const move = (ev) => { lastX = ev.clientX; lastY = ev.clientY; edgeTrack(ev.clientY); paint(0); };
      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        edgeScrollOff();
        ghost.remove();
        setRect(card, target); resolve(card); save(); layout();
      };
      edgeScrollOn(paint, e.clientY);
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
    });
  });

  // Heights are explicit now, so content changing size no longer moves
  // anything — the card scrolls inside its own box. Only a width change
  // matters, because the column width is derived from the container.
  window.addEventListener('resize', relayout);

  apply();

  // Handle for tools that drive the grid from outside — the zoomed-out
  // arranger. Everything it needs already exists in here as a closure; this
  // only makes it reachable, so placement and persistence keep one
  // implementation.
  return {
    cards: () => widgets().map((c) => {
      const r = rectOf(c);
      return {
        id: c.id,
        title: c.dataset.title || c.id,
        col: r.c, row: r.r, span: r.w, rows: r.h,
        hidden: c.classList.contains('widget-off'),
      };
    }),
    columns: COLS,
    place(id, rect) {
      const c = document.getElementById(id);
      if (!c) return;
      setRect(c, rect);
      resolve(c);
    },
    setHidden(id, off) {
      const c = document.getElementById(id);
      if (!c) return;
      c.classList.toggle('widget-off', !!off);
      // Showing a card has to place it, exactly as the Add-section picker does.
      // Hiding only sets widget-off and leaves the old position behind, and a
      // card that was never shown has none at all (rectOf then reads 0,0) — so
      // without this the arranger drops it straight onto the top-left card.
      // Must run after the class is off, so contentRows can measure it.
      if (!off) placeIntoFreeSpace(c);
      refreshAdd();
    },
    compact() { compact(); },
    commit() { layout(); save(); },
  };
}
