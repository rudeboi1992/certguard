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

  // --- edge auto-scroll ---
  // A drag that reaches the bottom of the window used to stop there: you cannot
  // move the pointer any further, so a card near the foot of the page could not
  // be made taller. While the pointer sits in an edge band the page now scrolls,
  // and each frame re-applies the drag — the pointer is still, but the content
  // moves under it, so the card keeps growing. Speed ramps with depth into the
  // band so a nudge creeps and a firm push moves.
  // Speed ramps with the SQUARE of how far into the band the pointer is, and
  // tops out low. Resizing the last card on the page is a feedback loop — every
  // pixel it grows extends the document, which creates the scroll room for the
  // next frame — so it never runs out of room and whatever speed is set here is
  // simply how fast the card grows, indefinitely. A linear ramp at 24px/frame
  // meant ~1400px/s, far too fast to land on a size. Squared, the first third of
  // the band barely creeps and you have to push deliberately to go quickly.
  // Measured in pixels per SECOND, not per frame: a per-frame budget is silently
  // multiplied by the refresh rate, and on a 120Hz screen the same constant
  // moved twice as fast as intended. Fractional pixels are carried over between
  // frames too — scrollBy(0.4) rounds to nothing, so the shallow end of the band
  // did precisely nothing however long you held it there.
  const EDGE_BAND = 90, EDGE_SPEED = 300;
  let edgeRaf = null, edgePointerY = 0, edgeApply = null, edgeLast = 0, edgeAcc = 0;
  function edgeFrame(ts) {
    const dt = edgeLast ? Math.min(50, ts - edgeLast) : 16;
    edgeLast = ts;
    const h = window.innerHeight;
    let dir = 0, depth = 0;
    if (edgePointerY > h - EDGE_BAND) { dir = 1; depth = (edgePointerY - (h - EDGE_BAND)) / EDGE_BAND; }
    else if (edgePointerY < EDGE_BAND) { dir = -1; depth = (EDGE_BAND - edgePointerY) / EDGE_BAND; }
    if (dir) {
      // Squared ramp: the first third of the band creeps, and you have to push
      // deliberately to move quickly.
      edgeAcc += dir * Math.min(1, depth) ** 2 * EDGE_SPEED * (dt / 1000);
      const step = Math.trunc(edgeAcc);
      if (step) {
        edgeAcc -= step;
        const before = window.scrollY;
        window.scrollBy(0, step);
        // Report what actually moved. Callers add up only the scrolling we
        // asked for, never what the browser did on its own (see below).
        const moved = window.scrollY - before;
        if (moved && edgeApply) edgeApply(moved);
      }
    } else {
      edgeAcc = 0;
    }
    edgeRaf = requestAnimationFrame(edgeFrame);
  }
  function edgeScrollOn(apply, y) {
    edgeApply = apply; edgePointerY = y; edgeLast = 0; edgeAcc = 0;
    if (!edgeRaf) edgeRaf = requestAnimationFrame(edgeFrame);
  }
  const edgeTrack = (y) => { edgePointerY = y; };
  function edgeScrollOff() {
    if (edgeRaf) cancelAnimationFrame(edgeRaf);
    edgeRaf = null; edgeApply = null; edgeLast = 0; edgeAcc = 0;
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
      let lastX = e.clientX, lastY = e.clientY, autoScrolled = 0;

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

      const preview = () => {
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
        // The card itself tracks the pointer, offset from where it started,
        // plus any scrolling we performed — same reasoning as the height drag.
        card.style.left = (left0 + lastX - x0) + 'px';
        card.style.top = (top0 + lastY - y0 + autoScrolled) + 'px';
      };
      // Re-evaluated each auto-scroll frame: the pointer is still, but rows are
      // sliding past it, so the drop slot genuinely changes.
      const apply = (delta) => {
        if (delta) autoScrolled += delta;
        if (!moved) return;
        const next = dropIndex(lastX, lastY, card);
        if (next !== index) index = next;
        preview();
      };

      const move = (ev) => {
        lastX = ev.clientX; lastY = ev.clientY;
        edgeTrack(ev.clientY);
        if (!moved) {
          if (Math.abs(ev.clientX - x0) < 5 && Math.abs(ev.clientY - y0) < 5) return;
          begin();
        }
        apply();
      };

      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        edgeScrollOff();
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
      edgeScrollOn(apply, e.clientY);
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
      // Height tracks pointer movement plus the scrolling WE performed — never
      // window.scrollY directly. Shrinking the last card on the page makes the
      // document shorter, so the browser clamps the scroll position up, and
      // reading scrollY fed that back in as more shrinking: a 100px drag took
      // 294px off. Counting only deliberate auto-scroll breaks the loop.
      const startClientY = e.clientY;
      const startH = card.offsetHeight;
      const natural = contentHeight(card); // measured once — it forces a reflow
      let lastClientY = e.clientY, autoScrolled = 0;
      const apply = (delta) => {
        if (delta) autoScrolled += delta;
        const raw = Math.max(96, startH + (lastClientY - startClientY) + autoScrolled);
        const snapped = applySnap(card, raw, natural);
        setHeight(card, snapped.h);
        layout();
        showGuide(snapped.hit ? (parseFloat(card.style.top) || 0) + snapped.h : null);
      };
      const move = (ev) => { lastClientY = ev.clientY; edgeTrack(ev.clientY); apply(); };
      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        edgeScrollOff();
        showGuide(null);
        save();
      };
      edgeScrollOn(apply, e.clientY);
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
