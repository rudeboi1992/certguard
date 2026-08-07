// The topbar's page links, defined once here so a new page is one entry
// rather than an edit to every HTML file.
//
// Loaded before common.js, which binds #logout unguarded — the button lives in
// this nav, so it has to exist by then. Deliberately self-contained (no $, no
// escapeHtml): nothing here is user data, and depending on common.js would
// invert that load order.
//
// One set of markup serves all three presentations, chosen by data-nav on
// <html> (written by prefs-init.js before paint):
//   menu  — a "Navigation" disclosure button; the list drops down (default)
//   icons — the list inline, icons only
//   text  — the list inline, words only
// Switching is therefore a CSS swap with no re-render, and the accessible name
// of every item is the same in all three.
//
// This is a disclosure button, not role="menu". W3C guidance is that site
// navigation should stay plain links: role="menu" implies application-style
// arrow-key semantics that a nav does not have, and it would be wrong in the
// two inline modes where nothing is a popup at all.
(function () {
  var mount = document.getElementById('mainNav');
  if (!mount) return;

  var S = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">';
  var ICONS = {
    dashboard: S + '<rect x="3.2" y="3.2" width="7.4" height="7.4" rx="1.6"/><rect x="13.4" y="3.2" width="7.4" height="7.4" rx="1.6"/><rect x="3.2" y="13.4" width="7.4" height="7.4" rx="1.6"/><rect x="13.4" y="13.4" width="7.4" height="7.4" rx="1.6"/></svg>',
    inventory: S + '<path d="M8.5 6h12M8.5 12h12M8.5 18h12"/><circle cx="4.2" cy="6" r="1.3" fill="currentColor" stroke="none"/><circle cx="4.2" cy="12" r="1.3" fill="currentColor" stroke="none"/><circle cx="4.2" cy="18" r="1.3" fill="currentColor" stroke="none"/></svg>',
    timeline: S + '<rect x="3.2" y="4.6" width="17.6" height="16.2" rx="2.2"/><path d="M3.2 9.4h17.6M8.2 2.8v3.4M15.8 2.8v3.4"/><circle cx="8.4" cy="13.6" r="1.15" fill="currentColor" stroke="none"/><circle cx="15.6" cy="17" r="1.15" fill="currentColor" stroke="none"/></svg>',
    issuers: S + '<path d="M12 2.8 4.4 6v5.6c0 4.4 3.1 8.1 7.6 9.6 4.5-1.5 7.6-5.2 7.6-9.6V6z"/><path d="M9.2 12.1l1.9 1.9 3.7-3.9"/></svg>',
    coverage: S + '<circle cx="12" cy="12" r="8.9"/><path d="M3.1 12h17.8"/><path d="M12 3.1a13.6 13.6 0 0 1 0 17.8 13.6 13.6 0 0 1 0-17.8z"/></svg>',
    activity: S + '<path d="M2.9 12.4h4l2.5-6.6 4.2 12.5 2.5-5.9h5"/></svg>',
    status: S + '<path d="M12 3.3a8.7 8.7 0 1 1-6.2 2.6"/><path d="M12 7.6V12l3 1.9"/></svg>',
    settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    signout: S + '<path d="M9.5 20.2H5.4a1.8 1.8 0 0 1-1.8-1.8V5.6a1.8 1.8 0 0 1 1.8-1.8h4.1"/><path d="M15.6 16.4 20 12l-4.4-4.4"/><path d="M20 12H9.5"/></svg>',
    menu: S + '<path d="M3.8 6.5h16.4M3.8 12h16.4M3.8 17.5h16.4"/></svg>',
    caret: S + '<path d="M6.2 9.3 12 15.1l5.8-5.8"/></svg>',
  };

  // The routes come from pages.js so the menu and the home-page allowlist
  // cannot drift apart. The icon key is the path with its slash removed
  // ("/inventory" → inventory); "/" is the dashboard.
  var ITEMS = (window.CG_PAGES || []).map(function (p) {
    return { href: p[0], label: p[1], icon: ICONS[p[0] === '/' ? 'dashboard' : p[0].slice(1)] || ICONS.dashboard };
  });

  var path = window.location.pathname;
  function itemHtml(it) {
    // "/" would prefix-match every path, so it is current only when exact.
    var current = it.href === '/' ? path === '/' : path.indexOf(it.href) === 0;
    return '<a class="nav-btn nav-item' + (current ? ' current' : '') + '" href="' + it.href + '"'
      + (current ? ' aria-current="page"' : '')
      + ' title="' + it.label + '" aria-label="' + it.label + '">'
      + it.icon + '<span class="nav-label">' + it.label + '</span></a>';
  }

  mount.innerHTML =
    '<button type="button" id="navTrigger" class="nav-btn nav-trigger" aria-expanded="false"'
    + ' aria-controls="navPanel" aria-label="Navigation">'
    + ICONS.menu + '<span class="nav-trigger-l">Navigation</span>'
    + '<span class="nav-caret">' + ICONS.caret + '</span></button>'
    + '<div class="nav-panel" id="navPanel">'
    + ITEMS.map(itemHtml).join('')
    + '<button id="logout" type="button" class="nav-btn nav-item" title="Sign out" aria-label="Sign out">'
    + ICONS.signout + '<span class="nav-label">Sign out</span></button>'
    + '</div>';

  // Pages can add a link that only exists in some configurations — the public
  // status page is off unless the server enables it, and nav.js runs long
  // before we know that.
  window.navAddItem = function (href, label, iconName) {
    var panel = document.getElementById('navPanel');
    if (!panel || panel.querySelector('a[href="' + href + '"]')) return;
    var tmp = document.createElement('div');
    tmp.innerHTML = itemHtml({ href: href, label: label, icon: ICONS[iconName] || ICONS.status });
    panel.insertBefore(tmp.firstChild, document.getElementById('logout'));
  };

  // --- disclosure behaviour (menu mode only; the CSS hides the trigger
  // otherwise, and a display:none button cannot be clicked or focused) ---
  var wrap = mount;
  var trigger = document.getElementById('navTrigger');
  var panel = document.getElementById('navPanel');
  var closeTimer = null;
  // Hover opens the menu; a click pins it so it survives the pointer leaving.
  // Without the distinction, clicking the trigger on a desktop would toggle
  // shut the menu that hovering had just opened — you move the mouse there, it
  // opens, you click, it closes, and the button reads as broken.
  var pinned = false;

  function setOpen(open) {
    wrap.classList.toggle('open', open);
    trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
  function open() { clearTimeout(closeTimer); setOpen(true); }
  function close() { clearTimeout(closeTimer); pinned = false; setOpen(false); }

  trigger.addEventListener('click', function (e) {
    e.stopPropagation();
    // Closing only ever happens on a click that was itself the pin — or via
    // Escape, an outside click, or the pointer leaving an unpinned menu.
    // Keyboard users land here too: a <button> fires click on Enter and Space.
    if (pinned) { close(); return; }
    pinned = true;
    open();
  });

  // Hover only where hovering is real. A touch device reports no hover, and
  // wiring mouseenter there produces a menu that opens on the tap and closes
  // on the synthetic mouse events that follow it.
  var canHover = false;
  try { canHover = window.matchMedia('(hover: hover) and (pointer: fine)').matches; } catch (e) {}
  if (canHover) {
    wrap.addEventListener('mouseenter', open);
    // A small delay: the pointer often clips the corner of the panel on its
    // way from the trigger to an item, and closing instantly on that is the
    // classic unusable dropdown. A pinned menu ignores the pointer entirely.
    wrap.addEventListener('mouseleave', function () {
      if (pinned) return;
      clearTimeout(closeTimer);
      closeTimer = setTimeout(close, 220);
    });
  }

  document.addEventListener('click', function (e) {
    if (!wrap.contains(e.target)) close();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && wrap.classList.contains('open')) {
      close();
      trigger.focus();
    }
  });
  // Tabbing out of the menu should close it, the same as clicking away.
  wrap.addEventListener('focusout', function (e) {
    if (!wrap.contains(e.relatedTarget)) close();
  });
  panel.addEventListener('click', function (e) {
    if (e.target.closest('a')) close(); // let the navigation happen
  });
})();
