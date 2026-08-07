// The topbar's page links, rendered from one list so a new page means one
// entry here rather than an edit to every HTML file.
//
// Loaded before common.js, which binds #logout unguarded — the button is part
// of this nav, so it has to exist by then. Deliberately self-contained (no $,
// no escapeHtml): nothing here is user data, and depending on common.js would
// invert that load order.
//
// Icons or words is a per-browser preference. Both are always in the markup
// and CSS shows one or the other, so switching needs no re-render and the
// accessible name (title + aria-label) is the same either way.
(function () {
  var nav = document.getElementById('mainNav');
  if (!nav) return;

  var S = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">';
  var ICONS = {
    // Four panes — the dashboard is a grid of cards.
    dashboard: S + '<rect x="3.2" y="3.2" width="7.4" height="7.4" rx="1.6"/><rect x="13.4" y="3.2" width="7.4" height="7.4" rx="1.6"/><rect x="3.2" y="13.4" width="7.4" height="7.4" rx="1.6"/><rect x="13.4" y="13.4" width="7.4" height="7.4" rx="1.6"/></svg>',
    // Rows with markers — a list of things.
    inventory: S + '<path d="M8.5 6h12M8.5 12h12M8.5 18h12"/><circle cx="4.2" cy="6" r="1.3" fill="currentColor" stroke="none"/><circle cx="4.2" cy="12" r="1.3" fill="currentColor" stroke="none"/><circle cx="4.2" cy="18" r="1.3" fill="currentColor" stroke="none"/></svg>',
    settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    // Door with an arrow leaving it.
    signout: S + '<path d="M9.5 20.2H5.4a1.8 1.8 0 0 1-1.8-1.8V5.6a1.8 1.8 0 0 1 1.8-1.8h4.1"/><path d="M15.6 16.4 20 12l-4.4-4.4"/><path d="M20 12H9.5"/></svg>',
  };

  var ITEMS = [
    { href: '/', label: 'Dashboard', icon: ICONS.dashboard },
    { href: '/inventory', label: 'Inventory', icon: ICONS.inventory },
    { href: '/settings', label: 'Settings', icon: ICONS.settings },
  ];

  var path = window.location.pathname;
  var html = '';
  for (var i = 0; i < ITEMS.length; i++) {
    var it = ITEMS[i];
    // "/" would prefix-match everything, so it only counts as current when the
    // path is exactly "/".
    var current = it.href === '/' ? path === '/' : path.indexOf(it.href) === 0;
    html += '<a class="nav-btn nav-item' + (current ? ' current' : '') + '" href="' + it.href + '"'
      + (current ? ' aria-current="page"' : '')
      + ' title="' + it.label + '" aria-label="' + it.label + '">'
      + it.icon + '<span class="nav-label">' + it.label + '</span></a>';
  }
  html += '<button id="logout" type="button" class="nav-btn nav-item" title="Sign out" aria-label="Sign out">'
    + ICONS.signout + '<span class="nav-label">Sign out</span></button>';
  nav.innerHTML = html;
})();
