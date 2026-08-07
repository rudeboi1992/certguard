// Apply the saved per-browser preferences before the page paints: theme, nav
// style, and which page "/" lands on. All three have to happen here rather
// than in common.js, because each of them is visible — a late theme is a
// white flash, a late nav style flashes the labels on and off, and a late home
// redirect renders the dashboard before replacing it.
//
// Externalised (rather than an inline <script>) so the Content-Security-Policy
// can stay strict: script-src 'self' with no inline-script allowance.
//
// These are deliberately per-browser, not per-account: they are presentation,
// they match how the theme has always worked, and storing them server-side
// would mean a schema migration and an API for something that never leaves the
// browser. The settings card says so.
(function () {
  var ls;
  try { ls = window.localStorage; } catch (e) { return; } // private mode, etc.

  try {
    var theme = ls.getItem('certguard-theme');
    if (theme) document.documentElement.setAttribute('data-theme', theme);
  } catch (e) {}

  try {
    // "menu" (a Navigation dropdown) by default; "icons" and "text" lay the
    // same list out inline instead.
    var nav = ls.getItem('certguard-nav');
    document.documentElement.setAttribute('data-nav',
      nav === 'text' || nav === 'icons' ? nav : 'menu');
  } catch (e) {}

  try {
    // Only ever redirects from "/" itself, so there is no loop, /login is
    // untouched, and every other page loads normally. replace() rather than
    // assign() keeps the Back button working: it would otherwise bounce off
    // "/" straight back to the chosen page.
    if (window.location.pathname !== '/') return;
    var home = homePath(ls.getItem('certguard-home'));
    if (home && home !== '/') window.location.replace(home);
  } catch (e) {}

  // Resolve a stored preference to a path, or '' if it is not a page we serve.
  //
  // The allowlist matters: this value is fed to location.replace(), and
  // accepting it verbatim would turn anything that can write localStorage into
  // an open redirect — including a "javascript:" URL. Only the routes in
  // CG_PAGES are ever followed.
  function homePath(v) {
    if (!v) return '';
    // Older builds stored "dashboard"/"inventory" rather than a path.
    if (v === 'dashboard') return '/';
    if (v === 'inventory') return '/inventory';
    var pages = window.CG_PAGES || [];
    for (var i = 0; i < pages.length; i++) {
      // pages[i][2] === false marks a page that may not be a home page, so a
      // value left over from before it was excluded stops being followed.
      if (pages[i][0] === v) return pages[i][2] === false ? '' : v;
    }
    return '';
  }
})();
