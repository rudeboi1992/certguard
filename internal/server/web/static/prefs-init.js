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
    // Icons by default; "text" restores the worded links.
    var nav = ls.getItem('certguard-nav');
    document.documentElement.setAttribute('data-nav', nav === 'text' ? 'text' : 'icons');
  } catch (e) {}

  try {
    // Only ever redirects from "/" itself, so there is no loop, /login is
    // untouched, and every other page loads normally. replace() rather than
    // assign() keeps the Back button working: it would otherwise bounce off
    // "/" straight back to the inventory.
    if (window.location.pathname === '/' && ls.getItem('certguard-home') === 'inventory') {
      window.location.replace('/inventory');
    }
  } catch (e) {}
})();
