// The one list of signed-in pages, in nav order.
//
// Three things need it and they run at different moments: prefs-init.js in
// <head>, before paint, to decide whether "/" should redirect somewhere else;
// nav.js at the end of <body>, to build the menu; settings.js, to offer them
// as home-page choices. Keeping the list here means adding a page is one line,
// and — more importantly — the home-page allowlist cannot drift out of step
// with the menu, which would let "/" redirect to a route that no longer exists.
//
// Icons stay in nav.js: they are large SVG strings and only the menu needs them.
//
// [path, label, canBeHome]. The third field defaults to true; false keeps the
// page in the menu but out of the home-page choices.
//
// Settings is false: it is somewhere you go to change something and then
// leave, not somewhere to land every time you open certguard.
//
// /status is absent entirely. It is the public page, it is off unless the
// operator enables it, and a home page that 404s the moment that switch is
// turned off is a trap. nav.js adds it separately when the server says it
// exists.
window.CG_PAGES = [
  ['/', 'Dashboard'],
  ['/inventory', 'Inventory'],
  ['/timeline', 'Timeline'],
  ['/coverage', 'Coverage'],
  ['/issuers', 'Issuers'],
  ['/activity', 'Activity'],
  ['/settings', 'Settings', false],
];
