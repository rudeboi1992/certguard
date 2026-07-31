// Apply the saved theme before the page paints, to avoid a light/dark flash.
// Externalised (rather than an inline <script>) so the Content-Security-Policy
// can stay strict: script-src 'self' with no inline-script allowance.
try {
  var t = localStorage.getItem('certguard-theme');
  if (t) document.documentElement.setAttribute('data-theme', t);
} catch (e) {}
