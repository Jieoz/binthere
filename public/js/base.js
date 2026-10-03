// base.js — deployment base-path support (self-host extension).
// The mount point comes from <html data-bt-base="/temp"> — a data attribute,
// not an inline script, because the CSP (script-src 'self') forbids inline JS.
// Absent attribute (upstream/Worker deploys) → '' → byte-identical URLs.
// All fetch/URL construction in api.js/app.js/stars.js goes through btUrl().
(function () {
  let base = '';
  try {
    if (typeof document !== 'undefined') {
      base = document.documentElement.getAttribute('data-bt-base') || '';
    }
  } catch { /* no document (tests) — keep '' */ }
  if (base.endsWith('/')) base = base.slice(0, -1);
  if (typeof window !== 'undefined') window.__btBase = base;
})();

/** Join the deployment base with an absolute root path ('/api/…', '/p/…'). */
export function btUrl(path) {
  const base = typeof window !== 'undefined' ? (window.__btBase || '') : '';
  return base + path;
}
