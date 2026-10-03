// base.js — deployment base-path support (self-host extension).
// index.html sets <script>window.BT_BASE='/temp'</script> before this; the
// default for upstream/Worker deploys is '' (root mount), byte-identical URLs.
// All fetch/URL construction in api.js/app.js/stars.js goes through btUrl().
(function () {
  let base = '';
  try {
    base = typeof window !== 'undefined' && typeof window.BT_BASE === 'string' ? window.BT_BASE : '';
  } catch { /* no window (tests) — keep '' */ }
  if (base.endsWith('/')) base = base.slice(0, -1);
  if (typeof window !== 'undefined') window.__btBase = base;
})();

/** Join the deployment base with an absolute root path ('/api/…', '/p/…'). */
export function btUrl(path) {
  const base = typeof window !== 'undefined' ? (window.__btBase || '') : '';
  return base + path;
}
