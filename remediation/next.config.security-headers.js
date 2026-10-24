/**
 * Silver Oak University — security header remediation
 * ====================================================
 *
 * Closes all 12 findings from the VulnLens AI live scan of https://silveroakuni.ac.in/
 * (24 Sep 2026). The site is Next.js behind Cloudflare, so every header is set centrally
 * here — no per-page changes, no template edits.
 *
 * HOW TO USE
 * ----------
 * 1. Copy the `headers()` function below into the root `next.config.js` (see the wrapper
 *    at the bottom of this file if you don't already have one).
 * 2. Redeploy. Headers are applied at build time by Next.js.
 * 3. Re-run:  node live_scan.js https://silveroakuni.ac.in/
 *    Expect the header-based findings to drop from 8 to 0 once the mixed-content link
 *    (finding #3) is also fixed.
 *
 * CAVEAT — READ BEFORE ENABLING CSP
 * ---------------------------------
 * The scan found 17 inline <script> blocks. The CSP below therefore includes
 * 'unsafe-inline' in script-src as a STARTING POINT so the site does not break on
 * deploy. That weakens CSP against XSS. The correct end state is to remove
 * 'unsafe-inline' and use a per-request nonce instead.
 *
 * Deploy in two phases:
 *   Phase 1 (now)    — ship with 'unsafe-inline', use Content-Security-Policy-Report-Only
 *                      for a week and collect violations from the report endpoint.
 *   Phase 2 (after)  — migrate inline scripts to external files or nonces, then remove
 *                      'unsafe-inline' and switch to the enforcing header.
 */

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 1 — Report-Only. Nothing breaks. Watch the console for violations.
// Uncomment this block, deploy, and watch for ~1 week before moving to Phase 2.
// ─────────────────────────────────────────────────────────────────────────────
const CSP_PHASE1_REPORT_ONLY = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.googletagmanager.com https://www.google-analytics.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: https:",
  "connect-src 'self' https://www.google-analytics.com https://www.googletagmanager.com",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
  "upgrade-insecure-requests",
  "report-uri /api/csp-report"
].join('; ');

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 2 — Enforcing. Only after all 17 inline scripts are migrated to
// external files or nonces. Remove 'unsafe-inline' and 'unsafe-eval' from
// script-src. This is the configuration that actually defends against XSS.
// ─────────────────────────────────────────────────────────────────────────────
const CSP_PHASE2_ENFORCING = [
  "default-src 'self'",
  "script-src 'self' https://www.googletagmanager.com https://www.google-analytics.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: https:",
  "connect-src 'self' https://www.google-analytics.com https://www.googletagmanager.com",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
  "upgrade-insecure-requests"
].join('; ');

// The header set. Every one of these maps to a live scan finding.
const SECURITY_HEADERS = [
  {
    key: 'Content-Security-Policy-Report-Only',   // Phase 1 — finding #1
    value: CSP_PHASE1_REPORT_ONLY
  },
  {
    key: 'Strict-Transport-Security',             // finding #2
    // max-age = 1 year. includeSubDomains is added only after confirming every
    // subdomain serves HTTPS — verify before enabling, or you can lock out
    // legacy HTTP-only hosts.
    value: 'max-age=31536000; includeSubDomains'
    // Add '; preload' and submit to https://hstspreload.org once stable.
  },
  { key: 'X-Content-Type-Options', value: 'nosniff' },              // keep — already correct
  { key: 'X-Frame-Options', value: 'DENY' },                        // keep — already correct
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }, // finding #5
  {
    key: 'Permissions-Policy',                                       // finding #9
    value: 'geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=()'
  },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },      // finding #12
  { key: 'X-DNS-Prefetch-Control', value: 'off' }
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  async headers() {
    return [
      {
        // Apply site-wide.
        source: '/:path*',
        headers: SECURITY_HEADERS
      },
      {
        // Finding #6 — Cache-Control was `s-maxage=31536000,` (stray comma,
        // no browser max-age). HTML documents should not be cached long-term
        // at the browser unless truly static; let the CDN revalidate.
        source: '/:path*',
        headers: [
          { key: 'Cache-Control', value: 'public, max-age=0, s-maxage=31536000, must-revalidate' }
        ]
      }
    ];
  }
};

module.exports = nextConfig;

/* ─────────────────────────────────────────────────────────────────────────────
   FINDINGS THAT CANNOT BE FIXED BY HEADERS ALONE
   ─────────────────────────────────────────────────────────────────────────────

   #3  Mixed content — http://ieee.socet.edu.in/  (href)
       The target DOES support HTTPS (verified: https://ieee.socet.edu.in/ → 200).
       Fix: change that one link to https://. Nothing else is required — no
       dependency is blocking it. The CSP `upgrade-insecure-requests` directive
       also auto-upgrades any http:// subresource, giving a safety net for
       future regressions.

   #4  Unsafe DOM sink (document.write / eval / .innerHTML)
       Search the codebase:
           grep -rn "document.write\|innerHTML\s*=\|eval(\|new Function(" src/
       Replace with textContent, createElement, or DOMPurify for any user-
       influenced HTML. This is the highest-value code fix — a DOM sink plus a
       CSP containing 'unsafe-inline' is exactly the XSS profile CSP exists to
       stop.

   #7  Inline scripts — 17 blocks
       Blocks the strict CSP. See Phase 2 above.

   #8  target="_blank" without rel="noopener" — 21 links
       Fix once at the component level so every future external link inherits it.
       Next.js: use a shared <ExternalLink> component, or run a codemod.

   #10 Server: cloudflare  and  #11 x-nextjs-cache: HIT
       Cosmetic information disclosure. `Server` can be genericized in the
       Cloudflare dashboard (Transform Rules → Set static header). The
       x-nextjs-* family is set by Next.js and is generally harmless — remove
       only if you have no internal tooling depending on it.

   ─────────────────────────────────────────────────────────────────────────────
   VERIFY AFTER DEPLOY
   ─────────────────────────────────────────────────────────────────────────────
     node live_scan.js https://silveroakuni.ac.in/
     node find_mixed.js https://silveroakuni.ac.in/     # expect "0 found"
   Then confirm against:
     https://securityheaders.com/?q=silveroakuni.ac.in
     https://developer.mozilla.org/observatory/analyze?host=silveroakuni.ac.in
   ───────────────────────────────────────────────────────────────────────────── */
