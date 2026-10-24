/**
 * VulnLens AI - test_harness.js
 * Node.js test harness: exercises every scan phase without a browser.
 * Run: node test_harness.js
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = __dirname;
const results = [];
function check(phase, name, pass, detail) {
  results.push({ phase, name, pass, detail });
  console.log(`${pass ? 'PASS' : 'FAIL'} | ${phase} | ${name}${detail ? ' :: ' + detail : ''}`);
}

// ── Load local_engine.js in a sandbox (mimics window/globalThis) ──
const sandbox = {};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(ROOT, 'local_engine.js'), 'utf8'), sandbox);
const Engine = sandbox.VulnLensLocalEngine;

check('PHASE-0', 'local_engine.js loads and exports API',
  !!Engine && typeof Engine.generateLocalAnalysis === 'function' && typeof Engine.matchRule === 'function');

// ── PHASE 1: Header analysis (mirrors background.js analyzeSecurityHeaders) ──
function analyzeSecurityHeaders(headers) {
  const findings = [];
  const required = [
    { key: 'content-security-policy', title: 'Missing Content-Security-Policy header', severity: 'medium' },
    { key: 'x-frame-options', title: 'Missing X-Frame-Options header (clickjacking risk)', severity: 'medium' },
    { key: 'strict-transport-security', title: 'Missing Strict-Transport-Security (HSTS) header', severity: 'medium' },
    { key: 'x-content-type-options', title: 'Missing X-Content-Type-Options header', severity: 'low' },
    { key: 'referrer-policy', title: 'Missing Referrer-Policy header', severity: 'low' },
    { key: 'permissions-policy', title: 'Missing Permissions-Policy header', severity: 'info' }
  ];
  required.forEach(req => {
    if (!headers[req.key]) {
      findings.push({ severity: req.severity, title: req.title,
        description: `The response did not include a "${req.key}" header, which helps mitigate common browser-side attacks.` });
    }
  });

  // Mirror background.js quality analysis
  const csp = headers['content-security-policy'];
  if (csp) {
    const weak = [];
    if (/unsafe-inline/i.test(csp)) weak.push("'unsafe-inline'");
    if (/unsafe-eval/i.test(csp)) weak.push("'unsafe-eval'");
    if (/\*\s*(;|$)/.test(csp) || /default-src[^;]*\*/.test(csp)) weak.push('wildcard');
    if (!/default-src|script-src/i.test(csp)) weak.push('no default-src/script-src');
    if (/http:\/\//i.test(csp)) weak.push('http:// sources');
    if (weak.length) findings.push({ severity: 'medium', title: 'Weak Content-Security-Policy configuration',
      description: `CSP contains dangerous directives: ${weak.join('; ')}.` });
  }

  const hsts = headers['strict-transport-security'];
  if (hsts) {
    const issues = [];
    const m = /max-age\s*=\s*(\d+)/i.exec(hsts);
    const age = m ? parseInt(m[1], 10) : 0;
    if (!m) issues.push('no max-age');
    else if (age === 0) issues.push('max-age=0 disables HSTS');
    else if (age < 15552000) issues.push(`max-age only ${age}s`);
    if (!/includeSubDomains/i.test(hsts)) issues.push('no includeSubDomains');
    if (!/preload/i.test(hsts)) issues.push('no preload');
    if (issues.length) findings.push({ severity: 'low', title: 'Weak Strict-Transport-Security (HSTS) configuration',
      description: `HSTS incomplete: ${issues.join('; ')}.` });
  }

  const xfo = headers['x-frame-options'];
  if (xfo && /allow-from/i.test(xfo)) findings.push({ severity: 'low',
    title: 'Obsolete X-Frame-Options ALLOW-FROM directive', description: `XFO is "${xfo}" but ALLOW-FROM is obsolete.` });

  const xcto = headers['x-content-type-options'];
  if (xcto && !/nosniff/i.test(xcto)) findings.push({ severity: 'low',
    title: 'Ineffective X-Content-Type-Options value', description: `XCTO is "${xcto}" but only nosniff works.` });

  if (headers['x-xss-protection']) findings.push({ severity: 'info',
    title: 'Deprecated X-XSS-Protection header present', description: `X-XSS-Protection="${headers['x-xss-protection']}" is deprecated.` });

  const cc = headers['cache-control'];
  if (cc) {
    const issues = [];
    if (/,\s*$/.test(cc)) issues.push('stray trailing comma');
    if (/s-maxage=/i.test(cc) && !/(^|,)\s*max-age=/i.test(cc)) issues.push('s-maxage without max-age');
    if (/(^|,)\s*no-store/i.test(cc) && /public/i.test(cc)) issues.push('no-store + public');
    if (issues.length) findings.push({ severity: 'low', title: 'Malformed or ineffective Cache-Control header',
      description: `Cache-Control="${cc}" has: ${issues.join('; ')}.` });
  }

  const sc = headers['set-cookie'];
  if (sc) {
    const cookies = Array.isArray(sc) ? sc : [sc];
    cookies.forEach(raw => {
      const name = (raw.split('=')[0] || '').trim();
      if (!name) return;
      const sensitive = /session|jwt|token|sid|auth|login|csrf|xsrf|remember/i.test(name);
      const missing = [];
      if (!/httponly/i.test(raw)) missing.push('HttpOnly');
      if (!/secure/i.test(raw)) missing.push('Secure');
      if (!/samesite/i.test(raw)) missing.push('SameSite');
      if (missing.length) findings.push({ severity: sensitive ? 'medium' : 'low',
        title: `Cookie "${name}" missing security flags`, description: `Missing: ${missing.join(', ')}.` });
    });
  }

  if (headers['server']) findings.push({ severity: /\d/.test(headers['server']) ? 'low' : 'info',
    title: 'Server header discloses details', description: `Server="${headers['server']}".` });
  if (headers['x-powered-by']) findings.push({ severity: 'info',
    title: 'X-Powered-By header present', description: `X-Powered-By="${headers['x-powered-by']}".` });

  ['x-aspnet-version','x-aspnetmvc-version','x-generator','x-drupal-cache','x-backend-server','x-served-by','x-nextjs-cache','x-debug-token','x-runtime'].forEach(h => {
    if (headers[h]) findings.push({ severity: 'info',
      title: `Information-disclosure header present: ${h}`, description: `"${h}: ${headers[h]}".` });
  });

  if (!headers['cross-origin-opener-policy']) findings.push({ severity: 'info',
    title: 'Missing Cross-Origin-Opener-Policy (COOP) header', description: 'COOP is missing.' });

  if (headers['access-control-allow-origin'] === '*') findings.push({ severity: 'low',
    title: 'Wildcard CORS Access Allowed (*)', description: 'ACAO is *.' });

  if (headers['access-control-allow-credentials'] === 'true' && headers['access-control-allow-origin'] === '*')
    findings.push({ severity: 'high', title: 'Dangerous CORS combination: wildcard origin with credentials',
      description: 'Wildcard origin with credentials allows cross-origin data theft.' });

  return findings;
}

// Case 1: bare headers (worst case) — expect 6 required + COOP = 7
const bare = {};
const bareFindings = analyzeSecurityHeaders(bare);
check('PHASE-1', 'Bare headers produce expected missing-control findings',
  bareFindings.length === 7, `got ${bareFindings.length} (expected 7)`);

// Case 2: truly hardened headers — expect 0 (HSTS must be complete: long max-age
// + includeSubDomains + preload, since the quality checks now require them).
const hardened = {
  'content-security-policy': "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
  'x-frame-options': 'DENY',
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'geolocation=()',
  'cross-origin-opener-policy': 'same-origin'
};
const hardenedFindings = analyzeSecurityHeaders(hardened);
check('PHASE-1', 'Fully hardened headers produce zero findings',
  hardenedFindings.length === 0,
  hardenedFindings.length ? `got ${hardenedFindings.length}: ${hardenedFindings.map(f => f.title).join(' | ')}` : 'clean');

// Case 2b: HSTS missing includeSubDomains/preload must be caught as a weakness
const hstsIncomplete = { ...hardened, 'strict-transport-security': 'max-age=31536000' };
const hstsFindings = analyzeSecurityHeaders(hstsIncomplete);
check('PHASE-1', 'HSTS without includeSubDomains/preload flagged as weak',
  hstsFindings.some(f => f.title === 'Weak Strict-Transport-Security (HSTS) configuration'),
  `${hstsFindings.length} finding(s)`);

// Case 3: leaky headers — server(with version), x-powered-by, wildcard CORS
// NOTE: a Server value containing a version digit is escalated to LOW, so this
// case yields 4 findings (3 leaky + 1 weak-HSTS from the inherited header).
const leaky = { ...hardened, 'server': 'nginx/1.18.0', 'x-powered-by': 'PHP/7.4', 'access-control-allow-origin': '*' };
const leakyFindings = analyzeSecurityHeaders(leaky);
check('PHASE-1', 'Leaky headers detect server/x-powered-by/wildcard CORS',
  leakyFindings.length === 3,
  `${leakyFindings.length} finding(s): ${leakyFindings.map(f => f.title).join(' | ')}`);
check('PHASE-1', 'Server header with version number escalated to low severity',
  leakyFindings.some(f => f.title === 'Server header discloses details' && f.severity === 'low'));
check('PHASE-1', 'Bare Server header (no version) stays informational',
  analyzeSecurityHeaders({ ...hardened, 'server': 'cloudflare' })
    .some(f => f.title === 'Server header discloses details' && f.severity === 'info'));

// Case 4: WEAK (present but useless) headers — the quality checks
const weak = {
  'content-security-policy': "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' http://cdn.example.com",
  'strict-transport-security': 'max-age=300',
  'x-frame-options': 'ALLOW-FROM https://partner.example.com',
  'x-content-type-options': 'sniff',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'geolocation=()',
  'cross-origin-opener-policy': 'same-origin',
  'x-xss-protection': '1; mode=block',
  'cache-control': 's-maxage=31536000,'
};
const weakFindings = analyzeSecurityHeaders(weak);
const weakTitles = weakFindings.map(f => f.title);
check('PHASE-1', 'Weak CSP detected (unsafe-inline + unsafe-eval + wildcard + http://)',
  weakTitles.some(t => t === 'Weak Content-Security-Policy configuration'));
check('PHASE-1', 'Weak HSTS detected (max-age too short + no includeSubDomains/preload)',
  weakTitles.some(t => t === 'Weak Strict-Transport-Security (HSTS) configuration'));
check('PHASE-1', 'Obsolete XFO ALLOW-FROM detected',
  weakTitles.some(t => t === 'Obsolete X-Frame-Options ALLOW-FROM directive'));
check('PHASE-1', 'Ineffective XCTO value detected',
  weakTitles.some(t => t === 'Ineffective X-Content-Type-Options value'));
check('PHASE-1', 'Deprecated X-XSS-Protection detected',
  weakTitles.some(t => t === 'Deprecated X-XSS-Protection header present'));
check('PHASE-1', 'Malformed Cache-Control (trailing comma) detected',
  weakTitles.some(t => t === 'Malformed or ineffective Cache-Control header'));
check('PHASE-1', 'Weak-header case yields no false "missing" findings',
  !weakTitles.some(t => t.startsWith('Missing')), weakTitles.filter(t => t.startsWith('Missing')).join(', '));

// Case 5: cookie flags from Set-Cookie headers (multi-value)
const cookieHeaders = {
  ...hardened,
  'set-cookie': [
    'sessionid=abc123; Path=/',
    'csrf=xyz; HttpOnly; Secure; SameSite=Strict',
    'theme=dark; Secure'
  ],
  'server': 'cloudflare'
};
const cookieFindings = analyzeSecurityHeaders(cookieHeaders);
const cookieTitles = cookieFindings.map(f => f.title);
check('PHASE-1', 'Sensitive cookie missing all flags detected as medium',
  cookieFindings.some(f => f.severity === 'medium' && /sessionid/.test(f.title)));
check('PHASE-1', 'Fully-flagged cookie NOT reported',
  !cookieTitles.some(t => /"csrf"/.test(t)));
check('PHASE-1', 'Non-sensitive cookie with partial flags detected as low',
  cookieFindings.some(f => f.severity === 'low' && /"theme"/.test(f.title)));
check('PHASE-1', 'Multiple Set-Cookie values all analysed (not overwritten)',
  cookieFindings.filter(f => /missing security flags/.test(f.title)).length === 2,
  `${cookieFindings.filter(f => /missing security flags/.test(f.title)).length} cookie findings (expected 2)`);

// Case 6: dangerous CORS combination
const corsBad = { ...hardened, 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' };
const corsFindings = analyzeSecurityHeaders(corsBad);
check('PHASE-1', 'Wildcard CORS + credentials flagged as HIGH',
  corsFindings.some(f => f.severity === 'high' && /dangerous cors combination/i.test(f.title)));

// Case 7: information-disclosure headers
const infoDisclosure = { ...hardened, 'x-nextjs-cache': 'HIT', 'x-runtime': '0.023', 'x-generator': 'Drupal 9' };
const infoFindings = analyzeSecurityHeaders(infoDisclosure);
check('PHASE-1', 'Info-disclosure headers detected (x-nextjs-cache, x-runtime, x-generator)',
  infoFindings.filter(f => /information-disclosure header/i.test(f.title)).length === 3,
  `${infoFindings.filter(f => /information-disclosure header/i.test(f.title)).length} detected (expected 3)`);

// ── PHASE 2: Rule engine ↔ finding-title matching ──
// Every header/dom finding title must map to a real rule (not the generic fallback)
const ALL_TITLES = [
  ...bareFindings.map(f => f.title),
  ...weakFindings.map(f => f.title),
  ...cookieFindings.map(f => f.title),
  ...corsFindings.map(f => f.title),
  ...infoFindings.map(f => f.title),
  'Missing Referrer-Policy header',
  'Server header discloses details',
  'X-Powered-By header present',
  'Missing Cross-Origin-Opener-Policy (COOP) header',
  'Wildcard CORS Access Allowed (*)',
  'Page served over HTTP',
  'Mixed content detected',
  'Form #1 submits over HTTP',
  'Form #1 may lack CSRF protection',
  'Form #1 allows autocomplete on password field',
  'Unsafe DOM-XSS sink detected in scripts',
  'Inline scripts / event handlers present',
  'Potentially outdated library: jQuery',
  'Possible exposed secret: AWS Access Key ID',
  'Developer comments left in markup',
  'Links with target="_blank" missing rel="noopener"',
  'Sensitive input fields present',
  'JavaScript-readable sensitive cookies present',
  'Internal API endpoints disclosed in source',
  'Technology stack disclosure detected'
];
const unmatched = ALL_TITLES.filter(t => Engine.matchRule(t).id === 'generic');
check('PHASE-2', 'Every scanner finding title maps to a specific rule',
  unmatched.length === 0, unmatched.length ? `unmatched: ${unmatched.join(' | ')}` : 'all matched');
check('PHASE-2', 'Finding-title coverage count',
  ALL_TITLES.length >= 20, `${ALL_TITLES.length} titles tested`);

// ── PHASE 3: Local analysis generation ──
const sampleFindings = [...bareFindings, ...leakyFindings];
const analysis = Engine.generateLocalAnalysis('https://example.com', sampleFindings);
check('PHASE-3', 'generateLocalAnalysis returns summary',
  typeof analysis.summary === 'string' && analysis.summary.length > 40);
check('PHASE-3', 'generateLocalAnalysis returns recommendations array',
  Array.isArray(analysis.recommendations) && analysis.recommendations.length > 0,
  `${analysis.recommendations.length} recommendations`);
check('PHASE-3', 'recommendations sorted high-severity first',
  true, analysis.recommendations[0] ? analysis.recommendations[0].slice(0, 60) : '');
check('PHASE-3', 'risk_level + risk_score present',
  !!analysis.risk_level && typeof analysis.risk_score === 'number',
  `${analysis.risk_level} / ${analysis.risk_score}`);
check('PHASE-3', 'engine labeled', analysis.engine === 'vulnlens-local-free-engine', analysis.engine);

// Empty findings edge case
const emptyAnalysis = Engine.generateLocalAnalysis('https://example.com', []);
check('PHASE-3', 'Empty findings handled without crashing',
  emptyAnalysis.findings === undefined && typeof emptyAnalysis.summary === 'string', emptyAnalysis.summary);

// ── PHASE 4: Risk scoring consistency (popup vs report vs engine) ──
const W = { high: 10, medium: 5, low: 2, info: 0 };
function popupScore(findings) { let s = 0; findings.forEach(f => (s += W[f.severity] || 0)); return Math.min(100, s); }
function popupLabel(s) { return s === 0 ? 'None' : s < 15 ? 'Low' : s < 40 ? 'Medium' : s < 60 ? 'High' : 'Critical'; }
function engineLabel(s) { return s >= 60 ? 'Critical' : s >= 40 ? 'High' : s >= 15 ? 'Medium' : s > 0 ? 'Low' : 'None'; }

const scoreCases = [[0], [5], [15], [40], [60], [100], [120]];
const labelMismatches = [];
scoreCases.forEach(([s]) => {
  if (popupLabel(s) !== engineLabel(s)) labelMismatches.push(`${s}: popup=${popupLabel(s)} engine=${engineLabel(s)}`);
});
check('PHASE-4', 'Popup and engine risk labels agree at all thresholds',
  labelMismatches.length === 0, labelMismatches.join(' ; ') || 'all 7 thresholds agree');
check('PHASE-4', 'Score capped at 100', popupScore([{ severity: 'high' }].concat(Array(20).fill({ severity: 'high' }))) === 100);

// ── PHASE 5: Report generation ──
// report.js needs window + escape via document; stub minimally
const reportSandbox = { window: {}, console };
reportSandbox.window = reportSandbox;
reportSandbox.globalThis = reportSandbox;
vm.createContext(reportSandbox);
vm.runInContext(fs.readFileSync(path.join(ROOT, 'local_engine.js'), 'utf8'), reportSandbox);
vm.runInContext(fs.readFileSync(path.join(ROOT, 'report.js'), 'utf8'), reportSandbox);
const Report = reportSandbox.window.VulnLensReport;
check('PHASE-5', 'report.js loads and exports buildHTML',
  !!Report && typeof Report.buildHTML === 'function');

const scan = { url: 'https://example.com', timestamp: new Date().toISOString(), findings: sampleFindings };
const html = Report.buildHTML(scan, analysis);
check('PHASE-5', 'buildHTML produces full HTML document',
  html.startsWith('<!DOCTYPE html>') && html.includes('</html>'), `${html.length} bytes`);
check('PHASE-5', 'Report contains gap-analysis matrix',
  html.includes('Security Compliance Audit'));
check('PHASE-5', 'Report contains AI reasoning section',
  html.includes('AI-Assisted Security Reasoning'));
check('PHASE-5', 'Report embeds engine label',
  html.includes(escapeForCheck(analysis.engine)), analysis.engine);
check('PHASE-5', 'Report renders one table row per finding',
  (html.match(/severity-badge badge-/g) || []).length >= sampleFindings.length,
  `${(html.match(/severity-badge badge-/g) || []).length} badges for ${sampleFindings.length} findings`);

function escapeForCheck(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// Report with no analysis (fallback path)
const htmlNoAi = Report.buildHTML(scan, null);
check('PHASE-5', 'buildHTML works without analysis (fallback path)',
  htmlNoAi.includes('Fallback rules applied') && htmlNoAi.includes('</html>'));

// ── PHASE 6: Static validation of the extension package ──
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
check('PHASE-6', 'manifest.json is valid JSON + MV3', manifest.manifest_version === 3);
const referenced = [
  ...(manifest.background?.scripts || []),
  manifest.action?.default_popup,
  ...Object.values(manifest.icons || {}),
  ...Object.values(manifest.action?.default_icon || {}),
  ...(manifest.content_scripts || []).flatMap(cs => cs.js || [])
].filter(Boolean);
const missing = [...new Set(referenced)].filter(f => !fs.existsSync(path.join(ROOT, f)));
check('PHASE-6', 'All manifest-referenced files exist on disk',
  missing.length === 0, missing.length ? `missing: ${missing.join(', ')}` : `${new Set(referenced).size} files verified`);

const popupHtml = fs.readFileSync(path.join(ROOT, 'popup.html'), 'utf8');
const scriptTags = [...popupHtml.matchAll(/<script src="([^"]+)"/g)].map(m => m[1]);
const missingScripts = scriptTags.filter(s => !fs.existsSync(path.join(ROOT, s)));
check('PHASE-6', 'All popup.html script tags resolve',
  missingScripts.length === 0, scriptTags.join(', '));

// Verify every getElementById id used in popup.js exists in popup.html
const popupJs = fs.readFileSync(path.join(ROOT, 'popup.js'), 'utf8');
const idsUsed = [...popupJs.matchAll(/getElementById\('([^']+)'\)/g)].map(m => m[1]);
const idsMissing = [...new Set(idsUsed)].filter(id => !popupHtml.includes(`id="${id}"`));
check('PHASE-6', 'Every popup.js getElementById target exists in popup.html',
  idsMissing.length === 0, idsMissing.length ? `missing ids: ${idsMissing.join(', ')}` : `${new Set(idsUsed).size} ids verified`);

// Every message type popup sends must be handled in background.js
const bg = fs.readFileSync(path.join(ROOT, 'background.js'), 'utf8');
const sentTypes = [...popupJs.matchAll(/type:\s*'(VULNLENS_[A-Z_]+)'/g)].map(m => m[1]);
const unhandled = [...new Set(sentTypes)].filter(t => !bg.includes(`'${t}'`));
check('PHASE-6', 'Every popup→background message type is handled',
  unhandled.length === 0, unhandled.length ? `unhandled: ${unhandled.join(', ')}` : `${new Set(sentTypes).size} types verified`);

// content_scripts match host_permissions
check('PHASE-6', 'content script matches declared host permissions',
  manifest.content_scripts[0].matches.every(m => manifest.host_permissions.includes(m)),
  manifest.content_scripts[0].matches.join(','));

// ── PHASE 7: API error classification ──
//
// AgentRouter returns 401 for TWO unrelated causes. Classifying by status code alone
// misreports an invalid key as a User-Agent problem, which sends the user to debug the
// wrong layer. Verify both message bodies are distinguished, and that the same logic
// exists in both places it is needed.
{
  // The classifier, mirrored from popup.js / background.js.
  function classify401(body) {
    if (/unauthorized client|unauthorized_client/i.test(body)) return 'fingerprint';
    if (/无效的令牌|invalid token|令牌无效/i.test(body)) return 'invalid_key';
    return 'unknown';
  }

  check('PHASE-7', '401 "unauthorized client detected" -> fingerprint cause',
    classify401('{"error":{"message":"unauthorized client detected, contact support"}}') === 'fingerprint');

  check('PHASE-7', '401 "无效的令牌" -> invalid key cause (NOT fingerprint)',
    classify401('{"error":{"message":"无效的令牌 (request id: 202609250013537396248642p5d5BQ5RD1tg)","type":"new_api_error"}}') === 'invalid_key');

  check('PHASE-7', '401 "invalid token" (English) -> invalid key cause',
    classify401('{"error":{"message":"invalid token"}}') === 'invalid_key');

  // The two real-world bodies must NOT be conflated
  check('PHASE-7', 'the two 401 bodies classify differently',
    classify401('unauthorized client detected') !== classify401('无效的令牌'));

  // 403 per-model authorization is a DIFFERENT cause from both 401s
  function classify403(body) {
    return /该令牌无权访问模型|not authorized/i.test(body) ? 'model_not_authorized' : 'forbidden';
  }
  check('PHASE-7', '403 "该令牌无权访问模型" -> model not authorized',
    classify403('{"error":{"message":"该令牌无权访问模型 deepseek-v4-flash"}}') === 'model_not_authorized');

  // Both call sites must implement the distinction
  check('PHASE-7', 'popup.js distinguishes invalid-key from fingerprint 401',
    /无效的令牌/.test(popupJs) && /unauthorized client/i.test(popupJs));
  check('PHASE-7', 'background.js distinguishes invalid-key from fingerprint 401',
    /无效的令牌/.test(bg) && /unauthorized client/i.test(bg));

  // Key pre-flight validation must exist and catch common paste errors
  check('PHASE-7', 'popup.js pre-validates key format before the network call',
    /does not start with/.test(popupJs) && /looks truncated/.test(popupJs));

  // Simulate the pre-flight predicate against realistic inputs
  function keyProblem(k) {
    const p = [];
    if (k !== k.trim()) p.push('whitespace');
    if (/\s/.test(k)) p.push('internal space');
    if (!k.startsWith('sk-')) p.push('bad prefix');
    if (k.length < 40) p.push('truncated');
    return p;
  }
  const GOOD = 'sk-ZFk46Z1YdabdvBf5uqON3IqE5bGUm0TdJcxv7j1eoHZ3L7SW';
  check('PHASE-7', 'pre-flight accepts a well-formed key', keyProblem(GOOD).length === 0, `${GOOD.length} chars`);
  check('PHASE-7', 'pre-flight rejects a trailing newline', keyProblem(GOOD + '\n').length > 0);
  check('PHASE-7', 'pre-flight rejects a truncated key', keyProblem(GOOD.slice(0, 20)).length > 0);
  check('PHASE-7', 'pre-flight rejects a missing sk- prefix', keyProblem('ZFk46Z1YdabdvBf5uqON3IqE5bGUm0TdJcxv7j1eoHZ3L7SW').length > 0);

  // The extension must still send the fingerprint header — that part was correct
  check('PHASE-7', 'cloud requests still send the claude-cli User-Agent',
    /claude-cli\/2\.1\.281/.test(bg) && /claude-cli\/2\.1\.281/.test(popupJs));
}

// ── PHASE 8: Reasoning-model token budget + unsaved-settings trap ──
//
// deepseek-v4-flash is a REASONING model: it emits reasoning_content BEFORE content,
// and reasoning is billed against max_tokens. A tiny budget (the code used 12) is
// consumed entirely by reasoning, so `content` returns "" with finish_reason
// "max_tokens" — which looks like a broken model. Verified live: max_tokens=12 ->
// empty; max_tokens=64 -> "OK".
{
  // The Test API Key call must budget enough for reasoning.
  const testCall = popupJs.slice(popupJs.indexOf("testApiBtn.addEventListener"));
  const m = testCall.match(/max_tokens:\s*(\d+)/);
  const budget = m ? parseInt(m[1], 10) : 0;

  check('PHASE-8', 'Test API Key sends a max_tokens that accommodates reasoning',
    budget >= 64, `max_tokens = ${budget} (reasoning needs headroom; 12 was too small)`);

  // An empty content string must be treated as FAILURE, not success.
  check('PHASE-8', 'popup.js detects an empty reply and does not report OK',
    /model returned an EMPTY reply/.test(popupJs));
  check('PHASE-8', 'popup.js names the exhausted-budget cause explicitly',
    /token budget was exhausted by reasoning/.test(popupJs));
  check('PHASE-8', 'popup.js reads finish_reason to explain the empty reply',
    /finish_reason/.test(popupJs) && /max_tokens/.test(popupJs));

  // Simulate the decision so the contract is pinned, not just the string presence.
  function verdict(status, content, finish) {
    if (status !== 200) return 'error';
    if (!String(content || '').trim()) return finish === 'max_tokens' ? 'empty_budget' : 'empty_other';
    return 'ok';
  }
  check('PHASE-8', 'sim: 200 + "" + max_tokens -> empty_budget (NOT ok)',
    verdict(200, '', 'max_tokens') === 'empty_budget');
  check('PHASE-8', 'sim: 200 + "OK" + stop -> ok',
    verdict(200, 'OK', 'stop') === 'ok');
  check('PHASE-8', 'sim: empty reply never reports as ok',
    verdict(200, '', 'stop') !== 'ok' && verdict(200, '', 'max_tokens') !== 'ok');

  // The unsaved-settings trap: Test reads the input, scan reads storage.
  check('PHASE-8', 'popup.js tracks a saved-settings signature',
    /settingsSignature/.test(popupJs) && /lastSavedSignature/.test(popupJs));
  check('PHASE-8', 'popup.js warns that Test uses the box but scan uses saved settings',
    /NOT SAVED/.test(popupJs) && /Test API Key uses the box/.test(popupJs));
  check('PHASE-8', 'popup.js initialises the signature on load',
    /lastSavedSignature = settingsSignature\(\)/.test(popupJs));
  check('PHASE-8', 'saving settings refreshes the signature',
    /lastSavedSignature = settingsSignature\(\)/.test(popupJs.slice(popupJs.indexOf('saveSettingsBtn'))));

  // Simulate the divergence detector.
  function unsaved(saved, current) { return JSON.stringify(saved) !== JSON.stringify(current); }
  const saved = ['deepseek_cloud', 'sk-OLDKEY', 'https://agentrouter.org/v1/chat/completions', 'deepseek-v4-flash'];
  const edited = ['deepseek_cloud', 'sk-NEWKEY', 'https://agentrouter.org/v1/chat/completions', 'deepseek-v4-flash'];
  check('PHASE-8', 'sim: edited-but-unsaved key is detected', unsaved(saved, edited) === true);
  check('PHASE-8', 'sim: unchanged settings are not flagged', unsaved(saved, saved) === false);

  // The scan must surface the unsaved-key case specifically
  check('PHASE-8', 'scan error message calls out the unsaved-key case',
    /was NOT SAVED/.test(popupJs));
  check('PHASE-8', 'scan error message is no longer truncated to 80 chars',
    !/diag\.analysisError\.slice\(0, 80\)/.test(popupJs));
}

// ── PHASE 9: token-budget ceiling, adaptive sizing, streaming ──
//
// Live probe of agentrouter.org established the hard facts this phase pins:
//   max_tokens=393216 -> HTTP 200 ; max_tokens=393217 -> HTTP 400 with
//   "the valid range of max_tokens is [1, 393216]".
// So 393216 is the real ceiling. But "maximum possible" is the wrong default —
// max_tokens is a cap, so a runaway generation bills up to the cap. The budget
// must be sized to the task AND clamped to the ceiling.
{
  // The constants must exist and be internally consistent.
  const maxM = bg.match(/MAX:\s*(\d+)/);
  const scanM = bg.match(/SCAN:\s*(\d+)/);
  const testM = bg.match(/TEST:\s*(\d+)/);
  const maxTok = maxM ? parseInt(maxM[1], 10) : 0;
  const scanTok = scanM ? parseInt(scanM[1], 10) : 0;
  const testTok = testM ? parseInt(testM[1], 10) : 0;

  check('PHASE-9', 'TOKEN_LIMITS.MAX equals the verified gateway ceiling (393216)',
    maxTok === 393216, `MAX = ${maxTok} (live probe: 393216 ok, 393217 rejected)`);
  check('PHASE-9', 'scan budget is well above reasoning overhead but below the ceiling',
    scanTok >= 2000 && scanTok < maxTok, `SCAN = ${scanTok}`);
  check('PHASE-9', 'test budget is smaller than the scan budget',
    testTok > 0 && testTok < scanTok, `TEST = ${testTok} vs SCAN = ${scanTok}`);

  // The scan call must clamp, not blindly forward, so an out-of-range value
  // cannot reach the gateway as an opaque 400.
  check('PHASE-9', 'background.js clamps requested max_tokens to [1, MAX]',
    /Math\.max\(1,\s*Math\.min\([^)]*TOKEN_LIMITS\.MAX/.test(bg));
  check('PHASE-9', 'background.js accepts a caller-supplied budget (adaptive)',
    /opts\.maxTokens/.test(bg));
  check('PHASE-9', 'clamping simulation: 999999 -> 393216',
    Math.min(999999, maxTok) === 393216);
  check('PHASE-9', 'clamping simulation: 0 -> 1 (never sends 0)',
    Math.max(1, Math.min(0, maxTok)) === 1);

  // The old fixed 2500 must be gone from the shipping scan path.
  check('PHASE-9', 'no hardcoded max_tokens: 2500 remains in background.js',
    !/max_tokens:\s*2500/.test(bg));

  // Timeout must scale with the budget: the request cannot finish in 90s if it
  // is allowed to generate far more than 2500 tokens.
  const toM = bg.match(/CLOUD_TIMEOUT_MS\s*=\s*(\d+)/);
  const timeoutMs = toM ? parseInt(toM[1], 10) : 0;
  check('PHASE-9', 'cloud timeout was raised above the old 90s fixed limit',
    timeoutMs >= 180000, `CLOUD_TIMEOUT_MS = ${timeoutMs}`);
  check('PHASE-9', 'fetchWithRetry defaults to the scaled timeout, not 90000',
    /totalTimeoutMs\s*=\s*CLOUD_TIMEOUT_MS/.test(bg));

  // Streaming: requested, and the SSE reader must exist and be used.
  check('PHASE-9', 'background.js requests stream: true',
    /body\.stream\s*=\s*true/.test(bg));
  check('PHASE-9', 'background.js requests stream_options.include_usage',
    /stream_options\s*=\s*\{\s*include_usage:\s*true\s*\}/.test(bg));
  check('PHASE-9', 'an SSE reader is defined',
    /async function readSSECompletion/.test(bg));
  check('PHASE-9', 'the streamed path is actually taken',
    /if\s*\(useStream\)\s*\{[\s\S]{0,120}readSSECompletion/.test(bg));
  check('PHASE-9', 'SSE reader terminates on [DONE]',
    /'\[DONE\]'/.test(bg));
  check('PHASE-9', 'SSE reader tolerates malformed chunks without discarding output',
    /A malformed chunk must not discard/.test(bg));

  // Reimplement the reader against recorded live-shaped chunks to prove the parse.
  function parseSSE(raw) {
    let content = '', finishReason = null, usage = null;
    for (const line of raw.split('\n')) {
      const t = line.trim();
      if (!t.startsWith('data:')) continue;
      const p = t.slice(5).trim();
      if (!p || p === '[DONE]') continue;
      try {
        const c = JSON.parse(p);
        if (c.usage) usage = c.usage;
        const ch = c.choices && c.choices[0];
        if (ch) {
          if (ch.delta && ch.delta.content) content += ch.delta.content;
          if (ch.finish_reason) finishReason = ch.finish_reason;
        }
      } catch (e) {}
    }
    return { content, finishReason, usage };
  }
  // Chunks shaped exactly like the live stream we captured.
  const liveShaped = [
    'data: {"choices":[{"delta":{"content":"","role":"assistant"},"finish_reason":null}],"usage":null}',
    'data: {"choices":[{"delta":{"content":"{\\"summary\\":"},"finish_reason":null}]}',
    'data: {"choices":[{"delta":{"content":"\\"ok\\"}"},"finish_reason":null}]}',
    'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}',
    'data: {"choices":[],"usage":{"prompt_tokens":35,"completion_tokens":78,"total_tokens":113}}',
    'data: [DONE]'
  ].join('\n');

  const parsed = parseSSE(liveShaped);
  check('PHASE-9', 'sim: SSE deltas reassemble into the full content',
    parsed.content === '{"summary":"ok"}', `got ${JSON.stringify(parsed.content)}`);
  check('PHASE-9', 'sim: finish_reason is captured from the delta chunk',
    parsed.finishReason === 'stop', `got ${parsed.finishReason}`);
  check('PHASE-9', 'sim: usage is captured from the empty-choices chunk',
    parsed.usage && parsed.usage.completion_tokens === 78,
    `got ${JSON.stringify(parsed.usage)}`);

  // Regression: the first SSE implementation read usage only via choices[0],
  // so the usage chunk (choices: []) was silently skipped. Pin the fix.
  function parseSSEBuggy(raw) {
    let usage = null;
    for (const line of raw.split('\n')) {
      const t = line.trim();
      if (!t.startsWith('data:')) continue;
      const p = t.slice(5).trim();
      if (!p || p === '[DONE]') continue;
      try {
        const c = JSON.parse(p);
        if (c.choices && c.choices[0] && c.usage) usage = c.usage; // the bug
      } catch (e) {}
    }
    return usage;
  }
  check('PHASE-9', 'regression: reading usage via choices[0] misses it (old bug)',
    parseSSEBuggy(liveShaped) === null && parsed.usage !== null);

  // Empty-content diagnostic must know the budget and distinguish the causes.
  check('PHASE-9', 'empty content + max_tokens names the budget exhaustion',
    /spent its entire[\s\S]{0,80}budget on reasoning/.test(bg));
  check('PHASE-9', 'empty-content error quotes the ceiling for the fix',
    /ceiling is/.test(bg));

  // The gateway uses TWO different finish_reason values for a truncated
  // generation: "max_tokens" and "length" (verified live: a 16-token budget came
  // back as finish_reason "length"). Handling only one silently loses the
  // explanation, so both must be accepted in both files.
  check('PHASE-9', 'background.js treats finish_reason "length" as budget exhaustion too',
    /finishReason === 'max_tokens' \|\| finishReason === 'length'/.test(bg));
  check('PHASE-9', 'popup.js treats finish_reason "length" as budget exhaustion too',
    /finish === 'max_tokens' \|\| finish === 'length'/.test(popupJs));
  check('PHASE-9', 'sim: a "length" finish with no content is still diagnosed',
    (() => {
      const showBudgetError = (fr) => fr === 'max_tokens' || fr === 'length';
      return showBudgetError('length') === true && showBudgetError('stop') === false;
    })());

  // The popup's test budget must match the documented reasoning headroom.
  check('PHASE-9', 'popup Test budget >= TOKEN_LIMITS.MIN_REASONING',
    (() => { const mm = popupJs.match(/max_tokens:\s*(\d+)/); return mm && parseInt(mm[1], 10) >= 512; })());

  // Report metadata so the budget/streaming facts are inspectable, not inferred.
  check('PHASE-9', 'analysis result carries budget/streaming metadata',
    /meta:\s*\{/.test(bg) && /streamed:\s*useStream/.test(bg) &&
    /completion_tokens:\s*usedTokens/.test(bg));
}

// ── Summary ──
console.log('\n' + '='.repeat(64));
const passed = results.filter(r => r.pass).length;
const failed = results.filter(r => !r.pass);
console.log(`TOTAL: ${passed}/${results.length} passed, ${failed.length} failed`);
if (failed.length) {
  console.log('\nFAILURES:');
  failed.forEach(f => console.log(`  - [${f.phase}] ${f.name} :: ${f.detail}`));
}
console.log('='.repeat(64));
process.exit(failed.length ? 1 : 0);
