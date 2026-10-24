/**
 * verify_package.js — VulnLens AI release validation
 *
 * Two layers:
 *   1. Generic archive integrity (CRC-verified extraction, root placement,
 *      reference resolution) — from the firefox-extension-packaging skill.
 *   2. Project-specific checks — that the security fixes are actually shipped
 *      and that no dev-only file leaked into the package.
 *
 * Run: node verify_package.js [archive]    (default: latest dist/*.xpi)
 */

const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const DIST = path.join(ROOT, 'dist');

// ── Resolve the archive under test ──
function resolveArchive() {
  const arg = process.argv[2];
  if (arg) return path.resolve(arg);
  if (!fs.existsSync(DIST)) return null;
  const xpis = fs.readdirSync(DIST).filter((f) => f.endsWith('.xpi')).sort();
  return xpis.length ? path.join(DIST, xpis[xpis.length - 1]) : null;
}

const archive = resolveArchive();
if (!archive || !fs.existsSync(archive)) {
  console.error('No archive found. Run `node build_package.js` first.');
  process.exit(1);
}

// ── Layer 1: generic archive integrity (skill-delegated) ──
const SKILL_SCRIPTS = path.join(
  process.env.USERPROFILE || process.env.HOME || '',
  '.workbuddy-ai', 'skills', 'firefox-extension-packaging', 'scripts'
);
const VERIFIER = path.join(SKILL_SCRIPTS, 'verify-extension-zip.js');

if (!fs.existsSync(VERIFIER)) {
  console.error(`Skill verifier not found: ${VERIFIER}`);
  console.error('Install the firefox-extension-packaging skill first.');
  process.exit(1);
}

const { verifyExtensionArchive } = require(VERIFIER);
const EXTRACT = path.join(DIST, 'verify');

console.log('='.repeat(64));
console.log(' LAYER 1 — archive integrity (skill verifier)');
console.log('='.repeat(64));

let result;
try {
  result = verifyExtensionArchive(archive, { extractTo: EXTRACT });
} catch (err) {
  console.error('FAIL: ' + err.message);
  process.exit(1);
}

console.log('');
if (!result.valid) {
  console.log('RESULT: INVALID');
  result.failures.forEach((f) => console.log('  - ' + f));
  process.exit(1);
}

// ── Layer 2: project-specific checks ──
console.log('='.repeat(64));
console.log(' LAYER 2 — VulnLens-specific checks');
console.log('='.repeat(64));

const read = (f) => fs.readFileSync(path.join(EXTRACT, f), 'utf8');
const exists = (f) => fs.existsSync(path.join(EXTRACT, f));
const checks = [];
const add = (name, ok) => checks.push([name, !!ok]);

const bg = read('background.js');
const report = read('report.js');
const engine = read('local_engine.js');
const popup = read('popup.js');
const popupHtml = read('popup.html');
const manifest = JSON.parse(read('manifest.json'));

// Manifest
add('manifest_version is 3', manifest.manifest_version === 3);
add('gecko id present', !!(manifest.browser_specific_settings?.gecko?.id));
add('strict_min_version >= 109', parseFloat(manifest.browser_specific_settings.gecko.strict_min_version) >= 109);
add('permissions: webRequest + scripting + storage + downloads',
  ['webRequest', 'scripting', 'storage', 'downloads'].every((p) => manifest.permissions.includes(p)));
add('host_permissions cover http + https',
  manifest.host_permissions.join() === 'http://*/*,https://*/*');

// Popup wiring
const ids = [...new Set([...popup.matchAll(/getElementById\(["']([^"']+)["']\)/g)].map((x) => x[1]))];
add(`popup.js getElementById targets exist (${ids.length} ids)`,
  ids.every((id) => popupHtml.includes('id="' + id + '"')));
const types = [...new Set([...popup.matchAll(/type:\s*["']([A-Z_]+)["']/g)].map((x) => x[1]))];
add(`popup→background message handlers (${types.length} types)`,
  types.every((t) => bg.includes(t)));

// Security fixes must actually be in the shipped bundle
add('AgentRouter UA fingerprint header', bg.includes('claude-cli/2.1.281'));
add('AgentRouter endpoint default', bg.includes('agentrouter.org'));
add('model default deepseek-v4-flash', bg.includes('deepseek-v4-flash'));
add('fetchWithRetry backoff', bg.includes('fetchWithRetry'));
add('multi-value header capture', /Array\.isArray\(headers\[key\]\)/.test(bg));
add('header-freshness diagnostics', bg.includes('headerStatus'));
add('quality-based header analysis', bg.includes('unsafe-inline'));
add('extractJson robust parsing', bg.includes('extractJson'));
add('raw evidence section in report', report.includes('buildEvidenceSection'));
add('gap analysis present', report.includes('buildGapAnalysis'));
add('weak_csp precedes missing_csp', engine.indexOf('weak_csp') < engine.indexOf('missing_csp'));
add('cookie_flags rule regex fixed', /javascript-readable/.test(engine));
add('sensitive_inputs rule covers autocomplete', /allows autocomplete on password/.test(engine));

// API error classification — both 401 causes must be distinguished in the shipped bundle.
// Conflating them misreports an invalid key as a User-Agent problem.
add('popup.js distinguishes invalid-key from fingerprint 401',
  /无效的令牌/.test(popup) && /unauthorized client/i.test(popup));
add('background.js distinguishes invalid-key from fingerprint 401',
  /无效的令牌/.test(bg) && /unauthorized client/i.test(bg));
add('popup.js pre-validates key shape before network call',
  /does not start with/.test(popup) && /looks truncated/.test(popup));

// Reasoning-model token budget: deepseek-v4-flash spends max_tokens on reasoning
// BEFORE emitting content, so a tiny budget yields an empty reply on HTTP 200.
{
  const testCall = popup.slice(popup.indexOf('testApiBtn.addEventListener'));
  const m = testCall.match(/max_tokens:\s*(\d+)/);
  add('Test API Key budgets enough tokens for reasoning',
    m && parseInt(m[1], 10) >= 64, m ? `max_tokens=${m[1]}` : 'max_tokens not found');
}
add('popup.js treats an empty reply as failure, not OK',
  /model returned an EMPTY reply/.test(popup));
add('popup.js explains the exhausted reasoning budget',
  /token budget was exhausted by reasoning/.test(popup));

// Token-budget ceiling + streaming. The gateway's advertised range is
// [1, 393216] (probed live), and max_tokens is a CAP not a reservation, so the
// shipping code must size to the task and clamp, never blindly maximize.
add('TOKEN_LIMITS.MAX matches the verified gateway ceiling',
  /MAX:\s*393216/.test(bg));
add('scan budget is sized to the task, not the ceiling',
  /SCAN:\s*4000/.test(bg));
add('background.js clamps max_tokens into [1, MAX]',
  /Math\.max\(1,\s*Math\.min\([^)]*TOKEN_LIMITS\.MAX/.test(bg));
add('no stale hardcoded max_tokens: 2500',
  !/max_tokens:\s*2500/.test(bg));
add('cloud timeout scales with the output budget',
  /CLOUD_TIMEOUT_MS\s*=\s*180000/.test(bg));
add('streaming requested with usage reporting',
  /body\.stream\s*=\s*true/.test(bg) && /include_usage/.test(bg));
add('SSE stream reader ships',
  /async function readSSECompletion/.test(bg) && /'\[DONE\]'/.test(bg));
add('truncated finish_reason handled in both spellings (max_tokens | length)',
  /finishReason === 'max_tokens' \|\| finishReason === 'length'/.test(bg) &&
  /finish === 'max_tokens' \|\| finish === 'length'/.test(popup));

// Test API Key reads the input box while the scan reads storage — the divergence
// is a real footgun, so the unsaved-edit detector must ship.
add('popup.js detects unsaved cloud settings',
  /settingsSignature/.test(popup) && /lastSavedSignature/.test(popup));
add('scan error names the unsaved-key case',
  /was NOT SAVED/.test(popup));

// Nothing dev-only leaked
const devOnly = ['test_harness.js', 'live_scan.js', 'live_ai_test.js', 'scan_silveroak.js',
                 'find_mixed.js', 'build_package.js', 'verify_package.js',
                 'probe_limits.js', 'probe_limits2.js', 'probe_stream.js',
                 'probe_sse_tail.js', 'probe_budget.js'];
const leaked = devOnly.filter(exists);
add('no dev-only files leaked', leaked.length === 0);
if (leaked.length) console.log('  leaked: ' + leaked.join(', '));

let pass = 0;
checks.forEach(([name, ok]) => {
  if (ok) pass++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}`);
});

console.log('');
console.log(`${pass}/${checks.length} project checks passed`);

// Clean up extraction scratch dir on success
if (pass === checks.length) fs.rmSync(EXTRACT, { recursive: true, force: true });

process.exit(pass === checks.length ? 0 : 1);
