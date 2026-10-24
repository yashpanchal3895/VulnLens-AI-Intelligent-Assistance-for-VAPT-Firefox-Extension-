/**
 * build_package.js — VulnLens AI release build
 *
 * Uses the `firefox-extension-packaging` skill's builder (imported, not spawned —
 * spawning the same Node binary hits EBUSY in restricted environments). Risk
 * staging and ZIP writing live in the skill, so there's a single implementation;
 * this file encodes only VulnLens-specific paths.
 *
 * Run: node build_package.js
 */

const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const STAGE = path.join(ROOT, 'dist', 'stage');
const DIST = path.join(ROOT, 'dist');

// Runtime files — resolved from manifest.json AND from HTML <script>/<link> tags.
// popup.js is listed explicitly because manifest.json never mentions it.
const RUNTIME_FILES = [
  'manifest.json',
  'background.js',
  'content.js',
  'local_engine.js',
  'report.js',
  'popup.html',
  'popup.css',
  'popup.js',
  'report_viewer.html',
  'report_viewer.js',
  'icons/icon16.png',
  'icons/icon48.png',
  'icons/icon128.png'
];

// ── Locate the skill builder ──
const SKILL_SCRIPTS = path.join(
  process.env.USERPROFILE || process.env.HOME || '',
  '.workbuddy-ai', 'skills', 'firefox-extension-packaging', 'scripts'
);
const BUILDER = path.join(SKILL_SCRIPTS, 'build-extension-zip.js');

if (!fs.existsSync(BUILDER)) {
  console.error('Skill builder not found at:');
  console.error(`  ${BUILDER}`);
  console.error('\nInstall the firefox-extension-packaging skill first.');
  process.exit(1);
}

const { buildExtensionArchive } = require(BUILDER);

// ── Stage ──
console.log('Staging runtime files...');
fs.rmSync(STAGE, { recursive: true, force: true });
fs.mkdirSync(STAGE, { recursive: true });

const missing = [];
for (const rel of RUNTIME_FILES) {
  const src = path.join(ROOT, rel);
  if (!fs.existsSync(src)) { missing.push(rel); continue; }
  const dest = path.join(STAGE, rel);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
}
console.log(`  staged ${RUNTIME_FILES.length - missing.length}/${RUNTIME_FILES.length} files`);

if (missing.length) {
  console.error('\nFAIL: runtime files missing from source:');
  missing.forEach((m) => console.error('  ' + m));
  process.exit(1);
}

// ── Build ──
const manifest = JSON.parse(fs.readFileSync(path.join(STAGE, 'manifest.json'), 'utf8'));
const version = manifest.version || '0.0.0';
const xpi = path.join(DIST, `VulnLens-AI-v${version}.xpi`);
const zip = path.join(DIST, `VulnLens-AI-v${version}.zip`);

console.log('\nBuilding archive...');
try {
  const result = buildExtensionArchive(STAGE, xpi, { quiet: true });
  // .zip is a byte-identical copy — same content, friendlier extension for AMO upload.
  fs.copyFileSync(xpi, zip);

  console.log(`  name    : ${result.manifest.name}`);
  console.log(`  version : ${version}`);
  console.log(`  files   : ${result.fileCount}`);
  console.log(`  archive : ${(result.bytes / 1024).toFixed(1)} KB`);
  console.log(`  output  : dist/VulnLens-AI-v${version}.xpi`);
  console.log(`          + dist/VulnLens-AI-v${version}.zip`);
} catch (err) {
  console.error('\nFAIL: ' + err.message);
  process.exit(1);
}

console.log('\nNext: node verify_package.js');
