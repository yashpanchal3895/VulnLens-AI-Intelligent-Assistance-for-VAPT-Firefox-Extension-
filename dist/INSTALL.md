# VulnLens AI — Install Guide

Two ways to run this. Pick based on how long you need it to last.

---

## Option A — Temporary load (fastest, for development)

Use this while editing code. Reloads instantly, no signing.

1. Open **`about:debugging#/runtime/this-firefox`**
2. Click **Load Temporary Add-on…**
3. Select **`dist/stage/manifest.json`**

> **Important:** the file picker must be *inside* `dist/stage/`. Firefox reads `manifest.json`
> and loads its **parent folder** as the extension root. Picking a manifest with no sibling
> files fails with a missing-file error.

**Gone when Firefox closes.** Re-load each session.

**After you edit any `.js` file:**
1. Click **Reload** on the extension card in `about:debugging`
2. **Refresh the target tab too** — `content.js` only injects at page load, so a tab loaded
   before the reload is still running the old content script.

---

## Option B — Install the package (persists across restarts)

Install from **`dist/VulnLens-AI-v1.0.0.xpi`**.

### On Firefox Developer Edition / Nightly (unsigned installs allowed)
1. Open `about:config`
2. Set **`xpinstall.signatures.required`** → `false`
3. `about:addons` → gear icon → **Install Add-on From File…** → pick the `.xpi`

### On regular Firefox (release/beta)
Firefox **requires signing** and will refuse an unsigned `.xpi`. Two choices:

- **Temporary load** (Option A) — fine for your own testing.
- **Sign it free for personal use** at <https://addons.mozilla.org/developers/>
  → Submit a new add-on → **"On your own"** (self-distribution) → upload the `.zip`.
  You get a signed `.xpi` back, installable permanently. This is not public publishing —
  no store listing, no review queue in the usual sense. Requires a free AMO account.

---

## First run

1. Click the VulnLens icon (pin it via the puzzle-piece toolbar icon)
2. Open **API Settings**
3. Paste your AgentRouter key
4. Click **Test API Key** → expect:
   `OK — model "deepseek-v4-flash" replied "OK" in Nms`
5. Click **Save**
6. Navigate to a site you are **authorized to test**, then click **Scan This Page**

> **Scan the page *after* loading it.** Response headers are captured on page load, not on
> scan. Scanning a tab that was already loaded before the extension started shows
> `Header status: unavailable` — reload the page and scan again. That's the honest-diagnostics
> behaviour working as intended, not a bug.

---

## Rebuilding the package

After editing any source file:

```bash
node build_package.js     # rebuilds dist/VulnLens-AI-vX.Y.Z.xpi + .zip
node verify_package.js    # validates the built archive (18 checks)
node test_harness.js      # full regression suite (43 checks)
```

Bump `version` in `manifest.json` before rebuilding if you want distinct filenames.

---

## What's inside the package

13 files — runtime only. All dev tooling (`test_harness.js`, `live_scan.js`,
`find_mixed.js`, `scan_silveroak.js`, `live_ai_test.js`, `build_package.js`,
`verify_package.js`, `remediation/`) is deliberately excluded.

```
manifest.json          background.js        content.js
local_engine.js        report.js            popup.html / popup.css / popup.js
report_viewer.html / report_viewer.js
icons/icon16|48|128.png
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "This add-on could not be installed because it appears to be corrupt" | Archive nesting — manifest not at root | Rebuild with `node build_package.js` (it enforces root placement) |
| "could not be installed because it is not signed" | Normal Firefox + unsigned xpi | Use Option A, or self-sign via AMO |
| Extension loads but scan does nothing | Content script not injected | Refresh the target tab |
| `Header status: unavailable` | Page loaded before extension started | Reload the page, then scan |
| Status says cloud failed, local used | API key / network / 429 | Check popup diagnostics — it reports the real reason |
| Test API Key returns 401 | Missing client-fingerprint header | Handled in code; if it persists the key is genuinely wrong (see `agentrouter-api-access` skill) |
