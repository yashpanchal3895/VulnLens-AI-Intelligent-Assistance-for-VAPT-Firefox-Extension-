# VulnLens AI — Intelligent VAPT Assistant (Firefox Edition)

**Authors:** Yash M. Panchal & Umang K. Nagwadiya

A Firefox WebExtension that **passively** scans the currently open web page
for common security misconfigurations, then uses a **completely free,
offline AI analysis engine** to explain the risk and suggest defensive
remediation — packaged as a lightweight VAPT (Vulnerability Assessment &
Penetration Testing) assistant.

> ⚠️ **Authorized use only.** Only scan sites you own or have explicit
> written permission to test. This tool performs passive/read-only checks
> (headers, DOM inspection, source patterns) — it does **not** send
> exploit payloads, brute-force credentials, or perform active attacks.

## Why this build is 100% free

Unlike typical "AI-powered" tools that require a paid API key or third-party servers, VulnLens AI runs entirely in your browser:

- **100% Serverless**: No Python server scripts, database configs, or external hosts to set up.
- **Offline Rule Engine**: Falls back to an on-device JavaScript classification engine (`local_engine.js`) if no local LLM is running.
- **Direct Local LLM Connection**: Connects directly to **Ollama** running on your local machine (`http://localhost:11434`) without server-side middleware.
- **Private Scan History**: Scan history is stored directly in Firefox's sandbox storage (`browser.storage.local`).

---

## What it detects

- Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Mixed content (HTTP resources on HTTPS pages)
- Forms submitting over HTTP / missing CSRF-token-like hidden fields
- Inline scripts / inline event handlers (CSP weaknesses)
- Known-vulnerable/outdated frontend library version signatures
- Secrets/keys accidentally left in page source or HTML comments (AWS Keys, Private Keys, API Keys)
- `target="_blank"` links missing `rel="noopener"`
- Server/technology fingerprinting headers (`Server`, `X-Powered-By`)
- JS-readable (non-HttpOnly) cookies

---

## Project structure

```
VulnLens-AI-Firefox/
├── manifest.json          # Firefox WebExtension manifest (MV3 on Gecko)
├── popup.html/css/js      # Extension popup UI + logic (browser.* API)
├── content.js              # Passive DOM/source scanner (runs on page)
├── background.js           # Background script: header inspection + LLM orchestration
├── local_engine.js         # Offline rule-based analysis engine (JS fallback)
├── report.js                 # Builds a downloadable HTML VAPT report
├── icons/
└── assets/
```

---

## Setup & Usage

### 1. (Optional) Run a Local LLM
If you want to use advanced LLM summaries locally and offline:
1. Download and run **Ollama** from [ollama.com](https://ollama.com).
2. Pull your model of choice (e.g. `llama3` or `gemma2:2b`):
   ```bash
   ollama pull llama3
   ```

### 2. Load the Extension in Firefox
1. Open Firefox and type `about:debugging#/runtime/this-firefox` in the address bar.
2. Click **Load Temporary Add-on…**.
3. Select the `manifest.json` file inside the `VulnLens-AI-Firefox/` folder.

### 3. Scan a Web Page
1. Navigate to a page you are authorized to test.
2. Click the **VulnLens AI** extension icon in your toolbar.
3. Click **Scan This Page** to run the passive DOM/header checks.
4. Click **API Settings** at the bottom to configure your Ollama port and model name.
5. Click **AI Analysis (Free)** to generate summaries. If Ollama is running, it queries the model directly. If not, it falls back to the internal rule-based engine.
6. Click **Generate Report** to download a self-contained HTML report.

---

## Authors

**Yash M. Panchal** & **Umang K. Nagwadiya**
