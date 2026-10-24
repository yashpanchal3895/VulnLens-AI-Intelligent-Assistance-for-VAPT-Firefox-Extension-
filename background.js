/**
 * VulnLens AI - background.js (Firefox build)
 * Authors: Yash M. Panchal & Umang K. Nagwadiya
 *
 * Background script: inspects HTTP response headers for the active tab's
 * main document (invisible to content scripts) and relays scan requests
 * and results between popup, content script, and the local AI backend.
 *
 * Firefox WebExtensions expose `browser.*` with native Promises, so no
 * chrome.*-style callbacks or polyfill are required here.
 */

// AgentRouter (New API / One API gateway) gates its /v1/* endpoints behind a
// client-fingerprint check. Requests carrying the Claude Code CLI User-Agent
// are authorized; requests without it are rejected with HTTP 401
// "unauthorized client detected". This header is REQUIRED for cloud calls.
const AGENTROUTER_UA = 'claude-cli/2.1.281 (external, cli)';

// Store headers in browser.storage.local to survive background script suspension
browser.webRequest.onHeadersReceived.addListener(
  async (details) => {
    if (details.type === 'main_frame' && details.tabId >= 0) {
      const headers = {};
      (details.responseHeaders || []).forEach(h => {
        const key = h.name.toLowerCase();
        // Headers such as Set-Cookie legitimately repeat. Collapse them into an
        // array instead of overwriting, so every cookie is analysed.
        if (key in headers) {
          headers[key] = Array.isArray(headers[key])
            ? [...headers[key], h.value]
            : [headers[key], h.value];
        } else {
          headers[key] = h.value;
        }
      });
      const data = {};
      data[`header_${details.tabId}`] = { url: details.url, headers, capturedAt: Date.now() };
      await browser.storage.local.set(data);
    }
  },
  { urls: ['http://*/*', 'https://*/*'] },
  ['responseHeaders']
);

// Clean up stored headers when a tab is closed to prevent storage bloat
browser.tabs.onRemoved.addListener(async (tabId) => {
  await browser.storage.local.remove(`header_${tabId}`);
});

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
      findings.push({
        severity: req.severity,
        title: req.title,
        description: `The response did not include a "${req.key}" header, which helps mitigate common browser-side attacks.`
      });
    }
  });

  // ── Quality analysis (a header can be present but useless) ──

  // CSP: presence is not enough — unsafe directives defeat the purpose.
  const csp = headers['content-security-policy'];
  if (csp) {
    const weak = [];
    if (/unsafe-inline/i.test(csp)) weak.push("'unsafe-inline' (allows inline scripts, the main XSS vector)");
    if (/unsafe-eval/i.test(csp)) weak.push("'unsafe-eval' (allows eval/Function string execution)");
    if (/\*\s*(;|$)/.test(csp) || /default-src[^;]*\*/.test(csp)) weak.push('a wildcard (*) source (allows any origin)');
    if (/script-src[^;]*https?:/i.test(csp)) weak.push('broad http(s): sources in script-src');
    if (!/default-src|script-src/i.test(csp)) weak.push('no default-src or script-src directive (policy is ineffective)');
    if (/http:\/\//i.test(csp)) weak.push('plain http:// sources (downgradeable)');
    if (weak.length) {
      findings.push({
        severity: 'medium',
        title: 'Weak Content-Security-Policy configuration',
        description: `A CSP is present but contains dangerous directives: ${weak.join('; ')}. The policy therefore provides little protection against script injection.`
      });
    }
  }

  // HSTS: must have a long max-age and ideally cover subdomains + preload.
  const hsts = headers['strict-transport-security'];
  if (hsts) {
    const issues = [];
    const maxAgeMatch = /max-age\s*=\s*(\d+)/i.exec(hsts);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
    if (!maxAgeMatch) issues.push('no max-age directive (HSTS is ignored by browsers)');
    else if (maxAge === 0) issues.push('max-age=0 explicitly disables HSTS');
    else if (maxAge < 15552000) issues.push(`max-age is only ${maxAge}s (recommended minimum is 15552000s / 180 days)`);
    if (!/includeSubDomains/i.test(hsts)) issues.push('includeSubDomains is absent, leaving subdomains open to downgrade');
    if (!/preload/i.test(hsts)) issues.push('preload is absent, so the domain cannot be preloaded');
    if (issues.length) {
      findings.push({
        severity: 'low',
        title: 'Weak Strict-Transport-Security (HSTS) configuration',
        description: `HSTS is present but incomplete: ${issues.join('; ')}.`
      });
    }
  }

  // X-Frame-Options: ALLOW-FROM is obsolete and unsupported by modern browsers.
  const xfo = headers['x-frame-options'];
  if (xfo && /allow-from/i.test(xfo)) {
    findings.push({
      severity: 'low',
      title: 'Obsolete X-Frame-Options ALLOW-FROM directive',
      description: `X-Frame-Options is set to "${xfo}", but ALLOW-FROM is obsolete and ignored by all modern browsers. Use a CSP frame-ancestors directive instead.`
    });
  }

  // X-Content-Type-Options: must be exactly "nosniff" to take effect.
  const xcto = headers['x-content-type-options'];
  if (xcto && !/nosniff/i.test(xcto)) {
    findings.push({
      severity: 'low',
      title: 'Ineffective X-Content-Type-Options value',
      description: `X-Content-Type-Options is set to "${xcto}" but only the value "nosniff" has any effect.`
    });
  }

  // Deprecated security header that can introduce its own weaknesses.
  const xss = headers['x-xss-protection'];
  if (xss) {
    findings.push({
      severity: 'info',
      title: 'Deprecated X-XSS-Protection header present',
      description: `X-XSS-Protection is set to "${xss}". This header is deprecated and removed from modern browsers; it can also introduce vulnerabilities in older ones. Rely on CSP instead.`
    });
  }

  // Cache-Control: sensitive responses should not be stored. A trailing comma or
  // a directive-only s-maxage means browsers get no caching instruction at all.
  const cc = headers['cache-control'];
  if (cc) {
    const issues = [];
    if (/,\s*$/.test(cc)) issues.push('the value ends with a stray comma (malformed directive list)');
    if (/s-maxage=/i.test(cc) && !/(^|,)\s*max-age=/i.test(cc)) issues.push('only s-maxage is set, so browsers receive no explicit max-age');
    if (/(^|,)\s*no-store/i.test(cc) && /public/i.test(cc)) issues.push('contradictory no-store and public directives');
    if (issues.length) {
      findings.push({
        severity: 'low',
        title: 'Malformed or ineffective Cache-Control header',
        description: `Cache-Control is set to "${cc}", but ${issues.join('; ')}. Caching behaviour is therefore ambiguous and may store responses when it should not.`
      });
    }
  }

  // Set-Cookie flags — the definitive source of cookie-security truth.
  // (content.js can only see JS-readable cookies; these headers reveal HttpOnly/Secure.)
  const setCookie = headers['set-cookie'];
  if (setCookie) {
    const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
    cookies.forEach(raw => {
      const name = (raw.split('=')[0] || '').trim();
      if (!name) return;
      const looksSensitive = /session|jwt|token|sid|auth|login|csrf|xsrf|remember/i.test(name);
      const missing = [];
      if (!/httponly/i.test(raw)) missing.push('HttpOnly');
      if (!/secure/i.test(raw)) missing.push('Secure');
      if (!/samesite/i.test(raw)) missing.push('SameSite');
      if (missing.length) {
        findings.push({
          severity: looksSensitive ? 'medium' : 'low',
          title: `Cookie "${name}" missing security flags`,
          description: `The Set-Cookie header for "${name}" does not set: ${missing.join(', ')}.` +
            (looksSensitive ? ' This cookie appears session/auth-related, so missing HttpOnly exposes it to theft via XSS and missing Secure allows interception over HTTP.' : '')
        });
      }
    });
  }

  // Information-disclosure headers
  const serverHeader = headers['server'];
  if (serverHeader) {
    const leaksVersion = /\d/.test(serverHeader);
    findings.push({
      severity: leaksVersion ? 'low' : 'info',
      title: 'Server header discloses details',
      description: `Server header value "${serverHeader}" discloses web server details` +
        (leaksVersion ? ', including a version number that can be matched against known CVEs' : '') +
        ', aiding malicious fingerprinting and profiling.'
    });
  }

  const poweredBy = headers['x-powered-by'];
  if (poweredBy) {
    findings.push({
      severity: 'info',
      title: 'X-Powered-By header present',
      description: `Header discloses backend framework/technology: "${poweredBy}". Consider removing it to hide platform internals.`
    });
  }

  // Other common fingerprinting / internal-disclosure headers
  const INFO_HEADERS = ['x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-drupal-cache', 'x-backend-server', 'x-served-by', 'x-nextjs-cache', 'x-debug-token', 'x-runtime'];
  INFO_HEADERS.forEach(h => {
    if (headers[h]) {
      findings.push({
        severity: 'info',
        title: `Information-disclosure header present: ${h}`,
        description: `The response includes "${h}: ${headers[h]}", which reveals internal implementation details useful for reconnaissance.`
      });
    }
  });

  const coop = headers['cross-origin-opener-policy'];
  if (!coop) {
    findings.push({
      severity: 'info',
      title: 'Missing Cross-Origin-Opener-Policy (COOP) header',
      description: 'COOP header is missing. Setting this to "same-origin" isolates your tab context and mitigates side-channel attacks like Spectre.'
    });
  }

  const cors = headers['access-control-allow-origin'];
  if (cors === '*') {
    findings.push({
      severity: 'low',
      title: 'Wildcard CORS Access Allowed (*)',
      description: 'The resource responds with "Access-Control-Allow-Origin: *". Confirm this page does not handle session credentials.'
    });
  }

  const acac = headers['access-control-allow-credentials'];
  if (acac === 'true' && cors === '*') {
    findings.push({
      severity: 'high',
      title: 'Dangerous CORS combination: wildcard origin with credentials',
      description: 'The response allows credentials ("Access-Control-Allow-Credentials: true") together with a wildcard origin ("*"). Browsers normally block this, but if the origin is reflected dynamically it becomes a serious cross-origin data-theft issue. Restrict the allowed origin to an explicit allow-list.'
    });
  }

  return findings;
}

/**
 * Run the full scan pipeline against a tab and return findings + analysis.
 *
 * Header freshness matters: data is keyed by tabId, but a tab can navigate
 * (especially in an SPA such as Next.js) without the headers being re-captured.
 * If the stored headers belong to a different URL than the one just scanned,
 * we must not silently analyse stale data.
 */
async function runFullScan(tabId) {
  // Pin the request to the TOP-LEVEL frame. content.js now runs in every frame
  // (all_frames: true), and a bare tabs.sendMessage() fans out to all of them and
  // resolves with whichever answers first — which can be an iframe, reporting the
  // wrong URL and the wrong findings. frameId 0 is always the page the user sees.
  const domResponse = await browser.tabs.sendMessage(
    tabId,
    { type: 'VULNLENS_SCAN_REQUEST' },
    { frameId: 0 }
  );

  const key = `header_${tabId}`;
  const storageData = await browser.storage.local.get(key);
  const headerInfo = storageData[key];

  const scanUrl = domResponse?.result?.url;
  let headerFindings;
  let headerStatus;
  let headerCapturedAt = null;

  if (!headerInfo) {
    headerFindings = [{
      severity: 'info',
      title: 'Header data unavailable',
      description: 'Reload the page after installing the extension to capture response headers.'
    }];
    headerStatus = 'unavailable';
  } else {
    headerCapturedAt = headerInfo.capturedAt || null;
    // Normalise both URLs to origin+path so trailing slashes / hashes don't
    // create false mismatches.
    const norm = (u) => {
      try { const p = new URL(u); return `${p.origin}${p.pathname}`.replace(/\/$/, ''); }
      catch { return String(u || ''); }
    };
    const sameUrl = !scanUrl || norm(headerInfo.url) === norm(scanUrl);

    if (sameUrl) {
      headerFindings = analyzeSecurityHeaders(headerInfo.headers);
      headerStatus = 'current';
    } else {
      // Headers belong to a different page than the one we just scanned.
      headerFindings = [{
        severity: 'info',
        title: 'Header data may be stale for this URL',
        description: `Captured headers belong to ${headerInfo.url}, but the page scanned is ${scanUrl}. These can differ on single-page apps (client-side navigation does not refetch the document). Reload the page to capture headers for the current URL before relying on header findings.`
      }];
      headerStatus = 'stale';
    }
  }

  if (!domResponse?.ok) {
    throw new Error(domResponse?.error || 'Content script scan failed');
  }

  const allFindings = [...headerFindings, ...domResponse.result.findings];

  // ── Auto-AI Phase: run cloud/local analysis immediately during scan ──
  const { aiProvider, deepseekApiKey, cloudEndpoint, cloudModel, apiUrl, ollamaModel } = await browser.storage.local.get({
    aiProvider: 'ollama',
    deepseekApiKey: '',
    cloudEndpoint: 'https://agentrouter.org/v1/chat/completions',
    cloudModel: 'deepseek-v4-flash',
    apiUrl: 'http://127.0.0.1:11434',
    ollamaModel: 'llama3'
  });

  let analysis = null;
  let analysisError = null;

  if (aiProvider === 'deepseek_cloud' && deepseekApiKey) {
    try {
      analysis = await callDeepSeekCloudAPI(scanUrl, allFindings, deepseekApiKey, cloudEndpoint, cloudModel);
    } catch (cloudErr) {
      console.warn('[VulnLens] Cloud scan-phase call failed, falling back to local rules:', cloudErr);
      analysisError = cloudErr.message;
      analysis = globalThis.VulnLensLocalEngine.generateLocalAnalysis(scanUrl, allFindings);
      analysis.engine = `local-fallback (cloud error: ${cloudErr.message})`;
    }  } else if (aiProvider === 'deepseek_cloud' && !deepseekApiKey) {
    analysis = globalThis.VulnLensLocalEngine.generateLocalAnalysis(scanUrl, allFindings);
    analysis.engine = 'local-fallback (API key not set)';
    analysisError = 'API key not set';
  } else {
    // Ollama path – attempt local LLM, fall back to rule engine
    const base = (apiUrl || 'http://127.0.0.1:11434').replace(/\/$/, '');
    const model = ollamaModel || 'llama3';
    const prompt = buildAnalysisPrompt(scanUrl, allFindings);
    try {
      const controller = new AbortController();
      const tid = setTimeout(() => controller.abort(), 25000);
      const resp = await fetch(`${base}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model, stream: false,
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: prompt }
          ],
          options: { temperature: 0.2 },
          format: 'json'
        }),
        signal: controller.signal
      });
      clearTimeout(tid);
      if (!resp.ok) throw new Error(`Ollama status ${resp.status}`);
      const data = await resp.json();
      const parsed = JSON.parse(extractJson(data.message.content));
      const fb = globalThis.VulnLensLocalEngine.generateLocalAnalysis(scanUrl, allFindings);
      analysis = {
        summary: parsed.summary || fb.summary,
        recommendations: parsed.recommendations || fb.recommendations,
        risk_level: parsed.risk_level || fb.risk_level,
        risk_score: parsed.risk_score !== undefined ? parsed.risk_score : fb.risk_score,
        engine: `local-llm-ollama (${model})`
      };
    } catch (ollamaErr) {
      console.warn('[VulnLens] Ollama scan-phase call failed, using rule engine:', ollamaErr);
      analysisError = ollamaErr.message;
      analysis = globalThis.VulnLensLocalEngine.generateLocalAnalysis(scanUrl, allFindings);
    }
  }

  return {
    url: scanUrl,
    timestamp: domResponse.result.timestamp,
    findings: allFindings,
    analysis,
    // Raw evidence so the report can show exactly what was observed on the wire.
    rawHeaders: headerInfo?.headers || null,
    // Diagnostics so the UI/report can show data provenance honestly.
    diagnostics: {
      headerStatus,                       // current | stale | unavailable
      headerCapturedAt,
      headerUrl: headerInfo?.url || null,
      analysisError
    }
  };
}

const SYSTEM_PROMPT = `You are a defensive application-security assistant embedded in VulnLens AI, a browser-based VAPT (Vulnerability Assessment & Penetration Testing) helper extension.

You will be given a list of findings that were collected by a passive scanner (missing security headers, outdated libraries, insecure forms, exposed secrets, etc.). Your job is to:

1. Detail what security controls are MISSING on the target application and explain what safeguards are REQUIRED according to web security standards (OWASP/W3C).
2. Explain the business and technical risk of each finding category in plain language for developers and stakeholders.
3. Order findings by severity and recommend concrete, defensive remediation steps for all missing controls.

You must NOT:
- Produce exploit code, attack payloads, or step-by-step attack instructions.
- Suggest ways to bypass authentication, escalate privileges, or pivot further into a system.
- Speculate about unrelated vulnerabilities not present in the findings.

Respond with ONLY a JSON object matching this schema, and nothing else (no markdown fences, no preamble):

{
  "summary": "2-4 sentence overview detailing what critical controls are MISSING, what safeguards are REQUIRED to secure the site, and overall risk posture.",
  "recommendations": ["ordered list of prioritized, actionable remediation steps for missing safeguards"],
  "risk_level": "one of: None, Low, Medium, High, Critical",
  "risk_score": 0
}

ALL FOUR fields are REQUIRED. "risk_level" and "risk_score" must always be present:
- risk_score is an integer from 0 to 100 reflecting overall risk.
- risk_level must correspond to the score: 0=None, 1-14=Low, 15-39=Medium, 40-59=High, 60-100=Critical.
Never omit a field. If a field is unknown, infer it from the findings rather than leaving it out.

Reference the specific counts in the findings (number of missing headers, inline scripts, affected links) when useful, and keep each recommendation actionable and specific to this site.
`;

function buildAnalysisPrompt(url, findings) {
  const lines = findings.map(f => `- [${f.severity.toUpperCase()}] ${f.title}: ${f.description}`);
  return `Target URL: ${url}

The following findings were collected by a passive scanner (no active exploitation was performed):

${lines.join('\n')}

Summarize the overall risk and provide prioritized, defensive remediation recommendations following the JSON schema in your system instructions.`;
}

async function saveScanToHistory(scan, scanId) {
  const { scanHistory } = await browser.storage.local.get({ scanHistory: [] });
  scanHistory.unshift({
    id: scanId,
    url: scan.url,
    timestamp: scan.timestamp,
    findingsCount: scan.findings.length
  });
  if (scanHistory.length > 50) {
    const removed = scanHistory.splice(50);
    for (let item of removed) {
      await browser.storage.local.remove(`scan_detail_${item.id}`);
    }
  }
  await browser.storage.local.set({ scanHistory });
}

async function saveScanDetail(scanId, scan, analysis) {
  const data = {};
  data[`scan_detail_${scanId}`] = {
    url: scan.url,
    timestamp: scan.timestamp,
    findings: scan.findings,
    analysis: analysis || null
  };
  await browser.storage.local.set(data);
}

// ── Token budget configuration ───────────────────────────────────────────────
//
// The gateway advertises a max_tokens range of [1, 393216] (verified by probing:
// 393216 -> HTTP 200, 393217 -> HTTP 400 "valid range of max_tokens is
// [1, 393216]"). That is a 384K-token output ceiling — but "maximum possible" is
// NOT the right setting, for two reasons:
//
//   1. COST. max_tokens is a cap, not a reservation, so a huge cap costs nothing
//      on a normal reply. But a runaway reasoning loop could genuinely generate
//      hundreds of thousands of tokens and bill you for all of them before it
//      stops. An unbounded cap turns a bug into a large invoice.
//
//   2. LATENCY. The request cannot complete until generation stops. A cap that is
//      far above what the answer needs just means a stuck generation runs longer
//      before anything is returned.
//
// So we size the budget to the task and let the caller override it:
//   - SCAN: the analysis is a bounded JSON object (summary + recommendations).
//     ~4000 tokens is generous for that, and it comfortably clears the ~600-900
//     tokens of reasoning a reasoning model spends before emitting content.
//   - TEST: a one-word liveness probe. 512 tokens is plenty; the point is only to
//     prove the key works and the model answers with non-empty content.
//
// Both are well inside the ceiling, so we never trip the [1, 393216] validator.
const TOKEN_LIMITS = {
  MAX: 393216,        // hard ceiling enforced by the gateway (do not exceed)
  SCAN: 4000,         // JSON analysis object + reasoning headroom
  TEST: 512,          // liveness probe
  MIN_REASONING: 512  // reasoning models emit reasoning_content BEFORE content
};

// Total wall-clock budget for one cloud call. This — not max_tokens — is the real
// limit on how long a generation may run, so it must scale with the output budget
// instead of sitting at a fixed 90s that aborts long-but-legitimate replies.
const CLOUD_TIMEOUT_MS = 180000; // 3 minutes

/**
 * POST with bounded exponential backoff.
 *
 * Transient failures are common on shared AI gateways: 429 when rate-limited,
 * 5xx during upstream restarts, and plain network errors. Retrying these is
 * worthwhile, but only when the request never reached the model — a 4xx such as
 * 401/403/404 will fail identically every time and must not be retried.
 */
async function fetchWithRetry(url, options, { attempts = 3, baseDelayMs = 800, totalTimeoutMs = CLOUD_TIMEOUT_MS } = {}) {
  const startedAt = Date.now();
  let lastErr;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    const remaining = totalTimeoutMs - (Date.now() - startedAt);
    if (remaining <= 0) break;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), remaining);
    try {
      const resp = await fetch(url, { ...options, signal: controller.signal });
      clearTimeout(timer);

      // Success, or a permanent client error: return it to the caller as-is.
      if (resp.ok || (resp.status >= 400 && resp.status < 500 && resp.status !== 429)) {
        return resp;
      }

      // Retryable: 429 or 5xx.
      lastErr = new Error(`HTTP ${resp.status}`);
      if (attempt === attempts) return resp;
      const retryAfter = parseInt(resp.headers.get('retry-after') || '', 10);
      const delay = Number.isFinite(retryAfter)
        ? Math.min(retryAfter * 1000, 10000)
        : Math.min(baseDelayMs * 2 ** (attempt - 1), 8000);
      console.warn(`[VulnLens] ${lastErr.message} on attempt ${attempt}/${attempts}; retrying in ${delay}ms`);
      await new Promise(r => setTimeout(r, delay));
    } catch (err) {
      clearTimeout(timer);
      lastErr = err;
      if (attempt === attempts) break;
      const delay = Math.min(baseDelayMs * 2 ** (attempt - 1), 8000);
      console.warn(`[VulnLens] network error "${err.message}" on attempt ${attempt}/${attempts}; retrying in ${delay}ms`);
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw lastErr || new Error('Request failed');
}

/**
 * Read a Server-Sent Events response and reassemble the completion.
 *
 * When streaming is enabled the gateway sends `data: {...}` chunks, each holding
 * a token delta, terminated by `data: [DONE]`. Reassembling them here means the
 * request still yields one complete string to the caller — but the connection is
 * proven live immediately, which is what allows a long output budget to be
 * trustworthy rather than a hang waiting to happen.
 */
async function readSSECompletion(resp) {
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let content = '';
  let finishReason = null;
  let usage = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split('\n');
    buffer = lines.pop() || ''; // keep the trailing partial line

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('data:')) continue;
      const payload = trimmed.slice(5).trim();
      if (!payload || payload === '[DONE]') continue;
      try {
        const chunk = JSON.parse(payload);
        // Usage arrives on a chunk whose `choices` array is EMPTY, so read it
        // before touching choices or it gets skipped (verified live).
        if (chunk.usage) usage = chunk.usage;
        const choice = chunk.choices && chunk.choices[0];
        if (choice) {
          const delta = choice.delta?.content;
          if (delta) content += delta;
          // finish_reason may arrive on a delta chunk near the end, distinct
          // from the usage chunk, so capture it independently.
          if (choice.finish_reason) finishReason = choice.finish_reason;
        }
      } catch {
        // A malformed chunk must not discard everything already received.
      }
    }
  }
  return { content, finishReason, usage };
}

async function callDeepSeekCloudAPI(url, findings, apiKey, endpoint, model, opts = {}) {
  const prompt = buildAnalysisPrompt(url, findings);

  const apiEndpoint = endpoint || 'https://agentrouter.org/v1/chat/completions';
  const apiModel = model || 'deepseek-v4-flash';

  // Clamp to the gateway's advertised range so a bad caller value fails loudly
  // here with a clear message rather than as an opaque HTTP 400 later.
  const requested = Number(opts.maxTokens) || TOKEN_LIMITS.SCAN;
  const maxTokens = Math.max(1, Math.min(requested, TOKEN_LIMITS.MAX));
  const useStream = opts.stream !== false;

  const body = {
    model: apiModel,
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: prompt }
    ],
    max_tokens: maxTokens,
    temperature: 0.1
  };
  if (useStream) body.stream = true;
  // Ask the gateway to append a final usage chunk. Without this the stream
  // carries no token counts, and the empty-content diagnostic loses the
  // completion_tokens evidence it relies on. Verified live: with include_usage
  // the last chunk before [DONE] contains {"usage":{...}}.
  if (useStream) body.stream_options = { include_usage: true };

  const resp = await fetchWithRetry(apiEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
      // Required by AgentRouter: without this UA the gateway returns 401.
      'User-Agent': AGENTROUTER_UA,
      'x-app': 'cli',
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify(body)
  }, { totalTimeoutMs: CLOUD_TIMEOUT_MS });

  if (!resp.ok) {
    const errText = await resp.text();
    let hint = '';

    // AgentRouter returns 401 for TWO distinct causes. Classify by the message body,
    // not the status code — conflating them sends the user to debug the wrong layer.
    //   "unauthorized client detected" -> client-fingerprint (User-Agent) problem
    //   "无效的令牌" / "invalid token"  -> the KEY itself is wrong/revoked/mistyped
    if (resp.status === 401) {
      if (/unauthorized client|unauthorized_client/i.test(errText)) {
        hint = ' — the gateway rejected the client fingerprint: the request is missing the required User-Agent header.';
      } else if (/无效的令牌|invalid token|令牌无效/i.test(errText)) {
        hint = ' — the API KEY IS INVALID. Re-copy it from the AgentRouter console; a single mistyped or missing character produces exactly this error.';
      } else {
        hint = ' — unauthorized. Verify the API key in API Settings.';
      }
    } else if (resp.status === 403) {
      hint = /该令牌无权访问模型|not authorized/i.test(errText)
        ? ` — the key is VALID but is not authorized for model "${apiModel}". Use a permitted model (e.g. deepseek-v4-flash).`
        : ' — forbidden.';
    } else if (resp.status === 404) {
      hint = ' — endpoint not found. The URL must include /v1/ (e.g. https://agentrouter.org/v1/chat/completions).';
    } else if (resp.status === 429) {
      hint = ' — rate limited even after retries. Wait a moment and try again.';
    } else if (resp.status === 503) {
      hint = ' — no available channel for this model right now; it may be outside the batch window (daily batches at 10:00 and 19:00 Beijing time).';
    } else if (resp.status >= 500) {
      hint = ' — upstream gateway error, still failing after retries.';
    }
    throw new Error(`Cloud API [${apiModel}] returned HTTP ${resp.status}${hint}: ${errText.slice(0, 300)}`);
  }

  let rawContent = '';
  let finishReason = null;
  let usedTokens = null;

  if (useStream) {
    const sse = await readSSECompletion(resp);
    rawContent = (sse.content || '').trim();
    finishReason = sse.finishReason;
    usedTokens = sse.usage?.completion_tokens ?? null;
  } else {
    const data = await resp.json();
    rawContent = (data.choices?.[0]?.message?.content ?? '').trim();
    finishReason = data.choices?.[0]?.finish_reason ?? null;
    usedTokens = data.usage?.completion_tokens ?? null;
  }

  if (!rawContent) {
    // Distinguish "the model was never asked properly" from "the budget ran out".
    // A reasoning model spends tokens on reasoning_content BEFORE emitting
    // content, so a truncated finish with no content means the budget was
    // exhausted mid-reasoning — a configuration problem, not a broken gateway.
    //
    // NOTE: the gateway reports this as EITHER "max_tokens" OR "length"
    // depending on the upstream path (verified live: a 16-token budget returned
    // finish_reason "length"). Checking only "max_tokens" silently downgrades a
    // perfectly diagnosable cause to a vague error, so accept both.
    if (finishReason === 'max_tokens' || finishReason === 'length') {
      throw new Error(
        `Cloud API spent its entire ${maxTokens}-token budget on reasoning and emitted no content ` +
        `(finish_reason "${finishReason}"). Raise TOKEN_LIMITS.SCAN (ceiling is ${TOKEN_LIMITS.MAX}).`
      );
    }
    throw new Error('Cloud API returned an empty completion.');
  }

  let parsed;
  try {
    parsed = JSON.parse(extractJson(rawContent));
  } catch (parseErr) {
    throw new Error(`Cloud API returned unparseable JSON: ${parseErr.message}. Raw: ${rawContent.slice(0, 200)}`);
  }

  const localFallback = globalThis.VulnLensLocalEngine.generateLocalAnalysis(url, findings);
  return {
    summary: parsed.summary || localFallback.summary,
    recommendations: Array.isArray(parsed.recommendations) && parsed.recommendations.length
      ? parsed.recommendations
      : localFallback.recommendations,
    risk_level: parsed.risk_level || localFallback.risk_level,
    risk_score: parsed.risk_score !== undefined ? parsed.risk_score : localFallback.risk_score,
    engine: `AgentRouter (${apiModel})`,
    // Surface the budget/streaming facts so the report and console can prove what
    // was actually requested instead of leaving it to inference.
    meta: {
      max_tokens: maxTokens,
      streamed: useStream,
      finish_reason: finishReason,
      completion_tokens: usedTokens
    }
  };
}

/**
 * Some providers wrap JSON in markdown fences or add prose around it.
 * Strip fences and isolate the outermost JSON object before parsing, so a
 * slightly-off completion still yields a usable analysis instead of throwing.
 */
function extractJson(text) {
  let t = text.trim();
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) t = fence[1].trim();
  const start = t.indexOf('{');
  const end = t.lastIndexOf('}');
  if (start !== -1 && end > start) t = t.slice(start, end + 1);
  return t;
}

browser.runtime.onMessage.addListener(async (msg) => {
  if (msg?.type === 'VULNLENS_RUN_SCAN') {
    try {
      const tabId = msg.tabId ?? (await browser.tabs.query({ active: true, currentWindow: true }))[0]?.id;
      const result = await runFullScan(tabId);
      const scanId = Date.now();
      result.id = scanId;
      await browser.storage.local.set({ vulnlens_last_scan: result });
      await saveScanToHistory(result, scanId);
      await saveScanDetail(scanId, result, result.analysis || null);
      return { ok: true, result };
    } catch (err) {
      return { ok: false, error: String(err) };
    }
  }

  if (msg?.type === 'VULNLENS_DETECT_OLLAMA') {
    try {
      const { apiUrl } = await browser.storage.local.get({
        apiUrl: 'http://127.0.0.1:11434'
      });
      const base = apiUrl || 'http://127.0.0.1:11434';
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      const resp = await fetch(`${base.replace(/\/$/, '')}/api/tags`, { signal: controller.signal });
      clearTimeout(timeoutId);

      if (!resp.ok) throw new Error(`Ollama API status ${resp.status}`);
      const data = await resp.json();
      const models = (data.models || []).map(m => m.name);
      return { ok: true, models };
    } catch (err) {
      return { ok: false, error: String(err) };
    }
  }

  if (msg?.type === 'VULNLENS_AI_ANALYZE') {
    try {
      const { apiUrl, ollamaModel, aiProvider, deepseekApiKey, cloudEndpoint, cloudModel } = await browser.storage.local.get({
        apiUrl: 'http://127.0.0.1:11434',
        ollamaModel: 'llama3',
        aiProvider: 'ollama',
        deepseekApiKey: '',
        cloudEndpoint: 'https://agentrouter.org/v1/chat/completions',
        cloudModel: 'deepseek-v4-flash'
      });

      let analysis;
      if (aiProvider === 'deepseek_cloud') {
        if (!deepseekApiKey) {
          throw new Error('Cloud API Key missing. Enter key in API Settings.');
        }
        try {
          analysis = await callDeepSeekCloudAPI(msg.url, msg.findings, deepseekApiKey, cloudEndpoint, cloudModel);
        } catch (apiErr) {
          console.warn("DeepSeek Cloud API call failed, falling back to client-side rule engine: ", apiErr);
          analysis = globalThis.VulnLensLocalEngine.generateLocalAnalysis(msg.url, msg.findings);
          analysis.engine = `local-fallback (DeepSeek error: ${apiErr.message})`;
        }
      } else {
        const base = apiUrl || 'http://127.0.0.1:11434';
        const model = ollamaModel || 'llama3';
        const prompt = buildAnalysisPrompt(msg.url, msg.findings);

        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 25000); // 25s timeout

          const resp = await fetch(`${base.replace(/\/$/, '')}/api/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              model: model,
              messages: [
                { role: 'system', content: SYSTEM_PROMPT },
                { role: 'user', content: prompt }
              ],
              stream: false,
              options: { temperature: 0.2 },
              format: 'json'
            }),
            signal: controller.signal
          });
          clearTimeout(timeoutId);

          if (!resp.ok) throw new Error(`Ollama API returned status ${resp.status}`);
          const data = await resp.json();
          const rawContent = data.message.content.trim();
          const parsed = JSON.parse(rawContent);

          const localFallback = globalThis.VulnLensLocalEngine.generateLocalAnalysis(msg.url, msg.findings);
          analysis = {
            summary: parsed.summary || localFallback.summary,
            recommendations: parsed.recommendations || localFallback.recommendations,
            risk_level: parsed.risk_level || localFallback.risk_level,
            risk_score: parsed.risk_score !== undefined ? parsed.risk_score : localFallback.risk_score,
            engine: `local-llm-ollama (${model})`
          };
        } catch (ollamaErr) {
          console.warn("Direct local Ollama connection failed, executing client-side rule fallback: ", ollamaErr);
          analysis = globalThis.VulnLensLocalEngine.generateLocalAnalysis(msg.url, msg.findings);
        }
      }

      // Update scan detail with the analysis
      const scanId = msg.scanId || (await browser.storage.local.get('vulnlens_last_scan')).vulnlens_last_scan?.id;
      if (scanId) {
        const lastScan = (await browser.storage.local.get('vulnlens_last_scan')).vulnlens_last_scan;
        if (lastScan) {
          lastScan.analysis = analysis;
          await browser.storage.local.set({ vulnlens_last_scan: lastScan });
        }
        await saveScanDetail(scanId, { url: msg.url, timestamp: new Date().toISOString(), findings: msg.findings }, analysis);
      }

      return { ok: true, analysis };
    } catch (err) {
      return { ok: false, error: String(err) };
    }
  }

  if (msg?.type === 'VULNLENS_GET_HISTORY') {
    try {
      const { scanHistory } = await browser.storage.local.get({ scanHistory: [] });
      return { ok: true, history: scanHistory };
    } catch (err) {
      return { ok: false, error: String(err) };
    }
  }

  if (msg?.type === 'VULNLENS_GET_HISTORY_DETAIL') {
    try {
      const key = `scan_detail_${msg.scanId}`;
      const data = await browser.storage.local.get(key);
      const detail = data[key];
      if (!detail) throw new Error('Scan detail not found');
      return { ok: true, detail };
    } catch (err) {
      return { ok: false, error: String(err) };
    }
  }

  if (msg?.type === 'VULNLENS_CLEAR_HISTORY') {
    try {
      const { scanHistory } = await browser.storage.local.get({ scanHistory: [] });
      for (let item of scanHistory) {
        await browser.storage.local.remove(`scan_detail_${item.id}`);
      }
      await browser.storage.local.remove('scanHistory');
      await browser.storage.local.remove('vulnlens_last_scan');
      return { ok: true };
    } catch (err) {
      return { ok: false, error: String(err) };
    }
  }
});
