/**
 * VulnLens AI - popup.js (Firefox build)
 * Authors: Yash M. Panchal & Umang K. Nagwadiya
 */

const scanBtn = document.getElementById('scanBtn');
const analyzeBtn = document.getElementById('analyzeBtn');
const reportPdfBtn = document.getElementById('reportPdfBtn');
const statusEl = document.getElementById('status');
const summaryEl = document.getElementById('summary');
const findingsCountEl = document.getElementById('findingsCount');
const riskLabelEl = document.getElementById('riskLabel');
const riskScoreEl = document.getElementById('riskScore');
const scoreRingEl = document.querySelector('.score-ring');
const findingsListEl = document.getElementById('findingsList');
const connectionStatusEl = document.getElementById('connectionStatus');

// Footer elements
const settingsToggle = document.getElementById('settingsToggle');
const settingsPanel = document.getElementById('settingsPanel');
const apiUrlInput = document.getElementById('apiUrl');
const ollamaModelInput = document.getElementById('ollamaModel');
const saveSettingsBtn = document.getElementById('saveSettings');

const aiProviderSelect = document.getElementById('aiProvider');
const deepseekSettingsDiv = document.getElementById('deepseekSettings');
const ollamaSettingsDiv = document.getElementById('ollamaSettings');
const deepseekApiKeyInput = document.getElementById('deepseekApiKey');
const cloudEndpointInput = document.getElementById('cloudEndpoint');
const cloudModelInput = document.getElementById('cloudModel');
const testApiBtn = document.getElementById('testApiBtn');
const apiTestResult = document.getElementById('apiTestResult');

const historyToggle = document.getElementById('historyToggle');
const historyPanel = document.getElementById('historyPanel');
const historyListEl = document.getElementById('historyList');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');

let lastScan = null;
let lastAnalysis = null;

const SEVERITY_WEIGHT = { high: 10, medium: 5, low: 2, info: 0 };

init();

async function init() {
  const { apiUrl, aiProvider, deepseekApiKey, cloudEndpoint, cloudModel } = await browser.storage.local.get({
    apiUrl: 'http://127.0.0.1:11434',
    aiProvider: 'ollama',
    deepseekApiKey: '',
    cloudEndpoint: 'https://agentrouter.org/v1/chat/completions',
    cloudModel: 'deepseek-v4-flash'
  });
  apiUrlInput.value = apiUrl;
  aiProviderSelect.value = aiProvider || 'ollama';
  deepseekApiKeyInput.value = deepseekApiKey || '';
  cloudEndpointInput.value = cloudEndpoint || 'https://agentrouter.org/v1/chat/completions';
  cloudModelInput.value = cloudModel || 'deepseek-v4-flash';

  // Snapshot the saved settings so we can detect unsaved edits. Test API Key reads the
  // input box while the scan reads storage — if those diverge, the test passes but the
  // scan reports a bad key, which is deeply confusing.
  lastSavedSignature = settingsSignature();

  updateProviderUI(aiProviderSelect.value);

  const { vulnlens_last_scan } = await browser.storage.local.get('vulnlens_last_scan');
  if (vulnlens_last_scan) {
    lastScan = vulnlens_last_scan;
    lastAnalysis = vulnlens_last_scan.analysis || null;
    renderScan(lastScan);
    if (lastScan.findings && lastScan.findings.length > 0) {
      reportPdfBtn.disabled = false;
    }
    if (lastAnalysis) {
      setStatus('Loaded last scan analysis from storage.');
    } else {
      setStatus('Loaded last scan findings. Run AI Analysis to generate recommendations.');
    }
  }
}

function updateProviderUI(provider) {
  if (provider === 'deepseek_cloud') {
    deepseekSettingsDiv.classList.remove('hidden');
    ollamaSettingsDiv.classList.add('hidden');
    connectionStatusEl.textContent = 'AgentRouter (DeepSeek V4 Flash)';
    connectionStatusEl.className = 'ollama-status online';
    setStatus('AgentRouter Cloud API active (deepseek-v4-flash). Paste your API Key, then Save.');
  } else {
    deepseekSettingsDiv.classList.add('hidden');
    ollamaSettingsDiv.classList.remove('hidden');
    detectAndPopulateModels();
  }
}

aiProviderSelect.addEventListener('change', () => {
  updateProviderUI(aiProviderSelect.value);
});

async function detectAndPopulateModels() {
  if (aiProviderSelect.value === 'deepseek_cloud') return;
  ollamaModelInput.innerHTML = '<option value="">Detecting local models...</option>';
  connectionStatusEl.textContent = 'Probing...';
  connectionStatusEl.className = 'ollama-status offline';

  try {
    const response = await browser.runtime.sendMessage({ type: 'VULNLENS_DETECT_OLLAMA' });
    ollamaModelInput.innerHTML = '';
    
    if (response.ok && response.models && response.models.length > 0) {
      response.models.forEach(model => {
        const option = document.createElement('option');
        option.value = model;
        option.textContent = model;
        ollamaModelInput.appendChild(option);
      });
      
      const { ollamaModel } = await browser.storage.local.get('ollamaModel');
      if (ollamaModel && response.models.includes(ollamaModel)) {
        ollamaModelInput.value = ollamaModel;
      } else {
        ollamaModelInput.value = response.models[0];
        await browser.storage.local.set({ ollamaModel: response.models[0] });
      }
      
      connectionStatusEl.textContent = 'Ollama Connected';
      connectionStatusEl.className = 'ollama-status online';
      setStatus('Ollama active. Model pipeline loaded.');
    } else {
      const option = document.createElement('option');
      option.value = '';
      option.textContent = 'None (Rule-based Fallback)';
      ollamaModelInput.appendChild(option);
      
      connectionStatusEl.textContent = 'Ollama Empty';
      connectionStatusEl.className = 'ollama-status offline';
      setStatus('No models found in Ollama. Fallback active.');
    }
  } catch (err) {
    ollamaModelInput.innerHTML = '<option value="">None (Rule-based Fallback)</option>';
    connectionStatusEl.textContent = 'Ollama Offline';
    connectionStatusEl.className = 'ollama-status offline';
    setStatus('Ollama offline. Rule-based local analysis active.');
  }
}

settingsToggle.addEventListener('change', async () => {
  const isOpened = !settingsPanel.classList.toggle('hidden', !settingsToggle.checked);
  if (isOpened) {
    historyToggle.checked = false;
    historyPanel.classList.add('hidden');
    updateProviderUI(aiProviderSelect.value);
  }
});

historyToggle.addEventListener('change', async () => {
  const isOpened = !historyPanel.classList.toggle('hidden', !historyToggle.checked);
  if (isOpened) {
    settingsToggle.checked = false;
    settingsPanel.classList.add('hidden');
    await loadAndRenderHistory();
  }
});

async function loadAndRenderHistory() {
  historyListEl.innerHTML = '<li style="color:#8b93a7; cursor:default; justify-content:center;">Loading history...</li>';
  try {
    const response = await browser.runtime.sendMessage({ type: 'VULNLENS_GET_HISTORY' });
    historyListEl.innerHTML = '';
    
    if (response.ok && response.history && response.history.length > 0) {
      response.history.forEach(item => {
        const li = document.createElement('li');
        li.className = 'history-item';
        
        let domain = 'unknown';
        try { domain = new URL(item.url).hostname; } catch(e) {}
        const time = new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        li.innerHTML = `
          <span class="history-url" title="${escapeHtml(item.url)}">${escapeHtml(domain)}</span>
          <span style="display:flex; gap:8px; align-items:center;">
            <span style="color:#8b93a7; font-size:9px;">${time}</span>
            <span class="history-count">${item.findingsCount} findings</span>
          </span>
        `;
        li.addEventListener('click', async () => {
          setStatus('Loading historical scan...');
          const detailResp = await browser.runtime.sendMessage({ type: 'VULNLENS_GET_HISTORY_DETAIL', scanId: item.id });
          if (detailResp.ok && detailResp.detail) {
            lastScan = {
              url: detailResp.detail.url,
              timestamp: detailResp.detail.timestamp,
              findings: detailResp.detail.findings,
              id: item.id
            };
            lastAnalysis = detailResp.detail.analysis;
            
            renderScan(lastScan);
            if (lastAnalysis) {
              setStatus('Loaded scan with AI Analysis from history.');
            } else {
              setStatus('Loaded scan from history. Run AI Analysis to generate recommendations.');
            }
          } else {
            setStatus('Failed to load historical scan details.');
          }
        });
        historyListEl.appendChild(li);
      });
    } else {
      historyListEl.innerHTML = '<li style="color:#8b93a7; cursor:default; justify-content:center;">No scan history yet</li>';
    }
  } catch (err) {
    historyListEl.innerHTML = `<li style="color:#f87171; cursor:default; justify-content:center;">Error: ${err.message}</li>`;
  }
}

clearHistoryBtn.addEventListener('click', async () => {
  if (confirm('Are you sure you want to delete all past scans?')) {
    setStatus('Clearing history...');
    const response = await browser.runtime.sendMessage({ type: 'VULNLENS_CLEAR_HISTORY' });
    if (response.ok) {
      lastScan = null;
      lastAnalysis = null;
      summaryEl.classList.add('hidden');
      findingsListEl.innerHTML = '';
      reportPdfBtn.disabled = true;
      analyzeBtn.disabled = true;
      setStatus('Scan history cleared successfully.');
      await loadAndRenderHistory();
    } else {
      setStatus('Failed to clear history.');
    }
  }
});

saveSettingsBtn.addEventListener('click', async () => {
  await browser.storage.local.set({
    apiUrl: apiUrlInput.value.trim(),
    ollamaModel: ollamaModelInput.value,
    aiProvider: aiProviderSelect.value,
    deepseekApiKey: deepseekApiKeyInput.value.trim(),
    cloudEndpoint: cloudEndpointInput.value.trim() || 'https://agentrouter.org/v1/chat/completions',
    cloudModel: cloudModelInput.value.trim() || 'deepseek-v4-flash'
  });
  lastSavedSignature = settingsSignature();
  setStatus('Settings saved.');
  updateProviderUI(aiProviderSelect.value);
});

/**
 * A signature of the currently-saved cloud settings, so we can detect unsaved edits.
 * Test API Key reads the INPUT; the scan reads STORAGE. If the user tests a new key
 * and forgets to Save, the scan silently uses the old one — which surfaces as
 * "key invalid" on scan even though the test just passed.
 */
function settingsSignature() {
  return JSON.stringify([
    aiProviderSelect.value,
    deepseekApiKeyInput.value.trim(),
    cloudEndpointInput.value.trim(),
    cloudModelInput.value.trim()
  ]);
}

let lastSavedSignature = null;

function hasUnsavedCloudEdits() {
  return lastSavedSignature !== null && settingsSignature() !== lastSavedSignature;
}

testApiBtn.addEventListener('click', async () => {
  const key = deepseekApiKeyInput.value.trim();
  const endpoint = cloudEndpointInput.value.trim() || 'https://agentrouter.org/v1/chat/completions';
  const model = cloudModelInput.value.trim() || 'deepseek-v4-flash';

  if (!key) {
    apiTestResult.textContent = 'Enter an API key first.';
    apiTestResult.style.color = '#f87171';
    return;
  }

  // Warn if these settings aren't saved yet — the scan reads storage, not this input.
  const unsaved = hasUnsavedCloudEdits();

  // Pre-flight sanity checks — catch paste errors before burning a network round-trip.
  // A truncated, whitespace-padded, or character-swapped key produces the SAME 401 as a
  // fingerprint problem, which sends people debugging the wrong thing entirely.
  const keyProblems = [];
  if (key !== deepseekApiKeyInput.value) keyProblems.push('has leading/trailing whitespace');
  if (/\s/.test(key)) keyProblems.push('contains an internal space');
  if (!key.startsWith('sk-')) keyProblems.push('does not start with "sk-"');
  if (key.length < 40) keyProblems.push(`looks truncated (${key.length} chars)`);

  if (keyProblems.length) {
    apiTestResult.textContent = `Key looks malformed: ${keyProblems.join('; ')}. Re-copy it from the AgentRouter console.`;
    apiTestResult.style.color = '#fbbf24';
    return;
  }

  apiTestResult.textContent = 'Testing…';
  apiTestResult.style.color = '#8b93a7';
  testApiBtn.disabled = true;

  const started = Date.now();
  try {
    const controller = new AbortController();
    const to = setTimeout(() => controller.abort(), 60000);
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${key}`,
        // Required by AgentRouter — without the CLI User-Agent it returns 401.
        'User-Agent': 'claude-cli/2.1.281 (external, cli)',
        'x-app': 'cli',
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: 'Reply with exactly: OK' }],
        // deepseek-v4-flash is a REASONING model: it emits reasoning_content BEFORE
        // content, and reasoning is billed against max_tokens. A small budget (e.g. 12)
        // is consumed entirely by reasoning, so `content` returns "" with
        // finish_reason "max_tokens" — which looks like a broken model but is just a
        // too-small budget. A trivial liveness probe needs no more than this; the
        // gateway's ceiling is 393216, but a test should assert reachability, not
        // maximize spend.
        max_tokens: 512
      }),
      signal: controller.signal
    });
    clearTimeout(to);
    const elapsed = Date.now() - started;

    if (!resp.ok) {
      const errText = await resp.text();
      let hint = '';

      // AgentRouter returns 401 for TWO completely different causes. Classify by the
      // message body, not the status code — otherwise an invalid key gets misreported
      // as a User-Agent problem and the user debugs the wrong layer.
      //
      //   "unauthorized client detected"  -> missing/mismatched client-fingerprint UA
      //   "无效的令牌" / "invalid token"   -> the KEY is wrong, revoked, or mistyped
      if (resp.status === 401) {
        if (/unauthorized client|unauthorized_client/i.test(errText)) {
          hint = ' (client fingerprint rejected — the request is missing the required User-Agent header)';
        } else if (/无效的令牌|invalid token|令牌无效/i.test(errText)) {
          hint = ' (API KEY IS INVALID — re-copy it from https://agentrouter.org/console/token; check for a missing or swapped character)';
        } else {
          hint = ' (unauthorized — check the API key)';
        }
      } else if (resp.status === 403) {
        hint = /该令牌无权访问模型|not authorized/i.test(errText)
          ? ` (key is VALID, but not authorized for model "${model}" — check the model name on the pricing page)`
          : ' (forbidden)';
      } else if (resp.status === 404) {
        hint = ' (endpoint not found — check the URL; it must include /v1/)';
      } else if (resp.status === 429) {
        hint = ' (rate limited — wait and retry)';
      } else if (resp.status === 503) {
        hint = ' (model unavailable right now — AgentRouter rations models in daily batches at 10:00 and 19:00 Beijing time)';
      } else if (resp.status >= 500) {
        hint = ' (upstream server error — retry shortly)';
      }

      apiTestResult.textContent = `FAILED — HTTP ${resp.status}${hint} (${elapsed}ms): ${errText.slice(0, 140)}`;
      apiTestResult.style.color = '#f87171';
      return;
    }

    // HTTP 200 is NOT sufficient proof of success. A reasoning model with an
    // exhausted budget returns 200 with empty `content` and finish_reason
    // "max_tokens" — report that honestly instead of a misleading "OK".
    const data = await resp.json();
    const choice = data?.choices?.[0] || {};
    const reply = choice.message?.content ?? '';
    const reasoning = choice.message?.reasoning_content;
    const finish = choice.finish_reason;
    const used = data?.usage?.completion_tokens;

    let suffix = unsaved ? '  ⚠ Not saved yet — click Save, or the scan will use the old key.' : '';

    if (!String(reply).trim()) {
      // The gateway reports a truncated generation as EITHER "max_tokens" or
      // "length" (verified live: a 16-token budget returned "length"), so both
      // must be treated as budget exhaustion or the cause goes unexplained.
      if (finish === 'max_tokens' || finish === 'length') {
        apiTestResult.textContent =
          `FAILED — model returned an EMPTY reply: the token budget was exhausted by reasoning ` +
          `(${used} tokens used, finish_reason "${finish}"). (${elapsed}ms). ` +
          `Raise max_tokens — the gateway allows up to 393216, and deepseek-v4-flash ` +
          `spends tokens on reasoning before content.${suffix}`;
      } else {
        apiTestResult.textContent =
          `FAILED — model returned an empty reply (${reasoning ? 'reasoning-only response; ' : ''}` +
          `finish_reason "${finish || 'unknown'}") in ${elapsed}ms.${suffix}`;
      }
      apiTestResult.style.color = '#f87171';
      return;
    }

    apiTestResult.textContent =
      `OK — model "${model}" replied "${String(reply).trim().slice(0, 40)}" in ${elapsed}ms` +
      (used ? ` (${used} completion tokens)` : '') + suffix;
    apiTestResult.style.color = unsaved ? '#fbbf24' : '#34d399';
  } catch (err) {
    apiTestResult.textContent = `FAILED — ${err.message}`;
    apiTestResult.style.color = '#f87171';
  } finally {
    testApiBtn.disabled = false;
  }
});

scanBtn.addEventListener('click', async () => {  setStatus('Scanning and analyzing with AI — please wait...');
  scanBtn.disabled = true;
  try {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    const response = await browser.runtime.sendMessage({ type: 'VULNLENS_RUN_SCAN', tabId: tab.id });
    if (!response.ok) throw new Error(response.error);
    lastScan = response.result;
    lastAnalysis = response.result.analysis || null;  // AI analysis embedded during scan
    renderScan(lastScan);
    if (lastAnalysis) {
      const engineBadge = lastAnalysis.engine || 'AI';
      const diag = lastScan.diagnostics || {};
      // Surface provenance honestly: never claim cloud AI succeeded when the
      // engine label says it fell back.
      const fellBack = /local-fallback/i.test(engineBadge);
      const warn = [];
      if (diag.headerStatus === 'stale') warn.push('header data was captured for a different URL — reload the page and re-scan');
      if (diag.headerStatus === 'unavailable') warn.push('no header data captured — reload the page');

      if (fellBack && diag.analysisError) {
        const err = diag.analysisError;
        // An "invalid key" on scan — right after Test API Key passed — almost always
        // means the new key was tested but never Saved. The scan reads storage, the
        // test reads the input box. Name that case explicitly instead of leaving the
        // user staring at a generic 401.
        if (/API KEY IS INVALID|无效的令牌|invalid token/i.test(err) && hasUnsavedCloudEdits()) {
          warn.push('the API key in the settings box was NOT SAVED — click Save, then re-scan (Test API Key uses the box, but scanning uses saved settings)');
        } else if (/API KEY IS INVALID|无效的令牌|invalid token/i.test(err)) {
          warn.push('the saved API key was rejected — re-copy it from the AgentRouter console and click Save');
        } else {
          warn.push(`cloud AI unavailable (${err.slice(0, 110)})`);
        }
      }

      const base = fellBack
        ? `Scan complete — ${lastScan.findings.length} finding(s). Local analysis used; cloud AI did not run.`
        : `Scan + AI analysis complete (${engineBadge}). ${lastScan.findings.length} finding(s). Ready to export PDF.`;
      setStatus(warn.length ? `${base} Note: ${warn.join('; ')}.` : base);
      reportPdfBtn.disabled = false;
    } else {
      setStatus(`Scan complete: ${lastScan.findings.length} finding(s). Click Analyze for AI recommendations.`);
    }
  } catch (err) {
    setStatus(`Error: ${err.message}. Try reloading the target page first.`);
  } finally {
    scanBtn.disabled = false;
  }
});

analyzeBtn.addEventListener('click', async () => {
  if (!lastScan) return;
  setStatus('Re-running AI analysis...');
  analyzeBtn.disabled = true;
  try {
    const response = await browser.runtime.sendMessage({
      type: 'VULNLENS_AI_ANALYZE',
      findings: lastScan.findings,
      url: lastScan.url
    });
    if (!response.ok) throw new Error(response.error);
    lastAnalysis = response.analysis;
    const engineBadge = lastAnalysis.engine || 'AI';
    setStatus(`AI analysis complete (${engineBadge}). Ready to generate report.`);
    reportPdfBtn.disabled = false;
  } catch (err) {
    setStatus(`AI analysis failed: ${err.message}.`);
  } finally {
    analyzeBtn.disabled = false;
  }
});

reportPdfBtn.addEventListener('click', async () => {
  if (!lastScan) return;
  setStatus('Preparing PDF layout...');
  try {
    const html = window.VulnLensReport.buildHTML(lastScan, lastAnalysis);    await browser.storage.local.set({ vulnlens_last_report_html: html });
    await browser.tabs.create({
      url: browser.runtime.getURL('report_viewer.html')
    });
    setStatus('Report viewer opened. Use the on-screen assistant to export PDF.');
  } catch (err) {
    setStatus(`Report generation failed: ${err.message}`);
  }
});

function renderScan(scan) {
  summaryEl.classList.remove('hidden');
  findingsCountEl.textContent = scan.findings.length;
  findingsListEl.innerHTML = '';

  let score = 0;
  scan.findings.forEach(f => (score += SEVERITY_WEIGHT[f.severity] || 0));
  const capped = Math.min(100, score);
  riskScoreEl.textContent = capped;
  riskLabelEl.textContent = `Risk level: ${riskLabel(capped)}`;

  // Set score ring color
  scoreRingEl.className = 'score-ring'; // Reset
  const riskClass = capped === 0 ? 'risk-none' :
                    capped < 15 ? 'risk-low' :
                    capped < 40 ? 'risk-medium' :
                    capped < 60 ? 'risk-high' : 'risk-critical';
  scoreRingEl.classList.add(riskClass);

  scan.findings
    .slice()
    .sort((a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0))
    .forEach(f => {
      const rule = window.VulnLensLocalEngine.matchRule(f.title);
      const li = document.createElement('li');
      li.className = `sev-${f.severity}`;
      li.innerHTML = `
        <span class="finding-title">[${f.severity.toUpperCase()}] ${escapeHtml(f.title)}</span>
        <span class="finding-desc">${escapeHtml(f.description)}</span>
        <div class="finding-details">
          <strong>Vulnerability Risk:</strong> ${escapeHtml(rule.explanation)}
          <div class="finding-remediation"><strong>Defensive Fix:</strong> ${escapeHtml(rule.remediation)}</div>
        </div>
      `;
      li.addEventListener('click', (e) => {
        // Toggle expansion on click, making sure it doesn't close on clicking details inside
        if (e.target.tagName !== 'STRONG') {
          li.classList.toggle('expanded');
        }
      });
      findingsListEl.appendChild(li);
    });

  // Enable/disable action buttons
  analyzeBtn.disabled = scan.findings.length === 0;
  reportPdfBtn.disabled = scan.findings.length === 0;
}

function riskLabel(score) {
  if (score === 0) return 'None';
  if (score < 15) return 'Low';
  if (score < 40) return 'Medium';
  if (score < 60) return 'High';
  return 'Critical';
}

function setStatus(msg) {
  statusEl.textContent = msg;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
