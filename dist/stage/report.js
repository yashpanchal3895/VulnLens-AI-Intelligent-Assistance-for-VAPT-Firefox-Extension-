/**
 * VulnLens AI - report.js
 * Authors: Yash M. Panchal & Umang K. Nagwadiya
 * Builds a self-contained HTML VAPT findings report formatted for PDF printing.
 */

window.VulnLensReport = (function () {
  const SEVERITY_ORDER = ['high', 'medium', 'low', 'info'];

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  function calculateScore(scan) {
    const weights = { high: 10, medium: 5, low: 2, info: 0 };
    let score = 0;
    scan.findings.forEach(f => {
      score += weights[f.severity] || 0;
    });
    return Math.min(100, score);
  }

  function riskLabel(score) {
    if (score === 0) return 'None';
    if (score < 15) return 'Low';
    if (score < 40) return 'Medium';
    if (score < 60) return 'High';
    return 'Critical';
  }

  function buildGapAnalysis(scan) {
    const titles = (scan.findings || []).map(f => (f.title || '').toLowerCase());
    const has = (re) => titles.some(t => re.test(t));

    const controls = [
      {
        name: "Content-Security-Policy (CSP)",
        required: "Restrict resource origins & disallow unsafe inline script execution (OWASP A05)",
        test: () => has(/content-security-policy/),
        missingGap: "MISSING: No CSP header detected. Inline XSS vectors can execute unhindered.",
        weakGap: "DEFECTIVE: CSP present but weakened by unsafe directives (unsafe-inline/unsafe-eval/wildcards), leaving script injection largely unmitigated.",
        passText: "Content Security Policy configured with restrictive directives."
      },
      {
        name: "Transport Encryption (HTTPS/HSTS)",
        required: "Enforce site-wide HTTPS & Strict-Transport-Security (max-age >= 31536000, includeSubDomains)",
        test: () => has(/strict-transport-security|hsts/) || has(/served over http|submits over http/),
        missingGap: "MISSING / DEFECTIVE: Plain HTTP in use or HSTS header absent. Vulnerable to SSL-stripping.",
        weakGap: "DEFECTIVE: HSTS present but incomplete (short max-age, or missing includeSubDomains/preload), leaving downgrade windows open.",
        passText: "HTTPS and Transport Security active."
      },
      {
        name: "Clickjacking Defense (XFO / frame-ancestors)",
        required: "Frame protection via X-Frame-Options (DENY/SAMEORIGIN) or CSP frame-ancestors",
        test: () => has(/x-frame-options/),
        missingGap: "MISSING: X-Frame-Options header absent. Page can be embedded in attacker clickjacking iframes.",
        weakGap: "DEFECTIVE: X-Frame-Options uses the obsolete ALLOW-FROM directive, ignored by all modern browsers.",
        passText: "Anti-clickjacking frame protection active."
      },
      {
        name: "MIME-Type Sniffing Defense",
        required: "Include X-Content-Type-Options: nosniff header on all web responses",
        test: () => has(/x-content-type-options/),
        missingGap: "MISSING: X-Content-Type-Options absent. Browsers may MIME-sniff non-script content.",
        weakGap: "DEFECTIVE: X-Content-Type-Options is set to a value other than 'nosniff', so it has no effect.",
        passText: "MIME-type sniffing protection active."
      },
      {
        name: "Referrer Privacy Protection",
        required: "Restrict URL token/parameter leakage via strict Referrer-Policy",
        test: () => has(/referrer-policy/),
        missingGap: "MISSING: Referrer-Policy header absent. Full URLs may leak sensitive query parameters.",
        passText: "Referrer privacy policy active."
      },
      {
        name: "Cross-Origin Tab Isolation (COOP)",
        required: "Set Cross-Origin-Opener-Policy: same-origin to prevent window.opener attacks",
        test: () => has(/cross-origin-opener-policy/),
        missingGap: "MISSING: COOP header absent. Tab shares browsing context with cross-origin popups.",
        passText: "Cross-origin opener policy active."
      },
      {
        name: "CORS Wildcard Policy",
        required: "Avoid Access-Control-Allow-Origin: * on authenticated endpoints",
        test: () => has(/wildcard cors/) || has(/dangerous cors combination/),
        missingGap: "DEFECTIVE: Access-Control-Allow-Origin: * wildcard allows external origin data reading.",
        passText: "CORS policy restricts wildcard origin sharing."
      },
      {
        name: "Cookie Security Attributes",
        required: "HttpOnly, Secure and SameSite on all session/authentication cookies",
        test: () => has(/missing security flags/) || has(/readable cookies/),
        missingGap: "MISSING: Cookies lack HttpOnly/Secure/SameSite, exposing them to theft via XSS and CSRF.",
        passText: "Session cookies set with HttpOnly, Secure and SameSite."
      },
      {
        name: "Secrets & API Key Protection",
        required: "Zero hardcoded credentials (AWS, Stripe, GitHub, JWT, Private Keys) in frontend code",
        test: () => has(/exposed secret/),
        missingGap: "CRITICAL DEFECT: Exposed credential or API key pattern detected in page source/comments.",
        passText: "No hardcoded credentials detected in frontend code."
      },
      {
        name: "Form & CSRF Safeguards",
        required: "Anti-CSRF tokens on password forms & encrypted form submission endpoints",
        test: () => has(/csrf|submits over http/),
        missingGap: "MISSING: Form lacks anti-CSRF tokens or submits credentials over plain HTTP.",
        passText: "Forms pass transport and CSRF token checks."
      },
      {
        name: "DOM-XSS Execution Sinks",
        required: "Avoid document.write, eval, or innerHTML on unsanitized user inputs",
        test: () => has(/dom-xss|inline scripts/),
        missingGap: "DEFECTIVE: Unsafe DOM execution sinks or inline event handlers detected in scripts.",
        passText: "No dangerous DOM execution sinks detected."
      },
      {
        name: "Subresource Integrity (SRI)",
        required: "External scripts/styles loaded with an integrity attribute",
        test: () => has(/subresource integrity|without .*integrity/),
        missingGap: "MISSING: External resources load without integrity hashes, so a compromised CDN could inject arbitrary code.",
        passText: "External resources protected with Subresource Integrity."
      },
      {
        name: "Cache-Control Hygiene",
        required: "Well-formed caching directives; no-store on authenticated/personalised responses",
        test: () => has(/cache-control/),
        missingGap: "DEFECTIVE: Cache-Control is malformed or contradictory, so caching behaviour is ambiguous.",
        passText: "Cache-Control directives are well-formed."
      },
      {
        name: "Information Disclosure Headers",
        required: "Suppress Server / X-Powered-By and framework-internal headers",
        test: () => has(/server header discloses|x-powered-by|information-disclosure header/),
        missingGap: "MISSING: Response headers reveal server software or internal implementation details useful for reconnaissance.",
        passText: "No unnecessary technology-disclosure headers present."
      }
    ];

    let rowsHtml = '';
    controls.forEach(c => {
      // Distinguish "present but weak" from "entirely missing" — both are gaps,
      // but they call for different remediation.
      const isWeak = c.weakGap && has(/weak |obsolete |ineffective |malformed |deprecated |dangerous /) && /content-security-policy|strict-transport-security|x-frame-options|x-content-type-options|cache-control|cors|security flags/.test(c.name.toLowerCase()) ;
      const isGap = c.test();
      const statusBadge = isGap
        ? `<span class="severity-badge badge-high" style="background:rgba(239,68,68,0.15);color:#f87171;border-color:rgba(239,68,68,0.3);">MISSING / GAP</span>`
        : `<span class="severity-badge badge-success" style="background:rgba(16,185,129,0.15);color:#34d399;border-color:rgba(16,185,129,0.3);">COMPLIANT</span>`;

      const gapText = isGap
        ? escapeHtml((isWeak && c.weakGap) ? c.weakGap : c.missingGap)
        : escapeHtml(c.passText);

      rowsHtml += `
        <tr>
          <td class="bold-cell">${escapeHtml(c.name)}</td>
          <td style="font-size: 11px; color: #cbd5e1;">${escapeHtml(c.required)}</td>
          <td class="center-align">${statusBadge}</td>
          <td style="font-size: 11px; ${isGap ? 'color: #f87171; font-weight:600;' : 'color: #34d399;'}">${gapText}</td>
        </tr>`;
    });

    const compliantCount = controls.filter(c => !c.test()).length;
    const totalControls = controls.length;

    return `
      <section class="card" style="margin-top: 24px;">
        <h2>📋 Security Compliance Audit (Required Baseline vs Identified Gaps)</h2>
        <p class="muted" style="font-size: 11px; margin-bottom: 16px;">
          This audit matrix evaluates the target site against standard OWASP and W3C Web Security Baseline
          Requirements, explicitly identifying required controls, compliance status, and missing safeguards.
          <strong>${compliantCount} of ${totalControls} required controls are compliant.</strong>
        </p>
        <table>
          <thead>
            <tr>
              <th style="width: 22%;">Security Control</th>
              <th style="width: 38%;">Industry Standard Requirement</th>
              <th style="width: 15%; text-align: center;">Audit Status</th>
              <th style="width: 25%;">Observation &amp; Gap Analysis</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml}
          </tbody>
        </table>
      </section>`;
  }

  /**
   * Raw response-header evidence.
   *
   * A findings report is only auditable if the reader can verify the claim.
   * This section shows the actual header values observed, and explicitly marks
   * which expected security headers were absent — so the report stands on its
   * own as evidence rather than asking the reader to trust a derived verdict.
   */
  function buildEvidenceSection(scan) {
    const raw = scan.rawHeaders;
    if (!raw || typeof raw !== 'object') {
      return `
      <section class="card" style="margin-top: 24px;">
        <h2>🧾 Raw Evidence (HTTP Response Headers)</h2>
        <p class="muted" style="font-size: 11px;">
          Raw header evidence was not captured for this scan. Header data is only available when the
          scan ran against a live page load; scans restored from history may not include it.
        </p>
      </section>`;
    }

    const SECURITY_HEADERS = [
      'content-security-policy', 'strict-transport-security', 'x-frame-options',
      'x-content-type-options', 'referrer-policy', 'permissions-policy',
      'cross-origin-opener-policy', 'access-control-allow-origin', 'set-cookie'
    ];

    const present = SECURITY_HEADERS.filter(h => raw[h] !== undefined);
    const absent = SECURITY_HEADERS.filter(h => raw[h] === undefined);

    const rowHtml = (name, value, isPresent) => `
      <tr>
        <td class="bold-cell mono-cell">${escapeHtml(name)}</td>
        <td class="mono-cell" style="${isPresent ? 'color:#e2e8f0;' : 'color:#64748b; font-style:italic;'}">
          ${isPresent ? escapeHtml(Array.isArray(value) ? value.join('\n') : String(value)) : '— not sent by server —'}
        </td>
        <td class="center-align">
          ${isPresent
            ? '<span class="severity-badge" style="background:rgba(16,185,129,0.15);color:#34d399;border-color:rgba(16,185,129,0.3);">PRESENT</span>'
            : '<span class="severity-badge" style="background:rgba(239,68,68,0.15);color:#f87171;border-color:rgba(239,68,68,0.3);">ABSENT</span>'}
        </td>
      </tr>`;

    // Show the security-relevant headers first, then any remaining ones observed.
    const otherKeys = Object.keys(raw)
      .filter(k => !SECURITY_HEADERS.includes(k))
      .sort();

    return `
      <section class="card" style="margin-top: 24px;">
        <h2>🧾 Raw Evidence (HTTP Response Headers)</h2>
        <p class="muted" style="font-size: 11px; margin-bottom: 16px;">
          Exact values observed on the wire. ${present.length} of ${SECURITY_HEADERS.length} expected
          security headers were present; ${absent.length} were absent.
          ${scan.diagnostics?.headerStatus === 'stale'
            ? '<strong style="color:#fbbf24;">Warning: these headers were captured for a different URL than the one scanned (client-side navigation). Reload the page and re-scan for accurate header findings.</strong>'
            : ''}
          ${scan.diagnostics?.headerCapturedAt
            ? `Captured at ${escapeHtml(new Date(scan.diagnostics.headerCapturedAt).toLocaleString())}.`
            : ''}
        </p>
        <table>
          <thead>
            <tr>
              <th style="width: 30%;">Header</th>
              <th style="width: 55%;">Observed Value</th>
              <th style="width: 15%; text-align: center;">Status</th>
            </tr>
          </thead>
          <tbody>
            ${SECURITY_HEADERS.map(h => rowHtml(h, raw[h], raw[h] !== undefined)).join('')}
            ${otherKeys.map(k => rowHtml(k, raw[k], true)).join('')}
          </tbody>
        </table>
      </section>`;
  }

  function buildHTML(scan, analysis) {
    const total = scan.findings.length;
    const rawScore = calculateScore(scan);
    const scoreVal = analysis ? analysis.risk_score : rawScore;
    const levelText = analysis ? analysis.risk_level : riskLabel(rawScore);
    const generatedAt = new Date().toLocaleString();

    // 1. Group and sort findings in a single sequential array (High -> Medium -> Low -> Info)
    const weights = { high: 10, medium: 5, low: 2, info: 0 };
    const sortedFindings = [...(scan.findings || [])].sort((a, b) => {
      return (weights[b.severity] || 0) - (weights[a.severity] || 0);
    });

    // 2. Generate a single sequence-wise table
    let tableRowsHtml = '';
    if (sortedFindings.length > 0) {
      sortedFindings.forEach((f, index) => {
        const rule = window.VulnLensLocalEngine.matchRule(f.title);
        const sequenceNum = index + 1;
        tableRowsHtml += `
          <tr>
            <td class="bold-cell center-align">${sequenceNum}</td>
            <td>
              <span class="severity-badge badge-${f.severity}">${f.severity.toUpperCase()}</span>
            </td>
            <td class="bold-cell">${escapeHtml(f.title)}</td>
            <td>
              ${escapeHtml(f.description)}
              <br/><br/>
              <span class="impact-text"><strong>Technical Risk:</strong> ${escapeHtml(rule.explanation)}</span>
            </td>
            <td>
              <pre><code>${escapeHtml(rule.remediation)}</code></pre>
            </td>
          </tr>`;
      });
    }

    const findingsTableHtml = sortedFindings.length > 0
      ? `
      <table>
        <thead>
          <tr>
            <th style="width: 5%; text-align: center;">#</th>
            <th style="width: 12%;">Severity</th>
            <th style="width: 23%;">Vulnerability Title</th>
            <th style="width: 30%;">Technical Description</th>
            <th style="width: 30%;">Remediation &amp; Defensive Fix</th>
          </tr>
        </thead>
        <tbody>
          ${tableRowsHtml}
        </tbody>
      </table>`
      : '<p class="muted">No findings recorded during this passive scan session.</p>';

    // Group counts for severity stat cards
    const groups = { high: 0, medium: 0, low: 0, info: 0 };
    sortedFindings.forEach(f => {
      if (groups[f.severity] !== undefined) groups[f.severity]++;
      else groups.info++;
    });

    const gapAnalysisHtml = buildGapAnalysis(scan);
    const evidenceHtml = buildEvidenceSection(scan);

    const engineLabel = analysis?.engine ? escapeHtml(analysis.engine) : 'Local Heuristic Engine';

    const aiSection = analysis
      ? `
      <section class="card border-accent" style="margin-top: 24px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
          <h2 style="margin:0; border:none; padding:0;">🤖 AI-Assisted Security Reasoning &amp; Missing Controls Overview</h2>
          <span class="badge" style="background:rgba(99,102,241,0.15); color:#818cf8; border-color:rgba(99,102,241,0.3); font-size:11px;">
            Engine: ${engineLabel}
          </span>
        </div>
        <div class="ai-box">${escapeHtml(analysis.summary || '')}</div>
        ${Array.isArray(analysis.recommendations) ? `
          <h3>Prioritized Remediation Roadmap (Required Fixes)</h3>
          <ol class="roadmap-list">${analysis.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ol>` : ''}
      </section>`
      : `
      <section class="card" style="margin-top: 24px;">
        <p class="muted">No local AI summarization was performed for this report execution. Fallback rules applied.</p>
      </section>`;

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>VulnLens AI VAPT Report - ${escapeHtml(scan.url)}</title>
<style>
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    background: #0b0f19;
    color: #e2e8f0;
    margin: 0;
    padding: 40px;
    line-height: 1.5;
  }
  .report-container {
    max-width: 1150px;
    margin: 0 auto;
  }
  .header-area {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 2px solid #1e293b;
    padding-bottom: 20px;
    margin-bottom: 30px;
  }
  h1 { font-size: 26px; color: #f8fafc; margin: 0; font-weight: 700; letter-spacing: -0.5px; }
  h2 { font-size: 18px; color: #f1f5f9; margin-top: 0; border-bottom: 1px solid #334155; padding-bottom: 8px; }
  h3 { font-size: 14px; margin-bottom: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge-bar { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
  .badge { padding: 4px 12px; border-radius: 6px; background: #1e293b; font-size: 11px; color: #94a3b8; font-weight: 600; border: 1px solid #334155; }
  .badge.danger { background: rgba(239, 68, 68, 0.1); color: #ef4444; border-color: rgba(239, 68, 68, 0.2); }
  .badge.warning { background: rgba(245, 158, 11, 0.1); color: #f59e0b; border-color: rgba(245, 158, 11, 0.2); }
  .badge.success { background: rgba(16, 185, 129, 0.1); color: #10b981; border-color: rgba(16, 185, 129, 0.2); }
  
  .card {
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
  }
  .border-accent { border-left: 4px solid #4f46e5; }
  
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }
  .stat-card {
    background: #1f2937;
    border: 1px solid #374151;
    border-radius: 8px;
    padding: 16px;
    text-align: center;
  }
  .stat-card .val { font-size: 24px; font-weight: 700; color: #f8fafc; }
  .stat-card .lbl { font-size: 11px; color: #94a3b8; text-transform: uppercase; margin-top: 4px; font-weight: 600; }
  
  table { width: 100%; border-collapse: collapse; margin-top: 10px; margin-bottom: 30px; }
  th, td { text-align: left; padding: 12px; border-bottom: 1px solid #1f2937; font-size: 12px; vertical-align: top; }
  th { background: #111827; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; border-bottom: 2px solid #374151; }
  tr:hover { background: rgba(31, 41, 55, 0.3); }
  .bold-cell { font-weight: 600; color: #f1f5f9; }
  .center-align { text-align: center; }
  .mono-cell { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 10.5px; word-break: break-all; white-space: pre-wrap; }

  .severity-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    text-align: center;
    border: 1px solid transparent;
  }
  .badge-high { background: rgba(239, 68, 68, 0.15); color: #f87171; border-color: rgba(239, 68, 68, 0.3); }
  .badge-medium { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border-color: rgba(245, 158, 11, 0.3); }
  .badge-low { background: rgba(6, 182, 212, 0.15); color: #22d3ee; border-color: rgba(6, 182, 212, 0.3); }
  .badge-info { background: rgba(100, 116, 139, 0.15); color: #cbd5e1; border-color: rgba(100, 116, 139, 0.3); }
  
  .ai-box {
    background: #1e293b;
    border-left: 3px solid #6366f1;
    padding: 16px;
    border-radius: 8px;
    font-size: 13px;
    color: #e2e8f0;
    margin-bottom: 20px;
    white-space: pre-wrap;
  }
  .roadmap-list { margin: 0; padding-left: 20px; font-size: 12px; color: #cbd5e1; }
  .roadmap-list li { margin-bottom: 8px; }
  
  pre {
    margin: 0;
    background: #030712;
    padding: 10px;
    border-radius: 6px;
    border: 1px solid #1f2937;
    overflow-x: auto;
  }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px; color: #34d399; }
  .impact-text { color: #94a3b8; font-size: 11px; display: inline-block; margin-top: 6px; }
  
  .btn-print {
    background: #4f46e5;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .btn-print:hover { background: #4338ca; }
  
  .disclaimer {
    background: rgba(245, 158, 11, 0.05);
    border: 1px dashed rgba(245, 158, 11, 0.3);
    border-radius: 8px;
    padding: 16px;
    font-size: 11px;
    color: #f59e0b;
    margin-top: 40px;
  }
  
  footer {
    margin-top: 50px;
    border-top: 1px solid #1e293b;
    padding-top: 20px;
    font-size: 11px;
    color: #475569;
    text-align: center;
  }
  
  @media print {
    body { background: white; color: black; padding: 20px; }
    h1, h2, h3 { color: black; }
    .card, .stat-card { background: white; border: 1px solid #ccc; page-break-inside: avoid; }
    .btn-print { display: none !important; }
    th { background: #eee; color: black; border-bottom: 2px solid #555; }
    tr:hover { background: none; }
    pre { background: #f5f5f5; border-color: #ccc; }
    code { color: #065f46; }
    .badge { border-color: #ccc; color: black; background: white; }
    .ai-box { background: #f0f4f8; color: black; border-left-color: #4f46e5; page-break-inside: avoid; }
    .roadmap-list li { color: black; }
  }
</style>
</head>
<body>
  <div class="report-container">
    <div class="header-area">
      <div>
        <h1>VulnLens AI Security Audit Report</h1>
        <div class="badge-bar">
          <span class="badge">Target URL: ${escapeHtml(scan.url)}</span>
          <span class="badge">Findings: ${total}</span>
          <span class="badge">Date: ${escapeHtml(generatedAt)}</span>
          <span class="badge" style="background:rgba(99,102,241,0.15); color:#818cf8; border-color:rgba(99,102,241,0.3);">AI Engine: ${engineLabel}</span>
          <span class="badge ${scoreVal >= 60 ? 'danger' : scoreVal >= 15 ? 'warning' : 'success'}">
            Risk: ${escapeHtml(levelText)} (${scoreVal}/100)
          </span>
        </div>
      </div>
      <div>
        <button class="btn-print" onclick="window.print()">
          <svg style="width:16px;height:16px" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h10a2 2 0 002-2v-3a2 2 0 00-2-2H9a2 2 0 00-2 2v3a2 2 0 002 2zm0 0v-8a2 2 0 012-2h4a2 2 0 012 2v8H9z"></path></svg>
          Print / Save PDF
        </button>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card" style="border-top: 4px solid #ef4444;">
        <div class="val">${groups.high}</div>
        <div class="lbl">High Severity</div>
      </div>
      <div class="stat-card" style="border-top: 4px solid #f59e0b;">
        <div class="val">${groups.medium}</div>
        <div class="lbl">Medium Severity</div>
      </div>
      <div class="stat-card" style="border-top: 4px solid #06b6d4;">
        <div class="val">${groups.low}</div>
        <div class="lbl">Low Severity</div>
      </div>
      <div class="stat-card" style="border-top: 4px solid #64748b;">
        <div class="val">${groups.info}</div>
        <div class="lbl">Informational</div>
      </div>
    </div>

    ${gapAnalysisHtml}

    ${evidenceHtml}

    <section class="card" style="margin-top: 24px;">
      <h2>🔍 Vulnerability Scans &amp; Heuristic Detections</h2>
      ${findingsTableHtml}
    </section>

    ${aiSection}

    <div class="disclaimer">
      <strong>Standard Security Notice:</strong> This audit report was compiled using passive DOM scanning and localized Large Language Model processing. No active intrusion tests, fuzzing, or credential validation were performed. Results should be reviewed by a qualified analyst before staging deployment patches.
    </div>

    <footer>
      VulnLens AI Serverless Assistant • Developed by Yash M. Panchal &amp; Umang K. Nagwadiya
    </footer>
  </div>
</body>
</html>`;
  }

  return {
    buildHTML
  };
})();
