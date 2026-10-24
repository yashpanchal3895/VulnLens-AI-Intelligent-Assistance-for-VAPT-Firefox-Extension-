/**
 * VulnLens AI - content.js (Firefox build)
 * Authors: Yash M. Panchal & Umang K. Nagwadiya
 *
 * Passive, read-only scanner. Runs in the page context and inspects the
 * rendered DOM/source for common misconfigurations. It does NOT inject
 * payloads, submit forms, or attempt to exploit anything — detection only.
 */

(function () {
  const OUTDATED_LIB_SIGNATURES = [
    { name: 'jQuery', pattern: /jquery[-.]?(1\.[0-9]|2\.[01])\.[0-9]+/i, note: 'Known-vulnerable jQuery 1.x/2.0/2.1 range' },
    { name: 'AngularJS', pattern: /angular(?:\.min)?\.js.*1\.[0-5]\./i, note: 'Legacy AngularJS 1.x (EOL, multiple CVEs)' },
    { name: 'Bootstrap', pattern: /bootstrap[-.]?3\.[0-3]\./i, note: 'Older Bootstrap 3.x branch with known XSS advisories' }
  ];

  const SECRET_PATTERNS = [
    { name: 'AWS Access Key ID', pattern: /\b(AKIA|ASIA)[A-Z0-9]{16}\b/ },
    { name: 'Stripe API Key', pattern: /\b(sk|rk|pk)_live_[0-9a-zA-Z]{24,}\b/ },
    { name: 'GitHub PAT', pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b/ },
    { name: 'Google API Key', pattern: /\bAIza[0-9A-Za-z-_]{35}\b/ },
    { name: 'Slack Webhook URL', pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/ },
    { name: 'Hardcoded JWT Token', pattern: /\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*\b/ },
    { name: 'Private Key Block', pattern: /-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/ }
  ];

  function scanPage() {
    const findings = [];
    const pageSource = document.documentElement.outerHTML;
    const isHttps = location.protocol === 'https:';

    // 1. Basic Protocol Scan
    if (!isHttps) {
      findings.push(finding('high', 'Page served over HTTP', 'The page is not using HTTPS, exposing traffic to interception and tampering.'));
    }

    // 2. Mixed Content Scan
    if (isHttps) {
      const insecureResources = Array.from(document.querySelectorAll('img,script,link,iframe,form,source,audio,video,embed,object'))
        .filter(el => {
          const src = el.src || el.href || el.action || el.data || '';
          return src.startsWith('http://');
        });
      // Also catch insecure URLs inside inline CSS url(...) and srcset attributes,
      // which attribute-only checks miss entirely.
      const cssHttpMatches = (pageSource.match(/url\(\s*['"]?http:\/\//gi) || []).length;
      const srcsetHttpMatches = Array.from(document.querySelectorAll('[srcset]'))
        .filter(el => (el.getAttribute('srcset') || '').includes('http://')).length;
      const totalInsecure = insecureResources.length + cssHttpMatches + srcsetHttpMatches;
      if (totalInsecure > 0) {
        findings.push(finding('medium', 'Mixed content detected', `${totalInsecure} resource(s) loaded over HTTP on an HTTPS page, which browsers may block or flag.`));
      }
    }

    // 3. Form and Authentication Security Checks
    document.querySelectorAll('form').forEach((form, idx) => {
      const action = form.getAttribute('action') || '';
      if (action.startsWith('http://')) {
        findings.push(finding('high', `Form #${idx + 1} submits over HTTP`, 'Credentials or sensitive data entered may be sent unencrypted.'));
      }
      const hasPasswordField = !!form.querySelector('input[type="password"]');
      const hasHiddenToken = !!form.querySelector('input[type="hidden"][name*="csrf" i], input[type="hidden"][name*="token" i]');
      if (hasPasswordField && !hasHiddenToken) {
        findings.push(finding('low', `Form #${idx + 1} may lack CSRF protection`, 'No hidden CSRF-style token field was detected on a form containing a password field. Verify server-side protections manually.'));
      }
      if (form.getAttribute('autocomplete') !== 'off' && hasPasswordField) {
        findings.push(finding('info', `Form #${idx + 1} allows autocomplete on password field`, 'Consider disabling autocomplete for sensitive fields on shared devices.'));
      }
    });

    // 4. DOM XSS Dangerous Sinks checks
    let sinkCount = 0;
    document.querySelectorAll('script').forEach(scr => {
      const txt = scr.textContent;
      if (/(document\.write|eval\s*\(|setTimeout\s*\(\s*["']|setInterval\s*\(\s*["']|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\()/i.test(txt)) {
        sinkCount++;
      }
    });
    // Inline event-handler attributes can also carry injection sinks.
    let handlerSinkCount = 0;
    document.querySelectorAll('[onclick],[onload],[onerror],[onmouseover],[onfocus],[oninput]').forEach(el => {
      const code = Array.from(el.attributes)
        .filter(a => a.name.startsWith('on'))
        .map(a => a.value)
        .join(' ');
      if (/(document\.write|eval\s*\(|innerHTML)/i.test(code)) {
        handlerSinkCount++;
      }
    });
    const totalSinks = sinkCount + handlerSinkCount;
    if (totalSinks > 0) {
      findings.push(finding('medium', 'Unsafe DOM-XSS sink detected in scripts', `Found ${totalSinks} location(s) using document.write, eval, or .innerHTML assignments (${sinkCount} script block(s), ${handlerSinkCount} inline handler(s)). These are high-risk locations for DOM-based XSS if user input is not sanitized.`));
    }

    const inlineScripts = document.querySelectorAll('script:not([src])');
    const inlineHandlers = document.querySelectorAll('[onclick],[onload],[onerror],[onmouseover]');
    if (inlineScripts.length > 0 || inlineHandlers.length > 0) {
      findings.push(finding('low', 'Inline scripts / event handlers present',
        `${inlineScripts.length} inline <script> block(s) and ${inlineHandlers.length} inline event-handler attribute(s) found. These weaken Content-Security-Policy and increase XSS blast radius.`));
    }

    // 5. Outdated Libraries Checks
    const scriptSources = Array.from(document.querySelectorAll('script[src]')).map(s => s.src).join('\n');
    OUTDATED_LIB_SIGNATURES.forEach(lib => {
      if (lib.pattern.test(scriptSources) || lib.pattern.test(pageSource)) {
        findings.push(finding('medium', `Potentially outdated library: ${lib.name}`, lib.note));
      }
    });

    // 6. Sensitive Data and API Key Scanning
    const comments = getHtmlComments();
    const textToCheck = comments.join('\n');
    SECRET_PATTERNS.forEach(secret => {
      if (secret.pattern.test(textToCheck) || secret.pattern.test(pageSource)) {
        findings.push(finding('high', `Possible exposed secret: ${secret.name}`, `Pattern resembling a credential or key (${secret.name}) was found in page source or comments. Verify and rotate if genuine.`));
      }
    });

    const suspiciousComments = comments.filter(c => /TODO|FIXME|password|internal|debug|staging/i.test(c));
    if (suspiciousComments.length) {
      findings.push(finding('info', 'Developer comments left in markup', `${suspiciousComments.length} comment(s) mention debug/internal notes that could aid an attacker.`));
    }

    const unsafeTargetBlank = Array.from(document.querySelectorAll('a[target="_blank"]:not([rel*="noopener"])'));
    if (unsafeTargetBlank.length) {
      findings.push(finding('low', 'Links with target="_blank" missing rel="noopener"',
        `${unsafeTargetBlank.length} link(s) allow reverse-tabnabbing via window.opener.`));
    }

    const sensitiveInputs = document.querySelectorAll('input[type="password"], input[autocomplete="cc-number"]');
    if (sensitiveInputs.length) {
      findings.push(finding('info', 'Sensitive input fields present', 'Confirm these fields are served over HTTPS and are not logged client-side (e.g., via analytics scripts).'));
    }

    // 7. Cookie Flags Scan
    if (document.cookie && document.cookie.length > 0) {
      const sensitiveCookieNames = /session|jwt|token|sid|phpsessid|jsessionid|sec|auth|login/i;
      const cookies = document.cookie.split(';');
      const leakySensitiveCookies = cookies.filter(cookie => {
        const name = cookie.split('=')[0].trim();
        return sensitiveCookieNames.test(name);
      });
      if (leakySensitiveCookies.length > 0) {
        findings.push(finding('info', 'JavaScript-readable sensitive cookies present',
          `Sensitive cookie(s) (${leakySensitiveCookies.map(c => c.split('=')[0].trim()).join(', ')}) are readable via document.cookie. Verify HttpOnly flag is set on these session/auth cookies.`));
      }
    }

    // 8. API Endpoint and GraphQL exposure check
    const apiEndpoints = [];
    const restPattern = /["']\/api\/(v[0-9]|\w+)[\/\w-]*["']/gi;
    const graphqlPattern = /["'][\/\w-]*graphql["']/gi;
    
    let match;
    while ((match = restPattern.exec(pageSource)) !== null) {
      if (!apiEndpoints.includes(match[0])) apiEndpoints.push(match[0]);
    }
    while ((match = graphqlPattern.exec(pageSource)) !== null) {
      if (!apiEndpoints.includes(match[0])) apiEndpoints.push(match[0]);
    }
    
    if (apiEndpoints.length > 0) {
      findings.push(finding('info', 'Internal API endpoints disclosed in source', 
        `Discovered ${apiEndpoints.length} endpoint pattern(s) (e.g. ${apiEndpoints.slice(0, 3).map(e => e.replace(/['"]/g, '')).join(', ')}) in frontend scripts. Verify authentication controls are enforced on these routes.`));
    }

    // 9. Technology stack detection
    const detectedTech = [];
    if (document.querySelector('meta[name="generator"]')) {
      const generator = document.querySelector('meta[name="generator"]').getAttribute('content') || '';
      if (generator) detectedTech.push(generator);
    }
    if (pageSource.includes('_next/static') || pageSource.includes('__NEXT_DATA__')) {
      detectedTech.push('Next.js');
    }
    if (pageSource.includes('react-root') || document.querySelector('[data-reactroot]')) {
      detectedTech.push('React');
    }
    if (pageSource.includes('vue-container') || pageSource.includes('data-v-')) {
      detectedTech.push('Vue.js');
    }
    if (pageSource.includes('ng-version') || pageSource.includes('ng-app')) {
      detectedTech.push('Angular');
    }
    if (pageSource.includes('wp-content') || pageSource.includes('wp-includes')) {
      detectedTech.push('WordPress');
    }
    if (pageSource.includes('bootstrap.min.css') || pageSource.includes('class="container-fluid') || pageSource.includes('class="row') || pageSource.includes('class="col-')) {
      detectedTech.push('Bootstrap');
    }
    if (pageSource.includes('tailwind.config') || pageSource.includes('class="sm:flex') || pageSource.includes('class="bg-opacity-') || pageSource.includes('class="mx-auto')) {
      detectedTech.push('Tailwind CSS');
    }
    if (pageSource.includes('jquery.min.js') || pageSource.includes('jquery.js') || pageSource.includes('jQuery(')) {
      detectedTech.push('jQuery');
    }

    if (detectedTech.length > 0) {
      findings.push(finding('info', 'Technology stack disclosure detected', `Fingerprinted stack signatures: ${detectedTech.join(', ')}. Keep these frameworks updated to minimize CVE attack surfaces.`));
    }

    return { url: location.href, timestamp: new Date().toISOString(), findings };
  }

  function getHtmlComments() {
    const out = [];
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
    let node;
    while ((node = walker.nextNode())) out.push(node.nodeValue);
    return out;
  }

  function finding(severity, title, description) {
    return { severity, title, description };
  }

  let cachedScanResult = null;
  let scanTimeout = null;

  function schedulePassiveScan() {
    clearTimeout(scanTimeout);
    scanTimeout = setTimeout(() => {
      try {
        cachedScanResult = scanPage();
      } catch (err) {
        // Silent catch for passive scanning
      }
    }, 1200); // 1.2 second debounce
  }

  // Set up MutationObserver to watch for added/removed DOM nodes
  const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    for (let mutation of mutations) {
      if (mutation.addedNodes.length > 0 || mutation.removedNodes.length > 0) {
        shouldScan = true;
        break;
      }
    }
    if (shouldScan) {
      schedulePassiveScan();
    }
  });

  // Initial passive scan and start observing body
  try {
    cachedScanResult = scanPage();
    if (document.body) {
      observer.observe(document.body, { childList: true, subtree: true });
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        if (document.body) {
          observer.observe(document.body, { childList: true, subtree: true });
        }
      });
    }
  } catch (e) {}

  // Message listener returning cached results instantly
  browser.runtime.onMessage.addListener((msg) => {
    if (msg?.type === 'VULNLENS_SCAN_REQUEST') {
      try {
        const result = cachedScanResult || scanPage();
        return Promise.resolve({ ok: true, result });
      } catch (err) {
        return Promise.resolve({ ok: false, error: String(err) });
      }
    }
  });
})();
