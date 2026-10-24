/**
 * VulnLens AI - local_engine.js
 * Rule-based local analysis engine ported from Python.
 * Runs offline, requires no API key, and requires no servers.
 */

(function (global) {
  const SEVERITY_WEIGHT = { high: 10, medium: 5, low: 2, info: 0 };

  const KNOWLEDGE_BASE = [
    {
      id: "http_transport",
      match: /served over http|submits over http/i,
      explanation: "Traffic to this page/form is not encrypted in transit, so it can be intercepted, read, or modified by anyone on the network path.",
      remediation: "Enforce HTTPS site-wide (redirect HTTP to HTTPS) and enable HSTS."
    },
    {
      id: "mixed_content",
      match: /mixed content/i,
      explanation: "Some resources are loaded over plain HTTP on an otherwise secure page, which browsers may block and which weakens the page's overall transport security guarantees.",
      remediation: "Update all resource URLs (scripts, images, iframes) to HTTPS."
    },
    {
      id: "weak_csp",
      match: /weak content-security-policy/i,
      explanation: "A Content-Security-Policy exists but permits unsafe directives such as 'unsafe-inline', 'unsafe-eval', or wildcard sources. These effectively re-enable the very script-injection paths CSP is meant to block, so the policy provides far less protection than it appears to.",
      remediation: "Remove 'unsafe-inline' and 'unsafe-eval' by moving inline scripts to external files or using per-response nonces/hashes. Replace wildcard sources with an explicit allow-list, drop plain http:// sources, and verify with Content-Security-Policy-Report-Only before enforcing."
    },
    {
      id: "missing_csp",
      match: /content-security-policy/i,
      explanation: "Without a Content-Security-Policy, the browser has no allow-list restricting which scripts/styles can run, making cross-site scripting (XSS) attacks more likely to succeed if any injection point exists.",
      remediation: "Add a Content-Security-Policy header starting with a strict default-src and script-src allow-list."
    },
    {
      id: "weak_hsts",
      match: /weak strict-transport-security|weak hsts/i,
      explanation: "HSTS is present but incomplete. A short or absent max-age, missing includeSubDomains, or missing preload leaves windows where a downgrade to plain HTTP is still possible — typically on subdomains or on a user's first visit.",
      remediation: "Set Strict-Transport-Security: max-age=31536000; includeSubDomains (and add preload only after confirming every subdomain is HTTPS-only). Increase max-age gradually to avoid locking out users."
    },
    {
      id: "obsolete_xfo",
      match: /obsolete x-frame-options|allow-from/i,
      explanation: "X-Frame-Options uses the ALLOW-FROM directive, which is obsolete and ignored by all modern browsers. The page is therefore effectively unprotected against clickjacking despite the header appearing to be configured.",
      remediation: "Replace ALLOW-FROM with a CSP 'frame-ancestors' directive listing the permitted origins (or 'none'). Keep X-Frame-Options: DENY or SAMEORIGIN as a fallback for legacy browsers."
    },
    {
      id: "ineffective_xcto",
      match: /ineffective x-content-type-options/i,
      explanation: "X-Content-Type-Options is present but set to a value other than 'nosniff'. Only 'nosniff' has any effect, so MIME-type sniffing is still permitted and content may be interpreted as a type the server did not intend.",
      remediation: "Set X-Content-Type-Options to exactly 'nosniff' on all responses, including error pages and API endpoints."
    },
    {
      id: "deprecated_xxp",
      match: /deprecated x-xss-protection/i,
      explanation: "The X-XSS-Protection header is deprecated and has been removed from modern browsers. In older browsers its filter could itself introduce vulnerabilities (such as selective script disabling enabling XSS). It provides no protection today.",
      remediation: "Remove the X-XSS-Protection header entirely and rely on a strict Content-Security-Policy instead."
    },
    {
      id: "cache_control",
      match: /cache-control/i,
      explanation: "The Cache-Control header is malformed or contradictory. A stray comma, s-maxage without max-age, or contradictory no-store/public directives leave caching behaviour ambiguous — the browser or an intermediary may cache sensitive responses, or caching may not work as intended.",
      remediation: "Use a well-formed directive list. For sensitive/authenticated content return 'Cache-Control: no-store, private'. For public static assets use 'public, max-age=<seconds>, s-maxage=<seconds>' with no trailing comma."
    },
    {
      id: "cookie_flags_header",
      match: /cookie ".*" missing security flags/i,
      explanation: "A Set-Cookie response header is missing one or more of the HttpOnly, Secure, or SameSite attributes. Without HttpOnly the cookie is readable by JavaScript and can be stolen via any XSS; without Secure it can be sent over plain HTTP; without SameSite it may be attached to cross-site requests, enabling CSRF.",
      remediation: "Set all three attributes on session and authentication cookies: 'Set-Cookie: <name>=<value>; HttpOnly; Secure; SameSite=Lax' (use SameSite=Strict for the most sensitive cookies)."
    },
    {
      id: "cors_credentials",
      match: /dangerous cors combination/i,
      explanation: "The response combines a wildcard Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true. Browsers block this exact pairing, but if the origin is reflected dynamically from the request, any site can read authenticated responses — a serious cross-origin data-theft issue.",
      remediation: "Never combine Access-Control-Allow-Credentials: true with a wildcard. Validate the Origin header against an explicit allow-list and echo back only trusted origins."
    },
    {
      id: "info_disclosure_header",
      match: /information-disclosure header/i,
      explanation: "A response header reveals internal implementation details such as framework names, cache state, or version numbers. This aids reconnaissance and lets an attacker match the stack against publicly known vulnerabilities.",
      remediation: "Strip or genericize non-essential response headers at the reverse proxy, CDN, or application framework level."
    },
    {
      id: "missing_xfo",
      match: /x-frame-options/i,
      explanation: "Without X-Frame-Options (or a frame-ancestors CSP directive), the page can be embedded in a hidden iframe on an attacker's site, enabling clickjacking attacks.",
      remediation: "Add X-Frame-Options: DENY/SAMEORIGIN or a CSP frame-ancestors directive."
    },
    {
      id: "missing_hsts",
      match: /strict-transport-security/i,
      explanation: "Without HSTS, browsers may allow a downgrade to an insecure HTTP connection, exposing users to SSL-stripping attacks.",
      remediation: "Add Strict-Transport-Security with a long max-age (e.g. 31536000) once HTTPS is confirmed stable."
    },
    {
      id: "missing_xcto",
      match: /x-content-type-options/i,
      explanation: "Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses, which can be abused to execute content in an unintended way.",
      remediation: "Add X-Content-Type-Options: nosniff to all responses."
    },
    {
      id: "missing_referrer",
      match: /referrer-policy/i,
      explanation: "Without a Referrer-Policy, full URLs (which may contain tokens or sensitive query parameters) can leak to third-party sites via the Referer header.",
      remediation: "Add Referrer-Policy: strict-origin-when-cross-origin (or stricter)."
    },
    {
      id: "missing_permissions_policy",
      match: /permissions-policy/i,
      explanation: "Without a Permissions-Policy, powerful browser features (camera, microphone, geolocation) are not explicitly restricted for embedded/third-party content.",
      remediation: "Add a Permissions-Policy header restricting unused browser features."
    },
    {
      id: "csrf",
      match: /csrf protection/i,
      explanation: "A form handling sensitive data does not show an obvious anti-CSRF token, which could allow an attacker's site to submit requests on a logged-in user's behalf.",
      remediation: "Confirm server-side CSRF protection (synchronizer token or SameSite cookies) even if not visible client-side."
    },
    {
      id: "inline_script",
      match: /inline scripts/i,
      explanation: "Inline scripts and event-handler attributes make it harder to enforce a strict CSP and increase the impact of any injection vulnerability.",
      remediation: "Move inline scripts/handlers into external files and tighten CSP to disallow 'unsafe-inline'."
    },
    {
      id: "outdated_lib",
      match: /outdated library/i,
      explanation: "An outdated frontend library version was detected. Older versions often carry publicly known vulnerabilities with existing proof-of-concept exploits.",
      remediation: "Upgrade the flagged library to its latest stable, supported release."
    },
    {
      id: "exposed_secret",
      match: /exposed secret/i,
      explanation: "A pattern resembling an API key, access key, or private key was found in page source or comments. If genuine, this credential should be treated as compromised.",
      remediation: "Rotate the credential immediately, remove it from client-side code/comments, and load secrets server-side only."
    },
    {
      id: "dev_comments",
      match: /developer comments/i,
      explanation: "Leftover developer comments (TODO/FIXME/internal/debug notes) can give attackers hints about internal systems or unfinished security controls.",
      remediation: "Strip debug/internal comments from production markup as part of the build/release process."
    },
    {
      id: "tabnabbing",
      match: /noopener/i,
      explanation: "Links opening in a new tab without rel=\"noopener\" give the destination page partial control over window.opener, enabling reverse-tabnabbing phishing attacks.",
      remediation: "Add rel=\"noopener noreferrer\" to all target=\"_blank\" links."
    },
    {
      id: "server_fingerprint",
      match: /server header discloses|x-powered-by/i,
      explanation: "Response headers disclose backend software/version details, which can help an attacker select known exploits for that specific stack.",
      remediation: "Suppress or genericize Server and X-Powered-By headers at the web server/proxy level."
    },
    {
      id: "cookie_flags",
      match: /js-readable cookies|readable cookies|javascript-readable.*cookies/i,
      explanation: "At least one cookie is readable via JavaScript, meaning it lacks the HttpOnly flag. If an XSS vulnerability exists anywhere on the site, such cookies (e.g. session tokens) could be stolen.",
      remediation: "Set HttpOnly (and Secure, SameSite) flags on all session/authentication cookies."
    },
    {
      id: "sensitive_inputs",
      match: /sensitive input fields|allows autocomplete on password/i,
      explanation: "Password or payment-related fields were detected. These should be handled with extra care around transport security and client-side logging/analytics.",
      remediation: "Verify these fields are excluded from analytics/session-replay tools and always served over HTTPS."
    },
    {
      id: "coop_header",
      match: /cross-origin-opener-policy/i,
      explanation: "Without a Cross-Origin-Opener-Policy (COOP) header, the browser tab can share browsing contexts with other sites, opening up side-channel vulnerabilities like Spectre.",
      remediation: "Add Cross-Origin-Opener-Policy: same-origin response header."
    },
    {
      id: "cors_wildcard",
      match: /wildcard cors/i,
      explanation: "The server returns Access-Control-Allow-Origin: *, which allows scripts on other origins to access response bodies from this site.",
      remediation: "Avoid Access-Control-Allow-Origin: * for responses requiring session cookies/tokens. Set specific domains instead."
    },
    {
      id: "xss_sink",
      match: /dom-xss sink|unsafe dom-xss/i,
      explanation: "Scripts use dangerous JavaScript operations (such as document.write or innerHTML assignment) which can execute dynamic scripts from unvalidated input.",
      remediation: "Avoid innerHTML and document.write. Use secure elements like textContent or use DOMPurify library for input sanitization."
    },
    {
      id: "api_endpoints",
      match: /api endpoints disclosed/i,
      explanation: "Internal REST/GraphQL endpoint paths are visible inside frontend scripts, helping attackers profile and target backend API endpoints.",
      remediation: "Ensure strict server-side access controls, authorization, and rate-limiting are enforced on all backend API routes."
    },
    {
      id: "tech_disclosure",
      match: /technology stack disclosure/i,
      explanation: "Framework and library names are disclosed in the DOM, aiding attackers in locating public CVE advisories.",
      remediation: "Hide version strings and banners where possible, and run automated audits to keep these client libraries updated."
    }
  ];

  const FALLBACK_RULE = {
    id: "generic",
    explanation: "This finding does not map to a specific known category; review it manually against your security baseline.",
    remediation: "Manually review this finding and apply the appropriate hardening control."
  };

  function matchRule(title) {
    for (let rule of KNOWLEDGE_BASE) {
      if (rule.match.test(title)) {
        return rule;
      }
    }
    return FALLBACK_RULE;
  }

  function generateLocalAnalysis(url, findings) {
    if (!findings || findings.length === 0) {
      return {
        summary: "No findings were provided to analyze.",
        recommendations: [],
        engine: "vulnlens-local-free-engine"
      };
    }

    let totalScore = 0;
    const severityCounts = { high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => {
      totalScore += SEVERITY_WEIGHT[f.severity] || 0;
      severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
    });

    const cappedScore = Math.min(100, totalScore);
    const riskLevel = cappedScore >= 60 ? "Critical" :
                      cappedScore >= 40 ? "High" :
                      cappedScore >= 15 ? "Medium" :
                      cappedScore > 0 ? "Low" : "None";

    // Build category-level explanations
    const seenCategories = {};
    const sortedFindings = [...findings].sort((a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0));
    sortedFindings.forEach(f => {
      const rule = matchRule(f.title);
      if (!seenCategories[rule.id]) {
        seenCategories[rule.id] = {
          severity: f.severity,
          explanation: rule.explanation,
          remediation: rule.remediation
        };
      }
    });

    const recommendations = Object.values(seenCategories)
      .sort((a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0))
      .map(data => `[${data.severity.toUpperCase()}] ${data.remediation}`);

    const topCategories = Object.values(seenCategories).slice(0, 3);
    const summaryParts = [
      `Scanned ${url} and found ${findings.length} issue(s) ` +
      `(${severityCounts.high || 0} high, ${severityCounts.medium || 0} medium, ` +
      `${severityCounts.low || 0} low, ${severityCounts.info || 0} informational).`,
      `Overall risk posture: ${riskLevel} (score ${cappedScore}/100).`
    ];

    if (topCategories.length > 0) {
      summaryParts.push("Top concerns: " + topCategories.map(c => c.explanation).join("; "));
    }

    return {
      summary: summaryParts.join(" "),
      recommendations: recommendations,
      risk_level: riskLevel,
      risk_score: cappedScore,
      engine: "vulnlens-local-free-engine"
    };
  }

  // Export
  global.VulnLensLocalEngine = {
    generateLocalAnalysis: generateLocalAnalysis,
    matchRule: matchRule
  };
})(typeof window !== 'undefined' ? window : globalThis);
