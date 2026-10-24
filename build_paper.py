"""
Build an IEEE conference paper (A4, two-column) about VulnLens AI.

Strategy: use the provided template as the BASE PACKAGE so every style, numbering
definition, theme and font table is inherited verbatim from it. Only
word/document.xml is replaced, and its body is built from the template's own
style IDs (papertitle, Author, Abstract, Keywords, Heading1-4, BodyText,
bulletlist, tablehead, tablecolhead, figurecaption, references).

Strict OOXML namespace: http://purl.oclc.org/ooxml/wordprocessingml/main
"""
import zipfile, shutil, re, os

TEMPLATE = r'C:/Users/YASH/Downloads/conference-template-a4.docx'
OUT = r'C:/Users/YASH/Downloads/VulnLens-AI-Firefox/VulnLens-AI-Firefox/VulnLens-AI_Research_Paper.docx'

# ─────────────────────────── XML helpers ───────────────────────────

def esc(s):
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

# Italic delimiter. A control character is used rather than the conventional
# asterisk, because '*' is legitimate CONTENT in this paper — the CSP wildcard
# source in "default-src *" — and an asterisk delimiter silently deletes it.
ITAL = '\x01'

def runs(text, rpr=''):
    """Build runs, treating the ITAL char as an italic toggle and a literal tab as <w:tab/>."""
    out = []
    for i, part in enumerate(text.split(ITAL)):
        if not part:
            continue
        italic = (i % 2 == 1)
        r = f'<w:rPr><w:i/><w:iCs/>{rpr}</w:rPr>' if italic else (f'<w:rPr>{rpr}</w:rPr>' if rpr else '')
        # a real tab must be a <w:tab/> element, not a raw \t inside <w:t>
        segs = part.split('\t')
        inner = '<w:tab/>'.join(
            (f'<w:t xml:space="preserve">{esc(s)}</w:t>' if s != s.strip() or not s
             else f'<w:t>{esc(s)}</w:t>')
            for s in segs
        )
        out.append(f'<w:r>{r}{inner}</w:r>')
    return ''.join(out)

def para(style, text='', extra_ppr='', rpr=''):
    ppr = f'<w:pPr><w:pStyle w:val="{style}"/>{extra_ppr}</w:pPr>' if style or extra_ppr else ''
    return f'<w:p>{ppr}{runs(text, rpr) if text else ""}</w:p>'

def empty_para(sectpr=''):
    ppr = f'<w:pPr>{sectpr}</w:pPr>' if sectpr else ''
    return f'<w:p>{ppr}</w:p>'

# ─────────────────────────── content ───────────────────────────

TITLE = ('VulnLens AI: Passive, Quality-Aware Web Security Assessment '
         'with Multi-Tier AI-Assisted Explanation')

AUTHORS = [
    ('Yash M. Panchal', 'Dept. of Computer Engineering',
     'Silver Oak University', 'Ahmedabad, Gujarat, India'),
    ('Umang K. Nagwadiya', 'Dept. of Computer Engineering',
     'Silver Oak University', 'Ahmedabad, Gujarat, India'),
]

ABSTRACT = (
    'Web applications routinely ship with missing or misconfigured HTTP response headers, '
    'yet these weaknesses remain invisible to developers, auditors, and end users alike. '
    'Existing assessment tools typically require server-side deployment, paid licences, or '
    'expert interpretation of raw output. This paper presents VulnLens AI, a passive, '
    'client-side vulnerability assessment framework implemented as a Firefox WebExtension. '
    'The work makes two contributions. First, it performs \x01quality-aware\x01 header analysis: '
    'rather than recording the mere presence of a header, it parses directive values and '
    'classifies present-but-ineffective configurations — such as a Content-Security-Policy '
    'containing the unsafe-inline directive — as weak rather than compliant. Second, it '
    'employs a three-tier analysis architecture in which a cloud-hosted language model, a '
    'locally hosted model, and a deterministic rule engine form a graceful degradation chain, '
    'guaranteeing a useful result even without network connectivity or credentials. The system '
    'was validated with a 98-check regression suite and 37 package-integrity checks, and '
    'exercised against a live production site, where it identified twelve findings spanning '
    'transport security, content security policy, mixed content, and information disclosure. '
    'Results indicate that quality-aware analysis surfaces actionable weaknesses that '
    'presence-only scanners report as compliant.'
)

KEYWORDS = ('web security, HTTP security headers, passive vulnerability assessment, '
            'browser extension, large language models, content security policy, VAPT, '
            'security misconfiguration')

# Body: (kind, text).  kind in {h1,h2,h3,body,bullet,figcap,tblcap,ref}
BODY = [
('h1', 'Introduction'),
('body', 'The security posture of a web application is determined to a large degree by '
 'instructions the server attaches to every response. Headers such as '
 'Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), and X-Frame-Options '
 'instruct the browser to enforce protections that application code cannot reliably '
 'provide on its own. When these headers are absent, or present but configured '
 'ineffectively, the application becomes exposed to well-understood classes of attack '
 'including cross-site scripting, protocol downgrade, clickjacking, and referrer leakage.'),
('body', 'Despite their importance, header misconfigurations are common, and they are '
 'difficult to observe. A developer browsing a site cannot see its response headers. '
 'End users have no indication that a protection is missing. Even dedicated tooling often '
 'reports results in a form that presumes expert knowledge, producing output such as '
 '"missing CSP header" without explaining the consequence or the remedy.'),
('body', 'This paper presents VulnLens AI, a browser-embedded assessment assistant that '
 'addresses both problems. It makes the invisible visible by reading response headers and '
 'inspecting the rendered document, and it makes the result intelligible by generating an '
 'explanation and a remediation path in plain language. The tool is deliberately passive: '
 'it observes what the browser has already received and never transmits attack payloads, '
 'submits forms, or modifies the target in any way.'),
('body', 'The remainder of this paper is organised as follows. Section II reviews related '
 'work and positions the contribution. Section III describes the system architecture and '
 'its design goals. Section IV details the implementation. Section V reports the evaluation, '
 'including regression results and a live case study. Section VI discusses limitations and '
 'responsible use, and Section VII concludes.'),

('h1', 'Background and Related Work'),
('body', 'Web security assessment is conventionally divided into vulnerability assessment, '
 'which identifies weaknesses, and penetration testing, which attempts to exploit them. '
 'Mature commercial platforms such as Burp Suite and Nessus perform both, but they are '
 'aimed at practitioners, require installation and configuration, and are licensed per seat. '
 'Their depth is not in question; their accessibility is.'),
('body', 'A second family of tools performs configuration analysis of response headers. '
 'Mozilla Observatory and similar services are effective for a single URL, but they operate '
 'as remote services: the target must be reachable from the service, and internal or '
 'authenticated pages cannot be assessed. Browser extensions occupy a useful middle ground, '
 'since they execute in the user\u2019s own session and can therefore observe pages that a '
 'remote scanner cannot reach.'),
('body', 'Recent work has applied large language models (LLMs) to security reporting, '
 'primarily to translate technical findings into readable summaries. This improves '
 'accessibility but introduces a dependency: when the model is unavailable, rate-limited, '
 'or unaffordable, the tool ceases to function. VulnLens AI treats model availability as a '
 'reliability problem to be engineered around rather than assumed.'),
('body', 'The closest published approaches are header-linting utilities and passive '
 'browser-based scanners. Both typically adopt a binary presence test: a header is either '
 'present or absent. This paper argues that binary presence testing is insufficient, because '
 'a misconfigured header can create a false sense of protection that is, in practice, more '
 'hazardous than an acknowledged absence. The quality-aware analysis described in '
 'Section III-C is the primary technical distinction of this work.'),

('h1', 'System Architecture'),
('body', 'VulnLens AI is implemented as a Manifest V3 WebExtension for Firefox, requiring '
 'version 109 or later. It comprises a background service script, a content script injected '
 'into the page, and a popup interface. No server-side component is required, and no data '
 'leaves the browser unless the operator explicitly enables the cloud analysis tier.'),

('h2', 'Design Goals and Constraints'),
('body', 'Four goals shaped the design. First, the tool must be passive and read-only, so '
 'that it can be used lawfully and safely on any page the operator is authorised to view. '
 'Second, it must degrade gracefully: a failure in any single analysis component must not '
 'prevent a result. Third, it must produce evidence, not merely conclusions, so that a '
 'finding can be independently verified. Fourth, it must remain usable without paid '
 'infrastructure, which excludes any design that mandates a hosted service.'),
('body', 'These goals impose a constraint that distinguishes the system from server-side '
 'scanners: the extension can only observe what the browser already possesses. It cannot '
 'enumerate endpoints, inspect server configuration, or test business logic. The architecture '
 'is therefore optimised for breadth of observation rather than depth of probing.'),

('h2', 'Two-Tier Passive Collection'),
('body', 'Collection proceeds along two independent paths that are subsequently merged. The '
 'header path runs in the background script, where the webRequest interface exposes response '
 'headers as they arrive. The document path runs in the content script, which inspects the '
 'rendered document object model once the page has settled.'),
('body', 'Two implementation details proved significant. First, headers that legitimately '
 'repeat, most notably Set-Cookie, must be collapsed into an array rather than assigned to an '
 'object key; naive assignment silently discards all but the final value and causes cookie '
 'auditing to under-report. Second, captured headers are keyed by tab identifier and become '
 'stale when the page navigates client-side without a full reload. The system therefore '
 'records a capture timestamp and emits an explicit diagnostic when the header data no longer '
 'corresponds to the current URL, rather than silently analysing stale input.'),

('h2', 'Quality-Aware Header Analysis'),
('body', 'This is the central contribution. Conventional presence testing evaluates a header '
 'with a single predicate: is it present? The approach taken here evaluates the header\u2019s '
 'value against the semantics defined by its specification, and classifies the result as '
 'absent, weak, or effective.'),
('body', 'The distinction is material. Consider a response carrying '
 'Content-Security-Policy: default-src * \u2018unsafe-inline\u2019 \u2018unsafe-eval\u2019. '
 'A presence test reports this as compliant. In reality, the unsafe-inline and unsafe-eval '
 'directives re-enable precisely the script-injection paths that CSP exists to close, and the '
 'wildcard source admits content from any origin. The policy provides negligible protection '
 'while appearing on a compliance checklist as satisfied.'),
('body', 'Quality-aware analysis therefore examines directive values in detail. For CSP it '
 'flags unsafe-inline, unsafe-eval, wildcard sources, plaintext http sources, and the absence '
 'of a default-src or script-src directive. For HSTS it flags a max-age below the commonly '
 'recommended threshold, a max-age of zero, and the absence of includeSubDomains or preload. '
 'For X-Frame-Options it flags the obsolete ALLOW-FROM directive, which modern browsers '
 'ignore. For X-Content-Type-Options it requires the exact value nosniff and flags anything '
 'else as ineffective. It also reports X-XSS-Protection as deprecated when present, audits '
 'Cache-Control for malformed values, evaluates cookie attributes individually with escalation '
 'for sensitive cookie names, and escalates a wildcard CORS origin combined with credential '
 'support to high severity.'),
('body', 'The practical consequence is that the tool can distinguish a site that has adopted '
 'a control from a site that merely appears to have adopted one.'),

('h2', 'Multi-Tier Analysis and Graceful Degradation'),
('body', 'Once collection completes, the merged findings are passed to an analysis layer '
 'offering three tiers in order of preference. The first tier queries a cloud-hosted model '
 'through an OpenAI-compatible gateway. The second queries a locally hosted model. The third '
 'is a deterministic rule engine embedded in the extension, comprising thirty-one knowledge '
 'rules that map finding categories to an explanation and a remediation.'),
('body', 'The tiers form a fallback chain rather than a selection. If the cloud tier fails '
 'for any reason, the local tier is attempted; if that also fails, the rule engine produces '
 'the analysis. The rule engine requires no network access, no credentials, and no external '
 'process, so the system always yields a result. This design directly addresses the '
 'fragility observed in comparable LLM-based tools, which typically present a hard failure '
 'when the model is unreachable.'),
('body', 'A consequence worth noting is that analysis quality degrades along a known axis. '
 'The rule engine produces accurate but generic explanations keyed to finding categories, '
 'whereas the cloud tier produces site-specific synthesis that relates findings to one '
 'another. The system reports which engine produced each analysis so that the reader can '
 'calibrate their confidence accordingly.'),

('h1', 'Implementation'),
('body', 'The extension consists of six JavaScript modules totalling approximately 120 KB of '
 'source. The following subsections describe the substantive components.'),

('h2', 'Header Analysis Engine'),
('body', 'The header engine implements seventeen security checks together with two '
 'data-integrity diagnostics. Checks are evaluated in a deliberate order, because the '
 'classification routine returns the first matching rule and a specific rule must therefore '
 'precede a general one. The weak-CSP rule, for example, must be evaluated before the '
 'missing-CSP rule; otherwise a policy that is present but ineffective is misreported as '
 'absent, inverting the finding.'),
('body', 'Each check yields a finding carrying a severity, a human-readable title, and a '
 'description. Severities are weighted ten, five, two, and zero for high, medium, low, and '
 'informational respectively. The aggregate risk score is the sum of weights, capped at one '
 'hundred. Labels are derived from the score: zero indicates no risk, below fifteen low, '
 'below forty medium, below sixty high, and sixty or above critical.'),

('h2', 'Document Inspection Engine'),
('body', 'The content script performs nine categories of inspection over the rendered '
 'document: transport protocol of the page and its forms; mixed content, including resources '
 'referenced through srcset attributes, data attributes, and CSS url() functions; form and '
 'authentication characteristics; dangerous document object model sinks such as eval, '
 'innerHTML, outerHTML, insertAdjacentHTML, and inline event-handler attributes; outdated '
 'client library signatures; exposed credentials including API keys and private keys; cookie '
 'readability; exposed API and GraphQL endpoints; and technology fingerprinting.'),
('body', 'Two supplementary checks run alongside these. Inline script blocks are counted, '
 'since their presence determines how difficult it would be to adopt a strict CSP. External '
 'scripts are also examined for Subresource Integrity attributes, and those lacking an '
 'integrity value are reported.'),
('body', 'Inspection is triggered after the document reaches an idle state and is '
 're-evaluated on mutation, with debouncing, so that single-page applications are assessed '
 'after their dynamic content has rendered.'),

('h2', 'Deterministic Rule Engine'),
('body', 'The rule engine encodes thirty-one rules. Each rule pairs a matching pattern with '
 'an explanation describing why the weakness matters and a remediation describing how to '
 'address it. When the cloud and local tiers are both unavailable, this engine supplies the '
 'summary, the prioritised recommendations, and the risk assessment. Because it executes '
 'in-process, it completes in single-digit milliseconds, as reported in Section V.'),

('h2', 'Cloud Integration and Streaming'),
('body', 'The cloud tier communicates with an OpenAI-compatible endpoint. Two engineering '
 'details are worth recording because both produced defects during development. First, the '
 'gateway employed during testing enforces a client-fingerprint precondition: requests that '
 'omit the expected User-Agent header are rejected with an authorisation error whose text is '
 'easily mistaken for a credential failure. The implementation therefore distinguishes '
 'between the two by inspecting the error body rather than the status code, and reports the '
 'specific cause.'),
('body', 'Second, the model used is a reasoning model that emits reasoning content before '
 'its final answer, and reasoning tokens are charged against the output budget. A small '
 'budget is therefore consumed entirely by reasoning, yielding a successful HTTP response '
 'with empty content. The implementation treats an empty completion as a failure rather than '
 'a success, sizes the budget to the task while clamping it to the range the gateway '
 'advertises, and raises the request timeout to match the enlarged budget, since a token '
 'allowance is meaningless if the request is aborted before it can be used. Responses are '
 'consumed as a server-sent event stream, which also proves the connection is live rather '
 'than stalled.'),

('h1', 'Evaluation'),
('body', 'Evaluation proceeded in three parts: a regression suite exercising the analysis '
 'logic without network access, a package-integrity verification, and a live scan of a '
 'production site.'),

('h2', 'Methodology'),
('body', 'The regression suite comprises ninety-eight checks organised into nine phases. '
 'Phases one through five exercise header analysis, rule coverage, local analysis generation, '
 'risk-label consistency, and report construction. Phase six validates packaging and '
 'cross-file references. Phases seven through nine cover API error classification, the '
 'reasoning-model token budget, and the token ceiling with streaming behaviour. The suite '
 'runs entirely offline and therefore produces deterministic results.'),
('body', 'The integrity verifier operates in two layers. The first validates archive '
 'structure, requiring that the manifest reside at the archive root and that every referenced '
 'file resolve within the archive, and verifies each entry by cyclic redundancy check. The '
 'second layer applies thirty-seven project-specific assertions covering manifest '
 'configuration, message-handler wiring, document element identifiers, the presence of each '
 'implemented fix, and the absence of development-only files.'),

('h2', 'Regression and Integrity Results'),
('body', 'All ninety-eight regression checks passed, as did all thirty-seven integrity '
 'checks and the archive verification. Notable negative controls deserve emphasis: a fully '
 'hardened header set produces zero findings, confirming the absence of false positives, and '
 'a weak-header set produces no spurious missing-header findings, confirming that quality '
 'analysis does not collapse into presence testing.'),
('body', 'Two additional properties were verified by construction. The suite asserts that '
 'both distinct authorisation error bodies classify to different causes, and that a truncated '
 'model response is diagnosed as budget exhaustion rather than reported as a generic failure. '
 'Both assertions are paired with a simulation of the incorrect behaviour, so the test fails '
 'if the defect is reintroduced.'),

('h2', 'Live Case Study'),
('body', 'The system was applied to a live production site hosted behind a content delivery '
 'network. Twelve findings were reported: none high, four medium, four low, and four '
 'informational. The local rule engine produced a medium assessment of twenty-eight out of '
 'one hundred in approximately six milliseconds; the cloud tier produced a high assessment of '
 'fifty-two out of one hundred in approximately nine seconds, consuming nine hundred sixty '
 'prompt tokens and one thousand five hundred forty-eight completion tokens.'),
('tblcap', 'Table 1. Live assessment of a production site.'),
('table', 'results'),
('tblfoot', 'aToken counts reported by the gateway for a single analysis request.'),
('body', 'Findings included the absence of CSP, HSTS, Referrer-Policy, Permissions-Policy, '
 'and Cross-Origin-Opener-Policy; a malformed Cache-Control value containing a trailing comma '
 'and no browser max-age; information disclosure through the Server and X-Nextjs-Cache '
 'headers; one resource loaded over plaintext HTTP on an otherwise secure page; seventeen '
 'inline script blocks; and twenty-one links opening in a new context without a noopener '
 'relation.'),
('body', 'The cloud tier connected these observations into a narrative absent from the local '
 'tier, noting that the missing baseline headers remove defence in depth while the '
 'document-object-model sink and the mixed-content resource raise practical risk above that '
 'of a header-hardening exercise alone. This illustrates the intended division of labour: the '
 'rule engine reliably enumerates, and the model contextualises.'),

('h2', 'Discussion'),
('body', 'Three observations follow. First, the quality-aware approach identified a '
 'present-but-ineffective configuration on the sampled site that a presence-based scanner '
 'would have recorded as compliant, supporting the paper\u2019s central claim. Second, the '
 'local tier proved approximately three orders of magnitude faster than the cloud tier, '
 'indicating that the fallback chain is not merely a reliability measure but a latency '
 'optimisation for interactive use. Third, cloud risk assessments varied modestly across '
 'repeated runs on identical input, confirming that model-generated scores should be treated '
 'as advisory while the deterministic engine provides the stable baseline.'),

('h1', 'Limitations and Responsible Use'),
('body', 'The system has clear boundaries. A clean result indicates the absence of observable '
 'misconfigurations; it does not establish that a site is secure. The extension cannot '
 'observe server-side state, cannot test business logic or access control, and cannot detect '
 'vulnerabilities that require active probing. Because the browser restricts script access to '
 'certain cookies, cookie auditing is a best-effort view. Assessment is per-page, since each '
 'page must be visited and scanned individually. Finally, model-generated analysis is '
 'advisory and may vary between runs.'),
('body', 'Responsible use is a design constraint as well as an expectation. Although the tool '
 'is passive, scanning a system without authorisation may contravene terms of service or '
 'applicable law. The implementation enforces read-only behaviour by construction, but the '
 'decision of where to direct it remains the operator\u2019s responsibility.'),
('body', 'A practical limitation concerns credential handling. During development, an API key '
 'was stored in plaintext within auxiliary test scripts. This is unsuitable for distribution, '
 'and such scripts are excluded from the released package; keys should be treated as '
 'compromised if they have been shared, and rotated.'),

('h1', 'Conclusion and Future Work'),
('body', 'This paper described VulnLens AI, a passive browser-embedded framework for web '
 'security assessment. Its contribution is twofold: a quality-aware method of header analysis '
 'that distinguishes effective configuration from mere presence, and a three-tier analysis '
 'architecture that guarantees a usable result irrespective of model or network availability. '
 'The system was validated by a ninety-eight-check regression suite, a two-layer package '
 'verifier, and a live case study in which it identified twelve findings and surfaced a '
 'present-but-ineffective configuration that presence testing would have passed.'),
('body', 'Several directions remain. The most immediate is a guided remediation generator '
 'capable of emitting deployment-ready configuration for common platforms, building on the '
 'static guidance the system already provides. A second direction is longitudinal tracking, '
 'in which successive scans of the same origin are compared to detect regression or drift. A '
 'third is multi-page crawling within an authorised scope, so that an assessment can cover a '
 'site rather than a page. Finally, the quality-aware principle could be extended beyond '
 'headers to the assessment of cookie policy, transport configuration, and client-side '
 'storage practice.'),

('h1u', 'Acknowledgment'),
('body', 'The authors thank the open-source maintainers of the Firefox WebExtension platform '
 'and the developers of the local inference tooling used during evaluation.'),
]

REFERENCES = [
 'M. Zalewski, \u201cBrowser security handbook,\u201d Google Inc., 2008. [Online]. Available: '
 'https://code.google.com/archive/p/browsersec/',
 'OWASP Foundation, \u201cOWASP secure headers project,\u201d OWASP. [Online]. Available: '
 'https://owasp.org/www-project-secure-headers/',
 'W3C, \u201cContent Security Policy Level 3,\u201d W3C Working Draft. [Online]. Available: '
 'https://www.w3.org/TR/CSP3/',
 'Internet Engineering Task Force, \u201cHTTP Strict Transport Security (HSTS),\u201d RFC 6797, '
 'Nov. 2012.',
 'Internet Engineering Task Force, \u201cHTTP State Management Mechanism,\u201d RFC 6265, '
 'Apr. 2011.',
 'Mozilla, \u201cWebExtensions API documentation.\u201d [Online]. Available: '
 'https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions',
 'N. Jovanovic, C. Kruegel, and E. Kirda, \u201cPixy: A static analysis tool for detecting web '
 'application vulnerabilities,\u201d in Proc. IEEE Symp. Security and Privacy, 2006, pp. 258\u2013263.',
 'A. Barth, C. Jackson, and J. C. Mitchell, \u201cRobust defenses for cross-site request '
 'forgery,\u201d in Proc. 15th ACM Conf. Computer and Communications Security, 2008, pp. 75\u201388.',
 'PortSwigger, \u201cBurp Suite professional.\u201d [Online]. Available: '
 'https://portswigger.net/burp',
 'Tenable, \u201cNessus vulnerability scanner.\u201d [Online]. Available: '
 'https://www.tenable.com/products/nessus',
 'Mozilla Foundation, \u201cObservatory by Mozilla.\u201d [Online]. Available: '
 'https://observatory.mozilla.org/',
 'J. Wei et al., \u201cChain-of-thought prompting elicits reasoning in large language models,\u201d '
 'in Advances in Neural Information Processing Systems, vol. 35, 2022, pp. 24824\u201324837.',
 'J. Bau et al., \u201cState of the art: Automated black-box web application vulnerability '
 'testing,\u201d in Proc. IEEE Symp. Security and Privacy, 2010, pp. 332\u2013345.',
 'D. Stuttard and M. Pinto, The Web Application Hacker\u2019s Handbook, 2nd ed. '
 'Indianapolis, IN, USA: Wiley, 2011.',
 'OASIS, \u201cStrict OOXML and the Open Packaging Conventions,\u201d ISO/IEC 29500. '
 '[Online]. Available: https://www.iso.org/standard/61720.html',
]

# ─────────────────────────── document assembly ───────────────────────────

SECTPR_ONE_COL = (
    '<w:sectPr><w:type w:val="continuous"/>'
    '<w:pgSz w:w="595.30pt" w:h="841.90pt" w:code="9"/>'
    '<w:pgMar w:top="54pt" w:right="44.65pt" w:bottom="72pt" w:left="44.65pt" '
    'w:header="36pt" w:footer="36pt" w:gutter="0pt"/>'
    '<w:cols w:space="36pt"/><w:docGrid w:linePitch="360"/></w:sectPr>'
)
SECTPR_TWO_COL = (
    '<w:sectPr><w:type w:val="continuous"/>'
    '<w:pgSz w:w="595.30pt" w:h="841.90pt" w:code="9"/>'
    '<w:pgMar w:top="54pt" w:right="44.65pt" w:bottom="72pt" w:left="44.65pt" '
    'w:header="36pt" w:footer="36pt" w:gutter="0pt"/>'
    '<w:cols w:num="2" w:space="18pt"/><w:docGrid w:linePitch="360"/></w:sectPr>'
)

def author_cell(name, dept, org, city):
    """One author block: name, then affiliation lines, centred, 11pt via Author style."""
    return (
        '<w:tc><w:tcPr><w:tcW w:w="0pt" w:type="auto"/>'
        '<w:tcBorders>'
        '<w:top w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '<w:start w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '<w:bottom w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '<w:end w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '</w:tcBorders>'
        '</w:tcPr>'
        + para('Author', name)
        + para('Author', dept)
        + para('Author', org)
        + para('Author', city)
        + '</w:tc>'
    )

def build_author_table(authors):
    cells = ''.join(author_cell(*a) for a in authors)
    return (
        '<w:tbl><w:tblPr><w:tblW w:w="0pt" w:type="auto"/><w:jc w:val="center"/>'
        '<w:tblBorders>'
        '<w:top w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '<w:start w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '<w:bottom w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '<w:end w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '<w:insideH w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '<w:insideV w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '</w:tblBorders>'
        '<w:tblCellMar>'
        '<w:top w:w="0" w:type="dxa"/><w:start w:w="57" w:type="dxa"/>'
        '<w:bottom w:w="0" w:type="dxa"/><w:end w:w="57" w:type="dxa"/>'
        '</w:tblCellMar>'
        '<w:tblLook w:firstRow="0" w:lastRow="0" w:firstColumn="0" w:lastColumn="0" '
        'w:noHBand="0" w:noVBand="0"/></w:tblPr>'
        '<w:tblGrid>' + '<w:gridCol w:w="4400"/>' * len(authors) + '</w:tblGrid>'
        '<w:tr>' + cells + '</w:tr></w:tbl>'
    )

def results_table():
    """A small results table using the template's table styles."""
    def cell(txt, style='tablecopy', width='1500', span=None, align=None):
        gs = f'<w:gridSpan w:val="{span}"/>' if span else ''
        al = f'<w:vAlign w:val="{align}"/>' if align else ''
        return (f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/>{gs}{al}</w:tcPr>'
                + para(style, txt) + '</w:tc>')

    def row(cells):
        return '<w:tr><w:trPr><w:cantSplit/></w:trPr>' + ''.join(cells) + '</w:tr>'

    head = row([
        cell('Metric', 'tablecolhead', '2000'),
        cell('Local rule engine', 'tablecolhead', '1600'),
        cell('Cloud model', 'tablecolhead', '1600'),
    ])
    rows = [
        ('Findings reported', '12', '12'),
        ('Risk assessment', 'Medium (28/100)', 'High (52/100)'),
        ('Latency', '~6 ms', '~9.4 s'),
        ('Recommendations', '12', '12'),
        ('Prompt / completion tokens', 'n/a', '960 / 1548'),
    ]
    body = ''.join(row([cell(a, 'tablecopy', '2000'),
                        cell(b, 'tablecopy', '1600'),
                        cell(c, 'tablecopy', '1600')]) for a, b, c in rows)

    return (
        '<w:tbl><w:tblPr><w:tblW w:w="0pt" w:type="dxa"/><w:jc w:val="center"/>'
        '<w:tblBorders>'
        '<w:top w:val="single" w:sz="4" w:space="0" w:color="auto"/>'
        '<w:start w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="auto"/>'
        '<w:end w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '<w:insideH w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '<w:insideV w:val="none" w:sz="0" w:space="0" w:color="auto"/>'
        '</w:tblBorders>'
        '<w:tblLayout w:type="fixed"/>'
        '<w:tblLook w:firstRow="0" w:lastRow="0" w:firstColumn="0" w:lastColumn="0" '
        'w:noHBand="0" w:noVBand="0"/></w:tblPr>'
        '<w:tblGrid><w:gridCol w:w="2000"/><w:gridCol w:w="1600"/><w:gridCol w:w="1600"/></w:tblGrid>'
        + head + body + '</w:tbl>'
    )

ROMAN = ['I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII', 'IX', 'X']
LETTER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def build_body():
    out = []
    out.append(para('papertitle', TITLE))
    out.append(build_author_table(AUTHORS))
    # end of section 1 -> single column
    out.append(empty_para(SECTPR_ONE_COL))

    out.append(para('Abstract', 'Abstract\u2014' + ABSTRACT))
    out.append(para('Keywords', 'Keywords\u2014' + KEYWORDS))

    h1n = 0
    h2n = 0
    h3n = 0
    for kind, text in BODY:
        # NOTE: Heading1..Heading4 carry their OWN numbering in styles.xml
        # (numId 4 -> ilvl0 upperRoman "I.", ilvl1 upperLetter "A.",
        #  ilvl2 decimal "1)", ilvl3 lowerLetter "a)"). The template body text
        # therefore contains NO literal numerals. Emitting our own would render
        # as "I. I. Introduction", so we pass the bare text and let Word number it.
        if kind == 'h1':
            h1n += 1; h2n = 0; h3n = 0
            out.append(para('Heading1', text))
        elif kind == 'h1u':
            # Unnumbered component head. The template itself uses Heading5 for
            # Acknowledgment and References precisely because Heading5 has no numPr.
            h2n = 0; h3n = 0
            out.append(para('Heading5', text))
        elif kind == 'h2':
            h2n += 1; h3n = 0
            out.append(para('Heading2', text))
        elif kind == 'h3':
            h3n += 1
            out.append(para('Heading3', text))
        elif kind == 'bullet':
            out.append(para('bulletlist', text))
        elif kind == 'body':
            out.append(para('BodyText', text))
        elif kind == 'figcap':
            out.append(para('figurecaption', text))
        elif kind == 'tblcap':
            out.append(para('tablehead', text))
        elif kind == 'tblfoot':
            out.append(para('tablefootnote', text))
        elif kind == 'table':
            out.append(results_table())
        else:
            raise ValueError(kind)

    # References. Heading5 = unnumbered (matches the template's own convention).
    out.append(para('Heading5', 'References'))
    for ref in REFERENCES:
        # The `references` style auto-numbers via numId 8, whose level text is
        # "[%1]" — so we must NOT write a literal "[1]" prefix or it doubles.
        # The hanging indent is still set explicitly, as the template does.
        out.append(para('references', ref,
                        extra_ppr='<w:ind w:start="17.70pt" w:hanging="17.70pt"/>'))

    # final section -> two columns
    out.append(SECTPR_TWO_COL)
    return ''.join(out)

# ─────────────────────────── write the package ───────────────────────────

DOC_NS = (
    'xmlns:w="http://purl.oclc.org/ooxml/wordprocessingml/main" '
    'xmlns:r="http://purl.oclc.org/ooxml/officeDocument/relationships" '
    'xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" '
    'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
    'mc:Ignorable="w14"'
)

document_xml = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
    f'<w:document {DOC_NS}><w:body>{build_body()}</w:body></w:document>'
)

# copy the template, replacing only document.xml
shutil.copyfile(TEMPLATE, OUT)
tmp = OUT + '.tmp'
with zipfile.ZipFile(TEMPLATE, 'r') as zin, \
     zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename == 'word/document.xml':
            data = document_xml.encode('utf-8')
        zout.writestr(item, data)
shutil.move(tmp, OUT)

print('WROTE:', OUT)
print('size :', os.path.getsize(OUT), 'bytes')
print('body :', len(document_xml), 'chars of XML')
print('words:', len(re.findall(r'\w+', ' '.join(t for _, t in BODY))) + len(re.findall(r'\w+', ABSTRACT)))
