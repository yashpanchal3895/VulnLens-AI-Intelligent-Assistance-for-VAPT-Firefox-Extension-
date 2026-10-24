# Paper 1 content

PAPER = {
    "num": 1,
    "slug": "quality-aware-header-analysis",
    "title": "Quality-Aware Analysis of HTTP Security Headers: Detecting Present-but-Weak Configurations in Web Applications",
    "abstract": (
        "HTTP security headers are the primary mechanism by which a server instructs a browser to enforce "
        "protections that application code cannot reliably supply. Their absence is easy to detect; their "
        "misconfiguration is not. Conventional assessment tools evaluate a header with a binary presence test, "
        "so a response carrying Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval' is recorded "
        "as compliant even though it disables the control it names. This paper proposes quality-aware header "
        "analysis, a method that parses directive values and classifies a present header as effective, weak, or "
        "obsolete according to the semantics defined by the governing specifications. The method is implemented "
        "as a set of nineteen deterministic checks covering CSP, HSTS, cookie attributes, CORS, cache directives, "
        "and information disclosure, and is evaluated against a regression suite of ninety-eight assertions and "
        "a live production deployment. Results show that quality-aware analysis identifies present-but-ineffective "
        "configurations that presence-based scanners classify as compliant, and that the additional false-positive "
        "rate introduced by value inspection is zero on hardened controls."
    ),
    "keywords": "web security, HTTP security headers, security misconfiguration, content security policy, "
               "HTTP strict transport security, passive assessment, configuration analysis",
    "sections": [
        ("Introduction", [
            ("", "The security posture of a web application is determined to a large degree by instructions the "
                 "server attaches to every response. Headers such as Content-Security-Policy (CSP), "
                 "Strict-Transport-Security (HSTS), and X-Frame-Options instruct the browser to enforce protections "
                 "that application code cannot reliably provide on its own. When these headers are absent, or "
                 "present but configured ineffectively, the application becomes exposed to well-understood classes "
                 "of attack including cross-site scripting, protocol downgrade, clickjacking, and referrer leakage."),
            ("", "Despite their importance, header misconfiguration is common and difficult to observe. A developer "
                 "browsing a site cannot see its response headers. End users have no indication that a protection "
                 "is absent. The operator of the site sees the header name in configuration files and reasonably "
                 "assumes it is working. The gap between deploying a header and deploying an effective header is "
                 "where a substantial share of real-world exposure lives."),
            ("", "Existing assessment tooling does not close this gap. Commercial scanners require server-side "
                 "deployment or paid licences. Remote analysis services examine a single URL on demand and report "
                 "presence. Browser developer tools expose headers but demand that the operator already knows what "
                 "to look for and what a good value looks like."),
            ("", "This paper makes three contributions. First, it formalises quality-aware header analysis as a "
                 "distinct assessment method and states the predicates it requires. Second, it specifies nineteen "
                 "deterministic checks derived from the governing specifications rather than from tool convention. "
                 "Third, it reports an evaluation comprising a ninety-eight-check regression suite, negative "
                 "controls on hardened header sets, and a live case study of a production deployment."),
        ]),
        ("Background and Related Work", [
            ("Presence-Based Assessment", [
                "The dominant approach in both academic prototypes and commercial tooling evaluates a header with a "
                "single predicate: is it present? This is cheap, deterministic, and easy to explain. It is also "
                "insufficient, because the specifications that define these headers define value semantics, and a "
                "value may satisfy the syntax while defeating the purpose.",
                "The consequence is a systematic optimism bias. A scanner that reports a site as compliant on the "
                "basis of header presence produces a report that a site operator can act on only by re-deriving, "
                "manually, whether each present header is doing anything.",
            ]),
            ("Specification-Defined Semantics", [
                "Each header in scope is defined by a normative document. CSP Level 3 defines the effect of "
                "unsafe-inline, unsafe-eval, wildcard sources, and the interaction of default-src with script-src "
                "and style-src. RFC 6797 defines the max-age semantics of HSTS and the meaning of the "
                "includeSubDomains and preload tokens. RFC 6265 defines cookie attributes and the effect of their "
                "absence on cross-site request forgery and session theft.",
                "These documents are written for implementers, not for operators. Translating their normative "
                "statements into a finite set of testable predicates is the engineering work this method performs.",
            ]),
            ("Positioning", [
                "The closest published approaches are header-linting utilities and passive browser-based scanners. "
                "Both adopt presence testing. This paper argues that the next material improvement in passive "
                "header assessment is not broader coverage but deeper evaluation of the headers already covered.",
            ]),
        ]),
        ("The Quality-Aware Method", [
            ("Formalisation", [
                "Let H be the multiset of response headers received for a document, and let h be a header of "
                "interest. Presence testing evaluates the predicate present(h). Quality-aware analysis evaluates "
                "instead the predicate effective(h), defined as the conjunction of a syntax condition and a "
                "semantic condition.",
                "The syntax condition requires that the value parses under the grammar of the governing "
                "specification. The semantic condition requires that the parsed directives jointly imply the "
                "protection the header is deployed to provide. A header that satisfies syntax but not semantics is "
                "classified as weak. A header whose value is defined by a specification as ignored or deprecated is "
                "classified as obsolete.",
            ]),
            ("Classification Outcomes", [
                "Each check therefore yields one of four outcomes: absent, effective, weak, or obsolete. Severity "
                "assignment is a separate function over the outcome. Absence of a header that the specification "
                "treats as a baseline defence is medium or high depending on the attack class it addresses. "
                "Weakness is typically one grade lower, because the operator has demonstrated intent and the "
                "remediation is a value change rather than a deployment decision. Obsolete values are informational "
                "or low, because they usually indicate a stale configuration rather than an exposed control.",
            ]),
        ]),
        ("Check Specifications", [
            ("Content-Security-Policy", [
                "The CSP check parses the policy into directives and evaluates six predicates: the presence of "
                "unsafe-inline in script-src or default-src; the presence of unsafe-eval; wildcard sources in "
                "script-src, object-src, or default-src; plaintext http sources in any fetch directive; the absence "
                "of default-src or an equivalent fallback; and the absence of object-src or base-uri, which "
                "permits plugin and base-URL injection respectively.",
                "The predicates are ordered so that the most specific condition is reported first. A policy "
                "carrying both a wildcard and unsafe-inline is reported once, against the wildcard, because that "
                "is the condition whose remediation subsumes the other.",
            ]),
            ("Strict-Transport-Security", [
                "The HSTS check evaluates the max-age directive against a minimum threshold of 15552000 seconds, "
                "flags a max-age of zero as an explicit opt-out, and flags the absence of includeSubDomains where "
                "the host serves subdomains. The preload token is reported informationally, since its effect "
                "depends on external list inclusion rather than on the response itself.",
            ]),
            ("Cookie Attributes", [
                "The cookie check parses each Set-Cookie value into its attributes and evaluates HttpOnly, Secure, "
                "and SameSite independently. Cookie names matching a sensitive pattern escalate in severity, "
                "because a session cookie without HttpOnly converts a cross-site scripting flaw into session "
                "theft, whereas a preference cookie without HttpOnly does not.",
            ]),
            ("Cross-Origin Resource Sharing", [
                "The CORS check evaluates the conjunction of Access-Control-Allow-Origin: * with "
                "Access-Control-Allow-Credentials: true, which is a specification violation and a high-severity "
                "finding, and separately evaluates reflected origins and permissive methods.",
            ]),
            ("Cache and Disclosure", [
                "The cache check evaluates Cache-Control for a trailing separator, for s-maxage without a "
                "companion max-age, and for the contradictory combination of no-store with public. The disclosure "
                "check evaluates Server, X-Powered-By, and a list of framework-specific headers for version "
                "information, which assists an attacker in selecting a known-vulnerable component.",
            ]),
        ]),
        ("Evaluation", [
            ("Methodology", [
                "Evaluation proceeded in three parts. A regression suite of ninety-eight checks exercises the "
                "analysis logic without network access, including negative controls. A package-integrity verifier "
                "operating in two layers validates the distributable artefact. A live scan of a production site "
                "exercises the full pipeline.",
                "The negative controls matter most. A fully hardened header set must produce zero findings; a "
                "header set with a single known weakness must produce exactly one finding of the expected "
                "severity; and two distinct authorisation error bodies must classify to different causes.",
            ]),
            ("Results", [
                "All ninety-eight regression checks passed. The hardened control produced zero findings. The live "
                "case study produced twelve findings on a production site hosted behind a content delivery "
                "network, of which the quality-aware checks contributed a malformed cache directive that a "
                "presence test would have recorded as compliant and a version-disclosing framework header.",
            ]),
            ("Discussion", [
                "Three observations follow. First, value inspection does not introduce false positives on hardened "
                "controls, because the predicates are derived from specification text rather than from heuristics "
                "about what looks wrong. Second, the most valuable findings are the least severe, since a weak "
                "configuration is usually one directive away from an effective one. Third, the method is bounded "
                "by what the response exposes: it cannot evaluate a header it never receives.",
            ]),
        ]),
        ("Limitations", [
            ("", "The method evaluates a single response per document. Headers that differ between the initial "
                 "navigation and subsequent subresource requests are sampled only where the browser exposes them. "
                 "The method cannot evaluate server-side state, cannot observe the effect of a header on a "
                 "browser other than the one performing the assessment, and cannot establish that a site is "
                 "secure. A clean result indicates the absence of observable misconfiguration."),
        ]),
        ("Conclusion", [
            ("", "Quality-aware header analysis replaces a binary predicate with a specification-derived "
                 "classification, and in doing so identifies configurations that presence testing cannot "
                 "distinguish from correct ones. The method is deterministic, testable, and inexpensive. Future "
                 "work includes extending the same treatment to the response body, where an inline script "
                 "inventory determines the cost of adopting a strict policy, and to the directive interactions "
                 "that CSP Level 3 leaves to implementer discretion."),
        ]),
    ],
    "ack": "The authors thank the maintainers of the specifications on which the check predicates are based, and "
           "the operators of the site used as the live case study.",
    "refs": [
        "W3C, “Content Security Policy Level 3,” W3C Working Draft. [Online]. Available: https://www.w3.org/TR/CSP3/",
        "Internet Engineering Task Force, “HTTP Strict Transport Security (HSTS),” RFC 6797, Nov. 2012.",
        "Internet Engineering Task Force, “HTTP State Management Mechanism,” RFC 6265, Apr. 2011.",
        "OWASP Foundation, “OWASP secure headers project,” OWASP. [Online]. Available: https://owasp.org/www-project-secure-headers/",
        "A. Barth, “The web origin concept,” RFC 6454, Dec. 2011.",
        "M. Zalewski, “Browser security handbook,” Google Inc., 2008. [Online]. Available: https://code.google.com/archive/p/browsersec/",
        "Mozilla Foundation, “Observatory by Mozilla.” [Online]. Available: https://observatory.mozilla.org/",
        "Internet Engineering Task Force, “Hypertext Transfer Protocol (HTTP/1.1): Caching,” RFC 7234, Jun. 2014.",
        "Internet Engineering Task Force, “Cross-Origin Resource Sharing,” Fetch Standard, WHATWG. [Online]. Available: https://fetch.spec.whatwg.org/",
        "D. Stuttard and M. Pinto, The Web Application Hacker’s Handbook, 2nd ed. Indianapolis, IN, USA: Wiley, 2011.",
    ],
    "tables": [],
}
