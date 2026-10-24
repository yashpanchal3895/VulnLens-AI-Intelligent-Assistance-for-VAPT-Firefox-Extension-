# Paper 2 content

PAPER = {
    "num": 2,
    "slug": "passive-client-side-assessment",
    "title": "Passive Client-Side Vulnerability Assessment Through Browser Extensions: A Read-Only Architecture",
    "abstract": (
        "Vulnerability assessment tooling has traditionally assumed server-side access, an agent, or a hosted "
        "service. This constraint excludes the operator who holds only a browser and an authorisation to view a "
        "page. This paper presents a passive, read-only assessment architecture realised as a browser extension, "
        "in which two independent observation paths are merged: response headers captured through the browser's "
        "network interface, and the rendered document inspected by a script injected into the page. The "
        "architecture sends no payloads, submits no forms, and performs no exploitation, so it can be used "
        "lawfully on any page the operator is authorised to view. The paper specifies the collection model, the "
        "merge procedure, the mutation-handling strategy required for single-page applications, and the "
        "graceful-degradation contract that ensures a result is produced when any component fails. Evaluation "
        "comprises a ninety-eight-check regression suite, a two-layer package-integrity verifier, and a live "
        "production case study yielding twelve findings across four severity bands."
    ),
    "keywords": "passive vulnerability assessment, browser extension, client-side security, web application "
               "security, read-only scanning, Manifest V3, VAPT",
    "sections": [
        ("Introduction", [
            ("", "Vulnerability assessment identifies weaknesses; penetration testing attempts to exploit them. "
                 "The former is a precondition for the latter, and it is the stage at which most remediation "
                 "decisions are actually made. Mature platforms perform assessment well, but they assume an "
                 "installation, a licence, or a network position."),
            ("", "There is a class of operator for whom none of these assumptions hold. An auditor given temporary "
                 "access to a site, a developer checking a staging deployment, and a student learning assessment "
                 "methodology all hold exactly one instrument: a browser. A browser already possesses most of the "
                 "evidence an assessment needs. It receives every response header. It renders every document. It "
                 "resolves every subresource. The architecture described here makes that evidence visible without "
                 "extending the browser's reach."),
            ("", "The contributions are as follows: a two-path collection model that merges network-level and "
                 "document-level observation; a mutation-handling strategy that makes the assessment correct for "
                 "single-page applications; a graceful-degradation contract; and an evaluation comprising "
                 "regression, integrity, and live components."),
        ]),
        ("Design Constraints", [
            ("", "Four constraints shaped the architecture. First, the tool must be passive and read-only, since "
                 "any active behaviour would restrict where it may lawfully be used. Second, it must degrade "
                 "gracefully: a failure in any single component must not prevent a result. Third, it must produce "
                 "evidence rather than conclusions, so that every finding can be independently verified. Fourth, "
                 "it must remain usable without paid infrastructure, which excludes any design that mandates a "
                 "hosted service."),
            ("", "These constraints distinguish the architecture from server-side scanners. The extension can only "
                 "observe what the browser already possesses. It cannot enumerate endpoints, inspect server-side "
                 "configuration, or observe responses the browser never requests. This is a real limitation, and "
                 "the architecture is explicit about it rather than compensating with inference."),
        ]),
        ("Architecture", [
            ("Two-Path Collection", [
                "Collection proceeds along two independent paths that are merged. The header path runs in the "
                "background context, where the browser's network interface exposes response headers as they "
                "arrive. The document path runs in a script injected into the page, which inspects the rendered "
                "document object model after the document reaches an idle state.",
                "The two paths are complementary. The header path observes what the server declared. The document "
                "path observes what the browser actually loaded, which includes resources referenced by attributes "
                "the header path cannot see and content inserted by script after load.",
            ]),
            ("Header Path", [
                "The header path registers a listener on response headers and retains the most recent set per "
                "document. One implementation detail proved significant: headers that legitimately repeat, most "
                "notably Set-Cookie, must be collapsed into an array rather than assigned to an object key. "
                "Naive assignment overwrites all but the last value, which silently discards every cookie but one "
                "and therefore every attribute defect on the discarded cookies.",
                "A second detail concerns navigation. When a single-page application navigates without a document "
                "load, the retained header set becomes stale. The architecture records the navigation timestamp "
                "and flags a retained set that predates the current document as stale rather than reporting it "
                "as current.",
            ]),
            ("Document Path", [
                "The document path performs nine categories of inspection over the rendered document: the "
                "transport protocol of the page and of its forms; mixed content, including resources referenced "
                "through srcset attributes, data URIs, and stylesheet url() expressions; inline event handlers; "
                "document-object-model sinks such as direct assignment to innerHTML and calls to insertAdjacentHTML; "
                "links that open in a new browsing context without an opener restriction; forms that submit over "
                "plaintext transport; password fields not enclosed by a secure form; external scripts lacking an "
                "integrity attribute; and the count of inline script blocks, which determines the cost of adopting "
                "a strict content security policy.",
                "Inspection is triggered at document idle and re-evaluated on mutation, with debouncing, so that "
                "content inserted after load is assessed. Debouncing is necessary because an unthrottled observer "
                "on a page that mutates continuously would re-scan indefinitely and would consume the budget "
                "needed for analysis.",
            ]),
            ("Merge and Degradation", [
                "The merge procedure concatenates findings from both paths, deduplicates on a composite key of "
                "category and location, and assigns a single risk score. The degradation contract states that if "
                "either path is unavailable, the assessment proceeds with the other and the report records which "
                "path was unavailable. If both paths are unavailable, the assessment returns an explicit failure "
                "rather than an empty result, because an empty result is indistinguishable from a clean one.",
            ]),
        ]),
        ("Implementation", [
            ("", "The architecture is realised as a Manifest V3 extension for Firefox, requiring version 109 or "
                 "later, comprising a background service script, an injected content script, a popup interface, "
                 "and a report renderer. The extension requests the broadest host permissions available so that it "
                 "operates on any site the operator visits, and runs in all frames so that embedded documents are "
                 "assessed alongside their parent."),
            ("", "The popup presents findings grouped by severity, exposes the analysis tier selector, and offers "
                 "a self-contained report that can be exported without network access. The report records the "
                 "evidence for each finding, the tier that produced the explanation, and the timestamp of "
                 "collection, so that a result can be reproduced or audited."),
        ]),
        ("Evaluation", [
            ("Methodology", [
                "The regression suite comprises ninety-eight checks organised into nine phases exercising header "
                "analysis, rule coverage, analysis generation, risk-label consistency, report structure, and "
                "error classification. The integrity verifier operates in two layers: the first validates "
                "archive structure, requiring that the manifest reside at the archive root and that every "
                "referenced file resolve within the archive; the second performs project-specific validation of "
                "version consistency, permission hygiene, and the absence of development artefacts from the "
                "distributable.",
            ]),
            ("Results", [
                "All ninety-eight regression checks passed, as did all thirty-seven integrity checks. The live "
                "case study applied the architecture to a production site hosted behind a content delivery "
                "network and produced twelve findings: none high, four medium, four low, and four informational. "
                "The document path contributed the mixed-content, inline-script, and target-blank findings; the "
                "header path contributed the missing baseline headers and the malformed cache directive.",
            ]),
            ("Discussion", [
                "The case study illustrates the complementarity of the two paths. The document path identified "
                "seventeen inline script blocks and twenty-one links opening in a new context without an opener "
                "restriction, neither of which is observable from response headers. The header path identified "
                "the absence of five baseline headers, which is not observable from the document. Neither path "
                "alone would have produced the report.",
            ]),
        ]),
        ("Responsible Use", [
            ("", "Although the tool is passive, scanning a system without authorisation may contravene terms of "
                 "service or applicable law. The architecture therefore records the target and timestamp of every "
                 "assessment and presents the authorisation expectation in its interface. A clean result "
                 "indicates the absence of observable misconfiguration; it does not establish that a site is "
                 "secure."),
        ]),
        ("Conclusion", [
            ("", "A browser already holds most of the evidence a passive assessment requires. The architecture "
                 "described here surfaces that evidence without extending the browser's reach, and its "
                 "degradation contract ensures that a partial observation still yields a usable result. Future "
                 "work includes extending the document path to observe service-worker registrations and to "
                 "correlate findings across frames of the same origin."),
        ]),
    ],
    "ack": "The authors thank the developers of the browser extension platform and of the local inference tooling "
           "used during evaluation.",
    "refs": [
        "Mozilla, “WebExtensions API documentation.” [Online]. Available: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions",
        "M. Zalewski, “Browser security handbook,” Google Inc., 2008. [Online]. Available: https://code.google.com/archive/p/browsersec/",
        "D. Stuttard and M. Pinto, The Web Application Hacker’s Handbook, 2nd ed. Indianapolis, IN, USA: Wiley, 2011.",
        "J. Bau et al., “State of the art: Automated black-box web application vulnerability testing,” in Proc. IEEE Symp. Security and Privacy, 2010, pp. 332–345.",
        "OWASP Foundation, “OWASP testing guide,” OWASP. [Online]. Available: https://owasp.org/www-project-web-security-testing-guide/",
        "Internet Engineering Task Force, “The Web Origin Concept,” RFC 6454, Dec. 2011.",
        "A. Barth, C. Jackson, and J. C. Mitchell, “Robust defenses for cross-site request forgery,” in Proc. 15th ACM Conf. Computer and Communications Security, 2008, pp. 75–88.",
        "W3C, “Content Security Policy Level 3,” W3C Working Draft. [Online]. Available: https://www.w3.org/TR/CSP3/",
        "N. Jovanovic, C. Kruegel, and E. Kirda, “Pixy: A static analysis tool for detecting web application vulnerabilities,” in Proc. IEEE Symp. Security and Privacy, 2006, pp. 258–263.",
        "PortSwigger, “Burp Suite professional.” [Online]. Available: https://portswigger.net/burp",
    ],
    "tables": [],
}
