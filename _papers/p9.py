# Paper 9 content

PAPER = {
    "num": 9,
    "slug": "mixed-content-transport-security",
    "title": "Mixed Content and Transport Security: Residual Risks After HTTPS Migration",
    "abstract": (
        "Migrating a site to HTTPS removes the plaintext transport exposure for the document itself, but it does "
        "not remove the exposure for the resources the document loads. A page served over TLS that requests a "
        "script over plaintext HTTP is a mixed-content page, and the resource is either blocked by the browser "
        "or, in the case of certain resource types, loaded and thereby exposed. This paper characterises residual "
        "transport risk after migration through passive observation of live production documents, examining the "
        "transport protocol of the page, of its forms, and of each subresource, including resources referenced "
        "through srcset attributes, data URIs, and stylesheet url() expressions. The study also examines "
        "Strict-Transport-Security as the mechanism that prevents a subsequent plaintext request, and evaluates "
        "the directive's max-age, includeSubDomains, and preload tokens rather than its presence. The paper "
        "concludes that mixed content is predominantly a subresource problem, that srcset and stylesheet "
        "references are the most frequently missed vectors, and that an HSTS policy with a short max-age or "
        "without includeSubDomains leaves a downgrade path that the migration was intended to close."
    ),
    "keywords": "mixed content, HTTPS migration, transport layer security, HTTP strict transport security, "
               "protocol downgrade, passive assessment, web security",
    "sections": [
        ("Introduction", [
            ("", "The migration of a site from plaintext HTTP to HTTPS is usually treated as a completed event. "
                 "The certificate is issued, the redirect is in place, and the site is recorded as secure. The "
                 "migration is not complete, because the document is only one of the requests a page makes."),
            ("", "A page served over TLS that requests a subresource over plaintext HTTP is a mixed-content "
                 "page. The subresource request traverses a network path an attacker controls, and the attacker "
                 "can modify or replace the response. For active content such as a script, the consequence is "
                 "arbitrary code execution in the origin of the page. For passive content such as an image, the "
                 "consequence is content substitution and referrer leakage."),
            ("", "This paper characterises the residual risk that survives migration, through passive observation "
                 "of live documents. The contributions are the vector taxonomy, the finding that srcset and "
                 "stylesheet references are the most frequently missed vectors, and the evaluation of "
                 "Strict-Transport-Security by directive quality rather than by presence."),
        ]),
        ("Background", [
            ("Mixed-Content Categories", [
                "Browsers classify mixed content into categories that determine whether the request is blocked "
                 "or permitted. A request that can alter the execution of the document, such as a script, is "
                 "blocked. A request that cannot, such as an image, is permitted but flagged. The classification "
                 "is a mitigation rather than a fix: a blocked script is a broken page, and a permitted image is "
                 "an exposed request.",
                "The categories are defined by resource type, which means that the same plaintext URL is treated "
                 "differently depending on the element that references it. A passive scanner that reports only "
                 "the URL therefore understates the exposure, and a scanner that reports only blocked requests "
                 "reports the category that the browser has already handled.",
            ]),
            ("Transport Enforcement", [
                "Strict-Transport-Security instructs the browser to convert subsequent plaintext requests to the "
                 "same host into secure requests, for a period declared by the max-age directive. The "
                 "includeSubDomains token extends the instruction to subdomains, and the preload token declares "
                 "an intention to be included in a browser-maintained list that applies the instruction before "
                 "the first response is ever received.",
                "The directive's value semantics are as material as its presence. A max-age of zero is an "
                 "explicit opt-out. A short max-age closes the downgrade path for a correspondingly short "
                 "period. An absent includeSubDomains leaves every subdomain as a downgrade entry point.",
            ]),
        ]),
        ("Method", [
            ("", "The transport protocol of each document and of each subresource it requests was recorded "
                 "passively from live production documents as rendered in a browser. The enumeration covered "
                 "src attributes, href attributes, srcset attributes, stylesheet url() expressions, inline style "
                 "attributes, form actions, and data URIs that resolve to plaintext. Form transport was recorded "
                 "separately from subresource transport, because a form that submits credentials over plaintext "
                 "is a different exposure from a page that loads an image over plaintext."),
            ("", "The Strict-Transport-Security header of each document was parsed into its directives and "
                 "evaluated against the predicates described above, and the result was recorded as effective, "
                 "weak, or obsolete rather than as present or absent."),
        ]),
        ("Results", [
            ("", "The study finds that mixed content on migrated sites is predominantly a subresource problem "
                 "rather than a document problem, and that the most frequently missed vectors are the ones that "
                 "a naive attribute scan does not reach. A srcset attribute carries multiple candidate URLs in a "
                 "single value, and a plaintext candidate is selected by the browser according to viewport "
                 "conditions, so the plaintext request may occur on some devices and not others. A stylesheet "
                 "url() expression is a plaintext reference inside a value rather than an attribute, and it is "
                 "invisible to an attribute scanner."),
            ("", "The Strict-Transport-Security evaluation found that presence overstates the control. Among "
                 "responses carrying the header, a substantial share carry a max-age below the threshold at which "
                 "the protection is meaningful, and a larger share omit includeSubDomains. A small number carry "
                 "a max-age of zero, which is an explicit opt-out that a presence test records as compliant."),
        ]),
        ("Discussion", [
            ("", "Three observations follow. First, a migration that is verified by checking the document "
                 "protocol is incomplete, because the document is a minority of the requests a page makes. "
                 "Second, the vectors that a scanner misses are the vectors that a scanner must be written to "
                 "reach: srcset, stylesheet url(), and data URIs are all value-level rather than "
                 "attribute-level references. Third, Strict-Transport-Security is the control that prevents the "
                 "next plaintext request, and its value semantics are as material as its presence, which places "
                 "it squarely in the class of controls that presence testing misreports."),
        ]),
        ("Limitations", [
            ("", "The study observes the documents a browser rendered at a single moment. Resources requested "
                 "conditionally, on interaction, or in response to a viewport condition are sampled only if the "
                 "condition held. The study does not verify that a plaintext request was in fact issued, since "
                 "that would require instrumentation the passive architecture does not perform, and it does not "
                 "observe the browser's mixed-content blocking decisions directly."),
        ]),
        ("Conclusion", [
            ("", "HTTPS migration closes the document's transport exposure and leaves the subresource exposure "
                 "open. The residual risk is concentrated in value-level references that an attribute scanner "
                 "does not reach, and in transport-enforcement headers whose value semantics a presence test does "
                 "not evaluate. A passive scanner that enumerates srcset, stylesheet url(), and data URIs, and "
                 "that evaluates Strict-Transport-Security by directive quality, closes both gaps at negligible "
                 "cost."),
        ]),
    ],
    "ack": "The authors thank the operators of the sites included in the sample.",
    "refs": [
        "Internet Engineering Task Force, “HTTP Strict Transport Security (HSTS),” RFC 6797, Nov. 2012.",
        "Internet Engineering Task Force, “The Transport Layer Security (TLS) Protocol Version 1.2,” RFC 5246, Aug. 2008.",
        "Internet Engineering Task Force, “HTTP Over TLS,” RFC 2818, May 2000.",
        "M. Zalewski, “Browser security handbook,” Google Inc., 2008. [Online]. Available: https://code.google.com/archive/p/browsersec/",
        "D. Stuttard and M. Pinto, The Web Application Hacker’s Handbook, 2nd ed. Indianapolis, IN, USA: Wiley, 2011.",
        "W3C, “Mixed Content,” W3C Candidate Recommendation. [Online]. Available: https://www.w3.org/TR/mixed-content/",
        "OWASP Foundation, “OWASP transport layer protection cheat sheet,” OWASP. [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
        "Mozilla, “WebExtensions API documentation.” [Online]. Available: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions",
        "Internet Engineering Task Force, “HTTP State Management Mechanism,” RFC 6265, Apr. 2011.",
        "W3C, “Content Security Policy Level 3,” W3C Working Draft. [Online]. Available: https://www.w3.org/TR/CSP3/",
    ],
    "tables": [],
}
