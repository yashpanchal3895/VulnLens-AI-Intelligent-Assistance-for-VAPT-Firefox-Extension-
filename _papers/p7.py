# Paper 7 content

PAPER = {
    "num": 7,
    "slug": "subresource-integrity-supply-chain",
    "title": "Subresource Integrity as a Supply-Chain Control: Adoption and Failure Modes on the Web",
    "abstract": (
        "A page that loads a script from a third-party origin delegates the integrity of that page to the "
        "operator of that origin. Subresource Integrity addresses the delegation by allowing the page to declare "
        "the cryptographic digest of the resource it expects, so that a browser refuses to execute a modified "
        "response. This paper examines the control's adoption and its characteristic failure modes, using "
        "passive observation of live production documents. The study records the share of external scripts that "
        "carry an integrity attribute, the share of those whose attribute is well formed, and the failure modes "
        "observed: a missing crossorigin attribute that prevents the check from applying to a cross-origin "
        "response, an integrity attribute that is empty or malformed, and a digest that is present but does not "
        "match any algorithm the browser will enforce. The paper concludes that Subresource Integrity is "
        "under-adopted relative to the exposure it addresses, and that the failures that do occur are "
        "concentrated in the crossorigin interaction, which is a specification subtlety rather than an operator "
        "error."
    ),
    "keywords": "subresource integrity, supply-chain security, third-party scripts, content security policy, "
               "web security, crossorigin, integrity verification",
    "sections": [
        ("Introduction", [
            ("", "Modern pages load executable content from origins they do not control. An analytics snippet, a "
                 "tag manager, a font loader, and a widget each arrive from a third party. The page's security "
                 "posture is therefore a function of the security posture of every third party it loads, and the "
                 "page author has no direct control over any of them."),
            ("", "Subresource Integrity addresses one half of this problem. It allows the page to declare the "
                 "digest of the resource it expects, and the browser refuses to execute a response whose digest "
                 "does not match. It does not address availability, and it does not address a compromised origin "
                 "serving a modified resource with a matching digest, because the digest in the page is what the "
                 "attacker would need to change."),
            ("", "This paper measures the control's adoption and characterises its failure modes through passive "
                 "observation of live documents. The contributions are the failure-mode taxonomy and the finding "
                 "that the dominant failure is the crossorigin interaction rather than a missing attribute."),
        ]),
        ("Background", [
            ("The Integrity Attribute", [
                "The integrity attribute carries a comma-separated list of algorithm-hash pairs. A browser "
                 "computes the digest of the response it receives and compares it against the strongest "
                 "algorithm in the list it supports. A response that matches is executed; a response that does "
                 "not match is refused, and the page receives an error event rather than a script.",
                "The check applies only when the browser is permitted to read the response. For a cross-origin "
                 "request this requires a crossorigin attribute on the element, without which the response is "
                 "opaque to the page and the digest cannot be verified against it.",
            ]),
            ("Relationship to Content Security Policy", [
                "A content security policy can restrict the origins from which a script may load, which limits "
                 "the blast radius of a compromised third party but does not detect a modification. Subresource "
                 "Integrity detects a modification but does not restrict the origin. The two controls are "
                 "complementary, and a page that carries one without the other has closed half the exposure.",
            ]),
        ]),
        ("Method", [
            ("", "External scripts were enumerated passively from live production documents as rendered in a "
                 "browser, and each was examined for the presence and well-formedness of an integrity attribute "
                 "and for the presence of a crossorigin attribute. The origin of each resource was classified as "
                 "first-party or third-party by comparison with the document's origin. The document's inline "
                 "script inventory was also recorded, because an inline script cannot carry an integrity "
                 "attribute and therefore cannot be protected by the control at all."),
        ]),
        ("Results", [
            ("", "The study finds that the control is under-adopted relative to the exposure it addresses. A "
                 "minority of external scripts carry an integrity attribute, and the share is lowest for "
                 "resources loaded by tag managers, which are precisely the resources whose origin is most "
                 "likely to be compromised because they are loaded by a large number of sites."),
            ("", "Four failure modes were observed. The first is a missing integrity attribute, which is the "
                 "common case and is the absence of the control rather than a defect in it. The second is an "
                 "integrity attribute without a crossorigin attribute on a cross-origin resource, which is the "
                 "dominant defect among resources that do carry the attribute: the digest is present but the "
                 "browser cannot verify it, so the control is inert. The third is a malformed attribute, "
                 "typically an empty value or a value that does not parse into algorithm-hash pairs. The fourth "
                 "is a digest that names an algorithm the browser does not support, which the browser treats as "
                 "an unmatched resource."),
            ("", "The inline inventory is material to the interpretation of the first mode. A page whose scripts "
                 "are predominantly inline cannot adopt the control for those scripts at all, and the cost of "
                 "adoption is the cost of extracting them, which is the same cost that adopting a strict content "
                 "security policy imposes."),
        ]),
        ("Discussion", [
            ("", "Three observations follow. First, the crossorigin failure mode is a specification subtlety "
                 "rather than an operator error, and it is the failure most amenable to tooling, because a "
                 "scanner can detect the combination and report it. Second, adoption is lowest exactly where "
                 "the exposure is highest, which is the pattern typical of a control whose cost is borne by the "
                 "page author and whose benefit accrues to the page author only in the event of a third-party "
                 "compromise. Third, the control cannot protect inline scripts, so an adoption figure that "
                 "ignores the inline inventory overstates the protection delivered."),
        ]),
        ("Limitations", [
            ("", "The study observes the documents a browser rendered, at a single moment. Resources loaded "
                 "conditionally, on interaction, or after a consent decision are sampled only if they were "
                 "present at idle. The study does not verify that any observed digest matches the resource "
                 "served, since that would require an independent retrieval, and it does not attempt to "
                 "determine whether a third-party origin has been compromised."),
        ]),
        ("Conclusion", [
            ("", "Subresource Integrity is a supply-chain control that is under-adopted, and the failures that "
                 "occur among adopting sites are concentrated in the crossorigin interaction. A passive scanner "
                 "can detect the inert-digest combination at negligible cost, and reporting it would convert an "
                 "apparently adopted control into an actually enforced one. Future work includes correlating "
                 "third-party origin reuse across sites, which would identify the origins whose compromise "
                 "affects the largest number of pages."),
        ]),
    ],
    "ack": "The authors thank the operators of the sites included in the sample.",
    "refs": [
        "W3C, “Subresource Integrity,” W3C Recommendation. [Online]. Available: https://www.w3.org/TR/SRI/",
        "W3C, “Content Security Policy Level 3,” W3C Working Draft. [Online]. Available: https://www.w3.org/TR/CSP3/",
        "M. Zalewski, “Browser security handbook,” Google Inc., 2008. [Online]. Available: https://code.google.com/archive/p/browsersec/",
        "D. Stuttard and M. Pinto, The Web Application Hacker’s Handbook, 2nd ed. Indianapolis, IN, USA: Wiley, 2011.",
        "OWASP Foundation, “OWASP secure headers project,” OWASP. [Online]. Available: https://owasp.org/www-project-secure-headers/",
        "Internet Engineering Task Force, “The Web Origin Concept,” RFC 6454, Dec. 2011.",
        "L. Weichselbaum et al., “CSP is dead, long live CSP! On the insecurity of whitelists and the future of content security policy,” in Proc. ACM SIGSAC Conf. on Computer and Communications Security, 2016, pp. 1376–1387.",
        "Mozilla, “WebExtensions API documentation.” [Online]. Available: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions",
        "N. Jovanovic, C. Kruegel, and E. Kirda, “Pixy: A static analysis tool for detecting web application vulnerabilities,” in Proc. IEEE Symp. Security and Privacy, 2006, pp. 258–263.",
        "J. Bau et al., “State of the art: Automated black-box web application vulnerability testing,” in Proc. IEEE Symp. Security and Privacy, 2010, pp. 332–345.",
    ],
    "tables": [],
}
