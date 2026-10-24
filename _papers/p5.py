# Paper 5 content

PAPER = {
    "num": 5,
    "slug": "csp-directive-quality",
    "title": "Content Security Policy in Practice: Measuring Directive Quality Rather Than Header Presence",
    "abstract": (
        "Content Security Policy is the principal browser-enforced control against cross-site scripting, and its "
        "adoption is routinely measured by whether a response carries the header at all. That measurement "
        "overstates the protection delivered, because a policy may be syntactically valid while permitting the "
        "very vectors it names. This paper measures directive quality rather than header presence on a sample of "
        "live production responses, evaluating six predicates: unsafe-inline, unsafe-eval, wildcard sources, "
        "plaintext http sources, the absence of a default-src fallback, and the absence of object-src and "
        "base-uri. The study finds that a substantial share of responses carrying a policy fail at least one "
        "predicate, and that the most common failure is the presence of unsafe-inline in a policy that otherwise "
        "restricts sources tightly, which indicates that the policy was adopted for a narrow purpose rather than "
        "as a scripting control. The paper concludes that adoption statistics should be reported per predicate "
        "and that a policy which permits unsafe-inline in script-src should be counted as absent for the purpose "
        "of measuring cross-site scripting mitigation."
    ),
    "keywords": "content security policy, cross-site scripting, directive analysis, web security measurement, "
               "policy effectiveness, browser security controls",
    "sections": [
        ("Introduction", [
            ("", "Content Security Policy restricts the sources from which a document may load executable "
                 "content and the sinks into which it may inject markup. It is the only widely deployed control "
                 "that mitigates cross-site scripting at the point of exploitation rather than at the point of "
                 "injection, which is why it is the centrepiece of most modern web security guidance."),
            ("", "Adoption is usually measured by presence. A response either carries a Content-Security-Policy "
                 "header or it does not. This measurement is easy to collect and easy to report, and it "
                 "systematically overstates the protection delivered, because the policy grammar permits values "
                 "that satisfy the syntax while defeating the purpose."),
            ("", "This paper measures directive quality instead. It evaluates six predicates derived from the "
                 "policy specification against live production responses and reports the pass rate per "
                 "predicate. The contributions are the predicate set, the measurement methodology, and the "
                 "finding that presence statistics should not be used as a proxy for cross-site scripting "
                 "mitigation."),
        ]),
        ("Background", [
            ("The Policy Grammar", [
                "A policy is a sequence of directives, each of which restricts a resource type or a behaviour. "
                "The default-src directive supplies a fallback for fetch directives that do not specify their "
                "own source list. The script-src directive restricts executable content. The object-src and "
                "base-uri directives restrict plugin embedding and the document's base URL respectively.",
                "Two keywords are central to this study. The 'unsafe-inline' keyword permits inline script and "
                "inline event handlers, which are precisely the vectors the policy exists to constrain. The "
                "'unsafe-eval' keyword permits the eval family of functions, which converts any injection of "
                "text into executable code. A policy that carries either keyword in script-src or default-src "
                "mitigates little.",
            ]),
            ("Prior Measurement", [
                "Existing measurement studies report adoption rates and, where they examine policy content, "
                "typically report the frequency of individual directives rather than the frequency of "
                "combinations that defeat the control. The distinction matters: a policy that restricts "
                "script-src tightly but omits object-src leaves a vector that the specification defines as "
                "available.",
            ]),
        ]),
        ("Method", [
            ("Predicate Set", [
                "Six predicates are evaluated. P1: the policy does not carry 'unsafe-inline' in script-src or "
                "default-src. P2: the policy does not carry 'unsafe-eval'. P3: the policy does not carry a "
                "wildcard source in script-src, object-src, or default-src. P4: the policy does not carry a "
                "plaintext http source in a fetch directive. P5: the policy carries default-src or an equivalent "
                "fallback for every fetch directive. P6: the policy carries object-src and base-uri, or restricts "
                "them through default-src.",
                "A response passes the study only if it passes all six. A response that fails P1 is counted as "
                "not mitigating cross-site scripting, regardless of the other predicates, because unsafe-inline "
                "permits the dominant injection vector.",
            ]),
            ("Sampling", [
                "Responses were collected passively from documents rendered in a browser, so that the policy "
                "observed is the policy the browser actually enforced. Policies declared only in meta elements "
                "were excluded, because the header form is the form under study and the two forms interact in "
                "ways that a passive collector cannot disambiguate.",
            ]),
        ]),
        ("Results", [
            ("", "The study finds that a substantial share of responses carrying a policy fail at least one "
                 "predicate, and that the distribution of failures is uneven. The most common single failure is "
                 "P1, the presence of 'unsafe-inline', which occurs in policies that otherwise restrict sources "
                 "tightly. This pattern indicates that the policy was adopted to satisfy a specific requirement, "
                 "such as permitting an analytics snippet, rather than as a scripting control."),
            ("", "The second most common failure is P6, the omission of object-src and base-uri, which is "
                 "frequently a consequence of a default-src that does not cover them. Failures of P2 and P3 are "
                 "less common and, where they occur, cluster in policies that appear to have been generated "
                 "rather than authored."),
            ("", "The practical consequence is that a presence-based adoption statistic for the sampled "
                 "population overstates cross-site scripting mitigation by a wide margin, and that the "
                 "overstatement is concentrated in the category that matters most."),
        ]),
        ("Discussion", [
            ("", "Three observations follow. First, a policy carrying 'unsafe-inline' in script-src is, for "
                 "measurement purposes, equivalent to no policy with respect to the control it is credited with "
                 "providing. Second, the omission of object-src and base-uri is a specification subtlety rather "
                 "than an operator error, and it is the failure most amenable to tooling, because it is fixed by "
                 "adding two directives. Third, the inline script inventory of a document predicts the cost of "
                 "removing 'unsafe-inline' more accurately than the policy itself does, which suggests that a "
                 "measurement tool should report both."),
        ]),
        ("Limitations", [
            ("", "The study observes the policy delivered to a single browser at a single moment. Policies that "
                 "vary by path, by user agent, or by experiment bucket are sampled once. The study does not "
                 "attempt to determine why a policy carries a given keyword, and the inference that "
                 "'unsafe-inline' indicates narrow-purpose adoption is an interpretation of the observed pattern "
                 "rather than a finding."),
        ]),
        ("Conclusion", [
            ("", "Content Security Policy adoption should be measured per predicate rather than by presence. A "
                 "policy that permits 'unsafe-inline' in script-src does not mitigate cross-site scripting and "
                 "should not be counted as though it does. Future work includes correlating the inline script "
                 "inventory of a document with the keywords its policy carries, which would identify the sites "
                 "for which remediation is cheapest and therefore most likely to succeed."),
        ]),
    ],
    "ack": "The authors thank the operators of the sites included in the sample.",
    "refs": [
        "W3C, “Content Security Policy Level 3,” W3C Working Draft. [Online]. Available: https://www.w3.org/TR/CSP3/",
        "M. Zalewski, “Browser security handbook,” Google Inc., 2008. [Online]. Available: https://code.google.com/archive/p/browsersec/",
        "D. Stuttard and M. Pinto, The Web Application Hacker’s Handbook, 2nd ed. Indianapolis, IN, USA: Wiley, 2011.",
        "OWASP Foundation, “OWASP secure headers project,” OWASP. [Online]. Available: https://owasp.org/www-project-secure-headers/",
        "L. Weichselbaum et al., “CSP is dead, long live CSP! On the insecurity of whitelists and the future of content security policy,” in Proc. ACM SIGSAC Conf. on Computer and Communications Security, 2016, pp. 1376–1387.",
        "Internet Engineering Task Force, “HTTP State Management Mechanism,” RFC 6265, Apr. 2011.",
        "Mozilla, “WebExtensions API documentation.” [Online]. Available: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions",
        "N. Jovanovic, C. Kruegel, and E. Kirda, “Pixy: A static analysis tool for detecting web application vulnerabilities,” in Proc. IEEE Symp. Security and Privacy, 2006, pp. 258–263.",
        "J. Bau et al., “State of the art: Automated black-box web application vulnerability testing,” in Proc. IEEE Symp. Security and Privacy, 2010, pp. 332–345.",
        "Internet Engineering Task Force, “The Web Origin Concept,” RFC 6454, Dec. 2011.",
    ],
    "tables": [],
}
