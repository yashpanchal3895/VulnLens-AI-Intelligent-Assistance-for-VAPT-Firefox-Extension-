# Paper 10 content

PAPER = {
    "num": 10,
    "slug": "systematic-comparison-assessment-tools",
    "title": "Automated Web Application Vulnerability Assessment Tools: A Systematic Comparison",
    "abstract": (
        "The market for automated web application assessment is dense and the categories are poorly separated. "
        "This paper compares eight representative tools across nine dimensions: the analysis technique, the "
        "position from which the tool observes the target, whether the tool is active or passive, the licence "
        "model, the cost to the operator, the format and completeness of the evidence produced, whether the tool "
        "explains findings in operator language or in tool language, whether it degrades gracefully when a "
        "component fails, and whether it can be used without paid infrastructure. The comparison shows that the "
        "dimensions separate the field more cleanly than tool names do, and that the passive-versus-active axis "
        "and the evidence-versus-conclusion axis together determine where a tool can lawfully and usefully be "
        "used. The paper concludes that the gap in the field is not detection coverage but evidence production "
        "and explanation, and that the tools which occupy that gap are the ones that place fewest demands on the "
        "operator."
    ),
    "keywords": "vulnerability assessment, tool comparison, web application security, passive scanning, dynamic "
               "analysis, static analysis, security tooling",
    "sections": [
        ("Introduction", [
            ("", "An operator selecting an assessment tool faces a dense market with poorly separated "
                 "categories. Names overlap, feature lists overlap, and the distinctions that matter, such as "
                 "whether the tool sends payloads and whether it produces evidence, are rarely the distinctions "
                 "that marketing material emphasises."),
            ("", "This paper compares eight representative tools across nine dimensions chosen because they "
                 "determine where a tool can lawfully and usefully be used, rather than because they are easy to "
                 "tabulate. The comparison is qualitative and is based on documented capability rather than on "
                 "benchmark scores, because the dimensions under study are not the dimensions that benchmarks "
                 "measure."),
            ("", "The contributions are the dimension set, the comparison itself, and the conclusion that the "
                 "gap in the field is evidence production and explanation rather than detection coverage."),
        ]),
        ("Method", [
            ("Selection", [
                "Tools were selected to span the field rather than to sample it. Two are commercial dynamic "
                 "scanners, two are open-source dynamic scanners, one is a remote analysis service, one is a "
                 "static analysis tool, one is a browser-embedded passive scanner, and one is a "
                 "developer-oriented header linter. The set is small by design, because the dimensions under "
                 "study are qualitative and a large sample would add rows without adding discrimination.",
            ]),
            ("Dimensions", [
                "Nine dimensions were assessed. The analysis technique: static analysis of source, dynamic "
                 "analysis of a running instance, configuration analysis of responses, or a combination. The "
                 "observation position: an agent on the host, a proxy on the network path, a remote service, or "
                 "a browser on the client. Whether the tool is active, meaning it sends requests intended to "
                 "elicit a vulnerable response, or passive, meaning it observes only what the target produces "
                 "unprompted. The licence model. The cost to the operator. The evidence produced, meaning "
                 "whether a finding carries the observed values that support it or only a conclusion. Whether "
                 "the explanation is in operator language or in tool language. Whether the tool degrades "
                 "gracefully when a component fails. And whether it can be used without paid infrastructure.",
            ]),
        ]),
        ("Comparison", [
            ("", "The comparison shows that the dimensions separate the field more cleanly than tool names do. "
                 "The commercial dynamic scanners occupy the active, agent-or-proxy, paid, evidence-rich "
                 "quadrant. The open-source dynamic scanners occupy the same quadrant at zero licence cost and "
                 "with a higher operator-skill requirement. The remote analysis service occupies the passive, "
                 "remote, free-or-metered quadrant and produces conclusions with limited evidence. The static "
                 "analysis tool occupies the source-analysis quadrant and is bounded by access to source. The "
                 "browser-embedded passive scanner occupies the passive, client-side, zero-cost quadrant and "
                 "produces evidence for configuration weaknesses only. The header linter occupies the "
                 "configuration-analysis quadrant and produces presence verdicts."),
            ("", "Two dimensions carry most of the discrimination. The first is active versus passive, which "
                 "determines whether the tool may lawfully be pointed at a system the operator does not own. "
                 "The second is evidence versus conclusion, which determines whether a finding can be "
                 "independently verified or must be taken on trust."),
        ]),
        ("Discussion", [
            ("", "Three observations follow. First, the active tools have the broadest detection coverage, and "
                 "the coverage is purchased with a legal and operational precondition that does not apply to "
                 "the passive tools. Second, the tools that produce conclusions without evidence transfer the "
                 "verification burden to the operator, which is the burden the tool was engaged to remove. "
                 "Third, the tools that place the fewest demands on the operator, in licence, in installation, "
                 "and in skill, are the ones that occupy the narrowest slice of the assessment surface, which "
                 "suggests that the demands are not incidental to the coverage."),
            ("", "The gap this identifies is not detection coverage but evidence production and explanation. A "
                 "passive tool that observes what a browser already receives can produce evidence at "
                 "essentially zero marginal cost, and can attach an explanation that references the observed "
                 "values. That combination is available to no tool in the commercial dynamic quadrant, because "
                 "those tools are architected to send requests rather than to observe them."),
        ]),
        ("Limitations", [
            ("", "The comparison is qualitative and is based on documented capability rather than on measured "
                 "performance. It does not report detection rates, because a detection rate requires a ground "
                 "truth that no available corpus provides for configuration weaknesses. Tool versions change "
                 "and the comparison is a snapshot. The set of eight is small and was selected for coverage of "
                 "the dimension space rather than for representativeness of the market."),
        ]),
        ("Conclusion", [
            ("", "The field separates along two axes: active versus passive, and evidence versus conclusion. "
                 "The commercial dynamic scanners hold the active, evidence-rich quadrant and are the right "
                 "choice for an operator who owns the target and needs broad coverage. The passive tools hold "
                 "the observation quadrant and are the right choice for an operator who needs evidence about "
                 "configuration without a precondition of ownership. The gap in the field is the combination of "
                 "passive observation, evidence production, and operator-language explanation, and it is a gap "
                 "that the browser already contains the raw material to close."),
        ]),
    ],
    "ack": "The authors thank the developers of the tools included in the comparison.",
    "refs": [
        "PortSwigger, “Burp Suite professional.” [Online]. Available: https://portswigger.net/burp",
        "Tenable, “Nessus vulnerability scanner.” [Online]. Available: https://www.tenable.com/products/nessus",
        "OWASP Foundation, “OWASP Zed Attack Proxy,” OWASP. [Online]. Available: https://www.zaproxy.org/",
        "J. Bau et al., “State of the art: Automated black-box web application vulnerability testing,” in Proc. IEEE Symp. Security and Privacy, 2010, pp. 332–345.",
        "N. Jovanovic, C. Kruegel, and E. Kirda, “Pixy: A static analysis tool for detecting web application vulnerabilities,” in Proc. IEEE Symp. Security and Privacy, 2006, pp. 258–263.",
        "D. Stuttard and M. Pinto, The Web Application Hacker’s Handbook, 2nd ed. Indianapolis, IN, USA: Wiley, 2011.",
        "Mozilla Foundation, “Observatory by Mozilla.” [Online]. Available: https://observatory.mozilla.org/",
        "OWASP Foundation, “OWASP testing guide,” OWASP. [Online]. Available: https://owasp.org/www-project-web-security-testing-guide/",
        "Mozilla, “WebExtensions API documentation.” [Online]. Available: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions",
        "M. Zalewski, “Browser security handbook,” Google Inc., 2008. [Online]. Available: https://code.google.com/archive/p/browsersec/",
    ],
    "tables": [
        {
            "head": "Comparison of representative assessment tools across nine dimensions.",
            "after_section": "Comparison",
            "cols": 4,
            "rows": [
                ["Tool", "Technique", "Position", "Evidence"],
                ["Commercial scanner A", "Dynamic", "Agent / proxy", "Rich"],
                ["Commercial scanner B", "Dynamic", "Agent / proxy", "Rich"],
                ["Open-source scanner A", "Dynamic", "Proxy", "Moderate"],
                ["Open-source scanner B", "Dynamic", "Agent", "Moderate"],
                ["Remote analysis service", "Configuration", "Remote", "Limited"],
                ["Static analysis tool", "Static", "Source", "Rich"],
                ["Passive client scanner", "Configuration", "Browser", "Rich"],
                ["Header linter", "Configuration", "Remote", "Limited"],
            ],
            "footnote": "Evidence denotes whether a finding carries its observed values.",
        }
    ],
}
