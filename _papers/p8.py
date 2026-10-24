# Paper 8 content

PAPER = {
    "num": 8,
    "slug": "weighted-severity-risk-model",
    "title": "A Weighted Severity Model for Scoring Web Application Security Findings",
    "abstract": (
        "An assessment that reports findings without a score leaves the operator to construct an ordering from "
        "severity labels alone, and a count of findings is a poor proxy for exposure because severities are not "
        "commensurable. This paper specifies a weighted severity model in which each finding contributes a weight "
        "determined by its severity band, the aggregate is capped, and the capped aggregate maps to a small set "
        "of named risk levels. Weights of ten, five, two, and zero are assigned to high, medium, low, and "
        "informational severities, and the aggregate is capped at one hundred. The model is deterministic, "
        "order-independent, and monotone in each finding, and it is designed so that the addition of an "
        "informational finding never changes the level. The paper reports a consistency requirement that the "
        "level labels remain identical across every component of the tool that displays them, and the regression "
        "assertions that enforce it."
    ),
    "keywords": "risk scoring, severity weighting, vulnerability assessment, security metrics, risk "
               "quantification, aggregate scoring",
    "sections": [
        ("Introduction", [
            ("", "A security assessment produces a list of findings. The operator needs an ordering, and the "
                 "ordering must be derivable from the report rather than from the operator's judgement, because "
                 "the operator's judgement is the resource the report exists to conserve."),
            ("", "Severity labels supply a partial order. They do not supply a magnitude: ten low-severity "
                 "findings and two medium-severity findings have no natural comparison, and a count of findings "
                 "conflates a single high-severity issue with a dozen informational ones. A score is needed, and "
                 "the score must have properties that can be stated and tested."),
            ("", "This paper specifies a weighted severity model with four stated properties, a capping rule, and "
                 "a small set of named levels. The contributions are the model, the property set, and the "
                 "consistency requirement that level labels be identical across every surface that displays "
                 "them."),
        ]),
        ("Related Work", [
            ("Existing Scoring Schemes", [
                "Established schemes score a single finding rather than an assessment. The Common Vulnerability "
                 "Scoring System produces a value from exploitability, impact, and environmental metrics, and is "
                 "designed for a published vulnerability with a known description rather than for an observed "
                 "configuration weakness on a specific host.",
                "Commercial scanners typically report a count per severity band and a letter grade derived from "
                 "it. The derivation is rarely published, which makes the grade uninterpretable and the ordering "
                 "between two assessments unverifiable.",
            ]),
            ("Requirements for an Assessment-Level Score", [
                "An assessment-level score has requirements that a single-finding score does not. It must be "
                 "deterministic, so that the same finding set always yields the same score. It must be "
                 "order-independent, so that the order in which findings are collected cannot affect it. It must "
                 "be monotone, so that adding a finding never lowers the score. And it must be bounded, so that "
                 "a large finding set cannot produce an unbounded value.",
            ]),
        ]),
        ("The Model", [
            ("Weights and Aggregation", [
                "Each finding carries a severity in one of four bands: high, medium, low, and informational. The "
                "bands are assigned weights of ten, five, two, and zero respectively. The aggregate score is the "
                 "sum of the weights of all findings, capped at one hundred.",
                "The weight gap between adjacent bands is a factor between two and five, and the gap between "
                 "high and informational is unbounded in effect because the informational weight is zero. The "
                 "cap exists because a sum of uncapped weights grows without bound as findings are added, and a "
                 "score that a reader cannot interpret is worse than no score.",
            ]),
            ("Level Mapping", [
                "The capped aggregate maps to five named levels. A score of zero maps to the level indicating no "
                 "observable findings. Scores below fifteen map to a low level. Scores below forty map to a "
                 "medium level. Scores below sixty map to a high level. Scores of sixty and above map to the "
                 "highest level.",
                "The thresholds are chosen so that the levels are reachable and distinguishable. A single "
                 "high-severity finding reaches the low level and does not reach the medium level, which "
                 "reflects the judgement that one serious weakness warrants attention but not alarm. Two "
                 "high-severity findings, or one high and two medium, reach the medium level. Four "
                 "high-severity findings reach the high level.",
            ]),
            ("Properties", [
                "The model satisfies four properties by construction. Determinism: the score is a function of the "
                 "finding set. Order-independence: the score is a sum. Monotonicity: every weight is "
                 "non-negative, so adding a finding cannot lower the score. Boundedness: the cap bounds the "
                 "score at one hundred.",
                "A fifth property follows from the zero weight assigned to informational findings: adding an "
                 "informational finding never changes the level. This is deliberate, because a report that "
                 "escalates on the addition of an informational item trains the operator to disregard the level.",
            ]),
        ]),
        ("Consistency Across Surfaces", [
            ("", "A score is only as useful as the surfaces that display it. The model therefore imposes a "
                 "consistency requirement: the level labels and their thresholds must be identical in the "
                 "extension interface, in the offline rule engine, and in the exported report. A tool that "
                 "reports a medium level in its interface and a high level in its report for the same finding set "
                 "is worse than a tool with no levels, because the discrepancy destroys trust in both."),
            ("", "The requirement is enforced by regression assertions that evaluate the mapping at the threshold "
                 "boundaries and at the cap, in every component that defines it. The assertions are part of the "
                 "same suite that exercises the analysis logic, so a change to the thresholds in one component "
                 "fails the suite rather than shipping silently."),
        ]),
        ("Evaluation", [
            ("", "The model was exercised by the regression suite, which includes assertions at each threshold "
                 "boundary, at the cap, and for the monotonicity and order-independence properties. The live case "
                 "study produced a capped aggregate in the medium band for the local rule engine and in the high "
                 "band for the cloud tier, on the same finding set."),
            ("", "The divergence between the two tiers on the same finding set is the expected consequence of "
                 "the tiers assigning different severities to the same observations, and it is reported rather "
                 "than reconciled, because reconciling it would require the cloud tier to be constrained by the "
                 "rule engine's severity assignments, which is the boundary the architecture deliberately "
                 "maintains."),
        ]),
        ("Limitations", [
            ("", "The model aggregates severities and ignores exploitability, exposure, and asset value, all of "
                 "which an operator would weigh. It is a summary of what was found, not a prediction of what "
                 "would happen. The weights are ordinal rather than cardinal: the choice of ten, five, and two "
                 "is a judgement, and a different choice would produce different level boundaries without "
                 "producing a different ordering."),
        ]),
        ("Conclusion", [
            ("", "A weighted severity model with a cap and a small set of named levels gives an operator an "
                 "ordering that is deterministic, bounded, and testable. The consistency requirement, enforced by "
                 "regression assertions across every surface that displays a level, is what makes the score "
                 "trustworthy. Future work includes an environmental modifier that allows the operator to weight "
                 "findings by the sensitivity of the host on which they were observed."),
        ]),
    ],
    "ack": "The authors thank the operators of the site used as the live case study.",
    "refs": [
        "FIRST, “Common Vulnerability Scoring System version 3.1: Specification document,” Forum of Incident Response and Security Teams, 2019.",
        "OWASP Foundation, “OWASP risk rating methodology,” OWASP. [Online]. Available: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology",
        "D. Stuttard and M. Pinto, The Web Application Hacker’s Handbook, 2nd ed. Indianapolis, IN, USA: Wiley, 2011.",
        "OWASP Foundation, “OWASP secure headers project,” OWASP. [Online]. Available: https://owasp.org/www-project-secure-headers/",
        "W3C, “Content Security Policy Level 3,” W3C Working Draft. [Online]. Available: https://www.w3.org/TR/CSP3/",
        "Internet Engineering Task Force, “HTTP Strict Transport Security (HSTS),” RFC 6797, Nov. 2012.",
        "J. Bau et al., “State of the art: Automated black-box web application vulnerability testing,” in Proc. IEEE Symp. Security and Privacy, 2010, pp. 332–345.",
        "Mozilla, “WebExtensions API documentation.” [Online]. Available: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions",
        "N. Jovanovic, C. Kruegel, and E. Kirda, “Pixy: A static analysis tool for detecting web application vulnerabilities,” in Proc. IEEE Symp. Security and Privacy, 2006, pp. 258–263.",
        "M. Zalewski, “Browser security handbook,” Google Inc., 2008. [Online]. Available: https://code.google.com/archive/p/browsersec/",
    ],
    "tables": [
        {
            "head": "Severity weights and level thresholds.",
            "after_section": "The Model",
            "cols": 4,
            "rows": [
                ["Severity", "Weight", "Level", "Score range"],
                ["High", "10", "None", "0"],
                ["Medium", "5", "Low", "1–14"],
                ["Low", "2", "Medium", "15–39"],
                ["Informational", "0", "High", "40–59"],
                ["Capped aggregate", "≤100", "Critical", "≥60"],
            ],
            "footnote": "The aggregate is capped at 100.",
        }
    ],
}
