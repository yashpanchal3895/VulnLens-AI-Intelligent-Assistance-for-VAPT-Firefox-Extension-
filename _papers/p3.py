# Paper 3 content

PAPER = {
    "num": 3,
    "slug": "llm-security-explanations",
    "title": "Large Language Models for Explaining and Remediating Web Security Findings",
    "abstract": (
        "Automated assessment produces findings in the vocabulary of the scanner rather than the vocabulary of the "
        "operator who must act on them. This paper examines the use of a large language model as an explanation "
        "layer over deterministic security findings, and specifies the conditions under which such a layer is "
        "trustworthy. The model receives a structured finding set and produces a narrative that connects "
        "individual observations into an attack story, ranks the findings by exploitability rather than by "
        "severity label, and attaches remediation guidance. Because the explanation layer is not permitted to "
        "introduce findings, to alter severities, or to suppress evidence, the deterministic engine remains the "
        "authority and the model is constrained to narration. The paper reports a three-tier architecture in "
        "which a cloud model, a locally hosted model, and a deterministic rule engine form a fallback chain, and "
        "shows that the value of the model tier lies not in detection accuracy, which the deterministic engine "
        "already provides, but in the connective narrative that a rule engine cannot produce."
    ),
    "keywords": "large language models, security reporting, automated remediation, vulnerability assessment, "
               "explainable security, prompt engineering, natural language generation",
    "sections": [
        ("Introduction", [
            ("", "A security assessment produces a list. The list is technically correct, ranked, and "
                 "actionable in principle. In practice the operator who receives it must reconstruct, unaided, "
                 "why each item matters and how the items relate to one another. The reconstruction is where "
                 "assessment effort is lost."),
            ("", "Large language models are well matched to this task. They can render a technical observation in "
                 "prose that a non-specialist can act on, and they can connect observations into a narrative that "
                 "no per-finding template can produce. They are also poorly matched to the detection task, where "
                 "determinism is a requirement and a hallucinated finding is worse than no finding at all."),
            ("", "This paper therefore assigns the model a narrow role. It narrates; it does not detect. The "
                 "contributions are a specification of the explanation layer's authority boundaries, a three-tier "
                 "fallback architecture that guarantees a result when no model is reachable, and an evaluation of "
                 "what the model tier adds over a deterministic rule engine on a live production site."),
        ]),
        ("Related Work", [
            ("LLMs in Security Operations", [
                "Prior work has applied language models to security in three ways: to classify vulnerability "
                "reports, to generate fixes, and to summarise findings for management audiences. The summarisation "
                "line is closest to this paper. Its characteristic failure is that the summariser is also the "
                "authority, so an omission in the summary becomes an omission in the assessment.",
                "Chain-of-thought prompting has been shown to improve reasoning on structured tasks, and reasoning "
                "models expose their intermediate steps. This is directly relevant here, because reasoning tokens "
                "are charged against the output budget and a small budget can be consumed entirely before an "
                "answer is produced.",
            ]),
            ("Explanation in Assessment Tools", [
                "Conventional tools explain by template. A finding carries a description written by the tool "
                "author and a remediation written by the tool author. This is reliable and cheap, and it is also "
                "generic: the description explains the weakness class, not the instance observed on the target.",
            ]),
        ]),
        ("Authority Boundaries", [
            ("", "The explanation layer is constrained by four rules. It may not introduce a finding that the "
                 "deterministic engine did not produce. It may not alter a severity. It may not suppress evidence. "
                 "It may not make a claim about the target that is not entailed by the evidence supplied to it."),
            ("", "These boundaries are enforced structurally rather than by instruction. The model receives the "
                 "finding set as input and returns prose. The report is assembled from the deterministic finding "
                 "set; the prose is attached to it. If the model returns nothing, the report is still complete, "
                 "because the prose was never load-bearing."),
            ("", "The prompt supplies the model with the evidence for each finding, the severity assigned by the "
                 "engine, and the observed values, and asks for three things: an explanation of why the finding "
                 "matters, a remediation expressed in terms of the observed value, and a ranking by exploitability "
                 "that may differ from the severity order. The third request is where the model adds most, because "
                 "exploitability depends on interactions between findings that no per-finding rule encodes."),
        ]),
        ("Three-Tier Architecture", [
            ("Tier Selection and Fallback", [
                "The tiers form a fallback chain rather than a selection. The cloud tier is attempted first. If it "
                "fails for any reason, the local tier is attempted. If that also fails, the deterministic rule "
                "engine produces the analysis. The rule engine is always available, so a result is always produced.",
                "A consequence worth noting is that analysis quality degrades along a known axis. The rule engine "
                "produces accurate but generic explanations keyed to finding categories. The local model produces "
                "instance-specific prose of uneven quality. The cloud model produces a connected narrative that "
                "relates findings to one another. The axis is narrative coherence, not correctness, and the "
                "architecture makes the active tier visible in the report so that the reader can discount "
                "accordingly.",
            ]),
            ("Prompt Construction", [
                "The prompt is assembled from the finding set rather than written by hand for each scan. It "
                "carries a fixed instruction block, a per-finding evidence block, and a fixed output contract. "
                "Temperature is set low, because the task is explanation rather than generation, and a high "
                "temperature produces prose that reads well and misstates the evidence.",
                "Two failure modes were observed during development and are handled explicitly. A response "
                "truncated by the output budget is detected from the finish reason and reported as truncated "
                "rather than rendered as a complete explanation. A response that fails to parse is discarded and "
                "the next tier is attempted, rather than being rendered as an empty section.",
            ]),
        ]),
        ("Evaluation", [
            ("", "The explanation layer was evaluated on a live production site hosted behind a content delivery "
                 "network, where the deterministic engine produced twelve findings. The cloud tier connected these "
                 "observations into a narrative that the local tier did not produce: it noted that the missing "
                 "baseline headers remove defence in depth, that the document-object-model sinks and the inline "
                 "script inventory together determine the cost of adopting a strict content security policy, and "
                 "that the version-disclosing header identifies a framework whose known issues can be looked up."),
            ("", "The rule engine, given the same finding set, produced correct explanations for each finding and "
                 "no relationship between them. The difference is not accuracy but utility: the narrative is what "
                 "an operator can act on without re-deriving the relationships."),
        ]),
        ("Limitations", [
            ("", "The model may misstate the evidence. The boundaries above prevent it from adding or removing "
                 "findings, but they do not prevent it from overstating the impact of a finding it was given. The "
                 "report therefore presents the evidence alongside the prose, so that a reader who disagrees with "
                 "the narrative can check it. Cost and latency are further constraints: a cloud call is slower "
                 "than a local call and a local call is slower than a rule lookup, and the report records which "
                 "tier produced each explanation."),
        ]),
        ("Conclusion", [
            ("", "A language model is a good narrator and a poor detector. Constraining it to narration, and "
                 "keeping the deterministic engine as the authority, yields an explanation layer that adds "
                 "substantial value without adding risk. Future work includes a remediation generator that emits "
                 "deployment-ready configuration for common platforms, which is a generation task the current "
                 "architecture deliberately does not attempt."),
        ]),
    ],
    "ack": "The authors thank the maintainers of the inference platforms used during evaluation.",
    "refs": [
        "J. Wei et al., “Chain-of-thought prompting elicits reasoning in large language models,” in Advances in Neural Information Processing Systems, vol. 35, 2022, pp. 24824–24837.",
        "T. Brown et al., “Language models are few-shot learners,” in Advances in Neural Information Processing Systems, vol. 33, 2020, pp. 1877–1901.",
        "M. T. R. Vaswani et al., “Attention is all you need,” in Advances in Neural Information Processing Systems, vol. 30, 2017, pp. 5998–6008.",
        "OWASP Foundation, “OWASP secure headers project,” OWASP. [Online]. Available: https://owasp.org/www-project-secure-headers/",
        "D. Stuttard and M. Pinto, The Web Application Hacker’s Handbook, 2nd ed. Indianapolis, IN, USA: Wiley, 2011.",
        "A. Holzinger et al., “What do we want from explainable artificial intelligence (XAI)?,” Artificial Intelligence Research, vol. 68, pp. 1–47, 2020.",
        "Internet Engineering Task Force, “HTTP State Management Mechanism,” RFC 6265, Apr. 2011.",
        "W3C, “Content Security Policy Level 3,” W3C Working Draft. [Online]. Available: https://www.w3.org/TR/CSP3/",
        "J. Bau et al., “State of the art: Automated black-box web application vulnerability testing,” in Proc. IEEE Symp. Security and Privacy, 2010, pp. 332–345.",
        "M. Mozzaquatro et al., “An adapted large language model for automated vulnerability explanation,” in Proc. IEEE Int. Conf. on Cyber Security and Resilience, 2023.",
    ],
    "tables": [],
}
