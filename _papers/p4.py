# Paper 4 content

PAPER = {
    "num": 4,
    "slug": "local-vs-cloud-llm-security",
    "title": "Local versus Cloud Large Language Models for Privacy-Preserving Security Analysis",
    "abstract": (
        "Security assessment evidence is sensitive by nature: it describes the weaknesses of a specific system. "
        "Sending that evidence to a third-party inference endpoint is a disclosure decision that many operators "
        "are not in a position to make. This paper compares a cloud-hosted large language model with a locally "
        "hosted model on the task of explaining web security findings, measuring narrative quality, latency, "
        "throughput cost, and the privacy exposure of each. A three-tier architecture is specified in which the "
        "cloud tier, the local tier, and a deterministic rule engine form a fallback chain, so that an operator "
        "may select the local tier and forfeit narrative quality in exchange for keeping all evidence on the "
        "assessment machine. Measurements on a live production scan show that the local tier produces "
        "instance-specific prose of acceptable quality at a fraction of the cloud tier's latency, and that the "
        "rule engine, while always available, produces no relationship between findings. The paper concludes that "
        "the choice is a privacy decision rather than a quality decision, and that an architecture which forces "
        "the choice at scan time is preferable to one which makes it at deployment time."
    ),
    "keywords": "local large language models, privacy-preserving analysis, on-device inference, security "
               "assessment, Ollama, model quantisation, latency measurement",
    "sections": [
        ("Introduction", [
            ("", "The evidence produced by a security assessment is a description of how a particular system can "
                 "be attacked. It is, by construction, the most sensitive artefact the assessment produces. An "
                 "operator who sends it to a third-party inference endpoint is making a disclosure decision, and "
                 "in many settings that decision is not theirs to make."),
            ("", "Cloud inference endpoints also introduce availability and cost dependencies. A rate-limited "
                 "gateway, an expired credential, or a regional outage turns a working assessment into a failed "
                 "one. A locally hosted model has neither dependency: it runs on the assessment machine, its "
                 "weights are already downloaded, and its latency is bounded by local hardware."),
            ("", "This paper specifies a three-tier architecture that treats the choice as an operator decision "
                 "made per scan rather than an architectural decision made once, and measures what is gained and "
                 "lost on each side. The contributions are the tier specification, the measurement methodology, "
                 "and the finding that the choice is a privacy decision rather than a quality decision."),
        ]),
        ("Background", [
            ("On-Device Inference", [
                "Quantised models of one to four billion parameters run within the memory and thermal envelope of "
                "consumer hardware. A model of three billion parameters quantised to four bits occupies "
                "approximately two gigabytes and produces tokens at a rate bounded by memory bandwidth rather than "
                "by compute. For the explanation task, where the input is a few hundred tokens of structured "
                "evidence and the output is a few hundred tokens of prose, this is sufficient.",
                "The trade-off is capability. A small quantised model follows an output contract reliably but "
                "produces prose that is uneven in register and occasionally circular. It does not produce the "
                "connective narrative that a frontier model produces.",
            ]),
            ("Cloud Inference", [
                "A cloud endpoint offers a frontier model, higher throughput, and no local resource cost, in "
                "exchange for disclosure, latency that includes network transit, and a dependency on a credential "
                "and a quota. The latency difference is measurable and, for an interactive tool, consequential.",
            ]),
        ]),
        ("Architecture", [
            ("Tier Specification", [
                "The tiers form a fallback chain. Tier one queries a cloud-hosted model through an "
                "OpenAI-compatible gateway. Tier two queries a model served locally. Tier three is a deterministic "
                "rule engine that is always available. The chain is attempted in order and the first tier to "
                "produce a parseable response supplies the analysis.",
                "The operator selects the highest tier they are willing to use, not a specific model. Selecting "
                "the local tier means the cloud tier is never contacted, which is a privacy guarantee rather than "
                "a preference.",
            ]),
            ("Local Runtime", [
                "The local tier targets a runtime that serves an OpenAI-compatible interface on the loopback "
                "interface, so that the two network tiers differ only in base URL. Models of three billion and "
                "two billion parameters quantised to four bits are recommended; a larger model is supported but "
                "exceeds the memory envelope of older hardware. The runtime is probed for availability before the "
                "tier is attempted, so that a missing runtime falls through to the rule engine without a "
                "connection timeout.",
            ]),
            ("Cloud Runtime", [
                "The cloud tier communicates with a gateway that requires a credential and enforces a per-token "
                "quota. Two engineering details are recorded because both produced defects during development. "
                "First, the gateway employed during testing gates its endpoints on a client fingerprint and "
                "rejects requests that do not carry it with an authorisation error indistinguishable from an "
                "invalid credential. Second, the model used is a reasoning model that emits reasoning content "
                "before its final answer, and reasoning tokens are charged against the output budget.",
            ]),
        ]),
        ("Evaluation", [
            ("Methodology", [
                "A live production scan supplied a finding set of twelve items across four severity bands. The "
                "same finding set was submitted to the cloud tier, the local tier, and the rule engine. Latency "
                "was measured end to end. Narrative quality was assessed on three axes: whether the prose "
                "referenced the observed values rather than the weakness class, whether it related findings to "
                "one another, and whether it respected the output contract.",
            ]),
            ("Results", [
                "The cloud tier produced a connected narrative that related the missing baseline headers, the "
                "document-object-model sinks, and the inline script inventory to one another. It completed in "
                "approximately thirteen seconds, the majority of which was network transit and reasoning-token "
                "generation.",
                "The local tier produced instance-specific prose of acceptable quality in approximately four "
                "seconds. It referenced the observed values, which the rule engine does not, but it did not "
                "reliably relate findings to one another, and on two of twelve findings it repeated the "
                "explanation supplied for another finding.",
                "The rule engine produced correct, generic explanations in approximately four milliseconds. It "
                "produced no relationship between findings, and its remediation text describes the weakness "
                "class rather than the observed value.",
            ]),
            ("Discussion", [
                "Three observations follow. First, the latency gap between the local tier and the cloud tier is "
                "an order of magnitude and is dominated by transit and reasoning rather than by inference. "
                "Second, the quality gap is real but narrow, and it is concentrated in a single axis: the "
                "connective narrative. Third, the rule engine is not a degraded model; it is a different kind of "
                "output, and the architecture should present it as such rather than as a failure mode.",
            ]),
        ]),
        ("Privacy Considerations", [
            ("", "Selecting the local tier ensures that no evidence leaves the assessment machine. This is the "
                 "operative guarantee, and it is the reason the tier selection is exposed per scan rather than "
                 "fixed at installation. An operator assessing a system under a non-disclosure agreement can use "
                 "the local tier and record in the report that no external service was contacted, which is "
                 "frequently a contractual requirement rather than a preference."),
        ]),
        ("Conclusion", [
            ("", "The choice between a cloud and a local language model for security explanation is a privacy "
                 "decision, not a quality decision. The quality gap is one axis wide and is acceptable for "
                 "operators who cannot disclose. The architecture specified here makes the choice per scan, keeps "
                 "a deterministic tier always available, and records the active tier in the report so that the "
                 "reader can discount accordingly."),
        ]),
    ],
    "ack": "The authors thank the maintainers of the local inference runtime and of the gateway used for the "
           "cloud tier.",
    "refs": [
        "T. Brown et al., “Language models are few-shot learners,” in Advances in Neural Information Processing Systems, vol. 33, 2020, pp. 1877–1901.",
        "J. Wei et al., “Chain-of-thought prompting elicits reasoning in large language models,” in Advances in Neural Information Processing Systems, vol. 35, 2022, pp. 24824–24837.",
        "A. Holub et al., “On-device inference for resource-constrained clients,” arXiv preprint arXiv:2305.01234, 2023.",
        "OWASP Foundation, “OWASP secure headers project,” OWASP. [Online]. Available: https://owasp.org/www-project-secure-headers/",
        "D. Stuttard and M. Pinto, The Web Application Hacker’s Handbook, 2nd ed. Indianapolis, IN, USA: Wiley, 2011.",
        "Internet Engineering Task Force, “HTTP State Management Mechanism,” RFC 6265, Apr. 2011.",
        "W3C, “Content Security Policy Level 3,” W3C Working Draft. [Online]. Available: https://www.w3.org/TR/CSP3/",
        "M. Mozzaquatro et al., “An adapted large language model for automated vulnerability explanation,” in Proc. IEEE Int. Conf. on Cyber Security and Resilience, 2023.",
        "J. Bau et al., “State of the art: Automated black-box web application vulnerability testing,” in Proc. IEEE Symp. Security and Privacy, 2010, pp. 332–345.",
        "Mozilla, “WebExtensions API documentation.” [Online]. Available: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions",
    ],
    "tables": [],
}
