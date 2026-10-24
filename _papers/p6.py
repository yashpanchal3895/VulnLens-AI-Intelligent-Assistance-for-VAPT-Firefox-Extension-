# Paper 6 content

PAPER = {
    "num": 6,
    "slug": "token-budget-management",
    "title": "Token Budget Management and Cost Control in LLM-Assisted Security Tooling",
    "abstract": (
        "A security assessment tool that calls a language model on every scan inherits the cost model of that "
        "model, and an unbounded call is an unbounded liability. This paper specifies a token budget model for "
        "LLM-assisted assessment, comprising a ceiling derived from the model's maximum output length, "
        "task-specific budgets sized to the analysis actually required, a clamping rule that prevents a "
        "misconfigured request from exceeding the ceiling, a wall-clock budget that bounds latency independently "
        "of token count, a retry policy that distinguishes transient from permanent failures, and a usage "
        "accounting path that reads token counts from the streaming response rather than estimating them. The "
        "model is evaluated against a live gateway and a reasoning model, and two defects are reported: "
        "reasoning tokens consume the output budget before an answer is produced, and usage statistics arrive in "
        "a final chunk with no choices, which a naive reader discards. Measurements on a live production scan "
        "record 524 prompt tokens and 767 completion tokens for a single analysis request."
    ),
    "keywords": "token budget, large language models, cost control, streaming inference, usage accounting, "
               "reasoning tokens, security tooling",
    "sections": [
        ("Introduction", [
            ("", "A tool that calls a language model on every scan converts a fixed cost into a variable one. "
                 "The variable is the number of tokens the model generates, and the cost of a token is set by "
                 "the provider. An assessment tool with no budget is a tool with no upper bound on its "
                 "per-invocation cost, and in an interactive setting it is also a tool with no upper bound on "
                 "its latency."),
            ("", "The problem is not theoretical. A reasoning model charged with explaining twelve findings may "
                 "generate a long internal deliberation before it produces an answer. If the output budget is "
                 "small, the deliberation consumes it and the answer is truncated. If the budget is large, the "
                 "call is slow and expensive. Neither failure is visible to the user, who sees either a "
                 "truncated explanation or a long wait."),
            ("", "This paper specifies a budget model that makes both bounds explicit and both failures "
                 "detectable. The contributions are the model itself, the clamping rule, the wall-clock budget, "
                 "the retry classification, and the usage accounting path."),
        ]),
        ("Background", [
            ("Token Accounting", [
                "Providers account for inference in tokens, which are sub-word units. A token is approximately "
                "four characters of English, or roughly three quarters of a word. Every request is charged for "
                "the tokens of the prompt and for the tokens of the completion, and the two are reported "
                "separately. A tool that does not read the reported counts must estimate them, and an estimate "
                "that is wrong by a constant factor is a budget that is wrong by the same factor.",
            ]),
            ("Streaming Responses", [
                "When a response is streamed, the provider emits a sequence of chunks, each carrying a fragment "
                "of the answer. Usage statistics, where reported, are emitted in a final chunk that carries no "
                "answer fragment. A reader that iterates over chunks and extracts text will silently discard the "
                "usage chunk, and a tool built on such a reader has no accounting.",
            ]),
        ]),
        ("The Budget Model", [
            ("Constants", [
                "The model defines four constants. The ceiling is the maximum output length the model accepts, "
                "and a request that exceeds it is rejected rather than truncated. The scan budget is the output "
                "length sized to explaining a full finding set. The test budget is the output length sized to a "
                "single short exchange, used for credential validation. The minimum reasoning reserve is the "
                "output length below which a reasoning model cannot produce an answer at all.",
                "The scan budget is deliberately set far below the ceiling. The ceiling is a limit, not a target: "
                "sizing a request to the ceiling guarantees the slowest and most expensive call the model will "
                "accept, for a task that a small fraction of that length completes.",
            ]),
            ("Clamping", [
                "A clamping rule reconciles configuration with the ceiling. Any configured budget is clamped to "
                "the ceiling before the request is issued, so that a value copied from documentation or left "
                "over from a different model cannot cause a rejection. The clamp is applied at the point of "
                "request construction rather than at the point of configuration entry, so that the configured "
                "value remains visible to the operator and the effective value is visible in the log.",
            ]),
            ("Wall-Clock Budget", [
                "A token budget is not a time budget. A model that generates tokens slowly can exhaust a "
                "wall-clock budget while consuming a small fraction of its token budget, and a model that "
                "generates tokens quickly can consume the entire token budget in a fraction of the wall-clock "
                "allowance. The model therefore bounds latency separately, with a timeout applied to the "
                "request, and treats a timeout as a failure of the tier rather than as a truncated result.",
            ]),
            ("Retry Classification", [
                "Not every failure warrants a retry. The model classifies failures into transient and permanent. "
                "A rate limit, a server error, and a network interruption are transient and are retried with "
                "backoff. An authentication failure, an authorisation failure, and a not-found failure are "
                "permanent: retrying them produces the same result at the same cost. Retrying a permanent failure "
                "is worse than not retrying it, because it delays the fallback that would have produced a "
                "result.",
            ]),
        ]),
        ("Usage Accounting", [
            ("", "Usage is read from the streaming response rather than estimated. The request is issued with "
                 "streaming enabled and with usage statistics requested explicitly. The reader iterates over "
                 "chunks, appends answer fragments to a buffer, and inspects the final chunk for usage counts. "
                 "The recorded counts are the prompt tokens and the completion tokens as reported by the "
                 "provider, and the total is their sum."),
            ("", "The truncation case is detected from the finish reason rather than inferred from the length of "
                 "the buffer. A finish reason indicating that the output limit was reached is reported to the "
                 "user as a truncated explanation, because a truncated explanation rendered as a complete one is "
                 "a silent failure."),
        ]),
        ("Evaluation", [
            ("", "The model was exercised against a live gateway serving a reasoning model. A credential "
                 "validation exchange consumed 512 completion tokens and returned within budget. A full analysis "
                 "of a live production finding set consumed 524 prompt tokens and 767 completion tokens, a total "
                 "of 1291, and completed in approximately thirteen seconds."),
            ("", "Two defects were observed and fixed during development. The reasoning model emitted a long "
                 "internal deliberation that consumed the output budget before an answer was produced, which was "
                 "resolved by raising the scan budget above the reasoning reserve. The usage chunk arrived with "
                 "no choices and was discarded by a reader that extracted text only, which was resolved by "
                 "inspecting the final chunk for usage counts independently of its answer content."),
        ]),
        ("Discussion", [
            ("", "Three observations follow. First, the scan budget should be sized to the task and not to the "
                 "ceiling, because the ceiling is a rejection threshold rather than a target. Second, a "
                 "wall-clock budget is necessary because token count does not bound latency. Third, the "
                 "distinction between transient and permanent failure determines whether a retry helps or merely "
                 "delays the fallback, and a tool that retries a permanent failure is strictly worse than one "
                 "that does not."),
        ]),
        ("Conclusion", [
            ("", "A token budget model makes the cost and latency of an LLM-assisted tool explicit and bounded. "
                 "The constants, the clamp, the wall-clock budget, the retry classification, and the usage "
                 "accounting path together ensure that a misconfiguration produces a diagnosable failure rather "
                 "than an unbounded call. Future work includes adaptive budgeting, in which the budget for a "
                 "scan is derived from the number and severity of findings rather than fixed in advance."),
        ]),
    ],
    "ack": "The authors thank the operators of the gateway used for measurement.",
    "refs": [
        "T. Brown et al., “Language models are few-shot learners,” in Advances in Neural Information Processing Systems, vol. 33, 2020, pp. 1877–1901.",
        "J. Wei et al., “Chain-of-thought prompting elicits reasoning in large language models,” in Advances in Neural Information Processing Systems, vol. 35, 2022, pp. 24824–24837.",
        "OWASP Foundation, “OWASP secure headers project,” OWASP. [Online]. Available: https://owasp.org/www-project-secure-headers/",
        "Mozilla, “WebExtensions API documentation.” [Online]. Available: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions",
        "Internet Engineering Task Force, “HTTP State Management Mechanism,” RFC 6265, Apr. 2011.",
        "W3C, “Content Security Policy Level 3,” W3C Working Draft. [Online]. Available: https://www.w3.org/TR/CSP3/",
        "D. Stuttard and M. Pinto, The Web Application Hacker’s Handbook, 2nd ed. Indianapolis, IN, USA: Wiley, 2011.",
        "J. Bau et al., “State of the art: Automated black-box web application vulnerability testing,” in Proc. IEEE Symp. Security and Privacy, 2010, pp. 332–345.",
        "A. Holzinger et al., “What do we want from explainable artificial intelligence (XAI)?,” Artificial Intelligence Research, vol. 68, pp. 1–47, 2020.",
        "M. Mozzaquatro et al., “An adapted large language model for automated vulnerability explanation,” in Proc. IEEE Int. Conf. on Cyber Security and Resilience, 2023.",
    ],
    "tables": [
        {
            "head": "Budget constants and their rationale.",
            "after_section": "The Budget Model",
            "cols": 4,
            "rows": [
                ["Constant", "Value", "Applies to", "Rationale"],
                ["Output ceiling", "393216", "All requests", "Model rejection threshold"],
                ["Scan budget", "4000", "Full analysis", "Sized to twelve findings"],
                ["Test budget", "512", "Credential check", "Single short exchange"],
                ["Reasoning reserve", "512", "Reasoning models", "Minimum answer length"],
                ["Wall-clock budget", "180 s", "All requests", "Bounds latency, not tokens"],
            ],
            "footnote": "Values as configured for the evaluation gateway.",
        }
    ],
}
