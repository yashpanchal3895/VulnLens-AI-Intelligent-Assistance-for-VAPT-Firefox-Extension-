#!/usr/bin/env python3
"""
Build one IEEE conference paper by CLONING the template's own paragraph XML.

Nothing about formatting is authored here: every paragraph is a deep copy of a
prototype paragraph taken from conference-template-a4.docx, with its runs
replaced by new text. Fonts, sizes, colours, alignment, spacing, indents,
numbering and section geometry are therefore inherited byte-for-byte.
"""
import os
import re
from copy import deepcopy

from docx import Document
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

HERE = os.path.dirname(os.path.abspath(__file__))
TPL = os.path.join(HERE, "template_std.docx")
OUT = r"C:/Users/YASH/Downloads/MINOR PROJECT/VulnLens_AI_IEEE_Paper.docx"

# --------------------------------------------------------------------------
# prototype extraction
# --------------------------------------------------------------------------
doc = Document(TPL)

PROTO = {
    "title":     doc.paragraphs[0]._p,
    "author":    doc.paragraphs[4]._p,
    "abstract":  doc.paragraphs[10]._p,
    "keywords":  doc.paragraphs[11]._p,
    "h1":        doc.paragraphs[12]._p,
    "body":      doc.paragraphs[13]._p,
    "h2":        doc.paragraphs[15]._p,
    "thead":     doc.paragraphs[64]._p,
    "tfoot":     doc.paragraphs[65]._p,
    "ref":       doc.paragraphs[76]._p,
    "h5":        doc.paragraphs[68]._p,   # Acknowledgment / References heading (unnumbered)
}

SECTS = [c for c in doc.element.body.iter() if c.tag == qn("w:sectPr")]
SECT_TITLE, SECT_AUTHOR, _, SECT_BODY, _ = SECTS


def _run_proto(p):
    """First run's rPr in a prototype paragraph (may be None)."""
    for r in p.findall(qn("w:r")):
        rpr = r.find(qn("w:rPr"))
        if rpr is not None:
            return deepcopy(rpr)
        return None
    return None


RUNRPR = {k: _run_proto(v) for k, v in PROTO.items()}


def _mk_run(text, rpr=None, italic=False, sz=None, br_before=False):
    r = OxmlElement("w:r")
    if rpr is not None or italic or sz:
        new = deepcopy(rpr) if rpr is not None else OxmlElement("w:rPr")
        if italic:
            new.append(OxmlElement("w:i"))
            new.append(OxmlElement("w:iCs"))
        if sz:
            e = OxmlElement("w:sz"); e.set(qn("w:val"), str(sz)); new.append(e)
            e = OxmlElement("w:szCs"); e.set(qn("w:val"), str(sz)); new.append(e)
        r.append(new)
    if br_before:
        r.append(OxmlElement("w:br"))
    t = OxmlElement("w:t")
    t.set(qn("xml:space"), "preserve")
    t.text = text
    r.append(t)
    return r


def para(key, text, italic=False):
    """Clone prototype `key`, strip its runs, insert one run with `text`."""
    p = deepcopy(PROTO[key])
    pPr = p.find(qn("w:pPr"))
    for child in list(p):
        if child is not pPr:
            p.remove(child)
    p.append(_mk_run(text, RUNRPR[key], italic=italic))
    return p


def abstract_para(text):
    p = deepcopy(PROTO["abstract"])
    pPr = p.find(qn("w:pPr"))
    ital = deepcopy(RUNRPR["abstract"])  # template's label run is italic
    for child in list(p):
        if child is not pPr:
            p.remove(child)
    p.append(_mk_run("Abstract", ital))
    p.append(_mk_run("\u2014"))
    p.append(_mk_run(text))
    return p


def author_para(lines):
    """lines = [(text, italic), ...] joined with <w:br/>, 9pt as in the template."""
    p = deepcopy(PROTO["author"])
    pPr = p.find(qn("w:pPr"))
    for child in list(p):
        if child is not pPr:
            p.remove(child)
    for i, (text, italic) in enumerate(lines):
        p.append(_mk_run(text, None, italic=italic, sz=18, br_before=(i > 0)))
    return p


def attach_sect(p, sectPr):
    pPr = p.find(qn("w:pPr"))
    pPr.append(deepcopy(sectPr))


# --------------------------------------------------------------------------
# table, built on the template's own tblPr
# --------------------------------------------------------------------------
def data_table(header, rows, widths):
    tbl = OxmlElement("w:tbl")
    tblPr = OxmlElement("w:tblPr")
    for tag, attrs in (
        ("w:tblW", {"w:w": "0", "w:type": "dxa"}),
        ("w:jc", {"w:val": "center"}),
    ):
        e = OxmlElement(tag)
        for k, v in attrs.items():
            e.set(qn(k), v)
        tblPr.append(e)
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        e = OxmlElement("w:" + edge)
        e.set(qn("w:val"), "single")
        e.set(qn("w:sz"), "2")
        e.set(qn("w:space"), "0")
        e.set(qn("w:color"), "auto")
        borders.append(e)
    tblPr.append(borders)
    layout = OxmlElement("w:tblLayout"); layout.set(qn("w:type"), "fixed")
    tblPr.append(layout)
    look = OxmlElement("w:tblLook")
    for k, v in (("w:val", "0000"), ("w:firstRow", "0"), ("w:lastRow", "0"),
                 ("w:firstColumn", "0"), ("w:lastColumn", "0"),
                 ("w:noHBand", "0"), ("w:noVBand", "0")):
        look.set(qn(k), v)
    tblPr.append(look)
    tbl.append(tblPr)

    grid = OxmlElement("w:tblGrid")
    for w in widths:
        g = OxmlElement("w:gridCol"); g.set(qn("w:w"), str(w)); grid.append(g)
    tbl.append(grid)

    for ri, row in enumerate([header] + rows):
        tr = OxmlElement("w:tr")
        trPr = OxmlElement("w:trPr")
        trPr.append(OxmlElement("w:cantSplit"))
        h = OxmlElement("w:trHeight"); h.set(qn("w:val"), "240"); trPr.append(h)
        if ri == 0:
            trPr.append(OxmlElement("w:tblHeader"))
        jc = OxmlElement("w:jc"); jc.set(qn("w:val"), "center"); trPr.append(jc)
        tr.append(trPr)
        for ci, w in enumerate(widths):
            tc = OxmlElement("w:tc")
            tcPr = OxmlElement("w:tcPr")
            tw = OxmlElement("w:tcW"); tw.set(qn("w:w"), str(w)); tw.set(qn("w:type"), "dxa")
            tcPr.append(tw)
            va = OxmlElement("w:vAlign"); va.set(qn("w:val"), "center"); tcPr.append(va)
            tc.append(tcPr)
            p = OxmlElement("w:p")
            pPr = OxmlElement("w:pPr")
            if ri == 0:
                st = OxmlElement("w:pStyle"); st.set(qn("w:val"), "tablecolhead")
                pPr.append(st)
            else:
                rPr = OxmlElement("w:rPr")
                s = OxmlElement("w:sz"); s.set(qn("w:val"), "16"); rPr.append(s)
                s = OxmlElement("w:szCs"); s.set(qn("w:val"), "16"); rPr.append(s)
                pPr.append(rPr)
            p.append(pPr)
            p.append(_mk_run(row[ci] if ci < len(row) else "", None))
            tc.append(p)
            tr.append(tc)
        tbl.append(tr)
    return tbl


# --------------------------------------------------------------------------
# content
# --------------------------------------------------------------------------
TITLE = ("VulnLens AI: Quality-Aware Passive Web Security Assessment with a "
         "Three-Tier AI Explanation Layer")

AUTHORS = [
    [("Yash M. Panchal", False),
     ("Dept. of Computer Science Engineering in Cyber Security", True),
     ("Silver Oak University", True),
     ("Ahmedabad, Gujarat, India", False)],
    [("Umang K. Nagwadiya", False),
     ("Dept. of Computer Science Engineering in Cyber Security", True),
     ("Silver Oak University", True),
     ("Ahmedabad, Gujarat, India", False)],
]

ABSTRACT = (
    "Web applications routinely ship with missing or misconfigured HTTP response headers, yet these "
    "weaknesses remain invisible to the developer browsing the site and to the end user who depends on it. "
    "Existing assessment tooling assumes a server-side position, a paid licence, or expert interpretation of "
    "raw output, and almost all of it evaluates a header by asking only whether it is present. This paper "
    "presents VulnLens AI, a passive, read-only assessment framework implemented as a Firefox WebExtension. "
    "It makes two contributions. First, it performs quality-aware header analysis: instead of recording "
    "presence, it parses directive values and classifies a present header as effective, weak, or obsolete "
    "according to the governing specifications. Second, it pairs a deterministic thirty-one-rule engine with a "
    "three-tier explanation layer in which a cloud model, a locally hosted model, and the rule engine form a "
    "fallback chain, so that an explanation is produced even when no model is reachable. The token budget that "
    "bounds each call is specified explicitly. Ninety-eight regression checks and thirty-seven package-integrity "
    "checks pass, and a live assessment of a production site behind a content delivery network reports twelve "
    "findings at a deterministic score of 28/100."
)

KEYWORDS = ("web security, HTTP security headers, passive vulnerability assessment, browser extension, "
            "large language models, content security policy, VAPT, security misconfiguration")

SECTIONS = [
    ("Introduction", [
        ("", "The security posture of a web application is determined to a large degree by instructions the "
             "server attaches to every response. Headers such as Content-Security-Policy (CSP), "
             "Strict-Transport-Security (HSTS), and X-Frame-Options instruct the browser to enforce protections "
             "that application code cannot reliably provide on its own. When these headers are absent, or present "
             "but configured ineffectively, the application becomes exposed to well-understood classes of attack "
             "including cross-site scripting, protocol downgrade, clickjacking, and referrer leakage."),
        ("", "Despite their importance, header misconfigurations are common and difficult to observe. A developer "
             "browsing a site cannot see its response headers. End users have no indication that a protection is "
             "absent. The operator sees the header name in a configuration file and reasonably assumes it is "
             "working. The gap between deploying a header and deploying an effective header is where a "
             "substantial share of real-world exposure lives."),
        ("", "Existing assessment tooling does not close this gap. Commercial dynamic scanners require an agent, "
             "a proxy position, or a paid licence. Remote analysis services examine a single URL on demand and "
             "report presence. Browser developer tools expose headers but demand that the operator already knows "
             "what a good value looks like."),
        ("", "This paper presents VulnLens AI, a browser-embedded assessment assistant that addresses both "
             "problems. It makes the invisible visible by reading response headers and inspecting the rendered "
             "document from inside the browser, using only what the browser already possesses, and it makes the "
             "result intelligible by pairing a deterministic rule engine with a language-model explanation layer "
             "that degrades gracefully to offline operation."),
        ("", "The remainder of this paper is organised as follows. Section II reviews related work. Section III "
             "states the design goals and the collection architecture. Section IV specifies the quality-aware "
             "header method. Section V describes the three-tier explanation layer and its token budget. Section "
             "VI covers implementation, Section VII reports the evaluation, and Section VIII discusses "
             "limitations before Section IX concludes."),
    ]),
    ("Related Work", [
        ("", "Web security assessment is conventionally divided into vulnerability assessment, which identifies "
             "weaknesses, and penetration testing, which attempts to exploit them. Mature commercial platforms "
             "such as Burp Suite and Nessus perform both well, and academic work on black-box testing established "
             "the methodology that these tools automate [1], [2]. All of them assume that the assessor can send "
             "requests to the target, which in turn assumes an authorisation and a network position that a "
             "casual operator rarely holds."),
        ("", "A second family of tools performs configuration analysis of response headers. Mozilla Observatory "
             "and the OWASP Secure Headers Project are the reference points [3], [4]. Observatory is effective "
             "for a single URL, but it operates as a remote service: the target must be reachable from the "
             "service, and the assessment is a point-in-time snapshot of one response. Header-linting "
             "utilities adopt the same model locally and, like the remote services, reduce a header to a "
             "boolean."),
        ("", "Recent work has applied large language models to security reporting, primarily to translate "
             "technical findings into readable summaries. Chain-of-thought prompting demonstrated that "
             "intermediate reasoning improves structured tasks [5], and the models that expose that reasoning "
             "as a separate stream are directly relevant here, because reasoning tokens are charged against "
             "the output budget. This improves accessibility but introduces a dependency: if the model is "
             "unreachable, the report is unreachable."),
        ("", "The closest published approaches are therefore header-linting utilities and passive browser-based "
             "scanners, and both adopt binary presence testing. This paper argues that the next material "
             "improvement in passive header assessment is not broader coverage but deeper evaluation of the "
             "headers already covered, and that an explanation layer is only trustworthy when it is not the "
             "authority on what was found."),
    ]),
    ("Design Goals and Architecture", [
        ("Design Goals", [
            "Four goals shaped the design. First, the tool must be passive and read-only, so that it can be used "
            "lawfully and safely on any page the operator is authorised to view. Second, it must degrade "
            "gracefully: a failure in any single analysis component must not prevent a result. Third, it must "
            "produce evidence rather than conclusions, so that every finding can be independently verified. "
            "Fourth, it must remain usable without paid infrastructure, which excludes any design that mandates "
            "a hosted service.",
            "These goals impose a constraint that distinguishes the system from server-side scanners: the "
            "extension can only observe what the browser already possesses. It cannot enumerate endpoints, "
            "inspect server-side configuration, or observe responses the browser never requests. This is a real "
            "limitation, and the design is explicit about it rather than compensating with inference.",
        ]),
        ("Two-Path Passive Collection", [
            "Collection proceeds along two independent paths that are subsequently merged. The header path runs "
            "in the background script, where the webRequest interface exposes response headers as they arrive; "
            "these headers are invisible to code running inside the document. The document path runs in a "
            "content script injected into the page, which inspects the rendered document object model after the "
            "document reaches an idle state.",
            "The paths are complementary rather than redundant. The header path observes what the server "
            "declared. The document path observes what the browser actually loaded, including resources "
            "referenced through attributes the header path cannot see and content inserted by script after load.",
        ]),
        ("Merge and Degradation Contract", [
            "The merge procedure concatenates findings from both paths and assigns a single risk score. The "
            "degradation contract states that if either path is unavailable, the assessment proceeds with the "
            "other and the report records which path was unavailable. If both are unavailable, the assessment "
            "returns an explicit failure rather than an empty result, because an empty result is "
            "indistinguishable from a clean one.",
            "A freshness rule guards the header path. Data is keyed by tab identifier, but a tab can navigate "
            "without a document load, which is the normal behaviour of a single-page application. The captured "
            "header set therefore carries the URL it was captured for, and a scan whose URL does not match is "
            "reported as stale rather than silently analysed. Both URLs are normalised to origin and path "
            "before comparison, so that a trailing slash cannot produce a false mismatch.",
        ]),
    ]),
    ("Quality-Aware Header Analysis", [
        ("From Presence to Effectiveness", [
            "Conventional presence testing evaluates a header with a single predicate: is it present? The "
            "approach taken here evaluates the header's value against the semantics defined by its governing "
            "specification. Let H be the set of received headers and h a header of interest. Presence testing "
            "evaluates present(h); this method evaluates effective(h), defined as the conjunction of a syntax "
            "condition, that the value parses under the grammar of the specification, and a semantic condition, "
            "that the parsed directives jointly imply the protection the header is deployed to provide.",
            "The distinction is material. Consider a response carrying a policy whose source list is a wildcard "
            "and which also permits inline script. A presence test reports this as compliant. In reality the "
            "policy re-enables the injection paths that CSP exists to close, and the protection delivered is "
            "close to zero. Each check therefore yields one of four outcomes: absent, effective, weak, or "
            "obsolete, and severity is assigned as a separate function over that outcome.",
        ]),
        ("Check Specification", [
            "Six baseline headers are checked for presence: CSP, X-Frame-Options, HSTS, X-Content-Type-Options, "
            "Referrer-Policy, and Permissions-Policy. Presence, however, is only the first layer.",
            "For CSP the value is parsed into directives and six predicates are evaluated: the presence of "
            "unsafe-inline in a script directive, the presence of unsafe-eval, wildcard sources, plaintext http "
            "sources, the absence of a default-src or script-src fallback, and the absence of object-src or "
            "base-uri, which leaves plugin embedding and base-URL injection unconstrained.",
            "For HSTS the max-age directive is compared against a minimum of fifteen million five hundred and "
            "twenty thousand seconds, a max-age of zero is reported as an explicit opt-out, and the absence of "
            "includeSubDomains is reported where the host serves subdomains. The preload token is reported "
            "informationally, because its effect depends on inclusion in a browser-maintained list rather than "
            "on the response.",
            "For X-Frame-Options the obsolete ALLOW-FROM directive is flagged, since no modern browser honours "
            "it. For X-Content-Type-Options any value other than nosniff is flagged, because only that value "
            "has an effect. X-XSS-Protection is reported as deprecated wherever it appears.",
            "Three further checks examine values that are frequently malformed. Cache-Control is inspected for a "
            "trailing separator, for s-maxage without a companion max-age, and for the contradictory "
            "combination of no-store with public. Each Set-Cookie value is parsed into its attributes, and "
            "HttpOnly, Secure, and SameSite are evaluated independently, with cookie names matching a sensitive "
            "pattern escalated in severity because a session cookie without HttpOnly converts a cross-site "
            "scripting flaw into session theft. Cross-origin policy is inspected for a wildcard origin, and for "
            "the specification-violating combination of a wildcard origin with credential support, which is "
            "reported as a high-severity finding.",
            "Finally, information disclosure is evaluated across the Server and X-Powered-By headers and a list "
            "of framework-specific headers, with a version number in any of them escalated because it can be "
            "matched against published vulnerabilities.",
        ]),
    ]),
    ("Three-Tier Explanation Layer", [
        ("Tier Structure and Fallback", [
            "Once collection completes, the merged findings are passed to an analysis layer offering three tiers "
            "in order of preference. The first tier queries a cloud-hosted model through an OpenAI-compatible "
            "gateway; during evaluation this was deepseek-v4-flash served by AgentRouter. The second tier queries "
            "a model served locally by an Ollama runtime on the loopback interface; the default model identifier "
            "is llama3 and both the host and the identifier are configurable. The third tier is a deterministic "
            "rule engine that encodes thirty-one rules, each pairing a matching pattern with an explanation of "
            "why the weakness matters and a remediation describing how to address it.",
            "The tiers form a fallback chain rather than a selection. If the cloud tier fails for any reason the "
            "local tier is attempted; if that also fails the rule engine produces the analysis. The rule engine "
            "is always available, so a result is always produced.",
            "A consequence worth noting is that analysis quality degrades along a known axis. The rule engine "
            "produces accurate but generic explanations keyed to finding categories. The local model produces "
            "instance-specific prose of uneven quality. The cloud model produces a connected narrative that "
            "relates findings to one another. The axis is narrative coherence, not correctness, and the report "
            "records which tier produced the analysis so that the reader can discount accordingly.",
            "The explanation layer is constrained by four rules that are enforced structurally rather than by "
            "instruction. It may not introduce a finding the deterministic engine did not produce, may not alter "
            "a severity, may not suppress evidence, and may not make a claim about the target that is not "
            "entailed by the evidence supplied to it. The report is assembled from the finding set; the prose is "
            "attached to it. If the model returns nothing, the report is still complete, because the prose was "
            "never load-bearing.",
        ]),
        ("Token Budget Model", [
            "A tool that calls a language model on every scan inherits the cost model of that model, and an "
            "unbounded call is an unbounded liability. Four constants bound the exposure. The ceiling is the "
            "maximum output length the gateway accepts, 393 216 tokens, and a request that exceeds it is "
            "rejected rather than truncated. The scan budget is 4 000 tokens, sized to a full finding set plus "
            "reasoning headroom. The test budget is 512 tokens, sized to a single liveness exchange used for "
            "credential validation. The reasoning reserve is 512 tokens, the length below which a reasoning "
            "model cannot produce an answer at all.",
            "The scan budget is deliberately set far below the ceiling. The ceiling is a limit, not a target: "
            "sizing a request to the ceiling guarantees the slowest and most expensive call the model will "
            "accept, for a task that a small fraction of that length completes. A clamping rule reconciles "
            "configuration with the ceiling, so that a value left over from a different model cannot cause an "
            "opaque rejection; the effective value is clamped at the point of request construction and recorded "
            "alongside the result.",
            "A token budget is not a time budget. A model that generates slowly can exhaust a wall-clock "
            "allowance while consuming a small fraction of its token budget, and a model that generates quickly "
            "can consume the entire token budget in a fraction of the allowance. Latency is therefore bounded "
            "separately, at 180 seconds per call, and a timeout is treated as a failure of the tier rather than "
            "as a truncated result.",
            "Failures are classified into transient and permanent before any retry. A rate limit, a server "
            "error, and a network interruption are transient and are retried up to three times with exponential "
            "backoff, honouring a Retry-After header where present. An authentication failure, an authorisation "
            "failure, and a not-found failure are permanent: retrying them produces the same result at the same "
            "cost, and delays the fallback that would have produced a result.",
        ]),
        ("Streaming and Usage Accounting", [
            "Requests are issued with streaming enabled and with usage reporting requested explicitly. Usage "
            "statistics arrive in a final chunk whose choices array is empty, so a reader that iterates over "
            "chunks and extracts text silently discards them; the implementation reads usage before inspecting "
            "choices. Truncation is detected from the finish reason rather than inferred from the length of the "
            "accumulated text, and both spellings of the truncation reason are accepted, because the gateway "
            "reports the condition differently depending on the upstream path.",
            "Two defects were found and corrected during development. A reasoning model emitted a long internal "
            "deliberation that consumed the output budget before an answer was produced, which was resolved by "
            "raising the scan budget above the reasoning reserve. Separately, the gateway gates its endpoints on "
            "a client fingerprint and rejects requests that do not carry the expected client identifier with an "
            "authorisation error that is indistinguishable from an invalid credential; the two causes are "
            "distinguished by inspecting the response body, so that the operator is directed to the correct "
            "layer rather than to the wrong one.",
        ]),
    ]),
    ("Implementation", [
        ("Header Path", [
            "The extension is a Manifest V3 WebExtension for Firefox, requiring version 109 or later, comprising "
            "a background script, an injected content script, a popup interface, and a report renderer. The "
            "header path registers a listener on response headers for main-frame documents and persists the "
            "captured set in extension storage so that it survives suspension of the background context.",
            "One implementation detail proved significant. Headers that legitimately repeat, most notably "
            "Set-Cookie, must be collapsed into an array rather than assigned to an object key. Naive assignment "
            "overwrites all but the last value, which silently discards every cookie but one and therefore every "
            "attribute defect on the discarded cookies. Entries are also removed when their tab closes, so that "
            "storage does not grow without bound.",
        ]),
        ("Document Path", [
            "The document path performs nine categories of inspection over the rendered document. It records the "
            "transport protocol of the page and of each form, and flags a form that submits over plaintext. It "
            "detects mixed content on a secure page, including resources referenced through srcset attributes, "
            "stylesheet url() expressions, and data attributes, which attribute-only scans miss entirely. It "
            "counts document-object-model sinks such as direct assignment to innerHTML and calls to "
            "insertAdjacentHTML, both in script blocks and in inline event-handler attributes. It counts inline "
            "script blocks and inline handlers, since their presence determines how difficult it would be to "
            "adopt a strict content security policy.",
            "It further matches script sources against a signature list of known-outdated libraries, and scans "
            "page source and comments for credential-shaped strings. It inspects links that open a new browsing "
            "context without an opener restriction, and enumerates API and GraphQL endpoint patterns disclosed "
            "in front-end code. Finally, it fingerprints the technology stack from generator metadata and "
            "framework-specific markers.",
            "Inspection is triggered when the document reaches an idle state and is re-evaluated on mutation, "
            "with debouncing, so that single-page applications are assessed after their dynamic content has "
            "rendered. Debouncing is necessary because an unthrottled observer on a continuously mutating page "
            "would re-scan indefinitely.",
        ]),
        ("Collection Scope and Reporting", [
            "The content script is registered for all HTTP and HTTPS documents and runs in all frames, so that "
            "embedded documents are assessed alongside their parent. The scan request is nevertheless pinned to "
            "the top-level frame: with injection into every frame enabled, an unpinned request fans out to all "
            "of them and resolves with whichever answers first, which can be a frame reporting a different URL "
            "and a different finding set.",
            "The report is a self-contained document that can be exported without network access. It presents a "
            "gap-analysis matrix of required controls against observed state, the findings grouped by severity, "
            "a raw-evidence section listing the actual header values observed with present and absent badges, "
            "and the analysis text labelled with the tier that produced it. Recording the evidence alongside the "
            "prose is what allows a reader who disagrees with the narrative to check it.",
        ]),
    ]),
    ("Evaluation", [
        ("Methodology", [
            "Evaluation proceeded in three parts: a regression suite exercising the analysis logic without "
            "network access, a package-integrity verification, and a live scan of a production site.",
            "The regression suite comprises ninety-eight checks organised into nine phases. The phases exercise "
            "header analysis, rule coverage, analysis generation, risk-label consistency, report structure, "
            "error classification, and the token-budget metadata described in Section V. Negative controls are "
            "included: a fully hardened header set must produce zero findings, and a header set with a single "
            "known weakness must produce exactly one finding of the expected severity.",
            "The integrity verifier operates in two layers. The first validates archive structure, requiring "
            "that the manifest reside at the archive root and that every referenced file resolve within the "
            "archive, with a checksum verified for each. The second performs thirty-seven project-specific "
            "checks covering version consistency, permission hygiene, the presence of the required runtime "
            "files, and the absence of development artefacts from the distributable.",
        ]),
        ("Regression and Integrity Results", [
            "All ninety-eight regression checks passed, as did all thirty-seven integrity checks. Two "
            "properties deserve emphasis because they are easy to get wrong. The suite asserts that the two "
            "distinct authorisation error bodies classify to different causes, so that a client-fingerprint "
            "rejection is not reported as an invalid key. It also asserts that a truncated model response is "
            "diagnosed as truncation in both of the spellings the gateway uses.",
        ]),
        ("Live Case Study", [
            "The system was applied to a production site hosted behind a content delivery network. The document "
            "was 308 218 bytes of markup, retrieved in 7.95 seconds through the extension's own retrying fetch "
            "path, and the header status was reported as current. Twelve findings were reported: none high, four "
            "medium, four low, and four informational, of which eight originated on the header path and four on "
            "the document path.",
            "Findings included the absence of CSP, HSTS, Referrer-Policy, Permissions-Policy, and "
            "Cross-Origin-Opener-Policy; a malformed Cache-Control value containing a trailing separator and no "
            "browser max-age; a framework cache header disclosing internal caching state; seventeen inline "
            "script blocks; and twenty-one links opening a new browsing context without an opener restriction.",
            "The rule engine produced a deterministic score of 28 out of 100, classified as medium, in two to "
            "four milliseconds. The cloud tier produced a score of 42 out of 100, classified as high, in "
            "approximately 11.1 seconds, consuming 192 prompt tokens and 1771 completion tokens. A separate run "
            "consumed 524 prompt tokens and 767 completion tokens, of which 91 were reasoning tokens. The "
            "divergence between the two scores is expected: the tiers assign different severities to the same "
            "observations, and the cloud score drifts between runs because the model is non-deterministic, which "
            "is why the deterministic score is the one reported as the assessment result and the model score is "
            "presented as advisory.",
        ]),
    ]),
    ("Discussion and Limitations", [
        ("", "Three observations follow from the evaluation. First, the quality-aware approach identified "
             "present-but-ineffective configurations that a presence-based scanner would have recorded as "
             "compliant, and it did so without introducing findings on the hardened negative control, because "
             "the predicates are derived from specification text rather than from heuristics about what looks "
             "wrong. Second, the two collection paths are genuinely complementary: the document path found "
             "seventeen inline script blocks and twenty-one opener-less links, neither of which is observable "
             "from response headers, while the header path found five absent baseline headers, which is not "
             "observable from the document. Third, the value of the model tier lies not in detection accuracy, "
             "which the deterministic engine already provides, but in the connective narrative that a "
             "per-finding template cannot produce."),
        ("", "The system has clear boundaries. A clean result indicates the absence of observable "
             "misconfiguration; it does not establish that a site is secure. The extension cannot observe "
             "server-side state, cannot test authentication or authorisation logic, and cannot establish the "
             "behaviour of a browser other than the one performing the assessment. The method evaluates a single "
             "response per document, so headers that differ between the initial navigation and later subresource "
             "requests are sampled only where the browser exposes them."),
        ("", "Responsible use is a design constraint as well as an expectation. Although the tool is passive, "
             "scanning a system without authorisation may contravene terms of service or applicable law. The "
             "implementation records the target and timestamp of every assessment and presents the "
             "authorisation expectation in its interface. Credentials are held in extension storage and are "
             "never written into the exported report."),
    ]),
    ("Conclusion and Future Work", [
        ("", "This paper described VulnLens AI, a passive browser-embedded framework for web security "
             "assessment. Its contribution is twofold: a quality-aware method of header analysis that "
             "distinguishes an effective control from a merely present one, and a three-tier explanation layer "
             "with an explicit token budget that keeps a language model useful without making it authoritative. "
             "Ninety-eight regression checks, thirty-seven integrity checks, and a live assessment of a "
             "production deployment support the claims."),
        ("", "Several directions remain. The most immediate is a remediation generator capable of emitting "
             "deployment-ready configuration for common platforms, building on the static guidance the system "
             "already produces. A second is extending the value-level treatment to the response body, where an "
             "inline-script inventory determines the cost of adopting a strict policy. A third is an adaptive "
             "budget, in which the allowance for a scan is derived from the number and severity of findings "
             "rather than fixed in advance."),
    ]),
]

ACK = ("The authors thank the open-source maintainers of the Firefox WebExtension platform and the developers "
       "of the local inference tooling used during evaluation.")

REFS = [
    "J. Bau et al., \u201cState of the art: Automated black-box web application vulnerability testing,\u201d in Proc. IEEE Symp. Security and Privacy, 2010, pp. 332\u2013345.",
    "D. Stuttard and M. Pinto, The Web Application Hacker\u2019s Handbook, 2nd ed. Indianapolis, IN, USA: Wiley, 2011.",
    "Mozilla Foundation, \u201cObservatory by Mozilla.\u201d [Online]. Available: https://observatory.mozilla.org/",
    "OWASP Foundation, \u201cOWASP secure headers project.\u201d [Online]. Available: https://owasp.org/www-project-secure-headers/",
    "J. Wei et al., \u201cChain-of-thought prompting elicits reasoning in large language models,\u201d in Advances in Neural Information Processing Systems, vol. 35, 2022, pp. 24824\u201324837.",
    "W3C, \u201cContent Security Policy Level 3,\u201d W3C Working Draft. [Online]. Available: https://www.w3.org/TR/CSP3/",
    "Internet Engineering Task Force, \u201cHTTP Strict Transport Security (HSTS),\u201d RFC 6797, Nov. 2012.",
    "Internet Engineering Task Force, \u201cHTTP State Management Mechanism,\u201d RFC 6265, Apr. 2011.",
    "Mozilla, \u201cWebExtensions API documentation.\u201d [Online]. Available: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions",
    "M. Zalewski, \u201cBrowser security handbook,\u201d Google Inc., 2008. [Online]. Available: https://code.google.com/archive/p/browsersec/",
    "PortSwigger, \u201cBurp Suite professional.\u201d [Online]. Available: https://portswigger.net/burp",
    "Tenable, \u201cNessus vulnerability scanner.\u201d [Online]. Available: https://www.tenable.com/products/nessus",
]

TABLE = {
    "head": "Severity distribution and aggregate risk score for the live assessment.",
    "foot": "Weights follow the model in Section V; the aggregate is capped at 100.",
    "header": ["Severity band", "Weight", "Count", "Contribution"],
    "rows": [
        ["High", "10", "0", "0"],
        ["Medium", "5", "4", "20"],
        ["Low", "2", "4", "8"],
        ["Informational", "0", "4", "0"],
        ["Aggregate", "\u2014", "12", "28 / 100 (medium)"],
    ],
    "widths": [1500, 760, 700, 1906],
}


# --------------------------------------------------------------------------
# assemble
# --------------------------------------------------------------------------
def main():
    body = doc.element.body
    for c in list(body):
        body.remove(c)

    p = para("title", TITLE)
    attach_sect(p, SECT_TITLE)
    body.append(p)

    a1 = author_para(AUTHORS[0])
    a2 = author_para(AUTHORS[1])
    # two authors -> two columns. The template's own instructions say to adjust
    # this column count for fewer than six authors; only w:num changes.
    sect_auth = deepcopy(SECT_AUTHOR)
    cols = sect_auth.find(qn("w:cols"))
    if cols is not None:
        cols.set(qn("w:num"), "2")
    attach_sect(a2, sect_auth)            # section break rides on the last author para
    body.append(a1)
    body.append(a2)

    body.append(abstract_para(ABSTRACT))
    body.append(para("keywords", "Keywords\u2014" + KEYWORDS))

    table_done = False
    for heading, blocks in SECTIONS:
        body.append(para("h1", heading))
        for block in blocks:
            if isinstance(block, tuple):
                sub, paras = block
                if sub:
                    body.append(para("h2", sub))
                if isinstance(paras, str):      # ("", "one paragraph")
                    paras = [paras]
                for t in paras:
                    body.append(para("body", t))
            else:
                body.append(para("body", block))
        # place the table at the end of the Evaluation section
        if heading == "Evaluation" and not table_done:
            body.append(para("thead", TABLE["head"]))
            body.append(data_table(TABLE["header"], TABLE["rows"], TABLE["widths"]))
            body.append(para("tfoot", TABLE["foot"]))
            table_done = True

    body.append(para("h5", "Acknowledgment"))
    body.append(para("body", ACK))

    body.append(para("h5", "References"))
    for r in REFS:
        body.append(para("ref", r))

    # final section: the body section geometry, applied to everything above
    body.append(deepcopy(SECT_BODY))

    doc.save(OUT)
    print("saved", OUT, os.path.getsize(OUT), "bytes")


if __name__ == "__main__":
    main()
