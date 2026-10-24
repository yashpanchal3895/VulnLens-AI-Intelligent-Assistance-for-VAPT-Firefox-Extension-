# -*- coding: utf-8 -*-
"""Build the BTech Minor Project report (VulnLens AI) as a .docx following the
GUIDELINES FOR B.TECH PROJECT REPORT PREPARATION (Silver Oak University)."""
import os
from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING, WD_TAB_ALIGNMENT, WD_BREAK
from docx.enum.section import WD_SECTION_START
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

HERE = os.path.dirname(os.path.abspath(__file__))
FIG = os.path.join(HERE, "_figs")
OUT = r"C:\Users\YASH\Downloads\MINOR PROJECT\VulnLens_AI_BTech_Project_Report.docx"

STUDENT1 = "Yash Panchal"
ENROLL1 = "2301030700072"
STUDENT2 = "Umang K. Nagwadiya"
ENROLL2  = "2301030700027"
GUIDE = "Ms. Harshita Makwana"
DEPT = "Department of Computer Engineering"
COLLEGE = "College of Technology"
UNIV = "Silver Oak University, Ahmedabad"
MONTH_YEAR = "October, 2026"
ACADEMIC_YEAR = "2026-2027"
TITLE = "VulnLens AI \u2014 Intelligent Assistance for VAPT"
SUBJECT = "Advanced Programming with Project-I / Minor Project"

# ----------------------------------------------------------------------------
doc = Document()

# Normal style: Times New Roman 12, justified, 1.5 spacing
normal = doc.styles["Normal"]
normal.font.name = "Times New Roman"
normal.font.size = Pt(12)
normal.paragraph_format.line_spacing = 1.5
normal.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
rpr = normal.element.get_or_add_rPr()
rfonts = rpr.find(qn("w:rFonts"))
if rfonts is None:
    rfonts = OxmlElement("w:rFonts"); rpr.append(rfonts)
rfonts.set(qn("w:ascii"), "Times New Roman")
rfonts.set(qn("w:hAnsi"), "Times New Roman")
rfonts.set(qn("w:cs"), "Times New Roman")

for hname, size, caps, before, after in [
    ("Heading 1", 16, True, 12, 6),
    ("Heading 2", 14, True, 10, 4),
    ("Heading 3", 12, False, 8, 3),
]:
    st = doc.styles[hname]
    st.font.name = "Times New Roman"
    st.font.size = Pt(size)
    st.font.bold = True
    st.font.all_caps = caps
    st.paragraph_format.space_before = Pt(before)
    st.paragraph_format.space_after = Pt(after)
    st.paragraph_format.line_spacing = 1.5
    sp = st.element.get_or_add_rPr().get_or_add_rFonts()
    sp.set(qn("w:ascii"), "Times New Roman"); sp.set(qn("w:hAnsi"), "Times New Roman")

# Section margins (first/prelim section)
sec0 = doc.sections[0]
sec0.top_margin = Inches(1); sec0.bottom_margin = Inches(1)
sec0.left_margin = Inches(1.25); sec0.right_margin = Inches(1)

USABLE = Inches(6.25)

# ---- low level helpers -----------------------------------------------------
def para(text="", align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=12, bold=False, italic=False,
         space_after=6, style=None):
    p = doc.add_paragraph(style=style)
    p.alignment = align
    p.paragraph_format.space_after = Pt(space_after)
    if text:
        r = p.add_run(text)
        r.font.size = Pt(size); r.bold = bold; r.italic = italic
        r.font.name = "Times New Roman"
    return p

def bullet(text):
    p = doc.add_paragraph(style="List Bullet")
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.space_after = Pt(3)
    r = p.add_run(text); r.font.size = Pt(12); r.font.name = "Times New Roman"
    return p

def page_field(paragraph):
    run = paragraph.add_run()
    fld1 = OxmlElement("w:fldChar"); fld1.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText"); instr.set(qn("xml:space"), "preserve")
    instr.text = "PAGE"
    fld2 = OxmlElement("w:fldChar"); fld2.set(qn("w:fldCharType"), "end")
    run._r.append(fld1); run._r.append(instr); run._r.append(fld2)
    run.font.name = "Times New Roman"; run.font.size = Pt(10)

def set_page_number(section, fmt, start=None):
    pg = section._sectPr.find(qn("w:pgNumType"))
    if pg is None:
        pg = OxmlElement("w:pgNumType"); section._sectPr.append(pg)
    pg.set(qn("w:fmt"), fmt)
    if start is not None:
        pg.set(qn("w:start"), str(start))
    else:
        pg.attrib.pop(qn("w:start"), None)

def set_footer(section):
    f = section.footer
    f.is_linked_to_previous = False
    p = f.paragraphs[0]
    p.text = ""
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.tab_stops.add_tab_stop(Inches(3.125), WD_TAB_ALIGNMENT.CENTER)
    p.paragraph_format.tab_stops.add_tab_stop(USABLE, WD_TAB_ALIGNMENT.RIGHT)
    r = p.add_run("College of Technology"); r.font.size = Pt(10); r.font.name = "Times New Roman"
    p.add_run("\t")
    page_field(p)
    p.add_run("\t")
    r2 = p.add_run("Silver Oak University"); r2.font.size = Pt(10); r2.font.name = "Times New Roman"

def set_header(section, text):
    h = section.header
    h.is_linked_to_previous = False
    p = h.paragraphs[0]
    p.text = ""
    p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    r = p.add_run(text); r.font.size = Pt(10); r.font.name = "Times New Roman"
    r.italic = True

def heading(text, level=1):
    h = doc.add_heading(text, level=level)
    return h

def add_table(caption, headers, rows, widths=None):
    para(caption, align=WD_ALIGN_PARAGRAPH.CENTER, bold=True, space_after=4)
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    hdr = t.rows[0].cells
    for i, htext in enumerate(headers):
        hdr[i].text = ""
        r = hdr[i].paragraphs[0].add_run(htext)
        r.bold = True; r.font.size = Pt(11); r.font.name = "Times New Roman"
    for row in rows:
        cells = t.add_row().cells
        for i, val in enumerate(row):
            cells[i].text = ""
            r = cells[i].paragraphs[0].add_run(str(val))
            r.font.size = Pt(10); r.font.name = "Times New Roman"
    if widths:
        for i, w in enumerate(widths):
            for row in t.rows:
                row.cells[i].width = Inches(w)
    para("", space_after=8)
    return t

def add_figure(path, caption):
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(6); p.paragraph_format.space_after = Pt(2)
    if os.path.exists(path):
        p.add_run().add_picture(path, width=Inches(6.0))
    cap = doc.add_paragraph(); cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = cap.add_run(caption); r.font.size = Pt(11); r.bold = True; r.font.name = "Times New Roman"
    cap.paragraph_format.space_after = Pt(10)

def title_block(lines, center=True):
    for text, size in lines:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER if center else WD_ALIGN_PARAGRAPH.LEFT
        p.paragraph_format.space_after = Pt(4)
        r = p.add_run(text); r.font.size = Pt(size); r.font.name = "Times New Roman"
        if size >= 16: r.bold = True

# -> footer + roman numbering on prelim section
set_footer(sec0)
set_page_number(sec0, "lowerLetter", 1)

# ===========================================================================
# I. COVER PAGE
# ===========================================================================
title_block([
    (SUBJECT + " REPORT", 16),
    ("", 6),
    ("Entitled", 14,),
    (TITLE, 18),
    ("", 10),
    ("Submitted by", 14),
    (f"{STUDENT1} \u2014 {ENROLL1}", 14),
    (f"{STUDENT2} \u2014 {ENROLL2}", 14),
    ("", 10),
    ("In Partial Fulfillment for the Degree of", 14),
    ("BACHELOR OF TECHNOLOGY", 16),
    ("in", 14),
    ("Computer Engineering", 14),
    ("", 10),
    (DEPT, 16),
    (COLLEGE, 16),
    (UNIV, 16),
    (MONTH_YEAR, 14),
])
doc.add_page_break()

# ===========================================================================
# II. TITLE PAGE (specimen Appendix 1)
# ===========================================================================
title_block([
    (COLLEGE, 16),
    (DEPT, 16),
    ("", 8),
    ("Minor Project Report", 14),
    ("", 4),
    ("Entitled", 13),
    (TITLE, 16),
    ("", 8),
    ("Submitted by", 13),
    (f"{STUDENT1}  (Enrolment No. {ENROLL1})", 13),
    (f"{STUDENT2}  (Enrolment No. {ENROLL2})", 13),
    ("", 8),
    ("In partial fulfillment of the requirement for the award of the degree of", 12),
    ("Bachelor of Technology in Computer Engineering", 13),
    ("", 8),
    ("Under the guidance of", 12),
    (f"{GUIDE} (Internal Guide)", 13),
    ("", 12),
    (f"{DEPT}", 13),
    (f"{COLLEGE}, {UNIV}", 13),
    (ACADEMIC_YEAR, 13),
    (MONTH_YEAR, 13),
])
doc.add_page_break()

# ===========================================================================
# III. INSTITUTE CERTIFICATE (Appendix 2)
# ===========================================================================
heading("CERTIFICATE", level=1)
para("")
para(f"This is to certify that {STUDENT1} (Enrolment No. {ENROLL1}) and {STUDENT2} "
     f"(Enrolment No. {ENROLL2}) have submitted the {SUBJECT} report entitled "
     f"\u201c{TITLE}\u201d in partial fulfillment of the requirement for the award of the "
     f"degree of Bachelor of Technology in Computer Engineering of {UNIV} during the "
     f"academic year {ACADEMIC_YEAR}.")
para("")
para(f"The report embodies the original work done by the students under the supervision of "
     f"{GUIDE} and has not been submitted elsewhere for the award of any degree or diploma.")
para("")
para("")
para("Internal Guide: " + GUIDE, space_after=4)
para("Designation: Assistant Professor", space_after=4)
para(DEPT, space_after=4)
para(COLLEGE, space_after=4)
para(UNIV, space_after=4)
para("")
para("Head of the Department: ____________________", space_after=4)
para("Designation: Professor", space_after=4)
para(DEPT, space_after=4)
para(COLLEGE, space_after=4)
para(UNIV, space_after=4)
doc.add_page_break()

# ===========================================================================
# IV. (Company certificate omitted - college project; declaration follows)
# ===========================================================================
# V. DECLARATION (Appendix 4)
heading("DECLARATION", level=1)
para("")
para(f"We hereby declare that the {SUBJECT} report submitted along with the project entitled "
     f"\u201c{TITLE}\u201d, submitted in partial fulfillment for the Bachelor of Technology in "
     f"Computer Engineering to {UNIV}, is a bonafide record of original work carried out by us "
     f"at the {COLLEGE} under the supervision of {GUIDE}.")
para("We further declare that the report does not contain any material previously submitted for "
     "the award of any degree or diploma in this or any other university. It is also certified "
     "that no part of this report has been copied from any source without proper acknowledgment, "
     "and all referenced materials, figures, and information from other sources have been "
     "appropriately cited in the report.")
para("")
para("")
para(f"{STUDENT1}                                        {STUDENT2}")
para(f"(Enrolment No. {ENROLL1})                       (Enrolment No. {ENROLL2})")
para("")
para("Signature of Student 1: ____________________      Signature of Student 2: ____________________")
doc.add_page_break()

# ===========================================================================
# VI. ACKNOWLEDGEMENT
# ===========================================================================
heading("ACKNOWLEDGEMENT", level=1)
para("")
para(f"We express our sincere gratitude to {GUIDE}, our Internal Guide, for her constant "
     "guidance, valuable suggestions, and encouragement throughout the course of this minor "
     "project. Her insightful feedback helped us refine both the engineering approach and the "
     "clarity of this report.")
para("We also thank the faculty and staff of the Department of Computer Engineering, College of "
     "Technology, Silver Oak University, for providing the infrastructure and academic "
     "environment that made this work possible. Our thanks are due to the open-source community "
     "behind the Mozilla WebExtensions platform, Ollama, and the AgentRouter gateway, whose "
     "documentation and tooling formed the foundation of the implementation.")
para("Finally, we thank our peers and family for their support and patience during the "
     "development and testing cycles of this project.")
doc.add_page_break()

# ===========================================================================
# VII. ABSTRACT
# ===========================================================================
heading("ABSTRACT", level=1)
para("")
para("Web applications are the primary target of modern cyber attacks, yet most successful "
     "breaches begin with mundane configuration mistakes \u2014 a missing Content-Security-Policy, "
     "an exposed API key, or a session cookie without the HttpOnly flag. Existing security tools "
     "are either too heavy for everyday developers, send proprietary code to paid cloud services, "
     "or report only whether a security header is present rather than whether it actually works.")
para("VulnLens AI is a passive Firefox extension (Manifest V3) that scans the active web page for "
     "common web-security weaknesses and produces an AI-explained report with remediation "
     "guidance. Its central contribution is quality-aware header analysis: a header that is "
     "present but ineffective (for example a CSP containing unsafe-inline) is reported as weak, "
     "not compliant. The tool combines a three-tier AI fallback \u2014 cloud (deepseek-v4-flash via "
     "AgentRouter, opt-in), local (Ollama hosting qwen2.5:3b or gemma2:2b), and an offline 31-rule "
     "engine \u2014 so the scan always completes, even fully offline, and always chooses the best "
     "analysis the current conditions allow.")
para("The 98-check regression suite and 37-check archive verifier confirm the implementation, and "
     "a live scan of a production website demonstrates the end-to-end workflow.")
para("")
para("Keywords: VAPT, WebExtension, Content-Security-Policy, quality-aware analysis, large "
     "language model, Ollama, AgentRouter, passive scanning, Firefox, Manifest V3.", bold=False, italic=True)
doc.add_page_break()

# ===========================================================================
# VIII. LIST OF FIGURES
# ===========================================================================
heading("LIST OF FIGURES", level=1)
figs = [
    ("3.1", "Project Schedule (Gantt)"),
    ("4.1", "System Architecture of VulnLens AI"),
    ("5.1", "Scan Data-Flow"),
    ("6.1", "Token Budget Model"),
]
for num, cap in figs:
    para(f"Fig {num}   {cap}", space_after=4, align=WD_ALIGN_PARAGRAPH.LEFT)
doc.add_page_break()

# ===========================================================================
# IX. LIST OF TABLES
# ===========================================================================
heading("LIST OF TABLES", level=1)
tabs = [
    ("1.1", "Comparison of Existing Security Testing Tools"),
    ("2.1", "Technology Stack"),
    ("4.1", "Requirements of the Proposed System"),
    ("4.2", "Modules / Components of the Proposed System"),
    ("6.1", "Live Scan Results \u2014 silveroakuni.ac.in"),
    ("7.1", "Representative Test Cases"),
]
for num, cap in tabs:
    para(f"Table {num}   {cap}", space_after=4, align=WD_ALIGN_PARAGRAPH.LEFT)
doc.add_page_break()

# ===========================================================================
# X. ABBREVIATIONS / NOMENCLATURE
# ===========================================================================
heading("LIST OF SYMBOLS, ABBREVIATIONS AND NOMENCLATURE", level=1)
add_table("Table of Abbreviations", ["Abbreviation", "Meaning"], [
    ["VAPT", "Vulnerability Assessment and Penetration Testing"],
    ["CSP", "Content-Security-Policy"],
    ["HSTS", "HTTP Strict-Transport-Security"],
    ["CORS", "Cross-Origin Resource Sharing"],
    ["SRI", "Subresource Integrity"],
    ["DOM", "Document Object Model"],
    ["XSS", "Cross-Site Scripting"],
    ["MV3", "Manifest Version 3"],
    ["LLM", "Large Language Model"],
    ["SSE", "Server-Sent Events"],
    ["API", "Application Programming Interface"],
    ["URL", "Uniform Resource Locator"],
    ["JSON", "JavaScript Object Notation"],
    ["HTTP", "HyperText Transfer Protocol"],
    ["HTTPS", "HTTP Secure"],
], widths=[1.6, 4.6])
doc.add_page_break()

# ===========================================================================
# XI. TABLE OF CONTENTS
# ===========================================================================
heading("TABLE OF CONTENTS", level=1)
toc = [
    ("Declaration", "i"), ("Acknowledgement", "ii"), ("Abstract", "iii"),
    ("List of Figures", "iv"), ("List of Tables", "v"),
    ("Abbreviations", "vi"), ("Table of Contents", "vii"),
    ("1. Introduction", "1"),
    ("2. Literature Review and Technology", "5"),
    ("3. Project Planning and Management", "9"),
    ("4. System Analysis", "12"),
    ("5. System Design", "17"),
    ("6. Implementation", "21"),
    ("7. Testing", "27"),
    ("8. Conclusion and Discussion", "30"),
    ("References", "34"),
    ("Appendix A \u2014 Glossary and File Manifest", "36"),
]
for name, pg in toc:
    p = doc.add_paragraph(); p.paragraph_format.space_after = Pt(3)
    r = p.add_run(name); r.font.size = Pt(12); r.font.name = "Times New Roman"
    p.add_run("\t\t\t").font.name = "Times New Roman"
    r2 = p.add_run(pg); r2.font.size = Pt(12); r2.font.name = "Times New Roman"
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
doc.add_page_break()

# ===========================================================================
# Helper to start a new chapter section (arabic numbering, per-chapter header)
# ===========================================================================
chapter_idx = [0]
def new_chapter(num, title):
    chapter_idx[0] += 1
    # page break then new section
    pb = doc.add_paragraph(); pb.add_run().add_break(WD_BREAK.PAGE)
    ns = doc.add_section(WD_SECTION_START.NEW_PAGE)
    ns.top_margin = Inches(1); ns.bottom_margin = Inches(1)
    ns.left_margin = Inches(1.25); ns.right_margin = Inches(1)
    set_header(ns, f"Chapter {num}  {title}")
    set_footer(ns)
    if chapter_idx[0] == 1:
        set_page_number(ns, "decimal", 1)
    else:
        set_page_number(ns, "decimal")
    h = doc.add_heading(f"{num}. {title}", level=1)
    return h

# ===========================================================================
# CHAPTER 1 - INTRODUCTION
# ===========================================================================
new_chapter(1, "INTRODUCTION")
heading("1.1 Background and Motivation", level=2)
para("The number of web applications and the value of the data they hold have grown enormously, "
     "and so has the attack surface. The Open Web Application Security Project (OWASP) consistently "
     "lists security misconfiguration and injection among the most common risks. Importantly, most "
     "incidents do not begin with exotic zero-day exploits; they begin with small, silent "
     "configuration mistakes that a developer never notices because the site still appears to work.")
para("A second problem is access. Professional security scanners such as OWASP ZAP and Burp Suite "
     "are powerful but heavy, require trained operators, and produce output that a junior developer "
     "struggles to act on. Cloud-based AI security assistants produce readable summaries but send "
     "the user's code, headers, and cookies to a third party and charge per scan. Simple "
     "browser-extension scanners are free but emit static, text-only warnings with no remediation "
     "and no reasoning.")
heading("1.2 Problem Statement", level=2)
para("There is no lightweight, privacy-respecting, and free tool that (a) runs inside the browser "
     "with zero installation friction, (b) judges the quality of a security control rather than "
     "merely its presence, and (c) explains each finding in plain language with a concrete fix. "
     "This project addresses that gap.")
heading("1.3 Objectives of the Project", level=2)
bullet("Build a passive Firefox extension that scans the active page for security weaknesses without attacking it.")
bullet("Implement quality-aware header analysis that flags weak or misconfigured headers, not only missing ones.")
bullet("Provide a three-tier AI fallback (cloud \u2192 local \u2192 offline) so the scan always completes, even offline.")
bullet("Keep privacy the default: cloud analysis is strictly opt-in and nothing is transmitted without an explicit key.")
bullet("Generate evidence-preserving reports that include the raw observed headers, a gap-analysis matrix, and remediation steps.")
heading("1.4 Scope (What it can and cannot do)", level=2)
para("In scope: passive assessment of HTTP response headers and rendered page content on any "
     "http(s) website; quality-aware classification of headers; DOM checks (mixed content, "
     "DOM-XSS sinks, exposed secrets, cookie flags, SRI, framework disclosure); AI-written "
     "explanations; and an exportable self-contained report.")
para("Out of scope: active exploitation or penetration testing, execution of page JavaScript, "
     "authentication of findings through live attacks, and scanning of browser-protected pages "
     "(about:, file:, and Mozilla-restricted domains) which Firefox prohibits by design.")
heading("1.5 Report Organization", level=2)
para("The remainder of this report is organized as follows. Chapter 2 reviews existing tools and "
     "the technology stack. Chapter 3 covers project planning and scheduling. Chapter 4 analyses "
     "the current system and the requirements of the proposed system. Chapter 5 presents the "
     "design. Chapter 6 describes implementation and the token budget model. Chapter 7 reports "
     "testing. Chapter 8 concludes with limitations and future work.")

# ===========================================================================
# CHAPTER 2 - LITERATURE REVIEW AND TECHNOLOGY
# ===========================================================================
new_chapter(2, "LITERATURE REVIEW AND TECHNOLOGY")
heading("2.1 Existing Security Testing Tools", level=2)
para("We studied five families of tools. OWASP ZAP and Burp Suite are industry-standard active "
     "scanners with deep coverage but heavy interfaces and a steep learning curve. Standard "
     "WebExtension scanners are simple and browser-native but limited to static text and offer no "
     "AI reasoning. Cloud-AI assistants give natural-language summaries at the cost of privacy and "
     "billing. Local LLMs (Ollama) are private and free but smaller in capability than frontier "
     "cloud models.")
heading("2.2 Comparative Study", level=2)
add_table("Table 1.1  Comparison of Existing Security Testing Tools",
          ["Tool / Approach", "Strength", "Weakness"],
          [["OWASP ZAP / Burp Suite", "Deep, industry-standard active scanning", "Heavy, complex, needs trained operator"],
           ["WebExtension scanners", "Simple, runs in browser", "Static text only, no remediation/AI"],
           ["Cloud-AI assistants", "Natural-language summaries", "Privacy trade-off, paid, latency"],
           ["Local LLM (Ollama)", "Private, free, on-device", "Smaller model, needs local RAM/disk"],
           ["VulnLens AI (this work)", "Quality-aware + 3-tier AI, free, private", "Passive only, Firefox-focused"]],
          widths=[1.7, 2.3, 2.2])
heading("2.3 Technology Stack", level=2)
add_table("Table 2.1  Technology Stack",
          ["Layer", "Technology", "Purpose"],
          [["UI / Platform", "HTML5, CSS3, JavaScript ES6+", "Popup, report rendering, logic"],
           ["Browser API", "Gecko WebExtensions, Manifest V3", "tabs, storage, webRequest, downloads"],
           ["Cloud AI", "deepseek-v4-flash via AgentRouter", "Opt-in detailed analysis"],
           ["Local AI", "Ollama (qwen2.5:3b, gemma2:2b)", "Private on-device analysis"],
           ["Offline engine", "local_engine.js (31 rules)", "Instant deterministic fallback"],
           ["Persistence", "browser.storage.local", "Header cache, history, settings"]],
          widths=[1.5, 2.4, 2.3])
heading("2.4 Selection of Technology and Justification", level=2)
para("Manifest V3 on the Gecko (Firefox) platform was selected because it is the current standard, "
     "is natively promise-based (no polyfill), and is freely loadable for testing through "
     "about:debugging. A web-request and content-script architecture was chosen because it can read "
     "both network headers and the live DOM without modifying the page. The three AI tiers were "
     "selected to balance intelligence, privacy, and availability: the cloud model is the smartest "
     "but costs tokens and needs the internet; the local model is private and free; the offline "
     "rule engine is instant and always present.")

# ===========================================================================
# CHAPTER 3 - PROJECT PLANNING
# ===========================================================================
new_chapter(3, "PROJECT PLANNING AND MANAGEMENT")
heading("3.1 Project Summary", level=2)
para("VulnLens AI is a passive, read-only security assistant for web developers and auditors. It "
     "captures real HTTP response headers, inspects the rendered DOM, classifies each security "
     "control as absent / weak / effective, and asks an AI model to explain the findings and "
     "recommend fixes in plain language.")
heading("3.2 Purpose", level=2)
para("The purpose is to lower the barrier to secure coding: to turn a raw security alert into an "
     "actionable, understandable instruction that a developer can apply immediately, without "
     "sending any proprietary data off the device unless they explicitly choose to.")
heading("3.3 Objectives", level=2)
bullet("Deliver a working Firefox extension with a one-click scan.")
bullet("Detect weak headers (e.g., a CSP with unsafe-inline), not only missing ones.")
bullet("Explain each finding and provide a remediation step.")
bullet("Degrade gracefully across cloud, local, and offline tiers.")
heading("3.4 Scope", level=2)
para("See Section 1.4. The project deliberately remains passive and Firefox-focused; an active "
     "testing mode and a Chromium port are identified as future work (Section 8.5).")
heading("3.5 Project Development Approach and Justification", level=2)
para("We adopted an incremental, test-driven approach. Because the rules engine is deterministic, "
     "we built it first and wrapped it with a regression suite, then layered the AI tiers on top. "
     "This ordering guaranteed that a working scan existed from day one and that every later change "
     "could be verified against the 98-check suite before delivery.")
heading("3.6 Effort, Time and Cost Estimation", level=2)
para("The project was completed within a single academic minor-project cycle at zero monetary cost: "
     "the toolchain is free and open-source, the offline and local tiers require no paid API, and "
     "the cloud tier is used only when an opt-in key is supplied. Effort was dominated by the "
     "quality-aware header logic and the token-handling code rather than by infrastructure.")
heading("3.7 Roles and Responsibilities", level=2)
para(f"Both students, {STUDENT1} and {STUDENT2}, shared implementation and testing responsibilities "
     f"equally under the guidance of {GUIDE}, who reviewed the approach and the report at each "
     "internal review.")
heading("3.8 Project Scheduling", level=2)
para("Figure 3.1 shows the Gantt schedule across six weeks, from requirements and design through "
     "implementation, AI integration, and the documentation and review milestones.")
add_figure(os.path.join(FIG, "fig3_1_gantt.png"), "Fig 3.1   Project Schedule (Gantt)")

# ===========================================================================
# CHAPTER 4 - SYSTEM ANALYSIS
# ===========================================================================
new_chapter(4, "SYSTEM ANALYSIS")
heading("4.1 Study of Current System", level=2)
para("The current practice for a typical developer is to open browser developer tools, manually "
     "inspect response headers, and consult online checkers one header at a time. This is slow, "
     "easy to forget, and produces no durable record of what was found.")
heading("4.2 Problems and Weaknesses of Current System", level=2)
bullet("Manual inspection scales poorly and depends on the developer's knowledge.")
bullet("Online checkers report presence/absence only and ignore header quality.")
bullet("Cloud tools leak proprietary code and incur per-scan cost.")
bullet("Findings are not preserved as evidence for later audit.")
heading("4.3 Requirements of the New System", level=2)
add_table("Table 4.1  Requirements of the Proposed System",
          ["Category", "Requirement"],
          [["Functional", "Capture response headers and scan the DOM on the active page"],
           ["Functional", "Classify each control as absent / weak / effective"],
           ["Functional", "Produce an AI explanation and remediation per finding"],
           ["Functional", "Export a self-contained report with raw evidence"],
           ["Non-functional", "Privacy by default; no transmission without opt-in key"],
           ["Non-functional", "Always completes via graceful AI-tier degradation"],
           ["Non-functional", "Sub-5 ms cached response on Scan click"]],
          widths=[1.6, 4.6])
heading("4.4 System Feasibility", level=2)
bullet("Operational: the tool runs in any modern Firefox with no server or database.")
bullet("Technical: the Gecko WebExtensions API exposes exactly the headers and DOM needed.")
bullet("Economic: zero cost; offline and local tiers need no paid subscription.")
heading("4.5 Activities in the Proposed System", level=2)
para("On page load the background script captures headers via webRequest; the content script "
     "pre-scans the DOM and caches the result. On Scan, the popup reads the cache, runs "
     "quality-aware analysis, selects an AI tier, and builds the report.")
heading("4.6 Features of the Proposed System", level=2)
bullet("Quality-aware header analysis (presence + effectiveness).")
bullet("Nine categories of DOM checks inside the page.")
bullet("Three-tier AI with automatic fallback.")
bullet("Evidence-preserving HTML report with a gap-analysis matrix.")
heading("4.7 Modules / Components", level=2)
add_table("Table 4.2  Modules / Components of the Proposed System",
          ["Module", "Responsibility"],
          [["manifest.json", "Extension identity, permissions, MV3 declaration"],
           ["background.js", "Header capture, analysis, AI dispatch, token control"],
           ["content.js", "Passive DOM scan, 9 categories, debounced observer"],
           ["popup.*", "User interface, settings, scan history"],
           ["local_engine.js", "Offline 31-rule knowledge base"],
           ["report.js", "Self-contained HTML report builder"]],
          widths=[1.7, 4.5])
heading("4.8 Selection of Methodology and Justification", level=2)
para("A passive, agent-assisted architecture was chosen over an active scanner because it is safe "
     "to run on any authorized site, requires no special permissions beyond reading the page, and "
     "pairs naturally with an LLM that explains rather than exploits. Figure 4.1 shows the "
     "resulting architecture.")
add_figure(os.path.join(FIG, "fig4_1_arch.png"), "Fig 4.1   System Architecture of VulnLens AI")

# ===========================================================================
# CHAPTER 5 - SYSTEM DESIGN
# ===========================================================================
new_chapter(5, "SYSTEM DESIGN")
heading("5.1 Design Methodology", level=2)
para("The design follows a clear separation between collection (headers vs DOM), analysis "
     "(quality-aware rules), and presentation (report), so each concern can be tested and improved "
     "independently.")
heading("5.2 Architecture / Structure Design", level=2)
para("The system has three execution contexts: the background script (network + orchestration), "
     "the content script (page inspection), and the popup (user interaction). The architecture is "
     "depicted in Figure 4.1 and the per-scan data-flow in Figure 5.1.")
heading("5.3 Scan Data-Flow", level=2)
para("Figure 5.1 traces a scan from page open to report. Headers are captured as they arrive, the "
     "DOM is scanned and cached, and the cached result is read instantly on Scan. Analysis then "
     "selects the best available AI tier and the report is assembled.")
add_figure(os.path.join(FIG, "fig5_1_flow.png"), "Fig 5.1   Scan Data-Flow")
heading("5.4 Input / Output and Interface Design", level=2)
heading("5.4.1 State / Data Flow", level=3)
para("State is held in browser.storage.local: the most recent header set keyed by tab id, "
     "settings, and scan history. A MutationObserver in the content script keeps the DOM scan "
     "fresh for single-page applications without repeated full walks.")
heading("5.4.2 Access Control and Security", level=3)
para("The extension requests only activeTab, scripting, storage, webRequest, and downloads. No "
     "cookies are exported, no file system access is requested, and cloud analysis is strictly "
     "opt-in behind a saved key. All scanning is read-only; the tool never submits forms or "
     "payloads.")

# ===========================================================================
# CHAPTER 6 - IMPLEMENTATION
# ===========================================================================
new_chapter(6, "IMPLEMENTATION")
heading("6.1 Implementation Platform / Environment", level=2)
bullet("Language: JavaScript ES6+, no build step or external dependency.")
bullet("Browser: Firefox 109+ (Manifest V3, Gecko).")
bullet("AI runtimes: AgentRouter gateway (cloud) and Ollama (local).")
bullet("Verification: Node.js for the 98-check suite and 37-check archive verifier.")
heading("6.2 Module Specifications", level=2)
para("background.js exposes analyzeSecurityHeaders(), which parses each header's directive values "
     "and classifies it as absent, weak, or effective. content.js runs nine DOM checks and caches "
     "the result; report.js assembles the self-contained HTML with the raw header block, the "
     "gap-analysis matrix, the findings table, and the AI section.")
heading("6.3 Token Budget Model", level=2)
para("Every cloud call is governed by a token budget. A token is roughly four characters of text; "
     "the model is billed in prompt tokens (input) plus completion tokens (output). The constants "
     "are MAX = 393,216 (gateway ceiling, never exceeded), SCAN = 4,000 (full report), and TEST = "
     "512 (liveness probe). The requested budget is always clamped to the range [1, 393,216], so "
     "no malformed value can be sent. A 180-second wall-clock timeout, which scales with the "
     "token budget, bounds how long a generation may run. Usage is read from the final "
     "empty-choices chunk of the stream, and a finish_reason of max_tokens or length is treated as "
     "budget exhaustion. Figure 6.1 summarizes the model.")
add_figure(os.path.join(FIG, "fig6_1_token.png"), "Fig 6.1   Token Budget Model")
heading("6.4 AI Model Tiers", level=2)
bullet("Tier 1 (cloud, opt-in): deepseek-v4-flash via AgentRouter; detailed explanations.")
bullet("Tier 2 (local): Ollama hosting qwen2.5:3b (recommended) or gemma2:2b; private, free.")
bullet("Tier 3 (offline): local_engine.js with 31 expert rules; instant, deterministic, no network.")
para("Failures always fall downward (cloud \u2192 local \u2192 offline), so a scan never fails to produce a result.")
heading("6.5 Findings / Results", level=2)
para("A live scan of a production website (https://silveroakuni.ac.in) exercised the full pipeline. "
     "Results are summarized in Table 6.1.")
add_table("Table 6.1  Live Scan Results \u2014 silveroakuni.ac.in",
          ["Metric", "Value"],
          [["HTTP status", "200 OK"],
           ["Header-based findings", "8"],
           ["DOM-based findings", "4"],
           ["Total findings", "12"],
           ["Severity split", "0 High / 4 Medium / 4 Low / 4 Info"],
           ["Offline engine risk", "Medium (28/100) in ~4 ms"],
           ["Cloud engine risk", "High (52/100) in ~13.5 s"],
           ["Stack identified", "Next.js behind Cloudflare"]],
          widths=[2.6, 3.6])
heading("6.6 Result Analysis", level=2)
para("The two engines disagree usefully: the offline rule engine scores only what it can prove "
     "mechanically, whereas the cloud model reasons about the combination of weaknesses \u2014 a "
     "missing CSP together with 17 inline scripts is far more dangerous than either alone. The "
     "subtle catches (a Cache-Control trailing comma, an x-nextjs-cache disclosure) illustrate the "
     "value of quality-aware, evidence-backed analysis.")

# ===========================================================================
# CHAPTER 7 - TESTING
# ===========================================================================
new_chapter(7, "TESTING")
heading("7.1 Testing Plan / Strategy", level=2)
para("Testing is continuous and automated. A 98-check regression suite (9 phases) validates the "
     "real source files offline, and a 37-check archive verifier validates the built extension "
     "package (manifest at root, no leaked dev files, CRC integrity). Live scripts additionally "
     "exercise real endpoints and the cloud model.")
heading("7.2 Test Results and Analysis", level=2)
para("The regression suite currently reports 98/98 passing and the archive verifier reports 37/37. "
     "A representative subset of checks is shown in Table 7.1.")
heading("7.2.1 Test Cases", level=3)
add_table("Table 7.1  Representative Test Cases",
          ["Test ID", "Condition", "Expected", "Actual", "Remark"],
          [["PH-01", "CSP with unsafe-inline", "Weak", "Weak", "Quality-aware"],
           ["HD-02", "webRequest headers collapsed", "All Set-Cookie kept", "Array of all", "Multi-value fix"],
           ["AI-03", "No API key", "Offline engine used", "Offline engine", "Graceful fall"],
           ["TK-04", "Request 999999 tokens", "Clamped to 393216", "393216", "Budget clamp"],
           ["TK-05", "Stream finish_reason", "max_tokens detected", "Detected", "Usage from last chunk"],
           ["PK-06", "Archive build", "37 checks pass", "37 pass", "No dev files leaked"]],
          widths=[0.8, 2.2, 1.6, 1.3, 1.3])

# ===========================================================================
# CHAPTER 8 - CONCLUSION
# ===========================================================================
new_chapter(8, "CONCLUSION AND DISCUSSION")
heading("8.1 Overall Analysis", level=2)
para("VulnLens AI demonstrates that a useful, honest security assistant need not be heavy, "
     "expensive, or invasive. Quality-aware header analysis combined with a three-tier AI fallback "
     "ensures the tool always returns the best analysis the current conditions allow, while the "
     "conservative token model keeps it affordable for daily use.")
heading("8.2 Continuous Evaluation", level=2)
para("The work was reviewed at internal Review 1 (scope, objectives, and architecture) and "
     "continued to Review 2 (implementation and verification). Both reviews confirmed the "
     "approach and the test evidence.")
heading("8.3 Problems Encountered and Solutions", level=2)
bullet("401 \u201cunauthorized client detected\u201d on the cloud gateway was traced to a missing client-fingerprint User-Agent; adding it returns HTTP 200.")
bullet("Repeated Set-Cookie headers overwrote each other until onHeadersReceived was changed to store multi-value headers as arrays.")
bullet("Rule ordering mattered: the specific weak_csp rule must precede the generic missing_csp rule, or weak headers are misclassified.")
bullet("Token usage counts were invisible until stream_options.include_usage was enabled and usage was read from the final empty-choices chunk.")
heading("8.4 Summary of Project Work", level=2)
para("A passive Firefox extension was designed, implemented, and verified. It captures headers and "
     "DOM, performs quality-aware analysis, explains findings through a three-tier AI, and emits an "
     "evidence-preserving report. All objectives in Section 1.3 were met, with a 98/98 regression "
     "suite and a 37/37 archive check confirming correctness.")
heading("8.5 Limitation and Future Enhancement", level=2)
bullet("Limitation: passive only \u2014 it reports risk indicators, not confirmed exploitable breaches.")
bullet("Limitation: Firefox-focused; a Chromium port would need a namespace adaptation.")
bullet("Future: an authorized active-testing mode to prove findings.")
bullet("Future: CI integration to fail a build on new High findings.")
bullet("Future: historical risk tracking across repeated scans.")

# ===========================================================================
# REFERENCES
# ===========================================================================
pb = doc.add_paragraph(); pb.add_run().add_break(WD_BREAK.PAGE)
ref_sec = doc.sections[-1]
ref_sec.top_margin = Inches(1); ref_sec.bottom_margin = Inches(1)
ref_sec.left_margin = Inches(1.25); ref_sec.right_margin = Inches(1)
set_header(ref_sec, "References")
set_footer(ref_sec)
set_page_number(ref_sec, "decimal")
heading("REFERENCES", level=1)
refs = [
    "Mozilla Developer Network (MDN), WebExtensions API documentation, developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions.",
    "Ollama, Local LLM Chat Completion API documentation, github.com/ollama/ollama/blob/main/docs/api.md.",
    "OWASP Foundation, OWASP Top 10 Web Application Security Risks and Secure Headers Project, owasp.org.",
    "W3C, Content Security Policy Level 3, w3.org/TR/CSP3/.",
    "IETF, HTTP Strict Transport Security (HSTS), RFC 6797 (2012); HTTP State Management Mechanism, RFC 6265 (2011).",
    "AgentRouter, LLM Gateway (deepseek-v4-flash), agentrouter.org.",
    "PortSwigger, Burp Suite Professional, portswigger.net/burp; Tenable, Nessus; Mozilla Observatory, observatory.mozilla.org.",
    "J. Wei et al., \u201cChain-of-thought prompting elicits reasoning in large language models,\u201d NeurIPS 35, pp. 24824\u201324837, 2022.",
    "D. Stuttard and M. Pinto, The Web Application Hacker\u2019s Handbook, 2nd ed., Wiley, 2011.",
]
for i, r in enumerate(refs, 1):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.3)
    p.paragraph_format.first_line_indent = Inches(-0.3)
    p.paragraph_format.space_after = Pt(6)
    run = p.add_run(f"[{i}] {r}")
    run.font.size = Pt(11); run.font.name = "Times New Roman"

# ===========================================================================
# APPENDIX A
# ===========================================================================
doc.add_page_break()
heading("APPENDIX A \u2014 GLOSSARY AND FILE MANIFEST", level=1)
heading("A.1 Glossary", level=2)
for term, mean in [
    ("VAPT", "Vulnerability Assessment and Penetration Testing."),
    ("CSP", "Content-Security-Policy; tells the browser which scripts may run."),
    ("HSTS", "Forces use of the secure HTTPS version of a site."),
    ("Mixed content", "A secure page that loads a sub-resource over plain HTTP."),
    ("LLM", "Large Language Model; an AI trained to read and write text."),
    ("Token", "Unit of text an AI bills by; roughly 4 characters."),
    ("max_tokens", "Maximum length the model may generate."),
    ("Graceful degradation", "Falling back to a working option instead of failing."),
]:
    p = doc.add_paragraph(style="List Bullet")
    r = p.add_run(f"{term} \u2014 {mean}"); r.font.size = Pt(11); r.font.name = "Times New Roman"

heading("A.2 File Manifest (Runtime Package)", level=2)
add_table("Runtime Files",
          ["File", "Role"],
          [["manifest.json", "Identity, permissions, MV3"],
           ["background.js", "Header capture, analysis, AI dispatch"],
           ["local_engine.js", "Offline 31-rule engine"],
           ["content.js", "DOM scan, 9 categories"],
           ["popup.html / .js / .css", "User interface"],
           ["report.js", "HTML report builder"],
           ["report_viewer.html / .js", "Report viewer"],
           ["icons/icon16/48/128.png", "Toolbar icons"]],
          widths=[2.6, 3.6])

# ---------------------------------------------------------------------------
os.makedirs(os.path.dirname(OUT), exist_ok=True)
doc.save(OUT)
print("SAVED:", OUT)
