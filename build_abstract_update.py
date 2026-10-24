"""
Update the minor-project abstract by editing word/document.xml directly.

The editor_sdk path corrupted the file on save (duplicated paragraphs plus CR
artifacts), so this bypasses it entirely: read the original .docx, rebuild only
word/document.xml, write a new archive. Every other part is copied byte-identical.

Paragraph XML is matched to the document's own idioms, read from the file:
  section heading    : <w:b/><w:bCs/><w:sz w:val="28"/>   (bold, 14pt)
  subsection / body  : <w:sz w:val="28"/>                 (plain, 14pt)
  (w:sz is in half-points, so 28 = 14pt)
"""
import zipfile, shutil, re, os

SRC = r'C:/Users/YASH/Downloads/MINOR PROJECT/Abstract VulnLens Al - Intelligent Assistance for VAPT.docx'
OUT = SRC  # edit in place

RPR_PLAIN = '<w:rPr><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr>'
RPR_BOLD = '<w:rPr><w:b/><w:bCs/><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr>'

_para_id = [0x70000000]

def next_id():
    _para_id[0] += 1
    return '%08X' % _para_id[0]

def esc(s):
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def para(text, bold=False):
    rpr = RPR_BOLD if bold else RPR_PLAIN
    return ('<w:p w14:paraId="%s" w14:textId="77777777">'
            '<w:pPr>%s</w:pPr>'
            '<w:r>%s<w:t xml:space="preserve">%s</w:t></w:r>'
            '</w:p>') % (next_id(), rpr, rpr, esc(text))

# ── content to add: (anchor prefix, [ (text, bold), ... ] ) ──
ADDITIONS = [
    # 3.4 + 3.5 go after the 3.3 body paragraph
    ('To guarantee offline reliability', [
        ('3.4. Quality-Aware Header Analysis', False),
        ('The core technical contribution of VulnLens AI is that it judges the quality of a '
         'security header, not merely its presence. Most scanners ask one binary question: is the '
         'header present? If the answer is yes, the check is marked as passed and nothing further '
         'is inspected. That answer is dangerously incomplete.', False),
        ('Consider a server that returns Content-Security-Policy: default-src * \u2018unsafe-inline\u2019 '
         '\u2018unsafe-eval\u2019. A presence-based scanner reports this site as protected. In reality, '
         'unsafe-inline and unsafe-eval switch back on the exact script-injection paths that CSP '
         'exists to close, and the wildcard source allows content from any origin. The site carries '
         'a CSP and is, in practice, unprotected.', False),
        ('VulnLens AI therefore reads the value of each header and classifies it as absent, weak, '
         'or effective. It flags unsafe directives inside CSP, an HSTS max-age that is too short, '
         'the obsolete ALLOW-FROM directive in X-Frame-Options, any X-Content-Type-Options value '
         'other than nosniff, and the deprecated X-XSS-Protection header. Cookie attributes are '
         'checked one cookie at a time, and a cookie whose name suggests a session or login token '
         'is treated more severely. A wildcard CORS origin combined with credential support is '
         'escalated to the highest severity.', False),
        ('This distinction matters because a weak header can be more dangerous than a missing one. '
         'It creates false confidence: a developer who sees \u201cCSP: present\u201d on a checklist '
         'believes the site is protected and stops looking.', False),
        ('3.5. Optional Cloud Tier with Privacy-Preserving Defaults', False),
        ('The two local tiers are enough for everyday use, and they stay the default because no '
         'scan data ever leaves the machine. For operators who want a richer written analysis and '
         'accept that trade-off, the extension also supports an optional third tier that queries a '
         'cloud-hosted language model. It is strictly opt-in: it remains inactive until an API key '
         'is entered and the provider is explicitly selected, so a default installation stays '
         'fully offline and private.', False),
    ]),
    # 4.5 goes after the 4.4 body paragraph
    ('The extension replaces SQLite with an internal history', [
        ('4.5. Evidence-Preserving Reporting', False),
        ('Automated scanners are often distrusted because they give conclusions without proof. '
         'VulnLens AI avoids this by placing the raw evidence inside the report itself. Every '
         'finding is shown together with the actual response headers that were observed, each '
         'marked as present or absent, along with the capture time and the URL those headers '
         'belong to.', False),
        ('The report also contains a gap-analysis matrix that lists each security control and '
         'states whether it is missing, present but weak, or correctly configured. A reader can '
         'therefore verify every claim instead of trusting the tool\u2019s summary. The output is a '
         'single self-contained HTML file that can be saved as a PDF and shared with a development '
         'team or kept as an audit record.', False),
    ]),
    # D. goes after the 5.C body paragraph
    ('By targeting the cookie scanner to session keywords', [
        ('D. Verification and Correctness Testing', False),
        ('A scanner that reports the wrong thing is worse than no scanner at all, so correctness '
         'was checked with an automated test suite rather than by manual inspection. The suite '
         'contains ninety-eight checks grouped into nine phases, covering header analysis, rule '
         'coverage, local analysis output, risk-label consistency, report generation, packaging '
         'integrity, error classification, and token-budget behaviour.', False),
        ('Two results are worth highlighting. First, a fully hardened set of headers produces zero '
         'findings, which confirms that the scanner does not raise false positives, while a '
         'deliberately weak set produces no spurious missing-header findings, confirming that '
         'quality analysis never collapses back into presence testing. Second, the suite asserts '
         'that the two different authorisation errors returned by the cloud gateway are classified '
         'as different causes, and that a truncated model reply is reported as an exhausted token '
         'budget rather than a vague failure. Each assertion is paired with a simulation of the '
         'incorrect behaviour, so the test fails if the bug is ever reintroduced.', False),
        ('Because the suite runs entirely offline, it is deterministic and can be used in '
         'continuous integration.', False),
    ]),
]

# ── read ──
z = zipfile.ZipFile(SRC)
doc = z.read('word/document.xml').decode('utf-8')

# rename 3.3
before = doc.count('3.3. Two-Tier AI Fallback Model')
doc = doc.replace('3.3. Two-Tier AI Fallback Model', '3.3. Multi-Tier AI Fallback Model')
print('renamed 3.3 : %d occurrence(s)' % before)

# ── insert ──
paras = list(re.finditer(r'<w:p[ >].*?</w:p>', doc, re.S))
print('paragraphs before:', len(paras))

inserted = 0
# work from the LAST anchor to the FIRST so earlier offsets stay valid
for anchor, blocks in reversed(ADDITIONS):
    target = None
    for m in re.finditer(r'<w:p[ >].*?</w:p>', doc, re.S):
        txt = re.sub(r'<[^>]+>', '', m.group(0))
        if txt.startswith(anchor):
            target = m
            break
    if target is None:
        raise SystemExit('ANCHOR NOT FOUND: %r' % anchor[:40])
    payload = ''.join(para(t, b) for t, b in blocks)
    doc = doc[:target.end()] + payload + doc[target.end():]
    inserted += len(blocks)
    print('inserted %2d paras after %r' % (len(blocks), anchor[:44]))

# ── write ──
tmp = SRC + '.tmp'
with zipfile.ZipFile(SRC) as zin, zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename == 'word/document.xml':
            data = doc.encode('utf-8')
        zout.writestr(item, data)
shutil.move(tmp, OUT)

print()
print('paragraphs after :', len(re.findall(r'<w:p[ >]', doc)))
print('CR artifacts     :', doc.count('&#13;'))
print('written          :', OUT)
print('size             :', os.path.getsize(OUT), 'bytes')
