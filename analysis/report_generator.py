"""
report_generator.py
Builds a PDF assessment report from the ranked scan findings.

There is no GUI code in this module, so the same function can be called from
the results screen or, later, from a command-line run.
"""
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from analysis.risk_scorer import RISK_ORDER, rank_findings, risk_label

NVD_URL = "https://nvd.nist.gov/vuln/detail/"
LOW_CONFIDENCE = "Name only"

NAVY = (31, 58, 95)
TEXT = (27, 39, 51)
MUTED = (102, 114, 127)
LINK = (21, 101, 192)
WARN = (230, 81, 0)
STRIPE = (244, 246, 249)
BORDER = (217, 222, 229)
WHITE = (255, 255, 255)

# (background, text) for each risk level
RISK_COLORS = {
    "CRITICAL": ((183, 28, 28), WHITE),
    "HIGH": ((230, 81, 0), WHITE),
    "MEDIUM": ((251, 192, 45), TEXT),
    "LOW": ((200, 230, 201), TEXT),
    "INFO": ((236, 239, 241), TEXT),
}

# (title, width in mm, alignment). The widths add up to 178 of the 180 mm available.
COLUMNS = [
    ("#", 10, "C"),
    ("Port", 14, "C"),
    ("Service", 42, "L"),
    ("Version", 28, "L"),
    ("CVEs", 12, "C"),
    ("Top CVSS", 18, "C"),
    ("Risk", 22, "C"),
    ("Match", 32, "L"),
]
ROW_HEIGHT = 7

NEXT_STEPS = [
    "Start with the CRITICAL and HIGH findings at the top of the ranked list.",
    "Update or patch the affected software to a version that the CVE details do not list.",
    "Close or firewall services that are not needed, especially remote-access ports.",
    "Rescan after making changes to confirm the findings are gone.",
]

LIMITATIONS = [
    "Matching depends on what nmap can identify. Vague versions (for example "
    "Samba 3.X - 4.X) cannot be matched, so NO MATCH never means a service is safe.",
    "'Name only' matches are low confidence: they mention the service name, but "
    "the exact version is unknown.",
    "Risk is the highest CVSS score among a service's CVEs. It does not yet "
    "consider how important the device is or whether an exploit exists.",
    "Scores come from the US National Vulnerability Database at the time of the "
    "scan and can change later.",
    "This report lists known, published vulnerabilities only. It does not detect "
    "intrusions, malware or unknown flaws.",
]

# The built-in PDF fonts only cover Latin-1, so common punctuation is replaced
_REPLACEMENTS = {
    "\r\n": "\n", "\r": "\n",
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    "\u2013": "-", "\u2014": "-", "\u2026": "...", "\u00a0": " ", "\u2022": "-",
}
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


# ---------- small helpers (no PDF involved) ----------

def clean(text):
    """Make text safe for the built-in PDF fonts."""
    text = "" if text is None else str(text)
    for old, new in _REPLACEMENTS.items():
        text = text.replace(old, new)
    text = _CONTROL_CHARS.sub("", text)
    return text.encode("latin-1", "replace").decode("latin-1")


def fingerprint(rows):
    """SHA-256 of the ranked findings. The same findings always give the same value."""
    payload = [
        {
            "port": row["port"],
            "product": row["product"],
            "version": row["version"],
            "cves": [[c["cve_id"], c["cvss_score"]] for c in row["cves"]],
        }
        for row in rows
    ]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def default_filename(target, when=None):
    when = when or datetime.now()
    safe_target = re.sub(r"[^A-Za-z0-9._-]", "_", str(target))
    return f"NVAS_report_{safe_target}_{when:%Y%m%d_%H%M}.pdf"


def format_duration(seconds):
    if seconds is None:
        return "unknown"
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes} min {secs} s" if minutes else f"{secs} s"


def score_text(score):
    return "n/a" if score is None else f"{score:.1f}"


def cve_count_text(count):
    return f"{count} CVE" if count == 1 else f"{count} CVEs"


def service_name(row):
    return f"{row['product']} {row['version']}".strip()


def row_values(row):
    return [
        str(row["rank"] or "-"),
        str(row["port"]),
        row["product"],
        row["version"],
        str(len(row["cves"])),
        score_text(row["top_cvss"]) if row["top_cvss"] is not None else "-",
        risk_label(row["level"]),
        row["match"] or "-",
    ]


def key_finding_text(rows):
    with_cves = [row for row in rows if row["cves"]]
    if not with_cves:
        return ("No known vulnerabilities were matched for the services found. "
                "This does not prove the target is secure; see Method and limitations.")
    top = with_cves[0]
    return (f"{len(with_cves)} of {len(rows)} services have known vulnerabilities. "
            f"The highest-priority finding is port {top['port']} ({service_name(top)}), "
            f"top CVSS {score_text(top['top_cvss'])} ({risk_label(top['level'])}).")


# ---------- the PDF itself ----------

class ReportPDF(FPDF):
    def __init__(self, target):
        super().__init__(format="A4")
        self.target = clean(target)
        self.set_margins(15, 15, 15)
        self.set_auto_page_break(auto=True, margin=18)
        self.alias_nb_pages()
        self.set_title("Network Vulnerability Assessment Report")
        self.set_creator("Network Vulnerability Assessment System")

    # page furniture
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 6, f"Network Vulnerability Assessment Report - {self.target}",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(*BORDER)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        half = (self.w - self.l_margin - self.r_margin) / 2
        self.cell(half, 6, "Only scan systems you own or have permission to test.")
        self.cell(half, 6, f"Page {self.page_no()} of {{nb}}", align="R")

    # text helpers
    def put(self, text, size=10, style="", color=TEXT, height=6, align="L"):
        self.set_font("Helvetica", style, size)
        self.set_text_color(*color)
        self.cell(0, height, clean(text), align=align,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def paragraph(self, text, size=9, color=TEXT, height=5):
        self.set_font("Helvetica", "", size)
        self.set_text_color(*color)
        self.multi_cell(0, height, clean(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def heading(self, text):
        self.ln(4)
        self.put(text, size=13, style="B", color=NAVY, height=8)
        self.set_draw_color(*BORDER)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)

    def need_space(self, height):
        if self.get_y() + height > self.page_break_trigger:
            self.add_page()

    def fit(self, text, width):
        """Shorten text with '...' so it fits in a cell of the given width."""
        text = clean(text)
        limit = width - 2
        if self.get_string_width(text) <= limit:
            return text
        while text and self.get_string_width(text + "...") > limit:
            text = text[:-1]
        return text + "..."

    # first page
    def title_block(self, subtitle):
        self.set_fill_color(*NAVY)
        self.rect(0, 0, self.w, 38, style="F")
        self.set_xy(self.l_margin, 12)
        self.put("Network Vulnerability Assessment Report", size=20, style="B",
                 color=WHITE, height=10)
        self.put(subtitle, size=10, color=(184, 199, 220))
        self.set_y(46)

    def info_grid(self, pairs):
        for label, value in pairs:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*MUTED)
            self.cell(48, 7, clean(label))
            self.set_font("Helvetica", "", 10)
            self.set_text_color(*TEXT)
            self.cell(0, 7, clean(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def risk_boxes(self, counts):
        gap = 3
        width = (self.w - self.l_margin - self.r_margin - gap * 4) / 5
        top = self.get_y()
        for index, level in enumerate(RISK_ORDER):
            background, foreground = RISK_COLORS[level]
            x = self.l_margin + index * (width + gap)
            self.set_fill_color(*background)
            self.rect(x, top, width, 20, style="F")
            self.set_text_color(*foreground)
            self.set_xy(x, top + 3)
            self.set_font("Helvetica", "B", 16)
            self.cell(width, 8, str(counts.get(level, 0)), align="C")
            self.set_xy(x, top + 12)
            self.set_font("Helvetica", "B", 8)
            self.cell(width, 5, risk_label(level), align="C")
        self.set_y(top + 26)

    # ranked table
    def table_header(self):
        self.set_fill_color(*NAVY)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 9)
        for title, width, align in COLUMNS:
            self.cell(width, ROW_HEIGHT, title, fill=True, align=align)
        self.ln(ROW_HEIGHT)

    def table_row(self, values, level, striped):
        for (title, width, align), value in zip(COLUMNS, values):
            is_risk = title == "Risk"
            if is_risk:
                fill, color = RISK_COLORS[level]
            else:
                fill, color = (STRIPE if striped else WHITE), TEXT
            self.set_fill_color(*fill)
            self.set_text_color(*color)
            self.set_font("Helvetica", "B" if is_risk else "", 9)
            self.cell(width, ROW_HEIGHT, self.fit(value, width), fill=True, align=align)
        self.ln(ROW_HEIGHT)

    def ranked_table(self, rows):
        self.table_header()
        for index, row in enumerate(rows):
            if self.get_y() + ROW_HEIGHT > self.page_break_trigger:
                self.add_page()
                self.table_header()
            self.table_row(row_values(row), row["level"], index % 2 == 1)

    # finding details
    def finding_detail(self, row):
        self.need_space(45)
        background, foreground = RISK_COLORS[row["level"]]
        self.set_fill_color(*background)
        self.set_text_color(*foreground)
        self.set_font("Helvetica", "B", 9)
        self.cell(24, 7, risk_label(row["level"]), fill=True, align="C")

        self.set_text_color(*TEXT)
        self.set_font("Helvetica", "B", 11)
        title = f"  #{row['rank']}  Port {row['port']} - {service_name(row)}"
        room = self.w - self.l_margin - self.r_margin - 24
        self.cell(0, 7, self.fit(title, room), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        meta = (f"Top CVSS {score_text(row['top_cvss'])}  |  {cve_count_text(len(row['cves']))}  |  "
                f"Matched by: {row['match'] or 'nothing'}")
        self.put(meta, size=9, color=MUTED)
        if row["match"] == LOW_CONFIDENCE:
            self.paragraph("Low confidence: these CVEs mention the service name, but the "
                           "exact version was not identified, so they may not apply to "
                           "this device.", color=WARN)
        for cve in row["cves"]:
            self.cve_block(cve)
        self.ln(3)

    def cve_block(self, cve):
        self.need_space(22)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*LINK)
        self.cell(38, 6, clean(cve["cve_id"]), link=NVD_URL + cve["cve_id"])
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*TEXT)
        details = f"{cve['severity'] or 'n/a'}  |  CVSS {score_text(cve['cvss_score'])}"
        self.cell(0, 6, clean(details), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        description = clean(cve["description"])
        if len(description) > 500:
            description = description[:500] + "..."
        self.paragraph(description)
        self.ln(1.5)


# ---------- report sections ----------

def build_summary_page(pdf, target, rows, info, generated_at):
    pdf.add_page()
    pdf.title_block("Prioritised findings from an authorised scan")
    finished = info.get("finished") or generated_at
    with_cves = sum(1 for row in rows if row["cves"])
    pdf.info_grid([
        ("Target", target),
        ("Scan finished", f"{finished:%d %B %Y, %H:%M}"),
        ("Scan duration", format_duration(info.get("seconds"))),
        ("Scan run by", info.get("operator") or "not recorded"),
        ("Open ports found", str(len(rows))),
        ("Services with CVEs", f"{with_cves} of {len(rows)}"),
        ("CVE data source", "US National Vulnerability Database (NVD)"),
        ("Findings fingerprint", fingerprint(rows)[:16]),
    ])
    pdf.heading("Risk summary")
    counts = {level: sum(1 for row in rows if row["level"] == level) for level in RISK_ORDER}
    pdf.risk_boxes(counts)
    pdf.paragraph(key_finding_text(rows), size=10, height=5.5)
    pdf.heading("Recommended next steps")
    for step in NEXT_STEPS:
        pdf.paragraph("- " + step, size=10, height=5.5)
        pdf.ln(1)


def build_ranked_section(pdf, rows):
    pdf.add_page()
    pdf.heading("Ranked findings")
    pdf.paragraph("Services are ordered by their highest CVSS score. "
                  "NO MATCH means no CVE was matched.", color=MUTED)
    pdf.ln(2)
    if rows:
        pdf.ranked_table(rows)
    else:
        pdf.paragraph("No open ports were found on this target.")


def build_details_section(pdf, rows):
    with_cves = [row for row in rows if row["cves"]]
    if not with_cves:
        return
    pdf.add_page()
    pdf.heading("Finding details")
    for row in with_cves:
        pdf.finding_detail(row)


def build_closing_section(pdf, rows):
    pdf.need_space(70)
    pdf.heading("Method and limitations")
    for item in LIMITATIONS:
        pdf.paragraph("- " + item)
        pdf.ln(1)
    pdf.heading("Integrity")
    pdf.paragraph("Findings fingerprint (SHA-256 of the ranked findings): "
                  + fingerprint(rows), size=8, color=MUTED)


# ---------- public function ----------

def generate_report(target, matched, info=None, output_path=None, generated_at=None):
    """
    Write a PDF report and return its path.

    target       the scanned IP address
    matched      the list returned by match_scan_results()
    info         optional dict: {"seconds": scan duration, "finished": datetime}
    output_path  where to save it (default: reports/NVAS_report_<target>_<time>.pdf)
    """
    info = info or {}
    generated_at = generated_at or datetime.now()
    rows = rank_findings(matched)

    pdf = ReportPDF(target)
    build_summary_page(pdf, target, rows, info, generated_at)
    build_ranked_section(pdf, rows)
    build_details_section(pdf, rows)
    build_closing_section(pdf, rows)

    path = Path(output_path) if output_path else Path("reports") / default_filename(target, generated_at)
    path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(path))
    return str(path)