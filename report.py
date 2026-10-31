"""
PHASE 6 — REPORT GENERATION ENGINE (v2)

Builds the report as either .docx or .pdf, in one of four configurable
modes (report_mode param) — per the critique that a single 50+ page
everything-included PDF is a lot for an analyst to consume, and that the
right audience-appropriate view differs by who's reading it:

  - "analyst"    : default. Shows everything except confirmed/likely-benign
                   findings. Full detail, full evidence.
  - "executive"   : only P1/P2 priority findings with confidence >= 60%;
                   informational/benign collapsed to a single count line.
                   Short, for a non-technical audience.
  - "soc"         : suspicious/likely_malicious/malicious only; benign and
                   informational collapsed to a summary count, not hidden
                   entirely (per the critique: don't delete evidence just
                   because it's noise — collapse it, don't erase it).
  - "forensic"    : everything, including confirmed-benign, with full
                   per-finding evidence samples and analyst notes. No cap
                   on Detailed Findings.

Every finding now shows Severity, Confidence, Priority, and Disposition as
four separate values (not collapsed into one badge), plus a bounded
evidence sample so an analyst can see WHY something was classified/grouped
the way it was, instead of just trusting a rolled-up label.
"""
from __future__ import annotations
import io
import os
from xml.sax.saxutils import escape as xml_escape

from docx import Document
from docx.shared import RGBColor, Inches, Pt
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.section import WD_SECTION
from docx.oxml import OxmlElement
from docx.oxml import parse_xml
from docx.oxml.ns import qn
from docx.oxml.ns import nsdecls
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image,
)
from reportlab.pdfgen import canvas as pdfcanvas

from . import pipeline as pipeline_mod

ACCENT = "A8583F"
INK = "28221B"
DIM = "847A6A"
CREAM = "F4EFE3"

_STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
_LOGO_PATH = os.path.join(_STATIC_DIR, "title.png")
_COVER_BG_PATH = os.path.join(_STATIC_DIR, "report-cover-bg.png")

PDF_FRAME_WIDTH = LETTER[0] - (1.8 * inch)

# ---------------------------------------------------------------- cover ---
REPORT_MODE_INFO = {
    "analyst": {
        "label": "Analyst View",
        "blurb": "Full-detail investigative report. Every finding except confirmed/"
                 "likely-benign activity, shown with complete evidence chains.",
    },
    "executive": {
        "label": "Executive Briefing",
        "blurb": "Condensed decision-maker summary. Only P1/P2 priority findings at "
                 "60%+ confidence — informational and benign activity collapsed to "
                 "a single count line.",
    },
    "soc": {
        "label": "SOC Analyst View",
        "blurb": "Active-triage view for SOC operations. Suspicious, likely-"
                 "malicious, and malicious findings are prioritized; benign/"
                 "informational activity is collapsed, not hidden.",
    },
    "forensic": {
        "label": "Forensic Record",
        "blurb": "Complete forensic record of the analysis. Every finding, full "
                 "per-finding evidence samples, and analyst notes — no caps.",
    },
}

DISPOSITION_LABELS = {
    "malicious": "Malicious", "likely_malicious": "Likely Malicious",
    "suspicious": "Suspicious", "benign": "Benign", "likely_benign": "Likely Benign",
    "informational": "Informational", "unknown": "Unknown",
}

REPORT_MODES = {
    "analyst": {
        "exclude": {"benign", "likely_benign"},
        "collapse": set(),
        "detail_cap": 100,
        "min_confidence": 0,
        "min_priority": None,
    },
    "executive": {
        "exclude": {"benign", "likely_benign", "informational"},
        "collapse": {"unknown"},
        "detail_cap": 25,
        "min_confidence": 60,
        "min_priority": {"P1", "P2"},
    },
    "soc": {
        "exclude": set(),
        "collapse": {"benign", "likely_benign", "informational"},
        "detail_cap": 60,
        "min_confidence": 0,
        "min_priority": None,
    },
    "forensic": {
        "exclude": set(),
        "collapse": set(),
        "detail_cap": 10_000,
        "min_confidence": 0,
        "min_priority": None,
    },
}


def _mode_config(report_mode: str) -> dict:
    return REPORT_MODES.get(report_mode, REPORT_MODES["analyst"])


def _visible_and_collapsed(report_data: dict, report_mode: str) -> tuple[list[dict], dict]:
    """Returns (visible_groups, collapsed_counts_by_disposition)."""
    cfg = _mode_config(report_mode)
    groups = report_data["aggregated_events"]
    visible = []
    collapsed = {}

    for g in groups:
        disp = pipeline_mod.effective_disposition(g)
        if disp in cfg["exclude"]:
            continue
        if cfg["min_priority"] and g["priority"] not in cfg["min_priority"]:
            if disp in cfg["collapse"]:
                collapsed[disp] = collapsed.get(disp, 0) + g["count"]
            continue
        if g["confidence"] < cfg["min_confidence"]:
            continue
        if disp in cfg["collapse"]:
            collapsed[disp] = collapsed.get(disp, 0) + g["count"]
            continue
        visible.append(g)

    return visible, collapsed


def _ip_display(g: dict) -> str:
    ips = g.get("source_ips") or ([g["source_ip"]] if g.get("source_ip") and g["source_ip"] != "unknown" else [])
    if not ips:
        return "-"
    if len(ips) == 1:
        return ips[0]
    return f"{ips[0]} (+{len(ips) - 1} more)"


def _disp_label(g: dict) -> str:
    disp = pipeline_mod.effective_disposition(g)
    label = DISPOSITION_LABELS.get(disp, disp)
    return label + (" [analyst]" if g.get("user_disposition") else "")


def _fmt_time(dt) -> str:
    return dt.strftime("%H:%M:%S") if dt else "?"


def _set_docx_page_border(document, color_hex: str = ACCENT):
    """Draws a square border on every page of the document (applies to the
    whole section, so it repeats on each page automatically)."""
    for section in document.sections:
        sectPr = section._sectPr
        existing = sectPr.find(qn("w:pgBorders"))
        if existing is not None:
            sectPr.remove(existing)
        pg_borders = OxmlElement("w:pgBorders")
        pg_borders.set(qn("w:offsetFrom"), "page")
        for edge in ("top", "left", "bottom", "right"):
            el = OxmlElement(f"w:{edge}")
            el.set(qn("w:val"), "single")
            el.set(qn("w:sz"), "14")       # eighths of a point
            el.set(qn("w:space"), "20")     # points from page edge
            el.set(qn("w:color"), color_hex)
            pg_borders.append(el)
        sectPr.append(pg_borders)


def _set_cell_shading(cell, fill_hex: str):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill_hex)


def _set_cell_width(cell, width_inches: float):
    width = int(width_inches * 1440)
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_w = tc_pr.find(qn("w:tcW"))
    if tc_w is None:
        tc_w = OxmlElement("w:tcW")
        tc_pr.append(tc_w)
    tc_w.set(qn("w:w"), str(width))
    tc_w.set(qn("w:type"), "dxa")


def _set_cell_margins(cell, margin_twips: int = 80):
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = tc_pr.find(qn("w:tcMar"))
    if tc_mar is None:
        tc_mar = OxmlElement("w:tcMar")
        tc_pr.append(tc_mar)
    for edge in ("top", "left", "bottom", "right"):
        node = tc_mar.find(qn(f"w:{edge}"))
        if node is None:
            node = OxmlElement(f"w:{edge}")
            tc_mar.append(node)
        node.set(qn("w:w"), str(margin_twips))
        node.set(qn("w:type"), "dxa")


def _format_docx_table(table, widths: list[float], font_size: int = 8):
    table.autofit = False
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table_width = sum(widths)
    tbl_pr = table._tbl.tblPr
    tbl_w = tbl_pr.find(qn("w:tblW"))
    if tbl_w is None:
        tbl_w = OxmlElement("w:tblW")
        tbl_pr.append(tbl_w)
    tbl_w.set(qn("w:w"), str(int(table_width * 1440)))
    tbl_w.set(qn("w:type"), "dxa")

    for row_idx, row in enumerate(table.rows):
        row.height = None
        for idx, cell in enumerate(row.cells):
            _set_cell_width(cell, widths[min(idx, len(widths) - 1)])
            _set_cell_margins(cell)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            for paragraph in cell.paragraphs:
                paragraph.paragraph_format.space_before = Pt(0)
                paragraph.paragraph_format.space_after = Pt(0)
                paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT
                for run in paragraph.runs:
                    run.font.size = Pt(font_size)
                    if row_idx == 0:
                        run.font.bold = True
                        run.font.color.rgb = RGBColor(255, 255, 255)
            if row_idx == 0:
                _set_cell_shading(cell, INK)


def _add_docx_cover_background(doc: Document):
    """Full-bleed cover background image, anchored behind the text.

    Uses a DrawingML floating picture (wp:anchor) rather than the legacy
    VML shape trick: VML is silently dropped by LibreOffice/Google Docs
    (which is why it never actually rendered), while a DrawingML anchor is
    broadly supported by every modern OOXML consumer, including Word.
    """
    if not os.path.exists(_COVER_BG_PATH):
        return
    section = doc.sections[0]
    section.different_first_page_header_footer = True
    header = section.first_page_header
    paragraph = header.paragraphs[0] if header.paragraphs else header.add_paragraph()
    run = paragraph.add_run()
    run.add_picture(_COVER_BG_PATH, width=Inches(8.5), height=Inches(11))

    # add_picture() produces an inline <w:drawing><wp:inline>...</wp:inline>.
    # Pull its pieces out and rebuild them inside a <wp:anchor> so the image
    # floats full-bleed behind the page instead of sitting inline in the flow.
    drawing = run._r.find(qn("w:drawing"))
    inline = drawing.find(qn("wp:inline"))
    extent = inline.find(qn("wp:extent"))
    docPr = inline.find(qn("wp:docPr"))
    cNvGraphicFramePr = inline.find(qn("wp:cNvGraphicFramePr"))
    graphic = inline.find(qn("a:graphic"))

    anchor = OxmlElement("wp:anchor")
    for attr, val in {
        "behindDoc": "1", "distT": "0", "distB": "0", "distL": "0", "distR": "0",
        "simplePos": "0", "locked": "0", "layoutInCell": "1",
        "allowOverlap": "1", "relativeHeight": "1",
    }.items():
        anchor.set(attr, val)

    simple_pos = OxmlElement("wp:simplePos")
    simple_pos.set("x", "0")
    simple_pos.set("y", "0")

    position_h = OxmlElement("wp:positionH")
    position_h.set("relativeFrom", "page")
    offset_h = OxmlElement("wp:posOffset")
    offset_h.text = "0"
    position_h.append(offset_h)

    position_v = OxmlElement("wp:positionV")
    position_v.set("relativeFrom", "page")
    offset_v = OxmlElement("wp:posOffset")
    offset_v.text = "0"
    position_v.append(offset_v)

    wrap_none = OxmlElement("wp:wrapNone")

    anchor.append(simple_pos)
    anchor.append(position_h)
    anchor.append(position_v)
    anchor.append(extent)              # moves extent from inline -> anchor
    anchor.append(wrap_none)
    anchor.append(docPr)               # moves docPr
    anchor.append(cNvGraphicFramePr)   # moves cNvGraphicFramePr
    anchor.append(graphic)             # moves graphic

    drawing.remove(inline)
    drawing.append(anchor)


def _justify_body_paragraphs(document):
    """Applies justified alignment to body prose (Normal / List styles).
    Headings, table cells, and the cover page are left as-is: cover
    paragraphs already have an explicit CENTER alignment set (checked via
    `p.alignment is None` below, not identity — lxml hands back a fresh
    wrapper object on every `document.paragraphs` access, so comparing
    object/element identity across two passes is unreliable), and
    justifying short heading text or narrow table cells reads worse, not
    better."""
    justify_styles = {"Normal", "List Bullet", "List Number", "Body Text"}
    for p in document.paragraphs:
        if p.alignment is not None:
            continue  # already deliberately aligned (e.g. cover page)
        if p.style and p.style.name in justify_styles and p.text.strip():
            p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY


def _add_docx_cover_page(doc: Document, report_data: dict, report_mode: str):
    mode_info = REPORT_MODE_INFO.get(report_mode, REPORT_MODE_INFO["analyst"])
    s = report_data["stats"]

    # All cover content lives inside a single-cell "card" table, shaded
    # cream, so it stays legible sitting on top of the dark cover
    # background image (added separately, full-bleed, behind everything).
    card = doc.add_table(rows=1, cols=1)
    card.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = card.cell(0, 0)
    _set_cell_width(cell, 6.2)
    _set_cell_shading(cell, CREAM)
    _set_cell_margins(cell, margin_twips=360)

    # push the logo + wordmark down a little from the top of the card
    top_p = cell.paragraphs[0]
    top_p.paragraph_format.space_after = Pt(36)

    if os.path.exists(_LOGO_PATH):
        pic_p = cell.add_paragraph()
        pic_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        pic_p.add_run().add_picture(_LOGO_PATH, width=Inches(0.9))

    brand = cell.add_paragraph()
    brand.alignment = WD_ALIGN_PARAGRAPH.CENTER
    brand_run = brand.add_run("BREACH · BRIEF")
    brand_run.font.size = Pt(15)
    brand_run.font.color.rgb = RGBColor.from_string(INK)
    brand_run.font.name = "Cormorant"
    brand_run.font.bold = False

    cell.add_paragraph().paragraph_format.space_after = Pt(6)

    title_p = cell.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_run = title_p.add_run("Security Log Correlation\n& Incident Report")
    title_run.font.size = Pt(30)
    title_run.font.bold = True
    title_run.font.color.rgb = RGBColor.from_string(ACCENT)

    mode_p = cell.add_paragraph()
    mode_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    mode_p.paragraph_format.space_before = Pt(14)
    mode_run = mode_p.add_run(mode_info["label"].upper())
    mode_run.font.size = Pt(12)
    mode_run.font.bold = True
    mode_run.font.color.rgb = RGBColor.from_string(INK)

    blurb_p = cell.add_paragraph()
    blurb_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    blurb_run = blurb_p.add_run(mode_info["blurb"])
    blurb_run.italic = True
    blurb_run.font.size = Pt(10)
    blurb_run.font.color.rgb = RGBColor.from_string(DIM)

    cell.add_paragraph().paragraph_format.space_after = Pt(24)

    # ---- report specifics block -------------------------------------
    specs = [
        ("Analysis ID", report_data.get("analysis_id", "n/a")),
        ("Generated", report_data["generated_at"].strftime("%Y-%m-%d %H:%M UTC")),
        ("Report mode", mode_info["label"]),
        ("Source files", str(s["total_files"])),
        ("Raw events analyzed", str(s["total_raw_events"])),
        ("Correlated findings", str(s["total_aggregated_events"])),
        ("Overall risk posture", str(s["overall_posture"])),
        ("Unique source IPs", str(s["unique_source_ips"])),
    ]
    spec_table = cell.add_table(rows=0, cols=2)
    spec_table.autofit = True
    for label, value in specs:
        row = spec_table.add_row().cells
        lp = row[0].paragraphs[0]
        lr = lp.add_run(label)
        lr.font.bold = True
        lr.font.size = Pt(10)
        lr.font.color.rgb = RGBColor.from_string(DIM)
        vp = row[1].paragraphs[0]
        vr = vp.add_run(value)
        vr.font.size = Pt(10)
        vr.font.color.rgb = RGBColor.from_string(INK)
    # center the spec table within the card
    spec_table.alignment = 1  # WD_TABLE_ALIGNMENT.CENTER

    # trailing space inside the card so the shading doesn't hug the last row
    cell.add_paragraph().paragraph_format.space_after = Pt(18)

    doc.add_page_break()


# ------------------------------------------------------------------ DOCX ---
def generate_docx(report_data: dict, report_mode: str = "analyst") -> bytes:
    groups, collapsed = _visible_and_collapsed(report_data, report_mode)
    cfg = _mode_config(report_mode)
    doc = Document()

    _add_docx_cover_page(doc, report_data, report_mode)
    _add_docx_cover_background(doc)

    title = doc.add_heading("Security Log Correlation & Incident Report", level=0)
    for run in title.runs:
        run.font.color.rgb = RGBColor.from_string(ACCENT)

    meta = doc.add_paragraph()
    meta.add_run(f"Generated: {report_data['generated_at'].strftime('%Y-%m-%d %H:%M UTC')}"
                 f"  ·  Report mode: {report_mode.upper()}").italic = True
    if collapsed:
        summary = ", ".join(f"{DISPOSITION_LABELS.get(k, k)}: {v}" for k, v in collapsed.items())
        doc.add_paragraph(f"Collapsed (not shown individually): {summary}").italic = True

    # 1. Executive Summary
    doc.add_heading("1. Executive Summary", level=1)
    s = report_data["stats"]
    doc.add_paragraph(
        f"This report was generated from {s['total_files']} ingested file(s), covering "
        f"{s['total_raw_events']} raw log/alert events which correlated into "
        f"{s['total_aggregated_events']} distinct event group(s), {len(groups)} shown in this "
        f"{report_mode} view. Overall risk posture: {s['overall_posture']}."
    )
    for b in [
        f"High-risk findings: {s['high_risk_count']}",
        f"Medium-risk findings: {s['medium_risk_count']}",
        f"Low-risk findings: {s['low_risk_count']}",
        f"Unique source IPs involved: {s['unique_source_ips']}",
        f"Stages observed: {', '.join(s['stages_observed']) if s['stages_observed'] else 'none'}",
    ]:
        doc.add_paragraph(b, style="List Bullet")

    # 2. Findings Overview Table — now with Confidence, Priority, Disposition
    doc.add_heading("2. Findings Overview", level=1)
    table = doc.add_table(rows=1, cols=8)
    table.style = "Light Grid Accent 2"
    hdr = table.rows[0].cells
    for i, h in enumerate(["Event Type", "Count", "Time Range", "Source IP(s)",
                            "Severity", "Confidence", "Priority", "Disposition"]):
        hdr[i].text = h
    for g in groups:
        row = table.add_row().cells
        row[0].text = g["event_type"]
        row[1].text = str(g["count"])
        row[2].text = f"{_fmt_time(g['start_time'])} - {_fmt_time(g['end_time'])}"
        row[3].text = _ip_display(g)
        row[4].text = g["severity"]
        row[5].text = f"{g['confidence']:.0f}%"
        row[6].text = g["priority"]
        row[7].text = _disp_label(g)
    _format_docx_table(table, [1.05, 0.42, 0.8, 0.9, 0.62, 0.68, 0.48, 1.05], font_size=7)

    # 3. Timeline
    doc.add_heading("3. Timeline (Chain of Custody)", level=1)
    doc.add_paragraph(report_data["timeline_summary"])
    visible_gids = {g["group_id"] for g in groups}
    for t in report_data["timeline"]:
        if t.get("group_id") not in visible_gids:
            continue
        p = doc.add_paragraph()
        p.add_run(f"[{t['time_label']}] ").bold = True
        p.add_run(f"{t['stage']} \u2192 {t['event_type']} ({t['count']} attempts)")

    # 4. Detailed Findings — with evidence
    doc.add_heading("4. Detailed Findings", level=1)
    top_groups = sorted(groups, key=lambda g: g["risk_score"], reverse=True)[:cfg["detail_cap"]]
    if len(groups) > cfg["detail_cap"]:
        doc.add_paragraph(
            f"Showing the top {cfg['detail_cap']} of {len(groups)} groups by risk score. "
            f"The remaining {len(groups) - cfg['detail_cap']} are listed in the Findings Overview table above."
        ).italic = True
    for g in top_groups:
        doc.add_heading(f"{g['event_type']} \u2014 {_ip_display(g)}", level=2)
        meta_line = doc.add_paragraph()
        meta_line.add_run(
            f"Severity: {g['severity']}  ·  Confidence: {g['confidence']:.0f}%  ·  "
            f"Priority: {g['priority']}  ·  Disposition: {_disp_label(g)}  ·  Risk score: {g['risk_score']}"
        ).bold = True
        doc.add_paragraph(
            f"Occurred {g['count']} time(s) between {_fmt_time(g['start_time'])} and "
            f"{_fmt_time(g['end_time'])}. Destination(s): {', '.join(g['destination_ips']) or 'n/a'}. "
            f"Port(s): {', '.join(str(p) for p in g['ports']) or 'n/a'}."
        )
        m = g["mapping"]
        map_line = doc.add_paragraph()
        map_line.add_run("Framework mapping: ").bold = True
        mitre_conf = f" (confidence {m['mitre_confidence']}%, {m['mitre_source']})" if m.get("mitre_confidence") else ""
        map_line.add_run(
            f"MITRE {m.get('MITRE') or 'n/a'}{mitre_conf} | CWE {m.get('CWE') or 'n/a'} | "
            f"OWASP {m.get('OWASP') or 'n/a'} | NIST {m.get('NIST') or 'n/a'} | "
            f"CIS {m.get('CIS') or 'n/a'}" + (f" | CVE {', '.join(m['CVE'])}" if m.get("CVE") else "")
        )
        if g.get("user_notes"):
            note_p = doc.add_paragraph()
            note_p.add_run("Analyst notes: ").bold = True
            note_p.add_run(g["user_notes"])

        # Reasoning chain (Phase 2 — Evidence Reasoning Engine): what was
        # observed vs. derived vs. inferred vs. explicitly NOT observed, so
        # the report never implies more certainty than the data supports.
        r = g.get("reasoning")
        if r:
            reason_p = doc.add_paragraph()
            reason_p.add_run("Why this was flagged: ").bold = True
            reason_p.add_run(r["reasoning_text"])

            if r.get("confidence_breakdown"):
                cb_p = doc.add_paragraph()
                cb_p.add_run("Confidence basis: ").bold = True
                cb_p.add_run(" + ".join(f"{c['label']} ({c['points']} pts)" for c in r["confidence_breakdown"])
                             + f" = {g['confidence']:.0f}%")

            for label, key in [("Observed", "observed"), ("Derived", "derived"),
                                ("Inferred", "inferred"), ("Not observed", "not_observed")]:
                items = r.get(key)
                if items:
                    p = doc.add_paragraph()
                    p.add_run(f"{label}: ").bold = True
                    p.add_run(" ".join(items))

        # Evidence subsection — the "why am I seeing this" layer.
        if g.get("evidence"):
            doc.add_paragraph("Evidence (sample of underlying events):").bold = True
            ev_table = doc.add_table(rows=1, cols=5)
            ev_table.style = "Light List Accent 2"
            ehdr = ev_table.rows[0].cells
            for i, h in enumerate(["Timestamp", "Source IP", "Agent", "Rule", "Message"]):
                ehdr[i].text = h
            for ev in g["evidence"]:
                row = ev_table.add_row().cells
                row[0].text = ev.get("timestamp") or "-"
                row[1].text = ev.get("source_ip") or "-"
                row[2].text = ev.get("agent") or "-"
                row[3].text = f"{ev.get('rule_id') or ''} {ev.get('rule_description') or ''}".strip() or "-"
                row[4].text = (ev.get("raw_message") or "")[:150]
            _format_docx_table(ev_table, [1.08, 0.78, 0.92, 1.28, 2.02], font_size=6)

    # 5. Risk Assessment
    doc.add_heading("5. Risk Assessment", level=1)
    doc.add_paragraph(
        "Top priority findings, ranked by risk score "
        "(Severity x Confidence x Impact x log-scaled Frequency):"
    )
    for i, g in enumerate(report_data["top_threats"], 1):
        doc.add_paragraph(
            f"{i}. {g['event_type']} from {g['source_ip'] or 'unknown'} "
            f"\u2014 score {g['risk_score']}, priority {g['priority']}, "
            f"confidence {g['confidence']:.0f}%",
            style="List Number",
        )

    # 6. Recommendations
    doc.add_heading("6. Recommendations", level=1)
    for r in report_data["recommendations"]:
        p = doc.add_paragraph(style="List Bullet")
        p.add_run(f"{r['event_type']}: ").bold = True
        p.add_run(r["action"])

    # 7. Appendices
    doc.add_heading("7. Appendix \u2014 Source Files", level=1)
    for f in report_data["files"]:
        doc.add_paragraph(f"{f['filename']} ({f['file_type']}, source: {f['source']})", style="List Bullet")

    if report_mode == "forensic":
        doc.add_heading("Appendix \u2014 Raw Correlated Events (sample)", level=2)
        doc.add_paragraph(
            f"Showing a sample of {min(200, len(report_data['events']))} of "
            f"{report_data.get('events_total_count', len(report_data['events']))} total raw events."
        ).italic = True
        raw_table = doc.add_table(rows=1, cols=4)
        raw_table.style = "Light List Accent 2"
        hdr2 = raw_table.rows[0].cells
        for i, h in enumerate(["Timestamp", "Event Type", "Source IP", "Message"]):
            hdr2[i].text = h
        for ev in report_data["events"][:200]:
            row = raw_table.add_row().cells
            row[0].text = _fmt_time(ev["timestamp"])
            row[1].text = ev["event_type"]
            row[2].text = ev["source_ip"] or "-"
            row[3].text = (ev.get("raw_message") or "")[:120]
        _format_docx_table(raw_table, [0.92, 1.15, 0.85, 3.08], font_size=6)

    _set_docx_page_border(doc)
    _justify_body_paragraphs(doc)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _pdf_page_border(canvas, doc, draw_watermark=True):
    """Draws a square border on every page (called for both first and
    later pages by SimpleDocTemplate). Runs at the START of the page,
    before any flowable/body text is drawn onto it — which is why the
    watermark is drawn from here rather than in a footer callback: it
    needs to land underneath the text, not on top of it."""
    canvas.saveState()
    if draw_watermark:
        _draw_watermark(canvas)
    canvas.setStrokeColor(colors.HexColor("#" + ACCENT))
    canvas.setLineWidth(1.1)
    margin = 0.42 * inch
    canvas.rect(margin, margin, LETTER[0] - 2 * margin, LETTER[1] - 2 * margin)
    canvas.restoreState()


_WATERMARK_OPACITY = 0.055  # kept low so it never competes with body text
_WATERMARK_SIZE = 3.3 * inch


def _draw_watermark(canvas):
    """Faint centered logo watermark, opacity kept low enough to sit
    behind body text without ever overlapping/competing with it."""
    if not os.path.exists(_LOGO_PATH):
        return
    canvas.saveState()
    canvas.setFillAlpha(_WATERMARK_OPACITY)
    size = _WATERMARK_SIZE
    canvas.drawImage(
        _LOGO_PATH,
        (LETTER[0] - size) / 2, (LETTER[1] - size) / 2,
        width=size, height=size,
        mask="auto", preserveAspectRatio=True,
    )
    canvas.restoreState()


def _draw_footer_page_number(canvas, page_num, page_count):
    # Sits below the 0.42in page-border rect (drawn by _pdf_page_border /
    # _pdf_cover_page) so the footer never touches or clips on it.
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#" + DIM))
    canvas.drawCentredString(LETTER[0] / 2, 0.2 * inch, f"Page {page_num} of {page_count}")
    canvas.restoreState()


class _NumberedCanvas(pdfcanvas.Canvas):
    """Defers each page's final emission until the total page count is
    known, so the footer can read 'Page N of TOTAL' — a plain per-page
    draw callback only ever knows N at the time it runs, never the total.
    Standard ReportLab recipe: snapshot canvas state on showPage(), then
    replay each snapshot (drawing the footer/watermark into it first)
    once every page has been built."""

    def __init__(self, *args, **kwargs):
        pdfcanvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        page_count = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_extras(page_count)
            pdfcanvas.Canvas.showPage(self)
        pdfcanvas.Canvas.save(self)

    def _draw_page_extras(self, page_count):
        # Only the page-number footer is added here (at save() time, once
        # the total is known) — it lands in the empty margin below the
        # body-text frame, so draw order doesn't affect its legibility.
        # The watermark is NOT drawn here: this runs after every flowable
        # on the page is already in the content stream, which would paint
        # it OVER the text instead of behind it. It's drawn early instead,
        # from _pdf_page_border, before any body text reaches the page.
        _draw_footer_page_number(self, self._pageNumber, page_count)


def _pdf_cover_page(canvas, doc):
    """Cover-page-only decoration: full-bleed background image, with a
    cream 'card' drawn behind the cover content area so the cover text
    (which uses the same ink/dim colors as the rest of the report) stays
    legible against the dark background image, then the usual border.
    No logo watermark on this page — the cover already carries its own
    full-bleed art and a prominent logo, so a second faint copy under
    the card would just be noise."""
    canvas.saveState()
    if os.path.exists(_COVER_BG_PATH):
        canvas.drawImage(_COVER_BG_PATH, 0, 0, width=LETTER[0], height=LETTER[1],
                          preserveAspectRatio=False, mask="auto")
        card_margin = 0.85 * inch
        canvas.setFillColor(colors.HexColor("#" + CREAM))
        canvas.setFillAlpha(0.96)
        canvas.roundRect(card_margin, card_margin,
                          LETTER[0] - 2 * card_margin, LETTER[1] - 2 * card_margin,
                          10, stroke=0, fill=1)
        canvas.setFillAlpha(1)
    canvas.restoreState()
    _pdf_page_border(canvas, doc, draw_watermark=False)


def _pdf_cover_story(report_data: dict, report_mode: str, styles) -> list:
    mode_info = REPORT_MODE_INFO.get(report_mode, REPORT_MODE_INFO["analyst"])
    s = report_data["stats"]
    story = []

    story.append(Spacer(1, 60))
    if os.path.exists(_LOGO_PATH):
        img = Image(_LOGO_PATH, width=0.85 * inch, height=0.85 * inch)
        img.hAlign = "CENTER"
        story.append(img)
        story.append(Spacer(1, 10))

    story.append(Paragraph("BREACH · BRIEF", styles["CoverBrand"]))
    story.append(Spacer(1, 14))
    story.append(Paragraph("Security Log Correlation<br/>&amp; Incident Report", styles["CoverTitle"]))
    story.append(Spacer(1, 16))
    story.append(Paragraph(mode_info["label"].upper(), styles["CoverMode"]))
    story.append(Paragraph(mode_info["blurb"], styles["CoverBlurb"]))
    story.append(Spacer(1, 28))

    specs = [
        ["Analysis ID", report_data.get("analysis_id", "n/a")],
        ["Generated", report_data["generated_at"].strftime("%Y-%m-%d %H:%M UTC")],
        ["Report mode", mode_info["label"]],
        ["Source files", str(s["total_files"])],
        ["Raw events analyzed", str(s["total_raw_events"])],
        ["Correlated findings", str(s["total_aggregated_events"])],
        ["Overall risk posture", str(s["overall_posture"])],
        ["Unique source IPs", str(s["unique_source_ips"])],
    ]
    spec_table = Table(specs, colWidths=[1.9 * inch, 2.8 * inch], hAlign="CENTER")
    spec_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#" + DIM)),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#" + INK)),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#d8d0bd")),
    ]))
    story.append(spec_table)
    story.append(PageBreak())
    return story


# ------------------------------------------------------------------- PDF ---
def generate_pdf(report_data: dict, report_mode: str = "analyst") -> bytes:
    groups, collapsed = _visible_and_collapsed(report_data, report_mode)
    cfg = _mode_config(report_mode)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=LETTER,
                             topMargin=0.9 * inch, bottomMargin=0.9 * inch,
                             leftMargin=0.9 * inch, rightMargin=0.9 * inch)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="H1c", parent=styles["Heading1"], textColor=colors.HexColor("#" + ACCENT)))
    styles.add(ParagraphStyle(name="TitleC", parent=styles["Title"], textColor=colors.HexColor("#" + ACCENT)))
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#" + DIM)))
    styles.add(ParagraphStyle(name="CoverBrand", parent=styles["Normal"], fontSize=15,
                               alignment=TA_CENTER, textColor=colors.HexColor("#" + INK)))
    styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontSize=27,
                               leading=32, alignment=TA_CENTER, textColor=colors.HexColor("#" + ACCENT)))
    styles.add(ParagraphStyle(name="CoverMode", parent=styles["Normal"], fontSize=12,
                               alignment=TA_CENTER, textColor=colors.HexColor("#" + INK),
                               fontName="Helvetica-Bold", spaceAfter=6))
    styles.add(ParagraphStyle(name="CoverBlurb", parent=styles["Normal"], fontSize=9.5,
                               alignment=TA_CENTER, textColor=colors.HexColor("#" + DIM),
                               fontName="Helvetica-Oblique"))
    # Justified body text throughout, per the requested layout — headings
    # and the "Small" caption style stay left-aligned (justifying short
    # headings/captions reads worse, not better).
    styles["Normal"].alignment = TA_JUSTIFY

    story = []
    story.extend(_pdf_cover_story(report_data, report_mode, styles))
    story.append(Paragraph("Security Log Correlation &amp; Incident Report", styles["TitleC"]))
    story.append(Paragraph(
        f"Generated: {report_data['generated_at'].strftime('%Y-%m-%d %H:%M UTC')} "
        f"&middot; Report mode: {report_mode.upper()}", styles["Small"]))
    if collapsed:
        summary = ", ".join(f"{DISPOSITION_LABELS.get(k, k)}: {v}" for k, v in collapsed.items())
        story.append(Paragraph(f"Collapsed (not shown individually): {summary}", styles["Small"]))
    story.append(Spacer(1, 16))

    s = report_data["stats"]
    story.append(Paragraph("1. Executive Summary", styles["H1c"]))
    story.append(Paragraph(
        f"This report was generated from {s['total_files']} ingested file(s), covering "
        f"{s['total_raw_events']} raw log/alert events which correlated into "
        f"{s['total_aggregated_events']} distinct event group(s), {len(groups)} shown in this "
        f"<b>{report_mode}</b> view. Overall risk posture: <b>{s['overall_posture']}</b>.", styles["Normal"]))
    story.append(Spacer(1, 6))
    for b in [f"High-risk findings: {s['high_risk_count']}",
              f"Medium-risk findings: {s['medium_risk_count']}",
              f"Low-risk findings: {s['low_risk_count']}",
              f"Unique source IPs involved: {s['unique_source_ips']}",
              f"Stages observed: {', '.join(s['stages_observed']) if s['stages_observed'] else 'none'}"]:
        story.append(Paragraph(f"\u2022 {b}", styles["Normal"]))
    story.append(Spacer(1, 14))

    story.append(Paragraph("2. Findings Overview", styles["H1c"]))
    data = [["Event Type", "Count", "Time Range", "Source IP(s)", "Sev", "Conf", "Pri", "Disposition"]]
    for g in groups:
        data.append([g["event_type"], str(g["count"]),
                     f"{_fmt_time(g['start_time'])}-{_fmt_time(g['end_time'])}",
                     _ip_display(g), g["severity"], f"{g['confidence']:.0f}%", g["priority"], _disp_label(g)])
    # Event Type, Count, Time Range, Source IP(s), Sev, Conf, Pri, Disposition
    findings_widths = [1.0 * inch, 0.4 * inch, 1.3 * inch, 1.25 * inch,
                        0.55 * inch, 0.55 * inch, 0.5 * inch, 0.9 * inch]
    story.append(_styled_table(data, col_widths=findings_widths))
    story.append(Spacer(1, 14))

    story.append(Paragraph("3. Timeline (Chain of Custody)", styles["H1c"]))
    story.append(Paragraph(report_data["timeline_summary"], styles["Normal"]))
    story.append(Spacer(1, 6))
    visible_gids = {g["group_id"] for g in groups}
    for t in report_data["timeline"]:
        if t.get("group_id") not in visible_gids:
            continue
        story.append(Paragraph(
            f"<b>[{t['time_label']}]</b> {t['stage']} \u2192 {t['event_type']} ({t['count']} attempts)",
            styles["Normal"]))
    story.append(PageBreak())

    story.append(Paragraph("4. Detailed Findings", styles["H1c"]))
    top_groups = sorted(groups, key=lambda g: g["risk_score"], reverse=True)[:cfg["detail_cap"]]
    if len(groups) > cfg["detail_cap"]:
        story.append(Paragraph(
            f"Showing the top {cfg['detail_cap']} of {len(groups)} groups by risk score.",
            styles["Small"]))
    for g in top_groups:
        story.append(Paragraph(f"{g['event_type']} \u2014 {_ip_display(g)}", styles["Heading3"]))
        story.append(Paragraph(
            f"<b>Severity:</b> {g['severity']} &nbsp; <b>Confidence:</b> {g['confidence']:.0f}% &nbsp; "
            f"<b>Priority:</b> {g['priority']} &nbsp; <b>Disposition:</b> {_disp_label(g)} &nbsp; "
            f"<b>Risk score:</b> {g['risk_score']}", styles["Normal"]))
        story.append(Paragraph(
            f"Occurred {g['count']} time(s) between {_fmt_time(g['start_time'])} and "
            f"{_fmt_time(g['end_time'])}. Destination(s): {', '.join(g['destination_ips']) or 'n/a'}. "
            f"Port(s): {', '.join(str(p) for p in g['ports']) or 'n/a'}.", styles["Normal"]))
        m = g["mapping"]
        mitre_conf = f" (confidence {m['mitre_confidence']}%, {m['mitre_source']})" if m.get("mitre_confidence") else ""
        story.append(Paragraph(
            f"<b>Framework mapping:</b> MITRE {m.get('MITRE') or 'n/a'}{mitre_conf} | CWE {m.get('CWE') or 'n/a'} | "
            f"OWASP {m.get('OWASP') or 'n/a'} | NIST {m.get('NIST') or 'n/a'} | CIS {m.get('CIS') or 'n/a'}"
            + (f" | CVE {', '.join(m['CVE'])}" if m.get("CVE") else ""), styles["Normal"]))
        if g.get("user_notes"):
            story.append(Paragraph(f"<b>Analyst notes:</b> {g['user_notes']}", styles["Normal"]))

        r = g.get("reasoning")
        if r:
            story.append(Paragraph(f"<b>Why this was flagged:</b> {r['reasoning_text']}", styles["Normal"]))
            if r.get("confidence_breakdown"):
                basis = " + ".join(f"{c['label']} ({c['points']} pts)" for c in r["confidence_breakdown"])
                story.append(Paragraph(f"<b>Confidence basis:</b> {basis} = {g['confidence']:.0f}%", styles["Small"]))
            for label, key in [("Observed", "observed"), ("Derived", "derived"),
                                ("Inferred", "inferred"), ("Not observed", "not_observed")]:
                items = r.get(key)
                if items:
                    story.append(Paragraph(f"<b>{label}:</b> {' '.join(items)}", styles["Normal"]))

        if g.get("evidence"):
            story.append(Paragraph("<b>Evidence (sample):</b>", styles["Normal"]))
            ev_data = [["Timestamp", "Source IP", "Agent", "Rule", "Message"]]
            for ev in g["evidence"]:
                ev_data.append([
                    ev.get("timestamp") or "-", ev.get("source_ip") or "-", ev.get("agent") or "-",
                    f"{ev.get('rule_id') or ''} {ev.get('rule_description') or ''}".strip()[:30] or "-",
                    (ev.get("raw_message") or "")[:60],
                ])
            evidence_widths = [1.0 * inch, 0.85 * inch, 1.0 * inch, 1.3 * inch, 2.3 * inch]
            story.append(_styled_table(ev_data, col_widths=evidence_widths))
        story.append(Spacer(1, 10))

    story.append(Paragraph("5. Risk Assessment", styles["H1c"]))
    story.append(Paragraph(
        "Top priority findings, ranked by risk score "
        "(Severity x Confidence x Impact x log-scaled Frequency):", styles["Normal"]))
    for i, g in enumerate(report_data["top_threats"], 1):
        story.append(Paragraph(
            f"{i}. {g['event_type']} from {g['source_ip'] or 'unknown'} \u2014 score {g['risk_score']}, "
            f"priority {g['priority']}, confidence {g['confidence']:.0f}%",
            styles["Normal"]))
    story.append(Spacer(1, 14))

    story.append(Paragraph("6. Recommendations", styles["H1c"]))
    for r in report_data["recommendations"]:
        story.append(Paragraph(f"\u2022 <b>{r['event_type']}:</b> {r['action']}", styles["Normal"]))
    story.append(Spacer(1, 14))

    story.append(Paragraph("7. Appendix \u2014 Source Files", styles["H1c"]))
    for f in report_data["files"]:
        story.append(Paragraph(f"\u2022 {f['filename']} ({f['file_type']}, source: {f['source']})", styles["Normal"]))

    doc.build(story, onFirstPage=_pdf_cover_page, onLaterPages=_pdf_page_border,
              canvasmaker=_NumberedCanvas)
    return buf.getvalue()


_TABLE_CELL_STYLE = ParagraphStyle(
    name="TableCell", fontName="Helvetica", fontSize=7.5, leading=9,
    textColor=colors.HexColor("#" + INK),
)
_TABLE_HEADER_STYLE = ParagraphStyle(
    name="TableHeader", fontName="Helvetica-Bold", fontSize=7.5, leading=9,
    textColor=colors.white,
)


def _styled_table(data: list[list[str]], col_widths: list[float] | None = None) -> Table:
    # Wrap every cell in a Paragraph so long content reflows within its
    # column instead of forcing the column (and the table) to widen to fit
    # the longest unwrapped line. Without explicit col_widths, ReportLab
    # also sizes each column to its content, so both are required together
    # to keep the table inside the page frame.
    wrapped = []
    for row_idx, row in enumerate(data):
        style = _TABLE_HEADER_STYLE if row_idx == 0 else _TABLE_CELL_STYLE
        wrapped.append([Paragraph(xml_escape(str(cell)), style) for cell in row])

    if col_widths is None:
        n = len(data[0]) if data else 1
        col_widths = [PDF_FRAME_WIDTH / n] * n

    t = Table(wrapped, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#" + INK)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d8d0bd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4efe3")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t
