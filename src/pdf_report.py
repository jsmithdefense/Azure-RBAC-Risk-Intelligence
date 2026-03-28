from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _severity_color(severity: str) -> str:
    mapping = {
        "Critical": "#B00020",
        "High": "#D35400",
        "Medium": "#B7950B",
        "Low": "#1E8449",
    }
    return mapping.get(severity, "#111111")


def _short_sub_name(name: str) -> str:
    if len(name) <= 24:
        return name
    return f"{name[:21]}..."


def _scope_display_name(scope: str, scope_type: str) -> str:
    if scope_type == "subscription":
        return "subscription"
    parts = scope.split("/")
    try:
        rg_index = parts.index("resourceGroups")
        rg_name = parts[rg_index + 1] if rg_index + 1 < len(parts) else "unknown"
    except (ValueError, IndexError):
        return scope_type
    if scope_type == "resource" and parts:
        return f"{rg_name}/{parts[-1]}"
    return rg_name


def _footer(canvas, doc, timestamp: str) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawString(doc.leftMargin, 0.35 * inch, f"Generated: {timestamp}")
    canvas.drawRightString(letter[0] - doc.rightMargin, 0.35 * inch, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


def _p(text: str, style: ParagraphStyle) -> Paragraph:
    parts = re.split(r'\*\*(.+?)\*\*', str(text))
    xml = "".join(
        f"<b>{escape(p)}</b>" if i % 2 else escape(p)
        for i, p in enumerate(parts)
    )
    return Paragraph(xml, style)


def _split_ai_sections(summary_text: str) -> tuple[list[str], list[str]]:
    cap: list[str] = []
    rec: list[str] = []
    section = ""
    for line in summary_text.splitlines():
        stripped = line.strip()
        if stripped == "Capability Summary:":
            section = "cap"
            continue
        if stripped == "Recommended Actions:":
            section = "rec"
            continue
        if not stripped:
            continue
        if section == "cap":
            cap.append(stripped)
        elif section == "rec":
            rec.append(stripped)
    return cap, rec


def generate_pdf_report(
    report_path: str,
    selected_subs: list[dict[str, str]],
    all_records: list[Any],
    all_taxonomies: dict[str, str],
    all_actions: dict[str, str],
    role_subscriptions: dict[str, set[str]],
    subscription_risks: list[dict[str, Any]],
    top_principals: list[Any],
    principal_names: dict[tuple[str, str], str],
) -> str:
    json_report_path = Path(report_path)
    if not json_report_path.is_absolute():
        json_report_path = Path(__file__).resolve().parents[1] / json_report_path

    stem = json_report_path.stem
    timestamp_suffix = stem.removeprefix("rbac_risk_")
    pdf_name = f"rbac_risk_{timestamp_suffix}.pdf"
    pdf_report_path = json_report_path.with_name(pdf_name)

    json_payload = json.loads(json_report_path.read_text(encoding="utf-8"))
    principals_from_json = json_payload.get("principals", [])
    ai_present = any("capability_summary" in p for p in principals_from_json)
    enriched_map = {
        (p.get("id", ""), p.get("type", "")): p.get("capability_summary", "")
        for p in principals_from_json
        if p.get("capability_summary")
    }

    doc = SimpleDocTemplate(
        str(pdf_report_path),
        pagesize=letter,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.6 * inch,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Title"], fontSize=24, leading=30, spaceAfter=20)
    h_style = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14, leading=18, spaceBefore=8, spaceAfter=6)
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=10, leading=13)
    mono = ParagraphStyle("Mono", parent=body, fontName="Courier", fontSize=8.5, leading=11)
    tbl_hdr = ParagraphStyle("TblHdr", parent=body, fontName="Helvetica-Bold", fontSize=9, leading=11, spaceBefore=0, spaceAfter=0)
    tbl_cell = ParagraphStyle("TblCell", parent=body, fontSize=8.5, leading=11, spaceBefore=0, spaceAfter=0)
    tbl_cell_right = ParagraphStyle("TblCellR", parent=tbl_cell, alignment=TA_RIGHT)
    tbl_cell_mono = ParagraphStyle("TblCellMono", parent=tbl_cell, fontName="Courier", fontSize=8, leading=10)

    story = []

    tenant_name = "Multi-Subscription Analysis" if len(selected_subs) != 1 else selected_subs[0]["name"]
    generated_iso = json_payload.get("metadata", {}).get("generated_timestamp", datetime.now().isoformat(timespec="seconds"))

    # Title page
    story.append(_p("Azure RBAC Risk Report", title_style))
    story.append(Paragraph(f"<b>{tenant_name}</b>", styles["Heading3"]))
    story.append(Spacer(1, 0.18 * inch))
    story.append(_p(f"Generated: {generated_iso}", body))
    story.append(Spacer(1, 0.08 * inch))
    story.append(_p("Subscriptions analyzed:", body))
    for sub in selected_subs:
        story.append(Paragraph(f"- {sub['name']} (<font name='Courier'>{sub['id']}</font>)", body))
    story.append(PageBreak())

    # Section 1
    story.append(_p("Section 1: Tenant-Level Risk Summary", h_style))
    summary_table = Table(
        [
            ["Subscriptions analyzed", str(len(selected_subs))],
            ["Total assignments", str(len(all_records))],
            ["Unique roles", str(len(all_taxonomies))],
        ],
        colWidths=[2.4 * inch, 1.2 * inch],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 0.16 * inch))

    # Section 2
    story.append(_p("Section 2: Subscription Risk Ranking", h_style))
    ranking_rows = [
        [
            _p("Rank", tbl_hdr),
            _p("Subscription", tbl_hdr),
            _p("Risk Score", tbl_hdr),
            _p("Assignments", tbl_hdr),
            _p("Principals", tbl_hdr),
        ]
    ]
    for i, sub in enumerate(subscription_risks, 1):
        ranking_rows.append(
            [
                _p(str(i), tbl_cell_right),
                _p(sub["name"], tbl_cell),
                _p(str(sub["total_score"]), tbl_cell_right),
                _p(str(sub["assignment_count"]), tbl_cell_right),
                _p(str(sub["principal_count"]), tbl_cell_right),
            ]
        )
    ranking_table = Table(
        ranking_rows,
        colWidths=[
            0.58 * inch,
            3.36 * inch,
            0.88 * inch,
            1.20 * inch,
            0.88 * inch,
        ],
    )
    ranking_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEF8")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(ranking_table)
    story.append(Spacer(1, 0.16 * inch))

    # Section 3
    story.append(_p("Section 3: Assigned Role Classifications", h_style))
    role_rows = [
        [
            _p("Role", tbl_hdr),
            _p("Classification", tbl_hdr),
            _p("Triggering Action", tbl_hdr),
            _p("Subscriptions", tbl_hdr),
        ]
    ]
    for role_name in sorted(all_taxonomies.keys(), key=str.lower):
        subs = sorted(role_subscriptions.get(role_name, set()))
        role_rows.append(
            [
                _p(role_name, tbl_cell),
                _p(all_taxonomies.get(role_name, "custom_or_unknown"), tbl_cell),
                _p(all_actions.get(role_name, "") or "N/A", tbl_cell),
                _p(", ".join(subs) if subs else "N/A", tbl_cell),
            ]
        )
    role_table = Table(
        role_rows,
        colWidths=[1.70 * inch, 1.30 * inch, 1.20 * inch, 2.90 * inch],
        repeatRows=1,
    )
    role_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEF8")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(role_table)
    story.append(PageBreak())

    # Section 4
    story.append(_p("Section 4: Principal Risk Analysis", h_style))
    sub_id_to_name = {s["id"]: s["name"] for s in selected_subs}
    for principal in top_principals:
        p_name = principal_names.get((principal.principal_id, principal.principal_type), principal.principal_id)
        sev = principal.cumulative_severity
        sev_color = _severity_color(sev)
        story.append(
            Paragraph(
                f"<b>{p_name}</b> | Type: {principal.principal_type} | "
                f"Severity: <font color='{sev_color}'><b>{sev}</b></font> | "
                f"Score: <b>{principal.cumulative_score}</b> | "
                f"Riskiest Role: {principal.highest_assignment.record.role_name}",
                body,
            )
        )
        story.append(Paragraph(f"ID: <font name='Courier'>{principal.principal_id}</font>", mono))
        assign_rows = [
            [
                _p("Severity", tbl_hdr),
                _p("Score", tbl_hdr),
                _p("Role", tbl_hdr),
                _p("Classification", tbl_hdr),
                _p("Action", tbl_hdr),
                _p("Scope", tbl_hdr),
                _p("Subscription", tbl_hdr),
            ]
        ]
        for sa in principal.risky_assignments:
            r = sa.record
            scope_disp = _scope_display_name(r.scope, r.scope_type)
            sev_color = _severity_color(sa.severity)
            sub_nm = sub_id_to_name.get(r.subscription_id, r.subscription_id)
            assign_rows.append(
                [
                    Paragraph(
                        f"<font color='{sev_color}'><b>{escape(sa.severity)}</b></font>",
                        tbl_cell,
                    ),
                    _p(str(sa.score), tbl_cell_right),
                    _p(r.role_name, tbl_cell),
                    _p(sa.bucket, tbl_cell),
                    _p(sa.triggering_action or "N/A", tbl_cell),
                    Paragraph(
                        f"<font name='Courier'>{escape(scope_disp)} ({escape(r.scope_type)})</font>",
                        tbl_cell_mono,
                    ),
                    _p(sub_nm, tbl_cell),
                ]
            )
        assign_table = Table(
            assign_rows,
            colWidths=[0.72 * inch, 0.52 * inch, 1.05 * inch, 1.05 * inch, 0.95 * inch, 1.45 * inch, 1.21 * inch],
            repeatRows=1,
        )
        assign_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEF8")),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(assign_table)
        story.append(Spacer(1, 0.12 * inch))

    # Section 5 (optional)
    if ai_present:
        story.append(PageBreak())
        story.append(_p("Section 5: AI Enrichment Summary", h_style))
        for principal in top_principals:
            key = (principal.principal_id, principal.principal_type)
            summary = enriched_map.get(key, "")
            if not summary:
                continue
            p_name = principal_names.get(key, principal.principal_id)
            story.append(Paragraph(f"<b>{p_name}</b>", styles["Heading4"]))
            cap_lines, rec_lines = _split_ai_sections(summary)
            story.append(Paragraph("<b>Capability Summary</b>", body))
            for line in cap_lines:
                story.append(_p(line, body))
            story.append(Spacer(1, 0.06 * inch))
            story.append(Paragraph("<b>Recommended Actions</b>", body))
            for line in rec_lines:
                story.append(_p(line, body))
            story.append(Spacer(1, 0.10 * inch))

    doc.build(story, onFirstPage=lambda c, d: _footer(c, d, generated_iso), onLaterPages=lambda c, d: _footer(c, d, generated_iso))
    return str(Path("reports") / pdf_name)
