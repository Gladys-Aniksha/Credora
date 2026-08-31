from __future__ import annotations

from pathlib import Path
from typing import Any

from core.config import REPORT_DIR


def create_docx_report(report: Any, output_path: str | Path | None = None) -> Path:
    try:
        from docx import Document
        from docx.shared import Inches
    except ImportError as exc:  # noqa: BLE001
        raise RuntimeError("python-docx is required for DOCX report export. Run: pip install python-docx") from exc

    report_dict = report.to_dict() if hasattr(report, "to_dict") else dict(report)
    model_name = report_dict.get("model_name", "model")
    path = Path(output_path) if output_path else REPORT_DIR / f"{model_name}_trust_report.docx"
    path.parent.mkdir(parents=True, exist_ok=True)

    doc = Document()
    section = doc.sections[0]
    section.top_margin = Inches(0.6)
    section.bottom_margin = Inches(0.6)
    section.left_margin = Inches(0.7)
    section.right_margin = Inches(0.7)

    doc.add_heading("TrustAI Sentinel Trust Report", 0)
    doc.add_paragraph(f"Model: {model_name}")
    doc.add_paragraph(f"Generated at: {report_dict.get('generated_at', 'unknown')}")
    doc.add_paragraph(f"Final trust score: {report_dict.get('trust_score', 0)}/100")
    doc.add_paragraph(f"Deployment status: {report_dict.get('status', 'unknown')}")

    doc.add_heading("Module Results", level=1)
    table = doc.add_table(rows=1, cols=4)
    table.style = "Table Grid"
    headers = table.rows[0].cells
    headers[0].text = "Module"
    headers[1].text = "Status"
    headers[2].text = "Score"
    headers[3].text = "Summary"
    for result in report_dict.get("module_results", []):
        cells = table.add_row().cells
        cells[0].text = str(result.get("module", ""))
        cells[1].text = str(result.get("status", ""))
        cells[2].text = str(result.get("score", ""))
        cells[3].text = str(result.get("summary", ""))

    doc.add_heading("Findings", level=1)
    for result in report_dict.get("module_results", []):
        findings = result.get("findings", [])
        if not findings:
            continue
        doc.add_heading(str(result.get("module", "Module")).replace("_", " ").title(), level=2)
        for finding in findings:
            doc.add_paragraph(f"{finding.get('title', 'Finding')} [{finding.get('severity', 'info')}]", style="List Bullet")
            doc.add_paragraph(str(finding.get("description", "")))
            recommendation = finding.get("recommendation")
            if recommendation:
                doc.add_paragraph(f"Recommendation: {recommendation}")

    recommendations = report_dict.get("recommendations", [])
    doc.add_heading("Deployment Recommendations", level=1)
    if recommendations:
        for recommendation in recommendations:
            doc.add_paragraph(str(recommendation), style="List Bullet")
    else:
        doc.add_paragraph("No recommendations were generated.")

    doc.save(path)
    return path
