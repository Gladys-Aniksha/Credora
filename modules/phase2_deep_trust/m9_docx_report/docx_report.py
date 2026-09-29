from __future__ import annotations

from pathlib import Path
from typing import Any

from core.config import REPORT_DIR
from core.security import ensure_within_directory, slugify_filename


def create_docx_report(report: Any, output_path: str | Path | None = None) -> Path:
    try:
        from docx import Document
        from docx.shared import Inches
    except ImportError as exc:  # noqa: BLE001
        raise RuntimeError("python-docx is required for DOCX report export. Run: pip install python-docx") from exc

    report_dict = report.to_dict() if hasattr(report, "to_dict") else dict(report)
    model_name = report_dict.get("model_name", "model")
    path = Path(output_path) if output_path else REPORT_DIR / f"{slugify_filename(model_name)}_trust_report.docx"
    path = ensure_within_directory(path, REPORT_DIR)
    path.parent.mkdir(parents=True, exist_ok=True)

    doc = Document()
    section = doc.sections[0]
    section.top_margin = Inches(0.6)
    section.bottom_margin = Inches(0.6)
    section.left_margin = Inches(0.7)
    section.right_margin = Inches(0.7)

    doc.add_heading("Credora Trust Report", 0)
    doc.add_paragraph(f"Model: {model_name}")
    doc.add_paragraph(f"Generated at: {report_dict.get('generated_at', 'unknown')}")
    trust_result = next(
        (result for result in report_dict.get("module_results", []) if result.get("module") == "trust_score"),
        {},
    )
    if trust_result.get("details", {}).get("issued") is False:
        doc.add_paragraph("Final trust score: Not issued because the Security Gate failed")
    else:
        doc.add_paragraph(f"Final trust score: {report_dict.get('trust_score', 0)}/100")
    doc.add_paragraph(f"Deployment status: {report_dict.get('status', 'unknown')}")

    threat_model = report_dict.get("threat_model", {})
    if threat_model:
        summary = threat_model.get("summary", {})
        doc.add_heading("Threat Model", level=1)
        doc.add_paragraph(
            f"Overall posture: {summary.get('overall_threat_posture', 'UNKNOWN')} | "
            f"Threats: {summary.get('threats_identified', 0)} | "
            f"Critical: {summary.get('critical', 0)} | High: {summary.get('high', 0)} | "
            f"Mitigated: {summary.get('mitigated', 0)} | Not assessed: {summary.get('not_assessed', 0)}"
        )
        important = [
            threat
            for threat in threat_model.get("threats", [])
            if threat.get("residual_severity") in {"Critical", "High"}
            or threat.get("detection_status") in {"HIGH RISK", "DETECTED"}
        ]
        if important:
            for threat in important:
                doc.add_heading(f"{threat.get('id')}: {threat.get('name')}", level=2)
                doc.add_paragraph(
                    f"Status: {threat.get('detection_status')} | "
                    f"Residual risk: {threat.get('residual_severity')}"
                )
                doc.add_paragraph(f"Controls: {', '.join(threat.get('existing_controls', []))}")
                doc.add_paragraph(f"Residual risk: {threat.get('residual_explanation', '')}")
        else:
            doc.add_paragraph("No critical or high residual threats were identified by available evidence.")

        doc.add_heading("Threat-to-Control Mapping", level=2)
        matrix = doc.add_table(rows=1, cols=4)
        matrix.style = "Table Grid"
        for cell, title in zip(matrix.rows[0].cells, ("Threat", "Existing Control", "Result", "Residual Risk")):
            cell.text = title
        for row in threat_model.get("control_matrix", []):
            cells = matrix.add_row().cells
            cells[0].text = str(row.get("threat", ""))
            cells[1].text = str(row.get("existing_control", ""))
            cells[2].text = str(row.get("result", ""))
            cells[3].text = str(row.get("residual_risk", ""))

        doc.add_heading("Security Assumptions", level=2)
        for assumption in threat_model.get("security_assumptions", []):
            doc.add_paragraph(str(assumption), style="List Bullet")
        doc.add_heading("Out-of-Scope Threats", level=2)
        for threat in threat_model.get("out_of_scope_threats", []):
            doc.add_paragraph(str(threat), style="List Bullet")

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

    analysis_trace = report_dict.get("analysis_trace", [])
    doc.add_heading("Deep Assessment Evidence", level=1)
    if analysis_trace:
        for step in analysis_trace:
            doc.add_heading(
                f"Step {step.get('step', '')}: {str(step.get('module', 'assessment')).replace('_', ' ').title()}",
                level=2,
            )
            doc.add_paragraph(f"Status: {step.get('status', 'unknown')} | Score: {step.get('score', 0)}/100")
            doc.add_paragraph(f"Method: {step.get('method', '')}")
            doc.add_paragraph(f"Observed evidence: {step.get('evidence', '')}")
            doc.add_paragraph(f"Conclusion: {step.get('conclusion', '')}")
    else:
        doc.add_paragraph("No detailed analysis trace was recorded for this legacy report.")

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

    remediation_plan = report_dict.get("remediation_plan", [])
    doc.add_heading("Model-Specific Remediation Plan", level=1)
    if remediation_plan:
        for item in remediation_plan:
            doc.add_heading(f"{item.get('id', 'FIX')} [{item.get('priority', 'P2')}] {item.get('title', 'Corrective action')}", level=2)
            doc.add_paragraph(f"Evidence: {item.get('evidence', '')}")
            doc.add_paragraph(f"Diagnosis: {item.get('diagnosis', '')}")
            doc.add_paragraph(f"Required change: {item.get('fix', '')}")
            doc.add_paragraph(f"Retest condition: {item.get('validation', '')}")
    else:
        doc.add_paragraph("No corrective action is required by the current assessment evidence.")

    doc.save(path)
    return path
