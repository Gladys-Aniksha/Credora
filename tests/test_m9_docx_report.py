from __future__ import annotations

from docx import Document
import pytest

from core.report_schema import Finding, ModuleResult, TrustReport
from core.security import SecurityValidationError
from modules.phase2_deep_trust.m9_docx_report import docx_report


def _report() -> TrustReport:
    module = ModuleResult(
        "classifier_evaluation",
        "warning",
        72,
        "One class needs attention.",
        [Finding("classifier_evaluation", "Weak recall", "medium", "Recall was 0.70.", "Retrain.")],
    )
    return TrustReport.create(
        "Traffic Model v1",
        72,
        "warning",
        [module],
        ["Retrain."],
        analysis_trace=[{
            "step": 1,
            "module": "classifier_evaluation",
            "status": "warning",
            "score": 72,
            "method": "Holdout evaluation",
            "evidence": "Recall was 0.70",
            "conclusion": "Needs improvement",
        }],
        remediation_plan=[{
            "id": "FIX-01",
            "priority": "P1",
            "title": "Improve recall",
            "evidence": "Recall was 0.70",
            "diagnosis": "Class imbalance",
            "fix": "Rebalance training data",
            "validation": "Recall reaches 0.90",
        }],
    )


def test_docx_report_is_generated_and_contains_assessment_evidence(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(docx_report, "REPORT_DIR", tmp_path)

    path = docx_report.create_docx_report(_report())
    document = Document(path)
    text = "\n".join(paragraph.text for paragraph in document.paragraphs)

    assert path.parent == tmp_path
    assert path.name == "Traffic_Model_v1_trust_report.docx"
    assert path.stat().st_size > 0
    assert "Credora Trust Report" in text
    assert "Model: Traffic Model v1" in text
    assert "Deep Assessment Evidence" in text
    assert "Model-Specific Remediation Plan" in text
    assert document.tables[0].cell(1, 0).text == "classifier_evaluation"


def test_docx_report_rejects_output_outside_report_directory(tmp_path, monkeypatch) -> None:
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    monkeypatch.setattr(docx_report, "REPORT_DIR", report_dir)

    with pytest.raises(SecurityValidationError):
        docx_report.create_docx_report(_report(), tmp_path / "escaped.docx")
