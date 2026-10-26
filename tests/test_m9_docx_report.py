from __future__ import annotations

import onnx
import pytest
from docx import Document
from onnx import TensorProto, helper

from core import db
from core.artifact_integrity import (
    assert_report_artifact_integrity,
    register_or_verify_artifact,
)
from core.report_schema import Finding, ModuleResult, TrustReport
from core.security import SecurityValidationError
from modules.phase2_deep_trust.m9_docx_report import docx_report


@pytest.fixture
def _report(tmp_path, monkeypatch) -> TrustReport:
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "artifact-registry.sqlite3")
    model_path = tmp_path / "model.onnx"
    graph = helper.make_graph(
        [helper.make_node("Identity", ["X"], ["Y"])],
        "docx-fixture",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [None, 2])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [None, 2])],
    )
    onnx.save(helper.make_model(graph), model_path)
    binding = register_or_verify_artifact(model_path)
    module = ModuleResult(
        "classifier_evaluation",
        "warning",
        72,
        "One class needs attention.",
        [
            Finding(
                "classifier_evaluation",
                "Weak recall",
                "medium",
                "Recall was 0.70.",
                "Retrain.",
                metric="details.recall",
            )
        ],
        details={"recall": 0.70},
    )
    report = TrustReport.create(
        "Traffic Model v1",
        72,
        "warning",
        [
            module,
            ModuleResult(
                "model_verification",
                "pass",
                100,
                "Fixture hash captured.",
                details={"sha256": binding["sha256"], "file_name": model_path.name},
            ),
        ],
        ["Retrain."],
        analysis_trace=[
            {
                "step": 1,
                "module": "classifier_evaluation",
                "status": "warning",
                "score": 72,
                "method": "Holdout evaluation",
                "evidence": "Recall was 0.70",
                "conclusion": "Needs improvement",
            }
        ],
        remediation_plan=[
            {
                "id": "FIX-01",
                "priority": "P1",
                "title": "Improve recall",
                "evidence": "Recall was 0.70",
                "diagnosis": "Class imbalance",
                "fix": "Rebalance training data",
                "validation": "Recall reaches 0.90",
            }
        ],
    )
    report.model_artifact = {key: binding[key] for key in ("id", "owner_id", "sha256")}
    return report


def test_docx_report_is_generated_and_contains_assessment_evidence(
    tmp_path, monkeypatch, _report
) -> None:
    monkeypatch.setattr(docx_report, "REPORT_DIR", tmp_path)

    assert_report_artifact_integrity(_report.to_dict())
    path = docx_report.create_docx_report(_report)
    document = Document(path)
    text = "\n".join(paragraph.text for paragraph in document.paragraphs)

    assert path.parent == tmp_path
    assert path.name == "Traffic_Model_v1_trust_report.docx"
    assert path.stat().st_size > 0
    assert "Credora Trust Report" in text
    assert "Model: Traffic Model v1" in text
    assert "Deep Assessment Evidence" in text
    assert "Model-Specific Remediation Plan" in text
    assert "Evidence: classifier_evaluation.details.recall" in text
    assert any(
        paragraph.text == "Evidence: classifier_evaluation.details.recall"
        and paragraph.style.name == "Caption"
        for paragraph in document.paragraphs
    )
    assert document.tables[0].cell(1, 0).text == "classifier_evaluation"


def test_docx_report_rejects_output_outside_report_directory(
    tmp_path, monkeypatch, _report
) -> None:
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    monkeypatch.setattr(docx_report, "REPORT_DIR", report_dir)

    with pytest.raises(SecurityValidationError):
        docx_report.create_docx_report(_report, tmp_path / "escaped.docx")
