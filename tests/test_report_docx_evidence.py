from __future__ import annotations

import hashlib
from dataclasses import asdict

import pandas as pd
import pytest

from core.report_evidence import (
    ReportEvidenceError,
    resolve_metric,
    validate_report_evidence,
)
from core.report_schema import Finding, ModuleResult
from modules.phase2_deep_trust.m9_docx_report import docx_report
from modules.phase3_operations.m4_adversarial_validation import (
    adversarial,
    sequence_adversarial,
)
from modules.phase3_operations.m5_secure_deployment import gatekeeper, security_gate
from modules.phase3_operations.m6_runtime_integrity.watcher import (
    check_runtime_integrity,
)


def assert_citations(result):
    data = asdict(result)
    validate_report_evidence({"module_results": [data]})
    for finding in result.findings:
        assert finding.module == result.module
        assert finding.metric.startswith("details.")
        resolve_metric(data, finding.metric)


@pytest.fixture
def bound_report(tmp_path, monkeypatch):
    import onnx
    from onnx import TensorProto, helper

    from core import db
    from core.artifact_integrity import register_or_verify_artifact

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "artifact-registry.sqlite3")
    model = tmp_path / "model.onnx"
    graph = helper.make_graph(
        [helper.make_node("Identity", ["X"], ["Y"])],
        "docx-evidence",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [None, 2])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [None, 2])],
    )
    onnx.save(helper.make_model(graph), model)
    binding = register_or_verify_artifact(model)
    return {
        "model_name": "evidence",
        "model_artifact": {key: binding[key] for key in ("id", "owner_id", "sha256")},
        "module_results": [
            {
                "module": "model_verification",
                "status": "pass",
                "score": 100,
                "findings": [],
                "details": {"sha256": binding["sha256"], "file_name": model.name},
            }
        ],
    }


@pytest.mark.parametrize(
    "finding",
    [
        {"module": "runtime_integrity", "metric": ""},
        {"module": "runtime_integrity", "metric": "details.not_measured"},
        {"module": "other_module", "metric": "details.hash_matches"},
    ],
)
def test_invalid_finding_never_creates_docx_output(
    tmp_path, monkeypatch, finding, bound_report
):
    monkeypatch.setattr(docx_report, "REPORT_DIR", tmp_path)
    report = bound_report
    report["module_results"].extend(
        [
            {
                "module": "runtime_integrity",
                "status": "fail",
                "score": 0,
                "details": {"hash_matches": False},
                "findings": [{"title": "Mismatch", **finding}],
            }
        ]
    )
    output = tmp_path / "not-created" / "report.docx"
    with pytest.raises(ReportEvidenceError):
        docx_report.create_docx_report(report, output)
    assert not output.parent.exists()


def test_invalid_finding_does_not_overwrite_existing_docx(
    tmp_path, monkeypatch, bound_report
):
    monkeypatch.setattr(docx_report, "REPORT_DIR", tmp_path)
    output = tmp_path / "keep.docx"
    output.write_bytes(b"existing report")
    report = bound_report
    report["module_results"].extend(
        [
            {
                "module": "runtime_integrity",
                "findings": [
                    {"module": "runtime_integrity", "metric": "details.absent"}
                ],
            }
        ]
    )
    with pytest.raises(ReportEvidenceError):
        docx_report.create_docx_report(report, output)
    assert output.read_bytes() == b"existing report"


def test_missing_model_verification_hash_prevents_docx_output(
    tmp_path, monkeypatch, bound_report
):
    from core.artifact_integrity import ModelArtifactIntegrityError

    monkeypatch.setattr(docx_report, "REPORT_DIR", tmp_path)
    bound_report["module_results"][0]["details"].pop("sha256")
    output = tmp_path / "not-created" / "report.docx"
    with pytest.raises(ModelArtifactIntegrityError):
        docx_report.create_docx_report(bound_report, output)
    assert not output.parent.exists()


@pytest.mark.parametrize("mutation", ["tampered", "deleted"])
def test_artifact_integrity_failure_prevents_docx_output(
    tmp_path, monkeypatch, bound_report, mutation
):
    from core.artifact_integrity import ModelArtifactIntegrityError

    monkeypatch.setattr(docx_report, "REPORT_DIR", tmp_path)
    model = tmp_path / "model.onnx"
    if mutation == "deleted":
        model.unlink()
    else:
        model.write_bytes(b"changed after registration")
    output = tmp_path / "not-created" / "report.docx"
    with pytest.raises(ModelArtifactIntegrityError):
        docx_report.create_docx_report(bound_report, output)
    assert not output.parent.exists()


def test_docx_export_infers_owner_from_public_artifact_binding(
    tmp_path, monkeypatch, bound_report
):
    from core.artifact_integrity import register_or_verify_artifact

    monkeypatch.setattr(docx_report, "REPORT_DIR", tmp_path)
    binding = register_or_verify_artifact(tmp_path / "model.onnx", owner_id=17)
    bound_report["model_artifact"] = {
        key: binding[key] for key in ("id", "owner_id", "sha256")
    }
    output = docx_report.create_docx_report(bound_report, tmp_path / "owned.docx")
    assert output.is_file()


@pytest.mark.parametrize(
    "state,score",
    [
        ("missing", 0),
        ("unbaselined", 45),
        ("changed", 0),
        ("unsigned", 80),
        ("verified", 100),
    ],
)
def test_runtime_observed_conditions_have_real_citations(tmp_path, state, score):
    path = tmp_path / "model.onnx"
    metadata = {}
    if state != "missing":
        path.write_bytes(b"hash fixture")
    if state in {"changed", "unsigned", "verified"}:
        metadata["_expected_sha256"] = (
            "0" * 64
            if state == "changed"
            else hashlib.sha256(path.read_bytes()).hexdigest()
        )
        metadata["_signature_verified"] = state != "unsigned"
    result = check_runtime_integrity(path, metadata)
    assert result.score == score
    assert_citations(result)
    expected = {
        "missing": "details.artifact_available",
        "unbaselined": "details.expected_hash_available",
        "changed": "details.hash_matches",
        "unsigned": "details.hash_matches",
        "verified": "details.hash_matches",
    }
    assert result.findings[0].metric == expected[state]
    if state in {"missing", "unbaselined", "changed"}:
        assert resolve_metric(asdict(result), result.findings[0].metric) is False


def test_tabular_adversarial_failures_record_observed_error_and_columns(monkeypatch):
    def fail(*args):
        raise OSError("model unavailable")

    monkeypatch.setattr(adversarial, "load_model_backend", fail)
    result = adversarial.run_adversarial_validation("model.onnx", "test.csv")
    assert result.details["load_error"] == "model unavailable"
    assert_citations(result)
    monkeypatch.setattr(adversarial, "load_model_backend", lambda *args: object())
    monkeypatch.setattr(
        adversarial.pd, "read_csv", lambda *args: pd.DataFrame({"label": ["a"]})
    )
    result = adversarial.run_adversarial_validation(
        "model.onnx", "test.csv", {"expected_features": ["duration"]}
    )
    assert result.details["missing_columns"] == ["duration"]
    assert_citations(result)


@pytest.mark.parametrize(
    "function,f1,stability,sensitive,metric",
    [
        ("run_sequence_robustness", 0.65, 1.0, None, "worst_case_f1"),
        ("run_sequence_robustness", 0.95, 0.60, None, "minimum_prediction_stability"),
        ("run_sequence_robustness", 0.80, 1.0, None, "worst_case_f1"),
        ("run_sequence_robustness", 0.95, 0.85, None, "minimum_prediction_stability"),
        ("run_sequence_robustness", 0.95, 0.95, None, "worst_case_f1"),
        ("run_sequence_adversarial_validation", 0.65, 1.0, None, "worst_case_f1"),
        (
            "run_sequence_adversarial_validation",
            0.95,
            1.0,
            0.70,
            "worst_sensitive_recall",
        ),
        ("run_sequence_adversarial_validation", 0.80, 1.0, None, "worst_case_f1"),
        (
            "run_sequence_adversarial_validation",
            0.95,
            0.80,
            None,
            "minimum_prediction_stability",
        ),
        (
            "run_sequence_adversarial_validation",
            0.95,
            1.0,
            0.80,
            "worst_sensitive_recall",
        ),
        ("run_sequence_adversarial_validation", 0.95, 1.0, None, "worst_case_f1"),
    ],
)
def test_sequence_metrics_follow_the_actual_threshold_branch(
    monkeypatch, function, f1, stability, sensitive, metric
):
    details = {
        "baseline_f1": 1.0,
        "worst_case_f1": f1,
        "minimum_prediction_stability": stability,
        "worst_sensitive_recall": sensitive,
        "worst_case_scenario": "fixture",
    }
    monkeypatch.setattr(
        sequence_adversarial,
        "_run_sequence_scenarios",
        lambda *args: (dict(details), [{"scenario": "fixture"}], []),
    )
    result = getattr(sequence_adversarial, function)("model.onnx", "test.npz", {})
    assert result.findings[0].metric == "details." + metric
    assert_citations(result)


@pytest.mark.parametrize(
    "function", ["run_sequence_robustness", "run_sequence_adversarial_validation"]
)
def test_sequence_execution_failure_cites_the_error(monkeypatch, function):
    def fail(*args):
        raise RuntimeError()

    monkeypatch.setattr(sequence_adversarial, "_run_sequence_scenarios", fail)
    result = getattr(sequence_adversarial, function)("model.onnx", "test.npz", {})
    assert result.details["execution_error"] == "RuntimeError"
    assert_citations(result)


def test_security_gate_cites_the_failed_checks(monkeypatch):
    monkeypatch.setattr(security_gate, "get_deployment_policy", dict)
    result = security_gate.evaluate_security_gate([])
    assert result.details["failed_checks"]
    assert result.findings[0].metric == "details.failed_checks"
    assert_citations(result)


@pytest.mark.parametrize(
    "severity,decision,metric",
    [
        (None, "approved", "decision"),
        ("medium", "conditional", "medium_risk_finding_count"),
        ("high", "blocked", "failed_checks"),
    ],
)
def test_deployment_gate_cites_observed_decision_inputs(
    monkeypatch, severity, decision, metric
):
    monkeypatch.setattr(gatekeeper, "get_deployment_policy", dict)
    results = [
        ModuleResult("security_gate", "pass", 100, "", details={"decision": "passed"}),
        ModuleResult("classifier_evaluation", "pass", 100, ""),
        ModuleResult("trust_score", "pass", 100, "", details={"issued": True}),
    ]
    if severity:
        results.append(
            ModuleResult(
                "robustness_testing",
                "warning",
                90,
                "",
                [
                    Finding(
                        "robustness_testing",
                        "Measured drop",
                        severity,
                        "Drop observed.",
                        metric="details.drop",
                    )
                ],
                {"drop": 0.1},
            )
        )
    result = gatekeeper.evaluate_deployment_gate(
        results, 100, {"deployment_policy": {"minimum_trust_score": 0}}
    )
    assert result.details["decision"] == decision
    assert result.findings[0].metric == "details." + metric
    assert result.details["self_reported_policy_ignored"] is True
    assert_citations(result)
