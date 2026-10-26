from __future__ import annotations

import copy
from dataclasses import asdict
from types import SimpleNamespace

import numpy as np
import pytest

from core.report_evidence import (
    ReportEvidenceError,
    resolve_metric,
    validate_report_evidence,
)
from core.report_schema import Finding, ModuleResult, TrustReport


def report_for(result):
    return TrustReport.create("evidence-test", result.score, result.status, [result], [])


def observed_result():
    return ModuleResult(
        "classifier_evaluation", "pass", 93, "Measured classifier result",
        [Finding("classifier_evaluation", "Observed F1", "info", "F1 was measured.",
                 metric="details.class_metrics.test-class.f1")],
        {"class_metrics": {"test-class": {"f1": 0.93}}, "samples": [{"count": 0}],
         "available": False, "empty": []},
    )


@pytest.mark.parametrize("metric,expected", [
    ("score", 93), ("status", "pass"), ("details.class_metrics.test-class.f1", 0.93),
    ("details.samples.0.count", 0), ("details.available", False), ("details.empty", []),
])
def test_explicit_metrics_resolve_actual_values(metric, expected):
    result = observed_result()
    result.findings[0].metric = metric
    assert resolve_metric(asdict(result), metric) == expected
    report = report_for(result)
    validate_report_evidence(report)
    payload = report.to_dict()
    assert payload["module_results"][0]["findings"][0]["metric"] == metric
    assert payload["model_artifact"] == {}


@pytest.mark.parametrize("metric", [
    "", " ", None, 3, "details.unknown", "accuracy", "summary", "details", "score.value",
    "status.value", "details.samples.1.count", "details.samples.-1.count", "details.samples[0].count",
    "details.samples.0.__class__", "details.samples.0.count.numerator", "details..available",
    "details.samples.0.count()", "__import__('os').system('echo invalid')", " score",
    "details.samples." + "9" * 5000,
])
def test_missing_unknown_or_expression_metrics_are_rejected_without_retrofit(metric):
    payload = asdict(report_for(observed_result()))
    finding = payload["module_results"][0]["findings"][0]
    finding["metric"] = metric
    original = copy.deepcopy(payload)
    with pytest.raises(ReportEvidenceError):
        validate_report_evidence(payload)
    assert payload == original


def test_legacy_dictionary_remains_readable_but_cannot_be_exported_as_evidence():
    payload = asdict(report_for(observed_result()))
    del payload["module_results"][0]["findings"][0]["metric"]
    assert payload["module_results"][0]["findings"][0]["title"] == "Observed F1"
    with pytest.raises(ReportEvidenceError, match="nonempty explicit"):
        validate_report_evidence(payload)
    assert "metric" not in payload["module_results"][0]["findings"][0]


def test_finding_from_another_existing_module_cannot_borrow_its_evidence():
    payload = asdict(report_for(observed_result()))
    payload["module_results"].append(asdict(ModuleResult("other", "pass", 100, "Another result")))
    payload["module_results"][0]["findings"][0]["module"] = "other"
    with pytest.raises(ReportEvidenceError, match="containing actual module"):
        validate_report_evidence(payload)


def test_duplicate_actual_modules_rejected_even_without_findings():
    result = asdict(ModuleResult("same", "pass", 100, "Measured"))
    with pytest.raises(ReportEvidenceError, match="Duplicate"):
        validate_report_evidence({"module_results": [result, result]})


@pytest.mark.parametrize("payload", [
    {}, [], {"module_results": {}}, {"module_results": [None]},
    {"module_results": [{"module": ""}]}, {"module_results": [{"module": " "}]},
    {"module_results": [{"module": "actual", "findings": {}}]},
    {"module_results": [{"module": "actual", "findings": [None]}]},
])
def test_malformed_evidence_structure_rejected(payload):
    with pytest.raises(ReportEvidenceError):
        validate_report_evidence(payload)


def test_appended_fabricated_finding_blocks_serialization():
    report = report_for(observed_result())
    report.module_results[0].findings.append(Finding(
        "classifier_evaluation", "Fabricated privacy guarantee", "info", "No measured source exists.",
    ))
    with pytest.raises(ReportEvidenceError, match="nonempty explicit"):
        report.to_dict()
    assert report.module_results[0].findings[-1].metric == ""


def test_finding_positional_compatibility_and_independent_artifact_defaults():
    finding = Finding("module", "title", "info", "description", "recommendation")
    assert finding.recommendation == "recommendation" and finding.metric == ""
    first, second = report_for(observed_result()), report_for(observed_result())
    first.model_artifact["sha256"] = "measured-model-hash"
    assert second.model_artifact == {}
    assert first.to_dict()["model_artifact"]["sha256"] == "measured-model-hash"


@pytest.mark.parametrize("case", ["missing", "unsupported", "invalid", "risky", "hash-match", "hash-mismatch"])
def test_verifier_findings_cite_observed_evidence(tmp_path, monkeypatch, case):
    from core.hashing import sha256_file
    from modules.phase1_foundation.m1_model_verification import verifier

    model = tmp_path / ("model.bin" if case == "unsupported" else "model.joblib")
    metadata = {}
    if case != "missing":
        model.write_bytes(b"observed bytes")
        monkeypatch.setattr(verifier, "verify_model_file_type", lambda path: case != "invalid")
        if case.startswith("hash-"):
            metadata = {"_expected_sha256": sha256_file(model) if case == "hash-match" else "different",
                        "sha256": "self-reported", "model_name": "name", "version": "1",
                        "_signature_verified": True}
    result = verifier.verify_model(model, metadata)
    assert result.findings
    report_for(result).to_dict()
    assert all(finding.metric.startswith("details.") for finding in result.findings)


@pytest.mark.parametrize("case", ["missing", "standalone", "clean", "vulnerable", "failed", "exception", "invalid-json"])
def test_dependency_findings_cite_audit_or_availability_evidence(tmp_path, monkeypatch, case):
    from modules.phase1_foundation.m2_dependency_scanner import scanner

    path = tmp_path / "requirements.txt"
    if case not in {"missing", "standalone"}:
        path.write_text("observed-package==1\n")

    def audit(*args, **kwargs):
        if case == "exception":
            raise OSError("observed audit unavailable")
        payload = '{"dependencies": []}'
        if case == "vulnerable":
            payload = '{"dependencies": [{"name": "observed-package", "vulns": [{"id": "observed-id"}]}]}'
        if case == "invalid-json":
            payload = "{invalid"
        return SimpleNamespace(stdout=payload, stderr="observed audit failure" if case == "failed" else "",
                               returncode=2 if case == "failed" else 0)

    monkeypatch.setattr(scanner.subprocess, "run", audit)
    metadata = {"input_type": "sequence"} if case == "standalone" else {}
    result = scanner.scan_dependencies(path, metadata)
    report_for(result).to_dict()
    if case in {"failed", "exception", "invalid-json"}:
        assert result.details["audit_error"]


@pytest.mark.parametrize("case", ["model-missing", "dataset-missing", "model-load", "dataset-load", "target", "features"])
def test_classifier_failure_findings_cite_actual_availability_or_errors(tmp_path, monkeypatch, case):
    from modules.phase1_foundation.m8_etc_classifier import evaluate

    model, dataset = tmp_path / "model.onnx", tmp_path / "dataset.csv"
    if case != "model-missing":
        model.touch()
    if case != "dataset-missing":
        dataset.write_text("feature,label\n1,A\n")

    def load(*args):
        if case == "model-load":
            raise ValueError("observed invalid model")
        return object()

    monkeypatch.setattr(evaluate, "load_model_backend", load)
    if case == "dataset-load":
        monkeypatch.setattr(evaluate.pd, "read_csv", lambda path: (_ for _ in ()).throw(ValueError("observed CSV error")))
    metadata = {"target_column": "absent"} if case == "target" else {"expected_features": ["absent"]}
    result = evaluate.evaluate_classifier(model, dataset, metadata)
    assert result.status == "fail"
    assert len(result.findings) == 1
    report_for(result).to_dict()


@pytest.mark.parametrize("predictions", [list("AAAABBBB"), list("AAABABBB"), list("AAAAAAAA")])
def test_classifier_measured_findings_resolve_specific_metrics(tmp_path, monkeypatch, predictions):
    from modules.phase1_foundation.m8_etc_classifier import evaluate

    model, dataset = tmp_path / "model.onnx", tmp_path / "dataset.csv"
    model.touch()
    dataset.write_text("feature,label\n" + "".join(f"{i},{label}\n" for i, label in enumerate("AAAABBBB")))
    monkeypatch.setattr(evaluate, "load_model_backend", lambda *args: SimpleNamespace(
        predict=lambda features: np.asarray(predictions),
    ))
    result = evaluate.evaluate_classifier(model, dataset)
    payload = report_for(result).to_dict()
    assert result.details["expected_features_available"] is False
    assert result.details["f1_score"] <= 1
    assert all(item["metric"] != "score" for item in payload["module_results"][0]["findings"])


def test_trust_aggregator_missing_modules_and_high_risk_count_are_observed(monkeypatch):
    from modules.phase1_foundation.m11_trust_score import aggregator

    monkeypatch.setattr(aggregator, "get_trust_weights", lambda: {"present": 0.5, "absent": 0.5})
    source = ModuleResult("present", "fail", 0, "Observed failure", [
        Finding("present", "Measured high risk", "high", "Observed error", metric="status"),
    ])
    result = aggregator.calculate_trust_score([source], ("present", "absent"))
    report_for(result).to_dict()
    assert result.details["missing_modules"] == ["absent"]
    assert result.details["high_risk_finding_count"] == 1
    assert result.findings[0].metric == "details.missing_modules.0"
