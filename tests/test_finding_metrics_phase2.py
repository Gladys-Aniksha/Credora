from __future__ import annotations

import ast
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import numpy as np
import pandas as pd
import pytest

from core.report_evidence import resolve_metric, validate_report_evidence
from core.sequence_data import SequenceDataset
from modules.phase2_deep_trust.m3_robustness_testing import robustness
from modules.phase2_deep_trust.m4_data_drift import drift
from modules.phase2_deep_trust.m5_explainability import explain
from modules.phase2_deep_trust.m6_model_risk import risk
from modules.phase2_deep_trust.m7_trust_drift import trust_drift
from modules.phase2_deep_trust.m8_behavior_analysis import behavior
from modules.phase2_deep_trust.m10_dataset_leakage import leakage
from modules.phase2_deep_trust.m11_privacy_risk import privacy


def citations(result):
    payload = asdict(result)
    validate_report_evidence({"module_results": [payload]})
    assert result.findings
    for finding in result.findings:
        assert finding.module == result.module
        assert finding.metric.startswith("details.")
        resolve_metric(payload, finding.metric)
    return {finding.title: finding for finding in result.findings}


@pytest.fixture
def files(tmp_path, monkeypatch):
    folder = tmp_path / "data"
    folder.mkdir()
    train, test = folder / "train.csv", folder / "test.csv"
    pd.DataFrame({"x": np.arange(20), "label": ["A"] * 20}).to_csv(train, index=False)
    pd.DataFrame({"x": np.arange(100, 120), "label": ["A"] * 20}).to_csv(test, index=False)
    for module in (drift, leakage, privacy):
        monkeypatch.setattr(module, "DATA_DIR", folder)
    monkeypatch.setattr(drift, "PROJECT_ROOT", tmp_path)
    return SimpleNamespace(train=train, test=test, metadata={
        "training_dataset_path": "data/train.csv", "expected_features": ["x"], "target_column": "label",
    })


def backend():
    return SimpleNamespace(
        predict=lambda values: np.repeat("A", len(values)),
        predict_proba=lambda values: np.tile([0.9, 0.1], (len(values), 1)),
        feature_importance=lambda columns: [{"feature": name, "importance": 1 / len(columns)} for name in columns],
    )


def test_every_owned_finding_constructor_has_an_explicit_metric():
    root = Path(__file__).resolve().parents[1] / "modules" / "phase2_deep_trust"
    count = 0
    for path in root.rglob("*.py"):
        if "m9_docx_report" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Finding":
                metrics = [keyword.value for keyword in node.keywords if keyword.arg == "metric"]
                assert len(metrics) == 1, (path, node.lineno)
                assert not isinstance(metrics[0], ast.Constant) or metrics[0].value, (path, node.lineno)
                count += 1
    assert count > 0


@pytest.mark.parametrize("sequence", [False, True])
@pytest.mark.parametrize("module,entry", [
    (robustness, robustness.test_robustness), (drift, drift.detect_data_drift),
    (explain, explain.explain_model), (behavior, behavior.analyze_behavior),
    (leakage, leakage.check_dataset_leakage), (privacy, privacy.assess_privacy_risk),
])
def test_read_and_inference_setup_errors_cite_the_caught_error(files, monkeypatch, sequence, module, entry):
    failure = Mock(side_effect=ValueError("observed incompatible input"))
    metadata = {**files.metadata, "input_type": "sequence" if sequence else "tabular"}
    if module is robustness and sequence:
        from modules.phase3_operations.m4_adversarial_validation import (
            sequence_adversarial,
        )
        monkeypatch.setattr(sequence_adversarial, "load_sequence_dataset", failure)
    elif module is drift or (module is leakage and not sequence):
        if sequence:
            monkeypatch.setattr(module, "load_sequence_dataset", failure)
        else:
            monkeypatch.setattr(module.pd, "read_csv", failure)
    elif module is leakage:
        monkeypatch.setattr(module, "load_sequence_dataset", failure)
    else:
        monkeypatch.setattr(module, "load_model_backend", failure)
    result = entry(files.test, metadata) if module is drift else entry("model.onnx", files.test, metadata)
    citations(result)
    for finding in result.findings:
        assert resolve_metric(asdict(result), finding.metric) == "observed incompatible input"


@pytest.mark.parametrize("sequence", [False, True])
@pytest.mark.parametrize("module,entry", [(drift, drift.detect_data_drift),
    (leakage, leakage.check_dataset_leakage), (privacy, privacy.assess_privacy_risk)])
def test_unavailable_baseline_records_actual_availability(files, sequence, module, entry):
    metadata = {"input_type": "sequence" if sequence else "tabular"}
    result = entry(files.test, metadata) if module is drift else entry("model.onnx", files.test, metadata)
    citations(result)
    key = "baseline_available" if module is drift else "training_dataset_available"
    assert result.details[key] is False
    assert result.findings[0].metric == "details." + key
    assert result.score == 65


@pytest.mark.parametrize("module,entry,key", [
    (robustness, robustness.test_robustness, "target_column_present"),
    (behavior, behavior.analyze_behavior, "target_column_present"),
    (behavior, behavior.analyze_behavior, "missing_features"),
    (explain, explain.explain_model, "feature_columns"),
    (leakage, leakage.check_dataset_leakage, "common_features"),
    (privacy, privacy.assess_privacy_risk, "feature_columns"),
])
def test_schema_failures_cite_observed_missing_columns(files, monkeypatch, module, entry, key):
    if hasattr(module, "load_model_backend"):
        monkeypatch.setattr(module, "load_model_backend", lambda *args: backend())
    metadata = {**files.metadata, "expected_features": ["absent"]}
    if key == "target_column_present":
        metadata["target_column"] = "absent"
    result = entry("model.onnx", files.test, metadata)
    citations(result)
    assert result.findings[0].metric == "details." + key
    assert result.details[key] == (["absent"] if key == "missing_features" else False if key.endswith("present") else [])
    assert result.score == 0


def test_no_numeric_robustness_features(files, monkeypatch):
    monkeypatch.setattr(robustness, "load_model_backend", lambda *args: backend())
    pd.DataFrame({"x": ["words"], "label": ["A"]}).to_csv(files.test, index=False)
    result = robustness.test_robustness("model.onnx", files.test, files.metadata)
    citations(result)
    assert result.details["perturbed_features"] == []
    assert result.score == 60


@pytest.mark.parametrize("f1,stability,metric", [
    (0.60, 0.95, "worst_case_f1"), (0.95, 0.70, "minimum_prediction_stability"),
    (0.80, 0.95, "worst_case_f1"), (0.95, 0.85, "minimum_prediction_stability"),
    (0.95, 0.95, "worst_case_f1"),
])
def test_delegated_sequence_robustness_cites_its_actual_measurements(files, monkeypatch, f1, stability, metric):
    from modules.phase3_operations.m4_adversarial_validation import sequence_adversarial

    measured = {"baseline_f1": 1.0, "worst_case_f1": f1, "minimum_prediction_stability": stability}
    monkeypatch.setattr(sequence_adversarial, "_run_sequence_scenarios", lambda *args: (measured, [], []))
    result = robustness.test_robustness("model.onnx", files.test, {"input_type": "sequence"})
    citations(result)
    assert result.findings[0].metric == "details." + metric


def test_sequence_explanation_without_probabilities_cites_observed_error(files, monkeypatch):
    model = backend()
    model.predict_proba = lambda values: None
    monkeypatch.setattr(explain, "load_model_backend", lambda *args: model)
    monkeypatch.setattr(explain, "load_sequence_dataset", lambda *args: SequenceDataset(np.ones((2, 4)), np.repeat("A", 2)))
    result = explain.explain_model("model.onnx", files.test, {"input_type": "sequence"})
    citations(result)
    assert "did not expose probability outputs" in result.details["error"]
    assert result.score == 60


@pytest.mark.parametrize("wrong_baseline", [False, True])
@pytest.mark.parametrize("changed", [0, 3, 6])
def test_robustness_cites_the_triggering_drop_or_stability(files, monkeypatch, changed, wrong_baseline):
    initial = "B" if wrong_baseline else "A"
    altered = np.repeat(initial, 20)
    altered[:changed] = "C" if wrong_baseline else "B"
    model = SimpleNamespace(predict=Mock(side_effect=[np.repeat(initial, 20)] + [altered] * 25))
    monkeypatch.setattr(robustness, "load_model_backend", lambda *args: model)
    result = robustness.test_robustness("model.onnx", files.test, files.metadata)
    citations(result)
    expected = "details.perturbed_f1" if changed == 0 else "details.prediction_stability" if wrong_baseline else "details.f1_drop"
    assert result.findings[0].metric == expected
    assert result.details["trial_count"] == 25


@pytest.mark.parametrize("sequence", [False, True])
@pytest.mark.parametrize("psi", [0.0, 0.15, 0.30])
def test_drift_success_paths_cite_computed_distributions(files, monkeypatch, sequence, psi):
    if sequence:
        data = SequenceDataset(np.ones((20, 4), dtype=np.int64), np.repeat("A", 20))
        monkeypatch.setattr(drift, "load_sequence_dataset", lambda *args: data)
    monkeypatch.setattr(drift, "_psi", lambda *args: psi)
    result = drift.detect_data_drift(files.test, {**files.metadata, "input_type": "sequence" if sequence else "tabular"})
    citations(result)
    assert result.details["max_psi"] == psi
    assert result.findings[0].metric == ("details.drifted_features" if psi == 0.15 else "details.max_psi")


def test_unsafe_drift_path_cites_the_rejection(files):
    result = drift.detect_data_drift(files.test, {"training_dataset_path": "../../outside.csv"})
    citations(result)
    assert result.findings[0].metric == "details.error"
    assert result.details["error"]


@pytest.mark.parametrize("mode", ["native", "distributed", "shap", "shap_error"])
def test_tabular_explanations_preserve_native_wording_and_cite_influence(files, monkeypatch, mode):
    model = backend()
    model.feature_importance = lambda columns: (
        [{"feature": "x", "importance": 0.8}] if mode == "native" else
        [{"feature": "x", "importance": 0.2}] if mode == "distributed" else []
    )
    monkeypatch.setattr(explain, "load_model_backend", lambda *args: model)
    shap = Mock(side_effect=ValueError("observed SHAP error")) if mode == "shap_error" else Mock(return_value=([{"feature": "x", "importance": 0.9}], "shap"))
    monkeypatch.setattr(explain, "_shap_importance", shap)
    result = explain.explain_model("model.onnx", files.test, files.metadata)
    findings = citations(result)
    if mode in {"native", "distributed"}:
        assert "native model" in result.summary
        shap.assert_not_called()
    elif mode == "shap":
        assert findings["SHAP fallback explanation used"].metric == "details.method"
        assert "native feature importance" in findings["SHAP fallback explanation used"].description
    else:
        assert result.details["error"] == "observed SHAP error"
        assert result.score == 60


@pytest.mark.parametrize("position", [0, 4])
def test_sequence_explanation_cites_occlusion_arrays(files, monkeypatch, position):
    values = np.ones((3, 8), dtype=np.int64)
    monkeypatch.setattr(explain, "load_sequence_dataset", lambda *args: SequenceDataset(values, np.repeat("A", 3)))
    model = backend()
    model.predict_proba = lambda data: np.column_stack((0.6 + data[:, position] * 0.1, 0.4 - data[:, position] * 0.1))
    monkeypatch.setattr(explain, "load_model_backend", lambda *args: model)
    result = explain.explain_model("model.onnx", files.test, {"input_type": "sequence"})
    citations(result)
    assert result.findings[0].metric == ("details.top_saliency" if position == 0 else "details.saliency")
    assert result.details["top_saliency"][0]["position_start"] == position


@pytest.mark.parametrize("case", ["missing", "complete", "serialization", "metadata_missing", "incomplete",
                                  "sequence", "features", "self_reported", "large", "moderate"])
def test_model_risk_indicators_have_specific_evidence(files, case):
    path = files.train.parent / ("model.pkl" if case == "serialization" else "model.onnx")
    metadata = {"model_name": "model", "version": "1", "algorithm": "test", "framework": "test",
                "task": "classification", "target_column": "label", "expected_features": ["x"],
                "_signature_verified": True}
    if case != "missing":
        with path.open("wb") as stream:
            stream.truncate((101 if case == "large" else 26 if case == "moderate" else 0) * 1024 * 1024)
    if case == "metadata_missing":
        metadata = {}
    elif case == "incomplete":
        metadata.pop("algorithm")
    elif case == "sequence":
        metadata["input_type"] = "sequence"
    elif case == "features":
        metadata.pop("expected_features")
    elif case == "self_reported":
        metadata.update(signature_status="valid", _signature_verified=False)
    result = risk.analyze_model_risk(path, metadata)
    citations(result)
    expected = {"missing": 0, "complete": 100, "serialization": 88, "metadata_missing": 53,
                "incomplete": 95, "sequence": 70, "features": 88, "self_reported": 90,
                "large": 80, "moderate": 92}
    assert result.score == expected[case]


@pytest.mark.parametrize("sequence", [False, True])
@pytest.mark.parametrize("previous", [[], [95], [87], [81], [90, 110]])
def test_trust_drift_cites_history_counts_and_actual_deltas(monkeypatch, sequence, previous):
    input_type = "sequence" if sequence else "tabular"
    monkeypatch.setattr(trust_drift, "list_scans", lambda **kwargs: [
        {"model_name": "model", "input_type": input_type, "trust_score": value} for value in previous])
    result = trust_drift.analyze_trust_drift(80, "model", owner_id=41, input_type=input_type)
    citations(result)
    assert result.details["previous_scan_count"] == len(previous)


@pytest.mark.parametrize("sequence", [False, True])
@pytest.mark.parametrize("weak,sensitive,confidence,importance", [
    (True, True, 0.55, [0.6, 0.1, 0.1, 0.1, 0.1]),
    (True, False, 0.9, [0.3, 0.3, 0.2, 0.1, 0.1]),
    (False, True, 0.9, [0.2] * 5), (False, False, None, []),
])
def test_behavior_cites_class_confidence_confusion_and_feature_evidence(files, monkeypatch, sequence, weak, sensitive, confidence, importance):
    labels = np.asarray(["A"] * 10 + ["B"] * 10)
    columns = ["x", "y", "z", "u", "v"]
    values = np.tile(np.arange(20)[:, None], (1, 5))
    frame = pd.DataFrame(values, columns=columns)
    frame["label"] = labels
    frame.to_csv(files.test, index=False)
    model = backend()
    model.predict = lambda data: np.repeat("A", 20) if weak else labels
    model.predict_proba = lambda data: None if confidence is None else np.tile([confidence, 1 - confidence], (20, 1))
    model.feature_importance = lambda names: [{"feature": name, "importance": value} for name, value in zip(columns, importance)]
    monkeypatch.setattr(behavior, "load_model_backend", lambda *args: model)
    monkeypatch.setattr(behavior, "get_sensitive_label_taxonomy", lambda: ["b"] if sensitive else ["attack"])
    monkeypatch.setattr(behavior, "load_sequence_dataset", lambda *args: SequenceDataset(values, labels))
    result = behavior.analyze_behavior("model.onnx", files.test, {
        "input_type": "sequence" if sequence else "tabular", "expected_features": columns, "class_labels": ["A", "B"],
    })
    findings = citations(result)
    assert result.details["confidence"]["available"] is (confidence is not None)
    if weak:
        assert findings["Class confusion detected"].metric == "details.confusion_pairs"
    if confidence is None:
        assert findings["Prediction confidence unavailable"].metric == "details.confidence.available"


@pytest.mark.parametrize("sequence", [False, True])
@pytest.mark.parametrize("count,shared", [(20, 0), (20, 1), (20, 3), (20, 4), (100, 1)])
@pytest.mark.parametrize("gap", [False, True])
def test_leakage_overlap_and_generalization_metrics(files, monkeypatch, sequence, count, shared, gap):
    train_values = np.arange(count)
    test_values = np.concatenate((np.arange(shared), np.arange(200, 200 + count - shared)))
    train = pd.DataFrame({"x": train_values, "label": ["A"] * count})
    test = pd.DataFrame({"x": test_values, "label": ["A"] * count})
    train.to_csv(files.train, index=False)
    test.to_csv(files.test, index=False)
    model = backend()
    model.predict = lambda data: np.repeat("B" if gap and np.asarray(data).mean() > 100 else "A", len(data))
    monkeypatch.setattr(leakage, "load_model_backend", lambda *args: model)
    monkeypatch.setattr(leakage, "load_sequence_dataset", Mock(side_effect=[
        SequenceDataset(train_values[:, None], np.repeat("A", count)),
        SequenceDataset(test_values[:, None], np.repeat("A", count)),
    ]))
    result = leakage.check_dataset_leakage("model.onnx", files.test,
        {**files.metadata, "input_type": "sequence" if sequence else "tabular"})
    citations(result)
    assert result.details["feature_overlap_rate"] == pytest.approx(shared / count)
    assert result.details["generalization_gap"] == (1.0 if gap else 0.0)
    if not sequence and shared == 3:
        assert result.findings[0].metric == "details.full_row_overlap_rate"


def test_leakage_partial_failure_records_actual_comparison_error(files, monkeypatch):
    monkeypatch.setattr(leakage, "load_model_backend", Mock(side_effect=ValueError("prediction shape mismatch")))
    result = leakage.check_dataset_leakage("model.onnx", files.test, files.metadata)
    findings = citations(result)
    assert findings["Train/test performance comparison unavailable"].metric == "details.performance_comparison_error"
    assert result.details["performance_comparison_error"] == "prediction shape mismatch"
    assert result.details["generalization_gap"] is None


@pytest.mark.parametrize("sequence", [False, True])
@pytest.mark.parametrize("train_values,test_values,metric", [
    ([0.99], [0.7], "confidence_gap"), ([0.9], [0.83], "confidence_gap"),
    ([0.9], [0.9], "confidence_gap"), ([0.999], [0.999], "confidence_gap"),
    ([1.0, 0.92], [0.95], "high_confidence_gap"),
    ([0.99, 0.94, 0.94, 0.94, 0.94], [0.95], "high_confidence_gap"),
    (None, None, "confidence_available"),
])
def test_privacy_cites_mean_or_high_confidence_trigger(files, monkeypatch, sequence, train_values, test_values, metric):
    monkeypatch.setattr(privacy, "load_model_backend", lambda *args: backend())
    monkeypatch.setattr(privacy, "load_sequence_dataset", lambda *args: SequenceDataset(np.ones((2, 4)), np.repeat("A", 2)))
    monkeypatch.setattr(privacy, "_max_confidence", Mock(side_effect=[
        None if train_values is None else np.asarray(train_values),
        None if test_values is None else np.asarray(test_values),
    ]))
    result = privacy.assess_privacy_risk("model.onnx", files.test,
        {**files.metadata, "input_type": "sequence" if sequence else "tabular"})
    findings = citations(result)
    assert result.findings[0].metric == "details." + metric
    if not sequence and train_values == [0.999]:
        assert findings["Very high confidence across splits"].metric == "details.train_mean_confidence"
