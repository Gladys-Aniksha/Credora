from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from core.assessment_inputs import prepare_assessment_inputs
from core.execution_provider import execution_policy
from modules.phase2_deep_trust.m3_robustness_testing import robustness
from modules.phase2_deep_trust.m5_explainability import explain
from modules.phase2_deep_trust.m10_dataset_leakage import leakage
from modules.phase2_deep_trust.m11_privacy_risk import privacy
from modules.phase3_operations.m4_adversarial_validation import adversarial


class _Backend:
    def predict(self, features):
        return np.asarray(["normal"] * len(features))

    def predict_proba(self, features):
        return np.tile([[0.9, 0.1]], (len(features), 1))

    def feature_importance(self, columns):
        return [{"feature": column, "importance": 1 / len(columns)} for column in columns]


@pytest.mark.parametrize("device", ["cpu", "auto", "cuda"])
@pytest.mark.parametrize("module,runner,evidence_key", [
    (robustness, robustness.test_robustness, "trial_count"),
    (explain, explain.explain_model, "top_features"),
    (leakage, leakage.check_dataset_leakage, "train_f1"),
    (privacy, privacy.assess_privacy_risk, "confidence_gap"),
    (adversarial, adversarial.run_adversarial_validation, "scenarios"),
])
def test_tabular_stage_uses_selected_policy_during_assessment(
    tmp_path, monkeypatch, device, module, runner, evidence_key,
):
    dataset_path = tmp_path / "test.csv"
    train_path = tmp_path / "train.csv"
    frame = pd.DataFrame({"duration": [1.0, 2.0, 3.0], "bytes": [10.0, 20.0, 30.0],
                          "label": ["normal"] * 3})
    frame.to_csv(dataset_path, index=False)
    frame.to_csv(train_path, index=False)
    metadata = {
        "input_type": "tabular", "execution_device": device, "execution_fallback": "error",
        "expected_features": ["duration", "bytes"], "training_dataset_path": str(train_path),
    }
    captured = []

    def load(path, policy_metadata=None):
        captured.append(policy_metadata)
        return _Backend()

    monkeypatch.setattr(module, "load_model_backend", load)
    if module in (leakage, privacy):
        monkeypatch.setattr(module, "DATA_DIR", tmp_path / "data")
    if module is adversarial:
        monkeypatch.setattr(module, "get_sensitive_label_taxonomy", lambda: ["attack"])
    result = runner(tmp_path / "model.onnx", dataset_path, metadata)

    assert captured == [metadata]
    assert captured[0] is metadata
    assert evidence_key in result.details
    assert not any("failed" in finding.title.lower() for finding in result.findings)


@pytest.mark.parametrize("metadata", [
    {"execution_device": "cuda"},
    {"execution_device": "cuda", "execution_fallback": "error"},
    {"execution_device": "auto", "execution_fallback": "error"},
])
def test_fallback_flag_overrides_metadata_policy_without_a_device_argument(tmp_path, monkeypatch, metadata):
    import onnxruntime as ort

    monkeypatch.setattr(ort, "get_available_providers", lambda: ["CPUExecutionProvider"])
    original = dict(metadata)
    prepared = prepare_assessment_inputs(
        Path("model.onnx"), Path("test.csv"), metadata, tmp_path / "prepared",
        allow_cpu_fallback=True,
    )
    assert execution_policy(prepared.metadata) == {
        "execution_device": metadata["execution_device"], "execution_fallback": "cpu",
    }
    assert metadata == original
    assert not (tmp_path / "prepared").exists()


def test_metadata_cuda_still_fails_without_explicit_fallback(tmp_path, monkeypatch):
    import onnxruntime as ort

    monkeypatch.setattr(ort, "get_available_providers", lambda: ["CPUExecutionProvider"])
    with pytest.raises(ValueError, match="no CUDA provider"):
        prepare_assessment_inputs(
            Path("model.onnx"), Path("test.csv"), {"execution_device": "cuda"}, tmp_path,
        )


def test_fallback_permission_does_not_enable_gpu_for_sklearn(tmp_path):
    with pytest.raises(ValueError, match="only for ONNX"):
        prepare_assessment_inputs(
            Path("model.joblib"), Path("test.csv"), {"execution_device": "cuda"}, tmp_path,
            allow_cpu_fallback=True,
        )


def test_device_override_still_selects_cuda_with_explicit_fallback(tmp_path):
    prepared = prepare_assessment_inputs(
        Path("model.onnx"), Path("test.csv"), {"execution_device": "cpu"}, tmp_path,
        execution_device="cuda", allow_cpu_fallback=True,
    )
    assert execution_policy(prepared.metadata) == {
        "execution_device": "cuda", "execution_fallback": "cpu",
    }


def test_default_policy_remains_cpu(tmp_path):
    prepared = prepare_assessment_inputs(Path("model.onnx"), Path("test.csv"), {}, tmp_path)
    assert execution_policy(prepared.metadata)["execution_device"] == "cpu"
