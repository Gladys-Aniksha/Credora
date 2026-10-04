from __future__ import annotations

from modules.phase2_deep_trust.m4_data_drift import drift as drift_module
from modules.phase2_deep_trust.m5_explainability.explain import explain_model
from modules.phase2_deep_trust.m10_dataset_leakage import leakage as leakage_module
from modules.phase2_deep_trust.m10_dataset_leakage.leakage import check_dataset_leakage
from modules.phase2_deep_trust.m11_privacy_risk import privacy as privacy_module
from modules.phase2_deep_trust.m11_privacy_risk.privacy import assess_privacy_risk
from modules.phase2_deep_trust.m3_robustness_testing.robustness import test_robustness as run_robustness
from modules.phase3_operations.m4_adversarial_validation.adversarial import run_adversarial_validation
from sequence_fixtures import build_sequence_onnx, sequence_metadata, write_sequence_npz


def _sequence_paths(tmp_path, monkeypatch):
    data_root = tmp_path / "data"
    data_root.mkdir()
    train_path = data_root / "train.npz"
    test_path = data_root / "test.npz"
    write_sequence_npz(train_path)
    write_sequence_npz(test_path)
    monkeypatch.setattr(drift_module, "DATA_DIR", data_root)
    monkeypatch.setattr(drift_module, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(leakage_module, "DATA_DIR", data_root)
    monkeypatch.setattr(privacy_module, "DATA_DIR", data_root)
    metadata = {**sequence_metadata(), "training_dataset_path": "data/train.npz"}
    return train_path, test_path, metadata


def test_sequence_drift_leakage_privacy_and_occlusion(tmp_path, monkeypatch) -> None:
    model_path = build_sequence_onnx(tmp_path / "model.onnx")
    _train_path, test_path, metadata = _sequence_paths(tmp_path, monkeypatch)

    drift = drift_module.detect_data_drift(test_path, metadata)
    leakage = check_dataset_leakage(model_path, test_path, metadata)
    privacy = assess_privacy_risk(model_path, test_path, metadata)
    explanation = explain_model(model_path, test_path, metadata)
    robustness = run_robustness(model_path, test_path, metadata)
    adversarial = run_adversarial_validation(model_path, test_path, metadata)

    assert drift.details["input_type"] == "sequence"
    assert leakage.details["input_type"] == "sequence"
    assert privacy.details["input_type"] == "sequence"
    assert explanation.details["method"] == "occlusion"
    assert explanation.details["saliency"]
    assert robustness.details["scenarios"]
    assert adversarial.details["scenarios"]
    assert adversarial.details["input_type"] == "sequence"
