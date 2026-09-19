from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from modules.phase2_deep_trust.m10_dataset_leakage.leakage import check_dataset_leakage
from modules.phase2_deep_trust.m11_privacy_risk.privacy import assess_privacy_risk


def _write_model_and_data(tmp_path: Path) -> tuple[Path, Path, Path, dict]:
    train = pd.DataFrame({
        "f1": [0, 0, 1, 1, 2, 2],
        "f2": [0, 1, 0, 1, 0, 1],
        "label": ["A", "A", "B", "B", "B", "B"],
    })
    test = pd.DataFrame({
        "f1": [0, 3, 4],
        "f2": [0, 1, 0],
        "label": ["A", "B", "B"],
    })
    train_path = tmp_path / "train.csv"
    test_path = tmp_path / "test.csv"
    model_path = tmp_path / "model.joblib"
    train.to_csv(train_path, index=False)
    test.to_csv(test_path, index=False)
    model = RandomForestClassifier(n_estimators=8, random_state=7).fit(train[["f1", "f2"]], train["label"])
    joblib.dump(model, model_path)
    metadata = {"target_column": "label", "expected_features": ["f1", "f2"], "training_dataset_path": str(train_path)}
    return model_path, train_path, test_path, metadata


def test_dataset_leakage_flags_overlapping_holdout_rows(tmp_path) -> None:
    model_path, _train_path, test_path, metadata = _write_model_and_data(tmp_path)

    result = check_dataset_leakage(model_path, test_path, metadata)

    assert result.module == "dataset_leakage"
    assert result.status in {"warning", "fail"}
    assert result.details["feature_overlap_rate"] > 0
    assert any(finding.title in {"Possible holdout leakage", "Small train/test overlap detected"} for finding in result.findings)


def test_privacy_risk_reports_confidence_evidence(tmp_path) -> None:
    model_path, _train_path, test_path, metadata = _write_model_and_data(tmp_path)

    result = assess_privacy_risk(model_path, test_path, metadata)

    assert result.module == "privacy_risk"
    assert result.details["confidence_available"] is True
    assert "confidence_gap" in result.details
    assert result.findings
