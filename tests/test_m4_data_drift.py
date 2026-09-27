from __future__ import annotations

import numpy as np
import pandas as pd

from modules.phase2_deep_trust.m4_data_drift import drift


def _write_datasets(tmp_path, current_values: np.ndarray) -> tuple[str, str]:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    baseline = data_dir / "baseline.csv"
    current = data_dir / "current.csv"
    pd.DataFrame({"duration": np.arange(1, 101), "label": ["A"] * 100}).to_csv(
        baseline, index=False
    )
    pd.DataFrame({"duration": current_values, "label": ["A"] * 100}).to_csv(
        current, index=False
    )
    return "data/baseline.csv", str(current)


def test_data_drift_flags_shifted_numeric_distribution(tmp_path, monkeypatch) -> None:
    baseline_path, current_path = _write_datasets(tmp_path, np.arange(201, 301))
    monkeypatch.setattr(drift, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(drift, "DATA_DIR", tmp_path / "data")

    result = drift.detect_data_drift(
        current_path,
        {
            "training_dataset_path": baseline_path,
            "target_column": "label",
            "expected_features": ["duration"],
        },
    )

    assert result.status in {"warning", "fail"}
    assert result.details["max_psi"] >= 0.25
    assert result.details["drifted_features"][0]["drift_level"] == "high"
    assert result.findings[0].title == "High data drift detected"


def test_data_drift_passes_matching_numeric_distribution(tmp_path, monkeypatch) -> None:
    baseline_path, current_path = _write_datasets(tmp_path, np.arange(1, 101))
    monkeypatch.setattr(drift, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(drift, "DATA_DIR", tmp_path / "data")

    result = drift.detect_data_drift(
        current_path,
        {"training_dataset_path": baseline_path, "expected_features": ["duration"]},
    )

    assert result.status == "pass"
    assert result.score == 100
    assert result.details["max_psi"] == 0
    assert result.details["drifted_features"] == []
