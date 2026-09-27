from __future__ import annotations

import json
from pathlib import Path

from modules.phase3_operations.m4_adversarial_validation.adversarial import run_adversarial_validation
from scripts.create_phase3_validation_pack import create_shifted_pack


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_adversarial_validation_runs_three_real_model_scenarios() -> None:
    metadata = json.loads((PROJECT_ROOT / "data" / "metadata" / "traffic_rf_v1_metadata.json").read_text(encoding="utf-8"))
    result = run_adversarial_validation(
        PROJECT_ROOT / "data" / "sample_models" / "traffic_rf_v1.joblib",
        PROJECT_ROOT / "data" / "processed" / "encrypted_traffic_test.csv",
        metadata,
    )

    assert result.status in {"pass", "warning", "fail"}
    assert 0 <= result.score <= 100
    assert len(result.details["scenarios"]) == 3
    assert result.details["baseline_f1"] >= result.details["worst_case_f1"]
    assert result.details["worst_case_scenario"] in {
        "timing_jitter",
        "sensitive_flow_evasion",
        "sensor_feature_dropout",
    }
    assert result.details["trial_count"] == 25
    for scenario in result.details["scenarios"]:
        assert scenario["trial_count"] == 25
        assert len(scenario["trials"]) == 25
        assert len({trial["seed"] for trial in scenario["trials"]}) == 25
        assert scenario["f1"] <= scenario["mean_f1"]
        assert scenario["accuracy"] <= scenario["mean_accuracy"]
        assert scenario["prediction_stability"] <= scenario["mean_prediction_stability"]

    details = result.details
    expected_score = (
        100.0
        - (details["max_f1_drop"] * 90)
        - ((1 - details["minimum_prediction_stability"]) * 35)
        - (max(0.0, details["baseline_sensitive_recall"] - details["worst_sensitive_recall"]) * 45)
        - details["absolute_f1_penalty"]
        - details["absolute_sensitive_recall_penalty"]
    )
    assert result.score == round(max(0.0, min(expected_score, 100.0)), 2)


def test_adversarial_validation_scores_evasive_sensitive_flows_as_high_risk(tmp_path) -> None:
    dataset_path = PROJECT_ROOT / "data" / "processed" / "encrypted_traffic_test.csv"
    metadata_path = PROJECT_ROOT / "data" / "metadata" / "traffic_rf_v1_metadata.json"
    paths = create_shifted_pack(dataset_path, metadata_path, tmp_path)
    metadata = json.loads(Path(paths["metadata_path"]).read_text(encoding="utf-8"))
    result = run_adversarial_validation(
        PROJECT_ROOT / "data" / "sample_models" / "traffic_rf_v1.joblib",
        paths["test_dataset_path"],
        metadata,
    )

    assert result.status == "fail"
    assert result.score < 55
    assert result.details["worst_sensitive_recall"] < 0.90
    assert any(finding.severity == "high" for finding in result.findings)
