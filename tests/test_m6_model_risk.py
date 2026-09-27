from __future__ import annotations

from modules.phase2_deep_trust.m6_model_risk.risk import analyze_model_risk


def _complete_metadata() -> dict:
    return {
        "model_name": "traffic-model",
        "version": "1.0",
        "algorithm": "RandomForestClassifier",
        "framework": "scikit-learn",
        "task": "classification",
        "target_column": "label",
        "expected_features": ["duration", "packet_count"],
        "_signature_verified": True,
    }


def test_model_risk_accepts_complete_verified_metadata(tmp_path) -> None:
    model = tmp_path / "traffic.joblib"
    model.write_bytes(b"model")

    result = analyze_model_risk(model, _complete_metadata())

    assert result.status == "pass"
    assert result.score == 88
    assert result.details["signature_verified"] is True
    assert result.details["expected_feature_count"] == 2
    assert {finding.title for finding in result.findings} == {"Unsafe serialization family"}


def test_model_risk_ignores_self_reported_signature(tmp_path) -> None:
    model = tmp_path / "traffic.joblib"
    model.write_bytes(b"model")
    metadata = _complete_metadata()
    metadata.pop("_signature_verified")
    metadata["signature_status"] = "valid"

    result = analyze_model_risk(model, metadata)

    assert result.details["signature_verified"] is False
    assert result.score == 78
    assert "Model signature not verified" in {finding.title for finding in result.findings}
    assert "Self-reported signature ignored" in {finding.title for finding in result.findings}


def test_model_risk_fails_for_missing_artifact(tmp_path) -> None:
    result = analyze_model_risk(tmp_path / "missing.joblib", _complete_metadata())

    assert result.status == "fail"
    assert result.score == 0
    assert result.findings[0].severity == "critical"
