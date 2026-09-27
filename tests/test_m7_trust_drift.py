from __future__ import annotations

from modules.phase2_deep_trust.m7_trust_drift import trust_drift


def test_trust_drift_creates_first_baseline(monkeypatch) -> None:
    monkeypatch.setattr(trust_drift, "list_scans", lambda **kwargs: [])

    result = trust_drift.analyze_trust_drift(86, "traffic-model", owner_id=7)

    assert result.status == "pass"
    assert result.score == 100
    assert result.details["previous_scan_count"] == 0
    assert result.findings[0].title == "First trust baseline created"


def test_trust_drift_detects_owner_scoped_major_regression(monkeypatch) -> None:
    captured = {}

    def fake_list_scans(*, limit, owner_id):
        captured.update({"limit": limit, "owner_id": owner_id})
        return [
            {"model_name": "traffic-model", "trust_score": 90},
            {"model_name": "other-model", "trust_score": 100},
            {"model_name": "traffic-model", "trust_score": 95},
        ]

    monkeypatch.setattr(trust_drift, "list_scans", fake_list_scans)

    result = trust_drift.analyze_trust_drift(70, "traffic-model", owner_id=42)

    assert captured == {"limit": 50, "owner_id": 42}
    assert result.status == "fail"
    assert result.score == 50
    assert result.details["previous_scan_count"] == 2
    assert result.details["drop_from_latest"] == 20
    assert result.details["drop_from_best"] == 25
    assert {finding.title for finding in result.findings} == {
        "Major trust regression",
        "Below historical best",
    }
