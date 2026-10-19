from __future__ import annotations

from dashboard.components.assessment_motion import comparable_reports, motion_payload


def test_comparison_requires_matching_model_and_input_track() -> None:
    current = {"model_name": "model", "input_type": "sequence", "generated_at": "2026-10-10"}
    valid = {**current, "generated_at": "2026-10-09"}
    reports = [current, valid, {**valid, "input_type": "tabular"}, {**valid, "model_name": "other"}]
    assert comparable_reports(reports, current) == [valid]


def test_missing_and_non_applicable_evidence_is_not_drawn_as_zero() -> None:
    report = {"trust_score": 65, "module_results": [
        {"module": "dependency_scanner", "status": "not_applicable", "score": 0},
        {"module": "classifier_evaluation", "status": "pass", "score": 94},
        {"module": "security_gate", "details": {"decision": "failed"}},
    ]}
    payload = motion_payload(report, None, live=True)
    assert payload["points"][1]["current"] is None
    assert payload["points"][2]["current"] == 94
    assert payload["completed"] == 1
    assert payload["gate"] == "Deployment blocked"
    assert payload["hasBaseline"] is False
    assert payload["live"] is True


def test_invalid_scores_are_not_serialized_as_chart_measurements() -> None:
    report = {"trust_score": float("nan"), "module_results": [
        {"module": "classifier_evaluation", "status": "pass", "score": float("inf")},
    ]}
    payload = motion_payload(report, {"trust_score": 88})
    assert payload["score"] is None
    assert payload["points"][2]["current"] is None
    assert payload["baselineScore"] == 88
