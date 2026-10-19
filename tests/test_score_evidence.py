from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict

import pytest

from core.report_schema import ModuleResult
from core.score_evidence import trust_score_evidence
from scripts.run_phase1_scan import _apply_raw_model_cap


def _report(result):
    return {"trust_score": result.score, "module_results": [asdict(result)]}


def _historical():
    return {"trust_score": 70, "module_results": [
        {"module": "quality", "status": "pass", "score": 90},
        {"module": "integrity", "status": "warning", "score": 80},
        {"module": "security_gate", "status": "fail", "score": 0},
        {"module": "trust_score", "score": 70, "details": {
            "weights": {"quality": 3, "integrity": 1},
            "expected_modules": ["quality", "integrity"], "raw_model_trust_cap": 70,
            "issued": True,
        }},
    ]}


def test_different_high_measured_scores_retain_the_unsigned_cap():
    evidence = []
    for score in (81.25, 94.75):
        result = _apply_raw_model_cap(ModuleResult("trust_score", "pass", score, "Measured"), {})
        assert result.score == 70
        assert result.status == "warning"
        assert result.details["uncapped_score"] == score
        assert result.details["raw_model_trust_cap"] == 70
        evidence.append(trust_score_evidence(_report(result)))
    assert [item["measured_score"] for item in evidence] == [81.25, 94.75]
    assert [item["published_score"] for item in evidence] == [70, 70]
    assert all(item["cap_applied"] and "Unsigned" in item["reason"] for item in evidence)


@pytest.mark.parametrize("score", [0, 49.5, 70])
def test_lower_scores_are_recorded_and_unchanged(score):
    result = _apply_raw_model_cap(ModuleResult("trust_score", "fail", score, "Measured"), {})
    assert result.score == result.details["uncapped_score"] == score
    assert result.status == "fail" and result.summary == "Measured" and result.findings == []
    assert trust_score_evidence(_report(result)) == {
        "measured_score": score, "published_score": score,
        "cap_applied": False, "cap": None, "reason": None,
    }


def test_verified_signature_is_not_capped_and_repeated_application_preserves_original():
    signed = _apply_raw_model_cap(ModuleResult("trust_score", "pass", 95, "Measured"), {
        "_signature_verified": True,
    })
    assert signed.score == signed.details["uncapped_score"] == 95
    assert not trust_score_evidence(_report(signed))["cap_applied"]
    unsigned = _apply_raw_model_cap(ModuleResult("trust_score", "pass", 95, "Measured"), {})
    _apply_raw_model_cap(unsigned, {})
    assert unsigned.details["uncapped_score"] == 95
    assert unsigned.score == 70


def test_historical_reconstruction_uses_stored_weights_and_does_not_mutate():
    report = _historical()
    original = deepcopy(report)
    evidence = trust_score_evidence(report)
    assert evidence["measured_score"] == 87.5
    assert evidence["published_score"] == evidence["cap"] == 70
    assert evidence["cap_applied"]
    assert report == original


def test_historical_coverage_and_not_applicable_match_aggregator():
    report = _historical()
    details = report["module_results"][-1]["details"]
    details["expected_modules"].extend(["missing", "unsupported"])
    details["weights"]["missing"] = 2
    report["module_results"].insert(0, {"module": "unsupported", "status": "not_applicable", "score": 0})
    del details["raw_model_trust_cap"]
    report["trust_score"] = report["module_results"][-1]["score"] = round(87.5 * 2 / 3, 2)
    evidence = trust_score_evidence(report)
    assert evidence["measured_score"] == evidence["published_score"] == 58.33
    assert not evidence["cap_applied"]


@pytest.mark.parametrize("report", [{}, {"trust_score": 70}, {
    "trust_score": 70, "module_results": [{"module": "trust_score", "score": 70,
                                            "details": {"raw_model_trust_cap": 70}}],
}])
def test_missing_evidence_never_invents_a_measured_score(report):
    assert trust_score_evidence(report)["measured_score"] is None


@pytest.mark.parametrize("mutation", ["weights", "expected", "score", "duplicate", "mismatch"])
def test_incomplete_or_ambiguous_history_does_not_invent_scores(mutation):
    report = _historical()
    details = report["module_results"][-1]["details"]
    if mutation == "weights":
        del details["weights"]["quality"]
    elif mutation == "expected":
        details["expected_modules"] = []
    elif mutation == "score":
        del report["module_results"][0]["score"]
    elif mutation == "duplicate":
        report["module_results"].append(dict(report["module_results"][0]))
    else:
        report["trust_score"] = 65
    assert trust_score_evidence(report)["measured_score"] is None


@pytest.mark.parametrize("bad", [None, True, "90", -1, 101, float("nan"), float("inf")])
def test_invalid_explicit_uncapped_score_is_not_reconstructed_over(bad):
    report = _historical()
    report["module_results"][-1]["details"]["uncapped_score"] = bad
    assert trust_score_evidence(report)["measured_score"] is None


def test_unissued_and_empty_module_evidence_is_not_zero_measurement():
    report = {"trust_score": 0, "module_results": [{"module": "trust_score", "score": 0, "details": {
        "issued": False, "weights": {"absent": 1}, "expected_modules": ["absent"],
    }}]}
    evidence = trust_score_evidence(report)
    assert evidence["published_score"] is evidence["measured_score"] is None
