from __future__ import annotations

import pytest

from core.report_schema import ModuleResult
from modules.phase1_foundation.m11_trust_score import aggregator
from modules.phase1_foundation.m11_trust_score.aggregator import (
    FINAL_EXPECTED_MODULES,
    PRE_DEPLOYMENT_EXPECTED_MODULES,
    calculate_trust_score,
)
from modules.phase3_operations.m5_secure_deployment import gatekeeper


def _result(module: str, *, details: dict | None = None) -> ModuleResult:
    return ModuleResult(module, "pass", 100, "ok", [], details or {})


@pytest.fixture(autouse=True)
def fixed_trust_configuration(monkeypatch):
    monkeypatch.setattr(aggregator, "get_trust_weights", lambda: dict(aggregator.WEIGHTS))
    monkeypatch.setattr(
        gatekeeper,
        "get_deployment_policy",
        lambda: {
            "minimum_trust_score": 85,
            "minimum_classifier_score": 85,
            "minimum_adversarial_score": 80,
            "minimum_sensitive_recall": 0.90,
        },
    )


def test_incomplete_scan_scores_lower_than_same_complete_results() -> None:
    complete_results = [_result(module) for module in FINAL_EXPECTED_MODULES]
    incomplete_results = complete_results[:-1]

    complete = calculate_trust_score(complete_results, FINAL_EXPECTED_MODULES)
    incomplete = calculate_trust_score(incomplete_results, FINAL_EXPECTED_MODULES)

    assert complete.score == 100
    assert incomplete.score == round(100 * ((len(FINAL_EXPECTED_MODULES) - 1) / len(FINAL_EXPECTED_MODULES)), 2)
    assert incomplete.score < complete.score
    assert incomplete.details["missing_modules"] == [FINAL_EXPECTED_MODULES[-1]]
    assert incomplete.findings[0].severity == "high"


def test_complete_pre_deployment_stage_is_not_penalized() -> None:
    results = [_result(module) for module in PRE_DEPLOYMENT_EXPECTED_MODULES]

    trust = calculate_trust_score(results, PRE_DEPLOYMENT_EXPECTED_MODULES)

    assert trust.score == 100
    assert trust.details["module_coverage"] == 1.0
    assert trust.details["missing_modules"] == []


def test_preliminary_missing_module_finding_propagates_to_deployment_gate() -> None:
    results = [_result(module) for module in PRE_DEPLOYMENT_EXPECTED_MODULES if module != "explainability"]
    results = [
        _result("adversarial_validation", details={"worst_sensitive_recall": 1.0, "sensitive_labels": []})
        if result.module == "adversarial_validation"
        else result
        for result in results
    ]
    preliminary = calculate_trust_score(results, PRE_DEPLOYMENT_EXPECTED_MODULES)

    gate = gatekeeper.evaluate_deployment_gate(
        results,
        preliminary.score,
        preliminary_trust=preliminary,
    )

    assert preliminary.score >= 85
    assert any(finding.title == "Missing explainability" for finding in preliminary.findings)
    assert gate.details["decision"] == "blocked"
    assert gate.details["high_risk_finding_count"] == 1
    assert "No high-risk findings" in gate.details["failed_checks"]
