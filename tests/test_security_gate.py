from __future__ import annotations

import pytest

from core.report_schema import Finding, ModuleResult
from modules.phase3_operations.m5_secure_deployment import security_gate
from modules.phase3_operations.m5_secure_deployment.security_gate import (
    evaluate_security_gate,
)


def _result(
    module: str,
    score: float = 100,
    *,
    status: str = "pass",
    details: dict | None = None,
    findings: list[Finding] | None = None,
) -> ModuleResult:
    return ModuleResult(module, status, score, "ok", findings or [], details or {})


def _healthy_results() -> list[ModuleResult]:
    return [
        _result(
            "model_verification",
            details={"signature_verified": True, "expected_sha256_source": "signed_package"},
        ),
        _result("dependency_scanner"),
        _result("model_risk_analyzer"),
        _result(
            "adversarial_validation",
            94,
            details={"sensitive_labels": ["attack"], "worst_sensitive_recall": 0.96},
        ),
        _result("runtime_integrity", details={"integrity_state": "verified"}),
    ]


@pytest.fixture(autouse=True)
def fixed_policy(monkeypatch):
    monkeypatch.setattr(
        security_gate,
        "get_deployment_policy",
        lambda: {"minimum_adversarial_score": 80, "minimum_sensitive_recall": 0.90},
    )


def test_security_gate_passes_only_complete_mandatory_evidence() -> None:
    gate = evaluate_security_gate(_healthy_results())

    assert gate.status == "pass"
    assert gate.details["decision"] == "passed"
    assert gate.details["trust_score_eligible"] is True


def test_failed_signature_blocks_even_when_other_results_are_perfect() -> None:
    results = _healthy_results()
    results[0].details["signature_verified"] = False

    gate = evaluate_security_gate(results)

    assert gate.status == "fail"
    assert gate.details["trust_score_eligible"] is False
    assert "Verified model signature" in gate.details["failed_checks"]


def test_zero_adversarial_safety_blocks_instead_of_being_averaged() -> None:
    results = _healthy_results()
    results[3] = _result(
        "adversarial_validation",
        0,
        status="fail",
        details={"sensitive_labels": ["attack"], "worst_sensitive_recall": 0.0},
        findings=[Finding("adversarial_validation", "Evasion succeeded", "critical", "Recall collapsed.")],
    )

    gate = evaluate_security_gate(results)

    assert gate.details["decision"] == "blocked"
    assert "Adversarial safety" in gate.details["failed_checks"]
    assert "Security-sensitive recall" in gate.details["failed_checks"]


def test_missing_security_module_fails_closed() -> None:
    results = [result for result in _healthy_results() if result.module != "runtime_integrity"]

    gate = evaluate_security_gate(results)

    assert gate.details["decision"] == "blocked"
    assert "Runtime artifact integrity" in gate.details["failed_checks"]
