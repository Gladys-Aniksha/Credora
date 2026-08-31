from __future__ import annotations

from core.report_schema import Finding, ModuleResult
from modules.phase3_operations.m5_secure_deployment.gatekeeper import evaluate_deployment_gate


def result(module: str, score: float, status: str = "pass", findings: list[Finding] | None = None, details: dict | None = None) -> ModuleResult:
    return ModuleResult(module, status, score, module, findings or [], details or {})


def healthy_results(extra_findings: list[Finding] | None = None) -> list[ModuleResult]:
    return [
        result("classifier_evaluation", 96, findings=extra_findings),
        result("adversarial_validation", 92, details={"worst_sensitive_recall": 0.94, "sensitive_labels": ["Suspicious"]}),
        result("runtime_integrity", 100),
    ]


def test_gate_approves_when_all_production_controls_pass() -> None:
    gate = evaluate_deployment_gate(healthy_results(), 94)
    assert gate.status == "pass"
    assert gate.details["decision"] == "approved"
    assert gate.details["failed_checks"] == []


def test_gate_is_conditional_for_medium_risk() -> None:
    medium = Finding("model_risk_analyzer", "Serialization risk", "medium", "Pickle family", "Use a signed trusted artifact.")
    gate = evaluate_deployment_gate(healthy_results([medium]), 94)
    assert gate.status == "warning"
    assert gate.details["decision"] == "conditional"


def test_gate_blocks_weak_adversarial_security_recall() -> None:
    results = healthy_results()
    results[1] = result(
        "adversarial_validation",
        42,
        status="fail",
        findings=[Finding("adversarial_validation", "Bypass", "high", "Sensitive recall collapsed.", "Retrain with evasive flows.")],
        details={"worst_sensitive_recall": 0.35, "sensitive_labels": ["Suspicious"]},
    )
    gate = evaluate_deployment_gate(results, 82)
    assert gate.status == "fail"
    assert gate.details["decision"] == "blocked"
    assert "Adversarial resilience" in gate.details["failed_checks"]
    assert "Security-sensitive recall" in gate.details["failed_checks"]
