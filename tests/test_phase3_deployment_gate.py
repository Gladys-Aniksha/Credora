from __future__ import annotations

from core.report_schema import Finding, ModuleResult
from modules.phase3_operations.m5_secure_deployment.gatekeeper import evaluate_deployment_gate


def result(module: str, score: float, status: str = "pass", findings: list[Finding] | None = None, details: dict | None = None) -> ModuleResult:
    return ModuleResult(module, status, score, module, findings or [], details or {})


def healthy_results(extra_findings: list[Finding] | None = None) -> list[ModuleResult]:
    return [
        result("classifier_evaluation", 96, findings=extra_findings),
        result("security_gate", 100, details={"decision": "passed", "trust_score_eligible": True}),
        result("trust_score", 94, details={"issued": True}),
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


def test_gate_propagates_a_blocked_security_gate() -> None:
    results = healthy_results()
    results[1] = result(
        "security_gate",
        50,
        status="fail",
        findings=[Finding("security_gate", "Security Gate blocked", "critical", "Signature failed.")],
        details={"decision": "blocked", "trust_score_eligible": True, "deployment_eligible": False},
    )
    gate = evaluate_deployment_gate(results, 99)
    assert gate.status == "fail"
    assert gate.details["decision"] == "blocked"
    assert "Security Gate" in gate.details["failed_checks"]
    assert "Trust score issued" not in gate.details["failed_checks"]
