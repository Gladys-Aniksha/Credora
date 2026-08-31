from __future__ import annotations

from core.report_schema import Finding, ModuleResult

WEIGHTS = {
    "model_verification": 0.12,
    "dependency_scanner": 0.08,
    "classifier_evaluation": 0.18,
    "robustness_testing": 0.10,
    "data_drift_detection": 0.08,
    "explainability": 0.05,
    "behavior_analysis": 0.10,
    "model_risk_analyzer": 0.07,
    "adversarial_validation": 0.12,
    "runtime_integrity": 0.08,
    "deployment_gate": 0.08,
    "trust_drift_timeline": 0.02,
}


def calculate_trust_score(results: list[ModuleResult]) -> ModuleResult:
    by_module = {result.module: result for result in results if result.module != "trust_score"}
    weighted_score = 0.0
    total_weight = 0.0
    findings: list[Finding] = []

    for module, weight in WEIGHTS.items():
        result = by_module.get(module)
        if result is None:
            findings.append(Finding("trust_score", f"Missing {module}", "medium", f"{module} did not run.", "Run the full trust scan."))
            continue
        weighted_score += result.score * weight
        total_weight += weight

    final_score = weighted_score / total_weight if total_weight else 0.0
    deployment_gate = by_module.get("deployment_gate")
    gate_decision = deployment_gate.details.get("decision") if deployment_gate else None
    if gate_decision == "blocked":
        status = "fail"
        summary = "Blocked by the Phase 3 production deployment gate."
    elif gate_decision == "conditional":
        status = "warning"
        summary = "Conditionally approved for production after listed controls are resolved."
    elif gate_decision == "approved" and final_score >= 85:
        status = "pass"
        summary = "Approved by the Phase 3 production deployment gate."
    elif final_score >= 85:
        status = "pass"
        summary = "Trusted for validation; run the production deployment gate before release."
    elif final_score >= 70:
        status = "warning"
        summary = "Mostly trusted, but review warnings before deployment."
    else:
        status = "fail"
        summary = "Not recommended for deployment until major issues are fixed."

    critical_or_high = [finding for result in by_module.values() for finding in result.findings if finding.severity in {"critical", "high"}]
    if critical_or_high:
        findings.append(Finding("trust_score", "High-risk findings present", "high", f"There are {len(critical_or_high)} high or critical finding(s).", "Resolve high-risk findings before deployment."))

    return ModuleResult(
        module="trust_score",
        status=status,
        score=round(final_score, 2),
        summary=summary,
        findings=findings,
        details={"weights": WEIGHTS, "modules_scored": list(by_module.keys()), "deployment_decision": gate_decision},
    )
