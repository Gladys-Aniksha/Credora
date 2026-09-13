from __future__ import annotations

from core.config import DEFAULT_DEPLOYMENT_POLICY
from core.report_schema import Finding, ModuleResult


def _module(results: list[ModuleResult], name: str) -> ModuleResult | None:
    return next((result for result in results if result.module == name), None)


def evaluate_deployment_gate(
    results: list[ModuleResult], preliminary_trust_score: float, metadata: dict | None = None
) -> ModuleResult:
    metadata = metadata or {}
    policy = DEFAULT_DEPLOYMENT_POLICY
    trust_target = float(policy.get("minimum_trust_score", 85))
    classifier_target = float(policy.get("minimum_classifier_score", 85))
    adversarial_target = float(policy.get("minimum_adversarial_score", 80))
    sensitive_recall_target = float(policy.get("minimum_sensitive_recall", 0.90))

    classifier = _module(results, "classifier_evaluation")
    adversarial = _module(results, "adversarial_validation")
    runtime = _module(results, "runtime_integrity")
    all_findings = [finding for result in results for finding in result.findings]
    high_risk = [finding for finding in all_findings if finding.severity in {"critical", "high"}]
    medium_risk = [finding for finding in all_findings if finding.severity == "medium"]
    sensitive_recall = adversarial.details.get("worst_sensitive_recall") if adversarial else None
    policy_findings: list[Finding] = []
    if metadata.get("deployment_policy"):
        policy_findings.append(Finding(
            "deployment_gate",
            "Self-reported deployment policy ignored",
            "info",
            "The uploaded metadata included deployment_policy thresholds, but Credora uses server-side policy for gate decisions.",
            "Configure deployment thresholds on the server, not in uploaded metadata.",
        ))

    checks = [
        {"check": "Trust score", "passed": preliminary_trust_score >= trust_target, "actual": round(preliminary_trust_score, 2), "target": trust_target, "required": True},
        {"check": "Classifier score", "passed": bool(classifier and classifier.score >= classifier_target), "actual": classifier.score if classifier else None, "target": classifier_target, "required": True},
        {"check": "Adversarial resilience", "passed": bool(adversarial and adversarial.score >= adversarial_target), "actual": adversarial.score if adversarial else None, "target": adversarial_target, "required": True},
        {"check": "Runtime artifact integrity", "passed": bool(runtime and runtime.status == "pass"), "actual": runtime.status if runtime else "missing", "target": "pass", "required": True},
        {"check": "Security-sensitive recall", "passed": sensitive_recall is None or sensitive_recall >= sensitive_recall_target, "actual": sensitive_recall, "target": sensitive_recall_target, "required": bool(adversarial and adversarial.details.get("sensitive_labels"))},
        {"check": "No high-risk findings", "passed": not high_risk, "actual": len(high_risk), "target": 0, "required": True},
    ]
    failed_required = [check for check in checks if check["required"] and not check["passed"]]
    passed_required = [check for check in checks if check["required"] and check["passed"]]
    required_count = len(failed_required) + len(passed_required)
    gate_score = round((len(passed_required) / required_count) * 100, 2) if required_count else 0.0

    if failed_required or high_risk:
        decision, status, severity = "blocked", "fail", "high"
        failed_names = ", ".join(check["check"] for check in failed_required) or "high-risk findings"
        summary = f"Production deployment blocked by {len(failed_required)} required gate check(s)."
        description = f"Failed production gate checks: {failed_names}."
        recommendations = [finding.recommendation for finding in high_risk if finding.recommendation]
        recommendation = recommendations[0] if recommendations else "Resolve every failed gate check and rerun the complete Phase 3 assessment."
    elif medium_risk:
        decision, status, severity = "conditional", "warning", "medium"
        summary = f"Production deployment is conditional with {len(medium_risk)} medium-risk finding(s)."
        description = "All mandatory score checks passed, but medium-risk controls still require review."
        recommendations = [finding.recommendation for finding in medium_risk if finding.recommendation]
        recommendation = recommendations[0] if recommendations else "Document and remediate medium-risk findings before production approval."
    else:
        decision, status, severity = "approved", "pass", "info"
        summary = "All mandatory Phase 3 production deployment checks passed."
        description = "The model met the configured trust, performance, adversarial, integrity, and security-sensitive recall gates."
        recommendation = "Record this approval with the exact model hash and monitor runtime integrity after deployment."

    return ModuleResult(
        module="deployment_gate",
        status=status,
        score=gate_score,
        summary=summary,
        findings=[Finding("deployment_gate", f"Deployment {decision}", severity, description, recommendation), *policy_findings],
        details={
            "decision": decision,
            "checks": checks,
            "failed_checks": [check["check"] for check in failed_required],
            "high_risk_finding_count": len(high_risk),
            "medium_risk_finding_count": len(medium_risk),
            "policy": {
                "minimum_trust_score": trust_target,
                "minimum_classifier_score": classifier_target,
                "minimum_adversarial_score": adversarial_target,
                "minimum_sensitive_recall": sensitive_recall_target,
            },
        },
    )
