from __future__ import annotations

from core.db import get_deployment_policy
from core.report_schema import Finding, ModuleResult


def _module(results: list[ModuleResult], name: str) -> ModuleResult | None:
    return next((result for result in results if result.module == name), None)


def evaluate_deployment_gate(
    results: list[ModuleResult],
    trust_score: float,
    metadata: dict | None = None,
    trust_result: ModuleResult | None = None,
) -> ModuleResult:
    """Apply release policy after the independent Security Gate and Trust Score."""
    metadata = metadata or {}
    policy = get_deployment_policy()
    trust_target = float(policy.get("minimum_trust_score", 85))
    classifier_target = float(policy.get("minimum_classifier_score", 85))

    security_gate = _module(results, "security_gate")
    classifier = _module(results, "classifier_evaluation")
    trust_result = trust_result or _module(results, "trust_score")
    trust_missing_findings = [] if trust_result in results else [
        finding
        for finding in (trust_result.findings if trust_result else [])
        if finding.module == "trust_score" and finding.title.startswith("Missing ")
    ]
    all_findings = [finding for result in results for finding in result.findings] + trust_missing_findings
    high_risk = [finding for finding in all_findings if finding.severity in {"critical", "high"}]
    medium_risk = [finding for finding in all_findings if finding.severity == "medium"]
    policy_findings: list[Finding] = []
    if metadata.get("deployment_policy"):
        policy_findings.append(Finding(
            "deployment_gate",
            "Self-reported deployment policy ignored",
            "info",
            "The uploaded metadata included deployment_policy thresholds, but Credora uses server-side policy for gate decisions.",
            "Configure deployment thresholds on the server, not in uploaded metadata.",
            metric="details.self_reported_policy_ignored",
        ))

    checks = [
        {
            "check": "Security Gate",
            "passed": bool(security_gate and security_gate.details.get("decision") == "passed"),
            "actual": security_gate.details.get("decision", "missing") if security_gate else "missing",
            "target": "passed",
            "required": True,
        },
        {
            "check": "Trust score issued",
            "passed": bool(trust_result and trust_result.details.get("issued") is True),
            "actual": "issued" if trust_result and trust_result.details.get("issued") is True else "not issued",
            "target": "issued",
            "required": True,
        },
        {"check": "Trust score", "passed": trust_score >= trust_target, "actual": round(trust_score, 2), "target": trust_target, "required": True},
        {"check": "Classifier score", "passed": bool(classifier and classifier.score >= classifier_target), "actual": classifier.score if classifier else None, "target": classifier_target, "required": True},
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
        summary = "The Security Gate and all production assurance thresholds passed."
        description = "The model passed mandatory security controls before meeting the configured trust and classifier thresholds."
        recommendation = "Record this approval with the exact model hash and monitor runtime integrity after deployment."

    return ModuleResult(
        module="deployment_gate",
        status=status,
        score=gate_score,
        summary=summary,
        findings=[Finding("deployment_gate", f"Deployment {decision}", severity, description, recommendation,
                          metric="details.failed_checks" if decision == "blocked" else "details.medium_risk_finding_count" if decision == "conditional" else "details.decision"), *policy_findings],
        details={
            "decision": decision,
            "self_reported_policy_ignored": bool(metadata.get("deployment_policy")),
            "checks": checks,
            "failed_checks": [check["check"] for check in failed_required],
            "high_risk_finding_count": len(high_risk),
            "medium_risk_finding_count": len(medium_risk),
            "policy": {
                "minimum_trust_score": trust_target,
                "minimum_classifier_score": classifier_target,
            },
        },
    )

