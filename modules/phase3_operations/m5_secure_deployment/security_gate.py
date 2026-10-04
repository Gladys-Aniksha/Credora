from __future__ import annotations

from core.db import get_deployment_policy
from core.report_schema import Finding, ModuleResult

SECURITY_MODULES = {
    "model_verification",
    "dependency_scanner",
    "model_risk_analyzer",
    "adversarial_validation",
    "runtime_integrity",
}


def _module(results: list[ModuleResult], name: str) -> ModuleResult | None:
    return next((result for result in results if result.module == name), None)


def _approved_not_applicable(result: ModuleResult | None) -> bool:
    return bool(
        result
        and result.status == "not_applicable"
        and result.details.get("policy_approved") is True
    )


def evaluate_security_gate(results: list[ModuleResult]) -> ModuleResult:
    """Evaluate non-negotiable security evidence before deployment approval."""
    policy = get_deployment_policy()
    adversarial_target = float(policy.get("minimum_adversarial_score", 80))
    sensitive_recall_target = float(policy.get("minimum_sensitive_recall", 0.90))

    verification = _module(results, "model_verification")
    dependencies = _module(results, "dependency_scanner")
    model_risk = _module(results, "model_risk_analyzer")
    adversarial = _module(results, "adversarial_validation")
    runtime = _module(results, "runtime_integrity")

    signature_verified = bool(
        verification and verification.details.get("signature_verified") is True
    )
    trusted_hash = bool(
        verification
        and verification.details.get("expected_sha256_source") not in {None, "", "none"}
        and not any(finding.title == "Hash mismatch" for finding in verification.findings)
    )
    artifact_valid = bool(
        verification
        and verification.status != "fail"
        and not any(
            finding.severity == "critical"
            for finding in verification.findings
        )
    )
    dependency_blockers = [
        finding
        for finding in (dependencies.findings if dependencies else [])
        if finding.severity in {"critical", "high"}
    ]
    dependencies_not_applicable = _approved_not_applicable(dependencies)
    model_risk_blockers = [
        finding
        for finding in (model_risk.findings if model_risk else [])
        if finding.severity in {"critical", "high"}
    ]
    adversarial_safe = bool(
        _approved_not_applicable(adversarial)
        or (
            adversarial
            and adversarial.status != "fail"
            and adversarial.score >= adversarial_target
        )
    )
    sensitive_labels = adversarial.details.get("sensitive_labels", []) if adversarial else []
    sensitive_recall = adversarial.details.get("worst_sensitive_recall") if adversarial else None
    sensitive_recall_passed = bool(
        adversarial
        and (
            _approved_not_applicable(adversarial)
            or
            not sensitive_labels
            or (
                sensitive_recall is not None
                and float(sensitive_recall) >= sensitive_recall_target
            )
        )
    )
    runtime_verified = bool(
        runtime
        and runtime.status == "pass"
        and runtime.details.get("integrity_state") == "verified"
    )

    checks = [
        {
            "check": "Verified model signature",
            "passed": signature_verified,
            "actual": "verified" if signature_verified else "missing or invalid",
            "target": "verified",
            "required": True,
        },
        {
            "check": "Trusted model hash",
            "passed": trusted_hash,
            "actual": verification.details.get("expected_sha256_source", "missing") if verification else "missing",
            "target": "trusted baseline",
            "required": True,
        },
        {
            "check": "Safe artifact validation",
            "passed": artifact_valid,
            "actual": verification.status if verification else "missing",
            "target": "pass or warning without critical findings",
            "required": True,
        },
        {
            "check": "No critical dependency findings",
            "passed": dependencies_not_applicable or (dependencies is not None and not dependency_blockers),
            "actual": "not applicable" if dependencies_not_applicable else len(dependency_blockers) if dependencies else "missing",
            "target": 0,
            "required": not dependencies_not_applicable,
        },
        {
            "check": "No critical model-risk findings",
            "passed": model_risk is not None and not model_risk_blockers,
            "actual": len(model_risk_blockers) if model_risk else "missing",
            "target": 0,
            "required": True,
        },
        {
            "check": "Adversarial safety",
            "passed": adversarial_safe,
            "actual": "not applicable" if _approved_not_applicable(adversarial) else adversarial.score if adversarial else "missing",
            "target": adversarial_target,
            "required": not _approved_not_applicable(adversarial),
        },
        {
            "check": "Security-sensitive recall",
            "passed": sensitive_recall_passed,
            "actual": "not applicable" if _approved_not_applicable(adversarial) else sensitive_recall if adversarial else "missing",
            "target": sensitive_recall_target,
            "required": not _approved_not_applicable(adversarial),
        },
        {
            "check": "Runtime artifact integrity",
            "passed": runtime_verified,
            "actual": runtime.details.get("integrity_state", runtime.status) if runtime else "missing",
            "target": "verified",
            "required": True,
        },
    ]
    required_checks = [check for check in checks if check["required"]]
    failed = [check for check in required_checks if not check["passed"]]
    passed_count = len(required_checks) - len(failed)
    score = round((passed_count / len(required_checks)) * 100, 2) if required_checks else 100.0

    if failed:
        failed_names = ", ".join(str(check["check"]) for check in failed)
        return ModuleResult(
            module="security_gate",
            status="fail",
            score=score,
            summary=f"Security Gate blocked deployment because {len(failed)} mandatory check(s) failed.",
            findings=[
                Finding(
                    "security_gate",
                    "Security Gate blocked",
                    "critical",
                    f"Failed mandatory checks: {failed_names}.",
                    "Resolve every failed security check and rerun the complete assessment before deployment.",
                )
            ],
            details={
                "decision": "blocked",
                "checks": checks,
                "failed_checks": [check["check"] for check in failed],
                "trust_score_eligible": True,
                "deployment_eligible": False,
            },
        )

    return ModuleResult(
        module="security_gate",
        status="pass",
        score=100.0,
        summary="All mandatory security checks passed; the model may proceed to deployment policy evaluation.",
        findings=[],
        details={
            "decision": "passed",
            "checks": checks,
            "failed_checks": [],
            "trust_score_eligible": True,
            "deployment_eligible": True,
        },
    )
