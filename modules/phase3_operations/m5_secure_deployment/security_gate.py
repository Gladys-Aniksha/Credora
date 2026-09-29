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


def evaluate_security_gate(results: list[ModuleResult]) -> ModuleResult:
    """Evaluate non-negotiable security evidence before issuing a Trust Score."""
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
    model_risk_blockers = [
        finding
        for finding in (model_risk.findings if model_risk else [])
        if finding.severity in {"critical", "high"}
    ]
    adversarial_safe = bool(
        adversarial
        and adversarial.status != "fail"
        and adversarial.score >= adversarial_target
    )
    sensitive_labels = adversarial.details.get("sensitive_labels", []) if adversarial else []
    sensitive_recall = adversarial.details.get("worst_sensitive_recall") if adversarial else None
    sensitive_recall_passed = bool(
        adversarial
        and (
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
            "passed": dependencies is not None and not dependency_blockers,
            "actual": len(dependency_blockers) if dependencies else "missing",
            "target": 0,
            "required": True,
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
            "actual": adversarial.score if adversarial else "missing",
            "target": adversarial_target,
            "required": True,
        },
        {
            "check": "Security-sensitive recall",
            "passed": sensitive_recall_passed,
            "actual": sensitive_recall if adversarial else "missing",
            "target": sensitive_recall_target,
            "required": True,
        },
        {
            "check": "Runtime artifact integrity",
            "passed": runtime_verified,
            "actual": runtime.details.get("integrity_state", runtime.status) if runtime else "missing",
            "target": "verified",
            "required": True,
        },
    ]
    failed = [check for check in checks if check["required"] and not check["passed"]]
    passed_count = len(checks) - len(failed)
    score = round((passed_count / len(checks)) * 100, 2)

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
                    "Resolve every failed security check and rerun the complete assessment before calculating a Trust Score.",
                )
            ],
            details={
                "decision": "blocked",
                "checks": checks,
                "failed_checks": [check["check"] for check in failed],
                "trust_score_eligible": False,
            },
        )

    return ModuleResult(
        module="security_gate",
        status="pass",
        score=100.0,
        summary="All mandatory security checks passed; Trust Score calculation is permitted.",
        findings=[],
        details={
            "decision": "passed",
            "checks": checks,
            "failed_checks": [],
            "trust_score_eligible": True,
        },
    )
