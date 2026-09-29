from __future__ import annotations

from core.db import get_trust_weights
from core.report_schema import Finding, ModuleResult

WEIGHTS = {
    "model_verification": 0.09,
    "dependency_scanner": 0.06,
    "classifier_evaluation": 0.13,
    "robustness_testing": 0.08,
    "data_drift_detection": 0.07,
    "explainability": 0.07,
    "dataset_leakage": 0.08,
    "privacy_risk": 0.07,
    "behavior_analysis": 0.08,
    "model_risk_analyzer": 0.05,
    "adversarial_validation": 0.09,
    "runtime_integrity": 0.06,
    "trust_drift_timeline": 0.02,
}
FINAL_EXPECTED_MODULES = tuple(WEIGHTS)
PRE_DEPLOYMENT_EXPECTED_MODULES = tuple(
    module for module in FINAL_EXPECTED_MODULES if module != "trust_drift_timeline"
)


def calculate_trust_score(
    results: list[ModuleResult],
    expected_modules: tuple[str, ...] = FINAL_EXPECTED_MODULES,
) -> ModuleResult:
    by_module = {result.module: result for result in results if result.module != "trust_score"}
    weighted_score = 0.0
    total_weight = 0.0
    findings: list[Finding] = []
    scored_modules: list[str] = []
    missing_modules: list[str] = []

    active_weights = get_trust_weights()
    for module in expected_modules:
        weight = active_weights[module]
        result = by_module.get(module)
        if result is None:
            missing_modules.append(module)
            findings.append(Finding("trust_score", f"Missing {module}", "high", f"{module} did not run.", "Run the full trust scan."))
            continue
        scored_modules.append(module)
        weighted_score += result.score * weight
        total_weight += weight

    normalized_score = weighted_score / total_weight if total_weight else 0.0
    module_coverage = len(scored_modules) / len(expected_modules) if expected_modules else 0.0
    final_score = normalized_score * module_coverage
    if final_score >= 85:
        status = "pass"
        summary = "High overall assurance based on the completed non-gate assessment modules."
    elif final_score >= 70:
        status = "warning"
        summary = "Moderate overall assurance; review warnings before deployment approval."
    else:
        status = "fail"
        summary = "Low overall assurance; major assessment issues require remediation."

    critical_or_high = [finding for result in by_module.values() for finding in result.findings if finding.severity in {"critical", "high"}]
    if critical_or_high:
        findings.append(Finding("trust_score", "High-risk findings present", "high", f"There are {len(critical_or_high)} high or critical finding(s).", "Resolve high-risk findings before deployment."))

    return ModuleResult(
        module="trust_score",
        status=status,
        score=round(final_score, 2),
        summary=summary,
        findings=findings,
        details={
            "weights": active_weights,
            "expected_modules": list(expected_modules),
            "modules_scored": scored_modules,
            "missing_modules": missing_modules,
            "module_coverage": round(module_coverage, 4),
            "issued": True,
        },
    )


def trust_score_not_issued(security_gate: ModuleResult) -> ModuleResult:
    """Represent a blocked score without presenting zero as an assurance measurement."""
    failed_checks = list(security_gate.details.get("failed_checks", []))
    return ModuleResult(
        module="trust_score",
        status="not_run",
        score=0.0,
        summary="Trust Score was not issued because the Security Gate failed.",
        findings=[
            Finding(
                "trust_score",
                "Trust Score not issued",
                "critical",
                "Mandatory security evidence failed before weighted assurance scoring.",
                "Resolve the failed Security Gate checks and rerun the assessment.",
            )
        ],
        details={
            "issued": False,
            "blocked_by": "security_gate",
            "failed_security_checks": failed_checks,
            "weights": {},
            "expected_modules": [],
            "modules_scored": [],
            "missing_modules": [],
            "module_coverage": 0.0,
        },
    )



