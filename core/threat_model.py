from __future__ import annotations

from dataclasses import asdict, is_dataclass
from math import ceil
from typing import Any, cast

from core.threat_catalog import (
    ATTACK_SURFACES,
    OUT_OF_SCOPE_THREATS,
    PROTECTED_ASSETS,
    SECURITY_ASSUMPTIONS,
    THREAT_ACTORS,
    THREAT_DEFINITIONS,
    TRUST_BOUNDARIES,
)

RISK_LABELS = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


def risk_severity(value: int) -> str:
    if value >= 13:
        return "Critical"
    if value >= 9:
        return "High"
    if value >= 5:
        return "Medium"
    return "Low"


def _mapping(value: Any) -> dict[str, Any]:
    if is_dataclass(value):
        return asdict(value)
    return dict(value)


def _relevant_findings(result: dict[str, Any], keywords: list[str]) -> list[dict[str, Any]]:
    output = []
    for finding in result.get("findings", []):
        text = " ".join(
            str(finding.get(field, "")) for field in ("title", "description", "recommendation")
        ).lower()
        if not keywords or any(keyword in text for keyword in keywords):
            output.append(finding)
    return output


def _status_for_threat(definition: dict[str, Any], results: dict[str, dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    if definition.get("not_assessed"):
        return "NOT ASSESSED", []

    evidence = [results[module] for module in definition["modules"] if module in results]
    if not evidence:
        return "NOT ASSESSED", []

    relevant = [
        finding
        for result in evidence
        for finding in _relevant_findings(result, definition.get("keywords", []))
    ]
    if any(finding.get("severity") in {"critical", "high"} for finding in relevant):
        return "HIGH RISK", evidence
    if any(result.get("status") == "fail" for result in evidence):
        return "HIGH RISK", evidence
    if any(finding.get("severity") == "medium" for finding in relevant):
        return "DETECTED", evidence
    if any(result.get("status") == "warning" for result in evidence):
        return "WARNING", evidence
    if len(evidence) < len(definition["modules"]):
        return "NOT ASSESSED", evidence
    return "MITIGATED", evidence


def _residual_value(initial: int, status: str) -> int:
    if status == "MITIGATED":
        return max(1, ceil(initial * 0.25))
    if status == "WARNING":
        return max(1, ceil(initial * 0.65))
    if status == "DETECTED":
        return max(1, ceil(initial * 0.8))
    return initial


def build_threat_model(
    module_results: list[Any],
    *,
    model_name: str = "Unknown model",
    report_signed: bool = False,
    auth_rbac_enabled: bool = True,
) -> dict[str, Any]:
    """Derive threat assessments from existing Credora evidence without rescanning artifacts."""
    results = {_mapping(result).get("module", ""): _mapping(result) for result in module_results}
    if report_signed:
        results["report_signature"] = {
            "module": "report_signature",
            "status": "pass",
            "score": 100,
            "summary": "The report contains a cryptographic signature.",
            "findings": [],
        }
    if auth_rbac_enabled:
        results["auth_rbac"] = {
            "module": "auth_rbac",
            "status": "pass",
            "score": 100,
            "summary": "Authentication, owner scoping, and role authorization are enabled.",
            "findings": [],
        }

    threats = []
    matrix = []
    for definition in THREAT_DEFINITIONS:
        status, evidence = _status_for_threat(definition, results)
        likelihood = cast(int, definition["likelihood"])
        impact = cast(int, definition["impact"])
        controls = cast(list[str], definition["controls"])
        initial_risk = likelihood * impact
        residual_risk = _residual_value(initial_risk, status)
        result_text = "; ".join(
            f"{result.get('module', 'control')}: {str(result.get('status', 'unknown')).upper()}"
            for result in evidence
        ) or "No assessment evidence"
        threat = {
            "id": definition["id"],
            "name": definition["name"],
            "description": definition["description"],
            "threat_actor": definition["actor"],
            "target_asset": definition["asset"],
            "attack_surface": definition["surface"],
            "likelihood": RISK_LABELS[likelihood],
            "impact": RISK_LABELS[impact],
            "initial_risk": initial_risk,
            "severity": risk_severity(initial_risk),
            "existing_controls": list(controls),
            "detection_status": status,
            "control_result": result_text,
            "residual_risk": residual_risk,
            "residual_severity": risk_severity(residual_risk),
            "residual_explanation": definition["residual"],
            "recommended_action": definition["action"],
        }
        threats.append(threat)
        matrix.append({
            "threat": f"{definition['id']} - {definition['name']}",
            "existing_control": ", ".join(controls),
            "result": status,
            "residual_risk": threat["residual_severity"],
        })

    status_counts = {status: sum(threat["detection_status"] == status for threat in threats) for status in ("MITIGATED", "DETECTED", "WARNING", "HIGH RISK", "NOT ASSESSED")}
    severity_counts = {severity: sum(threat["residual_severity"] == severity for threat in threats) for severity in ("Critical", "High", "Medium", "Low")}
    assessed_threats = [threat for threat in threats if threat["detection_status"] != "NOT ASSESSED"]
    highest = max((cast(int, threat["residual_risk"]) for threat in assessed_threats), default=1)
    overall_posture = (
        f"{risk_severity(highest).upper()} RISK"
        if assessed_threats
        else "NOT ASSESSED"
    )

    return {
        "model_name": model_name,
        "method": "Risk = Likelihood x Impact; residual risk is reduced only when existing control evidence passes.",
        "summary": {
            "threats_identified": len(threats),
            "assessed_threats": len(assessed_threats),
            **{key.lower(): value for key, value in severity_counts.items()},
            **{key.lower().replace(" ", "_"): value for key, value in status_counts.items()},
            "overall_threat_posture": overall_posture,
            "not_assessed_note": "Not independently assessed threats are excluded from the headline posture.",
        },
        "protected_assets": PROTECTED_ASSETS,
        "threat_actors": THREAT_ACTORS,
        "attack_surfaces": ATTACK_SURFACES,
        "trust_boundaries": TRUST_BOUNDARIES,
        "threats": threats,
        "control_matrix": matrix,
        "security_assumptions": SECURITY_ASSUMPTIONS,
        "out_of_scope_threats": OUT_OF_SCOPE_THREATS,
    }
