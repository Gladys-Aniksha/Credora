from __future__ import annotations

from core.report_schema import Finding, ModuleResult
from core.threat_model import build_threat_model


def _result(
    module: str,
    *,
    status: str = "pass",
    score: float = 100,
    findings: list[Finding] | None = None,
) -> ModuleResult:
    return ModuleResult(module, status, score, "evidence", findings or [], {})


def test_threat_model_uses_real_findings_and_keeps_risk_separate() -> None:
    results = [
        _result("model_verification"),
        _result(
            "dependency_scanner",
            status="fail",
            score=20,
            findings=[Finding("dependency_scanner", "Known CVE", "high", "Vulnerable dependency detected.")],
        ),
        _result("runtime_integrity"),
        _result("security_gate"),
    ]

    model = build_threat_model(results, model_name="traffic-model")
    dependency = next(threat for threat in model["threats"] if threat["id"] == "TM-003")

    assert dependency["detection_status"] == "HIGH RISK"
    assert dependency["initial_risk"] == 9
    assert dependency["residual_risk"] == 9
    assert "trust_score" not in dependency


def test_passed_controls_reduce_but_do_not_remove_residual_risk() -> None:
    results = [
        _result("model_verification"),
        _result("runtime_integrity"),
        _result("security_gate"),
    ]

    model = build_threat_model(results)
    tampering = next(threat for threat in model["threats"] if threat["id"] == "TM-001")

    assert tampering["detection_status"] == "MITIGATED"
    assert 0 < tampering["residual_risk"] < tampering["initial_risk"]
    assert tampering["residual_explanation"]


def test_unsupported_account_compromise_is_not_claimed_as_mitigated() -> None:
    model = build_threat_model([], auth_rbac_enabled=True)
    account = next(threat for threat in model["threats"] if threat["id"] == "TM-014")

    assert account["detection_status"] == "NOT ASSESSED"


def test_summary_and_matrix_cover_every_catalogued_threat() -> None:
    model = build_threat_model([], report_signed=True)

    assert model["summary"]["threats_identified"] == 15
    assert len(model["control_matrix"]) == 15
    assert model["summary"]["not_assessed"] > 0
    assert model["method"].startswith("Risk = Likelihood x Impact")
