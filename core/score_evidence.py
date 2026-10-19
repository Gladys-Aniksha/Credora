"""Read measured and published trust scores without changing scoring policy."""
from __future__ import annotations

from math import isfinite
from typing import Any, TypedDict


class TrustScoreEvidence(TypedDict):
    measured_score: float | None
    published_score: float | None
    cap_applied: bool
    cap: float | None
    reason: str | None


def _number(value: object, *, maximum: float | None = None) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (ValueError, OverflowError):
        return None
    if not isfinite(number) or number < 0 or (maximum is not None and number > maximum):
        return None
    return number


def _historical_score(results: list[dict], details: dict) -> float | None:
    weights = details.get("weights")
    expected = details.get("expected_modules")
    if not isinstance(weights, dict) or not isinstance(expected, list) or not expected:
        return None
    if any(not isinstance(name, str) or not name or name == "trust_score" for name in expected):
        return None
    if len(set(expected)) != len(expected):
        return None
    by_module = {}
    for result in results:
        name = result.get("module")
        if not isinstance(name, str) or name not in expected:
            continue
        if name in by_module:
            return None
        by_module[name] = result
    applicable = [name for name in expected if by_module.get(name, {}).get("status") != "not_applicable"]
    if not applicable:
        return None
    weighted_score = total_weight = 0.0
    scored = 0
    for name in applicable:
        weight = _number(weights.get(name))
        if weight is None:
            return None
        if name not in by_module:
            continue
        score = _number(by_module[name].get("score"), maximum=100)
        if score is None:
            return None
        scored += 1
        weighted_score += score * weight
        total_weight += weight
    if not scored or not total_weight or not isfinite(total_weight) or not isfinite(weighted_score):
        return None
    return round(weighted_score / total_weight * (scored / len(applicable)), 2)


def trust_score_evidence(reportdict: dict[str, Any]) -> TrustScoreEvidence:
    """Return measured_score/published_score/cap_applied/cap/reason.

    Scores and cap are finite 0..100 numbers or None; reason is text or None.
    measured_score prefers trust_score.details.uncapped_score. Older reports
    reconstruct the weighted score and missing-module coverage using only their
    stored weights, expected_modules and module_results (never today's policy).
    Reconstruction must agree with the recorded published score after any
    recorded provenance cap. Missing/ambiguous evidence yields None, not zero.
    cap_applied describes score clipping, not signature or deployment approval.
    No input is modified and no database or current configuration is consulted.
    """
    raw_results = reportdict.get("module_results", [])
    results = [item for item in raw_results if isinstance(item, dict)] if isinstance(raw_results, list) else []
    trust_results = [item for item in results if item.get("module") == "trust_score"]
    trust = trust_results[0] if len(trust_results) == 1 else {}
    details = trust.get("details", {})
    details = details if isinstance(details, dict) else {}
    published = _number(reportdict.get("trust_score"), maximum=100)
    if published is None:
        published = _number(trust.get("score"), maximum=100)
    if details.get("issued") is False:
        published = None
    cap = _number(details.get("raw_model_trust_cap"), maximum=100)
    measured = _number(details.get("uncapped_score"), maximum=100)
    if measured is None and "uncapped_score" not in details:
        measured = _historical_score(results, details)
        if measured is not None and published is not None:
            expected_published = min(measured, cap) if cap is not None else measured
            if abs(expected_published - published) > 0.000001:
                measured = None
    applied = cap is not None and (
        measured > cap if measured is not None else published == cap
    )
    return {
        "measured_score": measured,
        "published_score": published,
        "cap_applied": applied,
        "cap": cap,
        "reason": (f"Unsigned model provenance limits the published trust score to {cap:g}/100; "
                   "a verified signed model package is required to remove this cap.") if applied else None,
    }
