from __future__ import annotations

from core.db import list_scans
from core.report_schema import Finding, ModuleResult


def analyze_trust_drift(
    current_score: float,
    model_name: str,
    owner_id: int | None = None,
    input_type: str = "tabular",
) -> ModuleResult:
    scans = [
        scan
        for scan in list_scans(limit=50, owner_id=owner_id)
        if scan.get("model_name") == model_name
        and scan.get("input_type", "tabular") == input_type
    ]
    findings: list[Finding] = []

    previous_scores = [float(scan.get("trust_score", 0)) for scan in scans]
    previous_best = max(previous_scores) if previous_scores else None
    previous_latest = previous_scores[0] if previous_scores else None
    drop_from_latest = round(previous_latest - current_score, 2) if previous_latest is not None else 0.0
    drop_from_best = round(previous_best - current_score, 2) if previous_best is not None else 0.0

    score = 100.0
    if previous_latest is None:
        findings.append(Finding("trust_drift_timeline", "First trust baseline created", "info", "No previous scan exists for this model, so this score becomes the baseline.", metric="details.previous_scan_count"))
    elif drop_from_latest >= 15:
        score -= 35
        findings.append(Finding("trust_drift_timeline", "Major trust regression", "high", f"Trust score dropped by {drop_from_latest} points from the previous scan.", "Compare model, dataset, dependency, and metadata changes before deployment.", metric="details.drop_from_latest"))
    elif drop_from_latest >= 7:
        score -= 18
        findings.append(Finding("trust_drift_timeline", "Moderate trust regression", "medium", f"Trust score dropped by {drop_from_latest} points from the previous scan.", "Review new warnings before approval.", metric="details.drop_from_latest"))
    else:
        findings.append(Finding("trust_drift_timeline", "Trust score is stable", "info", "No meaningful trust regression was detected against previous scans.", metric="details.drop_from_latest"))

    if drop_from_best >= 20:
        score -= 15
        findings.append(Finding("trust_drift_timeline", "Below historical best", "medium", f"Current score is {drop_from_best} points below this model's best recorded score.", "Inspect the trust timeline for version regressions.", metric="details.drop_from_best"))

    status = "pass" if score >= 80 else "warning" if score >= 55 else "fail"
    return ModuleResult(
        module="trust_drift_timeline",
        status=status,
        score=round(max(score, 0.0), 2),
        summary=f"Compared current trust score with {len(previous_scores)} previous scan(s) for this model.",
        findings=findings,
        details={"input_type": input_type, "previous_scan_count": len(previous_scores), "previous_latest_score": previous_latest, "previous_best_score": previous_best, "drop_from_latest": drop_from_latest, "drop_from_best": drop_from_best},
    )

