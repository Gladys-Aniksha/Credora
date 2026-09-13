from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from core.config import DATA_DIR, PROJECT_ROOT
from core.report_schema import Finding, ModuleResult
from core.security import SecurityValidationError, ensure_within_directory, resolve_user_data_path


def _psi(expected: pd.Series, actual: pd.Series, buckets: int = 10) -> float:
    expected = pd.to_numeric(expected, errors="coerce").dropna()
    actual = pd.to_numeric(actual, errors="coerce").dropna()
    if expected.empty or actual.empty:
        return 0.0
    quantiles = np.linspace(0, 1, buckets + 1)
    breakpoints = np.unique(np.quantile(expected, quantiles))
    if len(breakpoints) < 3:
        return 0.0
    expected_counts, _ = np.histogram(expected, bins=breakpoints)
    actual_counts, _ = np.histogram(actual, bins=breakpoints)
    expected_pct = np.maximum(expected_counts / max(expected_counts.sum(), 1), 0.0001)
    actual_pct = np.maximum(actual_counts / max(actual_counts.sum(), 1), 0.0001)
    return float(np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct)))


def detect_data_drift(current_dataset_path: str | Path, metadata: dict | None = None) -> ModuleResult:
    metadata = metadata or {}
    findings: list[Finding] = []
    current_path = Path(current_dataset_path)
    baseline_path = metadata.get("training_dataset_path") or metadata.get("baseline_dataset_path")
    if baseline_path:
        try:
            baseline_path = resolve_user_data_path(baseline_path, PROJECT_ROOT)
            baseline_path = ensure_within_directory(baseline_path, DATA_DIR)
        except SecurityValidationError as exc:
            return ModuleResult(
                module="data_drift_detection",
                status="fail",
                score=0,
                summary="Rejected unsafe baseline dataset path.",
                findings=[Finding(
                    "data_drift_detection",
                    "Unsafe baseline dataset path",
                    "critical",
                    str(exc),
                    "Use a baseline dataset stored under Credora's data directory, not an arbitrary path from uploaded metadata.",
                )],
                details={"baseline_dataset_path": str(baseline_path), "drifted_features": []},
            )
    else:
        baseline_path = current_path.parents[1] / "processed" / "encrypted_traffic_train.csv"

    if not baseline_path.exists():
        return ModuleResult(
            module="data_drift_detection",
            status="warning",
            score=65,
            summary="No baseline training dataset was available for drift comparison.",
            findings=[Finding("data_drift_detection", "Missing baseline dataset", "medium", "Drift detection needs a training or baseline CSV to compare against the uploaded test data.", "Add training_dataset_path to metadata or keep the training CSV in data/processed.")],
            details={"baseline_dataset_path": str(baseline_path), "drifted_features": []},
        )

    try:
        baseline = pd.read_csv(baseline_path)
        current = pd.read_csv(current_path)
    except Exception as exc:  # noqa: BLE001
        return ModuleResult("data_drift_detection", "fail", 0, "Could not read datasets for drift detection.", [Finding("data_drift_detection", "Dataset read failed", "high", str(exc))])

    target_column = metadata.get("target_column", "label")
    feature_columns = metadata.get("expected_features") or [column for column in current.columns if column != target_column]
    common_numeric = [column for column in feature_columns if column in baseline.columns and column in current.columns and pd.api.types.is_numeric_dtype(baseline[column])]

    drift_rows = []
    for column in common_numeric:
        psi = _psi(baseline[column], current[column])
        drift_rows.append({"feature": column, "psi": round(psi, 4), "drift_level": "high" if psi >= 0.25 else "medium" if psi >= 0.1 else "low"})

    drifted = [row for row in drift_rows if row["psi"] >= 0.1]
    high_drifted = [row for row in drift_rows if row["psi"] >= 0.25]
    max_psi = max([row["psi"] for row in drift_rows], default=0.0)
    mean_psi = float(np.mean([row["psi"] for row in drift_rows])) if drift_rows else 0.0
    score = round(max(0.0, 100.0 - len(drifted) * 8 - len(high_drifted) * 10 - min(max_psi * 25, 20)), 2)

    if high_drifted:
        findings.append(Finding("data_drift_detection", "High data drift detected", "high", f"{len(high_drifted)} feature(s) have PSI >= 0.25.", "Re-evaluate or retrain the classifier with current traffic data."))
    elif drifted:
        findings.append(Finding("data_drift_detection", "Moderate data drift detected", "medium", f"{len(drifted)} feature(s) have PSI >= 0.10.", "Monitor model performance and consider retraining if the trend continues."))
    else:
        findings.append(Finding("data_drift_detection", "No major drift detected", "info", "Current test traffic is close to the baseline feature distribution."))

    status = "pass" if score >= 80 else "warning" if score >= 55 else "fail"
    return ModuleResult(
        module="data_drift_detection",
        status=status,
        score=score,
        summary=f"Compared {len(common_numeric)} numeric traffic feature(s) against baseline data.",
        findings=findings,
        details={
            "baseline_dataset_path": str(baseline_path),
            "current_dataset_path": str(current_path),
            "mean_psi": round(mean_psi, 4),
            "max_psi": round(max_psi, 4),
            "drifted_features": drifted,
            "feature_drift": drift_rows,
        },
    )
