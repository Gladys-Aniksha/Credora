from __future__ import annotations

from pathlib import Path

import pandas as pd

from core.db import save_drift_window, save_runtime_alert
from core.report_schema import ModuleResult
from modules.phase2_deep_trust.m4_data_drift.drift import detect_data_drift


def monitor_drift_window(
    *,
    model_name: str,
    window_path: str | Path,
    baseline_path: str | Path,
    window_label: str,
    expected_features: list[str] | None = None,
    owner_id: int | None = None,
) -> ModuleResult:
    window = Path(window_path)
    frame = pd.read_csv(window)
    metadata = {
        "model_name": model_name,
        "baseline_dataset_path": str(Path(baseline_path)),
        "expected_features": expected_features or [column for column in frame.columns if column != "label"],
        "target_column": "label",
    }
    result = detect_data_drift(window, metadata)
    save_drift_window(
        model_name=model_name,
        window_label=window_label,
        source_path=window,
        row_count=len(frame),
        result=result,
        owner_id=owner_id,
    )
    if result.status != "pass":
        finding = next((item for item in result.findings if item.severity != "info"), None)
        save_runtime_alert(
            source="rolling_drift",
            severity=finding.severity if finding else "medium",
            title=finding.title if finding else "Production drift window requires review",
            message=finding.description if finding else result.summary,
            recommendation=finding.recommendation if finding else "Review current traffic and retrain if drift persists.",
            model_name=model_name,
            details={"window_label": window_label, **result.details},
            dedupe_key=f"drift:{model_name}:{window_label}:{result.status}",
            owner_id=owner_id,
        )
    return result


def monitor_rolling_windows(
    *,
    model_name: str,
    captured_csv_path: str | Path,
    baseline_path: str | Path,
    output_dir: str | Path,
    window_size: int = 250,
    step_size: int | None = None,
    expected_features: list[str] | None = None,
    owner_id: int | None = None,
) -> list[ModuleResult]:
    if window_size <= 0:
        raise ValueError("window_size must be positive")
    step = step_size or window_size
    if step <= 0:
        raise ValueError("step_size must be positive")
    frame = pd.read_csv(captured_csv_path)
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    results = []
    for start in range(0, len(frame), step):
        window = frame.iloc[start : start + window_size]
        if window.empty:
            continue
        label = f"rows-{start + 1}-{start + len(window)}"
        window_path = destination / f"{label}.csv"
        window.to_csv(window_path, index=False)
        results.append(
            monitor_drift_window(
                model_name=model_name,
                window_path=window_path,
                baseline_path=baseline_path,
                window_label=label,
                expected_features=expected_features,
                owner_id=owner_id,
            )
        )
    return results

