from __future__ import annotations

import json
import time
from pathlib import Path
from threading import Event
from typing import Callable

from core.db import save_integrity_check, save_runtime_alert
from core.report_schema import ModuleResult
from modules.phase3_operations.m6_runtime_integrity.watcher import check_runtime_integrity


def run_integrity_cycle(model_path: str | Path, metadata_path: str | Path) -> ModuleResult:
    metadata = json.loads(Path(metadata_path).read_text(encoding="utf-8"))
    model_name = metadata.get("model_name") or Path(model_path).stem
    result = check_runtime_integrity(model_path, metadata)
    save_integrity_check(model_name, result)
    if result.status != "pass":
        finding = next((item for item in result.findings if item.severity in {"critical", "high", "medium"}), None)
        details = result.details
        save_runtime_alert(
            source="runtime_integrity",
            severity=finding.severity if finding else "high",
            title=finding.title if finding else "Runtime integrity check failed",
            message=finding.description if finding else result.summary,
            recommendation=finding.recommendation if finding else "Block serving and restore the approved artifact.",
            model_name=model_name,
            details=details,
            dedupe_key=f"integrity:{model_name}:{details.get('actual_sha256')}:{result.status}",
        )
    return result


def monitor_runtime_integrity(
    model_path: str | Path,
    metadata_path: str | Path,
    interval_seconds: float = 300.0,
    max_checks: int | None = None,
    stop_event: Event | None = None,
    on_check: Callable[[ModuleResult], None] | None = None,
) -> list[ModuleResult]:
    if interval_seconds < 0:
        raise ValueError("interval_seconds cannot be negative")
    results: list[ModuleResult] = []
    completed = 0
    while max_checks is None or completed < max_checks:
        if stop_event and stop_event.is_set():
            break
        result = run_integrity_cycle(model_path, metadata_path)
        results.append(result)
        completed += 1
        if on_check:
            on_check(result)
        if max_checks is not None and completed >= max_checks:
            break
        if stop_event:
            stop_event.wait(interval_seconds)
        else:
            time.sleep(interval_seconds)
    return results
