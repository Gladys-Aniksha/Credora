from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from core.model_access import model_operation


def load_json(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.exists():
        return {}
    return json.loads(file_path.read_text(encoding="utf-8"))


@model_operation("report.export.json")
def save_json(path: str | Path, payload: dict[str, Any]) -> None:
    if "module_results" in payload:
        from core.artifact_integrity import assert_report_artifact_integrity
        from core.report_evidence import validate_report_evidence

        validate_report_evidence(payload)
        assert_report_artifact_integrity(payload)
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
