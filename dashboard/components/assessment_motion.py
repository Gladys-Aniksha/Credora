from __future__ import annotations

import json
import math
from pathlib import Path
from uuid import uuid4

import streamlit.components.v1 as components

from dashboard.components.common import module_label
from modules.phase1_foundation.m11_trust_score.aggregator import WEIGHTS


def comparable_reports(reports: list[dict], current: dict) -> list[dict]:
    return sorted([
        report for report in reports
        if report.get("model_name") == current.get("model_name")
        and report.get("input_type", "tabular") == current.get("input_type", "tabular")
        and str(report.get("generated_at", "")) < str(current.get("generated_at", ""))
    ], key=lambda report: str(report.get("generated_at", "")), reverse=True)


def _score(value: object) -> float | None:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return None
    return max(0.0, min(number, 100.0)) if math.isfinite(number) else None


def motion_payload(current: dict, baseline: dict | None, *, live: bool = False) -> dict:
    results = {item["module"]: item for item in current.get("module_results", [])}
    reference = {item["module"]: item for item in (baseline or {}).get("module_results", [])}
    modules = [name for name in WEIGHTS if name != "trust_drift_timeline"]
    def measured(items: dict, name: str) -> float | None:
        item = items.get(name, {})
        return _score(item.get("score")) if item.get("status") not in {"not_applicable", "not_run"} else None
    points = [{"label": module_label(name), "current": measured(results, name), "baseline": measured(reference, name)} for name in modules]
    trust = results.get("trust_score", {})
    gate = results.get("security_gate", {}).get("details", {})
    return {
        "model": current.get("model_name", "Model assessment"),
        "points": points,
        "score": _score(current.get("trust_score")),
        "baselineScore": _score((baseline or {}).get("trust_score")),
        "live": live,
        "gate": "Deployment blocked" if gate.get("decision") in {"blocked", "failed"} or trust.get("details", {}).get("security_gate_passed") is False else "Security Gate passed" if gate.get("decision") == "passed" else "Security Gate pending",
        "hasBaseline": baseline is not None,
        "completed": sum(point["current"] is not None for point in points),
        "identity": str(current.get("model_name", "")) + str(current.get("input_type", "tabular")),
    }


def render_motion(current: dict, baseline: dict | None = None, *, live: bool = False) -> None:
    template = (Path(__file__).parent / "assessment_motion.html").read_text(encoding="utf-8")
    payload = motion_payload(current, baseline, live=live)
    payload["mount"] = uuid4().hex
    data = json.dumps(payload, allow_nan=False).replace("<", "\\u003c")
    components.html(template.replace("__ASSESSMENT_DATA__", data), height=440, scrolling=False)


def render_assessment_comparison(current: dict, reports: list[dict]) -> None:
    previous = comparable_reports(reports, current)
    baseline = previous[0] if previous else None
    render_motion(current, baseline)
