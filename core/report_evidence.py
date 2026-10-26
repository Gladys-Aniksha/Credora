"""Validate explicit finding citations against the containing module's evidence."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from core.report_schema import TrustReport


class ReportEvidenceError(ValueError):
    """A report contains an untraceable or ambiguous finding."""


def resolve_metric(result: dict[str, Any], metric: str) -> Any:
    """Resolve dotted dictionary keys/list indices without evaluating expressions."""
    if not isinstance(metric, str) or not metric or metric != metric.strip():
        raise ReportEvidenceError("Finding metric must be a nonempty explicit evidence path.")
    parts = metric.split(".")
    if (any(not part for part in parts)
            or parts[0] not in {"score", "status", "details"}
            or (parts[0] in {"score", "status"} and len(parts) != 1)
            or (parts[0] == "details" and len(parts) < 2)):
        raise ReportEvidenceError(f"Unsupported finding metric path: {metric!r}.")
    value: Any = result
    for part in parts:
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isascii() and part.isdecimal():
            try:
                index = int(part)
            except ValueError:
                raise ReportEvidenceError(f"Finding metric {metric!r} has an invalid list index.") from None
            if index >= len(value):
                raise ReportEvidenceError(f"Finding metric {metric!r} does not resolve to actual module evidence.")
            value = value[index]
        else:
            raise ReportEvidenceError(f"Finding metric {metric!r} does not resolve to actual module evidence.")
    return value


def validate_report_evidence(report: dict[str, Any] | TrustReport) -> None:
    """Reject missing/misattributed citations; never modify or retrofit a report.

    This checks structural traceability to recorded results. It cannot prove that
    the measurements themselves are truthful or that prose correctly interprets them.
    """
    if isinstance(report, TrustReport):
        report = asdict(report)
    if not isinstance(report, dict) or not isinstance(report.get("module_results"), list):
        raise ReportEvidenceError("Report must contain a module_results list.")
    seen: set[str] = set()
    for result in report["module_results"]:
        if not isinstance(result, dict):
            raise ReportEvidenceError("Each actual module result must be an object.")
        module = result.get("module")
        if not isinstance(module, str) or not module.strip():
            raise ReportEvidenceError("Each actual module result needs a nonempty module ID.")
        if module in seen:
            raise ReportEvidenceError(f"Duplicate actual module ID: {module!r}.")
        seen.add(module)
        findings = result.get("findings", [])
        if not isinstance(findings, list):
            raise ReportEvidenceError(f"Module {module!r} findings must be a list.")
        for finding in findings:
            if not isinstance(finding, dict) or finding.get("module") != module:
                raise ReportEvidenceError(f"Finding module must equal its containing actual module {module!r}.")
            try:
                resolve_metric(result, finding.get("metric", ""))
            except ReportEvidenceError as exc:
                raise ReportEvidenceError(f"Module {module!r}, finding {finding.get('title', '')!r}: {exc}") from exc
