from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
Status = Literal["pass", "warning", "fail", "not_run"]


@dataclass
class Finding:
    module: str
    title: str
    severity: Severity
    description: str
    recommendation: str = ""


@dataclass
class ModuleResult:
    module: str
    status: Status
    score: float
    summary: str
    findings: list[Finding] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustReport:
    model_name: str
    generated_at: str
    trust_score: float
    status: str
    module_results: list[ModuleResult]
    recommendations: list[str]
    docx_report_path: str | None = None
    analysis_trace: list[dict[str, Any]] = field(default_factory=list)
    remediation_plan: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        model_name: str,
        trust_score: float,
        status: str,
        module_results: list[ModuleResult],
        recommendations: list[str],
        analysis_trace: list[dict[str, Any]] | None = None,
        remediation_plan: list[dict[str, Any]] | None = None,
    ) -> "TrustReport":
        return cls(
            model_name=model_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            trust_score=round(float(trust_score), 2),
            status=status,
            module_results=module_results,
            recommendations=recommendations,
            analysis_trace=analysis_trace or [],
            remediation_plan=remediation_plan or [],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
