from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from core.report_schema import Finding, ModuleResult

REQ_PATTERN = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:==|>=|<=|~=|>|<)?\s*([^;#\s]+)?")


def parse_requirements(requirements_path: str | Path) -> list[str]:
    path = Path(requirements_path)
    if not path.exists():
        return []
    packages: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        match = REQ_PATTERN.match(stripped)
        if match:
            packages.append(match.group(1))
    return packages


def scan_dependencies(requirements_path: str | Path) -> ModuleResult:
    path = Path(requirements_path)
    findings: list[Finding] = []
    packages = parse_requirements(path)

    if not path.exists():
        return ModuleResult(
            module="dependency_scanner",
            status="warning",
            score=55,
            summary="No requirements.txt file was provided.",
            findings=[Finding("dependency_scanner", "Missing requirements file", "medium", "Dependencies cannot be audited without a requirements file.", "Upload requirements.txt for scanning.")],
            details={"package_count": 0, "vulnerabilities": []},
        )

    vulnerabilities = []
    pip_audit_error = ""
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-r", str(path), "-f", "json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=45,
        )
        if completed.stdout.strip():
            payload = json.loads(completed.stdout)
            for dep in payload.get("dependencies", []):
                for vuln in dep.get("vulns", []):
                    vulnerabilities.append({
                        "package": dep.get("name"),
                        "id": vuln.get("id"),
                        "description": (vuln.get("description") or "")[:220],
                        "fix_versions": vuln.get("fix_versions", []),
                    })
        if completed.returncode not in (0, 1):
            pip_audit_error = completed.stderr.strip()[:300]
    except Exception as exc:  # noqa: BLE001
        pip_audit_error = str(exc)

    score = 100.0
    if vulnerabilities:
        score -= min(65, len(vulnerabilities) * 15)
        findings.append(Finding(
            "dependency_scanner",
            "Known dependency vulnerabilities found",
            "high" if len(vulnerabilities) >= 2 else "medium",
            f"Found {len(vulnerabilities)} known vulnerability record(s).",
            "Upgrade affected packages or pin safe versions.",
        ))
    else:
        findings.append(Finding("dependency_scanner", "No vulnerabilities returned", "info", "No known vulnerabilities were returned by the local audit command."))

    if pip_audit_error:
        score -= 10
        findings.append(Finding(
            "dependency_scanner",
            "pip-audit warning",
            "low",
            f"pip-audit could not fully complete: {pip_audit_error}",
            "Ensure pip-audit is installed and network access is available for full audits.",
        ))

    status = "pass" if score >= 80 else "warning" if score >= 50 else "fail"
    return ModuleResult(
        module="dependency_scanner",
        status=status,
        score=max(0, score),
        summary=f"Scanned {len(packages)} package(s) from {path.name}.",
        findings=findings,
        details={"package_count": len(packages), "packages": packages, "vulnerabilities": vulnerabilities},
    )
