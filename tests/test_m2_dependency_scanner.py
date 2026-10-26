from __future__ import annotations

import json
import subprocess

from modules.phase1_foundation.m2_dependency_scanner import scanner


def test_dependency_scanner_parses_packages_and_vulnerabilities(tmp_path, monkeypatch) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "# runtime\nrequests==2.19.0\nuvicorn[standard]>=0.20\n-r extra.txt\n",
        encoding="utf-8",
    )
    payload = {
        "dependencies": [
            {
                "name": "requests",
                "vulns": [
                    {"id": "CVE-TEST-1", "description": "first", "fix_versions": ["2.31.0"]},
                    {"id": "CVE-TEST-2", "description": "second", "fix_versions": ["2.32.0"]},
                ],
            }
        ]
    }

    monkeypatch.setattr(
        scanner.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, json.dumps(payload), ""),
    )

    result = scanner.scan_dependencies(requirements)

    assert result.status == "warning"
    assert result.score == 70
    assert result.details["package_count"] == 2
    assert result.details["packages"] == ["requests", "uvicorn"]
    assert [item["id"] for item in result.details["vulnerabilities"]] == [
        "CVE-TEST-1",
        "CVE-TEST-2",
    ]
    assert result.findings[0].severity == "high"


def test_dependency_scanner_reports_missing_requirements_file(tmp_path) -> None:
    result = scanner.scan_dependencies(tmp_path / "missing.txt")

    assert result.status == "warning"
    assert result.score == 55
    assert result.details == {"package_count": 0, "vulnerabilities": [], "requirements_available": False}
    assert result.findings[0].title == "Missing requirements file"
