from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from core.hashing import sha256_file
from core.report_schema import Finding, ModuleResult


def check_runtime_integrity(model_path: str | Path, metadata: dict | None = None) -> ModuleResult:
    metadata = metadata or {}
    path = Path(model_path)
    if not path.exists() or not path.is_file():
        return ModuleResult(
            "runtime_integrity", "fail", 0, "Runtime integrity could not establish a model baseline.",
            [Finding("runtime_integrity", "Runtime model missing", "critical", f"Model artifact not found: {path}", "Restore the approved artifact and block model serving until its hash is verified.")],
        )

    actual_hash = sha256_file(path)
    expected_hash = metadata.get("sha256")
    signature_valid = metadata.get("signature_status") == "valid"
    findings: list[Finding] = []
    score = 100.0

    if expected_hash and expected_hash != actual_hash:
        score = 0.0
        findings.append(Finding(
            "runtime_integrity", "Runtime model hash changed", "critical",
            "The model artifact no longer matches its approved SHA-256 baseline.",
            "Stop model serving, restore the approved artifact, investigate the file change, and rotate the deployment only after re-signing it.",
        ))
    elif not expected_hash:
        score -= 35
        findings.append(Finding(
            "runtime_integrity", "No approved runtime hash", "high",
            "Runtime monitoring has no approved hash to compare with the deployed model.",
            "Store the reviewed model SHA-256 in signed metadata before deployment.",
        ))
    else:
        findings.append(Finding(
            "runtime_integrity", "Runtime hash baseline established", "info",
            "The model artifact matches the approved SHA-256 value.",
            "Recheck this hash at service startup and on a scheduled runtime interval.",
        ))

    if not signature_valid:
        score -= 20
        findings.append(Finding(
            "runtime_integrity", "Runtime signature evidence missing", "medium",
            "Metadata does not mark the deployed artifact signature as valid.",
            "Sign the model manifest and verify the signature before starting the model service.",
        ))

    score = round(max(0.0, score), 2)
    status = "pass" if score >= 80 else "warning" if score >= 55 else "fail"
    return ModuleResult(
        module="runtime_integrity", status=status, score=score,
        summary="Compared the runtime model artifact with its approved integrity baseline.",
        findings=findings,
        details={
            "integrity_state": "verified" if expected_hash == actual_hash and signature_valid else "changed" if expected_hash else "unbaselined",
            "model_path": str(path.resolve()),
            "actual_sha256": actual_hash,
            "expected_sha256": expected_hash,
            "signature_valid": signature_valid,
            "file_size_bytes": path.stat().st_size,
            "file_modified_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
            "checked_at": datetime.now(timezone.utc).isoformat(),
        },
    )
