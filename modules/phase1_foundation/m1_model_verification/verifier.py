from __future__ import annotations

from pathlib import Path
from core.config import RISKY_MODEL_EXTENSIONS, SUPPORTED_MODEL_EXTENSIONS
from core.hashing import sha256_file
from core.report_schema import Finding, ModuleResult


def verify_model(model_path: str | Path, metadata: dict | None = None) -> ModuleResult:
    metadata = metadata or {}
    path = Path(model_path)
    findings: list[Finding] = []

    if not path.exists():
        return ModuleResult(
            module="model_verification",
            status="fail",
            score=0,
            summary="Model file was not found.",
            findings=[Finding("model_verification", "Missing model file", "critical", f"Could not find {path}", "Upload a valid model file.")],
        )

    extension = path.suffix.lower()
    file_hash = sha256_file(path)
    size_mb = path.stat().st_size / (1024 * 1024)
    score = 100.0

    if extension not in SUPPORTED_MODEL_EXTENSIONS:
        score -= 30
        findings.append(Finding(
            "model_verification",
            "Unsupported model format",
            "high",
            f"The file extension {extension} is not supported in Phase 1.",
            "Use a scikit-learn model saved as .joblib or .pkl.",
        ))

    if extension in RISKY_MODEL_EXTENSIONS:
        score -= 10
        findings.append(Finding(
            "model_verification",
            "Pickle-based model format",
            "medium",
            ".joblib and .pkl files can execute code if loaded from an untrusted source.",
            "Only load verified models from trusted sources.",
        ))

    expected_hash = metadata.get("sha256")
    if expected_hash:
        if expected_hash == file_hash:
            findings.append(Finding("model_verification", "Hash matched metadata", "info", "The model hash matches the supplied metadata."))
        else:
            score -= 35
            findings.append(Finding(
                "model_verification",
                "Hash mismatch",
                "critical",
                "The model hash does not match the supplied metadata.",
                "Do not deploy until the model source is verified.",
            ))
    else:
        score -= 8
        findings.append(Finding(
            "model_verification",
            "No expected hash supplied",
            "low",
            "No reference hash was provided for comparison.",
            "Store this hash in metadata for future version checks.",
        ))

    if not metadata.get("model_name"):
        score -= 5
        findings.append(Finding("model_verification", "Missing model name", "low", "Metadata does not include model_name.", "Add model_name to metadata."))

    if not metadata.get("version"):
        score -= 5
        findings.append(Finding("model_verification", "Missing model version", "low", "Metadata does not include version.", "Add version to metadata."))

    signature_status = metadata.get("signature_status", "missing")
    if signature_status != "valid":
        score -= 10
        findings.append(Finding("model_verification", "Missing or invalid signature", "medium", "The model metadata does not show a valid signature.", "Sign model artifacts before deployment."))

    score = max(0.0, min(100.0, score))
    status = "pass" if score >= 80 else "warning" if score >= 50 else "fail"
    return ModuleResult(
        module="model_verification",
        status=status,
        score=score,
        summary=f"Verified {path.name}; SHA256 captured and format reviewed.",
        findings=findings,
        details={"file_name": path.name, "extension": extension, "sha256": file_hash, "size_mb": round(size_mb, 3)},
    )
