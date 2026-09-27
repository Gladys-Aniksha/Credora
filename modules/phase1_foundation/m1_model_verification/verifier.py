from __future__ import annotations

from pathlib import Path
from core.config import RISKY_MODEL_EXTENSIONS, SUPPORTED_MODEL_EXTENSIONS, verify_model_file_type
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
            "Use a supported tabular classifier saved as .joblib, .pkl, or .onnx.",
        ))
    elif not verify_model_file_type(path):
        score -= 40
        findings.append(Finding(
            "model_verification",
            "Model file signature mismatch",
            "critical",
            "The artifact extension is supported, but its serialized structure is invalid for that model format.",
            "Reject renamed or malformed model uploads before any automatic loading.",
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

    expected_hash = metadata.get("_expected_sha256")
    if expected_hash:
        if expected_hash == file_hash:
            findings.append(Finding("model_verification", "Hash matched trusted baseline", "info", "The model hash matches a server-side or package-verified baseline."))
        else:
            score -= 35
            findings.append(Finding(
                "model_verification",
                "Hash mismatch",
                "critical",
                "The model hash does not match the trusted baseline.",
                "Do not deploy until the model source is verified.",
            ))
    else:
        score -= 8
        findings.append(Finding(
            "model_verification",
            "No trusted hash baseline",
            "medium",
            "No server-side or signed-package reference hash was available for comparison.",
            "Register or verify the model through a signed Credora package before approval.",
        ))

    if metadata.get("sha256") and metadata.get("sha256") != expected_hash:
        findings.append(Finding(
            "model_verification",
            "Self-reported hash ignored",
            "info",
            "The uploaded metadata contains a sha256 value, but Credora does not trust upload-provided hashes for scoring.",
            "Use the server-side registry or signed package manifest as the integrity baseline.",
        ))

    if not metadata.get("model_name"):
        score -= 5
        findings.append(Finding("model_verification", "Missing model name", "low", "Metadata does not include model_name.", "Add model_name to metadata."))

    if not metadata.get("version"):
        score -= 5
        findings.append(Finding("model_verification", "Missing model version", "low", "Metadata does not include version.", "Add version to metadata."))

    signature_valid = metadata.get("_signature_verified") is True
    if not signature_valid:
        score -= 10
        findings.append(Finding("model_verification", "Missing or invalid signature", "medium", "No package-verified signature was established for this model artifact.", "Sign and scan model artifacts through the Credora package flow before deployment."))

    score = max(0.0, min(100.0, score))
    status = "pass" if score >= 80 else "warning" if score >= 50 else "fail"
    return ModuleResult(
        module="model_verification",
        status=status,
        score=score,
        summary=f"Verified {path.name}; SHA256 captured and format reviewed.",
        findings=findings,
        details={
            "file_name": path.name,
            "extension": extension,
            "sha256": file_hash,
            "size_mb": round(size_mb, 3),
            "signature_verified": signature_valid,
            "expected_sha256_source": metadata.get("_expected_sha256_source", "none"),
        },
    )
