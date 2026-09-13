from __future__ import annotations

from pathlib import Path

from core.report_schema import Finding, ModuleResult


def analyze_model_risk(model_path: str | Path, metadata: dict | None = None) -> ModuleResult:
    metadata = metadata or {}
    path = Path(model_path)
    findings: list[Finding] = []
    score = 100.0

    if not path.exists():
        return ModuleResult("model_risk_analyzer", "fail", 0, "Model risk analysis could not find the file.", [Finding("model_risk_analyzer", "Missing model", "critical", f"Model file not found: {path}")])

    size_mb = path.stat().st_size / (1024 * 1024)
    extension = path.suffix.lower()
    expected_features = metadata.get("expected_features") or []

    if extension in {".pkl", ".pickle", ".joblib"}:
        score -= 12
        findings.append(Finding("model_risk_analyzer", "Unsafe serialization family", "medium", "Pickle/joblib models can execute code when loaded from an untrusted source.", "Accept only models from trusted sources and verify hashes before loading."))
    if size_mb > 100:
        score -= 20
        findings.append(Finding("model_risk_analyzer", "Large model artifact", "medium", f"Model size is {size_mb:.1f} MB.", "Confirm the artifact is expected and scan the storage source."))
    elif size_mb > 25:
        score -= 8
        findings.append(Finding("model_risk_analyzer", "Moderately large model artifact", "low", f"Model size is {size_mb:.1f} MB.", "Keep model-size baselines for future versions."))
    if not metadata:
        score -= 25
        findings.append(Finding("model_risk_analyzer", "Metadata missing", "high", "No metadata file was supplied for this model.", "Provide metadata with model name, version, algorithm, expected features, and hash."))
    else:
        required = ["model_name", "version", "algorithm", "framework", "task", "target_column"]
        missing = [field for field in required if not metadata.get(field)]
        if missing:
            score -= min(25, len(missing) * 5)
            findings.append(Finding("model_risk_analyzer", "Incomplete metadata", "medium", f"Missing metadata field(s): {', '.join(missing)}.", "Complete model metadata before deployment."))
    if not expected_features:
        score -= 12
        findings.append(Finding("model_risk_analyzer", "Expected feature list missing", "medium", "The system cannot strictly validate dataset/model feature compatibility.", "Add expected_features to metadata.json."))
    if metadata.get("_signature_verified") is not True:
        score -= 10
        findings.append(Finding("model_risk_analyzer", "Model signature not verified", "medium", "Credora did not verify an Ed25519 package signature for this artifact.", "Scan a signed .credora package before deployment approval."))

    if metadata.get("signature_status") == "valid" and metadata.get("_signature_verified") is not True:
        findings.append(Finding(
            "model_risk_analyzer",
            "Self-reported signature ignored",
            "info",
            "The uploaded metadata claims signature_status=valid, but this field is not used as signature evidence.",
            "Use Credora package verification so signature validity is set internally.",
        ))

    if not findings:
        findings.append(Finding("model_risk_analyzer", "No major model risk indicators", "info", "Artifact metadata, size, and format are acceptable for the current prototype."))

    score = round(max(0.0, min(score, 100.0)), 2)
    status = "pass" if score >= 80 else "warning" if score >= 55 else "fail"
    return ModuleResult(
        module="model_risk_analyzer",
        status=status,
        score=score,
        summary="Checked artifact-level model deployment risk indicators.",
        findings=findings,
        details={
            "file_name": path.name,
            "extension": extension,
            "size_mb": round(size_mb, 3),
            "metadata_fields": sorted(key for key in metadata.keys() if not key.startswith("_")),
            "expected_feature_count": len(expected_features),
            "signature_verified": metadata.get("_signature_verified") is True,
        },
    )
