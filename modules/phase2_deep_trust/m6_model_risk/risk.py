from __future__ import annotations

from pathlib import Path
from core.model_storage import model_size

from core.report_schema import Finding, ModuleResult


def analyze_model_risk(model_path: str | Path, metadata: dict | None = None) -> ModuleResult:
    metadata = metadata or {}
    path = Path(model_path)
    findings: list[Finding] = []
    score = 100.0

    if not path.exists():
        return ModuleResult("model_risk_analyzer", "fail", 0, "Model risk analysis could not find the file.", [Finding("model_risk_analyzer", "Missing model", "critical", f"Model file not found: {path}", metric="details.model_available")], {"model_available": False, "file_name": path.name})

    size_mb = model_size(path) / (1024 * 1024)
    extension = path.suffix.lower()
    expected_features = metadata.get("expected_features") or []
    input_type = metadata.get("input_type", "tabular")
    missing: list[str] = []
    missing_sequence: list[str] = []

    if extension in {".pkl", ".pickle", ".joblib"}:
        score -= 12
        findings.append(Finding("model_risk_analyzer", "Unsafe serialization family", "medium", "Pickle/joblib models can execute code when loaded from an untrusted source.", "Accept only models from trusted sources and verify hashes before loading.", metric="details.extension"))
    if size_mb > 100:
        score -= 20
        findings.append(Finding("model_risk_analyzer", "Large model artifact", "medium", f"Model size is {size_mb:.1f} MB.", "Confirm the artifact is expected and scan the storage source.", metric="details.size_mb"))
    elif size_mb > 25:
        score -= 8
        findings.append(Finding("model_risk_analyzer", "Moderately large model artifact", "low", f"Model size is {size_mb:.1f} MB.", "Keep model-size baselines for future versions.", metric="details.size_mb"))
    if not metadata:
        score -= 25
        findings.append(Finding("model_risk_analyzer", "Metadata missing", "high", "No metadata file was supplied for this model.", "Provide metadata with model name, version, algorithm, expected features, and hash.", metric="details.metadata_fields"))
    else:
        required = ["model_name", "version", "algorithm", "framework", "task", "target_column"]
        missing = [field for field in required if not metadata.get(field)]
        if missing:
            score -= min(25, len(missing) * 5)
            findings.append(Finding("model_risk_analyzer", "Incomplete metadata", "medium", f"Missing metadata field(s): {', '.join(missing)}.", "Complete model metadata before deployment.", metric="details.missing_metadata_fields"))
    if input_type == "sequence":
        required_sequence = ["max_sequence_length", "sequence_dtype", "vocab_size", "class_labels"]
        missing_sequence = [field for field in required_sequence if not metadata.get(field)]
        if missing_sequence:
            score -= min(30, len(missing_sequence) * 8)
            findings.append(Finding("model_risk_analyzer", "Incomplete sequence contract", "high", f"Missing sequence metadata: {', '.join(missing_sequence)}.", "Provide the complete sequence input contract before scanning.", metric="details.missing_sequence_fields"))
    elif not expected_features:
        score -= 12
        findings.append(Finding("model_risk_analyzer", "Expected feature list missing", "medium", "The system cannot strictly validate dataset/model feature compatibility.", "Add expected_features to metadata.json.", metric="details.expected_feature_count"))
    if metadata.get("_signature_verified") is not True:
        score -= 10
        findings.append(Finding("model_risk_analyzer", "Model signature not verified", "medium", "Credora did not verify an Ed25519 package signature for this artifact.", "Scan a signed .credora package before deployment approval.", metric="details.signature_verified"))

    if metadata.get("signature_status") == "valid" and metadata.get("_signature_verified") is not True:
        findings.append(Finding(
            "model_risk_analyzer",
            "Self-reported signature ignored",
            "info",
            "The uploaded metadata claims signature_status=valid, but this field is not used as signature evidence.",
            "Use Credora package verification so signature validity is set internally.", metric="details.signature_claim",
        ))

    risk_indicator_count = len(findings)
    if not findings:
        findings.append(Finding("model_risk_analyzer", "No major model risk indicators", "info", "Artifact metadata, size, and format are acceptable for the current prototype.", metric="details.risk_indicator_count"))

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
            "input_type": input_type,
            "sequence_length": metadata.get("max_sequence_length"),
            "sequence_dtype": metadata.get("sequence_dtype"),
            "signature_verified": metadata.get("_signature_verified") is True,
            "signature_claim": metadata.get("signature_status"),
            "missing_metadata_fields": missing,
            "missing_sequence_fields": missing_sequence,
            "risk_indicator_count": risk_indicator_count,
        },
    )
