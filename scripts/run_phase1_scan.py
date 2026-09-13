from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.config import DATA_DIR, REPORT_DIR
from core.assessment_insights import build_analysis_trace, build_remediation_plan
from core.db import latest_model_by_name, register_model, save_scan
from core.hashing import sha256_file
from core.report_schema import Finding, ModuleResult, TrustReport
from core.security import ensure_within_directory, slugify_filename
from core.storage import save_json
from modules.phase1_foundation.m1_model_verification.verifier import verify_model
from modules.phase1_foundation.m2_dependency_scanner.scanner import scan_dependencies
from modules.phase1_foundation.m8_etc_classifier.evaluate import evaluate_classifier
from modules.phase1_foundation.m11_trust_score.aggregator import calculate_trust_score
from modules.phase2_deep_trust.m3_robustness_testing.robustness import test_robustness
from modules.phase2_deep_trust.m4_data_drift.drift import detect_data_drift
from modules.phase2_deep_trust.m5_explainability.explain import explain_model
from modules.phase2_deep_trust.m6_model_risk.risk import analyze_model_risk
from modules.phase2_deep_trust.m7_trust_drift.trust_drift import analyze_trust_drift
from modules.phase2_deep_trust.m8_behavior_analysis.behavior import analyze_behavior
from modules.phase2_deep_trust.m9_docx_report.docx_report import create_docx_report
from modules.phase3_operations.m4_adversarial_validation.adversarial import run_adversarial_validation
from modules.phase3_operations.m5_secure_deployment.gatekeeper import evaluate_deployment_gate
from modules.phase3_operations.m6_runtime_integrity.watcher import check_runtime_integrity


RAW_MODEL_TRUST_CAP = 70.0


def _safe_report_path(model_name: str, suffix: str) -> Path:
    safe_name = slugify_filename(model_name)
    return ensure_within_directory(REPORT_DIR / f"{safe_name}_{suffix}", REPORT_DIR)


def _apply_raw_model_cap(result: ModuleResult, metadata: dict[str, Any]) -> ModuleResult:
    if metadata.get("_signature_verified") is True or result.score <= RAW_MODEL_TRUST_CAP:
        return result
    result.score = RAW_MODEL_TRUST_CAP
    result.status = "warning"
    result.summary = "Raw pickle/joblib provenance caps the maximum trust score until a signed package is verified."
    result.findings.append(Finding(
        "trust_score",
        "Raw model provenance cap applied",
        "medium",
        f"Unsigned raw model uploads cannot score above {RAW_MODEL_TRUST_CAP:.0f}/100.",
        "Package and sign the model with Credora before requesting deployment approval.",
    ))
    result.details["raw_model_trust_cap"] = RAW_MODEL_TRUST_CAP
    return result


def _augment_trusted_metadata(metadata: dict[str, Any], model_path: Path, package_manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    metadata = dict(metadata)
    model_name = metadata.get("model_name") or model_path.stem
    metadata["_signature_verified"] = package_manifest is not None
    metadata["_expected_sha256"] = None
    metadata["_expected_sha256_source"] = "none"

    if package_manifest:
        metadata["_expected_sha256"] = package_manifest["artifacts"]["model"]["sha256"]
        metadata["_expected_sha256_source"] = "signed_package_manifest"
        return metadata

    registered = latest_model_by_name(str(model_name))
    if registered and registered.get("sha256"):
        metadata["_expected_sha256"] = registered["sha256"]
        metadata["_expected_sha256_source"] = "server_registry"
    return metadata


def run_phase1_scan(
    model_path: str | Path,
    dataset_path: str | Path,
    requirements_path: str | Path,
    metadata_path: str | Path | None = None,
    trusted_public_key_path: str | Path | None = None,
    progress_callback=None,
    generate_docx: bool = True,
) -> TrustReport:
    def progress(level: str, message: str) -> None:
        if progress_callback:
            progress_callback(level, message)

    def run_step(level: str, message: str, runner) -> ModuleResult:
        progress(level, f"Starting: {message}")
        result = runner()
        issues = [finding.title for finding in result.findings if finding.severity != "info"]
        issue_text = f" Issues: {', '.join(issues[:3])}." if issues else " No actionable issue was found."
        progress(
            level,
            f"Completed: {result.status.upper()} at {result.score:.1f}/100. {result.summary}{issue_text}",
        )
        return result

    metadata: dict[str, Any] = {}
    package_manifest = None
    progress("Level 0 - Intake", "Starting: validating uploaded paths and reading model metadata.")
    model_path = Path(model_path)
    dataset_path = Path(dataset_path)
    requirements_path = Path(requirements_path)
    metadata_path = Path(metadata_path) if metadata_path else None

    if model_path.suffix.lower() == ".credora":
        if trusted_public_key_path is None:
            raise ValueError("A trusted public key is required to scan a signed .credora package.")
        from core.model_package import verify_model_package

        extract_dir = ensure_within_directory(DATA_DIR / "uploads" / "verified_packages" / model_path.stem, DATA_DIR)
        verified = verify_model_package(model_path, trusted_public_key_path, extract_dir)
        model_path = verified.model_path
        requirements_path = verified.requirements_path
        metadata_path = verified.metadata_path
        package_manifest = verified.manifest
        progress("Level 0 - Intake", "Completed: verified signed Credora package and extracted trusted artifacts.")

    if metadata_path and Path(metadata_path).exists():
        metadata = json.loads(Path(metadata_path).read_text(encoding="utf-8"))
        metadata = _augment_trusted_metadata(metadata, model_path, package_manifest)
        progress(
            "Level 0 - Intake",
            f"Completed: loaded metadata for {metadata.get('model_name', Path(model_path).stem)} with {len(metadata.get('expected_features', []))} declared feature(s).",
        )
    else:
        metadata = _augment_trusted_metadata({}, model_path, package_manifest)
        progress("Level 0 - Intake", "Completed with warning: no metadata file was supplied; identity and feature checks will be limited.")

    results: list[ModuleResult] = []
    results.append(run_step("Level 1 - Integrity", "calculating the artifact hash and checking type, signature metadata, and size.", lambda: verify_model(model_path, metadata)))
    results.append(run_step("Level 2 - Supply Chain", "auditing declared packages and known dependency vulnerabilities.", lambda: scan_dependencies(requirements_path)))
    results.append(run_step("Level 3 - Classifier Performance", "running every labeled flow through the model and calculating per-class metrics.", lambda: evaluate_classifier(model_path, dataset_path, metadata)))
    results.append(run_step("Level 4 - Robustness", "perturbing numeric flow features and measuring prediction stability.", lambda: test_robustness(model_path, dataset_path, metadata)))
    results.append(run_step("Level 5 - Data Drift", "comparing current flow distributions with the training baseline using PSI.", lambda: detect_data_drift(dataset_path, metadata)))
    results.append(run_step("Level 6 - Explainability", "ranking the traffic features that drive model decisions.", lambda: explain_model(model_path, dataset_path, metadata)))
    results.append(run_step("Level 7 - Behavior Analysis", "examining confidence, weak classes, security-sensitive recall, confusion, and feature reliance.", lambda: analyze_behavior(model_path, dataset_path, metadata)))
    results.append(run_step("Level 8 - Model Risk", "reviewing serialization, metadata completeness, artifact size, and deployment-risk indicators.", lambda: analyze_model_risk(model_path, metadata)))
    results.append(run_step("Level 9 - Adversarial Validation", "testing timing jitter, sensitive-flow evasion, and sensor feature dropout.", lambda: run_adversarial_validation(model_path, dataset_path, metadata)))
    results.append(run_step("Level 10 - Runtime Integrity", "comparing the active artifact with its approved hash and signature baseline.", lambda: check_runtime_integrity(model_path, metadata)))

    progress("Level 11 - Trust Scoring", "Starting: combining module evidence using the published weighting policy.")
    preliminary_trust = calculate_trust_score(results)
    preliminary_trust = _apply_raw_model_cap(preliminary_trust, metadata)
    progress("Level 11 - Trust Scoring", f"Completed: preliminary trust score is {preliminary_trust.score:.1f}/100.")
    results.append(run_step("Level 12 - Deployment Gate", "applying mandatory score, integrity, adversarial, and security-sensitive recall controls.", lambda: evaluate_deployment_gate(results, preliminary_trust.score, metadata)))
    model_name = metadata.get("model_name") or Path(model_path).stem
    results.append(run_step("Level 13 - Trust Drift", "comparing this score with prior assessments of the same model identity.", lambda: analyze_trust_drift(preliminary_trust.score, model_name)))
    progress("Level 14 - Final Report", "Starting: interpreting evidence and generating model-specific corrective actions and retest conditions.")
    trust_result = calculate_trust_score(results)
    trust_result = _apply_raw_model_cap(trust_result, metadata)
    results.append(trust_result)

    analysis_trace = build_analysis_trace(results)
    remediation_plan = build_remediation_plan(results, model_name, metadata)
    recommendations = [item["fix"] for item in remediation_plan]

    report = TrustReport.create(
        model_name,
        trust_result.score,
        trust_result.status,
        results,
        recommendations,
        analysis_trace=analysis_trace,
        remediation_plan=remediation_plan,
    )
    output_path = _safe_report_path(model_name, "phase3_trust_report.json")

    docx_path = None
    if generate_docx:
        try:
            docx_path = create_docx_report(report, _safe_report_path(model_name, "phase3_trust_report.docx"))
        except RuntimeError as exc:
            results.append(ModuleResult(
                module="docx_report_export",
                status="warning",
                score=65,
                summary="DOCX report export is not available until python-docx is installed.",
                findings=[],
                details={"error": str(exc)},
            ))
            trust_result = calculate_trust_score([result for result in results if result.module != "trust_score"])
            trust_result = _apply_raw_model_cap(trust_result, metadata)
            results = [result for result in results if result.module != "trust_score"] + [trust_result]
            analysis_trace = build_analysis_trace(results)
            remediation_plan = build_remediation_plan(results, model_name, metadata)
            recommendations = [item["fix"] for item in remediation_plan]
            report = TrustReport.create(
                model_name,
                trust_result.score,
                trust_result.status,
                results,
                recommendations,
                analysis_trace=analysis_trace,
                remediation_plan=remediation_plan,
            )

    if docx_path:
        report.docx_report_path = str(docx_path)
    report_dict = report.to_dict()
    save_json(output_path, report_dict)

    register_model(
        model_name=model_name,
        version=metadata.get("version", "unknown"),
        algorithm=metadata.get("algorithm"),
        framework=metadata.get("framework"),
        task=metadata.get("task"),
        model_path=model_path,
        dataset_path=dataset_path,
        requirements_path=requirements_path,
        metadata_path=metadata_path,
        sha256=sha256_file(model_path),
    )
    save_scan(report_dict, output_path)
    progress(
        "Level 14 - Final Report",
        f"Completed: saved deep evidence with {len(analysis_trace)} analysis record(s) and {len(remediation_plan)} model-specific fix(es).",
    )
    return report


if __name__ == "__main__":
    import argparse

    from core.config import METADATA_DIR, PROCESSED_DATA_DIR, SAMPLE_MODEL_DIR, SAMPLE_REQUIREMENTS_DIR

    parser = argparse.ArgumentParser(description="Run the complete Credora Phase 1-3 assessment.")
    parser.add_argument("--model", type=Path, default=SAMPLE_MODEL_DIR / "traffic_rf_v1.joblib")
    parser.add_argument("--dataset", type=Path, default=PROCESSED_DATA_DIR / "encrypted_traffic_test.csv")
    parser.add_argument("--requirements", type=Path, default=SAMPLE_REQUIREMENTS_DIR / "requirements_demo.txt")
    parser.add_argument("--metadata", type=Path, default=METADATA_DIR / "traffic_rf_v1_metadata.json")
    parser.add_argument("--no-docx", action="store_true", help="Skip DOCX evidence report generation.")
    args = parser.parse_args()

    report = run_phase1_scan(
        args.model,
        args.dataset,
        args.requirements,
        args.metadata,
        generate_docx=not args.no_docx,
    )
    print(json.dumps(report.to_dict(), indent=2))
