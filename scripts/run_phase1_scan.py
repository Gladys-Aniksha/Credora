from __future__ import annotations

import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.config import REPORT_DIR
from core.db import register_model, save_scan
from core.hashing import sha256_file
from core.report_schema import ModuleResult, TrustReport
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


def run_phase1_scan(
    model_path: str | Path,
    dataset_path: str | Path,
    requirements_path: str | Path,
    metadata_path: str | Path | None = None,
    progress_callback=None,
    generate_docx: bool = True,
) -> TrustReport:
    def progress(level: str, message: str) -> None:
        if progress_callback:
            progress_callback(level, message)

    metadata = {}
    if metadata_path and Path(metadata_path).exists():
        progress("Level 0 - Intake", "Reading model metadata and preparing assessment inputs.")
        metadata = json.loads(Path(metadata_path).read_text(encoding="utf-8"))

    results: list[ModuleResult] = []
    progress("Level 1 - Integrity", "Verifying model file type, hash, signature metadata, and artifact size.")
    results.append(verify_model(model_path, metadata))
    progress("Level 2 - Supply Chain", "Scanning dependency file for package and vulnerability risk.")
    results.append(scan_dependencies(requirements_path))
    progress("Level 3 - Classifier Performance", "Running predictions on the labeled encrypted-flow test dataset.")
    results.append(evaluate_classifier(model_path, dataset_path, metadata))
    progress("Level 4 - Robustness", "Perturbing numeric flow features to see whether predictions remain stable.")
    results.append(test_robustness(model_path, dataset_path, metadata))
    progress("Level 5 - Data Drift", "Comparing uploaded traffic features against the training baseline distribution.")
    results.append(detect_data_drift(dataset_path, metadata))
    progress("Level 6 - Explainability", "Inspecting which traffic features drive the model's decisions.")
    results.append(explain_model(model_path, dataset_path, metadata))
    progress("Level 7 - Behavior Analysis", "Checking confidence, class confusion, suspicious-class recall, and behavior-specific weaknesses.")
    results.append(analyze_behavior(model_path, dataset_path, metadata))
    progress("Level 8 - Model Risk", "Assessing serialization format, metadata completeness, and deployment-risk indicators.")
    results.append(analyze_model_risk(model_path, metadata))
    progress("Level 9 - Adversarial Validation", "Testing timing jitter, sensitive-flow evasion, and sensor feature dropout scenarios.")
    results.append(run_adversarial_validation(model_path, dataset_path, metadata))
    progress("Level 10 - Runtime Integrity", "Establishing the approved runtime hash and signature baseline.")
    results.append(check_runtime_integrity(model_path, metadata))

    progress("Level 11 - Trust Scoring", "Combining validation evidence into a preliminary production trust score.")
    preliminary_trust = calculate_trust_score(results)
    progress("Level 12 - Deployment Gate", "Applying mandatory production score, integrity, and security-sensitive recall gates.")
    results.append(evaluate_deployment_gate(results, preliminary_trust.score, metadata))
    model_name = metadata.get("model_name") or Path(model_path).stem
    progress("Level 13 - Trust Drift", "Comparing this model score with prior scans for suspicious trust changes.")
    results.append(analyze_trust_drift(preliminary_trust.score, model_name))
    progress("Level 14 - Final Report", "Building the production gate decision, tailored fixes, and Phase 3 report.")
    trust_result = calculate_trust_score(results)
    results.append(trust_result)

    recommendations = []
    for result in results:
        for finding in result.findings:
            if finding.recommendation and finding.severity != "info":
                recommendations.append(finding.recommendation)
    recommendations = list(dict.fromkeys(recommendations))

    report = TrustReport.create(model_name, trust_result.score, trust_result.summary, results, recommendations)
    output_path = REPORT_DIR / f"{model_name}_phase3_trust_report.json"

    docx_path = None
    if generate_docx:
        try:
            docx_path = create_docx_report(report, REPORT_DIR / f"{model_name}_phase3_trust_report.docx")
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
            results = [result for result in results if result.module != "trust_score"] + [trust_result]
            report = TrustReport.create(model_name, trust_result.score, trust_result.summary, results, recommendations)

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
    return report


if __name__ == "__main__":
    import argparse

    from core.config import METADATA_DIR, PROCESSED_DATA_DIR, SAMPLE_MODEL_DIR, SAMPLE_REQUIREMENTS_DIR

    parser = argparse.ArgumentParser(description="Run the complete TrustAI Sentinel Phase 1-3 assessment.")
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
