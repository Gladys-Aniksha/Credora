from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.model_backend import OnnxBackend, load_model_backend
from modules.phase1_foundation.m11_trust_score.aggregator import calculate_trust_score
from modules.phase1_foundation.m8_etc_classifier.evaluate import evaluate_classifier
from modules.phase2_deep_trust.m3_robustness_testing.robustness import test_robustness
from modules.phase2_deep_trust.m4_data_drift.drift import detect_data_drift
from modules.phase2_deep_trust.m5_explainability.explain import explain_model
from modules.phase2_deep_trust.m8_behavior_analysis.behavior import analyze_behavior
from modules.phase3_operations.m4_adversarial_validation.adversarial import (
    run_adversarial_validation,
)


DIAGNOSTIC_MODULES = (
    "classifier_evaluation",
    "robustness_testing",
    "data_drift_detection",
    "explainability",
    "behavior_analysis",
    "adversarial_validation",
)


def verify_variant(variant_dir: Path) -> dict:
    metadata = json.loads((variant_dir / "metadata.json").read_text(encoding="utf-8"))
    model_path = variant_dir / f"{metadata['model_name']}.onnx"
    test_path = variant_dir / "test.csv"
    features = pd.read_csv(test_path)[metadata["expected_features"]]
    backend = load_model_backend(model_path)
    if not isinstance(backend, OnnxBackend):
        raise AssertionError(f"{metadata['model_name']} did not load through OnnxBackend.")
    predictions = backend.predict(features)
    probabilities = backend.predict_proba(features)
    if predictions.shape != (len(features),):
        raise AssertionError(f"Unexpected prediction shape for {metadata['model_name']}.")
    if probabilities is None or probabilities.shape != (len(features), len(metadata["class_labels"])):
        raise AssertionError(f"Unexpected probability shape for {metadata['model_name']}.")

    results = [
        evaluate_classifier(model_path, test_path, metadata),
        test_robustness(model_path, test_path, metadata),
        detect_data_drift(test_path, metadata),
        explain_model(model_path, test_path, metadata),
        analyze_behavior(model_path, test_path, metadata),
        run_adversarial_validation(model_path, test_path, metadata),
    ]
    diagnostic = calculate_trust_score(results, DIAGNOSTIC_MODULES)
    by_module = {result.module: result for result in results}
    sensitive_labels = by_module["adversarial_validation"].details.get("sensitive_labels", [])
    return {
        "variant": metadata["model_name"],
        "backend": type(backend).__name__,
        "prediction_shape": list(predictions.shape),
        "probability_shape": list(probabilities.shape),
        "module_scores": {result.module: result.score for result in results},
        "module_statuses": {result.module: result.status for result in results},
        "test_accuracy": by_module["classifier_evaluation"].details.get("accuracy"),
        "weighted_diagnostic_score": diagnostic.score,
        "official_trust_score_issued": False,
        "score_context": "The weighted score is calculated for assessment and drift tracking. The unsigned model still fails the Security Gate and is blocked from deployment.",
        "sensitive_labels": sensitive_labels,
        "sensitive_label_detected": "Malicious-DoH-Tunnel" in sensitive_labels,
        "explainability_method": by_module["explainability"].details.get("method"),
    }


def _summary_table(results: list[dict]) -> str:
    modules = list(DIAGNOSTIC_MODULES)
    headers = ["Variant", *modules, "Diagnostic", "Sensitive label"]
    rows = []
    for result in results:
        rows.append([
            result["variant"],
            *[f"{result['module_scores'][module]:.2f}" for module in modules],
            f"{result['weighted_diagnostic_score']:.2f}",
            "yes" if result["sensitive_label_detected"] else "no",
        ])
    widths = [max(len(headers[index]), *(len(row[index]) for row in rows)) for index in range(len(headers))]
    line = " | ".join(headers[index].ljust(widths[index]) for index in range(len(headers)))
    divider = "-+-".join("-" * width for width in widths)
    body = [" | ".join(row[index].ljust(widths[index]) for index in range(len(headers))) for row in rows]
    return "\n".join([line, divider, *body])


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Credora modules against the DoH ONNX test kit.")
    parser.add_argument(
        "--kit-root",
        type=Path,
        default=PROJECT_ROOT / "data" / "doh_onnx_test_kit",
    )
    args = parser.parse_args()
    results = [
        verify_variant(args.kit_root / variant)
        for variant in ("credora_doh_strong", "credora_doh_weak")
    ]
    if results[0]["weighted_diagnostic_score"] <= results[1]["weighted_diagnostic_score"]:
        raise AssertionError("The strong DoH model did not score higher than the weak model.")
    output_path = args.kit_root / "verification_results.json"
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(_summary_table(results))
    print(f"\nSaved verification results to {output_path}")


if __name__ == "__main__":
    main()
