from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score

from core.model_backend import load_model_backend
from core.report_schema import Finding, ModuleResult


TRIAL_SEEDS = tuple(range(25))


def _percentile(values: list[float], percentile: float = 10) -> float:
    return float(np.percentile(values, percentile))


def test_robustness(model_path: str | Path, dataset_path: str | Path, metadata: dict | None = None, noise_level: float = 0.05) -> ModuleResult:
    metadata = metadata or {}
    if metadata.get("input_type", "tabular") == "sequence":
        from modules.phase3_operations.m4_adversarial_validation.sequence_adversarial import run_sequence_robustness

        return run_sequence_robustness(model_path, dataset_path, metadata)
    findings: list[Finding] = []
    model_file = Path(model_path)
    data_file = Path(dataset_path)

    try:
        model = load_model_backend(model_file)
        data = pd.read_csv(data_file)
    except Exception as exc:  # noqa: BLE001
        return ModuleResult("robustness_testing", "fail", 0, "Robustness test could not run.", [Finding("robustness_testing", "Robustness test failed", "high", str(exc), "Verify that model and CSV files are compatible.")])

    target_column = metadata.get("target_column", "label")
    if target_column not in data.columns:
        return ModuleResult("robustness_testing", "fail", 0, "Target column missing for robustness test.", [Finding("robustness_testing", "Missing target column", "critical", f"Dataset does not contain {target_column}.")])

    feature_columns = metadata.get("expected_features") or [column for column in data.columns if column != target_column]
    feature_columns = [column for column in feature_columns if column in data.columns]
    X = data[feature_columns].copy()
    y_true = data[target_column]
    numeric_columns = X.select_dtypes(include=["number", "bool"]).columns.tolist()

    if not numeric_columns:
        return ModuleResult("robustness_testing", "warning", 60, "No numeric traffic features available for perturbation.", [Finding("robustness_testing", "No perturbable features", "medium", "Robustness testing needs numeric flow metadata features.", "Use numeric flow features such as duration, packet count, byte count, and inter-arrival time.")])

    baseline_predictions = model.predict(X)
    baseline_accuracy = accuracy_score(y_true, baseline_predictions)
    baseline_f1 = f1_score(y_true, baseline_predictions, average="weighted", zero_division=0)

    baseline_values = pd.Series(baseline_predictions).astype(str).values
    trials = []
    for seed in TRIAL_SEEDS:
        rng = np.random.default_rng(seed)
        perturbed = X.copy()
        for column in numeric_columns:
            series = pd.to_numeric(perturbed[column], errors="coerce")
            scale = series.std()
            if pd.isna(scale) or scale == 0:
                scale = max(abs(float(series.mean() or 0)), 1.0)
            noise = rng.normal(0, scale * noise_level, len(series))
            perturbed[column] = (series + noise).clip(lower=0)

        predictions = model.predict(perturbed)
        trials.append({
            "seed": seed,
            "accuracy": float(accuracy_score(y_true, predictions)),
            "f1": float(f1_score(y_true, predictions, average="weighted", zero_division=0)),
            "prediction_stability": float(
                np.mean(pd.Series(predictions).astype(str).values == baseline_values)
            ),
        })

    accuracy_values = [trial["accuracy"] for trial in trials]
    f1_values = [trial["f1"] for trial in trials]
    stability_values = [trial["prediction_stability"] for trial in trials]
    mean_accuracy = float(np.mean(accuracy_values))
    mean_f1 = float(np.mean(f1_values))
    mean_stability = float(np.mean(stability_values))
    worst_case_accuracy = _percentile(accuracy_values)
    perturbed_f1 = _percentile(f1_values)
    prediction_stability = _percentile(stability_values)
    f1_drop = max(0.0, baseline_f1 - perturbed_f1)

    score = round(max(0.0, 100.0 - (f1_drop * 170) - ((1 - prediction_stability) * 65)), 2)
    if f1_drop > 0.15 or prediction_stability < 0.75:
        severity = "high"
        findings.append(Finding("robustness_testing", "Model is sensitive to small traffic changes", severity, f"F1 dropped by {f1_drop:.3f} and prediction stability was {prediction_stability:.3f}.", "Retrain with more varied traffic samples or add robustness testing before deployment."))
    elif f1_drop > 0.06 or prediction_stability < 0.9:
        findings.append(Finding("robustness_testing", "Moderate robustness risk", "medium", f"F1 dropped by {f1_drop:.3f} under small feature perturbations.", "Review features that are unstable in real encrypted traffic."))
    else:
        findings.append(Finding("robustness_testing", "Robust under small feature changes", "info", f"Perturbed F1 remained {perturbed_f1:.3f} with {prediction_stability:.3f} prediction stability."))

    status = "pass" if score >= 80 else "warning" if score >= 55 else "fail"
    return ModuleResult(
        module="robustness_testing",
        status=status,
        score=score,
        summary=f"Tested robustness across {len(TRIAL_SEEDS)} trials with {noise_level * 100:.1f}% numeric feature perturbation.",
        findings=findings,
        details={
            "noise_level": noise_level,
            "trial_count": len(TRIAL_SEEDS),
            "lower_percentile": 10,
            "baseline_accuracy": round(float(baseline_accuracy), 4),
            "baseline_f1": round(float(baseline_f1), 4),
            "mean_perturbed_accuracy": round(mean_accuracy, 4),
            "worst_case_accuracy": round(worst_case_accuracy, 4),
            "mean_perturbed_f1": round(mean_f1, 4),
            "perturbed_f1": round(float(perturbed_f1), 4),
            "f1_drop": round(float(f1_drop), 4),
            "mean_prediction_stability": round(mean_stability, 4),
            "prediction_stability": round(prediction_stability, 4),
            "perturbed_features": numeric_columns,
            "trials": [
                {
                    "seed": trial["seed"],
                    "accuracy": round(trial["accuracy"], 4),
                    "f1": round(trial["f1"], 4),
                    "prediction_stability": round(trial["prediction_stability"], 4),
                }
                for trial in trials
            ],
        },
    )
