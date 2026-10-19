from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, recall_score

from core.db import get_sensitive_label_taxonomy
from core.model_backend import ModelBackend, load_model_backend
from core.report_schema import Finding, ModuleResult


TIMING_HINTS = ("duration", "iat", "inter_arrival", "latency", "time")
VOLUME_HINTS = ("byte", "packet", "size", "count", "rate", "per_second")
TRIAL_SEEDS = tuple(range(25))


def _numeric_columns(frame: pd.DataFrame) -> list[str]:
    return frame.select_dtypes(include=["number", "bool"]).columns.tolist()


def _matching_columns(columns: list[str], hints: tuple[str, ...]) -> list[str]:
    return [column for column in columns if any(hint in column.lower() for hint in hints)]


def _sensitive_labels(labels: list[str]) -> list[str]:
    sensitive_hints = get_sensitive_label_taxonomy()
    return [label for label in labels if any(hint in label.lower() for hint in sensitive_hints)]


def _sensitive_recall(y_true: pd.Series, y_pred: pd.Series, sensitive_labels: list[str]) -> float | None:
    if not sensitive_labels:
        return None
    recalls = recall_score(
        y_true.astype(str), y_pred.astype(str), labels=sensitive_labels, average=None, zero_division=0
    )
    return float(np.min(recalls)) if len(recalls) else None


def _feature_importance_order(model: ModelBackend, feature_columns: list[str]) -> list[str]:
    values = model.feature_importance(feature_columns)
    if not values:
        return feature_columns
    return [str(item["feature"]) for item in values]


def _build_scenarios(
    model,
    features: pd.DataFrame,
    labels: pd.Series,
    feature_columns: list[str],
    sensitive_labels: list[str],
    seed: int,
) -> list[tuple[str, str, pd.DataFrame, list[str]]]:
    numeric = _numeric_columns(features)
    timing = _matching_columns(numeric, TIMING_HINTS) or numeric[: max(1, len(numeric) // 3)]
    volume = _matching_columns(numeric, VOLUME_HINTS) or numeric
    ranked = _feature_importance_order(model, feature_columns)
    top_features = [feature for feature in ranked if feature in numeric][:2]
    rng = np.random.default_rng(seed)

    timing_frame = features.copy()
    for column in timing:
        multiplier = rng.uniform(0.55, 1.45, len(timing_frame))
        timing_frame[column] = (pd.to_numeric(timing_frame[column], errors="coerce") * multiplier).clip(lower=0)

    evasion_frame = features.copy()
    sensitive_mask = labels.astype(str).isin(sensitive_labels)
    benign_mask = ~sensitive_mask
    if sensitive_mask.any() and benign_mask.any():
        for column in volume:
            benign_median = float(pd.to_numeric(features.loc[benign_mask, column], errors="coerce").median())
            original = pd.to_numeric(features.loc[sensitive_mask, column], errors="coerce")
            evasion_frame.loc[sensitive_mask, column] = (original * 0.35) + (benign_median * 0.65)
    else:
        for column in volume:
            evasion_frame[column] = pd.to_numeric(evasion_frame[column], errors="coerce") * 0.6

    dropout_frame = features.copy()
    for column in top_features:
        dropout_frame[column] = float(pd.to_numeric(features[column], errors="coerce").median())

    return [
        ("timing_jitter", "Large but plausible changes to duration and inter-arrival timing.", timing_frame, timing),
        ("sensitive_flow_evasion", "Security-sensitive flows are blended toward benign byte and packet patterns.", evasion_frame, volume),
        ("sensor_feature_dropout", "The two strongest numeric sensor features are replaced by their median.", dropout_frame, top_features),
    ]


def _percentile(values: list[float], percentile: float = 10) -> float:
    return float(np.percentile(values, percentile))


def run_adversarial_validation(
    model_path: str | Path, dataset_path: str | Path, metadata: dict | None = None
) -> ModuleResult:
    metadata = metadata or {}
    if metadata.get("input_type", "tabular") == "sequence":
        from modules.phase3_operations.m4_adversarial_validation.sequence_adversarial import run_sequence_adversarial_validation

        return run_sequence_adversarial_validation(model_path, dataset_path, metadata)
    try:
        model = load_model_backend(model_path, metadata)
        data = pd.read_csv(dataset_path)
    except Exception as exc:  # noqa: BLE001
        return ModuleResult(
            "adversarial_validation", "fail", 0, "Adversarial validation could not load the model or dataset.",
            [Finding("adversarial_validation", "Adversarial validation failed", "high", str(exc), "Verify the model and labeled CSV before deployment testing.")],
        )

    target_column = metadata.get("target_column", "label")
    feature_columns = metadata.get("expected_features") or [column for column in data.columns if column != target_column]
    missing = [column for column in [target_column, *feature_columns] if column not in data.columns]
    if missing:
        return ModuleResult(
            "adversarial_validation", "fail", 0, "Adversarial validation inputs are incomplete.",
            [Finding("adversarial_validation", "Missing adversarial-test inputs", "critical", f"Missing column(s): {', '.join(missing)}", "Use a labeled dataset with every expected model feature.")],
        )

    x_test = data[feature_columns].copy()
    y_true = data[target_column].astype(str)
    baseline_pred = pd.Series(model.predict(x_test)).astype(str)
    baseline_accuracy = float(accuracy_score(y_true, baseline_pred))
    baseline_f1 = float(f1_score(y_true, baseline_pred, average="weighted", zero_division=0))
    labels = [str(label) for label in (metadata.get("class_labels") or sorted(y_true.unique().tolist()))]
    sensitive_labels = _sensitive_labels(labels)
    baseline_sensitive_recall = _sensitive_recall(y_true, baseline_pred, sensitive_labels)

    scenario_trials: dict[str, dict] = {}
    for seed in TRIAL_SEEDS:
        for name, description, attacked, changed_features in _build_scenarios(
            model, x_test, y_true, feature_columns, sensitive_labels, seed
        ):
            attacked_pred = pd.Series(model.predict(attacked)).astype(str)
            sensitive_recall = _sensitive_recall(y_true, attacked_pred, sensitive_labels)
            scenario = scenario_trials.setdefault(name, {
                "description": description,
                "features_changed": changed_features,
                "trials": [],
            })
            scenario["trials"].append({
                "seed": seed,
                "accuracy": float(accuracy_score(y_true, attacked_pred)),
                "f1": float(f1_score(y_true, attacked_pred, average="weighted", zero_division=0)),
                "prediction_stability": float(np.mean(attacked_pred.values == baseline_pred.values)),
                "sensitive_recall": sensitive_recall,
            })

    scenarios = []
    for name, scenario in scenario_trials.items():
        trials = scenario["trials"]
        accuracy_values = [trial["accuracy"] for trial in trials]
        f1_values = [trial["f1"] for trial in trials]
        stability_values = [trial["prediction_stability"] for trial in trials]
        sensitive_values = [trial["sensitive_recall"] for trial in trials if trial["sensitive_recall"] is not None]
        worst_f1 = _percentile(f1_values)
        scenarios.append({
            "scenario": name,
            "description": scenario["description"],
            "features_changed": scenario["features_changed"],
            "trial_count": len(trials),
            "lower_percentile": 10,
            "mean_accuracy": round(float(np.mean(accuracy_values)), 4),
            "accuracy": round(_percentile(accuracy_values), 4),
            "mean_f1": round(float(np.mean(f1_values)), 4),
            "f1": round(worst_f1, 4),
            "f1_drop": round(max(0.0, baseline_f1 - worst_f1), 4),
            "mean_prediction_stability": round(float(np.mean(stability_values)), 4),
            "prediction_stability": round(_percentile(stability_values), 4),
            "mean_sensitive_recall": round(float(np.mean(sensitive_values)), 4) if sensitive_values else None,
            "sensitive_recall": round(_percentile(sensitive_values), 4) if sensitive_values else None,
            "trials": [
                {
                    "seed": trial["seed"],
                    "accuracy": round(trial["accuracy"], 4),
                    "f1": round(trial["f1"], 4),
                    "prediction_stability": round(trial["prediction_stability"], 4),
                    "sensitive_recall": round(trial["sensitive_recall"], 4)
                    if trial["sensitive_recall"] is not None else None,
                }
                for trial in trials
            ],
        })

    worst = min(scenarios, key=lambda item: (item["f1"], item["prediction_stability"]))
    max_f1_drop = max(item["f1_drop"] for item in scenarios)
    min_stability = min(item["prediction_stability"] for item in scenarios)
    sensitive_values = [item["sensitive_recall"] for item in scenarios if item["sensitive_recall"] is not None]
    worst_sensitive_recall = min(sensitive_values) if sensitive_values else None
    sensitive_drop = 0.0
    if baseline_sensitive_recall is not None and worst_sensitive_recall is not None:
        sensitive_drop = max(0.0, baseline_sensitive_recall - worst_sensitive_recall)

    absolute_f1_penalty = max(0.0, 0.85 - worst["f1"]) * 80
    absolute_sensitive_penalty = max(0.0, 0.90 - worst_sensitive_recall) * 100 if worst_sensitive_recall is not None else 0.0
    score = (
        100.0
        - (max_f1_drop * 90)
        - ((1 - min_stability) * 35)
        - (sensitive_drop * 45)
        - absolute_f1_penalty
        - absolute_sensitive_penalty
    )
    score = round(max(0.0, min(score, 100.0)), 2)
    findings: list[Finding] = []
    if worst["f1"] < 0.70 or (worst_sensitive_recall is not None and worst_sensitive_recall < 0.75):
        findings.append(Finding(
            "adversarial_validation", "Adversarial traffic bypass risk", "high",
            f"{worst['scenario']} reduced F1 to {worst['f1']:.3f}; worst security-sensitive recall was {worst_sensitive_recall if worst_sensitive_recall is not None else 'not available'}.",
            "Block deployment, add adversarially varied suspicious flows to training, and require security-sensitive recall of at least 0.90 on the release holdout.",
        ))
    elif max_f1_drop > 0.08 or min_stability < 0.85 or (worst_sensitive_recall is not None and worst_sensitive_recall < 0.90):
        findings.append(Finding(
            "adversarial_validation", "Adversarial resilience needs improvement", "medium",
            f"Worst scenario was {worst['scenario']} with F1 {worst['f1']:.3f} and prediction stability {worst['prediction_stability']:.3f}.",
            f"Retrain with the {worst['scenario']} scenario, then rerun Phase 3 until worst-case F1 and security-sensitive recall are both at least 0.90.",
        ))
    else:
        findings.append(Finding(
            "adversarial_validation", "Adversarial release tests passed", "info",
            f"All {len(scenarios)} scenarios retained stable classifier behavior; worst-case F1 was {worst['f1']:.3f}.",
            "Keep these scenarios as mandatory release tests and expand them with captured production traffic.",
        ))

    status = "pass" if score >= 80 else "warning" if score >= 55 else "fail"
    return ModuleResult(
        module="adversarial_validation", status=status, score=score,
        summary=f"Ran {len(scenarios)} adversarial encrypted-flow scenarios across {len(TRIAL_SEEDS)} trials; worst-case F1 was {worst['f1']:.3f}.",
        findings=findings,
        details={
            "trial_count": len(TRIAL_SEEDS),
            "lower_percentile": 10,
            "baseline_accuracy": round(baseline_accuracy, 4),
            "baseline_f1": round(baseline_f1, 4),
            "baseline_sensitive_recall": round(baseline_sensitive_recall, 4) if baseline_sensitive_recall is not None else None,
            "worst_case_f1": worst["f1"],
            "worst_case_scenario": worst["scenario"],
            "max_f1_drop": round(max_f1_drop, 4),
            "absolute_f1_penalty": round(absolute_f1_penalty, 4),
            "absolute_sensitive_recall_penalty": round(absolute_sensitive_penalty, 4),
            "minimum_prediction_stability": round(min_stability, 4),
            "worst_sensitive_recall": worst_sensitive_recall,
            "sensitive_labels": sensitive_labels,
            "scenarios": scenarios,
        },
    )

