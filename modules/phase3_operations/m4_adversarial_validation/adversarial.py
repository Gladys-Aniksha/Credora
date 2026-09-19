from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, recall_score

from core.db import get_sensitive_label_taxonomy
from core.model_loading import load_checked_model
from core.report_schema import Finding, ModuleResult


SENSITIVE_LABEL_HINTS = ("malicious", "attack", "suspicious", "botnet", "scan", "dos", "ddos", "intrusion")
TIMING_HINTS = ("duration", "iat", "inter_arrival", "latency", "time")
VOLUME_HINTS = ("byte", "packet", "size", "count", "rate", "per_second")


def _numeric_columns(frame: pd.DataFrame) -> list[str]:
    return frame.select_dtypes(include=["number", "bool"]).columns.tolist()


def _matching_columns(columns: list[str], hints: tuple[str, ...]) -> list[str]:
    return [column for column in columns if any(hint in column.lower() for hint in hints)]


def _sensitive_recall(y_true: pd.Series, y_pred: pd.Series, sensitive_labels: list[str]) -> float | None:
    if not sensitive_labels:
        return None
    recalls = recall_score(
        y_true.astype(str), y_pred.astype(str), labels=sensitive_labels, average=None, zero_division=0
    )
    return float(np.min(recalls)) if len(recalls) else None


def _feature_importance_order(model, feature_columns: list[str]) -> list[str]:
    estimator = list(model.named_steps.values())[-1] if hasattr(model, "named_steps") else model
    values = getattr(estimator, "feature_importances_", None)
    if values is None or len(values) != len(feature_columns):
        return feature_columns
    return [feature for feature, _ in sorted(zip(feature_columns, values), key=lambda item: item[1], reverse=True)]


def _build_scenarios(
    model,
    features: pd.DataFrame,
    labels: pd.Series,
    feature_columns: list[str],
    sensitive_labels: list[str],
) -> list[tuple[str, str, pd.DataFrame, list[str]]]:
    numeric = _numeric_columns(features)
    timing = _matching_columns(numeric, TIMING_HINTS) or numeric[: max(1, len(numeric) // 3)]
    volume = _matching_columns(numeric, VOLUME_HINTS) or numeric
    ranked = _feature_importance_order(model, feature_columns)
    top_features = [feature for feature in ranked if feature in numeric][:2]
    rng = np.random.default_rng(2026)

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


def run_adversarial_validation(
    model_path: str | Path, dataset_path: str | Path, metadata: dict | None = None
) -> ModuleResult:
    metadata = metadata or {}
    try:
        model = load_checked_model(model_path)
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
    baseline_f1 = float(f1_score(y_true, baseline_pred, average="weighted", zero_division=0))
    labels = [str(label) for label in (metadata.get("class_labels") or sorted(y_true.unique().tolist()))]
    sensitive_hints = get_sensitive_label_taxonomy() or SENSITIVE_LABEL_HINTS
    sensitive_labels = [label for label in labels if any(hint in label.lower() for hint in sensitive_hints)]
    baseline_sensitive_recall = _sensitive_recall(y_true, baseline_pred, sensitive_labels)

    scenarios = []
    for name, description, attacked, changed_features in _build_scenarios(model, x_test, y_true, feature_columns, sensitive_labels):
        attacked_pred = pd.Series(model.predict(attacked)).astype(str)
        attacked_f1 = float(f1_score(y_true, attacked_pred, average="weighted", zero_division=0))
        stability = float(np.mean(attacked_pred.values == baseline_pred.values))
        sensitive_recall = _sensitive_recall(y_true, attacked_pred, sensitive_labels)
        scenarios.append({
            "scenario": name,
            "description": description,
            "features_changed": changed_features,
            "f1": round(attacked_f1, 4),
            "f1_drop": round(max(0.0, baseline_f1 - attacked_f1), 4),
            "prediction_stability": round(stability, 4),
            "sensitive_recall": round(sensitive_recall, 4) if sensitive_recall is not None else None,
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
        summary=f"Ran {len(scenarios)} adversarial encrypted-flow scenario(s); worst-case F1 was {worst['f1']:.3f}.",
        findings=findings,
        details={
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

