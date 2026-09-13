from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from core.model_loading import load_checked_model
from core.report_schema import Finding, ModuleResult


MALICIOUS_LABEL_HINTS = ("malicious", "attack", "suspicious", "botnet", "scan", "dos", "ddos", "intrusion")


def _extract_estimator(model):
    if hasattr(model, "named_steps"):
        for name in ["classifier", "model", "estimator", "rf"]:
            if name in model.named_steps:
                return model.named_steps[name]
        return list(model.named_steps.values())[-1]
    return model


def _feature_importance(model, feature_columns: list[str]) -> list[dict]:
    estimator = _extract_estimator(model)
    importances = getattr(estimator, "feature_importances_", None)
    if importances is None or len(importances) != len(feature_columns):
        return []
    ranked = sorted(zip(feature_columns, importances), key=lambda item: item[1], reverse=True)
    return [{"feature": feature, "importance": round(float(value), 5)} for feature, value in ranked]


def _confidence_summary(model, x_test: pd.DataFrame) -> dict:
    if not hasattr(model, "predict_proba"):
        return {"available": False}
    probabilities = model.predict_proba(x_test)
    if isinstance(probabilities, list):
        probabilities = probabilities[0]
    max_confidence = np.max(probabilities, axis=1)
    low_confidence_rate = float(np.mean(max_confidence < 0.65))
    return {
        "available": True,
        "mean_confidence": round(float(np.mean(max_confidence)), 4),
        "p10_confidence": round(float(np.quantile(max_confidence, 0.10)), 4),
        "low_confidence_rate": round(low_confidence_rate, 4),
    }


def analyze_behavior(model_path: str | Path, dataset_path: str | Path, metadata: dict | None = None) -> ModuleResult:
    metadata = metadata or {}
    findings: list[Finding] = []

    try:
        model = load_checked_model(model_path)
        data = pd.read_csv(dataset_path)
    except Exception as exc:  # noqa: BLE001
        return ModuleResult(
            "behavior_analysis",
            "fail",
            0,
            "Behavior analysis could not run.",
            [Finding("behavior_analysis", "Behavior analysis failed", "high", str(exc), "Verify that the model and test CSV are compatible.")],
        )

    target_column = metadata.get("target_column", "label")
    if target_column not in data.columns:
        return ModuleResult(
            "behavior_analysis",
            "fail",
            0,
            "Target column missing for behavior analysis.",
            [Finding("behavior_analysis", "Missing target column", "critical", f"Dataset does not contain {target_column}.")],
        )

    feature_columns = metadata.get("expected_features") or [column for column in data.columns if column != target_column]
    missing_features = [feature for feature in feature_columns if feature not in data.columns]
    if missing_features:
        return ModuleResult(
            "behavior_analysis",
            "fail",
            0,
            "Behavior analysis could not run because features are missing.",
            [Finding("behavior_analysis", "Feature mismatch", "critical", f"Missing features: {', '.join(missing_features)}", "Upload a dataset with the model's expected feature columns.")],
        )

    x_test = data[feature_columns]
    y_true = data[target_column].astype(str)
    y_pred = pd.Series(model.predict(x_test)).astype(str)
    labels = metadata.get("class_labels") or sorted(y_true.unique().tolist())
    labels = [str(label) for label in labels]

    report = classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0)
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    confidence = _confidence_summary(model, x_test)
    top_features = _feature_importance(model, feature_columns)

    weak_classes = []
    for label in labels:
        metrics = report.get(label, {})
        recall = float(metrics.get("recall", 0))
        precision = float(metrics.get("precision", 0))
        f1 = float(metrics.get("f1-score", 0))
        if recall < 0.85 or precision < 0.85 or f1 < 0.85:
            weak_classes.append({"class": label, "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)})

    malicious_labels = [label for label in labels if any(hint in label.lower() for hint in MALICIOUS_LABEL_HINTS)]
    malicious_weak = [item for item in weak_classes if item["class"] in malicious_labels]

    confusion_pairs = []
    for actual_idx, actual in enumerate(labels):
        for predicted_idx, predicted in enumerate(labels):
            if actual_idx == predicted_idx:
                continue
            mistakes = int(matrix[actual_idx][predicted_idx])
            if mistakes:
                confusion_pairs.append({"actual": actual, "predicted": predicted, "count": mistakes})
    confusion_pairs = sorted(confusion_pairs, key=lambda item: item["count"], reverse=True)

    score = 100.0
    if malicious_weak:
        score -= 25
        labels_text = ", ".join(item["class"] for item in malicious_weak)
        findings.append(Finding(
            "behavior_analysis",
            "Weak malicious/suspicious class detection",
            "high",
            f"The model is weak on security-sensitive class(es): {labels_text}.",
            f"Add more labeled {labels_text} flows, tune class weights, and set a deployment gate that blocks release until recall for these classes is at least 0.90.",
        ))
    elif malicious_labels:
        findings.append(Finding(
            "behavior_analysis",
            "Security-sensitive class detection is strong",
            "info",
            f"The model correctly handles monitored class(es): {', '.join(malicious_labels)} on this test set.",
            "Keep a separate malicious/suspicious holdout set and retest before every deployment.",
        ))

    if weak_classes and not malicious_weak:
        score -= min(20, len(weak_classes) * 8)
        weakest = min(weak_classes, key=lambda item: item["f1"])
        findings.append(Finding(
            "behavior_analysis",
            "Class-specific behavior weakness",
            "medium",
            f"The weakest class is {weakest['class']} with F1 {weakest['f1']}.",
            f"Collect more {weakest['class']} samples and inspect flows that are confused with nearby classes.",
        ))

    if confusion_pairs:
        score -= min(18, sum(pair["count"] for pair in confusion_pairs) * 2)
        pair = confusion_pairs[0]
        findings.append(Finding(
            "behavior_analysis",
            "Class confusion detected",
            "medium",
            f"{pair['actual']} is most often misclassified as {pair['predicted']} ({pair['count']} flow(s)).",
            f"Add targeted features that separate {pair['actual']} from {pair['predicted']}, then retrain and compare the confusion matrix.",
        ))

    if confidence.get("available"):
        low_rate = confidence["low_confidence_rate"]
        if low_rate > 0.20:
            score -= 18
            findings.append(Finding(
                "behavior_analysis",
                "Many low-confidence predictions",
                "medium",
                f"{low_rate:.1%} of predictions have confidence below 0.65.",
                "Add an abstain/review threshold: if max class probability is below 0.65, route the flow to manual review instead of auto-deploying the decision.",
            ))
        else:
            findings.append(Finding(
                "behavior_analysis",
                "Prediction confidence is stable",
                "info",
                f"Mean confidence is {confidence['mean_confidence']}; low-confidence rate is {low_rate:.1%}.",
                "Keep monitoring confidence drift in production traffic.",
            ))
    else:
        score -= 8
        findings.append(Finding(
            "behavior_analysis",
            "Prediction confidence unavailable",
            "low",
            "The model does not expose predict_proba(), so confidence-based review thresholds cannot be assessed.",
            "Use a classifier with probability estimates or calibrate the model before deployment.",
        ))

    if top_features:
        top = top_features[0]
        top3_sum = sum(item["importance"] for item in top_features[:3])
        if top["importance"] > 0.45:
            score -= 12
            findings.append(Finding(
                "behavior_analysis",
                "Behavior relies heavily on one traffic pattern",
                "medium",
                f"The model's strongest behavior signal is {top['feature']} with importance {top['importance']}.",
                f"Validate that {top['feature']} cannot be spoofed easily and add alternate timing/byte-ratio features before deployment.",
            ))
        elif top3_sum > 0.75:
            score -= 7
            findings.append(Finding(
                "behavior_analysis",
                "Behavior depends on a narrow feature group",
                "low",
                f"The top three features contribute {top3_sum:.2f} of total model importance.",
                "Test on traffic captured from a different network before deployment.",
            ))
        else:
            findings.append(Finding(
                "behavior_analysis",
                "Behavior uses distributed evidence",
                "info",
                "Feature importance is not dominated by a single flow pattern.",
                "Preserve this feature diversity when retraining future versions.",
            ))

    if not findings:
        findings.append(Finding("behavior_analysis", "No behavioral issues detected", "info", "The model behavior is stable on the uploaded test data."))

    score = round(max(0.0, min(score, 100.0)), 2)
    status = "pass" if score >= 80 else "warning" if score >= 55 else "fail"
    summary = f"Analysed class behavior, confidence, confusion, and feature reliance across {len(data)} flow record(s)."
    return ModuleResult(
        module="behavior_analysis",
        status=status,
        score=score,
        summary=summary,
        findings=findings,
        details={
            "confidence": confidence,
            "weak_classes": weak_classes,
            "malicious_or_suspicious_classes": malicious_labels,
            "confusion_pairs": confusion_pairs[:10],
            "top_features": top_features[:10],
            "class_metrics": {label: report.get(label, {}) for label in labels},
        },
    )
