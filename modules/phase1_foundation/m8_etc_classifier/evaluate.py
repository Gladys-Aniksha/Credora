from __future__ import annotations

from pathlib import Path
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from core.model_backend import load_model_backend
from core.report_schema import Finding, ModuleResult
from core.sequence_data import load_sequence_dataset
from core.sequence_validation import validate_sequence_compatibility


def evaluate_classifier(model_path: str | Path, dataset_path: str | Path, metadata: dict | None = None) -> ModuleResult:
    metadata = metadata or {}
    model_file = Path(model_path)
    data_file = Path(dataset_path)
    findings: list[Finding] = []

    if not model_file.exists():
        return ModuleResult("classifier_evaluation", "fail", 0, "Model file not found.", [Finding("classifier_evaluation", "Missing model", "critical", "The model file was not found.")])
    if not data_file.exists():
        return ModuleResult("classifier_evaluation", "fail", 0, "Dataset file not found.", [Finding("classifier_evaluation", "Missing dataset", "critical", "The test dataset was not found.")])

    input_type = metadata.get("input_type", "tabular")
    try:
        if input_type == "sequence":
            compatibility = validate_sequence_compatibility(model_file, data_file, metadata)
            sequence_data = load_sequence_dataset(data_file, metadata)
            model = load_model_backend(model_file, metadata)
            X = sequence_data.features
            y_true = pd.Series(sequence_data.labels)
            feature_columns: list[str] = []
            record_label = "encrypted traffic sequence"
        else:
            compatibility = None
            model = load_model_backend(model_file, metadata)
    except Exception as exc:  # noqa: BLE001
        return ModuleResult("classifier_evaluation", "fail", 0, "Model could not be loaded.", [Finding("classifier_evaluation", "Model load failed", "critical", str(exc), "Use a trusted .joblib, .pkl, or ONNX tabular classifier.")])

    if input_type != "sequence":
        try:
            data = pd.read_csv(data_file)
        except Exception as exc:  # noqa: BLE001
            return ModuleResult("classifier_evaluation", "fail", 0, "Dataset could not be read.", [Finding("classifier_evaluation", "Dataset load failed", "critical", str(exc))])
        target_column = metadata.get("target_column", "label")
        if target_column not in data.columns:
            return ModuleResult("classifier_evaluation", "fail", 0, "Target column not found.", [Finding("classifier_evaluation", "Missing target column", "critical", f"Dataset does not contain '{target_column}'.")])

        expected_features = metadata.get("expected_features")
        if expected_features:
            missing = [feature for feature in expected_features if feature not in data.columns]
            if missing:
                return ModuleResult("classifier_evaluation", "fail", 0, "Dataset is missing expected features.", [Finding("classifier_evaluation", "Feature mismatch", "critical", f"Missing features: {', '.join(missing)}", "Upload a compatible dataset or metadata file.")])
            feature_columns = expected_features
        else:
            feature_columns = [column for column in data.columns if column != target_column]
            findings.append(Finding("classifier_evaluation", "No explicit feature list", "low", "Using all columns except the target label as features.", "Add expected_features to metadata for external models."))

        X = data[feature_columns]
        y_true = data[target_column]
        record_label = "encrypted traffic flow"
        compatibility = None
    y_pred = model.predict(X)

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, average="weighted", zero_division=0)
    recall = recall_score(y_true, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    labels = sorted(pd.Series(y_true).astype(str).unique().tolist())
    matrix = confusion_matrix(y_true.astype(str), pd.Series(y_pred).astype(str), labels=labels).tolist()
    report = classification_report(y_true.astype(str), pd.Series(y_pred).astype(str), labels=labels, output_dict=True, zero_division=0)
    weak_classes = []
    for label in labels:
        metrics = report.get(label, {})
        class_f1 = float(metrics.get("f1-score", 0))
        class_recall = float(metrics.get("recall", 0))
        if class_f1 < 0.85 or class_recall < 0.85:
            weak_classes.append({
                "class": label,
                "f1": round(class_f1, 4),
                "recall": round(class_recall, 4),
            })

    confusion_pairs = []
    for actual_idx, actual in enumerate(labels):
        for predicted_idx, predicted in enumerate(labels):
            if actual_idx == predicted_idx:
                continue
            count = int(matrix[actual_idx][predicted_idx])
            if count:
                confusion_pairs.append({"actual": actual, "predicted": predicted, "count": count})
    confusion_pairs = sorted(confusion_pairs, key=lambda item: item["count"], reverse=True)

    score = round(f1 * 100, 2)
    if f1 < 0.7:
        findings.append(Finding("classifier_evaluation", "Low classifier F1 score", "high", f"Weighted F1 is {f1:.2f}.", "Retrain or tune the classifier before deployment."))
    elif f1 < 0.85:
        findings.append(Finding("classifier_evaluation", "Moderate classifier F1 score", "medium", f"Weighted F1 is {f1:.2f}.", "Review confused classes before production use."))
    else:
        findings.append(Finding("classifier_evaluation", "Classifier performance is strong", "info", f"Weighted F1 is {f1:.2f}."))

    if weak_classes:
        weakest = min(weak_classes, key=lambda item: item["f1"])
        findings.append(Finding(
            "classifier_evaluation",
            "Weak class-specific performance",
            "medium",
            f"{weakest['class']} has F1 {weakest['f1']} and recall {weakest['recall']}.",
            f"Collect more labeled {weakest['class']} flows, rebalance class weights, and rerun the scan before deployment.",
        ))

    if confusion_pairs:
        pair = confusion_pairs[0]
        findings.append(Finding(
            "classifier_evaluation",
            "Most common class confusion",
            "medium",
            f"{pair['actual']} was predicted as {pair['predicted']} in {pair['count']} test flow(s).",
            f"Add features that separate {pair['actual']} from {pair['predicted']} and validate the confusion matrix after retraining.",
        ))

    status = "pass" if score >= 85 else "warning" if score >= 70 else "fail"
    return ModuleResult(
        module="classifier_evaluation",
        status=status,
        score=score,
        summary=f"Evaluated {len(y_true)} {record_label} record(s).",
        findings=findings,
        details={
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "labels": labels,
            "confusion_matrix": matrix,
            "feature_columns": feature_columns,
            "class_metrics": {label: report.get(label, {}) for label in labels},
            "weak_classes": weak_classes,
            "confusion_pairs": confusion_pairs[:10],
            "input_type": input_type,
            "sequence_compatibility": compatibility,
        },
    )
