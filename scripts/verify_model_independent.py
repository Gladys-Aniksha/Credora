from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score

from core.model_backend import load_model_backend


def load_metadata(metadata_path: Path | None) -> dict:
    if metadata_path is None or not metadata_path.exists():
        return {}
    return json.loads(metadata_path.read_text(encoding="utf-8"))


def verify_model(model_path: Path, dataset_path: Path, metadata_path: Path | None) -> dict:
    metadata = load_metadata(metadata_path)
    model = load_model_backend(model_path)
    dataset = pd.read_csv(dataset_path)

    target_column = metadata.get("target_column", "label")
    if target_column not in dataset.columns:
        raise ValueError(f"Dataset is missing target column: {target_column}")

    expected_features = metadata.get("expected_features")
    if expected_features:
        missing_features = [feature for feature in expected_features if feature not in dataset.columns]
        if missing_features:
            raise ValueError(f"Dataset is missing feature columns: {', '.join(missing_features)}")
        feature_columns = expected_features
    else:
        feature_columns = [column for column in dataset.columns if column != target_column]

    x_test = dataset[feature_columns]
    y_true = dataset[target_column].astype(str)
    y_pred = pd.Series(model.predict(x_test)).astype(str)
    labels = metadata.get("class_labels") or sorted(y_true.unique().tolist())

    return {
        "model_path": str(model_path),
        "dataset_path": str(dataset_path),
        "metadata_path": str(metadata_path) if metadata_path else None,
        "rows_evaluated": int(len(dataset)),
        "feature_count": int(len(feature_columns)),
        "feature_columns": feature_columns,
        "target_column": target_column,
        "classes": labels,
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision_weighted": round(float(precision_score(y_true, y_pred, average="weighted", zero_division=0)), 4),
        "recall_weighted": round(float(recall_score(y_true, y_pred, average="weighted", zero_division=0)), 4),
        "f1_weighted": round(float(f1_score(y_true, y_pred, average="weighted", zero_division=0)), 4),
        "f1_macro": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "classification_report": classification_report(y_true, y_pred, labels=labels, zero_division=0, output_dict=True),
        "prediction_preview": [
            {"actual": str(actual), "predicted": str(predicted)}
            for actual, predicted in list(zip(y_true.tolist(), y_pred.tolist()))[:12]
        ],
    }


def print_report(report: dict) -> None:
    print("Independent Model Verification")
    print("=" * 31)
    print(f"Model: {report['model_path']}")
    print(f"Dataset: {report['dataset_path']}")
    print(f"Metadata: {report['metadata_path']}")
    print(f"Rows evaluated: {report['rows_evaluated']}")
    print(f"Feature count: {report['feature_count']}")
    print(f"Target column: {report['target_column']}")
    print(f"Classes: {', '.join(report['classes'])}")
    print(f"Accuracy: {report['accuracy']}")
    print(f"Weighted F1: {report['f1_weighted']}")
    print(f"Macro F1: {report['f1_macro']}")
    print()
    print("Confusion matrix")
    print("Rows = actual, columns = predicted")
    print(pd.DataFrame(report["confusion_matrix"], index=report["classes"], columns=report["classes"]))
    print()
    print("Prediction preview")
    for item in report["prediction_preview"]:
        print(f"actual={item['actual']}, predicted={item['predicted']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify the encrypted traffic classifier without using Credora."
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=PROJECT_ROOT / "data" / "sample_models" / "traffic_rf_v1.joblib",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=PROJECT_ROOT / "data" / "processed" / "encrypted_traffic_test.csv",
    )
    parser.add_argument(
        "--metadata",
        type=Path,
        default=PROJECT_ROOT / "data" / "metadata" / "traffic_rf_v1_metadata.json",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=PROJECT_ROOT / "reports" / "model_cards" / "independent_verification_report.json",
    )
    args = parser.parse_args()

    report = verify_model(args.model, args.dataset, args.metadata)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print_report(report)
    print()
    print(f"Saved JSON report: {args.json_out}")


if __name__ == "__main__":
    main()
