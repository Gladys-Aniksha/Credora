from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

LABEL_CANDIDATES = [
    "label",
    "Label",
    "LABEL",
    "class",
    "Class",
    "CLASS",
    "type",
    "Type",
    "TYPE",
    "traffic_type",
    "Traffic Type",
    "traffic_category",
    "category",
    "Category",
]

DROP_NAME_HINTS = [
    "flow id",
    "flow_id",
    "timestamp",
    "time stamp",
    "src ip",
    "source ip",
    "dst ip",
    "destination ip",
    "ip address",
    "source port",
    "destination port",
]


def detect_label_column(df: pd.DataFrame, requested: str | None) -> str:
    if requested:
        if requested not in df.columns:
            raise ValueError(f"Requested label column '{requested}' was not found. Available columns: {list(df.columns)[:30]}")
        return requested
    for candidate in LABEL_CANDIDATES:
        if candidate in df.columns:
            return candidate
    object_columns = [column for column in df.columns if df[column].dtype == "object"]
    plausible = [column for column in object_columns if 2 <= df[column].nunique(dropna=True) <= 30]
    if plausible:
        return plausible[-1]
    raise ValueError("Could not auto-detect the label column. Re-run with --label-column <column_name>.")


def clean_feature_frame(df: pd.DataFrame, label_column: str) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    work = df.copy()
    work = work.replace([np.inf, -np.inf], np.nan)
    work = work.dropna(axis=0, subset=[label_column])
    y = work[label_column].astype(str).str.strip()
    X = work.drop(columns=[label_column])

    drop_columns: list[str] = []
    row_count = max(len(X), 1)
    for column in X.columns:
        lowered = str(column).lower()
        if any(hint in lowered for hint in DROP_NAME_HINTS):
            drop_columns.append(column)
            continue
        non_null = X[column].dropna()
        if non_null.empty:
            drop_columns.append(column)
            continue
        unique_ratio = non_null.nunique() / row_count
        if X[column].dtype == "object" and unique_ratio > 0.55:
            drop_columns.append(column)

    X = X.drop(columns=drop_columns, errors="ignore")
    return X, y, drop_columns


def build_pipeline(X: pd.DataFrame, random_state: int) -> Pipeline:
    numeric_features = X.select_dtypes(include=["number", "bool"]).columns.tolist()
    categorical_features = [column for column in X.columns if column not in numeric_features]

    numeric_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )
    categorical_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ]
    )
    preprocessor = ColumnTransformer(
        transformers=[
            ("numeric", numeric_pipeline, numeric_features),
            ("categorical", categorical_pipeline, categorical_features),
        ],
        remainder="drop",
    )
    classifier = RandomForestClassifier(
        n_estimators=180,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=random_state,
        n_jobs=-1,
    )
    return Pipeline(steps=[("preprocessor", preprocessor), ("classifier", classifier)])


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a real encrypted-traffic upload pack for TrustAI Sentinel.")
    parser.add_argument("--source-csv", required=True, help="Path to the downloaded public encrypted traffic CSV.")
    parser.add_argument("--label-column", default=None, help="Optional label column name if auto-detection fails.")
    parser.add_argument("--model-name", default="cic_vpn_real_rf_v1", help="Output model name.")
    parser.add_argument("--test-size", type=float, default=0.25, help="Test split size.")
    parser.add_argument("--max-rows", type=int, default=60000, help="Optional row cap for laptop-friendly training.")
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    source_path = Path(args.source_csv).expanduser().resolve()
    if not source_path.exists():
        raise FileNotFoundError(f"Source CSV not found: {source_path}")

    df = pd.read_csv(source_path)
    if args.max_rows and len(df) > args.max_rows:
        df = df.sample(n=args.max_rows, random_state=args.random_state)

    label_column = detect_label_column(df, args.label_column)
    X, y, dropped_columns = clean_feature_frame(df, label_column)

    valid_class_counts = y.value_counts()
    keep_labels = valid_class_counts[valid_class_counts >= 2].index
    keep_mask = y.isin(keep_labels)
    X = X.loc[keep_mask]
    y = y.loc[keep_mask]

    if y.nunique() < 2:
        raise ValueError("The selected label column must contain at least two classes with two samples each.")

    stratify = y if y.value_counts().min() >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=stratify,
    )

    model = build_pipeline(X_train, args.random_state)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    output_dir = PROJECT_ROOT / "data" / "real_upload_pack" / args.model_name
    output_dir.mkdir(parents=True, exist_ok=True)

    model_path = output_dir / f"{args.model_name}.joblib"
    test_csv_path = output_dir / "test_dataset.csv"
    requirements_path = output_dir / "requirements.txt"
    metadata_path = output_dir / "metadata.json"
    summary_path = output_dir / "training_summary.json"

    joblib.dump(model, model_path)
    test_df = X_test.copy()
    test_df["label"] = y_test.values
    test_df.to_csv(test_csv_path, index=False)

    requirements_path.write_text(
        "scikit-learn\n"
        "pandas\n"
        "numpy\n"
        "joblib\n",
        encoding="utf-8",
    )

    metadata = {
        "model_name": args.model_name,
        "version": "1.0-real-dataset",
        "algorithm": "Random Forest",
        "framework": "scikit-learn Pipeline",
        "task": "Encrypted Traffic Classification",
        "dataset_source": str(source_path),
        "target_column": "label",
        "original_label_column": label_column,
        "expected_features": X_test.columns.tolist(),
        "dropped_columns": dropped_columns,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    summary = {
        "source_csv": str(source_path),
        "rows_used": int(len(X)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "classes": sorted(y.unique().tolist()),
        "class_counts": y.value_counts().to_dict(),
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision_weighted": round(float(precision_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
        "recall_weighted": round(float(recall_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
        "f1_weighted": round(float(f1_score(y_test, y_pred, average="weighted", zero_division=0)), 4),
        "confusion_matrix": confusion_matrix(y_test.astype(str), pd.Series(y_pred).astype(str), labels=sorted(y.unique().tolist())).tolist(),
        "classification_report": classification_report(y_test, y_pred, zero_division=0),
        "upload_files": {
            "model": str(model_path),
            "test_dataset_csv": str(test_csv_path),
            "requirements_txt": str(requirements_path),
            "metadata_json": str(metadata_path),
        },
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("Real encrypted-traffic upload pack created:")
    print(f"Model: {model_path}")
    print(f"Test CSV: {test_csv_path}")
    print(f"Requirements: {requirements_path}")
    print(f"Metadata: {metadata_path}")
    print(f"Training summary: {summary_path}")
    print(f"Weighted F1: {summary['f1_weighted']}")


if __name__ == "__main__":
    main()
