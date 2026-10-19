from __future__ import annotations

import hashlib
from pathlib import Path

import pandas as pd
from sklearn.metrics import f1_score

from core.config import DATA_DIR
from core.model_backend import load_model_backend
from core.report_schema import Finding, ModuleResult
from core.sequence_data import load_sequence_dataset
from core.security import ensure_within_directory


def _training_dataset_path(metadata: dict) -> Path | None:
    raw_path = metadata.get("training_dataset_path") or metadata.get("baseline_dataset_path")
    if not raw_path:
        return None
    try:
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = DATA_DIR.parent / candidate
        return ensure_within_directory(candidate, DATA_DIR.parent)
    except ValueError:
        return None


def _row_fingerprints(frame: pd.DataFrame, columns: list[str]) -> set[str]:
    if not columns:
        return set()
    rows = frame[columns].copy()
    rows = rows.fillna("<NA>").astype(str)
    return set(pd.util.hash_pandas_object(rows, index=False).astype(str).tolist())


def check_dataset_leakage(model_path: str | Path, dataset_path: str | Path, metadata: dict | None = None) -> ModuleResult:
    metadata = metadata or {}
    findings: list[Finding] = []
    train_f1: float | None = None
    test_f1: float | None = None
    train_path = _training_dataset_path(metadata)
    if train_path is None or not train_path.exists():
        return ModuleResult(
            "dataset_leakage",
            "warning",
            65,
            "Training baseline was not available, so holdout leakage could not be verified.",
            [Finding("dataset_leakage", "Training baseline unavailable", "medium", "Credora could not compare the uploaded test file against a training/baseline dataset.", "Provide training_dataset_path metadata that points to the original training split or a trusted baseline sample.")],
            {"training_dataset_available": False},
        )

    if metadata.get("input_type", "tabular") == "sequence":
        try:
            train = load_sequence_dataset(train_path, metadata)
            test = load_sequence_dataset(dataset_path, metadata)
            train_hashes = {hashlib.sha256(row.tobytes()).hexdigest() for row in train.features}
            test_hashes = {hashlib.sha256(row.tobytes()).hexdigest() for row in test.features}
            overlap = len(train_hashes.intersection(test_hashes)) / max(len(test_hashes), 1)
            model = load_model_backend(model_path, metadata)
            train_pred = model.predict(train.features)
            test_pred = model.predict(test.features)
            train_f1 = float(f1_score(train.labels.astype(str), pd.Series(train_pred).astype(str), average="weighted", zero_division=0))
            test_f1 = float(f1_score(test.labels.astype(str), pd.Series(test_pred).astype(str), average="weighted", zero_division=0))
            gap = train_f1 - test_f1
        except Exception as exc:  # noqa: BLE001
            return ModuleResult("dataset_leakage", "fail", 0, "Sequence leakage check could not run.", [Finding("dataset_leakage", "Sequence leakage check failed", "high", str(exc), "Provide compatible training and test NPZ files.")])
        score = 100.0
        if overlap >= 0.20:
            score -= 45
            findings.append(Finding("dataset_leakage", "Possible sequence holdout leakage", "high", f"{overlap:.1%} of test sequences also appear in training.", "Rebuild the holdout with independent sequences."))
        elif overlap >= 0.05:
            score -= 22
            findings.append(Finding("dataset_leakage", "Small sequence overlap detected", "medium", f"{overlap:.1%} of test sequences overlap training.", "Remove duplicate sequences before release evaluation."))
        else:
            findings.append(Finding("dataset_leakage", "No exact sequence leakage detected", "info", "Test sequence hashes did not exactly match training sequence hashes."))
        if gap > 0.15:
            score -= 20
            findings.append(Finding("dataset_leakage", "Large sequence generalization gap", "medium", f"Training F1 is {train_f1:.3f}; test F1 is {test_f1:.3f}.", "Investigate overfitting and collect a harder holdout."))
        return ModuleResult("dataset_leakage", "pass" if score >= 80 else "warning" if score >= 55 else "fail", round(max(score, 0.0), 2), f"Compared {len(test.features)} test sequence(s) with {len(train.features)} training sequence(s).", findings, {"input_type": "sequence", "training_dataset_available": True, "training_dataset_path": str(train_path), "test_row_count": len(test.features), "training_row_count": len(train.features), "feature_overlap_rate": round(overlap, 4), "full_row_overlap_rate": round(overlap, 4), "train_f1": round(train_f1, 4), "test_f1": round(test_f1, 4), "generalization_gap": round(gap, 4)})

    try:
        train = pd.read_csv(train_path)
        test = pd.read_csv(dataset_path)
    except Exception as exc:  # noqa: BLE001
        return ModuleResult("dataset_leakage", "fail", 0, "Dataset leakage check could not read the required CSV files.", [Finding("dataset_leakage", "Leakage check failed", "high", str(exc), "Verify that the training baseline and uploaded test dataset are readable CSV files.")])

    target_column = metadata.get("target_column", "label")
    feature_columns = metadata.get("expected_features") or [column for column in test.columns if column != target_column]
    common_features = [column for column in feature_columns if column in train.columns and column in test.columns]
    if not common_features:
        return ModuleResult("dataset_leakage", "fail", 0, "No common feature columns were available for leakage analysis.", [Finding("dataset_leakage", "Feature mismatch", "critical", "The training and test datasets do not share the expected feature columns.", "Use compatible training and holdout datasets with the same feature schema.")])

    train_feature_hashes = _row_fingerprints(train, common_features)
    test_feature_hashes = _row_fingerprints(test, common_features)
    duplicate_features = train_feature_hashes.intersection(test_feature_hashes)
    feature_overlap_rate = len(duplicate_features) / max(len(test_feature_hashes), 1)

    full_columns = [column for column in common_features + ([target_column] if target_column in train.columns and target_column in test.columns else [])]
    full_overlap_rate = len(_row_fingerprints(train, full_columns).intersection(_row_fingerprints(test, full_columns))) / max(len(test), 1)

    generalization_gap: float | None = None
    if target_column in train.columns and target_column in test.columns:
        try:
            model = load_model_backend(model_path, metadata)
            train_pred = model.predict(train[common_features])
            test_pred = model.predict(test[common_features])
            train_f1 = float(f1_score(train[target_column].astype(str), pd.Series(train_pred).astype(str), average="weighted", zero_division=0))
            test_f1 = float(f1_score(test[target_column].astype(str), pd.Series(test_pred).astype(str), average="weighted", zero_division=0))
            generalization_gap = train_f1 - test_f1
        except Exception as exc:  # noqa: BLE001
            findings.append(Finding("dataset_leakage", "Train/test performance comparison unavailable", "low", str(exc), "Keep feature metadata aligned so Credora can compare training and holdout performance."))

    score = 100.0
    if feature_overlap_rate >= 0.20 or full_overlap_rate >= 0.10:
        score -= 45
        findings.append(Finding("dataset_leakage", "Possible holdout leakage", "high", f"{feature_overlap_rate:.1%} of unique test feature rows also appear in the training baseline.", "Rebuild the split from raw data using group/time-aware separation, then rerun the scan on an untouched holdout file."))
    elif feature_overlap_rate >= 0.05 or full_overlap_rate > 0:
        score -= 22
        findings.append(Finding("dataset_leakage", "Small train/test overlap detected", "medium", f"{feature_overlap_rate:.1%} of unique test feature rows overlap with training data.", "Remove duplicate or near-duplicate flows from the test set and keep a locked holdout dataset."))
    else:
        findings.append(Finding("dataset_leakage", "No exact train/test row leakage detected", "info", "The uploaded test rows did not exactly match training feature rows."))

    if generalization_gap is not None:
        if generalization_gap > 0.15:
            score -= 20
            findings.append(Finding("dataset_leakage", "Large train/test performance gap", "medium", f"Training weighted F1 is {train_f1:.3f}, while test weighted F1 is {test_f1:.3f}.", "Investigate overfitting, class imbalance, and unstable features before claiming production accuracy."))
        elif abs(generalization_gap) <= 0.05:
            findings.append(Finding("dataset_leakage", "Train/test performance is consistent", "info", f"Training and test weighted F1 differ by {abs(generalization_gap):.3f}."))

    score = round(max(0.0, min(score, 100.0)), 2)
    status = "pass" if score >= 80 else "warning" if score >= 55 else "fail"
    return ModuleResult(
        "dataset_leakage",
        status,
        score,
        f"Compared {len(test)} test row(s) with {len(train)} training/baseline row(s) for leakage and generalization evidence.",
        findings,
        {
            "training_dataset_available": True,
            "training_dataset_path": str(train_path),
            "test_row_count": int(len(test)),
            "training_row_count": int(len(train)),
            "common_features": common_features,
            "feature_overlap_rate": round(float(feature_overlap_rate), 4),
            "full_row_overlap_rate": round(float(full_overlap_rate), 4),
            "train_f1": round(train_f1, 4) if train_f1 is not None else None,
            "test_f1": round(test_f1, 4) if test_f1 is not None else None,
            "generalization_gap": round(generalization_gap, 4) if generalization_gap is not None else None,
        },
    )
