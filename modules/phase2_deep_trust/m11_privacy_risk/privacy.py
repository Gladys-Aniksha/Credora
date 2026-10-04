from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from core.config import DATA_DIR
from core.model_backend import ModelBackend, load_model_backend
from core.report_schema import Finding, ModuleResult
from core.security import ensure_within_directory
from core.sequence_data import load_sequence_dataset


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


def _max_confidence(model: ModelBackend, frame: pd.DataFrame) -> np.ndarray | None:
    probabilities = model.predict_proba(frame)
    if probabilities is None:
        return None
    if isinstance(probabilities, list):
        probabilities = probabilities[0]
    return np.max(probabilities, axis=1)


def assess_privacy_risk(model_path: str | Path, dataset_path: str | Path, metadata: dict | None = None) -> ModuleResult:
    metadata = metadata or {}
    findings: list[Finding] = []
    train_path = _training_dataset_path(metadata)
    if train_path is None or not train_path.exists():
        return ModuleResult(
            "privacy_risk",
            "warning",
            65,
            "Training baseline was not available, so memorization risk could not be estimated.",
            [Finding("privacy_risk", "Privacy baseline unavailable", "medium", "Credora needs a training/baseline split to compare confidence on member-like and holdout rows.", "Provide a representative training baseline path in metadata for membership-inference style checks.")],
            {"training_dataset_available": False},
        )

    if metadata.get("input_type", "tabular") == "sequence":
        try:
            model = load_model_backend(model_path, metadata)
            train = load_sequence_dataset(train_path, metadata)
            test = load_sequence_dataset(dataset_path, metadata)
            train_confidence = _max_confidence(model, train.features[:1000])
            test_confidence = _max_confidence(model, test.features[:1000])
        except Exception as exc:  # noqa: BLE001
            return ModuleResult("privacy_risk", "fail", 0, "Sequence privacy risk check could not run.", [Finding("privacy_risk", "Sequence privacy check failed", "high", str(exc), "Provide compatible training and holdout NPZ files.")])
        if train_confidence is None or test_confidence is None:
            return ModuleResult("privacy_risk", "warning", 62, "The sequence model does not expose probability confidence.", [Finding("privacy_risk", "Membership risk signal unavailable", "medium", "Credora cannot compare train-vs-test confidence without predict_proba().", "Use a sequence model with probability outputs or calibrate its outputs.")], {"input_type": "sequence", "confidence_available": False})
        train_mean = float(np.mean(train_confidence))
        test_mean = float(np.mean(test_confidence))
        confidence_gap = train_mean - test_mean
        train_high = float(np.mean(train_confidence >= 0.98))
        test_high = float(np.mean(test_confidence >= 0.98))
        high_confidence_gap = train_high - test_high
        score = 100.0
        if confidence_gap > 0.10 or high_confidence_gap > 0.20:
            score -= 35
            findings.append(Finding("privacy_risk", "Elevated sequence membership-inference risk", "high", f"Training confidence exceeds holdout confidence by {confidence_gap:.3f}.", "Regularize, calibrate, and repeat privacy testing."))
        elif confidence_gap > 0.04 or high_confidence_gap > 0.10:
            score -= 18
            findings.append(Finding("privacy_risk", "Moderate sequence memorization signal", "medium", f"Training confidence exceeds holdout confidence by {confidence_gap:.3f}.", "Calibrate probabilities and test on an independent holdout."))
        else:
            findings.append(Finding("privacy_risk", "No strong sequence confidence memorization signal", "info", f"Train/test confidence gap is {confidence_gap:.3f}."))
        return ModuleResult("privacy_risk", "pass" if score >= 80 else "warning" if score >= 55 else "fail", round(max(score, 0.0), 2), f"Compared sequence confidence on {len(train.features[:1000])} training and {len(test.features[:1000])} holdout rows.", findings, {"input_type": "sequence", "training_dataset_available": True, "confidence_available": True, "training_dataset_path": str(train_path), "train_mean_confidence": round(train_mean, 4), "test_mean_confidence": round(test_mean, 4), "confidence_gap": round(confidence_gap, 4), "train_high_confidence_rate": round(train_high, 4), "test_high_confidence_rate": round(test_high, 4), "high_confidence_gap": round(high_confidence_gap, 4)})

    try:
        model = load_model_backend(model_path)
        train = pd.read_csv(train_path)
        test = pd.read_csv(dataset_path)
    except Exception as exc:  # noqa: BLE001
        return ModuleResult("privacy_risk", "fail", 0, "Privacy risk check could not run.", [Finding("privacy_risk", "Privacy risk check failed", "high", str(exc), "Verify that the model and datasets are readable and schema-compatible.")])

    target_column = metadata.get("target_column", "label")
    feature_columns = metadata.get("expected_features") or [column for column in test.columns if column != target_column]
    feature_columns = [column for column in feature_columns if column in train.columns and column in test.columns]
    if not feature_columns:
        return ModuleResult("privacy_risk", "fail", 0, "No common feature columns were available for privacy analysis.", [Finding("privacy_risk", "Feature mismatch", "critical", "Training and test datasets do not share expected feature columns.", "Use compatible datasets with the same feature schema.")])

    train_sample = train[feature_columns].head(1000)
    test_sample = test[feature_columns].head(1000)
    train_confidence = _max_confidence(model, train_sample)
    test_confidence = _max_confidence(model, test_sample)
    if train_confidence is None or test_confidence is None:
        return ModuleResult(
            "privacy_risk",
            "warning",
            62,
            "The model does not expose probability confidence, so memorization risk is limited to a qualitative warning.",
            [Finding("privacy_risk", "Membership risk signal unavailable", "medium", "The model lacks predict_proba(), so Credora cannot compare train-vs-test confidence separation.", "Use calibrated probability estimates or provide a privacy audit artifact for non-probabilistic models.")],
            {"confidence_available": False, "feature_columns": feature_columns},
        )

    train_mean = float(np.mean(train_confidence))
    test_mean = float(np.mean(test_confidence))
    confidence_gap = train_mean - test_mean
    train_high = float(np.mean(train_confidence >= 0.98))
    test_high = float(np.mean(test_confidence >= 0.98))
    high_confidence_gap = train_high - test_high

    score = 100.0
    if confidence_gap > 0.10 or high_confidence_gap > 0.20:
        score -= 35
        findings.append(Finding("privacy_risk", "Elevated membership-inference risk", "high", f"Training rows receive noticeably higher confidence than holdout rows; mean confidence gap is {confidence_gap:.3f}.", "Reduce overfitting with regularization, pruning, calibration, and a locked privacy audit before deployment."))
    elif confidence_gap > 0.04 or high_confidence_gap > 0.10:
        score -= 18
        findings.append(Finding("privacy_risk", "Moderate memorization signal", "medium", f"Training confidence is higher than holdout confidence by {confidence_gap:.3f}.", "Calibrate probabilities and compare against a shadow-model or holdout privacy test before production use."))
    else:
        findings.append(Finding("privacy_risk", "No strong confidence memorization signal", "info", f"Train/test confidence gap is {confidence_gap:.3f} on the sampled rows."))

    if train_mean >= 0.995 and test_mean >= 0.995:
        score -= 8
        findings.append(Finding("privacy_risk", "Very high confidence across splits", "low", "Both training and test predictions are near-certain, which can make privacy claims harder to validate on easy datasets.", "Retest with a harder recent holdout set and calibrated confidence reporting."))

    score = round(max(0.0, min(score, 100.0)), 2)
    status = "pass" if score >= 80 else "warning" if score >= 55 else "fail"
    return ModuleResult(
        "privacy_risk",
        status,
        score,
        f"Compared prediction confidence on {len(train_sample)} training/baseline row(s) and {len(test_sample)} holdout row(s).",
        findings,
        {
            "training_dataset_available": True,
            "confidence_available": True,
            "training_dataset_path": str(train_path),
            "feature_columns": feature_columns,
            "train_mean_confidence": round(train_mean, 4),
            "test_mean_confidence": round(test_mean, 4),
            "confidence_gap": round(confidence_gap, 4),
            "train_high_confidence_rate": round(train_high, 4),
            "test_high_confidence_rate": round(test_high, 4),
            "high_confidence_gap": round(high_confidence_gap, 4),
        },
    )
