from __future__ import annotations

from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, f1_score, recall_score

from core.db import get_sensitive_label_taxonomy
from core.model_backend import load_model_backend
from core.report_schema import Finding, ModuleResult
from core.sequence_data import load_sequence_dataset


TRIAL_SEEDS = tuple(range(12))
MAX_SEQUENCE_EVIDENCE_ROWS = 512


def _sensitive_labels(labels: list[str]) -> list[str]:
    hints = get_sensitive_label_taxonomy()
    return [label for label in labels if any(hint in label.lower() for hint in hints)]


def _sensitive_recall(y_true: np.ndarray, y_pred: np.ndarray, labels: list[str]) -> float | None:
    if not labels:
        return None
    values = recall_score(y_true, y_pred, labels=labels, average=None, zero_division=0)
    return float(np.min(values)) if len(values) else None


def _replacement_values(values: np.ndarray, metadata: dict, rng: np.random.Generator, count: int) -> np.ndarray:
    result = values.copy()
    positions = rng.choice(result.shape[1], size=count, replace=False)
    if result.dtype == np.int64:
        result[:, positions] = rng.integers(1, int(metadata["vocab_size"]), size=(len(result), count), dtype=np.int64)
    else:
        result[:, positions] = rng.random((len(result), count), dtype=np.float32)
    return result


def _attacked(values: np.ndarray, scenario: str, metadata: dict, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    result = values.copy()
    pad_id = int(metadata.get("pad_id", 0))
    length = result.shape[1]
    changed = max(1, int(length * 0.05))

    if scenario == "random_byte_noise":
        return _replacement_values(result, metadata, rng, changed)
    if scenario == "padding_injection":
        positions = rng.choice(length, size=changed, replace=False)
        result[:, positions] = pad_id
        return result
    if scenario == "tail_truncation":
        cutoff_low = max(1, int(length * 0.75))
        cutoff = int(rng.integers(cutoff_low, max(cutoff_low + 1, length)))
        result[:, cutoff:] = pad_id
        return result
    if scenario == "block_reordering":
        first = length // 3
        second = (2 * length) // 3
        result = np.concatenate((result[:, second:], result[:, first:second], result[:, :first]), axis=1)
        return result
    if scenario == "packet_drop":
        start = int(rng.integers(0, max(1, length - changed + 1)))
        result[:, start : start + changed] = pad_id
        return result
    raise ValueError(f"Unknown sequence attack scenario: {scenario}")


SCENARIOS = (
    ("random_byte_noise", "Replace a small percentage of token or byte positions with random values."),
    ("tail_truncation", "Truncate the tail of the sequence and pad the removed positions."),
    ("padding_injection", "Insert padding at random positions to simulate missing payload bytes."),
    ("block_reordering", "Reorder broad sequence blocks to simulate segmentation or ordering changes."),
    ("packet_drop", "Remove a short contiguous span to simulate dropped packet content."),
)


def _run_sequence_scenarios(
    model_path: str | Path,
    dataset_path: str | Path,
    metadata: dict,
    include_sensitive_recall: bool,
) -> tuple[dict, list[dict], list[Finding]]:
    data = load_sequence_dataset(dataset_path, metadata)
    model = load_model_backend(model_path, metadata)
    labels = [str(label) for label in metadata["class_labels"]]
    features = data.features[:MAX_SEQUENCE_EVIDENCE_ROWS]
    y_true = data.labels[:MAX_SEQUENCE_EVIDENCE_ROWS].astype(str)
    attack_inputs = [features]
    scenario_indexes = {name: index for index, (name, _description) in enumerate(SCENARIOS)}
    for name, _description in SCENARIOS:
        for seed in TRIAL_SEEDS:
            attack_inputs.append(_attacked(features, name, metadata, seed))
    predictions = np.asarray(model.predict(np.concatenate(attack_inputs, axis=0))).astype(str)
    baseline_pred = predictions[: len(features)]
    baseline_accuracy = float(accuracy_score(y_true, baseline_pred))
    baseline_f1 = float(f1_score(y_true, baseline_pred, average="weighted", zero_division=0))
    sensitive_labels = _sensitive_labels(labels)
    baseline_sensitive = _sensitive_recall(y_true, baseline_pred, sensitive_labels)
    results: list[dict] = []

    for name, description in SCENARIOS:
        trials = []
        for trial_index, seed in enumerate(TRIAL_SEEDS):
            prediction_start = len(features) + ((scenario_indexes[name] * len(TRIAL_SEEDS) + trial_index) * len(features))
            prediction = predictions[prediction_start : prediction_start + len(features)]
            sensitive = _sensitive_recall(y_true, prediction, sensitive_labels)
            trials.append({
                "seed": seed,
                "accuracy": float(accuracy_score(y_true, prediction)),
                "f1": float(f1_score(y_true, prediction, average="weighted", zero_division=0)),
                "prediction_stability": float(np.mean(prediction == baseline_pred)),
                "sensitive_recall": sensitive,
            })
        worst_f1 = float(np.percentile([trial["f1"] for trial in trials], 10))
        worst_stability = float(np.percentile([trial["prediction_stability"] for trial in trials], 10))
        sensitive_values = [trial["sensitive_recall"] for trial in trials if trial["sensitive_recall"] is not None]
        worst_sensitive = float(np.percentile(sensitive_values, 10)) if sensitive_values else None
        results.append({
            "scenario": name,
            "description": description,
            "trial_count": len(trials),
            "lower_percentile": 10,
            "accuracy": round(float(np.percentile([trial["accuracy"] for trial in trials], 10)), 4),
            "f1": round(worst_f1, 4),
            "f1_drop": round(max(0.0, baseline_f1 - worst_f1), 4),
            "prediction_stability": round(worst_stability, 4),
            "sensitive_recall": round(worst_sensitive, 4) if worst_sensitive is not None else None,
            "trials": trials,
        })

    return {
        "input_type": "sequence",
        "trial_count": len(TRIAL_SEEDS),
        "baseline_accuracy": round(baseline_accuracy, 4),
        "baseline_f1": round(baseline_f1, 4),
        "baseline_sensitive_recall": round(baseline_sensitive, 4) if baseline_sensitive is not None else None,
        "sensitive_labels": sensitive_labels,
        "scenarios": results,
        "worst_case_f1": min(item["f1"] for item in results),
        "worst_case_scenario": min(results, key=lambda item: item["f1"])["scenario"],
        "minimum_prediction_stability": min(item["prediction_stability"] for item in results),
        "worst_sensitive_recall": min(
            [item["sensitive_recall"] for item in results if item["sensitive_recall"] is not None],
            default=None,
        ),
        "semantic_coverage": "These are semantic-agnostic sequence perturbations; they do not guarantee a valid packet.",
    }, results, []


def _failure(module: str, message: str, exc: Exception) -> ModuleResult:
    return ModuleResult(
        module,
        "fail",
        0,
        message,
        [Finding(module, f"{module.replace('_', ' ').title()} failed", "high", str(exc), "Verify the sequence model, metadata, and NPZ dataset.")],
    )


def run_sequence_robustness(model_path: str | Path, dataset_path: str | Path, metadata: dict) -> ModuleResult:
    try:
        details, scenarios, findings = _run_sequence_scenarios(model_path, dataset_path, metadata, False)
    except Exception as exc:  # noqa: BLE001
        return _failure("robustness_testing", "Sequence robustness testing could not run.", exc)

    worst_f1 = details["worst_case_f1"]
    stability = details["minimum_prediction_stability"]
    score = round(max(0.0, min(100.0, 100.0 - max(0.0, details["baseline_f1"] - worst_f1) * 170 - (1 - stability) * 65)), 2)
    if worst_f1 < 0.70 or stability < 0.75:
        findings.append(Finding("robustness_testing", "Sequence model is sensitive to perturbations", "high", f"Worst-case F1 was {worst_f1:.3f} and prediction stability was {stability:.3f}.", "Train with varied sequence corruption and rerun the robustness assessment."))
    elif worst_f1 < 0.85 or stability < 0.90:
        findings.append(Finding("robustness_testing", "Moderate sequence robustness risk", "medium", f"Worst-case F1 was {worst_f1:.3f}.", "Review the sequence positions and perturbations that caused the largest score drop."))
    else:
        findings.append(Finding("robustness_testing", "Sequence perturbation tests passed", "info", f"Worst-case F1 was {worst_f1:.3f} with {stability:.3f} prediction stability."))
    details["scenarios"] = scenarios
    return ModuleResult("robustness_testing", "pass" if score >= 80 else "warning" if score >= 55 else "fail", score, f"Tested {len(scenarios)} sequence perturbation scenarios across {len(TRIAL_SEEDS)} trials.", findings, details)


def run_sequence_adversarial_validation(model_path: str | Path, dataset_path: str | Path, metadata: dict) -> ModuleResult:
    try:
        details, scenarios, findings = _run_sequence_scenarios(model_path, dataset_path, metadata, True)
    except Exception as exc:  # noqa: BLE001
        return _failure("adversarial_validation", "Sequence adversarial validation could not run.", exc)

    worst_f1 = details["worst_case_f1"]
    stability = details["minimum_prediction_stability"]
    sensitive = details["worst_sensitive_recall"]
    sensitive_penalty = max(0.0, 0.90 - sensitive) * 100 if sensitive is not None else 0.0
    score = round(max(0.0, min(100.0, 100.0 - max(0.0, details["baseline_f1"] - worst_f1) * 90 - (1 - stability) * 35 - sensitive_penalty)), 2)
    if worst_f1 < 0.70 or (sensitive is not None and sensitive < 0.75):
        findings.append(Finding("adversarial_validation", "Sequence bypass risk detected", "high", f"Worst-case F1 was {worst_f1:.3f}; sensitive recall was {sensitive if sensitive is not None else 'not available'}.", "Block deployment and retrain with adversarially varied sequence samples."))
    elif worst_f1 < 0.85 or stability < 0.85 or (sensitive is not None and sensitive < 0.90):
        findings.append(Finding("adversarial_validation", "Sequence adversarial resilience needs improvement", "medium", f"Worst-case scenario was {details['worst_case_scenario']} with F1 {worst_f1:.3f}.", "Add the failing sequence scenario to training and rerun the release assessment."))
    else:
        findings.append(Finding("adversarial_validation", "Sequence adversarial release tests passed", "info", f"All {len(scenarios)} sequence scenarios retained acceptable behavior."))
    details["scenarios"] = scenarios
    return ModuleResult("adversarial_validation", "pass" if score >= 80 else "warning" if score >= 55 else "fail", score, f"Ran {len(scenarios)} sequence adversarial scenarios across {len(TRIAL_SEEDS)} trials.", findings, details)
