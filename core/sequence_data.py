from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from core.config import MAX_SEQUENCE_DATASET_BYTES, MAX_SEQUENCE_LENGTH, MAX_SEQUENCE_ROWS


class SequenceDataError(ValueError):
    """Raised when a sequence dataset does not satisfy Credora's safe input contract."""


@dataclass(frozen=True)
class SequenceDataset:
    features: np.ndarray
    labels: np.ndarray


def validate_sequence_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    if metadata.get("input_type", "tabular") != "sequence":
        raise SequenceDataError("Sequence metadata must declare input_type as 'sequence'.")

    required = ["max_sequence_length", "sequence_dtype", "vocab_size", "class_labels"]
    missing = [key for key in required if metadata.get(key) is None or metadata.get(key) == ""]
    if missing:
        raise SequenceDataError("Sequence metadata is missing: " + ", ".join(missing))

    length = int(metadata["max_sequence_length"])
    if length <= 0 or length > MAX_SEQUENCE_LENGTH:
        raise SequenceDataError(
            f"max_sequence_length must be between 1 and {MAX_SEQUENCE_LENGTH}."
        )
    dtype = str(metadata["sequence_dtype"]).lower()
    if dtype not in {"int64", "float32"}:
        raise SequenceDataError("sequence_dtype must be 'int64' or 'float32'.")
    vocab_size = int(metadata["vocab_size"])
    if vocab_size <= 0:
        raise SequenceDataError("vocab_size must be positive.")
    pad_id = int(metadata.get("pad_id", 0))
    if not 0 <= pad_id < vocab_size:
        raise SequenceDataError("pad_id must be inside the declared vocabulary.")
    labels = [str(label) for label in metadata.get("class_labels", [])]
    if not labels or len(set(labels)) != len(labels):
        raise SequenceDataError("class_labels must be a non-empty ordered list of unique labels.")
    return {
        **metadata,
        "max_sequence_length": length,
        "sequence_dtype": dtype,
        "vocab_size": vocab_size,
        "pad_id": pad_id,
        "class_labels": labels,
    }


def load_sequence_dataset(path: str | Path, metadata: dict[str, Any]) -> SequenceDataset:
    contract = validate_sequence_metadata(metadata)
    dataset_path = Path(path)
    if not dataset_path.is_file():
        raise SequenceDataError(f"Sequence dataset not found: {dataset_path}")
    if dataset_path.suffix.lower() != ".npz":
        raise SequenceDataError("Sequence datasets must use the .npz format.")
    if dataset_path.stat().st_size > MAX_SEQUENCE_DATASET_BYTES:
        raise SequenceDataError("Sequence dataset exceeds the configured size limit.")

    try:
        with np.load(dataset_path, allow_pickle=False) as payload:
            if "X" not in payload or "y" not in payload:
                raise SequenceDataError("Sequence dataset must contain X and y arrays.")
            features = np.asarray(payload["X"])
            labels = np.asarray(payload["y"])
    except SequenceDataError:
        raise
    except (OSError, ValueError) as exc:
        raise SequenceDataError(f"Sequence dataset could not be read safely: {exc}") from exc

    if features.ndim != 2:
        raise SequenceDataError("X must be a two-dimensional [rows, sequence_length] array.")
    if labels.ndim != 1:
        raise SequenceDataError("y must be a one-dimensional label array.")
    if len(features) != len(labels):
        raise SequenceDataError("X and y contain different numbers of rows.")
    if len(features) == 0 or len(features) > MAX_SEQUENCE_ROWS:
        raise SequenceDataError(
            f"Sequence dataset rows must be between 1 and {MAX_SEQUENCE_ROWS}."
        )
    if features.shape[1] != contract["max_sequence_length"]:
        raise SequenceDataError(
            f"Dataset sequence length is {features.shape[1]}, but metadata declares "
            f"{contract['max_sequence_length']}."
        )

    expected_dtype = np.dtype(contract["sequence_dtype"])
    if features.dtype != expected_dtype:
        raise SequenceDataError(
            f"Dataset X uses {features.dtype}, but metadata declares {expected_dtype}."
        )
    if not np.isfinite(features).all():
        raise SequenceDataError("Sequence data contains NaN or infinite values.")
    if contract["sequence_dtype"] == "int64":
        if np.any(features < 0):
            raise SequenceDataError("Sequence token IDs cannot be negative.")
        if np.any(features >= contract["vocab_size"]):
            raise SequenceDataError("Sequence data contains an ID outside the declared vocabulary.")

    declared_labels = set(contract["class_labels"])
    observed_labels = {str(label) for label in labels.tolist()}
    unknown = sorted(observed_labels - declared_labels)
    if unknown:
        raise SequenceDataError("Dataset contains undeclared labels: " + ", ".join(unknown))
    return SequenceDataset(features=features, labels=labels.astype(str))
