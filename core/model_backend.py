from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import numpy as np
import pandas as pd

from core.config import (
    MAX_SEQUENCE_MODEL_BYTES,
    SEQUENCE_INFERENCE_BATCH_SIZE,
    SEQUENCE_INFERENCE_TIMEOUT_SECONDS,
)
from core.execution_provider import EVIDENCE_PREFIX, OnnxExecution, execution_policy
from core.model_loading import load_checked_model
from core.onnx_safety import validate_onnx_model
from core.process_isolation import run_isolated_python
from core.sequence_data import validate_sequence_metadata
from core.sequence_validation import validate_sequence_model_contract


class ModelBackend(ABC):
    """Common prediction interface for supported tabular model formats."""

    @abstractmethod
    def predict(self, features: Any) -> np.ndarray:
        """Return one predicted label per input row."""

    @abstractmethod
    def predict_proba(self, features: Any) -> np.ndarray | None:
        """Return class probabilities when the model exposes them."""

    @abstractmethod
    def feature_importance(self, feature_columns: list[str]) -> list[dict] | None:
        """Return native feature importance evidence when available."""


class SklearnBackend(ModelBackend):
    def __init__(self, path: str | Path):
        self.model = load_checked_model(path)

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        return np.asarray(self.model.predict(features))

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray | None:
        if not hasattr(self.model, "predict_proba"):
            return None
        return np.asarray(self.model.predict_proba(features))

    def feature_importance(self, feature_columns: list[str]) -> list[dict] | None:
        importances = getattr(self.model, "feature_importances_", None)
        if importances is None:
            return None
        return sorted(
            [
                {"feature": feature, "importance": float(importance)}
                for feature, importance in zip(feature_columns, importances)
            ],
            key=lambda item: item["importance"],
            reverse=True,
        )


class OnnxBackend(ModelBackend):
    def __init__(self, path: str | Path, metadata: dict[str, Any] | None = None):
        import onnxruntime as ort

        if Path(path).is_file():
            validate_onnx_model(path)
        self._execution = OnnxExecution(ort, path, metadata)
        self.session = self._execution.session
        self.execution_details = self._execution.details
        self.input_name = self.session.get_inputs()[0].name
        self.output_names = [output.name for output in self.session.get_outputs()]

    def _run(self, features: pd.DataFrame) -> list:
        inputs = {self.input_name: features.to_numpy(dtype=np.float32)}
        return self._execution.run(self.output_names, inputs)

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        outputs = self._run(features)
        return np.asarray(outputs[0]).reshape(-1)

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray | None:
        outputs = self._run(features)
        if len(outputs) <= 1:
            return None
        probabilities = outputs[1]
        if isinstance(probabilities, list) and probabilities and isinstance(probabilities[0], dict):
            class_labels = list(probabilities[0])
            return np.asarray(
                [[row.get(label, 0.0) for label in class_labels] for row in probabilities],
                dtype=float,
            )
        return np.asarray(probabilities)

    def feature_importance(self, feature_columns: list[str]) -> list[dict] | None:
        return None


class SequenceOnnxBackend(ModelBackend):
    def __init__(self, path: str | Path, metadata: dict[str, Any]):
        self.path = Path(path).resolve()
        if self.path.stat().st_size > MAX_SEQUENCE_MODEL_BYTES:
            raise ValueError("Sequence ONNX model exceeds the configured size limit.")
        self.metadata = validate_sequence_metadata(metadata)
        self._execution_policy = execution_policy(self.metadata)
        self.execution_details: dict[str, Any] = {
            **self._execution_policy,
            "strict_gpu_guarantee": False,
            "execution_observation": "worker_evidence_unavailable",
            "observed_node_providers": [],
        }
        self.contract = validate_sequence_model_contract(self.path, self.metadata)
        self.class_labels = np.asarray(self.metadata["class_labels"], dtype=str)
        code = (
            "from core.onnx_worker import run_onnx_worker; import sys; "
            f"run_onnx_worker(sys.argv[1], None, None{self._worker_policy_argument()})"
        )
        completed = run_isolated_python(
            code,
            arguments=[str(self.path)],
            timeout_seconds=SEQUENCE_INFERENCE_TIMEOUT_SECONDS,
        )
        self._read_execution_details(completed)

    def _worker_policy_argument(self) -> str:
        # Preserve legacy three-argument worker calls for the default CPU policy.
        if self._execution_policy == execution_policy():
            return ""
        return f", {self._execution_policy!r}"

    def _read_execution_details(self, completed) -> None:
        stdout = getattr(completed, "stdout", "")
        if not isinstance(stdout, str):
            return
        for line in stdout.splitlines():
            if line.startswith(EVIDENCE_PREFIX):
                details = json.loads(line[len(EVIDENCE_PREFIX):])
                observed = set(self.execution_details.get("observed_node_providers", []))
                observed.update(details.get("observed_node_providers", []))
                details["observed_node_providers"] = sorted(observed)
                details["successful_runs"] = (
                    self.execution_details.get("successful_runs", 0) + details.get("successful_runs", 0)
                )
                reasons = list(self.execution_details.get("fallback_reasons", []))
                if details.get("fallback_reason") and details["fallback_reason"] not in reasons:
                    reasons.append(details["fallback_reason"])
                details["fallback_reasons"] = reasons
                details["evidence_scope"] = "isolated_worker_inferences_observed_so_far"
                if "CPUExecutionProvider" in observed and "CUDAExecutionProvider" in observed:
                    details["execution_observation"] = "mixed_cpu_cuda"
                self.execution_details = details

    def _run_batch(self, features: np.ndarray) -> list[np.ndarray]:
        with TemporaryDirectory(prefix="credora-sequence-") as temp_dir:
            input_path = Path(temp_dir) / "input.npz"
            output_path = Path(temp_dir) / "output.npz"
            np.savez_compressed(input_path, X=features)
            code = (
                "from core.onnx_worker import run_onnx_worker; import sys; "
                f"run_onnx_worker(sys.argv[1], sys.argv[2], sys.argv[3]{self._worker_policy_argument()})"
            )
            completed = run_isolated_python(
                code,
                arguments=[str(self.path), str(input_path), str(output_path)],
                timeout_seconds=SEQUENCE_INFERENCE_TIMEOUT_SECONDS,
            )
            self._read_execution_details(completed)
            with np.load(output_path, allow_pickle=False) as payload:
                return [np.asarray(payload[key]) for key in sorted(payload.files)]

    def _run(self, features: np.ndarray) -> list[np.ndarray]:
        values = np.asarray(features)
        if values.ndim != 2 or values.shape[1] != self.metadata["max_sequence_length"]:
            raise ValueError(
                f"Sequence input must have shape [rows, {self.metadata['max_sequence_length']}]."
            )
        expected_dtype = np.dtype(self.metadata["sequence_dtype"])
        if values.dtype != expected_dtype:
            raise ValueError(f"Sequence input must use {expected_dtype}; received {values.dtype}.")
        collected: list[list[np.ndarray]] = []
        for start in range(0, len(values), SEQUENCE_INFERENCE_BATCH_SIZE):
            outputs = self._run_batch(values[start : start + SEQUENCE_INFERENCE_BATCH_SIZE])
            if not collected:
                collected = [[] for _ in outputs]
            for index, output in enumerate(outputs):
                collected[index].append(output)
        return [np.concatenate(parts, axis=0) for parts in collected]

    @staticmethod
    def _probabilities(values: np.ndarray) -> np.ndarray:
        matrix = np.asarray(values, dtype=float)
        if matrix.ndim != 2:
            raise ValueError("Sequence probability output must be a two-dimensional matrix.")
        row_sums = matrix.sum(axis=1)
        if np.any(matrix < 0) or not np.allclose(row_sums, 1.0, atol=1e-4):
            shifted = matrix - matrix.max(axis=1, keepdims=True)
            exponent = np.exp(shifted)
            matrix = exponent / exponent.sum(axis=1, keepdims=True)
        return matrix

    def predict_proba(self, features: np.ndarray) -> np.ndarray | None:
        outputs = self._run(features)
        candidate = outputs[1] if len(outputs) > 1 else outputs[0]
        if candidate.ndim != 2:
            return None
        probabilities = self._probabilities(candidate)
        if probabilities.shape[1] != len(self.class_labels):
            raise ValueError(
                f"Model returns {probabilities.shape[1]} classes, but metadata declares "
                f"{len(self.class_labels)}."
            )
        return probabilities

    def predict(self, features: np.ndarray) -> np.ndarray:
        outputs = self._run(features)
        if len(outputs) > 1 and outputs[0].ndim == 1:
            labels = outputs[0].astype(str)
            if set(labels.tolist()).issubset(set(self.class_labels.tolist())):
                return labels
        candidate = outputs[1] if len(outputs) > 1 else outputs[0]
        probabilities = self._probabilities(candidate)
        return self.class_labels[np.argmax(probabilities, axis=1)]

    def feature_importance(self, feature_columns: list[str]) -> list[dict] | None:
        return None


def load_model_backend(path: str | Path, metadata: dict[str, Any] | None = None) -> ModelBackend:
    model_path = Path(path)
    if (metadata or {}).get("input_type", "tabular") == "sequence":
        if model_path.suffix.lower() != ".onnx":
            raise ValueError("Sequence models must use the ONNX format.")
        return SequenceOnnxBackend(model_path, metadata or {})
    if model_path.suffix.lower() == ".onnx":
        if metadata and any(key in metadata for key in ("execution_device", "execution_fallback")):
            return OnnxBackend(model_path, metadata)
        return OnnxBackend(model_path)
    return SklearnBackend(model_path)
