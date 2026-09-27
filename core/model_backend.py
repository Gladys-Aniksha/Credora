from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

import numpy as np
import pandas as pd

from core.model_loading import load_checked_model


class ModelBackend(ABC):
    """Common prediction interface for supported tabular model formats."""

    @abstractmethod
    def predict(self, features: pd.DataFrame) -> np.ndarray:
        """Return one predicted label per input row."""

    @abstractmethod
    def predict_proba(self, features: pd.DataFrame) -> np.ndarray | None:
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
    def __init__(self, path: str | Path):
        import onnxruntime as ort

        session_options = ort.SessionOptions()
        session_options.intra_op_num_threads = 1
        session_options.inter_op_num_threads = 1
        session_options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        self.session = ort.InferenceSession(
            str(path),
            sess_options=session_options,
            providers=["CPUExecutionProvider"],
        )
        self.input_name = self.session.get_inputs()[0].name
        self.output_names = [output.name for output in self.session.get_outputs()]

    def _run(self, features: pd.DataFrame) -> list:
        inputs = {self.input_name: features.to_numpy(dtype=np.float32)}
        return self.session.run(self.output_names, inputs)

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


def load_model_backend(path: str | Path) -> ModelBackend:
    model_path = Path(path)
    if model_path.suffix.lower() == ".onnx":
        return OnnxBackend(model_path)
    return SklearnBackend(model_path)
