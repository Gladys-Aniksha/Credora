from __future__ import annotations

import sys
from types import SimpleNamespace

import numpy as np
import pandas as pd

from core import model_backend
from core.config import RISKY_MODEL_EXTENSIONS, SUPPORTED_MODEL_EXTENSIONS


class _SklearnModel:
    feature_importances_ = np.asarray([0.2, 0.8])

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        return np.asarray(["normal"] * len(features))

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        return np.asarray([[0.9, 0.1]] * len(features))


class _OnnxSession:
    def __init__(self, path: str, sess_options: object, providers: list[str]):
        self.path = path
        self.sess_options = sess_options
        self.providers = providers
        self.last_inputs: dict | None = None

    def get_inputs(self) -> list[SimpleNamespace]:
        return [SimpleNamespace(name="features")]

    def get_outputs(self) -> list[SimpleNamespace]:
        return [SimpleNamespace(name="label"), SimpleNamespace(name="probabilities")]

    def run(self, output_names: list[str], inputs: dict) -> list[object]:
        self.last_inputs = inputs
        assert output_names == ["label", "probabilities"]
        return [np.asarray([[1], [0]]), [{0: 0.1, 1: 0.9}, {0: 0.8, 1: 0.2}]]


def test_sklearn_backend_reuses_checked_loader(monkeypatch, tmp_path) -> None:
    model_path = tmp_path / "classifier.joblib"
    loaded_paths = []
    monkeypatch.setattr(
        model_backend,
        "load_checked_model",
        lambda path: loaded_paths.append(path) or _SklearnModel(),
    )

    backend = model_backend.load_model_backend(model_path)
    features = pd.DataFrame({"duration": [1.0], "bytes": [12.0]})

    assert isinstance(backend, model_backend.SklearnBackend)
    assert loaded_paths == [model_path]
    assert backend.predict(features).tolist() == ["normal"]
    assert backend.predict_proba(features).tolist() == [[0.9, 0.1]]
    assert backend.feature_importance(["duration", "bytes"]) == [
        {"feature": "bytes", "importance": 0.8},
        {"feature": "duration", "importance": 0.2},
    ]


def test_onnx_backend_uses_cpu_provider_and_float32_inputs(monkeypatch, tmp_path) -> None:
    session_options = SimpleNamespace(
        intra_op_num_threads=None,
        inter_op_num_threads=None,
        execution_mode=None,
    )
    runtime = SimpleNamespace(
        InferenceSession=_OnnxSession,
        SessionOptions=lambda: session_options,
        ExecutionMode=SimpleNamespace(ORT_SEQUENTIAL="sequential"),
    )
    monkeypatch.setitem(sys.modules, "onnxruntime", runtime)
    model_path = tmp_path / "classifier.ONNX"
    backend = model_backend.load_model_backend(model_path)
    features = pd.DataFrame({"duration": [1.0, 2.0], "bytes": [12.0, 7.0]})

    assert isinstance(backend, model_backend.OnnxBackend)
    assert backend.session.providers == ["CPUExecutionProvider"]
    assert backend.session.sess_options.intra_op_num_threads == 1
    assert backend.session.sess_options.inter_op_num_threads == 1
    assert backend.session.sess_options.execution_mode == "sequential"
    assert backend.predict(features).tolist() == [1, 0]
    assert backend.predict_proba(features).tolist() == [[0.1, 0.9], [0.8, 0.2]]
    assert backend.session.last_inputs["features"].dtype == np.float32
    assert backend.feature_importance(list(features.columns)) is None


def test_onnx_is_supported_without_entering_pickle_risk_policy() -> None:
    assert ".onnx" in SUPPORTED_MODEL_EXTENSIONS
    assert ".onnx" not in RISKY_MODEL_EXTENSIONS
    assert {".joblib", ".pkl"} <= RISKY_MODEL_EXTENSIONS
