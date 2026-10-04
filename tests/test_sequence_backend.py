from __future__ import annotations

import numpy as np

from core.model_backend import SequenceOnnxBackend, load_model_backend
from modules.phase1_foundation.m8_etc_classifier.evaluate import evaluate_classifier
from sequence_fixtures import build_sequence_onnx, sequence_metadata, write_sequence_npz


def test_sequence_backend_runs_isolated_predictions_and_probabilities(tmp_path) -> None:
    model_path = build_sequence_onnx(tmp_path / "model.onnx")
    metadata = sequence_metadata()
    backend = load_model_backend(model_path, metadata)
    features = np.asarray([[0, 0, 0, 0], [1, 1, 1, 1]], dtype=np.int64)

    assert isinstance(backend, SequenceOnnxBackend)
    assert backend.predict(features).tolist() == ["Low", "High"]
    probabilities = backend.predict_proba(features)
    assert probabilities is not None
    assert probabilities.shape == (2, 2)
    assert np.allclose(probabilities.sum(axis=1), 1.0)


def test_sequence_classifier_evaluation_preserves_common_metric_contract(tmp_path) -> None:
    model_path = build_sequence_onnx(tmp_path / "model.onnx")
    data_path = write_sequence_npz(tmp_path / "test.npz")

    result = evaluate_classifier(model_path, data_path, sequence_metadata())

    assert result.status == "pass"
    assert result.score == 100.0
    assert result.details["input_type"] == "sequence"
    assert result.details["labels"] == ["High", "Low"]
    assert result.details["sequence_compatibility"]["rows"] == 3
