from __future__ import annotations

import numpy as np
import pytest

from core.sequence_data import SequenceDataError, load_sequence_dataset
from core.sequence_validation import validate_sequence_compatibility
from sequence_fixtures import build_sequence_onnx, sequence_metadata, write_sequence_npz


def test_sequence_npz_and_model_contract_are_compatible(tmp_path) -> None:
    model_path = build_sequence_onnx(tmp_path / "model.onnx")
    data_path = write_sequence_npz(tmp_path / "data.npz")

    details = validate_sequence_compatibility(model_path, data_path, sequence_metadata())

    assert details["rows"] == 3
    assert details["sequence_length"] == 4
    assert details["sequence_dtype"] == "int64"


def test_pickled_object_npz_is_rejected(tmp_path) -> None:
    path = tmp_path / "unsafe.npz"
    np.savez(path, X=np.asarray([[{"payload": "unsafe"}]], dtype=object), y=np.asarray(["Low"]))

    with pytest.raises(SequenceDataError, match="could not be read safely"):
        load_sequence_dataset(path, sequence_metadata(sequence_length=1))


def test_shape_dtype_and_vocabulary_mismatches_fail_loudly(tmp_path) -> None:
    path = tmp_path / "bad.npz"
    np.savez(path, X=np.asarray([[0, 1, 2, 300]], dtype=np.int64), y=np.asarray(["High"]))
    with pytest.raises(SequenceDataError, match="outside the declared vocabulary"):
        load_sequence_dataset(path, sequence_metadata())

    model_path = build_sequence_onnx(tmp_path / "model.onnx", sequence_length=8)
    with pytest.raises(SequenceDataError, match="expects sequence length 8"):
        validate_sequence_compatibility(model_path, write_sequence_npz(tmp_path / "ok.npz"), sequence_metadata())
