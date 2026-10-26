from __future__ import annotations

import pytest
from onnx import TensorProto, helper

from core.onnx_safety import UnsafeOnnxError, validate_onnx_model
from sequence_fixtures import build_sequence_onnx


def test_valid_standard_onnx_is_accepted(tmp_path) -> None:
    report = validate_onnx_model(build_sequence_onnx(tmp_path / "valid.onnx"))

    assert report.node_count == 6
    assert report.inputs[0].shape == [None, 4]
    assert report.inputs[0].dtype == "int64"


def test_custom_operator_domain_is_rejected(tmp_path) -> None:
    input_info = helper.make_tensor_value_info("X", TensorProto.FLOAT, [None, 2])
    output_info = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [None, 2])
    graph = helper.make_graph(
        [helper.make_node("Dangerous", ["X"], ["Y"], domain="evil.custom")],
        "unsafe",
        [input_info],
        [output_info],
    )
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("evil.custom", 1)],
    )
    path = tmp_path / "custom.onnx"
    path.write_bytes(model.SerializeToString())

    with pytest.raises(UnsafeOnnxError, match="custom operator domains"):
        validate_onnx_model(path)


def test_access_limit_remains_a_rate_denial_not_an_invalid_model(tmp_path, monkeypatch) -> None:
    from core.model_access import ModelAccessLimitError, model_access_context

    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DISTINCT_LIMIT", "1")
    first = build_sequence_onnx(tmp_path / "first.onnx")
    second = build_sequence_onnx(tmp_path / "second.onnx")
    with model_access_context(7, "sequence_preflight", owner_id=7):
        validate_onnx_model(first)
        with pytest.raises(ModelAccessLimitError, match="distinct-model limit"):
            validate_onnx_model(second)
