from __future__ import annotations

from pathlib import Path

import numpy as np
import onnx
from onnx import TensorProto, helper


def build_sequence_onnx(path: Path, sequence_length: int = 4) -> Path:
    input_info = helper.make_tensor_value_info(
        "tokens", TensorProto.INT64, [None, sequence_length]
    )
    output_info = helper.make_tensor_value_info("logits", TensorProto.FLOAT, [None, 2])
    nodes = [
        helper.make_node("Cast", ["tokens"], ["float_tokens"], to=TensorProto.FLOAT),
        helper.make_node("ReduceSum", ["float_tokens"], ["score"], axes=[1], keepdims=0),
        helper.make_node("Neg", ["score"], ["negative_score"]),
        helper.make_node("Unsqueeze", ["negative_score"], ["negative_column"], axes=[1]),
        helper.make_node("Unsqueeze", ["score"], ["positive_column"], axes=[1]),
        helper.make_node("Concat", ["negative_column", "positive_column"], ["logits"], axis=1),
    ]
    graph = helper.make_graph(nodes, "sequence-test", [input_info], [output_info])
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 11)],
        producer_name="credora-tests",
    )
    model.ir_version = 8
    onnx.checker.check_model(model)
    path.write_bytes(model.SerializeToString())
    return path


def sequence_metadata(sequence_length: int = 4) -> dict:
    return {
        "model_name": "sequence-test",
        "version": "1.0",
        "algorithm": "test-sequence-graph",
        "framework": "ONNX",
        "task": "Encrypted Traffic Sequence Classification",
        "input_type": "sequence",
        "max_sequence_length": sequence_length,
        "sequence_dtype": "int64",
        "vocab_size": 256,
        "pad_id": 0,
        "class_labels": ["Low", "High"],
        "target_column": "label",
    }


def write_sequence_npz(path: Path, sequence_length: int = 4) -> Path:
    features = np.asarray(
        [[0] * sequence_length, [1] * sequence_length, [2] * sequence_length],
        dtype=np.int64,
    )
    labels = np.asarray(["Low", "High", "High"])
    np.savez_compressed(path, X=features, y=labels)
    return path
