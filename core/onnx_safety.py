from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import onnx
from google.protobuf.message import DecodeError
from onnx import TensorProto
from core.model_access import ModelAccessLimitError

from core.model_storage import read_model_bytes

ALLOWED_ONNX_DOMAINS = frozenset({"", "ai.onnx", "ai.onnx.ml"})


class UnsafeOnnxError(ValueError):
    """Raised when an ONNX graph uses an unsupported or unsafe capability."""


@dataclass(frozen=True)
class OnnxTensorContract:
    name: str
    dtype: str
    shape: list[int | None]


@dataclass(frozen=True)
class OnnxSafetyReport:
    opsets: dict[str, int]
    node_count: int
    inputs: list[OnnxTensorContract]
    outputs: list[OnnxTensorContract]


def _dimension_value(dimension: Any) -> int | None:
    if dimension.HasField("dim_value"):
        return int(dimension.dim_value)
    return None


def _tensor_contract(value: Any) -> OnnxTensorContract:
    tensor_type = value.type.tensor_type
    try:
        dtype = TensorProto.DataType.Name(tensor_type.elem_type).lower()
    except ValueError:
        dtype = f"unknown:{tensor_type.elem_type}"
    return OnnxTensorContract(
        name=str(value.name),
        dtype=dtype,
        shape=[_dimension_value(item) for item in tensor_type.shape.dim],
    )


def validate_onnx_model(path: str | Path) -> OnnxSafetyReport:
    """Validate an ONNX graph without resolving external tensor data."""
    try:
        model = onnx.load_model_from_string(read_model_bytes(path))
        # Tensor attributes, subgraphs, functions and sparse tensors can also
        # reference server files. Reject them before checker/runtime processing.
        pending = [model]
        while pending:
            message = pending.pop()
            if isinstance(message, TensorProto) and (
                message.data_location == TensorProto.EXTERNAL or message.external_data
            ):
                raise UnsafeOnnxError("ONNX external tensor data is not allowed.")
            for descriptor, value in message.ListFields():
                if descriptor.message_type is not None:
                    if descriptor.is_repeated:
                        pending.extend(value)
                    else:
                        pending.append(value)
        onnx.checker.check_model(model)
    except ModelAccessLimitError:
        raise
    except (onnx.checker.ValidationError, DecodeError, OSError, ValueError) as exc:
        raise UnsafeOnnxError(f"ONNX structure validation failed: {exc}") from exc

    external = [
        initializer.name
        for initializer in model.graph.initializer
        if initializer.data_location == TensorProto.EXTERNAL or initializer.external_data
    ]
    if external:
        raise UnsafeOnnxError(
            "ONNX external tensor data is not allowed: " + ", ".join(external[:5])
        )

    node_domains = {str(node.domain or "") for node in model.graph.node}
    opset_domains = {str(item.domain or "") for item in model.opset_import}
    unsupported = sorted((node_domains | opset_domains) - ALLOWED_ONNX_DOMAINS)
    if unsupported:
        raise UnsafeOnnxError(
            "ONNX custom operator domains are not allowed: " + ", ".join(unsupported)
        )

    graph_inputs = {value.name: value for value in model.graph.input}
    initializer_names = {initializer.name for initializer in model.graph.initializer}
    inputs = [
        _tensor_contract(value)
        for name, value in graph_inputs.items()
        if name not in initializer_names
    ]
    outputs = [_tensor_contract(value) for value in model.graph.output]
    return OnnxSafetyReport(
        opsets={str(item.domain or "ai.onnx"): int(item.version) for item in model.opset_import},
        node_count=len(model.graph.node),
        inputs=inputs,
        outputs=outputs,
    )
