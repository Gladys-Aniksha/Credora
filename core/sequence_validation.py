from __future__ import annotations

from pathlib import Path
from typing import Any

from core.onnx_safety import OnnxSafetyReport, validate_onnx_model
from core.sequence_data import SequenceDataError, load_sequence_dataset, validate_sequence_metadata


def validate_sequence_model_contract(
    model_path: str | Path,
    metadata: dict[str, Any],
) -> OnnxSafetyReport:
    contract = validate_sequence_metadata(metadata)
    report = validate_onnx_model(model_path)
    if len(report.inputs) != 1:
        raise SequenceDataError(
            f"Sequence models must expose exactly one graph input; found {len(report.inputs)}."
        )
    graph_input = report.inputs[0]
    if len(graph_input.shape) != 2:
        raise SequenceDataError(
            f"Sequence model input must have rank 2 [batch, sequence_length]; found {graph_input.shape}."
        )
    graph_length = graph_input.shape[1]
    if graph_length is not None and graph_length != contract["max_sequence_length"]:
        raise SequenceDataError(
            f"Model expects sequence length {graph_length}, but metadata declares "
            f"{contract['max_sequence_length']}. Model input '{graph_input.name}' "
            f"has shape {graph_input.shape} and dtype {graph_input.dtype}; metadata "
            f"declares {contract['sequence_dtype']}. Check that the model, dataset "
            "and metadata belong to the same export; tabular features are not sequence tokens."
        )
    graph_dtype = {"float": "float32", "double": "float64"}.get(graph_input.dtype, graph_input.dtype)
    if graph_dtype != contract["sequence_dtype"]:
        raise SequenceDataError(
            f"Model expects {graph_input.dtype} input, but metadata declares "
            f"{contract['sequence_dtype']}."
        )
    return report


def validate_sequence_compatibility(
    model_path: str | Path,
    dataset_path: str | Path,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    report = validate_sequence_model_contract(model_path, metadata)
    dataset = load_sequence_dataset(dataset_path, metadata)
    return {
        "input_type": "sequence",
        "rows": int(len(dataset.features)),
        "sequence_length": int(dataset.features.shape[1]),
        "sequence_dtype": str(dataset.features.dtype),
        "class_count": len(metadata["class_labels"]),
        "onnx_node_count": report.node_count,
        "onnx_opsets": report.opsets,
        "onnx_inputs": [item.__dict__ for item in report.inputs],
        "onnx_outputs": [item.__dict__ for item in report.outputs],
    }
