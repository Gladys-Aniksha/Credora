from __future__ import annotations

from pathlib import Path

import numpy as np

from core.onnx_safety import validate_onnx_model


def _normalize_output(value) -> np.ndarray:
    if isinstance(value, list) and value and isinstance(value[0], dict):
        labels = list(value[0])
        return np.asarray([[row.get(label, 0.0) for label in labels] for row in value])
    return np.asarray(value)


def run_onnx_worker(model_path: str, input_path: str | None, output_path: str | None) -> None:
    """Create and optionally execute an ONNX session inside a bounded child process."""
    import onnxruntime as ort

    validate_onnx_model(model_path)
    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    session = ort.InferenceSession(
        str(Path(model_path)),
        sess_options=options,
        providers=["CPUExecutionProvider"],
    )
    if input_path is None:
        return

    with np.load(input_path, allow_pickle=False) as payload:
        features = np.asarray(payload["X"])
    input_name = session.get_inputs()[0].name
    output_names = [output.name for output in session.get_outputs()]
    outputs = session.run(output_names, {input_name: features})
    arrays = {f"output_{index}": _normalize_output(value) for index, value in enumerate(outputs)}
    np.savez_compressed(output_path, **arrays)
