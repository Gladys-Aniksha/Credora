"""Trusted container entrypoint. Never loads pickle, custom layers, or model code.

TensorFlow support is deliberately Keras 3 save_weights HDF5 dense layout only:
layers/dense/vars/{0,1}, layers/dense_1/vars/{0,1}, etc., plus empty root vars.
Optimizer/full-model state,
external/soft links, virtual datasets, compression and unknown objects are rejected.
Framework tensor files are mapped to fixed standard ONNX operators, so installing
PyTorch or TensorFlow is unnecessary. Native decoding dependencies stay here.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# -I removes cwd from sys.path; /app is immutable trusted image content.
if __name__ == "__main__":
    if sys.platform != "linux":
        raise SystemExit("Native worker requires the configured Linux Docker image.")
    import resource
    import signal

    # An independent deadline stops the entrypoint even if the Docker client dies.
    signal.alarm(75)
    resource.setrlimit(resource.RLIMIT_CPU, (70, 75))
    sys.path.insert(0, "/app")

from core.native_import import (
    MAX_ONNX_BYTES,
    NativeImportError,
    expected_tensors,
    read_metadata,
    validate_weights_file,
)


def _keras_weights(path: Path, contract: dict) -> dict:
    import h5py
    import numpy as np

    expected = expected_tensors(contract)
    count = len(contract["hidden_sizes"]) + 1
    datasets = {}
    groups = {"layers", "vars"}
    for index in range(count):
        layer = "dense" + (f"_{index}" if index else "")
        prefix = f"layers/{layer}"
        groups.update({prefix, prefix + "/vars"})
        for number, suffix in ((0, "weight"), (1, "bias")):
            name = f"layers.{index}.{suffix}"
            shape = expected[name]
            datasets[f"{prefix}/vars/{number}"] = (
                name,
                shape[::-1] if number == 0 else shape,
            )
    tensors = {}
    seen_groups = set()
    seen_objects = set()
    with h5py.File(path, "r") as handle:

        def visit(group, prefix=""):
            for key in group:
                name = prefix + key
                link = group.get(key, getlink=True)
                if not isinstance(link, h5py.HardLink):
                    raise NativeImportError("HDF5 external/soft links are disallowed.")
                obj = group[key]
                address = h5py.h5o.get_info(obj.id).addr
                if address in seen_objects:
                    raise NativeImportError("HDF5 aliases/cycles are disallowed.")
                seen_objects.add(address)
                if isinstance(obj, h5py.Group) and name in groups:
                    seen_groups.add(name)
                    visit(obj, name + "/")
                elif isinstance(obj, h5py.Dataset) and name in datasets:
                    tensor_name, shape = datasets[name]
                    if (
                        list(obj.shape) != shape
                        or obj.dtype != np.dtype("float32")
                        or obj.is_virtual
                        or obj.external
                        or obj.compression is not None
                        or obj.id.get_create_plist().get_nfilters() != 0
                    ):
                        raise NativeImportError(
                            "Unsupported HDF5 tensor storage, dtype or shape."
                        )
                    values = obj[...]
                    tensors[tensor_name] = (
                        values.T.copy() if tensor_name.endswith("weight") else values
                    )
                else:
                    raise NativeImportError(
                        "HDF5 must contain only approved dense weights."
                    )

        visit(handle)
    if set(tensors) != set(expected) or not groups.issubset(seen_groups):
        raise NativeImportError("Keras dense weights layout is incomplete.")
    return tensors


def convert_weights(weights: Path, metadata: Path, output: Path) -> None:
    """Called only in the locked-down worker; optional libraries are local imports."""
    import numpy as np
    import onnx
    from onnx import TensorProto, helper, numpy_helper

    contract = read_metadata(metadata)
    validate_weights_file(weights, contract)
    if contract["framework"] == "pytorch":
        from safetensors.numpy import load_file

        tensors = load_file(str(weights))
    else:
        tensors = _keras_weights(weights, contract)
    expected = expected_tensors(contract)
    if set(tensors) != set(expected):
        raise NativeImportError("Weight tensor names differ from the approved network.")
    for name, shape in expected.items():
        values = tensors[name]
        if (
            list(values.shape) != shape
            or values.dtype != np.float32
            or not np.isfinite(values).all()
        ):
            raise NativeImportError(
                "Weights must match shapes and contain finite float32 values."
            )
    initializers = [numpy_helper.from_array(v, name=k) for k, v in tensors.items()]
    nodes = []
    previous = "input"
    input_shape = [None, contract["input_size"]]
    if contract["architecture"] == "cnn1d":
        input_shape = [None, contract["sequence_length"]]
        initializers.append(
            numpy_helper.from_array(np.array([1], dtype=np.int64), name="channel_axis")
        )
        nodes.append(
            helper.make_node("Unsqueeze", [previous, "channel_axis"], ["channel_input"])
        )
        previous = "channel_input"
        for index in range(len(contract["channels"])):
            prefix = f"convs.{index}"
            nodes.append(
                helper.make_node(
                    "Conv", [previous, prefix + ".weight", prefix + ".bias"], [prefix]
                )
            )
            previous = prefix + ".relu"
            nodes.append(helper.make_node("Relu", [prefix], [previous]))
        nodes.append(
            helper.make_node("ReduceMean", [previous], ["pooled"], axes=[2], keepdims=0)
        )
        previous = "pooled"
    for index in range(len(contract["hidden_sizes"]) + 1):
        prefix = f"layers.{index}"
        last = index == len(contract["hidden_sizes"])
        target = "logits" if last else prefix
        nodes.append(
            helper.make_node(
                "Gemm",
                [previous, prefix + ".weight", prefix + ".bias"],
                [target],
                transB=1,
            )
        )
        previous = target
        if not last:
            previous = prefix + ".relu"
            nodes.append(helper.make_node("Relu", [target], [previous]))
    initializers.append(
        numpy_helper.from_array(
            np.asarray(contract["class_labels"], dtype=object), name="class_labels"
        )
    )
    nodes.append(helper.make_node("Softmax", ["logits"], ["probabilities"], axis=1))
    nodes.append(
        helper.make_node(
            "ArgMax", ["probabilities"], ["label_indices"], axis=1, keepdims=0
        )
    )
    nodes.append(
        helper.make_node(
            "Gather", ["class_labels", "label_indices"], ["labels"], axis=0
        )
    )
    graph = helper.make_graph(
        nodes,
        "restricted_native_v1",
        [helper.make_tensor_value_info("input", TensorProto.FLOAT, input_shape)],
        [
            helper.make_tensor_value_info("labels", TensorProto.STRING, [None]),
            helper.make_tensor_value_info(
                "probabilities", TensorProto.FLOAT, [None, contract["output_size"]]
            ),
        ],
        initializer=initializers,
    )
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", 17)],
        producer_name="restricted-native-v1",
    )
    model.ir_version = 9
    onnx.checker.check_model(model, full_check=True)
    # Graph structure is generated exclusively above; no user ONNX graph is accepted.
    if model.functions or any(
        t.external_data or t.data_location == TensorProto.EXTERNAL
        for t in model.graph.initializer
    ):
        raise NativeImportError("External data/functions are disallowed.")
    payload = model.SerializeToString()
    if len(payload) > MAX_ONNX_BYTES:
        raise NativeImportError("Converted ONNX exceeds file limit.")
    output.mkdir(exist_ok=True)
    (output / "model.onnx").write_bytes(payload)
    receipt = {
        "validated": True,
        "source_sha256": hashlib.sha256(weights.read_bytes()).hexdigest(),
        "onnx_sha256": hashlib.sha256(payload).hexdigest(),
    }
    (output / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")


if __name__ == "__main__":
    try:
        contract = read_metadata(Path("/input/metadata.json"))
        filename = (
            "weights.safetensors"
            if contract["framework"] == "pytorch"
            else "weights.weights.h5"
        )
        convert_weights(
            Path("/input") / filename, Path("/input/metadata.json"), Path("/output")
        )
    except Exception as exc:  # noqa: BLE001 - worker boundary reports decoder/checker errors.
        print(
            f"Restricted native conversion failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
