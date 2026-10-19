from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
import types
from pathlib import Path

import pytest

from core import native_import as native

IMAGE = "trusted/native-import@sha256:" + "a" * 64


def metadata(**updates):
    return {
        "framework": "pytorch",
        "architecture": "mlp",
        "input_size": 3,
        "hidden_sizes": [4],
        "output_size": 2,
        "class_labels": ["safe", "other"],
        **updates,
    }


def write_weights(path, contract, *, nonfinite=False):
    import numpy as np

    header, payload = {}, bytearray()
    for name, shape in native.expected_tensors(contract).items():
        values = np.ones(shape, dtype="<f4")
        if nonfinite:
            values.flat[0] = np.nan
        raw = values.tobytes()
        header[name] = {
            "dtype": "F32",
            "shape": shape,
            "data_offsets": [len(payload), len(payload) + len(raw)],
        }
        payload.extend(raw)
    encoded = json.dumps(header).encode()
    encoded += b" " * (-len(encoded) % 8)
    path.write_bytes(struct.pack("<Q", len(encoded)) + encoded + payload)
    return path


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    monkeypatch.setenv(native.IMAGE_ENV, IMAGE)
    contract = metadata(
        _trusted=True, conversion_provenance={"image": "evil"}, docker_image="evil"
    )
    weights = write_weights(tmp_path / "source.safetensors", contract)
    meta = tmp_path / "source.json"
    meta.write_text(json.dumps(contract))
    return weights, meta, tmp_path / "result"


@pytest.mark.parametrize(
    "updates",
    [
        {"framework": "pickle"},
        {"architecture": "custom"},
        {"framework": "tensorflow", "architecture": "cnn1d"},
        {"input_size": True},
        {"input_size": 0},
        {"input_size": 4097},
        {"hidden_sizes": [512] * 5},
        {"input_size": 4096, "hidden_sizes": [512]},
        {"output_size": 257},
        {"class_labels": ["x", "x"]},
        {"class_labels": ["x"]},
        {"feature_columns": ["x"]},
        {
            "architecture": "cnn1d",
            "sequence_length": 2,
            "channels": [4],
            "kernel_sizes": [3],
        },
        {
            "architecture": "cnn1d",
            "sequence_length": 4,
            "channels": [4],
            "kernel_sizes": [1, 2],
        },
        {
            "architecture": "cnn1d",
            "sequence_length": 4096,
            "channels": [4],
            "kernel_sizes": [1],
            "input_size": 5,
        },
    ],
)
def test_reject_architecture_and_dimensions(updates):
    with pytest.raises(native.NativeImportError):
        native.validate_native_metadata(metadata(**updates))


def test_safe_copy_and_parameter_count():
    value = native.validate_native_metadata(
        metadata(_trusted=True, trusted=True, custom_layers=["X"])
    )
    assert value["total_parameters"] == 26
    assert not {"_trusted", "trusted", "custom_layers"} & value.keys()
    cnn = native.validate_native_metadata(
        metadata(
            architecture="cnn1d",
            sequence_length=8,
            input_size=1,
            channels=[4],
            kernel_sizes=[3],
        )
    )
    assert native.expected_tensors(cnn)["convs.0.weight"] == [4, 1, 3]


@pytest.mark.parametrize(
    "framework,suffix",
    [
        ("pytorch", ".pt"),
        ("pytorch", ".pth"),
        ("pytorch", ".onnx"),
        ("tensorflow", ".h5"),
        ("tensorflow", ".keras"),
    ],
)
def test_reject_disallowed_formats(tmp_path, framework, suffix):
    path = tmp_path / ("model" + suffix)
    path.write_bytes(b"x" * 32)
    with pytest.raises(native.NativeImportError):
        native.validate_weights_file(
            path, native.validate_native_metadata(metadata(framework=framework))
        )


def test_safetensors_header_and_payload_validation(tmp_path):
    contract = native.validate_native_metadata(metadata())
    path = write_weights(tmp_path / "m.safetensors", contract)
    native.validate_weights_file(path, contract)
    path.write_bytes(path.read_bytes() + b"extra")
    with pytest.raises(native.NativeImportError, match="payload"):
        native.validate_weights_file(path, contract)
    path.write_bytes(struct.pack("<Q", 2**63))
    with pytest.raises(native.NativeImportError, match="header"):
        native.validate_weights_file(path, contract)


@pytest.mark.parametrize("mutation", ["overlap", "dtype", "shape", "names"])
def test_safetensors_rejects_bad_tensor_contract(tmp_path, mutation):
    contract = native.validate_native_metadata(metadata())
    path = write_weights(tmp_path / "m.safetensors", contract)
    raw = path.read_bytes()
    length = struct.unpack("<Q", raw[:8])[0]
    header = json.loads(raw[8 : 8 + length])
    first, second = list(header)[:2]
    if mutation == "overlap":
        header[second]["data_offsets"] = [
            0,
            header[second]["data_offsets"][1] - header[second]["data_offsets"][0],
        ]
    elif mutation == "dtype":
        header[first]["dtype"] = "F64"
    elif mutation == "shape":
        header[first]["shape"][0] += 1
    else:
        header["evil"] = header.pop(first)
    encoded = json.dumps(header).encode()
    path.write_bytes(struct.pack("<Q", len(encoded)) + encoded + raw[8 + length :])
    with pytest.raises(native.NativeImportError):
        native.validate_weights_file(path, contract)


def docker_mock(monkeypatch, *, timeout=False, receipt_bad=False, daemon_bad=False):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        assert command[0] == "docker"
        assert not kwargs.get("shell")
        if command[1] == "info":
            data = {
                "OSType": "linux",
                "MemoryLimit": True,
                "SwapLimit": True,
                "CpuCfsQuota": True,
                "PidsLimit": not daemon_bad,
            }
            return subprocess.CompletedProcess(command, 0, json.dumps(data), "")
        if command[1] == "run":
            if timeout:
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])
            mounts = [
                command[i + 1] for i, arg in enumerate(command) if arg == "--mount"
            ]
            source = Path(mounts[0].split("source=", 1)[1].split(",target=")[0])
            out = Path(mounts[1].split("source=", 1)[1].split(",target=")[0])
            assert source.name == "input" and source.parent == out.parent
            assert mounts[0].endswith("target=/input,readonly")
            assert sorted(p.name for p in source.iterdir()) == [
                "metadata.json",
                "weights.safetensors",
            ]
            staged_meta = json.loads((source / "metadata.json").read_text())
            assert "_trusted" not in staged_meta and "docker_image" not in staged_meta
            payload = b"mock validated ONNX"
            (out / "model.onnx").write_bytes(payload)
            receipt = {
                "validated": True,
                "source_sha256": hashlib.sha256(
                    (source / "weights.safetensors").read_bytes()
                ).hexdigest(),
                "onnx_sha256": hashlib.sha256(payload).hexdigest(),
            }
            if receipt_bad:
                receipt["source_sha256"] = "bad"
            (out / "receipt.json").write_text(json.dumps(receipt))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(native.subprocess, "run", run)
    return calls


def test_docker_flags_containment_and_provenance(inputs, monkeypatch):
    calls = docker_mock(monkeypatch)
    result = native.import_native_model(*inputs)
    assert result.artifact_path == inputs[2] / "model.onnx"
    value = json.loads(result.metadata_path.read_text())
    assert value["class_labels"] == ["safe", "other"]
    assert value["artifact_trust"] == "untrusted" and "_trusted" not in value
    provenance = value["conversion_provenance"]
    assert (
        provenance["source_sha256"]
        == hashlib.sha256(inputs[0].read_bytes()).hexdigest()
    )
    assert provenance["framework"] == "pytorch" and provenance["image"] == IMAGE
    assert provenance["is_signature_or_trust"] is False
    command, kwargs = next(call for call in calls if call[0][1] == "run")
    for flag, expected in {
        "--network": "none",
        "--cap-drop": "ALL",
        "--security-opt": "no-new-privileges:true",
        "--user": "65532:65532",
        "--memory": "1g",
        "--memory-swap": "1g",
        "--cpus": "1",
        "--pids-limit": "64",
    }.items():
        assert command[command.index(flag) + 1] == expected
    assert "--read-only" in command and "--pull=never" in command
    assert kwargs["timeout"] == 90
    assert calls[-1][0][1:3] == ["rm", "--force"]
    assert not any(c[0][1] in ("build", "pull") for c in calls)


def test_timeout_forces_container_removal(inputs, monkeypatch):
    calls = docker_mock(monkeypatch, timeout=True)
    with pytest.raises(native.NativeImportError, match="timed out"):
        native.import_native_model(*inputs)
    assert calls[-1][0][1:3] == ["rm", "--force"]
    assert not inputs[2].exists()


def test_mismatched_receipt_rejected(inputs, monkeypatch):
    docker_mock(monkeypatch, receipt_bad=True)
    with pytest.raises(native.NativeImportError, match="receipt"):
        native.import_native_model(*inputs)
    assert not inputs[2].exists()


def test_unenforced_limits_rejected(inputs, monkeypatch):
    calls = docker_mock(monkeypatch, daemon_bad=True)
    with pytest.raises(native.NativeImportError, match="enforce"):
        native.import_native_model(*inputs)
    assert not any(c[0][1] == "run" for c in calls)


def test_missing_image_and_docker_fail_closed(inputs, monkeypatch):
    monkeypatch.delenv(native.IMAGE_ENV)
    with pytest.raises(native.NativeImportError, match="Operator"):
        native.import_native_model(*inputs)
    monkeypatch.setenv(native.IMAGE_ENV, IMAGE)

    def missing(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(native.subprocess, "run", missing)
    with pytest.raises(native.NativeImportError, match="Docker is required"):
        native.import_native_model(*inputs)


def test_existing_output_rejected(inputs, monkeypatch):
    inputs[2].mkdir()
    (inputs[2] / "keep").write_text("unchanged")
    with pytest.raises(native.NativeImportError, match="already exist"):
        native.import_native_model(*inputs)
    assert (inputs[2] / "keep").read_text() == "unchanged"


def test_worker_symlink_output_rejected(inputs, monkeypatch):
    docker_mock(monkeypatch)
    original = Path.is_symlink
    monkeypatch.setattr(
        Path, "is_symlink", lambda path: path.name == "model.onnx" or original(path)
    )
    with pytest.raises(native.NativeImportError, match="regular ONNX"):
        native.import_native_model(*inputs)
    assert not inputs[2].exists()


def test_image_missing_never_starts_conversion(inputs, monkeypatch):
    calls = docker_mock(monkeypatch)
    original = native.subprocess.run

    def image_missing(command, **kwargs):
        if command[1:3] == ["image", "inspect"]:
            raise subprocess.CalledProcessError(1, command)
        return original(command, **kwargs)

    monkeypatch.setattr(native.subprocess, "run", image_missing)
    with pytest.raises(native.NativeImportError, match="trusted image"):
        native.import_native_model(*inputs)
    assert not any(c[0][1] == "run" for c in calls)


def test_cleanup_failure_does_not_publish(inputs, monkeypatch):
    docker_mock(monkeypatch)
    original = native.subprocess.run

    def cleanup_failure(command, **kwargs):
        if command[1] == "rm":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return original(command, **kwargs)

    monkeypatch.setattr(native.subprocess, "run", cleanup_failure)
    with pytest.raises(native.NativeImportError, match="Failed to remove"):
        native.import_native_model(*inputs)
    assert not inputs[2].exists()


def test_duplicate_metadata_keys(tmp_path):
    path = tmp_path / "metadata.json"
    path.write_text('{"framework":"pytorch","framework":"tensorflow"}')
    with pytest.raises(native.NativeImportError, match="Duplicate"):
        native.read_metadata(path)


def test_integration_metadata_preserved_and_checked():
    raw = metadata(
        dataset="holdout.csv",
        expected_features=["a", "b", "c"],
        training_dataset_path="data/train.csv",
        model_name="small",
    )
    value = native.validate_native_metadata(raw)
    for key in ("dataset", "expected_features", "training_dataset_path", "model_name"):
        assert value[key] == raw[key]
    with pytest.raises(native.NativeImportError, match="training_dataset_path"):
        native.validate_native_metadata(
            metadata(training_dataset_path={"_trusted": True})
        )
    with pytest.raises(native.NativeImportError, match="expected_features"):
        native.validate_native_metadata(metadata(expected_features=["a", "a", "c"]))
    cnn = native.validate_native_metadata(
        metadata(
            input_size=1,
            architecture="cnn1d",
            sequence_length=8,
            channels=[4],
            kernel_sizes=[3],
        )
    )
    assert cnn["input_type"] == "sequence"
    assert cnn["max_sequence_length"] == 8 and cnn["sequence_dtype"] == "float32"
    assert cnn["vocab_size"] == 256 and cnn["pad_id"] == 0


@pytest.mark.parametrize("architecture", ["mlp", "cnn1d"])
def test_worker_generates_backend_compatible_onnx_with_mock_decoder(
    tmp_path, architecture, monkeypatch
):
    import numpy as np
    import pandas as pd

    onnx = pytest.importorskip("onnx")
    pytest.importorskip("onnxruntime")
    from core.native_worker import convert_weights

    raw = metadata(architecture=architecture)
    if architecture == "cnn1d":
        raw.update(input_size=1, sequence_length=8, channels=[4], kernel_sizes=[3])
    contract = native.validate_native_metadata(raw)
    weights = write_weights(tmp_path / "m.safetensors", contract)
    meta = tmp_path / "m.json"
    meta.write_text(json.dumps(contract))
    package = types.ModuleType("safetensors")
    decoder = types.ModuleType("safetensors.numpy")
    decoder.load_file = lambda path: {
        name: np.ones(shape, dtype=np.float32)
        for name, shape in native.expected_tensors(contract).items()
    }
    monkeypatch.setitem(sys.modules, "safetensors", package)
    monkeypatch.setitem(sys.modules, "safetensors.numpy", decoder)
    convert_weights(weights, meta, tmp_path / "out")
    model = onnx.load(str(tmp_path / "out/model.onnx"))
    onnx.checker.check_model(model, full_check=True)
    assert {n.op_type for n in model.graph.node} <= {
        "Conv",
        "Relu",
        "ReduceMean",
        "Gemm",
        "Unsqueeze",
        "Softmax",
        "ArgMax",
        "Gather",
    }
    assert model.graph.output[0].name == "labels"
    assert model.graph.output[1].name == "probabilities"
    from core.model_backend import OnnxBackend, SequenceOnnxBackend

    if architecture == "mlp":
        backend = OnnxBackend(tmp_path / "out/model.onnx")
        values = pd.DataFrame(np.ones((2, 3), dtype=np.float32))
    else:
        # Exercise existing sequence prediction methods independently of its
        # known FLOAT/float32 validator mismatch (separate regression below).
        import onnxruntime as ort

        backend = object.__new__(SequenceOnnxBackend)
        backend.metadata = contract
        backend.class_labels = np.asarray(contract["class_labels"])
        session = ort.InferenceSession(
            str(tmp_path / "out/model.onnx"), providers=["CPUExecutionProvider"]
        )
        monkeypatch.setattr(
            backend, "_run_batch", lambda values: session.run(None, {"input": values})
        )
        values = np.ones((2, 8), dtype=np.float32)
    assert backend.predict(values).tolist() == ["safe", "safe"]
    np.testing.assert_allclose(
        backend.predict_proba(values), np.full((2, 2), 0.5), atol=1e-6
    )


def test_existing_sequence_validator_accepts_float32(tmp_path):
    from onnx import TensorProto, helper

    from core.sequence_validation import validate_sequence_model_contract

    graph = helper.make_graph(
        [helper.make_node("Identity", ["X"], ["Y"])],
        "dtype_contract",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [None, 8])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [None, 8])],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)])
    path = tmp_path / "float.onnx"
    path.write_bytes(model.SerializeToString())
    contract = native.validate_native_metadata(
        metadata(
            input_size=1,
            architecture="cnn1d",
            sequence_length=8,
            channels=[4],
            kernel_sizes=[3],
        )
    )
    validate_sequence_model_contract(path, contract)


def test_real_safetensors_decoder_when_available(tmp_path):
    pytest.importorskip("safetensors")
    from core.native_worker import convert_weights

    contract = native.validate_native_metadata(metadata())
    path = write_weights(tmp_path / "m.safetensors", contract)
    meta = tmp_path / "m.json"
    meta.write_text(json.dumps(contract))
    convert_weights(path, meta, tmp_path / "out")


def test_keras_layout_and_external_links(tmp_path):
    h5py = pytest.importorskip("h5py")
    import numpy as np

    from core.native_worker import _keras_weights

    contract = native.validate_native_metadata(metadata(framework="tensorflow"))
    path = tmp_path / "m.weights.h5"
    with h5py.File(path, "w") as handle:
        handle.create_group("vars")
        for index, (source, target) in enumerate([(3, 4), (4, 2)]):
            layer = "dense" + (f"_{index}" if index else "")
            group = handle.create_group(f"layers/{layer}/vars")
            group.create_dataset("0", data=np.ones((source, target), dtype=np.float32))
            group.create_dataset("1", data=np.ones(target, dtype=np.float32))
    assert _keras_weights(path, contract)["layers.0.weight"].shape == (4, 3)
    with h5py.File(path, "a") as handle:
        handle["escape"] = h5py.ExternalLink("/etc/passwd", "/")
    with pytest.raises(native.NativeImportError, match="links"):
        _keras_weights(path, contract)
