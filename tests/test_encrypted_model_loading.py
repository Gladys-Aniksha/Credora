from __future__ import annotations

import base64
import os
import pickle
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import numpy as np
import onnx
import pandas as pd
import pytest
from onnx import TensorProto, helper
from sequence_fixtures import build_sequence_onnx, sequence_metadata
from sklearn.tree import DecisionTreeClassifier

from core import (
    db,
    execution_provider,
    model_backend,
    model_loading,
    model_storage,
    onnx_safety,
    onnx_worker,
)
from core.execution_provider import CPU, CUDA, OnnxExecution
from core.model_storage import ModelStorageError, write_model_bytes
from core.process_isolation import run_isolated_python


@pytest.fixture(autouse=True)
def isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "storage.sqlite3")
    monkeypatch.setenv(
        "CREDORA_MODEL_ENCRYPTION_KEY",
        base64.urlsafe_b64encode(os.urandom(32)).decode(),
    )
    monkeypatch.delenv("CREDORA_MODEL_LOAD_CHILD", raising=False)


def classifier_bytes():
    model = DecisionTreeClassifier(random_state=0).fit([[0], [1]], ["low", "high"])
    return pickle.dumps(model, protocol=3)


def onnx_bytes():
    graph = helper.make_graph(
        [helper.make_node("Identity", ["X"], ["Y"])],
        "memory_model",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [None, 2])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [None, 2])],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)])
    model.ir_version = 9
    return model.SerializeToString()


def memory_children(monkeypatch, module, *, onnx_runtime=False):
    """Check memory-only sessions without replacing storage or process isolation.

    The production subprocess helper propagates the isolated DB and actor context.
    No plaintext model bytes or key appear in child code.
    """
    completed_children = []
    bootstrap = "import os; print('MODEL_CHILD_PID:'+str(os.getpid()));\n"
    if onnx_runtime:
        bootstrap += (
            "import onnxruntime as ort\n"
            "_original_session = ort.InferenceSession\n"
            "def _memory_session(source, *args, **kwargs):\n"
            "    assert isinstance(source, bytes), 'worker reopened a model path'\n"
            "    print('MEMORY_ONNX_MODEL:'+str(os.getpid()))\n"
            "    return _original_session(source, *args, **kwargs)\n"
            "ort.InferenceSession = _memory_session\n"
        )

    def isolated(code, *, arguments=None, timeout_seconds=15, environment=None):
        completed = run_isolated_python(
            bootstrap + code,
            arguments=arguments,
            timeout_seconds=timeout_seconds,
            environment=environment,
        )
        completed_children.append(completed)
        return completed

    monkeypatch.setattr(module, "run_isolated_python", isolated)
    return completed_children


@pytest.mark.parametrize("encrypted", [False, True])
def test_joblib_loads_checked_memory_stream_and_preserves_child_preflight(
    tmp_path, monkeypatch, encrypted
):
    payload = classifier_bytes()
    path = tmp_path / "model.joblib"
    if encrypted:
        write_model_bytes(path, payload)
    else:
        path.write_bytes(payload)
    stored = path.read_bytes()
    children = memory_children(monkeypatch, model_loading)
    original_load = model_loading.joblib.load
    streams = []

    def load(stream, *args, **kwargs):
        assert isinstance(stream, BytesIO)
        assert stream.getvalue() == payload
        assert str(stream) == str(path)
        streams.append(stream)
        return original_load(stream, *args, **kwargs)

    monkeypatch.setattr(model_loading.joblib, "load", load)
    model = model_loading.load_checked_model(path)
    assert model.predict([[0], [1]]).tolist() == ["low", "high"]
    assert len(streams) == 1 and streams[0].closed
    assert len(children) == 1 and "ok" in children[0].stdout
    child_pid = int(children[0].stdout.split("MODEL_CHILD_PID:")[1].splitlines()[0])
    assert child_pid != os.getpid()
    assert path.read_bytes() == stored
    if encrypted:
        assert stored.startswith(model_storage.MAGIC) and stored != payload


def test_encrypted_pickle_globals_still_reject_disallowed_callables(
    tmp_path, monkeypatch
):
    path = tmp_path / "blocked.pkl"
    write_model_bytes(path, pickle.dumps(os.system))
    calls = []
    monkeypatch.setattr(
        model_loading,
        "_run_deserialization_preflight",
        lambda *args: calls.append("child"),
    )
    monkeypatch.setattr(
        model_loading.joblib, "load", lambda *args: calls.append("load")
    )
    with pytest.raises(model_loading.UnsafeModelError, match="disallowed callable"):
        model_loading.load_checked_model(path)
    assert not calls


def test_encrypted_authentication_failure_never_reaches_deserializer(
    tmp_path, monkeypatch
):
    path = tmp_path / "model.pkl"
    write_model_bytes(path, classifier_bytes())
    damaged = bytearray(path.read_bytes())
    damaged[-1] ^= 1
    path.write_bytes(damaged)
    calls = []
    monkeypatch.setattr(
        model_loading.joblib, "load", lambda *args: calls.append("load")
    )
    with pytest.raises(ModelStorageError, match="authentication failed"):
        model_loading.load_checked_model(path)
    assert not calls


def test_plaintext_replaced_during_preflight_is_rechecked(tmp_path, monkeypatch):
    path = tmp_path / "legacy.pkl"
    path.write_bytes(classifier_bytes())
    monkeypatch.setattr(
        model_loading,
        "_run_deserialization_preflight",
        lambda target: target.write_bytes(pickle.dumps(os.system)),
    )
    calls = []
    monkeypatch.setattr(
        model_loading.joblib, "load", lambda *args: calls.append("load")
    )
    with pytest.raises(model_loading.UnsafeModelError, match="disallowed callable"):
        model_loading.load_checked_model(path)
    assert not calls


def test_encrypted_onnx_custom_domains_are_still_rejected(tmp_path):
    graph = helper.make_graph(
        [helper.make_node("Unknown", ["X"], ["Y"], domain="untrusted.custom")],
        "custom",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [None, 2])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [None, 2])],
    )
    model = helper.make_model(
        graph, opset_imports=[helper.make_opsetid("untrusted.custom", 1)]
    )
    path = tmp_path / "model.onnx"
    write_model_bytes(path, model.SerializeToString())
    with pytest.raises(onnx_safety.UnsafeOnnxError, match="custom operator domains"):
        onnx_safety.validate_onnx_model(path)


def external_tensor_model(layout, location, marker):
    """Exercise singular/repeated protobuf carriers, including ignored attributes."""
    tensor = TensorProto(name="external", data_type=TensorProto.FLOAT, dims=[1])
    if marker != "metadata_only":
        tensor.data_location = TensorProto.EXTERNAL
    if marker != "location_only":
        entry = tensor.external_data.add()
        entry.key, entry.value = "location", str(location)
        entry = tensor.external_data.add()
        entry.key, entry.value = "length", "4"
    model = onnx.load_model_from_string(onnx_bytes())

    def constant(value):
        return helper.make_node("Constant", [], ["constant_output"], value=value)

    def subgraph():
        return helper.make_graph(
            [constant(tensor)],
            "nested",
            [],
            [helper.make_tensor_value_info("constant_output", TensorProto.FLOAT, [1])],
        )

    def sparse():
        value = onnx.SparseTensorProto()
        value.dims.extend([1])
        value.values.CopyFrom(
            helper.make_tensor("sparse_values", TensorProto.FLOAT, [1], [1.0])
        )
        value.indices.CopyFrom(
            helper.make_tensor("sparse_indices", TensorProto.INT64, [1], [0])
        )
        if layout == "sparse_indices":
            value.indices.CopyFrom(tensor)
            value.indices.data_type = TensorProto.INT64
        else:
            value.values.CopyFrom(tensor)
        return value

    if layout == "initializer":
        model.graph.initializer.add().CopyFrom(tensor)
    elif layout == "constant":
        model.graph.node.add().CopyFrom(constant(tensor))
    elif layout == "nested_graph":
        condition = helper.make_tensor("condition", TensorProto.BOOL, [], [True])
        model.graph.initializer.add().CopyFrom(condition)
        model.graph.node.add().CopyFrom(
            helper.make_node(
                "If",
                ["condition"],
                ["branch_output"],
                then_branch=subgraph(),
                else_branch=subgraph(),
            )
        )
    elif layout in {"tensor_list", "graph_list", "sparse_attribute", "sparse_list"}:
        # These malicious carriers need not be schema-valid: rejection must
        # precede even checker interpretation of their attribute/op names.
        node = model.graph.node.add()
        node.op_type = "Carrier"
        attribute = node.attribute.add()
        attribute.name = "payload"
        if layout == "tensor_list":
            attribute.type = onnx.AttributeProto.TENSORS
            attribute.tensors.add().CopyFrom(tensor)
        elif layout == "graph_list":
            attribute.type = onnx.AttributeProto.GRAPHS
            attribute.graphs.add().CopyFrom(subgraph())
        elif layout == "sparse_attribute":
            attribute.type = onnx.AttributeProto.SPARSE_TENSOR
            attribute.sparse_tensor.CopyFrom(sparse())
        else:
            attribute.type = onnx.AttributeProto.SPARSE_TENSORS
            attribute.sparse_tensors.add().CopyFrom(sparse())
    elif layout in {"sparse_values", "sparse_indices"}:
        model.graph.sparse_initializer.add().CopyFrom(sparse())
    elif layout in {"function_body", "function_default"}:
        function = model.functions.add()
        function.name, function.domain = "FixtureFunction", "fixture.local"
        function.output.append("constant_output")
        function.opset_import.add().CopyFrom(helper.make_opsetid("", 17))
        if layout == "function_body":
            function.node.add().CopyFrom(constant(tensor))
        else:
            function.attribute_proto.add().CopyFrom(
                helper.make_attribute("default_value", tensor)
            )
    elif layout in {"training_initialization", "training_algorithm"}:
        training = model.training_info.add()
        field = "initialization" if layout == "training_initialization" else "algorithm"
        getattr(training, field).CopyFrom(subgraph())
    else:
        raise AssertionError("Unknown test layout")
    return model.SerializeToString()


@pytest.mark.parametrize("encrypted", [False, True])
@pytest.mark.parametrize("marker", ["both", "location_only", "metadata_only"])
@pytest.mark.parametrize(
    "layout",
    [
        "initializer",
        "constant",
        "nested_graph",
        "tensor_list",
        "graph_list",
        "sparse_values",
        "sparse_indices",
        "sparse_attribute",
        "sparse_list",
        "function_body",
        "function_default",
        "training_initialization",
        "training_algorithm",
    ],
)
def test_all_external_tensor_carriers_reject_before_checker_runtime_or_file_read(
    tmp_path, monkeypatch, encrypted, marker, layout
):
    import onnxruntime as ort

    external_file = tmp_path / "never-read-external.bin"
    external_file.write_bytes(b"\x00\x00\x80\x3f")
    payload = external_tensor_model(layout, external_file, marker)
    path = tmp_path / "model.onnx"
    if encrypted:
        write_model_bytes(path, payload)
    else:
        path.write_bytes(payload)

    checker = Mock(
        side_effect=AssertionError("Checker must not inspect external tensors")
    )
    runtime = Mock(
        side_effect=AssertionError("Runtime must not inspect external tensors")
    )
    monkeypatch.setattr(onnx.checker, "check_model", checker)
    monkeypatch.setattr(ort, "InferenceSession", runtime)
    opened = []
    original_open = Path.open

    def guarded_open(candidate, *args, **kwargs):
        if candidate == external_file:
            opened.append(candidate)
            pytest.fail("External sentinel file was opened")
        return original_open(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    for consume in (
        lambda: onnx_safety.validate_onnx_model(path),
        lambda: model_backend.OnnxBackend(path),
        lambda: onnx_worker.run_onnx_worker(str(path), None, None),
    ):
        with pytest.raises(
            onnx_safety.UnsafeOnnxError, match="external tensor data is not allowed"
        ):
            consume()
    checker.assert_not_called()
    runtime.assert_not_called()
    assert not opened


@pytest.mark.parametrize("encrypted", [False, True])
def test_onnx_validation_and_execution_consume_model_bytes(
    tmp_path, monkeypatch, encrypted
):
    import onnxruntime as ort

    payload = onnx_bytes()
    path = tmp_path / "model.onnx"
    if encrypted:
        write_model_bytes(path, payload)
    else:
        path.write_bytes(payload)
    original_session = ort.InferenceSession
    sources = []

    def session(source, *args, **kwargs):
        assert isinstance(source, bytes) and source == payload
        sources.append(source)
        return original_session(source, *args, **kwargs)

    monkeypatch.setattr(ort, "InferenceSession", session)
    monkeypatch.setattr(
        onnx,
        "load",
        lambda *args, **kwargs: pytest.fail("ONNX decoder reopened a file path"),
    )
    report = onnx_safety.validate_onnx_model(path)
    assert report.inputs[0].shape == [None, 2]
    backend = model_backend.OnnxBackend(path)
    frame = pd.DataFrame({"a": [1.0, 2.0], "b": [3.0, 4.0]})
    np.testing.assert_array_equal(
        backend._run(frame)[0], frame.to_numpy(dtype=np.float32)
    )
    assert len(sources) == 1
    assert not backend.execution_details["strict_gpu_guarantee"]


def test_cuda_fallback_reuses_the_same_plaintext_buffer(tmp_path, monkeypatch):
    payload = onnx_bytes()
    path = tmp_path / "model.onnx"
    write_model_bytes(path, payload)
    original_read = execution_provider.read_model_bytes
    reads, sources = [], []

    def read(source):
        reads.append(source)
        return original_read(source)

    class Session:
        def __init__(self, source, sess_options, providers):
            sources.append(source)
            if CUDA in providers:
                raise RuntimeError("test CUDA initialization failure")
            self.providers = providers

        def get_providers(self):
            return self.providers

        def end_profiling(self):
            return ""

    runtime = SimpleNamespace(
        SessionOptions=SimpleNamespace,
        ExecutionMode=SimpleNamespace(ORT_SEQUENTIAL=0),
        get_available_providers=lambda: [CUDA, CPU],
        InferenceSession=Session,
    )
    monkeypatch.setattr(execution_provider, "read_model_bytes", read)
    execution = OnnxExecution(runtime, path, {"execution_device": "auto"})
    assert (
        len(reads) == 1 and sources == [payload, payload] and sources[0] is sources[1]
    )
    assert execution.details["registered_providers"] == [CPU]
    assert "test CUDA" in execution.details["fallback_reason"]
    execution.close()
    assert execution._profile_dir is None


def test_sequence_size_limit_measures_plaintext_not_envelope(tmp_path, monkeypatch):
    plain = build_sequence_onnx(tmp_path / "fixture.onnx").read_bytes()
    path = tmp_path / "model.onnx"
    write_model_bytes(path, plain)
    assert path.stat().st_size > len(plain)
    monkeypatch.setattr(model_backend, "MAX_SEQUENCE_MODEL_BYTES", len(plain))
    calls = []
    monkeypatch.setattr(
        model_backend, "run_isolated_python", lambda *args, **kwargs: calls.append(args)
    )
    model_backend.SequenceOnnxBackend(path, sequence_metadata())
    assert len(calls) == 1
    monkeypatch.setattr(model_backend, "MAX_SEQUENCE_MODEL_BYTES", len(plain) - 1)
    with pytest.raises(ValueError, match="size limit"):
        model_backend.SequenceOnnxBackend(path, sequence_metadata())
    assert len(calls) == 1


def test_sequence_worker_decrypts_inside_real_child_without_plaintext_model_file(
    tmp_path, monkeypatch
):
    fixture = build_sequence_onnx(tmp_path / "fixture.onnx")
    payload = fixture.read_bytes()
    fixture.unlink()
    path = tmp_path / "model.onnx"
    write_model_bytes(path, payload)
    stored = path.read_bytes()
    children = memory_children(monkeypatch, model_backend, onnx_runtime=True)
    backend = model_backend.SequenceOnnxBackend(path, sequence_metadata())
    values = np.array([[0, 0, 0, 0], [1, 1, 1, 1]], dtype=np.int64)
    assert backend.predict(values).tolist() == ["Low", "High"]
    probabilities = backend.predict_proba(values)
    np.testing.assert_allclose(probabilities.sum(axis=1), 1.0)
    assert len(children) == 3
    assert all("MEMORY_ONNX_MODEL:" in child.stdout for child in children)
    assert all(
        f"MODEL_CHILD_PID:{os.getpid()}\n" not in child.stdout for child in children
    )
    assert path.read_bytes() == stored and stored.startswith(model_storage.MAGIC)
    assert list(tmp_path.glob("*.onnx")) == [path]
