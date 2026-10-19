from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

from core import model_backend, onnx_worker
from core.execution_provider import (
    CPU,
    CUDA,
    EVIDENCE_PREFIX,
    OnnxExecution,
    execution_policy,
)


def fake_runtime(tmp_path, available=(CPU,), registered=None, observed=(CUDA,), fail_cuda=False):
    sessions = []

    class Session:
        def __init__(self, path, sess_options, providers):
            if fail_cuda and CUDA in providers:
                raise RuntimeError("CUDA libraries could not load")
            self.providers = list(providers if registered is None else registered)
            self.options = sess_options
            self.fallback_disabled = False
            sessions.append(self)

        def get_providers(self):
            return self.providers

        def disable_fallback(self):
            self.fallback_disabled = True

        def get_inputs(self):
            return [SimpleNamespace(name="X")]

        def get_outputs(self):
            return [SimpleNamespace(name="probabilities")]

        def run(self, names, inputs):
            self.last_inputs = inputs
            return [np.tile([[0.25, 0.75]], (len(inputs["X"]), 1))]

        def end_profiling(self):
            path = Path(self.options.profile_file_prefix + ".json")
            path.write_text(json.dumps([
                {"cat": "Node", "args": {"provider": provider}} for provider in observed
            ]), encoding="utf-8")
            return str(path)

    return SimpleNamespace(
        get_available_providers=lambda: list(available),
        SessionOptions=SimpleNamespace,
        ExecutionMode=SimpleNamespace(ORT_SEQUENTIAL="sequential"),
        InferenceSession=Session,
        sessions=sessions,
    )


@pytest.mark.parametrize("device", ["gpu", "CUDA", None, False])
def test_invalid_device_is_rejected(device):
    with pytest.raises(ValueError, match="execution_device"):
        execution_policy({"execution_device": device})


def test_invalid_fallback_is_rejected():
    with pytest.raises(ValueError, match="execution_fallback"):
        execution_policy({"execution_fallback": True})


def test_default_cpu_does_not_select_available_cuda(tmp_path):
    runtime = fake_runtime(tmp_path, available=(CUDA, CPU))
    execution = OnnxExecution(runtime, "unused.onnx")
    assert execution.details["configured_providers"] == [CPU]
    assert execution.details["registered_providers"] == [CPU]
    assert execution.details["execution_observation"] == "not_run"
    assert not hasattr(execution.session.options, "enable_profiling")


def test_cuda_unavailable_fails_without_explicit_fallback(tmp_path):
    runtime = fake_runtime(tmp_path)
    with pytest.raises(RuntimeError, match="CUDAExecutionProvider is unavailable"):
        OnnxExecution(runtime, "unused.onnx", {"execution_device": "cuda"})
    assert runtime.sessions == []


@pytest.mark.parametrize("policy", [
    {"execution_device": "auto"},
    {"execution_device": "cuda", "execution_fallback": "cpu"},
])
def test_cpu_fallback_has_truthful_registration_evidence(tmp_path, policy):
    execution = OnnxExecution(fake_runtime(tmp_path), "unused.onnx", policy)
    assert execution.details["configured_providers"] == [CPU]
    assert execution.details["registered_providers"] == [CPU]
    assert "unavailable" in execution.details["fallback_reason"]
    assert not execution.details["strict_gpu_guarantee"]


def test_auto_can_explicitly_disallow_fallback(tmp_path):
    with pytest.raises(RuntimeError, match="unavailable"):
        OnnxExecution(fake_runtime(tmp_path), "unused.onnx", {
            "execution_device": "auto", "execution_fallback": "error",
        })


@pytest.mark.parametrize("device", ["auto", "cuda"])
def test_cuda_load_failure_fallback_is_policy_controlled(tmp_path, device):
    runtime = fake_runtime(tmp_path, available=(CUDA, CPU), fail_cuda=True)
    policy = {"execution_device": device}
    if device == "cuda":
        with pytest.raises(RuntimeError, match="CUDA session initialization failed"):
            OnnxExecution(runtime, "unused.onnx", policy)
    else:
        execution = OnnxExecution(runtime, "unused.onnx", policy)
        assert execution.details["registered_providers"] == [CPU]
        assert "CUDA libraries" in execution.details["fallback_reason"]
        execution.run(["probabilities"], {"X": np.zeros((1, 4))})
        assert execution._profile_dir is None


@pytest.mark.parametrize("device", ["auto", "cuda"])
def test_silent_runtime_cpu_registration_is_detected(tmp_path, device):
    runtime = fake_runtime(tmp_path, available=(CUDA, CPU), registered=[CPU], observed=[CPU])
    if device == "cuda":
        with pytest.raises(RuntimeError, match="did not register"):
            OnnxExecution(runtime, "unused.onnx", {"execution_device": device})
    else:
        execution = OnnxExecution(runtime, "unused.onnx", {"execution_device": device})
        assert execution.details["configured_providers"] == [CUDA, CPU]
        assert execution.details["registered_providers"] == [CPU]
        assert execution.details["fallback_reason"]
        execution.run(["probabilities"], {"X": np.zeros((1, 4))})
        assert execution.details["execution_observation"] == "cpu_nodes_observed"


@pytest.mark.parametrize("observed, observation", [
    ([CUDA], "cuda_nodes_observed"),
    ([CUDA, CPU], "mixed_cpu_cuda"),
    ([CPU], "cpu_nodes_observed"),
    ([], "node_placement_unverified"),
])
def test_profile_distinguishes_observed_nodes_from_gpu_guarantee(tmp_path, observed, observation):
    runtime = fake_runtime(tmp_path, available=(CUDA, CPU), observed=observed)
    execution = OnnxExecution(runtime, "unused.onnx", {"execution_device": "cuda"})
    assert execution.session.fallback_disabled
    assert execution.details["observed_node_providers"] == []
    execution.run(["probabilities"], {"X": np.zeros((1, 4))})
    assert execution.details["execution_observation"] == observation
    assert execution.details["observed_node_providers"] == sorted(observed)
    assert execution.details["cpu_node_fallback_allowed"]
    assert not execution.details["strict_gpu_guarantee"]
    assert execution._profile_dir is None
    execution.run(["probabilities"], {"X": np.zeros((1, 4))})
    assert execution.details["successful_runs"] == 2
    assert execution.details["evidence_scope"] == "first_successful_inference_only"


def test_profile_failure_does_not_invent_gpu_evidence(tmp_path):
    execution = OnnxExecution(fake_runtime(tmp_path, available=(CUDA, CPU)), "unused.onnx", {
        "execution_device": "auto",
    })
    execution.session.end_profiling = lambda: str(tmp_path / "missing.json")
    execution.run(["probabilities"], {"X": np.zeros((1, 4))})
    assert execution.details["execution_observation"] == "node_placement_unverified"
    assert execution.details["profiling_error"]


def test_tabular_metadata_reaches_runtime_and_exposes_evidence(monkeypatch, tmp_path):
    runtime = fake_runtime(tmp_path, available=(CUDA, CPU), observed=[CUDA, CPU])
    monkeypatch.setitem(sys.modules, "onnxruntime", runtime)
    backend = model_backend.load_model_backend(tmp_path / "unused.onnx", {"execution_device": "auto"})
    backend.predict(pd.DataFrame({"a": [1]}))
    assert backend.execution_details["execution_observation"] == "mixed_cpu_cuda"
    assert backend.session.last_inputs["X"].dtype == np.float32


def test_native_model_loading_ignores_onnx_policy(monkeypatch, tmp_path):
    model = object()
    monkeypatch.setattr(model_backend, "load_checked_model", lambda path: model)
    backend = model_backend.load_model_backend(tmp_path / "model.joblib", {"execution_device": "cuda"})
    assert backend.model is model


def test_sequence_policy_and_evidence_use_existing_worker(monkeypatch, tmp_path):
    from sequence_fixtures import build_sequence_onnx, sequence_metadata

    runtime = fake_runtime(tmp_path, available=(CUDA, CPU), observed=[CUDA, CPU])
    monkeypatch.setitem(sys.modules, "onnxruntime", runtime)
    calls = []

    def isolated(code, *, arguments, timeout_seconds):
        # Execute the exact child entrypoint in-process to mock CUDA, without
        # altering the production process boundary or function signatures.
        from contextlib import redirect_stdout
        from io import StringIO

        calls.append((code, arguments))
        monkeypatch.setattr(sys, "argv", ["-c", *arguments])
        stdout = StringIO()
        with redirect_stdout(stdout):
            exec(code, {})  # noqa: S102 - Exercise the production worker entrypoint with a mocked runtime.
        return SimpleNamespace(stdout=stdout.getvalue())

    monkeypatch.setattr(model_backend, "run_isolated_python", isolated)
    metadata = {**sequence_metadata(), "execution_device": "auto"}
    backend = model_backend.SequenceOnnxBackend(build_sequence_onnx(tmp_path / "model.onnx"), metadata)
    assert backend.execution_details["execution_observation"] == "not_run"
    assert backend.predict(np.ones((2, 4), dtype=np.int64)).tolist() == ["High", "High"]
    assert len(calls) == 2
    assert [len(arguments) for _, arguments in calls] == [1, 3]
    assert backend.execution_details["execution_observation"] == "mixed_cpu_cuda"
    assert backend.execution_details["registered_providers"] == [CUDA, CPU]


def test_default_worker_three_argument_signature_is_preserved(monkeypatch, tmp_path):
    from sequence_fixtures import build_sequence_onnx, sequence_metadata

    calls = []
    monkeypatch.setattr(model_backend, "run_isolated_python", lambda code, *, arguments, timeout_seconds:
                        calls.append(code))
    model_backend.SequenceOnnxBackend(build_sequence_onnx(tmp_path / "model.onnx"), sequence_metadata())
    assert "run_onnx_worker(sys.argv[1], None, None)" in calls[0]


def test_worker_default_cpu_returns_unmodified_output_arrays(monkeypatch, tmp_path, capsys):
    from sequence_fixtures import build_sequence_onnx

    monkeypatch.setitem(sys.modules, "onnxruntime", fake_runtime(tmp_path))
    model_path = build_sequence_onnx(tmp_path / "model.onnx")
    input_path = tmp_path / "input.npz"
    output_path = tmp_path / "output.npz"
    np.savez_compressed(input_path, X=np.ones((2, 4), dtype=np.int64))
    onnx_worker.run_onnx_worker(str(model_path), str(input_path), str(output_path))
    with np.load(output_path, allow_pickle=False) as payload:
        assert payload.files == ["output_0"]
        assert payload["output_0"].shape == (2, 2)
    details = json.loads(capsys.readouterr().out.split(EVIDENCE_PREFIX)[1])
    assert details["registered_providers"] == [CPU]
    assert details["successful_runs"] == 1


def test_sequence_batch_evidence_retains_mixed_execution_and_fallback_history():
    backend = model_backend.SequenceOnnxBackend.__new__(model_backend.SequenceOnnxBackend)
    backend.execution_details = {}
    for provider, reason in [(CUDA, None), (CPU, "CUDA unavailable"), (CUDA, None)]:
        backend._read_execution_details(SimpleNamespace(stdout=EVIDENCE_PREFIX + json.dumps({
            "observed_node_providers": [provider],
            "execution_observation": "cuda_nodes_observed" if provider == CUDA else "cpu_nodes_observed",
            "fallback_reason": reason,
            "successful_runs": 1,
        })))
    assert backend.execution_details["execution_observation"] == "mixed_cpu_cuda"
    assert backend.execution_details["fallback_reasons"] == ["CUDA unavailable"]
    assert backend.execution_details["successful_runs"] == 3


def test_real_sequence_auto_cpu_fallback_is_reported_from_child(tmp_path):
    import onnxruntime as ort
    from sequence_fixtures import build_sequence_onnx, sequence_metadata

    if CUDA in ort.get_available_providers():
        pytest.skip("This test specifically covers a CPU-only runtime.")
    backend = model_backend.SequenceOnnxBackend(
        build_sequence_onnx(tmp_path / "model.onnx"),
        {**sequence_metadata(), "execution_device": "auto"},
    )
    assert backend.predict(np.ones((1, 4), dtype=np.int64)).tolist() == ["High"]
    assert backend.execution_details["registered_providers"] == [CPU]
    assert backend.execution_details["fallback_reasons"]
    assert not backend.execution_details["strict_gpu_guarantee"]


def test_real_sequence_cuda_failure_is_reported_from_child(tmp_path):
    import onnxruntime as ort
    from sequence_fixtures import build_sequence_onnx, sequence_metadata

    from core.process_isolation import IsolatedProcessError

    if CUDA in ort.get_available_providers():
        pytest.skip("This test specifically covers a CPU-only runtime.")
    with pytest.raises(IsolatedProcessError, match="CUDAExecutionProvider is unavailable"):
        model_backend.SequenceOnnxBackend(
            build_sequence_onnx(tmp_path / "model.onnx"),
            {**sequence_metadata(), "execution_device": "cuda"},
        )
