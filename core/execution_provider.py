"""Optional ONNX provider policy and conservative execution evidence.

Metadata accepts execution_device=cpu|auto|cuda and execution_fallback=error|cpu.
CUDA requires a registered CUDA provider unless CPU fallback is explicitly allowed.
Provider registration never guarantees that every graph node executes on CUDA.
"""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from core.model_storage import read_model_bytes

CPU = "CPUExecutionProvider"
CUDA = "CUDAExecutionProvider"
EVIDENCE_PREFIX = "ONNX_EXECUTION_DETAILS:"


def execution_policy(metadata: dict[str, Any] | None = None) -> dict[str, str]:
    metadata = metadata or {}
    device = metadata.get("execution_device", "cpu")
    if device not in ("cpu", "auto", "cuda"):
        raise ValueError("execution_device must be 'cpu', 'auto', or 'cuda'.")
    fallback = metadata.get("execution_fallback", "error" if device == "cuda" else "cpu")
    if fallback not in ("error", "cpu"):
        raise ValueError("execution_fallback must be 'error' or 'cpu'.")
    return {"execution_device": device, "execution_fallback": fallback}


class OnnxExecution:
    """Own one session; sample its first inference through ORT's node profiler.

    Profiling is enabled only for CUDA-configured sessions. Evidence describes
    that sample, not a strict guarantee about all nodes or subsequent runs.
    """

    def __init__(self, runtime, path: str | Path, metadata: dict[str, Any] | None = None):
        policy = execution_policy(metadata)
        device = policy["execution_device"]
        allow_fallback = policy["execution_fallback"] == "cpu"
        get_available = getattr(runtime, "get_available_providers", None)
        available = list(get_available()) if get_available else None
        providers = [CPU]
        reason = None
        if device != "cpu":
            if available is not None and CUDA in available:
                providers = [CUDA, CPU]
            elif not allow_fallback:
                raise RuntimeError("CUDAExecutionProvider is unavailable; install a compatible "
                                   "optional ONNX GPU runtime or set execution_fallback='cpu'.")
            else:
                reason = "CUDAExecutionProvider is unavailable in this runtime."
        self.details: dict[str, Any] = {
            **policy,
            "available_providers": available,
            "configured_providers": providers,
            "registered_providers": None,
            "fallback_reason": reason,
            "cpu_node_fallback_allowed": True,
            "strict_gpu_guarantee": False,
            "observed_node_providers": [],
            "execution_observation": "not_run",
            "evidence_scope": "first_successful_inference_only",
            "successful_runs": 0,
        }
        # Nonexistent paths are retained for runtime mocks; real artifacts are
        # decrypted only into memory, including the explicit CPU fallback path.
        model_source = read_model_bytes(path) if Path(path).is_file() else str(path)
        self._profile_dir = None
        options = runtime.SessionOptions()
        options.intra_op_num_threads = 1
        options.inter_op_num_threads = 1
        options.execution_mode = runtime.ExecutionMode.ORT_SEQUENTIAL
        if CUDA in providers:
            self._profile_dir = TemporaryDirectory(prefix="credora-onnx-profile-")
            options.enable_profiling = True
            options.profile_file_prefix = str(Path(self._profile_dir.name) / "profile")
        try:
            self.session = runtime.InferenceSession(model_source, sess_options=options, providers=providers)
        except Exception as exc:
            if CUDA not in providers or not allow_fallback:
                self._cleanup_profile()
                if CUDA in providers:
                    raise RuntimeError(f"CUDA session initialization failed: {exc}") from exc
                raise
            self.details["fallback_reason"] = f"CUDA session initialization failed: {exc}"
            try:
                self.session = runtime.InferenceSession(model_source, sess_options=options, providers=[CPU])
            except Exception:
                self._cleanup_profile()
                raise
        self._refresh_registered()
        registered = self.details["registered_providers"]
        if CUDA in providers and (registered is None or CUDA not in registered):
            if not allow_fallback:
                self._cleanup_profile()
                raise RuntimeError("CUDAExecutionProvider was requested but the session did not "
                                   "register it; CPU fallback is disabled.")
            self.details["fallback_reason"] = (
                self.details["fallback_reason"] or "CUDA was configured but did not register in the session."
            )
        if not allow_fallback and CUDA in providers:
            self.session.disable_fallback()

    def _refresh_registered(self) -> None:
        getter = getattr(self.session, "get_providers", None)
        self.details["registered_providers"] = list(getter()) if getter else None
        registered = self.details["registered_providers"]
        if CUDA in self.details["configured_providers"] and registered is not None and CUDA not in registered:
            self.details["fallback_reason"] = (
                self.details["fallback_reason"] or "CUDA was configured but did not register in the session."
            )

    def close(self) -> None:
        """Finish unused profiling (for validation-only worker sessions)."""
        if self._profile_dir is not None:
            try:
                self.session.end_profiling()
            except (OSError, ValueError, RuntimeError) as exc:
                self.details["profiling_error"] = str(exc)
            finally:
                self._cleanup_profile()

    def _cleanup_profile(self) -> None:
        if self._profile_dir is not None:
            self._profile_dir.cleanup()
            self._profile_dir = None

    def run(self, output_names, inputs):
        outputs = self.session.run(output_names, inputs)
        self._refresh_registered()
        if (self.details["execution_device"] != "cpu"
                and self.details["execution_fallback"] == "error"
                and CUDA not in (self.details["registered_providers"] or [])):
            raise RuntimeError("CUDAExecutionProvider is no longer registered; CPU fallback is disabled.")
        self.details["successful_runs"] += 1
        if self.details["successful_runs"] == 1:
            self.details["execution_observation"] = "node_placement_unverified"
            if self._profile_dir is not None:
                try:
                    profile_path = self.session.end_profiling()
                    with Path(profile_path).open(encoding="utf-8") as stream:
                        events = json.load(stream)
                    observed = sorted({event.get("args", {}).get("provider") for event in events
                                       if event.get("cat") == "Node" and event.get("args", {}).get("provider")})
                    self.details["observed_node_providers"] = observed
                    if CUDA in observed and CPU in observed:
                        observation = "mixed_cpu_cuda"
                    elif observed == [CUDA]:
                        observation = "cuda_nodes_observed"
                    elif observed == [CPU]:
                        observation = "cpu_nodes_observed"
                    else:
                        observation = "node_placement_unverified"
                    self.details["execution_observation"] = observation
                except (OSError, ValueError, TypeError, AttributeError, RuntimeError) as exc:
                    self.details["profiling_error"] = str(exc)
                finally:
                    self._cleanup_profile()
        return outputs
