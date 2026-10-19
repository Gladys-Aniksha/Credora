"""Restricted, Docker-only native weights conversion.

Schema v1: framework=pytorch|tensorflow, architecture=mlp|cnn1d,
input_size, hidden_sizes, output_size, class_labels. CNN additionally requires
sequence_length, channels, kernel_sizes (valid convolution, ReLU, global mean).
MLP uses ReLU hidden layers; CNN input is [N, L] with one channel.
Both expose string labels [N] and softmax probabilities [N, class_count].
Only float32 weights are accepted. Conversion conveys no signature or trust.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_WEIGHTS_BYTES = 32 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_PARAMETERS = 2_000_000
MAX_ONNX_BYTES = 16 * 1024 * 1024
IMAGE_ENV = "NATIVE_IMPORT_IMAGE"


class NativeImportError(ValueError):
    """Unsupported input or unavailable enforced conversion environment."""


@dataclass(frozen=True)
class NativeImportResult:
    artifact_path: Path
    metadata_path: Path


def _integer(value: Any, name: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise NativeImportError(f"{name} must be an integer in [1, {maximum}].")
    return value


def _sizes(value: Any, name: str, maximum: int, *, empty: bool = False) -> list[int]:
    if not isinstance(value, list) or not (0 if empty else 1) <= len(value) <= 4:
        raise NativeImportError(f"{name} must be a list with at most four sizes.")
    return [_integer(v, name, maximum) for v in value]


def validate_native_metadata(metadata: Any) -> dict[str, Any]:
    """Return an allowlisted copy; user trust/provenance/underscore fields vanish."""
    if not isinstance(metadata, dict):
        raise NativeImportError("Metadata must be a JSON object.")
    framework = metadata.get("framework")
    architecture = metadata.get("architecture")
    if framework not in ("pytorch", "tensorflow") or architecture not in (
        "mlp",
        "cnn1d",
    ):
        raise NativeImportError(
            "Approved frameworks/architectures: pytorch mlp/cnn1d, tensorflow mlp."
        )
    if framework == "tensorflow" and architecture != "mlp":
        raise NativeImportError("TensorFlow supports only built-in mlp.")
    result = {"framework": framework, "architecture": architecture, "schema_version": 1}
    if (
        type(metadata.get("schema_version", 1)) is not int
        or metadata.get("schema_version", 1) != 1
    ):
        raise NativeImportError("Unsupported schema_version.")
    result["input_size"] = _integer(metadata.get("input_size"), "input_size", 4096)
    result["output_size"] = _integer(metadata.get("output_size"), "output_size", 256)
    result["hidden_sizes"] = _sizes(
        metadata.get("hidden_sizes", []), "hidden_sizes", 512, empty=True
    )
    if architecture == "cnn1d":
        if result["input_size"] != 1:
            raise NativeImportError(
                "CNN input_size must be 1 (single input channel for [N,L])."
            )
        result["sequence_length"] = _integer(
            metadata.get("sequence_length"), "sequence_length", 4096
        )
        if result["input_size"] * result["sequence_length"] > 16384:
            raise NativeImportError("CNN input element limit exceeded.")
        result["channels"] = _sizes(metadata.get("channels"), "channels", 128)
        result["kernel_sizes"] = _sizes(
            metadata.get("kernel_sizes"), "kernel_sizes", 15
        )
        if len(result["channels"]) != len(result["kernel_sizes"]):
            raise NativeImportError(
                "channels and kernel_sizes must have equal lengths."
            )
        if result["sequence_length"] - sum(k - 1 for k in result["kernel_sizes"]) < 1:
            raise NativeImportError("Convolution kernels exceed sequence length.")
    labels = metadata.get("class_labels")
    if (
        not isinstance(labels, list)
        or len(labels) != result["output_size"]
        or any(not isinstance(v, str) or not v or len(v) > 256 for v in labels)
        or len(set(labels)) != len(labels)
    ):
        raise NativeImportError(
            "class_labels must be unique nonempty strings matching output_size."
        )
    result["class_labels"] = list(labels)
    for key in (
        "name",
        "model_name",
        "description",
        "version",
        "target_column",
        "task",
        "algorithm",
        "dataset",
        "training_dataset_path",
    ):
        if key in metadata:
            if (
                not isinstance(metadata[key], str)
                or len(metadata[key]) > 2048
                or "\x00" in metadata[key]
            ):
                raise NativeImportError(f"Invalid {key}.")
            result[key] = metadata[key]
    for feature_key in ("feature_columns", "expected_features"):
        if feature_key not in metadata:
            continue
        if architecture == "cnn1d":
            raise NativeImportError(
                "CNN sequence metadata cannot declare tabular features."
            )
        columns = metadata[feature_key]
        if (
            not isinstance(columns, list)
            or len(columns) != result["input_size"]
            or any(not isinstance(v, str) or not v or len(v) > 256 for v in columns)
            or len(set(columns)) != len(columns)
        ):
            raise NativeImportError(
                f"{feature_key} must match input_size and be unique strings."
            )
        result[feature_key] = list(columns)
    if (
        "feature_columns" in result
        and "expected_features" in result
        and result["feature_columns"] != result["expected_features"]
    ):
        raise NativeImportError("feature_columns and expected_features disagree.")
    if "feature_columns" in result:
        result["expected_features"] = list(result["feature_columns"])
    expected_type = "sequence" if architecture == "cnn1d" else "tabular"
    if metadata.get("input_type", expected_type) != expected_type:
        raise NativeImportError(
            "input_type is incompatible with approved architecture."
        )
    result["input_type"] = expected_type
    if "pcap_schema" in metadata:
        if architecture != "mlp" or metadata["pcap_schema"] != "pcap_flow_v1":
            raise NativeImportError("Native imports support PCAP only with the tabular pcap_flow_v1 schema.")
        result["pcap_schema"] = "pcap_flow_v1"
    if architecture == "cnn1d":
        if (
            metadata.get("max_sequence_length", result["sequence_length"])
            != result["sequence_length"]
        ):
            raise NativeImportError("max_sequence_length must match sequence_length.")
        if metadata.get("sequence_dtype", "float32") != "float32":
            raise NativeImportError("CNN sequence_dtype must be float32.")
        result["max_sequence_length"] = result["sequence_length"]
        result["sequence_dtype"] = "float32"
        result["vocab_size"] = _integer(
            metadata.get("vocab_size", 256), "vocab_size", 65536
        )
        pad_id = metadata.get("pad_id", 0)
        if type(pad_id) is not int or not 0 <= pad_id < result["vocab_size"]:
            raise NativeImportError("pad_id must be inside vocabulary.")
        result["pad_id"] = pad_id
    parameters = sum(math.prod(shape) for shape in expected_tensors(result).values())
    if parameters > MAX_PARAMETERS:
        raise NativeImportError("Architecture exceeds total parameter limit.")
    result["total_parameters"] = parameters
    return result


def expected_tensors(metadata: dict[str, Any]) -> dict[str, list[int]]:
    """Canonical PyTorch names; dense weights are [out, in], CNN [out, in, k]."""
    shapes = {}
    width = metadata["input_size"]
    if metadata["architecture"] == "cnn1d":
        for index, (channels, kernel) in enumerate(
            zip(metadata["channels"], metadata["kernel_sizes"])
        ):
            shapes[f"convs.{index}.weight"] = [channels, width, kernel]
            shapes[f"convs.{index}.bias"] = [channels]
            width = channels
    for index, size in enumerate([*metadata["hidden_sizes"], metadata["output_size"]]):
        shapes[f"layers.{index}.weight"] = [size, width]
        shapes[f"layers.{index}.bias"] = [size]
        width = size
    return shapes


def _json_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise NativeImportError("Duplicate JSON keys are not allowed.")
        result[key] = value
    return result


def read_metadata(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_METADATA_BYTES:
        raise NativeImportError("Metadata missing or exceeds 64 KiB.")
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_METADATA_BYTES + 1)
        if len(data) > MAX_METADATA_BYTES:
            raise NativeImportError("Metadata exceeds 64 KiB.")
        return validate_native_metadata(
            json.loads(data.decode("utf-8"), object_pairs_hook=_json_object)
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise NativeImportError("Invalid metadata JSON.") from exc


def validate_weights_file(path: Path, metadata: dict) -> None:
    if not path.is_file() or not 8 <= path.stat().st_size <= MAX_WEIGHTS_BYTES:
        raise NativeImportError("Weights missing or exceed 32 MiB.")
    if metadata["framework"] == "tensorflow":
        if not path.name.endswith(".weights.h5"):
            raise NativeImportError("TensorFlow requires weights-only .weights.h5.")
        with path.open("rb") as stream:
            if stream.read(8) != b"\x89HDF\r\n\x1a\n":
                raise NativeImportError("Invalid HDF5 weights signature.")
        return
    if path.suffix != ".safetensors":
        raise NativeImportError(
            "PyTorch requires .safetensors; pickle .pt/.pth is disallowed."
        )
    try:
        with path.open("rb") as stream:
            length = struct.unpack("<Q", stream.read(8))[0]
            if (
                not 2 <= length <= MAX_METADATA_BYTES
                or length + 8 > path.stat().st_size
            ):
                raise NativeImportError("Invalid safetensors header length.")
            header = json.loads(stream.read(length), object_pairs_hook=_json_object)
        if not isinstance(header, dict):
            raise NativeImportError("Invalid safetensors header.")
        header.pop("__metadata__", None)
        expected = expected_tensors(metadata)
        if set(header) != set(expected):
            raise NativeImportError(
                "Safetensors tensor names do not match approved architecture."
            )
        intervals = []
        for name, shape in expected.items():
            item = header[name]
            if (
                not isinstance(item, dict)
                or item.get("dtype") != "F32"
                or item.get("shape") != shape
                or any(type(v) is not int for v in item.get("shape", []))
            ):
                raise NativeImportError("Safetensors dtype/shape mismatch.")
            offsets = item.get("data_offsets")
            if (
                not isinstance(offsets, list)
                or len(offsets) != 2
                or any(type(v) is not int for v in offsets)
                or offsets[0] < 0
                or offsets[1] - offsets[0] != math.prod(shape) * 4
            ):
                raise NativeImportError("Invalid safetensors offsets.")
            intervals.append(offsets)
        cursor = 0
        for start, end in sorted(intervals):
            if start != cursor:
                raise NativeImportError("Safetensors overlap or gap.")
            cursor = end
        if cursor != path.stat().st_size - 8 - length:
            raise NativeImportError("Safetensors payload size mismatch.")
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        struct.error,
        RecursionError,
    ) as exc:
        raise NativeImportError("Invalid safetensors file.") from exc


def _docker(arguments: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess:
    try:
        # No shell, framework subprocess, automatic image pull, or host fallback.
        return subprocess.run(
            ["docker", *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise NativeImportError(
            "Docker is required for native import; no host fallback."
        ) from exc
    except (subprocess.SubprocessError, OSError) as exc:
        raise NativeImportError(
            "Docker conversion failed or timed out; check the trusted image and daemon limits."
        ) from exc


def import_native_model(
    weights: str | Path, metadata: str | Path, outputdir: str | Path
) -> NativeImportResult:
    """Standalone parent integration. Outputdir must not exist; returns model/JSON paths.

    Operator must set NATIVE_IMPORT_IMAGE to a locally present repo@sha256:digest.
    No image choice from user metadata or CLI is accepted. Worker deadline=75s,
    Docker client timeout=90s (cleanup has its own 15s timeout);
    container memory=1 GiB, CPU=1, pids=64. Requires Linux Docker with cgroup limits.
    """
    image = os.environ.get(IMAGE_ENV, "")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[0-9a-f]{64}", image):
        raise NativeImportError(
            "Operator must configure NATIVE_IMPORT_IMAGE with a trusted image digest."
        )
    destination = Path(outputdir).resolve()
    if destination.exists():
        raise NativeImportError("Output directory must not already exist.")
    source = Path(weights).resolve()
    contract = read_metadata(Path(metadata).resolve())
    validate_weights_file(source, contract)
    try:
        info = json.loads(_docker(["info", "--format", "{{json .}}"]).stdout)
        if info.get("OSType") != "linux" or not all(
            info.get(key) is True
            for key in ("MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit")
        ):
            raise NativeImportError(
                "Docker must enforce Linux memory, swap, CPU and PID limits."
            )
    except (json.JSONDecodeError, AttributeError) as exc:
        raise NativeImportError("Cannot verify Docker resource-limit support.") from exc
    _docker(["image", "inspect", image])  # local image only; never build or pull
    name = "native-import-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="native-import-") as temporary:
        root = Path(temporary)
        inputs, outputs = root / "input", root / "output"
        inputs.mkdir()
        inputs.chmod(0o755)
        outputs.mkdir()
        outputs.chmod(
            0o777
        )  # Dedicated empty directory, writable by the container UID.
        staged = inputs / (
            "weights.safetensors"
            if contract["framework"] == "pytorch"
            else "weights.weights.h5"
        )
        # Copy at most the cap even if the source grows concurrently.
        with source.open("rb") as reader, staged.open("wb") as writer:
            data = reader.read(MAX_WEIGHTS_BYTES + 1)
            if len(data) > MAX_WEIGHTS_BYTES:
                raise NativeImportError("Weights exceed file cap.")
            writer.write(data)
        validate_weights_file(staged, contract)
        staged.chmod(0o644)
        source_hash = hashlib.sha256(data).hexdigest()
        (inputs / "metadata.json").write_text(json.dumps(contract), encoding="utf-8")
        (inputs / "metadata.json").chmod(0o644)
        # Mount dedicated staging directories, never an entire user directory.
        if any("," in str(p) for p in (inputs, outputs)):
            raise NativeImportError("Docker staging mount paths cannot contain commas.")
        try:
            _docker(
                [
                    "run",
                    "--pull=never",
                    "--name",
                    name,
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--user",
                    "65532:65532",
                    "--memory",
                    "1g",
                    "--memory-swap",
                    "1g",
                    "--cpus",
                    "1",
                    "--pids-limit",
                    "64",
                    "--ulimit",
                    "fsize=16777216:16777216",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=64m,mode=1777",
                    "--mount",
                    f"type=bind,source={inputs},target=/input,readonly",
                    "--mount",
                    f"type=bind,source={outputs},target=/output",
                    "--entrypoint",
                    "python",
                    image,
                    "-I",
                    "/app/core/native_worker.py",
                ],
                timeout=90,
            )
            model = outputs / "model.onnx"
            if (
                model.is_symlink()
                or not model.is_file()
                or not 0 < model.stat().st_size <= MAX_ONNX_BYTES
            ):
                raise NativeImportError(
                    "Worker did not produce a bounded regular ONNX artifact."
                )
            # The trusted worker validates ONNX inside the resource-limited container.
            receipt_path = outputs / "receipt.json"
            if (
                receipt_path.is_symlink()
                or not receipt_path.is_file()
                or receipt_path.stat().st_size > MAX_METADATA_BYTES
            ):
                raise NativeImportError("Worker validation receipt missing or invalid.")
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            artifact_hash = hashlib.sha256(model.read_bytes()).hexdigest()
            if receipt != {
                "source_sha256": source_hash,
                "onnx_sha256": artifact_hash,
                "validated": True,
            }:
                raise NativeImportError(
                    "Worker validation receipt does not match artifacts."
                )
            final_metadata = dict(contract)
            final_metadata.update(
                {
                    "model_format": "onnx",
                    "input_dtype": "float32",
                    "input_shape": [
                        None,
                        contract["sequence_length"]
                        if contract["architecture"] == "cnn1d"
                        else contract["input_size"],
                    ],
                    "output_semantics": "labels_and_probabilities",
                    "artifact_trust": "untrusted",
                    "conversion_provenance": {
                        "converter": "restricted-native-v1",
                        "framework": contract["framework"],
                        "source_sha256": source_hash,
                        "onnx_sha256": artifact_hash,
                        "image": image,
                        "is_signature_or_trust": False,
                    },
                }
            )
        finally:
            # Docker CLI timeout alone does not stop a container. Always force removal.
            try:
                _docker(["rm", "--force", name])
            except NativeImportError as exc:
                raise NativeImportError(
                    f"Failed to remove converter container {name}; inspect Docker cleanup."
                ) from exc
        # Publish only after successful conversion, receipt verification and cleanup.
        destination.mkdir(parents=True, exist_ok=False)
        try:
            shutil.copyfile(model, destination / "model.onnx")
            (destination / "metadata.json").write_text(
                json.dumps(final_metadata, indent=2), encoding="utf-8"
            )
        except BaseException:
            shutil.rmtree(destination)
            raise
    return NativeImportResult(destination / "model.onnx", destination / "metadata.json")
