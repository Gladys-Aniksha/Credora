"""Prepare explicitly supported uploads before the existing assessment pipeline."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from core.hashing import sha256_file


@dataclass(frozen=True)
class PreparedAssessment:
    model_path: Path
    dataset_path: Path
    metadata: dict[str, Any]
    provenance: dict[str, Any]


def prepare_assessment_inputs(
    model_path: Path,
    dataset_path: Path,
    metadata: dict[str, Any],
    output_dir: Path,
    *,
    flow_labels_path: Path | None = None,
    execution_device: str | None = None,
    allow_cpu_fallback: bool = False,
) -> PreparedAssessment:
    if not isinstance(metadata, dict):
        raise ValueError("Model metadata must be a JSON object, not verification results or a list.")
    metadata = dict(metadata)
    provenance: dict[str, Any] = {}
    native = model_path.suffix.lower() == ".safetensors" or model_path.name.lower().endswith(".weights.h5")
    if native:
        from core.native_import import import_native_model

        output_dir.mkdir(parents=True, exist_ok=True)
        source_metadata = output_dir / "native-source-metadata.json"
        source_metadata.write_text(json.dumps(metadata), encoding="utf-8")
        imported = import_native_model(model_path, source_metadata, output_dir / "native")
        model_path = imported.artifact_path
        metadata = json.loads(imported.metadata_path.read_text(encoding="utf-8"))
        provenance["model_conversion"] = metadata.get("conversion_provenance", {})
    elif model_path.suffix.lower() in {".pt", ".pth", ".keras", ".h5"}:
        raise ValueError("Unrestricted native checkpoints are not accepted. Use approved weights-only imports or ONNX.")
    if dataset_path.suffix.lower() in {".pcap", ".pcapng"}:
        from core.pcap_ingestion import ingest_pcap

        if flow_labels_path is None:
            raise ValueError("PCAP assessment requires an explicit flow-label mapping CSV; labels are never inferred.")
        output_dir.mkdir(parents=True, exist_ok=True)
        source_hash = sha256_file(dataset_path)
        labels_hash = sha256_file(flow_labels_path)
        suffix = ".npz" if metadata.get("input_type") == "sequence" else ".csv"
        converted = ingest_pcap(dataset_path, output_dir / f"evaluation{suffix}", flow_labels_path, metadata)
        dataset_path = converted.output_path
        provenance["dataset_conversion"] = {
            "format": "offline_pcap", "schema": metadata.get("pcap_schema"),
            "source_sha256": source_hash, "labels_sha256": labels_hash,
            "rows": converted.row_count, "packets": converted.packet_count,
            "skipped_packets": converted.skipped_packets, "decrypts_tls": False,
        }
    if execution_device is not None:
        metadata["execution_device"] = execution_device
        metadata["execution_fallback"] = "cpu" if execution_device == "auto" or allow_cpu_fallback else "error"
    if allow_cpu_fallback:
        metadata["execution_fallback"] = "cpu"
    from core.execution_provider import execution_policy

    policy = execution_policy(metadata)
    if model_path.suffix.lower() != ".onnx" and policy["execution_device"] != "cpu":
        raise ValueError("Optional GPU execution is available only for ONNX models, not sklearn artifacts.")
    if policy["execution_device"] == "cuda" and policy["execution_fallback"] == "error":
        import onnxruntime

        if "CUDAExecutionProvider" not in onnxruntime.get_available_providers():
            raise ValueError("CUDA execution was requested, but this runtime has no CUDA provider. Select CPU/Auto or install a compatible optional GPU runtime.")
    return PreparedAssessment(model_path, dataset_path, metadata, provenance)
