from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

import numpy as np
import pandas as pd

CANONICAL_FEATURES = [
    "flow_duration",
    "packet_count",
    "avg_packet_size",
    "bytes_sent",
    "bytes_received",
    "iat_mean",
    "iat_std",
    "flow_bytes_per_second",
]


@dataclass(frozen=True)
class FlowIngestionResult:
    source_format: str
    source_path: Path
    output_path: Path
    row_count: int
    columns: list[str]


def _normalized(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


def _column_map(frame: pd.DataFrame) -> dict[str, str]:
    return {_normalized(column): column for column in frame.columns}


def _series(frame: pd.DataFrame, columns: dict[str, str], *aliases: str, default: float = 0.0) -> pd.Series:
    for alias in aliases:
        source = columns.get(_normalized(alias))
        if source is not None:
            return pd.to_numeric(frame[source], errors="coerce").fillna(default)
    return pd.Series(default, index=frame.index, dtype=float)


def _read_zeek(path: Path) -> pd.DataFrame:
    fields: list[str] | None = None
    rows: list[list[str]] = []
    separator = "\t"
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw_line.startswith("#separator"):
            encoded = raw_line.split(" ", 1)[-1].strip()
            separator = bytes(encoded, "utf-8").decode("unicode_escape")
        elif raw_line.startswith("#fields"):
            fields = raw_line.split(separator)[1:]
        elif raw_line and not raw_line.startswith("#"):
            rows.append(raw_line.split(separator))
    if not fields:
        raise ValueError("Zeek log is missing a #fields header.")
    normalized_rows = [row[: len(fields)] + [""] * max(0, len(fields) - len(row)) for row in rows]
    return pd.DataFrame(normalized_rows, columns=fields)


def _from_zeek(frame: pd.DataFrame) -> pd.DataFrame:
    columns = _column_map(frame)
    duration_seconds = _series(frame, columns, "duration")
    orig_packets = _series(frame, columns, "orig_pkts")
    resp_packets = _series(frame, columns, "resp_pkts")
    sent = _series(frame, columns, "orig_bytes")
    received = _series(frame, columns, "resp_bytes")
    packets = orig_packets + resp_packets
    total_bytes = sent + received
    safe_duration = duration_seconds.replace(0, np.nan)
    output = pd.DataFrame(index=frame.index)
    output["flow_duration"] = duration_seconds * 1000.0
    output["packet_count"] = packets
    output["avg_packet_size"] = (total_bytes / packets.replace(0, np.nan)).fillna(0.0)
    output["bytes_sent"] = sent
    output["bytes_received"] = received
    output["iat_mean"] = (duration_seconds / (packets - 1).clip(lower=1)).fillna(0.0)
    output["iat_std"] = 0.0
    output["flow_bytes_per_second"] = (total_bytes / safe_duration).fillna(0.0)
    return output


def _from_cicflowmeter(frame: pd.DataFrame) -> pd.DataFrame:
    columns = _column_map(frame)
    sent = _series(frame, columns, "Total Length of Fwd Packets", "TotLen Fwd Pkts", "bytes_sent")
    received = _series(frame, columns, "Total Length of Bwd Packets", "TotLen Bwd Pkts", "bytes_received")
    fwd_packets = _series(frame, columns, "Total Fwd Packets", "Tot Fwd Pkts")
    bwd_packets = _series(frame, columns, "Total Backward Packets", "Tot Bwd Pkts")
    packets = fwd_packets + bwd_packets
    duration_microseconds = _series(frame, columns, "Flow Duration", "flow_duration")
    avg_size = _series(frame, columns, "Average Packet Size", "Pkt Size Avg")
    calculated_avg = ((sent + received) / packets.replace(0, np.nan)).fillna(0.0)
    output = pd.DataFrame(index=frame.index)
    output["flow_duration"] = duration_microseconds / 1000.0
    output["packet_count"] = packets
    output["avg_packet_size"] = avg_size.where(avg_size > 0, calculated_avg)
    output["bytes_sent"] = sent
    output["bytes_received"] = received
    output["iat_mean"] = _series(frame, columns, "Flow IAT Mean") / 1_000_000.0
    output["iat_std"] = _series(frame, columns, "Flow IAT Std") / 1_000_000.0
    output["flow_bytes_per_second"] = _series(frame, columns, "Flow Bytes/s", "Flow Byts/s")
    label_column = columns.get("label")
    if label_column:
        output["label"] = frame[label_column].astype(str).str.strip()
    return output


def _from_canonical(frame: pd.DataFrame) -> pd.DataFrame:
    missing = [column for column in CANONICAL_FEATURES if column not in frame.columns]
    if missing:
        raise ValueError(f"Canonical CSV is missing feature(s): {', '.join(missing)}")
    columns = CANONICAL_FEATURES + (["label"] if "label" in frame.columns else [])
    output = frame[columns].copy()
    for column in CANONICAL_FEATURES:
        output[column] = pd.to_numeric(output[column], errors="coerce").fillna(0.0)
    return output


def ingest_flow_file(
    source_path: str | Path,
    output_path: str | Path,
    source_format: str = "auto",
    default_label: str | None = None,
) -> FlowIngestionResult:
    source = Path(source_path)
    if not source.is_file():
        raise FileNotFoundError(f"Captured flow file not found: {source}")
    requested = source_format.lower()
    if requested == "auto":
        requested = "zeek" if source.suffix.lower() in {".log", ".zeek"} else "csv"

    if requested == "zeek":
        canonical = _from_zeek(_read_zeek(source))
        detected = "zeek"
    else:
        frame = pd.read_csv(source)
        if set(CANONICAL_FEATURES).issubset(frame.columns):
            canonical = _from_canonical(frame)
            detected = "canonical"
        else:
            canonical = _from_cicflowmeter(frame)
            detected = "cicflowmeter"

    canonical = canonical.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    if default_label is not None and "label" not in canonical.columns:
        canonical["label"] = default_label
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    canonical.to_csv(target, index=False)
    return FlowIngestionResult(detected, source.resolve(), target.resolve(), len(canonical), canonical.columns.tolist())
