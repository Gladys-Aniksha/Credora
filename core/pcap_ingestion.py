"""Bounded, offline classic-PCAP conversion. No sockets, execution, or decryption.

API: ingest_pcap(input_path, output_path, labels_path, schema, limits=Limits()).
The keyword metadata= is an alias for schema=; supply exactly one. Result exposes
output_path (and outputpath alias) as an absolute Path. Output location is entirely
caller-selected; callers should pass their owner-scoped destination.
``schema`` is a metadata dict (CLI: --schema JSON file), requiring class_labels,
target_column='label', and exactly one versioned pcap_schema:

* pcap_flow_v1: input_type='tabular', expected_features=list(FLOW_FEATURES).
  CSV columns are those eight features followed by label. flow_duration is ms;
  packet_count counts captured IP packets; sizes/bytes count complete IP datagram
  lengths (including IP/transport headers, excluding Ethernet/padding/FCS).
  sent is canonical endpoint A -> B, NOT initiator/client direction. avg_packet_size
  is total IP bytes / packet_count. iat_mean and iat_std are seconds, population
  statistics of successive flow packet gaps. For one packet both are zero.
  flow_bytes_per_second is total IP bytes / observed duration; zero for zero duration.
  These semantics must match model training; names alone do not imply CIC/Zeek parity.
* pcap_transport_bytes_v1: input_type='sequence', sequence_dtype='int64',
  vocab_size=257, pad_id=0, max_sequence_length in [1,8192]. NPZ contains only
  X:int64[flows,length], y:unicode[flows]. TCP/UDP payload bytes, in capture order
  within each bidirectional flow, become byte+1 tokens; trailing padding is zero.
  TCP retransmissions remain, directions are concatenated, and no stream reassembly
  occurs. Encrypted protocol bytes stay encrypted; no plaintext is inferred.
  A flow exceeding the declared length is rejected, never silently clipped.

Labels CSV must have exactly src_ip,src_port,dst_ip,dst_port,protocol,label columns
in that order. Protocol accepts tcp/udp or 6/17. Every observed flow needs an explicit
declared class label; reverse keys normalize identically; duplicate keys are errors.
Unused mappings are allowed. Endpoint order is (IP version, packed IP, port).
Output rows sort by normalized (protocol,A,B); result.flow_keys gives that order.
One tuple is one flow for the WHOLE capture, including reused connections; no
timeout splitting, packet extrapolation, checksums, or inferred missing traffic.

Accepts PCAP 2.4, both endian orders, micro/nanosecond timestamps, Ethernet with up
to two VLAN tags, IPv4/IPv6 TCP/UDP. Common IPv6 option/routing/AH headers are
bounded to eight; fragments (even atomic), ESP, jumbograms, pcapng, snaplen-truncated
records, and decreasing global timestamps are rejected. Non-IP Ethernet and other
IP protocols are skipped and counted. Capture must contain a supported flow.
Limits fail the whole conversion; no partial dataset is published. Only a packet,
flow aggregates and (sequence only) bounded token bytes are retained. Output is
atomically replaced after successful parsing/validation. NumPy is imported only
for sequence output; no additional dependencies or application config are needed.

CLI: python -m core.pcap_ingestion --input capture.pcap --output flows.csv
     --labels labels.csv --schema metadata.json
Minimal flow metadata in Python (serialize as JSON for the CLI)::

    {"pcap_schema": "pcap_flow_v1", "input_type": "tabular",
     "expected_features": list(FLOW_FEATURES), "target_column": "label",
     "class_labels": ["Normal", "VPN"]}

For byte metadata, replace pcap_schema/input_type with
pcap_transport_bytes_v1/sequence, remove expected_features, and add
sequence_dtype='int64', vocab_size=257, pad_id=0, max_sequence_length=8192.
Example label row after the LABEL_COLUMNS header:
10.0.0.1,1000,10.0.0.2,443,tcp,VPN
Default limits: 200 MiB capture, 1M packets, 100K flows/label rows, 256 KiB
packet/snaplen, 8 MiB labels, 64 MiB output/dense arrays. CLI exposes every
Limits field as a --max-... flag; these bound conversion, independently of
the downstream application's configurable dataset limits.
Use load_sequence_dataset(output, metadata) for NPZ or the existing canonical CSV
loader for CSV. Existing metadata needs the explicit pcap_schema and matching
semantics above; this converter never manufactures unsupported model features.
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass, field
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import struct
import tempfile
from typing import BinaryIO

FLOW_FEATURES = (
    "flow_duration", "packet_count", "avg_packet_size", "bytes_sent",
    "bytes_received", "iat_mean", "iat_std", "flow_bytes_per_second",
)
LABEL_COLUMNS = ("src_ip", "src_port", "dst_ip", "dst_port", "protocol", "label")
Endpoint = tuple[int, bytes, int]
FlowKey = tuple[int, Endpoint, Endpoint]


class PcapIngestionError(ValueError):
    """Malformed, unsupported, unlabelled, or over-budget offline input."""


@dataclass(frozen=True)
class Limits:
    max_capture_bytes: int = 200 * 1024 * 1024
    max_packets: int = 1_000_000
    max_flows: int = 100_000
    max_packet_bytes: int = 262_144
    max_labels_bytes: int = 8 * 1024 * 1024
    max_label_rows: int = 100_000
    max_dataset_bytes: int = 64 * 1024 * 1024

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in vars(self).values()):
            raise PcapIngestionError("All resource limits must be positive integers.")


@dataclass(frozen=True)
class IngestionResult:
    output_path: Path
    row_count: int
    packet_count: int
    skipped_packets: int
    flow_keys: tuple[FlowKey, ...]

    @property
    def outputpath(self) -> Path:
        """Compatibility alias for callers using the unseparated outputpath name."""
        return self.output_path


@dataclass
class _Flow:
    first: int
    last: int
    count: int = 0
    sent: int = 0
    received: int = 0
    gap_mean: float = 0.0
    gap_m2: float = 0.0
    payload: bytearray = field(default_factory=bytearray)

    def add(self, timestamp: int, size: int, forward: bool, payload: bytes,
            sequence_length: int):
        if self.count:
            gap = (timestamp - self.last) / 1_000_000_000
            delta = gap - self.gap_mean
            self.gap_mean += delta / self.count
            self.gap_m2 += delta * (gap - self.gap_mean)
        self.last = timestamp
        self.count += 1
        if forward:
            self.sent += size
        else:
            self.received += size
        if sequence_length:
            if len(self.payload) + len(payload) > sequence_length:
                raise PcapIngestionError("Flow payload exceeds max_sequence_length; no clipping allowed.")
            self.payload.extend(payload)

    def features(self):
        seconds = (self.last - self.first) / 1_000_000_000
        total = self.sent + self.received
        return (seconds * 1000, self.count, total / self.count, self.sent,
                self.received, self.gap_mean,
                math.sqrt(max(0, self.gap_m2 / (self.count - 1))) if self.count > 1 else 0,
                total / seconds if seconds else 0)


def _key(src: str, sport: int, dst: str, dport: int, protocol: int) -> FlowKey:
    a, b = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if a.version != b.version or not (0 <= sport <= 65535 and 0 <= dport <= 65535):
        raise PcapIngestionError("Invalid label flow endpoints.")
    endpoints = sorted(((a.version, a.packed, sport), (b.version, b.packed, dport)))
    return protocol, endpoints[0], endpoints[1]


def _read_bounded(path: Path, limit: int) -> bytes:
    if not path.is_file() or path.stat().st_size > limit:
        raise PcapIngestionError(f"Missing file or byte limit exceeded: {path}")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise PcapIngestionError(f"Byte limit exceeded: {path}")
    return data


def _schema(metadata: dict) -> tuple[list[str], int]:
    if not isinstance(metadata, dict):
        raise PcapIngestionError("Schema must be a metadata object.")
    classes = metadata.get("class_labels")
    if (not isinstance(classes, list) or not classes
            or any(not isinstance(x, str) or not x.strip() or len(x) > 256 for x in classes)
            or len(set(classes)) != len(classes)):
        raise PcapIngestionError("class_labels must be unique nonempty strings (at most 256 characters).")
    if metadata.get("target_column") != "label":
        raise PcapIngestionError("target_column must explicitly be 'label'.")
    name = metadata.get("pcap_schema")
    if name == "pcap_flow_v1":
        if metadata.get("input_type") != "tabular" or metadata.get("expected_features") != list(FLOW_FEATURES):
            raise PcapIngestionError("pcap_flow_v1 requires tabular input and exact ordered expected_features.")
        return classes, 0
    if name == "pcap_transport_bytes_v1":
        length = metadata.get("max_sequence_length")
        if (metadata.get("input_type") != "sequence" or metadata.get("sequence_dtype") != "int64"
                or type(metadata.get("vocab_size")) is not int or metadata["vocab_size"] != 257
                or type(metadata.get("pad_id")) is not int or metadata["pad_id"] != 0
                or type(length) is not int or not 1 <= length <= 8192):
            raise PcapIngestionError("Byte sequence schema requires int64, vocab_size=257, pad_id=0, length 1..8192.")
        if "expected_features" in metadata:
            raise PcapIngestionError("Byte sequence schema does not support tabular expected_features.")
        return classes, length
    raise PcapIngestionError("Unknown pcap_schema; no features can be inferred.")


def _labels(path: Path, classes: list[str], limits: Limits) -> dict[FlowKey, str]:
    data = _read_bounded(path, limits.max_labels_bytes).decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(data, newline=""), strict=True)
    if reader.fieldnames != list(LABEL_COLUMNS):
        raise PcapIngestionError("Labels CSV requires exact columns: " + ",".join(LABEL_COLUMNS))
    result = {}
    for index, row in enumerate(reader, 1):
        if index > limits.max_label_rows:
            raise PcapIngestionError("Label row cap exceeded.")
        if None in row or any(v is None for v in row.values()):
            raise PcapIngestionError("Malformed label row.")
        protocol = {"tcp": 6, "udp": 17, "6": 6, "17": 17}.get(row["protocol"].lower())
        if protocol is None or row["label"] not in classes:
            raise PcapIngestionError("Label row has unsupported protocol or undeclared class.")
        try:
            key = _key(row["src_ip"], int(row["src_port"]), row["dst_ip"], int(row["dst_port"]), protocol)
        except ValueError as exc:
            raise PcapIngestionError("Invalid label 5-tuple.") from exc
        if key in result:
            raise PcapIngestionError("Duplicate direction-normalized label flow key.")
        result[key] = row["label"]
    if not result:
        raise PcapIngestionError("Explicit flow label mappings are required.")
    return result


def _need(data: bytes, end: int):
    if end > len(data):
        raise PcapIngestionError("Truncated Ethernet/IP/transport header or payload.")


def _packet(frame: bytes):
    _need(frame, 14)
    kind = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    for _ in range(2):
        if kind not in (0x8100, 0x88A8):
            break
        _need(frame, offset + 4)
        kind = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if kind in (0x8100, 0x88A8):
        raise PcapIngestionError("VLAN nesting exceeds two tags.")
    ip = frame[offset:]
    if kind == 0x0800:
        _need(ip, 20)
        header = (ip[0] & 15) * 4
        size = struct.unpack_from("!H", ip, 2)[0]
        if ip[0] >> 4 != 4 or header < 20 or size < header:
            raise PcapIngestionError("Invalid IPv4 lengths/version.")
        _need(ip, size)
        if struct.unpack_from("!H", ip, 6)[0] & 0xBFFF:
            raise PcapIngestionError("IPv4 fragments/reserved flag are unsupported.")
        protocol, start = ip[9], header
        a, b = ip[12:16], ip[16:20]
        version = 4
    elif kind == 0x86DD:
        _need(ip, 40)
        plen = struct.unpack_from("!H", ip, 4)[0]
        if ip[0] >> 4 != 6 or not plen:
            raise PcapIngestionError("Invalid IPv6 version or unsupported jumbogram.")
        size, start, protocol = 40 + plen, 40, ip[6]
        _need(ip, size)
        a, b, version = ip[8:24], ip[24:40], 6
        extensions = 0
        while protocol in (0, 43, 60, 51):
            extensions += 1
            if extensions > 8 or start + 2 > size:
                raise PcapIngestionError("IPv6 extension chain exceeds bounds.")
            length = (ip[start + 1] + 2) * 4 if protocol == 51 else (ip[start + 1] + 1) * 8
            if length < (12 if protocol == 51 else 8) or start + length > size:
                raise PcapIngestionError("Invalid IPv6 extension length.")
            protocol, start = ip[start], start + length
    else:
        return None
    if protocol == 50 or (version == 6 and protocol == 44):
        raise PcapIngestionError("IP fragments/ESP are unsupported.")
    if protocol not in (6, 17):
        return None
    transport = ip[start:size]
    _need(transport, 20 if protocol == 6 else 8)
    sport, dport = struct.unpack_from("!HH", transport)
    if protocol == 6:
        header = (transport[12] >> 4) * 4
        if header < 20:
            raise PcapIngestionError("Invalid TCP data offset.")
        _need(transport, header)
    else:
        header = 8
        length = struct.unpack_from("!H", transport, 4)[0]
        if length != len(transport) or length < 8:
            raise PcapIngestionError("Invalid UDP length (jumbograms unsupported).")
    src, dst = (version, a, sport), (version, b, dport)
    key = protocol, min(src, dst), max(src, dst)
    return key, src == key[1], size, transport[header:]


def _records(stream: BinaryIO, limits: Limits):
    header = stream.read(24)
    if header[:4] == b"\x0a\x0d\x0d\x0a":
        raise PcapIngestionError("pcapng is unsupported; convert explicitly to classic PCAP.")
    variants = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
                b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
    if len(header) != 24 or header[:4] not in variants:
        raise PcapIngestionError("Invalid/truncated classic PCAP header.")
    endian, multiplier = variants[header[:4]]
    major, minor, zone, accuracy, snaplen, network = struct.unpack(endian + "HHiIII", header[4:])
    if (major, minor) != (2, 4) or network != 1:
        raise PcapIngestionError("Only PCAP 2.4 Ethernet (linktype 1 without flags) is supported.")
    if not 1 <= snaplen <= limits.max_packet_bytes:
        raise PcapIngestionError("PCAP snaplen exceeds packet bounds or is zero.")
    used, count, previous = 24, 0, -1
    if used > limits.max_capture_bytes:
        raise PcapIngestionError("Capture byte cap exceeded.")
    while True:
        record = stream.read(16)
        if not record:
            return
        count += 1
        if len(record) != 16:
            raise PcapIngestionError("Truncated PCAP record header.")
        if count > limits.max_packets:
            raise PcapIngestionError("Packet cap exceeded.")
        seconds, fraction, captured, original = struct.unpack(endian + "IIII", record)
        if fraction >= 1_000_000_000 // multiplier:
            raise PcapIngestionError("Invalid PCAP timestamp fraction.")
        timestamp = seconds * 1_000_000_000 + fraction * multiplier
        if timestamp < previous:
            raise PcapIngestionError("Decreasing capture timestamps are unsupported.")
        previous = timestamp
        if not captured or captured != original or captured > snaplen or captured > limits.max_packet_bytes:
            raise PcapIngestionError("Invalid, truncated, or over-budget PCAP packet length.")
        used += 16 + captured
        if used > limits.max_capture_bytes:
            raise PcapIngestionError("Capture byte cap exceeded.")
        frame = stream.read(captured)
        if len(frame) != captured:
            raise PcapIngestionError("Truncated PCAP packet body.")
        yield timestamp, frame


def ingest_pcap(input_path: str | Path, output_path: str | Path,
                labels_path: str | Path, schema: dict | None = None,
                limits: Limits = Limits(), *, metadata: dict | None = None) -> IngestionResult:
    """Convert a complete bounded capture or raise PcapIngestionError without publishing output."""
    temporary = None
    try:
        if schema is not None and metadata is not None:
            raise PcapIngestionError("Supply exactly one of schema or metadata.")
        schema = metadata if metadata is not None else schema
        classes, length = _schema(schema)
        source, target, labels_file = Path(input_path), Path(output_path), Path(labels_path)
        if target.resolve() in (source.resolve(), labels_file.resolve()):
            raise PcapIngestionError("Output must not overwrite input capture or label mappings.")
        if target.suffix.lower() != (".npz" if length else ".csv"):
            raise PcapIngestionError("Output suffix must match schema (.npz or .csv).")
        labels = _labels(labels_file, classes, limits)
        if not source.is_file() or source.stat().st_size > limits.max_capture_bytes:
            raise PcapIngestionError("Missing capture or capture byte cap exceeded.")
        flows: dict[FlowKey, _Flow] = {}
        count = skipped = dataset_bytes = 0
        with source.open("rb") as stream:
            for timestamp, frame in _records(stream, limits):
                count += 1
                packet = _packet(frame)
                if packet is None:
                    skipped += 1
                    continue
                key, forward, size, payload = packet
                if key not in labels:
                    raise PcapIngestionError(f"Missing explicit label for flow {key!r}.")
                if key not in flows:
                    if len(flows) >= limits.max_flows:
                        raise PcapIngestionError("Flow cap exceeded.")
                    # Reserve dense X plus worst-case Unicode y before retaining any payload.
                    dataset_bytes += length * 8 + len(labels[key]) * 4 if length else 0
                    if dataset_bytes > limits.max_dataset_bytes:
                        raise PcapIngestionError("Sequence dataset byte cap exceeded.")
                    flows[key] = _Flow(timestamp, timestamp)
                flows[key].add(timestamp, size, forward, payload, length)
        if not flows:
            raise PcapIngestionError("Capture has no supported TCP/UDP flows.")
        keys = tuple(sorted(flows))
        ordered_labels = [labels[key] for key in keys]
        if length and len(keys) * (length * 8 + max(map(len, ordered_labels)) * 4) > limits.max_dataset_bytes:
            raise PcapIngestionError("Sequence dataset byte cap exceeded (dense label width).")
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=".pcap-", delete=False) as temp:
            temporary = Path(temp.name)
        if length:
            import numpy as np
            features = np.zeros((len(keys), length), dtype=np.int64)
            for index, key in enumerate(keys):
                payload = flows[key].payload
                features[index, :len(payload)] = np.frombuffer(payload, dtype=np.uint8).astype(np.int64) + 1
            with temporary.open("wb") as out:
                np.savez(out, X=features, y=np.asarray(ordered_labels, dtype=str))
        else:
            with temporary.open("w", encoding="utf-8", newline="") as out:
                writer = csv.writer(out)
                writer.writerow((*FLOW_FEATURES, "label"))
                for key in keys:
                    writer.writerow((*flows[key].features(), labels[key]))
                    if out.tell() > limits.max_dataset_bytes:
                        raise PcapIngestionError("Output dataset byte cap exceeded.")
        if temporary.stat().st_size > limits.max_dataset_bytes:
            raise PcapIngestionError("Output dataset byte cap exceeded (including container overhead).")
        os.replace(temporary, target)
        return IngestionResult(target.resolve(), len(keys), count, skipped, keys)
    except PcapIngestionError:
        raise
    except (OSError, ValueError, csv.Error, OverflowError) as exc:
        raise PcapIngestionError(f"PCAP conversion failed: {exc}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ("input", "output", "labels", "schema"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name, default in vars(Limits()).items():
        parser.add_argument("--" + name.replace("_", "-"), type=int, default=default)
    args = parser.parse_args(argv)
    try:
        if args.output.resolve() == args.schema.resolve():
            raise PcapIngestionError("Output must not overwrite schema metadata.")
        schema = json.loads(_read_bounded(args.schema, 64 * 1024).decode("utf-8-sig"))
        limits = Limits(**{name: getattr(args, name) for name in vars(Limits())})
        result = ingest_pcap(args.input, args.output, args.labels, schema, limits)
    except (PcapIngestionError, ValueError, OSError) as exc:
        parser.exit(2, f"PCAP conversion failed: {exc}\n")
    print(json.dumps({"output_path": str(result.output_path), "row_count": result.row_count,
                      "packet_count": result.packet_count, "skipped_packets": result.skipped_packets}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
