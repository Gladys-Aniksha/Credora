from __future__ import annotations

import csv
from dataclasses import replace
import ipaddress
import json
import struct
import subprocess
import sys

import numpy as np
import pytest

from core.pcap_ingestion import FLOW_FEATURES, LABEL_COLUMNS, Limits, PcapIngestionError, ingest_pcap


def metadata(sequence=False, length=8):
    result = {"pcap_schema": "pcap_flow_v1", "input_type": "tabular",
              "expected_features": list(FLOW_FEATURES), "target_column": "label",
              "class_labels": ["Normal", "VPN"]}
    if sequence:
        result.pop("expected_features")
        result.update(pcap_schema="pcap_transport_bytes_v1", input_type="sequence",
                      sequence_dtype="int64", vocab_size=257, pad_id=0, max_sequence_length=length)
    return result


def packet(src="10.0.0.1", dst="10.0.0.2", sport=1000, dport=443,
           protocol=6, payload=b"\x16\x03", vlan=0, extension=False):
    if protocol == 6:
        transport = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x10, 1024, 0, 0) + payload
    elif protocol == 17:
        transport = struct.pack("!HHHH", sport, dport, len(payload) + 8, 0) + payload
    else:
        transport = payload
    source, dest = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if source.version == 4:
        network = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 1, 0x4000,
                              64, protocol, 0, source.packed, dest.packed) + transport
        kind = 0x0800
    else:
        if extension:
            transport = bytes([protocol, 0]) + b"\x00" * 6 + transport
        network = struct.pack("!IHBB16s16s", 6 << 28, len(transport), 0 if extension else protocol,
                              64, source.packed, dest.packed) + transport
        kind = 0x86DD
    tags = b""
    for _ in range(vlan):
        tags = struct.pack("!HH", 1, kind) + tags
        kind = 0x8100
    return b"\x00" * 12 + struct.pack("!H", kind) + tags + network


def capture(records, endian="<", nano=False, snaplen=65535, network=1):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    data = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, network)
    for timestamp, frame in records:
        unit = 1_000_000_000 if nano else 1_000_000
        seconds, fraction = divmod(timestamp, unit)
        data += struct.pack(endian + "IIII", seconds, fraction, len(frame), len(frame)) + frame
    return data


def inputs(tmp_path, frames=None, rows=None, raw=None):
    source, labels = tmp_path / "capture.pcap", tmp_path / "labels.csv"
    source.write_bytes(raw if raw is not None else capture(frames or [(0, packet())]))
    with labels.open("w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(LABEL_COLUMNS)
        writer.writerows(rows if rows is not None else [["10.0.0.1", 1000, "10.0.0.2", 443, "tcp", "VPN"]])
    return source, labels


def convert(tmp_path, source, labels, schema=None, limits=Limits()):
    schema = metadata() if schema is None else schema
    output = tmp_path / ("dataset.npz" if schema.get("input_type") == "sequence" else "dataset.csv")
    return ingest_pcap(source, output, labels, schema, limits)


def test_bidirectional_statistics_use_actual_ip_bytes_and_gaps(tmp_path):
    frames = [(0, packet(payload=b"ab")),
              (1_000_000, packet(src="10.0.0.2", dst="10.0.0.1", sport=443, dport=1000, payload=b"cdef")),
              (3_000_000, packet(payload=b""))]
    source, labels = inputs(tmp_path, frames)
    result = convert(tmp_path, source, labels)
    with result.output_path.open(newline="") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)
        assert reader.fieldnames == [*FLOW_FEATURES, "label"]
    row = rows[0]
    assert row["label"] == "VPN"
    expected = (3000, 3, 42, 82, 44, 1.5, 0.5, 42)
    assert [float(row[name]) for name in FLOW_FEATURES] == pytest.approx(expected)
    assert (result.row_count, result.packet_count, result.skipped_packets) == (1, 3, 0)


@pytest.mark.parametrize("endian,nano", [("<", False), (">", False), ("<", True), (">", True)])
def test_pcap_byte_order_resolution_and_zero_duration(tmp_path, endian, nano):
    source, labels = inputs(tmp_path, raw=capture([(0, packet()), (1, packet())], endian, nano))
    result = convert(tmp_path, source, labels)
    row = next(csv.DictReader(result.output_path.open()))
    assert float(row["flow_duration"]) == pytest.approx(0.000001 if nano else 0.001)
    source.write_bytes(capture([(0, packet())], endian, nano))
    result = convert(tmp_path, source, labels)
    row = next(csv.DictReader(result.output_path.open()))
    assert [float(row[k]) for k in ("flow_duration", "iat_mean", "iat_std", "flow_bytes_per_second")] == [0] * 4


def test_sequence_keeps_encrypted_bytes_reverse_direction_and_padding(tmp_path, monkeypatch):
    source, labels = inputs(tmp_path, [(0, packet(payload=b"\x00\xff")),
        (1, packet(src="10.0.0.2", dst="10.0.0.1", sport=443, dport=1000, payload=b"\x16\x03"))])
    schema = metadata(True)
    result = convert(tmp_path, source, labels, schema)
    with np.load(result.output_path, allow_pickle=False) as data:
        assert set(data.files) == {"X", "y"}
        assert data["X"].dtype == np.int64
        assert data["X"].tolist() == [[1, 256, 23, 4, 0, 0, 0, 0]]
        assert data["y"].tolist() == ["VPN"]
    monkeypatch.setenv("CREDORA_API_KEY", "pcap-test-only")
    from core.sequence_data import load_sequence_dataset
    loaded = load_sequence_dataset(result.output_path, schema)
    assert loaded.features.shape == (1, 8)


@pytest.mark.parametrize("vlan", [0, 1, 2])
@pytest.mark.parametrize("protocol", [6, 17])
def test_ipv6_extensions_and_vlan(tmp_path, vlan, protocol):
    frame = packet(src="2001:db8::2", dst="2001:db8::1", protocol=protocol, vlan=vlan, extension=True)
    source, labels = inputs(tmp_path, [(0, frame)],
        rows=[["2001:db8::1", 443, "2001:0db8::2", 1000, str(protocol), "Normal"]])
    result = convert(tmp_path, source, labels)
    row = next(csv.DictReader(result.output_path.open()))
    assert float(row["bytes_sent"]) == 0
    assert float(row["bytes_received"]) == 40 + 8 + (20 if protocol == 6 else 8) + 2


def test_sorted_flow_order_and_explicit_skips(tmp_path):
    frames = [(0, packet(protocol=17)), (1, b"\x00" * 12 + b"\x08\x06"),
              (2, packet(protocol=1)), (3, packet())]
    source, labels = inputs(tmp_path, frames, rows=[
        ["10.0.0.2", 443, "10.0.0.1", 1000, "udp", "Normal"],
        ["10.0.0.1", 1000, "10.0.0.2", 443, "tcp", "VPN"]])
    result = convert(tmp_path, source, labels, metadata(True))
    assert result.skipped_packets == 2
    assert [key[0] for key in result.flow_keys] == [6, 17]
    with np.load(result.output_path, allow_pickle=False) as data:
        assert data["y"].tolist() == ["VPN", "Normal"]


@pytest.mark.parametrize("rows,match", [
    ([], "required"),
    ([["10.0.0.1", 7, "10.0.0.2", 443, "tcp", "VPN"]], "Missing explicit"),
    ([["10.0.0.1", 1000, "10.0.0.2", 443, "tcp", "guess"]], "undeclared"),
    ([["10.0.0.1", -1, "10.0.0.2", 443, "tcp", "VPN"]], "5-tuple"),
    ([["bad", 1000, "10.0.0.2", 443, "tcp", "VPN"]], "5-tuple"),
    ([["10.0.0.1", 1000, "10.0.0.2", 443, "icmp", "VPN"]], "protocol"),
    ([["10.0.0.1", 1000, "10.0.0.2", 443, "tcp", "VPN"],
      ["10.0.0.2", 443, "10.0.0.1", 1000, "6", "Normal"]], "Duplicate"),
])
def test_invalid_or_missing_labels_fail(tmp_path, rows, match):
    source, labels = inputs(tmp_path, rows=rows)
    with pytest.raises(PcapIngestionError, match=match):
        convert(tmp_path, source, labels)
    assert not (tmp_path / "dataset.csv").exists()


@pytest.mark.parametrize("change", [
    {"pcap_schema": "unknown"}, {"expected_features": ["fake"]},
    {"expected_features": list(reversed(FLOW_FEATURES))}, {"input_type": "sequence"},
    {"target_column": "class"}, {"class_labels": ["VPN", "VPN"]},
])
def test_unknown_feature_contract_rejected(tmp_path, change):
    source, labels = inputs(tmp_path)
    with pytest.raises(PcapIngestionError):
        convert(tmp_path, source, labels, {**metadata(), **change})


@pytest.mark.parametrize("change", [{"vocab_size": 256}, {"pad_id": 1},
    {"sequence_dtype": "float32"}, {"max_sequence_length": 8193}, {"max_sequence_length": True},
    {"expected_features": ["fake"]}])
def test_sequence_contract_is_exact(tmp_path, change):
    source, labels = inputs(tmp_path)
    with pytest.raises(PcapIngestionError):
        convert(tmp_path, source, labels, {**metadata(True), **change})


def corrupt_packet(kind):
    data = bytearray(packet())
    if kind == "ethernet":
        return bytes(data[:13])
    if kind == "ip_short":
        return bytes(data[:25])
    if kind == "ip_version":
        data[14] = 0x65
    if kind == "ip_length":
        data[16:18] = b"\x00\x10"
    if kind == "ip_fragment":
        data[20:22] = b"\x20\x00"
    if kind == "ip_payload_short":
        return bytes(data[:-1])
    if kind == "tcp_offset":
        data[46] = 0x40
    if kind == "tcp_short":
        data[46] = 0xF0
    if kind == "udp_length":
        data = bytearray(packet(protocol=17))
        data[38:40] = b"\x00\x08"
    if kind == "ipv6_fragment":
        data = bytearray(packet(src="::1", dst="::2"))
        data[20] = 44
    if kind == "ipv6_ext_length":
        data = bytearray(packet(src="::1", dst="::2", extension=True))
        data[55] = 255
    if kind == "vlan_depth":
        return packet(vlan=3)
    return bytes(data)


@pytest.mark.parametrize("kind", ["ethernet", "ip_short", "ip_version", "ip_length",
    "ip_fragment", "ip_payload_short", "tcp_offset", "tcp_short", "udp_length",
    "ipv6_fragment", "ipv6_ext_length", "vlan_depth"])
def test_malformed_packets_never_publish_partial_output(tmp_path, kind):
    source, labels = inputs(tmp_path, [(0, packet()), (1, corrupt_packet(kind))])
    output = tmp_path / "dataset.csv"
    output.write_text("previous-good-dataset", encoding="utf-8")
    with pytest.raises(PcapIngestionError):
        convert(tmp_path, source, labels)
    assert output.read_text() == "previous-good-dataset"
    assert not list(tmp_path.glob(".pcap-*"))


@pytest.mark.parametrize("kind", ["pcapng", "header", "record", "body", "snap_truncated",
    "fraction", "timestamps", "linktype", "version", "snaplen"])
def test_invalid_capture_containers(tmp_path, kind):
    data = bytearray(capture([(0, packet())]))
    if kind == "pcapng":
        data[:4] = b"\x0a\x0d\x0d\x0a"
    elif kind == "header":
        data = data[:23]
    elif kind == "record":
        data = data[:39]
    elif kind == "body":
        data = data[:-1]
    elif kind == "snap_truncated":
        struct.pack_into("<I", data, 36, len(packet()) + 1)
    elif kind == "fraction":
        struct.pack_into("<I", data, 28, 1_000_000)
    elif kind == "timestamps":
        data = capture([(1, packet()), (0, packet())])
    elif kind == "linktype":
        struct.pack_into("<I", data, 20, 101)
    elif kind == "version":
        struct.pack_into("<H", data, 4, 3)
    elif kind == "snaplen":
        struct.pack_into("<I", data, 16, 0)
    source, labels = inputs(tmp_path, raw=bytes(data))
    with pytest.raises(PcapIngestionError):
        convert(tmp_path, source, labels)


@pytest.mark.parametrize("limit,value", [("max_capture_bytes", 50), ("max_packets", 1),
    ("max_flows", 1), ("max_packet_bytes", 40), ("max_labels_bytes", 10),
    ("max_label_rows", 1), ("max_dataset_bytes", 10)])
def test_resource_caps(tmp_path, limit, value):
    source, labels = inputs(tmp_path, [(0, packet()), (1, packet(protocol=17))], rows=[
        ["10.0.0.1", 1000, "10.0.0.2", 443, "tcp", "VPN"],
        ["10.0.0.1", 1000, "10.0.0.2", 443, "udp", "Normal"]])
    with pytest.raises(PcapIngestionError):
        convert(tmp_path, source, labels, limits=replace(Limits(), **{limit: value}))
    assert not (tmp_path / "dataset.csv").exists()


def test_sequence_overflow_and_budget_do_not_clip(tmp_path):
    source, labels = inputs(tmp_path)
    with pytest.raises(PcapIngestionError, match="no clipping"):
        convert(tmp_path, source, labels, metadata(True, 1))
    with pytest.raises(PcapIngestionError, match="byte cap"):
        convert(tmp_path, source, labels, metadata(True), replace(Limits(), max_dataset_bytes=4))
    assert not (tmp_path / "dataset.npz").exists()


def test_empty_or_unsupported_only_capture_fails(tmp_path):
    for raw in [capture([]), capture([(0, packet(protocol=1))])]:
        source, labels = inputs(tmp_path, raw=raw)
        with pytest.raises(PcapIngestionError, match="no supported"):
            convert(tmp_path, source, labels)


def test_cli_and_schema_is_required(tmp_path):
    source, labels = inputs(tmp_path)
    schema = tmp_path / "metadata.json"
    schema.write_text(json.dumps(metadata()), encoding="utf-8")
    command = [sys.executable, "-m", "core.pcap_ingestion", "--input", str(source),
               "--output", str(tmp_path / "cli.csv"), "--labels", str(labels)]
    missing = subprocess.run(command, capture_output=True, text=True)
    assert missing.returncode == 2
    run = subprocess.run(command + ["--schema", str(schema)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)["row_count"] == 1
    run = subprocess.run(command + ["--schema", str(schema), "--max-packets", "0"], capture_output=True, text=True)
    assert run.returncode == 2


def test_input_collision_and_invalid_labels_encoding(tmp_path):
    source, labels = inputs(tmp_path)
    original = labels.read_bytes()
    with pytest.raises(PcapIngestionError, match="overwrite"):
        ingest_pcap(source, labels, labels, metadata())
    assert labels.read_bytes() == original
    labels.write_bytes(b"\xff")
    with pytest.raises(PcapIngestionError):
        convert(tmp_path, source, labels)


def test_csv_integrates_with_existing_canonical_loader(tmp_path):
    import pandas as pd
    from modules.phase3_operations.m7_flow_ingestion.collector import ingest_flow_file

    source, labels = inputs(tmp_path)
    result = convert(tmp_path, source, labels)
    forwarded = tmp_path / "canonical.csv"
    contract = ingest_flow_file(result.output_path, forwarded, "csv")
    assert contract.source_format == "canonical"
    pd.testing.assert_frame_equal(pd.read_csv(result.output_path), pd.read_csv(forwarded))


def test_ipv4_udp_options_and_ethernet_padding_are_not_payload(tmp_path):
    frame = bytearray(packet(protocol=17, payload=b"\x00\xff"))
    frame[14] = 0x46
    struct.pack_into("!H", frame, 16, 24 + 8 + 2)
    frame[34:34] = b"\x01" * 4
    frame += b"\xff" * 20  # Ethernet padding outside the declared IP datagram.
    source, labels = inputs(tmp_path, [(0, bytes(frame))], rows=[
        ["10.0.0.1", 1000, "10.0.0.2", 443, "udp", "Normal"]])
    result = convert(tmp_path, source, labels, metadata(True, 2))
    with np.load(result.output_path, allow_pickle=False) as data:
        assert data["X"].tolist() == [[1, 256]]
    result = convert(tmp_path, source, labels)
    row = next(csv.DictReader(result.output_path.open()))
    assert float(row["avg_packet_size"]) == 34


def test_exact_limits_and_empty_transport_are_valid(tmp_path):
    source, labels = inputs(tmp_path, [(0, packet(payload=b""))])
    limits = replace(Limits(), max_capture_bytes=source.stat().st_size,
                     max_labels_bytes=labels.stat().st_size, max_label_rows=1,
                     max_packets=1, max_flows=1)
    result = convert(tmp_path, source, labels, metadata(True, 1), limits)
    with np.load(result.output_path, allow_pickle=False) as data:
        assert data["X"].tolist() == [[0]]


def test_oversized_record_is_rejected_before_body_read(tmp_path):
    raw = capture([]) + struct.pack("<IIII", 0, 0, 0xFFFFFFFF, 0xFFFFFFFF)
    source, labels = inputs(tmp_path, raw=raw)
    with pytest.raises(PcapIngestionError, match="packet length"):
        convert(tmp_path, source, labels)


def test_ipv6_extension_count_is_bounded(tmp_path):
    frame = bytearray(packet(src="::1", dst="::2", extension=True))
    frame[54:54] = (b"\x00" * 8) * 8
    struct.pack_into("!H", frame, 18, len(frame) - 54)
    source, labels = inputs(tmp_path, [(0, bytes(frame))])
    with pytest.raises(PcapIngestionError, match="extension chain"):
        convert(tmp_path, source, labels)


@pytest.mark.parametrize("bad", [b"src_ip,label\nx,y\n", b"src_ip,src_port,dst_ip,dst_port,protocol,label\nx,1\n"])
def test_bad_label_csv_structure(tmp_path, bad):
    source, labels = inputs(tmp_path)
    labels.write_bytes(bad)
    with pytest.raises(PcapIngestionError):
        convert(tmp_path, source, labels)


def test_parent_metadata_and_outputpath_contract(tmp_path):
    source, labels = inputs(tmp_path)
    output = tmp_path / "owner-42" / "scan-7" / "dataset.csv"
    result = ingest_pcap(source, output, labels_path=labels, metadata=metadata())
    assert result.output_path == output.resolve()
    assert result.outputpath == result.output_path
    assert result.outputpath.is_file()
    with pytest.raises(PcapIngestionError, match="exactly one"):
        ingest_pcap(source, output, labels, schema=metadata(), metadata=metadata())
    with pytest.raises(PcapIngestionError, match="metadata object"):
        ingest_pcap(source, output, labels)
