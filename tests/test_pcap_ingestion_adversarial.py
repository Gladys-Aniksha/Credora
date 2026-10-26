"""Adversarial regression checks for the documented PCAP rejection contract."""

import json
import re
import struct
import subprocess
import sys
from pathlib import Path
from time import perf_counter

import pytest
from test_pcap_ingestion import capture, inputs, metadata, packet

from core.pcap_ingestion import PcapIngestionError, ingest_pcap

CALL_BUDGET_SECONDS = 5
SUITE_BUDGET_SECONDS = 60
PREVIOUS_OUTPUT = b"previous validated dataset\n"
REJECT_WORKER = """
import json
import sys
from core.pcap_ingestion import Limits, PcapIngestionError, ingest_pcap

source, output, labels, schema, limits = sys.argv[1:]
try:
    result = ingest_pcap(source, output, labels, json.loads(schema), Limits(**json.loads(limits)))
except PcapIngestionError as exc:
    print(str(exc))
else:
    raise AssertionError(f"Malformed or over-budget capture accepted: {result}")
"""


@pytest.fixture(scope="module", autouse=True)
def adversarial_suite_budget():
    started = perf_counter()
    yield
    elapsed = perf_counter() - started
    assert elapsed < SUITE_BUDGET_SECONDS, f"Adversarial suite exceeded budget: {elapsed:.2f}s"


def reject(tmp_path, source, labels, match, *, limits=None, schema=None):
    """A subprocess deadline also bounds regressions that never return an error."""
    schema = metadata() if schema is None else schema
    output = tmp_path / ("dataset.npz" if schema["input_type"] == "sequence" else "dataset.csv")
    output.write_bytes(PREVIOUS_OUTPUT)
    started = perf_counter()
    try:
        result = subprocess.run(
            [sys.executable, "-c", REJECT_WORKER, str(source), str(output), str(labels),
             json.dumps(schema), json.dumps(limits or {})],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
            timeout=CALL_BUDGET_SECONDS, check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"PCAP rejection exceeded {CALL_BUDGET_SECONDS}s deadline")
    elapsed = perf_counter() - started
    assert elapsed < CALL_BUDGET_SECONDS, f"Rejection took {elapsed:.2f}s"
    assert result.returncode == 0, result.stdout + result.stderr
    assert re.search(match, result.stdout, re.IGNORECASE), result.stdout
    assert output.read_bytes() == PREVIOUS_OUTPUT
    assert not list(tmp_path.glob(".pcap-*"))


@pytest.mark.parametrize("ip_version", [6, 4])
def test_esp_in_mixed_capture_rejects_whole_conversion(tmp_path, ip_version):
    # A supported packet prevents the no-supported-flows check masking an ESP skip.
    endpoints = (
        {"src": "2001:db8::1", "dst": "2001:db8::2"}
        if ip_version == 6 else {}
    )
    frames = [
        (0, packet()),
        (1, packet(protocol=50, payload=b"\x00" * 16, **endpoints)),
    ]
    source, labels = inputs(tmp_path, frames=frames)
    output = tmp_path / "dataset.csv"
    previous = b"previous validated dataset\n"
    output.write_bytes(previous)

    with pytest.raises(PcapIngestionError, match="ESP"):
        result = ingest_pcap(source, output, labels, metadata())
        pytest.fail(
            f"IPv{ip_version} ESP was accepted: packets={result.packet_count}, "
            f"skipped={result.skipped_packets}, rows={result.row_count}, "
            f"previous_output_preserved={output.read_bytes() == previous}"
        )

    assert output.read_bytes() == previous


@pytest.mark.parametrize("offset", [0, 1, 3, 4, 12, 23])
def test_truncated_global_headers(tmp_path, offset):
    source, labels = inputs(tmp_path, raw=capture([(0, packet())])[:offset])
    reject(tmp_path, source, labels, "Invalid/truncated classic PCAP header")


@pytest.mark.parametrize("offset", [1, 4, 8, 15])
def test_truncated_record_after_supported_packet(tmp_path, offset):
    raw = capture([(0, packet())]) + struct.pack("<IIII", 0, 1, len(packet()), len(packet()))[:offset]
    source, labels = inputs(tmp_path, raw=raw)
    reject(tmp_path, source, labels, "Truncated PCAP record header")


@pytest.mark.parametrize("offset", [0, 1, 13, 14, 33, 55])
def test_truncated_payload_after_supported_packet(tmp_path, offset):
    frame = packet()
    assert offset < len(frame)
    raw = capture([(0, frame)]) + struct.pack("<IIII", 0, 1, len(frame), len(frame)) + frame[:offset]
    source, labels = inputs(tmp_path, raw=raw)
    reject(tmp_path, source, labels, "Truncated PCAP packet body")


@pytest.mark.parametrize("captured_delta,original_delta", [(1, 0), (-1, 0), (0, 1), (0, -1)])
def test_mismatched_record_lengths(tmp_path, captured_delta, original_delta):
    frame = packet()
    raw = capture([(0, frame)]) + struct.pack(
        "<IIII", 0, 1, len(frame) + captured_delta, len(frame) + original_delta,
    ) + frame
    source, labels = inputs(tmp_path, raw=raw)
    reject(tmp_path, source, labels, "PCAP packet length")


@pytest.mark.parametrize("declared", [0, 13, 55, 57, 0xFFFFFFFF])
def test_equal_declared_lengths_cannot_hide_short_or_oversized_body(tmp_path, declared):
    raw = capture([(0, packet())]) + struct.pack("<IIII", 0, 1, declared, declared) + packet()
    source, labels = inputs(tmp_path, raw=raw)
    reject(tmp_path, source, labels, "packet length|Truncated")


@pytest.mark.parametrize("flags", [0x2000, 1, 0x2001])
def test_ipv4_fragments_reject_whole_conversion(tmp_path, flags):
    frame = bytearray(packet())
    struct.pack_into("!H", frame, 20, flags)
    source, labels = inputs(tmp_path, frames=[(0, packet()), (1, bytes(frame))])
    reject(tmp_path, source, labels, "IPv4 fragments")


@pytest.mark.parametrize("flags", [0, 1, 8], ids=["atomic", "more-fragments", "nonzero-offset"])
def test_ipv6_fragments_including_atomic_reject_whole_conversion(tmp_path, flags):
    fragment = struct.pack("!BBHI", 6, 0, flags, 123) + packet()[34:]
    frame = packet(src="::1", dst="::2", protocol=44, payload=fragment)
    source, labels = inputs(tmp_path, frames=[(0, packet()), (1, frame)])
    reject(tmp_path, source, labels, "fragments/ESP")


def test_ipv6_jumbogram_rejected(tmp_path):
    frame = bytearray(packet(src="::1", dst="::2"))
    struct.pack_into("!H", frame, 18, 0)
    source, labels = inputs(tmp_path, frames=[(0, packet()), (1, bytes(frame))])
    reject(tmp_path, source, labels, "jumbogram")


def test_pcapng_rejected_explicitly(tmp_path):
    source, labels = inputs(tmp_path, raw=b"\x0a\x0d\x0d\x0a" + b"\x00" * 24)
    reject(tmp_path, source, labels, "pcapng is unsupported")


def test_snaplen_truncated_record_rejected(tmp_path):
    frame = packet()
    raw = capture([(0, frame)]) + struct.pack("<IIII", 0, 1, len(frame), len(frame) + 100) + frame
    source, labels = inputs(tmp_path, raw=raw)
    reject(tmp_path, source, labels, "truncated.*PCAP packet length")


def test_decreasing_global_timestamps_across_distinct_flows_rejected(tmp_path):
    source, labels = inputs(tmp_path, frames=[(2, packet()), (1, packet(protocol=17))], rows=[
        ["10.0.0.1", 1000, "10.0.0.2", 443, "tcp", "VPN"],
        ["10.0.0.1", 1000, "10.0.0.2", 443, "udp", "Normal"],
    ])
    reject(tmp_path, source, labels, "Decreasing capture timestamps")


def extension_frame(kinds):
    transport = packet(src="::1", dst="::2")[54:]
    for index in reversed(range(len(kinds))):
        following = kinds[index + 1] if index + 1 < len(kinds) else 6
        transport = (bytes([following, 1]) + b"\x00" * 10 if kinds[index] == 51
                     else bytes([following, 0]) + b"\x00" * 6) + transport
    return packet(src="::1", dst="::2", protocol=kinds[0], payload=transport)


@pytest.mark.parametrize("kinds", [[0] * 9, [43] * 9, [60] * 9, [51] * 9,
                                   [0, 43, 60, 51] * 4, [0] * 256])
def test_ipv6_extension_chain_over_eight_rejected(tmp_path, kinds):
    source, labels = inputs(tmp_path, frames=[(0, packet()), (1, extension_frame(kinds))])
    reject(tmp_path, source, labels, "IPv6 extension chain exceeds bounds")


def test_exactly_eight_ipv6_extensions_remain_supported(tmp_path):
    source, labels = inputs(tmp_path, frames=[(0, extension_frame([0, 43, 60, 51] * 2))], rows=[
        ["::2", 443, "::1", 1000, "6", "VPN"],
    ])
    result = ingest_pcap(source, tmp_path / "dataset.csv", labels, metadata())
    assert (result.packet_count, result.row_count, result.skipped_packets) == (1, 1, 0)


@pytest.mark.parametrize("kind", ["packets", "flows"])
def test_extreme_counts_fail_at_configured_caps_with_deadline(tmp_path, kind):
    count = 50_000 if kind == "packets" else 8192
    if kind == "packets":
        frame = packet()
        record = struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
        source, labels = inputs(tmp_path, raw=capture([]) + record * count)
        limits = {"max_packets": 256}
    else:
        frames = [(index, packet(sport=1000 + index)) for index in range(count)]
        rows = [["10.0.0.1", 1000 + index, "10.0.0.2", 443, "tcp", "VPN"]
                for index in range(count)]
        source, labels = inputs(tmp_path, frames=frames, rows=rows)
        limits = {"max_flows": 128}
    reject(tmp_path, source, labels, f"{kind[:-1]} cap exceeded", limits=limits)


@pytest.mark.parametrize("limit,value,match", [
    ("max_capture_bytes", 50, "capture byte cap"),
    ("max_packet_bytes", 40, "packet bounds"),
    ("max_labels_bytes", 10, "byte limit"),
    ("max_label_rows", 1, "Label row cap"),
    ("max_dataset_bytes", 10, "dataset byte cap"),
])
def test_remaining_resource_caps_preserve_previous_output(tmp_path, limit, value, match):
    source, labels = inputs(tmp_path, frames=[(0, packet()), (1, packet(protocol=17))], rows=[
        ["10.0.0.1", 1000, "10.0.0.2", 443, "tcp", "VPN"],
        ["10.0.0.1", 1000, "10.0.0.2", 443, "udp", "Normal"],
    ])
    reject(tmp_path, source, labels, match, limits={limit: value})


def test_sequence_dense_memory_cap_rejects_before_publication(tmp_path):
    source, labels = inputs(tmp_path)
    reject(tmp_path, source, labels, "Sequence dataset byte cap",
           schema=metadata(True), limits={"max_dataset_bytes": 4})


@pytest.mark.parametrize("reverse,conflicting", [(False, False), (True, False), (True, True)])
def test_duplicate_direction_normalized_labels(tmp_path, reverse, conflicting):
    first = ["10.0.0.1", 1000, "10.0.0.2", 443, "tcp", "VPN"]
    second = (["10.0.0.2", 443, "10.0.0.1", 1000, "6", "VPN"] if reverse else list(first))
    if conflicting:
        second[-1] = "Normal"
    source, labels = inputs(tmp_path, rows=[first, second])
    reject(tmp_path, source, labels, "Duplicate direction-normalized")


def test_ipv6_reverse_aliases_are_duplicate_keys(tmp_path):
    source, labels = inputs(tmp_path, rows=[
        ["2001:db8::1", 1000, "2001:db8::2", 443, "tcp", "VPN"],
        ["2001:0db8:0:0:0:0:0:2", 443, "2001:0db8::1", 1000, "6", "VPN"],
    ])
    reject(tmp_path, source, labels, "Duplicate direction-normalized")


@pytest.mark.parametrize("field,value,match", [
    (0, "invalid-ip", "5-tuple"), (0, "2001:db8::1", "5-tuple"),
    (1, -1, "5-tuple"), (1, 65536, "5-tuple"), (3, "not-a-port", "5-tuple"),
    (4, "icmp", "unsupported protocol"), (5, "undeclared", "undeclared class"),
])
def test_malformed_reverse_label_keys_rejected(tmp_path, field, value, match):
    row = ["10.0.0.2", 443, "10.0.0.1", 1000, "tcp", "VPN"]
    row[field] = value
    source, labels = inputs(tmp_path, rows=[row])
    reject(tmp_path, source, labels, match)


def test_label_csv_matching_zero_capture_flows_rejected(tmp_path):
    source, labels = inputs(tmp_path, rows=[
        ["192.0.2.1", 5000, "192.0.2.2", 443, "tcp", "VPN"],
    ])
    reject(tmp_path, source, labels, "Missing explicit label")
