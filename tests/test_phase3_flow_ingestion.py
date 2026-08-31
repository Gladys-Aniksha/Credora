from __future__ import annotations

import pandas as pd

from modules.phase3_operations.m7_flow_ingestion.collector import CANONICAL_FEATURES, ingest_flow_file


def test_cicflowmeter_conversion_produces_canonical_features(tmp_path) -> None:
    source = tmp_path / "cic.csv"
    output = tmp_path / "canonical.csv"
    pd.DataFrame({
        "Flow Duration": [2_000_000],
        "Total Fwd Packets": [4],
        "Total Backward Packets": [6],
        "Total Length of Fwd Packets": [1000],
        "Total Length of Bwd Packets": [2000],
        "Average Packet Size": [300],
        "Flow IAT Mean": [200_000],
        "Flow IAT Std": [50_000],
        "Flow Bytes/s": [1500],
        "Label": ["VPN"],
    }).to_csv(source, index=False)

    result = ingest_flow_file(source, output, "cicflowmeter")
    converted = pd.read_csv(output)

    assert result.source_format == "cicflowmeter"
    assert converted.loc[0, "flow_duration"] == 2000
    assert converted.loc[0, "packet_count"] == 10
    assert converted.loc[0, "iat_mean"] == 0.2
    assert set(CANONICAL_FEATURES).issubset(converted.columns)


def test_zeek_conversion_uses_connection_metadata_only(tmp_path) -> None:
    source = tmp_path / "conn.log"
    output = tmp_path / "canonical.csv"
    source.write_text(
        "#separator \\x09\n"
        "#fields\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\n"
        "2.0\t1000\t500\t5\t5\n",
        encoding="utf-8",
    )

    result = ingest_flow_file(source, output, "zeek")
    converted = pd.read_csv(output)

    assert result.source_format == "zeek"
    assert converted.loc[0, "flow_duration"] == 2000
    assert converted.loc[0, "packet_count"] == 10
    assert converted.loc[0, "flow_bytes_per_second"] == 750
