from __future__ import annotations

import json

import numpy as np
import pandas as pd

import core.db as db
from core.hashing import sha256_file
from modules.phase3_operations.m6_runtime_integrity.scheduler import run_integrity_cycle
from modules.phase3_operations.m8_production_monitoring.monitor import monitor_drift_window


FEATURES = [
    "flow_duration",
    "packet_count",
    "avg_packet_size",
    "bytes_sent",
    "bytes_received",
    "iat_mean",
    "iat_std",
    "flow_bytes_per_second",
]


def _frame(offset: float) -> pd.DataFrame:
    base = np.arange(1, 101, dtype=float) + offset
    return pd.DataFrame({feature: base * (index + 1) for index, feature in enumerate(FEATURES)})


def test_drift_window_persists_history_and_alert(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "registry.sqlite3")
    baseline = tmp_path / "baseline.csv"
    current = tmp_path / "current.csv"
    _frame(0).to_csv(baseline, index=False)
    _frame(1000).to_csv(current, index=False)

    result = monitor_drift_window(
        model_name="traffic-model",
        window_path=current,
        baseline_path=baseline,
        window_label="window-1",
        expected_features=FEATURES,
    )

    assert result.status in {"warning", "fail"}
    assert len(db.list_drift_windows("traffic-model")) == 1
    alerts = db.list_runtime_alerts(status="open")
    assert len(alerts) == 1
    assert alerts[0]["source"] == "rolling_drift"


def test_integrity_cycle_persists_tamper_alert(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "registry.sqlite3")
    model = tmp_path / "model.joblib"
    metadata = tmp_path / "metadata.json"
    model.write_bytes(b"approved")
    metadata.write_text(json.dumps({
        "model_name": "runtime-model",
        "_expected_sha256": sha256_file(model),
        "_signature_verified": True,
    }), encoding="utf-8")

    assert run_integrity_cycle(model, metadata).status == "pass"
    model.write_bytes(b"tampered")
    result = run_integrity_cycle(model, metadata)

    assert result.status == "fail"
    assert len(db.list_integrity_checks("runtime-model")) == 2
    alerts = db.list_runtime_alerts(status="open")
    assert any(alert["source"] == "runtime_integrity" for alert in alerts)
