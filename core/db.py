from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.config import DATA_DIR

DB_PATH = DATA_DIR / "registry" / "credora_registry.sqlite3"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if is_dataclass(value):
        return asdict(value)
    return dict(value)


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS model_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL,
                version TEXT NOT NULL,
                algorithm TEXT,
                framework TEXT,
                task TEXT,
                model_path TEXT NOT NULL,
                dataset_path TEXT,
                requirements_path TEXT,
                metadata_path TEXT,
                sha256 TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL,
                version TEXT,
                trust_score REAL NOT NULL,
                status TEXT NOT NULL,
                report_path TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runtime_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                recommendation TEXT,
                model_name TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                dedupe_key TEXT,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                acknowledged_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS drift_windows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL,
                window_label TEXT NOT NULL,
                source_path TEXT NOT NULL,
                row_count INTEGER NOT NULL,
                score REAL NOT NULL,
                status TEXT NOT NULL,
                mean_psi REAL NOT NULL,
                max_psi REAL NOT NULL,
                drifted_features_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS integrity_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL,
                model_path TEXT NOT NULL,
                expected_sha256 TEXT,
                actual_sha256 TEXT,
                integrity_state TEXT NOT NULL,
                score REAL NOT NULL,
                status TEXT NOT NULL,
                details_json TEXT NOT NULL,
                checked_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_runtime_alerts_status ON runtime_alerts(status, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_drift_windows_model ON drift_windows(model_name, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_integrity_model ON integrity_checks(model_name, id DESC)")


def register_model(
    *,
    model_name: str,
    version: str,
    model_path: str | Path,
    dataset_path: str | Path | None = None,
    requirements_path: str | Path | None = None,
    metadata_path: str | Path | None = None,
    sha256: str | None = None,
    algorithm: str | None = None,
    framework: str | None = None,
    task: str | None = None,
) -> int:
    init_db()
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO model_registry (
                model_name, version, algorithm, framework, task, model_path,
                dataset_path, requirements_path, metadata_path, sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                model_name,
                version,
                algorithm,
                framework,
                task,
                str(model_path),
                str(dataset_path) if dataset_path else None,
                str(requirements_path) if requirements_path else None,
                str(metadata_path) if metadata_path else None,
                sha256,
                utc_now(),
            ),
        )
        return int(cursor.lastrowid)


def save_scan(report: Any, report_path: str | Path) -> int:
    init_db()
    report_dict = report.to_dict() if hasattr(report, "to_dict") else dict(report)
    model_name = report_dict.get("model_name", "unknown_model")
    version = None
    for result in report_dict.get("module_results", []):
        if result.get("module") == "model_verification":
            version = result.get("details", {}).get("version")
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scan_history (
                model_name, version, trust_score, status, report_path, generated_at, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                model_name,
                version,
                float(report_dict.get("trust_score", 0)),
                report_dict.get("status", "unknown"),
                str(report_path),
                report_dict.get("generated_at", utc_now()),
                json.dumps(report_dict),
            ),
        )
        return int(cursor.lastrowid)


def list_models(limit: int = 25) -> list[dict[str, Any]]:
    init_db()
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM model_registry ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def list_scans(limit: int = 25) -> list[dict[str, Any]]:
    init_db()
    with connect() as conn:
        rows = conn.execute(
            "SELECT id, model_name, version, trust_score, status, report_path, generated_at FROM scan_history ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def latest_scan() -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT report_json FROM scan_history ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return None
    return json.loads(row["report_json"])


def save_runtime_alert(
    *,
    source: str,
    severity: str,
    title: str,
    message: str,
    recommendation: str = "",
    model_name: str | None = None,
    details: dict[str, Any] | None = None,
    dedupe_key: str | None = None,
) -> int:
    init_db()
    with connect() as conn:
        if dedupe_key:
            existing = conn.execute(
                "SELECT id FROM runtime_alerts WHERE dedupe_key = ? AND status = 'open' ORDER BY id DESC LIMIT 1",
                (dedupe_key,),
            ).fetchone()
            if existing:
                return int(existing["id"])
        cursor = conn.execute(
            """
            INSERT INTO runtime_alerts (
                source, severity, title, message, recommendation, model_name,
                status, dedupe_key, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)
            """,
            (
                source,
                severity,
                title,
                message,
                recommendation,
                model_name,
                dedupe_key,
                json.dumps(details or {}),
                utc_now(),
            ),
        )
        return int(cursor.lastrowid)


def list_runtime_alerts(limit: int = 100, status: str | None = None) -> list[dict[str, Any]]:
    init_db()
    query = "SELECT * FROM runtime_alerts"
    parameters: tuple[Any, ...]
    if status:
        query += " WHERE status = ?"
        parameters = (status, limit)
    else:
        parameters = (limit,)
    query += " ORDER BY id DESC LIMIT ?"
    with connect() as conn:
        rows = conn.execute(query, parameters).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json"))
        output.append(item)
    return output


def acknowledge_runtime_alert(alert_id: int) -> bool:
    init_db()
    with connect() as conn:
        cursor = conn.execute(
            "UPDATE runtime_alerts SET status = 'acknowledged', acknowledged_at = ? WHERE id = ? AND status = 'open'",
            (utc_now(), alert_id),
        )
        return cursor.rowcount > 0


def save_drift_window(
    *,
    model_name: str,
    window_label: str,
    source_path: str | Path,
    row_count: int,
    result: Any,
) -> int:
    init_db()
    result_dict = _as_dict(result)
    details = result_dict.get("details", {})
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO drift_windows (
                model_name, window_label, source_path, row_count, score, status,
                mean_psi, max_psi, drifted_features_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                model_name,
                window_label,
                str(source_path),
                int(row_count),
                float(result_dict.get("score", 0)),
                result_dict.get("status", "not_run"),
                float(details.get("mean_psi", 0)),
                float(details.get("max_psi", 0)),
                json.dumps(details.get("drifted_features", [])),
                utc_now(),
            ),
        )
        return int(cursor.lastrowid)


def list_drift_windows(model_name: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    init_db()
    with connect() as conn:
        if model_name:
            rows = conn.execute(
                "SELECT * FROM drift_windows WHERE model_name = ? ORDER BY id DESC LIMIT ?",
                (model_name, limit),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM drift_windows ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["drifted_features"] = json.loads(item.pop("drifted_features_json"))
        output.append(item)
    return output


def save_integrity_check(model_name: str, result: Any) -> int:
    init_db()
    result_dict = _as_dict(result)
    details = result_dict.get("details", {})
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO integrity_checks (
                model_name, model_path, expected_sha256, actual_sha256, integrity_state,
                score, status, details_json, checked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                model_name,
                details.get("model_path", ""),
                details.get("expected_sha256"),
                details.get("actual_sha256"),
                details.get("integrity_state", "unknown"),
                float(result_dict.get("score", 0)),
                result_dict.get("status", "not_run"),
                json.dumps(details),
                details.get("checked_at", utc_now()),
            ),
        )
        return int(cursor.lastrowid)


def list_integrity_checks(model_name: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    init_db()
    with connect() as conn:
        if model_name:
            rows = conn.execute(
                "SELECT * FROM integrity_checks WHERE model_name = ? ORDER BY id DESC LIMIT ?",
                (model_name, limit),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM integrity_checks ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json"))
        output.append(item)
    return output
