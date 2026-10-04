from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.config import DATA_DIR

DB_PATH = DATA_DIR / "registry" / "credora_registry.sqlite3"
OWNER_TABLES = ("model_registry", "scan_history", "runtime_alerts", "drift_windows", "integrity_checks")
ROLES = {"uploader", "reviewer", "admin"}


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


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _add_column(conn: sqlite3.Connection, table: str, column_sql: str) -> None:
    column_name = column_sql.split()[0]
    if column_name not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column_sql}")


def _bootstrap_admin_user(conn: sqlite3.Connection) -> int:
    import os

    from core.auth import hash_password

    existing = conn.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
    if existing:
        return int(existing["id"])
    username = os.getenv("CREDORA_BOOTSTRAP_ADMIN", "admin")
    email = os.getenv("CREDORA_BOOTSTRAP_EMAIL", "admin@credora.local")
    password = os.getenv("CREDORA_BOOTSTRAP_PASSWORD", "credora-admin")
    cursor = conn.execute(
        """
        INSERT INTO users (username, email, password_hash, role, created_at)
        VALUES (?, ?, ?, 'admin', ?)
        """,
        (username, email, hash_password(password), utc_now()),
    )
    return int(cursor.lastrowid)


def init_db() -> None:
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'uploader',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_login_at TEXT,
                disabled INTEGER NOT NULL DEFAULT 0,
                session_version INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS model_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER REFERENCES users(id),
                model_name TEXT NOT NULL,
                input_type TEXT NOT NULL DEFAULT 'tabular',
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
                owner_id INTEGER REFERENCES users(id),
                model_name TEXT NOT NULL,
                input_type TEXT NOT NULL DEFAULT 'tabular',
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
                owner_id INTEGER REFERENCES users(id),
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
                owner_id INTEGER REFERENCES users(id),
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
                owner_id INTEGER REFERENCES users(id),
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
        for table in OWNER_TABLES:
            _add_column(conn, table, "owner_id INTEGER REFERENCES users(id)")
        _add_column(conn, "model_registry", "input_type TEXT NOT NULL DEFAULT 'tabular'")
        _add_column(conn, "scan_history", "input_type TEXT NOT NULL DEFAULT 'tabular'")
        _add_column(conn, "users", "disabled INTEGER NOT NULL DEFAULT 0")
        _add_column(conn, "users", "session_version INTEGER NOT NULL DEFAULT 0")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER REFERENCES users(id),
                event_type TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS platform_settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_by INTEGER REFERENCES users(id),
                updated_at TEXT NOT NULL
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS trusted_signers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                public_key_pem TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_by INTEGER REFERENCES users(id),
                created_at TEXT NOT NULL
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS deployment_overrides (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER REFERENCES users(id),
                scan_id INTEGER REFERENCES scan_history(id),
                decision TEXT NOT NULL,
                justification TEXT NOT NULL,
                reviewer_id INTEGER REFERENCES users(id),
                created_at TEXT NOT NULL
            )
            """)
        admin_id = _bootstrap_admin_user(conn)
        for table in OWNER_TABLES:
            conn.execute(f"UPDATE {table} SET owner_id = ? WHERE owner_id IS NULL", (admin_id,))
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_model_registry_owner ON model_registry(owner_id, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_owner ON scan_history(owner_id, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_lineage ON scan_history(owner_id, model_name, input_type, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_runtime_alerts_status ON runtime_alerts(owner_id, status, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_drift_windows_model ON drift_windows(owner_id, model_name, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_integrity_model ON integrity_checks(owner_id, model_name, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_overrides_scan ON deployment_overrides(scan_id, id DESC)")


def create_user(username: str, password: str, email: str | None = None, role: str = "uploader") -> dict[str, Any]:
    from core.auth import hash_password

    username = (username or "").strip().lower()
    email = (email or "").strip().lower() or None
    if len(username) < 3:
        raise ValueError("Username must be at least 3 characters.")
    if role not in ROLES:
        raise ValueError("Unsupported user role.")
    init_db()
    try:
        with connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users (username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, email, hash_password(password), role, utc_now()),
            )
            user_id = int(cursor.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise ValueError("Username or email already exists.") from exc
    user = get_user_by_id(user_id)
    assert user is not None
    return user


def get_user_by_username(username: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", ((username or "").strip().lower(),)).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    if int(user_id) <= 0:
        return None
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT id, username, email, role, created_at, last_login_at, disabled, session_version FROM users WHERE id = ?", (int(user_id),)).fetchone()
    return dict(row) if row else None


def list_users() -> list[dict[str, Any]]:
    init_db()
    with connect() as conn:
        rows = conn.execute("SELECT id, username, email, role, created_at, last_login_at, disabled, session_version FROM users ORDER BY id").fetchall()
    return [dict(row) for row in rows]


def authenticate_user(username: str, password: str) -> dict[str, Any] | None:
    from core.auth import DUMMY_PASSWORD_HASH, verify_password

    init_db()
    username_key = (username or "").strip().lower()
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username_key,)).fetchone()
        password_hash = row["password_hash"] if row else DUMMY_PASSWORD_HASH
        password_matches = verify_password(password, password_hash)
        if not row or int(row["disabled"] or 0) or not password_matches:
            row = None
        else:
            conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (utc_now(), row["id"]))
            user = {key: row[key] for key in ("id", "username", "email", "role", "created_at", "session_version")}
    if row is None:
        log_audit_event(None, "auth.login_failed", "user", username_key, {"username": username_key})
        return None
    log_audit_event(int(user["id"]), "auth.login", "user", str(user["id"]), {"username": user["username"]})
    return user


def _owner_clause(owner_id: int | None, include_all: bool, prefix: str = "WHERE") -> tuple[str, tuple[Any, ...]]:
    if include_all or owner_id is None:
        return "", ()
    return f" {prefix} owner_id = ?", (int(owner_id),)


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
    owner_id: int | None = None,
    input_type: str = "tabular",
) -> int:
    init_db()
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO model_registry (
                owner_id, model_name, input_type, version, algorithm, framework, task, model_path,
                dataset_path, requirements_path, metadata_path, sha256, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                owner_id,
                model_name,
                input_type,
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


def save_scan(report: Any, report_path: str | Path, owner_id: int | None = None) -> int:
    init_db()
    report_dict = report.to_dict() if hasattr(report, "to_dict") else dict(report)
    model_name = report_dict.get("model_name", "unknown_model")
    input_type = report_dict.get("input_type", "tabular")
    version = None
    for result in report_dict.get("module_results", []):
        if result.get("module") == "model_verification":
            version = result.get("details", {}).get("version")
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scan_history (
                owner_id, model_name, input_type, version, trust_score, status, report_path, generated_at, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                owner_id,
                model_name,
                input_type,
                version,
                float(report_dict.get("trust_score", 0)),
                report_dict.get("status", "unknown"),
                str(report_path),
                report_dict.get("generated_at", utc_now()),
                json.dumps(report_dict),
            ),
        )
        return int(cursor.lastrowid)


def list_models(limit: int = 25, owner_id: int | None = None, include_all: bool = False) -> list[dict[str, Any]]:
    init_db()
    clause, params = _owner_clause(owner_id, include_all)
    with connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM model_registry{clause} ORDER BY id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def latest_model_by_name(model_name: str, owner_id: int | None = None, include_all: bool = False) -> dict[str, Any] | None:
    init_db()
    if include_all or owner_id is None:
        query = "SELECT * FROM model_registry WHERE model_name = ? ORDER BY id DESC LIMIT 1"
        params: tuple[Any, ...] = (model_name,)
    else:
        query = "SELECT * FROM model_registry WHERE model_name = ? AND owner_id = ? ORDER BY id DESC LIMIT 1"
        params = (model_name, int(owner_id))
    with connect() as conn:
        row = conn.execute(query, params).fetchone()
    return dict(row) if row else None


def list_scans(limit: int = 25, owner_id: int | None = None, include_all: bool = False, model_name: str | None = None) -> list[dict[str, Any]]:
    init_db()
    filters: list[str] = []
    params: list[Any] = []
    if not include_all and owner_id is not None:
        filters.append("owner_id = ?")
        params.append(int(owner_id))
    if model_name:
        filters.append("model_name = ?")
        params.append(model_name)
    where = f" WHERE {' AND '.join(filters)}" if filters else ""
    with connect() as conn:
        rows = conn.execute(
            f"SELECT id, owner_id, model_name, input_type, version, trust_score, status, report_path, generated_at FROM scan_history{where} ORDER BY id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def list_scan_reports(
    limit: int = 25,
    owner_id: int | None = None,
    include_all: bool = False,
    model_name: str | None = None,
) -> list[dict[str, Any]]:
    init_db()
    filters: list[str] = []
    params: list[Any] = []
    if not include_all and owner_id is not None:
        filters.append("owner_id = ?")
        params.append(int(owner_id))
    if model_name:
        filters.append("model_name = ?")
        params.append(model_name)
    where = f" WHERE {' AND '.join(filters)}" if filters else ""
    with connect() as conn:
        rows = conn.execute(
            f"SELECT report_json FROM scan_history{where} ORDER BY id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()

    reports: list[dict[str, Any]] = []
    for row in rows:
        try:
            reports.append(json.loads(row["report_json"]))
        except (TypeError, json.JSONDecodeError):
            continue
    return reports


def latest_scan(owner_id: int | None = None, include_all: bool = False) -> dict[str, Any] | None:
    init_db()
    clause, params = _owner_clause(owner_id, include_all)
    with connect() as conn:
        row = conn.execute(f"SELECT report_json FROM scan_history{clause} ORDER BY id DESC LIMIT 1", params).fetchone()
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
    owner_id: int | None = None,
) -> int:
    init_db()
    with connect() as conn:
        if dedupe_key:
            if owner_id is None:
                existing = conn.execute(
                    "SELECT id FROM runtime_alerts WHERE dedupe_key = ? AND status = 'open' ORDER BY id DESC LIMIT 1",
                    (dedupe_key,),
                ).fetchone()
            else:
                existing = conn.execute(
                    "SELECT id FROM runtime_alerts WHERE dedupe_key = ? AND owner_id = ? AND status = 'open' ORDER BY id DESC LIMIT 1",
                    (dedupe_key, int(owner_id)),
                ).fetchone()
            if existing:
                return int(existing["id"])
        cursor = conn.execute(
            """
            INSERT INTO runtime_alerts (
                owner_id, source, severity, title, message, recommendation, model_name,
                status, dedupe_key, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)
            """,
            (
                owner_id,
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


def list_runtime_alerts(limit: int = 100, status: str | None = None, owner_id: int | None = None, include_all: bool = False) -> list[dict[str, Any]]:
    init_db()
    filters: list[str] = []
    params: list[Any] = []
    if status:
        filters.append("status = ?")
        params.append(status)
    if not include_all and owner_id is not None:
        filters.append("owner_id = ?")
        params.append(int(owner_id))
    where = f" WHERE {' AND '.join(filters)}" if filters else ""
    with connect() as conn:
        rows = conn.execute(f"SELECT * FROM runtime_alerts{where} ORDER BY id DESC LIMIT ?", (*params, limit)).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json"))
        output.append(item)
    return output


def acknowledge_runtime_alert(alert_id: int, owner_id: int | None = None, include_all: bool = False) -> bool:
    init_db()
    if include_all or owner_id is None:
        query = "UPDATE runtime_alerts SET status = 'acknowledged', acknowledged_at = ? WHERE id = ? AND status = 'open'"
        params: tuple[Any, ...] = (utc_now(), alert_id)
    else:
        query = "UPDATE runtime_alerts SET status = 'acknowledged', acknowledged_at = ? WHERE id = ? AND owner_id = ? AND status = 'open'"
        params = (utc_now(), alert_id, int(owner_id))
    with connect() as conn:
        cursor = conn.execute(query, params)
        return cursor.rowcount > 0


def save_drift_window(
    *,
    model_name: str,
    window_label: str,
    source_path: str | Path,
    row_count: int,
    result: Any,
    owner_id: int | None = None,
) -> int:
    init_db()
    result_dict = _as_dict(result)
    details = result_dict.get("details", {})
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO drift_windows (
                owner_id, model_name, window_label, source_path, row_count, score, status,
                mean_psi, max_psi, drifted_features_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                owner_id,
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


def list_drift_windows(model_name: str | None = None, limit: int = 100, owner_id: int | None = None, include_all: bool = False) -> list[dict[str, Any]]:
    init_db()
    filters: list[str] = []
    params: list[Any] = []
    if model_name:
        filters.append("model_name = ?")
        params.append(model_name)
    if not include_all and owner_id is not None:
        filters.append("owner_id = ?")
        params.append(int(owner_id))
    where = f" WHERE {' AND '.join(filters)}" if filters else ""
    with connect() as conn:
        rows = conn.execute(f"SELECT * FROM drift_windows{where} ORDER BY id DESC LIMIT ?", (*params, limit)).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["drifted_features"] = json.loads(item.pop("drifted_features_json"))
        output.append(item)
    return output


def save_integrity_check(model_name: str, result: Any, owner_id: int | None = None) -> int:
    init_db()
    result_dict = _as_dict(result)
    details = result_dict.get("details", {})
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO integrity_checks (
                owner_id, model_name, model_path, expected_sha256, actual_sha256, integrity_state,
                score, status, details_json, checked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                owner_id,
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


def list_integrity_checks(model_name: str | None = None, limit: int = 100, owner_id: int | None = None, include_all: bool = False) -> list[dict[str, Any]]:
    init_db()
    filters: list[str] = []
    params: list[Any] = []
    if model_name:
        filters.append("model_name = ?")
        params.append(model_name)
    if not include_all and owner_id is not None:
        filters.append("owner_id = ?")
        params.append(int(owner_id))
    where = f" WHERE {' AND '.join(filters)}" if filters else ""
    with connect() as conn:
        rows = conn.execute(f"SELECT * FROM integrity_checks{where} ORDER BY id DESC LIMIT ?", (*params, limit)).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json"))
        output.append(item)
    return output


DEFAULT_TRUST_WEIGHTS = {
    "model_verification": 0.09,
    "dependency_scanner": 0.06,
    "classifier_evaluation": 0.13,
    "robustness_testing": 0.08,
    "data_drift_detection": 0.07,
    "explainability": 0.07,
    "dataset_leakage": 0.08,
    "privacy_risk": 0.07,
    "behavior_analysis": 0.08,
    "model_risk_analyzer": 0.05,
    "adversarial_validation": 0.09,
    "runtime_integrity": 0.06,
    "trust_drift_timeline": 0.02,
}
DEFAULT_SENSITIVE_LABELS = ["attack", "malware", "suspicious", "threat", "botnet", "ddos", "intrusion"]


def log_audit_event(
    actor_id: int | None,
    event_type: str,
    target_type: str | None = None,
    target_id: str | int | None = None,
    details: dict[str, Any] | None = None,
) -> int:
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO audit_logs (actor_id, event_type, target_type, target_id, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (actor_id, event_type, target_type, str(target_id) if target_id is not None else None, json.dumps(details or {}), utc_now()),
        )
        return int(cursor.lastrowid)


def list_audit_logs(limit: int = 200, event_type: str | None = None) -> list[dict[str, Any]]:
    init_db()
    if event_type:
        query = "SELECT * FROM audit_logs WHERE event_type = ? ORDER BY id DESC LIMIT ?"
        params: tuple[Any, ...] = (event_type, limit)
    else:
        query = "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?"
        params = (limit,)
    with connect() as conn:
        rows = conn.execute(query, params).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json"))
        output.append(item)
    return output


def change_user_password(user_id: int, current_password: str, new_password: str) -> bool:
    from core.auth import hash_password, verify_password

    init_db()
    with connect() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id = ? AND disabled = 0", (int(user_id),)).fetchone()
        if not row or not verify_password(current_password, row["password_hash"]):
            log_audit_event(user_id, "auth.password_change_failed", "user", user_id)
            return False
        conn.execute(
            "UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?",
            (hash_password(new_password), int(user_id)),
        )
    log_audit_event(user_id, "auth.password_changed", "user", user_id)
    return True


def admin_set_password(user_id: int, new_password: str, actor_id: int | None = None) -> None:
    from core.auth import hash_password

    init_db()
    with connect() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?",
            (hash_password(new_password), int(user_id)),
        )
    log_audit_event(actor_id, "admin.password_reset", "user", user_id)


def update_user_role(user_id: int, role: str, actor_id: int | None = None) -> None:
    if role not in ROLES:
        raise ValueError("Unsupported user role.")
    init_db()
    with connect() as conn:
        conn.execute("UPDATE users SET role = ?, session_version = session_version + 1 WHERE id = ?", (role, int(user_id)))
    log_audit_event(actor_id, "admin.role_changed", "user", user_id, {"role": role})


def set_user_disabled(user_id: int, disabled: bool, actor_id: int | None = None) -> None:
    init_db()
    with connect() as conn:
        conn.execute(
            "UPDATE users SET disabled = ?, session_version = session_version + 1 WHERE id = ?",
            (1 if disabled else 0, int(user_id)),
        )
    log_audit_event(actor_id, "admin.user_disabled" if disabled else "admin.user_enabled", "user", user_id)


def revoke_user_sessions(user_id: int, actor_id: int | None = None) -> None:
    init_db()
    with connect() as conn:
        conn.execute("UPDATE users SET session_version = session_version + 1 WHERE id = ?", (int(user_id),))
    log_audit_event(actor_id, "admin.sessions_revoked", "user", user_id)


def delete_user_account(user_id: int, actor_id: int | None = None) -> None:
    init_db()
    with connect() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (int(user_id),))
    log_audit_event(actor_id, "admin.user_deleted", "user", user_id)


def get_platform_setting(key: str, default: Any = None) -> Any:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT value_json FROM platform_settings WHERE key = ?", (key,)).fetchone()
    return json.loads(row["value_json"]) if row else default


def set_platform_setting(key: str, value: Any, actor_id: int | None = None) -> None:
    init_db()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO platform_settings (key, value_json, updated_by, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_by = excluded.updated_by, updated_at = excluded.updated_at
            """,
            (key, json.dumps(value), actor_id, utc_now()),
        )
    log_audit_event(actor_id, "admin.setting_updated", "setting", key, {"value": value})


def get_deployment_policy() -> dict[str, Any]:
    from core.config import DEFAULT_DEPLOYMENT_POLICY

    policy = dict(DEFAULT_DEPLOYMENT_POLICY)
    policy.update(get_platform_setting("deployment_policy", {}) or {})
    return policy


def set_deployment_policy(policy: dict[str, Any], actor_id: int | None = None) -> None:
    numeric = {key: float(value) for key, value in policy.items()}
    set_platform_setting("deployment_policy", numeric, actor_id=actor_id)


def get_trust_weights() -> dict[str, float]:
    weights = dict(DEFAULT_TRUST_WEIGHTS)
    configured = get_platform_setting("trust_weights", {}) or {}
    weights.update({key: value for key, value in configured.items() if key in weights})
    total = sum(float(value) for value in weights.values())
    if total > 0:
        weights = {key: float(value) / total for key, value in weights.items()}
    return weights


def set_trust_weights(weights: dict[str, Any], actor_id: int | None = None) -> None:
    cleaned = {key: max(float(value), 0.0) for key, value in weights.items() if key in DEFAULT_TRUST_WEIGHTS}
    if not cleaned or sum(cleaned.values()) <= 0:
        raise ValueError("At least one trust weight must be positive.")
    set_platform_setting("trust_weights", cleaned, actor_id=actor_id)


def get_sensitive_label_taxonomy() -> list[str]:
    labels = get_platform_setting("sensitive_label_taxonomy", DEFAULT_SENSITIVE_LABELS)
    return [str(label).strip().lower() for label in labels if str(label).strip()]


def set_sensitive_label_taxonomy(labels: list[str], actor_id: int | None = None) -> None:
    cleaned = sorted({str(label).strip().lower() for label in labels if str(label).strip()})
    if not cleaned:
        raise ValueError("At least one sensitive label hint is required.")
    set_platform_setting("sensitive_label_taxonomy", cleaned, actor_id=actor_id)


def add_trusted_signer(name: str, public_key_pem: str, actor_id: int | None = None) -> int:
    init_db()
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO trusted_signers (name, public_key_pem, status, created_by, created_at)
            VALUES (?, ?, 'active', ?, ?)
            """,
            (name.strip(), public_key_pem.strip(), actor_id, utc_now()),
        )
        signer_id = int(cursor.lastrowid)
    log_audit_event(actor_id, "admin.trusted_signer_added", "trusted_signer", signer_id, {"name": name})
    return signer_id


def list_trusted_signers(include_inactive: bool = False) -> list[dict[str, Any]]:
    init_db()
    query = "SELECT id, name, public_key_pem, status, created_by, created_at FROM trusted_signers"
    params: tuple[Any, ...] = ()
    if not include_inactive:
        query += " WHERE status = 'active'"
    query += " ORDER BY id DESC"
    with connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def set_trusted_signer_status(signer_id: int, status: str, actor_id: int | None = None) -> None:
    if status not in {"active", "disabled"}:
        raise ValueError("Signer status must be active or disabled.")
    init_db()
    with connect() as conn:
        conn.execute("UPDATE trusted_signers SET status = ? WHERE id = ?", (status, int(signer_id)))
    log_audit_event(actor_id, "admin.trusted_signer_status", "trusted_signer", signer_id, {"status": status})


def create_deployment_override(scan_id: int, decision: str, justification: str, reviewer_id: int) -> int:
    if decision not in {"approved", "rejected"}:
        raise ValueError("Override decision must be approved or rejected.")
    if len((justification or "").strip()) < 10:
        raise ValueError("A justification note is required.")
    init_db()
    scan = get_scan_record(scan_id, include_report=False, include_all=True)
    if not scan:
        raise ValueError("Scan not found.")
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO deployment_overrides (owner_id, scan_id, decision, justification, reviewer_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (scan.get("owner_id"), int(scan_id), decision, justification.strip(), int(reviewer_id), utc_now()),
        )
        override_id = int(cursor.lastrowid)
    log_audit_event(reviewer_id, "review.deployment_override", "scan", scan_id, {"decision": decision, "justification": justification})
    return override_id


def list_deployment_overrides(limit: int = 100, owner_id: int | None = None, include_all: bool = False) -> list[dict[str, Any]]:
    init_db()
    clause, params = _owner_clause(owner_id, include_all)
    with connect() as conn:
        rows = conn.execute(f"SELECT * FROM deployment_overrides{clause} ORDER BY id DESC LIMIT ?", (*params, limit)).fetchall()
    return [dict(row) for row in rows]


def get_scan_record(scan_id: int, include_report: bool = True, owner_id: int | None = None, include_all: bool = False) -> dict[str, Any] | None:
    init_db()
    filters = ["id = ?"]
    params: list[Any] = [int(scan_id)]
    if not include_all and owner_id is not None:
        filters.append("owner_id = ?")
        params.append(int(owner_id))
    columns = "*" if include_report else "id, owner_id, model_name, version, trust_score, status, report_path, generated_at"
    with connect() as conn:
        row = conn.execute(f"SELECT {columns} FROM scan_history WHERE {' AND '.join(filters)}", params).fetchone()
    if not row:
        return None
    item = dict(row)
    if include_report and item.get("report_json"):
        item["report"] = json.loads(item["report_json"])
    return item


def delete_scan(scan_id: int, owner_id: int | None = None, include_all: bool = False, actor_id: int | None = None) -> bool:
    scan = get_scan_record(scan_id, include_report=False, owner_id=owner_id, include_all=include_all)
    if not scan:
        return False
    report_path = Path(scan.get("report_path") or "")
    init_db()
    with connect() as conn:
        if include_all or owner_id is None:
            cursor = conn.execute("DELETE FROM scan_history WHERE id = ?", (int(scan_id),))
        else:
            cursor = conn.execute("DELETE FROM scan_history WHERE id = ? AND owner_id = ?", (int(scan_id), int(owner_id)))
    try:
        if report_path.exists() and report_path.is_file():
            report_path.unlink()
    except OSError:
        pass
    log_audit_event(actor_id, "data.scan_deleted", "scan", scan_id)
    return cursor.rowcount > 0


def delete_model_records(model_name: str, owner_id: int | None = None, include_all: bool = False, actor_id: int | None = None) -> int:
    init_db()
    scans = list_scans(limit=10000, owner_id=owner_id, include_all=include_all, model_name=model_name)
    deleted = 0
    for scan in scans:
        if delete_scan(int(scan["id"]), owner_id=owner_id, include_all=include_all, actor_id=actor_id):
            deleted += 1
    if include_all or owner_id is None:
        query = "DELETE FROM model_registry WHERE model_name = ?"
        params: tuple[Any, ...] = (model_name,)
    else:
        query = "DELETE FROM model_registry WHERE model_name = ? AND owner_id = ?"
        params = (model_name, int(owner_id))
    with connect() as conn:
        cursor = conn.execute(query, params)
    log_audit_event(actor_id, "data.model_deleted", "model", model_name, {"scan_count": deleted, "registry_rows": cursor.rowcount})
    return deleted + cursor.rowcount


def platform_analytics() -> dict[str, Any]:
    init_db()
    with connect() as conn:
        user_count = conn.execute("SELECT COUNT(*) AS n FROM users WHERE disabled = 0").fetchone()["n"]
        scan_count = conn.execute("SELECT COUNT(*) AS n FROM scan_history").fetchone()["n"]
        model_count = conn.execute("SELECT COUNT(*) AS n FROM model_registry").fetchone()["n"]
        status_rows = conn.execute("SELECT status, COUNT(*) AS n FROM scan_history GROUP BY status").fetchall()
        score_rows = conn.execute(
            """
            SELECT
              SUM(CASE WHEN trust_score >= 85 THEN 1 ELSE 0 END) AS pass_count,
              SUM(CASE WHEN trust_score >= 70 AND trust_score < 85 THEN 1 ELSE 0 END) AS warning_count,
              SUM(CASE WHEN trust_score < 70 THEN 1 ELSE 0 END) AS fail_count
            FROM scan_history
            """
        ).fetchone()
        scans = conn.execute("SELECT report_json FROM scan_history ORDER BY id DESC LIMIT 1000").fetchall()
    findings: dict[str, int] = {}
    for row in scans:
        try:
            report = json.loads(row["report_json"])
        except json.JSONDecodeError:
            continue
        for result in report.get("module_results", []):
            for finding in result.get("findings", []):
                if finding.get("severity") in {"critical", "high", "medium"}:
                    title = str(finding.get("title", "Finding"))
                    findings[title] = findings.get(title, 0) + 1
    common = sorted(findings.items(), key=lambda item: item[1], reverse=True)[:10]
    return {
        "active_users": int(user_count or 0),
        "total_models": int(model_count or 0),
        "total_scans": int(scan_count or 0),
        "scan_status_counts": {row["status"]: row["n"] for row in status_rows},
        "trust_score_distribution": {
            "pass": int(score_rows["pass_count"] or 0),
            "warning": int(score_rows["warning_count"] or 0),
            "fail": int(score_rows["fail_count"] or 0),
        },
        "common_security_findings": [{"finding": title, "count": count} for title, count in common],
    }

