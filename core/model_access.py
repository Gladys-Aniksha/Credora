"""Persistent model-read admission, audit, and burst alerts.

Call record_model_read BEFORE opening/decrypting model bytes. It records an
admitted *attempt*, not a claim that I/O succeeded. model_read_access additionally
records completion, and never holds a database transaction across its yield.
Rate accounting includes admitted attempts, including later failed I/O, but not
denied requests. The sliding window is (now-window, now], with future records
also retained conservatively if the server clock moves backwards. The default
is 20 distinct owner/canonical-path identities per actor in 60 seconds. Purposes
and owners do not partition an actor's budget. This is admission control, not
authorization; callers must enforce ownership separately.

record_model_read(..., connection=conn) uses the supplied SQLite connection;
if needed it starts BEGIN IMMEDIATE, but NEVER commits/closes that connection.
Use a caller-held write transaction, and finish it before byte I/O whenever
possible. Caller rollback also rolls back its audit/denial/alert. Do not open a
second logging connection while holding a write transaction. Our standalone
model_access_transaction commits admission denials before re-raising them.

Trusted API/dashboard/CLI boundaries set model_access_context. Never derive the
context from uploaded metadata. access_environment returns a subprocess env
overlay (not a complete environment). It carries actor, owner, purpose and DB
path; worker bootstrap must call configure_access_database_from_environment()
before any DB use. Environment identity is only for server-created workers.
No model bytes, keys or exception messages are stored in access audit records.
Only this module's access table and existing-compatible audit/alert tables are
initialized; this does not bootstrap accounts or migrate ownership.
"""
from __future__ import annotations

import inspect
import json
import os
import sqlite3
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
from hashlib import sha256
from pathlib import Path

from core import db

_PREFIX = "CREDORA_MODEL_ACCESS_"


class ModelAccessLimitError(ValueError):
    """A persistent per-actor distinct-model budget rejected this read."""


@dataclass(frozen=True)
class _AccessContext:
    actor_id: int | None
    purpose: str
    owner_id: int | None


@dataclass(frozen=True)
class ModelReadRecord:
    id: int
    actor_id: int | None
    owner_id: int | None
    path_identity: str
    path: str
    purpose: str
    timestamp: str


_context: ContextVar[_AccessContext | None] = ContextVar("credora_model_access", default=None)


def _identifier(value: int | None) -> int | None:
    if value is not None and (type(value) is not int or not 0 <= value < 2**63):
        raise ValueError("Model access identities must be nonnegative SQLite integers or None.")
    return value


def _purpose(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 128 or any(ord(char) < 32 for char in value):
        raise ValueError("Model access purpose must be nonempty text of at most 128 characters.")
    return value.strip()


def _environment_id(name: str) -> int | None:
    value = os.environ.get(_PREFIX + name, "")
    return _identifier(int(value)) if value else None


def _current() -> _AccessContext:
    context = _context.get()
    if context is not None:
        return context
    return _AccessContext(_environment_id("ACTOR"),
                          _purpose(os.environ.get(_PREFIX + "PURPOSE") or "model.read"),
                          _environment_id("OWNER"))


@contextmanager
def model_access_context(actor_id: int | None = None, purpose: str = "model.read",
                         owner_id: int | None = None) -> Iterator[None]:
    """Set trusted identities locally; nested, async and exception paths restore them."""
    token = _context.set(_AccessContext(_identifier(actor_id), _purpose(purpose), _identifier(owner_id)))
    try:
        yield
    finally:
        _context.reset(token)


def access_environment() -> dict[str, str]:
    """Return trusted context/DB settings to overlay on a fresh worker environment."""
    current = _current()
    actor = current.actor_id if current.actor_id is not None else current.owner_id
    return {
        _PREFIX + "ACTOR": "" if actor is None else str(actor),
        _PREFIX + "OWNER": "" if current.owner_id is None else str(current.owner_id),
        _PREFIX + "PURPOSE": current.purpose,
        _PREFIX + "DB_PATH": str(Path(db.DB_PATH).resolve()),
    }


def model_operation(purpose: str):
    """Set an operation purpose/bound owner while preserving a trusted outer actor."""
    purpose = _purpose(purpose)

    def decorate(function):
        signature = inspect.signature(function)

        def operation_context(args, kwargs):
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            current = _current()
            owner = bound.arguments.get("owner_id", current.owner_id)
            actor = current.actor_id if current.actor_id is not None else current.owner_id
            return model_access_context(actor_id=actor, purpose=purpose, owner_id=owner)

        if inspect.iscoroutinefunction(function):
            @wraps(function)
            async def asynchronous(*args, **kwargs):
                with operation_context(args, kwargs):
                    return await function(*args, **kwargs)
            return asynchronous

        @wraps(function)
        def synchronous(*args, **kwargs):
            with operation_context(args, kwargs):
                return function(*args, **kwargs)
        return synchronous

    return decorate


def configure_access_database_from_environment() -> None:
    """Worker-only bootstrap: select the trusted parent's registry before DB use."""
    value = os.environ.get(_PREFIX + "DB_PATH")
    if value:
        path = Path(value)
        if not path.is_absolute():
            raise ValueError("Inherited model access database path must be absolute.")
        db.DB_PATH = path


def initialize_model_access(connection: sqlite3.Connection) -> None:
    """Initialize access-only structures using the caller's transaction."""
    connection.execute("""CREATE TABLE IF NOT EXISTS model_access_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_id INTEGER, owner_id INTEGER,
        path_identity TEXT NOT NULL, path TEXT NOT NULL, purpose TEXT NOT NULL,
        occurred_at REAL NOT NULL, created_at TEXT NOT NULL,
        outcome TEXT NOT NULL CHECK(outcome IN ('attempted', 'denied', 'succeeded', 'failed'))
    )""")
    connection.execute("""CREATE INDEX IF NOT EXISTS idx_model_access_actor_window
        ON model_access_events(actor_id, occurred_at, path_identity)""")
    connection.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER REFERENCES users(id),
        event_type TEXT NOT NULL, target_type TEXT, target_id TEXT,
        details_json TEXT NOT NULL, created_at TEXT NOT NULL
    )""")
    connection.execute("""CREATE TABLE IF NOT EXISTS runtime_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER REFERENCES users(id),
        source TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
        message TEXT NOT NULL, recommendation TEXT, model_name TEXT,
        status TEXT NOT NULL DEFAULT 'open', dedupe_key TEXT, details_json TEXT NOT NULL,
        created_at TEXT NOT NULL, acknowledged_at TEXT
    )""")


@contextmanager
def model_access_transaction() -> Iterator[sqlite3.Connection]:
    """Short metadata transaction; persist limit denials even when raising to caller."""
    with closing(db.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            initialize_model_access(connection)
            yield connection
        except ModelAccessLimitError:
            connection.commit()
            raise
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()


def _limits() -> tuple[int, int]:
    limit = int(os.environ.get(_PREFIX + "DISTINCT_LIMIT", "20"))
    window = int(os.environ.get(_PREFIX + "WINDOW_SECONDS", "60"))
    if not 0 < limit < 2**31 or not 0 < window < 2**31:
        raise ValueError("Model access limit and window must be positive integers below 2**31.")
    return limit, window


def _now() -> float:
    return time.time()


def _audit(connection: sqlite3.Connection, record: ModelReadRecord, outcome: str,
           details: dict | None = None) -> None:
    payload = {"access_id": record.id, "actor_id": record.actor_id, "owner_id": record.owner_id,
               "path_identity": record.path_identity, "path": record.path,
               "purpose": record.purpose, "outcome": outcome, **(details or {})}
    connection.execute("""INSERT INTO audit_logs
        (actor_id, event_type, target_type, target_id, details_json, created_at)
        VALUES (?, ?, 'model', ?, ?, ?)""",
        (record.actor_id, "model.read." + outcome, record.path_identity, json.dumps(payload),
         datetime.fromtimestamp(_now(), timezone.utc).isoformat()))


def record_model_read(path: str | Path, owner_id: int | None = None, *, purpose: str | None = None,
                      connection: sqlite3.Connection | None = None) -> ModelReadRecord:
    """Admit/log before byte I/O. Supplied-connection audit durability is caller-owned."""
    if connection is None:
        with model_access_transaction() as transaction:
            return record_model_read(path, owner_id, purpose=purpose, connection=transaction)
    current = _current()
    owner_id = _identifier(owner_id if owner_id is not None else current.owner_id)
    actor_id = current.actor_id if current.actor_id is not None else owner_id
    purpose = _purpose(purpose if purpose is not None else current.purpose)
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValueError("Model access path must be nonempty text without NUL characters.")
    canonical = os.path.normcase(os.path.realpath(os.path.abspath(raw)))
    identity = sha256(json.dumps([owner_id, canonical]).encode("utf-8")).hexdigest()
    limit, window = _limits()
    if not connection.in_transaction:
        connection.execute("BEGIN IMMEDIATE")
    initialize_model_access(connection)
    now = _now()
    timestamp = datetime.fromtimestamp(now, timezone.utc).isoformat()
    count, known = connection.execute("""SELECT COUNT(DISTINCT path_identity),
        COALESCE(MAX(path_identity = ?), 0) FROM model_access_events
        WHERE actor_id IS ? AND occurred_at > ? AND outcome != 'denied'""",
        (identity, actor_id, now - window)).fetchone()
    distinct = count + (0 if known else 1)
    denied = distinct > limit
    outcome = "denied" if denied else "attempted"
    cursor = connection.execute("""INSERT INTO model_access_events
        (actor_id, owner_id, path_identity, path, purpose, occurred_at, created_at, outcome)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (actor_id, owner_id, identity, canonical, purpose, now, timestamp, outcome))
    record = ModelReadRecord(int(cursor.lastrowid), actor_id, owner_id, identity, canonical, purpose, timestamp)
    observed = {"distinct_models": distinct, "limit": limit, "window_seconds": window}
    _audit(connection, record, outcome, observed)
    if denied:
        dedupe = "model_access.distinct:" + str(actor_id)
        existing = connection.execute("""SELECT id FROM runtime_alerts
            WHERE owner_id IS ? AND source = 'model_access' AND dedupe_key = ?
            AND status = 'open' LIMIT 1""", (owner_id, dedupe)).fetchone()
        if existing is None:
            connection.execute("""INSERT INTO runtime_alerts
                (owner_id, source, severity, title, message, recommendation, status,
                 dedupe_key, details_json, created_at)
                VALUES (?, 'model_access', 'high', 'Unusual model access burst', ?, ?,
                        'open', ?, ?, ?)""",
                (owner_id, f"An actor attempted access to {distinct} distinct models within {window} seconds; access was denied.",
                 "Review the model-read audit and verify that this access pattern is authorized.", dedupe,
                 json.dumps({**observed, "actor_id": actor_id, "owner_id": owner_id,
                             "path_identity": identity, "purpose": purpose}), timestamp))
        raise ModelAccessLimitError(
            f"Model access denied: distinct-model limit of {limit} within {window} seconds exceeded."
        )
    return record


def finish_model_read(record: ModelReadRecord, *, succeeded: bool,
                      connection: sqlite3.Connection | None = None) -> None:
    """Record an admitted read's real completion, without charging another admission."""
    if type(succeeded) is not bool:
        raise ValueError("Model-read completion requires a boolean outcome.")
    if connection is None:
        with model_access_transaction() as transaction:
            finish_model_read(record, succeeded=succeeded, connection=transaction)
        return
    if not connection.in_transaction:
        connection.execute("BEGIN IMMEDIATE")
    initialize_model_access(connection)
    outcome = "succeeded" if succeeded else "failed"
    cursor = connection.execute("""UPDATE model_access_events SET outcome = ?
        WHERE id = ? AND actor_id IS ? AND owner_id IS ? AND path_identity = ? AND outcome = 'attempted'""",
        (outcome, record.id, record.actor_id, record.owner_id, record.path_identity))
    if cursor.rowcount != 1:
        raise ValueError("Model-read receipt is unknown or already completed.")
    _audit(connection, record, outcome)


@contextmanager
def model_read_access(path: str | Path, owner_id: int | None = None, *,
                      purpose: str | None = None) -> Iterator[ModelReadRecord]:
    """Admit, release DB locks, yield for I/O, and audit actual completion."""
    record = record_model_read(path, owner_id, purpose=purpose)
    try:
        yield record
    except BaseException:
        finish_model_read(record, succeeded=False)
        raise
    else:
        finish_model_read(record, succeeded=True)
