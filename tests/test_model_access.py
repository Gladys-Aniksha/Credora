from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

import pytest

from core import db
from core import model_access as access


@pytest.fixture(autouse=True)
def registry(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "access.sqlite3")
    for name in ("ACTOR", "OWNER", "PURPOSE", "DB_PATH", "DISTINCT_LIMIT", "WINDOW_SECONDS"):
        monkeypatch.delenv("CREDORA_MODEL_ACCESS_" + name, raising=False)
    return tmp_path


def events():
    with closing(db.connect()) as connection:
        return [dict(row) for row in connection.execute("SELECT * FROM model_access_events ORDER BY id")]


def audits():
    with closing(db.connect()) as connection:
        return [{**dict(row), "details": json.loads(row["details_json"])}
                for row in connection.execute("SELECT * FROM audit_logs ORDER BY id")]


def test_real_successful_read_audits_identity_and_never_secret_bytes(registry):
    model = registry / "model.onnx"
    model.write_bytes(b"MODEL_SECRET_BYTES_NOT_FOR_AUDIT")
    with access.model_access_context(actor_id=9, purpose="scan", owner_id=7), access.model_read_access(model, 7) as receipt:
        assert model.read_bytes() == b"MODEL_SECRET_BYTES_NOT_FOR_AUDIT"
    stored = events()
    assert stored[0]["outcome"] == "succeeded"
    assert stored[0]["actor_id"] == 9
    assert stored[0]["owner_id"] == 7
    assert stored[0]["purpose"] == "scan"
    assert stored[0]["path"] == os.path.normcase(str(model.resolve()))
    assert stored[0]["path_identity"] == receipt.path_identity
    assert len(receipt.path_identity) == 64
    assert stored[0]["created_at"].endswith("+00:00")
    logged = audits()
    assert [row["event_type"] for row in logged] == ["model.read.attempted", "model.read.succeeded"]
    assert all(row["target_type"] == "model" and row["actor_id"] == 9 for row in logged)
    assert "MODEL_SECRET_BYTES" not in json.dumps(logged)
    assert access.access_environment()["CREDORA_MODEL_ACCESS_ACTOR"] == ""


def test_attempted_and_failed_byte_reads_are_not_claimed_as_success(registry):
    path = registry / "absent.onnx"
    attempted = access.record_model_read(path, 7)
    assert events()[0]["outcome"] == "attempted"
    with pytest.raises(FileNotFoundError), access.model_read_access(path, 7):
        path.read_bytes()
    assert [row["outcome"] for row in events()] == ["attempted", "failed"]
    assert [row["details"]["outcome"] for row in audits()] == ["attempted", "attempted", "failed"]
    access.finish_model_read(attempted, succeeded=True)
    with pytest.raises(ValueError, match="already completed"):
        access.finish_model_read(attempted, succeeded=True)


def test_twenty_distinct_models_are_allowed_then_real_burst_is_denied_and_alerted(registry):
    for index in range(20):
        access.record_model_read(registry / f"model-{index}.onnx", 7)
    with pytest.raises(access.ModelAccessLimitError, match="limit of 20"):
        access.record_model_read(registry / "model-21.onnx", 7)
    assert len(events()) == 21
    assert events()[-1]["outcome"] == "denied"
    assert len(audits()) == 21
    assert audits()[-1]["event_type"] == "model.read.denied"
    assert audits()[-1]["details"]["distinct_models"] == 21
    alerts = db.list_runtime_alerts(owner_id=7)
    assert len(alerts) == 1
    assert alerts[0]["source"] == "model_access"
    assert alerts[0]["status"] == "open"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["details"]["actor_id"] == 7
    assert db.list_runtime_alerts(owner_id=8) == []
    assert any(row["id"] == alerts[0]["id"] for row in db.list_runtime_alerts(include_all=True))
    assert len(db.list_audit_logs(event_type="model.read.denied")) == 1


def test_repeated_reads_of_same_canonical_model_do_not_consume_distinct_budget(registry, monkeypatch):
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DISTINCT_LIMIT", "1")
    first = access.record_model_read(registry / "model.onnx", 7)
    for _ in range(25):
        same = access.record_model_read(registry / "subdir" / ".." / "model.onnx", 7, purpose="another-operation")
        assert same.path_identity == first.path_identity
    assert len(events()) == 26
    assert all(row["outcome"] == "attempted" for row in events())


def test_actor_budget_spans_purposes_and_owners_but_other_actors_are_independent(registry, monkeypatch):
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DISTINCT_LIMIT", "1")
    with access.model_access_context(9, "scan", owner_id=7):
        access.record_model_read(registry / "model.onnx", 7)
    with access.model_access_context(9, "export", owner_id=8), pytest.raises(access.ModelAccessLimitError):
        access.record_model_read(registry / "model.onnx", 8)
    with access.model_access_context(10, "scan", owner_id=8):
        access.record_model_read(registry / "other.onnx", 8)
    assert [row["actor_id"] for row in events()] == [9, 9, 10]
    assert events()[1]["owner_id"] == 8


def test_nested_context_restores_outer_actor_even_on_exception(registry):
    with access.model_access_context(9, "scan", owner_id=7):
        first = access.record_model_read(registry / "a.onnx")
        with pytest.raises(RuntimeError), access.model_access_context(10, "export", owner_id=8):
            second = access.record_model_read(registry / "b.onnx", purpose="download")
            raise RuntimeError("interrupted")
        third = access.record_model_read(registry / "c.onnx")
    assert (first.actor_id, first.owner_id, first.purpose) == (9, 7, "scan")
    assert (second.actor_id, second.owner_id, second.purpose) == (10, 8, "download")
    assert (third.actor_id, third.owner_id, third.purpose) == (9, 7, "scan")
    default = access.record_model_read(registry / "d.onnx", 11)
    assert (default.actor_id, default.owner_id, default.purpose) == (11, 11, "model.read")


def test_sliding_window_exact_boundary_and_denials_do_not_extend_admission(registry, monkeypatch):
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DISTINCT_LIMIT", "1")
    clock = [100.0]
    monkeypatch.setattr(access, "_now", lambda: clock[0])
    access.record_model_read(registry / "a.onnx", 7)
    clock[0] = 159.999
    with pytest.raises(access.ModelAccessLimitError):
        access.record_model_read(registry / "b.onnx", 7)
    clock[0] = 160.0
    access.record_model_read(registry / "b.onnx", 7)
    assert [row["outcome"] for row in events()] == ["attempted", "denied", "attempted"]


def test_clock_rollback_does_not_forget_later_admissions(registry, monkeypatch):
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DISTINCT_LIMIT", "1")
    clock = [100.0]
    monkeypatch.setattr(access, "_now", lambda: clock[0])
    access.record_model_read(registry / "a.onnx", 7)
    clock[0] = 90.0
    with pytest.raises(access.ModelAccessLimitError):
        access.record_model_read(registry / "b.onnx", 7)


def test_repeated_denials_audit_each_attempt_but_deduplicate_open_alert(registry, monkeypatch):
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DISTINCT_LIMIT", "1")
    access.record_model_read(registry / "a.onnx", 7)
    for index in range(3):
        with pytest.raises(access.ModelAccessLimitError):
            access.record_model_read(registry / f"blocked-{index}.onnx", 7)
    assert len(audits()) == 4
    assert len(db.list_runtime_alerts(owner_id=7)) == 1
    alert = db.list_runtime_alerts(owner_id=7)[0]
    db.acknowledge_runtime_alert(alert["id"], owner_id=7)
    with pytest.raises(access.ModelAccessLimitError):
        access.record_model_read(registry / "blocked-after-review.onnx", 7)
    assert len(db.list_runtime_alerts(owner_id=7)) == 2


def test_parallel_admission_is_atomic_and_denials_persist(registry, monkeypatch):
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DISTINCT_LIMIT", "3")

    def attempt(index):
        try:
            access.record_model_read(registry / f"model-{index}.onnx", 7)
            return True
        except access.ModelAccessLimitError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        accepted = list(pool.map(attempt, range(8)))
    assert sum(accepted) == 3
    assert [row["outcome"] for row in events()].count("denied") == 5
    assert len(audits()) == 8
    assert len(db.list_runtime_alerts(owner_id=7)) == 1


def test_db_lock_is_released_before_admitted_reader_runs(registry):
    model = registry / "model.onnx"
    model.write_bytes(b"model")
    with access.model_read_access(model, 7):
        with closing(db.connect()) as connection:
            connection.execute("PRAGMA busy_timeout = 1")
            connection.execute("BEGIN IMMEDIATE")
            connection.rollback()
        assert model.read_bytes() == b"model"


def test_supplied_connection_never_opens_a_second_connection_or_commits(registry, monkeypatch):
    with closing(db.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        monkeypatch.setattr(db, "connect", lambda: pytest.fail("must reuse supplied connection"))
        access.record_model_read(registry / "model.onnx", 7, connection=connection)
        assert connection.in_transaction
        assert connection.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0] == 1
        connection.rollback()


def test_caller_transaction_rollback_caveat_and_helper_denial_commit(registry, monkeypatch):
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DISTINCT_LIMIT", "1")
    access.record_model_read(registry / "a.onnx", 7)
    with closing(db.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(access.ModelAccessLimitError):
            access.record_model_read(registry / "b.onnx", 7, connection=connection)
        assert connection.execute("SELECT COUNT(*) FROM model_access_events").fetchone()[0] == 2
        connection.rollback()
    assert len(events()) == 1
    with pytest.raises(access.ModelAccessLimitError), access.model_access_transaction() as connection:
        access.record_model_read(registry / "b.onnx", 7, connection=connection)
    assert len(events()) == 2
    assert events()[-1]["outcome"] == "denied"


def test_real_subprocess_inherits_actor_owner_purpose_database_and_budget(registry, monkeypatch):
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DISTINCT_LIMIT", "1")
    script = (
        "import sys\n"
        "from core.model_access import configure_access_database_from_environment, record_model_read, ModelAccessLimitError\n"
        "configure_access_database_from_environment()\n"
        "try:\n"
        "    record = record_model_read(sys.argv[1])\n"
        "    print(record.actor_id, record.owner_id, record.purpose)\n"
        "except ModelAccessLimitError:\n"
        "    print('denied')\n"
    )
    with access.model_access_context(9, "worker-scan", owner_id=7):
        access.record_model_read(registry / "a.onnx", 7)
        inherited = access.access_environment()
    assert inherited["CREDORA_MODEL_ACCESS_DB_PATH"] == str(db.DB_PATH.resolve())
    for path, expected in [(registry / "b.onnx", "denied"), (registry / "a.onnx", "9 7 worker-scan")]:
        result = subprocess.run([sys.executable, "-B", "-c", script, str(path)],
            env={**os.environ, **inherited}, cwd=Path(__file__).resolve().parents[1],
            capture_output=True, text=True, timeout=30, check=False)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == expected
    assert [row["actor_id"] for row in events()] == [9, 9, 9]
    assert [row["owner_id"] for row in events()] == [7, 7, 7]
    assert [row["purpose"] for row in events()] == ["worker-scan"] * 3


def test_operation_decorator_binds_owner_and_preserves_actor(registry):
    @access.model_operation("rescan")
    def read(owner_id=None):
        return access.record_model_read(registry / "model.onnx", owner_id)

    assert read(7).actor_id == 7
    with access.model_access_context(9, "outer", owner_id=7):
        record = read(owner_id=8)
        assert (record.actor_id, record.owner_id, record.purpose) == (9, 8, "rescan")
        assert access.access_environment()["CREDORA_MODEL_ACCESS_PURPOSE"] == "outer"
    assert read.__name__ == "read"


def test_operation_preserves_explicit_and_default_shared_owner(registry):
    @access.model_operation("shared-read")
    def read(owner_id=None):
        return access.access_environment()

    @access.model_operation("inherited-read")
    def without_owner():
        return access.access_environment()

    with access.model_access_context(9, "outer", owner_id=7):
        for observed in (read(owner_id=None), read(None), read()):
            assert observed["CREDORA_MODEL_ACCESS_OWNER"] == ""
            assert observed["CREDORA_MODEL_ACCESS_ACTOR"] == "9"
            assert observed["CREDORA_MODEL_ACCESS_PURPOSE"] == "shared-read"
        assert without_owner()["CREDORA_MODEL_ACCESS_OWNER"] == "7"
        assert access.access_environment()["CREDORA_MODEL_ACCESS_OWNER"] == "7"


def test_async_contexts_are_isolated_and_operation_decorator_covers_await(registry):
    @access.model_operation("async-read")
    async def operation(owner_id):
        await asyncio.sleep(0)
        return access.record_model_read(registry / f"model-{owner_id}.onnx", owner_id)

    async def run(actor, owner):
        with access.model_access_context(actor, "request", owner_id=owner):
            return await operation(owner)

    async def run_together():
        return await asyncio.gather(run(9, 7), run(10, 8))

    first, second = asyncio.run(run_together())
    assert (first.actor_id, first.owner_id, first.purpose) == (9, 7, "async-read")
    assert (second.actor_id, second.owner_id, second.purpose) == (10, 8, "async-read")


@pytest.mark.parametrize("variable,value", [
    ("DISTINCT_LIMIT", "0"), ("DISTINCT_LIMIT", "-1"), ("DISTINCT_LIMIT", "invalid"),
    ("WINDOW_SECONDS", "0"), ("WINDOW_SECONDS", "nan"), ("WINDOW_SECONDS", "1.5"),
])
def test_invalid_policy_never_permits_byte_reader(registry, monkeypatch, variable, value):
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_" + variable, value)
    entered = False
    with pytest.raises(ValueError), access.model_read_access(registry / "model.onnx", 7):
        entered = True
    assert not entered


def test_zero_service_actor_is_preserved_and_unknown_actor_defaults_to_owner(registry):
    with access.model_access_context(0, "service", owner_id=7):
        assert access.record_model_read(registry / "a.onnx", 7).actor_id == 0
    with access.model_access_context(owner_id=7):
        assert access.record_model_read(registry / "a.onnx").actor_id == 7


@pytest.mark.parametrize("identity", [True, -1, 2**63, "7"])
def test_invalid_context_identity_rejected(identity):
    with pytest.raises(ValueError), access.model_access_context(identity, "scan"):
        pytest.fail("invalid identity context entered")
