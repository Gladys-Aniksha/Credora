from __future__ import annotations

import base64
import hashlib
import os
from contextlib import closing

import pytest

from core import db, model_storage
from core.artifact_integrity import ModelArtifactIntegrityError, assert_artifact_integrity, register_or_verify_artifact
from core.model_access import model_access_context
from core.model_storage import MAGIC, ModelStorageError, read_model_bytes, write_model_bytes


@pytest.fixture(autouse=True)
def storage_environment(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "registry.sqlite3")
    monkeypatch.setattr(model_storage, "DATA_DIR", tmp_path / "data")
    monkeypatch.setenv("CREDORA_MODEL_ENCRYPTION_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DISTINCT_LIMIT", "20")


def test_ciphertext_at_rest_and_plaintext_hash_stable(tmp_path):
    path = tmp_path / "model.onnx"
    plaintext = b"private learned model weights" * 100
    with model_access_context(7, "scan", owner_id=7):
        write_model_bytes(path, plaintext, 7)
        binding = register_or_verify_artifact(path, 7, expected_sha256=hashlib.sha256(plaintext).hexdigest())
        assert read_model_bytes(path) == plaintext
        assert assert_artifact_integrity(binding, 7) == binding
    raw = path.read_bytes()
    assert raw.startswith(MAGIC)
    assert plaintext not in raw
    assert binding["sha256"] == hashlib.sha256(plaintext).hexdigest()
    with closing(db.connect()) as conn:
        rows = conn.execute("SELECT actor_id, details_json FROM audit_logs WHERE event_type = 'model.read.succeeded'").fetchall()
    assert rows and all(row[0] == 7 for row in rows)
    assert all("scan" in row[1] for row in rows)


@pytest.mark.parametrize("key", ["", "not-base64", base64.urlsafe_b64encode(b"short").decode()])
def test_missing_or_invalid_key_never_writes(tmp_path, monkeypatch, key):
    monkeypatch.setenv("CREDORA_MODEL_ENCRYPTION_KEY", key)
    path = tmp_path / "model.onnx"
    with pytest.raises(ModelStorageError, match="CREDORA_MODEL_ENCRYPTION_KEY"):
        write_model_bytes(path, b"secret", 1)
    assert not path.exists()


def test_wrong_key_fails_and_logs_failure(tmp_path, monkeypatch):
    path = tmp_path / "model.onnx"
    write_model_bytes(path, b"secret", 1)
    monkeypatch.setenv("CREDORA_MODEL_ENCRYPTION_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
    with pytest.raises(ModelStorageError, match="authentication failed"):
        read_model_bytes(path)
    with closing(db.connect()) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_logs WHERE event_type='model.read.failed'").fetchone()[0] == 1


def test_ciphertext_tampering_fails_before_consumer(tmp_path):
    path = tmp_path / "model.onnx"
    write_model_bytes(path, b"secret", 1)
    binding = register_or_verify_artifact(path, 1)
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 1
    path.write_bytes(raw)
    with pytest.raises(ModelArtifactIntegrityError):
        assert_artifact_integrity(binding, 1)


def test_ciphertext_cannot_move_between_paths(tmp_path):
    first, second = tmp_path / "first.onnx", tmp_path / "second.onnx"
    write_model_bytes(first, b"secret", 1)
    write_model_bytes(second, b"secret", 1)
    second.write_bytes(first.read_bytes())
    with pytest.raises(ModelStorageError, match="authentication failed"):
        read_model_bytes(second)


def test_plaintext_downgrade_is_rejected_even_with_original_bytes(tmp_path):
    path = tmp_path / "model.onnx"
    write_model_bytes(path, b"secret", 1)
    path.write_bytes(b"secret")
    with pytest.raises(ModelStorageError, match="replaced with plaintext"):
        read_model_bytes(path)


def test_atomic_write_never_publishes_plaintext(tmp_path, monkeypatch):
    path = tmp_path / "model.onnx"
    replace = model_storage.os.replace
    observed = []

    def inspect_replace(source, target):
        observed.append(source.read_bytes())
        assert source.read_bytes().startswith(MAGIC)
        replace(source, target)

    monkeypatch.setattr(model_storage.os, "replace", inspect_replace)
    write_model_bytes(path, b"secret", 1)
    assert observed and not list(tmp_path.glob(".encrypted-model-*"))


def test_existing_model_cannot_be_silently_repaired(tmp_path):
    path = tmp_path / "model.onnx"
    write_model_bytes(path, b"secret", 1)
    path.write_bytes(b"tampered")
    with pytest.raises(ModelStorageError):
        write_model_bytes(path, b"secret", 1)
    assert path.read_bytes() == b"tampered"


def test_identical_bytes_cannot_reassign_storage_owner(tmp_path):
    path = tmp_path / "model.onnx"
    write_model_bytes(path, b"secret", 1)
    with pytest.raises(ModelStorageError, match="storage identity"):
        write_model_bytes(path, b"secret", 2)


def test_explicit_legacy_migration_preserves_original_baseline(tmp_path):
    path = tmp_path / "data" / "uploads" / "1" / "model.onnx"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"original")
    with model_storage._allow_legacy_migration():
        binding = register_or_verify_artifact(path, 1)
    with pytest.raises(ModelStorageError, match="migration"):
        read_model_bytes(path)
    model_storage.migrate_registered_model(path, 1)
    assert path.read_bytes().startswith(MAGIC)
    assert read_model_bytes(path) == b"original"
    assert assert_artifact_integrity(binding, 1)["sha256"] == hashlib.sha256(b"original").hexdigest()


def test_migration_refuses_changed_or_unregistered_upload(tmp_path):
    path = tmp_path / "data" / "uploads" / "1" / "model.onnx"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"original")
    with pytest.raises(ModelStorageError, match="original server registration"):
        model_storage.migrate_registered_model(path, 1)
    with model_storage._allow_legacy_migration():
        register_or_verify_artifact(path, 1)
    path.write_bytes(b"changed")
    with pytest.raises(ModelArtifactIntegrityError):
        model_storage.migrate_registered_model(path, 1)
    assert path.read_bytes() == b"changed"


def test_failed_migration_publication_can_retry_only_with_original_bytes(tmp_path, monkeypatch):
    path = tmp_path / "data" / "uploads" / "1" / "model.onnx"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"original")
    with model_storage._allow_legacy_migration():
        binding = register_or_verify_artifact(path, 1)
    replace = model_storage.os.replace

    def failed_replace(source, target):
        raise OSError("simulated interrupted publication")

    monkeypatch.setattr(model_storage.os, "replace", failed_replace)
    with pytest.raises(OSError, match="interrupted"):
        model_storage.migrate_registered_model(path, 1)
    assert path.read_bytes() == b"original"
    with pytest.raises(ModelStorageError):
        read_model_bytes(path)
    assert not list(path.parent.glob(".encrypted-model-*"))
    monkeypatch.setattr(model_storage.os, "replace", replace)
    path.write_bytes(b"changed after interruption")
    with pytest.raises(ModelArtifactIntegrityError):
        model_storage.migrate_registered_model(path, 1)
    assert path.read_bytes() == b"changed after interruption"
    path.write_bytes(b"original")
    model_storage.migrate_registered_model(path, 1)
    assert assert_artifact_integrity(binding, 1)["sha256"] == binding["sha256"]
    assert path.read_bytes().startswith(MAGIC)
