"""Bounded CLI inventory/migration checks against an isolated upload registry."""
from __future__ import annotations

import base64
import hashlib
import os
import sys
from contextlib import closing
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core import db, model_storage
from core.artifact_integrity import register_or_verify_artifact
from scripts import encrypt_model_storage as migration


@pytest.fixture
def project(tmp_path, monkeypatch):
    data = tmp_path / "data"
    monkeypatch.setattr(migration, "DATA_DIR", data)
    monkeypatch.setattr(model_storage, "DATA_DIR", data)
    monkeypatch.setattr(db, "DATA_DIR", data)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "registry.sqlite3")
    monkeypatch.setenv("CREDORA_MODEL_ENCRYPTION_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"))
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DISTINCT_LIMIT", "20")
    db.init_db()
    owner = int(db.list_users()[0]["id"])
    uploads = data / "uploads" / str(owner)
    uploads.mkdir(parents=True)
    monkeypatch.setattr(sys, "argv", ["encrypt_model_storage.py"])
    return SimpleNamespace(root=tmp_path, data=data, uploads=uploads, owner=owner)


def register_legacy(path, owner, payload=b"original registered model"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    db.register_model(model_name=path.stem, version="1", model_path=path,
                      sha256=hashlib.sha256(payload).hexdigest(), owner_id=owner)
    return path


def identity_snapshot():
    with closing(db.connect()) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return {
            table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")]
            for table in ("model_registry", "model_artifact_registry", "encrypted_model_files")
            if table in tables
        }


def test_registered_inventory_unions_registries_deduplicates_and_excludes_source_fixtures(project):
    legacy = register_legacy(project.uploads / "legacy.pkl", project.owner)
    modern = project.uploads / "modern.credora"
    model_storage.write_model_bytes(modern, b"registered source package bytes", project.owner)
    register_or_verify_artifact(modern, project.owner)
    db.register_model(model_name="also-legacy", version="1", model_path=modern,
                      sha256=hashlib.sha256(b"registered source package bytes").hexdigest(), owner_id=project.owner)
    source = register_legacy(project.data / "source_fixtures" / "public.onnx", project.owner)
    before = identity_snapshot()

    inventory = migration.registered_uploads()

    assert {(path, owner) for path, owner in inventory} == {(legacy, project.owner), (modern, project.owner)}
    assert len(inventory) == 2
    assert all(path != source for path, _owner in inventory)
    assert migration.unregistered_uploads(inventory) == []
    assert identity_snapshot() == before


@pytest.mark.parametrize("name", ["legacy.onnx", "legacy.pkl", "legacy.joblib", "legacy.CREDORA"])
@pytest.mark.parametrize("apply", [False, True], ids=["dry-run", "apply"])
def test_unregistered_models_and_packages_are_flagged_without_creating_baselines(
    project, monkeypatch, capsys, name, apply,
):
    unknown = project.uploads / name
    original = b"unregistered private artifact must not acquire a baseline"
    unknown.write_bytes(original)
    (project.uploads / "test.csv").write_text("feature,label\n1,Normal\n", encoding="utf-8")
    source = project.data / "source_fixtures" / "public.onnx"
    source.parent.mkdir()
    source.write_bytes(b"public source fixture")
    before = identity_snapshot()
    migrate = Mock(side_effect=AssertionError("Unregistered artifact reached migration"))
    monkeypatch.setattr(migration, "migrate_registered_model", migrate)
    monkeypatch.setattr(sys, "argv", ["encrypt_model_storage.py", *(["--apply"] if apply else [])])

    assert migration.unregistered_uploads([]) == [unknown]
    assert migration.main() == 1

    captured = capsys.readouterr()
    assert f"UNREGISTERED: {name}" in captured.err
    assert "no original baseline exists" in captured.err
    assert "Re-upload and reassess or securely remove" in captured.err
    assert "0 candidate(s), 1 failure(s)." in captured.out
    assert "public.onnx" not in captured.err and "test.csv" not in captured.err
    assert unknown.read_bytes() == original
    assert identity_snapshot() == before
    migrate.assert_not_called()


def test_default_dry_run_lists_candidates_without_reading_or_verifying_model_bytes(project, monkeypatch, capsys):
    path = register_legacy(project.uploads / "known.onnx", project.owner)
    # Inventory is not a successful hash-verification claim, even for changed files.
    current = b"changed since original registration"
    path.write_bytes(current)
    before = identity_snapshot()
    migrate = Mock(side_effect=AssertionError("Dry run attempted migration"))
    monkeypatch.setattr(migration, "migrate_registered_model", migrate)

    assert migration.main() == 0

    captured = capsys.readouterr()
    assert f"Candidate: owner={project.owner}, known.onnx" in captured.out
    assert "No model files changed (dry run)." in captured.out
    assert "Encrypted and verified" not in captured.out
    assert not captured.err
    assert path.read_bytes() == current
    assert identity_snapshot() == before
    migrate.assert_not_called()


def test_explicit_apply_encrypts_registered_original_without_changing_legacy_hash(project, monkeypatch, capsys):
    original = b"original model for explicitly applied migration"
    path = register_legacy(project.uploads / "known.onnx", project.owner, original)
    before = identity_snapshot()["model_registry"]
    monkeypatch.setattr(sys, "argv", ["encrypt_model_storage.py", "--apply"])

    assert migration.main() == 0

    captured = capsys.readouterr()
    assert "Encrypted and verified:" in captured.out and "known.onnx" in captured.out
    assert "1 candidate(s), 0 failure(s)." in captured.out
    assert not captured.err
    assert path.read_bytes().startswith(model_storage.MAGIC)
    assert original not in path.read_bytes()
    assert model_storage.read_model_bytes(path) == original
    assert identity_snapshot()["model_registry"] == before


@pytest.mark.parametrize("key", [None, "", "not-base64", base64.urlsafe_b64encode(b"short").decode("ascii")])
def test_missing_or_invalid_key_fails_before_inventory_or_file_changes(project, monkeypatch, capsys, key):
    path = register_legacy(project.uploads / "known.onnx", project.owner)
    original = path.read_bytes()
    before = identity_snapshot()
    if key is None:
        monkeypatch.delenv("CREDORA_MODEL_ENCRYPTION_KEY", raising=False)
    else:
        monkeypatch.setenv("CREDORA_MODEL_ENCRYPTION_KEY", key)
    inventory = Mock(side_effect=AssertionError("Invalid key reached inventory"))
    monkeypatch.setattr(migration, "registered_uploads", inventory)

    with pytest.raises(model_storage.ModelStorageError, match="CREDORA_MODEL_ENCRYPTION_KEY"):
        migration.main()

    assert path.read_bytes() == original
    assert identity_snapshot() == before
    assert capsys.readouterr().out == ""
    inventory.assert_not_called()
