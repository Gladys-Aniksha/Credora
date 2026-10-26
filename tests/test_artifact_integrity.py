from __future__ import annotations

import hashlib
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from core import artifact_integrity as integrity
from core import db


@pytest.fixture(autouse=True)
def isolated_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "registry.sqlite3")
    db.init_db()


@pytest.fixture
def artifact(tmp_path):
    path = tmp_path / "classifier.onnx"
    path.write_bytes(b"original uploaded model")
    return path


def _legacy(path, sha256, owner_id=7, name="same-model"):
    # Avoid init_db's historical NULL-owner reassignment when building legacy evidence.
    with db.connect() as conn:
        return conn.execute(
            """INSERT INTO model_registry (owner_id, model_name, version, model_path, sha256, created_at)
               VALUES (?, ?, '1.0', ?, ?, ?)""", (owner_id, name, str(path), sha256, db.utc_now())
        ).lastrowid


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _public(binding):
    return {key: binding[key] for key in ("id", "owner_id", "sha256")}


def _report(binding, **details):
    return {
        "model_artifact": _public(binding),
        "module_results": [{"module": "model_verification", "details": {"sha256": binding["sha256"], **details}}],
    }


def test_registration_is_stable_normalized_and_rechecked(artifact):
    binding = integrity.register_or_verify_artifact(artifact, 7)
    assert set(binding) == {"id", "owner_id", "path", "sha256"}
    assert binding["path"] == os.path.normcase(os.path.abspath(artifact))
    assert binding["sha256"] == _digest(artifact)
    assert integrity.register_or_verify_artifact(artifact.parent / "." / artifact.name, 7) == binding
    assert integrity.assert_artifact_integrity(binding, 7) == binding
    assert integrity.assert_artifact_integrity(artifact, 7) == binding
    artifact.write_bytes(b"tampered before model verification")
    for operation in (
        lambda: integrity.register_or_verify_artifact(artifact, 7),
        lambda: integrity.assert_artifact_integrity(binding, 7),
        lambda: integrity.assert_artifact_integrity(artifact, 7),
    ):
        with pytest.raises(integrity.ModelArtifactIntegrityError, match="Model artifact has changed since registration"):
            operation()
    with db.connect() as conn:
        rows = conn.execute("SELECT * FROM model_artifact_registry").fetchall()
    assert len(rows) == 1
    assert rows[0]["sha256"] == binding["sha256"]


def test_server_upload_digest_anchors_original_bytes_before_registration(artifact):
    incoming_digest = _digest(artifact)
    artifact.write_bytes(b"replaced after upload before first registration")
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="server upload digest"):
        integrity.register_or_verify_artifact(artifact, 7, expected_sha256=incoming_digest)
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM model_artifact_registry").fetchone()[0] == 0


def test_server_upload_digest_must_match_existing_baseline(artifact):
    incoming_digest = _digest(artifact)
    binding = integrity.register_or_verify_artifact(artifact, 7, expected_sha256=incoming_digest)
    assert integrity.register_or_verify_artifact(artifact, 7, expected_sha256=incoming_digest) == binding
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="server upload digest"):
        integrity.register_or_verify_artifact(artifact, 7, expected_sha256="0" * 64)
    artifact.write_bytes(b"changed file cannot supply its own replacement baseline")
    with pytest.raises(integrity.ModelArtifactIntegrityError):
        integrity.register_or_verify_artifact(artifact, 7, expected_sha256=_digest(artifact))
    with db.connect() as conn:
        row = conn.execute("SELECT sha256 FROM model_artifact_registry WHERE id = ?", (binding["id"],)).fetchone()
    assert row["sha256"] == incoming_digest


def test_invalid_server_upload_digest_creates_no_registration(artifact):
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="server upload digest is invalid"):
        integrity.register_or_verify_artifact(artifact, 7, expected_sha256="invalid")
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM model_artifact_registry").fetchone()[0] == 0


def test_new_path_with_same_model_name_is_a_valid_new_version(artifact, tmp_path):
    original_hash = _digest(artifact)
    _legacy(artifact, original_hash)
    original = integrity.register_or_verify_artifact(artifact, 7)
    new = tmp_path / "v2" / artifact.name
    new.parent.mkdir()
    new.write_bytes(b"new model version with same name")
    _legacy(new, _digest(new))
    latest = integrity.register_or_verify_artifact(new, 7)
    assert latest["id"] != original["id"]
    assert latest["sha256"] != original["sha256"]
    assert integrity.assert_artifact_integrity(original, 7) == original


def test_oldest_legacy_hash_cannot_be_replaced_by_a_newer_registration(artifact):
    _legacy(artifact, _digest(artifact))
    artifact.write_bytes(b"overwritten model")
    _legacy(artifact, _digest(artifact))
    for _ in range(2):
        with pytest.raises(integrity.ModelArtifactIntegrityError, match="oldest legacy"):
            integrity.register_or_verify_artifact(artifact, 7)
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM model_artifact_registry").fetchone()[0] == 0


@pytest.mark.parametrize("missing_hash", [None, "", "not-a-sha256"])
def test_known_legacy_without_oldest_hash_cannot_be_rebaselined(artifact, missing_hash):
    _legacy(artifact, missing_hash)
    _legacy(artifact, _digest(artifact))
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="no valid recorded hash"):
        integrity.register_or_verify_artifact(artifact, 7)


def test_legacy_exact_resolved_path_uses_oldest_hash(artifact):
    alias = artifact.parent / "subdir" / ".." / artifact.name
    _legacy(alias, _digest(artifact))
    assert integrity.register_or_verify_artifact(artifact, 7)["sha256"] == _digest(artifact)


def test_owner_scope_and_null_scope_are_exact(artifact):
    _legacy(artifact, "0" * 64, owner_id=8)
    owner = integrity.register_or_verify_artifact(artifact, 7)
    shared = integrity.register_or_verify_artifact(artifact)
    assert owner["id"] != shared["id"]
    assert shared["owner_id"] is None
    with pytest.raises(integrity.ModelArtifactIntegrityError):
        integrity.assert_artifact_integrity(owner, owner_id=None)
    with pytest.raises(integrity.ModelArtifactIntegrityError):
        integrity.assert_artifact_integrity(shared, 7)
    with pytest.raises(integrity.ModelArtifactIntegrityError):
        integrity.assert_artifact_integrity(owner, 8)
    db.init_db()
    assert integrity.assert_artifact_integrity(shared)["owner_id"] is None
    with pytest.raises(integrity.ModelArtifactIntegrityError):
        integrity.register_or_verify_artifact(artifact, 8)


def test_null_legacy_owner_does_not_mean_all_owners(artifact):
    _legacy(artifact, "0" * 64, owner_id=None)
    assert integrity.register_or_verify_artifact(artifact, 7)["sha256"] == _digest(artifact)
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="oldest legacy"):
        integrity.register_or_verify_artifact(artifact)


@pytest.mark.parametrize("owner", [None, 7])
def test_concurrent_registration_has_one_baseline(artifact, owner):
    with ThreadPoolExecutor(max_workers=4) as pool:
        bindings = list(pool.map(lambda _: integrity.register_or_verify_artifact(artifact, owner), range(4)))
    assert all(binding == bindings[0] for binding in bindings)
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM model_artifact_registry").fetchone()[0] == 1


def test_registry_rows_cannot_be_updated_or_deleted(artifact):
    integrity.register_or_verify_artifact(artifact)
    for query in ("UPDATE model_artifact_registry SET sha256 = 'new'", "DELETE FROM model_artifact_registry"):
        with db.connect() as conn, pytest.raises(sqlite3.IntegrityError, match="immutable"):
            conn.execute(query)


@pytest.mark.parametrize("owner", [None, 7])
def test_path_free_report_resolves_server_path_and_checks_hash(artifact, owner):
    binding = integrity.register_or_verify_artifact(artifact, owner)
    report = _report(binding)
    assert "path" not in report["model_artifact"]
    assert integrity.assert_report_artifact_integrity(report, owner) == binding
    report["module_results"][0]["details"]["sha256"] = "0" * 64
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="verification hash"):
        integrity.assert_report_artifact_integrity(report, owner)


def test_omitted_owner_infers_binding_but_explicit_none_remains_shared(artifact):
    binding = integrity.register_or_verify_artifact(artifact, 7)
    assert integrity.assert_artifact_integrity(_public(binding)) == binding
    assert integrity.assert_report_artifact_integrity(_report(binding)) == binding
    for operation in (
        lambda: integrity.assert_artifact_integrity(_public(binding), owner_id=None),
        lambda: integrity.assert_report_artifact_integrity(_report(binding), owner_id=None),
        lambda: integrity.assert_artifact_integrity(artifact),
    ):
        with pytest.raises(integrity.ModelArtifactIntegrityError):
            operation()


def test_omitted_owner_does_not_infer_from_legacy_model_name(artifact):
    _legacy(artifact, _digest(artifact), owner_id=7)
    report = {"model_name": "same-model", "module_results": [{"module": "model_verification", "details": {"file_name": artifact.name, "sha256": _digest(artifact)}}]}
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="Rescan"):
        integrity.assert_report_artifact_integrity(report)


@pytest.mark.parametrize("replacement", [
    {"id": None}, {"id": 9999}, {"id": 2**100}, {"id": True},
    {"sha256": "0" * 64}, {"owner_id": 8}, {"path": "other.onnx"},
])
def test_forged_report_binding_cannot_replace_server_baseline(artifact, replacement):
    binding = integrity.register_or_verify_artifact(artifact, 7)
    report = _report(binding)
    report["model_artifact"].update(replacement)
    with pytest.raises(integrity.ModelArtifactIntegrityError):
        integrity.assert_report_artifact_integrity(report, 7)
    assert integrity.assert_artifact_integrity(binding, 7) == binding


def test_missing_report_binding_id_cannot_create_registration(artifact):
    report = _report({"id": 999, "owner_id": 7, "sha256": _digest(artifact)})
    report["model_artifact"].pop("id")
    report["model_artifact"]["path"] = str(artifact)
    _legacy(artifact, _digest(artifact))
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="Rescan"):
        integrity.assert_report_artifact_integrity(report, 7)
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM model_artifact_registry").fetchone()[0] == 0


def test_path_assertion_never_registers_an_unknown_file(artifact):
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="no immutable registration"):
        integrity.assert_artifact_integrity(artifact, 7)


def test_report_rechecks_both_extracted_model_and_original_archive(artifact, tmp_path):
    source = tmp_path / "original.credora"
    source.write_bytes(b"original signed archive")
    main = integrity.register_or_verify_artifact(artifact, 7)
    archive = integrity.register_or_verify_artifact(source, 7)
    report = _report(main)
    report["model_artifact"]["source_artifact"] = _public(archive)
    verified = integrity.assert_report_artifact_integrity(report, 7)
    assert verified["source_artifact"] == archive
    assert integrity.assert_report_artifact_integrity(report) == verified
    source.write_bytes(b"modified archive")
    with pytest.raises(integrity.ModelArtifactIntegrityError):
        integrity.assert_report_artifact_integrity(report, 7)
    source.write_bytes(b"original signed archive")
    artifact.write_bytes(b"modified extracted model")
    with pytest.raises(integrity.ModelArtifactIntegrityError):
        integrity.assert_report_artifact_integrity(report, 7)


def test_report_source_cannot_claim_another_owner_or_omit_registry_id(artifact, tmp_path):
    archive = tmp_path / "original.credora"
    archive.write_bytes(b"archive")
    main = integrity.register_or_verify_artifact(artifact, 7)
    source = integrity.register_or_verify_artifact(archive, 8)
    report = _report(main)
    report["model_artifact"]["source_artifact"] = _public(source)
    with pytest.raises(integrity.ModelArtifactIntegrityError):
        integrity.assert_report_artifact_integrity(report, 7)
    report["model_artifact"]["source_artifact"] = {"owner_id": 7, "sha256": source["sha256"]}
    with pytest.raises(integrity.ModelArtifactIntegrityError):
        integrity.assert_report_artifact_integrity(report, 7)


def test_legacy_report_filename_and_hash_resolve_unique_path(artifact):
    _legacy(artifact, _digest(artifact))
    _legacy(artifact, _digest(artifact))
    report = {"module_results": [{"module": "model_verification", "details": {"file_name": artifact.name, "sha256": _digest(artifact)}}]}
    binding = integrity.assert_report_artifact_integrity(report, 7)
    assert binding["path"] == os.path.normcase(str(artifact))
    assert integrity.assert_report_artifact_integrity(report, 7) == binding
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="Rescan"):
        integrity.assert_report_artifact_integrity(report, 8)


def test_legacy_report_ambiguous_paths_fail_closed(artifact, tmp_path):
    other = tmp_path / "other" / artifact.name
    other.parent.mkdir()
    other.write_bytes(artifact.read_bytes())
    _legacy(artifact, _digest(artifact))
    _legacy(other, _digest(other))
    report = {"model_name": "same-model", "module_results": [{"module": "model_verification", "details": {"file_name": artifact.name, "sha256": _digest(artifact)}}]}
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="ambiguous"):
        integrity.assert_report_artifact_integrity(report, 7)


@pytest.mark.parametrize("details", [{}, {"sha256": "0" * 64}, {"file_name": "classifier.onnx"}])
def test_legacy_report_without_verification_evidence_fails_closed(details):
    report = {"model_name": "same-model", "module_results": [{"module": "model_verification", "details": details}]}
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="Rescan"):
        integrity.assert_report_artifact_integrity(report, 7)


def test_legacy_report_does_not_accept_newer_overwritten_hash(artifact):
    _legacy(artifact, _digest(artifact))
    artifact.write_bytes(b"overwritten")
    _legacy(artifact, _digest(artifact))
    report = {"module_results": [{"module": "model_verification", "details": {"file_name": artifact.name, "sha256": _digest(artifact)}}]}
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="oldest legacy"):
        integrity.assert_report_artifact_integrity(report, 7)


def test_symlink_retarget_rejected_even_if_target_bytes_match(artifact, tmp_path):
    other = tmp_path / "identical.onnx"
    other.write_bytes(artifact.read_bytes())
    link = tmp_path / "uploaded.onnx"
    try:
        link.symlink_to(artifact)
    except OSError:
        pytest.skip("Creating symlinks is unavailable on this Windows account")
    binding = integrity.register_or_verify_artifact(link, 7)
    assert binding["path"] == os.path.normcase(str(link))
    link.unlink()
    link.symlink_to(other)
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="canonical target"):
        integrity.assert_artifact_integrity(binding, 7)
    with pytest.raises(integrity.ModelArtifactIntegrityError):
        integrity.register_or_verify_artifact(link, 7)


def test_canonical_target_check_runs_without_symlink_privileges(artifact, tmp_path, monkeypatch):
    binding = integrity.register_or_verify_artifact(artifact, 7)
    other = tmp_path / "identical.onnx"
    other.write_bytes(artifact.read_bytes())
    original_resolve = Path.resolve

    def retargeted_resolve(path, *args, **kwargs):
        if os.path.normcase(str(path)) == binding["path"]:
            return other
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", retargeted_resolve)
    for operation in (
        lambda: integrity.assert_artifact_integrity(binding, 7),
        lambda: integrity.register_or_verify_artifact(artifact, 7),
    ):
        with pytest.raises(integrity.ModelArtifactIntegrityError, match="canonical target") as error:
            operation()
        assert str(tmp_path) not in str(error.value)


def test_change_during_hash_read_is_rejected(artifact, monkeypatch):
    original_sha256 = integrity.hashlib.sha256

    class ChangingDigest:
        def __init__(self):
            self.digest = original_sha256()

        def update(self, chunk):
            self.digest.update(chunk)
            artifact.write_bytes(b"modified during read with different size")

        def hexdigest(self):
            return self.digest.hexdigest()

    monkeypatch.setattr(integrity.hashlib, "sha256", ChangingDigest)
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="while reading"):
        integrity.register_or_verify_artifact(artifact, 7)


def test_size_limit_and_missing_file_fail_closed(artifact, monkeypatch):
    binding = integrity.register_or_verify_artifact(artifact, 7)
    monkeypatch.setattr(integrity, "MAX_UPLOAD_BYTES", 4)
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="size limit"):
        integrity.assert_artifact_integrity(binding, 7)
    artifact.unlink()
    with pytest.raises(integrity.ModelArtifactIntegrityError, match="unavailable"):
        integrity.assert_artifact_integrity(binding, 7)
