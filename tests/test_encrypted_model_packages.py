from __future__ import annotations

import base64
import hashlib
import json
import os
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization

from core import db, model_package, model_storage
from core.model_access import model_access_context


@pytest.fixture(autouse=True)
def encryption_key(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "registry.sqlite3")
    monkeypatch.setenv("CREDORA_MODEL_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))


@pytest.fixture
def inputs(tmp_path):
    model = tmp_path / "model.joblib"
    metadata = tmp_path / "metadata.json"
    requirements = tmp_path / "requirements.txt"
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    metadata.write_text('{"model_name":"encrypted-package-test"}', encoding="utf-8")
    requirements.write_text("joblib\n", encoding="utf-8")
    model_package.generate_signing_keypair(private, public)
    return SimpleNamespace(
        model=model, metadata=metadata, requirements=requirements, private=private, public=public,
        package=tmp_path / "model.credora", payload=b"logical model bytes: never extract this as plaintext",
        root=tmp_path,
    )


def _create(inputs, *, encrypted_model=True):
    if encrypted_model:
        model_storage.write_model_bytes(inputs.model, inputs.payload)
    else:
        inputs.model.write_bytes(inputs.payload)
    return model_package.create_signed_model_package(
        inputs.model, inputs.metadata, inputs.requirements, inputs.package, inputs.private,
    )


def _encrypted_package(inputs, package):
    target = inputs.root / "encrypted.credora"
    model_storage.write_model_bytes(target, package.read_bytes())
    return target


def _resign(inputs, entries, manifest):
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    private_key = serialization.load_pem_private_key(inputs.private.read_bytes(), password=None)
    entries[model_package.MANIFEST_NAME] = manifest_bytes
    entries[model_package.SIGNATURE_NAME] = base64.b64encode(private_key.sign(manifest_bytes))
    with ZipFile(inputs.package, "w", compression=ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


@pytest.mark.parametrize("alias", [
    "requirements-model", "metadata-model", "metadata-requirements", "case", "dot", "ancestor", "reverse-ancestor",
])
def test_signed_artifact_aliases_are_rejected_before_any_extraction_write(inputs, monkeypatch, alias):
    package = _create(inputs)
    with ZipFile(package) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    manifest = json.loads(entries[model_package.MANIFEST_NAME])
    artifacts = manifest["artifacts"]
    if alias in {"requirements-model", "metadata-model", "metadata-requirements"}:
        destination, source = alias.split("-")
        artifacts[destination] = dict(artifacts[source])
    else:
        if alias == "case":
            member = "artifacts/MODEL.joblib"
        elif alias == "dot":
            member = "artifacts/./model.joblib"
        elif alias == "ancestor":
            member = "artifacts/model.joblib/requirements.txt"
        else:
            member = "artifacts"
        artifacts["requirements"] = {**artifacts["model"], "path": member}
        entries[member] = inputs.payload
    _resign(inputs, entries, manifest)
    writer = Mock()
    plaintext_writer = Mock()
    monkeypatch.setattr(model_package, "write_model_bytes", writer)
    monkeypatch.setattr(Path, "write_bytes", plaintext_writer)
    output = inputs.root / "rejected-alias"
    with pytest.raises(model_package.ModelPackageError, match="destinations overlap"):
        model_package.verify_model_package(package, inputs.public, output)
    writer.assert_not_called()
    plaintext_writer.assert_not_called()
    assert not output.exists()


@pytest.mark.parametrize("redirect", ["escape", "overlap"])
def test_resolved_destination_alias_or_escape_is_rejected_before_any_extraction_write(inputs, monkeypatch, redirect):
    package = _create(inputs)
    output = inputs.root / "rejected-escape"
    redirected = output / "artifacts" / "requirements.txt"
    original_resolve = Path.resolve

    def resolve_with_escape(path, *args, **kwargs):
        if path == redirected:
            if redirect == "overlap":
                return output / "artifacts" / "model.joblib"
            return inputs.root / "outside.txt"
        return original_resolve(path, *args, **kwargs)

    writer = Mock()
    plaintext_writer = Mock()
    monkeypatch.setattr(Path, "resolve", resolve_with_escape)
    monkeypatch.setattr(model_package, "write_model_bytes", writer)
    monkeypatch.setattr(Path, "write_bytes", plaintext_writer)
    reason = "escapes the extraction root" if redirect == "escape" else "destinations overlap"
    with pytest.raises(model_package.ModelPackageError, match=reason):
        model_package.verify_model_package(package, inputs.public, output)
    writer.assert_not_called()
    plaintext_writer.assert_not_called()
    assert not output.exists()
    assert not (inputs.root / "outside.txt").exists()


def test_existing_hardlink_alias_is_rejected_before_any_extraction_write(inputs, monkeypatch):
    package = _create(inputs)
    output = inputs.root / "rejected-hardlink"
    artifacts = output / "artifacts"
    artifacts.mkdir(parents=True)
    model = artifacts / "model.joblib"
    model.write_bytes(b"existing shared file must remain untouched")
    requirements = artifacts / "requirements.txt"
    try:
        os.link(model, requirements)
    except OSError:
        pytest.skip("Hard links are unavailable on this filesystem")
    before = model.read_bytes()
    writer = Mock()
    plaintext_writer = Mock()
    monkeypatch.setattr(model_package, "write_model_bytes", writer)
    monkeypatch.setattr(Path, "write_bytes", plaintext_writer)
    with pytest.raises(model_package.ModelPackageError, match="destinations overlap"):
        model_package.verify_model_package(package, inputs.public, output)
    writer.assert_not_called()
    plaintext_writer.assert_not_called()
    assert model.read_bytes() == requirements.read_bytes() == before
    assert not (artifacts / "metadata.json").exists()


@pytest.mark.parametrize("encrypted_model", [False, True])
def test_signed_package_contains_logical_model_bytes_and_plaintext_hashes(inputs, encrypted_model):
    package = _create(inputs, encrypted_model=encrypted_model)
    with ZipFile(package) as archive:
        manifest = json.loads(archive.read(model_package.MANIFEST_NAME))
        entry = manifest["artifacts"]["model"]
        assert archive.read(entry["path"]) == inputs.payload
        assert entry["sha256"] == hashlib.sha256(inputs.payload).hexdigest()
        assert entry["size_bytes"] == len(inputs.payload)
        assert archive.read(manifest["artifacts"]["metadata"]["path"]) == inputs.metadata.read_bytes()
        assert archive.read(manifest["artifacts"]["requirements"]["path"]) == inputs.requirements.read_bytes()
    if encrypted_model:
        assert inputs.model.read_bytes() != inputs.payload


@pytest.mark.parametrize("encrypted_package", [False, True])
def test_verification_encrypts_only_model_and_reads_encrypted_packages(inputs, encrypted_package, monkeypatch):
    package = _create(inputs)
    if encrypted_package:
        package = _encrypted_package(inputs, package)
        assert not package.read_bytes().startswith(b"PK")
    original_write_bytes = type(inputs.model).write_bytes

    def reject_plaintext_model(path, data):
        assert data != inputs.payload, "Model bytes were written to a plaintext extraction file"
        return original_write_bytes(path, data)

    monkeypatch.setattr(type(inputs.model), "write_bytes", reject_plaintext_model)
    output = inputs.root / "extracted"
    verified = model_package.verify_model_package(package, inputs.public, output)
    assert model_storage.read_model_bytes(verified.model_path) == inputs.payload
    assert verified.model_path.read_bytes() != inputs.payload
    assert model_storage.model_size(verified.model_path) == len(inputs.payload)
    assert verified.metadata_path.read_bytes() == inputs.metadata.read_bytes()
    assert verified.requirements_path.read_bytes() == inputs.requirements.read_bytes()
    for path in output.rglob("*"):
        if path.is_file():
            assert path.read_bytes() != inputs.payload


@pytest.mark.parametrize("mismatch", ["sha256", "size_bytes"])
def test_member_digest_and_size_are_verified_before_model_storage_write(inputs, mismatch, monkeypatch):
    package = _create(inputs)
    with ZipFile(package) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    manifest = json.loads(entries[model_package.MANIFEST_NAME])
    model = manifest["artifacts"]["model"]
    model[mismatch] = "0" * 64 if mismatch == "sha256" else len(inputs.payload) + 1
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    private_key = serialization.load_pem_private_key(inputs.private.read_bytes(), password=None)
    entries[model_package.MANIFEST_NAME] = manifest_bytes
    entries[model_package.SIGNATURE_NAME] = base64.b64encode(private_key.sign(manifest_bytes))
    with ZipFile(package, "w", compression=ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    writer = Mock()
    monkeypatch.setattr(model_package, "write_model_bytes", writer)
    output = inputs.root / "rejected"
    with pytest.raises(model_package.ModelPackageError, match="Artifact verification failed: model"):
        model_package.verify_model_package(package, inputs.public, output)
    writer.assert_not_called()
    assert not (output / model["path"]).exists()


def test_verifier_forwards_explicit_model_owner(inputs, monkeypatch):
    package = _create(inputs)
    writer = Mock(wraps=model_package.write_model_bytes)
    monkeypatch.setattr(model_package, "write_model_bytes", writer)
    verified = model_package.verify_model_package(package, inputs.public, inputs.root / "owned", owner_id=42)
    writer.assert_called_once_with(verified.model_path, inputs.payload, owner_id=42)
    assert model_storage.read_model_bytes(verified.model_path) == inputs.payload
    with db.connect() as connection:
        assert connection.execute("SELECT owner_id FROM encrypted_model_files WHERE owner_id = 42").fetchone()[0] == 42


@pytest.mark.parametrize("owner_kwargs,expected_owner", [
    ({}, 42), ({"owner_id": None}, 42), ({"owner_id": 17}, 17),
])
def test_verifier_inherits_trusted_scan_owner_without_upstream_keyword(inputs, owner_kwargs, expected_owner):
    package = _create(inputs)
    with model_access_context(actor_id=42, purpose="scan", owner_id=42):
        verified = model_package.verify_model_package(
            package, inputs.public, inputs.root / "context-owned", **owner_kwargs,
        )
    assert model_storage.read_model_bytes(verified.model_path) == inputs.payload
    with db.connect() as connection:
        rows = connection.execute(
            "SELECT owner_id FROM encrypted_model_files WHERE artifact_path = ?",
            (model_storage._path(verified.model_path),),
        ).fetchall()
    assert len(rows) == 1
    assert rows[0]["owner_id"] == expected_owner


def test_package_size_limit_uses_logical_archive_size(inputs, monkeypatch):
    package = _create(inputs)
    logical_size = len(package.read_bytes())
    package = _encrypted_package(inputs, package)
    assert package.stat().st_size > logical_size
    monkeypatch.setattr(model_package, "MAX_PACKAGE_BYTES", logical_size)
    verified = model_package.verify_model_package(package, inputs.public, inputs.root / "within-limit")
    assert model_storage.read_model_bytes(verified.model_path) == inputs.payload
    monkeypatch.setattr(model_package, "MAX_PACKAGE_BYTES", logical_size - 1)
    with pytest.raises(model_package.ModelPackageError, match="safety limit"):
        model_package.verify_model_package(package, inputs.public, inputs.root / "over-limit")


def test_inspection_temporary_model_is_encrypted(inputs, monkeypatch):
    package = _create(inputs)
    package = _encrypted_package(inputs, package)
    written_paths = []
    original_write = model_package.write_model_bytes

    def encrypted_write(path, data, owner_id=None):
        original_write(path, data, owner_id=owner_id)
        assert path.read_bytes() != inputs.payload
        assert model_storage.read_model_bytes(path) == inputs.payload
        written_paths.append(path)

    monkeypatch.setattr(model_package, "write_model_bytes", encrypted_write)
    inspected = model_package.inspect_model_package(package, inputs.public)
    assert inspected["verified"] is True
    assert len(written_paths) == 1
    assert not written_paths[0].exists()


def test_encrypted_input_can_be_repackaged_without_nesting_ciphertext(inputs):
    first = _create(inputs)
    extracted = model_package.verify_model_package(first, inputs.public, inputs.root / "first")
    repackaged = model_package.create_signed_model_package(
        extracted.model_path, extracted.metadata_path, extracted.requirements_path,
        inputs.root / "repackaged.credora", inputs.private,
    )
    with ZipFile(BytesIO(repackaged.read_bytes())) as archive:
        manifest = json.loads(archive.read(model_package.MANIFEST_NAME))
        assert archive.read(manifest["artifacts"]["model"]["path"]) == inputs.payload
    verified = model_package.verify_model_package(repackaged, inputs.public, inputs.root / "second")
    assert model_storage.read_model_bytes(verified.model_path) == inputs.payload


def test_invalid_package_signature_never_writes_model(inputs, monkeypatch):
    package = _create(inputs)
    wrong_private = inputs.root / "wrong-private.pem"
    wrong_public = inputs.root / "wrong-public.pem"
    model_package.generate_signing_keypair(wrong_private, wrong_public)
    writer = Mock()
    monkeypatch.setattr(model_package, "write_model_bytes", writer)
    with pytest.raises(model_package.ModelPackageError, match="signature verification failed"):
        model_package.verify_model_package(package, wrong_public, inputs.root / "rejected")
    writer.assert_not_called()


def test_extraction_requires_explicit_encryption_key_without_plaintext_fallback(inputs, monkeypatch):
    package = _create(inputs, encrypted_model=False)
    monkeypatch.delenv("CREDORA_MODEL_ENCRYPTION_KEY", raising=False)
    output = inputs.root / "missing-key"
    with pytest.raises(model_storage.ModelStorageError, match="CREDORA_MODEL_ENCRYPTION_KEY"):
        model_package.verify_model_package(package, inputs.public, output)
    assert not (output / "artifacts" / "model.joblib").exists()
