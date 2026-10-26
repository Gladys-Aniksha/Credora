"""Real signed-package intake must preserve immutable extraction identities."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock

import onnx
import pytest
from cryptography.fernet import Fernet
from sequence_fixtures import build_sequence_onnx

from core import db, model_package
from core.artifact_integrity import (
    ModelArtifactIntegrityError,
    assert_artifact_integrity,
    assert_registered_artifacts_in_directory,
)
from core.hashing import sha256_file
from core.model_storage import MAGIC, read_model_bytes
from scripts import run_phase1_scan as scan


class IntakeStopped(Exception):
    """Stop after package validation and baseline capture, before model assessment."""


@pytest.fixture
def project(tmp_path, monkeypatch):
    data = tmp_path / "data"
    monkeypatch.setenv("CREDORA_MODEL_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    monkeypatch.setattr(db, "DB_PATH", data / "registry.sqlite3")
    monkeypatch.setattr(scan, "DATA_DIR", data)
    monkeypatch.setattr(scan, "REPORT_DIR", tmp_path / "reports")
    db.init_db()
    owner = int(db.list_users()[0]["id"])
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    model_package.generate_signing_keypair(private, public)
    dataset = tmp_path / "test.csv"
    dataset.write_text("value,label\n1,Low\n", encoding="utf-8")
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("# Standalone ONNX\n", encoding="utf-8")
    return SimpleNamespace(root=tmp_path, data=data, owner=owner, private=private,
                           public=public, dataset=dataset, requirements=requirements)


def signed_package(project, directory, marker):
    root = project.root / directory
    root.mkdir()
    model = build_sequence_onnx(root / "model.onnx")
    graph = onnx.load(str(model))
    graph.graph.doc_string = marker
    onnx.save_model(graph, str(model))
    metadata = root / "metadata.json"
    # Intake stops before inference; tabular metadata avoids an unrelated
    # sequence-dataset compatibility check while keeping the ONNX graph valid.
    metadata.write_text(json.dumps({"model_name": marker, "version": "1",
                                    "input_type": "tabular"}), encoding="utf-8")
    package = model_package.create_signed_model_package(
        model, metadata, project.requirements, root / "same-name.credora", project.private,
    )
    return SimpleNamespace(path=package, model_bytes=model.read_bytes(), sha256=sha256_file(model))


def run_scan(project, package):
    return scan.run_phase1_scan(
        package.path, project.dataset, project.requirements,
        trusted_public_key_path=project.public, owner_id=project.owner, generate_docx=False,
    )


def registered_rows():
    with db.connect() as connection:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM model_artifact_registry ORDER BY id",
        ).fetchall()]


def run_to_baseline(project, package, monkeypatch):
    observed = {}

    def stop(model_path, metadata):
        # Assertions only: these calls cannot create a missing registration.
        binding = assert_artifact_integrity(model_path, owner_id=project.owner)
        source = assert_artifact_integrity(package.path, owner_id=project.owner)
        assert binding["sha256"] == package.sha256
        assert metadata["_signature_verified"] is True
        assert metadata["_expected_sha256"] == package.sha256
        assert metadata["_expected_sha256_source"] == "signed_package_manifest"
        assert read_model_bytes(model_path) == package.model_bytes
        assert model_path.read_bytes().startswith(MAGIC)
        expected = (project.data / "uploads" / str(project.owner) / "verified_packages"
                    / str(source["id"]) / "artifacts" / "model.onnx")
        assert model_path == expected.resolve()
        observed.update(model_path=model_path, binding=binding, source=source)
        raise IntakeStopped

    verifier = Mock(side_effect=stop)
    inference = Mock(side_effect=AssertionError("Package test reached inference"))
    monkeypatch.setattr(scan, "verify_model", verifier)
    monkeypatch.setattr(scan, "evaluate_classifier", inference)
    with pytest.raises(IntakeStopped):
        run_scan(project, package)
    verifier.assert_called_once()
    inference.assert_not_called()
    assert not (project.root / "reports").exists()
    assert db.list_scans(owner_id=project.owner) == []
    return SimpleNamespace(**observed)


def test_valid_original_package_reextraction_keeps_model_and_baselines(project, monkeypatch):
    package = signed_package(project, "original", "original signed graph")
    first = run_to_baseline(project, package, monkeypatch)
    before = registered_rows()
    assert len(before) == 2
    extraction = Mock(wraps=model_package.verify_model_package)
    monkeypatch.setattr(model_package, "verify_model_package", extraction)

    second = run_to_baseline(project, package, monkeypatch)

    extraction.assert_called_once()
    assert first.model_path == second.model_path
    assert first.binding == second.binding
    assert first.source == second.source
    assert read_model_bytes(second.model_path) == package.model_bytes
    assert second.model_path.read_bytes().startswith(MAGIC)
    assert registered_rows() == before


@pytest.mark.parametrize("change", ["tampered", "missing"])
def test_changed_extracted_model_rejects_before_extraction_without_restoration(project, monkeypatch, change):
    package = signed_package(project, "original", "original signed graph")
    first = run_to_baseline(project, package, monkeypatch)
    before = registered_rows()
    tampered = b"tampered extracted model must not be silently restored"
    if change == "tampered":
        first.model_path.write_bytes(tampered)
    else:
        first.model_path.unlink()
    archive_hash = sha256_file(package.path)
    extraction = Mock(wraps=model_package.verify_model_package)
    verifier = Mock(side_effect=AssertionError("Changed extracted model reached verification"))
    inference = Mock(side_effect=AssertionError("Changed extracted model reached inference"))
    monkeypatch.setattr(model_package, "verify_model_package", extraction)
    monkeypatch.setattr(scan, "verify_model", verifier)
    monkeypatch.setattr(scan, "evaluate_classifier", inference)

    with pytest.raises(ModelArtifactIntegrityError, match="changed since registration"):
        run_scan(project, package)

    extraction.assert_not_called()
    verifier.assert_not_called()
    inference.assert_not_called()
    if change == "tampered":
        assert first.model_path.read_bytes() == tampered
    else:
        assert not first.model_path.exists()
    assert sha256_file(package.path) == archive_hash
    assert registered_rows() == before
    assert not (project.root / "reports").exists()
    assert db.list_scans(owner_id=project.owner) == []


def test_same_basename_packages_in_different_directories_keep_independent_models(project, monkeypatch):
    left = signed_package(project, "left", "first signed graph")
    right = signed_package(project, "right", "different second signed graph")
    assert left.path.name == right.path.name
    assert left.path.parent != right.path.parent
    assert left.sha256 != right.sha256
    first = run_to_baseline(project, left, monkeypatch)
    first_rows = registered_rows()

    second = run_to_baseline(project, right, monkeypatch)

    assert first.model_path != second.model_path
    assert first.source["id"] != second.source["id"]
    assert first.binding["id"] != second.binding["id"]
    assert read_model_bytes(first.model_path) == left.model_bytes
    assert read_model_bytes(second.model_path) == right.model_bytes
    assert first.model_path.read_bytes().startswith(MAGIC)
    assert second.model_path.read_bytes().startswith(MAGIC)
    assert assert_artifact_integrity(first.binding, owner_id=project.owner) == first.binding
    assert assert_artifact_integrity(second.binding, owner_id=project.owner) == second.binding
    after = registered_rows()
    assert len(after) == 4
    assert after[:len(first_rows)] == first_rows


def test_legacy_tampered_extraction_rejects_without_restoring_or_rebaselining(project):
    # A historical numeric package basename can coincide with a new source ID.
    extract_dir = project.data / "uploads" / str(project.owner) / "verified_packages" / "1"
    model = extract_dir / "artifacts" / "model.onnx"
    model.parent.mkdir(parents=True)
    model.write_bytes(b"original historically registered model")
    original_hash = sha256_file(model)
    legacy_id = db.register_model(
        model_name="historical-package", version="1", model_path=model,
        sha256=original_hash, owner_id=project.owner,
    )
    assert registered_rows() == []
    with db.connect() as connection:
        before = [dict(row) for row in connection.execute("SELECT * FROM model_registry ORDER BY id")]
    assert [row["id"] for row in before] == [legacy_id]
    tampered = b"tampered historical bytes must remain untouched on rejection"
    model.write_bytes(tampered)

    with pytest.raises(ModelArtifactIntegrityError, match="oldest legacy registration"):
        assert_registered_artifacts_in_directory(extract_dir, owner_id=project.owner)

    assert model.read_bytes() == tampered
    assert registered_rows() == []
    with db.connect() as connection:
        after = [dict(row) for row in connection.execute("SELECT * FROM model_registry ORDER BY id")]
    assert after == before
    assert after[0]["sha256"] == original_hash
