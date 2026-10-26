from __future__ import annotations

import json

import pytest

from core.model_package import (
    ModelPackageError,
    create_signed_model_package,
    generate_signing_keypair,
    verify_model_package,
)
from core.model_storage import MAGIC, read_model_bytes


def test_signed_model_package_verifies_and_extracts(tmp_path) -> None:
    model = tmp_path / "model.joblib"
    metadata = tmp_path / "metadata.json"
    requirements = tmp_path / "requirements.txt"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    package = tmp_path / "model.credora"
    model.write_bytes(b"trusted-model")
    metadata.write_text(json.dumps({"model_name": "trusted"}), encoding="utf-8")
    requirements.write_text("scikit-learn\n", encoding="utf-8")
    generate_signing_keypair(private_key, public_key)

    create_signed_model_package(model, metadata, requirements, package, private_key)
    verified = verify_model_package(package, public_key, tmp_path / "extracted")

    assert verified.model_path.read_bytes().startswith(MAGIC)
    assert read_model_bytes(verified.model_path) == b"trusted-model"
    assert verified.manifest["signature_algorithm"] == "Ed25519"


def test_model_package_rejects_untrusted_key(tmp_path) -> None:
    model = tmp_path / "model.joblib"
    metadata = tmp_path / "metadata.json"
    requirements = tmp_path / "requirements.txt"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    wrong_private = tmp_path / "wrong-private.pem"
    wrong_public = tmp_path / "wrong-public.pem"
    package = tmp_path / "model.credora"
    model.write_bytes(b"trusted-model")
    metadata.write_text("{}", encoding="utf-8")
    requirements.write_text("joblib\n", encoding="utf-8")
    generate_signing_keypair(private_key, public_key)
    generate_signing_keypair(wrong_private, wrong_public)
    create_signed_model_package(model, metadata, requirements, package, private_key)

    with pytest.raises(ModelPackageError, match="signature verification failed"):
        verify_model_package(package, wrong_public, tmp_path / "rejected")
