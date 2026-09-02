from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from core.hashing import sha256_file

PACKAGE_VERSION = 1
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"
MAX_PACKAGE_BYTES = 512 * 1024 * 1024


class ModelPackageError(ValueError):
    """Raised when a model package cannot be trusted or safely extracted."""


@dataclass(frozen=True)
class VerifiedModelPackage:
    package_path: Path
    manifest: dict[str, Any]
    model_path: Path
    metadata_path: Path
    requirements_path: Path


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_signing_keypair(private_key_path: str | Path, public_key_path: str | Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)


def create_signed_model_package(
    model_path: str | Path,
    metadata_path: str | Path,
    requirements_path: str | Path,
    output_path: str | Path,
    private_key_path: str | Path,
) -> Path:
    source_paths = {
        "model": Path(model_path),
        "metadata": Path(metadata_path),
        "requirements": Path(requirements_path),
    }
    missing = [name for name, path in source_paths.items() if not path.is_file()]
    if missing:
        raise ModelPackageError(f"Missing package artifact(s): {', '.join(missing)}")

    package_entries = {
        "model": f"artifacts/model{source_paths['model'].suffix.lower()}",
        "metadata": "artifacts/metadata.json",
        "requirements": "artifacts/requirements.txt",
    }
    artifacts = {}
    for name, path in source_paths.items():
        artifacts[name] = {
            "path": package_entries[name],
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }

    manifest = {
        "package_version": PACKAGE_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "signature_algorithm": "Ed25519",
        "artifacts": artifacts,
    }
    manifest_bytes = _canonical_json(manifest)
    private_key = serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ModelPackageError("The signing key must be an Ed25519 private key.")
    signature = private_key.sign(manifest_bytes)

    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(target, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(MANIFEST_NAME, manifest_bytes)
        archive.writestr(SIGNATURE_NAME, base64.b64encode(signature))
        for name, path in source_paths.items():
            archive.write(path, package_entries[name])
    return target


def _validate_member_name(name: str) -> None:
    member = PurePosixPath(name)
    if member.is_absolute() or ".." in member.parts or "\\" in name:
        raise ModelPackageError(f"Unsafe package member path: {name}")


def verify_model_package(
    package_path: str | Path,
    trusted_public_key_path: str | Path,
    extract_dir: str | Path,
) -> VerifiedModelPackage:
    package = Path(package_path)
    if not package.is_file():
        raise ModelPackageError(f"Model package not found: {package}")
    if package.stat().st_size > MAX_PACKAGE_BYTES:
        raise ModelPackageError("Model package exceeds the 512 MB safety limit.")

    public_key = serialization.load_pem_public_key(Path(trusted_public_key_path).read_bytes())
    if not isinstance(public_key, Ed25519PublicKey):
        raise ModelPackageError("The trust key must be an Ed25519 public key.")

    destination = Path(extract_dir)
    destination.mkdir(parents=True, exist_ok=True)
    with ZipFile(package) as archive:
        infos = archive.infolist()
        for info in infos:
            _validate_member_name(info.filename)
            if info.file_size > MAX_PACKAGE_BYTES:
                raise ModelPackageError(f"Package member is too large: {info.filename}")
        names = {info.filename for info in infos}
        if MANIFEST_NAME not in names or SIGNATURE_NAME not in names:
            raise ModelPackageError("Package manifest or signature is missing.")

        manifest_bytes = archive.read(MANIFEST_NAME)
        try:
            manifest = json.loads(manifest_bytes)
            signature = base64.b64decode(archive.read(SIGNATURE_NAME), validate=True)
            public_key.verify(signature, _canonical_json(manifest))
        except (json.JSONDecodeError, InvalidSignature, ValueError) as exc:
            raise ModelPackageError("Model package signature verification failed.") from exc

        if manifest.get("package_version") != PACKAGE_VERSION:
            raise ModelPackageError(f"Unsupported package version: {manifest.get('package_version')}")
        artifacts = manifest.get("artifacts", {})
        if set(artifacts) != {"model", "metadata", "requirements"}:
            raise ModelPackageError("Package must contain model, metadata, and requirements artifacts.")

        extracted: dict[str, Path] = {}
        for name, details in artifacts.items():
            member_name = str(details.get("path", ""))
            _validate_member_name(member_name)
            if member_name not in names:
                raise ModelPackageError(f"Manifest artifact is missing: {member_name}")
            data = archive.read(member_name)
            target = destination.joinpath(*PurePosixPath(member_name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            if sha256_file(target) != details.get("sha256") or target.stat().st_size != details.get("size_bytes"):
                raise ModelPackageError(f"Artifact verification failed: {name}")
            extracted[name] = target

    return VerifiedModelPackage(
        package_path=package.resolve(),
        manifest=manifest,
        model_path=extracted["model"],
        metadata_path=extracted["metadata"],
        requirements_path=extracted["requirements"],
    )


def inspect_model_package(package_path: str | Path, trusted_public_key_path: str | Path) -> dict[str, Any]:
    with TemporaryDirectory(prefix="credora-package-") as temp_dir:
        verified = verify_model_package(package_path, trusted_public_key_path, temp_dir)
        return {
            "package_path": str(verified.package_path),
            "verified": True,
            "manifest": verified.manifest,
        }
