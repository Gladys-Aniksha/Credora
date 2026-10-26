from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core.hashing import sha256_file
from core.model_access import access_environment
from core.model_storage import model_size, read_model_bytes, write_model_bytes

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
    model_bytes = read_model_bytes(source_paths["model"])
    artifacts = {}
    for name, path in source_paths.items():
        artifacts[name] = {
            "path": package_entries[name],
            "sha256": hashlib.sha256(model_bytes).hexdigest() if name == "model" else sha256_file(path),
            "size_bytes": model_size(path) if name == "model" else path.stat().st_size,
        }
    if artifacts["model"]["size_bytes"] != len(model_bytes):
        raise ModelPackageError("Model changed while creating its package.")

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
            if name == "model":
                archive.writestr(package_entries[name], model_bytes)
            else:
                archive.write(path, package_entries[name])
    return target


def _validate_member_name(name: str) -> None:
    member = PurePosixPath(name)
    if (
        not member.parts or member.is_absolute() or ".." in member.parts or "\\" in name or "\x00" in name
        or any(":" in part or part.endswith((".", " ")) for part in member.parts)
    ):
        raise ModelPackageError(f"Unsafe package member path: {name}")


def _artifact_destinations(artifacts: dict, destination: Path, names: set[str]) -> dict[str, tuple[str, Path]]:
    """Validate every output before extraction can publish either ciphertext or plaintext."""
    try:
        root = Path(os.path.normcase(str(destination.resolve())))
        outputs: dict[str, tuple[str, Path]] = {}
        member_paths: list[PurePosixPath] = []
        canonical_paths: list[Path] = []
        file_identities: set[tuple[int, int]] = set()
        for name, details in artifacts.items():
            if not isinstance(details, dict) or not isinstance(details.get("path"), str):
                raise ModelPackageError("Invalid package artifact path.")
            member_name = details["path"]
            _validate_member_name(member_name)
            if member_name not in names:
                raise ModelPackageError(f"Manifest artifact is missing: {member_name}")
            member = PurePosixPath(member_name)
            # Enforce portable case uniqueness even when inspecting an archive on Linux.
            member_key = PurePosixPath(os.path.normcase(member.as_posix()).casefold())
            target = Path(os.path.normcase(str(destination.joinpath(*member.parts).resolve())))
            if target == root or not target.is_relative_to(root):
                raise ModelPackageError("Package artifact destination escapes the extraction root.")
            if any(
                member_key == prior or member_key in prior.parents or prior in member_key.parents
                for prior in member_paths
            ) or any(
                target == prior or target in prior.parents or prior in target.parents
                for prior in canonical_paths
            ):
                raise ModelPackageError("Package artifact destinations overlap.")
            if target.exists():
                info = target.stat()
                identity = (info.st_dev, info.st_ino)
                if identity in file_identities:
                    raise ModelPackageError("Package artifact destinations overlap through an existing file.")
                file_identities.add(identity)
            member_paths.append(member_key)
            canonical_paths.append(target)
            outputs[name] = (member_name, target)
        return outputs
    except (OSError, RuntimeError) as exc:
        raise ModelPackageError("Package artifact destinations cannot be resolved safely.") from exc


def verify_model_package(
    package_path: str | Path,
    trusted_public_key_path: str | Path,
    extract_dir: str | Path,
    *,
    owner_id: int | None = None,
) -> VerifiedModelPackage:
    if owner_id is None:
        context_owner = access_environment()["CREDORA_MODEL_ACCESS_OWNER"]
        owner_id = int(context_owner) if context_owner else None
    package = Path(package_path)
    if not package.is_file():
        raise ModelPackageError(f"Model package not found: {package}")
    package_bytes = read_model_bytes(package)
    if len(package_bytes) > MAX_PACKAGE_BYTES:
        raise ModelPackageError("Model package exceeds the 512 MB safety limit.")

    public_key = serialization.load_pem_public_key(Path(trusted_public_key_path).read_bytes())
    if not isinstance(public_key, Ed25519PublicKey):
        raise ModelPackageError("The trust key must be an Ed25519 public key.")

    destination = Path(extract_dir)
    with ZipFile(BytesIO(package_bytes)) as archive:
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

        destinations = _artifact_destinations(artifacts, destination, names)
        extracted: dict[str, Path] = {}
        for name, details in artifacts.items():
            member_name, target = destinations[name]
            data = archive.read(member_name)
            if hashlib.sha256(data).hexdigest() != details.get("sha256") or len(data) != details.get("size_bytes"):
                raise ModelPackageError(f"Artifact verification failed: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            if name == "model":
                write_model_bytes(target, data, owner_id=owner_id)
            else:
                target.write_bytes(data)
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
