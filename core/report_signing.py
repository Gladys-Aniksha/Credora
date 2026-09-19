from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

REPORT_SIGNATURE_FIELD = "report_signature"
REPORT_SIGNATURE_VERSION = 1


class ReportSignatureError(ValueError):
    """Raised when a trust report signature cannot be created or verified."""


def _canonical_report_bytes(report: dict[str, Any]) -> bytes:
    unsigned = dict(report)
    unsigned.pop(REPORT_SIGNATURE_FIELD, None)
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _load_private_key(private_key_path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ReportSignatureError("The report signing key must be an Ed25519 private key.")
    return key


def _load_public_key(public_key: str | bytes | Path | Ed25519PublicKey) -> Ed25519PublicKey:
    if isinstance(public_key, Ed25519PublicKey):
        return public_key
    if isinstance(public_key, Path):
        data = public_key.read_bytes()
    elif isinstance(public_key, bytes):
        data = public_key
    else:
        text = str(public_key)
        if "-----BEGIN" in text:
            data = text.encode("utf-8")
        else:
            possible_path = Path(text)
            data = possible_path.read_bytes() if possible_path.exists() else text.encode("utf-8")
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise ReportSignatureError("The trusted report key must be an Ed25519 public key.")
    return key


def public_key_fingerprint(public_key: str | bytes | Path | Ed25519PublicKey) -> str:
    key = _load_public_key(public_key)
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def generate_report_signing_keypair(private_key_path: str | Path, public_key_path: str | Path) -> None:
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


def sign_report_dict(report: dict[str, Any], private_key_path: str | Path, signer: str | None = None) -> dict[str, Any]:
    private_key = _load_private_key(private_key_path)
    public_key = private_key.public_key()
    payload = _canonical_report_bytes(report)
    signature = private_key.sign(payload)
    signed_report = dict(report)
    signed_report[REPORT_SIGNATURE_FIELD] = {
        "version": REPORT_SIGNATURE_VERSION,
        "algorithm": "Ed25519",
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "signer": signer or "local-report-signer",
        "public_key_fingerprint": public_key_fingerprint(public_key),
    }
    return signed_report


def sign_report_file(report_path: str | Path, private_key_path: str | Path, signer: str | None = None, output_path: str | Path | None = None) -> Path:
    source = Path(report_path)
    report = json.loads(source.read_text(encoding="utf-8"))
    signed_report = sign_report_dict(report, private_key_path, signer=signer)
    target = Path(output_path) if output_path else source
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(signed_report, indent=2), encoding="utf-8")
    return target


def verify_report_dict(report: dict[str, Any], public_key: str | bytes | Path | Ed25519PublicKey) -> dict[str, Any]:
    signature_block = report.get(REPORT_SIGNATURE_FIELD)
    if not isinstance(signature_block, dict):
        return {"verified": False, "trusted": False, "reason": "Report is unsigned."}
    if signature_block.get("algorithm") != "Ed25519":
        return {"verified": False, "trusted": False, "reason": "Unsupported report signature algorithm."}

    payload = _canonical_report_bytes(report)
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    expected_sha256 = signature_block.get("payload_sha256")
    if expected_sha256 != payload_sha256:
        return {
            "verified": False,
            "trusted": False,
            "reason": "Report payload hash does not match the signed hash.",
            "expected_payload_sha256": expected_sha256,
            "actual_payload_sha256": payload_sha256,
        }

    try:
        key = _load_public_key(public_key)
        signature = base64.b64decode(str(signature_block.get("signature_b64", "")), validate=True)
        key.verify(signature, payload)
    except (InvalidSignature, ValueError, TypeError, ReportSignatureError) as exc:
        return {"verified": False, "trusted": False, "reason": f"Signature verification failed: {exc}"}

    fingerprint = public_key_fingerprint(key)
    return {
        "verified": True,
        "trusted": False,
        "reason": "Report signature is valid for the provided public key.",
        "signer": signature_block.get("signer"),
        "signed_at": signature_block.get("signed_at"),
        "public_key_fingerprint": fingerprint,
        "claimed_public_key_fingerprint": signature_block.get("public_key_fingerprint"),
        "payload_sha256": payload_sha256,
    }


def verify_report_file(report_path: str | Path, public_key_path: str | Path) -> dict[str, Any]:
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    return verify_report_dict(report, Path(public_key_path))


def verify_report_against_trusted_signers(report: dict[str, Any], trusted_signers: list[dict[str, Any]]) -> dict[str, Any]:
    signature_block = report.get(REPORT_SIGNATURE_FIELD)
    if not isinstance(signature_block, dict):
        return {"verified": False, "trusted": False, "reason": "Report is unsigned."}

    failures: list[str] = []
    for signer in trusted_signers:
        if signer.get("status", "active") != "active":
            continue
        result = verify_report_dict(report, str(signer.get("public_key_pem", "")))
        if result.get("verified"):
            result.update({
                "trusted": True,
                "trusted_signer_id": signer.get("id"),
                "trusted_signer_name": signer.get("name"),
                "reason": "Report signature is valid and matches an active trusted signer.",
            })
            return result
        if result.get("reason"):
            failures.append(str(result["reason"]))

    return {
        "verified": False,
        "trusted": False,
        "reason": "Report signature did not match any active trusted signer.",
        "verification_errors": failures[:5],
        "signer": signature_block.get("signer"),
        "signed_at": signature_block.get("signed_at"),
        "claimed_public_key_fingerprint": signature_block.get("public_key_fingerprint"),
    }

