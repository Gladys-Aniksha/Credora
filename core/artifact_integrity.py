from __future__ import annotations

import hashlib
import hmac
import os
import stat
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path
from typing import Any, NoReturn

from core import db
from core.config import MAX_UPLOAD_BYTES
from core.model_storage import read_model_bytes
from core.model_access import ModelAccessLimitError


class ModelArtifactIntegrityError(ValueError):
    """The registered artifact or its claimed identity could not be verified."""


class _OmittedOwner:
    pass


_OMITTED_OWNER = _OmittedOwner()


def _fail(reason: str) -> NoReturn:
    raise ModelArtifactIntegrityError(
        f"Model artifact has changed since registration. {reason} Rescan the original artifact."
    )


def _path(path: str | Path) -> str:
    if not isinstance(path, (str, Path)) or not os.fspath(path) or "\x00" in os.fspath(path):
        raise ValueError("Invalid artifact path")
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _owner(owner_id: int | None) -> int | None:
    if owner_id is not None and (type(owner_id) is not int or not 0 <= owner_id < 2**63):
        _fail("Invalid artifact owner.")
    return owner_id


def _assertion_owner(owner_id: int | None | _OmittedOwner, binding: Any) -> int | None:
    if owner_id is _OMITTED_OWNER:
        owner_id = binding.get("owner_id") if isinstance(binding, Mapping) else None
    return _owner(owner_id)


def _valid_hash(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _identity(info: os.stat_result) -> tuple:
    # Windows stat/fstat can disagree on creation time even for the same file.
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _snapshot(path: str) -> tuple[str, str]:
    """Hash a bounded regular file and reject path/descriptor changes during the read."""
    try:
        target = _path(Path(path).resolve(strict=True))
        before = os.stat(path)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_UPLOAD_BYTES + 128:
            _fail("Artifact is not a regular file within the upload size limit.")
        digest = hashlib.sha256()
        data = read_model_bytes(path)
        if len(data) > MAX_UPLOAD_BYTES:
            _fail("Artifact exceeds the upload size limit.")
        digest.update(data)
        if _identity(before) != _identity(os.stat(path)) or target != _path(Path(path).resolve(strict=True)):
            _fail("Artifact path changed while reading it.")
        return target, digest.hexdigest()
    except (OSError, RuntimeError, ValueError) as exc:
        if isinstance(exc, (ModelArtifactIntegrityError, ModelAccessLimitError)):
            raise
        _fail("Artifact is unavailable or unreadable.")


def _binding(row: Mapping) -> dict[str, Any]:
    return {"id": row["id"], "owner_id": row["owner_id"], "path": row["artifact_path"], "sha256": row["sha256"]}


def _legacy_rows(conn, owner_id: int | None) -> list:
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'model_registry'").fetchone():
        return []
    return conn.execute(
        "SELECT id, model_path, sha256 FROM model_registry WHERE owner_id IS ? ORDER BY id ASC", (owner_id,)
    ).fetchall()


def _legacy_match(row, lexical: str, target: str) -> bool:
    if not row["model_path"]:
        return False
    try:
        return _path(row["model_path"]) == lexical or _path(Path(row["model_path"]).resolve()) == target
    except (OSError, RuntimeError, ValueError):
        return False


def _verify_row(row) -> dict[str, Any]:
    target, actual = _snapshot(row["artifact_path"])
    if target != row["resolved_path"] or not hmac.compare_digest(actual, row["sha256"]):
        _fail("The file or its canonical target no longer matches the immutable baseline.")
    return _binding(row)


def register_or_verify_artifact(
    path: str | Path, owner_id: int | None = None, *, expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Capture/verify once per path and owner; expected_sha256 must come from server upload bytes."""
    owner_id = _owner(owner_id)
    if expected_sha256 is not None and not _valid_hash(expected_sha256):
        _fail("The server upload digest is invalid.")
    try:
        lexical = _path(path)
    except (TypeError, ValueError):
        _fail("Invalid artifact path.")
    # Model reads write their own audit transaction. Never hold a registry write
    # lock across a read, or a worker/audit connection would deadlock.
    target, actual = _snapshot(lexical)
    if expected_sha256 is not None and not hmac.compare_digest(expected_sha256, actual):
        _fail("The file does not match the server upload digest.")
    with closing(db.connect()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        db._init_artifact_registry(conn)
        row = conn.execute(
            "SELECT * FROM model_artifact_registry WHERE owner_id IS ? AND artifact_path = ?", (owner_id, lexical)
        ).fetchone()
        if row is not None:
            if row["sha256"] != actual or row["resolved_path"] != target:
                _fail("The file or its canonical target no longer matches the immutable baseline.")
        else:
            legacy = next((item for item in _legacy_rows(conn, owner_id) if _legacy_match(item, lexical, target)), None)
            expected = actual if legacy is None else legacy["sha256"]
            if not _valid_hash(expected):
                _fail("The oldest legacy registration has no valid recorded hash.")
            if not hmac.compare_digest(actual, expected):
                _fail("The file does not match its oldest legacy registration.")
            cursor = conn.execute(
                """INSERT INTO model_artifact_registry (owner_id, artifact_path, resolved_path, sha256, created_at)
                   VALUES (?, ?, ?, ?, ?)""", (owner_id, lexical, target, expected, db.utc_now())
            )
            row = conn.execute("SELECT * FROM model_artifact_registry WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _verify_row(row)


def assert_artifact_integrity(
    binding: Mapping | str | Path, owner_id: int | None | _OmittedOwner = _OMITTED_OWNER,
) -> dict[str, Any]:
    """Verify by ID/path. Omitted owners infer mapping ownership; explicit None is shared only."""
    owner_id = _assertion_owner(owner_id, binding)
    with closing(db.connect()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        db._init_artifact_registry(conn)
        if isinstance(binding, Mapping):
            if (
                type(binding.get("id")) is not int or not 0 < binding["id"] < 2**63
                or "owner_id" not in binding or _owner(binding["owner_id"]) != owner_id
            ):
                _fail("Invalid artifact binding or owner.")
            row = conn.execute(
                "SELECT * FROM model_artifact_registry WHERE id = ? AND owner_id IS ?", (binding["id"], owner_id)
            ).fetchone()
            if row is None or not _valid_hash(binding.get("sha256")) or binding["sha256"] != row["sha256"]:
                _fail("Artifact binding is not registered for this owner.")
            if "path" in binding:
                try:
                    matches = _path(binding["path"]) == row["artifact_path"]
                except (TypeError, ValueError):
                    matches = False
                if not matches:
                    _fail("Artifact binding path does not match the server registry.")
        else:
            try:
                lexical = _path(binding)
            except (TypeError, ValueError):
                _fail("Invalid artifact path.")
            row = conn.execute(
                "SELECT * FROM model_artifact_registry WHERE owner_id IS ? AND artifact_path = ?", (owner_id, lexical)
            ).fetchone()
            if row is None:
                _fail("Artifact has no immutable registration.")
    return _verify_row(row)


def _verification_details(report: Mapping) -> Mapping:
    results = report.get("module_results")
    if not isinstance(results, list):
        _fail("Report has no model verification evidence.")
    details = [result.get("details") for result in results if isinstance(result, Mapping) and result.get("module") == "model_verification"]
    if len(details) != 1 or not isinstance(details[0], Mapping) or not _valid_hash(details[0].get("sha256")):
        _fail("Report model verification evidence is missing or ambiguous.")
    return details[0]


def assert_registered_artifacts_in_directory(
    directory: str | Path, owner_id: int | None = None,
) -> None:
    """Check existing extraction identities before verified package extraction writes."""
    owner_id = _owner(owner_id)
    root = Path(_path(directory))
    with closing(db.connect()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        db._init_artifact_registry(conn)
        rows = conn.execute(
            "SELECT * FROM model_artifact_registry WHERE owner_id IS ?", (owner_id,)
        ).fetchall()
        paths = {row["artifact_path"] for row in rows}
        for row in _legacy_rows(conn, owner_id):
            if row["model_path"]:
                try:
                    paths.add(_path(row["model_path"]))
                except (OSError, RuntimeError, ValueError):
                    continue
    # Legacy registrations must also be checked before extraction can overwrite
    # their bytes; migration must never anchor the already restored file instead.
    for path in paths:
        if Path(path).is_relative_to(root):
            register_or_verify_artifact(path, owner_id=owner_id)


def assert_report_artifact_integrity(
    report: Mapping, owner_id: int | None | _OmittedOwner = _OMITTED_OWNER,
) -> dict[str, Any]:
    """Verify path-free bindings. Omitted owners infer new bindings, never legacy model names."""
    if not isinstance(report, Mapping):
        _fail("Invalid report.")
    owner_id = _assertion_owner(owner_id, report.get("model_artifact"))
    details = _verification_details(report)
    if "model_artifact" in report:
        claimed = report["model_artifact"]
        if not isinstance(claimed, Mapping):
            _fail("Invalid report artifact binding.")
        verified = assert_artifact_integrity(claimed, owner_id)
        if verified["sha256"] != details["sha256"]:
            _fail("Report verification hash does not match its artifact binding.")
        if "source_artifact" in claimed:
            source = claimed["source_artifact"]
            if not isinstance(source, Mapping) or "source_artifact" in source:
                _fail("Invalid source artifact binding.")
            verified["source_artifact"] = assert_artifact_integrity(source, owner_id)
        return verified

    # Legacy reports carry a filename and observed hash, never a trusted model-name baseline.
    filename = details.get("file_name")
    explicit_path = details.get("model_path", details.get("path"))
    if not isinstance(filename, str) or not filename or Path(filename).name != filename:
        _fail("Legacy report lacks an unambiguous artifact filename.")
    with closing(db.connect()) as conn, conn:
        candidates = {
            _path(row["model_path"])
            for row in _legacy_rows(conn, owner_id)
            if row["model_path"] and row["sha256"] == details["sha256"] and Path(row["model_path"]).name == filename
        }
    if explicit_path is not None:
        try:
            candidates &= {_path(explicit_path)}
        except (TypeError, ValueError):
            _fail("Legacy report has an invalid artifact path.")
    if len(candidates) != 1:
        _fail("Legacy report artifact is missing or ambiguous in this owner's registry.")
    verified = register_or_verify_artifact(candidates.pop(), owner_id)
    if verified["sha256"] != details["sha256"]:
        _fail("Legacy report hash does not match the immutable baseline.")
    return verified
