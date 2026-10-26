from __future__ import annotations

import base64
import binascii
from hashlib import sha256
import hmac
import os
import stat
import struct
import tempfile
from contextlib import closing, contextmanager
from contextvars import ContextVar
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core import db
from core.config import DATA_DIR, MAX_UPLOAD_BYTES

MAGIC = b"CREDORA-AESGCM\x01"
_HEADER = struct.Struct(">qQ")
_OVERHEAD = len(MAGIC) + _HEADER.size + 12 + 16
_legacy_migration: ContextVar[bool] = ContextVar("legacy_model_migration", default=False)


class ModelStorageError(ValueError):
    """An encrypted artifact cannot be stored or authenticated safely."""


def require_model_encryption_key() -> bytes:
    value = os.environ.get("CREDORA_MODEL_ENCRYPTION_KEY", "").strip()
    try:
        key = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ModelStorageError("CREDORA_MODEL_ENCRYPTION_KEY must be a URL-safe base64 encoded 32-byte key.") from exc
    if not value or len(key) != 32:
        raise ModelStorageError("CREDORA_MODEL_ENCRYPTION_KEY must be set to a URL-safe base64 encoded 32-byte key; no default is provided.")
    return key


def _path(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _init(conn) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS encrypted_model_files (
        artifact_path TEXT PRIMARY KEY, owner_id INTEGER, sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL)""")
    for operation in ("UPDATE", "DELETE"):
        conn.execute(f"""CREATE TRIGGER IF NOT EXISTS encrypted_files_{operation.lower()}
            BEFORE {operation} ON encrypted_model_files
            BEGIN SELECT RAISE(ABORT, 'Encrypted artifact identities are immutable'); END""")


def _record(path: str):
    with closing(db.connect()) as conn, conn:
        _init(conn)
        return conn.execute("SELECT * FROM encrypted_model_files WHERE artifact_path = ?", (path,)).fetchone()


def _raw_bytes(path: Path) -> bytes:
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_UPLOAD_BYTES + _OVERHEAD:
        raise ModelStorageError("Model artifact is not a bounded regular file.")
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if identity(before) != identity(opened):
            raise ModelStorageError("Model artifact changed while opening it.")
        payload = stream.read(MAX_UPLOAD_BYTES + _OVERHEAD + 1)
        after = os.fstat(stream.fileno())
    if len(payload) > MAX_UPLOAD_BYTES + _OVERHEAD or identity(opened) != identity(after) or opened.st_ctime_ns != after.st_ctime_ns or identity(after) != identity(path.stat()):
        raise ModelStorageError("Model artifact changed while reading it.")
    return payload


def read_model_bytes(path: str | Path) -> bytes:
    """Read authenticated plaintext into memory, never a temporary model file."""
    from core.model_access import model_read_access

    lexical = _path(path)
    record = _record(lexical)
    owner_id = record["owner_id"] if record is not None else None
    with model_read_access(lexical, owner_id):
        return _decode(path, lexical, record, owner_id)


def _decode(path, lexical, record, owner_id) -> bytes:
    raw = _raw_bytes(Path(path))
    if not raw.startswith(MAGIC):
        if record is not None:
            # Explicit migration can recover a failed ciphertext publication,
            # but only with the original hash. Ordinary reads still fail closed.
            if not _legacy_migration.get() or not hmac.compare_digest(sha256(raw).hexdigest(), record["sha256"]):
                raise ModelStorageError("Encrypted model artifact was replaced with plaintext or invalid ciphertext.")
        if Path(lexical).is_relative_to((DATA_DIR / "uploads").resolve()) and not _legacy_migration.get():
            raise ModelStorageError("Stored plaintext model requires explicit verified encryption migration before use.")
        # Development fixtures remain source files, not protected user uploads.
        return raw
    if len(raw) < _OVERHEAD:
        raise ModelStorageError("Encrypted model artifact is truncated.")
    offset = len(MAGIC)
    header = raw[offset:offset + _HEADER.size]
    owner_value, size = _HEADER.unpack(header)
    if size > MAX_UPLOAD_BYTES:
        raise ModelStorageError("Encrypted model exceeds the upload size limit.")
    if record is None or owner_value != (-1 if owner_id is None else owner_id):
        raise ModelStorageError("Encrypted model has no matching storage identity.")
    offset += _HEADER.size
    nonce = raw[offset:offset + 12]
    aad = MAGIC + header + lexical.encode("utf-8")
    try:
        plaintext = AESGCM(require_model_encryption_key()).decrypt(nonce, raw[offset + 12:], aad)
    except InvalidTag as exc:
        raise ModelStorageError("Encrypted model authentication failed; the key, path, or artifact has changed.") from exc
    if len(plaintext) != size or not hmac.compare_digest(sha256(plaintext).hexdigest(), record["sha256"]):
        raise ModelStorageError("Encrypted model does not match its storage identity.")
    return plaintext


def model_size(path: str | Path) -> int:
    return len(read_model_bytes(path))


def read_model_header(path: str | Path) -> bytes:
    """Authenticate protected models; inspect only magic bytes of source files."""
    from core.model_access import model_read_access

    lexical = _path(path)
    if _record(lexical) is not None:
        return read_model_bytes(path)[:4]
    if Path(lexical).is_relative_to((DATA_DIR / "uploads").resolve()) and not _legacy_migration.get():
        raise ModelStorageError("Stored plaintext model requires explicit verified encryption migration before use.")
    with model_read_access(lexical):
        with Path(path).open("rb") as stream:
            return stream.read(4)


def write_model_bytes(
    path: str | Path, payload: bytes, owner_id: int | None = None, *,
    _migration: bool = False,
) -> None:
    """Atomically publish only authenticated ciphertext at a stable storage path."""
    key = require_model_encryption_key()
    payload = bytes(payload)
    if len(payload) > MAX_UPLOAD_BYTES:
        raise ModelStorageError("Model exceeds the upload size limit.")
    if owner_id is not None and (type(owner_id) is not int or not 0 <= owner_id < 2**63):
        raise ModelStorageError("Invalid model storage owner.")
    target = Path(path)
    if target.is_symlink():
        raise ModelStorageError("Refusing to replace a symlink model artifact.")
    lexical = _path(target)
    digest = sha256(payload).hexdigest()
    prior = _record(lexical)
    if prior is not None and (prior["owner_id"] != owner_id or prior["sha256"] != digest):
        raise ModelStorageError("Model storage identity does not match the original encrypted artifact.")
    if target.exists() and not _migration:
        if prior is None or read_model_bytes(target) != payload:
            raise ModelStorageError("Refusing to overwrite an existing or changed model artifact.")
        return
    with closing(db.connect()) as conn, conn:
        _init(conn)
        conn.execute("INSERT OR IGNORE INTO encrypted_model_files VALUES (?, ?, ?, ?)", (lexical, owner_id, digest, db.utc_now()))
        row = conn.execute("SELECT * FROM encrypted_model_files WHERE artifact_path = ?", (lexical,)).fetchone()
        if row["owner_id"] != owner_id or row["sha256"] != digest:
            raise ModelStorageError("Model storage identity does not match the original encrypted artifact.")
    header = _HEADER.pack(-1 if owner_id is None else owner_id, len(payload))
    nonce = os.urandom(12)
    ciphertext = MAGIC + header + nonce + AESGCM(key).encrypt(nonce, payload, MAGIC + header + lexical.encode("utf-8"))
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".encrypted-model-", dir=target.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(ciphertext)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def migrate_registered_model(path: str | Path, owner_id: int | None = None) -> None:
    """Explicit migration: verify the original baseline before encrypting in place."""
    from core.artifact_integrity import register_or_verify_artifact

    target = Path(path)
    if not target.resolve().is_relative_to((DATA_DIR / "uploads").resolve()):
        raise ModelStorageError("Migration is limited to stored uploads, not source fixtures.")
    lexical = _path(target)
    with closing(db.connect()) as conn, conn:
        db._init_artifact_registry(conn)
        known = conn.execute("SELECT 1 FROM model_artifact_registry WHERE owner_id IS ? AND artifact_path = ?", (owner_id, lexical)).fetchone()
        if known is None:
            tables = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='model_registry'").fetchone()
            known = tables and any(_path(row[0]) == lexical for row in conn.execute("SELECT model_path FROM model_registry WHERE owner_id IS ?", (owner_id,)))
        if not known:
            raise ModelStorageError("Migration requires an original server registration; it cannot establish a new baseline.")
    # A migration retry may encounter an encryption identity whose atomic file
    # replacement failed. Both the storage hash and original scan hash must pass.
    with _allow_legacy_migration():
        binding = register_or_verify_artifact(target, owner_id)
        payload = read_model_bytes(target)
    if sha256(payload).hexdigest() != binding["sha256"]:
        raise ModelStorageError("Model changed during migration.")
    write_model_bytes(target, payload, owner_id, _migration=True)
    register_or_verify_artifact(target, owner_id)


@contextmanager
def _allow_legacy_migration():
    token = _legacy_migration.set(True)
    try:
        yield
    finally:
        _legacy_migration.reset(token)
