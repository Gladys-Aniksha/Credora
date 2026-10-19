from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys

import pytest

import core.auth as auth


def _legacy_hash(password: str, salt: str = "0123456789abcdef0123456789abcdef") -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 240_000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def test_new_hashes_are_salted_versioned_and_accept_eight_characters() -> None:
    first = auth.hash_password("12345678")
    second = auth.hash_password("12345678")
    scheme, iterations, salt, digest = first.split("$")
    assert scheme == "pbkdf2_sha256_v2"
    assert int(iterations) >= 600_000
    assert len(salt) == 32
    assert digest == hashlib.pbkdf2_hmac("sha256", b"12345678", salt.encode("utf-8"), int(iterations)).hex()
    assert first != second
    assert auth.verify_password("12345678", first)
    assert not auth.verify_password("wrong-password", first)
    with pytest.raises(ValueError, match="at least 8"):
        auth.hash_password("1234567")


def test_new_hashes_use_entire_utf8_password() -> None:
    password = "\u00e9" * 40
    stored = auth.hash_password(password)
    assert auth.verify_password(password, stored)
    assert not auth.verify_password("\u00e9" * 36 + "changed", stored)


def test_legacy_pbkdf2_remains_available_without_bcrypt(monkeypatch) -> None:
    stored = _legacy_hash("legacy-\u00e9-password")
    monkeypatch.setattr(auth, "bcrypt", None)
    assert auth.verify_password("legacy-\u00e9-password", stored)
    assert not auth.verify_password("wrong-password", stored)
    assert auth.verify_password("12345678", auth.hash_password("12345678"))


@pytest.mark.parametrize("prefix", [b"2a", b"2b", b"2y"])
def test_existing_bcrypt_hashes(prefix) -> None:
    bcrypt = pytest.importorskip("bcrypt")
    stored = bcrypt.hashpw(b"12345678", bcrypt.gensalt(rounds=4)).decode("ascii")
    stored = "$" + prefix.decode("ascii") + stored[3:]
    assert auth.verify_password("12345678", stored)
    assert not auth.verify_password("wrong-password", stored)


def test_legacy_bcrypt_preserves_72_byte_truncation() -> None:
    bcrypt = pytest.importorskip("bcrypt")
    password = "a" * 71 + "\u00e9" + "legacy-suffix"
    stored = bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt(rounds=4)).decode("ascii")
    assert auth.verify_password(password, stored)
    assert auth.verify_password("a" * 71 + "\u00e9" + "other-suffix", stored)
    assert not auth.verify_password("b" + password[1:], stored)
    assert not auth.verify_password("12345678\x00", stored)


@pytest.mark.parametrize("stored", [
    None, 42, b"hash", "", "plaintext", "$2b$invalid", "$2a$", "$2y$invalid", "$2x$invalid",
    "pbkdf2_sha256$$" + "0" * 64,
    "pbkdf2_sha256$salt$short", "pbkdf2_sha256$salt$" + "z" * 64,
    "pbkdf2_sha256$salt$" + "\u00e9" * 64,
    "pbkdf2_sha256$salt$" + "0" * 64 + "$extra",
    "pbkdf2_sha256_v2$600000$salt$" + "0" * 64,
    "pbkdf2_sha256_v2$1$" + "a" * 32 + "$" + "0" * 64,
    "pbkdf2_sha256_v2$999999999999999999999$" + "a" * 32 + "$" + "0" * 64,
])
def test_malformed_or_unsupported_hashes_fail_closed(stored) -> None:
    assert auth.verify_password("12345678", stored) is False


def test_unknown_scheme_cannot_be_interpreted_as_legacy_pbkdf2() -> None:
    stored = _legacy_hash("12345678")
    assert not auth.verify_password("12345678", stored.replace("pbkdf2_sha256$", "unknown$", 1))


def test_unavailable_bcrypt_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(auth, "bcrypt", None)
    assert not auth.verify_password("12345678", "$2b$12$" + "a" * 53)


@pytest.mark.parametrize("password", [None, 42, b"12345678", "\ud800"])
def test_invalid_password_values_fail_closed(password) -> None:
    assert not auth.verify_password(password, _legacy_hash("12345678"))


@pytest.mark.parametrize("disable_bcrypt", [False, True])
def test_import_and_password_operations_need_no_passlib(disable_bcrypt) -> None:
    script = """
import builtins
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == 'passlib' or name.startswith('passlib.'):
        raise AssertionError('Passlib must not be imported')
    if name == 'bcrypt' and sys.argv[1] == 'True':
        raise ImportError('bcrypt intentionally unavailable')
    return original_import(name, *args, **kwargs)
import sys
builtins.__import__ = guarded_import
from core import auth
if sys.argv[1] == 'True':
    assert auth.bcrypt is None
assert auth.verify_password('12345678', auth.hash_password('12345678'))
assert not auth.verify_password('12345678', '$2b$invalid')
if auth.bcrypt is not None:
    stored = auth.bcrypt.hashpw(b'12345678', auth.bcrypt.gensalt(rounds=4)).decode('ascii')
    assert auth.verify_password('12345678', stored)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(disable_bcrypt)], cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "__about__" not in result.stderr
    assert "bcrypt version" not in result.stderr
