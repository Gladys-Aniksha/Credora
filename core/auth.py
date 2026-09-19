from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import secrets
from typing import Any

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from core.config import API_KEY

try:  # Preferred production path; listed in requirements.txt.
    from jose import JWTError, jwt
except Exception:  # pragma: no cover - local fallback for environments before dependency install.
    JWTError = Exception
    jwt = None

try:  # Preferred production password hashing.
    from passlib.context import CryptContext
except Exception:  # pragma: no cover - local fallback for environments before dependency install.
    CryptContext = None

JWT_SECRET = os.getenv("CREDORA_JWT_SECRET") or secrets.token_hex(32)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = int(os.getenv("CREDORA_ACCESS_TOKEN_MINUTES", "45"))
REFRESH_TOKEN_DAYS = int(os.getenv("CREDORA_REFRESH_TOKEN_DAYS", "7"))
SERVICE_USER_ID = 0
SERVICE_USER = {"id": SERVICE_USER_ID, "username": "service-admin", "role": "admin", "email": None}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto") if CryptContext else None


def hash_password(password: str) -> str:
    if len(password or "") < 8:
        raise ValueError("Password must be at least 8 characters.")
    if _pwd_context:
        return _pwd_context.hash(password)
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 240_000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    if _pwd_context and not password_hash.startswith("pbkdf2_sha256$"):
        return _pwd_context.verify(password, password_hash)
    try:
        _, salt, expected = password_hash.split("$", 2)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 240_000).hex()
    return hmac.compare_digest(actual, expected)


def _expiry(minutes: int | None = None, days: int | None = None) -> datetime:
    now = datetime.now(timezone.utc)
    if days is not None:
        return now + timedelta(days=days)
    return now + timedelta(minutes=minutes or ACCESS_TOKEN_MINUTES)


def _stdlib_encode(payload: dict[str, Any]) -> str:
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
    signature = hmac.new(JWT_SECRET.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    sig = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"local.{body}.{sig}"


def _stdlib_decode(token: str) -> dict[str, Any]:
    try:
        prefix, body, sig = token.split(".", 2)
    except ValueError as exc:
        raise ValueError("Invalid token") from exc
    if prefix != "local":
        raise ValueError("Invalid token")
    expected = base64.urlsafe_b64encode(
        hmac.new(JWT_SECRET.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    ).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Invalid token")
    padded = body + "=" * (-len(body) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    exp = payload.get("exp")
    if exp and datetime.fromtimestamp(float(exp), timezone.utc) < datetime.now(timezone.utc):
        raise ValueError("Expired token")
    return payload


def create_token(user: dict[str, Any], *, token_type: str) -> str:
    expires = _expiry(days=REFRESH_TOKEN_DAYS) if token_type == "refresh" else _expiry(minutes=ACCESS_TOKEN_MINUTES)
    payload = {
        "sub": str(user["id"]),
        "username": user.get("username"),
        "role": user.get("role", "uploader"),
        "session_version": int(user.get("session_version", 0) or 0),
        "type": token_type,
        "exp": int(expires.timestamp()),
    }
    if jwt:
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return _stdlib_encode(payload)


def create_access_token(user: dict[str, Any]) -> str:
    return create_token(user, token_type="access")


def create_refresh_token(user: dict[str, Any]) -> str:
    return create_token(user, token_type="refresh")


def decode_token(token: str, *, expected_type: str = "access") -> dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM]) if jwt else _stdlib_decode(token)
    except (JWTError, ValueError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token") from exc
    if payload.get("type") != expected_type:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    return payload


def token_user(token: str, *, expected_type: str = "access") -> dict[str, Any]:
    from core.db import get_user_by_id

    payload = decode_token(token, expected_type=expected_type)
    user = get_user_by_id(int(payload["sub"]))
    if not user or int(user.get("disabled", 0) or 0):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    if int(user.get("session_version", 0) or 0) != int(payload.get("session_version", 0) or 0):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return user


def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    x_credora_api_key: str | None = Header(default=None),
) -> dict[str, Any]:
    if x_credora_api_key == API_KEY:
        return SERVICE_USER
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return token_user(token)


def require_role(*roles: str):
    def checker(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        if user.get("role") not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return checker


def can_view_all(user: dict[str, Any] | None) -> bool:
    return bool(user and user.get("role") in {"reviewer", "admin"})

