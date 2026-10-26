"""Keep model-access state and test keys out of the user's running deployment."""
from __future__ import annotations

import base64
import secrets

import pytest


@pytest.fixture(autouse=True)
def isolated_model_security_state(tmp_path, monkeypatch):
    from core import db

    database = tmp_path / "security-registry.sqlite3"
    monkeypatch.setattr(db, "DB_PATH", database)
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DB_PATH", str(database))
    monkeypatch.setenv("CREDORA_MODEL_ENCRYPTION_KEY", base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())
