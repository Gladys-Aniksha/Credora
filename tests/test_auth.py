from __future__ import annotations

import json
import secrets

import pytest
from fastapi import HTTPException
from starlette.requests import Request

import core.auth as auth
import core.db as db
from api.main import login_rate_limit
from core.auth import create_access_token, get_current_user, require_role, token_user
from core.config import API_KEY, _required_environment_variable


def _minimal_report(model_name: str, score: float) -> dict:
    return {
        "model_name": model_name,
        "trust_score": score,
        "status": "pass",
        "generated_at": db.utc_now(),
        "recommendations": [],
        "module_results": [
            {"module": "model_verification", "status": "pass", "score": 100, "summary": "ok", "findings": [], "details": {"version": "1.0"}},
        ],
    }


def _request(client_host: str = "127.0.0.1", path: str = "/models") -> Request:
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": [],
            "client": (client_host, 50000),
            "server": ("testserver", 80),
        }
    )


@pytest.fixture()
def isolated_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "credora_registry.sqlite3")
    db.init_db()
    return db.DB_PATH


def test_register_login_and_wrong_password_fails(isolated_registry) -> None:
    user = db.create_user("alice", "strong-password", "alice@example.com")

    assert user["username"] == "alice"
    assert db.authenticate_user("alice", "strong-password") is not None
    assert db.authenticate_user("alice", "wrong-password") is None

    with pytest.raises(ValueError):
        db.create_user("alice", "another-password")


def test_unknown_username_still_verifies_dummy_password_hash(isolated_registry, monkeypatch) -> None:
    calls: list[tuple[str, str]] = []

    def record_verification(password: str, password_hash: str) -> bool:
        calls.append((password, password_hash))
        return False

    monkeypatch.setattr(auth, "verify_password", record_verification)

    assert db.authenticate_user("missing-user", "submitted-password") is None
    assert calls == [("submitted-password", auth.DUMMY_PASSWORD_HASH)]


def test_owner_scoped_scan_history_allows_same_model_name(isolated_registry, tmp_path) -> None:
    alice = db.create_user("alice", "strong-password")
    bob = db.create_user("bob", "strong-password")

    db.save_scan(_minimal_report("traffic_rf_v1", 91), tmp_path / "alice.json", owner_id=alice["id"])
    db.save_scan(_minimal_report("traffic_rf_v1", 62), tmp_path / "bob.json", owner_id=bob["id"])

    alice_scans = db.list_scans(owner_id=alice["id"])
    bob_scans = db.list_scans(owner_id=bob["id"])

    assert [scan["trust_score"] for scan in alice_scans] == [91]
    assert [scan["trust_score"] for scan in bob_scans] == [62]
    assert len(db.list_scans(include_all=True)) >= 2


def test_auth_token_and_role_enforcement(isolated_registry) -> None:
    alice = db.create_user("alice", "strong-password", role="uploader")
    token = create_access_token(alice)

    assert token_user(token)["username"] == "alice"
    with pytest.raises(HTTPException) as missing:
        get_current_user(request=_request(), token=None, x_credora_api_key=None)
    assert missing.value.status_code == 401

    admin_only = require_role("admin")
    with pytest.raises(HTTPException) as denied:
        admin_only(user=alice)
    assert denied.value.status_code == 403


def test_service_api_key_is_required(monkeypatch) -> None:
    monkeypatch.delenv("CREDORA_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="CREDORA_API_KEY must be set"):
        _required_environment_variable("CREDORA_API_KEY")


def test_service_api_key_is_audited_and_shares_login_rate_limit(isolated_registry) -> None:
    auth._auth_rate_limit_buckets.clear()
    request = _request(client_host="192.0.2.10", path="/models")

    for _ in range(auth.AUTH_RATE_LIMIT_MAX_REQUESTS - 1):
        login_rate_limit(request)

    service_user = get_current_user(request=request, token=None, x_credora_api_key=API_KEY)
    assert service_user["username"] == "service-admin"

    logs = db.list_audit_logs(event_type="auth.service_key_used")
    assert len(logs) == 1
    assert logs[0]["details"] == {"client": "192.0.2.10", "path": "/models"}
    assert API_KEY not in json.dumps(logs)

    with pytest.raises(HTTPException) as limited:
        get_current_user(request=request, token=None, x_credora_api_key=API_KEY)
    assert limited.value.status_code == 429


def test_invalid_service_key_is_rejected_and_audited(isolated_registry) -> None:
    auth._auth_rate_limit_buckets.clear()
    request = _request(client_host="192.0.2.11", path="/scans")
    invalid_key = secrets.token_urlsafe(32)

    with pytest.raises(HTTPException) as rejected:
        get_current_user(request=request, token=None, x_credora_api_key=invalid_key)
    assert rejected.value.status_code == 401

    logs = db.list_audit_logs(event_type="auth.service_key_rejected")
    assert len(logs) == 1
    assert invalid_key not in json.dumps(logs)


def test_token_scoped_scan_listing_is_isolated(isolated_registry, tmp_path) -> None:
    alice = db.create_user("alice", "strong-password")
    bob = db.create_user("bob", "strong-password")
    db.save_scan(_minimal_report("same-name", 88), tmp_path / "alice.json", owner_id=alice["id"])
    db.save_scan(_minimal_report("same-name", 41), tmp_path / "bob.json", owner_id=bob["id"])

    alice_user = token_user(create_access_token(alice))
    bob_user = token_user(create_access_token(bob))

    alice_scans = db.list_scans(owner_id=alice_user["id"])
    bob_scans = db.list_scans(owner_id=bob_user["id"])

    assert [scan["trust_score"] for scan in alice_scans] == [88]
    assert [scan["trust_score"] for scan in bob_scans] == [41]


def test_admin_controls_policy_audit_revocation_and_delete(isolated_registry, tmp_path) -> None:
    admin = db.create_user("admin2", "strong-password", role="admin")
    user = db.create_user("charlie", "strong-password", role="uploader")
    token = create_access_token(user)
    assert token_user(token)["username"] == "charlie"

    db.update_user_role(user["id"], "reviewer", actor_id=admin["id"])
    assert db.get_user_by_id(user["id"])["role"] == "reviewer"

    db.revoke_user_sessions(user["id"], actor_id=admin["id"])
    with pytest.raises(HTTPException):
        token_user(token)

    db.set_deployment_policy({"minimum_trust_score": 90, "minimum_classifier_score": 88, "minimum_adversarial_score": 82, "minimum_sensitive_recall": 0.92}, actor_id=admin["id"])
    assert db.get_deployment_policy()["minimum_trust_score"] == 90.0

    db.set_trust_weights({"model_verification": 2, "classifier_evaluation": 1}, actor_id=admin["id"])
    weights = db.get_trust_weights()
    assert round(sum(weights.values()), 6) == 1.0
    assert weights["model_verification"] > weights["classifier_evaluation"]

    db.set_sensitive_label_taxonomy(["malware", "abuse"], actor_id=admin["id"])
    assert db.get_sensitive_label_taxonomy() == ["abuse", "malware"]

    report_path = tmp_path / "scan.json"
    report_path.write_text("{}", encoding="utf-8")
    db.save_scan(_minimal_report("owned-model", 77), report_path, owner_id=user["id"])
    scan = db.list_scans(owner_id=user["id"])[0]
    override_id = db.create_deployment_override(scan["id"], "approved", "Reviewed compensating controls", admin["id"])
    assert override_id > 0

    assert db.delete_scan(scan["id"], owner_id=user["id"], actor_id=user["id"])
    assert not report_path.exists()
    assert db.list_audit_logs()
