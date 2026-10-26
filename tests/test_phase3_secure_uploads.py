"""Encrypted upload and authenticated actor boundaries, without plaintext model staging."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest
from fastapi import HTTPException, UploadFile


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("CREDORA_MODEL_ENCRYPTION_KEY", base64.urlsafe_b64encode(bytes(range(32))).decode())
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DISTINCT_LIMIT", "1000")
    from api import main
    from core import db

    monkeypatch.setattr(db, "DB_PATH", tmp_path / "registry.sqlite3")
    db.init_db()
    owner = int(db.list_users()[0]["id"])
    reviewer = db.create_user("reviewer-test", "a-test-password", role="reviewer")["id"]
    monkeypatch.setattr(main, "UPLOAD_DIR", tmp_path / "data" / "uploads")
    return SimpleNamespace(root=tmp_path, owner=owner, actor=int(reviewer), db=db, api=main)


class _BoundedUpload(BytesIO):
    def __init__(self, payload):
        super().__init__(payload)
        self.requests = []

    def read(self, size=-1):
        assert 0 < size <= 1024 * 1024
        self.requests.append(size)
        return super().read(size)


async def _asgi_request(app, chunks, headers, path="/upload"):
    incoming = iter(chunks)
    sent = []

    async def receive():
        chunk = next(incoming, None)
        if chunk is None:
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.request", "body": chunk, "more_body": True}

    async def send(message):
        sent.append(message)

    await app({"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
               "method": "POST", "scheme": "http", "path": path, "raw_path": path.encode(),
               "query_string": b"", "root_path": "", "server": ("test", 80),
               "client": ("127.0.0.1", 1234), "headers": [
                   (name.lower().encode(), value.encode()) for name, value in headers.items()
               ]}, receive, send)
    return SimpleNamespace(status_code=next(m["status"] for m in sent if m["type"] == "http.response.start"),
                           body=b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body"))


@pytest.mark.parametrize("subdir,filename", [
    ("models", "model.onnx"), ("models", "model.credora"),
    ("runtime_models", "model.joblib"), ("packages", "model.credora"),
])
def test_api_models_are_encrypted_before_the_first_disk_copy(project, monkeypatch, subdir, filename):
    from core.artifact_integrity import assert_artifact_integrity
    from core.model_storage import MAGIC, read_model_bytes

    payload = b"private-model-weights-not-for-disk" * 30
    stream = _BoundedUpload(payload)
    original_open = Path.open

    def reject_direct_model_write(path, mode="r", *args, **kwargs):
        if path.is_relative_to(project.api.UPLOAD_DIR) and any(flag in mode for flag in "wax+"):
            raise AssertionError("Upload attempted a direct plaintext model write")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", reject_direct_model_write)
    saved = project.api.save_upload(UploadFile(filename=filename, file=stream), subdir, project.owner)
    raw = saved.read_bytes()
    assert raw.startswith(MAGIC) and payload not in raw
    assert read_model_bytes(saved) == payload
    binding = assert_artifact_integrity(saved, owner_id=project.owner)
    assert binding["sha256"] == hashlib.sha256(payload).hexdigest()
    assert stream.requests
    assert list(saved.parent.iterdir()) == [saved]


def test_api_oversized_models_never_reach_encrypted_storage(project, monkeypatch):
    monkeypatch.setattr(project.api, "MAX_ONNX_UPLOAD_BYTES", 8)
    write = Mock(side_effect=AssertionError("Oversized model reached storage"))
    monkeypatch.setattr(project.api, "write_model_bytes", write)
    stream = _BoundedUpload(b"x" * 100)
    with pytest.raises(HTTPException) as caught:
        project.api.save_upload(UploadFile(filename="large.onnx", file=stream), "models", project.owner)
    assert caught.value.status_code == 413
    assert stream.tell() == 9
    write.assert_not_called()
    assert not list(project.api.UPLOAD_DIR.rglob("*.onnx"))


def test_missing_encryption_key_fails_without_a_plaintext_upload(project, monkeypatch):
    monkeypatch.delenv("CREDORA_MODEL_ENCRYPTION_KEY")
    with pytest.raises(HTTPException) as caught:
        project.api.save_upload(UploadFile(filename="model.onnx", file=BytesIO(b"private weights")),
                                "models", project.owner)
    assert caught.value.status_code == 409
    assert "CREDORA_MODEL_ENCRYPTION_KEY" in caught.value.detail
    assert not list(project.api.UPLOAD_DIR.rglob("*.onnx"))


def test_non_model_uploads_keep_their_original_bytes_without_an_encryption_key(project, monkeypatch):
    monkeypatch.delenv("CREDORA_MODEL_ENCRYPTION_KEY")
    payload = b"feature,label\n1,normal\n"
    saved = project.api.save_upload(UploadFile(filename="test.csv", file=BytesIO(payload)),
                                    "datasets", project.owner)
    assert saved.read_bytes() == payload


def test_large_multipart_upload_never_rolls_to_plaintext_disk(project, monkeypatch):
    import tempfile

    from fastapi import Depends, FastAPI, File

    from core.model_storage import MAGIC, read_model_bytes

    payload = b"private multipart model weights" * 40000
    assert len(payload) > 1024 * 1024
    app = FastAPI()
    app.add_middleware(project.api.BoundedBodyMiddleware)
    checked = []

    def authorize():
        checked.append(True)

    model_field = File(...)

    @app.post("/upload", dependencies=[Depends(authorize), Depends(project.api.require_api_key)])
    def upload(model: UploadFile = model_field):
        assert not model.file._rolled
        saved = project.api.save_upload(model, "models", project.owner)
        assert saved.read_bytes().startswith(MAGIC)
        assert read_model_bytes(saved) == payload
        return {"rolled": model.file._rolled}

    def reject_rollover(*args, **kwargs):
        raise AssertionError("Multipart model attempted plaintext disk staging")

    monkeypatch.setattr(tempfile.SpooledTemporaryFile, "rollover", reject_rollover)

    multipart_body = (b'--test\r\nContent-Disposition: form-data; name="model"; filename="private.onnx"\r\n'
                      b'Content-Type: application/octet-stream\r\n\r\n' + payload + b'\r\n--test--\r\n')
    headers = {"Content-Type": "multipart/form-data; boundary=test"}

    async def request():
        denied = await _asgi_request(app, [multipart_body], headers)
        assert denied.status_code == 401
        return await _asgi_request(app, [multipart_body], {
            **headers, "X-Credora-API-Key": project.api.API_KEY,
        })

    response = asyncio.run(request())
    assert response.status_code == 200, response.body
    assert json.loads(response.body) == {"rolled": False}
    assert checked


@pytest.mark.parametrize("headers", [{}, {"Content-Length": "1"}, {"Transfer-Encoding": "chunked"}])
def test_received_body_limit_rejects_without_parsing_even_without_length(project, monkeypatch, headers):
    from starlette.formparsers import MultiPartParser

    monkeypatch.setattr(project.api, "MAX_UPLOAD_BYTES", 32)

    async def reject_parser(*args, **kwargs):
        raise AssertionError("Oversized request reached multipart parser")

    monkeypatch.setattr(MultiPartParser, "parse", reject_parser)

    def chunks():
        yield b"a" * 20
        yield b"b" * 20
        raise AssertionError("Body consumed after crossing the limit")

    response = asyncio.run(_asgi_request(project.api.app, chunks(), {
        "Content-Type": "multipart/form-data; boundary=test", **headers,
    }, path="/scan"))
    assert response.status_code == 413, response.body
    assert not list(project.api.UPLOAD_DIR.rglob("*.onnx"))


def test_api_startup_requires_encryption_key_before_database_init(project, monkeypatch):
    monkeypatch.delenv("CREDORA_MODEL_ENCRYPTION_KEY")
    init = Mock()
    monkeypatch.setattr(project.api, "init_db", init)
    with pytest.raises(ValueError, match="CREDORA_MODEL_ENCRYPTION_KEY"):
        project.api.on_startup()
    init.assert_not_called()


def test_body_buffer_coalesces_tiny_and_empty_chunks(project, monkeypatch):
    monkeypatch.setattr(project.api, "MAX_UPLOAD_BYTES", 128)
    received = []

    async def endpoint(scope, receive, send):
        received.append(await receive())
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    def chunks():
        yield from (b"" for _ in range(10000))
        yield from (b"x" for _ in range(100))

    response = asyncio.run(_asgi_request(project.api.BoundedBodyMiddleware(endpoint), chunks(), {}))
    assert response.status_code == 200
    assert received == [{"type": "http.request", "body": b"x" * 100, "more_body": False}]


def _uploaded(payload):
    value = BytesIO(payload)
    value.name = "model.onnx"
    return value


def test_dashboard_model_cache_rechecks_ciphertext_and_never_restores_tampered_bytes(project, monkeypatch):
    from core.model_storage import MAGIC, read_model_bytes
    from dashboard.components import scan_submission

    monkeypatch.setattr(scan_submission.st, "session_state", {"auth_user": {"id": project.owner}})
    payload = b"private dashboard model"
    saved = scan_submission.persist_upload(_uploaded(payload), "models", project.root)
    assert saved.read_bytes().startswith(MAGIC)
    assert read_model_bytes(saved) == payload
    assert scan_submission.persist_upload(_uploaded(payload), "models", project.root) == saved
    raw = bytearray(saved.read_bytes())
    raw[-1] ^= 1
    saved.write_bytes(raw)
    with pytest.raises(ValueError):
        scan_submission.persist_upload(_uploaded(payload), "models", project.root)
    assert saved.read_bytes() == bytes(raw)


def _report(project, name="model.onnx"):
    from core.artifact_integrity import register_or_verify_artifact

    saved = project.api.save_upload(UploadFile(filename=name, file=BytesIO(b"model weights")),
                                    "models", project.owner)
    binding = register_or_verify_artifact(saved, owner_id=project.owner)
    return {"model_name": "private-model", "trust_score": 90, "status": "pass",
            "model_artifact": {key: binding[key] for key in ("id", "owner_id", "sha256")},
            "module_results": [{"module": "model_verification", "status": "pass", "score": 100,
                                "findings": [], "details": {"sha256": binding["sha256"], "file_name": name}}]}


def _access_events(project, purpose):
    with project.db.connect() as connection:
        return [dict(row) for row in connection.execute(
            "SELECT * FROM model_access_events WHERE purpose = ?", (purpose,)
        )]


def test_api_report_checks_audit_the_authenticated_actor_not_the_report_owner(project, monkeypatch):
    report = _report(project)
    monkeypatch.setattr(project.api, "latest_scan", lambda **kwargs: report)
    monkeypatch.setattr(project.api, "get_scan_record", lambda *args, **kwargs:
                        {"owner_id": project.owner, "report": report})
    user = {"id": project.actor, "role": "reviewer"}
    assert project.api.scan_latest(user=user) == report
    project.api.verify_scan_report_signature(1, user=user)
    events = _access_events(project, "report_access")
    assert events and all(event["actor_id"] == project.actor for event in events)
    assert all(event["owner_id"] == project.owner for event in events)
    with pytest.raises(HTTPException) as caught:
        project.api._check_report_access(report, owner_id=project.actor, actor_id=project.actor)
    assert caught.value.status_code == 409


def test_deferred_report_callbacks_keep_the_authenticated_actor(project, monkeypatch):
    from dashboard.pages import reports
    from modules.phase2_deep_trust.m9_docx_report import docx_report

    report = _report(project)
    cached = project.root / "cached.docx"
    cached.write_bytes(b"cached file must not be served")
    report["docx_report_path"] = str(cached)
    ui = MagicMock()
    ui.session_state = {"show_all_users": True}
    ui.columns.return_value = (MagicMock(), MagicMock())
    monkeypatch.setattr(reports, "st", ui)
    monkeypatch.setattr(reports, "render_page_head", Mock())
    monkeypatch.setattr(reports, "REPORT_DIR", project.root / "reports")
    monkeypatch.setattr(docx_report, "REPORT_DIR", project.root / "reports")
    reports.render_reports_page(
        current_user={"id": project.actor, "role": "reviewer"}, report_data=report, deployment_gate={},
        model_name=report["model_name"], generated_at="2026-10-20", trust_score=90, trust_score_issued=True,
        threat_model={}, remediation_plan=[], analysis_trace=[],
    )
    callbacks = [call.args[1] for call in ui.download_button.call_args_list]
    assert len(callbacks) == 2 and all(callable(callback) for callback in callbacks)
    assert json.loads(callbacks[0]())["model_artifact"]["owner_id"] == project.owner
    assert callbacks[1]().startswith(b"PK")
    for purpose in ("report_render", "report_download"):
        events = _access_events(project, purpose)
        assert events and all(event["actor_id"] == project.actor for event in events)
        assert all(event["owner_id"] == project.owner for event in events)


def test_api_sequence_preflight_uses_authenticated_access_context(project, monkeypatch):
    from core.model_access import access_environment

    observed = []
    monkeypatch.setattr(project.api, "validate_sequence_compatibility",
                        lambda *args: observed.append(access_environment()))
    monkeypatch.setattr(project.api, "run_phase1_scan", Mock(return_value=SimpleNamespace(to_dict=dict)))
    project.api.scan_phase1(
        model=UploadFile(filename="model.onnx", file=BytesIO(b"weights")),
        dataset=UploadFile(filename="test.npz", file=BytesIO(b"test arrays")), requirements=None,
        metadata=UploadFile(filename="metadata.json", file=BytesIO(b'{"input_type":"sequence"}')),
        trust_key=None, flow_labels=None, execution_device=None, allow_cpu_fallback=False,
        user={"id": project.owner, "role": "uploader"},
    )
    assert len(observed) == 1
    assert observed[0]["CREDORA_MODEL_ACCESS_ACTOR"] == str(project.owner)
    assert observed[0]["CREDORA_MODEL_ACCESS_OWNER"] == str(project.owner)
    assert observed[0]["CREDORA_MODEL_ACCESS_PURPOSE"] == "sequence_preflight"


def test_model_access_limit_is_not_downgraded_to_integrity_conflict(project, monkeypatch):
    from core.model_access import ModelAccessLimitError

    limit = ModelAccessLimitError("Distinct model access limit exceeded")
    monkeypatch.setattr(project.api, "assert_report_artifact_integrity", Mock(side_effect=limit))
    with pytest.raises(ModelAccessLimitError):
        project.api._check_report_access({}, owner_id=project.owner, actor_id=project.actor)
    handler = project.api.app.exception_handlers[ModelAccessLimitError]
    response = asyncio.run(handler(None, limit))
    assert response.status_code == 429
    assert json.loads(response.body)["detail"] == str(limit)


def test_real_distinct_model_limit_preserves_authenticated_actor_and_denial(project, monkeypatch):
    from core.model_access import ModelAccessLimitError

    first, second = _report(project, "first.onnx"), _report(project, "second.onnx")
    monkeypatch.setenv("CREDORA_MODEL_ACCESS_DISTINCT_LIMIT", "1")
    project.api._check_report_access(first, owner_id=project.owner, actor_id=project.actor)
    with pytest.raises(ModelAccessLimitError):
        project.api._check_report_access(second, owner_id=project.owner, actor_id=project.actor)
    events = _access_events(project, "report_access")
    assert any(event["outcome"] == "denied" and event["actor_id"] == project.actor for event in events)
