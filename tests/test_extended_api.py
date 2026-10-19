"""HTTP-level intake checks without model execution or an external test client."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


def multipart(files, fields=None):
    boundary = "credora-extended-api-test-boundary"
    parts = []
    for name, value in (fields or {}).items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
    for name, (filename, body) in files.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
            'Content-Type: application/octet-stream\r\n\r\n'.encode() + body + b"\r\n"
        )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def post(app, files, fields=None):
    body, content_type = multipart(files, fields)

    async def request():
        messages = []
        finished = asyncio.Event()
        body_sent = False

        async def receive():
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            await finished.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            messages.append(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                finished.set()

        scope = {
            "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1", "method": "POST", "scheme": "http",
            "path": "/scan/phase1", "raw_path": b"/scan/phase1", "root_path": "",
            "query_string": b"", "server": ("testserver", 80), "client": ("127.0.0.1", 12345),
            "headers": [(b"host", b"testserver"), (b"content-type", content_type.encode()),
                        (b"content-length", str(len(body)).encode())],
        }
        await asyncio.wait_for(app(scope, receive, send), timeout=10)
        response = next(item for item in messages if item["type"] == "http.response.start")
        payload = b"".join(item.get("body", b"") for item in messages if item["type"] == "http.response.body")
        return response["status"], json.loads(payload)

    return asyncio.run(request())


@pytest.fixture
def api(monkeypatch, tmp_path):
    monkeypatch.setenv("CREDORA_API_KEY", "extended-api-test-key")
    from api import main

    monkeypatch.setattr(main, "UPLOAD_DIR", tmp_path / "uploads")
    monkeypatch.setattr(main, "_rate_limit_buckets", {})
    previous_overrides = main.app.dependency_overrides.copy()
    main.app.dependency_overrides.clear()
    try:
        yield main
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(previous_overrides)


def evidence(model_name="model.onnx", input_type="sequence"):
    return {
        "model": (model_name, b"mock model; never executed"),
        "dataset": ("capture.pcap", b"mock capture; conversion mocked"),
        "requirements": ("requirements.txt", b"numpy\n"),
        "metadata": ("metadata.json", json.dumps({"input_type": input_type,
            "pcap_schema": "pcap_transport_bytes_v1" if input_type == "sequence" else "pcap_flow_v1"}).encode()),
        "flow_labels": ("labels.csv", b"src_ip,src_port,dst_ip,dst_port,protocol,label\n"),
        "trust_key": ("public.pem", b"mock public key"),
    }


def test_oversized_request_returns_413_without_upload_or_scan(api, monkeypatch):
    monkeypatch.setattr(api, "MAX_UPLOAD_BYTES", 32)
    save = Mock(side_effect=AssertionError("oversized request reached upload persistence"))
    scan = Mock(side_effect=AssertionError("oversized request reached scan"))
    monkeypatch.setattr(api, "save_upload", save)
    monkeypatch.setattr(api, "run_phase1_scan", scan)
    status, response = post(api.app, evidence())
    assert status == 413
    assert response == {"detail": "Upload exceeds Credora size limit."}
    save.assert_not_called()
    scan.assert_not_called()
    assert not api.UPLOAD_DIR.exists()


def test_unauthenticated_extended_scan_cannot_persist_or_execute(api, monkeypatch):
    save, scan = Mock(), Mock()
    monkeypatch.setattr(api, "save_upload", save)
    monkeypatch.setattr(api, "run_phase1_scan", scan)
    status, response = post(api.app, evidence())
    assert status == 401
    assert response == {"detail": "Authentication required"}
    save.assert_not_called()
    scan.assert_not_called()
    assert not api.UPLOAD_DIR.exists()


@pytest.mark.parametrize("model_name,input_type", [
    ("model.onnx", "sequence"), ("model.onnx", "tabular"),
    ("weights.safetensors", "sequence"), ("model.weights.h5", "tabular"),
])
def test_extended_scan_forwards_settings_and_isolates_owners(api, monkeypatch, model_name, input_type):
    scan = Mock(return_value=SimpleNamespace(to_dict=lambda: {"model_name": "mock", "trust_score": 42}))
    preflight = Mock(side_effect=AssertionError("PCAP must be converted before NPZ preflight"))
    monkeypatch.setattr(api, "run_phase1_scan", scan)
    monkeypatch.setattr(api, "validate_sequence_compatibility", preflight)
    files = evidence(model_name, input_type)
    saved_by_owner = []
    for owner_id in (41, 42):
        api.app.dependency_overrides[api.get_current_user] = lambda owner=owner_id: {"id": owner, "role": "uploader"}
        status, response = post(api.app, files, {
            "execution_device": "cuda", "allow_cpu_fallback": "true", "owner_id": "999",
        })
        assert status == 200
        assert response == {"model_name": "mock", "trust_score": 42}
        args, kwargs = scan.call_args
        assert kwargs["owner_id"] == owner_id
        assert kwargs["execution_device"] == "cuda"
        assert kwargs["allow_cpu_fallback"] is True
        paths = {
            "model": args[0], "dataset": args[1], "requirements": args[2], "metadata": args[3],
            "flow_labels": kwargs["flow_labels_path"], "trust_key": kwargs["trusted_public_key_path"],
        }
        owner_root = (api.UPLOAD_DIR / str(owner_id)).resolve()
        for name, path in paths.items():
            assert isinstance(path, Path)
            assert path.is_relative_to(owner_root)
            assert path.read_bytes() == files[name][1]
        saved_by_owner.append(set(paths.values()))
    assert saved_by_owner[0].isdisjoint(saved_by_owner[1])
    assert scan.call_count == 2
    preflight.assert_not_called()
    assert not (api.UPLOAD_DIR / "999").exists()


def test_optional_requirements_and_default_execution_flags(api, monkeypatch):
    api.app.dependency_overrides[api.get_current_user] = lambda: {"id": 41, "role": "uploader"}
    scan = Mock(return_value=SimpleNamespace(to_dict=lambda: {"ok": True}))
    monkeypatch.setattr(api, "run_phase1_scan", scan)
    files = evidence()
    del files["requirements"]
    del files["trust_key"]
    status, response = post(api.app, files)
    assert (status, response) == (200, {"ok": True})
    args, kwargs = scan.call_args
    assert args[2].is_relative_to((api.UPLOAD_DIR / "41" / "requirements").resolve())
    assert "Standalone ONNX" in args[2].read_text()
    assert kwargs["execution_device"] is None
    assert kwargs["allow_cpu_fallback"] is False
    assert kwargs["trusted_public_key_path"] is None
    assert kwargs["flow_labels_path"].is_file()


@pytest.mark.parametrize("error", [ValueError("missing explicit label"), OSError("input unavailable"),
                                      RuntimeError("execution provider unavailable")])
def test_extended_scan_errors_return_400(api, monkeypatch, error):
    api.app.dependency_overrides[api.get_current_user] = lambda: {"id": 41, "role": "uploader"}
    scan = Mock(side_effect=error)
    monkeypatch.setattr(api, "run_phase1_scan", scan)
    status, response = post(api.app, evidence())
    assert status == 400
    assert response == {"detail": str(error)}
    scan.assert_called_once()


@pytest.mark.parametrize("contents", [b"not-json", b"[]"])
def test_invalid_metadata_returns_400_before_scan(api, monkeypatch, contents):
    api.app.dependency_overrides[api.get_current_user] = lambda: {"id": 41, "role": "uploader"}
    scan = Mock()
    monkeypatch.setattr(api, "run_phase1_scan", scan)
    files = evidence()
    files["metadata"] = ("metadata.json", contents)
    status, response = post(api.app, files)
    assert status == 400
    assert "detail" in response
    scan.assert_not_called()
