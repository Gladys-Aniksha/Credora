from __future__ import annotations

from core.db import add_trusted_signer, list_trusted_signers
from core.report_signing import (
    generate_report_signing_keypair,
    sign_report_dict,
    verify_report_against_trusted_signers,
    verify_report_dict,
)


def _sample_report() -> dict:
    return {
        "model_name": "traffic_rf_v1",
        "trust_score": 91.5,
        "status": "pass",
        "results": [{"module": "classifier_eval", "score": 94.2, "status": "pass"}],
        "recommendations": [],
    }


def test_signed_report_verifies_and_tampering_fails(tmp_path):
    private_key = tmp_path / "report_private.pem"
    public_key = tmp_path / "report_public.pem"
    generate_report_signing_keypair(private_key, public_key)

    signed_report = sign_report_dict(_sample_report(), private_key, signer="Credora Release")
    result = verify_report_dict(signed_report, public_key)

    assert result["verified"] is True
    assert result["signer"] == "Credora Release"

    tampered = dict(signed_report)
    tampered["trust_score"] = 12.0
    tampered_result = verify_report_dict(tampered, public_key)

    assert tampered_result["verified"] is False
    assert "hash" in tampered_result["reason"].lower()


def test_signed_report_matches_active_trusted_signer(tmp_path):
    private_key = tmp_path / "report_private.pem"
    public_key = tmp_path / "report_public.pem"
    generate_report_signing_keypair(private_key, public_key)
    add_trusted_signer("Credora Release", public_key.read_text(encoding="utf-8"), actor_id=None)

    signed_report = sign_report_dict(_sample_report(), private_key, signer="Credora Release")
    result = verify_report_against_trusted_signers(signed_report, list_trusted_signers())

    assert result["verified"] is True
    assert result["trusted"] is True
    assert result["trusted_signer_name"] == "Credora Release"
