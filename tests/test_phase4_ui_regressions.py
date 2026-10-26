"""Behavioral guards for six historical dashboard presentation regressions."""
from __future__ import annotations

import ast
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import MagicMock, Mock

import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]


class _Elements(HTMLParser):
    def __init__(self, markup):
        super().__init__()
        self.elements = []
        self.stack = []
        self.text = ""
        self.feed(markup)

    def handle_starttag(self, tag, attrs):
        element = {"tag": tag, "attrs": dict(attrs), "text": ""}
        self.elements.append(element)
        if tag not in {"br", "hr", "img", "input", "meta", "link", "path"}:
            self.stack.append(element)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]["tag"] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        self.text += data
        for element in self.stack:
            element["text"] += data

    def by_class(self, name):
        return [element for element in self.elements
                if name in element["attrs"].get("class", "").split()]


@pytest.mark.parametrize("with_evidence,expected", [(True, "LOW RISK"), (False, "NOT ASSESSED")])
def test_threat_headline_excludes_unassessed_account_and_displays_separate_note(with_evidence, expected):
    from core.threat_catalog import THREAT_DEFINITIONS
    from core.threat_model import build_threat_model

    modules = {module for threat in THREAT_DEFINITIONS for module in threat["modules"]}
    evidence = [{"module": module, "status": "pass", "findings": []} for module in modules]
    model = build_threat_model(evidence if with_evidence else [], auth_rbac_enabled=with_evidence)
    account = next(threat for threat in model["threats"] if threat["id"] == "TM-014")
    assert account["detection_status"] == "NOT ASSESSED"
    assert account["residual_risk"] == 12
    assert model["summary"]["overall_threat_posture"] == expected
    app = AppTest.from_string(
        "import streamlit as st\n"
        "from dashboard.pages.threat_model import render_threat_model_page\n"
        "render_threat_model_page(st.session_state['test_threat_model'])\n",
        default_timeout=20,
    )
    app.session_state["test_threat_model"] = model
    app.run()
    assert not app.exception
    markup = _Elements("".join(item.value for item in app.markdown))
    posture, = markup.by_class("threat-posture")
    assert expected in posture["text"]
    excluded = "NOT ASSESSED" if with_evidence else "HIGH RISK"
    assert excluded not in posture["text"]
    assert model["summary"]["not_assessed_note"] in [item.value for item in app.caption]
    metric = next(item for item in app.metric if item.label == "Not assessed")
    assert int(metric.value) == model["summary"]["not_assessed"] > 0


def test_app_has_no_dead_inline_theme_and_uses_theme_module():
    app_tree = ast.parse((ROOT / "dashboard" / "app.py").read_text(encoding="utf-8"))
    assert not any(isinstance(node, ast.Constant) and isinstance(node.value, str)
                   and "<style" in node.value.lower() for node in ast.walk(app_tree))
    assert any(isinstance(node, ast.ImportFrom) and node.module == "dashboard.theme"
               and any(alias.name == "inject_credora_theme" for alias in node.names)
               for node in app_tree.body)
    assert any(isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
               and isinstance(node.value.func, ast.Name) and node.value.func.id == "inject_credora_theme"
               for node in app_tree.body)
    theme = (ROOT / "dashboard" / "theme.py").read_text(encoding="utf-8")
    assert "<style>" in theme and "#ad3438" in theme.lower()


@pytest.mark.parametrize("score,tier", [(95, "A"), (80, "B"), (60, "C"), (30, "D"), (80, None)])
def test_overview_highlights_only_actual_issued_tier(monkeypatch, score, tier):
    from dashboard.components import overview

    ui = MagicMock()
    monkeypatch.setattr(overview, "st", ui)
    overview.render_metric_cards(score, 90, 10, 0, ([score], [90], [10]), tier is not None, True)
    markup = _Elements(ui.markdown.call_args.args[0])
    legend, = markup.by_class("tier-legend")
    active = [element["text"].strip().split()[0] for element in markup.by_class("active")]
    assert active == ([tier] if tier else [])
    assert all(label in legend["text"] for label in ("A", "B", "C", "D"))
    ring, = markup.by_class("overview-tier-ring")
    assert (tier if tier else "Score unavailable") in (ring["text"] if tier else legend["text"])


def _auth_app(monkeypatch):
    monkeypatch.setattr("dashboard.pages.auth.init_db", lambda: None)
    return AppTest.from_string(
        "from dashboard.pages.auth import require_dashboard_auth\nrequire_dashboard_auth()\n",
        default_timeout=20,
    ).run()


def test_auth_modes_have_no_or_separator_or_enterprise_claim(monkeypatch):
    app = _auth_app(monkeypatch)
    for register in (False, True):
        if register:
            app.button(key="show-register").click().run()
        assert not app.exception
        rendered = " ".join(item.value for item in app.markdown)
        elements = _Elements(rendered)
        visible = elements.text
        visible += " " + " ".join(item.value for item in app.caption)
        assert "enterprise" not in visible.lower()
        assert not any(element["text"].strip().upper() == "OR" for element in elements.elements)
        assert not any(_Elements(item.value).text.strip().upper() == "OR" for item in app.markdown)
        assert "OR" not in [item.value.strip().upper() for item in app.caption]
        assert not any("sso" in button.label.lower() for button in app.button)


def test_registration_confirmation_blocks_mismatch_before_registration(monkeypatch):
    registration = Mock(side_effect=ValueError("Registration reached after matching confirmation"))
    monkeypatch.setattr("dashboard.pages.auth.create_user", registration)
    app = _auth_app(monkeypatch)
    app.button(key="show-register").click().run()
    fields = {field.label: field for field in app.text_input}
    fields["Username"].set_value("phase4-user")
    fields["Email address"].set_value("user@example.test")
    fields["Password"].set_value("a-secure-test-password")
    fields["Confirm password"].set_value("different-password")
    next(button for button in app.button if button.label.startswith("Create Account")).click().run()
    assert not app.exception
    registration.assert_not_called()
    assert any("Passwords do not match" in error.value for error in app.error)
    assert "auth_user" not in app.session_state
    next(field for field in app.text_input if field.label == "Confirm password").set_value("a-secure-test-password")
    next(button for button in app.button if button.label.startswith("Create Account")).click().run()
    assert not app.exception
    registration.assert_called_once_with("phase4-user", "a-secure-test-password", "user@example.test", role="uploader")


def test_report_displays_filename_not_absolute_server_path(monkeypatch, tmp_path):
    from dashboard.pages import reports

    ui = MagicMock()
    ui.session_state = {}
    ui.columns.return_value = (MagicMock(), MagicMock())
    monkeypatch.setattr(reports, "st", ui)
    report_root = tmp_path / "private-server-directory" / "reports"
    monkeypatch.setattr(reports, "REPORT_DIR", report_root)
    monkeypatch.setattr(reports, "render_page_head", Mock())
    monkeypatch.setattr(reports, "validate_report_evidence", Mock())
    monkeypatch.setattr(reports, "assert_report_artifact_integrity", Mock())
    monkeypatch.setattr(reports, "list_trusted_signers", Mock(return_value=[]))
    monkeypatch.setattr(reports, "verify_report_against_trusted_signers", Mock(return_value={}))
    reports.render_reports_page(
        current_user={"id": 7, "role": "uploader"}, report_data={}, deployment_gate={},
        model_name="traffic-model", generated_at="2026-10-20T00:00:00Z", trust_score=70,
        trust_score_issued=True, threat_model={}, remediation_plan=[], analysis_trace=[],
    )
    rendered = "".join(call.args[0] for call in ui.markdown.call_args_list)
    markup = _Elements(rendered)
    artifact, = markup.by_class("path-box")
    assert artifact["text"] == "traffic-model_phase2_trust_report.json"
    assert str(report_root) not in rendered
    assert "/" not in artifact["text"] and "\\" not in artifact["text"]
    download, = ui.download_button.call_args_list
    assert download.kwargs["file_name"] == artifact["text"]
