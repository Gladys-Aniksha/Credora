from unittest.mock import MagicMock

from dashboard import theme
from dashboard.components import overview


def test_status_and_risk_labels_are_plain_text(monkeypatch):
    ui = MagicMock()
    monkeypatch.setattr(overview, "st", ui)
    overview.render_recent_assessments([{"model_name": "example", "status": "fail", "trust_score": 70}])
    overview.render_alerts([{"severity": "critical", "title": "Integrity check failed"}], "2026-10-19")
    markup = "".join(str(call.args[0]) for call in ui.markdown.call_args_list)
    assert "Failed</i>" in markup
    assert "Critical</i>" in markup
    assert "●" not in markup


def test_theme_has_balanced_width_and_text_only_status_rules(monkeypatch):
    ui = MagicMock()
    monkeypatch.setattr(theme, "st", ui)
    theme.inject_credora_theme()
    css = ui.markdown.call_args.args[0]
    assert "width:100%; max-width:1360px; padding:0 24px 28px; margin:0 auto;" in css
    assert "min-height:60px; margin:0 -24px; padding:8px 24px;" in css
    assert ".overview-metric {min-height:168px;" in css
    assert ".metric-round {width:48px; height:48px;}" in css
    assert ".metric-core strong {font-size:26px;}" in css
    assert '[data-testid="stMetricValue"] {font-size:26px;}' in css
    assert ".metric-label {font-size:12px;" in css
    assert ".metric-core p {font-size:13px;" in css
    assert "max-width:600px !important; padding:36px !important;" in css
    assert ".status-chip, .severity-chip, .status-pill" in css
    assert "background:transparent !important; border:0; border-radius:0;" in css
    assert "grid-template-columns:repeat(2,minmax(0,1fr))" in css
    assert ".module-row {display:grid;" in css
