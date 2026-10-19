from html.parser import HTMLParser
from unittest.mock import Mock

from streamlit.material_icon_names import ALL_MATERIAL_ICONS

from dashboard.components import overview


class MetricSymbols(HTMLParser):
    def __init__(self):
        super().__init__()
        self.symbols = []
        self.symbol_span = False

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "span" and "material-symbols-rounded" in attributes.get("class", "").split():
            assert attributes.get("aria-hidden") == "true"
            assert "Material Symbols Rounded" in attributes.get("style", "")
            self.symbol_span = True

    def handle_data(self, data):
        if self.symbol_span:
            self.symbols.append(data)

    def handle_endtag(self, tag):
        if tag == "span":
            self.symbol_span = False


def render_cards(monkeypatch, *, issued=True, gate_passed=False):
    markdown = Mock()
    monkeypatch.setattr(overview.st, "markdown", markdown)
    overview.render_metric_cards(73, 91, 38, 2, ([61, 73], [88, 91], [40, 38]), issued, gate_passed)
    markdown.assert_called_once()
    assert markdown.call_args.kwargs["unsafe_allow_html"] is True
    return markdown.call_args.args[0]


def test_metric_cards_use_three_distinct_bundled_standard_symbols(monkeypatch):
    markup = render_cards(monkeypatch)
    parser = MetricSymbols()
    parser.feed(markup)
    assert parser.symbols == ["speed", "fingerprint", "inventory_2"]
    assert len(set(parser.symbols)) == 3
    assert set(parser.symbols) <= ALL_MATERIAL_ICONS
    assert '<strong>73<small>/ 100</small>' in markup
    assert '<strong>91<small>/ 100</small>' in markup
    assert '<strong>38<small>/ 100</small>' in markup
    assert "2 actionable finding(s)" in markup
    assert "Security Gate failed" in markup
    assert "Do not deploy" in markup
    assert "Deployment blocked" in markup


def test_standard_icons_preserve_unissued_score_state(monkeypatch):
    markup = render_cards(monkeypatch, issued=False)
    assert "<strong>Not issued</strong>" in markup
    assert "Assessment score unavailable" in markup
    assert "Score unavailable" in markup
    assert "Ready for production" not in markup
    parser = MetricSymbols()
    parser.feed(markup)
    assert parser.symbols == ["speed", "fingerprint", "inventory_2"]


def test_existing_non_metric_icons_keep_their_svg_contract():
    for name in ("shield", "integrity", "database", "model", "clock", "chip", "search", "bell", "info"):
        markup = overview._icon(name)
        assert markup.startswith('<svg class="ui-icon" aria-hidden="true" viewBox="0 0 24 24">')
        assert markup.endswith("</svg>")
        assert "material-symbols" not in markup
    assert overview._icon("unknown") == overview._icon("info")
