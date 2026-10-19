from __future__ import annotations

import ast
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from dashboard.components.assurance_gauge import assurance_gauge_html


def _elements(score, status="Assessment complete"):
    return list(ET.fromstring(assurance_gauge_html(score, status)).iter())


def test_arcs_are_unfilled_and_have_visible_segmented_strokes():
    paths = [item for item in _elements(72) if item.tag.endswith("path")]
    assert len(paths) == 5
    assert all(item.get("fill") == "none" for item in paths)
    assert all(float(item.get("stroke-width")) > 0 and item.get("stroke") for item in paths)
    assert [item.get("stroke-dasharray") for item in paths[1:]] == ["50 50", "20 80", "15 85", "15 85"]
    assert [item.get("stroke-dashoffset") for item in paths[1:]] == ["0", "-50", "-70", "-85"]


@pytest.mark.parametrize("score,readout,angle,tier", [
    (-20, "0.0", -90, "Tier 1"), (0, "0.0", -90, "Tier 1"),
    (50, "50.0", 0, "Tier 2"), (70, "70.0", 36, "Tier 3"),
    (85, "85.0", 63, "Tier 4"), (100, "100.0", 90, "Tier 4"),
    (120, "100.0", 90, "Tier 4"), ("82.5", "82.5", 58.5, "Tier 3"),
])
def test_score_is_visible_and_clamped_to_the_full_semicircle(score, readout, angle, tier):
    elements = _elements(score)
    svg = next(item for item in elements if item.tag.endswith("svg"))
    assert svg.get("aria-label") == f"Trust score {readout} out of 100"
    group = next(item for item in elements if item.tag == "{http://www.w3.org/2000/svg}g")
    assert group.get("transform") == f"rotate({angle:.1f} 120 120)"
    text = next(item for item in elements if item.get("class") == "assurance-readout")
    assert readout in "".join(text.itertext())
    assert text.get("fill") == "#201a1a"
    assert any(tier in (item.text or "") for item in elements)
    labels = [item.text for item in elements if item.tag.endswith("text")]
    assert "0" in labels and "100" in labels


@pytest.mark.parametrize("score", [None, "", "unavailable", float("nan"), float("inf"), -float("inf"), True])
def test_missing_or_invalid_score_is_not_shown_as_zero_or_trusted(score):
    elements = _elements(score)
    assert not any(item.get("class") == "gauge-needle" for item in elements)
    assert not any(item.get("class") == "gauge-hub" for item in elements)
    svg = next(item for item in elements if item.tag.endswith("svg"))
    assert svg.get("aria-label") == "Trust score not evaluated"
    text = next(item for item in elements if item.get("class") == "assurance-readout")
    assert "--" in "".join(text.itertext())
    assert any(item.text == "Not evaluated" for item in elements)


def test_status_text_is_escaped():
    markup = assurance_gauge_html(None, '<img src="x" onerror="alert(1)"/>')
    assert "<img" not in markup
    assert "&lt;img" in markup
    ET.fromstring(markup)


@pytest.mark.parametrize("score,readout", [(0, "0.0"), (100, "100.0"), (None, "--"), (float("nan"), "--")])
def test_app_wrapper_uses_the_self_contained_gauge_and_keeps_evidence_bars(score, readout):
    app_path = Path(__file__).resolve().parents[1] / "dashboard" / "app.py"
    tree = ast.parse(app_path.read_text(encoding="utf-8"))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "assurance_tier_html")
    # Load only the pure renderer; importing app.py would start the dashboard.
    namespace = {
        "safe_score": lambda value: float(value or 0),
        "adversarial": {"score": 75}, "classifier": {"score": 85},
        "leakage": {"score": 65}, "privacy": {"score": 70},
        "runtime_integrity": {"score": 95},
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(app_path), "exec"), namespace)  # noqa: S102
    markup = namespace["assurance_tier_html"](score, "Blocked")
    elements = list(ET.fromstring(markup).iter())
    assert "Assurance Tier Architecture" in markup
    assert "65 / 100" in markup
    assert "Blocked" in markup
    assert "&#10003;" not in markup and "\u2713" not in markup
    text = next(item for item in elements if item.get("class") == "assurance-readout")
    assert readout in "".join(text.itertext())
    paths = [item for item in elements if item.tag.endswith("path")]
    assert len(paths) == 5 and all(item.get("fill") == "none" for item in paths)
