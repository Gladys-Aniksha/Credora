from __future__ import annotations

import json
from pathlib import Path

from modules.phase1_foundation.m8_etc_classifier.evaluate import evaluate_classifier


ROOT = Path(__file__).resolve().parents[1] / "data" / "sequence_test_kit"


def _fixture(name: str) -> tuple[Path, Path, dict]:
    folder = ROOT / name
    metadata = json.loads((folder / "metadata.json").read_text(encoding="utf-8"))
    return folder / f"{name}.onnx", folder / "test.npz", metadata


def test_strong_sequence_fixture_outperforms_weak_fixture() -> None:
    strong_model, strong_data, strong_metadata = _fixture("credora_sequence_strong")
    weak_model, weak_data, weak_metadata = _fixture("credora_sequence_weak")

    strong = evaluate_classifier(strong_model, strong_data, strong_metadata)
    weak = evaluate_classifier(weak_model, weak_data, weak_metadata)

    assert strong.status == "pass"
    assert strong.score > weak.score
    assert strong.details["input_type"] == "sequence"
