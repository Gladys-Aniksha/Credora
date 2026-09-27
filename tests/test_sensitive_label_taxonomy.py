from __future__ import annotations

from modules.phase2_deep_trust.m8_behavior_analysis import behavior
from modules.phase3_operations.m4_adversarial_validation import adversarial


def test_behavior_and_adversarial_modules_use_the_same_sensitive_taxonomy(monkeypatch) -> None:
    taxonomy = ["abuse", "command-and-control"]
    labels = ["Benign", "AbuseTraffic", "Command-And-Control", "DDoS"]
    expected = ["AbuseTraffic", "Command-And-Control"]

    monkeypatch.setattr(behavior, "get_sensitive_label_taxonomy", lambda: taxonomy)
    monkeypatch.setattr(adversarial, "get_sensitive_label_taxonomy", lambda: taxonomy)

    assert behavior._sensitive_labels(labels) == expected
    assert adversarial._sensitive_labels(labels) == expected
