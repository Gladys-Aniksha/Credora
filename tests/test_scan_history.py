from __future__ import annotations

import json

import pytest

from core import db


@pytest.fixture
def registry(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "registry.sqlite3")
    db.init_db()
    return tmp_path


def report(name, score, *, timestamp="2026-10-20T10:00:00+00:00", input_type="tabular"):
    return {
        "model_name": name, "trust_score": score, "status": "warning",
        "generated_at": timestamp, "input_type": input_type,
        "module_results": [{"module": "model_verification", "score": score + 1,
                            "details": {"version": "1.0"}}],
    }


def test_same_export_path_preserves_distinct_history_snapshots(registry):
    path = registry / "same_model_report.json"
    older, newer = report("same-model", 43), report("same-model", 70)
    path.write_text(json.dumps(older), encoding="utf-8")
    old_id = db.save_scan(older, path, owner_id=41)
    path.write_text(json.dumps(newer), encoding="utf-8")
    new_id = db.save_scan(newer, path, owner_id=41)
    # Export mutation and caller mutation must not rewrite either saved assessment.
    path.write_text('{"model_name":"wrong-export","trust_score":99}', encoding="utf-8")
    newer["module_results"][0]["score"] = -1
    path.unlink()
    history = db.list_scan_reports(owner_id=41, model_name="same-model")
    assert [item["trust_score"] for item in history] == [70, 43]
    assert [item["module_results"][0]["score"] for item in history] == [71, 44]
    assert db.latest_scan(owner_id=41) == history[0]
    assert db.latest_scan(owner_id=41, model_name="same-model") == history[0]
    assert db.get_scan_record(old_id, owner_id=41)["report"] == history[1]
    assert db.get_scan_record(new_id, owner_id=41)["report"] == history[0]
    assert [item["id"] for item in db.list_scans(owner_id=41)] == [new_id, old_id]


def test_latest_report_filters_model_and_owner_without_falling_back(registry):
    path = registry / "shared-name.json"
    alice_model = report("selected-model", 46)
    bob_model = report("selected-model", 88)
    alice_newest = report("different-model", 62)
    db.save_scan(alice_model, path, owner_id=41)
    bob_id = db.save_scan(bob_model, path, owner_id=42)
    db.save_scan(alice_newest, path, owner_id=41)
    assert db.latest_scan(owner_id=41, model_name="selected-model") == alice_model
    assert db.latest_scan(owner_id=42, model_name="selected-model") == bob_model
    assert db.latest_scan(owner_id=41) == alice_newest
    assert db.latest_scan(owner_id=42) == bob_model
    assert db.latest_scan(owner_id=41, model_name="missing-model") is None
    assert db.latest_scan(owner_id=99, model_name="selected-model") is None
    assert db.latest_scan(owner_id=99) is None
    assert db.get_scan_record(bob_id, owner_id=41) is None
    assert db.list_scan_reports(owner_id=41, model_name="selected-model") == [alice_model]
    assert db.list_scan_reports(owner_id=99) == []
    assert [item["model_name"] for item in db.list_scans(owner_id=41)] == ["different-model", "selected-model"]


def test_latest_uses_save_order_not_equal_or_backdated_timestamps(registry):
    path = registry / "model.json"
    older = report("model", 51)
    same_time = report("model", 59)
    backdated = report("model", 67, timestamp="2020-01-01T00:00:00+00:00")
    for item in (older, same_time, backdated):
        db.save_scan(item, path, owner_id=41)
    assert db.latest_scan(owner_id=41) == backdated
    assert db.latest_scan(owner_id=41, model_name="model") == backdated
    assert db.list_scan_reports(owner_id=41, limit=2) == [backdated, same_time]


def test_explicit_all_owner_scope_preserves_model_filter(registry):
    path = registry / "model.json"
    alice = report("model", 52)
    bob = report("model", 79)
    other = report("another-model", 91)
    db.save_scan(alice, path, owner_id=41)
    db.save_scan(bob, path, owner_id=42)
    db.save_scan(other, path, owner_id=42)
    assert db.latest_scan(owner_id=41, include_all=True, model_name="model") == bob
    assert db.latest_scan(owner_id=41, include_all=True) == other
    assert db.list_scan_reports(owner_id=41, include_all=True, model_name="model") == [bob, alice]
    # Retain the existing unscoped behavior for trusted internal callers.
    assert db.latest_scan(model_name="model") == bob


def test_model_selection_is_not_limited_to_recent_hundred_scans(registry):
    path = registry / "report.json"
    selected = report("old-selected-model", 57)
    db.save_scan(selected, path, owner_id=41)
    for index in range(101):
        db.save_scan(report(f"other-{index}", 70), path, owner_id=41)
    assert "old-selected-model" not in {item["model_name"] for item in db.list_scans(limit=100, owner_id=41)}
    assert db.latest_scan(owner_id=41, model_name="old-selected-model") == selected
    assert db.list_scan_reports(owner_id=41, model_name="old-selected-model", limit=1) == [selected]


def test_same_model_retains_tabular_and_sequence_snapshots(registry):
    path = registry / "model.json"
    tabular, sequence = report("model", 61), report("model", 69, input_type="sequence")
    db.save_scan(tabular, path, owner_id=41)
    db.save_scan(sequence, path, owner_id=41)
    assert db.list_scan_reports(owner_id=41, model_name="model") == [sequence, tabular]
    assert db.latest_scan(owner_id=41, model_name="model") == sequence
