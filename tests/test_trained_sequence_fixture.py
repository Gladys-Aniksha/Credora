from __future__ import annotations

import builtins
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort
import pytest

from scripts import build_test_sequence_model as builder

HAS_TORCH = importlib.util.find_spec("torch") is not None
requires_torch = pytest.mark.skipif(not HAS_TORCH, reason="Optional development-only PyTorch absent")


def test_motif_data_is_reproducible_balanced_and_order_specific():
    data = builder.motif_dataset(17, 3072)
    repeat = builder.motif_dataset(17, 3072)
    other = builder.motif_dataset(23, 768)
    for key in data:
        np.testing.assert_array_equal(data[key], repeat[key])
    assert data["X"].shape == (3072, 128)
    assert data["X"].dtype == np.int64
    assert data["y"].dtype.kind == "U"
    assert data["X"].min() >= 1 and data["X"].max() < builder.VOCAB_SIZE
    assert np.unique(data["y"], return_counts=True)[1].tolist() == [768] * 4
    assert set(data["motif_start"]) == set(range(125))
    assert not np.array_equal(data["X"][:768], other["X"])
    for row, label, start in zip(data["X"], data["y"], data["motif_start"]):
        motif = builder.MOTIFS[builder.TRAINED_LABELS.index(label)]
        np.testing.assert_array_equal(row[start:start + 4], motif)
        assert (np.delete(row, np.arange(start, start + 4)) < 240).all()
    assert len({tuple(motif) for motif in builder.MOTIFS}) == 4
    assert len({tuple(sorted(motif)) for motif in builder.MOTIFS}) == 1


def test_default_cli_retains_original_paths_and_names(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(sys, "argv", ["builder"])
    monkeypatch.setattr(builder, "build_variant", lambda root, name, weak: calls.append((root, name, weak)))
    builder.main()
    root = builder.DATA_ROOT / "sequence_test_kit"
    assert calls == [(root, "credora_sequence_strong", False), (root, "credora_sequence_weak", True)]
    assert "Built sequence fixtures" in capsys.readouterr().out


def test_quick_builder_does_not_import_torch(tmp_path, monkeypatch):
    original_import = builtins.__import__

    def without_torch(name, *args, **kwargs):
        if name.split(".")[0] == "torch":
            raise AssertionError("Quick CI builder imported PyTorch")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_torch)
    for weak in [False, True]:
        name = "weak" if weak else "strong"
        builder.build_variant(tmp_path, name, weak)
        metadata = json.loads((tmp_path / name / "metadata.json").read_text())
        assert metadata["max_sequence_length"] == 32
        assert metadata["algorithm"] == "Synthetic ONNX sequence classifier"
        assert metadata["class_labels"] == builder.LABELS
        with np.load(tmp_path / name / "test.npz", allow_pickle=False) as data:
            assert data["X"].shape == (300, 32)


def test_trained_missing_dependency_is_actionable(tmp_path, monkeypatch):
    original_import = builtins.__import__

    def without_torch(name, *args, **kwargs):
        if name == "torch":
            raise ModuleNotFoundError("Torch absent")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_torch)
    monkeypatch.setattr(sys, "argv", ["builder", "--trained", "--output-dir", str(tmp_path)])
    with pytest.raises(SystemExit) as error:
        builder.main()
    assert error.value.code == 1
    assert not list(tmp_path.iterdir())
    with pytest.raises(RuntimeError, match="install torch in a separate"):
        builder.build_trained(tmp_path)


def test_trained_default_uses_separate_directory(monkeypatch):
    calls = []
    monkeypatch.setattr(sys, "argv", ["builder", "--trained"])
    monkeypatch.setattr(builder, "build_trained", lambda root, seed: calls.append((root, seed)))
    builder.main()
    assert calls == [(builder.DATA_ROOT / "sequence_trained_kit", 1729)]


@requires_torch
def test_trained_refuses_existing_and_quick_fixture_outputs(tmp_path):
    with pytest.raises(ValueError, match="separate output"):
        builder.build_trained(builder.DATA_ROOT / "sequence_test_kit")
    target = tmp_path / "credora_sequence_strong"
    target.mkdir()
    sentinel = target / "train.npz"
    sentinel.write_bytes(b"existing fixture")
    with pytest.raises(FileExistsError, match="Refusing to replace"):
        builder.build_trained(tmp_path)
    assert sentinel.read_bytes() == b"existing fixture"


@pytest.fixture(scope="module")
def trained_kit(tmp_path_factory):
    if not HAS_TORCH:
        pytest.skip("Optional development-only PyTorch absent")
    root = tmp_path_factory.mktemp("trained-sequences")
    evidence = builder.build_trained(root)
    return root, evidence


def test_trained_exports_metrics_probabilities_and_saliency(trained_kit):
    from core.onnx_safety import validate_onnx_model
    from core.sequence_validation import validate_sequence_compatibility
    from modules.phase1_foundation.m8_etc_classifier.evaluate import evaluate_classifier

    root, evidence = trained_kit
    scores = []
    datasets = []
    for name in ["credora_sequence_strong", "credora_sequence_weak"]:
        target = root / name
        path = target / f"{name}.onnx"
        metadata = json.loads((target / "metadata.json").read_text())
        assert metadata["algorithm"] == "Trained 1D-CNN"
        assert Path(metadata["training_dataset_path"]).is_file()
        graph = onnx.load(str(path), load_external_data=False)
        assert [op.version for op in graph.opset_import] == [15]
        assert all(not node.domain for node in graph.graph.node)
        assert any(node.op_type == "Conv" for node in graph.graph.node)
        assert not any(weight.external_data for weight in graph.graph.initializer)
        assert len(validate_onnx_model(path).inputs) == 1
        for split, rows in [("train", 3072), ("test", 768)]:
            with np.load(target / f"{split}.npz", allow_pickle=False) as data:
                assert data["X"].shape == (rows, 128)
                assert data["X"].dtype == np.int64
                assert set(data["y"]) == set(builder.TRAINED_LABELS)
        validate_sequence_compatibility(path, target / "test.npz", metadata)
        with np.load(target / "test.npz", allow_pickle=False) as data:
            x, y, offsets = data["X"], data["y"], data["motif_start"]
        datasets.append(x)
        session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
        probabilities = builder._probabilities(session, x)
        assert probabilities.shape == (768, 4)
        assert np.isfinite(probabilities).all()
        assert ((probabilities >= 0) & (probabilities <= 1)).all()
        np.testing.assert_allclose(probabilities.sum(axis=1), 1, atol=1e-6)
        result = evaluate_classifier(path, target / "test.npz", metadata)
        scores.append(result.score)
        assert result.details["accuracy"] == pytest.approx(metadata["test_metrics"]["accuracy"], abs=1e-4)
        if name.endswith("strong"):
            assert result.status == "pass"
            assert metadata["training"]["epochs"] == 12
            occluded = np.repeat(x[:1], 128, axis=0)
            occluded[np.arange(128), np.arange(128)] = 0
            label = builder.TRAINED_LABELS.index(y[0])
            drops = probabilities[0, label] - builder._probabilities(session, occluded)[:, label]
            assert offsets[0] <= drops.argmax() < offsets[0] + 4
            assert drops.max() > 0
        else:
            assert metadata["training"]["rows_used"] == 32
            assert metadata["training"]["epochs"] == 1
    np.testing.assert_array_equal(*datasets)
    assert scores[0] > scores[1] + 20
    assert evidence["credora_sequence_strong"]["saliency"]["peak_in_motif"]


@requires_torch
def test_cpu_training_seed_reproduces_weights():
    torch = builder._torch_dependency()
    data = builder.motif_dataset(17, 64)
    with torch.random.fork_rng(devices=[]):
        first, _ = builder._train_cnn(torch, data, 1729, weak=True)
        second, _ = builder._train_cnn(torch, data, 1729, weak=True)
    for key, weights in first.state_dict().items():
        assert torch.equal(weights, second.state_dict()[key])
