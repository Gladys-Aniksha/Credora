"""Build small deterministic ONNX sequence fixtures for local and CI testing."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import onnx
from onnx import TensorProto, helper

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = PROJECT_ROOT / "data"
SEQUENCE_LENGTH = 32
VOCAB_SIZE = 256
LABELS = ["Benign-HTTPS", "Benign-DoH", "Malicious-DoH-Tunnel"]
CENTERS = np.asarray([32.0, 96.0, 160.0], dtype=np.float32)

TRAINED_LENGTH = 128
TRAINED_LABELS = ["Synthetic-A", "Synthetic-B", "Synthetic-C", "Synthetic-D"]
MOTIFS = np.asarray([
    [240, 241, 242, 243], [241, 243, 240, 242],
    [242, 240, 243, 241], [243, 242, 241, 240],
], dtype=np.int64)


def motif_dataset(seed: int, rows: int) -> dict[str, np.ndarray]:
    """Balanced classes with identical motif token counts but different order."""
    rng = np.random.default_rng(seed)
    classes = np.arange(rows) % len(TRAINED_LABELS)
    rng.shuffle(classes)
    tokens = rng.integers(1, 240, (rows, TRAINED_LENGTH), dtype=np.int64)
    offsets = rng.integers(0, TRAINED_LENGTH - MOTIFS.shape[1] + 1, rows)
    for row, (label, offset) in enumerate(zip(classes, offsets)):
        tokens[row, offset:offset + MOTIFS.shape[1]] = MOTIFS[label]
    return {"X": tokens, "y": np.asarray(TRAINED_LABELS)[classes], "motif_start": offsets}


def _torch_dependency():
    try:
        import torch
    except ImportError as exc:
        raise RuntimeError(
            "--trained requires development-only PyTorch; install requirements-model-build.txt "
            "in a development environment. The default builder does not need Torch."
        ) from exc
    return torch


def _train_cnn(torch, data: dict[str, np.ndarray], seed: int, weak: bool):
    torch.manual_seed(seed)

    class MotifCNN(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.embedding = torch.nn.Embedding(VOCAB_SIZE, 16, padding_idx=0)
            self.conv = torch.nn.Conv1d(16, 32, kernel_size=MOTIFS.shape[1])
            self.classifier = torch.nn.Linear(32, len(TRAINED_LABELS))

        def forward(self, tokens):
            embedded = self.embedding(tokens).transpose(1, 2)
            features = torch.relu(self.conv(embedded)).amax(dim=2)
            return self.classifier(features)

    model = MotifCNN().cpu()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.003)
    class_ids = {label: index for index, label in enumerate(TRAINED_LABELS)}
    x = torch.from_numpy(data["X"])
    y = torch.tensor([class_ids[label] for label in data["y"]], dtype=torch.long)
    # Same initial weights and optimizer; only exposure to training data differs.
    rows, epochs = (32, 1) if weak else (len(x), 12)
    generator = torch.Generator().manual_seed(seed + 1)
    model.train()
    for _ in range(epochs):
        for indices in torch.randperm(rows, generator=generator).split(128):
            optimizer.zero_grad()
            loss = torch.nn.functional.cross_entropy(model(x[indices]), y[indices])
            loss.backward()
            optimizer.step()
    return model.eval(), {"seed": seed, "epochs": epochs, "rows_used": rows,
                          "batch_size": 128, "learning_rate": 0.003, "optimizer": "Adam"}


def _export_cnn(model, path: Path) -> None:
    """Export learned CPU weights directly, avoiding exporter-version dependencies."""
    from onnx import numpy_helper

    weights = [numpy_helper.from_array(value.detach().cpu().numpy(), name)
               for name, value in model.state_dict().items()]
    nodes = [
        helper.make_node("Gather", ["embedding.weight", "tokens"], ["embedding"], axis=0),
        helper.make_node("Transpose", ["embedding"], ["channels"], perm=[0, 2, 1]),
        helper.make_node("Conv", ["channels", "conv.weight", "conv.bias"], ["convolved"]),
        helper.make_node("Relu", ["convolved"], ["activated"]),
        helper.make_node("ReduceMax", ["activated"], ["pooled"], axes=[2], keepdims=0),
        helper.make_node("Gemm", ["pooled", "classifier.weight", "classifier.bias"],
                         ["logits"], transB=1),
    ]
    graph = helper.make_graph(
        nodes, "trained-synthetic-motif-cnn",
        [helper.make_tensor_value_info("tokens", TensorProto.INT64, [None, TRAINED_LENGTH])],
        [helper.make_tensor_value_info("logits", TensorProto.FLOAT, [None, len(TRAINED_LABELS)])],
        initializer=weights,
    )
    exported = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 15)],
                                 producer_name="credora-trained-fixture")
    exported.ir_version = 8
    onnx.checker.check_model(exported, full_check=True)
    if any(weight.external_data or weight.data_location == TensorProto.EXTERNAL
           for weight in exported.graph.initializer):
        raise ValueError("Trained fixture must not contain external tensor data.")
    onnx.save_model(exported, str(path), save_as_external_data=False)


def _probabilities(session, tokens: np.ndarray) -> np.ndarray:
    logits = session.run(None, {"tokens": tokens})[0]
    exponent = np.exp(logits - logits.max(axis=1, keepdims=True))
    return exponent / exponent.sum(axis=1, keepdims=True)


def build_trained(root: Path, seed: int = 1729) -> dict:
    """Manually regenerate trained fixtures without touching the quick CI kit."""
    torch = _torch_dependency()
    import onnxruntime as ort
    from sklearn.metrics import accuracy_score, f1_score

    if root.resolve() == (DATA_ROOT / "sequence_test_kit").resolve():
        raise ValueError("Use a separate output directory for trained fixtures.")
    names = ["credora_sequence_strong", "credora_sequence_weak"]
    for name in names:
        target = root / name
        if any((target / filename).exists() for filename in
               (f"{name}.onnx", "train.npz", "test.npz", "metadata.json")):
            raise FileExistsError(f"Refusing to replace existing fixtures in {target}")
    train, test = motif_dataset(seed + 10, 3072), motif_dataset(seed + 20, 768)
    previous_threads = torch.get_num_threads()
    previous_determinism = torch.are_deterministic_algorithms_enabled()
    previous_warn_only = torch.is_deterministic_algorithms_warn_only_enabled()
    evidence = {}
    try:
        torch.set_num_threads(1)
        torch.use_deterministic_algorithms(True)
        with torch.random.fork_rng(devices=[]):
            for name, weak in zip(names, [False, True]):
                model, training = _train_cnn(torch, train, seed, weak)
                target = root / name
                target.mkdir(parents=True, exist_ok=True)
                model_path = target / f"{name}.onnx"
                _export_cnn(model, model_path)
                options = ort.SessionOptions()
                options.intra_op_num_threads = 1
                session = ort.InferenceSession(str(model_path), sess_options=options,
                                               providers=["CPUExecutionProvider"])
                with torch.no_grad():
                    expected = model(torch.from_numpy(test["X"][:17])).numpy()
                actual = session.run(None, {"tokens": test["X"][:17]})[0]
                np.testing.assert_allclose(actual, expected, rtol=1e-4, atol=1e-5)
                probabilities = _probabilities(session, test["X"])
                if not np.isfinite(probabilities).all():
                    raise ValueError("Nonfinite trained fixture probabilities.")
                np.testing.assert_allclose(probabilities.sum(axis=1), 1, atol=1e-6)
                predictions = np.asarray(TRAINED_LABELS)[probabilities.argmax(axis=1)]
                metrics = {"accuracy": float(accuracy_score(test["y"], predictions)),
                           "weighted_f1": float(f1_score(test["y"], predictions, average="weighted"))}
                # A one-token occlusion sample supplies reproducible saliency evidence.
                sample = test["X"][:1]
                occluded = np.repeat(sample, TRAINED_LENGTH, axis=0)
                occluded[np.arange(TRAINED_LENGTH), np.arange(TRAINED_LENGTH)] = 0
                label = TRAINED_LABELS.index(test["y"][0])
                drops = probabilities[0, label] - _probabilities(session, occluded)[:, label]
                start = int(test["motif_start"][0])
                saliency = {"sample_index": 0, "motif_start": start, "motif_length": 4,
                            "peak_position": int(drops.argmax()),
                            "peak_probability_drop": float(drops.max()),
                            "peak_in_motif": bool(start <= drops.argmax() < start + 4)}
                for split, data in [("train", train), ("test", test)]:
                    np.savez_compressed(target / f"{split}.npz", **data)
                metadata = {
                    "model_name": name, "version": "2.0", "algorithm": "Trained 1D-CNN",
                    "framework": "PyTorch exported to ONNX", "task": "Synthetic motif classification",
                    "input_type": "sequence", "max_sequence_length": TRAINED_LENGTH,
                    "sequence_dtype": "int64", "vocab_size": VOCAB_SIZE, "pad_id": 0,
                    "class_labels": TRAINED_LABELS, "target_column": "label",
                    "training_dataset_path": str((target / "train.npz").resolve()),
                    "training": {**training, "torch_version": str(torch.__version__),
                                 "device": "cpu", "deterministic_algorithms": True,
                                 "weakening": "one epoch on first 32 rows" if weak else "none"},
                    "architecture": "Embedding(256,16), Conv1d(16,32,4), ReLU, global max, Linear(32,4)",
                    "export": {"opset": 15, "external_data": False,
                               "method": "learned weights mapped to standard ONNX operators",
                               "pytorch_onnx_parity_checked": True},
                    "dataset": {"train_seed": seed + 10, "test_seed": seed + 20,
                                "train_rows": len(train["X"]), "test_rows": len(test["X"]),
                                "motifs": MOTIFS.tolist(), "offsets": "uniform, inclusive 0..124"},
                    "test_metrics": metrics, "occlusion_sample": saliency,
                    "fixture_note": "Trained on artificial ordered token motifs with random background. "
                                    "Not network captures; classes are synthetic and metrics do not "
                                    "establish real traffic detection, privacy, or robustness. "
                                    "Seeds reproduce CPU builds within the same dependency environment; "
                                    "cross-version bitwise identity is not guaranteed.",
                }
                (target / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
                evidence[name] = {"metrics": metrics, "saliency": saliency}
        strong_evidence, weak_evidence = (evidence[name] for name in names)
        if not (strong_evidence["metrics"]["accuracy"] >= 0.9
                and strong_evidence["metrics"]["weighted_f1"] > weak_evidence["metrics"]["weighted_f1"] + 0.2
                and strong_evidence["metrics"]["accuracy"] > weak_evidence["metrics"]["accuracy"] + 0.2
                and strong_evidence["saliency"]["peak_in_motif"]
                and strong_evidence["saliency"]["peak_probability_drop"] > 0):
            raise RuntimeError(f"Trained fixture quality checks failed: {evidence}")
    finally:
        torch.set_num_threads(previous_threads)
        torch.use_deterministic_algorithms(previous_determinism, warn_only=previous_warn_only)
    return evidence


def _model(path: Path, weak: bool) -> None:
    input_info = helper.make_tensor_value_info("tokens", TensorProto.INT64, [None, SEQUENCE_LENGTH])
    output_info = helper.make_tensor_value_info("logits", TensorProto.FLOAT, [None, len(LABELS)])
    nodes = [
        helper.make_node("Cast", ["tokens"], ["float_tokens"], to=TensorProto.FLOAT),
        helper.make_node("ReduceMean", ["float_tokens"], ["mean_token"], axes=[1], keepdims=0),
    ]
    centers = np.repeat(96.0, len(LABELS)) if weak else CENTERS
    columns = []
    for index, center in enumerate(centers):
        center_name = f"center_{index}"
        distance = f"distance_{index}"
        magnitude = f"magnitude_{index}"
        score = f"score_{index}"
        nodes.extend([
            helper.make_node("Constant", [], [center_name], value=helper.make_tensor(center_name, TensorProto.FLOAT, [], [float(center)])),
            helper.make_node("Sub", ["mean_token", center_name], [distance]),
            helper.make_node("Abs", [distance], [magnitude]),
            helper.make_node("Neg", [magnitude], [score]),
            helper.make_node("Unsqueeze", [score], [f"column_{index}"], axes=[1]),
        ])
        columns.append(f"column_{index}")
    nodes.append(helper.make_node("Concat", columns, ["logits"], axis=1))
    graph = helper.make_graph(nodes, "credora-sequence-fixture", [input_info], [output_info])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 11)], producer_name="credora")
    model.ir_version = 8
    onnx.checker.check_model(model)
    path.write_bytes(model.SerializeToString())


def _dataset(path: Path, seed: int, rows: int) -> None:
    rng = np.random.default_rng(seed)
    labels = rng.integers(0, len(LABELS), size=rows)
    means = CENTERS[labels]
    values = np.clip(rng.normal(means[:, None], 7.0, size=(rows, SEQUENCE_LENGTH)), 0, VOCAB_SIZE - 1)
    np.savez_compressed(path, X=np.rint(values).astype(np.int64), y=np.asarray([LABELS[index] for index in labels]))


def build_variant(root: Path, name: str, weak: bool) -> None:
    target = root / name
    target.mkdir(parents=True, exist_ok=True)
    _model(target / f"{name}.onnx", weak)
    _dataset(target / "train.npz", 17 if not weak else 19, 600)
    _dataset(target / "test.npz", 23 if not weak else 29, 300)
    metadata = {
        "model_name": name,
        "version": "1.0",
        "algorithm": "Synthetic ONNX sequence classifier",
        "framework": "ONNX",
        "task": "Encrypted Traffic Sequence Classification",
        "input_type": "sequence",
        "max_sequence_length": SEQUENCE_LENGTH,
        "sequence_dtype": "int64",
        "vocab_size": VOCAB_SIZE,
        "pad_id": 0,
        "class_labels": LABELS,
        "target_column": "label",
        "training_dataset_path": f"data/sequence_test_kit/{name}/train.npz",
        "fixture_note": "Synthetic shaped data for pipeline testing; not a real network capture.",
    }
    (target / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--trained", action="store_true", help="Train optional development-only motif CNNs")
    parser.add_argument("--seed", type=int, default=1729, help="Trained build seed")
    args = parser.parse_args()
    if args.trained:
        output = args.output_dir if args.output_dir is not None else DATA_ROOT / "sequence_trained_kit"
        try:
            evidence = build_trained(output, args.seed)
        except (RuntimeError, ValueError, FileExistsError) as exc:
            parser.exit(1, f"{exc}\n")
        print(json.dumps(evidence, indent=2))
        print(f"Built trained sequence fixtures in {output}")
        return
    if args.output_dir is None:
        args.output_dir = DATA_ROOT / "sequence_test_kit"
    build_variant(args.output_dir, "credora_sequence_strong", weak=False)
    build_variant(args.output_dir, "credora_sequence_weak", weak=True)
    print(f"Built sequence fixtures in {args.output_dir}")


if __name__ == "__main__":
    main()
