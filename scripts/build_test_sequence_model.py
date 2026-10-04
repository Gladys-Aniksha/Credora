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
    parser.add_argument("--output-dir", type=Path, default=DATA_ROOT / "sequence_test_kit")
    args = parser.parse_args()
    build_variant(args.output_dir, "credora_sequence_strong", weak=False)
    build_variant(args.output_dir, "credora_sequence_weak", weak=True)
    print(f"Built sequence fixtures in {args.output_dir}")


if __name__ == "__main__":
    main()
