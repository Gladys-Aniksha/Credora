from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import numpy as np
import onnx
import onnxruntime as ort
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def check_variant(variant_dir: Path) -> dict:
    metadata = json.loads((variant_dir / "metadata.json").read_text(encoding="utf-8"))
    model_path = variant_dir / f"{metadata['model_name']}.onnx"
    test_path = variant_dir / "test.csv"
    onnx.checker.check_model(str(model_path))

    session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
    features = pd.read_csv(test_path)[metadata["expected_features"]].head(16)
    outputs = session.run(
        None,
        {session.get_inputs()[0].name: features.to_numpy(dtype=np.float32)},
    )
    if len(outputs) < 2:
        raise AssertionError(f"{metadata['model_name']} has no probability output.")
    probabilities = outputs[1]
    if isinstance(probabilities, (list, dict)):
        raise AssertionError(f"{metadata['model_name']} uses a ZipMap-style probability output.")
    if not isinstance(probabilities, np.ndarray) or probabilities.dtype.kind != "f":
        raise AssertionError(f"{metadata['model_name']} probabilities are not a float array.")
    if probabilities.shape != (len(features), len(metadata["class_labels"])):
        raise AssertionError(
            f"{metadata['model_name']} probability shape {probabilities.shape} is invalid."
        )
    labels = np.asarray(outputs[0]).reshape(-1).astype(str)
    if not set(labels).issubset(set(metadata["class_labels"])):
        raise AssertionError(f"{metadata['model_name']} emitted unexpected class labels.")
    return {
        "variant": metadata["model_name"],
        "label_shape": list(labels.shape),
        "probability_shape": list(probabilities.shape),
        "probability_dtype": str(probabilities.dtype),
        "zipmap": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate DoH ONNX label and probability outputs.")
    parser.add_argument(
        "--kit-root",
        type=Path,
        default=PROJECT_ROOT / "data" / "doh_onnx_test_kit",
    )
    args = parser.parse_args()
    results = [
        check_variant(args.kit_root / variant)
        for variant in ("credora_doh_strong", "credora_doh_weak")
    ]
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
