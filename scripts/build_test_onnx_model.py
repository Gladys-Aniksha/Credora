from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import numpy as np
from skl2onnx import to_onnx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.model_loading import load_checked_model


def build_onnx_model(model_path: Path, metadata_path: Path, output_path: Path) -> Path:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    feature_columns = metadata.get("expected_features")
    if not feature_columns:
        raise ValueError("Metadata must define expected_features before ONNX conversion.")

    model = load_checked_model(model_path)
    sample = np.zeros((1, len(feature_columns)), dtype=np.float32)
    options = {id(model): {"zipmap": False}}
    onnx_model = to_onnx(model, sample, options=options, target_opset=15)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(onnx_model.SerializeToString())
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Credora's sample sklearn classifier to ONNX.")
    parser.add_argument(
        "--model",
        type=Path,
        default=PROJECT_ROOT / "data" / "sample_models" / "traffic_rf_v1.joblib",
    )
    parser.add_argument(
        "--metadata",
        type=Path,
        default=PROJECT_ROOT / "data" / "metadata" / "traffic_rf_v1_metadata.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "data" / "sample_models" / "traffic_rf_v1.onnx",
    )
    args = parser.parse_args()

    output_path = build_onnx_model(args.model, args.metadata, args.output)
    print(f"Created ONNX model: {output_path}")


if __name__ == "__main__":
    main()
