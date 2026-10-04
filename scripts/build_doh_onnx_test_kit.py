from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, cast

import numpy as np
import onnx
import pandas as pd
from onnx import TensorProto, helper
from onnxmltools import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


CLASS_LABELS = ["Benign-HTTPS", "Benign-DoH", "Malicious-DoH-Tunnel"]
TARGET_COLUMN = "label"
FEATURE_COLUMNS = [
    "duration",
    "bytes_sent",
    "bytes_received",
    "send_rate",
    "receive_rate",
    "packet_length_mean",
    "packet_length_median",
    "packet_length_mode",
    "packet_length_variance",
    "packet_length_std",
    "packet_length_skew_from_median",
    "packet_length_skew_from_mode",
    "packet_length_coefficient_of_variation",
    "packet_timing_mean",
    "packet_timing_median",
    "packet_timing_mode",
    "packet_timing_variance",
    "packet_timing_std",
    "packet_timing_skew_from_median",
    "packet_timing_skew_from_mode",
    "packet_timing_coefficient_of_variation",
]

VARIANTS = {
    "credora_doh_strong": {
        "samples": 3600,
        "weights": [0.34, 0.33, 0.33],
        "class_sep": 2.0,
        "flip_y": 0.015,
        "random_state": 431,
        "model": {
            "n_estimators": 140,
            "max_depth": 4,
            "learning_rate": 0.07,
            "subsample": 0.9,
            "colsample_bytree": 0.9,
            "min_child_weight": 2,
        },
    },
    "credora_doh_weak": {
        "samples": 2400,
        "weights": [0.68, 0.27, 0.05],
        "class_sep": 0.65,
        "flip_y": 0.09,
        "random_state": 907,
        "model": {
            "n_estimators": 7,
            "max_depth": 1,
            "learning_rate": 0.08,
            "subsample": 0.7,
            "colsample_bytree": 0.65,
            "min_child_weight": 8,
        },
    },
}


def _scale_features(values: np.ndarray) -> pd.DataFrame:
    """Map synthetic latent features into plausible DoH flow-statistic ranges."""
    scaled = np.empty_like(values, dtype=np.float64)
    positive_scales = [
        (1200.0, 850.0),
        (45000.0, 22000.0),
        (65000.0, 30000.0),
        (9000.0, 4200.0),
        (11000.0, 5000.0),
        (620.0, 210.0),
        (570.0, 190.0),
        (520.0, 175.0),
        (42000.0, 18000.0),
        (180.0, 80.0),
    ]
    for index, (center, spread) in enumerate(positive_scales):
        scaled[:, index] = np.maximum(0.001, center + values[:, index] * spread)

    scaled[:, 10] = np.clip(values[:, 10] * 0.55, -3.5, 3.5)
    scaled[:, 11] = np.clip(values[:, 11] * 0.65, -3.5, 3.5)
    scaled[:, 12] = np.maximum(0.001, 0.38 + values[:, 12] * 0.12)
    scaled[:, 13] = np.maximum(0.001, 42.0 + values[:, 13] * 18.0)
    scaled[:, 14] = np.maximum(0.001, 38.0 + values[:, 14] * 16.0)
    scaled[:, 15] = np.maximum(0.001, 34.0 + values[:, 15] * 15.0)
    scaled[:, 16] = np.maximum(0.001, 950.0 + values[:, 16] * 420.0)
    scaled[:, 17] = np.maximum(0.001, 28.0 + values[:, 17] * 12.0)
    scaled[:, 18] = np.clip(values[:, 18] * 0.55, -3.5, 3.5)
    scaled[:, 19] = np.clip(values[:, 19] * 0.65, -3.5, 3.5)
    scaled[:, 20] = np.maximum(0.001, 0.46 + values[:, 20] * 0.14)
    return pd.DataFrame(scaled, columns=FEATURE_COLUMNS).round(6)


def _replace_integer_labels(onnx_model: onnx.ModelProto) -> None:
    classifier = next(
        (node for node in onnx_model.graph.node if node.op_type == "TreeEnsembleClassifier"),
        None,
    )
    if classifier is None:
        raise RuntimeError("Converted XGBoost graph does not contain TreeEnsembleClassifier.")

    attributes = [
        attribute
        for attribute in classifier.attribute
        if attribute.name != "classlabels_int64s"
    ]
    del classifier.attribute[:]
    classifier.attribute.extend(attributes)
    classifier.attribute.append(helper.make_attribute("classlabels_strings", CLASS_LABELS))
    onnx_model.graph.output[0].type.tensor_type.elem_type = TensorProto.STRING


def _export_onnx(model: XGBClassifier, output_path: Path) -> None:
    # onnxmltools 1.16 emits a tensor probability output directly and has no
    # zipmap conversion option. The companion checker enforces that contract.
    converted = convert_xgboost(
        model,
        initial_types=[("flow_features", FloatTensorType([None, len(FEATURE_COLUMNS)]))],
        target_opset=15,
    )
    _replace_integer_labels(converted)
    onnx.checker.check_model(converted)
    output_path.write_bytes(converted.SerializeToString())


def _metadata(variant: str, train_path: Path, accuracy: float, gap: float) -> dict:
    return {
        "model_name": variant,
        "version": "1.0",
        "algorithm": "XGBoost",
        "framework": "ONNX (onnxmltools XGBoost converter)",
        "task": "DNS-over-HTTPS Tunnel Detection",
        "input_type": "tabular",
        "target_column": TARGET_COLUMN,
        "training_dataset_path": train_path.relative_to(PROJECT_ROOT).as_posix(),
        "expected_features": FEATURE_COLUMNS,
        "class_labels": CLASS_LABELS,
        "signature_status": "unverified",
        "synthetic_data": True,
        "measured_test_accuracy": round(accuracy, 6),
        "measured_train_test_accuracy_gap": round(gap, 6),
    }


def build_variant(variant: str, output_root: Path) -> dict:
    config = cast(dict[str, Any], VARIANTS[variant])
    features, target = make_classification(
        n_samples=int(config["samples"]),
        n_features=len(FEATURE_COLUMNS),
        n_informative=14,
        n_redundant=4,
        n_repeated=0,
        n_classes=len(CLASS_LABELS),
        n_clusters_per_class=2,
        weights=config["weights"],
        class_sep=float(config["class_sep"]),
        flip_y=float(config["flip_y"]),
        random_state=int(config["random_state"]),
    )
    frame = _scale_features(features)
    frame[TARGET_COLUMN] = [CLASS_LABELS[index] for index in target]
    train_frame, test_frame = train_test_split(
        frame,
        test_size=0.25,
        stratify=frame[TARGET_COLUMN],
        random_state=int(config["random_state"]) + 1,
    )

    label_to_index = {label: index for index, label in enumerate(CLASS_LABELS)}
    x_train = train_frame[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    y_train = train_frame[TARGET_COLUMN].map(label_to_index).astype(int)
    x_test = test_frame[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    y_test = test_frame[TARGET_COLUMN].map(label_to_index).astype(int)
    model = XGBClassifier(
        objective="multi:softprob",
        num_class=len(CLASS_LABELS),
        eval_metric="mlogloss",
        random_state=int(config["random_state"]),
        n_jobs=1,
        tree_method="hist",
        base_score=0.5,
        **config["model"],
    )
    model.fit(x_train, y_train)
    train_accuracy = float(model.score(x_train, y_train))
    test_accuracy = float(model.score(x_test, y_test))
    gap = train_accuracy - test_accuracy

    variant_dir = output_root / variant
    variant_dir.mkdir(parents=True, exist_ok=True)
    train_path = variant_dir / "train.csv"
    test_path = variant_dir / "test.csv"
    model_path = variant_dir / f"{variant}.onnx"
    metadata_path = variant_dir / "metadata.json"
    train_frame.to_csv(train_path, index=False)
    test_frame.to_csv(test_path, index=False)
    _export_onnx(model, model_path)
    metadata_path.write_text(
        json.dumps(_metadata(variant, train_path, test_accuracy, gap), indent=2),
        encoding="utf-8",
    )
    return {
        "variant": variant,
        "train_rows": len(train_frame),
        "test_rows": len(test_frame),
        "train_accuracy": round(train_accuracy, 6),
        "test_accuracy": round(test_accuracy, 6),
        "train_test_gap": round(gap, 6),
        "model_path": str(model_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Credora's synthetic XGBoost DoH ONNX test kit.")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=PROJECT_ROOT / "data" / "doh_onnx_test_kit",
    )
    args = parser.parse_args()
    args.output_root.mkdir(parents=True, exist_ok=True)
    summaries = [build_variant(variant, args.output_root) for variant in VARIANTS]
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
