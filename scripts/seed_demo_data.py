from __future__ import annotations

import json
from pathlib import Path
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.config import METADATA_DIR, PROCESSED_DATA_DIR, SAMPLE_MODEL_DIR, SAMPLE_REQUIREMENTS_DIR
from core.hashing import sha256_file

FEATURES = [
    "flow_duration",
    "packet_count",
    "avg_packet_size",
    "bytes_sent",
    "bytes_received",
    "iat_mean",
    "iat_std",
    "flow_bytes_per_second",
]
CLASSES = ["Normal", "VPN", "Suspicious"]


def make_dataset(rows: int = 900, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    parts = []
    profiles = {
        "Normal": (45_000, 55, 620, 24_000, 38_000, 0.030, 0.018, 900),
        "VPN": (95_000, 120, 840, 58_000, 91_000, 0.045, 0.026, 1500),
        "Suspicious": (18_000, 190, 390, 140_000, 36_000, 0.009, 0.055, 6600),
    }
    for label, means in profiles.items():
        n = rows // len(profiles)
        frame = pd.DataFrame({
            "flow_duration": rng.normal(means[0], means[0] * 0.18, n).clip(500),
            "packet_count": rng.normal(means[1], max(means[1] * 0.16, 2), n).clip(2).round(),
            "avg_packet_size": rng.normal(means[2], means[2] * 0.12, n).clip(40),
            "bytes_sent": rng.normal(means[3], means[3] * 0.20, n).clip(100),
            "bytes_received": rng.normal(means[4], means[4] * 0.20, n).clip(100),
            "iat_mean": rng.normal(means[5], max(means[5] * 0.25, 0.001), n).clip(0.001),
            "iat_std": rng.normal(means[6], max(means[6] * 0.30, 0.001), n).clip(0.001),
            "flow_bytes_per_second": rng.normal(means[7], means[7] * 0.22, n).clip(10),
            "label": label,
        })
        parts.append(frame)
    return pd.concat(parts, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)


def main() -> None:
    data = make_dataset()
    train_df, test_df = train_test_split(data, test_size=0.25, stratify=data["label"], random_state=7)
    model = RandomForestClassifier(n_estimators=140, max_depth=10, random_state=7, class_weight="balanced")
    model.fit(train_df[FEATURES], train_df["label"])
    predictions = model.predict(test_df[FEATURES])
    f1 = f1_score(test_df["label"], predictions, average="weighted")

    train_path = PROCESSED_DATA_DIR / "encrypted_traffic_train.csv"
    test_path = PROCESSED_DATA_DIR / "encrypted_traffic_test.csv"
    model_path = SAMPLE_MODEL_DIR / "traffic_rf_v1.joblib"
    requirements_path = SAMPLE_REQUIREMENTS_DIR / "requirements_demo.txt"
    metadata_path = METADATA_DIR / "traffic_rf_v1_metadata.json"

    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)
    joblib.dump(model, model_path)
    requirements_path.write_text("scikit-learn\npandas\nnumpy\njoblib\n", encoding="utf-8")

    metadata = {
        "model_name": "traffic_rf_v1",
        "version": "1.0",
        "algorithm": "Random Forest",
        "framework": "scikit-learn",
        "task": "Encrypted Traffic Classification",
        "target_column": "label",
        "training_dataset_path": str(train_path),
        "expected_features": FEATURES,
        "class_labels": CLASSES,
        "signature_status": "valid",
        "sha256": sha256_file(model_path),
        "demo_f1_score": round(float(f1), 4),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Created demo model: {model_path}")
    print(f"Created test dataset: {test_path}")
    print(f"Created metadata: {metadata_path}")
    print(f"Demo weighted F1: {f1:.3f}")


if __name__ == "__main__":
    main()




