from __future__ import annotations

import argparse
import json
import random
import time
from datetime import datetime
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

from core.model_loading import load_checked_model


PROFILE_RANGES = {
    "Normal": {
        "flow_duration": (24210, 62350),
        "packet_count": (37, 78),
        "avg_packet_size": (434, 857),
        "bytes_sent": (6488, 35796),
        "bytes_received": (16887, 58602),
        "iat_mean": (0.012, 0.045),
        "iat_std": (0.007, 0.030),
        "flow_bytes_per_second": (429, 1457),
    },
    "VPN": {
        "flow_duration": (54435, 133869),
        "packet_count": (65, 164),
        "avg_packet_size": (563, 1110),
        "bytes_sent": (33205, 80515),
        "bytes_received": (55827, 141955),
        "iat_mean": (0.015, 0.073),
        "iat_std": (0.008, 0.046),
        "flow_bytes_per_second": (611, 2154),
    },
    "Suspicious": {
        "flow_duration": (11115, 24406),
        "packet_count": (144, 281),
        "avg_packet_size": (260, 494),
        "bytes_sent": (88490, 229829),
        "bytes_received": (14502, 54518),
        "iat_mean": (0.005, 0.016),
        "iat_std": (0.011, 0.090),
        "flow_bytes_per_second": (4269, 8698),
    },
}


def load_metadata(metadata_path: Path) -> dict:
    return json.loads(metadata_path.read_text(encoding="utf-8"))


def sample_live_flow(label: str, feature_columns: list[str]) -> dict:
    profile = PROFILE_RANGES[label]
    flow = {}
    for feature in feature_columns:
        low, high = profile[feature]
        value = random.uniform(low, high)
        flow[feature] = int(value) if feature in {"packet_count", "bytes_sent", "bytes_received"} else round(value, 3)
    return flow


def main() -> None:
    parser = argparse.ArgumentParser(description="Run live-style encrypted flow predictions with the trained classifier.")
    parser.add_argument("--model", type=Path, default=PROJECT_ROOT / "data" / "sample_models" / "traffic_rf_v1.joblib")
    parser.add_argument("--metadata", type=Path, default=PROJECT_ROOT / "data" / "metadata" / "traffic_rf_v1_metadata.json")
    parser.add_argument("--events", type=int, default=20, help="Number of live flow events to send through the model.")
    parser.add_argument("--delay", type=float, default=0.7, help="Seconds to wait between flow events.")
    args = parser.parse_args()

    metadata = load_metadata(args.metadata)
    feature_columns = metadata["expected_features"]
    class_labels = metadata.get("class_labels", list(PROFILE_RANGES))
    model = load_checked_model(args.model)

    print("Realtime Encrypted Traffic Classifier Probe")
    print("=" * 43)
    print(f"Model: {args.model}")
    print(f"Features: {', '.join(feature_columns)}")
    print(f"Events: {args.events}")
    print()

    correct = 0
    for index in range(1, args.events + 1):
        expected = random.choice(class_labels)
        flow = sample_live_flow(expected, feature_columns)
        prediction = str(model.predict(pd.DataFrame([flow]))[0])
        correct += int(prediction == expected)

        timestamp = datetime.now().strftime("%H:%M:%S")
        status = "OK" if prediction == expected else "CHECK"
        print(
            f"[{timestamp}] event={index:03d} expected={expected:<10} "
            f"predicted={prediction:<10} status={status} "
            f"packets={flow['packet_count']} bytes/s={flow['flow_bytes_per_second']}"
        )
        time.sleep(args.delay)

    accuracy = correct / args.events if args.events else 0
    print()
    print(f"Live probe accuracy: {accuracy:.3f} ({correct}/{args.events})")


if __name__ == "__main__":
    main()
