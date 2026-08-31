from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.phase3_operations.m8_production_monitoring.monitor import monitor_rolling_windows


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze and persist rolling production drift windows.")
    parser.add_argument("--model-name", default="traffic_rf_v1")
    parser.add_argument("--captured-csv", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, default=PROJECT_ROOT / "data" / "processed" / "encrypted_traffic_train.csv")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "data" / "production_windows")
    parser.add_argument("--window-size", type=int, default=250)
    parser.add_argument("--step-size", type=int, default=None)
    args = parser.parse_args()
    results = monitor_rolling_windows(
        model_name=args.model_name,
        captured_csv_path=args.captured_csv,
        baseline_path=args.baseline,
        output_dir=args.output_dir,
        window_size=args.window_size,
        step_size=args.step_size,
    )
    print(json.dumps([
        {"window": index + 1, "status": result.status, "score": result.score, "details": result.details}
        for index, result in enumerate(results)
    ], indent=2))


if __name__ == "__main__":
    main()
