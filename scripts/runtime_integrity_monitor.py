from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.phase3_operations.m6_runtime_integrity.scheduler import monitor_runtime_integrity


def main() -> None:
    parser = argparse.ArgumentParser(description="Continuously verify a deployed model against its approved hash.")
    parser.add_argument("--model", type=Path, default=PROJECT_ROOT / "data" / "sample_models" / "traffic_rf_v1.joblib")
    parser.add_argument("--metadata", type=Path, default=PROJECT_ROOT / "data" / "metadata" / "traffic_rf_v1_metadata.json")
    parser.add_argument("--interval", type=float, default=300.0, help="Seconds between checks.")
    parser.add_argument("--checks", type=int, default=None, help="Optional finite number of checks.")
    args = parser.parse_args()

    def show(result) -> None:
        details = result.details
        print(
            f"[{details.get('checked_at')}] state={details.get('integrity_state')} "
            f"status={result.status} score={result.score:.1f} hash={details.get('actual_sha256')}"
        )

    try:
        monitor_runtime_integrity(args.model, args.metadata, args.interval, args.checks, on_check=show)
    except KeyboardInterrupt:
        print("Integrity monitor stopped.")


if __name__ == "__main__":
    main()
