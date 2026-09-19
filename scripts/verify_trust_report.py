from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.report_signing import verify_report_file


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify a Credora trust report signature using an Ed25519 public key.")
    parser.add_argument("--report", type=Path, required=True, help="Signed trust report JSON.")
    parser.add_argument("--public-key", type=Path, required=True, help="Trusted Ed25519 public key PEM.")
    args = parser.parse_args()

    result = verify_report_file(args.report, args.public_key)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result.get("verified") else 2)


