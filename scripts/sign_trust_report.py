from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.report_signing import sign_report_file


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Attach an Ed25519 signature to a Credora trust report JSON file.")
    parser.add_argument("--report", type=Path, required=True, help="Trust report JSON to sign.")
    parser.add_argument("--private-key", type=Path, required=True, help="Ed25519 private key PEM.")
    parser.add_argument("--signer", default="local-report-signer", help="Human-readable signer name to store in the report.")
    parser.add_argument("--output", type=Path, help="Optional output path. Defaults to updating the report in place.")
    args = parser.parse_args()

    target = sign_report_file(args.report, args.private_key, signer=args.signer, output_path=args.output)
    print(f"Signed trust report: {target}")


