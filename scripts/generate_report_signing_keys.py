from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.report_signing import generate_report_signing_keypair


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate an Ed25519 keypair for Credora final report signing.")
    parser.add_argument("--private-key", type=Path, required=True, help="Path for the private signing key PEM.")
    parser.add_argument("--public-key", type=Path, required=True, help="Path for the public verification key PEM.")
    args = parser.parse_args()

    generate_report_signing_keypair(args.private_key, args.public_key)
    print(f"Created report signing private key: {args.private_key}")
    print(f"Created report verification public key: {args.public_key}")


