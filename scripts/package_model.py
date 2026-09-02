from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.model_package import (
    create_signed_model_package,
    generate_signing_keypair,
    inspect_model_package,
    verify_model_package,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create and verify signed Credora model packages.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="Generate an Ed25519 signing keypair.")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)

    create = subparsers.add_parser("create", help="Create a signed .credora model package.")
    create.add_argument("--model", type=Path, required=True)
    create.add_argument("--metadata", type=Path, required=True)
    create.add_argument("--requirements", type=Path, required=True)
    create.add_argument("--private-key", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser("verify", help="Verify a package with an external trusted public key.")
    verify.add_argument("--package", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--extract-dir", type=Path)

    args = parser.parse_args()
    if args.command == "keygen":
        generate_signing_keypair(args.private_key, args.public_key)
        print(json.dumps({"private_key": str(args.private_key), "public_key": str(args.public_key)}, indent=2))
    elif args.command == "create":
        output = create_signed_model_package(args.model, args.metadata, args.requirements, args.output, args.private_key)
        print(json.dumps({"package": str(output)}, indent=2))
    elif args.extract_dir:
        verified = verify_model_package(args.package, args.public_key, args.extract_dir)
        print(json.dumps({
            "verified": True,
            "model": str(verified.model_path),
            "metadata": str(verified.metadata_path),
            "requirements": str(verified.requirements_path),
        }, indent=2))
    else:
        print(json.dumps(inspect_model_package(args.package, args.public_key), indent=2))


if __name__ == "__main__":
    main()
