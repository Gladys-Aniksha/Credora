"""Standalone restricted native import: weights metadata outputdir.

Operator setup: build docker/native-import.Dockerfile separately, obtain a trusted
repository digest, and set NATIVE_IMPORT_IMAGE. This CLI never builds/pulls images.
See core/native_import.py and core/native_worker.py for exact supported schemas.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.native_import import NativeImportError, import_native_model


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert approved weights to ONNX in locked-down Docker."
    )
    parser.add_argument("weights", type=Path)
    parser.add_argument("metadata", type=Path)
    parser.add_argument(
        "outputdir", type=Path, help="New directory for model.onnx and metadata.json"
    )
    args = parser.parse_args()
    try:
        result = import_native_model(args.weights, args.metadata, args.outputdir)
    except (NativeImportError, OSError, ValueError) as exc:
        parser.exit(2, f"Native import failed: {exc}\n")
    print(
        json.dumps(
            {
                "artifact_path": str(result.artifact_path),
                "metadata_path": str(result.metadata_path),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
