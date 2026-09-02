from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.phase3_operations.m7_flow_ingestion.collector import ingest_flow_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Zeek or CICFlowMeter output into Credora flow features.")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--format", choices=["auto", "zeek", "cicflowmeter", "csv"], default="auto")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--default-label", default=None)
    args = parser.parse_args()
    result = ingest_flow_file(args.source, args.output, args.format, args.default_label)
    print(json.dumps({
        "source_format": result.source_format,
        "source_path": str(result.source_path),
        "output_path": str(result.output_path),
        "row_count": result.row_count,
        "columns": result.columns,
    }, indent=2))


if __name__ == "__main__":
    main()
