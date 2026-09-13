from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.run_phase1_scan import run_phase1_scan


def deployment_decision(report: dict) -> str:
    for result in report.get("module_results", []):
        if result.get("module") == "deployment_gate":
            return str(result.get("details", {}).get("decision", "blocked"))
    return "blocked"


def run_gate(
    model: Path,
    dataset: Path,
    requirements: Path,
    metadata: Path,
    minimum_score: float,
    require_approved: bool,
    trust_key: Path | None = None,
) -> tuple[dict, bool]:
    report = run_phase1_scan(
        model,
        dataset,
        requirements,
        metadata,
        trusted_public_key_path=trust_key,
        generate_docx=False,
    ).to_dict()
    decision = deployment_decision(report)
    allowed_decisions = {"approved"} if require_approved else {"approved", "conditional"}
    passed = float(report.get("trust_score", 0)) >= minimum_score and decision in allowed_decisions
    return {
        "passed": passed,
        "model_name": report.get("model_name"),
        "trust_score": report.get("trust_score"),
        "minimum_score": minimum_score,
        "deployment_decision": decision,
        "require_approved": require_approved,
    }, passed


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the complete Phase 3 CI/deployment release gate.")
    parser.add_argument("--model", type=Path, default=PROJECT_ROOT / "data" / "sample_models" / "traffic_rf_v1.joblib")
    parser.add_argument("--dataset", type=Path, default=PROJECT_ROOT / "data" / "processed" / "encrypted_traffic_test.csv")
    parser.add_argument("--requirements", type=Path, default=PROJECT_ROOT / "data" / "sample_requirements" / "requirements_demo.txt")
    parser.add_argument("--metadata", type=Path, default=PROJECT_ROOT / "data" / "metadata" / "traffic_rf_v1_metadata.json")
    parser.add_argument("--package", type=Path)
    parser.add_argument("--trust-key", type=Path)
    parser.add_argument("--minimum-score", type=float, default=85.0)
    parser.add_argument("--require-approved", action="store_true")
    args = parser.parse_args()

    if bool(args.package) != bool(args.trust_key):
        parser.error("--package and --trust-key must be supplied together")
    with TemporaryDirectory(prefix="credora-release-"):
        if args.package:
            model = args.package
            metadata = args.metadata
            requirements = args.requirements
            trust_key = args.trust_key
        else:
            model = args.model
            metadata = args.metadata
            requirements = args.requirements
            trust_key = None
        summary, passed = run_gate(
            model,
            args.dataset,
            requirements,
            metadata,
            args.minimum_score,
            args.require_approved,
            trust_key,
        )
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if passed else 2)


if __name__ == "__main__":
    main()
