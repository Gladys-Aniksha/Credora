from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.config import METADATA_DIR, PROCESSED_DATA_DIR, SAMPLE_MODEL_DIR, SAMPLE_REQUIREMENTS_DIR


SENSITIVE_HINTS = ("suspicious", "malicious", "attack", "intrusion", "botnet", "dos", "ddos")


def create_shifted_pack(
    dataset_path: Path,
    metadata_path: Path,
    output_dir: Path,
    seed: int = 2026,
) -> dict[str, str]:
    data = pd.read_csv(dataset_path)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    target = metadata.get("target_column", "label")
    features = metadata.get("expected_features") or [column for column in data.columns if column != target]
    numeric = [column for column in features if column in data.columns and pd.api.types.is_numeric_dtype(data[column])]
    labels = data[target].astype(str)
    sensitive_mask = labels.str.lower().apply(lambda value: any(hint in value for hint in SENSITIVE_HINTS))
    benign_mask = ~sensitive_mask
    shifted = data.copy()
    rng = np.random.default_rng(seed)

    for column in numeric:
        benign_median = float(pd.to_numeric(data.loc[benign_mask, column], errors="coerce").median())
        sensitive_values = pd.to_numeric(data.loc[sensitive_mask, column], errors="coerce")
        noise_scale = max(abs(benign_median) * 0.04, 0.0001)
        shifted.loc[sensitive_mask, column] = (
            sensitive_values * 0.18
            + benign_median * 0.82
            + rng.normal(0, noise_scale, int(sensitive_mask.sum()))
        ).clip(lower=0)

    output_dir.mkdir(parents=True, exist_ok=True)
    shifted_path = output_dir / "evasive_traffic_test.csv"
    shifted.to_csv(shifted_path, index=False)

    shifted_metadata = dict(metadata)
    shifted_metadata["model_name"] = f"{metadata.get('model_name', 'model')}_evasion_probe"
    shifted_metadata["version"] = f"{metadata.get('version', 'unknown')}-phase3-evasion"
    shifted_metadata["validation_profile"] = "phase3_sensitive_flow_evasion"
    shifted_metadata["deployment_policy"] = {
        "minimum_trust_score": 85,
        "minimum_classifier_score": 85,
        "minimum_adversarial_score": 80,
        "minimum_sensitive_recall": 0.90,
    }
    shifted_metadata_path = output_dir / "metadata.json"
    shifted_metadata_path.write_text(json.dumps(shifted_metadata, indent=2), encoding="utf-8")

    requirements_source = SAMPLE_REQUIREMENTS_DIR / "requirements_demo.txt"
    requirements_target = output_dir / "requirements.txt"
    shutil.copyfile(requirements_source, requirements_target)

    manifest = {
        "purpose": "Phase 3 release-gate proof using the legitimate trained model with evasive traffic patterns.",
        "model_path": str(SAMPLE_MODEL_DIR / "traffic_rf_v1.joblib"),
        "test_dataset_path": str(shifted_path),
        "metadata_path": str(shifted_metadata_path),
        "requirements_path": str(requirements_target),
        "rows": int(len(shifted)),
        "sensitive_rows_shifted": int(sensitive_mask.sum()),
        "features_shifted": numeric,
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {key: str(value) for key, value in manifest.items() if key.endswith("_path")}


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a real-model Phase 3 evasive traffic validation pack.")
    parser.add_argument("--dataset", type=Path, default=PROCESSED_DATA_DIR / "encrypted_traffic_test.csv")
    parser.add_argument("--metadata", type=Path, default=METADATA_DIR / "traffic_rf_v1_metadata.json")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "data" / "phase3_validation" / "traffic_rf_v1_evasion_probe")
    args = parser.parse_args()
    paths = create_shifted_pack(args.dataset, args.metadata, args.output)
    print("Created Phase 3 evasive validation pack:")
    for label, path in paths.items():
        print(f"  {label}: {path}")


if __name__ == "__main__":
    main()
