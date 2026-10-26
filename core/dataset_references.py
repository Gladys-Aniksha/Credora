"""Authorize baseline dataset references before assessment preparation.

Pipeline hook (after loading metadata, before prepare_assessment_inputs):
    metadata = validate_training_dataset_references(metadata, owner_id=owner_id)

Only authenticated-owner uploads and operator-configured shared dataset roots are
allowed. Defaults are PROCESSED_DATA_DIR, DATA_DIR/sample_datasets, and the three
shipped fixture-kit directories listed below. Additional directories must be
supplied explicitly by trusted application code
using shared_dataset_roots; never take roots or owner_id from uploaded metadata.
Output paths are project-relative for the existing drift/leakage/privacy readers.
This helper authorizes references without opening or parsing dataset contents.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from core.config import DATA_DIR, PROCESSED_DATA_DIR, PROJECT_ROOT
from core.security import SecurityValidationError

REFERENCE_FIELDS = ("training_dataset_path", "baseline_dataset_path")
APPROVED_SHARED_DATASET_SUBDIRECTORIES = (
    "sample_datasets",
    "sequence_test_kit",
    "doh_onnx_test_kit",
    "trained_sequence_test_kit",
)


def validate_training_dataset_references(
    metadata: Mapping[str, Any],
    *,
    owner_id: int | None,
    shared_dataset_roots: Sequence[str | Path] | None = None,
) -> dict[str, Any]:
    """Return a copy with both aliases validated; reject forbidden paths eagerly.

    owner_id=None authorizes shared datasets only. Missing files within authorized
    directories remain allowed, preserving downstream 'baseline unavailable'
    behavior. Existing paths must be regular files, with CSV for tabular models
    and NPZ for sequence models. Unknown/internal metadata does not grant access.
    """
    if not isinstance(metadata, Mapping):
        raise SecurityValidationError("Metadata must be an object.")
    if owner_id is not None and (type(owner_id) is not int or owner_id <= 0):
        raise SecurityValidationError(
            "Dataset owner must be an authenticated positive integer ID."
        )
    project = PROJECT_ROOT.resolve()
    data = DATA_DIR.resolve()
    uploads = (data / "uploads").resolve()
    private_root = uploads / str(owner_id) if owner_id is not None else None
    # Do not resolve private_root: an owner-directory symlink must not redefine
    # that owner's scope as another owner's directory.
    configured_roots = (
        (
            PROCESSED_DATA_DIR,
            *(DATA_DIR / name for name in APPROVED_SHARED_DATASET_SUBDIRECTORIES),
        )
        if shared_dataset_roots is None
        else shared_dataset_roots
    )
    if isinstance(configured_roots, (str, bytes, Path)):
        raise SecurityValidationError(
            "Shared dataset roots must be a sequence of directories."
        )
    shared_roots = []
    for configured_root in configured_roots:
        root = Path(configured_root)
        root = (root if root.is_absolute() else project / root).resolve()
        if (
            not root.is_relative_to(data)
            or root == data
            or root.is_relative_to(uploads)
            or uploads.is_relative_to(root)
        ):
            raise SecurityValidationError(
                "Shared dataset roots must be explicit non-upload directories under data."
            )
        shared_roots.append(root)
    result = dict(metadata)
    approved: dict[str, Path] = {}
    suffix = (
        ".npz"
        if metadata.get("input_type", "tabular") == "sequence"
        else ".csv"
    )
    for field in REFERENCE_FIELDS:
        value = metadata.get(field)
        if value is None or value == "":
            result.pop(field, None)
            continue
        if (
            not isinstance(value, (str, Path))
            or len(str(value)) > 4096
            or "\x00" in str(value)
        ):
            raise SecurityValidationError(f"Invalid {field} dataset reference.")
        try:
            raw = Path(value)
            # Reject drive-relative paths on Windows (e.g. C:dataset.csv).
            if raw.drive and not raw.is_absolute():
                raise SecurityValidationError(f"Invalid {field} dataset reference.")
            candidate = (raw if raw.is_absolute() else project / raw).resolve()
            owner_allowed = private_root is not None and candidate.is_relative_to(
                private_root
            )
            shared_allowed = any(
                candidate.is_relative_to(root) for root in shared_roots
            )
            if not candidate.is_relative_to(project) or not (
                owner_allowed or shared_allowed
            ):
                raise SecurityValidationError(
                    f"{field} must reference your own uploads or an approved shared dataset."
                )
            if candidate.suffix.lower() != suffix:
                raise SecurityValidationError(
                    f"{field} must reference a {suffix} dataset."
                )
            if candidate.exists() and not candidate.is_file():
                raise SecurityValidationError(
                    f"{field} must reference a regular dataset file."
                )
            approved[field] = candidate
        except (OSError, RuntimeError) as exc:
            raise SecurityValidationError(
                f"Invalid {field} dataset reference."
            ) from exc
    if len(set(approved.values())) > 1:
        raise SecurityValidationError(
            "training_dataset_path and baseline_dataset_path must reference the same dataset."
        )
    for field, path in approved.items():
        result[field] = path.relative_to(project).as_posix()
    # Normalize either authorized baseline alias for downstream readers.
    if approved:
        result["training_dataset_path"] = (
            next(iter(approved.values())).relative_to(project).as_posix()
        )
    return result
