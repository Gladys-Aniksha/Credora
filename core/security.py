from __future__ import annotations

import re
from pathlib import Path


class SecurityValidationError(ValueError):
    """Raised when user-controlled input would escape a trusted boundary."""


def slugify_filename(value: str | None, fallback: str = "model", max_length: int = 80) -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", value or "")
    slug = slug.strip("._-")
    if not slug:
        slug = fallback
    return slug[:max_length].strip("._-") or fallback


def ensure_within_directory(path: str | Path, root: str | Path) -> Path:
    root_path = Path(root).resolve()
    candidate = Path(path).resolve()
    if candidate != root_path and not candidate.is_relative_to(root_path):
        raise SecurityValidationError(f"Path escapes trusted directory: {candidate}")
    return candidate


def resolve_user_data_path(value: str | Path, root: str | Path, *, allow_absolute: bool = False) -> Path:
    raw_path = Path(value)
    if raw_path.is_absolute() and not allow_absolute:
        raise SecurityValidationError("Absolute paths are not accepted for uploaded metadata references.")
    candidate = raw_path if raw_path.is_absolute() else Path(root) / raw_path
    return ensure_within_directory(candidate, root)


def safe_child_path(root: str | Path, file_name: str) -> Path:
    slug = slugify_filename(file_name)
    return ensure_within_directory(Path(root) / slug, root)
