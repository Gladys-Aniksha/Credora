from __future__ import annotations

import argparse
import os
import sys
from contextlib import closing
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import db
from core.config import DATA_DIR
from core.model_access import model_access_context
from core.model_storage import migrate_registered_model, require_model_encryption_key


def registered_uploads() -> list[tuple[Path, int | None]]:
    root = (DATA_DIR / "uploads").resolve()
    found = set()
    with closing(db.connect()) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        for table, column in (("model_artifact_registry", "artifact_path"), ("model_registry", "model_path")):
            if table in tables:
                for row in conn.execute(f"SELECT {column}, owner_id FROM {table}"):
                    if row[0] and Path(row[0]).resolve().is_relative_to(root):
                        found.add((os.path.normcase(os.path.abspath(row[0])), row[1]))
    return [(Path(path), owner) for path, owner in sorted(found, key=lambda item: (item[0], str(item[1])))]


def unregistered_uploads(candidates: list[tuple[Path, int | None]]) -> list[Path]:
    known = {os.path.normcase(os.path.abspath(path)) for path, _owner in candidates}
    with closing(db.connect()) as conn:
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='encrypted_model_files'").fetchone():
            known.update(row[0] for row in conn.execute("SELECT artifact_path FROM encrypted_model_files"))
    return sorted(
        path for path in (DATA_DIR / "uploads").rglob("*")
        if path.is_file() and path.suffix.lower() in {".onnx", ".pkl", ".joblib", ".credora"}
        and os.path.normcase(os.path.abspath(path)) not in known
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Encrypt registered stored models after verifying their original hashes.")
    parser.add_argument("--apply", action="store_true", help="Perform migration; otherwise list candidates without changing model files.")
    args = parser.parse_args()
    require_model_encryption_key()
    candidates = registered_uploads()
    unknown = unregistered_uploads(candidates)
    for path in unknown:
        print(f"UNREGISTERED: {path.name}; no original baseline exists. Re-upload and reassess or securely remove the legacy copy.", file=sys.stderr)
    failures = len(unknown)
    for path, owner in candidates:
        if not args.apply:
            print(f"Candidate: owner={owner}, {path.name}")
            continue
        try:
            with model_access_context(None, "model.encryption_migration", owner_id=owner):
                migrate_registered_model(path, owner)
            print(f"Encrypted and verified: owner={owner}, {path.name}")
        except (OSError, ValueError) as exc:
            failures += 1
            print(f"BLOCKED: owner={owner}, {path.name}: {exc}", file=sys.stderr)
    print(f"{len(candidates)} candidate(s), {failures} failure(s)." + (" No model files changed (dry run)." if not args.apply else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
