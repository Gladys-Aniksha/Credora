from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    file_path = Path(path)
    if file_path.suffix.lower() in {".onnx", ".joblib", ".pkl", ".credora"}:
        from core.model_storage import read_model_bytes

        return hashlib.sha256(read_model_bytes(file_path)).hexdigest()
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
