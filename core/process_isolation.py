from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


class IsolatedProcessError(RuntimeError):
    """Raised when a bounded child-process operation cannot complete safely."""


def run_isolated_python(
    code: str,
    *,
    arguments: list[str] | None = None,
    timeout_seconds: int = 15,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run project Python code in the same bounded subprocess pattern used for model loading."""
    project_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    from core import db
    from core.model_access import access_environment

    env.update(access_environment())
    env["CREDORA_MODEL_ACCESS_DB_PATH"] = str(db.DB_PATH.resolve())
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(project_root)
        if not existing_pythonpath
        else f"{project_root}{os.pathsep}{existing_pythonpath}"
    )
    if environment:
        env.update(environment)

    command = [sys.executable, "-c", code, *(arguments or [])]
    try:
        completed = subprocess.run(
            command,
            cwd=project_root,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise IsolatedProcessError(
            f"Isolated operation timed out after {timeout_seconds} second(s)."
        ) from exc
    except OSError as exc:
        raise IsolatedProcessError(f"Isolated operation could not start: {exc}") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unknown child-process failure").strip()
        raise IsolatedProcessError(f"Isolated operation failed: {detail}")
    return completed
