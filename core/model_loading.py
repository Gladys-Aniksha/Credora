from __future__ import annotations

import os
import pickletools
import subprocess
import sys
from pathlib import Path
from typing import Any

import joblib


class UnsafeModelError(ValueError):
    """Raised when a serialized model contains unsafe pickle references."""


ALLOWED_GLOBAL_TOP_LEVEL_MODULES = frozenset(
    {
        "builtins",
        "collections",
        "copyreg",
        "joblib",
        "numpy",
        "dtype",
        "pandas",
        "scipy",
        "sklearn",
    }
)

MODEL_LOAD_TIMEOUT_SECONDS = 15
_CHILD_LOAD_ENV = "CREDORA_MODEL_LOAD_CHILD"


def _is_allowed_global(module: str) -> bool:
    top_level_module = module.split(".", 1)[0]
    return top_level_module in ALLOWED_GLOBAL_TOP_LEVEL_MODULES


def scan_pickle_globals(path: str | Path) -> list[str]:
    data = Path(path).read_bytes()
    stack: list[str] = []
    blocked: list[str] = []

    try:
        operations = pickletools.genops(data)
        for opcode, argument, _position in operations:
            name = opcode.name
            if name in {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE"}:
                stack.append(str(argument))
            elif name == "GLOBAL":
                module, global_name = str(argument).split(" ", 1)
                if not _is_allowed_global(module):
                    blocked.append(f"{module}.{global_name}")
                stack.append(f"{module}.{global_name}")
            elif name == "STACK_GLOBAL":
                global_name = stack.pop() if stack else "<unknown>"
                module = stack.pop() if stack else "<unknown>"
                if not _is_allowed_global(module):
                    blocked.append(f"{module}.{global_name}")
                stack.append(f"{module}.{global_name}")
            elif name == "POP" and stack:
                stack.pop()
            elif name == "EMPTY_TUPLE":
                stack.append("()")
    except Exception as exc:  # noqa: BLE001
        raise UnsafeModelError(f"Could not statically inspect the pickle stream: {exc}") from exc

    return blocked


def assert_pickle_is_safe(path: str | Path) -> None:
    blocked = scan_pickle_globals(path)
    if blocked:
        sample = ", ".join(blocked[:5])
        raise UnsafeModelError(f"Serialized model references disallowed callable(s): {sample}")


def _load_after_static_check(path: str | Path) -> Any:
    assert_pickle_is_safe(path)
    return joblib.load(path)


def _run_deserialization_preflight(path: str | Path, timeout_seconds: int = MODEL_LOAD_TIMEOUT_SECONDS) -> None:
    """Load the model once in a child process before this process deserializes it."""
    model_path = Path(path).resolve()
    project_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(project_root) if not existing_pythonpath else f"{project_root}{os.pathsep}{existing_pythonpath}"
    env[_CHILD_LOAD_ENV] = "1"

    command = [
        sys.executable,
        "-c",
        (
            "from pathlib import Path; "
            "from core.model_loading import _load_after_static_check; "
            f"model = _load_after_static_check(Path({str(model_path)!r})); "
            "assert callable(getattr(model, 'predict', None)), 'loaded artifact does not expose predict()'; "
            "print('ok')"
        ),
    ]

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
        raise UnsafeModelError(f"Model deserialization timed out after {timeout_seconds} second(s) in isolated preflight.") from exc
    except OSError as exc:
        raise UnsafeModelError(f"Model deserialization preflight could not start: {exc}") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unknown child-process failure").strip()
        raise UnsafeModelError(f"Model deserialization failed in isolated preflight: {detail}")


def load_checked_model(path: str | Path) -> Any:
    assert_pickle_is_safe(path)
    if os.environ.get(_CHILD_LOAD_ENV) != "1":
        _run_deserialization_preflight(path)
    return joblib.load(path)
