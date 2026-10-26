from __future__ import annotations

import os
import pickletools
from io import BytesIO
from pathlib import Path
from typing import Any

import joblib

from core.model_storage import read_model_bytes
from core.process_isolation import IsolatedProcessError, run_isolated_python


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


def _scan_pickle_bytes(data: bytes) -> list[str]:
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
    except Exception as exc:
        raise UnsafeModelError(f"Could not statically inspect the pickle stream: {exc}") from exc

    return blocked


def scan_pickle_globals(path: str | Path) -> list[str]:
    return _scan_pickle_bytes(read_model_bytes(path))


def _assert_pickle_bytes_safe(data: bytes) -> None:
    blocked = _scan_pickle_bytes(data)
    if blocked:
        sample = ", ".join(blocked[:5])
        raise UnsafeModelError(f"Serialized model references disallowed callable(s): {sample}")


def assert_pickle_is_safe(path: str | Path) -> None:
    blocked = scan_pickle_globals(path)
    if blocked:
        sample = ", ".join(blocked[:5])
        raise UnsafeModelError(f"Serialized model references disallowed callable(s): {sample}")


class _ModelStream(BytesIO):
    """Memory-only model bytes with the original filename for loader diagnostics."""

    def __init__(self, data: bytes, path: str | Path):
        super().__init__(data)
        self.name = str(path)

    def __str__(self) -> str:
        return self.name


def _load_after_static_check(path: str | Path) -> Any:
    data = read_model_bytes(path)
    _assert_pickle_bytes_safe(data)
    with _ModelStream(data, path) as stream:
        return joblib.load(stream)


def _run_deserialization_preflight(path: str | Path, timeout_seconds: int = MODEL_LOAD_TIMEOUT_SECONDS) -> None:
    """Load the model once in a child process before this process deserializes it."""
    model_path = Path(path).resolve()
    code = (
            "from pathlib import Path; "
            "from core.model_loading import _load_after_static_check; "
            f"model = _load_after_static_check(Path({str(model_path)!r})); "
            "assert callable(getattr(model, 'predict', None)), 'loaded artifact does not expose predict()'; "
            "print('ok')"
    )
    try:
        run_isolated_python(
            code,
            timeout_seconds=timeout_seconds,
            environment={_CHILD_LOAD_ENV: "1"},
        )
    except IsolatedProcessError as exc:
        raise UnsafeModelError(f"Model deserialization failed in isolated preflight: {exc}") from exc


def load_checked_model(path: str | Path) -> Any:
    assert_pickle_is_safe(path)
    if os.environ.get(_CHILD_LOAD_ENV) != "1":
        _run_deserialization_preflight(path)
    return _load_after_static_check(path)
