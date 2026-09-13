from __future__ import annotations

import pickletools
from pathlib import Path
from typing import Any

import joblib


class UnsafeModelError(ValueError):
    """Raised when a serialized model contains unsafe pickle references."""


ALLOWED_GLOBAL_PREFIXES = (
    "builtins",
    "collections",
    "copyreg",
    "joblib.",
    "numpy",
    "dtype",
    "pandas.",
    "scipy.",
    "sklearn.",
)


def _is_allowed_global(module: str) -> bool:
    return module == "numpy" or any(module == prefix.rstrip(".") or module.startswith(prefix) for prefix in ALLOWED_GLOBAL_PREFIXES)


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


def load_checked_model(path: str | Path) -> Any:
    assert_pickle_is_safe(path)
    return joblib.load(path)
