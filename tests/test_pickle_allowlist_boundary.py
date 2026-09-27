from __future__ import annotations

import pytest

from core.model_loading import _is_allowed_global


@pytest.mark.parametrize(
    "module",
    [
        "builtins",
        "collections.abc",
        "joblib.numpy_pickle",
        "numpy.core.multiarray",
        "pandas.core.frame",
        "scipy.sparse",
        "sklearn.ensemble._forest",
    ],
)
def test_pickle_allowlist_accepts_exact_top_level_modules(module: str) -> None:
    assert _is_allowed_global(module)


@pytest.mark.parametrize(
    "module",
    [
        "numpyevil",
        "numpy_evil",
        "collectionsabc_exploit",
        "builtinshack",
        "dtypehack",
        "joblibevil",
        "pandas_fake",
        "scipymalware",
        "sklearn_backdoor",
    ],
)
def test_pickle_allowlist_rejects_prefix_near_misses(module: str) -> None:
    assert not _is_allowed_global(module)
