from __future__ import annotations

import numpy as np
import pandas as pd


def sequence_aggregates(features: np.ndarray, pad_id: int = 0, histogram_bins: int = 16) -> pd.DataFrame:
    """Create stable scalar distributions that can be compared with PSI."""
    values = np.asarray(features)
    if values.ndim != 2:
        raise ValueError("Sequence features must be a two-dimensional array.")
    rows: list[dict[str, float]] = []
    for row in values:
        numeric = row.astype(float)
        non_pad = numeric[numeric != float(pad_id)]
        counts = np.histogram(numeric, bins=histogram_bins, range=(0, max(float(np.max(numeric)), 1.0)))[0]
        counts = counts / max(float(counts.sum()), 1.0)
        probabilities = counts[counts > 0]
        entropy = float(-(probabilities * np.log2(probabilities)).sum()) if len(probabilities) else 0.0
        item = {
            "non_pad_length": float(len(non_pad)),
            "entropy": entropy,
            "pad_fraction": float(np.mean(numeric == float(pad_id))),
        }
        item.update({f"token_histogram_{index}": float(value) for index, value in enumerate(counts)})
        rows.append(item)
    return pd.DataFrame(rows)
