"""Exact TreeSHAP explanations for the LightGBM detector, grouped into feature families.

LightGBM computes SHAP values natively (``pred_contrib=True``): one contribution per feature
in raw-margin (log-odds) units plus a bias term, summing exactly to the model's raw score.
Contributions are aggregated into thrember's feature families so a person can read *why*
a file scored as it did, e.g. "Imported libraries & functions pushed the score toward
malicious". These are model attributions, not proof of behaviour.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, List, Tuple

import numpy as np

GROUP_LABELS = {
    "general": "General file properties (size, entropy, start bytes)",
    "histogram": "Byte value distribution",
    "byteentropy": "Byte entropy distribution (packing / encryption)",
    "strings": "Printable strings (URLs, paths, registry keys, keywords)",
    "header": "PE header fields",
    "section": "Sections (names, sizes, entropy, permissions)",
    "imports": "Imported libraries and functions",
    "exports": "Exported functions",
    "datadirectories": "Data directories",
    "richheader": "Rich header (build toolchain)",
    "authenticode": "Authenticode signature properties",
    "pefilewarnings": "PE parser warnings (malformed structures)",
}


@lru_cache(maxsize=1)
def feature_blocks() -> Tuple[Tuple[str, int, int], ...]:
    """(group name, start, end) for every thrember feature family, in vector order."""
    from threatweaver.scanner.ember_v3 import get_extractor

    blocks, off = [], 0
    for f in get_extractor()._ext.features:
        blocks.append((f.name, off, off + f.dim))
        off += f.dim
    return tuple(blocks)


def group_of(index: int) -> Tuple[str, int]:
    for name, start, end in feature_blocks():
        if start <= index < end:
            return name, index - start
    raise IndexError(index)


def explain(booster, vector: np.ndarray, top_groups: int = 6, top_features: int = 3) -> Dict[str, Any]:
    """Grouped SHAP explanation for one feature vector (raw-margin units)."""
    contrib = np.asarray(booster.predict(np.atleast_2d(np.asarray(vector, dtype=np.float32)), pred_contrib=True))[0]
    values, bias = contrib[:-1], float(contrib[-1])
    groups: List[Dict[str, Any]] = []
    for name, start, end in feature_blocks():
        block = values[start:end]
        total = float(block.sum())
        order = np.argsort(-np.abs(block))[:top_features]
        groups.append({
            "group": name,
            "label": GROUP_LABELS.get(name, name),
            "contribution": total,
            "direction": "toward malicious" if total > 0 else "toward benign",
            "top_features": [{"index": int(start + i), "local_index": int(i), "contribution": float(block[i])}
                             for i in order if block[i] != 0],
        })
    groups.sort(key=lambda g: abs(g["contribution"]), reverse=True)
    return {
        "units": "log-odds (raw LightGBM margin, before calibration)",
        "bias": bias,
        "raw_score": float(values.sum() + bias),
        "groups": groups[:top_groups],
        "all_groups_total": float(values.sum()),
    }


def summarize(expl: Dict[str, Any], n: int = 3) -> List[str]:
    """Plain-language lines for the strongest contributing groups."""
    lines = []
    for g in expl["groups"][:n]:
        if abs(g["contribution"]) < 0.05:
            continue
        lines.append(f"{g['label']} pushed the score {g['direction']} ({g['contribution']:+.2f} log-odds).")
    return lines
