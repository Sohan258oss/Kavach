"""
feature_extractor.py — Converts filesystem event windows into ML features.

Used by the real-time prediction loop in main.py.
SUSPICIOUS_EXTENSIONS and FEATURES imported from config.py (single source).
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Any, Union

from config import SUSPICIOUS_EXTENSIONS, FEATURES
from logging_utils import get_logger

logger = get_logger('feature_extractor')

FeatureDict = Dict[str, Union[int, float]]


def extract_features(event_log: List[Dict[str, Any]]) -> FeatureDict:
    """
    Convert a time-window of events into ML features.

    Args:
        event_log: list of dicts with keys
            type, entropy, extension, process_cpu, open_files.

    Returns:
        Dict whose keys match ``config.FEATURES``.
    """
    if not event_log:
        return _empty_features()

    df: pd.DataFrame = pd.DataFrame(event_log)
    total: int = max(len(df), 1)

    # ── Counts ──
    rename_count: int = (
        int((df['type'] == 'renamed').sum()) if 'type' in df.columns else 0
    )
    delete_count: int = (
        int((df['type'] == 'deleted').sum()) if 'type' in df.columns else 0
    )
    create_count: int = (
        int((df['type'] == 'created').sum()) if 'type' in df.columns else 0
    )

    # ── Entropy ──
    if 'entropy' in df.columns and df['entropy'].notna().any():
        avg_entropy: float = float(df['entropy'].mean())
        max_entropy: float = float(df['entropy'].max())
        high_entropy_ratio: float = float((df['entropy'] > 7.0).mean())
    else:
        avg_entropy = max_entropy = high_entropy_ratio = 0.0

    # ── Process stats ──
    avg_cpu: float = (
        float(df['process_cpu'].mean())
        if 'process_cpu' in df.columns and df['process_cpu'].notna().any()
        else 0.0
    )
    avg_open_files: float = (
        float(df['open_files'].mean())
        if 'open_files' in df.columns and df['open_files'].notna().any()
        else 0.0
    )

    # ── Extension analysis ──
    if 'extension' in df.columns:
        suspicious_ext_count: int = int(
            df['extension'].str.lower().isin(SUSPICIOUS_EXTENSIONS).sum()
        )
        unique_extensions: int = int(df['extension'].nunique())
    else:
        suspicious_ext_count = unique_extensions = 0

    # ── Ratios ──
    rename_ratio: float = round(rename_count / total, 4)
    delete_ratio: float = round(delete_count / total, 4)

    return {
        'file_events_per_sec':  total,
        'rename_count':         rename_count,
        'delete_count':         delete_count,
        'create_count':         create_count,
        'avg_entropy':          round(avg_entropy, 4),
        'max_entropy':          round(max_entropy, 4),
        'high_entropy_ratio':   round(high_entropy_ratio, 4),
        'avg_cpu':              round(avg_cpu, 4),
        'avg_open_files':       round(avg_open_files, 4),
        'suspicious_ext_count': suspicious_ext_count,
        'unique_extensions':    unique_extensions,
        'rename_ratio':         rename_ratio,
        'delete_ratio':         delete_ratio,
    }


def _empty_features() -> FeatureDict:
    """Return zeroed features when no events are in the window."""
    return {
        'file_events_per_sec':  0,
        'rename_count':         0,
        'delete_count':         0,
        'create_count':         0,
        'avg_entropy':          0.0,
        'max_entropy':          0.0,
        'high_entropy_ratio':   0.0,
        'avg_cpu':              0.0,
        'avg_open_files':       0.0,
        'suspicious_ext_count': 0,
        'unique_extensions':    0,
        'rename_ratio':         0.0,
        'delete_ratio':         0.0,
    }


def validate_features(features: FeatureDict) -> bool:
    """
    Sanity-check features before passing to the predictor.

    Returns True if features look valid, False otherwise.
    """
    missing = [k for k in FEATURES if k not in features]
    if missing:
        logger.error("Missing feature keys: %s", missing)
        return False

    avg_ent = features.get('avg_entropy', 0.0)
    if not isinstance(avg_ent, (int, float)) or avg_ent > 8.0 or avg_ent < 0:
        logger.error("Invalid entropy value: %s", avg_ent)
        return False

    logger.info(
        "Features valid — %d events in window",
        features.get('file_events_per_sec', 0),
    )
    return True