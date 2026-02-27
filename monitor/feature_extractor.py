import pandas as pd
import numpy as np

# Suspicious extensions ransomware commonly uses
SUSPICIOUS_EXTENSIONS = [
    '.locked', '.enc', '.crypt', '.zzz', '.aaa', '.abc', '.xyz',
    '.encrypted', '.crypted', '.crypz', '.crypto', '.darkness',
    '.ransomed', '.fucked', '.pays', '.wnry', '.wncry'
]

def extract_features(event_log: list) -> dict:
    """
    Convert a time-window of events into ML features.
    
    event_log: list of dicts with keys:
        - type:        'created' | 'renamed' | 'deleted' | 'modified'
        - entropy:     float 0.0 - 8.0 (Shannon entropy of file)
        - extension:   str e.g. '.txt', '.locked'
        - process_cpu: float (CPU % of process that triggered event)
        - open_files:  int (number of open file handles)
    
    Returns dict with keys matching FEATURES in train_model.py and predictor.py
    """
    if not event_log:
        return _empty_features()

    df = pd.DataFrame(event_log)

    # ── Counts ──
    total = max(len(df), 1)  # avoid division by zero
    
    rename_count = int(len(df[df['type'] == 'renamed']))   if 'type' in df.columns else 0
    delete_count = int(len(df[df['type'] == 'deleted']))   if 'type' in df.columns else 0
    create_count = int(len(df[df['type'] == 'created']))   if 'type' in df.columns else 0

    # ── Entropy ──
    if 'entropy' in df.columns and df['entropy'].notna().any():
        avg_entropy       = float(df['entropy'].mean())
        max_entropy       = float(df['entropy'].max())
        high_entropy_ratio = float((df['entropy'] > 7.0).mean())
    else:
        avg_entropy        = 0.0
        max_entropy        = 0.0
        high_entropy_ratio = 0.0

    # ── Process stats ──
    avg_cpu        = float(df['process_cpu'].mean()) if 'process_cpu' in df.columns and df['process_cpu'].notna().any() else 0.0
    avg_open_files = float(df['open_files'].mean())  if 'open_files'  in df.columns and df['open_files'].notna().any()  else 0.0

    # ── Extension analysis ──
    if 'extension' in df.columns:
        suspicious_ext_count = int(df['extension'].str.lower().isin(SUSPICIOUS_EXTENSIONS).sum())
        unique_extensions    = int(df['extension'].nunique())
    else:
        suspicious_ext_count = 0
        unique_extensions    = 0

    # ── Ratios ──
    rename_ratio = round(rename_count / total, 4)
    delete_ratio = round(delete_count / total, 4)

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
        'delete_ratio':         delete_ratio
    }

def _empty_features() -> dict:
    """Return zeroed features when no events in window."""
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
        'delete_ratio':         0.0
    }

def validate_features(features: dict) -> bool:
    """
    Quick sanity check — call this before passing to predictor.
    Returns True if features look valid, False if something is wrong.
    """
    EXPECTED_KEYS = [
        'file_events_per_sec', 'rename_count', 'delete_count', 'create_count',
        'avg_entropy', 'max_entropy', 'high_entropy_ratio', 'avg_cpu',
        'avg_open_files', 'suspicious_ext_count', 'unique_extensions',
        'rename_ratio', 'delete_ratio'
    ]
    
    missing = [k for k in EXPECTED_KEYS if k not in features]
    if missing:
        print(f"[Feature Extractor] ❌ Missing keys: {missing}")
        return False
    
    if features['avg_entropy'] > 8.0 or features['avg_entropy'] < 0:
        print(f"[Feature Extractor] ❌ Invalid entropy value: {features['avg_entropy']}")
        return False
    
    print(f"[Feature Extractor] ✅ Features valid — {features['file_events_per_sec']} events in window")
    return True