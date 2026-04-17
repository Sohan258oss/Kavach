"""
config.py — Centralized configuration for Project Kavach (Sentinel).

All constants, thresholds, paths, feature columns, and input validation
live here. No other module should hard-code these values.
"""

import os
import sys
import pathlib
import secrets
from typing import List, FrozenSet

# ── Project Root ──────────────────────────────────────────────────────────────
PROJECT_ROOT: str = os.path.dirname(os.path.abspath(__file__))

# ── Suspicious File Extensions (union of all prior lists) ─────────────────────
SUSPICIOUS_EXTENSIONS: FrozenSet[str] = frozenset([
    '.locked', '.enc', '.crypt', '.crypto', '.encrypted',
    '.zzzzz', '.zzz', '.aaa', '.abc', '.xyz', '.wncry',
    '.wnry', '.darkness', '.ransomed', '.crypted', '.crypz',
    '.fucked', '.pays',
])

# Extensions to SKIP for entropy analysis (naturally high-entropy formats)
ENTROPY_SKIP_EXTENSIONS: FrozenSet[str] = frozenset([
    '.exe', '.dll', '.zip', '.png', '.jpg', '.mp3', '.mp4', '.pdf',
    '.gz', '.bz2', '.7z', '.rar', '.iso', '.bin',
])

# ── Suspicious Process Names ─────────────────────────────────────────────────
SUSPICIOUS_PROCESSES: FrozenSet[str] = frozenset([
    'vssadmin', 'bcdedit', 'wbadmin', 'cipher',
    'schtasks', 'wscript', 'cscript',
])

SUSPICIOUS_PROCESS_EXES: FrozenSet[str] = frozenset([
    'vssadmin.exe', 'bcdedit.exe', 'powershell.exe',
    'cipher.exe', 'wbadmin.exe', 'schtasks.exe',
])

# ── ML Feature Columns (single source of truth) ─────────────────────────────
FEATURES: List[str] = [
    'file_events_per_sec', 'rename_count', 'delete_count', 'create_count',
    'avg_entropy', 'max_entropy', 'high_entropy_ratio',
    'avg_cpu', 'avg_open_files',
    'suspicious_ext_count', 'unique_extensions',
    'rename_ratio', 'delete_ratio',
]

# ── Thresholds ────────────────────────────────────────────────────────────────
ENTROPY_THRESHOLD: float = 7.2
CONFIDENCE_THRESHOLD: float = 55.0
HIGH_CONFIDENCE_THRESHOLD: float = 90.0
SNAPSHOT_CONFIDENCE_THRESHOLD: float = 70.0
HIGH_ENTROPY_FILE_SIZE_LIMIT: int = 50 * 1024 * 1024   # 50 MB
ENTROPY_SAMPLE_CHUNK_SIZE: int = 4096                   # 4 KB per chunk

# File monitor
WINDOW_SECONDS: int = 5
THRESHOLD_EVENTS: int = 50

# Process monitor
COOLDOWN_SECONDS: int = 30
PROCESS_CPU_THRESHOLD: float = 80.0
PROCESS_OPEN_FILES_THRESHOLD: int = 50

# AI prediction loop
AI_PREDICTION_INTERVAL: float = 3.0
AI_STARTUP_DELAY: float = 2.0
EVENT_LOG_MAX_SIZE: int = 200

# Dashboard / process broadcast
DASHBOARD_INTERVAL: float = 60.0
PROCESS_BROADCAST_INTERVAL: float = 3.0

# ── Paths ─────────────────────────────────────────────────────────────────────
LOG_FILE: str = os.path.join(PROJECT_ROOT, 'alerts.log')
ML_DIR: str = os.path.join(PROJECT_ROOT, 'ml')
MODEL_PATH: str = os.path.join(ML_DIR, 'model.pkl')
ENCODER_PATH: str = os.path.join(ML_DIR, 'encoder.pkl')
FAMILY_MODEL_PATH: str = os.path.join(ML_DIR, 'model_family.pkl')
FAMILY_ENCODER_PATH: str = os.path.join(ML_DIR, 'encoder_family.pkl')
FEATURE_COLS_PATH: str = os.path.join(ML_DIR, 'feature_cols.pkl')

# ── WebSocket ─────────────────────────────────────────────────────────────────
WS_HOST: str = '0.0.0.0'
WS_PORT: int = 8765
WS_PING_INTERVAL: int = 20
WS_PING_TIMEOUT: int = 10

# JWT
JWT_SECRET_FILE: str = os.path.join(PROJECT_ROOT, '.sentinel_jwt_secret')
JWT_ALGORITHM: str = 'HS256'
JWT_EXPIRY_HOURS: int = 24

# SSL / TLS
SSL_CERT_FILE: str = os.path.join(PROJECT_ROOT, 'certs', 'sentinel.crt')
SSL_KEY_FILE: str = os.path.join(PROJECT_ROOT, 'certs', 'sentinel.key')

# ── Canary ────────────────────────────────────────────────────────────────────
CANARY_DIR_NAME: str = '.sentinel_canary'
CANARY_FILE_COUNT: int = 3
CANARY_FILE_SIZE: int = 8192  # 8 KB of random bytes
CANARY_TARGET_DIRS: List[str] = [
    os.path.expanduser('~/Documents'),
    os.path.expanduser('~/Desktop'),
    os.path.expanduser('~/Downloads'),
]

# ── Watch-Path Blocklist ──────────────────────────────────────────────────────
BLOCKED_PATHS: List[str] = ['/proc', '/sys', '/dev', r'C:\Windows\System32']


# ═══════════════════════════════════════════════════════════════════════════════
# Helper functions
# ═══════════════════════════════════════════════════════════════════════════════

def _get_jwt_secret() -> str:
    """Load or generate a persistent JWT secret."""
    if os.path.exists(JWT_SECRET_FILE):
        with open(JWT_SECRET_FILE, 'r', encoding='utf-8') as f:
            return f.read().strip()
    secret: str = secrets.token_hex(32)
    with open(JWT_SECRET_FILE, 'w', encoding='utf-8') as f:
        f.write(secret)
    return secret


JWT_SECRET: str = _get_jwt_secret()


def validate_watch_path(path: str) -> str:
    """
    Validate and sanitize WATCH_PATH.

    Blocks monitoring of /proc, /sys, /dev, and the application's own
    directory tree.  Returns the resolved absolute path.

    Raises:
        ValueError: If the path is dangerous or invalid.
    """
    resolved: str = os.path.abspath(os.path.normpath(path))
    resolved_p: pathlib.Path = pathlib.Path(resolved)
    project_p: pathlib.Path = pathlib.Path(PROJECT_ROOT)

    # Block the application's own directory
    try:
        if resolved_p == project_p or resolved_p.is_relative_to(project_p):
            raise ValueError(
                f"WATCH_PATH cannot be the application directory: {resolved}"
            )
    except AttributeError:
        # Python < 3.9 fallback
        if str(resolved_p).startswith(str(project_p)):
            raise ValueError(
                f"WATCH_PATH cannot be the application directory: {resolved}"
            )

    # Block system directories
    for blocked in BLOCKED_PATHS:
        blocked_abs: str = os.path.abspath(os.path.normpath(blocked))
        try:
            bp = pathlib.Path(blocked_abs)
            if resolved_p == bp or resolved_p.is_relative_to(bp):
                raise ValueError(
                    f"WATCH_PATH blocked (system dir): {resolved}"
                )
        except AttributeError:
            if str(resolved_p).startswith(str(blocked_abs)):
                raise ValueError(
                    f"WATCH_PATH blocked (system dir): {resolved}"
                )

    return resolved


def get_watch_path() -> str:
    """Get and validate the WATCH_PATH from environment or default."""
    raw: str = os.getenv('WATCH_PATH', r'C:\RanSim')
    return validate_watch_path(raw)
