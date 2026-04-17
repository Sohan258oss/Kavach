"""
canary.py — Honeypot / canary file system for Project Kavach (Sentinel).

Plants hidden high-entropy decoy files in sensitive directories and
monitors them with watchdog.  Any modification, deletion, or rename of
a canary file triggers an immediate high-priority alert — a strong
signal that ransomware is actively encrypting user files.
"""

import os
import secrets
import hashlib
import json
import threading
from typing import Callable, Dict, List, Set, Optional, Any

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from config import (
    CANARY_DIR_NAME,
    CANARY_FILE_COUNT,
    CANARY_FILE_SIZE,
    CANARY_TARGET_DIRS,
    PROJECT_ROOT,
)
from logging_utils import get_logger

logger = get_logger('canary')

# ── Registry of deployed canary files ─────────────────────────────────────────
_canary_registry: Dict[str, str] = {}        # abs-path → SHA-256
_registry_lock = threading.Lock()
_REGISTRY_FILE: str = os.path.join(PROJECT_ROOT, '.canary_registry.json')


# ═══════════════════════════════════════════════════════════════════════════════
# Watchdog handler
# ═══════════════════════════════════════════════════════════════════════════════

class CanaryHandler(FileSystemEventHandler):
    """Fires alerts the instant any canary file is touched."""

    def __init__(self, alert_callback: Callable[..., None]) -> None:
        self.alert_callback: Callable[..., None] = alert_callback

    def _is_canary(self, path: str) -> bool:
        with _registry_lock:
            return os.path.abspath(path) in _canary_registry

    def _trigger(self, filepath: str, action: str) -> None:
        msg: str = (
            f"\U0001f6a8 CANARY TRIP-WIRE: Decoy file {action}! "
            f"File: {filepath} — Possible ransomware activity!"
        )
        logger.critical(msg)
        self.alert_callback(
            msg,
            event_data={
                'type':        'canary',
                'entropy':     8.0,
                'extension':   os.path.splitext(filepath)[1],
                'process_cpu': 0.0,
                'open_files':  0,
            },
        )

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory and self._is_canary(event.src_path):
            self._trigger(event.src_path, 'MODIFIED')

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory and self._is_canary(event.src_path):
            self._trigger(event.src_path, 'DELETED')

    def on_moved(self, event: FileSystemEvent) -> None:
        if self._is_canary(event.src_path):
            self._trigger(event.src_path, 'RENAMED')


# ═══════════════════════════════════════════════════════════════════════════════
# Internal helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _generate_content() -> bytes:
    """Generate high-entropy random bytes for a canary file."""
    return secrets.token_bytes(CANARY_FILE_SIZE)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _save_registry() -> None:
    with _registry_lock:
        with open(_REGISTRY_FILE, 'w', encoding='utf-8') as fh:
            json.dump(_canary_registry, fh, indent=2)


def _load_registry() -> None:
    global _canary_registry
    if os.path.exists(_REGISTRY_FILE):
        with open(_REGISTRY_FILE, 'r', encoding='utf-8') as fh:
            _canary_registry = json.load(fh)
        logger.info("Loaded %d canary entries from registry", len(_canary_registry))


def _hide_on_windows(path: str) -> None:
    """Set the hidden attribute on Windows; no-op elsewhere."""
    if os.name == 'nt':
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(path, 0x02)  # type: ignore[union-attr]
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════════

_DECOY_NAMES: List[str] = [
    'financial_report_Q1.xlsx.bak',
    'passwords_backup.docx',
    'tax_records_2025.pdf.tmp',
    'confidential_notes.txt',
    'database_dump.sql.bak',
]


def deploy_canaries(
    target_dirs: Optional[List[str]] = None,
    count_per_dir: int = CANARY_FILE_COUNT,
) -> List[str]:
    """
    Plant hidden high-entropy decoy files in sensitive directories.

    Returns:
        List of absolute paths of deployed canary files.
    """
    dirs: List[str] = target_dirs or CANARY_TARGET_DIRS
    deployed: List[str] = []

    for tdir in dirs:
        if not os.path.isdir(tdir):
            logger.warning("Canary target dir missing, skipping: %s", tdir)
            continue

        canary_dir: str = os.path.join(tdir, CANARY_DIR_NAME)
        os.makedirs(canary_dir, exist_ok=True)
        _hide_on_windows(canary_dir)

        for i in range(count_per_dir):
            filename: str = _DECOY_NAMES[i % len(_DECOY_NAMES)]
            filepath: str = os.path.join(canary_dir, filename)

            content: bytes = _generate_content()
            file_hash: str = _sha256(content)

            with open(filepath, 'wb') as fh:
                fh.write(content)
            _hide_on_windows(filepath)

            abs_path: str = os.path.abspath(filepath)
            with _registry_lock:
                _canary_registry[abs_path] = file_hash

            deployed.append(abs_path)
            logger.info("Deployed canary: %s", abs_path)

    _save_registry()
    logger.info(
        "Total canaries deployed: %d across %d directories",
        len(deployed), len(dirs),
    )
    return deployed


def start_canary_monitor(
    alert_callback: Callable[..., None],
) -> List[Observer]:
    """
    Deploy canaries and begin monitoring them.

    Returns:
        List of Observer instances (call .stop() on shutdown).
    """
    _load_registry()
    deployed: List[str] = deploy_canaries()

    # Unique parent directories that need watching
    watch_dirs: Set[str] = set()
    for fp in deployed:
        watch_dirs.add(os.path.dirname(fp))
    with _registry_lock:
        for fp in _canary_registry:
            parent = os.path.dirname(fp)
            if os.path.isdir(parent):
                watch_dirs.add(parent)

    handler = CanaryHandler(alert_callback)
    observers: List[Observer] = []

    for wd in watch_dirs:
        obs = Observer()
        obs.schedule(handler, wd, recursive=False)
        obs.start()
        observers.append(obs)
        logger.info("Canary monitor watching: %s", wd)

    return observers


def verify_canary_integrity() -> List[str]:
    """
    Check every registered canary for tampering or deletion.

    Returns:
        List of tampered/missing file paths.
    """
    tampered: List[str] = []
    with _registry_lock:
        for filepath, expected in _canary_registry.items():
            if not os.path.exists(filepath):
                tampered.append(filepath)
                logger.critical("Canary MISSING: %s", filepath)
                continue
            try:
                with open(filepath, 'rb') as fh:
                    if _sha256(fh.read()) != expected:
                        tampered.append(filepath)
                        logger.critical("Canary TAMPERED: %s", filepath)
            except Exception as exc:
                logger.error("Cannot verify canary %s: %s", filepath, exc)
                tampered.append(filepath)
    return tampered
