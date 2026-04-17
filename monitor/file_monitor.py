"""
file_monitor.py — Filesystem event handler for ransomware detection.

Uses watchdog to monitor create / modify / delete / rename in real time.
All constants imported from config.py.
"""

import os
import time
from collections import defaultdict
from typing import Callable, Dict, Any

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from config import SUSPICIOUS_EXTENSIONS, WINDOW_SECONDS, THRESHOLD_EVENTS
from monitor.entropy_checker import is_suspicious_entropy
from logging_utils import get_logger

logger = get_logger('file_monitor')


class RansomwareFileHandler(FileSystemEventHandler):
    """Detects ransomware-like filesystem behaviour patterns."""

    def __init__(self, alert_callback: Callable[..., None]) -> None:
        self.alert_callback: Callable[..., None] = alert_callback
        self.event_counts: Dict[str, int] = defaultdict(int)
        self.window_start: float = time.time()

    # ── helpers ────────────────────────────────────────────────────────────

    def _make_event_data(
        self,
        event_type: str,
        entropy: float = 0.0,
        extension: str = '',
    ) -> Dict[str, Any]:
        """Build event data — static placeholders for speed."""
        return {
            'type':        event_type,
            'entropy':     entropy,
            'extension':   extension,
            'process_cpu': 5.0,
            'open_files':  10,
        }

    def _check_rate(self, event_type: str) -> None:
        """Detect bursts of filesystem activity within the time window."""
        now: float = time.time()
        if now - self.window_start > WINDOW_SECONDS:
            self.event_counts.clear()
            self.window_start = now

        self.event_counts[event_type] += 1
        total: int = sum(self.event_counts.values())

        if total >= THRESHOLD_EVENTS:
            self.alert_callback(
                f"HIGH FILE ACTIVITY: {total} events in {WINDOW_SECONDS}s",
                event_data=self._make_event_data(event_type),
            )

    # ── watchdog callbacks ────────────────────────────────────────────────

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._check_rate('modified')
            ext: str = os.path.splitext(event.src_path)[1].lower()
            suspicious, entropy = is_suspicious_entropy(event.src_path)
            entropy = float(entropy) if entropy and entropy > 0 else 0.0
            event_data = self._make_event_data('modified', entropy, ext)

            if suspicious:
                self.alert_callback(
                    f"HIGH ENTROPY FILE: {event.src_path} (entropy={entropy:.4f})",
                    event_data=event_data,
                )
            else:
                self.alert_callback(None, event_data=event_data)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._check_rate('created')
            ext: str = os.path.splitext(event.src_path)[1].lower()
            self.alert_callback(
                None, event_data=self._make_event_data('created', 0.0, ext),
            )

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._check_rate('deleted')
            ext: str = os.path.splitext(event.src_path)[1].lower()
            self.alert_callback(
                None, event_data=self._make_event_data('deleted', 0.0, ext),
            )

    def on_moved(self, event: FileSystemEvent) -> None:
        self._check_rate('renamed')
        dst: str = event.dest_path
        ext: str = os.path.splitext(dst)[1].lower()
        event_data = self._make_event_data('renamed', 0.0, ext)

        if ext in SUSPICIOUS_EXTENSIONS:
            self.alert_callback(
                f"SUSPICIOUS RENAME: {event.src_path} → {dst}",
                event_data=event_data,
            )
        else:
            self.alert_callback(None, event_data=event_data)


def start_file_monitor(
    watch_path: str,
    alert_callback: Callable[..., None],
) -> Observer:
    """Start the watchdog file-monitor observer."""
    handler = RansomwareFileHandler(alert_callback)
    observer = Observer()
    observer.schedule(handler, watch_path, recursive=True)
    observer.start()
    logger.info("File Monitor watching: %s", os.path.abspath(watch_path))
    return observer