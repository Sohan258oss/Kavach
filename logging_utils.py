"""
logging_utils.py — Centralized logging for Project Kavach (Sentinel).

Replaces all print() and synchronous file writes with Python's logging
module.  Uses QueueHandler + QueueListener for non-blocking file I/O
to alerts.log.
"""

import logging
import logging.handlers
import os
import sys
import queue
from typing import Optional

from config import LOG_FILE


# ── Custom Formatter ──────────────────────────────────────────────────────────

class SentinelFormatter(logging.Formatter):
    """Level-aware formatter that preserves emoji and adds structure."""

    _FORMATS = {
        logging.DEBUG:    '%(asctime)s [DEBUG]    %(name)s: %(message)s',
        logging.INFO:     '%(asctime)s [INFO]     %(name)s: %(message)s',
        logging.WARNING:  '%(asctime)s [WARNING]  %(name)s: %(message)s',
        logging.ERROR:    '%(asctime)s [ERROR]    %(name)s: %(message)s',
        logging.CRITICAL: '%(asctime)s [CRITICAL] %(name)s: %(message)s',
    }

    def format(self, record: logging.LogRecord) -> str:
        fmt = self._FORMATS.get(record.levelno, self._FORMATS[logging.INFO])
        formatter = logging.Formatter(fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)


# ── Module-level state ────────────────────────────────────────────────────────

_listener: Optional[logging.handlers.QueueListener] = None


def setup_logging(
    name: str = 'sentinel',
    level: int = logging.DEBUG,
) -> logging.Logger:
    """
    Configure and return the root Sentinel logger with:

    * Console handler  → stdout, DEBUG level
    * Threaded file handler → alerts.log, INFO level, non-blocking
    """
    global _listener

    logger = logging.getLogger(name)
    if logger.handlers:          # idempotent
        return logger

    logger.setLevel(level)

    # ── Console handler ──
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG)
    console.setFormatter(SentinelFormatter())
    logger.addHandler(console)

    # ── Non-blocking file handler (QueueHandler → QueueListener) ──
    log_q: queue.Queue[logging.LogRecord] = queue.Queue(-1)

    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(SentinelFormatter())

    queue_handler = logging.handlers.QueueHandler(log_q)
    queue_handler.setLevel(logging.INFO)
    logger.addHandler(queue_handler)

    _listener = logging.handlers.QueueListener(
        log_q, file_handler, respect_handler_level=True,
    )
    _listener.start()

    return logger


def get_logger(module_name: str) -> logging.Logger:
    """Return a child logger for a specific module (e.g. 'sentinel.canary')."""
    return logging.getLogger(f'sentinel.{module_name}')


def shutdown_logging() -> None:
    """Flush all queued records and shut down handlers cleanly."""
    global _listener
    if _listener is not None:
        _listener.stop()
        _listener = None
    logging.shutdown()
