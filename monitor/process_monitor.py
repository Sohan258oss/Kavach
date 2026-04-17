"""
process_monitor.py — Event-driven process monitoring.

Uses WMI Win32_ProcessStartTrace on Windows for instant detection of
suspicious process launches.  Falls back to psutil polling on
non-Windows platforms.
"""

import os
import sys
import time
import platform
from collections import defaultdict
from typing import Callable, Dict, Optional, Any

from config import (
    SUSPICIOUS_PROCESSES,
    COOLDOWN_SECONDS,
    PROCESS_CPU_THRESHOLD,
    PROCESS_OPEN_FILES_THRESHOLD,
)
from logging_utils import get_logger

logger = get_logger('process_monitor')

# ── Cooldown trackers ─────────────────────────────────────────────────────────
_alerted_pids: Dict[int, float] = defaultdict(float)
_alerted_procs: Dict[str, float] = defaultdict(float)


def _on_cooldown(key: Any, tracker: Dict[Any, float]) -> bool:
    """Return True if an alert for *key* was fired within COOLDOWN_SECONDS."""
    now: float = time.time()
    if now - tracker[key] < COOLDOWN_SECONDS:
        return True
    tracker[key] = now
    return False


def _make_process_event(
    cpu: float = 0.0,
    open_files: int = 0,
) -> Dict[str, Any]:
    """Build event data dict consumed by the ML pipeline."""
    return {
        'type':        'process',
        'entropy':     0.0,
        'extension':   '',
        'process_cpu': cpu,
        'open_files':  open_files,
    }


def _get_process_features(pid: int) -> Optional[Dict[str, Any]]:
    """Extract behavioural features from a single process by PID."""
    import psutil
    try:
        proc = psutil.Process(pid)
        return {
            'pid':         pid,
            'name':        proc.name(),
            'cpu_percent': proc.cpu_percent(interval=0.5),
            'memory_mb':   round(proc.memory_info().rss / (1024 * 1024), 2),
            'open_files':  len(proc.open_files()),
            'connections': len(proc.connections()),
            'status':      proc.status(),
        }
    except Exception:
        return None


def _handle_new_process(
    pid: int,
    name: str,
    cmdline: str,
    alert_callback: Callable[..., None],
) -> None:
    """Evaluate a newly-started process for suspicious indicators."""
    name_lower: str = name.lower()
    cmdline_lower: str = cmdline.lower()

    # ── Known suspicious process names ──
    for suspicious in SUSPICIOUS_PROCESSES:
        if suspicious in name_lower or suspicious in cmdline_lower:
            if not _on_cooldown(name_lower, _alerted_procs):
                alert_callback(
                    f"SUSPICIOUS PROCESS: {name} | CMD: {cmdline[:100]}",
                    event_data=_make_process_event(),
                )
                logger.warning(
                    "Suspicious process: %s (PID=%d)", name, pid,
                )
            return

    # ── High CPU + many open files  →  encryption behaviour ──
    features = _get_process_features(pid)
    if features:
        cpu: float = features['cpu_percent']
        of: int = features['open_files']
        if cpu > PROCESS_CPU_THRESHOLD and of > PROCESS_OPEN_FILES_THRESHOLD:
            if not _on_cooldown(pid, _alerted_pids):
                alert_callback(
                    f"SUSPICIOUS BEHAVIOR: {features['name']} "
                    f"CPU={cpu}% Files={of}",
                    event_data=_make_process_event(cpu, of),
                )
                logger.warning(
                    "Suspicious behaviour: %s CPU=%.1f%% Files=%d",
                    features['name'], cpu, of,
                )


# ═══════════════════════════════════════════════════════════════════════════════
# WMI event-driven backend (Windows)
# ═══════════════════════════════════════════════════════════════════════════════

def _scan_wmi(alert_callback: Callable[..., None]) -> None:
    """Block on WMI Win32_ProcessStartTrace — zero polling."""
    import pythoncom          # type: ignore[import-untyped]
    import wmi as wmi_mod     # type: ignore[import-untyped]

    pythoncom.CoInitialize()
    try:
        c = wmi_mod.WMI()
        logger.info("WMI event-driven process monitor started")
        watcher = c.Win32_ProcessStartTrace.watch_for()

        while True:
            try:
                event = watcher(timeout_ms=5000)
                if event:
                    pid: int = int(event.ProcessID)
                    pname: str = str(event.ProcessName)
                    # WMI doesn't expose cmdline; fetch via psutil
                    try:
                        import psutil
                        cmdline = ' '.join(psutil.Process(pid).cmdline() or [])
                    except Exception:
                        cmdline = pname
                    _handle_new_process(pid, pname, cmdline, alert_callback)
            except Exception as exc:
                # x_wmi_timed_out or transient errors
                if 'timed out' not in str(exc).lower():
                    logger.debug("WMI event error (non-fatal): %s", exc)
                continue
    finally:
        pythoncom.CoUninitialize()


# ═══════════════════════════════════════════════════════════════════════════════
# Polling fallback (Linux / macOS / no-WMI)
# ═══════════════════════════════════════════════════════════════════════════════

def _scan_polling(alert_callback: Callable[..., None]) -> None:
    """Fallback: poll psutil.process_iter every 2 s."""
    import psutil
    logger.info("Polling-based process monitor started (non-Windows fallback)")
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pid = proc.info['pid']
                name = proc.info['name'] or ''
                cmdline = ' '.join(proc.info['cmdline'] or [])
                _handle_new_process(pid, name, cmdline, alert_callback)
            except Exception:
                pass
        time.sleep(2)


# ═══════════════════════════════════════════════════════════════════════════════
# Public entry point
# ═══════════════════════════════════════════════════════════════════════════════

def scan_processes(alert_callback: Callable[..., None]) -> None:
    """
    Start process monitoring.

    Uses WMI on Windows, falls back to polling otherwise.
    """
    if platform.system() == 'Windows':
        try:
            _scan_wmi(alert_callback)
        except ImportError:
            logger.warning(
                "WMI/pywin32 not installed — falling back to polling. "
                "Install with: pip install wmi pywin32"
            )
            _scan_polling(alert_callback)
        except Exception as exc:
            logger.error("WMI failed (%s) — falling back to polling", exc)
            _scan_polling(alert_callback)
    else:
        _scan_polling(alert_callback)