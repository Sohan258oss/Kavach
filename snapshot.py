"""
snapshot.py — "Time Machine" snapshotting for Project Kavach (Sentinel).

Triggers a VSS shadow copy (Windows) or ZFS snapshot (Linux) when the
AI model's ransomware confidence exceeds 70 %.  A cooldown prevents
snapshot spam.
"""

import os
import subprocess
import platform
import time
import threading
from typing import Optional, List

from config import SNAPSHOT_CONFIDENCE_THRESHOLD, PROJECT_ROOT
from logging_utils import get_logger

logger = get_logger('snapshot')

_MIN_SNAPSHOT_INTERVAL: float = 60.0          # seconds between snapshots
_last_snapshot_time: float = 0.0
_snapshot_lock: threading.Lock = threading.Lock()


# ═══════════════════════════════════════════════════════════════════════════════
# Privilege check
# ═══════════════════════════════════════════════════════════════════════════════

def _is_admin() -> bool:
    """Return True if the process has admin / root privileges."""
    if platform.system() == 'Windows':
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[union-attr]
        except Exception:
            return False
    return os.geteuid() == 0  # type: ignore[attr-defined]


# ═══════════════════════════════════════════════════════════════════════════════
# VSS (Windows)
# ═══════════════════════════════════════════════════════════════════════════════

def _create_vss_snapshot(volume: str = 'C:') -> Optional[str]:
    """Create a Volume Shadow Copy via vssadmin."""
    if not _is_admin():
        logger.error(
            "VSS requires Administrator privileges. "
            "Run Sentinel as Administrator for snapshot support."
        )
        return None

    try:
        cmd: List[str] = ['vssadmin', 'create', 'shadow', f'/for={volume}\\']
        logger.info("Creating VSS snapshot for %s …", volume)
        flags: int = 0
        if platform.system() == 'Windows':
            flags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=120, creationflags=flags,
        )

        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if 'Shadow Copy ID' in line:
                    sid: str = line.split(':')[-1].strip()
                    logger.info("VSS snapshot created: %s", sid)
                    return sid
            logger.info("VSS snapshot created (ID not parsed)")
            return 'created'

        logger.error("VSS failed: %s", result.stderr.strip())
        return None

    except subprocess.TimeoutExpired:
        logger.error("VSS snapshot timed out (120 s)")
        return None
    except FileNotFoundError:
        logger.error("vssadmin not found on this system")
        return None
    except Exception as exc:
        logger.error("VSS error: %s", exc)
        return None


def _create_wmi_shadow(volume: str = 'C:') -> Optional[str]:
    """Fallback: create shadow copy via WMI COM."""
    try:
        import wmi as wmi_mod  # type: ignore[import-untyped]
        c = wmi_mod.WMI()
        logger.info("Creating WMI shadow copy for %s …", volume)
        result = c.Win32_ShadowCopy.Create(Volume=f'{volume}\\')
        if result[0] == 0:
            logger.info("WMI shadow copy created: %s", result[1])
            return str(result[1])
        logger.error("WMI shadow copy failed (code %d)", result[0])
        return None
    except ImportError:
        logger.error("WMI module not available")
        return None
    except Exception as exc:
        logger.error("WMI shadow copy error: %s", exc)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# ZFS (Linux)
# ═══════════════════════════════════════════════════════════════════════════════

def _create_zfs_snapshot(dataset: Optional[str] = None) -> Optional[str]:
    """Create a ZFS snapshot on Linux."""
    if not _is_admin():
        logger.error("ZFS snapshot requires root privileges")
        return None

    try:
        if dataset is None:
            r = subprocess.run(
                ['zfs', 'list', '-H', '-o', 'name', '/'],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0 and r.stdout.strip():
                dataset = r.stdout.strip()
            else:
                logger.error("Cannot auto-detect ZFS dataset")
                return None

        ts: str = time.strftime('%Y%m%d_%H%M%S')
        snap: str = f"{dataset}@sentinel_defense_{ts}"
        r2 = subprocess.run(
            ['zfs', 'snapshot', snap],
            capture_output=True, text=True, timeout=60,
        )
        if r2.returncode == 0:
            logger.info("ZFS snapshot created: %s", snap)
            return snap
        logger.error("ZFS snapshot failed: %s", r2.stderr.strip())
        return None

    except FileNotFoundError:
        logger.error("ZFS not available on this system")
        return None
    except Exception as exc:
        logger.error("ZFS error: %s", exc)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════════

def trigger_snapshot(
    confidence: float,
    label: str = 'Unknown',
    threshold: float = SNAPSHOT_CONFIDENCE_THRESHOLD,
) -> bool:
    """
    Trigger a system snapshot when ransomware confidence exceeds *threshold*.

    Args:
        confidence: AI confidence percentage (0–100).
        label:      Detection label (e.g. 'Ransomware').
        threshold:  Minimum confidence to trigger (default 70 %).

    Returns:
        True if a snapshot was successfully created.
    """
    global _last_snapshot_time

    if confidence < threshold:
        return False

    with _snapshot_lock:
        now: float = time.time()
        if now - _last_snapshot_time < _MIN_SNAPSHOT_INTERVAL:
            remaining = _MIN_SNAPSHOT_INTERVAL - (now - _last_snapshot_time)
            logger.info("Snapshot skipped — cooldown (%.0fs left)", remaining)
            return False

        logger.critical(
            "SNAPSHOT TRIGGERED — confidence %.1f%% (%s) > %.0f%% threshold",
            confidence, label, threshold,
        )

        result: Optional[str] = None
        system: str = platform.system()

        if system == 'Windows':
            result = _create_vss_snapshot()
            if result is None:
                result = _create_wmi_shadow()
        elif system == 'Linux':
            result = _create_zfs_snapshot()
        else:
            logger.warning("Snapshots not supported on %s", system)
            return False

        if result:
            _last_snapshot_time = now
            logger.info("Snapshot completed: %s", result)
            return True

        logger.error("Snapshot FAILED — manual backup recommended")
        return False


def list_vss_snapshots() -> List[str]:
    """List existing VSS shadow copies (Windows only)."""
    if platform.system() != 'Windows':
        return []
    try:
        r = subprocess.run(
            ['vssadmin', 'list', 'shadows'],
            capture_output=True, text=True, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
        )
        if r.returncode == 0:
            return [
                ln.split(':')[-1].strip()
                for ln in r.stdout.splitlines()
                if 'Shadow Copy ID' in ln
            ]
    except Exception:
        pass
    return []
