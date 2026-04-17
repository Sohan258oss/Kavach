"""
main.py — Entry point for Project Kavach (Sentinel).

Wires together all monitoring threads.  All mutable state lives inside
the ``StateManager`` class; this module only orchestrates threads.
"""

import threading
import time
import os
import re
import asyncio
from typing import Dict, List, Optional, Any

import psutil

from config import (
    get_watch_path,
    SUSPICIOUS_PROCESS_EXES,
    AI_PREDICTION_INTERVAL,
    AI_STARTUP_DELAY,
    EVENT_LOG_MAX_SIZE,
    DASHBOARD_INTERVAL,
    PROCESS_BROADCAST_INTERVAL,
    HIGH_CONFIDENCE_THRESHOLD,
    SNAPSHOT_CONFIDENCE_THRESHOLD,
)
from logging_utils import setup_logging, get_logger, shutdown_logging
from monitor.file_monitor import start_file_monitor
from monitor.process_monitor import scan_processes
from monitor.feature_extractor import extract_features, validate_features
from ml.predictor import predict
from websocket_server import start_server, queue_alert
from canary import start_canary_monitor, verify_canary_integrity
from snapshot import trigger_snapshot

# ── Initialise structured logging (must be first) ────────────────────────────
setup_logging()
logger = get_logger('main')


# ═══════════════════════════════════════════════════════════════════════════════
# StateManager — single owner of all mutable runtime state
# ═══════════════════════════════════════════════════════════════════════════════

class StateManager:
    """Thread-safe container for every piece of mutable Sentinel state."""

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._stats: Dict[str, int] = {
            'total_alerts':           0,
            'ransomware_predictions': 0,
            'benign_predictions':     0,
            'processes_killed':       0,
            'high_entropy_files':     0,
            'suspicious_renames':     0,
        }
        self.alerts: List[str] = []
        self.event_log: List[Dict[str, Any]] = []
        self.event_log_lock: threading.Lock = threading.Lock()

    # ── stats helpers ─────────────────────────────────────────────────────

    def inc(self, key: str, amount: int = 1) -> None:
        with self._lock:
            self._stats[key] = self._stats.get(key, 0) + amount

    def snapshot_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    @property
    def ransomware_predictions(self) -> int:
        with self._lock:
            return self._stats['ransomware_predictions']

    # ── event-log helpers ─────────────────────────────────────────────────

    def push_event(self, event_data: Dict[str, Any]) -> None:
        with self.event_log_lock:
            self.event_log.append(event_data)
            if len(self.event_log) > EVENT_LOG_MAX_SIZE:
                self.event_log.pop(0)

    def drain_events(self) -> List[Dict[str, Any]]:
        with self.event_log_lock:
            snapshot = list(self.event_log)
            if snapshot:
                self.event_log.clear()
            return snapshot


# ═══════════════════════════════════════════════════════════════════════════════
# Globals
# ═══════════════════════════════════════════════════════════════════════════════

state = StateManager()
stop_event = threading.Event()
loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()


# ═══════════════════════════════════════════════════════════════════════════════
# WebSocket bootstrap
# ═══════════════════════════════════════════════════════════════════════════════

def _start_ws() -> None:
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(start_server())
    except Exception as exc:
        logger.error("WebSocket thread error: %s", exc)


# ═══════════════════════════════════════════════════════════════════════════════
# Alert handler
# ═══════════════════════════════════════════════════════════════════════════════

def handle_alert(
    message: Optional[str],
    event_data: Optional[Dict[str, Any]] = None,
) -> None:
    """Central alert handler called by every monitor."""
    if event_data:
        state.push_event(event_data)

    if not message:
        return

    timestamp: str = time.strftime('%Y-%m-%d %H:%M:%S')
    log_line: str = f"[{timestamp}] \u26a0\ufe0f  ALERT: {message}"
    logger.warning(message)
    state.alerts.append(log_line)
    state.inc('total_alerts')

    msg_upper: str = message.upper()
    if 'RENAME' in msg_upper:
        state.inc('suspicious_renames')
    if 'ENTROPY' in msg_upper:
        state.inc('high_entropy_files')

    alert_type: str = (
        'rename'  if 'RENAME'  in msg_upper else
        'entropy' if 'ENTROPY' in msg_upper else
        'process' if 'PROCESS' in msg_upper else
        'canary'  if 'CANARY'  in msg_upper else 'activity'
    )

    asyncio.run_coroutine_threadsafe(queue_alert({
        'type': 'alert', 'alertType': alert_type, 'message': message,
    }), loop)
    asyncio.run_coroutine_threadsafe(queue_alert({
        'type': 'stats', 'stats': state.snapshot_stats(),
    }), loop)

    if alert_type == 'entropy':
        match = re.search(r"HIGH ENTROPY FILE: (.*) \(entropy=(.*)\)", message)
        if match:
            asyncio.run_coroutine_threadsafe(queue_alert({
                'type': 'entropy',
                'filename': match.group(1),
                'entropy': float(match.group(2)),
            }), loop)


# ═══════════════════════════════════════════════════════════════════════════════
# Process killer
# ═══════════════════════════════════════════════════════════════════════════════

def kill_suspicious_process(name: str) -> None:
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'].lower() == name.lower():
                proc.kill()
                logger.critical(
                    "PROCESS KILLED: %s (pid=%d)", name, proc.info['pid'],
                )
                state.inc('processes_killed')
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# AI prediction loop
# ═══════════════════════════════════════════════════════════════════════════════

def run_ai_prediction() -> None:
    time.sleep(AI_STARTUP_DELAY)

    while not stop_event.is_set():
        time.sleep(AI_PREDICTION_INTERVAL)
        window: List[Dict[str, Any]] = state.drain_events()
        logger.debug("AI window size: %d events", len(window))

        if not window:
            continue

        features = extract_features(window)
        if not validate_features(features):
            continue

        result = predict(features)
        label: str = result['label']
        confidence: float = result['confidence']

        if result['is_ransomware']:
            state.inc('ransomware_predictions')
        else:
            state.inc('benign_predictions')

        logger.info("Prediction: %s | Confidence: %.1f%%", label, confidence)

        # ── Snapshot trigger (confidence > 70 %) ──
        if result['is_ransomware']:
            trigger_snapshot(confidence, label)

        if result['is_ransomware'] and result.get('high_confidence'):
            logger.critical(
                "HIGH CONFIDENCE RANSOMWARE DETECTED! %.1f%%", confidence,
            )
            handle_alert(
                f"[!!!] HIGH CONFIDENCE RANSOMWARE DETECTED! {confidence}%"
            )

        asyncio.run_coroutine_threadsafe(queue_alert({
            'type':                   'prediction',
            'label':                  label,
            'confidence':             confidence,
            'ransomware_probability': result.get('ransomware_probability', 0),
            'features':               features,
        }), loop)
        asyncio.run_coroutine_threadsafe(queue_alert({
            'type': 'stats', 'stats': state.snapshot_stats(),
        }), loop)


# ═══════════════════════════════════════════════════════════════════════════════
# Process monitor broadcast (for dashboard process list)
# ═══════════════════════════════════════════════════════════════════════════════

def process_monitor_loop() -> None:
    while not stop_event.is_set():
        processes: List[Dict[str, Any]] = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                processes.append({
                    'name':       proc.info['name'],
                    'cpu':        proc.info['cpu_percent'] or 0,
                    'suspicious': proc.info['name'].lower() in SUSPICIOUS_PROCESS_EXES,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        processes.sort(key=lambda x: x['cpu'], reverse=True)
        asyncio.run_coroutine_threadsafe(queue_alert({
            'type': 'process', 'processes': processes[:10],
        }), loop)
        time.sleep(PROCESS_BROADCAST_INTERVAL)


# ═══════════════════════════════════════════════════════════════════════════════
# Terminal dashboard
# ═══════════════════════════════════════════════════════════════════════════════

def print_dashboard() -> None:
    while not stop_event.is_set():
        time.sleep(DASHBOARD_INTERVAL)
        s = state.snapshot_stats()
        rp = s['ransomware_predictions']
        threat = (
            "\U0001f534 HIGH"    if rp > 3 else
            "\U0001f7e1 MEDIUM"  if rp > 0 else
            "\U0001f7e2 LOW"
        )
        logger.info(
            "\n"
            "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
            "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
            "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
            "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n"
            "\u2551        THREAT SUMMARY DASHBOARD          \u2551\n"
            "\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
            "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
            "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
            "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n"
            "\u2551  Threat Level      : %-21s\u2551\n"
            "\u2551  Total Alerts      : %-21d\u2551\n"
            "\u2551  High Entropy Files: %-21d\u2551\n"
            "\u2551  Ransomware Flags  : %-21d\u2551\n"
            "\u2551  Benign Checks     : %-21d\u2551\n"
            "\u2551  Processes Killed  : %-21d\u2551\n"
            "\u2551  Suspicious Renames: %-21d\u2551\n"
            "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
            "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
            "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
            "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d",
            threat,
            s['total_alerts'], s['high_entropy_files'],
            s['ransomware_predictions'], s['benign_predictions'],
            s['processes_killed'], s['suspicious_renames'],
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Canary integrity loop
# ═══════════════════════════════════════════════════════════════════════════════

def canary_integrity_loop() -> None:
    """Periodically verify canary file integrity."""
    while not stop_event.is_set():
        time.sleep(30)
        tampered = verify_canary_integrity()
        if tampered:
            handle_alert(
                f"\U0001f6a8 CANARY INTEGRITY CHECK: "
                f"{len(tampered)} canary file(s) tampered/missing!"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    # ── Validate watch path ──
    WATCH_PATH: str = get_watch_path()
    if not os.path.exists(WATCH_PATH):
        os.makedirs(WATCH_PATH)

    logger.info("=== SENTINEL | AI-Powered Ransomware Early Detection ===")
    logger.info("Watching  : %s", os.path.abspath(WATCH_PATH))
    logger.info("AI Model  : Loaded")
    logger.info("Dashboard : Open dashboard.html in browser")

    # ── Start WebSocket server thread ──
    ws_thread = threading.Thread(target=_start_ws, daemon=True)
    ws_thread.start()

    # ── Start file monitor ──
    observer = start_file_monitor(WATCH_PATH, handle_alert)

    # ── Deploy canary files & start canary monitors ──
    canary_observers = start_canary_monitor(handle_alert)

    # ── Start background threads ──
    threads: List[threading.Thread] = [
        threading.Thread(target=scan_processes, args=(handle_alert,), daemon=True),
        threading.Thread(target=run_ai_prediction, daemon=True),
        threading.Thread(target=process_monitor_loop, daemon=True),
        threading.Thread(target=print_dashboard, daemon=True),
        threading.Thread(target=canary_integrity_loop, daemon=True),
    ]
    for t in threads:
        t.start()

    logger.info("All monitors active.  Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        observer.stop()
        for co in canary_observers:
            co.stop()
        logger.info("SENTINEL stopped.")
        shutdown_logging()

    observer.join()
    for co in canary_observers:
        co.join()