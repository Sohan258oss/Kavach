import threading
import time
import os
import psutil
import asyncio
import re
from monitor.file_monitor import start_file_monitor
from monitor.process_monitor import scan_processes
from monitor.feature_extractor import extract_features, validate_features
from ml.predictor import predict
from websocket_server import start_server, queue_alert

# ── WebSocket Server ──────────────────────────────────────────────────────────
loop = asyncio.new_event_loop()
def start_ws():
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(start_server())
    except Exception as e:
        print(f"[!!!] WebSocket Server Thread Error: {e}")

ws_thread = threading.Thread(target=start_ws, daemon=True)
ws_thread.start()

# ── Config ────────────────────────────────────────────────────────────────────
WATCH_PATH = os.getenv("WATCH_PATH", "./watch_dir")
if not os.path.exists(WATCH_PATH):
    os.makedirs(WATCH_PATH)
LOG_FILE = "alerts.log"

stop_event  = threading.Event()
alerts      = []
stats = {
    'total_alerts':           0,
    'ransomware_predictions': 0,
    'benign_predictions':     0,
    'processes_killed':       0,
    'high_entropy_files':     0,
    'suspicious_renames':     0
}

# ── Event Log Window ──────────────────────────────────────────────────────────
event_log      = []
event_log_lock = threading.Lock()

# ── Logging ───────────────────────────────────────────────────────────────────
def log_to_file(message):
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(message + '\n')

# ── Alert Handler ─────────────────────────────────────────────────────────────
def handle_alert(message, event_data=None):
    # ── Always store event data for ML first ──
    if event_data:
        with event_log_lock:
            event_log.append(event_data)
            if len(event_log) > 200:
                event_log.pop(0)

    # ── Silent event — no message, just data collection ──
    if not message:
        return

    # ── Real alert ──
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log       = f"[{timestamp}] ⚠️  ALERT: {message}"
    print(log)
    alerts.append(log)
    log_to_file(log)
    stats['total_alerts'] += 1

    msg_upper = message.upper()

    if 'RENAME' in msg_upper:
        stats['suspicious_renames'] += 1
    if 'ENTROPY' in msg_upper:
        stats['high_entropy_files'] += 1

    alert_type = 'rename'  if 'RENAME'  in msg_upper else \
                 'entropy' if 'ENTROPY' in msg_upper else \
                 'process' if 'PROCESS' in msg_upper else 'activity'

    asyncio.run_coroutine_threadsafe(queue_alert({
        'type':      'alert',
        'alertType': alert_type,
        'message':   message
    }), loop)

    asyncio.run_coroutine_threadsafe(queue_alert({
        'type':  'stats',
        'stats': dict(stats)
    }), loop)

    if alert_type == 'entropy':
        match = re.search(r"HIGH ENTROPY FILE: (.*) \(entropy=(.*)\)", message)
        if match:
            asyncio.run_coroutine_threadsafe(queue_alert({
                'type':     'entropy',
                'filename': match.group(1),
                'entropy':  float(match.group(2))
            }), loop)

# ── Process Killer ────────────────────────────────────────────────────────────
def kill_suspicious_process(name):
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'].lower() == name.lower():
                proc.kill()
                msg = f"[!!!] PROCESS KILLED: {name} (pid={proc.info['pid']})"
                print(msg)
                log_to_file(msg)
                stats['processes_killed'] += 1
        except Exception:
            pass

# ── AI Prediction Loop ────────────────────────────────────────────────────────
def run_ai_prediction():
    # Wait 2 seconds before first prediction so system is ready
    time.sleep(2)

    while not stop_event.is_set():
        # ── Predict every 3 seconds instead of 5 ──
        # Simulation runs in ~3 seconds so 5s window was missing events
        time.sleep(3)

        with event_log_lock:
            current_window = list(event_log)
            # DON'T clear — accumulate events across windows
            # Only clear if we got a prediction
            if current_window:
                event_log.clear()

        print(f"[AI] Window size: {len(current_window)} events")

        if not current_window:
            print("[AI] No events in window — skipping prediction")
            continue

        features = extract_features(current_window)

        if not validate_features(features):
            print("[AI] Feature validation failed — skipping prediction")
            continue

        result     = predict(features)
        label      = result['label']
        confidence = result['confidence']

        if result['is_ransomware']:
            stats['ransomware_predictions'] += 1
        else:
            stats['benign_predictions'] += 1

        status = f"[AI] Prediction: {label} | Confidence: {confidence}%"
        print(status)
        log_to_file(status)

        if result['is_ransomware'] and result.get('high_confidence'):
            warning = f"[!!!] HIGH CONFIDENCE RANSOMWARE DETECTED! {confidence}%"
            print(warning)
            log_to_file(warning)
            handle_alert(warning)

        asyncio.run_coroutine_threadsafe(queue_alert({
            'type':                  'prediction',
            'label':                 label,
            'confidence':            confidence,
            'ransomware_probability': result.get('ransomware_probability', 0),
            'features':              features
        }), loop)

        asyncio.run_coroutine_threadsafe(queue_alert({
            'type':  'stats',
            'stats': dict(stats)
        }), loop)

# ── Process Monitor Loop ──────────────────────────────────────────────────────
def process_monitor_loop():
    while not stop_event.is_set():
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                processes.append({
                    'name':      proc.info['name'],
                    'cpu':       proc.info['cpu_percent'] or 0,
                    'suspicious': proc.info['name'].lower() in [
                        'vssadmin.exe', 'bcdedit.exe', 'powershell.exe',
                        'cipher.exe', 'wbadmin.exe', 'schtasks.exe'
                    ]
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        processes.sort(key=lambda x: x['cpu'], reverse=True)

        asyncio.run_coroutine_threadsafe(queue_alert({
            'type':      'process',
            'processes': processes[:10]
        }), loop)
        time.sleep(3)

# ── Terminal Dashboard ────────────────────────────────────────────────────────
def print_dashboard():
    while not stop_event.is_set():
        time.sleep(60)
        threat_level = "🟢 LOW"
        if stats['ransomware_predictions'] > 0:
            threat_level = "🟡 MEDIUM"
        if stats['ransomware_predictions'] > 3:
            threat_level = "🔴 HIGH"

        print(f"""
╔══════════════════════════════════════════╗
║        THREAT SUMMARY DASHBOARD          ║
╠══════════════════════════════════════════╣
║  Threat Level      : {threat_level:<21}║
║  Total Alerts      : {stats['total_alerts']:<21}║
║  High Entropy Files: {stats['high_entropy_files']:<21}║
║  Ransomware Flags  : {stats['ransomware_predictions']:<21}║
║  Benign Checks     : {stats['benign_predictions']:<21}║
║  Processes Killed  : {stats['processes_killed']:<21}║
║  Suspicious Renames: {stats['suspicious_renames']:<21}║
╚══════════════════════════════════════════╝
        """)

# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== SENTINEL | AI-Powered Ransomware Early Detection ===")
    print(f"[*] Watching  : {os.path.abspath(WATCH_PATH)}")
    print(f"[*] AI Model  : Loaded")
    print(f"[*] Log File  : {LOG_FILE}")
    print(f"[*] Dashboard : Open dashboard.html in browser\n")

    observer = start_file_monitor(WATCH_PATH, handle_alert)

    threads = [
        threading.Thread(target=scan_processes,        args=(handle_alert,), daemon=True),
        threading.Thread(target=run_ai_prediction,                            daemon=True),
        threading.Thread(target=process_monitor_loop,                         daemon=True),
        threading.Thread(target=print_dashboard,                              daemon=True),
    ]
    for t in threads:
        t.start()

    print("[*] All monitors active. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        observer.stop()
        print("\n[*] SENTINEL stopped.")
        print(f"[*] Alerts saved to: {LOG_FILE}")

    observer.join()