import psutil
import time
from collections import defaultdict

SUSPICIOUS_PROCESSES = ['vssadmin', 'bcdedit', 'wbadmin', 'cipher', 'schtasks', 'wscript', 'cscript']

# ── Cooldown tracker — prevents spamming same alert repeatedly ──
_alerted_pids  = defaultdict(float)   # pid  → last alert timestamp
_alerted_procs = defaultdict(float)   # name → last alert timestamp
COOLDOWN_SECONDS = 30

def _on_cooldown(key, tracker):
    now = time.time()
    if now - tracker[key] < COOLDOWN_SECONDS:
        return True
    tracker[key] = now
    return False

def get_process_features(pid):
    """Extract behavioral features from a single process."""
    try:
        proc = psutil.Process(pid)
        return {
            'pid':         pid,
            'name':        proc.name(),
            'cpu_percent': proc.cpu_percent(interval=0.5),
            'memory_mb':   proc.memory_info().rss / (1024 * 1024),
            'open_files':  len(proc.open_files()),
            'connections': len(proc.connections()),
            'status':      proc.status()
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def scan_processes(alert_callback):
    """Continuously scan all processes for anomalies."""
    while True:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pid     = proc.info['pid']
                name    = proc.info['name'].lower()
                cmdline = ' '.join(proc.info['cmdline'] or []).lower()

                # ── Check for suspicious process names/commands ──
                for suspicious in SUSPICIOUS_PROCESSES:
                    if suspicious in name or suspicious in cmdline:
                        if not _on_cooldown(name, _alerted_procs):
                            alert_callback(
                                f"SUSPICIOUS PROCESS: {name} | CMD: {cmdline[:100]}",
                                event_data={
                                    'type':        'process',
                                    'entropy':     0.0,
                                    'extension':   '',
                                    'process_cpu': 0.0,
                                    'open_files':  0
                                }
                            )

                # ── Check for high CPU + many open files (encryption behavior) ──
                features = get_process_features(pid)
                if features:
                    cpu        = features['cpu_percent']
                    open_files = features['open_files']

                    if cpu > 80 and open_files > 50:
                        if not _on_cooldown(pid, _alerted_pids):
                            alert_callback(
                                f"SUSPICIOUS BEHAVIOR: {features['name']} "
                                f"CPU={cpu}% Files={open_files}",
                                event_data={
                                    'type':        'process',
                                    'entropy':     0.0,
                                    'extension':   '',
                                    'process_cpu': cpu,
                                    'open_files':  open_files
                                }
                            )

            except Exception:
                pass

        time.sleep(2)