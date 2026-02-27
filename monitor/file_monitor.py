import time
import os
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict
from monitor.entropy_checker import is_suspicious_entropy

SUSPICIOUS_EXTENSIONS = [
    '.locked', '.enc', '.crypt', '.crypto', '.encrypted',
    '.zzzzz', '.zzz', '.aaa', '.abc', '.xyz', '.wncry',
    '.wnry', '.darkness', '.ransomed', '.crypted', '.crypz'
]

class RansomwareFileHandler(FileSystemEventHandler):
    def __init__(self, alert_callback):
        self.alert_callback   = alert_callback
        self.event_counts     = defaultdict(int)
        self.window_start     = time.time()
        self.WINDOW_SECONDS   = 5
        self.THRESHOLD_EVENTS = 50

    def _make_event_data(self, event_type, entropy=0.0, extension=''):
        """Build event_data — NO psutil calls, just static values for speed."""
        return {
            'type':        event_type,
            'entropy':     entropy,
            'extension':   extension,
            'process_cpu': 5.0,   # static placeholder — not needed for detection
            'open_files':  10     # static placeholder — not needed for detection
        }

    def _check_rate(self, event_type):
        now = time.time()
        if now - self.window_start > self.WINDOW_SECONDS:
            self.event_counts.clear()
            self.window_start = now

        self.event_counts[event_type] += 1
        total = sum(self.event_counts.values())

        if total >= self.THRESHOLD_EVENTS:
            self.alert_callback(
                f"HIGH FILE ACTIVITY: {total} events in {self.WINDOW_SECONDS}s",
                event_data=self._make_event_data(event_type)
            )

    def on_modified(self, event):
        if not event.is_directory:
            self._check_rate('modified')
            ext                 = os.path.splitext(event.src_path)[1].lower()
            suspicious, entropy = is_suspicious_entropy(event.src_path)
            entropy             = float(entropy) if entropy and entropy > 0 else 0.0
            event_data          = self._make_event_data('modified', entropy, ext)

            if suspicious:
                self.alert_callback(
                    f"HIGH ENTROPY FILE: {event.src_path} (entropy={entropy:.4f})",
                    event_data=event_data
                )
            else:
                self.alert_callback(None, event_data=event_data)

    def on_created(self, event):
        if not event.is_directory:
            self._check_rate('created')
            ext = os.path.splitext(event.src_path)[1].lower()
            self.alert_callback(None, event_data=self._make_event_data('created', 0.0, ext))

    def on_deleted(self, event):
        if not event.is_directory:
            self._check_rate('deleted')
            ext = os.path.splitext(event.src_path)[1].lower()
            self.alert_callback(None, event_data=self._make_event_data('deleted', 0.0, ext))

    def on_moved(self, event):
        self._check_rate('renamed')
        dst        = event.dest_path
        ext        = os.path.splitext(dst)[1].lower()
        event_data = self._make_event_data('renamed', 0.0, ext)

        if ext in SUSPICIOUS_EXTENSIONS:
            self.alert_callback(
                f"SUSPICIOUS RENAME: {event.src_path} → {dst}",
                event_data=event_data
            )
        else:
            self.alert_callback(None, event_data=event_data)


def start_file_monitor(watch_path, alert_callback):
    handler  = RansomwareFileHandler(alert_callback)
    observer = Observer()
    observer.schedule(handler, watch_path, recursive=True)
    observer.start()
    print(f"[*] File Monitor: Watching {os.path.abspath(watch_path)}")
    return observer