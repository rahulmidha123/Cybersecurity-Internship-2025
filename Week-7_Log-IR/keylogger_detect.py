# This module provides simulated detection helpers.
# Real keystroke hook detection requires OS-level hooks and elevated privileges.
# For educational purposes we use heuristics and pynput to demonstrate.

import threading
import time
from pynput import keyboard
from pathlib import Path
from .logger import log_suspicious

_keystroke_activity = {
    'count': 0,
    'last_time': None
}
_monitoring = False

def _on_press(key):
    _keystroke_activity['count'] += 1
    _keystroke_activity['last_time'] = time.time()

def start_keystroke_monitor(duration=10):
    """Start a short background monitor to count keystrokes (simulation)."""
    global _monitoring, _keystroke_activity
    if _monitoring:
        return
    _monitoring = True
    _keystroke_activity = {'count': 0, 'last_time': None}
    listener = keyboard.Listener(on_press=_on_press)
    listener.start()

    # run for `duration` seconds in a separate thread then stop
    def _run_and_stop():
        time.sleep(duration)
        try:
            listener.stop()
        except:
            pass
        # heuristic: if many keystrokes observed quickly, log as suspicious (demo)
        if _keystroke_activity['count'] > 30:
            log_suspicious(f"High keystroke activity observed during demo monitor: count={_keystroke_activity['count']}")
    t = threading.Thread(target=_run_and_stop, daemon=True)
    t.start()
