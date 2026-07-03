# debounce.py — generic per-key time-window debouncer, used by escalation and notify-level throttling
import time
from typing import Dict, Tuple


class Debouncer:
    def __init__(self):
        self._last: Dict[Tuple, float] = {}

    def is_debounced(self, key: Tuple, window: float) -> bool:
        now = time.time()
        last = self._last.get(key, 0.0)
        if now - last < window:
            return True
        self._last[key] = now
        return False
