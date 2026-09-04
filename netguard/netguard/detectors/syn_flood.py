"""
syn_flood.py — sliding-window SYN flood detector.

Counts SYN (no ACK) packets per source IP within a window and fires
when the rate crosses a threshold. This is a coarse signal on its
own — real SYN flood mitigation usually also looks at half-open
connection counts on the target — but it's a reasonable first pass
and cheap to compute per-packet.
"""

import time
from collections import defaultdict, deque


class SynFloodDetector:
    name = "syn_flood"

    def __init__(self, notifier, window_seconds: int = 5, syn_threshold: int = 100):
        self.notifier = notifier
        self.window_seconds = window_seconds
        self.syn_threshold = syn_threshold
        self._activity = defaultdict(deque)
        self._already_alerted = set()

    def process_syn(self, src_ip: str, timestamp: float = None):
        ts = timestamp or time.time()
        window = self._activity[src_ip]
        window.append(ts)
        self._evict_old(window, ts)

        if len(window) >= self.syn_threshold:
            if src_ip not in self._already_alerted:
                self.notifier.fire(
                    detector=self.name,
                    source_ip=src_ip,
                    severity="HIGH",
                    message=(
                        f"{src_ip} sent {len(window)} SYN packets in "
                        f"{self.window_seconds}s — possible SYN flood"
                    ),
                )
                self._already_alerted.add(src_ip)
        else:
            self._already_alerted.discard(src_ip)

    def _evict_old(self, window: deque, now: float):
        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()
