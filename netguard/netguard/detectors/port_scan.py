"""
port_scan.py — sliding-window port scan detector.

Approach:
    For each source IP, track the set of distinct destination ports
    it has touched within `window_seconds`. If that set grows past
    `unique_port_threshold`, fire an alert. This catches classic
    horizontal/vertical scans (nmap -sS, -sT, masscan, etc.) without
    needing full stateful connection tracking.

Limitations (noted honestly, not hidden):
    - Pure sliding window per source IP; doesn't yet correlate across
      spoofed source IPs or distributed scans from a botnet.
    - No allowlist for known scanners (e.g. your own vuln scanner) yet
      — see TODO.md.
"""

import time
from collections import defaultdict, deque


class PortScanDetector:
    name = "port_scan"

    def __init__(self, notifier, window_seconds: int = 10, unique_port_threshold: int = 15):
        self.notifier = notifier
        self.window_seconds = window_seconds
        self.unique_port_threshold = unique_port_threshold
        # source_ip -> deque[(timestamp, dst_port)]
        self._activity = defaultdict(deque)
        self._already_alerted = set()

    def process_packet(self, src_ip: str, dst_port: int, timestamp: float = None):
        ts = timestamp or time.time()
        window = self._activity[src_ip]
        window.append((ts, dst_port))
        self._evict_old(window, ts)

        distinct_ports = {p for _, p in window}
        if len(distinct_ports) >= self.unique_port_threshold:
            if src_ip not in self._already_alerted:
                self.notifier.fire(
                    detector=self.name,
                    source_ip=src_ip,
                    severity="HIGH",
                    message=(
                        f"{src_ip} touched {len(distinct_ports)} distinct ports "
                        f"in {self.window_seconds}s — likely port scan"
                    ),
                )
                self._already_alerted.add(src_ip)
        else:
            self._already_alerted.discard(src_ip)

    def _evict_old(self, window: deque, now: float):
        cutoff = now - self.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()
