"""
dns_tunnel.py — STATUS: IN PROGRESS (tracked in TODO.md #4)

DNS tunneling (e.g. iodine, dnscat2) typically shows up as:
    - Abnormally long subdomain labels / query names
    - High Shannon entropy in the queried name (base32/64-ish payloads)
    - High query volume to a single, unusual domain

`shannon_entropy()` below is done and unit-tested (see tests/).
The actual packet-level hook into the sniffer is not wired up yet —
next step is pulling DNS query names out of scapy's DNSQR layer in
sniffer.py and calling should_flag() per query.
"""

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    """Return the Shannon entropy (bits/char) of a string. Higher = more random-looking."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class DnsTunnelDetector:
    name = "dns_tunnel"

    def __init__(self, notifier, max_query_length: int = 60, entropy_threshold: float = 3.5):
        self.notifier = notifier
        self.max_query_length = max_query_length
        self.entropy_threshold = entropy_threshold

    def should_flag(self, query_name: str) -> bool:
        """Pure logic, easy to unit test. Not yet called from the live sniffer."""
        if len(query_name) >= self.max_query_length:
            return True
        if shannon_entropy(query_name) >= self.entropy_threshold:
            return True
        return False

    def process_dns_query(self, src_ip: str, query_name: str):
        # TODO: wire this into sniffer.py's DNS packet handler once
        # should_flag() has been validated against a real capture of
        # both normal traffic and an iodine/dnscat2 test session.
        raise NotImplementedError("DNS tunnel live detection not wired up yet — see TODO.md")
