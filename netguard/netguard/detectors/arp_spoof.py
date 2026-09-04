"""
arp_spoof.py — STATUS: NOT IMPLEMENTED YET (tracked in TODO.md #3)

Plan:
    Maintain a table of {ip: mac} learned from ARP replies. When an
    IP that we've already learned suddenly maps to a *different* MAC
    without a corresponding DHCP/network change, fire a MEDIUM alert
    (could be legit — e.g. NIC swap, VM migration — hence not HIGH).
    Also flag unsolicited "gratuitous ARP" bursts, which is the classic
    ettercap/arpspoof signature.

Why it's stubbed:
    Wanted port scan + SYN flood detection solid and tested first
    before adding a detector that touches L2 and is more prone to
    false positives on networks with DHCP churn or load balancers.
"""

from scapy.all import ARP


class ArpSpoofDetector:
    name = "arp_spoof"

    def __init__(self, notifier):
        self.notifier = notifier
        self.ip_to_mac = {}
        raise NotImplementedError(
            "ArpSpoofDetector is a work in progress — see TODO.md. "
            "Set arp_spoof_detector.enabled: false in config.yaml until this lands."
        )

    def process_arp(self, pkt):
        # TODO: implement mismatch detection + gratuitous ARP burst detection
        pass
