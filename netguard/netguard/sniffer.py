#!/usr/bin/env python3
"""
sniffer.py — NetGuard entry point.

Sniffs live traffic on the configured interface and feeds packets to
whichever detectors are enabled in config.yaml. Requires root / raw
socket privileges (or CAP_NET_RAW on Linux) to sniff.

Usage:
    sudo python3 sniffer.py [--config config.yaml]

Only run this against network interfaces you own or have explicit
permission to monitor.
"""

import argparse
import sys

import yaml
from scapy.all import sniff, IP, TCP

from db import AlertStore
from alerts.notifier import Notifier
from detectors.port_scan import PortScanDetector
from detectors.syn_flood import SynFloodDetector

# arp_spoof and dns_tunnel are intentionally not imported into the live
# pipeline yet — see detectors/arp_spoof.py and detectors/dns_tunnel.py


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def build_detectors(cfg: dict, notifier: Notifier) -> list:
    detectors = []

    ps_cfg = cfg.get("port_scan_detector", {})
    if ps_cfg.get("enabled"):
        detectors.append(
            PortScanDetector(
                notifier,
                window_seconds=ps_cfg.get("window_seconds", 10),
                unique_port_threshold=ps_cfg.get("unique_port_threshold", 15),
            )
        )

    sf_cfg = cfg.get("syn_flood_detector", {})
    if sf_cfg.get("enabled"):
        detectors.append(
            SynFloodDetector(
                notifier,
                window_seconds=sf_cfg.get("window_seconds", 5),
                syn_threshold=sf_cfg.get("syn_threshold", 100),
            )
        )

    if cfg.get("arp_spoof_detector", {}).get("enabled"):
        print("WARNING: arp_spoof_detector is enabled in config but not implemented yet. "
              "Ignoring — see detectors/arp_spoof.py", file=sys.stderr)

    if cfg.get("dns_tunnel_detector", {}).get("enabled"):
        print("WARNING: dns_tunnel_detector is enabled in config but not wired up yet. "
              "Ignoring — see detectors/dns_tunnel.py", file=sys.stderr)

    return detectors


def make_packet_handler(port_scan_detector, syn_flood_detector):
    def handle(pkt):
        if IP not in pkt:
            return
        src_ip = pkt[IP].src

        if TCP in pkt:
            dst_port = pkt[TCP].dport
            flags = pkt[TCP].flags

            if port_scan_detector:
                port_scan_detector.process_packet(src_ip, dst_port)

            # SYN set, ACK not set == connection attempt
            if syn_flood_detector and flags & 0x02 and not flags & 0x10:
                syn_flood_detector.process_syn(src_ip)

    return handle


def main():
    parser = argparse.ArgumentParser(description="NetGuard live traffic monitor")
    parser.add_argument("--config", default="config.yaml", help="path to config.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)

    store = AlertStore(cfg["logging"]["sqlite_path"])
    notifier = Notifier(store, webhook_url=cfg.get("alerting", {}).get("webhook_url", ""))

    detectors = build_detectors(cfg, notifier)
    port_scan_detector = next((d for d in detectors if d.name == "port_scan"), None)
    syn_flood_detector = next((d for d in detectors if d.name == "syn_flood"), None)

    iface = cfg.get("interface", "eth0")
    print(f"[NetGuard] Sniffing on {iface}. Ctrl+C to stop.")
    print(f"[NetGuard] Active detectors: {[d.name for d in detectors]}")

    sniff(
        iface=iface,
        prn=make_packet_handler(port_scan_detector, syn_flood_detector),
        store=False,
    )


if __name__ == "__main__":
    main()
