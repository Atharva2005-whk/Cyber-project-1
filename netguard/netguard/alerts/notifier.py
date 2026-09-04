"""
notifier.py — fan out alerts to console + optional webhook + sqlite.

Kept deliberately small. If you want email/Slack/Discord/PagerDuty,
add a method here rather than scattering notification logic through
the detectors.
"""

from rich.console import Console
from rich.text import Text
import requests

console = Console()

SEVERITY_STYLES = {
    "LOW": "cyan",
    "MEDIUM": "yellow",
    "HIGH": "bold red",
}


class Notifier:
    def __init__(self, alert_store, webhook_url: str = ""):
        self.alert_store = alert_store
        self.webhook_url = webhook_url.strip()

    def fire(self, detector: str, source_ip: str, severity: str, message: str):
        # 1. persist
        self.alert_store.add_alert(detector, source_ip, severity, message)

        # 2. console
        style = SEVERITY_STYLES.get(severity, "white")
        text = Text(f"[{severity}] {detector} — {message} (src={source_ip})", style=style)
        console.print(text)

        # 3. webhook (best-effort, non-blocking would be nicer — see TODO.md)
        if self.webhook_url:
            self._send_webhook(detector, source_ip, severity, message)

    def _send_webhook(self, detector, source_ip, severity, message):
        payload = {"text": f"*[{severity}] {detector}*\n{message}\nsrc: {source_ip}"}
        try:
            requests.post(self.webhook_url, json=payload, timeout=3)
        except requests.RequestException as e:
            console.print(f"[dim]webhook delivery failed: {e}[/dim]")
