# TODO

Roughly in the order I plan to tackle them.

1. [ ] **Allowlist for port scan detector** — exclude known scanners
   (e.g. my own vuln scanner box) from triggering alerts on themselves.
2. [ ] **Async webhook delivery** — `notifier.py` currently calls
   `requests.post` synchronously, which will stall packet processing
   if the webhook endpoint is slow. Move to a background queue/thread.
3. [ ] **ARP spoof detector** (`detectors/arp_spoof.py`)
   - Build `{ip: mac}` table from observed ARP replies
   - Alert on IP→MAC remapping without corresponding DHCP lease change
   - Alert on gratuitous ARP bursts
   - Needs a test plan: capture a real `arpspoof`/`ettercap` session on
     a lab VM pair to validate against real traffic, not just synthetic data
4. [ ] **Wire up DNS tunnel detector** (`detectors/dns_tunnel.py`)
   - `shannon_entropy()` and `should_flag()` are done + tested
   - Need to pull `DNSQR` layer out of packets in `sniffer.py` and call
     `process_dns_query()` per query
   - Validate against a real `iodine` or `dnscat2` test session before
     enabling by default
5. [ ] **Dashboard charts** — alerts-over-time and alerts-by-detector
   using Chart.js, replacing the placeholder box in `templates/index.html`
6. [ ] **Dockerfile** — package sniffer + dashboard for easier demo/deploy
7. [ ] Write up a short writeup/blog post with a demo GIF for the README
