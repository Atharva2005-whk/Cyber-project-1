# NetGuard 🛡️

A lightweight network intrusion detection toolkit written in Python. Sniffs
live traffic, flags suspicious activity (port scans, SYN floods, and soon
ARP spoofing / DNS tunneling), logs alerts to SQLite, and surfaces them
through a small web dashboard.

> **Status: actively in progress.** Core detection engine and tests are
> working; a couple of detectors and the dashboard's charting are still
> being built. See [TODO.md](TODO.md) for exactly what's left.

## Why I built this

I wanted a project that goes beyond "run nmap and call it a day" — something
that actually processes live packets, makes a detection decision with a
documented, testable algorithm, and reports on it like a real tool would.

## What's working right now

- ✅ Live packet capture via `scapy`
- ✅ **Port scan detection** — sliding-window, per-source-IP distinct-port
  tracking ([`detectors/port_scan.py`](detectors/port_scan.py))
- ✅ **SYN flood detection** — sliding-window SYN rate tracking
  ([`detectors/syn_flood.py`](detectors/syn_flood.py))
- ✅ Alert persistence to SQLite + console output + optional webhook
- ✅ Basic Flask dashboard showing the live alert feed
- ✅ Unit tests for both finished detectors (`pytest tests/`)

## What's still in progress

- 🚧 **ARP spoof detection** — designed, not implemented (`detectors/arp_spoof.py`)
- 🚧 **DNS tunneling detection** — entropy-based scoring logic is done and
  tested, but not yet wired into the live sniffer (`detectors/dns_tunnel.py`)
- 🚧 **Dashboard charts** — alerts-over-time / by-detector graphs (currently
  just a table)

See [TODO.md](TODO.md) for the full breakdown and reasoning behind what's
sequenced where.

## Architecture

```
sniffer.py          → captures packets, feeds them to enabled detectors
detectors/           → one file per detection technique, each independently testable
alerts/notifier.py  → fan-out: console + sqlite + optional webhook
db.py               → SQLite persistence layer
dashboard.py         → Flask app reading from the same SQLite DB
config.yaml          → all thresholds/toggles live here, not hardcoded
```

## Setup

```bash
git clone <this-repo>
cd netguard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Edit `config.yaml` — set `interface` to your network interface (`ip a` on Linux).

## Usage

Run the sniffer (requires root/raw-socket privileges):

```bash
sudo python3 sniffer.py --config config.yaml
```

In a separate terminal, run the dashboard:

```bash
python3 dashboard.py --config config.yaml
# open http://127.0.0.1:5000
```

Run the test suite:

```bash
pytest tests/ -v
```

## ⚠️ Responsible use

Only run this against network interfaces and traffic you own or have
explicit permission to monitor. This is a defensive/educational tool, not
built for scanning networks that aren't yours.

## License

MIT
