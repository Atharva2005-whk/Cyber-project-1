#!/usr/bin/env python3
"""
dashboard.py — minimal Flask UI over the alerts DB.

STATUS: basic table view works. Chart.js breakdown (alerts over time,
by detector) is stubbed in templates/index.html — see TODO.md #5.

Usage:
    python3 dashboard.py --config config.yaml
    then open http://127.0.0.1:5000
"""

import argparse

import yaml
from flask import Flask, render_template

from db import AlertStore

app = Flask(__name__)
store = None  # set in main()


@app.route("/")
def index():
    alerts = store.recent_alerts(limit=100)
    counts = store.alert_counts_by_detector()
    return render_template("index.html", alerts=alerts, counts=counts)


def main():
    global store
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    store = AlertStore(cfg["logging"]["sqlite_path"])
    app.run(debug=True)


if __name__ == "__main__":
    main()
