import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detectors.port_scan import PortScanDetector


class FakeNotifier:
    def __init__(self):
        self.calls = []

    def fire(self, **kwargs):
        self.calls.append(kwargs)


def test_no_alert_below_threshold():
    notifier = FakeNotifier()
    detector = PortScanDetector(notifier, window_seconds=10, unique_port_threshold=5)

    for port in range(1, 4):  # 3 distinct ports, threshold is 5
        detector.process_packet("10.0.0.5", port, timestamp=1000.0)

    assert len(notifier.calls) == 0


def test_alert_fires_at_threshold():
    notifier = FakeNotifier()
    detector = PortScanDetector(notifier, window_seconds=10, unique_port_threshold=5)

    for port in range(1, 7):  # 6 distinct ports, threshold is 5
        detector.process_packet("10.0.0.5", port, timestamp=1000.0)

    assert len(notifier.calls) == 1
    assert notifier.calls[0]["source_ip"] == "10.0.0.5"
    assert notifier.calls[0]["severity"] == "HIGH"


def test_alert_fires_once_not_repeatedly():
    notifier = FakeNotifier()
    detector = PortScanDetector(notifier, window_seconds=10, unique_port_threshold=3)

    for port in range(1, 10):
        detector.process_packet("10.0.0.5", port, timestamp=1000.0)

    # should only fire once while staying above threshold
    assert len(notifier.calls) == 1


def test_old_activity_evicted_outside_window():
    notifier = FakeNotifier()
    detector = PortScanDetector(notifier, window_seconds=5, unique_port_threshold=3)

    detector.process_packet("10.0.0.5", 1, timestamp=1000.0)
    detector.process_packet("10.0.0.5", 2, timestamp=1001.0)
    # jump forward past the window — old entries should be evicted
    detector.process_packet("10.0.0.5", 3, timestamp=1010.0)

    assert len(notifier.calls) == 0
