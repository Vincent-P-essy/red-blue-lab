"""Unit tests for the blue-team detectors."""

from __future__ import annotations

from lab.blue.detectors import (
    BruteForceDetector,
    PathTraversalDetector,
    PortScanDetector,
    SQLiDetector,
    SSRFDetector,
)
from lab.telemetry import Event


def _http(source="a", **data):
    return Event(kind="http", source=source, data=data)


def test_sqli_detector_fires_on_payload():
    d = SQLiDetector()
    assert d.inspect(_http(endpoint="search", query="' OR 1=1--", sql="...")) is not None


def test_sqli_detector_ignores_benign_query():
    d = SQLiDetector()
    assert d.inspect(_http(endpoint="search", query="laptop", sql="SELECT * ... 'laptop'")) is None


def test_sqli_detector_dedups_per_source():
    d = SQLiDetector()
    assert d.inspect(_http(query="' OR 1=1--")) is not None
    assert d.inspect(_http(query="union select 1")) is None  # same source, suppressed


def test_path_traversal_detector():
    d = PathTraversalDetector()
    assert d.inspect(_http(requested_path="../../etc/passwd")) is not None
    assert d.inspect(_http(source="b", requested_path="report.pdf")) is None


def test_ssrf_detector_only_on_fetch():
    d = SSRFDetector()
    assert d.inspect(_http(endpoint="fetch", url="http://169.254.169.254/")) is not None
    # internal URL but not the fetch endpoint -> ignored
    assert d.inspect(_http(source="b", endpoint="search", url="http://127.0.0.1")) is None
    # public URL on fetch -> ignored
    assert d.inspect(_http(source="c", endpoint="fetch", url="https://example.com")) is None


def test_brute_force_needs_threshold_failures():
    d = BruteForceDetector(threshold=5, window_s=30)
    alerts = [d.inspect(_http(endpoint="login", outcome="fail")) for _ in range(5)]
    assert alerts[:4] == [None, None, None, None]
    assert alerts[4] is not None


def test_brute_force_ignores_successful_logins():
    d = BruteForceDetector(threshold=3)
    for _ in range(5):
        assert d.inspect(_http(endpoint="login", outcome="success")) is None


def test_port_scan_needs_distinct_ports():
    d = PortScanDetector(threshold=10, window_s=10)
    # 9 distinct ports: no alert yet.
    for p in range(9):
        assert d.inspect(Event(kind="tcp", source="s", data={"port": 1000 + p})) is None
    # 10th distinct port trips it.
    assert d.inspect(Event(kind="tcp", source="s", data={"port": 2000})) is not None


def test_port_scan_ignores_repeated_same_port():
    d = PortScanDetector(threshold=3)
    for _ in range(10):
        assert d.inspect(Event(kind="tcp", source="s", data={"port": 80})) is None
