"""Tests for the multi-port TCP host."""

from __future__ import annotations

import socket
import time

from lab.target.tcp_host import MultiPortHost
from lab.telemetry import TelemetryBus


def test_host_binds_requested_number_of_ports():
    bus = TelemetryBus()
    host = MultiPortHost(bus, num_ports=8)
    host.start()
    try:
        assert len(host.ports) == 8
        assert all(isinstance(p, int) for p in host.ports)
    finally:
        host.stop()


def test_connection_emits_tcp_event():
    bus = TelemetryBus()
    host = MultiPortHost(bus, num_ports=4)
    host.start()
    try:
        for port in host.ports:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                pass
        # Give the selector loop a moment to log the connections.
        deadline = time.time() + 2
        while time.time() < deadline and len(bus.all()) < 4:
            time.sleep(0.05)
        tcp_events = [e for e in bus.all() if e.kind == "tcp"]
        assert len(tcp_events) == 4
        assert {e.data["port"] for e in tcp_events} == set(host.ports)
    finally:
        host.stop()
