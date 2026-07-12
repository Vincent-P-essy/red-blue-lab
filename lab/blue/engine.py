"""Streaming detection engine.

Polls the telemetry bus and runs every detector over new events, mimicking a
real-time SIEM. Alerts are timestamped when raised, which is what lets the
referee measure detection latency against the attack's start time.
"""

from __future__ import annotations

import threading
import time

from ..telemetry import TelemetryBus
from .detectors import Alert, Detector, default_detectors


class DetectionEngine:
    def __init__(
        self,
        bus: TelemetryBus,
        detectors: list[Detector] | None = None,
        poll_interval_s: float = 0.1,
    ) -> None:
        self._bus = bus
        self._detectors = detectors or default_detectors()
        self._interval = poll_interval_s
        self._cursor = 0
        self._alerts: list[Alert] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._running = False

    def poll_once(self) -> list[Alert]:
        """Process all new events; return any alerts raised this pass."""
        events, self._cursor = self._bus.since(self._cursor)
        raised: list[Alert] = []
        for event in events:
            for detector in self._detectors:
                alert = detector.inspect(event)
                if alert is not None:
                    raised.append(alert)
        if raised:
            with self._lock:
                self._alerts.extend(raised)
        return raised

    def alerts(self) -> list[Alert]:
        with self._lock:
            return list(self._alerts)

    def find(self, alert_type: str, source: str) -> Alert | None:
        with self._lock:
            return next(
                (a for a in self._alerts if a.type == alert_type and a.source == source), None
            )

    # -- background operation ---------------------------------------------
    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while self._running:
            self.poll_once()
            time.sleep(self._interval)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        self.poll_once()  # final drain
