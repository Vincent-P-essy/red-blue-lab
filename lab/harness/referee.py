"""The referee: stand up the lab, run each attack, assert detection.

Boots the target (HTTP app + TCP host) and the blue-team engine, then runs each
red scenario and waits up to the detection budget for the expected alert —
recording whether it fired and how long it took.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Any

from werkzeug.serving import make_server

from ..blue.engine import DetectionEngine
from ..red.base import RedContext
from ..red.scenarios import all_scenarios
from ..target.app import create_target
from ..target.tcp_host import MultiPortHost
from ..telemetry import TelemetryBus


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Outcome:
    name: str
    expected_alert: str
    attacks: int
    detected: bool
    latency_s: float | None
    detail: str
    note: str
    evidence: dict[str, Any] = field(default_factory=dict)


class Lab:
    def __init__(self, detection_budget_s: float = 5.0, tcp_ports: int = 16) -> None:
        self.budget = detection_budget_s
        self.bus = TelemetryBus()
        self.engine = DetectionEngine(self.bus)
        self.host = MultiPortHost(self.bus, num_ports=tcp_ports)
        self._app = create_target(self.bus)
        self._port = _free_port()
        self._server = make_server("127.0.0.1", self._port, self._app, threaded=True)
        self._srv_thread = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    def start(self) -> None:
        import threading

        self.host.start()
        self._srv_thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._srv_thread.start()
        self.engine.start()
        self._wait_healthy()

    def _wait_healthy(self, timeout: float = 5.0) -> None:
        import requests

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if requests.get(f"{self.base_url}/healthz", timeout=1).status_code == 200:
                    return
            except requests.RequestException:
                time.sleep(0.1)
        raise RuntimeError("target failed to become healthy")

    def stop(self) -> None:
        self._server.shutdown()
        self.engine.stop()
        self.host.stop()

    def run_all(self) -> list[Outcome]:
        ctx = RedContext(base_url=self.base_url, tcp_ports=self.host.ports)
        outcomes: list[Outcome] = []
        for scenario in all_scenarios():
            outcomes.append(self._run_one(scenario, ctx))
        return outcomes

    def _run_one(self, scenario: Any, ctx: RedContext) -> Outcome:
        start = time.time()
        result = scenario.run(ctx)
        alert = self._await_alert(scenario.expected_alert, scenario.source, start)
        return Outcome(
            name=scenario.name,
            expected_alert=scenario.expected_alert,
            attacks=result.attacks,
            detected=alert is not None,
            latency_s=(alert.ts - start) if alert else None,
            detail=alert.detail if alert else "no alert within budget",
            note=result.note,
            evidence=alert.evidence if alert else {},
        )

    def _await_alert(self, alert_type: str, source: str, start: float):
        deadline = start + self.budget
        while time.time() < deadline:
            alert = self.engine.find(alert_type, source)
            if alert is not None:
                return alert
            time.sleep(0.05)
        return None
