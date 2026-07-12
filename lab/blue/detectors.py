"""Blue-team detectors.

Each detector inspects telemetry events and emits a typed :class:`Alert` when its
signal fires. Detectors are **scenario-blind** — they see only event features
(paths, payloads, ports, outcomes), never which attack is running. Each emits at
most one alert per source per incident (dedup on ``(type, source)``) so a burst
does not spam the referee.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..telemetry import Event


@dataclass
class Alert:
    type: str
    source: str
    detail: str
    ts: float = field(default_factory=time.time)
    evidence: dict[str, Any] = field(default_factory=dict)


class Detector(ABC):
    type: str = "generic"

    def __init__(self) -> None:
        self._fired: set[tuple[str, str]] = set()

    def _once(self, source: str) -> bool:
        """True the first time this (type, source) fires; suppresses repeats."""
        key = (self.type, source)
        if key in self._fired:
            return False
        self._fired.add(key)
        return True

    @abstractmethod
    def inspect(self, event: Event) -> Alert | None: ...


# --- injection / traversal / ssrf: pattern detectors -----------------------
_SQLI_PATTERNS = [
    "' or ", "\" or ", " or 1=1", "union select", "union all select", "--",
    "; drop", "sleep(", "benchmark(", "information_schema", "' and '1'='1", "waitfor delay",
]


class SQLiDetector(Detector):
    type = "sqli"

    def inspect(self, event: Event) -> Alert | None:
        if event.kind != "http":
            return None
        blob = f"{event.data.get('query', '')} {event.data.get('sql', '')}".lower()
        for pat in _SQLI_PATTERNS:
            if pat in blob and self._once(event.source):
                return Alert(self.type, event.source, f"SQL injection pattern '{pat.strip()}'",
                             evidence={"query": event.data.get("query")})
        return None


_TRAVERSAL_PATTERNS = ["../", "..\\", "..%2f", "%2e%2e", "/etc/passwd", "/etc/shadow", "c:\\windows"]


class PathTraversalDetector(Detector):
    type = "path_traversal"

    def inspect(self, event: Event) -> Alert | None:
        if event.kind != "http":
            return None
        path = str(event.data.get("requested_path", "")).lower()
        for pat in _TRAVERSAL_PATTERNS:
            if pat in path and self._once(event.source):
                return Alert(self.type, event.source, f"path traversal sequence '{pat}'",
                             evidence={"requested_path": event.data.get("requested_path")})
        return None


_SSRF_TARGETS = [
    "127.0.0.1", "localhost", "0.0.0.0", "169.254.169.254", "metadata.google",
    "file://", "gopher://", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
]


class SSRFDetector(Detector):
    type = "ssrf"

    def inspect(self, event: Event) -> Alert | None:
        if event.kind != "http" or event.data.get("endpoint") != "fetch":
            return None
        url = str(event.data.get("url", "")).lower()
        for target in _SSRF_TARGETS:
            if target in url and self._once(event.source):
                return Alert(self.type, event.source, f"SSRF to internal target '{target}'",
                             evidence={"url": event.data.get("url")})
        return None


# --- brute force / port scan: threshold-in-window detectors ----------------
class BruteForceDetector(Detector):
    type = "brute_force"

    def __init__(self, threshold: int = 5, window_s: float = 30.0) -> None:
        super().__init__()
        self._threshold = threshold
        self._window = window_s
        self._fails: dict[str, list[float]] = {}

    def inspect(self, event: Event) -> Alert | None:
        if event.kind != "http" or event.data.get("endpoint") != "login":
            return None
        if event.data.get("outcome") != "fail":
            return None
        times = self._fails.setdefault(event.source, [])
        times.append(event.ts)
        cutoff = event.ts - self._window
        times[:] = [t for t in times if t >= cutoff]
        if len(times) >= self._threshold and self._once(event.source):
            return Alert(self.type, event.source,
                         f"{len(times)} failed logins in {self._window:.0f}s",
                         evidence={"failures": len(times)})
        return None


class PortScanDetector(Detector):
    type = "port_scan"

    def __init__(self, threshold: int = 10, window_s: float = 10.0) -> None:
        super().__init__()
        self._threshold = threshold
        self._window = window_s
        self._ports: dict[str, list[tuple[float, int]]] = {}

    def inspect(self, event: Event) -> Alert | None:
        if event.kind != "tcp":
            return None
        hits = self._ports.setdefault(event.source, [])
        hits.append((event.ts, int(event.data.get("port", 0))))
        cutoff = event.ts - self._window
        hits[:] = [(t, p) for t, p in hits if t >= cutoff]
        distinct = {p for _, p in hits}
        if len(distinct) >= self._threshold and self._once(event.source):
            return Alert(self.type, event.source,
                         f"{len(distinct)} distinct ports in {self._window:.0f}s",
                         evidence={"ports": sorted(distinct)})
        return None


def default_detectors() -> list[Detector]:
    return [
        SQLiDetector(),
        PathTraversalDetector(),
        SSRFDetector(),
        BruteForceDetector(),
        PortScanDetector(),
    ]
