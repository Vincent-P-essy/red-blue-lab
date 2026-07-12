"""Shared telemetry bus.

Both target surfaces (the vulnerable HTTP app and the multi-port TCP host) append
structured events here; the blue-team engine polls it. This is the single seam
between "what the target observed" and "what the defenders see" — detectors never
receive anything the target didn't actually emit.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Event:
    kind: str  # "http" | "tcp"
    source: str  # actor identity (src ip / id), grouped on by detectors
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


class TelemetryBus:
    """Thread-safe append-only event log with cursor-based reads."""

    def __init__(self) -> None:
        self._events: list[Event] = []
        self._lock = threading.Lock()

    def emit(self, kind: str, source: str, **data: Any) -> None:
        with self._lock:
            self._events.append(Event(kind=kind, source=source, data=data))

    def since(self, cursor: int) -> tuple[list[Event], int]:
        """Return events added since ``cursor`` and the new cursor."""
        with self._lock:
            new = self._events[cursor:]
            return list(new), len(self._events)

    def all(self) -> list[Event]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
