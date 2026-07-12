"""A small multi-port TCP host.

Binds a contiguous block of localhost ports and logs every inbound connection to
the telemetry bus with the port it hit. A port sweep therefore shows up as many
distinct ports touched by one source in a short window — the signal the blue
team's port-scan detector keys on. Uses a single selector loop so N ports cost
one thread, not N.
"""

from __future__ import annotations

import contextlib
import selectors
import socket
import threading

from ..telemetry import TelemetryBus


class MultiPortHost:
    def __init__(self, bus: TelemetryBus, num_ports: int = 16) -> None:
        self._bus = bus
        self._num_ports = num_ports
        self._sel = selectors.DefaultSelector()
        self._listeners: list[socket.socket] = []
        self._ports: list[int] = []
        self._thread: threading.Thread | None = None
        self._running = False

    @property
    def ports(self) -> list[int]:
        return list(self._ports)

    def start(self) -> None:
        for _ in range(self._num_ports):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))  # OS-assigned free port
            s.listen(8)
            s.setblocking(False)
            self._sel.register(s, selectors.EVENT_READ)
            self._listeners.append(s)
            self._ports.append(s.getsockname()[1])
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while self._running:
            for key, _ in self._sel.select(timeout=0.2):
                listener: socket.socket = key.fileobj  # type: ignore[assignment]
                port = listener.getsockname()[1]
                try:
                    conn, addr = listener.accept()
                    self._bus.emit("tcp", addr[0], port=port)
                    conn.close()
                except OSError:
                    continue

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)
        for s in self._listeners:
            with contextlib.suppress(KeyError, ValueError):
                self._sel.unregister(s)
            s.close()
        self._sel.close()
