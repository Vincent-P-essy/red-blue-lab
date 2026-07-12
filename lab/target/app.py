"""Deliberately vulnerable target application (the blue team's crown jewels).

Every request emits a structured telemetry event to the shared bus. The
vulnerabilities are intentional — this app exists to be attacked so the detection
engine can be proven against real exploitation. Do not deploy it.

Actor identity is taken from the ``X-Actor`` header (set by the red team to a
source ip) so detectors can group activity by source, falling back to the peer
address as a real deployment would.
"""

from __future__ import annotations

from flask import Flask, request

from ..telemetry import TelemetryBus

_VALID = {"admin": "s3cr3t"}


def create_target(bus: TelemetryBus) -> Flask:
    app = Flask(__name__)

    def actor() -> str:
        return request.headers.get("X-Actor") or request.remote_addr or "unknown"

    @app.get("/healthz")
    def healthz() -> tuple[str, int]:
        return "ok", 200

    @app.post("/login")
    def login() -> tuple[str, int]:
        # VULNERABLE: no lockout, no rate limit, verbose failure.
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ok = _VALID.get(username) == password
        status = 200 if ok else 401
        bus.emit(
            "http",
            actor(),
            endpoint="login",
            method="POST",
            path="/login",
            status=status,
            outcome="success" if ok else "fail",
            username=username,
        )
        return ("welcome" if ok else "invalid credentials"), status

    @app.get("/search")
    def search() -> tuple[str, int]:
        # VULNERABLE: query concatenated into SQL with no parameterisation.
        q = request.args.get("q", "")
        fake_sql = f"SELECT * FROM products WHERE name = '{q}'"
        bus.emit(
            "http",
            actor(),
            endpoint="search",
            method="GET",
            path="/search",
            status=200,
            query=q,
            sql=fake_sql,
        )
        return f"results for {q}", 200

    @app.get("/files")
    def files() -> tuple[str, int]:
        # VULNERABLE: path used to read a file with no normalisation.
        path = request.args.get("path", "")
        bus.emit(
            "http",
            actor(),
            endpoint="files",
            method="GET",
            path="/files",
            status=200,
            requested_path=path,
        )
        return f"contents of {path}", 200

    @app.get("/fetch")
    def fetch() -> tuple[str, int]:
        # VULNERABLE: fetches an attacker-controlled URL (SSRF).
        url = request.args.get("url", "")
        bus.emit(
            "http",
            actor(),
            endpoint="fetch",
            method="GET",
            path="/fetch",
            status=200,
            url=url,
        )
        return f"fetched {url}", 200

    @app.errorhandler(404)
    def not_found(_e: object) -> tuple[str, int]:
        bus.emit(
            "http",
            actor(),
            endpoint="unknown",
            method=request.method,
            path=request.path,
            status=404,
        )
        return "not found", 404

    return app
