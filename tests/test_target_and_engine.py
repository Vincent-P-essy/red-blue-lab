"""Target-app telemetry and engine integration."""

from __future__ import annotations

from lab.blue.engine import DetectionEngine
from lab.target.app import create_target
from lab.telemetry import TelemetryBus


def test_login_failure_emits_fail_event():
    bus = TelemetryBus()
    client = create_target(bus).test_client()
    client.post("/login", data={"username": "admin", "password": "wrong"},
                headers={"X-Actor": "1.2.3.4"})
    ev = bus.all()[-1]
    assert ev.data["endpoint"] == "login"
    assert ev.data["outcome"] == "fail"
    assert ev.source == "1.2.3.4"


def test_login_success():
    bus = TelemetryBus()
    client = create_target(bus).test_client()
    r = client.post("/login", data={"username": "admin", "password": "s3cr3t"})
    assert r.status_code == 200
    assert bus.all()[-1].data["outcome"] == "success"


def test_search_records_query():
    bus = TelemetryBus()
    client = create_target(bus).test_client()
    client.get("/search?q=laptop")
    assert bus.all()[-1].data["query"] == "laptop"


def test_engine_raises_alert_for_attack_telemetry():
    bus = TelemetryBus()
    client = create_target(bus).test_client()
    engine = DetectionEngine(bus)
    client.get("/search?q=' OR 1=1--", headers={"X-Actor": "9.9.9.9"})
    raised = engine.poll_once()
    assert any(a.type == "sqli" and a.source == "9.9.9.9" for a in raised)
    assert engine.find("sqli", "9.9.9.9") is not None


def test_engine_find_missing_returns_none():
    engine = DetectionEngine(TelemetryBus())
    assert engine.find("sqli", "nobody") is None
