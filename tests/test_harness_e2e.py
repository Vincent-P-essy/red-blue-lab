"""End-to-end: the full lab must detect every attack.

This is the security-regression test itself — real attacks against a live target,
asserted against real detections. If a detector regresses, this fails.
"""

from __future__ import annotations

import logging

import pytest

from lab.harness.referee import Lab
from lab.report import render_html, summarize, to_json


@pytest.fixture(scope="module")
def outcomes():
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    lab = Lab(detection_budget_s=5.0)
    lab.start()
    try:
        yield lab.run_all()
    finally:
        lab.stop()


def test_full_coverage(outcomes):
    assert all(o.detected for o in outcomes), [
        (o.name, o.detail) for o in outcomes if not o.detected
    ]
    assert {o.name for o in outcomes} == {
        "sql_injection", "brute_force", "port_scan", "path_traversal", "ssrf"
    }


def test_detection_is_fast(outcomes):
    for o in outcomes:
        assert o.latency_s is not None and o.latency_s < 5.0


def test_each_attack_actually_ran(outcomes):
    for o in outcomes:
        assert o.attacks > 0


def test_summary_and_report(outcomes):
    s = summarize(outcomes)
    assert s["coverage_pct"] == 100.0
    assert s["detected"] == 5
    html = render_html(outcomes)
    assert "Detection coverage" in html or "Coverage" in html
    payload = to_json(outcomes)
    assert len(payload["scenarios"]) == 5
