"""CLI runner test — exercises the full main() path and exit code."""

from __future__ import annotations

from pathlib import Path

from lab import runner


def test_runner_full_pass(tmp_path, monkeypatch):
    report = tmp_path / "report.html"
    monkeypatch.setenv("RBL_REPORT_PATH", str(report))
    monkeypatch.setenv("RBL_FAIL_UNDER", "100")
    code = runner.main()
    assert code == 0
    assert report.exists()
    assert (tmp_path / "report.json").exists()
    assert "Coverage" in report.read_text()


def test_runner_fail_under_gate(tmp_path, monkeypatch):
    # An impossible threshold (>100%) forces a non-zero exit even at full coverage.
    monkeypatch.setenv("RBL_REPORT_PATH", str(tmp_path / "r.html"))
    monkeypatch.setenv("RBL_FAIL_UNDER", "101")
    assert runner.main() == 1
    Path(tmp_path / "r.html").unlink(missing_ok=True)
