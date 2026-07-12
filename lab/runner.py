"""CLI entrypoint: run the full lab, print a table, write the report, set exit code.

Exit code is non-zero when detection coverage falls below ``RBL_FAIL_UNDER`` — so
CI fails the build if a change breaks a detector.
"""

from __future__ import annotations

import os
import sys

from .harness.referee import Lab
from .report import summarize, write_reports


def main() -> int:
    # Quiet the target's dev-server request log so the results table stands out.
    import logging

    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    budget = float(os.getenv("RBL_DETECTION_BUDGET_S", "5.0"))
    report_path = os.getenv("RBL_REPORT_PATH", "report.html")
    fail_under = float(os.getenv("RBL_FAIL_UNDER", "100"))

    lab = Lab(detection_budget_s=budget)
    lab.start()
    try:
        outcomes = lab.run_all()
    finally:
        lab.stop()

    summary = summarize(outcomes)
    _print_table(outcomes, summary)
    write_reports(outcomes, report_path)
    print(f"\nReport: {report_path}")

    if summary["coverage_pct"] < fail_under:
        print(f"FAIL: coverage {summary['coverage_pct']}% < required {fail_under}%")
        return 1
    return 0


def _print_table(outcomes, summary) -> None:  # noqa: ANN001
    print(f"{'SCENARIO':<18}{'ATTACKS':<13}{'DETECTED':<11}{'LATENCY':<10}RESULT")
    for o in outcomes:
        latency = f"{o.latency_s:.2f} s" if o.latency_s is not None else "—"
        print(
            f"{o.name:<18}{str(o.attacks) + ' actions':<13}"
            f"{'yes' if o.detected else 'NO':<11}{latency:<10}"
            f"{'PASS' if o.detected else 'FAIL'}"
        )
    ml = summary["median_latency_s"]
    print(
        f"\nDetection coverage: {summary['detected']}/{summary['total']} "
        f"({summary['coverage_pct']}%)"
        + (f"  ·  median latency {ml} s" if ml is not None else "")
    )


if __name__ == "__main__":
    sys.exit(main())
