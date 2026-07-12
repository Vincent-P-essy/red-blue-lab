"""Coverage report — JSON summary and a standalone HTML page."""

from __future__ import annotations

import json
import statistics
from typing import Any

from .harness.referee import Outcome


def summarize(outcomes: list[Outcome]) -> dict[str, Any]:
    total = len(outcomes)
    detected = sum(1 for o in outcomes if o.detected)
    latencies = [o.latency_s for o in outcomes if o.latency_s is not None]
    return {
        "total": total,
        "detected": detected,
        "coverage_pct": round(100 * detected / total, 1) if total else 0.0,
        "median_latency_s": round(statistics.median(latencies), 3) if latencies else None,
        "max_latency_s": round(max(latencies), 3) if latencies else None,
    }


def to_json(outcomes: list[Outcome]) -> dict[str, Any]:
    return {
        "summary": summarize(outcomes),
        "scenarios": [
            {
                "name": o.name,
                "expected_alert": o.expected_alert,
                "attacks": o.attacks,
                "detected": o.detected,
                "latency_s": o.latency_s,
                "detail": o.detail,
                "note": o.note,
                "evidence": o.evidence,
            }
            for o in outcomes
        ],
    }


def render_html(outcomes: list[Outcome]) -> str:
    s = summarize(outcomes)
    bar_color = "#22c55e" if s["coverage_pct"] == 100 else ("#f59e0b" if s["coverage_pct"] >= 60 else "#ef4444")
    rows = []
    for o in outcomes:
        result = "PASS" if o.detected else "FAIL"
        rcolor = "#22c55e" if o.detected else "#ef4444"
        latency = f"{o.latency_s:.3f} s" if o.latency_s is not None else "—"
        rows.append(f"""
      <tr>
        <td class="mono">{o.name}</td>
        <td>{o.attacks}</td>
        <td class="mono">{o.expected_alert}</td>
        <td>{latency}</td>
        <td class="detail">{_esc(o.detail)}</td>
        <td><span class="pill" style="background:{rcolor}">{result}</span></td>
      </tr>""")
    ml = s["median_latency_s"]
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Red/Blue Lab — Detection Coverage</title>
<style>
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:#0b0f17; color:#e6edf3; margin:0; padding:32px; }}
  h1 {{ margin:0 0 4px; letter-spacing:-.5px; }}
  .sub {{ color:#8b98a9; margin-bottom:24px; }}
  .cards {{ display:flex; gap:16px; margin-bottom:24px; flex-wrap:wrap; }}
  .card {{ background:#131a26; border:1px solid #263145; border-radius:12px; padding:16px 20px; min-width:150px; }}
  .card .k {{ color:#8b98a9; font-size:12px; text-transform:uppercase; letter-spacing:.5px; }}
  .card .v {{ font-size:28px; font-weight:700; margin-top:4px; }}
  .bar {{ height:10px; background:#263145; border-radius:999px; overflow:hidden; margin-top:10px; }}
  .bar > span {{ display:block; height:100%; width:{s['coverage_pct']}%; background:{bar_color}; }}
  table {{ width:100%; border-collapse:collapse; background:#131a26; border:1px solid #263145; border-radius:12px; overflow:hidden; }}
  th, td {{ text-align:left; padding:12px 14px; border-bottom:1px solid #263145; font-size:14px; }}
  th {{ color:#8b98a9; font-size:12px; text-transform:uppercase; letter-spacing:.5px; }}
  .mono {{ font-family: ui-monospace, Menlo, monospace; color:#38bdf8; }}
  .detail {{ color:#8b98a9; }}
  .pill {{ color:#06121c; font-weight:700; padding:2px 10px; border-radius:999px; font-size:12px; }}
</style></head>
<body>
  <h1>Red/Blue Lab</h1>
  <div class="sub">Detection coverage — real attacks vs. real detections</div>
  <div class="cards">
    <div class="card"><div class="k">Coverage</div><div class="v">{s['coverage_pct']}%</div>
      <div class="bar"><span></span></div></div>
    <div class="card"><div class="k">Detected</div><div class="v">{s['detected']}/{s['total']}</div></div>
    <div class="card"><div class="k">Median latency</div><div class="v">{ml if ml is not None else '—'}{' s' if ml is not None else ''}</div></div>
  </div>
  <table>
    <thead><tr><th>Scenario</th><th>Attacks</th><th>Alert</th><th>Latency</th><th>Detail</th><th>Result</th></tr></thead>
    <tbody>{''.join(rows)}
    </tbody>
  </table>
</body></html>"""


def _esc(s: str) -> str:
    return (
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def write_reports(outcomes: list[Outcome], html_path: str) -> None:
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(render_html(outcomes))
    json_path = html_path.rsplit(".", 1)[0] + ".json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(to_json(outcomes), fh, indent=2)
