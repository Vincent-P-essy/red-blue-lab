# Red/Blue Lab

**A security regression harness that launches real attacks against a live target and
asserts that detection fires** — SQL injection, brute force, port scan, path
traversal and SSRF, each with a hard "detected within N seconds" gate and an HTML
coverage report. Runs on every push via GitHub Actions.

[![Security Regression](https://github.com/Vincent-P-essy/red-blue-lab/actions/workflows/security-regression.yml/badge.svg)](https://github.com/Vincent-P-essy/red-blue-lab/actions/workflows/security-regression.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Why this is different

Most detection projects stop at a unit test with a mocked event. This one closes
the loop: it stands up a **deliberately vulnerable app**, runs a **red team** of
real attacks against it over HTTP and TCP, feeds the target's telemetry to a
**blue team** streaming detection engine, and then a **referee** asserts —
attack by attack — that the right alert fired within the time budget. A missed
detection fails the build. That's a *security regression test*: it proves your
detections still work every time the code changes, the way real Red/Blue teams
validate coverage.

```
red team ──attacks──▶  vulnerable target  ──telemetry──▶  blue detection engine
                                                                   │ alerts
                                                                   ▼
                                        referee: was each attack detected in ≤ N s?
                                                                   │
                                                          PASS / FAIL + HTML report
```

---

## The five scenarios

| Scenario | Attack | Blue-team signal | Gate |
|---|---|---|---|
| **SQL injection** | `sqlmap`-style payloads on `/search` | injection patterns in query/body | ≤ 5 s |
| **Brute force** | credential spray against `/login` | N failed logins from one source | ≤ 5 s |
| **Port scan** | TCP sweep across the target's ports | many distinct ports from one source | ≤ 5 s |
| **Path traversal** | `../../etc/passwd` on `/files` | traversal sequences in the path | ≤ 5 s |
| **SSRF** | fetch `http://169.254.169.254/…` via `/fetch?url=` | internal/loopback URL in a request param | ≤ 5 s |

The detectors work purely on telemetry features — they are **not** told which
scenario is running. The referee maps each attack to its expected alert type and
measures detection latency independently.

---

## Quick start

```bash
git clone https://github.com/Vincent-P-essy/red-blue-lab
cd red-blue-lab
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m lab.runner          # runs all scenarios, prints a table, writes report.html
```

Example output:

```
SCENARIO           ATTACK          DETECTED   LATENCY   RESULT
sql_injection      12 payloads     yes        0.31 s    PASS
brute_force        20 attempts     yes        0.44 s    PASS
port_scan          24 ports        yes        0.28 s    PASS
path_traversal     8 payloads      yes        0.30 s    PASS
ssrf               6 payloads      yes        0.33 s    PASS

Detection coverage: 5/5 (100%)  ·  median latency 0.31 s
Report: report.html
```

Open `report.html` for the full breakdown (per-scenario timeline, the exact
alert that fired, and coverage over the run).

### Docker

```bash
docker compose up --build     # runs the harness in a container, exits non-zero on any miss
```

---

## Architecture

```
lab/target/   deliberately vulnerable Flask app + a small multi-port TCP host,
              both emitting structured events to a shared telemetry bus
lab/blue/     streaming detection engine: five feature-based detectors polling
              the bus and emitting typed alerts with timestamps
lab/red/      five attack scenarios behind one Scenario interface
lab/harness/  the referee: start blue, run each red scenario, wait for the
              expected alert within the budget, record latency
lab/report    HTML + JSON coverage report
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how telemetry flows, why
detectors are scenario-blind, and how detection latency is measured.

---

## CI: security regression on every push

`.github/workflows/security-regression.yml` runs the full harness and fails the
build if coverage drops below 100% — so a change that breaks a detector is caught
in the pull request, not in production. The HTML report is uploaded as a build
artifact.

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `RBL_DETECTION_BUDGET_S` | `5.0` | Max seconds an attack may go undetected before it FAILs |
| `RBL_REPORT_PATH` | `report.html` | Where to write the HTML report |
| `RBL_FAIL_UNDER` | `100` | Minimum coverage % for a zero exit code |

---

## License

MIT © Vincent Plessy
