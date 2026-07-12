# Architecture & Design Notes

## 1. What this proves that a unit test can't

A unit test that feeds a mocked event to a detector proves the detector matches a
string. It does **not** prove that the target actually emits that telemetry, that
the emission survives the real request path, or that detection happens fast
enough to matter. This harness proves all three by running the attack for real
against a live target and asserting on the resulting detection — the same thing a
Red/Blue team does when validating coverage, automated so it runs on every push.

## 2. The telemetry seam

The one connection between offence and defence is the `TelemetryBus`. The target
(HTTP app + TCP host) *emits* structured events; the blue engine *consumes* them.
Crucially, that is the **only** channel — detectors never receive the scenario
name, the expected outcome, or anything the target didn't actually observe. This
keeps the test honest: a detector can only fire on signal that a real deployment
would also have.

```
red attack ─▶ target ─(emit)▶ TelemetryBus ─(poll)▶ blue engine ─▶ Alert
                                                                     │
                              referee ◀────────────────────────────┘
                              (matches Alert.type + Alert.source to the scenario)
```

## 3. Scenario-blind detectors

Each detector keys on event features only:

- **SQLi / path traversal / SSRF** — payload/pattern detectors that fire on the
  first malicious request (injection tokens, `../` sequences, internal-target
  URLs). Immediate, because a single request is already the attack.
- **Brute force / port scan** — threshold-in-window detectors that need a *rate*
  of activity from one source (N failed logins; N distinct ports) before firing,
  the way a real correlation rule does. This is what stops a single failed login
  or one connection from tripping an alert.

Each detector emits at most one alert per `(type, source)` so a burst produces one
incident, not a hundred alerts — and, because every scenario uses a distinct
source identity, incidents never bleed across scenarios.

## 4. Measuring detection latency

The referee records wall-clock time immediately before launching each attack. The
blue engine timestamps every alert at the moment it is raised (it runs as a
background poll loop, like a streaming SIEM). Detection latency is
`alert.ts - attack_start`, and a scenario FAILs if no matching alert appears
within `RBL_DETECTION_BUDGET_S`. This turns "is it detected?" into "is it detected
*in time?*" — the metric that actually matters operationally.

## 5. The port-scan model

A single HTTP app has no ports to scan, so the target includes a small
multi-port TCP host that binds a block of localhost ports through one `selectors`
loop (N ports, one thread) and logs every inbound connection. A sweep therefore
appears as many distinct ports touched by one source in a short window — a real
port-scan signal, fully self-contained, with no external network or root needed.

## 6. Failure is the point

The runner exits non-zero when coverage drops below `RBL_FAIL_UNDER` (default
100%). Wired into CI, that means **a change which breaks a detector fails the pull
request**. The Docker image is the same gate in a box: `docker run` the container
and its exit code is your detection verdict. The HTML report is uploaded as a CI
artifact so a human can see exactly which attack slipped through and why.

## 7. Extending it

Add a scenario by implementing `Scenario` (declare the attack, its expected alert
type and source) and add a detector implementing `Detector`. The referee, report
and CI pick them up automatically — the coverage gate then holds the new
detection to the same standard as the rest.
