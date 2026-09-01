# Role P5 — Drift Monitor + Simulated Response

## Project context

We're building a prototype of ULPF — a system that ingests security logs
from perimeter devices in many vendor formats and normalizes them into a
common schema (OCSF). Once a parsing rule is deployed, it can silently
break over time — e.g. a vendor firmware update reorders fields, and the
rule keeps "matching" but extracts wrong or empty values. You own the
mechanism that catches this: continuously watching a rule's output health
and automatically reacting when it degrades. This is a real differentiator
for the pitch — most competing teams won't have this at all, so it's worth
building for real, even in simplified form.

You don't need real production statistics for 3 days — a clear, honest,
simplified version (explicitly scoped down, not faked) is the right target.

## Your function signatures

```python
# drift_monitor/monitor.py
from schemas.schemas import NormalizedEvent, DriftMetric

def compute_null_rate(events: list[NormalizedEvent], field_path: str) -> float:
    """
    Given a batch of NormalizedEvents (all sharing the same fingerprint_id)
    and a dotted field path (e.g. "src_endpoint.ip"), return the fraction
    of events where that field is None/missing.
    """

def classify_severity(current_null_rate: float, baseline_null_rate: float) -> str:
    """
    Compare current vs baseline null rate and return one of:
    "none", "minor", "moderate", "severe".
    Suggested simple thresholds (fine to use these as-is for 3 days):
      - increase < 3x baseline (or < 0.05 absolute, whichever is looser) -> "none"
      - increase 3x-6x baseline -> "minor"
      - increase 6x-15x baseline -> "moderate"
      - increase > 15x baseline -> "severe"
    """

def check_drift(fingerprint_id: str, field_path: str, events: list[NormalizedEvent],
                 baseline_null_rate: float) -> DriftMetric:
    """
    Combine the two functions above into one DriftMetric result for a
    batch of events.
    """

def response_for_severity(severity: str) -> str:
    """
    Return a short string describing the automatic system response:
      "none" -> "no action"
      "minor" -> "logged for review"
      "moderate" -> "field quarantined, rule stays live"
      "severe" -> "reverted to raw-only forwarding"
    """
```

## Schemas you consume/produce (from schemas.py — do not redefine)

```python
@dataclass
class NormalizedEvent:
    event_id: str
    raw_id: str
    fingerprint_id: str
    rule_version: int
    class_name: str
    time: str
    severity_id: Optional[int]
    src_endpoint: Optional[dict]
    dst_endpoint: Optional[dict]
    action: Optional[str]
    unmapped_fields: dict

@dataclass
class DriftMetric:
    fingerprint_id: str
    field_name: str
    window_start: str
    window_end: str
    null_rate: float
    baseline_null_rate: float
    severity: Literal["none", "minor", "moderate", "severe"]
```

## Day-by-day

**Day 1**
- Build all four functions above.
- Test using `/testdata/fixtures/drift_sequence.json` — this file is a
  pre-built sequence of null-rate snapshots showing gradual degradation
  from "none" through "severe". Confirm your `classify_severity()`
  produces the same severity labels already in that file, given the
  same null_rate/baseline pairs.
- Build a small script that replays that sequence and prints out each
  step's severity + response — this becomes your demo asset directly.

**Day 2**
- If P2's parser engine is producing real `NormalizedEvent` batches by
  now, try `compute_null_rate()` on real (healthy) output — confirm it
  returns a low/expected value.
- Since we won't have real drift happening naturally in 3 days, build a
  **simulated drift generator**: take a batch of real normalized events
  and artificially null out a field in a growing fraction of them over
  several "windows," to feed into your pipeline realistically for the
  demo. Coordinate with P6 on this — it overlaps with their test-data
  role.

**Day 3**
- Wire your functions into a simple visual (a line chart of null_rate
  over time, e.g. via `matplotlib` or Streamlit's built-in chart
  functions — coordinate with P4 on whether this lives in their app or a
  separate small script/page).
- Support integration testing with P6.

## Definition of done (day 1 checkpoint)

```python
import json
sequence = json.load(open("testdata/fixtures/drift_sequence.json"))
for snapshot in sequence:
    predicted = classify_severity(snapshot["null_rate"], snapshot["baseline_null_rate"])
    assert predicted == snapshot["severity"], f"mismatch at {snapshot}"
```

## What NOT to build

- No real statistical process control (control charts, calibrated
  confidence intervals) — the simple threshold-based approach above is
  the correct, honest scope for 3 days. State the more rigorous version
  as "future work" in the architecture doc, don't try to build it now.
- No automatic re-onboarding trigger that actually calls P1's SLM again —
  for the demo, printing/displaying "would trigger re-onboarding" on
  severe drift is enough; you don't need it to actually fire a real call.

## Instructions for your AI agent

Paste this whole file plus `schemas/schemas.py` as context. Ask it to
implement the four functions above. Test against
`/testdata/fixtures/drift_sequence.json` before trying anything with real
event data.
