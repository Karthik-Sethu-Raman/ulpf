# Drift Monitor (`drift_monitor/`)

Watches deployed rule health over time and triggers an automatic,
fail-closed response when a rule starts producing degraded output — for
example, after a silent vendor firmware update reorders or renames log
fields.

## Core functions

```python
# drift_monitor/monitor.py
def compute_null_rate(events: list[NormalizedEvent], field_path: str) -> float
def classify_severity(current_null_rate: float, baseline_null_rate: float) -> str
def check_drift(...) -> DriftMetric
def response_for_severity(severity: str) -> str
```

Compares a field's current null rate against its recorded baseline and
classifies severity as `none`, `minor`, `moderate`, or `severe`, each
mapping to an escalating response — log only, quarantine the affected
field, or revert the source to raw-only forwarding entirely. This never
touches the hot path's latency; it's an observer on the parser engine's
output, not a gate in front of it.

## Supporting scripts

- `simulate_drift.py` — generates a synthetic sequence of degrading
  null rates for demonstration, since a short-lived prototype won't see
  real drift occur naturally.
- `demo_replay.py` — prints the drift sequence with computed severity
  and response side by side, a ready-made asset for showing the
  mechanism end to end.

## What this deliberately does not do

Uses simple threshold-based severity classification rather than full
statistical process control (calibrated confidence intervals, control
charts) — an explicit, documented scope choice for this stage, not a
gap to hide. The type/range sanity checks in `ingestion/validate_rule.py`
work from day one regardless of data volume; the null-rate comparison
here benefits from more historical data to establish a reliable
baseline.