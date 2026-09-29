# services/drift/detect.py — Window -> findings -> drift_windows rows
# (R-M3-4 measurement + R-M3-11 evaluation).
#
# Two layers over one window: window_rows (measurement — the per-field rates
# and shape histograms, tier-1 severity) and evaluate_window (Task 5 — the
# graduated decision: tier-1 ALWAYS, tier-2 null/match/shape/volume ladders
# only when a baseline profile exists, per-field severity = max across
# signals, decide_action semantics with the two ruling overrides: quarantined
# fields stay measured and still escalate, unmapped.* rows are new-key
# signals only — alert-only, decide_action bypassed). aggregate_baseline is
# the pure FIRST-N-window aggregation behind baseline establishment.
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from ulpf_core.drift import (
    SEVERITIES,
    decide_action,
    js_divergence,
    match_rate_severity,
    null_rate_severity,
    shape_histogram,
    shape_severity,
    tier1_severity,
    volume_severity,
)

from drift.windows import FieldStats, Window

if TYPE_CHECKING:
    from drift.store import ActiveDriftRule

# drift_windows.field vocabulary (migration 007): OCSF path, 'unmapped.<key>',
# or the per-window rule-level sentinel that carries match_rate.
RULE_FIELD = "__rule__"
UNMAPPED_PREFIX = "unmapped."

# Column order of the drift_windows INSERT in store.insert_windows (this is
# the tuple contract the two modules share; scanned_at uses its DB default).
_ROW_COLUMNS = (
    "fingerprint_id", "rule_version", "field", "window_start", "window_end",
    "events_count", "null_rate", "match_rate", "violation_rate", "shape_dist",
    "severity", "action_taken",
)


@dataclass(frozen=True)
class Finding:
    """One (window, field) drift decision: the measured window's per-field
    severity (max across tier-1 + tier-2 signals), the graduated action the
    severity warrants, the measurements behind it, and the window's start (the
    audit detail + the deterministic drift_windows key)."""

    field: str
    severity: str
    action: str | None
    stats: dict
    window_start: datetime


def shape_dist(stats: FieldStats) -> dict:
    """Histogram for one field's stats — EMPTY HISTOGRAM GUARD (Task 3 review
    carry, binding): an empty value list short-circuits to {} BEFORE the shape
    machinery runs, so js_divergence is never fed an empty histogram and a
    field with no observed values stays silent (silence is the volume ladder's
    job, never a shape comparison)."""
    return shape_histogram(stats.values) if stats.values else {}


def window_rows(rule: ActiveDriftRule, windows: list[Window]) -> list[tuple]:
    """One drift_windows tuple per (window, field), in _ROW_COLUMNS order.

    A window with zero parsed docs emits ONLY the __rule__ row: with no docs
    there is nothing to shape-compare (guard) and no tier-1 denominator.
    action_taken stays NULL — Task 5's enforcement decides and audits it.
    """
    rows: list[tuple] = []
    for win in windows:
        if win.parsed:
            for field, stats in win.field_stats.items():
                rows.append(_field_row(rule, win, field, stats))
        rows.append(_rule_row(rule, win))
    return rows


def _field_row(rule: ActiveDriftRule, win: Window, field: str,
               stats: FieldStats) -> tuple:
    is_unmapped = field.startswith(UNMAPPED_PREFIX)
    violation_rate = None if is_unmapped else stats.violations / win.parsed
    severity = "none" if is_unmapped else tier1_severity(violation_rate)
    return (
        rule.fingerprint_id, rule.version, field,
        win.start, win.end, win.count,
        stats.nulls / win.parsed,   # null_rate
        None,                       # match_rate is __rule__-only
        violation_rate,
        shape_dist(stats),
        severity,
        None,                       # action_taken (Task 5 enforcement)
    )


def _rule_row(rule: ActiveDriftRule, win: Window) -> tuple:
    denominator = win.parsed + win.parse_errors
    match_rate = win.parsed / denominator if denominator else None
    return (
        rule.fingerprint_id, rule.version, RULE_FIELD,
        win.start, win.end, win.count,
        None, match_rate, None, None,
        # Measurement default: the decided severity/action come from
        # evaluate_window and are overlaid by enforce.record_windows.
        "none",
        None,
    )


# --- Task 5: tier-2 evaluation (R-M3-11) -------------------------------------------


def _max_severity(signals: list[str]) -> str:
    """Max severity by ladder order (SEVERITIES is ascending none..severe)."""
    return max(signals, key=SEVERITIES.index) if signals else "none"


def evaluate_window(win: Window, baseline: dict | None,
                    *, rule_quarantined: list[str] | tuple = ()) -> list[Finding]:
    """Evaluate one closed window: tier-1 ALWAYS, tier-2 only when a baseline
    profile exists for the field (R-M3-11). Emission mirrors window_rows
    exactly — mapped fields only when win.parsed > 0, then the __rule__
    sentinel — so enforce.record_windows can overlay findings onto measured
    rows by field. Quarantined fields are STILL measured and STILL escalate:
    quarantine only suppresses a redundant re-quarantine action, never a
    finding, and a quarantined field going severe still deactivates the rule.
    """
    findings: list[Finding] = []
    if win.parsed:
        for field_name, stats in win.field_stats.items():
            findings.append(_field_finding(win, field_name, stats, baseline,
                                           tuple(rule_quarantined)))
    findings.append(_rule_finding(win, baseline))
    return findings


def _field_finding(win: Window, field_name: str, stats: FieldStats,
                   baseline: dict | None, rule_quarantined: tuple) -> Finding:
    null_rate = stats.nulls / win.parsed
    hist = shape_dist(stats)  # the EMPTY HISTOGRAM GUARD lives in here

    if field_name.startswith(UNMAPPED_PREFIX):
        # Binding ruling (Task 4 review carry): unmapped rows are NEW-KEY-
        # EMERGENCE signals only — no tier-1 ladder, no tier-2 null/shape
        # comparison even if a profile somehow exists, and decide_action is
        # bypassed: alert-only. Rates below are the recorded measurement, the
        # same numbers window_rows writes, never re-derived into severity.
        is_new = field_name[len(UNMAPPED_PREFIX):] in win.new_unmapped
        return Finding(
            field_name, "minor" if is_new else "none", "alert" if is_new else None,
            {"events_count": win.count, "null_rate": null_rate, "shape_dist": hist},
            win.start)

    violation_rate = stats.violations / win.parsed
    signals = [tier1_severity(violation_rate)]
    profile = baseline.get(field_name) if baseline else None
    if profile is not None:  # tier-2 arms per field: no profile -> tier-1 only
        base_null = profile.get("null_rate")
        if base_null is not None:
            signals.append(null_rate_severity(null_rate, base_null))
        base_shape = profile.get("shape_dist")
        if hist and base_shape:
            # Empty-histogram guard: a window with no observed values never
            # shape-compares (silence is the volume ladder's job).
            signals.append(shape_severity(
                js_divergence(hist, _window_scale(base_shape, hist))))
    severity = _max_severity(signals)
    action = decide_action(severity)
    if action == "field_quarantined" and field_name in rule_quarantined:
        action = None  # already quarantined: idempotent skip, never a re-audit
    return Finding(field_name, severity, action,
                   {"events_count": win.count, "null_rate": null_rate,
                    "violation_rate": violation_rate, "shape_dist": hist},
                   win.start)


def _rule_finding(win: Window, baseline: dict | None) -> Finding:
    """The __rule__ sentinel: match_rate_severity + volume_severity, both
    tier-2 (no tier-1 signal exists for the rule itself)."""
    denominator = win.parsed + win.parse_errors
    match_rate = win.parsed / denominator if denominator else None
    signals: list[str] = []
    profile = baseline.get(RULE_FIELD) if baseline else None
    if profile is not None:
        base_match = profile.get("match_rate")
        if match_rate is not None and base_match is not None:
            signals.append(match_rate_severity(match_rate, base_match))
        bounds = profile.get("events_count") or {}
        if "min" in bounds and "max" in bounds:
            signals.append(volume_severity(win.count, bounds["min"], bounds["max"]))
    severity = _max_severity(signals)
    action = decide_action(severity)
    if action == "field_quarantined":
        # The sentinel is not a mappable field: a moderate match/volume
        # decline alerts (humans look); only severe deactivates.
        action = "alert"
    return Finding(RULE_FIELD, severity, action,
                   {"events_count": win.count, "match_rate": match_rate}, win.start)


def merge_findings(findings: list[Finding]) -> dict[str, str]:
    """Per-field max severity across one scan's findings (R-M3-11) — the
    worst thing each field did in any window of the scan."""
    merged: dict[str, str] = {}
    for finding in findings:
        current = merged.get(finding.field, "none")
        if SEVERITIES.index(finding.severity) > SEVERITIES.index(current):
            merged[finding.field] = finding.severity
    return merged


# --- Task 5: baseline aggregation (R-M3-7) -----------------------------------------


def aggregate_baseline(rows: list[tuple], *, baseline_windows: int) -> dict | None:
    """Aggregate the FIRST `baseline_windows` closed windows of a rule version
    into its baseline profiles, or None while fewer windows exist.

    rows: fetch_window_history output — (window_start, field, events_count,
    null_rate, match_rate, shape_dist) ordered by window_start. Per mapped
    field: mean null_rate + shape_dist SUMMED across the windows then
    normalized to proportions. __rule__: mean match_rate + events_count
    min/max (the volume bounds, R-M3-10). unmapped.* rows are skipped — they
    are alert-only new-key signals, never tier-2 compared (binding ruling).
    """
    starts: list = []
    seen: set = set()
    for row in rows:
        if row[0] not in seen:
            seen.add(row[0])
            starts.append(row[0])
    if len(starts) < baseline_windows:
        return None
    cutoff = starts[baseline_windows - 1]

    buckets: dict[str, dict] = {}
    for window_start, field_name, events_count, null_rate, match_rate, shape in rows:
        if window_start > cutoff or field_name.startswith(UNMAPPED_PREFIX):
            continue
        bucket = buckets.setdefault(field_name, {"null_rates": [], "match_rates": [],
                                                 "shape": {}, "counts": []})
        if null_rate is not None:
            bucket["null_rates"].append(null_rate)
        if match_rate is not None:
            bucket["match_rates"].append(match_rate)
        if shape:
            for cls, n in shape.items():
                bucket["shape"][cls] = bucket["shape"].get(cls, 0) + n
        bucket["counts"].append(events_count)

    profiles: dict[str, dict] = {}
    for field_name, bucket in buckets.items():
        if field_name == RULE_FIELD:
            profiles[field_name] = {
                "match_rate": (_mean(bucket["match_rates"])),
                "events_count": {"min": min(bucket["counts"]),
                                 "max": max(bucket["counts"])},
            }
        else:
            profiles[field_name] = {
                "null_rate": _mean(bucket["null_rates"]),
                "shape_dist": _normalized(bucket["shape"]),
            }
    return profiles


def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def _normalized(histogram: dict) -> dict:
    """Count histogram -> proportions summing to 1.0 ({} stays {}). The STORED
    profile is scale-free; comparisons rescale it back (see _window_scale)."""
    total = sum(histogram.values())
    return {cls: n / total for cls, n in histogram.items()} if total else {}


def _window_scale(baseline_shape: dict, hist: dict) -> dict:
    """Project the stored (normalized) baseline shape onto the current
    window's observed-value count. R-M3-5's js_divergence add-1 smoothing is
    calibrated for COUNT-scale histograms (T3 pins 'grows toward ln2 as counts
    grow'); feeding raw proportions would let the +1s dominate the baseline
    side and cap every shape comparison at ~0.32 (verified: full flip
    converges 0.2404@N=20 -> 0.3178@N=10k; the ~0.057 figure is the cap of a
    props-vs-props shape that never occurs), leaving the severe band
    unreachable. Rescaling puts both sides at the same count scale, where the
    smoothing is negligible and the ladder bands mean what T3 calibrated."""
    total = sum(hist.values())
    return {cls: proportion * total for cls, proportion in baseline_shape.items()}
