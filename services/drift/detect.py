# services/drift/detect.py — Window -> drift_windows row assembly (R-M3-4).
#
# Tier-1 only at this layer: mapped-field rows carry the violation-rate ladder
# (ulpf_core.drift.tier1_severity), the '__rule__' sentinel carries match_rate.
# Tier-2 comparisons (null/match/shape ladders against a baseline) and the
# enforcement side (severity -> action, quarantine, deactivate, alerts) are
# Task 5's evaluate/enforce layers on top of these rows.
from __future__ import annotations

from typing import TYPE_CHECKING

from ulpf_core.drift import shape_histogram, tier1_severity

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
        # The match-rate severity ladder is tier-2 (needs the Task 5 baseline);
        # recorded 'none' until evaluate_window joins the loop.
        "none",
        None,
    )
