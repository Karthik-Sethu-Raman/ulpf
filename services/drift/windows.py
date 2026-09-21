# services/drift/windows.py — pure window math over the current view (R-M3-4).
#
# Stateless recompute contract (spec §7.1): windows are derived ONLY from the
# rows handed in — ordered by parsed_at — and never from the wall clock, so
# the same rows always produce identical windows (idempotent INSERT keys).
# Detection math beyond counting (JS divergence, ladders) lives in
# ulpf_core.drift; this module owns slicing and the per-field aggregation.
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

# Same dotted-quad shape as ulpf_core.validation._IP_RE / drift._IPV4_RE
# (four digit quads, no 0-255 enforcement — a shape test, not a parser).
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


@dataclass(frozen=True)
class FieldStats:
    """Per-field aggregates for one window: null count, tier-1 invariant
    violation count, and the non-null values (input of the shape histogram)."""

    nulls: int
    violations: int
    values: list


@dataclass(frozen=True)
class Window:
    """One closed window of the current view (a trailing partial is never
    emitted — it may still grow before the next scan)."""

    start: datetime          # parsed_at of the window's first event
    end: datetime            # parsed_at of the window's last event
    count: int               # parsed + parse_error rows in the window
    parsed: int
    parse_errors: int
    field_stats: dict[str, FieldStats]
    new_unmapped: set[str]


def compute_windows(rows, *, count_window, time_window_s,
                    mapped_paths=(), known_unmapped=None) -> list[Window]:
    """Slice current-view rows into closed windows.

    rows: (parsed_at, status, ocsf|None) ordered by parsed_at. A window closes
    when it holds count_window rows OR when its FIRST row is older than
    window_time_s — checked at scan time against the NEWEST row's parsed_at
    (the data's own horizon, never the wall clock; determinism). The trailing
    partial window is held back: it may still grow before the next scan.

    mapped_paths: the rule's mapped OCSF targets — the fields field_stats
    covers (a mapped-but-None value is a null, never a tier-1 violation).
    known_unmapped: None while no baseline exists (unmapped keys are recorded
    but none are "new"); afterwards, the baseline's first-window key set, and
    keys absent from BOTH it and the mapped targets are new (Step 1 contract).

    The frozen call form compute_windows(rows, count_window=...,
    time_window_s=...) is unchanged; the two rule-context keywords default to
    the pre-baseline, no-mappings behavior.
    """
    if not rows:
        return []
    horizon = rows[-1][0] - timedelta(seconds=time_window_s)
    windows: list[Window] = []
    current: list = []
    for row in rows:
        current.append(row)
        if len(current) >= count_window or current[0][0] < horizon:
            windows.append(_close_window(current, mapped_paths, known_unmapped))
            current = []
    return windows


def _close_window(rows, mapped_paths, known_unmapped) -> Window:
    """Aggregate one closed window: counts, per-field stats, new unmapped."""
    docs = [ocsf for (_, status, ocsf) in rows if status == "parsed" and ocsf is not None]
    parse_errors = sum(1 for (_, status, _) in rows if status == "parse_error")

    nulls = {path: 0 for path in mapped_paths}
    violations = {path: 0 for path in mapped_paths}
    values: dict[str, list] = {path: [] for path in mapped_paths}
    un_nulls: dict[str, int] = {}
    un_values: dict[str, list] = {}
    for doc in docs:
        for path in mapped_paths:
            value = _doc_get(doc, path)
            if value is None:
                nulls[path] += 1
            else:
                values[path].append(value)
                if tier1_violation(path, value):
                    violations[path] += 1
        for key, value in (doc.get("unmapped") or {}).items():
            if value is None:
                un_nulls[key] = un_nulls.get(key, 0) + 1
            else:
                un_values.setdefault(key, []).append(value)

    field_stats = {path: FieldStats(nulls[path], violations[path], values[path])
                   for path in mapped_paths}
    for key in sorted(set(un_nulls) | set(un_values)):  # sorted: deterministic order
        field_stats[f"unmapped.{key}"] = FieldStats(
            un_nulls.get(key, 0), 0, un_values.get(key, []))

    if known_unmapped is None:
        new_unmapped: set[str] = set()  # pre-baseline: recorded, never "new"
    else:
        targets = set(mapped_paths)
        new_unmapped = {key for key in set(un_nulls) | set(un_values)
                        if key not in targets and key not in known_unmapped}

    return Window(start=rows[0][0], end=rows[-1][0], count=len(rows),
                  parsed=len(docs), parse_errors=parse_errors,
                  field_stats=field_stats, new_unmapped=new_unmapped)


def tier1_violation(field: str, value) -> bool:
    """Tier-1 invariant for one mapped value (spec §7.1), mirroring
    validation._value_sanity's checks as window-aggregated drift-time counts —
    deliberately NOT an import: validation is candidate-time, this is
    drift-time. None is NOT a violation (nulls are tier-2's signal); fields
    with no invariant (message, unmapped.*) never violate."""
    if value is None:
        return False
    if field in ("src_endpoint.ip", "dst_endpoint.ip"):
        return not (isinstance(value, str) and _IPV4_RE.match(value))
    if field in ("src_endpoint.port", "dst_endpoint.port"):
        return not _is_int_in(value, 0, 65535)
    if field == "severity_id":
        return not _is_int_in(value, 0, 6)
    if field == "time":
        if not isinstance(value, str):
            return True
        try:
            datetime.fromisoformat(value)
        except ValueError:
            return True
        return False
    return False


def _is_int_in(v, lo: int, hi: int) -> bool:
    # Mirrors validation._is_int_in: bool is an int subclass — a True flag is
    # neither a port nor a severity.
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _doc_get(doc: dict, dotted_path: str):
    """Walk a document by dotted OCSF path ('src_endpoint.ip'); missing -> None."""
    current = doc
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
