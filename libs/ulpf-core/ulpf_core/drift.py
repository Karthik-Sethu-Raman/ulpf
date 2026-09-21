"""Pure drift-detection math for the M3 drift service (spec §7.1, R-M3-5).

Everything here is deterministic and dependency-free — stdlib only, no DB,
no model calls — so Tasks 4/5 (window loop, enforcement) can import it
anywhere. Scalar value classification, shape histograms, smoothed JS
divergence, the severity ladders and the severity-to-action mapping.

Deliberately standalone: the class vocabulary is scalar-level
("ipv4"/"int"/"timestamp"/"free_text"), independent of fingerprint's
token-level ``_classify`` shapes, and must not import it (R-M3-5).
"""

import math
import re

SEVERITIES = ("none", "minor", "moderate", "severe")

# Same dotted-quad shape as validation's IP sanity check (four digit quads,
# no 0-255 range enforcement — this is a class test, not an address parser).
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
# ISO-8601-ish: a value that OPENS with a YYYY-MM-DD / YYYY/MM/DD date.
_TS_PREFIX_RE = re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}")
_DIGITS_RE = re.compile(r"^\d+$")


def classify_value(v) -> str:
    """Scalar class of a mapped value: "ipv4" | "int" | "timestamp" |
    "free_text". None-free contract: callers filter nulls before binning
    (null-rate is its own tier-2 signal), so None is rejected loudly here
    instead of silently classifying as "None" free text."""
    if v is None:
        raise ValueError("classify_value is None-free: filter nulls at the caller")
    if isinstance(v, str):
        if _IPV4_RE.match(v):
            return "ipv4"
        if _TS_PREFIX_RE.match(v):
            return "timestamp"
        if _DIGITS_RE.match(v):
            return "int"
    elif isinstance(v, int) and not isinstance(v, bool):
        # bool is an int subclass — a True flag is not an int value
        return "int"
    return "free_text"


def shape_histogram(values: list) -> dict[str, int]:
    """Count of values per classify_value class — the tier-2 shape_dist."""
    hist: dict[str, int] = {}
    for v in values:
        cls = classify_value(v)
        hist[cls] = hist.get(cls, 0) + 1
    return hist


def js_divergence(p: dict, q: dict) -> float:
    """Symmetric Jensen-Shannon divergence (natural log) over two
    histograms, add-1 smoothed across the key union so a key unseen on
    one side contributes mass instead of a divide-by-zero infinity.
    Identical histograms give exactly 0.0; disjoint supports approach
    ln 2 (~0.693) as counts grow."""
    keys = set(p) | set(q)
    if not keys:
        return 0.0
    smoothed_p = {k: p.get(k, 0) + 1 for k in keys}
    smoothed_q = {k: q.get(k, 0) + 1 for k in keys}
    total_p, total_q = sum(smoothed_p.values()), sum(smoothed_q.values())
    divergence = 0.0
    for k in keys:
        pi = smoothed_p[k] / total_p
        qi = smoothed_q[k] / total_q
        m = (pi + qi) / 2
        divergence += 0.5 * pi * math.log(pi / m) + 0.5 * qi * math.log(qi / m)
    return divergence


def null_rate_severity(current: float, baseline: float) -> str:
    """The legacy demo's proven ladder (legacy-demo/drift_monitor/monitor.py
    classify_severity, verbatim semantics): ratio < 3 or absolute diff
    < 0.05 -> none; ratio < 10 -> minor; ratio < 40 -> moderate; else
    severe. Baseline 0: ratio is inf when current > 0 (never-null field
    starting to null is infinitely worse) else 1.0."""
    current = round(current, 6)
    baseline = round(baseline, 6)
    if baseline > 0:
        ratio = current / baseline
    else:
        ratio = float("inf") if current > 0 else 1.0
    difference = round(current - baseline, 6)
    if ratio < 3 or difference < 0.05:
        return "none"
    if ratio < 10:
        return "minor"
    if ratio < 40:
        return "moderate"
    return "severe"


def _band_severity(value: float, minor: float, moderate: float, severe: float) -> str:
    """Shared ascending-threshold ladder: below `minor` -> none, below
    `moderate` -> minor, below `severe` -> moderate, else severe. The
    match/shape/tier-1 ladders differ only in their threshold triples."""
    if value < minor:
        return "none"
    if value < moderate:
        return "minor"
    if value < severe:
        return "moderate"
    return "severe"


def match_rate_severity(current: float, baseline: float) -> str:
    """Absolute match-rate drop ladder: <0.10 none, <0.25 minor, <0.50
    moderate, else severe. The drop is quantized to 6 decimals like the
    null ladder so a nominal 1.00 -> 0.90 window sits exactly ON the 0.10
    boundary (1.0 - 0.9 is 0.0999... in binary), not just under it."""
    return _band_severity(round(baseline - current, 6), 0.10, 0.25, 0.50)


def shape_severity(divergence: float) -> str:
    """JS-divergence ladder: <0.15 none, <0.35 minor, <0.60 moderate,
    else severe."""
    return _band_severity(divergence, 0.15, 0.35, 0.60)


def tier1_severity(violation_rate: float) -> str:
    """Tier-1 invariant-violation rate ladder: <0.05 none, <0.20 minor,
    <0.50 moderate, else severe."""
    return _band_severity(violation_rate, 0.05, 0.20, 0.50)


def volume_severity(count: int, p05: float, p95: float) -> str:
    """Per-source event volume against baseline percentile bounds:
    silence (0 events) is severe — a dead feed must never look healthy —
    inside [p05, p95] is none, anything else is minor (drought or flood)."""
    if count == 0:
        return "severe"
    if p05 <= count <= p95:
        return "none"
    return "minor"


def decide_action(severity: str) -> str | None:
    """Severity -> graduated enforcement step (spec §7.2): minor alerts,
    moderate quarantines the field (rule stays live for healthy fields),
    severe deactivates the rule; none needs no action."""
    return {"none": None, "minor": "alert", "moderate": "field_quarantined",
            "severe": "rule_deactivated"}[severity]
