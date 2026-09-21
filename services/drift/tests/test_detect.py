# services/drift/tests/test_detect.py — Window -> drift_windows row assembly
# (tier-1 severity, __rule__ match_rate, the EMPTY HISTOGRAM GUARD from Task 3's
# review). Pure functions + monkeypatched shape_histogram; NEVER a live DB.
from datetime import UTC, datetime, timedelta

import pytest
from ulpf_core.models import Mapping

from drift import detect
from drift.detect import RULE_FIELD, shape_dist, window_rows
from drift.store import ActiveDriftRule
from drift.windows import FieldStats, compute_windows


def _ts(seconds: float) -> datetime:
    return datetime(2026, 9, 21, 10, 0, 0, tzinfo=UTC) + timedelta(seconds=seconds)


def _doc(ip="198.51.100.4", unmapped=None):
    return {"src_endpoint": {"ip": ip, "port": 443}, "severity_id": 3,
            "time": "2026-09-19T10:00:03Z",
            "unmapped": unmapped if unmapped is not None else {}}


def _rule():
    return ActiveDriftRule(
        id=7, fingerprint_id="fp_a", version=2, pattern=r"x",
        mappings=[Mapping(source_field="SRC", ocsf_path="src_endpoint.ip")],
        provenance="human", quarantined_fields=["dst_endpoint.ip"])


def _windows(rows, rule=None, **kw):
    rule = rule or _rule()
    return compute_windows(rows, count_window=len(rows), time_window_s=600,
                           mapped_paths=tuple(m.ocsf_path for m in rule.mappings),
                           **kw)


# --- __rule__ sentinel row: match_rate = parsed / (parsed + parse_errors) ------


def test_rule_row_carries_match_rate():
    rows = ([(_ts(i), "parsed", _doc()) for i in range(3)]
            + [(_ts(3), "parse_error", None)])
    (rule_row,) = [r for r in window_rows(_rule(), _windows(rows)) if r[2] == RULE_FIELD]
    fp, version, field, start, end, count, null_rate, match_rate, violation_rate, \
        shape, severity, action = rule_row
    assert (fp, version, field) == ("fp_a", 2, "__rule__")
    assert count == 4 and start == _ts(0) and end == _ts(3)
    assert match_rate == pytest.approx(3 / 4)
    # No rates, no shape, no tier-1 on the sentinel; the match-rate severity
    # ladder needs a baseline (Task 5's evaluate) — recorded 'none' for now.
    assert null_rate is None and violation_rate is None and shape is None
    assert severity == "none" and action is None


def test_rule_row_zero_parsed_docs_match_rate_is_zero():
    rows = [(_ts(0), "parse_error", None), (_ts(1), "parse_error", None)]
    (rule_row,) = window_rows(_rule(), _windows(rows))
    assert rule_row[7] == 0.0


def test_rule_row_match_rate_none_when_no_denominator():
    # Defensive: a row with neither parsed nor parse_error status cannot happen
    # in the current view (unparsed rows carry rule_version 0), but the rate
    # degrades to NULL instead of dividing by zero.
    from drift.windows import Window
    synthetic = Window(start=_ts(0), end=_ts(0), count=1, parsed=0, parse_errors=0,
                       field_stats={}, new_unmapped=set())
    (rule_row,) = window_rows(_rule(), [synthetic])
    assert rule_row[7] is None


# --- mapped field rows: tier-1 severity ladder ---------------------------------


def test_mapped_field_row_tier1_severity_and_rates():
    # 1 violation of 4 parsed docs = 0.25 -> tier1_severity ladder 'moderate'.
    rows = ([(_ts(i), "parsed", _doc("SRC=198.51.100.4")) for i in (0,)]
            + [(_ts(i), "parsed", _doc()) for i in (1, 2, 3)])
    (ip_row,) = [r for r in window_rows(_rule(), _windows(rows))
                 if r[2] == "src_endpoint.ip"]
    assert ip_row[5] == 4                      # events_count
    assert ip_row[6] == 0.0                    # null_rate = 0/4
    assert ip_row[7] is None                   # match_rate is __rule__-only
    assert ip_row[8] == pytest.approx(0.25)    # violation_rate = 1/4
    assert ip_row[9] == {"ipv4": 3, "free_text": 1}  # shape over non-null values
    # (the violating SRC=... garbage classifies free_text — violators still bin)
    assert ip_row[10] == "moderate"            # tier1_severity(0.25)
    assert ip_row[11] is None                  # action_taken: Task 5 enforcement


def test_mapped_field_row_zero_violations_is_none_severity():
    rows = [(_ts(i), "parsed", _doc()) for i in range(2)]
    (ip_row,) = [r for r in window_rows(_rule(), _windows(rows))
                 if r[2] == "src_endpoint.ip"]
    assert ip_row[8] == 0.0 and ip_row[10] == "none"


def test_mapped_field_row_null_rate_counts_nulls():
    docs = [(_ts(0), "parsed", _doc(None)), (_ts(1), "parsed", _doc())]
    (ip_row,) = [r for r in window_rows(_rule(), _windows(docs))
                 if r[2] == "src_endpoint.ip"]
    assert ip_row[6] == pytest.approx(0.5)
    assert ip_row[8] == 0.0                    # the null is not a violation


# --- unmapped.* rows: recorded always, no tier-1 invariant ----------------------


def test_unmapped_field_rows_have_no_violation_rate():
    rows = [(_ts(0), "parsed", _doc(unmapped={"IN": "eth0"})),
            (_ts(1), "parsed", _doc(unmapped={"IN": "eth1"}))]
    (in_row,) = [r for r in window_rows(_rule(), _windows(rows))
                 if r[2] == "unmapped.IN"]
    assert in_row[6] == 0.0                    # null_rate still measured
    assert in_row[8] is None                   # no tier-1 invariant on unmapped
    assert in_row[9] == {"free_text": 2}       # shape still measured
    assert in_row[10] == "none"                # findings stay alert-only (Task 5)


# --- EMPTY HISTOGRAM GUARD (Task 3 review carry, binding) -----------------------


def test_zero_parsed_window_emits_only_the_rule_row():
    # A window with zero parsed docs skips shape comparison ENTIRELY — silence
    # is the volume ladder's job (Task 5), never a shape comparison on {}.
    rows = [(_ts(i), "parse_error", None) for i in range(3)]
    assert window_rows(_rule(), _windows(rows)) == [
        ("fp_a", 2, "__rule__", _ts(0), _ts(2), 3,
         None, 0.0, None, None, "none", None)]


def test_shape_dist_never_runs_on_an_empty_histogram(monkeypatch):
    # The guard itself: an empty value list short-circuits to {} BEFORE the
    # shape machinery (and therefore before any js_divergence caller in Task 5)
    # ever sees it.
    def boom(values):
        raise AssertionError("shape machinery called on an empty histogram")

    monkeypatch.setattr(detect, "shape_histogram", boom)
    assert shape_dist(FieldStats(nulls=3, violations=0, values=[])) == {}


def test_shape_dist_computes_histogram_from_values():
    stats = FieldStats(nulls=0, violations=0, values=["1.2.3.4", "DROP", 7])
    assert shape_dist(stats) == {"ipv4": 1, "free_text": 1, "int": 1}


# --- row shape: rule identity, determinism --------------------------------------


def test_rows_are_deterministic_for_the_same_input():
    rows = ([(_ts(0), "parsed", _doc("SRC=1.2.3.4"))]
            + [(_ts(i), "parsed", _doc()) for i in (1, 2)])
    assert (window_rows(_rule(), _windows(rows))
            == window_rows(_rule(), _windows(rows)))


def test_rows_order_is_mapped_then_sorted_unmapped_then_rule():
    rows = [(_ts(0), "parsed", _doc(unmapped={"Z": "1", "A": "2"}))]
    fields = [r[2] for r in window_rows(_rule(), _windows(rows))]
    assert fields == ["src_endpoint.ip", "unmapped.A", "unmapped.Z", "__rule__"]
