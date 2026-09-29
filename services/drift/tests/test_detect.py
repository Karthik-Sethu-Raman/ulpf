# services/drift/tests/test_detect.py — Window -> drift_windows row assembly
# (tier-1 severity, __rule__ match_rate, the EMPTY HISTOGRAM GUARD from Task 3's
# review) PLUS Task 5's evaluate_window / merge_findings / aggregate_baseline
# (tier-2 ladders, graduated actions, baseline aggregation). Pure functions +
# monkeypatched shape_histogram; NEVER a live DB.
from datetime import UTC, datetime, timedelta

import pytest
from ulpf_core.models import Mapping

from drift import detect
from drift.detect import (
    RULE_FIELD,
    Finding,
    aggregate_baseline,
    evaluate_window,
    merge_findings,
    shape_dist,
    window_rows,
)
from drift.store import ActiveDriftRule
from drift.windows import FieldStats, Window, compute_windows


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


# --- Task 5: evaluate_window ------------------------------------------------------


def _win(parsed=10, errors=0, stats=None, new=(), start=None):
    """Synthetic Window (parsed>0 keeps field rows; the FieldStats are the
    test's chosen measurement, no docs needed — evaluate is pure over stats)."""
    return Window(start=start or _ts(0), end=_ts(60), count=parsed + errors,
                  parsed=parsed, parse_errors=errors,
                  field_stats=stats or {}, new_unmapped=set(new))


def _ip_stats(nulls=0, violations=0, values=None):
    return FieldStats(nulls=nulls, violations=violations,
                      values=values if values is not None else ["198.51.100.7"])


def _finding_for(win, baseline, field_name, *, quarantined=()):
    """The one finding for field_name out of the window's evaluation."""
    return next(f for f in evaluate_window(win, baseline, rule_quarantined=quarantined)
                if f.field == field_name)


def test_evaluate_tier1_only_without_baseline_ladder_and_actions():
    # violation_rate 0.1 -> tier-1 'minor' -> alert; decide_action semantics.
    win = _win(stats={"src_endpoint.ip": _ip_stats(violations=1)})
    finding = _finding_for(win, None, "src_endpoint.ip")
    assert (finding.field, finding.severity, finding.action) == (
        "src_endpoint.ip", "minor", "alert")
    assert finding.stats["violation_rate"] == pytest.approx(0.1)
    assert finding.stats["null_rate"] == 0.0 and finding.stats["events_count"] == 10
    assert finding.window_start == win.start


def test_evaluate_tier1_moderate_quarantines_and_severe_deactivates():
    # 0.2 violation-rate -> moderate -> field_quarantined; 0.5 -> severe ->
    # rule_deactivated (the full §7.2 ladder through tier-1 alone).
    stats_mod = _win(stats={"src_endpoint.ip": _ip_stats(violations=2)})
    assert _finding_for(stats_mod, None, "src_endpoint.ip").action \
        == "field_quarantined"
    stats_sev = _win(stats={"src_endpoint.ip": _ip_stats(violations=5)})
    f = _finding_for(stats_sev, None, "src_endpoint.ip")
    assert f.severity == "severe" and f.action == "rule_deactivated"


def test_evaluate_tier1_only_when_field_missing_from_baseline():
    # A field with no profile in the baseline dict (e.g. never observed during
    # the baseline windows) degrades to tier-1-only, never KeyError.
    baseline = {"other.field": {"null_rate": 0.0, "shape_dist": {"ipv4": 1.0}}}
    win = _win(stats={"src_endpoint.ip": _ip_stats()})
    finding = _finding_for(win, baseline, "src_endpoint.ip")
    assert finding.severity == "none" and finding.action is None


def test_evaluate_tier2_null_rate_escalates_over_quiet_tier1():
    # null 0.0 -> 0.2 against baseline 0.01: ratio 20, diff 0.19 -> moderate.
    baseline = {"src_endpoint.ip": {"null_rate": 0.01, "shape_dist": {"ipv4": 1.0}}}
    win = _win(stats={"src_endpoint.ip": _ip_stats(
        nulls=2, values=["198.51.100.7"] * 8)})   # null_rate 0.2, shape identical
    finding = _finding_for(win, baseline, "src_endpoint.ip")
    assert finding.severity == "moderate" and finding.action == "field_quarantined"


def test_evaluate_tier2_shape_divergence_alone_reaches_severe():
    # A field with NO tier-1 invariant (shape is its only signal): 1000
    # free-text values against an all-ipv4 baseline rescale to count parity
    # ({free_text: 1000} vs {ipv4: 1000}) -> T3's disjoint-count divergence
    # ~0.693 -> severe -> rule_deactivated.
    baseline = {"metadata.note": {"null_rate": 0.0, "shape_dist": {"ipv4": 1.0}}}
    win = _win(stats={"metadata.note": FieldStats(nulls=0, violations=0,
                                                  values=["DROP"] * 1000)})
    finding = _finding_for(win, baseline, "metadata.note")
    assert finding.severity == "severe" and finding.action == "rule_deactivated"


def test_evaluate_tier2_shape_rescales_baseline_to_window_count(monkeypatch):
    # The stored profile is normalized, but js_divergence must see it at the
    # window's count scale: {ipv4: 1.0} x 4 observed values -> {ipv4: 4.0}.
    captured = {}

    def spy(p, q):
        captured.update(p=p, q=q)
        return 0.0

    monkeypatch.setattr(detect, "js_divergence", spy)
    baseline = {"src_endpoint.ip": {"null_rate": 0.0, "shape_dist": {"ipv4": 1.0}}}
    win = _win(stats={"src_endpoint.ip": _ip_stats(values=["198.51.100.7"] * 4)})
    _finding_for(win, baseline, "src_endpoint.ip")
    assert captured["p"] == {"ipv4": 4} and captured["q"] == {"ipv4": 4.0}


def test_evaluate_severity_is_max_across_signals():
    # tier-1 minor (0.1 violations) + tier-2 null moderate (0.2 vs 0.01):
    # the field's severity is the MAX — moderate — not either alone.
    baseline = {"src_endpoint.ip": {"null_rate": 0.01, "shape_dist": {"ipv4": 1.0}}}
    win = _win(stats={"src_endpoint.ip": _ip_stats(nulls=2, violations=1,
                                                   values=["198.51.100.7"] * 7)})
    finding = _finding_for(win, baseline, "src_endpoint.ip")
    assert finding.severity == "moderate" and finding.action == "field_quarantined"


def test_evaluate_quarantined_field_still_measured_and_skips_requarantine():
    # Already-quarantined field sitting at moderate: STILL measured (the
    # finding exists, severity recorded) but the quarantine action is an
    # idempotent skip — decide_action('moderate') is suppressed to None.
    baseline = {"src_endpoint.ip": {"null_rate": 0.01, "shape_dist": {"ipv4": 1.0}}}
    win = _win(stats={"src_endpoint.ip": _ip_stats(nulls=2,
                                                   values=["198.51.100.7"] * 8)})
    finding = _finding_for(win, baseline, "src_endpoint.ip",
                           quarantined=["src_endpoint.ip"])
    assert finding.severity == "moderate" and finding.action is None


def test_evaluate_quarantined_field_worsening_to_severe_deactivates():
    # The binding escalation rule: a quarantined field going WORSE must reach
    # rule_deactivated — quarantine never hides the field.
    baseline = {"src_endpoint.ip": {"null_rate": 0.0, "shape_dist": {"ipv4": 1.0}}}
    win = _win(stats={"src_endpoint.ip": _ip_stats(nulls=5,
                                                   values=["198.51.100.7"] * 5)})
    finding = _finding_for(win, baseline, "src_endpoint.ip",
                           quarantined=["src_endpoint.ip"])
    assert finding.severity == "severe" and finding.action == "rule_deactivated"


def test_evaluate_never_shape_compares_an_empty_current_histogram(monkeypatch):
    # Task 3/4 review carry (binding): a window with no observed values
    # short-circuits shape comparison entirely — js_divergence must never see
    # an empty histogram. The baseline here is an ALWAYS-NULL field (null
    # ladder quiet), so only a broken shape path could fire.
    def boom(p, q):
        raise AssertionError("js_divergence called on an empty histogram")

    monkeypatch.setattr(detect, "js_divergence", boom)
    baseline = {"src_endpoint.ip": {"null_rate": 1.0, "shape_dist": {}}}
    win = _win(stats={"src_endpoint.ip": _ip_stats(nulls=10, values=[])})
    finding = _finding_for(win, baseline, "src_endpoint.ip")
    assert finding.severity == "none"    # null 1.0 vs baseline 1.0: ratio 1.0
    assert finding.stats["shape_dist"] == {}


def test_evaluate_rule_row_pre_baseline_is_none():
    win = _win(errors=0, stats={})   # parsed 10, match_rate 1.0, no baseline yet
    (finding,) = evaluate_window(win, None, rule_quarantined=[])
    assert finding.field == RULE_FIELD
    assert finding.severity == "none" and finding.action is None
    assert finding.stats == {"events_count": 10, "match_rate": 1.0}


def test_evaluate_rule_row_match_rate_collapse_deactivates():
    # match 1.0 -> 0.3 = 0.7 drop -> severe; volume inside bounds stays none.
    baseline = {RULE_FIELD: {"match_rate": 1.0,
                             "events_count": {"min": 5, "max": 20}}}
    win = _win(parsed=3, errors=7, stats={})
    (finding,) = evaluate_window(win, baseline, rule_quarantined=[])
    assert finding.severity == "severe" and finding.action == "rule_deactivated"
    assert finding.stats["match_rate"] == pytest.approx(0.3)


def test_evaluate_rule_row_volume_outside_bounds_is_minor_alert():
    # count 25 outside [5, 20] -> volume 'minor'; match unchanged -> none.
    baseline = {RULE_FIELD: {"match_rate": 1.0,
                             "events_count": {"min": 5, "max": 20}}}
    win = _win(parsed=25, errors=0, stats={})
    (finding,) = evaluate_window(win, baseline, rule_quarantined=[])
    assert finding.severity == "minor" and finding.action == "alert"


def test_evaluate_rule_row_moderate_downgrades_quarantine_to_alert():
    # The __rule__ sentinel is NOT a quarantinable field: a moderate match drop
    # (1.0 -> 0.7, inside volume bounds) alerts — only severe deactivates.
    baseline = {RULE_FIELD: {"match_rate": 1.0,
                             "events_count": {"min": 5, "max": 20}}}
    win = _win(parsed=7, errors=3, stats={})   # match 0.7 -> 0.3 drop: moderate
    (finding,) = evaluate_window(win, baseline, rule_quarantined=[])
    assert finding.severity == "moderate" and finding.action == "alert"


def test_evaluate_unmapped_new_key_is_minor_alert_only():
    # decide_action is BYPASSED for unmapped.*: a brand-new key surfaces as
    # minor/alert (the extension-opportunity card), never quarantine/deactivate.
    win = _win(stats={"unmapped.NEW": FieldStats(nulls=0, violations=0,
                                                 values=["eth9"])},
               new={"NEW"})
    finding = _finding_for(win, None, "unmapped.NEW")
    assert (finding.field, finding.severity, finding.action) == (
        "unmapped.NEW", "minor", "alert")


def test_evaluate_unmapped_known_key_stays_none_even_with_terrible_rates():
    # Binding ruling: unmapped rows are new-key-emergence signals ONLY — null
    # rates are never re-derived into severity (10/10 nulls here stay 'none'),
    # and even a (defensive) baseline profile for an unmapped field is ignored.
    baseline = {"unmapped.IN": {"null_rate": 0.0, "shape_dist": {"ipv4": 1.0}}}
    win = _win(stats={"unmapped.IN": FieldStats(nulls=10, violations=0,
                                                values=[])},
               new=set())
    finding = _finding_for(win, baseline, "unmapped.IN")
    assert finding.severity == "none" and finding.action is None
    assert finding.stats["null_rate"] == 1.0   # measured + recorded, never acted on


def test_evaluate_zero_parsed_window_emits_only_the_rule_finding():
    win = _win(parsed=0, errors=3, stats={"src_endpoint.ip": _ip_stats()})
    findings = evaluate_window(win, None, rule_quarantined=[])
    assert [f.field for f in findings] == [RULE_FIELD]


def test_evaluate_emission_parity_with_window_rows():
    # record_windows overlays findings onto window_rows' measured rows, so the
    # two must emit the SAME field set for the same window (mapped, unmapped,
    # sentinel; zero-parsed case above).
    rows = ([(_ts(i), "parsed", _doc()) for i in range(2)]
            + [(_ts(2), "parsed", _doc(unmapped={"IN": "eth0", "Z": "1"}))])
    win = _windows(rows)[0]
    measured = [r[2] for r in window_rows(_rule(), [win])]
    evaluated = [f.field for f in evaluate_window(win, None, rule_quarantined=[])]
    assert evaluated == measured


# --- Task 5: merge_findings (R-M3-11 per-field max) -------------------------------


def test_merge_findings_takes_per_field_max_across_windows():
    findings = [
        Finding("src_endpoint.ip", "minor", "alert", {}, _ts(0)),
        Finding("src_endpoint.ip", "moderate", "field_quarantined", {}, _ts(60)),
        Finding("dst_endpoint.ip", "severe", "rule_deactivated", {}, _ts(60)),
        Finding("dst_endpoint.ip", "none", None, {}, _ts(120)),
    ]
    assert merge_findings(findings) == {
        "src_endpoint.ip": "moderate", "dst_endpoint.ip": "severe"}


def test_merge_findings_empty_is_empty():
    assert merge_findings([]) == {}


# --- Task 5: aggregate_baseline (the FIRST-N window aggregation) ------------------


def _hist_row(start_s, field, count, null_rate, match_rate, shape):
    return (_ts(start_s), field, count, null_rate, match_rate, shape)


def test_aggregate_baseline_matches_hand_computed_fixture():
    # Hand-computed: 3 windows, ip field nulls 0.1/0.2/0.3 -> mean 0.2; shapes
    # summed {ipv4: 18, free_text: 12} -> normalized 0.6/0.4; __rule__ match
    # 1.0/0.9/0.8 -> 0.9 with count bounds min 10 / max 14; unmapped excluded.
    rows = [
        _hist_row(0, "src_endpoint.ip", 10, 0.1, None, {"ipv4": 8, "free_text": 2}),
        _hist_row(0, RULE_FIELD, 10, None, 1.0, None),
        _hist_row(60, "src_endpoint.ip", 12, 0.2, None, {"ipv4": 6, "free_text": 4}),
        _hist_row(60, RULE_FIELD, 12, None, 0.9, None),
        _hist_row(120, "src_endpoint.ip", 14, 0.3, None, {"ipv4": 4, "free_text": 6}),
        _hist_row(120, RULE_FIELD, 14, None, 0.8, None),
        _hist_row(120, "unmapped.X", 14, 0.5, None, {"free_text": 3}),
    ]
    profiles = aggregate_baseline(rows, baseline_windows=3)

    assert set(profiles) == {"src_endpoint.ip", RULE_FIELD}   # unmapped skipped
    ip = profiles["src_endpoint.ip"]
    assert ip["null_rate"] == pytest.approx(0.2)
    assert ip["shape_dist"]["ipv4"] == pytest.approx(0.6)
    assert ip["shape_dist"]["free_text"] == pytest.approx(0.4)
    assert sum(ip["shape_dist"].values()) == pytest.approx(1.0)
    rule = profiles[RULE_FIELD]
    assert rule["match_rate"] == pytest.approx(0.9)
    assert rule["events_count"] == {"min": 10, "max": 14}


def test_aggregate_baseline_none_before_n_windows_exist():
    rows = [_hist_row(0, RULE_FIELD, 10, None, 1.0, None)]
    assert aggregate_baseline(rows, baseline_windows=10) is None
    assert aggregate_baseline([], baseline_windows=10) is None


def test_aggregate_baseline_uses_only_the_first_n_windows():
    # Windows 4 and 5 exist (null 0.9) but must NOT enter a 3-window baseline.
    rows = ([_hist_row(i * 60, "src_endpoint.ip", 10 + i, 0.1 + 0.1 * i, None,
                       {"ipv4": 10})
             for i in range(3)]
            + [_hist_row(240, "src_endpoint.ip", 99, 0.9, None, {"free_text": 10}),
               _hist_row(300, "src_endpoint.ip", 99, 0.9, None, {"free_text": 10})])
    profiles = aggregate_baseline(rows, baseline_windows=3)
    assert profiles["src_endpoint.ip"]["null_rate"] == pytest.approx(0.2)
    assert profiles["src_endpoint.ip"]["shape_dist"] == {"ipv4": 1.0}


def test_aggregate_baseline_skips_none_match_rates_in_mean():
    rows = [
        _hist_row(0, RULE_FIELD, 10, None, 1.0, None),
        _hist_row(60, RULE_FIELD, 10, None, 0.8, None),
        _hist_row(120, RULE_FIELD, 10, None, None, None),   # defensive NULL
    ]
    profiles = aggregate_baseline(rows, baseline_windows=3)
    assert profiles[RULE_FIELD]["match_rate"] == pytest.approx(0.9)
