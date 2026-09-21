# libs/ulpf-core/tests/test_drift.py — the pure drift-math module, all with concrete data:
import math

import pytest
from ulpf_core.drift import (
    SEVERITIES,
    classify_value,
    decide_action,
    js_divergence,
    match_rate_severity,
    null_rate_severity,
    shape_histogram,
    shape_severity,
    tier1_severity,
    volume_severity,
)

# --- classify_value / shape_histogram ----------------------------------------

def test_classify_value_classes():
    assert classify_value("198.51.100.4") == "ipv4"
    assert classify_value(52114) == "int" and classify_value("52114") == "int"
    assert classify_value("2026-09-19T10:00:03Z") == "timestamp"
    assert classify_value("2026/09/19 10:00:03") == "timestamp"
    assert classify_value("DROP IN=eth0") == "free_text"
    assert classify_value(3.14) == "free_text"                  # no float class

def test_classify_value_ip_must_be_dotted_quad():
    assert classify_value("1.2.3.4.5") == "free_text"           # five groups
    assert classify_value("1.2.3") == "free_text"
    assert classify_value("999.999.999.999") == "ipv4"          # shape-level: 4 digit quads

def test_classify_value_bool_is_not_int():
    assert classify_value(True) == "free_text"                  # bool is an int subclass
    assert classify_value("007") == "int"                       # digit-string, leading zeros fine

def test_classify_value_none_free_contract():
    with pytest.raises(ValueError):                             # callers filter nulls first
        classify_value(None)

def test_shape_histogram_counts():
    values = ["1.2.3.4", "5", "5", "hello", 7, "2026-09-19T00:00:00Z"]
    assert shape_histogram(values) == {"ipv4": 1, "int": 3, "free_text": 1, "timestamp": 1}

def test_shape_histogram_empty():
    assert shape_histogram([]) == {}

# --- js_divergence ------------------------------------------------------------

def test_js_identity_is_zero():
    assert js_divergence({"ipv4": 90, "int": 10}, {"ipv4": 90, "int": 10}) == 0.0

def test_js_symmetric():
    p, q = {"ipv4": 90, "int": 10}, {"ipv4": 10, "int": 90}
    assert js_divergence(p, q) == pytest.approx(js_divergence(q, p))

def test_js_smoothing_keeps_unseen_key_finite():
    d = js_divergence({"ipv4": 100}, {"int": 100})              # disjoint supports
    assert math.isfinite(d) and 0 < d < math.log(2)

def test_js_disjoint_smoothed_value():
    # add-1 over the union: (11/12, 1/12) vs (1/12, 11/12) -> JS = 0.406311...
    assert js_divergence({"a": 10}, {"b": 10}) == pytest.approx(0.4063111975, abs=1e-6)

def test_js_grows_toward_ln2_as_counts_grow():
    small = js_divergence({"a": 10}, {"b": 10})
    big = js_divergence({"a": 10000}, {"b": 10000})
    assert big > small and big == pytest.approx(math.log(2), abs=5e-3)

def test_js_empty_histograms():
    assert js_divergence({}, {}) == 0.0

# --- null-rate ladder (legacy 3x/10x/40x + 0.05 abs gate) ---------------------
# Dyadic-friendly rates so the ratios land exactly ON the boundaries under test.

def test_null_ratio_just_below_3x_none():
    assert null_rate_severity(0.0934375, 0.03125) == "none"     # 2.99x, diff 0.0622 >= 0.05

def test_null_ratio_exactly_3x_minor():
    assert null_rate_severity(0.09375, 0.03125) == "minor"      # 3.0x exact, diff 0.0625

def test_null_ratio_just_below_10x_minor():
    assert null_rate_severity(0.1546875, 0.015625) == "minor"   # 9.9x

def test_null_ratio_exactly_10x_moderate():
    assert null_rate_severity(0.15625, 0.015625) == "moderate"  # 10.0x exact

def test_null_ratio_just_below_40x_moderate():
    assert null_rate_severity(0.15234375, 0.00390625) == "moderate"   # 39x

def test_null_ratio_exactly_40x_severe():
    assert null_rate_severity(0.15625, 0.00390625) == "severe"  # 40.0x exact

def test_null_abs_gate_suppresses_tiny_baseline_ratio():
    assert null_rate_severity(0.04, 0.004) == "none"            # 10x ratio but diff 0.036 < 0.05

def test_null_abs_diff_exactly_05_not_suppressed():
    assert null_rate_severity(0.065625, 0.015625) == "minor"    # diff exactly 0.05, ratio 4.2x

def test_null_baseline_zero_current_zero_none():
    assert null_rate_severity(0.0, 0.0) == "none"               # ratio defined as 1.0

def test_null_baseline_zero_current_positive_severe():
    assert null_rate_severity(0.3, 0.0) == "severe"             # inf ratio: field went null

def test_null_steady_state_none():
    assert null_rate_severity(0.2, 0.2) == "none"               # ratio 1, diff 0

# --- match-rate drop ladder (<0.10 / <0.25 / <0.50) ---------------------------

def test_match_drop_below_10pp_none():
    assert match_rate_severity(0.6875, 0.75) == "none"          # drop 0.0625

def test_match_drop_exactly_10pp_minor():
    assert match_rate_severity(0.9, 1.0) == "minor"             # nominal 0.10 (quantized to 6dp)

def test_match_drop_just_below_25pp_minor():
    assert match_rate_severity(0.25390625, 0.5) == "minor"      # drop 0.2461

def test_match_drop_exactly_25pp_moderate():
    assert match_rate_severity(0.25, 0.5) == "moderate"         # drop 0.25

def test_match_drop_just_below_50pp_moderate():
    assert match_rate_severity(0.25390625, 0.75) == "moderate"  # drop 0.4961

def test_match_drop_exactly_50pp_severe():
    assert match_rate_severity(0.25, 0.75) == "severe"          # drop 0.50

def test_match_improvement_none():
    assert match_rate_severity(0.9, 0.5) == "none"              # negative drop: rule got better

# --- shape / tier-1 / volume ladders ------------------------------------------

def test_shape_severity_bands():
    assert shape_severity(0.0) == "none" and shape_severity(0.149) == "none"
    assert shape_severity(0.15) == "minor" and shape_severity(0.34) == "minor"
    assert shape_severity(0.35) == "moderate" and shape_severity(0.59) == "moderate"
    assert shape_severity(0.60) == "severe" and shape_severity(0.9) == "severe"

def test_tier1_severity_bands():
    assert tier1_severity(0.0) == "none" and tier1_severity(0.049) == "none"
    assert tier1_severity(0.05) == "minor" and tier1_severity(0.19) == "minor"
    assert tier1_severity(0.20) == "moderate" and tier1_severity(0.49) == "moderate"
    assert tier1_severity(0.50) == "severe" and tier1_severity(1.0) == "severe"

def test_volume_silence_is_severe():
    assert volume_severity(0, 50, 100) == "severe"              # dead feed never looks healthy
    assert volume_severity(0, 0, 100) == "severe"               # even though 0 is inside bounds

def test_volume_inside_bounds_none():
    assert volume_severity(50, 50, 100) == "none"               # ON p05
    assert volume_severity(100, 50, 100) == "none"              # ON p95
    assert volume_severity(75, 50, 100) == "none"

def test_volume_outside_bounds_minor():
    assert volume_severity(49, 50, 100) == "minor"              # drought
    assert volume_severity(101, 50, 100) == "minor"             # flood

# --- severity -> action mapping -----------------------------------------------

def test_decide_action_full_mapping():                           # spec §7.2 graduated enforcement
    expected = [None, "alert", "field_quarantined", "rule_deactivated"]
    assert [decide_action(s) for s in SEVERITIES] == expected
    assert decide_action("none") is None

def test_severities_tuple():
    assert SEVERITIES == ("none", "minor", "moderate", "severe")
