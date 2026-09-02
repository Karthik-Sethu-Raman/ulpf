"""
onboarding/test_generate_rule.py

Formalizes P1's day-1 definition-of-done checkpoint from ROLE_P1.md.
Run with: pytest onboarding/test_generate_rule.py -v
"""

import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from onboarding.generate_rule import generate_rule  # noqa: E402


def _load_cef_lines():
    path = os.path.join(os.path.dirname(__file__), "..", "testdata", "raw_logs_cef.txt")
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def test_generate_rule_produces_valid_regex():
    lines = _load_cef_lines()
    rule = generate_rule("cef_test", lines)
    # must not raise — re.compile inside generate_rule already validated this,
    # this just re-confirms at the test level
    re.compile(rule.pattern)


def test_generate_rule_extracts_core_fields_on_majority_of_lines():
    lines = _load_cef_lines()
    rule = generate_rule("cef_test", lines)
    compiled = re.compile(rule.pattern)

    matches = 0
    for line in lines:
        m = compiled.search(line)
        if m and all(k in m.groupdict() and m.groupdict()[k] for k in ("src_ip", "dst_ip")):
            matches += 1

    # day-1 bar: at least 2 of 3 sample lines match with src/dst extracted
    assert matches >= 2, f"only {matches}/{len(lines)} lines matched with src_ip+dst_ip populated"


def test_generate_rule_maps_required_ocsf_fields():
    lines = _load_cef_lines()
    rule = generate_rule("cef_test", lines)
    mapped = {fm.ocsf_path for fm in rule.field_mappings}
    assert "src_endpoint.ip" in mapped
    assert "dst_endpoint.ip" in mapped


def test_generate_rule_confidence_in_range():
    lines = _load_cef_lines()
    rule = generate_rule("cef_test", lines)
    assert 0.0 <= rule.confidence <= 1.0


def test_generate_rule_consistency_across_runs():
    """Not a hard pass/fail — prints confidence across 3 runs so you can
    eyeball whether the model is stable or noisy. Useful before deciding
    whether to stick with 3B or move to 8B."""
    lines = _load_cef_lines()
    confidences = []
    for i in range(3):
        rule = generate_rule("cef_test", lines)
        confidences.append(rule.confidence)
    print(f"\nConfidence across 3 runs: {confidences}")
    # loose sanity check only — real judgment call is yours based on the printed spread
    assert all(0.0 <= c <= 1.0 for c in confidences)