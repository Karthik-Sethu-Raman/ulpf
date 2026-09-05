"""
testdata/check_fixtures.py

Sanity-checks every fixture file in testdata/fixtures/ against the shapes
in schemas.py, and flags specific known-suspicious patterns (like a Rule
whose field_mappings reference source_fields that aren't actually named
groups in its own regex pattern).

This does NOT require anyone else's module code to exist yet — it only
reads JSON fixture files and checks their shape/internal consistency.
Good to run early and re-run any time a fixture file changes.

Owner: P6
"""

import json
import re
from pathlib import Path

FIXTURES_DIR = Path("testdata/fixtures")


def load(name):
    path = FIXTURES_DIR / name
    if not path.exists():
        print(f"  [SKIP] {name} not found at {path}")
        return None
    with open(path) as f:
        return json.load(f)


def check_rule_fields_match_pattern(rule: dict, label: str):
    """
    For a Rule-shaped dict, verify every field_mappings[i].source_field
    actually appears as a named group in the regex pattern. This is the
    exact check validate_rule() is supposed to perform (P3's spec) —
    we replicate it here standalone so we can catch fixture bugs before
    anyone's real validate_rule() exists.
    """
    pattern = rule.get("pattern", "")
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        print(f"  [FAIL] {label}: pattern does not compile as regex: {e}")
        return

    named_groups = set(compiled.groupindex.keys())
    mapped_fields = {fm["source_field"] for fm in rule.get("field_mappings", [])}
    orphans = mapped_fields - named_groups

    if orphans:
        print(f"  [FAIL] {label}: field_mappings reference fields with NO matching "
              f"named group in pattern: {sorted(orphans)}")
        print(f"         named groups actually in pattern: {sorted(named_groups)}")
    else:
        print(f"  [PASS] {label}: all field_mappings have matching named groups "
              f"{sorted(mapped_fields)}")


def check_drift_sequence_thresholds(sequence: list[dict]):
    """
    Cross-check each drift_sequence.json entry's stated 'severity' against
    P5's own documented thresholds:
      ratio < 3x (or absolute diff < 0.05) -> none
      3x-6x   -> minor
      6x-15x  -> moderate
      >15x    -> severe
    Flags any mismatch so it can be raised with P5 before Day 3.
    """
    def expected_severity(null_rate, baseline):
        if baseline == 0:
            ratio = float("inf") if null_rate > 0 else 1.0
        else:
            ratio = null_rate / baseline
        diff = null_rate - baseline
        if ratio < 3 or diff < 0.05:
            return "none"
        elif ratio < 6:
            return "minor"
        elif ratio < 15:
            return "moderate"
        else:
            return "severe"

    for i, snap in enumerate(sequence):
        exp = expected_severity(snap["null_rate"], snap["baseline_null_rate"])
        actual = snap["severity"]
        status = "PASS" if exp == actual else "FAIL"
        marker = "  " if status == "PASS" else "->"
        print(f"  {marker}[{status}] window {snap.get('window_start')}-{snap.get('window_end')}: "
              f"null_rate={snap['null_rate']}, baseline={snap['baseline_null_rate']}, "
              f"fixture says '{actual}', threshold formula says '{exp}'")


def main():
    print("=== Checking Rule fixtures for orphan field_mappings ===")
    for name in ["sample_rule.json", "sample_rule_extension_style.json",
                 "sample_rule_bad.json", "bad_rule_fixture_syslog.json"]:
        rule = load(name)
        if rule is not None:
            check_rule_fields_match_pattern(rule, name)

    print("\n=== Checking sample_rule.json against sample_normalized_event.json ===")
    raw_event = load("sample_raw_event.json")
    rule = load("sample_rule.json")
    expected = load("sample_normalized_event.json")
    if raw_event and rule and expected:
        match = re.search(rule["pattern"], raw_event["raw_text"])
        if not match:
            print("  [FAIL] sample_rule.json's pattern does not even match sample_raw_event.json's raw_text")
        else:
            groups = match.groupdict()
            print(f"  Actual regex groups captured: {groups}")
            print(f"  Expected output requires individual src/dst/spt/dpt/act values — "
                  f"{'FOUND' if 'src' in groups else 'NOT FOUND'} as a named group")

    print("\n=== Checking drift_sequence.json against P5's stated thresholds ===")
    sequence = load("drift_sequence.json")
    if sequence is not None:
        check_drift_sequence_thresholds(sequence)

    print("\nDone. Review any [FAIL] lines above before Day 3 integration.")


if __name__ == "__main__":
    main()
