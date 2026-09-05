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
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

FIXTURES_DIR = Path("testdata/fixtures")

# Try to import the REAL apply_rule() so we test against actual behavior,
# not a guess at what the regex "should" do. apply_rule() does a two-step
# parse for CEF-style rules (header regex + separate extension key=value
# split), so any static "are all field_mappings named groups" check is
# WRONG for those rules — it doesn't know about the extension step.
try:
    from parser_engine.apply_rule import apply_rule
    from schemas.schemas import RawEvent, Rule, FieldMapping
    APPLY_RULE_AVAILABLE = True
except ImportError as e:
    APPLY_RULE_AVAILABLE = False
    print(f"  [WARN] Could not import apply_rule() yet ({e}) — "
          f"falling back to a basic regex-compile check only.\n")


def load(name):
    path = FIXTURES_DIR / name
    if not path.exists():
        print(f"  [SKIP] {name} not found at {path}")
        return None
    with open(path) as f:
        return json.load(f)


def _dict_to_rule(rule_dict: dict) -> "Rule":
    mappings = [FieldMapping(**fm) for fm in rule_dict.get("field_mappings", [])]
    kwargs = dict(rule_dict)
    kwargs["field_mappings"] = mappings
    return Rule(**kwargs)


def check_rule_pattern_compiles(rule: dict, label: str):
    """Basic hygiene check: does the regex at least compile? Runs regardless
    of whether apply_rule() is importable yet."""
    pattern = rule.get("pattern", "")
    if pattern == "__JSON__":
        print(f"  [PASS] {label}: uses the special '__JSON__' path (no regex needed)")
        return
    try:
        re.compile(pattern)
        print(f"  [PASS] {label}: pattern compiles as valid regex")
    except re.error as e:
        print(f"  [FAIL] {label}: pattern does not compile as regex: {e}")


def check_rule_against_real_apply_rule(rule_dict: dict, raw_event_dict: dict, label: str):
    """
    The real check: actually run apply_rule() (P2's real code) against a raw
    event and see what happens. This replaces static guessing about regex
    groups, since apply_rule() may do extra parsing steps (like splitting a
    CEF 'extension' blob into key=value pairs) that a static check can't see.
    """
    if not APPLY_RULE_AVAILABLE:
        return
    try:
        rule = _dict_to_rule(rule_dict)
        raw_event = RawEvent(**raw_event_dict)
        result = apply_rule(raw_event, rule)
        print(f"  [PASS] {label}: apply_rule() ran successfully")
        print(f"         -> src_endpoint={result.src_endpoint}, "
              f"dst_endpoint={result.dst_endpoint}, action={result.action}")
    except Exception as e:
        print(f"  [FAIL] {label}: apply_rule() raised an error: {e}")


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
    print("=== Checking Rule fixtures compile as valid regex ===")
    rule_fixture_names = ["sample_rule.json", "sample_rule_extension_style.json",
                           "sample_rule_bad.json", "bad_rule_fixture_syslog.json"]
    rules = {}
    for name in rule_fixture_names:
        rule = load(name)
        rules[name] = rule
        if rule is not None:
            check_rule_pattern_compiles(rule, name)

    print("\n=== Running real apply_rule() against sample_rule.json + sample_raw_event.json ===")
    raw_event = load("sample_raw_event.json")
    if raw_event and rules.get("sample_rule.json"):
        check_rule_against_real_apply_rule(rules["sample_rule.json"], raw_event, "sample_rule.json")
        expected = load("sample_normalized_event.json")
        if expected and APPLY_RULE_AVAILABLE:
            try:
                rule = _dict_to_rule(rules["sample_rule.json"])
                re_obj = RawEvent(**raw_event)
                result = apply_rule(re_obj, rule)
                mismatches = []
                if result.src_endpoint != expected.get("src_endpoint"):
                    mismatches.append(f"src_endpoint: got {result.src_endpoint}, expected {expected.get('src_endpoint')}")
                if result.dst_endpoint != expected.get("dst_endpoint"):
                    mismatches.append(f"dst_endpoint: got {result.dst_endpoint}, expected {expected.get('dst_endpoint')}")
                if result.action != expected.get("action"):
                    mismatches.append(f"action: got {result.action}, expected {expected.get('action')}")
                if mismatches:
                    print(f"  [FAIL] output doesn't match sample_normalized_event.json:")
                    for m in mismatches:
                        print(f"         {m}")
                else:
                    print(f"  [PASS] output matches sample_normalized_event.json exactly")
            except Exception as e:
                print(f"  [FAIL] could not compare output: {e}")

    print("\n=== Sanity-checking known-bad rule fixtures still fail cleanly ===")
    for name in ["sample_rule_bad.json", "bad_rule_fixture_syslog.json"]:
        rule = rules.get(name)
        if rule and raw_event:
            # These are EXPECTED to fail or produce garbage — just confirm
            # apply_rule() doesn't crash the whole script (raising ValueError
            # is fine/expected; an unhandled crash type would not be).
            check_rule_against_real_apply_rule(rule, raw_event, f"{name} (expected to misbehave)")

    print("\n=== Checking drift_sequence.json against P5's stated thresholds ===")
    sequence = load("drift_sequence.json")
    if sequence is not None:
        check_drift_sequence_thresholds(sequence)

    print("\nDone. Review any [FAIL] lines above before Day 3 integration.")


if __name__ == "__main__":
    main()
