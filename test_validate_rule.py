"""
Test script for P3's validate_rule().
Run with:  python3 test_validate_rule.py

Updated to validate against the OFFICIAL team fixtures (from P6) rather
than hand-made stand-ins. The real sample_rule.json uses the
extension-blob style (a single (?P<extension>...) group) mixed with one
directly-named header field (severity) — this is a genuine real-world
test of the dynamic orphan-detection logic in validate_rule().
"""
from pathlib import Path

from ingestion.validate_rule import validate_rule
from testdata.fixtures import load_rule

TESTDATA_DIR = Path(__file__).parent / "testdata"


def _load_cef_lines() -> list[str]:
    path = TESTDATA_DIR / "raw_logs_cef.txt"
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def test_official_rule_passes():
    print("--- Test 1: official team sample_rule.json should pass validation ---")
    rule = load_rule("sample_rule.json")
    held_out_lines = _load_cef_lines()  # all 3 official CEF lines
    result = validate_rule(rule, held_out_lines)

    print("checks:", result.checks)
    print("notes: ", result.notes)
    assert result.passed is True, "expected the official rule to pass"
    assert all(result.checks.values())
    print("PASSED\n")


def test_official_rule_extracts_expected_values():
    """
    Cross-check against sample_normalized_event.json's expected values —
    proves the official fixtures agree with each other, and that
    validate_rule's field extraction (including extension-blob parsing)
    lines up with what P2's apply_rule() is expected to produce.
    """
    print("--- Test 2: extracted fields match sample_normalized_event.json expectations ---")
    import re
    from ingestion.validate_rule import _extract_fields

    rule = load_rule("sample_rule.json")
    compiled = re.compile(rule.pattern)

    raw_text = (
        "CEF:0|PaloAlto|PAN-OS|10.1|THREAT|spyware|5|src=203.0.113.45 "
        "dst=192.168.1.10 spt=51422 dpt=443 act=block cat=spyware msg=Suspicious DNS Query"
    )
    match = compiled.search(raw_text)
    assert match is not None
    fields = _extract_fields(match, has_extension_group=True)

    assert fields["src"] == "203.0.113.45"
    assert fields["dst"] == "192.168.1.10"
    assert fields["spt"] == "51422"
    assert fields["dpt"] == "443"
    assert fields["act"] == "block"
    assert fields["severity"] == "5"
    assert fields["cat"] == "spyware"
    assert fields["msg"] == "Suspicious DNS Query"
    print("Extracted fields match expected values from sample_normalized_event.json.")
    print("PASSED\n")


def test_bad_rule_fails():
    print("--- Test 3: deliberately bad rule should fail validation ---")
    rule = load_rule("sample_rule_bad.json")
    held_out_lines = _load_cef_lines()[:2]  # first two lines, both have cat/msg
    result = validate_rule(rule, held_out_lines)

    print("checks:", result.checks)
    print("notes: ", result.notes)
    assert result.passed is False, "expected the bad rule to fail"
    assert result.checks["port_fields_look_like_ports"] is False
    assert result.checks["no_orphan_mappings"] is False
    print("PASSED (correctly rejected)\n")


def test_pattern_that_never_matches():
    print("--- Test 4: rule whose regex matches nothing should fail cleanly ---")
    rule = load_rule("sample_rule.json")
    result = validate_rule(rule, ["this line has nothing to do with CEF at all"])

    print("checks:", result.checks)
    print("notes: ", result.notes)
    assert result.passed is False
    assert result.checks["pattern_matches_all_lines"] is False
    print("PASSED (correctly rejected)\n")


if __name__ == "__main__":
    test_official_rule_passes()
    test_official_rule_extracts_expected_values()
    test_bad_rule_fails()
    test_pattern_that_never_matches()
    print("All P3 validate_rule() checks passed against official team fixtures.")
