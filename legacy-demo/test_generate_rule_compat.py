"""
Simulated compatibility test between P1's generate_rule() approach and
P3's validate_rule().

We can't run the actual local SLM (Ollama) in this environment, so
instead we hand-construct Rule objects in the EXACT shapes P1's prompt
is designed to produce (per onboarding/generate_rule.py's own few-shot
example and header-skipping strategy), then run them through the real
validate_rule() to prove compatibility ahead of time.

Two realistic variants are tested, since an LLM won't always name its
capture groups the same way run to run:

  Variant A — capture group names match the log's own literal keys
              (src, dst, spt, dpt, act) — this is what you'd get if the
              model just echoes the field names it sees in the log.

  Variant B — capture group names are renamed to semantic labels
              (src_ip, src_port, dst_ip, dst_port, action) — this is
              what the few-shot example in generate_rule.py actually
              demonstrates to the model, so it's arguably the MORE
              likely output style in practice.
"""
from datetime import datetime, timezone
from pathlib import Path

from schemas.schemas import Rule, FieldMapping
from ingestion.validate_rule import validate_rule

# Read directly from the official team test-data file, rather than a
# hardcoded copy, so this test always reflects the real shared fixtures.
_CEF_FILE = Path(__file__).parent / "testdata" / "raw_logs_cef.txt"
ALL_CEF_LINES = [line.strip() for line in _CEF_FILE.read_text().splitlines() if line.strip()]

# Pretend generate_rule() only ever saw line 0 as its "sample" — lines 1
# and 2 stand in as genuine held-out data, never shown to the "model".
HELD_OUT_LINES = ALL_CEF_LINES[1:]


def _fake_generated_rule_variant_a() -> Rule:
    """Capture groups named after the log's own literal keys."""
    pattern = (
        r"^CEF:[\d.]+\|.*\|"
        r"src=(?P<src>[\d.]+)\s+dst=(?P<dst>[\d.]+)\s+"
        r"spt=(?P<spt>\d+)\s+dpt=(?P<dpt>\d+)\s+act=(?P<act>\w+)"
    )  # no trailing $ anchor — official lines may have more fields (cat=, msg=) after act=
    field_mappings = [
        FieldMapping(source_field="src", ocsf_path="src_endpoint.ip"),
        FieldMapping(source_field="dst", ocsf_path="dst_endpoint.ip"),
        FieldMapping(source_field="spt", ocsf_path="src_endpoint.port"),
        FieldMapping(source_field="dpt", ocsf_path="dst_endpoint.port"),
        FieldMapping(source_field="act", ocsf_path="action"),
    ]
    return Rule(
        fingerprint_id="cef_test",
        pattern=pattern,
        field_mappings=field_mappings,
        confidence=1.0,
        provenance="slm-generated",
        version=1,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def _fake_generated_rule_variant_b() -> Rule:
    """Capture groups renamed to semantic labels, matching the exact
    style shown in generate_rule.py's own few-shot example."""
    pattern = (
        r"^CEF:[\d.]+\|.*\|"
        r"src=(?P<src_ip>[\d.]+)\s+dst=(?P<dst_ip>[\d.]+)\s+"
        r"spt=(?P<src_port>\d+)\s+dpt=(?P<dst_port>\d+)\s+act=(?P<action>\w+)"
    )  # no trailing $ anchor — official lines may have more fields (cat=, msg=) after act=
    field_mappings = [
        FieldMapping(source_field="src_ip", ocsf_path="src_endpoint.ip"),
        FieldMapping(source_field="dst_ip", ocsf_path="dst_endpoint.ip"),
        FieldMapping(source_field="src_port", ocsf_path="src_endpoint.port"),
        FieldMapping(source_field="dst_port", ocsf_path="dst_endpoint.port"),
        FieldMapping(source_field="action", ocsf_path="action"),
    ]
    return Rule(
        fingerprint_id="cef_test",
        pattern=pattern,
        field_mappings=field_mappings,
        confidence=1.0,
        provenance="slm-generated",
        version=1,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def test_variant_a():
    print("--- Variant A: capture groups = literal log keys (src, dst, spt, dpt, act) ---")
    rule = _fake_generated_rule_variant_a()
    result = validate_rule(rule, HELD_OUT_LINES)
    print("checks:", result.checks)
    print("notes: ", result.notes)
    assert result.passed is True
    print("COMPATIBLE\n")


def test_variant_b():
    print("--- Variant B: capture groups = semantic names (src_ip, dst_ip, ...) ---")
    rule = _fake_generated_rule_variant_b()
    result = validate_rule(rule, HELD_OUT_LINES)
    print("checks:", result.checks)
    print("notes: ", result.notes)
    assert result.passed is True
    print("COMPATIBLE\n")


if __name__ == "__main__":
    test_variant_a()
    test_variant_b()
    print("validate_rule() is compatible with both plausible generate_rule() output styles.")
