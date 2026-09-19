"""
parser_engine/test_parser_engine.py

Day 1 & Day 2 Unit Tests for P2 Parser Engine in ULPF.
Verifies fingerprint() and apply_rule() against testdata fixtures.
"""

import json
from pathlib import Path

import pytest
import sys
import os

# Make sure ulpf modules are importable
ULPF_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ULPF_DIR))

from schemas.schemas import RawEvent, Rule, FieldMapping
from parser_engine.fingerprint import fingerprint
from parser_engine.apply_rule import apply_rule
from parser_engine.rule_store import load_rule_from_json, register_rule, get_rule, clear_rules


FIXTURES_DIR = ULPF_DIR / "testdata" / "fixtures"
TESTDATA_DIR = ULPF_DIR / "testdata"


def load_fixture_json(filename: str) -> dict:
    return json.loads((FIXTURES_DIR / filename).read_text(encoding="utf-8"))


def test_fingerprint_cef():
    cef_lines = (TESTDATA_DIR / "raw_logs_cef.txt").read_text().splitlines()
    assert fingerprint(cef_lines[0]).startswith("cef")


def test_fingerprint_syslog():
    syslog_lines = (TESTDATA_DIR / "raw_logs_syslog.txt").read_text().splitlines()
    assert fingerprint(syslog_lines[0]) == "syslog"


def test_fingerprint_json():
    json_lines = (TESTDATA_DIR / "raw_logs_json.txt").read_text().splitlines()
    assert fingerprint(json_lines[0]) == "json"


def test_fingerprint_unknown():
    assert fingerprint("some random application log string") == "unknown"


def test_apply_rule_definition_of_done():
    """Verify Day 1 checkpoint assertions from ROLE_P2.md."""
    raw_data = load_fixture_json("sample_raw_event.json")
    rule_data = load_fixture_json("sample_rule.json")

    raw_event = RawEvent(**raw_data)
    rule = Rule(
        fingerprint_id=rule_data["fingerprint_id"],
        pattern=rule_data["pattern"],
        field_mappings=[FieldMapping(**fm) for fm in rule_data["field_mappings"]],
        confidence=rule_data["confidence"],
        provenance=rule_data["provenance"],
        version=rule_data["version"],
        created_at=rule_data["created_at"],
    )

    result = apply_rule(raw_event, rule)

    # Assertions specified in ROLE_P2.md definition of done:
    assert result.src_endpoint["ip"] == "203.0.113.45"
    assert result.dst_endpoint["port"] == 443
    assert result.raw_id == "raw_00042"
    assert result.action == "block"
    assert "cat" in result.unmapped_fields
    assert result.unmapped_fields["cat"] == "spyware"
    assert result.unmapped_fields["msg"] == "Suspicious DNS Query"


def test_apply_rule_mismatch():
    """Verify apply_rule raises ValueError when pattern fails to match."""
    raw_event = RawEvent(
        raw_id="raw_999",
        source_id="fw01",
        timestamp_ingested="2026-08-27T14:32:10+05:30",
        format_guess="cef",
        raw_text="INVALID NON MATCHING LOG LINE",
    )
    rule_data = load_fixture_json("sample_rule.json")
    rule = Rule(
        fingerprint_id=rule_data["fingerprint_id"],
        pattern=rule_data["pattern"],
        field_mappings=[FieldMapping(**fm) for fm in rule_data["field_mappings"]],
        confidence=rule_data["confidence"],
        provenance=rule_data["provenance"],
        version=rule_data["version"],
        created_at=rule_data["created_at"],
    )

    with pytest.raises(ValueError) as excinfo:
        apply_rule(raw_event, rule)
    assert "did not match" in str(excinfo.value)


def test_rule_store():
    """Test loading and registering rules in rule_store."""
    clear_rules()
    rule = load_rule_from_json(FIXTURES_DIR / "sample_rule.json")
    assert rule.fingerprint_id == "cef_paloalto_v1"
    fetched = get_rule("cef_paloalto_v1")
    assert fetched is not None
    assert fetched.pattern == rule.pattern
