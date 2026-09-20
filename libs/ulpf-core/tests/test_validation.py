# libs/ulpf-core/tests/test_validation.py — the candidate validation gate, all with concrete data:
import dataclasses
import json
import random

import pytest
from ulpf_core import validation
from ulpf_core.fingerprint import shape_hash
from ulpf_core.models import Mapping, Rule
from ulpf_core.validation import (
    CandidateReport,
    find_hardcoded_literals,
    mutate_line,
    report_to_json,
    validate_candidate,
)

ACME = [
    "ACMEGW fw01 2026-09-19T10:00:03Z DROP IN=eth0 OUT= SRC=198.51.100.4 DST=203.0.113.9 SPT=52114 DPT=8443",
    "ACMEGW fw02 2026-09-19T10:00:11Z ACCEPT IN=eth1 OUT= SRC=198.51.100.9 DST=203.0.113.4 SPT=49300 DPT=443",
]

# The brief's kv_rule pinned literal DROP, but its own ACME held-out line is an
# ACCEPT event and test_valid_rule_passes_all_checks expects
# held_out_match_rate == 1.0 — so the pattern accepts both actions (the
# fixture's DROP/ACCEPT variety is clearly deliberate).
def kv_rule(pattern=r"^.*?(?:DROP|ACCEPT)\s+(?P<extension>.*)$"):
    return Rule(fingerprint_id="auto_x", version=1, pattern=pattern, provenance="human",
                mappings=[Mapping(source_field=k, ocsf_path=p) for k, p in [
                    ("SRC", "src_endpoint.ip"), ("DST", "dst_endpoint.ip"),
                    ("SPT", "src_endpoint.port"), ("DPT", "dst_endpoint.port")]])

def json_rule():
    return Rule(fingerprint_id="json_x", version=1, pattern="__JSON__", provenance="human",
                mappings=[Mapping(source_field=s, ocsf_path=o) for s, o in [
                    ("src_ip", "src_endpoint.ip"), ("src_port", "src_endpoint.port"),
                    ("dest_ip", "dst_endpoint.ip"), ("dest_port", "dst_endpoint.port"),
                    ("timestamp", "time"), ("alert.severity", "severity_id"),
                    ("event_type", "action"), ("alert.signature", "message")]])

def jline(src="198.51.100.4", dst="203.0.113.9", sev=3):
    return json.dumps({"timestamp": "2026-09-19T10:00:03Z", "event_type": "alert",
                       "src_ip": src, "src_port": 52114, "dest_ip": dst, "dest_port": 8443,
                       "alert": {"severity": sev, "signature": "suspicious dns query"}},
                      separators=(",", ":"))

def test_valid_rule_passes_all_checks():
    report = validate_candidate(kv_rule(), ACME[:1], ACME[1:])
    assert report.passed and all(report.checks.values())
    assert report.held_out_match_rate == 1.0
    assert len(report.previews) == 1 and report.previews[0]["status"] == "parsed"

def test_pattern_missing_line_fails_match_all():
    bad = kv_rule(pattern=r"^NOMATCH.*$")
    report = validate_candidate(bad, ACME[:1], ACME[1:])
    assert report.checks["samples_parse"] is False or report.checks["held_out_match_all"] is False
    assert report.passed is False

def test_hardcoded_hostname_caught_by_probe_and_literal_check():
    hardcoded = kv_rule(pattern=r"^ACMEGW fw01 2026-09-19T10:00:03Z DROP\s+(?P<extension>.*)$")
    assert find_hardcoded_literals(hardcoded.pattern, ACME[:1])  # ts + hostname literals
    report = validate_candidate(hardcoded, ACME[:1], ACME[1:])
    assert report.passed is False  # held-out line has different ts/host -> no match

def test_orphan_mapping_fails():
    rule = kv_rule()
    rule = Rule(**{**rule.model_dump(),
                   "mappings": rule.mappings + [Mapping(source_field="NOPE", ocsf_path="action")]})
    report = validate_candidate(rule, ACME[:1], ACME[1:])
    assert report.checks["no_orphan_mappings"] is False

def test_mutate_line_changes_values_not_shape():
    rng = random.Random(7)
    m = mutate_line(ACME[0], rng)
    assert m != ACME[0] and "SRC=" in m and "DST=" in m

def test_no_samples_degrades_gracefully():
    report = validate_candidate(kv_rule(), [], [])
    assert report.passed is True and any("no samples" in n for n in report.notes)

def test_report_to_json_shape():
    j = report_to_json(validate_candidate(kv_rule(), ACME[:1], ACME[1:]))
    assert set(j) == {"passed", "checks", "held_out_match_rate", "notes", "previews",
                      "prompt_count", "held_out_count"}

# --- additional cases --------------------------------------------------------

def test_port_out_of_range_fails_port_fields_valid():   # mapped value AFTER parse
    line = ("ACMEGW fw01 2026-09-19T10:00:03Z DROP IN=eth0 OUT= "
            "SRC=198.51.100.4 DST=203.0.113.9 SPT=70000 DPT=443")
    report = validate_candidate(kv_rule(), ACME[:1], [line])
    assert report.checks["port_fields_valid"] is False and report.passed is False

def test_non_ip_fails_ip_fields_valid():
    line = ("ACMEGW fw01 2026-09-19T10:00:03Z DROP IN=eth0 OUT= "
            "SRC=banana DST=203.0.113.9 SPT=52114 DPT=443")
    report = validate_candidate(kv_rule(), ACME[:1], [line])
    assert report.checks["ip_fields_valid"] is False and report.passed is False

def test_json_sentinel_rule_validates():                # __JSON__ via the JSON path
    report = validate_candidate(json_rule(), [jline()],
                                [jline(src="198.51.100.8", dst="203.0.113.3", sev=5)])
    assert report.passed and all(report.checks.values())
    assert report.held_out_match_rate == 1.0

def test_adversarial_probe_20_mutants_per_prompt_line():
    assert validation.PROBE_MUTANTS_PER_LINE == 20
    brittle = kv_rule(r"^ACMEGW \S+ 2026-09-19T10:00:03Z (?:DROP|ACCEPT)\s+(?P<extension>.*)$")
    report = validate_candidate(brittle, ACME[:1], ACME[1:])
    assert report.checks["adversarial_probe"] is False and report.passed is False

def test_validate_rule_output_failures_surface_as_caps_and_allowlist():
    oversized = kv_rule(pattern="^(?:a|b)" * 400 + r"(?P<extension>.*)$")  # > 1000 chars
    report = validate_candidate(oversized, ACME[:1], ACME[1:])
    assert report.checks["caps_and_allowlist"] is False and report.passed is False
    assert any("cap" in n for n in report.notes)
    base = kv_rule()
    evil = Rule(**{**base.model_dump(),
                   "mappings": base.mappings
                   + [Mapping(source_field="SRC", ocsf_path="evil.path")]})
    report = validate_candidate(evil, ACME[:1], ACME[1:])
    assert report.checks["caps_and_allowlist"] is False and any("allow" in n for n in report.notes)

def test_severity_out_of_range_fails_value_sanity():    # severity must be int 0-6 or None
    report = validate_candidate(json_rule(), [], [jline(sev=9)])
    assert report.checks["samples_parse"] is False and report.passed is False
    assert any("severity" in n for n in report.notes)

def test_mutate_line_preserves_shape_hash():            # probe premise: shape must not move
    rng = random.Random(7)
    m = mutate_line(ACME[0], rng)
    assert shape_hash(m) == shape_hash(ACME[0]) and "DROP" in m

def test_previews_capped_at_five_and_counts_recorded():
    held = [f"ACMEGW fw0{i} 2026-09-19T10:00:{i:02d}Z DROP IN=eth0 OUT= "
            f"SRC=198.51.100.{i} DST=203.0.113.{i} SPT=5000{i} DPT=44{i}" for i in range(7)]
    report = validate_candidate(kv_rule(), ACME[:1], held)
    assert len(report.previews) == 5
    assert all(set(p) == {"line", "status", "ocsf"} for p in report.previews)
    assert report.held_out_match_rate == 1.0
    j = report_to_json(report)
    assert j["prompt_count"] == 1 and j["held_out_count"] == 7

def test_hardcoded_literals_common_values_not_flagged():
    # Lines differ in host/IP/port but share the timestamp: the shared ts is
    # common to every line and must not count as hardcoded, unlike fw01 below.
    same_ts = [
        ("ACMEGW fw01 2026-09-19T10:00:03Z DROP IN=eth0 OUT= "
         "SRC=198.51.100.4 DST=203.0.113.9 SPT=52114 DPT=8443"),
        ("ACMEGW fw09 2026-09-19T10:00:03Z DROP IN=eth0 OUT= "
         "SRC=198.51.100.8 DST=203.0.113.3 SPT=52115 DPT=8444"),
    ]
    generic = kv_rule()
    assert find_hardcoded_literals(generic.pattern, same_ts) == []
    pinned = r"^ACMEGW fw01 \S+ (?:DROP|ACCEPT)\s+(?P<extension>.*)$"
    assert "fw01" in find_hardcoded_literals(pinned, same_ts)

def test_candidate_report_is_frozen_dataclass():
    report = validate_candidate(kv_rule(), ACME[:1], ACME[1:])
    assert isinstance(report, CandidateReport)
    with pytest.raises(dataclasses.FrozenInstanceError):
        report.passed = False
