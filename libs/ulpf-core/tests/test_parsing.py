# libs/ulpf-core/tests/test_parsing.py — key cases, all with concrete data:
from ulpf_core.parsing import parse, validate_rule_output, OCSF_TARGETS
from ulpf_core.models import Rule, Mapping

CEF_RULE = Rule(fingerprint_id="cef_paloalto", version=1,
    pattern=r"^.*\|(?P<extension>.*)$",
    mappings=[Mapping(source_field="src", ocsf_path="src_endpoint.ip"),
              Mapping(source_field="dst", ocsf_path="dst_endpoint.ip"),
              Mapping(source_field="spt", ocsf_path="src_endpoint.port"),
              Mapping(source_field="dpt", ocsf_path="dst_endpoint.port"),
              Mapping(source_field="act", ocsf_path="action"),
              Mapping(source_field="msg", ocsf_path="message")],
    provenance="human")
CEF_LINE = ("CEF:0|PaloAlto|PAN-OS|10.1|THREAT|spyware|5|src=203.0.113.45 "
            "dst=192.168.1.10 spt=51422 dpt=443 act=block cat=spyware msg=Suspicious DNS Query")

JSON_RULE = Rule(fingerprint_id="json", version=1, pattern="__JSON__",
    mappings=[Mapping(source_field="src_ip", ocsf_path="src_endpoint.ip"),
              Mapping(source_field="src_port", ocsf_path="src_endpoint.port"),
              Mapping(source_field="dest_ip", ocsf_path="dst_endpoint.ip"),
              Mapping(source_field="dest_port", ocsf_path="dst_endpoint.port"),
              Mapping(source_field="timestamp", ocsf_path="time"),
              Mapping(source_field="alert.severity", ocsf_path="severity_id"),
              Mapping(source_field="event_type", ocsf_path="action"),
              Mapping(source_field="alert.signature", ocsf_path="message")],
    provenance="human")

def test_parse_cef_core_fields():
    doc, err = parse(CEF_LINE, CEF_RULE)
    assert err is None
    assert doc["src_endpoint"] == {"ip": "203.0.113.45", "port": 51422}
    assert doc["dst_endpoint"]["port"] == 443
    assert doc["action"] == "block"
    assert doc["unmapped"]["cat"] == "spyware"          # never dropped (spec §6.4)
    assert doc["message"] == "Suspicious DNS Query"

def test_parse_no_match_is_error_not_raise():
    doc, err = parse("COMPLETELY UNRELATED", CEF_RULE)
    assert doc is None and "did not match" in err

def test_timeout_treated_as_error():                    # spec §10
    evil = Rule(fingerprint_id="x", version=1,
                pattern=r"(a+)+$", mappings=[], provenance="human")
    doc, err = parse("a" * 60 + "!", evil, timeout_ms=30)
    assert doc is None and ("timeout" in err or "did not match" in err)

def test_timeout_path_maps_timeouterror_to_error():     # spec §10 plumbing
    # (a|aa)+b cannot match (no 'b') and backtracks exponentially, so the
    # regex module's per-match timeout genuinely fires here (30ms ≪ full search).
    evil = Rule(fingerprint_id="x", version=1,
                pattern=r"(a|aa)+b", mappings=[], provenance="human")
    doc, err = parse("a" * 40, evil, timeout_ms=30)
    assert doc is None and "timeout" in err

def test_json_sentinel_path():                          # __JSON__ rule on golden JSON corpus line
    import json as _json
    from pathlib import Path
    line = (Path(__file__).parent / "data/golden/raw_logs_json.txt").read_text().splitlines()[0]
    src = _json.loads(line)["src_ip"]                   # expectation derived from the line itself
    doc, err = parse(line, JSON_RULE)
    assert err is None
    assert doc["src_endpoint"]["ip"] == src
    assert doc["metadata"] == {"product": "ULPF"}
    assert doc["unmapped"]                              # unmapped keys preserved, spec §6.4

def test_severity_text_does_not_crash():                # demo hot-path crash bug stays fixed
    import json as _json
    line = _json.dumps({"timestamp": "2026-08-27T14:32:07Z", "event_type": "alert",
                        "src_ip": "203.0.113.45", "dest_ip": "10.0.0.9",
                        "alert": {"severity": "high", "signature": "text severity probe"}})
    doc, err = parse(line, JSON_RULE)
    assert err is None and doc is not None and doc["severity_id"] is None

def test_must_be_allowlisted():
    rule = Rule(fingerprint_id="x", version=1, pattern=r"(?P<a>.*)",
                mappings=[Mapping(source_field="a", ocsf_path="evil.path")], provenance="human")
    errs = validate_rule_output(rule, ["sample"]); assert any("allow" in e for e in errs)

def test_activation_validation_passes_for_golden_cef():
    from pathlib import Path
    lines = (Path(__file__).parent / "data/golden/raw_logs_cef.txt").read_text().splitlines()
    assert validate_rule_output(CEF_RULE, lines) == []
