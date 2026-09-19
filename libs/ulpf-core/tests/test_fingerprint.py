# libs/ulpf-core/tests/test_fingerprint.py
import re
from pathlib import Path

from ulpf_core.fingerprint import fingerprint_id, shape_hash

GOLDEN = Path(__file__).parent / "data" / "golden"
LINES = {p.stem: [l for l in p.read_text().splitlines() if l.strip()] for p in GOLDEN.glob("raw_logs_*.txt")}

def test_known_formats():
    assert fingerprint_id(LINES["raw_logs_cef"][0]) == "cef_paloalto"
    assert fingerprint_id(LINES["raw_logs_syslog"][0]) == "syslog"
    assert fingerprint_id(LINES["raw_logs_json"][0]) == "json"

def test_unknown_gets_stable_auto_id():
    fp = fingerprint_id(LINES["raw_logs_acmegw"][0])
    assert re.fullmatch(r"auto_[0-9a-f]{8}", fp)

def test_two_unknown_vendors_differ():  # spec §9: no shared "unknown" bucket
    assert fingerprint_id(LINES["raw_logs_acmegw"][0]) != fingerprint_id(LINES["raw_logs_zenwall"][0])

def test_mutation_stability_within_format_group():
    # Invariant (spec §9): all lines of ONE format share one shape hash.
    # Group by fingerprint first — raw_logs_cef.txt mixes 3 CEF vendors,
    # and different vendors legitimately hash differently.
    groups: dict[str, set[str]] = {}
    for lines in LINES.values():
        for l in lines:
            groups.setdefault(fingerprint_id(l), set()).add(shape_hash(l))
    for fp, hashes in groups.items():
        assert len(hashes) == 1, f"{fp} fragmented into {len(hashes)} shapes: {hashes}"

def test_mutated_hostnames_and_numbers_stable():
    base = LINES["raw_logs_syslog"][0]
    mutated = re.sub(r"SRC=[\d.]+", "SRC=1.2.3.4", base)
    mutated = re.sub(r"DPT=\d+", "DPT=9999", mutated)
    assert shape_hash(mutated) == shape_hash(base)

def test_csv_and_xml_detected():
    assert fingerprint_id("a,b,c,1,2,3") == "csv"
    assert fingerprint_id("<event><src>1.2.3.4</src></event>") == "xml"

def test_deeply_nested_xml_cannot_wedge_fingerprint(monkeypatch):
    # R19 regression: on recursion-limited ElementTree builds the probe over a
    # deeply-nested hostile line raises RecursionError instead of ParseError.
    # RecursionError is not a ParseError, so an uncaught one escapes
    # fingerprint_id and wedges the pipeline batch (redelivery loop). It must
    # classify as "not xml" and fall through to the shape-hash path.
    import xml.etree.ElementTree as ET

    def recurse_forever(text):
        raise RecursionError("maximum recursion depth exceeded while parsing")

    monkeypatch.setattr(ET, "fromstring", recurse_forever)
    assert re.fullmatch(r"auto_[0-9a-f]{8}", fingerprint_id("<a>" * 100000))

def test_hostile_nested_xml_line_is_stable():
    # The literal hostile input: never raises, and the same line always gets
    # the same auto_ id (the truncation probe stays intact).
    line = "<a>" * 100000
    assert fingerprint_id(line).startswith("auto_")
    assert fingerprint_id(line) == fingerprint_id(line)

def test_hostile_kv_token_cannot_wedge_classify():
    # Same failure class as the XML probe (R19), one layer down: _classify
    # recursed once per "=" in a token, so a single token with thousands of
    # key=value layers raised RecursionError out of shape_hash and wedged the
    # pipeline batch. Classification must be iterative: no exception, and the
    # same line always gets the same shape hash / auto_ id.
    line = "a=" * 1200  # one token: no spaces or [|;,] separators
    assert shape_hash(line) == shape_hash(line)
    assert fingerprint_id(line) == fingerprint_id(line)
    assert fingerprint_id(line).startswith("auto_")

def test_deeply_nested_json_cannot_wedge_fingerprint():
    # Same failure class again (final-review critical): json.loads raises
    # RecursionError — not JSONDecodeError — for deeply-nested hostile text,
    # and the 65,536-char line cap does not bound nesting depth. This exact
    # line is 17,995 chars, so it reaches fingerprint_id via UDP/HTTP ingest.
    line = '{"a":' * 3000 + "1" + "}" * 3000
    fp = fingerprint_id(line)
    assert re.fullmatch(r"auto_[0-9a-f]{8}", fp)
    assert fp == fingerprint_id(line)
