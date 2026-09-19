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
