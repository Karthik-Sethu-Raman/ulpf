"""
onboarding/test_multi_format.py

Manual exploration script — not a strict pass/fail test like
test_generate_rule.py. Run this to see how the SLM handles syslog and
JSON, which are structurally very different from CEF (no delimiters at
all in raw syslog; nested structure in JSON).

Run: python onboarding/test_multi_format.py
"""

import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from onboarding.generate_rule import generate_rule  # noqa: E402


def load_lines(filename):
    path = os.path.join(os.path.dirname(__file__), "..", "testdata", filename)
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def try_format(fingerprint_id, filename):
    print(f"\n{'=' * 60}\n{fingerprint_id} ({filename})\n{'=' * 60}")
    lines = load_lines(filename)
    try:
        rule = generate_rule(fingerprint_id, lines)
    except RuntimeError as e:
        print(f"FAILED to generate: {e}")
        return

    compiled = re.compile(rule.pattern)
    matches = sum(1 for l in lines if compiled.search(l))
    print(f"Pattern: {rule.pattern}")
    print(f"Field mappings: {[(fm.source_field, fm.ocsf_path) for fm in rule.field_mappings]}")
    print(f"Confidence: {rule.confidence}")
    print(f"Match rate: {matches}/{len(lines)} lines")


if __name__ == "__main__":
    try_format("syslog_test", "raw_logs_syslog.txt")
    try_format("json_test", "raw_logs_json.txt")