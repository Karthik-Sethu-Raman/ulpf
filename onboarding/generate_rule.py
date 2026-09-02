"""
onboarding/generate_rule.py

Given raw sample log lines of an unrecognized format, ask a local SLM
(via Ollama) to generate a candidate parsing rule: a regex with named
capture groups, plus a mapping from each captured field to an OCSF
field path.

Requires: pip install ollama
Requires: ollama running locally with a pulled model (see MODEL_NAME below)
"""

import json
import re
import sys
import os
from datetime import datetime, timezone

# Make schemas importable whether this file is run from repo root or from
# inside onboarding/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from schemas.schemas import Rule, FieldMapping  # noqa: E402

# pyrefly: ignore [missing-import]
import ollama  # noqa: E402


MODEL_NAME = "ibm/granite4.1:3b"  # fallback: "qwen3.5:4b" — check `ollama list` for exact local tag

# Keep this short and targeted — do NOT dump the full OCSF spec into the prompt.
OCSF_TARGET_FIELDS = [
    "src_endpoint.ip",
    "src_endpoint.port",
    "dst_endpoint.ip",
    "dst_endpoint.port",
    "time",
    "severity_id",
    "action",
    "message",
]

# One worked example, in a DIFFERENT vendor format but the SAME general
# shape (pipe-delimited header + space-separated key=value extension) as
# CEF/LEEF — this teaches the model the right structural pattern instead
# of inventing a garbled hybrid. A structurally-unrelated example (e.g.
# plain syslog) taught the model the wrong lesson in testing.
FEW_SHOT_EXAMPLE_INPUT = """Sample log lines:
LEEF:2.0|Acme|NetGuard|3.2|401|src=198.51.100.7 srcPort=44521 dst=192.168.1.5 dstPort=443 proto=TCP action=allow msg=Session started
LEEF:2.0|Acme|NetGuard|3.2|402|src=203.0.113.9 srcPort=51002 dst=192.168.1.6 dstPort=22 proto=TCP action=deny msg=Blocked login attempt
"""

FEW_SHOT_EXAMPLE_OUTPUT = {
    "pattern": (
        r"^LEEF:[\d.]+\|.*\|"
        r"src=(?P<src_ip>[\d.]+)\s+srcPort=(?P<src_port>\d+)\s+"
        r"dst=(?P<dst_ip>[\d.]+)\s+dstPort=(?P<dst_port>\d+)\s+"
        r"proto=\w+\s+action=(?P<action>\w+)\s+msg=(?P<message>.*)$"
    ),
    "field_mappings": [
        {"source_field": "src_ip", "ocsf_path": "src_endpoint.ip"},
        {"source_field": "src_port", "ocsf_path": "src_endpoint.port"},
        {"source_field": "dst_ip", "ocsf_path": "dst_endpoint.ip"},
        {"source_field": "dst_port", "ocsf_path": "dst_endpoint.port"},
        {"source_field": "action", "ocsf_path": "action"},
        {"source_field": "message", "ocsf_path": "message"},
    ],
}


def _build_prompt(sample_lines: list[str]) -> str:
    joined_samples = "\n".join(sample_lines)
    return f"""You are a log-parsing rule generator. You will be given raw log lines
that all share the same format. Produce a Python regular expression with
NAMED capture groups (?P<name>...) that matches the structure of these
lines, plus a mapping from each captured group to a target field.

IMPORTANT structural note: many security log formats (CEF, LEEF, and
similar) have TWO distinct parts:
  1. A pipe-delimited HEADER (vendor, product, version, signature id,
     name, severity, etc.) at the start of the line.
  2. An EXTENSION containing key=value pairs separated by whitespace —
     this is where src/dst/port/action/message fields actually live.
     Capture groups belong here, one per relevant key=value pair.

CRITICAL: do NOT try to count and match the header's pipe-delimited
fields one at a time with repeated [^|]*\\| segments — different vendors
use different numbers of header fields, and guessing the wrong count
will make the pattern fail to match. Instead, since the extension never
itself contains a pipe character, skip the ENTIRE header generically
with a single GREEDY wildcard up to the LAST pipe before the extension,
like this: ^FORMAT:[\\d.]+\\|.*\\|key1=(?P<...>...) — the ".*\\|" part
consumes all header fields regardless of how many there are.

Only map fields that clearly correspond to one of these target fields —
leave other captured groups unmapped if they don't fit:
{", ".join(OCSF_TARGET_FIELDS)}

Respond with ONLY a JSON object, no other text, no markdown code fences,
in exactly this shape:

{FEW_SHOT_EXAMPLE_INPUT}
Expected output:
{json.dumps(FEW_SHOT_EXAMPLE_OUTPUT, indent=2)}

Now do the same for these sample lines:
{joined_samples}

Respond with ONLY the JSON object.
"""


def _extract_json(raw_response: str) -> dict:
    """Model sometimes wraps JSON in ```json fences or adds stray text — strip that."""
    text = raw_response.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    # If there's still leading/trailing junk, grab the outermost {...}
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON object found in model response: {raw_response[:200]}")
    return json.loads(match.group(0))


def _compute_confidence(pattern: str, sample_lines: list[str], expected_groups: list[str]) -> float:
    """Fraction of sample_lines where the pattern matches AND all named
    groups it defines come back non-empty."""
    try:
        compiled = re.compile(pattern)
    except re.error:
        return 0.0

    if not sample_lines:
        return 0.0

    hits = 0
    for line in sample_lines:
        m = compiled.search(line)
        if not m:
            continue
        groupdict = m.groupdict()
        if all(groupdict.get(g) for g in expected_groups):
            hits += 1
    return round(hits / len(sample_lines), 2)


def generate_rule(fingerprint_id: str, sample_lines: list[str], max_attempts: int = 3) -> Rule:
    """
    Given raw sample log lines (all believed to be the same format), call
    the local SLM to infer a regex + OCSF field mapping. Retries on
    malformed output or a regex that fails to compile.
    """
    if not sample_lines:
        raise ValueError("generate_rule requires at least one sample line")

    prompt = _build_prompt(sample_lines)
    last_error = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = ollama.chat(
                model=MODEL_NAME,
                messages=[{"role": "user", "content": prompt}],
                format="json",
                options={"temperature": 0.1},
            )
            content = response["message"]["content"]
            if os.environ.get("ULPF_DEBUG"):
                print(f"--- raw model response (attempt {attempt}) ---\n{content}\n---", file=sys.stderr)
            parsed = _extract_json(content)

            pattern = parsed["pattern"]
            raw_mappings = parsed["field_mappings"]

            # validate regex compiles before we trust it
            re.compile(pattern)

            field_mappings = [
                FieldMapping(source_field=m["source_field"], ocsf_path=m["ocsf_path"])
                for m in raw_mappings
            ]
            expected_groups = [m["source_field"] for m in raw_mappings]

            confidence = _compute_confidence(pattern, sample_lines, expected_groups)

            return Rule(
                fingerprint_id=fingerprint_id,
                pattern=pattern,
                field_mappings=field_mappings,
                confidence=confidence,
                provenance="slm-generated",
                version=1,
                created_at=datetime.now(timezone.utc).isoformat(),
            )

        except (json.JSONDecodeError, KeyError, re.error, ValueError) as e:
            last_error = e
            continue

    raise RuntimeError(
        f"Failed to generate a valid rule for fingerprint '{fingerprint_id}' "
        f"after {max_attempts} attempts. Last error: {last_error}"
    )


if __name__ == "__main__":
    # Quick manual test against the CEF sample logs.
    # Run from repo root: python onboarding/generate_rule.py
    log_path = os.path.join(os.path.dirname(__file__), "..", "testdata", "raw_logs_cef.txt")
    with open(log_path) as f:
        lines = [line.strip() for line in f if line.strip()]

    rule = generate_rule("cef_test", lines)
    print(json.dumps({
        "fingerprint_id": rule.fingerprint_id,
        "pattern": rule.pattern,
        "field_mappings": [vars(fm) for fm in rule.field_mappings],
        "confidence": rule.confidence,
        "provenance": rule.provenance,
    }, indent=2))