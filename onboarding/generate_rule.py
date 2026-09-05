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
        r"^.*\|(?P<extension>.*)$"
    ),
    "field_mappings": [
        {"source_field": "src", "ocsf_path": "src_endpoint.ip"},
        {"source_field": "srcPort", "ocsf_path": "src_endpoint.port"},
        {"source_field": "dst", "ocsf_path": "dst_endpoint.ip"},
        {"source_field": "dstPort", "ocsf_path": "dst_endpoint.port"},
        {"source_field": "action", "ocsf_path": "action"},
        {"source_field": "msg", "ocsf_path": "message"},
    ],
}

# Second few-shot example: prefix-boilerplate log with iptables-style keys.
# Teaches two things the LEEF example doesn't: (1) skip an arbitrary leading
# prefix (timestamp/hostname/process) rather than anchoring tightly, and
# (2) IN=/OUT=/MAC=/LEN= are interface/hardware fields, NOT endpoints —
# only SRC=/DST=/SPT=/DPT=-style keys are actual source/destination data.
FEW_SHOT_EXAMPLE_INPUT_2 = """Sample log lines:
Sep 3 10:05:12 gw02 kernel: FW-DROP: IN=eth1 OUT= MAC=00:1a:2b SRC=10.0.0.5 DST=10.0.0.9 LEN=40 PROTO=TCP SPT=443 DPT=8080 FLAGS=ACK
Sep 5 22:41:03 gw07 kernel: FW-DROP: IN=eth2 OUT= MAC=aa:bb:cc SRC=10.1.4.2 DST=10.1.4.9 LEN=60 PROTO=UDP SPT=53 DPT=33211 FLAGS=
"""

FEW_SHOT_EXAMPLE_OUTPUT_2 = {
    "pattern": (
        r"^.*?FW-DROP:\s*(?P<extension>.*)$"
    ),
    "field_mappings": [
        {"source_field": "SRC", "ocsf_path": "src_endpoint.ip"},
        {"source_field": "DST", "ocsf_path": "dst_endpoint.ip"},
        {"source_field": "SPT", "ocsf_path": "src_endpoint.port"},
        {"source_field": "DPT", "ocsf_path": "dst_endpoint.port"},
    ],
}

JSON_SENTINEL = "__JSON__"  # rule.pattern value signaling "parse as JSON, not regex"


def _build_prompt(sample_lines: list[str]) -> str:
    joined_samples = "\n".join(sample_lines)
    return f"""You are a log-parsing rule generator. You will be given raw log lines
of semi-structured text that all share the same format. Produce a Python
regular expression with NAMED capture groups (?P<name>...) that matches
the structure of these lines, plus a mapping from each captured group to
a target field.

1. Many formats have a HEADER before the meaningful content — either
   pipe-delimited (CEF, LEEF) or a free-text prefix like a timestamp and
   hostname (syslog-style). Do NOT try to match the header field-by-field.
   Use a GREEDY generic skip instead:
     - pipe-delimited header: use "^.*\\|" to skip to the last pipe
     - free-text prefix: use "^.*?" (non-greedy) to skip to wherever the
       actual meaningful key=value content begins
   This works regardless of exactly how many header fields exist.

2. If the meaningful content consists of space-separated key=value pairs
   (e.g., src=1.2.3.4 dst=5.6.7.8), do NOT try to match each pair individually.
   Instead, capture the ENTIRE key=value remainder of the line in a single
   named group called (?P<extension>.*). Our system will automatically parse
   the key=value pairs inside the extension blob. The source_field in your
   mappings must exactly match the key name from the log (e.g. "src", "dstPort").

3. In firewall/iptables-style logs, IN=, OUT=, MAC=, and LEN= are
   NETWORK INTERFACE / hardware fields — they are NOT source or
   destination addresses. Do not map them to endpoint IPs. The real
   endpoint data is in keys like SRC=, DST=, SPT=, DPT= (or clearly
   analogous names). Only capture and map fields that are actually
   source/destination/port/action/message data.

4. CRITICAL — do not hardcode any literal text that is specific to just
   the sample lines shown to you (a specific hostname, process name, PID,
   date, or exact interface name). Your pattern must generalize to lines
   you have NOT seen, which will have DIFFERENT hostnames/timestamps/etc.
   Anything that varies conceptually must be matched with a generic wildcard.

Only map fields that clearly correspond to one of these target fields —
leave other captured groups unmapped if they don't fit:
{", ".join(OCSF_TARGET_FIELDS)}

Respond with ONLY a JSON object, no other text, no markdown code fences,
in exactly this shape. Two worked examples:

Example 1 (pipe-delimited header):
{FEW_SHOT_EXAMPLE_INPUT}
Expected output:
{json.dumps(FEW_SHOT_EXAMPLE_OUTPUT, indent=2)}

Example 2 (free-text prefix, interface fields present but NOT mapped):
{FEW_SHOT_EXAMPLE_INPUT_2}
Expected output:
{json.dumps(FEW_SHOT_EXAMPLE_OUTPUT_2, indent=2)}

Now do the same for these sample lines:
{joined_samples}

Respond with ONLY the JSON object.
"""


def _is_valid_json(line: str) -> bool:
    try:
        json.loads(line)
        return True
    except json.JSONDecodeError:
        return False


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


def _resolve_json_path(obj: dict, dotted_path: str):
    """Walk a nested dict using a dotted path like 'alert.severity'.
    Returns None if any part of the path is missing (never raises)."""
    current = obj
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _flatten_json(obj: dict, prefix: str = "") -> dict:
    """Flatten a nested dict into {dotted.path: value} pairs."""
    flat = {}
    for key, value in obj.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(_flatten_json(value, path))
        else:
            flat[path] = value
    return flat


# Common key-name aliases seen in real security log JSON, matched against
# the LEAF (last segment) of a flattened dotted path, case-insensitively.
_JSON_FIELD_ALIASES = {
    "src_endpoint.ip": ["src_ip", "source_ip", "srcip"],
    "src_endpoint.port": ["src_port", "source_port", "srcport"],
    "dst_endpoint.ip": ["dest_ip", "dst_ip", "destination_ip", "dstip"],
    "dst_endpoint.port": ["dest_port", "dst_port", "destination_port", "dstport"],
    "time": ["timestamp", "time"],
    "severity_id": ["severity", "sev"],
    "action": ["action", "event_type"],
    "message": ["message", "msg", "signature"],
}


def _generate_json_rule(fingerprint_id: str, sample_lines: list[str]) -> Rule:
    """
    Deterministic path for JSON-formatted logs — NO model call. JSON is
    already self-describing, so we flatten it and match field names
    against known aliases directly. This is more reliable and much
    faster than asking an SLM to reverse-engineer a regex for data
    that's already structured.
    """
    parsed_lines = []
    for line in sample_lines:
        try:
            parsed_lines.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if not parsed_lines:
        raise ValueError(f"No sample lines for '{fingerprint_id}' parsed as valid JSON")

    # Union of flattened keys across all sample lines, so we catch fields
    # that only appear in some lines.
    all_flat_keys = set()
    for obj in parsed_lines:
        all_flat_keys.update(_flatten_json(obj).keys())

    field_mappings = []
    for ocsf_path, aliases in _JSON_FIELD_ALIASES.items():
        for flat_key in all_flat_keys:
            leaf = flat_key.split(".")[-1].lower()
            if leaf in aliases:
                field_mappings.append(FieldMapping(source_field=flat_key, ocsf_path=ocsf_path))
                break  # first match wins per target field

    confidence = _compute_json_confidence(sample_lines, field_mappings)

    return Rule(
        fingerprint_id=fingerprint_id,
        pattern=JSON_SENTINEL,
        field_mappings=field_mappings,
        confidence=confidence,
        provenance="slm-generated",  # still "generated", just deterministically rather than via model call
        version=1,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def _compute_json_confidence(sample_lines: list[str], field_mappings: list[FieldMapping]) -> float:
    """For JSON rules: fraction of sample_lines that parse as JSON AND
    have every mapped path resolve to a non-null value."""
    if not sample_lines:
        return 0.0
    hits = 0
    for line in sample_lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if all(_resolve_json_path(obj, fm.source_field) is not None for fm in field_mappings):
            hits += 1
    return round(hits / len(sample_lines), 2)


_EXTENSION_KV_PATTERN = re.compile(r'(\w+)=(?:"([^"]*)"|([^=]+?)(?=\s+\w+=|$))')

def _parse_extension_kv(extension_str: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    if not extension_str:
        return pairs
    for match in _EXTENSION_KV_PATTERN.finditer(extension_str):
        key = match.group(1)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        pairs[key] = value.strip()
    return pairs

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
        fields = dict(m.groupdict())
        extension_text = fields.get("extension")
        if extension_text:
            fields.update(_parse_extension_kv(extension_text))
            
        if all(fields.get(g) for g in expected_groups):
            hits += 1
    return round(hits / len(sample_lines), 2)


def generate_rule(fingerprint_id: str, sample_lines: list[str], max_attempts: int = 3) -> Rule:
    """
    Given raw sample log lines (all believed to be the same format), infer
    a parsing rule. JSON-formatted logs are detected up front and handled
    deterministically (no model call — see _generate_json_rule). Everything
    else goes through the SLM to generate a regex + field mapping, with
    retries on malformed output or a regex that fails to compile.
    """
    if not sample_lines:
        raise ValueError("generate_rule requires at least one sample line")

    # Detect JSON programmatically rather than trusting the model to
    # notice — this is more reliable and skips an unnecessary model call.
    is_json = all(_is_valid_json(line) for line in sample_lines)
    if is_json:
        return _generate_json_rule(fingerprint_id, sample_lines)

    # Cap how many lines actually go INTO the prompt. More samples can
    # help a large model generalize better, but empirically made a 3B
    # model scramble field order (attention dilution) rather than help —
    # 3-5 well-chosen lines are enough to show the pattern's shape.
    # Confidence is still checked against the FULL sample_lines set below,
    # so this doesn't weaken validation, only what the model has to read.
    MAX_PROMPT_SAMPLES = 5
    prompt_lines = sample_lines[:MAX_PROMPT_SAMPLES]

    prompt = _build_prompt(prompt_lines)
    last_error = None
    last_generated_rule = None

    messages = [{"role": "user", "content": prompt}]
    
    for attempt in range(1, max_attempts + 1):
        try:
            response = ollama.chat(
                model=MODEL_NAME,
                messages=messages,
                format="json",
                options={"temperature": 0.1 + (attempt - 1) * 0.2},
            )
            content = response["message"]["content"]
            messages.append({"role": "assistant", "content": content})
            
            if os.environ.get("ULPF_DEBUG"):
                print(f"--- raw model response (attempt {attempt}) ---\n{content}\n---", file=sys.stderr)
            parsed = _extract_json(content)

            pattern = parsed["pattern"]
            raw_mappings = parsed["field_mappings"]
            field_mappings = [
                FieldMapping(source_field=m["source_field"], ocsf_path=m["ocsf_path"])
                for m in raw_mappings
            ]

            if pattern == JSON_SENTINEL:
                # JSON rule: no regex to validate, use JSON-path confidence instead.
                confidence = _compute_json_confidence(sample_lines, field_mappings)
            else:
                # validate regex compiles before we trust it
                re.compile(pattern)
                expected_groups = [m["source_field"] for m in raw_mappings]
                confidence = _compute_confidence(pattern, sample_lines, expected_groups)
            
            rule = Rule(
                fingerprint_id=fingerprint_id,
                pattern=pattern,
                field_mappings=field_mappings,
                confidence=confidence,
                provenance="slm-generated",
                version=1,
                created_at=datetime.now(timezone.utc).isoformat(),
            )

            if confidence == 0.0:
                last_generated_rule = rule
                raise ValueError("Generated rule yielded 0.0 confidence. It failed to match the samples. Try a simpler regex.")

            return rule

        except (json.JSONDecodeError, KeyError, re.error, ValueError) as e:
            last_error = e
            messages.append({"role": "user", "content": f"That rule failed with error: {str(e)}\nPlease try again and fix the issue."})
            continue

    if last_generated_rule is not None:
        return last_generated_rule

    raise RuntimeError(
        f"Failed to generate a valid rule for fingerprint '{fingerprint_id}' "
        f"after {max_attempts} attempts. Last error: {last_error}"
    )


def _print_rule(rule: Rule):
    print(json.dumps({
        "fingerprint_id": rule.fingerprint_id,
        "pattern": rule.pattern,
        "field_mappings": [vars(fm) for fm in rule.field_mappings],
        "confidence": rule.confidence,
        "provenance": rule.provenance,
    }, indent=2))


if __name__ == "__main__":
    # Run from repo root: python onboarding/generate_rule.py
    base = os.path.join(os.path.dirname(__file__), "..", "testdata")

    for fp_id, filename in [
        ("cef_test", "raw_logs_cef.txt"),
        ("syslog_test", "raw_logs_syslog.txt"),
        ("json_test", "raw_logs_json.txt"),
    ]:
        with open(os.path.join(base, filename)) as f:
            lines = [line.strip() for line in f if line.strip()]
        print(f"\n=== {fp_id} ===")
        rule = generate_rule(fp_id, lines)
        _print_rule(rule)