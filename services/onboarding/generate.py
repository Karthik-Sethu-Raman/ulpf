# services/onboarding/generate.py — SLM candidate generation + JSON fast-path.
#
# Ported from legacy-demo/onboarding/generate_rule.py (the proven demo logic):
# the prompt (both few-shots + anti-hardcoding rule 4), fence-tolerant JSON
# extraction, the retry loop with escalating temperature and error-feedback
# turns, and the deterministic JSON-alias fast-path. Deliberate differences:
#   - the SLM sits behind the SLMClient Protocol and OllamaClient imports
#     `ollama` lazily inside chat() — no test or import path touches it;
#   - exhausted retries raise GenerationError (fail-closed: app.py records the
#     attempt and moves on) instead of returning the demo's last 0-confidence
#     rule;
#   - confidence rides GeneratedRule (the rules.confidence REAL column) via
#     the ActiveRule subclass precedent from services/pipeline/rules.py — the
#     ulpf_core Rule model deliberately carries no confidence field;
#   - provenance is 'slm' (the rules table CHECK), not the demo's
#     'slm-generated';
#   - the OCSF target list comes from ulpf_core.parsing.OCSF_TARGETS and the
#     extension key=value grammar from EXTENSION_KV (single definitions —
#     never recompiled here);
#   - set iteration is sorted before alias matching so the generated rule is
#     deterministic across runs (the demo iterated a raw set).
import json
import logging
import re
from typing import Protocol

from ulpf_core.models import Mapping, Rule
from ulpf_core.parsing import EXTENSION_KV, JSON_SENTINEL, OCSF_TARGETS

log = logging.getLogger("onboarding.generate")


class GenerationError(RuntimeError):
    """The SLM could not produce a usable rule within max_attempts."""


class GeneratedRule(Rule):
    """Rule plus generation-time confidence (rules.confidence REAL).

    A GeneratedRule IS a Rule — parse() and the Task 3 validation gate are
    unaffected — mirroring the ActiveRule precedent in
    services/pipeline/rules.py (an id/extra riding a Rule subclass).
    """

    confidence: float


class SLMClient(Protocol):
    def chat(self, prompt: str, temperature: float) -> str: ...


class OllamaClient:
    """SLMClient over a local Ollama server. `ollama` is imported lazily in
    chat() so this module (and the unit tests) load without it installed."""

    def __init__(self, base_url: str, model: str):
        self.base_url = base_url
        self.model = model

    def chat(self, prompt: str, temperature: float) -> str:
        from ollama import Client  # deferred: unit tests never need ollama

        response = Client(host=self.base_url).chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            format="json",
            options={"temperature": temperature},
        )
        return response["message"]["content"]


# Keep this short and targeted — do NOT dump the full OCSF spec into the prompt.
_OCSF_TARGET_LIST = sorted(OCSF_TARGETS)

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


def build_prompt(sample_lines: list[str]) -> str:
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
{", ".join(_OCSF_TARGET_LIST)}

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


def is_json_line(line: str) -> bool:
    try:
        json.loads(line)
        return True
    except json.JSONDecodeError:
        return False


def extract_json(raw_response: str) -> dict:
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


def _flatten(obj: dict, prefix: str = "") -> dict:
    """Flatten a nested dict into {dotted.path: value} pairs."""
    flat = {}
    for key, value in obj.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(_flatten(value, path))
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


def generate_json_rule(fingerprint_id: str, sample_lines: list[str]) -> GeneratedRule:
    """Deterministic path for JSON-formatted logs — NO model call. JSON is
    already self-describing, so we flatten it and match field names against
    known aliases directly. This is more reliable and much faster than asking
    an SLM to reverse-engineer a regex for data that's already structured.
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
    # that only appear in some lines. Sorted before matching: "first match
    # wins per target field" must not depend on set iteration order.
    all_flat_keys = set()
    for obj in parsed_lines:
        all_flat_keys.update(_flatten(obj).keys())

    field_mappings = []
    for ocsf_path, aliases in _JSON_FIELD_ALIASES.items():
        for flat_key in sorted(all_flat_keys):
            leaf = flat_key.split(".")[-1].lower()
            if leaf in aliases:
                field_mappings.append(Mapping(source_field=flat_key, ocsf_path=ocsf_path))
                break  # first match wins per target field

    if not field_mappings:
        # A zero-mapping rule passes every validation check vacuously — a
        # useless pending_review candidate that blocks the fingerprint until
        # a human rejects it (T5-M2). Refuse instead.
        raise GenerationError(
            f"no mappable fields via alias table for fingerprint '{fingerprint_id}' "
            f"(keys seen: {sorted(all_flat_keys)})")

    return GeneratedRule(
        fingerprint_id=fingerprint_id,
        pattern=JSON_SENTINEL,
        mappings=field_mappings,
        confidence=_json_confidence(sample_lines, field_mappings),
        provenance="slm",
        version=1,
    )


def _json_confidence(lines: list[str], mappings: list[Mapping]) -> float:
    """Legacy _compute_json_confidence: fraction of lines that parse as JSON
    AND have every mapped path resolve to a non-null value."""
    if not lines:
        return 0.0
    hits = 0
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if all(_resolve_json_path(obj, m.source_field) is not None for m in mappings):
            hits += 1
    return round(hits / len(lines), 2)


def _parse_extension_kv(extension_str: str) -> dict[str, str]:
    """Extension-blob key=value scan via the shared ulpf_core grammar."""
    pairs: dict[str, str] = {}
    if not extension_str:
        return pairs
    for match in EXTENSION_KV.finditer(extension_str):
        key = match.group(1)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        pairs[key] = value.strip()
    return pairs


def _regex_confidence(pattern: str, mappings: list[Mapping], lines: list[str]) -> float:
    """Legacy _compute_confidence semantics: fraction of lines where the
    pattern matches AND every mapped field resolves to a non-empty value
    (extension-blob keys included)."""
    try:
        compiled = re.compile(pattern)
    except re.error:
        return 0.0

    if not lines:
        return 0.0

    expected_groups = [m.source_field for m in mappings]
    hits = 0
    for line in lines:
        match = compiled.search(line)
        if not match:
            continue
        fields = dict(match.groupdict())
        extension_text = fields.get("extension")
        if extension_text:
            fields.update(_parse_extension_kv(extension_text))
        if all(fields.get(group) for group in expected_groups):
            hits += 1
    return round(hits / len(lines), 2)


def generate_candidate(fingerprint_id: str, prompt_lines: list[str], client: SLMClient,
                       max_attempts: int = 3) -> GeneratedRule:
    """Ask the SLM for a candidate rule, retrying with an escalated temperature
    and an error-feedback turn after each malformed or non-matching response.

    Raises GenerationError after max_attempts (fail-closed — the app loop
    records the attempt and leaves the hot path untouched).
    """
    if not prompt_lines:
        raise GenerationError(f"no prompt lines for fingerprint '{fingerprint_id}'")

    base_prompt = build_prompt(prompt_lines)
    prompt = base_prompt
    last_error: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        temperature = 0.1 + (attempt - 1) * 0.2
        try:
            content = client.chat(prompt, temperature)
        except Exception as exc:
            # ANY failure from the transport call is a transport failure for
            # retry purposes (T5-M3): builtin ConnectionError, but also
            # httpx.ConnectError / ollama.ResponseError, which are NOT
            # builtin subclasses — without this the ladder would fail fast
            # on attempt 1. Counted like any failed attempt; never fed back
            # as rule feedback. The exc_info log surfaces the outage and
            # keeps the broad catch lint-legal (BLE001).
            log.warning("SLM chat failed (attempt %d/%d): %s", attempt, max_attempts,
                        exc, exc_info=True)
            last_error = exc
            continue
        try:
            parsed = extract_json(content)

            pattern = parsed["pattern"]
            raw_mappings = parsed["field_mappings"]
            mappings = [
                Mapping(source_field=m["source_field"], ocsf_path=m["ocsf_path"])
                for m in raw_mappings
            ]

            if pattern == JSON_SENTINEL:
                if not mappings:
                    # Same vacuity as the fast-path (T5-M2): a sentinel rule
                    # with zero mappings passes every check vacuously — send
                    # it back through the feedback loop instead.
                    raise ValueError("JSON rule carried zero field mappings")
                confidence = _json_confidence(prompt_lines, mappings)
            else:
                re.compile(pattern)  # must compile before we trust it
                confidence = _regex_confidence(pattern, mappings, prompt_lines)

            if confidence == 0.0:
                raise ValueError(
                    "Generated rule yielded 0.0 confidence. It failed to match the "
                    "samples. Try a simpler regex.")

            return GeneratedRule(
                fingerprint_id=fingerprint_id,
                pattern=pattern,
                mappings=mappings,
                confidence=confidence,
                provenance="slm",
                version=1,
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError, re.error) as exc:
            last_error = exc
            prompt = (base_prompt +
                      f"\n\nYour previous response failed with error: {exc}\n"
                      "Please try again and fix the issue.")
            continue

    raise GenerationError(
        f"Failed to generate a valid rule for fingerprint '{fingerprint_id}' "
        f"after {max_attempts} attempts. Last error: {last_error}")
