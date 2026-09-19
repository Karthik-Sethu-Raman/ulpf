"""Single parsing implementation: raw line + Rule -> OCSF document (spec §6.1, §6.4).

Ported from legacy-demo/parser_engine/apply_rule.py (the proven demo logic)
with the spec fixes M1 requires:

- rule-supplied regex runs through the ``regex`` module under a per-match
  timeout (spec §10) — timeout / compile error / no match are returned as
  errors, never a hot-path hang or raise;
- mapping targets are allow-listed (``OCSF_TARGETS``) at document build —
  defense-in-depth behind activation-time validation, so a rule can never
  write outside the curated subset;
- severity/port integer casts are wrapped: a bad value becomes ``None``
  (severity) or keeps the string (port) instead of crashing the hot path
  (the demo's crash bug, fixed);
- the full OCSF document is built (class_uid / class_name / activity_id /
  metadata), not the demo's partial shape.

``time``: parse() takes the line only, so the document carries the rule-mapped
event time when the rule maps one, else ``None`` — the pipeline fills
ingestion time (received_at) before emission.
"""

from __future__ import annotations

import json
from typing import Any

import regex

from ulpf_core.models import Rule

# The only OCSF paths a rule mapping may target (activation allow-list, spec §6.4).
OCSF_TARGETS: frozenset[str] = frozenset({
    "src_endpoint.ip",
    "src_endpoint.port",
    "dst_endpoint.ip",
    "dst_endpoint.port",
    "time",
    "severity_id",
    "action",
    "message",
})

# Extension-blob key=value grammar — the ONE definition; onboarding (M2) imports
# this instead of recompiling. Matches key="value" OR key=value_up_to_next_key_or_end.
EXTENSION_KV = regex.compile(r'(\w+)=(?:"([^"]*)"|([^=]+?)(?=\s+\w+=|$))')

# Sentinel pattern: parse the line as JSON and walk dotted paths, no regex.
JSON_SENTINEL = "__JSON__"

# CEF-style header groups describe the envelope, not payload fields — they
# never land in unmapped (legacy structural exclusion, carried over).
_STRUCTURAL_KEYS = frozenset(
    {"extension", "vendor", "product", "version", "sig_id", "name", "severity"}
)

# Pattern caps checked at activation (spec §10: length/group-count/nesting).
MAX_PATTERN_CHARS = 1000
MAX_PATTERN_GROUPS = 32
MAX_PATTERN_NESTING = 5

_CLASS_UID = 4001
_CLASS_NAME = "Network Activity"
_ACTIVITY_ID = 99  # "other" — curated subset carries no per-activity taxonomy yet


def parse(line: str, rule: Rule, *, timeout_ms: int = 50) -> tuple[dict | None, str | None]:
    """Apply one rule to one raw line; returns ``(ocsf_doc, None)`` or ``(None, error)``.

    Never raises on bad input — bad pattern, timeout, no match and invalid JSON
    are all errors — raising is reserved for programmer error (e.g. a Rule that
    violates its own model). The document's ``time`` is the rule-mapped event
    time, or ``None`` when the rule maps no timestamp; the pipeline fills
    ingestion time (received_at) before emission.
    """
    if rule.pattern == JSON_SENTINEL:
        return _parse_json(line, rule)
    return _parse_regex(line, rule, timeout_ms)


def validate_rule_output(rule: Rule, samples: list[str]) -> list[str]:
    """Activation-time check (spec §6.4): pattern caps, compiles, allow-listed
    mappings, every sample parses, output documents validate.

    Returns the list of problems; empty means the rule may activate. Never
    raises on rule or sample content — a broken rule is exactly what this
    exists to catch.
    """
    errors = _pattern_cap_errors(rule.pattern)
    if errors:
        return errors

    try:
        regex.compile(rule.pattern)
    except regex.error as exc:
        return [f"compile error: {exc}"]

    for mapping in rule.mappings:
        if mapping.ocsf_path not in OCSF_TARGETS:
            errors.append(
                f"mapping {mapping.source_field!r} -> {mapping.ocsf_path!r} "
                "is not in the OCSF allow-list"
            )

    for i, line in enumerate(samples):
        doc, err = parse(line, rule)
        if err is not None:
            errors.append(f"sample {i}: {err}")
            continue
        errors.extend(f"sample {i}: {e}" for e in _document_errors(doc))
    return errors


# --- regex path -------------------------------------------------------------

def _parse_regex(line: str, rule: Rule, timeout_ms: int) -> tuple[dict | None, str | None]:
    try:
        compiled = regex.compile(rule.pattern)
    except regex.error as exc:
        return None, f"compile error: {exc}"
    try:
        # `regex` takes the timeout per match, in seconds (spec §10: ms-scale).
        match = compiled.search(line, timeout=timeout_ms / 1000.0)
    except TimeoutError:
        return None, "timeout"
    if match is None:
        return None, f"rule pattern {rule.pattern!r} did not match line"

    all_fields: dict[str, Any] = dict(match.groupdict())
    extension_text = all_fields.get("extension")
    if extension_text:
        all_fields.update(_parse_extension_kv(extension_text))

    parts = _new_parts()
    mapped: set[str] = set()
    lookup = {m.source_field: m.ocsf_path for m in rule.mappings}
    for source_field, value in all_fields.items():
        ocsf_path = lookup.get(source_field)
        if ocsf_path is None:
            continue
        mapped.add(source_field)
        _set_path(parts, ocsf_path, value)
    return _build_document(parts, _unmapped_regex(all_fields, mapped)), None


def _parse_extension_kv(extension_str: str) -> dict[str, str]:
    """Parse key=value pairs from extension text (e.g. src=1.2.3.4 msg=Suspicious DNS Query)."""
    pairs: dict[str, str] = {}
    if not extension_str:
        return pairs
    for match in EXTENSION_KV.finditer(extension_str):
        key = match.group(1)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        pairs[key] = value.strip()
    return pairs


# --- JSON sentinel path ------------------------------------------------------

def _parse_json(line: str, rule: Rule) -> tuple[dict | None, str | None]:
    """``__JSON__`` rule: parse the line as JSON and walk dotted-path mappings."""
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, RecursionError) as exc:
        # RecursionError: pathologically deep nesting is bad input too, not a crash.
        return None, f"invalid JSON: {exc}"
    if not isinstance(obj, dict):
        return None, "invalid JSON: expected an object"

    parts = _new_parts()
    mapped: set[str] = set()
    for mapping in rule.mappings:
        value = _resolve_json_path(obj, mapping.source_field)
        if value is None:
            continue
        mapped.add(mapping.source_field)
        _set_path(parts, mapping.ocsf_path, value)
    return _build_document(parts, _unmapped_json(obj, mapped)), None


def _resolve_json_path(obj: dict, dotted_path: str) -> Any:
    """Walk a nested dict using a dotted path like 'alert.severity'."""
    current: Any = obj
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _flatten(obj: dict, prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in obj.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(_flatten(value, path))
        else:
            flat[path] = value
    return flat


# --- document construction (shared) -------------------------------------------

def _new_parts() -> dict[str, Any]:
    return {
        "src_endpoint": {},
        "dst_endpoint": {},
        "severity_id": None,
        "time": None,
        "action": None,
        "message": None,
    }


def _set_path(parts: dict[str, Any], ocsf_path: str, value: Any) -> None:
    """Write one mapped value into the document accumulator.

    Targets outside OCSF_TARGETS are rejected here (defense-in-depth —
    activation-time validation rejects first), so a rule can never write
    outside the curated subset, e.g. override metadata.product or class_uid.
    """
    if ocsf_path not in OCSF_TARGETS:
        return
    if ocsf_path == "src_endpoint.ip":
        parts["src_endpoint"]["ip"] = str(value)
    elif ocsf_path == "src_endpoint.port":
        parts["src_endpoint"]["port"] = _as_int(value, keep=True)
    elif ocsf_path == "dst_endpoint.ip":
        parts["dst_endpoint"]["ip"] = str(value)
    elif ocsf_path == "dst_endpoint.port":
        parts["dst_endpoint"]["port"] = _as_int(value, keep=True)
    elif ocsf_path == "action":
        parts["action"] = str(value)
    elif ocsf_path == "message":
        parts["message"] = str(value)
    elif ocsf_path == "time":
        parts["time"] = str(value)
    elif ocsf_path == "severity_id":
        parts["severity_id"] = _as_int(value, keep=False)


def _as_int(value: Any, *, keep: bool) -> Any:
    """int cast with the hot-path fix: a bad value keeps the string (ports)
    or becomes None (severity) instead of crashing the parse."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return value if keep else None


def _unmapped_regex(all_fields: dict[str, Any], mapped: set[str]) -> dict[str, Any]:
    """Captured fields with no OCSF mapping — never dropped (spec §6.4)."""
    out: dict[str, Any] = {}
    for source_field, value in all_fields.items():
        if source_field in mapped or source_field in _STRUCTURAL_KEYS or value is None:
            continue
        out[source_field] = int(value) if isinstance(value, str) and value.isdigit() else value
    return out


def _unmapped_json(obj: dict, mapped: set[str]) -> dict[str, Any]:
    return {k: v for k, v in _flatten(obj).items() if k not in mapped}


def _build_document(parts: dict[str, Any], unmapped: dict[str, Any]) -> dict[str, Any]:
    return {
        "class_uid": _CLASS_UID,
        "class_name": _CLASS_NAME,
        "activity_id": _ACTIVITY_ID,
        "severity_id": parts["severity_id"],
        "time": parts["time"],
        "src_endpoint": parts["src_endpoint"] or None,
        "dst_endpoint": parts["dst_endpoint"] or None,
        "action": parts["action"],
        "message": parts["message"],
        "metadata": {"product": "ULPF"},
        "unmapped": unmapped,
    }


# --- activation helpers --------------------------------------------------------

def _pattern_cap_errors(pattern: str) -> list[str]:
    """Spec §10 pattern caps: length / group-count / nesting depth."""
    errors: list[str] = []
    if len(pattern) > MAX_PATTERN_CHARS:
        errors.append(
            f"pattern length {len(pattern)} exceeds cap {MAX_PATTERN_CHARS}"
        )
    groups = 0
    depth = 0
    max_depth = 0
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":          # escaped character — never a group delimiter
            i += 2
            continue
        if ch == "(":
            groups += 1
            depth += 1
            max_depth = max(max_depth, depth)
        elif ch == ")":
            depth -= 1
        i += 1
    if groups > MAX_PATTERN_GROUPS:
        errors.append(f"pattern group count {groups} exceeds cap {MAX_PATTERN_GROUPS}")
    if max_depth > MAX_PATTERN_NESTING:
        errors.append(f"pattern nesting depth {max_depth} exceeds cap {MAX_PATTERN_NESTING}")
    return errors


def _document_errors(doc: dict) -> list[str]:
    """ocsf_schema.validator.validate_document, or [] when ocsf-schema is not
    installed. The two libs are always installed together in practice (CI, dev
    setup); the fallback mirrors the validator's own jsonschema-optional
    contract and keeps ulpf-core importable standalone."""
    try:
        from ocsf_schema.validator import validate_document
    except ImportError:
        return []
    return validate_document(doc)
