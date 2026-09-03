"""
Data access layer for the Review-Gate UI + Normalized Event Browser.

Day 1: every function here reads from local fixture JSON files.
Day 2: swap the *body* of each function for a real call into P1 (rule
generation), P2 (normalization pipeline), or P3 (raw event store) --
the UI code in pages/ never has to change, since the return types
(schemas.schemas.*) stay the same.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REVIEW_UI_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = REVIEW_UI_DIR.parent
for _p in (PROJECT_ROOT, REVIEW_UI_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from schemas.schemas import FieldMapping, NormalizedEvent, RawEvent, Rule, ValidationResult

FIXTURES_DIR = PROJECT_ROOT / "testdata" / "fixtures"

# ---------------------------------------------------------------------------
# Real teammate modules -- imported defensively. If a module isn't in the
# repo yet, isn't on the path, or errors on import (e.g. P1's
# generate_rule.py imports `ollama`, which may not be installed/running),
# we fall back to fixtures instead of crashing the whole app. Each flag
# below reflects what's actually usable right now.
# ---------------------------------------------------------------------------

try:
    from parser_engine.rule_store import get_rule, list_rules, register_rule  # noqa: E402
    _HAS_RULE_STORE = True
except Exception:
    _HAS_RULE_STORE = False

try:
    from parser_engine.apply_rule import apply_rule as _p2_apply_rule  # noqa: E402
    _HAS_APPLY_RULE = True
except Exception:
    _HAS_APPLY_RULE = False

try:
    from ingestion.ingest import get_raw_event as _p3_get_raw_event  # noqa: E402
    _HAS_P3_INGEST = True
except Exception:
    _HAS_P3_INGEST = False

try:
    from ingestion.validate_rule import validate_rule as _p3_validate_rule  # noqa: E402
    _HAS_P3_VALIDATE = True
except Exception:
    _HAS_P3_VALIDATE = False

# Known fingerprint for the CEF PaloAlto rule everyone's been testing
# against since day 1 -- update this if the demo's target format changes.
DEFAULT_FINGERPRINT_ID = "cef_paloalto_v1"


def _load_json(filename: str):
    path = FIXTURES_DIR / filename
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# dict -> dataclass converters
# ---------------------------------------------------------------------------

def dict_to_field_mapping(d: dict) -> FieldMapping:
    return FieldMapping(source_field=d["source_field"], ocsf_path=d["ocsf_path"])


def dict_to_rule(d: dict) -> Rule:
    return Rule(
        fingerprint_id=d["fingerprint_id"],
        pattern=d["pattern"],
        field_mappings=[dict_to_field_mapping(fm) for fm in d["field_mappings"]],
        confidence=d["confidence"],
        provenance=d["provenance"],
        version=d["version"],
        created_at=d["created_at"],
    )


def dict_to_validation_result(d: dict) -> ValidationResult:
    return ValidationResult(
        rule_fingerprint_id=d["rule_fingerprint_id"],
        passed=d["passed"],
        checks=d["checks"],
        notes=d["notes"],
    )


def dict_to_normalized_event(d: dict) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=d["event_id"],
        raw_id=d["raw_id"],
        fingerprint_id=d["fingerprint_id"],
        rule_version=d["rule_version"],
        class_name=d["class_name"],
        time=d["time"],
        severity_id=d.get("severity_id"),
        src_endpoint=d.get("src_endpoint"),
        dst_endpoint=d.get("dst_endpoint"),
        action=d.get("action"),
        unmapped_fields=d.get("unmapped_fields", {}),
    )


def dict_to_raw_event(d: dict) -> RawEvent:
    return RawEvent(
        raw_id=d["raw_id"],
        source_id=d["source_id"],
        timestamp_ingested=d["timestamp_ingested"],
        format_guess=d["format_guess"],
        raw_text=d["raw_text"],
    )


# ---------------------------------------------------------------------------
# Page 1: Rule Review
# ---------------------------------------------------------------------------

def load_sample_rule() -> Rule:
    """
    Real source: P2's rule_store (parser_engine/rule_store.py), which
    holds whatever rules P1's onboarding engine has generated and
    registered so far.

    Falls back to the fixture if the store isn't importable yet, or has
    nothing registered under DEFAULT_FINGERPRINT_ID (in which case the
    fixture rule is also registered into the store, so downstream calls
    like apply_rule() have a consistent rule to work with).
    """
    if _HAS_RULE_STORE:
        try:
            rule = get_rule(DEFAULT_FINGERPRINT_ID)
            if rule is None:
                existing = list_rules()
                if existing:
                    rule = existing[0]
            if rule is not None:
                return rule
        except Exception:
            pass

    rule = dict_to_rule(_load_json("sample_rule.json"))
    if _HAS_RULE_STORE:
        try:
            register_rule(rule)
        except Exception:
            pass
    return rule


def load_sample_validation_result() -> ValidationResult:
    """
    Real source: P3's validate_rule() (ingestion/validate_rule.py), run
    against held-out CEF lines (testdata/raw_logs_cef.txt) that were NOT
    used to generate the rule.

    Falls back to the fixture if P3's validator isn't importable yet, the
    held-out log file is missing, or the real call errors for any reason.
    """
    if _HAS_P3_VALIDATE:
        try:
            rule = load_sample_rule()
            held_out_path = PROJECT_ROOT / "testdata" / "raw_logs_cef.txt"
            if held_out_path.exists():
                lines = [ln.strip() for ln in held_out_path.read_text().splitlines() if ln.strip()]
                held_out = lines[-3:] if len(lines) >= 3 else lines
                if held_out:
                    return _p3_validate_rule(rule, held_out)
        except Exception:
            pass

    return dict_to_validation_result(_load_json("sample_validation_result.json"))


def load_sample_raw_event() -> RawEvent:
    """
    Raw sample line used to build the "before -> after" example.
    Real source: P3's get_raw_event() for the known demo raw_id.
    Falls back to the fixture if P3's ingestion module isn't importable
    yet, or that raw_id hasn't been ingested.
    """
    if _HAS_P3_INGEST:
        try:
            real = _p3_get_raw_event("raw_00042")
            if real is not None:
                return real
        except Exception:
            pass

    return dict_to_raw_event(_load_json("sample_raw_event.json"))


# ---------------------------------------------------------------------------
# Page 2: Normalized Event Browser
# ---------------------------------------------------------------------------

def load_normalized_events() -> list[NormalizedEvent]:
    """
    Real source: run P2's apply_rule(raw_event, rule) using the real rule
    (from rule_store) and the real raw event (from P3), producing a real
    NormalizedEvent live.

    Falls back to the fixture if apply_rule isn't importable, or if it
    raises (e.g. the pattern doesn't match this raw line) -- keeps the
    page from crashing mid-demo.
    """
    if _HAS_APPLY_RULE:
        try:
            rule = load_sample_rule()
            raw = load_sample_raw_event()
            event = _p2_apply_rule(raw, rule)
            return [event]
        except Exception:
            pass

    data = _load_json("sample_normalized_event.json")
    if isinstance(data, list):
        return [dict_to_normalized_event(d) for d in data]
    return [dict_to_normalized_event(data)]


def get_raw_event(raw_id: str) -> RawEvent | None:
    """
    Real source: P3's get_raw_event(raw_id) (ingestion/ingest.py).
    Falls back to fixture lookup (sample_raw_event.json, plus any extra
    entries in testdata/fixtures/raw_events.json) if P3's ingestion
    module isn't importable, or that raw_id hasn't been ingested there.
    """
    if _HAS_P3_INGEST:
        try:
            real = _p3_get_raw_event(raw_id)
            if real is not None:
                return real
        except Exception:
            pass

    candidates = []

    single_path = FIXTURES_DIR / "sample_raw_event.json"
    if single_path.exists():
        candidates.append(_load_json("sample_raw_event.json"))

    multi_path = FIXTURES_DIR / "raw_events.json"
    if multi_path.exists():
        extra = _load_json("raw_events.json")
        if isinstance(extra, list):
            candidates.extend(extra)

    for c in candidates:
        if c.get("raw_id") == raw_id:
            return dict_to_raw_event(c)
    return None


# ---------------------------------------------------------------------------
# Rule application, for the "before -> after" example on Page 1
# ---------------------------------------------------------------------------

def apply_rule_to_raw_text(rule: Rule, raw_text: str) -> dict:
    """
    Runs the rule's regex against a raw log line and maps the captured
    fields onto OCSF paths using field_mappings.

    Handles the common CEF/LEEF shape where the regex captures a trailing
    "extension" blob of space-separated key=value pairs -- those get
    flattened in alongside the top-level named groups before mapping, so
    field_mappings can reference either kind of source_field.

    Returns:
        {
            "matched": bool,
            "captured_groups": {...},   # flattened, pre-mapping
            "mapped_output": {...},     # nested dict built from ocsf_path
            "error": str | None,
        }
    """
    result = {
        "matched": False,
        "captured_groups": None,
        "mapped_output": {},
        "error": None,
    }

    try:
        match = re.match(rule.pattern, raw_text)
    except re.error as e:
        result["error"] = f"Invalid regex: {e}"
        return result

    if not match:
        result["error"] = "Pattern did not match the sample raw line."
        return result

    groups = dict(match.groupdict())

    # Flatten a trailing key=value "extension" blob (CEF/LEEF-style logs)
    # so field_mappings can reference its keys directly.
    extension = groups.pop("extension", None)
    if extension:
        for token in extension.split():
            if "=" in token:
                k, v = token.split("=", 1)
                groups[k] = v

    result["matched"] = True
    result["captured_groups"] = groups

    mapped: dict = {}
    for fm in rule.field_mappings:
        value = groups.get(fm.source_field)
        _set_nested(mapped, fm.ocsf_path, value)
    result["mapped_output"] = mapped
    return result


def _set_nested(d: dict, dotted_path: str, value) -> None:
    parts = dotted_path.split(".")
    cur = d
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value
