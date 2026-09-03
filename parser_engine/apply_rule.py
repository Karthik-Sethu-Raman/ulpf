"""
parser_engine/apply_rule.py

Applies a deterministic parsing rule (regex + field mappings) to a RawEvent,
producing a NormalizedEvent conforming to canonical OCSF contracts.
"""

from __future__ import annotations

import re
import sys
import os
import uuid
from typing import Any

# Ensure schemas module can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from schemas.schemas import RawEvent, Rule, NormalizedEvent


def _parse_extension_kv(extension_str: str) -> dict[str, str]:
    """Parse key=value pairs from extension text (e.g. src=1.2.3.4 msg=Suspicious DNS Query)."""
    pairs: dict[str, str] = {}
    if not extension_str:
        return pairs
    # Matches key="value" OR key=value_up_to_next_key_or_end
    pattern = re.compile(r'(\w+)=(?:"([^"]*)"|([^=]+?)(?=\s+\w+=|$))')
    for match in pattern.finditer(extension_str):
        k = match.group(1)
        v = match.group(2) if match.group(2) is not None else match.group(3)
        pairs[k] = v.strip()
    return pairs


def apply_rule(raw_event: RawEvent, rule: Rule) -> NormalizedEvent:
    """
    Apply rule.pattern (a regex) to raw_event.raw_text. Use rule.field_mappings
    to build the OCSF-shaped output. Any captured field with no OCSF mapping
    goes into unmapped_fields — never drop it.
    
    Raises ValueError if rule.pattern does not match raw_event.raw_text.
    """
    compiled_pattern = re.compile(rule.pattern)
    match = compiled_pattern.search(raw_event.raw_text)

    if not match:
        raise ValueError(
            f"Rule pattern '{rule.pattern}' did not match raw_event (raw_id={raw_event.raw_id})"
        )

    captured = match.groupdict()
    all_fields: dict[str, Any] = dict(captured)

    # If an 'extension' group exists, parse key=value pairs inside it
    extension_text = captured.get("extension")
    if extension_text:
        ext_kv = _parse_extension_kv(extension_text)
        all_fields.update(ext_kv)

    # Build mapping lookup: source_field -> ocsf_path
    mapping_lookup: dict[str, str] = {}
    for fm in rule.field_mappings:
        mapping_lookup[fm.source_field] = fm.ocsf_path

    src_endpoint: dict[str, Any] = {}
    dst_endpoint: dict[str, Any] = {}
    action: str | None = None
    severity_id: int | None = None
    event_time: str | None = None
    mapped_sources: set[str] = set()

    for src_field, val in all_fields.items():
        if src_field in mapping_lookup:
            ocsf_path = mapping_lookup[src_field]
            mapped_sources.add(src_field)

            if ocsf_path == "src_endpoint.ip":
                src_endpoint["ip"] = str(val)
            elif ocsf_path == "src_endpoint.port":
                try:
                    src_endpoint["port"] = int(val)
                except (ValueError, TypeError):
                    src_endpoint["port"] = val
            elif ocsf_path == "dst_endpoint.ip":
                dst_endpoint["ip"] = str(val)
            elif ocsf_path == "dst_endpoint.port":
                try:
                    dst_endpoint["port"] = int(val)
                except (ValueError, TypeError):
                    dst_endpoint["port"] = val
            elif ocsf_path == "action":
                action = str(val)
            elif ocsf_path == "severity_id":
                try:
                    severity_id = int(val)
                except (ValueError, TypeError):
                    severity_id = None
            elif ocsf_path == "time":
                event_time = str(val)

    # Build unmapped fields dictionary — ignore internal structural groups
    structural_header_keys = {"extension", "vendor", "product", "version", "sig_id", "name", "severity"}
    unmapped_fields: dict[str, Any] = {}

    for src_field, val in all_fields.items():
        if src_field not in mapped_sources and src_field not in structural_header_keys:
            if val is not None:
                # Convert digits to int if appropriate
                if isinstance(val, str) and val.isdigit():
                    unmapped_fields[src_field] = int(val)
                else:
                    unmapped_fields[src_field] = val

    # Generate unique event_id linked to raw_id
    raw_suffix = raw_event.raw_id.split("_")[-1] if "_" in raw_event.raw_id else raw_event.raw_id
    event_id = f"evt_{raw_suffix}"

    return NormalizedEvent(
        event_id=event_id,
        raw_id=raw_event.raw_id,
        fingerprint_id=rule.fingerprint_id,
        rule_version=rule.version,
        class_name="Network Activity",
        time=event_time or raw_event.timestamp_ingested,
        severity_id=severity_id,
        src_endpoint=src_endpoint if src_endpoint else None,
        dst_endpoint=dst_endpoint if dst_endpoint else None,
        action=action,
        unmapped_fields=unmapped_fields,
    )
