"""
parser_engine/rule_store.py

Rule store managing in-memory mapping from fingerprint_id -> Rule.
Supports rule registration, lookup, and disk loading for Day 2/3 integration.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Dict

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from schemas.schemas import Rule, FieldMapping

_RULE_STORE: Dict[str, Rule] = {}


def register_rule(rule: Rule) -> None:
    """Register or update a Rule in memory."""
    _RULE_STORE[rule.fingerprint_id] = rule


def get_rule(fingerprint_id: str) -> Optional[Rule]:
    """Retrieve a Rule by fingerprint_id, or None if not registered."""
    return _RULE_STORE.get(fingerprint_id)


def load_rule_from_json(file_path: str | Path) -> Rule:
    """Load a Rule object from a JSON file and register it."""
    path = Path(file_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    
    field_mappings = [
        FieldMapping(source_field=fm["source_field"], ocsf_path=fm["ocsf_path"])
        for fm in data.get("field_mappings", [])
    ]
    
    rule = Rule(
        fingerprint_id=data["fingerprint_id"],
        pattern=data["pattern"],
        field_mappings=field_mappings,
        confidence=data.get("confidence", 1.0),
        provenance=data.get("provenance", "slm-generated"),
        version=data.get("version", 1),
        created_at=data.get("created_at", ""),
    )
    register_rule(rule)
    return rule


def list_rules() -> list[Rule]:
    """Return a list of all registered rules."""
    return list(_RULE_STORE.values())


def clear_rules() -> None:
    """Clear all registered rules (useful for testing)."""
    _RULE_STORE.clear()
