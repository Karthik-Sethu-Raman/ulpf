"""
Patch for parser_engine/rule_store.py — add simple JSON-file persistence.

Currently _RULE_STORE is a plain in-memory dict, which means rules
registered by running integration_runner.py (one process) are invisible
to a separately-launched `streamlit run review_ui/app.py` (a different
process). This patch makes register_rule() write to disk and makes the
module auto-load any persisted rules at import time, so both processes
see the same rules.

Replace the whole file with this version (or apply just the marked
changes if you'd rather edit in place).
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

# NEW: where registered rules get persisted so separate processes
# (integration_runner.py, streamlit) see the same store.
_PERSIST_PATH = Path(__file__).resolve().parent.parent / "testdata" / "registered_rules.json"


def _rule_to_dict(rule: Rule) -> dict:
    return {
        "fingerprint_id": rule.fingerprint_id,
        "pattern": rule.pattern,
        "field_mappings": [
            {"source_field": fm.source_field, "ocsf_path": fm.ocsf_path}
            for fm in rule.field_mappings
        ],
        "confidence": rule.confidence,
        "provenance": rule.provenance,
        "version": rule.version,
        "created_at": rule.created_at,
    }


def _dict_to_rule(d: dict) -> Rule:
    return Rule(
        fingerprint_id=d["fingerprint_id"],
        pattern=d["pattern"],
        field_mappings=[
            FieldMapping(source_field=fm["source_field"], ocsf_path=fm["ocsf_path"])
            for fm in d["field_mappings"]
        ],
        confidence=d["confidence"],
        provenance=d["provenance"],
        version=d["version"],
        created_at=d["created_at"],
    )


def _save_to_disk() -> None:
    _PERSIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = [_rule_to_dict(r) for r in _RULE_STORE.values()]
    _PERSIST_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_from_disk() -> None:
    if not _PERSIST_PATH.exists():
        return
    try:
        data = json.loads(_PERSIST_PATH.read_text(encoding="utf-8"))
        for d in data:
            rule = _dict_to_rule(d)
            _RULE_STORE[rule.fingerprint_id] = rule
    except Exception:
        pass  # corrupt/empty file -- start clean rather than crash


# Auto-load whatever was persisted by a previous run, at import time.
_load_from_disk()


def register_rule(rule: Rule) -> None:
    """Register or update a Rule in memory AND persist it to disk."""
    _RULE_STORE[rule.fingerprint_id] = rule
    _save_to_disk()


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
    """Clear all registered rules (in memory AND on disk)."""
    _RULE_STORE.clear()
    if _PERSIST_PATH.exists():
        _PERSIST_PATH.unlink()