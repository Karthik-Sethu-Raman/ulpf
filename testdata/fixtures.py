"""
Shared helper for loading JSON fixture files into the real dataclasses
from schemas.schemas. Keeps every role's test scripts from re-writing
this JSON-to-dataclass conversion logic themselves.
"""
import json
from pathlib import Path

from schemas.schemas import Rule, FieldMapping

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_rule(filename: str) -> Rule:
    """
    Load a Rule fixture, e.g. load_rule("sample_rule.json").
    """
    path = FIXTURES_DIR / filename
    with open(path) as f:
        data = json.load(f)

    return Rule(
        fingerprint_id=data["fingerprint_id"],
        pattern=data["pattern"],
        field_mappings=[FieldMapping(**fm) for fm in data["field_mappings"]],
        confidence=data["confidence"],
        provenance=data["provenance"],
        version=data["version"],
        created_at=data["created_at"],
    )
