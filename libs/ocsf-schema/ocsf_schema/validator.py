"""Validation of OCSF documents against the curated subset schema (spec §6.4).

Used at rule activation + runtime canary only — NEVER per event (per-event
JSON Schema validation is far too slow for the hot path; hot-path structure is
guaranteed by construction in ulpf_core.parsing).
"""

from __future__ import annotations

import json
import pathlib

_SCHEMA = json.loads((pathlib.Path(__file__).parent / "schema.json").read_text())


def validate_document(doc: dict) -> list[str]:
    """Return human-readable schema errors for one document; empty list = valid.

    jsonschema is optional at runtime: if it is not installed, validation
    degrades to no-op ([]). Activation tests pin jsonschema so the real
    validator is what tests exercise.
    """
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        return []  # jsonschema optional at runtime; activation tests pin it
    return [
        f"schema: {e.message} at {list(e.absolute_path)}"
        for e in Draft202012Validator(_SCHEMA).iter_errors(doc)
    ]
