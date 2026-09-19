# services/pipeline/rules.py — active-rule cache loader for the worker.
#
# One SELECT per batch (the worker refreshes every consume batch, so a rule
# activated mid-stream is picked up on the next batch — no restart, no push).
# mappings arrives as JSONB (list of {source_field, ocsf_path} dicts) and is
# rebuilt into the typed Mapping model before parse() ever sees the rule.
from __future__ import annotations

from typing import TYPE_CHECKING

from ulpf_core.models import Mapping, Rule

if TYPE_CHECKING:
    import psycopg


class ActiveRule(Rule):
    """Rule plus the rules-table serial id.

    load_active_rules must return dict[str, Rule] per the plan contract, but
    normalized_events.rule_id wants the DB id — so the id rides on this Rule
    subclass (an ActiveRule IS a Rule; parse() and the type contract are
    unaffected, and the worker reads ``rule.id`` for attribution).
    """

    id: int


def load_active_rules(conn: psycopg.Connection) -> dict[str, Rule]:
    """All status='active' rules keyed by fingerprint_id (one per fingerprint,
    enforced by the rules_one_active partial unique index)."""
    rules: dict[str, Rule] = {}
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, fingerprint_id, version, pattern, mappings, provenance "
            "FROM rules WHERE status = 'active'"
        )
        for rule_id, fingerprint, version, pattern, mappings, provenance in cur.fetchall():
            rules[fingerprint] = ActiveRule(
                id=rule_id,
                fingerprint_id=fingerprint,
                version=version,
                pattern=pattern,
                mappings=[Mapping(**m) for m in mappings],
                provenance=provenance,
            )
    return rules
