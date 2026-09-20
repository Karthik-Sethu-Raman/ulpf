# services/onboarding/reparse.py — R11 backlog re-parse: convergent sweep.
#
# When a rule is approved at version N, every normalized_events row for the
# fingerprint still counted under an OLDER version (or unparsed, version 0) is
# stale. This module finds such fingerprints, re-parses their raw backlog
# under the new version in batches, INSERTs the new-version rows (event_id
# minted exactly as the pipeline mints them: event_id_for(raw_id, version)),
# and supersedes the old rows via normalized_events.superseded_by_event_id —
# the single column-scoped UPDATE grant migration 003 gives onboarding_role,
# the only mutable cell in the event store. Insert + supersede share ONE
# transaction per batch, so a crash never leaves a duplicated or orphaned
# backlog row: the next poll re-finds whatever stayed stale and the sweep
# converges (a re-run over swept rows is a no-op by construction).
from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from ulpf_core.ids import event_id_for
from ulpf_core.models import Mapping, Rule
from ulpf_core.parsing import parse

from onboarding.config import Config
from onboarding.store import audit, connect_db

if TYPE_CHECKING:
    import psycopg

log = logging.getLogger("onboarding.reparse")

# Active rules whose fingerprint still has unsuperseded rows parsed under an
# older version (COALESCE(rule_version, 0): unparsed rows are stale from any
# version). r.provenance is additive to the plan's STALE_SQL: Rule requires it
# (controller ruling — disclosed, not guessed).
STALE_SQL = """
SELECT r.id, r.fingerprint_id, r.version, r.pattern, r.mappings, r.provenance
FROM rules r
WHERE r.status = 'active' AND EXISTS (
  SELECT 1 FROM normalized_events ne
  WHERE ne.fingerprint_id = r.fingerprint_id
    AND ne.superseded_by_event_id IS NULL
    AND COALESCE(ne.rule_version, 0) < r.version)
"""
BATCH_SQL = """
SELECT ne.event_id, ne.raw_id, ne.raw_received_at, raw.raw_text
FROM normalized_events ne
JOIN raw_events raw ON raw.raw_id = ne.raw_id AND raw.received_at = ne.raw_received_at
WHERE ne.fingerprint_id = %s AND ne.superseded_by_event_id IS NULL
  AND COALESCE(ne.rule_version, 0) < %s
ORDER BY ne.raw_received_at
LIMIT %s
"""
SUPERSEDE_SQL = ("UPDATE normalized_events SET superseded_by_event_id = %s "
                 "WHERE event_id = %s AND parsed_at = %s")

_STALE_KEYS = ("id", "fingerprint_id", "version", "pattern", "mappings", "provenance")

# The staged-COPY insert below duplicates pipeline.db.persist_normalized's
# block (temp table -> COPY -> INSERT .. ON CONFLICT (event_id, parsed_at) DO
# NOTHING). Deliberate duplication, NOT an import: services don't cross-import
# (M1 pythonpath ruling — the pipeline package is not on the onboarding image),
# so the ~15-line staging helper lives here too.
_NE_COLUMNS = (
    "event_id", "raw_id", "raw_received_at", "parsed_at", "fingerprint_id",
    "rule_id", "rule_version", "status", "ocsf",
)


@dataclass(frozen=True)
class _NewEvent:
    """One new-version normalized_events row (field-for-field the pipeline's
    NormalizedRow — duplicated for the same no-cross-import reason)."""

    event_id: uuid.UUID
    raw_id: uuid.UUID
    raw_received_at: datetime
    parsed_at: datetime
    fingerprint_id: str
    rule_id: int
    rule_version: int
    status: str
    ocsf: dict | None


def find_stale(conn: psycopg.Connection) -> list[dict]:
    """Active rules with stale backlog, one dict per rule keyed by
    _STALE_KEYS (id = the rules-table serial id, needed for attribution)."""
    with conn.cursor() as cur:
        cur.execute(STALE_SQL)
        return [dict(zip(_STALE_KEYS, row)) for row in cur.fetchall()]


def _rule_from_row(rule_row: dict) -> Rule:
    """Rebuild the typed Rule parse() consumes; mappings arrive from Postgres
    as a JSON list of dicts."""
    return Rule(
        fingerprint_id=rule_row["fingerprint_id"],
        version=rule_row["version"],
        pattern=rule_row["pattern"],
        mappings=[Mapping(**m) for m in rule_row["mappings"]],
        provenance=rule_row["provenance"],
    )


def sweep_one(conn: psycopg.Connection, rule_row: dict, batch_size: int) -> dict:
    """Re-parse one fingerprint's stale backlog under its active rule.

    Loops BATCH_SQL until a batch returns < batch_size rows — the stale select
    drains as rows get superseded, so the sweep terminates and is idempotent
    (a second sweep finds nothing and does nothing). Per batch, ONE
    transaction: staged-COPY INSERT of the new rows, then SUPERSEDE_SQL per
    old row. Audits reparse_complete once per sweep that did work.
    """
    from psycopg.types.json import Json  # deferred: keeps psycopg off the test path

    rule = _rule_from_row(rule_row)
    inserted = superseded = 0
    while True:
        with conn.cursor() as cur:
            cur.execute(BATCH_SQL, (rule.fingerprint_id, rule.version, batch_size))
            old_rows = cur.fetchall()
        if not old_rows:
            break

        new_events = []
        for old_event_id, raw_id, raw_received_at, raw_text in old_rows:
            doc, err = parse(raw_text, rule)
            if err is not None:
                status, ocsf = "parse_error", None
            else:
                status, ocsf = "parsed", doc
                if doc["time"] is None:
                    # Worker parity: parse() leaves time None when the rule
                    # maps no timestamp; the pipeline fills ingestion time
                    # (received_at) before persisting (ulpf_core.parsing).
                    doc["time"] = raw_received_at.isoformat()
            new_events.append(_NewEvent(
                event_id=event_id_for(raw_id, rule.version),
                raw_id=raw_id,
                raw_received_at=raw_received_at,
                parsed_at=raw_received_at,  # := raw received_at (deterministic)
                fingerprint_id=rule.fingerprint_id,
                rule_id=rule_row["id"],
                rule_version=rule.version,
                status=status,
                ocsf=ocsf,
            ))

        with conn.transaction(), conn.cursor() as cur:
            cur.execute("CREATE TEMP TABLE staging_ne (LIKE normalized_events INCLUDING DEFAULTS) ON COMMIT DROP")
            with cur.copy(f"COPY staging_ne ({', '.join(_NE_COLUMNS)}) FROM STDIN") as copy:
                for ev in new_events:
                    copy.write_row((
                        ev.event_id, ev.raw_id, ev.raw_received_at, ev.parsed_at,
                        ev.fingerprint_id, ev.rule_id, ev.rule_version, ev.status,
                        Json(ev.ocsf) if ev.ocsf is not None else None,
                    ))
            cur.execute(
                f"INSERT INTO normalized_events ({', '.join(_NE_COLUMNS)}) "
                f"SELECT {', '.join(_NE_COLUMNS)} FROM staging_ne "
                "ON CONFLICT (event_id, parsed_at) DO NOTHING"
            )
            for (old_event_id, _raw_id, old_parsed_at, _raw_text), ev in zip(old_rows, new_events):
                # old_parsed_at == the old row's parsed_at: parsed_at is ALWAYS
                # the raw's received_at (spec §4 deterministic minting), so the
                # PK (event_id, parsed_at) is keyed by what BATCH_SQL selected.
                cur.execute(SUPERSEDE_SQL, (ev.event_id, old_event_id, old_parsed_at))

        inserted += len(new_events)
        superseded += len(old_rows)
        if len(old_rows) < batch_size:
            break

    if inserted or superseded:  # audit once per sweep that did work
        audit(conn, "reparse_complete", rule.fingerprint_id, {
            "rule_id": rule_row["id"],
            "version": rule.version,
            "inserted": inserted,
            "superseded": superseded,
        })
    log.info("reparse sweep %s: v%d inserted=%d superseded=%d",
             rule.fingerprint_id, rule.version, inserted, superseded)
    return {"inserted": inserted, "superseded": superseded, "status": "complete"}


def run_reparse_loop(cfg: Config, stop: threading.Event) -> None:
    """Poll find_stale and sweep each stale fingerprint, serially (cold path).
    `stop.set()` ends the loop promptly (wait() is sliced by the event). Every
    exception is logged and the loop continues — convergence self-heals: the
    next poll re-finds whatever the failed sweep left stale."""
    log.info("onboarding reparse loop started (batch=%d, poll=%.1fs)",
             cfg.reparse_batch, cfg.reparse_poll_s)
    while not stop.is_set():
        try:
            with connect_db(cfg.database_url) as conn:
                stale = find_stale(conn)
            for rule_row in stale:
                if stop.is_set():
                    break
                try:
                    with connect_db(cfg.database_url) as conn:
                        sweep_one(conn, rule_row, cfg.reparse_batch)
                except Exception:
                    log.exception("reparse sweep failed for %s; continuing",
                                  rule_row.get("fingerprint_id"))
        except Exception:
            log.exception("reparse loop iteration failed; will retry")
        stop.wait(cfg.reparse_poll_s)
    log.info("onboarding reparse loop stopped")
