# services/drift/store.py — all drift DB access (cold path, Postgres only).
#
# Every function takes a live connection (the app loop opens one per scan) and
# imports psycopg lazily, so unit tests drive everything through fake conns —
# never a live DB. Connections run AUTOCOMMIT (the T7 house style): each
# multi-statement operation wraps exactly one `with conn.transaction():` block,
# single statements rely on autocommit.
#
# Grant shape (migration 007): drift_role has SELECT on normalized_events,
# rules, drift_windows and baseline_profiles, and INSERT on drift_windows,
# baseline_profiles and audit_log. Detection is INSERT-only — no UPDATE
# anywhere in this module (the rules UPDATE grants are Task 5's enforce layer).
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pydantic import Field
from ulpf_core.models import Mapping, Rule

if TYPE_CHECKING:
    import psycopg

log = logging.getLogger("drift.store")

# Audit actor for every drift-side action (Task 5's enforce layer reuses it).
ACTOR = "drift"


class ActiveDriftRule(Rule):
    """Rule plus the rules-table serial id and the M3 quarantine list (the
    pipeline's rules.ActiveRule pattern). pattern is fetched only because Rule
    requires it — the scan never compiles it."""

    id: int
    quarantined_fields: list[str] = Field(default_factory=list)


def connect_db(url: str) -> psycopg.Connection:
    """psycopg connection for drift_role; autocommit per house style."""
    import psycopg  # deferred: unit tests never need psycopg

    return psycopg.connect(url, autocommit=True)


def load_active_rules(conn: psycopg.Connection) -> list[ActiveDriftRule]:
    """All status='active' rules, ordered by fingerprint_id for a deterministic
    scan order. mappings arrives as JSONB (list of {source_field, ocsf_path})
    and is rebuilt into the typed Mapping model; quarantined_fields as TEXT[].
    provenance is fetched only because Rule requires it (the reparse ruling).
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, fingerprint_id, version, pattern, mappings, "
            "quarantined_fields, provenance FROM rules WHERE status = 'active' "
            "ORDER BY fingerprint_id"
        )
        return [
            ActiveDriftRule(
                id=rule_id,
                fingerprint_id=fingerprint_id,
                version=version,
                pattern=pattern,
                mappings=[Mapping(**m) for m in mappings],
                provenance=provenance,
                quarantined_fields=list(quarantined or []),
            )
            for (rule_id, fingerprint_id, version, pattern, mappings,
                 quarantined, provenance) in cur.fetchall()
        ]


def fetch_current_view(conn: psycopg.Connection, fingerprint_id: str,
                       version: int) -> list[tuple]:
    """The DB current view (ne_current_idx semantics): unsuperseded
    normalized_events rows parsed under the ACTIVE version, oldest first. A
    fingerprint with only unparsed rows (rule_version 0) has no rows here —
    and therefore no windows."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT parsed_at, status, ocsf FROM normalized_events "
            "WHERE fingerprint_id = %s AND rule_version = %s "
            "AND superseded_by_event_id IS NULL ORDER BY parsed_at",
            (fingerprint_id, version),
        )
        return cur.fetchall()


def insert_windows(conn: psycopg.Connection, rows: list[tuple]) -> None:
    """One INSERT per drift_windows row, idempotent by the deterministic PK
    (fingerprint_id, rule_version, field, window_start) — a re-scan of already
    closed windows INSERTs nothing. The whole batch is one transaction so a
    crash never leaves a half-written window. shape_dist (dict) is wrapped for
    JSONB here, at the SQL boundary."""
    from psycopg.types.json import Json  # deferred: keeps psycopg off the test path

    sql = (
        "INSERT INTO drift_windows (fingerprint_id, rule_version, field, "
        "window_start, window_end, events_count, null_rate, match_rate, "
        "violation_rate, shape_dist, severity, action_taken) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
        "ON CONFLICT (fingerprint_id, rule_version, field, window_start) DO NOTHING"
    )
    with conn.transaction(), conn.cursor() as cur:
        for row in rows:
            shape = row[9]
            params = row[:9] + (Json(shape) if shape is not None else None,) + row[10:]
            cur.execute(sql, params)
    log.info("inserted up to %d drift window rows (conflicts are no-ops)", len(rows))


def baseline_for(conn: psycopg.Connection, fingerprint_id: str,
                 version: int) -> dict | None:
    """{field: profile} for the (fingerprint, version) baseline, or None while
    no baseline exists (tier-1-only mode). profile is the JSONB dict written
    at establishment (Task 5)."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT field, profile FROM baseline_profiles "
            "WHERE fingerprint_id = %s AND rule_version = %s",
            (fingerprint_id, version),
        )
        rows = cur.fetchall()
    return {field: profile for field, profile in rows} or None


def fetch_window_history(conn: psycopg.Connection, fingerprint_id: str,
                         version: int) -> list[tuple]:
    """(window_start, field, events_count, null_rate, match_rate, shape_dist)
    rows of the version's drift_windows, oldest window first, field-sorted
    within a window — the ordered input detect.aggregate_baseline slices the
    FIRST N closed windows from (the whole history is read: it is bounded by
    raw retention, and the scan is a cold path)."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT window_start, field, events_count, null_rate, match_rate, "
            "shape_dist FROM drift_windows "
            "WHERE fingerprint_id = %s AND rule_version = %s "
            "ORDER BY window_start, field",
            (fingerprint_id, version),
        )
        return cur.fetchall()


def first_window_unmapped(conn: psycopg.Connection, fingerprint_id: str,
                          version: int) -> set[str]:
    """Unmapped keys of the baseline's FIRST window — the key set new unmapped
    keys are measured against (Step 1: absent from the mapped targets AND from
    this set). Keys are returned unprefixed (as doc['unmapped'] keys)."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT DISTINCT field FROM drift_windows "
            "WHERE fingerprint_id = %s AND rule_version = %s "
            "AND field LIKE 'unmapped.%%' "
            "AND window_start = (SELECT MIN(window_start) FROM drift_windows "
            "WHERE fingerprint_id = %s AND rule_version = %s)",
            (fingerprint_id, version, fingerprint_id, version),
        )
        prefix_len = len("unmapped.")
        return {row[0][prefix_len:] for row in cur.fetchall()}


def insert_baseline(conn: psycopg.Connection, fingerprint_id: str, version: int,
                    profiles: dict, windows_seen: int) -> bool:
    """Insert the baseline profiles once: an existence SELECT guards the write
    (the plan's INSERT-once semantics) and ON CONFLICT DO NOTHING backs it
    against a race. One transaction covers guard + inserts. True iff rows were
    written; False when a baseline already exists (a no-op, nothing audited)."""
    from psycopg.types.json import Json  # deferred: keeps psycopg off the test path

    with conn.transaction(), conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM baseline_profiles WHERE fingerprint_id = %s "
            "AND rule_version = %s LIMIT 1",
            (fingerprint_id, version),
        )
        if cur.fetchone():  # exists (None/[] both falsy, [1] truthy)
            return False
        for field in sorted(profiles):
            cur.execute(
                "INSERT INTO baseline_profiles (fingerprint_id, rule_version, "
                "field, profile, windows_seen) VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (fingerprint_id, rule_version, field) DO NOTHING",
                (fingerprint_id, version, field, Json(profiles[field]), windows_seen),
            )
    log.info("baseline established for %s v%d over %d windows (%d fields)",
             fingerprint_id, version, windows_seen, len(profiles))
    return True
