# services/gateway/queries.py — read-only SQL behind the gateway endpoints.
#
# gateway_role is SELECT-only (Task 5 DDL), and every value goes through %s
# placeholders — parameterized SQL only; nothing user-controlled is ever
# interpolated into a statement string. psycopg is imported lazily inside
# _connect() so unit tests (which monkeypatch these functions) need neither a
# DB nor the driver on the test path (mirrors services/pipeline/db.py).
#
# Controller R9: every query over normalized_events carries the current-view
# predicate `superseded_by_event_id IS NULL`. M1 never supersedes, so it always
# matches today — but it stays in the SQL so M2+ inherits correct semantics.
from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import psycopg

DEFAULT_LIMIT = 50
MAX_LIMIT = 500
SNAPSHOT_LIMIT = 100  # SSE initial snapshot: latest N rows, emitted oldest-first

_STATUS_KEYS = ("parsed", "unparsed", "parse_error", "quarantined")


def _connect() -> psycopg.Connection:
    """One connection per request; dict rows so queries return contract dicts."""
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.connect(os.environ["DATABASE_URL"], row_factory=dict_row)


def clamp_limit(limit: int) -> int:
    """Defensive LIMIT clamp: 1..MAX_LIMIT regardless of caller input."""
    return max(1, min(int(limit), MAX_LIMIT))


def zero_fill_statuses(rows) -> dict[str, int]:
    """by_status GROUP BY rows -> contract dict with all four keys, zero-filled."""
    out = {status: 0 for status in _STATUS_KEYS}
    for status, count in rows:
        out[status] = count
    return out


def fetch_stats() -> dict:
    """GET /api/stats body (contract: dlq_total is null + note in M1 — no rpk
    broker-side DLQ counting exists in the walking skeleton)."""
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM raw_events")
        raw_total = cur.fetchone()["n"]
        cur.execute(
            "SELECT status, count(*) AS n FROM normalized_events "
            "WHERE superseded_by_event_id IS NULL GROUP BY status"
        )
        by_status = zero_fill_statuses(cur.fetchall())
        cur.execute(
            "SELECT fingerprint_id, count(*) AS total, "
            "count(*) FILTER (WHERE status = 'parsed') AS parsed "
            "FROM normalized_events WHERE superseded_by_event_id IS NULL "
            "GROUP BY fingerprint_id ORDER BY total DESC, fingerprint_id"
        )
        by_fingerprint = cur.fetchall()
        cur.execute(
            "SELECT count(*) AS n FROM normalized_events "
            "WHERE superseded_by_event_id IS NULL "
            "AND parsed_at >= now() - interval '1 minute'"
        )
        events_last_minute = cur.fetchone()["n"]
    return {
        "raw_total": raw_total,
        "by_status": by_status,
        "by_fingerprint": by_fingerprint,
        "events_last_minute": events_last_minute,
        "dlq_total": None,
        "note": "dlq_total is not counted in M1 (needs broker-side inspection of "
                "pipeline.dlq); always null for M1",
    }


def fetch_events(status=None, fingerprint=None, limit=DEFAULT_LIMIT, before=None):
    """GET /api/events rows: current view, newest first, EventRow columns only
    (exactly the 7 contract keys — rule_id is deliberately not exposed)."""
    limit = clamp_limit(limit)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT event_id, raw_id, fingerprint_id, rule_version, status, parsed_at, ocsf "
            "FROM normalized_events "
            "WHERE superseded_by_event_id IS NULL "
            "AND (%s::text IS NULL OR status = %s) "
            "AND (%s::text IS NULL OR fingerprint_id = %s) "
            "AND (%s::timestamptz IS NULL OR parsed_at < %s) "
            "ORDER BY parsed_at DESC LIMIT %s",
            (status, status, fingerprint, fingerprint, before, before, limit),
        )
        return cur.fetchall()


def fetch_raw_trace(event_id) -> dict | None:
    """GET /api/events/{event_id}/raw body: the raw line behind a normalized
    event, joined on the raw_events composite FK. None -> 404 upstream."""
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT r.raw_id, r.received_at, r.source_id, r.transport, "
            "r.content_hash, r.raw_text "
            "FROM raw_events r "
            "JOIN normalized_events n "
            "  ON n.raw_id = r.raw_id AND n.raw_received_at = r.received_at "
            "WHERE n.event_id = %s AND n.superseded_by_event_id IS NULL "
            "LIMIT 1",
            (event_id,),
        )
        return cur.fetchone()


def poll_events(after=None, limit=SNAPSHOT_LIMIT):
    """SSE poll: current-view rows strictly newer than `after` (R9 predicate in
    both branches), chronological for ordered streaming. after=None snapshots
    the latest rows (reversed to oldest-first)."""
    limit = clamp_limit(limit)
    with _connect() as conn, conn.cursor() as cur:
        if after is None:
            cur.execute(
                "SELECT event_id, raw_id, fingerprint_id, rule_version, status, parsed_at, ocsf "
                "FROM normalized_events WHERE superseded_by_event_id IS NULL "
                "ORDER BY parsed_at DESC LIMIT %s",
                (limit,),
            )
            return list(reversed(cur.fetchall()))
        cur.execute(
            "SELECT event_id, raw_id, fingerprint_id, rule_version, status, parsed_at, ocsf "
            "FROM normalized_events WHERE superseded_by_event_id IS NULL AND parsed_at > %s "
            "ORDER BY parsed_at LIMIT %s",
            (after, limit),
        )
        return cur.fetchall()


def fetch_chain_heads() -> list[dict]:
    """GET /api/audit/chain/head: the latest committed batch per Kafka partition
    (the chain head of each per-partition hash chain)."""
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT DISTINCT ON (partition_id) partition_id, batch_seq, merkle_root, count "
            "FROM raw_batches ORDER BY partition_id, batch_seq DESC"
        )
        return cur.fetchall()
