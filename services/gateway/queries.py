# services/gateway/queries.py — read-only SQL behind the gateway endpoints.
#
# gateway_role is SELECT-only (Task 5 DDL), and every value goes through %s
# placeholders — parameterized SQL only; nothing user-controlled is ever
# interpolated into a statement string. The M2 write path lives in writes.py
# (rules_role over WRITE_DATABASE_URL); this module stays read-only over the
# M1 read DSN. psycopg is imported lazily inside
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
    """by_status GROUP BY rows (dict_row dicts: {"status": ..., "n": ...}) ->
    contract dict with all four keys, zero-filled. A status key outside
    _STATUS_KEYS is a contract breach, not a shape to widen — raise (T9)."""
    out = {status: 0 for status in _STATUS_KEYS}
    for row in rows:
        if row["status"] not in out:
            raise ValueError(
                f"unexpected status {row['status']!r}; expected one of {_STATUS_KEYS}")
        out[row["status"]] = row["n"]
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
            "GROUP BY fingerprint_id ORDER BY total DESC, fingerprint_id "
            "LIMIT 500"  # controller R20: hard cap — unbounded once M2 onboarding mints fingerprints
        )
        by_fingerprint = cur.fetchall()
        cur.execute(
            "SELECT count(*) AS n FROM normalized_events "
            "WHERE superseded_by_event_id IS NULL "
            "AND parsed_at >= now() - interval '1 minute'"
        )
        events_last_minute = cur.fetchone()["n"]
    out = {
        "raw_total": raw_total,
        "by_status": by_status,
        "by_fingerprint": by_fingerprint,
        "events_last_minute": events_last_minute,
        "dlq_total": None,
        "note": "dlq_total is not counted in M1 (needs broker-side inspection of "
                "pipeline.dlq); always null for M1",
    }
    if len(by_fingerprint) >= MAX_LIMIT:
        # T9: the hard cap truncates by_fingerprint — say so. Key stays ABSENT
        # below the cap (additive; M1 bodies are unchanged when not truncated).
        out["by_fingerprint_truncated"] = True
    return out


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


# --- M2 review surfaces (Task 7; consumed by the web Review Queue / Rules) -----

_RULE_COLUMNS = (
    "id, fingerprint_id, version, pattern, mappings, provenance, confidence, "
    "status, created_by, created_at, activated_at, deactivated_at, validation"
)


def fetch_rules(status=None):
    """GET /api/rules rows: RuleRow columns only; every status unless filtered
    (controller ruling), newest version first per fingerprint."""
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT {_RULE_COLUMNS} FROM rules "
            "WHERE (%s::text IS NULL OR status = %s) "
            "ORDER BY fingerprint_id, version DESC",
            (status, status),
        )
        return cur.fetchall()


def fetch_rule_history(fingerprint_id: str) -> dict:
    """GET /api/rules/{fp} body: every version of the fingerprint (newest
    first) plus its audit trail (entity = fingerprint_id, latest 200)."""
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT {_RULE_COLUMNS} FROM rules "
            "WHERE fingerprint_id = %s ORDER BY version DESC",
            (fingerprint_id,),
        )
        rules = cur.fetchall()
        cur.execute(
            "SELECT id, ts, actor, action, entity, detail FROM audit_log "
            "WHERE entity = %s ORDER BY id DESC LIMIT 200",
            (fingerprint_id,),
        )
        audit = cur.fetchall()
    return {"rules": rules, "audit": audit}


def fetch_samples_status(fingerprint=None):
    """GET /api/onboarding/samples rows: per-fingerprint sample accounting —
    total, per-role counts (zero-filled), latest capture. Omitted fingerprint
    -> one row per fingerprint; given -> the single row (zero-filled when the
    fingerprint has no samples yet)."""
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT fingerprint_id, count(*) AS total, "
            "count(*) FILTER (WHERE role = 'prompt') AS prompt, "
            "count(*) FILTER (WHERE role = 'held_out') AS held_out, "
            "count(*) FILTER (WHERE role = 'unused') AS unused, "
            "max(captured_at) AS latest_captured_at "
            "FROM onboarding_samples "
            "WHERE (%s::text IS NULL OR fingerprint_id = %s) "
            "GROUP BY fingerprint_id ORDER BY fingerprint_id",
            (fingerprint, fingerprint),
        )
        rows = cur.fetchall()
    if fingerprint is not None and not rows:
        return [{"fingerprint_id": fingerprint, "total": 0,
                 "by_role": {"prompt": 0, "held_out": 0, "unused": 0},
                 "latest_captured_at": None}]
    return [{
        "fingerprint_id": row["fingerprint_id"],
        "total": row["total"],
        "by_role": {"prompt": row["prompt"] or 0, "held_out": row["held_out"] or 0,
                    "unused": row["unused"] or 0},
        "latest_captured_at": row["latest_captured_at"],
    } for row in rows]


def fetch_audit(fingerprint=None, limit=DEFAULT_LIMIT):
    """GET /api/audit rows: the audit trail, latest first, optionally scoped to
    one fingerprint (entity = the fingerprint_id)."""
    limit = clamp_limit(limit)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, ts, actor, action, entity, detail FROM audit_log "
            "WHERE (%s::text IS NULL OR entity = %s) "
            "ORDER BY id DESC LIMIT %s",
            (fingerprint, fingerprint, limit),
        )
        return cur.fetchall()
