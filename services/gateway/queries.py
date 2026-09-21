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
# Export rows are bulk (SIEM/data-lake integration), so the export endpoints
# get their OWN cap — 100x MAX_LIMIT — kept separate so the interactive LIMIT
# clamp can never silently widen (and vice versa).
EXPORT_MAX = 50_000

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


# --- M3 drift surfaces (Task 7; SELECT arrives via 003's default privileges) ----

_DRIFT_WINDOW_COLUMNS = (
    "fingerprint_id, rule_version, field, window_start, window_end, events_count, "
    "null_rate, match_rate, violation_rate, shape_dist, severity, action_taken"
)


def fetch_drift_metrics(limit=DEFAULT_LIMIT) -> list[dict]:
    """GET /api/drift/metrics rows: the LATEST closed window per
    (fingerprint_id, field) — DISTINCT ON over window_start DESC — clamp-capped.
    shape_dist is JSONB, so dict_row hands back a dict natively (no unwrap)."""
    limit = clamp_limit(limit)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT DISTINCT ON (fingerprint_id, field) {_DRIFT_WINDOW_COLUMNS} "
            "FROM drift_windows "
            "ORDER BY fingerprint_id, field, window_start DESC LIMIT %s",
            (limit,),
        )
        return cur.fetchall()


def _alert_recency(row: dict):
    """Latest-first merge key across the two alert sources (P-4): a window row
    is as recent as its window_start, an audit row as its ts."""
    return row["window_start"] if "window_start" in row else row["ts"]


def fetch_drift_alerts(limit=DEFAULT_LIMIT) -> list[dict]:
    """GET /api/drift/alerts rows — controller ruling P-4's kind-discriminated
    union, rendered by the web feed as ONE list: "window" rows are
    drift_windows with severity minor/moderate/severe (the row IS the alert);
    "audit" rows are audit_log actions field_quarantined/field_unquarantined/
    rule_deactivated from ANY actor (drift's enforcement or a human override).
    Both sources are fetched latest-first and clamp-capped, then merged into a
    single latest-first list capped at the same limit. The severity/action
    IN-lists are module-controlled vocabulary (never request input), so they
    stay literals — the _STATUS_KEYS / samples-role style."""
    limit = clamp_limit(limit)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            f"SELECT {_DRIFT_WINDOW_COLUMNS} FROM drift_windows "
            "WHERE severity IN ('minor', 'moderate', 'severe') "
            "ORDER BY window_start DESC LIMIT %s",
            (limit,),
        )
        windows = [dict(row, kind="window") for row in cur.fetchall()]
        cur.execute(
            "SELECT id, ts, actor, action, entity, detail FROM audit_log "
            "WHERE action IN ('field_quarantined', 'field_unquarantined', "
            "'rule_deactivated') "
            "ORDER BY id DESC LIMIT %s",
            (limit,),
        )
        audits = [dict(row, kind="audit") for row in cur.fetchall()]
    return sorted(windows + audits, key=_alert_recency, reverse=True)[:limit]


# --- M3 exports (Task 8; spec §11 / PS g+h — SIEM/data-lake integration) --------

def clamp_export_limit(limit: int) -> int:
    """Export LIMIT clamp: 1..EXPORT_MAX regardless of caller input. The export
    endpoints take an UNBOUNDED limit param (no FastAPI le= — a bulk export
    must not 422) and clamp here, in the query: one enforcement point, pinned
    by the fake-conn tests."""
    return max(1, min(int(limit), EXPORT_MAX))


def fetch_export_rows(fingerprint=None, status=None, limit=EXPORT_MAX):
    """Export fetch shared by GET /api/export/{ocsf,parquet}: current view
    (R9 predicate), EventRow columns + ocsf, newest first, clamp-capped at
    EXPORT_MAX.

    PARSED-ONLY by design: the exports carry OCSF documents, and only parsed
    rows have one. The `status = 'parsed'` literal is module-controlled
    vocabulary (never request input), so it stays a literal like the
    drift-severity lists; the status param narrows WITHIN parsed — it arrives
    parameterized and INTERSECTS, so status=unparsed/parse_error/quarantined
    selects nothing (non-parsed rows are skipped here, in SQL — the JSONL
    stream never carries a "null" line) rather than erroring."""
    limit = clamp_export_limit(limit)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT event_id, raw_id, fingerprint_id, rule_version, status, parsed_at, ocsf "
            "FROM normalized_events "
            "WHERE superseded_by_event_id IS NULL "
            "AND status = 'parsed' "
            "AND (%s::text IS NULL OR status = %s) "
            "AND (%s::text IS NULL OR fingerprint_id = %s) "
            "ORDER BY parsed_at DESC LIMIT %s",
            (status, status, fingerprint, fingerprint, limit),
        )
        return cur.fetchall()
